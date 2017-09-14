/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  object.c
//
// Object manager related functions
//
// Functions contained within:
//
//    object_create
//    object_free
//    object_is_modifiable
//    object_is_private
//    object_is_token_object
//    object_is_session_object
//

#include <pthread.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"
#include "trace.h"

// object_create()
//
// Args:   void *  attributes : (INPUT)  pointer to data block containing ATTRIBUTEs
//         OBJECT *       obj : (OUTPUT) destination object
//
// Creates an object with the specified attributes.  Verifies that all required
// attributes are present and adds any missing attributes that have Cryptoki-defined
// default values.  This routine does not check whether the session is authorized
// to create the object.  That is done elsewhere (see object_mgr_create())
//
CK_RV
object_create( STDLL_TokData_t * tokdata,
	       CK_ATTRIBUTE  * pTemplate,
               CK_ULONG        ulCount,
               OBJECT       ** obj )
{
   OBJECT        * o           = NULL;
   CK_ATTRIBUTE  * attr        = NULL;
   CK_ATTRIBUTE  * sensitive   = NULL;
   CK_ATTRIBUTE  * extractable = NULL;
   CK_BBOOL        class_given = FALSE;
   CK_BBOOL        subclass_given = FALSE;
   CK_BBOOL        flag;
   CK_ULONG        class = 0xFFFFFFFF, subclass = 0xFFFFFFFF;
   CK_RV           rc;
   unsigned int    i;

   if (!pTemplate){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   // extract the object class and subclass
   //
   attr = pTemplate;
   for (i=0; i < ulCount; i++, attr++) {
      if (attr->type == CKA_CLASS) {
         class = *(CK_OBJECT_CLASS *)attr->pValue;
         class_given = TRUE;
      }

      if (attr->type == CKA_CERTIFICATE_TYPE) {
         subclass = *(CK_CERTIFICATE_TYPE *)attr->pValue;
         subclass_given = TRUE;
      }

      if (attr->type == CKA_KEY_TYPE) {
         subclass = *(CK_KEY_TYPE *)attr->pValue;
         subclass_given = TRUE;
      }

      if (attr->type == CKA_HW_FEATURE_TYPE) {
	 subclass = *(CK_HW_FEATURE_TYPE *)attr->pValue;
	 subclass_given = TRUE;
      }
   }

   if (class_given == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
      return CKR_TEMPLATE_INCOMPLETE;
   }

	// Return CKR_ATTRIBUTE_TYPE_INVALID when trying to create a
	// vendor-defined object.
	if (class >= CKO_VENDOR_DEFINED) {
		TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID));
		return CKR_ATTRIBUTE_TYPE_INVALID;
	}

   if (class != CKO_DATA && subclass_given != TRUE){
      TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
      return CKR_TEMPLATE_INCOMPLETE;
   }

   rc = object_create_skel( tokdata, pTemplate, ulCount,
                            MODE_CREATE, class, subclass, &o );
   if (rc != CKR_OK){
      TRACE_DEVEL("object_create_skel failed.\n");
      return rc;
   }
   // for key objects, we need be careful...
   //
   // note:  I would think that keys loaded with C_CreateObject should
   //        have their CKA_NEVER_EXTRACTABLE == FALSE and
   //        CKA_ALWAYS_SENSITIVE == FALSE since the key data was presumably
   //        stored in the clear prior to the call to C_CreateObject.  The
   //        PKCS #11 spec doesn't impose this restriction however.
   //
   if (class == CKO_PRIVATE_KEY || class == CKO_SECRET_KEY) {
      rc = template_attribute_find( o->template, CKA_SENSITIVE, &attr );
      if (rc == FALSE) {
	 TRACE_ERROR("Failed to find CKA_SENSITIVE for the key.\n");
         rc = CKR_FUNCTION_FAILED;
         goto error;
      }

      flag = *(CK_BBOOL *)attr->pValue;

      rc = build_attribute( CKA_ALWAYS_SENSITIVE, &flag, sizeof(CK_BYTE), &sensitive );
      if (rc != CKR_OK){
         TRACE_DEVEL("build_attribute failed.\n");
         goto error;
      }

      rc = template_attribute_find( o->template, CKA_EXTRACTABLE, &attr );
      if (rc == FALSE) {
	 TRACE_ERROR("Failed to find CKA_EXTRACTABLE for the key.\n");
         rc = CKR_FUNCTION_FAILED;
         goto error;
      }

      flag = *(CK_BBOOL *)attr->pValue;
      flag = (~flag) & 0x1;

      rc = build_attribute( CKA_NEVER_EXTRACTABLE, &flag, sizeof(CK_BYTE), &extractable );
      if (rc != CKR_OK){
         TRACE_DEVEL("build attribute failed.\n");
         goto error;
      }
      template_update_attribute( o->template, sensitive );
      template_update_attribute( o->template, extractable );
   }

   *obj = o;

   return CKR_OK;

error:
   if (sensitive)    free( sensitive );
   if (extractable)  free( extractable );

   object_free( o );
   return rc;
}


// object_copy()
//
// Args:   OBJECT *   old_obj : (INPUT)  pointer to the source object
//         void *  attributes : (INPUT)  pointer to data block containing additional ATTRIBUTEs
//         CK_ULONG     count : (INPUT)  number of new attributes
//         OBJECT **  new_obj : (OUTPUT) destination object
//
// Builds a copy of the specified object.  The new object gets the original
// object's attribute template plus any additional attributes that are specified.
// Verifies that all required attributes are present.  This routine does not
// check whether the session is authorized to copy the object -- routines at
// the individual object level don't have the concept of "session".  These checks
// are done by the object manager.
//
CK_RV
object_copy( STDLL_TokData_t * tokdata,
             CK_ATTRIBUTE  * pTemplate,
             CK_ULONG        ulCount,
             OBJECT        * old_obj,
             OBJECT       ** new_obj )
{
   TEMPLATE  * tmpl     = NULL;
   TEMPLATE  * new_tmpl = NULL;
   OBJECT    * o        = NULL;
   CK_BBOOL    found;
   CK_ULONG    class, subclass;
   CK_RV       rc;


   if (!old_obj || !pTemplate || !new_obj){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   o        = (OBJECT   *)malloc(sizeof(OBJECT));
   tmpl     = (TEMPLATE *)malloc(sizeof(TEMPLATE));
   new_tmpl = (TEMPLATE *)malloc(sizeof(TEMPLATE));

   if (!o || !tmpl || !new_tmpl) {
      rc = CKR_HOST_MEMORY;
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      if (o)        free(o);
      if (tmpl)     free(tmpl);
      if (new_tmpl) free(new_tmpl);
      return rc; // do not goto done -- memory might not be initialized
   }

   memset( o,        0x0, sizeof(OBJECT) );
   memset( tmpl,     0x0, sizeof(TEMPLATE) );
   memset( new_tmpl, 0x0, sizeof(TEMPLATE) );

   // copy the original object's attribute template
   //
   rc = template_copy( tmpl, old_obj->template );
   if (rc != CKR_OK){
      TRACE_DEVEL("Failed to copy template.\n");
      goto error;
   }
   rc = template_add_attributes( new_tmpl, pTemplate, ulCount );
   if (rc != CKR_OK){
      TRACE_DEVEL("template_add_attributes failed.\n");
      goto error;
   }
   // at this point, the new object has the list of attributes.  we need
   // to do some more checking now:
   //    1) invalid attribute values
   //    2) missing required attributes
   //    3) attributes inappropriate for the object class
   //    4) conflicting attributes/values
   //

   found = template_get_class( tmpl, &class, &subclass );
   if (found == FALSE) {
      TRACE_ERROR("Could not find CKA_CLASS in object's template.\n");
      rc = CKR_TEMPLATE_INCONSISTENT;
      goto error;
   }


   // the user cannot change object classes so we assume the existing
   // object attributes are valid.  we still need to check the new attributes.
   // we cannot merge the new attributes in with the old ones and then check
   // for validity because some attributes are added internally and are not
   // allowed to be specified by the user (ie. CKA_LOCAL for key types) but
   // may still be part of the old template.
   //
   rc = template_validate_attributes( tokdata, new_tmpl, class, subclass,
				      MODE_COPY );
   if (rc != CKR_OK){
      TRACE_DEVEL("template_validate_attributes failed.\n");
      goto error;
   }
   // merge in the new attributes
   //
   rc = template_merge( tmpl, &new_tmpl );
   if (rc != CKR_OK){
      TRACE_DEVEL("template_merge failed.\n");
      goto error;
   }
   // do we need this?  since an attribute cannot be removed, the original
   // object's template (contained in tmpl) already has the required attributes
   // present
   //
   rc = template_check_required_attributes( tmpl, class, subclass, MODE_COPY );
   if (rc != CKR_OK){
      TRACE_ERROR("template_check_required_attributes failed.\n");
      goto error;
   }
   // at this point, we should have a valid object with correct attributes
   //
   o->template = tmpl;
   *new_obj = o;

   return CKR_OK;

error:
   if (tmpl)     template_free( tmpl );
   if (new_tmpl) template_free( new_tmpl );
   if (o)        object_free( o );

   return rc;
}


// object_flatten() - this is still used when saving token objects
//
CK_RV
object_flatten( OBJECT    * obj,
                CK_BYTE  ** data,
                CK_ULONG  * len )
{
   CK_BYTE    * buf = NULL;
   CK_ULONG     tmpl_len, total_len;
   CK_ULONG     offset;
   CK_ULONG_32     count;
   long         rc;

   if (!obj){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   count    = template_get_count( obj->template );
   tmpl_len = template_get_compressed_size ( obj->template );

   total_len = tmpl_len + sizeof(CK_OBJECT_CLASS_32) + sizeof(CK_ULONG_32) + 8;

   buf = (CK_BYTE *)malloc(total_len);
   if (!buf){ // SAB  XXX FIXME  This was DATA
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }

   memset( (CK_BYTE *)buf,0x0,total_len);

   offset = 0;

   memcpy( buf + offset, &obj->class, sizeof(CK_OBJECT_CLASS_32) );
   offset += sizeof(CK_OBJECT_CLASS_32);

   memcpy( buf + offset, &count, sizeof(CK_ULONG_32) );
   offset += sizeof(CK_ULONG_32);

   memcpy( buf + offset, &obj->name,  sizeof(CK_BYTE) * 8 );
   offset += 8;
   rc = template_flatten( obj->template, buf + offset );
   if (rc != CKR_OK) {
      free( buf );
      return rc;
   }

   *data = buf;
   *len  = total_len;

   return CKR_OK;
}



// object_free()
//
// does what it says...
//
void object_free(OBJECT *obj)
{
	/* refactorization here to do actual free - fix from coverity scan */
	if (obj) {
		if (obj->template)
			template_free(obj->template);
		free(obj);
	}
}

//call_free()
//This function is added to silence the compiler during implicit void (*)(void*) function pointer casting in call back functions.
//
void call_free(void *ptr)
{
	if (ptr)
		object_free ((OBJECT*) ptr);
}

// object_is_modifiable()
//
CK_BBOOL
object_is_modifiable( OBJECT *obj )
{
   CK_ATTRIBUTE  * attr = NULL;
   CK_BBOOL        modifiable;
   CK_BBOOL        found;

   found = template_attribute_find( obj->template, CKA_MODIFIABLE, &attr );
   if (found == FALSE)
      return TRUE;      // should always be found but we default to TRUE

   //axelrh: prevent dereferencing NULL from bad parse
   if (attr->pValue == NULL)
	return TRUE; //default to TRUE

   modifiable = *(CK_BBOOL *)attr->pValue;

   return modifiable;
}


// object_is_private()
//
// an is_private member should probably be added to OBJECT
//
CK_BBOOL
object_is_private( OBJECT *obj )
{
   CK_ATTRIBUTE  * attr = NULL;
   CK_BBOOL        priv;
   CK_BBOOL        found;

   found = template_attribute_find( obj->template, CKA_PRIVATE, &attr );
   if (found == FALSE){
      return TRUE;      // should always be found but we default to TRUE
   }
   if ( attr == NULL)  return  TRUE;


   //axelrh: prevent segfault caused by 0-len attribute
   //that has a null pValue
   CK_BBOOL *bboolPtr = (CK_BBOOL *)attr->pValue;
   if (bboolPtr == NULL)
       return TRUE; //default

   priv = *(bboolPtr);

   return priv;
}


// object_is_public()
//
CK_BBOOL
object_is_public( OBJECT *obj )
{
   CK_BBOOL rc;

   rc = object_is_private( obj );

   if (rc)
      return FALSE;

   return TRUE;
}


// object_is_token_object()
//
CK_BBOOL
object_is_token_object( OBJECT *obj )
{
   CK_ATTRIBUTE  * attr = NULL;
   CK_BBOOL        is_token;
   CK_BBOOL        found;

   found = template_attribute_find( obj->template, CKA_TOKEN, &attr );
   if (found == FALSE)
      return FALSE;

   //axelrh: prevent dereferencing NULL from bad parse
   if (attr->pValue == NULL)
	return FALSE;

   is_token = *(CK_BBOOL *)attr->pValue;
   return is_token;
}


// object_is_session_object()
//
CK_BBOOL
object_is_session_object( OBJECT *obj )
{
   CK_BBOOL rc;

   rc = object_is_token_object( obj );

   if (rc)
      return FALSE;
   else
      return TRUE;
}


// object_get_size()
//
CK_ULONG
object_get_size( OBJECT *obj )
{
   CK_ULONG  size;

   size = sizeof(OBJECT) + template_get_size(obj->template);

   return size;
}


//
//
CK_RV
object_get_attribute_values( OBJECT        * obj,
                             CK_ATTRIBUTE  * pTemplate,
                             CK_ULONG        ulCount )
{
   TEMPLATE          *obj_tmpl = NULL;
   CK_ATTRIBUTE      *attr     = NULL;
   CK_ULONG           i;
   CK_BBOOL           flag;
   CK_RV              rc;

   rc = CKR_OK;

   obj_tmpl = obj->template;

   for (i=0; i < ulCount; i++) {
      flag = template_check_exportability( obj_tmpl, pTemplate[i].type);
      if (flag == FALSE) {
         TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_SENSITIVE));
         rc = CKR_ATTRIBUTE_SENSITIVE;
         pTemplate[i].ulValueLen = (CK_ULONG)-1;
         continue;
      }

      flag = template_attribute_find( obj_tmpl, pTemplate[i].type, &attr );
      if (flag == FALSE) {
         TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID));
         rc = CKR_ATTRIBUTE_TYPE_INVALID;
         pTemplate[i].ulValueLen = (CK_ULONG)-1;
         continue;
      }

      if (pTemplate[i].pValue == NULL) {
         pTemplate[i].ulValueLen = attr->ulValueLen;
      }
      else if (pTemplate[i].ulValueLen >= attr->ulValueLen) {
         memcpy( pTemplate[i].pValue, attr->pValue, attr->ulValueLen );
         pTemplate[i].ulValueLen = attr->ulValueLen;
      }
      else {
         TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
         rc = CKR_BUFFER_TOO_SMALL;
         pTemplate[i].ulValueLen = (CK_ULONG)-1;
      }
   }

   return rc;
}

// object_set_attribute_values()
//
CK_RV
object_set_attribute_values( STDLL_TokData_t * tokdata,
			     OBJECT        * obj,
                             CK_ATTRIBUTE  * pTemplate,
                             CK_ULONG        ulCount )
{
   TEMPLATE * new_tmpl = NULL;
   CK_BBOOL   found;
   CK_ULONG   class, subclass;
   CK_RV      rc;


   if (!obj || !pTemplate){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }

   found = template_get_class( obj->template, &class, &subclass );
   if (found == FALSE) {
      TRACE_ERROR("Failed to find CKA_CLASS in object template.\n");
      rc = CKR_FUNCTION_FAILED;
      goto error;
   }

   new_tmpl = (TEMPLATE *)malloc(sizeof(TEMPLATE));
   if (!new_tmpl){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }
   memset( new_tmpl, 0x0, sizeof(TEMPLATE) );

   rc = template_add_attributes( new_tmpl, pTemplate, ulCount );
   if (rc != CKR_OK){
      TRACE_DEVEL("template_add_attributes failed.\n");
      goto error;
   }

   // the user cannot change object classes so we assume the existing
   // object attributes are valid.  we still need to check the new attributes.
   // we cannot merge the new attributes in with the old ones and then check
   // for validity because some attributes are added internally and are not
   // allowed to be specified by the user (ie. CKA_LOCAL for key types) but
   // may still be part of the old template.
   //
   rc = template_validate_attributes( tokdata, new_tmpl, class, subclass,
				      MODE_MODIFY );
   if (rc != CKR_OK){
      TRACE_DEVEL("template_validate_attributes failed.\n");
      goto error;
   }

   // merge in the new attributes
   //
   rc = template_merge( obj->template, &new_tmpl );
   if (rc != CKR_OK){
      TRACE_DEVEL("template_merge failed.\n");
      return rc;
   }
   return CKR_OK;

error:
   // we only free the template if there was an error...otherwise the
   // object "owns" the template
   //
   if (new_tmpl)  template_free( new_tmpl );
   return rc;
}


//
//
CK_RV
object_restore( CK_BYTE *data, OBJECT **new_obj, CK_BBOOL replace )
{
   return object_restore_withSize(data, new_obj, replace, -1);
}

//
//Modified object_restore to prevent buffer overflow
//If data_size=-1, won't do bounds checking
CK_RV
object_restore_withSize( CK_BYTE *data, OBJECT **new_obj, CK_BBOOL replace, int data_size )
{
   TEMPLATE  * tmpl = NULL;
   OBJECT    * obj  = NULL;
   CK_ULONG    offset = 0;
   CK_ULONG_32    count = 0;
   CK_RV       rc;

   if (!data || !new_obj){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   obj = (OBJECT *)malloc(sizeof(OBJECT));
   if (!obj) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto error;
   }


   memset( obj, 0x0, sizeof(OBJECT) );

   memcpy( &obj->class, data + offset, sizeof(CK_OBJECT_CLASS_32) );
   offset += sizeof(CK_OBJECT_CLASS_32);

   memcpy( &count, data + offset, sizeof(CK_ULONG_32) );
   offset += sizeof(CK_ULONG_32);


   memcpy( &obj->name, data + offset, 8 );
   offset += 8;

   rc = template_unflatten_withSize( &tmpl, data + offset, count, data_size );
   if (rc != CKR_OK){
      TRACE_DEVEL("template_unflatten_withSize failed.\n");
      goto error;
   }
   obj->template = tmpl;

   if (replace == FALSE) {
      *new_obj = obj;
   }
   else {
      template_free( (*new_obj)->template );
      memcpy( *new_obj, obj, sizeof(OBJECT) );

      free( obj );  // don't want to do object_free() here!
   }

   return CKR_OK;

error:
   if (obj)  object_free( obj );
   if (tmpl) template_free( tmpl );

   return rc;
}


//
//
CK_RV
object_create_skel( STDLL_TokData_t  * tokdata,
		    CK_ATTRIBUTE  * pTemplate,
                    CK_ULONG        ulCount,
                    CK_ULONG        mode,
                    CK_ULONG        class,
                    CK_ULONG        subclass,
                    OBJECT       ** obj )
{
   TEMPLATE  * tmpl  = NULL;
   TEMPLATE  * tmpl2 = NULL;
   OBJECT   * o     = NULL;
   CK_RV      rc;


   if (!obj){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (!pTemplate && (ulCount != 0)){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   o     = (OBJECT *)malloc(sizeof(OBJECT));
   tmpl  = (TEMPLATE *)malloc(sizeof(TEMPLATE));
   tmpl2 = (TEMPLATE *)malloc(sizeof(TEMPLATE));

   if (!o || !tmpl || !tmpl2) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto done;
   }
   memset( o,     0x0, sizeof(OBJECT)   );
   memset( tmpl,  0x0, sizeof(TEMPLATE) );
   memset( tmpl2, 0x0, sizeof(TEMPLATE) );


   rc = template_add_attributes( tmpl2, pTemplate, ulCount );
   if (rc != CKR_OK)
      goto done;


   // at this point, the new template has the list of attributes.  we need
   // to do some more checking now:
   //    1) invalid attribute values
   //    2) missing required attributes
   //    3) attributes inappropriate for the object class
   //    4) conflicting attributes/values
   //

   rc = template_validate_attributes( tokdata, tmpl2, class, subclass, mode );
   if (rc != CKR_OK){
      TRACE_DEVEL("template_validate_attributes failed.\n");
      goto done;
   }

   rc = template_check_required_attributes( tmpl2, class, subclass, mode );
   if (rc != CKR_OK){
      TRACE_DEVEL("template_check_required_attributes failed.\n");
      goto done;
   }

   rc = template_add_default_attributes( tmpl, tmpl2, class, subclass, mode );
   if (rc != CKR_OK)
      goto done;


   rc = template_merge( tmpl, &tmpl2 );
   if (rc != CKR_OK){
      TRACE_DEVEL("template_merge failed.\n");
      goto done;
   }
   // at this point, we should have a valid object with correct attributes
   //
   o->template = tmpl;
   *obj = o;

   return CKR_OK;

done:
   if (o)      free( o );
   if (tmpl)   template_free( tmpl );
   if (tmpl2)  template_free( tmpl2 );

   return rc;
}
