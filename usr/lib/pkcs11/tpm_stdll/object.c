
/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */


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

//#include <windows.h>
#include <pthread.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>
#ifdef LEEDS_BUILD
  #include <string.h>  // for memcmp() et al
#endif


#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"

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
object_create( CK_ATTRIBUTE  * pTemplate,
               CK_ULONG        ulCount,
               OBJECT       ** obj )
{
   OBJECT        * o           = NULL;
   CK_ATTRIBUTE  * attr        = NULL;
   CK_ATTRIBUTE  * sensitive   = NULL;
   CK_ATTRIBUTE  * extractable = NULL;
   CK_ATTRIBUTE  * local       = NULL;
   CK_BBOOL        class_given = FALSE;
   CK_BBOOL        subclass_given = FALSE;
   CK_BBOOL        flag;
   CK_ULONG        class = 0xFFFFFFFF, subclass = 0xFFFFFFFF;
   CK_RV           rc;
   int             i;

   if (!pTemplate){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
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
      st_err_log(48, __FILE__, __LINE__);
      return CKR_TEMPLATE_INCOMPLETE;
   }
   if (class != CKO_DATA && subclass_given != TRUE){
      st_err_log(48, __FILE__, __LINE__);
      return CKR_TEMPLATE_INCOMPLETE;
   }

   rc = object_create_skel( pTemplate, ulCount,
                            MODE_CREATE,
                            class, subclass,
                            &o );
   if (rc != CKR_OK){
      st_err_log(89, __FILE__, __LINE__); 
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
         st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
         rc = CKR_FUNCTION_FAILED;
         goto error;
      }

      flag = *(CK_BBOOL *)attr->pValue;

      rc = build_attribute( CKA_ALWAYS_SENSITIVE, &flag, sizeof(CK_BYTE), &sensitive );
      if (rc != CKR_OK){
         st_err_log(84, __FILE__, __LINE__); 
         goto error;
      }

      rc = template_attribute_find( o->template, CKA_EXTRACTABLE, &attr );
      if (rc == FALSE) {
         st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
         rc = CKR_FUNCTION_FAILED;
         goto error;
      }

      flag = *(CK_BBOOL *)attr->pValue;
      flag = (~flag) & 0x1;

      rc = build_attribute( CKA_NEVER_EXTRACTABLE, &flag, sizeof(CK_BYTE), &extractable );
      if (rc != CKR_OK){
         st_err_log(84, __FILE__, __LINE__); 
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
   if (local)        free( local );

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
object_copy( CK_ATTRIBUTE  * pTemplate,
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
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED; 
   }
   o        = (OBJECT   *)malloc(sizeof(OBJECT));
   tmpl     = (TEMPLATE *)malloc(sizeof(TEMPLATE));
   new_tmpl = (TEMPLATE *)malloc(sizeof(TEMPLATE));

   if (!o || !tmpl || !new_tmpl) {
      rc = CKR_HOST_MEMORY;
      st_err_log(0, __FILE__, __LINE__);
      goto error;
   }

   memset( o,        0x0, sizeof(OBJECT) );
   memset( tmpl,     0x0, sizeof(TEMPLATE) );
   memset( new_tmpl, 0x0, sizeof(TEMPLATE) );

   // copy the original object's attribute template
   //
   rc = template_copy( tmpl, old_obj->template );
   if (rc != CKR_OK){
      st_err_log(163, __FILE__, __LINE__); 
      goto error;
   }
   rc = template_add_attributes( new_tmpl, pTemplate, ulCount );
   if (rc != CKR_OK){
      st_err_log(164, __FILE__, __LINE__); 
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
      st_err_log(49, __FILE__, __LINE__); 
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
   rc = template_validate_attributes( new_tmpl, class, subclass, MODE_COPY );
   if (rc != CKR_OK){
      st_err_log(165, __FILE__, __LINE__); 
      goto error;
   }
   // merge in the new attributes
   //
   rc = template_merge( tmpl, &new_tmpl );
   if (rc != CKR_OK){
      st_err_log(165, __FILE__, __LINE__); 
      goto error;
   }
   // do we need this?  since an attribute cannot be removed, the original
   // object's template (contained in tmpl) already has the required attributes
   // present
   //
   rc = template_check_required_attributes( tmpl, class, subclass, MODE_COPY );
   if (rc != CKR_OK){
      st_err_log(166, __FILE__, __LINE__); 
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
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   count    = template_get_count( obj->template );
   tmpl_len = template_get_compressed_size ( obj->template );

   total_len = tmpl_len + sizeof(CK_OBJECT_CLASS_32) + sizeof(CK_ULONG_32) + 8;

   buf = (CK_BYTE *)malloc(total_len);
   if (!buf){ // SAB  XXX FIXME  This was DATA
      st_err_log(0, __FILE__, __LINE__);
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
CK_BBOOL
object_free( OBJECT *obj )
{
   template_free( obj->template );
   free( obj );

   return TRUE;
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
  

   priv = *((CK_BBOOL *)attr->pValue);

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
         st_err_log(70, __FILE__, __LINE__); 
         rc = CKR_ATTRIBUTE_SENSITIVE;
         pTemplate[i].ulValueLen = (CK_ULONG)-1;
         continue;
      }

      flag = template_attribute_find( obj_tmpl, pTemplate[i].type, &attr );
      if (flag == FALSE) {
         st_err_log(8, __FILE__, __LINE__); 
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
         st_err_log(111, __FILE__, __LINE__); 
         rc = CKR_BUFFER_TOO_SMALL;
         pTemplate[i].ulValueLen = (CK_ULONG)-1;
      }
   }

   return rc;
}


// object_set_attribute_values()
//
CK_RV
object_set_attribute_values( OBJECT        * obj,
                             CK_ATTRIBUTE  * pTemplate,
                             CK_ULONG        ulCount )
{
   TEMPLATE * new_tmpl;
   CK_BBOOL   found;
   CK_ULONG   class, subclass;
   CK_RV      rc;


   if (!obj || !pTemplate){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   found = template_get_class( obj->template, &class, &subclass );
   if (found == FALSE) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto error;
   }

   new_tmpl = (TEMPLATE *)malloc(sizeof(TEMPLATE));
   if (!new_tmpl){
      st_err_log(0, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }
   memset( new_tmpl, 0x0, sizeof(TEMPLATE) );

   rc = template_add_attributes( new_tmpl, pTemplate, ulCount );
   if (rc != CKR_OK){
      st_err_log(164, __FILE__, __LINE__); 
      goto error;
   }

   // the user cannot change object classes so we assume the existing
   // object attributes are valid.  we still need to check the new attributes.
   // we cannot merge the new attributes in with the old ones and then check
   // for validity because some attributes are added internally and are not
   // allowed to be specified by the user (ie. CKA_LOCAL for key types) but
   // may still be part of the old template.
   //
   rc = template_validate_attributes( new_tmpl, class, subclass, MODE_MODIFY );
   if (rc != CKR_OK){
      st_err_log(165, __FILE__, __LINE__); 
      goto error;
   }

   // merge in the new attributes
   //
   rc = template_merge( obj->template, &new_tmpl );
   if (rc != CKR_OK){
      st_err_log(165, __FILE__, __LINE__); 
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
   TEMPLATE  * tmpl = NULL;
   OBJECT    * obj  = NULL;
   CK_ULONG    offset = 0;
   CK_ULONG_32    count = 0;
   CK_RV       rc;

   if (!data || !new_obj){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   obj = (OBJECT *)malloc(sizeof(OBJECT));
   if (!obj) {
      st_err_log(0, __FILE__, __LINE__);
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

   rc = template_unflatten( &tmpl, data + offset, count );
   if (rc != CKR_OK){
      st_err_log(166, __FILE__, __LINE__);
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
object_create_skel( CK_ATTRIBUTE  * pTemplate,
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
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (!pTemplate && (ulCount != 0)){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   o     = (OBJECT *)malloc(sizeof(OBJECT));
   tmpl  = (TEMPLATE *)malloc(sizeof(TEMPLATE));
   tmpl2 = (TEMPLATE *)malloc(sizeof(TEMPLATE));

   if (!o || !tmpl || !tmpl2) {
      st_err_log(0, __FILE__, __LINE__);
      rc = CKR_HOST_MEMORY;
      goto done;
   }
   memset( o,     0x0, sizeof(OBJECT)   );
   memset( tmpl,  0x0, sizeof(TEMPLATE) );
   memset( tmpl2, 0x0, sizeof(TEMPLATE) );


   rc = template_add_default_attributes( tmpl, class, subclass, mode );
   if (rc != CKR_OK)
      goto done;

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

   rc = template_validate_attributes( tmpl2, class, subclass, mode );
   if (rc != CKR_OK){
      st_err_log(165, __FILE__, __LINE__); 
      goto done;
   }

   rc = template_check_required_attributes( tmpl2, class, subclass, mode );
   if (rc != CKR_OK){
      st_err_log(166, __FILE__, __LINE__); 
      goto done;
   }

   rc = template_merge( tmpl, &tmpl2 );
   if (rc != CKR_OK){
      st_err_log(165, __FILE__, __LINE__); 
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

