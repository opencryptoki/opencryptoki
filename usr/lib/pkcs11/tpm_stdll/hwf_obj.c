
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


// File:  hwf_obj.c
//
// Hardware Feature Object functions

#include <pthread.h>
#include <stdlib.h>

#include <string.h>  // for memcmp() et al

#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"

#include "tok_spec_struct.h"


// hwf_object_check_required_attributes()
//
// Check required common attributes for hardware feature objects
//
CK_RV
hwf_object_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE * attr = NULL;
   CK_BBOOL    found;

   found = template_attribute_find( tmpl, CKA_HW_FEATURE_TYPE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return template_check_required_base_attributes( tmpl, mode );
}

CK_RV
clock_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL	found;

   if (mode == MODE_CREATE){
      found = template_attribute_find( tmpl, CKA_VALUE, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return hwf_object_check_required_attributes( tmpl, mode );
}

CK_RV
counter_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL     found;

   if (mode == MODE_CREATE){
      found = template_attribute_find( tmpl, CKA_VALUE, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
      
      found = template_attribute_find( tmpl, CKA_HAS_RESET, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
      
      found = template_attribute_find( tmpl, CKA_RESET_ON_INIT, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return hwf_object_check_required_attributes( tmpl, mode );
}


// hwf_object_set_default_attributes()
//
CK_RV
hwf_object_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
#if 0
   CK_ATTRIBUTE * local_attr  = NULL;

   local_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );

   if (!local_attr) {
      st_err_log(1, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }

   local_attr->type        = CKA_LOCAL;
   local_attr->ulValueLen  = sizeof(CK_BBOOL);
   local_attr->pValue      = (CK_BYTE *)local_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)local_attr->pValue = FALSE;

   template_update_attribute( tmpl, local_attr  );
#endif
   return CKR_OK;
}


// hwf_object_validate_attribute()
//
CK_RV
hwf_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode)
{
   switch (attr->type) {
      case CKA_HW_FEATURE_TYPE:
         if (mode == MODE_CREATE)
            return CKR_OK;
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }

      default:
         return template_validate_base_attribute( tmpl, attr, mode );
   }

   st_err_log(8, __FILE__, __LINE__);
   return CKR_ATTRIBUTE_TYPE_INVALID;
}

//
//
CK_RV
clock_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode)
{
   switch (attr->type)
   {
      case CKA_VALUE:
	 return CKR_OK;

      default:
	 return hwf_validate_attribute( tmpl, attr, mode );
   }
}

//
//
CK_RV
counter_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode)
{
   switch (attr->type)
   {
      case CKA_VALUE:
	 /* Fall Through */
      case CKA_HAS_RESET:
	 /* Fall Through */
      case CKA_RESET_ON_INIT:
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;

      default:
	 return hwf_validate_attribute( tmpl, attr, mode );
   }
}


CK_RV
clock_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_RV		rc;
   CK_ATTRIBUTE		*value_attr;
	
   rc = hwf_object_set_default_attributes( tmpl, mode );
   if (rc != CKR_OK)
      return rc;
   
   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!value_attr) {
      st_err_log(1, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}

CK_RV
counter_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_RV                rc;
   CK_ATTRIBUTE         *value_attr;
   CK_ATTRIBUTE         *hasreset_attr;
   CK_ATTRIBUTE         *resetoninit_attr;

   rc = hwf_object_set_default_attributes( tmpl, mode );
   if (rc != CKR_OK)
      return rc;

   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   hasreset_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
   resetoninit_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));

   if (!value_attr || !hasreset_attr || !resetoninit_attr) {
      if (value_attr) free( value_attr );
      if (hasreset_attr) free( hasreset_attr );
      if (resetoninit_attr) free( resetoninit_attr );
      st_err_log(1, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   hasreset_attr->type       = CKA_HAS_RESET;
   hasreset_attr->ulValueLen = sizeof(CK_BBOOL);
   hasreset_attr->pValue     = (CK_BYTE *)hasreset_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)hasreset_attr->pValue = FALSE;

   /* Hmm...  Not sure if we should be setting this here. */
   resetoninit_attr->type       = CKA_RESET_ON_INIT;
   resetoninit_attr->ulValueLen = sizeof(CK_BBOOL);
   resetoninit_attr->pValue     = (CK_BYTE *)resetoninit_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)resetoninit_attr->pValue = FALSE;

   template_update_attribute( tmpl, value_attr );
   template_update_attribute( tmpl, hasreset_attr );
   template_update_attribute( tmpl, resetoninit_attr );

   return CKR_OK;
}



