
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


// File:  dp_obj.c
//
// Domain Parameter Object functions

#include <pthread.h>
#include <stdlib.h>

#include <string.h>  // for memcmp() et al

#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"

#include "tok_spec_struct.h"


// dp_object_check_required_attributes()
//
// Check required common attributes for domain parameter objects
//
CK_RV
dp_object_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE * attr = NULL;
   CK_BBOOL    found;

   found = template_attribute_find( tmpl, CKA_KEY_TYPE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return template_check_required_base_attributes( tmpl, mode );
}

CK_RV
dp_dsa_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode)
{
   CK_ATTRIBUTE	*attr = NULL;
   CK_BBOOL	found;

   if (mode == MODE_CREATE){
      found = template_attribute_find( tmpl, CKA_PRIME, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
      
      found = template_attribute_find( tmpl, CKA_SUBPRIME, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
      
      found = template_attribute_find( tmpl, CKA_BASE, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   } else if (mode == MODE_KEYGEN) {
      found = template_attribute_find( tmpl, CKA_PRIME_BITS, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return dp_object_check_required_attributes( tmpl, mode );

}

CK_RV
dp_dh_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode)
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL     found;

   if (mode == MODE_CREATE){
      found = template_attribute_find( tmpl, CKA_PRIME, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }

      found = template_attribute_find( tmpl, CKA_BASE, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   } else if (mode == MODE_KEYGEN) {
      found = template_attribute_find( tmpl, CKA_PRIME_BITS, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return dp_object_check_required_attributes( tmpl, mode );


}

CK_RV
dp_x9dh_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode)
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL     found;

   if (mode == MODE_CREATE){
      found = template_attribute_find( tmpl, CKA_PRIME, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }

      found = template_attribute_find( tmpl, CKA_SUBPRIME, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }

      found = template_attribute_find( tmpl, CKA_BASE, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   } else if (mode == MODE_KEYGEN) {
      found = template_attribute_find( tmpl, CKA_PRIME_BITS, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
      found = template_attribute_find( tmpl, CKA_SUBPRIME_BITS, &attr );
      if (!found) {
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return dp_object_check_required_attributes( tmpl, mode );
}


// dp_object_set_default_attributes()
//
CK_RV
dp_object_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
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

   return CKR_OK;
}


// dp_object_validate_attribute()
//
CK_RV
dp_object_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode)
{
   switch (attr->type) {
      case CKA_KEY_TYPE:
         if (mode == MODE_CREATE)
            return CKR_OK;
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }

      case CKA_LOCAL:
	 if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
	    st_err_log(8, __FILE__, __LINE__);
	    return CKR_ATTRIBUTE_TYPE_INVALID;
	 }
	 return CKR_OK;

      default:
         return template_validate_base_attribute( tmpl, attr, mode );
   }
}

// 
//
CK_RV
dp_dsa_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode)
{
   switch (attr->type) {
      case CKA_PRIME: 
	 if (mode == MODE_KEYGEN) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }   
	 return CKR_OK;
	 
      case CKA_PRIME_BITS:
	 if (mode == MODE_CREATE) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }   
	 return CKR_OK;
	 
      case CKA_BASE:
	 if (mode == MODE_KEYGEN) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }   
	 return CKR_OK;
	 
      case CKA_SUBPRIME:
	 if (mode == MODE_KEYGEN) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }   
	 return CKR_OK;
	      
      default:
	 return dp_object_validate_attribute( tmpl, attr, mode );
   }
}

// 
//
CK_RV
dp_dh_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode)
{
   switch (attr->type) {
      case CKA_PRIME: 
	 if (mode == MODE_KEYGEN) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }   
	 return CKR_OK;
	 
      case CKA_PRIME_BITS:
	 if (mode == MODE_CREATE) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }
	 return CKR_OK;
      
      case CKA_BASE:
	 if (mode == MODE_KEYGEN) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }   
	 return CKR_OK;
	      
      default:
	 return dp_object_validate_attribute( tmpl, attr, mode );
   }
}

// 
//
CK_RV
dp_x9dh_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode)
{
   switch (attr->type) {
      case CKA_PRIME: 
	 if (mode == MODE_KEYGEN) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }   
	 return CKR_OK;
	 
      case CKA_PRIME_BITS:
	 if (mode == MODE_CREATE) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }
	 return CKR_OK;

      case CKA_BASE:
	 if (mode == MODE_KEYGEN) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }   
	 return CKR_OK;
	 
      case CKA_SUBPRIME:
	 if (mode == MODE_KEYGEN) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }   
	 return CKR_OK;
	 
      case CKA_SUBPRIME_BITS:
	 if (mode == MODE_CREATE) {
	    st_err_log(193, __FILE__, __LINE__);
	    return CKR_DOMAIN_PARAMS_INVALID;
	 }
	 return CKR_OK;
	      
      default:
	 return dp_object_validate_attribute( tmpl, attr, mode );
   }
}
		   

CK_RV
dp_dsa_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_RV		rc;
   CK_ATTRIBUTE		*prime_attr;
   CK_ATTRIBUTE		*subprime_attr;
   CK_ATTRIBUTE		*base_attr;
   CK_ATTRIBUTE		*primebits_attr;
   CK_ATTRIBUTE		*type_attr;
	
   rc = dp_object_set_default_attributes( tmpl, mode );
   if (rc != CKR_OK)
      return rc;
   
   prime_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   subprime_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   base_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   primebits_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   type_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );

   if (!prime_attr || !subprime_attr || !base_attr || !primebits_attr || !type_attr) {
      if (prime_attr) free( prime_attr );
      if (subprime_attr) free( subprime_attr );
      if (base_attr) free( base_attr );
      if (primebits_attr) free( primebits_attr );
      if (type_attr) free( type_attr );
      st_err_log(1, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }

   prime_attr->type       = CKA_PRIME;
   prime_attr->ulValueLen = 0;
   prime_attr->pValue     = NULL;

   subprime_attr->type       = CKA_SUBPRIME;
   subprime_attr->ulValueLen = 0;
   subprime_attr->pValue     = NULL;

   base_attr->type       = CKA_BASE;
   base_attr->ulValueLen = 0;
   base_attr->pValue     = NULL;

   primebits_attr->type       = CKA_PRIME_BITS;
   primebits_attr->ulValueLen = 0;
   primebits_attr->pValue     = NULL;
#if 0
   primebits_attr->ulValueLen = sizeof(CK_ULONG);
   primebits_attr->pValue     = (CK_ULONG *)primebits_attr + sizeof(CK_ATTRIBUTE);
   *(CK_ULONG *)primebits_attr->pValue = 0;
#endif
   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_DSA;

   template_update_attribute( tmpl, prime_attr );
   template_update_attribute( tmpl, subprime_attr );
   template_update_attribute( tmpl, base_attr );
   template_update_attribute( tmpl, primebits_attr );
   template_update_attribute( tmpl, type_attr );

   return CKR_OK;
}

CK_RV
dp_dh_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_RV		rc;
   CK_ATTRIBUTE         *prime_attr;
   CK_ATTRIBUTE         *base_attr;
   CK_ATTRIBUTE         *primebits_attr;
   CK_ATTRIBUTE         *type_attr;

   rc = dp_object_set_default_attributes( tmpl, mode );
   if (rc != CKR_OK)
      return rc;

   prime_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   base_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   primebits_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   type_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );

   if (!prime_attr || !base_attr || !primebits_attr || !type_attr) {
      if (prime_attr) free( prime_attr );
      if (base_attr) free( base_attr );
      if (primebits_attr) free( primebits_attr );
      if (type_attr) free( type_attr );
      st_err_log(1, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }

   prime_attr->type       = CKA_PRIME;
   prime_attr->ulValueLen = 0;
   prime_attr->pValue     = NULL;

   base_attr->type       = CKA_BASE;
   base_attr->ulValueLen = 0;
   base_attr->pValue     = NULL;

   primebits_attr->type       = CKA_PRIME_BITS;
   primebits_attr->ulValueLen = 0;
   primebits_attr->pValue     = NULL;
   
   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_DH;

   template_update_attribute( tmpl, prime_attr );
   template_update_attribute( tmpl, base_attr );
   template_update_attribute( tmpl, primebits_attr );
   template_update_attribute( tmpl, type_attr );

   return CKR_OK;

}

CK_RV
dp_x9dh_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_RV		rc;
   CK_ATTRIBUTE         *prime_attr;
   CK_ATTRIBUTE         *subprime_attr;
   CK_ATTRIBUTE         *base_attr;
   CK_ATTRIBUTE         *primebits_attr;
   CK_ATTRIBUTE		*subprimebits_attr;
   CK_ATTRIBUTE         *type_attr;

   rc = dp_object_set_default_attributes( tmpl, mode );
   if (rc != CKR_OK)
      return rc;

   prime_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   subprime_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   base_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   primebits_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   subprimebits_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   type_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );

   if (!prime_attr     || !subprime_attr     || !base_attr || 
       !primebits_attr || !subprimebits_attr || !type_attr) {
      if (prime_attr) free( prime_attr );
      if (subprime_attr) free( subprime_attr );
      if (base_attr) free( base_attr );
      if (primebits_attr) free( primebits_attr );
      if (subprimebits_attr) free( subprimebits_attr );
      if (type_attr) free( type_attr );
      st_err_log(1, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }

   prime_attr->type       = CKA_PRIME;
   prime_attr->ulValueLen = 0;
   prime_attr->pValue     = NULL;

   subprime_attr->type       = CKA_SUBPRIME;
   subprime_attr->ulValueLen = 0;
   subprime_attr->pValue     = NULL;

   base_attr->type       = CKA_BASE;
   base_attr->ulValueLen = 0;
   base_attr->pValue     = NULL;

   primebits_attr->type       = CKA_PRIME_BITS;
   primebits_attr->ulValueLen = 0;
   primebits_attr->pValue     = NULL;
   
   subprimebits_attr->type       = CKA_SUBPRIME_BITS;
   subprimebits_attr->ulValueLen = 0;
   subprimebits_attr->pValue     = NULL;
   
   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_DSA;

   template_update_attribute( tmpl, prime_attr );
   template_update_attribute( tmpl, subprime_attr );
   template_update_attribute( tmpl, base_attr );
   template_update_attribute( tmpl, primebits_attr );
   template_update_attribute( tmpl, type_attr );

   return CKR_OK;

}



