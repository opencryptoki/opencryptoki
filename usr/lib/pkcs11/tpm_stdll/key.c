
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


// File:  key.c
//
// Functions contained within:
//
//    key_object_check_required_attributes
//    key_object_set_default_attributes
//    key_object_validate_attribute
//
//    publ_key_check_required_attributes
//    publ_key_set_default_attributes
//    publ_key_validate_attribute
//
//    priv_key_check_required_attributes
//    priv_key_set_default_attributes
//    priv_key_validate_attribute
//
//    secret_key_check_required_attributes
//    secret_key_set_default_attributes
//    secret_key_validate_attribute
//
//    rsa_publ_check_required_attributes
//    rsa_publ_validate_attribute
//    rsa_priv_check_required_attributes
//    rsa_priv_validate_attribute
//    rsa_priv_check_exportability
//
//    dsa_publ_check_required_attributes
//    dsa_publ_validate_attribute
//    dsa_priv_check_required_attributes
//    dsa_priv_validate_attribute
//    dsa_priv_check_exportability
//
//    ecdsa_publ_check_required_attributes
//    ecdsa_publ_validate_attribute
//    ecdsa_priv_checK_required_attributes
//    ecdsa_priv_validate_attribute
//    ecdsa_priv_check_exportability
//
//    dh_publ_check_required_attributes
//    dh_publ_validate_attribute
//    dh_priv_check_required_attributes
//    dh_priv_validate_attribute
//    dh_priv_check_exportability
//
//    kea_publ_check_required_attributes
//    kea_publ_validate_attribute
//    kea_priv_check_required_attributes
//    kea_priv_validate_attribute
//    kea_priv_check_exportability
//
//    generic_secret_check_required_attributes
//    generic_secret_validate_attribute
//
//    rc2_check_required_attributes
//    rc2_validate_attribute
//    rc2_priv_check_exportability
//
//    rc4_check_required_attributes
//    rc4_validate_attribute
//    rc4_priv_check_exportability
//
//    rc5_check_required_attributes
//    rc5_validate_attribute
//    rc5_priv_check_exportability
//
//    des_check_required_attributes
//    des_validate_attribute
//    des_priv_check_exportability
//
//    des2_check_required_attributes
//    des2_validate_attribute
//    des2_priv_check_exportability
//
//    des3_check_required_attributes
//    des3_validate_attribute
//    des3_priv_check_exportability
//
//    cast_check_required_attributes
//    cast_validate_attribute
//    cast_priv_check_exportability
//
//    cast3_check_required_attributes
//    cast3_validate_attribute
//    cast3_priv_check_exportability
//
//    cast5_check_required_attributes
//    cast5_validate_attribute
//    cast5_priv_check_exportability
//
//    idea_check_required_attributes
//    idea_validate_attribute
//    idea_priv_check_exportability
//
//    cdmf_check_required_attributes
//    cdmf_validate_attribute
//    cdmf_priv_check_exportability
//
//    skipjack_check_required_attributes
//    skipjack_validate_attribute
//    skipjack_priv_check_exportability
//
//    baton_check_required_attributes
//    baton_validate_attribute
//    baton_priv_check_exportability
//
//    juniper_check_required_attributes
//    juniper_validate_attribute
//    juniper_priv_check_exportability
//

//#include <windows.h>

#include <pthread.h>
#include <stdlib.h>

  #include <string.h>  // for memcmp() et al

#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"

#include "tok_spec_struct.h"
//#include "args.h"


// key_object_check_required_attributes()
//
// Check required common attributes for key objects
//
CK_RV
key_object_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
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


//  key_object_set_default_attributes()
//
CK_RV
key_object_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE * id_attr     = NULL;
   CK_ATTRIBUTE * sdate_attr  = NULL;
   CK_ATTRIBUTE * edate_attr  = NULL;
   CK_ATTRIBUTE * derive_attr = NULL;
   CK_ATTRIBUTE * local_attr  = NULL;

   // satisfy the compiler
   //
   if (mode)
      id_attr = NULL;

   id_attr        = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE)                    );
   sdate_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE)                    );
   edate_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE)                    );
   derive_attr    = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   local_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );

   if (!id_attr || !sdate_attr || !edate_attr || !derive_attr || !local_attr) {
      if (id_attr)      free( id_attr     );
      if (sdate_attr)   free( sdate_attr  );
      if (edate_attr)   free( edate_attr  );
      if (derive_attr)  free( derive_attr );
      if (local_attr)   free( local_attr  );
      st_err_log(1, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }

   id_attr->type           = CKA_ID;
   id_attr->ulValueLen     = 0;
   id_attr->pValue         = NULL;

   sdate_attr->type        = CKA_START_DATE;
   sdate_attr->ulValueLen  = 0;
   sdate_attr->pValue      = NULL;

   edate_attr->type        = CKA_END_DATE;
   edate_attr->ulValueLen  = 0;
   edate_attr->pValue      = NULL;

   derive_attr->type       = CKA_DERIVE;
   derive_attr->ulValueLen = sizeof(CK_BBOOL);
   derive_attr->pValue     = (CK_BYTE *)derive_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)derive_attr->pValue = FALSE;

   local_attr->type        = CKA_LOCAL;
   local_attr->ulValueLen  = sizeof(CK_BBOOL);
   local_attr->pValue      = (CK_BYTE *)local_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)local_attr->pValue = FALSE;

   template_update_attribute( tmpl, id_attr     );
   template_update_attribute( tmpl, sdate_attr  );
   template_update_attribute( tmpl, edate_attr  );
   template_update_attribute( tmpl, derive_attr );
   template_update_attribute( tmpl, local_attr  );

   return CKR_OK;
}


// key_object_validate_attribute()
//
CK_RV
key_object_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode)
{
   switch (attr->type) {
      case CKA_KEY_TYPE:
         if (mode == MODE_CREATE || mode == MODE_DERIVE ||
             mode == MODE_KEYGEN || mode == MODE_UNWRAP)
            return CKR_OK;
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_ID:
      case CKA_START_DATE:
      case CKA_END_DATE:
      case CKA_DERIVE:
         return CKR_OK;

      case CKA_LOCAL:
         // CKA_LOCAL is only set by the key-generate routine
         //
         st_err_log(7, __FILE__, __LINE__);
         return CKR_ATTRIBUTE_READ_ONLY;

      default:
         return template_validate_base_attribute( tmpl, attr, mode );
   }

   st_err_log(8, __FILE__, __LINE__);
   return CKR_ATTRIBUTE_TYPE_INVALID;
}


// publ_key_check_required_attributes()
//
CK_RV
publ_key_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   // CKO_PUBLIC_KEY has no required attributes
   //
   return key_object_check_required_attributes( tmpl, mode );
}


// publ_key_set_default_attributes()
//
// some of the common public key attributes have defaults but none of the specific
// public keytypes have default attributes
//
CK_RV
publ_key_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE    *class_attr          = NULL;
   CK_ATTRIBUTE    *subject_attr        = NULL;
   CK_ATTRIBUTE    *encrypt_attr        = NULL;
   CK_ATTRIBUTE    *verify_attr         = NULL;
   CK_ATTRIBUTE    *verify_recover_attr = NULL;
   CK_ATTRIBUTE    *wrap_attr           = NULL;

   CK_OBJECT_CLASS  class = CKO_PUBLIC_KEY;
   CK_RV            rc;


   rc = key_object_set_default_attributes( tmpl, mode );
   if (rc != CKR_OK){
      st_err_log(172, __FILE__, __LINE__);
      return rc;
   }
   // add the default CKO_PUBLIC_KEY attributes
   //
   class_attr          = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS) );
   subject_attr        = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   encrypt_attr        = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   verify_attr         = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   verify_recover_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   wrap_attr           = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );

   if (!class || !subject_attr || !encrypt_attr ||
       !verify_attr  || !verify_recover_attr || !wrap_attr)
   {
      if (class_attr)          free( class_attr );
      if (subject_attr)        free( subject_attr );
      if (encrypt_attr)        free( encrypt_attr );
      if (verify_attr)         free( verify_attr );
      if (verify_recover_attr) free( verify_recover_attr );
      if (wrap_attr)           free( wrap_attr );

      st_err_log(1, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }

   class_attr->type           = CKA_CLASS;
   class_attr->ulValueLen     = sizeof(CK_OBJECT_CLASS);
   class_attr->pValue         = (CK_BYTE *)class_attr + sizeof(CK_ATTRIBUTE);
   *(CK_OBJECT_CLASS *)class_attr->pValue = CKO_PUBLIC_KEY;

   subject_attr->type         = CKA_SUBJECT;
   subject_attr->ulValueLen   = 0;  // empty string
   subject_attr->pValue       = NULL;

   encrypt_attr->type          = CKA_ENCRYPT;
   encrypt_attr->ulValueLen    = sizeof(CK_BBOOL);
   encrypt_attr->pValue        = (CK_BYTE *)encrypt_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)encrypt_attr->pValue = TRUE;

   verify_attr->type          = CKA_VERIFY;
   verify_attr->ulValueLen    = sizeof(CK_BBOOL);
   verify_attr->pValue        = (CK_BYTE *)verify_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)verify_attr->pValue = TRUE;

   verify_recover_attr->type          = CKA_VERIFY_RECOVER;
   verify_recover_attr->ulValueLen    = sizeof(CK_BBOOL);
   verify_recover_attr->pValue        = (CK_BYTE *)verify_recover_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)verify_recover_attr->pValue = TRUE;

   wrap_attr->type          = CKA_WRAP;
   wrap_attr->ulValueLen    = sizeof(CK_BBOOL);
   wrap_attr->pValue        = (CK_BYTE *)wrap_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)wrap_attr->pValue = TRUE;

   template_update_attribute( tmpl, class_attr          );
   template_update_attribute( tmpl, subject_attr        );
   template_update_attribute( tmpl, encrypt_attr        );
   template_update_attribute( tmpl, verify_attr         );
   template_update_attribute( tmpl, verify_recover_attr );
   template_update_attribute( tmpl, wrap_attr           );

   return CKR_OK;
}


// publ_key_validate_attribute
//
CK_RV
publ_key_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_SUBJECT:
         return CKR_OK;

      case CKA_ENCRYPT:
      case CKA_VERIFY:
      case CKA_VERIFY_RECOVER:
      case CKA_WRAP:
         if (mode == MODE_MODIFY) {
            if (nv_token_data->tweak_vector.allow_key_mods == TRUE)
               return CKR_OK;
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
         return CKR_OK;

      default:
         return key_object_validate_attribute( tmpl, attr, mode );
   }

   st_err_log(8, __FILE__, __LINE__);
   return CKR_ATTRIBUTE_TYPE_INVALID;
}


// priv_key_check_required_attributes()
//
CK_RV
priv_key_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   // CKO_PRIVATE_KEY has no required attributes
   //
   return key_object_check_required_attributes( tmpl, mode );
}


// priv_key_set_default_attributes()
//
// some of the common private key attributes have defaults but none of the specific
// private keytypes have default attributes
//
CK_RV
priv_key_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE    *class_attr        = NULL;
   CK_ATTRIBUTE    *subject_attr      = NULL;
   CK_ATTRIBUTE    *sensitive_attr    = NULL;
   CK_ATTRIBUTE    *decrypt_attr      = NULL;
   CK_ATTRIBUTE    *sign_attr         = NULL;
   CK_ATTRIBUTE    *sign_recover_attr = NULL;
   CK_ATTRIBUTE    *unwrap_attr       = NULL;
   CK_ATTRIBUTE    *extractable_attr  = NULL;
   CK_ATTRIBUTE    *never_extr_attr   = NULL;
   CK_ATTRIBUTE    *always_sens_attr  = NULL;
   CK_RV            rc;


   rc = key_object_set_default_attributes( tmpl, mode );
   if (rc != CKR_OK){
      st_err_log(172, __FILE__, __LINE__);
      return rc;
   }
   // add the default CKO_PUBLIC_KEY attributes
   //
   class_attr        = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS) );
   subject_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   sensitive_attr    = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   decrypt_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   sign_attr         = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   sign_recover_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   unwrap_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   extractable_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   never_extr_attr   = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   always_sens_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );

   if (!class_attr || !subject_attr      || !sensitive_attr || !decrypt_attr ||
       !sign_attr  || !sign_recover_attr || !unwrap_attr    || !extractable_attr ||
       !never_extr_attr || !always_sens_attr )
   {
      if (class_attr)        free( class_attr );
      if (subject_attr)      free( subject_attr );
      if (sensitive_attr)    free( sensitive_attr );
      if (decrypt_attr)      free( decrypt_attr );
      if (sign_attr)         free( sign_attr );
      if (sign_recover_attr) free( sign_recover_attr );
      if (unwrap_attr)       free( unwrap_attr );
      if (extractable_attr)  free( extractable_attr );
      if (always_sens_attr)  free( always_sens_attr );
      if (never_extr_attr)   free( never_extr_attr );

      st_err_log(1, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }

   class_attr->type       = CKA_CLASS;
   class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
   class_attr->pValue     = (CK_BYTE *)class_attr + sizeof(CK_ATTRIBUTE);
   *(CK_OBJECT_CLASS *)class_attr->pValue = CKO_PRIVATE_KEY;

   subject_attr->type       = CKA_SUBJECT;
   subject_attr->ulValueLen = 0;  // empty string
   subject_attr->pValue     = NULL;

   sensitive_attr->type       = CKA_SENSITIVE;
   sensitive_attr->ulValueLen = sizeof(CK_BBOOL);
   sensitive_attr->pValue     = (CK_BYTE *)sensitive_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)sensitive_attr->pValue = FALSE;

   decrypt_attr->type       = CKA_DECRYPT;
   decrypt_attr->ulValueLen = sizeof(CK_BBOOL);
   decrypt_attr->pValue     = (CK_BYTE *)decrypt_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)decrypt_attr->pValue = TRUE;

   sign_attr->type       = CKA_SIGN;
   sign_attr->ulValueLen = sizeof(CK_BBOOL);
   sign_attr->pValue     = (CK_BYTE *)sign_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)sign_attr->pValue = TRUE;

   sign_recover_attr->type       = CKA_SIGN_RECOVER;
   sign_recover_attr->ulValueLen = sizeof(CK_BBOOL);
   sign_recover_attr->pValue     = (CK_BYTE *)sign_recover_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)sign_recover_attr->pValue = TRUE;

   unwrap_attr->type       = CKA_UNWRAP;
   unwrap_attr->ulValueLen = sizeof(CK_BBOOL);
   unwrap_attr->pValue     = (CK_BYTE *)unwrap_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)unwrap_attr->pValue = TRUE;

   extractable_attr->type       = CKA_EXTRACTABLE;
   extractable_attr->ulValueLen = sizeof(CK_BBOOL);
   extractable_attr->pValue     = (CK_BYTE *)extractable_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)extractable_attr->pValue = TRUE;

   // by default, we'll set NEVER_EXTRACTABLE == FALSE and ALWAYS_SENSITIVE == FALSE
   // If the key is being created with KEYGEN, it will adjust as necessary.
   //
   never_extr_attr->type       = CKA_NEVER_EXTRACTABLE;
   never_extr_attr->ulValueLen = sizeof(CK_BBOOL);
   never_extr_attr->pValue     = (CK_BYTE *)never_extr_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)never_extr_attr->pValue = FALSE;

   always_sens_attr->type       = CKA_ALWAYS_SENSITIVE;
   always_sens_attr->ulValueLen = sizeof(CK_BBOOL);
   always_sens_attr->pValue     = (CK_BYTE *)always_sens_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)always_sens_attr->pValue = FALSE;

   template_update_attribute( tmpl, class_attr );
   template_update_attribute( tmpl, subject_attr );
   template_update_attribute( tmpl, sensitive_attr );
   template_update_attribute( tmpl, decrypt_attr );
   template_update_attribute( tmpl, sign_attr );
   template_update_attribute( tmpl, sign_recover_attr );
   template_update_attribute( tmpl, unwrap_attr );
   template_update_attribute( tmpl, extractable_attr );
   template_update_attribute( tmpl, never_extr_attr );
   template_update_attribute( tmpl, always_sens_attr );

   return CKR_OK;
}


//
//
CK_RV
priv_key_unwrap( TEMPLATE *tmpl,
                 CK_ULONG  keytype,
                 CK_BYTE  *data,
                 CK_ULONG  data_len )
{
   CK_ATTRIBUTE *extractable   = NULL;
   CK_ATTRIBUTE *always_sens   = NULL;
   CK_ATTRIBUTE *never_extract = NULL;
   CK_ATTRIBUTE *sensitive     = NULL;
   CK_ATTRIBUTE *local         = NULL;
   CK_BBOOL   true  = TRUE;
   CK_BBOOL   false = FALSE;
   CK_RV      rc;

   switch (keytype) {
      case CKK_RSA:
         rc = rsa_priv_unwrap( tmpl, data, data_len );
         break;

      case CKK_DSA:
         rc = dsa_priv_unwrap( tmpl, data, data_len );
         break;

      default:
         st_err_log(62, __FILE__, __LINE__);
         return CKR_WRAPPED_KEY_INVALID;
   }

   if (rc != CKR_OK) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return rc;
   }

   // make sure
   //    CKA_LOCAL             == FALSE
   //    CKA_ALWAYS_SENSITIVE  == FALSE
   //    CKA_EXTRACTABLE       == TRUE
   //    CKA_NEVER_EXTRACTABLE == FALSE
   //
   rc = build_attribute( CKA_LOCAL,  &false, 1, &local );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto cleanup;
   }
   rc = build_attribute( CKA_ALWAYS_SENSITIVE,  &false, 1, &always_sens );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto cleanup;
   }
   rc = build_attribute( CKA_SENSITIVE,         &false, 1, &sensitive );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto cleanup;
   }
   rc = build_attribute( CKA_EXTRACTABLE,       &true,  1, &extractable );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto cleanup;
   }
   rc = build_attribute( CKA_NEVER_EXTRACTABLE, &false, 1, &never_extract );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto cleanup;
   }
   template_update_attribute( tmpl, local );
   template_update_attribute( tmpl, always_sens );
   template_update_attribute( tmpl, sensitive );
   template_update_attribute( tmpl, extractable );
   template_update_attribute( tmpl, never_extract );

   return CKR_OK;

cleanup:

   if (local)         free(local);
   if (always_sens)   free(always_sens);
   if (extractable)   free(extractable);
   if (never_extract) free(never_extract);

   return rc;
}


// priv_key_validate_attribute()
//
CK_RV
priv_key_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_SUBJECT:
         return CKR_OK;

      case CKA_DECRYPT:
      case CKA_SIGN:
      case CKA_SIGN_RECOVER:
      case CKA_UNWRAP:
         // we might want to do this for MODE_COPY too
         //
         if (mode == MODE_MODIFY) {
            if (nv_token_data->tweak_vector.allow_key_mods == TRUE)
               return CKR_OK;
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
         return CKR_OK;

      // after key creation, CKA_SENSITIVE may only be set to TRUE
      //
      case CKA_SENSITIVE:
         {
            CK_BBOOL value;

            if (mode == MODE_CREATE || mode == MODE_KEYGEN)
               return CKR_OK;

            value = *(CK_BBOOL *)attr->pValue;
            if (value != TRUE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
         }
         return CKR_OK;

      // after key creation, CKA_EXTRACTABLE may only be set to FALSE
      //
      case CKA_EXTRACTABLE:
         {
            CK_BBOOL value;

            value = *(CK_BBOOL *)attr->pValue;
            if ((mode != MODE_CREATE && mode != MODE_KEYGEN) && value != FALSE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (value == FALSE) {
               CK_ATTRIBUTE *attr;

               attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
               if (!attr){
                  st_err_log(1, __FILE__, __LINE__);
                  return CKR_HOST_MEMORY;
               }
               attr->type       = CKA_NEVER_EXTRACTABLE;
               attr->ulValueLen = sizeof(CK_BBOOL);
               attr->pValue     = (CK_BYTE *)attr + sizeof(CK_ATTRIBUTE);
               *(CK_BBOOL *)attr->pValue = FALSE;

               template_update_attribute( tmpl, attr );
            }
	 }
         return CKR_OK;

      case CKA_IBM_OPAQUE:
         {
	    CK_ATTRIBUTE *new_attr;

            if (mode != MODE_CREATE && mode != MODE_KEYGEN){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
	    new_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
	    if (!new_attr){
	       st_err_log(1, __FILE__, __LINE__);
	       return CKR_HOST_MEMORY;
	    }
	    new_attr->type       = CKA_IBM_OPAQUE;
	    new_attr->ulValueLen = attr->ulValueLen;
	    new_attr->pValue     = malloc(attr->ulValueLen);
	    if (new_attr->pValue == NULL) {
	       st_err_log(1, __FILE__, __LINE__);
	       return CKR_HOST_MEMORY;
	    }
	    memcpy(new_attr->pValue, attr->pValue, new_attr->ulValueLen);

	    template_update_attribute( tmpl, new_attr );
	 }
         return CKR_OK;

      case CKA_ALWAYS_SENSITIVE:
      case CKA_NEVER_EXTRACTABLE:
         st_err_log(7, __FILE__, __LINE__);
         return CKR_ATTRIBUTE_READ_ONLY;

      default:
         return key_object_validate_attribute( tmpl, attr, mode );
   }

   st_err_log(8, __FILE__, __LINE__);
   return CKR_ATTRIBUTE_TYPE_INVALID;
}




// secret_key_check_required_attributes()
//
CK_RV
secret_key_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   return key_object_check_required_attributes( tmpl, mode );
}


// secret_key_set_default_attributes()
//
// some of the common secret key attributes have defaults but none of the specific
// secret keytypes have default attributes
//
CK_RV
secret_key_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE       *class_attr       = NULL;
   CK_ATTRIBUTE       *sensitive_attr   = NULL;
   CK_ATTRIBUTE       *encrypt_attr     = NULL;
   CK_ATTRIBUTE       *decrypt_attr     = NULL;
   CK_ATTRIBUTE       *sign_attr        = NULL;
   CK_ATTRIBUTE       *verify_attr      = NULL;
   CK_ATTRIBUTE       *wrap_attr        = NULL;
   CK_ATTRIBUTE       *unwrap_attr      = NULL;
   CK_ATTRIBUTE       *extractable_attr = NULL;
   CK_ATTRIBUTE       *never_extr_attr  = NULL;
   CK_ATTRIBUTE       *always_sens_attr = NULL;
   CK_RV            rc;


   rc = key_object_set_default_attributes( tmpl, mode );
   if (rc != CKR_OK)
      return rc;

   // add the default CKO_DATA attributes
   //
   class_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS) );
   sensitive_attr   = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   encrypt_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   decrypt_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   sign_attr        = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   verify_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   wrap_attr        = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   unwrap_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   extractable_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   never_extr_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
   always_sens_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );

   if (!class_attr  || !sensitive_attr || !encrypt_attr  || !decrypt_attr ||
       !sign_attr   || !verify_attr    || !wrap_attr     ||
       !unwrap_attr || !extractable_attr || !never_extr_attr || !always_sens_attr)
   {
      if (class_attr)       free( class_attr );
      if (sensitive_attr)   free( sensitive_attr );
      if (encrypt_attr)     free( encrypt_attr );
      if (decrypt_attr)     free( decrypt_attr );
      if (sign_attr)        free( sign_attr );
      if (verify_attr)      free( verify_attr );
      if (wrap_attr)        free( wrap_attr );
      if (unwrap_attr)      free( unwrap_attr );
      if (extractable_attr) free( extractable_attr );
      if (never_extr_attr)  free( never_extr_attr );
      if (always_sens_attr) free( always_sens_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   class_attr->type       = CKA_CLASS;
   class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
   class_attr->pValue     = (CK_BYTE *)class_attr + sizeof(CK_ATTRIBUTE);
   *(CK_OBJECT_CLASS *)class_attr->pValue = CKO_SECRET_KEY;

   sensitive_attr->type       = CKA_SENSITIVE;
   sensitive_attr->ulValueLen = sizeof(CK_BBOOL);
   sensitive_attr->pValue     = (CK_BYTE *)sensitive_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)sensitive_attr->pValue = FALSE;

   encrypt_attr->type       = CKA_ENCRYPT;
   encrypt_attr->ulValueLen = sizeof(CK_BBOOL);
   encrypt_attr->pValue     = (CK_BYTE *)encrypt_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)encrypt_attr->pValue = TRUE;

   decrypt_attr->type       = CKA_DECRYPT;
   decrypt_attr->ulValueLen = sizeof(CK_BBOOL);
   decrypt_attr->pValue     = (CK_BYTE *)decrypt_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)decrypt_attr->pValue = TRUE;

   sign_attr->type       = CKA_SIGN;
   sign_attr->ulValueLen = sizeof(CK_BBOOL);
   sign_attr->pValue     = (CK_BYTE *)sign_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)sign_attr->pValue = TRUE;

   verify_attr->type       = CKA_VERIFY;
   verify_attr->ulValueLen = sizeof(CK_BBOOL);
   verify_attr->pValue     = (CK_BYTE *)verify_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)verify_attr->pValue = TRUE;

   wrap_attr->type       = CKA_WRAP;
   wrap_attr->ulValueLen = sizeof(CK_BBOOL);
   wrap_attr->pValue     = (CK_BYTE *)wrap_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)wrap_attr->pValue = TRUE;

   unwrap_attr->type       = CKA_UNWRAP;
   unwrap_attr->ulValueLen = sizeof(CK_BBOOL);
   unwrap_attr->pValue     = (CK_BYTE *)unwrap_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)unwrap_attr->pValue = TRUE;

   extractable_attr->type       = CKA_EXTRACTABLE;
   extractable_attr->ulValueLen = sizeof(CK_BBOOL);
   extractable_attr->pValue     = (CK_BYTE *)extractable_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)extractable_attr->pValue = TRUE;

   // by default, we'll set NEVER_EXTRACTABLE == FALSE and ALWAYS_SENSITIVE == FALSE
   // If the key is being created with KEYGEN, it will adjust as necessary.
   //
   always_sens_attr->type       = CKA_ALWAYS_SENSITIVE;
   always_sens_attr->ulValueLen = sizeof(CK_BBOOL);
   always_sens_attr->pValue     = (CK_BYTE *)always_sens_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)always_sens_attr->pValue = FALSE;

   never_extr_attr->type       = CKA_NEVER_EXTRACTABLE;
   never_extr_attr->ulValueLen = sizeof(CK_BBOOL);
   never_extr_attr->pValue     = (CK_BYTE *)never_extr_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)never_extr_attr->pValue = FALSE;

   template_update_attribute( tmpl, class_attr );
   template_update_attribute( tmpl, sensitive_attr );
   template_update_attribute( tmpl, encrypt_attr );
   template_update_attribute( tmpl, decrypt_attr );
   template_update_attribute( tmpl, sign_attr );
   template_update_attribute( tmpl, verify_attr );
   template_update_attribute( tmpl, wrap_attr );
   template_update_attribute( tmpl, unwrap_attr );
   template_update_attribute( tmpl, extractable_attr );
   template_update_attribute( tmpl, never_extr_attr );
   template_update_attribute( tmpl, always_sens_attr );

   return CKR_OK;
}


//
//
CK_RV
secret_key_unwrap( TEMPLATE *tmpl,
                   CK_ULONG  keytype,
                   CK_BYTE  *data,
                   CK_ULONG  data_len,
                   CK_BBOOL  fromend )
{
   CK_ATTRIBUTE *local         = NULL;
   CK_ATTRIBUTE *always_sens   = NULL;
   CK_ATTRIBUTE *sensitive     = NULL;
   CK_ATTRIBUTE *extractable   = NULL;
   CK_ATTRIBUTE *never_extract = NULL;
   CK_BBOOL   true  = TRUE;
   CK_BBOOL   false = FALSE;
   CK_RV      rc;

   switch (keytype) {
      case CKK_CDMF:
      case CKK_DES:
         rc = des_unwrap( tmpl, data, data_len, fromend );
         break;

      case CKK_DES3:
         rc = des3_unwrap( tmpl, data, data_len, fromend );
         break;

      case CKK_AES:
	 rc = aes_unwrap( tmpl, data, data_len, fromend );
	 break;

      case CKK_GENERIC_SECRET:
      case CKK_RC2:
      case CKK_RC4:
      case CKK_RC5:
      case CKK_CAST:
      case CKK_CAST3:
      case CKK_CAST5:
         rc = generic_secret_unwrap( tmpl, data, data_len, fromend );
         break;

      default:
         st_err_log(62, __FILE__, __LINE__);
         return CKR_WRAPPED_KEY_INVALID;
   }

   if (rc != CKR_OK)
      return rc;

   // make sure
   //    CKA_LOCAL             == FALSE
   //    CKA_ALWAYS_SENSITIVE  == FALSE
   //    CKA_EXTRACTABLE       == TRUE
   //    CKA_NEVER_EXTRACTABLE == FALSE
   //
   rc = build_attribute( CKA_LOCAL,             &false, 1, &local );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto cleanup;
   }
   rc = build_attribute( CKA_ALWAYS_SENSITIVE,  &false, 1, &always_sens );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto cleanup;
   }
   rc = build_attribute( CKA_SENSITIVE,         &false, 1, &sensitive );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto cleanup;
   }
   rc = build_attribute( CKA_EXTRACTABLE,       &true,  1, &extractable );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto cleanup;
   }
   rc = build_attribute( CKA_NEVER_EXTRACTABLE, &false, 1, &never_extract );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto cleanup;
   }
   template_update_attribute( tmpl, local );
   template_update_attribute( tmpl, always_sens );
   template_update_attribute( tmpl, sensitive );
   template_update_attribute( tmpl, extractable );
   template_update_attribute( tmpl, never_extract );

   return CKR_OK;

cleanup:

   if (local)         free(local);
   if (extractable)   free(extractable);
   if (always_sens)   free(always_sens);
   if (never_extract) free(never_extract);

   return rc;
}




// secret_key_validate_attribute()
//
CK_RV
secret_key_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_ENCRYPT:
      case CKA_DECRYPT:
      case CKA_SIGN:
      case CKA_VERIFY:
      case CKA_WRAP:
      case CKA_UNWRAP:
         if (mode == MODE_MODIFY) {
            if (nv_token_data->tweak_vector.allow_key_mods == TRUE)
               return CKR_OK;
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
         return CKR_OK;

      // after key creation, CKA_SENSITIVE may only be set to TRUE
      //
      case CKA_SENSITIVE:
         {
            CK_BBOOL value;

            value = *(CK_BBOOL *)attr->pValue;
            if ((mode != MODE_CREATE && mode != MODE_DERIVE && mode !=
MODE_KEYGEN) && (value != TRUE)){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
         }
         return CKR_OK;

      // after key creation, CKA_EXTRACTABLE may only be set to FALSE
      //
      case CKA_EXTRACTABLE:
         {
            CK_BBOOL value;

            // the unwrap routine will automatically set extractable to TRUE
            //
            value = *(CK_BBOOL *)attr->pValue;
            if ((mode != MODE_CREATE && mode != MODE_DERIVE && mode !=
MODE_KEYGEN) && (value != FALSE)){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (value == FALSE) {
               CK_ATTRIBUTE *attr;

               attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );
               if (!attr){
                  st_err_log(1, __FILE__, __LINE__);
                  return CKR_HOST_MEMORY;
               }
               attr->type = CKA_NEVER_EXTRACTABLE;
               attr->ulValueLen = sizeof(CK_BBOOL);
               attr->pValue     = (CK_BYTE *)attr + sizeof(CK_ATTRIBUTE);
               *(CK_BBOOL *)attr->pValue = FALSE;

               template_update_attribute( tmpl, attr );
            }
         }
         return CKR_OK;

      case CKA_ALWAYS_SENSITIVE:
      case CKA_NEVER_EXTRACTABLE:
         st_err_log(7, __FILE__, __LINE__);
         return CKR_ATTRIBUTE_READ_ONLY;

      default:
         return key_object_validate_attribute( tmpl, attr, mode );
   }

   st_err_log(8, __FILE__, __LINE__);
   return CKR_ATTRIBUTE_TYPE_INVALID;
}


// secret_key_check_exportability()
//
CK_BBOOL
secret_key_check_exportability( CK_ATTRIBUTE_TYPE type )
{
   switch (type) {
      case CKA_VALUE:
         st_err_log(86, __FILE__, __LINE__);
         return FALSE;
   }

   return TRUE;
}


// rsa_publ_check_required_attributes()
//
CK_RV
rsa_publ_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;


   found = template_attribute_find( tmpl, CKA_MODULUS, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_MODULUS_BITS, &attr );
   if (!found) {
      if (mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_PUBLIC_EXPONENT, &attr );
   if (!found) {
      if (mode == MODE_CREATE || mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return publ_key_check_required_attributes( tmpl, mode );
}


//  rsa_publ_set_default_attributes()
//
CK_RV
rsa_publ_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *type_attr         = NULL;
   CK_ATTRIBUTE   *modulus_attr      = NULL;
   CK_ATTRIBUTE   *modulus_bits_attr = NULL;
   CK_ATTRIBUTE   *public_exp_attr   = NULL;
   CK_ULONG        bits = 0L;

   publ_key_set_default_attributes( tmpl, mode );

   type_attr         = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   modulus_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   modulus_bits_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );
   public_exp_attr   = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !modulus_attr || !modulus_bits_attr || !public_exp_attr) {
      if (type_attr)         free( type_attr );
      if (modulus_attr)      free( modulus_attr );
      if (modulus_bits_attr) free( modulus_bits_attr );
      if (public_exp_attr)   free( public_exp_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_RSA;

   modulus_attr->type       = CKA_MODULUS;
   modulus_attr->ulValueLen = 0;
   modulus_attr->pValue     = NULL;

   modulus_bits_attr->type       = CKA_MODULUS_BITS;
   modulus_bits_attr->ulValueLen = sizeof(CK_ULONG);
   modulus_bits_attr->pValue     = (CK_BYTE *)modulus_bits_attr + sizeof(CK_ATTRIBUTE);
   *(CK_ULONG *)modulus_bits_attr->pValue = bits;

   public_exp_attr->type       = CKA_PUBLIC_EXPONENT;
   public_exp_attr->ulValueLen = 0;
   public_exp_attr->pValue     = NULL;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, modulus_attr );
   template_update_attribute( tmpl, modulus_bits_attr );
   template_update_attribute( tmpl, public_exp_attr );

   return CKR_OK;
}


// rsa_publ_validate_attributes()
//
CK_RV
rsa_publ_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_MODULUS_BITS:
         if (mode == MODE_KEYGEN) {
            if (attr->ulValueLen != sizeof(CK_ULONG)){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else {
               CK_ULONG mod_bits = *(CK_ULONG *)attr->pValue;

               if (mod_bits < 512 || mod_bits > 2048){
                  st_err_log(9, __FILE__, __LINE__);
                  return CKR_ATTRIBUTE_VALUE_INVALID;
               }

               if (mod_bits % 8 != 0){
                  st_err_log(9, __FILE__, __LINE__);
                  return CKR_ATTRIBUTE_VALUE_INVALID;
               }
               return CKR_OK;
            }
         }
         else{ 
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_MODULUS:
         if (mode == MODE_CREATE)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_PUBLIC_EXPONENT:
         if (mode == MODE_CREATE || mode == MODE_KEYGEN)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      default:
         return publ_key_validate_attribute( tmpl, attr, mode );
   }
}


// rsa_priv_check_required_attributes()
//
CK_RV
rsa_priv_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;


   found = template_attribute_find( tmpl, CKA_MODULUS, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }


   //
   // PKCS #11 is flexible with respect to which attributes must be present
   // in an RSA key.  Keys can be specified in Chinese-Remainder format or
   // they can be specified in modular-exponent format.  Right now, I only
   // support keys created in Chinese-Remainder format.  That is, we return
   // CKR_TEMPLATE_INCOMPLETE if a modular-exponent key is specified.  This
   // is allowed by PKCS #11.
   //
   // In the future, we should allow for creation of keys in modular-exponent
   // format too.  This raises some issues.  It's easy enough to recognize
   // when a key has been specified in modular-exponent format.  And it's
   // easy enough to recognize when all attributes have been specified
   // (which is what we require right now).  What's trickier to handle is
   // the "middle" cases in which more than the minimum yet less than the
   // full number of attributes have been specified.  Do we revert back to
   // modular-exponent representation?  Do we compute the missing attributes
   // ourselves?  Do we simply return CKR_TEMPLATE_INCOMPLETE?
   //

   found = template_attribute_find( tmpl, CKA_PUBLIC_EXPONENT, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_PRIVATE_EXPONENT, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_PRIME_1, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_PRIME_2, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_EXPONENT_1, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_EXPONENT_2, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_COEFFICIENT, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   // we should probably verify that the (e != p) and (e != q). ie. gcd(e,n) == 1
   //

   return priv_key_check_required_attributes( tmpl, mode );
}


//  rsa_priv_set_default_attributes()
//
CK_RV
rsa_priv_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *modulus_attr      = NULL;
   CK_ATTRIBUTE   *public_exp_attr   = NULL;
   CK_ATTRIBUTE   *private_exp_attr  = NULL;
   CK_ATTRIBUTE   *type_attr         = NULL;

   // satisfy the compiler
   //
   if (mode)
      modulus_attr = NULL;

   priv_key_set_default_attributes( tmpl, mode );

   type_attr         = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   modulus_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   public_exp_attr   = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   private_exp_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !modulus_attr || !public_exp_attr || !private_exp_attr) {
      if (type_attr)        free( type_attr );
      if (modulus_attr)     free( modulus_attr );
      if (public_exp_attr)  free( public_exp_attr );
      if (private_exp_attr) free( private_exp_attr );

      st_err_log(1, __FILE__, __LINE__);
      return CKR_HOST_MEMORY;
   }

   modulus_attr->type       = CKA_MODULUS;
   modulus_attr->ulValueLen = 0;
   modulus_attr->pValue     = NULL;

   public_exp_attr->type       = CKA_PUBLIC_EXPONENT;
   public_exp_attr->ulValueLen = 0;
   public_exp_attr->pValue     = NULL;

   private_exp_attr->type       = CKA_PRIVATE_EXPONENT;
   private_exp_attr->ulValueLen = 0;
   private_exp_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_RSA;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, modulus_attr );
   template_update_attribute( tmpl, public_exp_attr );
   template_update_attribute( tmpl, private_exp_attr );

   return CKR_OK;
}


// rsa_priv_validate_attributes()
//
CK_RV
rsa_priv_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_MODULUS:
      case CKA_PRIVATE_EXPONENT:
         if (mode == MODE_CREATE)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_PUBLIC_EXPONENT:
      case CKA_PRIME_1:
      case CKA_PRIME_2:
      case CKA_EXPONENT_1:
      case CKA_EXPONENT_2:
      case CKA_COEFFICIENT:
         if (mode == MODE_CREATE)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      default:
         return priv_key_validate_attribute( tmpl, attr, mode );
   }
}


// rsa_priv_check_exportability()
//
CK_BBOOL
rsa_priv_check_exportability( CK_ATTRIBUTE_TYPE type )
{
   switch (type) {
      case CKA_PRIVATE_EXPONENT:
      case CKA_PRIME_1:
      case CKA_PRIME_2:
      case CKA_EXPONENT_1:
      case CKA_EXPONENT_2:
      case CKA_COEFFICIENT:
         st_err_log(86, __FILE__, __LINE__);
         return FALSE;
   }

   return TRUE;
}


// create the ASN.1 encoding for the private key for wrapping as defined
// in PKCS #8
//
// ASN.1 type PrivateKeyInfo ::= SEQUENCE {
//    version Version
//    privateKeyAlgorithm  PrivateKeyAlgorithmIdentifier
//    privateKey PrivateKey
//    attributes OPTIONAL
// }
//
// Where PrivateKey is defined as follows for RSA:
//
// ASN.1 type RSAPrivateKey
//
// RSAPrivateKey ::= SEQUENCE {
//   version Version
//   modulus INTEGER
//   publicExponent INTEGER
//   privateExponent INTEGER
//   prime1 INTEGER
//   prime2 INTEGER
//   exponent1 INTEGER
//   exponent2 INTEGER
//   coefficient INTEGER
// }
//
CK_RV
rsa_priv_wrap_get_data( TEMPLATE  *tmpl,
                        CK_BBOOL   length_only,
                        CK_BYTE  **data,
                        CK_ULONG  *data_len )
{
   CK_ATTRIBUTE *modulus   = NULL;
   CK_ATTRIBUTE *publ_exp  = NULL, *priv_exp  = NULL;
   CK_ATTRIBUTE *prime1    = NULL, *prime2    = NULL;
   CK_ATTRIBUTE *exponent1 = NULL, *exponent2 = NULL;
   CK_ATTRIBUTE *coeff     = NULL;
   CK_RV      rc;


   // compute the total length of the BER-encoded data
   //
   if (template_attribute_find(tmpl, CKA_MODULUS, &modulus) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED; 
   }
   if (template_attribute_find(tmpl, CKA_PUBLIC_EXPONENT, &publ_exp) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (template_attribute_find(tmpl, CKA_PRIVATE_EXPONENT, &priv_exp) ==
FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (template_attribute_find(tmpl, CKA_PRIME_1, &prime1) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (template_attribute_find(tmpl, CKA_PRIME_2, &prime2) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (template_attribute_find(tmpl, CKA_EXPONENT_1, &exponent1) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (template_attribute_find(tmpl, CKA_EXPONENT_2, &exponent2) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (template_attribute_find(tmpl, CKA_COEFFICIENT, &coeff) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = ber_encode_RSAPrivateKey( length_only, data, data_len,
                                  modulus,
                                  publ_exp,  priv_exp,
                                  prime1,    prime2,
                                  exponent1, exponent2,
                                  coeff );
   if (rc != CKR_OK){
      st_err_log(87, __FILE__, __LINE__);
   }
   return rc;
}


//
//
CK_RV
rsa_priv_unwrap( TEMPLATE *tmpl,
                 CK_BYTE  *data,
                 CK_ULONG  total_length )
{
   CK_ATTRIBUTE *modulus   = NULL;
   CK_ATTRIBUTE *publ_exp  = NULL;
   CK_ATTRIBUTE *priv_exp  = NULL;
   CK_ATTRIBUTE *prime1    = NULL;
   CK_ATTRIBUTE *prime2    = NULL;
   CK_ATTRIBUTE *exponent1 = NULL;
   CK_ATTRIBUTE *exponent2 = NULL;
   CK_ATTRIBUTE *coeff     = NULL;
   CK_RV      rc;

   rc = ber_decode_RSAPrivateKey( data,
                                  total_length,
                                  &modulus,
                                  &publ_exp,
                                  &priv_exp,
                                  &prime1,
                                  &prime2,
                                  &exponent1,
                                  &exponent2,
                                  &coeff );

   if (rc != CKR_OK){
      st_err_log(88, __FILE__, __LINE__);
      return rc;
   }
   remove_leading_zeros( modulus );
   remove_leading_zeros( publ_exp );
   remove_leading_zeros( priv_exp );
   remove_leading_zeros( prime1 );
   remove_leading_zeros( prime2 );
   remove_leading_zeros( exponent1 );
   remove_leading_zeros( exponent2 );
   remove_leading_zeros( coeff );

   template_update_attribute( tmpl, modulus );
   template_update_attribute( tmpl, publ_exp );
   template_update_attribute( tmpl, priv_exp );
   template_update_attribute( tmpl, prime1 );
   template_update_attribute( tmpl, prime2 );
   template_update_attribute( tmpl, exponent1 );
   template_update_attribute( tmpl, exponent2 );
   template_update_attribute( tmpl, coeff );

   return CKR_OK;
}


// dsa_publ_check_required_attributes()
//
CK_RV
dsa_publ_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;


   found = template_attribute_find( tmpl, CKA_PRIME, &attr );
   if (!found) {
      if (mode == MODE_CREATE || mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }
   found = template_attribute_find( tmpl, CKA_SUBPRIME, &attr );
   if (!found) {
      if (mode == MODE_CREATE || mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_BASE, &attr );
   if (!found) {
      if (mode == MODE_CREATE || mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return publ_key_check_required_attributes( tmpl, mode );
}


//  dsa_publ_set_default_attributes()
//
CK_RV
dsa_publ_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *prime_attr    = NULL;
   CK_ATTRIBUTE   *subprime_attr = NULL;
   CK_ATTRIBUTE   *base_attr     = NULL;
   CK_ATTRIBUTE   *value_attr    = NULL;
   CK_ATTRIBUTE   *type_attr     = NULL;

   if (mode)
      prime_attr = NULL;

   publ_key_set_default_attributes( tmpl, mode );

   type_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   prime_attr    = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   subprime_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   base_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_attr    = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !prime_attr || !subprime_attr || !base_attr || !value_attr) {
      if (type_attr)     free( type_attr );
      if (prime_attr)    free( prime_attr );
      if (subprime_attr) free( subprime_attr );
      if (base_attr)     free( base_attr );
      if (value_attr)    free( value_attr );
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

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_DSA;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, prime_attr );
   template_update_attribute( tmpl, subprime_attr );
   template_update_attribute( tmpl, base_attr );
   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}


// dsa_publ_validate_attributes()
//
CK_RV
dsa_publ_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_PRIME:
         {
            CK_ULONG size;

            if (mode != MODE_CREATE && mode != MODE_KEYGEN){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            // must be between [512, 1024] bits, and a multiple of 64 bits
            //
            size = attr->ulValueLen;
            if (size < 64 || size > 128 || (size % 8 != 0)){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            return remove_leading_zeros( attr );
         }

      case CKA_SUBPRIME:
         {
            if (mode != MODE_CREATE && mode != MODE_KEYGEN){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            // subprime must be 160 bits
            //
            if (attr->ulValueLen != 20){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            return remove_leading_zeros( attr );
         }

      case CKA_BASE:
         if (mode == MODE_CREATE || mode == MODE_KEYGEN)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_VALUE:
         if (mode == MODE_CREATE)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      default:
         return publ_key_validate_attribute( tmpl, attr, mode );
   }
}


// dsa_priv_check_required_attributes()
//
CK_RV
dsa_priv_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;


   found = template_attribute_find( tmpl, CKA_PRIME, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_SUBPRIME, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_BASE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return priv_key_check_required_attributes( tmpl, mode );
}


//  dsa_priv_set_default_attributes()
//
CK_RV
dsa_priv_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *prime_attr      = NULL;
   CK_ATTRIBUTE   *subprime_attr   = NULL;
   CK_ATTRIBUTE   *base_attr       = NULL;
   CK_ATTRIBUTE   *value_attr      = NULL;
   CK_ATTRIBUTE   *type_attr       = NULL;

   if (mode)
      prime_attr = NULL;

   priv_key_set_default_attributes( tmpl, mode );

   type_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   prime_attr    = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   subprime_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   base_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_attr    = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !prime_attr || !subprime_attr || !base_attr || !value_attr) {
      if (type_attr)     free( type_attr );
      if (prime_attr)    free( prime_attr );
      if (subprime_attr) free( subprime_attr );
      if (base_attr)     free( base_attr );
      if (value_attr)    free( value_attr );
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

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_DSA;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, prime_attr );
   template_update_attribute( tmpl, subprime_attr );
   template_update_attribute( tmpl, base_attr );
   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}


// dsa_priv_validate_attributes()
//
CK_RV
dsa_priv_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_PRIME:
         {
            CK_ULONG size;

            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            // must be between [512, 1024] bits, and a multiple of 64 bits
            //
            size = attr->ulValueLen;
            if (size < 64 || size > 128 || (size % 8 != 0)){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
               }
            return remove_leading_zeros( attr );
         }

      case CKA_SUBPRIME:
         {
            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            // subprime must be 160 bits
            //
            if (attr->ulValueLen != 20){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            return remove_leading_zeros( attr );
         }

      case CKA_BASE:
      case CKA_VALUE:
         if (mode == MODE_CREATE)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      default:
         return priv_key_validate_attribute( tmpl, attr, mode );
   }
}


// dsa_priv_check_exportability()
//
CK_BBOOL
dsa_priv_check_exportability( CK_ATTRIBUTE_TYPE type )
{
   switch (type) {
      case CKA_VALUE:
         return FALSE;
   }

   return TRUE;
}


// create the ASN.1 encoding for the private key for wrapping as defined
// in PKCS #8
//
// ASN.1 type PrivateKeyInfo ::= SEQUENCE {
//    version Version
//    privateKeyAlgorithm  PrivateKeyAlgorithmIdentifier
//    privateKey PrivateKey
//    attributes OPTIONAL
// }
//
// PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
//
// AlgorithmIdentifier ::= SEQUENCE {
//    algorithm OBJECT IDENTIFIER
//    parameters ANY DEFINED BY algorithm OPTIONAL
// }
//
// paramters ::= SEQUENCE {
//    p  INTEGER
//    q  INTEGER
//    g  INTEGER
// }
//
// privateKey ::= INTEGER
//
//
CK_RV
dsa_priv_wrap_get_data( TEMPLATE  *tmpl,
                        CK_BBOOL   length_only,
                        CK_BYTE  **data,
                        CK_ULONG  *data_len )
{
   CK_ATTRIBUTE *prime     = NULL;
   CK_ATTRIBUTE *subprime  = NULL;
   CK_ATTRIBUTE *base      = NULL;
   CK_ATTRIBUTE *value     = NULL;
   CK_RV      rc;


   // compute the total length of the BER-encoded data
   //
   if (template_attribute_find(tmpl, CKA_PRIME, &prime) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (template_attribute_find(tmpl, CKA_SUBPRIME, &subprime) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (template_attribute_find(tmpl, CKA_BASE, &base) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (template_attribute_find(tmpl, CKA_VALUE, &value) == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = ber_encode_DSAPrivateKey( length_only, data, data_len,
                                  prime, subprime, base, value );
   if (rc != CKR_OK){
      st_err_log(87, __FILE__, __LINE__);
   }

   return rc;
}


//
//
CK_RV
dsa_priv_unwrap( TEMPLATE *tmpl,
                 CK_BYTE  *data,
                 CK_ULONG  total_length )
{
   CK_ATTRIBUTE *prime     = NULL;
   CK_ATTRIBUTE *subprime  = NULL;
   CK_ATTRIBUTE *base      = NULL;
   CK_ATTRIBUTE *value     = NULL;
   CK_RV      rc;

   rc = ber_decode_DSAPrivateKey( data, total_length,
                                  &prime, &subprime, &base, &value );

   if (rc != CKR_OK){
      st_err_log(88, __FILE__, __LINE__);
      return rc;
   }
   remove_leading_zeros( prime );
   remove_leading_zeros( subprime );
   remove_leading_zeros( base );
   remove_leading_zeros( value );

   template_update_attribute( tmpl, prime );
   template_update_attribute( tmpl, subprime );
   template_update_attribute( tmpl, base );
   template_update_attribute( tmpl, value );

   return CKR_OK;
}


// ecdsa_publ_check_required_attributes()
//
CK_RV
ecdsa_publ_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;


   found = template_attribute_find( tmpl, CKA_ECDSA_PARAMS, &attr );
   if (!found) {
      if (mode == MODE_CREATE || mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_EC_POINT, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return publ_key_check_required_attributes( tmpl, mode );
}


//  ecdsa_publ_set_default_attributes()
//
CK_RV
ecdsa_publ_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *params_attr   = NULL;
   CK_ATTRIBUTE   *ec_point_attr = NULL;
   CK_ATTRIBUTE   *type_attr     = NULL;

   if (mode)
      params_attr = NULL;

   publ_key_set_default_attributes( tmpl, mode );

   type_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   params_attr   = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   ec_point_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !params_attr || !ec_point_attr) {
      if (type_attr)     free( type_attr );
      if (params_attr)   free( params_attr );
      if (ec_point_attr) free( ec_point_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   params_attr->type       = CKA_ECDSA_PARAMS;
   params_attr->ulValueLen = 0;
   params_attr->pValue     = NULL;

   ec_point_attr->type       = CKA_EC_POINT;
   ec_point_attr->ulValueLen = 0;
   ec_point_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_ECDSA;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, params_attr );
   template_update_attribute( tmpl, ec_point_attr );

   return CKR_OK;
}


// ecdsa_publ_validate_attributes()
//
CK_RV
ecdsa_publ_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_ECDSA_PARAMS:
         if (mode == MODE_CREATE || mode == MODE_KEYGEN)
            return CKR_OK;
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_EC_POINT:
         if (mode == MODE_CREATE)
            return CKR_OK;
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      default:
         return publ_key_validate_attribute( tmpl, attr, mode );
   }
}


// ecdsa_priv_check_required_attributes()
//
CK_RV
ecdsa_priv_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;


   found = template_attribute_find( tmpl, CKA_ECDSA_PARAMS, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_EC_POINT, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return priv_key_check_required_attributes( tmpl, mode );
}


//  ecdsa_priv_set_default_attributes()
//
CK_RV
ecdsa_priv_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *params_attr  = NULL;
   CK_ATTRIBUTE   *value_attr   = NULL;
   CK_ATTRIBUTE   *type_attr    = NULL;

   if (mode)
      params_attr = NULL;

   priv_key_set_default_attributes( tmpl, mode );

   type_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   params_attr   = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_attr    = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !params_attr || !value_attr) {
      if (type_attr)   free( type_attr );
      if (params_attr) free( params_attr );
      if (value_attr)  free( value_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   params_attr->type       = CKA_ECDSA_PARAMS;
   params_attr->ulValueLen = 0;
   params_attr->pValue     = NULL;

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_ECDSA;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, params_attr );
   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}


// ecdsa_priv_validate_attributes()
//
CK_RV
ecdsa_priv_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_ECDSA_PARAMS:
         if (mode == MODE_CREATE)
            return CKR_OK;
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_VALUE:
         if (mode == MODE_CREATE)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      default:
         return priv_key_validate_attribute( tmpl, attr, mode );
   }
}


// ecdsa_priv_check_exportability()
//
CK_BBOOL
ecdsa_priv_check_exportability( CK_ATTRIBUTE_TYPE type )
{
   switch (type) {
      case CKA_VALUE:
         return FALSE;
   }

   return TRUE;
}


// dh_publ_check_required_attributes()
//
CK_RV
dh_publ_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;


   found = template_attribute_find( tmpl, CKA_PRIME, &attr );
   if (!found) {
      if (mode == MODE_CREATE || mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_BASE, &attr );
   if (!found) {
      if (mode == MODE_CREATE || mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return publ_key_check_required_attributes( tmpl, mode );
}


//  dh_publ_set_default_attributes()
//
CK_RV
dh_publ_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *prime_attr   = NULL;
   CK_ATTRIBUTE   *base_attr    = NULL;
   CK_ATTRIBUTE   *value_attr   = NULL;
   CK_ATTRIBUTE   *type_attr    = NULL;

   if (mode)
      prime_attr = NULL;

   publ_key_set_default_attributes( tmpl, mode );

   type_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   prime_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   base_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !prime_attr || !base_attr || !value_attr) {
      if (type_attr)  free( type_attr );
      if (prime_attr) free( prime_attr );
      if (base_attr)  free( base_attr );
      if (value_attr) free( value_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   prime_attr->type       = CKA_PRIME;
   prime_attr->ulValueLen = 0;
   prime_attr->pValue     = NULL;

   base_attr->type       = CKA_BASE;
   base_attr->ulValueLen = 0;
   base_attr->pValue     = NULL;

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type         = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_DH;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, prime_attr );
   template_update_attribute( tmpl, base_attr );
   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}




// dh_publ_validate_attribute()
//
CK_RV
dh_publ_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_PRIME:
      case CKA_BASE:
         if (mode == MODE_CREATE || mode == MODE_KEYGEN)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_VALUE:
         if (mode == MODE_CREATE)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      default:
         return publ_key_validate_attribute( tmpl, attr, mode );
   }
}


// dh_priv_check_required_attributes()
//
CK_RV
dh_priv_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;


   found = template_attribute_find( tmpl, CKA_PRIME, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_BASE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE_BITS, &attr );
   if (found) {
      if (mode == MODE_CREATE || mode == MODE_UNWRAP){
         st_err_log(7, __FILE__, __LINE__);
         return CKR_ATTRIBUTE_READ_ONLY;
      }
   }

   return priv_key_check_required_attributes( tmpl, mode );
}


//  dh_priv_set_default_attributes()
//
CK_RV
dh_priv_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *prime_attr      = NULL;
   CK_ATTRIBUTE   *base_attr       = NULL;
   CK_ATTRIBUTE   *value_attr      = NULL;
   CK_ATTRIBUTE   *value_bits_attr = NULL;
   CK_ATTRIBUTE   *type_attr       = NULL;
   CK_ULONG        bits = 0L;

   priv_key_set_default_attributes( tmpl, mode );

   type_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   prime_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   base_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_bits_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );

   if (!type_attr || !prime_attr || !base_attr || !value_attr || !value_bits_attr) {
      if (type_attr)       free( type_attr );
      if (prime_attr)      free( prime_attr );
      if (base_attr)       free( base_attr );
      if (value_attr)      free( value_attr );
      if (value_bits_attr) free( value_bits_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   prime_attr->type       = CKA_PRIME;
   prime_attr->ulValueLen = 0;
   prime_attr->pValue     = NULL;

   base_attr->type       = CKA_BASE;
   base_attr->ulValueLen = 0;
   base_attr->pValue     = NULL;

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   value_bits_attr->type       = CKA_VALUE_BITS;
   value_bits_attr->ulValueLen = sizeof(CK_ULONG);
   value_bits_attr->pValue     = (CK_BYTE *)value_bits_attr + sizeof(CK_ATTRIBUTE);
   *(CK_ULONG *)value_bits_attr->pValue = bits;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_DH;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, prime_attr );
   template_update_attribute( tmpl, base_attr );
   template_update_attribute( tmpl, value_attr );
   template_update_attribute( tmpl, value_bits_attr );

   return CKR_OK;
}


// dh_priv_validate_attribute()
//
CK_RV
dh_priv_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_PRIME:
      case CKA_BASE:
      case CKA_VALUE:
         if (mode == MODE_CREATE || mode == MODE_KEYGEN)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      // I'm not sure what to do about VALUE_BITS...we don't really support
      // Diffie-Hellman keys other than for storage...when the object is
      // created, we're supposed to add CKA_VALUE_BITS outselves...which we
      // don't do at this time.  (we'd need to add code in C_CreateObject to
      // call some sort of objecttype-specific callback)
      //
      // kapil 05/08/03 : Commented out error flagging, as CKA_VALUE_BITS is valid
      //                  attribute for creating DH priv object.  The above is 
      //                  an older comment.
      case CKA_VALUE_BITS:
      //   st_err_log(7, __FILE__, __LINE__);
      //   return CKR_ATTRIBUTE_READ_ONLY;
           return CKR_OK ;
           break ;

      default:
         return priv_key_validate_attribute( tmpl, attr, mode );
   }
}


// dh_priv_check_exportability()
//
CK_BBOOL
dh_priv_check_exportability( CK_ATTRIBUTE_TYPE type )
{
   switch (type) {
      case CKA_VALUE:
         return FALSE;
   }

   return TRUE;
}


// kea_publ_check_required_attributes()
//
CK_RV
kea_publ_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;


   found = template_attribute_find( tmpl, CKA_PRIME, &attr );
   if (!found) {
      if (mode == MODE_CREATE || mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_SUBPRIME, &attr );
   if (!found) {
      if (mode == MODE_CREATE || mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_BASE, &attr );
   if (!found) {
      if (mode == MODE_CREATE || mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return publ_key_check_required_attributes( tmpl, mode );
}


//  kea_publ_set_default_attributes()
//
CK_RV
kea_publ_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *prime_attr    = NULL;
   CK_ATTRIBUTE   *subprime_attr = NULL;
   CK_ATTRIBUTE   *base_attr     = NULL;
   CK_ATTRIBUTE   *value_attr    = NULL;
   CK_ATTRIBUTE   *type_attr     = NULL;

   if (mode)
      prime_attr = NULL;


   publ_key_set_default_attributes( tmpl, mode );

   type_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   prime_attr    = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   subprime_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   base_attr     = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_attr    = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !prime_attr || !subprime_attr || !base_attr || !value_attr) {
      if (type_attr)     free( type_attr );
      if (prime_attr)    free( prime_attr );
      if (subprime_attr) free( subprime_attr );
      if (base_attr)     free( base_attr );
      if (value_attr)    free( value_attr );
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

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_KEA;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, prime_attr );
   template_update_attribute( tmpl, subprime_attr );
   template_update_attribute( tmpl, base_attr );
   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}


// kea_publ_validate_attribute()
//
CK_RV
kea_publ_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_PRIME:
      case CKA_SUBPRIME:
      case CKA_BASE:
         if (mode == MODE_CREATE || mode == MODE_KEYGEN)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_VALUE:
         if (mode == MODE_CREATE)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      default:
         return publ_key_validate_attribute( tmpl, attr, mode );
   }
}


// kea_priv_check_required_attributes()
//
CK_RV
kea_priv_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;


   found = template_attribute_find( tmpl, CKA_PRIME, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_SUBPRIME, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_BASE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return priv_key_check_required_attributes( tmpl, mode );
}


//  kea_priv_set_default_attributes()
//
CK_RV
kea_priv_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *prime_attr    = NULL;
   CK_ATTRIBUTE   *subprime_attr = NULL;
   CK_ATTRIBUTE   *base_attr     = NULL;
   CK_ATTRIBUTE   *value_attr    = NULL;
   CK_ATTRIBUTE   *type_attr     = NULL;

   if (mode)
      prime_attr = NULL;

   priv_key_set_default_attributes( tmpl, mode );

   type_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   prime_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   subprime_attr   = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   base_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !prime_attr || !base_attr || !value_attr || !subprime_attr) {
      if (prime_attr)    free( prime_attr );
      if (subprime_attr) free( subprime_attr );
      if (base_attr)     free( base_attr );
      if (value_attr)    free( value_attr );
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

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_KEA;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, prime_attr );
   template_update_attribute( tmpl, subprime_attr );
   template_update_attribute( tmpl, base_attr );
   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}


// kea_priv_validate_attribute()
//
CK_RV
kea_priv_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_PRIME:
      case CKA_SUBPRIME:
      case CKA_BASE:
      case CKA_VALUE:
         if (mode == MODE_CREATE)
            return remove_leading_zeros( attr );
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      default:
         return priv_key_validate_attribute( tmpl, attr, mode );
   }
}


// kea_priv_check_exportability()
//
CK_BBOOL
kea_priv_check_exportability( CK_ATTRIBUTE_TYPE type )
{
   switch (type) {
      case CKA_VALUE:
         return FALSE;
   }

   return TRUE;
}


// generic_secret_check_required_attributes()
//
CK_RV
generic_secret_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }


   found = template_attribute_find( tmpl, CKA_VALUE_LEN, &attr );
   if (!found) {
      // here's another place where PKCS #11 deviates from its own specification.
      // the spec states that VALUE_LEN must be present for KEYGEN but later
      // it's merely optional if the mechanism is CKM_SSL3_PRE_MASTER_KEY_GEN.
      // Unfortunately, we can't check the mechanism at this point
      //
      //if (mode == MODE_KEYGEN)
      //   return CKR_TEMPLATE_INCOMPLETE;
      return CKR_OK;
   }
   else {
      // Another contradiction within the spec:  When describing the key types
      // the spec says that VALUE_LEN must not be specified when unwrapping
      // a key.  In the section describing the mechanisms, though, it's allowed for
      // most unwrapping mechanisms.  Netscape DOES does specify this attribute
      // when unwrapping.
      //
      //if (mode == MODE_CREATE || mode == MODE_UNWRAP)
      if (mode == MODE_CREATE){
         st_err_log(7, __FILE__, __LINE__);
         return CKR_ATTRIBUTE_READ_ONLY;
      }
   }

   return secret_key_check_required_attributes( tmpl, mode );
}


//  generic_secret_set_default_attributes()
//
CK_RV
generic_secret_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr       = NULL;
   CK_ATTRIBUTE   *value_len_attr   = NULL;
   CK_ATTRIBUTE   *type_attr        = NULL;
   CK_ULONG    len = 0L;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_len_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );

   if (!type_attr || !value_attr || !value_len_attr) {
      if (type_attr)      free( type_attr );
      if (value_attr)     free( value_attr );
      if (value_len_attr) free( value_len_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   value_len_attr->type       = CKA_VALUE_LEN;
   value_len_attr->ulValueLen = sizeof(CK_ULONG);
   value_len_attr->pValue     = (CK_BYTE *)value_len_attr + sizeof(CK_ATTRIBUTE);
   *(CK_ULONG *)value_len_attr->pValue = len;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_GENERIC_SECRET;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   template_update_attribute( tmpl, value_len_attr );

   return CKR_OK;
}


// generic_secret_validate_attribute()
//
CK_RV
generic_secret_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_VALUE:
         if (mode == MODE_CREATE)
            return CKR_OK;
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      // Another contradiction within the spec:  When describing the key types
      // the spec says that VALUE_LEN must not be specified when unwrapping
      // a key.  In the section describing the mechanisms, though, it's allowed for
      // most unwrapping mechanisms.  Netscape DOES does specify this attribute
      // when unwrapping.
      //
      case CKA_VALUE_LEN:
         if (mode == MODE_KEYGEN || mode == MODE_DERIVE)
            return CKR_OK;
         else {
            if (mode == MODE_UNWRAP) {
               if (nv_token_data->tweak_vector.netscape_mods == TRUE)
                  return CKR_OK;
            }
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


// generic_secret_check_exportability()
//
CK_BBOOL
generic_secret_check_exportability( CK_ATTRIBUTE_TYPE type )
{
   switch (type) {
      case CKA_VALUE:
         return FALSE;
   }

   return TRUE;
}


//
//
CK_RV
generic_secret_wrap_get_data( TEMPLATE   * tmpl,
                              CK_BBOOL     length_only,
                              CK_BYTE   ** data,
                              CK_ULONG   * data_len )
{
   CK_ATTRIBUTE    * attr = NULL;
   CK_BYTE      * ptr  = NULL;
   CK_RV          rc;


   if (!tmpl || !data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   rc = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (rc == FALSE){
      st_err_log(26, __FILE__, __LINE__);
      return CKR_KEY_NOT_WRAPPABLE;
   }
   *data_len = attr->ulValueLen;

   if (length_only == FALSE) {
      ptr = (CK_BYTE *)malloc( attr->ulValueLen );
      if (!ptr){
         st_err_log(1, __FILE__, __LINE__);
         return CKR_HOST_MEMORY;
      }
      memcpy( ptr, attr->pValue, attr->ulValueLen );

      *data = ptr;
   }

   return CKR_OK;
}


//
//
CK_RV
generic_secret_unwrap( TEMPLATE *tmpl,
                       CK_BYTE  *data,
                       CK_ULONG  data_len,
                       CK_BBOOL  fromend )
{
   CK_ATTRIBUTE  * attr           = NULL;
   CK_ATTRIBUTE  * value_attr     = NULL;
   CK_ATTRIBUTE  * value_len_attr = NULL;
   CK_BYTE    * ptr            = NULL;
   CK_ULONG     rc, len;


   if (fromend == TRUE)
      ptr = data + data_len;
   else
      ptr = data;

   // it's possible that the user specified CKA_VALUE_LEN in the
   // template.  if so, try to use it.  by default, CKA_VALUE_LEN is 0
   //
   rc = template_attribute_find( tmpl, CKA_VALUE_LEN, &attr );
   if (rc) {
      len = *(CK_ULONG *)attr->pValue;
      if (len > data_len) {
         st_err_log(9, __FILE__, __LINE__);
         rc = CKR_ATTRIBUTE_VALUE_INVALID;
         goto error;
      }

      if (len != 0)
         data_len = len;
   }

   if (fromend == TRUE)
      ptr -= data_len;

   rc = build_attribute( CKA_VALUE, ptr, data_len, &value_attr );
   if (rc != CKR_OK){
      st_err_log(84, __FILE__, __LINE__);
      goto error;
   }
   if (data_len != len) {
      rc = build_attribute( CKA_VALUE_LEN, (CK_BYTE *)&data_len, sizeof(CK_ULONG), &value_len_attr );
      if (rc != CKR_OK){
         st_err_log(84, __FILE__, __LINE__);
         goto error;
      }
   }

   template_update_attribute( tmpl, value_attr );

   if (data_len != len)
      template_update_attribute( tmpl, value_len_attr );

   return CKR_OK;

error:
   if (value_attr)     free( value_attr );
   if (value_len_attr) free( value_len_attr );

   return rc;
}


// rc2_check_required_attributes()
//
CK_RV
rc2_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE_LEN, &attr );
   if (!found) {
      if (mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return secret_key_check_required_attributes( tmpl, mode );
}


//  rc2_set_default_attributes()
//
CK_RV
rc2_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE    *value_attr       = NULL;
   CK_ATTRIBUTE    *value_len_attr   = NULL;
   CK_ATTRIBUTE    *type_attr        = NULL;
   CK_ULONG     len = 0L;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_len_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );

   if (!type_attr || !value_attr || !value_len_attr) {
      if (type_attr)      free( type_attr );
      if (value_attr)     free( value_attr );
      if (value_len_attr) free( value_len_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   value_len_attr->type       = CKA_VALUE_LEN;
   value_len_attr->ulValueLen = sizeof(CK_ULONG);
   value_len_attr->pValue     = (CK_BYTE *)value_len_attr + sizeof(CK_ATTRIBUTE);
   *(CK_ULONG *)value_len_attr->pValue = len;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_RC2;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   template_update_attribute( tmpl, value_len_attr );

   return CKR_OK;
}


// rc2_validate_attribute()
//
CK_RV
rc2_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_VALUE:
         if (mode != MODE_CREATE){
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
         // rc2 key length <= 128 bytes
         //
         if (attr->ulValueLen > 128)
            return CKR_ATTRIBUTE_VALUE_INVALID;
         else
            return CKR_OK;

      case CKA_VALUE_LEN:
         {
            CK_ULONG len;

            if (mode != MODE_KEYGEN && mode != MODE_DERIVE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            len = *(CK_ULONG *)attr->pValue;
            if (len > 128){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


//  rc4_set_default_attributes()
//
CK_RV
rc4_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr      = NULL;
   CK_ATTRIBUTE   *value_len_attr  = NULL;
   CK_ATTRIBUTE   *type_attr       = NULL;
   CK_ULONG     len = 0L;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_len_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );

   if (!type_attr || !value_attr || !value_len_attr) {
      if (type_attr)      free( type_attr );
      if (value_attr)     free( value_attr );
      if (value_len_attr) free( value_len_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   value_len_attr->type       = CKA_VALUE_LEN;
   value_len_attr->ulValueLen = sizeof(CK_ULONG);
   value_len_attr->pValue     = (CK_BYTE *)value_len_attr + sizeof(CK_ATTRIBUTE);
   *(CK_ULONG *)value_len_attr->pValue = len;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_RC4;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   template_update_attribute( tmpl, value_len_attr );

   return CKR_OK;
}


// rc4_check_required_attributes()
//
CK_RV
rc4_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE_LEN, &attr );
   if (!found) {
      if (mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return secret_key_check_required_attributes( tmpl, mode );
}


// rc4_validate_attribute()
//
CK_RV
rc4_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_VALUE:
         {
            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
	    }
            // key length <= 256 bytes
            //
            if (attr->ulValueLen > 256){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      case CKA_VALUE_LEN:
         {
            CK_ULONG len;

            if (mode != MODE_KEYGEN && mode != MODE_DERIVE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            len = *(CK_ULONG *)attr->pValue;
            if (len > 255){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


// rc5_check_required_attributes()
//
CK_RV
rc5_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE_LEN, &attr );
   if (!found) {
      if (mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return secret_key_check_required_attributes( tmpl, mode );
}


//  rc5_set_default_attributes()
//
CK_RV
rc5_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr      = NULL;
   CK_ATTRIBUTE   *value_len_attr  = NULL;
   CK_ATTRIBUTE   *type_attr       = NULL;
   CK_ULONG     len = 0L;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_len_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );

   if (!type_attr || !value_attr || !value_len_attr) {
      if (type_attr)      free( type_attr );
      if (value_attr)     free( value_attr );
      if (value_len_attr) free( value_len_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   value_len_attr->type       = CKA_VALUE_LEN;
   value_len_attr->ulValueLen = sizeof(CK_ULONG);
   value_len_attr->pValue     = (CK_BYTE *)value_len_attr + sizeof(CK_ATTRIBUTE);
   *(CK_ULONG *)value_len_attr->pValue = len;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_RC5;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   template_update_attribute( tmpl, value_len_attr );

   return CKR_OK;
}


// rc5_validate_attribute()
//
CK_RV
rc5_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_VALUE:
         {
            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            // key length <= 256 bytes
            //
            if (attr->ulValueLen > 255){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      case CKA_VALUE_LEN:
         {
            CK_ULONG len;

            if (mode != MODE_KEYGEN && mode != MODE_DERIVE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            len = *(CK_ULONG *)attr->pValue;
            if (len > 255){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


//
//
CK_RV
des_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return secret_key_check_required_attributes( tmpl, mode );
}


//
//
CK_BBOOL
des_check_weak_key( CK_BYTE *key )
{
   CK_ULONG i;

   for (i=0; i < des_weak_count; i++) {
      if (memcmp(key, des_weak_keys[i], DES_KEY_SIZE) == 0)
         return TRUE;
   }

   for (i=0; i < des_semi_weak_count; i++) {
      if (memcmp(key, des_semi_weak_keys[i], DES_KEY_SIZE) == 0)
         return TRUE;
   }

   for (i=0; i < des_possibly_weak_count; i++) {
      if (memcmp(key, des_possibly_weak_keys[i], DES_KEY_SIZE) == 0)
         return TRUE;
   }

   return FALSE;
}



//
//
CK_RV
des_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   * value_attr  = NULL;
   CK_ATTRIBUTE   * type_attr   = NULL;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   type_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );

   if (!value_attr || !type_attr) {
      if (value_attr) free( value_attr );
      if (type_attr)  free( type_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_DES;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}


//
//
CK_RV
des_unwrap( TEMPLATE *tmpl,
            CK_BYTE  *data,
            CK_ULONG  data_len,
            CK_BBOOL  fromend )
{
   CK_ATTRIBUTE  * value_attr = NULL;
   CK_BYTE    * ptr        = NULL;
   CK_ULONG     i;


   if (data_len < DES_BLOCK_SIZE){
      st_err_log(62, __FILE__, __LINE__);
      return CKR_WRAPPED_KEY_INVALID;
   }
   if (fromend == TRUE)
      ptr = data + data_len - DES_BLOCK_SIZE;
   else
      ptr = data;

   if (nv_token_data->tweak_vector.check_des_parity == TRUE) {
      for (i=0; i < DES_KEY_SIZE; i++) {
         if (parity_is_odd(ptr[i]) == FALSE){
               st_err_log(9, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_VALUE_INVALID;
         }
      }
   }

   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + DES_BLOCK_SIZE );

   if (!value_attr) {
      if (value_attr)
         free( value_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = DES_BLOCK_SIZE;
   value_attr->pValue     = (CK_BYTE *)value_attr + sizeof(CK_ATTRIBUTE);
   memcpy( value_attr->pValue, ptr, DES_BLOCK_SIZE );

   template_update_attribute( tmpl, value_attr );
   return CKR_OK;
}


// des_validate_attribute()
//
CK_RV
des_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   CK_BYTE   * ptr = NULL;
   CK_ULONG    i;

   switch (attr->type) {
      case CKA_VALUE:
         // key length always 8 bytes
         //
         if (mode == MODE_CREATE) {
            if (attr->ulValueLen != DES_KEY_SIZE){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            if (nv_token_data->tweak_vector.check_des_parity == TRUE) {
               ptr = attr->pValue;
               for (i=0; i < DES_KEY_SIZE; i++) {
                  if (parity_is_odd(ptr[i]) == FALSE){
                     st_err_log(9, __FILE__, __LINE__);
                     return CKR_ATTRIBUTE_VALUE_INVALID;
                  }
               }
            }

            return CKR_OK;
         }
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_VALUE_LEN:
         // Cryptoki doesn't allow this but Netscape tries uses it
         //
         if (nv_token_data->tweak_vector.netscape_mods == TRUE) {
            if (mode == MODE_CREATE || mode == MODE_DERIVE ||
                mode == MODE_KEYGEN || mode == MODE_UNWRAP)
            {
               CK_ULONG len = *(CK_ULONG *)attr->pValue;
               if (len != DES_KEY_SIZE){
                  st_err_log(9, __FILE__, __LINE__);
                  return CKR_ATTRIBUTE_VALUE_INVALID;
               }
               else
                  return CKR_OK;
            }
            else{
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            } 
         }
         else{
            st_err_log(49, __FILE__, __LINE__);
            return CKR_TEMPLATE_INCONSISTENT;
         }
      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


//
//
CK_RV
des_wrap_get_data( TEMPLATE   * tmpl,
                   CK_BBOOL     length_only,
                   CK_BYTE   ** data,
                   CK_ULONG   * data_len )
{
   CK_ATTRIBUTE    * attr = NULL;
   CK_BYTE      * ptr  = NULL;
   CK_RV          rc;


   if (!tmpl || !data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   rc = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (rc == FALSE){
      st_err_log(26, __FILE__, __LINE__);
      return CKR_KEY_NOT_WRAPPABLE;
   }
   *data_len = attr->ulValueLen;

   if (length_only == FALSE) {
      ptr = (CK_BYTE *)malloc( attr->ulValueLen );
      if (!ptr){
         st_err_log(1, __FILE__, __LINE__);
         return CKR_HOST_MEMORY;
      }
      memcpy( ptr, attr->pValue, attr->ulValueLen );

      *data = ptr;
   }

   return CKR_OK;
}


// des2_check_required_attributes()
//
CK_RV
des2_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return secret_key_check_required_attributes( tmpl, mode );
}


//  des2_set_default_attributes()
//
CK_RV
des2_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   * value_attr  = NULL;
   CK_ATTRIBUTE   * type_attr   = NULL;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   type_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );

   if (!value_attr || !type_attr) {
      if (value_attr) free( value_attr );
      if (type_attr)  free( type_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type         = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_DES2;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}


// des2_validate_attribute()
//
CK_RV
des2_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   CK_BYTE   * ptr = NULL;
   CK_ULONG    i;

   switch (attr->type) {
      case CKA_VALUE:
         // key length always 16 bytes
         //
         if (mode == MODE_CREATE) {
            if (attr->ulValueLen != (2 * DES_KEY_SIZE)){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            if (nv_token_data->tweak_vector.check_des_parity == TRUE) {
               ptr = attr->pValue;
               for (i=0; i < 2*DES_KEY_SIZE; i++) {
                  if (parity_is_odd(ptr[i]) == FALSE){
                     st_err_log(9, __FILE__, __LINE__);
                     return CKR_ATTRIBUTE_VALUE_INVALID;
                  }
               }
            }
            return CKR_OK;
         }
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_VALUE_LEN:
         // Cryptoki doesn't allow this but Netscape tries uses it
         //
         if (nv_token_data->tweak_vector.netscape_mods == TRUE) {
            if (mode == MODE_CREATE || mode == MODE_DERIVE ||
                mode == MODE_KEYGEN || mode == MODE_UNWRAP)
            {
               CK_ULONG len = *(CK_ULONG *)attr->pValue;
               if (len != (2 * DES_KEY_SIZE)){
                  st_err_log(9, __FILE__, __LINE__);
                  return CKR_ATTRIBUTE_VALUE_INVALID;
               } 
               else
                  return CKR_OK;
            }
            else{
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
         }
         else{
            st_err_log(49, __FILE__, __LINE__);
            return CKR_TEMPLATE_INCONSISTENT;
         }
      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


// des3_check_required_attributes()
//
CK_RV
des3_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return secret_key_check_required_attributes( tmpl, mode );
}


//  des3_set_default_attributes()
//
CK_RV
des3_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   * value_attr  = NULL;
   CK_ATTRIBUTE   * type_attr   = NULL;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   type_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );

   if (!value_attr || !type_attr) {
      if (value_attr) free( value_attr );
      if (type_attr)  free( type_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_DES3;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}


//
//
CK_RV
des3_unwrap( TEMPLATE *tmpl,
             CK_BYTE  *data,
             CK_ULONG  data_len,
             CK_BBOOL  fromend )
{
   CK_ATTRIBUTE  * value_attr = NULL;
   CK_BYTE    * ptr        = NULL;
   CK_ULONG     i;


   if (data_len < 3 * DES_BLOCK_SIZE){
      st_err_log(62, __FILE__, __LINE__);
      return CKR_WRAPPED_KEY_INVALID;
   }
   if (fromend == TRUE)
      ptr = data + data_len - (3*DES_BLOCK_SIZE);
   else
      ptr = data;

   if (nv_token_data->tweak_vector.check_des_parity == TRUE) {
      for (i=0; i < 3*DES_KEY_SIZE; i++) {
         if (parity_is_odd(ptr[i]) == FALSE){
            st_err_log(9, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_VALUE_INVALID;
         }
      }
   }

   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + (3 * DES_BLOCK_SIZE) );

   if (!value_attr) {
      if (value_attr)
         free( value_attr );
      st_err_log(0, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 3 * DES_BLOCK_SIZE;
   value_attr->pValue     = (CK_BYTE *)value_attr + sizeof(CK_ATTRIBUTE);
   memcpy( value_attr->pValue, ptr, 3 * DES_BLOCK_SIZE );

   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}


//
//
CK_RV
des3_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   CK_BYTE   * ptr = NULL;
   CK_ULONG    i;

   switch (attr->type) {
      case CKA_VALUE:
         // key length always 24 bytes
         //
         if (mode == MODE_CREATE) {
            if (attr->ulValueLen != (3 * DES_KEY_SIZE)){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            if (nv_token_data->tweak_vector.check_des_parity == TRUE) {
               ptr = attr->pValue;
               for (i=0; i < 3*DES_KEY_SIZE; i++) {
                  if (parity_is_odd(ptr[i]) == FALSE){
                     st_err_log(9, __FILE__, __LINE__);
                     return CKR_ATTRIBUTE_VALUE_INVALID;
                  }
               }
            }
            return CKR_OK;
         }
         else{
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_VALUE_LEN:
         // Cryptoki doesn't allow this but Netscape tries uses it
         //
         if (nv_token_data->tweak_vector.netscape_mods == TRUE) {
            if (mode == MODE_CREATE || mode == MODE_DERIVE ||
                mode == MODE_KEYGEN || mode == MODE_UNWRAP)
            {
//               CK_ULONG len = *(CK_ULONG *)attr->pValue;
//               if (len != (3 * DES_KEY_SIZE))
//                  return CKR_ATTRIBUTE_VALUE_INVALID;
//               else
                  return CKR_OK;
            }
            else{
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
         }
         else{
            st_err_log(49, __FILE__, __LINE__);
            return CKR_TEMPLATE_INCONSISTENT;
         }
      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


//
//
CK_RV
des3_wrap_get_data( TEMPLATE   * tmpl,
                    CK_BBOOL     length_only,
                    CK_BYTE   ** data,
                    CK_ULONG   * data_len )
{
   CK_ATTRIBUTE    * attr = NULL;
   CK_BYTE      * ptr  = NULL;
   CK_RV          rc;


   if (!tmpl || !data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   rc = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (rc == FALSE){
      st_err_log(26, __FILE__, __LINE__);
      return CKR_KEY_NOT_WRAPPABLE;
   }
   *data_len = attr->ulValueLen;

   if (length_only == FALSE) {
      ptr = (CK_BYTE *)malloc( attr->ulValueLen );
      if (!ptr){
         st_err_log(0, __FILE__, __LINE__);
         return CKR_HOST_MEMORY;
      }
      memcpy( ptr, attr->pValue, attr->ulValueLen );

      *data = ptr;
   }

   return CKR_OK;
}


// cast_check_required_attributes()
//
CK_RV
cast_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE_LEN, &attr );
   if (!found) {
      if (mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return secret_key_check_required_attributes( tmpl, mode );
}


//  cast_set_default_attributes()
//
CK_RV
cast_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr      = NULL;
   CK_ATTRIBUTE   *value_len_attr  = NULL;
   CK_ATTRIBUTE   *type_attr       = NULL;
   CK_ULONG     len = 0L;


   secret_key_set_default_attributes( tmpl, mode );

   type_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_len_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );

   if (!type_attr || !value_attr || !value_len_attr) {
      if (type_attr)      free( type_attr );
      if (value_attr)     free( value_attr );
      if (value_len_attr) free( value_len_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   value_len_attr->type       = CKA_VALUE_LEN;
   value_len_attr->ulValueLen = sizeof(CK_ULONG);
   value_len_attr->pValue     = (CK_BYTE *)value_len_attr + sizeof(CK_ATTRIBUTE);
   *(CK_ULONG *)value_len_attr->pValue = len;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_CAST;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   template_update_attribute( tmpl, value_len_attr );

   return CKR_OK;
}


// cast_validate_attribute()
//
CK_RV
cast_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   CK_ULONG len;

   switch (attr->type) {
      case CKA_VALUE:
         {
            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (attr->ulValueLen > 8 || attr->ulValueLen < 1){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      case CKA_VALUE_LEN:
         {
            if (mode != MODE_KEYGEN && mode != MODE_DERIVE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            len = *(CK_ULONG *)attr->pValue;
            if (len > 8 || len < 1){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }


      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


// cast3_check_required_attributes()
//
CK_RV
cast3_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   found = template_attribute_find( tmpl, CKA_VALUE_LEN, &attr );
   if (!found) {
      if (mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }
   return secret_key_check_required_attributes( tmpl, mode );
}


//  cast3_set_default_attributes()
//
CK_RV
cast3_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr      = NULL;
   CK_ATTRIBUTE   *value_len_attr  = NULL;
   CK_ATTRIBUTE   *type_attr       = NULL;
   CK_ULONG     len = 0L;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_len_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );

   if (!type_attr || !value_attr || !value_len_attr) {
      if (type_attr)      free( type_attr );
      if (value_attr)     free( value_attr );
      if (value_len_attr) free( value_len_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   value_len_attr->type       = CKA_VALUE_LEN;
   value_len_attr->ulValueLen = sizeof(CK_ULONG);
   value_len_attr->pValue     = (CK_BYTE *)value_len_attr + sizeof(CK_ATTRIBUTE);
   *(CK_ULONG *)value_len_attr->pValue = len;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_CAST3;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   template_update_attribute( tmpl, value_len_attr );

   return CKR_OK;
}


// cast3_validate_attribute()
//
CK_RV
cast3_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   CK_ULONG len;

   switch (attr->type) {
      case CKA_VALUE:
         {
            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (attr->ulValueLen > 8 || attr->ulValueLen < 1){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      case CKA_VALUE_LEN:
         {
            if (mode != MODE_KEYGEN && mode != MODE_DERIVE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            len = *(CK_ULONG *)attr->pValue;
            if (len > 8 || len < 1){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


// cast5_check_required_attributes()
//
CK_RV
cast5_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }
   found = template_attribute_find( tmpl, CKA_VALUE_LEN, &attr );
   if (!found) {
      if (mode == MODE_KEYGEN){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }
   return secret_key_check_required_attributes( tmpl, mode );
}


//  cast5_set_default_attributes()
//
CK_RV
cast5_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr      = NULL;
   CK_ATTRIBUTE   *value_len_attr  = NULL;
   CK_ATTRIBUTE   *type_attr       = NULL;
   CK_ULONG     len = 0L;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr       = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr      = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   value_len_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );

   if (!type_attr || !value_attr || !value_len_attr) {
      if (type_attr)      free( type_attr );
      if (value_attr)     free( value_attr );
      if (value_len_attr) free( value_len_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   value_len_attr->type = CKA_VALUE_LEN;
   value_len_attr->ulValueLen = sizeof(CK_ULONG);
   value_len_attr->pValue     = (CK_BYTE *)value_len_attr + sizeof(CK_ATTRIBUTE);
   *(CK_ULONG *)value_len_attr->pValue = len;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_CAST5;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   template_update_attribute( tmpl, value_len_attr );

   return CKR_OK;
}


// cast5_validate_attribute()
//
CK_RV
cast5_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   CK_ULONG  len;

   switch (attr->type) {
      case CKA_VALUE:
         {
            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (attr->ulValueLen > 16 || attr->ulValueLen < 1){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      case CKA_VALUE_LEN:
         {
            if (mode != MODE_KEYGEN && mode != MODE_DERIVE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            len = *(CK_ULONG *)attr->pValue;
            if (len < 1 || len > 16){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


// idea_check_required_attributes()
//
CK_RV
idea_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }
   return secret_key_check_required_attributes( tmpl, mode );
}


//  idea_set_default_attributes()
//
CK_RV
idea_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr = NULL;
   CK_ATTRIBUTE   *type_attr  = NULL;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   if (!type_attr || !value_attr) {
      if (type_attr)  free( type_attr );
      if (value_attr) free( value_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_IDEA;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   return CKR_OK;
}


// idea_validate_attribute()
//
CK_RV
idea_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_VALUE:
         {
            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (attr->ulValueLen != 16){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


// cdmf_check_required_attributes()
//
CK_RV
cdmf_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }
   return secret_key_check_required_attributes( tmpl, mode );
}


#if !(NOCDMF)
//  cdmf_set_default_attributes()
//
CK_RV
cdmf_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr = NULL;
   CK_ATTRIBUTE   *type_attr  = NULL;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !value_attr) {
      if (type_attr)  free( type_attr );
      if (value_attr) free( value_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_CDMF;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   return CKR_OK;
}


// cdmf_validate_attribute()
//
CK_RV
cdmf_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   CK_ULONG len;

   switch (attr->type) {
      case CKA_VALUE:
         {
#if 0
            CDMF_Transform_Args  args;
#endif
            CK_ULONG             req_len, repl_len;
            CK_BYTE              cdmf_key[DES_KEY_SIZE];
            CK_RV                rc;

            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (attr->ulValueLen != DES_KEY_SIZE){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
#if 0
            req_len  = sizeof(args);
            repl_len = DES_KEY_SIZE;

            memcpy( args.des_key, attr->pValue, DES_KEY_SIZE );

            rc = communicate( PK_CDMF_TRANSFORM_KEY,
                             &args,      req_len,
                              cdmf_key, &repl_len,
                              NULL,      0,
                              NULL,      0 );

            if (rc != CKR_OK)
               return rc;

            if (rc == CKR_OK) {
               if (repl_len != DES_KEY_SIZE)
                  return CKR_GENERAL_ERROR;

               memcpy( attr->pValue, cdmf_key, DES_KEY_SIZE );
            }

            return CKR_OK;
#else
            return tok_cdmf_transform(attr->pValue, DES_KEY_SIZE);
#endif
         }

      case CKA_VALUE_LEN:
         {
            if (nv_token_data->tweak_vector.netscape_mods == TRUE) {
               if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
                  len = *(CK_ULONG *)attr->pValue;
                  if (len != DES_KEY_SIZE){
                     st_err_log(9, __FILE__, __LINE__);
                     return CKR_ATTRIBUTE_VALUE_INVALID;
                  }
                  else
                     return CKR_OK;
               }
               else{
                  st_err_log(7, __FILE__, __LINE__);
                  return CKR_ATTRIBUTE_READ_ONLY;
               }
            }
            else{
               st_err_log(49, __FILE__, __LINE__);
               return CKR_TEMPLATE_INCONSISTENT;
            }
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}

#endif

// skipjack_check_required_attributes()
//
CK_RV
skipjack_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }
   return secret_key_check_required_attributes( tmpl, mode );
}


//  skipjack_set_default_attributes()
//
CK_RV
skipjack_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr = NULL;
   CK_ATTRIBUTE   *type_attr  = NULL;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !value_attr) {
      if (type_attr)  free( type_attr );
      if (value_attr) free( value_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type         = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_SKIPJACK;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   return CKR_OK;
}


// skipjack_validate_attribute()
//
CK_RV
skipjack_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_VALUE:
         {
            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (attr->ulValueLen != 20){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


// baton_check_required_attributes()
//
CK_RV
baton_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }
   return secret_key_check_required_attributes( tmpl, mode );
}


//  baton_set_default_attributes()
//
CK_RV
baton_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr = NULL;
   CK_ATTRIBUTE   *type_attr  = NULL;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !value_attr) {
      if (type_attr)  free( type_attr );
      if (value_attr) free( value_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_BATON;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   return CKR_OK;
}


// baton_validate_attribute()
//
CK_RV
baton_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_VALUE:
         {
            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (attr->ulValueLen != 40){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


// juniper_check_required_attributes()
//
CK_RV
juniper_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }
   return secret_key_check_required_attributes( tmpl, mode );
}


//  juniper_set_default_attributes()
//
CK_RV
juniper_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   *value_attr = NULL;
   CK_ATTRIBUTE   *type_attr  = NULL;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   type_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );

   if (!type_attr || !value_attr) {
      if (type_attr)  free( type_attr );
      if (value_attr) free( value_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type         = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_JUNIPER;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );
   return CKR_OK;
}


// juniper_validate_attribute()
//
CK_RV
juniper_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   switch (attr->type) {
      case CKA_VALUE:
         {
            if (mode != MODE_CREATE){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (attr->ulValueLen != 40){
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            else
               return CKR_OK;
         }

      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}

//  aes_set_default_attributes()
//
CK_RV
aes_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE   * value_attr  = NULL;
   CK_ATTRIBUTE   * type_attr   = NULL;

   if (mode)
      value_attr = NULL;

   secret_key_set_default_attributes( tmpl, mode );

   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) );
   type_attr  = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );

   if (!value_attr || !type_attr) {
      if (value_attr) free( value_attr );
      if (type_attr)  free( type_attr );
      st_err_log(1, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = 0;
   value_attr->pValue     = NULL;

   type_attr->type       = CKA_KEY_TYPE;
   type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
   type_attr->pValue     = (CK_BYTE *)type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)type_attr->pValue = CKK_AES;

   template_update_attribute( tmpl, type_attr );
   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}

// aes_check_required_attributes()
//
CK_RV
aes_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode )
{
   CK_ATTRIBUTE *attr = NULL;
   CK_BBOOL   found;

   found = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (!found) {
      if (mode == MODE_CREATE){
         st_err_log(48, __FILE__, __LINE__);
         return CKR_TEMPLATE_INCOMPLETE;
      }
   }

   return secret_key_check_required_attributes( tmpl, mode );
}

//
//
CK_RV
aes_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode )
{
   CK_BYTE   * ptr = NULL;
   CK_ULONG    val;

   switch (attr->type) {
      case CKA_VALUE:
         // key length is either 16, 24 or 32 bytes
         //
         if (mode == MODE_CREATE) {
            if (attr->ulValueLen != AES_KEY_SIZE_128 &&
		attr->ulValueLen != AES_KEY_SIZE_192 &&
		attr->ulValueLen != AES_KEY_SIZE_256   )
	    {
               st_err_log(9, __FILE__, __LINE__);
               return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            return CKR_OK;
	 } else {
            st_err_log(7, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_READ_ONLY;
         }
      case CKA_VALUE_LEN:
         if (mode == MODE_CREATE || mode == MODE_DERIVE ||
             mode == MODE_KEYGEN || mode == MODE_UNWRAP)
         {
	    val = *(CK_ULONG *)attr->pValue;
            if (val != AES_KEY_SIZE_128 &&
		val != AES_KEY_SIZE_192 &&
		val != AES_KEY_SIZE_256   ){
               st_err_log(7, __FILE__, __LINE__);
               return CKR_TEMPLATE_INCONSISTENT;
            }
	    return CKR_OK;
         }
         else{
            st_err_log(49, __FILE__, __LINE__);
            return CKR_TEMPLATE_INCONSISTENT;
         }
      default:
         return secret_key_validate_attribute( tmpl, attr, mode );
   }
}


//
//
CK_RV
aes_wrap_get_data( TEMPLATE   * tmpl,
                   CK_BBOOL     length_only,
                   CK_BYTE   ** data,
                   CK_ULONG   * data_len )
{
   CK_ATTRIBUTE    * attr = NULL;
   CK_BYTE      * ptr  = NULL;
   CK_RV          rc;


   if (!tmpl || !data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   rc = template_attribute_find( tmpl, CKA_VALUE, &attr );
   if (rc == FALSE){
      st_err_log(26, __FILE__, __LINE__);
      return CKR_KEY_NOT_WRAPPABLE;
   }
   *data_len = attr->ulValueLen;

   if (length_only == FALSE) {
      ptr = (CK_BYTE *)malloc( attr->ulValueLen );
      if (!ptr){
         st_err_log(1, __FILE__, __LINE__);
         return CKR_HOST_MEMORY;
      }
      memcpy( ptr, attr->pValue, attr->ulValueLen );

      *data = ptr;
   }

   return CKR_OK;
}

//
//
CK_RV
aes_unwrap( TEMPLATE *tmpl,
            CK_BYTE  *data,
            CK_ULONG  data_len,
            CK_BBOOL  fromend )
{
   CK_ATTRIBUTE  * value_attr   = NULL;
   CK_ATTRIBUTE  * val_len_attr = NULL;
   CK_BYTE       * ptr          = NULL;
   CK_ULONG        i;
   CK_ULONG	   key_size;
   CK_BBOOL	   found        = FALSE;

   
   /* If the user didn't specify the size of the AES key being
    * unwrapped, we return. - KEY */
   found = template_attribute_find( tmpl, CKA_VALUE_LEN, &val_len_attr );
   if (!found){
      st_err_log(48, __FILE__, __LINE__);
      return CKR_TEMPLATE_INCOMPLETE;
   }
   key_size = *(CK_ULONG *)val_len_attr->pValue;
      
   /* key_size should be one of AES's possible sizes */
   if (key_size != AES_KEY_SIZE_128 &&
       key_size != AES_KEY_SIZE_192 &&
       key_size != AES_KEY_SIZE_256){
      st_err_log(62, __FILE__, __LINE__);
      return CKR_ATTRIBUTE_VALUE_INVALID;
   }
   if (fromend == TRUE)
      ptr = data + data_len - key_size;
   else
      ptr = data;
   
#if 0
   if (nv_token_data->tweak_vector.check_des_parity == TRUE) {
      for (i=0; i < 3*DES_KEY_SIZE; i++) {
         if (parity_is_odd(ptr[i]) == FALSE){
            st_err_log(9, __FILE__, __LINE__);
            return CKR_ATTRIBUTE_VALUE_INVALID;
         }
      }
   }
#endif
   
   value_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + key_size );

   if (!value_attr) {
      if (value_attr)
         free( value_attr );
      st_err_log(0, __FILE__, __LINE__);

      return CKR_HOST_MEMORY;
   }

   value_attr->type       = CKA_VALUE;
   value_attr->ulValueLen = key_size;
   value_attr->pValue     = (CK_BYTE *)value_attr + sizeof(CK_ATTRIBUTE);
   memcpy( value_attr->pValue, ptr, key_size );

   template_update_attribute( tmpl, value_attr );

   return CKR_OK;
}


