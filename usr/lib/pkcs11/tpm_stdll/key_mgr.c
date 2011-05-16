
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

/***************************************************************************
                          Change Log
                          ==========
       4/25/03    Kapil Sood (kapil@corrent.com)
                  Added DH key pair generation and DH shared key derivation
                  functions.
****************************************************************************/


// File:  key_mgr.c
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


static CK_BBOOL true = TRUE, false = FALSE;

//
//
CK_RV
key_mgr_generate_key( SESSION           * sess,
                      CK_MECHANISM      * mech,
                      CK_ATTRIBUTE      * pTemplate,
                      CK_ULONG            ulCount,
                      CK_OBJECT_HANDLE  * handle )
{
   OBJECT        * key_obj  = NULL;
   CK_ATTRIBUTE  * attr     = NULL;
   CK_ATTRIBUTE  * new_attr = NULL;
   CK_ULONG        i, keyclass, subclass = 0;
   CK_BBOOL        flag;
   CK_RV           rc;


   if (!sess || !mech || !handle){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (!pTemplate && (ulCount != 0)){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   // it's silly but Cryptoki allows the user to specify the CKA_CLASS
   // in the template.  so we have to iterate through the provided template
   // and make sure that if CKA_CLASS is CKO_SECRET_KEY, if it is present.
   //
   // it would have been more logical for Cryptoki to forbid specifying
   // the CKA_CLASS attribute when generating a key
   //
   for (i=0; i < ulCount; i++) {
      if (pTemplate[i].type == CKA_CLASS) {
         keyclass = *(CK_OBJECT_CLASS *)pTemplate[i].pValue;
         if (keyclass != CKO_SECRET_KEY){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
         }
      }

      if (pTemplate[i].type == CKA_KEY_TYPE)
         subclass = *(CK_ULONG *)pTemplate[i].pValue;
   }


   switch (mech->mechanism) {
      case CKM_DES_KEY_GEN:
         if (subclass != 0 && subclass != CKK_DES){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
         }

         subclass = CKK_DES;
         break;

      case CKM_DES3_KEY_GEN:
         if (subclass != 0 && subclass != CKK_DES3){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
         }

         subclass = CKK_DES3;
         break;

#if !(NOCDMF)
      case CKM_CDMF_KEY_GEN:
         if (subclass != 0 && subclass != CKK_CDMF){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
         }

         subclass = CKK_CDMF;
         break;
#endif

      case CKM_SSL3_PRE_MASTER_KEY_GEN:
         if (subclass != 0 && subclass != CKK_GENERIC_SECRET){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
         }
         if (mech->ulParameterLen != sizeof(CK_VERSION)){
            OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
            return CKR_MECHANISM_PARAM_INVALID;
         }
         subclass = CKK_GENERIC_SECRET;
         break;

      case CKM_AES_KEY_GEN:
	 if (subclass != 0 && subclass != CKK_AES){
	    OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
	    return CKR_TEMPLATE_INCONSISTENT;
	 }

	 subclass = CKK_AES;
	 break;

      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         return CKR_MECHANISM_INVALID;
   }


   rc = object_mgr_create_skel( sess,
                                pTemplate, ulCount,
                                MODE_KEYGEN,
                                CKO_SECRET_KEY, subclass,
                                &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_CREATE_SKEL);
      goto error;
   }

   // at this point, 'key_obj' should contain a skeleton key.  depending on
   // the key type, we may need to extract one or more attributes from
   // the object prior to generating the key data (ie. variable key length)
   //

   switch (mech->mechanism) {
      case CKM_DES_KEY_GEN:
            rc = ckm_des_key_gen( key_obj->template );
            break;

         case CKM_DES3_KEY_GEN:
            rc = ckm_des3_key_gen( key_obj->template );
            break;

#if !(NOCDMF)
         case CKM_CDMF_KEY_GEN:
            rc = ckm_cdmf_key_gen( key_obj->template );
            break;
#endif

         case CKM_SSL3_PRE_MASTER_KEY_GEN:
            rc = ckm_ssl3_pre_master_key_gen( key_obj->template, mech );
            break;
#ifndef NOAES
	 case CKM_AES_KEY_GEN:
	    rc = ckm_aes_key_gen( key_obj->template );
	    break;
#endif
      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         rc = CKR_MECHANISM_INVALID;
   }

   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_KEYGEN);
      goto error;
   }

   // we can now set CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE
   // to their appropriate values.  this only applies to CKO_SECRET_KEY
   // and CKO_PRIVATE_KEY objects
   //
   flag = template_attribute_find( key_obj->template, CKA_SENSITIVE, &attr );
   if (flag == TRUE) {
      flag = *(CK_BBOOL *)attr->pValue;

      rc = build_attribute( CKA_ALWAYS_SENSITIVE, &flag, sizeof(CK_BBOOL), &new_attr );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_BLD_ATTR);
         goto error;
      }
      template_update_attribute( key_obj->template, new_attr );

   } else {
      rc = CKR_FUNCTION_FAILED;
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      goto error;
   }


   flag = template_attribute_find( key_obj->template, CKA_EXTRACTABLE, &attr );
   if (flag == TRUE) {
      flag = *(CK_BBOOL *)attr->pValue;

      rc = build_attribute( CKA_NEVER_EXTRACTABLE, &true, sizeof(CK_BBOOL), &new_attr );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_BLD_ATTR);
         goto error;
      }
      if (flag == TRUE)
         *(CK_BBOOL *)new_attr->pValue = FALSE;

      template_update_attribute( key_obj->template, new_attr );

   } else {
      rc = CKR_FUNCTION_FAILED;
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      goto error;
   }


   // at this point, the key should be fully constructed...assign
   // an object handle and store the key
   //
   rc = object_mgr_create_final( sess, key_obj, handle );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_CREATE_FINAL);
      goto error;
   }
   return rc;

error:
   if (key_obj) object_free( key_obj );

   *handle = 0;

   return rc;
}


//
//
CK_RV
key_mgr_generate_key_pair( SESSION           * sess,
                           CK_MECHANISM      * mech,
                           CK_ATTRIBUTE      * publ_tmpl,
                           CK_ULONG            publ_count,
                           CK_ATTRIBUTE      * priv_tmpl,
                           CK_ULONG            priv_count,
                           CK_OBJECT_HANDLE  * publ_key_handle,
                           CK_OBJECT_HANDLE  * priv_key_handle )
{
   OBJECT        * publ_key_obj = NULL;
   OBJECT        * priv_key_obj = NULL;
   CK_ATTRIBUTE  * attr         = NULL;
   CK_ATTRIBUTE  * new_attr     = NULL;
   CK_ULONG        i, keyclass, subclass = 0;
   CK_BBOOL        flag;
   CK_RV           rc;

   if (!sess || !mech || !publ_key_handle || !priv_key_handle){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (!publ_tmpl && (publ_count != 0)){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (!priv_tmpl && (priv_count != 0)){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   // it's silly but Cryptoki allows the user to specify the CKA_CLASS
   // in the template.  so we have to iterate through the provided template
   // and make sure that if CKA_CLASS is valid, if it is present.
   //
   // it would have been more logical for Cryptoki to forbid specifying
   // the CKA_CLASS attribute when generating a key
   //
   for (i=0; i < publ_count; i++) {
      if (publ_tmpl[i].type == CKA_CLASS) {
         keyclass = *(CK_OBJECT_CLASS *)publ_tmpl[i].pValue;
         if (keyclass != CKO_PUBLIC_KEY){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
         }
      }

      if (publ_tmpl[i].type == CKA_KEY_TYPE)
         subclass = *(CK_ULONG *)publ_tmpl[i].pValue;
   }


   for (i=0; i < priv_count; i++) {
      if (priv_tmpl[i].type == CKA_CLASS) {
         keyclass = *(CK_OBJECT_CLASS *)priv_tmpl[i].pValue;
         if (keyclass != CKO_PRIVATE_KEY){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
         }
      }

      if (priv_tmpl[i].type == CKA_KEY_TYPE) {
         CK_ULONG temp = *(CK_ULONG *)priv_tmpl[i].pValue;
         if (temp != subclass){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
         }
      }
   }


   switch (mech->mechanism) {
      case CKM_RSA_PKCS_KEY_PAIR_GEN:
         if (subclass != 0 && subclass != CKK_RSA){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
          }

         subclass = CKK_RSA;
         break;

#if !(NODSA)
      case CKM_DSA_KEY_PAIR_GEN:
         if (subclass != 0 && subclass != CKK_DSA){
           OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
           return CKR_TEMPLATE_INCONSISTENT;
         }
         subclass = CKK_DSA;
         break;
#endif

/* Begin code contributed by Corrent corp. */
#if !(NODH)
      case CKM_DH_PKCS_KEY_PAIR_GEN:
         if (subclass != 0 && subclass != CKK_DH){
           OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
           return CKR_TEMPLATE_INCONSISTENT;
         }
         subclass = CKK_DH;
         break;
#endif
/* End  code contributed by Corrent corp. */

      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         return CKR_MECHANISM_INVALID;
   }


   rc = object_mgr_create_skel( sess,
                                publ_tmpl,       publ_count,
                                MODE_KEYGEN,
                                CKO_PUBLIC_KEY,  subclass,
                                &publ_key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_CREATE_SKEL);
      goto error;
   }
   rc = object_mgr_create_skel( sess,
                                priv_tmpl,       priv_count,
                                MODE_KEYGEN,
                                CKO_PRIVATE_KEY, subclass,
                                &priv_key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_CREATE_SKEL);
      goto error;
   }

   // at this point, 'key_obj' should contain a skeleton key.  depending on
   // the key type, we may need to extract one or more attributes from
   // the object prior to generating the key data (ie. variable key length)
   //

   switch (mech->mechanism) {
      case CKM_RSA_PKCS_KEY_PAIR_GEN:
         rc = ckm_rsa_key_pair_gen( publ_key_obj->template,
                                    priv_key_obj->template );
         break;

#if !(NODSA)
      case CKM_DSA_KEY_PAIR_GEN:
         rc = ckm_dsa_key_pair_gen( publ_key_obj->template,
                                    priv_key_obj->template );
         break;
#endif

/* Begin code contributed by Corrent corp. */
#if !(NODH)
      case CKM_DH_PKCS_KEY_PAIR_GEN:
         rc = ckm_dh_pkcs_key_pair_gen( publ_key_obj->template,
                                        priv_key_obj->template );
         break;
#endif
/* End code contributed by Corrent corp. */

      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         rc = CKR_MECHANISM_INVALID;
         break;
   }

   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_KEYGEN);
      goto error;
   }

   // we can now set CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE
   // to their appropriate values.  this only applies to CKO_SECRET_KEY
   // and CKO_PRIVATE_KEY objects
   //
   flag = template_attribute_find( priv_key_obj->template, CKA_SENSITIVE, &attr );
   if (flag == TRUE) {
      flag = *(CK_BBOOL *)attr->pValue;

      rc = build_attribute( CKA_ALWAYS_SENSITIVE, &flag, sizeof(CK_BBOOL), &new_attr );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_BLD_ATTR);
         goto error;
      }
      template_update_attribute( priv_key_obj->template, new_attr );

   } else {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto error;
   }


   flag = template_attribute_find( priv_key_obj->template, CKA_EXTRACTABLE, &attr );
   if (flag == TRUE) {
      flag = *(CK_BBOOL *)attr->pValue;

      rc = build_attribute( CKA_NEVER_EXTRACTABLE, &true, sizeof(CK_BBOOL), &new_attr );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_BLD_ATTR);
         goto error;
      }
      if (flag == TRUE)
         *(CK_BBOOL *)new_attr->pValue = false;

      template_update_attribute( priv_key_obj->template, new_attr );

   } else {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto error;
   }


   // at this point, the keys should be fully constructed...assign
   // object handles and store the keys
   //
   rc = object_mgr_create_final( sess, publ_key_obj, publ_key_handle );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_CREATE_FINAL);
      goto error;
   }
   rc = object_mgr_create_final( sess, priv_key_obj, priv_key_handle );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_CREATE_FINAL);
      // just calling object_free in the error path below would lead to a double
      // free error on session close - KEY 09/26/07
      object_mgr_destroy_object( sess, *publ_key_handle );
      publ_key_obj = NULL;
      goto error;
   }
   return rc;

error:
   if (publ_key_obj) object_free( publ_key_obj );
   if (priv_key_obj) object_free( priv_key_obj );

   *publ_key_handle = 0;
   *priv_key_handle = 0;

   return rc;
}


//
//
CK_RV
key_mgr_wrap_key( SESSION           * sess,
                  CK_BBOOL            length_only,
                  CK_MECHANISM      * mech,
                  CK_OBJECT_HANDLE    h_wrapping_key,
                  CK_OBJECT_HANDLE    h_key,
                  CK_BYTE           * wrapped_key,
                  CK_ULONG          * wrapped_key_len )
{
   ENCR_DECR_CONTEXT * ctx       = NULL;
   OBJECT            * key1_obj  = NULL;
   OBJECT            * key2_obj  = NULL;
   CK_ATTRIBUTE      * attr      = NULL;
   CK_BYTE           * data      = NULL;
   CK_ULONG            data_len;
   CK_OBJECT_CLASS     class;
   CK_KEY_TYPE         keytype;
   CK_BBOOL            flag;
   CK_RV               rc;


   if (!sess || !wrapped_key_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   rc = object_mgr_find_in_map1( h_wrapping_key, &key1_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_WRAPPING_KEY_HANDLE_INVALID);
      return CKR_WRAPPING_KEY_HANDLE_INVALID;
   }
   rc = object_mgr_find_in_map1( h_key, &key2_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_KEY_HANDLE_INVALID);
      return CKR_KEY_HANDLE_INVALID;
   }

   // is the key-to-be-wrapped EXTRACTABLE?
   //
   rc = template_attribute_find( key2_obj->template, CKA_EXTRACTABLE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
      return CKR_KEY_NOT_WRAPPABLE;  // could happen if user tries to wrap a public key
   }
   else {
      flag = *(CK_BBOOL *)attr->pValue;
      if (flag == FALSE){
         OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
         return CKR_KEY_NOT_WRAPPABLE;
      }
   }


   // what kind of key are we trying to wrap?  make sure the mechanism is
   // allowed to wrap this kind of key
   //
   rc = template_attribute_find( key2_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
      return CKR_KEY_NOT_WRAPPABLE;
   }
   else
      class = *(CK_OBJECT_CLASS *)attr->pValue;

   switch (mech->mechanism) {
#if !(NOCDMF)
      case CKM_CDMF_ECB:
      case CKM_CDMF_CBC:
#endif
      case CKM_DES_ECB:
      case CKM_DES_CBC:
      case CKM_DES3_ECB:
      case CKM_DES3_CBC:
      case CKM_AES_ECB:
      case CKM_AES_CBC:
         if (class != CKO_SECRET_KEY){
            OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
            return CKR_KEY_NOT_WRAPPABLE;
         }
         break;

#if !(NOCDMF)
      case CKM_CDMF_CBC_PAD:
#endif
      case CKM_DES_CBC_PAD:
      case CKM_DES3_CBC_PAD:
      case CKM_AES_CBC_PAD:
         // these mechanisms can wrap any type of key
         //
         break;

      case CKM_RSA_PKCS:
         if (class != CKO_SECRET_KEY){
            OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
            return CKR_KEY_NOT_WRAPPABLE;
         }
         break;

      default:
         OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
         return CKR_KEY_NOT_WRAPPABLE;
   }


   // extract the secret data to be wrapped
   //
   rc = template_attribute_find( key2_obj->template, CKA_KEY_TYPE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
      return CKR_KEY_NOT_WRAPPABLE;
   }
   else
      keytype = *(CK_KEY_TYPE *)attr->pValue;

   switch (keytype) {
#if !(NOCDMF)
      case CKK_CDMF:
#endif
      case CKK_DES:
         rc = des_wrap_get_data( key2_obj->template, length_only, &data, &data_len );
         if (rc != CKR_OK){
            OCK_LOG_ERR(ERR_DES_WRAP_GETDATA);
            return rc;
         }
         break;

      case CKK_DES3:
         rc = des3_wrap_get_data( key2_obj->template, length_only, &data, &data_len );
         if (rc != CKR_OK){
            OCK_LOG_ERR(ERR_DES3_WRAP_GETDATA);
            return rc;
         }
         break;

      case CKK_RSA:
         rc = rsa_priv_wrap_get_data( key2_obj->template, length_only, &data, &data_len );
         if (rc != CKR_OK){
            OCK_LOG_ERR(ERR_RSA_WRAP_GETDATA);
            return rc;
         }
         break;

#if !(NODSA)
      case CKK_DSA:
         rc = dsa_priv_wrap_get_data( key2_obj->template, length_only, &data, &data_len );
         if (rc != CKR_OK){
            OCK_LOG_ERR(ERR_DSA_WRAP_GETDATA);
            return rc;
         }
         break;
#endif

      case CKK_GENERIC_SECRET:
         rc = generic_secret_wrap_get_data( key2_obj->template, length_only, &data, &data_len );
         if (rc != CKR_OK){
            OCK_LOG_ERR(ERR_GENERIC_WRAP_GETDATA);
            return rc;
         }
         break;
#ifndef NOAES
      case CKK_AES:
	 rc = aes_wrap_get_data( key2_obj->template, length_only, &data, &data_len );
	 if (rc != CKR_OK){
	    OCK_LOG_ERR(ERR_AES_WRAP_GETDATA);
	    return rc;
	 }
	 break;
#endif
      default:
         OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
         return CKR_KEY_NOT_WRAPPABLE;
   }

   // we might need to format the wrapped data based on the mechanism
   //
   switch (mech->mechanism) {
#if !(NOCMF)
      case CKM_CDMF_ECB:
      case CKM_CDMF_CBC:
#endif
      case CKM_DES_ECB:
      case CKM_DES_CBC:
      case CKM_DES3_ECB:
      case CKM_DES3_CBC:
         rc = ckm_des_wrap_format( length_only, &data, &data_len );
         if (rc != CKR_OK) {
            OCK_LOG_ERR(ERR_DES_WRAP_FORMAT);
            if (data) free( data );
            return rc;
         }
         break;
#ifndef NOAES
      case CKM_AES_ECB:
      case CKM_AES_CBC:
	 rc = ckm_aes_wrap_format( length_only, &data, &data_len );
	 if (rc != CKR_OK) {
	    OCK_LOG_ERR(ERR_AES_WRAP_FORMAT);
	    if (data) free( data );
	    return rc;
	 }
	 break;
#endif
#if !(NOCMF)
      case CKM_CDMF_CBC_PAD:
#endif
      case CKM_DES_CBC_PAD:
      case CKM_DES3_CBC_PAD:
      case CKM_AES_CBC_PAD:
         // these mechanisms pad themselves
         //
         break;

      case CKM_RSA_PKCS:
//         rc = ckm_rsa_wrap_format( length_only, &data, &data_len );
//         if (rc != CKR_OK) {
//            free( data );
//            return rc;
//         }
         break;

      default:
         OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
         return CKR_KEY_NOT_WRAPPABLE;
   }

   ctx = (ENCR_DECR_CONTEXT *)malloc(sizeof(ENCR_DECR_CONTEXT));
   if (!ctx){
      OCK_LOG_ERR(ERR_HOST_MEMORY);
      return CKR_HOST_MEMORY;
   }
   memset( ctx, 0x0, sizeof(ENCR_DECR_CONTEXT) );

   // prepare to do the encryption
   //
   rc = encr_mgr_init( sess, ctx, OP_WRAP, mech, h_wrapping_key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_ENCRYPTMGR_INIT);
      return rc;
   }
   // do the encryption and clean up.  at this point, 'value' may or may not
   // be NULL depending on 'length_only'
   //
   rc = encr_mgr_encrypt( sess,        length_only,
                          ctx,
                          data,        data_len,
                          wrapped_key, wrapped_key_len );
   if (data != NULL){
      free( data );
   }
   encr_mgr_cleanup( ctx );
   free( ctx );
   
   return rc;
}


//
//
CK_RV
key_mgr_unwrap_key( SESSION           * sess,
                    CK_MECHANISM      * mech,
                    CK_ATTRIBUTE      * attributes,
                    CK_ULONG            attrib_count,
                    CK_BYTE           * wrapped_key,
                    CK_ULONG            wrapped_key_len,
                    CK_OBJECT_HANDLE    h_unwrapping_key,
                    CK_OBJECT_HANDLE  * h_unwrapped_key )
{
   ENCR_DECR_CONTEXT * ctx = NULL;
   OBJECT            * key_obj = NULL;
   CK_BYTE           * data = NULL;
   CK_ULONG            data_len;
   CK_ULONG            keyclass, keytype;
   CK_ULONG            i;
   CK_BBOOL            found_class, found_type, fromend;
   CK_RV               rc;


   if (!sess || !wrapped_key || !h_unwrapped_key){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   rc = object_mgr_find_in_map1( h_unwrapping_key, &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_WRAPPING_KEY_HANDLE_INVALID);
      return CKR_WRAPPING_KEY_HANDLE_INVALID;
   }

   found_class    = FALSE;
   found_type     = FALSE;

   // some mechanisms are restricted to wrapping certain types of keys.
   // in these cases, the CKA_CLASS attribute is implied and isn't required
   // to be specified in the template (though it still may appear)
   //
   switch (mech->mechanism) {
      case CKM_RSA_PKCS:
         keyclass = CKO_SECRET_KEY;
         found_class = TRUE;
         break;

#if !(NOCMF)
      case CKM_CDMF_ECB:
      case CKM_CDMF_CBC:
#endif
      case CKM_DES_ECB:
      case CKM_DES_CBC:
      case CKM_DES3_ECB:
      case CKM_DES3_CBC:
      case CKM_AES_ECB:
      case CKM_AES_CBC:
         keyclass = CKO_SECRET_KEY;
         found_class = TRUE;
         break;

#if !(NOCMF)
      case CKM_CDMF_CBC_PAD:
#endif
      case CKM_DES_CBC_PAD:
      case CKM_DES3_CBC_PAD:
      case CKM_AES_CBC_PAD:
         // these mechanisms can wrap any type of key so nothing is implied
         //
         break;
   }


   // extract key type and key class from the template if they exist.  we
   // have to scan the entire template in case the CKA_CLASS or CKA_KEY_TYPE
   // attributes are duplicated
   //
   for (i=0; i < attrib_count; i++) {
      switch (attributes[i].type) {
         case CKA_CLASS:
            keyclass = *(CK_OBJECT_CLASS *)attributes[i].pValue;
            found_class = TRUE;
            break;

         case CKA_KEY_TYPE:
            keytype = *(CK_KEY_TYPE *)attributes[i].pValue;
            found_type = TRUE;
            break;
      }
   }

   // if we're unwrapping a private key, we can extract the key type from
   // the BER-encoded information
   //
   if (found_class == FALSE || (found_type == FALSE && keyclass !=
CKO_PRIVATE_KEY)){
      OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
      return CKR_TEMPLATE_INCOMPLETE;
   }

   // final check to see if mechanism is allowed to unwrap such a key
   //
   switch (mech->mechanism) {
      case CKM_RSA_PKCS:
         if (keyclass != CKO_SECRET_KEY){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
         }
         break;

#if !(NOCMF)
      case CKM_CDMF_ECB:
      case CKM_CDMF_CBC:
#endif
      case CKM_DES_ECB:
      case CKM_DES_CBC:
      case CKM_DES3_ECB:
      case CKM_DES3_CBC:
      case CKM_AES_ECB:
      case CKM_AES_CBC:
         if (keyclass != CKO_SECRET_KEY){
            OCK_LOG_ERR(ERR_TEMPLATE_INCONSISTENT);
            return CKR_TEMPLATE_INCONSISTENT;
         }
         break;

#if !(NOCMF)
      case CKM_CDMF_CBC_PAD:
#endif
      case CKM_DES_CBC_PAD:
      case CKM_DES3_CBC_PAD:
      case CKM_AES_CBC_PAD:
         break;

      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         return CKR_MECHANISM_INVALID;
   }


   // looks okay...do the decryption
   //
   ctx = (ENCR_DECR_CONTEXT *)malloc(sizeof(ENCR_DECR_CONTEXT));
   if (!ctx){
      OCK_LOG_ERR(ERR_HOST_MEMORY);
      return CKR_HOST_MEMORY;
   }
   memset( ctx, 0x0, sizeof(ENCR_DECR_CONTEXT) );

   rc = decr_mgr_init( sess, ctx, OP_UNWRAP, mech, h_unwrapping_key );
   if (rc != CKR_OK)
      return rc;

   rc = decr_mgr_decrypt( sess,
                          TRUE,
                          ctx,
                          wrapped_key, wrapped_key_len,
                          data,       &data_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DECRYPTMGR_DECRYPT);
      goto error;
   }
   data = (CK_BYTE *)malloc(data_len);
   if (!data) {
      OCK_LOG_ERR(ERR_HOST_MEMORY);
      rc = CKR_HOST_MEMORY;
      goto error;
   }

   rc = decr_mgr_decrypt( sess,
                          FALSE,
                          ctx,
                          wrapped_key, wrapped_key_len,
                          data,       &data_len );

   decr_mgr_cleanup( ctx );
   free( ctx );

   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DECRYPTMGR_DECRYPT);
      goto error;
   }
   // if we use X.509, the data will be padded from the front with zeros.
   // PKCS #11 specifies that for this mechanism, CK_VALUE is to be read
   // from the end of the data.
   //
   // Note: the PKCS #11 reference implementation gets this wrong.
   //
   if (mech->mechanism == CKM_RSA_X_509)
      fromend = TRUE;
   else
      fromend = FALSE;

   // extract the key type from the PrivateKeyInfo::AlgorithmIndicator
   //
   if (keyclass == CKO_PRIVATE_KEY) {
      rc = key_mgr_get_private_key_type( data, data_len, &keytype );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_KEYMGR_GETPRIVKEY);
         goto error;
      }
   }


   // we have decrypted the wrapped key data.  we also
   // know what type of key it is.  now we need to construct a new key
   // object...
   //

   rc = object_mgr_create_skel( sess,
                                attributes,    attrib_count,
                                MODE_UNWRAP,
                                keyclass,      keytype,
                                &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_CREATE_SKEL);
      goto error;
   }
   // at this point, 'key_obj' should contain a skeleton key.  depending on
   // the key type.  we're now ready to plug in the decrypted key data.
   // in some cases, the data will be BER-encoded so we'll need to decode it.
   //
   // this routine also ensires that CKA_EXTRACTABLE == FALSE,
   // CKA_ALWAYS_SENSITIVE == FALSE and CKA_LOCAL == FALSE
   //
   switch (keyclass) {
      case CKO_SECRET_KEY:
         rc = secret_key_unwrap( key_obj->template, keytype, data, data_len, fromend );
         break;

      case CKO_PRIVATE_KEY:
         rc = priv_key_unwrap( key_obj->template, keytype, data, data_len );
         break;

      default:
         rc = CKR_WRAPPED_KEY_INVALID;
         break;
   }

   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_KEY_UNWRAP);
      goto error;
   }
   // at this point, the key should be fully constructed...assign
   // an object handle and store the key
   //
   rc = object_mgr_create_final( sess, key_obj, h_unwrapped_key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_CREATE_FINAL);
      goto error;
   }
   if (data) free(data);
   return rc;

error:
   if (key_obj) object_free( key_obj );
   if (data)    free(data);

   return rc;
}


CK_RV
key_mgr_get_private_key_type( CK_BYTE     *keydata,
                              CK_ULONG     keylen,
                              CK_KEY_TYPE *keytype )
{
   CK_BYTE  *alg = NULL;
   CK_BYTE  *priv_key = NULL;
   CK_ULONG  alg_len;
   CK_RV    rc;

   rc = ber_decode_PrivateKeyInfo( keydata, keylen, &alg, &alg_len, &priv_key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DECODE_PRIVKEY);
      return rc;
   }
   // check the entire AlgorithmIdentifier for RSA
   //
   if (alg_len >= ber_rsaEncryptionLen) {
      if (memcmp(alg, ber_rsaEncryption, ber_rsaEncryptionLen) == 0) {
         *keytype = CKK_RSA;
         return CKR_OK;
      }
   }

   // Check only the OBJECT IDENTIFIER for DSA
   //
   if (alg_len >= ber_idDSALen) {
      if (memcmp(alg, ber_idDSA, ber_idDSALen) == 0) {
          *keytype = CKK_DSA;
          return CKR_OK;
      }
   }

   OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
   return CKR_TEMPLATE_INCOMPLETE;
}


//
//
CK_RV
key_mgr_derive_key( SESSION           * sess,
                    CK_MECHANISM      * mech,
                    CK_OBJECT_HANDLE    base_key,
                    CK_OBJECT_HANDLE  * derived_key,
                    CK_ATTRIBUTE      * pTemplate,
                    CK_ULONG            ulCount )
{
   if (!sess || !mech){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (!pTemplate && (ulCount != 0)){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   switch (mech->mechanism)
   {
      case CKM_SSL3_MASTER_KEY_DERIVE:
      {
         if (!derived_key){
            OCK_LOG_ERR(ERR_FUNCTION_FAILED);
            return CKR_FUNCTION_FAILED;
         }
         return ssl3_master_key_derive( sess, mech, base_key,
                                        pTemplate, ulCount, derived_key );
      }
      break ;

      case CKM_SSL3_KEY_AND_MAC_DERIVE:
      {
         CK_SSL3_KEY_MAT_PARAMS *params = (CK_SSL3_KEY_MAT_PARAMS *)mech->pParameter;

         // Check FCV
         //
//         if (((nv_FCV.FunctionCntlBytes[DES_FUNCTION_BYTE] & FCV_56_BIT_DES) == 0) && (params->bIsExport == FALSE))
//            return CKR_MECHANISM_INVALID;

         return ssl3_key_and_mac_derive( sess, mech, base_key,
                                         pTemplate, ulCount );
      }
      break ;

/* Begin code contributed by Corrent corp. */
#ifndef NODH
      case CKM_DH_PKCS_DERIVE:
      {
         if (!derived_key){
            OCK_LOG_ERR(ERR_FUNCTION_FAILED);
            return CKR_FUNCTION_FAILED;
         }
         return dh_pkcs_derive( sess, mech, base_key,
                                pTemplate, ulCount, derived_key );
      }
      break ;
#endif
/* End code contributed by Corrent corp. */
      
      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         return CKR_MECHANISM_INVALID;
   }
}

