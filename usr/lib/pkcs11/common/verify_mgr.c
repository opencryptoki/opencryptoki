/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  verify_mgr.c
//
// Verify manager routines
//

#include <pthread.h>
#include <string.h>            // for memcmp() et al
#include <stdlib.h>


#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"


//
//
CK_RV
verify_mgr_init( SESSION             * sess,
                 SIGN_VERIFY_CONTEXT * ctx,
                 CK_MECHANISM        * mech,
                 CK_BBOOL              recover_mode,
                 CK_OBJECT_HANDLE      key )
{
   OBJECT          * key_obj = NULL;
   CK_ATTRIBUTE    * attr    = NULL;
   CK_BYTE         * ptr     = NULL;
   CK_KEY_TYPE       keytype;
   CK_OBJECT_CLASS   class;
   CK_BBOOL          flag;
   CK_RV             rc;


   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active != FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
      return CKR_OPERATION_ACTIVE;
   }

   // key usage restrictions
   //
   rc = object_mgr_find_in_map1( key, &key_obj );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to acquire key from specified handle.\n");
      if (rc == CKR_OBJECT_HANDLE_INVALID)
         return CKR_KEY_HANDLE_INVALID;
      else
         return rc;
   }
   // is key allowed to verify signatures?
   //
   rc = template_attribute_find( key_obj->template, CKA_VERIFY, &attr );
   if (rc == FALSE){
      TRACE_ERROR("Could not find CKA_VERIFY for the key.\n");
      return CKR_KEY_FUNCTION_NOT_PERMITTED;
   }
   else {
      flag = *(CK_BBOOL *)attr->pValue;
      if (flag != TRUE){
         TRACE_ERROR("%s\n", ock_err(ERR_KEY_FUNCTION_NOT_PERMITTED));
         return CKR_KEY_FUNCTION_NOT_PERMITTED;
      }
   }


   // is the mechanism supported?  is the key type correct?  is a
   // parameter present if required?  is the key size allowed?
   // is the key allowed to generate signatures?
   //
   switch (mech->mechanism) {
      case CKM_RSA_X_509:
      case CKM_RSA_PKCS:
      case CKM_RSA_PKCS_PSS:
         {
	    if (mech->mechanism == CKM_RSA_PKCS_PSS) {
		rc = template_attribute_find(key_obj->template, CKA_MODULUS,
					     &attr);
		if (rc == FALSE) {
		   TRACE_ERROR("Could not find CKA_VERIFY for the key.\n");
		   return CKR_FUNCTION_FAILED;
		}

		rc = check_pss_params(mech, attr->ulValueLen);
		if (rc != CKR_OK) {
		    TRACE_DEVEL("check_pss_params failed.\n");
		    return rc;
		}
            } else {
                if (mech->ulParameterLen != 0) {
                    TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                    return CKR_MECHANISM_PARAM_INVALID;
                }
            }

            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_RSA){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // must be a PUBLIC key operation
            //
            flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
            if (flag == FALSE){
	       TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else
               class = *(CK_OBJECT_CLASS *)attr->pValue;

            if (class != CKO_PUBLIC_KEY){
		TRACE_ERROR("This operation requires a private key.\n");
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
            // PKCS #11 doesn't allow multi-part RSA operations
            //
            ctx->context_len = 0;
            ctx->context     = NULL;
         }
         break;

      case CKM_ECDSA:
      case CKM_ECDSA_SHA1:
      case CKM_ECDSA_SHA256:
      case CKM_ECDSA_SHA384:
      case CKM_ECDSA_SHA512:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
	       TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_EC){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // must be a PUBLIC key operation
            //
            flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
            if (flag == FALSE){
	       TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else
               class = *(CK_OBJECT_CLASS *)attr->pValue;

            if (class != CKO_PUBLIC_KEY){
	       TRACE_ERROR("This operation requires a public key.\n");
	       return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }

	    if (mech->mechanism == CKM_ECDSA) {
	       ctx->context_len = 0;
	       ctx->context     = NULL;
	    } else {
               ctx->context_len = sizeof(RSA_DIGEST_CONTEXT);
	       ctx->context     = (CK_BYTE *)malloc(sizeof(RSA_DIGEST_CONTEXT));
	       if (!ctx->context){
                  TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		  return CKR_HOST_MEMORY;
	       }
	       memset( ctx->context, 0x0, sizeof(RSA_DIGEST_CONTEXT));
	    }
         }
         break;

      case CKM_MD2_RSA_PKCS:
      case CKM_MD5_RSA_PKCS:
      case CKM_SHA1_RSA_PKCS:
      case CKM_SHA256_RSA_PKCS:
      case CKM_SHA384_RSA_PKCS:
      case CKM_SHA512_RSA_PKCS:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
	       TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_RSA){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // must be a PUBLIC key operation
            //
            flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
            if (flag == FALSE){
	       TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else
               class = *(CK_OBJECT_CLASS *)attr->pValue;

            if (class != CKO_PUBLIC_KEY){
	       TRACE_ERROR("This operation requires a public key.\n");
	       return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
            ctx->context_len = sizeof(RSA_DIGEST_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(RSA_DIGEST_CONTEXT));
            if (!ctx->context){
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(RSA_DIGEST_CONTEXT));
         }
         break;

      case CKM_SHA1_RSA_PKCS_PSS:
      case CKM_SHA256_RSA_PKCS_PSS:
      case CKM_SHA384_RSA_PKCS_PSS:
      case CKM_SHA512_RSA_PKCS_PSS:
         {
	    rc = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
	    if (rc == FALSE) {
	       TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
               return CKR_FUNCTION_FAILED;
	    }

	    rc = check_pss_params(mech, attr->ulValueLen);
	    if (rc != CKR_OK) {
		TRACE_DEVEL("check_pss_params failed.\n");
		return rc;
	    }

            rc = template_attribute_find(key_obj->template, CKA_KEY_TYPE,
					 &attr);
            if (rc == FALSE) {
	       TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
               return CKR_FUNCTION_FAILED;
            } else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_RSA) {
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // must be a PUBLIC key operation
            //
            flag = template_attribute_find(key_obj->template, CKA_CLASS, &attr);
            if (flag == FALSE) {
	       TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
               return CKR_FUNCTION_FAILED;
            } else
               class = *(CK_OBJECT_CLASS *)attr->pValue;

            if (class != CKO_PUBLIC_KEY) {
	       TRACE_ERROR("This operation requires a public key.\n");
	       return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
            ctx->context_len = sizeof(DIGEST_CONTEXT);
            ctx->context = (CK_BYTE *)malloc(ctx->context_len);
            if (!ctx->context) {
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset(ctx->context, 0x0, ctx->context_len);
         }
         break;

#if !(NODSA)
      case CKM_DSA:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
	       TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_DSA){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // must be a PUBLIC key operation
            //
            flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
            if (flag == FALSE){
	       TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else
               class = *(CK_OBJECT_CLASS *)attr->pValue;

            if (class != CKO_PUBLIC_KEY){
	       TRACE_ERROR("This operation requires a public key.\n");
	       return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
            // PKCS #11 doesn't allow multi-part DSA operations
            //
            ctx->context_len = 0;
            ctx->context     = NULL;
         }
         break;
#endif

      case CKM_MD2_HMAC:
      case CKM_MD5_HMAC:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
	       TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_GENERIC_SECRET){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // PKCS #11 doesn't allow multi-part HMAC operations
            //
            ctx->context_len = 0;
            ctx->context     = NULL;
	 }
	 break;

      case CKM_SHA_1_HMAC:
      case CKM_SHA256_HMAC:
      case CKM_SHA384_HMAC:
      case CKM_SHA512_HMAC:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
	       TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_GENERIC_SECRET){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            /* Note: It was previously believed that pkcs#11 did not
	     * support hmac multipart. As a result, those tokens using the
	     * locally implemented hmac helper functions do not support
	     * multipart hmac.
	     */
            ctx->context_len = 0;
            ctx->context     = NULL;

            rc = hmac_verify_init(sess, mech, key);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to initialize hmac.\n");
                return rc;
            }
         }
         break;

      case CKM_MD2_HMAC_GENERAL:
      case CKM_MD5_HMAC_GENERAL:
         {
            CK_MAC_GENERAL_PARAMS *param = (CK_MAC_GENERAL_PARAMS *)mech->pParameter;

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            if ((mech->mechanism == CKM_MD2_HMAC_GENERAL) && (*param > 16)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            if ((mech->mechanism == CKM_MD5_HMAC_GENERAL) && (*param > 16)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }

            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
	       TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_GENERIC_SECRET){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // PKCS #11 doesn't allow multi-part HMAC operations
            //
            ctx->context_len = 0;
            ctx->context     = NULL;
	 }
	 break;

      case CKM_SHA_1_HMAC_GENERAL:
      case CKM_SHA256_HMAC_GENERAL:
      case CKM_SHA384_HMAC_GENERAL:
      case CKM_SHA512_HMAC_GENERAL:
         {
            CK_MAC_GENERAL_PARAMS *param = (CK_MAC_GENERAL_PARAMS *)mech->pParameter;

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            if ((mech->mechanism == CKM_MD2_HMAC_GENERAL) && (*param > 16)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            if ((mech->mechanism == CKM_MD5_HMAC_GENERAL) && (*param > 16)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            if ((mech->mechanism == CKM_SHA_1_HMAC_GENERAL) && (*param > 20)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            if ((mech->mechanism == CKM_SHA256_HMAC_GENERAL) && (*param > 32)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            if ((mech->mechanism == CKM_SHA384_HMAC_GENERAL) && (*param > 48)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            if ((mech->mechanism == CKM_SHA512_HMAC_GENERAL) && (*param > 64)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
	       TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_GENERIC_SECRET){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            /* Note: It was previously believed that pkcs#11 did not
	     * support hmac multipart. As a result, those tokens using the
	     * locally implemented hmac helper functions do not support
	     * multipart hmac.
	     */
            ctx->context_len = 0;
            ctx->context     = NULL;

            rc = hmac_verify_init(sess, mech, key);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to initialize hmac.\n");
                return rc;
            }
         }
         break;

      case CKM_SSL3_MD5_MAC:
      case CKM_SSL3_SHA1_MAC:
         {
            CK_MAC_GENERAL_PARAMS *param = (CK_MAC_GENERAL_PARAMS *)mech->pParameter;

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // Netscape sets the parameter == 16.  PKCS #11 limit is 8
            //
            if (mech->mechanism == CKM_SSL3_MD5_MAC) {
               if (*param < 4 || *param > 16){
                  TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                  return CKR_MECHANISM_PARAM_INVALID;
               }
            }

            if (mech->mechanism == CKM_SSL3_SHA1_MAC) {
               if (*param < 4 || *param > 20){
                  TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                  return CKR_MECHANISM_PARAM_INVALID;
               }
            }

            rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
            if (rc == FALSE){
	       TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
               return CKR_FUNCTION_FAILED;
            }
            else {
               class = *(CK_OBJECT_CLASS *)attr->pValue;
               if (class != CKO_SECRET_KEY){
	          TRACE_ERROR("This operation requires a secret key.\n");
	          return CKR_KEY_FUNCTION_NOT_PERMITTED;
               }
            }

            ctx->context_len = sizeof(SSL3_MAC_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(SSL3_MAC_CONTEXT));
            if (!ctx->context){
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(SSL3_MAC_CONTEXT));
         }
         break;

      case CKM_DES3_MAC:
      case CKM_DES3_MAC_GENERAL:
         {
          if (mech->pParameter) {
             if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)){
                 TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                 return CKR_MECHANISM_PARAM_INVALID;
             }

             CK_MAC_GENERAL_PARAMS *param = (CK_MAC_GENERAL_PARAMS *)mech->pParameter;
             if (mech->mechanism == CKM_DES3_MAC_GENERAL) {
                if (*param < 1 || *param > DES_BLOCK_SIZE){
                   TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                   return CKR_MECHANISM_PARAM_INVALID;
                }
             }
               /* CKM_DES_MAC or CKM_DES3_MAC should not have params */
                else return CKR_MECHANISM_PARAM_INVALID;
          }

          ctx->context     = (CK_BYTE *)malloc(sizeof(DES_DATA_CONTEXT));
          ctx->context_len = sizeof(DES_DATA_CONTEXT);

          if (!ctx->context){
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
          }
          memset( ctx->context, 0x0, sizeof(DES_DATA_CONTEXT));
         }
         break;

      case CKM_AES_MAC:
      case CKM_AES_MAC_GENERAL:
         {
          if (mech->pParameter) {
             if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)){
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                return CKR_MECHANISM_PARAM_INVALID;
             }

             CK_MAC_GENERAL_PARAMS *param = (CK_MAC_GENERAL_PARAMS *)mech->pParameter;

             if (mech->mechanism == CKM_AES_MAC_GENERAL) {
                if (*param < 1 || *param > AES_BLOCK_SIZE){
                   TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                   return CKR_MECHANISM_PARAM_INVALID;
                }
             }
                /* CKM_AES_MAC should not have params */
                else return CKR_MECHANISM_PARAM_INVALID;
          }

          ctx->context     = (CK_BYTE *)malloc(sizeof(AES_DATA_CONTEXT));
          ctx->context_len = sizeof(AES_DATA_CONTEXT);

          if (!ctx->context){
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
          }
          memset( ctx->context, 0x0, sizeof(AES_DATA_CONTEXT));
         }
         break;

      default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
         return CKR_MECHANISM_INVALID;
   }


   if (mech->ulParameterLen > 0) {
      ptr = (CK_BYTE *)malloc(mech->ulParameterLen);
      if (!ptr){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      memcpy( ptr, mech->pParameter, mech->ulParameterLen );
   }

   ctx->key                 = key;
   ctx->mech.ulParameterLen = mech->ulParameterLen;
   ctx->mech.mechanism      = mech->mechanism;
   ctx->mech.pParameter     = ptr;
   ctx->multi               = FALSE;
   ctx->active              = TRUE;
   ctx->recover             = recover_mode;

   return CKR_OK;
}


//
//
CK_RV
verify_mgr_cleanup( SIGN_VERIFY_CONTEXT *ctx )
{
   if (!ctx){
      TRACE_ERROR("Invalid function argument.\n");
      return CKR_FUNCTION_FAILED;
   }
   ctx->key                 = 0;
   ctx->mech.ulParameterLen = 0;
   ctx->mech.mechanism      = 0;
   ctx->multi               = FALSE;
   ctx->active              = FALSE;
   ctx->recover             = FALSE;
   ctx->context_len         = 0;

   if (ctx->mech.pParameter) {
      free( ctx->mech.pParameter );
      ctx->mech.pParameter = NULL;
   }

   if (ctx->context) {
      free( ctx->context );
      ctx->context = NULL;
   }

   return CKR_OK;
}


//
//
CK_RV
verify_mgr_verify( SESSION             * sess,
                   SIGN_VERIFY_CONTEXT * ctx,
                   CK_BYTE             * in_data,
                   CK_ULONG              in_data_len,
                   CK_BYTE             * signature,
                   CK_ULONG              sig_len )
{
   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   if (ctx->recover == TRUE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   // if the caller just wants the signature length, there is no reason to
   // specify the input data.  I just need the input data length
   //
   if (!in_data || !signature){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->multi == TRUE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
      return CKR_OPERATION_ACTIVE;
   }

   switch (ctx->mech.mechanism) {
      case CKM_RSA_PKCS:
         return rsa_pkcs_verify( sess,      ctx,
                                 in_data,   in_data_len,
                                 signature, sig_len );

      case CKM_RSA_X_509:
         return rsa_x509_verify( sess,      ctx,
                                 in_data,   in_data_len,
                                 signature, sig_len );

      case CKM_RSA_PKCS_PSS:
	 return rsa_pss_verify(sess, ctx, in_data, in_data_len,
			       signature, sig_len);

      case CKM_MD2_RSA_PKCS:
      case CKM_MD5_RSA_PKCS:
      case CKM_SHA1_RSA_PKCS:
      case CKM_SHA256_RSA_PKCS:
      case CKM_SHA384_RSA_PKCS:
      case CKM_SHA512_RSA_PKCS:
         return rsa_hash_pkcs_verify( sess,      ctx,
                                      in_data,   in_data_len,
                                      signature, sig_len );

      case CKM_SHA1_RSA_PKCS_PSS:
      case CKM_SHA256_RSA_PKCS_PSS:
      case CKM_SHA384_RSA_PKCS_PSS:
      case CKM_SHA512_RSA_PKCS_PSS:
	 return rsa_hash_pss_verify(sess, ctx, in_data, in_data_len, signature,
				    sig_len);

#if !(NODSA)
      case CKM_DSA:
         return dsa_verify( sess,      ctx,
                            in_data,   in_data_len,
                            signature, sig_len );
#endif

#if !(NOMD2)
      case CKM_MD2_HMAC:
      case CKM_MD2_HMAC_GENERAL:
         return md2_hmac_verify( sess,      ctx,
                                 in_data,   in_data_len,
                                 signature, sig_len );
#endif

      case CKM_MD5_HMAC:
      case CKM_MD5_HMAC_GENERAL:
         return md5_hmac_verify( sess,      ctx,
                                 in_data,   in_data_len,
                                 signature, sig_len );

      case CKM_SHA_1_HMAC:
      case CKM_SHA_1_HMAC_GENERAL:
         return sha1_hmac_verify( sess,      ctx,
                                  in_data,   in_data_len,
                                  signature, sig_len );

      case CKM_SHA256_HMAC:
      case CKM_SHA256_HMAC_GENERAL:
         return sha2_hmac_verify( sess,      ctx,
                                  in_data,   in_data_len,
                                  signature, sig_len );

      case CKM_SHA384_HMAC:
      case CKM_SHA384_HMAC_GENERAL:
         return sha3_hmac_verify( sess,      ctx,
                                  in_data,   in_data_len,
                                  signature, sig_len );

      case CKM_SHA512_HMAC:
      case CKM_SHA512_HMAC_GENERAL:
         return sha5_hmac_verify( sess,      ctx,
                                  in_data,   in_data_len,
                                  signature, sig_len );

      case CKM_SSL3_MD5_MAC:
      case CKM_SSL3_SHA1_MAC:
         return ssl3_mac_verify( sess,      ctx,
                                 in_data,   in_data_len,
                                 signature, sig_len );

      case CKM_DES3_MAC:
      case CKM_DES3_MAC_GENERAL:
         return des3_mac_verify( sess, ctx,
                         in_data, in_data_len, signature, sig_len);

      case CKM_AES_MAC:
      case CKM_AES_MAC_GENERAL:
         return aes_mac_verify( sess, ctx,
                         in_data, in_data_len, signature, sig_len);

      case CKM_ECDSA_SHA1:
      case CKM_ECDSA_SHA256:
      case CKM_ECDSA_SHA384:
      case CKM_ECDSA_SHA512:
         return ec_hash_verify( sess,	ctx,
                                 in_data,   in_data_len,
                                 signature, sig_len );
      case CKM_ECDSA:
         return ec_verify( sess,	ctx,
                                 in_data,   in_data_len,
                                 signature, sig_len );
      default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
         return CKR_MECHANISM_INVALID;
   }

   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
verify_mgr_verify_update( SESSION             * sess,
                          SIGN_VERIFY_CONTEXT * ctx,
                          CK_BYTE             * in_data,
                          CK_ULONG              in_data_len )
{
   if (!sess || !ctx) {
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   if (ctx->recover == TRUE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   ctx->multi = TRUE;


   switch (ctx->mech.mechanism) {
      case CKM_MD2_RSA_PKCS:
      case CKM_MD5_RSA_PKCS:
      case CKM_SHA1_RSA_PKCS:
      case CKM_SHA256_RSA_PKCS:
      case CKM_SHA384_RSA_PKCS:
      case CKM_SHA512_RSA_PKCS:
         return rsa_hash_pkcs_verify_update( sess, ctx, in_data, in_data_len );

      case CKM_SHA1_RSA_PKCS_PSS:
      case CKM_SHA256_RSA_PKCS_PSS:
      case CKM_SHA384_RSA_PKCS_PSS:
      case CKM_SHA512_RSA_PKCS_PSS:
	 return rsa_hash_pss_update(sess, ctx, in_data, in_data_len);

      case CKM_SSL3_MD5_MAC:
      case CKM_SSL3_SHA1_MAC:
         return ssl3_mac_verify_update( sess, ctx, in_data, in_data_len );

      case CKM_DES3_MAC:
      case CKM_DES3_MAC_GENERAL:
          return des3_mac_verify_update( sess, ctx, in_data, in_data_len );

      case CKM_AES_MAC:
      case CKM_AES_MAC_GENERAL:
          return aes_mac_verify_update( sess, ctx, in_data, in_data_len );

      case CKM_ECDSA_SHA1:
      case CKM_ECDSA_SHA256:
      case CKM_ECDSA_SHA384:
      case CKM_ECDSA_SHA512:
	 return ec_hash_verify_update( sess, ctx, in_data, in_data_len );

      case CKM_SHA_1_HMAC:
      case CKM_SHA256_HMAC:
      case CKM_SHA384_HMAC:
      case CKM_SHA512_HMAC:
      case CKM_SHA_1_HMAC_GENERAL:
      case CKM_SHA256_HMAC_GENERAL:
      case CKM_SHA384_HMAC_GENERAL:
      case CKM_SHA512_HMAC_GENERAL:
        return hmac_verify_update(sess, in_data, in_data_len);

      default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
         return CKR_MECHANISM_INVALID;
   }
   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
verify_mgr_verify_final( SESSION             * sess,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * signature,
                         CK_ULONG              sig_len )
{
   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   if (ctx->recover == TRUE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   switch (ctx->mech.mechanism) {
      case CKM_MD2_RSA_PKCS:
      case CKM_MD5_RSA_PKCS:
      case CKM_SHA1_RSA_PKCS:
      case CKM_SHA256_RSA_PKCS:
      case CKM_SHA384_RSA_PKCS:
      case CKM_SHA512_RSA_PKCS:
         return rsa_hash_pkcs_verify_final( sess, ctx, signature, sig_len );

      case CKM_SHA1_RSA_PKCS_PSS:
      case CKM_SHA256_RSA_PKCS_PSS:
      case CKM_SHA384_RSA_PKCS_PSS:
      case CKM_SHA512_RSA_PKCS_PSS:
	 return rsa_hash_pss_verify_final(sess, ctx, signature, sig_len);

      case CKM_SSL3_MD5_MAC:
      case CKM_SSL3_SHA1_MAC:
         return ssl3_mac_verify_final( sess, ctx, signature, sig_len );

      case CKM_DES3_MAC:
      case CKM_DES3_MAC_GENERAL:
         return des3_mac_verify_final( sess, ctx, signature, sig_len );

      case CKM_AES_MAC:
      case CKM_AES_MAC_GENERAL:
         return aes_mac_verify_final( sess, ctx, signature, sig_len );

      case CKM_ECDSA_SHA1:
      case CKM_ECDSA_SHA256:
      case CKM_ECDSA_SHA384:
      case CKM_ECDSA_SHA512:
	 return ec_hash_verify_final( sess, ctx, signature, sig_len );

      case CKM_SHA_1_HMAC:
      case CKM_SHA256_HMAC:
      case CKM_SHA384_HMAC:
      case CKM_SHA512_HMAC:
      case CKM_SHA_1_HMAC_GENERAL:
      case CKM_SHA256_HMAC_GENERAL:
      case CKM_SHA384_HMAC_GENERAL:
      case CKM_SHA512_HMAC_GENERAL:
        return hmac_verify_final(sess, signature, sig_len);

      default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
         return CKR_MECHANISM_INVALID;
   }

   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
verify_mgr_verify_recover( SESSION             * sess,
                           CK_BBOOL              length_only,
                           SIGN_VERIFY_CONTEXT * ctx,
                           CK_BYTE             * signature,
                           CK_ULONG              sig_len,
                           CK_BYTE             * out_data,
                           CK_ULONG            * out_len )
{
   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   if (ctx->recover == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   // if the caller just wants the signature length, there is no reason to
   // specify the input data.  I just need the input data length
   //
   if (!signature || !out_len){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->multi == TRUE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
      return CKR_OPERATION_ACTIVE;
   }

   switch (ctx->mech.mechanism) {
      case CKM_RSA_PKCS:
         return rsa_pkcs_verify_recover( sess,      length_only,
                                         ctx,
                                         signature, sig_len,
                                         out_data,  out_len );
      case CKM_RSA_X_509:
         return rsa_x509_verify_recover( sess,      length_only,
                                         ctx,
                                         signature, sig_len,
                                         out_data,  out_len );

      default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
         return CKR_MECHANISM_INVALID;
   }

   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}
