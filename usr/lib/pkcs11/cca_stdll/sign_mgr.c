/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki CCA token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
 *
 */


// File:  sign_mgr.c
//
// Signature manager routines
//

#include <pthread.h>

#include <string.h>            // for memcmp() et al
#include <stdlib.h>

#include "cca_stdll.h"

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"


//
//
CK_RV
sign_mgr_init( SESSION                * sess,
               SIGN_VERIFY_CONTEXT    * ctx,
               CK_MECHANISM           * mech,
               CK_BBOOL                 recover_mode,
               CK_OBJECT_HANDLE         key )
{
   OBJECT          * key_obj = NULL;
   CK_ATTRIBUTE    * attr    = NULL;
   CK_BYTE         * ptr     = NULL;
   CK_KEY_TYPE       keytype;
   CK_OBJECT_CLASS   class;
   CK_BBOOL          flag;
   CK_RV             rc;


   if (!sess || !ctx){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active != FALSE){
      OCK_LOG_ERR(ERR_OPERATION_ACTIVE);
      return CKR_OPERATION_ACTIVE;
   }

   // key usage restrictions
   //
   rc = object_mgr_find_in_map1( key, &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_KEY_HANDLE_INVALID);
      return CKR_KEY_HANDLE_INVALID;
   }
   // is key allowed to generate signatures?
   //
   rc = template_attribute_find( key_obj->template, CKA_SIGN, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
      return CKR_KEY_TYPE_INCONSISTENT;
   }
   else {
      flag = *(CK_BBOOL *)attr->pValue;
      if (flag != TRUE){
         OCK_LOG_ERR(ERR_KEY_FUNCTION_NOT_PERMITTED);
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
         {
            if (mech->ulParameterLen != 0){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_RSA){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // must be a PRIVATE key
            //
            flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
            if (flag == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
               class = *(CK_OBJECT_CLASS *)attr->pValue;

            // if it's not a private RSA key then we have an internal failure...means
            // that somehow a public key got assigned a CKA_SIGN attribute
            //
            if (class != CKO_PRIVATE_KEY){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            // PKCS #11 doesn't allow multi-part RSA operations
            //
            ctx->context_len = 0;
            ctx->context     = NULL;
         }
         break;

      case CKM_ECDSA:
      case CKM_ECDSA_SHA1:
         {
            if (mech->ulParameterLen != 0){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_EC){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // must be a PRIVATE key
            //
            flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
            if (flag == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
               class = *(CK_OBJECT_CLASS *)attr->pValue;

            if (class != CKO_PRIVATE_KEY){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }

	    if (mech->mechanism == CKM_ECDSA) {
		    ctx->context_len = 0;
		    ctx->context     = NULL;
	    } else {
		    ctx->context_len = sizeof(RSA_DIGEST_CONTEXT);
		    ctx->context     = (CK_BYTE *)malloc(sizeof(RSA_DIGEST_CONTEXT));
		    if (!ctx->context){
			    OCK_LOG_ERR(ERR_HOST_MEMORY);
			    return CKR_HOST_MEMORY;
		    }
		    memset( ctx->context, 0x0, sizeof(RSA_DIGEST_CONTEXT));
	    }
         }
         break;

#if  !(NOMD2)
      case CKM_MD2_RSA_PKCS:
#endif
      case CKM_MD5_RSA_PKCS:
      case CKM_SHA1_RSA_PKCS:
      case CKM_SHA256_RSA_PKCS:
         {
            if (mech->ulParameterLen != 0){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_RSA){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // must be a PRIVATE key operation
            //
            flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
            if (flag == FALSE){
               OCK_LOG_ERR(ERR_FUNCTION_FAILED);
               return CKR_FUNCTION_FAILED;
            }
            else
               class = *(CK_OBJECT_CLASS *)attr->pValue;

            if (class != CKO_PRIVATE_KEY){
               OCK_LOG_ERR(ERR_FUNCTION_FAILED);
               return CKR_FUNCTION_FAILED;
            }
            ctx->context_len = sizeof(RSA_DIGEST_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(RSA_DIGEST_CONTEXT));
            if (!ctx->context){
               OCK_LOG_ERR(ERR_HOST_MEMORY);
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(RSA_DIGEST_CONTEXT));
         }
         break;


#if !(NODSA)
      case CKM_DSA:
         {
            if (mech->ulParameterLen != 0){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_DSA){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // must be a PRIVATE key
            //
            flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
            if (flag == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
               class = *(CK_OBJECT_CLASS *)attr->pValue;

            // if it's not a private RSA key then we have an internal failure...means
            // that somehow a public key got assigned a CKA_SIGN attribute
            //
            if (class != CKO_PRIVATE_KEY){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            // PKCS #11 doesn't allow multi-part DSA operations
            //
            ctx->context_len = 0;
            ctx->context     = NULL;
         }
         break;
#endif

#if  !(NOMD2)
      case CKM_MD2_HMAC:
#endif
      case CKM_MD5_HMAC:
      case CKM_SHA_1_HMAC:
      case CKM_SHA256_HMAC:
         {
            if (mech->ulParameterLen != 0){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_GENERIC_SECRET){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // PKCS #11 doesn't allow multi-part HMAC operations
            //
            ctx->context_len = 0;
            ctx->context     = NULL;
         }
         break;

#if  !(NOMD2)
      case CKM_MD2_HMAC_GENERAL:
#endif
      case CKM_MD5_HMAC_GENERAL:
      case CKM_SHA_1_HMAC_GENERAL:
      case CKM_SHA256_HMAC_GENERAL:
         {
            CK_MAC_GENERAL_PARAMS *param = (CK_MAC_GENERAL_PARAMS *)mech->pParameter;

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }

#if  !(NOMD2)
            if ((mech->mechanism == CKM_MD2_HMAC_GENERAL) && (*param > 16)){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
#endif

            if ((mech->mechanism == CKM_MD5_HMAC_GENERAL) && (*param > 16)){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            if ((mech->mechanism == CKM_SHA_1_HMAC_GENERAL) && (*param > 20)){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            if ((mech->mechanism == CKM_SHA256_HMAC_GENERAL) && (*param > 32)){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_GENERIC_SECRET){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // PKCS #11 doesn't allow multi-part HMAC operations
            //
            ctx->context_len = 0;
            ctx->context     = NULL;
         }
         break;

      case CKM_SSL3_MD5_MAC:
      case CKM_SSL3_SHA1_MAC:
         {
            CK_MAC_GENERAL_PARAMS *param = (CK_MAC_GENERAL_PARAMS *)mech->pParameter;

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // FIXME - Netscape sets the parameter == 16.  PKCS #11 limit is 8
            //
            if (mech->mechanism == CKM_SSL3_MD5_MAC) {
               if (*param < 4 || *param > 16){
                  OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
                  return CKR_MECHANISM_PARAM_INVALID;
               }
            }

            if (mech->mechanism == CKM_SSL3_SHA1_MAC) {
               if (*param < 4 || *param > 20){
                  OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
                  return CKR_MECHANISM_PARAM_INVALID;
               }
            }

            rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else {
               class = *(CK_OBJECT_CLASS *)attr->pValue;
               if (class != CKO_SECRET_KEY){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            ctx->context_len = sizeof(SSL3_MAC_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(SSL3_MAC_CONTEXT));
            if (!ctx->context){
               OCK_LOG_ERR(ERR_HOST_MEMORY);
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(SSL3_MAC_CONTEXT));
         }
         break;

      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         return CKR_MECHANISM_INVALID;
   }


   if (mech->ulParameterLen > 0) {
      ptr = (CK_BYTE *)malloc(mech->ulParameterLen);
      if (!ptr){
         OCK_LOG_ERR(ERR_HOST_MEMORY);
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
sign_mgr_cleanup( SIGN_VERIFY_CONTEXT *ctx )
{
   if (!ctx){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
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
sign_mgr_sign( SESSION              * sess,
               CK_BBOOL               length_only,
               SIGN_VERIFY_CONTEXT  * ctx,
               CK_BYTE              * in_data,
               CK_ULONG               in_data_len,
               CK_BYTE              * out_data,
               CK_ULONG             * out_data_len )
{
   if (!sess || !ctx){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   if (ctx->recover == TRUE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   // if the caller just wants the signature length, there is no reason to
   // specify the input data.  I just need the input data length
   //
   if ((length_only == FALSE) && (!in_data || !out_data)){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->multi == TRUE){
      OCK_LOG_ERR(ERR_OPERATION_ACTIVE);
      return CKR_OPERATION_ACTIVE;
   }
   switch (ctx->mech.mechanism) {
      case CKM_RSA_PKCS:
         return rsa_pkcs_sign( sess,     length_only,  ctx,
                               in_data,  in_data_len,
                               out_data, out_data_len );
#if 0
      case CKM_RSA_X_509:
         return rsa_x509_sign( sess,     length_only,  ctx,
                               in_data,  in_data_len,
                               out_data, out_data_len );
#endif
#if !(NOMD2)
      case CKM_MD2_RSA_PKCS:
#endif
      case CKM_MD5_RSA_PKCS:
      case CKM_SHA1_RSA_PKCS:
      case CKM_SHA256_RSA_PKCS:
         return rsa_hash_pkcs_sign( sess,     length_only, ctx,
                                    in_data,  in_data_len,
                                    out_data, out_data_len );

#if !(NODSA)
      case CKM_DSA:
         return dsa_sign( sess,     length_only,  ctx,
                          in_data,  in_data_len,
                          out_data, out_data_len );
#endif

#if !(NOMD2)
      case CKM_MD2_HMAC:
      case CKM_MD2_HMAC_GENERAL:
         return md2_hmac_sign( sess,     length_only, ctx,
                               in_data,  in_data_len,
                               out_data, out_data_len );
#endif

      case CKM_MD5_HMAC:
      case CKM_MD5_HMAC_GENERAL:
         return md5_hmac_sign( sess,     length_only, ctx,
                               in_data,  in_data_len,
                               out_data, out_data_len );

      case CKM_SHA_1_HMAC:
      case CKM_SHA_1_HMAC_GENERAL:
         return sha1_hmac_sign( sess,     length_only, ctx,
                               in_data,  in_data_len,
                               out_data, out_data_len );

      case CKM_SHA256_HMAC:
      case CKM_SHA256_HMAC_GENERAL:
         return sha2_hmac_sign( sess,     length_only, ctx,
                               in_data,  in_data_len,
                               out_data, out_data_len );

      case CKM_SSL3_MD5_MAC:
      case CKM_SSL3_SHA1_MAC:
         return ssl3_mac_sign( sess,     length_only, ctx,
                               in_data,  in_data_len,
			       out_data, out_data_len );
      case CKM_ECDSA_SHA1:
         return ec_hash_sign( sess, length_only, ctx,
                               in_data,  in_data_len,
                               out_data, out_data_len );

      case CKM_ECDSA:
         return ec_sign( sess, length_only, ctx,
                               in_data,  in_data_len,
                               out_data, out_data_len );

      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         return CKR_MECHANISM_INVALID;
   }

   OCK_LOG_ERR(ERR_FUNCTION_FAILED);
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
sign_mgr_sign_update( SESSION             * sess,
                      SIGN_VERIFY_CONTEXT * ctx,
                      CK_BYTE             * in_data,
                      CK_ULONG              in_data_len )
{
   if (!sess || !ctx || !in_data){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->active == FALSE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   if (ctx->recover == TRUE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   ctx->multi = TRUE;

   switch (ctx->mech.mechanism) {
#if !(NOMD2)
      case CKM_MD2_RSA_PKCS:
#endif
      case CKM_MD5_RSA_PKCS:
      case CKM_SHA1_RSA_PKCS:
      case CKM_SHA256_RSA_PKCS:
         return rsa_hash_pkcs_sign_update( sess, ctx, in_data, in_data_len );

      case CKM_SSL3_MD5_MAC:
      case CKM_SSL3_SHA1_MAC:
         return ssl3_mac_sign_update( sess, ctx, in_data, in_data_len );

      case CKM_ECDSA_SHA1:
	 return ec_hash_sign_update( sess, ctx, in_data, in_data_len );

      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         return CKR_MECHANISM_INVALID;
   }
   OCK_LOG_ERR(ERR_MECHANISM_INVALID);
   return CKR_MECHANISM_INVALID;
}


//
//
CK_RV
sign_mgr_sign_final( SESSION             * sess,
                     CK_BBOOL              length_only,
                     SIGN_VERIFY_CONTEXT * ctx,
                     CK_BYTE             * signature,
                     CK_ULONG            * sig_len )
{
   if (!sess || !ctx){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   if (ctx->recover == TRUE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   switch (ctx->mech.mechanism) {
#if !(NOMD2)
      case CKM_MD2_RSA_PKCS:
#endif
      case CKM_MD5_RSA_PKCS:
      case CKM_SHA1_RSA_PKCS:
      case CKM_SHA256_RSA_PKCS:
         return rsa_hash_pkcs_sign_final( sess, length_only, ctx, signature, sig_len );

      case CKM_SSL3_MD5_MAC:
      case CKM_SSL3_SHA1_MAC:
         return ssl3_mac_sign_final( sess, length_only, ctx, signature, sig_len );

      case CKM_ECDSA_SHA1:
	 return ec_hash_sign_final (sess, length_only, ctx, signature, sig_len );

      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         return CKR_MECHANISM_INVALID;
   }

   OCK_LOG_ERR(ERR_MECHANISM_INVALID);
   return CKR_MECHANISM_INVALID;
}


//
//
CK_RV
sign_mgr_sign_recover( SESSION             * sess,
                       CK_BBOOL              length_only,
                       SIGN_VERIFY_CONTEXT * ctx,
                       CK_BYTE             * in_data,
                       CK_ULONG              in_data_len,
                       CK_BYTE             * out_data,
                       CK_ULONG            * out_data_len )
{
   if (!sess || !ctx){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   if (ctx->recover == FALSE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   // if the caller just wants the signature length, there is no reason to
   // specify the input data.  I just need the input data length
   //
   if ((length_only == FALSE) && (!in_data || !out_data)){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->multi == TRUE){
      OCK_LOG_ERR(ERR_OPERATION_ACTIVE);
      return CKR_OPERATION_ACTIVE;
   }
   switch (ctx->mech.mechanism) {
#if 0
      case CKM_RSA_PKCS:
         // we can use the same sign mechanism to do sign-recover
         //
         return rsa_pkcs_sign( sess,     length_only,  ctx,
                               in_data,  in_data_len,
                               out_data, out_data_len );
      case CKM_RSA_X_509:
         return rsa_x509_sign( sess,     length_only,  ctx,
                               in_data,  in_data_len,
                               out_data, out_data_len );
#endif
      default:
         OCK_LOG_ERR(ERR_MECHANISM_INVALID);
         return CKR_MECHANISM_INVALID;
   }

   OCK_LOG_ERR(ERR_FUNCTION_FAILED);
   return CKR_FUNCTION_FAILED;
}
