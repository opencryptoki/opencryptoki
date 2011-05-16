/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki CCA token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
 *
 */


// File:  encr_mgr.c
//
// Encryption manager routines
//

//#include <windows.h>

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
encr_mgr_init( SESSION           * sess,
               ENCR_DECR_CONTEXT * ctx,
               CK_ULONG            operation,
               CK_MECHANISM      * mech,
               CK_OBJECT_HANDLE    key_handle )
{
   OBJECT        * key_obj = NULL;
   CK_ATTRIBUTE  * attr    = NULL;
   CK_BYTE       * ptr     = NULL;
   CK_KEY_TYPE     keytype;
   CK_BBOOL        flag;
   CK_RV           rc;


   if (!sess || !ctx || !mech){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active != FALSE){
      OCK_LOG_ERR(ERR_OPERATION_ACTIVE);
      return CKR_OPERATION_ACTIVE;
   }

   // key usage restrictions
   //
   if (operation == OP_ENCRYPT_INIT)
   {
      rc = object_mgr_find_in_map1( key_handle, &key_obj );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_KEY_HANDLE_INVALID);
         return CKR_KEY_HANDLE_INVALID;
      }
      // is key allowed to do general encryption?
      //
      rc = template_attribute_find( key_obj->template, CKA_ENCRYPT, &attr );
      if (rc == FALSE){
         OCK_LOG_ERR(ERR_KEY_FUNCTION_NOT_PERMITTED);
         return CKR_KEY_FUNCTION_NOT_PERMITTED;
      }
      else
      {
         flag = *(CK_BBOOL *)attr->pValue;
         if (flag != TRUE){
            OCK_LOG_ERR(ERR_KEY_FUNCTION_NOT_PERMITTED);
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
         }
      }
   }
   else if (operation == OP_WRAP)
   {
      rc = object_mgr_find_in_map1( key_handle, &key_obj );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_WRAPPING_KEY_HANDLE_INVALID);
         return CKR_WRAPPING_KEY_HANDLE_INVALID;
      }
      // is key allowed to wrap other keys?
      //
      rc = template_attribute_find( key_obj->template, CKA_WRAP, &attr );
      if (rc == FALSE){
         OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
         return CKR_KEY_NOT_WRAPPABLE;
      }
      else
      {
         flag = *(CK_BBOOL *)attr->pValue;
         if (flag == FALSE){
            OCK_LOG_ERR(ERR_KEY_NOT_WRAPPABLE);
            return CKR_KEY_NOT_WRAPPABLE;
         }
      }
   }
   else{
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   // is the mechanism supported?  is the key type correct?  is a
   // parameter present if required?  is the key size allowed?
   // does the key support encryption?
   //
   // Will the FCV allow the operation?
   //
   switch (mech->mechanism)
   {
#ifndef NOECB
      case CKM_DES_ECB:
         {
            if (mech->ulParameterLen != 0){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_DES){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // Check FCV
            //
//            if ((nv_FCV.FunctionCntlBytes[DES_FUNCTION_BYTE] & FCV_56_BIT_DES) == 0)
//               return CKR_MECHANISM_INVALID;

            ctx->context_len = sizeof(DES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(DES_CONTEXT));
            if (!ctx->context){
               OCK_LOG_ERR(ERR_HOST_MEMORY);
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;
#ifndef NOCDMF
      case CKM_CDMF_ECB:
         {
            if (mech->ulParameterLen != 0){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_CDMF){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            ctx->context_len = sizeof(DES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(DES_CONTEXT));
            if (!ctx->context){
               OCK_LOG_ERR(ERR_HOST_MEMORY);
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;
#endif
#endif
      case CKM_DES_CBC:
      case CKM_DES_CBC_PAD:
         {
            if (mech->ulParameterLen != DES_BLOCK_SIZE){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_DES){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // Check FCV
            //
//            if ((nv_FCV.FunctionCntlBytes[DES_FUNCTION_BYTE] & FCV_56_BIT_DES) == 0)
//               return CKR_MECHANISM_INVALID;

            ctx->context_len = sizeof(DES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(DES_CONTEXT));
            if (!ctx->context){
               OCK_LOG_ERR(ERR_HOST_MEMORY);
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;
#ifndef NOCDMF
      case CKM_CDMF_CBC:
      case CKM_CDMF_CBC_PAD:
         {
            if (mech->ulParameterLen != DES_BLOCK_SIZE){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_CDMF){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }


            ctx->context_len = sizeof(DES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(DES_CONTEXT));
            if (!ctx->context){
               OCK_LOG_ERR(ERR_HOST_MEMORY);
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;
#endif
#ifndef NOECB
      case CKM_DES3_ECB:
         {
            if (mech->ulParameterLen != 0){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }

            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_DES3 && keytype != CKK_DES2){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // Check FCV
            //
//            if ((nv_FCV.FunctionCntlBytes[DES_FUNCTION_BYTE] & FCV_TRIPLE_DES) == 0)
//               return CKR_MECHANISM_INVALID;

            ctx->context_len = sizeof(DES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(DES_CONTEXT));
            if (!ctx->context){
               OCK_LOG_ERR(ERR_HOST_MEMORY);
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;
#endif
      case CKM_DES3_CBC:
      case CKM_DES3_CBC_PAD:
         {
            if (mech->ulParameterLen != DES_BLOCK_SIZE){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_DES3 && keytype != CKK_DES2){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // Check FCV
            //
//            if ((nv_FCV.FunctionCntlBytes[DES_FUNCTION_BYTE] & FCV_TRIPLE_DES) == 0)
//               return CKR_MECHANISM_INVALID;

            ctx->context_len = sizeof(DES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(DES_CONTEXT));
            if (!ctx->context){
               OCK_LOG_ERR(ERR_HOST_MEMORY);
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;

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
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_RSA){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            // Check FCV
            //
//            rc = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
//            if (rc == FALSE || nv_FCV.SymmetricModLength/8 < attr->value_length)
//               return (operation == OP_DECRYPT_INIT ? CKR_KEY_SIZE_RANGE : CKR_WRAPPING_KEY_SIZE_RANGE );

            // RSA cannot be used for multi-part operations
            //
            ctx->context_len = 0;
            ctx->context     = NULL;
         }
         break;
#ifndef NOAES
      case CKM_AES_ECB:
	 {
	    // XXX Copied in from DES3, should be verified - KEY
		
            if (mech->ulParameterLen != 0){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }

            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_AES){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            ctx->context_len = sizeof(AES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(AES_CONTEXT));
            if (!ctx->context){
               OCK_LOG_ERR(ERR_HOST_MEMORY);
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(AES_CONTEXT) );

	 }
	 break;
      case CKM_AES_CBC:
      case CKM_AES_CBC_PAD:
	 {
	    // XXX Copied in from DES3, should be verified - KEY
		
            if (mech->ulParameterLen != AES_INIT_VECTOR_SIZE){
               OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
               OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
               return CKR_KEY_TYPE_INCONSISTENT;
            }
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_AES){
                  OCK_LOG_ERR(ERR_KEY_TYPE_INCONSISTENT);
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            ctx->context_len = sizeof(AES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(AES_CONTEXT));
            if (!ctx->context){
               OCK_LOG_ERR(ERR_HOST_MEMORY);
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(AES_CONTEXT) );

	 }
	 break;
#endif
      default:
         OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
         return CKR_MECHANISM_INVALID;
   }


   if (mech->ulParameterLen > 0)
   {
      ptr = (CK_BYTE *)malloc(mech->ulParameterLen);
      if (!ptr){
         OCK_LOG_ERR(ERR_HOST_MEMORY);
         return CKR_HOST_MEMORY;
      }
      memcpy( ptr, mech->pParameter, mech->ulParameterLen );
   }

   ctx->key                 = key_handle;
   ctx->mech.ulParameterLen = mech->ulParameterLen;
   ctx->mech.mechanism      = mech->mechanism;
   ctx->mech.pParameter     = ptr;
   ctx->multi               = FALSE;
   ctx->active              = TRUE;

   return CKR_OK;
}


//
//
CK_RV
encr_mgr_cleanup( ENCR_DECR_CONTEXT *ctx )
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
encr_mgr_encrypt( SESSION           *sess,
                  CK_BBOOL           length_only,
                  ENCR_DECR_CONTEXT *ctx,
                  CK_BYTE           *in_data,
                  CK_ULONG           in_data_len,
                  CK_BYTE           *out_data,
                  CK_ULONG          *out_data_len )
{
   if (!sess || !ctx){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   // if the caller just wants the encrypted length, there is no reason to
   // specify the input data.  I just need the data length
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
#ifndef NOECB
#ifndef NOCDMF
      case CKM_CDMF_ECB:
#endif
      case CKM_DES_ECB:
         return pk_des_ecb_encrypt( sess,     length_only,
                                 ctx,
                                 in_data,  in_data_len,
                                 out_data, out_data_len );
#endif
#ifndef NOCDMF
      case CKM_CDMF_CBC:
#endif
      case CKM_DES_CBC:
         return pk_des_cbc_encrypt( sess,     length_only,
                                 ctx,
                                 in_data,  in_data_len,
                                 out_data, out_data_len );
#ifndef NOCDMF
      case CKM_CDMF_CBC_PAD:
#endif
      case CKM_DES_CBC_PAD:
         return des_cbc_pad_encrypt( sess,     length_only,
                                     ctx,
                                     in_data,  in_data_len,
                                     out_data, out_data_len );
#ifndef NOECB
      case CKM_DES3_ECB:
         return des3_ecb_encrypt( sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len );
#endif
      case CKM_DES3_CBC:
         return des3_cbc_encrypt( sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len );

      case CKM_DES3_CBC_PAD:
         return des3_cbc_pad_encrypt( sess,     length_only,
                                      ctx,
                                      in_data,  in_data_len,
                                      out_data, out_data_len );

      case CKM_RSA_PKCS:
         return rsa_pkcs_encrypt( sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len );
#if 0
      case CKM_RSA_X_509:
         return rsa_x509_encrypt( sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len );
#endif
#ifndef NOAES
      case CKM_AES_CBC:
	 return aes_cbc_encrypt( sess,     length_only,
			 	 ctx,
				 in_data,  in_data_len,
				 out_data, out_data_len );
      case CKM_AES_ECB:
	 return aes_ecb_encrypt( sess,     length_only,
			 	 ctx,
				 in_data,  in_data_len,
				 out_data, out_data_len );
      case CKM_AES_CBC_PAD:
	 return aes_cbc_pad_encrypt( sess,     length_only,
			 	     ctx,
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


//
//
CK_RV
encr_mgr_encrypt_update( SESSION            *sess,
                         CK_BBOOL            length_only,
                         ENCR_DECR_CONTEXT  *ctx,
                         CK_BYTE            *in_data,
                         CK_ULONG            in_data_len,
                         CK_BYTE            *out_data,
                         CK_ULONG           *out_data_len )
{
   if (!sess || !in_data || !ctx){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   if (!out_data && !length_only){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->active == FALSE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   ctx->multi = TRUE;

   switch (ctx->mech.mechanism) {
#ifndef NOECB
#ifndef NOCDMF
      case CKM_CDMF_ECB:
#endif
      case CKM_DES_ECB:
         return des_ecb_encrypt_update( sess,     length_only,
                                        ctx,
                                        in_data,  in_data_len,
                                        out_data, out_data_len );
#endif
#ifndef NOCDMF
      case CKM_CDMF_CBC:
#endif
      case CKM_DES_CBC:
         return des_cbc_encrypt_update( sess,     length_only,
                                        ctx,
                                        in_data,  in_data_len,
                                        out_data, out_data_len );
#ifndef NOCDMF
      case CKM_CDMF_CBC_PAD:
#endif
      case CKM_DES_CBC_PAD:
         return des_cbc_pad_encrypt_update( sess,     length_only,
                                            ctx,
                                            in_data,  in_data_len,
                                            out_data, out_data_len );
#ifndef NOECB
      case CKM_DES3_ECB:
         return des3_ecb_encrypt_update( sess,     length_only,
                                         ctx,
                                         in_data,  in_data_len,
                                         out_data, out_data_len );
#endif
      case CKM_DES3_CBC:
         return des3_cbc_encrypt_update( sess,     length_only,
                                         ctx,
                                         in_data,  in_data_len,
                                         out_data, out_data_len );

      case CKM_DES3_CBC_PAD:
         return des3_cbc_pad_encrypt_update( sess,     length_only,
                                             ctx,
                                             in_data,  in_data_len,
                                             out_data, out_data_len );
#ifndef NOAES
      case CKM_AES_ECB:
	 return aes_ecb_encrypt_update( sess,     length_only,
			 		ctx,
					in_data,  in_data_len,
					out_data, out_data_len );
      case CKM_AES_CBC:
	 return aes_cbc_encrypt_update( sess,     length_only,
			 		ctx,
					in_data,  in_data_len,
					out_data, out_data_len );
	 
      case CKM_AES_CBC_PAD:
	 return aes_cbc_pad_encrypt_update( sess,     length_only,
			 		    ctx,
					    in_data,  in_data_len,
					    out_data, out_data_len );
#endif
      default:
         return CKR_MECHANISM_INVALID;
   }
   OCK_LOG_ERR(ERR_FUNCTION_FAILED);

   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
encr_mgr_encrypt_final( SESSION            *sess,
                        CK_BBOOL            length_only,
                        ENCR_DECR_CONTEXT  *ctx,
                        CK_BYTE            *out_data,
                        CK_ULONG           *out_data_len )
{
   if (!sess || !ctx){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      OCK_LOG_ERR(ERR_OPERATION_NOT_INITIALIZED);
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   switch (ctx->mech.mechanism) {
#ifndef NOECB
#ifndef NOCDMF
      case CKM_CDMF_ECB:
#endif
      case CKM_DES_ECB:
         return des_ecb_encrypt_final( sess,     length_only,
                                       ctx,
                                       out_data, out_data_len );
#endif
#ifndef NOCDMF
      case CKM_CDMF_CBC:
#endif
      case CKM_DES_CBC:
         return des_cbc_encrypt_final( sess,     length_only,
                                       ctx,
                                       out_data, out_data_len );
#ifndef NOCDMF
      case CKM_CDMF_CBC_PAD:
#endif
      case CKM_DES_CBC_PAD:
         return des_cbc_pad_encrypt_final( sess,     length_only,
                                           ctx,
                                           out_data, out_data_len );
#ifndef NOECB
      case CKM_DES3_ECB:
         return des3_ecb_encrypt_final( sess,     length_only,
                                        ctx,
                                        out_data, out_data_len );
#endif
      case CKM_DES3_CBC:
         return des3_cbc_encrypt_final( sess,     length_only,
                                        ctx,
                                        out_data, out_data_len );

      case CKM_DES3_CBC_PAD:
         return des3_cbc_pad_encrypt_final( sess,     length_only,
                                            ctx,
                                            out_data, out_data_len );
#ifndef NOAES
      case CKM_AES_ECB:
	 return aes_ecb_encrypt_final( sess,     length_only,
			 	       ctx,
				       out_data, out_data_len );
      case CKM_AES_CBC:
	 return aes_cbc_encrypt_final( sess,     length_only,
			 	       ctx,
				       out_data, out_data_len );
	 
      case CKM_AES_CBC_PAD:
	 return aes_cbc_pad_encrypt_final( sess,     length_only,
			 		   ctx,
					   out_data, out_data_len );
#endif
      default:
         return CKR_MECHANISM_INVALID;
   }

   OCK_LOG_ERR(ERR_FUNCTION_FAILED);
   return CKR_FUNCTION_FAILED;
}

