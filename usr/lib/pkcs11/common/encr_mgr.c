/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  encr_mgr.c
//
// Encryption manager routines
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
encr_mgr_init( STDLL_TokData_t   *tokdata,
	       SESSION           * sess,
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
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active != FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
      return CKR_OPERATION_ACTIVE;
   }

   // key usage restrictions
   //
   if (operation == OP_ENCRYPT_INIT)
   {
      rc = object_mgr_find_in_map1( tokdata, key_handle, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to acquire key from specified handle.\n");
	 if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
	 else
	    return rc;
      }
      // is key allowed to do general encryption?
      //
      rc = template_attribute_find( key_obj->template, CKA_ENCRYPT, &attr );
      if (rc == FALSE){
	 TRACE_ERROR("Could not find CKA_ENCRYPT for the key.\n");
         return CKR_KEY_FUNCTION_NOT_PERMITTED;
      }
      else
      {
         flag = *(CK_BBOOL *)attr->pValue;
         if (flag != TRUE){
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_FUNCTION_NOT_PERMITTED));
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
         }
      }
   }
   else if (operation == OP_WRAP)
   {
      rc = object_mgr_find_in_map1( tokdata, key_handle, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to acquire key from specified handle.\n");
	 if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_WRAPPING_KEY_HANDLE_INVALID;
	 else
	    return rc;
      }
      // is key allowed to wrap other keys?
      //
      rc = template_attribute_find( key_obj->template, CKA_WRAP, &attr );
      if (rc == FALSE){
	 TRACE_ERROR("Could not find CKA_WRAP for the key.\n");
         return CKR_KEY_FUNCTION_NOT_PERMITTED;
      }
      else
      {
         flag = *(CK_BBOOL *)attr->pValue;
         if (flag == FALSE){
            TRACE_ERROR("CKA_WRAP is set to FALSE.\n");
            return CKR_KEY_FUNCTION_NOT_PERMITTED;
         }
      }
   }
   else{
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
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
      case CKM_DES_ECB:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_DES){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
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
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;

      case CKM_CDMF_ECB:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
            }
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_CDMF){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            ctx->context_len = sizeof(DES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(DES_CONTEXT));
            if (!ctx->context){
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;

      case CKM_DES_CBC:
      case CKM_DES_CBC_PAD:
         {
            if (mech->ulParameterLen != DES_BLOCK_SIZE){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_DES){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
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
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;

      case CKM_DES_CFB8:
      case CKM_DES_CFB64:
      case CKM_DES_OFB64:
         {
           if (mech->ulParameterLen != DES_BLOCK_SIZE){
              TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
              return CKR_MECHANISM_PARAM_INVALID;
           }

           rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
           if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
           } else {
              keytype = *(CK_KEY_TYPE *)attr->pValue;
              if ((keytype != CKK_DES3) ) {
                 TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                 return CKR_KEY_TYPE_INCONSISTENT;
              }
           }

           ctx->context_len = sizeof(DES_CONTEXT);
           ctx->context     = (CK_BYTE *)malloc(sizeof(DES_CONTEXT));
           if (!ctx->context){
              TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
              return CKR_HOST_MEMORY;
           }
           memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;

      case CKM_CDMF_CBC:
      case CKM_CDMF_CBC_PAD:
         {
            if (mech->ulParameterLen != DES_BLOCK_SIZE){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_CDMF){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }


            ctx->context_len = sizeof(DES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(DES_CONTEXT));
            if (!ctx->context){
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;

      case CKM_DES3_ECB:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }

            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_DES3 && keytype != CKK_DES2){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
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
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;

      case CKM_DES3_CBC:
      case CKM_DES3_CBC_PAD:
         {
            if (mech->ulParameterLen != DES_BLOCK_SIZE){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
            }
            else
            {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_DES3 && keytype != CKK_DES2){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
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
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(DES_CONTEXT) );
         }
         break;

      case CKM_RSA_PKCS_OAEP:
	    if (mech->ulParameterLen == 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
		return CKR_MECHANISM_PARAM_INVALID;
	    }
	    rc = template_attribute_find(key_obj->template, CKA_KEY_TYPE,
					  &attr);
	    if (rc == FALSE) {
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
	    }
            keytype = *(CK_KEY_TYPE *)attr->pValue;
            if (keytype != CKK_RSA) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
		return CKR_KEY_TYPE_INCONSISTENT;
	    }
	    // RSA cannot be used for multi-part operations
	    //
	    ctx->context_len = 0;
	    ctx->context = NULL;

	    break;

      case CKM_RSA_X_509:
      case CKM_RSA_PKCS:
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

            // RSA cannot be used for multi-part operations
            //
            ctx->context_len = 0;
            ctx->context     = NULL;
         }
         break;

      case CKM_AES_ECB:
	 {
	    // XXX Copied in from DES3, should be verified - KEY

            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }

            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_AES){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            ctx->context_len = sizeof(AES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(AES_CONTEXT));
            if (!ctx->context){
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
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
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            // is the key type correct?
            //
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_AES){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

            ctx->context_len = sizeof(AES_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(AES_CONTEXT));
            if (!ctx->context){
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(AES_CONTEXT) );

	 }
	 break;
     case CKM_AES_CTR:
	 {
	    if (mech->ulParameterLen != sizeof(CK_AES_CTR_PARAMS)){
	       TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
	       return CKR_MECHANISM_PARAM_INVALID;
	    }
	    // is the key type correct
            rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
            if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
            }
            else {
               keytype = *(CK_KEY_TYPE *)attr->pValue;
               if (keytype != CKK_AES){
                  TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                  return CKR_KEY_TYPE_INCONSISTENT;
               }
            }

           ctx->context_len = sizeof(AES_CONTEXT);
           ctx->context     = (CK_BYTE *)malloc(sizeof(AES_CONTEXT));
           if (!ctx->context){
              TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
              return CKR_HOST_MEMORY;
           }
           memset( ctx->context, 0x0, sizeof(AES_CONTEXT) );
	}
	break;
	case CKM_AES_GCM:
	{
		if (mech->ulParameterLen != sizeof(CK_GCM_PARAMS)) {
			TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}
		rc = template_attribute_find(key_obj->template, CKA_KEY_TYPE,
					     &attr);
		if (rc == FALSE) {
			TRACE_ERROR("Could not find CKA_KEY_TYPE for key.\n");
			return CKR_FUNCTION_FAILED;
		} else {
			keytype = *(CK_KEY_TYPE *)attr->pValue;
			if (keytype != CKK_AES) {
				TRACE_ERROR("%s\n",
					    ock_err(ERR_KEY_TYPE_INCONSISTENT));
				return CKR_KEY_TYPE_INCONSISTENT;
			}
		}

		ctx->context_len = sizeof(AES_GCM_CONTEXT);
		ctx->context = (CK_BYTE *)malloc(sizeof(AES_GCM_CONTEXT));
		if (!ctx->context) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			return CKR_HOST_MEMORY;
		}
		memset(ctx->context, 0x0, sizeof(AES_GCM_CONTEXT));

		rc = aes_gcm_init(tokdata, sess, ctx, mech, key_handle, 1);
		if (rc != CKR_OK) {
			TRACE_ERROR("Could not initialize AES_GCM parms.\n");
			return CKR_FUNCTION_FAILED;
		}
	}
	break;

     case CKM_AES_OFB:
     case CKM_AES_CFB8:
     case CKM_AES_CFB64:
     case CKM_AES_CFB128:
        {
          if (mech->ulParameterLen != AES_INIT_VECTOR_SIZE){
             TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
             return CKR_MECHANISM_PARAM_INVALID;
          }

          rc = template_attribute_find( key_obj->template, CKA_KEY_TYPE, &attr );
          if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
		return CKR_FUNCTION_FAILED;
          } else {
             keytype = *(CK_KEY_TYPE *)attr->pValue;
             if ( keytype != CKK_AES ){
                TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                return CKR_KEY_TYPE_INCONSISTENT;
             }
          }

          ctx->context_len = sizeof(AES_CONTEXT);
          ctx->context     = (CK_BYTE *)malloc(sizeof(AES_CONTEXT));
          if (!ctx->context){
             TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
             return CKR_HOST_MEMORY;
          }
          memset( ctx->context, 0x0, sizeof(AES_CONTEXT) );
         }
         break;

     default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
         return CKR_MECHANISM_INVALID;
   }

	if ((mech->ulParameterLen > 0) || (mech->mechanism == CKM_AES_CTR) ||
	    (mech->mechanism == CKM_AES_GCM)) {
        ptr = (CK_BYTE *)malloc (mech->ulParameterLen);
	if (!ptr){
	   TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
	   return CKR_HOST_MEMORY;
	}
	memcpy( ptr, mech->pParameter, mech->ulParameterLen );
    }
   else if (mech->ulParameterLen > 0){
           ptr = (CK_BYTE *)malloc(mech->ulParameterLen);
           if (!ptr){
              TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
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
      TRACE_ERROR("Invalid function argument.\n");
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
encr_mgr_encrypt( STDLL_TokData_t   *tokdata,
		  SESSION           *sess,
                  CK_BBOOL           length_only,
                  ENCR_DECR_CONTEXT *ctx,
                  CK_BYTE           *in_data,
                  CK_ULONG           in_data_len,
                  CK_BYTE           *out_data,
                  CK_ULONG          *out_data_len )
{
   CK_KEY_TYPE   keytype;

   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   // if the caller just wants the encrypted length, there is no reason to
   // specify the input data.  I just need the data length
   //
   if ((length_only == FALSE) && (!in_data || !out_data)){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->multi == TRUE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
      return CKR_OPERATION_ACTIVE;
   }
   switch (ctx->mech.mechanism) {
      case CKM_CDMF_ECB:
      case CKM_DES_ECB:
         return pk_des_ecb_encrypt( tokdata, sess, length_only,
                                 ctx,
                                 in_data,  in_data_len,
                                 out_data, out_data_len );

      case CKM_CDMF_CBC:
      case CKM_DES_CBC:
         return pk_des_cbc_encrypt( tokdata, sess, length_only,
                                 ctx,
                                 in_data,  in_data_len,
                                 out_data, out_data_len );

      case CKM_DES_CBC_PAD:
      case CKM_CDMF_CBC_PAD:
         return des_cbc_pad_encrypt( tokdata, sess, length_only,
                                     ctx,
                                     in_data,  in_data_len,
                                     out_data, out_data_len );

      case CKM_DES_OFB64:
         get_keytype(tokdata, ctx->key, &keytype);
         if (keytype == CKK_DES3) {
             return des3_ofb_encrypt( tokdata, sess,     length_only,
                                      ctx,
                                      in_data,  in_data_len,
                                      out_data, out_data_len );
         } else {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
         }

      case CKM_DES_CFB8:
         get_keytype(tokdata, ctx->key, &keytype);
         if (keytype == CKK_DES3) {
            return des3_cfb_encrypt( tokdata, sess,     length_only,
                                     ctx,
                                     in_data,  in_data_len,
                                     out_data, out_data_len, 0x01);
         } else {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
         }

      case CKM_DES_CFB64:
         get_keytype(tokdata, ctx->key, &keytype);
         if (keytype == CKK_DES3) {
            return des3_cfb_encrypt( tokdata, sess,     length_only,
                                     ctx,
                                     in_data,  in_data_len,
                                     out_data, out_data_len, 0x08);
         } else {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
         }

      case CKM_DES3_ECB:
         return des3_ecb_encrypt(  tokdata, sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len );

      case CKM_DES3_CBC:
         return des3_cbc_encrypt( tokdata, sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len );

      case CKM_DES3_CBC_PAD:
         return des3_cbc_pad_encrypt( tokdata, sess,     length_only,
                                      ctx,
                                      in_data,  in_data_len,
                                      out_data, out_data_len );

      case CKM_RSA_PKCS:
         return rsa_pkcs_encrypt( tokdata, sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len );

      case CKM_RSA_PKCS_OAEP:
         return rsa_oaep_crypt(tokdata, sess, length_only, ctx, in_data,
			       in_data_len, out_data, out_data_len, ENCRYPT);

      case CKM_RSA_X_509:
         return rsa_x509_encrypt( tokdata, sess, length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len );
#ifndef NOAES
      case CKM_AES_CBC:
	 return aes_cbc_encrypt( tokdata, sess,     length_only,
				 ctx,
				 in_data,  in_data_len,
				 out_data, out_data_len );

      case CKM_AES_ECB:
	 return aes_ecb_encrypt( tokdata, sess,     length_only,
				 ctx,
				 in_data,  in_data_len,
				 out_data, out_data_len );

      case CKM_AES_CBC_PAD:
	 return aes_cbc_pad_encrypt( tokdata, sess,     length_only,
				     ctx,
				     in_data,  in_data_len,
				     out_data, out_data_len );
      case CKM_AES_CTR:
	 return aes_ctr_encrypt( tokdata, sess,     length_only,
				 ctx,
				 in_data,  in_data_len,
				 out_data, out_data_len );
	case CKM_AES_GCM:
	   return aes_gcm_encrypt(tokdata, sess, length_only,
				  ctx, in_data, in_data_len,
				  out_data, out_data_len);
      case CKM_AES_OFB:
          return aes_ofb_encrypt( tokdata, sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len );

      case CKM_AES_CFB8:
          return aes_cfb_encrypt( tokdata, sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len, 0x01);
      case CKM_AES_CFB64:
          return aes_cfb_encrypt( tokdata, sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len, 0x08);
      case CKM_AES_CFB128:
          return aes_cfb_encrypt( tokdata, sess,     length_only,
                                  ctx,
                                  in_data,  in_data_len,
                                  out_data, out_data_len, 0x10);

#endif

      default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
         return CKR_MECHANISM_INVALID;
   }
   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

   return CKR_FUNCTION_FAILED;
}
//
//
CK_RV
encr_mgr_encrypt_update( STDLL_TokData_t    *tokdata,
			 SESSION            *sess,
                         CK_BBOOL            length_only,
                         ENCR_DECR_CONTEXT  *ctx,
                         CK_BYTE            *in_data,
                         CK_ULONG            in_data_len,
                         CK_BYTE            *out_data,
                         CK_ULONG           *out_data_len )
{
   CK_KEY_TYPE   keytype;

   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }

   if (!out_data && !length_only){
      TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->active == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   ctx->multi = TRUE;

   switch (ctx->mech.mechanism) {
      case CKM_CDMF_ECB:
      case CKM_DES_ECB:
         return des_ecb_encrypt_update( tokdata, sess, length_only,
                                        ctx,
                                        in_data,  in_data_len,
                                        out_data, out_data_len );

      case CKM_CDMF_CBC:
      case CKM_DES_CBC:
         return des_cbc_encrypt_update( tokdata, sess, length_only,
                                        ctx,
                                        in_data,  in_data_len,
                                        out_data, out_data_len );

      case CKM_DES_CBC_PAD:
      case CKM_CDMF_CBC_PAD:
         return des_cbc_pad_encrypt_update( tokdata, sess, length_only,
                                            ctx,
                                            in_data,  in_data_len,
                                            out_data, out_data_len );

      case CKM_DES_OFB64:
         get_keytype(tokdata, ctx->key, &keytype);
         if (keytype == CKK_DES3) {
            return des3_ofb_encrypt_update( tokdata, sess,     length_only,
                                            ctx,
                                            in_data,  in_data_len,
                                            out_data, out_data_len );
         } else {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
         }

      case CKM_DES_CFB8:
         get_keytype(tokdata, ctx->key, &keytype);
         if (keytype == CKK_DES3) {
             return des3_cfb_encrypt_update( tokdata, sess,     length_only,
                                             ctx,
                                             in_data,  in_data_len,
                                             out_data, out_data_len, 0x01);
         } else {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
         }

      case CKM_DES_CFB64:
         get_keytype(tokdata, ctx->key, &keytype);
         if (keytype == CKK_DES3) {
             return des3_cfb_encrypt_update( tokdata, sess,     length_only,
                                             ctx,
                                             in_data,  in_data_len,
                                             out_data, out_data_len, 0x08);
         } else {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
         }

      case CKM_DES3_ECB:
         return des3_ecb_encrypt_update( tokdata, sess,     length_only,
                                         ctx,
                                         in_data,  in_data_len,
                                         out_data, out_data_len );

      case CKM_DES3_CBC:
         return des3_cbc_encrypt_update( tokdata, sess,     length_only,
                                         ctx,
                                         in_data,  in_data_len,
                                         out_data, out_data_len );

      case CKM_DES3_CBC_PAD:
         return des3_cbc_pad_encrypt_update( tokdata, sess,     length_only,
                                             ctx,
                                             in_data,  in_data_len,
                                             out_data, out_data_len );
#ifndef NOAES
      case CKM_AES_ECB:
	 return aes_ecb_encrypt_update( tokdata, sess,     length_only,
					ctx,
					in_data,  in_data_len,
					out_data, out_data_len );

      case CKM_AES_CBC:
	 return aes_cbc_encrypt_update( tokdata, sess,     length_only,
					ctx,
					in_data,  in_data_len,
					out_data, out_data_len );

      case CKM_AES_CBC_PAD:
	 return aes_cbc_pad_encrypt_update( tokdata, sess,     length_only,
					    ctx,
					    in_data,  in_data_len,
					    out_data, out_data_len );

     case CKM_AES_CTR:
	 return aes_ctr_encrypt_update( tokdata, sess,     length_only,
					 ctx,
					 in_data,  in_data_len,
					 out_data, out_data_len );

      case CKM_AES_GCM:
	  return aes_gcm_encrypt_update(tokdata, sess, length_only, ctx, in_data,
					in_data_len, out_data, out_data_len);

     case CKM_AES_OFB:
        return aes_ofb_encrypt_update( tokdata, sess,     length_only,
                                       ctx,
                                       in_data,  in_data_len,
                                       out_data, out_data_len );

     case CKM_AES_CFB8:
         return aes_cfb_encrypt_update( tokdata, sess,     length_only,
                                        ctx,
                                        in_data,  in_data_len,
                                        out_data, out_data_len, 0x01);
     case CKM_AES_CFB64:
         return aes_cfb_encrypt_update( tokdata, sess,     length_only,
                                        ctx,
                                        in_data,  in_data_len,
                                        out_data, out_data_len, 0x08);
     case CKM_AES_CFB128:
         return aes_cfb_encrypt_update( tokdata, sess,     length_only,
                                        ctx,
                                        in_data,  in_data_len,
                                        out_data, out_data_len, 0x10);

#endif
      default:
         return CKR_MECHANISM_INVALID;
   }
   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

   return CKR_FUNCTION_FAILED;
}
//
//
CK_RV
encr_mgr_encrypt_final( STDLL_TokData_t    *tokdata,
			SESSION            *sess,
                        CK_BBOOL            length_only,
                        ENCR_DECR_CONTEXT  *ctx,
                        CK_BYTE            *out_data,
                        CK_ULONG           *out_data_len )
{
   CK_KEY_TYPE   keytype;

   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   switch (ctx->mech.mechanism) {
      case CKM_CDMF_ECB:
      case CKM_DES_ECB:
         return des_ecb_encrypt_final( tokdata, sess, length_only,
                                       ctx,
                                       out_data, out_data_len );

      case CKM_CDMF_CBC:
      case CKM_DES_CBC:
         return des_cbc_encrypt_final( tokdata, sess, length_only,
                                       ctx,
                                       out_data, out_data_len );

      case CKM_DES_CBC_PAD:
      case CKM_CDMF_CBC_PAD:
         return des_cbc_pad_encrypt_final( tokdata, sess, length_only,
                                           ctx,
                                           out_data, out_data_len );

      case CKM_DES_OFB64:
         get_keytype(tokdata, ctx->key, &keytype);
         if (keytype == CKK_DES3) {
            return des3_ofb_encrypt_final( tokdata, sess,     length_only,
                                           ctx,
                                           out_data, out_data_len );
         } else {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
         }

      case CKM_DES_CFB8:
         get_keytype(tokdata, ctx->key, &keytype);
         if (keytype == CKK_DES3) {
            return des3_cfb_encrypt_final( tokdata, sess,     length_only,
                                           ctx,
                                           out_data, out_data_len, 0x01);
         } else {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
         }

      case CKM_DES_CFB64:
         get_keytype(tokdata, ctx->key, &keytype);
         if (keytype == CKK_DES3) {
            return des3_cfb_encrypt_final( tokdata, sess,     length_only,
                                           ctx,
                                           out_data, out_data_len, 0x08);
         } else {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            return CKR_KEY_TYPE_INCONSISTENT;
         }

      case CKM_DES3_ECB:
         return des3_ecb_encrypt_final( tokdata, sess,     length_only,
                                        ctx,
                                        out_data, out_data_len );

      case CKM_DES3_CBC:
         return des3_cbc_encrypt_final( tokdata, sess,     length_only,
                                        ctx,
                                        out_data, out_data_len );

      case CKM_DES3_CBC_PAD:
         return des3_cbc_pad_encrypt_final( tokdata, sess,     length_only,
                                            ctx,
                                            out_data, out_data_len );
#ifndef NOAES
      case CKM_AES_ECB:
	 return aes_ecb_encrypt_final( tokdata, sess,     length_only,
				       ctx,
				       out_data, out_data_len );

      case CKM_AES_CBC:
	 return aes_cbc_encrypt_final( tokdata, sess,     length_only,
				       ctx,
				       out_data, out_data_len );

      case CKM_AES_CBC_PAD:
	 return aes_cbc_pad_encrypt_final( tokdata, sess,     length_only,
					   ctx,
					   out_data, out_data_len );

     case CKM_AES_CTR:
	 return aes_ctr_encrypt_final( tokdata, sess,     length_only,
				       ctx,
				       out_data, out_data_len );

     case CKM_AES_GCM:
	 return aes_gcm_encrypt_final(tokdata, sess, length_only, ctx,
				      out_data, out_data_len);

     case CKM_AES_OFB:
         return aes_ofb_encrypt_final( tokdata, sess,     length_only,
                                       ctx,
                                       out_data, out_data_len );

     case CKM_AES_CFB8:
         return aes_cfb_encrypt_final( tokdata, sess,     length_only,
                                       ctx, out_data, out_data_len, 0x01);
     case CKM_AES_CFB64:
         return aes_cfb_encrypt_final( tokdata, sess,     length_only,
                                       ctx, out_data, out_data_len, 0x08);
     case CKM_AES_CFB128:
         return aes_cfb_encrypt_final( tokdata, sess,     length_only,
                                       ctx, out_data, out_data_len, 0x10);
#endif
      default:
         return CKR_MECHANISM_INVALID;
   }

   TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
   return CKR_FUNCTION_FAILED;
}
