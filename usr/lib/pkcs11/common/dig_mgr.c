/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  dig_mgr.c
//
// Digest manager routines
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
digest_mgr_init( STDLL_TokData_t   *tokdata,
		 SESSION           *sess,
                 DIGEST_CONTEXT    *ctx,
                 CK_MECHANISM      *mech )
{
   CK_RV rc = CKR_OK;
   CK_BYTE  * ptr = NULL;

   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active != FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
      return CKR_OPERATION_ACTIVE;
   }
   // is the mechanism supported?  is the parameter present if required?
   //
   switch (mech->mechanism) {
      case CKM_SHA_1:
      case CKM_SHA256:
      case CKM_SHA384:
      case CKM_SHA512:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }

            ctx->context = NULL;
            rc = sha_init(tokdata, sess, ctx, mech);
            if (rc != CKR_OK) {
               digest_mgr_cleanup(ctx);  // to de-initialize context above
	       TRACE_ERROR("Failed to init sha context.\n");
               return rc;
            }
         }
         break;

      case CKM_MD2:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            ctx->context_len = sizeof(MD2_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(MD2_CONTEXT));
            if (!ctx->context){
               digest_mgr_cleanup(ctx);  // to de-initialize context above
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(MD2_CONTEXT) );
         }
         break;

      case CKM_MD5:
         {
            if (mech->ulParameterLen != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
               return CKR_MECHANISM_PARAM_INVALID;
            }
            ctx->context_len = sizeof(MD5_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(MD5_CONTEXT));
            if (!ctx->context){
               digest_mgr_cleanup(ctx);  // to de-initialize context above
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
            ckm_md5_init( tokdata, (MD5_CONTEXT *)ctx->context );
         }
         break;

      default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
         return CKR_MECHANISM_INVALID;
   }

   if (mech->ulParameterLen > 0) {
      ptr = (CK_BYTE *)malloc(mech->ulParameterLen);
      if (!ptr){
         digest_mgr_cleanup(ctx);  // to de-initialize context above
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      memcpy( ptr, mech->pParameter, mech->ulParameterLen );
   }
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
digest_mgr_cleanup( DIGEST_CONTEXT *ctx )
{
   if (!ctx){
      TRACE_ERROR("Invalid function argument.\n");
      return CKR_FUNCTION_FAILED;
   }
   ctx->mech.ulParameterLen = 0;
   ctx->mech.mechanism      = 0;
   ctx->multi               = FALSE;
   ctx->active              = FALSE;
   ctx->context_len         = 0;

   if (ctx->mech.pParameter) {
      free( ctx->mech.pParameter );
      ctx->mech.pParameter = NULL;
   }

   if (ctx->context != NULL) {
      free( ctx->context );
      ctx->context = NULL;
   }

   return CKR_OK;
}



//
//
CK_RV
digest_mgr_digest( STDLL_TokData_t *tokdata,
		   SESSION         *sess,
                   CK_BBOOL         length_only,
                   DIGEST_CONTEXT  *ctx,
                   CK_BYTE         *in_data,
                   CK_ULONG         in_data_len,
                   CK_BYTE         *out_data,
                   CK_ULONG        *out_data_len )
{
   CK_RV        rc;

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
      rc = CKR_FUNCTION_FAILED;
      goto out;
   }

   if (ctx->multi == TRUE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
      rc = CKR_OPERATION_ACTIVE;
      goto out;
   }
   switch (ctx->mech.mechanism) {
      case CKM_SHA_1:
      case CKM_SHA256:
      case CKM_SHA384:
      case CKM_SHA512:
         rc = sha_hash( tokdata, sess, length_only, ctx, in_data, in_data_len,
		        out_data, out_data_len );
         break;

#if !(NOMD2 )
      case CKM_MD2:
         rc = md2_hash( tokdata, sess, length_only, ctx, in_data, in_data_len,
			out_data, out_data_len );
         break;
#endif

      case CKM_MD5:
         rc = md5_hash( tokdata, sess, length_only, ctx, in_data, in_data_len,
			out_data, out_data_len );
         break;

      default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
         rc = CKR_MECHANISM_INVALID;
   }

out:
   if ( !((rc == CKR_BUFFER_TOO_SMALL) ||
          (rc == CKR_OK && length_only == TRUE)) ) {
      // "A call to C_Digest always terminates the active digest operation unless it
      // returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
      // to determine the length of the buffer needed to hold the message digest."
      digest_mgr_cleanup(ctx);
   }

   return rc;

}


//
//
CK_RV
digest_mgr_digest_update( STDLL_TokData_t *tokdata,
			  SESSION         *sess,
                          DIGEST_CONTEXT  *ctx,
                          CK_BYTE         *data,
                          CK_ULONG         data_len )
{
   CK_RV        rc;

   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   ctx->multi = TRUE;

   switch (ctx->mech.mechanism) {
      case CKM_SHA_1:
      case CKM_SHA256:
      case CKM_SHA384:
      case CKM_SHA512:
         rc = sha_hash_update(tokdata, sess, ctx, data, data_len);
         break;

#if !(NOMD2)
      case CKM_MD2:
         rc = md2_hash_update( tokdata, sess, ctx, data, data_len );
         break;
#endif

      case CKM_MD5:
         rc = md5_hash_update( tokdata, sess, ctx, data, data_len );
         break;

      default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
         rc = CKR_MECHANISM_INVALID;
   }

   if (rc != CKR_OK) {
      digest_mgr_cleanup(ctx);  // "A call to C_DigestUpdate which results in an error
                                // terminates the current digest operation."
   }

   return rc;
}


//
//
CK_RV
digest_mgr_digest_key( STDLL_TokData_t  *tokdata,
		       SESSION          * sess,
                       DIGEST_CONTEXT   * ctx,
                       CK_OBJECT_HANDLE   key_handle )
{
   CK_ATTRIBUTE    * attr     = NULL;
   OBJECT          * key_obj  = NULL;
   CK_OBJECT_CLASS   class;
   CK_RV             rc;


   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }

   rc = object_mgr_find_in_map1( tokdata, key_handle, &key_obj );
   if (rc != CKR_OK){
      TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
      rc = CKR_KEY_HANDLE_INVALID;
      goto out;
   }
   // only allow digesting of CKO_SECRET keys
   //
   rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE) {
      TRACE_ERROR("%s\n", ock_err(ERR_KEY_INDIGESTIBLE));
      rc = CKR_KEY_INDIGESTIBLE;
      goto out;
   }
   else
      class = *(CK_OBJECT_CLASS *)attr->pValue;

   if (class != CKO_SECRET_KEY){
      TRACE_ERROR("%s\n", ock_err(ERR_KEY_INDIGESTIBLE));
      rc = CKR_KEY_INDIGESTIBLE;
      goto out;
   }

   // every secret key has a CKA_VALUE attribute
   //
   rc = template_attribute_find( key_obj->template, CKA_VALUE, &attr );
   if (!rc){
      TRACE_ERROR("%s\n", ock_err(ERR_KEY_INDIGESTIBLE));
      rc = CKR_KEY_INDIGESTIBLE;
      goto out;
   }
   rc = digest_mgr_digest_update( tokdata, sess, ctx,
                                  attr->pValue, attr->ulValueLen );
   if (rc != CKR_OK){
      TRACE_DEVEL("digest_mgr_digest_update failed\n");
   }

out:
   if (rc != CKR_OK) {
      digest_mgr_cleanup(ctx);
   }
   return rc;
}


//
//
CK_RV
digest_mgr_digest_final( STDLL_TokData_t *tokdata,
			 SESSION         *sess,
                         CK_BBOOL         length_only,
                         DIGEST_CONTEXT  *ctx,
                         CK_BYTE         *hash,
                         CK_ULONG        *hash_len )
{
   CK_RV        rc;

   if (!sess || !ctx){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   switch (ctx->mech.mechanism) {
      case CKM_SHA_1:
      case CKM_SHA256:
      case CKM_SHA384:
      case CKM_SHA512:
         rc = sha_hash_final(tokdata, sess, length_only, ctx, hash, hash_len);
         break;

#if !(NOMD2)
      case CKM_MD2:
         rc = md2_hash_final(tokdata, sess, length_only, ctx, hash, hash_len);
         break;
#endif

      case CKM_MD5:
         rc = md5_hash_final(tokdata, sess, length_only, ctx, hash, hash_len);
         break;

      default:
         TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
         rc = CKR_MECHANISM_INVALID;   // shouldn't happen
   }

   if ( !((rc == CKR_BUFFER_TOO_SMALL) ||
          (rc == CKR_OK && length_only == TRUE)) ) {
      // "A call to C_DigestFinal always terminates the active digest operation unless it
      // returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e., one which returns CKR_OK)
      // to determine the length of the buffer needed to hold the message digest."
      digest_mgr_cleanup(ctx);
   }

   return rc;
}
