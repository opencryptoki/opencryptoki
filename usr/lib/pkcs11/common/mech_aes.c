/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  mech_aes.c
//
// Mechanisms for AES
//

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
aes_ecb_encrypt( STDLL_TokData_t   *tokdata,
		 SESSION           *sess,
                 CK_BBOOL           length_only,
                 ENCR_DECR_CONTEXT *ctx,
                 CK_BYTE           *in_data,
                 CK_ULONG           in_data_len,
                 CK_BYTE           *out_data,
                 CK_ULONG          *out_data_len )
{
   OBJECT       *key       = NULL;
   CK_RV         rc;


   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (in_data_len % AES_BLOCK_SIZE != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
      return CKR_DATA_LEN_RANGE;
   }
   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len) {
      *out_data_len = in_data_len;
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   return ckm_aes_ecb_encrypt(tokdata, in_data, in_data_len,
			      out_data, out_data_len, key);
}


//
//
CK_RV
aes_ecb_decrypt( STDLL_TokData_t   *tokdata,
		 SESSION           *sess,
                 CK_BBOOL           length_only,
                 ENCR_DECR_CONTEXT *ctx,
                 CK_BYTE           *in_data,
                 CK_ULONG           in_data_len,
                 CK_BYTE           *out_data,
                 CK_ULONG          *out_data_len)
{
   OBJECT       *key       = NULL;
   CK_RV         rc;


   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   // CKM_DES3_ECB requires the input data to be an integral
   // multiple of the block size
   //
   if (in_data_len % AES_BLOCK_SIZE != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len) {
      *out_data_len = in_data_len;
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   return ckm_aes_ecb_decrypt(tokdata, in_data, in_data_len,
                               out_data, out_data_len, key);
}


//
//
CK_RV
aes_cbc_encrypt( STDLL_TokData_t   *tokdata,
		 SESSION           *sess,
                 CK_BBOOL           length_only,
                 ENCR_DECR_CONTEXT *ctx,
                 CK_BYTE           *in_data,
                 CK_ULONG           in_data_len,
                 CK_BYTE           *out_data,
                 CK_ULONG          *out_data_len)
{
   OBJECT       *key       = NULL;
   CK_RV         rc;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // CKM_DES3_CBC requires the input data to be an integral
   // multiple of the block size
   //
   if (in_data_len % AES_BLOCK_SIZE != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
      return CKR_DATA_LEN_RANGE;
   }

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len) {
      *out_data_len = in_data_len;
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   return ckm_aes_cbc_encrypt(tokdata, in_data, in_data_len, out_data,
			      out_data_len, ctx->mech.pParameter, key);
}

//
//
CK_RV
aes_cbc_decrypt( STDLL_TokData_t    *tokdata,
		 SESSION            *sess,
                 CK_BBOOL            length_only,
                 ENCR_DECR_CONTEXT  *ctx,
                 CK_BYTE            *in_data,
                 CK_ULONG            in_data_len,
                 CK_BYTE            *out_data,
                 CK_ULONG           *out_data_len)
{
   OBJECT       *key       = NULL;
   CK_RV         rc;


   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // CKM_DES3_CBC requires the input data to be an integral
   // multiple of the block size
   //
   if (in_data_len % AES_BLOCK_SIZE != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len) {
      *out_data_len = in_data_len;
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   return ckm_aes_cbc_decrypt(tokdata, in_data, in_data_len, out_data,
			      out_data_len, ctx->mech.pParameter, key);
}


//
//
CK_RV
aes_cbc_pad_encrypt( STDLL_TokData_t   *tokdata,
		     SESSION           *sess,
                     CK_BBOOL           length_only,
                     ENCR_DECR_CONTEXT *ctx,
                     CK_BYTE           *in_data,
                     CK_ULONG           in_data_len,
                     CK_BYTE           *out_data,
                     CK_ULONG          *out_data_len)
{
   OBJECT       *key       = NULL;
   CK_BYTE      *clear     = NULL;
   CK_ULONG      padded_len;
   CK_RV         rc;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // DES3-CBC-PAD has no input length requirements
   //

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   // compute the output length, accounting for padding
   //
   padded_len = AES_BLOCK_SIZE * (in_data_len / AES_BLOCK_SIZE + 1);

   if (length_only == TRUE) {
      *out_data_len = padded_len;
      return CKR_OK;
   }

   if (*out_data_len < padded_len) {
      *out_data_len = padded_len;
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   clear = (CK_BYTE *)malloc( padded_len );
   if (!clear){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }
   memcpy( clear, in_data, in_data_len );

   add_pkcs_padding( clear + in_data_len,
                     AES_BLOCK_SIZE,
                     in_data_len,
                     padded_len );

   rc = ckm_aes_cbc_encrypt(tokdata, clear, padded_len, out_data, out_data_len,
                            ctx->mech.pParameter, key);

   free( clear );
   return rc;
}


//
//
CK_RV
aes_cbc_pad_decrypt( STDLL_TokData_t    *tokdata,
		     SESSION            *sess,
                     CK_BBOOL            length_only,
                     ENCR_DECR_CONTEXT  *ctx,
                     CK_BYTE            *in_data,
                     CK_ULONG            in_data_len,
                     CK_BYTE            *out_data,
                     CK_ULONG           *out_data_len)
{
   OBJECT       *key       = NULL;
   CK_BYTE      *clear     = NULL;
   CK_ULONG      padded_len;
   CK_RV         rc;


   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   //
   // no need to validate the input length since we'll pad as necessary
   //

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   // we're decrypting so even with CBC-PAD, we should have an integral
   // number of block to decrypt
   //
   if (in_data_len % AES_BLOCK_SIZE != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   // the amount of cleartext after stripping the padding will actually be less
   // than the input bytes...
   //
   padded_len = in_data_len;

   if (length_only == TRUE) {
      *out_data_len = padded_len;
      return CKR_OK;
   }

   clear = (CK_BYTE *)malloc( padded_len );
   if (!clear){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }
   rc = ckm_aes_cbc_decrypt(tokdata, in_data, in_data_len, clear, &padded_len,
                            ctx->mech.pParameter, key);

   if (rc == CKR_OK) {
      strip_pkcs_padding( clear, padded_len, out_data_len );
      memcpy( out_data, clear, *out_data_len );
   }

   free( clear );
   return rc;
}
//
//
CK_RV
aes_ctr_encrypt( STDLL_TokData_t   *tokdata,
		 SESSION           *sess,
                 CK_BBOOL           length_only,
		 ENCR_DECR_CONTEXT *ctx,
                 CK_BYTE           *in_data,
                 CK_ULONG           in_data_len,
                 CK_BYTE           *out_data,
                 CK_ULONG 	   *out_data_len )
{
   OBJECT *key = NULL;
   CK_RV rc;
   CK_AES_CTR_PARAMS *aesctr = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (in_data_len % AES_BLOCK_SIZE != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
      return CKR_DATA_LEN_RANGE;
   }
   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   if (length_only == TRUE) {
      *out_data_len = in_data_len;
       return CKR_OK;
   }

   if (*out_data_len < in_data_len) {
      *out_data_len = in_data_len;
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   aesctr = (CK_AES_CTR_PARAMS *)ctx->mech.pParameter;

   return ckm_aes_ctr_encrypt(tokdata, in_data, in_data_len, out_data,
			      out_data_len, (CK_BYTE *)aesctr->cb,
			      (CK_ULONG)aesctr->ulCounterBits, key);
}

//
//
CK_RV
aes_ctr_decrypt( STDLL_TokData_t   *tokdata,
		 SESSION           *sess,
                 CK_BBOOL           length_only,
		 ENCR_DECR_CONTEXT *ctx,
                 CK_BYTE           *in_data,
                 CK_ULONG           in_data_len,
                 CK_BYTE           *out_data,
                 CK_ULONG 	   *out_data_len )
{
   OBJECT *key = NULL;
   CK_RV rc;
   CK_AES_CTR_PARAMS *aesctr = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (in_data_len % AES_BLOCK_SIZE != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   if (length_only == TRUE) {
      *out_data_len = in_data_len;
       return CKR_OK;
   }

   if (*out_data_len < in_data_len) {
      *out_data_len = in_data_len;
       TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
       return CKR_BUFFER_TOO_SMALL;
   }

   aesctr = (CK_AES_CTR_PARAMS *)ctx->mech.pParameter;

   return ckm_aes_ctr_decrypt(tokdata, in_data, in_data_len, out_data,
			      out_data_len, (CK_BYTE *)aesctr->cb,
			      (CK_ULONG)aesctr->ulCounterBits, key);
}

//
//
CK_RV
aes_ecb_encrypt_update( STDLL_TokData_t   *tokdata,
			SESSION           *sess,
                        CK_BBOOL           length_only,
                        ENCR_DECR_CONTEXT *ctx,
                        CK_BYTE           *in_data,
                        CK_ULONG           in_data_len,
                        CK_BYTE           *out_data,
                        CK_ULONG          *out_data_len )
{
   AES_CONTEXT  * context   = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * clear     = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad arguments\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (AES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < AES_BLOCK_SIZE) {
      if (length_only == FALSE) {
         memcpy( context->data + context->len, in_data, in_data_len );
         context->len += in_data_len;
      }
      *out_data_len = 0;
      return CKR_OK;
   }
   else {
      // we have at least 1 block
      //
      remain  = (total % AES_BLOCK_SIZE);
      out_len = (total - remain);     // should always be at least 1 block

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      rc = object_mgr_find_in_map_nocache( ctx->key, &key );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      clear = (CK_BYTE *)malloc( out_len );
      if (!clear){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous encryption operation first
      //
      memcpy( clear,                context->data, context->len );
      memcpy( clear + context->len, in_data,       out_len - context->len );

      rc = ckm_aes_ecb_encrypt(tokdata, clear, out_len, out_data, out_data_len,
			       key);
      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // update the context buffer.  we already used the buffer's current
         // contents so we completely overwrite it
         //
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );

         context->len = remain;
      }

      free( clear );
      return rc;
   }
}


//
//
CK_RV
aes_ecb_decrypt_update( STDLL_TokData_t   *tokdata,
			SESSION           *sess,
                        CK_BBOOL           length_only,
                        ENCR_DECR_CONTEXT *ctx,
                        CK_BYTE           *in_data,
                        CK_ULONG           in_data_len,
                        CK_BYTE           *out_data,
                        CK_ULONG          *out_data_len )
{
   AES_CONTEXT  * context   = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * cipher    = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (AES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < AES_BLOCK_SIZE) {
      if (length_only == FALSE) {
         memcpy( context->data + context->len, in_data, in_data_len );
         context->len += in_data_len;
      }

      *out_data_len = 0;
      return CKR_OK;
   }
   else {
      // we have at least 1 block
      //
      remain  = (total % AES_BLOCK_SIZE);
      out_len = total - remain;

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      rc = object_mgr_find_in_map_nocache( ctx->key, &key );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous decryption operation first
      //
      memcpy( cipher,                context->data, context->len );
      memcpy( cipher + context->len, in_data,       out_len - context->len );

      rc = ckm_aes_ecb_decrypt(tokdata, cipher, out_len, out_data,
			       out_data_len, key);
      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // copy the remaining 'new' input data to the context buffer
         //
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }

      free( cipher );
      return rc;
   }
}


//
//
CK_RV
aes_cbc_encrypt_update( STDLL_TokData_t   *tokdata,
			SESSION           *sess,
                        CK_BBOOL           length_only,
                        ENCR_DECR_CONTEXT *ctx,
                        CK_BYTE           *in_data,
                        CK_ULONG           in_data_len,
                        CK_BYTE           *out_data,
                        CK_ULONG          *out_data_len )
{
   AES_CONTEXT  * context   = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * clear     = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;


   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (AES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < AES_BLOCK_SIZE) {
      if (length_only == FALSE) {
         memcpy( context->data + context->len, in_data, in_data_len );
         context->len += in_data_len;
      }

      *out_data_len = 0;
      return CKR_OK;
   }
   else {
      // we have at least 1 block
      //
      remain  = (total % AES_BLOCK_SIZE);
      out_len = total - remain;

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      rc = object_mgr_find_in_map_nocache( ctx->key, &key );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      // these buffers need to be longword aligned
      //
      clear  = (CK_BYTE *)malloc( out_len );
      if (!clear){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous encryption operation first
      //
      memcpy( clear,                context->data, context->len );
      memcpy( clear + context->len, in_data,       out_len - context->len );

      rc = ckm_aes_cbc_encrypt(tokdata, clear, out_len, out_data, out_data_len,
                               ctx->mech.pParameter, key);

      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // the new init_v is the last encrypted data block
         //
         memcpy( ctx->mech.pParameter, out_data + (*out_data_len - AES_BLOCK_SIZE), AES_BLOCK_SIZE );

         // copy the remaining 'new' input data to the context buffer
         //
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }

      free( clear );
      return rc;
   }
}


//
//
CK_RV
aes_cbc_decrypt_update( STDLL_TokData_t   *tokdata,
			SESSION           *sess,
                        CK_BBOOL           length_only,
                        ENCR_DECR_CONTEXT *ctx,
                        CK_BYTE           *in_data,
                        CK_ULONG           in_data_len,
                        CK_BYTE           *out_data,
                        CK_ULONG          *out_data_len )
{
   AES_CONTEXT  * context   = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * cipher    = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;


   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   context = (AES_CONTEXT *)ctx->context;

   total = context->len + in_data_len;

   if (total < AES_BLOCK_SIZE) {
      if (length_only == FALSE) {
         memcpy( context->data + context->len, in_data, in_data_len );
         context->len += in_data_len;
      }

      *out_data_len = 0;
      return CKR_OK;
   }
   else {
      // we have at least 1 block
      //
      remain  = total % AES_BLOCK_SIZE;
      out_len = total - remain;

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      rc = object_mgr_find_in_map_nocache( ctx->key, &key );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      // these buffers need to be longword aligned
      //
      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous decryption operation first
      //
      memcpy( cipher,                context->data, context->len );
      memcpy( cipher + context->len, in_data,       out_len - context->len );

      rc = ckm_aes_cbc_decrypt(tokdata, cipher, out_len, out_data, out_data_len,
                               ctx->mech.pParameter, key);

      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // the new init_v is the last input data block
         //
         memcpy( ctx->mech.pParameter, cipher + (out_len - AES_BLOCK_SIZE), AES_BLOCK_SIZE );

         // copy the remaining 'new' input data to the context buffer
         //
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );

         context->len = remain;
      }

      free( cipher );
      return rc;
   }
}


//
//
CK_RV
aes_cbc_pad_encrypt_update( STDLL_TokData_t   *tokdata,
			    SESSION           *sess,
                            CK_BBOOL           length_only,
                            ENCR_DECR_CONTEXT *ctx,
                            CK_BYTE           *in_data,
                            CK_ULONG           in_data_len,
                            CK_BYTE           *out_data,
                            CK_ULONG          *out_data_len )
{
   AES_CONTEXT  * context   = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * clear     = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;


   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   context = (AES_CONTEXT *)ctx->context;

   total     = (context->len + in_data_len);

   // note, this is subtly different from the other encrypt update routines
   //
   if (total <= AES_BLOCK_SIZE) {
      if (length_only == FALSE) {
         memcpy( context->data + context->len, in_data, in_data_len );
         context->len += in_data_len;
      }

      *out_data_len = 0;
      return CKR_OK;
   }
   else {
      remain  = (total % AES_BLOCK_SIZE);
      out_len = total - remain;  // out_len is a multiple of DES_BLOCK_SIZE

      if (remain == 0) {
         remain     = AES_BLOCK_SIZE;
         out_len -= AES_BLOCK_SIZE;
      }

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      // at this point, we should have:
      //    1) remain != 0
      //    2) out_len != 0
      //
      rc = object_mgr_find_in_map_nocache( ctx->key, &key );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      // these buffers need to be longword aligned
      //
      clear = (CK_BYTE *)malloc( out_len );
      if (!clear){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous encryption operation first
      //
      memcpy( clear,                context->data, context->len );
      memcpy( clear + context->len, in_data,       out_len - context->len );

      //
      // we don't do padding during the update
      //
      rc = ckm_aes_cbc_encrypt(tokdata, clear, out_len, out_data, out_data_len,
                               ctx->mech.pParameter, key);

      if (rc == CKR_OK) {
         // the new init_v is the last encrypted data block
         //
         memcpy( ctx->mech.pParameter, out_data + (*out_data_len - AES_BLOCK_SIZE), AES_BLOCK_SIZE );

         // copy the remaining 'new' input data to the temporary space
         //
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }

      free( clear );
      return rc;
   }
}


//
//
CK_RV
aes_cbc_pad_decrypt_update( STDLL_TokData_t   *tokdata,
			    SESSION           *sess,
                            CK_BBOOL           length_only,
                            ENCR_DECR_CONTEXT *ctx,
                            CK_BYTE           *in_data,
                            CK_ULONG           in_data_len,
                            CK_BYTE           *out_data,
                            CK_ULONG          *out_data_len )
{
   AES_CONTEXT  * context   = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * cipher    = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;


   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   context = (AES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   // note, this is subtly different from the other decrypt update routines
   //
   if (total <= AES_BLOCK_SIZE) {
      if (length_only == FALSE) {
         memcpy( context->data + context->len, in_data, in_data_len );
         context->len += in_data_len;
      }

      *out_data_len = 0;
      return CKR_OK;
   }
   else {
      // we have at least 1 block + 1 byte
      //
      remain  = total % AES_BLOCK_SIZE;
      out_len = total - remain;

      if (remain == 0) {
         remain     = AES_BLOCK_SIZE;
         out_len -= AES_BLOCK_SIZE;
      }

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      // at this point, we should have:
      //    1) remain != 0
      //    2) out_len != 0
      //
      rc = object_mgr_find_in_map_nocache( ctx->key, &key );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      // these buffers need to be longword aligned
      //
      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous decryption operation first
      //
      memcpy( cipher,                context->data, context->len );
      memcpy( cipher + context->len, in_data,       out_len - context->len );

      rc = ckm_aes_cbc_decrypt(tokdata, cipher, out_len, out_data, out_data_len,
                               ctx->mech.pParameter, key);

      if (rc == CKR_OK) {
         // the new init_v is the last input data block
         //
         memcpy( ctx->mech.pParameter, cipher + (out_len - AES_BLOCK_SIZE), AES_BLOCK_SIZE );

         // copy the remaining 'new' input data to the temporary space
         //
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }

      free( cipher );
      return rc;
   }
}
//
//
CK_RV
aes_ctr_encrypt_update( STDLL_TokData_t		*tokdata,
			SESSION                 *sess,
                        CK_BBOOL 		 length_only,
			ENCR_DECR_CONTEXT 	*ctx,
                        CK_BYTE                 *in_data,
                        CK_ULONG 		 in_data_len,
                        CK_BYTE                 *out_data,
			CK_ULONG 		*out_data_len )
{
   AES_CONTEXT  * context   = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * clear     = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;
   CK_AES_CTR_PARAMS *aesctr = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (AES_CONTEXT *)ctx -> context;
   total = (context->len + in_data_len);
   if( total < AES_BLOCK_SIZE){
     if(length_only == FALSE){
        memcpy( context->data + context->len, in_data, in_data_len);
	context->len += in_data_len;
     }
     *out_data_len = 0;
     return CKR_OK;
   }
   else
   {
     // we atleast have 1 block
     remain = (total % AES_BLOCK_SIZE);
     out_len = total -remain;
     if (length_only == TRUE){
	*out_data_len = out_len;
	 return CKR_OK;
     }
     rc = object_mgr_find_in_map_nocache(ctx->key, &key);
     if(rc != CKR_OK){
	TRACE_ERROR("Failed to find specified object.\n");
	return rc;
     }

     //these buffers need to be longword aligned
     clear = (CK_BYTE*) malloc (out_len);
     if (!clear){
	TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
     }
     //copy all the leftover data  from the previous encryption operation first
     memcpy ( clear,		     context->data, context->len);
     memcpy ( clear+context->len, in_data, out_len - context->len);
     aesctr = (CK_AES_CTR_PARAMS *)ctx->mech.pParameter;
     rc = ckm_aes_ctr_encrypt(tokdata, clear, out_len, out_data, out_data_len,
                               (CK_BYTE *)aesctr->cb,
			       (CK_ULONG)aesctr->ulCounterBits, key);
     if (rc == CKR_OK){
	*out_data_len = out_len;
	// copy the remaining 'new' input data to the context buffer
        if (remain != 0)
           memcpy( context->data, in_data + (in_data_len - remain), remain );
	context->len = remain;
      }

      free( clear );
      return rc;
   }
}
//
//
CK_RV
aes_ctr_decrypt_update( STDLL_TokData_t		*tokdata,
			SESSION                 *sess,
                        CK_BBOOL 		 length_only,
			ENCR_DECR_CONTEXT 	*ctx,
                        CK_BYTE                 *in_data,
                        CK_ULONG 		 in_data_len,
                        CK_BYTE                 *out_data,
                        CK_ULONG 		*out_data_len )
{
   AES_CONTEXT  * context   = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * clear     = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;
   CK_AES_CTR_PARAMS *aesctr = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (AES_CONTEXT *)ctx -> context;
   total = (context->len + in_data_len);
   if( total < AES_BLOCK_SIZE){
     if(length_only == FALSE){
       memcpy( context->data + context->len, in_data, in_data_len);
       context->len += in_data_len;
     }
     *out_data_len = 0;
     return CKR_OK;
   }
   else{
     // we atleast have 1 block
     remain = (total % AES_BLOCK_SIZE);
     out_len = total -remain;
     if (length_only == TRUE){
	*out_data_len = out_len;
	return CKR_OK;
     }
     rc = object_mgr_find_in_map_nocache(ctx->key, &key);
     if(rc != CKR_OK){
       TRACE_ERROR("Failed to find specified object.\n");
       return rc;
     }

     //these buffers need to be longword aligned
     clear = (CK_BYTE*) malloc (out_len);
     if (!clear){
	TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
	return CKR_HOST_MEMORY;
     }
     //copy all the leftover data  from the previous encryption operation first
     memcpy ( clear,		     context->data, context->len);
     memcpy ( clear+context->len, in_data, out_len - context->len);
     aesctr = (CK_AES_CTR_PARAMS *)ctx->mech.pParameter;
     rc = ckm_aes_ctr_decrypt(tokdata, clear, out_len, out_data, out_data_len,
                              (CK_BYTE *)aesctr->cb,
			      (CK_ULONG)aesctr->ulCounterBits, key);
     if (rc == CKR_OK){
	*out_data_len = out_len;
	// copy the remaining 'new' input data to the context buffer
        if (remain != 0)
           memcpy( context->data, in_data + (in_data_len - remain), remain );
        context->len = remain;
     }

     free( clear );
     return rc;
     }
}
//
//
CK_RV
aes_ecb_encrypt_final( STDLL_TokData_t   *tokdata,
		       SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   AES_CONTEXT *context   = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // satisfy the compiler
   //
   if (length_only)
      context = NULL;

   context = (AES_CONTEXT *)ctx->context;

   // DES3-ECB does no padding so there had better not be
   // any data in the context buffer.  if there is it means
   // that the overall data length was not a multiple of the blocksize
   //
   if (context->len != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
      return CKR_DATA_LEN_RANGE;
   }
   *out_data_len = 0;
   return CKR_OK;
}


//
//
CK_RV
aes_ecb_decrypt_final( STDLL_TokData_t   *tokdata,
		       SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   AES_CONTEXT *context   = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // satisfy the compiler
   //
   if (length_only)
      context = NULL;

   context = (AES_CONTEXT *)ctx->context;

   // DES3-ECB does no padding so there had better not be
   // any data in the context buffer.  if there is it means
   // that the overall data length was not a multiple of the blocksize
   //
   if (context->len != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   *out_data_len = 0;
   return CKR_OK;
}


//
//
CK_RV
aes_cbc_encrypt_final( STDLL_TokData_t   *tokdata,
		       SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   AES_CONTEXT *context   = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // satisfy the compiler
   //
   if (length_only)
      context = NULL;

   context = (AES_CONTEXT *)ctx->context;

   // DES3-CBC does no padding so there had better not be
   // any data in the context buffer.  if there is it means
   // that the overall data length was not a multiple of the blocksize
   //
   if (context->len != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
      return CKR_DATA_LEN_RANGE;
   }
   *out_data_len = 0;
   return CKR_OK;
}


//
//
CK_RV
aes_cbc_decrypt_final( STDLL_TokData_t   *tokdata,
		       SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   AES_CONTEXT *context   = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // satisfy the compiler
   //
   if (length_only)
      context = NULL;

   context = (AES_CONTEXT *)ctx->context;

   if (context->len != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   *out_data_len = 0;
   return CKR_OK;
}


//
//
CK_RV
aes_cbc_pad_encrypt_final( STDLL_TokData_t   *tokdata,
			   SESSION           *sess,
                           CK_BBOOL           length_only,
                           ENCR_DECR_CONTEXT *ctx,
                           CK_BYTE           *out_data,
                           CK_ULONG          *out_data_len )
{
   AES_CONTEXT    *context   = NULL;
   OBJECT         *key       = NULL;
   CK_BYTE         clear[2*AES_BLOCK_SIZE];
   CK_ULONG        out_len;
   CK_RV           rc;


   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   context = (AES_CONTEXT *)ctx->context;

   // there will never be more than one block in the context buffer
   // so the amount of output is as follows:
   //    if less than 1 block stored, we generate one block of output
   //    if a full block is stored, we generate two blocks of output (one pad block)
   //
   if (context->len == AES_BLOCK_SIZE)
      out_len = 2 * AES_BLOCK_SIZE;
   else
      out_len = AES_BLOCK_SIZE;

   if (length_only == TRUE) {
      *out_data_len = out_len;
      return CKR_OK;
   }
   else {
      memcpy( clear, context->data, context->len );

      add_pkcs_padding( clear + context->len,
                        AES_BLOCK_SIZE,
                        context->len,
                        out_len );

      rc = ckm_aes_cbc_encrypt(tokdata, clear, out_len, out_data, out_data_len,
                               ctx->mech.pParameter, key);

      return rc;
   }
}


//
//
CK_RV
aes_cbc_pad_decrypt_final( STDLL_TokData_t   *tokdata,
			   SESSION           *sess,
                           CK_BBOOL           length_only,
                           ENCR_DECR_CONTEXT *ctx,
                           CK_BYTE           *out_data,
                           CK_ULONG          *out_data_len )
{
   AES_CONTEXT    *context   = NULL;
   OBJECT         *key       = NULL;
   CK_BYTE         clear[AES_BLOCK_SIZE];
   CK_ULONG        out_len;
   CK_RV           rc;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   context = (AES_CONTEXT *)ctx->context;

   // there had better be a full block in the context buffer
   //
   if (context->len != AES_BLOCK_SIZE){
      TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   // we don't know a priori how much data we'll be returning.  we won't
   // know until after we decrypt it and strip the padding.  it's possible
   // that we'll return nothing (the final block might be a padding block).
   //
   out_len = AES_BLOCK_SIZE;  // upper bound on what we'll return

   if (length_only == TRUE) {
      *out_data_len = out_len;
      return CKR_OK;
   }
   else {
      rc = ckm_aes_cbc_decrypt(tokdata, context->data, AES_BLOCK_SIZE, clear,
			       &out_len, ctx->mech.pParameter, key);

      if (rc == CKR_OK) {
         strip_pkcs_padding( clear, out_len, &out_len );

         if (out_len != 0)
            memcpy( out_data, clear, out_len );

         *out_data_len = out_len;
      }

      return rc;
   }
}

//
//
CK_RV
aes_ctr_encrypt_final( STDLL_TokData_t   *tokdata,
		       SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   AES_CONTEXT *context   = NULL;
   CK_AES_CTR_PARAMS *aesctr = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // satisfy the compiler
   //
   if (length_only)
      context = NULL;

   context = (AES_CONTEXT *)ctx->context;

   // DES3-CBC does no padding so there had better not be
   // any data in the context buffer.  if there is it means
   // that the overall data length was not a multiple of the blocksize
   //
   if (context->len != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
      return CKR_DATA_LEN_RANGE;
   }
   aesctr = (CK_AES_CTR_PARAMS *)ctx->mech.pParameter;
   //to check that the counter buffer doesnot overflow
   if ( ((CK_ULONG)aesctr->ulCounterBits) > ((CK_ULONG)aesctr->ulCounterBits+1) )
   {
	TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
	return CKR_DATA_LEN_RANGE;
   }

   *out_data_len = 0;
   return CKR_OK;
}

//
//
CK_RV
aes_ctr_decrypt_final( STDLL_TokData_t   *tokdata,
		       SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   AES_CONTEXT *context   = NULL;
   CK_AES_CTR_PARAMS *aesctr = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // satisfy the compiler
   //
   if (length_only)
      context = NULL;

   context = (AES_CONTEXT *)ctx->context;

   // DES3-CBC does no padding so there had better not be
   // any data in the context buffer.  if there is it means
   // that the overall data length was not a multiple of the blocksize
   //
   if (context->len != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   aesctr = (CK_AES_CTR_PARAMS *)ctx->mech.pParameter;
   //to check that the counter buffer doesnot overflow
   if ( ((CK_ULONG)aesctr->ulCounterBits) > ((CK_ULONG)aesctr->ulCounterBits+1) )
   {
	TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
	return CKR_DATA_LEN_RANGE;
   }
   *out_data_len = 0;
   return CKR_OK;
}

CK_RV
aes_ofb_encrypt( STDLL_TokData_t   * tokdata,
		 SESSION           * sess,
                 CK_BBOOL            length_only,
                 ENCR_DECR_CONTEXT * ctx,
                 CK_BYTE           * in_data,
                 CK_ULONG            in_data_len,
                 CK_BYTE           * out_data,
                 CK_ULONG          * out_data_len)
{
   CK_ULONG           rc;
   OBJECT           * key_obj  = NULL;

   if (!sess || !ctx || !in_data || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len){
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   rc = token_specific.t_aes_ofb(tokdata, in_data, in_data_len, out_data,
				 key_obj, ctx->mech.pParameter, 1);

   if (rc != CKR_OK)
	TRACE_DEVEL("Token specific aes ofb encrypt failed.\n");
   return rc;
}

CK_RV
aes_ofb_encrypt_update( STDLL_TokData_t      * tokdata,
			SESSION              * sess,
                        CK_BBOOL               length_only,
                        ENCR_DECR_CONTEXT    * ctx,
                        CK_BYTE              * in_data,
                        CK_ULONG               in_data_len,
                        CK_BYTE              * out_data,
                        CK_ULONG             * out_data_len)
{
   AES_CONTEXT  * context   = NULL;
   CK_BYTE      * cipher    = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;
   OBJECT       * key_obj  = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (AES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < AES_BLOCK_SIZE) {
      if (length_only == FALSE) {
         memcpy( context->data + context->len, in_data, in_data_len );
         context->len += in_data_len;
      }

      *out_data_len = 0;
      return CKR_OK;
   }
   else {
      // we have at least 1 block
      remain  = (total % AES_BLOCK_SIZE);
      out_len = total - remain;

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      if (*out_data_len < out_len){
         TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
         return CKR_BUFFER_TOO_SMALL;
      }

      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous encryption operation first
      memcpy( cipher,                    context->data, context->len );
      memcpy( cipher + context->len, in_data, out_len - context->len );

      rc = token_specific.t_aes_ofb(tokdata, cipher, out_len, out_data,
				    key_obj, ctx->mech.pParameter, 1);

      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // copy the remaining 'new' input data to the context buffer
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      } else
	    TRACE_DEVEL("Token specific aes ofb encrypt failed.\n");
      free( cipher );
      return rc;
   }
}

CK_RV
aes_ofb_encrypt_final( STDLL_TokData_t   *tokdata,
		       SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   OBJECT      *key_obj  = NULL;
   AES_CONTEXT *context  = NULL;
   CK_RV        rc;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   context = (AES_CONTEXT *)ctx->context;

   // there will never be more than one block in the context buffer
   // so the amount of output is as follows:
   //    if less than 1 block stored, we generate same length of output data
   //    if no data stored, no data can be returned (length zero)

   if (length_only == TRUE) {
      *out_data_len = context->len;
      return CKR_OK;
   }
   else {
      if (context->len == 0) {
         *out_data_len = 0;
         return CKR_OK;
      }

      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
         TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      rc = token_specific.t_aes_ofb(tokdata, context->data, context->len,
				    out_data, key_obj, ctx->mech.pParameter, 1);

      if (rc != CKR_OK)
	 TRACE_DEVEL("Token specific aes ofb encrypt failed.\n");

      *out_data_len = context->len;
      return rc;
   }
}

CK_RV
aes_ofb_decrypt( STDLL_TokData_t   *tokdata,
		 SESSION           * sess,
                 CK_BBOOL            length_only,
                 ENCR_DECR_CONTEXT * ctx,
                 CK_BYTE           * in_data,
                 CK_ULONG            in_data_len,
                 CK_BYTE           * out_data,
                 CK_ULONG          * out_data_len )
{
   CK_ULONG          rc;
   OBJECT           *key_obj  = NULL;

   if (!sess || !ctx || !in_data || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (length_only == TRUE) {
       *out_data_len = in_data_len;
       return CKR_OK;
   }

   if (*out_data_len < in_data_len){
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   rc = token_specific.t_aes_ofb(tokdata, in_data, in_data_len, out_data,
				 key_obj, ctx->mech.pParameter, 0);

   if (rc != CKR_OK)
	TRACE_DEVEL("Token specific aes ofb decrypt failed.\n");
   return rc;
}

CK_RV
aes_ofb_decrypt_update( STDLL_TokData_t      * tokdata,
			SESSION              * sess,
                        CK_BBOOL               length_only,
                        ENCR_DECR_CONTEXT    * ctx,
                        CK_BYTE              * in_data,
                        CK_ULONG               in_data_len,
                        CK_BYTE              * out_data,
                        CK_ULONG             * out_data_len)
{
   AES_CONTEXT  * context  = NULL;
   CK_BYTE      * cipher   = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;
   OBJECT       * key_obj  = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   context = (AES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < AES_BLOCK_SIZE) {
      if (length_only == FALSE) {
         memcpy( context->data + context->len, in_data, in_data_len );
         context->len += in_data_len;
      }

      *out_data_len = 0;
      return CKR_OK;
   }
   else {
      // we have at least 1 block
      remain  = (total % AES_BLOCK_SIZE);
      out_len = total - remain;

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      if (*out_data_len < out_len){
         TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
         return CKR_BUFFER_TOO_SMALL;
      }

      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous decryption operation first
      memcpy( cipher,                    context->data, context->len );
      memcpy( cipher + context->len, in_data, out_len - context->len );

      rc = token_specific.t_aes_ofb(tokdata, cipher, out_len, out_data,
				    key_obj, ctx->mech.pParameter, 0);

      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // copy the remaining 'new' input data to the context buffer
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      } else
	 TRACE_DEVEL("Token specific aes ofb decrypt failed.\n");
      free( cipher );
      return rc;
   }
}

CK_RV
aes_ofb_decrypt_final( STDLL_TokData_t   *tokdata,
		       SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   OBJECT      * key_obj = NULL;
   AES_CONTEXT * context = NULL;
   CK_RV         rc;

   if (!sess || !ctx || !out_data_len){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // satisfy the compiler
   //if (length_only)
   //   context = NULL;

   context = (AES_CONTEXT *)ctx->context;

   // there will never be more than one block in the context buffer
   // so the amount of output is as follows:
   //    if less than 1 block stored, we generate same length of output data
   //    if no data stored, no data can be returned (length zero)

   if (length_only == TRUE) {
      *out_data_len = context->len;
      return CKR_OK;
   }
   else {
      if (context->len == 0) {
         *out_data_len = 0;
         return CKR_OK;
      }

      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      rc = token_specific.t_aes_ofb(tokdata, context->data, context->len,
				    out_data, key_obj, ctx->mech.pParameter, 0);

      if (rc != CKR_OK)
         TRACE_DEVEL("Token specific aes ofb decrypt failed.\n");

      *out_data_len = context->len;
      return rc;
   }
}

CK_RV
aes_cfb_encrypt( STDLL_TokData_t   * tokdata,
		 SESSION           * sess,
                 CK_BBOOL            length_only,
                 ENCR_DECR_CONTEXT * ctx,
                 CK_BYTE           * in_data,
                 CK_ULONG            in_data_len,
                 CK_BYTE           * out_data,
                 CK_ULONG          * out_data_len,
                 CK_ULONG            cfb_len )
{
   CK_ULONG          rc;
   OBJECT           *key_obj = NULL;

   if (!sess || !ctx || !in_data || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len){
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   rc = token_specific.t_aes_cfb(tokdata, in_data, in_data_len, out_data,
				 key_obj, ctx->mech.pParameter, cfb_len, 1);

   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific aes cfb encrypt failed.\n");
   return rc;
}

CK_RV
aes_cfb_encrypt_update( STDLL_TokData_t      * tokdata,
			SESSION              * sess,
                        CK_BBOOL               length_only,
                        ENCR_DECR_CONTEXT    * ctx,
                        CK_BYTE              * in_data,
                        CK_ULONG               in_data_len,
                        CK_BYTE              * out_data,
                        CK_ULONG             * out_data_len,
                        CK_ULONG               cfb_len)
{
   AES_CONTEXT  * context  = NULL;
   CK_BYTE      * cipher   = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;
   OBJECT       * key_obj  = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (AES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < cfb_len) {
      if (length_only == FALSE) {
         memcpy( context->data + context->len, in_data, in_data_len );
         context->len += in_data_len;
      }

      *out_data_len = 0;
      return CKR_OK;
   }
   else {
      // we have at least 1 block
      remain  = (total % cfb_len);
      out_len = total - remain;

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      if (*out_data_len < out_len){
         TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
         return CKR_BUFFER_TOO_SMALL;
      }

      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous encryption operation first
      memcpy( cipher,                    context->data, context->len );
      memcpy( cipher + context->len, in_data, out_len - context->len );

      rc = token_specific.t_aes_cfb(tokdata, cipher, out_len, out_data,
				    key_obj, ctx->mech.pParameter, cfb_len, 1);

      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // copy the remaining 'new' input data to the context buffer
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      } else
         TRACE_DEVEL("Token specific aes cfb encrypt failed.\n");
      free( cipher );
      return rc;
   }
}

CK_RV
aes_cfb_encrypt_final( STDLL_TokData_t   *tokdata,
		       SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len,
                       CK_ULONG           cfb_len)
{
   OBJECT      *key_obj  = NULL;
   AES_CONTEXT *context  = NULL;
   CK_RV        rc;

   if (!sess || !ctx || !out_data_len){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   context = (AES_CONTEXT *)ctx->context;

   // there will never be more than one block in the context buffer
   // so the amount of output is as follows:
   //    if less than 1 block stored, we generate same length of output data
   //    if no data stored, no data can be returned (length zero)

   if (context->len == 0) {
      *out_data_len = 0;
      return CKR_OK;
   }

   if (length_only == TRUE) {
      *out_data_len = context->len;
      return CKR_OK;
   }
   else {
      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      rc = token_specific.t_aes_cfb(tokdata, context->data, context->len,
				    out_data, key_obj, ctx->mech.pParameter,
				    cfb_len, 1);

      if (rc != CKR_OK)
         TRACE_DEVEL("Token specific aes cfb encrypt failed.\n");

      *out_data_len = context->len;
      return rc;
   }
}

CK_RV
aes_cfb_decrypt( STDLL_TokData_t   * tokdata,
		 SESSION           * sess,
                 CK_BBOOL            length_only,
                 ENCR_DECR_CONTEXT * ctx,
                 CK_BYTE           * in_data,
                 CK_ULONG            in_data_len,
                 CK_BYTE           * out_data,
                 CK_ULONG          * out_data_len,
                 CK_ULONG            cfb_len )
{
   CK_ULONG          rc;
   OBJECT           *key_obj = NULL;

   if (!sess || !ctx || !in_data || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len){
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   rc = token_specific.t_aes_cfb(tokdata, in_data, in_data_len, out_data,
				 key_obj, ctx->mech.pParameter, cfb_len, 0);

   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific aes cfb decrypt failed.\n");
   return rc;
}

CK_RV
aes_cfb_decrypt_update( STDLL_TokData_t      * tokdata,
			SESSION              * sess,
                        CK_BBOOL               length_only,
                        ENCR_DECR_CONTEXT    * ctx,
                        CK_BYTE              * in_data,
                        CK_ULONG               in_data_len,
                        CK_BYTE              * out_data,
                        CK_ULONG             * out_data_len,
                        CK_ULONG               cfb_len)
{
   AES_CONTEXT  * context  = NULL;
   CK_BYTE      * cipher   = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;
   OBJECT       * key_obj  = NULL;

   if (!sess || !ctx || !out_data_len) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (AES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < cfb_len) {
      if (length_only == FALSE) {
         memcpy( context->data + context->len, in_data, in_data_len );
         context->len += in_data_len;
      }

      *out_data_len = 0;
      return CKR_OK;
   }
   else {
      // we have at least 1 block
      remain  = (total % cfb_len);
      out_len = total - remain;

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      if (*out_data_len < out_len){
         TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
         return CKR_BUFFER_TOO_SMALL;
      }

      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous decryption operation first
      memcpy( cipher,                    context->data, context->len );
      memcpy( cipher + context->len, in_data, out_len - context->len );

      rc = token_specific.t_aes_cfb(tokdata, cipher, out_len, out_data,
				    key_obj, ctx->mech.pParameter, cfb_len, 0);

      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // copy the remaining 'new' input data to the context buffer
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }
      else
         TRACE_DEVEL("Token specific aes cfb decrypt failed.\n");
      free( cipher );
      return rc;
   }
}

CK_RV
aes_cfb_decrypt_final( STDLL_TokData_t   *tokdata,
		       SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len,
                       CK_ULONG           cfb_len)
{
   OBJECT      *key_obj  = NULL;
   AES_CONTEXT *context  = NULL;
   CK_RV        rc;

   if (!sess || !ctx || !out_data_len){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   context = (AES_CONTEXT *)ctx->context;

   // there will never be more than one block in the context buffer
   // so the amount of output is as follows:
   //    if less than 1 block stored, we generate same length of output data
   //    if no data stored, no data can be returned (length zero)

   if (context->len == 0) {
      *out_data_len = 0;
      return CKR_OK;
   }

   if (length_only == TRUE) {
      *out_data_len = context->len;
      return CKR_OK;
   }
   else {
      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      rc = token_specific.t_aes_cfb(tokdata, context->data, context->len,
				    out_data, key_obj, ctx->mech.pParameter,
				    cfb_len, 0);

      if (rc != CKR_OK)
         TRACE_DEVEL("Token specific aes cfb decrypt failed.\n");

      *out_data_len = context->len;
      return rc;
   }
}


CK_RV
aes_mac_sign( STDLL_TokData_t      * tokdata,
	      SESSION              * sess,
              CK_BBOOL               length_only,
              SIGN_VERIFY_CONTEXT  * ctx,
              CK_BYTE              * in_data,
              CK_ULONG               in_data_len,
              CK_BYTE              * out_data,
              CK_ULONG             * out_data_len)
{
 CK_ULONG         rc;
 OBJECT           * key_obj  = NULL;
 CK_ULONG         mac_len;

   if (!sess || !ctx || !out_data_len){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->mech.pParameter)
      mac_len = *(CK_MAC_GENERAL_PARAMS *)ctx->mech.pParameter;
   else
      mac_len = AES_BLOCK_SIZE / 2;

   if (length_only == TRUE) {
      *out_data_len = mac_len;
      return CKR_OK;
   }

 if ( (in_data_len % AES_BLOCK_SIZE) != 0) {
    rc = aes_mac_sign_update(tokdata, sess, ctx, in_data, in_data_len);
    if (rc != CKR_OK)
       return rc;

    rc = aes_mac_sign_final(tokdata, sess, length_only, ctx, out_data,
			    out_data_len);

    return rc;
 }
 else {

   if (*out_data_len < mac_len) {
      *out_data_len = mac_len;
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   rc = token_specific.t_aes_mac(tokdata, in_data, in_data_len,
				 key_obj,
				 ((AES_DATA_CONTEXT *)ctx->context)->iv);
   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific aes mac failed.\n");

   memcpy(out_data, ((AES_DATA_CONTEXT *)ctx->context)->iv, mac_len);
   *out_data_len = mac_len;

   return rc;
 }
}

CK_RV
aes_mac_sign_update ( STDLL_TokData_t      * tokdata,
		      SESSION              * sess,
                      SIGN_VERIFY_CONTEXT  * ctx,
                      CK_BYTE              * in_data,
                      CK_ULONG               in_data_len )
{
 CK_ULONG         rc;
 OBJECT           * key_obj  = NULL;
 AES_DATA_CONTEXT * context  = NULL;
 CK_BYTE          * cipher   = NULL;
 CK_ULONG         total, remain, out_len;

  if (!sess || !ctx) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
  }

   context = (AES_DATA_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < AES_BLOCK_SIZE) {
      memcpy( context->data + context->len, in_data, in_data_len );
      context->len += in_data_len;
      return CKR_OK;
   }
   else {
      // we have at least 1 block
      remain  = (total % AES_BLOCK_SIZE);
      out_len = total - remain;

      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous signUpdate operation first
      memcpy( cipher,                context->data, context->len );
      memcpy( cipher + context->len, in_data,       out_len - context->len );

      rc = token_specific.t_aes_mac(tokdata, cipher, out_len, key_obj, context->iv);

      if (rc == CKR_OK) {
         // copy the remaining 'new' input data to the context buffer
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      } else
         TRACE_DEVEL("Token specific aes mac failed.\n");

      free( cipher );
      return rc;
   }
}

CK_RV
aes_mac_sign_final( STDLL_TokData_t      * tokdata,
		    SESSION              * sess,
                    CK_BBOOL               length_only,
                    SIGN_VERIFY_CONTEXT  * ctx,
                    CK_BYTE              * out_data,
                    CK_ULONG             * out_data_len)
{
  CK_ULONG           rc = CKR_OK;
  CK_ULONG           mac_len;
  AES_DATA_CONTEXT * context  = NULL;
  OBJECT           * key_obj  = NULL;

   if (!sess || !ctx || !out_data_len){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   context = (AES_DATA_CONTEXT *)ctx->context;

   if (ctx->mech.pParameter)
      mac_len = *(CK_MAC_GENERAL_PARAMS *)ctx->mech.pParameter;
   else
      mac_len = AES_BLOCK_SIZE / 2;

   // there will never be more than one block in the context buffer
   // so the amount of output is as follows:
   //    if less than 1 block stored, we generate one block of output (with padding)
   //    if no data stored, we are done (take the cipher from previous round)

   if (length_only == TRUE) {
      *out_data_len = mac_len;
      return CKR_OK;
   }

   if (context->len > 0) {

      if (*out_data_len < mac_len) {
         *out_data_len = mac_len;
         TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
         return CKR_BUFFER_TOO_SMALL;
      }

      /* padding with '00' in case case we didn't reach block size */
      memset(context->data + context->len, 0x0, AES_BLOCK_SIZE - context->len);

      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      rc = token_specific.t_aes_mac(tokdata, context->data, AES_BLOCK_SIZE,
				    key_obj, context->iv);
      if (rc != CKR_OK) {
         TRACE_DEVEL("Token Specific aes mac failed.\n");
         return rc;
      }
   }
   memcpy(out_data, context->iv, mac_len);
   *out_data_len = mac_len;

   return rc;
}

CK_RV
aes_mac_verify( STDLL_TokData_t      * tokdata,
		SESSION              * sess,
                SIGN_VERIFY_CONTEXT  * ctx,
                CK_BYTE              * in_data,
                CK_ULONG               in_data_len,
                CK_BYTE              * out_data,
                CK_ULONG               out_data_len)
{
 CK_ULONG         rc;
 OBJECT           * key_obj  = NULL;
 CK_ULONG         mac_len;

   if (!sess || !ctx || !in_data || !out_data){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

 if ( (in_data_len % AES_BLOCK_SIZE) != 0) {
    rc = aes_mac_verify_update(tokdata, sess, ctx, in_data, in_data_len);
    if (rc != CKR_OK)
       return rc;

    rc = aes_mac_verify_final(tokdata, sess, ctx, out_data, out_data_len);
    return rc;
 }
 else {

   if (ctx->mech.pParameter)
      mac_len = *(CK_MAC_GENERAL_PARAMS *)ctx->mech.pParameter;
   else
      mac_len = AES_BLOCK_SIZE / 2;

   if (out_data_len != mac_len) {
           TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
           return CKR_SIGNATURE_LEN_RANGE;
   }

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to find specified object.\n");
      return rc;
   }

   rc = token_specific.t_aes_mac(tokdata, in_data, in_data_len,
				 key_obj,
				 ((AES_DATA_CONTEXT *)ctx->context)->iv);

   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific aes mac failed.\n");
   if (memcmp(
       out_data, ((AES_DATA_CONTEXT *)ctx->context)->iv, out_data_len) == 0) {
       return CKR_OK;
   }
   else
       return CKR_SIGNATURE_INVALID;
 }
}


CK_RV
aes_mac_verify_update( STDLL_TokData_t      * tokdata,
		       SESSION              * sess,
                       SIGN_VERIFY_CONTEXT  * ctx,
                       CK_BYTE              * in_data,
                       CK_ULONG               in_data_len)
{
 CK_ULONG         rc;
 OBJECT           * key_obj  = NULL;
 AES_DATA_CONTEXT * context  = NULL;
 CK_BYTE          * cipher   = NULL;
 CK_ULONG         total, remain, out_len;

   if (!sess || !ctx) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   context = (AES_DATA_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < AES_BLOCK_SIZE) {
      memcpy( context->data + context->len, in_data, in_data_len );
      context->len += in_data_len;
      return CKR_OK;
   }
   else {
      // we have at least 1 block
      remain  = (total % AES_BLOCK_SIZE);
      out_len = total - remain;

      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }

      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous signUpdate operation first
      memcpy( cipher,                context->data, context->len );
      memcpy( cipher + context->len, in_data,       out_len - context->len );

      rc = token_specific.t_aes_mac(tokdata, cipher, out_len, key_obj,
				    context->iv);
      if (rc == CKR_OK) {
         // copy the remaining 'new' input data to the context buffer
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }
      else
         TRACE_DEVEL("Token specific aes mac failed.\n");

      free( cipher );
      return rc;
   }
}

CK_RV
aes_mac_verify_final( STDLL_TokData_t      * tokdata,
		      SESSION              * sess,
                      SIGN_VERIFY_CONTEXT  * ctx,
                      CK_BYTE              * signature,
                      CK_ULONG               signature_len)
{
 CK_ULONG           rc;
 OBJECT           * key_obj  = NULL;
 CK_ULONG           mac_len;
 AES_DATA_CONTEXT * context  = NULL;

   if (!sess || !ctx || !signature){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   context = (AES_DATA_CONTEXT *)ctx->context;

   if (ctx->mech.pParameter)
      mac_len = *(CK_MAC_GENERAL_PARAMS *)ctx->mech.pParameter;
   else
      mac_len = AES_BLOCK_SIZE / 2;

   // there will never be more than one block in the context buffer
   // so the amount of output is as follows:
   //    if less than 1 block stored, we generate one block of output (with padding)
   //    if no data stored, we are done (take the cipher from previous round)

   if (context->len > 0) {

      if (signature_len != mac_len) {
           TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
           return CKR_SIGNATURE_LEN_RANGE;
      }

      /* padding with '00' in case case we didn't reach block size */
      memset(context->data + context->len, 0x0, AES_BLOCK_SIZE - context->len);

      rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
      if (rc != CKR_OK){
	 TRACE_ERROR("Failed to find specified object.\n");
         return rc;
      }
      rc = token_specific.t_aes_mac(tokdata, context->data, AES_BLOCK_SIZE,
				    key_obj, context->iv);
      if (rc != CKR_OK) {
         TRACE_DEVEL("Token specific aes mac failed.\n");
         return rc;
      }
   }

   if (memcmp(signature, context->iv, signature_len) == 0) {
      return CKR_OK;
   }
   else
      return CKR_SIGNATURE_INVALID;
}

CK_RV aes_gcm_init(STDLL_TokData_t *tokdata, SESSION *sess,
		   ENCR_DECR_CONTEXT *ctx, CK_MECHANISM *mech,
		   CK_OBJECT_HANDLE key, CK_BYTE direction)
{
	if (token_specific.t_aes_gcm_init == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	return token_specific.t_aes_gcm_init(tokdata, sess, ctx, mech, key,
					     direction);
}

CK_RV aes_gcm_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
		      CK_BBOOL length_only,
		      ENCR_DECR_CONTEXT	*ctx, CK_BYTE *in_data,
		      CK_ULONG in_data_len, CK_BYTE *out_data,
		      CK_ULONG *out_data_len)
{
	CK_RV rc;
	CK_GCM_PARAMS *aesgcm = NULL;
	CK_ULONG tag_data_len;

	if (!sess || !ctx || !in_data || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	aesgcm = (CK_GCM_PARAMS *)ctx->mech.pParameter;
	tag_data_len = (aesgcm->ulTagBits + 7) / 8; /* round to full byte */


	if (length_only == TRUE) {
		*out_data_len = in_data_len + tag_data_len;
		return CKR_OK;
	}

	if (*out_data_len < in_data_len + tag_data_len) {
		*out_data_len = in_data_len + tag_data_len;
		TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
		return CKR_BUFFER_TOO_SMALL;
	}

	if (token_specific.t_aes_gcm == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	rc = token_specific.t_aes_gcm(tokdata, sess, ctx , in_data,
				      in_data_len, out_data, out_data_len, 1);
	if (rc != CKR_OK)
		TRACE_ERROR("Token specific aes gcm encrypt failed:  %02lx\n",
			    rc);
	return rc;

}

CK_RV aes_gcm_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
			     CK_BBOOL length_only,
			     ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
			     CK_ULONG in_data_len, CK_BYTE *out_data,
			     CK_ULONG *out_data_len)
{
	AES_GCM_CONTEXT *context = NULL;
	CK_ULONG total, remain, out_len;
	CK_RV rc;

	if (!sess || !ctx || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	context = (AES_GCM_CONTEXT *)ctx->context;
	total = (context->len + in_data_len);

	if (length_only) {
		if (total < AES_BLOCK_SIZE) {
			*out_data_len = 0;
			return CKR_OK;
		} else {
			remain = (total % AES_BLOCK_SIZE);
			out_len = total - remain;
			*out_data_len = out_len;
			TRACE_DEVEL("Length Only requested (%02ld bytes).\n",
				    *out_data_len);
			return CKR_OK;
		}
	}

	if (token_specific.t_aes_gcm_update == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	rc = token_specific.t_aes_gcm_update(tokdata, sess, ctx, in_data,
					     in_data_len, out_data,
					     out_data_len, 1);
	if (rc != CKR_OK)
		TRACE_ERROR("Token specific AES GCM EncryptUpdate failed: "
			    "%02lx\n", rc);
	return rc;
}

CK_RV aes_gcm_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
			    CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
			    CK_BYTE *out_data, CK_ULONG *out_data_len)
{
	CK_GCM_PARAMS *aesgcm = NULL;
	AES_GCM_CONTEXT	*context = NULL;
	CK_ULONG tag_data_len;
	CK_RV rc = CKR_OK;

	if (!sess || !ctx || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	context = (AES_GCM_CONTEXT *)ctx->context;

	aesgcm = (CK_GCM_PARAMS *)ctx->mech.pParameter;
	tag_data_len = (aesgcm->ulTagBits + 7) / 8; /* round to full byte */

	if (length_only) {
		if (context->len == 0) {
			*out_data_len = tag_data_len;
		} else {
			*out_data_len = context->len + tag_data_len;
		}
		return CKR_OK;
	}

	if (*out_data_len < context->len + tag_data_len) {
		TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
		return CKR_BUFFER_TOO_SMALL;
	}

	if (token_specific.t_aes_gcm_final == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	rc = token_specific.t_aes_gcm_final(tokdata, sess, ctx, out_data,
					    out_data_len, 1);
	if (rc != CKR_OK)
		TRACE_ERROR("Token specific AES GCM EncryptFinal failed: "
			    "%02lx\n", rc);
	return rc;
}

CK_RV aes_gcm_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
		      CK_BBOOL length_only,
		      ENCR_DECR_CONTEXT	*ctx, CK_BYTE *in_data,
		      CK_ULONG in_data_len, CK_BYTE *out_data,
		      CK_ULONG *out_data_len)
{
	CK_GCM_PARAMS *aesgcm = NULL;
	CK_ULONG tag_data_len;
	CK_RV rc;

	if (!sess || !ctx || !in_data || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	aesgcm = (CK_GCM_PARAMS *)ctx->mech.pParameter;
	tag_data_len = (aesgcm->ulTagBits + 7) / 8; /* round to full byte */

	if (length_only == TRUE) {
		*out_data_len = in_data_len - tag_data_len;
		return CKR_OK;
	}

	if (*out_data_len < in_data_len - tag_data_len) {
		*out_data_len = in_data_len - tag_data_len;
		TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
		return CKR_BUFFER_TOO_SMALL;
	}

	if (token_specific.t_aes_gcm == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	rc = token_specific.t_aes_gcm(tokdata, sess, ctx, in_data, in_data_len,
				      out_data, out_data_len, 0);
	if (rc != CKR_OK)
		TRACE_ERROR("Token specific aes gcm decrypt failed.\n");

	return rc;
}

CK_RV aes_gcm_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
			     CK_BBOOL length_only,
			     ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
			     CK_ULONG in_data_len, CK_BYTE *out_data,
			     CK_ULONG *out_data_len)
{
	AES_GCM_CONTEXT	*context = NULL;
	CK_GCM_PARAMS *aesgcm = NULL;
	CK_ULONG total, remain, out_len;
	CK_ULONG tag_data_len;
	CK_RV rc;

	if (!sess || !ctx || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	/* Be aware that this part of incoming data could be the last chunk,
	 * that means it's tag data, not encrypted plaintext.
	 * Hence we'll keep at least tag data size in the context buffer */

	context = (AES_GCM_CONTEXT *)ctx->context;
	total = (context->len + in_data_len);

	aesgcm = (CK_GCM_PARAMS *)ctx->mech.pParameter;
	tag_data_len = (aesgcm->ulTagBits + 7) / 8; /* round to full byte */

	if (length_only) {
		if (total < AES_BLOCK_SIZE + tag_data_len) {
			*out_data_len = 0;
			return CKR_OK;
		} else {
			remain = ((total - tag_data_len) % AES_BLOCK_SIZE)
				   + tag_data_len;
			out_len = total - remain;
			*out_data_len = out_len;
			TRACE_DEVEL("Length Only requested (%02ld bytes).\n",
				    *out_data_len);
			return CKR_OK;
		}
	}

	if (token_specific.t_aes_gcm_update == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	rc = token_specific.t_aes_gcm_update(tokdata, sess, ctx, in_data,
					     in_data_len, out_data,
					     out_data_len, 0 );
	if (rc != CKR_OK)
		TRACE_ERROR("Token specific AES GCM DecryptUpdate "
			    "failed: %02lx\n", rc);
	return rc;
}

CK_RV aes_gcm_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
			    CK_BBOOL length_only,
			    ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
			    CK_ULONG *out_data_len)
{
	AES_GCM_CONTEXT	*context = NULL;
	CK_RV rc = CKR_OK;

	if (!sess || !ctx || !out_data_len) {
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	context = (AES_GCM_CONTEXT *)ctx->context;

	if (length_only) {
		if (context->len == 0) {
			*out_data_len = 0;
		} else {
			*out_data_len = context->len;
		}
		return CKR_OK;
	}

	if (token_specific.t_aes_gcm_final == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	rc = token_specific.t_aes_gcm_final(tokdata, sess, ctx, out_data,
					    out_data_len, 0);
	if (rc != CKR_OK)
		TRACE_ERROR("Token specific AES GCM DecryptFinal failed: "
			    "%02lx\n", rc);

	return rc;
}

//
// mechanisms
//


//
//
CK_RV
ckm_aes_key_gen( STDLL_TokData_t *tokdata, TEMPLATE *tmpl )
{

   CK_ATTRIBUTE     * opaque_attr   = NULL;
   CK_ATTRIBUTE     * value_attr    = NULL;
   CK_ATTRIBUTE     * key_type_attr = NULL;
   CK_ATTRIBUTE     * class_attr    = NULL;
   CK_ATTRIBUTE     * local_attr    = NULL;
   CK_ATTRIBUTE     * val_len_attr  = NULL;
   CK_BYTE          * aes_key       = NULL;
   CK_BYTE            dummy_key[AES_KEY_SIZE_256] = { 0, };
   CK_ULONG           rc;
   CK_ULONG	      key_size;
   CK_ULONG	      token_keysize;
   CK_BBOOL	      found	    = FALSE;


   found = template_attribute_find( tmpl, CKA_VALUE_LEN, &val_len_attr );
   if (found == FALSE)
      return CKR_TEMPLATE_INCONSISTENT;

   key_size = *(CK_ULONG *)val_len_attr->pValue;
   if (key_size != AES_KEY_SIZE_128 &&
       key_size != AES_KEY_SIZE_192 &&
       key_size != AES_KEY_SIZE_256) {
	   return CKR_ATTRIBUTE_VALUE_INVALID;
   }

   if (token_specific.t_aes_key_gen == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
      return CKR_MECHANISM_INVALID;
   }

   if (token_specific.token_keysize)
	token_keysize = token_specific.token_keysize;
   else
	token_keysize = key_size;

   if ((aes_key = (CK_BYTE *)calloc(1,token_keysize)) == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }

   rc = token_specific.t_aes_key_gen(tokdata, aes_key, token_keysize, key_size);

   if (rc != CKR_OK)
      goto err;

   /* For secure-key keys put in CKA_IBM_OPAQUE
    * and put dummy_key in CKA_VALUE.
    */
   if (token_specific.token_keysize) {
        opaque_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + token_keysize);
        if (!opaque_attr) {
           TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
           rc = CKR_HOST_MEMORY;
           goto err;
        }
        opaque_attr->type = CKA_IBM_OPAQUE;
        opaque_attr->ulValueLen = token_keysize;
        opaque_attr->pValue = (CK_BYTE *)opaque_attr + sizeof(CK_ATTRIBUTE);
        memcpy(opaque_attr->pValue, aes_key, token_keysize);
        template_update_attribute(tmpl, opaque_attr);
   }

   value_attr    = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + key_size );
   key_type_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   class_attr    = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS) );
   local_attr    = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );

   if (!value_attr || !key_type_attr || !class_attr || !local_attr) {
      if (value_attr)    free( value_attr );
      if (key_type_attr) free( key_type_attr );
      if (class_attr)    free( class_attr );
      if (local_attr)    free( local_attr );

      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto err;
   }

   value_attr->type         = CKA_VALUE;
   value_attr->ulValueLen   = key_size;
   value_attr->pValue       = (CK_BYTE *)value_attr + sizeof(CK_ATTRIBUTE);
   if (token_specific.token_keysize)
      memcpy( value_attr->pValue, dummy_key, key_size );
   else
      memcpy( value_attr->pValue, aes_key, key_size );
   free(aes_key);

   key_type_attr->type         = CKA_KEY_TYPE;
   key_type_attr->ulValueLen   = sizeof(CK_KEY_TYPE);
   key_type_attr->pValue       = (CK_BYTE *)key_type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)key_type_attr->pValue = CKK_AES;

   class_attr->type         = CKA_CLASS;
   class_attr->ulValueLen   = sizeof(CK_OBJECT_CLASS);
   class_attr->pValue       = (CK_BYTE *)class_attr + sizeof(CK_ATTRIBUTE);
   *(CK_OBJECT_CLASS *)class_attr->pValue = CKO_SECRET_KEY;

   local_attr->type         = CKA_LOCAL;
   local_attr->ulValueLen   = sizeof(CK_BBOOL);
   local_attr->pValue       = (CK_BYTE *)local_attr + sizeof(CK_ATTRIBUTE);
   *(CK_BBOOL *)local_attr->pValue = TRUE;

   template_update_attribute( tmpl, value_attr );
   template_update_attribute( tmpl, key_type_attr );
   template_update_attribute( tmpl, class_attr );
   template_update_attribute( tmpl, local_attr );

   return CKR_OK;

err:
   if (aes_key)
	free(aes_key);
   return rc;
}


//
//
CK_RV
ckm_aes_ecb_encrypt( STDLL_TokData_t * tokdata,
		     CK_BYTE     * in_data,
                     CK_ULONG      in_data_len,
                     CK_BYTE     * out_data,
                     CK_ULONG    * out_data_len,
		     OBJECT	 * key )
{
   CK_ULONG         rc;

   if (!in_data || !out_data || !key){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (*out_data_len < in_data_len){
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   if (token_specific.t_aes_ecb == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
      return CKR_MECHANISM_INVALID;
   }

   rc = token_specific.t_aes_ecb(tokdata, in_data,in_data_len,
				 out_data,out_data_len, key, 1);

   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific aes ecb encrypt failed.\n");
   return rc;
}

//
//
CK_RV
ckm_aes_ecb_decrypt( STDLL_TokData_t * tokdata,
		     CK_BYTE     * in_data,
                     CK_ULONG      in_data_len,
                     CK_BYTE     * out_data,
                     CK_ULONG    * out_data_len,
                     OBJECT      * key )
{
   CK_ULONG         rc;


   if (!in_data || !out_data || !key){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (*out_data_len < in_data_len){
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   if (token_specific.t_aes_ecb == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
      return CKR_MECHANISM_INVALID;
   }

   rc = token_specific.t_aes_ecb(tokdata, in_data,in_data_len,
				 out_data,out_data_len, key, 0);

   if (rc != CKR_OK)
      TRACE_DEVEL("token specific aes ecb decrypt failed.\n");

   return rc;
}


//
//
CK_RV
ckm_aes_cbc_encrypt( STDLL_TokData_t * tokdata,
		     CK_BYTE     * in_data,
                     CK_ULONG      in_data_len,
                     CK_BYTE     * out_data,
                     CK_ULONG    * out_data_len,
                     CK_BYTE     * init_v,
                     OBJECT      * key )
{
   CK_ULONG         rc;

   if (!in_data || !out_data || !init_v || !key){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (*out_data_len < in_data_len){
      *out_data_len = in_data_len;
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   if (token_specific.t_aes_cbc == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
      return CKR_MECHANISM_INVALID;
   }

   rc = token_specific.t_aes_cbc(tokdata, in_data, in_data_len,
				 out_data,out_data_len, key, init_v, 1);

   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific aes cbc encrypt failed.\n");
   return rc;
}


//
//
CK_RV
ckm_aes_cbc_decrypt( STDLL_TokData_t * tokdata,
		     CK_BYTE     * in_data,
                     CK_ULONG      in_data_len,
                     CK_BYTE     * out_data,
                     CK_ULONG    * out_data_len,
                     CK_BYTE     * init_v,
                     OBJECT      * key )
{
   CK_ULONG         rc;

   if (!in_data || !out_data || !init_v || !key ){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (*out_data_len < in_data_len){
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }

   if (token_specific.t_aes_cbc == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
      return CKR_MECHANISM_INVALID;
   }

   rc = token_specific.t_aes_cbc(tokdata, in_data, in_data_len,
				 out_data, out_data_len, key, init_v,0);

   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific aes cbc decrypt failed.\n");
   return rc;
}
//
//
CK_RV
ckm_aes_ctr_encrypt( STDLL_TokData_t * tokdata,
		     CK_BYTE    *in_data,
                     CK_ULONG    in_data_len,
                     CK_BYTE    *out_data,
                     CK_ULONG 	*out_data_len,
                     CK_BYTE    *counterblock,
                     CK_ULONG    counter_width,
                     OBJECT  	*key )
{
   CK_ULONG         rc;
   if (!in_data || !out_data || !counterblock || !key){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (*out_data_len < in_data_len){
      *out_data_len = in_data_len;
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }
   if (counter_width % 8 != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
      return CKR_MECHANISM_PARAM_INVALID;
   }

   if (token_specific.t_aes_ctr == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
      return CKR_MECHANISM_INVALID;
   }

   rc = token_specific.t_aes_ctr(tokdata, in_data, in_data_len,
                                 out_data, out_data_len, key,
				 counterblock, counter_width, 1);
   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific aes ctr encrypt failed.\n");
   return rc;
}
//
//
CK_RV
ckm_aes_ctr_decrypt( STDLL_TokData_t * tokdata,
		     CK_BYTE       *in_data,
                     CK_ULONG       in_data_len,
                     CK_BYTE       *out_data,
                     CK_ULONG      *out_data_len,
                     CK_BYTE       *counterblock,
                     CK_ULONG       counter_width,
		     OBJECT        *key )
{
   CK_ULONG         rc;
   if (!in_data || !out_data || !counterblock || !key){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (*out_data_len < in_data_len){
      *out_data_len = in_data_len;
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }
   if (counter_width % 8 != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
      return CKR_MECHANISM_PARAM_INVALID;
   }

   if (token_specific.t_aes_ctr == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
      return CKR_MECHANISM_INVALID;
   }

   rc = token_specific.t_aes_ctr(tokdata, in_data, in_data_len,
				 out_data,out_data_len, key,
				 counterblock, counter_width, 0);
   if (rc != CKR_OK)
      TRACE_ERROR("Token specific aes ctr decrypt failed.\n");
   return rc;
}
//
//
CK_RV
ckm_aes_wrap_format( STDLL_TokData_t * tokdata,
		     CK_BBOOL    length_only,
                     CK_BYTE  ** data,
                     CK_ULONG  * data_len )
{
   CK_BYTE   * ptr = NULL;
   CK_ULONG    len1, len2;


   len1 = *data_len;

   // if the input key data isn't a multiple of the blocksize,
   // we pad with NULLs to the next blocksize multiple.
   //
   if (len1 % AES_BLOCK_SIZE != 0) {
      len2 = AES_BLOCK_SIZE * ((len1 / AES_BLOCK_SIZE) + 1);

      if (length_only == FALSE) {
         ptr = (CK_BYTE *)realloc(*data, len2);
         if (!ptr){
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
         }
         else
            memset( ptr + len1, 0x0, (len2 - len1) );

         *data     = ptr;
         *data_len = len2;
      }
   }

   return CKR_OK;
}
