
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


// File:  mech_des.c
//
// Mechanisms for DES
//

//#include <windows.h>

#include <string.h>            // for memcmp() et al
#include <stdlib.h>

#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
//#include "args.h"



//
//
CK_RV
pk_des_ecb_encrypt( SESSION           *sess,
                 CK_BBOOL           length_only,
                 ENCR_DECR_CONTEXT *ctx,
                 CK_BYTE           *in_data,
                 CK_ULONG           in_data_len,
                 CK_BYTE           *out_data,
                 CK_ULONG          *out_data_len )
{
   OBJECT       *key       = NULL;
   CK_ATTRIBUTE *attr      = NULL;
   CK_RV         rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   // CKM_DES_ECB requires the input data to be an integral
   // multiple of the block size
   //
   if (in_data_len % DES_BLOCK_SIZE != 0){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_DATA_LEN_RANGE;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   rc = template_attribute_find( key->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len) {
      *out_data_len = in_data_len;
      OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
      return CKR_BUFFER_TOO_SMALL;
   }

   return ckm_des_ecb_encrypt( in_data,  in_data_len,
                               out_data, out_data_len, attr->pValue);
}


//
//
CK_RV
des_ecb_decrypt( SESSION           *sess,
                 CK_BBOOL           length_only,
                 ENCR_DECR_CONTEXT *ctx,
                 CK_BYTE           *in_data,
                 CK_ULONG           in_data_len,
                 CK_BYTE           *out_data,
                 CK_ULONG          *out_data_len)
{
   OBJECT       *key       = NULL;
   CK_ATTRIBUTE *attr      = NULL;
   CK_RV         rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   // CKM_DES_ECB requires the input data to be an integral
   // multiple of the block size
   //
   if (in_data_len % DES_BLOCK_SIZE != 0){
      OCK_LOG_ERR(ERR_ENCRYPTED_DATA_LEN_RANGE);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   rc = template_attribute_find( key->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len) {
      *out_data_len = in_data_len;
      OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
      return CKR_BUFFER_TOO_SMALL;
   }

   return ckm_des_ecb_decrypt( in_data,  in_data_len,
                               out_data, out_data_len, attr->pValue );
}


//
//
CK_RV
pk_des_cbc_encrypt( SESSION           *sess,
                 CK_BBOOL           length_only,
                 ENCR_DECR_CONTEXT *ctx,
                 CK_BYTE           *in_data,
                 CK_ULONG           in_data_len,
                 CK_BYTE           *out_data,
                 CK_ULONG          *out_data_len)
{
   OBJECT       *key       = NULL;
   CK_ATTRIBUTE *attr      = NULL;
   CK_RV         rc;

   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   // CKM_DES_CBC requires the input data to be an integral
   // multiple of the block size
   //
   if (in_data_len % DES_BLOCK_SIZE != 0){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_DATA_LEN_RANGE;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   rc = template_attribute_find( key->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len) {
      *out_data_len = in_data_len;
      OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
      return CKR_BUFFER_TOO_SMALL;
   }

   return ckm_des_cbc_encrypt( in_data,  in_data_len,
                               out_data, out_data_len,
                               ctx->mech.pParameter,
                               attr->pValue );
}


//
//
CK_RV
des_cbc_decrypt( SESSION            *sess,
                 CK_BBOOL            length_only,
                 ENCR_DECR_CONTEXT  *ctx,
                 CK_BYTE            *in_data,
                 CK_ULONG            in_data_len,
                 CK_BYTE            *out_data,
                 CK_ULONG           *out_data_len)
{
   OBJECT    *key       = NULL;
   CK_ATTRIBUTE *attr      = NULL;
   CK_RV      rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   // CKM_DES_CBC requires the input data to be an integral
   // multiple of the block size
   //
   if (in_data_len % DES_BLOCK_SIZE != 0){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   rc = template_attribute_find( key->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *out_data_len = in_data_len;
      return CKR_OK;
   }

   if (*out_data_len < in_data_len) {
      *out_data_len = in_data_len;
      OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
      return CKR_BUFFER_TOO_SMALL;
   }

   return ckm_des_cbc_decrypt( in_data,  in_data_len,
                               out_data, out_data_len,
                               ctx->mech.pParameter,
                               attr->pValue );
}


//
//
CK_RV
des_cbc_pad_encrypt( SESSION           *sess,
                     CK_BBOOL           length_only,
                     ENCR_DECR_CONTEXT *ctx,
                     CK_BYTE           *in_data,
                     CK_ULONG           in_data_len,
                     CK_BYTE           *out_data,
                     CK_ULONG          *out_data_len)
{
   OBJECT       *key       = NULL;
   CK_ATTRIBUTE *attr      = NULL;
   CK_BYTE      *clear     = NULL;
   CK_ULONG      padded_len;
   CK_RV         rc;

   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   // DES-CBC-PAD has no input length requirements
   //

   rc = object_mgr_find_in_map1( ctx->key, &key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   rc = template_attribute_find( key->template, CKA_VALUE, &attr  );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   // compute the output length, accounting for padding
   //
   padded_len = DES_BLOCK_SIZE * (in_data_len / DES_BLOCK_SIZE + 1);

   if (length_only == TRUE) {
      *out_data_len = padded_len;
      return CKR_OK;
   }

   if (*out_data_len < padded_len) {
      *out_data_len = padded_len;
      OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
      return CKR_BUFFER_TOO_SMALL;
   }

   clear = (CK_BYTE *)malloc( padded_len );
   if (!clear){
      OCK_LOG_ERR(ERR_HOST_MEMORY);
      return CKR_HOST_MEMORY;
   }
   memcpy( clear, in_data, in_data_len );

   add_pkcs_padding( clear + in_data_len,
                     DES_BLOCK_SIZE,
                     in_data_len,
                     padded_len );

   rc = ckm_des_cbc_encrypt( clear,    padded_len,
                             out_data, out_data_len,
                             ctx->mech.pParameter,
                             attr->pValue );
   if (rc != CKR_OK) 
      OCK_LOG_ERR(ERR_DES_CBC_ENCRYPT);
   free( clear );
   return rc;
}


//
//
CK_RV
des_cbc_pad_decrypt( SESSION            *sess,
                     CK_BBOOL            length_only,
                     ENCR_DECR_CONTEXT  *ctx,
                     CK_BYTE            *in_data,
                     CK_ULONG            in_data_len,
                     CK_BYTE            *out_data,
                     CK_ULONG           *out_data_len)
{
   OBJECT      *key       = NULL;
   CK_ATTRIBUTE   *attr      = NULL;
   CK_BYTE     *clear     = NULL;
   CK_ULONG     padded_len;
   CK_RV        rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   //
   // no need to validate the input length since we'll pad as necessary
   //

   rc = object_mgr_find_in_map1( ctx->key, &key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   rc = template_attribute_find( key->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   // we're decrypting so even with CBC-PAD, we should have an integral
   // number of block to decrypt
   //
   if (in_data_len % DES_BLOCK_SIZE != 0){
      OCK_LOG_ERR(ERR_ENCRYPTED_DATA_LEN_RANGE);
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
      OCK_LOG_ERR(ERR_HOST_MEMORY);
      return CKR_HOST_MEMORY;
   }
   rc = ckm_des_cbc_decrypt( in_data, in_data_len,
                             clear,   &padded_len,
                             ctx->mech.pParameter,
                             attr->pValue );

   if (rc == CKR_OK) {
      strip_pkcs_padding( clear, padded_len, out_data_len );
      memcpy( out_data, clear, *out_data_len );
   }
   else
      OCK_LOG_ERR(ERR_DES_CBC_DECRYPT);

   free( clear );
   return rc;
}


//
//
CK_RV
des_ecb_encrypt_update( SESSION            *sess,
                        CK_BBOOL            length_only,
                        ENCR_DECR_CONTEXT  *ctx,
                        CK_BYTE            *in_data,
                        CK_ULONG            in_data_len,
                        CK_BYTE            *out_data,
                        CK_ULONG           *out_data_len )
{
   DES_CONTEXT  * context   = NULL;
   CK_ATTRIBUTE * attr      = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * clear     = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;

   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (DES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < DES_BLOCK_SIZE) {
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
      remain  = (total % DES_BLOCK_SIZE);
      out_len = (total - remain);     // should always be at least 1 block

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      rc = object_mgr_find_in_map1( ctx->key, &key );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
         return rc;
      }
      rc = template_attribute_find( key->template, CKA_VALUE, &attr );
      if (rc == FALSE){
         OCK_LOG_ERR(ERR_FUNCTION_FAILED);
         return CKR_FUNCTION_FAILED;
      }
      clear  = (CK_BYTE *)malloc( out_len );
      if (!clear){
         OCK_LOG_ERR(ERR_HOST_MEMORY);
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous encryption operation first
      //
      memcpy( clear,                context->data, context->len );
      memcpy( clear + context->len, in_data,       out_len - context->len );

      rc = ckm_des_ecb_encrypt( clear,    out_len,
                                out_data, out_data_len, attr->pValue );
      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // update the context buffer.  we already used the buffer's current
         // contents so we completely overwrite it
         //
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }
      else
         OCK_LOG_ERR(ERR_DES_ECB_ENCRYPT);
      free( clear );
      return rc;
   }

   OCK_LOG_ERR(ERR_FUNCTION_FAILED);
   return CKR_FUNCTION_FAILED;  // shouldn't reach this
}


//
//
CK_RV
des_ecb_decrypt_update( SESSION           *sess,
                        CK_BBOOL           length_only,
                        ENCR_DECR_CONTEXT *ctx,
                        CK_BYTE           *in_data,
                        CK_ULONG           in_data_len,
                        CK_BYTE           *out_data,
                        CK_ULONG          *out_data_len )
{
   DES_CONTEXT  * context   = NULL;
   CK_ATTRIBUTE * attr      = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * cipher    = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;

   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (DES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < DES_BLOCK_SIZE) {
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
      remain  = (total % DES_BLOCK_SIZE);
      out_len = total - remain;

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      rc = object_mgr_find_in_map1( ctx->key, &key );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
         return rc;
      }
      rc = template_attribute_find( key->template, CKA_VALUE, &attr );
      if (rc == FALSE){
         OCK_LOG_ERR(ERR_FUNCTION_FAILED);
         return CKR_FUNCTION_FAILED;
      }

      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         OCK_LOG_ERR(ERR_HOST_MEMORY);
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous decryption operation first
      //
      memcpy( cipher,                context->data, context->len );
      memcpy( cipher + context->len, in_data,       out_len - context->len );

      rc = ckm_des_ecb_decrypt( cipher,   out_len,
                                out_data, out_data_len, attr->pValue );
      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // copy the remaining 'new' input data to the context buffer
         //
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }
      else
         OCK_LOG_ERR(ERR_DES_ECB_DECRYPT);
      free( cipher );
      return rc;
   }

   OCK_LOG_ERR(ERR_FUNCTION_FAILED);
   return CKR_FUNCTION_FAILED;  // shouldn't reach this
}


//
//
CK_RV
des_cbc_encrypt_update( SESSION           *sess,
                        CK_BBOOL           length_only,
                        ENCR_DECR_CONTEXT *ctx,
                        CK_BYTE           *in_data,
                        CK_ULONG           in_data_len,
                        CK_BYTE           *out_data,
                        CK_ULONG          *out_data_len )
{
   DES_CONTEXT  * context   = NULL;
   CK_ATTRIBUTE * attr      = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * clear     = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (DES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   if (total < DES_BLOCK_SIZE) {
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
      remain  = (total % DES_BLOCK_SIZE);
      out_len = total - remain;

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      rc = object_mgr_find_in_map1( ctx->key, &key );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
         return rc;
      }
      rc = template_attribute_find( key->template, CKA_VALUE, &attr );
      if (rc == FALSE){
         OCK_LOG_ERR(ERR_FUNCTION_FAILED);
         return CKR_FUNCTION_FAILED;
      }

      // these buffers need to be longword aligned
      //
      clear  = (CK_BYTE *)malloc( out_len );
      if (!clear){
         OCK_LOG_ERR(ERR_HOST_MEMORY);
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous encryption operation first
      //
      memcpy( clear,                context->data, context->len );
      memcpy( clear + context->len, in_data,       out_len - context->len );

      rc = ckm_des_cbc_encrypt( clear,    out_len,
                                out_data, out_data_len,
                                ctx->mech.pParameter,
                                attr->pValue );
      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // the new init_v is the last encrypted data block
         //
         memcpy( ctx->mech.pParameter, out_data + (*out_data_len - DES_BLOCK_SIZE), DES_BLOCK_SIZE );

         // copy the remaining 'new' input data to the context buffer
         //
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }

      else
         OCK_LOG_ERR(ERR_DES_CBC_ENCRYPT);
      free( clear );
      return rc;
   }

   OCK_LOG_ERR(ERR_FUNCTION_FAILED);
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
des_cbc_decrypt_update( SESSION           *sess,
                        CK_BBOOL           length_only,
                        ENCR_DECR_CONTEXT *ctx,
                        CK_BYTE           *in_data,
                        CK_ULONG           in_data_len,
                        CK_BYTE           *out_data,
                        CK_ULONG          *out_data_len )
{
   DES_CONTEXT  * context   = NULL;
   CK_ATTRIBUTE * attr      = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * cipher    = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (DES_CONTEXT *)ctx->context;

   total = context->len + in_data_len;

   if (total < DES_BLOCK_SIZE) {
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
      remain  = total % DES_BLOCK_SIZE;
      out_len = total - remain;

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      rc = object_mgr_find_in_map1( ctx->key, &key );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
         return rc;
      }
      rc = template_attribute_find( key->template, CKA_VALUE, &attr );
      if (rc == FALSE){
         OCK_LOG_ERR(ERR_FUNCTION_FAILED);
         return CKR_FUNCTION_FAILED;
      }

      // these buffers need to be longword aligned
      //
      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         OCK_LOG_ERR(ERR_HOST_MEMORY);
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous decryption operation first
      //
      memcpy( cipher,                context->data, context->len );
      memcpy( cipher + context->len, in_data,       out_len - context->len );

      rc = ckm_des_cbc_decrypt( cipher,   out_len,
                                out_data, out_data_len,
                                ctx->mech.pParameter,
                                attr->pValue );
      if (rc == CKR_OK) {
         *out_data_len = out_len;

         // the new init_v is the last decrypted data block
         //
         memcpy( ctx->mech.pParameter, cipher + (out_len - DES_BLOCK_SIZE), DES_BLOCK_SIZE );

         // copy the remaining 'new' input data to the context buffer
         //
         if (remain != 0)
            memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }

      else
         OCK_LOG_ERR(ERR_DES_CBC_DECRYPT);
      free( cipher );
      return rc;
   }

   OCK_LOG_ERR(ERR_FUNCTION_FAILED);
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
des_cbc_pad_encrypt_update( SESSION           *sess,
                            CK_BBOOL           length_only,
                            ENCR_DECR_CONTEXT *ctx,
                            CK_BYTE           *in_data,
                            CK_ULONG           in_data_len,
                            CK_BYTE           *out_data,
                            CK_ULONG          *out_data_len )
{
   DES_CONTEXT  * context   = NULL;
   CK_ATTRIBUTE * attr      = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * clear     = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (DES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   // note, this is subtly different from the other encrypt update routines
   //
   if (total <= DES_BLOCK_SIZE) {
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
      remain  = total % DES_BLOCK_SIZE;
      out_len = total - remain;

      if (remain == 0) {
         remain     = DES_BLOCK_SIZE;
         out_len -= DES_BLOCK_SIZE;
      }

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      // at this point, we should have:
      //    1) remain != 0
      //    2) out_len != 0
      //
      rc = object_mgr_find_in_map1( ctx->key, &key );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
         return rc;
      }
      rc = template_attribute_find( key->template, CKA_VALUE, &attr );
      if (rc == FALSE){
         OCK_LOG_ERR(ERR_FUNCTION_FAILED);
         return CKR_FUNCTION_FAILED;
      }

      // these buffers need to be longword aligned
      //
      clear = (CK_BYTE *)malloc( out_len );
      if (!clear){
         OCK_LOG_ERR(ERR_HOST_MEMORY);
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous encryption operation first
      //
      memcpy( clear,                context->data, context->len );
      memcpy( clear + context->len, in_data,       out_len - context->len );

      //
      // we don't do padding during the update
      //
      rc = ckm_des_cbc_encrypt( clear,    out_len,
                                out_data, out_data_len,
                                ctx->mech.pParameter,
                                attr->pValue );

      if (rc == CKR_OK) {
         // the new init_v is the last encrypted data block
         //
         memcpy( ctx->mech.pParameter, out_data + (*out_data_len - DES_BLOCK_SIZE), DES_BLOCK_SIZE );

         // copy the remaining 'new' input data to the temporary space
         //
         memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }


      else
         OCK_LOG_ERR(ERR_DES_CBC_ENCRYPT);
      free( clear );
      return rc;
   }
}


//
//
CK_RV
des_cbc_pad_decrypt_update( SESSION           *sess,
                            CK_BBOOL           length_only,
                            ENCR_DECR_CONTEXT *ctx,
                            CK_BYTE           *in_data,
                            CK_ULONG           in_data_len,
                            CK_BYTE           *out_data,
                            CK_ULONG          *out_data_len )
{
   DES_CONTEXT  * context   = NULL;
   CK_ATTRIBUTE * attr      = NULL;
   OBJECT       * key       = NULL;
   CK_BYTE      * cipher    = NULL;
   CK_ULONG       total, remain, out_len;
   CK_RV          rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (DES_CONTEXT *)ctx->context;

   total = (context->len + in_data_len);

   // note, this is subtly different from the other decrypt update routines
   //
   if (total <= DES_BLOCK_SIZE) {
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
      remain  = total % DES_BLOCK_SIZE;
      out_len = total - remain;

      if (remain == 0) {
         remain     = DES_BLOCK_SIZE;
         out_len -= DES_BLOCK_SIZE;
      }

      if (length_only == TRUE) {
         *out_data_len = out_len;
         return CKR_OK;
      }

      // at this point, we should have:
      //    1) remain != 0
      //    2) out_len != 0
      //
      rc = object_mgr_find_in_map1( ctx->key, &key );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
         return rc;
      }
      rc = template_attribute_find( key->template, CKA_VALUE, &attr );
      if (rc == FALSE){
         OCK_LOG_ERR(ERR_FUNCTION_FAILED);
         return CKR_FUNCTION_FAILED;
      }

      // these buffers need to be longword aligned
      //
      cipher = (CK_BYTE *)malloc( out_len );
      if (!cipher){
         OCK_LOG_ERR(ERR_HOST_MEMORY);
         return CKR_HOST_MEMORY;
      }
      // copy any data left over from the previous decryption operation first
      //
      memcpy( cipher,                context->data, context->len );
      memcpy( cipher + context->len, in_data,       out_len - context->len );

      rc = ckm_des_cbc_decrypt( cipher,  out_len,
                                out_data, out_data_len,
                                ctx->mech.pParameter,
                                attr->pValue );

      if (rc == CKR_OK) {
         // the new init_v is the last decrypted data block
         //
         memcpy( ctx->mech.pParameter, cipher + (out_len - DES_BLOCK_SIZE), DES_BLOCK_SIZE );

         // copy the remaining 'new' input data to the temporary space
         //
         memcpy( context->data, in_data + (in_data_len - remain), remain );
         context->len = remain;
      }
      
      else
         OCK_LOG_ERR(ERR_DES_CBC_DECRYPT);
      free( cipher );
      return rc;
   }

   OCK_LOG_ERR(ERR_FUNCTION_FAILED);
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
des_ecb_encrypt_final( SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   DES_CONTEXT *context   = NULL;

   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   // satisfy the compiler
   //
   if (length_only)
      context = NULL;

   context = (DES_CONTEXT *)ctx->context;

   // DES-ECB does no padding so there had better not be
   // any data in the context buffer.  if there is it means
   // that the overall data length was not a multiple of the blocksize
   //
   if (context->len != 0){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_DATA_LEN_RANGE;
   }
   *out_data_len = 0;
   return CKR_OK;
}


//
//
CK_RV
des_ecb_decrypt_final( SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   DES_CONTEXT *context   = NULL;

   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED; 
   }
   // satisfy the compiler
   //
   if (length_only)
      context = NULL;

   context = (DES_CONTEXT *)ctx->context;

   // DES-ECB does no padding so there had better not be
   // any data in the context buffer.  if there is it means
   // that the overall data length was not a multiple of the blocksize
   //
   if (context->len != 0){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_DATA_LEN_RANGE;
   }
   *out_data_len = 0;
   return CKR_OK;
}


//
//
CK_RV
des_cbc_encrypt_final( SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   DES_CONTEXT *context   = NULL;

   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   // satisfy the compiler
   //
   if (length_only)
      context = NULL;

   context = (DES_CONTEXT *)ctx->context;

   // DES-CBC does no padding so there had better not be
   // any data in the context buffer.  if there is it means
   // that the overall data length was not a multiple of the blocksize
   //
   if (context->len != 0){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_DATA_LEN_RANGE;
   }
   *out_data_len = 0;
   return CKR_OK;
}


//
//
CK_RV
des_cbc_decrypt_final( SESSION           *sess,
                       CK_BBOOL           length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE           *out_data,
                       CK_ULONG          *out_data_len )
{
   DES_CONTEXT *context   = NULL;

   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   // satisfy the compiler
   //
   if (length_only)
      context = NULL;

   context = (DES_CONTEXT *)ctx->context;

   // DES-CBC does no padding so there had better not be
   // any data in the context buffer.  if there is it means
   // that the overall data length was not a multiple of the blocksize
   //
   if (context->len != 0){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_DATA_LEN_RANGE;
   }
   *out_data_len = 0; 
   return CKR_OK;
}


//
//
CK_RV
des_cbc_pad_encrypt_final( SESSION           *sess,
                           CK_BBOOL           length_only,
                           ENCR_DECR_CONTEXT *ctx,
                           CK_BYTE           *out_data,
                           CK_ULONG          *out_data_len )
{
   DES_CONTEXT    *context   = NULL;
   OBJECT         *key       = NULL;
   CK_ATTRIBUTE   *attr      = NULL;
   CK_BYTE         clear[2 * DES_BLOCK_SIZE];
   CK_ULONG        out_len;
   CK_RV           rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   rc = object_mgr_find_in_map1( ctx->key, &key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   rc = template_attribute_find( key->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (DES_CONTEXT *)ctx->context;

   // there will never be more than one block in the context buffer
   // so the amount of output is as follows:
   //    if less than 1 block stored, we generate one block of output
   //    if a full block is stored, we generate two blocks of output (one pad block)
   //
   if (context->len == DES_BLOCK_SIZE)
      out_len = 2 * DES_BLOCK_SIZE;
   else
      out_len = DES_BLOCK_SIZE;

   if (length_only == TRUE) {
      *out_data_len = out_len;
      return CKR_OK;
   }
   else {
      memcpy( clear, context->data, context->len );

      add_pkcs_padding( clear + context->len,
                        DES_BLOCK_SIZE,
                        context->len,
                        out_len );

      rc = ckm_des_cbc_encrypt( clear,    out_len,
                                out_data, out_data_len,
                                ctx->mech.pParameter,
                                attr->pValue );
      if (rc != CKR_OK) 
         OCK_LOG_ERR(ERR_DES_CBC_ENCRYPT);
      return rc;
   }
}


//
//
CK_RV
des_cbc_pad_decrypt_final( SESSION           *sess,
                           CK_BBOOL           length_only,
                           ENCR_DECR_CONTEXT *ctx,
                           CK_BYTE           *out_data,
                           CK_ULONG          *out_data_len )
{
   DES_CONTEXT  *context   = NULL;
   OBJECT       *key       = NULL;
   CK_ATTRIBUTE *attr      = NULL;
   CK_BYTE       clear[DES_BLOCK_SIZE];
   CK_BYTE       cipher[DES_BLOCK_SIZE];
   CK_ULONG      out_len;
   CK_RV         rc;

   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   rc = template_attribute_find( key->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (DES_CONTEXT *)ctx->context;

   // there had better be a full block in the context buffer
   //
   if (context->len != DES_BLOCK_SIZE){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   // we don't know a priori how much data we'll be returning.  we won't
   // know until after we decrypt it and strip the padding.  it's possible
   // that we'll return nothing (the final block might be a padding block).
   //
   out_len = DES_BLOCK_SIZE;  // upper bound on what we'll return

   if (length_only == TRUE) {
      *out_data_len = out_len;
      return CKR_OK;
   }
   else {
      memcpy( cipher, context->data, DES_BLOCK_SIZE );

      rc = ckm_des_cbc_decrypt( cipher, DES_BLOCK_SIZE,
                                clear,  &out_len,
                                ctx->mech.pParameter,
                                attr->pValue );
      if (rc == CKR_OK) {
         strip_pkcs_padding( clear, DES_BLOCK_SIZE, &out_len );

         if (out_len != 0)
            memcpy( out_data, clear, out_len );

         *out_data_len = out_len;
      }
      else
         OCK_LOG_ERR(ERR_DES_CBC_DECRYPT);

      return rc;
   }
}


//
// mechanisms
//


//
//
CK_RV
ckm_des_key_gen( TEMPLATE *tmpl )
{

   CK_ATTRIBUTE     * value_attr    = NULL;
   CK_ATTRIBUTE     * key_type_attr = NULL;
   CK_ATTRIBUTE     * class_attr    = NULL;
   CK_ATTRIBUTE     * local_attr    = NULL;
   CK_BYTE            des_key[DES_KEY_SIZE];
   CK_ULONG           req_len, repl_len, expected_repl_len;
   CK_ULONG           rc;
   // Checking for a weak key is redundant in that the token
   // specific keygen may already do this
   // If the key generated is NOT a clear key, then this 
   // needs to be re-worked.
   // probably by deciding if the key is being created as a private or
   // public token object.  Only token objects are encrypted
   // The size is passed in to allow the same token specific code to
   // do both DES and TDES
   do {
      rc = token_specific.t_des_key_gen(des_key,DES_KEY_SIZE);
   } while (des_check_weak_key(des_key) != FALSE  && rc != CKR_OK);
   if (rc != CKR_OK)
      goto done;

   value_attr    = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + DES_KEY_SIZE );
   key_type_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   class_attr    = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS) );
   local_attr    = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );

   if (!value_attr || !key_type_attr || !class_attr || !local_attr) {
      if (value_attr)    free( value_attr );
      if (key_type_attr) free( key_type_attr );
      if (class_attr)    free( class_attr );
      if (local_attr)    free( local_attr );

      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   value_attr->type         = CKA_VALUE;
   value_attr->ulValueLen   = DES_KEY_SIZE;
   value_attr->pValue       = (CK_BYTE *)value_attr + sizeof(CK_ATTRIBUTE);
   memcpy( value_attr->pValue, des_key, DES_KEY_SIZE );

   key_type_attr->type         = CKA_KEY_TYPE;
   key_type_attr->ulValueLen   = sizeof(CK_KEY_TYPE);
   key_type_attr->pValue       = (CK_BYTE *)key_type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)key_type_attr->pValue = CKK_DES;

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

//   return CKR_OK;

done:
   return rc;
}

#if !(NOCDMF)

//
//
CK_RV
ckm_cdmf_key_gen( TEMPLATE *tmpl )
{
   CK_ATTRIBUTE     * value_attr    = NULL;
   CK_ATTRIBUTE     * key_type_attr = NULL;
   CK_ATTRIBUTE     * class_attr    = NULL;
   CK_ATTRIBUTE     * local_attr    = NULL;
   CK_BYTE            cdmf_key[DES_KEY_SIZE];
   CK_ULONG           repl_len, expected_repl_len;
   CK_ULONG           rc;

   repl_len = expected_repl_len = DES_KEY_SIZE;

   rc = communicate( PK_CDMF_KEYGEN,
                     NULL,       0,
                     cdmf_key,  &repl_len,
                     NULL,       0,
                     NULL,       0 );

   if (rc == CKR_OK) {
      if (repl_len != expected_repl_len)
         return CKR_GENERAL_ERROR;
   }

   value_attr    = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + DES_KEY_SIZE );
   key_type_attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE) );
   class_attr    = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS) );
   local_attr    = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL) );

   if (!value_attr || !key_type_attr || !class_attr || !local_attr) {
      if (value_attr)    free( value_attr );
      if (key_type_attr) free( key_type_attr );
      if (class_attr)    free( class_attr );
      if (local_attr)    free( local_attr );

      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }


   value_attr->type         = CKA_VALUE;
   value_attr->ulValueLen   = DES_KEY_SIZE;
   value_attr->pValue       = (CK_BYTE *)value_attr + sizeof(CK_ATTRIBUTE);
   memcpy( value_attr->pValue, cdmf_key, DES_KEY_SIZE );

   key_type_attr->type         = CKA_KEY_TYPE;
   key_type_attr->ulValueLen   = sizeof(CK_KEY_TYPE);
   key_type_attr->pValue       = (CK_BYTE *)key_type_attr + sizeof(CK_ATTRIBUTE);
   *(CK_KEY_TYPE *)key_type_attr->pValue = CKK_CDMF;

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
}

#endif

//
//
CK_RV
ckm_des_ecb_encrypt( CK_BYTE   * in_data,
                     CK_ULONG    in_data_len,
                     CK_BYTE   * out_data,
                     CK_ULONG  * out_data_len,
                     CK_BYTE   * key_value )
{
   CK_ULONG       req_len, repl_len, expected_repl_len;
   CK_ULONG       rc;


   if (!in_data || !out_data || !key_value){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (*out_data_len < in_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   rc = token_specific.t_des_ecb(in_data,in_data_len,out_data,out_data_len,key_value,1);//  token specifics return CKR_ errors ... 

   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_DES_ECB_TOK_SPEC);
   return rc;
}


//
//
CK_RV
ckm_des_ecb_decrypt( CK_BYTE   * in_data,
                     CK_ULONG    in_data_len,
                     CK_BYTE   * out_data,
                     CK_ULONG  * out_data_len,
                     CK_BYTE   * key_value )
{
   CK_ULONG         req_len, repl_len, expected_repl_len;
   CK_ULONG         rc;



   if (!in_data || !out_data || !key_value){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (*out_data_len < in_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   rc = token_specific.t_des_ecb(in_data,in_data_len,out_data,
         out_data_len,key_value,0);  // last parm is the encrypt flag
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_DES_ECB_TOK_SPEC);
   return rc;
}


//
//
CK_RV
ckm_des_cbc_encrypt( CK_BYTE   * in_data,
                     CK_ULONG    in_data_len,
                     CK_BYTE   * out_data,
                     CK_ULONG  * out_data_len,
                     CK_BYTE   * init_v,
                     CK_BYTE   * key_value )
{
   CK_ULONG         req_len, repl_len, expected_repl_len;
   CK_ULONG         rc;


   if (!in_data || !out_data || !init_v || !key_value){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (*out_data_len < in_data_len){
#if 0
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
#else
      *out_data_len = in_data_len;
      OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
      return CKR_BUFFER_TOO_SMALL;
#endif
   }
   rc = token_specific.t_des_cbc(in_data,in_data_len,out_data,
         out_data_len,key_value,init_v,1);  // last parm is the encrypt flag

   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_DES_CBC_TOK_SPEC);
   return rc;
}


//
//
CK_RV
ckm_des_cbc_decrypt( CK_BYTE   * in_data,
                     CK_ULONG    in_data_len,
                     CK_BYTE   * out_data,
                     CK_ULONG  * out_data_len,
                     CK_BYTE   * init_v,
                     CK_BYTE   * key_value )
{
   CK_ULONG         req_len, repl_len, expected_repl_len;
   CK_ULONG         rc;


   if (!in_data || !out_data || !init_v || !key_value){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (*out_data_len < in_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   rc = token_specific.t_des_cbc(in_data,in_data_len,out_data,
         out_data_len,key_value,init_v,0);  // last parm is the encrypt flag

   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_DES_CBC_TOK_SPEC);
   return rc;
}


// we're preparing to wrap a key using DES.  need to make sure the
// data length is a integral multiple of the DES block size.
//
// PKCS #11 specifies that the padding shall be in the form of NULL
// bytes appended to the data
//
// this routine works with either DES and 3DES as the wrapping mechanism
//
CK_RV
ckm_des_wrap_format( CK_BBOOL    length_only,
                     CK_BYTE  ** data,
                     CK_ULONG  * data_len )
{
   CK_BYTE   * ptr = NULL;
   CK_ULONG    len1, len2;


   len1 = *data_len;

   // if the input key data isn't a multiple of the blocksize,
   // we pad with NULLs to the next blocksize multiple.
   //
   if (len1 % DES_BLOCK_SIZE != 0) {
      len2 = DES_BLOCK_SIZE * ((len1 / DES_BLOCK_SIZE) + 1);

      if (length_only == FALSE) {
         ptr = (CK_BYTE *)realloc(*data, len2);
         if (!ptr){
            OCK_LOG_ERR(ERR_HOST_MEMORY);
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
