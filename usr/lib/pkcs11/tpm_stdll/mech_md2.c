
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


//

#include <pthread.h>
#include <string.h>            // for memcmp() et al
#include <stdlib.h>


#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
//#include "args.h"


// Permutation of 0..255 constructed from the digits of pi. It gives a
// "random" nonlinear byte substitution operation.
//
static CK_BYTE S[256] = {
   41,  46,  67, 201, 162, 216, 124,   1,  61,  54,  84, 161, 236, 240,   6,
   19,  98, 167,   5, 243, 192, 199, 115, 140, 152, 147,  43, 217, 188,
   76, 130, 202,  30, 155,  87,  60, 253, 212, 224,  22, 103,  66, 111,  24,
  138,  23, 229,  18, 190,  78, 196, 214, 218, 158, 222,  73, 160, 251,
  245, 142, 187,  47, 238, 122, 169, 104, 121, 145,  21, 178,   7,  63,
  148, 194,  16, 137,  11,  34,  95,  33, 128, 127,  93, 154,  90, 144,  50,
   39,  53,  62, 204, 231, 191, 247, 151,   3, 255,  25,  48, 179,  72, 165,
  181, 209, 215,  94, 146,  42, 172,  86, 170, 198,  79, 184,  56, 210,
  150, 164, 125, 182, 118, 252, 107, 226, 156, 116,   4, 241,  69, 157,
  112,  89, 100, 113, 135,  32, 134,  91, 207, 101, 230,  45, 168,   2,  27,
   96,  37, 173, 174, 176, 185, 246,  28,  70,  97, 105,  52,  64, 126,  15,
   85,  71, 163,  35, 221,  81, 175,  58, 195,  92, 249, 206, 186, 197,
  234,  38,  44,  83,  13, 110, 133,  40, 132,   9, 211, 223, 205, 244,  65,
  129,  77,  82, 106, 220,  55, 200, 108, 193, 171, 250,  36, 225, 123,
    8,  12, 189, 177,  74, 120, 136, 149, 139, 227,  99, 232, 109, 233,
  203, 213, 254,  59,   0,  29,  57, 242, 239, 183,  14, 102,  88, 208, 228,
  166, 119, 114, 248, 235, 117,  75,  10,  49,  68,  80, 180, 143, 237,
   31,  26, 219, 153, 141,  51, 159,  17, 131,  20
};

static CK_BYTE *padding[] = {
  (CK_BYTE *)"",
  (CK_BYTE *)"\x01",
  (CK_BYTE *)"\x02\x02",
  (CK_BYTE *)"\x03\x03\x03",
  (CK_BYTE *)"\x04\x04\x04\x04",
  (CK_BYTE *)"\x05\x05\x05\x05\x05",
  (CK_BYTE *)"\x06\x06\x06\x06\x06\x06",
  (CK_BYTE *)"\x07\x07\x07\x07\x07\x07\x07",
  (CK_BYTE *)"\x08\x08\x08\x08\x08\x08\x08\x08",
  (CK_BYTE *)"\x09\x09\x09\x09\x09\x09\x09\x09\x09",
  (CK_BYTE *)"\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a\x0a",
  (CK_BYTE *)"\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b",
  (CK_BYTE *)"\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c\x0c",
  (CK_BYTE *)"\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d\x0d",
  (CK_BYTE *)"\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e\x0e",
  (CK_BYTE *)"\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f\x0f",
  (CK_BYTE *)"\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10\x10"
};



//
//
CK_RV
md2_hash( SESSION         * sess,
          CK_BBOOL          length_only,
          DIGEST_CONTEXT  * ctx,
          CK_BYTE         * in_data,
          CK_ULONG          in_data_len,
          CK_BYTE         * out_data,
          CK_ULONG        * out_data_len )
{
   CK_RV     rc;


   if (!sess || !ctx || !out_data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (length_only == TRUE) {
      *out_data_len = MD2_HASH_SIZE;
      return CKR_OK;
   }

   rc = md2_hash_update( sess, ctx, in_data, in_data_len );
   if (rc != CKR_OK){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   return md2_hash_final( sess,      FALSE,
                          ctx,
                          out_data,  out_data_len );
}


//
//
CK_RV
md2_hash_update( SESSION         * sess,
                 DIGEST_CONTEXT  * ctx,
                 CK_BYTE         * in_data,
                 CK_ULONG          in_data_len )
{
   if (!sess || !ctx || !in_data){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   return ckm_md2_update( (MD2_CONTEXT *)ctx->context,
                          in_data, in_data_len );
}


//
//
CK_RV
md2_hash_final( SESSION         * sess,
                CK_BYTE           length_only,
                DIGEST_CONTEXT  * ctx,
                CK_BYTE         * out_data,
                CK_ULONG        * out_data_len )
{
   CK_RV      rc;

   if (!sess || !ctx || !out_data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *out_data_len = MD2_HASH_SIZE;
      return CKR_OK;
   }

   rc = ckm_md2_final( (MD2_CONTEXT *)ctx->context,
                       out_data, MD2_HASH_SIZE );

   if (rc == CKR_OK) {
      *out_data_len = MD2_HASH_SIZE;
      return rc;
   }

   return rc;
}


// this routine gets called for two mechanisms actually:
//    CKM_MD2_HMAC
//    CKM_MD2_HMAC_GENERAL
//
CK_RV
md2_hmac_sign( SESSION              * sess,
               CK_BBOOL               length_only,
               SIGN_VERIFY_CONTEXT  * ctx,
               CK_BYTE              * in_data,
               CK_ULONG               in_data_len,
               CK_BYTE              * out_data,
               CK_ULONG             * out_data_len )
{
   OBJECT          * key_obj = NULL;
   CK_ATTRIBUTE       * attr    = NULL;
   CK_BYTE           hash[MD2_HASH_SIZE];
   DIGEST_CONTEXT    digest_ctx;
   CK_MECHANISM      digest_mech;
   CK_BYTE           k_ipad[MD2_BLOCK_SIZE];
   CK_BYTE           k_opad[MD2_BLOCK_SIZE];
   CK_ULONG          key_bytes, hash_len, hmac_len;
   CK_ULONG          i;
   CK_RV             rc;


   if (!sess || !ctx || !out_data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->mech.mechanism == CKM_MD2_HMAC_GENERAL) {
      hmac_len = *(CK_ULONG *)ctx->mech.pParameter;

      if (hmac_len == 0)
      {
         *out_data_len = 0;
         return CKR_OK;
      }
   }
   else
      hmac_len = MD2_HASH_SIZE;


   if (length_only == TRUE) {
      *out_data_len = hmac_len;
      return CKR_OK;
   }

   memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );

   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   rc = template_attribute_find( key_obj->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      key_bytes = attr->ulValueLen;


   // build (K XOR ipad), (K XOR opad)
   //
   if (key_bytes > MD2_BLOCK_SIZE)
   {
      digest_mech.mechanism      = CKM_MD2;
      digest_mech.ulParameterLen = 0;
      digest_mech.pParameter     = NULL;

      rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
      if (rc != CKR_OK){
         st_err_log(123, __FILE__, __LINE__);
         return rc;
      }
      hash_len = sizeof(hash);
      rc = digest_mgr_digest( sess, FALSE, &digest_ctx,
                              attr->pValue, attr->ulValueLen,
                              hash,  &hash_len );
      if (rc != CKR_OK){
         st_err_log(124, __FILE__, __LINE__);
         return rc;
      }
      digest_mgr_cleanup( &digest_ctx );
      memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );

      for (i = 0; i < hash_len; i++)
      {
         k_ipad[i] = hash[i] ^ 0x36;
         k_opad[i] = hash[i] ^ 0x5C;
      }

      memset( &k_ipad[i], 0x36, MD2_BLOCK_SIZE - i);
      memset( &k_opad[i], 0x5C, MD2_BLOCK_SIZE - i);
   }
   else
   {
      CK_BYTE *key = (CK_BYTE *)attr + sizeof(CK_ATTRIBUTE);

      for (i = 0; i < key_bytes; i++)
      {
         k_ipad[i] = key[i] ^ 0x36;
         k_opad[i] = key[i] ^ 0x5C;
      }

      memset( &k_ipad[i], 0x36, MD2_BLOCK_SIZE - key_bytes );
      memset( &k_opad[i], 0x5C, MD2_BLOCK_SIZE - key_bytes );
   }

   digest_mech.mechanism      = CKM_MD2;
   digest_mech.ulParameterLen = 0;
   digest_mech.pParameter     = NULL;


   // inner hash
   //
   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK){
      st_err_log(123, __FILE__, __LINE__);
      return rc;
   }
   rc = digest_mgr_digest_update( sess, &digest_ctx, k_ipad, MD2_BLOCK_SIZE );
   if (rc != CKR_OK){
      st_err_log(125, __FILE__, __LINE__);
      return rc;
   }
   rc = digest_mgr_digest_update( sess, &digest_ctx, in_data, in_data_len );
   if (rc != CKR_OK){
      st_err_log(123, __FILE__, __LINE__);
      return rc;
   }
   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, FALSE, &digest_ctx, hash, &hash_len );
   if (rc != CKR_OK){
      st_err_log(126, __FILE__, __LINE__);
      return rc;
   }
   digest_mgr_cleanup( &digest_ctx );
   memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );


   // outer hash
   //
   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK){
      st_err_log(123, __FILE__, __LINE__);
      return rc;
   }
   rc = digest_mgr_digest_update( sess, &digest_ctx, k_opad, MD2_BLOCK_SIZE );
   if (rc != CKR_OK){
      st_err_log(123, __FILE__, __LINE__);
      return rc;
   }
   rc = digest_mgr_digest_update( sess, &digest_ctx, hash, hash_len );
   if (rc != CKR_OK){
      st_err_log(123, __FILE__, __LINE__);
      return rc;
   }
   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, FALSE, &digest_ctx, hash, &hash_len );
   if (rc != CKR_OK){
      st_err_log(126, __FILE__, __LINE__);
      return rc;
   }
   memcpy( out_data, hash, hmac_len );
   *out_data_len = hmac_len;

   return CKR_OK;
}


//
//
CK_RV
md2_hmac_verify( SESSION              * sess,
                 SIGN_VERIFY_CONTEXT  * ctx,
                 CK_BYTE              * in_data,
                 CK_ULONG               in_data_len,
                 CK_BYTE              * signature,
                 CK_ULONG               sig_len )
{
   CK_BYTE              hmac[MD2_HASH_SIZE];
   SIGN_VERIFY_CONTEXT  hmac_ctx;
   CK_ULONG             hmac_len, len;
   CK_RV                rc;

   if (!sess || !ctx || !in_data || !signature){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->mech.mechanism == CKM_MD2_HMAC_GENERAL)
      hmac_len = *(CK_ULONG *)ctx->mech.pParameter;
   else
      hmac_len = MD2_HASH_SIZE;

   memset( &hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT) );

   rc = sign_mgr_init( sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      st_err_log(127, __FILE__, __LINE__);
      return rc;
   }
   len = sizeof(hmac);
   rc = sign_mgr_sign( sess, FALSE, &hmac_ctx,
                       in_data, in_data_len,
                       hmac,   &len );
   if (rc != CKR_OK){
      st_err_log(128, __FILE__, __LINE__);
      return rc;
   }
   if ((len != hmac_len) || (len != sig_len)){
      st_err_log(46, __FILE__, __LINE__);
      return CKR_SIGNATURE_LEN_RANGE;
   }
   if (memcmp(hmac, signature, hmac_len) != 0){
      st_err_log(47, __FILE__, __LINE__);
      return CKR_SIGNATURE_INVALID;
   }
   return CKR_OK;
}


//
// CKM routines
//


// MD2 block update operation. Continues an MD2 message-digest
//   operation, processing another message block, and updating the
//   context.
//
CK_RV
ckm_md2_update( MD2_CONTEXT  * context,
                CK_BYTE      * input,
                CK_ULONG       inputLen )
{
   CK_ULONG i, index, partLen;

   // Update number of bytes mod 16
   //
   index = context->count;
   context->count = (index + inputLen) & 0xf;

   partLen = 16 - index;

   // Process any complete 16-byte blocks
   //
   if (inputLen >= partLen)
   {
      memcpy( (CK_BYTE *)&context->buffer[index], (CK_BYTE *)input, partLen );
      ckm_md2_transform( context->state, context->checksum, context->buffer );

      for (i = partLen; i + 15 < inputLen; i += 16)
         ckm_md2_transform( context->state, context->checksum, &input[i] );

      index = 0;
   }
   else
      i = 0;

   // Buffer remaining input
   //
   memcpy( (CK_BYTE *)&context->buffer[index], (CK_BYTE *)&input[i], inputLen-i );

   return CKR_OK;
}


// MD2 finalization. Ends an MD2 message-digest operation, writing the
//   message digest and zeroizing the context.
//
CK_RV
ckm_md2_final( MD2_CONTEXT  * context,
               CK_BYTE      * out_data,
               CK_ULONG       out_data_len )
{
   CK_ULONG index, padLen;

   if (!context || !out_data || (out_data_len < MD2_HASH_SIZE)){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // Pad input to 16-byte multiple (1 - 16 pad bytes)
   //
   index = context->count;
   padLen = 16 - index;
   ckm_md2_update( context, padding[padLen], padLen );

   // Add checksum
   //
   ckm_md2_update( context, context->checksum, 16 );

   // Store state in digest
   //
   memcpy( (CK_BYTE *)out_data, (CK_BYTE *)context->state, 16 );

   return CKR_OK;
}


// MD2 basic transformation. Transforms state and updates checksum
//   based on block.
//
void
ckm_md2_transform( CK_BYTE  * state,
                   CK_BYTE  * checksum,
                   CK_BYTE  * block )
{
   CK_ULONG i, j, t;
   CK_BYTE  x[48];

   // Form encryption block from state, block, state ^ block.
   //
   memcpy( (CK_BYTE *)x,    (CK_BYTE *)state, 16 );
   memcpy( (CK_BYTE *)x+16, (CK_BYTE *)block, 16 );

   for (i = 0; i < 16; i++)
      x[i+32] = state[i] ^ block[i];

   // Encrypt block (18 rounds).
   //
   t = 0;
   for (i = 0; i < 18; i++) {
      for (j = 0; j < 48; j++)
         t = x[j] ^= S[t];
      t = (t + i) & 0xff;
   }

   // Save new state
   //
   memcpy( (CK_BYTE *)state, (CK_BYTE *)x, 16 );

   // Update checksum.
   //
   t = checksum[15];
   for (i = 0; i < 16; i++)
      t = checksum[i] ^= S[block[i] ^ t];

}

