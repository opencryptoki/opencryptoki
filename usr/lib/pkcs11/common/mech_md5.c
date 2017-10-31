/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <pthread.h>
#include <string.h>            // for memcmp() et al
#include <stdlib.h>

#include "pkcs11types.h"
#include "pkcs32.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"


// forward declaration
//
void ckm_md5_transform ();

static CK_BYTE PADDING[64] = {
  0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};



//
//
CK_RV
md5_hash( STDLL_TokData_t * tokdata,
	  SESSION         * sess,
          CK_BBOOL          length_only,
          DIGEST_CONTEXT  * ctx,
          CK_BYTE         * in_data,
          CK_ULONG          in_data_len,
          CK_BYTE         * out_data,
          CK_ULONG        * out_data_len )
{
   CK_RV     rc;


   if (!sess || !ctx || !out_data_len){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (length_only == TRUE) {
      *out_data_len = MD5_HASH_SIZE;
      return CKR_OK;
   }

   rc = md5_hash_update( tokdata, sess, ctx, in_data, in_data_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("md5_hash_update failed\n");
      return rc;
   }
   return md5_hash_final( tokdata, sess, FALSE, ctx, out_data,  out_data_len );
}


//
//
CK_RV
md5_hash_update( STDLL_TokData_t * tokdata,
		 SESSION         * sess,
                 DIGEST_CONTEXT  * ctx,
                 CK_BYTE         * in_data,
                 CK_ULONG          in_data_len )
{
   if (!sess || !ctx || !in_data){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   return ckm_md5_update( tokdata, (MD5_CONTEXT *)ctx->context,
                          in_data, in_data_len );
}


//
//
CK_RV
md5_hash_final( STDLL_TokData_t * tokdata,
		SESSION         * sess,
                CK_BYTE           length_only,
                DIGEST_CONTEXT  * ctx,
                CK_BYTE         * out_data,
                CK_ULONG        * out_data_len )
{
   CK_RV      rc;


   if (!sess || !ctx || !out_data_len){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *out_data_len = MD5_HASH_SIZE;
      return CKR_OK;
   }

   rc = ckm_md5_final( tokdata, (MD5_CONTEXT *)ctx->context,
                       out_data, MD5_HASH_SIZE );

   if (rc == CKR_OK) {
      *out_data_len = MD5_HASH_SIZE;
      return rc;
   }

   return rc;
}


// this routine gets called for two mechanisms actually:
//    CKM_MD5_HMAC
//    CKM_MD5_HMAC_GENERAL
//
CK_RV
md5_hmac_sign( STDLL_TokData_t      * tokdata,
	       SESSION              * sess,
               CK_BBOOL               length_only,
               SIGN_VERIFY_CONTEXT  * ctx,
               CK_BYTE              * in_data,
               CK_ULONG               in_data_len,
               CK_BYTE              * out_data,
               CK_ULONG             * out_data_len )
{
   OBJECT          * key_obj = NULL;
   CK_ATTRIBUTE    * attr    = NULL;
   CK_BYTE           hash[MD5_HASH_SIZE];
   DIGEST_CONTEXT    digest_ctx;
   CK_MECHANISM      digest_mech;
   CK_BYTE           k_ipad[MD5_BLOCK_SIZE];
   CK_BYTE           k_opad[MD5_BLOCK_SIZE];
   CK_ULONG          key_bytes, hash_len, hmac_len;
   CK_ULONG          i;
   CK_RV             rc;


   if (!sess || !ctx || !out_data_len){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->mech.mechanism == CKM_MD5_HMAC_GENERAL) {
      hmac_len = *(CK_ULONG *)ctx->mech.pParameter;

      if (hmac_len == 0) {
         *out_data_len = 0;
         return CKR_OK;
      }
   }
   else
      hmac_len = MD5_HASH_SIZE;


   if (length_only == TRUE) {
      *out_data_len = hmac_len;
      return CKR_OK;
   }

   memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );

   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
   if (rc != CKR_OK)
      return rc;

   rc = template_attribute_find( key_obj->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      TRACE_ERROR("Could not find CKA_VALUE in the template\n");
      return CKR_FUNCTION_FAILED;
   }
   else
      key_bytes = attr->ulValueLen;


   // build (K XOR ipad), (K XOR opad)
   //
   if (key_bytes > MD5_BLOCK_SIZE) {
      digest_mech.mechanism      = CKM_MD5;
      digest_mech.ulParameterLen = 0;
      digest_mech.pParameter     = NULL;

      rc = digest_mgr_init( tokdata, sess, &digest_ctx, &digest_mech );
      if (rc != CKR_OK)
      {
         return rc;
      }

      hash_len = sizeof(hash);
      rc = digest_mgr_digest( tokdata, sess, FALSE, &digest_ctx,
                              attr->pValue, attr->ulValueLen,
                              hash,  &hash_len );
      if (rc != CKR_OK) {
         return rc;
      }

      memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );

      for (i=0; i < hash_len; i++) {
         k_ipad[i] = hash[i] ^ 0x36;
         k_opad[i] = hash[i] ^ 0x5C;
      }

      memset( &k_ipad[i], 0x36, MD5_BLOCK_SIZE - i);
      memset( &k_opad[i], 0x5C, MD5_BLOCK_SIZE - i);
   }
   else {
      CK_BYTE *key = attr->pValue;

      for (i=0; i < key_bytes; i++) {
         k_ipad[i] = key[i] ^ 0x36;
         k_opad[i] = key[i] ^ 0x5C;
      }

      memset( &k_ipad[i], 0x36, MD5_BLOCK_SIZE - key_bytes );
      memset( &k_opad[i], 0x5C, MD5_BLOCK_SIZE - key_bytes );
   }

   digest_mech.mechanism      = CKM_MD5;
   digest_mech.ulParameterLen = 0;
   digest_mech.pParameter     = NULL;


   // inner hash
   //
   rc = digest_mgr_init( tokdata, sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK)
   {
      TRACE_DEVEL("Digest Mgr Init failed.\n");
      return rc;
   }

   rc = digest_mgr_digest_update( tokdata, sess, &digest_ctx, k_ipad,
				  MD5_BLOCK_SIZE );
   if (rc != CKR_OK)
   {
      TRACE_DEVEL("Digest Mgr Update failed.\n");
      return rc;
   }

   rc = digest_mgr_digest_update( tokdata, sess, &digest_ctx, in_data,
				  in_data_len );
   if (rc != CKR_OK)
   {
      TRACE_DEVEL("Digest Mgr Update failed.\n");
      return rc;
   }

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( tokdata, sess, FALSE, &digest_ctx, hash,
				 &hash_len );
   if (rc != CKR_OK)
   {
      TRACE_DEVEL("Digest Mgr Final failed.\n");
      return rc;
   }

   memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );


   // outer hash
   //
   rc = digest_mgr_init( tokdata, sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK)
   {
      TRACE_DEVEL("Digest Mgr Init failed.\n");
      return rc;
   }

   rc = digest_mgr_digest_update( tokdata, sess, &digest_ctx, k_opad,
				  MD5_BLOCK_SIZE );
   if (rc != CKR_OK)
   {
      TRACE_DEVEL("Digest Mgr Update failed.\n");
      return rc;
   }

   rc = digest_mgr_digest_update( tokdata, sess, &digest_ctx, hash, hash_len );
   if (rc != CKR_OK)
   {
      TRACE_DEVEL("Digest Mgr Update failed.\n");
      return rc;
   }

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( tokdata, sess, FALSE, &digest_ctx, hash,
				 &hash_len );
   if (rc != CKR_OK)
   {
      TRACE_DEVEL("Digest Mgr Final failed.\n");
      return rc;
   }

   memcpy( out_data, hash, hmac_len );
   *out_data_len = hmac_len;

   return CKR_OK;
}


//
//
CK_RV
md5_hmac_verify( STDLL_TokData_t      * tokdata,
		 SESSION              * sess,
                 SIGN_VERIFY_CONTEXT  * ctx,
                 CK_BYTE              * in_data,
                 CK_ULONG               in_data_len,
                 CK_BYTE              * signature,
                 CK_ULONG               sig_len )
{
   CK_BYTE              hmac[MD5_HASH_SIZE];
   SIGN_VERIFY_CONTEXT  hmac_ctx;
   CK_ULONG             hmac_len, len;
   CK_RV                rc;

   if (!sess || !ctx || !in_data || !signature){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->mech.mechanism == CKM_MD5_HMAC_GENERAL)
      hmac_len = *(CK_ULONG *)ctx->mech.pParameter;
   else
      hmac_len = MD5_HASH_SIZE;

   memset( &hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT) );

   rc = sign_mgr_init( tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key );
   if (rc != CKR_OK) {
      sign_mgr_cleanup( &hmac_ctx );
      return rc;
   }

   len = sizeof(hmac);
   rc = sign_mgr_sign( tokdata, sess, FALSE, &hmac_ctx,
                       in_data, in_data_len,
                       hmac,   &len );
   if (rc != CKR_OK) {
      sign_mgr_cleanup( &hmac_ctx );
      return rc;
   }

   if ((len != hmac_len) || (len != sig_len)){
      TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
      return CKR_SIGNATURE_LEN_RANGE;
   }
   if (memcmp(hmac, signature, hmac_len) != 0){
      TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
      rc = CKR_SIGNATURE_INVALID;
   }
   sign_mgr_cleanup( &hmac_ctx );
   return rc;
}


//
// CKM routines
//


void
ckm_md5_init( STDLL_TokData_t *tokdata, MD5_CONTEXT *context )
{
  context->i[0] = context->i[1] = 0;

  // Load magic initialization constants.
  //
  context->buf[0] = (CK_ULONG)0x67452301;
  context->buf[1] = (CK_ULONG)0xefcdab89;
  context->buf[2] = (CK_ULONG)0x98badcfe;
  context->buf[3] = (CK_ULONG)0x10325476;
}


//
//
CK_RV
ckm_md5_update( STDLL_TokData_t * tokdata,
		MD5_CONTEXT  * context,
                CK_BYTE      * in_data,
                CK_ULONG       in_data_len )
{
  CK_ULONG in[16];
  int      mdi;
  CK_ULONG i, ii;

  // compute number of bytes mod 64
  //
  mdi = (int)((context->i[0] >> 3) & 0x3F);

  // update number of bits
  //
  if ((context->i[0] + (in_data_len << 3)) < context->i[0])
    context->i[1]++;

  context->i[0] += (in_data_len << 3);
  context->i[1] += (in_data_len >> 29);

  while (in_data_len--) {
    // add new character to buffer, increment mdi
    //
    context->in[mdi++] = *in_data++;

    // transform if necessary
    //
    if (mdi == 0x40) {
      for (i = 0, ii = 0; i < 16; i++, ii += 4)
        in[i] = (((CK_ULONG)context->in[ii+3]) << 24) |
                (((CK_ULONG)context->in[ii+2]) << 16) |
                (((CK_ULONG)context->in[ii+1]) << 8) |
                 ((CK_ULONG)context->in[ii]);
      ckm_md5_transform (tokdata, context->buf, in);
      mdi = 0;
    }
  }

  return CKR_OK;
}


//
//
CK_RV
ckm_md5_final( STDLL_TokData_t *tokdata,
	       MD5_CONTEXT *context,
               CK_BYTE     *out_data,
               CK_ULONG     out_data_len )
{
  CK_ULONG  in[16];
  int       mdi;
  CK_ULONG  i, ii;
  CK_ULONG  padLen;

   if (!out_data) {
	TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
	return CKR_FUNCTION_FAILED;
   }

   if (out_data_len < MD5_HASH_SIZE) {
      TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
      return CKR_BUFFER_TOO_SMALL;
   }
  // save number of bits
  //
  in[14] = context->i[0];
  in[15] = context->i[1];

  // compute number of bytes mod 64
  //
  mdi = (int)((context->i[0] >> 3) & 0x3F);

  // pad out to 56 mod 64
  //
  padLen = (mdi < 56) ? (56 - mdi) : (120 - mdi);
  ckm_md5_update( tokdata, context, PADDING, padLen );

  // append length in bits and transform
  //
  for (i = 0, ii = 0; i < 14; i++, ii += 4)
    in[i] = (((CK_ULONG)context->in[ii+3]) << 24) |
            (((CK_ULONG)context->in[ii+2]) << 16) |
            (((CK_ULONG)context->in[ii+1]) << 8) |
            ((CK_ULONG)context->in[ii]);
  ckm_md5_transform (tokdata, context->buf, in);

  // store buffer in digest
  //
  for (i = 0, ii = 0; i < 4; i++, ii += 4) {
    context->digest[ii  ] = (CK_BYTE) (context->buf[i]        & 0xFF);
    context->digest[ii+1] = (CK_BYTE)((context->buf[i] >>  8) & 0xFF);
    context->digest[ii+2] = (CK_BYTE)((context->buf[i] >> 16) & 0xFF);
    context->digest[ii+3] = (CK_BYTE)((context->buf[i] >> 24) & 0xFF);
  }

  memcpy( out_data, context->digest, MD5_HASH_SIZE );

  return CKR_OK;
}
// Stuff stolen from CCA (saf_md5.c)
/******************************************************************************/
/* Rotate a word (32 bits) left by a specified number of bits.  The 32-bit    */
/* number invalue is circularly rotated left by num_bits bit positions.  The  */
/* result is returned as the function result.                                 */
/*----------------------------------------------------------------------------*/
#define rotate_left(Data, bit_cnt)              \
        (Data = ( (Data << bit_cnt) |           \
                  (Data >> (32 - bit_cnt)) ) )

/******************************************************************************/
/* Implement the MD5 algorithm's "F" function.  This function performs a      */
/* transform on three input words, designated x, y, and z, producing a        */
/* single word output value.  The transform is:                               */
/*                                                                            */
/*    output = ( x AND y ) OR ( (NOT x) AND z )                               */
/*----------------------------------------------------------------------------*/
#define F( x, y, z) ( ( x & y ) | ( (~x) & z) )

/******************************************************************************/
/* Implement the MD5 algorithm's "G" function.  This function performs a      */
/* transform on three input words, designated x, y, and z, producing a        */
/* single word output value.  The transform is:                               */
/*                                                                            */
/*    output = ( x AND z ) OR ( y AND (NOT z) )                               */
/*----------------------------------------------------------------------------*/
#define G( x, y, z) ( ( x & z ) | ( y & (~z) ) )

/******************************************************************************/
/* Implement the MD5 algorithm's "H" function.  This function performs a      */
/* transform on three input words, designated x, y, and z, producing a        */
/* single word output value.  The transform is:                               */
/*                                                                            */
/*    output = ( x XOR y XOR z )                                              */
/*----------------------------------------------------------------------------*/
#define H( x, y, z) ( x ^ y ^ z )

/******************************************************************************/
/* Implement the MD5 algorithm's "I" function.  This function performs a      */
/* transform on three input words, designated x, y, and z, producing a        */
/* single word output value.  The transform is:                               */
/*                                                                            */
/*    output = ( y XOR ( x OR (NOT z) ) )                                     */
/*----------------------------------------------------------------------------*/
#define I( x, y, z) ( y ^ ( x | (~z) ) )

/*----------------------------------------------------------------------------*/
/*                                                                            */
/* Define the MD5 "T[]" table.  This table consists of 64 4-byte (MD5_word)   */
/* entries, designated T[1] through T[64].  (Note that this is different from */
/* the way C will index them, from 0..63 instead of 1..64.)                   */
/*                                                                            */
/* If the index of each entry is i, where i ranges from 1 to 64, then the     */
/* value in each entry is given by the following formula.                     */
/*                                                                            */
/*      T[i] = int ( 4294967296 * abs ( sin ( i ) ) )                         */
/*                                                                            */
/* where the function sin(i) expects i in radians, and the function int(x)    */
/* returns the integer portion of a floating point number x.                  */
/*                                                                            */
/*----------------------------------------------------------------------------*/

static CK_ULONG T[64] = { 0xD76AA478,  /* T[01]                               */
                   0xE8C7B756,         /* T[02]                               */
                   0x242070DB,         /* T[03]                               */
                   0xC1BDCEEE,         /* T[04]                               */
                   0xF57C0FAF,         /* T[05]                               */
                   0x4787C62A,         /* T[06]                               */
                   0xA8304613,         /* T[07]                               */
                   0xFD469501,         /* T[08]                               */
                   0x698098D8,         /* T[09]                               */
                   0x8B44F7AF,         /* T[10]                               */
                   0xFFFF5BB1,         /* T[11]                               */
                   0x895CD7BE,         /* T[12]                               */
                   0x6B901122,         /* T[13]                               */
                   0xFD987193,         /* T[14]                               */
                   0xA679438E,         /* T[15]                               */
                   0x49B40821,         /* T[16]                               */
                   0xF61E2562,         /* T[17]                               */
                   0xC040B340,         /* T[18]                               */
                   0x265E5A51,         /* T[19]                               */
                   0xE9B6C7AA,         /* T[20]                               */
                   0xD62F105D,         /* T[21]                               */
                   0x02441453,         /* T[22]                               */
                   0xD8A1E681,         /* T[23]                               */
                   0xE7D3FBC8,         /* T[24]                               */
                   0x21E1CDE6,         /* T[25]                               */
                   0xC33707D6,         /* T[26]                               */
                   0xF4D50D87,         /* T[27]                               */
                   0x455A14ED,         /* T[28]                               */
                   0xA9E3E905,         /* T[29]                               */
                   0xFCEFA3F8,         /* T[30]                               */
                   0x676F02D9,         /* T[31]                               */
                   0x8D2A4C8A,         /* T[32]                               */
                   0xFFFA3942,         /* T[33]                               */
                   0x8771F681,         /* T[34]                               */
                   0x6D9D6122,         /* T[35]                               */
                   0xFDE5380C,         /* T[36]                               */
                   0xA4BEEA44,         /* T[37]                               */
                   0x4BDECFA9,         /* T[38]                               */
                   0xF6BB4B60,         /* T[39]                               */
                   0xBEBFBC70,         /* T[40]                               */
                   0x289B7EC6,         /* T[41]                               */
                   0xEAA127FA,         /* T[42]                               */
                   0xD4EF3085,         /* T[43]                               */
                   0x04881D05,         /* T[44]                               */
                   0xD9D4D039,         /* T[45]                               */
                   0xE6DB99E5,         /* T[46]                               */
                   0x1FA27CF8,         /* T[47]                               */
                   0xC4AC5665,         /* T[48]                               */
                   0xF4292244,         /* T[49]                               */
                   0x432AFF97,         /* T[50]                               */
                   0xAB9423A7,         /* T[51]                               */
                   0xFC93A039,         /* T[52]                               */
                   0x655B59C3,         /* T[53]                               */
                   0x8F0CCC92,         /* T[54]                               */
                   0xFFEFF47D,         /* T[55]                               */
                   0x85845DD1,         /* T[56]                               */
                   0x6FA87E4F,         /* T[57]                               */
                   0xFE2CE6E0,         /* T[58]                               */
                   0xA3014314,         /* T[59]                               */
                   0x4E0811A1,         /* T[60]                               */
                   0xF7537E82,         /* T[61]                               */
                   0xBD3AF235,         /* T[62]                               */
                   0x2AD7D2BB,         /* T[63]                               */
                   0xEB86D391 };       /* T[64]                               */


// Basic MD5 step. Transform buf based on in.
//
void
ckm_md5_transform(STDLL_TokData_t *tokdata, CK_ULONG *long_buf, CK_ULONG *long_in)
{

   /*-------------------------------------------------------------------------*/
   /* The inputs to this function SHOULD be 4 4-byte elements of buf[] and    */
   /* 16 4-byte elements of in[].  There are architectures, however --        */
   /* 64-bit Linux390 among them--in which CK_ULONG translates to an 8-byte   */
   /* number.  Therefore this function must copy inputs to 4-byte temps and   */
   /* copy the temps back into the 8-byte arrays at the end.                  */
   /*-------------------------------------------------------------------------*/
   /*                                                                         */
   /* Macro ROUND_FCN defines the common function that is performed           */
   /* throughout the MD5 round.  Parameters are:                              */
   /*                                                                         */
   /*   - The name of the function to be performed on the data for this       */
   /*     round.  There are four logical functions, F, G, H, and I, and they  */
   /*     are each used throughout the algorithm.                             */
   /*                                                                         */
   /*   - a, b, c, and d are the four md5-word parameters to the functions    */
   /*     F, G, H, and I.  They are replaced with varying permutations of the */
   /*     accumulated hash values in A, B, C, and D.                          */
   /*                                                                         */
   /*   - x_index is an index into the in[] array, where in[] is the input    */
   /*     block of message text.                                              */
   /*                                                                         */
   /*   - t_index is an index into the T[] array, a set of constants.         */
   /*                                                                         */
   /*   - rotate_cnt is the number of bits the result must be rotated.        */
   /*                                                                         */
   /*-------------------------------------------------------------------------*/

   CK_ULONG AA = 0x00000000;           /* Temp. save areas for A, B, C, D     */
   CK_ULONG BB = 0x00000000;           /* Temp. save areas for A, B, C, D     */
   CK_ULONG CC = 0x00000000;           /* Temp. save areas for A, B, C, D     */
   CK_ULONG DD = 0x00000000;           /* Temp. save areas for A, B, C, D     */

   CK_ULONG_32 buf[4];                 // temps for long_buf[i]
   CK_ULONG_32 in[16];                 // temps for long_in[i]

   int i;                              // loop counter

   #define ROUND_FCN(FCN, a, b, c, d, x_index, rotate_cnt, t_index) \
    { a += FCN(b,c,d) + in[x_index] + T[t_index-1];           \
      rotate_left( a, rotate_cnt);                           \
      a += b;                                                \
    }

   /* Save the MD buffer in the temporary locations AA-DD.                    */

   AA = long_buf[0];
   BB = long_buf[1];
   CC = long_buf[2];
   DD = long_buf[3];

   // Copy the input long_buf elements into buf and long_in elements into in
   for (i=0;i<4;i++) {
     buf[i] = (CK_ULONG_32)long_buf[i];
     in[i] = (CK_ULONG_32)long_in[i];
   }
   for (i=4;i<16;i++)
     in[i] = (CK_ULONG_32)long_in[i];


   /*==================================================================*/
   /*                                                                  */
   /* Process the four rounds for each 16-word block.                  */
   /*                                                                  */
   /* The function for each of these has the form:                     */
   /*                                                                  */
   /*    a = b + (( a + fcn( b, c, d ) + in[k] + T[i] ) <<< s )        */
   /*                                                                  */
   /* for a function fcn() which can be F, G, H, or I, and for input   */
   /* values a, b, c, d, k, i, and s.  Array T is the array of         */
   /* constants, computed from the sin() function.  Array in is the    */
   /* current input block.  Value s is the number of bits to rotate    */
   /* left, where <<< represents a 32-bit left rotation.               */
   /*                                                                  */
   /* The definitions of these functions are taken directly from the   */
   /* definition of MD5 in RFC 1321.                                   */
   /*                                                                  */
   /*==================================================================*/

   /*------------------------------------------------------------------*/
   /*                                                                  */
   /* Round 1                                                          */
   /*                                                                  */
   /*------------------------------------------------------------------*/

   ROUND_FCN(F, buf[0], buf[1], buf[2], buf[3],  0,  7,  1);
   ROUND_FCN(F, buf[3], buf[0], buf[1], buf[2],  1, 12,  2);
   ROUND_FCN(F, buf[2], buf[3], buf[0], buf[1],  2, 17,  3);
   ROUND_FCN(F, buf[1], buf[2], buf[3], buf[0],  3, 22,  4);
   ROUND_FCN(F, buf[0], buf[1], buf[2], buf[3],  4,  7,  5);
   ROUND_FCN(F, buf[3], buf[0], buf[1], buf[2],  5, 12,  6);
   ROUND_FCN(F, buf[2], buf[3], buf[0], buf[1],  6, 17,  7);
   ROUND_FCN(F, buf[1], buf[2], buf[3], buf[0],  7, 22,  8);
   ROUND_FCN(F, buf[0], buf[1], buf[2], buf[3],  8,  7,  9);
   ROUND_FCN(F, buf[3], buf[0], buf[1], buf[2],  9, 12, 10);
   ROUND_FCN(F, buf[2], buf[3], buf[0], buf[1], 10, 17, 11);
   ROUND_FCN(F, buf[1], buf[2], buf[3], buf[0], 11, 22, 12);
   ROUND_FCN(F, buf[0], buf[1], buf[2], buf[3], 12,  7, 13);
   ROUND_FCN(F, buf[3], buf[0], buf[1], buf[2], 13, 12, 14);
   ROUND_FCN(F, buf[2], buf[3], buf[0], buf[1], 14, 17, 15);
   ROUND_FCN(F, buf[1], buf[2], buf[3], buf[0], 15, 22, 16);

   /*------------------------------------------------------------------*/
   /*                                                                  */
   /* Round 2                                                          */
   /*                                                                  */
   /*------------------------------------------------------------------*/


   ROUND_FCN(G, buf[0], buf[1], buf[2], buf[3],  1,  5, 17);
   ROUND_FCN(G, buf[3], buf[0], buf[1], buf[2],  6,  9, 18);
   ROUND_FCN(G, buf[2], buf[3], buf[0], buf[1], 11, 14, 19);
   ROUND_FCN(G, buf[1], buf[2], buf[3], buf[0],  0, 20, 20);
   ROUND_FCN(G, buf[0], buf[1], buf[2], buf[3],  5,  5, 21);
   ROUND_FCN(G, buf[3], buf[0], buf[1], buf[2], 10,  9, 22);
   ROUND_FCN(G, buf[2], buf[3], buf[0], buf[1], 15, 14, 23);
   ROUND_FCN(G, buf[1], buf[2], buf[3], buf[0],  4, 20, 24);
   ROUND_FCN(G, buf[0], buf[1], buf[2], buf[3],  9,  5, 25);
   ROUND_FCN(G, buf[3], buf[0], buf[1], buf[2], 14,  9, 26);
   ROUND_FCN(G, buf[2], buf[3], buf[0], buf[1],  3, 14, 27);
   ROUND_FCN(G, buf[1], buf[2], buf[3], buf[0],  8, 20, 28);
   ROUND_FCN(G, buf[0], buf[1], buf[2], buf[3], 13,  5, 29);
   ROUND_FCN(G, buf[3], buf[0], buf[1], buf[2],  2,  9, 30);
   ROUND_FCN(G, buf[2], buf[3], buf[0], buf[1],  7, 14, 31);
   ROUND_FCN(G, buf[1], buf[2], buf[3], buf[0], 12, 20, 32);

   /*------------------------------------------------------------------*/
   /*                                                                  */
   /* Round 3                                                          */
   /*                                                                  */
   /*------------------------------------------------------------------*/


   ROUND_FCN(H, buf[0], buf[1], buf[2], buf[3],  5,  4, 33);
   ROUND_FCN(H, buf[3], buf[0], buf[1], buf[2],  8, 11, 34);
   ROUND_FCN(H, buf[2], buf[3], buf[0], buf[1], 11, 16, 35);
   ROUND_FCN(H, buf[1], buf[2], buf[3], buf[0], 14, 23, 36);
   ROUND_FCN(H, buf[0], buf[1], buf[2], buf[3],  1,  4, 37);
   ROUND_FCN(H, buf[3], buf[0], buf[1], buf[2],  4, 11, 38);
   ROUND_FCN(H, buf[2], buf[3], buf[0], buf[1],  7, 16, 39);
   ROUND_FCN(H, buf[1], buf[2], buf[3], buf[0], 10, 23, 40);
   ROUND_FCN(H, buf[0], buf[1], buf[2], buf[3], 13,  4, 41);
   ROUND_FCN(H, buf[3], buf[0], buf[1], buf[2],  0, 11, 42);
   ROUND_FCN(H, buf[2], buf[3], buf[0], buf[1],  3, 16, 43);
   ROUND_FCN(H, buf[1], buf[2], buf[3], buf[0],  6, 23, 44);
   ROUND_FCN(H, buf[0], buf[1], buf[2], buf[3],  9,  4, 45);
   ROUND_FCN(H, buf[3], buf[0], buf[1], buf[2], 12, 11, 46);
   ROUND_FCN(H, buf[2], buf[3], buf[0], buf[1], 15, 16, 47);
   ROUND_FCN(H, buf[1], buf[2], buf[3], buf[0],  2, 23, 48);

   /*------------------------------------------------------------------*/
   /*                                                                  */
   /* Round 4                                                          */
   /*                                                                  */
   /*------------------------------------------------------------------*/


   ROUND_FCN(I, buf[0], buf[1], buf[2], buf[3],  0,  6, 49);
   ROUND_FCN(I, buf[3], buf[0], buf[1], buf[2],  7, 10, 50);
   ROUND_FCN(I, buf[2], buf[3], buf[0], buf[1], 14, 15, 51);
   ROUND_FCN(I, buf[1], buf[2], buf[3], buf[0],  5, 21, 52);
   ROUND_FCN(I, buf[0], buf[1], buf[2], buf[3], 12,  6, 53);
   ROUND_FCN(I, buf[3], buf[0], buf[1], buf[2],  3, 10, 54);
   ROUND_FCN(I, buf[2], buf[3], buf[0], buf[1], 10, 15, 55);
   ROUND_FCN(I, buf[1], buf[2], buf[3], buf[0],  1, 21, 56);
   ROUND_FCN(I, buf[0], buf[1], buf[2], buf[3],  8,  6, 57);
   ROUND_FCN(I, buf[3], buf[0], buf[1], buf[2], 15, 10, 58);
   ROUND_FCN(I, buf[2], buf[3], buf[0], buf[1],  6, 15, 59);
   ROUND_FCN(I, buf[1], buf[2], buf[3], buf[0], 13, 21, 60);
   ROUND_FCN(I, buf[0], buf[1], buf[2], buf[3],  4,  6, 61);
   ROUND_FCN(I, buf[3], buf[0], buf[1], buf[2], 11, 10, 62);
   ROUND_FCN(I, buf[2], buf[3], buf[0], buf[1],  2, 15, 63);
   ROUND_FCN(I, buf[1], buf[2], buf[3], buf[0],  9, 21, 64);

   // Copy the elements of buf into long_buf
   for (i=0;i<4;i++)
     long_buf[i] = (CK_ULONG) buf[i];

   /* Add to each MD buffer variable the value it had before this block was   */
   /* started.                                                                */

   long_buf[0] += AA;
   long_buf[1] += BB;
   long_buf[2] += CC;
   long_buf[3] += DD;

   /* Undefine the ROUND_FCN macro we used in this function.                  */
   #undef ROUND_FCN
}
