/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki CCA token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
 *
 * Author: Kent E. Yoder <yoder1@us.ibm.com>
 *
 */


// File:  mech_sha.c
//
// Mechanisms for SHA-1 related routines
//
// The following applies to the software SHA implementation:
//    Written 2 September 1992, Peter C. Gutmann.
//    This implementation placed in the public domain.
//
//    Modified 1 June 1993, Colin Plumb.
//    Modified for the new SHS based on Peter Gutmann's work,
//    18 July 1994, Colin Plumb.
//    Gutmann's work.
//    Renamed to SHA and comments updated a bit 1 November 1995, Colin Plumb.
//    These modifications placed in the public domain.
//
//    Comments to pgut1@cs.aukuni.ac.nz
//

#include <pthread.h>
#include <string.h>            // for memcmp() et al
#include <stdlib.h>
#include <memory.h>

#include "cca_stdll.h"

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"

#define SHA_HARDWARE_THRESHHOLD 128000

// The SHA f()-functions.  The f1 and f3 functions can be optimized to
// save one boolean operation each - thanks to Rich Schroeppel,
// rcs@cs.arizona.edu for discovering this
//
#define f1(x,y,z) (z ^ (x & (y ^ z)))        // Rounds  0-19
#define f2(x,y,z) (x ^ y ^ z)                // Rounds 20-39
#define f3(x,y,z) ((x & y) | (z & (x | y)))  // Rounds 40-59
#define f4(x,y,z) (x ^ y ^ z)                // Rounds 60-79

// The SHA Mysterious Constants.
// K1 = floor(sqrt(2)  * 2^30)
// K2 = floor(sqrt(3)  * 2^30)
// K3 = floor(sqrt(5)  * 2^30)
// K4 = floor(sqrt(10) * 2^30)
//
#define K1  0x5A827999L // Rounds  0-19
#define K2  0x6ED9EBA1L // Rounds 20-39
#define K3  0x8F1BBCDCL // Rounds 40-59
#define K4  0xCA62C1D6L // Rounds 60-79

// SHA initial values
//
#define h0init 0x67452301
#define h1init 0xEFCDAB89
#define h2init 0x98BADCFE
#define h3init 0x10325476
#define h4init 0xC3D2E1F0

//
// Note that it may be necessary to add parentheses to these macros
// if they are to be called with expressions as arguments.
//

// 32-bit rotate left - kludged with shifts
//

#define ROTL(n,X)  ((X << n) | (X >> (32-n)))

// The initial expanding function
//
// The hash function is defined over an 80-word expanded input array W,
// where the first 16 are copies of the input data, and the remaining 64
// are defined by W[i] = W[i-16] ^ W[i-14] ^ W[i-8] ^ W[i-3].  This
// implementation generates these values on the fly in a circular buffer.
//

#define expand(W,i) \
   (W[i&15] ^= W[(i-14)&15] ^ W[(i-8)&15] ^ W[(i-3)&15], W[i&15] = ROTL(1, W[i&15]))

// The prototype SHA sub-round
//
// The fundamental sub-round is
// a' = e + ROTL(5,a) + f(b, c, d) + k + data;
// b' = a;
// c' = ROTL(30,b);
// d' = c;
// e' = d;
// ... but this is implemented by unrolling the loop 5 times and renaming
// the variables (e,a,b,c,d) = (a',b',c',d',e') each iteration.
//
#define subRound(a, b, c, d, e, f, k, data)  \
   (e += ROTL(5,a) + f(b, c, d) + k + data, b = ROTL(30, b))


void shaInit( SHA1_CONTEXT *ctx );
void shaUpdate( SHA1_CONTEXT *ctx, CK_BYTE const *buffer, CK_ULONG count);
void shaFinal( SHA1_CONTEXT *ctx, CK_BYTE *hash );
void shaTransform( SHA1_CONTEXT *ctx );

//
//
CK_RV
sha1_hash( SESSION         *sess,
           CK_BBOOL         length_only,
           DIGEST_CONTEXT  *ctx,
           CK_BYTE         *in_data,
           CK_ULONG         in_data_len,
           CK_BYTE         *out_data,
           CK_ULONG        *out_data_len )
{
   CK_RV rv;
   
   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *out_data_len = SHA1_HASH_SIZE;
      return CKR_OK;
   }

   if(ctx->context == NULL)
	   return CKR_HOST_MEMORY;

   if((rv = ckm_sha1_update(ctx, in_data, in_data_len)))
	   return rv;
   
   return ckm_sha1_final(  ctx, out_data, out_data_len );
}

CK_RV
sha2_hash( SESSION         *sess,
           CK_BBOOL         length_only,
           DIGEST_CONTEXT  *ctx,
           CK_BYTE         *in_data,
           CK_ULONG         in_data_len,
           CK_BYTE         *out_data,
           CK_ULONG        *out_data_len )
{
   CK_RV rv;
   struct cca_sha256_ctx *cca_ctx;

   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *out_data_len = SHA2_HASH_SIZE;
      return CKR_OK;
   }

   if (ctx->context == NULL)
      return CKR_HOST_MEMORY;

   if ((rv = ckm_sha2_update(ctx, in_data, in_data_len)))
      return rv;

    /* Note: for a single part hash on cca token, CSNBOWH gives us
     * the hash and there is no need to call final.
     * Calling final will result in CSNBOWH being called again.
     * So just copy hash into output buffer here.
     */

    cca_ctx = (struct cca_sha256_ctx *)ctx->context;
    if (*out_data_len < cca_ctx->scratch_len) {
       OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
       return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(out_data, cca_ctx->scratch, cca_ctx->scratch_len);
    *out_data_len = cca_ctx->scratch_len;

    return CKR_OK;

}

CK_RV
sha3_hash( SESSION         *sess,
           CK_BBOOL         length_only,
           DIGEST_CONTEXT  *ctx,
           CK_BYTE         *in_data,
           CK_ULONG         in_data_len,
           CK_BYTE         *out_data,
           CK_ULONG        *out_data_len )
{
   CK_RV rv;

	return rv = 0;
}
CK_RV
sha5_hash( SESSION         *sess,
           CK_BBOOL         length_only,
           DIGEST_CONTEXT  *ctx,
           CK_BYTE         *in_data,
           CK_ULONG         in_data_len,
           CK_BYTE         *out_data,
           CK_ULONG        *out_data_len )
{
   CK_RV rv;

	return rv = 0;
}
//
//
CK_RV
sha1_hash_update( SESSION        * sess,
                  DIGEST_CONTEXT * ctx,
                  CK_BYTE        * in_data,
                  CK_ULONG         in_data_len )
{
   if (!sess || !in_data){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   return ckm_sha1_update( ctx, in_data, in_data_len );
}

CK_RV
sha2_hash_update( SESSION        * sess,
                  DIGEST_CONTEXT * ctx,
                  CK_BYTE        * in_data,
                  CK_ULONG         in_data_len )
{
   if (!sess || !in_data) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   return ckm_sha2_update( ctx, in_data, in_data_len );
}

CK_RV
sha3_hash_update( SESSION        * sess,
                  DIGEST_CONTEXT * ctx,
                  CK_BYTE        * in_data,
                  CK_ULONG         in_data_len )
{
	return CKR_OK;
}
CK_RV
sha5_hash_update( SESSION        * sess,
                  DIGEST_CONTEXT * ctx,
                  CK_BYTE        * in_data,
                  CK_ULONG         in_data_len )
{
	return CKR_OK;
}
//
//
CK_RV
sha1_hash_final( SESSION         * sess,
                 CK_BYTE           length_only,
                 DIGEST_CONTEXT  * ctx,
                 CK_BYTE         * out_data,
                 CK_ULONG        * out_data_len )
{
   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *out_data_len = SHA1_HASH_SIZE;
      return CKR_OK;
   }

   return ckm_sha1_final( ctx, out_data, out_data_len );
}

CK_RV
sha2_hash_final( SESSION         * sess,
                 CK_BYTE           length_only,
                 DIGEST_CONTEXT  * ctx,
                 CK_BYTE         * out_data,
                 CK_ULONG        * out_data_len )
{
   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (length_only == TRUE) {
      *out_data_len = SHA2_HASH_SIZE;
      return CKR_OK;
   }

   return ckm_sha2_final( ctx, out_data, out_data_len );
}

CK_RV
sha3_hash_final( SESSION         * sess,
                 CK_BYTE           length_only,
                 DIGEST_CONTEXT  * ctx,
                 CK_BYTE         * out_data,
                 CK_ULONG        * out_data_len )
{
	return CKR_OK;
}
CK_RV
sha5_hash_final( SESSION         * sess,
                 CK_BYTE           length_only,
                 DIGEST_CONTEXT  * ctx,
                 CK_BYTE         * out_data,
                 CK_ULONG        * out_data_len )
{
	return CKR_OK;
}
// this routine gets called for two mechanisms actually:
//    CKM_SHA_1_HMAC
//    CKM_SHA_1_HMAC_GENERAL
//
CK_RV
sha1_hmac_sign( SESSION              * sess,
                CK_BBOOL               length_only,
                SIGN_VERIFY_CONTEXT  * ctx,
                CK_BYTE              * in_data,
                CK_ULONG               in_data_len,
                CK_BYTE              * out_data,
                CK_ULONG             * out_data_len )
{
   OBJECT          * key_obj = NULL;
   CK_ATTRIBUTE    * attr    = NULL;
   CK_BYTE           hash[SHA1_HASH_SIZE];
   DIGEST_CONTEXT    digest_ctx;
   CK_MECHANISM      digest_mech;
   CK_BYTE           k_ipad[SHA1_BLOCK_SIZE];
   CK_BYTE           k_opad[SHA1_BLOCK_SIZE];
   CK_ULONG          key_bytes, hash_len, hmac_len;
   CK_ULONG          i;
   CK_RV             rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->mech.mechanism == CKM_SHA_1_HMAC_GENERAL) {
      hmac_len = *(CK_ULONG *)ctx->mech.pParameter;

      if (hmac_len == 0) {
         *out_data_len = 0;
         return CKR_OK;
      }
   }
   else
      hmac_len = SHA1_HASH_SIZE;


   if (length_only == TRUE) {
      *out_data_len = hmac_len;
      return CKR_OK;
   }

   memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );

   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   rc = template_attribute_find( key_obj->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   else
      key_bytes = attr->ulValueLen;


   // build (K XOR ipad), (K XOR opad)
   //
   if (key_bytes > SHA1_BLOCK_SIZE) {
      digest_mech.mechanism      = CKM_SHA_1;
      digest_mech.ulParameterLen = 0;
      digest_mech.pParameter     = NULL;

      rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
      if (rc != CKR_OK) {
         OCK_LOG_ERR(ERR_DIGEST_INIT);
         return rc;
      }

      hash_len = sizeof(hash);
      rc = digest_mgr_digest( sess, FALSE, &digest_ctx,
                              attr->pValue,
                              attr->ulValueLen,
                              hash,  &hash_len );
      if (rc != CKR_OK) {
         OCK_LOG_ERR(ERR_DIGEST);
         return rc;
      }

      memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );

      for (i=0; i < hash_len; i++) {
         k_ipad[i] = hash[i] ^ 0x36;
         k_opad[i] = hash[i] ^ 0x5C;
      }

      memset( &k_ipad[i], 0x36, SHA1_BLOCK_SIZE - i);
      memset( &k_opad[i], 0x5C, SHA1_BLOCK_SIZE - i);
   }
   else {
      CK_BYTE *key = attr->pValue;

      for (i=0; i < key_bytes; i++) {
         k_ipad[i] = key[i] ^ 0x36;
         k_opad[i] = key[i] ^ 0x5C;
      }

      memset( &k_ipad[i], 0x36, SHA1_BLOCK_SIZE - key_bytes );
      memset( &k_opad[i], 0x5C, SHA1_BLOCK_SIZE - key_bytes );
   }

   digest_mech.mechanism      = CKM_SHA_1;
   digest_mech.ulParameterLen = 0;
   digest_mech.pParameter     = NULL;

   // inner hash
   //
   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_INIT);
      return rc;
   }

   rc = digest_mgr_digest_update( sess, &digest_ctx, k_ipad, SHA1_BLOCK_SIZE );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_UPDATE);
      return rc;
   }

   rc = digest_mgr_digest_update( sess, &digest_ctx, in_data, in_data_len );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_UPDATE);
      return rc;
   }

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, FALSE, &digest_ctx, hash, &hash_len );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_FINAL);
      return rc;
   }

   memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );


   // outer hash
   //
   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_INIT);
      return rc;
   }

   rc = digest_mgr_digest_update( sess, &digest_ctx, k_opad, SHA1_BLOCK_SIZE );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_UPDATE);
      return rc;
   }

   rc = digest_mgr_digest_update( sess, &digest_ctx, hash, hash_len );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_UPDATE);
      return rc;
   }

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, FALSE, &digest_ctx, hash, &hash_len );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_FINAL);
      return rc;
   }

   memcpy( out_data, hash, hmac_len );
   *out_data_len = hmac_len;

   return CKR_OK;
}

/** This routine gets called for two mechanisms actually:
 *    CKM_SHA256_HMAC
 *    CKM_SHA256_HMAC_GENERAL
 */
CK_RV
sha2_hmac_sign( SESSION              * sess,
                CK_BBOOL               length_only,
                SIGN_VERIFY_CONTEXT  * ctx,
                CK_BYTE              * in_data,
                CK_ULONG               in_data_len,
                CK_BYTE              * out_data,
                CK_ULONG             * out_data_len )
{
   OBJECT          * key_obj = NULL;
   CK_ATTRIBUTE    * attr    = NULL;
   CK_BYTE           hash[SHA2_HASH_SIZE];
   DIGEST_CONTEXT    digest_ctx;
   CK_MECHANISM      digest_mech;
   CK_BYTE           k_ipad[SHA2_BLOCK_SIZE];
   CK_BYTE           k_opad[SHA2_BLOCK_SIZE];
   CK_ULONG          key_bytes, hash_len, hmac_len;
   CK_ULONG          i;
   CK_RV             rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->mech.mechanism == CKM_SHA256_HMAC_GENERAL) {
      hmac_len = *(CK_ULONG *)ctx->mech.pParameter;

      if (hmac_len == 0) {
         *out_data_len = 0;
         return CKR_OK;
      }
   }
   else
      hmac_len = SHA2_HASH_SIZE;


   if (length_only == TRUE) {
      *out_data_len = hmac_len;
      return CKR_OK;
   }

   memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );

   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   rc = template_attribute_find( key_obj->template, CKA_VALUE, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   else
      key_bytes = attr->ulValueLen;


   // build (K XOR ipad), (K XOR opad)
   //
   if (key_bytes > SHA2_BLOCK_SIZE) {
      digest_mech.mechanism      = CKM_SHA256;
      digest_mech.ulParameterLen = 0;
      digest_mech.pParameter     = NULL;

      rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
      if (rc != CKR_OK) {
         OCK_LOG_ERR(ERR_DIGEST_INIT);
         return rc;
      }

      hash_len = sizeof(hash);
      rc = digest_mgr_digest( sess, FALSE, &digest_ctx,
                              attr->pValue,
                              attr->ulValueLen,
                              hash,  &hash_len );
      if (rc != CKR_OK) {
         OCK_LOG_ERR(ERR_DIGEST);
         return rc;
      }

      memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );

      for (i=0; i < hash_len; i++) {
         k_ipad[i] = hash[i] ^ 0x36;
         k_opad[i] = hash[i] ^ 0x5C;
      }

      memset( &k_ipad[i], 0x36, SHA2_BLOCK_SIZE - i);
      memset( &k_opad[i], 0x5C, SHA2_BLOCK_SIZE - i);
   }
   else {
      CK_BYTE *key = attr->pValue;

      for (i=0; i < key_bytes; i++) {
         k_ipad[i] = key[i] ^ 0x36;
         k_opad[i] = key[i] ^ 0x5C;
      }

      memset( &k_ipad[i], 0x36, SHA2_BLOCK_SIZE - key_bytes );
      memset( &k_opad[i], 0x5C, SHA2_BLOCK_SIZE - key_bytes );
   }

   digest_mech.mechanism      = CKM_SHA256;
   digest_mech.ulParameterLen = 0;
   digest_mech.pParameter     = NULL;

   // inner hash
   //
   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_INIT);
      return rc;
   }

   rc = digest_mgr_digest_update( sess, &digest_ctx, k_ipad, SHA2_BLOCK_SIZE );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_UPDATE);
      return rc;
   }

   rc = digest_mgr_digest_update( sess, &digest_ctx, in_data, in_data_len );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_UPDATE);
      return rc;
   }

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, FALSE, &digest_ctx, hash, &hash_len );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_FINAL);
      return rc;
   }

   memset( &digest_ctx, 0x0, sizeof(DIGEST_CONTEXT) );


   // outer hash
   //
   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_INIT);
      return rc;
   }

   rc = digest_mgr_digest_update( sess, &digest_ctx, k_opad, SHA2_BLOCK_SIZE );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_UPDATE);
      return rc;
   }

   rc = digest_mgr_digest_update( sess, &digest_ctx, hash, hash_len );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_UPDATE);
      return rc;
   }

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, FALSE, &digest_ctx, hash, &hash_len );
   if (rc != CKR_OK) {
      OCK_LOG_ERR(ERR_DIGEST_FINAL);
      return rc;
   }

   memcpy( out_data, hash, hmac_len );
   *out_data_len = hmac_len;

   return CKR_OK;
}

//
//
CK_RV
sha1_hmac_verify( SESSION              * sess,
                  SIGN_VERIFY_CONTEXT  * ctx,
                  CK_BYTE              * in_data,
                  CK_ULONG               in_data_len,
                  CK_BYTE              * signature,
                  CK_ULONG               sig_len )
{
   CK_BYTE              hmac[SHA1_HASH_SIZE];
   SIGN_VERIFY_CONTEXT  hmac_ctx;
   CK_ULONG             hmac_len, len;
   CK_RV                rc;

   if (!sess || !ctx || !in_data || !signature){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->mech.mechanism == CKM_SHA_1_HMAC_GENERAL)
      hmac_len = *(CK_ULONG *)ctx->mech.pParameter;
   else
      hmac_len = SHA1_HASH_SIZE;

   memset( &hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT) );

   rc = sign_mgr_init( sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_SIGN_INIT);
      goto done;
   }
   len = sizeof(hmac);
   rc = sign_mgr_sign( sess, FALSE, &hmac_ctx,
                       in_data, in_data_len,
                       hmac,   &len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_SIGN);
      goto done;
   }
   if ((len != hmac_len) || (len != sig_len)) {
      OCK_LOG_ERR(ERR_SIGNATURE_LEN_RANGE);
      rc = CKR_SIGNATURE_LEN_RANGE;
      goto done;
   }

   if (memcmp(hmac, signature, hmac_len) != 0){
      OCK_LOG_ERR(ERR_SIGNATURE_INVALID);
      rc = CKR_SIGNATURE_INVALID;
   }
done:
   sign_mgr_cleanup( &hmac_ctx );
   return rc;
}

CK_RV
sha2_hmac_verify( SESSION              * sess,
                  SIGN_VERIFY_CONTEXT  * ctx,
                  CK_BYTE              * in_data,
                  CK_ULONG               in_data_len,
                  CK_BYTE              * signature,
                  CK_ULONG               sig_len )
{
   CK_BYTE              hmac[SHA2_HASH_SIZE];
   SIGN_VERIFY_CONTEXT  hmac_ctx;
   CK_ULONG             hmac_len, len;
   CK_RV                rc;

   if (!sess || !ctx || !in_data || !signature){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->mech.mechanism == CKM_SHA256_HMAC_GENERAL)
      hmac_len = *(CK_ULONG *)ctx->mech.pParameter;
   else
      hmac_len = SHA2_HASH_SIZE;

   memset( &hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT) );

   rc = sign_mgr_init( sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_SIGN_INIT);
      goto done;
   }
   len = sizeof(hmac);
   rc = sign_mgr_sign( sess, FALSE, &hmac_ctx,
                       in_data, in_data_len,
                       hmac,   &len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_SIGN);
      goto done;
   }
   if ((len != hmac_len) || (len != sig_len)) {
      OCK_LOG_ERR(ERR_SIGNATURE_LEN_RANGE);
      rc = CKR_SIGNATURE_LEN_RANGE;
      goto done;
   }

   if (memcmp(hmac, signature, hmac_len) != 0){
      OCK_LOG_ERR(ERR_SIGNATURE_INVALID);
      rc = CKR_SIGNATURE_INVALID;
   }
done:
   sign_mgr_cleanup( &hmac_ctx );
   return rc;
}

//
// CKM routines
//

//
//
CK_RV
ckm_sha1_update( DIGEST_CONTEXT * ctx,
                 CK_BYTE        * in_data,
                 CK_ULONG         in_data_len )
{
    if( token_specific.t_sha_update == NULL ){
	if (!ctx || !in_data){
	    OCK_LOG_ERR(ERR_FUNCTION_FAILED);
	    return CKR_FUNCTION_FAILED;
	}
	shaUpdate( (SHA1_CONTEXT *)ctx->context, in_data, in_data_len );
	return CKR_OK;
    }

    return token_specific.t_sha_update(ctx, in_data, in_data_len);
}

CK_RV
ckm_sha2_update( DIGEST_CONTEXT * ctx,
                 CK_BYTE        * in_data,
                 CK_ULONG         in_data_len )
{
    if( token_specific.t_sha2_update == NULL ){
        /* TODO: Software implementation here */
        return CKR_MECHANISM_INVALID;
    }

    return token_specific.t_sha2_update(ctx, in_data, in_data_len);
}

CK_RV
ckm_sha3_update( DIGEST_CONTEXT * ctx,
                 CK_BYTE        * in_data,
                 CK_ULONG         in_data_len )
{
	return CKR_OK;
}
CK_RV
ckm_sha5_update( DIGEST_CONTEXT * ctx,
                 CK_BYTE        * in_data,
                 CK_ULONG         in_data_len )
{
	return CKR_OK;
}
CK_RV
ckm_sha3_final( DIGEST_CONTEXT * ctx,
                CK_BYTE        * out_data,
                CK_ULONG       * out_data_len )
{
	return CKR_OK;
}
CK_RV
ckm_sha5_final( DIGEST_CONTEXT * ctx,
                CK_BYTE        * out_data,
                CK_ULONG       * out_data_len )
{
	return CKR_OK;
}
//
//
CK_RV
ckm_sha1_final( DIGEST_CONTEXT * ctx,
                CK_BYTE        * out_data,
                CK_ULONG       * out_data_len )
{
    if (token_specific.t_sha_final  == NULL ){
	if (!ctx || !out_data || !out_data_len){
	    OCK_LOG_ERR(ERR_FUNCTION_FAILED);
	    return CKR_FUNCTION_FAILED;
	}
	if (*out_data_len < SHA1_HASH_SIZE){
	    OCK_LOG_ERR(ERR_FUNCTION_FAILED);
	    return CKR_FUNCTION_FAILED;
	}
	shaFinal( (SHA1_CONTEXT *)ctx->context, out_data );
	*out_data_len = SHA1_HASH_SIZE;

	return CKR_OK;
    } 
    
    return token_specific.t_sha_final(ctx, out_data, out_data_len);
}

CK_RV
ckm_sha2_final( DIGEST_CONTEXT * ctx,
                CK_BYTE        * out_data,
                CK_ULONG       * out_data_len )
{
    if (token_specific.t_sha2_final  == NULL ){
       /* TODO: Software implementation here */
       return CKR_MECHANISM_INVALID;
    }

    return token_specific.t_sha2_final(ctx, out_data, out_data_len);
}

//
// Software SHA-1 implementation
//
void
ckm_sha1_init( DIGEST_CONTEXT * ctx)
{
    // Set the h-vars to their initial values
    if (token_specific.t_sha_init  == NULL ) {
	SHA1_CONTEXT *sha1_ctx;
	/* Allocate the context */
	ctx->context_len = sizeof(SHA1_CONTEXT);
	ctx->context = (CK_BYTE *)malloc(sizeof(SHA1_CONTEXT));
	if( ctx->context == NULL )
		return;
    
	sha1_ctx = (SHA1_CONTEXT *)ctx->context;
	sha1_ctx->hash_value[0]  = h0init;
	sha1_ctx->hash_value[1]  = h1init;
	sha1_ctx->hash_value[2]  = h2init;
	sha1_ctx->hash_value[3]  = h3init;
	sha1_ctx->hash_value[4]  = h4init;

	// Initialise bit count
    	sha1_ctx->bits_lo = sha1_ctx->bits_hi = 0;
    } else {
	// SAB XXX call token specific init... the init MUST allocate it's context
	token_specific.t_sha_init(ctx);
    }
}

void
ckm_sha2_init( DIGEST_CONTEXT * ctx)
{
    if (token_specific.t_sha2_init == NULL ) {
       /* TODO: Software implementation here */
       return;
    } else {
	// SAB XXX call token specific init... the init MUST allocate it's context
	token_specific.t_sha2_init(ctx);
    }
}

void
ckm_sha5_init( DIGEST_CONTEXT * ctx)
{
	ctx = NULL;
}
void
ckm_sha3_init( DIGEST_CONTEXT * ctx)
{
	ctx = NULL;
}
// Perform the SHA transformation.  Note that this code, like MD5, seems to
// break some optimizing compilers due to the complexity of the expressions
// and the size of the basic block.  It may be necessary to split it into
// sections, e.g. based on the four subrounds
//
// Note that this corrupts the sha->data area
//
void
shaTransform( SHA1_CONTEXT *ctx )
{
   register unsigned int A, B, C, D, E;

   // Set up first buffer
   //
   A = ctx->hash_value[0];
   B = ctx->hash_value[1];
   C = ctx->hash_value[2];
   D = ctx->hash_value[3];
   E = ctx->hash_value[4];

   // Heavy mangling, in 4 sub-rounds of 20 interations each.
   //
   subRound( A, B, C, D, E, f1, K1, ctx->buf[ 0] );
   subRound( E, A, B, C, D, f1, K1, ctx->buf[ 1] );
   subRound( D, E, A, B, C, f1, K1, ctx->buf[ 2] );
   subRound( C, D, E, A, B, f1, K1, ctx->buf[ 3] );
   subRound( B, C, D, E, A, f1, K1, ctx->buf[ 4] );
   subRound( A, B, C, D, E, f1, K1, ctx->buf[ 5] );
   subRound( E, A, B, C, D, f1, K1, ctx->buf[ 6] );
   subRound( D, E, A, B, C, f1, K1, ctx->buf[ 7] );
   subRound( C, D, E, A, B, f1, K1, ctx->buf[ 8] );
   subRound( B, C, D, E, A, f1, K1, ctx->buf[ 9] );
   subRound( A, B, C, D, E, f1, K1, ctx->buf[10] );
   subRound( E, A, B, C, D, f1, K1, ctx->buf[11] );
   subRound( D, E, A, B, C, f1, K1, ctx->buf[12] );
   subRound( C, D, E, A, B, f1, K1, ctx->buf[13] );
   subRound( B, C, D, E, A, f1, K1, ctx->buf[14] );
   subRound( A, B, C, D, E, f1, K1, ctx->buf[15] );
   subRound( E, A, B, C, D, f1, K1, expand(ctx->buf, 16) );
   subRound( D, E, A, B, C, f1, K1, expand(ctx->buf, 17) );
   subRound( C, D, E, A, B, f1, K1, expand(ctx->buf, 18) );
   subRound( B, C, D, E, A, f1, K1, expand(ctx->buf, 19) );

   subRound( A, B, C, D, E, f2, K2, expand(ctx->buf, 20) );
   subRound( E, A, B, C, D, f2, K2, expand(ctx->buf, 21) );
   subRound( D, E, A, B, C, f2, K2, expand(ctx->buf, 22) );
   subRound( C, D, E, A, B, f2, K2, expand(ctx->buf, 23) );
   subRound( B, C, D, E, A, f2, K2, expand(ctx->buf, 24) );
   subRound( A, B, C, D, E, f2, K2, expand(ctx->buf, 25) );
   subRound( E, A, B, C, D, f2, K2, expand(ctx->buf, 26) );
   subRound( D, E, A, B, C, f2, K2, expand(ctx->buf, 27) );
   subRound( C, D, E, A, B, f2, K2, expand(ctx->buf, 28) );
   subRound( B, C, D, E, A, f2, K2, expand(ctx->buf, 29) );
   subRound( A, B, C, D, E, f2, K2, expand(ctx->buf, 30) );
   subRound( E, A, B, C, D, f2, K2, expand(ctx->buf, 31) );
   subRound( D, E, A, B, C, f2, K2, expand(ctx->buf, 32) );
   subRound( C, D, E, A, B, f2, K2, expand(ctx->buf, 33) );
   subRound( B, C, D, E, A, f2, K2, expand(ctx->buf, 34) );
   subRound( A, B, C, D, E, f2, K2, expand(ctx->buf, 35) );
   subRound( E, A, B, C, D, f2, K2, expand(ctx->buf, 36) );
   subRound( D, E, A, B, C, f2, K2, expand(ctx->buf, 37) );
   subRound( C, D, E, A, B, f2, K2, expand(ctx->buf, 38) );
   subRound( B, C, D, E, A, f2, K2, expand(ctx->buf, 39) );

   subRound( A, B, C, D, E, f3, K3, expand(ctx->buf, 40) );
   subRound( E, A, B, C, D, f3, K3, expand(ctx->buf, 41) );
   subRound( D, E, A, B, C, f3, K3, expand(ctx->buf, 42) );
   subRound( C, D, E, A, B, f3, K3, expand(ctx->buf, 43) );
   subRound( B, C, D, E, A, f3, K3, expand(ctx->buf, 44) );
   subRound( A, B, C, D, E, f3, K3, expand(ctx->buf, 45) );
   subRound( E, A, B, C, D, f3, K3, expand(ctx->buf, 46) );
   subRound( D, E, A, B, C, f3, K3, expand(ctx->buf, 47) );
   subRound( C, D, E, A, B, f3, K3, expand(ctx->buf, 48) );
   subRound( B, C, D, E, A, f3, K3, expand(ctx->buf, 49) );
   subRound( A, B, C, D, E, f3, K3, expand(ctx->buf, 50) );
   subRound( E, A, B, C, D, f3, K3, expand(ctx->buf, 51) );
   subRound( D, E, A, B, C, f3, K3, expand(ctx->buf, 52) );
   subRound( C, D, E, A, B, f3, K3, expand(ctx->buf, 53) );
   subRound( B, C, D, E, A, f3, K3, expand(ctx->buf, 54) );
   subRound( A, B, C, D, E, f3, K3, expand(ctx->buf, 55) );
   subRound( E, A, B, C, D, f3, K3, expand(ctx->buf, 56) );
   subRound( D, E, A, B, C, f3, K3, expand(ctx->buf, 57) );
   subRound( C, D, E, A, B, f3, K3, expand(ctx->buf, 58) );
   subRound( B, C, D, E, A, f3, K3, expand(ctx->buf, 59) );

   subRound( A, B, C, D, E, f4, K4, expand(ctx->buf, 60) );
   subRound( E, A, B, C, D, f4, K4, expand(ctx->buf, 61) );
   subRound( D, E, A, B, C, f4, K4, expand(ctx->buf, 62) );
   subRound( C, D, E, A, B, f4, K4, expand(ctx->buf, 63) );
   subRound( B, C, D, E, A, f4, K4, expand(ctx->buf, 64) );
   subRound( A, B, C, D, E, f4, K4, expand(ctx->buf, 65) );
   subRound( E, A, B, C, D, f4, K4, expand(ctx->buf, 66) );
   subRound( D, E, A, B, C, f4, K4, expand(ctx->buf, 67) );
   subRound( C, D, E, A, B, f4, K4, expand(ctx->buf, 68) );
   subRound( B, C, D, E, A, f4, K4, expand(ctx->buf, 69) );
   subRound( A, B, C, D, E, f4, K4, expand(ctx->buf, 70) );
   subRound( E, A, B, C, D, f4, K4, expand(ctx->buf, 71) );
   subRound( D, E, A, B, C, f4, K4, expand(ctx->buf, 72) );
   subRound( C, D, E, A, B, f4, K4, expand(ctx->buf, 73) );
   subRound( B, C, D, E, A, f4, K4, expand(ctx->buf, 74) );
   subRound( A, B, C, D, E, f4, K4, expand(ctx->buf, 75) );
   subRound( E, A, B, C, D, f4, K4, expand(ctx->buf, 76) );
   subRound( D, E, A, B, C, f4, K4, expand(ctx->buf, 77) );
   subRound( C, D, E, A, B, f4, K4, expand(ctx->buf, 78) );
   subRound( B, C, D, E, A, f4, K4, expand(ctx->buf, 79) );

   // Build message digest
   //
   ctx->hash_value[0] += A;
   ctx->hash_value[1] += B;
   ctx->hash_value[2] += C;
   ctx->hash_value[3] += D;
   ctx->hash_value[4] += E;
}


// SHA is defined in big-endian form, so this converts the buffer from
// bytes to words, independent of the machine's native endianness.
//
// Assuming a consistent byte ordering for the machine, this also
// has the magic property of being self-inverse.  It is used as
// such.
//
static void
byteReverse( unsigned int *buffer,
             unsigned int  byteCount )
{
#ifndef __BYTE_ORDER
#error  "Endianess MUST be defined"
#endif
#if  __BYTE_ORDER == __LITTLE_ENDIAN
   CK_ULONG value, val;

   byteCount /= sizeof(CK_ULONG_32);

   while (byteCount--) {
      val = *buffer;
      value = ((0x000000FF & val) << 24) |
              ((0x0000FF00 & val) << 8 ) |
              ((0x00FF0000 & val) >> 8 ) |
              ((0xFF000000 & val) >> 24);

      *buffer++ = value;
   }
#endif

// JRM - this code gives funky results on Linux/Intel.
//       I assume this is a GCC issue since regression tests passed on NT
//
//   byteCount /= sizeof(CK_ULONG);
//   while ( byteCount-- ) {
//      value = (CK_ULONG)((unsigned)((CK_BYTE *)buffer)[0] << 8 | ((CK_BYTE *)buffer)[1]) << 16 |
//                        ((unsigned)((CK_BYTE *)buffer)[2] << 8 | ((CK_BYTE *)buffer)[3]);
//      *buffer++ = value;
//   }
}


void
shaUpdate( SHA1_CONTEXT      * ctx,
           CK_BYTE const     * buffer,
           CK_ULONG            count)
{
   CK_ULONG t;

   // Update bitcount
   //
   t = ctx->bits_lo;
   if ((ctx->bits_lo = t + count) < t)
      ctx->bits_hi++;   // Carry from low to high

   t &= 0x3f;  // Bytes already in ctx->buf

   // Handle any leading odd-sized chunks
   //
   if (t) {
      CK_BYTE *p = (CK_BYTE *)ctx->buf + t;

      t = 64-t;
      if (count < t) {
         memcpy(p, buffer, count);
         return;
      }
      memcpy(p, buffer, t);
      byteReverse(ctx->buf, SHA1_BLOCK_SIZE);
      shaTransform(ctx);
      buffer += t;
      count -= t;
   }

   // Process data in SHA1_BLOCK_SIZE chunks
   //
   while (count >= SHA1_BLOCK_SIZE) {
      memcpy(ctx->buf, buffer, SHA1_BLOCK_SIZE);
      byteReverse(ctx->buf, SHA1_BLOCK_SIZE);
      shaTransform(ctx);
      buffer += SHA1_BLOCK_SIZE;
      count -= SHA1_BLOCK_SIZE;
   }

   // Handle any remaining bytes of data.
   //
   memcpy(ctx->buf, buffer, count);
}


// Final wrapup - pad to 64-byte boundary with the bit pattern
// 1 0* (64-bit count of bits processed, MSB-first)
//
void
shaFinal( SHA1_CONTEXT * ctx,
          CK_BYTE      * hash )
{
   int count;
   CK_BYTE *p;

   // Compute number of bytes mod 64
   //
   count = (int)ctx->bits_lo & 0x3F;

   // Set the first char of padding to 0x80.
   // This is safe since there is always at least one byte free
   //
   p = (CK_BYTE *)ctx->buf + count;
   *p++ = 0x80;

   // Bytes of padding needed to make 64 bytes
   //
   count = SHA1_BLOCK_SIZE - 1 - count;

   // Pad out to 56 mod 64
   //
   if (count < 8) {
      // Two lots of padding:  Pad the first block to 64 bytes
      //
      memset(p, 0, count);
      byteReverse(ctx->buf, SHA1_BLOCK_SIZE);
      shaTransform(ctx);

      // Now fill the next block with 56 bytes
      //
      memset(ctx->buf, 0, SHA1_BLOCK_SIZE-8);
   } else {
      // Pad block to 56 bytes
      //
      memset(p, 0, count-8);
   }
   byteReverse(ctx->buf, SHA1_BLOCK_SIZE-8);

   // Append length in *bits* and transform
   //
   ctx->buf[14] = ctx->bits_hi << 3 | ctx->bits_lo >> 29;
   ctx->buf[15] = ctx->bits_lo << 3;

   shaTransform(ctx);

   // Store output hash in buffer
   //
   byteReverse(ctx->hash_value, SHA1_HASH_SIZE);
   memcpy(hash, ctx->hash_value, SHA1_HASH_SIZE);
}
