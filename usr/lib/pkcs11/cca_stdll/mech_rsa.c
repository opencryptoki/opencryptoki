/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki CCA token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
 *
 */


// File:  mech_rsa.c
//
// Mechanisms for RSA
//
// Routines contained within:

#include <pthread.h>
#include <stdio.h>

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
rsa_pkcs_encrypt( SESSION           *sess,
                  CK_BBOOL           length_only,
                  ENCR_DECR_CONTEXT *ctx,
                  CK_BYTE           *in_data,
                  CK_ULONG           in_data_len,
                  CK_BYTE           *out_data,
                  CK_ULONG          *out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (in_data_len > (modulus_bytes - 11)){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_DATA_LEN_RANGE;
   }

   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   if (*out_data_len < modulus_bytes) {
      *out_data_len = modulus_bytes;
      OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = ckm_rsa_encrypt( in_data, in_data_len, out_data, out_data_len, key_obj );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_RSA_ENCRYPT);
   return rc;
}


//
//
CK_RV
rsa_pkcs_decrypt( SESSION           *sess,
                  CK_BBOOL           length_only,
                  ENCR_DECR_CONTEXT *ctx,
                  CK_BYTE           *in_data,
                  CK_ULONG           in_data_len,
                  CK_BYTE           *out_data,
                  CK_ULONG          *out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE)
      return CKR_FUNCTION_FAILED;
   else
      modulus_bytes = attr->ulValueLen;


   // check input data length restrictions
   //
   if (in_data_len != modulus_bytes){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      // this is not exact but it's the upper bound; otherwise we'll need
      // to do the RSA operation just to get the required length
      //
      *out_data_len = modulus_bytes - 11;
      return CKR_OK;
   }

   rc = ckm_rsa_decrypt( in_data, modulus_bytes, out_data, out_data_len, key_obj );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_RSA_DECRYPT);

   if (rc == CKR_DATA_LEN_RANGE){
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   return rc;
}


//
//
CK_RV
rsa_pkcs_sign( SESSION             *sess,
               CK_BBOOL             length_only,
               SIGN_VERIFY_CONTEXT *ctx,
               CK_BYTE             *in_data,
               CK_ULONG             in_data_len,
               CK_BYTE             *out_data,
               CK_ULONG            *out_data_len )
{
   OBJECT          *key_obj   = NULL;
   CK_ATTRIBUTE    *attr      = NULL;
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }

   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE)
      return CKR_FUNCTION_FAILED;
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (in_data_len > modulus_bytes - 11) {
      OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
      return CKR_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   if (*out_data_len < modulus_bytes) {
      *out_data_len = modulus_bytes;
      OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = ckm_rsa_sign( in_data, in_data_len, out_data, out_data_len, key_obj );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_RSA_SIGN);
   return rc;
}


//
//
CK_RV
rsa_pkcs_verify( SESSION             * sess,
                 SIGN_VERIFY_CONTEXT * ctx,
                 CK_BYTE             * in_data,
                 CK_ULONG              in_data_len,
                 CK_BYTE             * signature,
                 CK_ULONG              sig_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (sig_len != modulus_bytes){
      OCK_LOG_ERR(ERR_SIGNATURE_LEN_RANGE);
      return CKR_SIGNATURE_LEN_RANGE;
   }
   rc = ckm_rsa_verify( in_data, in_data_len, signature, sig_len, key_obj );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_RSA_VERIFY);

   return rc;
}


//
//
#if 0
CK_RV
rsa_pkcs_verify_recover( SESSION             * sess,
                         CK_BBOOL              length_only,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * signature,
                         CK_ULONG              sig_len,
                         CK_BYTE             * out_data,
                         CK_ULONG            * out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   if (!sess || !ctx || !out_data_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (sig_len != modulus_bytes){
      OCK_LOG_ERR(ERR_SIGNATURE_LEN_RANGE);
      return CKR_SIGNATURE_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   // verify is a public key operation --> encrypt
   //
   rc = ckm_rsa_encrypt( signature, modulus_bytes, out_data, out_data_len, key_obj );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_RSA_ENCRYPT);

   return rc;
}
#endif

//
//
CK_RV
rsa_hash_pkcs_sign( SESSION              * sess,
                    CK_BBOOL               length_only,
                    SIGN_VERIFY_CONTEXT  * ctx,
                    CK_BYTE              * in_data,
                    CK_ULONG               in_data_len,
                    CK_BYTE              * signature,
                    CK_ULONG             * sig_len )
{
   CK_BYTE            * ber_data  = NULL;
   CK_BYTE            * octet_str = NULL;
   CK_BYTE            * oid       = NULL;
   CK_BYTE            * tmp       = NULL;

   CK_ULONG             buf1[16];  // 64 bytes is more than enough

   CK_BYTE              hash[SHA256_HASH_SIZE];  // must be large enough for the largest hash
						 // the CCA token supports
   DIGEST_CONTEXT       digest_ctx;
   SIGN_VERIFY_CONTEXT  sign_ctx;
   CK_MECHANISM         digest_mech;
   CK_MECHANISM         sign_mech;
   CK_ULONG             ber_data_len, hash_len, octet_str_len, oid_len;
   CK_RV                rc;

   if (!sess || !ctx || !in_data){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   memset( &digest_ctx, 0x0, sizeof(digest_ctx) );
   memset( &sign_ctx,   0x0, sizeof(sign_ctx)   );

   if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS) {
      digest_mech.mechanism      = CKM_MD2;
      oid = ber_AlgMd2;
      oid_len = ber_AlgMd2Len;

   }
   else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
      digest_mech.mechanism      = CKM_MD5;
      oid = ber_AlgMd5;
      oid_len = ber_AlgMd5Len;
   }
   else if (ctx->mech.mechanism == CKM_SHA256_RSA_PKCS) {
      digest_mech.mechanism      = CKM_SHA256;
      oid = ber_AlgSha256;
      oid_len = ber_AlgSha256Len;
   }
   else {
      digest_mech.mechanism      = CKM_SHA_1;
      oid = ber_AlgSha1;
      oid_len = ber_AlgSha1Len;
   }

   digest_mech.ulParameterLen = 0;
   digest_mech.pParameter     = NULL;

   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DIGEST_INIT);
      return rc;
   }
   hash_len = sizeof(hash);
   rc = digest_mgr_digest( sess, length_only, &digest_ctx, in_data, in_data_len, hash, &hash_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DIGEST);
      return rc;
   }
      // build the BER-encodings
     
    rc = ber_encode_OCTET_STRING( FALSE, &octet_str, &octet_str_len, hash, hash_len );
    if (rc != CKR_OK){
       OCK_LOG_ERR(ERR_ENCODE_OCTET);
       goto error;
    }
    tmp = (CK_BYTE *)buf1;
    memcpy( tmp,           oid,       oid_len );
    memcpy( tmp + oid_len, octet_str, octet_str_len);
      
    rc = ber_encode_SEQUENCE( FALSE, &ber_data, &ber_data_len, tmp, (oid_len + octet_str_len) );
    if (rc != CKR_OK){
       OCK_LOG_ERR(ERR_ENCODE_SEQ);
       goto error;
    }
    // sign the BER-encoded data block
   

   sign_mech.mechanism      = CKM_RSA_PKCS;
   sign_mech.ulParameterLen = 0;
   sign_mech.pParameter     = NULL;

   rc = sign_mgr_init( sess, &sign_ctx, &sign_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_SIGN_INIT);
      goto error;
   }
   //rc = sign_mgr_sign( sess, length_only, &sign_ctx, hash, hash_len, signature, sig_len );
   rc = sign_mgr_sign( sess, length_only, &sign_ctx, ber_data, ber_data_len, signature, sig_len );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_SIGN);

error:
   if (octet_str) free( octet_str );
   if (ber_data)  free( ber_data );
   sign_mgr_cleanup( &sign_ctx );
   return rc;
}


//
//
CK_RV
rsa_hash_pkcs_sign_update( SESSION              * sess,
                           SIGN_VERIFY_CONTEXT  * ctx,
                           CK_BYTE              * in_data,
                           CK_ULONG               in_data_len )
{
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_MECHANISM          digest_mech;
   CK_RV                 rc;

   if (!sess || !ctx || !in_data){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   if (context->flag == FALSE) {
      if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS)
         digest_mech.mechanism = CKM_MD2;
      else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS)
         digest_mech.mechanism = CKM_MD5;
      else if (ctx->mech.mechanism == CKM_SHA256_RSA_PKCS)
         digest_mech.mechanism = CKM_SHA256;
      else
         digest_mech.mechanism = CKM_SHA_1;

      digest_mech.ulParameterLen = 0;
      digest_mech.pParameter     = NULL;

      rc = digest_mgr_init( sess, &context->hash_context, &digest_mech );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_DIGEST_INIT);
         return rc;
      }
      context->flag = TRUE;
   }

   rc = digest_mgr_digest_update( sess, &context->hash_context, in_data, in_data_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DIGEST_UPDATE);
      return rc;
   }
   return CKR_OK;
}


//
//
CK_RV
rsa_hash_pkcs_verify( SESSION              * sess,
                      SIGN_VERIFY_CONTEXT  * ctx,
                      CK_BYTE              * in_data,
                      CK_ULONG               in_data_len,
                      CK_BYTE              * signature,
                      CK_ULONG               sig_len )
{
   CK_BYTE            * ber_data  = NULL;
   CK_BYTE            * octet_str = NULL;
   CK_BYTE            * oid       = NULL;
   CK_BYTE            * tmp       = NULL;

   CK_ULONG             buf1[16];  // 64 bytes is more than enough
   CK_BYTE              hash[SHA256_HASH_SIZE];
   DIGEST_CONTEXT       digest_ctx;
   SIGN_VERIFY_CONTEXT  verify_ctx;
   CK_MECHANISM         digest_mech;
   CK_MECHANISM         verify_mech;
   CK_ULONG             ber_data_len, hash_len, octet_str_len, oid_len;
   CK_RV                rc;

   if (!sess || !ctx || !in_data){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   memset( &digest_ctx, 0x0, sizeof(digest_ctx) );
   memset( &verify_ctx, 0x0, sizeof(verify_ctx) );

   if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS) {
      digest_mech.mechanism      = CKM_MD2;
      oid = ber_AlgMd2;
      oid_len = ber_AlgMd2Len;
   }
   else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
      digest_mech.mechanism      = CKM_MD5;
      oid = ber_AlgMd5;
      oid_len = ber_AlgMd5Len;
   }
   else if (ctx->mech.mechanism == CKM_SHA256_RSA_PKCS) {
      digest_mech.mechanism      = CKM_SHA256;
      oid = ber_AlgSha256;
      oid_len = ber_AlgSha256Len;
   }
   else {
      digest_mech.mechanism      = CKM_SHA_1;
      oid = ber_AlgSha1;
      oid_len = ber_AlgSha1Len;
   }


   digest_mech.ulParameterLen = 0;
   digest_mech.pParameter     = NULL;

   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DIGEST_INIT);
      return rc;
   }
   hash_len = sizeof(hash);
   rc = digest_mgr_digest( sess, FALSE, &digest_ctx, in_data, in_data_len, hash, &hash_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DIGEST);
      return rc;
   }

   // Build the BER encoding
   //
   rc = ber_encode_OCTET_STRING( FALSE, &octet_str, &octet_str_len, hash, hash_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_ENCODE_OCTET);
      goto done;
   }
   tmp = (CK_BYTE *)buf1;
   memcpy( tmp,           oid,       oid_len );
   memcpy( tmp + oid_len, octet_str, octet_str_len );

   rc = ber_encode_SEQUENCE( FALSE, &ber_data, &ber_data_len, tmp, (oid_len + octet_str_len) );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_ENCODE_SEQ);
      goto done;
   }
   // Verify the Signed BER-encoded Data block
   //
   verify_mech.mechanism      = CKM_RSA_PKCS;
   verify_mech.ulParameterLen = 0;
   verify_mech.pParameter     = NULL;

   rc = verify_mgr_init( sess, &verify_ctx, &verify_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_VERIFY_INIT);
      goto done;
   }
   //rc = verify_mgr_verify( sess, &verify_ctx, hash, hash_len, signature, sig_len );
   rc = verify_mgr_verify( sess, &verify_ctx, ber_data, ber_data_len, signature, sig_len );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_VERIFY);
done:
   if (octet_str) free( octet_str );
   if (ber_data)  free( ber_data );
   sign_mgr_cleanup( &verify_ctx );
   return rc;
}

//
//
CK_RV
rsa_hash_pkcs_verify_update( SESSION              * sess,
                             SIGN_VERIFY_CONTEXT  * ctx,
                             CK_BYTE              * in_data,
                             CK_ULONG               in_data_len )
{
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_MECHANISM          digest_mech;
   CK_RV                 rc;

   if (!sess || !ctx || !in_data){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   if (context->flag == FALSE) {
      if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS)
         digest_mech.mechanism = CKM_MD2;
      else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS)
         digest_mech.mechanism = CKM_MD5;
      else if (ctx->mech.mechanism == CKM_SHA256_RSA_PKCS)
         digest_mech.mechanism = CKM_SHA256;
      else
         digest_mech.mechanism = CKM_SHA_1;

      digest_mech.ulParameterLen = 0;
      digest_mech.pParameter     = NULL;

      rc = digest_mgr_init( sess, &context->hash_context, &digest_mech );
      if (rc != CKR_OK){
         OCK_LOG_ERR(ERR_DIGEST_INIT);
         return rc;
      }
      context->flag = TRUE;
   }

   rc = digest_mgr_digest_update( sess, &context->hash_context, in_data, in_data_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DIGEST_UPDATE);
      return rc;
   }
   return CKR_OK;
}


//
//
CK_RV
rsa_hash_pkcs_sign_final( SESSION              * sess,
                          CK_BBOOL               length_only,
                          SIGN_VERIFY_CONTEXT  * ctx,
                          CK_BYTE              * signature,
                          CK_ULONG             * sig_len )
{
   CK_BYTE            * ber_data  = NULL;
   CK_BYTE            * octet_str = NULL;
   CK_BYTE            * oid       = NULL;
   CK_BYTE            * tmp       = NULL;

   CK_ULONG              buf1[16];  // 64 bytes is more than enough

   CK_BYTE               hash[SHA256_HASH_SIZE];
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_ULONG              ber_data_len, hash_len, octet_str_len, oid_len;
   CK_MECHANISM          sign_mech;
   SIGN_VERIFY_CONTEXT   sign_ctx;
   CK_RV                 rc;

   if (!sess || !ctx || !sig_len){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS) {
      oid = ber_AlgMd2;
      oid_len = ber_AlgMd2Len;
   }
   else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
      oid = ber_AlgMd5;
      oid_len = ber_AlgMd5Len;
   }
   else if (ctx->mech.mechanism == CKM_SHA256_RSA_PKCS) {
      oid = ber_AlgSha256;
      oid_len = ber_AlgSha256Len;
   }
   else {
      oid = ber_AlgSha1;
      oid_len = ber_AlgSha1Len;
   }

   memset( &sign_ctx, 0x0, sizeof(sign_ctx));

   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, length_only, &context->hash_context, hash, &hash_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DIGEST_FINAL);
      return rc;
   }
   // Build the BER Encoded Data block
   //
   rc = ber_encode_OCTET_STRING( FALSE, &octet_str, &octet_str_len, hash, hash_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_ENCODE_OCTET);
      goto done;
   }
   tmp = (CK_BYTE *)buf1;
   memcpy( tmp,           oid,       oid_len );
   memcpy( tmp + oid_len, octet_str, octet_str_len );

   rc = ber_encode_SEQUENCE( FALSE, &ber_data, &ber_data_len, tmp, (oid_len + octet_str_len) );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_ENCODE_SEQ);
      goto done;
   }
   // sign the BER-encoded data block
   //

   sign_mech.mechanism      = CKM_RSA_PKCS;
   sign_mech.ulParameterLen = 0;
   sign_mech.pParameter     = NULL;

   rc = sign_mgr_init( sess, &sign_ctx, &sign_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_SIGN_INIT);
      goto done;
   }
   //rc = sign_mgr_sign( sess, length_only, &sign_ctx, hash, hash_len, signature, sig_len );
   rc = sign_mgr_sign( sess, length_only, &sign_ctx, ber_data, ber_data_len, signature, sig_len );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_SIGN);

   if (length_only == TRUE || rc == CKR_BUFFER_TOO_SMALL) {
      sign_mgr_cleanup( &sign_ctx );
      return rc;
   }

done:
   if (octet_str) free( octet_str );
   if (ber_data)  free( ber_data );
   sign_mgr_cleanup( &sign_ctx );
   return rc;
}


//
//
CK_RV
rsa_hash_pkcs_verify_final( SESSION              * sess,
                            SIGN_VERIFY_CONTEXT  * ctx,
                            CK_BYTE              * signature,
                            CK_ULONG               sig_len )
{
   CK_BYTE            * ber_data  = NULL;
   CK_BYTE            * octet_str = NULL;
   CK_BYTE            * oid       = NULL;
   CK_BYTE            * tmp       = NULL;

   CK_ULONG             buf1[16];   // 64 bytes is more than enough
   CK_BYTE               hash[SHA256_HASH_SIZE];
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_ULONG              ber_data_len, hash_len, octet_str_len, oid_len;
   CK_MECHANISM          verify_mech;
   SIGN_VERIFY_CONTEXT   verify_ctx;
   CK_RV                 rc;

   if (!sess || !ctx || !signature){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS) {
      oid = ber_AlgMd2;
      oid_len = ber_AlgMd2Len;
   }
   else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
      oid = ber_AlgMd5;
      oid_len = ber_AlgMd5Len;
   }
   else if (ctx->mech.mechanism == CKM_SHA256_RSA_PKCS) {
      oid = ber_AlgSha256;
      oid_len = ber_AlgSha256Len;
   }
   else {
      oid = ber_AlgSha1;
      oid_len = ber_AlgSha1Len;
   }

   memset( &verify_ctx, 0x0, sizeof(verify_ctx));

   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, FALSE, &context->hash_context, hash, &hash_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DIGEST_FINAL);
      return rc;
   }
   // Build the BER encoding
   //
   rc = ber_encode_OCTET_STRING( FALSE, &octet_str, &octet_str_len, hash, hash_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_ENCODE_OCTET);
      goto done;
   }
   tmp = (CK_BYTE *)buf1;
   memcpy( tmp,           oid,       oid_len );
   memcpy( tmp + oid_len, octet_str, octet_str_len );

   rc = ber_encode_SEQUENCE( FALSE, &ber_data, &ber_data_len, tmp, (oid_len + octet_str_len) );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_ENCODE_SEQ);
      goto done;
   }
   // verify the signed BER-encoded data block
   //

   verify_mech.mechanism      = CKM_RSA_PKCS;
   verify_mech.ulParameterLen = 0;
   verify_mech.pParameter     = NULL;

   rc = verify_mgr_init( sess, &verify_ctx, &verify_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_VERIFY_INIT);
      goto done;
   }
   //rc = verify_mgr_verify( sess, &verify_ctx, hash, hash_len, signature, sig_len );
   rc = verify_mgr_verify( sess, &verify_ctx, ber_data, ber_data_len, signature, sig_len );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_VERIFY);
done:
   if (octet_str) free( octet_str );
   if (ber_data)  free( ber_data );
   verify_mgr_cleanup( &verify_ctx );
   return rc;
}


//
// mechanisms
//



//
//
CK_RV
ckm_rsa_key_pair_gen( TEMPLATE  * publ_tmpl,
                      TEMPLATE  * priv_tmpl )
{
   CK_RV                rc;

   rc = token_specific.t_rsa_generate_keypair(publ_tmpl, priv_tmpl);
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_KEYGEN);

   return rc;
}


//
//
CK_RV
ckm_rsa_encrypt( CK_BYTE   * in_data,
                 CK_ULONG    in_data_len,
                 CK_BYTE   * out_data,
                 CK_ULONG  * out_data_len,
                 OBJECT    * key_obj )
{
   CK_ATTRIBUTE      * attr    = NULL;
   CK_OBJECT_CLASS     keyclass;
   CK_RV               rc;

   rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a public key
   //
   if (keyclass != CKO_PUBLIC_KEY){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   
   rc = token_specific.t_rsa_encrypt(in_data, in_data_len, out_data, out_data_len, key_obj);
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_RSA_ENCRYPT_TOK_SPEC);

   return rc;
}


//
//
CK_RV
ckm_rsa_decrypt( CK_BYTE   * in_data,
                 CK_ULONG    in_data_len,
                 CK_BYTE   * out_data,
                 CK_ULONG  * out_data_len,
                 OBJECT    * key_obj )
{
   CK_ATTRIBUTE      * attr     = NULL;
   CK_OBJECT_CLASS     keyclass;
   CK_RV               rc;

   rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a private key
   //
   if (keyclass != CKO_PRIVATE_KEY){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   rc = token_specific.t_rsa_decrypt(in_data, in_data_len, out_data, out_data_len, key_obj);
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_RSA_DECRYPT_TOK_SPEC);

   return rc;
}

//
//
CK_RV
ckm_rsa_sign( CK_BYTE   * in_data,
              CK_ULONG    in_data_len,
              CK_BYTE   * out_data,
              CK_ULONG  * out_data_len,
              OBJECT    * key_obj )
{
   CK_ATTRIBUTE      * attr     = NULL;
   CK_OBJECT_CLASS     keyclass;
   CK_RV               rc;

   rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a private key
   //
   if (keyclass != CKO_PRIVATE_KEY){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   rc = token_specific.t_rsa_sign(in_data, in_data_len, out_data, out_data_len, key_obj);
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_RSA_SIGN_TOK_SPEC);

   return rc;
}

//
//
CK_RV
ckm_rsa_verify( CK_BYTE   * in_data,
                CK_ULONG    in_data_len,
                CK_BYTE   * out_data,
                CK_ULONG    out_data_len,
                OBJECT    * key_obj )
{
   CK_ATTRIBUTE      * attr     = NULL;
   CK_OBJECT_CLASS     keyclass;
   CK_RV               rc;

   rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a private key
   //
   if (keyclass != CKO_PUBLIC_KEY){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   rc = token_specific.t_rsa_verify(in_data, in_data_len, out_data, out_data_len, key_obj);
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_RSA_VERIFY);

   return rc;
}

