/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki CCA token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
 *
 */

// File:  mech_ec.c
//
// Mechanisms for Elliptic Curve (EC)
//
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"
#include "tok_specific.h"
#include "ec_defs.h"

CK_BYTE brainpoolP160r1[] = { 0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,
			      0x01,0x01,0x01 };
CK_BYTE brainpoolP192r1[] = { 0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,
			      0x01,0x01,0x03 };
CK_BYTE brainpoolP224r1[] = { 0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,
			      0x01,0x01,0x05 };
CK_BYTE brainpoolP256r1[] = { 0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,
			      0x01,0x01,0x07 };
CK_BYTE brainpoolP320r1[] = { 0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,
			      0x01,0x01,0x09 };
CK_BYTE brainpoolP384r1[] = { 0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,
			      0x01,0x01,0x0B };
CK_BYTE brainpoolP512r1[] = { 0x06,0x09,0x2B,0x24,0x03,0x03,0x02,0x08,
			      0x01,0x01,0x0D };
CK_BYTE prime192[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x01 };
CK_BYTE secp224[] = { 0x06,0x05,0x2B,0x81,0x04,0x00,0x21 };
CK_BYTE prime256[] = { 0x06,0x08,0x2A,0x86,0x48,0xCE,0x3D,0x03,0x01,0x07 };
CK_BYTE secp384[] = { 0x06,0x05,0x2B,0x81,0x04,0x00,0x22 };
CK_BYTE secp521[] = { 0x06,0x05,0x2B,0x81,0x04,0x00,0x23 };

struct _ec der_ec_supported[NUMEC] = {
	{BRAINPOOL_CURVE, CURVE160, sizeof(brainpoolP160r1), &brainpoolP160r1},
	{BRAINPOOL_CURVE, CURVE192, sizeof(brainpoolP192r1), &brainpoolP192r1},
	{BRAINPOOL_CURVE, CURVE224, sizeof(brainpoolP224r1), &brainpoolP224r1},
	{BRAINPOOL_CURVE, CURVE256, sizeof(brainpoolP256r1), &brainpoolP256r1},
	{BRAINPOOL_CURVE, CURVE320, sizeof(brainpoolP320r1), &brainpoolP320r1},
	{BRAINPOOL_CURVE, CURVE384, sizeof(brainpoolP384r1), &brainpoolP384r1},
	{BRAINPOOL_CURVE, CURVE512, sizeof(brainpoolP512r1), &brainpoolP512r1},
	{PRIME_CURVE, CURVE192, sizeof(prime192), &prime192},
	{PRIME_CURVE, CURVE224, sizeof(secp224), &secp224},
	{PRIME_CURVE, CURVE256, sizeof(prime256), &prime256},
	{PRIME_CURVE, CURVE384, sizeof(secp384), &secp384},
	{PRIME_CURVE, CURVE521, sizeof(secp521), &secp521},
};


CK_RV get_ecsiglen(OBJECT *key_obj, CK_ULONG *size)
{
	CK_BBOOL flag;
	CK_ATTRIBUTE *attr = NULL;
	int i;

	flag = template_attribute_find(key_obj->template, CKA_ECDSA_PARAMS,
					&attr);
	if (flag == FALSE) {
		TRACE_ERROR("Could not find CKA_ECDSA_PARAMS for the key.\n");
		return CKR_FUNCTION_FAILED;
	}

	/* loop thru supported curves to find the size.
	 * both pkcs#11v2.20 and CCA expect the signature length to be
	 * twice the length of p.
	 * (See EC Signatures in pkcs#11v2.20 and docs for CSNDDSG.)
	 */
	for (i = 0; i < NUMEC; i++) {
		if ((memcmp(attr->pValue, der_ec_supported[i].data,
		     attr->ulValueLen) == 0)) {
			*size = der_ec_supported[i].len_bits;
			/* round up if necessary */
			if ((*size % 8) == 0)
				*size = (*size / 8) * 2;
			else
				*size = ((*size / 8) + 1) * 2;
			TRACE_DEVEL("getlen, curve = %d, size = %lu\n",
				    der_ec_supported[i].len_bits, *size);
			return CKR_OK;
		}
	}

	TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
	return CKR_MECHANISM_PARAM_INVALID;
}

CK_RV
ckm_ec_key_pair_gen( TEMPLATE  * publ_tmpl,
		TEMPLATE  * priv_tmpl )
{
	CK_RV rc;
	rc = token_specific.t_ec_generate_keypair(publ_tmpl, priv_tmpl);
	if (rc != CKR_OK)
		TRACE_ERROR("Key Generation failed\n");
	return rc;
}

CK_RV
ckm_ec_sign( CK_BYTE		*in_data,
		CK_ULONG	in_data_len,
		CK_BYTE		*out_data,
		CK_ULONG	*out_data_len,
		OBJECT		*key_obj )
{
	CK_ATTRIBUTE		* attr     = NULL;
	CK_OBJECT_CLASS		keyclass;
	CK_RV			rc;

	rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
	if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_CLASS in the template\n");
		return CKR_FUNCTION_FAILED;
	}
	else
		keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

	// this had better be a private key
	//
	if (keyclass != CKO_PRIVATE_KEY){
		TRACE_ERROR("This operation requires a private key.\n");
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}
	rc = token_specific.t_ec_sign(in_data, in_data_len, out_data,
					out_data_len, key_obj);
	if (rc != CKR_OK)
		TRACE_DEVEL("EC Sign failed.\n");

	return rc;
}

CK_RV
ec_sign( SESSION			*sess,
               CK_BBOOL			length_only,
               SIGN_VERIFY_CONTEXT	*ctx,
               CK_BYTE			*in_data,
               CK_ULONG			in_data_len,
               CK_BYTE			*out_data,
               CK_ULONG			*out_data_len )
{
	OBJECT          *key_obj   = NULL;
	CK_ULONG         plen;
	CK_RV            rc;

	if (!sess || !ctx || !out_data_len){
		TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	rc = object_mgr_find_in_map1( ctx->key, &key_obj );
	if (rc != CKR_OK){
		TRACE_ERROR("Failed to acquire key from specified handle");
		if (rc == CKR_OBJECT_HANDLE_INVALID)
			return CKR_KEY_HANDLE_INVALID;
		else
			return rc;
	}

	rc = get_ecsiglen(key_obj, &plen);
	if (rc != CKR_OK) {
		TRACE_DEVEL("get_ecsiglen failed.\n");
		return rc;
	}

	if (length_only == TRUE) {
		*out_data_len = plen;
		return CKR_OK;
	}

	if (*out_data_len < plen) {
		TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
		return CKR_BUFFER_TOO_SMALL;
	}

	rc = ckm_ec_sign( in_data, in_data_len, out_data,
			out_data_len, key_obj );
	return rc;
}

CK_RV
ckm_ec_verify( CK_BYTE		*in_data,
		CK_ULONG	in_data_len,
		CK_BYTE		*out_data,
		CK_ULONG	out_data_len,
		OBJECT		*key_obj )
{
	CK_ATTRIBUTE	*attr = NULL;
	CK_OBJECT_CLASS	keyclass;
	CK_RV		rc;

	rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
	if (rc == FALSE){
		TRACE_ERROR("Could not find CKA_CLASS in the template\n");
		return CKR_FUNCTION_FAILED;
	}
	else
		keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

	// this had better be a public key
	//
	if (keyclass != CKO_PUBLIC_KEY){
		TRACE_ERROR("This operation requires a public key.\n");
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	rc = token_specific.t_ec_verify(in_data, in_data_len,
			out_data, out_data_len, key_obj);
	if (rc != CKR_OK)
		TRACE_ERROR("Token specific ec verify failed.\n");

	return rc;
}

CK_RV
ec_verify(SESSION		*sess,
	SIGN_VERIFY_CONTEXT	*ctx,
	CK_BYTE			*in_data,
	CK_ULONG		in_data_len,
	CK_BYTE			*signature,
	CK_ULONG		sig_len )
{
	OBJECT          *key_obj  = NULL;
	CK_ULONG         plen;
	CK_RV            rc;


	rc = object_mgr_find_in_map1(ctx->key, &key_obj);
	if (rc != CKR_OK){
		TRACE_ERROR("Failed to acquire key from specified handle");
		if (rc == CKR_OBJECT_HANDLE_INVALID)
			return CKR_KEY_HANDLE_INVALID;
		else
			return rc;
	}

	rc = get_ecsiglen(key_obj, &plen);
	if (rc != CKR_OK) {
		TRACE_DEVEL("get_ecsiglen failed.\n");
		return rc;
	}

	// check input data length restrictions
	//
	if (sig_len > plen){
		TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
		return CKR_SIGNATURE_LEN_RANGE;
	}
	rc = ckm_ec_verify(in_data, in_data_len, signature,
			sig_len, key_obj);

	return rc;
}

CK_RV
ec_hash_sign( SESSION              * sess,
		CK_BBOOL               length_only,
		SIGN_VERIFY_CONTEXT  * ctx,
		CK_BYTE              * in_data,
		CK_ULONG               in_data_len,
		CK_BYTE              * signature,
		CK_ULONG             * sig_len )
{
   CK_BYTE              hash[SHA1_HASH_SIZE];
   DIGEST_CONTEXT       digest_ctx;
   SIGN_VERIFY_CONTEXT  sign_ctx;
   CK_MECHANISM         digest_mech;
   CK_MECHANISM         sign_mech;
   CK_ULONG             hash_len;
   CK_RV                rc;

   if (!sess || !ctx || !in_data){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   memset( &digest_ctx, 0x0, sizeof(digest_ctx) );
   memset( &sign_ctx,   0x0, sizeof(sign_ctx)   );

   digest_mech.mechanism      = CKM_SHA_1;
   digest_mech.ulParameterLen = 0;
   digest_mech.pParameter     = NULL;

   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK){
      TRACE_DEVEL("Digest Mgr Init failed.\n");
      return rc;
   }
   hash_len = sizeof(hash);
   rc = digest_mgr_digest( sess, length_only, &digest_ctx, in_data, in_data_len, hash, &hash_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("Digest Mgr Digest failed.\n");
      return rc;
   }

    sign_mech.mechanism      = CKM_ECDSA;
    sign_mech.ulParameterLen = 0;
    sign_mech.pParameter     = NULL;

   rc = sign_mgr_init( sess, &sign_ctx, &sign_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      TRACE_DEVEL("Sign Mgr Init failed.\n");
      goto error;
   }

   rc = sign_mgr_sign( sess, length_only, &sign_ctx, hash, hash_len, signature, sig_len );
   if (rc != CKR_OK)
      TRACE_DEVEL("Sign Mgr Sign failed.\n");

error:
   sign_mgr_cleanup( &sign_ctx );
   return rc;
}

CK_RV
ec_hash_sign_update( SESSION              * sess,
                     SIGN_VERIFY_CONTEXT  * ctx,
                     CK_BYTE              * in_data,
                     CK_ULONG               in_data_len )
{
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_MECHANISM          digest_mech;
   CK_RV                 rc;

   if (!sess || !ctx) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   if (context->flag == FALSE) {
      digest_mech.mechanism = CKM_SHA_1;
      digest_mech.ulParameterLen = 0;
      digest_mech.pParameter     = NULL;

      rc = digest_mgr_init( sess, &context->hash_context, &digest_mech );
      if (rc != CKR_OK){
	 TRACE_DEVEL("Digest Mgr Init failed.\n");
         return rc;
      }
      context->flag = TRUE;
   }

   rc = digest_mgr_digest_update( sess, &context->hash_context, in_data, in_data_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("Digest Mgr Update failed.\n");
      return rc;
   }
   return CKR_OK;
}

CK_RV
ec_hash_sign_final( SESSION              * sess,
                    CK_BBOOL               length_only,
                    SIGN_VERIFY_CONTEXT  * ctx,
                    CK_BYTE              * signature,
                    CK_ULONG             * sig_len )
{
   CK_BYTE               hash[SHA1_HASH_SIZE];
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_ULONG              hash_len;
   CK_MECHANISM          sign_mech;
   SIGN_VERIFY_CONTEXT   sign_ctx;
   CK_RV                 rc;

   if (!sess || !ctx || !sig_len){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   memset( &sign_ctx, 0x0, sizeof(sign_ctx));

   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, length_only, &context->hash_context, hash, &hash_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("Digest Mgr Final failed.\n");
      return rc;
   }

   sign_mech.mechanism      = CKM_ECDSA;
   sign_mech.ulParameterLen = 0;
   sign_mech.pParameter     = NULL;

   rc = sign_mgr_init( sess, &sign_ctx, &sign_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      TRACE_DEVEL("Sign Mgr Init failed.\n");
      goto done;
   }

   //rc = sign_mgr_sign( sess, length_only, &sign_ctx, ber_data, ber_data_len, signature, sig_len );
   rc = sign_mgr_sign( sess, length_only, &sign_ctx, hash, hash_len, signature, sig_len );
   if (rc != CKR_OK)
      TRACE_DEVEL("Sign Mgr Sign failed.\n");

   if (length_only == TRUE || rc == CKR_BUFFER_TOO_SMALL) {
      sign_mgr_cleanup( &sign_ctx );
      return rc;
   }

done:
   sign_mgr_cleanup( &sign_ctx );
   return rc;
}

CK_RV
ec_hash_verify( SESSION              * sess,
                SIGN_VERIFY_CONTEXT  * ctx,
                CK_BYTE              * in_data,
                CK_ULONG               in_data_len,
                CK_BYTE              * signature,
                CK_ULONG               sig_len )
{
   CK_BYTE              hash[SHA1_HASH_SIZE];
   DIGEST_CONTEXT       digest_ctx;
   SIGN_VERIFY_CONTEXT  verify_ctx;
   CK_MECHANISM         digest_mech;
   CK_MECHANISM         verify_mech;
   CK_ULONG             hash_len;
   CK_RV                rc;

   if (!sess || !ctx || !in_data){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   memset( &digest_ctx, 0x0, sizeof(digest_ctx) );
   memset( &verify_ctx, 0x0, sizeof(verify_ctx) );

   digest_mech.mechanism      = CKM_SHA_1;
   digest_mech.ulParameterLen = 0;
   digest_mech.pParameter     = NULL;

   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK){
      TRACE_DEVEL("Digest Mgr Init failed.\n");
      return rc;
   }
   hash_len = sizeof(hash);
   rc = digest_mgr_digest( sess, FALSE, &digest_ctx, in_data, in_data_len, hash, &hash_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("Digest Mgr Digest failed.\n");
      return rc;
   }

   // Verify the Signed BER-encoded Data block
   //
   verify_mech.mechanism      = CKM_ECDSA;
   verify_mech.ulParameterLen = 0;
   verify_mech.pParameter     = NULL;

   rc = verify_mgr_init( sess, &verify_ctx, &verify_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      TRACE_DEVEL("Verify Mgr Init failed.\n");
      goto done;
   }

   //rc = verify_mgr_verify( sess, &verify_ctx, ber_data, ber_data_len, signature, sig_len );
   rc = verify_mgr_verify( sess, &verify_ctx, hash, hash_len, signature, sig_len );
   if (rc != CKR_OK)
      TRACE_DEVEL("Verify Mgr Verify failed.\n");
done:
   sign_mgr_cleanup( &verify_ctx );
   return rc;
}


CK_RV
ec_hash_verify_update( SESSION              * sess,
                       SIGN_VERIFY_CONTEXT  * ctx,
                       CK_BYTE              * in_data,
                       CK_ULONG               in_data_len )
{
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_MECHANISM          digest_mech;
   CK_RV                 rc;

   if (!sess || !ctx) {
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   if (context->flag == FALSE) {
      digest_mech.mechanism = CKM_SHA_1;
      digest_mech.ulParameterLen = 0;
      digest_mech.pParameter     = NULL;

      rc = digest_mgr_init( sess, &context->hash_context, &digest_mech );
      if (rc != CKR_OK){
	 TRACE_DEVEL("Digest Mgr Init failed.\n");
         return rc;
      }
      context->flag = TRUE;
   }

   rc = digest_mgr_digest_update( sess, &context->hash_context, in_data, in_data_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("Digest Mgr Update failed.\n");
      return rc;
   }
   return CKR_OK;
}

CK_RV
ec_hash_verify_final( SESSION              * sess,
                      SIGN_VERIFY_CONTEXT  * ctx,
                      CK_BYTE              * signature,
                      CK_ULONG               sig_len )
{
   CK_BYTE               hash[SHA1_HASH_SIZE];
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_ULONG              hash_len;
   CK_MECHANISM          verify_mech;
   SIGN_VERIFY_CONTEXT   verify_ctx;
   CK_RV                 rc;

   if (!sess || !ctx || !signature){
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   memset( &verify_ctx, 0x0, sizeof(verify_ctx));

   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, FALSE, &context->hash_context, hash, &hash_len );
   if (rc != CKR_OK){
      TRACE_DEVEL("Digest Mgr Final failed.\n");
      return rc;
   }
   verify_mech.mechanism      = CKM_ECDSA;
   verify_mech.ulParameterLen = 0;
   verify_mech.pParameter     = NULL;

   rc = verify_mgr_init( sess, &verify_ctx, &verify_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      TRACE_DEVEL("Verify Mgr Init failed.\n");
      goto done;
   }

   rc = verify_mgr_verify( sess, &verify_ctx, hash, hash_len, signature, sig_len );
   if (rc != CKR_OK)
      TRACE_DEVEL("Verify Mgr Verify failed.\n");
done:
   verify_mgr_cleanup( &verify_ctx );
   return rc;
}
