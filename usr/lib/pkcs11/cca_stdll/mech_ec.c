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
#include <string.h>
#include "cca_stdll.h"
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"

CK_RV
ckm_ec_key_pair_gen( TEMPLATE  * publ_tmpl,
		TEMPLATE  * priv_tmpl )
{
	CK_RV rc;
	rc = token_specific.t_ec_generate_keypair(publ_tmpl, priv_tmpl);
	if (rc != CKR_OK)
		OCK_LOG_ERR(ERR_KEYGEN);
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
	rc = token_specific.t_ec_sign(in_data, in_data_len, out_data,
					out_data_len, key_obj);
	if (rc != CKR_OK)
		OCK_LOG_ERR(ERR_EC_SIGN);

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
	CK_ATTRIBUTE    *attr      = NULL;
	CK_ULONG         public_key_len;
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

	flag = template_attribute_find( key_obj->template,
			CKA_EC_POINT, &attr );
	if (flag == FALSE)
		return CKR_FUNCTION_FAILED;
	else
		public_key_len = attr->ulValueLen;

	if (length_only == TRUE) {
		*out_data_len = public_key_len;
		return CKR_OK;
	}

	if (*out_data_len < public_key_len) {
		OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
		return CKR_BUFFER_TOO_SMALL;
	}
	*out_data_len = public_key_len;

	rc = ckm_ec_sign( in_data, in_data_len, out_data,
			out_data_len, key_obj );
	if (rc != CKR_OK)
		OCK_LOG_ERR(ERR_EC_SIGN);

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

	rc = token_specific.t_ec_verify(in_data, in_data_len,
			out_data, out_data_len, key_obj);
	if (rc != CKR_OK)
		OCK_LOG_ERR(ERR_EC_VERIFY);

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
	CK_ATTRIBUTE    *attr     = NULL;
	CK_ULONG         public_key_len;
	CK_BBOOL         flag;
	CK_RV            rc;


	rc = object_mgr_find_in_map1(ctx->key, &key_obj);
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_OBJMGR_FIND_MAP);
		return rc;
	}
	flag = template_attribute_find( key_obj->template,
			CKA_EC_POINT, &attr );
	if (flag == FALSE)
		return CKR_FUNCTION_FAILED;
	else
		public_key_len = attr->ulValueLen;

	// check input data length restrictions
	//
	if (sig_len > public_key_len){
		OCK_LOG_ERR(ERR_SIGNATURE_LEN_RANGE);
		return CKR_SIGNATURE_LEN_RANGE;
	}
	rc = ckm_ec_verify(in_data, in_data_len, signature,
			sig_len, key_obj);
	if (rc != CKR_OK)
		OCK_LOG_ERR(ERR_EC_VERIFY);

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
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   memset( &digest_ctx, 0x0, sizeof(digest_ctx) );
   memset( &sign_ctx,   0x0, sizeof(sign_ctx)   );

   digest_mech.mechanism      = CKM_SHA_1;
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

    sign_mech.mechanism      = CKM_ECDSA;
    sign_mech.ulParameterLen = 0;
    sign_mech.pParameter     = NULL;

   rc = sign_mgr_init( sess, &sign_ctx, &sign_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_SIGN_INIT);
      goto error;
   }

   rc = sign_mgr_sign( sess, length_only, &sign_ctx, hash, hash_len, signature, sig_len );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_SIGN);

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

   if (!sess || !ctx || !in_data){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   if (context->flag == FALSE) {
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
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   memset( &sign_ctx, 0x0, sizeof(sign_ctx));

   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, length_only, &context->hash_context, hash, &hash_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DIGEST_FINAL);
      return rc;
   }

   sign_mech.mechanism      = CKM_ECDSA;
   sign_mech.ulParameterLen = 0;
   sign_mech.pParameter     = NULL;

   rc = sign_mgr_init( sess, &sign_ctx, &sign_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_SIGN_INIT);
      goto done;
   }

   //rc = sign_mgr_sign( sess, length_only, &sign_ctx, ber_data, ber_data_len, signature, sig_len );
   rc = sign_mgr_sign( sess, length_only, &sign_ctx, hash, hash_len, signature, sig_len );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_SIGN);

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
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   memset( &digest_ctx, 0x0, sizeof(digest_ctx) );
   memset( &verify_ctx, 0x0, sizeof(verify_ctx) );

   digest_mech.mechanism      = CKM_SHA_1;
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

   // Verify the Signed BER-encoded Data block
   //
   verify_mech.mechanism      = CKM_ECDSA;
   verify_mech.ulParameterLen = 0;
   verify_mech.pParameter     = NULL;

   rc = verify_mgr_init( sess, &verify_ctx, &verify_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_VERIFY_INIT);
      goto done;
   }

   //rc = verify_mgr_verify( sess, &verify_ctx, ber_data, ber_data_len, signature, sig_len );
   rc = verify_mgr_verify( sess, &verify_ctx, hash, hash_len, signature, sig_len );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_VERIFY);
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

   if (!sess || !ctx || !in_data){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   if (context->flag == FALSE) {
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
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   memset( &verify_ctx, 0x0, sizeof(verify_ctx));

   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, FALSE, &context->hash_context, hash, &hash_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DIGEST_FINAL);
      return rc;
   }
   verify_mech.mechanism      = CKM_ECDSA;
   verify_mech.ulParameterLen = 0;
   verify_mech.pParameter     = NULL;

   rc = verify_mgr_init( sess, &verify_ctx, &verify_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_VERIFY_INIT);
      goto done;
   }

   rc = verify_mgr_verify( sess, &verify_ctx, hash, hash_len, signature, sig_len );
   if (rc != CKR_OK)
      OCK_LOG_ERR(ERR_VERIFY);
done:
   verify_mgr_cleanup( &verify_ctx );
   return rc;
}
