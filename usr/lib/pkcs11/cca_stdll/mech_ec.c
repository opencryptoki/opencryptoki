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
		st_err_log(91, __FILE__, __LINE__);
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
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	else
		keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

	// this had better be a private key
	//
	if (keyclass != CKO_PRIVATE_KEY){
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	rc = token_specific.t_ec_sign(in_data, in_data_len, out_data,
					out_data_len, key_obj);
	if (rc != CKR_OK)
		st_err_log(135, __FILE__, __LINE__);

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
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	rc = object_mgr_find_in_map1( ctx->key, &key_obj );
	if (rc != CKR_OK){
		st_err_log(110, __FILE__, __LINE__);
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

	rc = ckm_ec_sign( in_data, in_data_len, out_data,
			out_data_len, key_obj );
	if (rc != CKR_OK)
		st_err_log(133, __FILE__, __LINE__);

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
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}
	else
		keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

	// this had better be a public key
	//
	if (keyclass != CKO_PUBLIC_KEY){
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	rc = token_specific.t_ec_verify(in_data, in_data_len,
			out_data, out_data_len, key_obj);
	if (rc != CKR_OK)
		st_err_log(135, __FILE__, __LINE__);

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
		st_err_log(110, __FILE__, __LINE__);
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
		st_err_log(46, __FILE__, __LINE__);
		return CKR_SIGNATURE_LEN_RANGE;
	}
	rc = ckm_ec_verify(in_data, in_data_len, signature,
			sig_len, key_obj);
	if (rc != CKR_OK)
		st_err_log(132, __FILE__, __LINE__);

	return rc;
}
