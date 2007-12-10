
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

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <limits.h>
#include <syslog.h>

#include <openssl/des.h>

#include "cca_stdll.h"

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "h_extern.h"

#include "csulincl.h"

CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "IBM CCA Token";
CK_CHAR descr[] = "IBM PKCS#11 CCA Token";
CK_CHAR label[] = "IBM PKCS#11 for CCA";

/* mechanisms provided by this token */
MECH_LIST_ELEMENT mech_list[] = {
   { CKM_DES_KEY_GEN,                { 8,    8, CKF_HW | CKF_GENERATE } },
   { CKM_DES3_KEY_GEN,              { 24,   24, CKF_HW | CKF_GENERATE } },
   { CKM_RSA_PKCS_KEY_PAIR_GEN,    { 512, 2048, CKF_HW | CKF_GENERATE_KEY_PAIR } },
   { CKM_RSA_PKCS,                 { 512, 2048, CKF_HW           |
                                                CKF_ENCRYPT      | CKF_DECRYPT |
                                                CKF_SIGN         | CKF_VERIFY } },
   { CKM_MD2_RSA_PKCS,             { 512, 2048, CKF_HW      |
                                                CKF_SIGN    | CKF_VERIFY } },
   { CKM_MD5_RSA_PKCS,             { 512, 2048, CKF_HW      |
                                                CKF_SIGN    | CKF_VERIFY } },
   { CKM_SHA1_RSA_PKCS,            { 512, 2048, CKF_HW      |
                                                CKF_SIGN    | CKF_VERIFY } },
   { CKM_DES_CBC,                    { 8,    8, CKF_HW      |
                                                CKF_ENCRYPT | CKF_DECRYPT |
                                                CKF_WRAP    | CKF_UNWRAP } },
   { CKM_DES_CBC_PAD,                { 8,    8, CKF_HW      |
                                                CKF_ENCRYPT | CKF_DECRYPT |
                                                CKF_WRAP    | CKF_UNWRAP } },
   { CKM_DES3_CBC,                  { 24,   24, CKF_HW      |
                                                CKF_ENCRYPT | CKF_DECRYPT |
                                                CKF_WRAP    | CKF_UNWRAP } },
   { CKM_DES3_CBC_PAD,              { 24,   24, CKF_HW      |
                                                CKF_ENCRYPT | CKF_DECRYPT |
                                                CKF_WRAP    | CKF_UNWRAP } },
   { CKM_SHA_1,                      { 0,    0, CKF_DIGEST } },
   { CKM_SHA_1_HMAC,                 { 0,    0, CKF_SIGN | CKF_VERIFY } },
   { CKM_SHA_1_HMAC_GENERAL,         { 0,    0, CKF_SIGN | CKF_VERIFY } },
   { CKM_MD5,                        { 0,    0, CKF_DIGEST } },
   { CKM_MD5_HMAC,                   { 0,    0, CKF_SIGN | CKF_VERIFY } },
   { CKM_MD5_HMAC_GENERAL,           { 0,    0, CKF_SIGN | CKF_VERIFY } },
   { CKM_MD2,                        { 0,    0, CKF_DIGEST } },
   { CKM_MD2_HMAC,                   { 0,    0, CKF_SIGN | CKF_VERIFY } },
   { CKM_MD2_HMAC_GENERAL,           { 0,    0, CKF_SIGN | CKF_VERIFY } }
};

CK_ULONG mech_list_len = (sizeof(mech_list) / sizeof(MECH_LIST_ELEMENT));


CK_RV
token_specific_session(CK_SLOT_ID  slotid)
{
       return CKR_OK;
}

CK_RV
token_rng(CK_BYTE *output, CK_ULONG bytes)
{
	long return_code, reason_code;
	unsigned char form[CCA_KEYWORD_SIZE], random_number[CCA_RNG_SIZE];
	CK_ULONG bytes_so_far = 0, bytes_left;
	CK_RV rv;

	DBG("Enter");

	memcpy(form, "RANDOM  ", (size_t)CCA_KEYWORD_SIZE);

	while (bytes_so_far < bytes) {
		CSNBRNG(&return_code,
			&reason_code,
			NULL,
			NULL,
			form,
			random_number);

		if (return_code != CCA_SUCCESS) {
			CCADBG("CSNBRNG", return_code, reason_code);
			rv = CKR_FUNCTION_FAILED;
			return rv;
		}

		if (bytes_so_far + CCA_RNG_SIZE > bytes) {
			bytes_left = bytes - bytes_so_far;
			memcpy(&output[bytes_so_far], random_number, (size_t)bytes_left);
			bytes_so_far += bytes_left;
		} else {
			memcpy(&output[bytes_so_far], random_number, (size_t)CCA_RNG_SIZE);
			bytes_so_far += CCA_RNG_SIZE;
		}
	}

	return CKR_OK;
}

// convert pkcs slot number to local representation
int
tok_slot2local(CK_SLOT_ID snum)
{
	return 1;
}

CK_RV
token_specific_init(char *Correlator, CK_SLOT_ID SlotNumber)
{
	unsigned char rule_array[256] = { 0, };
        long return_code, reason_code, rule_array_count, verb_data_length;

        memcpy(rule_array, "STATCCAE", 8);

        rule_array_count = 1;
        verb_data_length = 0;

        CSUACFQ(&return_code,
                &reason_code,
                NULL,
                NULL,
                &rule_array_count,
                rule_array,
                &verb_data_length,
                NULL);

        if (return_code != CCA_SUCCESS) {
                CCADBG("CSUACFQ (STATUS QUERY)", return_code, reason_code);
                return CKR_FUNCTION_FAILED;
        }

	/* This value should be 2 if the master key is set in the card */
	if (memcmp(&rule_array[CCA_STATCCAE_SYM_CMK_OFFSET], "2       ", 8)) {
		LOG(LOG_WARNING, "Warning: CCA symmetric master key is not yet loaded");
	}
	if (memcmp(&rule_array[CCA_STATCCAE_ASYM_CMK_OFFSET], "2       ", 8)) {
		LOG(LOG_WARNING, "Warning: CCA asymmetric master key is not yet loaded");
	}

	return CKR_OK;
}

CK_RV
token_specific_final()
{
	return CKR_OK;
}

CK_RV
token_specific_des_key_gen(CK_BYTE *des_key, CK_ULONG len, CK_ULONG key_size)
{
	long return_code, reason_code;
	unsigned char key_form[CCA_KEYWORD_SIZE], key_length[CCA_KEYWORD_SIZE];
	unsigned char key_type_1[CCA_KEYWORD_SIZE], key_type_2[CCA_KEYWORD_SIZE] = { 0, };
	unsigned char kek_key_identifier_1[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char kek_key_identifier_2[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char generated_key_identifier_1[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char generated_key_identifier_2[CCA_KEY_ID_SIZE] = { 0, };

	DBG("Enter");

	memcpy(key_form, "OP      ", (size_t)CCA_KEYWORD_SIZE);
	memcpy(key_type_1, "DATA    ", (size_t)CCA_KEYWORD_SIZE);

	switch (key_size) {
		case 8:
			memcpy(key_length, "KEYLN8  ", (size_t)CCA_KEYWORD_SIZE);
			break;
#if 0
		case 16:
			memcpy(key_length, "KEYLN16 ", CCA_KEYWORD_SIZE);
			break;
#endif
		case 24:
			memcpy(key_length, "KEYLN24 ", (size_t)CCA_KEYWORD_SIZE);
			break;
		default:
			DBG("Invalid key length: %lu", key_size);
			return CKR_KEY_SIZE_RANGE;
	}

	CSNBKGN(&return_code,
		&reason_code,
		NULL,
		NULL,
		key_form,
		key_length,
		key_type_1,
		key_type_2,
		kek_key_identifier_1,
		kek_key_identifier_2,
		generated_key_identifier_1,
		generated_key_identifier_2);

	if (return_code != CCA_SUCCESS) {
		CCADBG("CSNBKGN (DES KEYGEN)", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	memcpy(des_key, generated_key_identifier_1, (size_t)CCA_KEY_ID_SIZE);

#ifdef DEBUG
	DBG("Created a new key of size %lu", key_size);
	{
		uint32_t *i = (uint32_t *) des_key, j;
		for ( j = 0; j < 16; j++)
			DBG("%.8x ", *i++);
	}
#endif

	return CKR_OK;
}

CK_RV
token_specific_des_ecb(CK_BYTE  *in_data,
		       CK_ULONG  in_data_len,
		       CK_BYTE  *out_data,
		       CK_ULONG *out_data_len,
		       CK_BYTE  *key_value,
		       CK_BYTE   encrypt)
{
	DBG("Unsupported function reached.");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
token_specific_des_cbc(CK_BYTE  *in_data,
		       CK_ULONG  in_data_len,
		       CK_BYTE  *out_data,
		       CK_ULONG *out_data_len,
		       CK_BYTE  *key_value,
		       CK_BYTE  *init_v,
		       CK_BYTE   encrypt)
{
	long return_code, reason_code, rule_array_count, length;
	long pad_character = 0;
	//char iv[8] = { 0xfe, 0x43, 0x12, 0xed, 0xaa, 0xbb, 0xdd, 0x90 };
	unsigned char chaining_vector[CCA_OCV_SIZE];
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
	CK_BYTE *local_out = out_data;

	DBG("Enter");

	/* We need to have 8 bytes more than the in data length in case CCA
	 * adds some padding, although this extra 8 bytes may not be needed.
	 * If *out_data_len is not 8 bytes larger than in_data_len, then
	 * we'll malloc the needed space and get the data back from CCA in this
	 * malloc'd buffer. If it turns out that the extra 8 bytes wasn't
	 * needed, we just silently copy the data to the user's buffer and
	 * free our malloc'd space, returning as normal. If the space was
	 * needed, we return an error and no memory corruption happens. */
	if (*out_data_len < (in_data_len + 8)) {
		local_out = malloc(in_data_len + 8);
		if (!local_out) {
			DBG("Malloc of %lu bytes failed.", in_data_len + 8);
			return CKR_HOST_MEMORY;
		}
	}

	length = in_data_len;

	rule_array_count = 1;
	memcpy(rule_array, "CBC     ", (size_t)CCA_KEYWORD_SIZE);

	if (encrypt) {
		CSNBENC(&return_code,
			&reason_code,
			NULL,
			NULL,
			key_value, //id,
			&length,
			in_data, //in,
			init_v, //iv,
			&rule_array_count,
			rule_array,
			&pad_character,
			chaining_vector,
			local_out);//out_data); //out);
	} else {
		CSNBDEC(&return_code,
			&reason_code,
			NULL,
			NULL,
			key_value, //id,
			&length,
			in_data, //in,
			init_v, //iv,
			&rule_array_count,
			rule_array,
			chaining_vector,
			local_out);//out_data); //out);
	}

	if (return_code != CCA_SUCCESS) {
		CCADBG("CSNBENC (DES ENCRYPT)", return_code, reason_code);
#ifdef DEBUG
		{
			uint32_t *i = (uint32_t *) key_value, j;
			DBG("Bad key:");
			for ( j = 0; j < 16; j++)
				DBG("%.8x ", *i++);
		}
#endif
		return CKR_FUNCTION_FAILED;
	}

	/* If we malloc'd a new buffer due to overflow concerns and the data
	 * coming out turned out to be bigger than expected, return an error.
	 *
	 * Else, memcpy the data back to the user's buffer
	 */
	if ((local_out != out_data) && ((CK_ULONG)length > *out_data_len)) {
		DBG("CKR_BUFFER_TOO_SMALL: %ld bytes to write into %ld bytes space",
		    length, *out_data_len);
		st_err_log(111, __FILE__, __LINE__);
		return CKR_BUFFER_TOO_SMALL;
	} else if (local_out != out_data) {
		memcpy(out_data, local_out, (size_t)length);
	}

	*out_data_len = length;

	return CKR_OK;
}

CK_RV
token_specific_tdes_ecb(CK_BYTE  *in_data,
			CK_ULONG  in_data_len,
			CK_BYTE  *out_data,
			CK_ULONG *out_data_len,
			CK_BYTE  *key_value,
			CK_BYTE   encrypt)
{
	DBG("Unsupported function reached.");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
token_specific_tdes_cbc(CK_BYTE  *in_data,
			CK_ULONG  in_data_len,
			CK_BYTE  *out_data,
			CK_ULONG *out_data_len,
			CK_BYTE  *key_value,
			CK_BYTE  *init_v,
			CK_BYTE   encrypt)
{
	DBG("Enter");
	/* Since keys are opaque objects in this token and there's only
	 * one encipher command to CCA, we can just pass through */
	return token_specific_des_cbc(in_data, in_data_len, out_data,
				      out_data_len, key_value, init_v,
				      encrypt);
}

uint16_t
cca_inttok_privkey_get_len(CK_BYTE *tok)
{
	return *(uint16_t *)&tok[CCA_RSA_INTTOK_PRIVKEY_LENGTH_OFFSET];
}

/* Given a CCA internal token private key object, get the modulus */
CK_RV
cca_inttok_privkey_get_n(CK_BYTE *tok, CK_ULONG *n_len, CK_BYTE *n)
{
	uint16_t privkey_length, n_length;
	uint32_t privkey_n_offset;

	privkey_length = *(uint16_t *)&tok[CCA_RSA_INTTOK_PRIVKEY_LENGTH_OFFSET];
	n_length = *(uint16_t *)&tok[CCA_RSA_INTTOK_PRIVKEY_N_LENGTH_OFFSET];

	if (n_length > (*n_len)) {
		DBG("Not enough room to return n. (Got %lu, need %hu)", *n_len,
		    n_length);
		return CKR_FUNCTION_FAILED;
	}

	privkey_n_offset = privkey_length - n_length;

	memcpy(n, &tok[privkey_n_offset], (size_t)n_length);
	*n_len = n_length;

	return CKR_OK;
}

/* Given a CCA internal token pubkey object, get the public exponent */
CK_RV
cca_inttok_pubkey_get_e(CK_BYTE *tok, CK_ULONG *e_len, CK_BYTE *e)
{
	uint16_t e_length;

	e_length = *(uint16_t *)&tok[CCA_RSA_INTTOK_PUBKEY_E_LENGTH_OFFSET];

	if (e_length > (*e_len)) {
		DBG("Not enough room to return e. (Got %lu, need %hu)", *e_len,
		    e_length);
		return CKR_FUNCTION_FAILED;
	}

	memcpy(e, &tok[CCA_RSA_INTTOK_PUBKEY_E_OFFSET], (size_t)e_length);
	*e_len = (CK_ULONG)e_length;

	return CKR_OK;
}

CK_RV
token_create_keypair_object(TEMPLATE *tmpl, CK_ULONG tok_len, CK_BYTE *tok)
{
	uint16_t privkey_len, pubkey_offset;
	CK_BYTE n[CCATOK_MAX_N_LEN], e[CCATOK_MAX_E_LEN];
	CK_ULONG n_len = CCATOK_MAX_N_LEN, e_len = CCATOK_MAX_E_LEN;
	CK_ATTRIBUTE *modulus, *pub_exp, *opaque_key;
	CK_RV rv;

	privkey_len = cca_inttok_privkey_get_len(&tok[CCA_RSA_INTTOK_PRIVKEY_OFFSET]);
	pubkey_offset = privkey_len + CCA_RSA_INTTOK_HDR_LENGTH;

	/* That's right, n is stored in the private key area. Get it there */
	if ((rv = cca_inttok_privkey_get_n(&tok[CCA_RSA_INTTOK_PRIVKEY_OFFSET],
					   &n_len, n))) {
		DBG("Call to cca_inttok_privkey_get_n() failed. rv=0x%lx", rv);
		return rv;
	}

	/* Get e */
	if ((rv = cca_inttok_pubkey_get_e(&tok[pubkey_offset], &e_len, e))) {
		DBG("Call to cca_inttok_pubkey_get_e() failed. rv=0x%lx", rv);
		return rv;
	}

	/* Add n's value to the template */
	if ((rv = build_attribute(CKA_MODULUS, n, n_len, &modulus))) {
		DBG("build_attribute for n failed. rv=0x%lx", rv);
		return rv;
	}
	template_update_attribute(tmpl, modulus);

	/* Add e's value to the template */
	if ((rv = build_attribute(CKA_PUBLIC_EXPONENT, e, e_len, &pub_exp))) {
		DBG("build_attribute for e failed. rv=0x%lx", rv);
		return rv;
	}
	template_update_attribute(tmpl, pub_exp);

	/* Add the opaque key object to the template */
	if ((rv = build_attribute(CKA_IBM_OPAQUE, tok, tok_len, &opaque_key))) {
		DBG("build_attribute for opaque key failed. rv=0x%lx", rv);
		return rv;
	}
	template_update_attribute(tmpl, opaque_key);

	return CKR_OK;
}

#if 0
CK_RV
token_create_priv_key(TEMPLATE *priv_tmpl, CK_ULONG tok_len, CK_BYTE *tok)
{
	CK_BYTE n[CCATOK_MAX_N_LEN];
	CK_ULONG n_len = CCATOK_MAX_N_LEN;
	CK_RV rv;
	CK_ATTRIBUTE *opaque_key, *modulus;

	/* That's right, n is stored in the private key area. Get it there */
	if ((rv = cca_inttok_privkey_get_n(&tok[CCA_RSA_INTTOK_PRIVKEY_OFFSET],
					   &n_len, n))) {
		DBG("Call to cca_inttok_privkey_get_n() failed. rv=0x%lx", rv);
		return rv;
	}

	/* Add n's value to the template. We need to do this for the private
	 * key as well as the public key because openCryptoki checks data
	 * sizes against the size of the CKA_MODULUS attribute of whatever
	 * key object it gets */
	if ((rv = build_attribute(CKA_MODULUS, n, n_len, &modulus))) {
		DBG("build_attribute for n failed. rv=0x%lx", rv);
		return rv;
	}
	template_update_attribute(priv_tmpl, modulus);

	/* Add the opaque key object to the template */
	if ((rv = build_attribute(CKA_IBM_OPAQUE, tok, tok_len, &opaque_key))) {
		DBG("build_attribute for opaque key failed. rv=0x%lx", rv);
		return rv;
	}
	template_update_attribute(priv_tmpl, opaque_key);

	return CKR_OK;
}
#endif

CK_RV
token_specific_rsa_generate_keypair(TEMPLATE *publ_tmpl,
				    TEMPLATE *priv_tmpl)
{
	long return_code, reason_code, rule_array_count;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };

	long key_value_structure_length;
	long private_key_name_length, key_token_length;
	unsigned char key_value_structure[CCA_KEY_VALUE_STRUCT_SIZE] = { 0, };
	unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
	unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };

	long regeneration_data_length, generated_key_token_length;
	unsigned char regeneration_data[CCA_REGENERATION_DATA_SIZE] = { 0, };
	unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char generated_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };

	uint16_t size_of_e;
	uint16_t mod_bits;
	CK_ATTRIBUTE *pub_exp = NULL, *attr = NULL;
	CK_RV rv;

	if (!template_attribute_find(publ_tmpl, CKA_MODULUS_BITS, &attr)) {
		st_err_log(48, __FILE__, __LINE__);
		return CKR_TEMPLATE_INCOMPLETE;
	}
	mod_bits = *(CK_ULONG *)attr->pValue;


	/* If e is specified in the template, use it */
	rv = template_attribute_find(publ_tmpl, CKA_PUBLIC_EXPONENT, &pub_exp);
	if (rv == TRUE) {
		if (pub_exp->ulValueLen > SHRT_MAX)
			return CKR_TEMPLATE_INCONSISTENT;

		size_of_e = (uint16_t)pub_exp->ulValueLen;

		memcpy(&key_value_structure[CCA_PKB_E_SIZE_OFFSET],
		       &size_of_e, (size_t)CCA_PKB_E_SIZE);
		memcpy(&key_value_structure[CCA_PKB_E_OFFSET],
		       pub_exp->pValue, (size_t)pub_exp->ulValueLen);
	}

	key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;
	memcpy(key_value_structure, &mod_bits, sizeof(uint16_t));

	rule_array_count = 2;
	memcpy(rule_array, "RSA-CRT KEY-MGMT", (size_t)(CCA_KEYWORD_SIZE * 2));

	private_key_name_length = 0;

	key_token_length = CCA_KEY_TOKEN_SIZE;

        CSNDPKB(&return_code,
                &reason_code,
                NULL,
                NULL,
                &rule_array_count,
                rule_array,
                &key_value_structure_length,
                key_value_structure,
                &private_key_name_length,
                private_key_name,
                0,
                NULL,
                0,
                NULL,
                0,
                NULL,
                0,
                NULL,
                0,
                NULL,
                &key_token_length,
                key_token);

        if (return_code != CCA_SUCCESS) {
                CCADBG("CSNDPKB (RSA KEY TOKEN BUILD)", return_code, reason_code);
                return CKR_FUNCTION_FAILED;
        }

        rule_array_count = 1;
        memset(rule_array, 0, sizeof(rule_array));
        memcpy(rule_array, "MASTER  ", (size_t)CCA_KEYWORD_SIZE);

        generated_key_token_length = CCA_KEY_TOKEN_SIZE;

        regeneration_data_length = 0;

        CSNDPKG(&return_code,
                &reason_code,
                NULL,
                NULL,
                &rule_array_count,
                rule_array,
                &regeneration_data_length,
                regeneration_data,
                &key_token_length,
                key_token,
                transport_key_identifier,
                &generated_key_token_length,
                generated_key_token);

        if (return_code != CCA_SUCCESS) {
                CCADBG("CSNDPKG (RSA KEY GENERATE)", return_code, reason_code);
                return CKR_FUNCTION_FAILED;
        }

	DBG("RSA secure key token generated. size: %ld", generated_key_token_length);

	rv = token_create_keypair_object(publ_tmpl, generated_key_token_length,
					 generated_key_token);
	if (rv != CKR_OK) {
		DBG("token_create_keypair_object failed. rv: %lu", rv);
		return rv;
	}

	rv = token_create_keypair_object(priv_tmpl, generated_key_token_length,
					 generated_key_token);
	if (rv != CKR_OK)
		DBG("token_create_keypair_object failed. rv: %lu", rv);

	return rv;
}


CK_RV
token_specific_rsa_encrypt(CK_BYTE  *in_data,
			   CK_ULONG  in_data_len,
			   CK_BYTE  *out_data,
			   CK_ULONG *out_data_len,
			   OBJECT   *key_obj)
{
	long return_code, reason_code, rule_array_count, data_structure_length;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	CK_ATTRIBUTE *attr;

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr)) {
		st_err_log(48, __FILE__, __LINE__);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* The max value allowable by CCA for out_data_len is 256, so cap the incoming value if its
	 * too large. CCA will throw error 8, 72 otherwise. */
	if (*out_data_len > 256)
		*out_data_len = 256;

	rule_array_count = 1;
	memcpy(rule_array, "PKCS-1.2", CCA_KEYWORD_SIZE);

	data_structure_length = 0;

	CSNDPKE(&return_code,
		&reason_code,
		NULL,
		NULL,
		&rule_array_count,
		rule_array,
		(long *)&in_data_len,
		in_data,
		&data_structure_length, // must be 0
		NULL,                   // ignored
		(long *)&(attr->ulValueLen),
		attr->pValue,
		(long *)out_data_len,
		out_data);

	if (return_code != CCA_SUCCESS) {
		CCADBG("CSNDPKE (RSA ENCRYPT)", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV
token_specific_rsa_decrypt(CK_BYTE  *in_data,
			   CK_ULONG  in_data_len,
			   CK_BYTE  *out_data,
			   CK_ULONG *out_data_len,
			   OBJECT   *key_obj)
{
	long return_code, reason_code, rule_array_count, data_structure_length;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	CK_ATTRIBUTE *attr;

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr)) {
		st_err_log(48, __FILE__, __LINE__);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* The max value allowable by CCA for out_data_len is 256, so cap the incoming value if its
	 * too large. CCA will throw error 8, 72 otherwise. */
	if (*out_data_len > 256)
		*out_data_len = 256;

	rule_array_count = 1;
	memcpy(rule_array, "PKCS-1.2", CCA_KEYWORD_SIZE);

	data_structure_length = 0;

	CSNDPKD(&return_code,
		&reason_code,
		NULL,
		NULL,
		&rule_array_count,
		rule_array,
		(long *)&in_data_len,
		in_data,
		&data_structure_length, // must be 0
		NULL,                   // ignored
		(long *)&(attr->ulValueLen),
		attr->pValue,
		(long *)out_data_len,
		out_data);

	if (return_code != CCA_SUCCESS) {
		CCADBG("CSNDPKD (RSA DECRYPT)", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV
token_specific_rsa_sign(CK_BYTE  * in_data,
			CK_ULONG   in_data_len,
			CK_BYTE  * out_data,
			CK_ULONG * out_data_len,
			OBJECT   * key_obj )
{
        long return_code, reason_code, rule_array_count;
        unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
        long signature_bit_length;
	CK_ATTRIBUTE *attr;

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr)) {
		st_err_log(48, __FILE__, __LINE__);
		return CKR_TEMPLATE_INCOMPLETE;
	}

        rule_array_count = 1;
        memcpy(rule_array, "PKCS-1.1", CCA_KEYWORD_SIZE);

        CSNDDSG(&return_code,
                &reason_code,
                NULL,
                NULL,
                &rule_array_count,
                rule_array,
                (long *)&(attr->ulValueLen),
                attr->pValue,
                (long *)&in_data_len,
                in_data,
                (long *)out_data_len,
                &signature_bit_length,
                out_data);

        if (return_code != CCA_SUCCESS) {
                CCADBG("CSNDDSG (RSA SIGN)", return_code, reason_code);
                return CKR_FUNCTION_FAILED;
        }

        return CKR_OK;
}

CK_RV
token_specific_rsa_verify(CK_BYTE  * in_data,
			  CK_ULONG   in_data_len,
			  CK_BYTE  * out_data,
			  CK_ULONG   out_data_len,
			  OBJECT   * key_obj )
{
	long return_code, reason_code, rule_array_count;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	CK_ATTRIBUTE *attr;

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr)) {
		st_err_log(48, __FILE__, __LINE__);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	rule_array_count = 1;
	memcpy(rule_array, "PKCS-1.1", CCA_KEYWORD_SIZE);

	CSNDDSV(&return_code,
		&reason_code,
		NULL,
		NULL,
		&rule_array_count,
		rule_array,
		(long *)&(attr->ulValueLen),
		attr->pValue,
		(long *)&in_data_len,
		in_data,
		(long *)&out_data_len,
		out_data);

	if (return_code == 4 && reason_code == 429) {
		return CKR_SIGNATURE_INVALID;
	} else if (return_code != CCA_SUCCESS) {
		CCADBG("CSNDDSV (RSA VERIFY)", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}


#ifndef NOAES
CK_RV
token_specific_aes_key_gen(CK_BYTE *key, CK_ULONG len)
{
	DBG("Unsupported function reached.");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
token_specific_aes_ecb(CK_BYTE  *in_data,
		       CK_ULONG  in_data_len,
		       CK_BYTE	*out_data,
		       CK_ULONG	*out_data_len,
		       CK_BYTE	*key_value,
		       CK_ULONG	 key_len,
		       CK_BYTE	 encrypt)
{
	DBG("Unsupported function reached.");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
token_specific_aes_cbc(CK_BYTE  *in_data,
		       CK_ULONG	 in_data_len,
		       CK_BYTE	*out_data,
		       CK_ULONG	*out_data_len,
		       CK_BYTE	*key_value,
		       CK_ULONG	 key_len,
		       CK_BYTE	*init_v,
		       CK_BYTE	 encrypt)
{
	DBG("Unsupported function reached.");
	return CKR_FUNCTION_NOT_SUPPORTED;
}
#endif

#ifndef NODH
/* Begin code contributed by Corrent corp. */
CK_RV
token_specific_dh_pkcs_derive(CK_BYTE  *z,
                              CK_ULONG *z_len,
                              CK_BYTE  *y,
                              CK_ULONG  y_len,
                              CK_BYTE  *x,
                              CK_ULONG  x_len,
                              CK_BYTE  *p,
                              CK_ULONG  p_len)
{
	DBG("Unsupported function reached.");
	return CKR_FUNCTION_NOT_SUPPORTED;
}

CK_RV
token_specific_dh_pkcs_key_pair_gen(TEMPLATE *publ_tmpl,
                                    TEMPLATE *priv_tmpl )
{
	DBG("Unsupported function reached.");
	return CKR_FUNCTION_NOT_SUPPORTED;
}
/* End code contributed by Corrent corp. */
#endif

/* See the top of this file for the declarations of mech_list and
 * mech_list_len.
 */
CK_RV
token_specific_get_mechanism_list(CK_MECHANISM_TYPE *pMechanismList, CK_ULONG *pulCount)
{
	CK_ULONG i;

	DBG("Enter");

	if (pMechanismList == NULL) {
		(*pulCount) = mech_list_len;
		return CKR_OK;
	}

	if ((*pulCount) < mech_list_len) {
		(*pulCount) = mech_list_len;
		st_err_log(111, __FILE__, __LINE__);
		return CKR_BUFFER_TOO_SMALL;
	}

	for (i = 0; i < mech_list_len; i++)
		pMechanismList[i] = mech_list[i].mech_type;
	(*pulCount) = mech_list_len;

	return CKR_OK;
}

CK_RV
token_specific_get_mechanism_info(CK_MECHANISM_TYPE type, CK_MECHANISM_INFO *pInfo)
{
        CK_ULONG i;

	DBG("Enter");

	for (i = 0; i < mech_list_len; i++) {
                if (mech_list[i].mech_type == type) {
                        memcpy(pInfo, &mech_list[i].mech_info,
                               sizeof(CK_MECHANISM_INFO));
                        return CKR_OK;
                }
        }

        st_err_log(28, __FILE__, __LINE__);
        return CKR_MECHANISM_INVALID;
}


CK_RV
sw_des3_cbc(CK_BYTE * in_data,
	    CK_ULONG in_data_len,
	    CK_BYTE *out_data,
	    CK_ULONG *out_data_len,
	    CK_BYTE *init_v,
	    CK_BYTE  *key_value,
	    CK_BYTE  encrypt)
{
	des_key_schedule des_key1;
	des_key_schedule des_key2;
	des_key_schedule des_key3;

	const_des_cblock key_SSL1, key_SSL2, key_SSL3;
	des_cblock ivec;

	DBG("Enter");

	// the des decrypt will only fail if the data length is not evenly divisible
	// by 8
	if (in_data_len % 8) {
		st_err_log(11, __FILE__, __LINE__);
		DBG("CKR_DATA_LEN_RANGE");
		return CKR_DATA_LEN_RANGE;
	}

	// The key as passed in is a 24 byte string containing 3 keys
	// pick it apart and create the key schedules
	memcpy(&key_SSL1, key_value, (size_t)8);
	memcpy(&key_SSL2, key_value+8, (size_t)8);
	memcpy(&key_SSL3, key_value+16, (size_t)8);
	des_set_key_unchecked(&key_SSL1, des_key1);
	des_set_key_unchecked(&key_SSL2, des_key2);
	des_set_key_unchecked(&key_SSL3, des_key3);

	memcpy(ivec, init_v, sizeof(ivec));

	// Encrypt or decrypt the data
	if (encrypt) {
		des_ede3_cbc_encrypt(in_data,
				out_data,
				in_data_len,
				des_key1,
				des_key2,
				des_key3,
				&ivec,
				DES_ENCRYPT);
		*out_data_len = in_data_len;
	} else {
		des_ede3_cbc_encrypt(in_data,
				out_data,
				in_data_len,
				des_key1,
				des_key2,
				des_key3,
				&ivec,
				DES_DECRYPT);

		*out_data_len = in_data_len;
	}

	return CKR_OK;
}

