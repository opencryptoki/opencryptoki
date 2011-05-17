
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
#include <dlfcn.h>

#include <openssl/des.h>

#include "cca_stdll.h"

#include "pkcs11types.h"
#include "p11util.h"
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
   { CKM_RSA_PKCS_KEY_PAIR_GEN,    { 512, 4096, CKF_HW | CKF_GENERATE_KEY_PAIR } },
   { CKM_RSA_PKCS,                 { 512, 4096, CKF_HW           |
                                                CKF_ENCRYPT      | CKF_DECRYPT |
                                                CKF_SIGN         | CKF_VERIFY } },
   { CKM_MD5_RSA_PKCS,             { 512, 4096, CKF_HW      |
                                                CKF_SIGN    | CKF_VERIFY } },
   { CKM_SHA1_RSA_PKCS,            { 512, 4096, CKF_HW      |
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
   { CKM_AES_KEY_GEN,                16,   32, CKF_HW },
   { CKM_AES_ECB,                    16,   32, CKF_HW      |
   					       CKF_ENCRYPT | CKF_DECRYPT |
   					       CKF_WRAP    | CKF_UNWRAP },
   { CKM_AES_CBC,                    16,   32, CKF_HW      |
   					       CKF_ENCRYPT | CKF_DECRYPT |
   					       CKF_WRAP    | CKF_UNWRAP },
   { CKM_AES_CBC_PAD,                16,   32, CKF_HW      |
   					       CKF_ENCRYPT | CKF_DECRYPT |
   					       CKF_WRAP    | CKF_UNWRAP },
   { CKM_SHA_1,                      { 0,    0, CKF_DIGEST } },
   { CKM_SHA_1_HMAC,                 { 0,    0, CKF_SIGN | CKF_VERIFY } },
   { CKM_SHA_1_HMAC_GENERAL,         { 0,    0, CKF_SIGN | CKF_VERIFY } },
   { CKM_MD5,                        { 0,    0, CKF_DIGEST } },
   { CKM_MD5_HMAC,                   { 0,    0, CKF_SIGN | CKF_VERIFY } },
   { CKM_MD5_HMAC_GENERAL,           { 0,    0, CKF_SIGN | CKF_VERIFY } },
   { CKM_EC_KEY_PAIR_GEN,	     { 160,    521, CKF_HW | CKF_GENERATE_KEY_PAIR |
				                    CKF_EC_NAMEDCURVE | CKF_EC_F_P } },
   { CKM_ECDSA,			     { 160,    521, CKF_HW | CKF_SIGN | CKF_VERIFY |
				                    CKF_EC_NAMEDCURVE | CKF_EC_F_P } },
   { CKM_ECDSA_SHA1,		     { 160,    521, CKF_HW | CKF_SIGN | CKF_VERIFY |
				                    CKF_EC_NAMEDCURVE | CKF_EC_F_P } }
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
	void *lib_csulcca;
	
	lib_csulcca = dlopen("libcsulcca.so",  (RTLD_GLOBAL | RTLD_NOW));
	if (lib_csulcca == NULL) {
		OCK_SYSLOG(LOG_ERR, "%s: Error loading library: [%s]\n", __FUNCTION__, dlerror());
		return CKR_FUNCTION_FAILED;
	}

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
		OCK_SYSLOG(LOG_WARNING, "Warning: CCA symmetric master key is not yet loaded");
	}
	if (memcmp(&rule_array[CCA_STATCCAE_ASYM_CMK_OFFSET], "2       ", 8)) {
		OCK_SYSLOG(LOG_WARNING, "Warning: CCA asymmetric master key is not yet loaded");
	}

	return CKR_OK;
}

CK_RV
token_specific_final()
{
	return CKR_OK;
}

CK_RV cca_key_gen(enum cca_key_type type, CK_BYTE *key, unsigned char *key_form,
		  unsigned char *key_type_1, CK_ULONG key_size)
{

	long return_code, reason_code;
	unsigned char key_length[CCA_KEYWORD_SIZE];
	unsigned char key_type_2[CCA_KEYWORD_SIZE] = { 0, };
	unsigned char kek_key_identifier_1[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char kek_key_identifier_2[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char *generated_key_identifier_1 = key;
	unsigned char generated_key_identifier_2[CCA_KEY_ID_SIZE] = { 0, };

	if (type == CCA_DES_KEY) {
		switch (key_size) {
		case 8:
			memcpy(key_length, "KEYLN8  ", (size_t)CCA_KEYWORD_SIZE);
			break;
		case 24:
			memcpy(key_length, "KEYLN24 ", (size_t)CCA_KEYWORD_SIZE);
			break;
		default:
			DBG("Invalid key length: %lu", key_size);
			OCK_LOG_ERR(ERR_KEY_SIZE_RANGE);
			return CKR_KEY_SIZE_RANGE;
		}
	} else if (type == CCA_AES_KEY) {
		switch (key_size) {
		case 16:
			memcpy(key_length, "KEYLN16 ", CCA_KEYWORD_SIZE);
			break;
		case 24:
			memcpy(key_length, "KEYLN24 ", (size_t)CCA_KEYWORD_SIZE);
			break;
		case 32:
			memcpy(key_length, "        ", (size_t)CCA_KEYWORD_SIZE);
			break;
		default:
			DBG("Invalid key length: %lu", key_size);
			OCK_LOG_ERR(ERR_KEY_SIZE_RANGE);
			return CKR_KEY_SIZE_RANGE;
		}
	} else {
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		return CKR_FUNCTION_FAILED;
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
		key,
		generated_key_identifier_2);

	if (return_code != CCA_SUCCESS) {
		CCADBG("CSNBKGN (KEYGEN)", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

//	memcpy(key, generated_key_identifier_1, (size_t)CCA_KEY_ID_SIZE);


	return CKR_OK;
}

CK_RV
token_specific_des_key_gen(CK_BYTE *des_key, CK_ULONG len, CK_ULONG key_size)
{
	long return_code, reason_code;
	unsigned char key_form[CCA_KEYWORD_SIZE], key_length[CCA_KEYWORD_SIZE];
	unsigned char key_type_1[CCA_KEYWORD_SIZE];

	DBG("Enter CCA DES keygen");

	memcpy(key_form, "OP      ", (size_t)CCA_KEYWORD_SIZE);
	memcpy(key_type_1, "DATA    ", (size_t)CCA_KEYWORD_SIZE);

	return cca_key_gen(CCA_DES_KEY, des_key, key_form, key_type_1, key_size);
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
		if (out_data != local_out)
			free(local_out);
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
		OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
		free(local_out);
		return CKR_BUFFER_TOO_SMALL;
	} else if (local_out != out_data) {
		memcpy(out_data, local_out, (size_t)length);
		free(local_out);
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
        CK_BYTE_PTR ptr;
        CK_ULONG tmpsize, tmpexp;


	if (!template_attribute_find(publ_tmpl, CKA_MODULUS_BITS, &attr)) {
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
		return CKR_TEMPLATE_INCOMPLETE;
	}
	mod_bits = *(CK_ULONG *)attr->pValue;


	/* If e is specified in the template, use it */
	rv = template_attribute_find(publ_tmpl, CKA_PUBLIC_EXPONENT, &pub_exp);
	if (rv == TRUE) {

                /* Per CCA manual, we really only support 3 values here:        *
                 * * 0 (generate random public exponent)                        *
                 * * 3 or                                                       *
                 * * 65537                                                      *
                 * Trim the P11 value so we can check what's comming our way    */

                tmpsize = pub_exp->ulValueLen;
                ptr = p11_bigint_trim(pub_exp->pValue, &tmpsize);
                /* If we trimmed the number correctly, only 3 bytes are         *
                 * sufficient to hold 65537 (0x010001)                          */
                if (tmpsize > 3)
			return CKR_TEMPLATE_INCONSISTENT;

                /* make pValue into CK_ULONG so we can compare */
                tmpexp = 0;
                memcpy((void *)&tmpexp + sizeof(CK_ULONG) - tmpsize,    // right align
                       ptr, tmpsize);

                /* Check for one of the three allowed values */
                if ( (tmpexp != 0) &&
                     (tmpexp != 3) &&
                     (tmpexp != 65537) )
                        return CKR_TEMPLATE_INCONSISTENT;


		size_of_e = (uint16_t)tmpsize;

		memcpy(&key_value_structure[CCA_PKB_E_SIZE_OFFSET],
		       &size_of_e, (size_t)CCA_PKB_E_SIZE);
		memcpy(&key_value_structure[CCA_PKB_E_OFFSET],
		       ptr, (size_t)tmpsize);
	}

	key_value_structure_length = CCA_KEY_VALUE_STRUCT_SIZE;
	memcpy(key_value_structure, &mod_bits, sizeof(uint16_t));

        /* One last check. CCA can't auto-generate a random public      *
         * exponent if the modulus length is more than 2048 bits        *
         * We should be ok checking the public exponent length in the   *
         * key_value_structure, since either the caller never           *
         * specified it or we trimmed it's size. The size should be     *
         * zero if the value is zero in both cases.                     *
         * public exponent has CCA_PKB_E_SIZE_OFFSET offset with        *
         * 2-bytes size                                                 */
        if (mod_bits > 2048 &&
            key_value_structure[CCA_PKB_E_SIZE_OFFSET] == 0x00 &&
            key_value_structure[CCA_PKB_E_SIZE_OFFSET + 1] == 0x00) {
                return CKR_TEMPLATE_INCONSISTENT;
        }

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
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
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
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
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
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
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
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
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
token_specific_aes_key_gen(CK_BYTE *aes_key, CK_ULONG key_size)
{
	long return_code, reason_code;
	unsigned char key_length[CCA_KEYWORD_SIZE];
	unsigned char key_token[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char key_value[32];
	unsigned char key_form[CCA_KEYWORD_SIZE];
	unsigned char key_type[CCA_KEYWORD_SIZE];
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0x20, };
	long exit_data_len = 0, rule_array_count;
	unsigned char exit_data[4] = { 0, };
	unsigned char reserved_1[4] = { 0, };
	unsigned char point_to_array_of_zeros = 0;
	unsigned char mkvp[16] = { 0, };
	
	memcpy(rule_array, "INTERNALAES     NO-KEY  ", (size_t) (CCA_KEYWORD_SIZE*3));
	memcpy(key_type, "DATA    ", (size_t)CCA_KEYWORD_SIZE);
	
	switch (key_size) {
		case 16:
			memcpy(rule_array + 3*CCA_KEYWORD_SIZE, "KEYLN16 ", CCA_KEYWORD_SIZE);
			break;
		case 24:
			memcpy(rule_array + 3*CCA_KEYWORD_SIZE, "KEYLN24 ", (size_t)CCA_KEYWORD_SIZE);
			break;
		case 32:
			memcpy(rule_array + 3*CCA_KEYWORD_SIZE, "KEYLN32 ", (size_t)CCA_KEYWORD_SIZE);
			break;
		default:
			DBG("Invalid key length: %lu", key_size);
			return CKR_KEY_SIZE_RANGE;
	}
#ifdef DEBUG
		{
			uint32_t j;
			DBG("Rule Array:");
			for ( j = 0; j < 32; j++)
				printf("%c", rule_array[j]);
			printf("\n");
			for ( j = 0; j < 8; j++)
				printf("%c", key_type[j]);
		}
#endif
	rule_array_count = 4;
	CSNBKTB(&return_code,
		&reason_code,
		&exit_data_len,
		exit_data,
		key_token,
		key_type,
		&rule_array_count,
		rule_array,
		NULL,
		reserved_1,
		NULL,
		&point_to_array_of_zeros,
		NULL,
		NULL,
		NULL,
		NULL,
		mkvp);
	
	if (return_code != CCA_SUCCESS) {
		CCADBG("CSNBTKB (TOKEN BUILD)", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}
	memcpy(key_form, "OP      ", (size_t)CCA_KEYWORD_SIZE);
	memcpy(key_type, "AESTOKEN", (size_t) CCA_KEYWORD_SIZE);
	memcpy(aes_key, key_token, (size_t)CCA_KEY_ID_SIZE);

	return cca_key_gen(CCA_AES_KEY, aes_key, key_form, key_type, key_size);
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
	
	long return_code, reason_code, rule_array_count, length;
	long pad_character = 0, block_size = 16;
	unsigned char chaining_vector[CCA_OCV_SIZE];
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
	long opt_data_len = 0, key_params_len =0, exit_data_len = 0, IV_len = 0, chain_vector_len = 0;
	char exit_data[0];
	CK_BYTE *local_out = out_data;

	key_len = 64;	
	rule_array_count = 4;
	memcpy(rule_array, "AES     ECB     KEYIDENTINITIAL ", 
	       rule_array_count*(size_t)CCA_KEYWORD_SIZE);
	
	if (encrypt) {
		CSNBSAE(&return_code,
			&reason_code,
			&exit_data_len,
			exit_data,
			&rule_array_count,
			rule_array,
			&key_len,
			key_value,
			&key_params_len,
			NULL,
			&block_size,
			&IV_len,
			NULL,
			&chain_vector_len,
			NULL,
			&in_data_len,
			in_data,
			out_data_len,
			local_out,
			&opt_data_len,
			NULL);
	} else {
		CSNBSAD(&return_code,
			&reason_code,
			&exit_data_len,
			exit_data,
			&rule_array_count,
			rule_array,
			&key_len,
			key_value,
			&key_params_len,
			NULL,
			&block_size,
			&IV_len,
			NULL,
			&chain_vector_len,
			NULL,
			&in_data_len,
			in_data,
			out_data_len,
			local_out,
			&opt_data_len,
			NULL);
	}
	
	if (return_code != CCA_SUCCESS) {
		if (encrypt)
			CCADBG("CSNBSAE (AES ENCRYPT)", return_code, reason_code);
		else
			CCADBG("CSNBSAD (AES DECRYPT)", return_code, reason_code);
#ifdef DEBUG
		{
			uint32_t *i = (uint32_t *) key_value, j;
			DBG("Bad key:");
		//	for ( j = 0; j < 16; j++)
		//		DBG("%.8x ", *i++);
		}
#endif
		(*out_data_len) = 0;
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
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
	long return_code, reason_code, rule_array_count, length;
	long pad_character = 0, block_size = 16;
	unsigned char IV[8] = { 0xfe, 0x43, 0x12, 0xed, 0xaa, 0xbb, 0xdd, 0x90 };
	unsigned char chaining_vector[32];
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE];
	long opt_data_len = 0, key_params_len =0, exit_data_len = 0, IV_len = 16, chain_vector_len = 32;
	CK_BYTE *local_out = out_data;
	char exit_data[0];

	if (in_data_len%16 == 0) {
		rule_array_count = 3;
		memcpy(rule_array, "AES     KEYIDENTINITIAL ", 
		       rule_array_count*(size_t)CCA_KEYWORD_SIZE);
	} else {
		if ((encrypt) && (*out_data_len < (in_data_len + 16))) {
			local_out = malloc(in_data_len + 16);
			if (!local_out) {
				DBG("Malloc of %lu bytes failed.", in_data_len + 16);
				return CKR_HOST_MEMORY;
			}
		}

		rule_array_count = 3;
		memcpy(rule_array, "AES     PKCS-PADKEYIDENT", 
		       rule_array_count*(size_t)CCA_KEYWORD_SIZE);
	}

	length = in_data_len;
	key_len = 64;
	if (encrypt) {
		CSNBSAE(&return_code,
			&reason_code,
			&exit_data_len,
			exit_data,
			&rule_array_count,
			rule_array,
			&key_len,
			key_value,
			&key_params_len,
			exit_data,
			&block_size,
			&IV_len,
			init_v,
			&chain_vector_len,
			chaining_vector,
			&length,
			in_data,
			out_data_len,
			out_data,
			&opt_data_len,
			NULL);
	} else {
		CSNBSAD(&return_code,
			&reason_code,
			&exit_data_len,
			exit_data,
			&rule_array_count,
			rule_array,
			&key_len,
			key_value,
			&key_params_len,
			NULL,
			&block_size,
			&IV_len,
			init_v,
			&chain_vector_len,
			chaining_vector,
			&length,
			in_data,
			out_data_len,
			out_data,
			&opt_data_len,
			NULL);
	}
	
	if (return_code != CCA_SUCCESS) {
		CCADBG("CSNBENC (AES ENCRYPT)", return_code, reason_code);
#ifdef DEBUG
		{
			uint32_t *i = (uint32_t *) key_value, j;
			DBG("Bad key:");
			//for ( j = 0; j < 16; j++)
			//	DBG("%.8x ", *i++);
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
		OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
		free(local_out);
		return CKR_BUFFER_TOO_SMALL;
	} else if (local_out != out_data) {
		memcpy(out_data, local_out, (size_t)length);
		free(local_out);
	}

	*out_data_len = length;

	return CKR_OK;
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
		OCK_LOG_ERR(ERR_BUFFER_TOO_SMALL);
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

        OCK_LOG_ERR(ERR_MECHANISM_INVALID);
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
		OCK_LOG_ERR(ERR_DATA_LEN_RANGE);
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

CK_RV
build_update_attribute(TEMPLATE *tmpl,
		CK_ATTRIBUTE_TYPE  type,
		CK_BYTE *data,
		CK_ULONG data_len)
{
	CK_ATTRIBUTE *attr;
	CK_RV rv;
	if (rv = build_attribute(type, data, data_len, &attr)) {
		DBG("Build attribute for type=%d failed rv=0x%lx\n", type, rv);
		return rv;
	}
	template_update_attribute(tmpl, attr);
	return CKR_OK;
}

uint16_t
cca_ec_privkey_offset(CK_BYTE *tok)
{
	uint8_t privkey_id = CCA_PRIVKEY_ID, privkey_rec;
	privkey_rec = ntohs(*(uint8_t*)&tok[CCA_EC_HEADER_SIZE]);
	if ((memcmp(&privkey_rec, &privkey_id, sizeof(uint8_t)) == 0)) {
		return CCA_EC_HEADER_SIZE;
	}
	DBG("+++++++++ Token key private section is CORRUPTED");
	return CCA_EC_HEADER_SIZE;
}

uint16_t
cca_ec_publkey_offset(CK_BYTE *tok)
{
	uint16_t priv_offset, privSec_len;
	uint8_t publkey_id = CCA_PUBLKEY_ID, publkey_rec;

	priv_offset = cca_ec_privkey_offset(tok);
	privSec_len = ntohs(*(uint16_t*)&tok[priv_offset + CCA_SECTION_LEN_OFFSET]);
	publkey_rec = ntohs(*(uint8_t*)&tok[priv_offset + privSec_len]);
	if ((memcmp(&publkey_rec, &publkey_id, sizeof(uint8_t)) == 0)) {
		return (priv_offset + privSec_len);
	}
	DBG("++++++++ Token key public section is CORRUPTED");
	return (priv_offset + privSec_len);
}

CK_RV
token_create_ec_keypair(TEMPLATE *publ_tmpl,
		TEMPLATE *priv_tmpl,
		CK_ULONG tok_len,
		CK_BYTE *tok)
{
	uint16_t pubkey_offset, qlen_offset, q_offset;
	uint16_t p_len, p_len_offset, i;
	CK_ULONG q_len;
	CK_BYTE q[CCATOK_EC_MAX_Q_LEN];
	CK_BBOOL found = FALSE;
	CK_RV rv;

	/*
	 * The token includes the header section first,
	 * the private key section in the middle,
	 * and the public key section last.
	 */

	/*
	 * Get Q data for public and private key.
	 */
	pubkey_offset = cca_ec_publkey_offset(tok);

	qlen_offset =  pubkey_offset + CCA_EC_INTTOK_PUBKEY_Q_LEN_OFFSET;
	q_len = *(uint16_t *)&tok[qlen_offset];
	q_len = ntohs(q_len);

	if (q_len > CCATOK_EC_MAX_Q_LEN) {
		DBG("Not enough room to return q.  (Got %d, need %ld)\n", CCATOK_EC_MAX_Q_LEN, q_len);
		return CKR_FUNCTION_FAILED;
	}

	q_offset = pubkey_offset + CCA_EC_INTTOK_PUBKEY_Q_OFFSET;
	memcpy(q, &tok[q_offset], (size_t)q_len);

	if ((rv = build_update_attribute(publ_tmpl, CKA_EC_POINT, q, q_len)))
	{
		DBG("Build and update attribute for q failed rv=0x%lx\n", rv);
		return rv;
	}

	if ((rv = build_update_attribute(priv_tmpl, CKA_EC_POINT, q, q_len)))
	{
		DBG("Build and update attribute for q failed rv=0x%lx\n", rv);
		return rv;
	}

	/*
	 * Get ECDSA PAMRAMS for both keys.
	 */
	p_len_offset = pubkey_offset + CCA_PUBL_P_LEN_OFFSET;
	p_len = *(uint16_t *)&tok[p_len_offset];
	p_len = ntohs(p_len);

	for (i = 0; i < NUMEC; i++) {
		if (p_len == der_ec_supported[i].len_bits) {
			found = TRUE;
			break;
		}
	}

	if(found == FALSE) {
		DBG("The p len %lx is not valid.\n", p_len);
		return CKR_FUNCTION_FAILED;
	}

	if ((rv = build_update_attribute(publ_tmpl, CKA_ECDSA_PARAMS,
					der_ec_supported[i].data,
					der_ec_supported[i].data_size))) {
		DBG("Build and update attribute for der data failed rv=0x%lx\n", rv);
		return rv;
	}

	if ((rv = build_update_attribute(priv_tmpl, CKA_ECDSA_PARAMS,
					der_ec_supported[i].data,
					der_ec_supported[i].data_size))) {
		DBG("Build and update attribute for der data failed rv=0x%lx\n", rv);
		return rv;
	}

	/*
	 * Save the CKA_IBM_OPAQUE for both keys.
	 */
	if ((rv = build_update_attribute(publ_tmpl, CKA_IBM_OPAQUE, tok, tok_len))) {
		DBG("Build and update attribute for tok failed rv=0x%lx\n", rv);
		return rv;
	}

	if ((rv = build_update_attribute(priv_tmpl, CKA_IBM_OPAQUE, tok, tok_len))) {
		DBG("Build and update attribute for tok failed rv=0x%lx\n", rv);
		return rv;
	}

	return CKR_OK;
}

CK_RV
token_specific_ec_generate_keypair(TEMPLATE *publ_tmpl,
				TEMPLATE *priv_tmpl)
{
	long return_code, reason_code, rule_array_count, exit_data_len = 0;
	unsigned char *exit_data = NULL;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	long key_value_structure_length, private_key_name_length, key_token_length;
	unsigned char key_value_structure[CCA_EC_KEY_VALUE_STRUCT_SIZE] = { 0, };
	unsigned char private_key_name[CCA_PRIVATE_KEY_NAME_SIZE] = { 0, };
	unsigned char key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
	long regeneration_data_length, generated_key_token_length;
	unsigned char regeneration_data[CCA_REGENERATION_DATA_SIZE] = { 0, };
	unsigned char transport_key_identifier[CCA_KEY_ID_SIZE] = { 0, };
	unsigned char generated_key_token[CCA_KEY_TOKEN_SIZE] = { 0, };
	unsigned int i;
	CK_BBOOL found = FALSE;
	CK_ATTRIBUTE *attr = NULL;
	CK_RV rv;
	long param1=0;
	unsigned char *param2=NULL;

	DBG("Entering EC Generate Keypair");

	if (!template_attribute_find(publ_tmpl, CKA_ECDSA_PARAMS, &attr)) {
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	for (i = 0; i < NUMEC; i++) {
		if ((attr->ulValueLen == der_ec_supported[i].data_size) &&
				(memcmp(attr->pValue, der_ec_supported[i].data,
				attr->ulValueLen) == 0)) {
			found = TRUE;
			break;
		}
	}

	if(found == FALSE) {
		OCK_LOG_ERR(ERR_MECHANISM_PARAM_INVALID);
		return CKR_MECHANISM_PARAM_INVALID;
	}

	/*
	 * See CCA doc: page 94 for offset of data in key_value_structure
	 */
	memcpy(key_value_structure,
			&(der_ec_supported[i].curve_type), sizeof(uint8_t));
	memcpy(&key_value_structure[CCA_PKB_EC_LEN_OFFSET],
			&(der_ec_supported[i].len_bits), sizeof(uint16_t));

	key_value_structure_length = CCA_EC_KEY_VALUE_STRUCT_SIZE;

	rule_array_count = 1;
	memcpy(rule_array, "ECC-PAIR", (size_t)(CCA_KEYWORD_SIZE));

	private_key_name_length = 0;

	key_token_length = CCA_KEY_TOKEN_SIZE;

	CSNDPKB(&return_code,
			&reason_code,
			&exit_data_len,
			exit_data,
			&rule_array_count,
			rule_array,
			&key_value_structure_length,
			key_value_structure,
			&private_key_name_length,
			private_key_name,
			&param1,
			param2,
			&param1,
			param2,
			&param1,
			param2,
			&param1,
			param2,
			&param1,
			param2,
			&key_token_length,
			key_token);

	if (return_code != CCA_SUCCESS) {
		CCADBG("CSNDPKB (EC KEY TOKEN BUILD)", return_code, reason_code);
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
			CCADBG("CSNDPKG (EC KEY GENERATE)", return_code, reason_code);
			return CKR_FUNCTION_FAILED;
	}

	DBG("ECC secure key token generated. size: %ld", generated_key_token_length);

	rv = token_create_ec_keypair(publ_tmpl, priv_tmpl,
			generated_key_token_length, generated_key_token);
	if (rv != CKR_OK) {
		DBG("token_create_ec_keypair failed. rv: %lu", rv);
		return rv;
	}

	return rv;
}

CK_RV
token_specific_ec_sign(CK_BYTE  * in_data,
			CK_ULONG   in_data_len,
			CK_BYTE  * out_data,
			CK_ULONG * out_data_len,
			OBJECT   * key_obj )
{
	long return_code, reason_code, rule_array_count;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	long signature_bit_length;
	CK_ATTRIBUTE *attr;

	DBG("Entering EC Sign, in_data_len is %lu.", in_data_len);

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr)) {
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* CCA doc: page 113 */
	rule_array_count = 1;
	memcpy(rule_array, "ECDSA   ", CCA_KEYWORD_SIZE);

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
			CCADBG("CSNDDSG (EC SIGN)", return_code, reason_code);
			return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV
token_specific_ec_verify(CK_BYTE  * in_data,
			  CK_ULONG   in_data_len,
			  CK_BYTE  * out_data,
			  CK_ULONG   out_data_len,
			  OBJECT   * key_obj )
{
	long return_code, reason_code, rule_array_count;
	unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
	CK_ATTRIBUTE *attr;

	DBG("Entering EC Verify");

	/* Find the secure key token */
	if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr))	{
		OCK_LOG_ERR(ERR_TEMPLATE_INCOMPLETE);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* CCA doc: page 118 */
	rule_array_count = 1;
	memcpy(rule_array, "ECDSA   ", CCA_KEYWORD_SIZE);

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
		CCADBG("CSNDDSV (EC VERIFY)", return_code, reason_code);
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}
