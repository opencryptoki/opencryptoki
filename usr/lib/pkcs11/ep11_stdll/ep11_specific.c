/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/***************************************************************************
			  Change Log
			  ==========
****************************************************************************/

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "errno.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "stdll.h"
#include "attributes.h"
#include "trace.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <asm/zcrypt.h>
#include <syslog.h>
#include <dlfcn.h>
#include <lber.h>
#include <grp.h>

#ifdef DEBUG
#include <ctype.h>
#endif

#include "ep11.h"
#include "ep11_func.h"

#define EP11SHAREDLIB "libep11.so"

CK_RV ep11tok_get_mechanism_list(STDLL_TokData_t *tokdata,
				 CK_MECHANISM_TYPE_PTR mlist,
				 CK_ULONG_PTR count);
CK_RV ep11tok_get_mechanism_info(STDLL_TokData_t *tokdata,
				 CK_MECHANISM_TYPE type,
				 CK_MECHANISM_INFO_PTR pInfo);

static m_GenerateRandom_t	dll_m_GenerateRandom;
static m_SeedRandom_t		dll_m_SeedRandom;

static m_Digest_t		dll_m_Digest;
static m_DigestInit_t		dll_m_DigestInit;
static m_DigestUpdate_t		dll_m_DigestUpdate;
static m_DigestKey_t		dll_m_DigestKey;
static m_DigestFinal_t		dll_m_DigestFinal;
static m_DigestSingle_t		dll_m_DigestSingle;

static m_Encrypt_t		dll_m_Encrypt;
static m_EncryptInit_t		dll_m_EncryptInit;
static m_EncryptUpdate_t	dll_m_EncryptUpdate;
static m_EncryptFinal_t		dll_m_EncryptFinal;
static m_EncryptSingle_t	dll_m_EncryptSingle;

static m_Decrypt_t		dll_m_Decrypt;
static m_DecryptInit_t		dll_m_DecryptInit;
static m_DecryptUpdate_t	dll_m_DecryptUpdate;
static m_DecryptFinal_t		dll_m_DecryptFinal;
static m_DecryptSingle_t	dll_m_DecryptSingle;

static m_ReencryptSingle_t	dll_m_ReencryptSingle;
static m_GenerateKey_t		dll_m_GenerateKey;
static m_GenerateKeyPair_t	dll_m_GenerateKeyPair;

static m_Sign_t			dll_m_Sign;
static m_SignInit_t		dll_m_SignInit;
static m_SignUpdate_t		dll_m_SignUpdate;
static m_SignFinal_t		dll_m_SignFinal;
static m_SignSingle_t		dll_m_SignSingle;

static m_Verify_t		dll_m_Verify;
static m_VerifyInit_t		dll_m_VerifyInit;
static m_VerifyUpdate_t		dll_m_VerifyUpdate;
static m_VerifyFinal_t		dll_m_VerifyFinal;
static m_VerifySingle_t		dll_m_VerifySingle;

static m_WrapKey_t		dll_m_WrapKey;
static m_UnwrapKey_t		dll_m_UnwrapKey;
static m_DeriveKey_t		dll_m_DeriveKey;

static m_GetMechanismList_t	dll_m_GetMechanismList;
static m_GetMechanismInfo_t	dll_m_GetMechanismInfo;
static m_GetAttributeValue_t	dll_m_GetAttributeValue;
static m_SetAttributeValue_t	dll_m_SetAttributeValue;

static m_Login_t		dll_m_Login;
static m_Logout_t		dll_m_Logout;
static m_admin_t		dll_m_admin;
static m_add_backend_t		dll_m_add_backend;
static m_init_t			dll_m_init;
static m_shutdown_t		dll_m_shutdown;

#ifdef DEBUG

/* a simple function for dumping out a memory area */
static inline void hexdump(void *buf, size_t buflen)
{
	/*           1         2         3         4         5         6
		     0123456789012345678901234567890123456789012345678901234567890123456789
		     xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx    ................
	*/

	int i, j;
	char line[68];
	for (i=0; i < buflen; i += 16) {
		for (j=0; j < 16; j++) {
			if (i+j < buflen) {
				unsigned char b = ((unsigned char*)buf)[i+j];
				sprintf(line + j*3, "%02hhx ", b);
				line[51+j] = (isalnum(b) ? b : '.');
			} else {
				sprintf(line + j*3, "   ");
				line[51+j] = ' ';
			}
		}
		line[47] = line[48] = line[49] = line[50] = ' ';
		line[67] = '\0';
		TRACE_DEBUG("%s\n", line);
	}
}

#define TRACE_DEBUG_DUMP(_buf, _buflen) hexdump(_buf, _buflen)

#endif /* DEBUG */

CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "IBM EP11Tok ";
CK_CHAR descr[] = "IBM PKCS#11 EP11 token";
CK_CHAR label[] = "IBM OS PKCS#11   ";

/* largest blobsize ever seen is about 5k (for 4096 mod bits RSA keys) */
#define MAX_BLOBSIZE 8192
#define MAX_CSUMSIZE 64
#define MAX_DIGEST_STATE_BYTES 1024
#define MAX_CRYPT_STATE_BYTES 8192
#define MAX_SIGN_STATE_BYTES 8192
#define MAX_APQN 256

/* wrap_key is used for importing keys */
char     wrap_key_name[] = "EP11_wrapkey";

/* EP11 token private data */
typedef struct {
    uint64_t      *target_list; // pointer to adapter target list
    unsigned char *ep11_pin_blob;
    CK_ULONG      ep11_pin_blob_len;
    CK_BYTE       raw2key_wrap_blob[MAX_BLOBSIZE];
    size_t        raw2key_wrap_blob_l;
} ep11_private_data_t;

/* target list of adapters/domains, specified in a config file by user,
   tells the device driver which adapter/domain pairs should be used,
   they must have the same master key */
typedef struct {
	short format;
	short length;
	short apqns[2*MAX_APQN];
} __attribute__((packed)) ep11_target_t;

/* defined in the makefile, ep11 library can run standalone (without HW card),
   crypto algorithms are implemented in software then (no secure key) */


/* mechanisms provided by this token will be generated from the underlaying
 * crypto adapter. Anyway to be conform to the generic mech_list handling
 * we need to define these dummies */
MECH_LIST_ELEMENT mech_list[] = {};
CK_ULONG mech_list_len = 0;

/* mechanisms yet unknown by ock, but known by EP11 */
#define CKM_SHA224_RSA_PKCS       0x00000046
#define CKM_SHA224_RSA_PKCS_PSS   0x00000047
#define CKM_SHA384_RSA_PKCS_PSS   0x00000044
#define CKM_SHA512_RSA_PKCS_PSS   0x00000045
#define CKM_SHA224                0x00000255
#define CKM_SHA224_KEY_DERIVATION 0x00000396
#define CKM_SHA256_RSA_PKCS_PSS   0x00000043
#define CKM_SHA224_HMAC           0x00000256
#define CKM_SHA384_KEY_DERIVATION 0x00000394
#define CKM_SHA512_KEY_DERIVATION 0x00000395
#define CKM_SHA512_224            0x000002B0
#define CKM_SHA512_224_HMAC       0x000002B1
#define CKM_SHA512_224_HMAC_GENERAL 0x000002B2
#define CKM_SHA512_256            0x000002C0
#define CKM_SHA512_256_HMAC       0x000002C1
#define CKM_SHA512_256_HMAC_GENERAL 0x000002C2
#define CKM_ECDSA_SHA224          0x00001043

/* Vendor specific mechanisms unknown by ock, but known by EP11 */
#define CKA_IBM_MACKEY                     CKM_VENDOR_DEFINED + 0x00010007
#define CKM_IBM_ECDSA_SHA224               CKM_VENDOR_DEFINED + 0x00010008
#define CKM_IBM_ECDSA_SHA256               CKM_VENDOR_DEFINED + 0x00010009
#define CKM_IBM_ECDSA_SHA384               CKM_VENDOR_DEFINED + 0x0001000A
#define CKM_IBM_ECDSA_SHA512               CKM_VENDOR_DEFINED + 0x0001000B
#define CKM_IBM_EC_MULTIPLY                CKM_VENDOR_DEFINED + 0x0001000C
#define CKM_IBM_EAC                        CKM_VENDOR_DEFINED + 0x0001000D
#define CKM_IBM_SHA512_256                 CKM_VENDOR_DEFINED + 0x00010012
#define CKM_IBM_SHA512_224                 CKM_VENDOR_DEFINED + 0x00010013
#define CKM_IBM_SHA512_256_HMAC            CKM_VENDOR_DEFINED + 0x00010014
#define CKM_IBM_SHA512_224_HMAC            CKM_VENDOR_DEFINED + 0x00010015
#define CKM_IBM_SHA512_256_KEY_DERIVATION  CKM_VENDOR_DEFINED + 0x00010016
#define CKM_IBM_SHA512_224_KEY_DERIVATION  CKM_VENDOR_DEFINED + 0x00010017
#define CKM_IBM_ATTRIBUTEBOUND_WRAP        CKM_VENDOR_DEFINED + 0x00020004
#define CKM_IBM_TRANSPORTKEY               CKM_VENDOR_DEFINED + 0x00020005
#define CKM_IBM_DH_PKCS_DERIVE_RAW         CKM_VENDOR_DEFINED + 0x00020006
#define CKM_IBM_ECDH1_DERIVE_RAW           CKM_VENDOR_DEFINED + 0x00020007
#define CKM_IBM_RETAINKEY                  CKM_VENDOR_DEFINED + 0x00040001


static CK_RV
check_key_attributes(CK_KEY_TYPE kt, CK_OBJECT_CLASS kc, CK_ATTRIBUTE_PTR attrs,
		     CK_ULONG attrs_len, CK_ATTRIBUTE_PTR *p_attrs,
		     CK_ULONG *p_attrs_len) {

	CK_RV rc;
	CK_ULONG i;
	CK_BBOOL true = TRUE;
	CK_ULONG check_types_pub[] = {CKA_VERIFY, CKA_ENCRYPT, CKA_WRAP };
	CK_ULONG check_types_priv[] = {CKA_SIGN, CKA_DECRYPT, CKA_UNWRAP };
	CK_ULONG check_types_sec[] =
		{CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP};
	CK_ULONG check_types_gen_sec[] =
		{CKA_SIGN, CKA_VERIFY, CKA_ENCRYPT, CKA_DECRYPT};
	CK_ULONG check_types_derive[] = {CKA_DERIVE};
	CK_ULONG *check_types = NULL;
	CK_BBOOL *check_values[] = { &true, &true, &true, &true };
	CK_ULONG attr_cnt = 0;

	/* check/add attributes for public key template */
	if ((rc = dup_attribute_array(attrs, attrs_len,
				      p_attrs, p_attrs_len)))
		return rc;

	switch (kc) {
	case CKO_SECRET_KEY:
		if (kt == CKK_GENERIC_SECRET) {
			check_types = &check_types_gen_sec[0];
			attr_cnt = sizeof(check_types_gen_sec)/sizeof(CK_ULONG);
		} else {
			check_types = &check_types_sec[0];
			attr_cnt = sizeof(check_types_sec)/sizeof(CK_ULONG);
		}
		break;
	case CKO_PUBLIC_KEY:
		if ((kt == CKK_EC) || (kt == CKK_ECDSA) ||
		    (kt == CKK_DSA)) {
			check_types = &check_types_pub[0];
			attr_cnt = 1; /* only CKA_VERIFY */
		} else if (kt == CKK_RSA) {
			check_types = &check_types_pub[0];
			attr_cnt = sizeof(check_types_pub)/sizeof(CK_ULONG);
		}
		/* do nothing for CKM_DH_PKCS_KEY_PAIR_GEN
		   and CKM_DH_PKCS_PARAMETER_GEN */
		break;
	case CKO_PRIVATE_KEY:
		if ((kt == CKK_EC) || (kt == CKK_ECDSA) ||
		    (kt == CKK_DSA)) {
			check_types = &check_types_priv[0];
			attr_cnt = 1; /* only CKA_SIGN */
		} else if (kt == CKK_RSA) {
			check_types = &check_types_priv[0];
			attr_cnt = sizeof(check_types_priv)/sizeof(CK_ULONG);
		} else if (kt == CKK_DH) {
			check_types = &check_types_derive[0];
			attr_cnt = sizeof(check_types_derive)/sizeof(CK_ULONG);
		}
		break;
	default:
		return CKR_OK;
	}

	for (i = 0; i < attr_cnt; i++, check_types++) {
		CK_ATTRIBUTE_PTR attr = get_attribute_by_type(*p_attrs,
							      *p_attrs_len, *check_types);
		if (!attr) {
			rc = add_to_attribute_array(p_attrs, p_attrs_len,
						    *check_types,
						    (CK_BYTE *) check_values[i],
						    sizeof(*check_values[i]));
			if (rc)
				goto cleanup;
		}
	}
	return CKR_OK;
cleanup:
	if (rc) {
		free_attribute_array(*p_attrs, *p_attrs_len);
		*p_attrs = NULL;
		*p_attrs_len = 0;
	}
	return rc;
}

CK_RV
ber_encode_RSAPublicKey(CK_BBOOL length_only, CK_BYTE **data, CK_ULONG *data_len,
			CK_ATTRIBUTE *modulus, CK_ATTRIBUTE *publ_exp)
{
	CK_ULONG len, offset, total, total_len;
	CK_RV rc;
	CK_BYTE *buf = NULL;
	CK_BYTE *buf2 = NULL;
	CK_BYTE *buf3 = NULL;
	BerValue *val;
	BerElement *ber;

	offset = 0;
	rc = 0;
	total_len = ber_AlgIdRSAEncryptionLen;
	total = 0;

	rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, modulus->ulValueLen);
	offset += len;
	rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, publ_exp->ulValueLen);
	offset += len;

	if (rc != CKR_OK) {
		TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
		return CKR_FUNCTION_FAILED;
	}

	buf = (CK_BYTE *)malloc(offset);
	if (!buf) {
		TRACE_ERROR("%s Memory allocation failed\n", __func__);
		return CKR_HOST_MEMORY;
	}
	offset = 0;
	rc = 0;

	rc = ber_encode_INTEGER(FALSE, &buf2, &len,
				(CK_BYTE *)modulus + sizeof(CK_ATTRIBUTE),
				modulus->ulValueLen);
	if (rc != CKR_OK) {
		TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
		return rc;
	}
	memcpy(buf+offset, buf2, len);
	offset += len;
	free(buf2);

	rc = ber_encode_INTEGER(FALSE, &buf2, &len,
				(CK_BYTE *)publ_exp + sizeof(CK_ATTRIBUTE),
				publ_exp->ulValueLen);
	if (rc != CKR_OK) {
		TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
		return rc;
	}
	memcpy(buf+offset, buf2, len);
	offset += len;
	free(buf2);

	rc = ber_encode_SEQUENCE(FALSE, &buf2, &len, buf, offset);
	if (rc != CKR_OK) {
		TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
		return rc;
	}

	/* length of outer sequence */
	rc = ber_encode_OCTET_STRING(TRUE, NULL, &total, buf2, len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("%s ber_encode_Oct_Str failed with rc=0x%lx\n", __func__, rc);
		return rc;
	} else
		total_len += total + 1;

	/* mem for outer sequence */
	buf3 = (CK_BYTE *)malloc(total_len);
	if (!buf3) {
		TRACE_ERROR("%s Memory allocation failed\n", __func__);
		return CKR_HOST_MEMORY;
	}
	total_len = 0;

	/* copy alg id */
	memcpy(buf3+total_len, ber_AlgIdRSAEncryption, ber_AlgIdRSAEncryptionLen);
	total_len += ber_AlgIdRSAEncryptionLen;

	/* need a bitstring */
	ber = ber_alloc_t(LBER_USE_DER);
	rc  = ber_put_bitstring(ber, buf2, len*8, 0x03);
	rc  = ber_flatten(ber, &val);
	memcpy(buf3+total_len, val->bv_val, val->bv_len);
	total_len += val->bv_len;

	rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf3, total_len);
	if (rc != CKR_OK)
		TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);

	return rc;
}

/* get the public key from a SPKI
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *     algorithm         AlgorithmIdentifier,
 *     subjectPublicKey  BIT STRING
 *   }
 *
 *   AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm   OBJECT IDENTIFIER,
 *     parameters  ANY DEFINED BY algorithm OPTIONAL
 *   }
 */
CK_RV
ep11_spki_key(CK_BYTE *spki, CK_BYTE **key, CK_ULONG *bit_str_len)
{
	CK_BYTE *out_seq, *id_seq, *bit_str;
	CK_BYTE *data;
	CK_ULONG data_len;
	CK_ULONG field_len;
	CK_ULONG key_len_bytes;
	CK_RV rc;
	CK_ULONG length_octets = 0;
	CK_ULONG len = 0;

	*bit_str_len = 0;
	out_seq = spki;
	rc = ber_decode_SEQUENCE(out_seq, &data, &data_len, &field_len);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s ber_decode_SEQUENCE #1 failed rc=0x%lx\n",
			    __func__, rc);
		return CKR_FUNCTION_FAILED;
	}

	id_seq = out_seq + field_len - data_len;
	/* get id seq length */
	rc = ber_decode_SEQUENCE(id_seq, &data, &data_len, &field_len);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s ber_decode_SEQUENCE #2 failed rc=0x%lx\n",
			    __func__, rc);
		return CKR_FUNCTION_FAILED;
	}

	bit_str = id_seq + field_len;
	/* we should be at a bistring */
	if (bit_str[0] != 0x03) {
		TRACE_ERROR("%s ber_decode no BITSTRING\n", __func__);
		return CKR_GENERAL_ERROR;
	}

	if ((bit_str[1] & 0x80) == 0) {
		key_len_bytes = 1;
		*bit_str_len = bit_str[1] & 0x7F;
	} else {
		key_len_bytes = 1 + (bit_str[1] & 0x7F);
	}

	*key = bit_str + key_len_bytes + 2; /* one 'unused bits' byte */

	if (*bit_str_len == 0) {
		length_octets = bit_str[1] & 0x7F;

		if (length_octets == 1) {
			len = bit_str[2];
		}

		if (length_octets == 2) {
			len = bit_str[2];
			len = len << 8;
			len |= bit_str[3];
		}

		if (length_octets == 3) {
			len = bit_str[2];
			len = len << 8;
			len |= bit_str[3];
			len = len << 8;
			len |= bit_str[4];
		}
		*bit_str_len = len;
	}

	return CKR_OK;
}


CK_RV
ep11_get_keytype(CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
		 CK_MECHANISM_PTR mech, CK_ULONG *type, CK_ULONG *class)
{
	int i;
	CK_RV rc = CKR_TEMPLATE_INCONSISTENT;

	*type  = 0;
	*class = 0;

	for (i = 0; i < attrs_len; i++) {
		if (attrs[i].type == CKA_CLASS)
			*class = *(CK_ULONG *)attrs[i].pValue;
	}

	for (i = 0; i < attrs_len; i++) {
		if (attrs[i].type == CKA_KEY_TYPE) {
			*type = *(CK_ULONG *)attrs[i].pValue;
			return CKR_OK;
		}
	}

	/* no CKA_KEY_TYPE found, derive from mech */

	switch (mech->mechanism) {
	case CKM_DES_KEY_GEN:
		*type = CKK_DES;
		break;

	case CKM_DES3_KEY_GEN:
		*type = CKK_DES3;
		break;

	case CKM_CDMF_KEY_GEN:
		*type = CKK_CDMF;
		break;

	case CKM_AES_KEY_GEN:
		*type = CKK_AES;
		break;

	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		*type = CKK_RSA;
		break;

	case CKM_EC_KEY_PAIR_GEN:
		*type = CKK_EC;
		break;

	case CKM_DSA_KEY_PAIR_GEN:
		*type = CKK_DSA;
		break;

	case CKM_DH_PKCS_KEY_PAIR_GEN:
		*type = CKK_DH;
		break;

	default:
		return CKR_MECHANISM_INVALID;
	}

	rc = CKR_OK;

	return rc;
}

/* for logging, debugging */
static const char* ep11_get_ckm(CK_ULONG mechanism)
{
	switch(mechanism) {
	case CKM_RSA_PKCS_KEY_PAIR_GEN: return "CKM_RSA_PKCS_KEY_PAIR_GEN";
	case CKM_RSA_PKCS: return "CKM_RSA_PKCS";
	case CKM_RSA_9796: return "CKM_RSA_9796";
	case CKM_RSA_X_509: return "CKM_RSA_X_509";
	case CKM_MD2_RSA_PKCS: return "CKM_MD2_RSA_PKCS";
	case CKM_MD5_RSA_PKCS: return "CKM_MD5_RSA_PKCS";
	case CKM_SHA1_RSA_PKCS: return "CKM_SHA1_RSA_PKCS";
	case CKM_RIPEMD128_RSA_PKCS: return "CKM_RIPEMD128_RSA_PKCS";
	case CKM_RIPEMD160_RSA_PKCS: return "CKM_RIPEMD160_RSA_PKCS";
	case CKM_RSA_PKCS_OAEP: return "CKM_RSA_PKCS_OAEP";
	case CKM_RSA_X9_31_KEY_PAIR_GEN: return "CKM_RSA_X9_31_KEY_PAIR_GEN";
	case CKM_RSA_X9_31: return "CKM_RSA_X9_31";
	case CKM_SHA1_RSA_X9_31: return "CKM_SHA1_RSA_X9_31";
	case CKM_RSA_PKCS_PSS: return "CKM_RSA_PKCS_PSS";
	case CKM_SHA1_RSA_PKCS_PSS: return "CKM_SHA1_RSA_PKCS_PSS";
	case CKM_DSA_KEY_PAIR_GEN: return "CKM_DSA_KEY_PAIR_GEN";
	case CKM_DSA: return "CKM_DSA";
	case CKM_DSA_SHA1: return "CKM_DSA_SHA1";
	case CKM_DH_PKCS_KEY_PAIR_GEN: return "CKM_DH_PKCS_KEY_PAIR_GEN";
	case CKM_DH_PKCS_DERIVE: return "CKM_DH_PKCS_DERIVE";
	case CKM_X9_42_DH_KEY_PAIR_GEN: return "CKM_X9_42_DH_KEY_PAIR_GEN";
	case CKM_X9_42_DH_DERIVE: return "CKM_X9_42_DH_DERIVE";
	case CKM_X9_42_DH_HYBRID_DERIVE: return "CKM_X9_42_DH_HYBRID_DERIVE";
	case CKM_X9_42_MQV_DERIVE: return "CKM_X9_42_MQV_DERIVE";
	case CKM_SHA256_RSA_PKCS: return "CKM_SHA256_RSA_PKCS";
	case CKM_SHA384_RSA_PKCS: return "CKM_SHA384_RSA_PKCS";
	case CKM_SHA512_RSA_PKCS: return "CKM_SHA512_RSA_PKCS";
	case CKM_RC2_KEY_GEN: return "CKM_RC2_KEY_GEN";
	case CKM_RC2_ECB: return "CKM_RC2_ECB";
	case CKM_RC2_CBC: return "CKM_RC2_CBC";
	case CKM_RC2_MAC: return "CKM_RC2_MAC";
	case CKM_RC2_MAC_GENERAL: return "CKM_RC2_MAC_GENERAL";
	case CKM_RC2_CBC_PAD: return "CKM_RC2_CBC_PAD";
	case CKM_RC4_KEY_GEN: return "CKM_RC4_KEY_GEN";
	case CKM_RC4: return "CKM_RC4";
	case CKM_DES_KEY_GEN: return "CKM_DES_KEY_GEN";
	case CKM_DES_ECB: return "CKM_DES_ECB";
	case CKM_DES_CBC: return "CKM_DES_CBC";
	case CKM_DES_MAC: return "CKM_DES_MAC";
	case CKM_DES_MAC_GENERAL: return "CKM_DES_MAC_GENERAL";
	case CKM_DES_CBC_PAD: return "CKM_DES_CBC_PAD";
	case CKM_DES2_KEY_GEN: return "CKM_DES2_KEY_GEN";
	case CKM_DES3_KEY_GEN: return "CKM_DES3_KEY_GEN";
	case CKM_DES3_ECB: return "CKM_DES3_ECB";
	case CKM_DES3_CBC: return "CKM_DES3_CBC";
	case CKM_DES3_MAC: return "CKM_DES3_MAC";
	case CKM_DES3_MAC_GENERAL: return "CKM_DES3_MAC_GENERAL";
	case CKM_DES3_CBC_PAD: return "CKM_DES3_CBC_PAD";
	case CKM_CDMF_KEY_GEN: return "CKM_CDMF_KEY_GEN";
	case CKM_CDMF_ECB: return "CKM_CDMF_ECB";
	case CKM_CDMF_CBC: return "CKM_CDMF_CBC";
	case CKM_CDMF_MAC: return "CKM_CDMF_MAC";
	case CKM_CDMF_MAC_GENERAL: return "CKM_CDMF_MAC_GENERAL";
	case CKM_CDMF_CBC_PAD: return "CKM_CDMF_CBC_PAD";
	case CKM_MD2: return "CKM_MD2";
	case CKM_MD2_HMAC: return "CKM_MD2_HMAC";
	case CKM_MD2_HMAC_GENERAL: return "CKM_MD2_HMAC_GENERAL";
	case CKM_MD5: return "CKM_MD5";
	case CKM_MD5_HMAC: return "CKM_MD5_HMAC";
	case CKM_MD5_HMAC_GENERAL: return "CKM_MD5_HMAC_GENERAL";
	case CKM_SHA_1: return "CKM_SHA_1";
	case CKM_SHA_1_HMAC: return "CKM_SHA_1_HMAC";
	case CKM_SHA_1_HMAC_GENERAL: return "CKM_SHA_1_HMAC_GENERAL";
	case CKM_RIPEMD128: return "CKM_RIPEMD128";
	case CKM_RIPEMD128_HMAC: return "CKM_RIPEMD128_HMAC";
	case CKM_RIPEMD128_HMAC_GENERAL: return "CKM_RIPEMD128_HMAC_GENERAL";
	case CKM_RIPEMD160: return "CKM_RIPEMD160";
	case CKM_RIPEMD160_HMAC: return "CKM_RIPEMD160_HMAC";
	case CKM_RIPEMD160_HMAC_GENERAL: return "CKM_RIPEMD160_HMAC_GENERAL";
	case CKM_SHA256: return "CKM_SHA256";
	case CKM_SHA256_HMAC: return "CKM_SHA256_HMAC";
	case CKM_SHA256_HMAC_GENERAL: return "CKM_SHA256_HMAC_GENERAL";
	case CKM_SHA384: return "CKM_SHA384";
	case CKM_SHA384_HMAC: return "CKM_SHA384_HMAC";
	case CKM_SHA384_HMAC_GENERAL: return "CKM_SHA384_HMAC_GENERAL";
	case CKM_SHA512: return "CKM_SHA512";
	case CKM_SHA512_HMAC: return "CKM_SHA512_HMAC";
	case CKM_SHA512_HMAC_GENERAL: return "CKM_SHA512_HMAC_GENERAL";
	case CKM_CAST_KEY_GEN: return "CKM_CAST_KEY_GEN";
	case CKM_CAST_ECB: return "CKM_CAST_ECB";
	case CKM_CAST_CBC: return "CKM_CAST_CBC";
	case CKM_CAST_MAC: return "CKM_CAST_MAC";
	case CKM_CAST_MAC_GENERAL: return "CKM_CAST_MAC_GENERAL";
	case CKM_CAST_CBC_PAD: return "CKM_CAST_CBC_PAD";
	case CKM_CAST3_KEY_GEN: return "CKM_CAST3_KEY_GEN";
	case CKM_CAST3_ECB: return "CKM_CAST3_ECB";
	case CKM_CAST3_CBC: return "CKM_CAST3_CBC";
	case CKM_CAST3_MAC: return "CKM_CAST3_MAC";
	case CKM_CAST3_MAC_GENERAL: return "CKM_CAST3_MAC_GENERAL";
	case CKM_CAST3_CBC_PAD: return "CKM_CAST3_CBC_PAD";
	case CKM_CAST5_KEY_GEN: return "CKM_CAST5_KEY_GEN";
	case CKM_CAST5_ECB: return "CKM_CAST5_ECB";
	case CKM_CAST5_CBC: return "CKM_CAST5_CBC";
	case CKM_CAST5_MAC: return "CKM_CAST5_MAC";
	case CKM_CAST5_MAC_GENERAL: return "CKM_CAST5_MAC_GENERAL";
	case CKM_CAST5_CBC_PAD: return "CKM_CAST5_CBC_PAD";
	case CKM_RC5_KEY_GEN: return "CKM_RC5_KEY_GEN";
	case CKM_RC5_ECB: return "CKM_RC5_ECB";
	case CKM_RC5_CBC: return "CKM_RC5_CBC";
	case CKM_RC5_MAC: return "CKM_RC5_MAC";
	case CKM_RC5_MAC_GENERAL: return "CKM_RC5_MAC_GENERAL";
	case CKM_RC5_CBC_PAD: return "CKM_RC5_CBC_PAD";
	case CKM_IDEA_KEY_GEN: return "CKM_IDEA_KEY_GEN";
	case CKM_IDEA_ECB: return "CKM_IDEA_ECB";
	case CKM_IDEA_CBC: return "CKM_IDEA_CBC";
	case CKM_IDEA_MAC: return "CKM_IDEA_MAC";
	case CKM_IDEA_MAC_GENERAL: return "CKM_IDEA_MAC_GENERAL";
	case CKM_IDEA_CBC_PAD: return "CKM_IDEA_CBC_PAD";
	case CKM_GENERIC_SECRET_KEY_GEN: return "CKM_GENERIC_SECRET_KEY_GEN";
	case CKM_CONCATENATE_BASE_AND_KEY: return "CKM_CONCATENATE_BASE_AND_KEY";
	case CKM_CONCATENATE_BASE_AND_DATA: return "CKM_CONCATENATE_BASE_AND_DATA";
	case CKM_CONCATENATE_DATA_AND_BASE: return "CKM_CONCATENATE_DATA_AND_BASE";
	case CKM_XOR_BASE_AND_DATA: return "CKM_XOR_BASE_AND_DATA";
	case CKM_EXTRACT_KEY_FROM_KEY: return "CKM_EXTRACT_KEY_FROM_KEY";
	case CKM_SSL3_PRE_MASTER_KEY_GEN: return "CKM_SSL3_PRE_MASTER_KEY_GEN";
	case CKM_SSL3_MASTER_KEY_DERIVE: return "CKM_SSL3_MASTER_KEY_DERIVE";
	case CKM_SSL3_KEY_AND_MAC_DERIVE: return "CKM_SSL3_KEY_AND_MAC_DERIVE";
	case CKM_SSL3_MASTER_KEY_DERIVE_DH: return "CKM_SSL3_MASTER_KEY_DERIVE_DH";
	case CKM_TLS_PRE_MASTER_KEY_GEN: return "CKM_TLS_PRE_MASTER_KEY_GEN";
	case CKM_TLS_MASTER_KEY_DERIVE: return "CKM_TLS_MASTER_KEY_DERIVE";
	case CKM_TLS_KEY_AND_MAC_DERIVE: return "CKM_TLS_KEY_AND_MAC_DERIVE";
	case CKM_TLS_MASTER_KEY_DERIVE_DH: return "CKM_TLS_MASTER_KEY_DERIVE_DH";
	case CKM_SSL3_MD5_MAC: return "CKM_SSL3_MD5_MAC";
	case CKM_SSL3_SHA1_MAC: return "CKM_SSL3_SHA1_MAC";
	case CKM_MD5_KEY_DERIVATION: return "CKM_MD5_KEY_DERIVATION";
	case CKM_MD2_KEY_DERIVATION: return "CKM_MD2_KEY_DERIVATION";
	case CKM_SHA1_KEY_DERIVATION: return "CKM_SHA1_KEY_DERIVATION";
	case CKM_SHA256_KEY_DERIVATION: return "CKM_SHA256_KEY_DERIVATION";
	case CKM_PBE_MD2_DES_CBC: return "CKM_PBE_MD2_DES_CBC";
	case CKM_PBE_MD5_DES_CBC: return "CKM_PBE_MD5_DES_CBC";
	case CKM_PBE_MD5_CAST_CBC: return "CKM_PBE_MD5_CAST_CBC";
	case CKM_PBE_MD5_CAST3_CBC: return "CKM_PBE_MD5_CAST3_CBC";
	case CKM_PBE_MD5_CAST5_CBC: return "CKM_PBE_MD5_CAST5_CBC";
	case CKM_PBE_SHA1_CAST5_CBC: return "CKM_PBE_SHA1_CAST5_CBC";
	case CKM_PBE_SHA1_RC4_128: return "CKM_PBE_SHA1_RC4_128";
	case CKM_PBE_SHA1_RC4_40: return "CKM_PBE_SHA1_RC4_40";
	case CKM_PBE_SHA1_DES3_EDE_CBC: return "CKM_PBE_SHA1_DES3_EDE_CBC";
	case CKM_PBE_SHA1_DES2_EDE_CBC: return "CKM_PBE_SHA1_DES2_EDE_CBC";
	case CKM_PBE_SHA1_RC2_128_CBC: return "CKM_PBE_SHA1_RC2_128_CBC";
	case CKM_PBE_SHA1_RC2_40_CBC: return "CKM_PBE_SHA1_RC2_40_CBC";
	case CKM_PKCS5_PBKD2: return "CKM_PKCS5_PBKD2";
	case CKM_PBA_SHA1_WITH_SHA1_HMAC: return "CKM_PBA_SHA1_WITH_SHA1_HMAC";
	case CKM_KEY_WRAP_LYNKS: return "CKM_KEY_WRAP_LYNKS";
	case CKM_KEY_WRAP_SET_OAEP: return "CKM_KEY_WRAP_SET_OAEP";
	case CKM_SKIPJACK_KEY_GEN: return "CKM_SKIPJACK_KEY_GEN";
	case CKM_SKIPJACK_ECB64: return "CKM_SKIPJACK_ECB64";
	case CKM_SKIPJACK_CBC64: return "CKM_SKIPJACK_CBC64";
	case CKM_SKIPJACK_OFB64: return "CKM_SKIPJACK_OFB64";
	case CKM_SKIPJACK_CFB64: return "CKM_SKIPJACK_CFB64";
	case CKM_SKIPJACK_CFB32: return "CKM_SKIPJACK_CFB32";
	case CKM_SKIPJACK_CFB16: return "CKM_SKIPJACK_CFB16";
	case CKM_SKIPJACK_CFB8: return "CKM_SKIPJACK_CFB8";
	case CKM_SKIPJACK_WRAP: return "CKM_SKIPJACK_WRAP";
	case CKM_SKIPJACK_PRIVATE_WRAP: return "CKM_SKIPJACK_PRIVATE_WRAP";
	case CKM_SKIPJACK_RELAYX: return "CKM_SKIPJACK_RELAYX";
	case CKM_KEA_KEY_PAIR_GEN: return "CKM_KEA_KEY_PAIR_GEN";
	case CKM_KEA_KEY_DERIVE: return "CKM_KEA_KEY_DERIVE";
	case CKM_FORTEZZA_TIMESTAMP: return "CKM_FORTEZZA_TIMESTAMP";
	case CKM_BATON_KEY_GEN: return "CKM_BATON_KEY_GEN";
	case CKM_BATON_ECB128: return "CKM_BATON_ECB128";
	case CKM_BATON_ECB96: return "CKM_BATON_ECB96";
	case CKM_BATON_CBC128: return "CKM_BATON_CBC128";
	case CKM_BATON_COUNTER: return "CKM_BATON_COUNTER";
	case CKM_BATON_SHUFFLE: return "CKM_BATON_SHUFFLE";
	case CKM_BATON_WRAP: return "CKM_BATON_WRAP";
	case CKM_EC_KEY_PAIR_GEN: return "CKM_EC_KEY_PAIR_GEN";
	case CKM_ECDSA: return "CKM_ECDSA";
	case CKM_ECDSA_SHA1: return "CKM_ECDSA_SHA1";
	case CKM_ECDSA_SHA224: return "CKM_ECDSA_SHA224";
	case CKM_ECDSA_SHA256: return "CKM_ECDSA_SHA256";
	case CKM_ECDSA_SHA384: return "CKM_ECDSA_SHA384";
	case CKM_ECDSA_SHA512: return "CKM_ECDSA_SHA512";
	case CKM_ECDH1_DERIVE: return "CKM_ECDH1_DERIVE";
	case CKM_ECDH1_COFACTOR_DERIVE: return "CKM_ECDH1_COFACTOR_DERIVE";
	case CKM_ECMQV_DERIVE: return "CKM_ECMQV_DERIVE";
	case CKM_JUNIPER_KEY_GEN: return "CKM_JUNIPER_KEY_GEN";
	case CKM_JUNIPER_ECB128: return "CKM_JUNIPER_ECB128";
	case CKM_JUNIPER_CBC128: return "CKM_JUNIPER_CBC128";
	case CKM_JUNIPER_COUNTER: return "CKM_JUNIPER_COUNTER";
	case CKM_JUNIPER_SHUFFLE: return "CKM_JUNIPER_SHUFFLE";
	case CKM_JUNIPER_WRAP: return "CKM_JUNIPER_WRAP";
	case CKM_FASTHASH: return "CKM_FASTHASH";
	case CKM_AES_KEY_GEN: return "CKM_AES_KEY_GEN";
	case CKM_AES_ECB: return "CKM_AES_ECB";
	case CKM_AES_CBC: return "CKM_AES_CBC";
	case CKM_AES_MAC: return "CKM_AES_MAC";
	case CKM_AES_MAC_GENERAL: return "CKM_AES_MAC_GENERAL";
	case CKM_AES_CBC_PAD: return "CKM_AES_CBC_PAD";
	case CKM_AES_CTR: return "CKM_AES_CTR";
	case CKM_DSA_PARAMETER_GEN: return "CKM_DSA_PARAMETER_GEN";
	case CKM_DH_PKCS_PARAMETER_GEN: return "CKM_DH_PKCS_PARAMETER_GEN";
	case CKM_X9_42_DH_PARAMETER_GEN: return "CKM_X9_42_DH_PARAMETER_GEN";
	case CKM_VENDOR_DEFINED: return "CKM_VENDOR_DEFINED";
	case CKM_SHA256_RSA_PKCS_PSS : return "CKM_SHA256_RSA_PKCS_PSS";
	case CKM_SHA224_RSA_PKCS: return "CKM_SHA224_RSA_PKCS";
	case CKM_SHA224_RSA_PKCS_PSS: return "CKM_SHA224_RSA_PKCS_PSS";
	case CKM_SHA384_RSA_PKCS_PSS: return "CKM_SHA384_RSA_PKCS_PSS";
	case CKM_SHA512_RSA_PKCS_PSS: return "CKM_SHA512_RSA_PKCS_PSS";
	case CKM_SHA224: return "CKM_SHA224";
	case CKM_SHA224_KEY_DERIVATION: return "CKM_SHA224_KEY_DERIVATION";
	case CKM_SHA224_HMAC: return "CKM_SHA224_HMAC";
	case CKM_SHA384_KEY_DERIVATION: return "CKM_SHA384_KEY_DERIVATION";
	case CKM_SHA512_KEY_DERIVATION: return "CKM_SHA512_KEY_DERIVATION";
	case CKM_SHA512_224: return "CKM_SHA512_224";
	case CKM_SHA512_224_HMAC: return "CKM_SHA512_224_HMAC";
	case CKM_SHA512_224_HMAC_GENERAL: return "CKM_SHA512_224_HMAC_GENERAL";
	case CKM_SHA512_256: return "CKM_SHA512_256";
	case CKM_SHA512_256_HMAC: return "CKM_SHA512_256_HMAC";
	case CKM_SHA512_256_HMAC_GENERAL: return "CKM_SHA512_256_HMAC_GENERAL";
	case CKA_IBM_MACKEY: return "CKA_IBM_MACKEY";
	case CKM_IBM_ECDSA_SHA224: return "CKM_IBM_ECDSA_SHA224";
	case CKM_IBM_ECDSA_SHA256: return "CKM_IBM_ECDSA_SHA256";
	case CKM_IBM_ECDSA_SHA384: return "CKM_IBM_ECDSA_SHA384";
	case CKM_IBM_ECDSA_SHA512: return "CKM_IBM_ECDSA_SHA512";
	case CKM_IBM_EC_MULTIPLY: return "CKM_IBM_EC_MULTIPLY";
	case CKM_IBM_EAC: return "CKM_IBM_EAC";
	case CKM_IBM_SHA512_256: return "CKM_IBM_SHA512_256";
	case CKM_IBM_SHA512_224: return "CKM_IBM_SHA512_224";
	case CKM_IBM_SHA512_256_HMAC: return "CKM_IBM_SHA512_256_HMAC";
	case CKM_IBM_SHA512_224_HMAC: return "CKM_IBM_SHA512_224_HMAC";
	case CKM_IBM_SHA512_256_KEY_DERIVATION: return "CKM_IBM_SHA512_256_KEY_DERIVATION";
	case CKM_IBM_SHA512_224_KEY_DERIVATION: return "CKM_IBM_SHA512_224_KEY_DERIVATION";
	case CKM_IBM_ATTRIBUTEBOUND_WRAP: return "CKM_IBM_ATTRIBUTEBOUND_WRAP";
	case CKM_IBM_TRANSPORTKEY: return "CKM_IBM_TRANSPORTKEY";
	case CKM_IBM_DH_PKCS_DERIVE_RAW: return "CKM_IBM_DH_PKCS_DERIVE_RAW";
	case CKM_IBM_ECDH1_DERIVE_RAW: return "CKM_IBM_ECDH1_DERIVE_RAW";
	case CKM_IBM_RETAINKEY: return "CKM_IBM_RETAINKEY";
	default:
		TRACE_WARNING("%s unknown mechanism 0x%lx\n", __func__, mechanism);
		return "UNKNOWN";
	}
}

static CK_RV h_opaque_2_blob(STDLL_TokData_t *tokdata, CK_OBJECT_HANDLE handle,
			     CK_BYTE **blob, size_t *blob_len, OBJECT **kobj);

#define EP11_DEFAULT_CFG_FILE "ep11tok.conf"
#define EP11_CFG_FILE_SIZE 4096

/* error rc for reading the adapter config file */
static const int APQN_FILE_INV_0 = 1;
static const int APQN_FILE_INV_1 = 2;
static const int APQN_FILE_INV_2 = 3;
static const int APQN_FILE_INV_3 = 4;
static const int APQN_FILE_INV_FILE_SIZE = 5;
static const int APQN_FILE_FILE_ACCESS    = 6;
static const int APQN_FILE_SYNTAX_ERROR_0 = 7;
static const int APQN_FILE_SYNTAX_ERROR_1 = 8;
static const int APQN_FILE_SYNTAX_ERROR_2 = 9;
static const int APQN_FILE_SYNTAX_ERROR_3 = 10;
static const int APQN_FILE_SYNTAX_ERROR_4 = 11;
static const int APQN_FILE_SYNTAX_ERROR_5 = 12;
static const int APQN_FILE_NO_APQN_GIVEN = 13;
static const int APQN_FILE_NO_APQN_MODE = 14;
static const int APQN_FILE_UNEXPECTED_END_OF_FILE = 15;

static int read_adapter_config_file(STDLL_TokData_t *tokdata, const char* conf_name);

/* import a DES/AES key, that is, make a blob for a DES/AES key
 * that was not created by EP11 hardware, encrypt the key by the wrap key,
 * unwrap it by the wrap key
 */
static CK_RV rawkey_2_blob(STDLL_TokData_t  * tokdata, unsigned char *key,
			   CK_ULONG ksize, CK_KEY_TYPE ktype,
			   unsigned char *blob, size_t *blen, OBJECT *key_obj)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	char   cipher[MAX_BLOBSIZE];
	CK_ULONG clen = sizeof(cipher);
	CK_BYTE csum[MAX_CSUMSIZE];
	size_t cslen = sizeof(csum);
	CK_BYTE iv[AES_BLOCK_SIZE];
	CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
	DL_NODE *node = key_obj->template->attribute_list;
	CK_RV rc;
	CK_ATTRIBUTE_PTR p_attrs = NULL;
	CK_ULONG attrs_len = 0;
	CK_ATTRIBUTE_PTR new_p_attrs = NULL;
	CK_ULONG new_attrs_len = 0;

	/* tell ep11 the attributes the user specified */
	node = key_obj->template->attribute_list;
	while (node != NULL) {
		CK_ATTRIBUTE_PTR a = node->data;

		/* ep11 handles this as 'read only' and reports
		 * an error if specified
		 */
		if (CKA_NEVER_EXTRACTABLE == a->type || CKA_MODIFIABLE == a->type
		    || CKA_LOCAL == a->type)
			;
		else {
			rc = add_to_attribute_array(&p_attrs, &attrs_len,
						    a->type, a->pValue,
						    a->ulValueLen);
			if (rc != CKR_OK) {
				TRACE_ERROR("%s adding attribute failed type=0x%lx rc=0x%lx\n",
					    __func__, a->type, rc);
				goto rawkey_2_blob_end;
			}
		}

		node = node->next;
	}

	memset(cipher, 0, sizeof(cipher));
	memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

	/*
	 * calls the ep11 lib (which in turns sends the request to the card),
	 * all m_ function are ep11 functions
	 */
	rc = dll_m_EncryptSingle(ep11_data->raw2key_wrap_blob, ep11_data->raw2key_wrap_blob_l, &mech,
			     key, ksize, cipher, &clen, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s encrypt ksize=0x%lx clen=0x%lx rc=0x%lx\n",
			    __func__, ksize, clen, rc);
		goto rawkey_2_blob_end;
	}
	TRACE_INFO("%s encrypt ksize=0x%lx clen=0x%lx rc=0x%lx\n",
		   __func__, ksize, clen, rc);

	rc = check_key_attributes(ktype, CKO_SECRET_KEY, p_attrs, attrs_len,
				  &new_p_attrs, &new_attrs_len);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s RSA/EC check private key attributes failed with rc=0x%lx\n",
			    __func__, rc);
		return rc;
	}

	/* the encrypted key is decrypted and a blob is build,
	 * card accepts only blobs as keys
	 */
	rc = dll_m_UnwrapKey(cipher, clen, ep11_data->raw2key_wrap_blob, ep11_data->raw2key_wrap_blob_l,
			 NULL, ~0, ep11_data->ep11_pin_blob, ep11_data->ep11_pin_blob_len, &mech,
			 new_p_attrs, new_attrs_len, blob, blen, csum, &cslen,
			 (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s unwrap blen=%zd rc=0x%lx\n", __func__, *blen, rc);
	} else {
		TRACE_INFO("%s unwrap blen=%zd rc=0x%lx\n", __func__, *blen, rc);
	}

rawkey_2_blob_end:
	if (p_attrs != NULL)
		free_attribute_array(p_attrs, attrs_len);
	if (new_p_attrs)
		free_attribute_array(new_p_attrs, new_attrs_len);
	return rc;
}

/* random number generator */
CK_RV token_specific_rng(STDLL_TokData_t *tokdata, CK_BYTE *output, CK_ULONG bytes)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

	CK_RV rc = dll_m_GenerateRandom(output, bytes,
					(uint64_t)ep11_data->target_list);
	if (rc != CKR_OK)
		TRACE_ERROR("%s output=%p bytes=%lu rc=0x%lx\n",
			    __func__, output, bytes, rc);
	return rc;
}

/*
 * for importing keys we need to encrypt the keys and build the blob by
 * m_UnwrapKey, use one wrap key for this purpose, can be any key,
 * we use an AES key
 */
static CK_RV make_wrapblob(STDLL_TokData_t *tokdata, CK_ATTRIBUTE *tmpl_in,
			   CK_ULONG tmpl_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_MECHANISM mech = {CKM_AES_KEY_GEN, NULL_PTR, 0};
	unsigned char csum[MAX_CSUMSIZE];
	size_t csum_l = sizeof(csum);
	CK_RV rc;

	if (ep11_data->raw2key_wrap_blob_l != 0) {
		TRACE_INFO("%s blob already exists raw2key_wrap_blob_l=0x%zx\n",
			   __func__, ep11_data->raw2key_wrap_blob_l);
		return CKR_OK;
	}

	ep11_data->raw2key_wrap_blob_l = sizeof(ep11_data->raw2key_wrap_blob);
	rc = dll_m_GenerateKey(&mech, tmpl_in, tmpl_len, NULL, 0, ep11_data->raw2key_wrap_blob,
			       &ep11_data->raw2key_wrap_blob_l, csum, &csum_l,
			       (uint64_t)ep11_data->target_list);


	if (rc != CKR_OK) {
		TRACE_ERROR("%s end raw2key_wrap_blob_l=0x%zx rc=0x%lx\n",
			    __func__, ep11_data->raw2key_wrap_blob_l, rc);
	} else {
		TRACE_INFO("%s end raw2key_wrap_blob_l=0x%zx rc=0x%lx\n",
			   __func__, ep11_data->raw2key_wrap_blob_l, rc);
	}

	return rc;
}

CK_RV ep11_resolve_lib_sym(void *hdl) {
	char *error = NULL;

	dlerror(); /* Clear existing error */

	dll_m_GenerateRandom	= (m_GenerateRandom_t)dlsym(hdl, "m_GenerateRandom");
	dll_m_SeedRandom	= (m_SeedRandom_t)dlsym(hdl, "m_SeedRandom");

	dll_m_Digest		= (m_Digest_t)dlsym(hdl, "m_Digest");
	dll_m_DigestInit	= (m_DigestInit_t)dlsym(hdl, "m_DigestInit");
	dll_m_DigestUpdate	= (m_DigestUpdate_t)dlsym(hdl, "m_DigestUpdate");
	dll_m_DigestFinal	= (m_DigestFinal_t)dlsym(hdl, "m_DigestFinal");
	dll_m_DigestKey		= (m_DigestKey_t)dlsym(hdl, "m_DigestKey");
	dll_m_DigestSingle	= (m_DigestSingle_t)dlsym(hdl, "m_DigestSingle");

	dll_m_Encrypt		= (m_Encrypt_t)dlsym(hdl, "m_Encrypt");
	dll_m_EncryptInit	= (m_EncryptInit_t)dlsym(hdl, "m_EncryptInit");
	dll_m_EncryptUpdate	= (m_EncryptUpdate_t)dlsym(hdl, "m_EncryptUpdate");
	dll_m_EncryptFinal	= (m_EncryptFinal_t)dlsym(hdl, "m_EncryptFinal");
	dll_m_EncryptSingle	= (m_EncryptSingle_t)dlsym(hdl, "m_EncryptSingle");

	dll_m_Decrypt		= (m_Decrypt_t)dlsym(hdl, "m_Decrypt");
	dll_m_DecryptInit	= (m_DecryptInit_t)dlsym(hdl, "m_DecryptInit");
	dll_m_DecryptUpdate	= (m_DecryptUpdate_t)dlsym(hdl, "m_DecryptUpdate");
	dll_m_DecryptFinal	= (m_DecryptFinal_t)dlsym(hdl, "m_DecryptFinal");
	dll_m_DecryptSingle	= (m_DecryptSingle_t)dlsym(hdl, "m_DecryptSingle");

	dll_m_ReencryptSingle	= (m_ReencryptSingle_t)dlsym(hdl, "m_ReencryptSingle");
	dll_m_GenerateKey	= (m_GenerateKey_t)dlsym(hdl, "m_GenerateKey");
	dll_m_GenerateKeyPair	= (m_GenerateKeyPair_t)dlsym(hdl, "m_GenerateKeyPair");

	dll_m_Sign		= (m_Sign_t)dlsym(hdl, "m_Sign");
	dll_m_SignInit		= (m_SignInit_t)dlsym(hdl, "m_SignInit");
	dll_m_SignUpdate	= (m_SignUpdate_t)dlsym(hdl, "m_SignUpdate");
	dll_m_SignFinal		= (m_SignFinal_t)dlsym(hdl, "m_SignFinal");
	dll_m_SignSingle	= (m_SignSingle_t)dlsym(hdl, "m_SignSingle");

	dll_m_Verify		= (m_Verify_t)dlsym(hdl, "m_Verify");
	dll_m_VerifyInit	= (m_VerifyInit_t)dlsym(hdl, "m_VerifyInit");
	dll_m_VerifyUpdate	= (m_VerifyUpdate_t)dlsym(hdl, "m_VerifyUpdate");
	dll_m_VerifyFinal	= (m_VerifyFinal_t)dlsym(hdl, "m_VerifyFinal");
	dll_m_VerifySingle	= (m_VerifySingle_t)dlsym(hdl, "m_VerifySingle");

	dll_m_WrapKey		= (m_WrapKey_t)dlsym(hdl, "m_WrapKey");
	dll_m_UnwrapKey		= (m_UnwrapKey_t)dlsym(hdl, "m_UnwrapKey");
	dll_m_DeriveKey		= (m_DeriveKey_t)dlsym(hdl, "m_DeriveKey");

	dll_m_GetMechanismList	= (m_GetMechanismList_t)dlsym(hdl, "m_GetMechanismList");
	dll_m_GetMechanismInfo	= (m_GetMechanismInfo_t)dlsym(hdl, "m_GetMechanismInfo");
	dll_m_GetAttributeValue	= (m_GetAttributeValue_t)dlsym(hdl, "m_GetAttributeValue");
	dll_m_SetAttributeValue	= (m_SetAttributeValue_t)dlsym(hdl, "m_SetAttributeValue");

	dll_m_Login		= (m_Login_t)dlsym(hdl, "m_Login");
	dll_m_Logout		= (m_Logout_t)dlsym(hdl, "m_Logout");
	dll_m_admin		= (m_admin_t)dlsym(hdl, "m_admin");

	dll_m_init		= (m_init_t)dlsym(hdl, "m_init");
	dll_m_add_backend	= (m_add_backend_t)dlsym(hdl, "m_add_backend");
	dll_m_shutdown		= (m_shutdown_t)dlsym(hdl, "m_shutdown");

	if ((error = dlerror()) != NULL)  {
		OCK_SYSLOG(LOG_ERR, "%s\n", error);
		return (EXIT_FAILURE);
	}
	else
		return CKR_OK;
}

CK_RV ep11tok_init(STDLL_TokData_t *tokdata, CK_SLOT_ID SlotNumber, char *conf_name)
{
	CK_RV rc;
	void *lib_ep11;
	CK_ULONG len = 16;
	CK_BBOOL cktrue = 1;
	CK_ATTRIBUTE wrap_tmpl[] = {{CKA_VALUE_LEN, &len, sizeof(CK_ULONG)},
				    {CKA_WRAP, (void*)&cktrue, sizeof(cktrue)},
				    {CKA_UNWRAP, (void*)&cktrue, sizeof(cktrue)},
				    {CKA_ENCRYPT, (void*)&cktrue, sizeof(cktrue)},
				    {CKA_DECRYPT, (void*)&cktrue, sizeof(cktrue)},
				    {CKA_EXTRACTABLE, (void*)&cktrue, sizeof(cktrue)},
				    {CKA_LABEL, (void*)wrap_key_name, sizeof(wrap_key_name)},
				    {CKA_TOKEN, (void*)&cktrue, sizeof(cktrue)}};
	ep11_private_data_t *ep11_data;

	TRACE_INFO("ep11 %s slot=%lu running\n", __func__, SlotNumber);

    ep11_data = calloc(1, sizeof(ep11_private_data_t));
    if (ep11_data == NULL)
        return CKR_HOST_MEMORY;
    ep11_data->target_list = calloc(1, sizeof(ep11_target_t));
    if (ep11_data->target_list == NULL)
        return CKR_HOST_MEMORY;

    tokdata->private_data = ep11_data;

	/* read ep11 specific config file with user specified adapter/domain pairs, ... */
	rc = read_adapter_config_file(tokdata, conf_name);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s ep11 config file error rc=0x%lx\n", __func__, rc);
		return CKR_GENERAL_ERROR;
	}

	/* dynamically load in the ep11 shared library */
	lib_ep11 = dlopen(EP11SHAREDLIB, RTLD_GLOBAL | RTLD_NOW);
	if (!lib_ep11) {
		OCK_SYSLOG(LOG_ERR,
			   "%s: Error loading shared library '%s' [%s]\n",
			   __func__, EP11SHAREDLIB, dlerror());
		TRACE_ERROR("%s Error loading shared library '%s' [%s]\n",
			    __func__, EP11SHAREDLIB, dlerror());
		return CKR_FUNCTION_FAILED;
	}

	rc = ep11_resolve_lib_sym(lib_ep11);
	if (rc)
		exit(rc);

#ifndef XCP_STANDALONE
	/* call ep11 shared lib init */
	if (dll_m_init() < 0) {
		TRACE_ERROR("%s ep11 lib init failed\n", __func__);
		return CKR_DEVICE_ERROR;
	}
#endif

	/* create an AES key needed for importing keys
	 * (encrypt by wrap_key and m_UnwrapKey by wrap key)
	 */
	rc = make_wrapblob(tokdata, wrap_tmpl, 8);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s make_wrapblob failed rc=0x%lx\n", __func__, rc);
		if (rc == 0x80010009) {
			TRACE_ERROR("%s rc is CKR_IBM_WK_NOT_INITIALIZED, "
				    "no master key set ?\n", __func__);
			OCK_SYSLOG(LOG_ERR,
				   "%s: CKR_IBM_WK_NOT_INITIALIZED occured, no "
				   "master key set ?\n", __func__);
		}
		return CKR_GENERAL_ERROR;
	}

	TRACE_INFO("%s init done successfully\n", __func__);

	return CKR_OK;
}

CK_RV ep11tok_final(STDLL_TokData_t *tokdata)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

	TRACE_INFO("ep11 %s running\n", __func__);

    if (ep11_data != NULL) {
        if (ep11_data->target_list)
            free(ep11_data->target_list);
        free(ep11_data);
        tokdata->private_data = NULL;
    }

	return CKR_OK;
}


/*
 * makes blobs for private imported RSA keys and
 * SPKIs for public imported RSA keys.
 * Similar to rawkey_2_blob, but keys must follow a standard BER encoding.
 */
static CK_RV import_RSA_key(STDLL_TokData_t *tokdata, OBJECT *rsa_key_obj,
			    CK_BYTE *blob, size_t *blob_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE iv[AES_BLOCK_SIZE];
	CK_MECHANISM mech_w = {CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE};
	CK_BYTE cipher[MAX_BLOBSIZE];
	CK_ULONG cipher_l = sizeof(cipher);
	DL_NODE *node;
	CK_ATTRIBUTE_PTR p_attrs = NULL;
	CK_ULONG attrs_len = 0;
	CK_ATTRIBUTE_PTR new_p_attrs = NULL;
	CK_ULONG new_attrs_len = 0;
	char csum[MAX_BLOBSIZE];
	CK_ULONG cslen = sizeof(csum);
	CK_OBJECT_CLASS class;
	CK_BYTE *data = NULL;
	CK_ULONG data_len;

	memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

	/* need class for private/public key info */
	if (!template_attribute_find(rsa_key_obj->template, CKA_CLASS, &attr)) {
		TRACE_ERROR("%s no CKA_CLASS\n", __func__);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* m_Unwrap builds key blob in the card,
	 * tell ep11 the attributes the user specified for that key.
	 */
	node = rsa_key_obj->template->attribute_list;
	while (node != NULL) {
		CK_ATTRIBUTE_PTR a = node->data;

		/* ep11 handles this as 'read only' */
		if (CKA_NEVER_EXTRACTABLE == a->type ||
		    CKA_MODIFIABLE == a->type || CKA_LOCAL == a->type)
			;
		else {
			rc = add_to_attribute_array(&p_attrs, &attrs_len,
						    a->type, a->pValue,
						    a->ulValueLen);
			if (rc != CKR_OK) {
				TRACE_ERROR("%s adding attribute failed type=0x%lx rc=0x%lx\n",
					    __func__, a->type, rc);
				goto import_RSA_key_end;
			}
		}

		node = node->next;
	}

	class = *(CK_OBJECT_CLASS *)attr->pValue;

	if (class != CKO_PRIVATE_KEY) {

		/* an imported public RSA key, we need a SPKI for it. */

		CK_ATTRIBUTE *modulus;
		CK_ATTRIBUTE *publ_exp;

		if (!template_attribute_find(rsa_key_obj->template,
					     CKA_MODULUS, &modulus)) {
			rc = CKR_TEMPLATE_INCOMPLETE;
			goto import_RSA_key_end;
		}
		if (!template_attribute_find(rsa_key_obj->template,
					     CKA_PUBLIC_EXPONENT, &publ_exp)) {
			rc = CKR_TEMPLATE_INCOMPLETE;
			goto import_RSA_key_end;
		}

		/* our contribution to asn1.c,
		 * builds the BER encoding that is a SPKI.
		 */
		rc = ber_encode_RSAPublicKey(0, &data, &data_len,
					     modulus, publ_exp);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s public key import class=0x%lx rc=0x%lx "
				    "data_len=0x%lx\n", __func__, class, rc,
				    data_len);
			goto import_RSA_key_end;
		} else {
			TRACE_INFO("%s public key import class=0x%lx rc=0x%lx "
				   "data_len=0x%lx\n", __func__, class, rc,
				   data_len);
		}

		/* save the SPKI as blob although it is not a blob.
		 * The card expects SPKIs as public keys.
		 */
		memcpy(blob, data, data_len);
		*blob_size = data_len;

	} else {

		/* imported private RSA key goes here */

		/* extract the secret data to be wrapped
		 * since this is AES_CBC_PAD, padding is done in mechanism.
		 */
		rc = rsa_priv_wrap_get_data(rsa_key_obj->template, FALSE,
					    &data, &data_len);
		if (rc != CKR_OK) {
			TRACE_DEVEL("%s RSA wrap get data failed\n", __func__);
			goto import_RSA_key_end;
		}

		/* encrypt */
		rc = dll_m_EncryptSingle(ep11_data->raw2key_wrap_blob, ep11_data->raw2key_wrap_blob_l, &mech_w,
					 data, data_len, cipher, &cipher_l,
					 (uint64_t)ep11_data->target_list);

		TRACE_INFO("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
			   __func__, rc, cipher_l);

		if (rc != CKR_OK) {
			TRACE_ERROR("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
				    __func__, rc, cipher_l);
			goto import_RSA_key_end;
		}

		rc = check_key_attributes(CKK_RSA, CKO_PRIVATE_KEY, p_attrs, attrs_len,
					  &new_p_attrs, &new_attrs_len);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s RSA/EC check private key attributes failed with rc=0x%lx\n",
				    __func__, rc);
			return rc;
		}

		/* calls the card, it decrypts the private RSA key,
		 * reads its BER format and builds a blob.
		 */
		rc = dll_m_UnwrapKey(cipher, cipher_l, ep11_data->raw2key_wrap_blob, ep11_data->raw2key_wrap_blob_l,
				 NULL, ~0, ep11_data->ep11_pin_blob, ep11_data->ep11_pin_blob_len, &mech_w,
				 new_p_attrs, new_attrs_len, blob, blob_size, csum, &cslen,
				 (uint64_t)ep11_data->target_list);

		if (rc != CKR_OK) {
			TRACE_ERROR("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
				    __func__, rc, *blob_size);
		} else {
			TRACE_INFO("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
				   __func__, rc, *blob_size);
		}
	}

import_RSA_key_end:
	if (data)
		free(data);
	if (p_attrs != NULL)
		free_attribute_array(p_attrs, attrs_len);
	if (new_p_attrs)
		free_attribute_array(new_p_attrs, new_attrs_len);
	return rc;
}

CK_RV
token_specific_object_add(STDLL_TokData_t *tokdata, OBJECT *obj)
{
	CK_KEY_TYPE keytype;
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE blob[MAX_BLOBSIZE];
	size_t blobsize = sizeof(blob);
	CK_RV rc;

	/* get key type */
	if (template_attribute_find(obj->template, CKA_KEY_TYPE, &attr) == FALSE) {
		/* not a key, so nothing to do. Just return. */
		return CKR_OK;
	}

	keytype = *(CK_KEY_TYPE *)attr->pValue;

	memset(blob, 0, sizeof(blob));

	/* only these keys can be imported */
	switch(keytype) {
	case CKK_RSA:
		rc = import_RSA_key(tokdata, obj, blob, &blobsize);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s import RSA key rc=0x%lx blobsize=0x%zx\n",
				    __func__, rc, blobsize);
			return CKR_FUNCTION_FAILED;
		}
		TRACE_INFO("%s import RSA key rc=0x%lx blobsize=0x%zx\n",
			   __func__, rc, blobsize);
		break;

	case CKK_DES2:
	case CKK_DES3:
	case CKK_AES:
	case CKK_GENERIC_SECRET:
		/* get key value */
		if (template_attribute_find(obj->template, CKA_VALUE, &attr) == FALSE) {
			TRACE_ERROR("%s token_specific_object_add incomplete template\n",
				    __func__);
			return CKR_TEMPLATE_INCOMPLETE;
		}
		/* attr holds key value specified by user,
		 * import that key (make a blob)
		 */
		rc = rawkey_2_blob(tokdata, attr->pValue, attr->ulValueLen, keytype,
				   blob, &blobsize, obj);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s rawkey_2_blob rc=0x%lx "
				    "blobsize=0x%zx\n", __func__, rc, blobsize);
			return CKR_FUNCTION_FAILED;
		}

		/* clear value attribute */
		memset(attr->pValue, 0, attr->ulValueLen);

		TRACE_INFO("%s rawkey_2_blob rc=0x%lx blobsize=0x%zx\n",
			   __func__, rc, blobsize);

		break;
	default:
		return CKR_KEY_FUNCTION_NOT_PERMITTED;
	}

	/* store the blob in the key obj */
	rc = build_attribute(CKA_IBM_OPAQUE, blob, blobsize, &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		return rc;
	}

	rc = template_update_attribute(obj->template, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		return rc;
	}

	return CKR_OK;
}


CK_RV ep11tok_generate_key(STDLL_TokData_t *tokdata, SESSION *session,
			   CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs,
			   CK_ULONG attrs_len, CK_OBJECT_HANDLE_PTR handle)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_BYTE blob[MAX_BLOBSIZE];
	size_t blobsize = sizeof(blob);
	CK_BYTE csum[MAX_CSUMSIZE];
	size_t csum_len = sizeof(csum);
	CK_ATTRIBUTE *attr = NULL;
	OBJECT *key_obj = NULL;
	CK_ULONG ktype;
	CK_ULONG class;
	CK_ATTRIBUTE_PTR new_attrs = NULL;
	CK_ULONG new_attrs_len = 0;
	CK_RV rc;

	memset(blob, 0, sizeof(blob));
	memset(csum, 0, sizeof(csum));

	/* Get the keytype to use when creating the key object */
	rc = ep11_get_keytype(attrs, attrs_len, mech, &ktype, &class);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s get_subclass failed with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}

	rc = check_key_attributes(ktype, CKO_SECRET_KEY, attrs, attrs_len,
				  &new_attrs, &new_attrs_len);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s check secret key attributes failed: rc=0x%lx\n",
			    __func__, rc);
		return rc;
	}

	rc = dll_m_GenerateKey(mech, new_attrs, new_attrs_len, ep11_data->ep11_pin_blob,
			   ep11_data->ep11_pin_blob_len, blob, &blobsize,
			   csum, &csum_len, (uint64_t)ep11_data->target_list);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s m_GenerateKey rc=0x%lx mech='%s' attrs_len=0x%lx\n",
			    __func__, rc, ep11_get_ckm(mech->mechanism), attrs_len);
		return rc;
	}

	TRACE_INFO("%s m_GenerateKey rc=0x%lx mech='%s' attrs_len=0x%lx\n",
		   __func__, rc, ep11_get_ckm(mech->mechanism), attrs_len);

	/* Start creating the key object */
	rc = object_mgr_create_skel(tokdata, session, new_attrs, new_attrs_len,
				    MODE_KEYGEN, CKO_SECRET_KEY, ktype,
				    &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s object_mgr_create_skel failed with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}

	rc = build_attribute(CKA_IBM_OPAQUE, blob, blobsize, &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}

	rc = template_update_attribute(key_obj->template, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}

	/* key should be fully constructed.
	 * Assign an object handle and store key
	 */
	rc = object_mgr_create_final(tokdata, session, key_obj, handle);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s object_mgr_create_final with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}

	goto done;
error:
	if (key_obj)
		object_free(key_obj);
	*handle = 0;
done:
	if (new_attrs)
		free_attribute_array(new_attrs, new_attrs_len);
	return rc;
}

CK_RV token_specific_sha_init(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *c,
			      CK_MECHANISM *mech)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	size_t state_len = MAX_DIGEST_STATE_BYTES;
	CK_BYTE *state;

	state = malloc(state_len); /* freed by dig_mgr.c */
	if (!state) {
		TRACE_ERROR("%s Memory allocation failed\n", __func__);
		return CKR_HOST_MEMORY;
	}

	rc = dll_m_DigestInit (state, &state_len, mech,
			       (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
		free(state);
	} else {
		/* DIGEST_CONTEXT will show up with following
		 *  requests (sha_update), 'state' is build by the card
		 * and holds all to continue, even by another adapter
		 */
		c->mech.ulParameterLen = mech->ulParameterLen;
		c->mech.mechanism = mech->mechanism;
		c->mech.pParameter = NULL;
		c->context = state;
		c->context_len = state_len;

		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV token_specific_sha(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *c,
			 CK_BYTE *in_data,
			 CK_ULONG in_data_len, CK_BYTE *out_data,
			 CK_ULONG *out_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;

	rc = dll_m_Digest(c->context, c->context_len, in_data, in_data_len,
		      out_data, out_data_len, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}
	return rc;
}


CK_RV token_specific_sha_update(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *c,
				CK_BYTE *in_data, CK_ULONG in_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;

	rc = dll_m_DigestUpdate(c->context, c->context_len, in_data, in_data_len,
				(uint64_t)ep11_data->target_list) ;

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}
	return rc;
}


CK_RV token_specific_sha_final(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *c,
			       CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;

	rc = dll_m_DigestFinal(c->context, c->context_len, out_data, out_data_len,
			       (uint64_t)ep11_data->target_list) ;

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}

CK_RV ep11tok_derive_key(STDLL_TokData_t *tokdata, SESSION *session, CK_MECHANISM_PTR mech,
			 CK_OBJECT_HANDLE hBaseKey, CK_OBJECT_HANDLE_PTR handle,
			 CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	CK_BYTE *keyblob;
	size_t keyblobsize;
	CK_BYTE newblob[MAX_BLOBSIZE];
	size_t newblobsize = sizeof(newblob);
	char csum[MAX_BLOBSIZE];
	CK_ULONG cslen = sizeof(csum);
	CK_ATTRIBUTE *opaque_attr = NULL;
	OBJECT *key_obj = NULL;
	CK_ULONG ktype;
	CK_ULONG class;
	CK_ATTRIBUTE_PTR new_attrs = NULL;
	CK_ULONG new_attrs_len = 0;

	memset(newblob, 0, sizeof(newblob));

	rc = h_opaque_2_blob(tokdata, hBaseKey, &keyblob, &keyblobsize, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s failedL hBaseKey=0x%lx\n", __func__, hBaseKey);
		return rc;
	}

	/* Get the keytype to use when creating the key object */
	rc = ep11_get_keytype(attrs, attrs_len, mech, &ktype, &class);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s get_subclass failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	rc = check_key_attributes(ktype, class, attrs, attrs_len,
				  &new_attrs, &new_attrs_len);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s Check key attributes for derived key failed with rc=0x%lx\n",
			    __func__, rc);
		return rc;
	}

	rc = dll_m_DeriveKey (mech, new_attrs, new_attrs_len, keyblob, keyblobsize, NULL,
			  0, ep11_data->ep11_pin_blob, ep11_data->ep11_pin_blob_len, newblob, &newblobsize,
			  csum, &cslen, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s hBaseKey=0x%lx rc=0x%lx handle=0x%lx blobsize=0x%zx\n",
			    __func__, hBaseKey, rc, *handle, newblobsize);
		return rc;
	}
	TRACE_INFO("%s hBaseKey=0x%lx rc=0x%lx handle=0x%lx blobsize=0x%zx\n",
		   __func__, hBaseKey, rc, *handle, newblobsize);

	/* Start creating the key object */
	rc = object_mgr_create_skel(tokdata, session, new_attrs, new_attrs_len,
				    MODE_DERIVE, class, ktype, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s object_mgr_create_skel failed with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}

	rc = build_attribute(CKA_IBM_OPAQUE, newblob, newblobsize, &opaque_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	rc = template_update_attribute(key_obj->template, opaque_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}

	/* key should be fully constructed.
	 * Assign an object handle and store key
	 */
	rc = object_mgr_create_final(tokdata, session, key_obj, handle);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s object_mgr_create_final with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	return rc;

error:
	if (key_obj)
		object_free(key_obj);
	*handle = 0;
	if (new_attrs)
		free_attribute_array(new_attrs, new_attrs_len);
	return rc;
}


#define  CKA_IBM_STRUCT_PARAMS  (CKA_VENDOR_DEFINED +0x10009)

static CK_RV dh_generate_keypair(STDLL_TokData_t *tokdata,
				 CK_MECHANISM_PTR pMechanism,
				 TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl,
				 CK_ATTRIBUTE_PTR pPublicKeyTemplate,
				 CK_ULONG ulPublicKeyAttributeCount,
				 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
				 CK_ULONG ulPrivateKeyAttributeCount,
				 CK_SESSION_HANDLE h)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV  rc;
	CK_BYTE publblob[MAX_BLOBSIZE];
	size_t publblobsize = sizeof(publblob);
	CK_BYTE privblob[MAX_BLOBSIZE];
	size_t privblobsize = sizeof(privblob);
	CK_ATTRIBUTE *prime_attr = NULL;
	CK_ATTRIBUTE *base_attr = NULL;
	CK_ATTRIBUTE *opaque_attr = NULL;
	CK_ATTRIBUTE *value_attr = NULL;
	CK_ATTRIBUTE *attr = NULL;
	CK_ATTRIBUTE  *pPublicKeyTemplate_new = NULL;
	size_t p_len=0, g_len=0;
	int i, new_public_attr;
	CK_ULONG data_len;
	CK_ULONG field_len;
	CK_BYTE  *data;
	CK_BYTE  *y_start;
	CK_ULONG bit_str_len;

	/* ep11 accepts CKA_PRIME and CKA_BASE parameters/attributes
	 * only in this format
	 */
	struct {
		size_t pg_bytes; /* total size: 2*bytecount(P) */
		unsigned char *pg;
	} dh_pgs;
	memset(&dh_pgs, 0, sizeof(dh_pgs));
	memset(publblob, 0, sizeof(publblob));
	memset(privblob, 0, sizeof(privblob));

	/* card does not want CKA_PRIME/CKA_BASE in template but in dh_pgs */
	pPublicKeyTemplate_new = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) * ulPublicKeyAttributeCount);
	if (!pPublicKeyTemplate_new) {
		TRACE_ERROR("%s Memory allocation failed\n", __func__);
		return CKR_HOST_MEMORY;
	}
	memset(pPublicKeyTemplate_new, 0, sizeof(CK_ATTRIBUTE) * ulPublicKeyAttributeCount);

	for (i = 0, new_public_attr = 0; i < ulPublicKeyAttributeCount; i++) {
		/* filter out CKA_PRIME/CKA_BASE,
		 * but remember where they can  be found
		 */
		switch(pPublicKeyTemplate[i].type) {
		case CKA_PRIME:
			prime_attr = &(pPublicKeyTemplate[i]);
			p_len = pPublicKeyTemplate[i].ulValueLen;
			break;
		case CKA_BASE:
			base_attr = &(pPublicKeyTemplate[i]);
			g_len = pPublicKeyTemplate[i].ulValueLen;
			break;
		default:
			/* copy all other attributes */
			memcpy(&pPublicKeyTemplate_new[new_public_attr],
			       &(pPublicKeyTemplate[i]), sizeof(CK_ATTRIBUTE));
			new_public_attr++;
		}
	}

	if (prime_attr == NULL || base_attr == NULL) {
		TRACE_ERROR("%s Incomplete template prime_attr=%p base_attr=%p\n",
			    __func__, prime_attr, base_attr);
		rc = CKR_TEMPLATE_INCOMPLETE;
		goto dh_generate_keypair_end;
	}

	/* copy CKA_PRIME/CKA_BASE to private template */
	rc = build_attribute(CKA_PRIME, prime_attr->pValue,
			     prime_attr->ulValueLen, &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dh_generate_keypair_end;
	}
	rc = template_update_attribute(priv_tmpl, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto dh_generate_keypair_end;
	}
	rc = build_attribute(CKA_BASE, base_attr->pValue,
			     base_attr->ulValueLen, &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dh_generate_keypair_end;
	}
	rc = template_update_attribute(priv_tmpl, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto dh_generate_keypair_end;
	}

	/* copy CKA_PRIME/CKA_BASE values */
	dh_pgs.pg = malloc(p_len*2);
	if (!dh_pgs.pg) {
		TRACE_ERROR("%s Memory allocation failed\n", __func__);
		return CKR_HOST_MEMORY;
	}
	memset(dh_pgs.pg, 0, p_len*2);
	memcpy(dh_pgs.pg, prime_attr->pValue, p_len); /* copy CKA_PRIME value */
	/* copy CKA_BASE value, it must have leading zeros
	 * if it is shorter than CKA_PRIME
	 */
	memcpy(dh_pgs.pg + p_len + (p_len - g_len), base_attr->pValue, g_len);
	dh_pgs.pg_bytes = p_len * 2;

#ifdef DEBUG
	TRACE_DEBUG("%s P:\n", __func__);
	TRACE_DEBUG_DUMP(&dh_pgs.pg[0], p_len);
	TRACE_DEBUG("%s G:\n", __func__);
	TRACE_DEBUG_DUMP(&dh_pgs.pg[p_len], p_len);
#endif

	/* add special attribute, do not add it to ock's pPublicKeyTemplate */
	CK_ATTRIBUTE pgs[] = {{CKA_IBM_STRUCT_PARAMS, (CK_VOID_PTR) dh_pgs.pg,
			       dh_pgs.pg_bytes}};
	memcpy(&(pPublicKeyTemplate_new[new_public_attr]),
	       &(pgs[0]), sizeof(CK_ATTRIBUTE));

	rc = dll_m_GenerateKeyPair(pMechanism, pPublicKeyTemplate_new,
			       new_public_attr+1, pPrivateKeyTemplate,
			       ulPrivateKeyAttributeCount, ep11_data->ep11_pin_blob,
			       ep11_data->ep11_pin_blob_len, privblob, &privblobsize,
			       publblob, &publblobsize,
			       (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s m_GenerateKeyPair failed rc=0x%lx\n", __func__, rc);
		goto dh_generate_keypair_end;
	}

	TRACE_INFO("%s rc=0x%lx plen=%zd publblobsize=0x%zx privblobsize=0x%zx\n",
		   __func__, rc, p_len, publblobsize, privblobsize);

	/* store the blobs */
	rc = build_attribute(CKA_IBM_OPAQUE, publblob, publblobsize, &opaque_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dh_generate_keypair_end;
	}

	rc = template_update_attribute(publ_tmpl, opaque_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto dh_generate_keypair_end;
	}

	rc = build_attribute(CKA_IBM_OPAQUE, privblob, privblobsize, &opaque_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dh_generate_keypair_end;
	}

	rc = template_update_attribute(priv_tmpl, opaque_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto dh_generate_keypair_end;
	}

#ifdef DEBUG
	TRACE_DEBUG("%s DH SPKI\n", __func__ );
	TRACE_DEBUG_DUMP(publblob, publblobsize);
#endif

	/* CKA_VALUE of the public key must hold 'y' */
	rc = ep11_spki_key(publblob, &y_start, &bit_str_len);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s ber_decode SKPI failed rc=0x%lx\n", __func__, rc);
		rc = CKR_GENERAL_ERROR;
		goto dh_generate_keypair_end;
	}

	/* DHPublicKey ::= INTEGER -- public key, y = g^x mod p */
	rc = ber_decode_INTEGER(y_start, &data, &data_len, &field_len);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s ber_decode_INTEGER failed rc=0x%lx\n", __func__, rc);
		rc = CKR_GENERAL_ERROR;
		goto dh_generate_keypair_end;
	}

	TRACE_INFO("%s DH SPKI decode INTEGER rc=0x%lx y_start=0x%x"
		   " field_len=%lu data_len=%lu data=0x%hhx\n",
		   __func__, rc, y_start[1], field_len, data_len, data[0]);

	/* remove leading zero, a leading zero is needed
	 * (according to standard) if left most bit of first byte is 1,
	 * in order to indicate a positive number.
	 * ock, like many others, interpret 'y' always as positive number,
	 * a leading zero is not expected by ock.
	 */
	if (data[0] == 0) {
		data_len = data_len - 1;
		data = data + 1;
		TRACE_INFO("%s DH SPKI removed leading zero rc=0x%lx"
			   " y_start=0x%x field_len=%lu data_len=%lu data=0x%hhx\n",
			   __func__, rc, y_start[1], field_len, data_len, data[0]);
	}

	rc = build_attribute(CKA_VALUE, data, data_len, &value_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dh_generate_keypair_end;
	}

	rc = template_update_attribute(publ_tmpl, value_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
	}

dh_generate_keypair_end:
	free(pPublicKeyTemplate_new);
	if (dh_pgs.pg != NULL)
		free(dh_pgs.pg);
	return rc;
}

static CK_RV dsa_generate_keypair(STDLL_TokData_t *tokdata,
				  CK_MECHANISM_PTR pMechanism,
				  TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl,
				  CK_ATTRIBUTE_PTR pPublicKeyTemplate,
				  CK_ULONG ulPublicKeyAttributeCount,
				  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
				  CK_ULONG ulPrivateKeyAttributeCount,
				  CK_SESSION_HANDLE h)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV  rc;
	CK_BYTE publblob[MAX_BLOBSIZE];
	size_t publblobsize = sizeof(publblob);
	CK_BYTE privblob[MAX_BLOBSIZE];
	size_t privblobsize = sizeof(privblob);
	CK_ATTRIBUTE *prime_attr = NULL;
	CK_ATTRIBUTE *sub_prime_attr = NULL;
	CK_ATTRIBUTE *base_attr = NULL;
	CK_ATTRIBUTE *opaque_attr = NULL;
	CK_ATTRIBUTE *value_attr = NULL;
	CK_ATTRIBUTE *attr = NULL;
	size_t p_len=0, q_len=0, g_len=0;
	int i, new_public_attr;
	CK_ATTRIBUTE *pPublicKeyTemplate_new = NULL;
	CK_BYTE *key;
	CK_BYTE *data;
	CK_ULONG data_len, field_len, bit_str_len;
	CK_ATTRIBUTE_PTR dsa_pPublicKeyTemplate = NULL;
	CK_ULONG dsa_ulPublicKeyAttributeCount = 0;
	CK_ATTRIBUTE_PTR dsa_pPrivateKeyTemplate = NULL;
	CK_ULONG dsa_ulPrivateKeyAttributeCount = 0;

	/* ep11 accepts CKA_PRIME,CKA_SUBPRIME,CKA_BASE only in this format */
	struct {
		size_t pqg_bytes;   /* total size: 3*bytecount(P) */
		unsigned char *pqg;
	} dsa_pqgs;
	memset(&dsa_pqgs, 0, sizeof(dsa_pqgs));
	memset(publblob, 0, sizeof(publblob));
	memset(privblob, 0, sizeof(privblob));

	/* card does not want CKA_PRIME/CKA_BASE/CKA_SUBPRIME
	 * in template but in dsa_pqgs
	 */
	pPublicKeyTemplate_new = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) * ulPublicKeyAttributeCount);
	if (!pPublicKeyTemplate_new) {
		TRACE_ERROR("%s Memory allocation failed\n", __func__);
		return CKR_HOST_MEMORY;
	}
	memset(pPublicKeyTemplate_new, 0,
	       sizeof(CK_ATTRIBUTE) * ulPublicKeyAttributeCount);

	for (i = 0, new_public_attr = 0; i < ulPublicKeyAttributeCount; i++) {
		switch(pPublicKeyTemplate[i].type) {
		case CKA_PRIME:
			prime_attr = &(pPublicKeyTemplate[i]);
			p_len = pPublicKeyTemplate[i].ulValueLen;
			break;
		case CKA_SUBPRIME:
			sub_prime_attr = &(pPublicKeyTemplate[i]);
			q_len = pPublicKeyTemplate[i].ulValueLen;
			break;
		case CKA_BASE:
			base_attr = &(pPublicKeyTemplate[i]);
			g_len = pPublicKeyTemplate[i].ulValueLen;
			break;
		default:
			/* copy all other attributes */
			memcpy(&pPublicKeyTemplate_new[new_public_attr],
			       &(pPublicKeyTemplate[i]), sizeof(CK_ATTRIBUTE));
			new_public_attr++;
		}
	}

	if (prime_attr == NULL || sub_prime_attr == NULL || base_attr == NULL)
		return CKR_TEMPLATE_INCOMPLETE;

	/* copy CKA_PRIME/CKA_BASE/CKA_SUBPRIME to private template */
	rc = build_attribute(CKA_PRIME, prime_attr->pValue,
			     prime_attr->ulValueLen, &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	rc = template_update_attribute( priv_tmpl, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	rc = build_attribute(CKA_BASE, base_attr->pValue,
			     base_attr->ulValueLen, &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	rc = template_update_attribute(priv_tmpl, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	rc = build_attribute(CKA_PRIME, sub_prime_attr->pValue,
			     sub_prime_attr->ulValueLen, &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	rc = template_update_attribute(priv_tmpl, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	/* if CKA_SUBPRIME,CKA_BASE are smaller than CKA_PRIME
	 * then they are extented by leading zeros till they have
	 * the size of CKA_PRIME
	 */
	dsa_pqgs.pqg = malloc(p_len*3);
	if (!dsa_pqgs.pqg) {
		TRACE_ERROR("%s Memory allocation failed\n", __func__);
		return CKR_HOST_MEMORY;
	}
	memset(dsa_pqgs.pqg, 0, p_len*3);
	memcpy(dsa_pqgs.pqg, prime_attr->pValue, p_len);
	memcpy(dsa_pqgs.pqg + p_len + (p_len - q_len),
	       sub_prime_attr->pValue, q_len);
	memcpy(dsa_pqgs.pqg + 2*p_len + (p_len - g_len),
	       base_attr->pValue, g_len);
	dsa_pqgs.pqg_bytes = p_len * 3;

#ifdef DEBUG
	TRACE_DEBUG("%s P:\n", __func__);
	TRACE_DEBUG_DUMP(&dsa_pqgs.pqg[0], p_len);
	TRACE_DEBUG("%s Q:\n", __func__);
	TRACE_DEBUG_DUMP(&dsa_pqgs.pqg[p_len], p_len);
	TRACE_DEBUG("%s G:\n", __func__);
	TRACE_DEBUG_DUMP(&dsa_pqgs.pqg[2*p_len], p_len);
#endif

	CK_ATTRIBUTE pqgs[] = {{CKA_IBM_STRUCT_PARAMS,
				(CK_VOID_PTR)dsa_pqgs.pqg, dsa_pqgs.pqg_bytes}};

	/* add special attribute, do not add it to ock's pPublicKeyTemplate */
	memcpy(&(pPublicKeyTemplate_new[new_public_attr]),
	       &(pqgs[0]), sizeof(CK_ATTRIBUTE));

	rc = check_key_attributes(CKK_DSA, CKO_PUBLIC_KEY,
				  pPublicKeyTemplate_new, new_public_attr+1,
				  &dsa_pPublicKeyTemplate,
				  &dsa_ulPublicKeyAttributeCount);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s RSA/EC check public key attributes failed with rc=0x%lx\n",
			    __func__, rc);
		return rc;
	}

	rc = check_key_attributes(CKK_DSA, CKO_PRIVATE_KEY,
				  pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
				  &dsa_pPrivateKeyTemplate,
				  &dsa_ulPrivateKeyAttributeCount);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s RSA/EC check private key attributes failed with rc=0x%lx\n",
			    __func__, rc);
		return rc;
	}

	rc = dll_m_GenerateKeyPair(pMechanism, dsa_pPublicKeyTemplate,
			       dsa_ulPublicKeyAttributeCount,
			       dsa_pPrivateKeyTemplate,
			       dsa_ulPrivateKeyAttributeCount, ep11_data->ep11_pin_blob,
			       ep11_data->ep11_pin_blob_len, privblob, &privblobsize,
			       publblob, &publblobsize,
			       (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s m_GenerateKeyPair failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	TRACE_INFO("%s rc=0x%lx p_len=%zd publblobsize=0x%zx privblobsize=0x%zx npattr=0x%x\n",
		   __func__, rc, p_len, publblobsize, privblobsize, new_public_attr+1);

	rc = build_attribute(CKA_IBM_OPAQUE, publblob, publblobsize, &opaque_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	rc = template_update_attribute(publ_tmpl, opaque_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto dsa_generate_keypair_end;
	}

	rc = build_attribute(CKA_IBM_OPAQUE, privblob, privblobsize, &opaque_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	rc = template_update_attribute(priv_tmpl, opaque_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto dsa_generate_keypair_end;
	}

	/* set CKA_VALUE of the public key, first get key from SPKI */
	rc = ep11_spki_key(publblob, &key, &bit_str_len);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s reading DSA SPKI failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	/* key must be an integer */
	rc = ber_decode_INTEGER(key, &data, &data_len, &field_len);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s reading DSA public key failed with rc=0x%lx\n",
			    __func__, rc);
		goto dsa_generate_keypair_end;
	}

#ifdef DEBUG
	TRACE_DEBUG("%s dsa_generate_keypair public key:\n", __func__);
	TRACE_DEBUG_DUMP(data, data_len);
#endif

	rc = build_attribute(CKA_VALUE, data, data_len, &value_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto dsa_generate_keypair_end;
	}

	rc = template_update_attribute(publ_tmpl, value_attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
	}

dsa_generate_keypair_end:
	free(pPublicKeyTemplate_new);
	if(dsa_pqgs.pqg != NULL)
		free(dsa_pqgs.pqg);
	if (dsa_pPublicKeyTemplate)
		free_attribute_array(dsa_pPublicKeyTemplate,
				     dsa_ulPublicKeyAttributeCount);
	if (dsa_pPrivateKeyTemplate)
		free_attribute_array(dsa_pPrivateKeyTemplate,
				     dsa_ulPrivateKeyAttributeCount);
	return rc;
}

static CK_RV rsa_ec_generate_keypair(STDLL_TokData_t *tokdata,
				     CK_MECHANISM_PTR pMechanism,
				     TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl,
				     CK_ATTRIBUTE_PTR pPublicKeyTemplate,
				     CK_ULONG ulPublicKeyAttributeCount,
				     CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
				     CK_ULONG ulPrivateKeyAttributeCount,
				     CK_SESSION_HANDLE h)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	CK_ATTRIBUTE *attr = NULL;
	CK_ATTRIBUTE *n_attr = NULL;
	CK_BYTE privkey_blob[MAX_BLOBSIZE];
	size_t privkey_blob_len = sizeof(privkey_blob);
	unsigned char spki[MAX_BLOBSIZE];
	size_t spki_len = sizeof(spki);
	CK_BYTE publblob[MAX_BLOBSIZE];
	size_t publblobsize = sizeof(publblob);
	CK_BYTE privblob[MAX_BLOBSIZE];
	size_t privblobsize = sizeof(privblob);
	int i;
	CK_ULONG bit_str_len;
	CK_BYTE *key;
	CK_BYTE *data;
	CK_ULONG data_len;
	CK_ULONG field_len;
	CK_ATTRIBUTE_PTR new_pPublicKeyTemplate = NULL;
	CK_ULONG new_ulPublicKeyAttributeCount = 0;
	CK_ATTRIBUTE_PTR new_pPrivateKeyTemplate = NULL;
	CK_ULONG new_ulPrivateKeyAttributeCount = 0;
	CK_ULONG ktype;

	if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN)
		ktype = CKK_EC;
	else if ((pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) ||
		 (pMechanism->mechanism == CKM_RSA_X9_31_KEY_PAIR_GEN))
		ktype = CKK_RSA;
	else {
		TRACE_ERROR("%s Neither RSA nor EC mech type provided for RSA/EC_key_pair_gen\n",
			    __func__);
		return CKR_MECHANISM_INVALID;
	}

	rc = check_key_attributes(ktype, CKO_PUBLIC_KEY,
				  pPublicKeyTemplate, ulPublicKeyAttributeCount,
				  &new_pPublicKeyTemplate,
				  &new_ulPublicKeyAttributeCount);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s RSA/EC check public key attributes failed with rc=0x%lx\n",
			    __func__, rc);
		return rc;
	}

	rc = check_key_attributes(ktype, CKO_PRIVATE_KEY, pPrivateKeyTemplate,
				  ulPrivateKeyAttributeCount,
				  &new_pPrivateKeyTemplate,
				  &new_ulPrivateKeyAttributeCount);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s RSA/EC check private key attributes failed with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}

	/* debug */
	for (i = 0; i < new_ulPrivateKeyAttributeCount; i++) {
		TRACE_INFO("%s gen priv attr type=0x%lx valuelen=0x%lx attrcnt=0x%lx\n",
			   __func__, new_pPrivateKeyTemplate[i].type,
			   new_pPrivateKeyTemplate[i].ulValueLen,
			   new_ulPrivateKeyAttributeCount);
	}

	rc = dll_m_GenerateKeyPair(pMechanism, new_pPublicKeyTemplate,
			       new_ulPublicKeyAttributeCount, new_pPrivateKeyTemplate,
			       new_ulPrivateKeyAttributeCount, ep11_data->ep11_pin_blob,
			       ep11_data->ep11_pin_blob_len, privkey_blob,
			       &privkey_blob_len, spki, &spki_len,
			       (uint64_t)ep11_data->target_list);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s m_GenerateKeyPair rc=0x%lx spki_len=0x%zx "
			    "privkey_blob_len=0x%zx mech='%s'\n",
			    __func__, rc, spki_len, privkey_blob_len,
			    ep11_get_ckm(pMechanism->mechanism));
		goto error;
	}
	TRACE_INFO("%s m_GenerateKeyPair rc=0x%lx spki_len=0x%zx "
		   "privkey_blob_len=0x%zx mech='%s'\n",
		   __func__, rc, spki_len, privkey_blob_len,
		   ep11_get_ckm(pMechanism->mechanism));

	if (spki_len > MAX_BLOBSIZE || privkey_blob_len > MAX_BLOBSIZE) {
		TRACE_ERROR("%s blobsize error\n", __func__);
		rc = CKR_KEY_INDIGESTIBLE;
		goto error;
	}

	memset(publblob, 0, sizeof(publblob));
	memset(privblob, 0, sizeof(privblob));

	memcpy(publblob, spki, spki_len);
	publblobsize = spki_len;

	memcpy(privblob, privkey_blob, privkey_blob_len);
	privblobsize = privkey_blob_len;

	rc = build_attribute(CKA_IBM_OPAQUE, publblob, publblobsize, &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}
	rc = template_update_attribute(publ_tmpl, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}

	rc = build_attribute(CKA_IBM_OPAQUE, privblob, privblobsize, &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}
	rc = template_update_attribute(priv_tmpl, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
			    __func__, rc);
		goto error;
	}

	if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
		/* scan the SPKI for CKA_EC_POINT */

#ifdef DEBUG
		TRACE_DEBUG("%s ec_generate_keypair spki:\n", __func__);
		TRACE_DEBUG_DUMP(spki, spki_len);
#endif
		rc = ep11_spki_key(spki, &key, &bit_str_len);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s read key from SPKI failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}

		/* 'key' is already EC point,
		 * SEC 1: Elliptic Curve Cryptography:
		 * The elliptic curve public key (a value of type ECPoint
		 * that is an OCTET STRING) is mapped to a subjectPublicKey
		 * (a value encoded as type BIT STRING) as follows: The most
		 * significant bit of the value of the OCTET STRING becomes
		 * the most significant bit of the value of the BIT STRING
		 * and so on with consecutive bits until the least significant
		 * bit of the OCTET STRING becomes the least significant bit
		 * of the BIT STRING.
		 */
		TRACE_INFO("%s ecpoint length 0x%lx\n", __func__, bit_str_len);
		data_len = bit_str_len;
		data = key;

#ifdef DEBUG
		TRACE_DEBUG("%s ec_generate_keypair ecpoint:\n", __func__);
		TRACE_DEBUG_DUMP(data, data_len);
#endif

		/* build and add CKA_EC_POINT */
		rc = build_attribute(CKA_EC_POINT, data, data_len, &attr);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}
		rc = template_update_attribute(publ_tmpl, attr);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}

		/* copy CKA_EC_PARAMS/CKA_ECDSA_PARAMS to private template  */
		if (template_attribute_find(publ_tmpl, CKA_EC_PARAMS, &attr)) {
			rc = build_attribute(attr->type, attr->pValue,
					     attr->ulValueLen, &n_attr);
			if (rc != CKR_OK) {
				TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
					    __func__, rc);
				goto error;
			}

			rc = template_update_attribute(priv_tmpl, n_attr);
			if (rc != CKR_OK) {
				TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
					    __func__, rc);
				goto error;
			}
		}

		if (template_attribute_find(publ_tmpl, CKA_ECDSA_PARAMS, &attr)) {
			rc = build_attribute(attr->type, attr->pValue,
					     attr->ulValueLen, &n_attr);
			if (rc != CKR_OK) {
				TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
					    __func__, rc);
				goto error;
			}

			rc = template_update_attribute(priv_tmpl, n_attr);
			if (rc != CKR_OK) {
				TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
					    __func__, rc);
				goto error;
			}
		}
	} else {
		/* scan the SPKI for modulus and public exponent and
		 * set the public key attributes, a user would use the
		 * already built SPKI (in CKA_IBM_OPAQUE of the public key).
		 */
		CK_BYTE *modulus, *publ_exp;

		rc = ep11_spki_key(spki, &key, &bit_str_len);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s read key from SPKI failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}

		/* key must be a sequence holding two integers,
		 * modulus and public exponent
		 */
		rc = ber_decode_SEQUENCE(key, &data, &data_len, &field_len);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s read sequence failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}

		modulus = key + field_len - data_len;
		rc = ber_decode_INTEGER(modulus, &data, &data_len, &field_len);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s read modulus failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}

#ifdef DEBUG
		TRACE_DEBUG("%s rsa_generate_keypair modulus:\n", __func__);
		TRACE_DEBUG_DUMP(data, data_len);
#endif

		/* build and add CKA_MODULUS */
		rc = build_attribute(CKA_MODULUS, data, data_len, &attr);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}
		rc = template_update_attribute(publ_tmpl, attr);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}

		/* read public exponent */
		publ_exp = modulus + field_len;
		rc = ber_decode_INTEGER(publ_exp, &data, &data_len, &field_len);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s read public exponent failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}

#ifdef DEBUG
		TRACE_DEBUG("%s rsa_generate_keypair public exponent:\n", __func__);
		TRACE_DEBUG_DUMP(data, data_len);
#endif

		/* build and add CKA_PUBLIC_EXPONENT */
		rc = build_attribute(CKA_PUBLIC_EXPONENT, data, data_len, &attr);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}
		rc = template_update_attribute(publ_tmpl, attr);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}
	}

error:
	if (new_pPrivateKeyTemplate)
		free_attribute_array(new_pPrivateKeyTemplate,
				     new_ulPrivateKeyAttributeCount);
	if (new_pPublicKeyTemplate)
		free_attribute_array(new_pPublicKeyTemplate,
				     new_ulPublicKeyAttributeCount);
	return rc;
}


/* generic function to generate RSA,DH,EC and DSA key pairs */
CK_RV ep11tok_generate_key_pair(STDLL_TokData_t *tokdata, SESSION * sess,
				CK_MECHANISM_PTR pMechanism,
				CK_ATTRIBUTE_PTR pPublicKeyTemplate,
				CK_ULONG ulPublicKeyAttributeCount,
				CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
				CK_ULONG ulPrivateKeyAttributeCount,
				CK_OBJECT_HANDLE_PTR phPublicKey,
				CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rc;
	OBJECT *public_key_obj = NULL;
	OBJECT *private_key_obj = NULL;
	CK_ULONG priv_ktype, publ_ktype;
	CK_ULONG class;
	CK_ATTRIBUTE *attr = NULL;
	CK_ATTRIBUTE *n_attr = NULL;

	/* Get the keytype to use when creating the key object */
	rc = ep11_get_keytype(pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
			      pMechanism, &priv_ktype, &class);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s get_keytype failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	rc = ep11_get_keytype(pPublicKeyTemplate, ulPublicKeyAttributeCount,
			      pMechanism, &publ_ktype, &class);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s get_keytype failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	/* Now build the skeleton key. */
	rc = object_mgr_create_skel(tokdata, sess, pPublicKeyTemplate,
				    ulPublicKeyAttributeCount, MODE_KEYGEN,
				    CKO_PUBLIC_KEY, publ_ktype,
				    &public_key_obj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("%s Object mgr create skeleton failed\n", __func__);
		goto error;
	}

	rc = object_mgr_create_skel(tokdata, sess, pPrivateKeyTemplate,
				    ulPrivateKeyAttributeCount, MODE_KEYGEN,
				    CKO_PRIVATE_KEY, priv_ktype,
				    &private_key_obj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("%s Object mgr create skeleton failed\n", __func__);
		goto error;
	}

	switch(pMechanism->mechanism) {
	case CKM_DH_PKCS_KEY_PAIR_GEN:
		rc = dh_generate_keypair(tokdata, pMechanism,
					 public_key_obj->template,
					 private_key_obj->template,
					 pPublicKeyTemplate,
					 ulPublicKeyAttributeCount,
					 pPrivateKeyTemplate,
					 ulPrivateKeyAttributeCount,
					 sess->handle);
		break;

	case CKM_EC_KEY_PAIR_GEN:      /* takes same parameters as RSA */
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
	case CKM_RSA_X9_31_KEY_PAIR_GEN:
		rc = rsa_ec_generate_keypair(tokdata, pMechanism,
					     public_key_obj->template,
					     private_key_obj->template,
					     pPublicKeyTemplate,
					     ulPublicKeyAttributeCount,
					     pPrivateKeyTemplate,
					     ulPrivateKeyAttributeCount,
					     sess->handle);
		break;

	case CKM_DSA_PARAMETER_GEN:
	case CKM_DSA_KEY_PAIR_GEN:
		rc = dsa_generate_keypair(tokdata, pMechanism,
					  public_key_obj->template,
					  private_key_obj->template,
					  pPublicKeyTemplate,
					  ulPublicKeyAttributeCount,
					  pPrivateKeyTemplate,
					  ulPrivateKeyAttributeCount,
					  sess->handle);
		break;
	default:
		TRACE_ERROR("%s invalid mech %s\n", __func__,
			    ep11_get_ckm(pMechanism->mechanism));
		rc = CKR_MECHANISM_INVALID;
		goto error;
	}

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx hpubkey=0x%lx hprivkey=0x%lx"
			    " pub_name='%s' priv_name='%s' pub_obj=%p priv_obj=%p\n",
			    __func__, rc, *phPublicKey, *phPrivateKey, public_key_obj->name,
			    private_key_obj->name, public_key_obj, private_key_obj);
		goto error;
	} else {
		TRACE_INFO("%s rc=0x%lx hpubkey=0x%lx hprivkey=0x%lx"
			   " pub_name='%s' priv_name='%s' pub_obj=%p priv_obj=%p\n",
			   __func__, rc, *phPublicKey, *phPrivateKey, public_key_obj->name,
			   private_key_obj->name, public_key_obj, private_key_obj);
	}

	/* Copy CKA_MODULUS and CKA_PUBLIC_EXPONENT attributes from
	 * public key object to private key object to fulfill PKCS#11
	 * private key template requirements
	 */

	if (template_attribute_find(public_key_obj->template, CKA_MODULUS,
				    &attr)) {
		rc = build_attribute(attr->type, attr->pValue, attr->ulValueLen,
				     &n_attr);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}

		rc = template_update_attribute(private_key_obj->template,
					       n_attr);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s template_update_attribute failed with "
				    "rc=0x%lx\n", __func__, rc);
			goto error;
		}
	}

	if (template_attribute_find(public_key_obj->template,
				    CKA_PUBLIC_EXPONENT, &attr)) {
		rc = build_attribute(attr->type, attr->pValue, attr->ulValueLen,
				     &n_attr);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
				    __func__, rc);
			goto error;
		}

		rc = template_update_attribute(private_key_obj->template,
					       n_attr);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s template_update_attribute failed with "
				     "rc=0x%lx\n", __func__, rc);
			goto error;
		}
	}

	/* Keys should be fully constructed,
	 * assign object handles and store keys.
	 */
	rc = object_mgr_create_final(tokdata, sess, public_key_obj, phPublicKey);
	if (rc != CKR_OK) {
		TRACE_DEVEL("%s Object mgr create final failed\n", __func__);
		goto error;
	}

	rc = object_mgr_create_final(tokdata, sess, private_key_obj, phPrivateKey);
	if (rc != CKR_OK) {
		TRACE_DEVEL("%s Object mgr create final failed\n", __func__);
		object_mgr_destroy_object(tokdata, sess, *phPublicKey);
		public_key_obj = NULL;
		goto error;
	}
	return rc;

error:
	if (public_key_obj) object_free(public_key_obj);
	if (private_key_obj) object_free(private_key_obj);

	*phPublicKey = 0;
	*phPrivateKey = 0;

	return rc;
}


/* Returns a blob for a key (handle or key obj).
 * The blob is created if none was build yet.
 */
static CK_RV h_opaque_2_blob(STDLL_TokData_t *tokdata, CK_OBJECT_HANDLE handle,
			     CK_BYTE **blob, size_t *blobsize, OBJECT **kobj)
{
	OBJECT *key_obj;
	CK_ATTRIBUTE *attr = NULL;
	CK_RV rc;

	/* find the key obj by the key handle */
	rc = object_mgr_find_in_map1(tokdata, handle, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s key 0x%lx not mapped\n", __func__, handle);
		return rc;
	}

	/* blob already exists */
	if (template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr) &&
	    (attr->ulValueLen > 0)) {
		*blob = attr->pValue;
		*blobsize = (size_t) attr->ulValueLen;
		*kobj = key_obj;
		TRACE_INFO("%s blob found blobsize=0x%zx\n",
			   __func__, *blobsize);
		return CKR_OK;
	} else {

		/* should not happen, imported key types not supported
		 * should cause a failing token_specific_object_add
		 */
		TRACE_ERROR("%s no blob\n", __func__);
		return CKR_FUNCTION_FAILED;
	}
}

CK_RV ep11tok_sign_init(STDLL_TokData_t *tokdata, SESSION *session,
			CK_MECHANISM *mech, CK_BBOOL recover_mode,
			CK_OBJECT_HANDLE key)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	size_t keyblobsize = 0;
	CK_BYTE *keyblob;
	OBJECT *key_obj = NULL;
	SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
	size_t ep11_sign_state_l = MAX_SIGN_STATE_BYTES;
	CK_BYTE *ep11_sign_state = malloc(ep11_sign_state_l);

	if (!ep11_sign_state) {
		TRACE_ERROR("%s Memory allocation failed\n", __func__);
		return CKR_HOST_MEMORY;
	}

	rc = h_opaque_2_blob(tokdata, key, &keyblob, &keyblobsize, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
		return rc;
	}

	rc = dll_m_SignInit(ep11_sign_state, &ep11_sign_state_l,
			    mech, keyblob, keyblobsize,
			    (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx blobsize=0x%zx key=0x%lx mech=0x%lx\n",
			    __func__, rc, keyblobsize, key, mech->mechanism);
		free(ep11_sign_state);
	} else {
		/* SIGN_VERIFY_CONTEX holds all needed for continuing,
		 * also by another adapter (stateless requests)
		 */
		ctx->key = key;
		ctx->multi = FALSE;
		ctx->active = TRUE;
		ctx->context = ep11_sign_state;
		ctx->context_len = ep11_sign_state_l;

		TRACE_INFO("%s rc=0x%lx blobsize=0x%zx key=0x%lx mech=0x%lx\n",
			   __func__, rc, keyblobsize, key, mech->mechanism);
	}

	return rc;
}


CK_RV ep11tok_sign(STDLL_TokData_t *tokdata, SESSION *session,
		   CK_BBOOL length_only, CK_BYTE *in_data,
		   CK_ULONG in_data_len, CK_BYTE *signature, CK_ULONG *sig_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;

	rc = dll_m_Sign(ctx->context, ctx->context_len, in_data, in_data_len,
		    signature, sig_len, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_sign_update(STDLL_TokData_t *tokdata, SESSION *session,
			  CK_BYTE *in_data, CK_ULONG in_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;

	if (!in_data || !in_data_len)
		return CKR_OK;

	rc = dll_m_SignUpdate(ctx->context, ctx->context_len, in_data,
			  in_data_len, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_sign_final(STDLL_TokData_t *tokdata, SESSION *session,
			 CK_BBOOL length_only, CK_BYTE *signature,
			 CK_ULONG *sig_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;

	rc = dll_m_SignFinal(ctx->context, ctx->context_len, signature, sig_len,
			     (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_verify_init(STDLL_TokData_t *tokdata, SESSION *session,
			  CK_MECHANISM *mech, CK_BBOOL recover_mode,
			  CK_OBJECT_HANDLE key)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	CK_BYTE *spki;
	size_t spki_len = 0;
	OBJECT *key_obj = NULL;
	SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
	size_t ep11_sign_state_l = MAX_SIGN_STATE_BYTES;
	CK_BYTE *ep11_sign_state = malloc(ep11_sign_state_l);

	if (!ep11_sign_state) {
		TRACE_ERROR("%s Memory allocation failed\n", __func__);
		return CKR_HOST_MEMORY;
	}

	rc = h_opaque_2_blob(tokdata, key, &spki, &spki_len, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
		return rc;
	}

	rc = dll_m_VerifyInit(ep11_sign_state, &ep11_sign_state_l, mech,
			  spki, spki_len, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx spki_len=0x%zx key=0x%lx "
			    "ep11_sign_state_l=0x%zx mech=0x%lx\n", __func__,
			    rc, spki_len, key, ep11_sign_state_l,
			    mech->mechanism);
	} else {
		ctx->key = key;
		ctx->multi = FALSE;
		ctx->active = TRUE;
		ctx->context = ep11_sign_state;
		ctx->context_len = ep11_sign_state_l;

		TRACE_INFO("%s rc=0x%lx spki_len=0x%zx key=0x%lx "
			   "ep11_sign_state_l=0x%zx mech=0x%lx\n", __func__,
			   rc, spki_len, key, ep11_sign_state_l,
			   mech->mechanism);
	}

	return rc;
}


CK_RV ep11tok_verify(STDLL_TokData_t *tokdata, SESSION *session, CK_BYTE *in_data,
		     CK_ULONG in_data_len, CK_BYTE *signature, CK_ULONG sig_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;

	rc = dll_m_Verify(ctx->context, ctx->context_len, in_data, in_data_len,
		      signature, sig_len, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_verify_update(STDLL_TokData_t *tokdata, SESSION *session,
			    CK_BYTE *in_data, CK_ULONG in_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;

	if (!in_data || !in_data_len)
		return CKR_OK;

	rc = dll_m_VerifyUpdate(ctx->context, ctx->context_len, in_data,
			    in_data_len, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_verify_final(STDLL_TokData_t *tokdata, SESSION *session,
			   CK_BYTE *signature, CK_ULONG sig_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;

	rc = dll_m_VerifyFinal(ctx->context, ctx->context_len, signature,
			   sig_len, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_decrypt_final(STDLL_TokData_t *tokdata, SESSION *session,
			    CK_BYTE_PTR output_part,
			    CK_ULONG_PTR p_output_part_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc = CKR_OK;
	ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;

	rc = dll_m_DecryptFinal(ctx->context, ctx->context_len,
				output_part, p_output_part_len,
				(uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_decrypt(STDLL_TokData_t *tokdata, SESSION *session,
		      CK_BYTE_PTR input_data, CK_ULONG input_data_len,
		      CK_BYTE_PTR output_data, CK_ULONG_PTR p_output_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc = CKR_OK;
	ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;

	rc = dll_m_Decrypt(ctx->context, ctx->context_len, input_data,
			   input_data_len, output_data, p_output_data_len,
			   (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_decrypt_update(STDLL_TokData_t *tokdata, SESSION *session,
			     CK_BYTE_PTR input_part, CK_ULONG input_part_len,
			     CK_BYTE_PTR output_part,
			     CK_ULONG_PTR p_output_part_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc = CKR_OK;
	ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;

	if (!input_part || !input_part_len) {
		*p_output_part_len = 0;
		return CKR_OK; /* nothing to update, keep context */
	}

	rc = dll_m_DecryptUpdate(ctx->context, ctx->context_len,
			     input_part, input_part_len, output_part,
			     p_output_part_len, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_encrypt_final(STDLL_TokData_t *tokdata, SESSION *session,
			    CK_BYTE_PTR output_part,
			    CK_ULONG_PTR p_output_part_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc = CKR_OK;
	ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;

	rc = dll_m_EncryptFinal(ctx->context, ctx->context_len,
				output_part, p_output_part_len,
				(uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_encrypt(STDLL_TokData_t *tokdata, SESSION *session,
		      CK_BYTE_PTR input_data, CK_ULONG input_data_len,
		      CK_BYTE_PTR output_data, CK_ULONG_PTR p_output_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc = CKR_OK;
	ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;

	rc = dll_m_Encrypt(ctx->context, ctx->context_len, input_data,
			   input_data_len, output_data, p_output_data_len,
			   (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_encrypt_update(STDLL_TokData_t *tokdata, SESSION *session,
			     CK_BYTE_PTR input_part, CK_ULONG input_part_len,
			     CK_BYTE_PTR output_part,
			     CK_ULONG_PTR p_output_part_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc = CKR_OK;
	ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;

	if (!input_part || !input_part_len) {
		*p_output_part_len = 0;
		return CKR_OK; /* nothing to update, keep context */
	}

	rc = dll_m_EncryptUpdate(ctx->context, ctx->context_len,
				 input_part, input_part_len, output_part,
				 p_output_part_len,
				 (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


static CK_RV ep11_ende_crypt_init(STDLL_TokData_t *tokdata, SESSION *session,
				  CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key, int op)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc = CKR_OK;
	CK_BYTE *blob;
	size_t blob_len = 0;
	OBJECT *key_obj = NULL;
	size_t ep11_state_l = MAX_CRYPT_STATE_BYTES;
	CK_BYTE *ep11_state = malloc(ep11_state_l); /* freed by encr/decr_mgr.c */

	if (!ep11_state) {
		TRACE_ERROR("%s Memory allocation failed\n", __func__);
		return CKR_HOST_MEMORY;
	}

	rc = h_opaque_2_blob(tokdata, key, &blob, &blob_len, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
		return rc;
	}

	if (op == DECRYPT) {
		ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;
		rc = dll_m_DecryptInit(ep11_state, &ep11_state_l, mech, blob,
				   blob_len, (uint64_t)ep11_data->target_list);
		ctx->key = key;
		ctx->active = TRUE;
		ctx->context = ep11_state;
		ctx->context_len = ep11_state_l;
		if (rc != CKR_OK) {
			TRACE_ERROR("%s m_DecryptInit rc=0x%lx blob_len=0x%zx "
				    "mech=0x%lx\n", __func__, rc, blob_len,
				    mech->mechanism);
		} else {
			TRACE_INFO("%s m_DecryptInit rc=0x%lx blob_len=0x%zx "
				   "mech=0x%lx\n", __func__, rc, blob_len,
				   mech->mechanism);
		}
	} else {
		ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;
		rc = dll_m_EncryptInit (ep11_state, &ep11_state_l, mech, blob,
				    blob_len, (uint64_t)ep11_data->target_list);
		ctx->key = key;
		ctx->active = TRUE;
		ctx->context = ep11_state;
		ctx->context_len = ep11_state_l;
		if (rc != CKR_OK) {
			TRACE_ERROR("%s m_EncryptInit rc=0x%lx blob_len=0x%zx "
				    "mech=0x%lx\n", __func__, rc, blob_len,
				    mech->mechanism);
		} else {
			TRACE_INFO("%s m_EncryptInit rc=0x%lx blob_len=0x%zx "
				   "mech=0x%lx\n", __func__, rc, blob_len,
				   mech->mechanism);
		}
	}

	return rc;
}


CK_RV ep11tok_encrypt_init(STDLL_TokData_t *tokdata, SESSION *session,
			   CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key)
{
	CK_RV rc;

	TRACE_INFO("%s key=0x%lx\n", __func__, key);

	rc = ep11_ende_crypt_init(tokdata, session, mech, key, ENCRYPT);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_decrypt_init(STDLL_TokData_t *tokdata, SESSION *session,
			   CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key)
{
	CK_RV rc;

	TRACE_INFO("%s key=0x%lx mech=0x%lx\n", __func__, key, mech->mechanism);

	rc = ep11_ende_crypt_init(tokdata, session, mech, key, DECRYPT);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
	}

	return rc;
}


CK_RV ep11tok_wrap_key(STDLL_TokData_t *tokdata, SESSION *session,
		       CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE wrapping_key,
		       CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped_key,
		       CK_ULONG_PTR p_wrapped_key_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	CK_BYTE *wrapping_blob;
	size_t wrapping_blob_len;

	CK_BYTE *wrap_target_blob;
	size_t wrap_target_blob_len;
	int size_querry = 0;
	OBJECT *key_obj = NULL;
	CK_ATTRIBUTE *attr;

	/* ep11 weakness:
	 * it does not set *p_wrapped_key_len if wrapped_key == NULL
	 * (that is with a size query)
	 */
	if (wrapped_key == NULL) {
		size_querry = 1;
		*p_wrapped_key_len = MAX_BLOBSIZE;
		wrapped_key = malloc(MAX_BLOBSIZE);
		if (!wrapped_key) {
			TRACE_ERROR("%s Memory allocation failed\n", __func__);
			return CKR_HOST_MEMORY;
		}
	}

	/* the key that encrypts */
	rc = h_opaque_2_blob(tokdata, wrapping_key, &wrapping_blob,
			     &wrapping_blob_len, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s h_opaque_2_blob(wrapping_key) failed with rc=0x%lx\n",
			    __func__, rc);
		if (size_querry) free(wrapped_key);
		return rc;
	}

	/* the key to be wrapped */
	rc = h_opaque_2_blob(tokdata, key, &wrap_target_blob,
			     &wrap_target_blob_len, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s h_opaque_2_blob(key) failed with rc=0x%lx\n", __func__, rc);
		if (size_querry) free(wrapped_key);
		return rc;
	}

	/* check if wrap mechanism is allowed for the key to be wrapped.
	 * AES_ECB and AES_CBC is only allowed to wrap secret keys.
	 */
	if (!template_attribute_find(key_obj->template, CKA_CLASS, &attr)) {
		TRACE_ERROR("%s No CKA_CLASS attribute found in key template\n", __func__);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	if ((*(CK_OBJECT_CLASS *)attr->pValue != CKO_SECRET_KEY) &&
	    ((mech->mechanism == CKM_AES_ECB) ||
	     (mech->mechanism == CKM_AES_CBC))) {
		TRACE_ERROR("%s Wrap mechanism does not match to target key type\n", __func__);
		return CKR_KEY_NOT_WRAPPABLE;
	}

	/* debug */
	TRACE_INFO("%s start wrapKey: mech=0x%lx wr_key=0x%lx\n",
		   __func__, mech->mechanism, wrapping_key);

	/* the key to be wrapped is extracted from its blob by the card
	 * and a standard BER encoding is build which is encryted by
	 * the wrapping key (wrapping_blob).
	 * The wrapped key can be processed by any PKCS11 implementation.
	 */
	rc = dll_m_WrapKey(wrap_target_blob, wrap_target_blob_len, wrapping_blob,
		       wrapping_blob_len, NULL, ~0, mech, wrapped_key,
		       p_wrapped_key_len, (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s m_WrapKey failed with rc=0x%lx\n", __func__, rc);
	} else {
		TRACE_INFO("%s rc=0x%lx wr_key=%p wr_key_len=0x%lx\n",
			   __func__, rc, wrapped_key, *p_wrapped_key_len);
	}

	if (size_querry) free(wrapped_key);
	return rc;
}


CK_RV ep11tok_unwrap_key(STDLL_TokData_t *tokdata, SESSION *session, CK_MECHANISM_PTR mech,
			 CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			 CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_key_len,
			 CK_OBJECT_HANDLE wrapping_key,
			 CK_OBJECT_HANDLE_PTR p_key)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	CK_BYTE *wrapping_blob;
	size_t wrapping_blob_len;
	char csum[MAX_BLOBSIZE];
	CK_ULONG cslen = sizeof(csum);
	OBJECT *key_obj = NULL;
	CK_BYTE keyblob[MAX_BLOBSIZE];
	size_t keyblobsize = sizeof(keyblob);
	CK_ATTRIBUTE *attr = NULL;
	int i = 0;
	CK_ULONG ktype;
	CK_ULONG class;
	CK_ULONG len;
	CK_ATTRIBUTE_PTR new_attrs = NULL;
	CK_ULONG new_attrs_len = 0;
	OBJECT *kobj = NULL;

	/* get wrapping key blob */
	rc = h_opaque_2_blob(tokdata, wrapping_key, &wrapping_blob, &wrapping_blob_len, &kobj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s h_opaque_2_blob(wrapping_key) failed with rc=0x%lx\n", __func__, rc);
		return rc;
	}

	TRACE_DEVEL("%s start unwrapKey:  mech=0x%lx attrs_len=0x%lx wr_key=0x%lx\n",
		    __func__, mech->mechanism, attrs_len, wrapping_key);
	for (i = 0; i < attrs_len; i++) {
		TRACE_DEVEL(" attribute attrs.type=0x%lx\n", attrs[i].type);
	}

	memset(keyblob, 0, sizeof(keyblob));

	/*get key type of unwrapped key*/
	CK_ATTRIBUTE_PTR cla_attr = get_attribute_by_type(attrs, attrs_len, CKA_CLASS);
	CK_ATTRIBUTE_PTR keytype_attr = get_attribute_by_type(attrs, attrs_len, CKA_KEY_TYPE);
	if (!cla_attr || !keytype_attr) {
		TRACE_ERROR("%s CKA_CLASS or CKA_KEY_CLASS attributes not found\n", __func__);
		return CKR_FUNCTION_FAILED;
	}
	switch (*(CK_KEY_TYPE *)cla_attr->pValue) {
	case CKO_SECRET_KEY:
		rc = check_key_attributes(*(CK_KEY_TYPE *)keytype_attr->pValue,
					  CKO_SECRET_KEY, attrs,
					  attrs_len, &new_attrs,
					  &new_attrs_len);
		break;
	case CKO_PUBLIC_KEY:
		rc = check_key_attributes(*(CK_KEY_TYPE *)keytype_attr->pValue,
					  CKO_PUBLIC_KEY, attrs, attrs_len,
					  &new_attrs, &new_attrs_len);
		break;
	case CKO_PRIVATE_KEY:
		rc = check_key_attributes(*(CK_KEY_TYPE *)keytype_attr->pValue,
					  CKO_PRIVATE_KEY, attrs, attrs_len,
					  &new_attrs, &new_attrs_len);
		break;
	default:
		TRACE_ERROR("%s Missing CKA_CLASS type of wrapped key\n", __func__);
		return CKR_TEMPLATE_INCOMPLETE;
	}
	if (rc != CKR_OK) {
		TRACE_ERROR("%s check key attributes failed: rc=0x%lx\n", __func__, rc);
		goto error;
	}

	/* check if unwrap mechanism is allowed for the key to be unwrapped.
	 * AES_ECB and AES_CBC only allowed to unwrap secret keys.
	 */
	if ( (*(CK_OBJECT_CLASS *)cla_attr->pValue != CKO_SECRET_KEY) &&
	     ((mech->mechanism == CKM_AES_ECB) ||
	      (mech->mechanism == CKM_AES_CBC)))
		return CKR_ARGUMENTS_BAD;

	/* we need a blob for the new key created by unwrapping,
	 * the wrapped key comes in BER
	 */
	rc = dll_m_UnwrapKey(wrapped_key, wrapped_key_len, wrapping_blob,
			 wrapping_blob_len, NULL, ~0, ep11_data->ep11_pin_blob,
			 ep11_data->ep11_pin_blob_len, mech, new_attrs, new_attrs_len,
			 keyblob, &keyblobsize, csum, &cslen,
			 (uint64_t)ep11_data->target_list);

	if (rc != CKR_OK) {
		TRACE_ERROR("%s m_UnwrapKey rc=0x%lx blobsize=0x%zx mech=0x%lx\n",
			    __func__, rc, keyblobsize, mech->mechanism);
		goto error;
	}
	TRACE_INFO("%s m_UnwrapKey rc=0x%lx blobsize=0x%zx mech=0x%lx\n",
		   __func__, rc, keyblobsize, mech->mechanism);

	/* card provides length in csum bytes 4 - 7, big endian */
	len = csum[6] + 256*csum[5] + 256*256*csum[4] + 256*256*256*csum[3];
	len = len/8;  /* comes in bits */
	TRACE_INFO("%s m_UnwrapKey length 0x%hhx 0x%hhx 0x%hhx 0x%hhx 0x%lx\n",
		   __func__, csum[3], csum[4], csum[5], csum[6], len);

	/* Get the keytype to use when creating the key object */
	rc = ep11_get_keytype(new_attrs, new_attrs_len, mech, &ktype, &class);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s get_subclass failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	/* Start creating the key object */
	rc = object_mgr_create_skel(tokdata, session, new_attrs, new_attrs_len,
				    MODE_UNWRAP, class, ktype, &key_obj);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s object_mgr_create_skel failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	rc = build_attribute(CKA_IBM_OPAQUE, keyblob, keyblobsize, &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	rc = template_update_attribute(key_obj->template, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *) &len, sizeof(CK_ULONG), &attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	rc = template_update_attribute(key_obj->template, attr);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	/* key should be fully constructed.
	 * Assign an object handle and store key.
	 */
	rc = object_mgr_create_final(tokdata, session, key_obj, p_key);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s object_mgr_create_final with rc=0x%lx\n", __func__, rc);
		goto error;
	}

	goto done;

error:
	if (key_obj) object_free(key_obj);
	*p_key = 0;
done:
	if (new_attrs)
		free_attribute_array(new_attrs, new_attrs_len);

	return rc;
}


/* mechanisms ep11 reports but should be hidden because e.g.
   the EP11 card operates in a FIPS mode that forbides the mechanism,
   add here other mechanisms if required */
const CK_MECHANISM_TYPE ep11_banned_mech_list[] =
{
#ifdef DEFENSIVE_MECHLIST
	CKM_DES_KEY_GEN,
	CKM_DES_ECB,
	CKM_DES_CBC,
	CKM_DES_CBC_PAD,
	CKM_GENERIC_SECRET_KEY_GEN,

	CKM_SHA224,
	CKM_SHA224_HMAC,
	CKM_SHA224_RSA_PKCS,
	CKM_SHA224_RSA_PKCS_PSS,
	CKM_SHA256_RSA_PKCS_PSS,
	CKM_SHA384_RSA_PKCS_PSS,
	CKM_SHA512_RSA_PKCS_PSS,
	CKM_SHA224_KEY_DERIVATION,
	CKM_SHA384_KEY_DERIVATION,
	CKM_SHA512_KEY_DERIVATION,
	CKM_ECDSA_SHA224,
	CKM_SHA512_224,
	CKM_SHA512_224_HMAC,
	CKM_SHA512_224_HMAC_GENERAL,
	CKM_SHA512_256,
	CKM_SHA512_256_HMAC,
	CKM_SHA512_256_HMAC_GENERAL,

	/* Vendor specific */
	CKM_IBM_DH_PKCS_DERIVE_RAW,
	CKM_IBM_ECDH1_DERIVE_RAW,
	CKM_IBM_EC_MULTIPLY,
	CKM_IBM_ATTRIBUTEBOUND_WRAP,
	CKM_IBM_EAC,
	CKM_IBM_RETAINKEY,
	CKA_IBM_MACKEY,
	CKM_IBM_ECDSA_SHA224,
	CKM_IBM_ECDSA_SHA256,
	CKM_IBM_ECDSA_SHA384,
	CKM_IBM_ECDSA_SHA512,
	CKM_IBM_SHA512_256,
	CKM_IBM_SHA512_224,
	CKM_IBM_SHA512_256_HMAC,
	CKM_IBM_SHA512_224_HMAC,

#endif
};
const CK_ULONG banned_mech_list_len = (sizeof(ep11_banned_mech_list) / sizeof(CK_MECHANISM_TYPE));


/* filtering out some mechanisms we do not want to provide
 * makes it complicated
 */
CK_RV ep11tok_get_mechanism_list(STDLL_TokData_t *tokdata,
				 CK_MECHANISM_TYPE_PTR pMechanismList,
				 CK_ULONG_PTR pulCount)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc = 0;
	CK_ULONG counter = 0;
	CK_MECHANISM_TYPE_PTR mlist = NULL;
	int i, j, banned;

	/* size querry */
	if (pMechanismList == NULL) {
		rc = dll_m_GetMechanismList(0, pMechanismList, pulCount,
					    (uint64_t)ep11_data->target_list);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #1\n", __func__, rc);
			return rc;
		}

		/* adjust the size according to the ban list,
		 * for this we need to know what the card provides
		 */
		counter = *pulCount;
		mlist = (CK_MECHANISM_TYPE *)malloc(sizeof(CK_MECHANISM_TYPE) * counter);
		if (!mlist) {
			TRACE_ERROR("%s Memory allocation failed\n", __func__);
			return CKR_HOST_MEMORY;
		}
		rc = dll_m_GetMechanismList(0, mlist, &counter, (uint64_t)ep11_data->target_list);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #2\n", __func__, rc);
			free(mlist);
			return rc;
		}

		for (i = 0; i < counter; i++) {
			banned = 0;
			for (j = 0; j < banned_mech_list_len; j++) {
				if (mlist[i] == ep11_banned_mech_list[j]) {
					banned = 1;
					TRACE_INFO("%s banned mech '%s'\n",
						   __func__, ep11_get_ckm(ep11_banned_mech_list[j]));
				}
			}
			if (banned == 1) {
				/* banned mech found,
				 * decrement reported list size
				 */
				*pulCount = *pulCount - 1;
			}
		}
	} else {
		/* 2. call, content request */

		/* find out size ep11 will report, cannot use the size
		 * that comes as parameter, this is a 'reduced size',
		 * ep11 would complain about insufficient list size
		 */
		rc = dll_m_GetMechanismList(0, mlist, &counter,
					    (uint64_t)ep11_data->target_list);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #3\n", __func__, rc);
			return rc;
		}

		mlist = (CK_MECHANISM_TYPE *)malloc(sizeof(CK_MECHANISM_TYPE) * counter);
		if (!mlist) {
			TRACE_ERROR("%s Memory allocation failed\n", __func__);
			return CKR_HOST_MEMORY;
		}
		/* all the card has */
		rc = dll_m_GetMechanismList(0, mlist, &counter, (uint64_t)ep11_data->target_list);
		if (rc != CKR_OK) {
			TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #4\n", __func__, rc);
			free(mlist);
			return rc;
		}

		for (i = 0; i < counter; i++)
			TRACE_INFO("%s raw mech list entry '%s'\n",
				   __func__, ep11_get_ckm(mlist[i]));

		/* copy only mechanisms not banned */
		*pulCount = 0;
		for (i = 0; i < counter; i++) {
			banned = 0;
			for (j = 0; j < banned_mech_list_len; j++) {
				if (mlist[i] == ep11_banned_mech_list[j]) {
					banned = 1;
				}
			}
			if (banned == 0) {
				pMechanismList[*pulCount] = mlist[i];
				*pulCount = *pulCount + 1;
			} else {
				;
			} /* do not copy banned mech */
		}
	}

	if (mlist) free(mlist);
	return rc;
}


CK_RV ep11tok_get_mechanism_info(STDLL_TokData_t *tokdata,
				 CK_MECHANISM_TYPE type,
				 CK_MECHANISM_INFO_PTR pInfo)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	CK_RV rc;
	int i;

	rc = dll_m_GetMechanismInfo(0, type, pInfo, (uint64_t)ep11_data->target_list);
	if (rc != CKR_OK) {
		TRACE_ERROR("%s m_GetMechanismInfo(0x%lx) failed with rc=0x%lx\n",
			    __func__, type, rc);
		return rc;
	}

	/* The card operates always in a FISP mode that requires stronger
	 * key sizes, but, in theory, can also operate with weaker key sizes.
	 * Customers are not interested in theory but in what mechanism
	 * they can use (mechanisms that are not rejected by the card).
	 */
	for (i = 0; i < banned_mech_list_len; i++) {
		if (type == ep11_banned_mech_list[i])
			return CKR_MECHANISM_INVALID;
	}
#ifdef DEFENSIVE_MECHLIST
	if (rc == CKR_OK) {
		switch (type) {
		case CKM_RSA_PKCS:
		case CKM_RSA_PKCS_KEY_PAIR_GEN:
		case CKM_RSA_X9_31_KEY_PAIR_GEN:
		case CKM_RSA_PKCS_PSS:
		case CKM_SHA1_RSA_X9_31:
		case CKM_SHA1_RSA_PKCS:
		case CKM_SHA1_RSA_PKCS_PSS:
		case CKM_SHA256_RSA_PKCS:
		case CKM_SHA256_RSA_PKCS_PSS:
		case CKM_SHA224_RSA_PKCS:
		case CKM_SHA224_RSA_PKCS_PSS:
		case CKM_SHA384_RSA_PKCS:
		case CKM_SHA384_RSA_PKCS_PSS:
		case CKM_SHA512_RSA_PKCS:
		case CKM_SHA512_RSA_PKCS_PSS:
		case CKM_RSA_X_509:
		case CKM_RSA_X9_31:
			/* EP11 card always in a FIPS mode rejecting
			 * lower key sizes
			 */
			pInfo->ulMinKeySize = 1024;
			break;

		case CKM_SHA256_HMAC:
		case CKM_SHA224_HMAC:
		case CKM_SHA384_HMAC:
		case CKM_SHA512_HMAC:
		case CKM_DES3_ECB:
		case CKM_DES3_CBC:
		case CKM_DES3_CBC_PAD:
		case CKM_SHA_1_HMAC:
			/* EP11 card always in a FIPS mode rejecting
			 * lower key sizes < 80 bits.
			 */
			if (pInfo->ulMinKeySize == 8)
				pInfo->ulMinKeySize = 16;
			break;

		default:
			; /* do not touch */
		}
	}
#endif /* DEFENSIVE_MECHLIST */

	if (rc != CKR_OK)
		TRACE_ERROR("%s rc=0x%lx unsupported '%s'\n",
			    __func__, rc, ep11_get_ckm(type));
	return rc;
}


/* used for reading in the adapter config file,
 * converts a 'token' to a number, returns 0 with success
 */
static inline short check_n(ep11_target_t *target, char *nptr, int *apqn_i)
{
	int num;

	if (sscanf(nptr, "%i", &num) != 1) {
		TRACE_ERROR("%s invalid number '%s'\n", __func__, nptr);
		return -1;
	}

	if (num < 0 || num > 255) {
		TRACE_ERROR("%s invalid number '%s' %d\n", __func__, nptr, num);
		return -1;
	} else if (*apqn_i < 0 || *apqn_i >= MAX_APQN*2) {
		TRACE_ERROR("%s invalid amount of numbers %d\n", __func__, num);
		return -1;
	} else {
		/* insert number into target variable */
		target->apqns[*apqn_i] = (short)num;
		/* how many APQNs numbers so far */
		*apqn_i = *apqn_i + 1;
		return 0;
	}
}


static int read_adapter_config_file(STDLL_TokData_t *tokdata, const char* conf_name)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
	FILE *ap_fp = NULL;       /* file pointer adapter config file */
	int i, ap_file_size = 0;     /* size adapter config file */
	char *token, *str;
	char filebuf[EP11_CFG_FILE_SIZE];
	char line[1024];
	int whitemode = 0;
	int anymode   = 0;
	int apqn_i = 0;     /* how many APQN numbers */
	char *conf_dir = getenv("OCK_EP11_TOKEN_DIR");
	char fname[PATH_MAX];
	ep11_target_t *ep11_targets = (ep11_target_t *)ep11_data->target_list;
	int rc = 0;

	if (tokdata->initialized)
		return 0;

	memset(fname, 0, PATH_MAX);

	/* via envrionment variable it is possible to overwrite the
	 * directory where the ep11 token config file is searched.
	 */
	if (conf_dir) {
		if (conf_name && strlen(conf_name) > 0) {
			/* extract filename part from conf_name */
			for (i=strlen(conf_name)-1; i >= 0 && conf_name[i] != '/'; i--);

			snprintf(fname, sizeof(fname), "%s/%s", conf_dir, conf_name+i+1);
			fname[sizeof(fname)-1] = '\0';
			ap_fp = fopen(fname, "r");

			if (!ap_fp)
				TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
					    __func__, fname, errno);
		}
		if (!ap_fp) {
			snprintf(fname, sizeof(fname), "%s/%s", conf_dir, EP11_DEFAULT_CFG_FILE);
			fname[sizeof(fname)-1] = '\0';
			ap_fp = fopen(fname, "r");
			if (!ap_fp)
				TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
					    __func__, fname, errno);
		}
	} else {
		if (conf_name && strlen(conf_name) > 0) {
			strncpy(fname, conf_name, sizeof(fname));
			fname[sizeof(fname)-1] = '\0';
			ap_fp = fopen(fname, "r");
			if (!ap_fp) {
				TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
					    __func__, fname, errno);
				snprintf(fname, sizeof(fname), "%s/%s", OCK_CONFDIR, conf_name);
				fname[sizeof(fname)-1] = '\0';
				ap_fp = fopen(fname, "r");
				if (!ap_fp)
					TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
						    __func__, fname, errno);
			}
		} else {
			snprintf(fname, sizeof(fname), "%s/%s", OCK_CONFDIR, EP11_DEFAULT_CFG_FILE);
			fname[sizeof(fname)-1] = '\0';
			ap_fp = fopen(fname, "r");
			if (!ap_fp)
				TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
					    __func__, fname, errno);
		}
	}

	/* now we should really have an open ep11 token config file */
	if (!ap_fp) {
		TRACE_ERROR("%s no valid EP 11 config file found\n", __func__);
		return APQN_FILE_INV_2;
	}

	TRACE_INFO("%s EP 11 token config file is '%s'\n", __func__, fname);

	/* read config file line by line,
	 * ignore empty and # and copy rest into file buf
	 */
	memset(filebuf, 0, EP11_CFG_FILE_SIZE);
	while (fgets((char *)line, sizeof(line), ap_fp)) {
		char *p;
		int len;
		/* skip over leading spaces */
		for (p=line; *p == ' ' || *p == '\t'; p++) ;
		/* if line is empty or starts with # skip line */
		len = strlen(p);
		if (*p != '#' && *p != '\n' && len > 0) {
			/* store line in buffer */
			if (ap_file_size + len < EP11_CFG_FILE_SIZE) {
				memcpy(filebuf+ap_file_size, p, len);
				ap_file_size += len;
			} else {
				TRACE_ERROR("%s EP 11 config file filename too large\n",
					    __func__);
				return  APQN_FILE_INV_FILE_SIZE;
			}
		}
	}

	ep11_targets->length = 0;

	/* parse the file buf
	 * please note, we still accept the LOGLEVEL entry
	 * for compatibility reasons but just ignore it.
	 */
	for (i=0, str=filebuf; rc == 0; str=NULL) {
		/* strtok tokenizes the string,
		 * delimiters are newline and whitespace.
		 */
		token = strtok(str, "\n\t ");

		if (i == 0) {
			/* expecting APQN_WHITELIST or APQN_ANY or LOGLEVEL or eof */
			if (token == NULL)
				break;
			if (strncmp(token, "APQN_WHITELIST", 14) == 0) {
				whitemode = 1;
				i = 1;
			} else if (strncmp(token, "APQN_ANY", 8) == 0) {
				anymode = 1;
				i = 0;
			} else if (strncmp(token, "LOGLEVEL", 8) == 0)
				i = 3;
			else {
				/* syntax error */
				TRACE_ERROR("%s Expected APQN_WHITELIST or"
					    " APQN_ANY or LOGLEVEL keyword,"
					    " found '%s' in configfile\n",
					    __func__, token);
				rc = APQN_FILE_SYNTAX_ERROR_0;
				break;
			}
		} else if (i == 1) {
			/* expecting END or first number of a number
			 * pair (number range 0...255)
			 */
            if (token == NULL) {
                rc = APQN_FILE_UNEXPECTED_END_OF_FILE;
                break;
            }
			if (strncmp(token, "END", 3) == 0)
				i = 0;
			else {
				if (check_n(ep11_targets, token, &apqn_i) < 0) {
					rc = APQN_FILE_SYNTAX_ERROR_1;
					break;
				}
				i = 2;
			}
		} else if (i == 2) {
			/* expecting second number of a number pair
			 * (number range 0...255)
			 */
            if (token == NULL) {
                rc = APQN_FILE_UNEXPECTED_END_OF_FILE;
                break;
            }
			if (strncmp(token, "END", 3) == 0) {
				TRACE_ERROR("%s Expected 2nd number, found '%s' in configfile\n",
					    __func__, token);
				rc = APQN_FILE_SYNTAX_ERROR_2;
				break;
			}
			if (check_n(ep11_targets, token, &apqn_i) < 0) {
				rc = APQN_FILE_SYNTAX_ERROR_3;
				break;
			}
			ep11_targets->length++;
			if (ep11_targets->length > MAX_APQN) {
				TRACE_ERROR("%s Too many APQNs in configfile (max %d)\n",
					    __func__, (int) MAX_APQN);
				rc = APQN_FILE_SYNTAX_ERROR_4;
				break;
			}
			i = 1;
		} else if (i == 3) {
			/* expecting log level value
			 * (a number in the range 0...9)
			 */
            if (token == NULL) {
                rc = APQN_FILE_UNEXPECTED_END_OF_FILE;
                break;
            }
			char *endptr;
			int loglevel  = strtol(token, &endptr, 10);
			if (*endptr != '\0' || loglevel < 0 || loglevel > 9) {
				TRACE_ERROR("%s Invalid loglevel value '%s' in configfile\n",
					    __func__, token);
				rc = APQN_FILE_SYNTAX_ERROR_5;
				break;
			}
			TRACE_WARNING("%s LOGLEVEL setting is not supported any more !\n", __func__);
			TRACE_WARNING("%s Use opencryptoki logging/tracing facilities instead.\n", __func__);
			i = 0;
		}
	}

	/* do some checks: */
	if (rc == 0) {
		if ( !(whitemode || anymode)) {
			TRACE_ERROR("%s At least one APQN mode needs to be present in configfile:"
				    " APQN_WHITEMODE or APQN_ANY\n", __func__);
			rc = APQN_FILE_NO_APQN_MODE;
		} else if (whitemode) {
			/* at least one APQN needs to be defined */
			if (ep11_targets->length < 1) {
				TRACE_ERROR("%s At least one APQN needs to be defined in the configfile\n",
					    __func__);
				rc = APQN_FILE_NO_APQN_GIVEN;
			}
		}
	}

	/* log the whitelist of APQNs */
	if (rc == 0 && whitemode) {
		TRACE_INFO("%s whitelist with %d APQNs defined:\n",
			   __func__, ep11_targets->length);
		for (i=0; i < ep11_targets->length; i++) {
			TRACE_INFO(" APQN entry %d: adapter=%d domain=%d\n", i,
				   ep11_targets->apqns[2*i],
				   ep11_targets->apqns[2*i+1]);
		}
	}

	tokdata->initialized = TRUE;
	return rc;
}
