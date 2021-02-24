/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can
 * be found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 *
 * import/export test for the CCA token
 * by Harald Freudenberger <freude@de.ibm.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <stdint.h>

#include "pkcs11types.h"
#include "ec_curves.h"

#include "regress.h"
#include "common.c"

// define this to enable the AES cipher key import test:
// #define CCA_AES_CIPHER_KEY_SUPPORTED

static CK_RV export_ibm_opaque(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE handle,
			       CK_BYTE **buf, CK_ULONG *buflen)
{
    CK_RV rc;
    CK_ULONG len;
    CK_ATTRIBUTE a_opaque = { CKA_IBM_OPAQUE, NULL_PTR, 0 };

    rc = funcs->C_GetAttributeValue(session, handle, &a_opaque, 1);
    if (rc != CKR_OK) {
	testcase_error("C_GetAttributeValue() rc=%s", p11_get_ckr(rc));
	return rc;
    }
    len = a_opaque.ulValueLen;
    if (!len) {
	testcase_error("opaque attribute len is 0");
	return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    a_opaque.pValue = malloc(len);
    if (!a_opaque.pValue) {
	testcase_error("malloc(%lu) failed", len);
	return CKR_HOST_MEMORY;
    }
    rc = funcs->C_GetAttributeValue(session, handle, &a_opaque, 1);
    if (rc != CKR_OK) {
	testcase_error("C_GetAttributeValue() rc=%s", p11_get_ckr(rc));
	return rc;
    }

    *buf = a_opaque.pValue;
    *buflen = len;

    return CKR_OK;
}

static CK_RV import_cca_des_key(CK_SESSION_HANDLE session,
				const char *label,
				CK_BYTE *ccatoken, CK_ULONG tokenlen,
				CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_DES;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_LABEL, (char *) label, strlen(label) + 1},
	{CKA_ENCRYPT, &true, sizeof(true)},
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_IBM_OPAQUE, ccatoken, tokenlen}
    };
    CK_ULONG nattr = sizeof(template)/sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
	testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_cca_des3_key(CK_SESSION_HANDLE session,
				 const char *label,
				 CK_BYTE *ccatoken, CK_ULONG tokenlen,
				 CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_DES3;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_LABEL, (char *) label, strlen(label) + 1},
	{CKA_ENCRYPT, &true, sizeof(true)},
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_IBM_OPAQUE, ccatoken, tokenlen}
    };
    CK_ULONG nattr = sizeof(template)/sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
	testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_cca_aes_key(CK_SESSION_HANDLE session,
				const char *label,
				CK_BYTE *ccatoken, CK_ULONG tokenlen,
				CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_LABEL, (char *) label, strlen(label) + 1},
	{CKA_ENCRYPT, &true, sizeof(true)},
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_IBM_OPAQUE, ccatoken, tokenlen}
    };
    CK_ULONG nattr = sizeof(template)/sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
	testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

#if CCA_AES_CIPHER_KEY_SUPPORTED
static CK_RV import_cca_aes_cipher_key(CK_SESSION_HANDLE session,
				       const char *label,
				       CK_BYTE *ccatoken, CK_ULONG tokenlen,
				       unsigned int keybitsize,
				       CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_BYTE value[32];
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_LABEL, (char *) label, strlen(label) + 1},
	{CKA_ENCRYPT, &true, sizeof(true)},
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_VALUE, value, sizeof(value)},
	{CKA_IBM_OPAQUE, ccatoken, tokenlen}
    };
    CK_ULONG nattr = sizeof(template)/sizeof(CK_ATTRIBUTE);

    memset(value, 0, sizeof(value));
    template[5].ulValueLen = keybitsize / 8;

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
	testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}
#endif

static CK_RV import_cca_gen_sec_key(CK_SESSION_HANDLE session,
				    const char *label,
				    CK_BYTE *ccatoken, CK_ULONG tokenlen,
				    unsigned int keybitsize,
				    CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_GENERIC_SECRET;
    CK_BYTE value[512];
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_LABEL, (char *) label, strlen(label) + 1},
	{CKA_SIGN, &true, sizeof(true)},
	{CKA_VERIFY, &true, sizeof(true)},
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_VALUE, value, sizeof(value)},
	{CKA_IBM_OPAQUE, ccatoken, tokenlen}
    };
    CK_ULONG nattr = sizeof(template)/sizeof(CK_ATTRIBUTE);
    unsigned pl, calc_pl;

    memset(value, 0, sizeof(value));

    // cca only supports hmac key in range 80...2048
    if (keybitsize < 80 || keybitsize > 2048) {
	testcase_error("invalid keybitsize %u", keybitsize);
	return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    // calculate expected payloadbitsize based on keybitsize
    calc_pl = (((keybitsize + 32) + 63) & (~63)) + 320;
    // pull payloadbitsize from the cca hmac token
    pl = *((uint16_t *)(ccatoken + 38));
    if (calc_pl != pl) {
	testcase_error("mismatch keybitsize %u - expected pl bitsize %u / cca pl bitsize %u",
		       keybitsize, calc_pl, pl);
	return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    template[6].ulValueLen = (keybitsize + 7) / 8;

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
	testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_rsa_priv_key(CK_SESSION_HANDLE session,
				 const char *label,
				 CK_BYTE *ccatoken, CK_ULONG tokenlen,
				 CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_LABEL, (char *) label, strlen(label) + 1},
	{CKA_SIGN, &true, sizeof(true)},
	{CKA_DECRYPT, &true, sizeof(true)},
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_IBM_OPAQUE, ccatoken, tokenlen}
    };
    CK_ULONG nattr = sizeof(template)/sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
	testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_rsa_publ_key(CK_SESSION_HANDLE session,
				 const char *label,
				 CK_BYTE *ccatoken, CK_ULONG tokenlen,
				 CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_LABEL, (char *) label, strlen(label) + 1},
	{CKA_VERIFY, &true, sizeof(true)},
	{CKA_ENCRYPT, &true, sizeof(true)},
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_IBM_OPAQUE, ccatoken, tokenlen}
    };
    CK_ULONG nattr = sizeof(template)/sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
	testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_ecc_priv_key(CK_SESSION_HANDLE session,
				 const char *label,
				 CK_BYTE *ccatoken, CK_ULONG tokenlen,
				 CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_EC;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_LABEL, (char *) label, strlen(label) + 1},
	{CKA_SIGN, &true, sizeof(true)},
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_IBM_OPAQUE, ccatoken, tokenlen}
    };
    CK_ULONG nattr = sizeof(template)/sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
	testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_ecc_publ_key(CK_SESSION_HANDLE session,
				 const char *label,
				 CK_BYTE *ccatoken, CK_ULONG tokenlen,
				 CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_EC;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
	{CKA_CLASS, &keyClass, sizeof(keyClass)},
	{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
	{CKA_LABEL, (char *) label, strlen(label) + 1},
	{CKA_VERIFY, &true, sizeof(true)},
	{CKA_TOKEN, &false, sizeof(false)},
	{CKA_IBM_OPAQUE, ccatoken, tokenlen}
    };
    CK_ULONG nattr = sizeof(template)/sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
	testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV cca_des_data_export_import_tests(void)
{
    const char *tstr = "CCA export/import test with DES data key";
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    CK_BYTE iv[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    CK_MECHANISM mech = { CKM_DES_CBC, iv, sizeof(iv) };
    CK_OBJECT_HANDLE hkey, hikey;
    CK_BYTE data[80], encdata1[80], encdata2[80];
    CK_ULONG ilen, len;
    CK_BYTE *opaquekey = NULL;
    CK_ULONG opaquekeylen;
    char label[80];

    testcase_begin("%s", tstr);

    if (!is_cca_token(SLOT_ID)) {
	testcase_skip("%s: this slot is not a CCA token", tstr);
	goto out;
    }

    testcase_rw_session();
    testcase_user_login();

    // create ock des key

    rc = create_DESKey(session, key, sizeof(key), &hkey);
    if (rc != CKR_OK) {
	testcase_error("create_DESKey() rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }

    // encrypt some data with this key

    rc = funcs->C_EncryptInit(session, &mech, hkey);
    if (rc != CKR_OK) {
	testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }
    ilen = len = sizeof(data);
    rc = funcs->C_Encrypt(session, data, ilen, encdata1, &len);
    if (rc != CKR_OK) {
	testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }
    if (ilen != len) {
	testcase_fail("plain and encrypted data len does not match");
	goto testcase_cleanup;
    }

    testcase_new_assertion();

    // export this key's cca token

    rc = export_ibm_opaque(session, hkey, &opaquekey, &opaquekeylen);
    if (rc != CKR_OK) {
	testcase_fail("export_ibm_opaque rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }

    // re-import this cca token as a new key object

    snprintf(label, sizeof(label), "re-imported_des_key");
    rc = import_cca_des_key(session, label, opaquekey, opaquekeylen, &hikey);
    if (rc != CKR_OK) {
	testcase_fail("import_cca_des_key rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }

    // encrypt same data with this re-imported key

    rc = funcs->C_EncryptInit(session, &mech, hikey);
    if (rc != CKR_OK) {
	testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }
    ilen = len = sizeof(data);
    rc = funcs->C_Encrypt(session, data, ilen, encdata2, &len);
    if (rc != CKR_OK) {
	testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }
    if (ilen != len) {
	testcase_fail("plain and encrypted data len does not match");
	goto testcase_cleanup;
    }

    // and check the encrypted data to be equal

    if (memcmp(encdata1, encdata2, len) != 0) {
	testcase_fail("encrypted data from original and exported/imported key is NOT the same");
	goto testcase_cleanup;
    }

    testcase_pass("%s: ok", tstr);

testcase_cleanup:
    testcase_close_session();
    free(opaquekey);
out:
    return rc;
}

static CK_RV cca_des3_data_export_import_tests(void)
{
    const char *tstr = "CCA export/import test with DES3 data key";
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE key[] = { 0xe9, 0x7c, 0x83, 0x13, 0xba, 0x26, 0x5d, 0x43,
		      0x25, 0x4c, 0xbf, 0x9e, 0x8f, 0x7c, 0x2a, 0xa8,
		      0xa7, 0x54, 0xd6, 0x5e, 0x8a, 0xe9, 0x97, 0xe3 };
    CK_BYTE iv[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    CK_MECHANISM mech = { CKM_DES3_CBC, iv, sizeof(iv) };
    CK_OBJECT_HANDLE hkey, hikey;
    CK_BYTE data[80], encdata1[80], encdata2[80];
    CK_ULONG ilen, len;
    CK_BYTE *opaquekey = NULL;
    CK_ULONG opaquekeylen;
    char label[80];

    testcase_begin("%s", tstr);

    if (!is_cca_token(SLOT_ID)) {
	testcase_skip("%s: this slot is not a CCA token", tstr);
	goto out;
    }

    testcase_rw_session();
    testcase_user_login();

    // create ock 3des key

    rc = create_DES3Key(session, key, sizeof(key), &hkey);
    if (rc != CKR_OK) {
	testcase_error("create_DES3Key() rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }

    // encrypt some data with this key

    rc = funcs->C_EncryptInit(session, &mech, hkey);
    if (rc != CKR_OK) {
	testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }
    ilen = len = sizeof(data);
    rc = funcs->C_Encrypt(session, data, ilen, encdata1, &len);
    if (rc != CKR_OK) {
	testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }
    if (ilen != len) {
	testcase_fail("plain and encrypted data len does not match");
	goto testcase_cleanup;
    }

    testcase_new_assertion();

    // export this key's cca token

    rc = export_ibm_opaque(session, hkey, &opaquekey, &opaquekeylen);
    if (rc != CKR_OK) {
	testcase_fail("export_ibm_opaque rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }

    // re-import this cca token as a new key object

    snprintf(label, sizeof(label), "re-imported_des3_key");
    rc = import_cca_des3_key(session, label, opaquekey, opaquekeylen, &hikey);
    if (rc != CKR_OK) {
	testcase_fail("import_cca_des3_key rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }

    // encrypt same data with this re-imported key

    rc = funcs->C_EncryptInit(session, &mech, hikey);
    if (rc != CKR_OK) {
	testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }
    ilen = len = sizeof(data);
    rc = funcs->C_Encrypt(session, data, ilen, encdata2, &len);
    if (rc != CKR_OK) {
	testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
	goto testcase_cleanup;
    }
    if (ilen != len) {
	testcase_fail("plain and encrypted data len does not match");
	goto testcase_cleanup;
    }

    // and check the encrypted data to be equal

    if (memcmp(encdata1, encdata2, len) != 0) {
	testcase_fail("encrypted data from original and exported/imported key is NOT the same");
	goto testcase_cleanup;
    }

    testcase_pass("%s: ok", tstr);

testcase_cleanup:
    testcase_close_session();
    free(opaquekey);
out:
    return rc;
}

static CK_RV cca_aes_data_export_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
		      0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
		      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
		      0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    CK_BYTE iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    CK_MECHANISM mech = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_OBJECT_HANDLE hkey, hikey;
    CK_BYTE data[160], encdata1[160], encdata2[160];
    CK_ULONG ilen, len;
    CK_BYTE *opaquekey = NULL;
    CK_ULONG opaquekeylen;
    unsigned int keylen;
    char label[80];

    testcase_rw_session();
    testcase_user_login();

    for (keylen = 16; keylen <= 32; keylen += 8) {

	testcase_begin("CCA export/import test with AES%d data key", 8 * keylen);

	if (!is_cca_token(SLOT_ID)) {
	    testcase_skip("this slot is not a CCA token");
	    goto out;
	}

	// create ock aes key

	rc = create_AESKey(session, CK_TRUE, key, keylen, &hkey);
	if (rc != CKR_OK) {
	    testcase_error("create_AESKey() rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// encrypt some data with this key

	rc = funcs->C_EncryptInit(session, &mech, hkey);
	if (rc != CKR_OK) {
	    testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	ilen = len = sizeof(data);
	rc = funcs->C_Encrypt(session, data, ilen, encdata1, &len);
	if (rc != CKR_OK) {
	    testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	if (ilen != len) {
	    testcase_fail("plain and encrypted data len does not match");
	    goto error;
	}

	testcase_new_assertion();

	// export this key's cca token

	rc = export_ibm_opaque(session, hkey, &opaquekey, &opaquekeylen);
	if (rc != CKR_OK) {
	    testcase_fail("export_ibm_opaque rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// re-import this cca token as a new key object

	snprintf(label, sizeof(label), "re-imported_aes%u_key", 8 * keylen);
	rc = import_cca_aes_key(session, label, opaquekey, opaquekeylen, &hikey);
	if (rc != CKR_OK) {
	    testcase_fail("import_cca_aes_key rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// encrypt same data with this re-imported key

	rc = funcs->C_EncryptInit(session, &mech, hikey);
	if (rc != CKR_OK) {
	    testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	ilen = len = sizeof(data);
	rc = funcs->C_Encrypt(session, data, ilen, encdata2, &len);
	if (rc != CKR_OK) {
	    testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	if (ilen != len) {
	    testcase_fail("plain and encrypted data len does not match");
	    goto error;
	}

	// and check the encrypted data to be equal

	if (memcmp(encdata1, encdata2, len) != 0) {
	    testcase_fail("encrypted data from original and exported/imported key is NOT the same");
	    goto error;
	}

	testcase_pass("CCA export/import test with AES%d data key: ok", 8 * keylen);

error:
	free(opaquekey);
	opaquekey = NULL;
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

#if CCA_AES_CIPHER_KEY_SUPPORTED
static CK_RV cca_aes_cipher_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE key[1024] = { 0 };
    CK_BYTE iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    CK_MECHANISM mech = { CKM_AES_CBC, iv, sizeof(iv) };
    CK_OBJECT_HANDLE hkey;;
    CK_BYTE data[160], encdata[160];
    CK_ULONG ilen, len, keylen;
    unsigned int i, keybitlen[] = { 128, 192, 256, 0 };
    char filename[256], label[80];
    FILE *f;

    testcase_rw_session();
    testcase_user_login();

    for (i = 0; keybitlen[i]; i++) {

	testcase_begin("CCA import test with AES%d cipher key", keybitlen[i]);

	if (!is_cca_token(SLOT_ID)) {
	    testcase_skip("this slot is not a CCA token");
	    goto out;
	}

	// Opencryptoki can't create CCA AES cipher keys.
	// So let's read a raw CCA AES cipher key from the pkey sysfs api

	sprintf(filename, "/sys/devices/virtual/misc/pkey/ccacipher/ccacipher_aes_%u", keybitlen[i]);
	f = fopen(filename, "r");
	if (!f) {
	    testcase_error("Can't open file '%s'", filename);
	    goto error;
	}
	keylen = fread(key, 1, sizeof(key), f);
	if (ferror(f) || keylen < 1) {
	    testcase_error("Can't read cipher key from file '%s'", filename);
	    fclose(f);
	    goto error;
	}
	fclose(f);

	testcase_new_assertion();

	// import this key into Opencryptoki as an AES key object :-)

	snprintf(label, sizeof(label), "imported_aes%u_cipher_key", keybitlen[i]);
	rc = import_cca_aes_cipher_key(session, label, key, keylen, keybitlen[i], &hkey);
	if (rc != CKR_OK) {
	    testcase_fail("import_cca_aes_cipher_key rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// encrypt same data with this key just to make sure it is working

	rc = funcs->C_EncryptInit(session, &mech, hkey);
	if (rc != CKR_OK) {
	    testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	ilen = len = sizeof(data);
	rc = funcs->C_Encrypt(session, data, ilen, encdata, &len);
	if (rc != CKR_OK) {
	    testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	if (ilen != len) {
	    testcase_fail("plain and encrypted data len does not match");
	    goto error;
	}

	// that's it here

	testcase_pass("CCA import test with AES%d cipher key: ok", keybitlen[i]);

error:
	;
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}
#endif

static CK_RV cca_hmac_data_export_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE key[512] = { 0x00 };
    CK_OBJECT_HANDLE hkey, hikey;
    CK_MECHANISM mech = { CKM_SHA_1_HMAC, 0, 0 };
    CK_BYTE data[4096], mac1[4096], mac2[4096];
    CK_BYTE *opaquekey = NULL;
    CK_ULONG mac1len, mac2len, opaquekeylen;
    unsigned int i, keybits[] = { 80, 160, 320, 640, 1024, 2048, 0 };
    char label[80];

    testcase_rw_session();
    testcase_user_login();

    for (i = 0; keybits[i]; i++) {

	testcase_begin("CCA export/import test with generic secret key %u", keybits[i]);

	if (!is_cca_token(SLOT_ID)) {
	    testcase_skip("this slot is not a CCA token");
	    goto out;
	}

	// create hmac key

	rc = create_GenericSecretKey(session, key, keybits[i] / 8, &hkey);
	if (rc != CKR_OK) {
	    testcase_error("create_GenericSecretKey() rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// sign data with original hmac key

	rc = funcs->C_SignInit(session, &mech, hkey);
	if (rc != CKR_OK) {
	    testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	mac1len = sizeof(mac1);
	rc = funcs->C_Sign(session, data, sizeof(data), mac1, &mac1len);
	if (rc != CKR_OK) {
	    testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	testcase_new_assertion();

	// export this key's cca token

	rc = export_ibm_opaque(session, hkey, &opaquekey, &opaquekeylen);
	if (rc != CKR_OK) {
	    testcase_fail("export_ibm_opaque rc=%s", p11_get_ckr(rc));
	    goto error;
	}

#if 0
	printf("cca hmac key token (%lu bytes):\n", opaquekeylen);
	print_hex(opaquekey, opaquekeylen);
#endif

	// re-import this cca token as a new key object

	snprintf(label, sizeof(label), "re-imported_hmac%u_key", keybits[i]);
	rc = import_cca_gen_sec_key(session, label,
				    opaquekey, opaquekeylen, keybits[i],
				    &hikey);
	if (rc != CKR_OK) {
	    testcase_fail("import_cca_gen_sec_key rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// sign data with re-imported hmac key

	rc = funcs->C_SignInit(session, &mech, hikey);
	if (rc != CKR_OK) {
	    testcase_error("C_SignInit with re-imported key failed, rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	mac2len = sizeof(mac2);
	rc = funcs->C_Sign(session, data, sizeof(data), mac2, &mac2len);
	if (rc != CKR_OK) {
	    testcase_error("C_Sign with re-imported key failed, rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// compare the two signatures

	if (mac1len != mac2len) {
	    testcase_fail("mac len with orig key %lu differs from mac len with re-imported key %lu",
			  mac1len, mac2len);
	    goto error;
	}
	if (memcmp(mac1, mac2, mac1len) != 0) {
	    testcase_fail("signature with orig key differs from signature with re-imported key");
	    goto error;
	}

	testcase_pass("CCA export/import test with generic secret key %u: ok", keybits[i]);

error:
	free(opaquekey);
	opaquekey = NULL;
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

static CK_RV cca_rsa_export_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 };
    CK_OBJECT_HANDLE publ_key, priv_key;
    CK_OBJECT_HANDLE imp_priv_key, imp_publ_key;
    CK_BYTE msg[512], sig[512];
    CK_ULONG msglen, siglen;
    CK_MECHANISM mech = {CKM_RSA_PKCS, 0, 0};
    unsigned int keybitlen;
    CK_BYTE *priv_opaquekey = NULL, *publ_opaquekey = NULL;
    CK_ULONG priv_opaquekeylen, publ_opaquekeylen;
    char label[80];

    testcase_rw_session();
    testcase_user_login();

    for (keybitlen = 512; keybitlen <= 4096; keybitlen = 2 * keybitlen) {

	testcase_begin("CCA export/import test with RSA %u key", keybitlen);

	if (!is_cca_token(SLOT_ID)) {
	    testcase_skip("this slot is not a CCA token");
	    goto out;
	}

	// create ock rsa keypair

	rc = generate_RSA_PKCS_KeyPair(session, keybitlen,
				       exp, sizeof(exp),
				       &publ_key, &priv_key);
	if (rc != CKR_OK) {
	    testcase_error("generate_RSA_PKCS_KeyPair() rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	testcase_new_assertion();

	// sign with original private key

	rc = funcs->C_SignInit(session, &mech, priv_key);
	if (rc != CKR_OK) {
	    testcase_error("C_SignInit() rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	msglen = (keybitlen / 8) / 2;
	siglen = sizeof(sig);
	rc = funcs->C_Sign(session, msg, msglen, sig, &siglen);
	if (rc != CKR_OK) {
	    testcase_error("C_Sign() rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// verify with original public key

	rc = funcs->C_VerifyInit(session, &mech, publ_key);
	if (rc != CKR_OK) {
	    testcase_error("C_VerifyInit() rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	rc = funcs->C_Verify(session, msg, msglen, sig, siglen);
	if (rc == CKR_OK) {
	    ;
	} else if (rc == CKR_SIGNATURE_INVALID || rc == CKR_SIGNATURE_LEN_RANGE) {
	    testcase_fail("signature verify failed");
	    goto error;
	} else {
	    testcase_error("C_Verify() rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// export original private key's cca token

	rc = export_ibm_opaque(session, priv_key, &priv_opaquekey, &priv_opaquekeylen);
	if (rc != CKR_OK) {
	    testcase_fail("export_ibm_opaque on private key failed rc=%s", p11_get_ckr(rc));
	    goto error;
	}
#if 0
	printf("priv_opaquekey (%lu bytes):\n", priv_opaquekeylen);
	print_hex(priv_opaquekey, priv_opaquekeylen);
#endif

	// re-import this cca private rsa key token as new private rsa key

	snprintf(label, sizeof(label), "re-imported_rsa%u_private_key", keybitlen);
	rc = import_rsa_priv_key(session, label, priv_opaquekey, priv_opaquekeylen, &imp_priv_key);
	if (rc != CKR_OK) {
	    testcase_fail("import_rsa_priv_key on exported cca rsa key token failed rc=%s",
			  p11_get_ckr(rc));
	    goto error;
	}

	// export original public key's cca token

	rc = export_ibm_opaque(session, publ_key, &publ_opaquekey, &publ_opaquekeylen);
	if (rc != CKR_OK) {
	    testcase_fail("export_ibm_opaque on public key failed rc=%s", p11_get_ckr(rc));
	    goto error;
	}
#if 0
	printf("publ_opaquekey (%lu bytes):\n", publ_opaquekeylen);
	print_hex(publ_opaquekey, publ_opaquekeylen);
#endif

	// re-import this cca public rsa key token as new public rsa key

	snprintf(label, sizeof(label), "re-imported_rsa%u_public_key", keybitlen);
	rc = import_rsa_publ_key(session, label, publ_opaquekey, publ_opaquekeylen, &imp_publ_key);
	if (rc != CKR_OK) {
	    testcase_fail("import_rsa_publ_key on exported cca rsa key token failed rc=%s",
			  p11_get_ckr(rc));
	    goto error;
	}

	// sign with re-imported private key

	rc = funcs->C_SignInit(session, &mech, imp_priv_key);
	if (rc != CKR_OK) {
	    testcase_error("C_SignInit() with re-imported priv key failed, rc=%s",
			   p11_get_ckr(rc));
	    goto error;
	}
	siglen = sizeof(sig);
	rc = funcs->C_Sign(session, msg, msglen, sig, &siglen);
	if (rc != CKR_OK) {
	    testcase_error("C_Sign() with re-imported priv key failed, rc=%s",
			   p11_get_ckr(rc));
	    goto error;
	}

	// verify with original public key

	rc = funcs->C_VerifyInit(session, &mech, publ_key);
	if (rc != CKR_OK) {
	    testcase_error("C_VerifyInit() rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	rc = funcs->C_Verify(session, msg, msglen, sig, siglen);
	if (rc == CKR_OK) {
	    ;
	} else if (rc == CKR_SIGNATURE_INVALID || rc == CKR_SIGNATURE_LEN_RANGE) {
	    testcase_fail("signature verify on signature generated with re-imported priv key failed, rc=%s",
			  p11_get_ckr(rc));
	    goto error;
	} else {
	    testcase_error("C_Verify() on signature generated with re-imported priv key failed, rc=%s",
			   p11_get_ckr(rc));
	    goto error;
	}

	// sign with original private key

	rc = funcs->C_SignInit(session, &mech, priv_key);
	if (rc != CKR_OK) {
	    testcase_error("C_SignInit() rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	msglen = (keybitlen / 8) / 2;
	siglen = sizeof(sig);
	rc = funcs->C_Sign(session, msg, msglen, sig, &siglen);
	if (rc != CKR_OK) {
	    testcase_error("C_Sign() rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// verify with re-imported public key

	rc = funcs->C_VerifyInit(session, &mech, imp_publ_key);
	if (rc != CKR_OK) {
	    testcase_error("C_VerifyInit() with re-imported pub key failed, rc=%s",
			   p11_get_ckr(rc));
	    goto error;
	}
	rc = funcs->C_Verify(session, msg, msglen, sig, siglen);
	if (rc == CKR_OK) {
	    ;
	} else if (rc == CKR_SIGNATURE_INVALID || rc == CKR_SIGNATURE_LEN_RANGE) {
	    testcase_fail("signature verify with re-imported pub key on signature failed");
	    goto error;
	} else {
	    testcase_error("C_Verify() with re-imported pub key on signature failed, rc=%s",
			   p11_get_ckr(rc));
	    goto error;
	}

	testcase_pass("CCA export/import test with RSA %u key: ok", keybitlen);

error:
	free(priv_opaquekey);
	priv_opaquekey = NULL;
	free(publ_opaquekey);
	publ_opaquekey = NULL;
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

static CK_BYTE brainpoolP160r1[] = OCK_BRAINPOOL_P160R1;
static CK_BYTE brainpoolP160t1[] = OCK_BRAINPOOL_P160T1;
static CK_BYTE brainpoolP192r1[] = OCK_BRAINPOOL_P192R1;
static CK_BYTE brainpoolP192t1[] = OCK_BRAINPOOL_P192T1;
static CK_BYTE brainpoolP224r1[] = OCK_BRAINPOOL_P224R1;
static CK_BYTE brainpoolP224t1[] = OCK_BRAINPOOL_P224T1;
static CK_BYTE brainpoolP256r1[] = OCK_BRAINPOOL_P256R1;
static CK_BYTE brainpoolP256t1[] = OCK_BRAINPOOL_P256T1;
static CK_BYTE brainpoolP320r1[] = OCK_BRAINPOOL_P320R1;
static CK_BYTE brainpoolP320t1[] = OCK_BRAINPOOL_P320T1;
static CK_BYTE brainpoolP384r1[] = OCK_BRAINPOOL_P384R1;
static CK_BYTE brainpoolP384t1[] = OCK_BRAINPOOL_P384T1;
static CK_BYTE brainpoolP512r1[] = OCK_BRAINPOOL_P512R1;
static CK_BYTE brainpoolP512t1[] = OCK_BRAINPOOL_P512T1;
static CK_BYTE prime192v1[] = OCK_PRIME192V1;
static CK_BYTE secp224r1[] = OCK_SECP224R1;
static CK_BYTE prime256v1[] = OCK_PRIME256V1;
static CK_BYTE secp384r1[] = OCK_SECP384R1;
static CK_BYTE secp521r1[] = OCK_SECP521R1;
static CK_BYTE secp256k1[] = OCK_SECP256K1;
static CK_BYTE curve25519[] = OCK_CURVE25519;
static CK_BYTE curve448[] = OCK_CURVE448;
static CK_BYTE ed25519[] = OCK_ED25519;
static CK_BYTE ed448[] = OCK_ED448;

static struct {
    CK_BYTE *curve;
    CK_ULONG size;
    const char *name;
} ec_curves[] = {
    {brainpoolP160r1, sizeof(brainpoolP160r1), "brainpoolP160r1"},
    {brainpoolP160t1, sizeof(brainpoolP160t1), "brainpoolP160t1"},
    {brainpoolP192r1, sizeof(brainpoolP192r1), "brainpoolP192r1"},
    {brainpoolP192t1, sizeof(brainpoolP192t1), "brainpoolP192t1"},
    {brainpoolP224r1, sizeof(brainpoolP224r1), "brainpoolP224r1"},
    {brainpoolP224t1, sizeof(brainpoolP224t1), "brainpoolP224t1"},
    {brainpoolP256r1, sizeof(brainpoolP256r1), "brainpoolP256r1"},
    {brainpoolP256t1, sizeof(brainpoolP256t1), "brainpoolP256t1"},
    {brainpoolP320r1, sizeof(brainpoolP320r1), "brainpoolP320r1"},
    {brainpoolP320t1, sizeof(brainpoolP320t1), "brainpoolP320t1"},
    {brainpoolP384r1, sizeof(brainpoolP384r1), "brainpoolP384r1"},
    {brainpoolP384t1, sizeof(brainpoolP384t1), "brainpoolP384t1"},
    {brainpoolP512r1, sizeof(brainpoolP512r1), "brainpoolP512r1"},
    {brainpoolP512t1, sizeof(brainpoolP512t1), "brainpoolP512t1"},
    {prime192v1, sizeof(prime192v1), "prime192v1"},
    {secp224r1, sizeof(secp224r1), "secp224r1"},
    {prime256v1, sizeof(prime256v1), "prime256v1"},
    {secp384r1, sizeof(secp384r1), "secp384r1"},
    {secp521r1, sizeof(secp521r1), "secp521r1"},
    {secp256k1, sizeof(secp256k1), "secp256k1"},
    {curve25519, sizeof(curve25519), "curve25519"},
    {curve448, sizeof(curve448), "curve448"},
    {ed25519, sizeof(ed25519), "ed25519"},
    {ed448, sizeof(ed448), "ed448"},
    {0, 0, 0}
};

static CK_RV cca_ecc_export_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_OBJECT_HANDLE publ_key, priv_key;
    CK_OBJECT_HANDLE imp_priv_key, imp_publ_key;
    CK_BYTE msg[32], sig[256];
    CK_ULONG msglen, siglen;
    CK_MECHANISM mech = { CKM_ECDSA, 0, 0};
    CK_BYTE *priv_opaquekey = NULL, *publ_opaquekey = NULL;
    CK_ULONG priv_opaquekeylen, publ_opaquekeylen;
    char label[80];
    int i;

    testcase_rw_session();
    testcase_user_login();

    for (i = 0; ec_curves[i].curve; i++) {

	testcase_begin("CCA export/import test with public/private ECC curve %s keys",
		       ec_curves[i].name);

	if (!is_cca_token(SLOT_ID)) {
	    testcase_skip("this slot is not a CCA token");
	    goto out;
	}

	// create ock ecc keypair

	rc = generate_EC_KeyPair(session,
				 ec_curves[i].curve, ec_curves[i].size,
				 &publ_key, &priv_key);
	if (rc == CKR_CURVE_NOT_SUPPORTED) {
	    testcase_skip("ECC curve %s not supported yet by CCA token", ec_curves[i].name);
	    goto error;
	}
	if (rc != CKR_OK) {
	    testcase_error("generate_EC_KeyPair() rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	testcase_new_assertion();

	// sign with original private key

	rc = funcs->C_SignInit(session, &mech, priv_key);
	if (rc != CKR_OK) {
	    testcase_error("C_SignInit() rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	msglen = sizeof(msg);
	siglen = sizeof(sig);
	rc = funcs->C_Sign(session, msg, msglen, sig, &siglen);
	if (rc != CKR_OK) {
	    testcase_error("C_Sign() rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// verify with original public key

	rc = funcs->C_VerifyInit(session, &mech, publ_key);
	if (rc != CKR_OK) {
	    testcase_error("C_VerifyInit() rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	rc = funcs->C_Verify(session, msg, msglen, sig, siglen);
	if (rc == CKR_OK) {
	    ;
	} else if (rc == CKR_SIGNATURE_INVALID || rc == CKR_SIGNATURE_LEN_RANGE) {
	    testcase_fail("signature verify failed");
	    goto error;
	} else {
	    testcase_error("C_Verify() rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// export original private key's cca token

	rc = export_ibm_opaque(session, priv_key, &priv_opaquekey, &priv_opaquekeylen);
	if (rc != CKR_OK) {
	    testcase_fail("export_ibm_opaque on private key failed rc=%s", p11_get_ckr(rc));
	    goto error;
	}
#if 0
	printf("priv_opaquekey (%lu bytes):\n", priv_opaquekeylen);
	print_hex(priv_opaquekey, priv_opaquekeylen);
#endif

	// re-import this cca private ecc key token as new private ecc key

	snprintf(label, sizeof(label), "re-imported_ecc_%s_private_key", ec_curves[i].name);
	rc = import_ecc_priv_key(session, label, priv_opaquekey, priv_opaquekeylen, &imp_priv_key);
	if (rc != CKR_OK) {
	    testcase_fail("import_ecc_priv_key on exported cca ecc key token failed rc=%s",
			  p11_get_ckr(rc));
	    goto error;
	}

	// export original public key's cca token

	rc = export_ibm_opaque(session, publ_key, &publ_opaquekey, &publ_opaquekeylen);
	if (rc != CKR_OK) {
	    testcase_fail("export_ibm_opaque on public key failed rc=%s", p11_get_ckr(rc));
	    goto error;
	}
#if 0
	printf("publ_opaquekey (%lu bytes):\n", publ_opaquekeylen);
	print_hex(publ_opaquekey, publ_opaquekeylen);
#endif

	// re-import this cca public ecc key token as new public ecc key

	snprintf(label, sizeof(label), "re-imported_ecc_%s_public_key", ec_curves[i].name);
	rc = import_ecc_publ_key(session, label, publ_opaquekey, publ_opaquekeylen, &imp_publ_key);
	if (rc != CKR_OK) {
	    testcase_fail("import_ecc_publ_key on exported cca ecc key token failed rc=%s",
			  p11_get_ckr(rc));
	    goto error;
	}

	// sign with re-imported private key

	rc = funcs->C_SignInit(session, &mech, imp_priv_key);
	if (rc != CKR_OK) {
	    testcase_error("C_SignInit() with re-imported priv key failed, rc=%s",
			   p11_get_ckr(rc));
	    goto error;
	}
	msglen = sizeof(msg);
	siglen = sizeof(sig);
	rc = funcs->C_Sign(session, msg, msglen, sig, &siglen);
	if (rc != CKR_OK) {
	    testcase_error("C_Sign() with re-imported priv key failed, rc=%s",
			   p11_get_ckr(rc));
	    goto error;
	}

	// verify with original public key

	rc = funcs->C_VerifyInit(session, &mech, publ_key);
	if (rc != CKR_OK) {
	    testcase_error("C_VerifyInit() rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	rc = funcs->C_Verify(session, msg, msglen, sig, siglen);
	if (rc == CKR_OK) {
	    ;
	} else if (rc == CKR_SIGNATURE_INVALID || rc == CKR_SIGNATURE_LEN_RANGE) {
	    testcase_fail("signature verify on signature generated with re-imported priv key failed, rc=%s",
			  p11_get_ckr(rc));
	    goto error;
	} else {
	    testcase_error("C_Verify() on signature generated with re-imported priv key failed, rc=%s",
			   p11_get_ckr(rc));
	    goto error;
	}

	// sign with original private key

	rc = funcs->C_SignInit(session, &mech, priv_key);
	if (rc != CKR_OK) {
	    testcase_error("C_SignInit() rc=%s", p11_get_ckr(rc));
	    goto error;
	}
	msglen = sizeof(msg);
	siglen = sizeof(sig);
	rc = funcs->C_Sign(session, msg, msglen, sig, &siglen);
	if (rc != CKR_OK) {
	    testcase_error("C_Sign() rc=%s", p11_get_ckr(rc));
	    goto error;
	}

	// verify with re-imported public key

	rc = funcs->C_VerifyInit(session, &mech, imp_publ_key);
	if (rc != CKR_OK) {
	    testcase_error("C_VerifyInit() with re-imported pub key failed, rc=%s",
			   p11_get_ckr(rc));
	    goto error;
	}
	rc = funcs->C_Verify(session, msg, msglen, sig, siglen);
	if (rc == CKR_OK) {
	    ;
	} else if (rc == CKR_SIGNATURE_INVALID || rc == CKR_SIGNATURE_LEN_RANGE) {
	    testcase_fail("signature verify with re-imported pub key on signature failed");
	    goto error;
	} else {
	    testcase_error("C_Verify() with re-imported pub key on signature failed, rc=%s",
			   p11_get_ckr(rc));
	    goto error;
	}

	testcase_pass("CCA export/import test with public/private ECC curve %s keys: ok",
		      ec_curves[i].name);

error:
	free(priv_opaquekey);
	priv_opaquekey = NULL;
	free(publ_opaquekey);
	publ_opaquekey = NULL;
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

static CK_RV cca_export_import_tests(void)
{
    CK_RV rc = CKR_OK, rv = CKR_OK;

    testsuite_begin("CCA export/import tests");

    rc = cca_des_data_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
	rv = rc;

    rc = cca_des3_data_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
	rv = rc;

    rc = cca_aes_data_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
	rv = rc;

    rc = cca_hmac_data_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
	rv = rc;

    rc = cca_rsa_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
	rv = rc;

    rc = cca_ecc_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
	rv = rc;

#if CCA_AES_CIPHER_KEY_SUPPORTED
    rc = cca_aes_cipher_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
	rv = rc;
#endif

    return rv;
}

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int rc;
    CK_RV rv;

    rc = do_ParseArgs(argc, argv);
    if (rc != 1)
	return rc;

    printf("Using slot #%lu...\n", SLOT_ID);

    rc = do_GetFunctionList();
    if (!rc) {
	testcase_error("do_getFunctionList(), rc=%s", p11_get_ckr(rc));
	return rc;
    }

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    // SAB Add calls to ALL functions before the C_Initialize gets hit

    funcs->C_Initialize(&cinit_args);

    {
	CK_SESSION_HANDLE hsess = 0;

	rc = funcs->C_GetFunctionStatus(hsess);
	if (rc != CKR_FUNCTION_NOT_PARALLEL)
	    return rc;

	rc = funcs->C_CancelFunction(hsess);
	if (rc != CKR_FUNCTION_NOT_PARALLEL)
	    return rc;

    }

    testcase_setup(0);
    rv = cca_export_import_tests();
    testcase_print_result();

    funcs->C_Finalize(NULL);

    /* make sure we return non-zero if rv is non-zero */
    return ((rv == 0) || (rv % 256) ? (int)rv : -1);
}
