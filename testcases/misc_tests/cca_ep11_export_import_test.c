/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can
 * be found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 *
 * import/export test for the CCA and EP11 token
 * by Harald Freudenberger <freude@de.ibm.com>
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <stdint.h>

#include "platform.h"
#include "pkcs11types.h"
#include "ec_curves.h"
#include "mechtable.h"
#include "mech_to_str.h"

#include "regress.h"
#include "common.c"

/** Create an AES key handle with given value **/
CK_RV create_cca_ep11_AESKey(CK_SESSION_HANDLE session, CK_BBOOL extractable,
                             unsigned char key[], unsigned char key_len,
                             CK_KEY_TYPE keyType, CK_IBM_CCA_AES_KEY_MODE_TYPE mode,
                             CK_OBJECT_HANDLE * h_key, int is_cca)
{
    CK_RV rc;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL pkeyextractable = !extractable;
    CK_ATTRIBUTE keyTemplate[] = {
        {CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_VALUE, key, key_len},
        {CKA_IBM_PROTKEY_EXTRACTABLE, &pkeyextractable, sizeof(CK_BBOOL)},
        {CKA_IBM_CCA_AES_KEY_MODE, &mode, sizeof(mode)},
    };
    CK_ULONG keyTemplate_len = sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE);

    if (!is_cca)
        keyTemplate_len--;

    if (combined_extract)
        pkeyextractable = CK_TRUE;

    rc = funcs->C_CreateObject(session, keyTemplate, keyTemplate_len, h_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session))
            rc = CKR_POLICY_VIOLATION;
        else
            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV extract_restrict(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE handle)
{
    CK_RV rc;
    CK_BBOOL ck_false = FALSE;
    CK_ATTRIBUTE a_extract = { CKA_EXTRACTABLE, &ck_false, sizeof(ck_false) };

    rc = funcs->C_SetAttributeValue(session, handle, &a_extract, 1);
    if (rc != CKR_OK) {
        testcase_error("C_SetAttributeValue() rc=%s", p11_get_ckr(rc));
        return rc;
    }

    return CKR_OK;
}

static CK_RV convert_to_cipher_key(CK_SESSION_HANDLE session,
                                   CK_OBJECT_HANDLE handle)
{
    CK_RV rc;
    CK_IBM_CCA_AES_KEY_MODE_TYPE mode = CK_IBM_CCA_AES_CIPHER_KEY;
    CK_ATTRIBUTE a_extract = { CKA_IBM_CCA_AES_KEY_MODE, &mode, sizeof(mode) };

    rc = funcs->C_SetAttributeValue(session, handle, &a_extract, 1);
    if (rc != CKR_OK) {
        testcase_error("C_SetAttributeValue() rc=%s", p11_get_ckr(rc));
        return rc;
    }

    return CKR_OK;
}

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

static CK_RV import_des_key(CK_SESSION_HANDLE session,
                            const char *label,
                            CK_BYTE *blob, CK_ULONG bloblen,
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
        {CKA_IBM_OPAQUE, blob, bloblen}
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_des3_key(CK_SESSION_HANDLE session,
                             const char *label,
                             CK_BYTE *blob, CK_ULONG bloblen,
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
        {CKA_IBM_OPAQUE, blob, bloblen}
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_aes_key(CK_SESSION_HANDLE session,
                            const char *label,
                            CK_BYTE *blob, CK_ULONG bloblen,
                            CK_OBJECT_HANDLE *handle,
                            CK_KEY_TYPE keyType,
                            CK_IBM_CCA_AES_KEY_MODE_TYPE exp_mode,
                            int is_cca)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (char *) label, strlen(label) + 1},
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_IBM_OPAQUE, blob, bloblen},
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);
    CK_IBM_CCA_AES_KEY_MODE_TYPE mode;
    CK_ATTRIBUTE a_mode = { CKA_IBM_CCA_AES_KEY_MODE, &mode, sizeof(mode) };

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
        goto out;
    }

    if (is_cca) {
        rc = funcs->C_GetAttributeValue(session, *handle, &a_mode, 1);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue() rc=%s", p11_get_ckr(rc));
            goto out;
        }

        if (mode != exp_mode) {
            testcase_error("CCA key mode not as expected (%lu != %lu)",
                           mode, exp_mode);
            rc = CKR_ATTRIBUTE_VALUE_INVALID;
            goto out;
        }
    }

out:
    return rc;
}

static CK_RV import_gen_sec_key(CK_SESSION_HANDLE session,
                                const char *label, CK_KEY_TYPE keyType,
                                CK_BYTE *blob, CK_ULONG bloblen,
                                unsigned int keybitsize,
                                CK_OBJECT_HANDLE *handle,
                                int is_cca)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
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
        {CKA_IBM_OPAQUE, blob, bloblen},
        {CKA_VALUE, value, sizeof(value)},
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);
    unsigned pl, calc_pl;

    memset(value, 0, sizeof(value));

    // CCA/EP11 only supports hmac key in range 80...2048
    if (keybitsize < 80 || keybitsize > 2048) {
        testcase_error("invalid keybitsize %u", keybitsize);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (is_cca) {
        // calculate expected payloadbitsize based on keybitsize
        calc_pl = (((keybitsize + 32) + 63) & (~63)) + 320;
        // pull payloadbitsize from the cca hmac blob
        pl = be16toh(*((uint16_t *)(blob + 38)));
        if (calc_pl != pl) {
            testcase_error("mismatch keybitsize %u - expected pl bitsize %u / cca pl bitsize %u",
                           keybitsize, calc_pl, pl);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        template[7].ulValueLen = (keybitsize + 7) / 8;
    } else {
        nattr--;
    }

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_rsa_priv_key(CK_SESSION_HANDLE session,
                                 const char *label,
                                 CK_BYTE *blob, CK_ULONG bloblen,
                                 CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (char *) label, strlen(label) + 1},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_IBM_OPAQUE, blob, bloblen}
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK && rc != CKR_PUBLIC_KEY_INVALID) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_rsa_publ_key(CK_SESSION_HANDLE session,
                                 const char *label,
                                 CK_BYTE *blob, CK_ULONG bloblen,
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
        {CKA_PRIVATE, &false, sizeof(false)},
        {CKA_IBM_OPAQUE, blob, bloblen}
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK && rc != CKR_PUBLIC_KEY_INVALID) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_ecc_priv_key(CK_SESSION_HANDLE session,
                                 CK_KEY_TYPE keyType,const char *label,
                                 CK_BYTE *blob, CK_ULONG bloblen,
                                 CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (char *) label, strlen(label) + 1},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_IBM_OPAQUE, blob, bloblen}
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK && rc != CKR_PUBLIC_KEY_INVALID) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_ecc_publ_key(CK_SESSION_HANDLE session,
                                 CK_KEY_TYPE keyType, const char *label,
                                 CK_BYTE *blob, CK_ULONG bloblen,
                                 CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (char *) label, strlen(label) + 1},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_PRIVATE, &false, sizeof(false)},
        {CKA_IBM_OPAQUE, blob, bloblen}
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK && rc != CKR_PUBLIC_KEY_INVALID) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_ibm_ml_dsa_priv_key(CK_SESSION_HANDLE session,
                                        CK_KEY_TYPE keyType,
                                        const char *label,
                                        CK_BYTE *blob, CK_ULONG bloblen,
                                        CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (char *) label, strlen(label) + 1},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_IBM_OPAQUE, blob, bloblen}
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK && rc != CKR_PUBLIC_KEY_INVALID) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_ibm_ml_dsa_publ_key(CK_SESSION_HANDLE session,
                                        CK_KEY_TYPE keyType,
                                        const char *label,
                                        CK_BYTE *blob, CK_ULONG bloblen,
                                        CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (char *) label, strlen(label) + 1},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_PRIVATE, &false, sizeof(false)},
        {CKA_IBM_OPAQUE, blob, bloblen}
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK && rc != CKR_PUBLIC_KEY_INVALID) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_ibm_ml_kem_priv_key(CK_SESSION_HANDLE session,
                                        CK_KEY_TYPE keyType,
                                        const char *label,
                                        CK_BYTE *blob, CK_ULONG bloblen,
                                        CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PRIVATE_KEY;
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (char *) label, strlen(label) + 1},
        {CKA_DERIVE, &true, sizeof(true)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_IBM_OPAQUE, blob, bloblen}
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK && rc != CKR_PUBLIC_KEY_INVALID) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV import_ibm_ml_kem_publ_key(CK_SESSION_HANDLE session,
                                        CK_KEY_TYPE keyType,
                                        const char *label,
                                        CK_BYTE *blob, CK_ULONG bloblen,
                                        CK_OBJECT_HANDLE *handle)
{
    CK_RV rc;
    CK_OBJECT_CLASS keyClass = CKO_PUBLIC_KEY;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &keyClass, sizeof(keyClass)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_LABEL, (char *) label, strlen(label) + 1},
        {CKA_DERIVE, &true, sizeof(true)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_PRIVATE, &false, sizeof(false)},
        {CKA_IBM_OPAQUE, blob, bloblen}
    };
    CK_ULONG nattr = sizeof(template) / sizeof(CK_ATTRIBUTE);

    rc = funcs->C_CreateObject(session, template, nattr, handle);
    if (rc != CKR_OK && rc != CKR_PUBLIC_KEY_INVALID) {
        testcase_error("C_CreateObject() rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static CK_RV des_export_import_tests(void)
{
    const char *tstr = "CCA/EP11 export/import test with DES key";
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE key[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };
    CK_BYTE iv[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    CK_MECHANISM mech = { CKM_DES_CBC, iv, sizeof(iv) };
    CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE, hikey = CK_INVALID_HANDLE;
    CK_BYTE data[80], encdata1[80], encdata2[80];
    CK_ULONG ilen, len;
    CK_BYTE *opaquekey = NULL;
    CK_ULONG opaquekeylen;
    char label[80];

    testcase_begin("%s", tstr);

    if (!is_cca_token(SLOT_ID) && !is_ep11_token(SLOT_ID)) {
        testcase_skip("%s: this slot is not a CCA or EP11 token", tstr);
        goto out;
    }
    if (!mech_supported(SLOT_ID, CKM_DES_KEY_GEN)) {
        testcase_skip("this slot does not support CKM_DES_KEY_GEN");
        goto out;
    }

    testcase_rw_session();
    testcase_user_login();

    // create ock des key

    rc = create_DESKey(session, key, sizeof(key), &hkey);
    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("DES key generation is not allowed by policy");
            goto testcase_cleanup;
        }

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

    // export this key's CCA/EP11 blob

    rc = export_ibm_opaque(session, hkey, &opaquekey, &opaquekeylen);
    if (rc != CKR_OK) {
        testcase_fail("export_ibm_opaque rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    // re-import this CCA/EP11 blob as a new key object

    snprintf(label, sizeof(label), "re-imported_des_key");
    rc = import_des_key(session, label, opaquekey, opaquekeylen, &hikey);
    if (rc != CKR_OK) {
        testcase_fail("import_des_key rc=%s", p11_get_ckr(rc));
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
    if (hkey != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, hkey);
    if (hikey != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, hikey);
    testcase_close_session();
    free(opaquekey);
out:
    return rc;
}

static CK_RV des3_export_import_tests(void)
{
    const char *tstr = "CCA/EP11 export/import test with DES3 data key";
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
    CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE, hikey = CK_INVALID_HANDLE;
    CK_BYTE data[80], encdata1[80], encdata2[80];
    CK_ULONG ilen, len;
    CK_BYTE *opaquekey = NULL;
    CK_ULONG opaquekeylen;
    char label[80];

    testcase_begin("%s", tstr);

    if (!is_cca_token(SLOT_ID) && !is_ep11_token(SLOT_ID)) {
        testcase_skip("%s: this slot is not a CCA or EP11 token", tstr);
        goto out;
    }
    if (!mech_supported(SLOT_ID, CKM_DES3_KEY_GEN)) {
        testcase_skip("this slot does not support CKM_DES3_KEY_GEN");
        goto out;
    }

    testcase_rw_session();
    testcase_user_login();

    // create ock 3des key

    rc = create_DES3Key(session, key, sizeof(key), &hkey);
    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("DES3 key generation is not allowed by policy");
            goto testcase_cleanup;
        }

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

    // export this key's CCA/EP11 blob

    rc = export_ibm_opaque(session, hkey, &opaquekey, &opaquekeylen);
    if (rc != CKR_OK) {
        testcase_fail("export_ibm_opaque rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    // re-import this CCA/EP11 blob as a new key object

    snprintf(label, sizeof(label), "re-imported_des3_key");
    rc = import_des3_key(session, label, opaquekey, opaquekeylen, &hikey);
    if (rc != CKR_OK) {
        testcase_fail("import_des3_key rc=%s", p11_get_ckr(rc));
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
    if (hkey != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, hkey);
    if (hikey != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, hikey);
    testcase_close_session();
    free(opaquekey);
out:
    return rc;
}

static CK_RV aes_export_import_tests(CK_IBM_CCA_AES_KEY_MODE_TYPE mode)
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
    CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE, hikey = CK_INVALID_HANDLE;
    CK_BYTE data[160], encdata1[160], encdata2[160], encdata3[160];;
    CK_ULONG ilen, len;
    CK_BYTE *opaquekey = NULL;
    CK_ULONG opaquekeylen;
    unsigned int keylen;
    char label[80];
    int is_cca = is_cca_token(SLOT_ID);

    if (!is_cca && !is_ep11_token(SLOT_ID)) {
        testcase_skip("this slot is not a CCA or EP11 token");
        goto out;
    }
    if (!mech_supported(SLOT_ID, CKM_AES_KEY_GEN)) {
        testcase_skip("this slot does not support CKM_AES_KEY_GEN");
        goto out;
    }

    if (!is_cca && mode != CK_IBM_CCA_AES_DATA_KEY)
        goto out;

    testcase_rw_session();
    testcase_user_login();

    for (keylen = 16; keylen <= 32; keylen += 8) {

        testcase_begin("CCA/EP11 export/import test with AES-%u %s key",
                       8 * keylen,
                       is_cca ?
                          (mode == CK_IBM_CCA_AES_DATA_KEY ? "DATA" : "CIPHER") :
                          "EP11");

        // create ock aes key

        rc = create_cca_ep11_AESKey(session, CK_TRUE, key, keylen, CKK_AES, mode,
                                    &hkey, is_cca);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key generation is not allowed by policy");
                continue;
            }

            testcase_error("create_cca_ep11_AESKey() rc=%s", p11_get_ckr(rc));
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

        // export this key's CCA/EP11 blob

        rc = export_ibm_opaque(session, hkey, &opaquekey, &opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 blob as a new key object

        snprintf(label, sizeof(label), "re-imported_aes%u_key", 8 * keylen);
        rc = import_aes_key(session, label, opaquekey, opaquekeylen, &hikey,
                            CKK_AES, mode, is_cca);
        if (rc != CKR_OK) {
            testcase_fail("import_aes_key rc=%s", p11_get_ckr(rc));
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


        if (is_cca) {
            /* Set extractable to FALSE on original key */
            rc = extract_restrict(session, hkey);
            if (rc != CKR_OK) {
                testcase_fail("extract_restrict rc=%s", p11_get_ckr(rc));
                goto error;
            }

            /* Convert to CIPHER key */
            rc = convert_to_cipher_key(session, hkey);
            if (rc != CKR_OK) {
                testcase_fail("convert_to_cipher_key rc=%s", p11_get_ckr(rc));
                goto error;
            }

            /* encrypt some data with this converted key */

            rc = funcs->C_EncryptInit(session, &mech, hkey);
            if (rc != CKR_OK) {
                testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
                goto error;
            }
            ilen = len = sizeof(data);
            rc = funcs->C_Encrypt(session, data, ilen, encdata3, &len);
            if (rc != CKR_OK) {
                testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
                goto error;
            }
            if (ilen != len) {
                testcase_fail("plain and encrypted data len does not match");
                goto error;
            }

            /* and check the encrypted data to be equal */

            if (memcmp(encdata1, encdata3, len) != 0) {
                testcase_fail("encrypted data from original and converted key is NOT the same");
                goto error;
            }
        }

        testcase_pass("CCA/EP11 export/import test with AES-%u %s key: ok",
                      8 * keylen,
                      is_cca ?
                           (mode == CK_IBM_CCA_AES_DATA_KEY ? "DATA" : "CIPHER") :
                           "EP11");

error:
        free(opaquekey);
        opaquekey = NULL;
        if (hkey != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, hkey);
            hkey = CK_INVALID_HANDLE;
        }
        if (hikey != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, hikey);
            hikey = CK_INVALID_HANDLE;
        }
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

static CK_RV aes_xts_export_import_tests(CK_IBM_CCA_AES_KEY_MODE_TYPE mode)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE key[] = { 0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                      0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                      0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4,
                      0x61, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                      0x2c, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                      0x1e, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                      0x2e, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };
    CK_BYTE iv[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    CK_MECHANISM mech = { CKM_AES_XTS, iv, sizeof(iv) };
    CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE, hikey = CK_INVALID_HANDLE;
    CK_BYTE data[160], encdata1[160], encdata2[160], encdata3[160];;
    CK_ULONG ilen, len;
    CK_BYTE *opaquekey = NULL;
    CK_ULONG opaquekeylen;
    unsigned int keylen;
    char label[80];
    int is_cca = is_cca_token(SLOT_ID);

    if (!is_cca && !is_ep11_token(SLOT_ID)) {
        testcase_skip("this slot is not a CCA or EP11 token");
        goto out;
    }
    if (!mech_supported(SLOT_ID, CKM_AES_XTS_KEY_GEN)) {
       testcase_skip("this slot does not support AES-XTS");
        goto out;
    }

    if (!is_cca && mode != CK_IBM_CCA_AES_DATA_KEY)
        goto out;

    testcase_rw_session();
    testcase_user_login();

    for (keylen = 32; keylen <= 64; keylen += 32) {

        testcase_begin("CCA export/import test with AES-XTS-%u %s key",
                       8 * keylen / 2,
                       is_cca ?
                            (mode == CK_IBM_CCA_AES_DATA_KEY ? "DATA" : "CIPHER") :
                            "EP11");

        // create ock aes key

        rc = create_cca_ep11_AESKey(session, CK_FALSE, key, keylen, CKK_AES_XTS,
                                    mode, &hkey, is_cca);
        if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("AES-XTS key generation is not allowed by policy");
            continue;
        }

            testcase_error("create_cca_ep11_AESKey() rc=%s", p11_get_ckr(rc));
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

        // export this key's CCA/EP11 blob

        rc = export_ibm_opaque(session, hkey, &opaquekey, &opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 blob as a new key object

        snprintf(label, sizeof(label), "re-imported_aes-xts-%u_key",
                 8 * keylen / 8);
        rc = import_aes_key(session, label, opaquekey, opaquekeylen, &hikey,
                            CKK_AES_XTS, mode, is_cca);
        if (rc != CKR_OK) {
            testcase_fail("import_aes_key rc=%s", p11_get_ckr(rc));
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

        if (is_cca) {
            /* Set extractable to FALSE on original key */
            rc = extract_restrict(session, hkey);
            if (rc != CKR_OK) {
                testcase_fail("extract_restrict rc=%s", p11_get_ckr(rc));
                goto error;
            }

            /* Convert to CIPHER key */
            rc = convert_to_cipher_key(session, hkey);
            if (rc != CKR_OK) {
                testcase_fail("extract_restrict rc=%s", p11_get_ckr(rc));
                goto error;
            }

            /* encrypt some data with this converted key */

            rc = funcs->C_EncryptInit(session, &mech, hkey);
            if (rc != CKR_OK) {
                testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
                goto error;
            }
            ilen = len = sizeof(data);
            rc = funcs->C_Encrypt(session, data, ilen, encdata3, &len);
            if (rc != CKR_OK) {
                testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
                goto error;
            }
            if (ilen != len) {
                testcase_fail("plain and encrypted data len does not match");
                goto error;
            }

            /* and check the encrypted data to be equal */

            if (memcmp(encdata1, encdata3, len) != 0) {
                testcase_fail("encrypted data from original and converted key is NOT the same");
                goto error;
            }
        }

        testcase_pass("CCA/EP11 export/import test with AES-XTS-%u %s key: ok",
                      8 * keylen / 2,
                      is_cca ?
                          (mode == CK_IBM_CCA_AES_DATA_KEY ? "DATA" : "CIPHER") :
                          "EP11");

error:
        free(opaquekey);
        opaquekey = NULL;
        if (hkey != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, hkey);
            hkey = CK_INVALID_HANDLE;
        }
        if (hikey != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, hikey);
            hikey = CK_INVALID_HANDLE;
        }
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

static CK_RV generic_secret_export_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE key[512] = { 0x00 };
    CK_OBJECT_HANDLE hkey = CK_INVALID_HANDLE, hikey = CK_INVALID_HANDLE;
    CK_BYTE data[4096], mac1[4096], mac2[4096];
    CK_BYTE *opaquekey = NULL;
    CK_ULONG mac1len, mac2len, opaquekeylen;
    unsigned int i, k, keybits[] = { 80, 160, 320, 640, 1024, 2048, 0 };
    char label[80];
    int is_cca = is_cca_token(SLOT_ID);

    static struct hmac_mech_info {
        const char *name;
        CK_KEY_TYPE keytype;
        CK_MECHANISM_TYPE keygen_mech;
        CK_ULONG min_key_size;
        CK_MECHANISM hmac_mech;
    } hmac_mechs[] = {
        { "generic secret", CKK_GENERIC_SECRET, CKM_GENERIC_SECRET_KEY_GEN, 20,
          { CKM_SHA_1_HMAC, 0, 0 } },
        { "sha-1-hmac",     CKK_SHA_1_HMAC,     CKM_SHA_1_KEY_GEN, 20,
          { CKM_SHA_1_HMAC, 0, 0 } },
        { "sha256-hmac",     CKK_SHA256_HMAC,   CKM_SHA256_KEY_GEN, 32,
          { CKM_SHA256_HMAC, 0, 0 } },
        { "sha3-256-hmac",   CKK_SHA3_256_HMAC, CKM_SHA3_256_KEY_GEN, 32,
          { CKM_SHA3_256_HMAC, 0, 0 } },
    };

    if (!is_cca && !is_ep11_token(SLOT_ID)) {
        testcase_skip("this slot is not a CCA or EP11 token");
        goto out;
    }

    testcase_rw_session();
    testcase_user_login();

    for (k = 0; k < sizeof(hmac_mechs) / sizeof(struct hmac_mech_info); k++) {
        for (i = 0; keybits[i]; i++) {

            if (keybits[i] < hmac_mechs[k].min_key_size * 8)
                continue;

            if (!mech_supported(SLOT_ID, hmac_mechs[k].hmac_mech.mechanism)) {
                testcase_skip("this slot does not support %s",
                              mech_to_str(hmac_mechs[k].hmac_mech.mechanism));
                continue;
            }
            if (!mech_supported(SLOT_ID, hmac_mechs[k].keygen_mech)) {
                testcase_skip("this slot does not support %s",
                              mech_to_str(hmac_mechs[k].keygen_mech));
                continue;
            }

            testcase_begin("CCA/EP11 export/import test with %s key %u",
                           hmac_mechs[k].name, keybits[i]);

            // create hmac key

            rc = create_GenericSecretKey(session, hmac_mechs[k].keytype,
                                         key, keybits[i] / 8, &hkey);
            if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("%s key import is not allowed by policy",
                              hmac_mechs[k].name);
                continue;
            }

                testcase_error("create_GenericSecretKey() rc=%s",
                               p11_get_ckr(rc));
                goto error;
            }

            // sign data with original hmac key

            rc = funcs->C_SignInit(session, &hmac_mechs[k].hmac_mech, hkey);
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

            // export this key's CCA/EP11 blob

            rc = export_ibm_opaque(session, hkey, &opaquekey, &opaquekeylen);
            if (rc != CKR_OK) {
                testcase_fail("export_ibm_opaque rc=%s", p11_get_ckr(rc));
                goto error;
            }

            if (is_cca) {
                /* Set extractable to FALSE */
                rc = extract_restrict(session, hkey);
                if (rc != CKR_OK) {
                    testcase_fail("extract_restrict rc=%s", p11_get_ckr(rc));
                    goto error;
                }
            }

            // re-import this CCA/EP11 blob as a new key object

            snprintf(label, sizeof(label), "re-imported_hmac%u_key",
                     keybits[i]);
            rc = import_gen_sec_key(session, label, hmac_mechs[k].keytype,
                                    opaquekey, opaquekeylen, keybits[i],
                                    &hikey, is_cca);
            if (rc != CKR_OK) {
                testcase_fail("import_gen_sec_key rc=%s", p11_get_ckr(rc));
                goto error;
            }

            // sign data with re-imported hmac key

            rc = funcs->C_SignInit(session, &hmac_mechs[k].hmac_mech, hikey);
            if (rc != CKR_OK) {
                testcase_error("C_SignInit with re-imported key failed, rc=%s",
                               p11_get_ckr(rc));
                goto error;
            }
            mac2len = sizeof(mac2);
            rc = funcs->C_Sign(session, data, sizeof(data), mac2, &mac2len);
            if (rc != CKR_OK) {
                testcase_error("C_Sign with re-imported key failed, rc=%s",
                               p11_get_ckr(rc));
                goto error;
            }

            // compare the two signatures

            if (mac1len != mac2len) {
                testcase_fail("mac len with orig key %lu differs from mac len "
                              "with re-imported key %lu", mac1len, mac2len);
                goto error;
            }
            if (memcmp(mac1, mac2, mac1len) != 0) {
                testcase_fail("signature with orig key differs from signature "
                              "with re-imported key");
                goto error;
            }

            testcase_pass("CCA/EP11 export/import test with %st key %u: ok",
                          hmac_mechs[k].name, keybits[i]);

error:
            free(opaquekey);
            opaquekey = NULL;
            if (hkey != CK_INVALID_HANDLE) {
                funcs->C_DestroyObject(session, hkey);
                hkey = CK_INVALID_HANDLE;
            }
            if (hikey != CK_INVALID_HANDLE) {
                funcs->C_DestroyObject(session, hikey);
                hikey = CK_INVALID_HANDLE;
            }
        }
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

static CK_RV rsa_export_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE exp[] = { 0x01, 0x00, 0x01 };
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE imp_priv_key = CK_INVALID_HANDLE, imp_publ_key = CK_INVALID_HANDLE;
    CK_BYTE msg[1024], sig[1024];
    CK_ULONG msglen, siglen;
    CK_MECHANISM mech = {CKM_RSA_PKCS, 0, 0};
    unsigned int keybitlen;
    CK_BYTE *priv_opaquekey = NULL, *publ_opaquekey = NULL;
    CK_ULONG priv_opaquekeylen, publ_opaquekeylen;
    char label[80];

    if (!is_cca_token(SLOT_ID) && !is_ep11_token(SLOT_ID)) {
        testcase_skip("this slot is not a CCA or EP11 token");
        goto out;
    }
    if (!mech_supported(SLOT_ID, CKM_RSA_PKCS_KEY_PAIR_GEN)) {
            testcase_skip("this slot does not support CKM_RSA_PKCS_KEY_PAIR_GEN");
            goto out;
        }
    if (!mech_supported(SLOT_ID, mech.mechanism)) {
        testcase_skip("this slot does not support CKM_RSA_PKCS");
        goto out;
    }

    testcase_rw_session();
    testcase_user_login();

    for (keybitlen = 512; keybitlen <= 8192; keybitlen = 2 * keybitlen) {
        if (!keysize_supported(SLOT_ID, CKM_RSA_PKCS_KEY_PAIR_GEN, keybitlen) ||
            (keybitlen > 4096 && !rsa8k))
            continue;

        testcase_begin("CCA/EP11 export/import test with RSA %u key", keybitlen);


        // create ock rsa keypair

        rc = generate_RSA_PKCS_KeyPair(session, CKM_RSA_PKCS_KEY_PAIR_GEN,
                                       keybitlen, exp, sizeof(exp),
                                       &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("RSA key generation with key size %u is not supported", keybitlen);
                goto error;
            }
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key generation is not allowed by policy");
                goto error;
            }

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

        // export original public key's CCA/EP11 blob

        rc = export_ibm_opaque(session, publ_key, &publ_opaquekey, &publ_opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque on public key failed rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 public rsa key blob as new public rsa key

        snprintf(label, sizeof(label), "re-imported_rsa%u_public_key", keybitlen);
        rc = import_rsa_publ_key(session, label, publ_opaquekey, publ_opaquekeylen, &imp_publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_PUBLIC_KEY_INVALID && is_ep11_token(SLOT_ID)) {
                testcase_skip("import_rsa_publ_key on exported CCA/EP11 rsa key blob failed due to missing EP11 FW fix");
            } else {
                testcase_fail("import_rsa_publ_key on exported CCA/EP11 rsa key blob failed rc=%s",
                              p11_get_ckr(rc));
            }
            goto error;
        }

        // export original private key's CCA/EP11 blob

        rc = export_ibm_opaque(session, priv_key, &priv_opaquekey, &priv_opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque on private key failed rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 private rsa key blob as new private rsa key

        snprintf(label, sizeof(label), "re-imported_rsa%u_private_key", keybitlen);
        rc = import_rsa_priv_key(session, label, priv_opaquekey, priv_opaquekeylen, &imp_priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_PUBLIC_KEY_INVALID && is_ep11_token(SLOT_ID)) {
                testcase_skip("import_rsa_priv_key on exported CCA/EP11 rsa key blob failed due to missing EP11 FW fix");
            } else {
                testcase_fail("import_rsa_priv_key on exported CCA/EP11 rsa key blob failed rc=%s",
                              p11_get_ckr(rc));
            }
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

        testcase_pass("CCA/EP11 export/import test with RSA %u key: ok", keybitlen);

error:
        free(priv_opaquekey);
        priv_opaquekey = NULL;
        free(publ_opaquekey);
        publ_opaquekey = NULL;

        if (publ_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, publ_key);
            publ_key = CK_INVALID_HANDLE;
        }
        if (priv_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, priv_key);
            priv_key = CK_INVALID_HANDLE;
        }
        if (imp_publ_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, imp_publ_key);
            imp_publ_key = CK_INVALID_HANDLE;
        }
        if (imp_priv_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, imp_priv_key);
            imp_priv_key = CK_INVALID_HANDLE;
        }
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
static CK_BYTE ed25519[] = OCK_ED25519;
static CK_BYTE ed448[] = OCK_ED448;

static CK_EDDSA_PARAMS eddsa_params = { FALSE, 0, NULL };

static struct {
    CK_BYTE *curve;
    CK_ULONG size;
    const char *name;
    CK_MECHANISM keygen_mech;
    CK_MECHANISM sign_mech;
    CK_KEY_TYPE key_type;
} ec_curves[] = {
    {brainpoolP160r1, sizeof(brainpoolP160r1), "brainpoolP160r1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP160t1, sizeof(brainpoolP160t1), "brainpoolP160t1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP192r1, sizeof(brainpoolP192r1), "brainpoolP192r1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP192t1, sizeof(brainpoolP192t1), "brainpoolP192t1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP224r1, sizeof(brainpoolP224r1), "brainpoolP224r1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP224t1, sizeof(brainpoolP224t1), "brainpoolP224t1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP256r1, sizeof(brainpoolP256r1), "brainpoolP256r1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP256t1, sizeof(brainpoolP256t1), "brainpoolP256t1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP320r1, sizeof(brainpoolP320r1), "brainpoolP320r1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP320t1, sizeof(brainpoolP320t1), "brainpoolP320t1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP384r1, sizeof(brainpoolP384r1), "brainpoolP384r1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP384t1, sizeof(brainpoolP384t1), "brainpoolP384t1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP512r1, sizeof(brainpoolP512r1), "brainpoolP512r1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {brainpoolP512t1, sizeof(brainpoolP512t1), "brainpoolP512t1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {prime192v1, sizeof(prime192v1), "prime192v1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {secp224r1, sizeof(secp224r1), "secp224r1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {prime256v1, sizeof(prime256v1), "prime256v1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {secp384r1, sizeof(secp384r1), "secp384r1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {secp521r1, sizeof(secp521r1), "secp521r1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {secp256k1, sizeof(secp256k1), "secp256k1",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_ECDSA, NULL, 0}, CKK_EC},
    {ed25519, sizeof(ed25519), "ed25519",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_IBM_ED25519_SHA512, NULL, 0},
            CKK_EC},
    {ed448, sizeof(ed448), "ed448",
            {CKM_EC_KEY_PAIR_GEN, NULL, 0}, {CKM_IBM_ED448_SHA3, NULL, 0},
            CKK_EC}, 
    {ed25519, sizeof(ed25519), "ed25519",
            {CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL, 0},
            {CKM_EDDSA, &eddsa_params, sizeof(eddsa_params)}, CKK_EC_EDWARDS},
    {ed448, sizeof(ed448), "ed448",
            {CKM_EC_EDWARDS_KEY_PAIR_GEN, NULL, 0},
            {CKM_EDDSA, &eddsa_params, sizeof(eddsa_params)}, CKK_EC_EDWARDS},
    {0, 0, 0, {0, NULL, 0}, {0, NULL, 0}, 0}
};

static CK_RV ecc_export_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE imp_priv_key = CK_INVALID_HANDLE, imp_publ_key = CK_INVALID_HANDLE;
    CK_BYTE msg[32], sig[256];
    CK_ULONG msglen, siglen;
    CK_BYTE *priv_opaquekey = NULL, *publ_opaquekey = NULL;
    CK_ULONG priv_opaquekeylen, publ_opaquekeylen;
    CK_BBOOL ck_true = TRUE;
    CK_ATTRIBUTE tmpl_derive[] = {
            { CKA_DERIVE, &ck_true, sizeof(ck_true)}
    };
    CK_ULONG tmpl_derive_len = sizeof(tmpl_derive) / sizeof(CK_ATTRIBUTE);
    char label[80];
    int i;
    int is_cca = is_cca_token(SLOT_ID);

    if (!is_cca && !is_ep11_token(SLOT_ID)) {
        testcase_skip("this slot is not a CCA or EP11 token");
        goto out;
    }

    testcase_rw_session();
    testcase_user_login();

    for (i = 0; ec_curves[i].curve; i++) {

        testcase_begin("CCA/EP11 export/import test with public/private ECC "
                       "curve %s keys and %s", ec_curves[i].name,
                       p11_get_ckm(&mechtable_funcs,
                                   ec_curves[i].sign_mech.mechanism));


        if (!mech_supported(SLOT_ID, ec_curves[i].keygen_mech.mechanism)) {
            testcase_skip("this slot does not support %s",
                          p11_get_ckm(&mechtable_funcs,
                                  ec_curves[i].keygen_mech.mechanism));
            goto error;
        }
        if (!mech_supported(SLOT_ID, ec_curves[i].sign_mech.mechanism)) {
            testcase_skip("this slot does not support %s",
                          p11_get_ckm(&mechtable_funcs,
                                  ec_curves[i].sign_mech.mechanism));
            goto error;
        }

        rc = generate_EC_KeyPair(session, ec_curves[i].keygen_mech.mechanism,
                                 ec_curves[i].curve, ec_curves[i].size,
                                 &publ_key, &priv_key, CK_FALSE);
        if (rc == CKR_CURVE_NOT_SUPPORTED) {
            testcase_skip("ECC curve %s not supported yet by CCA/EP11 token",
                          ec_curves[i].name);
            goto error;
        }
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("ECC key generation is not allowed by policy");
                goto error;
            }

            testcase_error("generate_EC_KeyPair() rc=%s", p11_get_ckr(rc));
            goto error;
        }

        testcase_new_assertion();

        // sign with original private key

        rc = funcs->C_SignInit(session, &ec_curves[i].sign_mech, priv_key);
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

        rc = funcs->C_VerifyInit(session, &ec_curves[i].sign_mech, publ_key);
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

        // export original public key's CCA/EP11 blob

        rc = export_ibm_opaque(session, publ_key, &publ_opaquekey, &publ_opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque on public key failed rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 public ecc key blob as new public ecc key

        snprintf(label, sizeof(label), "re-imported_ecc_%s_public_key", ec_curves[i].name);
        rc = import_ecc_publ_key(session, ec_curves[i].key_type, label,
                                 publ_opaquekey, publ_opaquekeylen, &imp_publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_PUBLIC_KEY_INVALID && is_ep11_token(SLOT_ID)) {
                testcase_skip("import_ecc_publ_key on exported CCA/EP11 ecc key blob failed due to missing EP11 FW fix");
            } else {
                testcase_fail("import_ecc_publ_key on exported CCA/EP11 ecc key blob failed rc=%s",
                              p11_get_ckr(rc));
            }
            goto error;
        }

        // export original private key's CCA/EP11 blob

        rc = export_ibm_opaque(session, priv_key, &priv_opaquekey, &priv_opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque on private key failed rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 private ecc key blob as new private ecc key

        snprintf(label, sizeof(label), "re-imported_ecc_%s_private_key", ec_curves[i].name);
        rc = import_ecc_priv_key(session, ec_curves[i].key_type, label,
                                 priv_opaquekey, priv_opaquekeylen, &imp_priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_PUBLIC_KEY_INVALID && is_ep11_token(SLOT_ID)) {
                testcase_skip("import_ecc_priv_key on exported CCA/EP11 ecc key blob failed due to missing EP11 FW fix");
            } else {
                testcase_fail("import_ecc_priv_key on exported CCA/EP11 ecc key blob failed rc=%s",
                              p11_get_ckr(rc));
            }
            goto error;
        }

        // sign with re-imported private key

        rc = funcs->C_SignInit(session, &ec_curves[i].sign_mech, imp_priv_key);
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

        rc = funcs->C_VerifyInit(session, &ec_curves[i].sign_mech, publ_key);
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

        rc = funcs->C_SignInit(session, &ec_curves[i].sign_mech, priv_key);
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

        rc = funcs->C_VerifyInit(session, &ec_curves[i].sign_mech, imp_publ_key);
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

        if (is_cca) {
            /* Try to change CKA_DERIVE to TRUE of private key */
            rc = funcs->C_SetAttributeValue(session, priv_key,
                                            tmpl_derive, tmpl_derive_len);
            if (rc != CKR_OK) {
                testcase_error("C_SetAttributeValue() with CKA_DERIVE=TRUE failed, rc=%s",
                               p11_get_ckr(rc));
                goto error;
            }
        }

        testcase_pass("CCA/EP11 export/import test with public/private ECC "
                      "curve %s keys and %s: ok", ec_curves[i].name,
                      p11_get_ckm(&mechtable_funcs,
                                  ec_curves[i].sign_mech.mechanism));

error:
        free(priv_opaquekey);
        priv_opaquekey = NULL;
        free(publ_opaquekey);
        publ_opaquekey = NULL;

        if (publ_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, publ_key);
            publ_key = CK_INVALID_HANDLE;
        }
        if (priv_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, priv_key);
            priv_key = CK_INVALID_HANDLE;
        }
        if (imp_publ_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, imp_publ_key);
            imp_publ_key = CK_INVALID_HANDLE;
        }
        if (imp_priv_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, imp_priv_key);
            imp_priv_key = CK_INVALID_HANDLE;
        }
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

static struct {
    CK_ULONG keyform;
    const char *name;
} dilithium_variants[] = {
    {CK_IBM_DILITHIUM_KEYFORM_ROUND2_65, "Round 2 (6,5)"},
    {CK_IBM_DILITHIUM_KEYFORM_ROUND2_87, "Round 2 (8,7)"},
    {CK_IBM_DILITHIUM_KEYFORM_ROUND3_44, "Round 3 (4,4)"},
    {CK_IBM_DILITHIUM_KEYFORM_ROUND3_65, "Round 3 (6,5)"},
    {CK_IBM_DILITHIUM_KEYFORM_ROUND3_87, "Round 3 (8,7)"},
    {0, NULL}
};

static CK_RV ibm_dilithium_export_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BBOOL attr_sign = TRUE;
    CK_BBOOL attr_verify = TRUE;
    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE imp_priv_key = CK_INVALID_HANDLE, imp_publ_key = CK_INVALID_HANDLE;
    CK_BYTE msg[32], sig[5000];
    CK_ULONG msglen, siglen;
    CK_MECHANISM mech = { CKM_IBM_DILITHIUM, 0, 0};
    CK_BYTE *priv_opaquekey = NULL, *publ_opaquekey = NULL;
    CK_ULONG priv_opaquekeylen, publ_opaquekeylen;
    char label[80];
    int i;

    if (!is_cca_token(SLOT_ID) && !is_ep11_token(SLOT_ID)) {
        testcase_skip("this slot is not a CCA or EP11 token");
        goto out;
    }
    if (!mech_supported(SLOT_ID, CKM_IBM_DILITHIUM)) {
        testcase_skip("this slot does not support CKM_IBM_DILITHIUM");
        goto out;
    }

    testcase_rw_session();
    testcase_user_login();

    for (i = 0; dilithium_variants[i].keyform != 0; i++) {
        CK_ATTRIBUTE dilithium_attr_private[] = {
            {CKA_SIGN, &attr_sign, sizeof(CK_BBOOL)},
            {CKA_IBM_DILITHIUM_KEYFORM,
             (CK_BYTE *)&dilithium_variants[i].keyform, sizeof(CK_ULONG)},
             {CKA_TOKEN, &true, sizeof(true)},
             {CKA_PRIVATE, &true, sizeof(true)},
        };
        CK_ATTRIBUTE dilithium_attr_public[] = {
            {CKA_VERIFY, &attr_verify, sizeof(CK_BBOOL)},
            {CKA_IBM_DILITHIUM_KEYFORM,
             (CK_BYTE *)&dilithium_variants[i].keyform, sizeof(CK_ULONG)},
             {CKA_TOKEN, &false, sizeof(false)},
             {CKA_PRIVATE, &false, sizeof(false)},
        };
        CK_ULONG num_dilithium_attrs =
                sizeof(dilithium_attr_public) / sizeof(CK_ATTRIBUTE);

        testcase_begin("CCA/EP11 export/import test with public/private IBM Dilithium %s keys",
                       dilithium_variants[i].name);

        /* Generate Dilithium key pair */
        rc = funcs->C_GenerateKeyPair(session, &mech,
                       dilithium_attr_public, num_dilithium_attrs,
                       dilithium_attr_private, num_dilithium_attrs,
                       &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("IBM Dilithium variant %s is not supported",
                              dilithium_variants[i].name);
                goto error;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM Dilithium key generation is not allowed by policy");
                goto error;
            } else {
                testcase_new_assertion();
                testcase_fail("C_GenerateKeyPair with %s failed, rc=%s",
                              dilithium_variants[i].name, p11_get_ckr(rc));
                goto error;
            }
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
        } else if (rc == CKR_SIGNATURE_INVALID ||
                   rc == CKR_SIGNATURE_LEN_RANGE) {
            testcase_fail("signature verify failed");
            goto error;
        } else {
            testcase_error("C_Verify() rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // export original public key's CCA/EP11 blob

        rc = export_ibm_opaque(session, publ_key, &publ_opaquekey,
                               &publ_opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque on public key failed rc=%s",
                           p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 public Dilithium key blob as new public ecc key

        snprintf(label, sizeof(label), "re-imported_dilithium_%s_public_key",
                 dilithium_variants[i].name);
        rc = import_ibm_ml_dsa_publ_key(session, CKK_IBM_PQC_DILITHIUM,
                                        label, publ_opaquekey,
                                        publ_opaquekeylen, &imp_publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_PUBLIC_KEY_INVALID && is_ep11_token(SLOT_ID)) {
                testcase_skip("import_ibm_ml_dsa_publ_key on exported CCA/EP11 Dilithium key blob failed due to missing EP11 FW fix");
            } else {
                testcase_fail("import_ibm_ml_dsa_publ_key on exported CCA/EP11 Dilithium key blob failed rc=%s",
                              p11_get_ckr(rc));
            }
            goto error;
        }

        // export original private key's CCA/EP11 blob

        rc = export_ibm_opaque(session, priv_key, &priv_opaquekey,
                               &priv_opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque on private key failed rc=%s",
                          p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 private Dilithium key blob as new private ecc key

        snprintf(label, sizeof(label), "re-imported_dilithium_%s_private_key",
                 dilithium_variants[i].name);
        rc = import_ibm_ml_dsa_priv_key(session, CKK_IBM_PQC_DILITHIUM,
                                        label, priv_opaquekey,
                                        priv_opaquekeylen, &imp_priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_PUBLIC_KEY_INVALID && is_ep11_token(SLOT_ID)) {
                testcase_skip("import_ibm_ml_dsa_priv_key on exported CCA/EP11 Dilithium key blob failed due to missing EP11 FW fix");
            } else {
                testcase_fail("import_ibm_ml_dsa_priv_key on exported CCA/EP11 Dilithium key blob failed rc=%s",
                              p11_get_ckr(rc));
            }
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
        } else if (rc == CKR_SIGNATURE_INVALID ||
                   rc == CKR_SIGNATURE_LEN_RANGE) {
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
        } else if (rc == CKR_SIGNATURE_INVALID ||
                   rc == CKR_SIGNATURE_LEN_RANGE) {
            testcase_fail("signature verify with re-imported pub key on signature failed");
            goto error;
        } else {
            testcase_error("C_Verify() with re-imported pub key on signature failed, rc=%s",
                           p11_get_ckr(rc));
            goto error;
        }

        testcase_pass("CCA/EP11 export/import test with public/private IBM Dilithium %s keys",
                      dilithium_variants[i].name);

error:
        free(priv_opaquekey);
        priv_opaquekey = NULL;
        free(publ_opaquekey);
        publ_opaquekey = NULL;

        if (publ_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, publ_key);
            publ_key = CK_INVALID_HANDLE;
        }
        if (priv_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, priv_key);
            priv_key = CK_INVALID_HANDLE;
        }
        if (imp_publ_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, imp_publ_key);
            imp_publ_key = CK_INVALID_HANDLE;
        }
        if (imp_priv_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, imp_priv_key);
            imp_priv_key = CK_INVALID_HANDLE;
        }
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

static struct {
    CK_ULONG parameter_set;
    const char *name;
} ml_dsa_variants[] = {
    {CKP_IBM_ML_DSA_44, "ML-DSA (4,4)"},
    {CKP_IBM_ML_DSA_65, "ML-DSA (6,5)"},
    {CKP_IBM_ML_DSA_87, "ML-DSA (8,7)"},
    {0, NULL}
};

static CK_RV ibm_ml_dsa_export_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BBOOL attr_sign = TRUE;
    CK_BBOOL attr_verify = TRUE;
    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE imp_priv_key = CK_INVALID_HANDLE, imp_publ_key = CK_INVALID_HANDLE;
    CK_BYTE msg[32], sig[5000];
    CK_ULONG msglen, siglen;
    CK_MECHANISM mech = { CKM_IBM_ML_DSA, 0, 0};
    CK_MECHANISM keygen_mech = { CKM_IBM_ML_DSA_KEY_PAIR_GEN, 0, 0};
    CK_BYTE *priv_opaquekey = NULL, *publ_opaquekey = NULL;
    CK_ULONG priv_opaquekeylen, publ_opaquekeylen;
    char label[80];
    int i;

    if (!is_cca_token(SLOT_ID) && !is_ep11_token(SLOT_ID)) {
        testcase_skip("this slot is not a CCA or EP11 token");
        goto out;
    }
    if (!mech_supported(SLOT_ID, CKM_IBM_ML_DSA_KEY_PAIR_GEN)) {
        testcase_skip("this slot does not support CKM_IBM_ML_DSA_KEY_PAIR_GEN");
        goto out;
    }
    if (!mech_supported(SLOT_ID, CKM_IBM_ML_DSA)) {
        testcase_skip("this slot does not support CKM_IBM_ML_DSA");
        goto out;
    }

    testcase_rw_session();
    testcase_user_login();

    for (i = 0; ml_dsa_variants[i].parameter_set != 0; i++) {
        CK_ATTRIBUTE ibm_ml_dsa_attr_private[] = {
            {CKA_SIGN, &attr_sign, sizeof(CK_BBOOL)},
            {CKA_IBM_PARAMETER_SET,
             (CK_BYTE *)&ml_dsa_variants[i].parameter_set, sizeof(CK_ULONG)},
             {CKA_TOKEN, &true, sizeof(true)},
             {CKA_PRIVATE, &true, sizeof(true)},
        };
        CK_ATTRIBUTE ibm_ml_dsa_attr_public[] = {
            {CKA_VERIFY, &attr_verify, sizeof(CK_BBOOL)},
            {CKA_IBM_PARAMETER_SET,
             (CK_BYTE *)&ml_dsa_variants[i].parameter_set, sizeof(CK_ULONG)},
             {CKA_TOKEN, &false, sizeof(false)},
             {CKA_PRIVATE, &false, sizeof(false)},
        };
        CK_ULONG num_ibm_ml_dsa_attrs =
                sizeof(ibm_ml_dsa_attr_public) / sizeof(CK_ATTRIBUTE);

        testcase_begin("CCA/EP11 export/import test with public/private IBM ML-DSA %s keys",
                       ml_dsa_variants[i].name);

        /* Generate IBM-ML-DSA key pair */
        rc = funcs->C_GenerateKeyPair(session, &keygen_mech,
                       ibm_ml_dsa_attr_public, num_ibm_ml_dsa_attrs,
                       ibm_ml_dsa_attr_private, num_ibm_ml_dsa_attrs,
                       &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("IBM ML-DSA variant %s is not supported",
                              ml_dsa_variants[i].name);
                goto error;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM ML-DSA key generation is not allowed by policy");
                goto error;
            } else {
                testcase_new_assertion();
                testcase_fail("C_GenerateKeyPair with %s failed, rc=%s",
                              ml_dsa_variants[i].name, p11_get_ckr(rc));
                goto error;
            }
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
        } else if (rc == CKR_SIGNATURE_INVALID ||
                   rc == CKR_SIGNATURE_LEN_RANGE) {
            testcase_fail("signature verify failed");
            goto error;
        } else {
            testcase_error("C_Verify() rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // export original public key's CCA/EP11 blob

        rc = export_ibm_opaque(session, publ_key, &publ_opaquekey,
                               &publ_opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque on public key failed rc=%s",
                           p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 public ML-DSA key blob as new public ML-DSA key

        snprintf(label, sizeof(label), "re-imported_ml_dsa_%s_public_key",
                 ml_dsa_variants[i].name);
        rc = import_ibm_ml_dsa_publ_key(session, CKK_IBM_ML_DSA,
                                        label, publ_opaquekey,
                                        publ_opaquekeylen, &imp_publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_PUBLIC_KEY_INVALID && is_ep11_token(SLOT_ID)) {
                testcase_skip("import_ibm_ml_dsa_publ_key on exported CCA/EP11 ML-DSA key blob failed due to missing EP11 FW fix");
            } else {
                testcase_fail("import_ibm_ml_dsa_publ_key on exported CCA/EP11 ML-DSA key blob failed rc=%s",
                              p11_get_ckr(rc));
            }
            goto error;
        }

        // export original private key's CCA/EP11 blob

        rc = export_ibm_opaque(session, priv_key, &priv_opaquekey,
                               &priv_opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque on private key failed rc=%s",
                          p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 private ML-DSA key blob as new private ML-DSA key

        snprintf(label, sizeof(label), "re-imported_ml_dsa_%s_private_key",
                 ml_dsa_variants[i].name);
        rc = import_ibm_ml_dsa_priv_key(session, CKK_IBM_ML_DSA,
                                        label, priv_opaquekey,
                                        priv_opaquekeylen, &imp_priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_PUBLIC_KEY_INVALID && is_ep11_token(SLOT_ID)) {
                testcase_skip("import_ibm_ml_dsa_priv_key on exported CCA/EP11 ML-DSA key blob failed due to missing EP11 FW fix");
            } else {
                testcase_fail("import_ibm_ml_dsa_priv_key on exported CCA/EP11 ML-DSA key blob failed rc=%s",
                              p11_get_ckr(rc));
            }
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
        } else if (rc == CKR_SIGNATURE_INVALID ||
                   rc == CKR_SIGNATURE_LEN_RANGE) {
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
        } else if (rc == CKR_SIGNATURE_INVALID ||
                   rc == CKR_SIGNATURE_LEN_RANGE) {
            testcase_fail("signature verify with re-imported pub key on signature failed");
            goto error;
        } else {
            testcase_error("C_Verify() with re-imported pub key on signature failed, rc=%s",
                           p11_get_ckr(rc));
            goto error;
        }

        testcase_pass("CCA/EP11 export/import test with public/private IBM ML-DSA %s keys",
                      ml_dsa_variants[i].name);

error:
        free(priv_opaquekey);
        priv_opaquekey = NULL;
        free(publ_opaquekey);
        publ_opaquekey = NULL;

        if (publ_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, publ_key);
            publ_key = CK_INVALID_HANDLE;
        }
        if (priv_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, priv_key);
            priv_key = CK_INVALID_HANDLE;
        }
        if (imp_publ_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, imp_publ_key);
            imp_publ_key = CK_INVALID_HANDLE;
        }
        if (imp_priv_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, imp_priv_key);
            imp_priv_key = CK_INVALID_HANDLE;
        }
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

static struct {
    CK_ULONG parameter_set;
    const char *name;
} ml_kem_variants[] = {
    {CKP_IBM_ML_KEM_512, "ML-KEM 512"},
    {CKP_IBM_ML_KEM_768, "ML-KEM 768"},
    {CKP_IBM_ML_KEM_1024, "ML-KEM 1024"},
    {0, NULL}
};

static CK_RV ibm_ml_kem_export_import_tests(void)
{
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BBOOL attr_derive = TRUE;
    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE imp_priv_key = CK_INVALID_HANDLE, imp_publ_key = CK_INVALID_HANDLE;
    CK_BYTE output_data[8192];
    CK_ULONG outlen;
    CK_IBM_ML_KEM_PARAMS ml_kem_params;
    CK_MECHANISM mech = { CKM_IBM_ML_KEM, &ml_kem_params, sizeof(ml_kem_params)};
    CK_MECHANISM keygen_mech = { CKM_IBM_ML_KEM_KEY_PAIR_GEN, 0, 0};
    CK_BYTE *priv_opaquekey = NULL, *publ_opaquekey = NULL;
    CK_ULONG priv_opaquekeylen, publ_opaquekeylen;
    char label[80];
    int i;

    if (!is_cca_token(SLOT_ID) && !is_ep11_token(SLOT_ID)) {
        testcase_skip("this slot is not a CCA or EP11 token");
        goto out;
    }
    if (!mech_supported(SLOT_ID, CKM_IBM_ML_KEM_KEY_PAIR_GEN)) {
        testcase_skip("this slot does not support CKM_IBM_ML_KEM_KEY_PAIR_GEN");
        goto out;
    }
    if (!mech_supported(SLOT_ID, CKM_IBM_ML_KEM)) {
        testcase_skip("this slot does not support CKM_IBM_ML_KEM");
        goto out;
    }

    testcase_rw_session();
    testcase_user_login();

    for (i = 0; ml_kem_variants[i].parameter_set != 0; i++) {
        CK_ATTRIBUTE ibm_ml_kem_attr_private[] = {
            {CKA_DERIVE, &attr_derive, sizeof(CK_BBOOL)},
            {CKA_IBM_PARAMETER_SET,
             (CK_BYTE *)&ml_kem_variants[i].parameter_set, sizeof(CK_ULONG)},
             {CKA_TOKEN, &true, sizeof(true)},
             {CKA_PRIVATE, &true, sizeof(true)},
        };
        CK_ATTRIBUTE ibm_ml_kem_attr_public[] = {
            {CKA_DERIVE, &attr_derive, sizeof(CK_BBOOL)},
            {CKA_IBM_PARAMETER_SET,
             (CK_BYTE *)&ml_kem_variants[i].parameter_set, sizeof(CK_ULONG)},
             {CKA_TOKEN, &false, sizeof(false)},
             {CKA_PRIVATE, &false, sizeof(false)},
        };
        CK_ULONG num_ibm_ml_kem_attrs =
                sizeof(ibm_ml_kem_attr_public) / sizeof(CK_ATTRIBUTE);
        CK_OBJECT_CLASS class = CKO_SECRET_KEY;
        CK_KEY_TYPE key_type = CKK_AES;
        CK_ULONG secret_key_len = 32;
        CK_ATTRIBUTE  derive_tmpl[] = {
            {CKA_CLASS, &class, sizeof(class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_SENSITIVE, &false, sizeof(false)},
            {CKA_VALUE_LEN, &secret_key_len, sizeof(secret_key_len)},
            {CKA_SIGN, &true, sizeof(true)},
            {CKA_VERIFY, &true, sizeof(true)},
        };
        CK_ULONG derive_tmpl_len = sizeof(derive_tmpl) / sizeof(CK_ATTRIBUTE);
        CK_OBJECT_HANDLE key1 = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE key2 = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE key3 = CK_INVALID_HANDLE;
        CK_OBJECT_HANDLE key4 = CK_INVALID_HANDLE;

        testcase_begin("CCA/EP11 export/import test with public/private IBM ML-KEM %s keys",
                       ml_kem_variants[i].name);

        /* Generate IBM-ML-KEM key pair */
        rc = funcs->C_GenerateKeyPair(session, &keygen_mech,
                       ibm_ml_kem_attr_public, num_ibm_ml_kem_attrs,
                       ibm_ml_kem_attr_private, num_ibm_ml_kem_attrs,
                       &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("IBM ML-KEM variant %s is not supported",
                              ml_kem_variants[i].name);
                goto error;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM ML-KEM key generation is not allowed by policy");
                goto error;
            } else {
                testcase_new_assertion();
                testcase_fail("C_GenerateKeyPair with %s failed, rc=%s",
                              ml_kem_variants[i].name, p11_get_ckr(rc));
                goto error;
            }
        }

        testcase_new_assertion();

        // Encapsulate with original public key

        memset(&ml_kem_params, 0, sizeof(ml_kem_params));
        ml_kem_params.ulVersion = CK_IBM_ML_KEM_VERSION;
        ml_kem_params.mode = CK_IBM_ML_KEM_ENCAPSULATE;
        ml_kem_params.ulCipherLen = sizeof(output_data);
        ml_kem_params.pCipher = output_data;
        ml_kem_params.kdf = CKD_NULL;
        ml_kem_params.pSharedData = NULL;;
        ml_kem_params.ulSharedDataLen = 0;
        ml_kem_params.bPrepend = CK_FALSE;
        ml_kem_params.hSecret = CK_INVALID_HANDLE;

        rc = funcs->C_DeriveKey(session, &mech, publ_key, derive_tmpl,
                                derive_tmpl_len, &key1);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey (encapsulate) with %s failed, rc=%s",
                          ml_kem_variants[i].name, p11_get_ckr(rc));
            goto error;
        }
        outlen = ml_kem_params.ulCipherLen;

        // Decapsulate with original private key

        memset(&ml_kem_params, 0, sizeof(ml_kem_params));
        ml_kem_params.ulVersion = CK_IBM_ML_KEM_VERSION;
        ml_kem_params.mode = CK_IBM_ML_KEM_DECAPSULATE;
        ml_kem_params.ulCipherLen = outlen;
        ml_kem_params.kdf = CKD_NULL;
        ml_kem_params.pCipher = output_data;
        ml_kem_params.pSharedData = NULL;;
        ml_kem_params.ulSharedDataLen = 0;
        ml_kem_params.bPrepend = CK_FALSE;
        ml_kem_params.hSecret = CK_INVALID_HANDLE;

        rc = funcs->C_DeriveKey(session, &mech, priv_key, derive_tmpl,
                                derive_tmpl_len, &key2);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey (decapsulate) with %s failed, rc=%s",
                          ml_kem_variants[i].name, p11_get_ckr(rc));
            goto error;
        }

        // export original public key's CCA/EP11 blob

        rc = export_ibm_opaque(session, publ_key, &publ_opaquekey,
                               &publ_opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque on public key failed rc=%s",
                           p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 public ML-KEM key blob as new public ML-KEM key

        snprintf(label, sizeof(label), "re-imported_ml_kem_%s_public_key",
                 ml_kem_variants[i].name);
        rc = import_ibm_ml_kem_publ_key(session, CKK_IBM_ML_KEM,
                                        label, publ_opaquekey,
                                        publ_opaquekeylen, &imp_publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_PUBLIC_KEY_INVALID && is_ep11_token(SLOT_ID)) {
                testcase_skip("import_ibm_ml_kem_publ_key on exported CCA/EP11 ML-KEM key blob failed due to missing EP11 FW fix");
            } else {
                testcase_fail("import_ibm_ml_kem_publ_key on exported CCA/EP11 ML-KEM key blob failed rc=%s",
                              p11_get_ckr(rc));
            }
            goto error;
        }

        // export original private key's CCA/EP11 blob

        rc = export_ibm_opaque(session, priv_key, &priv_opaquekey,
                               &priv_opaquekeylen);
        if (rc != CKR_OK) {
            testcase_fail("export_ibm_opaque on private key failed rc=%s",
                          p11_get_ckr(rc));
            goto error;
        }

        // re-import this CCA/EP11 private ML-KEM key blob as new private ML-KEM key

        snprintf(label, sizeof(label), "re-imported_ml_kem_%s_private_key",
                 ml_kem_variants[i].name);
        rc = import_ibm_ml_kem_priv_key(session, CKK_IBM_ML_KEM,
                                        label, priv_opaquekey,
                                        priv_opaquekeylen, &imp_priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_PUBLIC_KEY_INVALID && is_ep11_token(SLOT_ID)) {
                testcase_skip("import_ibm_ml_kem_priv_key on exported CCA/EP11 ML-KEM key blob failed due to missing EP11 FW fix");
            } else {
                testcase_fail("import_ibm_ml_kem_priv_key on exported CCA/EP11 ML-KEM key blob failed rc=%s",
                              p11_get_ckr(rc));
            }
            goto error;
        }

        // Decapsulate with imported private key

        memset(&ml_kem_params, 0, sizeof(ml_kem_params));
        ml_kem_params.ulVersion = CK_IBM_ML_KEM_VERSION;
        ml_kem_params.mode = CK_IBM_ML_KEM_DECAPSULATE;
        ml_kem_params.ulCipherLen = outlen;
        ml_kem_params.kdf = CKD_NULL;
        ml_kem_params.pCipher = output_data;
        ml_kem_params.pSharedData = NULL;;
        ml_kem_params.ulSharedDataLen = 0;
        ml_kem_params.bPrepend = CK_FALSE;
        ml_kem_params.hSecret = CK_INVALID_HANDLE;

        rc = funcs->C_DeriveKey(session, &mech, imp_priv_key, derive_tmpl,
                                derive_tmpl_len, &key3);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey (decapsulate) with %s failed, rc=%s",
                          ml_kem_variants[i].name, p11_get_ckr(rc));
            goto error;
        }

        // Encapsulate with imported public key

        memset(&ml_kem_params, 0, sizeof(ml_kem_params));
        ml_kem_params.ulVersion = CK_IBM_ML_KEM_VERSION;
        ml_kem_params.mode = CK_IBM_ML_KEM_ENCAPSULATE;
        ml_kem_params.ulCipherLen = sizeof(output_data);
        ml_kem_params.pCipher = output_data;
        ml_kem_params.kdf = CKD_NULL;
        ml_kem_params.pSharedData = NULL;;
        ml_kem_params.ulSharedDataLen = 0;
        ml_kem_params.bPrepend = CK_FALSE;
        ml_kem_params.hSecret = CK_INVALID_HANDLE;

        rc = funcs->C_DeriveKey(session, &mech, imp_publ_key, derive_tmpl,
                                derive_tmpl_len, &key4);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey (encapsulate) with %s failed, rc=%s",
                          ml_kem_variants[i].name, p11_get_ckr(rc));
            goto error;
        }
        outlen = ml_kem_params.ulCipherLen;

        testcase_pass("CCA/EP11 export/import test with public/private IBM ML-KEM %s keys",
                      ml_kem_variants[i].name);

error:
        free(priv_opaquekey);
        priv_opaquekey = NULL;
        free(publ_opaquekey);
        publ_opaquekey = NULL;

        if (publ_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, publ_key);
            publ_key = CK_INVALID_HANDLE;
        }
        if (priv_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, priv_key);
            priv_key = CK_INVALID_HANDLE;
        }
        if (imp_publ_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, imp_publ_key);
            imp_publ_key = CK_INVALID_HANDLE;
        }
        if (imp_priv_key != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, imp_priv_key);
            imp_priv_key = CK_INVALID_HANDLE;
        }
        if (key1 != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, key1);
            key1 = CK_INVALID_HANDLE;
        }
        if (key2 != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, key2);
            key2 = CK_INVALID_HANDLE;
        }
        if (key3 != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, key3);
            key3 = CK_INVALID_HANDLE;
        }
        if (key4 != CK_INVALID_HANDLE) {
            funcs->C_DestroyObject(session, key4);
            key4 = CK_INVALID_HANDLE;
        }
    }

testcase_cleanup:
    testcase_close_session();
out:
    return rc;
}

static CK_RV cca_ep11_export_import_tests(void)
{
    CK_RV rc = CKR_OK, rv = CKR_OK;

    testsuite_begin("CCA/EP11 export/import tests");

    rc = des_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = des3_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = aes_export_import_tests(CK_IBM_CCA_AES_DATA_KEY);
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = aes_xts_export_import_tests(CK_IBM_CCA_AES_DATA_KEY);
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = aes_export_import_tests(CK_IBM_CCA_AES_CIPHER_KEY);
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = aes_xts_export_import_tests(CK_IBM_CCA_AES_CIPHER_KEY);
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = generic_secret_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = rsa_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = ecc_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = ibm_dilithium_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = ibm_ml_dsa_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

    rc = ibm_ml_kem_export_import_tests();
    if (rc != CKR_OK && rv == CKR_OK)
        rv = rc;

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

    testcase_setup();
    rv = cca_ep11_export_import_tests();
    testcase_print_result();

    funcs->C_Finalize(NULL);

    return testcase_return(rv);
}
