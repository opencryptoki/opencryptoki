/*
 * COPYRIGHT (c) International Business Machines Corp. 2025
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"
#include "defs.h"
#include "mechtable.h"
#include "ec_curves.h"
#include "ibm_ml_kem.h"

/**
 * Support for IBM ML-KEM keys and KEM
 * with oid = 2.16.840.1.101.3.4.4.xxx
 */

const CK_BYTE prime256v1[] = OCK_PRIME256V1;

typedef struct variant_info {
    const char *name;
    CK_IBM_ML_KEM_PARAMETER_SET_TYPE parameter_set;
} _variant_info;

const _variant_info variants[] = {
    { "ML_KEM_512", CKP_IBM_ML_KEM_512, },
    { "ML_KEM_768", CKP_IBM_ML_KEM_768, },
    { "ML_KEM_1024", CKP_IBM_ML_KEM_1024, },
};

const CK_ULONG num_variants = sizeof(variants) / sizeof(_variant_info);

typedef struct kemParam {
    CK_IBM_ML_KEM_KDF_TYPE kdf;
    CK_KEY_TYPE secret_key_type;
    CK_ULONG secret_key_len;
    CK_ULONG shard_data_len;
    CK_BYTE shared_data[32];
    CK_BBOOL hybrid;
    CK_BBOOL prepend;
} _kemParam;

const _kemParam kemInput[] = {
    { CKD_NULL, CKK_AES, 32, 0, {0x00}, CK_FALSE, CK_FALSE },
    { CKD_IBM_HYBRID_SHA1_KDF, CKK_GENERIC_SECRET, 16, 0, {0x00}, CK_TRUE, CK_FALSE },
    { CKD_IBM_HYBRID_SHA1_KDF, CKK_GENERIC_SECRET, 32, 16,
      { 0x32,0x3F,0xA3,0x16,0x9D,0x8E,0x9C,0x65,0x93,0xF5,0x94,0x76,0xBC,0x14,0x20,0x00 },
      CK_TRUE, CK_TRUE },
    { CKD_IBM_HYBRID_SHA224_KDF, CKK_GENERIC_SECRET, 16, 0, {0x00}, CK_TRUE, CK_FALSE },
    { CKD_IBM_HYBRID_SHA224_KDF, CKK_GENERIC_SECRET, 32, 16,
      { 0x32,0x3F,0xA3,0x16,0x9D,0x8E,0x9C,0x65,0x93,0xF5,0x94,0x76,0xBC,0x14,0x20,0x00 },
      CK_TRUE, CK_TRUE },
    { CKD_IBM_HYBRID_SHA256_KDF, CKK_GENERIC_SECRET, 16, 0, {0x00}, CK_TRUE, CK_FALSE },
    { CKD_IBM_HYBRID_SHA256_KDF, CKK_GENERIC_SECRET, 32, 16,
      { 0x32,0x3F,0xA3,0x16,0x9D,0x8E,0x9C,0x65,0x93,0xF5,0x94,0x76,0xBC,0x14,0x20,0x00 },
      CK_TRUE, CK_TRUE },
    { CKD_IBM_HYBRID_SHA384_KDF, CKK_GENERIC_SECRET, 16, 0, {0x00}, CK_TRUE, CK_FALSE },
    { CKD_IBM_HYBRID_SHA384_KDF, CKK_GENERIC_SECRET, 32, 16,
      { 0x32,0x3F,0xA3,0x16,0x9D,0x8E,0x9C,0x65,0x93,0xF5,0x94,0x76,0xBC,0x14,0x20,0x00 },
      CK_TRUE, CK_TRUE },
    { CKD_IBM_HYBRID_SHA512_KDF, CKK_GENERIC_SECRET, 16, 0, {0x00}, CK_TRUE, CK_FALSE },
    { CKD_IBM_HYBRID_SHA512_KDF, CKK_GENERIC_SECRET, 32, 16,
      { 0x32,0x3F,0xA3,0x16,0x9D,0x8E,0x9C,0x65,0x93,0xF5,0x94,0x76,0xBC,0x14,0x20,0x00 },
      CK_TRUE, CK_TRUE },
    { CKD_IBM_HYBRID_SHA224_KDF, CKK_AES, 32, 0, {0x00}, CK_TRUE, CK_FALSE },
    { CKD_IBM_HYBRID_SHA224_KDF, CKK_AES, 32, 16,
      { 0x32,0x3F,0xA3,0x16,0x9D,0x8E,0x9C,0x65,0x93,0xF5,0x94,0x76,0xBC,0x14,0x20,0x00 },
      CK_TRUE, CK_TRUE },
    { CKD_IBM_HYBRID_SHA256_KDF, CKK_AES, 32, 0, {0x00}, CK_TRUE, CK_FALSE },
    { CKD_IBM_HYBRID_SHA256_KDF, CKK_AES, 32, 16,
      { 0x32,0x3F,0xA3,0x16,0x9D,0x8E,0x9C,0x65,0x93,0xF5,0x94,0x76,0xBC,0x14,0x20,0x00 },
      CK_TRUE, CK_TRUE },
    { CKD_IBM_HYBRID_SHA384_KDF, CKK_AES, 32, 0, {0x00}, CK_TRUE, CK_FALSE },
    { CKD_IBM_HYBRID_SHA384_KDF, CKK_AES, 32, 16,
      { 0x32,0x3F,0xA3,0x16,0x9D,0x8E,0x9C,0x65,0x93,0xF5,0x94,0x76,0xBC,0x14,0x20,0x00 },
      CK_TRUE, CK_TRUE },
    { CKD_IBM_HYBRID_SHA512_KDF, CKK_AES, 32, 0, {0x00}, CK_TRUE, CK_FALSE },
    { CKD_IBM_HYBRID_SHA512_KDF, CKK_AES, 32, 16,
      { 0x32,0x3F,0xA3,0x16,0x9D,0x8E,0x9C,0x65,0x93,0xF5,0x94,0x76,0xBC,0x14,0x20,0x00 },
      CK_TRUE, CK_TRUE },
};

static const char *p11_get_ckd(CK_EC_KDF_TYPE kdf)
{
    switch (kdf) {
    case CKD_NULL:
        return "CKD_NULL";
    case CKD_SHA1_KDF:
        return "CKD_SHA1_KDF";
    case CKD_SHA224_KDF:
        return "CKD_SHA224_KDF";
    case CKD_SHA256_KDF:
        return "CKD_SHA256_KDF";
    case CKD_SHA384_KDF:
        return "CKD_SHA384_KDF";
    case CKD_SHA512_KDF:
        return "CKD_SHA512_KDF";
    case CKD_IBM_HYBRID_NULL:
        return "CKD_IBM_HYBRID_NULL";
    case CKD_IBM_HYBRID_SHA1_KDF:
        return "CKD_IBM_HYBRID_SHA1_KDF";
    case CKD_IBM_HYBRID_SHA224_KDF:
        return "CKD_IBM_HYBRID_SHA224_KDF";
    case CKD_IBM_HYBRID_SHA256_KDF:
        return "CKD_IBM_HYBRID_SHA256_KDF";
    case CKD_IBM_HYBRID_SHA384_KDF:
        return "CKD_IBM_HYBRID_SHA384_KDF";
    case CKD_IBM_HYBRID_SHA512_KDF:
        return "CKD_IBM_HYBRID_SHA512_KDF";
    default:
        return "UNKNOWN";
    }
}

#define NUM_KEM_INPUTS sizeof(kemInput)/sizeof(_kemParam)

/*
 * Perform a AES encrypt and decrypt that the key is usable.
 */
CK_RV run_AESCrypt(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h_key1,
                   CK_OBJECT_HANDLE h_key2)
{
    CK_MECHANISM mech = { .mechanism = CKM_AES_ECB,
                          .pParameter = NULL, .ulParameterLen = 0 };
    CK_BYTE data[32] = { 0 };
    CK_BYTE out[32] = { 0 };
    CK_ULONG out_len = sizeof(out);
    CK_RV rc = CKR_OK;

    if (!mech_supported(SLOT_ID, CKM_AES_ECB)) {
        testcase_notice("Mechanism CKM_AES_ECB is not supported with slot "
                        "%lu. Skipping key check", SLOT_ID);
        return CKR_OK;
    }

    rc = funcs->C_EncryptInit(session, &mech, h_key1);
    if (rc != CKR_OK) {
        testcase_notice("C_EncryptInit rc=%s", p11_get_ckr(rc));
        goto error;
    }

    /** do encrypting  **/
    rc = funcs->C_Encrypt(session, data, sizeof(data), out, &out_len);
    if (rc != CKR_OK) {
        testcase_notice("C_Encrypt rc=%s", p11_get_ckr(rc));
        goto error;
    }

    rc = funcs->C_DecryptInit(session, &mech, h_key2);
    if (rc != CKR_OK) {
        testcase_notice("C_DecryptInit rc=%s", p11_get_ckr(rc));
        goto error;
    }

    /** do decrypt  **/
    rc = funcs->C_Decrypt(session, out, out_len, data, &out_len);
    if (rc != CKR_OK) {
        testcase_notice("C_Decrypt rc=%s", p11_get_ckr(rc));
        goto error;
    }

error:
    return rc;
}

/*
 * Perform a HMAC sign to verify that the key is usable.
 */
CK_RV run_HMACSign(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h_key1,
                   CK_OBJECT_HANDLE h_key2, CK_ULONG key_len)
{
    CK_MECHANISM mech = { .mechanism = CKM_SHA_1_HMAC,
                          .pParameter = NULL, .ulParameterLen = 0 };
    CK_BYTE data[32] = { 0 };
    CK_BYTE mac[SHA1_HASH_SIZE] = { 0 };
    CK_ULONG mac_len = sizeof(mac);
    CK_RV rc = CKR_OK;

    if (!mech_supported(SLOT_ID, CKM_SHA_1_HMAC)) {
        testcase_notice("Mechanism CKM_SHA_1_HMAC is not supported with slot "
                        "%lu. Skipping key check", SLOT_ID);
        return CKR_OK;
    }
    if (!check_supp_keysize(SLOT_ID, CKM_SHA_1_HMAC, key_len * 8)) {
        testcase_notice("Mechanism CKM_SHA_1_HMAC can not be used with keys "
                        "of size %lu. Skipping key check", key_len);
        return CKR_OK;
    }

    rc = funcs->C_SignInit(session, &mech, h_key1);
    if (rc != CKR_OK) {
        testcase_notice("C_SignInit rc=%s", p11_get_ckr(rc));
        goto error;
    }

    /** do signing  **/
    rc = funcs->C_Sign(session, data, sizeof(data), mac, &mac_len);
    if (rc != CKR_OK) {
        testcase_notice("C_Sign rc=%s", p11_get_ckr(rc));
        goto error;
    }

    rc = funcs->C_VerifyInit(session, &mech, h_key2);
    if (rc != CKR_OK) {
        testcase_notice("C_VerifyInit rc=%s", p11_get_ckr(rc));
        goto error;
    }

    /** do verify  **/
    rc = funcs->C_Verify(session, data, sizeof(data), mac, mac_len);
    if (rc != CKR_OK) {
        testcase_notice("C_Verify rc=%s", p11_get_ckr(rc));
        goto error;
    }

error:
    return rc;
}

CK_RV ecdh_derive_secret(CK_SESSION_HANDLE session, CK_ULONG secret_key_len,
                         CK_EC_KDF_TYPE kdf, CK_OBJECT_HANDLE *hybrid_key)
{
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv_key = CK_INVALID_HANDLE;
    CK_ECDH1_DERIVE_PARAMS ecda_params;
    CK_MECHANISM mech;
    CK_RV rc;

    CK_BYTE pubkey_value[256];
    CK_ATTRIBUTE  extr_tmpl[] = {
        {CKA_EC_POINT, pubkey_value, sizeof(pubkey_value)},
    };
    CK_ULONG extr_tmpl_len = sizeof(extr_tmpl)/sizeof(CK_ATTRIBUTE);

    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_ATTRIBUTE  derive_tmpl[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_SENSITIVE, &false, sizeof(false)},
        {CKA_VALUE_LEN, &secret_key_len, sizeof(CK_ULONG)},
        {CKA_IBM_USE_AS_DATA, &true, sizeof(true)},
    };
    CK_ULONG secret_tmpl_len =
        sizeof(derive_tmpl) / sizeof(CK_ATTRIBUTE);

    if (!mech_supported(SLOT_ID, CKM_EC_KEY_PAIR_GEN)) {
        testcase_notice("Slot %u doesn't support CKM_EC_KEY_PAIR_GEN\n",
                        (unsigned int) SLOT_ID);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = generate_EC_KeyPair(session, CKM_EC_KEY_PAIR_GEN,
                             (CK_BYTE *)prime256v1, sizeof(prime256v1),
                             &publ_key, &priv_key, CK_FALSE);
    if (rc != CKR_OK) {
        testcase_notice("generate_EC_KeyPair rc=%s", p11_get_ckr(rc));
        goto error;
    }

    rc = funcs->C_GetAttributeValue(session, publ_key, extr_tmpl, extr_tmpl_len);
    if (rc != CKR_OK) {
        testcase_notice("C_GetAttributeValue: rc = %s", p11_get_ckr(rc));
        goto error;
    }

    mech.mechanism = CKM_ECDH1_DERIVE;
    mech.pParameter = &ecda_params;
    mech.ulParameterLen = sizeof(ecda_params);

    memset(&ecda_params, 0, sizeof(ecda_params));
    ecda_params.kdf = kdf;
    ecda_params.pPublicData = extr_tmpl[0].pValue;
    ecda_params.ulPublicDataLen = extr_tmpl[0].ulValueLen;

    rc = funcs->C_DeriveKey(session, &mech, priv_key, derive_tmpl,
                            secret_tmpl_len, hybrid_key);
    if (rc != CKR_OK) {
        testcase_notice("C_DeriveKey: rc = %s", p11_get_ckr(rc));
        goto error;
    }

error:
    if (publ_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_key);
    if (priv_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_key);

    return rc;
}

CK_RV run_EnDecapsulateMLKEM(CK_SESSION_HANDLE session,
                             CK_OBJECT_HANDLE priv_key,
                             CK_OBJECT_HANDLE publ_key,
                             CK_KEY_TYPE key_type,
                             CK_ULONG secret_key_len,
                             CK_IBM_ML_KEM_KDF_TYPE kdf,
                             CK_BBOOL hybrid,
                             CK_BBOOL prepend,
                             const CK_BYTE *pSharedData,
                             CK_ULONG ulSharedDataLen,
                             const CK_BYTE *pCipher,
                             CK_ULONG ulCipherLen,
                             const CK_BYTE *pExpectedSecret,
                             CK_ULONG ulExpectedSecret)
{
    CK_MECHANISM mech;
    CK_IBM_ML_KEM_PARAMS ml_kem_params;
    CK_BYTE *cipher = NULL;
    CK_ULONG cipher_len = 0;
    CK_OBJECT_HANDLE secret_key1 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret_key2 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hybrid_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE expected_secret_key = CK_INVALID_HANDLE;
    CK_RV rc;

    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_ATTRIBUTE  derive_tmpl[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_SENSITIVE, &false, sizeof(false)},
        {CKA_VALUE_LEN, &secret_key_len, sizeof(secret_key_len)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
    };
    CK_ULONG secret_tmpl_len = sizeof(derive_tmpl) / sizeof(CK_ATTRIBUTE);

    mech.mechanism = CKM_IBM_ML_KEM;
    mech.ulParameterLen = sizeof(ml_kem_params);
    mech.pParameter = &ml_kem_params;

    /* Query the slot, check if this mech if supported */
    if (!mech_supported(SLOT_ID, mech.mechanism)) {
        testcase_notice("Slot %u doesn't support %s",
                        (unsigned int) SLOT_ID,
                        p11_get_ckm(&mechtable_funcs, mech.mechanism));
        rc = CKR_MECHANISM_INVALID;
        goto testcase_cleanup;
    }

    if (hybrid) {
        rc = ecdh_derive_secret(session, 32, CKD_IBM_HYBRID_NULL, &hybrid_key);
        if (rc != CKR_OK) {
            testcase_error("ecdh_derive_secret() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    if (pCipher != NULL && ulCipherLen != 0) {
        cipher_len = ulCipherLen;
        cipher = (CK_BYTE *)pCipher;
        goto decapsulate;
    }

    /* Perform encapsulation with public key */
    memset(&ml_kem_params, 0, sizeof(ml_kem_params));
    ml_kem_params.ulVersion = CK_IBM_ML_KEM_VERSION;
    ml_kem_params.mode = CK_IBM_ML_KEM_ENCAPSULATE;
    ml_kem_params.kdf = kdf;
    ml_kem_params.pSharedData = (CK_BYTE *)pSharedData;
    ml_kem_params.ulSharedDataLen = ulSharedDataLen;
    ml_kem_params.bPrepend = prepend;
    ml_kem_params.hSecret = hybrid_key;

    /* Size query */
    rc = funcs->C_DeriveKey(session, &mech, publ_key, derive_tmpl,
                            secret_tmpl_len, &secret_key1);
    if (rc != CKR_BUFFER_TOO_SMALL) {
        testcase_error("C_DeriveKey (size query) rc=%s (expected CKR_BUFFER_TOO_SMALL)",
                       p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    cipher_len = ml_kem_params.ulCipherLen;
    cipher = calloc(cipher_len, sizeof(CK_BYTE));
    if (cipher == NULL) {
        testcase_error("Can't allocate memory for %lu bytes",
                       sizeof(CK_BYTE) * cipher_len);
        rc = CKR_HOST_MEMORY;
        goto testcase_cleanup;
    }

    ml_kem_params.ulCipherLen = cipher_len;
    ml_kem_params.pCipher = cipher;

    /* Encapsulation */
    rc = funcs->C_DeriveKey(session, &mech, publ_key, derive_tmpl,
                            secret_tmpl_len, &secret_key1);
    if (rc != CKR_OK) {
        testcase_error("C_DeriveKey (encapsulation) rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }
    cipher_len = ml_kem_params.ulCipherLen;

decapsulate:
    /* Perform Decapsulation with private key */
    memset(&ml_kem_params, 0, sizeof(ml_kem_params));
    ml_kem_params.ulVersion = CK_IBM_ML_KEM_VERSION;
    ml_kem_params.mode = CK_IBM_ML_KEM_DECAPSULATE;
    ml_kem_params.kdf = kdf;
    ml_kem_params.pSharedData = (CK_BYTE *)pSharedData;
    ml_kem_params.ulSharedDataLen = ulSharedDataLen;
    ml_kem_params.bPrepend = prepend;
    ml_kem_params.hSecret = hybrid_key;
    ml_kem_params.ulCipherLen = cipher_len;
    ml_kem_params.pCipher = cipher;

    rc = funcs->C_DeriveKey(session, &mech, priv_key, derive_tmpl,
                            secret_tmpl_len, &secret_key2);
    if (rc != CKR_OK) {
        testcase_error("C_DeriveKey (decapsulation) rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (secret_key1 != CK_INVALID_HANDLE) {
        switch (key_type) {
        case CKK_AES:
            rc = run_AESCrypt(session, secret_key1, secret_key2);
            if (rc != CKR_OK) {
                testcase_fail("Derived keys are not usable or not the same: %s",
                              p11_get_ckr(rc));
                goto testcase_cleanup;
            }
            break;
        case CKK_GENERIC_SECRET:
            rc = run_HMACSign(session, secret_key1, secret_key2, secret_key_len);
            if (rc != CKR_OK) {
                testcase_fail("Derived keys are not usable or not the same: %s",
                              p11_get_ckr(rc));
                goto testcase_cleanup;
            }
            break;
        default:
            testcase_fail("Derived key type can not be tested");
            rc = CKR_FUNCTION_FAILED;
            goto testcase_cleanup;
        }
    }

    if (pExpectedSecret != NULL && ulExpectedSecret != 0) {
        rc = create_GenericSecretKey(session, CKK_GENERIC_SECRET,
                                     (CK_BYTE *)pExpectedSecret,
                                     ulExpectedSecret, &expected_secret_key);
        if (rc != CKR_OK) {
            testcase_fail("create_GenericSecretKey failed: %s",
                          p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = run_HMACSign(session, expected_secret_key, secret_key2,
                          secret_key_len);
        if (rc != CKR_OK) {
            testcase_fail("Derived secret key is not the expected one: %s",
                          p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    rc = CKR_OK;

testcase_cleanup:
    if (cipher != NULL && cipher != pCipher)
        free(cipher);
    if (secret_key1 != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret_key1);
    if (secret_key2 != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret_key2);
    if (hybrid_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, hybrid_key);
    if (expected_secret_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, expected_secret_key);

    return rc;
}

CK_RV run_EnDecapsulateMLKEMwithECDH(CK_SESSION_HANDLE session,
                                    CK_OBJECT_HANDLE priv_key,
                                    CK_OBJECT_HANDLE publ_key,
                                    CK_KEY_TYPE key_type,
                                    CK_ULONG secret_key_len,
                                    CK_IBM_ML_KEM_KDF_TYPE kdf,
                                    const CK_BYTE *pSharedData,
                                    CK_ULONG ulSharedDataLen)
{
    CK_MECHANISM mech;
    CK_IBM_ML_KEM_WITH_ECDH_PARAMS ml_kem_params;
    CK_BYTE *cipher = NULL;
    CK_ULONG cipher_len = 0;
    CK_OBJECT_HANDLE secret_key1 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret_key2 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE ec_priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE ec_pub_key = CK_INVALID_HANDLE;
    CK_RV rc;

    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_ATTRIBUTE  derive_tmpl[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_SENSITIVE, &false, sizeof(false)},
        {CKA_VALUE_LEN, &secret_key_len, sizeof(secret_key_len)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
    };
    CK_ULONG secret_tmpl_len = sizeof(derive_tmpl) / sizeof(CK_ATTRIBUTE);
    CK_BYTE pubkey_value[256];
    CK_ATTRIBUTE  extr_tmpl[] = {
        {CKA_EC_POINT, pubkey_value, sizeof(pubkey_value)},
    };
    CK_ULONG extr_tmpl_len = sizeof(extr_tmpl)/sizeof(CK_ATTRIBUTE);

    mech.mechanism = CKM_IBM_ML_KEM_WITH_ECDH;
    mech.ulParameterLen = sizeof(ml_kem_params);
    mech.pParameter = &ml_kem_params;

    /* Query the slot, check if this mech if supported */
    if (!mech_supported(SLOT_ID, mech.mechanism)) {
        testcase_notice("Slot %u doesn't support %s",
                        (unsigned int) SLOT_ID,
                        p11_get_ckm(&mechtable_funcs, mech.mechanism));
        rc = CKR_MECHANISM_INVALID;
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, CKM_EC_KEY_PAIR_GEN)) {
        testcase_notice("Slot %u doesn't support CKM_EC_KEY_PAIR_GEN\n",
                        (unsigned int) SLOT_ID);
        rc = CKR_MECHANISM_INVALID;
        goto testcase_cleanup;
    }

    if (is_cca_token(SLOT_ID)) {
        if (key_type != CKK_AES) {
            testcase_notice("CCA token in slot %u does only support to derive"
                            " AES keys\n", (unsigned int) SLOT_ID);
            rc = CKR_MECHANISM_INVALID;
            goto testcase_cleanup;
        }

        switch (kdf) {
        case CKD_IBM_HYBRID_SHA224_KDF:
        case CKD_IBM_HYBRID_SHA256_KDF:
        case CKD_IBM_HYBRID_SHA384_KDF:
        case CKD_IBM_HYBRID_SHA512_KDF:
            break;
        default:
            testcase_skip("CCA token in slot %u doesn't support this kdf\n",
                          (unsigned int) SLOT_ID);
            rc = CKR_MECHANISM_INVALID;
            goto testcase_cleanup;
        }
    }

    rc = generate_EC_KeyPair(session, CKM_EC_KEY_PAIR_GEN,
                             (CK_BYTE *)prime256v1, sizeof(prime256v1),
                             &ec_pub_key, &ec_priv_key, CK_FALSE);
    if (rc != CKR_OK) {
        testcase_notice("generate_EC_KeyPair rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_GetAttributeValue(session, ec_pub_key, extr_tmpl, extr_tmpl_len);
    if (rc != CKR_OK) {
        testcase_notice("C_GetAttributeValue: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Perform encapsulation with public key */
    memset(&ml_kem_params, 0, sizeof(ml_kem_params));
    ml_kem_params.mode = CK_IBM_ML_KEM_ENCAPSULATE;
    ml_kem_params.kdf = kdf;
    ml_kem_params.pSharedData = (CK_BYTE *)pSharedData;
    ml_kem_params.ulSharedDataLen = ulSharedDataLen;
    ml_kem_params.hECPrivateKey = ec_priv_key;
    ml_kem_params.pPublicData = extr_tmpl[0].pValue;
    ml_kem_params.ulPublicDataLen = extr_tmpl[0].ulValueLen;

    /* Size query */
    rc = funcs->C_DeriveKey(session, &mech, publ_key, derive_tmpl,
                            secret_tmpl_len, &secret_key1);
    if (rc != CKR_BUFFER_TOO_SMALL) {
        testcase_error("C_DeriveKey (size query) rc=%s (expected CKR_BUFFER_TOO_SMALL)",
                       p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    cipher_len = ml_kem_params.ulCipherLen;
    cipher = calloc(cipher_len, sizeof(CK_BYTE));
    if (cipher == NULL) {
        testcase_error("Can't allocate memory for %lu bytes",
                       sizeof(CK_BYTE) * cipher_len);
        rc = CKR_HOST_MEMORY;
        goto testcase_cleanup;
    }

    ml_kem_params.ulCipherLen = cipher_len;
    ml_kem_params.pCipher = cipher;

    /* Encapsulation */
    rc = funcs->C_DeriveKey(session, &mech, publ_key, derive_tmpl,
                            secret_tmpl_len, &secret_key1);
    if (rc != CKR_OK) {
        testcase_error("C_DeriveKey (encapsulation) rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }
    cipher_len = ml_kem_params.ulCipherLen;

    /* Perform Decapsulation with private key */
    memset(&ml_kem_params, 0, sizeof(ml_kem_params));
    ml_kem_params.mode = CK_IBM_ML_KEM_DECAPSULATE;
    ml_kem_params.kdf = kdf;
    ml_kem_params.pSharedData = (CK_BYTE *)pSharedData;
    ml_kem_params.ulSharedDataLen = ulSharedDataLen;
    ml_kem_params.hECPrivateKey = ec_priv_key;
    ml_kem_params.pPublicData = extr_tmpl[0].pValue;
    ml_kem_params.ulPublicDataLen = extr_tmpl[0].ulValueLen;
    ml_kem_params.ulCipherLen = cipher_len;
    ml_kem_params.pCipher = cipher;

    rc = funcs->C_DeriveKey(session, &mech, priv_key, derive_tmpl,
                            secret_tmpl_len, &secret_key2);
    if (rc != CKR_OK) {
        testcase_error("C_DeriveKey (decapsulation) rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (secret_key1 != CK_INVALID_HANDLE) {
        switch (key_type) {
        case CKK_AES:
            rc = run_AESCrypt(session, secret_key1, secret_key2);
            if (rc != CKR_OK) {
                testcase_fail("Derived keys are not usable or not the same: %s",
                              p11_get_ckr(rc));
                goto testcase_cleanup;
            }
            break;
        case CKK_GENERIC_SECRET:
            rc = run_HMACSign(session, secret_key1, secret_key2, secret_key_len);
            if (rc != CKR_OK) {
                testcase_fail("Derived keys are not usable or not the same: %s",
                              p11_get_ckr(rc));
                goto testcase_cleanup;
            }
            break;
        default:
            testcase_fail("Derived key type can not be tested");
            rc = CKR_FUNCTION_FAILED;
            goto testcase_cleanup;
        }
    }

    rc = CKR_OK;

testcase_cleanup:
    if (cipher != NULL)
        free(cipher);
    if (secret_key1 != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret_key1);
    if (secret_key2 != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret_key2);
    if (ec_priv_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, ec_priv_key);
    if (ec_pub_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, ec_pub_key);

    return rc;
}


CK_RV run_GenerateMLKEMKeyPairKEM(void)
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i, j;
    CK_FLAGS flags;
    CK_RV rc;

    testcase_rw_session();
    testcase_user_login();

    mech.mechanism = CKM_IBM_ML_KEM_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    /* query the slot, check if this mech is supported */
    if (!mech_supported(SLOT_ID, mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s",
                      (unsigned int) SLOT_ID,
                      p11_get_ckm(&mechtable_funcs, mech.mechanism));
        rc = CKR_OK;
        goto testcase_cleanup;
    }

    for (i = 0; i < num_variants; i++) {
        /* Setup attributes for public/private ML-KEM key */
        CK_BBOOL attr_derive = TRUE;
        CK_ATTRIBUTE ml_kem_attr_private[] = {
            {CKA_DERIVE, &attr_derive, sizeof(CK_BBOOL)},
            {CKA_IBM_PARAMETER_SET,
             (CK_BYTE *)&variants[i].parameter_set,
             sizeof(CK_IBM_ML_KEM_PARAMETER_SET_TYPE)},
        };
        CK_ATTRIBUTE ml_kem_attr_public[] = {
            {CKA_DERIVE, &attr_derive, sizeof(CK_BBOOL)},
            {CKA_IBM_PARAMETER_SET,
             (CK_BYTE *)&variants[i].parameter_set,
             sizeof(CK_IBM_ML_KEM_PARAMETER_SET_TYPE)},
        };
        CK_ULONG num_ml_kem_attrs = 2;

        testcase_begin("Starting IBM ML-KEM generate key pair with %s.",
                       variants[i].name);

        /* Generate ML-KEM key pair */
        rc = funcs->C_GenerateKeyPair(session, &mech,
                       ml_kem_attr_public, num_ml_kem_attrs,
                       ml_kem_attr_private, num_ml_kem_attrs,
                       &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_GenerateKeyPair with %s not supported",
                     variants[i].name);
                goto next;
            } else {
                testcase_new_assertion();
                testcase_fail("C_GenerateKeyPair with %s failed, rc=%s",
                     variants[i].name, p11_get_ckr(rc));
                goto testcase_cleanup;
            }
        }
        testcase_new_assertion();
        testcase_pass("Generate ML-KEM key pair with %s  passed.",
                      variants[i].name);

        for (j = 0; j < NUM_KEM_INPUTS; j++) {
            rc = run_EnDecapsulateMLKEM(session, priv_key, publ_key,
                                        kemInput[j].secret_key_type,
                                        kemInput[j].secret_key_len,
                                        kemInput[j].kdf,
                                        kemInput[j].hybrid,
                                        kemInput[j].prepend,
                                        kemInput[j].shared_data,
                                        kemInput[j].shard_data_len,
                                        NULL, 0, NULL, 0);
            if (rc == CKR_MECHANISM_INVALID) {
                testcase_skip("run_EnDecapsulateMLKEM with %s, %s, Shared data len %lu (index %lu).",
                               variants[i].name,
                               p11_get_ckd(kemInput[j].kdf),
                               kemInput[j].shard_data_len,
                               j);
            } else if (rc != 0) {
                testcase_new_assertion();
                testcase_fail("run_EnDecapsulateMLKEM with %s, %s, Shared data len %lu (index %lu) failed.",
                               variants[i].name,
                               p11_get_ckd(kemInput[j].kdf),
                               kemInput[j].shard_data_len,
                               j);
                goto next;
            } else {
                testcase_new_assertion();
                testcase_pass("*%sEncapsulate & Decapsulate (KEM) with %s, %s, Shared data len %lu (index %lu) passed.",
                              kemInput[j].hybrid ? "Hybrid " : "",
                              variants[i].name,
                              p11_get_ckd(kemInput[j].kdf),
                              kemInput[j].shard_data_len,
                              j);
            }

            if (!kemInput[j].hybrid)
                continue;

            rc = run_EnDecapsulateMLKEMwithECDH(session, priv_key, publ_key,
                                                kemInput[j].secret_key_type,
                                                kemInput[j].secret_key_len,
                                                kemInput[j].kdf,
                                                kemInput[j].shared_data,
                                                kemInput[j].shard_data_len);
            if (rc == CKR_MECHANISM_INVALID) {
                testcase_skip("run_EnDecapsulateMLKEMwithECDH with %s, %s, Shared data len %lu (index %lu).",
                                               variants[i].name,
                                               p11_get_ckd(kemInput[j].kdf),
                                               kemInput[j].shard_data_len,
                                               j);
            } else if (rc != 0) {
                testcase_new_assertion();
                testcase_fail("run_EnDecapsulateMLKEMwithECDH with %s, %s, Shared data len %lu (index %lu) failed.",
                               variants[i].name,
                               p11_get_ckd(kemInput[j].kdf),
                               kemInput[j].shard_data_len,
                               j);
                goto next;
            } else {
                testcase_new_assertion();
                testcase_pass("*Combined Encapsulate & Decapsulate (KEM) with ECDH with %s, %s, Shared data len %lu (index %lu) passed.",
                              variants[i].name,
                              p11_get_ckd(kemInput[j].kdf),
                              kemInput[j].shard_data_len,
                              j);
            }
        }

next:
        if (publ_key != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, publ_key);
        publ_key = CK_INVALID_HANDLE;
        if (priv_key != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, priv_key);
        priv_key = CK_INVALID_HANDLE;
    }

    rc = CKR_OK;

testcase_cleanup:
    if (publ_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_key);
    if (priv_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_key);

    testcase_user_logout();
    testcase_close_session();

    return rc;
}

CK_RV run_ImportMLKEMKeyPairSignVerify(void)
{
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i;
    CK_FLAGS flags;
    CK_RV rc;

    testcase_rw_session();
    testcase_user_login();

    /* query the slot, check if this mech is supported */
    if (!mech_supported(SLOT_ID, CKM_IBM_ML_KEM) &&
        !mech_supported(SLOT_ID, CKM_IBM_ML_KEM_WITH_ECDH)) {
        testcase_skip("Slot %u doesn't support CKM_IBM_ML_KEM nor "
                      "CKM_IBM_ML_KEM_WITH_ECDH", (unsigned int) SLOT_ID);
        rc = CKR_OK;
        goto testcase_cleanup;
    }

    for (i = 0; i < ML_KEM_TV_NUM; i++) {

        testcase_begin("Starting IBM ML-KEM import key pair, %s index=%lu",
                       ml_kem_tv[i].name, i);

        /* Create IBM ML-KEM private key */
        rc = create_IBM_ML_KEM_PrivateKey(session,
                                          ml_kem_tv[i].pkcs8,
                                          ml_kem_tv[i].pkcs8_len,
                                          ml_kem_tv[i].parameter_set,
                                          ml_kem_tv[i].sk, ml_kem_tv[i].sk_len,
                                          ml_kem_tv[i].pk, ml_kem_tv[i].pk_len,
                                          ml_kem_tv[i].priv_seed,
                                          ml_kem_tv[i].priv_seed_len,
                                          &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              ml_kem_tv[i].name);
                continue;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM ML-KEM key import is not allowed by policy");
                continue;
            }
            testcase_new_assertion();
            testcase_fail("C_CreateObject (IBM ML-KEM Private Key) failed at "
                          "i=%lu, rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import IBM ML-KEM private key (%s) index=%lu passed.",
                      ml_kem_tv[i].name, i);

        /* Create IBM ML-KEM public key */
        rc = create_IBM_ML_KEM_PublicKey(session,
                                         ml_kem_tv[i].spki,
                                         ml_kem_tv[i].spki_len,
                                         ml_kem_tv[i].parameter_set,
                                         ml_kem_tv[i].pk, ml_kem_tv[i].pk_len,
                                         &publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              ml_kem_tv[i].name);
                goto testcase_cleanup;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM ML-KEM key import is not allowed by policy");
                goto testcase_cleanup;
            }
            testcase_new_assertion();
            testcase_fail("C_CreateObject (IBM ML-KEM Public Key) failed at "
                          "i=%lu, rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import IBM ML-KEM public key (%s) index=%lu passed.",
                      ml_kem_tv[i].name, i);

        /* Test Encapsulate/decapsulate (KEM) */
        rc = run_EnDecapsulateMLKEM(session, priv_key, publ_key, CKK_AES, 32,
                                    CKD_NULL, CK_FALSE, CK_FALSE, NULL, 0,
                                    NULL, 0, NULL, 0);
        if (rc == CKR_MECHANISM_INVALID) {
            testcase_skip("run_EnDecapsulateMLKEM index=%lu.", i);
        } else if (rc != 0) {
            testcase_new_assertion();
            testcase_fail("run_EnDecapsulateMLKEM failed index=%lu.", i);
            goto testcase_cleanup;
        } else {
            testcase_new_assertion();
            testcase_pass("*Encapsulate & Decapsulate (KEM), i=%lu passed.", i);
        }

        rc = run_EnDecapsulateMLKEMwithECDH(session, priv_key, publ_key,
                                            CKK_AES, 32,
                                            CKD_IBM_HYBRID_SHA256_KDF, NULL, 0);
        if (rc == CKR_MECHANISM_INVALID) {
            testcase_skip("run_EnDecapsulateMLKEMwithECDH index=%lu.", i);
        } else if (rc != 0) {
            testcase_new_assertion();
            testcase_fail("run_EnDecapsulateMLKEMwithECDH failed index=%lu.", i);
            goto testcase_cleanup;
        } else {
            testcase_new_assertion();
            testcase_pass("*Combined Encapsulate & Decapsulate (KEM), i=%lu passed.", i);
        }

        /* Clean up */
        rc = funcs->C_DestroyObject(session, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }

        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }
    }

    goto done;

testcase_cleanup:
    if (publ_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_key);
    if (priv_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_key);

done:
    testcase_user_logout();
    testcase_close_session();

    return rc;
}

/**
 * Wraps the given key with the given secret key using the given wrapping
 * mechanism.
 */
CK_RV wrapKey(CK_SESSION_HANDLE session, CK_MECHANISM *wrap_mech,
              CK_OBJECT_HANDLE secret_key, CK_OBJECT_HANDLE key_to_wrap,
              CK_BYTE_PTR *wrapped_key, CK_ULONG *wrapped_keylen)
{
    CK_BYTE_PTR tmp_key;
    CK_ULONG tmp_len;
    CK_RV rc;

    /* Determine length of wrapped key */
    rc = funcs->C_WrapKey(session, wrap_mech, secret_key, key_to_wrap,
                          NULL, &tmp_len);
    if (rc != CKR_OK)
        goto done;

    /* Allocate memory for wrapped_key */
    tmp_key = calloc(tmp_len, sizeof(CK_BYTE));
    if (!tmp_key) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    /* Now wrap the key */
    rc = funcs->C_WrapKey(session, wrap_mech, secret_key, key_to_wrap,
                          tmp_key, &tmp_len);
    if (rc != CKR_OK) {
        free(tmp_key);
        tmp_key = NULL;
        goto done;
    }

    *wrapped_key = tmp_key;
    *wrapped_keylen = tmp_len;

    rc = CKR_OK;

done:

    return rc;
}

/**
 * Unwraps the given wrapped_key using the given secret_key and wrapping
 * mechanism.
 */
CK_RV unwrapKey(CK_SESSION_HANDLE session, CK_MECHANISM *wrap_mech,
                CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_keylen,
                CK_OBJECT_HANDLE secret_key, CK_OBJECT_HANDLE *unwrapped_key)
{
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_IBM_ML_KEM;
    CK_OBJECT_HANDLE tmp_key = CK_INVALID_HANDLE;
    CK_BYTE unwrap_label[] = "unwrapped_private_IBM_ML_KEM_Key";
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_BBOOL true = TRUE;
    CK_RV rc;

    CK_ATTRIBUTE unwrap_tmpl[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, &unwrap_label, sizeof(unwrap_label)},
        {CKA_SUBJECT, subject, sizeof(subject)},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_DERIVE, &true, sizeof(true)},
    };

    rc = funcs->C_UnwrapKey(session, wrap_mech, secret_key,
                            wrapped_key, wrapped_keylen,
                            unwrap_tmpl,
                            sizeof(unwrap_tmpl) / sizeof(CK_ATTRIBUTE),
                            &tmp_key);
    if (rc != CKR_OK)
        goto done;

    *unwrapped_key = tmp_key;

    rc = CKR_OK;

done:

    return rc;
}

CK_RV run_TransferMLKEMKeyPairSignVerify(void)
{
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i;
    CK_FLAGS flags;
    CK_RV rc;
    CK_OBJECT_HANDLE secret_key = CK_INVALID_HANDLE;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_ULONG wrapped_keylen;
    CK_OBJECT_HANDLE unwrapped_key = CK_INVALID_HANDLE;
    CK_MECHANISM wrap_mech, wkey_mech;

    testcase_rw_session();
    testcase_user_login();

    /* query the slot, check if this mech is supported */
    if (!mech_supported(SLOT_ID, CKM_IBM_ML_KEM) &&
        !mech_supported(SLOT_ID, CKM_IBM_ML_KEM_WITH_ECDH)) {
        testcase_skip("Slot %u doesn't support CKM_IBM_ML_KEM nor "
                      "CKM_IBM_ML_KEM_WITH_ECDH", (unsigned int) SLOT_ID);
        rc = CKR_OK;
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, CKM_AES_KEY_GEN)) {
        testcase_skip("Slot %u doesn't support CKM_AES_KEY_GEN",
                      (unsigned int) SLOT_ID);
        rc = CKR_OK;
        goto testcase_cleanup;
    }
    if (!mech_supported_flags(SLOT_ID, CKM_AES_CBC_PAD, CKF_WRAP)) {
        testcase_skip("Slot %u doesn't support key wrapping with CKM_AES_CBC_PAD",
                      (unsigned int) SLOT_ID);
        rc = CKR_OK;
        goto testcase_cleanup;
    }

    for (i = 0; i < ML_KEM_TV_NUM; i++) {

        testcase_begin("Starting IBM ML-KEM transfer key pair, %s index=%lu.",
                       ml_kem_tv[i].name, i);

        /* Create IBM ML-KEM private key */
        rc = create_IBM_ML_KEM_PrivateKey(session,
                                          ml_kem_tv[i].pkcs8,
                                          ml_kem_tv[i].pkcs8_len,
                                          ml_kem_tv[i].parameter_set,
                                          ml_kem_tv[i].sk, ml_kem_tv[i].sk_len,
                                          ml_kem_tv[i].pk, ml_kem_tv[i].pk_len,
                                          ml_kem_tv[i].priv_seed,
                                          ml_kem_tv[i].priv_seed_len,
                                          &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              ml_kem_tv[i].name);
                continue;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM ML-KEM key import is not allowed by policy");
                continue;
            }
            testcase_new_assertion();
            testcase_fail("C_CreateObject (IBM ML-KEM Private Key) failed at "
                          "i=%lu, rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import IBM ML-KEM private key (%s) index=%lu passed.",
                      ml_kem_tv[i].name, i);

        /* Create IBM ML-KEM public key */
        rc = create_IBM_ML_KEM_PublicKey(session,
                                         ml_kem_tv[i].spki,
                                         ml_kem_tv[i].spki_len,
                                         ml_kem_tv[i].parameter_set,
                                         ml_kem_tv[i].pk, ml_kem_tv[i].pk_len,
                                         &publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              ml_kem_tv[i].name);
                goto testcase_cleanup;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM ML-KEM key import is not allowed by policy");
                goto testcase_cleanup;
            }
            testcase_new_assertion();
            testcase_fail("C_CreateObject (IBM ML-KEM Public Key) failed at "
                          "i=%lu,rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import IBM ML-KEM public key (%s) index=%lu passed.",
                      ml_kem_tv[i].name, i);

        /* Create wrapping key (secret key) */
        wkey_mech.mechanism = CKM_AES_KEY_GEN;
        wkey_mech.pParameter = NULL;
        wkey_mech.ulParameterLen = 0;
        rc = generate_AESKey(session, 32, CK_TRUE, &wkey_mech, &secret_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key generation is not allowed by policy");
                goto testcase_cleanup;
            }

            testcase_error("generate_AESKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /* Setup wrapping mechanism */
        wrap_mech.mechanism = CKM_AES_CBC_PAD;
        wrap_mech.pParameter = "0123456789abcdef";
        wrap_mech.ulParameterLen = 16;

        /* Wrap IBM ML-KEM private key with secret key */
        rc = wrapKey(session, &wrap_mech, secret_key, priv_key,
                     &wrapped_key, &wrapped_keylen);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            testcase_error("wrapKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Wrap IBM ML-KEM private key (%s) index=%lu passed.",
                      ml_kem_tv[i].name, i);

        /* Unwrap IBM ML-KEM private key */
        rc = unwrapKey(session, &wrap_mech, wrapped_key, wrapped_keylen,
                       secret_key, &unwrapped_key);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            testcase_error("unwrapKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Unwrap IBM ML-KEM private key (%s) index=%lu passed.",
                      ml_kem_tv[i].name, i);

        free(wrapped_key);
        wrapped_key = NULL;

        /* Test Encapsulate/decapsulate (KEM) */
        rc = run_EnDecapsulateMLKEM(session, unwrapped_key, publ_key, CKK_AES, 32,
                                    CKD_NULL, CK_FALSE, CK_FALSE, NULL, 0,
                                    NULL, 0, NULL, 0);
        if (rc == CKR_MECHANISM_INVALID) {
            testcase_skip("run_EnDecapsulateMLKEM index=%lu.", i);
        } else if (rc != 0) {
            testcase_new_assertion();
            testcase_fail("run_EnDecapsulateMLKEM failed index=%lu.", i);
            goto testcase_cleanup;
        } else {
            testcase_new_assertion();
            testcase_pass("*Encapsulate & Decapsulate (KEM), i=%lu passed.", i);
        }

        rc = run_EnDecapsulateMLKEMwithECDH(session, unwrapped_key, publ_key,
                                            CKK_AES, 32,
                                            CKD_IBM_HYBRID_SHA256_KDF, NULL, 0);
        if (rc == CKR_MECHANISM_INVALID) {
            testcase_skip("run_EnDecapsulateMLKEMwithECDH index=%lu.", i);
        } else if (rc != 0) {
            testcase_new_assertion();
            testcase_fail("run_EnDecapsulateMLKEMwithECDH failed index=%lu.", i);
            goto testcase_cleanup;
        } else {
            testcase_new_assertion();
            testcase_pass("*Combined Encapsulate & Decapsulate (KEM), i=%lu passed.", i);
        }

        /* Clean up */
        rc = funcs->C_DestroyObject(session, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }

        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }

        rc = funcs->C_DestroyObject(session, secret_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }

        rc = funcs->C_DestroyObject(session, unwrapped_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }
    }

    goto done;

testcase_cleanup:
    if (publ_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_key);
    if (priv_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_key);
    if (secret_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret_key);
    if (unwrapped_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, unwrapped_key);

    if (wrapped_key)
        free(wrapped_key);

done:
    testcase_user_logout();
    testcase_close_session();

    return rc;
}

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int rc;
    CK_RV rv;

    rc = do_ParseArgs(argc, argv);
    if (rc != 1)
        return rc;

    printf("Using slot #%lu...\n\n", SLOT_ID);
    printf("With option: no_init: %d\n", no_init);

    rc = do_GetFunctionList();
    if (!rc) {
        PRINT_ERR("ERROR do_GetFunctionList() Failed , rc = 0x%0x\n", rc);
        return rc;
    }

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

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

    rv = run_GenerateMLKEMKeyPairKEM();
    rv |= run_ImportMLKEMKeyPairSignVerify();
    rv |= run_TransferMLKEMKeyPairSignVerify();

    testcase_print_result();

    funcs->C_Finalize(NULL);

    return testcase_return(rv);
}
