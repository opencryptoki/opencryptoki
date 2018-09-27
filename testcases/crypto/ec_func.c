/*
 * COPYRIGHT (c) International Business Machines Corp. 2011-2017
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
#include "ec.h"
#include "defs.h"

/*
 * Below is a list for the OIDs and DER encodings of the brainpool.
 * Beginning of each DER encoding should be 06 for OID and 09 for the length.
 * For example brainpoolP160r1 should be 06092B2403030208010101
 * brainpoolP160r1
 *		1.3.36.3.3.2.8.1.1.1
 *		2B2403030208010101
 * brainpoolP160t1
 *		1.3.36.3.3.2.8.1.1.2
 *		2B2403030208010102
 * brainpoolP192r1
 *		1.3.36.3.3.2.8.1.1.3
 *		2B2403030208010103
 * brainpoolP192t1
 *		1.3.36.3.3.2.8.1.1.4
 *		2B2403030208010104
 * brainpoolP224r1
 *		1.3.36.3.3.2.8.1.1.5
 *		2B2403030208010105
 * brainpoolP224t1
 *		1.3.36.3.3.2.8.1.1.6
 *		2B2403030208010106
 * brainpoolP256r1
 *		1.3.36.3.3.2.8.1.1.7
 *		2B2403030208010107
 * brainpoolP256t1
 *		1.3.36.3.3.2.8.1.1.8
 *		2B2403030208010108
 * brainpoolP320r1
 *		1.3.36.3.3.2.8.1.1.9
 *		2B2403030208010109
 * brainpoolP320t1
 *		1.3.36.3.3.2.8.1.1.10
 *		2B240303020801010A
 * brainpoolP384r1
 *		1.3.36.3.3.2.8.1.1.11
 *		2B240303020801010B
 * brainpoolP384t1
 *		1.3.36.3.3.2.8.1.1.12
 *		2B240303020801010C
 * brainpoolP512r1
 *		1.3.36.3.3.2.8.1.1.13
 *		2B240303020801010D
 * brainpoolP512t1
 *		1.3.36.3.3.2.8.1.1.14
 *		2B240303020801010E
 * prime192
 *		1.2.840.10045.3.1.1
 *		2A8648CE3D030101
 * secp224
 *		1.3.132.0.33
 *		2B81040021
 * prime256
 *		1.2.840.10045.3.1.7
 *		2A8648CE3D030107
 * secp384
 *		1.3.132.0.34
 *		2B81040022
 * secp521
 *		1.3.132.0.35
 *		2B81040023
 */

CK_ULONG total_assertions = 65;

typedef struct ec_struct {
    void const *curve;
    CK_ULONG size;
    CK_BBOOL twisted;
} _ec_struct;

/* Supported Elliptic Curves */
#define NUMEC		20
const CK_BYTE brainpoolP160r1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01 };
const CK_BYTE brainpoolP160t1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x02 };
const CK_BYTE brainpoolP192r1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03 };
const CK_BYTE brainpoolP192t1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x04 };
const CK_BYTE brainpoolP224r1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05 };
const CK_BYTE brainpoolP224t1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x06 };
const CK_BYTE brainpoolP256r1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
const CK_BYTE brainpoolP256t1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x08 };
const CK_BYTE brainpoolP320r1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09 };
const CK_BYTE brainpoolP320t1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0A };
const CK_BYTE brainpoolP384r1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B };
const CK_BYTE brainpoolP384t1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0C };
const CK_BYTE brainpoolP512r1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D };
const CK_BYTE brainpoolP512t1[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0E };
const CK_BYTE prime192[] =
    { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 };
const CK_BYTE secp224[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21 };
const CK_BYTE prime256[] =
    { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
const CK_BYTE secp384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
const CK_BYTE secp521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };
const CK_BYTE secp256k1[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x0A };

const _ec_struct der_ec_supported[NUMEC] = {
    {&brainpoolP160r1, sizeof(brainpoolP160r1), CK_FALSE},
    {&brainpoolP160t1, sizeof(brainpoolP160t1), CK_TRUE},
    {&brainpoolP192r1, sizeof(brainpoolP192r1), CK_FALSE},
    {&brainpoolP192t1, sizeof(brainpoolP192t1), CK_TRUE},
    {&brainpoolP224r1, sizeof(brainpoolP224r1), CK_FALSE},
    {&brainpoolP224t1, sizeof(brainpoolP224t1), CK_TRUE},
    {&brainpoolP256r1, sizeof(brainpoolP256r1), CK_FALSE},
    {&brainpoolP256t1, sizeof(brainpoolP256t1), CK_TRUE},
    {&brainpoolP320r1, sizeof(brainpoolP320r1), CK_FALSE},
    {&brainpoolP320t1, sizeof(brainpoolP320t1), CK_TRUE},
    {&brainpoolP384r1, sizeof(brainpoolP384r1), CK_FALSE},
    {&brainpoolP384t1, sizeof(brainpoolP384t1), CK_TRUE},
    {&brainpoolP512r1, sizeof(brainpoolP512r1), CK_FALSE},
    {&brainpoolP512t1, sizeof(brainpoolP512t1), CK_TRUE},
    {&prime192, sizeof(prime192), CK_FALSE},
    {&secp224, sizeof(secp224), CK_FALSE},
    {&prime256, sizeof(prime256), CK_FALSE},
    {&secp384, sizeof(secp384), CK_FALSE},
    {&secp521, sizeof(secp521), CK_FALSE},
    {&secp256k1, sizeof(secp256k1), CK_FALSE}
};

/* Invalid curves */
#define NUMECINVAL	4
const CK_BYTE invalidCurve[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x08, 0x08, 0x01, 0x01, 0x01 };
const CK_BYTE invalidLen1[] =
    { 0x06, 0x0A, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01 };
const CK_BYTE invalidLen2[] =
    { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01 };
const CK_BYTE invalidOIDfield[] =
    { 0x05, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01 };

const _ec_struct der_ec_notsupported[NUMECINVAL] = {
    {&invalidCurve, sizeof(invalidCurve), CK_FALSE},
    {&invalidLen1, sizeof(invalidLen1), CK_FALSE},
    {&invalidLen2, sizeof(invalidLen2), CK_FALSE},
    {&invalidOIDfield, sizeof(invalidOIDfield), CK_FALSE}
};

typedef struct signVerifyParam {
    CK_MECHANISM_TYPE mechtype;
    CK_ULONG inputlen;
    CK_ULONG parts;             /* 0 means process in 1 chunk via C_Sign,
                                 * >0 means process in n chunks via
                                 * C_SignUpdate/C_SignFinal
                                 */
} _signVerifyParam;


_signVerifyParam signVerifyInput[] = {
    {CKM_ECDSA, 20, 0},
    {CKM_ECDSA, 32, 0},
    {CKM_ECDSA, 48, 0},
    {CKM_ECDSA, 64, 0},
    {CKM_ECDSA_SHA1, 100, 0},
    {CKM_ECDSA_SHA1, 100, 4},
    {CKM_ECDSA_SHA224, 100, 0},
    {CKM_ECDSA_SHA224, 100, 4},
    {CKM_ECDSA_SHA256, 100, 0},
    {CKM_ECDSA_SHA256, 100, 4},
    {CKM_ECDSA_SHA384, 100, 0},
    {CKM_ECDSA_SHA384, 100, 4},
    {CKM_ECDSA_SHA512, 100, 0},
    {CKM_ECDSA_SHA512, 100, 4}
};

#define NUM_KDFS sizeof(kdfs)/sizeof(CK_EC_KDF_TYPE)
static CK_EC_KDF_TYPE kdfs[] = {
    CKD_NULL,
    CKD_SHA1_KDF,
    CKD_SHA224_KDF,
    CKD_SHA256_KDF,
    CKD_SHA384_KDF,
    CKD_SHA512_KDF,
};

static unsigned int curve_len(int index)
{
    switch (index) {
    case 0:
    case 1:
        return CURVE160_LENGTH/8;
    case 2:
    case 3:
        return CURVE192_LENGTH/8;
    case 4:
    case 5:
        return CURVE224_LENGTH/8;
    case 6:
    case 7:
        return CURVE256_LENGTH/8;
    case 8:
    case 9:
        return CURVE320_LENGTH/8;
    case 10:
    case 11:
        return CURVE384_LENGTH/8;
    case 12:
    case 13:
        return CURVE512_LENGTH/8;
    case 14:
        return CURVE192_LENGTH/8;
    case 15:
        return CURVE224_LENGTH/8;
    case 16:
        return CURVE256_LENGTH/8;
    case 17:
        return CURVE384_LENGTH/8;
    case 18:
        return CURVE521_LENGTH/8+1;
    case 19:
        return CURVE256_LENGTH/8;
    }

    return 0;
}

static CK_RV curve_supported(const char *name)
{
    if (name[strlen(name) - 2] == 'r' || name[strlen(name) - 2] == 'v')
        return 1;

    return 0;
}

/**
 * A test is skipped for the ep11token, when the derived key length
 * shall be bigger than the shared secret (z-value). The ep11token is
 * currently based on PKCS#11 v2.20 where no KDF is considered.
 * This restriction comes from the ep11 host library.
 */
static unsigned int too_many_key_bytes_requested_ep11(unsigned int curve,
                                                      unsigned int kdf,
                                                      unsigned int keylen)
{
    UNUSED(kdf);

    if (!is_ep11_token(SLOT_ID))
        return 0;

    if (keylen <= curve_len(curve))
        return 0;

    return 1;
}

/**
 * A test is skipped, when no KDF is used and the derived key length
 * shall be bigger than the shared secret (z-value). Without a KDF, max
 * z-length key bytes can be derived.
 */
static unsigned int too_many_key_bytes_requested(unsigned int curve,
                                                 unsigned int kdf,
                                                 unsigned int keylen)
{
    if (kdf > 0 || keylen <= curve_len(curve))
        return 0;

    return 1;
}

/*
 * Generate EC key-pairs for parties A and B.
 * Derive shared secrets based on Diffie Hellman key agreement defined in PKCS#3
 */
CK_RV run_DeriveECDHKey()
{
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech;
    CK_FLAGS flags;
    CK_OBJECT_HANDLE publ_keyA = CK_INVALID_HANDLE,
                     priv_keyA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE publ_keyB = CK_INVALID_HANDLE,
                     priv_keyB = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret_keyA = CK_INVALID_HANDLE,
                     secret_keyB = CK_INVALID_HANDLE;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc = CKR_OK;
    CK_ECDH1_DERIVE_PARAMS ecdh_parmA, ecdh_parmB;
    CK_BBOOL true = CK_TRUE;
    CK_BBOOL false = CK_FALSE;
    CK_BYTE pubkeyA_value[256];
    CK_BYTE pubkeyB_value[256];
    CK_BYTE secretA_value[80000]; //enough space for lengths in secret_key_len[]
    CK_BYTE deriveB_value[80000];
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_ULONG i, j, k, m;

    testcase_begin("starting run_DeriveECDHKey...");
    testcase_rw_session();
    testcase_user_login();

    if (!mech_supported(SLOT_ID, CKM_EC_KEY_PAIR_GEN)) {
        testcase_skip("Slot %u doesn't support CKM_EC_KEY_PAIR_GEN\n",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, CKM_ECDH1_DERIVE)) {
        testcase_skip("Slot %u doesn't support CKM_ECDH1_DERIVE\n",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

    for (i=0; i<NUMEC; i++) {
        CK_ATTRIBUTE prv_attr[] = {
            {CKA_SIGN, &true, sizeof(true)},
            {CKA_EXTRACTABLE, &true, sizeof(true)},
            {CKA_DERIVE, &true, sizeof(true)},
        };
        CK_ULONG prv_attr_len = sizeof(prv_attr)/sizeof(CK_ATTRIBUTE);

        CK_ATTRIBUTE pub_attr[] = {
            {CKA_ECDSA_PARAMS, (CK_VOID_PTR)der_ec_supported[i].curve,
             der_ec_supported[i].size},
            {CKA_VERIFY, &true, sizeof(true)},
            {CKA_MODIFIABLE, &true, sizeof(true)},
        };
        CK_ULONG pub_attr_len = sizeof(pub_attr)/sizeof(CK_ATTRIBUTE);

        CK_ATTRIBUTE  extr1_tmpl[] = {
            {CKA_EC_POINT, pubkeyA_value, sizeof(pubkeyA_value)},
        };
        CK_ULONG extr1_tmpl_len = sizeof(extr1_tmpl)/sizeof(CK_ATTRIBUTE);

        CK_ATTRIBUTE  extr2_tmpl[] = {
            {CKA_EC_POINT, pubkeyB_value, sizeof(pubkeyB_value)},
        };
        CK_ULONG extr2_tmpl_len = sizeof(extr2_tmpl)/sizeof(CK_ATTRIBUTE);

        if (!is_ep11_token(SLOT_ID)) {
            if (der_ec_supported[i].twisted) {
                testcase_skip("Slot %u doesn't support this curve",
                              (unsigned int) SLOT_ID);
                continue;
            }
            if (der_ec_supported[i].curve == secp256k1) {
                testcase_skip("Slot %u doesn't support this curve",
                              (unsigned int) SLOT_ID);
                continue;
            }
        }

        // Testcase #1 - Generate 2 EC key pairs.

        // First, generate the EC key pair for party A
        mech.mechanism = CKM_EC_KEY_PAIR_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        rc = funcs->C_GenerateKeyPair(session, &mech,
                                      pub_attr, pub_attr_len,
                                      prv_attr, prv_attr_len,
                                      &publ_keyA, &priv_keyA);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID ||
                rc == CKR_ATTRIBUTE_VALUE_INVALID) {
                testcase_skip("Slot %u doesn't support this curve",
                              (unsigned int) SLOT_ID);
                continue;
            }
            testcase_fail("C_GenerateKeyPair with valid input failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Extract public key A
        rc = funcs->C_GetAttributeValue(session, publ_keyA,
                                        extr1_tmpl, extr1_tmpl_len);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #1: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Now generate the EC key pair for party B
        mech.mechanism = CKM_EC_KEY_PAIR_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        rc = funcs->C_GenerateKeyPair(session, &mech,
                                      pub_attr, pub_attr_len,
                                      prv_attr, prv_attr_len,
                                      &publ_keyB, &priv_keyB);
        if (rc != CKR_OK) {
            testcase_fail("C_GenerateKeyPair with valid input failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Extract public key B
        rc = funcs->C_GetAttributeValue(session, publ_keyB,
                                        extr2_tmpl, extr2_tmpl_len);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #1: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Check if the key lengths are equal
        if (extr1_tmpl->ulValueLen != extr2_tmpl->ulValueLen) {
            testcase_error("Length of public key A not equal to length of "
                           "public key B");
            goto testcase_cleanup;
        }

        // Testcase #2 - Now derive the secrets...

        for (j=0; j < NUM_KDFS; j++) {

            for (k=0; k<NUM_SECRET_KEY_LENGTHS; k++) {

                if (too_many_key_bytes_requested(i, j, secret_key_len[k]) ||
                    too_many_key_bytes_requested_ep11(i, j,
                                                      secret_key_len[k])) {
                    testcase_skip("Cannot provide %lu key bytes with curve %lu"
                                  " without a kdf.\n", secret_key_len[k], i);
                    continue;
                }

                CK_ATTRIBUTE  secretA_tmpl[] = {
                    {CKA_VALUE, secretA_value, sizeof(secretA_value)},
                };
                CK_ULONG secretA_tmpl_len =
                    sizeof(secretA_tmpl) / sizeof(CK_ATTRIBUTE);

                CK_ATTRIBUTE  secretB_tmpl[] = {
                    {CKA_VALUE, deriveB_value, sizeof(deriveB_value)},
                };
                CK_ULONG secretB_tmpl_len =
                    sizeof(secretB_tmpl) / sizeof(CK_ATTRIBUTE);

                CK_ATTRIBUTE  derive_tmpl[] = {
                    {CKA_CLASS, &class, sizeof(class)},
                    {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
                    {CKA_VALUE_LEN, &(secret_key_len[k]), sizeof(CK_ULONG)},
                    {CKA_SENSITIVE, &false, sizeof(false)},
                };
                CK_ULONG secret_tmpl_len =
                    sizeof(derive_tmpl) / sizeof(CK_ATTRIBUTE);

                for (m=0; m<NUM_SHARED_DATA; m++) {

                    testcase_new_assertion();
                    testcase_begin("Starting with ec=%lu, kdf=%lu, keylen=%lu, shared_data=%lu", i,j,k,m);

                    // Now, derive a generic secret key using party A's private
                    // key and B's public key

                    if (is_ep11_token(SLOT_ID)) {
                        /* ep11token does not support KDFs nor shared data */
                        if (kdfs[j] != CKD_NULL || shared_data[m].length > 0) {
                            testcase_skip("EP11 does not support KDFs and shared data\n");
                            continue;
                        }
                    }

                    ecdh_parmA.kdf = kdfs[j];
                    ecdh_parmA.pPublicData = extr2_tmpl->pValue;
                    ecdh_parmA.ulPublicDataLen = extr2_tmpl->ulValueLen;
                    ecdh_parmA.pSharedData =
                        shared_data[m].length == 0 ?
                            NULL : (CK_BYTE_PTR) &shared_data[m].data;
                    ecdh_parmA.ulSharedDataLen = shared_data[m].length;

                    if (kdfs[j] == CKD_NULL) {
                        ecdh_parmA.pSharedData = NULL;
                        ecdh_parmA.ulSharedDataLen = 0;
                    }

                    mech.mechanism = CKM_ECDH1_DERIVE;
                    mech.ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);
                    mech.pParameter = &ecdh_parmA;

                    rc = funcs->C_DeriveKey(session, &mech,
                                            priv_keyA, derive_tmpl,
                                            secret_tmpl_len, &secret_keyA);
                    if (rc != CKR_OK) {
                        testcase_fail("C_DeriveKey #1: rc = %s",
                                      p11_get_ckr(rc));
                        goto testcase_cleanup;
                    }

                    // Now, derive a generic secret key using B's private key
                    // and A's public key

                    if (is_ep11_token(SLOT_ID)) {
                        /* ep11token does not support KDFs nor shared data */
                        if (kdfs[j] != CKD_NULL || shared_data[m].length > 0) {
                            testcase_skip("EP11 does not support KDFs and shared data\n");
                            continue;
                        }
                    }

                    ecdh_parmB.kdf = kdfs[j];
                    ecdh_parmB.pPublicData = extr1_tmpl->pValue;
                    ecdh_parmB.ulPublicDataLen = extr1_tmpl->ulValueLen;
                    ecdh_parmB.pSharedData =
                        shared_data[m].length == 0 ?
                            NULL : (CK_BYTE_PTR)&shared_data[m].data;
                    ecdh_parmB.ulSharedDataLen = shared_data[m].length;

                    if (kdfs[j] == CKD_NULL) {
                        ecdh_parmB.pSharedData = NULL;
                        ecdh_parmB.ulSharedDataLen = 0;
                    }

                    mech.mechanism = CKM_ECDH1_DERIVE;
                    mech.ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);
                    mech.pParameter = &ecdh_parmB;

                    rc = funcs->C_DeriveKey(session, &mech,
                                            priv_keyB, derive_tmpl,
                                            secret_tmpl_len, &secret_keyB);
                    if (rc != CKR_OK) {
                        testcase_fail("C_DeriveKey #2: rc = %s",
                                      p11_get_ckr(rc));
                        goto testcase_cleanup;
                    }

                    // Extract the derived secret A
                    rc = funcs->C_GetAttributeValue(session, secret_keyA,
                                                    secretA_tmpl,
                                                    secretA_tmpl_len);
                    if (rc != CKR_OK) {
                        testcase_error("C_GetAttributeValue #3:rc = %s",
                                       p11_get_ckr(rc));
                        goto testcase_cleanup;
                    }

                    // Extract the derived secret B
                    rc = funcs->C_GetAttributeValue(session, secret_keyB,
                                                    secretB_tmpl,
                                                    secretB_tmpl_len);
                    if (rc != CKR_OK) {
                        testcase_error("C_GetAttributeValue #4:rc = %s",
                                       p11_get_ckr(rc));
                        goto testcase_cleanup;
                    }

                    // Compare lengths of derived secrets from key object
                    if (secretA_tmpl[0].ulValueLen !=
                        secretB_tmpl[0].ulValueLen) {
                        testcase_fail("ERROR:derived key #1 length = %ld, "
                                      "derived key #2 length = %ld",
                                      secretA_tmpl[0].ulValueLen,
                                      secretB_tmpl[0].ulValueLen);
                        goto testcase_cleanup;
                    }

                    // Compare derive secrets A and B
                    if (memcmp(secretA_tmpl[0].pValue,
                               secretB_tmpl[0].pValue,
                               secretA_tmpl[0].ulValueLen) != 0) {
                        testcase_fail("ERROR:derived key mismatch, ec=%lu, "
                                      "kdf=%lu, keylen=%lu, shared_data=%lu",
                                      i, j, k, m);
                        goto testcase_cleanup;
                    }

                    testcase_pass("*Derive shared secret ec=%lu, kdf=%lu, "
                                  "keylen=%lu, shared_data=%lu passed.",
                                  i, j, k, m);

                    if (secret_keyA != CK_INVALID_HANDLE)
                        funcs->C_DestroyObject(session, secret_keyA);
                    if (secret_keyB != CK_INVALID_HANDLE)
                        funcs->C_DestroyObject(session, secret_keyB);
                }
            }
        }

        if (publ_keyA != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, publ_keyA);
        if (priv_keyA != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, priv_keyA);
        if (priv_keyB != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, priv_keyB);
        if (publ_keyB != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, publ_keyB);
    }

testcase_cleanup:
    if (publ_keyA != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_keyA);
    if (priv_keyA != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_keyA);
    if (priv_keyB != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_keyB);
    if (publ_keyB != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_keyB);
    if (secret_keyA != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret_keyA);
    if (secret_keyB != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret_keyB);

    testcase_user_logout();
    testcase_close_session();

	return rc;
} /* end run_DeriveECDHKey() */

/*
 * Run some ECDH known answer tests.
 */
CK_RV run_DeriveECDHKeyKAT()
{
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech;
    CK_FLAGS flags;
    CK_OBJECT_HANDLE publ_keyA = CK_INVALID_HANDLE,
                     priv_keyA = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE publ_keyB = CK_INVALID_HANDLE,
                     priv_keyB = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret_keyA = CK_INVALID_HANDLE,
                     secret_keyB = CK_INVALID_HANDLE;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_KEY_TYPE secret_key_type = CKK_GENERIC_SECRET;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_ECDH1_DERIVE_PARAMS ecdh_parmA, ecdh_parmB;
    CK_BBOOL false = CK_FALSE;
    CK_ULONG user_pin_len;
    CK_RV rc = CKR_OK;
    CK_BYTE secretA_value[1000]; // enough space for key lengths in ecdh_tv[]
    CK_BYTE secretB_value[1000];
    CK_ULONG i;

    testcase_begin("starting run_DeriveECDHKeyKAT...");
    testcase_rw_session();
    testcase_user_login();

    if (!mech_supported(SLOT_ID, CKM_ECDH1_DERIVE)) {
        testcase_skip("Slot %u doesn't support CKM_ECDH1_DERIVE\n",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

    if (is_ep11_token(SLOT_ID)) {
        testcase_skip("This testcase uses KDFs, currently not "
                      "supported by ep11token.\n");
        goto testcase_cleanup;
    }

    for (i=0; i<ECDH_TV_NUM; i++) {

        testcase_new_assertion();
        testcase_begin("Starting with shared secret i=%lu", i);

        // First, import the EC key pair for party A
        rc = create_ECPrivateKey(session,
                                 ecdh_tv[i].params, ecdh_tv[i].params_len,
                                 ecdh_tv[i].privkeyA, ecdh_tv[i].privkey_len,
                                 ecdh_tv[i].pubkeyA, ecdh_tv[i].pubkey_len,
                                 &priv_keyA);
        if (rc != CKR_OK) {
            testcase_fail("C_CreateObject (EC Private Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = create_ECPublicKey(session,
                                ecdh_tv[i].params, ecdh_tv[i].params_len,
                                ecdh_tv[i].pubkeyA, ecdh_tv[i].pubkey_len,
                                &publ_keyA);
        if (rc != CKR_OK) {
            testcase_fail("C_CreateObject (EC Public Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Now import the EC key pair for party B
        rc = create_ECPrivateKey(session,
                                 ecdh_tv[i].params, ecdh_tv[i].params_len,
                                 ecdh_tv[i].privkeyB, ecdh_tv[i].privkey_len,
                                 ecdh_tv[i].pubkeyB, ecdh_tv[i].pubkey_len,
                                 &priv_keyB);
        if (rc != CKR_OK) {
            testcase_fail("C_CreateObject (EC Private Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = create_ECPublicKey(session,
                                ecdh_tv[i].params, ecdh_tv[i].params_len,
                                ecdh_tv[i].pubkeyB, ecdh_tv[i].pubkey_len,
                                &publ_keyB);
        if (rc != CKR_OK) {
            testcase_fail("C_CreateObject (EC Public Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Now derive the secrets...

        CK_ATTRIBUTE  secretA_tmpl[] = {
            {CKA_VALUE, secretA_value, sizeof(secretA_value)}
        };
        CK_ULONG secretA_tmpl_len = sizeof(secretA_tmpl) / sizeof(CK_ATTRIBUTE);

        CK_ATTRIBUTE  secretB_tmpl[] = {
            {CKA_VALUE, secretB_value, sizeof(secretB_value)}
        };
        CK_ULONG secretB_tmpl_len = sizeof(secretB_tmpl) / sizeof(CK_ATTRIBUTE);

        CK_ATTRIBUTE  derive_tmpl[] = {
            {CKA_CLASS, &class, sizeof(class)},
            {CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type)},
            {CKA_VALUE_LEN, &(ecdh_tv[i].derived_key_len), sizeof(CK_ULONG)},
            {CKA_SENSITIVE, &false, sizeof(false)},
        };
        CK_ULONG derive_tmpl_len = sizeof(derive_tmpl) / sizeof(CK_ATTRIBUTE);

        testcase_new_assertion();

        // Now, derive a generic secret key using party A's private key
        // and B's public key

        if (is_ep11_token(SLOT_ID)) {
            /* ep11token does not support KDFs nor shared data */
            if (ecdh_tv[i].kdf != CKD_NULL || ecdh_tv[i].shared_data_len > 0) {
                testcase_skip("EP11 does not support KDFs and shared data\n");
                continue;
            }
        }

        ecdh_parmA.kdf = ecdh_tv[i].kdf;
        ecdh_parmA.pPublicData = ecdh_tv[i].pubkeyB;
        ecdh_parmA.ulPublicDataLen = ecdh_tv[i].pubkey_len;
        ecdh_parmA.pSharedData =
            ecdh_tv[i].shared_data_len == 0 ?
                NULL : (CK_BYTE_PTR)&ecdh_tv[i].shared_data;
        ecdh_parmA.ulSharedDataLen = ecdh_tv[i].shared_data_len;

        if (ecdh_tv[i].kdf == CKD_NULL) {
            ecdh_parmA.pSharedData = NULL;
            ecdh_parmA.ulSharedDataLen = 0;
        }

        mech.mechanism  = CKM_ECDH1_DERIVE;
        mech.ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);
        mech.pParameter = &ecdh_parmA;

        rc = funcs->C_DeriveKey(session, &mech,
                                priv_keyA, derive_tmpl,
                                derive_tmpl_len, &secret_keyA);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey #1: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Now, derive a generic secret key using B's private key and
        // A's public key

        if (is_ep11_token(SLOT_ID)) {
            /* ep11token does not support KDFs nor shared data */
            if (ecdh_tv[i].kdf != CKD_NULL || ecdh_tv[i].shared_data_len > 0) {
                testcase_skip("EP11 does not support KDFs and shared data\n");
                continue;
            }
        }

        ecdh_parmB.kdf = ecdh_tv[i].kdf;
        ecdh_parmB.pPublicData = ecdh_tv[i].pubkeyA;
        ecdh_parmB.ulPublicDataLen = ecdh_tv[i].pubkey_len;
        ecdh_parmB.pSharedData =
            ecdh_tv[i].shared_data_len == 0 ?
                NULL : (CK_BYTE_PTR)&ecdh_tv[i].shared_data;
        ecdh_parmB.ulSharedDataLen = ecdh_tv[i].shared_data_len;

        if (ecdh_tv[i].kdf == CKD_NULL) {
            ecdh_parmB.pSharedData = NULL;
            ecdh_parmB.ulSharedDataLen = 0;
        }

        mech.mechanism = CKM_ECDH1_DERIVE;
        mech.ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);
        mech.pParameter = &ecdh_parmB;

        rc = funcs->C_DeriveKey(session, &mech,
                                priv_keyB, derive_tmpl,
                                derive_tmpl_len, &secret_keyB);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey #2: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Extract the derived secret A
        rc = funcs->C_GetAttributeValue(session, secret_keyA,
                                        secretA_tmpl, secretA_tmpl_len);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #3:rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Compare lengths of derived secret from key object
        if (ecdh_tv[i].derived_key_len != secretA_tmpl[0].ulValueLen) {
            testcase_fail("ERROR:derived key #1 length = %ld, "
                          "derived key #2 length = %ld",
                          ecdh_tv[i].derived_key_len,
                          secretA_tmpl[0].ulValueLen);
            goto testcase_cleanup;
        }

        // Compare with known value
        if (memcmp(secretA_tmpl[0].pValue,
                   ecdh_tv[i].derived_key, ecdh_tv[i].derived_key_len) != 0) {
            testcase_fail("ERROR:derived key mismatch, i=%lu",i);
            goto testcase_cleanup;
        }

        // Extract the derived secret B
        rc = funcs->C_GetAttributeValue(session, secret_keyB,
                                        secretB_tmpl, secretB_tmpl_len);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #4:rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Compare lengths of derived secret from key object
        if (ecdh_tv[i].derived_key_len != secretB_tmpl[0].ulValueLen) {
            testcase_fail("ERROR:derived key #1 length = %ld, derived key #2 "
                          "length = %ld", ecdh_tv[i].derived_key_len,
                          secretB_tmpl[0].ulValueLen);
            goto testcase_cleanup;
        }

        // Compare with known value
        if (memcmp(secretB_tmpl[0].pValue,
                   ecdh_tv[i].derived_key, ecdh_tv[i].derived_key_len) != 0) {
            testcase_fail("ERROR:derived key mismatch, i=%lu",i);
            goto testcase_cleanup;
        }

        testcase_pass("*Derive shared secret i=%lu passed.", i);

        if (priv_keyA != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, priv_keyA);
        if (publ_keyA != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, publ_keyA);
        if (priv_keyB != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, priv_keyB);
        if (publ_keyB != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, publ_keyB);
        if (secret_keyA != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, secret_keyA);
        if (secret_keyB != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, secret_keyB);
    }

testcase_cleanup:
    if (priv_keyA != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_keyA);
    if (publ_keyA != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_keyA);
    if (priv_keyB != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_keyB);
    if (publ_keyB != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_keyB);
    if (secret_keyA != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret_keyA);
    if (secret_keyB != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret_keyB);

    testcase_user_logout();
    testcase_close_session();

    return rc;
} /* end run_DeriveECDHKeyKAT() */

CK_RV run_GenerateSignVerifyECC(CK_SESSION_HANDLE session,
                                CK_MECHANISM_TYPE mechType,
                                CK_ULONG inputlen,
                                CK_ULONG parts,
                                CK_OBJECT_HANDLE priv_key,
                                CK_OBJECT_HANDLE publ_key)
{
    CK_MECHANISM mech2;
    CK_BYTE_PTR data = NULL, signature = NULL;
    CK_ULONG i, signaturelen;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    testcase_begin("Starting with mechtype='%s', inputlen=%lu parts=%lu",
                   p11_get_ckm(mechType), inputlen, parts);

    mech2.mechanism = mechType;
    mech2.ulParameterLen = 0;
    mech2.pParameter = NULL;

    /* query the slot, check if this mech if supported */
    rc = funcs->C_GetMechanismInfo(SLOT_ID, mech2.mechanism, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for EC key gen? skip */
            testcase_skip("Slot %u doesn't support %s",
                          (unsigned int) SLOT_ID, p11_get_ckm(mechType));
            rc = CKR_OK;
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    data = calloc(sizeof(CK_BYTE), inputlen);
    if (data == NULL) {
        testcase_error("Can't allocate memory for %lu bytes",
                       sizeof(CK_BYTE) * inputlen);
        rc = -1;
        goto testcase_cleanup;
    }

    for (i = 0; i < inputlen; i++) {
        data[i] = (i + 1) % 255;
    }

    rc = funcs->C_SignInit(session, &mech2, priv_key);
    if (rc != CKR_OK) {
        testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (parts > 0) {
        for (i = 0; i < parts; i++) {
            rc = funcs->C_SignUpdate(session, data, inputlen);
            if (rc != CKR_OK) {
                testcase_error("C_SignUpdate rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }
        }

        /* get signature length */
        rc = funcs->C_SignFinal(session, signature, &signaturelen);
        if (rc != CKR_OK) {
            testcase_error("C_SignFinal rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    } else {
        rc = funcs->C_Sign(session, data, inputlen, NULL, &signaturelen);
        if (rc != CKR_OK) {
            testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    signature = calloc(sizeof(CK_BYTE), signaturelen);
    if (signature == NULL) {
        testcase_error("Can't allocate memory for %lu bytes",
                       sizeof(CK_BYTE) * signaturelen);
        rc = -1;
        goto testcase_cleanup;
    }

    if (parts > 0) {
        rc = funcs->C_SignFinal(session, signature, &signaturelen);
        if (rc != CKR_OK) {
            testcase_error("C_SignFinal rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    } else {
        rc = funcs->C_Sign(session, data, inputlen, signature, &signaturelen);
        if (rc != CKR_OK) {
            testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    /****** Verify *******/
    rc = funcs->C_VerifyInit(session, &mech2, publ_key);
    if (rc != CKR_OK) {
        testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (parts > 0) {
        for (i = 0; i < parts; i++) {
            rc = funcs->C_VerifyUpdate(session, data, inputlen);
            if (rc != CKR_OK) {
                testcase_error("C_VerifyUpdate rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }
        }

        rc = funcs->C_VerifyFinal(session, signature, signaturelen);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyFinal rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    } else {
        rc = funcs->C_Verify(session, data, inputlen, signature, signaturelen);
        if (rc != CKR_OK) {
            testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    // corrupt the signature and re-verify
    memcpy(signature, "ABCDEFGHIJKLMNOPQRSTUV",
           strlen("ABCDEFGHIJKLMNOPQRSTUV"));

    rc = funcs->C_VerifyInit(session, &mech2, publ_key);
    if (rc != CKR_OK) {
        testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (parts > 0) {
        for (i = 0; i < parts; i++) {
            rc = funcs->C_VerifyUpdate(session, data, inputlen);
            if (rc != CKR_OK) {
                testcase_error("C_VerifyUpdate rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }
        }

        rc = funcs->C_VerifyFinal(session, signature, signaturelen);
        if (rc != CKR_SIGNATURE_INVALID) {
            testcase_error("C_VerifyFinal rc=%s", p11_get_ckr(rc));
            PRINT_ERR("		Expected CKR_SIGNATURE_INVALID\n");
            goto testcase_cleanup;
        }
    } else {
        rc = funcs->C_Verify(session, data, inputlen, signature, signaturelen);
        if (rc != CKR_SIGNATURE_INVALID) {
            testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
            PRINT_ERR("		Expected CKR_SIGNATURE_INVALID\n");
            goto testcase_cleanup;
        }
    }

    rc = CKR_OK;

testcase_cleanup:
    if (data)
        free(data);
    if (signature)
        free(signature);

    return rc;
}

CK_RV run_GenerateECCKeyPairSignVerify()
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i, j;
    CK_FLAGS flags;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    testcase_begin("Starting ECC generate key pair.");

    testcase_rw_session();
    testcase_user_login();

    mech.mechanism = CKM_EC_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    /* query the slot, check if this mech is supported */
    rc = funcs->C_GetMechanismInfo(SLOT_ID, mech.mechanism, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for EC key gen? skip */
            testcase_skip("Slot %u doesn't support CKM_EC_KEY_PAIR_GEN",
                          (unsigned int) SLOT_ID);
            rc = CKR_OK;
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    for (i = 0; i < NUMEC; i++) {

        if (!is_ep11_token(SLOT_ID)) {
            if (der_ec_supported[i].twisted) {
                testcase_skip("Slot %u doesn't support this curve",
                              (unsigned int) SLOT_ID);
                continue;
            }
            if (der_ec_supported[i].curve == secp256k1) {
                testcase_skip("Slot %u doesn't support this curve",
                              (unsigned int) SLOT_ID);
                continue;
            }
        }

        CK_ATTRIBUTE ec_attr[] = {
            {CKA_ECDSA_PARAMS, (CK_VOID_PTR)der_ec_supported[i].curve,
             der_ec_supported[i].size}
        };

        rc = funcs->C_GenerateKeyPair(session, &mech, ec_attr, 1, NULL, 0,
                                      &publ_key, &priv_key);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID ||
                rc == CKR_ATTRIBUTE_VALUE_INVALID) {
                testcase_skip("Slot %u doesn't support this curve",
                              (unsigned int) SLOT_ID);
                continue;
            }
            testcase_fail
                ("C_GenerateKeyPair with valid input failed at i=%lu, rc=%s", i,
                 p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Generate supported key pair index=%lu passed.", i);

        for (j = 0;
             j < (sizeof(signVerifyInput) / sizeof(_signVerifyParam)); j++) {
            testcase_new_assertion();
            rc = run_GenerateSignVerifyECC(session,
                                           signVerifyInput[j].mechtype,
                                           signVerifyInput[j].inputlen,
                                           signVerifyInput[j].parts,
                                           priv_key, publ_key);
            if (rc != 0) {
                testcase_fail("run_GenerateSignVerifyECC failed index=%lu.", j);
                goto testcase_cleanup;
            }
            testcase_pass("*Sign & verify i=%lu, j=%lu passed.", i, j);
        }
    }

    for (i = 0; i < NUMECINVAL; i++) {
        CK_ATTRIBUTE ec_attr[] = {
            {CKA_ECDSA_PARAMS, (CK_VOID_PTR)der_ec_notsupported[i].curve,
             der_ec_notsupported[i].size}
        };

        rc = funcs->C_GenerateKeyPair(session, &mech, ec_attr, 1, NULL, 0,
                                      &publ_key, &priv_key);
        testcase_new_assertion();
        if (rc == CKR_OK) {
            testcase_fail
                ("C_GenerateKeyPair with invalid input failed at i=%lu", i);
            goto testcase_cleanup;
        }
        testcase_pass("*Generate unsupported key pair index=%lu passed.", i);
    }

    rc = CKR_OK;

testcase_cleanup:
    if (publ_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_key);
    if (priv_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_key);

    testcase_close_session();

    return rc;
}

CK_RV run_ImportECCKeyPairSignVerify()
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i, j;
    CK_FLAGS flags;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    testcase_begin("Starting ECC import key pair.");

    testcase_rw_session();
    testcase_user_login();

    mech.mechanism = CKM_ECDSA;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    /* query the slot, check if this mech is supported */
    rc = funcs->C_GetMechanismInfo(SLOT_ID, mech.mechanism, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for EC key gen? skip */
            testcase_skip("Slot %u doesn't support CKM_ECDSA",
                          (unsigned int) SLOT_ID);
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    for (i = 0; i < EC_TV_NUM; i++) {
        if ((is_ica_token(SLOT_ID) || is_cca_token(SLOT_ID))) {
            if (!curve_supported((char *)ec_tv[i].name)) {
                testcase_skip("Slot %u doesn't support this curve",
                              (unsigned int)SLOT_ID);
                continue;
            }
        }


        rc = create_ECPrivateKey(session, ec_tv[i].params, ec_tv[i].params_len,
                                 ec_tv[i].privkey, ec_tv[i].privkey_len,
                                 ec_tv[i].pubkey, ec_tv[i].pubkey_len,
                                 &priv_key);

        testcase_new_assertion();
        if (rc != CKR_OK) {
            testcase_fail("C_CreateObject (EC Private Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Import EC private key (%s) index=%lu passed.",
                      ec_tv[i].name, i);

        rc = create_ECPublicKey(session, ec_tv[i].params, ec_tv[i].params_len,
                                ec_tv[i].pubkey, ec_tv[i].pubkey_len,
                                &publ_key);

        testcase_new_assertion();
        if (rc != CKR_OK) {
            testcase_fail("C_CreateObject (EC Public Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Import EC public key (%s) index=%lu passed.",
                      ec_tv[i].name, i);

        /* create signature with private key */
        for (j = 0;
             j < (sizeof(signVerifyInput) / sizeof(_signVerifyParam)); j++) {
            testcase_new_assertion();
            rc = run_GenerateSignVerifyECC(session,
                                           signVerifyInput[j].mechtype,
                                           signVerifyInput[j].inputlen,
                                           signVerifyInput[j].parts,
                                           priv_key, publ_key);
            if (rc != 0) {
                testcase_fail("run_GenerateSignVerifyECC failed index=%lu.", j);
                goto testcase_cleanup;
            }
            testcase_pass("*Sign & verify i=%lu, j=%lu passed.", i, j);
        }

        // clean up
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

CK_RV run_TransferECCKeyPairSignVerify()
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i, j;
    CK_FLAGS flags;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;
    CK_MECHANISM aes_keygen_mech;
    CK_OBJECT_HANDLE secret_key = CK_INVALID_HANDLE;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_ULONG wrapped_keylen;
    CK_OBJECT_HANDLE unwrapped_key = CK_INVALID_HANDLE;
    CK_MECHANISM wrap_mech;

    testcase_begin("Starting ECC transfer key pair.");

    testcase_rw_session();
    testcase_user_login();

    mech.mechanism = CKM_ECDSA;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    /* query the slot, check if this mech is supported */
    rc = funcs->C_GetMechanismInfo(SLOT_ID, mech.mechanism, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for EC key gen? skip */
            testcase_skip("Slot %u doesn't support CKM_ECDSA",
                          (unsigned int) SLOT_ID);
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    for (i = 0; i < EC_TV_NUM; i++) {
        if (!(is_ep11_token(SLOT_ID))) {
            if (strstr((char *)ec_tv[i].name, "t1") != NULL) {
                testcase_skip("Slot %u doesn't support curve %s",
                              (unsigned int)SLOT_ID, ec_tv[i].name);
                continue;
            }
        }

        rc = create_ECPrivateKey(session, ec_tv[i].params, ec_tv[i].params_len,
                                 ec_tv[i].privkey, ec_tv[i].privkey_len,
                                 ec_tv[i].pubkey, ec_tv[i].pubkey_len,
                                 &priv_key);

        testcase_new_assertion();
        if (rc != CKR_OK) {
            testcase_fail
                ("C_CreateObject (EC Private Key) failed at i=%lu, rc=%s", i,
                 p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Import EC private key (%s) index=%lu passed.",
                      ec_tv[i].name, i);

        rc = create_ECPublicKey(session, ec_tv[i].params, ec_tv[i].params_len,
                                ec_tv[i].pubkey, ec_tv[i].pubkey_len,
                                &publ_key);

        testcase_new_assertion();
        if (rc != CKR_OK) {
            testcase_fail
                ("C_CreateObject (EC Public Key) failed at i=%lu, rc=%s", i,
                 p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Import EC public key (%s) index=%lu passed.",
                      ec_tv[i].name, i);

        /* create wrapping key (secret key) */
        aes_keygen_mech.mechanism = CKM_AES_KEY_GEN;

        CK_OBJECT_CLASS wkclass = CKO_SECRET_KEY;
        CK_ULONG keylen = 32;
        CK_BBOOL true = TRUE;
        CK_BYTE wrap_key_label[] = "Wrap_Key";
        CK_ATTRIBUTE secret_tmpl[] = {
            {CKA_CLASS, &wkclass, sizeof(wkclass)},
            {CKA_VALUE_LEN, &keylen, sizeof(keylen)},
            {CKA_LABEL, &wrap_key_label, sizeof(wrap_key_label)},
            {CKA_TOKEN, &true, sizeof(true)},
            {CKA_WRAP, &true, sizeof(true)},
            {CKA_UNWRAP, &true, sizeof(true)}
        };

        rc = funcs->C_GenerateKey(session, &aes_keygen_mech, secret_tmpl,
                                  sizeof(secret_tmpl) / sizeof(CK_ATTRIBUTE),
                                  &secret_key);
        if (rc != CKR_OK) {
            testcase_error("C_GenerateKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /* wrap/unwrap private and public EC key with a transport key */

        // length only
        wrap_mech.mechanism = CKM_AES_CBC_PAD;
        wrap_mech.pParameter = "0123456789abcdef";
        wrap_mech.ulParameterLen = 16;
        rc = funcs->C_WrapKey(session, &wrap_mech, secret_key, priv_key,
                              NULL, &wrapped_keylen);
        if (rc != CKR_OK) {
            testcase_error("C_WrapKey(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // allocate memory for wrapped_key
        wrapped_key = calloc(sizeof(CK_BYTE), wrapped_keylen);
        if (wrapped_key == NULL) {
            testcase_error("Can't allocate memory for %lu bytes.",
                           sizeof(CK_BYTE) * wrapped_keylen);
            rc = CKR_HOST_MEMORY;
            goto testcase_cleanup;
        }
        // wrap key
        //
        rc = funcs->C_WrapKey(session, &wrap_mech, secret_key, priv_key,
                              wrapped_key, &wrapped_keylen);
        if (rc != CKR_OK) {
            testcase_fail("C_WrapKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // unwrap key
        //
        CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
        CK_KEY_TYPE key_type = CKK_EC;
        CK_BYTE unwrap_label[] = "unwrapped_private_EC_Key";
        CK_BYTE subject[] = {0};
        CK_BYTE id[] = { 123 };

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
        };

        rc = funcs->C_UnwrapKey(session, &wrap_mech, secret_key,
                                wrapped_key, wrapped_keylen,
                                unwrap_tmpl,
                                sizeof(unwrap_tmpl) / sizeof(CK_ATTRIBUTE),
                                &unwrapped_key);
        if (rc != CKR_OK) {
            testcase_fail("C_UnwrapKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        if (wrapped_key) {
            free(wrapped_key);
            wrapped_key = NULL;
	}

        /* create signature with unwrapped private key and verify with
         * public key */
        for (j = 0;
             j < (sizeof(signVerifyInput) / sizeof(_signVerifyParam)); j++) {
            testcase_new_assertion();
            rc = run_GenerateSignVerifyECC(session,
                                           signVerifyInput[j].mechtype,
                                           signVerifyInput[j].inputlen,
                                           signVerifyInput[j].parts,
                                           unwrapped_key, publ_key);
            if (rc != 0) {
                testcase_fail("run_GenerateSignVerifyECC failed index=%lu.", j);
                goto testcase_cleanup;
            }
            testcase_pass("*Sign & verify i=%lu, j=%lu passed.", i, j);
        }

        // clean up
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

    testcase_setup(total_assertions);

    rv = run_GenerateECCKeyPairSignVerify();

    rv = run_ImportECCKeyPairSignVerify();

    rv = run_TransferECCKeyPairSignVerify();

    rv = run_DeriveECDHKey();

    rv = run_DeriveECDHKeyKAT();

    testcase_print_result();

    funcs->C_Finalize(NULL);

    /* make sure we return non-zero if rv is non-zero */
    return ((rv == 0) || (rv % 256) ? (int)rv : -1);
}
