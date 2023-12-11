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
#include "ec_curves.h"
#include "mechtable.h"

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
 * secp256k1
 *		1.3.132.0.10
 *		2B8104000A
 * curve25519
 *      1.3.101.110
 *      06032B656E
 * curve448[]
 *      1.3.101.111
 *      06032B656F
 * ed25519[]
 *      1.3.101.112
 *      06032B6570
 * ed448
 *      1.3.101.113
 *      06032B6571
 */

typedef struct ec_struct {
    void const *curve;
    CK_ULONG size;
    CK_BBOOL twisted;
    enum curve_type type;
    CK_ULONG bit_len;
    char *name;
} _ec_struct;

/* Supported Elliptic Curves */
#define NUMEC		24
const CK_BYTE brainpoolP160r1[] = OCK_BRAINPOOL_P160R1;
const CK_BYTE brainpoolP160t1[] = OCK_BRAINPOOL_P160T1;
const CK_BYTE brainpoolP192r1[] = OCK_BRAINPOOL_P192R1;
const CK_BYTE brainpoolP192t1[] = OCK_BRAINPOOL_P192T1;
const CK_BYTE brainpoolP224r1[] = OCK_BRAINPOOL_P224R1;
const CK_BYTE brainpoolP224t1[] = OCK_BRAINPOOL_P224T1;
const CK_BYTE brainpoolP256r1[] = OCK_BRAINPOOL_P256R1;
const CK_BYTE brainpoolP256t1[] = OCK_BRAINPOOL_P256T1;
const CK_BYTE brainpoolP320r1[] = OCK_BRAINPOOL_P320R1;
const CK_BYTE brainpoolP320t1[] = OCK_BRAINPOOL_P320T1;
const CK_BYTE brainpoolP384r1[] = OCK_BRAINPOOL_P384R1;
const CK_BYTE brainpoolP384t1[] = OCK_BRAINPOOL_P384T1;
const CK_BYTE brainpoolP512r1[] = OCK_BRAINPOOL_P512R1;
const CK_BYTE brainpoolP512t1[] = OCK_BRAINPOOL_P512T1;
const CK_BYTE prime192v1[] = OCK_PRIME192V1;
const CK_BYTE secp224r1[] = OCK_SECP224R1;
const CK_BYTE prime256v1[] = OCK_PRIME256V1;
const CK_BYTE secp384r1[] = OCK_SECP384R1;
const CK_BYTE secp521r1[] = OCK_SECP521R1;
const CK_BYTE secp256k1[] = OCK_SECP256K1;
const CK_BYTE curve25519[] = OCK_CURVE25519;
const CK_BYTE curve448[] = OCK_CURVE448;
const CK_BYTE ed25519[] = OCK_ED25519;
const CK_BYTE ed448[] = OCK_ED448;

const _ec_struct der_ec_supported[NUMEC] = {
    {&brainpoolP160r1, sizeof(brainpoolP160r1), CK_FALSE, CURVE_BRAINPOOL,
     CURVE160_LENGTH, "brainpoolP160r1"},
    {&brainpoolP160t1, sizeof(brainpoolP160t1), CK_TRUE, CURVE_BRAINPOOL,
     CURVE160_LENGTH, "brainpoolP160t1"},
    {&brainpoolP192r1, sizeof(brainpoolP192r1), CK_FALSE, CURVE_BRAINPOOL,
     CURVE192_LENGTH, "brainpoolP192r1"},
    {&brainpoolP192t1, sizeof(brainpoolP192t1), CK_TRUE, CURVE_BRAINPOOL,
     CURVE192_LENGTH, "brainpoolP192t1"},
    {&brainpoolP224r1, sizeof(brainpoolP224r1), CK_FALSE, CURVE_BRAINPOOL,
     CURVE224_LENGTH, "brainpoolP224r1"},
    {&brainpoolP224t1, sizeof(brainpoolP224t1), CK_TRUE, CURVE_BRAINPOOL,
     CURVE224_LENGTH, "brainpoolP224t1"},
    {&brainpoolP256r1, sizeof(brainpoolP256r1), CK_FALSE, CURVE_BRAINPOOL,
     CURVE256_LENGTH, "brainpoolP256r1"},
    {&brainpoolP256t1, sizeof(brainpoolP256t1), CK_TRUE, CURVE_BRAINPOOL,
     CURVE256_LENGTH, "brainpoolP256t1"},
    {&brainpoolP320r1, sizeof(brainpoolP320r1), CK_FALSE, CURVE_BRAINPOOL,
     CURVE320_LENGTH, "brainpoolP320r1"},
    {&brainpoolP320t1, sizeof(brainpoolP320t1), CK_TRUE, CURVE_BRAINPOOL,
     CURVE320_LENGTH, "brainpoolP320t1"},
    {&brainpoolP384r1, sizeof(brainpoolP384r1), CK_FALSE, CURVE_BRAINPOOL,
     CURVE384_LENGTH, "brainpoolP384r1"},
    {&brainpoolP384t1, sizeof(brainpoolP384t1), CK_TRUE, CURVE_BRAINPOOL,
     CURVE384_LENGTH, "brainpoolP384t1"},
    {&brainpoolP512r1, sizeof(brainpoolP512r1), CK_FALSE, CURVE_BRAINPOOL,
     CURVE512_LENGTH, "brainpoolP512r1"},
    {&brainpoolP512t1, sizeof(brainpoolP512t1), CK_TRUE, CURVE_BRAINPOOL,
     CURVE512_LENGTH, "brainpoolP512t1"},
    {&prime192v1, sizeof(prime192v1), CK_FALSE, CURVE_PRIME,
     CURVE192_LENGTH, "prime192v1"},
    {&secp224r1, sizeof(secp224r1), CK_FALSE, CURVE_PRIME,
     CURVE224_LENGTH , "secp224r1"},
    {&prime256v1, sizeof(prime256v1), CK_FALSE, CURVE_PRIME,
     CURVE256_LENGTH, "prime256v1"},
    {&secp384r1, sizeof(secp384r1), CK_FALSE, CURVE_PRIME,
     CURVE384_LENGTH, "secp384r1"},
    {&secp521r1, sizeof(secp521r1), CK_FALSE, CURVE_PRIME,
     CURVE521_LENGTH + 8, "secp521r1"},
    {&secp256k1, sizeof(secp256k1), CK_FALSE, CURVE_PRIME,
     CURVE256_LENGTH, "secp256k1"},
    {&curve25519, sizeof(curve25519), CK_FALSE, CURVE_MONTGOMERY,
     CURVE256_LENGTH, "curve25519"},
    {&curve448, sizeof(curve448), CK_FALSE, CURVE_MONTGOMERY,
     CURVE456_LENGTH, "curve448"},
    {&ed25519, sizeof(ed25519), CK_FALSE, CURVE_EDWARDS,
     CURVE256_LENGTH, "ed25519"},
    {&ed448, sizeof(ed448), CK_FALSE, CURVE_EDWARDS,
     CURVE456_LENGTH, "ed448"},
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
    {&invalidCurve, sizeof(invalidCurve), CK_FALSE, CURVE_BRAINPOOL,
     CURVE256_LENGTH, "invalidCurve"},
    {&invalidLen1, sizeof(invalidLen1), CK_FALSE, CURVE_BRAINPOOL,
     CURVE256_LENGTH, "invalidLen1"},
    {&invalidLen2, sizeof(invalidLen2), CK_FALSE, CURVE_BRAINPOOL,
     CURVE256_LENGTH, "invalidLen2"},
    {&invalidOIDfield, sizeof(invalidOIDfield), CK_FALSE, CURVE_BRAINPOOL,
     CURVE256_LENGTH, "invalidOIDfield"}
};

typedef struct signVerifyParam {
    CK_MECHANISM mech;
    CK_ULONG inputlen;
    CK_ULONG parts;             /* 0 means process in 1 chunk via C_Sign,
                                 * >0 means process in n chunks via
                                 * C_SignUpdate/C_SignFinal
                                 */
} _signVerifyParam;

CK_IBM_ECDSA_OTHER_PARAMS other_rand = { .submechanism = CKM_IBM_ECSDSA_RAND };
CK_IBM_ECDSA_OTHER_PARAMS other_compr_multi =
                                { .submechanism = CKM_IBM_ECSDSA_COMPR_MULTI };

_signVerifyParam signVerifyInput[] = {
    {{CKM_ECDSA, NULL, 0}, 20, 0},
    {{CKM_ECDSA, NULL, 0}, 32, 0},
    {{CKM_ECDSA, NULL, 0}, 48, 0},
    {{CKM_ECDSA, NULL, 0}, 64, 0},
    {{CKM_ECDSA_SHA1, NULL, 0}, 100, 0},
    {{CKM_ECDSA_SHA1, NULL, 0}, 100, 4},
    {{CKM_ECDSA_SHA1, NULL, 0}, 0, 0}, /* Empty Message via C_Sign */
    {{CKM_ECDSA_SHA1, NULL, 0}, 0, 1}, /* Empty Message via C_SignInit+C_SignFinal */
    {{CKM_ECDSA_SHA224, NULL, 0}, 100, 0},
    {{CKM_ECDSA_SHA224, NULL, 0}, 100, 4},
    {{CKM_ECDSA_SHA224, NULL, 0}, 0, 0}, /* Empty Message via C_Sign */
    {{CKM_ECDSA_SHA224, NULL, 0}, 0, 1}, /* Empty Message via C_SignInit+C_SignFinal */
    {{CKM_ECDSA_SHA256, NULL, 0}, 100, 0},
    {{CKM_ECDSA_SHA256, NULL, 0}, 100, 4},
    {{CKM_ECDSA_SHA256, NULL, 0}, 0, 0}, /* Empty Message via C_Sign */
    {{CKM_ECDSA_SHA256, NULL, 0}, 0, 1}, /* Empty Message via C_SignInit+C_SignFinal */
    {{CKM_ECDSA_SHA384, NULL, 0}, 100, 0},
    {{CKM_ECDSA_SHA384, NULL, 0}, 100, 4},
    {{CKM_ECDSA_SHA384, NULL, 0}, 0, 0}, /* Empty Message via C_Sign */
    {{CKM_ECDSA_SHA384, NULL, 0}, 0, 1}, /* Empty Message via C_SignInit+C_SignFinal */
    {{CKM_ECDSA_SHA512, NULL, 0}, 100, 0},
    {{CKM_ECDSA_SHA512, NULL, 0}, 100, 4},
    {{CKM_ECDSA_SHA512, NULL, 0}, 0, 0}, /* Empty Message via C_Sign */
    {{CKM_ECDSA_SHA512, NULL, 0}, 0, 1}, /* Empty Message via C_SignInit+C_SignFinal */
    {{CKM_IBM_ED25519_SHA512, NULL, 0}, 100, 0},
    {{CKM_IBM_ED448_SHA3, NULL, 0}, 100, 0},
    {{CKM_IBM_ECDSA_OTHER, &other_rand, sizeof(other_rand)}, 20, 0},
    {{CKM_IBM_ECDSA_OTHER, &other_compr_multi, sizeof(other_compr_multi)}, 20, 0},
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
    default:
        return "UNKNOWN";
    }
}

static unsigned int curve_len(int index)
{
    if (index >= NUMEC)
        return 0;

    return der_ec_supported[index].bit_len / 8;
}

static CK_RV curve_supported(const char *name)
{
    if (name[strlen(name) - 2] == 'r' || name[strlen(name) - 2] == 'v')
        return 1;

    return 0;
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
 * Perform a HMAC sign to verify that the key is usable.
 */
CK_RV run_HMACSign(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE h_key,
                   CK_ULONG key_len, CK_MECHANISM_TYPE hmac_mech,
                   CK_BYTE *mac, CK_ULONG *mac_len)
{
    CK_MECHANISM mech = { .mechanism = hmac_mech,
                          .pParameter = NULL, .ulParameterLen = 0 };
    CK_BYTE data[32] = { 0 };
    CK_RV rc = CKR_OK;

    if (!mech_supported(SLOT_ID, mech.mechanism)) {
        testcase_notice("Mechanism %s is not supported with slot "
                        "%lu. Skipping key check",
                        p11_get_ckm(&mechtable_funcs, mech.mechanism),
                        SLOT_ID);
        *mac_len = 0;
        return CKR_OK;
    }
    if (!check_supp_keysize(SLOT_ID, mech.mechanism, key_len * 8)) {
        testcase_notice("Mechanism %s can not be used with keys "
                        "of size %lu. Skipping key check",
                        p11_get_ckm(&mechtable_funcs, mech.mechanism),
                        key_len);
        *mac_len = 0;
        return CKR_OK;
    }

    rc = funcs->C_SignInit(session, &mech, h_key);
    if (rc != CKR_OK) {
        testcase_notice("C_SignInit rc=%s", p11_get_ckr(rc));
        goto error;
    }

    /** do signing  **/
    rc = funcs->C_Sign(session, data, sizeof(data), mac, mac_len);
    if (rc != CKR_OK) {
        testcase_notice("C_Sign rc=%s", p11_get_ckr(rc));
        goto error;
    }

error:
    return rc;
}

/*
 * Generate EC key-pairs for parties A and B.
 * Derive shared secrets based on Diffie Hellman key agreement defined in PKCS#3
 */
CK_RV run_DeriveECDHKey(void)
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
    CK_BYTE pubkeyA_value[256] = { 0 };
    CK_BYTE pubkeyB_value[256] = { 0 };
    CK_BYTE secretA_value[80000] = { 0 }; //enough space for lengths in secret_key_len[]
    CK_BYTE deriveB_value[80000] = { 0 };
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_ULONG i, j, k, m;
    CK_MECHANISM_TYPE derive_mech_type;

    testcase_begin("starting run_DeriveECDHKey with pkey=%X ...", pkey);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(SLOT_ID) && !is_cca_token(SLOT_ID)) {
        testcase_skip("pkey test option is true, but slot %u doesn't support protected keys",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

    if (!mech_supported(SLOT_ID, CKM_EC_KEY_PAIR_GEN)) {
        testcase_skip("Slot %u doesn't support CKM_EC_KEY_PAIR_GEN\n",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

    for (i=0; i<NUMEC; i++) {
        CK_ATTRIBUTE cka_derive_tmpl[] = {
            {CKA_PRIVATE, &true, sizeof(true)},
            {CKA_EXTRACTABLE, &true, sizeof(true)},
        };
        CK_ATTRIBUTE prv_attr[] = {
            {CKA_SIGN, &true, sizeof(true)},
            {CKA_EXTRACTABLE, &true, sizeof(true)},
            {CKA_DERIVE, &true, sizeof(true)},
            {CKA_DERIVE_TEMPLATE, &cka_derive_tmpl, sizeof(cka_derive_tmpl)},
        };
        CK_ULONG prv_attr_len = sizeof(prv_attr)/sizeof(CK_ATTRIBUTE);
        CK_ATTRIBUTE prv_attr_edwards[] = {
            {CKA_SIGN, &true, sizeof(true)},
            {CKA_EXTRACTABLE, &true, sizeof(true)},
        };
        CK_ULONG prv_attr_edwards_len =
                            sizeof(prv_attr_edwards)/sizeof(CK_ATTRIBUTE);
        CK_ATTRIBUTE prv_attr_montgomery[] = {
            {CKA_DERIVE, &true, sizeof(true)},
            {CKA_EXTRACTABLE, &true, sizeof(true)},
            {CKA_DERIVE_TEMPLATE, &cka_derive_tmpl, sizeof(cka_derive_tmpl)},
        };
        CK_ULONG prv_attr_montgomery_len =
                    sizeof(prv_attr_montgomery)/sizeof(CK_ATTRIBUTE);

        CK_ATTRIBUTE pub_attr[] = {
            {CKA_ECDSA_PARAMS, (CK_VOID_PTR)der_ec_supported[i].curve,
             der_ec_supported[i].size},
            {CKA_VERIFY, &true, sizeof(true)},
            {CKA_MODIFIABLE, &true, sizeof(true)},
        };
        CK_ULONG pub_attr_len = sizeof(pub_attr)/sizeof(CK_ATTRIBUTE);
        CK_ATTRIBUTE pub_attr_montgomery[] = {
            {CKA_ECDSA_PARAMS, (CK_VOID_PTR)der_ec_supported[i].curve,
             der_ec_supported[i].size},
            {CKA_MODIFIABLE, &true, sizeof(true)},
            {CKA_VERIFY, &true, sizeof(true)},
        };
        CK_ULONG pub_attr_montgomery_len =
                            sizeof(pub_attr_montgomery)/sizeof(CK_ATTRIBUTE);

        if (is_icsf_token(SLOT_ID))
            prv_attr_len -= 1; /* ICSF does not support array attributes */

        CK_ATTRIBUTE *prv_attr_gen = prv_attr;
        CK_ULONG prv_attr_gen_len = prv_attr_len;
        CK_ATTRIBUTE *pub_attr_gen = pub_attr;
        CK_ULONG pub_attr_gen_len = pub_attr_len;

        CK_ATTRIBUTE  extr1_tmpl[] = {
            {CKA_EC_POINT, pubkeyA_value, sizeof(pubkeyA_value)},
        };
        CK_ULONG extr1_tmpl_len = sizeof(extr1_tmpl)/sizeof(CK_ATTRIBUTE);

        CK_ATTRIBUTE  extr2_tmpl[] = {
            {CKA_EC_POINT, pubkeyB_value, sizeof(pubkeyB_value)},
        };
        CK_ULONG extr2_tmpl_len = sizeof(extr2_tmpl)/sizeof(CK_ATTRIBUTE);

        if (der_ec_supported[i].type == CURVE_EDWARDS) {
            testcase_skip("Edwards curves can not be used for ECDH derive");
            continue;
        }

        if (!is_ep11_token(SLOT_ID)) {
            if (der_ec_supported[i].twisted) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, der_ec_supported[i].name);
                continue;
            }
            if (der_ec_supported[i].curve == secp256k1) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, der_ec_supported[i].name);
                continue;
            }
            if (der_ec_supported[i].type != CURVE_BRAINPOOL &&
                der_ec_supported[i].type != CURVE_PRIME ) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, der_ec_supported[i].name);
                continue;
            }
        }

        derive_mech_type = CKM_ECDH1_DERIVE;
        if (der_ec_supported[i].type == CURVE_MONTGOMERY) {
            if (der_ec_supported[i].curve == curve25519)
                derive_mech_type = CKM_IBM_EC_X25519;
            if (der_ec_supported[i].curve == curve448)
                derive_mech_type = CKM_IBM_EC_X448;

            prv_attr_gen = prv_attr_montgomery;
            prv_attr_gen_len = prv_attr_montgomery_len;
            pub_attr_gen = pub_attr_montgomery;
            pub_attr_gen_len = pub_attr_montgomery_len;
        } else if (der_ec_supported[i].type == CURVE_EDWARDS) {
            prv_attr_gen = prv_attr_edwards;
            prv_attr_gen_len = prv_attr_edwards_len;
        }
        if (!mech_supported(SLOT_ID, derive_mech_type)) {
            testcase_skip("Slot %u doesn't support %s\n",
                         (unsigned int) SLOT_ID,
                         p11_get_ckm(&mechtable_funcs, derive_mech_type));
            goto testcase_cleanup;
        }

        // Testcase #1 - Generate 2 EC key pairs.

        // First, generate the EC key pair for party A
        mech.mechanism = CKM_EC_KEY_PAIR_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        rc = funcs->C_GenerateKeyPair(session, &mech,
                                      pub_attr_gen, pub_attr_gen_len,
                                      prv_attr_gen, prv_attr_gen_len,
                                      &publ_keyA, &priv_keyA);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("EC key generation is not allowed by policy");
                continue;
            }
            if (rc == CKR_MECHANISM_PARAM_INVALID ||
                rc == CKR_ATTRIBUTE_VALUE_INVALID ||
                rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, der_ec_supported[i].name);
                continue;
            }
            testcase_fail("C_GenerateKeyPair with valid input failed at i=%lu "
                          "(%s), rc=%s", i, der_ec_supported[i].name,
                          p11_get_ckr(rc));
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
                                      pub_attr_gen, pub_attr_gen_len,
                                      prv_attr_gen, prv_attr_gen_len,
                                      &publ_keyB, &priv_keyB);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("EC key generation is not allowed by policy");
                goto testcase_cleanup;
            }
            testcase_fail("C_GenerateKeyPair with valid input failed at i=%lu "
                          "(%s), rc=%s", i, der_ec_supported[i].name,
                          p11_get_ckr(rc));
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
            switch (kdfs[j]) {
            case CKD_SHA1_KDF:
                if (!mech_supported(SLOT_ID, CKM_SHA_1)) {
                    testcase_skip("Slot %u doesn't support CKD_SHA1_KDF\n",
                                  (unsigned int) SLOT_ID);
                    continue;
                }
                break;
            case CKD_SHA224_KDF:
                if (!mech_supported(SLOT_ID, CKM_SHA224)) {
                    testcase_skip("Slot %u doesn't support CKD_SHA224_KDF\n",
                                  (unsigned int) SLOT_ID);
                    continue;
                }
                break;
            case CKD_SHA256_KDF:
                if (!mech_supported(SLOT_ID, CKM_SHA256)) {
                    testcase_skip("Slot %u doesn't support CKD_SHA256_KDF\n",
                                  (unsigned int) SLOT_ID);
                    continue;
                }
                break;
            case CKD_SHA384_KDF:
                if (!mech_supported(SLOT_ID, CKM_SHA384)) {
                    testcase_skip("Slot %u doesn't support CKD_SHA384_KDF\n",
                                  (unsigned int) SLOT_ID);
                    continue;
                }
                break;
            case CKD_SHA512_KDF:
                if (!mech_supported(SLOT_ID, CKM_SHA512)) {
                    testcase_skip("Slot %u doesn't support CKD_SHA512_KDF\n",
                                  (unsigned int) SLOT_ID);
                    continue;
                }
                break;
            default:
                break;
            }

            for (k=0; k<NUM_SECRET_KEY_LENGTHS; k++) {

                if (too_many_key_bytes_requested(i, j, secret_key_len[k])) {
                    testcase_skip("Cannot provide %lu key bytes with curve %s"
                                  " without a kdf.\n", secret_key_len[k],
                                  der_ec_supported[i].name);
                    continue;
                }
                if (is_ep11_token(SLOT_ID) && k > 9) {
                    testcase_skip("EP11 cannot provide %lu key bytes with "
                                  "curve %s\n", secret_key_len[k],
                                  der_ec_supported[i].name);
                    continue;
                }
                if (is_ep11_token(SLOT_ID) &&
                    secret_key_len[k] > 0 && secret_key_len[k] < 10) {
                    /*
                     * EP11 can not derive keys less than 80 bits (10 bytes).
                     * This was formerly dependent on control point
                     * XCP_CPB_KEYSZ_BELOW80BIT, but this control point
                     * is now always OFF.
                     * */
                    testcase_skip("EP11 cannot provide %lu key bytes (%lu bits < 80 bits)\n",
                                  secret_key_len[k], secret_key_len[k] * 8);
                    continue;
                }
                if (secret_key_len[k] == 0 &&
                    der_ec_supported[i].type == CURVE_MONTGOMERY) {
                    testcase_skip("Curve %s can not be used without the "
                                  "derived key size specified in "
                                  "CKA_VALUE_LEN\n", der_ec_supported[i].name);
                    continue;
                }

                if (is_icsf_token(SLOT_ID) && secret_key_len[k] == 0) {
                    testcase_skip("ICSF token can not derive keys without CKA_VALUE_LEN\n");
                    continue;
                }
                if (is_icsf_token(SLOT_ID) && secret_key_len[k] > 256) {
                    testcase_skip("ICSF token can not derive keys of that size\n");
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
                    {CKA_SENSITIVE, &false, sizeof(false)},
                    {CKA_VALUE_LEN, &(secret_key_len[k]), sizeof(CK_ULONG)},
                };
                CK_ULONG secret_tmpl_len =
                    sizeof(derive_tmpl) / sizeof(CK_ATTRIBUTE);

                CK_BYTE mac1[SHA1_HASH_SIZE] = { 0 };
                CK_ULONG mac1_len = sizeof(mac1);
                CK_BYTE mac2[SHA1_HASH_SIZE] = { 0 };
                CK_ULONG mac2_len = sizeof(mac2);

                if (secret_key_len[k] == 0)
                    secret_tmpl_len--;

                for (m=0; m < (kdfs[j] == CKD_NULL ? 1 : NUM_SHARED_DATA); m++) {

                    testcase_begin("Starting with curve=%s, kdf=%s, keylen=%lu, "
                                  "shared_data=%u, mech=%s, pkey=%X",
                                  der_ec_supported[i].name,
                                  p11_get_ckd(kdfs[j]), secret_key_len[k],
                                  shared_data[m].length,
                                  p11_get_ckm(&mechtable_funcs, derive_mech_type),
                                  pkey);

                    // Now, derive a generic secret key using party A's private
                    // key and B's public key
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

                    mech.mechanism = derive_mech_type;
                    mech.ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);
                    mech.pParameter = &ecdh_parmA;

                    rc = funcs->C_DeriveKey(session, &mech,
                                            priv_keyA, derive_tmpl,
                                            secret_tmpl_len, &secret_keyA);
                    if (rc != CKR_OK) {
                        if (is_ep11_token(SLOT_ID) &&
                            rc == CKR_MECHANISM_PARAM_INVALID &&
                            (kdfs[j] != CKD_NULL ||
                             shared_data[m].length > 0)) {
                            testcase_skip("EP11 does not support KDFs and "
                                          "shared data with older firmware "
                                          "versions\n");
                            continue;
                        }
                        if (is_rejected_by_policy(rc, session)) {
                            testcase_skip("key derivation is not allowed by policy");
                            continue;
                        }

                        testcase_fail("C_DeriveKey #1: rc = %s",
                                      p11_get_ckr(rc));
                        goto testcase_cleanup;
                    }

                    mac1_len = sizeof(mac1);
                    rc = run_HMACSign(session, secret_keyA,
                                      secret_key_len[k] > 0 ?
                                          secret_key_len[k] : curve_len(i),
                                      CKM_SHA_1_HMAC, mac1, &mac1_len);
                    if (rc != CKR_OK) {
                        testcase_fail("Derived key #1 is not usable: %s",
                                      p11_get_ckr(rc));
                        goto testcase_cleanup;
                    }

                    // Now, derive a generic secret key using B's private key
                    // and A's public key
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

                    mech.mechanism = derive_mech_type;
                    mech.ulParameterLen = sizeof(CK_ECDH1_DERIVE_PARAMS);
                    mech.pParameter = &ecdh_parmB;

                    rc = funcs->C_DeriveKey(session, &mech,
                                            priv_keyB, derive_tmpl,
                                            secret_tmpl_len, &secret_keyB);
                    if (rc != CKR_OK) {
                        if (is_ep11_token(SLOT_ID) &&
                            rc == CKR_MECHANISM_PARAM_INVALID &&
                            (kdfs[j] != CKD_NULL ||
                             shared_data[m].length > 0)) {
                            testcase_skip("EP11 does not support KDFs and "
                                          "shared data with older firmware "
                                          "versions\n");
                            if (secret_keyA != CK_INVALID_HANDLE)
                                funcs->C_DestroyObject(session, secret_keyA);
                            continue;
                        }
                        if (is_rejected_by_policy(rc, session)) {
                            testcase_skip("key derivation is not allowed by policy");
                            if (secret_keyA != CK_INVALID_HANDLE)
                                funcs->C_DestroyObject(session, secret_keyA);
                            continue;
                        }

                        testcase_fail("C_DeriveKey #2: rc = %s",
                                      p11_get_ckr(rc));
                        goto testcase_cleanup;
                    }

                    testcase_new_assertion();
                    mac2_len = sizeof(mac2);
                    rc = run_HMACSign(session, secret_keyB,
                                      secret_key_len[k] > 0 ?
                                          secret_key_len[k] : curve_len(i),
                                      CKM_SHA_1_HMAC, mac2, &mac2_len);
                    if (rc != CKR_OK) {
                        testcase_fail("Derived key #2 is not usable: %s",
                                      p11_get_ckr(rc));
                        goto testcase_cleanup;
                    }

                    if (mac1_len != mac2_len ||
                        memcmp(mac1, mac2, mac1_len) != 0) {
                        testcase_fail("ERROR: derived keys do not produce the "
                                      "same HMAC");
                        goto testcase_cleanup;
                    }

                    /* A secure key token won't reveal the key value in clear */
                    if (!is_ep11_token(SLOT_ID) && !is_cca_token(SLOT_ID)) {
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
                            testcase_fail("ERROR: derived key #1 length = %lu, "
                                          "derived key #2 length = %lu",
                                          secretA_tmpl[0].ulValueLen,
                                          secretB_tmpl[0].ulValueLen);
                            goto testcase_cleanup;
                        }

                        // Compare derive secrets A and B
                        if (memcmp(secretA_tmpl[0].pValue,
                                   secretB_tmpl[0].pValue,
                                   secretA_tmpl[0].ulValueLen) != 0) {
                            testcase_fail("ERROR: derived key mismatch, curve=%s, "
                                          "kdf=%s, keylen=%lu, shared_data=%u",
                                          der_ec_supported[i].name,
                                          p11_get_ckd(kdfs[j]), secret_key_len[k],
                                          shared_data[m].length);
                            goto testcase_cleanup;
                        }
                    }

                    testcase_pass("*Derive shared secret curve=%s, kdf=%s, "
                                  "keylen=%lu, shared_data=%u, mech=%s passed.",
                                  der_ec_supported[i].name,
                                  p11_get_ckd(kdfs[j]), secret_key_len[k],
                                  shared_data[m].length,
                                  p11_get_ckm(&mechtable_funcs, derive_mech_type));

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
CK_RV run_DeriveECDHKeyKAT(void)
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
    CK_BYTE secretA_value[1000] = { 0 }; // enough space for key lengths in ecdh_tv[]
    CK_BYTE secretB_value[1000] = { 0 };
    CK_ULONG i;

    testcase_begin("starting run_DeriveECDHKeyKAT with pkey=%X ...", pkey);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(SLOT_ID) && !is_cca_token(SLOT_ID)) {
        testcase_skip("pkey test option is true, but slot %u doesn't support protected keys",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

    if (!mech_supported(SLOT_ID, CKM_ECDH1_DERIVE)) {
        testcase_skip("Slot %u doesn't support CKM_ECDH1_DERIVE\n",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

    if (is_ep11_token(SLOT_ID) || is_cca_token(SLOT_ID)) {
        testcase_skip("Slot %u is a secure key token, can not run known answer "
                      "tests with CKM_ECDH1_DERIVE on it\n",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

    for (i=0; i<ECDH_TV_NUM; i++) {

        testcase_begin("Starting with shared secret i=%lu, pkey=%X", i, pkey);

        switch (ecdh_tv[i].kdf) {
        case CKD_SHA1_KDF:
            if (!mech_supported(SLOT_ID, CKM_SHA_1)) {
                testcase_skip("Slot %u doesn't support CKD_SHA1_KDF\n",
                              (unsigned int) SLOT_ID);
                continue;
            }
            break;
        case CKD_SHA224_KDF:
            if (!mech_supported(SLOT_ID, CKM_SHA224)) {
                testcase_skip("Slot %u doesn't support CKD_SHA224_KDF\n",
                              (unsigned int) SLOT_ID);
                continue;
            }
            break;
        case CKD_SHA256_KDF:
            if (!mech_supported(SLOT_ID, CKM_SHA256)) {
                testcase_skip("Slot %u doesn't support CKD_SHA256_KDF\n",
                              (unsigned int) SLOT_ID);
                continue;
            }
            break;
        case CKD_SHA384_KDF:
            if (!mech_supported(SLOT_ID, CKM_SHA384)) {
                testcase_skip("Slot %u doesn't support CKD_SHA384_KDF\n",
                              (unsigned int) SLOT_ID);
                continue;
            }
            break;
        case CKD_SHA512_KDF:
            if (!mech_supported(SLOT_ID, CKM_SHA512)) {
                testcase_skip("Slot %u doesn't support CKD_SHA512_KDF\n",
                              (unsigned int) SLOT_ID);
                continue;
            }
            break;
        default:
            break;
        }

        // First, import the EC key pair for party A
        rc = create_ECPrivateKey(session,
                                 ecdh_tv[i].params, ecdh_tv[i].params_len,
                                 ecdh_tv[i].privkeyA, ecdh_tv[i].privkey_len,
                                 &priv_keyA, !pkey);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("EC key import is not allowed by policy");
                continue;
            }
            if (rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, ecdh_tv[i].name);
                goto testcase_next;
            }

            testcase_fail("C_CreateObject (EC Private Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = create_ECPublicKey(session,
                                ecdh_tv[i].params, ecdh_tv[i].params_len,
                                ecdh_tv[i].pubkeyA, ecdh_tv[i].pubkey_len,
                                &publ_keyA);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("EC key import is not allowed by policy");
                funcs->C_DestroyObject(session, priv_keyA);
                continue;
            }
            if (rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, ecdh_tv[i].name);
                goto testcase_next;
            }

            testcase_fail("C_CreateObject (EC Public Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Now import the EC key pair for party B
        rc = create_ECPrivateKey(session,
                                 ecdh_tv[i].params, ecdh_tv[i].params_len,
                                 ecdh_tv[i].privkeyB, ecdh_tv[i].privkey_len,
                                 &priv_keyB, !pkey);
        if (rc != CKR_OK) {
            if (rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, ecdh_tv[i].name);
                goto testcase_next;
            }

            testcase_fail("C_CreateObject (EC Private Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = create_ECPublicKey(session,
                                ecdh_tv[i].params, ecdh_tv[i].params_len,
                                ecdh_tv[i].pubkeyB, ecdh_tv[i].pubkey_len,
                                &publ_keyB);
        if (rc != CKR_OK) {
            if (rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, ecdh_tv[i].name);
                goto testcase_next;
            }

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

        CK_BBOOL extractable = !pkey;
        CK_ATTRIBUTE  derive_tmpl[] = {
            {CKA_CLASS, &class, sizeof(class)},
            {CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type)},
            {CKA_VALUE_LEN, &(ecdh_tv[i].derived_key_len), sizeof(CK_ULONG)},
            {CKA_SENSITIVE, &false, sizeof(false)},
            {CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
            {CKA_IBM_PROTKEY_EXTRACTABLE, &pkey, sizeof(CK_BBOOL)},
        };
        CK_ULONG derive_tmpl_len = sizeof(derive_tmpl) / sizeof(CK_ATTRIBUTE);

        // Now, derive a generic secret key using party A's private key
        // and B's public key
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
            if (rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, ecdh_tv[i].name);
                goto testcase_next;
            } else if (is_ep11_token(SLOT_ID) &&
                rc == CKR_MECHANISM_PARAM_INVALID &&
                (ecdh_tv[i].kdf != CKD_NULL ||
                 ecdh_tv[i].shared_data_len > 0)) {
                testcase_skip("EP11 does not support KDFs and shared data with "
                              "older firmware versions\n");
                if (priv_keyA != CK_INVALID_HANDLE)
                    funcs->C_DestroyObject(session, priv_keyA);
                if (publ_keyA != CK_INVALID_HANDLE)
                    funcs->C_DestroyObject(session, publ_keyA);
                if (priv_keyB != CK_INVALID_HANDLE)
                    funcs->C_DestroyObject(session, priv_keyB);
                if (publ_keyB != CK_INVALID_HANDLE)
                    funcs->C_DestroyObject(session, publ_keyB);
                continue;
            }

            testcase_fail("C_DeriveKey #1: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Now, derive a generic secret key using B's private key and
        // A's public key
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
            if (is_ep11_token(SLOT_ID) &&
                rc == CKR_MECHANISM_PARAM_INVALID &&
                (ecdh_tv[i].kdf != CKD_NULL ||
                 ecdh_tv[i].shared_data_len > 0)) {
                testcase_skip("EP11 does not support KDFs and shared data with "
                              "older firmware versions\n");
                if (secret_keyA != CK_INVALID_HANDLE)
                    funcs->C_DestroyObject(session, secret_keyA);
                if (priv_keyA != CK_INVALID_HANDLE)
                    funcs->C_DestroyObject(session, priv_keyA);
                if (publ_keyA != CK_INVALID_HANDLE)
                    funcs->C_DestroyObject(session, publ_keyA);
                if (priv_keyB != CK_INVALID_HANDLE)
                    funcs->C_DestroyObject(session, priv_keyB);
                if (publ_keyB != CK_INVALID_HANDLE)
                    funcs->C_DestroyObject(session, publ_keyB);
                continue;
            }

            testcase_fail("C_DeriveKey #2: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        testcase_new_assertion();

        // Extract the derived secret A
        rc = funcs->C_GetAttributeValue(session, secret_keyA,
                                        secretA_tmpl, secretA_tmpl_len);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #3:rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        // Compare lengths of derived secret from key object
        if (ecdh_tv[i].derived_key_len != secretA_tmpl[0].ulValueLen) {
            testcase_fail("ERROR:derived key #1 length = %lu, "
                          "derived key #2 length = %lu",
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
            testcase_fail("ERROR:derived key #1 length = %lu, derived key #2 "
                          "length = %lu", ecdh_tv[i].derived_key_len,
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

testcase_next:
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
                                CK_MECHANISM *mech,
                                CK_ULONG inputlen,
                                CK_ULONG parts,
                                CK_OBJECT_HANDLE priv_key,
                                CK_OBJECT_HANDLE publ_key,
                                enum curve_type curve_type,
                                CK_BYTE *params, CK_ULONG params_len)
{
    CK_BYTE_PTR data = NULL, signature = NULL;
    CK_ULONG i, signaturelen;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    testcase_begin("Starting with mechtype='%s', inputlen=%lu parts=%lu, pkey=%X",
                   p11_get_ckm(&mechtable_funcs, mech->mechanism), inputlen, parts, pkey);

    /* query the slot, check if this mech if supported */
    rc = funcs->C_GetMechanismInfo(SLOT_ID, mech->mechanism, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for EC key gen? skip */
            testcase_skip("Slot %u doesn't support %s",
                          (unsigned int) SLOT_ID,
                          p11_get_ckm(&mechtable_funcs, mech->mechanism));
            rc = CKR_OK;
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    if ((mech->mechanism == CKM_IBM_ED25519_SHA512 ||
         mech->mechanism == CKM_IBM_ED448_SHA3)) {
        if (curve_type != CURVE_EDWARDS) {
            /* Mechanism does not match to curve type, skip */
            testcase_skip("Mechanism %s can only be used with Edwards curves",
                          p11_get_ckm(&mechtable_funcs, mech->mechanism));
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        if (mech->mechanism == CKM_IBM_ED25519_SHA512 &&
            memcmp(params, ed25519, MIN(params_len, sizeof(ed25519))) != 0) {
            /* Mechanism does not match to curve, skip */
            testcase_skip("Mechanism %s can only be used with Ed25519 curve",
                          p11_get_ckm(&mechtable_funcs, mech->mechanism));
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        if (mech->mechanism == CKM_IBM_ED448_SHA3 &&
            memcmp(params, ed448, MIN(params_len, sizeof(ed448))) != 0) {
            /* Mechanism does not match to curve, skip */
            testcase_skip("Mechanism %s can only be used with Ed448 curve",
                          p11_get_ckm(&mechtable_funcs, mech->mechanism));
            rc = CKR_OK;
            goto testcase_cleanup;
        }
    } else if (mech->mechanism == CKM_IBM_ECDSA_OTHER &&
               memcmp(params, secp256k1, MIN(params_len, sizeof(secp256k1))) != 0 &&
               memcmp(params, prime256v1, MIN(params_len, sizeof(prime256v1))) != 0 &&
               memcmp(params, brainpoolP256r1, MIN(params_len, sizeof(brainpoolP256r1))) != 0 &&
               memcmp(params, brainpoolP256t1, MIN(params_len, sizeof(brainpoolP256t1)))) {
        /* CKM_IBM_ECDSA_OTHER can only be used with 256-bit EC curves, skip */
        testcase_skip("Mechanism %s can only be used with 256-bit EC curves",
                      p11_get_ckm(&mechtable_funcs, mech->mechanism));
        rc = CKR_OK;
        goto testcase_cleanup;
    } else {
        if (curve_type == CURVE_EDWARDS || curve_type == CURVE_MONTGOMERY) {
            /* Mechanism does not match to curve type, skip */
            testcase_skip("Mechanism %s can not be used with Edwards/Montogmery curves",
                          p11_get_ckm(&mechtable_funcs, mech->mechanism));
            rc = CKR_OK;
            goto testcase_cleanup;
        }
    }

    if (inputlen > 0) {
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
    }

    rc = funcs->C_SignInit(session, mech, priv_key);
    if (rc != CKR_OK) {
        testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (parts > 0) {
        if (inputlen > 0) {
            for (i = 0; i < parts && inputlen > 0; i++) {
                rc = funcs->C_SignUpdate(session, data, inputlen);
                if (rc != CKR_OK) {
                    testcase_error("C_SignUpdate rc=%s", p11_get_ckr(rc));
                    goto testcase_cleanup;
                }
            }
        } else {
            rc = funcs->C_SignUpdate(session, NULL, 0);
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
        rc = funcs->C_Sign(session, data != NULL ? data : (CK_BYTE *)"",
                           inputlen, NULL, &signaturelen);
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
        rc = funcs->C_Sign(session, data != NULL ? data : (CK_BYTE *)"",
                           inputlen, signature, &signaturelen);
        if (rc != CKR_OK) {
            testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    /****** Verify *******/
    rc = funcs->C_VerifyInit(session, mech, publ_key);
    if (rc != CKR_OK) {
        testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (parts > 0) {
        if (inputlen > 0) {
            for (i = 0; i < parts && inputlen > 0; i++) {
                rc = funcs->C_VerifyUpdate(session, data, inputlen);
                if (rc != CKR_OK) {
                    testcase_error("C_VerifyUpdate rc=%s", p11_get_ckr(rc));
                    goto testcase_cleanup;
                }
            }
        } else {
            rc = funcs->C_VerifyUpdate(session, NULL, 0);
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
        rc = funcs->C_Verify(session, data != NULL ? data : (CK_BYTE *)"",
                             inputlen, signature, signaturelen);
        if (rc != CKR_OK) {
            testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    // corrupt the signature and re-verify
    memcpy(signature, "ABCDEFGHIJKLMNOPQRSTUV",
           strlen("ABCDEFGHIJKLMNOPQRSTUV"));

    rc = funcs->C_VerifyInit(session, mech, publ_key);
    if (rc != CKR_OK) {
        testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (parts > 0) {
        if (inputlen > 0) {
            for (i = 0; i < parts && inputlen > 0; i++) {
                rc = funcs->C_VerifyUpdate(session, data, inputlen);
                if (rc != CKR_OK) {
                    testcase_error("C_VerifyUpdate rc=%s", p11_get_ckr(rc));
                    goto testcase_cleanup;
                }
            }
        } else {
            rc = funcs->C_VerifyUpdate(session, NULL, 0);
            if (rc != CKR_OK) {
                testcase_error("C_VerifyUpdate rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }
        }

        rc = funcs->C_VerifyFinal(session, signature, signaturelen);
        if (rc != CKR_SIGNATURE_INVALID) {
            if (rc ==  CKR_FUNCTION_FAILED && is_ica_token(SLOT_ID)) {
                testcase_notice("C_VerifyFinal rc=%s temporarily accepted for ICA token",
                                p11_get_ckr(rc));
            } else {
                testcase_error("C_VerifyFinal rc=%s", p11_get_ckr(rc));
                PRINT_ERR("		Expected CKR_SIGNATURE_INVALID\n");
                goto testcase_cleanup;
            }
        }
    } else {
        rc = funcs->C_Verify(session, data != NULL ? data : (CK_BYTE *)"",
                             inputlen, signature, signaturelen);
        if (rc != CKR_SIGNATURE_INVALID) {
            if (rc ==  CKR_FUNCTION_FAILED && is_ica_token(SLOT_ID)) {
                testcase_notice("C_Verify rc=%s temporarily accepted for ICA token",
                                p11_get_ckr(rc));
            } else {
                testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
                PRINT_ERR("		Expected CKR_SIGNATURE_INVALID\n");
                goto testcase_cleanup;
            }
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

CK_RV run_GenerateECCKeyPairSignVerify(void)
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i, j;
    CK_FLAGS flags;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    testcase_begin("Starting ECC generate key pair with pkey=%X ...", pkey);

    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(SLOT_ID) && !is_cca_token(SLOT_ID)) {
        testcase_skip("pkey test option is true, but slot %u doesn't support protected keys",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

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

        if (der_ec_supported[i].type == CURVE_MONTGOMERY) {
            testcase_skip("Montgomery curves can not be used for sign/verify");
            continue;
        }

        if (!is_ep11_token(SLOT_ID)) {
            if (der_ec_supported[i].twisted) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, der_ec_supported[i].name);
                continue;
            }
            if (der_ec_supported[i].curve == secp256k1) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, der_ec_supported[i].name);
                continue;
            }
            if (der_ec_supported[i].type != CURVE_BRAINPOOL &&
                der_ec_supported[i].type != CURVE_PRIME ) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID,der_ec_supported[i].name);
                continue;
            }
        }

        rc = generate_EC_KeyPair(session, (CK_BYTE *)der_ec_supported[i].curve,
                                 der_ec_supported[i].size,
                                 &publ_key, &priv_key, !pkey);

        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("EC key generation is not allowed by policy");
                continue;
            }
            if (rc == CKR_MECHANISM_PARAM_INVALID ||
                rc == CKR_ATTRIBUTE_VALUE_INVALID ||
                rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, der_ec_supported[i].name);
                continue;
            }
            testcase_fail
                ("generate_EC_KeyPair with valid input failed at i=%lu (%s), "
                 "rc=%s", i, der_ec_supported[i].name, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Generate supported key pair index=%lu passed.", i);

        for (j = 0;
             j < (sizeof(signVerifyInput) / sizeof(_signVerifyParam)); j++) {
            testcase_new_assertion();
            rc = run_GenerateSignVerifyECC(session,
                                           &signVerifyInput[j].mech,
                                           signVerifyInput[j].inputlen,
                                           signVerifyInput[j].parts,
                                           priv_key, publ_key,
                                           der_ec_supported[i].type,
                                           (CK_BYTE *)der_ec_supported[i].curve,
                                           der_ec_supported[i].size);
            if (rc != 0) {
                testcase_fail("run_GenerateSignVerifyECC failed index=%lu.", j);
                goto testcase_cleanup;
            }
            testcase_pass("*Sign & verify i=%lu, j=%lu passed.", i, j);
        }

        if (publ_key != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, publ_key);
        publ_key = CK_INVALID_HANDLE;
        if (priv_key != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, priv_key);
        priv_key = CK_INVALID_HANDLE;
    }

    for (i = 0; i < NUMECINVAL; i++) {
        rc = generate_EC_KeyPair(session, (CK_BYTE *)der_ec_notsupported[i].curve,
                                 der_ec_notsupported[i].size,
                                 &publ_key, &priv_key, !pkey);
        testcase_new_assertion();
        if (rc == CKR_OK) {
            testcase_fail
                ("generate_EC_KeyPair with invalid input failed at i=%lu (%s)",
                 i, der_ec_supported[i].name);
            goto testcase_cleanup;
        }
        testcase_pass("*Generate unsupported key pair curve=%s passed.",
                      der_ec_supported[i].name);
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

CK_RV run_ImportECCKeyPairSignVerify(void)
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i, j;
    CK_FLAGS flags;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    testcase_begin("Starting ECC import key pair with pkey=%X ...", pkey);

    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(SLOT_ID) && !is_cca_token(SLOT_ID)) {
        testcase_skip("pkey test option is true, but slot %u doesn't support protected keys",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

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
        if ((is_ica_token(SLOT_ID) || is_cca_token(SLOT_ID) ||
             is_icsf_token(SLOT_ID))) {
            if (!curve_supported((char *)ec_tv[i].name)) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int)SLOT_ID,ec_tv[i].name);
                continue;
            }
        }

        rc = create_ECPrivateKey(session, ec_tv[i].params, ec_tv[i].params_len,
                                 ec_tv[i].privkey, ec_tv[i].privkey_len,
                                 &priv_key, !pkey);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("EC key import is not allowed by policy");
                continue;
            }
            if (rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, ec_tv[i].name);
                continue;
            }

            if (is_ep11_token(SLOT_ID) &&
                rc == CKR_ENCRYPTED_DATA_INVALID &&
                (ec_tv[i].curve_type == CURVE_EDWARDS ||
                 ec_tv[i].curve_type == CURVE_MONTGOMERY)) {
                testcase_skip("Slot %u doesn't support this curve %s with "
                              "older firmware versions",
                              (unsigned int)SLOT_ID, ec_tv[i].name);
                continue;
            }

            testcase_fail("C_CreateObject (EC Private Key) failed at i=%lu "
                          "(%s), rc=%s", i, ec_tv[i].name, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import EC private key (%s) index=%lu passed.",
                      ec_tv[i].name, i);

        rc = create_ECPublicKey(session, ec_tv[i].params, ec_tv[i].params_len,
                                ec_tv[i].pubkey, ec_tv[i].pubkey_len,
                                &publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("EC key import is not allowed by policy");
                funcs->C_DestroyObject(session, priv_key);
                continue;
            }
            if (rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, ec_tv[i].name);
                funcs->C_DestroyObject(session, priv_key);
                continue;
            }

            if (is_ep11_token(SLOT_ID) &&
                rc == CKR_ENCRYPTED_DATA_INVALID &&
                (ec_tv[i].curve_type == CURVE_EDWARDS ||
                 ec_tv[i].curve_type == CURVE_MONTGOMERY)) {
                testcase_skip("Slot %u doesn't support this curve %s with "
                              "older firmware versions",
                              (unsigned int)SLOT_ID, ec_tv[i].name);
                funcs->C_DestroyObject(session, priv_key);
                continue;
            }

            testcase_fail("C_CreateObject (EC Public Key) failed at i=%lu "
                          "(%s), rc=%s", i, ec_tv[i].name, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import EC public key (%s) index=%lu passed.",
                      ec_tv[i].name, i);

        /* create signature with private key */
        for (j = 0;
             j < (sizeof(signVerifyInput) / sizeof(_signVerifyParam)); j++) {
            testcase_new_assertion();
            rc = run_GenerateSignVerifyECC(session,
                                           &signVerifyInput[j].mech,
                                           signVerifyInput[j].inputlen,
                                           signVerifyInput[j].parts,
                                           priv_key, publ_key,
                                           ec_tv[i].curve_type,
                                           ec_tv[i].params,
                                           ec_tv[i].params_len);
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

CK_RV run_TransferECCKeyPairSignVerify(void)
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

    testcase_begin("Starting ECC transfer key pair with pkey=%X ...", pkey);

    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(SLOT_ID) && !is_cca_token(SLOT_ID)) {
        testcase_skip("pkey test option is true, but slot %u doesn't support protected keys",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

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

    rc = funcs->C_GetMechanismInfo(SLOT_ID, CKM_AES_KEY_GEN, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for AES key gen? skip */
            testcase_skip("Slot %u doesn't support CKM_AES_KEY_GEN",
                          (unsigned int) SLOT_ID);
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    rc = funcs->C_GetMechanismInfo(SLOT_ID, CKM_AES_CBC_PAD, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for AES CBC wrap? skip */
            testcase_skip("Slot %u doesn't support CKM_AES_CBC_PAD",
                          (unsigned int) SLOT_ID);
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
    if ((mech_info.flags & CKF_WRAP) == 0 ||
        (mech_info.flags & CKF_UNWRAP) == 0) {
        /* no support for AES CBC wrap? skip */
        testcase_skip("Slot %u doesn't support CKM_AES_CBC_PAD for wrapping "
                      "keys", (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

    for (i = 0; i < EC_TV_NUM; i++) {
        if (!(is_ep11_token(SLOT_ID))) {
            if (strstr((char *)ec_tv[i].name, "t1") != NULL) {
                testcase_skip("Slot %u doesn't support curve %s",
                              (unsigned int)SLOT_ID, ec_tv[i].name);
                continue;
            }
            if (ec_tv[i].curve_type == CURVE_EDWARDS ||
                ec_tv[i].curve_type == CURVE_MONTGOMERY) {
                testcase_skip("Slot %u doesn't support curve %s",
                              (unsigned int)SLOT_ID, ec_tv[i].name);
                continue;
            }
        }

        rc = create_ECPrivateKey(session, ec_tv[i].params, ec_tv[i].params_len,
                                 ec_tv[i].privkey, ec_tv[i].privkey_len,
                                 &priv_key, CK_TRUE); // key to be wrapped must be extractable

        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("EC key import is not allowed by policy");
                continue;
            }
            if (rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, ec_tv[i].name);
                continue;
            }

            if (is_ep11_token(SLOT_ID) &&
                rc == CKR_ENCRYPTED_DATA_INVALID &&
                (ec_tv[i].curve_type == CURVE_EDWARDS ||
                 ec_tv[i].curve_type == CURVE_MONTGOMERY)) {
                testcase_skip("Slot %u doesn't support this curve %s with "
                              "older firmware versions",
                              (unsigned int)SLOT_ID, ec_tv[i].name);
                continue;
            }

            testcase_fail
                ("C_CreateObject (EC Private Key) failed at i=%lu, rc=%s", i,
                 p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import EC private key (%s) index=%lu passed.",
                      ec_tv[i].name, i);

        rc = create_ECPublicKey(session, ec_tv[i].params, ec_tv[i].params_len,
                                ec_tv[i].pubkey, ec_tv[i].pubkey_len,
                                &publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("EC key import is not allowed by policy");
                funcs->C_DestroyObject(session, priv_key);
                continue;
            }
            if (rc == CKR_CURVE_NOT_SUPPORTED) {
                testcase_skip("Slot %u doesn't support this curve: %s",
                              (unsigned int) SLOT_ID, ec_tv[i].name);
                funcs->C_DestroyObject(session, priv_key);
                continue;
            }

            if (is_ep11_token(SLOT_ID) &&
                rc == CKR_ENCRYPTED_DATA_INVALID &&
                (ec_tv[i].curve_type == CURVE_EDWARDS ||
                 ec_tv[i].curve_type == CURVE_MONTGOMERY)) {
                testcase_skip("Slot %u doesn't support this curve %s with "
                              "older firmware versions",
                              (unsigned int)SLOT_ID, ec_tv[i].name);
                funcs->C_DestroyObject(session, priv_key);
                continue;
            }

            testcase_fail
                ("C_CreateObject (EC Public Key) failed at i=%lu, rc=%s", i,
                 p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import EC public key (%s) index=%lu passed.",
                      ec_tv[i].name, i);

        /* create wrapping key (secret key) */
        aes_keygen_mech.mechanism = CKM_AES_KEY_GEN;

        CK_OBJECT_CLASS wkclass = CKO_SECRET_KEY;
        CK_ULONG keylen = 32;
        CK_BBOOL true = TRUE;
        CK_BBOOL false = FALSE;
        CK_BBOOL sign = TRUE;
        CK_BBOOL derive = TRUE;
        CK_BYTE wrap_key_label[] = "Wrap_Key";
        CK_OBJECT_CLASS wclass = CKO_PRIVATE_KEY;
        CK_KEY_TYPE keyType = CKK_EC;
        CK_ATTRIBUTE cka_wrap_tmpl[] = {
            {CKA_PRIVATE, &true, sizeof(true)},
            {CKA_CLASS, &wclass, sizeof(wclass)},
            {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        };
        CK_ATTRIBUTE cka_unwrap_tmpl[] = {
            {CKA_DECRYPT, &true, sizeof(true)},
            {CKA_SIGN, &sign, sizeof(sign)},
            {CKA_DERIVE, &derive, sizeof(derive)},
            {CKA_PRIVATE, &true, sizeof(true)},
            {CKA_IBM_PROTKEY_EXTRACTABLE, &true, sizeof(true)},
            {CKA_EXTRACTABLE, &false, sizeof(false)},
        };
        CK_ATTRIBUTE secret_tmpl[] = {
            {CKA_CLASS, &wkclass, sizeof(wkclass)},
            {CKA_VALUE_LEN, &keylen, sizeof(keylen)},
            {CKA_LABEL, &wrap_key_label, sizeof(wrap_key_label)},
            {CKA_TOKEN, &true, sizeof(true)},
            {CKA_WRAP, &true, sizeof(true)},
            {CKA_UNWRAP, &true, sizeof(true)},
            {CKA_WRAP_TEMPLATE, &cka_wrap_tmpl, sizeof(cka_wrap_tmpl)},
            {CKA_UNWRAP_TEMPLATE, &cka_unwrap_tmpl, sizeof(cka_unwrap_tmpl)},
        };
        CK_ULONG secret_tmpl_len = sizeof(secret_tmpl) / sizeof(CK_ATTRIBUTE);

        if (ec_tv[i].curve_type == CURVE_EDWARDS)
            derive = FALSE;
        if (ec_tv[i].curve_type == CURVE_MONTGOMERY)
            sign = FALSE;

        if (is_icsf_token(SLOT_ID))
            secret_tmpl_len -= 2; /* ICSF does not support array-attributes */

        rc = funcs->C_GenerateKey(session, &aes_keygen_mech, secret_tmpl,
                                  secret_tmpl_len, &secret_key);
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
        CK_BYTE id[] = { 123 };

        CK_ATTRIBUTE unwrap_tmpl[] = {
            {CKA_CLASS, &class, sizeof(class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_TOKEN, &true, sizeof(true)},
            {CKA_LABEL, &unwrap_label, sizeof(unwrap_label)},
            {CKA_ID, id, sizeof(id)},
            {CKA_SENSITIVE, &true, sizeof(true)},
            {CKA_DERIVE, &derive, sizeof(derive)},
            {CKA_SIGN, &sign, sizeof(sign)},
            {CKA_EXTRACTABLE, &false, sizeof(false)},
            {CKA_IBM_PROTKEY_EXTRACTABLE, &true, sizeof(true)},
        };
        CK_ULONG unwrap_tmpl_len = sizeof(unwrap_tmpl) / sizeof(CK_ATTRIBUTE);

        if (is_icsf_token(SLOT_ID))
            unwrap_tmpl_len -= 1; /* ICSF does not supp. CKA_IBM_PROTKEY_... */

        rc = funcs->C_UnwrapKey(session, &wrap_mech, secret_key,
                                wrapped_key, wrapped_keylen,
                                unwrap_tmpl, unwrap_tmpl_len,
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
                                           &signVerifyInput[j].mech,
                                           signVerifyInput[j].inputlen,
                                           signVerifyInput[j].parts,
                                           unwrapped_key, publ_key,
                                           ec_tv[i].curve_type,
                                           ec_tv[i].params,
                                           ec_tv[i].params_len);
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

/**
 * Tests the EP11 token protected key option. PKEY_MODE ENABLE4NONEXTR must be
 * set in ep11tok.conf in order to activate protected key support. With MSA9,
 * ECDSA with curves p256, p384, p521, and EDDSA with curves ed25519, and
 * ed448 are supported via CPACF. On older machines there is no CPACF support
 * for EC/ED at all and therefore all tests are performed only via the ep11
 * card. So the actual behavior of this testcase heavily depends on the
 * machine and token config.
 */
CK_RV run_ImportSignVerify_Pkey(void)
{
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_FLAGS flags;
    CK_RV rc;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE keytype = CKK_EC;
    CK_BBOOL true = TRUE;
    CK_BBOOL extr_priv, pkey_extr_priv, pkey_extr_pub;
    CK_MECHANISM ec_mech = {CKM_ECDSA, NULL, 0};
    CK_MECHANISM ed25519_mech = {CKM_IBM_ED25519_SHA512, NULL, 0};
    CK_MECHANISM ed448_mech = {CKM_IBM_ED448_SHA3, NULL, 0};
    CK_BYTE data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    };
    CK_BYTE *sig = NULL;
    CK_ULONG sig_len;
    unsigned int i, j;

    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(SLOT_ID) && !is_cca_token(SLOT_ID)) {
        testcase_skip("pkey test option is true, but slot %u doesn't support protected keys",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

    for (i = 0; i < EC_TV_NUM; i++) {

        CK_ATTRIBUTE priv_tmpl[] = {
            {CKA_CLASS, &class, sizeof(CK_OBJECT_CLASS)},
            {CKA_KEY_TYPE, &keytype, sizeof(CK_KEY_TYPE)},
            {CKA_PRIVATE, &true, sizeof(CK_BBOOL)},
            {CKA_SIGN, &true, sizeof(CK_BBOOL)},
            {CKA_EC_PARAMS, ec_tv[i].params, ec_tv[i].params_len},
            {CKA_EC_POINT, ec_tv[i].pubkey, ec_tv[i].pubkey_len},
            {CKA_VALUE, ec_tv[i].privkey, ec_tv[i].privkey_len},
            {CKA_EXTRACTABLE, &extr_priv, sizeof(CK_BBOOL)},
            {CKA_IBM_PROTKEY_EXTRACTABLE, &pkey_extr_priv, sizeof(CK_BBOOL)},
        };
        CK_ATTRIBUTE publ_tmpl[] = {
            {CKA_CLASS, &class, sizeof(CK_OBJECT_CLASS)},
            {CKA_KEY_TYPE, &keytype, sizeof(CK_KEY_TYPE)},
            {CKA_VERIFY, &true, sizeof(CK_BBOOL)},
            {CKA_EC_PARAMS, ec_tv[i].params, ec_tv[i].params_len},
            {CKA_EC_POINT, ec_tv[i].pubkey, ec_tv[i].pubkey_len},
            {CKA_IBM_PROTKEY_EXTRACTABLE, &pkey_extr_pub, sizeof(CK_BBOOL)},
        };

        for (j = 0; j < 2; j++) {

            if (j == 0)
                testcase_begin("Starting Import EC private key (%s) index=%u sign via CPACF / verify via card",
                               ec_tv[i].name, i);
            else
                testcase_begin("Starting Import EC private key (%s) index=%u sign via card / verify via CPACF",
                               ec_tv[i].name, i);

            /* j toggles between sign via protected key / verify via card
             * and vice versa. */
            if (j == 0) {
                extr_priv = FALSE;
                pkey_extr_priv = TRUE;
                pkey_extr_pub = FALSE;
            } else {
                extr_priv = TRUE;
                pkey_extr_priv = FALSE;
                pkey_extr_pub = TRUE;
            }

            class = CKO_PRIVATE_KEY;
            rc = funcs->C_CreateObject(session, priv_tmpl,
                                       sizeof(priv_tmpl) / sizeof(CK_ATTRIBUTE),
                                       &priv_key);
            if (rc != CKR_OK) {
                if (is_rejected_by_policy(rc, session)) {
                    testcase_skip("EC key generation is not allowed by policy");
                    continue;
                }
                if (rc == CKR_CURVE_NOT_SUPPORTED) {
                    testcase_skip("Slot %u doesn't support this curve: %s",
                                  (unsigned int) SLOT_ID, ec_tv[i].name);
                    continue;
                }
                testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            class = CKO_PUBLIC_KEY;
            rc = funcs->C_CreateObject(session, publ_tmpl,
                                       sizeof(publ_tmpl) / sizeof(CK_ATTRIBUTE),
                                       &publ_key);
            if (rc != CKR_OK) {
                if (is_rejected_by_policy(rc, session)) {
                    testcase_skip("EC key generation is not allowed by policy");
                    goto testcase_cleanup;
                }
                testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            if (ec_tv[i].curve_type != CURVE_EDWARDS &&
                ec_tv[i].curve_type != CURVE_MONTGOMERY)
                rc = funcs->C_SignInit(session, &ec_mech, priv_key);
            else if (memcmp(ec_tv[i].name, "ed25519", 7) == 0)
                rc = funcs->C_SignInit(session, &ed25519_mech, priv_key);
            else if (memcmp(ec_tv[i].name, "ed448", 5) == 0)
                rc = funcs->C_SignInit(session, &ed448_mech, priv_key);
            else {
                testcase_skip("Sign/verify not supported for curve %s.",
                              ec_tv[i].name);
                continue;
            }
            if (rc != CKR_OK) {
                testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            testcase_new_assertion();

            rc = funcs->C_Sign(session, data, sizeof(data), NULL, &sig_len);
            if (rc != CKR_OK) {
                testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            sig = calloc(sizeof(CK_BYTE), sig_len);
            if (sig == NULL) {
                testcase_error("Can't allocate memory for %lu bytes", sig_len);
                rc = CKR_HOST_MEMORY;
                goto testcase_cleanup;
            }

            rc = funcs->C_Sign(session, data, sizeof(data), sig, &sig_len);
            if (rc != CKR_OK) {
                testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            if (ec_tv[i].curve_type != CURVE_EDWARDS &&
                ec_tv[i].curve_type != CURVE_MONTGOMERY)
                rc = funcs->C_VerifyInit(session, &ec_mech, publ_key);
            else if (memcmp(ec_tv[i].name, "ed25519", 7) == 0)
                rc = funcs->C_VerifyInit(session, &ed25519_mech, publ_key);
            else
                rc = funcs->C_VerifyInit(session, &ed448_mech, publ_key);

            if (rc != CKR_OK) {
                testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            rc = funcs->C_Verify(session, data, sizeof(data), sig, sig_len);
            if (rc != CKR_OK) {
                testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            if (sig) {
                free(sig);
                sig = NULL;
            }

            if (j == 0)
                testcase_pass("*Import EC private key (%s) index=%u sign via CPACF / verify via card passed.",
                              ec_tv[i].name, i);
            else
                testcase_pass("*Import EC private key (%s) index=%u sign via card / verify via CPACF passed.",
                              ec_tv[i].name, i);
        }
    }

    rc = CKR_OK;

testcase_cleanup:
    if (publ_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_key);
    if (priv_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_key);
    if (sig)
        free(sig);

    testcase_close_session();
    return rc;
}

struct btc_test {
    const _ec_struct ec;
    CK_ULONG master_key_derive;
    CK_ULONG priv_to_pub;
    CK_ULONG priv_to_priv;
    CK_ULONG pub_to_pub;
};

static const struct btc_test btc_tests[] = {
    { .ec = { &secp256k1, sizeof(secp256k1), CK_FALSE, CURVE_PRIME,
              CURVE256_LENGTH, "secp256k1" },
      .master_key_derive = CK_IBM_BTC_BIP0032_MASTERK,
      .priv_to_pub = CK_IBM_BTC_BIP0032_PRV2PUB,
      .priv_to_priv = CK_IBM_BTC_BIP0032_PRV2PRV,
      .pub_to_pub = CK_IBM_BTC_BIP0032_PUB2PUB,
    },
    { .ec = { &secp256k1, sizeof(secp256k1), CK_FALSE, CURVE_PRIME,
              CURVE256_LENGTH, "secp256k1" },
      .master_key_derive = CK_IBM_BTC_SLIP0010_MASTERK,
      .priv_to_pub = CK_IBM_BTC_SLIP0010_PRV2PUB,
      .priv_to_priv = CK_IBM_BTC_SLIP0010_PRV2PRV,
      .pub_to_pub = CK_IBM_BTC_SLIP0010_PUB2PUB,
    },
    { .ec = { &prime256v1, sizeof(prime256v1), CK_FALSE, CURVE_PRIME,
              CURVE256_LENGTH, "prime256v1" },
      .master_key_derive = CK_IBM_BTC_SLIP0010_MASTERK,
      .priv_to_pub = CK_IBM_BTC_SLIP0010_PRV2PUB,
      .priv_to_priv = CK_IBM_BTC_SLIP0010_PRV2PRV,
      .pub_to_pub = CK_IBM_BTC_SLIP0010_PUB2PUB,
    },
    { .ec = { &ed25519, sizeof(ed25519), CK_FALSE, CURVE_EDWARDS,
              CURVE256_LENGTH, "ed25519" },
      .master_key_derive = CK_IBM_BTC_SLIP0010_MASTERK,
      .priv_to_pub = CK_IBM_BTC_SLIP0010_PRV2PUB,
      .priv_to_priv = CK_IBM_BTC_SLIP0010_PRV2PRV,
      .pub_to_pub = CK_IBM_BTC_SLIP0010_PUB2PUB,
    },
};

#define NUM_BTC_TESTS  4

static const CK_ULONG btc_child_key_index[] = {
    0,
    0x12,
    0x3456,
    0x987654,
    0x7fffffff,
    0 + CK_IBM_BTC_BIP0032_HARDENED,
    0x12 + CK_IBM_BTC_BIP0032_HARDENED,
    0x3456 + CK_IBM_BTC_BIP0032_HARDENED,
    0x987654 + CK_IBM_BTC_BIP0032_HARDENED,
    0x7fffffff + CK_IBM_BTC_BIP0032_HARDENED,
};

#define NUM_BTC_CHILD_KEY_INDEXES  10

static const char *btc_type_to_str(CK_ULONG btc_type)
{
    switch (btc_type) {
    case CK_IBM_BTC_BIP0032_PRV2PRV:
        return "CK_IBM_BTC_BIP0032_PRV2PRV";
    case CK_IBM_BTC_BIP0032_PRV2PUB:
        return "CK_IBM_BTC_BIP0032_PRV2PUB";
    case CK_IBM_BTC_BIP0032_PUB2PUB:
        return "CK_IBM_BTC_BIP0032_PUB2PUB";
    case CK_IBM_BTC_BIP0032_MASTERK:
        return "CK_IBM_BTC_BIP0032_MASTERK";
    case CK_IBM_BTC_SLIP0010_PRV2PRV:
        return "CK_IBM_BTC_SLIP0010_PRV2PRV";
    case CK_IBM_BTC_SLIP0010_PRV2PUB:
        return "CK_IBM_BTC_SLIP0010_PRV2PUB";
    case CK_IBM_BTC_SLIP0010_PUB2PUB:
        return "CK_IBM_BTC_SLIP0010_PUB2PUB";
    case CK_IBM_BTC_SLIP0010_MASTERK:
        return "CK_IBM_BTC_SLIP0010_MASTERK";
    default:
        return "UNKNOWN";
    }
}

/*
 * Run Bitcoin Key Derivation tests:
 * Derive a BTC master key from a generic secret key. Then derive a number of
 * child keys (public and private, hardened and non hardened) from the master
 * key.
 */
CK_RV run_DeriveBTC(void)
{
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech;
    CK_FLAGS flags;
    CK_OBJECT_HANDLE secret = CK_INVALID_HANDLE, master = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE child_priv = CK_INVALID_HANDLE, child_pub = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE child_pub2 = CK_INVALID_HANDLE;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc = CKR_OK;
    CK_BBOOL true = CK_TRUE;
    CK_IBM_BTC_DERIVE_PARAMS btc_parms;
    CK_BYTE master_chain_code[CK_IBM_BTC_CHAINCODE_LENGTH];
    CK_BYTE child_chain_code[CK_IBM_BTC_CHAINCODE_LENGTH];
    CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
    CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_EC;
    CK_OBJECT_CLASS secret_class = CKO_SECRET_KEY;
    CK_ULONG secret_keylen = 32;
    CK_ULONG i, k;

    testsuite_begin("starting run_DeriveBTC with pkey=%X ...", pkey);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(SLOT_ID) && !is_cca_token(SLOT_ID)) {
        testcase_skip("pkey test option is true, but slot %u doesn't support protected keys",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, CKM_GENERIC_SECRET_KEY_GEN)) {
        testcase_skip("Slot %u doesn't support CKM_GENERIC_SECRET_KEY_GEN\n",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, CKM_IBM_BTC_DERIVE)) {
        testcase_skip("Slot %u doesn't support CKM_IBM_BTC_DERIVE\n",
                      (unsigned int) SLOT_ID);
        goto testcase_cleanup;
    }

    for (i = 0; i < NUM_BTC_TESTS; i++) {
        CK_ATTRIBUTE secret_tmpl[] = {
            {CKA_CLASS, &secret_class, sizeof(secret_class)},
            {CKA_VALUE_LEN, &secret_keylen, sizeof(secret_keylen)},
            {CKA_IBM_USE_AS_DATA, &true, sizeof(true)},
        };
        CK_ULONG secret_tmpl_len = sizeof(secret_tmpl) / sizeof(CK_ATTRIBUTE);
        CK_ATTRIBUTE priv_derive_tmpl[] = {
            {CKA_CLASS, &priv_class, sizeof(priv_class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_DERIVE, &true, sizeof(true)},
            {CKA_EC_PARAMS, (CK_VOID_PTR)btc_tests[i].ec.curve, btc_tests[i].ec.size},
            {CKA_IBM_USE_AS_DATA, &true, sizeof(true)},
        };
        CK_ULONG priv_derive_tmpl_len =  sizeof(priv_derive_tmpl) / sizeof(CK_ATTRIBUTE);
        CK_ATTRIBUTE pub_derive_tmpl[] = {
            {CKA_CLASS, &pub_class, sizeof(pub_class)},
            {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
            {CKA_DERIVE, &true, sizeof(true)},
            {CKA_EC_PARAMS, (CK_VOID_PTR)btc_tests[i].ec.curve, btc_tests[i].ec.size},
            {CKA_IBM_USE_AS_DATA, &true, sizeof(true)},
        };
        CK_ULONG pub_derive_tmpl_len = sizeof(pub_derive_tmpl) / sizeof(CK_ATTRIBUTE);

        /* Testcase #1: Derive the BTC master key from a secret key */
        testcase_new_assertion();
        testcase_begin("BTC master key derive with curve=%s and type=%s, pkey=%X",
                       btc_tests[i].ec.name,
                       btc_type_to_str(btc_tests[i].master_key_derive), pkey);

        mech.mechanism = CKM_GENERIC_SECRET_KEY_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        rc = funcs->C_GenerateKey(session, &mech, secret_tmpl, secret_tmpl_len,
                                  &secret);
        if (rc != CKR_OK) {
            testcase_fail("C_GenerateKey, rc=%s", p11_get_ckr(rc));
            goto run_cleanup;
        }

        mech.mechanism = CKM_IBM_BTC_DERIVE;
        mech.ulParameterLen = sizeof(CK_IBM_BTC_DERIVE_PARAMS);
        mech.pParameter = &btc_parms;

        memset(master_chain_code, 0, sizeof(master_chain_code));
        memset(&btc_parms, 0, sizeof(btc_parms));
        btc_parms.version = CK_IBM_BTC_DERIVE_PARAMS_VERSION_1;
        btc_parms.type = btc_tests[i].master_key_derive;
        btc_parms.childKeyIndex = 0;
        btc_parms.ulChainCodeLen = 0;
        btc_parms.pChainCode = master_chain_code;

        rc = funcs->C_DeriveKey(session, &mech,
                                secret, priv_derive_tmpl,
                                priv_derive_tmpl_len, &master);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey BTC master key: rc = %s",
                          p11_get_ckr(rc));
            goto run_cleanup;
        }

        testcase_pass("BTC master key derive with curve=%s and type=%s, pkey=%X",
                      btc_tests[i].ec.name,
                      btc_type_to_str(btc_tests[i].master_key_derive), pkey);

        /* Derive child keys from the master key */
        for (k = 0; k < NUM_BTC_CHILD_KEY_INDEXES; k++) {
            /* Testcase #2: Derive private child key from private master key */

            /* For ed25519 only hardened child keys are supported (SLIP0010) */
            if (btc_tests[i].master_key_derive == CK_IBM_BTC_SLIP0010_MASTERK &&
                btc_tests[i].ec.type == CURVE_EDWARDS &&
                (btc_child_key_index[k] & CK_IBM_BTC_BIP0032_HARDENED) == 0)
                continue;

            testcase_new_assertion();
            testcase_begin("BTC priv-to-priv child key derive with curve=%s child-key-index=0x%lx and type=%s, pkey=%X",
                           btc_tests[i].ec.name, btc_child_key_index[k],
                           btc_type_to_str(btc_tests[i].priv_to_priv), pkey);

            mech.mechanism = CKM_IBM_BTC_DERIVE;
            mech.ulParameterLen = sizeof(CK_IBM_BTC_DERIVE_PARAMS);
            mech.pParameter = &btc_parms;

            memcpy(child_chain_code, master_chain_code, sizeof(master_chain_code));
            memset(&btc_parms, 0, sizeof(btc_parms));
            btc_parms.version = CK_IBM_BTC_DERIVE_PARAMS_VERSION_1;
            btc_parms.type = btc_tests[i].priv_to_priv;
            btc_parms.childKeyIndex = btc_child_key_index[k];
            btc_parms.ulChainCodeLen = sizeof(child_chain_code);
            btc_parms.pChainCode = child_chain_code;

            rc = funcs->C_DeriveKey(session, &mech,
                                    master, priv_derive_tmpl,
                                    priv_derive_tmpl_len, &child_priv);
            if (rc != CKR_OK) {
                testcase_fail("C_DeriveKey BTC child key (priv): rc = %s",
                              p11_get_ckr(rc));
                goto run_child_cleanup;
            }

            testcase_pass("BTC priv-to-priv child key derive with curve=%s child-key-index=0x%lx and type=%s, pkey=%X",
                          btc_tests[i].ec.name, btc_child_key_index[k],
                          btc_type_to_str(btc_tests[i].priv_to_priv), pkey);

            /* Testcase #3: Derive public child key from private master key */
            testcase_new_assertion();
            testcase_begin("BTC priv-to-pub child key derive with curve=%s child-key-index=0x%lx and type=%s, pkey=%X",
                           btc_tests[i].ec.name, btc_child_key_index[k],
                           btc_type_to_str(btc_tests[i].priv_to_pub), pkey);

            mech.mechanism = CKM_IBM_BTC_DERIVE;
            mech.ulParameterLen = sizeof(CK_IBM_BTC_DERIVE_PARAMS);
            mech.pParameter = &btc_parms;

            memcpy(child_chain_code, master_chain_code, sizeof(master_chain_code));
            memset(&btc_parms, 0, sizeof(btc_parms));
            btc_parms.version = CK_IBM_BTC_DERIVE_PARAMS_VERSION_1;
            btc_parms.type = btc_tests[i].priv_to_pub;
            btc_parms.childKeyIndex = btc_child_key_index[k];
            btc_parms.ulChainCodeLen = sizeof(child_chain_code);
            btc_parms.pChainCode = child_chain_code;

            rc = funcs->C_DeriveKey(session, &mech,
                                    master, pub_derive_tmpl,
                                    pub_derive_tmpl_len, &child_pub);
            if (rc != CKR_OK) {
                testcase_fail("C_DeriveKey BTC child key (pub): rc = %s",
                              p11_get_ckr(rc));
                goto run_child_cleanup;
            }

            testcase_pass("BTC priv-to-pub child key derive with curve=%s child-key-index=0x%lx and type=%s, pkey=%X",
                          btc_tests[i].ec.name, btc_child_key_index[k],
                          btc_type_to_str(btc_tests[i].priv_to_pub), pkey);

            /* Testcase #4: Test if derived keys are usable */
            testcase_new_assertion();

            if (btc_tests[i].ec.type == CURVE_EDWARDS)
                mech.mechanism = CKM_IBM_ED25519_SHA512;
            else
                mech.mechanism = CKM_ECDSA;
            mech.ulParameterLen = 0;
            mech.pParameter = NULL;

            rc = run_GenerateSignVerifyECC(session, &mech, 20, 0,
                                           child_priv, child_pub,
                                           btc_tests[i].ec.type,
                                           (CK_BYTE *)btc_tests[i].ec.curve,
                                           btc_tests[i].ec.size);
            if (rc != 0) {
                testcase_fail("run_GenerateSignVerifyECC failed.");
                goto testcase_cleanup;
            }
            testcase_pass("BTC check derived keys with curve=%s child-key-index=0x%lx, pkey=%X",
                          btc_tests[i].ec.name, btc_child_key_index[k], pkey);

            /*
             * Testcase #5: Derive public child key from public key
             * (non-hardened keys only, thus not supported for ed25519)
             */
            if ((btc_child_key_index[k] & CK_IBM_BTC_BIP0032_HARDENED) != 0)
                goto run_child_cleanup;

            testcase_new_assertion();
            testcase_begin("BTC pub-to-pub child key derive with curve=%s child-key-index=0x%lx and type=%s, pkey=%X",
                           btc_tests[i].ec.name, btc_child_key_index[k],
                           btc_type_to_str(btc_tests[i].pub_to_pub), pkey);

            mech.mechanism = CKM_IBM_BTC_DERIVE;
            mech.ulParameterLen = sizeof(CK_IBM_BTC_DERIVE_PARAMS);
            mech.pParameter = &btc_parms;

            memset(&btc_parms, 0, sizeof(btc_parms));
            btc_parms.version = CK_IBM_BTC_DERIVE_PARAMS_VERSION_1;
            btc_parms.type = btc_tests[i].pub_to_pub;
            btc_parms.childKeyIndex = btc_child_key_index[k];
            btc_parms.ulChainCodeLen = sizeof(child_chain_code);
            btc_parms.pChainCode = child_chain_code;

            rc = funcs->C_DeriveKey(session, &mech,
                                    child_pub, pub_derive_tmpl,
                                    pub_derive_tmpl_len, &child_pub2);
            if (rc != CKR_OK) {
                testcase_fail("C_DeriveKey BTC child key (pub): rc = %s",
                              p11_get_ckr(rc));
                goto run_child_cleanup;
            }

            testcase_pass("BTC pub-to-pub child key derive with curve=%s child-key-index=0x%lx and type=%s, pkey=%X",
                          btc_tests[i].ec.name, btc_child_key_index[k],
                          btc_type_to_str(btc_tests[i].pub_to_pub), pkey);

run_child_cleanup:
            if (child_priv != CK_INVALID_HANDLE)
                funcs->C_DestroyObject(session, child_priv);
            child_priv = CK_INVALID_HANDLE;
            if (child_pub != CK_INVALID_HANDLE)
                funcs->C_DestroyObject(session, child_pub);
            child_pub = CK_INVALID_HANDLE;
            if (child_pub2 != CK_INVALID_HANDLE)
                funcs->C_DestroyObject(session, child_pub2);
            child_pub2 = CK_INVALID_HANDLE;
        }

run_cleanup:
        if (secret != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, secret);
        secret = CK_INVALID_HANDLE;
        if (master != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, master);
        master = CK_INVALID_HANDLE;
    }

testcase_cleanup:
    if (secret != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret);
    if (master != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, master);

    testcase_user_logout();
    testcase_close_session();

    return rc;
} /* end run_DeriveBTC() */

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

    testcase_setup();

    pkey = CK_FALSE;
    rv = run_GenerateECCKeyPairSignVerify();
    rv += run_ImportECCKeyPairSignVerify();
    rv += run_TransferECCKeyPairSignVerify();
    rv += run_DeriveECDHKey();
    rv += run_DeriveECDHKeyKAT();
    rv += run_DeriveBTC();

    if (is_ep11_token(SLOT_ID) || is_cca_token(SLOT_ID)) {
        pkey = CK_TRUE;
        rv = run_GenerateECCKeyPairSignVerify();
        rv += run_ImportECCKeyPairSignVerify();
        rv += run_TransferECCKeyPairSignVerify();
        rv += run_DeriveECDHKey();
        rv += run_DeriveECDHKeyKAT();
        rv += run_ImportSignVerify_Pkey();
    }

    testcase_print_result();

    funcs->C_Finalize(NULL);

    return testcase_return(rv);
}
