/*
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/************************************************************************
*                                                                       *
*      Copyright:       Corrent Corporation (c) 2000-2003               *
*                                                                       *
*      Filename:        dh_func.c                                       *
*      Created By:      Kapil Sood                                      *
*      Created On:      April 28, 2003                                  *
*      Description:     This is the file for testing Diffie-Hellman     *
*                       key pair generation and shared key derivation   *
*                       operations.                                     *
*                                                                       *
************************************************************************/

// File: dh_func.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"


// These values were obtained from openssl genkey.
// These values are in big-endian format.
// These are required for generating DH keys and secrets.


CK_BYTE DH_PUBL_PRIME[128] = {
    0xd5, 0xb1, 0xaa, 0x6a, 0x3b, 0x85, 0x50, 0xf0, 0xe2,
    0xea, 0x6b, 0xec, 0x26, 0x3b, 0xe0, 0xbf, 0x7a, 0x82,
    0x45, 0x1b, 0xa8, 0x0a, 0x54, 0x2e, 0x14, 0x2c, 0xc2,
    0x58, 0xb1, 0xf5, 0x59, 0xec, 0x7d, 0x16, 0x9e, 0x00,
    0x62, 0xb3, 0xa7, 0xdc, 0x38, 0x6f, 0x64, 0x40, 0xfc,
    0x0d, 0x3e, 0x0b, 0x66, 0x13, 0x5e, 0xa5, 0x84, 0x90,
    0x26, 0x62, 0xcf, 0x5a, 0x14, 0x72, 0x2d, 0x1b, 0x37,
    0x7e, 0x8a, 0x4b, 0xc0, 0xb7, 0xf2, 0x63, 0xd1, 0xaa,
    0x51, 0x92, 0x96, 0x18, 0xae, 0xb9, 0xfd, 0x5f, 0x9d,
    0x5d, 0xdf, 0x75, 0xa9, 0x80, 0x3d, 0xaa, 0xc2, 0x54,
    0x00, 0xcc, 0xc1, 0x9e, 0x31, 0x4d, 0x22, 0x31, 0x44,
    0xe9, 0x69, 0x34, 0xae, 0xcf, 0xcd, 0x6d, 0xf6, 0xe9,
    0x37, 0x20, 0xa4, 0xd3, 0x85, 0x24, 0xff, 0x9f, 0x39,
    0xeb, 0x78, 0xf2, 0xd1, 0xc3, 0xf9, 0x66, 0xab, 0xbd,
    0x2d, 0xd3
};


CK_BYTE DH_PUBL_BASE[128] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02
};

CK_BYTE DH_PRIVATE_A[128] = {
    0x69, 0xd1, 0xfd, 0xaf, 0x5f, 0x00, 0x75, 0x0e, 0x85,
    0xfe, 0xc1, 0x8d, 0x5f, 0x0e, 0x86, 0x3f, 0xfa, 0xe0,
    0xef, 0x19, 0x8b, 0xfd, 0x90, 0xe5, 0x8e, 0xd7, 0xc6,
    0x5f, 0xd7, 0x37, 0x20, 0x15, 0xc6, 0x65, 0x6c, 0x9b,
    0xdd, 0xb7, 0x50, 0xda, 0x5e, 0xf0, 0xb9, 0x9f, 0x5d,
    0x9b, 0x06, 0xdf, 0x10, 0xf0, 0x60, 0x74, 0x8e, 0x71,
    0xb5, 0x4b, 0x6f, 0xdf, 0x0b, 0x86, 0x36, 0x54, 0x3d,
    0x95, 0x17, 0x38, 0x27, 0x6f, 0xb7, 0x32, 0x57, 0x2b,
    0x72, 0xc6, 0x9e, 0x81, 0x52, 0x8f, 0xcd, 0x43, 0x6f,
    0x9c, 0x6b, 0xee, 0x58, 0x00, 0x8c, 0xb5, 0xff, 0x94,
    0xfe, 0xbc, 0x2b, 0xd0, 0xab, 0x97, 0x90, 0x7c, 0x2c,
    0xbf, 0xf9, 0x19, 0xa8, 0x19, 0x82, 0xff, 0xf4, 0xc4,
    0xd0, 0x02, 0x01, 0xb7, 0xd5, 0x4b, 0x00, 0x6d, 0x69,
    0x1e, 0xfc, 0x7a, 0x9f, 0xc0, 0x3f, 0x38, 0x8b, 0xb3,
    0xc6, 0x89
};

CK_BYTE DH_PUBLIC_A[128] = {
    0x89, 0x5b, 0xfe, 0x83, 0xdd, 0x18, 0x69, 0x47, 0x86,
    0x28, 0x17, 0x86, 0xba, 0x8f, 0x47, 0x27, 0x3c, 0xe6,
    0x0e, 0x21, 0xac, 0x4f, 0x7f, 0xc4, 0x25, 0xaa, 0x52,
    0x86, 0x26, 0x07, 0xc6, 0x2d, 0x2e, 0xbe, 0xfc, 0xb5,
    0x97, 0xa9, 0x73, 0x57, 0x20, 0x11, 0x77, 0x0a, 0xef,
    0x3e, 0x55, 0x56, 0x29, 0x2b, 0xc3, 0x7f, 0x87, 0x9d,
    0x0f, 0x08, 0xd4, 0x4c, 0x46, 0x7a, 0x37, 0xba, 0xb7,
    0x3d, 0x47, 0xce, 0x70, 0x94, 0x9c, 0xa6, 0x59, 0x61,
    0xf7, 0x98, 0x15, 0x33, 0x7e, 0x6a, 0x25, 0x66, 0x1f,
    0x18, 0x88, 0x5a, 0x02, 0xfa, 0x69, 0xa5, 0x8e, 0x1b,
    0x9e, 0x2f, 0xcb, 0x2b, 0x28, 0x56, 0x8d, 0xcd, 0x92,
    0xea, 0xf0, 0x9d, 0x37, 0x9b, 0xa3, 0x92, 0x5b, 0x9c,
    0x10, 0x02, 0x7d, 0x57, 0xe9, 0xd7, 0x8d, 0x6e, 0x13,
    0x5e, 0x34, 0x9e, 0x8c, 0x15, 0x4e, 0x0f, 0xe2, 0x28,
    0x70, 0x3d
};

CK_BYTE DH_PRIVATE_B[128] = {
    0x71, 0x07, 0xa2, 0x3c, 0x08, 0x08, 0x5c, 0x47, 0x6e,
    0x2d, 0x70, 0xf5, 0x8c, 0xb1, 0xc0, 0xc6, 0x2b, 0xdf,
    0xa7, 0x23, 0x68, 0xcf, 0x84, 0x34, 0x88, 0xb5, 0x0a,
    0x99, 0xc2, 0x7b, 0x08, 0x1f, 0xe8, 0x83, 0x8d, 0x27,
    0x76, 0x28, 0x7c, 0xb8, 0x72, 0xf1, 0x17, 0x99, 0x87,
    0xe3, 0xaa, 0x97, 0xa9, 0x0f, 0x92, 0xa1, 0xe3, 0x6f,
    0x6b, 0x53, 0xff, 0xd1, 0x25, 0x83, 0xb0, 0xca, 0x07,
    0x32, 0x48, 0x72, 0xf3, 0xe5, 0xb4, 0xaf, 0x82, 0x6b,
    0x90, 0x0d, 0x32, 0x46, 0x07, 0x1b, 0x4b, 0x97, 0x73,
    0xbb, 0x4d, 0x57, 0x4e, 0x38, 0x7d, 0x59, 0xd6, 0xd5,
    0xb1, 0xbd, 0x93, 0x85, 0x15, 0xa1, 0x14, 0x98, 0xb7,
    0xe6, 0x7f, 0x8a, 0xf1, 0xbd, 0x1a, 0x88, 0x4a, 0x1b,
    0xa8, 0x3f, 0xc9, 0x1f, 0x9a, 0xbe, 0x33, 0x27, 0x79,
    0xd6, 0xeb, 0x45, 0xda, 0xc9, 0x5f, 0x59, 0xe8, 0xeb,
    0x79, 0xc7
};

CK_BYTE DH_PUBLIC_B[128] = {
    0xc5, 0xe3, 0xec, 0x7c, 0x29, 0x67, 0x4e, 0x61, 0x54,
    0xd6, 0xbb, 0xba, 0x23, 0xc3, 0xc9, 0x69, 0x05, 0x73,
    0x00, 0x8e, 0xa6, 0x79, 0x5b, 0x58, 0x35, 0x69, 0x70,
    0x0d, 0xd3, 0x42, 0xa2, 0x0c, 0xfa, 0x1e, 0x3d, 0x5a,
    0x5e, 0x21, 0x6c, 0x0e, 0x34, 0xb0, 0xd9, 0x1a, 0xb2,
    0x10, 0xa4, 0x0c, 0xf4, 0xb1, 0xfa, 0x2c, 0x40, 0x09,
    0xbe, 0x92, 0xf9, 0x70, 0xbe, 0x49, 0x79, 0xe0, 0x20,
    0xfc, 0x10, 0xa7, 0xda, 0xaa, 0xb6, 0x0c, 0x3b, 0xd4,
    0x6f, 0x51, 0x42, 0xfd, 0xf6, 0x08, 0x08, 0x4a, 0x0c,
    0xf8, 0xdb, 0xc1, 0x7b, 0x61, 0x36, 0x1c, 0x10, 0xc3,
    0x2c, 0x1a, 0x3b, 0xcb, 0xda, 0xae, 0x45, 0xfd, 0x0a,
    0xd7, 0x50, 0xc3, 0xf1, 0xfc, 0xfa, 0xeb, 0xc2, 0x64,
    0x18, 0xce, 0x4d, 0xd1, 0xd3, 0xfd, 0x1f, 0x31, 0x30,
    0x11, 0xe8, 0xaa, 0x40, 0xa4, 0xb8, 0x1d, 0xba, 0x24,
    0xf2, 0x75
};

/*
 * Generate/Import DH key-pairs for parties A and B.
 * Derive keys based on Diffie Hellman key agreement defined in PKCS#3.
 *
 */
CK_RV do_DeriveDHKey(CK_BBOOL do_import)
{
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE peer_publ_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE peer_priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE peer_secret_key = CK_INVALID_HANDLE;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc = CKR_OK, loc_rc = CKR_OK;

    int i = 0;
    CK_BYTE clear[32];
    CK_BYTE cipher[32];
    CK_BYTE re_cipher[32];
    CK_ULONG cipher_len = 32;
    CK_ULONG re_cipher_len = 32;
    CK_BBOOL ltrue = 1;

    CK_OBJECT_CLASS pub_key_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_DH;
    CK_UTF8CHAR publ_label[] = "A DH public key object";
    CK_OBJECT_CLASS priv_key_class = CKO_PRIVATE_KEY;
    CK_UTF8CHAR priv_label[] = "A DH private key object";

    CK_ULONG secret_key_size = sizeof(DH_PUBL_PRIME);
    CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE secret_key_type = CKK_GENERIC_SECRET;
    CK_UTF8CHAR secret_label[] = "A generic secret key object";

    CK_BYTE key1_value[sizeof(DH_PUBL_PRIME) * 2];
    CK_BYTE key2_value[sizeof(DH_PUBL_PRIME) * 2];

    CK_ATTRIBUTE publ_tmpl[] = {
        {CKA_CLASS, &pub_key_class, sizeof(pub_key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_LABEL, publ_label, sizeof(publ_label) - 1},
        {CKA_PRIME, DH_PUBL_PRIME, sizeof(DH_PUBL_PRIME)},
        {CKA_BASE, DH_PUBL_BASE, sizeof(DH_PUBL_BASE)}
    };

    CK_ATTRIBUTE priv_tmpl[] = {
        {CKA_CLASS, &priv_key_class, sizeof(priv_key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_LABEL, priv_label, sizeof(priv_label) - 1},
        {CKA_DERIVE, &ltrue, sizeof(ltrue)}
    };

    CK_ATTRIBUTE secret_tmpl[] = {
        {CKA_CLASS, &secret_key_class, sizeof(secret_key_class)},
        {CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type)},
        {CKA_VALUE_LEN, &secret_key_size, sizeof(secret_key_size)},
        {CKA_LABEL, secret_label, sizeof(secret_label) - 1}
    };

    CK_ATTRIBUTE extr1_tmpl[] = {
        {CKA_VALUE, key1_value, sizeof(key1_value)}
    };

    CK_ATTRIBUTE extr2_tmpl[] = {
        {CKA_VALUE, key2_value, sizeof(key2_value)}
    };

    if (do_import)
        testcase_begin("starting do_ImportDeriveDHKey...");
    else
        testcase_begin("starting do_GenerateDeriveDHKey...");
    testcase_rw_session();
    testcase_user_login();

    // Testcase #1 - Generate 2 DH key pairs.
    testcase_new_assertion();

    if (!do_import) {
        // First, generate the DH key Pair for Party A
        mech.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        rc = funcs->C_GenerateKeyPair(session, &mech, publ_tmpl, 5,
                                      priv_tmpl, 4, &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("DH key generation is not allowed by policy");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
            testcase_fail("C_GenerateKeyPair #1: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // Now generate a key-pair for party B (the peer)
        mech.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        rc = funcs->C_GenerateKeyPair(session, &mech, publ_tmpl, 5,
                                      priv_tmpl, 4, &peer_publ_key,
                                      &peer_priv_key);
        if (rc != CKR_OK) {
            testcase_fail("C_GenerateKeyPair #2: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // Extract the peer's public key
        rc = funcs->C_GetAttributeValue(session, peer_publ_key, extr1_tmpl, 1);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #1: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        testcase_pass("Successfully generated DH keys");
    } else {
        // First, import the DH key Pair for Party A

        // import the private key for Party A
        rc = create_DHPrivateKey(session,
                                 DH_PUBL_PRIME, sizeof(DH_PUBL_PRIME),
                                 DH_PUBL_BASE, sizeof(DH_PUBL_BASE),
                                 DH_PRIVATE_A, sizeof(DH_PRIVATE_A), &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("DH key import is not allowed by policy");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
            testcase_fail("C_CreateObject (DH Private Key) failed rc=%s",
                          p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // import the public key for Party A
        rc = create_DHPublicKey(session,
                                DH_PUBL_PRIME, sizeof(DH_PUBL_PRIME),
                                DH_PUBL_BASE, sizeof(DH_PUBL_BASE),
                                DH_PUBLIC_A, sizeof(DH_PUBLIC_A), &publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("DH key import is not allowed by policy");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
            testcase_fail("C_CreateObject (DH Public Key) failed rc=%s",
                          p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // import the private key for Party B
        rc = create_DHPrivateKey(session,
                                 DH_PUBL_PRIME, sizeof(DH_PUBL_PRIME),
                                 DH_PUBL_BASE, sizeof(DH_PUBL_BASE),
                                 DH_PRIVATE_B, sizeof(DH_PRIVATE_B),
                                 &peer_priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("DH key import is not allowed by policy");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
            testcase_fail("C_CreateObject (DH Private Key) failed rc=%s",
                          p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // import the public key for Party B
        rc = create_DHPublicKey(session,
                                DH_PUBL_PRIME, sizeof(DH_PUBL_PRIME),
                                DH_PUBL_BASE, sizeof(DH_PUBL_BASE),
                                DH_PUBLIC_B, sizeof(DH_PUBLIC_B),
                                &peer_publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("DH key import is not allowed by policy");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
            testcase_fail("C_CreateObject (DH Public Key) failed rc=%s",
                          p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // Extract the peer's public key
        rc = funcs->C_GetAttributeValue(session, peer_publ_key, extr1_tmpl, 1);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #1: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        testcase_pass("Successfully imported DH keys");
    }

    // Testcase #2 - Now derive the secrets...
    if (!securekey) {
        // Note: this is a clear key token testcase since comparing
        //       key values.
        testcase_new_assertion();

        /* Now, derive a generic secret key using party A's
         * private key and peer's public key
         */
        mech.mechanism = CKM_DH_PKCS_DERIVE;
        mech.ulParameterLen = extr1_tmpl[0].ulValueLen;
        mech.pParameter = key1_value;

        rc = funcs->C_DeriveKey(session, &mech, priv_key, secret_tmpl,
                                4, &secret_key);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey #1: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // Do the same for the peer

        // Extract party A's public key
        rc = funcs->C_GetAttributeValue(session, publ_key, extr2_tmpl, 1);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #2: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // Now, derive a generic secret key using peer's private key
        // and A's public key
        mech.mechanism = CKM_DH_PKCS_DERIVE;
        mech.ulParameterLen = extr2_tmpl[0].ulValueLen;
        mech.pParameter = key2_value;

        rc = funcs->C_DeriveKey(session, &mech, peer_priv_key,
                                secret_tmpl, 4, &peer_secret_key);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey #2: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // Extract the derived keys and compare them

        memset(key1_value, 0, sizeof(key1_value));
        extr1_tmpl[0].ulValueLen = sizeof(key1_value);

        rc = funcs->C_GetAttributeValue(session, secret_key, extr1_tmpl, 1);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #3:rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        memset(key2_value, 0, sizeof(key2_value));
        extr2_tmpl[0].ulValueLen = sizeof(key2_value);

        rc = funcs->C_GetAttributeValue(session, peer_secret_key,
                                        extr2_tmpl, 1);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #4:rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        if (extr1_tmpl[0].ulValueLen != extr2_tmpl[0].ulValueLen ||
            memcmp(key1_value, key2_value, extr1_tmpl[0].ulValueLen) != 0) {
            testcase_fail("ERROR:derived key mismatch");
            goto testcase_cleanup;
        }

        testcase_pass("Generating DH key pairs and deriving secrets");

        goto testcase_cleanup;

    } else {

        // Testcase for secure key token - encode/decode with secrect key and
        // peer secret key
        testcase_new_assertion();

        secret_key_size = 32;
        secret_key_type = CKK_AES;
        for (i = 0; i < 32; i++)
            clear[i] = i;

        /* Now, derive a generic secret key using party A's
         * private key and peer's public key
         */
        mech.mechanism = CKM_DH_PKCS_DERIVE;
        mech.ulParameterLen = extr1_tmpl[0].ulValueLen;
        mech.pParameter = key1_value;

        rc = funcs->C_DeriveKey(session, &mech, priv_key, secret_tmpl,
                                4, &secret_key);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey #1: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // Do the same for the peer

        // Extract party A's public key
        rc = funcs->C_GetAttributeValue(session, publ_key, extr2_tmpl, 1);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue #2: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // Now, derive a generic secret key using peer's private key
        // and A's public key
        mech.mechanism = CKM_DH_PKCS_DERIVE;
        mech.ulParameterLen = extr2_tmpl[0].ulValueLen;
        mech.pParameter = key2_value;

        rc = funcs->C_DeriveKey(session, &mech, peer_priv_key,
                                secret_tmpl, 4, &peer_secret_key);
        if (rc != CKR_OK) {
            testcase_fail("C_DeriveKey #2: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // Extract the derived keys and compare them

        mech.mechanism = CKM_AES_ECB;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        rc = funcs->C_EncryptInit(session, &mech, secret_key);
        if (rc != CKR_OK) {
            testcase_error("C_EncryptInit secret_key: rc = %s",
                           p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = funcs->C_Encrypt(session, clear, 32, cipher, &cipher_len);
        if (rc != CKR_OK) {
            testcase_error("C_Encrypt secret_key: rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = funcs->C_DecryptInit(session, &mech, peer_secret_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit peer_secret_key: rc = %s",
                           p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = funcs->C_Decrypt(session, cipher, cipher_len, re_cipher,
                              &re_cipher_len);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt peer secret_key: rc = %s",
                           p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        if (memcmp(clear, re_cipher, 32) != 0) {
            testcase_fail("ERROR:data mismatch");
            goto testcase_cleanup;
        }

        testcase_pass("Generating DH key pairs and deriving secrets");
    }

testcase_cleanup:
    funcs->C_DestroyObject(session, publ_key);
    funcs->C_DestroyObject(session, priv_key);
    funcs->C_DestroyObject(session, peer_priv_key);
    funcs->C_DestroyObject(session, peer_publ_key);
    funcs->C_DestroyObject(session, secret_key);
    funcs->C_DestroyObject(session, peer_secret_key);

    loc_rc = funcs->C_CloseSession(session);
    if (loc_rc != CKR_OK)
        testcase_error("C_CloseSession, loc_rc = %s", p11_get_ckr(loc_rc));

    return rc;
}                               /* end do_DeriveDHKey() */

CK_RV do_EnDecapsulateDHKey(void)
{
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret_key1 = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secret_key2 = CK_INVALID_HANDLE;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc = CKR_OK, loc_rc = CKR_OK;

    CK_ULONG i;
    CK_BYTE clear[32];
    CK_BYTE encrypted1[32];
    CK_BYTE encrypted2[32];
    CK_ULONG encrypted1_len = sizeof(encrypted1);
    CK_ULONG encrypted2_len = sizeof(encrypted2);
    CK_BBOOL ck_true = CK_TRUE;
    CK_BBOOL ck_false = CK_TRUE;
    CK_BYTE *cipher = NULL;
    CK_ULONG cipher_len = 0;

    CK_OBJECT_CLASS pub_key_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_DH;
    CK_UTF8CHAR publ_label[] = "A DH public key object";
    CK_OBJECT_CLASS priv_key_class = CKO_PRIVATE_KEY;
    CK_UTF8CHAR priv_label[] = "A DH private key object";

    CK_ULONG secret_key_size = 32;
    CK_OBJECT_CLASS secret_key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE secret_key_type = CKK_AES;
    CK_UTF8CHAR secret_label[] = "An AES secret key object";

    CK_ATTRIBUTE publ_tmpl[] = {
        {CKA_CLASS, &pub_key_class, sizeof(pub_key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_LABEL, publ_label, sizeof(publ_label) - 1},
        {CKA_PRIME, DH_PUBL_PRIME, sizeof(DH_PUBL_PRIME)},
        {CKA_BASE, DH_PUBL_BASE, sizeof(DH_PUBL_BASE)},
        {CKA_ENCAPSULATE, &ck_true, sizeof(ck_true)}
    };

    CK_ATTRIBUTE priv_tmpl[] = {
        {CKA_CLASS, &priv_key_class, sizeof(priv_key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_LABEL, priv_label, sizeof(priv_label) - 1},
        {CKA_DERIVE, &ck_false, sizeof(ck_false)},
        {CKA_DECAPSULATE, &ck_true, sizeof(ck_true)}
    };

    CK_ATTRIBUTE secret_tmpl[] = {
        {CKA_CLASS, &secret_key_class, sizeof(secret_key_class)},
        {CKA_KEY_TYPE, &secret_key_type, sizeof(secret_key_type)},
        {CKA_VALUE_LEN, &secret_key_size, sizeof(secret_key_size)},
        {CKA_LABEL, secret_label, sizeof(secret_label) - 1},
        {CKA_EXTRACTABLE, &ck_false, sizeof(ck_false)}
    };


    testcase_begin("starting do_GenerateDeriveDHKey...");
    testcase_rw_session();
    testcase_user_login();

    testcase_new_assertion();

    /* First, generate the DH key Pair for Party A */
    mech.mechanism = CKM_DH_PKCS_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rc = funcs->C_GenerateKeyPair(session, &mech, publ_tmpl, 6,
                                  priv_tmpl, 5, &publ_key, &priv_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session)) {
            testcase_skip("DH key generation is not allowed by policy");
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        testcase_fail("C_GenerateKeyPair #1: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully generated an DH key");

    /* Testcase #2 - Now encapsulate/decapsulate the secrets... */
    testcase_new_assertion();

    /* Now, encapsulate an AES key using party A's public key */
    mech.mechanism = CKM_DH_PKCS_DERIVE;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rc = funcs3_2->C_EncapsulateKey(session, &mech, publ_key,
                                    secret_tmpl, 5,
                                    NULL, &cipher_len, NULL);
    if (rc != CKR_OK) {
        testcase_fail("C_EncapsulateKey #1: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    cipher = calloc(cipher_len, sizeof(CK_BYTE));
    if (cipher == NULL) {
        testcase_error("Can't allocate memory for %lu bytes.", cipher_len);
        rc = CKR_HOST_MEMORY;
        goto testcase_cleanup;
    }

    rc = funcs3_2->C_EncapsulateKey(session, &mech, publ_key,
                                    secret_tmpl, 5,
                                    cipher, &cipher_len, &secret_key1);
    if (rc != CKR_OK) {
        testcase_fail("C_EncapsulateKey #2: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Now, decapsulate an AES key using A's private key */
    rc = funcs3_2->C_DecapsulateKey(session, &mech, priv_key,
                                    secret_tmpl, 5,
                                    cipher, cipher_len, &secret_key2);
    if (rc != CKR_OK) {
        testcase_fail("C_DecapsulateKey #1: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* CHeck if the same keys were en/decapsulated */

    for (i = 0; i < sizeof(clear); i++)
        clear[i] = i;

    mech.mechanism = CKM_AES_ECB;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rc = funcs->C_EncryptInit(session, &mech, secret_key1);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptInit secret_key1: rc = %s",
                       p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_Encrypt(session, clear, sizeof(clear),
                          encrypted1, &encrypted1_len);
    if (rc != CKR_OK) {
        testcase_error("C_Encrypt secret_key1: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_EncryptInit(session, &mech, secret_key2);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptInit secret_key2: rc = %s",
                       p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_Encrypt(session, clear, sizeof(clear),
                          encrypted2, &encrypted2_len);
    if (rc != CKR_OK) {
        testcase_error("C_Encrypt secret_key2: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted1_len != encrypted2_len ||
        memcmp(encrypted1, encrypted2, encrypted1_len) != 0) {
        testcase_fail("ERROR: data mismatch");
        goto testcase_cleanup;
    }

    testcase_pass("En/Decapsulate secrets");

testcase_cleanup:
    funcs->C_DestroyObject(session, publ_key);
    funcs->C_DestroyObject(session, priv_key);
    funcs->C_DestroyObject(session, secret_key1);
    funcs->C_DestroyObject(session, secret_key2);

    loc_rc = funcs->C_CloseSession(session);
    if (loc_rc != CKR_OK)
        testcase_error("C_CloseSession, loc_rc = %s", p11_get_ckr(loc_rc));

    return rc;
}

CK_RV dh_functions(void)
{
    CK_RV rv, rv2;
    CK_MECHANISM_INFO mechinfo;

    /** get mech info **/
    rv = funcs->C_GetMechanismInfo(SLOT_ID, CKM_DH_PKCS_KEY_PAIR_GEN,
                                   &mechinfo);
    rv2 = funcs->C_GetMechanismInfo(SLOT_ID, CKM_DH_PKCS_DERIVE, &mechinfo);

    if (rv == CKR_OK && rv2 == CKR_OK) {
        rv = do_DeriveDHKey(FALSE);

        if (rv == CKR_OK)
            rv = do_DeriveDHKey(TRUE);

        if (rv == CKR_OK &&
            (mechinfo.flags & CKF_ENCAPSULATE) != 0 &&
            (mechinfo.flags & CKF_DECAPSULATE) != 0)
            rv = do_EnDecapsulateDHKey();
    } else {
        /*
         ** One of the above mechanism is not available, so skip
         ** the test but do not report any
         ** rv = CKR_MECHANISM_INVALID;
         ** invalid or however failures as this is not a failure.
         **/
        return CKR_OK;
    }

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

    /*
     * -securekey option is needed on CCA and EP11 token,
     *  otherwise the testcase will fail. However, now this
     *  will be done automatically here.
     */
    if (is_ep11_token(SLOT_ID) || is_cca_token(SLOT_ID))
        securekey = 1;

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

    rv = dh_functions();

    testcase_print_result();

    funcs->C_Finalize(NULL);

    return testcase_return(rv);
}
