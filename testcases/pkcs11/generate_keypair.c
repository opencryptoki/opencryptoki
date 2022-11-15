/*
 * COPYRIGHT (c) International Business Machines Corp. 2015-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"

/* API Routines exercised:
 * C_GenerateKeyPair
 */
CK_RV do_GenerateKeyPairRSA(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_RV rc = 0;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    CK_OBJECT_HANDLE priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE;
    CK_MECHANISM mech;

    CK_KEY_TYPE keytype = CKK_RSA;
    CK_ULONG modbits = 2048;
    unsigned int modbytes = modbits / 8;
    CK_BYTE pubExp[3] = { 0x01, 0x00, 0x01 };
    CK_ATTRIBUTE publ_tmpl[] = {
        {CKA_KEY_TYPE, &keytype, sizeof(keytype)},
        {CKA_MODULUS_BITS, &modbits, sizeof(modbits)},
        {CKA_PUBLIC_EXPONENT, pubExp, sizeof(pubExp)}
    };

    CK_OBJECT_CLASS class;
    CK_BYTE publicExponent[4];
    CK_BYTE modulus[512];
    CK_BYTE subject[20], id[20];;
    CK_BYTE start_date[20], end_date[20];
    CK_BBOOL encrypt, decrypt, sign, sign_recover, verify, verify_recover;
    CK_BBOOL wrap, unwrap, derive, local, extractable, never;
    CK_BBOOL sensitive, always;

    CK_ATTRIBUTE publ_def[] = {
        {CKA_KEY_TYPE, &keytype, sizeof(keytype)},
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
        {CKA_MODULUS, modulus, sizeof(modulus)},
        {CKA_SUBJECT, subject, sizeof(subject)},
        {CKA_ENCRYPT, &encrypt, sizeof(encrypt)},
        {CKA_VERIFY, &verify, sizeof(verify)},
        {CKA_VERIFY_RECOVER, &verify_recover, sizeof(verify_recover)},
        {CKA_WRAP, &wrap, sizeof(wrap)},
        {CKA_ID, &id, sizeof(id)},
        {CKA_START_DATE, &start_date, sizeof(start_date)},
        {CKA_END_DATE, &end_date, sizeof(end_date)},
        {CKA_DERIVE, &derive, sizeof(derive)},
        {CKA_LOCAL, &local, sizeof(local)}
    };

    /* According to pkcs#11v2.20, Section 12.1.4, the implementation
     * MAY contribute some of the CRT attributes. So, dont look for these.
     * Only check for the common defaults for the private key.
     */
    CK_ATTRIBUTE priv_def[] = {
        {CKA_KEY_TYPE, &keytype, sizeof(keytype)},
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_SUBJECT, subject, sizeof(subject)},
        {CKA_SENSITIVE, &sensitive, sizeof(sensitive)},
        {CKA_DECRYPT, &decrypt, sizeof(decrypt)},
        {CKA_SIGN, &sign, sizeof(sign)},
        {CKA_SIGN_RECOVER, &sign_recover, sizeof(sign_recover)},
        {CKA_UNWRAP, &unwrap, sizeof(unwrap)},
        {CKA_EXTRACTABLE, &extractable, sizeof(extractable)},
        {CKA_ALWAYS_SENSITIVE, &always, sizeof(always)},
        {CKA_NEVER_EXTRACTABLE, &never, sizeof(never)},
        {CKA_ID, &id, sizeof(id)},
        {CKA_START_DATE, start_date, sizeof(start_date)},
        {CKA_END_DATE, end_date, sizeof(end_date)},
        {CKA_DERIVE, &derive, sizeof(derive)},
        {CKA_LOCAL, &local, sizeof(local)}
    };

    /* Do some setup and login to the token */
    testcase_begin("starting...");
    testcase_rw_session();
    testcase_user_login();

    mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    if (!mech_supported(SLOT_ID, CKM_RSA_PKCS_KEY_PAIR_GEN)) {
        testcase_skip("Mechanism CKM_RSA_PKCS_KEY_PAIR_GEN is not supported with slot "
                      "%lu. Skipping key check", SLOT_ID);
        goto testcase_cleanup;
    }

    /* Assertion #1: generate an RSA key pair. */
    testcase_new_assertion();

    rc = funcs->C_GenerateKeyPair(session, &mech, publ_tmpl, 3, NULL,
                                  0, &publ_key, &priv_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session)) {
            testcase_skip("Key generation is not allowed by policy");
            goto testcase_cleanup;
        }
        testcase_fail("C_GenerateKeyPair() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("C_GenerateKeypair was successful\n");

    /* Assertion #2: Ensure public key contains the default attributes
     * and those the implementation should have contributed for RSA PKCS#1
     * key pairs. (Section 12.1.4 of pkcs#11v2.20)
     */
    testcase_new_assertion();

    rc = funcs->C_GetAttributeValue(session, publ_key, publ_def, 14);
    if (rc == CKR_ATTRIBUTE_TYPE_INVALID) {
        testcase_fail("Some of the default attributes were missing.\n");
        goto testcase_cleanup;
    }
    if (rc != CKR_OK) {
        testcase_error("C_GetAttributeValue: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (*(CK_ULONG *) publ_def[0].pValue != CKK_RSA) {
        testcase_fail("Public RSA key was not generated correctly"
                      " (wrong CKA_KEY_TYPE).\n");
    }
    if (*(CK_ULONG *) publ_def[1].pValue != CKO_PUBLIC_KEY) {
        testcase_fail("Public RSA key was not generated correctly"
                      " (wrong CKA_CLASS).\n");
    }
    if (publ_def[2].ulValueLen != sizeof(pubExp)) {
        /* some tokens add an leading 0x00 to the exponent value */
        unsigned char *pv = (unsigned char *) publ_def[2].pValue;
        if (publ_def[2].ulValueLen == sizeof(pubExp) + 1
            && pv[0] == 0x00 && memcmp(pv + 1, pubExp, sizeof(pubExp)) == 0) {
            /* len is just +1, first byte is 0, rest matches to pubExp */
        } else {
            testcase_fail("Public RSA key was not generated correctly"
                          " (pub exp mismatch).\n");
        }
    } else {
        /* same length, check value */
        if (memcmp(publ_def[2].pValue, pubExp, sizeof(pubExp)) != 0) {
            testcase_fail("Public RSA key was not generated correctly"
                          " (pub exp mismatch).\n");
        }
    }
    if (publ_def[3].ulValueLen != modbytes) {
        /* some tokens add an leading 0x00 to the modulus value */
        unsigned char *pv = (unsigned char *) publ_def[3].pValue;
        if (publ_def[3].ulValueLen == modbytes + 1 && pv[0] == 0x00) {
            /* len is just +1, first byte is 0, all fine */
        } else {
            testcase_fail("Public RSA key was not generated correctly"
                          " (modulus length mismatch).\n");
        }
    }
    testcase_pass("Public RSA key generated correctly.\n");

    testcase_new_assertion();

    rc = funcs->C_GetAttributeValue(session, priv_key, priv_def, 16);
    if (rc != CKR_OK) {
        testcase_error("C_GetAttributeValue: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }
    if (rc == CKR_ATTRIBUTE_TYPE_INVALID) {
        testcase_fail("Some of the default attributes were missing.\n");
        goto testcase_cleanup;
    }
    if (rc != CKR_OK) {
        testcase_error("C_GetAttributeValue: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Assertion #3: Ensure private key contains the default attributes
     * and those the implementation should have contributed for RSA PKCS#1
     * key pairs. (Section 12.1.4 of pkcs#11v2.20)
     */
    if (*(CK_ULONG *) priv_def[0].pValue != CKK_RSA) {
        testcase_fail("Private RSA key was not generated correctly"
                      " (wrong CKA_KEY_TYPE).\n");
    }
    if (*(CK_ULONG *) priv_def[1].pValue != CKO_PRIVATE_KEY) {
        testcase_fail("Private RSA key was not generated correctly"
                      " (wrong CKA_CLASS).\n");
    }
    testcase_pass("Private RSA key generated correctly.\n");

testcase_cleanup:
    funcs->C_DestroyObject(session, priv_key);
    funcs->C_DestroyObject(session, publ_key);

    testcase_user_logout();
    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK) {
        testcase_error("C_CloseSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

int main(int argc, char **argv)
{
    int rc;
    CK_C_INITIALIZE_ARGS cinit_args;
    CK_RV rv = 0;

    rc = do_ParseArgs(argc, argv);
    if (rc != 1)
        return rc;

    printf("Using slot #%lu...\n\n", SLOT_ID);
    printf("With option: nostop: %d\n", no_stop);

    rc = do_GetFunctionList();
    if (!rc) {
        testcase_error("do_getFunctionList(), rc=%s", p11_get_ckr(rc));
        return rc;
    }

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    funcs->C_Initialize(&cinit_args);

    {
        CK_SESSION_HANDLE hsess = 0;

        rv = funcs->C_GetFunctionStatus(hsess);
        if (rv != CKR_FUNCTION_NOT_PARALLEL)
            return rv;

        rv = funcs->C_CancelFunction(hsess);
        if (rv != CKR_FUNCTION_NOT_PARALLEL)
            return rv;
    }

    testcase_setup();
    rc = do_GenerateKeyPairRSA();
    testcase_print_result();

    return testcase_return(rc);
}
