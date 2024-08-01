/*
 * COPYRIGHT (c) International Business Machines Corp. 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File: always_auth.c
 *
 * Test driver.  In-depth regression test for PKCS #11
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"
#include "mechtable.h"
#include "mech_to_str.h"


CK_MECHANISM rsakeygen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
CK_MECHANISM signver_mech = { CKM_SHA256_RSA_PKCS, NULL, 0 };
CK_MECHANISM endecrypt_mech = { CKM_RSA_PKCS, NULL, 0 };

CK_RV do_auth_sign(void)
{
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc = CKR_OK, loc_rc;
    CK_FLAGS flags;
    CK_OBJECT_HANDLE rsa_pub_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsa_priv_key = CK_INVALID_HANDLE;
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_BBOOL true = TRUE;
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
    CK_BYTE data[20] = { 0x00 };
    CK_BYTE signature[256] = { 0x00 };
    CK_ULONG signature_len  = sizeof(signature);

    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_WRAP, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}
    };
    CK_ULONG publicKeyTemplate_len =
                    sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_SUBJECT, subject, 0},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_UNWRAP, &true, sizeof(true)},
        {CKA_ALWAYS_AUTHENTICATE, &true, sizeof(true)},
    };
    CK_ULONG privateKeyTemplate_len =
                    sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE);

    testcase_begin("C_Sign with %s and CKA_ALWAYS_AUTHENTICATE=TRUE",
                   mech_to_str(signver_mech.mechanism));

    testcase_rw_session();
    testcase_user_login();

    if (!mech_supported(SLOT_ID, signver_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(signver_mech.mechanism),
                      (unsigned int)signver_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, rsakeygen_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(rsakeygen_mech.mechanism),
                      (unsigned int)rsakeygen_mech.mechanism);
        goto testcase_cleanup;
    }

    testcase_new_assertion();

    /* generate an RSA key */
    rc = funcs->C_GenerateKeyPair(session,
                                  &rsakeygen_mech,
                                  publicKeyTemplate, publicKeyTemplate_len,
                                  privateKeyTemplate, privateKeyTemplate_len,
                                  &rsa_pub_key, &rsa_priv_key);
    if (is_rejected_by_policy(rc, session)) {
        testcase_skip("generate key with mech %s (%u) in slot %lu "
                      "is not allowed by policy",
                      mech_to_str(rsakeygen_mech.mechanism),
                      (unsigned int)rsakeygen_mech.mechanism,
                      SLOT_ID);
        rc = CKR_OK;
        goto testcase_cleanup;
    }
    if (rc != CKR_OK) {
        testcase_error("generate key with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(rsakeygen_mech.mechanism),
                       (unsigned int)rsakeygen_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Initialize operation */
    rc = funcs->C_SignInit(session, &signver_mech, rsa_priv_key);
    if (rc != CKR_OK) {
        testcase_error("C_SignInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(signver_mech.mechanism),
                       (unsigned int)signver_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Perform C_Sign without doing a C_Login first, expected to fail */
    rc = funcs->C_Sign(session, data, sizeof(data), signature, &signature_len);
    if (rc != CKR_USER_NOT_LOGGED_IN) {
        testcase_fail("C_Sign without C_Login returned rc=%s, expected %s",
                      p11_get_ckr(rc), p11_get_ckr(CKR_USER_NOT_LOGGED_IN));
        goto testcase_cleanup;
    }

    /* Initialize the operation again, CKR_USER_NOT_LOGGED_IN terminated it */
    rc = funcs->C_SignInit(session, &signver_mech, rsa_priv_key);
    if (rc != CKR_OK) {
        testcase_error("C_SignInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(signver_mech.mechanism),
                       (unsigned int)signver_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Perform C_Login with CKU_CONTEXT_SPECIFIC and USER pin */
    rc = funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        testcase_error("C_Login with type CKU_CONTEXT_SPECIFIC failed, rc=%s",
                       p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Perform C_Sign after doing a C_Login */
    rc = funcs->C_Sign(session, data, sizeof(data), signature, &signature_len);
    if (rc != CKR_OK) {
        testcase_error("C_Sign after C_Login failed, rc=%s",
                       p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Perform C_Login after operation is complete, expected to fail */
    rc = funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, user_pin, user_pin_len);
    if (rc != CKR_OPERATION_NOT_INITIALIZED) {
        testcase_fail("C_Login after op is complete returned rc=%s, expected %s",
                      p11_get_ckr(rc),
                      p11_get_ckr(CKR_OPERATION_NOT_INITIALIZED));
        goto testcase_cleanup;
    }

    testcase_pass("C_Sign with %s and CKA_ALWAYS_AUTHENTICATE=TRUE",
                  mech_to_str(signver_mech.mechanism));

testcase_cleanup:
    if (rsa_pub_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, rsa_pub_key);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    if (rsa_priv_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, rsa_priv_key);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(SLOT_ID);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

CK_RV do_auth_decrypt(void)
{
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc = CKR_OK, loc_rc;
    CK_FLAGS flags;
    CK_OBJECT_HANDLE rsa_pub_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE rsa_priv_key = CK_INVALID_HANDLE;
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_BBOOL true = TRUE;
    CK_ULONG modulusBits = 2048;
    CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
    CK_BYTE data[20] = { 0x00 };
    CK_BYTE cipher[256] = { 0x00 };
    CK_ULONG cipher_len = sizeof(cipher);
    CK_BYTE clear[256] = { 0x00 };
    CK_ULONG clear_len = sizeof(clear);

    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_VERIFY, &true, sizeof(true)},
        {CKA_WRAP, &true, sizeof(true)},
        {CKA_MODULUS_BITS, &modulusBits, sizeof(modulusBits)},
        {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)}
    };
    CK_ULONG publicKeyTemplate_len =
                    sizeof(publicKeyTemplate) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_SUBJECT, subject, 0},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
        {CKA_UNWRAP, &true, sizeof(true)},
        {CKA_ALWAYS_AUTHENTICATE, &true, sizeof(true)},
    };
    CK_ULONG privateKeyTemplate_len =
                    sizeof(privateKeyTemplate) / sizeof(CK_ATTRIBUTE);

    testcase_begin("C_Decrypt with %s and CKA_ALWAYS_AUTHENTICATE=TRUE",
                   mech_to_str(endecrypt_mech.mechanism));

    testcase_rw_session();
    testcase_user_login();

    if (!mech_supported(SLOT_ID, endecrypt_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(endecrypt_mech.mechanism),
                      (unsigned int)endecrypt_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, rsakeygen_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(rsakeygen_mech.mechanism),
                      (unsigned int)rsakeygen_mech.mechanism);
        goto testcase_cleanup;
    }

    testcase_new_assertion();

    /* generate an RSA key */
    rc = funcs->C_GenerateKeyPair(session,
                                  &rsakeygen_mech,
                                  publicKeyTemplate, publicKeyTemplate_len,
                                  privateKeyTemplate, privateKeyTemplate_len,
                                  &rsa_pub_key, &rsa_priv_key);
    if (is_rejected_by_policy(rc, session)) {
        testcase_skip("generate key with mech %s (%u) in slot %lu "
                      "is not allowed by policy",
                      mech_to_str(rsakeygen_mech.mechanism),
                      (unsigned int)rsakeygen_mech.mechanism,
                      SLOT_ID);
        rc = CKR_OK;
        goto testcase_cleanup;
    }
    if (rc != CKR_OK) {
        testcase_error("generate key with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(rsakeygen_mech.mechanism),
                       (unsigned int)rsakeygen_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Encrypt some data */
    rc = funcs->C_EncryptInit(session, &endecrypt_mech, rsa_pub_key);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(endecrypt_mech.mechanism),
                       (unsigned int)endecrypt_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_Encrypt(session, data, sizeof(data), cipher, &cipher_len);
    if (rc != CKR_OK) {
        testcase_fail("C_Encrypt failedrc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Initialize operation */
    rc = funcs->C_DecryptInit(session, &endecrypt_mech, rsa_priv_key);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(endecrypt_mech.mechanism),
                       (unsigned int)endecrypt_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Perform C_Decrypt without doing a C_Login first, expected to fail */
    rc = funcs->C_Decrypt(session, cipher, cipher_len, clear, &clear_len);
    if (rc != CKR_USER_NOT_LOGGED_IN) {
        testcase_fail("C_Decrypt without C_Login returned rc=%s, expected %s",
                      p11_get_ckr(rc), p11_get_ckr(CKR_USER_NOT_LOGGED_IN));
        goto testcase_cleanup;
    }

    /* Initialize the operation again, CKR_USER_NOT_LOGGED_IN terminated it */
    rc = funcs->C_DecryptInit(session, &endecrypt_mech, rsa_priv_key);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(endecrypt_mech.mechanism),
                       (unsigned int)endecrypt_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Perform C_Login with CKU_CONTEXT_SPECIFIC and USER pin */
    rc = funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        testcase_error("C_Login with type CKU_CONTEXT_SPECIFIC failed, rc=%s",
                       p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Perform C_Decrypt after doing a C_Login */
    rc = funcs->C_Decrypt(session, cipher, cipher_len, clear, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_Decrypt after C_Login failed, rc=%s",
                       p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Perform C_Login after operation is complete, expected to fail */
    rc = funcs->C_Login(session, CKU_CONTEXT_SPECIFIC, user_pin, user_pin_len);
    if (rc != CKR_OPERATION_NOT_INITIALIZED) {
        testcase_fail("C_Login after op is complete returned rc=%s, expected %s",
                      p11_get_ckr(rc),
                      p11_get_ckr(CKR_OPERATION_NOT_INITIALIZED));
        goto testcase_cleanup;
    }

    testcase_pass("C_Decrypt with %s and CKA_ALWAYS_AUTHENTICATE=TRUE",
                  mech_to_str(endecrypt_mech.mechanism));

testcase_cleanup:
    if (rsa_pub_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, rsa_pub_key);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    if (rsa_priv_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, rsa_priv_key);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(SLOT_ID);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

CK_RV do_always_auth_tests(void)
{
    CK_RV rc = CKR_OK;

    if (is_icsf_token(SLOT_ID)) {
        testcase_skip("ICSF token does not support CKA_ALWAYS_AUTHENTICATE");
        return rc;
    }

    rc |= do_auth_sign();

    rc |= do_auth_decrypt();

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

    rc = do_GetFunctionList();
    if (!rc) {
        testcase_error("do_getFunctionList(), rc=%s", p11_get_ckr(rc));
        return rc;
    }

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;
    funcs->C_Initialize(&cinit_args);

    testcase_setup();

    rv = do_always_auth_tests();
    if (rv != CKR_OK)
        goto finalize;

    rv = funcs->C_Finalize(NULL);
    if (rv != CKR_OK) {
        testcase_fail("C_Finalize rc = %s", p11_get_ckr(rv));
        goto out;
    }

    rv = 0;
    goto out;

finalize:
    rv = funcs->C_Finalize(NULL);
    if (rv != CKR_OK) {
        testcase_fail("C_Finalize rc = %s", p11_get_ckr(rv));
        rv = 1;
    }
out:
    testcase_print_result();
    return testcase_return(rv);
}
