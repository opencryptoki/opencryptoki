/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File: dual_functions.c
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

CK_BYTE aes_iv[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };

CK_MECHANISM aeskeygen_mech = { CKM_AES_KEY_GEN, NULL, 0 };
CK_MECHANISM endecrypt_mech = { CKM_AES_CBC, aes_iv, sizeof(aes_iv) };
CK_MECHANISM signver_mech = { CKM_SHA256_HMAC, NULL, 0 };
CK_MECHANISM mackeygen_mech = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };
CK_MECHANISM digest_mech = { CKM_SHA256, NULL, 0 };

CK_BYTE data1[512];
CK_BYTE data2[512];


CK_RV do_digest_encrypt_decrypt_digest()
{
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc = CKR_OK, loc_rc;
    CK_FLAGS flags;
    CK_OBJECT_HANDLE aes_key = CK_INVALID_HANDLE;
    CK_BYTE encrypted1[sizeof(data1) + 16];
    CK_ULONG encrypted1_len;
    CK_BYTE encrypted2[sizeof(data2) + 16];
    CK_ULONG encrypted2_len;
    CK_BYTE encrypted3[16];
    CK_ULONG encrypted3_len;
    CK_BYTE clear[sizeof(data1) + 16];
    CK_ULONG clear_len;
    CK_BYTE digest1[32];
    CK_ULONG digest1_len;
    CK_BYTE digest2[32];
    CK_ULONG digest2_len;

    testcase_begin("C_DigestEncryptUpdate with %s/%s",
                   mech_to_str(digest_mech.mechanism),
                   mech_to_str(endecrypt_mech.mechanism));

    testcase_rw_session();
    testcase_user_login();

    if (!mech_supported(SLOT_ID, digest_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(digest_mech.mechanism),
                      (unsigned int)digest_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, endecrypt_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(endecrypt_mech.mechanism),
                      (unsigned int)endecrypt_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, aeskeygen_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(aeskeygen_mech.mechanism),
                      (unsigned int)aeskeygen_mech.mechanism);
        goto testcase_cleanup;
    }

    /* generate an AES key */
    rc = generate_AESKey(session, 256 / 8, CK_TRUE, &aeskeygen_mech, &aes_key);
    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("generate key with mech %s (%u) in slot %lu "
                          "is not allowed by policy",
                          mech_to_str(aeskeygen_mech.mechanism),
                          (unsigned int)aeskeygen_mech.mechanism,
                          SLOT_ID);
            rc = CKR_OK;
            goto testcase_cleanup;
        }

        testcase_error("generate key with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(aeskeygen_mech.mechanism),
                       (unsigned int)aeskeygen_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_new_assertion();

    /* Initialize operations */
    rc = funcs->C_EncryptInit(session, &endecrypt_mech, aes_key);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(endecrypt_mech.mechanism),
                       (unsigned int)endecrypt_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_DigestInit(session, &digest_mech);
    if (rc != CKR_OK) {
        testcase_error("C_DigestInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(digest_mech.mechanism),
                       (unsigned int)digest_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* First chunk */
    encrypted1_len = 0;
    rc = funcs->C_DigestEncryptUpdate(session, data1, sizeof(data1),
                                      NULL, &encrypted1_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestEncryptUpdate (1) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted1_len < sizeof(data1)) {
        testcase_error("Wrong encrypted length from C_DigestEncryptUpdate (1): %lu",
                       encrypted1_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    encrypted1_len = sizeof(encrypted1);
    rc = funcs->C_DigestEncryptUpdate(session, data1, sizeof(data1),
                                      encrypted1, &encrypted1_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestEncryptUpdate (2) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted1_len != sizeof(data1)) {
        testcase_error("Wrong encrypted length from C_DigestEncryptUpdate (2): %lu",
                       encrypted1_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    /* Second chunk */
    encrypted2_len = 0;
    rc = funcs->C_DigestEncryptUpdate(session, data2, sizeof(data2),
                                      NULL, &encrypted2_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestEncryptUpdate (3) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted2_len < sizeof(data2)) {
        testcase_error("Wrong encrypted length from C_DigestEncryptUpdate (3): %lu",
                       encrypted2_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    encrypted2_len = sizeof(encrypted2);
    rc = funcs->C_DigestEncryptUpdate(session, data2, sizeof(data2),
                                      encrypted2, &encrypted2_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestEncryptUpdate (4) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted2_len != sizeof(data2)) {
        testcase_error("Wrong encrypted length from C_DigestEncryptUpdate (4): %lu",
                       encrypted2_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    /* Finalize operations */
    encrypted3_len = sizeof(encrypted3);
    rc = funcs->C_EncryptFinal(session, encrypted3, &encrypted3_len);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted3_len != 0) {
        testcase_error("Wrong encrypted length from C_EncryptFinal: %lu",
                       encrypted3_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    digest1_len = sizeof(digest1);
    rc = funcs->C_DigestFinal(session, digest1, &digest1_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("C_DigestEncryptUpdate with %s/%s",
                  mech_to_str(digest_mech.mechanism),
                  mech_to_str(endecrypt_mech.mechanism));

    testcase_begin("C_DecryptDigestUpdate with %s/%s",
                   mech_to_str(endecrypt_mech.mechanism),
                   mech_to_str(digest_mech.mechanism));

    testcase_new_assertion();

    /* Initialize operations */
    rc = funcs->C_DecryptInit(session, &endecrypt_mech, aes_key);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(endecrypt_mech.mechanism),
                       (unsigned int)endecrypt_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_DigestInit(session, &digest_mech);
    if (rc != CKR_OK) {
        testcase_error("C_DigestInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(digest_mech.mechanism),
                       (unsigned int)digest_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* First chunk */
    clear_len = 0;
    rc = funcs->C_DecryptDigestUpdate(session, encrypted1, encrypted1_len,
                                      NULL, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptDigestUpdate (1) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (clear_len < sizeof(data1)) {
        testcase_error("Wrong encrypted length from C_DecryptDigestUpdate (1): %lu",
                       clear_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    clear_len = sizeof(clear);
    rc = funcs->C_DecryptDigestUpdate(session, encrypted1, encrypted1_len,
                                      clear, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptDigestUpdate (2) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (clear_len != sizeof(data1)) {
        testcase_error("Wrong encrypted length from C_DecryptDigestUpdate (2): %lu",
                       encrypted1_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }
    if (memcmp(clear, data1, clear_len) != 0) {
        testcase_error("Wrong decrypted data from C_DecryptDigestUpdate (2)");
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    /* Second chunk */
    clear_len = 0;
    rc = funcs->C_DecryptDigestUpdate(session, encrypted2, encrypted2_len,
                                      NULL, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptDigestUpdate (3) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (clear_len < sizeof(data2)) {
        testcase_error("Wrong encrypted length from C_DecryptDigestUpdate (3): %lu",
                       clear_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    clear_len = sizeof(clear);
    rc = funcs->C_DecryptDigestUpdate(session, encrypted2, encrypted2_len,
                                      clear, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptDigestUpdate (4) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (clear_len != sizeof(data2)) {
        testcase_error("Wrong encrypted length from C_DecryptDigestUpdate (4): %lu",
                       encrypted1_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }
    if (memcmp(clear, data2, clear_len) != 0) {
        testcase_error("Wrong decrypted data from C_DecryptDigestUpdate (4)");
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    /* Finalize operations */
    clear_len = sizeof(clear);
    rc = funcs->C_DecryptFinal(session, clear, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (clear_len != 0) {
        testcase_error("Wrong encrypted length from C_DecryptFinal: %lu",
                       clear_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    digest2_len = sizeof(digest2);
    rc = funcs->C_DigestFinal(session, digest2, &digest2_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (digest1_len != digest2_len) {
        testcase_error("Wrong encrypted length from C_DigestFinal: %lu",
                       digest2_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    if (memcmp(digest1, digest2, digest1_len) != 0) {
        testcase_error("Wrong digest from C_DigestFinal");
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    testcase_pass("C_DecryptDigestUpdate with %s/%s",
                  mech_to_str(endecrypt_mech.mechanism),
                  mech_to_str(digest_mech.mechanism));

testcase_cleanup:
    if (aes_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, aes_key);
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

CK_RV do_sign_encrypt_decrypt_verify()
{
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc = CKR_OK, loc_rc;
    CK_FLAGS flags;
    CK_OBJECT_HANDLE aes_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE mac_key = CK_INVALID_HANDLE;
    CK_BYTE encrypted1[sizeof(data1) + 16];
    CK_ULONG encrypted1_len;
    CK_BYTE encrypted2[sizeof(data2) + 16];
    CK_ULONG encrypted2_len;
    CK_BYTE encrypted3[16];
    CK_ULONG encrypted3_len;
    CK_BYTE clear[sizeof(data1) + 16];
    CK_ULONG clear_len;
    CK_BYTE signature[32];
    CK_ULONG signature_len;

    if (is_ica_token(SLOT_ID) || is_tpm_token(SLOT_ID)) {
        /*
         * The ICA and TPM tokens do not support CKM_SHA256_HMAC in multi-chunk
         * mode, only single chunk. Use CKM_AES_CMAC instead.
         */
        signver_mech.mechanism = CKM_AES_CMAC;
        mackeygen_mech.mechanism = CKM_AES_KEY_GEN;
    }


    testcase_begin("C_SignEncryptUpdate with %s/%s",
                   mech_to_str(signver_mech.mechanism),
                   mech_to_str(endecrypt_mech.mechanism));

    testcase_rw_session();
    testcase_user_login();

    if (!mech_supported(SLOT_ID, signver_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(signver_mech.mechanism),
                      (unsigned int)signver_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, endecrypt_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(endecrypt_mech.mechanism),
                      (unsigned int)endecrypt_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, aeskeygen_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(aeskeygen_mech.mechanism),
                      (unsigned int)aeskeygen_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, mackeygen_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(mackeygen_mech.mechanism),
                      (unsigned int)mackeygen_mech.mechanism);
        goto testcase_cleanup;
    }

    /* generate an AES key */
    rc = generate_AESKey(session, 256 / 8, CK_TRUE, &aeskeygen_mech, &aes_key);
    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("generate key with mech %s (%u) in slot %lu "
                          "is not allowed by policy",
                          mech_to_str(aeskeygen_mech.mechanism),
                          (unsigned int)aeskeygen_mech.mechanism,
                          SLOT_ID);
            rc = CKR_OK;
            goto testcase_cleanup;
        }

        testcase_error("generate key with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(aeskeygen_mech.mechanism),
                       (unsigned int)aeskeygen_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* generate a MAC key */
    if (mackeygen_mech.mechanism == CKM_AES_KEY_GEN)
        rc = generate_AESKey(session, 256 / 8, CK_TRUE, &aeskeygen_mech,
                             &mac_key);
    else
        rc = generate_SecretKey(session, 256, &mackeygen_mech, &mac_key);
    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("generate key with mech %s (%u) in slot %lu "
                          "is not allowed by policy",
                          mech_to_str(mackeygen_mech.mechanism),
                          (unsigned int)mackeygen_mech.mechanism,
                          SLOT_ID);
            rc = CKR_OK;
            goto testcase_cleanup;
        }

        testcase_error("generate key with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(mackeygen_mech.mechanism),
                       (unsigned int)mackeygen_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_new_assertion();

    /* Initialize operations */
    rc = funcs->C_EncryptInit(session, &endecrypt_mech, aes_key);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(endecrypt_mech.mechanism),
                       (unsigned int)endecrypt_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_SignInit(session, &signver_mech, mac_key);
    if (rc != CKR_OK) {
        testcase_error("C_SignInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(signver_mech.mechanism),
                       (unsigned int)signver_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* First chunk */
    encrypted1_len = 0;
    rc = funcs->C_SignEncryptUpdate(session, data1, sizeof(data1),
                                    NULL, &encrypted1_len);
    if (rc != CKR_OK) {
        testcase_error("C_SignEncryptUpdate (1) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted1_len < sizeof(data1)) {
        testcase_error("Wrong encrypted length from C_SignEncryptUpdate (1): %lu",
                       encrypted1_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    encrypted1_len = sizeof(encrypted1);
    rc = funcs->C_SignEncryptUpdate(session, data1, sizeof(data1),
                                    encrypted1, &encrypted1_len);
    if (rc != CKR_OK) {
        testcase_error("C_SignEncryptUpdate (2) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted1_len != sizeof(data1)) {
        testcase_error("Wrong encrypted length from C_SignEncryptUpdate (2): %lu",
                       encrypted1_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    /* Second chunk */
    encrypted2_len = 0;
    rc = funcs->C_SignEncryptUpdate(session, data2, sizeof(data2),
                                    NULL, &encrypted2_len);
    if (rc != CKR_OK) {
        testcase_error("C_SignEncryptUpdate (3) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted2_len < sizeof(data2)) {
        testcase_error("Wrong encrypted length from C_SignEncryptUpdate (3): %lu",
                       encrypted2_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    encrypted2_len = sizeof(encrypted2);
    rc = funcs->C_SignEncryptUpdate(session, data2, sizeof(data2),
                                    encrypted2, &encrypted2_len);
    if (rc != CKR_OK) {
        testcase_error("C_SignEncryptUpdate (4) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted2_len != sizeof(data2)) {
        testcase_error("Wrong encrypted length from C_SignEncryptUpdate (4): %lu",
                       encrypted2_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    /* Finalize operations */
    encrypted3_len = sizeof(encrypted3);
    rc = funcs->C_EncryptFinal(session, encrypted3, &encrypted3_len);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted3_len != 0) {
        testcase_error("Wrong encrypted length from C_EncryptFinal: %lu",
                       encrypted3_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    signature_len = sizeof(signature);
    rc = funcs->C_SignFinal(session, signature, &signature_len);
    if (rc != CKR_OK) {
        testcase_error("C_SignFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("C_SignEncryptUpdate with %s/%s",
                  mech_to_str(signver_mech.mechanism),
                  mech_to_str(endecrypt_mech.mechanism));

    testcase_begin("C_DecryptVerifyUpdate with %s/%s",
                   mech_to_str(endecrypt_mech.mechanism),
                   mech_to_str(signver_mech.mechanism));

    testcase_new_assertion();

    /* Initialize operations */
    rc = funcs->C_DecryptInit(session, &endecrypt_mech, aes_key);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(endecrypt_mech.mechanism),
                       (unsigned int)endecrypt_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_VerifyInit(session, &signver_mech, mac_key);
    if (rc != CKR_OK) {
        testcase_error("C_VerifyInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(digest_mech.mechanism),
                       (unsigned int)signver_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* First chunk */
    clear_len = 0;
    rc = funcs->C_DecryptVerifyUpdate(session, encrypted1, encrypted1_len,
                                      NULL, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptVerifyUpdate (1) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (clear_len < sizeof(data1)) {
        testcase_error("Wrong encrypted length from C_DecryptVerifyUpdate (1): %lu",
                       clear_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    clear_len = sizeof(clear);
    rc = funcs->C_DecryptVerifyUpdate(session, encrypted1, encrypted1_len,
                                      clear, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptVerifyUpdate (2) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (clear_len != sizeof(data1)) {
        testcase_error("Wrong encrypted length from C_DecryptVerifyUpdate (2): %lu",
                       encrypted1_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }
    if (memcmp(clear, data1, clear_len) != 0) {
        testcase_error("Wrong decrypted data from C_DecryptVerifyUpdate (2)");
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    /* Second chunk */
    clear_len = 0;
    rc = funcs->C_DecryptVerifyUpdate(session, encrypted2, encrypted2_len,
                                      NULL, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptVerifyUpdate (3) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (clear_len < sizeof(data2)) {
        testcase_error("Wrong encrypted length from C_DecryptVerifyUpdate (3): %lu",
                       clear_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    clear_len = sizeof(clear);
    rc = funcs->C_DecryptVerifyUpdate(session, encrypted2, encrypted2_len,
                                      clear, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptVerifyUpdate (4) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (clear_len != sizeof(data2)) {
        testcase_error("Wrong encrypted length from C_DecryptVerifyUpdate (4): %lu",
                       encrypted1_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }
    if (memcmp(clear, data2, clear_len) != 0) {
        testcase_error("Wrong decrypted data from C_DecryptVerifyUpdate (4)");
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    /* Finalize operations */
    clear_len = sizeof(clear);
    rc = funcs->C_DecryptFinal(session, clear, &clear_len);
    if (rc != CKR_OK) {
        testcase_error("C_DecryptFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (clear_len != 0) {
        testcase_error("Wrong encrypted length from C_DecryptFinal: %lu",
                       clear_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    rc = funcs->C_VerifyFinal(session, signature, signature_len);
    if (rc != CKR_OK) {
        testcase_error("C_VerifyFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("C_DecryptVerifyUpdate with %s/%s",
                  mech_to_str(endecrypt_mech.mechanism),
                  mech_to_str(signver_mech.mechanism));

testcase_cleanup:
    if (aes_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, aes_key);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    if (mac_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, mac_key);
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

CK_RV do_save_restore_dual_state()
{
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc = CKR_OK, loc_rc;
    CK_FLAGS flags;
    CK_OBJECT_HANDLE aes_key = CK_INVALID_HANDLE;
    CK_BYTE encrypted1[sizeof(data1) + 16];
    CK_ULONG encrypted1_len;
    CK_BYTE encrypted2[sizeof(data2) + 16];
    CK_ULONG encrypted2_len;
    CK_BYTE encrypted2a[sizeof(data2) + 16];
    CK_ULONG encrypted2a_len;
    CK_BYTE encrypted3[16];
    CK_ULONG encrypted3_len;
    CK_BYTE digest1[32];
    CK_ULONG digest1_len;
    CK_BYTE digest2[32];
    CK_ULONG digest2_len;
    CK_BYTE *state = NULL;
    CK_ULONG state_len;

    testcase_begin("Save/Restore state with 2 active operations");

    testcase_rw_session();
    testcase_user_login();

    if (!mech_supported(SLOT_ID, digest_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(digest_mech.mechanism),
                      (unsigned int)digest_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, endecrypt_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(endecrypt_mech.mechanism),
                      (unsigned int)endecrypt_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, aeskeygen_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)SLOT_ID,
                      mech_to_str(aeskeygen_mech.mechanism),
                      (unsigned int)aeskeygen_mech.mechanism);
        goto testcase_cleanup;
    }

    /* generate an AES key */
    rc = generate_AESKey(session, 256 / 8, CK_TRUE, &aeskeygen_mech, &aes_key);
    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("generate key with mech %s (%u) in slot %lu "
                          "is not allowed by policy",
                          mech_to_str(aeskeygen_mech.mechanism),
                          (unsigned int)aeskeygen_mech.mechanism,
                          SLOT_ID);
            rc = CKR_OK;
            goto testcase_cleanup;
        }

        testcase_error("generate key with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(aeskeygen_mech.mechanism),
                       (unsigned int)aeskeygen_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Initialize operations */
    rc = funcs->C_EncryptInit(session, &endecrypt_mech, aes_key);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(endecrypt_mech.mechanism),
                       (unsigned int)endecrypt_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_DigestInit(session, &digest_mech);
    if (rc != CKR_OK) {
        testcase_error("C_DigestInit with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(digest_mech.mechanism),
                       (unsigned int)digest_mech.mechanism,
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* First chunk */
    encrypted1_len = sizeof(encrypted1);
    rc = funcs->C_DigestEncryptUpdate(session, data1, sizeof(data1),
                                      encrypted1, &encrypted1_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestEncryptUpdate (2) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Save state of both operations */
    rc = funcs->C_GetOperationState(session, NULL, &state_len);
    if (rc != CKR_OK) {
        if (rc == CKR_STATE_UNSAVEABLE) {
            testcase_skip("Operation state is not savable");
            goto testcase_cleanup;
        }

        testcase_error("C_GetOperationState (1) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    state = calloc(1, state_len);
    if (state == NULL) {
        testcase_fail("malloc for state buffer of size %lu failed", state_len);
        rc = CKR_HOST_MEMORY;
        goto testcase_cleanup;
    }

    rc = funcs->C_GetOperationState(session, state, &state_len);
    if (rc != CKR_OK) {
        if (rc == CKR_STATE_UNSAVEABLE) {
            testcase_skip("Operation state is not savable");
            goto testcase_cleanup;
        }

        testcase_error("C_GetOperationState (2) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Second chunk */
    encrypted2_len = sizeof(encrypted2);
    rc = funcs->C_DigestEncryptUpdate(session, data2, sizeof(data2),
                                      encrypted2, &encrypted2_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestEncryptUpdate (4) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Finalize operations */
    encrypted3_len = sizeof(encrypted3);
    rc = funcs->C_EncryptFinal(session, encrypted3, &encrypted3_len);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    digest1_len = sizeof(digest1);
    rc = funcs->C_DigestFinal(session, digest1, &digest1_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_new_assertion();

    /* restore state from after first chunk */
    rc = funcs->C_SetOperationState(session, state, state_len,
                                    aes_key, CK_INVALID_HANDLE);
    if (rc != CKR_OK) {
        testcase_error("C_SetOperationState in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Second chunk again */
    encrypted2a_len = sizeof(encrypted2a);
    rc = funcs->C_DigestEncryptUpdate(session, data2, sizeof(data2),
                                      encrypted2a, &encrypted2a_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestEncryptUpdate (5) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (encrypted2a_len != encrypted2_len) {
        testcase_error("Wrong encrypted length from C_DigestEncryptUpdate (5): %lu",
                       encrypted2a_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    if (memcmp(encrypted2, encrypted2a, encrypted2_len) != 0) {
        testcase_error("Wrong encrypted data from C_DigestEncryptUpdate (5)");
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    /* Finalize operations again */
    encrypted3_len = sizeof(encrypted3);
    rc = funcs->C_EncryptFinal(session, encrypted3, &encrypted3_len);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptFinal in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    digest2_len = sizeof(digest2);
    rc = funcs->C_DigestFinal(session, digest2, &digest2_len);
    if (rc != CKR_OK) {
        testcase_error("C_DigestFinal (2) in slot %lu failed, rc=%s",
                       SLOT_ID, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (digest1_len != digest2_len) {
        testcase_error("Wrong encrypted length from C_DigestFinal (2): %lu",
                       digest2_len);
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    if (memcmp(digest1, digest2, digest1_len) != 0) {
        testcase_error("Wrong digest from C_DigestFinal (2)");
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    testcase_pass("Save/Restore state with 2 active operations");

testcase_cleanup:
    if (aes_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, aes_key);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(SLOT_ID);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    if (state != NULL)
        free(state);

    return rc;

}

CK_RV do_dual_functions_tests()
{
    CK_RV rc = CKR_OK;

    rc |= do_digest_encrypt_decrypt_digest();

    rc |= do_sign_encrypt_decrypt_verify();

    rc |= do_save_restore_dual_state();

    return rc;
}


int main(int argc, char **argv)
{
    int rc;
    CK_C_INITIALIZE_ARGS cinit_args;
    CK_RV rv = 0;
    CK_ULONG i;

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

    for (i = 0; i < sizeof(data1); i++)
        data1[i] = i;
    for (i = 0; i < sizeof(data1); i++)
        data2[i] = 255 - i;

    rv = do_dual_functions_tests();
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
