/*
 * COPYRIGHT (c) International Business Machines Corp. 2011-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

 /*
  * openCryptoki testcase for RSA
  *
  * August 18, 2011
  *
  * Fionnuala Gunter <fin@linux.vnet.ibm.com>
  */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "common.c"
#include "regress.h"

#include "rsa.h"

/**
 * Note: do_EncryptDecryptRSA fails if we don't manually
 * remove padding from decrypted values. This might be a bug.
 **/


/* This function should test:
 * RSA Key Generation, CKM_RSA_PKCS_KEY_PAIR_GEN
 * RSA Encryption, mechanism chosen by caller
 * RSA Decryption, mechanism chosen by caller
 *
 * 1. Generate RSA Key Pair
 * 2. Generate plaintext
 * 3. Encrypt plaintext
 * 4. Decrypt encrypted data
 * 5. Compare plaintext with decrypted data
 *
 */
CK_RV do_EncryptDecryptRSA(struct GENERATED_TEST_SUITE_INFO *tsuite)
{
    int i, j;
    CK_BYTE original[BIG_REQUEST];
    CK_ULONG original_len;
    CK_BYTE crypt[BIG_REQUEST];
    CK_ULONG crypt_len;
    CK_BYTE decrypt[BIG_REQUEST];
    CK_ULONG decrypt_len;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key, priv_key;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;

    char *s;

    // begin testsuite
    testsuite_begin("%s Encrypt Decrypt.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %u",
                       (unsigned int) slot_id,
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                          tsuite->tv[i].publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }
        // begin testcase
        testcase_begin("%s Encrypt and Decrypt with test vector %d."
                       "\npubl_exp='%s', modbits=%ld, publ_exp_len=%ld, "
                       "inputlen=%ld.", tsuite->name, i, s,
                       tsuite->tv[i].modbits,
                       tsuite->tv[i].publ_exp_len, tsuite->tv[i].inputlen);

        rc = CKR_OK;            // set rc

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %ld cannot be used with "
                          "modbits.='%ld'", SLOT_ID, tsuite->tv[i].modbits);
            continue;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("EP11 Token cannot "
                              "be used with publ_exp.='%s'", s);
                continue;
            }
        }
        // cca special cases:
        // cca token can only use the following public exponents
        // 0x03 or 0x010001 (65537)
        // so skip test if invalid public exponent is used
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                     tsuite->tv[i].publ_exp_len)) {
                testcase_skip("CCA Token cannot "
                              "be used with publ_exp.='%s'", s);
                continue;
            }
        }
        // tpm special cases:
        // tpm token can only use public exponent 0x010001 (65537)
        // so skip test if invalid public exponent is used
        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].modbits))) {
                testcase_skip("TPM Token cannot " "be used with publ_exp.='%s'",
                              s);
                continue;
            }
        }

        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len) ||
                (tsuite->tv[i].modbits < 1024)) {
                testcase_skip("ICSF Token cannot be used with "
                              "publ_exp='%s'.", s);
                continue;
            }
        }

        free(s);

        // clear buffers
        memset(original, 0, BIG_REQUEST);
        memset(crypt, 0, BIG_REQUEST);
        memset(decrypt, 0, BIG_REQUEST);

        // get test vector parameters
        original_len = tsuite->tv[i].inputlen;

        // generate key pair
        rc = generate_RSA_PKCS_KeyPair(session,
                                       tsuite->tv[i].modbits,
                                       tsuite->tv[i].publ_exp,
                                       tsuite->tv[i].publ_exp_len,
                                       &publ_key, &priv_key);

        if (rc != CKR_OK) {
            testcase_error("generate_RSA_PKCS_KeyPair(), "
                           "rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // generate plaintext
        for (j = 0; j < original_len; j++) {
            original[j] = (j + 1) % 255;
        }

        // set cipher buffer length
        crypt_len = BIG_REQUEST;
        decrypt_len = BIG_REQUEST;

        // get mech
        mech = tsuite->mech;
        if (mech.mechanism == CKM_RSA_PKCS_OAEP) {
            oaep_params = tsuite->tv[i].oaep_params;
            mech.pParameter = &oaep_params;
            mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
        }
        // initialize (public key) encryption
        rc = funcs->C_EncryptInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_EncryptInit, rc=%s", p11_get_ckr(rc));
        }
        // do (public key) encryption
        rc = funcs->C_Encrypt(session,
                              original, original_len, crypt, &crypt_len);
        if (rc != CKR_OK) {
            testcase_error("C_Encrypt, rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // initialize (private key) decryption
        rc = funcs->C_DecryptInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit, rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // do (private key) decryption
        rc = funcs->C_Decrypt(session, crypt, crypt_len, decrypt, &decrypt_len);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt, rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // FIXME: there shouldn't be any padding here
        // remove padding if mech is CKM_RSA_X_509
        if (mech.mechanism == CKM_RSA_X_509) {
            memmove(decrypt,
                    decrypt + decrypt_len - original_len, original_len);
            decrypt_len = original_len;
        }
        // check results
        testcase_new_assertion();

        if (decrypt_len != original_len) {
            testcase_fail("decrypted length does not match"
                          "original data length.\n expected length = %ld,"
                          "but found length=%ld.\n", original_len, decrypt_len);
        } else if (memcmp(decrypt, original, original_len)) {
            testcase_fail("decrypted data does not match " "original data.");
        } else {
            testcase_pass("C_Encrypt and C_Decrypt.");
        }

        // clean up
        rc = funcs->C_DestroyObject(session, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }

        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }

    }
    goto testcase_cleanup;
error:
    loc_rc = funcs->C_DestroyObject(session, publ_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

    loc_rc = funcs->C_DestroyObject(session, priv_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

testcase_cleanup:
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions, rc=%s", p11_get_ckr(loc_rc));
    }

    return rc;
}

/* This function should test:
 * RSA Key Generation, usign CKM_RSA_PKCS_KEY_PAIR_GEN
 * RSA Sign, mechanism chosen by caller
 * RSA Verify, mechanism chosen by caller
 *
 * 1. Generate RSA Key Pair
 * 2. Generate message
 * 3. Sign message
 * 4. Verify signature
 *
 */
CK_RV do_SignVerifyRSA(struct GENERATED_TEST_SUITE_INFO * tsuite,
                       CK_BBOOL recover_mode)
{
    int i;                      // test vector index
    int j;                      // message byte index
    CK_BYTE message[MAX_MESSAGE_SIZE];
    CK_ULONG message_len;
    CK_BYTE signature[MAX_SIGNATURE_SIZE];
    CK_ULONG signature_len;
    CK_BYTE out_message[MAX_MESSAGE_SIZE];
    CK_ULONG out_message_len;

    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key, priv_key;

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    char *s;

    // begin testsuite
    testsuite_begin("%s Sign%s Verify%s.", tsuite->name,
                    recover_mode ? "Recover" : "",
                    recover_mode ? "Recover" : "");
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %u",
                       (unsigned int) slot_id,
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    if (recover_mode) {
        if (!mech_supported_flags(slot_id, tsuite->mech.mechanism,
                                  CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER)) {
            testsuite_skip(tsuite->tvcount,
                           "Slot %u doesn't support Sign/VerifyRecover with %u",
                           (unsigned int) slot_id,
                           (unsigned int) tsuite->mech.mechanism);
            goto testcase_cleanup;
        }
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                          tsuite->tv[i].publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }
        // begin test
        testcase_begin("%s Sign%s and Verify%s with test vector %d, "
                       "\npubl_exp='%s', mod_bits='%lu', keylen='%lu'.",
                       tsuite->name, recover_mode ? "Recover" : "",
                       recover_mode ? "Recover" : "", i, s,
                       tsuite->tv[i].modbits, tsuite->tv[i].keylen);

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %ld cannot be used with "
                          "modbits.='%ld'", SLOT_ID, tsuite->tv[i].modbits);
            continue;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("EP11 Token cannot "
                              "be used with publ_exp.='%s'", s);
                continue;
            }
        }

        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                     tsuite->tv[i].publ_exp_len)) {
                testcase_skip("CCA Token cannot "
                              "be used with publ_exp='%s'.", s);
                continue;
            }
        }

        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].modbits))) {
                testcase_skip("TPM Token cannot " "be used with publ_exp='%s'.",
                              s);
                continue;
            }
        }

        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len) ||
                (tsuite->tv[i].modbits < 1024)) {
                testcase_skip("ICSF Token cannot be used with "
                              "publ_exp='%s'.", s);
                continue;
            }
        }
        // free memory
        free(s);

        rc = CKR_OK;            // set rc

        // clear buffers
        memset(message, 0, MAX_MESSAGE_SIZE);
        memset(signature, 0, MAX_SIGNATURE_SIZE);
        memset(out_message, 0, MAX_MESSAGE_SIZE);

        // get test vector parameters
        message_len = tsuite->tv[i].inputlen;

        // generate key pair
        rc = generate_RSA_PKCS_KeyPair(session,
                                       tsuite->tv[i].modbits,
                                       tsuite->tv[i].publ_exp,
                                       tsuite->tv[i].publ_exp_len,
                                       &publ_key, &priv_key);
        if (rc != CKR_OK) {
            testcase_error("generate_RSA_PKCS_KeyPair(), "
                           "rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // generate message
        for (j = 0; j < message_len; j++) {
            message[j] = (j + 1) % 255;
        }

        // get  mech
        mech = tsuite->mech;

        // initialize Sign (length only)
        if (recover_mode)
            rc = funcs->C_SignRecoverInit(session, &mech, priv_key);
        else
            rc = funcs->C_SignInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_Sign%sInit(), rc=%s",
                           recover_mode ? "Recover" : "", p11_get_ckr(rc));
            goto error;
        }
        // set buffer size
        signature_len = MAX_SIGNATURE_SIZE;

        // do Sign
        if (recover_mode)
            rc = funcs->C_SignRecover(session, message, message_len,
                                     signature, &signature_len);
        else
            rc = funcs->C_Sign(session, message, message_len,
                               signature, &signature_len);
        if (rc != CKR_OK) {
            testcase_error("C_Sign%s(), rc=%s signature len=%ld",
                           recover_mode ? "Recover" : "",
                           p11_get_ckr(rc), signature_len);
            goto error;
        }
        // initialize Verify
        if (recover_mode)
            rc = funcs->C_VerifyRecoverInit(session, &mech, publ_key);
        else
            rc = funcs->C_VerifyInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_Verify%sInit(), rc=%s",
                           recover_mode ? "Recover" : "", p11_get_ckr(rc));
        }
        // do Verify
        if (recover_mode) {
            out_message_len = sizeof(out_message);
            rc = funcs->C_VerifyRecover(session, signature, signature_len,
                                        out_message, &out_message_len);
        } else {
            rc = funcs->C_Verify(session, message, message_len,
                                 signature, signature_len);
        }

        // check results
        testcase_new_assertion();
        if (rc == CKR_OK) {
            if (recover_mode) {
                if (mech.mechanism == CKM_RSA_X_509) {
                    // out_message may have been left padded with binary zeros
                    if (memcmp(&message[out_message_len - message_len],
                               out_message, message_len) != 0) {
                        testcase_fail("C_VerifyRecover() message does not match");
                    } else {
                        testcase_pass("C_VerifyRecover.");
                    }
                } else {
                    if (out_message_len != message_len ||
                            memcmp(message, out_message, message_len) != 0) {
                        testcase_fail("C_VerifyRecover() message does not match");
                    } else {
                        testcase_pass("C_VerifyRecover.");
                    }
                }
            } else {
                testcase_pass("C_Verify.");
            }
        } else {
            testcase_fail("C_Verify%s(), rc=%s", recover_mode ? "Recover" : "",
                          p11_get_ckr(rc));
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
    goto testcase_cleanup;
error:
    loc_rc = funcs->C_DestroyObject(session, publ_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
    }
    loc_rc = funcs->C_DestroyObject(session, priv_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloesAllSessions, rc=%s", p11_get_ckr(rc));
    }

    return rc;
}


/* This function should test:
 * RSA Key Generation, usign CKM_RSA_PKCS_KEY_PAIR_GEN
 * RSA-PSS Sign, mechanism chosen by caller
 * RSA-PSS Verify, mechanism chosen by caller
 *
 * 1. Generate RSA Key Pair
 * 2. Generate message
 * 3. Generate hash for the message if required by mechanism.
 * 4. Sign message
 * 5. Verify signature
 *
 */
#define MAX_HASH_SIZE 64
CK_RV do_SignVerify_RSAPSS(struct GENERATED_TEST_SUITE_INFO * tsuite)
{
    int i;                      // test vector index
    int j;                      // message byte index
    CK_BYTE message[MAX_MESSAGE_SIZE];
    CK_BYTE signature[MAX_SIGNATURE_SIZE];
    CK_BYTE hash[MAX_HASH_SIZE];
    CK_ULONG message_len, signature_len, h_len;

    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key, priv_key;

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;
    CK_RSA_PKCS_PSS_PARAMS pss_params;

    char *s;

    // begin testsuite
    testsuite_begin("%s Sign Verify.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %u",
                       (unsigned int) slot_id,
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                          tsuite->tv[i].publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }
        // begin test
        testcase_begin("%s Sign and Verify with test vector %d, "
                       "\npubl_exp='%s', mod_bits='%lu', keylen='%lu'.",
                       tsuite->name, i, s,
                       tsuite->tv[i].modbits, tsuite->tv[i].keylen);

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %ld cannot be used with "
                          "modbits.='%ld'", SLOT_ID, tsuite->tv[i].modbits);
            continue;
        }
        // free memory
        free(s);

        rc = CKR_OK;            // set rc

        // clear buffers
        memset(message, 0, MAX_MESSAGE_SIZE);
        memset(signature, 0, MAX_SIGNATURE_SIZE);

        // get test vector parameters
        message_len = tsuite->tv[i].inputlen;

        // generate key pair
        rc = generate_RSA_PKCS_KeyPair(session, tsuite->tv[i].modbits,
                                       tsuite->tv[i].publ_exp,
                                       tsuite->tv[i].publ_exp_len, &publ_key,
                                       &priv_key);
        if (rc != CKR_OK) {
            testcase_error("generate_RSA_PKCS_KeyPair(), "
                           "rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // generate message
        for (j = 0; j < message_len; j++) {
            message[j] = (j + 1) % 255;
        }

        if (tsuite->mech.mechanism == CKM_RSA_PKCS_PSS) {
            // create digest of message to pass to C_Sign
            mech.mechanism = tsuite->tv[i].pss_params.hashAlg;
            mech.pParameter = 0;
            mech.ulParameterLen = 0;

            h_len = MAX_HASH_SIZE;

            rc = funcs->C_DigestInit(session, &mech);
            if (rc != CKR_OK) {
                testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }
            rc = funcs->C_Digest(session, message, message_len, hash, &h_len);
            if (rc != CKR_OK) {
                testcase_error("C_Digest rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }
        }
        // set mechanism for signing
        mech = tsuite->mech;
        pss_params = tsuite->tv[i].pss_params;
        mech.pParameter = &pss_params;
        mech.ulParameterLen = sizeof(CK_RSA_PKCS_PSS_PARAMS);

        // initialize Sign
        rc = funcs->C_SignInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_SignInit(), rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // set buffer size
        signature_len = MAX_SIGNATURE_SIZE;

        // do Sign
        if (mech.mechanism == CKM_RSA_PKCS_PSS)
            rc = funcs->C_Sign(session, hash, h_len, signature, &signature_len);
        else
            rc = funcs->C_Sign(session, message, message_len,
                               signature, &signature_len);
        if (rc != CKR_OK) {
            testcase_error("C_Sign(), rc=%s signature len=%ld",
                           p11_get_ckr(rc), signature_len);
            goto error;
        }
        // initialize Verify
        rc = funcs->C_VerifyInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyInit(), rc=%s", p11_get_ckr(rc));
        }
        // do Verify
        if (mech.mechanism == CKM_RSA_PKCS_PSS)
            rc = funcs->C_Verify(session, hash, h_len, signature,
                                 signature_len);
        else
            rc = funcs->C_Verify(session, message, message_len,
                                 signature, signature_len);

        // check results
        testcase_new_assertion();
        if (rc == CKR_OK)
            testcase_pass("C_Verify.");
        else
            testcase_fail("C_Verify(), rc=%s", p11_get_ckr(rc));

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
    goto testcase_cleanup;
error:
    loc_rc = funcs->C_DestroyObject(session, publ_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
    }
    loc_rc = funcs->C_DestroyObject(session, priv_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloesAllSessions, rc=%s", p11_get_ckr(rc));
    }

    return rc;
}


/* This function should test:
 * RSA Key Generation, using CKM_PKCS_KEY_PAIR_GEN
 * RSA Public-Key Wrap
 * RSA Private-Key Unwrap
 *
 */
CK_RV do_WrapUnwrapRSA(struct GENERATED_TEST_SUITE_INFO * tsuite)
{
    int i = 0, j = 0;
    char *s = NULL;
    CK_OBJECT_HANDLE publ_key, priv_key, secret_key, unwrapped_key;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_ULONG wrapped_keylen, unwrapped_keylen = 0;
    CK_MECHANISM wrap_mech, keygen_mech, mech;
    CK_BYTE clear[32], cipher[32], re_cipher[32];
    CK_ULONG cipher_len = 32, re_cipher_len = 32;
    CK_RSA_PKCS_OAEP_PARAMS oaep_params;

    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type;
    CK_ATTRIBUTE unwrap_tmpl[] = {
        {CKA_CLASS, &key_class, sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE, &key_type, sizeof(CK_KEY_TYPE)},
        {CKA_VALUE_LEN, &unwrapped_keylen, sizeof(CK_ULONG)}
    };
    CK_ULONG unwrap_tmpl_len;

    // begin test suite
    testsuite_begin("%s Wrap Unwrap.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* create some data */
    for (j = 0; j < 32; j++)
        clear[j] = j;

    // skip all tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %u",
                       (unsigned int) slot_id,
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    } else if (!wrap_supported(slot_id, tsuite->mech)) {
        // skip all tests if the slot doesn't support wrapping
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support key wrapping",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    for (i = 0; i < tsuite->tvcount; i++) {
        // skip if the slot doesn't support the keygen mechanism
        if (!mech_supported(slot_id, tsuite->tv[i].keytype.mechanism)) {
            testcase_skip("Slot %u doesn't support %u",
                          (unsigned int) slot_id,
                          (unsigned int) tsuite->tv[i].keytype.mechanism);
            continue;
        }

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %ld cannot be used with "
                          "modbits.='%ld'", SLOT_ID, tsuite->tv[i].modbits);
            continue;
        }
        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].publ_exp,
                          tsuite->tv[i].publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("EP11 Token cannot "
                              "be used with publ_exp.='%s'", s);
                continue;
            }
        }
        // begin test
        testcase_begin("%s Wrap Unwrap with test vector %d, "
                       "\npubl_exp='%s', mod_bits='%lu', keylen='%lu', "
                       "keytype='%s'", tsuite->name, i, s,
                       tsuite->tv[i].modbits, tsuite->tv[i].keylen,
                       p11_get_ckm(tsuite->tv[i].keytype.mechanism));

        // free memory
        if (s)
            free(s);

        // get key gen mechanism
        keygen_mech = tsuite->tv[i].keytype;

        // get wrapping mechanism
        wrap_mech = tsuite->mech;
        if (wrap_mech.mechanism == CKM_RSA_PKCS_OAEP) {
            oaep_params = tsuite->tv[i].oaep_params;
            wrap_mech.pParameter = &oaep_params;
            wrap_mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
        }
        // clear out buffers
        memset(cipher, 0, sizeof(cipher));
        memset(re_cipher, 0, sizeof(re_cipher));

        // initialize buffer lengths
        wrapped_keylen = PKCS11_MAX_PIN_LEN;

        // generate RSA key pair
        rc = generate_RSA_PKCS_KeyPair(session, tsuite->tv[i].modbits,
                                       tsuite->tv[i].publ_exp,
                                       tsuite->tv[i].publ_exp_len,
                                       &publ_key, &priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_GenerateKeyPair() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // generate secret key
        rc = generate_SecretKey(session, tsuite->tv[i].keylen,
                                &keygen_mech, &secret_key);
        if (rc != CKR_OK) {
            testcase_error("generate_SecretKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /* Testcase Goals:
         * 1. Encrypt data.
         * 2. Use RSA to wrap the secret key we just used to encrypt.
         * 3. Use RSA to unwrap the secret key.
         * 4. Decrypt with the newly unwrapped key to get original data.
         *
         * The first assertion will be the success of RSA to wrap and
         * unwrap the secret key.
         * The second assertion will be the success of the unwrapped
         * key to decrypt the original text.
         * Note: Generic secret keys are not used for encrypt/decrypt
         *       by default. So they will not be included in second
         *       assertion.
         */
        if (keygen_mech.mechanism != CKM_GENERIC_SECRET_KEY_GEN) {
            switch (keygen_mech.mechanism) {
            case CKM_AES_KEY_GEN:
                mech.mechanism = CKM_AES_ECB;
                key_type = CKK_AES;
                break;
            case CKM_DES3_KEY_GEN:
                mech.mechanism = CKM_DES3_ECB;
                key_type = CKK_DES3;
                break;
            case CKM_DES_KEY_GEN:
                mech.mechanism = CKM_DES_ECB;
                key_type = CKK_DES;
                break;
            case CKM_CDMF_KEY_GEN:
                mech.mechanism = CKM_CDMF_ECB;
                key_type = CKK_CDMF;
                break;
            default:
                testcase_error("unknown mech");
                goto error;
            }

            mech.ulParameterLen = 0;
            mech.pParameter = NULL;

            rc = funcs->C_EncryptInit(session, &mech, secret_key);
            if (rc != CKR_OK) {
                testcase_error("C_EncryptInit secret_key "
                               ": rc = %s", p11_get_ckr(rc));
                goto error;
            }

            rc = funcs->C_Encrypt(session, clear, 32, cipher, &cipher_len);
            if (rc != CKR_OK) {
                testcase_error("C_Encrypt secret_key: rc = %s",
                               p11_get_ckr(rc));
                goto error;
            }
        } else {
            key_type = CKK_GENERIC_SECRET;
        }

        testcase_new_assertion();       /* assertion #1 */
        // wrap key (length only)
        rc = funcs->C_WrapKey(session, &wrap_mech, publ_key, secret_key,
                              NULL, &wrapped_keylen);
        if (rc != CKR_OK) {
            testcase_error("C_WrapKey(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }
        // allocate memory for wrapped_key
        wrapped_key = calloc(sizeof(CK_BYTE), wrapped_keylen);
        if (wrapped_key == NULL) {
            testcase_error("Can't allocate memory for %lu bytes.",
                           sizeof(CK_BYTE) * wrapped_keylen);
            rc = CKR_HOST_MEMORY;
            goto error;
        }
        // wrap key
        rc = funcs->C_WrapKey(session, &wrap_mech, publ_key, secret_key,
                              wrapped_key, &wrapped_keylen);
        if (rc != CKR_OK) {
            testcase_fail("C_WrapKey, rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /* variable key length specific case:
         * According to PKCS#11 v2.2 section 12.1.12
         * CKM_RSA_X_509 does not wrap the key type, key length,
         * or any other information about the key; the application
         * must convey these separately, and supply them when
         * unwrapping the key.
         */
        if (((keygen_mech.mechanism == CKM_AES_KEY_GEN) ||
             (keygen_mech.mechanism == CKM_GENERIC_SECRET_KEY_GEN)) &&
            (wrap_mech.mechanism == CKM_RSA_X_509)) {
            unwrapped_keylen = tsuite->tv[i].keylen;
            unwrap_tmpl_len = 3;
        } else {
            unwrap_tmpl_len = 2;
        }

        // unwrap key
        rc = funcs->C_UnwrapKey(session, &wrap_mech, priv_key,
                                wrapped_key, wrapped_keylen,
                                unwrap_tmpl, unwrap_tmpl_len, &unwrapped_key);
        if (rc != CKR_OK) {
            testcase_fail("C_UnwrapKey, rc=%s", p11_get_ckr(rc));
            goto error;
        } else {
            testcase_pass("wrapped and unwrapped key successful.");
        }

        /* now decrypt the message with the unwrapped key */

        if (keygen_mech.mechanism != CKM_GENERIC_SECRET_KEY_GEN) {
            rc = funcs->C_DecryptInit(session, &mech, unwrapped_key);
            if (rc != CKR_OK) {
                testcase_error("C_DecryptInit unwrapped_key: "
                               " rc = %s", p11_get_ckr(rc));
                goto error;
            }

            rc = funcs->C_Decrypt(session, cipher, cipher_len,
                                  re_cipher, &re_cipher_len);
            if (rc != CKR_OK) {
                testcase_error("C_Decrypt unwrapped_key: "
                               "rc = %s", p11_get_ckr(rc));
                goto error;
            }

            testcase_new_assertion();

            if (memcmp(clear, re_cipher, 32) != 0) {
                testcase_fail("ERROR:data mismatch\n");
                goto error;
            } else {
                testcase_pass("Decrypted data is correct.");
            }
        }
        // clean up
        if (wrapped_key) {
            free(wrapped_key);
            wrapped_key = NULL;
        }

        rc = funcs->C_DestroyObject(session, secret_key);
        if (rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));

        rc = funcs->C_DestroyObject(session, publ_key);
        if (rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));

        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
    }
    goto testcase_cleanup;

error:
    if (wrapped_key) {
        free(wrapped_key);
        wrapped_key = NULL;
    }

    funcs->C_DestroyObject(session, secret_key);
    funcs->C_DestroyObject(session, publ_key);
    funcs->C_DestroyObject(session, priv_key);

testcase_cleanup:
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions(), rc=%s.", p11_get_ckr(rc));
    }

    return rc;
}


/* This function should test:
 * C_Sign, mechanism chosen by caller
 *
 * 1. Get message from test vector
 * 2. Get expected signature from test vector
 * 3. Sign message
 * 4. Compare expected signature with actual signature
 *
 */
CK_RV do_SignRSA(struct PUBLISHED_TEST_SUITE_INFO * tsuite)
{
    int i;
    CK_BYTE message[MAX_MESSAGE_SIZE];
    CK_BYTE actual[MAX_SIGNATURE_SIZE];
    CK_BYTE expected[MAX_SIGNATURE_SIZE];
    CK_ULONG message_len, actual_len, expected_len;

    CK_MECHANISM mech;
    CK_OBJECT_HANDLE priv_key;

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    // begin testsuite
    testsuite_begin("%s Sign. ", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %u",
                       (unsigned int) slot_id,
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {
        testcase_begin("%s Sign with test vector %d.", tsuite->name, i);

        rc = CKR_OK;            // set return value

        // special case for ica
        // prime1, prime2, exp1, exp2, coef
        // must be size mod_len/2 or smaller
        // skip test if prime1, or prime2, or exp1,
        // or exp2 or coef are too long
        if (is_ica_token(slot_id)) {
            // check sizes
            if ((tsuite->tv[i].prime1_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].prime2_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].exp1_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].exp2_len >
                 (tsuite->tv[i].mod_len / 2)) ||
                (tsuite->tv[i].coef_len > (tsuite->tv[i].mod_len / 2))) {
                testcase_skip("ICA Token cannot be used with "
                              "this test vector.");
                continue;
            }

        }
        // special case for EP11
        // modulus length must be multiple of 128 byte
        // skip test if modulus length has unsuported size
        if (is_ep11_token(slot_id)) {
            if ((tsuite->tv[i].mod_len % 128) != 0) {
                testcase_skip("EP11 Token cannot be used with "
                              "this test vector.");
                continue;
            }
        }

        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len))) {
                testcase_skip("TPM Token cannot "
                              "be used with this test vector.");
                continue;
            }
        }
        // clear buffers
        memset(message, 0, MAX_MESSAGE_SIZE);
        memset(actual, 0, MAX_SIGNATURE_SIZE);
        memset(expected, 0, MAX_SIGNATURE_SIZE);

        actual_len = MAX_SIGNATURE_SIZE;        // set buffer size

        // get message
        message_len = tsuite->tv[i].msg_len;
        memcpy(message, tsuite->tv[i].msg, message_len);

        // get (expected) signature
        expected_len = tsuite->tv[i].sig_len;
        memcpy(expected, tsuite->tv[i].sig, expected_len);

        // create (private) key handle
        rc = create_RSAPrivateKey(session,
                                  tsuite->tv[i].mod,
                                  tsuite->tv[i].pub_exp,
                                  tsuite->tv[i].priv_exp,
                                  tsuite->tv[i].prime1,
                                  tsuite->tv[i].prime2,
                                  tsuite->tv[i].exp1,
                                  tsuite->tv[i].exp2,
                                  tsuite->tv[i].coef,
                                  tsuite->tv[i].mod_len,
                                  tsuite->tv[i].pubexp_len,
                                  tsuite->tv[i].privexp_len,
                                  tsuite->tv[i].prime1_len,
                                  tsuite->tv[i].prime2_len,
                                  tsuite->tv[i].exp1_len,
                                  tsuite->tv[i].exp2_len,
                                  tsuite->tv[i].coef_len, &priv_key);
        if (rc != CKR_OK) {
            testcase_error("create_RSAPrivateKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // set mechanism
        mech = tsuite->mech;

        // initialize signing
        rc = funcs->C_SignInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_SignInit(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }
        // do signing
        rc = funcs->C_Sign(session, message, message_len, actual, &actual_len);

        if (rc != CKR_OK) {
            testcase_error("C_Sign(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }
        // check results
        testcase_new_assertion();

        if (actual_len != expected_len) {
            testcase_fail("%s Sign with test vector %d failed. "
                          "Expected len=%ld, found len=%ld.",
                          tsuite->name, i, expected_len, actual_len);
        } else if (memcmp(actual, expected, expected_len)) {
            testcase_fail("%s Sign with test vector %d failed. "
                          "Signature data does not match test vector "
                          "signature.", tsuite->name, i);

        } else {
            testcase_pass("C_Sign.");
        }

        // clean up
        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
    goto testcase_cleanup;
error:
    loc_rc = funcs->C_DestroyObject(session, priv_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject, rc=%s.", p11_get_ckr(loc_rc));
    }
testcase_cleanup:
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions, rc=%s.", p11_get_ckr(rc));
    }

    return rc;
}

/* This function should test:
 * C_Verify, mechanism chosen by caller
 *
 * 1. Get message from test vector
 * 2. Get signature from test vector
 * 3. Verify signature
 *
 */
CK_RV do_VerifyRSA(struct PUBLISHED_TEST_SUITE_INFO * tsuite)
{
    int i;
    CK_BYTE actual[MAX_SIGNATURE_SIZE];
    CK_BYTE message[MAX_MESSAGE_SIZE];
    CK_ULONG message_len;
    CK_BYTE signature[MAX_SIGNATURE_SIZE];
    CK_ULONG signature_len;

    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key;

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    // begin testsuite
    testsuite_begin("%s Verify.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %u",
                       (unsigned int) slot_id,
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        testcase_begin("%s Verify with test vector %d.", tsuite->name, i);

        rc = CKR_OK;            // set return value

        // special case for EP11
        // modulus length must be multiple of 128 byte
        // skip test if modulus length has unsuported size
        if (is_ep11_token(slot_id)) {
            if ((tsuite->tv[i].mod_len % 128) != 0) {
                testcase_skip("EP11 Token cannot be used with "
                              "this test vector.");
                continue;
            }
        }

        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len))) {
                testcase_skip("TPM Token cannot "
                              "be used with this test vector.");
                continue;
            }
        }
        // clear buffers
        memset(message, 0, MAX_MESSAGE_SIZE);
        memset(signature, 0, MAX_SIGNATURE_SIZE);
        memset(actual, 0, MAX_SIGNATURE_SIZE);

        // get message
        message_len = tsuite->tv[i].msg_len;
        memcpy(message, tsuite->tv[i].msg, message_len);

        // get signature
        signature_len = tsuite->tv[i].sig_len;
        memcpy(signature, tsuite->tv[i].sig, signature_len);

        // create (public) key handle
        rc = create_RSAPublicKey(session,
                                 tsuite->tv[i].mod,
                                 tsuite->tv[i].pub_exp,
                                 tsuite->tv[i].mod_len,
                                 tsuite->tv[i].pubexp_len, &publ_key);

        if (rc != CKR_OK) {
            testcase_error("create_RSAPublicKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // set mechanism
        mech = tsuite->mech;

        // initialize verify
        rc = funcs->C_VerifyInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyInit(), rc=%s", p11_get_ckr(rc));
            goto error;
        }
        // do verify
        rc = funcs->C_Verify(session,
                             message, message_len, signature, signature_len);

        // check result
        testcase_new_assertion();

        if (rc == CKR_OK) {
            testcase_pass("C_Verify.");
        } else {
            testcase_fail("%s Sign Verify with test vector %d "
                          "failed.", tsuite->name, i);
        }

        // clean up
        rc = funcs->C_DestroyObject(session, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

    }
    goto testcase_cleanup;
error:
    loc_rc = funcs->C_DestroyObject(session, publ_key);
    if (loc_rc != CKR_OK) {
        testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

CK_RV rsa_funcs()
{
    int i;
    CK_RV rv = CKR_OK;

    // published (known answer) tests
    for (i = 0; i < NUM_OF_PUBLISHED_TESTSUITES; i++) {
        rv = do_SignRSA(&published_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_VerifyRSA(&published_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // generated sign verify tests
    for (i = 0; i < NUM_OF_GENERATED_SIGVER_TESTSUITES; i++) {
        rv = do_SignVerifyRSA(&generated_sigver_test_suites[i], FALSE);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // generated sign verify tests for recover mode
    for (i = 0; i < NUM_OF_GENERATED_SIGVER_TESTSUITES; i++) {
        rv = do_SignVerifyRSA(&generated_sigver_test_suites[i], TRUE);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    for (i = 0; i < NUM_OF_GENERATED_PSS_TESTSUITES; i++) {
        rv = do_SignVerify_RSAPSS(&generated_pss_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // generated crypto tests
    for (i = 0; i < NUM_OF_GENERATED_CRYPTO_TESTSUITES; i++) {
        rv = do_EncryptDecryptRSA(&generated_crypto_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    for (i = 0; i < NUM_OF_GENERATED_OAEP_TESTSUITES; i++) {
        rv = do_EncryptDecryptRSA(&generated_oaep_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    for (i = 0; i < NUM_OF_GENERATED_OAEP_TESTSUITES; i++) {
        rv = do_WrapUnwrapRSA(&generated_oaep_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // generated keywrap tests
    for (i = 0; i < NUM_OF_GENERATED_KEYWRAP_TESTSUITES; i++) {
        rv = do_WrapUnwrapRSA(&generated_keywrap_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    return rv;
}

int main(int argc, char **argv)
{
    int rc;
    CK_C_INITIALIZE_ARGS cinit_args;
    CK_RV rv;

    rc = do_ParseArgs(argc, argv);
    if (rc != 1) {
        return rc;
    }

    printf("Using slot #%lu...\n\n", SLOT_ID);
    printf("With option: no_stop: %d\n", no_stop);

    rc = do_GetFunctionList();
    if (!rc) {
        PRINT_ERR("ERROR do_GetFunctionList() Failed, rx = 0x%0x\n", rc);
        return rc;
    }

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    funcs->C_Initialize(&cinit_args);
    {
        CK_SESSION_HANDLE hsess = 0;
        rc = funcs->C_GetFunctionStatus(hsess);
        if (rc != CKR_FUNCTION_NOT_PARALLEL) {
            return rc;
        }

        rc = funcs->C_CancelFunction(hsess);
        if (rc != CKR_FUNCTION_NOT_PARALLEL) {
            return rc;
        }
    }

    testcase_setup(0);
    rv = rsa_funcs();
    testcase_print_result();

    funcs->C_Finalize(NULL);

    return rv;
}
