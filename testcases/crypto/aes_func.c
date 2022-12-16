/*
 * COPYRIGHT (c) International Business Machines Corp. 2006-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "aes.h"
#include "common.c"
#include "mechtable.h"
#include "mech_to_str.h"

CK_ULONG key_lens[] = { 16, 24, 32 };

/* aes-ctr has 3encck+3decck+3encsk+3decsk+3keywrap+1RSA
 * aes-ecb has 3encck+3decck+3encsk+3decsk+3keywrap+1RSA
 * aec-cbc has 3encck+3decck+3encsk+3decsk+3keywrap+3encpad+3decpad+
 * 	       3keywrappad+2RSA
 * Note: securekey and clearkey both have 3enc and 3dec, so number
 * of assertions is the same whether using clearkey or securekey.
 */

CK_RV do_EncryptDecryptAES(struct generated_test_suite_info *tsuite)
{
    int i;
    CK_BYTE original[BIG_REQUEST];
    CK_BYTE crypt[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE decrypt[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG j;
    CK_ULONG user_pin_len;
    CK_ULONG orig_len, crypt_len, decrypt_len;

    CK_SESSION_HANDLE session;
    CK_MECHANISM mechkey, mech;
    CK_OBJECT_HANDLE h_key;
    CK_FLAGS flags;
    CK_RV rc = CKR_OK;
    CK_SLOT_ID slot_id = SLOT_ID;

    testsuite_begin("%s Encryption/Decryption.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(3, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip tests if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(3,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    /* Skip tests if pkey = false, but the slot doesn't support CKM_AES_XTS */
    if (is_ep11_token(slot_id) && tsuite->mech.mechanism == CKM_AES_XTS && pkey == FALSE) {
        testcase_skip("Slot supports AES-XTS only for protected keys.\n");
        goto testcase_cleanup;
    }

    /** iterate over test key sizes **/
    for (i = 0; i < 3; i++) {
        if (tsuite->mech.mechanism == CKM_AES_XTS && key_lens[i] == 24)
            continue;

        testcase_begin("%s Encryption/Decryption with key len=%lu and pkey=%X.",
                       tsuite->name, key_lens[i], pkey);

        /** set crypto mech **/
        mech = tsuite->mech;

        /** generate key **/
        mechkey = mech.mechanism == CKM_AES_XTS ? aes_xts_keygen : aes_keygen;
        rc = generate_AESKey(session,
                             mech.mechanism == CKM_AES_XTS ? key_lens[i] * 2 :
                                                             key_lens[i],
                             !pkey, &mechkey, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key generation is not allowed by policy");
                continue;
            }

            testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** clear buffers **/
        memset(original, 0, sizeof(original));
        memset(crypt, 0, sizeof(crypt));
        memset(decrypt, 0, sizeof(decrypt));

        /** generate data **/
        orig_len = sizeof(original);

        for (j = 0; j < orig_len; j++)
            original[j] = j % 255;

        /** single encryption **/
        rc = funcs->C_EncryptInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        crypt_len = sizeof(crypt);

        rc = funcs->C_Encrypt(session, original, orig_len, crypt, &crypt_len);

        if (rc != CKR_OK) {
            testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** single decryption **/
        rc = funcs->C_DecryptInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        decrypt_len = sizeof(decrypt);

        rc = funcs->C_Decrypt(session, crypt, crypt_len, decrypt, &decrypt_len);

        if (rc != CKR_OK) {
            testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** compare actual results with expected results **/
        testcase_new_assertion();

        if (decrypt_len != orig_len) {
            testcase_fail("decrypted data length does not "
                          "match original data length.\nexpected "
                          "length=%lu, but found length=%lu\n",
                          orig_len, decrypt_len);
        } else if (memcmp(decrypt, original, orig_len)) {
            testcase_fail("decrypted data does not match " "original data");
        } else {
            testcase_pass("%s Encryption/Decryption with "
                          "key length %lu passed.", tsuite->name, key_lens[i]);
        }

        /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
    goto testcase_cleanup;

error:
    rc = funcs->C_DestroyObject(session, h_key);
    if (rc != CKR_OK)
        testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

CK_RV do_EncryptDecryptUpdateAES(struct generated_test_suite_info * tsuite)
{
    int i;
    CK_BYTE original[BIG_REQUEST];
    CK_BYTE crypt[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE decrypt[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG j, k, tmp;
    CK_ULONG user_pin_len;
    CK_ULONG orig_len, crypt_len, decrypt_len;

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_MECHANISM mechkey, mech;
    CK_OBJECT_HANDLE h_key;
    CK_FLAGS flags;
    CK_RV rc = CKR_OK;

    /** begin testsuite **/
    testsuite_begin("%s Multipart Encryption/Decryption.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(3, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip test if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int) slot_id,
                      mech_to_str(tsuite->mech.mechanism),
                      (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    /* Skip tests if pkey = false, but the slot doesn't support CKM_AES_XTS */
    if (is_ep11_token(slot_id) && tsuite->mech.mechanism == CKM_AES_XTS && pkey == FALSE) {
        testcase_skip("Slot supports AES-XTS only for protected keys.\n");
        goto testcase_cleanup;
    }

    /** iterate over key sizes **/
    for (i = 0; i < 3; i++) {
        if (tsuite->mech.mechanism == CKM_AES_XTS && key_lens[i] == 24)
            continue;

        testcase_begin("%s Multipart Encryption/Decryption with "
                       "key len=%lu and pkey=%X.", tsuite->name, key_lens[i], pkey);

        /** set crypto mech **/
        mech = tsuite->mech;

        /** generate key **/
        mechkey = mech.mechanism == CKM_AES_XTS ? aes_xts_keygen : aes_keygen;
        rc = generate_AESKey(session,
                             mech.mechanism == CKM_AES_XTS ? key_lens[i] * 2 :
                                                                 key_lens[i],
                             !pkey, &mechkey, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key generation is not allowed by policy");
                continue;
            }

            testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** clear buffers **/
        memset(original, 0, sizeof(original));
        memset(crypt, 0, sizeof(crypt));
        memset(decrypt, 0, sizeof(decrypt));

        /** generate data **/
        orig_len = sizeof(original);

        for (j = 0; j < orig_len; j++)
            original[j] = j % 255;

        /** multipart encryption **/
        rc = funcs->C_EncryptInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /* Encrypt in place except for CBC_PAD or XTS, since it
         * pads and pkcs padding can make it unclear about what is
         * output at what stage. (See pkcs11v2.20 Section 11.2)
         */
        if (mech.mechanism != CKM_AES_CBC_PAD &&
            mech.mechanism != CKM_AES_XTS) {

            memcpy(crypt, original, orig_len);
            crypt_len = orig_len;
            k = 0;
            while (k < orig_len) {
                rc = funcs->C_EncryptUpdate(session,
                                            &crypt[k],
                                            AES_BLOCK_SIZE,
                                            &crypt[k], &crypt_len);
                if (rc != CKR_OK) {
                    testcase_error("C_EncryptUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }

                k += crypt_len; // encrypted amount
                crypt_len = orig_len - k;       // space in out buf

            }
        } else {

            j = k = 0;          // j indexes source buffer
            // k indexes destination buffer
            crypt_len = sizeof(crypt);

            while (j < orig_len) {
                tmp = crypt_len - k;    // room left
                rc = funcs->C_EncryptUpdate(session,
                                            &original[j],
                                            AES_BLOCK_SIZE, &crypt[k], &tmp);
                if (rc != CKR_OK) {
                    testcase_error("C_EncryptUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }

                k += tmp;
                j += AES_BLOCK_SIZE;
            }

            crypt_len = sizeof(crypt) - k;
        }

        rc = funcs->C_EncryptFinal(session, &crypt[k], &crypt_len);
        if (rc != CKR_OK) {
            testcase_error("C_EncryptFinal rc=%s", p11_get_ckr(rc));
            goto error;
        }

        crypt_len += k;

        /** multipart decryption **/
        rc = funcs->C_DecryptInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /* decrypt in place.  skip for AES_CBC_PAD or XTS since it
         * pads and pkcs padding can make it unclear about what is
         * output at what stage. (See pkcs11v2.20 Section 11.2)
         */
        if (mech.mechanism != CKM_AES_CBC_PAD &&
            mech.mechanism != CKM_AES_XTS) {

            memcpy(decrypt, crypt, crypt_len);
            k = 0;
            decrypt_len = crypt_len;
            while (k < crypt_len) {
                rc = funcs->C_DecryptUpdate(session,
                                            &decrypt[k],
                                            AES_BLOCK_SIZE,
                                            &decrypt[k], &decrypt_len);
                if (rc != CKR_OK) {
                    testcase_error("C_DecryptUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }

                k += decrypt_len;       // decrypted amount
                decrypt_len = crypt_len - k;    // space in out buf
            }
        } else {

            j = k = 0;          // j indexes source buffer,
            // k indexes destination buffer
            decrypt_len = sizeof(decrypt);
            while (j < crypt_len) {
                tmp = decrypt_len - k;  // room left in outbuf
                rc = funcs->C_DecryptUpdate(session,
                                            &crypt[j],
                                            AES_BLOCK_SIZE, &decrypt[k], &tmp);
                if (rc != CKR_OK) {
                    testcase_error("C_DecryptUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }
                k += tmp;
                j += AES_BLOCK_SIZE;
            }

            decrypt_len = sizeof(decrypt) - k;
        }

        rc = funcs->C_DecryptFinal(session, &decrypt[k], &decrypt_len);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptFinal rc=%s", p11_get_ckr(rc));
            goto error;
        }

        decrypt_len += k;

        /** compare actual results with expected results **/
        testcase_new_assertion();

        if (decrypt_len != orig_len) {
            testcase_fail("decrypted multipart data length does not"
                          " match original data length.\nexpected "
                          "length=%lu, but found length=%lu\n",
                          orig_len, decrypt_len);
        } else if (memcmp(decrypt, original, orig_len)) {
            testcase_fail("decrypted multipart data does not match"
                          " original data");
        } else {
            testcase_pass("%s Multipart Encryption/Decryption with"
                          " key length %lu passed.", tsuite->name, key_lens[i]);
        }

        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
    goto testcase_cleanup;

error:
    rc = funcs->C_DestroyObject(session, h_key);
    if (rc != CKR_OK)
        testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

CK_RV alloc_gcm_param(CK_GCM_PARAMS *gcm_param, CK_BYTE *pIV, CK_ULONG ulIVLen,
                      CK_BYTE *pAAD, CK_ULONG ulAADLen)
{
    gcm_param->pIv = malloc(ulIVLen);
    if (gcm_param->pIv == NULL)
        return CKR_HOST_MEMORY;
    gcm_param->ulIvLen = ulIVLen;
    memcpy(gcm_param->pIv, pIV, ulIVLen);
    gcm_param->ulIvBits = ulIVLen * 8;

    gcm_param->pAAD = malloc(ulAADLen);
    if (gcm_param->pAAD == NULL) {
        free(gcm_param->pIv);
        gcm_param->pIv = NULL;
        return CKR_HOST_MEMORY;
    }
    gcm_param->ulAADLen = ulAADLen;
    memcpy(gcm_param->pAAD, pAAD, ulAADLen);

    return CKR_OK;
}

void free_gcm_param(CK_GCM_PARAMS *gcm_param)
{
    if (gcm_param == NULL)
        return;

    if (gcm_param->pIv != NULL) {
        memset(gcm_param->pIv, 0, gcm_param->ulIvLen);
        free(gcm_param->pIv);
    }
    gcm_param->pIv = NULL;
    gcm_param->ulIvLen = 0;

    if (gcm_param->pAAD != NULL) {
        memset(gcm_param->pAAD, 0, gcm_param->ulAADLen);
        free(gcm_param->pAAD);
    }

    gcm_param->pAAD = NULL;
    gcm_param->ulAADLen = 0;
}

CK_RV do_EncryptAES(struct published_test_suite_info * tsuite)
{
    unsigned int i;
    CK_BYTE input[BIG_REQUEST]; // cleartext buffer
    CK_BYTE output[BIG_REQUEST];        // encryption buffer
    CK_BYTE expected[BIG_REQUEST];      // encrypted data
    CK_ULONG input_len, output_len, expected_len;
    CK_ULONG user_pin_len;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech = { .mechanism = 0, .pParameter = NULL, .ulParameterLen =  0 };
    CK_OBJECT_HANDLE h_key;
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_GCM_PARAMS *gcm_param;

    /** begin testsuite **/
    testsuite_begin("%s Encryption.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(tsuite->tvcount, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip test if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    /* Skip tests if pkey = false, but the slot doesn't support CKM_AES_XTS */
    if (is_ep11_token(slot_id) && tsuite->mech.mechanism == CKM_AES_XTS && pkey == FALSE) {
        testcase_skip("Slot supports AES-XTS only for protected keys.\n");
        goto testcase_cleanup;
    }

    for (i = 0; i < tsuite->tvcount; i++) {

        testcase_begin("%s Encryption with published test vector %u and pkey=%X.",
                       tsuite->name, i, pkey);

        /** get mech **/
        mech = tsuite->mech;

        /** create key handle **/
        rc = create_AESKey(session, !pkey,
                           tsuite->tv[i].key, tsuite->tv[i].klen,
                           mech.mechanism == CKM_AES_XTS ? CKK_AES_XTS :
                                                                   CKK_AES,
                           &h_key);

        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key import is not allowed by policy");
                continue;
            }

            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
            goto error;
        }

        if (mech.mechanism == CKM_AES_GCM) {
            gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
            gcm_param->ulTagBits = tsuite->tv[i].taglen;
            rc = alloc_gcm_param(gcm_param,
                                 (CK_BYTE *)tsuite->tv[i].iv,
                                 tsuite->tv[i].ivlen,
                                 (CK_BYTE *) tsuite->tv[i].aad,
                                 tsuite->tv[i].aadlen);
            if (rc != CKR_OK) {
                testcase_error("alloc_gcm_param rc=%s", p11_get_ckr(rc));
                goto error;
            }
        } else if (mech.mechanism == CKM_AES_XTS) {
            mech.pParameter = tsuite->tv[i].iv;
            mech.ulParameterLen = tsuite->tv[i].ivlen;
        }

        /** clear buffers **/
        memset(expected, 0, sizeof(expected));
        memset(input, 0, sizeof(input));
        memset(output, 0, sizeof(output));

        /** get ciphertext (expected results) **/
        expected_len = tsuite->tv[i].clen;
        memcpy(expected, tsuite->tv[i].ciphertext, expected_len);

        /** get plaintext **/
        input_len = tsuite->tv[i].plen;
        memcpy(input, tsuite->tv[i].plaintext, input_len);

        /** single (in-place) encryption **/
        rc = funcs->C_EncryptInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        if (mech.mechanism == CKM_AES_GCM) {
            /*
             * Zeroise and free the GCM parameters now to test that
             * Update/Final does not require access to the GCM parameters
             * anymore
             */
            gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
            free_gcm_param(gcm_param);
        }

        rc = funcs->C_Encrypt(session, input, input_len, NULL, &output_len);
        if (rc != CKR_OK) {
            testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
            goto error;
        }

        rc = funcs->C_Encrypt(session, input, input_len, output, &output_len);

        if (rc != CKR_OK) {
            testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** compare actual results with expected results. **/
        testcase_new_assertion();

        if (output_len != expected_len) {
            testcase_fail("encrypted data length does not match "
                          "test vector's encrypted data length.\n\n"
                          "expected length=%lu, but found length=%lu\n",
                          expected_len, output_len);
        } else if (memcmp(output, expected, expected_len)) {
            testcase_fail("encrypted data does not match test "
                          "vector's encrypted data");
        } else {
            testcase_pass("%s Encryption with test vector %u "
                          "passed.", tsuite->name, i);
        }

        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
    goto testcase_cleanup;

error:
    if (mech.mechanism == CKM_AES_GCM) {
        gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
        free_gcm_param(gcm_param);
    }

    rc = funcs->C_DestroyObject(session, h_key);
    if (rc != CKR_OK)
        testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

CK_RV do_EncryptUpdateAES(struct published_test_suite_info * tsuite)
{
    unsigned int i;
    CK_BYTE plaintext[BIG_REQUEST];
    CK_BYTE expected[BIG_REQUEST];      // encrypted data
    CK_BYTE crypt[BIG_REQUEST];
    CK_ULONG expected_len, p_len, crypt_len, k;
    CK_ULONG user_pin_len;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech = { .mechanism = 0, .pParameter = NULL, .ulParameterLen =  0 };
    CK_OBJECT_HANDLE h_key;
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_GCM_PARAMS *gcm_param;

    testsuite_begin("%s Multipart Encryption.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(tsuite->tvcount, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip test if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    /* Skip tests if pkey = false, but the slot doesn't support CKM_AES_XTS */
    if (is_ep11_token(slot_id) && tsuite->mech.mechanism == CKM_AES_XTS && pkey == FALSE) {
        testcase_skip("Slot supports AES-XTS only for protected keys.\n");
        goto testcase_cleanup;
    }

    for (i = 0; i < tsuite->tvcount; i++) {

        testcase_begin("%s Multipart Encryption with published test "
                       "vector %u and pkey=%X.", tsuite->name, i, pkey);

        /** get mech **/
        mech = tsuite->mech;

        /** create key handle **/
        rc = create_AESKey(session, !pkey,
                           tsuite->tv[i].key, tsuite->tv[i].klen,
                           mech.mechanism == CKM_AES_XTS ? CKK_AES_XTS :
                                                                     CKK_AES,
                           &h_key);

        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key import is not allowed by policy");
                continue;
            }

            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
            goto error;
        }

        if (mech.mechanism == CKM_AES_GCM) {
            gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
            gcm_param->ulTagBits = tsuite->tv[i].taglen;
            rc = alloc_gcm_param(gcm_param,
                                 (CK_BYTE *)tsuite->tv[i].iv,
                                 tsuite->tv[i].ivlen,
                                 (CK_BYTE *) tsuite->tv[i].aad,
                                 tsuite->tv[i].aadlen);
            if (rc != CKR_OK) {
                testcase_error("alloc_gcm_param rc=%s", p11_get_ckr(rc));
                goto error;
            }
        } else if (mech.mechanism == CKM_AES_XTS) {
            mech.pParameter = tsuite->tv[i].iv;
            mech.ulParameterLen = tsuite->tv[i].ivlen;
        }

        /** clear buffers **/
        memset(expected, 0, sizeof(expected));
        memset(plaintext, 0, sizeof(plaintext));
        memset(crypt, 0, sizeof(crypt));

        /** get ciphertext (expected results) **/
        expected_len = tsuite->tv[i].clen;
        memcpy(expected, tsuite->tv[i].ciphertext, expected_len);

        /** get plaintext **/
        p_len = tsuite->tv[i].plen;
        memcpy(plaintext, tsuite->tv[i].plaintext, p_len);

        /** multipart encryption **/
        rc = funcs->C_EncryptInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        if (mech.mechanism == CKM_AES_GCM) {
            /*
             * Zeroise and free the GCM parameters now to test that
             * Update/Final does not require access to the GCM parameters
             * anymore
             */
            gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
            free_gcm_param(gcm_param);
        }

        /* for chunks, -1 is NULL, and 0 is empty string,
         * and a value > 0 is amount of data from test vector's
         * plaintext data. This way we test vary-sized chunks.
         */
        if (tsuite->tv[i].num_chunks_plain) {
            int j;
            CK_ULONG outlen, len;
            CK_BYTE *data_chunk = NULL;

            k = 0;
            crypt_len = 0;
            outlen = sizeof(crypt);

            for (j = 0; j < tsuite->tv[i].num_chunks_plain; j++) {
                if (tsuite->tv[i].chunks_plain[j] == -1) {
                    len = 0;
                    data_chunk = NULL;
                } else if (tsuite->tv[i].chunks_plain[j] == 0) {
                    len = 0;
                    data_chunk = (CK_BYTE *) "";
                } else {
                    len = tsuite->tv[i].chunks_plain[j];
                    data_chunk = plaintext + k;
                }

                rc = funcs->C_EncryptUpdate(session, data_chunk,
                                            len, &crypt[crypt_len], &outlen);
                if (rc != CKR_OK) {
                    testcase_error("C_EncryptUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }
                k += len;
                crypt_len += outlen;
                outlen = sizeof(crypt) - crypt_len;
            }
        } else {
            crypt_len = sizeof(crypt);
            rc = funcs->C_EncryptUpdate(session, plaintext, p_len,
                                        crypt, &crypt_len);
            if (rc != CKR_OK) {
                testcase_error("C_EncryptUpdate rc=%s", p11_get_ckr(rc));
                goto error;
            }
        }

        k = sizeof(crypt) - crypt_len;
        rc = funcs->C_EncryptFinal(session, &crypt[crypt_len], &k);
        if (rc != CKR_OK) {
            testcase_error("C_EncryptFinal rc=%s", p11_get_ckr(rc));
            goto error;
        }

        crypt_len += k;

        /** compare encryption results with expected results. **/
        testcase_new_assertion();

        if (crypt_len != expected_len) {
            testcase_fail("encrypted multipart data length does "
                          "not match test vector's encrypted data length."
                          "\n\nexpected length=%lu, but found length=%lu"
                          "\n", expected_len, crypt_len);
        } else if (memcmp(crypt, expected, expected_len)) {
            testcase_fail("encrypted multipart data does not match"
                          " test vector's encrypted data.\n");
        } else {
            testcase_pass("%s Multipart Encryption with test "
                          "vector %u passed.", tsuite->name, i);
        }

        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
    goto testcase_cleanup;

error:
    if (mech.mechanism == CKM_AES_GCM) {
        gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
        free_gcm_param(gcm_param);
    }

    rc = funcs->C_DestroyObject(session, h_key);
    if (rc != CKR_OK)
        testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

CK_RV do_DecryptAES(struct published_test_suite_info * tsuite)
{
    unsigned int i;
    CK_BYTE input[BIG_REQUEST]; // encrypted buffer
    CK_BYTE output[BIG_REQUEST];        // decryption buffer
    CK_BYTE expected[BIG_REQUEST];      // decrypted data
    CK_ULONG input_len, output_len, expected_len;
    CK_ULONG user_pin_len;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech = { .mechanism = 0, .pParameter = NULL, .ulParameterLen =  0 };
    CK_OBJECT_HANDLE h_key;
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_GCM_PARAMS *gcm_param;

    testsuite_begin("%s Decryption.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(tsuite->tvcount, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip test if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    /* Skip tests if pkey = false, but the slot doesn't support CKM_AES_XTS */
    if (is_ep11_token(slot_id) && tsuite->mech.mechanism == CKM_AES_XTS && pkey == FALSE) {
        testcase_skip("Slot supports AES-XTS only for protected keys.\n");
        goto testcase_cleanup;
    }

    for (i = 0; i < tsuite->tvcount; i++) {

        testcase_begin("%s Decryption with published test vector %u and pkey=%X.",
                       tsuite->name, i, pkey);

        /** get mech **/
        mech = tsuite->mech;

        /** create key handle **/
        rc = create_AESKey(session, !pkey,
                           tsuite->tv[i].key, tsuite->tv[i].klen,
                           mech.mechanism == CKM_AES_XTS ? CKK_AES_XTS :
                                                                   CKK_AES,
                           &h_key);

        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key import is not allowed by policy");
                continue;
            }

            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
            goto error;
        }
               
	if (mech.mechanism == CKM_AES_GCM) {
            gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
            gcm_param->ulTagBits = tsuite->tv[i].taglen;
            rc = alloc_gcm_param(gcm_param,
                                 (CK_BYTE *)tsuite->tv[i].iv,
                                 tsuite->tv[i].ivlen,
                                 (CK_BYTE *) tsuite->tv[i].aad,
                                 tsuite->tv[i].aadlen);
            if (rc != CKR_OK) {
                testcase_error("alloc_gcm_param rc=%s", p11_get_ckr(rc));
                goto error;
            }
        } else if (mech.mechanism == CKM_AES_XTS) {
            mech.pParameter = tsuite->tv[i].iv;
            mech.ulParameterLen = tsuite->tv[i].ivlen;
        }

        /** clear buffers **/
        memset(expected, 0, sizeof(expected));
        memset(input, 0, sizeof(input));
        memset(output, 0, sizeof(output));

        /** get plaintext (expected results) **/
        expected_len = tsuite->tv[i].plen;
        memcpy(expected, tsuite->tv[i].plaintext, expected_len);

        /** get ciphertext **/
        input_len = tsuite->tv[i].clen;
        memcpy(input, tsuite->tv[i].ciphertext, input_len);

        /** single (in-place) decryption **/
        rc = funcs->C_DecryptInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        if (mech.mechanism == CKM_AES_GCM) {
            /*
             * Zeroise and free the GCM parameters now to test that
             * Update/Final does not require access to the GCM parameters
             * anymore
             */
            gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
            free_gcm_param(gcm_param);
        }

        rc = funcs->C_Decrypt(session, input, input_len, NULL, &output_len);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
            goto error;
        }

        rc = funcs->C_Decrypt(session, input, input_len, output, &output_len);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** compare actual results with expected results. **/
        testcase_new_assertion();

        if (output_len != expected_len) {
            testcase_fail("decrypted data length does not match "
                          "test vector's decrypted data length.\n\n"
                          "expected length=%lu, but found length=%lu\n",
                          expected_len, output_len);
        } else if (memcmp(output, expected, expected_len)) {
            testcase_fail("decrypted data does not match test "
                          "vector's decrypted data");
        } else {
            testcase_pass("%s Decryption with test vector %u "
                          "passed.", tsuite->name, i);
        }

                /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
    goto testcase_cleanup;

error:
    if (mech.mechanism == CKM_AES_GCM) {
        gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
        free_gcm_param(gcm_param);
    }

    rc = funcs->C_DestroyObject(session, h_key);
    if (rc != CKR_OK)
        testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK)
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));

    return rc;
}

CK_RV do_DecryptUpdateAES(struct published_test_suite_info * tsuite)
{
    unsigned int i;
    CK_BYTE cipher[BIG_REQUEST];
    CK_BYTE expected[BIG_REQUEST];      // decrypted data
    CK_BYTE plaintext[BIG_REQUEST];
    CK_ULONG cipher_len, expected_len, p_len, k;
    CK_ULONG user_pin_len;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech = { .mechanism = 0, .pParameter = NULL, .ulParameterLen =  0 };
    CK_OBJECT_HANDLE h_key;
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_GCM_PARAMS *gcm_param;

    testsuite_begin("%s Multipart Decryption.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(tsuite->tvcount, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip tests if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    /* Skip tests if pkey = false, but the slot doesn't support CKM_AES_XTS */
    if (is_ep11_token(slot_id) && tsuite->mech.mechanism == CKM_AES_XTS && pkey == FALSE) {
        testcase_skip("Slot supports AES-XTS only for protected keys.\n");
        goto testcase_cleanup;
    }

    for (i = 0; i < tsuite->tvcount; i++) {

        testcase_begin("%s Multipart Decryption with published test "
                       "vector %u and pkey=%X.", tsuite->name, i, pkey);

        /** get mech **/
        mech = tsuite->mech;

        /** create key handle **/
        rc = create_AESKey(session, !pkey,
                           tsuite->tv[i].key, tsuite->tv[i].klen,
                           mech.mechanism == CKM_AES_XTS ? CKK_AES_XTS :
                                                                     CKK_AES,
                           &h_key);

        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key import is not allowed by policy");
                continue;
            }

            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** get mech **/
        mech = tsuite->mech;
        if (mech.mechanism == CKM_AES_GCM) {
            gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
            gcm_param->ulTagBits = tsuite->tv[i].taglen;
            rc = alloc_gcm_param(gcm_param,
                                 (CK_BYTE *)tsuite->tv[i].iv,
                                 tsuite->tv[i].ivlen,
                                 (CK_BYTE *) tsuite->tv[i].aad,
                                 tsuite->tv[i].aadlen);
            if (rc != CKR_OK) {
                testcase_error("alloc_gcm_param rc=%s", p11_get_ckr(rc));
                goto error;
            }
        } else if (mech.mechanism == CKM_AES_XTS) {
            mech.pParameter = tsuite->tv[i].iv;
            mech.ulParameterLen = tsuite->tv[i].ivlen;
        }

        /** clear buffers **/
        memset(expected, 0, sizeof(expected));
        memset(cipher, 0, sizeof(cipher));
        memset(plaintext, 0, sizeof(plaintext));

        /** get plaintext (expected results) **/
        expected_len = tsuite->tv[i].plen;
        memcpy(expected, tsuite->tv[i].plaintext, expected_len);

        p_len = sizeof(plaintext);
        cipher_len = tsuite->tv[i].clen;
        memcpy(cipher, tsuite->tv[i].ciphertext, cipher_len);

        /** multipart (in-place) decryption **/
        rc = funcs->C_DecryptInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        if (mech.mechanism == CKM_AES_GCM) {
            /*
             * Zeroise and free the GCM parameters now to test that
             * Update/Final does not require access to the GCM parameters
             * anymore
             */
            gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
            free_gcm_param(gcm_param);
        }

        /* for chunks, -1 is NULL, and 0 is empty string,
         * and a value > 0 is amount of data from test vector's
         * plaintext data. This way we test vary-sized chunks.
         */
        if (tsuite->tv[i].num_chunks_ciph) {
            int j;
            CK_ULONG outlen, len;
            CK_BYTE *data_chunk = NULL;

            k = 0;
            p_len = 0;
            outlen = sizeof(plaintext);
            for (j = 0; j < tsuite->tv[i].num_chunks_ciph; j++) {
                if (tsuite->tv[i].chunks_ciph[j] == -1) {
                    len = 0;
                    data_chunk = NULL;
                } else if (tsuite->tv[i].chunks_ciph[j] == 0) {
                    len = 0;
                    data_chunk = (CK_BYTE *) "";
                } else {
                    len = tsuite->tv[i].chunks_ciph[j];
                    data_chunk = cipher + k;
                }

                rc = funcs->C_DecryptUpdate(session, data_chunk,
                                            len, &plaintext[p_len], &outlen);
                if (rc != CKR_OK) {
                    testcase_error("C_DecryptUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }
                k += len;
                p_len += outlen;
                outlen = sizeof(plaintext) - p_len;
            }
        } else {
            p_len = sizeof(plaintext);
            rc = funcs->C_DecryptUpdate(session, cipher, cipher_len,
                                        plaintext, &p_len);
            if (rc != CKR_OK) {
                testcase_error("C_DecryptUpdate rc=%s", p11_get_ckr(rc));
                goto error;
            }
        }

        k = sizeof(plaintext) - p_len;
        rc = funcs->C_DecryptFinal(session, &plaintext[p_len], &k);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptFinal rc=%s", p11_get_ckr(rc));
            goto error;
        }
        p_len += k;             /* add possible last part to overall length */

        /** compare decryption results with expected results. **/
        testcase_new_assertion();

        if (p_len != expected_len) {
            testcase_fail("decrypted multipart data length does "
                          "not match test vector's decrypted data "
                          "length.\n\nexpected length=%lu, but found "
                          "length=%lu\n", expected_len, p_len);
        } else if (memcmp(plaintext, expected, expected_len)) {
            testcase_fail("decrypted multipart data does not match"
                          " test vector's decrypted data.\n");
        } else {
            testcase_pass("%s Multipart Decryption with test "
                          "vector %u passed.", tsuite->name, i);
        }

        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
    goto testcase_cleanup;

error:
    if (mech.mechanism == CKM_AES_GCM) {
        gcm_param = ((CK_GCM_PARAMS *) mech.pParameter);
        free_gcm_param(gcm_param);
    }

    rc = funcs->C_DestroyObject(session, h_key);
    if (rc != CKR_OK)
        testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK)
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));

    return rc;
}

CK_RV do_WrapUnwrapAES(struct generated_test_suite_info * tsuite)
{
    unsigned int i, j;
    CK_BYTE original[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE crypt[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE decrypt[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE_PTR wrapped_data = NULL;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_SESSION_HANDLE session;
    CK_MECHANISM mechkey, mech;
    CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE w_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE uw_key = CK_INVALID_HANDLE;
    CK_ULONG wrapped_data_len = 0;
    CK_ULONG user_pin_len;
    CK_ULONG orig_len, crypt_len, decrypt_len;
    CK_ULONG tmpl_count = 2; /* Use only the first 2 attrs, except for CCA */
    CK_ULONG key_size;
    CK_FLAGS flags;
    CK_RV rc = CKR_OK;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_VALUE_LEN, &key_size, sizeof(key_size)} /* For CCA only */
    };

    testsuite_begin("%s Wrap/Unwrap.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(3, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip test if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(3,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    if (!wrap_supported(slot_id, tsuite->mech)) {
        testsuite_skip(3, "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    /* Skip tests if pkey = false, but the slot doesn't support CKM_AES_XTS */
    if (is_ep11_token(slot_id) && tsuite->mech.mechanism == CKM_AES_XTS && pkey == FALSE) {
        testcase_skip("Slot supports AES-XTS only for protected keys.\n");
        goto testcase_cleanup;
    }

    /* key sizes must be a multiple of AES block size in order to be passed
       in as data. Recall AES expects data in multiple of AES block size.
     */
    for (i = 0; i < 3; i++) {

        if (key_lens[i] % AES_BLOCK_SIZE != 0)
            continue;

        if (tsuite->mech.mechanism == CKM_AES_XTS && key_lens[i] == 24)
            continue;

        testcase_begin("%s Wrap/Unwrap key test with keylength=%lu and pkey=%X.",
                       tsuite->name, key_lens[i], pkey);

        /** set mechanisms **/
        mech = tsuite->mech;
        mechkey = mech.mechanism == CKM_AES_XTS ? aes_xts_keygen : aes_keygen;
        key_type = mech.mechanism == CKM_AES_XTS ? CKK_AES_XTS : CKK_AES;

        /** set key_size **/
        key_size = key_lens[i];

        /** clear buffers **/
        memset(original, 0, sizeof(original));
        memset(crypt, 0, sizeof(crypt));
        memset(decrypt, 0, sizeof(decrypt));

        /** generate crypto key (must be extractable) **/
        rc = generate_AESKey(session,
                             mech.mechanism == CKM_AES_XTS ? key_lens[i] * 2 :
                                                                   key_lens[i],
                             CK_TRUE, &mechkey, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key generation is not allowed by policy");
                continue;
            }

            testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** generate wrapping key **/
        rc = generate_AESKey(session,
                             mech.mechanism == CKM_AES_XTS ? key_lens[i] * 2 :
                                                           key_lens[i], !pkey,
                             &mechkey, &w_key);
        if (rc != CKR_OK) {
            testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** generate data **/
        orig_len = BIG_REQUEST;
        crypt_len = BIG_REQUEST + AES_BLOCK_SIZE;
        decrypt_len = BIG_REQUEST + AES_BLOCK_SIZE;
        for (j = 0; j < orig_len; j++) {
            original[j] = j % 255;
        }

        /** initiate the encrypt **/
        rc = funcs->C_EncryptInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** continue with encrypt **/
        rc = funcs->C_Encrypt(session, original, orig_len, crypt, &crypt_len);

        if (rc != CKR_OK) {
            testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** wrap key **/
        rc = funcs->C_WrapKey(session,
                              &mech, w_key, h_key, NULL, &wrapped_data_len);

        if (rc != CKR_OK) {
            testcase_error("C_WrapKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        wrapped_data = malloc(wrapped_data_len);
        if (wrapped_data == NULL) {
            testcase_error("malloc failed");
            goto error;
        }
        memset(wrapped_data, 0, wrapped_data_len);
        rc = funcs->C_WrapKey(session, &mech, w_key, h_key, wrapped_data,
                              &wrapped_data_len);
        if (rc != CKR_OK) {
            testcase_error("C_WrapKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        if (is_cca_token(slot_id)) {
            /*
             * CCA requires the CKA_VALUE_LEN attribute in the unwrap template,
             * although the PKCS#11 standard states that it can not be specified
             * for unwrap.
             */
            tmpl_count = 3;
        }

        /** unwrap key **/
        rc = funcs->C_UnwrapKey(session,
                                &mech,
                                w_key,
                                wrapped_data,
                                wrapped_data_len,
                                template, tmpl_count, &uw_key);

        if (rc != CKR_OK) {
            testcase_error("C_UnwrapKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        if (wrapped_data) {
            free(wrapped_data);
            wrapped_data = NULL;
        }

        /** initiate decryption (with unwrapped key) **/
        rc = funcs->C_DecryptInit(session, &mech, uw_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** do decryption (with the unwrapped key) **/
        rc = funcs->C_Decrypt(session, crypt, crypt_len, decrypt, &decrypt_len);

        if (rc != CKR_OK) {
            testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** compare actual results with expected results **/
        testcase_new_assertion();

        if (decrypt_len != orig_len) {
            testcase_fail("Decrypted length doesn't match the "
                          "original plaintext length.");
            rc = CKR_GENERAL_ERROR;
        } else if (memcmp(decrypt, original, orig_len)) {
            testcase_fail("Decrypted data does not match original "
                          "plaintext data.");
            rc = CKR_GENERAL_ERROR;
        } else {
            testcase_pass("%s Wrap/UnWrap test with key length "
                          "%u passed.", tsuite->name,
                          (unsigned int) key_lens[i]);
        }
        /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
        }
        h_key = CK_INVALID_HANDLE;

        rc = funcs->C_DestroyObject(session, w_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
        }
        w_key = CK_INVALID_HANDLE;

        rc = funcs->C_DestroyObject(session, uw_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
        }
        uw_key = CK_INVALID_HANDLE;
    }
    goto testcase_cleanup;
error:
    if (wrapped_data)
        free(wrapped_data);

    if (h_key != CK_INVALID_HANDLE) {
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
        }
    }

    if (w_key != CK_INVALID_HANDLE) {
        rc = funcs->C_DestroyObject(session, w_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
        }
    }

    if (uw_key != CK_INVALID_HANDLE) {
        rc = funcs->C_DestroyObject(session, uw_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
        }
    }
    goto testcase_cleanup;

testcase_cleanup:
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

CK_RV do_WrapUnwrapRSA(struct generated_test_suite_info * tsuite)
{
    unsigned int i;
    CK_BYTE original[BIG_REQUEST];
    CK_BYTE decipher[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE cipher[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE wrapped_data[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_BYTE pub_exp[] = { 0x01, 0x00, 0x01 };
    CK_MECHANISM mech, mech2;
    CK_MECHANISM_INFO mech_info;
    CK_OBJECT_HANDLE publ_key, priv_key, w_key, uw_key;
    CK_ULONG orig_len, cipher_len, decipher_len;
    CK_ULONG bits = 1024;
    CK_ULONG wrapped_data_len;
    CK_ULONG user_pin_len;
    CK_ULONG key_size;
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_OBJECT_CLASS keyclass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keytype = CKK_RSA;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_BBOOL extractable = !pkey;
    CK_BBOOL pkeyextractable = pkey;

    CK_ATTRIBUTE pub_tmpl[] = {
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp)},
    };
    CK_ULONG pub_tmpl_len = sizeof(pub_tmpl) / sizeof(CK_ATTRIBUTE);

    CK_ATTRIBUTE uw_tmpl[] = {
        {CKA_CLASS, &keyclass, sizeof(keyclass)},
        {CKA_KEY_TYPE, &keytype, sizeof(keytype)},
    };
    CK_ATTRIBUTE key_gen_tmpl[] = {
        {CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
        {CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG)},
        {CKA_IBM_PROTKEY_EXTRACTABLE, &pkeyextractable, sizeof(CK_BBOOL)},
    };
    CK_ULONG key_gen_tmpl_len = sizeof(key_gen_tmpl) / sizeof(CK_ATTRIBUTE);

    testsuite_begin("%s wrap/unwrap of RSA key.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(3, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip AES_EBC/AES_CBC (only supported for symmetric keys) **/
    if ((tsuite->mech.mechanism == CKM_AES_ECB) ||
        (tsuite->mech.mechanism == CKM_AES_CBC)) {
        testcase_skip
            ("Mechanism %s (%u) not supported to wrap/unwrap asymmetric Keys",
             mech_to_str(tsuite->mech.mechanism),
             (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    /** skip test if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(3,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, CKM_RSA_PKCS)) {
        testsuite_skip(3,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(CKM_RSA_PKCS),
                       (unsigned int) CKM_RSA_PKCS);
        goto testcase_cleanup;
    }

    if (!mech_supported(slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)) {
        testsuite_skip(3,
                       "Slot %u doesn't support CKM_RSA_PKCS_KEY_PAIR_GEN",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    if (!wrap_supported(slot_id, tsuite->mech)) {
        testsuite_skip(3, "Slot %u doesn't support wrapping with %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    rc = funcs->C_GetMechanismInfo(slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN, &mech_info);
    if (rc != CKR_OK) {
        testcase_error("C_GetMechanismInfo rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (bits < mech_info.ulMinKeySize)
        bits = mech_info.ulMinKeySize;

    for (i = 0; i < 3; i++) {
        if (tsuite->mech.mechanism == CKM_AES_XTS && key_lens[i] == 24)
            continue;

        testcase_begin("%s wrap/unwrap of RSA key for key length=%lu and pkey=%X.",
                       tsuite->name, key_lens[i], pkey);

        key_size = tsuite->mech.mechanism == CKM_AES_XTS ?
                                            key_lens[i] * 2 : key_lens[i];

        /** first mechanism generate AES wrapping key **/
        mech.mechanism = tsuite->mech.mechanism == CKM_AES_XTS ?
                                      CKM_AES_XTS_KEY_GEN : CKM_AES_KEY_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        /** mechanism to generate an RSA key pair to be wrapped **/
        mech2.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        mech2.ulParameterLen = 0;
        mech2.pParameter = NULL;

        /** generate an RSA key pair. **/
        rc = funcs->C_GenerateKeyPair(session, &mech2,
                                      pub_tmpl, pub_tmpl_len,
                                      NULL, 0, &publ_key, &priv_key);

        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }

            testcase_error("C_GenerateKeyPair rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** generate the wrapping key **/
        rc = funcs->C_GenerateKey(session, &mech,
                                  key_gen_tmpl, key_gen_tmpl_len,
                                  &w_key);

        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("AES key generation is not allowed by policy");
                continue;
            }

            testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** set the mech for AES crypto **/
        mech = tsuite->mech;

        /** wrap the key **/
        wrapped_data_len = sizeof(wrapped_data);

        /** get mech info **/
        rc = funcs->C_GetMechanismInfo(slot_id, mech.mechanism, &mech_info);

        if (rc != CKR_OK) {
            testcase_error("C_GetMechanismInfo rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** key is wrappable **/
        if (mech_info.flags & CKF_WRAP) {
            /** wrap key **/
            rc = funcs->C_WrapKey(session,
                                  &mech,
                                  w_key,
                                  priv_key, wrapped_data, &wrapped_data_len);

            if (rc != CKR_OK) {
                testcase_error("C_WrapKey rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            /** unwrap key **/
            rc = funcs->C_UnwrapKey(session,
                                    &mech,
                                    w_key,
                                    wrapped_data,
                                    wrapped_data_len, uw_tmpl, 2, &uw_key);

            if (rc != CKR_OK) {
                testcase_error("C_UnWrapKey rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            /** generate data **/
            orig_len = 30;
            for (i = 0; i < orig_len; i++)
                original[i] = i % 255;

            /** set mech2 for RSA crypto **/
            mech2.mechanism = CKM_RSA_PKCS;
            mech2.ulParameterLen = 0;
            mech2.pParameter = NULL;

            /** initialize RSA encryption (with public key) **/
            rc = funcs->C_EncryptInit(session, &mech2, publ_key);
            if (rc != CKR_OK) {
                testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            cipher_len = sizeof(cipher);        // set cipher buffer size

            /** do RSA encryption (with public key) **/
            rc = funcs->C_Encrypt(session,
                                  original, orig_len, cipher, &cipher_len);

            if (rc != CKR_OK) {
                testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            /** initialize RSA decryption
				(with unwrapped private key) **/
            rc = funcs->C_DecryptInit(session, &mech2, uw_key);
            if (rc != CKR_OK) {
                testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            decipher_len = sizeof(decipher);

            /** do RSA decryption (with unwrapped private key) **/
            rc = funcs->C_Decrypt(session,
                                  cipher, cipher_len, decipher, &decipher_len);

            if (rc != CKR_OK) {
                testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            /** compare actual results with expected results **/
            testcase_new_assertion();
            if (orig_len != decipher_len) {
                testcase_fail("lengths don't match: "
                              "%lu vs %lu\n", orig_len, decipher_len);
                rc = CKR_GENERAL_ERROR;
            } else if (memcmp(original, decipher, orig_len)) {
                testcase_fail("deciphered data does not match"
                              " original data");
                rc = CKR_GENERAL_ERROR;
            } else {
                testcase_pass("%s passed wrap/unwrap RSA key "
                              "test.", tsuite->name);
            }


        } else { /** key is not wrappable **/
            testcase_new_assertion();

            /** try to wrap key **/
            rc = funcs->C_WrapKey(session,
                                  &mech,
                                  w_key,
                                  priv_key, wrapped_data, &wrapped_data_len);
            if (rc != CKR_MECHANISM_INVALID && rc != CKR_KEY_NOT_WRAPPABLE) {
                testcase_fail("Expected CKR_MECHANISM_INVALID or "
                              "CKR_KEY_NOT_WRAPPABLE, but got %s",
                              p11_get_ckr(rc));
            } else {
                testcase_pass("%s passed wrap/unwrap RSA key "
                              "test.", tsuite->name);
            }
        }
    }

testcase_cleanup:
    testcase_close_session();

    return rc;
}

CK_RV do_WrapRSA_Err(struct generated_test_suite_info * tsuite)
{
    unsigned int i;
    CK_BYTE wrapped_data[BIG_REQUEST + AES_BLOCK_SIZE];
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_BYTE pub_exp[] = { 0x01, 0x00, 0x01 };
    CK_MECHANISM mech, mech2;
    CK_MECHANISM_INFO mech_info;
    CK_OBJECT_HANDLE publ_key, priv_key, w_key;
    CK_ULONG bits = 1024;
    CK_ULONG wrapped_data_len, user_pin_len, key_size;
    CK_RV rc = CKR_OK;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;

    CK_ATTRIBUTE pub_tmpl[] = {
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp)}
    };
    CK_ULONG pub_tmpl_len = sizeof(pub_tmpl) / sizeof(CK_ATTRIBUTE);

    CK_ATTRIBUTE key_gen_tmpl[] = {
        {CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG)}
    };
    CK_ULONG key_gen_tmpl_len = sizeof(key_gen_tmpl) / sizeof(CK_ATTRIBUTE);

    testsuite_begin("%s wrap/unwrap of RSA key.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(3, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip test if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(3, "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, CKM_AES_KEY_GEN)) {
        testsuite_skip(3,
                       "Slot %u doesn't support CKM_AES_KEY_GEN)",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }
    if (mech_supported_flags(slot_id, tsuite->mech.mechanism, CKF_WRAP) &&
        !mech_supported(slot_id, CKM_AES_CBC_PAD)) {
        testsuite_skip(3,
                       "Slot %u doesn't support CKM_AES_CBC_PAD)",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    if (!mech_supported(slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)) {
        testsuite_skip(3,
                       "Slot %u doesn't support CKM_RSA_PKCS_KEY_PAIR_GEN",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    rc = funcs->C_GetMechanismInfo(slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN, &mech_info);
    if (rc != CKR_OK) {
        testcase_error("C_GetMechanismInfo rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (bits < mech_info.ulMinKeySize)
        bits = mech_info.ulMinKeySize;

    for (i = 0; i < 3; i++) {

        testcase_begin("%s wrap/unwrap of RSA key for key length=%lu and pkey=%X.",
                       tsuite->name, key_lens[i], pkey);

        key_size = key_lens[i];

        /** first mechanism generate AES wrapping key **/
        mech.mechanism = CKM_AES_KEY_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        /** mechanism to generate an RSA key pair to be wrapped **/
        mech2.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        mech2.ulParameterLen = 0;
        mech2.pParameter = NULL;

        /** generate an RSA key pair. **/
        rc = funcs->C_GenerateKeyPair(session, &mech2,
                                      pub_tmpl, pub_tmpl_len,
                                      NULL, 0,
                                      &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }

            testcase_error("C_GenerateKeyPair rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** generate the wrapping key **/
        rc = funcs->C_GenerateKey(session, &mech, 
                                  key_gen_tmpl, key_gen_tmpl_len,
                                  &w_key);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("AES key generation is not allowed by policy");
                continue;
            }

            testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** set the mech for AES crypto **/
        mech = tsuite->mech;

        /** wrap the key **/
        wrapped_data_len = sizeof(wrapped_data);

        /** get mech info **/
        rc = funcs->C_GetMechanismInfo(slot_id, mech.mechanism, &mech_info);

        if (rc != CKR_OK) {
            testcase_error("C_GetMechanismInfo rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** key is wrappable **/
        if (mech_info.flags & CKF_WRAP) {

            testcase_new_assertion();

            /** wrap key **/
            rc = funcs->C_WrapKey(session, &mech, w_key, priv_key,
                                  wrapped_data, &wrapped_data_len);

            /* Expect dedicated error code here, since it's not allowed
             * to unwrap non secret keys with AES_ECB/AES_CBC */
            if (rc != CKR_KEY_NOT_WRAPPABLE) {
                testcase_error("Expected C_WrapKey rc=%s, but returned rc=%s",
                               p11_get_ckr(CKR_KEY_NOT_WRAPPABLE),
                               p11_get_ckr(rc));
                goto testcase_cleanup;
            } else {
                testcase_pass("%s passed wrap RSA key test.", tsuite->name);
            }
        } else {
            /** key is not wrappable **/
            testcase_new_assertion();

            /** try to wrap key **/
            rc = funcs->C_WrapKey(session, &mech, w_key, priv_key,
                                  wrapped_data, &wrapped_data_len);
            if (rc != CKR_MECHANISM_INVALID && rc != CKR_KEY_NOT_WRAPPABLE)
                testcase_fail("Expected CKR_MECHANISM_INVALID or "
                              "CKR_KEY_NOT_WRAPPABLE, but got %s",
                              p11_get_ckr(rc));
            else
                testcase_pass("%s passed wrap/unwrap RSA key test.",
                              tsuite->name);
        }
    }

testcase_cleanup:
    testcase_close_session();

    return rc;
}



CK_RV do_UnwrapRSA_Err(struct generated_test_suite_info * tsuite)
{
    unsigned int i;
    CK_BYTE wrapped_data[BIG_REQUEST + AES_BLOCK_SIZE] = {0};
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN] = {0};
    CK_BYTE pub_exp[] = { 0x01, 0x00, 0x01 };
    CK_MECHANISM mech, mech1, mech2;
    CK_MECHANISM_INFO mech_info;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE,
        priv_key = CK_INVALID_HANDLE, w_key = CK_INVALID_HANDLE,
        uw_key = CK_INVALID_HANDLE;
    CK_ULONG bits = 1024;
    CK_ULONG wrapped_data_len = 0, user_pin_len = 0, key_size = 0;
    CK_RV rc = CKR_OK;
    CK_FLAGS flags = 0;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS keyclass = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keytype = CKK_RSA;
    CK_SLOT_ID slot_id = SLOT_ID;

    memset(&mech, 0, sizeof(mech));
    memset(&mech1, 0, sizeof(mech1));
    memset(&mech2, 0, sizeof(mech2));
    memset(&mech_info, 0, sizeof(mech_info));

    CK_ATTRIBUTE pub_tmpl[] = {
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp)}
    };
    CK_ULONG pub_tmpl_len = sizeof(pub_tmpl) / sizeof(CK_ATTRIBUTE);

    CK_ATTRIBUTE uw_tmpl[] = {
        {CKA_CLASS, &keyclass, sizeof(keyclass)},
        {CKA_KEY_TYPE, &keytype, sizeof(keytype)}
    };
    CK_ATTRIBUTE key_gen_tmpl[] = {
        {CKA_VALUE_LEN, &key_size, sizeof(CK_ULONG)}
    };
    CK_ULONG key_gen_tmpl_len = sizeof(key_gen_tmpl) / sizeof(CK_ATTRIBUTE);

    testsuite_begin("%s wrap/unwrap of RSA key.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(3, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip test if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(3,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, CKM_AES_KEY_GEN)) {
        testsuite_skip(3,
                       "Slot %u doesn't support CKM_AES_KEY_GEN)",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }
    if (mech_supported_flags(slot_id, tsuite->mech.mechanism, CKF_UNWRAP) &&
        !mech_supported(slot_id, CKM_AES_CBC_PAD)) {
        testsuite_skip(3,
                       "Slot %u doesn't support CKM_AES_CBC_PAD)",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    if (!mech_supported(slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN)) {
        testsuite_skip(3,
                       "Slot %u doesn't support CKM_RSA_PKCS_KEY_PAIR_GEN",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    rc = funcs->C_GetMechanismInfo(slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN, &mech_info);
    if (rc != CKR_OK) {
        testcase_error("C_GetMechanismInfo rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (bits < mech_info.ulMinKeySize)
        bits = mech_info.ulMinKeySize;

    for (i = 0; i < 3; i++) {

        testcase_begin("%s wrap/unwrap of RSA key for key length=%lu and pkey=%X.",
                       tsuite->name, key_lens[i], pkey);

        key_size = key_lens[i];

        /** first mechanism generate AES wrapping key **/
        mech.mechanism = CKM_AES_KEY_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        /** mechanism to generate an RSA key pair to be wrapped **/
        mech2.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
        mech2.ulParameterLen = 0;
        mech2.pParameter = NULL;

        /** generate an RSA key pair. **/
        rc = funcs->C_GenerateKeyPair(session, &mech2,
                                      pub_tmpl, pub_tmpl_len,
                                      NULL, 0,
                                      &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }

            testcase_error("C_GenerateKeyPair rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** generate the wrapping key **/
        rc = funcs->C_GenerateKey(session, &mech,
                                  key_gen_tmpl, key_gen_tmpl_len,
                                  &w_key);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("AES key generation is not allowed by policy");
                continue;
            }

            testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** set the mech for AES crypto **/
        mech = tsuite->mech;

        /** wrap the key **/
        wrapped_data_len = sizeof(wrapped_data);

        /** get mech info **/
        rc = funcs->C_GetMechanismInfo(slot_id, mech.mechanism, &mech_info);
        if (rc != CKR_OK) {
            testcase_error("C_GetMechanismInfo rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** key is wrappable **/
        if (mech_info.flags & CKF_UNWRAP) {

            /** mechanism for wrapping the key **/
            mech1.mechanism = CKM_AES_CBC_PAD;
            mech1.ulParameterLen = AES_IV_SIZE;
            mech1.pParameter = &aes_iv;

            /** wrap key **/
            rc = funcs->C_WrapKey(session, &mech1, w_key, priv_key,
                                  wrapped_data, &wrapped_data_len);
            if (rc != CKR_OK) {
                testcase_error("C_WrapKey rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }

            testcase_new_assertion();

            /** unwrap key **/
            rc = funcs->C_UnwrapKey(session, &mech, w_key, wrapped_data,
                                    wrapped_data_len, uw_tmpl, 2, &uw_key);
            /* Expect dedicated error code here, since it's not allowed
             * to unwrap non secret keys with AES_ECB/AES_CBC */
            if (rc != CKR_ARGUMENTS_BAD) {
                testcase_error("Expected C_UnWrapKey rc=%s, but returned rc=%s",
                               p11_get_ckr(CKR_ARGUMENTS_BAD), p11_get_ckr(rc));
                goto testcase_cleanup;
            }
            testcase_pass("%s passed unwrap RSA key test.", tsuite->name);
        } else {
            /** key is not wrappable **/
            testcase_new_assertion();

            /** try to wrap key **/
            rc = funcs->C_WrapKey(session, &mech, w_key, priv_key,
                                  wrapped_data, &wrapped_data_len);
            if (rc != CKR_MECHANISM_INVALID && rc != CKR_KEY_NOT_WRAPPABLE) {
                testcase_fail("Expected CKR_MECHANISM_INVALID or "
                              "CKR_KEY_NOT_WRAPPABLE, but got %s",
                              p11_get_ckr(rc));
            } else {
                testcase_pass("%s passed unwrap RSA key test.", tsuite->name);
            }
        }
    }

testcase_cleanup:
    testcase_close_session();

    return rc;
}

CK_RV do_SignVerifyMAC(struct published_mac_test_suite_info *tsuite)
{
    unsigned int i;
    int k;
    CK_SESSION_HANDLE session;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE h_key;
    CK_FLAGS flags;
    CK_RV rc = CKR_OK;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG user_pin_len;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_MAC_GENERAL_PARAMS mac_param;
    CK_ULONG ofs;
    CK_BYTE actual[MAX_KEY_SIZE];
    CK_ULONG actual_len, mac_len;

    testsuite_begin("%s Sign/Verify MAC.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if pkey = true, but the slot doesn't support protected keys*/
    if (pkey && !is_ep11_token(slot_id)) {
        testsuite_skip(3, "pkey test option is true, but slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    /** skip tests if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(3,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }


    for (i = 0; i < tsuite->tvcount; i++) {
        testcase_begin("%s Sign/Verify MAC with published test vector %u and pkey=%X.",
                               tsuite->name, i, pkey);

        /** create key handle **/
        rc = create_AESKey(session, !pkey,
                           tsuite->tv[i].key, tsuite->tv[i].klen, CKK_AES,
                           &h_key);

        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key import is not allowed by policy");
                continue;
            }

            testcase_error("C_CreateObject rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** get mech **/
        mech = tsuite->mech;
        switch (mech.mechanism) {
        case CKM_AES_CMAC_GENERAL:
        case CKM_AES_MAC_GENERAL:
            mac_param = tsuite->tv[i].tlen;
            mech.pParameter = &mac_param;
            mech.ulParameterLen = sizeof(mac_param);
            mac_len = mac_param;
            break;
        case CKM_AES_CMAC:
        case CKM_IBM_CMAC:
            mac_len = AES_BLOCK_SIZE;
            break;
        case CKM_AES_MAC:
            mac_len = AES_BLOCK_SIZE / 2;
            break;
        default:
            testcase_error("Invalid mechanism: %s",
                           p11_get_ckm(&mechtable_funcs, mech.mechanism));
            goto error;
        }

        /** initialize signing **/
        rc = funcs->C_SignInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("C_SignInit with mech %s is not allowed by policy",
                              mech_to_str(mech.mechanism));
                goto error;
            }

            testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        actual_len = sizeof(actual);
        memset(actual, 0, sizeof(actual));

        if (tsuite->tv[i].num_chunks_message > 0) {
            ofs = 0;
            for (k = 0; k < tsuite->tv[i].num_chunks_message; k++) {
                rc = funcs->C_SignUpdate(session, tsuite->tv[i].msg + ofs,
                                         tsuite->tv[i].chunks_msg[k]);
                if (rc != CKR_OK) {
                    testcase_error("C_SignUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }
                ofs += tsuite->tv[i].chunks_msg[k];
            }

            rc = funcs->C_SignFinal(session, actual, &actual_len);
            if (rc != CKR_OK) {
                testcase_error("C_SignFinal rc=%s", p11_get_ckr(rc));
                goto error;
            }
        } else {
            rc = funcs->C_Sign(session, tsuite->tv[i].msg,tsuite->tv[i].mlen,
                               actual, &actual_len);
            if (rc != CKR_OK) {
                testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
                goto error;
            }
        }

        /** initilaize verification **/
        rc = funcs->C_VerifyInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** do verification **/
        if (tsuite->tv[i].num_chunks_message > 0) {
            ofs = 0;
            for (k = 0; k < tsuite->tv[i].num_chunks_message; k++) {
                rc = funcs->C_VerifyUpdate(session, tsuite->tv[i].msg + ofs,
                                         tsuite->tv[i].chunks_msg[k]);
                if (rc != CKR_OK) {
                    testcase_error("C_VerifyUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }
                ofs += tsuite->tv[i].chunks_msg[k];
            }

            rc = funcs->C_VerifyFinal(session, actual, actual_len);
            if (rc != CKR_OK) {
                testcase_error("C_VerifyFinal rc=%s", p11_get_ckr(rc));
                goto error;
            }
        } else {
            rc = funcs->C_Verify(session, tsuite->tv[i].msg,tsuite->tv[i].mlen,
                                 actual, actual_len);
            if (rc != CKR_OK) {
                testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
                goto error;
            }
        }

        /** compare sign/verify results with expected results **/
        testcase_new_assertion();

        if ((mech.mechanism == CKM_AES_CMAC_GENERAL ||
             mech.mechanism == CKM_AES_MAC_GENERAL) &&
            actual_len != tsuite->tv[i].tlen) {
            testcase_fail("signature length does not match test vector's "
                          "signature length\nexpected length=%u, found "
                          "length=%lu", tsuite->tv[i].tlen, actual_len);
        } else if (mech.mechanism != CKM_AES_CMAC_GENERAL &&
                   mech.mechanism != CKM_AES_MAC_GENERAL &&
                   actual_len != mac_len) {
            testcase_fail("signature length does not match test vector's "
                          "signature length\nexpected length=%lu, found "
                          "length=%lu", mac_len, actual_len);
        } else if (memcmp(actual, tsuite->tv[i].mac,
                   tsuite->tv[i].tlen < mac_len ? tsuite->tv[i].tlen :
                                                               mac_len)) {
            testcase_fail("signature does not match test vector's signature");
        } else {
            testcase_pass("%s Sign/Verify MAC with test vector %u "
                          "passed.", tsuite->name, i);
        }

        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
    goto testcase_cleanup;

error:
    rc = funcs->C_DestroyObject(session, h_key);
    if (rc != CKR_OK)
        testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

testcase_cleanup:
    testcase_close_session();

    return rc;
}

CK_RV do_SetAttributeValuesPkey(void)
{
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_FLAGS flags;
    CK_ULONG user_pin_len;
    CK_SLOT_ID slot_id = SLOT_ID;

    CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_MECHANISM keygen_mech = { CKM_AES_KEY_GEN, 0, 0 };
    CK_RV rc;

    CK_BBOOL pkey_extr;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_IBM_PROTKEY_EXTRACTABLE, &pkey_extr, sizeof(CK_BBOOL)},
    };
    CK_ULONG tmpl_len = sizeof(tmpl) / sizeof(CK_ATTRIBUTE);


    testsuite_begin("do_SetAttributeValuesPkey");
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if the slot doesn't support protected keys*/
    if (!is_ep11_token(slot_id)) {
        testsuite_skip(1, "Slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    testcase_begin("Generate AES key and change CKA_IBM_PROTKEY_EXTRACTABLE");
    testcase_new_assertion();

    /* Generate a test key */
    rc = generate_AESKey(session, 16, CK_FALSE, &keygen_mech, &h_key);
    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("AES key generation is not allowed by policy");
            goto testcase_cleanup;
        }

        testcase_fail("generate_AESKey rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Check value of CKA_IBM_PROTKEY_EXTRACTABLE */
    rc = funcs->C_GetAttributeValue(session, h_key, tmpl, tmpl_len);
    if (rc != CKR_OK) {
        testcase_fail("C_GetAttributeValue rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Change CKA_IBM_PROTKEY_EXTRACTABLE to false if it's true. This requires
     * token option PKEY_MODE = ENABLE4xxx. It cannot be changed from false
     * to true via C_SetAttributeValue. */
    if (pkey_extr) {
        pkey_extr = CK_FALSE;
        rc = funcs->C_SetAttributeValue(session, h_key, tmpl, tmpl_len);
        if (rc != CKR_OK) {
            testcase_fail("C_SetAttributeValue rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    /* Verify that the attempted change from false to true fails. The attribute
     * is false when using PKEY_MODE = DISABLED or DEFAULT. On older systems,
     * not supporting CKM_IBM_CPACF_WRAP, we get CKR_ATTRIBUTE_TYPE_INVALID
     * here.*/
    if (!pkey_extr) {
        pkey_extr = CK_TRUE;
        rc = funcs->C_SetAttributeValue(session, h_key, tmpl, tmpl_len);
        if (rc != CKR_ATTRIBUTE_READ_ONLY) {
            testcase_fail("Expected CKR_ATTRIBUTE_READ_ONLY, trying to change CKA_IBM_PROTKEY_EXTRACTABLE to true.");
            goto testcase_cleanup;
        }
    }

    testcase_pass("Generate AES key and change CKA_IBM_PROTKEY_EXTRACTABLE");

testcase_cleanup:

    if (h_key != CK_INVALID_HANDLE) {
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK)
            testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
    }

    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK)
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));

    return rc;
}

CK_RV do_EncryptDecryptAESPkey(void)
{
    CK_ULONG keylen = 16;
    CK_BBOOL btrue = CK_TRUE;
    CK_BBOOL bfalse = CK_FALSE;
    CK_RV rc = CKR_OK;
    CK_MECHANISM keygen_mech = { CKM_AES_KEY_GEN, 0, 0 };
    CK_MECHANISM encr_mech = { CKM_AES_ECB, 0, 0 };
    CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE h_key2[2] = {CK_INVALID_HANDLE, CK_INVALID_HANDLE};
    CK_SESSION_HANDLE session;
    CK_UTF8CHAR label[] = "A test key for protected key support";
    CK_ATTRIBUTE keygen_tmpl[] = {
        {CKA_TOKEN, &btrue, sizeof(CK_BBOOL)},
        {CKA_LABEL, &label, sizeof(label)},
        {CKA_EXTRACTABLE, &bfalse, sizeof(CK_BBOOL)},
        {CKA_VALUE_LEN, &keylen, sizeof(CK_ULONG)}
    };
    CK_ULONG keygen_tmpl_len = sizeof(keygen_tmpl) / sizeof(CK_ATTRIBUTE);

    CK_ATTRIBUTE find_tmpl[] = {
        {CKA_LABEL, &label, sizeof(label)},
    };
    CK_ULONG find_tmpl_len = sizeof(find_tmpl) / sizeof(CK_ATTRIBUTE);
    CK_ULONG count = 0;

    CK_BYTE input[] =
        { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
          0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
    CK_BYTE output[32];
    CK_BYTE decrypted[32];
    CK_ULONG outlen = sizeof(output), decrlen = sizeof(decrypted);

    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_FLAGS flags;
    CK_ULONG user_pin_len;
    CK_SLOT_ID slot_id = SLOT_ID;
    int i;

    testsuite_begin("do_EncryptDecryptAESPkey");
    testcase_rw_session();
    testcase_user_login();

    /* Skip tests if the slot doesn't support protected keys*/
    if (!is_ep11_token(slot_id)) {
        testsuite_skip(6, "Slot %u doesn't support protected keys",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }

    testcase_begin("Generate token key object and encrypt");
    testcase_new_assertion();

    /* Generate token object */
    rc = funcs->C_GenerateKey(session, &keygen_mech, keygen_tmpl, keygen_tmpl_len, &h_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session)) {
            testcase_skip("AES key generation is not allowed by policy");
            goto testcase_cleanup;
        }

        testcase_fail("C_GenerateKey rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Encrypt some data with this key object */
    rc = funcs->C_EncryptInit(session, &encr_mech, h_key);
    if (rc != CKR_OK) {
        testcase_fail("C_EncryptInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    memset(output, 0, sizeof(output));
    rc = funcs->C_Encrypt(session, input, sizeof(input), output, &outlen);
    if (rc != CKR_OK) {
        testcase_fail("C_Encrypt rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Generate token key object and encrypt");
    testcase_begin("Log out, close session, and login in again in new session");
    testcase_new_assertion();

    /* Log out and close session */
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_fail("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Log in again read/only, ok for just decrypt with an existing pkey */
    testcase_rw_session();
    testcase_user_login();

    testcase_pass("Log out, close session, and login in again in new session");
    testcase_begin("Retrieve the key from repository");
    testcase_new_assertion();

    /* Retrieve the key from repository */
    rc = funcs->C_FindObjectsInit(session, find_tmpl, find_tmpl_len);
    if (rc != CKR_OK) {
        testcase_fail("C_FindObjectsInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_FindObjects(session, h_key2, 2, &count);
    if (rc != CKR_OK) {
        testcase_fail("C_FindObjects rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }
    if (count == 0) {
        testcase_fail("Didn't find key with label '%s'in repository", label);
        goto testcase_cleanup;
    } else if (count > 1) {
        testcase_skip("Found %lu objs with label '%s', only expected one. "
                      "Skipping this test.\n", count, label);
        rc = funcs->C_FindObjectsFinal(session);
        goto testcase_cleanup;
    }

    /* h_key2[0] points to the same object as h_key in our first session,
     * so invalidate h_key to avoid a double destroy obj later. */
    h_key = CK_INVALID_HANDLE;

    rc = funcs->C_FindObjectsFinal(session);
    if (rc != CKR_OK) {
        testcase_fail("C_FindObjectsFinal rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Retrieve the key from repository");
    testcase_begin("Decrypt encrypted data with retrieved token object");
    testcase_new_assertion();

    /* Decrypt encrypted data with the retrieved token object */
    rc = funcs->C_DecryptInit(session, &encr_mech, h_key2[0]);
    if (rc != CKR_OK) {
        testcase_fail("C_DecryptInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    memset(decrypted, 0, sizeof(decrypted));
    rc = funcs->C_Decrypt(session, output, sizeof(input), decrypted, &decrlen);
    if (rc != CKR_OK) {
        testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Decrypt encrypted data with retrieved token object");
    testcase_begin("Check if result correct");
    testcase_new_assertion();

    /* Check if result correct */
    if (memcmp(input, decrypted, decrlen) != 0) {
        testcase_fail("Decrypted data incorrect");
        goto testcase_cleanup;
    }

    testcase_pass("Check if result correct");
    testcase_begin("Try to retrieve the protected key attribute");
    testcase_new_assertion();

    /* Try to retrieve the protected key attribute from token object*/
    CK_BYTE pkey_buf[64];
    CK_ATTRIBUTE extr_tmpl[] = {
        {CKA_IBM_OPAQUE_PKEY, &pkey_buf, sizeof(pkey_buf)},
    };
    CK_ULONG extr_tmpl_len = sizeof(extr_tmpl) / sizeof(CK_ATTRIBUTE);
    memset(&pkey_buf, 0, sizeof(pkey_buf));
    rc = funcs->C_GetAttributeValue(session, h_key2[0], extr_tmpl, extr_tmpl_len);
    if (rc != CKR_ATTRIBUTE_SENSITIVE) {
        testcase_fail("C_GetAttributeValue rc = %s, expected CKR_ATTRIBUTE_SENSITIVE", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Try to retrieve the protected key attribute");

testcase_cleanup:

    if (h_key != CK_INVALID_HANDLE) {
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK)
            testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
    }

    for (i = 0; i < 2; i++) {
        if (h_key2[i] != CK_INVALID_HANDLE) {
            rc = funcs->C_DestroyObject(session, h_key2[i]);
            if (rc != CKR_OK)
                testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
        }
    }

    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK)
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));

    return rc;
}

/**
 * Special tests for protected key support.
 */
CK_RV aes_funcs_pkey(void)
{
    CK_RV rv;

    rv = do_EncryptDecryptAESPkey();

    rv += do_SetAttributeValuesPkey();

    return rv;
}

CK_RV aes_funcs(void)
{
    unsigned int i;
    CK_RV rv = CKR_OK;

    for (i = 0; i < NUM_OF_PUBLISHED_TESTSUITES; i++) {
        rv = do_EncryptAES(&published_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_DecryptAES(&published_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_EncryptUpdateAES(&published_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_DecryptUpdateAES(&published_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;

    }

    for (i = 0; i < NUM_OF_GENERATED_TESTSUITES; i++) {
        rv = do_EncryptDecryptAES(&generated_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_EncryptDecryptUpdateAES(&generated_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_WrapUnwrapAES(&generated_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_WrapUnwrapRSA(&generated_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    /***** Error scenarios *****/
    for (i = 0; i < NUM_OF_GENERATED_ERR_TESTSUITES; i++) {
        rv = do_WrapRSA_Err(&generated_err_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_UnwrapRSA_Err(&generated_err_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    /* MAC test cases */
    for (i = 0; i < NUM_OF_PUBLISHED_MAC_TESTSUITES; i++) {
        rv = do_SignVerifyMAC(&published_mac_test_suites[i]);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    return rv;
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
    rv = aes_funcs();

    pkey = CK_TRUE;
    rv += aes_funcs();
    rv += aes_funcs_pkey();

    testcase_print_result();

    funcs->C_Finalize(NULL);

    return testcase_return(rv);
}
