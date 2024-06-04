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
#include "mechtable.h"
#include "mech_to_str.h"

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
    unsigned int i, j;
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
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
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
        testcase_begin("%s Encrypt and Decrypt with test vector %u."
                       "\npubl_exp='%s', modbits=%lu, publ_exp_len=%lu, "
                       "inputlen=%lu.", tsuite->name, i, s,
                       tsuite->tv[i].modbits,
                       tsuite->tv[i].publ_exp_len, tsuite->tv[i].inputlen);

        rc = CKR_OK;            // set rc

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].modbits);
            free(s);
            continue;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("EP11 Token cannot be used with publ_exp.='%s'", s);
                free(s);
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
                testcase_skip("CCA Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }

            if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA_1 &&
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA224 &&
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA256 &&
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA384 &&
                 tsuite->tv[i].oaep_params.hashAlg != CKM_SHA512) {
                 testcase_skip("CCA Token cannot use RSA OAEP with a hash "
                              "algorithm other than SHA1 and SHA2: %s",
                              mech_to_str(tsuite->tv[i].oaep_params.hashAlg));
                 free(s);
                 continue;
             }

            if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
                 tsuite->tv[i].oaep_params.source == CKZ_DATA_SPECIFIED &&
                 tsuite->tv[i].oaep_params.ulSourceDataLen > 0) {
                 testcase_skip("CCA Token cannot use RSA OAEP with non empty "
                               "source data");
                 free(s);
                 continue;
             }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp.='%s'",
                              s);
                free(s);
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
                testcase_skip("TPM Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }

        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len) ||
                (tsuite->tv[i].modbits < 1024)) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP) {
            if (!mech_supported(slot_id, tsuite->tv[i].oaep_params.hashAlg)) {
                testcase_skip("Slot %u doesn't support OAEP hash alg %s (0x%x)",
                              (unsigned int)slot_id,
                              mech_to_str(tsuite->tv[i].oaep_params.hashAlg),
                              (unsigned int)tsuite->tv[i].oaep_params.hashAlg);
                free(s);
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
        rc = generate_RSA_PKCS_KeyPair_cached(session,
                                              tsuite->tv[i].modbits,
                                              tsuite->tv[i].publ_exp,
                                              tsuite->tv[i].publ_exp_len,
                                              &publ_key, &priv_key);

        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }

            testcase_error("generate_RSA_PKCS_KeyPair_cached(), "
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
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_ep11_token(slot_id) &&
                (oaep_params.hashAlg != CKM_SHA_1 ||
                 oaep_params.mgf != CKG_MGF1_SHA1)) {
                testcase_skip("EP11 Token does not support RSA OAEP with hash "
                              "and/or MGF other than SHA-1");
                continue;
            }

            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_cca_token(slot_id) &&
                (oaep_params.hashAlg != CKM_SHA_1 ||
                 oaep_params.hashAlg != CKM_SHA256 ||
                 oaep_params.mgf != CKG_MGF1_SHA1 ||
                 oaep_params.mgf != CKG_MGF1_SHA256)) {
                testcase_skip("CCA Token does only support RSA OAEP with hash "
                              "and/or MGF other than SHA-1/SHA256 with "
                              "CCA 8.1 or later");
                continue;
            }

            testcase_error("C_EncryptInit, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // do (public key) encryption
        rc = funcs->C_Encrypt(session,
                              original, original_len, crypt, &crypt_len);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_cca_token(slot_id) &&
                (oaep_params.hashAlg != CKM_SHA_1 ||
                 oaep_params.hashAlg != CKM_SHA256 ||
                 oaep_params.mgf != CKG_MGF1_SHA1 ||
                 oaep_params.mgf != CKG_MGF1_SHA256)) {
                testcase_skip("CCA Token does only support RSA OAEP with hash "
                              "and/or MGF other than SHA-1/SHA256 with "
                              "CCA 8.1 or later");
                continue;
            }

            testcase_error("C_Encrypt, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // initialize (private key) decryption
        rc = funcs->C_DecryptInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // do (private key) decryption
        rc = funcs->C_Decrypt(session, crypt, crypt_len, decrypt, &decrypt_len);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
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
                          "original data length.\n expected length = %lu,"
                          "but found length=%lu.\n", original_len, decrypt_len);
        } else if (memcmp(decrypt, original, original_len)) {
            testcase_fail("decrypted data does not match " "original data.");
        } else {
            testcase_pass("C_Encrypt and C_Decrypt.");
        }

    }

    goto testcase_cleanup;

testcase_cleanup:
    free_rsa_key_cache(session);
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions, rc=%s", p11_get_ckr(loc_rc));
    }

    return rc;
}

/**
 * Note: do_EncryptDecryptImportRSA fails if we don't manually
 * remove padding from decrypted values. This might be a bug.
 **/


/* This function should test:
 * RSA Key Import
 * RSA Encryption, mechanism chosen by caller
 * RSA Decryption, mechanism chosen by caller
 *
 * 1. Import RSA Key Pair
 * 2. Generate plaintext
 * 3. Encrypt plaintext
 * 4. Decrypt encrypted data
 * 5. Compare plaintext with decrypted data
 *
 */
CK_RV do_EncryptDecryptImportRSA(struct PUBLISHED_TEST_SUITE_INFO *tsuite,
                                 CK_BBOOL me_only)
{
    unsigned int i, j;
    CK_BYTE original[BIG_REQUEST];
    CK_ULONG original_len;
    CK_BYTE crypt[BIG_REQUEST];
    CK_ULONG crypt_len;
    CK_BYTE decrypt[BIG_REQUEST];
    CK_ULONG decrypt_len;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    char *s;

    // begin testsuite
    testsuite_begin("%s Encrypt Decrypt Import%s.", tsuite->name,
                    me_only ? " (ME-format)" : "");
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    if (is_cca_token(slot_id) && tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP) {
        if (((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg !=
                                                                CKM_SHA_1 &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg !=
                                                                CKM_SHA224 &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg !=
                                                                CKM_SHA256 &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg !=
                                                                CKM_SHA384 &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg !=
                                                                CKM_SHA512) {
             testcase_skip("CCA Token cannot use RSA OAEP with a hash "
                          "algorithm other than SHA1 and SHA2: %s",
                          mech_to_str(((CK_RSA_PKCS_OAEP_PARAMS *)
                                          tsuite->mech.pParameter)->hashAlg));
             goto testcase_cleanup;
         }

        if (((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->source ==
                                                        CKZ_DATA_SPECIFIED &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->ulSourceDataLen
                                                        > 0) {
             testcase_skip("CCA Token cannot use RSA OAEP with non empty "
                           "source data");
             goto testcase_cleanup;
         }
    }

    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].pub_exp,
                          tsuite->tv[i].pubexp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }
        // begin testcase
        testcase_begin("%s Encrypt and Decrypt Import with test vector %u%s."
                       "\npubl_exp='%s', modbits=%lu, publ_exp_len=%lu.",
                       tsuite->name, i, me_only ? " (ME-format)" : "", s,
                       tsuite->tv[i].mod_len * 8,
                       tsuite->tv[i].pubexp_len);

        rc = CKR_OK;            // set rc

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].mod_len * 8)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].mod_len * 8);
            free(s);
            continue;
        }

        if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
            ((CK_RSA_PKCS_OAEP_PARAMS *)tsuite->mech.pParameter)->hashAlg ==
                                                                   CKM_SHA512 &&
            tsuite->tv[i].mod_len * 8 <= 1024) {
            testcase_skip("OAEP with SHA512 cannot be used with modbits='%lu'",
                          tsuite->tv[i].mod_len * 8);
            free(s);
            continue;
        }

        if (is_ep11_token(slot_id) || is_icsf_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len)) {
                testcase_skip("EP11/ICSF Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
            // modulus length must be multiple of 128 byte
            // skip test if modulus length has unsuported size
            if ((tsuite->tv[i].mod_len % 128) != 0) {
                testcase_skip("EP11/ICSF Token cannot be used with this test vector.");
                free(s);
                continue;
            }
        }

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
                testcase_skip("ICA Token cannot be used with this test vector.");
                free(s);
                continue;
            }

        }

        // cca special cases:
        // cca token can only use the following public exponents
        // 0x03 or 0x010001 (65537)
        // so skip test if invalid public exponent is used
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].pub_exp,
                                     tsuite->tv[i].pubexp_len)) {
                testcase_skip("CCA Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }

        // tpm special cases:
        // tpm token can only use public exponent 0x010001 (65537)
        // so skip test if invalid public exponent is used
        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len * 8))) {
                testcase_skip("TPM Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }

        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len) ||
                (tsuite->tv[i].mod_len * 8 < 1024)) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        free(s);

        // clear buffers
        memset(original, 0, BIG_REQUEST);
        memset(crypt, 0, BIG_REQUEST);
        memset(decrypt, 0, BIG_REQUEST);

        original_len = 10;

        // create (private) key handle
        rc = create_RSAPrivateKey(session,
                                  tsuite->tv[i].mod,
                                  tsuite->tv[i].pub_exp,
                                  tsuite->tv[i].priv_exp,
                                  me_only ? NULL : tsuite->tv[i].prime1,
                                  me_only ? NULL : tsuite->tv[i].prime2,
                                  me_only ? NULL : tsuite->tv[i].exp1,
                                  me_only ? NULL : tsuite->tv[i].exp2,
                                  me_only ? NULL : tsuite->tv[i].coef,
                                  tsuite->tv[i].mod_len,
                                  tsuite->tv[i].pubexp_len,
                                  tsuite->tv[i].privexp_len,
                                  me_only ? 0 : tsuite->tv[i].prime1_len,
                                  me_only ? 0 : tsuite->tv[i].prime2_len,
                                  me_only ? 0 : tsuite->tv[i].exp1_len,
                                  me_only ? 0 : tsuite->tv[i].exp2_len,
                                  me_only ? 0 : tsuite->tv[i].coef_len,
                                  &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                continue;
            }

            testcase_error("create_RSAPrivateKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // create (public) key handle
        rc = create_RSAPublicKey(session,
                                 tsuite->tv[i].mod,
                                 tsuite->tv[i].pub_exp,
                                 tsuite->tv[i].mod_len,
                                 tsuite->tv[i].pubexp_len, &publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                funcs->C_DestroyObject(session, priv_key);
                continue;
            }

            testcase_error("create_RSAPublicKey(), rc=%s", p11_get_ckr(rc));
            goto error;
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
        // initialize (public key) encryption
        rc = funcs->C_EncryptInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_ep11_token(slot_id) &&
                (((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->hashAlg !=
                                                             CKM_SHA_1 ||
                 ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->mgf !=
                                                             CKG_MGF1_SHA1)) {
                testcase_skip("EP11 Token does not support RSA OAEP with hash "
                              "and/or MGF other than SHA-1");
                goto tv_cleanup;
            }

            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_cca_token(slot_id) &&
                (((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->hashAlg !=
                                                                CKM_SHA_1 ||
                 ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->hashAlg !=
                                                                 CKM_SHA256 ||
                 ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->mgf !=
                                                             CKG_MGF1_SHA1 ||
                 ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->mgf !=
                                                             CKG_MGF1_SHA256)) {
                testcase_skip("CCA Token does only support RSA OAEP with hash "
                              "and/or MGF other than SHA-1/SHA256 with "
                              "CCA 8.1 or later");
                goto tv_cleanup;
            }

            testcase_error("C_EncryptInit, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }
        // do (public key) encryption
        rc = funcs->C_Encrypt(session,
                              original, original_len, crypt, &crypt_len);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_cca_token(slot_id) &&
                (((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->hashAlg !=
                                                                CKM_SHA_1 ||
                 ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->hashAlg !=
                                                                 CKM_SHA256 ||
                 ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->mgf !=
                                                             CKG_MGF1_SHA1 ||
                 ((CK_RSA_PKCS_OAEP_PARAMS *)mech.pParameter)->mgf !=
                                                             CKG_MGF1_SHA256)) {
                testcase_skip("CCA Token does only support RSA OAEP with hash "
                              "and/or MGF other than SHA-1/SHA256 with "
                              "CCA 8.1 or later");
                goto tv_cleanup;
            }

            testcase_error("C_Encrypt, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }
        // initialize (private key) decryption
        rc = funcs->C_DecryptInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }
        // do (private key) decryption
        rc = funcs->C_Decrypt(session, crypt, crypt_len, decrypt, &decrypt_len);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
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
                          "original data length.\n expected length = %lu,"
                          "but found length=%lu.\n", original_len, decrypt_len);
        } else if (memcmp(decrypt, original, original_len)) {
            testcase_fail("decrypted data does not match " "original data.");
        } else {
            testcase_pass("C_Encrypt and C_Decrypt%s.",
                          me_only ? " (ME-format)" : "");
        }

        // clean up
tv_cleanup:
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
    unsigned int i;                      // test vector index
    unsigned int j;                      // message byte index
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
    CK_RV rc;

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
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    if (recover_mode) {
        if (!mech_supported_flags(slot_id, tsuite->mech.mechanism,
                                  CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER)) {
            testsuite_skip(tsuite->tvcount,
                           "Slot %u doesn't support Sign/VerifyRecover with %s (0x%x)",
                           (unsigned int) slot_id,
                           mech_to_str(tsuite->mech.mechanism),
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
        testcase_begin("%s Sign%s and Verify%s with test vector %u, "
                       "\npubl_exp='%s', mod_bits='%lu', keylen='%lu'.",
                       tsuite->name, recover_mode ? "Recover" : "",
                       recover_mode ? "Recover" : "", i, s,
                       tsuite->tv[i].modbits, tsuite->tv[i].keylen);

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].modbits);
            free(s);
            continue;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("EP11 Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }

        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                     tsuite->tv[i].publ_exp_len)) {
                testcase_skip("CCA Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].modbits))) {
                testcase_skip("TPM Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len) ||
                (tsuite->tv[i].modbits < 1024)) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (tsuite->tv[i].modbits <= 512 &&
            (tsuite->mech.mechanism == CKM_SHA384_RSA_PKCS ||
             tsuite->mech.mechanism == CKM_SHA512_RSA_PKCS ||
             tsuite->mech.mechanism == CKM_SHA3_384_RSA_PKCS ||
             tsuite->mech.mechanism == CKM_SHA3_512_RSA_PKCS)) {
            testcase_skip("Mechanism %s can not be used with a key with mod_bits='%lu'.",
                          mech_to_str(tsuite->mech.mechanism),
                          tsuite->tv[i].modbits);
            free(s);
            continue;
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
        rc = generate_RSA_PKCS_KeyPair_cached(session,
                                              tsuite->tv[i].modbits,
                                              tsuite->tv[i].publ_exp,
                                              tsuite->tv[i].publ_exp_len,
                                              &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }

            testcase_error("generate_RSA_PKCS_KeyPair_cached(), "
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
            goto testcase_cleanup;
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
            testcase_error("C_Sign%s(), rc=%s signature len=%lu",
                           recover_mode ? "Recover" : "",
                           p11_get_ckr(rc), signature_len);
            goto testcase_cleanup;
        }
        // initialize Verify
        if (recover_mode)
            rc = funcs->C_VerifyRecoverInit(session, &mech, publ_key);
        else
            rc = funcs->C_VerifyInit(session, &mech, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_Verify%sInit(), rc=%s",
                           recover_mode ? "Recover" : "", p11_get_ckr(rc));
            goto testcase_cleanup;
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

    }

testcase_cleanup:
    free_rsa_key_cache(session);
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
    unsigned int i;                      // test vector index
    unsigned int j;                      // message byte index
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
    CK_RV rc;
    CK_RSA_PKCS_PSS_PARAMS pss_params;

    char *s;

    // begin testsuite
    testsuite_begin("%s Sign Verify.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
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
        testcase_begin("%s Sign and Verify with test vector %u, "
                       "\npubl_exp='%s', mod_bits='%lu', keylen='%lu'.",
                       tsuite->name, i, s,
                       tsuite->tv[i].modbits, tsuite->tv[i].keylen);

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].modbits);
            free(s);
            continue;
        }
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                     tsuite->tv[i].publ_exp_len)) {
                testcase_skip("CCA Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }
        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
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
        rc = generate_RSA_PKCS_KeyPair_cached(session, tsuite->tv[i].modbits,
                                              tsuite->tv[i].publ_exp,
                                              tsuite->tv[i].publ_exp_len,
                                              &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }

            testcase_error("generate_RSA_PKCS_KeyPair_cached(), "
                           "rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
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

            if (!mech_supported(slot_id, mech.mechanism)) {
                testcase_skip("Slot %u doesn't support %s (0x%x)",
                              (unsigned int)slot_id,
                              mech_to_str(mech.mechanism),
                              (unsigned int)mech.mechanism);
                continue;
            }

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
            goto testcase_cleanup;
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
            testcase_error("C_Sign(), rc=%s signature len=%lu",
                           p11_get_ckr(rc), signature_len);
            goto testcase_cleanup;
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
    }

testcase_cleanup:
    free_rsa_key_cache(session);
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
    unsigned int i = 0, j = 0;
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
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
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
            testcase_skip("Slot %u doesn't support %s (0x%x)",
                          (unsigned int) slot_id,
                          mech_to_str(tsuite->tv[i].keytype.mechanism),
                          (unsigned int) tsuite->tv[i].keytype.mechanism);
            continue;
        }

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].modbits);
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
                testcase_skip("EP11 Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
            }
        }
        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len) ||
                (tsuite->tv[i].modbits < 1024)) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }
        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) ||
                (!is_valid_tpm_modbits(tsuite->tv[i].modbits))) {
                testcase_skip("TPM Token cannot be used with publ_exp.='%s'", s);
                free(s);
                continue;
           }
        }
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].publ_exp,
                                     tsuite->tv[i].publ_exp_len)) {
                testcase_skip("CCA Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }

            if (tsuite->tv[i].keytype.mechanism == CKM_GENERIC_SECRET_KEY_GEN) {
                testcase_skip("CCA Token cannot wrap CKK_GENERIC_SECRET keys");
                free(s);
                continue;
            }

            if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
                tsuite->tv[i].oaep_params.hashAlg != CKM_SHA_1 &&
                tsuite->tv[i].oaep_params.hashAlg != CKM_SHA256) {
                testcase_skip("CCA Token cannot use RSA OAEP with a hash "
                             "algorithm other than SHA1 and SHA256: %s",
                             mech_to_str(tsuite->tv[i].oaep_params.hashAlg));
                free(s);
                continue;
            }

            if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP &&
                 tsuite->tv[i].oaep_params.source == CKZ_DATA_SPECIFIED &&
                 tsuite->tv[i].oaep_params.ulSourceDataLen > 0) {
                 testcase_skip("CCA Token cannot use RSA OAEP with non empty "
                               "source data");
                 free(s);
                 continue;
             }
        }
        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].publ_exp,
                                      tsuite->tv[i].publ_exp_len)) {
                testcase_skip("Soft Token cannot be used with publ_exp='%s'.", s);
                free(s);
                continue;
            }
        }

        if (tsuite->mech.mechanism == CKM_RSA_PKCS_OAEP) {
            if (!mech_supported(slot_id, tsuite->tv[i].oaep_params.hashAlg)) {
                testcase_skip("Slot %u doesn't support OAEP hash alg %s (0x%x)",
                              (unsigned int)slot_id,
                              mech_to_str(tsuite->tv[i].oaep_params.hashAlg),
                              (unsigned int)tsuite->tv[i].oaep_params.hashAlg);
                free(s);
                continue;
            }
        }

        // begin test
        testcase_begin("%s Wrap Unwrap with test vector %u, "
                       "\npubl_exp='%s', mod_bits='%lu', keylen='%lu', "
                       "keytype='%s'", tsuite->name, i, s,
                       tsuite->tv[i].modbits, tsuite->tv[i].keylen,
                       p11_get_ckm(&mechtable_funcs,
                                   tsuite->tv[i].keytype.mechanism));

        // free memory
        if (s)
            free(s);

        // get key gen mechanism
        keygen_mech = tsuite->tv[i].keytype;

        if (!mech_supported(slot_id, keygen_mech.mechanism)) {
            testcase_skip("Slot %u doesn't support %s (0x%x)",
                          (unsigned int)slot_id,
                          mech_to_str(keygen_mech.mechanism),
                          (unsigned int)keygen_mech.mechanism);
            continue;
        }
        if (keygen_mech.mechanism == CKM_AES_XTS_KEY_GEN &&
            (is_ep11_token(slot_id) || is_cca_token(slot_id))) {
            testcase_skip("Skip test as CKM_AES_XTS_KEY_GEN is supported " \
                          "only for protected keys in EP11 and CCA token");
            continue;
        }
        // get wrapping mechanism
        wrap_mech = tsuite->mech;
        if (wrap_mech.mechanism == CKM_RSA_PKCS_OAEP) {
            oaep_params = tsuite->tv[i].oaep_params;
            wrap_mech.pParameter = &oaep_params;
            wrap_mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);
        }

        if (!mech_supported(slot_id, wrap_mech.mechanism)) {
            testcase_skip("Slot %u doesn't support %s (0x%x)",
                          (unsigned int)slot_id,
                          mech_to_str(wrap_mech.mechanism),
                          (unsigned int)wrap_mech.mechanism);
            continue;
        }

        // clear out buffers
        memset(cipher, 0, sizeof(cipher));
        memset(re_cipher, 0, sizeof(re_cipher));

        // initialize buffer lengths
        wrapped_keylen = PKCS11_MAX_PIN_LEN;

        // generate RSA key pair
        rc = generate_RSA_PKCS_KeyPair_cached(session, tsuite->tv[i].modbits,
                                              tsuite->tv[i].publ_exp,
                                              tsuite->tv[i].publ_exp_len,
                                              &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key generation is not allowed by policy");
                continue;
            }

            testcase_error("C_GenerateKeyPair() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        // generate secret key
        rc = generate_SecretKey(session, tsuite->tv[i].keylen,
                                &keygen_mech, &secret_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("Generic secret key generation is not allowed by policy");
                funcs->C_DestroyObject(session, priv_key);
                continue;
            }
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
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        if (keygen_mech.mechanism != CKM_GENERIC_SECRET_KEY_GEN) {
            switch (keygen_mech.mechanism) {
            case CKM_AES_KEY_GEN:
                mech.mechanism = CKM_AES_CBC;
                mech.ulParameterLen = AES_IV_SIZE;
                mech.pParameter = &aes_iv;
                key_type = CKK_AES;
                break;
            case CKM_AES_XTS_KEY_GEN:
                mech.mechanism = CKM_AES_XTS;
                mech.ulParameterLen = AES_IV_SIZE;
                mech.pParameter = &aes_iv;
                key_type = CKK_AES_XTS;
                break;
            case CKM_DES3_KEY_GEN:
                mech.mechanism = CKM_DES3_CBC;
                mech.ulParameterLen = DES_IV_SIZE;
                mech.pParameter = &des_iv;
                key_type = CKK_DES3;
                break;
            case CKM_DES_KEY_GEN:
                mech.mechanism = CKM_DES_CBC;
                mech.ulParameterLen = DES_IV_SIZE;
                mech.pParameter = &des_iv;
                key_type = CKK_DES;
                break;
            default:
                testcase_error("unknown mech");
                goto error;
            }

            if (!mech_supported(slot_id, mech.mechanism)) {
                testcase_skip("Slot %u doesn't support %s (0x%x)",
                              (unsigned int) slot_id,
                              mech_to_str(mech.mechanism),
                              (unsigned int)mech.mechanism);
                goto tv_cleanup;
            }

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

        // wrap key (length only)
        rc = funcs->C_WrapKey(session, &wrap_mech, publ_key, secret_key,
                              NULL, &wrapped_keylen);
        if (rc != CKR_OK) {
            if (rc == CKR_MECHANISM_PARAM_INVALID &&
                wrap_mech.mechanism == CKM_RSA_PKCS_OAEP &&
                is_ep11_token(slot_id) &&
                (oaep_params.hashAlg != CKM_SHA_1 ||
                 oaep_params.mgf != CKG_MGF1_SHA1)) {
                testcase_skip("EP11 Token does not support RSA OAEP with hash "
                              "and/or MGF other than SHA-1");
                goto tv_cleanup;
            }

            testcase_error("C_WrapKey(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }

        testcase_new_assertion();       /* assertion #1 */

        // allocate memory for wrapped_key
        wrapped_key = calloc(wrapped_keylen, sizeof(CK_BYTE));
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
             (keygen_mech.mechanism == CKM_AES_XTS_KEY_GEN) ||
             (keygen_mech.mechanism == CKM_GENERIC_SECRET_KEY_GEN)) &&
            (wrap_mech.mechanism == CKM_RSA_X_509)) {
            unwrapped_keylen = tsuite->tv[i].keylen;
            unwrap_tmpl_len = 3;
        } else {
            unwrap_tmpl_len = 2;
        }

        switch (wrap_mech.mechanism) {
        case CKM_RSA_X_509:
        case CKM_AES_ECB:
        case CKM_AES_CBC:
        case CKM_DES_ECB:
        case CKM_DES_CBC:
        case CKM_DES3_ECB:
        case CKM_DES3_CBC:
            break;
        default:
            unwrap_tmpl_len = 2;
            break;
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
tv_cleanup:
        if (wrapped_key) {
            free(wrapped_key);
            wrapped_key = NULL;
        }

        rc = funcs->C_DestroyObject(session, secret_key);
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

testcase_cleanup:
    free_rsa_key_cache(session);
    testcase_user_logout();
    loc_rc = funcs->C_CloseAllSessions(slot_id);
    if (loc_rc != CKR_OK) {
        testcase_error("C_CloseAllSessions(), rc=%s.", p11_get_ckr(loc_rc));
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
CK_RV do_SignRSA(struct PUBLISHED_TEST_SUITE_INFO * tsuite, CK_BBOOL me_only)
{
    unsigned int i;
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
    testsuite_begin("%s Sign%s. ", tsuite->name, me_only ? " (ME-format)" : "");
    testcase_rw_session();
    testcase_user_login();

    // skip tests if the slot doesn't support this mechanism **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {
        testcase_begin("%s Sign%s with test vector %u.", tsuite->name,
                       me_only ? " (ME-format)" : "", i);

        rc = CKR_OK;            // set return value

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].mod_len * 8)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].mod_len * 8);
            continue;
        }

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
                testcase_skip("ICA Token cannot be used with this test vector.");
                continue;
            }
        }

        // special case for EP11 + ICSF
        // modulus length must be multiple of 128 byte
        // skip test if modulus length has unsuported size
        if (is_ep11_token(slot_id) || is_icsf_token(slot_id)) {
            if ((tsuite->tv[i].mod_len % 128) != 0) {
                testcase_skip("EP11/ICSF Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len))) {
                testcase_skip("TPM Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].pub_exp,
                                     tsuite->tv[i].pubexp_len)) {
                testcase_skip("CCA Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len)) {
                testcase_skip("Soft Token cannot be used with this test vector.");
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
                                  me_only ? NULL : tsuite->tv[i].prime1,
                                  me_only ? NULL : tsuite->tv[i].prime2,
                                  me_only ? NULL : tsuite->tv[i].exp1,
                                  me_only ? NULL : tsuite->tv[i].exp2,
                                  me_only ? NULL : tsuite->tv[i].coef,
                                  tsuite->tv[i].mod_len,
                                  tsuite->tv[i].pubexp_len,
                                  tsuite->tv[i].privexp_len,
                                  me_only ? 0 : tsuite->tv[i].prime1_len,
                                  me_only ? 0 : tsuite->tv[i].prime2_len,
                                  me_only ? 0 : tsuite->tv[i].exp1_len,
                                  me_only ? 0 : tsuite->tv[i].exp2_len,
                                  me_only ? 0 : tsuite->tv[i].coef_len,
                                  &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                continue;
            }

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
            goto skip;
        }
        // check results
        testcase_new_assertion();

        if (actual_len != expected_len) {
            testcase_fail("%s Sign with test vector %u failed. "
                          "Expected len=%lu, found len=%lu.",
                          tsuite->name, i, expected_len, actual_len);
        } else if (memcmp(actual, expected, expected_len)) {
            testcase_fail("%s Sign with test vector %u failed. "
                          "Signature data does not match test vector "
                          "signature.", tsuite->name, i);

        } else {
            testcase_pass("C_Sign%s.", me_only ? " (ME-format)" : "");
        }
skip:
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
        testcase_error("C_CloseAllSessions, rc=%s.", p11_get_ckr(loc_rc));
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
    unsigned int i;
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
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }
    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        testcase_begin("%s Verify with test vector %u.", tsuite->name, i);

        rc = CKR_OK;            // set return value

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].mod_len * 8)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].mod_len * 8);
            continue;
        }

        // special case for EP11 + ICSF
        // modulus length must be multiple of 128 byte
        // skip test if modulus length has unsuported size
        if (is_ep11_token(slot_id) || is_icsf_token(slot_id)) {
            if ((tsuite->tv[i].mod_len % 128) != 0) {
                testcase_skip("EP11/ICSF Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_tpm_token(slot_id)) {
            if ((!is_valid_tpm_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len))
                || (!is_valid_tpm_modbits(tsuite->tv[i].mod_len))) {
                testcase_skip("TPM Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(tsuite->tv[i].pub_exp,
                                     tsuite->tv[i].pubexp_len)) {
                testcase_skip("CCA Token cannot be used with this test vector.");
                continue;
            }
        }

        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(tsuite->tv[i].pub_exp,
                                      tsuite->tv[i].pubexp_len)) {
                testcase_skip("Soft Token cannot be used with this test vector.");
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
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                continue;
            }

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
            testcase_fail("%s Sign Verify with test vector %u "
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

CK_RV do_RSAImplicitRejection(struct PUBLISHED_TEST_SUITE_INFO *tsuite)
{
    unsigned int i;
    CK_BYTE decrypt[BIG_REQUEST];
    CK_ULONG decrypt_len;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE priv_key = CK_INVALID_HANDLE;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rc, loc_rc;

    char *s;

    // begin testsuite
    testsuite_begin("%s Implicit Rejection.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    if (!is_ica_token(slot_id) && !is_soft_token(slot_id)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support Implicit Rejection",
                       (unsigned int) slot_id);
        goto testcase_cleanup;
    }
    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "Slot %u doesn't support %s (0x%x)",
                       (unsigned int) slot_id,
                       mech_to_str(tsuite->mech.mechanism),
                       (unsigned int) tsuite->mech.mechanism);
        goto testcase_cleanup;
    }

    // iterate over test vectors
    for (i = 0; i < tsuite->tvcount; i++) {

        // get public exponent from test vector
        if (p11_ahex_dump(&s, tsuite->tv[i].pub_exp,
                          tsuite->tv[i].pubexp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = -1;
            goto testcase_cleanup;
        }
        // begin testcase
        testcase_begin("%s Implicit Rejection with test vector %u."
                       "\npubl_exp='%s', modbits=%lu, publ_exp_len=%lu.",
                       tsuite->name, i, s,
                       tsuite->tv[i].mod_len * 8,
                       tsuite->tv[i].pubexp_len);

        rc = CKR_OK;

        if (!keysize_supported(slot_id, tsuite->mech.mechanism,
                               tsuite->tv[i].mod_len * 8)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          SLOT_ID, tsuite->tv[i].mod_len * 8);
            free(s);
            continue;
        }

        free(s);

        // clear buffers
        memset(decrypt, 0, BIG_REQUEST);

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
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("RSA key import is not allowed by policy");
                continue;
            }

            testcase_error("create_RSAPrivateKey(), rc=%s", p11_get_ckr(rc));
            goto error;
        }

        // set cipher buffer length
        decrypt_len = BIG_REQUEST;

        // get mech
        mech = tsuite->mech;

        // initialize (private key) decryption
        rc = funcs->C_DecryptInit(session, &mech, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }
        // do (private key) decryption
        rc = funcs->C_Decrypt(session, tsuite->tv[i].msg, tsuite->tv[i].msg_len,
                              decrypt, &decrypt_len);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt, rc=%s", p11_get_ckr(rc));
            goto tv_cleanup;
        }

        // check results
        testcase_new_assertion();

        if (decrypt_len != tsuite->tv[i].sig_len) {
            testcase_fail("decrypted length does not match"
                          "expected data length.\n expected length = %lu, "
                          "but found length=%lu.\n",
                          tsuite->tv[i].sig_len, decrypt_len);
        } else if (memcmp(decrypt, tsuite->tv[i].sig, tsuite->tv[i].sig_len)) {
            testcase_fail("decrypted data does not match expected data.");
        } else {
            testcase_pass("Implicit Rejection.");
        }

        // clean up
tv_cleanup:

        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
            goto error;
        }
    }

    goto testcase_cleanup;
error:
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

CK_RV rsa_funcs(void)
{
    unsigned int i;
    CK_RV rv = CKR_OK;

    // published (known answer) tests
    for (i = 0; i < NUM_OF_PUBLISHED_TESTSUITES; i++) {
        rv = do_SignRSA(&published_test_suites[i], FALSE);
        if (rv != CKR_OK && (!no_stop))
            break;

        rv = do_SignRSA(&published_test_suites[i], TRUE);
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

    // key import tests
    for (i = 0; i < NUM_OF_ENCDEC_IMPORT_TESTSUITES; i++) {
        rv = do_EncryptDecryptImportRSA(&rsa_encdec_import_test_suites[i],
                                        FALSE);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    for (i = 0; i < NUM_OF_ENCDEC_IMPORT_TESTSUITES; i++) {
        rv = do_EncryptDecryptImportRSA(&rsa_encdec_import_test_suites[i],
                                        TRUE);
        if (rv != CKR_OK && (!no_stop))
            break;
    }

    // Implicit rejection tests
    for (i = 0; i < NUM_OF_IMPLICIT_REJECTION_TESTSUITES; i++) {
        rv = do_RSAImplicitRejection(&rsa_implicit_rejection_test_suites[i]);
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

    testcase_setup();
    rv = rsa_funcs();
    testcase_print_result();

    free_rsa_key_cache(CK_INVALID_HANDLE);
    funcs->C_Finalize(NULL);

    return testcase_return(rv);
}
