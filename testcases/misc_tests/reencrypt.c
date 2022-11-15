/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File: reencrypt.c
 *
 * Test driver.  In-depth regression test for PKCS #11
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>

#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "pkcs11types.h"
#include "regress.h"
#include "mech_to_str.h"
#include "common.c"

CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
CK_ULONG user_pin_len;
CK_SLOT_ID slot_id = 1;

CK_SESSION_HANDLE session;
CK_OBJECT_HANDLE sym_key1 = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE sym_key2 = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE publ_key1 = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE priv_key1 = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE publ_key2 = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE priv_key2 = CK_INVALID_HANDLE;

CK_C_IBM_ReencryptSingle _C_IBM_ReencryptSingle;

CK_RSA_PKCS_OAEP_PARAMS oaep_params_sha1 = {
        .hashAlg = CKM_SHA_1,
        .mgf = CKG_MGF1_SHA1,
        .source = 0,
        .pSourceData = NULL,
        .ulSourceDataLen = 0,
};

CK_RSA_PKCS_OAEP_PARAMS oaep_params_sha1_source = {
        .hashAlg = CKM_SHA_1,
        .mgf = CKG_MGF1_SHA1,
        .source = CKZ_DATA_SPECIFIED,
        .pSourceData = "abc",
        .ulSourceDataLen = 3,
};

CK_RSA_PKCS_OAEP_PARAMS oaep_params_sha256 = {
        .hashAlg = CKM_SHA256,
        .mgf = CKG_MGF1_SHA256,
        .source = 0,
        .pSourceData = NULL,
        .ulSourceDataLen = 0,
};

CK_RSA_PKCS_OAEP_PARAMS oaep_params_sha256_source = {
        .hashAlg = CKM_SHA256,
        .mgf = CKG_MGF1_SHA256,
        .source = CKZ_DATA_SPECIFIED,
        .pSourceData = "abc",
        .ulSourceDataLen = 3,
};


CK_BYTE aes_iv[16] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                       0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f };

CK_BYTE des_iv[8] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07 };

CK_BYTE clear_data[32];
CK_BYTE encrypted_data1[2048];
CK_ULONG encrypted_data1_len = sizeof(encrypted_data1);
CK_BYTE encrypted_data2[2048];
CK_ULONG encrypted_data2_len = sizeof(encrypted_data2);
CK_BYTE decrypted_data[1024];
CK_ULONG decrypted_data_len = sizeof(decrypted_data);

struct mech_info {
    char *name;
    CK_MECHANISM mech;
    CK_MECHANISM key_gen_mech;
    CK_ULONG rsa_modbits;
    CK_ULONG rsa_publ_exp_len;
    CK_BYTE rsa_publ_exp[4];
    CK_ULONG sym_keylen;
    CK_ULONG clear_data_len;
};

struct mech_info reencrypt_tests[] = {
    {
        .name = "AES 128 ECB",
        .mech = { CKM_AES_ECB, 0, 0 },
        .key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 16,
        .clear_data_len = 32,
    },
    {
        .name = "AES 192 ECB",
        .mech = { CKM_AES_ECB, 0, 0 },
        .key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 24,
        .clear_data_len = 32,
    },
    {
        .name = "AES 256 ECB",
        .mech = { CKM_AES_ECB, 0, 0 },
        .key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 32,
        .clear_data_len = 32,
    },
    {
        .name = "AES 128 CBC",
        .mech = { CKM_AES_CBC, aes_iv, sizeof(aes_iv) },
        .key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 16,
        .clear_data_len = 32,
    },
    {
        .name = "AES 192 CBC",
        .mech = { CKM_AES_CBC, aes_iv, sizeof(aes_iv) },
        .key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 24,
        .clear_data_len = 32,
    },
    {
        .name = "AES 256 CBC",
        .mech = { CKM_AES_CBC, aes_iv, sizeof(aes_iv) },
        .key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 32,
        .clear_data_len = 32,
    },
    {
        .name = "AES 128 CBC PAD",
        .mech = { CKM_AES_CBC_PAD, aes_iv, sizeof(aes_iv) },
        .key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 16,
        .clear_data_len = 30,
    },
    {
        .name = "AES 192 CBC PAD",
        .mech = { CKM_AES_CBC_PAD, aes_iv, sizeof(aes_iv) },
        .key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 24,
        .clear_data_len = 30,
    },
    {
        .name = "AES 256 CBC PAD",
        .mech = { CKM_AES_CBC_PAD, aes_iv, sizeof(aes_iv) },
        .key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 32,
        .clear_data_len = 30,
    },
    {
        .name = "DES ECB",
        .mech = { CKM_DES_ECB, 0, 0 },
        .key_gen_mech = { CKM_DES_KEY_GEN, 0, 0 },
        .clear_data_len = 32,
    },
    {
        .name = "DES CCB",
        .mech = { CKM_DES_CBC, des_iv, sizeof(des_iv) },
        .key_gen_mech = { CKM_DES_KEY_GEN, 0, 0 },
        .clear_data_len = 32,
    },
    {
        .name = "DES CBC PAD",
        .mech = { CKM_DES_CBC_PAD, des_iv, sizeof(des_iv) },
        .key_gen_mech = { CKM_DES_KEY_GEN, 0, 0 },
        .clear_data_len = 30,
    },
    {
        .name = "DES3 ECB",
        .mech = { CKM_DES3_ECB, 0, 0 },
        .key_gen_mech = { CKM_DES3_KEY_GEN, 0, 0 },
        .clear_data_len = 32,
    },
    {
        .name = "DES3 CCB",
        .mech = { CKM_DES3_CBC, des_iv, sizeof(des_iv) },
        .key_gen_mech = { CKM_DES3_KEY_GEN, 0, 0 },
        .clear_data_len = 32,
    },
    {
        .name = "DES3 CBC PAD",
        .mech = { CKM_DES3_CBC_PAD, des_iv, sizeof(des_iv) },
        .key_gen_mech = { CKM_DES3_KEY_GEN, 0, 0 },
        .clear_data_len = 30,
    },
    {
        .name = "RSA 512 PKCS",
        .mech = { CKM_RSA_PKCS, 0, 0 },
        .key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 512,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
        .clear_data_len = 30,
    },
    {
        .name = "RSA 1024 PKCS",
        .mech = { CKM_RSA_PKCS, 0, 0 },
        .key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
        .clear_data_len = 30,
    },
    {
        .name = "RSA 2048 PKCS",
        .mech = { CKM_RSA_PKCS, 0, 0 },
        .key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 2048,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
        .clear_data_len = 30,
    },
    {
        .name = "RSA 1024 PKCS OAEP (SHA1)",
        .mech = { CKM_RSA_PKCS_OAEP, &oaep_params_sha1,
                  sizeof(CK_RSA_PKCS_OAEP_PARAMS) },
        .key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
        .clear_data_len = 30,
    },
    {
        .name = "RSA 1024 PKCS OAEP (SHA1, source data)",
        .mech = { CKM_RSA_PKCS_OAEP, &oaep_params_sha1_source,
                  sizeof(CK_RSA_PKCS_OAEP_PARAMS) },
        .key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
        .clear_data_len = 30,
    },
    {
        .name = "RSA 1024 PKCS OAEP (SHA256)",
        .mech = { CKM_RSA_PKCS_OAEP, &oaep_params_sha256,
                  sizeof(CK_RSA_PKCS_OAEP_PARAMS) },
        .key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
        .clear_data_len = 30,
    },
    {
        .name = "RSA 1024 PKCS OAEP (SHA256, source data)",
        .mech = { CKM_RSA_PKCS_OAEP, &oaep_params_sha256_source,
                  sizeof(CK_RSA_PKCS_OAEP_PARAMS) },
        .key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
        .clear_data_len = 30,
    },
};

#define NUM_REENCRYPT_TESTS sizeof(reencrypt_tests) / \
                                sizeof(struct mech_info)

CK_RV do_reencrypt(struct mech_info *mech1, struct mech_info *mech2)
{
    CK_RSA_PKCS_OAEP_PARAMS *oaep;
    CK_RV loc_rc, rc = CKR_OK;
    char *s = NULL;

    testcase_begin("Reencrypt from '%s' to '%s'", mech1->name, mech2->name);

    if (!mech_supported(slot_id, mech2->key_gen_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                       (unsigned int)slot_id,
                       mech_to_str(mech2->key_gen_mech.mechanism),
                       (unsigned int)mech2->key_gen_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, mech2->mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                       (unsigned int)slot_id,
                       mech_to_str(mech2->mech.mechanism),
                       (unsigned int)mech2->mech.mechanism);
        goto testcase_cleanup;
    }

    switch (mech2->mech.mechanism) {
    case CKM_DES_ECB:
    case CKM_DES_CBC:
    case CKM_DES_CBC_PAD:
        if (is_cca_token(slot_id)) {
            testcase_skip("CCA does not support DES with reencrypt");
            goto testcase_cleanup;
        }
        break;
    case CKM_DES3_CBC_PAD:
        if (is_cca_token(slot_id)) {
            testcase_skip("CCA does not support DES3 CBC PAD with reencrypt");
            goto testcase_cleanup;
        }
        break;
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
        if (is_cca_token(slot_id)) {
            testcase_skip("CCA does not support RSA with reencrypt");
            goto testcase_cleanup;
        }
        break;
    default:
        break;
    }

    switch (mech1->mech.mechanism) {
    case CKM_AES_CBC_PAD:
    case CKM_DES_CBC_PAD:
    case CKM_DES3_CBC_PAD:
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
        switch (mech2->mech.mechanism) {
        case CKM_AES_CBC_PAD:
        case CKM_DES_CBC_PAD:
        case CKM_DES3_CBC_PAD:
        case CKM_RSA_PKCS:
        case CKM_RSA_PKCS_OAEP:
            break;
        default:
            testcase_skip("Cannot reencrypt from %s (%u) to %s (%u), because "
                          "the target mechanism does not pad.",
                          mech_to_str(mech1->mech.mechanism),
                          (unsigned int)mech1->mech.mechanism,
                          mech_to_str(mech2->mech.mechanism),
                          (unsigned int)mech2->mech.mechanism);
            goto testcase_cleanup;
        }
        break;
    default:
        break;
    }

    /*
     * Generate the key 1
     */
    switch (mech2->key_gen_mech.mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        if (p11_ahex_dump(&s, mech2->rsa_publ_exp,
                mech2->rsa_publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = CKR_FUNCTION_FAILED;
            goto testcase_cleanup;
        }

        if (!keysize_supported(slot_id, mech2->key_gen_mech.mechanism,
                               mech2->rsa_modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          slot_id, mech2->rsa_modbits);
            goto testcase_cleanup;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(mech2->rsa_publ_exp,
                                      mech2->rsa_publ_exp_len)) {
                testcase_skip("EP11 Token in cannot be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(mech2->rsa_publ_exp,
                                     mech2->rsa_publ_exp_len)) {
                testcase_skip("CCA Token in cannot be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(mech2->rsa_publ_exp,
                                      mech2->rsa_publ_exp_len)) {
                testcase_skip("Soft Token in cannot be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_tpm_token(slot_id) ) {
            if (!is_valid_tpm_pubexp(mech2->rsa_publ_exp,
                                     mech2->rsa_publ_exp_len) ||
                !is_valid_tpm_modbits(mech2->rsa_modbits)) {
                testcase_skip("TPM Token cannot be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(mech2->rsa_publ_exp,
                                      mech2->rsa_publ_exp_len) ||
                mech2->rsa_modbits < 1024) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                goto testcase_cleanup;
            }
        }
        rc = generate_RSA_PKCS_KeyPair(session, mech2->rsa_modbits,
                                       mech2->rsa_publ_exp,
                                       mech2->rsa_publ_exp_len,
                                       &publ_key2, &priv_key2);
        break;

    case CKM_AES_KEY_GEN:
        rc = generate_AESKey(session, mech2->sym_keylen, CK_TRUE,
                             &mech2->key_gen_mech, &sym_key2);
        break;

    case CKM_DES3_KEY_GEN:
    case CKM_DES2_KEY_GEN:
    case CKM_DES_KEY_GEN:
        rc = funcs->C_GenerateKey(session, &mech2->key_gen_mech,
                                  NULL, 0, &sym_key2);
        break;

    default:
        testcase_error("Testcase does not support %s (%u)",
                       mech_to_str(mech2->key_gen_mech.mechanism),
                       (unsigned int)mech2->key_gen_mech.mechanism);
        goto testcase_cleanup;
    }

    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("generate key-2 with mech %s (%u) in slot %lu "
                          "is not allowed by policy",
                          mech_to_str(mech2->key_gen_mech.mechanism),
                          (unsigned int)mech2->key_gen_mech.mechanism,
                          slot_id);
            goto testcase_cleanup;
        }

        testcase_error("generate key-2 with mech %s (%u) in slot %lu "
                       "failed, rc=%s",
                       mech_to_str(mech2->key_gen_mech.mechanism),
                       (unsigned int)mech2->key_gen_mech.mechanism,
                       slot_id, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    encrypted_data2_len = sizeof(encrypted_data2);
    rc = _C_IBM_ReencryptSingle(session, &mech1->mech,
                                sym_key1 != CK_INVALID_HANDLE ? sym_key1 :
                                                                    priv_key1,
                                &mech2->mech, sym_key2 != CK_INVALID_HANDLE ?
                                                        sym_key2 : publ_key2,
                                encrypted_data1, encrypted_data1_len,
                                encrypted_data2, &encrypted_data2_len);
    if (rc != CKR_OK) {
        oaep = (CK_RSA_PKCS_OAEP_PARAMS *)mech2->mech.pParameter;
        if (rc == CKR_MECHANISM_PARAM_INVALID &&
            mech2->mech.mechanism == CKM_RSA_PKCS_OAEP &&
            is_ep11_token(slot_id) &&
            (oaep->hashAlg != CKM_SHA_1 || oaep->mgf != CKG_MGF1_SHA1)) {
            testcase_skip("EP11 Token does not support RSA OAEP with hash "
                          "and/or MGF other than SHA-1");
            goto testcase_cleanup;
        }

        if (rc == CKR_FUNCTION_NOT_SUPPORTED) {
            testcase_skip("Slot %lu does not support C_IBM_ReencryptSingle",
                          slot_id);
            goto testcase_cleanup;
        }

        testcase_error("C_IBM_ReencryptSingle with decr-mech %s (%u) and "
                       "encr-mech %s (%u) failed, rc=%s",
                       mech_to_str(mech1->mech.mechanism),
                       (unsigned int)mech1->mech.mechanism,
                       mech_to_str(mech2->mech.mechanism),
                       (unsigned int)mech2->mech.mechanism,
                       p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_DecryptInit(session, &mech2->mech,
                              sym_key2 != CK_INVALID_HANDLE ? sym_key2 :
                                                                   priv_key2);
     if (rc != CKR_OK) {
         testcase_error("C_DecryptInit rc=%s", p11_get_ckr(rc));
         goto testcase_cleanup;
     }

     decrypted_data_len = sizeof(decrypted_data);
     rc = funcs->C_Decrypt(session, encrypted_data2, encrypted_data2_len,
                           decrypted_data, &decrypted_data_len);
     if (rc != CKR_OK) {
         testcase_error("C_Decrypt rc=%s", p11_get_ckr(rc));
         goto testcase_cleanup;
     }

     if (decrypted_data_len != mech1->clear_data_len) {
         testcase_error("The decrypted data length differs from the original "
                        "clear data: original: %lu, decrypted: %lu",
                        mech1->clear_data_len, decrypted_data_len);
         rc = CKR_FUNCTION_FAILED;
         goto testcase_cleanup;
     }

     if (memcmp(clear_data, decrypted_data, mech1->clear_data_len) != 0) {
         testcase_error("The decrypted data differs from the original "
                                 "clear data.");
         rc = CKR_FUNCTION_FAILED;
         goto testcase_cleanup;
     }

     testcase_new_assertion();
     testcase_pass("Reencrypt from '%s' to '%s'", mech1->name, mech2->name);

testcase_cleanup:
    if (sym_key2 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, sym_key2);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    sym_key2 = CK_INVALID_HANDLE;
    if (publ_key2 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, publ_key2);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    publ_key2 = CK_INVALID_HANDLE;
    if (priv_key2 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, priv_key2);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    priv_key2 = CK_INVALID_HANDLE;

    if (s != NULL)
        free(s);

    return rc;
}

CK_RV do_encrypt_reencrypt(struct mech_info *mech1)
{
    CK_RSA_PKCS_OAEP_PARAMS *oaep;
    CK_RV loc_rc, rc = CKR_OK;
    char *s = NULL;
    CK_ULONG i;

    testsuite_begin("with '%s'", mech1->name);

    if (!mech_supported(slot_id, mech1->key_gen_mech.mechanism)) {
        testsuite_skip(NUM_REENCRYPT_TESTS, "Slot %u doesn't support %s (0x%x)",
                       (unsigned int)slot_id,
                       mech_to_str(mech1->key_gen_mech.mechanism),
                       (unsigned int)mech1->key_gen_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id, mech1->mech.mechanism)) {
        testsuite_skip(NUM_REENCRYPT_TESTS, "Slot %u doesn't support %s (0x%x)",
                       (unsigned int)slot_id,
                       mech_to_str(mech1->mech.mechanism),
                       (unsigned int)mech1->mech.mechanism);
        goto testcase_cleanup;
    }

    switch (mech1->mech.mechanism) {
    case CKM_DES_ECB:
    case CKM_DES_CBC:
    case CKM_DES_CBC_PAD:
        if (is_cca_token(slot_id)) {
            testsuite_skip(NUM_REENCRYPT_TESTS, "CCA does not support DES "
                           "with reencrypt");
            goto testcase_cleanup;
        }
        break;
    case CKM_DES3_CBC_PAD:
        if (is_cca_token(slot_id)) {
            testsuite_skip(NUM_REENCRYPT_TESTS, "CCA does not support DES3 "
                           "CBC PAD with reencrypt");
            goto testcase_cleanup;
        }
        break;
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_OAEP:
        if (is_cca_token(slot_id)) {
            testsuite_skip(NUM_REENCRYPT_TESTS, "CCA does not support RSA "
                           "with reencrypt");
            goto testcase_cleanup;
        }
        break;
    default:
        break;
    }

    /*
     * Generate the key 1
     */
    switch (mech1->key_gen_mech.mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        if (p11_ahex_dump(&s, mech1->rsa_publ_exp,
                          mech1->rsa_publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = CKR_FUNCTION_FAILED;
            goto testcase_cleanup;
        }

        if (!keysize_supported(slot_id,
                               mech1->key_gen_mech.mechanism,
                               mech1->rsa_modbits)) {
            testsuite_skip(NUM_REENCRYPT_TESTS, "Token in slot %lu cannot be "
                          "used with modbits='%lu'", slot_id,
                          mech1->rsa_modbits);
            goto testcase_cleanup;
        }

        if (is_ep11_token(slot_id)) {
            if (!is_valid_ep11_pubexp(mech1->rsa_publ_exp,
                                      mech1->rsa_publ_exp_len)) {
                testsuite_skip(NUM_REENCRYPT_TESTS, "EP11 Token cannot be "
                               "used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_cca_token(slot_id)) {
            if (!is_valid_cca_pubexp(mech1->rsa_publ_exp,
                                     mech1->rsa_publ_exp_len)) {
                testsuite_skip(NUM_REENCRYPT_TESTS, "CCA Token cannot be "
                               "used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_soft_token(slot_id)) {
            if (!is_valid_soft_pubexp(mech1->rsa_publ_exp,
                                      mech1->rsa_publ_exp_len)) {
                testsuite_skip(NUM_REENCRYPT_TESTS, "Soft Token cannot be "
                               "used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_tpm_token(slot_id) ) {
            if (!is_valid_tpm_pubexp(mech1->rsa_publ_exp,
                                     mech1->rsa_publ_exp_len) ||
                !is_valid_tpm_modbits(mech1->rsa_modbits)) {
                testsuite_skip(NUM_REENCRYPT_TESTS, "TPM Token cannot be used "
                               "with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_icsf_token(slot_id)) {
            if (!is_valid_icsf_pubexp(mech1->rsa_publ_exp,
                                      mech1->rsa_publ_exp_len) ||
                mech1->rsa_modbits < 1024) {
                testsuite_skip(NUM_REENCRYPT_TESTS, "ICSF Token cannot be "
                               "used with publ_exp='%s'.", s);
                goto testcase_cleanup;
            }
        }
        rc = generate_RSA_PKCS_KeyPair(session, mech1->rsa_modbits,
                                       mech1->rsa_publ_exp,
                                       mech1->rsa_publ_exp_len,
                                       &publ_key1, &priv_key1);
        break;

    case CKM_AES_KEY_GEN:
        rc = generate_AESKey(session, mech1->sym_keylen, CK_TRUE,
                             &mech1->key_gen_mech, &sym_key1);
        break;

    case CKM_DES3_KEY_GEN:
    case CKM_DES2_KEY_GEN:
    case CKM_DES_KEY_GEN:
        rc = funcs->C_GenerateKey(session, &mech1->key_gen_mech,
                                  NULL, 0, &sym_key1);
        break;

    default:
        testcase_error("Testcase does not support %s (%u)",
                       mech_to_str(mech1->key_gen_mech.mechanism),
                       (unsigned int)mech1->key_gen_mech.mechanism);
        goto testcase_cleanup;
    }

    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("generate key-1 with mech %s (%u) in slot %lu "
                          "is not allowed by policy",
                          mech_to_str(mech1->key_gen_mech.mechanism),
                          (unsigned int)mech1->key_gen_mech.mechanism,
                          slot_id);
            goto testcase_cleanup;
        }

        testcase_error("generate key-1 with mech %s (%u) in slot %lu "
                       "failed, rc=%s",
                       mech_to_str(mech1->key_gen_mech.mechanism),
                       (unsigned int)mech1->key_gen_mech.mechanism,
                       slot_id, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_EncryptInit(session, &mech1->mech,
                              sym_key1 != CK_INVALID_HANDLE ? sym_key1 :
                                                                  publ_key1);
    if (rc != CKR_OK) {
        oaep = (CK_RSA_PKCS_OAEP_PARAMS *)mech1->mech.pParameter;
        if (rc == CKR_MECHANISM_PARAM_INVALID &&
            mech1->mech.mechanism == CKM_RSA_PKCS_OAEP &&
            is_ep11_token(slot_id) &&
            (oaep->hashAlg != CKM_SHA_1 || oaep->mgf != CKG_MGF1_SHA1)) {
            testsuite_skip(NUM_REENCRYPT_TESTS, "EP11 Token does not support "
                           "RSA OAEP with hash and/or MGF other than SHA-1");
            goto testcase_cleanup;
        }

        testcase_error("C_EncryptInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    encrypted_data1_len = sizeof(encrypted_data1);
    rc = funcs->C_Encrypt(session, clear_data, mech1->clear_data_len,
                          encrypted_data1, &encrypted_data1_len);
    if (rc != CKR_OK) {
        testcase_error("C_Encrypt rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    for (i = 0; i < NUM_REENCRYPT_TESTS; i++) {
        rc = do_reencrypt(mech1, &reencrypt_tests[i]);
        if (rc != CKR_OK)
            break;
    }

testcase_cleanup:
    if (sym_key1 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, sym_key1);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    sym_key1 = CK_INVALID_HANDLE;
    if (publ_key1 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, publ_key1);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    publ_key1 = CK_INVALID_HANDLE;
    if (priv_key1 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session, priv_key1);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    priv_key1 = CK_INVALID_HANDLE;

    if (s != NULL)
        free(s);

    return rc;
}

CK_RV do_reencrypt_tests(void)
{
    CK_ULONG i;
    CK_RV rc;

    for (i = 0; i < sizeof(clear_data); i++)
        clear_data[i] = (CK_BYTE)i;

    for (i = 0; i < NUM_REENCRYPT_TESTS; i++) {
        rc = do_encrypt_reencrypt(&reencrypt_tests[i]);
        if (rc != CKR_OK)
            break;
    }

    return CKR_OK;
}


int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int i, ret = 1;
    CK_RV rv;
    CK_FLAGS flags;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-slot") == 0) {
            ++i;
            if (i >= argc) {
                printf("Slot number missing\n");
                return -1;
            }
            slot_id = atoi(argv[i]);
        }

        if (strcmp(argv[i], "-h") == 0) {
            printf("usage:  %s [-slot <num>] [-h]\n\n", argv[0]);
            printf("By default, Slot #1 is used\n\n");
            return -1;
        }
    }

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;
    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    printf("Using slot #%lu...\n\n", slot_id);

    rv = do_GetFunctionList();
    if (rv != TRUE) {
        testcase_fail("do_GetFunctionList() rc = %s", p11_get_ckr(rv));
        goto out;
    }

    *(void **)(&_C_IBM_ReencryptSingle) =
                                dlsym(pkcs11lib, "C_IBM_ReencryptSingle");
    if (_C_IBM_ReencryptSingle == NULL) {
        testcase_skip("C_IBM_ReencryptSingle not supported");
        goto out;
    }

    testcase_setup();
    testcase_begin("Starting...");

    // Initialize
    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    if ((rv = funcs->C_Initialize(&cinit_args))) {
        testcase_fail("C_Initialize rc = %s", p11_get_ckr(rv));
        goto out;
    }

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
    if (rv != CKR_OK) {
        testcase_fail("C_OpenSession rc = %s", p11_get_ckr(rv));
        goto finalize;
    }

    rv = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
    if (rv != CKR_OK) {
        testcase_fail("C_Login rc = %s", p11_get_ckr(rv));
        goto close_session;
    }

    rv = do_reencrypt_tests();
    if (rv != CKR_OK)
        goto close_session;

    rv = funcs->C_CloseSession(session);
    if (rv != CKR_OK) {
        testcase_fail("C_CloseSession rc = %s", p11_get_ckr(rv));
        goto finalize;
    }

    rv = funcs->C_Finalize(NULL);
    if (rv != CKR_OK) {
        testcase_fail("C_Finalize rc = %s", p11_get_ckr(rv));
        goto out;
    }

    ret = 0;
    goto out;

close_session:
    rv = funcs->C_CloseSession(session);
    if (rv != CKR_OK) {
        testcase_fail("C_CloseSession rc = %s", p11_get_ckr(rv));
        ret = 1;
    }
finalize:
    rv = funcs->C_Finalize(NULL);
    if (rv != CKR_OK) {
        testcase_fail("C_Finalize rc = %s", p11_get_ckr(rv));
        ret = 1;
    }
out:
    testcase_print_result();
    return testcase_return(ret);
}
