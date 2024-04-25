/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File: tok2tok_transport.c
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
#include "ec_curves.h"
#include "common.c"

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

struct wrapping_mech_info {
    char *name;
    CK_MECHANISM wrapping_mech;
    CK_MECHANISM wrapping_key_gen_mech;
    CK_ULONG rsa_modbits;
    CK_ULONG rsa_publ_exp_len;
    CK_BYTE rsa_publ_exp[4];
    CK_ULONG sym_keylen;
};

struct wrapping_mech_info wrapping_tests[] = {
    {
        .name = "Wrap/Unwrap with RSA 512 PKCS",
        .wrapping_mech = { CKM_RSA_PKCS, 0, 0 },
        .wrapping_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 512,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
    },
    {
        .name = "Wrap/Unwrap with RSA 1024 PKCS",
        .wrapping_mech = { CKM_RSA_PKCS, 0, 0 },
        .wrapping_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
    },
    {
        .name = "Wrap/Unwrap with RSA 2048 PKCS",
        .wrapping_mech = { CKM_RSA_PKCS, 0, 0 },
        .wrapping_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 2048,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
    },
    {
        .name = "Wrap/Unwrap with RSA 1024 PKCS OAEP (SHA1)",
        .wrapping_mech = { CKM_RSA_PKCS_OAEP, &oaep_params_sha1,
                           sizeof(CK_RSA_PKCS_OAEP_PARAMS) },
        .wrapping_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
    },
    {
        .name = "Wrap/Unwrap with RSA 1024 PKCS OAEP (SHA1, source data)",
        .wrapping_mech = { CKM_RSA_PKCS_OAEP, &oaep_params_sha1_source,
                           sizeof(CK_RSA_PKCS_OAEP_PARAMS) },
        .wrapping_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
    },
    {
        .name = "Wrap/Unwrap with RSA 1024 PKCS OAEP (SHA256)",
        .wrapping_mech = { CKM_RSA_PKCS_OAEP, &oaep_params_sha256,
                           sizeof(CK_RSA_PKCS_OAEP_PARAMS) },
        .wrapping_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
    },
    {
        .name = "Wrap/Unwrap with RSA 1024 PKCS OAEP (SHA256, source data)",
        .wrapping_mech = { CKM_RSA_PKCS_OAEP, &oaep_params_sha256_source,
                           sizeof(CK_RSA_PKCS_OAEP_PARAMS) },
        .wrapping_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
    },
    {
        .name = "Wrap/Unwrap with AES 128 ECB",
        .wrapping_mech = { CKM_AES_ECB, 0, 0 },
        .wrapping_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 16,
    },
    {
        .name = "Wrap/Unwrap with AES 192 ECB",
        .wrapping_mech = { CKM_AES_ECB, 0, 0 },
        .wrapping_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 24,
    },
    {
        .name = "Wrap/Unwrap with AES 256 ECB",
        .wrapping_mech = { CKM_AES_ECB, 0, 0 },
        .wrapping_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 32,
    },
    {
        .name = "Wrap/Unwrap with AES 128 CBC",
        .wrapping_mech = { CKM_AES_CBC, aes_iv, sizeof(aes_iv) },
        .wrapping_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 16,
    },
    {
        .name = "Wrap/Unwrap with AES 192 CBC",
        .wrapping_mech = { CKM_AES_CBC, aes_iv, sizeof(aes_iv) },
        .wrapping_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 24,
    },
    {
        .name = "Wrap/Unwrap with AES 256 CBC",
        .wrapping_mech = { CKM_AES_CBC, aes_iv, sizeof(aes_iv) },
        .wrapping_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 32,
    },
    {
        .name = "Wrap/Unwrap with AES 128 CBC PAD",
        .wrapping_mech = { CKM_AES_CBC_PAD, aes_iv, sizeof(aes_iv) },
        .wrapping_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 16,
    },
    {
        .name = "Wrap/Unwrap with AES 192 CBC PAD",
        .wrapping_mech = { CKM_AES_CBC_PAD, aes_iv, sizeof(aes_iv) },
        .wrapping_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 24,
    },
    {
        .name = "Wrap/Unwrap with AES 256 CBC PAD",
        .wrapping_mech = { CKM_AES_CBC_PAD, aes_iv, sizeof(aes_iv) },
        .wrapping_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .sym_keylen = 32,
    },
    {
        .name = "Wrap/Unwrap with AES 128 XTS",
        .wrapping_mech = { CKM_AES_XTS, aes_iv, sizeof(aes_iv) },
        .wrapping_key_gen_mech = { CKM_AES_XTS_KEY_GEN, 0, 0 },
        .sym_keylen = 32,
    },
    {
        .name = "Wrap/Unwrap with AES 256 XTS",
        .wrapping_mech = { CKM_AES_XTS, aes_iv, sizeof(aes_iv) },
        .wrapping_key_gen_mech = { CKM_AES_XTS_KEY_GEN, 0, 0 },
        .sym_keylen = 64,
    },
    {
        .name = "Wrap/Unwrap with DES ECB",
        .wrapping_mech = { CKM_DES_ECB, 0, 0 },
        .wrapping_key_gen_mech = { CKM_DES_KEY_GEN, 0, 0 },
    },
    {
        .name = "Wrap/Unwrap with DES CBC",
        .wrapping_mech = { CKM_DES_CBC, des_iv, sizeof(des_iv) },
        .wrapping_key_gen_mech = { CKM_DES_KEY_GEN, 0, 0 },
    },
    {
        .name = "Wrap/Unwrap with DES CBC PAD",
        .wrapping_mech = { CKM_DES_CBC_PAD, des_iv, sizeof(des_iv) },
        .wrapping_key_gen_mech = { CKM_DES_KEY_GEN, 0, 0 },
    },
    {
        .name = "Wrap/Unwrap with DES2 ECB",
        .wrapping_mech = { CKM_DES3_ECB, 0, 0 },
        .wrapping_key_gen_mech = { CKM_DES2_KEY_GEN, 0, 0 },
    },
    {
        .name = "Wrap/Unwrap with DES2 CBC",
        .wrapping_mech = { CKM_DES3_CBC, des_iv, sizeof(des_iv) },
        .wrapping_key_gen_mech = { CKM_DES2_KEY_GEN, 0, 0 },
    },
    {
        .name = "Wrap/Unwrap with DES2 CBC PAD",
        .wrapping_mech = { CKM_DES3_CBC_PAD, des_iv, sizeof(des_iv) },
        .wrapping_key_gen_mech = { CKM_DES2_KEY_GEN, 0, 0 },
    },
    {
        .name = "Wrap/Unwrap with DES3 ECB",
        .wrapping_mech = { CKM_DES3_ECB, 0, 0 },
        .wrapping_key_gen_mech = { CKM_DES3_KEY_GEN, 0, 0 },
    },
    {
        .name = "Wrap/Unwrap with DES3 CBC",
        .wrapping_mech = { CKM_DES3_CBC, des_iv, sizeof(des_iv) },
        .wrapping_key_gen_mech = { CKM_DES3_KEY_GEN, 0, 0 },
    },
    {
        .name = "Wrap/Unwrap with DES3 CBC PAD",
        .wrapping_mech = { CKM_DES3_CBC_PAD, des_iv, sizeof(des_iv) },
        .wrapping_key_gen_mech = { CKM_DES3_KEY_GEN, 0, 0 },
    },
};

#define NUM_WRAPPING_TESTS sizeof(wrapping_tests) / \
                                sizeof(struct wrapping_mech_info)

CK_BYTE prime256v1[] = OCK_PRIME256V1;

struct wrapped_mech_info {
    char *name;
    CK_MECHANISM wrapped_key_gen_mech;
    CK_ULONG rsa_modbits;
    CK_ULONG rsa_publ_exp_len;
    CK_BYTE rsa_publ_exp[4];
    CK_ULONG sym_keylen;
    CK_BYTE *ec_params;
    CK_ULONG ec_params_len;
    CK_MECHANISM operation_mech;
};

struct wrapped_mech_info wrapped_key_tests[] = {
    {
        .name = "key type AES 128",
        .wrapped_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .operation_mech = { CKM_AES_ECB, 0, 0 },
        .sym_keylen = 16,
    },
    {
        .name = "key type AES 192",
        .wrapped_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .operation_mech = { CKM_AES_ECB, 0, 0 },
        .sym_keylen = 24,
    },
    {
        .name = "key type AES 256",
        .wrapped_key_gen_mech = { CKM_AES_KEY_GEN, 0, 0 },
        .operation_mech = { CKM_AES_ECB, 0, 0 },
        .sym_keylen = 32,
    },
    {
        .name = "key type AES-XTS 128",
        .wrapped_key_gen_mech = { CKM_AES_XTS_KEY_GEN, 0, 0 },
        .operation_mech = { CKM_AES_XTS, aes_iv, sizeof(aes_iv) },
        .sym_keylen = 32,
    },
    {
        .name = "key type AES-XTS 256",
        .wrapped_key_gen_mech = { CKM_AES_XTS_KEY_GEN, 0, 0 },
        .operation_mech = { CKM_AES_XTS, aes_iv, sizeof(aes_iv) },
        .sym_keylen = 64,
    },
    {
        .name = "key type DES3",
        .wrapped_key_gen_mech = { CKM_DES3_KEY_GEN, 0, 0 },
        .operation_mech = { CKM_DES3_ECB, 0, 0 },
    },
    {
        .name = "key type DES2",
        .wrapped_key_gen_mech = { CKM_DES2_KEY_GEN, 0, 0 },
        .operation_mech = { CKM_DES3_ECB, 0, 0 },
    },
    {
        .name = "key type DES",
        .wrapped_key_gen_mech = { CKM_DES_KEY_GEN, 0, 0 },
        .operation_mech = { CKM_DES_ECB, 0, 0 },
    },
    {
        .name = "key type GENERIC SECRET",
        .wrapped_key_gen_mech = { CKM_GENERIC_SECRET_KEY_GEN, 0, 0 },
        .operation_mech = { CKM_SHA_1_HMAC, 0, 0 },
        .sym_keylen = 32,
    },
    {
        .name = "key type RSA PKCS 512",
        .wrapped_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .operation_mech = { CKM_RSA_PKCS, 0, 0 },
        .rsa_modbits = 512,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
    },
    {
        .name = "key type RSA PKCS 1024",
        .wrapped_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .operation_mech = { CKM_RSA_PKCS, 0, 0 },
        .rsa_modbits = 1024,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
    },
    {
        .name = "key type RSA PKCS 2048",
        .wrapped_key_gen_mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, 0, 0 },
        .operation_mech = { CKM_RSA_PKCS, 0, 0 },
        .rsa_modbits = 2048,
        .rsa_publ_exp_len = 3,
        .rsa_publ_exp = {0x01, 0x00, 0x01},
    },
    {
        .name = "key type EC",
        .wrapped_key_gen_mech = { CKM_EC_KEY_PAIR_GEN, 0, 0 },
        .operation_mech = { CKM_ECDSA, 0, 0 },
        .ec_params = prime256v1,
        .ec_params_len = sizeof(prime256v1),
    },
};

#define NUM_WRAPPED_KEY_TESTS sizeof(wrapped_key_tests) / \
		                            sizeof(struct wrapped_mech_info)

CK_SLOT_ID slot_id1 = 1, slot_id2 = 2;
CK_SESSION_HANDLE session1 = CK_INVALID_HANDLE;
CK_SESSION_HANDLE session2 = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE sym_wrap_key1 = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE sym_wrap_key2 = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE publ_wrap_key1 = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE publ_wrap_key2 = CK_INVALID_HANDLE;
CK_OBJECT_HANDLE priv_wrap_key2 = CK_INVALID_HANDLE;

CK_RV do_perform_operation(CK_MECHANISM *mech,
                           CK_SLOT_ID slot1,
                           CK_SESSION_HANDLE sess1,
                           CK_OBJECT_HANDLE sym_key1,
                           CK_OBJECT_HANDLE publ_key1,
                           CK_SLOT_ID slot2,
                           CK_SESSION_HANDLE sess2,
                           CK_OBJECT_HANDLE sym_key2,
                           CK_OBJECT_HANDLE priv_key2)
{
    CK_RV rc;
    CK_MECHANISM_INFO mech_info;
    CK_BBOOL encr = FALSE, decr = FALSE, sign = FALSE, verify = FALSE;
    CK_ULONG input_size, cipher_size, output_size;
    CK_BYTE input_data[32] = { 0x00,0x01,0x02,0x03,0x04,0x05,0x06,0x07,
                               0x08,0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,
                               0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,
                               0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f};
    CK_BYTE cipher_data[512];
    CK_BYTE output_data[512];
    CK_OBJECT_HANDLE encr_key, decr_key, sign_key, verify_key;

    /* Check if Encrypt/Decrypt or Sign/Verify is supported */
    rc = funcs->C_GetMechanismInfo(slot1, mech->mechanism, &mech_info);
    if (rc != CKR_OK) {
        testcase_error("C_GetMechanismInfo on slot %lu, rc=%s", slot1,
                       p11_get_ckr(rc));
        return rc;
    }
    encr = (mech_info.flags & CKF_ENCRYPT) != 0;
    sign = (mech_info.flags & CKF_SIGN) != 0;

    rc = funcs->C_GetMechanismInfo(slot2, mech->mechanism, &mech_info);
    if (rc != CKR_OK) {
        testcase_error("C_GetMechanismInfo on slot %lu, rc=%s", slot2,
                       p11_get_ckr(rc));
        return rc;
    }

    decr = (mech_info.flags & CKF_DECRYPT) != 0;
    verify = (mech_info.flags & CKF_VERIFY) != 0;

    if (encr && decr) {
        /* Perform Encrypt/Decrypt operation */
        switch (mech->mechanism) {
        case CKM_AES_ECB:
        case CKM_AES_XTS:
            input_size = 16;
            encr_key = sym_key1;
            decr_key = sym_key2;
            break;
        case CKM_DES_ECB:
        case CKM_DES3_ECB:
            input_size = 8;
            encr_key = sym_key1;
            decr_key = sym_key2;
            break;
        case CKM_RSA_PKCS:
            input_size = 16;
            encr_key = publ_key1;
            decr_key = priv_key2;
            break;
        default:
            testcase_error("Operation not supported by testcase");
            return CKR_FUNCTION_NOT_SUPPORTED;
        }

        rc = funcs->C_EncryptInit(sess1, mech, encr_key);
        if (rc != CKR_OK) {
            testcase_error("C_EncryptInit on slot %lu rc=%s", slot1,
                           p11_get_ckr(rc));
            return rc;
        }

        cipher_size = sizeof(cipher_data);
        rc = funcs->C_Encrypt(sess1, input_data, input_size, cipher_data,
                              &cipher_size);
        if (rc != CKR_OK) {
            testcase_error("C_Encrypt on slot %lu rc=%s", slot1,
                           p11_get_ckr(rc));
            return rc;
        }

        rc = funcs->C_DecryptInit(sess2, mech, decr_key);
        if (rc != CKR_OK) {
            testcase_error("C_DecryptInit on slot %lu rc=%s", slot2,
                           p11_get_ckr(rc));
            return rc;
        }

        output_size = sizeof(output_data);
        rc = funcs->C_Decrypt(sess2, cipher_data, cipher_size, output_data,
                              &output_size);
        if (rc != CKR_OK) {
            testcase_error("C_Decrypt on slot %lu rc=%s", slot2,
                           p11_get_ckr(rc));
            return rc;
        }

        if (output_size != input_size) {
            testcase_error("Decrypted data has different size then original "
                           "data: orig: %lu decr: %lu", input_size,
                           output_size);
            return CKR_FUNCTION_FAILED;
        }
        if (memcmp(input_data, output_data, input_size) != 0) {
            testcase_error("Decrypted data is different then original data");
            return CKR_FUNCTION_FAILED;
        }
    } else if (sign && verify) {
        /* Perform Sign/Verify operation */
        switch (mech->mechanism) {
        case CKM_SHA_1_HMAC:
            sign_key = sym_key2;
            verify_key = sym_key1;
            input_size = 20;
            break;
        case CKM_RSA_PKCS:
        case CKM_ECDSA:
            sign_key = priv_key2;
            verify_key = publ_key1;
            input_size = 20;
            break;
        default:
            testcase_error("Operation not supported by testcase");
            return CKR_FUNCTION_NOT_SUPPORTED;
        }

        rc = funcs->C_SignInit(sess2, mech, sign_key);
        if (rc != CKR_OK) {
            testcase_error("C_SignInit on slot %lu rc=%s", slot2,
                           p11_get_ckr(rc));
            return rc;
        }

        output_size = sizeof(output_data);
        rc = funcs->C_Sign(sess2, input_data, input_size, output_data,
                           &output_size);
        if (rc != CKR_OK) {
            testcase_error("C_Sign on slot %lu rc=%s", slot2, p11_get_ckr(rc));
            return rc;
        }

        rc = funcs->C_VerifyInit(sess1, mech, verify_key);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyInit on slot %lu rc=%s", slot1,
                           p11_get_ckr(rc));
            return rc;
        }

        rc = funcs->C_Verify(sess1, input_data, input_size, output_data,
                             output_size);
        if (rc != CKR_OK) {
            testcase_error("C_Verify on slot %lu rc=%s", slot1, p11_get_ckr(rc));
            return rc;
        }
    } else {
        testcase_error("Neither Encrypt/Decrypt, nor Sign/Verify supported");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    return CKR_OK;
}

CK_RV do_wrap_key_test(struct wrapped_mech_info *tsuite,
                       CK_MECHANISM *wrap_mech)
{
    CK_RV loc_rc, rc = CKR_OK;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE priv_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE sym_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE unwrapped_key = CK_INVALID_HANDLE;
    CK_BYTE wrapped_key[4096];
    CK_ULONG wrapped_key_size = sizeof(wrapped_key);
    CK_OBJECT_CLASS key_class;
    CK_KEY_TYPE key_type;
    CK_ULONG key_len, unwrapped_keylen;
    CK_ATTRIBUTE unwrap_tmpl[] = {
        {CKA_CLASS, &key_class, sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE, &key_type, sizeof(CK_KEY_TYPE)},
        {CKA_VALUE_LEN, &key_len, sizeof(CK_ULONG)}
    };
    CK_ULONG unwrap_tmpl_num;
    CK_ATTRIBUTE getattr_tmpl[] = {
        {CKA_VALUE_LEN, &unwrapped_keylen, sizeof(CK_ULONG)}
    };
    char *s = NULL;
    CK_RSA_PKCS_OAEP_PARAMS *oaep;

    testcase_begin("Wrap/Unwrap of %s with %s", tsuite->name,
                   mech_to_str(wrap_mech->mechanism));

    if (!mech_supported(slot_id1, tsuite->wrapped_key_gen_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)slot_id1,
                      mech_to_str(tsuite->wrapped_key_gen_mech.mechanism),
                      (unsigned int)tsuite->wrapped_key_gen_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id2, tsuite->wrapped_key_gen_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)slot_id2,
                      mech_to_str(tsuite->wrapped_key_gen_mech.mechanism),
                      (unsigned int)tsuite->wrapped_key_gen_mech.mechanism);
        goto testcase_cleanup;
    }

    if (!mech_supported(slot_id1, tsuite->operation_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)slot_id1,
                      mech_to_str(tsuite->operation_mech.mechanism),
                      (unsigned int)tsuite->operation_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!mech_supported(slot_id2, tsuite->operation_mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s (0x%x)",
                      (unsigned int)slot_id2,
                      mech_to_str(tsuite->operation_mech.mechanism),
                      (unsigned int)tsuite->operation_mech.mechanism);
        goto testcase_cleanup;
    }

    if (is_ep11_token(slot_id2) && wrap_mech->mechanism == CKM_AES_CBC &&
        ((tsuite->wrapped_key_gen_mech.mechanism == CKM_AES_KEY_GEN &&
          tsuite->sym_keylen == 24) ||
         tsuite->wrapped_key_gen_mech.mechanism == CKM_DES3_KEY_GEN)) {
        testcase_skip("EP11 token in slot %lu doesn't support to unwrap "
                       "AES-192 or DES3 keys with CKM_AES_CBC", slot_id2);
        goto testcase_cleanup;
    }

    /* Generate the to be wrapped key in slot 1 */
    switch (tsuite->wrapped_key_gen_mech.mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        if (p11_ahex_dump(&s, tsuite->rsa_publ_exp,
                          tsuite->rsa_publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = CKR_FUNCTION_FAILED;
            goto testcase_cleanup;
        }

        if (!keysize_supported(slot_id1, tsuite->wrapped_key_gen_mech.mechanism,
                               tsuite->rsa_modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          slot_id1, tsuite->rsa_modbits);
            goto testcase_cleanup;
        }
        if (!keysize_supported(slot_id2, tsuite->wrapped_key_gen_mech.mechanism,
                               tsuite->rsa_modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          slot_id2, tsuite->rsa_modbits);
            goto testcase_cleanup;
        }

        if (is_ep11_token(slot_id1) || is_ep11_token(slot_id2)) {
            if (!is_valid_ep11_pubexp(tsuite->rsa_publ_exp,
                                      tsuite->rsa_publ_exp_len)) {
                testcase_skip("EP11 Token in cannot be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_cca_token(slot_id1) || is_cca_token(slot_id2)) {
            if (!is_valid_cca_pubexp(tsuite->rsa_publ_exp,
                                     tsuite->rsa_publ_exp_len)) {
                testcase_skip("CCA Token in scannot be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_soft_token(slot_id1) || is_soft_token(slot_id2)) {
            if (!is_valid_soft_pubexp(tsuite->rsa_publ_exp,
                                      tsuite->rsa_publ_exp_len)) {
                testcase_skip("Soft Token in scannot be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_tpm_token(slot_id1) || is_tpm_token(slot_id2)) {
            if (!is_valid_tpm_pubexp(tsuite->rsa_publ_exp,
                                     tsuite->rsa_publ_exp_len) ||
                !is_valid_tpm_modbits(tsuite->rsa_modbits)) {
                testcase_skip("TPM Token cannot " "be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_icsf_token(slot_id1) || is_icsf_token(slot_id2)) {
            if (!is_valid_icsf_pubexp(tsuite->rsa_publ_exp,
                                      tsuite->rsa_publ_exp_len) ||
                tsuite->rsa_modbits < 1024) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                goto testcase_cleanup;
            }
        }

        rc = generate_RSA_PKCS_KeyPair(session1, tsuite->rsa_modbits,
                                       tsuite->rsa_publ_exp,
                                       tsuite->rsa_publ_exp_len,
                                       &publ_key, &priv_key);
        break;

    case CKM_AES_KEY_GEN:
    case CKM_AES_XTS_KEY_GEN:
        if ((is_ep11_token(slot_id1) || is_ep11_token(slot_id2) ||
             is_cca_token(slot_id1) || is_cca_token(slot_id2)) &&
            tsuite->wrapped_key_gen_mech.mechanism == CKM_AES_XTS_KEY_GEN) {
            testcase_skip("Skipping as AES XTS is supported only with protected keys");
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        rc = generate_AESKey(session1, tsuite->sym_keylen, CK_TRUE,
                             &tsuite->wrapped_key_gen_mech, &sym_key);
        break;

    case CKM_DES3_KEY_GEN:
    case CKM_DES2_KEY_GEN:
    case CKM_DES_KEY_GEN:
        rc = funcs->C_GenerateKey(session1, &tsuite->wrapped_key_gen_mech,
                                  NULL, 0, &sym_key);
        break;

    case CKM_GENERIC_SECRET_KEY_GEN:
        rc = generate_SecretKey(session1, tsuite->sym_keylen,
                                &tsuite->wrapped_key_gen_mech, &sym_key);
        break;

    case CKM_EC_KEY_PAIR_GEN:
        rc = generate_EC_KeyPair(session1, tsuite->ec_params,
                                 tsuite->ec_params_len, &publ_key, &priv_key,
                                 CK_TRUE); // must be extractable for Wrap/Unwrap
        break;

    default:
        testcase_error("Testcase does not support %s (%u)",
                       mech_to_str(tsuite->wrapped_key_gen_mech.mechanism),
                       (unsigned int)tsuite->wrapped_key_gen_mech.mechanism);
        goto testcase_cleanup;
    }

    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("generate to be wrapped key with mech %s (%u) in slot "
                          "%lu is not allowed by policy",
                          mech_to_str(tsuite->wrapped_key_gen_mech.mechanism),
                          (unsigned int)tsuite->wrapped_key_gen_mech.mechanism,
                          slot_id1);
            rc = CKR_OK;
            goto testcase_cleanup;
        }

        testcase_error("generate to be wrapped key with mech %s (%u) in slot "
                       "%lu failed, rc=%s",
                       mech_to_str(tsuite->wrapped_key_gen_mech.mechanism),
                       (unsigned int)tsuite->wrapped_key_gen_mech.mechanism,
                       slot_id1, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Test the key with a crypto operation on slot 1 */
    rc = do_perform_operation(&tsuite->operation_mech,
                              slot_id1, session1, sym_key, publ_key,
                              slot_id1, session1, sym_key, priv_key);
    if (rc != CKR_OK)
        goto testcase_cleanup;

    /* Wrap the key on slot 1 */
    rc = funcs->C_WrapKey(session1, wrap_mech,
                          sym_wrap_key1 != CK_INVALID_HANDLE ?
                                        sym_wrap_key1 : publ_wrap_key1,
                          sym_key != CK_INVALID_HANDLE ? sym_key : priv_key,
                          wrapped_key, &wrapped_key_size);
    if (rc != CKR_OK) {
        if (rc == CKR_KEY_NOT_WRAPPABLE) {
            testcase_skip("Key not wrappable");
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        if (rc == CKR_MECHANISM_PARAM_INVALID &&
            wrap_mech->mechanism == CKM_RSA_PKCS_OAEP) {
            oaep = (CK_RSA_PKCS_OAEP_PARAMS *)wrap_mech->pParameter;
            if (is_cca_token(slot_id1) &&
                oaep->source == CKZ_DATA_SPECIFIED) {
                testcase_skip("CCA does not support RSA OAEP with source data");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
            if (is_cca_token(slot_id1) &&
                oaep->hashAlg != CKM_SHA_1 &&
                oaep->hashAlg != CKM_SHA256) {
                testcase_skip("CCA does not support RSA OAEP with a hash other "
                              "than SHA1 or SHA256");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
            if (is_ep11_token(slot_id1) && oaep->hashAlg != CKM_SHA_1 &&
                oaep->mgf != CKG_MGF1_SHA1) {
                testcase_skip("EP11 may not support RSA OAEP with a hash other "
                              "than SHA1 on older firmware levels");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
        }
        if (rc == CKR_ARGUMENTS_BAD) {
            if (is_ep11_token(slot_id1) &&
                publ_wrap_key1 != CK_INVALID_HANDLE &&
                (wrap_mech->mechanism == CKM_RSA_PKCS ||
                 wrap_mech->mechanism == CKM_RSA_PKCS_OAEP)) {
                testcase_skip("EP11 does not support to wrap asymmetric keys "
                              "with RSA");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
        }

        testcase_error("wrap with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(wrap_mech->mechanism),
                       (unsigned int)wrap_mech->mechanism,
                       slot_id1, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Get class and key type from original key */
    switch (tsuite->wrapped_key_gen_mech.mechanism) {
    case CKM_AES_KEY_GEN:
    case CKM_AES_XTS_KEY_GEN:
    case CKM_GENERIC_SECRET_KEY_GEN:
        unwrap_tmpl_num = 3;
        break;
   default:
        unwrap_tmpl_num = 2;
        break;
    }

    rc = funcs->C_GetAttributeValue(session1, sym_key != CK_INVALID_HANDLE ?
                                                        sym_key : priv_key,
                                    unwrap_tmpl, unwrap_tmpl_num);
    if (rc != CKR_OK) {
        testcase_error("C_GetAttributeValue() on slot %lu, rc=%s.", slot_id1,
                       p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    switch (wrap_mech->mechanism) {
    case CKM_RSA_X_509:
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_DES_ECB:
    case CKM_DES_CBC:
    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
        break;
    default:
        unwrap_tmpl_num = 2;
        break;
    }

    /* Unwrap the key on slot 2 */
    rc = funcs->C_UnwrapKey(session2, wrap_mech,
                            sym_wrap_key2 != CK_INVALID_HANDLE ?
                                                sym_wrap_key2 : priv_wrap_key2,
                            wrapped_key, wrapped_key_size, unwrap_tmpl,
                            unwrap_tmpl_num, &unwrapped_key);
    if (rc != CKR_OK) {
        if (rc == CKR_KEY_NOT_WRAPPABLE || rc == CKR_WRAPPED_KEY_INVALID) {
            testcase_skip("Key not (un-)wrappable");
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        if (rc == CKR_MECHANISM_PARAM_INVALID &&
            wrap_mech->mechanism == CKM_RSA_PKCS_OAEP) {
            oaep = (CK_RSA_PKCS_OAEP_PARAMS *)wrap_mech->pParameter;
            if (is_cca_token(slot_id2) &&
                oaep->source == CKZ_DATA_SPECIFIED) {
                testcase_skip("CCA does not support RSA OAEP with source data");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
            if (is_cca_token(slot_id2) &&
                oaep->hashAlg != CKM_SHA_1 &&
                oaep->hashAlg != CKM_SHA256) {
                testcase_skip("CCA does not support RSA OAEP with a hash other "
                              "than SHA1 or SHA256");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
            if (is_ep11_token(slot_id2) && oaep->hashAlg != CKM_SHA_1 &&
                oaep->mgf != CKG_MGF1_SHA1) {
                testcase_skip("EP11 may not support RSA OAEP with a hash other "
                              "than SHA1 on older firmware levels");
                rc = CKR_OK;
                goto testcase_cleanup;
            }
        }
        if ((rc == CKR_MECHANISM_INVALID || rc == CKR_KEY_TYPE_INCONSISTENT) &&
            is_ep11_token(slot_id2) && wrap_mech->mechanism == CKM_DES3_CBC &&
            (key_type == CKK_EC || key_type == CKK_RSA)) {
            testcase_skip("EP11 does not support unwrap of EC or RSA keys with DES3 CBC");
            rc = CKR_OK;
            goto testcase_cleanup;
        }

        testcase_error("unwrap with mech %s (%u) in slot %lu failed, rc=%s",
                       mech_to_str(wrap_mech->mechanism),
                       (unsigned int)wrap_mech->mechanism,
                       slot_id2, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (key_type == CKK_AES || key_type == CKK_AES_XTS ||
        key_type == CKK_GENERIC_SECRET) {
        /* Check if the unwrapped key has the desired key length */
        rc = funcs->C_GetAttributeValue(session2, unwrapped_key,
                                        getattr_tmpl, 1);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue() on slot %lu, rc=%s.", slot_id2,
                           p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        if (unwrapped_keylen != key_len) {
            testcase_error("Unwrapped key size (%lu) differers from original "
                           "(%lu)", unwrapped_keylen, key_len);
            rc = CKR_UNWRAPPING_KEY_SIZE_RANGE;
            goto testcase_cleanup;
        }
    }

    /* Test the unwrapped key with a crypto operation on slot 2 */
    rc = do_perform_operation(&tsuite->operation_mech,
                              slot_id1, session1, sym_key, publ_key,
                              slot_id2, session2, unwrapped_key,
                              unwrapped_key);
    if (rc != CKR_OK)
        goto testcase_cleanup;

    testcase_new_assertion();
    testcase_pass("Wrap/Unwrap of %s with %s", tsuite->name,
                  mech_to_str(wrap_mech->mechanism));

testcase_cleanup:
    if (sym_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session1, sym_key);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    if (publ_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session1, publ_key);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    if (priv_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session1, priv_key);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    if (unwrapped_key != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session2, unwrapped_key);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }

    if (s != NULL)
        free(s);

    if (rc != CKR_OK)
        testcase_fail("Wrap/Unwrap of %s with %s", tsuite->name,
                      mech_to_str(wrap_mech->mechanism));

    return rc;
}

CK_RV do_wrapping_test(struct wrapping_mech_info *tsuite)
{
    CK_RV loc_rc, rc = CKR_OK;
    CK_ULONG i;
    char *s = NULL;
    CK_BYTE modulus[512];
    CK_BYTE publ_exp[16];
    CK_BYTE key[64];
    CK_ULONG key_size = 0;
    CK_BYTE value[64];
    CK_ATTRIBUTE rsa_publ_tmpl[] = {
        {CKA_MODULUS, modulus, sizeof(modulus) },
        {CKA_PUBLIC_EXPONENT, publ_exp, sizeof(publ_exp) },
    };
    CK_ATTRIBUTE sym_tmpl[] = {
        {CKA_VALUE, value, sizeof(value) },
    };

    testsuite_begin("%s", tsuite->name);

    if (!mech_supported(slot_id1, tsuite->wrapping_key_gen_mech.mechanism)) {
        testsuite_skip(NUM_WRAPPED_KEY_TESTS, "Slot %u doesn't support %s (0x%x)",
                       (unsigned int)slot_id1,
                       mech_to_str(tsuite->wrapping_key_gen_mech.mechanism),
                       (unsigned int)tsuite->wrapping_key_gen_mech.mechanism);
        goto testcase_cleanup;
    }

    if (!mech_supported(slot_id2, tsuite->wrapping_key_gen_mech.mechanism)) {
        testsuite_skip(NUM_WRAPPED_KEY_TESTS, "Slot %u doesn't support %s (0x%x)",
                       (unsigned int)slot_id2,
                       mech_to_str(tsuite->wrapping_key_gen_mech.mechanism),
                       (unsigned int)tsuite->wrapping_key_gen_mech.mechanism);
        goto testcase_cleanup;
    }

    if (!mech_supported(slot_id1, tsuite->wrapping_mech.mechanism)) {
        testsuite_skip(NUM_WRAPPED_KEY_TESTS, "Slot %u doesn't support %s (0x%x)",
                       (unsigned int)slot_id1,
                       mech_to_str(tsuite->wrapping_mech.mechanism),
                       (unsigned int)tsuite->wrapping_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!wrap_supported(slot_id1, tsuite->wrapping_mech)) {
        testsuite_skip(NUM_WRAPPED_KEY_TESTS, "Slot %u doesn't support key "
                       "wrapping with %s (0x%x)", (unsigned int)slot_id1,
                       mech_to_str(tsuite->wrapping_mech.mechanism),
                       (unsigned int)tsuite->wrapping_mech.mechanism);
        goto testcase_cleanup;
    }

    if (!mech_supported(slot_id2, tsuite->wrapping_mech.mechanism)) {
        testsuite_skip(NUM_WRAPPED_KEY_TESTS, "Slot %u doesn't support %s (0x%x)",
                       (unsigned int)slot_id2,
                       mech_to_str(tsuite->wrapping_mech.mechanism),
                       (unsigned int)tsuite->wrapping_mech.mechanism);
        goto testcase_cleanup;
    }
    if (!unwrap_supported(slot_id2, tsuite->wrapping_mech)) {
        testsuite_skip(NUM_WRAPPED_KEY_TESTS, "Slot %u doesn't support key "
                       "wrapping with %s (0x%x)", (unsigned int)slot_id2,
                       mech_to_str(tsuite->wrapping_mech.mechanism),
                       (unsigned int)tsuite->wrapping_mech.mechanism);
        goto testcase_cleanup;
    }

    /*
     * Generate the wrapping key in slot 2.
     * For symmetric wrapping keys, generate the key from a random clear key
     * value, to be able to import the same key in the other token.
     * For RSA wrapping keys, the public key can be extracted and imported in
     * the other token.
     */
    switch (tsuite->wrapping_key_gen_mech.mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        if (p11_ahex_dump(&s, tsuite->rsa_publ_exp,
                          tsuite->rsa_publ_exp_len) == NULL) {
            testcase_error("p11_ahex_dump() failed");
            rc = CKR_FUNCTION_FAILED;
            goto testcase_cleanup;
        }

        if (!keysize_supported(slot_id1,
                               tsuite->wrapping_key_gen_mech.mechanism,
                               tsuite->rsa_modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          slot_id1, tsuite->rsa_modbits);
            goto testcase_cleanup;
        }
        if (!keysize_supported(slot_id2,
                               tsuite->wrapping_key_gen_mech.mechanism,
                               tsuite->rsa_modbits)) {
            testcase_skip("Token in slot %lu cannot be used with modbits='%lu'",
                          slot_id2, tsuite->rsa_modbits);
            goto testcase_cleanup;
        }

        if (is_ep11_token(slot_id1) || is_ep11_token(slot_id2)) {
            if (!is_valid_ep11_pubexp(tsuite->rsa_publ_exp,
                                      tsuite->rsa_publ_exp_len)) {
                testcase_skip("EP11 Token in cannot be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_cca_token(slot_id1) || is_cca_token(slot_id2)) {
            if (!is_valid_cca_pubexp(tsuite->rsa_publ_exp,
                                     tsuite->rsa_publ_exp_len)) {
                testcase_skip("CCA Token in scannot be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_soft_token(slot_id1) || is_soft_token(slot_id2)) {
            if (!is_valid_soft_pubexp(tsuite->rsa_publ_exp,
                                      tsuite->rsa_publ_exp_len)) {
                testcase_skip("Soft Token in scannot be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_tpm_token(slot_id1) || is_tpm_token(slot_id2)) {
            if (!is_valid_tpm_pubexp(tsuite->rsa_publ_exp,
                                     tsuite->rsa_publ_exp_len) ||
                !is_valid_tpm_modbits(tsuite->rsa_modbits)) {
                testcase_skip("TPM Token cannot " "be used with publ_exp.='%s'", s);
                goto testcase_cleanup;
            }
        }
        if (is_icsf_token(slot_id1) || is_icsf_token(slot_id2)) {
            if (!is_valid_icsf_pubexp(tsuite->rsa_publ_exp,
                                      tsuite->rsa_publ_exp_len) ||
                tsuite->rsa_modbits < 1024) {
                testcase_skip("ICSF Token cannot be used with publ_exp='%s'.", s);
                goto testcase_cleanup;
            }
        }
        rc = generate_RSA_PKCS_KeyPair(session2, tsuite->rsa_modbits,
                                       tsuite->rsa_publ_exp,
                                       tsuite->rsa_publ_exp_len,
                                       &publ_wrap_key2, &priv_wrap_key2);
        break;

    case CKM_AES_KEY_GEN:
        key_size = tsuite->sym_keylen;
        rc = funcs->C_GenerateRandom(session2, key, key_size);
        if (rc != CKR_OK) {
            testcase_error("C_GenerateRandom(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = create_AESKey(session2, CK_TRUE, key, key_size, CKK_AES,
                           &sym_wrap_key2);
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("AES key import is not allowed by policy");
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        break;

    case CKM_AES_XTS_KEY_GEN:
        key_size = tsuite->sym_keylen;
        rc = funcs->C_GenerateRandom(session2, key, key_size);
        if (rc != CKR_OK) {
            testcase_error("C_GenerateRandom(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = create_AESKey(session2, CK_TRUE, key, key_size, CKK_AES_XTS,
                           &sym_wrap_key2);
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("AES-XTS key import is not allowed by policy");
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        break;

    case CKM_DES3_KEY_GEN:
        key_size = 24;
        rc = funcs->C_GenerateRandom(session2, key, key_size);
        if (rc != CKR_OK) {
            testcase_error("C_GenerateRandom(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = create_DES3Key(session2, key, key_size, &sym_wrap_key2);
        break;

    case CKM_DES2_KEY_GEN:
        key_size = 16;
        rc = funcs->C_GenerateRandom(session2, key, key_size);
        if (rc != CKR_OK) {
            testcase_error("C_GenerateRandom(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = create_DES2Key(session2, key, key_size, &sym_wrap_key2);
        break;

    case CKM_DES_KEY_GEN:
        key_size = 8;
        rc = funcs->C_GenerateRandom(session2, key, key_size);
        if (rc != CKR_OK) {
            testcase_error("C_GenerateRandom(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = create_DESKey(session2, key, key_size, &sym_wrap_key2);
        break;

    default:
        testcase_error("Testcase does not support %s (%u)",
                       mech_to_str(tsuite->wrapping_key_gen_mech.mechanism),
                       (unsigned int)tsuite->wrapping_key_gen_mech.mechanism);
        goto testcase_cleanup;
    }

    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("generate wrapping key with mech %s (%u) in slot %lu "
                          "is not allowed by policy",
                          mech_to_str(tsuite->wrapping_key_gen_mech.mechanism),
                          (unsigned int)tsuite->wrapping_key_gen_mech.mechanism,
                          slot_id2);
            rc = CKR_OK;
            goto testcase_cleanup;
        }

        testcase_error("generate wrapping key with mech %s (%u) in slot %lu "
                       "failed, rc=%s",
                       mech_to_str(tsuite->wrapping_key_gen_mech.mechanism),
                       (unsigned int)tsuite->wrapping_key_gen_mech.mechanism,
                       slot_id2, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Import the wrapping key into slot 1 */
    switch (tsuite->wrapping_key_gen_mech.mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        rc = funcs->C_GetAttributeValue(session2, publ_wrap_key2,
                                        rsa_publ_tmpl, 2);
        if (rc != CKR_OK) {
            testcase_error("C_GetAttributeValue(), rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        rc = create_RSAPublicKey(session1, rsa_publ_tmpl[0].pValue,
                                 rsa_publ_tmpl[1].pValue,
                                 rsa_publ_tmpl[0].ulValueLen,
                                 rsa_publ_tmpl[1].ulValueLen, &publ_wrap_key1);
        break;

    case CKM_AES_KEY_GEN:
        memcpy(sym_tmpl[0].pValue, key, key_size);
        sym_tmpl[0].ulValueLen = key_size;

        rc = create_AESKey(session1, CK_TRUE, sym_tmpl[0].pValue, sym_tmpl[0].ulValueLen,
                           CKK_AES, &sym_wrap_key1);
        break;

    case CKM_AES_XTS_KEY_GEN:
        memcpy(sym_tmpl[0].pValue, key, key_size);
        sym_tmpl[0].ulValueLen = key_size;

        rc = create_AESKey(session1, CK_TRUE, sym_tmpl[0].pValue, sym_tmpl[0].ulValueLen,
                           CKK_AES_XTS, &sym_wrap_key1);
        break;

    case CKM_DES3_KEY_GEN:
        memcpy(sym_tmpl[0].pValue, key, key_size);
        sym_tmpl[0].ulValueLen = key_size;

        rc = create_DES3Key(session1, sym_tmpl[0].pValue,
                            sym_tmpl[0].ulValueLen, &sym_wrap_key1);
        break;

    case CKM_DES2_KEY_GEN:
        memcpy(sym_tmpl[0].pValue, key, key_size);
        sym_tmpl[0].ulValueLen = key_size;

        rc = create_DES2Key(session1, sym_tmpl[0].pValue,
                            sym_tmpl[0].ulValueLen, &sym_wrap_key1);
        break;

    case CKM_DES_KEY_GEN:
        memcpy(sym_tmpl[0].pValue, key, key_size);
        sym_tmpl[0].ulValueLen = key_size;

        rc = create_DESKey(session1, sym_tmpl[0].pValue, sym_tmpl[0].ulValueLen,
                           &sym_wrap_key1);
        break;

    default:
        testcase_error("Testcase does not support %s (%u)",
                       mech_to_str(tsuite->wrapping_key_gen_mech.mechanism),
                       (unsigned int)tsuite->wrapping_key_gen_mech.mechanism);
        goto testcase_cleanup;
    }

    if (rc != CKR_OK) {
        if (rc == CKR_POLICY_VIOLATION) {
            testcase_skip("import wrapping key in slot %lu is not allowed by policy",
                          slot_id1);
            rc = CKR_OK;
            goto testcase_cleanup;
        }

        testcase_error("import wrapping key in slot %lu failed, rc=%s",
                       slot_id1, p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Wrap/unwrap different keys with this wrapping key */
    for (i = 0; i< NUM_WRAPPED_KEY_TESTS; i++) {
        /* Some combinations can not work due to size restrictions */
        if (wrapped_key_tests[i].wrapped_key_gen_mech.mechanism == CKM_AES_XTS_KEY_GEN &&
            ((tsuite->wrapping_mech.mechanism == CKM_RSA_PKCS &&
              tsuite->rsa_modbits <= 512) ||
             (tsuite->wrapping_mech.mechanism == CKM_RSA_PKCS_OAEP &&
              tsuite->rsa_modbits <= 1024)))
                continue;

        if (wrapped_key_tests[i].wrapped_key_gen_mech.mechanism == CKM_DES_KEY_GEN &&
            tsuite->wrapping_mech.mechanism == CKM_AES_XTS)
            continue;

        rc = do_wrap_key_test(&wrapped_key_tests[i], &tsuite->wrapping_mech);
        if (rc != CKR_OK)
            break;
    }

testcase_cleanup:
    if (sym_wrap_key1 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session1, sym_wrap_key1);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    sym_wrap_key1 = CK_INVALID_HANDLE;
    if (sym_wrap_key2 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session2, sym_wrap_key2);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    sym_wrap_key2 = CK_INVALID_HANDLE;
    if (publ_wrap_key1 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session1, publ_wrap_key1);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    publ_wrap_key1 = CK_INVALID_HANDLE;
    if (publ_wrap_key2 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session2, publ_wrap_key2);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    publ_wrap_key2 = CK_INVALID_HANDLE;
    if (priv_wrap_key2 != CK_INVALID_HANDLE) {
        loc_rc = funcs->C_DestroyObject(session2, priv_wrap_key2);
        if (loc_rc != CKR_OK)
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(loc_rc));
    }
    priv_wrap_key2 = CK_INVALID_HANDLE;

    if (s != NULL)
        free(s);

    return rc;
}

CK_RV do_tok2tok_tests(void)
{
    CK_ULONG i;
    CK_RV rc;

    for (i = 0; i < NUM_WRAPPING_TESTS; i++) {
        rc = do_wrapping_test(&wrapping_tests[i]);
        if (rc != CKR_OK)
          break;
    }

    return CKR_OK;
}

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int i, ret = 1;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_RV rv;
    CK_FLAGS flags;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-slot1") == 0) {
            ++i;
            if (i >= argc) {
                printf("Slot number missing\n");
                return -1;
            }
            slot_id1 = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-slot2") == 0) {
            ++i;
            if (i >= argc) {
                printf("Slot number missing\n");
                return -1;
            }
            slot_id2 = atoi(argv[i]);
        }

        if (strcmp(argv[i], "-h") == 0) {
            printf("usage:  %s [-slot1 <num>] [-slot2 <num>] [-h]\n\n",
                   argv[0]);
            printf("By default, Slot #1 and #2 are used\n\n");
            return -1;
        }
    }

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;
    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    printf("Using slots #%lu and #%lu...\n\n", slot_id1, slot_id2);

    rv = do_GetFunctionList();
    if (rv != TRUE) {
        testcase_fail("do_GetFunctionList() rc = %s", p11_get_ckr(rv));
        goto out;
    }

    testcase_setup();
    testcase_begin("Starting...");

    // Initialize
    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    if ((rv = funcs->C_Initialize(&cinit_args))) {
        testcase_fail("C_Initialize() rc = %s", p11_get_ckr(rv));
        goto out;
    }

    // Open Session and login for slot 1
    testcase_new_assertion();
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = funcs->C_OpenSession(slot_id1, flags, NULL, NULL, &session1);
    if (rv != CKR_OK) {
        testcase_fail("C_OpenSession() on slot %lu rc = %s", slot_id1,
                      p11_get_ckr(rv));
        goto finalize;
    }
    testcase_pass("C_OpenSession on slot %lu", slot_id1);

    testcase_new_assertion();
    rv = funcs->C_Login(session1, CKU_USER, user_pin, user_pin_len);
    if (rv != CKR_OK) {
        testcase_fail("C_Login() on slot %lu rc = %s", slot_id1,
                      p11_get_ckr(rv));
        goto close_session;
    }
    testcase_pass("C_Login as User on slot %lu", slot_id1);

    // Open Session and login for slot 2
    testcase_new_assertion();
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = funcs->C_OpenSession(slot_id2, flags, NULL, NULL, &session2);
    if (rv != CKR_OK) {
        testcase_fail("C_OpenSession() on slot %lu rc = %s", slot_id2,
                      p11_get_ckr(rv));
        goto close_session;
    }
    testcase_pass("C_OpenSession on slot %lu", slot_id2);

    testcase_new_assertion();
    rv = funcs->C_Login(session2, CKU_USER, user_pin, user_pin_len);
    if (rv != CKR_OK) {
        testcase_fail("C_Login() on slot %lu rc = %s\n", slot_id2,
                       p11_get_ckr(rv));
        // ignore error
    } else {
        testcase_pass("C_Login as User on slot %lu", slot_id2);
    }

    rv = do_tok2tok_tests();
    if (rv != CKR_OK)
        goto close_session;

    ret = 0;

close_session:
    if (session1 != CK_INVALID_HANDLE) {
        rv = funcs->C_CloseSession(session1);
        if (rv != CKR_OK) {
            testcase_fail("C_CloseSession() on slot %lu rc = %s", slot_id1,
                          p11_get_ckr(rv));
        }
    }
    if (session2 != CK_INVALID_HANDLE) {
        rv = funcs->C_CloseSession(session2);
        if (rv != CKR_OK) {
            testcase_fail("C_CloseSession() on slot %lu rc = %s", slot_id2,
                          p11_get_ckr(rv));
        }
    }
finalize:
    rv = funcs->C_Finalize(NULL);
    if (rv != CKR_OK) {
        testcase_fail("C_Finalize() rc = %s", p11_get_ckr(rv));
    }
out:
    testcase_print_result();
    return testcase_return(ret);
}
