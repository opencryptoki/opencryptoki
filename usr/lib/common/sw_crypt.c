/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <openssl/des.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <fcntl.h>
#include "pkcs11types.h"
#include "p11util.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"
#include "sw_crypt.h"

CK_RV sw_des3_cbc(CK_BYTE *in_data,
                  CK_ULONG in_data_len,
                  CK_BYTE *out_data,
                  CK_ULONG *out_data_len,
                  CK_BYTE *init_v, CK_BYTE *key_value, CK_BYTE encrypt)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    DES_key_schedule des_key1;
    DES_key_schedule des_key2;
    DES_key_schedule des_key3;

    const_DES_cblock key_SSL1, key_SSL2, key_SSL3;
    DES_cblock ivec;

    // the des decrypt will only fail if the data length is not evenly divisible
    // by DES_BLOCK_SIZE
    if (in_data_len % DES_BLOCK_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }
    // The key as passed in is a 24 byte string containing 3 keys
    // pick it apart and create the key schedules
    memcpy(&key_SSL1, key_value, (size_t) 8);
    memcpy(&key_SSL2, key_value + 8, (size_t) 8);
    memcpy(&key_SSL3, key_value + 16, (size_t) 8);
    DES_set_key_unchecked(&key_SSL1, &des_key1);
    DES_set_key_unchecked(&key_SSL2, &des_key2);
    DES_set_key_unchecked(&key_SSL3, &des_key3);

    memcpy(ivec, init_v, sizeof(ivec));

    // Encrypt or decrypt the data
    if (encrypt) {
        DES_ede3_cbc_encrypt(in_data,
                             out_data,
                             in_data_len,
                             &des_key1,
                             &des_key2, &des_key3, &ivec, DES_ENCRYPT);
        *out_data_len = in_data_len;
    } else {
        DES_ede3_cbc_encrypt(in_data,
                             out_data,
                             in_data_len,
                             &des_key1,
                             &des_key2, &des_key3, &ivec, DES_DECRYPT);

        *out_data_len = in_data_len;
    }

    return CKR_OK;
#else
    CK_RV rc;
    int outlen;
    const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
    EVP_CIPHER_CTX *ctx = NULL;

    if (in_data_len % DES_BLOCK_SIZE || in_data_len > INT_MAX) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, cipher,
                          NULL, key_value, init_v, encrypt ? 1 : 0) != 1
        || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
        || EVP_CipherUpdate(ctx, out_data, &outlen, in_data, in_data_len) != 1
        || EVP_CipherFinal_ex(ctx, out_data, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    *out_data_len = in_data_len;
    rc = CKR_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
#endif
}

CK_RV sw_aes_cbc(CK_BYTE *in_data,
                 CK_ULONG in_data_len,
                 CK_BYTE *out_data,
                 CK_ULONG *out_data_len,
                 CK_BYTE *init_v, CK_BYTE *key_value, CK_ULONG keylen,
                 CK_BYTE encrypt)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000L
    AES_KEY aes_key;

    UNUSED(out_data_len); //XXX can this parameter be removed ?

    memset(&aes_key, 0, sizeof(aes_key));

    // the aes decrypt will only fail if the data length is not evenly divisible
    // by AES_BLOCK_SIZE
    if (in_data_len % AES_BLOCK_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }

    // Encrypt or decrypt the data
    if (encrypt) {
        AES_set_encrypt_key(key_value, keylen * 8, &aes_key);
        AES_cbc_encrypt(in_data, out_data, in_data_len, &aes_key,
                        init_v, AES_ENCRYPT);
    } else {
        AES_set_decrypt_key(key_value, keylen * 8, &aes_key);
        AES_cbc_encrypt(in_data,  out_data, in_data_len, &aes_key,
                        init_v, AES_DECRYPT);
    }

    return CKR_OK;
#else
    CK_RV rc;
    int outlen;
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;

    UNUSED(out_data_len);

    if (keylen == 128 / 8)
        cipher = EVP_aes_128_cbc();
    else if (keylen == 192 / 8)
        cipher = EVP_aes_192_cbc();
    else if (keylen == 256 / 8)
        cipher = EVP_aes_256_cbc();

    if (in_data_len % AES_BLOCK_SIZE || in_data_len > INT_MAX) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        rc = CKR_DATA_LEN_RANGE;
        goto done;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, cipher,
                          NULL, key_value, init_v, encrypt ? 1 : 0) != 1
        || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
        || EVP_CipherUpdate(ctx, out_data, &outlen, in_data, in_data_len) != 1
        || EVP_CipherFinal_ex(ctx, out_data, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    rc = CKR_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
#endif
}
