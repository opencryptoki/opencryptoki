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
}

CK_RV sw_aes_cbc(CK_BYTE *in_data,
                 CK_ULONG in_data_len,
                 CK_BYTE *out_data,
                 CK_ULONG *out_data_len,
                 CK_BYTE *init_v, CK_BYTE *key_value, CK_ULONG keylen,
                 CK_BYTE encrypt)
{
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
}
