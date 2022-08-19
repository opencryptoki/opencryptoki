/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <pthread.h>
#include <string.h>             // for memcmp() et al
#include <stdlib.h>
#include <memory.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>

//
// Software MD5 implementation (OpenSSL based)
//

static void sw_md5_free(STDLL_TokData_t *tokdata, SESSION *sess,
                        CK_BYTE *context, CK_ULONG context_len)
{
    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(context_len);

    EVP_MD_CTX_free((EVP_MD_CTX *)context);
}

CK_RV sw_md5_init(DIGEST_CONTEXT *ctx)
{
    ctx->context_len = 1;
    ctx->context = (CK_BYTE *)EVP_MD_CTX_new();
    if (ctx->context == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        ctx->context_len = 0;
        return CKR_HOST_MEMORY;
    }

    if (!EVP_DigestInit_ex((EVP_MD_CTX *)ctx->context, EVP_md5(), NULL)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        EVP_MD_CTX_free((EVP_MD_CTX *)ctx->context);
        ctx->context = NULL;
        ctx->context_len = 0;
        return CKR_FUNCTION_FAILED;
    }

    ctx->state_unsaveable = CK_TRUE;
    ctx->context_free_func = sw_md5_free;

    return CKR_OK;
}

CK_RV sw_md5_hash(DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
                  CK_ULONG in_data_len, CK_BYTE *out_data,
                  CK_ULONG *out_data_len)
{
    unsigned int len;

    if (!ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (*out_data_len < MD5_HASH_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    if (ctx->context == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    len = *out_data_len;
    if (!EVP_DigestUpdate((EVP_MD_CTX *)ctx->context, in_data, in_data_len) ||
        !EVP_DigestFinal((EVP_MD_CTX *)ctx->context, out_data, &len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    *out_data_len = len;

    EVP_MD_CTX_free((EVP_MD_CTX *)ctx->context);
    ctx->context = NULL;
    ctx->context_free_func = NULL;

    return CKR_OK;
}

static CK_RV sw_md5_update(DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
                           CK_ULONG in_data_len)
{
    if (ctx->context == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!EVP_DigestUpdate((EVP_MD_CTX *)ctx->context, in_data, in_data_len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV sw_md5_final(DIGEST_CONTEXT *ctx, CK_BYTE *out_data,
                          CK_ULONG *out_data_len)
{
    unsigned int len;

    if (ctx->context == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (*out_data_len < MD5_HASH_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    len = *out_data_len;
    if (!EVP_DigestFinal((EVP_MD_CTX *)ctx->context, out_data, &len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    *out_data_len = len;

    EVP_MD_CTX_free((EVP_MD_CTX *)ctx->context);
    ctx->context = NULL;
    ctx->context_free_func = NULL;

    return CKR_OK;
}

CK_RV md5_init(STDLL_TokData_t *tokdata, SESSION *sess, DIGEST_CONTEXT *ctx,
               CK_MECHANISM *mech)
{
    UNUSED(tokdata);
    UNUSED(sess);

    if (mech->mechanism == CKM_MD5) {
        return sw_md5_init(ctx);
    } else {
        return CKR_MECHANISM_INVALID;
    }
}

CK_RV md5_hash(STDLL_TokData_t *tokdata, SESSION *sess, CK_BBOOL length_only,
               DIGEST_CONTEXT *ctx, CK_BYTE *in_data, CK_ULONG in_data_len,
               CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    UNUSED(tokdata);
    UNUSED(sess);

    if (!ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (length_only == TRUE) {
        *out_data_len = MD5_HASH_SIZE;
        return CKR_OK;
    }

    if (*out_data_len < MD5_HASH_SIZE) {
        *out_data_len = MD5_HASH_SIZE;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    if (ctx->context == NULL)
        return CKR_HOST_MEMORY;

    if (ctx->mech.mechanism == CKM_MD5)
        return sw_md5_hash(ctx, in_data, in_data_len, out_data,
                           out_data_len);
    else
        return CKR_MECHANISM_INVALID;
}

//
//
CK_RV md5_hash_update(STDLL_TokData_t *tokdata, SESSION *sess,
                      DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
                      CK_ULONG in_data_len)
{
    UNUSED(tokdata);
    UNUSED(sess);

    /* if no data to hash, just return */
    if (!in_data_len)
        return CKR_OK;

    if (ctx->mech.mechanism == CKM_MD5)
        return sw_md5_update(ctx, in_data, in_data_len);
    else
        return CKR_MECHANISM_INVALID;
}

CK_RV md5_hash_final(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_BYTE length_only, DIGEST_CONTEXT *ctx,
                     CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    UNUSED(tokdata);
    UNUSED(sess);

    if (!out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (length_only == TRUE) {
        *out_data_len = MD5_HASH_SIZE;
        return CKR_OK;
    }

    if (*out_data_len < MD5_HASH_SIZE) {
        *out_data_len = MD5_HASH_SIZE;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    if (ctx->mech.mechanism == CKM_MD5)
        return sw_md5_final(ctx, out_data, out_data_len);
    else
        return CKR_MECHANISM_INVALID;
}

// this routine gets called for two mechanisms actually:
//    CKM_MD5_HMAC
//    CKM_MD5_HMAC_GENERAL
//
CK_RV md5_hmac_sign(STDLL_TokData_t *tokdata,
                     SESSION *sess, CK_BBOOL length_only,
                     SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                     CK_ULONG in_data_len, CK_BYTE *out_data,
                     CK_ULONG *out_data_len)
{
    CK_ULONG hmac_len;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (ctx->mech.mechanism == CKM_MD5_HMAC_GENERAL) {
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;

        if (hmac_len == 0) {
            *out_data_len = 0;
            return CKR_OK;
        }
    } else {
        hmac_len = MD5_HASH_SIZE;
    }

    if (length_only == TRUE) {
        *out_data_len = hmac_len;
        return CKR_OK;
    }

    rc = openssl_specific_hmac_init(tokdata, ctx, &ctx->mech, ctx->key);
    if (rc != CKR_OK)
        return rc;

    rc = openssl_specific_hmac(ctx, in_data, in_data_len,
                               out_data, out_data_len, TRUE);
    if (rc != CKR_OK)
        return rc;

    return CKR_OK;
}

CK_RV md5_hmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                       SIGN_VERIFY_CONTEXT *ctx,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_RV rc;

    if (!sess || !ctx || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = openssl_specific_hmac_init(tokdata, ctx, &ctx->mech, ctx->key);
    if (rc != CKR_OK)
        return rc;

    rc = openssl_specific_hmac(ctx, in_data, in_data_len,
                               signature, &sig_len, FALSE);
    if (rc != CKR_OK)
        return rc;

    return CKR_OK;
}
