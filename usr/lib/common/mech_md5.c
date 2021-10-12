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
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE hash[MD5_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    CK_MECHANISM digest_mech;
    CK_BYTE k_ipad[MD5_BLOCK_SIZE];
    CK_BYTE k_opad[MD5_BLOCK_SIZE];
    CK_ULONG key_bytes, hash_len, hmac_len;
    CK_ULONG i;
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

    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        goto done;
    }

    key_bytes = attr->ulValueLen;


    // build (K XOR ipad), (K XOR opad)
    //
    if (key_bytes > MD5_BLOCK_SIZE) {
        digest_mech.mechanism = CKM_MD5;
        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            goto done;
        }

        hash_len = sizeof(hash);
        rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
                               attr->pValue, attr->ulValueLen, hash, &hash_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Digest failed.\n");
            digest_mgr_cleanup(tokdata, sess, &digest_ctx);
            goto done;
        }

        memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

        for (i = 0; i < hash_len; i++) {
            k_ipad[i] = hash[i] ^ 0x36;
            k_opad[i] = hash[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, MD5_BLOCK_SIZE - i);
        memset(&k_opad[i], 0x5C, MD5_BLOCK_SIZE - i);
    } else {
        CK_BYTE *key = attr->pValue;

        for (i = 0; i < key_bytes; i++) {
            k_ipad[i] = key[i] ^ 0x36;
            k_opad[i] = key[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, MD5_BLOCK_SIZE - key_bytes);
        memset(&k_opad[i], 0x5C, MD5_BLOCK_SIZE - key_bytes);
    }

    digest_mech.mechanism = CKM_MD5;
    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    // inner hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        goto done;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_ipad,
                                  MD5_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        goto done;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
                                  in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        goto done;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        goto done;
    }

    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    // outer hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        goto done;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_opad,
                                  MD5_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        goto done;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash, hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        goto done;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        goto done;
    }

    memcpy(out_data, hash, hmac_len);
    *out_data_len = hmac_len;

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV md5_hmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                       SIGN_VERIFY_CONTEXT *ctx,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE hmac[MD5_HASH_SIZE];
    SIGN_VERIFY_CONTEXT hmac_ctx;
    CK_ULONG hmac_len, len;
    CK_RV rc;

    if (!sess || !ctx || !in_data || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (ctx->mech.mechanism == CKM_MD5_HMAC_GENERAL)
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;
    else
        hmac_len = MD5_HASH_SIZE;

    memset(&hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

    rc = sign_mgr_init(tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key,
                       FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign Mgr Init failed.\n");
        goto done;
    }
    len = sizeof(hmac);
    rc = sign_mgr_sign(tokdata, sess, FALSE, &hmac_ctx, in_data, in_data_len,
                       hmac, &len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign Mgr Sign failed.\n");
        goto done;
    }
    if ((len != hmac_len) || (len != sig_len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
        rc = CKR_SIGNATURE_LEN_RANGE;
        goto done;
    }

    if (CRYPTO_memcmp(hmac, signature, hmac_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        rc = CKR_SIGNATURE_INVALID;
    }

done:
    sign_mgr_cleanup(tokdata, sess, &hmac_ctx);
    return rc;
}
