/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  mech_sha.c
//
// Mechanisms for SHA-1 related routines
//
// The following applies to the software SHA implementation:
//    Written 2 September 1992, Peter C. Gutmann.
//    This implementation placed in the public domain.
//
//    Modified 1 June 1993, Colin Plumb.
//    Modified for the new SHS based on Peter Gutmann's work,
//    18 July 1994, Colin Plumb.
//    Gutmann's work.
//    Renamed to SHA and comments updated a bit 1 November 1995, Colin Plumb.
//    These modifications placed in the public domain.
//
//    Comments to pgut1@cs.aukuni.ac.nz
//

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

#include <openssl/sha.h>

//
// Software SHA-1 implementation (OpenSSL based)
//

void sw_sha1_init(DIGEST_CONTEXT *ctx)
{
    ctx->context_len = sizeof(SHA_CTX);
    ctx->context = (CK_BYTE *) malloc(sizeof(SHA_CTX));
    if (ctx->context == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        // TODO: propagate error up?
        return;
    }

    SHA1_Init((SHA_CTX *)ctx->context);
}

CK_RV sw_sha1_hash(DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
                   CK_ULONG in_data_len, CK_BYTE *out_data,
                   CK_ULONG *out_data_len)
{

    if (!ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (*out_data_len < SHA1_HASH_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    if (ctx->context == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    SHA1_Update((SHA_CTX *)ctx->context, in_data, in_data_len);
    SHA1_Final(out_data, (SHA_CTX *)ctx->context);
    *out_data_len = SHA1_HASH_SIZE;

    free(ctx->context);
    ctx->context = NULL;

    return CKR_OK;
}

CK_RV sw_sha1_update(DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
                     CK_ULONG in_data_len)
{
    if (ctx->context == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    SHA1_Update((SHA_CTX *)ctx->context, in_data, in_data_len);
    return CKR_OK;
}

CK_RV sw_sha1_final(DIGEST_CONTEXT *ctx, CK_BYTE *out_data,
                    CK_ULONG *out_data_len)
{
    if (ctx->context == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    SHA1_Final(out_data, (SHA_CTX *)ctx->context);
    *out_data_len = SHA1_HASH_SIZE;

    free(ctx->context);
    ctx->context = NULL;

    return CKR_OK;
}

CK_RV sha_init(STDLL_TokData_t *tokdata, SESSION *sess, DIGEST_CONTEXT *ctx,
               CK_MECHANISM *mech)
{
    UNUSED(sess);

    if (token_specific.t_sha_init != NULL) {
        return token_specific.t_sha_init(tokdata, ctx, mech);
    } else {
        /* For current tokens, continue legacy of using software
         *  implemented SHA-1 if the token does not have its own
         *  SHA-1 implementation.
         *  Future tokens' crypto should be its own so that
         *  opencryptoki is not responsible for crypto. If token
         *  does not have SHA-1, then should be mechanism not
         *  supported. JML
         */
        if (mech->mechanism == CKM_SHA_1) {
            sw_sha1_init(ctx);
            return CKR_OK;
        } else {
            return CKR_MECHANISM_INVALID;
        }
    }
}

CK_RV sha_hash(STDLL_TokData_t *tokdata, SESSION *sess, CK_BBOOL length_only,
               DIGEST_CONTEXT *ctx, CK_BYTE *in_data, CK_ULONG in_data_len,
               CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    CK_ULONG hsize;

    UNUSED(sess);

    if (!ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        hsize = SHA1_HASH_SIZE;
        break;
    case CKM_SHA224:
    case CKM_SHA512_224:
        hsize = SHA224_HASH_SIZE;
        break;
    case CKM_SHA256:
    case CKM_SHA512_256:
        hsize = SHA256_HASH_SIZE;
        break;
    case CKM_SHA384:
        hsize = SHA384_HASH_SIZE;
        break;
    case CKM_SHA512:
        hsize = SHA512_HASH_SIZE;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (length_only == TRUE) {
        *out_data_len = hsize;
        return CKR_OK;
    }

    if (*out_data_len < hsize) {
        *out_data_len = hsize;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    if (ctx->context == NULL)
        return CKR_HOST_MEMORY;

    if (token_specific.t_sha != NULL) {
        return token_specific.t_sha(tokdata, ctx, in_data, in_data_len,
                                    out_data, out_data_len);
    } else {
        if (ctx->mech.mechanism == CKM_SHA_1)
            return sw_sha1_hash(ctx, in_data, in_data_len, out_data,
                                out_data_len);
        else
            return CKR_MECHANISM_INVALID;
    }
}

//
//
CK_RV sha_hash_update(STDLL_TokData_t *tokdata, SESSION *sess,
                      DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
                      CK_ULONG in_data_len)
{
    UNUSED(sess);

    /* if no data to hash, just return */
    if (!in_data_len)
        return CKR_OK;

    if (token_specific.t_sha_update != NULL) {
        return token_specific.t_sha_update(tokdata, ctx, in_data, in_data_len);
    } else {
        if (ctx->mech.mechanism == CKM_SHA_1)
            return sw_sha1_update(ctx, in_data, in_data_len);
        else
            return CKR_MECHANISM_INVALID;
    }
}

CK_RV sha_hash_final(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_BYTE length_only, DIGEST_CONTEXT *ctx,
                     CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    CK_ULONG hsize;

    UNUSED(sess);

    if (!out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        hsize = SHA1_HASH_SIZE;
        break;
    case CKM_SHA224:
    case CKM_SHA512_224:
        hsize = SHA224_HASH_SIZE;
        break;
    case CKM_SHA256:
    case CKM_SHA512_256:
        hsize = SHA256_HASH_SIZE;
        break;
    case CKM_SHA384:
        hsize = SHA384_HASH_SIZE;
        break;
    case CKM_SHA512:
        hsize = SHA512_HASH_SIZE;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (length_only == TRUE) {
        *out_data_len = hsize;
        return CKR_OK;
    }

    if (*out_data_len < hsize) {
        *out_data_len = hsize;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    if (token_specific.t_sha_final != NULL) {
        return token_specific.t_sha_final(tokdata, ctx, out_data, out_data_len);
    } else {
        if (ctx->mech.mechanism == CKM_SHA_1)
            return sw_sha1_final(ctx, out_data, out_data_len);
        else
            return CKR_MECHANISM_INVALID;
    }
}

// this routine gets called for two mechanisms actually:
//    CKM_SHA_1_HMAC
//    CKM_SHA_1_HMAC_GENERAL
//
CK_RV sha1_hmac_sign(STDLL_TokData_t *tokdata,
                     SESSION *sess, CK_BBOOL length_only,
                     SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                     CK_ULONG in_data_len, CK_BYTE *out_data,
                     CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE hash[SHA1_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    CK_MECHANISM digest_mech;
    CK_BYTE k_ipad[SHA1_BLOCK_SIZE];
    CK_BYTE k_opad[SHA1_BLOCK_SIZE];
    CK_ULONG key_bytes, hash_len, hmac_len;
    CK_ULONG i;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (ctx->mech.mechanism == CKM_SHA_1_HMAC_GENERAL) {
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;

        if (hmac_len == 0) {
            *out_data_len = 0;
            return CKR_OK;
        }
    } else {
        hmac_len = SHA1_HASH_SIZE;
    }

    if (length_only == TRUE) {
        *out_data_len = hmac_len;
        return CKR_OK;
    }

    if (token_specific.t_hmac_sign != NULL)
        return token_specific.t_hmac_sign(tokdata, sess, in_data,
                                          in_data_len, out_data, out_data_len);

    /* Do manual hmac if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */

    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        return CKR_FUNCTION_FAILED;
    }

    key_bytes = attr->ulValueLen;


    // build (K XOR ipad), (K XOR opad)
    //
    if (key_bytes > SHA1_BLOCK_SIZE) {
        digest_mech.mechanism = CKM_SHA_1;
        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }

        hash_len = sizeof(hash);
        rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
                               attr->pValue, attr->ulValueLen, hash, &hash_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Digest failed.\n");
            return rc;
        }

        memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

        for (i = 0; i < hash_len; i++) {
            k_ipad[i] = hash[i] ^ 0x36;
            k_opad[i] = hash[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, SHA1_BLOCK_SIZE - i);
        memset(&k_opad[i], 0x5C, SHA1_BLOCK_SIZE - i);
    } else {
        CK_BYTE *key = attr->pValue;

        for (i = 0; i < key_bytes; i++) {
            k_ipad[i] = key[i] ^ 0x36;
            k_opad[i] = key[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, SHA1_BLOCK_SIZE - key_bytes);
        memset(&k_opad[i], 0x5C, SHA1_BLOCK_SIZE - key_bytes);
    }

    digest_mech.mechanism = CKM_SHA_1;
    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    // inner hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_ipad,
                                  SHA1_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
                                  in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    // outer hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_opad,
                                  SHA1_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash, hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    memcpy(out_data, hash, hmac_len);
    *out_data_len = hmac_len;

    return CKR_OK;
}

/** This routine gets called for two mechanisms actually:
 *    CKM_SHA224_HMAC
 *    CKM_SHA224_HMAC_GENERAL
 */
CK_RV sha224_hmac_sign(STDLL_TokData_t *tokdata,
                       SESSION *sess, CK_BBOOL length_only,
                       SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                       CK_ULONG in_data_len, CK_BYTE *out_data,
                       CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE hash[SHA224_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    CK_MECHANISM digest_mech;
    CK_BYTE k_ipad[SHA224_BLOCK_SIZE];
    CK_BYTE k_opad[SHA224_BLOCK_SIZE];
    CK_ULONG key_bytes, hash_len, hmac_len;
    CK_ULONG i;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (ctx->mech.mechanism == CKM_SHA224_HMAC_GENERAL) {
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;

        if (hmac_len == 0) {
            *out_data_len = 0;
            return CKR_OK;
        }
    } else {
        hmac_len = SHA224_HASH_SIZE;
    }

    if (length_only == TRUE) {
        *out_data_len = hmac_len;
        return CKR_OK;
    }

    if (token_specific.t_hmac_sign != NULL)
        return token_specific.t_hmac_sign(tokdata, sess, in_data,
                                          in_data_len, out_data, out_data_len);

    /* Do manual hmac if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */
    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }
    rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        return CKR_FUNCTION_FAILED;
    }

    key_bytes = attr->ulValueLen;

    // build (K XOR ipad), (K XOR opad)
    //
    if (key_bytes > SHA224_BLOCK_SIZE) {
        digest_mech.mechanism = CKM_SHA224;
        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }

        hash_len = sizeof(hash);
        rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
                               attr->pValue, attr->ulValueLen, hash, &hash_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Digest failed.\n");
            return rc;
        }

        memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

        for (i = 0; i < hash_len; i++) {
            k_ipad[i] = hash[i] ^ 0x36;
            k_opad[i] = hash[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, SHA224_BLOCK_SIZE - i);
        memset(&k_opad[i], 0x5C, SHA224_BLOCK_SIZE - i);
    } else {
        CK_BYTE *key = attr->pValue;

        for (i = 0; i < key_bytes; i++) {
            k_ipad[i] = key[i] ^ 0x36;
            k_opad[i] = key[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, SHA224_BLOCK_SIZE - key_bytes);
        memset(&k_opad[i], 0x5C, SHA224_BLOCK_SIZE - key_bytes);
    }

    digest_mech.mechanism = CKM_SHA224;
    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    // inner hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_ipad,
                                  SHA224_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
                                  in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    // outer hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_opad,
                                  SHA224_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash, hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    memcpy(out_data, hash, hmac_len);
    *out_data_len = hmac_len;

    return CKR_OK;
}

/** This routine gets called for two mechanisms actually:
 *    CKM_SHA256_HMAC
 *    CKM_SHA256_HMAC_GENERAL
 */
CK_RV sha256_hmac_sign(STDLL_TokData_t *tokdata,
                       SESSION *sess, CK_BBOOL length_only,
                       SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                       CK_ULONG in_data_len, CK_BYTE *out_data,
                       CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE hash[SHA256_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    CK_MECHANISM digest_mech;
    CK_BYTE k_ipad[SHA256_BLOCK_SIZE];
    CK_BYTE k_opad[SHA256_BLOCK_SIZE];
    CK_ULONG key_bytes, hash_len, hmac_len;
    CK_ULONG i;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (ctx->mech.mechanism == CKM_SHA256_HMAC_GENERAL) {
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;

        if (hmac_len == 0) {
            *out_data_len = 0;
            return CKR_OK;
        }
    } else {
        hmac_len = SHA256_HASH_SIZE;
    }

    if (length_only == TRUE) {
        *out_data_len = hmac_len;
        return CKR_OK;
    }

    if (token_specific.t_hmac_sign != NULL)
        return token_specific.t_hmac_sign(tokdata, sess, in_data,
                                          in_data_len, out_data, out_data_len);

    /* Do manual hmac if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */
    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }
    rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        return CKR_FUNCTION_FAILED;
    }

    key_bytes = attr->ulValueLen;

    // build (K XOR ipad), (K XOR opad)
    //
    if (key_bytes > SHA256_BLOCK_SIZE) {
        digest_mech.mechanism = CKM_SHA256;
        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }

        hash_len = sizeof(hash);
        rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
                               attr->pValue, attr->ulValueLen, hash, &hash_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Digest failed.\n");
            return rc;
        }

        memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

        for (i = 0; i < hash_len; i++) {
            k_ipad[i] = hash[i] ^ 0x36;
            k_opad[i] = hash[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, SHA256_BLOCK_SIZE - i);
        memset(&k_opad[i], 0x5C, SHA256_BLOCK_SIZE - i);
    } else {
        CK_BYTE *key = attr->pValue;

        for (i = 0; i < key_bytes; i++) {
            k_ipad[i] = key[i] ^ 0x36;
            k_opad[i] = key[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, SHA256_BLOCK_SIZE - key_bytes);
        memset(&k_opad[i], 0x5C, SHA256_BLOCK_SIZE - key_bytes);
    }

    digest_mech.mechanism = CKM_SHA256;
    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    // inner hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_ipad,
                                  SHA256_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
                                  in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    // outer hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_opad,
                                  SHA256_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash, hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    memcpy(out_data, hash, hmac_len);
    *out_data_len = hmac_len;

    return CKR_OK;
}

/** This routine gets called for two mechanisms actually:
 *    CKM_SHA384_HMAC
 *    CKM_SHA384_HMAC_GENERAL
 */
CK_RV sha384_hmac_sign(STDLL_TokData_t *tokdata,
                       SESSION *sess, CK_BBOOL length_only,
                       SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                       CK_ULONG in_data_len, CK_BYTE *out_data,
                       CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE hash[SHA384_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    CK_MECHANISM digest_mech;
    CK_BYTE k_ipad[SHA384_BLOCK_SIZE];
    CK_BYTE k_opad[SHA384_BLOCK_SIZE];
    CK_ULONG key_bytes, hash_len, hmac_len;
    CK_ULONG i;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (ctx->mech.mechanism == CKM_SHA384_HMAC_GENERAL) {
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;

        if (hmac_len == 0) {
            *out_data_len = 0;
            return CKR_OK;
        }
    } else {
        hmac_len = SHA384_HASH_SIZE;
    }

    if (length_only == TRUE) {
        *out_data_len = hmac_len;
        return CKR_OK;
    }

    if (token_specific.t_hmac_sign != NULL)
        return token_specific.t_hmac_sign(tokdata, sess, in_data,
                                          in_data_len, out_data, out_data_len);

    /* Do manual hmac if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */

    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }
    rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        return CKR_FUNCTION_FAILED;
    }

    key_bytes = attr->ulValueLen;

    // build (K XOR ipad), (K XOR opad)
    //
    if (key_bytes > SHA384_BLOCK_SIZE) {
        digest_mech.mechanism = CKM_SHA384;
        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }

        hash_len = sizeof(hash);
        rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
                               attr->pValue, attr->ulValueLen, hash, &hash_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Digest failed.\n");
            return rc;
        }

        memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

        for (i = 0; i < hash_len; i++) {
            k_ipad[i] = hash[i] ^ 0x36;
            k_opad[i] = hash[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, SHA384_BLOCK_SIZE - i);
        memset(&k_opad[i], 0x5C, SHA384_BLOCK_SIZE - i);
    } else {
        CK_BYTE *key = attr->pValue;

        for (i = 0; i < key_bytes; i++) {
            k_ipad[i] = key[i] ^ 0x36;
            k_opad[i] = key[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, SHA384_BLOCK_SIZE - key_bytes);
        memset(&k_opad[i], 0x5C, SHA384_BLOCK_SIZE - key_bytes);
    }

    digest_mech.mechanism = CKM_SHA384;
    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    // inner hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_ipad,
                                  SHA384_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
                                  in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    // outer hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_opad,
                                  SHA384_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash, hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    memcpy(out_data, hash, hmac_len);
    *out_data_len = hmac_len;

    return CKR_OK;
}

/** This routine gets called for 6 mechanisms actually:
 *    CKM_SHA512_HMAC
 *    CKM_SHA512_HMAC_GENERAL
 *    CKM_SHA512_224_HMAC
 *    CKM_SHA512_224_HMAC_GENERAL
 *    CKM_SHA512_256_HMAC
 *    CKM_SHA512_256_HMAC_GENERAL
 */
CK_RV sha512_hmac_sign(STDLL_TokData_t *tokdata,
                       SESSION *sess, CK_BBOOL length_only,
                       SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                       CK_ULONG in_data_len, CK_BYTE *out_data,
                       CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE hash[SHA512_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    CK_MECHANISM digest_mech;
    CK_BYTE k_ipad[SHA512_BLOCK_SIZE];
    CK_BYTE k_opad[SHA512_BLOCK_SIZE];
    CK_ULONG key_bytes, hash_len, hmac_len;
    CK_ULONG i;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (ctx->mech.mechanism == CKM_SHA512_HMAC_GENERAL ||
        ctx->mech.mechanism == CKM_SHA512_224_HMAC_GENERAL ||
        ctx->mech.mechanism == CKM_SHA512_256_HMAC_GENERAL) {
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;

        if (hmac_len == 0) {
            *out_data_len = 0;
            return CKR_OK;
        }
    } else if (ctx->mech.mechanism == CKM_SHA512_224_HMAC) {
        hmac_len = SHA224_HASH_SIZE;
    } else if (ctx->mech.mechanism == CKM_SHA512_224_HMAC) {
        hmac_len = SHA256_HASH_SIZE;
    } else {
        hmac_len = SHA512_HASH_SIZE;
    }

    if (length_only == TRUE) {
        *out_data_len = hmac_len;
        return CKR_OK;
    }

    if (token_specific.t_hmac_sign != NULL)
        return token_specific.t_hmac_sign(tokdata, sess, in_data,
                                          in_data_len, out_data, out_data_len);

    /* Do manual hmac if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */
    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }
    rc = template_attribute_find(key_obj->template, CKA_VALUE, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        return CKR_FUNCTION_FAILED;
    }

    key_bytes = attr->ulValueLen;

    // build (K XOR ipad), (K XOR opad)
    //
    if (key_bytes > SHA512_BLOCK_SIZE) {
        digest_mech.mechanism = CKM_SHA512;
        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }

        hash_len = sizeof(hash);
        rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
                               attr->pValue, attr->ulValueLen, hash, &hash_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Digest failed.\n");
            return rc;
        }

        memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

        for (i = 0; i < hash_len; i++) {
            k_ipad[i] = hash[i] ^ 0x36;
            k_opad[i] = hash[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, SHA512_BLOCK_SIZE - i);
        memset(&k_opad[i], 0x5C, SHA512_BLOCK_SIZE - i);
    } else {
        CK_BYTE *key = attr->pValue;

        for (i = 0; i < key_bytes; i++) {
            k_ipad[i] = key[i] ^ 0x36;
            k_opad[i] = key[i] ^ 0x5C;
        }

        memset(&k_ipad[i], 0x36, SHA512_BLOCK_SIZE - key_bytes);
        memset(&k_opad[i], 0x5C, SHA512_BLOCK_SIZE - key_bytes);
    }

    digest_mech.mechanism = CKM_SHA512;
    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    // inner hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_ipad,
                                  SHA512_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
                                  in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    /* Do manual hmac if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */
    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    // outer hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, k_opad,
                                  SHA512_BLOCK_SIZE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash, hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    memcpy(out_data, hash, hmac_len);
    *out_data_len = hmac_len;

    return CKR_OK;
}

CK_RV sha1_hmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                       SIGN_VERIFY_CONTEXT *ctx,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE hmac[SHA1_HASH_SIZE];
    SIGN_VERIFY_CONTEXT hmac_ctx;
    CK_ULONG hmac_len, len;
    CK_RV rc;

    if (!sess || !ctx || !in_data || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (token_specific.t_hmac_verify != NULL)
        return token_specific.t_hmac_verify(tokdata, sess, in_data,
                                            in_data_len, signature, sig_len);

    /* Do manual hmac verify  if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */
    if (ctx->mech.mechanism == CKM_SHA_1_HMAC_GENERAL)
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;
    else
        hmac_len = SHA1_HASH_SIZE;

    memset(&hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

    rc = sign_mgr_init(tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key);
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

    if (memcmp(hmac, signature, hmac_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        rc = CKR_SIGNATURE_INVALID;
    }

done:
    sign_mgr_cleanup(&hmac_ctx);
    return rc;
}

CK_RV sha224_hmac_verify(STDLL_TokData_t *tokdata,
                         SESSION *sess, SIGN_VERIFY_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE hmac[SHA224_HASH_SIZE];
    SIGN_VERIFY_CONTEXT hmac_ctx;
    CK_ULONG hmac_len, len;
    CK_RV rc;

    if (!sess || !ctx || !in_data || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (token_specific.t_hmac_verify != NULL)
        return token_specific.t_hmac_verify(tokdata, sess, in_data,
                                            in_data_len, signature, sig_len);

    /* Do manual hmac verify  if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */
    if (ctx->mech.mechanism == CKM_SHA224_HMAC_GENERAL)
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;
    else
        hmac_len = SHA224_HASH_SIZE;

    memset(&hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

    rc = sign_mgr_init(tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key);
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

    if (memcmp(hmac, signature, hmac_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        rc = CKR_SIGNATURE_INVALID;
    }

done:
    sign_mgr_cleanup(&hmac_ctx);
    return rc;
}

CK_RV sha256_hmac_verify(STDLL_TokData_t *tokdata,
                         SESSION *sess, SIGN_VERIFY_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE hmac[SHA256_HASH_SIZE];
    SIGN_VERIFY_CONTEXT hmac_ctx;
    CK_ULONG hmac_len, len;
    CK_RV rc;

    if (!sess || !ctx || !in_data || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (token_specific.t_hmac_verify != NULL)
        return token_specific.t_hmac_verify(tokdata, sess, in_data,
                                            in_data_len, signature, sig_len);

    /* Do manual hmac verify  if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */
    if (ctx->mech.mechanism == CKM_SHA256_HMAC_GENERAL)
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;
    else
        hmac_len = SHA256_HASH_SIZE;

    memset(&hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

    rc = sign_mgr_init(tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key);
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

    if (memcmp(hmac, signature, hmac_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        rc = CKR_SIGNATURE_INVALID;
    }

done:
    sign_mgr_cleanup(&hmac_ctx);

    return rc;
}

CK_RV sha384_hmac_verify(STDLL_TokData_t *tokdata,
                         SESSION *sess, SIGN_VERIFY_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE hmac[SHA384_HASH_SIZE];
    SIGN_VERIFY_CONTEXT hmac_ctx;
    CK_ULONG hmac_len, len;
    CK_RV rc;

    if (!sess || !ctx || !in_data || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (token_specific.t_hmac_verify != NULL)
        return token_specific.t_hmac_verify(tokdata, sess, in_data,
                                            in_data_len, signature, sig_len);

    /* Do manual hmac verify  if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */
    if (ctx->mech.mechanism == CKM_SHA384_HMAC_GENERAL)
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;
    else
        hmac_len = SHA384_HASH_SIZE;

    memset(&hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

    rc = sign_mgr_init(tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key);
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

    if (memcmp(hmac, signature, hmac_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        rc = CKR_SIGNATURE_INVALID;
    }
done:
    sign_mgr_cleanup(&hmac_ctx);

    return rc;
}

CK_RV sha512_hmac_verify(STDLL_TokData_t *tokdata,
                         SESSION *sess, SIGN_VERIFY_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE hmac[SHA512_HASH_SIZE];
    SIGN_VERIFY_CONTEXT hmac_ctx;
    CK_ULONG hmac_len, len;
    CK_RV rc;

    if (!sess || !ctx || !in_data || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (token_specific.t_hmac_verify != NULL)
        return token_specific.t_hmac_verify(tokdata, sess, in_data,
                                            in_data_len, signature, sig_len);

    /* Do manual hmac verify  if token doesn't have an hmac crypto call.
     * Secure tokens should not do manual hmac.
     */
    if (ctx->mech.mechanism == CKM_SHA512_HMAC_GENERAL)
        hmac_len = *(CK_ULONG *) ctx->mech.pParameter;
    else if (ctx->mech.mechanism == CKM_SHA512_224_HMAC)
        hmac_len = SHA224_HASH_SIZE;
    else if (ctx->mech.mechanism == CKM_SHA512_256_HMAC)
        hmac_len = SHA256_HASH_SIZE;
    else
        hmac_len = SHA512_HASH_SIZE;

    memset(&hmac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

    rc = sign_mgr_init(tokdata, sess, &hmac_ctx, &ctx->mech, FALSE, ctx->key);
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

    if (memcmp(hmac, signature, hmac_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        rc = CKR_SIGNATURE_INVALID;
    }
done:
    sign_mgr_cleanup(&hmac_ctx);

    return rc;
}

CK_RV hmac_sign_init(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_MECHANISM *mech, CK_OBJECT_HANDLE hkey)
{
    if (token_specific.t_hmac_sign_init != NULL)
        return token_specific.t_hmac_sign_init(tokdata, sess, mech, hkey);

    /* Return ok with the intention that the local hmac
     * implementation will get used instead.
     * For those tokens not supporting HMAC at all,
     * will need to return CKR_MECHANISM_INVALID.
     */
    return CKR_OK;
}

CK_RV hmac_sign_update(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BYTE *in_data, CK_ULONG in_data_len)
{
    SIGN_VERIFY_CONTEXT *ctx = &sess->sign_ctx;

    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (token_specific.t_hmac_sign_update != NULL)
        return token_specific.t_hmac_sign_update(tokdata, sess,
                                                 in_data, in_data_len);

    TRACE_ERROR("hmac-update is not supported\n");

    return CKR_MECHANISM_INVALID;
}

CK_RV hmac_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BYTE *signature, CK_ULONG *sig_len)
{
    SIGN_VERIFY_CONTEXT *ctx = &sess->sign_ctx;

    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (token_specific.t_hmac_sign_final != NULL)
        return token_specific.t_hmac_sign_final(tokdata, sess,
                                                signature, sig_len);

    TRACE_ERROR("hmac-final is not supported\n");

    return CKR_MECHANISM_INVALID;
}

CK_RV hmac_verify_init(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_MECHANISM *mech, CK_OBJECT_HANDLE hkey)
{
    if (token_specific.t_hmac_verify_init != NULL)
        return token_specific.t_hmac_verify_init(tokdata, sess, mech, hkey);

    /* Return ok with the intention that the local hmac
     * implementation will get used instead.
     * For those tokens not supporting HMAC at all,
     * will need to return CKR_MECHANISM_INVALID.
     */
    return CKR_OK;
}

CK_RV hmac_verify_update(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_BYTE *in_data, CK_ULONG in_data_len)
{
    SIGN_VERIFY_CONTEXT *ctx = &sess->sign_ctx;

    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (token_specific.t_hmac_verify_update != NULL)
        return token_specific.t_hmac_verify_update(tokdata, sess,
                                                   in_data, in_data_len);

    TRACE_ERROR("hmac-update is not supported\n");

    return CKR_MECHANISM_INVALID;
}

CK_RV hmac_verify_final(STDLL_TokData_t *tokdata, SESSION *sess,
                        CK_BYTE *signature, CK_ULONG sig_len)
{
    SIGN_VERIFY_CONTEXT *ctx = &sess->sign_ctx;

    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (token_specific.t_hmac_verify_final != NULL)
        return token_specific.t_hmac_verify_final(tokdata, sess,
                                                  signature, sig_len);

    TRACE_ERROR("hmac-final is not supported\n");

    return CKR_MECHANISM_INVALID;
}

CK_RV ckm_generic_secret_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl)
{
    if (token_specific.t_generic_secret_key_gen == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    return token_specific.t_generic_secret_key_gen(tokdata, tmpl);
}
