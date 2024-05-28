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
#include "attributes.h"

#include <openssl/evp.h>
#include <openssl/crypto.h>

//
// Software SHA-1 implementation (OpenSSL based)
//

static void sw_sha1_free(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_BYTE *context, CK_ULONG context_len)
{
    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(context_len);

    EVP_MD_CTX_free((EVP_MD_CTX *)context);
}

CK_RV sw_sha1_init(DIGEST_CONTEXT *ctx)
{
    ctx->context_len = 1;
    ctx->context = (CK_BYTE *)EVP_MD_CTX_new();
    if (ctx->context == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        ctx->context_len = 0;
        return CKR_HOST_MEMORY;
    }

    if (!EVP_DigestInit_ex((EVP_MD_CTX *)ctx->context, EVP_sha1(), NULL)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        EVP_MD_CTX_free((EVP_MD_CTX *)ctx->context);
        ctx->context = NULL;
        ctx->context_len = 0;
        return CKR_FUNCTION_FAILED;
    }

    ctx->state_unsaveable = CK_TRUE;
    ctx->context_free_func = sw_sha1_free;

    return CKR_OK;
}

CK_RV sw_sha1_hash(DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
                   CK_ULONG in_data_len, CK_BYTE *out_data,
                   CK_ULONG *out_data_len)
{
    unsigned int len;

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

static CK_RV sw_sha1_update(DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
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

static CK_RV sw_sha1_final(DIGEST_CONTEXT *ctx, CK_BYTE *out_data,
                           CK_ULONG *out_data_len)
{
    unsigned int len;

    if (ctx->context == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (*out_data_len < SHA1_HASH_SIZE) {
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
            return sw_sha1_init(ctx);
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
    CK_RV rc;

    UNUSED(sess);

    if (!ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = get_sha_size(ctx->mech.mechanism, &hsize);
    if (rc != CKR_OK) {
        TRACE_ERROR("get_sha_size failed\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
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
    CK_RV rc;

    UNUSED(sess);

    if (!out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = get_sha_size(ctx->mech.mechanism, &hsize);
    if (rc != CKR_OK) {
        TRACE_ERROR("get_sha_size failed\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
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

// this routine gets called for these mechanisms actually:
// CKM_SHA_1_HMAC
// CKM_SHA_1_HMAC_GENERAL
// CKM_SHA224_HMAC
// CKM_SHA224_HMAC_GENERAL
// CKM_SHA256_HMAC
// CKM_SHA256_HMAC_GENERAL
// CKM_SHA384_HMAC
// CKM_SHA384_HMAC_GENERAL
// CKM_SHA512_HMAC
// CKM_SHA512_HMAC_GENERAL
// CKM_SHA512_224_HMAC
// CKM_SHA512_224_HMAC_GENERAL
// CKM_SHA512_256_HMAC
// CKM_SHA512_256_HMAC_GENERAL
// CKM_SHA3_224_HMAC
// CKM_SHA3_224_HMAC_GENERAL
// CKM_SHA3_256_HMAC
// CKM_SHA3_256_HMAC_GENERAL
// CKM_SHA3_384_HMAC
// CKM_SHA3_384_HMAC_GENERAL
// CKM_SHA3_512_HMAC
// CKM_SHA3_512_HMAC_GENERAL
// CKM_IBM_SHA3_224_HMAC
// CKM_IBM_SHA3_256_HMAC
// CKM_IBM_SHA3_384_HMAC
// CKM_IBM_SHA3_512_HMAC
//
CK_RV sha_hmac_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess, CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                    CK_ULONG in_data_len, CK_BYTE *out_data,
                    CK_ULONG *out_data_len)
{
    CK_MECHANISM digest_mech;
    CK_ULONG hmac_len, digest_hash_len, digest_block_size;
    CK_BBOOL general = FALSE;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;
    rc = get_hmac_digest(ctx->mech.mechanism, &digest_mech.mechanism, &general);
    if (rc != 0) {
        TRACE_ERROR("get_hmac_digest failed");
        return rc;
    }

    rc = get_sha_block_size(digest_mech.mechanism, &digest_block_size);
    if (rc != 0) {
        TRACE_ERROR("get_sha_block_size failed");
        return rc;
    }

    rc = get_sha_size(digest_mech.mechanism, &digest_hash_len);
    if (rc != 0) {
        TRACE_ERROR("get_sha_size failed");
        return rc;
    }

    if (general == FALSE) {
        hmac_len = digest_hash_len;
    } else {
        hmac_len = *(CK_ULONG *)ctx->mech.pParameter;
        if (hmac_len > digest_hash_len)
            return CKR_MECHANISM_PARAM_INVALID;

        if (hmac_len == 0) {
            *out_data_len = 0;
            return CKR_OK;
        }
    }

    if (length_only == TRUE) {
        *out_data_len = hmac_len;
        return CKR_OK;
    }

    if (token_specific.t_hmac_sign != NULL)
        return token_specific.t_hmac_sign(tokdata, sess, in_data,
                                          in_data_len, out_data, out_data_len);

    return openssl_specific_hmac(&sess->sign_ctx, in_data, in_data_len,
                                 out_data, out_data_len, TRUE);
}

// this routine gets called for these mechanisms actually:
// CKM_SHA_1_HMAC
// CKM_SHA_1_HMAC_GENERAL
// CKM_SHA224_HMAC
// CKM_SHA224_HMAC_GENERAL
// CKM_SHA256_HMAC
// CKM_SHA256_HMAC_GENERAL
// CKM_SHA384_HMAC
// CKM_SHA384_HMAC_GENERAL
// CKM_SHA512_HMAC
// CKM_SHA512_HMAC_GENERAL
// CKM_SHA512_224_HMAC
// CKM_SHA512_224_HMAC_GENERAL
// CKM_SHA512_256_HMAC
// CKM_SHA512_256_HMAC_GENERAL
// CKM_SHA3_224_HMAC
// CKM_SHA3_224_HMAC_GENERAL
// CKM_SHA3_256_HMAC
// CKM_SHA3_256_HMAC_GENERAL
// CKM_SHA3_384_HMAC
// CKM_SHA3_384_HMAC_GENERAL
// CKM_SHA3_512_HMAC
// CKM_SHA3_512_HMAC_GENERAL
// CKM_IBM_SHA3_224_HMAC
// CKM_IBM_SHA3_256_HMAC
// CKM_IBM_SHA3_384_HMAC
// CKM_IBM_SHA3_512_HMAC
//
CK_RV sha_hmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *signature, CK_ULONG sig_len)
{
    if (!sess || !ctx || !in_data || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (token_specific.t_hmac_verify != NULL)
        return token_specific.t_hmac_verify(tokdata, sess, in_data,
                                            in_data_len, signature, sig_len);

    return openssl_specific_hmac(&sess->verify_ctx, in_data, in_data_len,
                                 signature, &sig_len, FALSE);
}

CK_RV hmac_sign_init(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_MECHANISM *mech, CK_OBJECT_HANDLE hkey)
{
    if (token_specific.t_hmac_sign_init != NULL)
        return token_specific.t_hmac_sign_init(tokdata, sess, mech, hkey);

    return openssl_specific_hmac_init(tokdata, &sess->sign_ctx, mech, hkey);
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

    return openssl_specific_hmac_update(&sess->sign_ctx, in_data, in_data_len,
                                        TRUE);
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

    return openssl_specific_hmac_final(&sess->sign_ctx, signature, sig_len,
                                       TRUE);
}

CK_RV hmac_verify_init(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_MECHANISM *mech, CK_OBJECT_HANDLE hkey)
{
    if (token_specific.t_hmac_verify_init != NULL)
        return token_specific.t_hmac_verify_init(tokdata, sess, mech, hkey);

    return openssl_specific_hmac_init(tokdata, &sess->verify_ctx, mech, hkey);
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

    return openssl_specific_hmac_update(&sess->verify_ctx, in_data, in_data_len,
                                        FALSE);
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

    return openssl_specific_hmac_final(&sess->verify_ctx, signature, &sig_len,
                                       FALSE);
}

CK_RV ckm_generic_secret_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl)
{
    if (token_specific.t_generic_secret_key_gen == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    return token_specific.t_generic_secret_key_gen(tokdata, tmpl);
}

CK_RV ckm_sha_derive(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_MECHANISM *mech, OBJECT *base_key_obj,
                     CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                     CK_OBJECT_HANDLE *derived_key_handle)
{
    OBJECT *derived_key_obj = NULL;
    CK_BYTE derived_key_value[MAX_SHA_HASH_SIZE];
    DIGEST_CONTEXT ctx;
    CK_MECHANISM digest_mech;
    CK_ULONG hsize = 0, allowed_keysize = 0;
    CK_ULONG derived_keytype = 0, derived_keylen = 0;
    CK_ATTRIBUTE *base_key_value;
    CK_ATTRIBUTE *value_attr, *vallen_attr = NULL;
    CK_ULONG base_key_class, base_key_type;
    CK_RV rc;

    memset(&ctx, 0, sizeof(DIGEST_CONTEXT));
    memset(&digest_mech, 0, sizeof(CK_MECHANISM));

    rc = get_digest_from_mech(mech->mechanism, &digest_mech.mechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
        return rc;
    }

    rc = get_sha_size(digest_mech.mechanism, &hsize);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_sha_size failed\n", __func__);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_VALUE_LEN,
                                     &derived_keylen);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return rc;
    }

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_KEY_TYPE,
                                     &derived_keytype);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return rc;
    }

    /*
     * According to PKCS#11:
     * - no key length and no key type: CKK_GENERIC_SECRET of size <hsize>.
     * - no key type, but length given: CKK_GENERIC_SECRET if specified length.
     * - no key length but key type specified: key must have a well-defined
     *                                         length, otherwise error.
     * - key length and key type specified: length must be compatible with key
     *                                      type, otherwise error.
     * - key length must always be less or equal to the digest size.
     */
    if (derived_keytype == 0)
        derived_keytype = CKK_GENERIC_SECRET;

    switch (derived_keytype) {
    case CKK_GENERIC_SECRET:
        allowed_keysize = hsize;
        break;
    case CKK_DES:
        allowed_keysize = DES_KEY_SIZE;
        break;
    case CKK_DES2:
        allowed_keysize = 2 * DES_KEY_SIZE;
        break;
    case CKK_DES3:
        allowed_keysize = 3 * DES_KEY_SIZE;
        break;
    case CKK_AES:
        switch (derived_keylen) {
        case AES_KEY_SIZE_128:
        case AES_KEY_SIZE_192:
        case AES_KEY_SIZE_256:
            allowed_keysize = derived_keylen;
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        break;
    case CKK_AES_XTS:
        switch (derived_keylen) {
        case 2 * AES_KEY_SIZE_128:
        case 2 * AES_KEY_SIZE_256:
            allowed_keysize = derived_keylen;
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        return CKR_TEMPLATE_INCONSISTENT;
    }

    if (derived_keylen == 0)
        derived_keylen = allowed_keysize;

    if (derived_keylen > hsize || derived_keylen > allowed_keysize) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        return CKR_TEMPLATE_INCONSISTENT;
    }

    if (!template_get_class(base_key_obj->template, &base_key_class,
                            &base_key_type)) {
        TRACE_ERROR("Could not find CKA_CLASS in the template\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if (base_key_class != CKO_SECRET_KEY) {
        TRACE_ERROR("Base key is not a secret key\n");
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    switch (base_key_type) {
    case CKK_GENERIC_SECRET:
    case CKK_DES:
    case CKK_DES2:
    case CKK_DES3:
    case CKK_AES:
    case CKK_AES_XTS:
        break;
    default:
        TRACE_ERROR("Base key type is not supported\n");
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    /* Digest the base key to derive the derived key */
    rc = template_attribute_get_non_empty(base_key_obj->template,
                                          CKA_VALUE, &base_key_value);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the base key.\n");
        return rc;
    }

    rc = digest_mgr_init(tokdata, sess, &ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return rc;
    }

    rc = digest_mgr_digest(tokdata, sess, FALSE, &ctx,
                           base_key_value->pValue, base_key_value->ulValueLen,
                           derived_key_value, &hsize);
    if (rc != CKR_OK) {
        TRACE_ERROR("digest_mgr_digest failed with rc = %s\n", ock_err(rc));
        digest_mgr_cleanup(tokdata, sess, &ctx);
        return rc;
    }

    rc = build_attribute(CKA_VALUE, derived_key_value, derived_keylen,
                         &value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to build the attribute from CKA_VALUE, rc=%s.\n",
                    ock_err(rc));
        return rc;
    }

    switch (derived_keytype) {
    case CKK_GENERIC_SECRET:
    case CKK_AES:
    case CKK_AES_XTS:
        /* Supply CKA_VAUE_LEN since this is required for those key types */
        rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE*)&derived_keylen,
                             sizeof(derived_keylen), &vallen_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to build the attribute from CKA_VALUE_LEN, "
                        "rc=%s.\n", ock_err(rc));
            goto end;
        }
        break;
    case CKK_DES:
        if (des_check_weak_key(derived_key_value)) {
            TRACE_ERROR("Derived key is a weak DES key\n");
            rc = CKR_FUNCTION_FAILED;
            goto end;
        }
        break;
    default:
        break;
    }

    /* Create the derived key object and update the attributes */
    rc = object_mgr_create_skel(tokdata, sess, pTemplate, ulCount, MODE_DERIVE,
                                CKO_SECRET_KEY, derived_keytype,
                                &derived_key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Object Mgr create skeleton failed, rc=%s.\n", ock_err(rc));
        goto end;
    }

    /* Update the template in the object with the new attributes */
    rc = template_update_attribute(derived_key_obj->template, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto end;
    }
    value_attr = NULL;

    if (vallen_attr != NULL) {
        rc = template_update_attribute(derived_key_obj->template, vallen_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto end;
        }
        vallen_attr = NULL;
    }

    rc = key_mgr_derive_always_sensitive_never_extractable_attrs(tokdata,
                                                base_key_obj, derived_key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("key_mgr_derive_always_sensitive_never_extractable_attrs "
                    "failed\n");
        goto end;
    }

    rc = object_mgr_create_final(tokdata, sess, derived_key_obj,
                                 derived_key_handle);
    if (rc != CKR_OK) {
        TRACE_ERROR("Object Mgr create final failed, rc=%s.\n", ock_err(rc));
        goto end;
    }

    rc = CKR_OK;

end:
    if (rc != CKR_OK && derived_key_obj != NULL) {
        object_free(derived_key_obj);
        derived_key_handle = CK_INVALID_HANDLE;
    }

    if (value_attr != NULL)
        free(value_attr);
    if (vallen_attr != NULL)
        free(vallen_attr);

    return rc;
}
