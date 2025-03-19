/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File:  mech_ec.c
 *
 * Mechanisms for Elliptic Curve (EC)
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "platform.h"
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "attributes.h"
#include "tok_spec_struct.h"
#include "trace.h"
#include "tok_specific.h"
#include "ec_defs.h"
#include "p11util.h"

#include "openssl/obj_mac.h"
#include <openssl/ec.h>

CK_RV get_ecsiglen(OBJECT *key_obj, CK_ULONG *size)
{
    CK_ATTRIBUTE *attr = NULL;
    int i;
    CK_RV rc;

    rc = template_attribute_get_non_empty(key_obj->template, CKA_ECDSA_PARAMS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_ECDSA_PARAMS for the key.\n");
        return rc;
    }

    /* loop thru supported curves to find the size.
     * both pkcs#11v2.20 and CCA expect the signature length to be
     * twice the length of p.
     * (See EC Signatures in pkcs#11v2.20 and docs for CSNDDSG.)
     */
    for (i = 0; i < NUMEC; i++) {
        if (!memcmp(attr->pValue, der_ec_supported[i].data,
                    MIN(attr->ulValueLen, der_ec_supported[i].data_size))) {
            *size = der_ec_supported[i].len_bits;
            /* round up if necessary */
            if ((*size % 8) == 0)
                *size = (*size / 8) * 2;
            else
                *size = ((*size / 8) + 1) * 2;

            TRACE_DEVEL("getlen, curve = %d, size = %lu\n",
                        der_ec_supported[i].len_bits, *size);
            return CKR_OK;
        }
    }

    TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));

    return CKR_MECHANISM_PARAM_INVALID;
}

CK_RV ckm_ec_key_pair_gen(STDLL_TokData_t *tokdata, TEMPLATE *publ_tmpl,
                          TEMPLATE *priv_tmpl)
{
    CK_RV rc;

    if (token_specific.t_ec_generate_keypair == NULL) {
        TRACE_ERROR("ec_generate_keypair not supported by this token\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = token_specific.t_ec_generate_keypair(tokdata, publ_tmpl, priv_tmpl);
    if (rc != CKR_OK)
        TRACE_ERROR("Key Generation failed\n");

    return rc;
}

CK_RV ckm_ec_sign(STDLL_TokData_t *tokdata,
                  SESSION *sess,
                  CK_BYTE *in_data,
                  CK_ULONG in_data_len,
                  CK_BYTE *out_data, CK_ULONG *out_data_len, OBJECT *key_obj)
{
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;

    if (token_specific.t_ec_sign == NULL) {
        TRACE_ERROR("ec_sign not supported by this token\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS, &keyclass);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    // this had better be a private key
    //
    if (keyclass != CKO_PRIVATE_KEY) {
        TRACE_ERROR("This operation requires a private key.\n");
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    rc = token_specific.t_ec_sign(tokdata, sess, in_data, in_data_len, out_data,
                                  out_data_len, key_obj);
    if (rc != CKR_OK)
        TRACE_DEVEL("EC Sign failed.\n");

    return rc;
}

CK_RV ec_sign(STDLL_TokData_t *tokdata,
              SESSION *sess,
              CK_BBOOL length_only,
              SIGN_VERIFY_CONTEXT *ctx,
              CK_BYTE *in_data,
              CK_ULONG in_data_len, CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ULONG plen;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = get_ecsiglen(key_obj, &plen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("get_ecsiglen failed.\n");
        goto done;
    }

    if (length_only == TRUE) {
        *out_data_len = plen;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < plen) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    rc = ckm_ec_sign(tokdata, sess, in_data, in_data_len, out_data,
                     out_data_len, key_obj);

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ckm_ec_verify(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG out_data_len, OBJECT *key_obj)
{
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;

    if (token_specific.t_ec_verify == NULL) {
        TRACE_ERROR("ec_verify not supported by this token\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS, &keyclass);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    // this had better be a public key
    //
    if (keyclass != CKO_PUBLIC_KEY) {
        TRACE_ERROR("This operation requires a public key.\n");
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    rc = token_specific.t_ec_verify(tokdata, sess, in_data, in_data_len,
                                    out_data, out_data_len, key_obj);
    if (rc != CKR_OK)
        TRACE_ERROR("Token specific ec verify failed.\n");

    return rc;
}

CK_RV ec_verify(STDLL_TokData_t *tokdata,
                SESSION *sess,
                SIGN_VERIFY_CONTEXT *ctx,
                CK_BYTE *in_data,
                CK_ULONG in_data_len, CK_BYTE *signature, CK_ULONG sig_len)
{
    OBJECT *key_obj = NULL;
    CK_ULONG plen;
    CK_RV rc;

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = get_ecsiglen(key_obj, &plen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("get_ecsiglen failed.\n");
        goto done;
    }
    // check input data length restrictions
    //
    if (sig_len > plen) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
        rc = CKR_SIGNATURE_LEN_RANGE;
        goto done;
    }
    rc = ckm_ec_verify(tokdata, sess, in_data, in_data_len, signature,
                       sig_len, key_obj);

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ec_hash_sign(STDLL_TokData_t *tokdata,
                   SESSION *sess,
                   CK_BBOOL length_only,
                   SIGN_VERIFY_CONTEXT *ctx,
                   CK_BYTE *in_data,
                   CK_ULONG in_data_len,
                   CK_BYTE *signature, CK_ULONG *sig_len)
{
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    SIGN_VERIFY_CONTEXT sign_ctx;
    CK_MECHANISM digest_mech;
    CK_MECHANISM sign_mech;
    CK_ULONG hash_len;
    CK_RV rc;

    if (!sess || !ctx || !in_data) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    memset(&digest_ctx, 0x0, sizeof(digest_ctx));
    memset(&sign_ctx, 0x0, sizeof(sign_ctx));

    rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
        return rc;
    }

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = get_sha_size(digest_mech.mechanism, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Get SHA Size failed.\n");
        return rc;
    }

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx, in_data,
                           in_data_len, hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Digest failed.\n");
        digest_mgr_cleanup(tokdata, sess, &digest_ctx);
        return rc;
    }

    sign_mech.mechanism = CKM_ECDSA;
    sign_mech.ulParameterLen = 0;
    sign_mech.pParameter = NULL;

    rc = sign_mgr_init(tokdata, sess, &sign_ctx, &sign_mech, FALSE, ctx->key,
                       FALSE, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign Mgr Init failed.\n");
        goto error;
    }

    rc = sign_mgr_sign(tokdata, sess, length_only, &sign_ctx, hash, hash_len,
                       signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Sign Mgr Sign failed.\n");

error:
    sign_mgr_cleanup(tokdata, sess, &sign_ctx);

    return rc;
}

CK_RV ec_hash_sign_update(STDLL_TokData_t *tokdata,
                          SESSION *sess,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *in_data, CK_ULONG in_data_len)
{
    RSA_DIGEST_CONTEXT *context = NULL;
    CK_MECHANISM digest_mech;
    CK_RV rc;

    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (RSA_DIGEST_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
            return rc;
        }

        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &context->hash_context,
                             &digest_mech, FALSE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }
        context->flag = TRUE;
        ctx->state_unsaveable |= context->hash_context.state_unsaveable;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                  in_data, in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    return CKR_OK;
}

CK_RV ec_hash_sign_final(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_BBOOL length_only,
                         SIGN_VERIFY_CONTEXT *ctx,
                         CK_BYTE *signature, CK_ULONG *sig_len)
{
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    RSA_DIGEST_CONTEXT *context = NULL;
    CK_ULONG hash_len;
    CK_MECHANISM sign_mech;
    SIGN_VERIFY_CONTEXT sign_ctx;
    CK_RV rc;

    if (!sess || !ctx || !sig_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    memset(&sign_ctx, 0x0, sizeof(sign_ctx));

    context = (RSA_DIGEST_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = ec_hash_sign_update(tokdata, sess, ctx, NULL, 0);
        TRACE_DEVEL("ec_hash_sign_update\n");
        if (rc != 0)
            return rc;
    }

    rc = get_sha_size(context->hash_context.mech.mechanism, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Get SHA Size failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_final(tokdata, sess, length_only,
                                 &context->hash_context, hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    sign_mech.mechanism = CKM_ECDSA;
    sign_mech.ulParameterLen = 0;
    sign_mech.pParameter = NULL;

    rc = sign_mgr_init(tokdata, sess, &sign_ctx, &sign_mech, FALSE, ctx->key,
                       FALSE, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign Mgr Init failed.\n");
        goto done;
    }
    //rc = sign_mgr_sign( sess, length_only, &sign_ctx, ber_data, ber_data_len,
    //signature, sig_len );
    rc = sign_mgr_sign(tokdata, sess, length_only, &sign_ctx, hash, hash_len,
                       signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Sign Mgr Sign failed.\n");

    if (length_only == TRUE || rc == CKR_BUFFER_TOO_SMALL) {
        sign_mgr_cleanup(tokdata, sess, &sign_ctx);
        return rc;
    }

done:
    sign_mgr_cleanup(tokdata, sess, &sign_ctx);

    return rc;
}

CK_RV ec_hash_verify(STDLL_TokData_t *tokdata,
                     SESSION *sess,
                     SIGN_VERIFY_CONTEXT *ctx,
                     CK_BYTE *in_data,
                     CK_ULONG in_data_len,
                     CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    SIGN_VERIFY_CONTEXT verify_ctx;
    CK_MECHANISM digest_mech;
    CK_MECHANISM verify_mech;
    CK_ULONG hash_len;
    CK_RV rc;

    if (!sess || !ctx || !in_data) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    memset(&digest_ctx, 0x0, sizeof(digest_ctx));
    memset(&verify_ctx, 0x0, sizeof(verify_ctx));

    rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
        return rc;
    }

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = get_sha_size(digest_mech.mechanism, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Get SHA Size failed.\n");
        return rc;
    }

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx, in_data,
                           in_data_len, hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Digest failed.\n");
        digest_mgr_cleanup(tokdata, sess, &digest_ctx);
        return rc;
    }
    // Verify the Signed BER-encoded Data block
    //
    verify_mech.mechanism = CKM_ECDSA;
    verify_mech.ulParameterLen = 0;
    verify_mech.pParameter = NULL;

    rc = verify_mgr_init(tokdata, sess, &verify_ctx, &verify_mech, FALSE,
                         ctx->key, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Verify Mgr Init failed.\n");
        goto done;
    }
    //rc = verify_mgr_verify( sess, &verify_ctx, ber_data, ber_data_len,
    //signature, sig_len );
    rc = verify_mgr_verify(tokdata, sess, &verify_ctx, hash, hash_len,
                           signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Verify Mgr Verify failed.\n");
done:
    sign_mgr_cleanup(tokdata, sess, &verify_ctx);

    return rc;
}


CK_RV ec_hash_verify_update(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            SIGN_VERIFY_CONTEXT *ctx,
                            CK_BYTE *in_data, CK_ULONG in_data_len)
{
    RSA_DIGEST_CONTEXT *context = NULL;
    CK_MECHANISM digest_mech;
    CK_RV rc;

    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (RSA_DIGEST_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
            return rc;
        }

        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &context->hash_context,
                             &digest_mech, FALSE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }
        context->flag = TRUE;
        ctx->state_unsaveable |= context->hash_context.state_unsaveable;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                  in_data, in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    return CKR_OK;
}

CK_RV ec_hash_verify_final(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    RSA_DIGEST_CONTEXT *context = NULL;
    CK_ULONG hash_len;
    CK_MECHANISM verify_mech;
    SIGN_VERIFY_CONTEXT verify_ctx;
    CK_RV rc;

    if (!sess || !ctx || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    memset(&verify_ctx, 0x0, sizeof(verify_ctx));

    context = (RSA_DIGEST_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = ec_hash_verify_update(tokdata, sess, ctx, NULL, 0);
        TRACE_DEVEL("ec_hash_verify_update\n");
        if (rc != 0)
            return rc;
    }

    rc = get_sha_size(context->hash_context.mech.mechanism, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Get SHA Size failed.\n");
        return rc;
    }

    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &context->hash_context,
                                 hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }
    verify_mech.mechanism = CKM_ECDSA;
    verify_mech.ulParameterLen = 0;
    verify_mech.pParameter = NULL;

    rc = verify_mgr_init(tokdata, sess, &verify_ctx, &verify_mech, FALSE,
                         ctx->key, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Verify Mgr Init failed.\n");
        goto done;
    }

    rc = verify_mgr_verify(tokdata, sess, &verify_ctx, hash, hash_len,
                           signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Verify Mgr Verify failed.\n");
done:
    verify_mgr_cleanup(tokdata, sess, &verify_ctx);

    return rc;
}

static CK_RV ckm_kdf(STDLL_TokData_t *tokdata, SESSION *sess, CK_ULONG kdf,
                     CK_BYTE *data, CK_ULONG data_len,
                     CK_BYTE *hash, CK_ULONG *h_len)
{
    CK_RV rc;
    DIGEST_CONTEXT ctx;
    CK_MECHANISM digest_mech;

    memset(&ctx, 0, sizeof(DIGEST_CONTEXT));
    memset(&digest_mech, 0, sizeof(CK_MECHANISM));

    rc = digest_from_kdf(kdf, &digest_mech.mechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("digest_from_kdf failed\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = get_sha_size(digest_mech.mechanism, h_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("get_sha_size failed\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = digest_mgr_init(tokdata, sess, &ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return rc;
    }

    rc = digest_mgr_digest(tokdata, sess, FALSE, &ctx, data, data_len, hash,
                           h_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("digest_mgr_digest failed with rc=0x%lx\n", rc);
        digest_mgr_cleanup(tokdata, sess, &ctx);
        return rc;
    }

    return CKR_OK;
}

CK_RV ckm_kdf_X9_63(STDLL_TokData_t *tokdata, SESSION *sess, CK_ULONG kdf,
                    CK_ULONG kdf_digest_len, const CK_BYTE *z, CK_ULONG z_len,
                    const CK_BYTE *shared_data, CK_ULONG shared_data_len,
                    CK_BYTE *key, CK_ULONG key_len)
{
    CK_ULONG counter_length = sizeof(uint32_t);
    CK_BYTE *ctx = NULL;
    CK_ULONG ctx_len;
    CK_BYTE hash[MAX_SUPPORTED_HASH_LENGTH];
    CK_ULONG h_len;
    CK_RV rc;
    uint32_t counter, counter_en;
    unsigned int i;

    /* Check max keylen according to ANSI X9.63 */
    /* digest_len * 2^32 */
    CK_ULONG max_keybytes = kdf_digest_len * 0x100000000ul;
    if (key_len >= max_keybytes) {
        TRACE_ERROR("Desired key length %lu greater than max supported key "
                    "length %lu.\n", key_len, max_keybytes);
        return CKR_KEY_SIZE_RANGE;
    }

    /*
     * Allocate memory for hash context:
     *  <secret> || <be32(counter 1..N)> || <sharedinfo>
     */
    ctx_len = z_len + counter_length + shared_data_len;
    ctx = malloc(ctx_len);
    if (!ctx)
        return CKR_HOST_MEMORY;

    memcpy(ctx, z, z_len);
    if (shared_data_len > 0)
        memcpy(ctx + z_len + counter_length, shared_data, shared_data_len);

    /* Provide key bytes according to ANSI X9.63 */
    counter = 1;
    for (i = 0; i < key_len / kdf_digest_len; i++) {
        counter_en = htobe32(counter);
        memcpy(ctx + z_len, &counter_en, counter_length);
        rc = ckm_kdf(tokdata, sess, kdf, ctx, ctx_len, hash, &h_len);
        if (rc != 0) {
            free(ctx);
            return rc;
        }
        memcpy(key + i * kdf_digest_len, hash, kdf_digest_len);
        counter++;
    }

    free(ctx);
    return CKR_OK;
}

CK_RV ckm_kdf_sp800_56c(STDLL_TokData_t *tokdata, SESSION *sess, CK_ULONG kdf,
                        CK_ULONG kdf_digest_len,
                        const CK_BYTE *z, CK_ULONG z_len,
                        const CK_BYTE *shared_data, CK_ULONG shared_data_len,
                        uint32_t purpose, CK_BYTE *key, CK_ULONG key_len)
{
    CK_ULONG counter_length = sizeof(uint32_t);
    CK_ULONG purpose_length = purpose > 0 ? sizeof(uint32_t) : 0;
    CK_BYTE *ctx = NULL;
    CK_ULONG ctx_len;
    CK_BYTE hash[MAX_SUPPORTED_HASH_LENGTH];
    CK_ULONG h_len;
    CK_RV rc;
    uint32_t counter, counter_en, purpose_en = htobe32(purpose);
    unsigned int i;

    /* Check max keylen according to FIPS SP800-56C */
    /* digest_len * 2^32 */
    CK_ULONG max_keybytes = kdf_digest_len * 0x100000000ul;
    if (key_len >= max_keybytes) {
        TRACE_ERROR("Desired key length %lu greater than max supported key "
                    "length %lu.\n", key_len, max_keybytes);
        return CKR_KEY_SIZE_RANGE;
    }

    /*
     * Allocate memory for hash context:
     *  be32(counter) || [be32(purpose)] || <secret> || <fixed.info>
     */
    ctx_len = counter_length + purpose_length + z_len + shared_data_len;
    ctx = malloc(ctx_len);
    if (!ctx)
        return CKR_HOST_MEMORY;

    if (purpose > 0)
        memcpy(ctx + counter_length, &purpose_en, purpose_length);
    memcpy(ctx + counter_length + purpose_length, z, z_len);
    if (shared_data_len > 0)
        memcpy(ctx + counter_length + purpose_length + z_len,
               shared_data, shared_data_len);

    /* Provide key bytes according to ANSI X9.63 */
    counter = 1;
    for (i = 0; i < key_len / kdf_digest_len; i++) {
        counter_en = htobe32(counter);
        memcpy(ctx, &counter_en, counter_length);
        rc = ckm_kdf(tokdata, sess, kdf, ctx, ctx_len, hash, &h_len);
        if (rc != 0) {
            free(ctx);
            return rc;
        }
        memcpy(key + i * kdf_digest_len, hash, kdf_digest_len);
        counter++;
    }

    free(ctx);
    return CKR_OK;
}

CK_RV ckm_ecdh_pkcs_derive(STDLL_TokData_t *tokdata, SESSION *sess,
                           CK_VOID_PTR other_pubkey, CK_ULONG other_pubkey_len,
                           OBJECT* base_key_obj,
                           CK_BYTE *secret_value, CK_ULONG *secret_value_len,
                           CK_MECHANISM_PTR mech, CK_BBOOL count_statistic)
{
    CK_RV rc;
    CK_ATTRIBUTE *attr;
    CK_BYTE *oid_p;
    CK_ULONG oid_len;
    CK_ULONG class = 0, keytype = 0;

    if (token_specific.t_ecdh_pkcs_derive == NULL) {
        TRACE_ERROR("ecdh pkcs derive is not supported by this token.\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    /* Get curve oid from CKA_ECDSA_PARAMS */
    rc = template_attribute_get_non_empty(base_key_obj->template,
                                          CKA_ECDSA_PARAMS, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_ECDSA_PARAMS for the base key.\n");
        goto done;
    }

    oid_p = attr->pValue;
    oid_len = attr->ulValueLen;

    if (!template_get_class(base_key_obj->template, &class, &keytype)) {
        TRACE_ERROR("Could not find CKA_CLASS in the template\n");
        rc = CKR_TEMPLATE_INCOMPLETE;
        goto done;
    }

    if (class != CKO_PRIVATE_KEY || keytype != CKK_EC) {
        TRACE_ERROR("Base key is not an EC private key\n");
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }

    /* Extract EC private key (D) from base_key */
    rc = template_attribute_get_non_empty(base_key_obj->template,
                                          CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the base key.\n");
        goto done;
    }

    /* Call token specific ECDH key derivation function */
    rc = token_specific.t_ecdh_pkcs_derive(tokdata,
                                           (CK_BYTE *) (attr->pValue),
                                           attr->ulValueLen,
                                           (CK_BYTE *) other_pubkey,
                                           other_pubkey_len, secret_value,
                                           secret_value_len, oid_p, oid_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Token specific ecdh pkcs derive failed with rc=%ld.\n",
                    rc);
    }

done:
    if (count_statistic == TRUE && rc == CKR_OK)
        INC_COUNTER(tokdata, sess, mech, base_key_obj, POLICY_STRENGTH_IDX_0);

    return rc;
}

/**
 * From PKCS#11 v2.40: PKCS #3 Diffie-Hellman key derivation
 *
 *   [...] It computes a Diffie-Hellman secret value from the public value and
 *   private key according to PKCS #3, and truncates the result according to the
 *   CKA_KEY_TYPE attribute of the template and, if it has one and the key type
 *   supports it, the CKA_VALUE_LEN attribute of the template.
 *
 *   For some key types, the derived key length is known, for others it
 *   must be specified in the template through CKA_VALUE_LEN.
 *
 */
static CK_ULONG keylen_from_keytype(CK_ULONG keytype)
{
    switch (keytype) {
    case CKK_DES:
        return 8;
    case CKK_DES2:
        return 16;
    case CKK_DES3:
        return 24;
        /* for all other keytypes CKA_VALUE_LEN must be specified */
    default:
        return 0;
    }
}

CK_RV ecdh_get_derived_key_size(CK_ULONG prime_len, CK_BYTE *curve_oid,
                                CK_ULONG curve_oid_len, CK_EC_KDF_TYPE kdf,
                                CK_ULONG key_type, CK_ULONG value_len,
                                CK_ULONG *key_len)
{
    CK_RV rc;
    CK_ULONG key_len_type;
    CK_MECHANISM_TYPE digest_mech;
    int i;

    *key_len = value_len;
    key_len_type = keylen_from_keytype(key_type);

    if (*key_len == 0) {
        *key_len = key_len_type;
    } else if (key_len_type != 0 && *key_len != key_len_type) {
        TRACE_ERROR("Derived key length does not work for the key type\n");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    if (prime_len == 0) {
        for (i = 0; i < NUMEC; i++) {
            if (der_ec_supported[i].data_size == curve_oid_len &&
                memcmp(der_ec_supported[i].data, curve_oid,
                       curve_oid_len) == 0)
                prime_len = (der_ec_supported[i].len_bits + 7) / 8;
        }

        if (prime_len == 0) {
            TRACE_ERROR("Curve not supported\n");
            return CKR_CURVE_NOT_SUPPORTED;
        }
    }

    /*
     * If no CKA_VALUE_LEN is specified and the key type does also not dictate
     * a certain length, then take then digest length of the used KDF, or if
     * no KDF, the size of the derived shared secret.
     */
    if (*key_len == 0) {
        /* Determine digest length */
        if (kdf != CKD_NULL && kdf != CKD_IBM_HYBRID_NULL) {
            rc = digest_from_kdf(kdf, &digest_mech);
            if (rc != CKR_OK) {
                TRACE_ERROR("Cannot determine mech from kdf.\n");
                return CKR_ARGUMENTS_BAD;
            }
            rc = get_sha_size(digest_mech, key_len);
            if (rc != CKR_OK) {
                TRACE_ERROR("Cannot determine SHA digest size.\n");
                return CKR_ARGUMENTS_BAD;
            }
        } else {
            *key_len = prime_len;
        }

        switch (key_type) {
        case CKK_AES:
            if (*key_len != AES_KEY_SIZE_128 &&
                *key_len != AES_KEY_SIZE_192 &&
                *key_len != AES_KEY_SIZE_256) {
                TRACE_ERROR("Derived key length does not work for the key "
                            "type\n");
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        case CKK_AES_XTS:
            if (*key_len != (AES_KEY_SIZE_128 * 2) &&
                *key_len != (AES_KEY_SIZE_256 * 2)) {
                TRACE_ERROR("Derived key length does not work for the key "
                            "type\n");
                return CKR_TEMPLATE_INCONSISTENT;
            }
            break;
        default:
            /* DES/DES2/DE3 has already been checked above */
            break;
        }
    }

    /* If no KDF used, max possible key length is the prime_len */
    if ((kdf == CKD_NULL || kdf == CKD_IBM_HYBRID_NULL) &&
        *key_len > prime_len) {
        TRACE_ERROR("Can only provide %ld key bytes without a KDF, "
                    "but %ld bytes requested.\n", prime_len, *key_len);
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

CK_RV ecdh_pkcs_derive(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_MECHANISM *mech, OBJECT *base_key_obj,
                       CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                       CK_OBJECT_HANDLE *derived_key_obj,
                       CK_BBOOL count_statistic)
{
    CK_RV rc;
    CK_ULONG class = 0, keytype = 0, key_len = 0;
    CK_ATTRIBUTE *value_attr, *vallen_attr = NULL;
    OBJECT *temp_obj = NULL;
    CK_ECDH1_DERIVE_PARAMS *pParms;
    CK_BYTE z_value[MAX_ECDH_SHARED_SECRET_SIZE];
    CK_ULONG z_len = 0, kdf_digest_len;
    CK_MECHANISM_TYPE digest_mech;
    CK_BYTE *derived_key = NULL;
    CK_ULONG derived_key_len;

    /* Check parm length */
    if (mech->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS) ||
        mech->pParameter == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* Check buffers */
    pParms = mech->pParameter;
    if (pParms == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (pParms->pPublicData == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* Get the keytype to use when deriving the key object */
    rc = pkcs_get_keytype(pTemplate, ulCount, mech, &keytype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("get_keytype failed with rc=0x%lx\n", rc);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* Optional shared data can only be provided together with a KDF */
    if ((pParms->kdf == CKD_NULL || pParms->kdf == CKD_IBM_HYBRID_NULL)
        && (pParms->pSharedData != NULL || pParms->ulSharedDataLen != 0)) {
        TRACE_ERROR("No KDF specified, but shared data ptr is not NULL.\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    rc = object_mgr_create_skel(tokdata, sess, pTemplate, ulCount, MODE_DERIVE,
                                class, keytype, &temp_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Object Mgr create skeleton failed, rc=0x%lx.\n", rc);
        return rc;
    }

    if (token_specific.t_ecdh_pkcs_derive_kdf != NULL) {
        rc = token_specific.t_ecdh_pkcs_derive_kdf(tokdata, sess, base_key_obj,
                                                   pParms, temp_obj,
                                                   class, keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("t_ecdh_pkcs_derive_kdf failed, rc=0x%lx.\n", rc);
            goto end;
        }

        INC_COUNTER(tokdata, sess, mech, base_key_obj, POLICY_STRENGTH_IDX_0);

        goto derive_done;
    }

    /* Derive the shared secret */
    rc = ckm_ecdh_pkcs_derive(tokdata, sess, pParms->pPublicData,
                              pParms->ulPublicDataLen, base_key_obj, z_value,
                              &z_len, mech, count_statistic);
    if (rc != CKR_OK) {
        TRACE_ERROR("Error deriving the shared secret.\n");
        goto end;
    }

    /* Determine derived key length */
    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_VALUE_LEN,
                                     &key_len);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        goto end;
    }

    rc = ecdh_get_derived_key_size(z_len, NULL, 0, pParms->kdf, keytype,
                                   key_len, &key_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Can not determine the derived key length\n");
        goto end;
    }

    /* Determine digest length */
    if (pParms->kdf != CKD_NULL && pParms->kdf != CKD_IBM_HYBRID_NULL) {
        rc = digest_from_kdf(pParms->kdf, &digest_mech);
        if (rc != CKR_OK) {
            TRACE_ERROR("Cannot determine mech from kdf.\n");
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto end;
        }
        rc = get_sha_size(digest_mech, &kdf_digest_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("Cannot determine SHA digest size.\n");
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto end;
        }
    } else {
        kdf_digest_len = z_len;
    }

    /* Allocate memory for derived key */
    derived_key_len = ((key_len / kdf_digest_len) + 1) * kdf_digest_len;
    derived_key = malloc(derived_key_len);
    if (!derived_key) {
        TRACE_ERROR("Cannot allocate %lu bytes for derived key.\n",
                    derived_key_len);
        rc = CKR_HOST_MEMORY;
        goto end;
    }

    /* Apply KDF function to shared secret */
    switch (pParms->kdf) {
    case CKD_NULL:
    case CKD_IBM_HYBRID_NULL:
        memcpy(derived_key, z_value, z_len);
        break;

    case CKD_SHA1_KDF:
    case CKD_SHA224_KDF:
    case CKD_SHA256_KDF:
    case CKD_SHA384_KDF:
    case CKD_SHA512_KDF:
    case CKD_SHA3_224_KDF:
    case CKD_SHA3_256_KDF:
    case CKD_SHA3_384_KDF:
    case CKD_SHA3_512_KDF:
    case CKD_IBM_HYBRID_SHA1_KDF:
    case CKD_IBM_HYBRID_SHA224_KDF:
    case CKD_IBM_HYBRID_SHA256_KDF:
    case CKD_IBM_HYBRID_SHA384_KDF:
    case CKD_IBM_HYBRID_SHA512_KDF:
        rc = ckm_kdf_X9_63(tokdata, sess, pParms->kdf, kdf_digest_len,
                           z_value, z_len, pParms->pSharedData,
                           pParms->ulSharedDataLen, derived_key,
                           derived_key_len);
        if (rc != CKR_OK)
            goto end;
        break;

    case CKD_SHA1_KDF_SP800:
    case CKD_SHA224_KDF_SP800:
    case CKD_SHA256_KDF_SP800:
    case CKD_SHA384_KDF_SP800:
    case CKD_SHA512_KDF_SP800:
    case CKD_SHA3_224_KDF_SP800:
    case CKD_SHA3_256_KDF_SP800:
    case CKD_SHA3_384_KDF_SP800:
    case CKD_SHA3_512_KDF_SP800:
        rc = ckm_kdf_sp800_56c(tokdata, sess, pParms->kdf, kdf_digest_len,
                               z_value, z_len, pParms->pSharedData,
                               pParms->ulSharedDataLen, 0, derived_key,
                               derived_key_len);
        if (rc != CKR_OK)
            goto end;
        break;

    default:
        TRACE_ERROR("Unsupported KDF: 0x%lx\n", pParms->kdf);
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto end;
    }

    /* Return the hashed and truncated derived bytes as CKA_VALUE attribute */
    rc = build_attribute(CKA_VALUE, derived_key, key_len, &value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to build the attribute from CKA_VALUE, rc=0x%lx.\n",
                    rc);
        goto end;
    }

    switch (keytype) {
    case CKK_GENERIC_SECRET:
    case CKK_SHA_1_HMAC:
    case CKK_SHA256_HMAC:
    case CKK_SHA384_HMAC:
    case CKK_SHA512_HMAC:
    case CKK_SHA224_HMAC:
    case CKK_SHA3_224_HMAC:
    case CKK_SHA3_256_HMAC:
    case CKK_SHA3_384_HMAC:
    case CKK_SHA3_512_HMAC:
    case CKK_SHA512_224_HMAC:
    case CKK_SHA512_256_HMAC:
    case CKK_AES:
    case CKK_AES_XTS:
        /* Supply CKA_VAUE_LEN since this is required for those key types */
        rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE*)&key_len,
                             sizeof(key_len), &vallen_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to build the attribute from CKA_VALUE_LEN, "
                        "rc=0x%lx.\n", rc);
            free(value_attr);
            goto end;
        }
        break;
    default:
        break;
    }

    /* Update the template in the object with the new attribute */
    rc = template_update_attribute(temp_obj->template, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(value_attr);
        free(vallen_attr);
        goto end;
    }

    if (vallen_attr != NULL) {
        rc = template_update_attribute(temp_obj->template, vallen_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            free(vallen_attr);
            goto end;
        }
    }

derive_done:
    /* At this point, the derived key is fully constructed...assign an object
     * handle and store the key */
    rc = object_mgr_create_final(tokdata, sess, temp_obj, derived_key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Object Mgr create final failed, rc=0x%lx.\n", rc);
        goto end;
    }
    temp_obj = NULL;

    rc = CKR_OK;

end:
    if (derived_key != NULL)
      free(derived_key);
    if (temp_obj != NULL)
        object_free(temp_obj);

    return rc;
}

static int ec_nid_from_oid(CK_BYTE *oid, CK_ULONG oid_length)
{
    int i;

    for (i = 0; i < NUMEC; i++) {
        if (der_ec_supported[i].data_size == oid_length &&
            memcmp(der_ec_supported[i].data, oid, oid_length) == 0)
            return der_ec_supported[i].nid;
    }

    return -1;
}

static int ec_curve_type_from_oid(CK_BYTE *oid, CK_ULONG oid_length)
{
    int i;

    for (i = 0; i < NUMEC; i++) {
        if (der_ec_supported[i].data_size == oid_length &&
            memcmp(der_ec_supported[i].data, oid, oid_length) == 0)
            return der_ec_supported[i].curve_type;
    }

    return -1;
}

/*
 * Uncompress a compressed EC public key. EC public keys can be un-compressed,
 * compressed, or hybrid. The fist byte of an EC public key determines if it
 * is compressed or not:
 * POINT_CONVERSION_COMPRESSED = 0x02
 * POINT_CONVERSION_UNCOMPRESSED = 0x04
 * POINT_CONVERSION_HYBRID = 0x06
 * Bit 0x01 determines if it is odd or even
 * The out_pubkey buffer size must be at least 1+2*privkey_len.
 */
CK_RV ec_uncompress_public_key(CK_BYTE *curve, CK_ULONG curve_len,
                               CK_BYTE *pubkey, CK_ULONG pubkey_len,
                               CK_ULONG privkey_len,
                               CK_BYTE *out_pubkey, CK_ULONG *out_len)
{
    EC_GROUP *group = NULL;
    EC_POINT *point = NULL;
    CK_ULONG pad_len = 0;
    BIGNUM *bn_x = NULL;
    BIGNUM *bn_y = NULL;
    BN_CTX *ctx = NULL;
    CK_RV rc;
    int y_bit = 0;
    CK_BYTE *x;
    int nid, type;

    if (*out_len < 1 + 2 * privkey_len)
        return CKR_BUFFER_TOO_SMALL;

    type = ec_curve_type_from_oid(curve, curve_len);
    if (type == -1)
        return CKR_CURVE_NOT_SUPPORTED;

    if (type == MONTGOMERY_CURVE || type == EDWARDS_CURVE) {
        /*
         * Public keys of Montgomery and Edwards curves are always compressed
         * and are not uncompressed.
         */
        memcpy(out_pubkey, pubkey, pubkey_len);
        *out_len = pubkey_len;
        return CKR_OK;
    }

    *out_len = 1 + 2 * privkey_len;

    if (pubkey_len == 1 + privkey_len &&
        (pubkey[0] == POINT_CONVERSION_COMPRESSED ||
         pubkey[0] == POINT_CONVERSION_COMPRESSED + 1)) {
        /* Compressed form */
        x = pubkey + 1;
        y_bit = pubkey[0] & 0x01;
    } else if (pubkey_len == 1 + 2 * privkey_len &&
               pubkey[0] == POINT_CONVERSION_UNCOMPRESSED) {
        /* Uncompressed form */
        memcpy(out_pubkey, pubkey, pubkey_len);
        return CKR_OK;
    } else if (pubkey_len == 1 + 2 * privkey_len &&
            (pubkey[0] == POINT_CONVERSION_HYBRID ||
             pubkey[0] == POINT_CONVERSION_HYBRID + 1)) {
        /* Hybrid form */
        out_pubkey[0] = POINT_CONVERSION_UNCOMPRESSED;
        memcpy(out_pubkey + 1, pubkey + 1, pubkey_len - 1);
        return CKR_OK;
    } else if (pubkey_len <= 2 * privkey_len) {
        /* Without format byte (and leading zeros), treat as uncompressed */
        pad_len = 2 * privkey_len - pubkey_len;
        out_pubkey[0] = POINT_CONVERSION_UNCOMPRESSED;
        memset(out_pubkey + 1, 0, pad_len);
        memcpy(out_pubkey + 1 + pad_len, pubkey, pubkey_len);
        return CKR_OK;
    } else {
        return CKR_KEY_SIZE_RANGE;
    }

    nid = ec_nid_from_oid(curve, curve_len);
    if (nid == -1)
        return CKR_CURVE_NOT_SUPPORTED;

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        TRACE_ERROR("Curve %d is not supported by openssl. Cannot decompress "
                    "public key\n", nid);
        return CKR_CURVE_NOT_SUPPORTED;
    }

    point = EC_POINT_new(group);
    if (point == NULL) {
        rc = CKR_FUNCTION_FAILED;
        goto end;
    }

    bn_x = BN_bin2bn(x, privkey_len, NULL);
    bn_y = BN_new();
    ctx = BN_CTX_new();

    if (!EC_POINT_set_compressed_coordinates(group,
                                             point, bn_x, y_bit, ctx)) {
        rc = CKR_FUNCTION_FAILED;
        goto end;
    }

    if (!EC_POINT_is_on_curve(group, point, ctx)) {
        rc = CKR_FUNCTION_FAILED;
        goto end;
    }

    if (!EC_POINT_get_affine_coordinates(group, point, bn_x, bn_y, ctx)) {
        rc = CKR_FUNCTION_FAILED;
        goto end;
    }

    out_pubkey[0] = POINT_CONVERSION_UNCOMPRESSED;
    memcpy(out_pubkey + 1, x, privkey_len);
    BN_bn2binpad(bn_y, out_pubkey + 1 + privkey_len, privkey_len);
    rc = CKR_OK;

end:
    if (ctx)
        BN_CTX_free(ctx);
    if (point)
        EC_POINT_free(point);
    if (group)
        EC_GROUP_free(group);
    if (bn_x)
        BN_free(bn_x);
    if (bn_y)
        BN_free(bn_y);

    return rc;
}

/*
 * Calculate the EC public key (ECPoint) from the EC private key.
 */
CK_RV ec_point_from_priv_key(CK_BYTE *parms, CK_ULONG parms_len,
                             CK_BYTE *d, CK_ULONG d_len,
                             CK_BYTE **point, CK_ULONG *point_len)
{
    EC_POINT *pub_key = NULL;
    EC_GROUP *group = NULL;
    int nid, p_len;
    BIGNUM *bn_d = NULL, *bn_x = NULL, *bn_y = NULL;
    CK_RV rc = CKR_OK;
    CK_BYTE *ec_point = NULL;
    CK_ULONG ec_point_len;

    nid = ec_nid_from_oid(parms, parms_len);
    if (nid == -1)
        return CKR_CURVE_NOT_SUPPORTED;

    bn_d = BN_secure_new();
    if (bn_d == NULL) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (BN_bin2bn(d, d_len, bn_d) == NULL) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto done;
    }

    p_len = (EC_GROUP_get_degree(group) + 7) / 8;

    pub_key = EC_POINT_new(group);
    if (pub_key == NULL) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (!EC_POINT_mul(group, pub_key, bn_d, NULL, NULL, NULL)) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Get (X,Y) as BIGNUMs */
    bn_x = BN_new();
    bn_y = BN_new();
    if (bn_x == NULL || bn_y == NULL) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    if (!EC_POINT_get_affine_coordinates(group, pub_key, bn_x, bn_y, NULL)) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    ec_point_len = 1 + 2 * p_len;
    ec_point = malloc(ec_point_len);
    if (ec_point == NULL) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    ec_point[0] = POINT_CONVERSION_UNCOMPRESSED;
    BN_bn2binpad(bn_x, ec_point + 1, p_len);
    BN_bn2binpad(bn_y, ec_point + 1 + p_len, p_len);

    *point = ec_point;
    *point_len = ec_point_len;
    ec_point = NULL;

done:
    if (pub_key)
        EC_POINT_free(pub_key);
    BN_clear_free(bn_x);
    BN_clear_free(bn_y);
    BN_clear_free(bn_d);
    if (group != NULL)
        EC_GROUP_free(group);

    return rc;
}

/*
 * Return the EC point from the specified data.
 * As per PKCS#11, a token MUST be able to accept this value encoded
 * as a raw octet string (as per section A.5.2 of [ANSI X9.62]).
 * A token MAY, in addition, support accepting this value as a
 * DER-encoded ECPoint (as per section E.6 of [ANSI X9.62]) i.e.
 * the same as a CKA_EC_POINT encoding.
 *
 * The EC point (encoded or raw) may or may not have a format byte.
 * The returned buffer in ec_point must be freed by the caller if
 * parameter 'allocated' is true on return.
 */
int ec_point_from_public_data(const CK_BYTE *data, CK_ULONG data_len,
                              CK_ULONG prime_len, CK_BBOOL allow_raw,
                              CK_BBOOL *allocated, CK_BYTE **ec_point,
                              CK_ULONG *ec_point_len)
{
    CK_ULONG value_len = 0, field_len = 0, pad_len;
    CK_BYTE *value = NULL;
    CK_BYTE *buff = NULL;
    CK_BYTE form;
    CK_RV rc;

    if (!allow_raw)
        goto check_encoded;

    /* Check if this could be a raw EC Point */
    form  = data[0] & ~0x01;
    switch (form) {
    case POINT_CONVERSION_COMPRESSED:
        if (data_len == prime_len + 1) {
            /* Length is as expected for a raw EC point in compressed form */
            *ec_point = (CK_BYTE *)data;
            *ec_point_len = data_len;
            *allocated = FALSE;
            TRACE_DEVEL("Raw EC Point in compressed form\n");
            return CKR_OK;
        }
        break;
    case POINT_CONVERSION_UNCOMPRESSED:
    case POINT_CONVERSION_HYBRID:
        if (data_len == 2 * prime_len + 1) {
            /* Length is as expected for a raw EC point in uncompressed form */
            *ec_point = (CK_BYTE *)data;
            *ec_point_len = data_len;
            *allocated = FALSE;
            TRACE_DEVEL("Raw EC Point in uncompressed/hybrid form\n");
            return CKR_OK;
        }
        break;
    default:
        /* No valid format byte */
        break;
    }

check_encoded:
    /* If we reach here, try to BER decode it as OCTET-STRING */
    rc = ber_decode_OCTET_STRING((CK_BYTE *)data, &value, &value_len,
                                  &field_len);
    if (rc == CKR_OK && field_len == data_len && value_len <= data_len - 2) {
         /* Looks like a BER encoded EC Point */
        form  = value[0] & ~0x01;
        TRACE_DEVEL("Encoded EC Point, form: %02x\n", form);
        switch (form) {
        case POINT_CONVERSION_COMPRESSED:
            if (value_len == prime_len + 1) {
                /* Length is as expected for an EC point in compressed form */
                *ec_point = (CK_BYTE *)value;
                *ec_point_len = value_len;
                *allocated = FALSE;
                TRACE_DEVEL("Encoded EC Point in compressed form\n");
                return CKR_OK;
            }
            break;
        case POINT_CONVERSION_UNCOMPRESSED:
        case POINT_CONVERSION_HYBRID:
            if (value_len == 2 * prime_len + 1) {
                /* Length is as expected for an EC point in uncompressed form */
                *ec_point = (CK_BYTE *)value;
                *ec_point_len = value_len;
                *allocated = FALSE;
                TRACE_DEVEL("Encoded EC Point in uncompressed/hybrid form\n");
                return CKR_OK;
            }
            break;
        default:
            /* No valid format byte */
            break;
        }
    } else {
        /* It is not BER encoded */
        TRACE_DEVEL("Raw EC Point\n");
        value = NULL;
        value_len = 0;
    }

    /*
     * If we reach here, the length do not match, neither as a raw EC Point,
     * nor for a BER encoded EC Point. Must be a EC Point without a format
     * byte, and possibly without leading zeros. Build a full EC Point
     * in uncompressed form, and pad with zeros on the left (if needed).
     */
    if ((value_len != 0 ? value_len : data_len) <= prime_len) {
        /* Must be larger than prime length to have x and y */
        TRACE_ERROR("Not a valid EC Point: data too short\n");
        return CKR_PUBLIC_KEY_INVALID;
    }
    if ((value_len != 0 ? value_len : data_len) > 2 * prime_len) {
        /* Can not be larger than 2 * prime length */
        TRACE_ERROR("Not a valid EC Point: data too large\n");
        return CKR_PUBLIC_KEY_INVALID;
    }

    buff = malloc(1 + 2 * prime_len);
    if (buff == NULL) {
        TRACE_ERROR("Malloc failed\n");
        return CKR_HOST_MEMORY;
    }

    buff[0] = POINT_CONVERSION_UNCOMPRESSED;
    pad_len = 2 * prime_len - (value_len != 0 ? value_len : data_len);
    memset(buff + 1, 0, pad_len);
    if (value != NULL)
        memcpy(buff + 1 + pad_len, value, value_len);
    else
        memcpy(buff + 1 + pad_len, data, data_len);

    *ec_point = (CK_BYTE *)buff;
    *ec_point_len = 1 + 2 * prime_len;
    *allocated = TRUE;
    TRACE_DEVEL("EC Point built from no format byte and trimmed\n");

    return CKR_OK;
}

/*
 * Like ec_point_from_public_data(), but returns the EC point in uncompressed
 * form. If the public data is in compressed form, it uncompresses it.
 * If it is in hybrid form, convert it into uncompressed form.
 */
int ec_point_uncompressed_from_public_data(const CK_BYTE *data,
                                           CK_ULONG data_len,
                                           CK_ULONG prime_len,
                                           CK_BYTE *curve_oid,
                                           CK_ULONG curve_oid_len,
                                           CK_BBOOL allow_raw,
                                           CK_BBOOL *allocated,
                                           CK_BYTE **ec_point,
                                           CK_ULONG *ec_point_len)
{
    CK_RV rc;
    CK_BYTE form;
    CK_ULONG ec_point2_len;
    CK_BYTE *ec_point2 = NULL;

    rc = ec_point_from_public_data(data, data_len, prime_len, allow_raw,
                                   allocated, ec_point, ec_point_len);
    if (rc != CKR_OK)
        return rc;

    form  = (*ec_point)[0] & ~0x01;
    switch (form) {
    case POINT_CONVERSION_COMPRESSED:
    case POINT_CONVERSION_HYBRID:
        ec_point2_len = 1 + 2 * prime_len;
        ec_point2 = malloc(ec_point2_len);
        if (ec_point2 == NULL) {
            TRACE_ERROR("Malloc failed\n");
            rc = CKR_HOST_MEMORY;
            break;
        }

        rc = ec_uncompress_public_key(curve_oid, curve_oid_len,
                                      *ec_point, *ec_point_len, prime_len,
                                      ec_point2, &ec_point2_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to uncompress\n");
            break;
        }

        if (*allocated)
            free(*ec_point);
        *ec_point = ec_point2;
        *ec_point_len = ec_point2_len;
        *allocated = TRUE;
        ec_point2 = NULL;
        break;

    case POINT_CONVERSION_UNCOMPRESSED:
    default:
        break;
    }

    if (rc != CKR_OK && *allocated) {
        free(*ec_point);
        *ec_point = NULL;
        *ec_point_len = 0;
        *allocated = FALSE;
    }
    if (ec_point2 != NULL)
        free(ec_point2);

    return rc;
}

CK_RV ecdh_aes_key_wrap(STDLL_TokData_t *tokdata, SESSION *sess,
                        CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                        CK_BYTE *in_data, CK_ULONG in_data_len,
                        CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    CK_ECDH_AES_KEY_WRAP_PARAMS *params;
    CK_ATTRIBUTE *ec_params = NULL, *ec_point = NULL;
    CK_MECHANISM ec_keygen_mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
    CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, &ecdh_params,
                               sizeof(ecdh_params) };
    CK_MECHANISM aeskw_kwm_mech = { CKM_AES_KEY_WRAP_KWP, NULL, 0 };
    ENCR_DECR_CONTEXT aeskw_ctx = { 0 };
    CK_OBJECT_HANDLE ec_publ_key_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE ec_priv_key_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE aes_key_handle = CK_INVALID_HANDLE;
    CK_OBJECT_CLASS aes_key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE aes_key_type = CKK_AES;
    CK_ULONG aes_key_size, field_len = 0, pub_ec_point_len = 0;
    CK_ULONG wrapped_key_len = 0, total_len;
    CK_BYTE *pub_ec_point = NULL;
    CK_BBOOL ck_true = TRUE;
    CK_BBOOL ck_false = TRUE;
    OBJECT *key_obj = NULL, *pub_key_obj = NULL;
    CK_RV rc, rc2;

    CK_ATTRIBUTE ec_publ_key_tmpl[] = {
        { CKA_EC_PARAMS, NULL, 0 },
        { CKA_HIDDEN, &ck_true, sizeof(ck_true) },
        { CKA_TOKEN, &ck_false, sizeof(ck_false) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        { CKA_WRAP, &ck_false, sizeof(ck_false) },
        { CKA_ENCRYPT, &ck_false, sizeof(ck_false) },
        { CKA_VERIFY, &ck_false, sizeof(ck_false) },
        { CKA_VERIFY_RECOVER, &ck_false, sizeof(ck_false) },
        { CKA_DERIVE, &ck_true, sizeof(ck_true) },
    };
    CK_ATTRIBUTE ec_priv_key_tmpl[] = {
        { CKA_HIDDEN, &ck_true, sizeof(ck_true) },
        { CKA_SENSITIVE, &ck_true, sizeof(ck_true) },
        { CKA_TOKEN, &ck_false, sizeof(ck_false) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        { CKA_UNWRAP, &ck_false, sizeof(ck_false) },
        { CKA_DECRYPT, &ck_false, sizeof(ck_false) },
        { CKA_SIGN, &ck_false, sizeof(ck_false) },
        { CKA_SIGN_RECOVER, &ck_false, sizeof(ck_false) },
        { CKA_DERIVE, &ck_true, sizeof(ck_true) },
    };
    CK_ATTRIBUTE aes_key_tmpl[] = {
        { CKA_CLASS, &aes_key_class, sizeof(aes_key_class) },
        { CKA_KEY_TYPE, &aes_key_type, sizeof(aes_key_type) },
        { CKA_VALUE_LEN, &aes_key_size, sizeof(aes_key_size) },
        { CKA_HIDDEN, &ck_true, sizeof(ck_true) },
        { CKA_SENSITIVE, &ck_true, sizeof(ck_true) },
        { CKA_TOKEN, &ck_false, sizeof(ck_false) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        { CKA_WRAP, &ck_false, sizeof(ck_false) },
        { CKA_UNWRAP, &ck_true, sizeof(ck_true) },
        { CKA_ENCRYPT, &ck_false, sizeof(ck_false) },
        { CKA_DECRYPT, &ck_false, sizeof(ck_false) },
        { CKA_SIGN, &ck_false, sizeof(ck_false) },
        { CKA_VERIFY, &ck_false, sizeof(ck_false) },
        { CKA_DERIVE, &ck_false, sizeof(ck_false) },
    };

    params = (CK_ECDH_AES_KEY_WRAP_PARAMS *)ctx->mech.pParameter;

    /* Get the EC parameters of the EC public key used with this mechanism */
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_EC_PARAMS,
                                          &ec_params);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to get CKA_EC_PARAMS.\n");
        goto done;
    }

    /* Generate a temporary EC key pair using the same EC parameters */
    ec_publ_key_tmpl[0] = *ec_params;
    rc = key_mgr_generate_key_pair(tokdata, sess, &ec_keygen_mech,
                                   ec_publ_key_tmpl, sizeof(ec_publ_key_tmpl) /
                                                       sizeof(CK_ATTRIBUTE),
                                   ec_priv_key_tmpl, sizeof(ec_priv_key_tmpl) /
                                                       sizeof(CK_ATTRIBUTE),
                                   &ec_publ_key_handle, &ec_priv_key_handle,
                                   FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to generate temporary EC key pair: "
                    "%s (0x%lx)\n", p11_get_ckr(rc), rc);
        goto done;
    }

    /* Perform ECDH to derive a shared AES key */
    ecdh_params.kdf = params->kdf;
    ecdh_params.pSharedData = params->pSharedData;
    ecdh_params.ulSharedDataLen = params->ulSharedDataLen;

    rc = template_attribute_get_non_empty(key_obj->template, CKA_EC_POINT,
                                          &ec_point);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to get CKA_EC_POINT.\n");
        goto done;
    }

    rc = ber_decode_OCTET_STRING((CK_BYTE *)ec_point->pValue,
                                  &ecdh_params.pPublicData,
                                  &ecdh_params.ulPublicDataLen,
                                  &field_len);
    if (rc != CKR_OK || field_len != ec_point->ulValueLen) {
        rc = CKR_FUNCTION_FAILED;
        TRACE_DEVEL("Failed to decode CKA_EC_POINT.\n");
        goto done;
    }

    aes_key_size = params->ulAESKeyBits / 8;
    rc = key_mgr_derive_key(tokdata, sess, &ecdh_mech,
                            ec_priv_key_handle, &aes_key_handle,
                            aes_key_tmpl,
                            sizeof(aes_key_tmpl) / sizeof(CK_ATTRIBUTE),
                            FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to derive temporary AES key (%lu bits): "
                    "%s (0x%lx)\n", params->ulAESKeyBits, p11_get_ckr(rc), rc);
        goto done;
    }

    /*
     * Encrypt (wrap) the to-be-wrapped key as the second part of the wrapped
     * key data (length-only operation to get the size of the second part).
     */
    rc = encr_mgr_init(tokdata, sess, &aeskw_ctx, OP_WRAP,
                       &aeskw_kwm_mech, aes_key_handle, TRUE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to encrypt the to-be-wrapped key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

    rc = encr_mgr_encrypt(tokdata, sess, TRUE, &aeskw_ctx,
                          in_data, in_data_len, NULL, &wrapped_key_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to encrypt the to-be-wrapped key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

    /* Calculate the final length of the wrapped key data */
    total_len = ecdh_params.ulPublicDataLen + wrapped_key_len;

    if (length_only) {
        *out_data_len = total_len;
        goto done;
    }

    if (*out_data_len < total_len) {
        *out_data_len = total_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    /*
     * Copy the (raw) EC point of the public transport EC key as first part of
     * the wrapped key data.
     */
    rc = object_mgr_find_in_map1(tokdata, ec_publ_key_handle,
                                 &pub_key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from EC public key handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = template_attribute_get_non_empty(pub_key_obj->template, CKA_EC_POINT,
                                          &ec_point);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to get CKA_EC_POINT.\n");
        goto done;
    }

    rc = ber_decode_OCTET_STRING((CK_BYTE *)ec_point->pValue,
                                  &pub_ec_point, &pub_ec_point_len, &field_len);
    if (rc != CKR_OK || field_len != ec_point->ulValueLen) {
        rc = CKR_FUNCTION_FAILED;
        TRACE_DEVEL("Failed to decode CKA_EC_POINT.\n");
        goto done;
    }

    memcpy(out_data, pub_ec_point, pub_ec_point_len);

    /*
     * Encrypt (wrap) the to-be-wrapped key as the second part of the wrapped
     * key data.
     */
    rc = encr_mgr_encrypt(tokdata, sess, FALSE, &aeskw_ctx,
                          in_data, in_data_len,
                          out_data + ecdh_params.ulPublicDataLen,
                          &wrapped_key_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to encrypt the to-be-wrapped key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

    *out_data_len = total_len;

done:
    if (ec_publ_key_handle != CK_INVALID_HANDLE) {
        rc2 = object_mgr_destroy_object(tokdata, sess, ec_publ_key_handle);
        if (rc2 != CKR_OK) {
            TRACE_ERROR("Failed to destroy temporary EC public key: %s "
                        "(0x%lx)\n", p11_get_ckr(rc2), rc2);
            if (rc == CKR_OK)
                rc = rc2;
        }
    }
    if (ec_priv_key_handle != CK_INVALID_HANDLE) {
        rc2 = object_mgr_destroy_object(tokdata, sess, ec_priv_key_handle);
        if (rc2 != CKR_OK) {
            TRACE_ERROR("Failed to destroy temporary EC private key: %s "
                        "(0x%lx)\n", p11_get_ckr(rc2), rc2);
            if (rc == CKR_OK)
                rc = rc2;
        }
    }
    if (aes_key_handle != CK_INVALID_HANDLE) {
        rc2 = object_mgr_destroy_object(tokdata, sess, aes_key_handle);
        if (rc2 != CKR_OK) {
            TRACE_ERROR("Failed to destroy temporary AES key: %s (0x%lx)\n",
                        p11_get_ckr(rc2), rc2);
            if (rc == CKR_OK)
                rc = rc2;
        }
    }

    encr_mgr_cleanup(tokdata, sess, &aeskw_ctx);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;
    object_put(tokdata, pub_key_obj, TRUE);
    pub_key_obj = NULL;

    return rc;
}

CK_RV ecdh_aes_key_unwrap(STDLL_TokData_t *tokdata, SESSION *sess,
                          CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    CK_ECDH_AES_KEY_WRAP_PARAMS *params;
    CK_ECDH1_DERIVE_PARAMS ecdh_params = { 0 };
    CK_MECHANISM ecdh_mech = { CKM_ECDH1_DERIVE, &ecdh_params,
                               sizeof(ecdh_params) };
    CK_MECHANISM aeskw_kwm_mech = { CKM_AES_KEY_WRAP_KWP, NULL, 0 };
    CK_OBJECT_HANDLE aes_key_handle = CK_INVALID_HANDLE;
    ENCR_DECR_CONTEXT aeskw_ctx = { 0 };
    CK_BBOOL ck_true = TRUE;
    CK_BBOOL ck_false = TRUE;
    OBJECT *key_obj = NULL;
    CK_ULONG prime_len = 0, public_data_len = 0;
    CK_OBJECT_CLASS aes_key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE aes_key_type = CKK_AES;
    CK_ULONG aes_key_size;
    CK_BYTE form;
    CK_RV rc, rc2;

    CK_ATTRIBUTE aes_key_tmpl[] = {
        { CKA_CLASS, &aes_key_class, sizeof(aes_key_class) },
        { CKA_KEY_TYPE, &aes_key_type, sizeof(aes_key_type) },
        { CKA_VALUE_LEN, &aes_key_size, sizeof(aes_key_size) },
        { CKA_HIDDEN, &ck_true, sizeof(ck_true) },
        { CKA_SENSITIVE, &ck_true, sizeof(ck_true) },
        { CKA_TOKEN, &ck_false, sizeof(ck_false) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        { CKA_WRAP, &ck_false, sizeof(ck_false) },
        { CKA_UNWRAP, &ck_true, sizeof(ck_true) },
        { CKA_ENCRYPT, &ck_false, sizeof(ck_false) },
        { CKA_DECRYPT, &ck_false, sizeof(ck_false) },
        { CKA_SIGN, &ck_false, sizeof(ck_false) },
        { CKA_VERIFY, &ck_false, sizeof(ck_false) },
        { CKA_DERIVE, &ck_false, sizeof(ck_false) },
    };

    params = (CK_ECDH_AES_KEY_WRAP_PARAMS *)ctx->mech.pParameter;

    /* Get the EC parameters of the EC key used with this mechanism */
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = get_ecsiglen(key_obj, &prime_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("get_ecsiglen failed.\n");
        goto done;
    }
    prime_len /= 2; /* prime length is half the size of an EC signature */

    /* Input must be at least a compressed EC point plus wrapped data */
    if (in_data_len <= prime_len + 1 + 2 * AES_KEY_WRAP_BLOCK_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
        goto done;
    }

    form  = in_data[0] & ~0x01;
    switch (form) {
    case POINT_CONVERSION_COMPRESSED:
        public_data_len = prime_len + 1;
        /* Length checked above already */
        break;
    case POINT_CONVERSION_UNCOMPRESSED:
    case POINT_CONVERSION_HYBRID:
        public_data_len = 2 * prime_len + 1;
        if (in_data_len < public_data_len + 2 * AES_KEY_WRAP_BLOCK_SIZE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
            rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
            goto done;
        }
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_INVALID));
        rc = CKR_ENCRYPTED_DATA_INVALID;
        goto done;
    }

    /* Perform ECDH to derive a shared AES key */
    ecdh_params.kdf = params->kdf;
    ecdh_params.pSharedData = params->pSharedData;
    ecdh_params.ulSharedDataLen = params->ulSharedDataLen;
    ecdh_params.pPublicData = in_data;
    ecdh_params.ulPublicDataLen = public_data_len;

    aes_key_size = params->ulAESKeyBits / 8;
    rc = key_mgr_derive_key(tokdata, sess, &ecdh_mech,
                            ctx->key, &aes_key_handle,
                            aes_key_tmpl,
                            sizeof(aes_key_tmpl) / sizeof(CK_ATTRIBUTE),
                            FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to derive temporary AES key (%lu bits): "
                    "%s (0x%lx)\n", params->ulAESKeyBits, p11_get_ckr(rc), rc);
        goto done;
    }

    /*
     * Decrypt (unwrap) the final key data from the the second part of the
     * wrapped key data.
     */
    rc = decr_mgr_init(tokdata, sess, &aeskw_ctx, OP_UNWRAP,
                       &aeskw_kwm_mech, aes_key_handle, TRUE, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to decrypt the to-be-unwrapped key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

    rc = decr_mgr_decrypt(tokdata, sess, length_only, &aeskw_ctx,
                          in_data + public_data_len,
                          in_data_len - public_data_len,
                          out_data, out_data_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to decrypt the to-be-unwrapped key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

done:
    if (aes_key_handle != CK_INVALID_HANDLE) {
        rc2 = object_mgr_destroy_object(tokdata, sess, aes_key_handle);
        if (rc2 != CKR_OK) {
            TRACE_ERROR("Failed to destroy temporary AES key: %s (0x%lx)\n",
                        p11_get_ckr(rc2), rc2);
            if (rc == CKR_OK)
                rc = rc2;
        }
    }

    encr_mgr_cleanup(tokdata, sess, &aeskw_ctx);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ec_agg_dup_param(CK_IBM_ECDSA_OTHER_BLS_PARAMS *from,
                       CK_IBM_ECDSA_OTHER_BLS_PARAMS *to)
{
    CK_ULONG i;

    if (from == NULL || to == NULL)
        return CKR_ARGUMENTS_BAD;

    if (from->numElements != 0 && from->elementSize > 0) {
        for (i = 0; i < CK_IBM_BLS_MAX_AGGREGATIONS; i++) {
            if (i < from->numElements) {
                to->pAggrElements[i] = (CK_BYTE*)malloc(from->elementSize);
                if (to->pAggrElements[i] == NULL) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    ec_agg_free_param(to);
                    return CKR_HOST_MEMORY;
                }
                memcpy(to->pAggrElements[i], from->pAggrElements[i],
                       from->elementSize);
            } else {
                to->pAggrElements[i] = NULL;
            }
        }
        to->numElements = from->numElements;
        to->elementSize = from->elementSize;
    } else {
        to->numElements = 0;
        to->elementSize = 0;
        memset(to->pAggrElements, 0, sizeof(to->pAggrElements));
    }
    return CKR_OK;
}

CK_RV ec_agg_free_param(CK_IBM_ECDSA_OTHER_BLS_PARAMS *params)
{
    CK_ULONG i;

    if (params == NULL)
        return CKR_ARGUMENTS_BAD;

    for (i = 0; i < CK_IBM_BLS_MAX_AGGREGATIONS; i++) {
        free(params->pAggrElements[i]);
        params->pAggrElements[i] = NULL;
    }

    params->numElements = 0;
    params->elementSize = 0;
    return CKR_OK;
}
