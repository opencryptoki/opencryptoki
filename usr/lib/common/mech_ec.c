/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
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

#define _GNU_SOURCE
#include <endian.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"
#include "tok_specific.h"
#include "ec_defs.h"

#include "openssl/obj_mac.h"
#include <openssl/ec.h>

#if OPENSSL_VERSION_NUMBER < 0x10100000L
/*
 * Older OpenSLL versions do not have BN_bn2binpad, so implement it here
 */
static int BN_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    int len, pad;
    unsigned char *buf;

    len = BN_num_bytes(a);
    buf = (unsigned char *)malloc(len);
    if (buf == NULL)
        return -1;
    BN_bn2bin(a, buf);

    if (len >= tolen) {
        memcpy(to, buf, tolen);
    } else {
        pad = tolen - len;
        memset(to, 0, pad);
        memcpy(to + pad, buf, len);
    }

    free(buf);
    return tolen;
}
#endif

#ifndef NID_brainpoolP160r1
/*
 * Older OpenSLL versions may not have the brainpool NIDs defined, define them
 * here
 */
#define NID_brainpoolP160r1             921
#define NID_brainpoolP160t1             922
#define NID_brainpoolP192r1             923
#define NID_brainpoolP192t1             924
#define NID_brainpoolP224r1             925
#define NID_brainpoolP224t1             926
#define NID_brainpoolP256r1             927
#define NID_brainpoolP256t1             928
#define NID_brainpoolP320r1             929
#define NID_brainpoolP320t1             930
#define NID_brainpoolP384r1             931
#define NID_brainpoolP384t1             932
#define NID_brainpoolP512r1             933
#define NID_brainpoolP512t1             934

#endif

#ifndef NID_X25519
#define NID_X25519                      1034
#define NID_X448                        1035
#endif
#ifndef NID_ED25519
#define NID_ED25519                     1087
#define NID_ED448                       1088
#endif

const CK_BYTE brainpoolP160r1[] = OCK_BRAINPOOL_P160R1;
const CK_BYTE brainpoolP160t1[] = OCK_BRAINPOOL_P160T1;
const CK_BYTE brainpoolP192r1[] = OCK_BRAINPOOL_P192R1;
const CK_BYTE brainpoolP192t1[] = OCK_BRAINPOOL_P192T1;
const CK_BYTE brainpoolP224r1[] = OCK_BRAINPOOL_P224R1;
const CK_BYTE brainpoolP224t1[] = OCK_BRAINPOOL_P224T1;
const CK_BYTE brainpoolP256r1[] = OCK_BRAINPOOL_P256R1;
const CK_BYTE brainpoolP256t1[] = OCK_BRAINPOOL_P256T1;
const CK_BYTE brainpoolP320r1[] = OCK_BRAINPOOL_P320R1;
const CK_BYTE brainpoolP320t1[] = OCK_BRAINPOOL_P320T1;
const CK_BYTE brainpoolP384r1[] = OCK_BRAINPOOL_P384R1;
const CK_BYTE brainpoolP384t1[] = OCK_BRAINPOOL_P384T1;
const CK_BYTE brainpoolP512r1[] = OCK_BRAINPOOL_P512R1;
const CK_BYTE brainpoolP512t1[] = OCK_BRAINPOOL_P512T1;
const CK_BYTE prime192v1[] = OCK_PRIME192V1;
const CK_BYTE secp224r1[] = OCK_SECP224R1;
const CK_BYTE prime256v1[] = OCK_PRIME256V1;
const CK_BYTE secp384r1[] = OCK_SECP384R1;
const CK_BYTE secp521r1[] = OCK_SECP521R1;
const CK_BYTE secp256k1[] = OCK_SECP256K1;
const CK_BYTE curve25519[] = OCK_CURVE25519;
const CK_BYTE curve448[] = OCK_CURVE448;
const CK_BYTE ed25519[] = OCK_ED25519;
const CK_BYTE ed448[] = OCK_ED448;

const struct _ec der_ec_supported[NUMEC] = {
    {BRAINPOOL_CURVE, CURVE160, NID_brainpoolP160r1,
            sizeof(brainpoolP160r1), &brainpoolP160r1},
    {BRAINPOOL_CURVE, CURVE160, NID_brainpoolP160t1,
            sizeof(brainpoolP160t1), &brainpoolP160t1},
    {BRAINPOOL_CURVE, CURVE192, NID_brainpoolP192r1,
            sizeof(brainpoolP192r1), &brainpoolP192r1},
    {BRAINPOOL_CURVE, CURVE192, NID_brainpoolP192t1,
            sizeof(brainpoolP192t1), &brainpoolP192t1},
    {BRAINPOOL_CURVE, CURVE224, NID_brainpoolP224r1,
            sizeof(brainpoolP224r1), &brainpoolP224r1},
    {BRAINPOOL_CURVE, CURVE224, NID_brainpoolP224t1,
            sizeof(brainpoolP224t1), &brainpoolP224t1},
    {BRAINPOOL_CURVE, CURVE256, NID_brainpoolP256r1,
            sizeof(brainpoolP256r1), &brainpoolP256r1},
    {BRAINPOOL_CURVE, CURVE256, NID_brainpoolP256t1,
            sizeof(brainpoolP256t1), &brainpoolP256t1},
    {BRAINPOOL_CURVE, CURVE320, NID_brainpoolP320r1,
            sizeof(brainpoolP320r1), &brainpoolP320r1},
    {BRAINPOOL_CURVE, CURVE320, NID_brainpoolP320t1,
            sizeof(brainpoolP320t1), &brainpoolP320t1},
    {BRAINPOOL_CURVE, CURVE384, NID_brainpoolP384r1,
            sizeof(brainpoolP384r1), &brainpoolP384r1},
    {BRAINPOOL_CURVE, CURVE384, NID_brainpoolP384t1,
            sizeof(brainpoolP384t1), &brainpoolP384t1},
    {BRAINPOOL_CURVE, CURVE512, NID_brainpoolP512r1,
            sizeof(brainpoolP512r1), &brainpoolP512r1},
    {BRAINPOOL_CURVE, CURVE512, NID_brainpoolP512t1,
            sizeof(brainpoolP512t1), &brainpoolP512t1},
    {PRIME_CURVE, CURVE192, NID_X9_62_prime192v1,
            sizeof(prime192v1), &prime192v1},
    {PRIME_CURVE, CURVE224, NID_secp224r1, sizeof(secp224r1), &secp224r1},
    {PRIME_CURVE, CURVE256, NID_X9_62_prime256v1,
            sizeof(prime256v1), &prime256v1},
    {PRIME_CURVE, CURVE384, NID_secp384r1, sizeof(secp384r1), &secp384r1},
    {PRIME_CURVE, CURVE521, NID_secp521r1, sizeof(secp521r1), &secp521r1},
    {PRIME_CURVE, CURVE256, NID_secp256k1, sizeof(secp256k1), &secp256k1},
    {MONTGOMERY_CURVE, CURVE256, NID_X25519, sizeof(curve25519), &curve25519},
    {MONTGOMERY_CURVE, CURVE456, NID_X448, sizeof(curve448), &curve448},
    {EDWARDS_CURVE, CURVE256, NID_ED25519, sizeof(ed25519), &ed25519},
    {EDWARDS_CURVE, CURVE456, NID_ED448, sizeof(ed448), &ed448},
};


CK_RV get_ecsiglen(OBJECT *key_obj, CK_ULONG *size)
{
    CK_BBOOL flag;
    CK_ATTRIBUTE *attr = NULL;
    int i;

    flag = template_attribute_find(key_obj->template, CKA_ECDSA_PARAMS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_ECDSA_PARAMS for the key.\n");
        return CKR_FUNCTION_FAILED;
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
    CK_ATTRIBUTE *attr = NULL;
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;

    if (token_specific.t_ec_sign == NULL) {
        TRACE_ERROR("ec_sign not supported by this token\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = template_attribute_find(key_obj->template, CKA_CLASS, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("Could not find CKA_CLASS in the template\n");
        return CKR_FUNCTION_FAILED;
    }

    keyclass = *(CK_OBJECT_CLASS *) attr->pValue;

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
        TRACE_ERROR("Failed to acquire key from specified handle");
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
    CK_ATTRIBUTE *attr = NULL;
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;

    if (token_specific.t_ec_verify == NULL) {
        TRACE_ERROR("ec_verify not supported by this token\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = template_attribute_find(key_obj->template, CKA_CLASS, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("Could not find CKA_CLASS in the template\n");
        return CKR_FUNCTION_FAILED;
    }

    keyclass = *(CK_OBJECT_CLASS *) attr->pValue;

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
        TRACE_ERROR("Failed to acquire key from specified handle");
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

    switch (ctx->mech.mechanism) {
    case CKM_ECDSA_SHA1:
        digest_mech.mechanism = CKM_SHA_1;
        break;
    case CKM_ECDSA_SHA224:
        digest_mech.mechanism = CKM_SHA224;
        break;
    case CKM_ECDSA_SHA256:
        digest_mech.mechanism = CKM_SHA256;
        break;
    case CKM_ECDSA_SHA384:
        digest_mech.mechanism = CKM_SHA384;
        break;
    case CKM_ECDSA_SHA512:
        digest_mech.mechanism = CKM_SHA512;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = get_sha_size(digest_mech.mechanism, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Get SHA Size failed.\n");
        return rc;
    }

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest(tokdata, sess, length_only, &digest_ctx, in_data,
                           in_data_len, hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Digest failed.\n");
        return rc;
    }

    sign_mech.mechanism = CKM_ECDSA;
    sign_mech.ulParameterLen = 0;
    sign_mech.pParameter = NULL;

    rc = sign_mgr_init(tokdata, sess, &sign_ctx, &sign_mech, FALSE, ctx->key);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign Mgr Init failed.\n");
        goto error;
    }

    rc = sign_mgr_sign(tokdata, sess, length_only, &sign_ctx, hash, hash_len,
                       signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Sign Mgr Sign failed.\n");

error:
    sign_mgr_cleanup(&sign_ctx);

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
        switch (ctx->mech.mechanism) {
        case CKM_ECDSA_SHA1:
            digest_mech.mechanism = CKM_SHA_1;
            break;
        case CKM_ECDSA_SHA224:
            digest_mech.mechanism = CKM_SHA224;
            break;
        case CKM_ECDSA_SHA256:
            digest_mech.mechanism = CKM_SHA256;
            break;
        case CKM_ECDSA_SHA384:
            digest_mech.mechanism = CKM_SHA384;
            break;
        case CKM_ECDSA_SHA512:
            digest_mech.mechanism = CKM_SHA512;
            break;
        default:
            return CKR_MECHANISM_INVALID;
        }

        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &context->hash_context,
                             &digest_mech);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }
        context->flag = TRUE;
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

    rc = sign_mgr_init(tokdata, sess, &sign_ctx, &sign_mech, FALSE, ctx->key);
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
        sign_mgr_cleanup(&sign_ctx);
        return rc;
    }

done:
    sign_mgr_cleanup(&sign_ctx);

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

    switch (ctx->mech.mechanism) {
    case CKM_ECDSA_SHA1:
        digest_mech.mechanism = CKM_SHA_1;
        break;
    case CKM_ECDSA_SHA224:
        digest_mech.mechanism = CKM_SHA224;
        break;
    case CKM_ECDSA_SHA256:
        digest_mech.mechanism = CKM_SHA256;
        break;
    case CKM_ECDSA_SHA384:
        digest_mech.mechanism = CKM_SHA384;
        break;
    case CKM_ECDSA_SHA512:
        digest_mech.mechanism = CKM_SHA512;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = get_sha_size(digest_mech.mechanism, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Get SHA Size failed.\n");
        return rc;
    }

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx, in_data,
                           in_data_len, hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Digest failed.\n");
        return rc;
    }
    // Verify the Signed BER-encoded Data block
    //
    verify_mech.mechanism = CKM_ECDSA;
    verify_mech.ulParameterLen = 0;
    verify_mech.pParameter = NULL;

    rc = verify_mgr_init(tokdata, sess, &verify_ctx, &verify_mech, FALSE,
                         ctx->key);
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
    sign_mgr_cleanup(&verify_ctx);

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
        switch (ctx->mech.mechanism) {
        case CKM_ECDSA_SHA1:
            digest_mech.mechanism = CKM_SHA_1;
            break;
        case CKM_ECDSA_SHA224:
            digest_mech.mechanism = CKM_SHA224;
            break;
        case CKM_ECDSA_SHA256:
            digest_mech.mechanism = CKM_SHA256;
            break;
        case CKM_ECDSA_SHA384:
            digest_mech.mechanism = CKM_SHA384;
            break;
        case CKM_ECDSA_SHA512:
            digest_mech.mechanism = CKM_SHA512;
            break;
        default:
            return CKR_MECHANISM_INVALID;
        }

        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &context->hash_context,
                             &digest_mech);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }
        context->flag = TRUE;
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
                         ctx->key);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Verify Mgr Init failed.\n");
        goto done;
    }

    rc = verify_mgr_verify(tokdata, sess, &verify_ctx, hash, hash_len,
                           signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Verify Mgr Verify failed.\n");
done:
    verify_mgr_cleanup(&verify_ctx);

    return rc;
}

CK_RV ckm_kdf(STDLL_TokData_t *tokdata, SESSION *sess, CK_ULONG kdf,
              CK_BYTE *data, CK_ULONG data_len, CK_BYTE *hash, CK_ULONG *h_len)
{
    CK_RV rc;
    DIGEST_CONTEXT ctx;
    CK_MECHANISM digest_mech;

    memset(&ctx, 0, sizeof(DIGEST_CONTEXT));
    memset(&digest_mech, 0, sizeof(CK_MECHANISM));

    switch (kdf) {
    case CKD_SHA1_KDF:
        digest_mech.mechanism = CKM_SHA_1;
        *h_len = SHA1_HASH_SIZE;
        break;
    case CKD_SHA224_KDF:
        digest_mech.mechanism = CKM_SHA224;
        *h_len = SHA224_HASH_SIZE;
        break;
    case CKD_SHA256_KDF:
        digest_mech.mechanism = CKM_SHA256;
        *h_len = SHA256_HASH_SIZE;
        break;
    case CKD_SHA384_KDF:
        digest_mech.mechanism = CKM_SHA384;
        *h_len = SHA384_HASH_SIZE;
        break;
    case CKD_SHA512_KDF:
        digest_mech.mechanism = CKM_SHA512;
        *h_len = SHA512_HASH_SIZE;
        break;
    case CKD_NULL:
        memcpy(hash, data, data_len - 4);
        *h_len = data_len - 4;  // data length minus counter length
        return CKR_OK;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    rc = digest_mgr_init(tokdata, sess, &ctx, &digest_mech);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return rc;
    }

    rc = digest_mgr_digest(tokdata, sess, FALSE, &ctx, data, data_len, hash,
                           h_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("digest_mgr_digest failed with rc = %s\n", ock_err(rc));
        return rc;
    }

    return CKR_OK;
}

CK_RV ckm_kdf_X9_63(STDLL_TokData_t *tokdata, SESSION *sess, CK_ULONG kdf,
                    CK_ULONG kdf_digest_len, const CK_BYTE *z, CK_ULONG z_len,
                    const CK_BYTE *shared_data, CK_ULONG shared_data_len,
                    CK_BYTE *key, CK_ULONG key_len)
{
    CK_ULONG counter_length = 4;
    CK_BYTE *ctx = NULL;
    CK_ULONG ctx_len;
    CK_BYTE hash[MAX_SUPPORTED_HASH_LENGTH];
    CK_ULONG h_len;
    CK_RV rc;
    unsigned int i, counter, counter_en;

    /* Check max keylen according to ANSI X9.63 */
    /* digest_len * 2^32 */
    CK_ULONG max_keybytes = kdf_digest_len * 0x100000000ul;
    if (key_len >= max_keybytes) {
        TRACE_ERROR("Desired key length %lu greater than max supported key "
                    "length %lu.\n", key_len, max_keybytes);
        return CKR_KEY_SIZE_RANGE;
    }

    /* If no KDF to be used, just return the shared_data.
     * Cannot concatenate hashes. */
    if (kdf == CKD_NULL) {
        memcpy(key, z, z_len);
        return CKR_OK;
    }

    /* Allocate memory for hash context */
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

CK_RV ckm_ecdh_pkcs_derive(STDLL_TokData_t *tokdata, CK_VOID_PTR other_pubkey,
                           CK_ULONG other_pubkey_len, CK_OBJECT_HANDLE base_key,
                           CK_BYTE *secret_value, CK_ULONG *secret_value_len)
{
    CK_RV rc;
    CK_ATTRIBUTE *attr;
    OBJECT *base_key_obj = NULL;
    CK_BYTE *oid_p;
    CK_ULONG oid_len;
    CK_ULONG class = 0, keytype = 0;

    if (token_specific.t_ecdh_pkcs_derive == NULL) {
        TRACE_ERROR("ecdh pkcs derive is not supported by this token.\n");
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    /* Find base_key struct */
    rc = object_mgr_find_in_map1(tokdata, base_key, &base_key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    /* Get curve oid from CKA_ECDSA_PARAMS */
    if (!template_attribute_find
        (base_key_obj->template, CKA_ECDSA_PARAMS, &attr)) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        rc = CKR_TEMPLATE_INCOMPLETE;
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
    if (!template_attribute_find(base_key_obj->template, CKA_VALUE, &attr)) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        rc = CKR_TEMPLATE_INCOMPLETE;
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
    object_put(tokdata, base_key_obj, TRUE);
    base_key_obj = NULL;

    return rc;
}

static CK_RV digest_from_kdf(CK_EC_KDF_TYPE kdf, CK_MECHANISM_TYPE *mech)
{
    switch (kdf) {
    case CKD_SHA1_KDF:
        *mech = CKM_SHA_1;
        break;
    case CKD_SHA224_KDF:
        *mech = CKM_SHA224;
        break;
    case CKD_SHA256_KDF:
        *mech = CKM_SHA256;
        break;
    case CKD_SHA384_KDF:
        *mech = CKM_SHA384;
        break;
    case CKD_SHA512_KDF:
        *mech = CKM_SHA512;
        break;
    default:
        TRACE_ERROR("Error unsupported KDF %ld.\n", kdf);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV pkcs_get_keytype(CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
                       CK_MECHANISM_PTR mech, CK_ULONG *type, CK_ULONG *class)
{
    CK_ULONG i;

    *type = 0;
    *class = 0;

    for (i = 0; i < attrs_len; i++) {
        if (attrs[i].type == CKA_CLASS) {
            *class = *(CK_ULONG *) attrs[i].pValue;
        }
    }

    for (i = 0; i < attrs_len; i++) {
        if (attrs[i].type == CKA_KEY_TYPE) {
            *type = *(CK_ULONG *) attrs[i].pValue;
            return CKR_OK;
        }
    }

    /* no CKA_KEY_TYPE found, derive from mech */
    switch (mech->mechanism) {
    case CKM_DES_KEY_GEN:
        *type = CKK_DES;
        break;
    case CKM_DES3_KEY_GEN:
        *type = CKK_DES3;
        break;
    case CKM_CDMF_KEY_GEN:
        *type = CKK_CDMF;
        break;
    case CKM_AES_KEY_GEN:
        *type = CKK_AES;
        break;
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        *type = CKK_RSA;
        break;
    case CKM_EC_KEY_PAIR_GEN:
        *type = CKK_EC;
        break;
    case CKM_DSA_KEY_PAIR_GEN:
        *type = CKK_DSA;
        break;
    case CKM_DH_PKCS_KEY_PAIR_GEN:
        *type = CKK_DH;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
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

CK_RV ecdh_pkcs_derive(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_MECHANISM *mech, CK_OBJECT_HANDLE base_key,
                       CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                       CK_OBJECT_HANDLE *derived_key_obj)
{
    CK_RV rc;
    CK_ULONG class = 0, keytype = 0, key_len = 0;
    CK_ATTRIBUTE *new_attr;
    OBJECT *temp_obj = NULL;
    CK_ECDH1_DERIVE_PARAMS *pParms;
    CK_BYTE z_value[MAX_ECDH_SHARED_SECRET_SIZE];
    CK_ULONG z_len = 0, kdf_digest_len;
    CK_MECHANISM_TYPE digest_mech;
    CK_BYTE *derived_key = NULL;
    CK_ULONG derived_key_len, i;

    /* Check parm length */
    if (mech->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)) {
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

    /* Determine derived key length */
    for (i = 0; i < ulCount; i++) {
        if (pTemplate[i].type == CKA_VALUE_LEN) {
            key_len = *(CK_ULONG *) pTemplate[i].pValue;
        }
    }

    if (key_len == 0) {
        key_len = keylen_from_keytype(keytype);
        if (key_len == 0) {
            TRACE_ERROR("Derived key length not specified in template.\n");
            return CKR_TEMPLATE_INCOMPLETE;
        }
    }

    /* Optional shared data can only be provided together with a KDF */
    if (pParms->kdf == CKD_NULL
        && (pParms->pSharedData != NULL || pParms->ulSharedDataLen != 0)) {
        TRACE_ERROR("No KDF specified, but shared data ptr is not NULL.\n");
        return CKR_ARGUMENTS_BAD;
    }

    /* Derive the shared secret */
    rc = ckm_ecdh_pkcs_derive(tokdata, pParms->pPublicData,
                              pParms->ulPublicDataLen, base_key, z_value,
                              &z_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Error deriving the shared secret.\n");
        return rc;
    }

    /* If no KDF used, max possible key length is the shared_secret length */
    if (pParms->kdf == CKD_NULL && key_len > z_len) {
        TRACE_ERROR("Can only provide %ld key bytes without a KDF, "
                    "but %ld bytes requested.\n",
                    (pParms->ulPublicDataLen / 2), key_len);
        return CKR_ARGUMENTS_BAD;
    }

    /* Determine digest length */
    if (pParms->kdf != CKD_NULL) {
        rc = digest_from_kdf(pParms->kdf, &digest_mech);
        if (rc != CKR_OK) {
            TRACE_ERROR("Cannot determine mech from kdf.\n");
            return CKR_ARGUMENTS_BAD;
        }
        rc = get_sha_size(digest_mech, &kdf_digest_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("Cannot determine SHA digest size.\n");
            return CKR_ARGUMENTS_BAD;
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
        return CKR_HOST_MEMORY;
    }

    /* Apply KDF function to shared secret */
    rc = ckm_kdf_X9_63(tokdata, sess, pParms->kdf, kdf_digest_len,
                       z_value, z_len, pParms->pSharedData,
                       pParms->ulSharedDataLen, derived_key, derived_key_len);
    if (rc != CKR_OK)
        goto end;

    /* Return the hashed and truncated derived bytes as CKA_VALUE attribute */
    rc = build_attribute(CKA_VALUE, derived_key, key_len, &new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to build the attribute from CKA_VALUE, rc=%s.\n",
                    ock_err(rc));
        goto end;
    }

    /* Create the object that will be passed back as a handle. This will contain
     * the new (computed) value of the attribute. */
    rc = object_mgr_create_skel(tokdata, sess, pTemplate, ulCount, MODE_KEYGEN,
                                class, keytype, &temp_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Object Mgr create skeleton failed, rc=%s.\n", ock_err(rc));
        free(new_attr);
        goto end;
    }

    /* Update the template in the object with the new attribute */
    template_update_attribute(temp_obj->template, new_attr);

    /* At this point, the derived key is fully constructed...assign an object
     * handle and store the key */
    rc = object_mgr_create_final(tokdata, sess, temp_obj, derived_key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Object Mgr create final failed, rc=%s.\n", ock_err(rc));
        object_free(temp_obj);
        temp_obj = NULL;
        goto end;
    }

    rc = CKR_OK;

end:
    free(derived_key);

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
