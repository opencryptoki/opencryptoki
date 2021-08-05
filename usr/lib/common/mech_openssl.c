/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */


#include <pthread.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <openssl/opensslv.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bn.h>
#if OPENSSL_VERSION_PREREQ(3, 0)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

CK_RV openssl_specific_rsa_keygen(TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    CK_ATTRIBUTE *publ_exp = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG mod_bits;
    CK_BBOOL flag;
    CK_RV rc;
    CK_ULONG BNLength;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    const RSA *rsa = NULL;
    const BIGNUM *bignum = NULL;
#else
    BIGNUM *bignum = NULL;
#endif
    CK_BYTE *ssl_ptr = NULL;
    BIGNUM *e = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    rc = template_attribute_get_ulong(publ_tmpl, CKA_MODULUS_BITS, &mod_bits);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE; // should never happen
    }

    // we don't support less than 512 bit keys in the sw
    if (mod_bits < 512 || mod_bits > OPENSSL_RSA_MAX_MODULUS_BITS) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        return CKR_KEY_SIZE_RANGE;
    }

    rc = template_attribute_get_non_empty(publ_tmpl, CKA_PUBLIC_EXPONENT,
                                          &publ_exp);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if (publ_exp->ulValueLen > sizeof(CK_ULONG)) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    e = BN_new();
    if (e == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    BN_bin2bn(publ_exp->pValue, publ_exp->ulValueLen, e);

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (mod_bits > INT_MAX
        || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, mod_bits) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, e) != 1) {
#else
    if (EVP_PKEY_CTX_set1_rsa_keygen_pubexp(ctx, e) != 1) {
#endif
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#if !OPENSSL_VERSION_PREREQ(3, 0)
    e = NULL; // will be freed as part of the context
#endif
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if ((rsa = EVP_PKEY_get0_RSA(pkey)) == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    RSA_get0_key(rsa, &bignum, NULL, NULL);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bignum)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_MODULUS, ssl_ptr, BNLength, &attr);    // in bytes
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        goto done;
    }
    free(ssl_ptr);
    ssl_ptr = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(bignum);
    bignum = NULL;
#endif

    // Public Exponent
#if !OPENSSL_VERSION_PREREQ(3, 0)
    RSA_get0_key(rsa, NULL, &bignum, NULL);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bignum)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    // in bytes
    rc = build_attribute(CKA_PUBLIC_EXPONENT, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        goto done;
    }

    /* add public exponent to the private template. Its already an attribute in
     * the private template at this point, we're just making its value correct
     */
    rc = build_attribute(CKA_PUBLIC_EXPONENT, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        goto done;
    }
    free(ssl_ptr);
    ssl_ptr = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(bignum);
    bignum = NULL;
#endif

    // local = TRUE
    //
    flag = TRUE;
    rc = build_attribute(CKA_LOCAL, &flag, sizeof(CK_BBOOL), &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        goto done;
    }

    //
    // now, do the private key
    //
    // Cheat here and put the whole original key into the CKA_VALUE... remember
    // to force the system to not return this for RSA keys..

    // Add the modulus to the private key information
#if !OPENSSL_VERSION_PREREQ(3, 0)
    RSA_get0_key(rsa, &bignum, NULL, NULL);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bignum)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_MODULUS, ssl_ptr, BNLength, &attr);    // in bytes
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        goto done;
    }
    free(ssl_ptr);
    ssl_ptr = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(bignum);
    bignum = NULL;
#endif

    // Private Exponent
#if !OPENSSL_VERSION_PREREQ(3, 0)
    RSA_get0_key(rsa, NULL, NULL, &bignum);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &bignum)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_PRIVATE_EXPONENT, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        OPENSSL_cleanse(attr, sizeof(CK_ATTRIBUTE) + attr->ulValueLen);
        free(attr);
        goto done;
    }
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(bignum);
    bignum = NULL;
#endif

    // prime #1: p
#if !OPENSSL_VERSION_PREREQ(3, 0)
    RSA_get0_factors(rsa, &bignum, NULL);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &bignum)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_PRIME_1, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        OPENSSL_cleanse(attr, sizeof(CK_ATTRIBUTE) + attr->ulValueLen);
        free(attr);
        goto done;
    }
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(bignum);
    bignum = NULL;
#endif

    // prime #2: q
#if !OPENSSL_VERSION_PREREQ(3, 0)
    RSA_get0_factors(rsa, NULL, &bignum);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &bignum)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_PRIME_2, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        OPENSSL_cleanse(attr, sizeof(CK_ATTRIBUTE) + attr->ulValueLen);
        free(attr);
        goto done;
    }
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(bignum);
    bignum = NULL;
#endif

    // exponent 1: d mod(p-1)
#if !OPENSSL_VERSION_PREREQ(3, 0)
    RSA_get0_crt_params(rsa, &bignum, NULL, NULL);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1, &bignum)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_EXPONENT_1, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        OPENSSL_cleanse(attr, sizeof(CK_ATTRIBUTE) + attr->ulValueLen);
        free(attr);
        goto done;
    }
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(bignum);
    bignum = NULL;
#endif

    // exponent 2: d mod(q-1)
#if !OPENSSL_VERSION_PREREQ(3, 0)
    RSA_get0_crt_params(rsa, NULL, &bignum, NULL);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2, &bignum)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_EXPONENT_2, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        OPENSSL_cleanse(attr, sizeof(CK_ATTRIBUTE) + attr->ulValueLen);
        free(attr);
        goto done;
    }
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(bignum);
    bignum = NULL;
#endif

    // CRT coefficient:  q_inverse mod(p)
#if !OPENSSL_VERSION_PREREQ(3, 0)
    RSA_get0_crt_params(rsa, NULL, NULL, &bignum);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                               &bignum)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_COEFFICIENT, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        OPENSSL_cleanse(attr, sizeof(CK_ATTRIBUTE) + attr->ulValueLen);
        free(attr);
        goto done;
    }
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(bignum);
    bignum = NULL;
#endif

    flag = TRUE;
    rc = build_attribute(CKA_LOCAL, &flag, sizeof(CK_BBOOL), &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        goto done;
    }

done:
    if (ssl_ptr != NULL) {
        OPENSSL_cleanse(ssl_ptr, BNLength);
        free(ssl_ptr);
    }
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (e != NULL)
        BN_free(e);
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (bignum != NULL)
        BN_free(bignum);
#endif
    return rc;
}

// convert from the local PKCS11 template representation to
// the underlying requirement
// returns the pointer to the local key representation
static EVP_PKEY *rsa_convert_public_key(OBJECT *key_obj)
{
    CK_BBOOL rc;
    CK_ATTRIBUTE *modulus = NULL;
    CK_ATTRIBUTE *pub_exp = NULL;
    EVP_PKEY *pkey = NULL;
    BIGNUM *bn_mod, *bn_exp;
#if OPENSSL_VERSION_PREREQ(3, 0)
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
#else
    RSA *rsa;
#endif

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &modulus);
    if (rc != CKR_OK)
        return NULL;
    rc = template_attribute_get_non_empty(key_obj->template,
                                          CKA_PUBLIC_EXPONENT, &pub_exp);
    if (rc != CKR_OK)
        return NULL;

    // Create and init BIGNUM structs
    bn_mod = BN_new();
    bn_exp = BN_new();

    if (bn_exp == NULL || bn_mod == NULL) {
        if (bn_mod)
            free(bn_mod);
        if (bn_exp)
            free(bn_exp);
        return NULL;
    }
    // Convert from strings to BIGNUMs
    BN_bin2bn((unsigned char *) modulus->pValue, modulus->ulValueLen, bn_mod);
    BN_bin2bn((unsigned char *) pub_exp->pValue, pub_exp->ulValueLen, bn_exp);

#if !OPENSSL_VERSION_PREREQ(3, 0)
    // Create an RSA key struct to return
    rsa = RSA_new();
    if (rsa == NULL) {
        if (bn_mod)
             free(bn_mod);
         if (bn_exp)
             free(bn_exp);
        return NULL;
    }

    RSA_set0_key(rsa, bn_mod, bn_exp, NULL);

    pkey = EVP_PKEY_new();
    if (pkey == NULL) {
       RSA_free(rsa);
       return NULL;
    }

    if (EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
        RSA_free(rsa);
        EVP_PKEY_free(pkey);
        return NULL;
    }
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        goto out;

    if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_N, bn_mod) ||
        !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, bn_exp))
        goto out;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto out;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pctx == NULL)
        goto out;

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params))
        goto out;

out:
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
    if (params != NULL)
        OSSL_PARAM_free(params);
    if (bn_mod != NULL)
        BN_free(bn_mod);
    if (bn_exp != NULL)
        BN_free(bn_exp);
#endif

    return pkey;
}

static EVP_PKEY *rsa_convert_private_key(OBJECT *key_obj)
{
    CK_ATTRIBUTE *modulus = NULL;
    CK_ATTRIBUTE *pub_exp = NULL;
    CK_ATTRIBUTE *priv_exp = NULL;
    CK_ATTRIBUTE *prime1 = NULL;
    CK_ATTRIBUTE *prime2 = NULL;
    CK_ATTRIBUTE *exp_1 = NULL;
    CK_ATTRIBUTE *exp_2 = NULL;
    CK_ATTRIBUTE *coeff = NULL;
    EVP_PKEY *pkey = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
#else
    RSA *rsa;
#endif
    BIGNUM *bn_mod, *bn_pub_exp, *bn_priv_exp, *bn_p1, *bn_p2, *bn_e1, *bn_e2,
        *bn_cf;

    template_attribute_get_non_empty(key_obj->template, CKA_MODULUS, &modulus);
    template_attribute_get_non_empty(key_obj->template,  CKA_PUBLIC_EXPONENT,
                                     &pub_exp);
    template_attribute_find(key_obj->template, CKA_PRIVATE_EXPONENT, &priv_exp);
    template_attribute_find(key_obj->template, CKA_PRIME_1, &prime1);
    template_attribute_find(key_obj->template, CKA_PRIME_2, &prime2);
    template_attribute_find(key_obj->template, CKA_EXPONENT_1, &exp_1);
    template_attribute_find(key_obj->template, CKA_EXPONENT_2,&exp_2);
    template_attribute_find(key_obj->template, CKA_COEFFICIENT, &coeff);

    if (!prime2 && !modulus) {
        return NULL;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    // Create and init all the RSA and BIGNUM structs we need.
    rsa = RSA_new();
    if (rsa == NULL)
        return NULL;

    /*
     * Depending if an engine is loaded on OpenSSL and define its own
     * RSA_METHOD, we can end up having an infinite loop as the SOFT
     * Token doesn't implement RSA and, instead, calls OpenSSL for it.
     * So to avoid it we set RSA methods to the default rsa methods.
     */
    RSA_set_method(rsa, RSA_PKCS1_OpenSSL());
#endif

    bn_mod = BN_new();
    bn_pub_exp = BN_new();
    bn_priv_exp = BN_new();
    bn_p1 = BN_new();
    bn_p2 = BN_new();
    bn_e1 = BN_new();
    bn_e2 = BN_new();
    bn_cf = BN_new();

    if ((bn_cf == NULL) || (bn_e2 == NULL) || (bn_e1 == NULL) ||
        (bn_p2 == NULL) || (bn_p1 == NULL) || (bn_priv_exp == NULL) ||
        (bn_pub_exp == NULL) || (bn_mod == NULL))
        goto out;

    // CRT key?
    if (prime1) {
        if (!prime2 || !exp_1 || !exp_2 || !coeff)
            goto out;

        // Even though this is CRT key, OpenSSL requires the
        // modulus and exponents filled in or encrypt and decrypt will
        // not work
        BN_bin2bn((unsigned char *) modulus->pValue, modulus->ulValueLen,
                  bn_mod);
        BN_bin2bn((unsigned char *) pub_exp->pValue, pub_exp->ulValueLen,
                  bn_pub_exp);
        BN_bin2bn((unsigned char *) priv_exp->pValue, priv_exp->ulValueLen,
                  bn_priv_exp);

        BN_bin2bn((unsigned char *) prime1->pValue, prime1->ulValueLen, bn_p1);
        BN_bin2bn((unsigned char *) prime2->pValue, prime2->ulValueLen, bn_p2);

        BN_bin2bn((unsigned char *) exp_1->pValue, exp_1->ulValueLen, bn_e1);
        BN_bin2bn((unsigned char *) exp_2->pValue, exp_2->ulValueLen, bn_e2);
        BN_bin2bn((unsigned char *) coeff->pValue, coeff->ulValueLen, bn_cf);

#if !OPENSSL_VERSION_PREREQ(3, 0)
        RSA_set0_key(rsa, bn_mod, bn_pub_exp, bn_priv_exp);
        bn_mod = NULL;
        bn_pub_exp = NULL;
        bn_priv_exp = NULL;
        RSA_set0_factors(rsa, bn_p1, bn_p2);
        bn_p1 = NULL;
        bn_p2 = NULL;
        RSA_set0_crt_params(rsa, bn_e1, bn_e2, bn_cf);
        bn_e1 = NULL;
        bn_e2 = NULL;
        bn_cf = NULL;

        pkey = EVP_PKEY_new();
        if (pkey == NULL)
            goto out;

        if (EVP_PKEY_assign_RSA(pkey, rsa) != 1)
            goto out;
#else
        tmpl = OSSL_PARAM_BLD_new();
        if (tmpl == NULL)
            goto out;

        if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_N, bn_mod) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, bn_pub_exp) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_D, bn_priv_exp) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR1, bn_p1) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR2, bn_p2) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT1,
                                                                       bn_e1) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT2,
                                                                       bn_e2) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                                                                       bn_cf))
            goto out;
#endif
    } else {                    // must be a non-CRT key
        if (!priv_exp) {
            return NULL;
        }
        BN_bin2bn((unsigned char *) modulus->pValue, modulus->ulValueLen,
                  bn_mod);
        BN_bin2bn((unsigned char *) pub_exp->pValue, pub_exp->ulValueLen,
                  bn_pub_exp);
        BN_bin2bn((unsigned char *) priv_exp->pValue, priv_exp->ulValueLen,
                  bn_priv_exp);

#if !OPENSSL_VERSION_PREREQ(3, 0)
        RSA_set0_key(rsa, bn_mod, bn_pub_exp, bn_priv_exp);
        bn_mod = NULL;
        bn_pub_exp = NULL;
        bn_priv_exp = NULL;

        pkey = EVP_PKEY_new();
        if (pkey == NULL)
            goto out;

        if (EVP_PKEY_assign_RSA(pkey, rsa) != 1)
            goto out;
#else
        tmpl = OSSL_PARAM_BLD_new();
        if (tmpl == NULL)
            goto out;

        if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_N, bn_mod) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, bn_pub_exp) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_D, bn_priv_exp))
            goto out;
#endif
    }

#if OPENSSL_VERSION_PREREQ(3, 0)
    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL)
        goto out;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pctx == NULL)
        goto out;

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_PUBLIC_KEY, params))
        goto out;

    EVP_PKEY_CTX_free(pctx);
    OSSL_PARAM_BLD_free(tmpl);
    OSSL_PARAM_free(params);
    BN_free(bn_mod);
    BN_free(bn_pub_exp);
    BN_free(bn_priv_exp);
    BN_free(bn_p1);
    BN_free(bn_p2);
    BN_free(bn_e1);
    BN_free(bn_e2);
    BN_free(bn_cf);
#endif

    return pkey;
out:
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (rsa)
        RSA_free(rsa);
#else
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
    if (params != NULL)
        OSSL_PARAM_free(params);
#endif
    if (pkey)
        EVP_PKEY_free(pkey);
    if (bn_mod)
        BN_free(bn_mod);
    if (bn_pub_exp)
        BN_free(bn_pub_exp);
    if (bn_priv_exp)
        BN_free(bn_priv_exp);
    if (bn_p1)
        BN_free(bn_p1);
    if (bn_p2)
        BN_free(bn_p2);
    if (bn_e1)
        BN_free(bn_e1);
    if (bn_e2)
        BN_free(bn_e2);
    if (bn_cf)
        BN_free(bn_cf);

    return NULL;
}

CK_RV openssl_specific_rsa_encrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                   CK_ULONG in_data_len, CK_BYTE *out_data,
                                   OBJECT *key_obj)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    CK_RV rc;
    size_t outlen = in_data_len;

    UNUSED(tokdata);

    pkey = rsa_convert_public_key(key_obj);
    if (pkey == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        return rc;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_PKEY_encrypt_init(ctx) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (EVP_PKEY_encrypt(ctx, out_data, &outlen,
                         in_data, in_data_len) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;
done:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    return rc;
}

CK_RV openssl_specific_rsa_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                   CK_ULONG in_data_len, CK_BYTE *out_data,
                                   OBJECT *key_obj)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t outlen = in_data_len;
    CK_RV rc;

    UNUSED(tokdata);

    pkey = rsa_convert_private_key(key_obj);
    if (pkey == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        return rc;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_PKEY_decrypt_init(ctx) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_NO_PADDING) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (EVP_PKEY_decrypt(ctx, out_data, &outlen,
                         in_data, in_data_len) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;
done:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    return rc;
}

CK_RV openssl_specific_rsa_pkcs_encrypt(STDLL_TokData_t *tokdata,
                                        CK_BYTE *in_data, CK_ULONG in_data_len,
                                        CK_BYTE *out_data,
                                        CK_ULONG *out_data_len,
                                        OBJECT *key_obj,
                                        t_rsa_encrypt rsa_encrypt_func)
{
    CK_RV rc;
    CK_ULONG modulus_bytes;
    CK_BYTE clear[MAX_RSA_KEYLEN], cipher[MAX_RSA_KEYLEN];
    CK_ATTRIBUTE *attr = NULL;

    /* format the data */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return rc;
    }
    modulus_bytes = attr->ulValueLen;

    rc = rsa_format_block(tokdata, in_data, in_data_len, clear,
                          modulus_bytes, PKCS_BT_2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_format_block failed\n");
        goto done;
    }
    // Do an RSA public encryption
    rc = rsa_encrypt_func(tokdata, clear, modulus_bytes, cipher, key_obj);

    if (rc == CKR_OK) {
        memcpy(out_data, cipher, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("openssl_specific_rsa_encrypt failed\n");
    }

done:
    OPENSSL_cleanse(clear, sizeof(clear));
    return rc;
}

CK_RV openssl_specific_rsa_pkcs_decrypt(STDLL_TokData_t *tokdata,
                                        CK_BYTE *in_data, CK_ULONG in_data_len,
                                        CK_BYTE *out_data,
                                        CK_ULONG *out_data_len, OBJECT *key_obj,
                                        t_rsa_decrypt rsa_decrypt_func)
{
    CK_RV rc;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;

    modulus_bytes = in_data_len;

    rc = rsa_decrypt_func(tokdata, in_data, modulus_bytes, out, key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("openssl_specific_rsa_decrypt failed\n");
        goto done;
    }

    rc = rsa_parse_block(out, modulus_bytes, out_data, out_data_len, PKCS_BT_2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_parse_block failed\n");
        goto done;
    }

    /*
     * For PKCS #1 v1.5 padding, out_data_len must be less than
     * modulus_bytes - 11.
     */
    if (*out_data_len > (modulus_bytes - 11)) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

done:
    OPENSSL_cleanse(out, sizeof(out));
    return rc;
}


CK_RV openssl_specific_rsa_pkcs_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                                     CK_BYTE *in_data, CK_ULONG in_data_len,
                                     CK_BYTE *signature, CK_ULONG *sig_len,
                                     OBJECT *key_obj,
                                     t_rsa_decrypt rsa_decrypt_func)
{
    CK_BYTE data[MAX_RSA_KEYLEN], sig[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

    UNUSED(sess);

    /* format the data */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return rc;
    }
    modulus_bytes = attr->ulValueLen;
    rc = rsa_format_block(tokdata, in_data, in_data_len, data,
                          modulus_bytes, PKCS_BT_1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_format_block failed\n");
        return rc;
    }

    /* signing is a private key operation --> decrypt */
    rc = rsa_decrypt_func(tokdata, data, modulus_bytes, sig, key_obj);
    if (rc == CKR_OK) {
        memcpy(signature, sig, modulus_bytes);
        *sig_len = modulus_bytes;
    } else {
        TRACE_DEVEL("openssl_specific_rsa_decrypt failed\n");
    }

    return rc;
}

CK_RV openssl_specific_rsa_pkcs_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                       CK_BYTE *in_data, CK_ULONG in_data_len,
                                       CK_BYTE *signature, CK_ULONG sig_len,
                                       OBJECT *key_obj,
                                       t_rsa_encrypt rsa_encrypt_func)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN], out_data[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes, out_data_len;
    CK_RV rc;

    UNUSED(sess);
    UNUSED(sig_len);

    out_data_len = MAX_RSA_KEYLEN;
    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return rc;
    } else {
        modulus_bytes = attr->ulValueLen;
    }

    // verifying is a public key operation --> encrypt
    //
    rc = rsa_encrypt_func(tokdata, signature, modulus_bytes, out, key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("openssl_specific_rsa_encrypt failed: %lx\n", rc);
        /*
         * Return CKR_SIGNATURE_INVALID in case of CKR_ARGUMENTS_BAD or
         * CKR_FUNCTION_FAILED because we dont know why the RSA op failed and
         * it may have failed due to a tampered signature being greater or equal
         * to the modulus.
         */
        if (rc == CKR_ARGUMENTS_BAD || rc == CKR_FUNCTION_FAILED) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rc = CKR_SIGNATURE_INVALID;
        }
        return rc;
    }

    rc = rsa_parse_block(out, modulus_bytes, out_data, &out_data_len,
                         PKCS_BT_1);
    if (rc == CKR_ENCRYPTED_DATA_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        return CKR_SIGNATURE_INVALID;
    } else if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    if (in_data_len != out_data_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        return CKR_SIGNATURE_INVALID;
    }

    if (CRYPTO_memcmp(in_data, out_data, out_data_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        return CKR_SIGNATURE_INVALID;
    }

    return rc;
}

CK_RV openssl_specific_rsa_pkcs_verify_recover(STDLL_TokData_t *tokdata,
                                               CK_BYTE *signature,
                                               CK_ULONG sig_len,
                                               CK_BYTE *out_data,
                                               CK_ULONG *out_data_len,
                                               OBJECT *key_obj,
                                               t_rsa_encrypt rsa_encrypt_func)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_RV rc;

    UNUSED(sig_len);

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return rc;
    } else {
        modulus_bytes = attr->ulValueLen;
    }

    // verifying is a public key operation --> encrypt
    //
    rc = rsa_encrypt_func(tokdata, signature, modulus_bytes, out, key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("openssl_specific_rsa_encrypt failed: %lx\n", rc);
        /*
         * Return CKR_SIGNATURE_INVALID in case of CKR_ARGUMENTS_BAD or
         * CKR_FUNCTION_FAILED because we dont know why the RSA op failed and
         * it may have failed due to a tampered signature being greater or equal
         * to the modulus.
         */
        if (rc == CKR_ARGUMENTS_BAD || rc == CKR_FUNCTION_FAILED) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rc = CKR_SIGNATURE_INVALID;
        }
        return rc;
    }

    rc = rsa_parse_block(out, modulus_bytes, out_data, out_data_len, PKCS_BT_1);
    if (rc == CKR_ENCRYPTED_DATA_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        return CKR_SIGNATURE_INVALID;
    } else if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
    }

    return rc;
}

CK_RV openssl_specific_rsa_pss_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                                    SIGN_VERIFY_CONTEXT *ctx,
                                    CK_BYTE *in_data, CK_ULONG in_data_len,
                                    CK_BYTE *sig, CK_ULONG *sig_len,
                                    t_rsa_decrypt rsa_decrypt_func)
{
    CK_RV rc;
    CK_ULONG modbytes;
    CK_ATTRIBUTE *attr = NULL;
    OBJECT *key_obj = NULL;
    CK_BYTE *emdata = NULL;
    CK_RSA_PKCS_PSS_PARAMS *pssParms = NULL;

    UNUSED(sess);

    /* check the arguments */
    if (!in_data || !sig) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    if (!ctx) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    pssParms = (CK_RSA_PKCS_PSS_PARAMS *) ctx->mech.pParameter;

    /* get the key */
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
   if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        goto done;
    } else {
        modbytes = attr->ulValueLen;
    }

    emdata = (CK_BYTE *) malloc(modbytes);
    if (emdata == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    rc = emsa_pss_encode(tokdata, pssParms, in_data, in_data_len, emdata,
                         &modbytes);
    if (rc != CKR_OK)
        goto done;

    /* signing is a private key operation --> decrypt  */
    rc = rsa_decrypt_func(tokdata, emdata, modbytes, sig, key_obj);
    if (rc == CKR_OK)
        *sig_len = modbytes;
    else
        TRACE_DEVEL("openssl_specific_rsa_decrypt failed\n");

done:
    if (emdata)
        free(emdata);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV openssl_specific_rsa_pss_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                      SIGN_VERIFY_CONTEXT *ctx,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *signature, CK_ULONG sig_len,
                                      t_rsa_encrypt rsa_encrypt_func)
{
    CK_RV rc;
    CK_ULONG modbytes;
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_RSA_PKCS_PSS_PARAMS *pssParms = NULL;

    UNUSED(sess);

    /* check the arguments */
    if (!in_data || !signature) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    if (!ctx) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    pssParms = (CK_RSA_PKCS_PSS_PARAMS *) ctx->mech.pParameter;

    /* get the key */
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        return rc;
    }

    /* verify is a public key operation ... encrypt */
    rc = rsa_encrypt_func(tokdata, signature, sig_len, out, key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("openssl_specific_rsa_encrypt failed: %lx\n", rc);
        /*
         * Return CKR_SIGNATURE_INVALID in case of CKR_ARGUMENTS_BAD or
         * CKR_FUNCTION_FAILED because we dont know why the RSA op failed and
         * it may have failed due to a tampered signature being greater or equal
         * to the modulus.
         */
        if (rc == CKR_ARGUMENTS_BAD || rc == CKR_FUNCTION_FAILED) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rc = CKR_SIGNATURE_INVALID;
        }
        goto done;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        goto done;
    } else {
        modbytes = attr->ulValueLen;
    }

    /* call the pss verify scheme */
    rc = emsa_pss_verify(tokdata, pssParms, in_data, in_data_len, out,
                         modbytes);

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV openssl_specific_rsa_x509_encrypt(STDLL_TokData_t *tokdata,
                                        CK_BYTE *in_data, CK_ULONG in_data_len,
                                        CK_BYTE *out_data,
                                        CK_ULONG *out_data_len, OBJECT *key_obj,
                                        t_rsa_encrypt rsa_encrypt_func)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE clear[MAX_RSA_KEYLEN], cipher[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_RV rc;

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        goto done;
    }

    modulus_bytes = attr->ulValueLen;

    // prepad with zeros
    //
    memset(clear, 0, modulus_bytes - in_data_len);
    memcpy(&clear[modulus_bytes - in_data_len], in_data, in_data_len);

    rc = rsa_encrypt_func(tokdata, clear, modulus_bytes, cipher, key_obj);
    if (rc == CKR_OK) {
        memcpy(out_data, cipher, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("openssl_specific_rsa_encrypt failed\n");
    }

done:
    OPENSSL_cleanse(clear, sizeof(clear));
    return rc;
}

CK_RV openssl_specific_rsa_x509_decrypt(STDLL_TokData_t *tokdata,
                                        CK_BYTE *in_data, CK_ULONG in_data_len,
                                        CK_BYTE *out_data,
                                        CK_ULONG *out_data_len, OBJECT *key_obj,
                                        t_rsa_decrypt rsa_decrypt_func)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_RV rc;

    UNUSED(in_data_len);

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        goto done;
    }

    modulus_bytes = attr->ulValueLen;

    rc = rsa_decrypt_func(tokdata, in_data, modulus_bytes, out, key_obj);
    if (rc == CKR_OK) {
        memcpy(out_data, out, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("openssl_specific_rsa_decrypt failed\n");
    }

done:
    OPENSSL_cleanse(out, sizeof(out));
    return rc;
}


CK_RV openssl_specific_rsa_x509_sign(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                     CK_ULONG in_data_len, CK_BYTE *signature,
                                     CK_ULONG *sig_len, OBJECT *key_obj,
                                     t_rsa_decrypt rsa_decrypt_func)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE data[MAX_RSA_KEYLEN], sig[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_RV rc;

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return rc;
    } else {
        modulus_bytes = attr->ulValueLen;
    }

    // prepad with zeros
    //

    memset(data, 0x0, modulus_bytes - in_data_len);
    memcpy(&data[modulus_bytes - in_data_len], in_data, in_data_len);

    rc = rsa_decrypt_func(tokdata, data, modulus_bytes, sig, key_obj);
    if (rc == CKR_OK) {
        memcpy(signature, sig, modulus_bytes);
        *sig_len = modulus_bytes;
    } else {
        TRACE_DEVEL("openssl_specific_rsa_encrypt failed: %lx\n", rc);
        /*
         * Return CKR_SIGNATURE_INVALID in case of CKR_ARGUMENTS_BAD or
         * CKR_FUNCTION_FAILED because we dont know why the RSA op failed and
         * it may have failed due to a tampered signature being greater or equal
         * to the modulus.
         */
        if (rc == CKR_ARGUMENTS_BAD || rc == CKR_FUNCTION_FAILED) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rc = CKR_SIGNATURE_INVALID;
        }
    }

    return rc;
}

CK_RV openssl_specific_rsa_x509_verify(STDLL_TokData_t *tokdata,
                                       CK_BYTE *in_data, CK_ULONG in_data_len,
                                       CK_BYTE *signature, CK_ULONG sig_len,
                                       OBJECT *key_obj,
                                       t_rsa_encrypt rsa_encrypt_func)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_RV rc;

    UNUSED(sig_len);

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return rc;
    } else {
        modulus_bytes = attr->ulValueLen;
    }

    rc = rsa_encrypt_func(tokdata, signature, modulus_bytes, out, key_obj);
    if (rc == CKR_OK) {
        CK_ULONG pos1, pos2, len;
        // it should be noted that in_data_len is not necessarily
        // the same as the modulus length
        //
        for (pos1 = 0; pos1 < in_data_len; pos1++)
            if (in_data[pos1] != 0)
                break;

        for (pos2 = 0; pos2 < modulus_bytes; pos2++)
            if (out[pos2] != 0)
                break;

        // at this point, pos1 and pos2 point to the first non-zero
        // bytes in the input data and the decrypted signature
        // (the recovered data), respectively.
        if ((in_data_len - pos1) != (modulus_bytes - pos2)) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            return CKR_SIGNATURE_INVALID;
        }
        len = in_data_len - pos1;

        if (CRYPTO_memcmp(&in_data[pos1], &out[pos2], len) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            return CKR_SIGNATURE_INVALID;
        }
        return CKR_OK;
    } else {
        TRACE_DEVEL("openssl_specific_rsa_encrypt failed: %lx\n", rc);
        /*
         * Return CKR_SIGNATURE_INVALID in case of CKR_ARGUMENTS_BAD or
         * CKR_FUNCTION_FAILED because we dont know why the RSA op failed and
         * it may have failed due to a tampered signature being greater or equal
         * to the modulus.
         */
        if (rc == CKR_ARGUMENTS_BAD || rc == CKR_FUNCTION_FAILED) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rc = CKR_SIGNATURE_INVALID;
        }
    }

    return rc;
}

CK_RV openssl_specific_rsa_x509_verify_recover(STDLL_TokData_t *tokdata,
                                               CK_BYTE *signature,
                                               CK_ULONG sig_len,
                                               CK_BYTE *out_data,
                                               CK_ULONG *out_data_len,
                                               OBJECT *key_obj,
                                               t_rsa_encrypt rsa_encrypt_func)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_RV rc;

    UNUSED(sig_len);

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return rc;
    } else {
        modulus_bytes = attr->ulValueLen;
    }

    rc = rsa_encrypt_func(tokdata, signature, modulus_bytes, out, key_obj);
    if (rc == CKR_OK) {
        memcpy(out_data, out, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("openssl_specific_rsa_encrypt failed\n");
    }

    return rc;
}

CK_RV openssl_specific_rsa_oaep_encrypt(STDLL_TokData_t *tokdata,
                                        ENCR_DECR_CONTEXT *ctx,
                                        CK_BYTE *in_data, CK_ULONG in_data_len,
                                        CK_BYTE *out_data,
                                        CK_ULONG *out_data_len, CK_BYTE *hash,
                                        CK_ULONG hlen,
                                        t_rsa_encrypt rsa_encrypt_func)
{
    CK_RV rc;
    CK_BYTE cipher[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *em_data = NULL;
    OBJECT *key_obj = NULL;
    CK_RSA_PKCS_OAEP_PARAMS_PTR oaepParms = NULL;

    if (!in_data || !out_data || !hash) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    oaepParms = (CK_RSA_PKCS_OAEP_PARAMS_PTR) ctx->mech.pParameter;

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        goto done;
    }

    modulus_bytes = attr->ulValueLen;

    /* pkcs1v2.2, section 7.1.1 Step 2:
     * EME-OAEP encoding.
     */
    em_data = (CK_BYTE *) malloc(modulus_bytes * sizeof(CK_BYTE));
    if (em_data == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    rc = encode_eme_oaep(tokdata, in_data, in_data_len, em_data,
                         modulus_bytes, oaepParms->mgf, hash, hlen);
    if (rc != CKR_OK)
        goto done;

    rc = rsa_encrypt_func(tokdata, em_data, modulus_bytes, cipher, key_obj);
    if (rc == CKR_OK) {
        memcpy(out_data, cipher, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("openssl_specific_rsa_encrypt failed\n");
    }

done:
    if (em_data) {
        OPENSSL_cleanse(em_data, modulus_bytes * sizeof(CK_BYTE));
        free(em_data);
    }

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV openssl_specific_rsa_oaep_decrypt(STDLL_TokData_t *tokdata,
                                        ENCR_DECR_CONTEXT *ctx,
                                        CK_BYTE *in_data, CK_ULONG in_data_len,
                                        CK_BYTE *out_data,
                                        CK_ULONG *out_data_len, CK_BYTE *hash,
                                        CK_ULONG hlen,
                                        t_rsa_encrypt rsa_decrypt_func)
{
    CK_RV rc;
    CK_BYTE *decr_data = NULL;
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_RSA_PKCS_OAEP_PARAMS_PTR oaepParms = NULL;

    if (!in_data || !out_data || !hash) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    oaepParms = (CK_RSA_PKCS_OAEP_PARAMS_PTR) ctx->mech.pParameter;

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        goto error;
    }

    *out_data_len = attr->ulValueLen;

    decr_data = (CK_BYTE *) malloc(in_data_len);
    if (decr_data == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    rc = rsa_decrypt_func(tokdata, in_data, in_data_len, decr_data, key_obj);
    if (rc != CKR_OK)
        goto error;

    /* pkcs1v2.2, section 7.1.2 Step 2:
     * EME-OAEP decoding.
     */
    rc = decode_eme_oaep(tokdata, decr_data, in_data_len, out_data,
                         out_data_len, oaepParms->mgf, hash, hlen);

error:
    if (decr_data) {
        OPENSSL_cleanse(decr_data, in_data_len);
        free(decr_data);
    }

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

