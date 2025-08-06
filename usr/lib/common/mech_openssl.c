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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/sha.h>
#include <openssl/cmac.h>
#include <openssl/des.h>
#if OPENSSL_VERSION_PREREQ(3, 0)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#endif

void openssl_free_ex_data(OBJECT *obj, void *ex_data, size_t ex_data_len)
{
    struct openssl_ex_data *data = ex_data;

    if (ex_data == NULL || ex_data_len < sizeof(struct openssl_ex_data))
        return;

    if (data->pkey != NULL) {
        EVP_PKEY_free(data->pkey);
        data->pkey = NULL;
    }

    free(data);
    obj->ex_data = NULL;
    obj->ex_data_len = 0;
}

CK_RV openssl_reload_ex_data(OBJECT *obj, void *ex_data, size_t ex_data_len)
{
    if (obj->ex_data_free != NULL)
        obj->ex_data_free(obj, ex_data, ex_data_len);
    return CKR_OK;
}

/*
 * Gets the attached OpenSSL ex_data from the key object. If no ex_data is
 * attached yet, then a WRITE lock is obtained, the ex_data is allocated in the
 * specified size, and the ex_data is returned. If the ex_data is already
 * attached, the need_wr_lock routine is called to determine if a WRTE lock is
 * needed. If the need_wr_lock routine returns TRUE, a WRITE lock is obtained,
 * else, or if no need_wr_lock routine is specified, a READ lock is obtained
 * and the ex_data is returned. The caller must release ex-data lock when
 * finished working with it.
 */
CK_RV openssl_get_ex_data(OBJECT *obj, void **ex_data, size_t ex_data_len,
                          CK_BBOOL (*need_wr_lock)(OBJECT *obj,
                                                   void *ex_data,
                                                   size_t ex_data_len),
                          void (*ex_data_free)(struct _OBJECT *obj,
                                               void *ex_data,
                                               size_t ex_data_len))
{
    CK_RV rc;

    rc = object_ex_data_lock(obj, READ_LOCK);
    if (rc != CKR_OK)
        return rc;

    if (obj->ex_data != NULL &&
        obj->ex_data_len >= ex_data_len &&
        (need_wr_lock == NULL ||
         need_wr_lock(obj, obj->ex_data, obj->ex_data_len) == FALSE)) {
        *ex_data = obj->ex_data;
        return CKR_OK;
    }

    rc = object_ex_data_unlock(obj);
    if (rc != CKR_OK)
        return rc;

    rc = object_ex_data_lock(obj, WRITE_LOCK);
    if (rc != CKR_OK)
        return rc;

    if (obj->ex_data == NULL) {
        obj->ex_data = calloc(1, ex_data_len);
        if (obj->ex_data == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            object_ex_data_unlock(obj);
            return CKR_HOST_MEMORY;
        }

        obj->ex_data_len = ex_data_len;
        obj->ex_data_free = ex_data_free != NULL ? ex_data_free :
                                                   openssl_free_ex_data;
        obj->ex_data_reload = openssl_reload_ex_data;
    }

    *ex_data = obj->ex_data;
    return CKR_OK;
}

static CK_BBOOL openssl_need_wr_lock(OBJECT *obj, void *ex_data,
                                     size_t ex_data_len)
{
    struct openssl_ex_data *data = ex_data;

    UNUSED(obj);

    if (ex_data == NULL || ex_data_len < sizeof(struct openssl_ex_data))
        return FALSE;

    return data->pkey == NULL;
}

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
    int try;
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
#if OPENSSL_VERSION_PREREQ(3, 0)
    /*
     * In OpenSSL 3.0 the RSA key gen algorithm has been changed and can now
     * fail to generate a key. Retry up to 10 times in such a case.
     */
    for (try = 1; try <= 10; try++) {
        if (EVP_PKEY_keygen(ctx, &pkey) == 1) {
            rc = CKR_OK;
            break;
        }

        TRACE_ERROR("%s (try %d)\n", ock_err(ERR_FUNCTION_FAILED), try);
        rc = CKR_FUNCTION_FAILED;
    }
    if (rc != CKR_OK)
        goto done;
#else
    if (EVP_PKEY_keygen(ctx, &pkey) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
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
        !EVP_PKEY_fromdata(pctx, &pkey, EVP_PKEY_KEYPAIR, params))
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
    struct openssl_ex_data *ex_data = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    CK_RV rc;
    size_t outlen = in_data_len;

    UNUSED(tokdata);

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(struct openssl_ex_data),
                             openssl_need_wr_lock, NULL);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->pkey == NULL) {
        ex_data->pkey = rsa_convert_public_key(key_obj);
        if (ex_data->pkey == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    pkey = ex_data->pkey;
    if (EVP_PKEY_up_ref(pkey) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
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
    object_ex_data_unlock(key_obj);
    return rc;
}

CK_RV openssl_specific_rsa_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                   CK_ULONG in_data_len, CK_BYTE *out_data,
                                   OBJECT *key_obj)
{
    struct openssl_ex_data *ex_data = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    size_t outlen = in_data_len;
    CK_RV rc;

    UNUSED(tokdata);

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(struct openssl_ex_data),
                             openssl_need_wr_lock, NULL);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->pkey == NULL) {
        ex_data->pkey = rsa_convert_private_key(key_obj);
        if (ex_data->pkey == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    pkey = ex_data->pkey;
    if (EVP_PKEY_up_ref(pkey) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
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
    object_ex_data_unlock(key_obj);
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
    unsigned char kdk[SHA256_HASH_SIZE] = { 0 };

    modulus_bytes = in_data_len;

    rc = rsa_decrypt_func(tokdata, in_data, modulus_bytes, out, key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("openssl_specific_rsa_decrypt failed\n");
        goto done;
    }

    rc = openssl_specific_rsa_derive_kdk(tokdata, key_obj,
                                         in_data, in_data_len,
                                         kdk, sizeof(kdk));
    if (rc != CKR_OK) {
        TRACE_DEVEL("openssl_specific_rsa_derive_kdk failed\n");
        goto done;
    }

    rc = rsa_parse_block(out, modulus_bytes, out_data, out_data_len, PKCS_BT_2,
                         kdk, sizeof(kdk));

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
                         PKCS_BT_1, NULL, 0);
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

    rc = rsa_parse_block(out, modulus_bytes, out_data, out_data_len, PKCS_BT_1,
                         NULL, 0);
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


#ifndef NO_EC

static int curve_nid_from_params(const CK_BYTE *params, CK_ULONG params_len)
{
    const unsigned char *oid;
    ASN1_OBJECT *obj = NULL;
    EC_GROUP *grp;
    int nid;

    oid = params;
    obj = d2i_ASN1_OBJECT(NULL, &oid, params_len);
    if (obj == NULL || oid != params + params_len) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        return NID_undef;
    }

    nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);

    grp = EC_GROUP_new_by_curve_name(nid);
    if (grp == NULL) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        return NID_undef;
    }

    EC_GROUP_free(grp);

    return nid;
}

static int ec_prime_len_from_nid(int nid)
{
    EC_GROUP *group;
    int primelen;

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL)
        return -1;

    primelen = EC_GROUP_order_bits(group);

    EC_GROUP_free(group);

    return (primelen + 7) / 8;
}

static int ec_prime_len_from_pkey(EVP_PKEY *pkey)
{
#if !OPENSSL_VERSION_PREREQ(3, 0)
    return (EC_GROUP_order_bits(EC_KEY_get0_group(
                             EVP_PKEY_get0_EC_KEY(pkey))) + 7) / 8;
#else
    size_t curve_len;
    char curve[80];

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        curve, sizeof(curve), &curve_len))
        return -1;

    return ec_prime_len_from_nid(OBJ_sn2nid(curve));
#endif
}


#if !OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV make_ec_key_from_params(const CK_BYTE *params, CK_ULONG params_len,
                                     EC_KEY **key)
{
    EC_KEY *ec_key = NULL;
    int nid;
    CK_RV rc = CKR_OK;

    nid = curve_nid_from_params(params, params_len);
    if (nid == NID_undef) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

    ec_key = EC_KEY_new_by_curve_name(nid);
    if (ec_key == NULL) {
       TRACE_ERROR("curve not supported by OpenSSL.\n");
       rc = CKR_CURVE_NOT_SUPPORTED;
       goto out;
    }

out:
    if (rc != CKR_OK) {
        if (ec_key != NULL)
            EC_KEY_free(ec_key);

        return rc;
    }

    *key = ec_key;

    return CKR_OK;
}
#endif

#if OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV build_pkey_from_params(OSSL_PARAM_BLD *tmpl, int selection,
                                    EVP_PKEY **pkey)
{

    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    CK_RV rc = CKR_OK;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        TRACE_ERROR("OSSL_PARAM_BLD_to_param failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new_id failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, pkey, selection, params)) {
        TRACE_ERROR("EVP_PKEY_fromdata failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new(*pkey, NULL);
    if (pctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (EVP_PKEY_check(pctx) != 1) {
            TRACE_ERROR("EVP_PKEY_check failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
    } else {
        if (EVP_PKEY_public_check(pctx) != 1) {
            TRACE_ERROR("EVP_PKEY_public_check failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
    }

out:
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (params != NULL)
        OSSL_PARAM_free(params);

    if (rc != 0 && *pkey != NULL) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return rc;
}
#endif

#if !OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV fill_ec_key_from_pubkey(EC_KEY *ec_key, const CK_BYTE *data,
                                     CK_ULONG data_len, CK_BBOOL allow_raw,
                                     int nid, EVP_PKEY **ec_pkey)
#else
static CK_RV fill_ec_key_from_pubkey(OSSL_PARAM_BLD *tmpl, const CK_BYTE *data,
                                     CK_ULONG data_len, CK_BBOOL allow_raw,
                                     int nid, EVP_PKEY **ec_pkey)
#endif
{
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len, privlen;
    CK_BBOOL allocated = FALSE;
    int len;

    CK_RV rc;

    len = ec_prime_len_from_nid(nid);
    if (len <= 0) {
        TRACE_ERROR("ec_prime_len_from_nid failed\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }
    privlen = len;

    rc = ec_point_from_public_data(data, data_len, privlen, allow_raw,
                                   &allocated, &ecpoint, &ecpoint_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ec_point_from_public_data failed\n");
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (!EC_KEY_oct2key(ec_key, ecpoint, ecpoint_len, NULL)) {
        TRACE_ERROR("EC_KEY_oct2key failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EC_KEY_check_key(ec_key)) {
        TRACE_ERROR("EC_KEY_check_key failed\n");
        rc = CKR_PUBLIC_KEY_INVALID;
        goto out;
    }

    *ec_pkey = EVP_PKEY_new();
    if (*ec_pkey == NULL) {
       TRACE_ERROR("EVP_PKEY_CTX_new failed.\n");
       rc = CKR_HOST_MEMORY;
       goto out;
    }

    if (!EVP_PKEY_assign_EC_KEY(*ec_pkey, ec_key)) {
        TRACE_ERROR("EVP_PKEY_assign_EC_KEY failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#else
    if (!OSSL_PARAM_BLD_push_octet_string(tmpl,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          ecpoint, ecpoint_len)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_octet_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = build_pkey_from_params(tmpl, EVP_PKEY_PUBLIC_KEY, ec_pkey);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_pkey_from_params failed\n");
        goto out;
    }
 #endif

out:
    if (allocated && ecpoint != NULL)
        free(ecpoint);

    return rc;
}

#if !OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV fill_ec_key_from_privkey(EC_KEY *ec_key, const CK_BYTE *data,
                                      CK_ULONG data_len, EVP_PKEY **ec_pkey)
#else
static CK_RV fill_ec_key_from_privkey(OSSL_PARAM_BLD *tmpl, const CK_BYTE *data,
                                      CK_ULONG data_len, int nid,
                                      EVP_PKEY **ec_pkey)
#endif
{
    EC_POINT *point = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    EC_GROUP *group = NULL;
    BIGNUM *bn_priv = NULL;
    unsigned char *pub_key = NULL;
    unsigned int pub_key_len;
    point_conversion_form_t form;
#endif
    CK_RV rc = CKR_OK;

#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (!EC_KEY_oct2priv(ec_key, data, data_len)) {
        TRACE_ERROR("EC_KEY_oct2priv failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    point = EC_POINT_new(EC_KEY_get0_group(ec_key));
    if (point == NULL) {
        TRACE_ERROR("EC_POINT_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EC_POINT_mul(EC_KEY_get0_group(ec_key), point,
                      EC_KEY_get0_private_key(ec_key), NULL, NULL, NULL)) {
        TRACE_ERROR("EC_POINT_mul failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EC_KEY_set_public_key(ec_key, point)) {
        TRACE_ERROR("EC_KEY_set_public_key failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EC_KEY_check_key(ec_key)) {
        TRACE_ERROR("EC_KEY_check_key failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    *ec_pkey = EVP_PKEY_new();
    if (*ec_pkey == NULL) {
       TRACE_ERROR("EVP_PKEY_CTX_new failed.\n");
       rc = CKR_HOST_MEMORY;
       goto out;
    }

    if (!EVP_PKEY_assign_EC_KEY(*ec_pkey, ec_key)) {
        TRACE_ERROR("EVP_PKEY_assign_EC_KEY failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#else
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        TRACE_ERROR("EC_GROUP_new_by_curve_name failed\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

    point = EC_POINT_new(group);
    if (point == NULL) {
        TRACE_ERROR("EC_POINT_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    bn_priv = BN_bin2bn(data, data_len, NULL);
    if (bn_priv == NULL) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EC_POINT_mul(group, point, bn_priv, NULL, NULL, NULL)) {
        TRACE_ERROR("EC_POINT_mul failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    form = EC_GROUP_get_point_conversion_form(group);
    pub_key_len = EC_POINT_point2buf(group, point, form, &pub_key,
                                     NULL);
    if (pub_key_len == 0) {
        TRACE_ERROR("EC_POINT_point2buf failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PUB_KEY,
                                          pub_key, pub_key_len)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_octet_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_BN failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = build_pkey_from_params(tmpl, EVP_PKEY_KEYPAIR, ec_pkey);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_pkey_from_params failed\n");
        goto out;
    }
#endif

out:
    if (point != NULL)
        EC_POINT_free(point);
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (group != NULL)
        EC_GROUP_free(group);
    if (bn_priv != NULL)
        BN_free(bn_priv);
    if (pub_key != NULL)
        OPENSSL_free(pub_key);
#endif

    return rc;
}

CK_RV openssl_make_ec_key_from_template(TEMPLATE *template, EVP_PKEY **pkey)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_OBJECT_CLASS keyclass;
    EVP_PKEY *ec_pkey = NULL;
    int nid;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EC_KEY *ec_key = NULL;
#else
    OSSL_PARAM_BLD *tmpl = NULL;
#endif
    CK_RV rc;

    rc = template_attribute_get_ulong(template, CKA_CLASS, &keyclass);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS in the template\n");
        goto out;
    }

    rc = template_attribute_get_non_empty(template, CKA_ECDSA_PARAMS, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_ECDSA_PARAMS in the template\n");
        goto out;
    }

    nid = curve_nid_from_params(attr->pValue, attr->ulValueLen);
    if (nid == NID_undef) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = make_ec_key_from_params(attr->pValue, attr->ulValueLen, &ec_key);
    if (rc != CKR_OK)
        goto out;
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        TRACE_ERROR("OSSL_PARAM_BLD_new failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(tmpl, OSSL_PKEY_PARAM_GROUP_NAME,
                                         OBJ_nid2sn(nid), 0)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_utf8_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#endif

    switch (keyclass) {
    case CKO_PUBLIC_KEY:
        rc = template_attribute_get_non_empty(template, CKA_EC_POINT, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_EC_POINT in the template\n");
            goto out;
        }

#if !OPENSSL_VERSION_PREREQ(3, 0)
        rc = fill_ec_key_from_pubkey(ec_key, attr->pValue, attr->ulValueLen,
                                     FALSE, nid, &ec_pkey);
#else
        rc = fill_ec_key_from_pubkey(tmpl, attr->pValue, attr->ulValueLen,
                                     FALSE, nid, &ec_pkey);
#endif
        if (rc != CKR_OK) {
            TRACE_DEVEL("fill_ec_key_from_pubkey failed\n");
            goto out;
        }
        break;

    case CKO_PRIVATE_KEY:
        rc = template_attribute_get_non_empty(template, CKA_VALUE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE in the template\n");
            goto out;
        }

#if !OPENSSL_VERSION_PREREQ(3, 0)
        rc = fill_ec_key_from_privkey(ec_key, attr->pValue, attr->ulValueLen,
                                      &ec_pkey);
#else
        rc = fill_ec_key_from_privkey(tmpl, attr->pValue, attr->ulValueLen,
                                      nid, &ec_pkey);

#endif
        if (rc != CKR_OK) {
            TRACE_DEVEL("fill_ec_key_from_privkey failed\n");
            goto out;
        }
        break;

    default:
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    ec_key = NULL;
#endif

    rc = CKR_OK;

out:
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
#endif

    if (rc != CKR_OK) {
        if (ec_pkey != NULL)
            EVP_PKEY_free(ec_pkey);
#if !OPENSSL_VERSION_PREREQ(3, 0)
        if (ec_key != NULL)
            EC_KEY_free(ec_key);
#endif

        return rc;
    }

    *pkey = ec_pkey;

    return CKR_OK;
}

CK_RV openssl_specific_ec_generate_keypair(STDLL_TokData_t *tokdata,
                                           TEMPLATE *publ_tmpl,
                                           TEMPLATE *priv_tmpl)
{

    CK_ATTRIBUTE *attr = NULL, *ec_point_attr, *value_attr, *parms_attr;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    const EC_KEY *ec_key = NULL;
    BN_CTX *bnctx = NULL;
#else
    BIGNUM *bn_d = NULL;
    int len;
#endif
    CK_BYTE *ecpoint = NULL, *enc_ecpoint = NULL, *d = NULL;
    CK_ULONG enc_ecpoint_len, d_len;
    size_t ecpoint_len;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *ec_pkey = NULL;
    int nid;
    CK_RV rc;

    UNUSED(tokdata);

    rc = template_attribute_get_non_empty(publ_tmpl, CKA_ECDSA_PARAMS, &attr);
    if (rc != CKR_OK)
        goto out;

    nid = curve_nid_from_params(attr->pValue, attr->ulValueLen);
    if (nid == NID_undef) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        TRACE_ERROR("EVP_PKEY_keygen_init failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        TRACE_ERROR("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

    if (EVP_PKEY_keygen(ctx, &ec_pkey) <= 0) {
        TRACE_ERROR("EVP_PKEY_keygen failed\n");
        if (ERR_GET_REASON(ERR_peek_last_error()) == EC_R_INVALID_CURVE)
            rc = CKR_CURVE_NOT_SUPPORTED;
        else
            rc = CKR_FUNCTION_FAILED;
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    ec_key = EVP_PKEY_get0_EC_KEY(ec_pkey);
    if (ec_key == NULL) {
       TRACE_ERROR("EVP_PKEY_get0_EC_KEY failed\n");
       rc = CKR_FUNCTION_FAILED;
       goto out;
   }

    bnctx = BN_CTX_new();
    if (bnctx == NULL) {
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    ecpoint_len = EC_KEY_key2buf(ec_key, POINT_CONVERSION_UNCOMPRESSED,
                                 &ecpoint, bnctx);
    if (ecpoint_len == 0) {
        TRACE_ERROR("Failed to get the EC Point compressed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#else
    if (!EVP_PKEY_get_octet_string_param(ec_pkey,
                                         OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                         NULL, 0, &ecpoint_len)) {
        TRACE_ERROR("EVP_PKEY_get_octet_string_param failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    ecpoint = OPENSSL_zalloc(ecpoint_len);
    if (ecpoint == NULL) {
        TRACE_ERROR("OPENSSL_zalloc failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (!EVP_PKEY_get_octet_string_param(ec_pkey,
                                         OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                         ecpoint, ecpoint_len, &ecpoint_len)) {
        TRACE_ERROR("EVP_PKEY_get_octet_string_param failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#endif

    rc = ber_encode_OCTET_STRING(FALSE, &enc_ecpoint, &enc_ecpoint_len,
                                 ecpoint, ecpoint_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
        goto out;
    }

    rc = build_attribute(CKA_EC_POINT, enc_ecpoint, enc_ecpoint_len,
                         &ec_point_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_attribute for CKA_EC_POINT failed rc=0x%lx\n", rc);
        goto out;
    }
    rc = template_update_attribute(publ_tmpl, ec_point_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(ec_point_attr);
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    d_len = EC_KEY_priv2buf(ec_key, &d);
    if (d_len == 0) {
        TRACE_ERROR("Failed to get the EC private key.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#else
    if (!EVP_PKEY_get_bn_param(ec_pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_d)) {
        TRACE_ERROR("EVP_PKEY_get_bn_param failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    len = ec_prime_len_from_nid(nid);
    if (len <= 0) {
        TRACE_ERROR("ec_prime_len_from_nid failed\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }
    d_len = len;
    d = OPENSSL_zalloc(d_len);
    if (d == NULL) {
        TRACE_ERROR("OPENSSL_zalloc failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    BN_bn2binpad(bn_d, d, d_len);
#endif

    rc = build_attribute(CKA_VALUE, d, d_len, &value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_attribute for CKA_VALUE failed, rc=0x%lx\n", rc);
        goto out;
    }
    rc = template_update_attribute(priv_tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(value_attr);
        goto out;
    }


    /* Add CKA_ECDSA_PARAMS to private template also */
    rc = build_attribute(CKA_ECDSA_PARAMS, attr->pValue, attr->ulValueLen,
                         &parms_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_attribute for CKA_ECDSA_PARAMS failed, rc=0x%lx\n",
                     rc);
        goto out;
    }
    rc = template_update_attribute(priv_tmpl, parms_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(parms_attr);
        goto out;
    }

    rc = CKR_OK;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (bnctx != NULL)
        BN_CTX_free(bnctx);
#else
    if (bn_d != NULL)
        BN_free(bn_d);
#endif
    if (ec_pkey != NULL)
        EVP_PKEY_free(ec_pkey);
    if (ecpoint != NULL)
        OPENSSL_free(ecpoint);
    if (enc_ecpoint != NULL)
        free(enc_ecpoint);
    if (d != NULL)
        OPENSSL_free(d);

    return rc;
}

CK_RV openssl_specific_ec_sign(STDLL_TokData_t *tokdata,  SESSION *sess,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *out_data, CK_ULONG *out_data_len,
                               OBJECT *key_obj)
{
    struct openssl_ex_data *ex_data = NULL;
    EVP_PKEY *ec_key = NULL;
    ECDSA_SIG *sig = NULL;
    const BIGNUM *r, *s;
    CK_ULONG privlen, n;
    CK_RV rc = CKR_OK;
    EVP_PKEY_CTX *ctx = NULL;
    size_t siglen;
    CK_BYTE *sigbuf = NULL;
    const unsigned char *p;
    int len;

    UNUSED(tokdata);
    UNUSED(sess);

    *out_data_len = 0;

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(struct openssl_ex_data),
                             openssl_need_wr_lock, NULL);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->pkey == NULL) {
        rc = openssl_make_ec_key_from_template(key_obj->template,
                                               &ex_data->pkey);
        if (rc != CKR_OK)
            goto out;
    }

    ec_key = ex_data->pkey;
    if (EVP_PKEY_up_ref(ec_key) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    ctx = EVP_PKEY_CTX_new(ec_key, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        TRACE_ERROR("EVP_PKEY_sign_init failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_sign(ctx, NULL, &siglen, in_data, in_data_len) <= 0) {
        TRACE_ERROR("EVP_PKEY_sign failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    sigbuf = malloc(siglen);
    if (sigbuf == NULL) {
        TRACE_ERROR("malloc failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (EVP_PKEY_sign(ctx, sigbuf, &siglen, in_data, in_data_len) <= 0) {
        TRACE_ERROR("EVP_PKEY_sign failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    p = sigbuf;
    sig = d2i_ECDSA_SIG(NULL, &p, siglen);
    if (sig == NULL) {
        TRACE_ERROR("d2i_ECDSA_SIG failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    ECDSA_SIG_get0(sig, &r, &s);

    len = ec_prime_len_from_pkey(ec_key);
    if (len <= 0) {
        TRACE_ERROR("ec_prime_len_from_pkey failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
    privlen = len;

    /* Insert leading 0's if r or s shorter than privlen */
    n = privlen - BN_num_bytes(r);
    memset(out_data, 0, n);
    BN_bn2bin(r, &out_data[n]);

    n = privlen - BN_num_bytes(s);
    memset(out_data + privlen, 0x00, n);
    BN_bn2bin(s, &out_data[privlen + n]);

    *out_data_len = 2 * privlen;

out:
    if (sig != NULL)
        ECDSA_SIG_free(sig);
    if (ec_key != NULL)
        EVP_PKEY_free(ec_key);
    if (sigbuf != NULL)
        free(sigbuf);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    object_ex_data_unlock(key_obj);

    return rc;
}

CK_RV openssl_specific_ec_verify(STDLL_TokData_t *tokdata,
                                 SESSION *sess,
                                 CK_BYTE *in_data,
                                 CK_ULONG in_data_len,
                                 CK_BYTE *signature,
                                 CK_ULONG signature_len, OBJECT *key_obj)
{
    struct openssl_ex_data *ex_data = NULL;
    EVP_PKEY *ec_key = NULL;
    CK_ULONG privlen;
    ECDSA_SIG *sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    CK_RV rc = CKR_OK;
    int len;
    size_t siglen;
    CK_BYTE *sigbuf = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    UNUSED(tokdata);
    UNUSED(sess);

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(struct openssl_ex_data),
                             openssl_need_wr_lock, NULL);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->pkey == NULL) {
        rc = openssl_make_ec_key_from_template(key_obj->template,
                                               &ex_data->pkey);
        if (rc != CKR_OK)
            goto out;
    }

    ec_key = ex_data->pkey;
    if (EVP_PKEY_up_ref(ec_key) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    len = ec_prime_len_from_pkey(ec_key);
    if (len <= 0) {
        TRACE_ERROR("ec_prime_len_from_pkey failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
    privlen = len;

    if (signature_len < 2 * privlen) {
        TRACE_ERROR("Signature is too short\n");
        rc = CKR_SIGNATURE_LEN_RANGE;
        goto out;
    }

    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    r = BN_bin2bn(signature, privlen, NULL);
    s = BN_bin2bn(signature + privlen, privlen, NULL);
    if (r == NULL || s == NULL) {
        TRACE_ERROR("BN_bin2bn failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!ECDSA_SIG_set0(sig, r, s)) {
        TRACE_ERROR("ECDSA_SIG_set0 failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    len = i2d_ECDSA_SIG(sig, &sigbuf);
    if (len <= 0) {
        TRACE_ERROR("i2d_ECDSA_SIG failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
    siglen = len;

    ctx = EVP_PKEY_CTX_new(ec_key, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        TRACE_ERROR("EVP_PKEY_verify_init failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = EVP_PKEY_verify(ctx, sigbuf, siglen, in_data, in_data_len);
    switch (rc) {
    case 0:
        rc = CKR_SIGNATURE_INVALID;
        break;
    case 1:
        rc = CKR_OK;
        break;
    default:
        rc = CKR_FUNCTION_FAILED;
        break;
    }

out:
    if (sig != NULL)
        ECDSA_SIG_free(sig);
    if (ec_key != NULL)
        EVP_PKEY_free(ec_key);
    if (sigbuf != NULL)
        OPENSSL_free(sigbuf);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    object_ex_data_unlock(key_obj);

    return rc;
}

CK_RV openssl_specific_ecdh_pkcs_derive(STDLL_TokData_t *tokdata,
                                        CK_BYTE *priv_bytes,
                                        CK_ULONG priv_length,
                                        CK_BYTE *pub_bytes,
                                        CK_ULONG pub_length,
                                        CK_BYTE *secret_value,
                                        CK_ULONG *secret_value_len,
                                        CK_BYTE *oid, CK_ULONG oid_length)
{
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EC_KEY *pub = NULL, *priv = NULL;
#else
    OSSL_PARAM_BLD *tmpl = NULL;
#endif
    EVP_PKEY *ec_pub = NULL, *ec_priv = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t secret_len;
    int nid, len;
    CK_RV rc;

    UNUSED(tokdata);

    nid = curve_nid_from_params(oid, oid_length);
    if (nid == NID_undef) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = make_ec_key_from_params(oid, oid_length, &priv);
    if (rc != CKR_OK) {
        TRACE_DEVEL("make_ec_key_from_params failed\n");
        goto out;
    }
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        TRACE_ERROR("OSSL_PARAM_BLD_new failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(tmpl, OSSL_PKEY_PARAM_GROUP_NAME,
                                         OBJ_nid2sn(nid), 0)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_utf8_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#endif

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = fill_ec_key_from_privkey(priv, priv_bytes, priv_length, &ec_priv);
#else
    rc = fill_ec_key_from_privkey(tmpl, priv_bytes, priv_length, nid, &ec_priv);
#endif
    if (rc != CKR_OK) {
        TRACE_DEVEL("fill_ec_key_from_privkey failed\n");
        goto out;
    }
#if !OPENSSL_VERSION_PREREQ(3, 0)
    priv = NULL;
#else
    OSSL_PARAM_BLD_free(tmpl);
    tmpl = NULL;
#endif

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = make_ec_key_from_params(oid, oid_length, &pub);
    if (rc != CKR_OK) {
        TRACE_DEVEL("make_ec_key_from_params failed\n");
        goto out;
    }
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        TRACE_ERROR("OSSL_PARAM_BLD_new failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(tmpl, OSSL_PKEY_PARAM_GROUP_NAME,
                                         OBJ_nid2sn(nid), 0)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_utf8_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#endif

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = fill_ec_key_from_pubkey(pub, pub_bytes, pub_length, TRUE, nid,
                                 &ec_pub);
#else
    rc = fill_ec_key_from_pubkey(tmpl, pub_bytes, pub_length, TRUE, nid,
                                 &ec_pub);
#endif
    if (rc != CKR_OK) {
        TRACE_DEVEL("fill_ec_key_from_pubkey failed\n");
        goto out;
    }
#if !OPENSSL_VERSION_PREREQ(3, 0)
    pub = NULL;
#else
    OSSL_PARAM_BLD_free(tmpl);
    tmpl = NULL;
#endif

    ctx = EVP_PKEY_CTX_new(ec_priv, NULL);
    if (ctx == NULL) {
        TRACE_DEVEL("EVP_PKEY_CTX_new failed\n");
        goto out;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, ec_pub) <= 0) {
        TRACE_DEVEL("EVP_PKEY_derive_init/EVP_PKEY_derive_set_peer failed\n");
        goto out;
    }

    len = ec_prime_len_from_nid(nid);
    if (len <= 0) {
        TRACE_ERROR("ec_prime_len_from_nid failed\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }
    secret_len = len;
    if (EVP_PKEY_derive(ctx, secret_value, &secret_len) <= 0) {
        TRACE_DEVEL("ECDH_compute_key failed\n");
        rc = CKR_FUNCTION_FAILED;
        *secret_value_len = 0;
        goto out;
    }

    *secret_value_len = secret_len;

out:
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (priv != NULL)
        EC_KEY_free(priv);
    if (pub != NULL)
        EC_KEY_free(pub);
#else
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
#endif
    if (ec_priv != NULL)
        EVP_PKEY_free(ec_priv);
    if (ec_pub != NULL)
        EVP_PKEY_free(ec_pub);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return rc;
}

#endif

static const EVP_MD *md_from_mech(CK_MECHANISM *mech)
{
    const EVP_MD *md = NULL;

    switch (mech->mechanism) {
    case CKM_SHA_1:
        md = EVP_sha1();
        break;
    case CKM_SHA224:
        md = EVP_sha224();
        break;
    case CKM_SHA256:
        md = EVP_sha256();
        break;
    case CKM_SHA384:
        md = EVP_sha384();
        break;
    case CKM_SHA512:
        md = EVP_sha512();
        break;
#ifdef NID_sha512_224WithRSAEncryption
    case CKM_SHA512_224:
        md = EVP_sha512_224();
        break;
#endif
#ifdef NID_sha512_256WithRSAEncryption
    case CKM_SHA512_256:
        md = EVP_sha512_256();
        break;
#endif
#ifdef NID_sha3_224
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        md = EVP_sha3_224();
        break;
#endif
#ifdef NID_sha3_256
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        md = EVP_sha3_256();
        break;
#endif
#ifdef NID_sha3_384
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        md = EVP_sha3_384();
        break;
#endif
#ifdef NID_sha3_512
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        md = EVP_sha3_512();
        break;
#endif
    default:
        break;
    }

    return md;
}

#if !OPENSSL_VERSION_PREREQ(3, 0)
static EVP_MD_CTX *md_ctx_from_context(DIGEST_CONTEXT *ctx)
{
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx;

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        return NULL;

    md = md_from_mech(&ctx->mech);
    if (md == NULL ||
        !EVP_DigestInit_ex(md_ctx, md, NULL)) {
        TRACE_ERROR("md_from_mech or EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    if (ctx->context_len == 0) {
        ctx->context_len = EVP_MD_meth_get_app_datasize(EVP_MD_CTX_md(md_ctx));
        ctx->context = malloc(ctx->context_len);
        if (ctx->context == NULL) {
            TRACE_ERROR("malloc failed\n");
            EVP_MD_CTX_free(md_ctx);
            ctx->context_len = 0;
            return NULL;
        }

        /* Save context data for later use */
        memcpy(ctx->context,  EVP_MD_CTX_md_data(md_ctx), ctx->context_len);
    } else {
        if (ctx->context_len !=
                (CK_ULONG)EVP_MD_meth_get_app_datasize(EVP_MD_CTX_md(md_ctx))) {
            TRACE_ERROR("context size mismatcht\n");
            return NULL;
        }
        /* restore the MD context data */
        memcpy(EVP_MD_CTX_md_data(md_ctx), ctx->context, ctx->context_len);
    }

    return md_ctx;
}
#endif

#if OPENSSL_VERSION_PREREQ(3, 0)
static void openssl_specific_sha_free(STDLL_TokData_t *tokdata, SESSION *sess,
                                      CK_BYTE *context, CK_ULONG context_len)
{
    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(context_len);

    EVP_MD_CTX_free((EVP_MD_CTX *)context);
}
#endif

CK_RV openssl_specific_sha_init(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                CK_MECHANISM *mech)
{
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EVP_MD_CTX *md_ctx;
#else
    const EVP_MD *md;
#endif

    UNUSED(tokdata);

    ctx->mech.ulParameterLen = mech->ulParameterLen;
    ctx->mech.mechanism = mech->mechanism;

#if !OPENSSL_VERSION_PREREQ(3, 0)
    md_ctx = md_ctx_from_context(ctx);
    if (md_ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    EVP_MD_CTX_free(md_ctx);
#else
    ctx->context_len = 1;
    ctx->context = (CK_BYTE *)EVP_MD_CTX_new();
    if (ctx->context == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    md = md_from_mech(&ctx->mech);
    if (md == NULL ||
        !EVP_DigestInit_ex((EVP_MD_CTX *)ctx->context, md, NULL)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        EVP_MD_CTX_free((EVP_MD_CTX *)ctx->context);
        return CKR_FUNCTION_FAILED;
    }

    ctx->state_unsaveable = CK_TRUE;
    ctx->context_free_func = openssl_specific_sha_free;
#endif

    return CKR_OK;
}

CK_RV openssl_specific_sha(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                           CK_BYTE *in_data, CK_ULONG in_data_len,
                           CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    unsigned int len;
    CK_RV rc = CKR_OK;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EVP_MD_CTX *md_ctx;
#endif

    UNUSED(tokdata);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!in_data || !out_data)
        return CKR_ARGUMENTS_BAD;

#if !OPENSSL_VERSION_PREREQ(3, 0)
    /* Recreate the OpenSSL MD context from the saved context */
    md_ctx = md_ctx_from_context(ctx);
    if (md_ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (*out_data_len < (CK_ULONG)EVP_MD_CTX_size(md_ctx))
        return CKR_BUFFER_TOO_SMALL;

    if (!EVP_DigestUpdate(md_ctx, in_data, in_data_len) ||
        !EVP_DigestFinal(md_ctx, out_data, &len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    *out_data_len = len;
#else
    if (*out_data_len < (CK_ULONG)EVP_MD_CTX_size((EVP_MD_CTX *)ctx->context)) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    len = *out_data_len;
    if (!EVP_DigestUpdate((EVP_MD_CTX *)ctx->context, in_data, in_data_len) ||
        !EVP_DigestFinal((EVP_MD_CTX *)ctx->context, out_data, &len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    *out_data_len = len;
#endif

#if !OPENSSL_VERSION_PREREQ(3, 0)
out:
    EVP_MD_CTX_free(md_ctx);
    free(ctx->context);
#else
    EVP_MD_CTX_free((EVP_MD_CTX *)ctx->context);
#endif
    ctx->context = NULL;
    ctx->context_len = 0;
    ctx->context_free_func = NULL;

    return rc;
}

CK_RV openssl_specific_sha_update(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                  CK_BYTE *in_data, CK_ULONG in_data_len)
{
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EVP_MD_CTX *md_ctx;
#endif

    UNUSED(tokdata);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!in_data)
        return CKR_ARGUMENTS_BAD;

#if !OPENSSL_VERSION_PREREQ(3, 0)
    /* Recreate the OpenSSL MD context from the saved context */
    md_ctx = md_ctx_from_context(ctx);
    if (md_ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (!EVP_DigestUpdate(md_ctx, in_data, in_data_len)) {
        EVP_MD_CTX_free(md_ctx);
        free(ctx->context);
        ctx->context = NULL;
        ctx->context_len = 0;
        ctx->context_free_func = NULL;
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    /* Save context data for later use */
    memcpy(ctx->context,  EVP_MD_CTX_md_data(md_ctx), ctx->context_len);

    EVP_MD_CTX_free(md_ctx);
#else
    if (!EVP_DigestUpdate((EVP_MD_CTX *)ctx->context, in_data, in_data_len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
#endif

    return CKR_OK;
}

CK_RV openssl_specific_sha_final(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                 CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    unsigned int len;
    CK_RV rc = CKR_OK;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EVP_MD_CTX *md_ctx;
#endif

    UNUSED(tokdata);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!out_data)
        return CKR_ARGUMENTS_BAD;

#if !OPENSSL_VERSION_PREREQ(3, 0)
    /* Recreate the OpenSSL MD context from the saved context */
    md_ctx = md_ctx_from_context(ctx);
    if (md_ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (*out_data_len < (CK_ULONG)EVP_MD_CTX_size(md_ctx))
        return CKR_BUFFER_TOO_SMALL;

    if (!EVP_DigestFinal(md_ctx, out_data, &len)) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
    *out_data_len = len;

out:
    EVP_MD_CTX_free(md_ctx);
    free(ctx->context);
    ctx->context = NULL;
    ctx->context_len = 0;
    ctx->context_free_func = NULL;
#else
    if (*out_data_len < (CK_ULONG)EVP_MD_CTX_size((EVP_MD_CTX *)ctx->context)) {
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
    ctx->context_len = 0;
    ctx->context_free_func = NULL;
#endif

    return rc;
}

CK_RV openssl_specific_shake_key_derive(STDLL_TokData_t *tokdata, SESSION *sess,
                                        CK_MECHANISM *mech,
                                        OBJECT *base_key_obj,
                                        CK_KEY_TYPE base_key_type,
                                        OBJECT *derived_key_obj,
                                        CK_KEY_TYPE derived_key_type,
                                        CK_ULONG derived_key_len)
{
    CK_ATTRIBUTE *base_key_value = NULL;
    CK_ATTRIBUTE *value_attr = NULL, *vallen_attr = NULL;
    CK_BYTE *derived_key_value = NULL;
    EVP_MD_CTX *ctx = NULL;
    const EVP_MD *md = NULL;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(base_key_type);

    rc = template_attribute_get_non_empty(base_key_obj->template,
                                          CKA_VALUE, &base_key_value);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the base key.\n");
        return rc;
    }

    derived_key_value = malloc(derived_key_len);
    if (derived_key_value == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    switch (mech->mechanism) {
    case CKM_SHAKE_128_KEY_DERIVATION:
        md = EVP_shake128();
        break;
    case CKM_SHAKE_256_KEY_DERIVATION:
        md = EVP_shake256();
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto out;
    }

    if (md == NULL ||
        !EVP_DigestInit_ex(ctx, md, NULL) ||
        !EVP_DigestUpdate(ctx, base_key_value->pValue,
                          base_key_value->ulValueLen) ||
        !EVP_DigestFinalXOF(ctx, derived_key_value, derived_key_len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = build_attribute(CKA_VALUE, derived_key_value, derived_key_len,
                         &value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to build the attribute from CKA_VALUE, rc=0x%lx.\n",
                    rc);
        goto out;
    }

    switch (derived_key_type) {
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
        /* Supply CKA_VALUE_LEN since this is required for those key types */
        rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE*)&derived_key_len,
                             sizeof(derived_key_len), &vallen_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to build the attribute from CKA_VALUE_LEN, "
                        "rc=0x%lx.\n", rc);
            goto out;
        }
        break;
    case CKK_DES:
        if (des_check_weak_key(derived_key_value)) {
            TRACE_ERROR("Derived key is a weak DES key\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
        break;
    default:
        break;
    }

    rc = template_update_attribute(derived_key_obj->template, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto out;
    }
    value_attr = NULL;

    if (vallen_attr != NULL) {
        rc = template_update_attribute(derived_key_obj->template, vallen_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto out;
        }
        vallen_attr = NULL;
    }

out:
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);

    if (derived_key_value != NULL) {
        OPENSSL_cleanse(derived_key_value, derived_key_len);
        free(derived_key_value);
    }

    if (value_attr != NULL)
        free(value_attr);
    if (vallen_attr != NULL)
        free(vallen_attr);

    return rc;
}

static const EVP_CIPHER *openssl_cipher_from_mech(CK_MECHANISM_TYPE mech,
                                                  CK_ULONG keylen,
                                                  CK_KEY_TYPE keytype)
{
    switch (mech) {
    case CKM_DES_ECB:
        if (keytype == CKK_DES && keylen == DES_KEY_SIZE)
            return EVP_des_ecb();
        break;
    case CKM_DES_CBC:
        if (keytype == CKK_DES && keylen == DES_KEY_SIZE)
            return EVP_des_cbc();
        break;
    case CKM_DES3_ECB:
        if (keytype == CKK_DES2 && keylen == DES_KEY_SIZE * 2)
            return EVP_des_ede_ecb();
        if (keytype == CKK_DES3 && keylen == DES_KEY_SIZE * 3)
            return EVP_des_ede3_ecb();
        break;
    case CKM_DES3_CBC:
        if (keytype == CKK_DES2 && keylen == DES_KEY_SIZE * 2)
            return EVP_des_ede_cbc();
        if (keytype == CKK_DES3 && keylen == DES_KEY_SIZE * 3)
            return EVP_des_ede3_cbc();
        break;
    case CKM_DES_OFB64:
        if (keytype == CKK_DES && keylen == DES_KEY_SIZE)
            return EVP_des_ofb();
        if (keytype == CKK_DES2 && keylen == DES_KEY_SIZE * 2)
            return EVP_des_ede_ofb();
        if (keytype == CKK_DES3 && keylen == DES_KEY_SIZE * 3)
            return EVP_des_ede3_ofb();
        break;
    case CKM_DES_CFB8:
        if (keytype == CKK_DES && keylen == DES_KEY_SIZE)
            return EVP_des_cfb8();
        if (keytype == CKK_DES3 && keylen == DES_KEY_SIZE * 3)
            return EVP_des_ede3_cfb8();
        break;
    case CKM_DES_CFB64:
        if (keytype == CKK_DES && keylen == DES_KEY_SIZE)
            return EVP_des_cfb64();
        if (keytype == CKK_DES2 && keylen == DES_KEY_SIZE * 2)
            return EVP_des_ede_cfb64();
        if (keytype == CKK_DES3 && keylen == DES_KEY_SIZE * 3)
            return EVP_des_ede3_cfb64();
        break;
    case CKM_AES_ECB:
        if (keytype != CKK_AES)
            break;
        switch (keylen * 8) {
        case 128:
            return EVP_aes_128_ecb();
        case 192:
            return EVP_aes_192_ecb();
        case 256:
            return EVP_aes_256_ecb();
        default:
            break;
        }
        break;
    case CKM_AES_CBC:
        if (keytype != CKK_AES)
            break;
        switch (keylen * 8) {
        case 128:
            return EVP_aes_128_cbc();
        case 192:
            return EVP_aes_192_cbc();
        case 256:
            return EVP_aes_256_cbc();
        default:
            break;
        }
        break;
    case CKM_AES_CTR:
        if (keytype != CKK_AES)
            break;
        switch (keylen * 8) {
        case 128:
            return EVP_aes_128_ctr();
        case 192:
            return EVP_aes_192_ctr();
        case 256:
            return EVP_aes_256_ctr();
        default:
            break;
        }
        break;
    case CKM_AES_OFB:
        if (keytype != CKK_AES)
            break;
        switch (keylen * 8) {
        case 128:
            return EVP_aes_128_ofb();
        case 192:
            return EVP_aes_192_ofb();
        case 256:
            return EVP_aes_256_ofb();
        default:
            break;
        }
        break;
    case CKM_AES_CFB8:
        if (keytype != CKK_AES)
            break;
        switch (keylen * 8) {
        case 128:
            return EVP_aes_128_cfb8();
        case 192:
            return EVP_aes_192_cfb8();
        case 256:
            return EVP_aes_256_cfb8();
        default:
            break;
        }
        break;
    case CKM_AES_CFB128:
        if (keytype != CKK_AES)
            break;
        switch (keylen * 8) {
        case 128:
            return EVP_aes_128_cfb128();
        case 192:
            return EVP_aes_192_cfb128();
        case 256:
            return EVP_aes_256_cfb128();
        default:
            break;
        }
        break;
    case CKM_AES_GCM:
        if (keytype != CKK_AES)
            break;
        switch (keylen * 8) {
        case 128:
            return EVP_aes_128_gcm();
        case 192:
            return EVP_aes_192_gcm();
        case 256:
            return EVP_aes_256_gcm();
        default:
            break;
        }
        break;
    case CKM_AES_XTS:
        if (keytype != CKK_AES_XTS)
            break;
        switch (keylen * 8) {
        case 256:
            return EVP_aes_128_xts();
        case 512:
            return EVP_aes_256_xts();
        default:
            break;
        }
        break;
    case CKM_AES_KEY_WRAP:
        if (keytype != CKK_AES)
            break;
        switch (keylen * 8) {
        case 128:
            return EVP_aes_128_wrap();
        case 192:
            return EVP_aes_192_wrap();
        case 256:
            return EVP_aes_256_wrap();
        default:
            break;
        }
        break;
    case CKM_AES_KEY_WRAP_KWP:
        if (keytype != CKK_AES)
            break;
        switch (keylen * 8) {
        case 128:
            return EVP_aes_128_wrap_pad();
        case 192:
            return EVP_aes_192_wrap_pad();
        case 256:
            return EVP_aes_256_wrap_pad();
        default:
            break;
        }
        break;
    default:
        TRACE_ERROR("mechanism 0x%lx not supported\n", mech);
        return NULL;
    }

    TRACE_ERROR("key length %lu or key type %lu not supported for mech 0x%lx\n",
                            keylen, keytype, mech);
    return NULL;
}

static CK_RV openssl_cipher_perform(OBJECT *key, CK_MECHANISM_TYPE mech,
                                    CK_BYTE *in_data,  CK_ULONG in_data_len,
                                    CK_BYTE *out_data, CK_ULONG *out_data_len,
                                    CK_BYTE *init_v, CK_BYTE *out_v,
                                    CK_BYTE encrypt)
{
    const EVP_CIPHER *cipher = NULL;
    CK_ATTRIBUTE *key_attr = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    CK_KEY_TYPE keytype = 0;
    int blocksize, outlen = 0, outlen2 = 0;
    CK_RV rc;

    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &key_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    cipher = openssl_cipher_from_mech(mech, key_attr->ulValueLen, keytype);
    if (cipher == NULL) {
        TRACE_ERROR("Cipher not supported.\n");
        return CKR_MECHANISM_INVALID;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    blocksize = EVP_CIPHER_block_size(cipher);
#else
    blocksize = EVP_CIPHER_get_block_size(cipher);
#endif
    if ((mech != CKM_AES_KEY_WRAP_KWP &&
         (mech == CKM_AES_XTS ? in_data_len < AES_BLOCK_SIZE :
                               in_data_len % blocksize)) ||
        in_data_len > INT_MAX) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    switch (mech) {
    case CKM_AES_KEY_WRAP:
    case CKM_AES_KEY_WRAP_KWP:
        EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
        break;
    }

    if (EVP_CipherInit_ex(ctx, cipher, NULL, key_attr->pValue,
                          init_v, encrypt ? 1 : 0) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    if (EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
        || EVP_CipherUpdate(ctx, out_data, &outlen, in_data, in_data_len) != 1
        || EVP_CipherFinal_ex(ctx, out_data, &outlen2) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    if (out_v != NULL) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
        memcpy(out_v, EVP_CIPHER_CTX_iv(ctx), EVP_CIPHER_CTX_iv_length(ctx));
#else
        if (EVP_CIPHER_CTX_get_updated_iv(ctx, out_v,
                                EVP_CIPHER_CTX_get_iv_length(ctx)) != 1) {
            TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
            rc = CKR_GENERAL_ERROR;
            goto done;
        }
#endif
    }

    *out_data_len = outlen + outlen2;
    rc = CKR_OK;

done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV openssl_cmac_perform(CK_MECHANISM_TYPE mech, CK_BYTE *message,
                           CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                           CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{
    int rc;
    size_t maclen;
    CK_RV rv = CKR_OK;
    CK_ATTRIBUTE *key_attr = NULL;
    const EVP_CIPHER *cipher;
    CK_KEY_TYPE keytype = 0;
    struct cmac_ctx {
#if !OPENSSL_VERSION_PREREQ(3, 0)
        EVP_MD_CTX *mctx;
        EVP_PKEY_CTX *pctx;
        EVP_PKEY *pkey;
#else
        EVP_MAC *mac;
        EVP_MAC_CTX *mctx;
#endif
        int macsize;
    };
    struct cmac_ctx *cmac = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    OSSL_PARAM params[2];
#endif

    if (first) {
        if (key == NULL)
            return CKR_ARGUMENTS_BAD;

        rv = template_attribute_get_ulong(key->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rv != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
            goto err;
        }

        rv = template_attribute_get_non_empty(key->template, CKA_VALUE,
                                              &key_attr);
        if (rv != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
            goto err;
        }

        switch (mech) {
        case CKM_AES_CMAC:
            cipher = openssl_cipher_from_mech(CKM_AES_CBC,
                                              key_attr->ulValueLen, keytype);
            break;
        case CKM_DES3_CMAC:
            cipher = openssl_cipher_from_mech(CKM_DES3_CBC,
                                              key_attr->ulValueLen,
                                              keytype);
            break;
         default:
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
            rv = CKR_MECHANISM_INVALID;
            goto err;
        }

        if (cipher == NULL) {
            TRACE_ERROR("Cipher not supported.\n");
            rv = CKR_MECHANISM_INVALID;
            goto err;
        }

        cmac = calloc(1, sizeof(*cmac));
        if (cmac == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        cmac->macsize = EVP_CIPHER_block_size(cipher);

#if !OPENSSL_VERSION_PREREQ(3, 0)
        cmac->mctx = EVP_MD_CTX_new();
        if (cmac->mctx == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        cmac->pkey = EVP_PKEY_new_CMAC_key(NULL, key_attr->pValue,
                                           key_attr->ulValueLen, cipher);
        if (cmac->pkey == NULL) {
            TRACE_ERROR("EVP_DigestSignInit failed\n");
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }

        if (EVP_DigestSignInit(cmac->mctx, &cmac->pctx,
                               NULL, NULL, cmac->pkey) != 1) {
            TRACE_ERROR("EVP_DigestSignInit failed\n");
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }
#else
        cmac->mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
        if (cmac->mac == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }

        cmac->mctx = EVP_MAC_CTX_new(cmac->mac);
        if (cmac->mctx == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                      (char *)EVP_CIPHER_get0_name(cipher), 0);
        params[1] = OSSL_PARAM_construct_end();

        if (!EVP_MAC_init(cmac->mctx, key_attr->pValue, key_attr->ulValueLen,
                          params)) {
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }
#endif

        *ctx = cmac;
    }

    cmac = (struct cmac_ctx *)*ctx;
    if (cmac == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rv =  CKR_FUNCTION_FAILED;
        goto err;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = EVP_DigestSignUpdate(cmac->mctx, message, message_len);
#else
    rc = EVP_MAC_update(cmac->mctx, message, message_len);
#endif
    if (rc != 1 || message_len > INT_MAX) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
        TRACE_ERROR("EVP_DigestSignUpdate failed\n");
#else
        TRACE_ERROR("EVP_MAC_update failed\n");
#endif
        rv =  CKR_FUNCTION_FAILED;
        goto err;
    }

    if (last) {
        maclen = cmac->macsize;
#if !OPENSSL_VERSION_PREREQ(3, 0)
        rc = EVP_DigestSignFinal(cmac->mctx, mac, &maclen);
#else
        rc = EVP_MAC_final(cmac->mctx, mac, &maclen, maclen);
#endif
        if (rc != 1) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
            TRACE_ERROR("EVP_DigestSignFinal failed\n");
#else
            TRACE_ERROR("EVP_MAC_final failed\n");
#endif
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }

#if !OPENSSL_VERSION_PREREQ(3, 0)
        EVP_MD_CTX_free(cmac->mctx); /* frees pctx */
        EVP_PKEY_free(cmac->pkey);
#else
        EVP_MAC_CTX_free(cmac->mctx);
        EVP_MAC_free(cmac->mac);
#endif
        free(cmac);
        *ctx = NULL;
    }

    return CKR_OK;
err:
    if (cmac != NULL) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
        if (cmac->mctx != NULL)
            EVP_MD_CTX_free(cmac->mctx); /* frees pctx */
        if (cmac->pkey != NULL)
            EVP_PKEY_free(cmac->pkey);
#else
        if (cmac->mctx != NULL)
            EVP_MAC_CTX_free(cmac->mctx);
        if (cmac->mac != NULL)
            EVP_MAC_free(cmac->mac);
#endif
        free(cmac);
    }
    *ctx = NULL;
    return rv;
}

CK_RV openssl_specific_aes_ecb(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               CK_ULONG *out_data_len,
                               OBJECT *key, CK_BYTE encrypt)
{
    UNUSED(tokdata);

    return openssl_cipher_perform(key, CKM_AES_ECB, in_data, in_data_len,
                                  out_data, out_data_len, NULL, NULL,
                                  encrypt);
}

CK_RV openssl_specific_aes_cbc(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               CK_ULONG *out_data_len,
                               OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    UNUSED(tokdata);

    return openssl_cipher_perform(key, CKM_AES_CBC, in_data, in_data_len,
                                  out_data, out_data_len, init_v, NULL,
                                  encrypt);
}

CK_RV openssl_specific_aes_ctr(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               CK_ULONG *out_data_len,
                               OBJECT *key,
                               CK_BYTE *counterblock,
                               CK_ULONG counter_width, CK_BYTE encrypt)
{
    unsigned char init_v[AES_BLOCK_SIZE];
    CK_RV rc;

    UNUSED(tokdata);

    if (counter_width > AES_BLOCK_SIZE * 8 || counter_width == 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    memset(init_v, 0, sizeof(init_v));
    memcpy(init_v, counterblock + AES_BLOCK_SIZE - (counter_width / 8),
           counter_width / 8);

    rc = openssl_cipher_perform(key, CKM_AES_CTR, in_data, in_data_len,
                                  out_data, out_data_len, init_v, init_v,
                                  encrypt);

    if (rc == CKR_OK)
        memcpy(counterblock, init_v + AES_BLOCK_SIZE - (counter_width / 8),
               counter_width / 8);

    return rc;
}

CK_RV openssl_specific_aes_ofb(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               OBJECT *key,
                               CK_BYTE *init_v, CK_BYTE encrypt)
{
    CK_ULONG out_data_len;

    UNUSED(tokdata);

    return openssl_cipher_perform(key, CKM_AES_OFB, in_data, in_data_len,
                                  out_data, &out_data_len, init_v, init_v,
                                  encrypt);
}

CK_RV openssl_specific_aes_cfb(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               OBJECT *key,
                               CK_BYTE *init_v, CK_ULONG cfb_len,
                               CK_BYTE encrypt)
{
    CK_ULONG out_data_len;
    CK_MECHANISM_TYPE mech;

    UNUSED(tokdata);

    switch (cfb_len * 8) {
    case 8:
        mech = CKM_AES_CFB8;
        break;
    case 128:
        mech = CKM_AES_CFB128;
        break;
    default:
        TRACE_ERROR("CFB length %lu not supported\n", cfb_len);
        return CKR_MECHANISM_INVALID;
    }

    return openssl_cipher_perform(key, mech, in_data, in_data_len,
                                  out_data, &out_data_len, init_v, init_v,
                                  encrypt);
}

static void openssl_specific_aes_gcm_free(STDLL_TokData_t *tokdata,
                                          struct _SESSION *sess,
                                          CK_BYTE *context,
                                          CK_ULONG context_len)
{
    AES_GCM_CONTEXT *ctx = (AES_GCM_CONTEXT *)context;

    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(context_len);

    if (ctx == NULL)
        return;

    if ((EVP_CIPHER_CTX *)ctx->ulClen != NULL)
        EVP_CIPHER_CTX_free((EVP_CIPHER_CTX *)ctx->ulClen);

    free(context);
}

CK_RV openssl_specific_aes_gcm_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                    ENCR_DECR_CONTEXT *ctx, CK_MECHANISM *mech,
                                    CK_OBJECT_HANDLE hkey, CK_BYTE encrypt)
{
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    AES_GCM_CONTEXT *context = NULL;
    OBJECT *key = NULL;
    EVP_CIPHER_CTX *gcm_ctx = NULL;
    CK_ATTRIBUTE *attr = NULL;
    unsigned char akey[32];
    const EVP_CIPHER *cipher = NULL;
    CK_ULONG keylen, tag_len;
    int outlen;
    CK_RV rc;

    UNUSED(sess);

    context = (AES_GCM_CONTEXT *)ctx->context;
    aes_gcm_param = (CK_GCM_PARAMS *)mech->pParameter;

    tag_len = (aes_gcm_param->ulTagBits + 7) / 8;
    if (tag_len > AES_BLOCK_SIZE) {
        TRACE_ERROR("Tag len too large.\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    // get the key value
    rc = object_mgr_find_in_map_nocache(tokdata, hkey, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        goto done;
    }

    keylen = attr->ulValueLen;
    cipher = openssl_cipher_from_mech(mech->mechanism, keylen, CKK_AES);
    if (cipher == NULL) {
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    memcpy(akey, attr->pValue, keylen);

    gcm_ctx = EVP_CIPHER_CTX_new();
    if (gcm_ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(gcm_ctx, cipher, NULL, NULL, NULL,
                          encrypt ? 1 : 0) != 1 ||
        EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_AEAD_SET_IVLEN,
                            aes_gcm_param->ulIvLen, NULL) != 1 ||
        EVP_CipherInit_ex(gcm_ctx, NULL, NULL, akey, aes_gcm_param->pIv,
                          encrypt ? 1 : 0) != 1) {
        TRACE_ERROR("GCM context initialization failed\n");
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    if (aes_gcm_param->ulAADLen > 0) {
        if (EVP_CipherUpdate(gcm_ctx, NULL, &outlen, aes_gcm_param->pAAD,
                             aes_gcm_param->ulAADLen) != 1) {
            TRACE_ERROR("GCM add AAD data failed\n");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }
    }

    /* (Miss-)use the ulClen of AES_GCM_CONTEXT to store the context */
    context->ulClen = (CK_ULONG)gcm_ctx;
    ctx->state_unsaveable = CK_TRUE;
    ctx->context_free_func = openssl_specific_aes_gcm_free;

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    if (rc != CKR_OK)
        EVP_CIPHER_CTX_free(gcm_ctx);

    return rc;
}

CK_RV openssl_specific_aes_gcm(STDLL_TokData_t *tokdata, SESSION *sess,
                               ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                               CK_ULONG in_data_len, CK_BYTE *out_data,
                               CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    AES_GCM_CONTEXT *context = NULL;
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    EVP_CIPHER_CTX *gcm_ctx = NULL;
    CK_RV rc = CKR_OK;
    CK_ULONG tag_len;
    int outlen, finlen;

    UNUSED(tokdata);
    UNUSED(sess);

    context = (AES_GCM_CONTEXT *)ctx->context;
    gcm_ctx = (EVP_CIPHER_CTX *)context->ulClen;
    aes_gcm_param = (CK_GCM_PARAMS *)ctx->mech.pParameter;

    tag_len = (aes_gcm_param->ulTagBits + 7) / 8;

    if (encrypt) {
        /* encrypt */
        if (EVP_CipherUpdate(gcm_ctx, out_data, &outlen,
                             in_data, in_data_len) != 1 ||
            EVP_CipherFinal_ex(gcm_ctx, out_data + outlen, &finlen) != 1) {
            TRACE_ERROR("GCM add plaintext data failed\n");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        /* Append the tag to the output */
        if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_AEAD_GET_TAG, tag_len,
                                out_data + outlen + finlen) != 1) {
            TRACE_ERROR("GCM get tag failed\n");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        *out_data_len = outlen + finlen + tag_len;
    } else {
        /* decrypt data exluding the tag */
        if (EVP_CipherUpdate(gcm_ctx, out_data, &outlen,
                             in_data, in_data_len - tag_len) != 1) {
            TRACE_ERROR("GCM add ciphertext data failed\n");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        /* Set the expected tag */
        if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_AEAD_SET_TAG, tag_len,
                                in_data + in_data_len - tag_len) != 1) {
            TRACE_ERROR("GCM set tag failed\n");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        /* Finalize the decryption */
        if(EVP_CipherFinal_ex(gcm_ctx, out_data + outlen, &finlen) != 1) {
            TRACE_ERROR("GCM finalize decryption failed\n");
            rc = CKR_ENCRYPTED_DATA_INVALID;
            goto done;
        }

        *out_data_len = outlen + finlen;
    }

done:
    EVP_CIPHER_CTX_free(gcm_ctx);
    context->ulClen = (CK_ULONG)NULL;

    return rc;
}

CK_RV openssl_specific_aes_gcm_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                      ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                                      CK_ULONG in_data_len, CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    AES_GCM_CONTEXT *context = NULL;
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    EVP_CIPHER_CTX *gcm_ctx = NULL;
    CK_RV rc = CKR_OK;
    CK_ULONG tag_len, len, out_buf_len;
    int outlen;

    UNUSED(tokdata);
    UNUSED(sess);

    context = (AES_GCM_CONTEXT *)ctx->context;
    gcm_ctx = (EVP_CIPHER_CTX *)context->ulClen;
    aes_gcm_param = (CK_GCM_PARAMS *)ctx->mech.pParameter;

    if (gcm_ctx == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    tag_len = (aes_gcm_param->ulTagBits + 7) / 8;

    if (encrypt) {
        /* encrypt */
        if (*out_data_len < in_data_len) {
            TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
            *out_data_len = in_data_len;
            rc = CKR_BUFFER_TOO_SMALL;
            goto done;
        }

        if (EVP_CipherUpdate(gcm_ctx, out_data, &outlen,
                             in_data, in_data_len) != 1) {
            TRACE_ERROR("GCM update failed\n");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        *out_data_len = outlen;
    } else {
        /* decrypt */
        out_buf_len = *out_data_len;
        *out_data_len = 0;

        /* Buffer the last tag_len input bytes */
        if (in_data_len >= tag_len) {
            if (out_buf_len < context->len + (in_data_len - tag_len)) {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                *out_data_len = context->len + (in_data_len - tag_len);
                rc = CKR_BUFFER_TOO_SMALL;
                goto done;
            }

            /* push buffered data */
            if (context->len > 0) {
                if (EVP_CipherUpdate(gcm_ctx, out_data, &outlen,
                                     context->data, context->len) != 1) {
                    TRACE_ERROR("GCM update failed\n");
                    rc = CKR_GENERAL_ERROR;
                    goto done;
                }
                context->len = 0;
                *out_data_len += outlen;
                out_data += outlen;
            }

            /* push input data except tag_len last bytes */
            if (EVP_CipherUpdate(gcm_ctx, out_data, &outlen,
                                 in_data, in_data_len - tag_len) != 1) {
                 TRACE_ERROR("GCM update failed\n");
                 rc = CKR_GENERAL_ERROR;
                 goto done;
             }
             *out_data_len += outlen;
             out_data += outlen;

             /* save tag in buffer */
             memcpy(context->data, in_data + in_data_len - tag_len, tag_len);
             context->len = tag_len;
        } else if (context->len + in_data_len > tag_len) {
            /* push first bytes of buffer */
            len = context->len + in_data_len - tag_len;
            if (out_buf_len < len) {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                *out_data_len = len;
                rc = CKR_BUFFER_TOO_SMALL;
                goto done;
            }

            if (EVP_CipherUpdate(gcm_ctx, out_data, &outlen,
                                 context->data, len) != 1) {
                TRACE_ERROR("GCM update failed\n");
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
            *out_data_len += outlen;
            out_data += outlen;

            /* move remaining to beginning of buffer */
            memmove(context->data, &context->data[len], context->len - len);
            context->len = context->len - len;

            /* append input data to buffer */
            memcpy(&context->data[context->len], in_data, in_data_len);
            context->len += in_data_len;
        } else {
            /* append input data to buffer */
            memcpy(&context->data[context->len], in_data, in_data_len);
            context->len += in_data_len;
        }
    }

done:
    return rc;
}

CK_RV openssl_specific_aes_gcm_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                     ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
                                     CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    AES_GCM_CONTEXT *context = NULL;
    CK_GCM_PARAMS *aes_gcm_param = NULL;
    EVP_CIPHER_CTX *gcm_ctx = NULL;
    CK_RV rc = CKR_OK;
    CK_ULONG tag_len;
    int outlen;

    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(encrypt);

    context = (AES_GCM_CONTEXT *)ctx->context;
    gcm_ctx = (EVP_CIPHER_CTX *)context->ulClen;
    aes_gcm_param = (CK_GCM_PARAMS *)ctx->mech.pParameter;

    if (gcm_ctx == NULL)
        return CKR_OPERATION_NOT_INITIALIZED;

    tag_len = (aes_gcm_param->ulTagBits + 7) / 8;

    if (encrypt) {
        /* encrypt */
        if (context->len == 0) {
            if (EVP_CipherFinal_ex(gcm_ctx, context->data, &outlen) != 1) {
                TRACE_ERROR("GCM finalize encryption failed\n");
                rc = CKR_GENERAL_ERROR;
                goto done;
            }
            if (outlen > 0)
                context->len = outlen;
            else
                context->len = (CK_ULONG)-1; /* no EVP_CipherFinal again */
        }

        outlen = (context->len == (CK_ULONG)-1 ? 0 : context->len);
        if (outlen + tag_len > *out_data_len) {
            TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
            /* Return here, do not cleanup the context */
            *out_data_len = outlen + tag_len;
            return CKR_BUFFER_TOO_SMALL;
        }

        memcpy(out_data, context->data, outlen);

        /* Append the tag to the output */
        if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_AEAD_GET_TAG, tag_len,
                                out_data + outlen) != 1) {
            TRACE_ERROR("GCM get tag failed\n");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        *out_data_len = outlen + tag_len;
    } else {
        if (context->len < tag_len) {
            TRACE_ERROR("GCM ciphertext does not contain tag data\n");
            rc = CKR_ENCRYPTED_DATA_INVALID;
            goto done;
        }

        if (*out_data_len < AES_BLOCK_SIZE) {
            TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
            /* Return here, do not cleanup the context */
            *out_data_len = AES_BLOCK_SIZE;
            return CKR_BUFFER_TOO_SMALL;
        }

        /* Set the expected tag */
        if (EVP_CIPHER_CTX_ctrl(gcm_ctx, EVP_CTRL_AEAD_SET_TAG, tag_len,
                                context->data) != 1) {
            TRACE_ERROR("GCM set tag failed\n");
            rc = CKR_GENERAL_ERROR;
            goto done;
        }

        /* Finalize the decryption */
        if(EVP_CipherFinal_ex(gcm_ctx, out_data, &outlen) != 1) {
            TRACE_ERROR("GCM finalize decryption failed\n");
            rc = CKR_ENCRYPTED_DATA_INVALID;
            goto done;
        }

        *out_data_len = outlen;
    }

done:
    EVP_CIPHER_CTX_free(gcm_ctx);
    context->ulClen = (CK_ULONG)NULL;

    return rc;
}

CK_RV openssl_specific_aes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                               CK_ULONG message_len, OBJECT *key, CK_BYTE *mac)
{
    CK_BYTE *out_buf;
    CK_ULONG out_len;
    CK_RV rc;

    out_buf = malloc(message_len);
    if (out_buf == NULL) {
        TRACE_ERROR("Malloc failed.\n");
        return CKR_HOST_MEMORY;
    }

    rc = openssl_specific_aes_cbc(tokdata, message, message_len, out_buf,
                                  &out_len, key, mac, 1);

    if (rc == CKR_OK && out_len >= AES_BLOCK_SIZE)
        memcpy(mac, out_buf + out_len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

    free(out_buf);

    return rc;
}

CK_RV openssl_specific_aes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                                CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                                CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{
    UNUSED(tokdata);

    return openssl_cmac_perform(CKM_AES_CMAC, message, message_len, key, mac,
                                first, last, ctx);
}

static EVP_CIPHER_CTX *aes_xts_init_ecb_cipher_ctx(const CK_BYTE *key,
                                                   CK_ULONG keylen,
                                                   CK_BBOOL encrypt)
{
    const EVP_CIPHER *cipher;
    EVP_CIPHER_CTX *ctx = NULL;

    if (key == NULL)
        return NULL;

    switch (keylen) {
    case AES_KEY_SIZE_128:
        cipher = EVP_aes_128_ecb();
        break;
    case AES_KEY_SIZE_256:
        cipher = EVP_aes_256_ecb();
        break;
    default:
        TRACE_ERROR("Key size wrong: %lu.\n", keylen);
        return NULL;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("EVP_CIPHER_CTX_new failed\n");
        return NULL;
    }

    if (EVP_CipherInit_ex(ctx, cipher, NULL, key, NULL,
                  encrypt ? 1 : 0) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        TRACE_ERROR("EVP_CipherInit_ex failed\n");
        return NULL;
    }

    return ctx;
}

static void aes_xts_xor_block(const CK_BYTE *in1, const CK_BYTE *in2,
                              CK_BYTE *out)
{
    CK_ULONG i;

    for (i = 0; i < AES_BLOCK_SIZE; i++)
        out[i] = in1[i] ^ in2[i];
}

static void aes_xts_mult(CK_BYTE *iv)
{
    CK_ULONG c, i;

    for (c = 0, i = 0; i < AES_BLOCK_SIZE; ++i) {
        c += ((CK_ULONG)iv[i]) << 1;
        iv[i] = (CK_BYTE)c;
        c = c >> 8;
    }

    iv[0] ^= (CK_BYTE)(0x87 & (0 - c));
}

struct aes_xts_cb_data {
    EVP_CIPHER_CTX *tweak_ctx;
    EVP_CIPHER_CTX *cipher_ctx;
};

static CK_RV aes_xts_iv_from_tweak(CK_BYTE *tweak, CK_BYTE* iv, void * cb_data)
{
    struct aes_xts_cb_data *data = cb_data;

    if (EVP_Cipher(data->tweak_ctx, iv, tweak, AES_BLOCK_SIZE) <= 0) {
        TRACE_ERROR("EVP_Cipher failed\n");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV aes_xts_cipher_blocks(CK_BYTE *in, CK_BYTE *out, CK_ULONG len,
                                   CK_BYTE *iv, void * cb_data)
{
    struct aes_xts_cb_data *data = cb_data;
    CK_BYTE buf[AES_INIT_VECTOR_SIZE];

    while (len >= AES_BLOCK_SIZE) {
        aes_xts_xor_block(in, iv, buf);

        if (EVP_Cipher(data->cipher_ctx, out, buf, AES_BLOCK_SIZE) <= 0) {
            TRACE_ERROR("EVP_Cipher failed\n");
            return CKR_FUNCTION_FAILED;
        }

        aes_xts_xor_block(out, iv, out);

        in += AES_BLOCK_SIZE;
        out += AES_BLOCK_SIZE;
        len -= AES_BLOCK_SIZE;

        aes_xts_mult(iv);
    }

    return CKR_OK;
}

CK_RV openssl_specific_aes_xts(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *out_data, CK_ULONG *out_data_len,
                               OBJECT *key_obj, CK_BYTE *tweak,
                               CK_BOOL encrypt, CK_BBOOL initial,
                               CK_BBOOL final, CK_BYTE* iv)
{
    struct aes_xts_cb_data data = { 0 };
    CK_ATTRIBUTE *key_attr;
    CK_RV rc;

    UNUSED(tokdata);

    if (initial && final)
        return openssl_cipher_perform(key_obj, CKM_AES_XTS,
                                      in_data, in_data_len,
                                      out_data, out_data_len,
                                      tweak, NULL, encrypt);

    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE,
                                          &key_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    if (initial) {
        data.tweak_ctx = aes_xts_init_ecb_cipher_ctx(
                        (CK_BYTE *)key_attr->pValue + key_attr->ulValueLen / 2,
                        key_attr->ulValueLen / 2, TRUE);
        if (data.tweak_ctx == NULL) {
            TRACE_ERROR("aes_xts_init_ecb_cipher_ctx failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
    }

    data.cipher_ctx = aes_xts_init_ecb_cipher_ctx((CK_BYTE *)key_attr->pValue,
                                                  key_attr->ulValueLen / 2,
                                                  encrypt);
    if (data.cipher_ctx == NULL) {
        TRACE_ERROR("aes_xts_init_ecb_cipher_ctx failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = aes_xts_cipher(in_data, in_data_len, out_data, out_data_len,
                        tweak, encrypt, initial, final, iv,
                        aes_xts_iv_from_tweak,
                        aes_xts_cipher_blocks,
                        &data);

out:
    if (data.tweak_ctx != NULL)
        EVP_CIPHER_CTX_free(data.tweak_ctx);
    if (data.cipher_ctx != NULL)
        EVP_CIPHER_CTX_free(data.cipher_ctx);

    return rc;
}

CK_RV openssl_specific_aes_key_wrap(STDLL_TokData_t *tokdata,
                                    CK_BYTE *in_data, CK_ULONG in_data_len,
                                    CK_BYTE *out_data, CK_ULONG *out_data_len,
                                    OBJECT *key_obj,
                                    CK_BYTE *iv, CK_ULONG iv_len,
                                    CK_BBOOL encrypt, CK_BBOOL pad)
{
    UNUSED(tokdata);

    if (iv != NULL &&
        iv_len != (pad ? AES_KEY_WRAP_KWP_IV_SIZE : AES_KEY_WRAP_IV_SIZE)) {
        TRACE_ERROR("IV len is invalid\n");
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return openssl_cipher_perform(key_obj, pad ? CKM_AES_KEY_WRAP_KWP :
                                                          CKM_AES_KEY_WRAP,
                                  in_data, in_data_len,
                                  out_data, out_data_len,
                                  iv, NULL, encrypt);
}

CK_RV openssl_specific_des_ecb(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               CK_ULONG *out_data_len,
                               OBJECT *key, CK_BYTE encrypt)
{
    UNUSED(tokdata);

    return openssl_cipher_perform(key, CKM_DES_ECB, in_data, in_data_len,
                                  out_data, out_data_len, NULL, NULL,
                                  encrypt);
}

CK_RV openssl_specific_des_cbc(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               CK_ULONG *out_data_len,
                               OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    UNUSED(tokdata);

    return openssl_cipher_perform(key, CKM_DES_CBC, in_data, in_data_len,
                                  out_data, out_data_len, init_v, NULL,
                                  encrypt);
}

CK_RV openssl_specific_tdes_ecb(STDLL_TokData_t *tokdata,
                                CK_BYTE *in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE *out_data,
                                CK_ULONG *out_data_len,
                                OBJECT *key, CK_BYTE encrypt)
{
    UNUSED(tokdata);

    return openssl_cipher_perform(key, CKM_DES3_ECB, in_data, in_data_len,
                                  out_data, out_data_len, NULL, NULL,
                                  encrypt);
}

CK_RV openssl_specific_tdes_cbc(STDLL_TokData_t *tokdata,
                                CK_BYTE *in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE *out_data,
                                CK_ULONG *out_data_len,
                                OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    UNUSED(tokdata);

    return openssl_cipher_perform(key, CKM_DES3_CBC, in_data, in_data_len,
                                  out_data, out_data_len, init_v, NULL,
                                  encrypt);
}

CK_RV openssl_specific_tdes_ofb(STDLL_TokData_t *tokdata,
                                CK_BYTE *in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE *out_data,
                                OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    CK_ULONG out_data_len;

    UNUSED(tokdata);

    return openssl_cipher_perform(key, CKM_DES_OFB64, in_data, in_data_len,
                                  out_data, &out_data_len, init_v, init_v,
                                  encrypt);

}

CK_RV openssl_specific_tdes_cfb(STDLL_TokData_t *tokdata,
                                CK_BYTE *in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE *out_data,
                                OBJECT *key,
                                CK_BYTE *init_v, CK_ULONG cfb_len,
                                CK_BYTE encrypt)
{
    CK_ULONG out_data_len;
    CK_MECHANISM_TYPE mech;

    UNUSED(tokdata);

    switch (cfb_len * 8) {
    case 8:
        mech = CKM_DES_CFB8;
        break;
    case 64:
        mech = CKM_DES_CFB64;
        break;
    default:
        TRACE_ERROR("CFB length %lu not supported\n", cfb_len);
        return CKR_MECHANISM_INVALID;
    }

    return openssl_cipher_perform(key, mech, in_data, in_data_len,
                                  out_data, &out_data_len, init_v, init_v,
                                  encrypt);
}

CK_RV openssl_specific_tdes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                                CK_ULONG message_len, OBJECT *key, CK_BYTE *mac)
{
    CK_BYTE *out_buf;
    CK_ULONG out_len;
    CK_RV rc;

    out_buf = malloc(message_len);
    if (out_buf == NULL) {
        TRACE_ERROR("Malloc failed.\n");
        return CKR_HOST_MEMORY;
    }

    rc = openssl_specific_tdes_cbc(tokdata, message, message_len, out_buf,
                                   &out_len, key, mac, 1);

    if (rc == CKR_OK && out_len >= DES_BLOCK_SIZE)
        memcpy(mac, out_buf + out_len - DES_BLOCK_SIZE, DES_BLOCK_SIZE);

    free(out_buf);

    return rc;
}

CK_RV openssl_specific_tdes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                                 CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                                 CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{
    UNUSED(tokdata);

    return openssl_cmac_perform(CKM_DES3_CMAC, message, message_len, key, mac,
                                first, last, ctx);
}

static void openssl_specific_hmac_free(STDLL_TokData_t *tokdata, SESSION *sess,
                                       CK_BYTE *context, CK_ULONG context_len)
{
    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(context_len);

    EVP_MD_CTX_destroy((EVP_MD_CTX *)context);
}

CK_RV openssl_specific_hmac_init(STDLL_TokData_t *tokdata,
                                 SIGN_VERIFY_CONTEXT *ctx,
                                 CK_MECHANISM_PTR mech,
                                 CK_OBJECT_HANDLE Hkey)
{
    int rc;
    OBJECT *key = NULL;
    CK_ATTRIBUTE *attr = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *pkey = NULL;

    rc = object_mgr_find_in_map1(tokdata, Hkey, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        goto done;
    }

    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, attr->pValue,
                                attr->ulValueLen);
    if (pkey == NULL) {
        TRACE_ERROR("EVP_PKEY_new_mac_key() failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    switch (mech->mechanism) {
    case CKM_MD5_HMAC_GENERAL:
    case CKM_MD5_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_md5(), NULL, pkey);
        break;
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA_1_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey);
        break;
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA224_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha224(), NULL, pkey);
        break;
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA256_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
        break;
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA384_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL, pkey);
        break;
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha512(), NULL, pkey);
        break;
#ifdef NID_sha512_224WithRSAEncryption
    case CKM_SHA512_224_HMAC_GENERAL:
    case CKM_SHA512_224_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha512_224(), NULL, pkey);
        break;
#endif
#ifdef NID_sha512_256WithRSAEncryption
    case CKM_SHA512_256_HMAC_GENERAL:
    case CKM_SHA512_256_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha512_256(), NULL, pkey);
        break;
#endif
#ifdef NID_sha3_224
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_224_HMAC_GENERAL:
    case CKM_IBM_SHA3_224_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha3_224(), NULL, pkey);
        break;
#endif
#ifdef NID_sha3_256
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_256_HMAC_GENERAL:
    case CKM_IBM_SHA3_256_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha3_256(), NULL, pkey);
        break;
#endif
#ifdef NID_sha3_384
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_384_HMAC_GENERAL:
    case CKM_IBM_SHA3_384_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha3_384(), NULL, pkey);
        break;
#endif
#ifdef NID_sha3_512
    case CKM_SHA3_512_HMAC:
    case CKM_SHA3_512_HMAC_GENERAL:
    case CKM_IBM_SHA3_512_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha3_512(), NULL, pkey);
        break;
#endif
    default:
        EVP_MD_CTX_destroy(mdctx);
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    if (rc != 1) {
        EVP_MD_CTX_destroy(mdctx);
        ctx->context = NULL;
        TRACE_ERROR("EVP_DigestSignInit failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    } else {
        ctx->context = (CK_BYTE *) mdctx;
        ctx->context_free_func = openssl_specific_hmac_free;
        ctx->state_unsaveable = TRUE;
    }

    rc = CKR_OK;
done:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);

    object_put(tokdata, key, TRUE);
    key = NULL;
    return rc;
}

CK_RV openssl_specific_hmac(SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                            CK_ULONG in_data_len, CK_BYTE *signature,
                            CK_ULONG *sig_len, CK_BBOOL sign)
{
    int rc;
    size_t mac_len, len;
    unsigned char mac[MAX_SHA_HASH_SIZE];
    EVP_MD_CTX *mdctx = NULL;
    CK_RV rv = CKR_OK;
    CK_BBOOL general = FALSE;
    CK_MECHANISM_TYPE digest_mech;
    CK_ULONG mac_len2;

    if (!ctx || !ctx->context) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (sign && !sig_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = get_hmac_digest(ctx->mech.mechanism, &digest_mech, &general);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_hmac_digest failed\n", __func__);
        return rc;
    }

    rc = get_sha_size(digest_mech, &mac_len2);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_sha_size failed\n", __func__);
        return rc;
    }
    mac_len = mac_len2;

    mdctx = (EVP_MD_CTX *) ctx->context;

    rc = EVP_DigestSignUpdate(mdctx, in_data, in_data_len);
    if (rc != 1) {
        TRACE_ERROR("EVP_DigestSignUpdate failed.\n");
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = EVP_DigestSignFinal(mdctx, mac, &mac_len);
    if (rc != 1) {
        TRACE_ERROR("EVP_DigestSignFinal failed.\n");
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (sign) {
        if (general)
            *sig_len = *(CK_ULONG *) ctx->mech.pParameter;
        else
            *sig_len = mac_len;

        memcpy(signature, mac, *sig_len);

    } else {
        if (general)
            len = *(CK_ULONG *) ctx->mech.pParameter;
        else
            len = mac_len;

        if (CRYPTO_memcmp(signature, mac, len) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rv = CKR_SIGNATURE_INVALID;
        }
    }
done:
    EVP_MD_CTX_destroy(mdctx);
    ctx->context = NULL;

    return rv;
}

CK_RV openssl_specific_hmac_update(SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                                   CK_ULONG in_data_len, CK_BBOOL sign)
{
    int rc;
    EVP_MD_CTX *mdctx = NULL;
    CK_RV rv = CKR_OK;

    UNUSED(sign);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    mdctx = (EVP_MD_CTX *) ctx->context;

    rc = EVP_DigestSignUpdate(mdctx, in_data, in_data_len);
    if (rc != 1) {
        TRACE_ERROR("EVP_DigestSignUpdate failed.\n");
        rv = CKR_FUNCTION_FAILED;
    } else {
        return CKR_OK;
    }

    EVP_MD_CTX_destroy(mdctx);
    ctx->context = NULL;
    return rv;
}

CK_RV openssl_specific_hmac_final(SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *signature,
                                  CK_ULONG *sig_len, CK_BBOOL sign)
{
    int rc;
    size_t mac_len, len;
    unsigned char mac[MAX_SHA_HASH_SIZE];
    EVP_MD_CTX *mdctx = NULL;
    CK_RV rv = CKR_OK;
    CK_BBOOL general = FALSE;
    CK_MECHANISM_TYPE digest_mech;
    CK_ULONG mac_len2;

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (sign && !sig_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = get_hmac_digest(ctx->mech.mechanism, &digest_mech, &general);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_hmac_digest failed\n", __func__);
        return rc;
    }

    rc = get_sha_size(digest_mech, &mac_len2);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_sha_size failed\n", __func__);
        return rc;
    }
    mac_len = mac_len2;

    if (signature == NULL) {
        if (sign) {
            if (general)
                *sig_len = *(CK_ULONG *) ctx->mech.pParameter;
            else
                *sig_len = (CK_ULONG) mac_len;
        }
        return CKR_OK;
    }

    mdctx = (EVP_MD_CTX *) ctx->context;

    rc = EVP_DigestSignFinal(mdctx, mac, &mac_len);
    if (rc != 1) {
        TRACE_ERROR("EVP_DigestSignFinal failed.\n");
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (sign) {
        if (general)
            *sig_len = *(CK_ULONG *) ctx->mech.pParameter;
        else
            *sig_len = mac_len;

        memcpy(signature, mac, *sig_len);

    } else {
        if (general)
            len = *(CK_ULONG *) ctx->mech.pParameter;
        else
            len = mac_len;

        if (CRYPTO_memcmp(signature, mac, len) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rv = CKR_SIGNATURE_INVALID;
        }
    }
done:
    EVP_MD_CTX_destroy(mdctx);
    ctx->context = NULL;
    return rv;
}

CK_RV calc_rsa_crt_from_me(CK_ATTRIBUTE *modulus, CK_ATTRIBUTE *pub_exp,
                           CK_ATTRIBUTE *priv_exp, CK_ATTRIBUTE **prime1,
                           CK_ATTRIBUTE **prime2, CK_ATTRIBUTE **exponent1,
                           CK_ATTRIBUTE **exponent2, CK_ATTRIBUTE **coef)
{
    BN_CTX *bn_ctx;
    BIGNUM *n, *e, *d, *k, *r, *t, *two, *g, *y, *n_minus_1, *j, *x;
    BIGNUM *p, *q, *dp, *dq, *invq;
    int i, prime_len;
    CK_BYTE *buff = NULL;
    CK_RV rc;

    bn_ctx = BN_CTX_secure_new();
    if (bn_ctx == NULL) {
        TRACE_ERROR("BN_CTX_secure_new failed\n");
        return CKR_FUNCTION_FAILED;
    }

    /* Get modulus as BIGNUM */
    n = BN_CTX_get(bn_ctx);
    if (n == NULL ||
        BN_bin2bn(modulus->pValue, modulus->ulValueLen, n) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed for modulus\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Get public exponent as BIGNUM */
    e = BN_CTX_get(bn_ctx);
    if (e == NULL ||
        BN_bin2bn(pub_exp->pValue, pub_exp->ulValueLen, e) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed for public exponent\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Get private exponent as BIGNUM */
    d = BN_CTX_get(bn_ctx);
    if (d == NULL ||
        BN_bin2bn(priv_exp->pValue, priv_exp->ulValueLen, d) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed for private exponent\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    n_minus_1 = BN_CTX_get(bn_ctx);
    two = BN_CTX_get(bn_ctx);
    k = BN_CTX_get(bn_ctx);
    r = BN_CTX_get(bn_ctx);
    t = BN_CTX_get(bn_ctx);
    g = BN_CTX_get(bn_ctx);
    y = BN_CTX_get(bn_ctx);
    j = BN_CTX_get(bn_ctx);
    x = BN_CTX_get(bn_ctx);
    p = BN_CTX_get(bn_ctx);
    q = BN_CTX_get(bn_ctx);
    dp = BN_CTX_get(bn_ctx);
    dq = BN_CTX_get(bn_ctx);
    invq = BN_CTX_get(bn_ctx);
    if (n_minus_1 == NULL || two == NULL || k == NULL || r == NULL ||
        t == NULL || g == NULL || y == NULL || j == NULL || x == NULL ||
        p == NULL || q == NULL || dp == NULL || dq == NULL || invq == NULL) {
        TRACE_ERROR("BN_CTX_get failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (BN_set_word(two, 2) != 1 ||
        BN_sub(n_minus_1, n, BN_value_one()) != 1) {
        TRACE_ERROR("BN_set_word/BN_sub failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /*
     * Prime-Factor Recovery from n, e and d described in NIST Special
     * Publication 800-56B R2 Recommendation for Pair-Wise Key Establishment
     * Schemes Using Integer Factorization Cryptography in Appendix C.
     */

    /* Step 1: Let k = d*e – 1. If k is odd, then go to Step 4. */
    if (BN_mul(k, d, e, bn_ctx) != 1 ||
        BN_sub_word(k, 1) != 1) {
        TRACE_ERROR("BN_mul/BN_sub_word failed for k\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (BN_is_odd(k))
        goto step4_fail;

    /*
     * Step 2: Write k as k = (2^t)*r, where r is the largest odd integer
     * dividing k, and t >= 1.
     */
    BN_zero(t);
    if (BN_copy(r, k) == NULL) {
        TRACE_ERROR("BN_set_word/BN_copy failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    do {
        if (BN_div(r, NULL, r, two, bn_ctx) != 1 ||
            BN_add_word(t, 1) != 1) {
            TRACE_ERROR("BN_div/BN_add_word failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    } while(!BN_is_odd(r));

    /* Step 3: For i = 1 to 100 do: */
    for (i = 1; i <= 100; i++) {
        /* Step 3a: Generate a random integer g in the range [0, n-1] */
#if OPENSSL_VERSION_PREREQ(3, 0)
        if (BN_rand_range_ex(g, n, 0, bn_ctx) != 1) {
#else
        if (BN_rand_range(g, n) != 1) {
#endif
            TRACE_ERROR("BN_rand_range[_ex] failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        /* Step 3b: Let y = g^r mod n */
        if (BN_mod_exp(y, g, r, n, bn_ctx) != 1) {
            TRACE_ERROR("BN_mod_exp failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        /* Step 3c: If y = 1 or y = n – 1, then step 3g */
        if (BN_cmp(y, BN_value_one()) == 0 || BN_cmp(y,  n_minus_1) == 0)
            goto step_3g;

        /* Step 3d:  For j = 1 to t – 1 do */
        for (BN_one(j); BN_cmp(j, t) < 0; BN_add_word(t, 1)) {
            /* Step 3d1: Let x = y^2 mod n */
            if (BN_mod_exp(x, y, two, n, bn_ctx) != 1) {
               TRACE_ERROR("BN_mod_exp failed\n");
               rc = CKR_FUNCTION_FAILED;
               goto done;
            }

            /* Step 3d2: If x = 1, go to Step 5 */
            if (BN_cmp(x, BN_value_one()) == 0)
                goto step5_success;

            /* Step 3d3: if x = n – 1, goto step 3g */
            if (BN_cmp(x, n_minus_1) == 0)
                goto step_3g;

            /* Step 3d4: Let y = x */
            if (BN_copy(y, x) == NULL) {
                TRACE_ERROR("BN_copy failed\n");
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
        }

        /* Step 3e: Let x = y^2 mod n. */
        if (BN_mod_exp(x, y, two, n, bn_ctx) != 1) {
           TRACE_ERROR("BN_mod_exp failed\n");
           rc = CKR_FUNCTION_FAILED;
           goto done;
        }

        /* Step 3f: If x = 1, go to Step 5 */
        if (BN_cmp(x, BN_value_one()) == 0)
            goto step5_success;

step_3g:
        /* Step 3g: continue */
        continue;
    }

step4_fail:
    /* Step 4: Output "prime factors not found" and exit */
    TRACE_ERROR("Prime factors not found\n");
    rc = CKR_FUNCTION_FAILED;
    goto done;

step5_success:
    /* Step 5:  Let p = GCD(y – 1, n) and let q = n/p */
    if (BN_sub_word(y, 1) != 1 ||
        BN_gcd(p, y, n, bn_ctx) != 1 ||
        BN_div(q, NULL, n, p, bn_ctx) != 1) {
        TRACE_ERROR("BN_sub_word/BN_gcd/BN_div failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Swap if p < q */
    if (BN_cmp(p, q) < 0) {
        x = q;
        q = p;
        p = x;
    }

    /* Calculate dp = d mod p−1, dq = d mod q-1, and qinv = q^−1 mod p */
    if (BN_copy(dp, p) == NULL ||
        BN_sub_word(dp, 1) != 1 ||
        BN_div(NULL, dp, d, dp, bn_ctx) != 1 ||
        BN_copy(dq, q) == NULL ||
        BN_sub_word(dq, 1) != 1 ||
        BN_div(NULL, dq, d, dq, bn_ctx) != 1 ||
        BN_mod_inverse(invq, q, p, bn_ctx) == NULL) {
        TRACE_ERROR("BN_copy/BN_sub_word/BN_div/BN_mod_inverse failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Add the CRT attributes to the key */
    prime_len = BN_num_bytes(p);
    buff = calloc(prime_len, 1);
    if (buff == NULL) {
        TRACE_DEVEL("calloc failed for buffer\n");
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (BN_bn2bin(p, buff) != prime_len) {
        TRACE_DEVEL("BN_bn2bin failed for p\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = build_attribute(CKA_PRIME_1, buff, prime_len, prime1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed for CKA_PRIME_1\n");
        goto done;
    }

    memset(buff, 0, prime_len);
    if (BN_bn2bin(q, buff) != prime_len) {
        TRACE_DEVEL("BN_bn2bin failed for q\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = build_attribute(CKA_PRIME_2, buff, prime_len, prime2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed for CKA_PRIME_2\n");
        goto done;
    }

    memset(buff, 0, prime_len);
    if (BN_bn2bin(dp, buff) != prime_len) {
        TRACE_DEVEL("BN_bn2bin failed for dp\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = build_attribute(CKA_EXPONENT_1, buff, prime_len, exponent1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed for CKA_EXPONENT_1\n");
        goto done;
    }

    memset(buff, 0, prime_len);
    if (BN_bn2bin(dq, buff) != prime_len) {
        TRACE_DEVEL("BN_bn2bin failed for dq\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = build_attribute(CKA_EXPONENT_2, buff, prime_len, exponent2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed for CKA_EXPONENT_2\n");
        goto done;
    }

    memset(buff, 0, prime_len);
    if (BN_bn2bin(invq, buff) != prime_len) {
        TRACE_DEVEL("BN_bn2bin failed for qinv\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = build_attribute(CKA_COEFFICIENT, buff, prime_len, coef);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed for CKA_COEFFICIENT\n");
        goto done;
    }

done:
    BN_CTX_free(bn_ctx);

    if (buff != NULL) {
        OPENSSL_cleanse(buff, prime_len);
        free(buff);
    }
    if (rc != CKR_OK) {
        if (*prime1 != NULL) {
            OPENSSL_cleanse((*prime1)->pValue, (*prime1)->ulValueLen);
            free(*prime1);
            *prime1 = NULL;
        }
        if (*prime2 != NULL) {
            OPENSSL_cleanse((*prime2)->pValue, (*prime2)->ulValueLen);
            free(*prime2);
            *prime2 = NULL;
        }
        if (*exponent1 != NULL) {
            OPENSSL_cleanse((*exponent1)->pValue, (*exponent1)->ulValueLen);
            free(*exponent1);
            *exponent1 = NULL;
        }
        if (*exponent2 != NULL) {
            OPENSSL_cleanse((*exponent2)->pValue, (*exponent2)->ulValueLen);
            free(*exponent2);
            *exponent2 = NULL;
        }
        if (*coef != NULL) {
            OPENSSL_cleanse((*coef)->pValue, (*coef)->ulValueLen);
            free(*coef);
            *coef = NULL;
        }
    }

    return rc;
}

static CK_RV calc_rsa_priv_exp(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                               CK_BYTE *priv_exp, CK_ULONG priv_exp_len)
{
    CK_ATTRIBUTE *modulus = NULL, *pub_exp = NULL;
    CK_ATTRIBUTE *prime1 = NULL, *prime2 = NULL;
    BN_CTX *bn_ctx;
    BIGNUM *n, *e, *p, *q, *d;
    CK_RV rc;

    UNUSED(tokdata);

    bn_ctx = BN_CTX_secure_new();
    if (bn_ctx == NULL) {
        TRACE_ERROR("BN_CTX_secure_new failed\n");
        return CKR_FUNCTION_FAILED;
    }

    /* Get modulus a BIGNUM */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &modulus);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get CKA_MODULUS\n");
        goto done;
    }

    n = BN_CTX_get(bn_ctx);
    if (n == NULL ||
        BN_bin2bn(modulus->pValue, modulus->ulValueLen, n) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed for modulus\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    BN_set_flags(n, BN_FLG_CONSTTIME);

    /* Get public exponent a BIGNUM */
    rc = template_attribute_get_non_empty(key_obj->template,
                                          CKA_PUBLIC_EXPONENT, &pub_exp);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get CKA_PUBLIC_EXPONENT\n");
        goto done;
    }

    e = BN_CTX_get(bn_ctx);
    if (e == NULL ||
        BN_bin2bn(pub_exp->pValue, pub_exp->ulValueLen, e) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed for public exponent\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    BN_set_flags(e, BN_FLG_CONSTTIME);

    /* Get prime1 a BIGNUM */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_PRIME_1,
                                          &prime1);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get CKA_PRIME_1\n");
        goto done;
    }

    p = BN_CTX_get(bn_ctx);
    if (p == NULL ||
        BN_bin2bn(prime1->pValue, prime1->ulValueLen, p) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed for prime1\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    BN_set_flags(p, BN_FLG_CONSTTIME);

    /* Get prime2 a BIGNUM */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_PRIME_2,
                                          &prime2);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get CKA_PRIME_2\n");
        goto done;
    }

    q = BN_CTX_get(bn_ctx);
    if (q == NULL ||
        BN_bin2bn(prime2->pValue, prime2->ulValueLen, q) == NULL) {
        TRACE_ERROR("BN_CTX_get/BN_bin2bn failed for prime2\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    BN_set_flags(q, BN_FLG_CONSTTIME);

    d = BN_CTX_get(bn_ctx);
    if (d == NULL) {
        TRACE_ERROR("BN_CTX_get failed to get d\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    BN_set_flags(d, BN_FLG_CONSTTIME);

    /*
     * phi(n) = (p - 1 )(q - 1) = n - p - q + 1
     * d = e ^{-1} mod phi(n).
     */
    if (BN_copy(d, n) == NULL ||
        BN_sub(d, d, p) == 0 ||
        BN_sub(d, d, q) == 0 ||
        BN_add_word(d, 1) == 0 ||
        BN_mod_inverse(d, e, d, bn_ctx) == NULL) {
        TRACE_ERROR("Failed to calculate private key part d\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (BN_bn2binpad(d, priv_exp, priv_exp_len) <= 0) {
        TRACE_ERROR("BN_bn2binpad failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

done:
    BN_CTX_free(bn_ctx);

    return rc;
}

CK_RV openssl_specific_rsa_derive_kdk(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                                      const CK_BYTE *in, CK_ULONG inlen,
                                      CK_BYTE *kdk, CK_ULONG kdklen)
{
    CK_ATTRIBUTE *priv_exp_attr = NULL, *modulus = NULL;
    CK_BYTE *priv_exp = NULL, *buf = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    const EVP_MD *md = NULL;
    size_t md_len;
    unsigned char d_hash[SHA256_HASH_SIZE] = { 0 };
    CK_RV rc;

    /*
     * The implementation of this function is copied from OpenSSL's function
     * derive_kdk() in crypto/rsa/rsa_ossl.c and is slightly modified to fit to
     * the OpenCryptoki environment.
     * Changes include:
     * - Different variable and define names.
     * - Usage of TRACE_ERROR to report errors and issue debug messages.
     * - Different return codes.
     * - Different code to get the private key component 'd'.
     * - Use of the EVP APIs instead of the internal APIs for Digest and HMAC
     *   operations.
     */

    if (kdklen != SHA256_HASH_SIZE) {
        TRACE_ERROR("KDK length is wrong\n");
        return CKR_ARGUMENTS_BAD;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &modulus);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get CKA_MODULUS\n");
        return rc;
    }

    buf = calloc(1, modulus->ulValueLen);
    if (buf == NULL) {
        TRACE_ERROR("Failed to allocate a buffer for private exponent\n");
        return CKR_HOST_MEMORY;
    }

    rc = template_attribute_get_non_empty(key_obj->template,
                                          CKA_PRIVATE_EXPONENT, &priv_exp_attr);
    if (rc != CKR_OK && rc != CKR_TEMPLATE_INCOMPLETE &&
        rc != CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("Failed to get CKA_PRIVATE_EXPONENT\n");
        goto out;
    }

    if (priv_exp_attr == NULL) {
        rc = calc_rsa_priv_exp(tokdata, key_obj, buf, modulus->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_ERROR("calc_rsa_priv_exp failed\n");
            goto out;
        }
        priv_exp = buf;
    } else {
        if (priv_exp_attr->ulValueLen < modulus->ulValueLen) {
            memcpy(buf + modulus->ulValueLen - priv_exp_attr->ulValueLen,
                   priv_exp_attr->pValue, priv_exp_attr->ulValueLen);
            priv_exp = buf;
        } else {
            priv_exp = (CK_BYTE *)priv_exp_attr->pValue +
                            priv_exp_attr->ulValueLen - modulus->ulValueLen;
        }
    }

    /*
     * we use hardcoded hash so that migrating between versions that use
     * different hash doesn't provide a Bleichenbacher oracle:
     * if the attacker can see that different versions return different
     * messages for the same ciphertext, they'll know that the message is
     * synthetically generated, which means that the padding check failed
     */
    md = EVP_sha256();
    if (md == NULL) {
        TRACE_ERROR("EVP_sha256 failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_Digest(priv_exp, modulus->ulValueLen, d_hash, NULL,
                   md, NULL) <= 0) {
        TRACE_ERROR("EVP_Digest failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, d_hash, sizeof(d_hash));
    if (pkey == NULL) {
        TRACE_ERROR("EVP_PKEY_new_mac_key() failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL) {
        TRACE_ERROR("EVP_MD_CTX_create() failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_DigestSignInit(mdctx, NULL, md, NULL, pkey) != 1) {
        TRACE_ERROR("EVP_DigestSignInit failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (inlen < modulus->ulValueLen) {
        memset(buf, 0, modulus->ulValueLen - inlen);
        if (EVP_DigestSignUpdate(mdctx, buf, modulus->ulValueLen - inlen)!= 1) {
            TRACE_ERROR("EVP_DigestSignUpdate failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
    }
    if (EVP_DigestSignUpdate(mdctx, in, inlen) != 1) {
        TRACE_ERROR("EVP_DigestSignUpdate failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    md_len = kdklen;
    if (EVP_DigestSignFinal(mdctx, kdk, &md_len) != 1 ||
        md_len != kdklen) {
        TRACE_ERROR("EVP_DigestSignFinal failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = CKR_OK;

out:
    if (buf != NULL)
        free(buf);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (mdctx != NULL)
        EVP_MD_CTX_free(mdctx);

    return rc;
}

CK_RV openssl_specific_rsa_prf(CK_BYTE *out, CK_ULONG outlen,
                               const char *label, CK_ULONG labellen,
                               const CK_BYTE *kdk, CK_ULONG kdklen,
                               uint16_t bitlen)
{
    CK_RV rc;
    CK_ULONG pos;
    uint16_t iter = 0;
    unsigned char be_iter[sizeof(iter)];
    unsigned char be_bitlen[sizeof(bitlen)];
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *mdctx = NULL;
    unsigned char hmac_out[SHA256_HASH_SIZE];
    size_t md_len;

    /*
     * The implementation of this function is copied from OpenSSL's function
     * ossl_rsa_prf() in crypto/rsa/rsapk1.c and is slightly modified to fit to
     * the providers environment.
     * Changes include:
     * - Different variable and define names.
     * - Usage of TRACE_ERROR report errors and issue debug messages.
     * - Different return codes.
     * - Use of the EVP API instead of the internal APIs for HMAC operations.
     */

    if (kdklen != SHA256_HASH_SIZE) {
        TRACE_ERROR("invalid kdklen\n");
        return CKR_ARGUMENTS_BAD;
    }
    if (outlen * 8 != bitlen) {
        TRACE_ERROR("invalid outlen\n");
        return CKR_ARGUMENTS_BAD;
    }

    be_bitlen[0] = (bitlen >> 8) & 0xff;
    be_bitlen[1] = bitlen & 0xff;

    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, kdk, kdklen);
    if (pkey == NULL) {
        TRACE_ERROR("EVP_PKEY_new_mac_key() failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL) {
        TRACE_ERROR("EVP_MD_CTX_create() failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    /*
     * we use hardcoded hash so that migrating between versions that use
     * different hash doesn't provide a Bleichenbacher oracle:
     * if the attacker can see that different versions return different
     * messages for the same ciphertext, they'll know that the message is
     * synthetically generated, which means that the padding check failed
     */
    for (pos = 0; pos < outlen; pos += SHA256_HASH_SIZE, iter++) {
        if (EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey) != 1) {
            TRACE_ERROR("EVP_DigestSignInit failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        be_iter[0] = (iter >> 8) & 0xff;
        be_iter[1] = iter & 0xff;

        if (EVP_DigestSignUpdate(mdctx, be_iter, sizeof(be_iter)) != 1) {
            TRACE_ERROR("EVP_DigestSignUpdate failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
        if (EVP_DigestSignUpdate(mdctx, (unsigned char *)label, labellen) != 1) {
            TRACE_ERROR("EVP_DigestSignUpdate failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
        if (EVP_DigestSignUpdate(mdctx, be_bitlen, sizeof(be_bitlen)) != 1) {
            TRACE_ERROR("EVP_DigestSignUpdate failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        /*
         * HMAC_Final requires the output buffer to fit the whole MAC
         * value, so we need to use the intermediate buffer for the last
         * unaligned block
         */
        md_len = SHA256_HASH_SIZE;
        if (pos + SHA256_HASH_SIZE > outlen) {
            md_len = sizeof(hmac_out);
            if (EVP_DigestSignFinal(mdctx, hmac_out, &md_len) != 1) {
                TRACE_ERROR("EVP_DigestSignFinal failed\n");
                rc = CKR_FUNCTION_FAILED;
                goto out;
            }
            memcpy(out + pos, hmac_out, outlen - pos);
        } else {
            md_len = outlen - pos;
            if (EVP_DigestSignFinal(mdctx, out + pos, &md_len) != 1) {
                TRACE_ERROR("EVP_DigestSignFinal failed\n");
                rc = CKR_FUNCTION_FAILED;
                goto out;
            }
        }
    }

    rc = CKR_OK;

out:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (mdctx != NULL)
        EVP_MD_CTX_free(mdctx);

    return rc;
}

#if OPENSSL_VERSION_PREREQ(3, 0)

const char *openssl_get_pqc_oid_name(const struct pqc_oid *oid)
{
    const CK_BYTE *poid = oid->oid;
    ASN1_OBJECT *obj = NULL;
    const char *alg_name;
    EVP_PKEY_CTX *ctx = NULL;
    int nid;

    if (d2i_ASN1_OBJECT(&obj, &poid, oid->oid_len) == NULL)
        return NULL;

    nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);

    if (nid == NID_undef)
        return NULL;

    alg_name = OBJ_nid2ln(nid);
    if (alg_name == NULL)
        return NULL;

    /* Try to fetch that algorithm to check if it is really supported */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (ctx == NULL)
        alg_name = NULL;
    EVP_PKEY_CTX_free(ctx);

    return alg_name;
}

static CK_RV get_key_from_pkey(EVP_PKEY *pkey, const char *param,
                               CK_BYTE **key, size_t *key_len)
{
    if (EVP_PKEY_get_octet_string_param(pkey, param, NULL, 0, key_len) != 1 ||
        *key_len == OSSL_PARAM_UNMODIFIED) {
        TRACE_ERROR("EVP_PKEY_get_octet_string_param failed for '%s'\n", param);
        return CKR_FUNCTION_FAILED;
    }

    *key = calloc(1, *key_len);
    if (*key == NULL) {
        TRACE_ERROR("Failed to allocate buffer for '%s'\n", param);
        return CKR_HOST_MEMORY;
    }

    if (EVP_PKEY_get_octet_string_param(pkey, param,
                                        *key, *key_len, key_len) != 1) {
        TRACE_ERROR("EVP_PKEY_get_octet_string_param failed for '%s'\n", param);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV openssl_specific_ibm_dilithium_generate_keypair(STDLL_TokData_t *tokdata,
                                                      const struct pqc_oid *oid,
                                                      TEMPLATE *publ_tmpl,
                                                      TEMPLATE *priv_tmpl)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *pkey = NULL;
    const char *alg_name;
    CK_BYTE *spki = NULL, *pkcs8 = NULL;
    CK_ULONG spki_len = 0, pkcs8_len = 0;
    size_t priv_len = 0, pub_len = 0;
    CK_BYTE *priv_key = NULL, *pub_key = NULL;
    CK_RV rc = CKR_OK;

    UNUSED(tokdata);

    alg_name = openssl_get_pqc_oid_name(oid);
    if (alg_name == NULL) {
        TRACE_ERROR("Dilithium key form '%lu' not supported by oqsprovider\n",
                    oid->keyform);
        rc = CKR_KEY_SIZE_RANGE;
        goto out;
    }

    /* Generate key via oqsprovider */
    ctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new_from_name failed for '%s'\n", alg_name);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1) {
        TRACE_ERROR("EVP_PKEY_keygen_init failed for '%s'\n", alg_name);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_generate(ctx, &pkey) != 1) {
        TRACE_ERROR("EVP_PKEY_generate failed for '%s'\n", alg_name);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    /* Get private and public key */
    rc = get_key_from_pkey(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                           &priv_key, &priv_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("get_key_from_pkey failed for priv key\n");
        goto out;
    }

    rc = get_key_from_pkey(pkey, OSSL_PKEY_PARAM_PUB_KEY,
                           &pub_key, &pub_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("get_key_from_pkey failed for pub key\n");
        goto out;
    }

    /* Extract key components */
    rc = ibm_dilithium_unpack_priv_key(priv_key, priv_len, oid, priv_tmpl);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_unpack_priv_key failed for priv key\n");
        goto out;
    }

    rc = ibm_dilithium_unpack_pub_key(pub_key, pub_len, oid, publ_tmpl);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_unpack_pub_key failed for pub key\n");
        goto out;
    }

    /* Also add public key components to private template */
    rc = ibm_dilithium_unpack_pub_key(pub_key, pub_len, oid, priv_tmpl);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_unpack_pub_key failed for pub key\n");
        goto out;
    }

    /* Add keyform and mode attributes to public and private template */
    rc = ibm_pqc_add_keyform_mode(publ_tmpl, oid, CKM_IBM_DILITHIUM);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
        goto out;
    }

    rc = ibm_pqc_add_keyform_mode(priv_tmpl, oid, CKM_IBM_DILITHIUM);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
        goto out;
    }

    /* Add SPKI as CKA_VALUE to public template */
    rc = ibm_dilithium_publ_get_spki(publ_tmpl, FALSE, &spki, &spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_publ_get_spki failed\n");
        goto out;
    }

    rc = template_build_update_attribute(publ_tmpl, CKA_VALUE, spki, spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_build_update_attribute for CKA_VALUE failed "
                    "rc=0x%lx\n", rc);
        goto out;
    }

    /* Add PKCS#8 encoding of private key to private template */
    rc = ibm_dilithium_priv_wrap_get_data(priv_tmpl, FALSE, &pkcs8, &pkcs8_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_priv_wrap_get_data failed\n");
        goto out;
    }

    rc = template_build_update_attribute(priv_tmpl, CKA_VALUE, pkcs8, pkcs8_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_build_update_attribute for CKA_VALUE failed "
                    "rc=0x%lx\n", rc);
        goto out;
    }

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (priv_key != NULL) {
        OPENSSL_cleanse(priv_key, priv_len);
        free(priv_key);
    }
    if (pub_key != NULL)
        free(pub_key);
    if (spki != NULL)
        free(spki);
    if (pkcs8 != NULL) {
        OPENSSL_cleanse(pkcs8, pkcs8_len);
        free(pkcs8);
    }

    return rc;
}

CK_RV openssl_make_ibm_dilithium_key_from_template(TEMPLATE *tmpl,
                                                   const struct pqc_oid *oid,
                                                   CK_BBOOL private_key,
                                                   const char *alg_name,
                                                   EVP_PKEY **pkey)
{
    CK_ULONG priv_len = 0, pub_len = 0;
    CK_BYTE *priv_key = NULL, *pub_key = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    CK_RV rc;

    if (private_key) {
        rc = ibm_dilithium_pack_priv_key(tmpl, oid, NULL, &priv_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("ibm_dilithium_pack_priv_key failed\n");
            goto out;
        }

        priv_key = calloc(1, priv_len);
        if (priv_key == NULL) {
            TRACE_ERROR("Failed to allocate private key buffer\n");
            rc = CKR_HOST_MEMORY;
            goto out;
        }

        rc = ibm_dilithium_pack_priv_key(tmpl, oid, priv_key, &priv_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("ibm_dilithium_pack_priv_key failed\n");
            goto out;
        }
    }

    rc = ibm_dilithium_pack_pub_key(tmpl, oid, NULL, &pub_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_pack_pub_key failed\n");
        goto out;
    }

    pub_key = calloc(1, pub_len);
    if (pub_key == NULL) {
        TRACE_ERROR("Failed to allocate public key buffer\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    rc = ibm_dilithium_pack_pub_key(tmpl, oid, pub_key, &pub_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_dilithium_pack_pub_key failed\n");
        goto out;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        TRACE_ERROR("OSSL_PARAM_BLD_new failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (private_key) {
        if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             priv_key, priv_len) != 1) {
            TRACE_ERROR("OSSL_PARAM_BLD_push_octet_string failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
    }

    if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         pub_key, pub_len) != 1) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_octet_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        TRACE_ERROR("OSSL_PARAM_BLD_to_param failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (pctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new_from_name failed for '%s'\n", alg_name);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_fromdata_init(pctx) != 1) {
        TRACE_ERROR("EVP_PKEY_fromdata_init failed for '%s'\n", alg_name);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_fromdata(pctx, pkey, private_key ? EVP_PKEY_KEYPAIR :
                                                    EVP_PKEY_PUBLIC_KEY,
                          params) != 1) {
        TRACE_ERROR("EVP_PKEY_fromdata failed for '%s'\n", alg_name);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

out:
    if (priv_key != NULL) {
        OPENSSL_cleanse(priv_key, priv_len);
        free(priv_key);
    }
    if (pub_key != NULL)
        free(pub_key);
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (bld != NULL)
        OSSL_PARAM_BLD_free(bld);
    if (params != NULL)
        OSSL_PARAM_free(params);

    return rc;
}

CK_RV openssl_specific_ibm_dilithium_sign(STDLL_TokData_t *tokdata,
                                          SESSION *sess,
                                          CK_BBOOL length_only,
                                          const struct pqc_oid *oid,
                                          CK_BYTE *in_data,
                                          CK_ULONG in_data_len,
                                          CK_BYTE *signature,
                                          CK_ULONG *signature_len,
                                          OBJECT *key_obj)
{
    struct openssl_ex_data *ex_data = NULL;
    EVP_PKEY *pkey = NULL;
    CK_RV rc = CKR_OK;
    EVP_PKEY_CTX *ctx = NULL;
    const char *alg_name;
    size_t siglen;

    UNUSED(tokdata);
    UNUSED(sess);

    alg_name = openssl_get_pqc_oid_name(oid);
    if (alg_name == NULL) {
        TRACE_ERROR("Dilithium key form is not supported by oqsprovider\n");
        return CKR_KEY_SIZE_RANGE;
    }

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(struct openssl_ex_data),
                             openssl_need_wr_lock, NULL);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->pkey == NULL) {
        rc = openssl_make_ibm_dilithium_key_from_template(key_obj->template,
                                                          oid, TRUE, alg_name,
                                                          &ex_data->pkey);
        if (rc != CKR_OK)
            goto out;
    }

    pkey = ex_data->pkey;
    if (EVP_PKEY_up_ref(pkey) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        TRACE_ERROR("EVP_PKEY_sign_init failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (length_only) {
        if (EVP_PKEY_sign(ctx, NULL, &siglen, in_data, in_data_len) <= 0) {
            TRACE_ERROR("EVP_PKEY_sign failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        *signature_len = siglen;
        goto out;
    }

    siglen = *signature_len;
    if (EVP_PKEY_sign(ctx, signature, &siglen, in_data, in_data_len) <= 0) {
        TRACE_ERROR("EVP_PKEY_sign failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    *signature_len = siglen;

out:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    object_ex_data_unlock(key_obj);

    return rc;
}

CK_RV openssl_specific_ibm_dilithium_verify(STDLL_TokData_t *tokdata,
                                            SESSION *sess,
                                            const struct pqc_oid *oid,
                                            CK_BYTE *in_data,
                                            CK_ULONG in_data_len,
                                            CK_BYTE *signature,
                                            CK_ULONG signature_len,
                                            OBJECT *key_obj)
{
    struct openssl_ex_data *ex_data = NULL;
    EVP_PKEY *pkey = NULL;
    CK_RV rc = CKR_OK;
    EVP_PKEY_CTX *ctx = NULL;
    const char *alg_name;
    size_t siglen;

    UNUSED(tokdata);
    UNUSED(sess);

    alg_name = openssl_get_pqc_oid_name(oid);
    if (alg_name == NULL) {
        TRACE_ERROR("Dilithium key form is not supported by oqsprovider\n");
        return CKR_KEY_SIZE_RANGE;
    }

    rc = openssl_get_ex_data(key_obj, (void **)&ex_data,
                             sizeof(struct openssl_ex_data),
                             openssl_need_wr_lock, NULL);
    if (rc != CKR_OK)
        return rc;

    if (ex_data->pkey == NULL) {
        rc = openssl_make_ibm_dilithium_key_from_template(key_obj->template,
                                                          oid, FALSE, alg_name,
                                                          &ex_data->pkey);
        if (rc != CKR_OK)
            goto out;
    }

    pkey = ex_data->pkey;
    if (EVP_PKEY_up_ref(pkey) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        TRACE_ERROR("EVP_PKEY_verify_init failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    siglen = signature_len;
    rc = EVP_PKEY_verify(ctx, signature, siglen, in_data, in_data_len);
    switch (rc) {
    case 0:
        rc = CKR_SIGNATURE_INVALID;
        break;
    case 1:
        rc = CKR_OK;
        break;
    default:
        TRACE_ERROR("EVP_PKEY_verify failed\n");
        rc = CKR_FUNCTION_FAILED;
        break;
    }

out:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    object_ex_data_unlock(key_obj);

    return rc;
}

#endif
