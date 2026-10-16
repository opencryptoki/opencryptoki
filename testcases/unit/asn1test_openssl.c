/*
 * COPYRIGHT (c) International Business Machines Corp. 2026
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * Unit tests that generate key pairs with OpenSSL:
 * 1) Encode private keys into PKCS#8 format using OpenSSL's EVP_PKEY2PKCS8 and
 *    i2d_PKCS8_PRIV_KEY_INFO_bio, decode them with opencryptoki's asn1 functions,
 *    re-encode them with opencryptoki's asn1 functions, and verify round-trip
 *    equivalence.
 * 2) Encode public keys into SPKI (SubjectPublicKeyInfo) format using OpenSSL's
 *    i2d_PUBKEY_bio, decode them with opencryptoki's asn1 functions, re-encode
 *    them with opencryptoki's asn1 functions, and verify round-trip equivalence.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/opensslv.h>
#include <openssl/evp.h>
#include <openssl/x509.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <openssl/obj_mac.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#include <openssl/encoder.h>
#endif

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "pqc_defs.h"
#include "h_extern.h"
#include "unittest.h"
#include "asn1test_openssl.h"

#ifndef NID_ffdhe2048
#define NID_ffdhe2048       1126
#endif

/* Helper function to compare byte arrays */
static int compare_bytes(const char *test_name, const CK_BYTE *expected,
                         const CK_BYTE *actual, CK_ULONG len)
{
    if (memcmp(expected, actual, len) != 0) {
        fprintf(stderr, "[FAIL] %s: Data mismatch (length %lu)\n",
                test_name, len);
        fprintf(stderr, "  Expected: ");
        for (CK_ULONG i = 0; i < (len > 32 ? 32 : len); i++)
            fprintf(stderr, "%02X ", expected[i]);
        if (len > 32)
            fprintf(stderr, "...");
        fprintf(stderr, "\n  Actual:   ");
        for (CK_ULONG i = 0; i < (len > 32 ? 32 : len); i++)
            fprintf(stderr, "%02X ", actual[i]);
        if (len > 32)
            fprintf(stderr, "...");
        fprintf(stderr, "\n");
        return 1;
    }
    return 0;
}

/* Helper to encode OpenSSL EVP_PKEY into PKCS#8 DER using EVP_PKEY2PKCS8 and i2d_PKCS8_PRIV_KEY_INFO_bio */
static CK_RV openssl_to_pkcs8_der(EVP_PKEY *pkey, CK_BYTE **der_out,
                                  CK_ULONG *der_len_out)
{
    PKCS8_PRIV_KEY_INFO *p8inf = NULL;
    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;
    CK_BYTE *buf = NULL;

    p8inf = EVP_PKEY2PKCS8(pkey);
    if (p8inf == NULL) {
        fprintf(stderr, "EVP_PKEY2PKCS8 failed\n");
        return CKR_FUNCTION_FAILED;
    }

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL) {
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        return CKR_HOST_MEMORY;
    }

    if (i2d_PKCS8_PRIV_KEY_INFO_bio(bio, p8inf) <= 0) {
        fprintf(stderr, "i2d_PKCS8_PRIV_KEY_INFO_bio failed\n");
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        BIO_free(bio);
        return CKR_FUNCTION_FAILED;
    }

    BIO_get_mem_ptr(bio, &bptr);
    if (bptr == NULL || bptr->length == 0) {
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        BIO_free(bio);
        return CKR_FUNCTION_FAILED;
    }

    buf = (CK_BYTE *)malloc(bptr->length);
    if (buf == NULL) {
        PKCS8_PRIV_KEY_INFO_free(p8inf);
        BIO_free(bio);
        return CKR_HOST_MEMORY;
    }

    memcpy(buf, bptr->data, bptr->length);
    *der_out = buf;
    *der_len_out = (CK_ULONG)bptr->length;

    PKCS8_PRIV_KEY_INFO_free(p8inf);
    BIO_free(bio);

    return CKR_OK;
}

/* Helper to encode OpenSSL EVP_PKEY into SPKI DER using i2d_PUBKEY_bio */
static CK_RV openssl_to_spki_der(EVP_PKEY *pkey, CK_BYTE **der_out,
                                 CK_ULONG *der_len_out)
{
    BIO *bio = NULL;
    BUF_MEM *bptr = NULL;
    CK_BYTE *buf = NULL;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
        return CKR_HOST_MEMORY;

    if (i2d_PUBKEY_bio(bio, pkey) <= 0) {
        fprintf(stderr, "i2d_PUBKEY_bio failed\n");
        BIO_free(bio);
        return CKR_FUNCTION_FAILED;
    }

    BIO_get_mem_ptr(bio, &bptr);
    if (bptr == NULL || bptr->length == 0) {
        BIO_free(bio);
        return CKR_FUNCTION_FAILED;
    }

    buf = (CK_BYTE *)malloc(bptr->length);
    if (buf == NULL) {
        BIO_free(bio);
        return CKR_HOST_MEMORY;
    }

    memcpy(buf, bptr->data, bptr->length);
    *der_out = buf;
    *der_len_out = (CK_ULONG)bptr->length;

    BIO_free(bio);
    return CKR_OK;
}

/* Helper to generate an OpenSSL RSA key */
static EVP_PKEY *create_openssl_rsa_key(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);

    if (ctx == NULL)
        return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* Helper to generate an OpenSSL DSA key */
static EVP_PKEY *create_openssl_dsa_key(void)
{
    EVP_PKEY *params = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    EVP_PKEY_CTX *kctx = NULL;

    if (pctx == NULL)
        return NULL;

    if (EVP_PKEY_paramgen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_dsa_paramgen_bits(pctx, 1024) <= 0 ||
        EVP_PKEY_paramgen(pctx, &params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);

    kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_free(params);
    if (kctx == NULL)
        return NULL;

    if (EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

/* Helper to generate an OpenSSL DH key */
static EVP_PKEY *create_openssl_dh_key(void)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);

    if (pctx == NULL)
        return NULL;

    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_dh_nid(pctx, NID_ffdhe2048) <= 0 ||
        EVP_PKEY_keygen(pctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(pctx);
    return pkey;
}

/* Helper to generate an OpenSSL EC key for a given curve NID */
static EVP_PKEY *create_openssl_ec_key(int nid)
{
    EVP_PKEY *params = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    EVP_PKEY_CTX *kctx = NULL;

    if (pctx == NULL)
        return NULL;

    if (EVP_PKEY_paramgen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, nid) <= 0 ||
        EVP_PKEY_paramgen(pctx, &params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return NULL;
    }
    EVP_PKEY_CTX_free(pctx);

    kctx = EVP_PKEY_CTX_new(params, NULL);
    EVP_PKEY_free(params);
    if (kctx == NULL)
        return NULL;

    if (EVP_PKEY_keygen_init(kctx) <= 0 ||
        EVP_PKEY_keygen(kctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(kctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(kctx);
    return pkey;
}

/* Helper to generate an OpenSSL key by NID or algorithm name */
static EVP_PKEY *create_openssl_named_key(int type_id, const char *type_name)
{
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    if (type_name != NULL)
        ctx = EVP_PKEY_CTX_new_from_name(NULL, type_name, NULL);
#endif
    if (ctx == NULL && type_id > 0)
        ctx = EVP_PKEY_CTX_new_id(type_id, NULL);

    if (ctx == NULL)
        return NULL;

    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return NULL;
    }

    EVP_PKEY_CTX_free(ctx);
    return pkey;
}

/* ========================================================================
 * OpenSSL PKCS#8 Private Key Tests
 * ======================================================================== */

/* Test RSA Private Key: OpenSSL EVP_PKEY2PKCS8 -> ber_decode_RSAPrivateKey -> ber_encode_RSAPrivateKey */
int test_openssl_pkcs8_rsa(void)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *p8_der = NULL;
    CK_ULONG p8_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *modulus = NULL, *pub_exp = NULL, *priv_exp = NULL;
    CK_ATTRIBUTE *prime1 = NULL, *prime2 = NULL, *exponent1 = NULL;
    CK_ATTRIBUTE *exponent2 = NULL, *coefficient = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_rsa_key();
    if (pkey == NULL) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_rsa: failed to generate OpenSSL RSA key\n");
        return 1;
    }

    rv = openssl_to_pkcs8_der(pkey, &p8_der, &p8_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || p8_der == NULL || p8_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_rsa: failed to encode PKCS#8 via OpenSSL\n");
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = ber_decode_RSAPrivateKey(p8_der, p8_der_len,
                                  &modulus, &pub_exp, &priv_exp,
                                  &prime1, &prime2, &exponent1,
                                  &exponent2, &coefficient);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_rsa: ber_decode_RSAPrivateKey failed with rv=%lu\n", rv);
        free(p8_der);
        return 1;
    }

    if (!modulus || !pub_exp || !priv_exp || !prime1 || !prime2 ||
        !exponent1 || !exponent2 || !coefficient) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_rsa: missing decoded attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_RSAPrivateKey(FALSE, &reencoded, &reencoded_len,
                                  modulus, pub_exp, priv_exp,
                                  prime1, prime2, exponent1,
                                  exponent2, coefficient);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_rsa: ber_encode_RSAPrivateKey failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != p8_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_rsa: length mismatch (expected %lu, got %lu)\n",
                p8_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_pkcs8_rsa", p8_der, reencoded, p8_der_len);
    }

cleanup:
    free(modulus);
    free(pub_exp);
    free(priv_exp);
    free(prime1);
    free(prime2);
    free(exponent1);
    free(exponent2);
    free(coefficient);
    free(p8_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_pkcs8_rsa\n");
    return result;
}

/* Test DSA Private Key: OpenSSL EVP_PKEY2PKCS8 -> ber_decode_DSAPrivateKey -> ber_encode_DSAPrivateKey */
int test_openssl_pkcs8_dsa(void)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *p8_der = NULL;
    CK_ULONG p8_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *prime = NULL, *subprime = NULL, *base = NULL, *priv_key = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_dsa_key();
    if (pkey == NULL) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dsa: failed to generate OpenSSL DSA key\n");
        return 1;
    }

    rv = openssl_to_pkcs8_der(pkey, &p8_der, &p8_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || p8_der == NULL || p8_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dsa: failed to encode PKCS#8 via OpenSSL\n");
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = ber_decode_DSAPrivateKey(p8_der, p8_der_len,
                                  &prime, &subprime, &base, &priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dsa: ber_decode_DSAPrivateKey failed with rv=%lu\n", rv);
        free(p8_der);
        return 1;
    }

    if (!prime || !subprime || !base || !priv_key) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dsa: missing decoded attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_DSAPrivateKey(FALSE, &reencoded, &reencoded_len,
                                  prime, subprime, base, priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dsa: ber_encode_DSAPrivateKey failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != p8_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dsa: length mismatch (expected %lu, got %lu)\n",
                p8_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_pkcs8_dsa", p8_der, reencoded, p8_der_len);
    }

cleanup:
    free(prime);
    free(subprime);
    free(base);
    free(priv_key);
    free(p8_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_pkcs8_dsa\n");
    return result;
}

/* Test DH Private Key: OpenSSL EVP_PKEY2PKCS8 -> ber_decode_DHPrivateKey -> ber_encode_DHPrivateKey */
int test_openssl_pkcs8_dh(void)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *p8_der = NULL;
    CK_ULONG p8_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *prime = NULL, *base = NULL, *priv_key = NULL;
    CK_ATTRIBUTE *dec2_prime = NULL, *dec2_base = NULL, *dec2_priv_key = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_dh_key();
    if (pkey == NULL) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dh: failed to generate OpenSSL DH key\n");
        return 1;
    }

    rv = openssl_to_pkcs8_der(pkey, &p8_der, &p8_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || p8_der == NULL || p8_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dh: failed to encode PKCS#8 via OpenSSL\n");
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = ber_decode_DHPrivateKey(p8_der, p8_der_len,
                                 &prime, &base, &priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dh: ber_decode_DHPrivateKey failed with rv=%lu\n", rv);
        free(p8_der);
        return 1;
    }

    if (!prime || !base || !priv_key) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dh: missing decoded attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_DHPrivateKey(FALSE, &reencoded, &reencoded_len,
                                 prime, base, priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_dh: ber_encode_DHPrivateKey failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len == p8_der_len && memcmp(reencoded, p8_der, p8_der_len) == 0) {
        /* Exact byte match */
    } else {
        /* Verify re-decoded attributes match if encoding details differ */
        rv = ber_decode_DHPrivateKey(reencoded, reencoded_len,
                                     &dec2_prime, &dec2_base, &dec2_priv_key);
        if (rv != CKR_OK || !dec2_prime || !dec2_base || !dec2_priv_key ||
            dec2_prime->ulValueLen != prime->ulValueLen ||
            memcmp(dec2_prime->pValue, prime->pValue, prime->ulValueLen) != 0 ||
            dec2_base->ulValueLen != base->ulValueLen ||
            memcmp(dec2_base->pValue, base->pValue, base->ulValueLen) != 0 ||
            dec2_priv_key->ulValueLen != priv_key->ulValueLen ||
            memcmp(dec2_priv_key->pValue, priv_key->pValue, priv_key->ulValueLen) != 0) {
            fprintf(stderr, "[FAIL] test_openssl_pkcs8_dh: round-trip attribute mismatch\n");
            result = 1;
        }
        free(dec2_prime);
        free(dec2_base);
        free(dec2_priv_key);
    }

cleanup:
    free(prime);
    free(base);
    free(priv_key);
    free(p8_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_pkcs8_dh\n");
    return result;
}

/* Helper to test EC Private Key for a specific curve */
static int test_openssl_pkcs8_ec_curve(int nid, const char *curve_name)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *p8_der = NULL;
    CK_ULONG p8_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *pub_key = NULL, *priv_key = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_ec_key(nid);
    if (pkey == NULL) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ec (%s): failed to generate OpenSSL EC key\n",
                curve_name);
        return 1;
    }

    rv = openssl_to_pkcs8_der(pkey, &p8_der, &p8_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || p8_der == NULL || p8_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ec (%s): failed to encode PKCS#8 via OpenSSL\n",
                curve_name);
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = der_decode_ECPrivateKey(p8_der, p8_der_len,
                                 &params, &pub_key, &priv_key, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ec (%s): der_decode_ECPrivateKey failed with rv=%lu\n",
                curve_name, rv);
        free(p8_der);
        return 1;
    }

    if (!params || !priv_key) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ec (%s): missing decoded attributes\n",
                curve_name);
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = der_encode_ECPrivateKey(FALSE, &reencoded, &reencoded_len,
                                 params, priv_key, pub_key, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ec (%s): der_encode_ECPrivateKey failed with rv=%lu\n",
                curve_name, rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != p8_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ec (%s): length mismatch (expected %lu, got %lu)\n",
                curve_name, p8_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_pkcs8_ec", p8_der, reencoded, p8_der_len);
    }

cleanup:
    free(params);
    free(pub_key);
    free(priv_key);
    free(p8_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_pkcs8_ec (%s)\n", curve_name);
    return result;
}

/* Test EC Private Keys across standard curves */
int test_openssl_pkcs8_ec(void)
{
    int failed = 0;

    failed += test_openssl_pkcs8_ec_curve(NID_X9_62_prime256v1, "P-256 / prime256v1");
    failed += test_openssl_pkcs8_ec_curve(NID_secp384r1, "P-384 / secp384r1");
    failed += test_openssl_pkcs8_ec_curve(NID_secp521r1, "P-521 / secp521r1");

    return failed;
}

#ifndef OSSL_PKEY_PARAM_OUTPUT_FORMATS
#define OSSL_PKEY_PARAM_OUTPUT_FORMATS "output-formats"
#endif

/*
 * Encode pkey as a PKCS#8 DER blob using the OpenSSL 3.x OSSL_ENCODER API.
 * When fmt is non-NULL the output format is selected via
 * OSSL_PKEY_PARAM_OUTPUT_FORMATS (available since OpenSSL 4.0).
 * Passing NULL for fmt lets OpenSSL produce its default encoding.
 *
 * Supported format strings for ML-DSA / ML-KEM (OpenSSL >= 4.0) are:
 *   "seed-only"  - private seed wrapped in [0] CHOICE
 *   "priv-only"  - expanded private key as OCTET STRING
 *   "seed-priv"  - SEQUENCE { seed OCTET STRING, expanded OCTET STRING }
 *
 * Also used for Edwards and Montgomery keys so that EVP_PKEY2PKCS8 (which is
 * unreliable for these types on some OpenSSL 3.x builds) is avoided.
 */
static CK_RV ossl_pkey_to_pkcs8_der_fmt(EVP_PKEY *pkey, const char *fmt,
                                       CK_BYTE **der_out, CK_ULONG *der_len_out)
{
    OSSL_PARAM params[2] = { OSSL_PARAM_END, OSSL_PARAM_END };
    OSSL_ENCODER_CTX *ectx = NULL;
    unsigned char *buf = NULL;
    size_t len = 0;
    CK_RV rv = CKR_FUNCTION_FAILED;

    ectx = OSSL_ENCODER_CTX_new_for_pkey(pkey, EVP_PKEY_KEYPAIR,
                                         "DER", "PrivateKeyInfo", NULL);
    if (ectx == NULL)
        goto out;

    if (fmt != NULL) {
        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_PKEY_PARAM_OUTPUT_FORMATS,
                                                     (char *)fmt, 0);
        if (!OSSL_ENCODER_CTX_set_params(ectx, params))
            goto out;
    }

    if (!OSSL_ENCODER_to_data(ectx, &buf, &len) || buf == NULL || len == 0)
        goto out;

    *der_out = (CK_BYTE *)buf;
    *der_len_out = (CK_ULONG)len;
    buf = NULL;
    rv = CKR_OK;

out:
    OSSL_ENCODER_CTX_free(ectx);
    OPENSSL_free(buf);
    return rv;
}

/* Helper to test Edwards Private Key (ED25519, ED448) */
static int test_openssl_pkcs8_edwards_curve(int type_id, const char *type_name)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *p8_der = NULL;
    CK_ULONG p8_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *pub_key = NULL, *priv_key = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_named_key(type_id, type_name);
    if (pkey == NULL) {
        printf("[SKIP] test_openssl_pkcs8_edwards (%s): not supported by OpenSSL build\n",
               type_name);
        return 0;
    }

    /*
     * Use OSSL_ENCODER on OpenSSL >= 3.0: EVP_PKEY2PKCS8 is unreliable for
     * Edwards keys on some 3.x builds and is not available before OpenSSL 1.1.
     */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = ossl_pkey_to_pkcs8_der_fmt(pkey, NULL, &p8_der, &p8_der_len);
#else
    rv = openssl_to_pkcs8_der(pkey, &p8_der, &p8_der_len);
#endif
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || p8_der == NULL || p8_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_edwards (%s): failed to encode PKCS#8 via OpenSSL\n",
                type_name);
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = der_decode_ECPrivateKey(p8_der, p8_der_len,
                                 &params, &pub_key, &priv_key, CKK_EC_EDWARDS);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_edwards (%s): der_decode_ECPrivateKey failed with rv=%lu\n",
                type_name, rv);
        free(p8_der);
        return 1;
    }

    if (!params || !priv_key) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_edwards (%s): missing decoded attributes\n",
                type_name);
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = der_encode_ECPrivateKey(FALSE, &reencoded, &reencoded_len,
                                 params, priv_key, NULL, CKK_EC_EDWARDS);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_edwards (%s): der_encode_ECPrivateKey failed with rv=%lu\n",
                type_name, rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != p8_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_edwards (%s): length mismatch (expected %lu, got %lu)\n",
                type_name, p8_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_pkcs8_edwards", p8_der, reencoded, p8_der_len);
    }

cleanup:
    free(params);
    free(pub_key);
    free(priv_key);
    free(p8_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_pkcs8_edwards (%s)\n", type_name);
    return result;
}

/* Test Edwards Curve Private Keys */
int test_openssl_pkcs8_edwards(void)
{
    int failed = 0;

#ifdef EVP_PKEY_ED25519
    failed += test_openssl_pkcs8_edwards_curve(EVP_PKEY_ED25519, "ED25519");
#else
    failed += test_openssl_pkcs8_edwards_curve(0, "ED25519");
#endif

#ifdef EVP_PKEY_ED448
    failed += test_openssl_pkcs8_edwards_curve(EVP_PKEY_ED448, "ED448");
#else
    failed += test_openssl_pkcs8_edwards_curve(0, "ED448");
#endif

    return failed;
}

/* Helper to test Montgomery Private Key (X25519, X448) */
static int test_openssl_pkcs8_montgomery_curve(int type_id, const char *type_name)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *p8_der = NULL;
    CK_ULONG p8_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *pub_key = NULL, *priv_key = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_named_key(type_id, type_name);
    if (pkey == NULL) {
        printf("[SKIP] test_openssl_pkcs8_montgomery (%s): not supported by OpenSSL build\n",
               type_name);
        return 0;
    }

    /*
     * Use OSSL_ENCODER on OpenSSL >= 3.0: EVP_PKEY2PKCS8 is unreliable for
     * Montgomery keys on some 3.x builds and is not available before OpenSSL 1.1.
     */
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
    rv = ossl_pkey_to_pkcs8_der_fmt(pkey, NULL, &p8_der, &p8_der_len);
#else
    rv = openssl_to_pkcs8_der(pkey, &p8_der, &p8_der_len);
#endif
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || p8_der == NULL || p8_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_montgomery (%s): failed to encode PKCS#8 via OpenSSL\n",
                type_name);
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = der_decode_ECPrivateKey(p8_der, p8_der_len,
                                 &params, &pub_key, &priv_key, CKK_EC_MONTGOMERY);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_montgomery (%s): der_decode_ECPrivateKey failed with rv=%lu\n",
                type_name, rv);
        free(p8_der);
        return 1;
    }

    if (!params || !priv_key) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_montgomery (%s): missing decoded attributes\n",
                type_name);
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = der_encode_ECPrivateKey(FALSE, &reencoded, &reencoded_len,
                                 params, priv_key, NULL, CKK_EC_MONTGOMERY);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_montgomery (%s): der_encode_ECPrivateKey failed with rv=%lu\n",
                type_name, rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != p8_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_montgomery (%s): length mismatch (expected %lu, got %lu)\n",
                type_name, p8_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_pkcs8_montgomery", p8_der, reencoded, p8_der_len);
    }

cleanup:
    free(params);
    free(pub_key);
    free(priv_key);
    free(p8_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_pkcs8_montgomery (%s)\n", type_name);
    return result;
}

/* Test Montgomery Curve Private Keys */
int test_openssl_pkcs8_montgomery(void)
{
    int failed = 0;

#ifdef EVP_PKEY_X25519
    failed += test_openssl_pkcs8_montgomery_curve(EVP_PKEY_X25519, "X25519");
#else
    failed += test_openssl_pkcs8_montgomery_curve(0, "X25519");
#endif

#ifdef EVP_PKEY_X448
    failed += test_openssl_pkcs8_montgomery_curve(EVP_PKEY_X448, "X448");
#else
    failed += test_openssl_pkcs8_montgomery_curve(0, "X448");
#endif

    return failed;
}

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
/* Helper to test one ML-DSA PKCS#8 output format.
 * fmt selects the output format (OpenSSL >= 4.0); pass NULL for the default. */
static int test_openssl_pkcs8_ml_dsa_fmt(const char *alg_name,
                                          const char *fmt,
                                          EVP_PKEY *pkey)
{
    CK_BYTE *p8_der = NULL;
    CK_ULONG p8_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *value = NULL, *seed = NULL;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    rv = ossl_pkey_to_pkcs8_der_fmt(pkey, fmt, &p8_der, &p8_der_len);
    if (rv != CKR_OK || p8_der == NULL || p8_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ml_dsa (%s, %s): "
                "failed to encode PKCS#8 via OpenSSL\n", alg_name,
                fmt ? fmt : "default");
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = ber_decode_ML_DSA_PrivateKey(p8_der, p8_der_len, &value, &seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ml_dsa (%s, %s): "
                "ber_decode_ML_DSA_PrivateKey failed with rv=%lu\n",
                alg_name, fmt ? fmt : "default", rv);
        free(p8_der);
        return 1;
    }

    if (!value && !seed) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ml_dsa (%s, %s): "
                "missing decoded value/seed attributes\n",
                alg_name, fmt ? fmt : "default");
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_ML_DSA_PrivateKey(FALSE, &reencoded, &reencoded_len,
                                      oid->oid, oid->oid_len, value, seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ml_dsa (%s, %s): "
                "ber_encode_ML_DSA_PrivateKey failed with rv=%lu\n",
                alg_name, fmt ? fmt : "default", rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != p8_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ml_dsa (%s, %s): "
                "length mismatch (expected %lu, got %lu)\n",
                alg_name, fmt ? fmt : "default", p8_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_pkcs8_ml_dsa",
                               p8_der, reencoded, p8_der_len);
    }

cleanup:
    free(value);
    free(seed);
    free(p8_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_pkcs8_ml_dsa (%s, %s)\n",
               alg_name, fmt ? fmt : "default");
    return result;
}

/* Helper to test ML-DSA Private Key PKCS#8 encoding.
 * On OpenSSL >= 4.0 all three output formats are tested; on 3.5.x only the
 * default format produced by OpenSSL is tested. */
static int test_openssl_pkcs8_ml_dsa_type(const char *alg_name)
{
    EVP_PKEY *pkey = NULL;
    int result = 0;

    pkey = create_openssl_named_key(0, alg_name);
    if (pkey == NULL) {
        /* OpenSSL does not support this algorithm */
        return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x40000000L
    result += test_openssl_pkcs8_ml_dsa_fmt(alg_name, "seed-only", pkey);
    result += test_openssl_pkcs8_ml_dsa_fmt(alg_name, "priv-only", pkey);
    result += test_openssl_pkcs8_ml_dsa_fmt(alg_name, "seed-priv", pkey);
#else
    /* OpenSSL 3.5.x: test only the default PKCS#8 encoding */
    result += test_openssl_pkcs8_ml_dsa_fmt(alg_name, NULL, pkey);
#endif

    EVP_PKEY_free(pkey);
    return result;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

/* Test ML-DSA Private Keys */
int test_openssl_pkcs8_ml_dsa(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    int failed = 0;

    failed += test_openssl_pkcs8_ml_dsa_type("ML-DSA-44");
    failed += test_openssl_pkcs8_ml_dsa_type("ML-DSA-65");
    failed += test_openssl_pkcs8_ml_dsa_type("ML-DSA-87");

    return failed;
#else
    printf("[SKIP] test_openssl_pkcs8_ml_dsa: requires OpenSSL >= 3.5\n");
    return 0;
#endif
}

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
/* Helper to test one ML-KEM PKCS#8 output format.
 * fmt selects the output format (OpenSSL >= 4.0); pass NULL for the default. */
static int test_openssl_pkcs8_ml_kem_fmt(const char *alg_name,
                                          const char *fmt,
                                          EVP_PKEY *pkey)
{
    CK_BYTE *p8_der = NULL;
    CK_ULONG p8_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *value = NULL, *seed = NULL;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    rv = ossl_pkey_to_pkcs8_der_fmt(pkey, fmt, &p8_der, &p8_der_len);
    if (rv != CKR_OK || p8_der == NULL || p8_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ml_kem (%s, %s): "
                "failed to encode PKCS#8 via OpenSSL\n",
                alg_name, fmt ? fmt : "default");
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = ber_decode_ML_KEM_PrivateKey(p8_der, p8_der_len, &value, &seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ml_kem (%s, %s): "
                "ber_decode_ML_KEM_PrivateKey failed with rv=%lu\n",
                alg_name, fmt ? fmt : "default", rv);
        free(p8_der);
        return 1;
    }

    if (!value && !seed) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ml_kem (%s, %s): "
                "missing decoded value/seed attributes\n",
                alg_name, fmt ? fmt : "default");
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_ML_KEM_PrivateKey(FALSE, &reencoded, &reencoded_len,
                                      oid->oid, oid->oid_len, value, seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ml_kem (%s, %s): "
                "ber_encode_ML_KEM_PrivateKey failed with rv=%lu\n",
                alg_name, fmt ? fmt : "default", rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != p8_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_pkcs8_ml_kem (%s, %s): "
                "length mismatch (expected %lu, got %lu)\n",
                alg_name, fmt ? fmt : "default", p8_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_pkcs8_ml_kem",
                               p8_der, reencoded, p8_der_len);
    }

cleanup:
    free(value);
    free(seed);
    free(p8_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_pkcs8_ml_kem (%s, %s)\n",
               alg_name, fmt ? fmt : "default");
    return result;
}

/* Helper to test ML-KEM Private Key PKCS#8 encoding.
 * On OpenSSL >= 4.0 all three output formats are tested; on 3.5.x only the
 * default format produced by OpenSSL is tested. */
static int test_openssl_pkcs8_ml_kem_type(const char *alg_name)
{
    EVP_PKEY *pkey = NULL;
    int result = 0;

    pkey = create_openssl_named_key(0, alg_name);
    if (pkey == NULL) {
        /* OpenSSL does not support this algorithm */
        return 0;
    }

#if OPENSSL_VERSION_NUMBER >= 0x40000000L
    result += test_openssl_pkcs8_ml_kem_fmt(alg_name, "seed-only", pkey);
    result += test_openssl_pkcs8_ml_kem_fmt(alg_name, "priv-only", pkey);
    result += test_openssl_pkcs8_ml_kem_fmt(alg_name, "seed-priv", pkey);
#else
    /* OpenSSL 3.5.x: test only the default PKCS#8 encoding */
    result += test_openssl_pkcs8_ml_kem_fmt(alg_name, NULL, pkey);
#endif

    EVP_PKEY_free(pkey);
    return result;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

/* Test ML-KEM Private Keys */
int test_openssl_pkcs8_ml_kem(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    int failed = 0;

    failed += test_openssl_pkcs8_ml_kem_type("ML-KEM-512");
    failed += test_openssl_pkcs8_ml_kem_type("ML-KEM-768");
    failed += test_openssl_pkcs8_ml_kem_type("ML-KEM-1024");

    return failed;
#else
    printf("[SKIP] test_openssl_pkcs8_ml_kem: requires OpenSSL >= 3.5\n");
    return 0;
#endif
}

/* ========================================================================
 * OpenSSL SPKI Public Key Tests
 * ======================================================================== */

/* Test RSA SPKI: OpenSSL i2d_PUBKEY_bio -> ber_decode_RSAPublicKey -> ber_encode_RSAPublicKey */
int test_openssl_spki_rsa(void)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *spki_der = NULL;
    CK_ULONG spki_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *modulus = NULL, *pub_exp = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_rsa_key();
    if (pkey == NULL) {
        fprintf(stderr, "[FAIL] test_openssl_spki_rsa: failed to generate OpenSSL RSA key\n");
        return 1;
    }

    rv = openssl_to_spki_der(pkey, &spki_der, &spki_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || spki_der == NULL || spki_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_spki_rsa: failed to encode SPKI via OpenSSL\n");
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = ber_decode_RSAPublicKey(spki_der, spki_der_len, &modulus, &pub_exp);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_rsa: ber_decode_RSAPublicKey failed with rv=%lu\n", rv);
        free(spki_der);
        return 1;
    }

    if (!modulus || !pub_exp) {
        fprintf(stderr, "[FAIL] test_openssl_spki_rsa: missing decoded attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_RSAPublicKey(FALSE, &reencoded, &reencoded_len, modulus, pub_exp);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_rsa: ber_encode_RSAPublicKey failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != spki_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_spki_rsa: length mismatch (expected %lu, got %lu)\n",
                spki_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_spki_rsa", spki_der, reencoded, spki_der_len);
    }

cleanup:
    free(modulus);
    free(pub_exp);
    free(spki_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_spki_rsa\n");
    return result;
}

/* Test DSA SPKI: OpenSSL i2d_PUBKEY_bio -> ber_decode_DSAPublicKey -> ber_encode_DSAPublicKey */
int test_openssl_spki_dsa(void)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *spki_der = NULL;
    CK_ULONG spki_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *prime = NULL, *subprime = NULL, *base = NULL, *value = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_dsa_key();
    if (pkey == NULL) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dsa: failed to generate OpenSSL DSA key\n");
        return 1;
    }

    rv = openssl_to_spki_der(pkey, &spki_der, &spki_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || spki_der == NULL || spki_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dsa: failed to encode SPKI via OpenSSL\n");
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = ber_decode_DSAPublicKey(spki_der, spki_der_len,
                                 &prime, &subprime, &base, &value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dsa: ber_decode_DSAPublicKey failed with rv=%lu\n", rv);
        free(spki_der);
        return 1;
    }

    if (!prime || !subprime || !base || !value) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dsa: missing decoded attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_DSAPublicKey(FALSE, &reencoded, &reencoded_len,
                                 prime, subprime, base, value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dsa: ber_encode_DSAPublicKey failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != spki_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dsa: length mismatch (expected %lu, got %lu)\n",
                spki_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_spki_dsa", spki_der, reencoded, spki_der_len);
    }

cleanup:
    free(prime);
    free(subprime);
    free(base);
    free(value);
    free(spki_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_spki_dsa\n");
    return result;
}

/* Test DH SPKI: OpenSSL i2d_PUBKEY_bio -> ber_decode_DHPublicKey -> ber_encode_DHPublicKey */
int test_openssl_spki_dh(void)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *spki_der = NULL;
    CK_ULONG spki_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *prime = NULL, *base = NULL, *value = NULL;
    CK_ATTRIBUTE *dec2_prime = NULL, *dec2_base = NULL, *dec2_value = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_dh_key();
    if (pkey == NULL) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dh: failed to generate OpenSSL DH key\n");
        return 1;
    }

    rv = openssl_to_spki_der(pkey, &spki_der, &spki_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || spki_der == NULL || spki_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dh: failed to encode SPKI via OpenSSL\n");
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = ber_decode_DHPublicKey(spki_der, spki_der_len,
                                &prime, &base, &value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dh: ber_decode_DHPublicKey failed with rv=%lu\n", rv);
        free(spki_der);
        return 1;
    }

    if (!prime || !base || !value) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dh: missing decoded attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_DHPublicKey(FALSE, &reencoded, &reencoded_len,
                                prime, base, value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_dh: ber_encode_DHPublicKey failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len == spki_der_len && memcmp(reencoded, spki_der, spki_der_len) == 0) {
        /* Exact byte match */
    } else {
        /* Re-decode and verify attributes match */
        rv = ber_decode_DHPublicKey(reencoded, reencoded_len,
                                    &dec2_prime, &dec2_base, &dec2_value);
        if (rv != CKR_OK ||
            dec2_prime->ulValueLen != prime->ulValueLen ||
            memcmp(dec2_prime->pValue, prime->pValue, prime->ulValueLen) != 0 ||
            dec2_base->ulValueLen != base->ulValueLen ||
            memcmp(dec2_base->pValue, base->pValue, base->ulValueLen) != 0 ||
            dec2_value->ulValueLen != value->ulValueLen ||
            memcmp(dec2_value->pValue, value->pValue, value->ulValueLen) != 0) {
            fprintf(stderr, "[FAIL] test_openssl_spki_dh: round-trip attribute mismatch\n");
            result = 1;
        }
        free(dec2_prime);
        free(dec2_base);
        free(dec2_value);
    }

cleanup:
    free(prime);
    free(base);
    free(value);
    free(spki_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_spki_dh\n");
    return result;
}

/* Helper to test EC SPKI for a specific curve */
static int test_openssl_spki_ec_curve(int nid, const char *curve_name)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *spki_der = NULL;
    CK_ULONG spki_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *point = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_ec_key(nid);
    if (pkey == NULL) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ec (%s): failed to generate OpenSSL EC key\n",
                curve_name);
        return 1;
    }

    rv = openssl_to_spki_der(pkey, &spki_der, &spki_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || spki_der == NULL || spki_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ec (%s): failed to encode SPKI via OpenSSL\n",
                curve_name);
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = der_decode_ECPublicKey(spki_der, spki_der_len,
                                &params, &point, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ec (%s): der_decode_ECPublicKey failed with rv=%lu\n",
                curve_name, rv);
        free(spki_der);
        return 1;
    }

    if (!params || !point) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ec (%s): missing decoded attributes\n",
                curve_name);
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_ECPublicKey(FALSE, &reencoded, &reencoded_len,
                                params, point, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ec (%s): ber_encode_ECPublicKey failed with rv=%lu\n",
                curve_name, rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != spki_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ec (%s): length mismatch (expected %lu, got %lu)\n",
                curve_name, spki_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_spki_ec", spki_der, reencoded, spki_der_len);
    }

cleanup:
    free(params);
    free(point);
    free(spki_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_spki_ec (%s)\n", curve_name);
    return result;
}

/* Test EC SPKI across standard curves */
int test_openssl_spki_ec(void)
{
    int failed = 0;

    failed += test_openssl_spki_ec_curve(NID_X9_62_prime256v1, "P-256 / prime256v1");
    failed += test_openssl_spki_ec_curve(NID_secp384r1, "P-384 / secp384r1");
    failed += test_openssl_spki_ec_curve(NID_secp521r1, "P-521 / secp521r1");

    return failed;
}

/* Helper to test Edwards SPKI (ED25519, ED448) */
static int test_openssl_spki_edwards_curve(int type_id, const char *type_name)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *spki_der = NULL;
    CK_ULONG spki_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *point = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_named_key(type_id, type_name);
    if (pkey == NULL) {
        printf("[SKIP] test_openssl_spki_edwards (%s): not supported by OpenSSL build\n",
               type_name);
        return 0;
    }

    rv = openssl_to_spki_der(pkey, &spki_der, &spki_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || spki_der == NULL || spki_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_spki_edwards (%s): failed to encode SPKI via OpenSSL\n",
                type_name);
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = der_decode_ECPublicKey(spki_der, spki_der_len,
                                &params, &point, CKK_EC_EDWARDS);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_edwards (%s): der_decode_ECPublicKey failed with rv=%lu\n",
                type_name, rv);
        free(spki_der);
        return 1;
    }

    if (!params || !point) {
        fprintf(stderr, "[FAIL] test_openssl_spki_edwards (%s): missing decoded attributes\n",
                type_name);
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_ECPublicKey(FALSE, &reencoded, &reencoded_len,
                                params, point, CKK_EC_EDWARDS);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_edwards (%s): ber_encode_ECPublicKey failed with rv=%lu\n",
                type_name, rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != spki_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_spki_edwards (%s): length mismatch (expected %lu, got %lu)\n",
                type_name, spki_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_spki_edwards", spki_der, reencoded, spki_der_len);
    }

cleanup:
    free(params);
    free(point);
    free(spki_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_spki_edwards (%s)\n", type_name);
    return result;
}

/* Test Edwards Curve SPKI */
int test_openssl_spki_edwards(void)
{
    int failed = 0;

#ifdef EVP_PKEY_ED25519
    failed += test_openssl_spki_edwards_curve(EVP_PKEY_ED25519, "ED25519");
#else
    failed += test_openssl_spki_edwards_curve(0, "ED25519");
#endif

#ifdef EVP_PKEY_ED448
    failed += test_openssl_spki_edwards_curve(EVP_PKEY_ED448, "ED448");
#else
    failed += test_openssl_spki_edwards_curve(0, "ED448");
#endif

    return failed;
}

/* Helper to test Montgomery SPKI (X25519, X448) */
static int test_openssl_spki_montgomery_curve(int type_id, const char *type_name)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *spki_der = NULL;
    CK_ULONG spki_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *point = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_named_key(type_id, type_name);
    if (pkey == NULL) {
        printf("[SKIP] test_openssl_spki_montgomery (%s): not supported by OpenSSL build\n",
               type_name);
        return 0;
    }

    rv = openssl_to_spki_der(pkey, &spki_der, &spki_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || spki_der == NULL || spki_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_spki_montgomery (%s): failed to encode SPKI via OpenSSL\n",
                type_name);
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = der_decode_ECPublicKey(spki_der, spki_der_len,
                                &params, &point, CKK_EC_MONTGOMERY);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_montgomery (%s): der_decode_ECPublicKey failed with rv=%lu\n",
                type_name, rv);
        free(spki_der);
        return 1;
    }

    if (!params || !point) {
        fprintf(stderr, "[FAIL] test_openssl_spki_montgomery (%s): missing decoded attributes\n",
                type_name);
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_ECPublicKey(FALSE, &reencoded, &reencoded_len,
                                params, point, CKK_EC_MONTGOMERY);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_montgomery (%s): ber_encode_ECPublicKey failed with rv=%lu\n",
                type_name, rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != spki_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_spki_montgomery (%s): length mismatch (expected %lu, got %lu)\n",
                type_name, spki_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_spki_montgomery", spki_der, reencoded, spki_der_len);
    }

cleanup:
    free(params);
    free(point);
    free(spki_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_spki_montgomery (%s)\n", type_name);
    return result;
}

/* Test Montgomery Curve SPKI */
int test_openssl_spki_montgomery(void)
{
    int failed = 0;

#ifdef EVP_PKEY_X25519
    failed += test_openssl_spki_montgomery_curve(EVP_PKEY_X25519, "X25519");
#else
    failed += test_openssl_spki_montgomery_curve(0, "X25519");
#endif

#ifdef EVP_PKEY_X448
    failed += test_openssl_spki_montgomery_curve(EVP_PKEY_X448, "X448");
#else
    failed += test_openssl_spki_montgomery_curve(0, "X448");
#endif

    return failed;
}

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
/* Helper to test ML-DSA SPKI if supported by OpenSSL */
static int test_openssl_spki_ml_dsa_type(const char *alg_name)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *spki_der = NULL;
    CK_ULONG spki_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *pubkey = NULL;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_named_key(0, alg_name);
    if (pkey == NULL) {
        /* OpenSSL does not support this algorithm */
        return 0;
    }

    rv = openssl_to_spki_der(pkey, &spki_der, &spki_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || spki_der == NULL || spki_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ml_dsa (%s): failed to encode SPKI via OpenSSL\n",
                alg_name);
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = ber_decode_ML_DSA_PublicKey(spki_der, spki_der_len, &pubkey, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ml_dsa (%s): ber_decode_ML_DSA_PublicKey failed with rv=%lu\n",
                alg_name, rv);
        free(spki_der);
        return 1;
    }

    if (!pubkey || !oid) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ml_dsa (%s): missing decoded attributes\n",
                alg_name);
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_ML_DSA_PublicKey(FALSE, &reencoded, &reencoded_len,
                                     oid->oid, oid->oid_len, pubkey);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ml_dsa (%s): ber_encode_ML_DSA_PublicKey failed with rv=%lu\n",
                alg_name, rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != spki_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ml_dsa (%s): length mismatch (expected %lu, got %lu)\n",
                alg_name, spki_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_spki_ml_dsa", spki_der, reencoded, spki_der_len);
    }

cleanup:
    free(pubkey);
    free(spki_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_spki_ml_dsa (%s)\n", alg_name);
    return result;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

/* Test ML-DSA SPKI */
int test_openssl_spki_ml_dsa(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    int failed = 0;

    failed += test_openssl_spki_ml_dsa_type("ML-DSA-44");
    failed += test_openssl_spki_ml_dsa_type("ML-DSA-65");
    failed += test_openssl_spki_ml_dsa_type("ML-DSA-87");

    return failed;
#else
    printf("[SKIP] test_openssl_spki_ml_dsa: requires OpenSSL >= 3.5\n");
    return 0;
#endif
}

#if OPENSSL_VERSION_NUMBER >= 0x30500000L
/* Helper to test ML-KEM SPKI if supported by OpenSSL */
static int test_openssl_spki_ml_kem_type(const char *alg_name)
{
    EVP_PKEY *pkey = NULL;
    CK_BYTE *spki_der = NULL;
    CK_ULONG spki_der_len = 0;
    CK_BYTE *reencoded = NULL;
    CK_ULONG reencoded_len = 0;
    CK_ATTRIBUTE *pubkey = NULL;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    pkey = create_openssl_named_key(0, alg_name);
    if (pkey == NULL) {
        /* OpenSSL does not support this algorithm */
        return 0;
    }

    rv = openssl_to_spki_der(pkey, &spki_der, &spki_der_len);
    EVP_PKEY_free(pkey);
    if (rv != CKR_OK || spki_der == NULL || spki_der_len == 0) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ml_kem (%s): failed to encode SPKI via OpenSSL\n",
                alg_name);
        return 1;
    }

    /* Decode using opencryptoki asn1 function */
    rv = ber_decode_ML_KEM_PublicKey(spki_der, spki_der_len, &pubkey, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ml_kem (%s): ber_decode_ML_KEM_PublicKey failed with rv=%lu\n",
                alg_name, rv);
        free(spki_der);
        return 1;
    }

    if (!pubkey || !oid) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ml_kem (%s): missing decoded attributes\n",
                alg_name);
        result = 1;
        goto cleanup;
    }

    /* Round trip: re-encode via opencryptoki asn1 function */
    rv = ber_encode_ML_KEM_PublicKey(FALSE, &reencoded, &reencoded_len,
                                     oid->oid, oid->oid_len, pubkey);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ml_kem (%s): ber_encode_ML_KEM_PublicKey failed with rv=%lu\n",
                alg_name, rv);
        result = 1;
        goto cleanup;
    }

    if (reencoded_len != spki_der_len) {
        fprintf(stderr, "[FAIL] test_openssl_spki_ml_kem (%s): length mismatch (expected %lu, got %lu)\n",
                alg_name, spki_der_len, reencoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_openssl_spki_ml_kem", spki_der, reencoded, spki_der_len);
    }

cleanup:
    free(pubkey);
    free(spki_der);
    free(reencoded);

    if (result == 0)
        printf("[PASS] test_openssl_spki_ml_kem (%s)\n", alg_name);
    return result;
}
#endif /* OPENSSL_VERSION_NUMBER >= 0x30500000L */

/* Test ML-KEM SPKI */
int test_openssl_spki_ml_kem(void)
{
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    int failed = 0;

    failed += test_openssl_spki_ml_kem_type("ML-KEM-512");
    failed += test_openssl_spki_ml_kem_type("ML-KEM-768");
    failed += test_openssl_spki_ml_kem_type("ML-KEM-1024");

    return failed;
#else
    printf("[SKIP] test_openssl_spki_ml_kem: requires OpenSSL >= 3.5\n");
    return 0;
#endif
}
