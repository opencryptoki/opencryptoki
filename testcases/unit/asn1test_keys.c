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
 * Cryptographic key encoding/decoding unit tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "unittest.h"
#include "asn1test_keys.h"


/* Helper function to create a CK_ATTRIBUTE with data */
CK_ATTRIBUTE *create_attribute(CK_ATTRIBUTE_TYPE type, CK_BYTE *data, CK_ULONG data_len);

/* Function prototypes from asn1.c */
CK_RV ber_encode_RSAPrivateKey(CK_BBOOL length_only,
                               CK_BYTE **data,
                               CK_ULONG *data_len,
                               CK_ATTRIBUTE *modulus,
                               CK_ATTRIBUTE *publ_exp,
                               CK_ATTRIBUTE *priv_exp,
                               CK_ATTRIBUTE *prime1,
                               CK_ATTRIBUTE *prime2,
                               CK_ATTRIBUTE *exponent1,
                               CK_ATTRIBUTE *exponent2,
                               CK_ATTRIBUTE *coeff);

CK_RV ber_decode_RSAPrivateKey(CK_BYTE *data,
                               CK_ULONG data_len,
                               CK_ATTRIBUTE **modulus,
                               CK_ATTRIBUTE **publ_exp,
                               CK_ATTRIBUTE **priv_exp,
                               CK_ATTRIBUTE **prime1,
                               CK_ATTRIBUTE **prime2,
                               CK_ATTRIBUTE **exponent1,
                               CK_ATTRIBUTE **exponent2,
                               CK_ATTRIBUTE **coeff);

CK_RV ber_encode_RSAPublicKey(CK_BBOOL length_only, CK_BYTE **data,
                              CK_ULONG *data_len, CK_ATTRIBUTE *modulus,
                              CK_ATTRIBUTE *publ_exp);

CK_RV ber_decode_RSAPublicKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **modulus,
                              CK_ATTRIBUTE **publ_exp);

CK_RV ber_encode_DSAPrivateKey(CK_BBOOL length_only,
                               CK_BYTE **data,
                               CK_ULONG *data_len,
                               CK_ATTRIBUTE *prime1,
                               CK_ATTRIBUTE *prime2,
                               CK_ATTRIBUTE *base,
                               CK_ATTRIBUTE *priv_key);

CK_RV ber_decode_DSAPrivateKey(CK_BYTE *data,
                               CK_ULONG data_len,
                               CK_ATTRIBUTE **prime,
                               CK_ATTRIBUTE **subprime,
                               CK_ATTRIBUTE **base,
                               CK_ATTRIBUTE **priv_key);

CK_RV ber_encode_DSAPublicKey(CK_BBOOL length_only,
                              CK_BYTE **data,
                              CK_ULONG *data_len,
                              CK_ATTRIBUTE *prime,
                              CK_ATTRIBUTE *subprime,
                              CK_ATTRIBUTE *base,
                              CK_ATTRIBUTE *value);

CK_RV ber_decode_DSAPublicKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **prime,
                              CK_ATTRIBUTE **subprime,
                              CK_ATTRIBUTE **base,
                              CK_ATTRIBUTE **value);

/* DH key encoding/decoding function prototypes */
CK_RV ber_encode_DHPrivateKey(CK_BBOOL length_only,
                              CK_BYTE **data,
                              CK_ULONG *data_len,
                              CK_ATTRIBUTE *prime,
                              CK_ATTRIBUTE *base,
                              CK_ATTRIBUTE *priv_key);

CK_RV ber_decode_DHPrivateKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **prime,
                              CK_ATTRIBUTE **base,
                              CK_ATTRIBUTE **priv_key);

CK_RV ber_encode_DHPublicKey(CK_BBOOL length_only,
                             CK_BYTE **data,
                             CK_ULONG *data_len,
                             CK_ATTRIBUTE *prime,
                             CK_ATTRIBUTE *base,
                             CK_ATTRIBUTE *value);

CK_RV ber_decode_DHPublicKey(CK_BYTE *data,
                             CK_ULONG data_len,
                             CK_ATTRIBUTE **prime,
                             CK_ATTRIBUTE **base,
                             CK_ATTRIBUTE **value);

/* EC key encoding/decoding function prototypes */
CK_RV der_encode_ECPrivateKey(CK_BBOOL length_only,
                              CK_BYTE **data,
                              CK_ULONG *data_len,
                              CK_ATTRIBUTE *params,
                              CK_ATTRIBUTE *privkey,
                              CK_ATTRIBUTE *pubkey,
                              CK_KEY_TYPE key_type);

CK_RV der_decode_ECPrivateKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **params,
                              CK_ATTRIBUTE **pub_key,
                              CK_ATTRIBUTE **priv_key,
                              CK_KEY_TYPE key_type);

CK_RV ber_encode_ECPublicKey(CK_BBOOL length_only,
                             CK_BYTE **data,
                             CK_ULONG *data_len,
                             CK_ATTRIBUTE *params,
                             CK_ATTRIBUTE *point,
                             CK_KEY_TYPE key_type);

CK_RV der_decode_ECPublicKey(CK_BYTE *data,
                             CK_ULONG data_len,
                             CK_ATTRIBUTE **ec_params,
                             CK_ATTRIBUTE **ec_point,
                             CK_KEY_TYPE key_type);

/* ML-DSA key encoding/decoding function prototypes */
CK_RV ber_encode_IBM_ML_DSA_PublicKey(CK_MECHANISM_TYPE mech,
                                      CK_BBOOL length_only,
                                      CK_BYTE **data, CK_ULONG *data_len,
                                      const CK_BYTE *oid, CK_ULONG oid_len,
                                      CK_ATTRIBUTE *rho, CK_ATTRIBUTE *t1);

CK_RV ber_decode_IBM_ML_DSA_PublicKey(CK_MECHANISM_TYPE mech,
                                      CK_BYTE *data,
                                      CK_ULONG data_len,
                                      CK_ATTRIBUTE **rho_attr,
                                      CK_ATTRIBUTE **t1_attr,
                                      CK_ATTRIBUTE **value_attr,
                                      const struct pqc_oid **oid);

CK_RV ber_encode_IBM_ML_DSA_PrivateKey(CK_MECHANISM_TYPE mech,
                                       CK_BBOOL length_only,
                                       CK_BYTE **data,
                                       CK_ULONG *data_len,
                                       const CK_BYTE *oid, CK_ULONG oid_len,
                                       CK_ATTRIBUTE *rho,
                                       CK_ATTRIBUTE *seed,
                                       CK_ATTRIBUTE *tr,
                                       CK_ATTRIBUTE *s1,
                                       CK_ATTRIBUTE *s2,
                                       CK_ATTRIBUTE *t0,
                                       CK_ATTRIBUTE *t1,
                                       CK_ATTRIBUTE *priv_seed);

CK_RV ber_decode_IBM_ML_DSA_PrivateKey(CK_MECHANISM_TYPE mech,
                                       CK_BYTE *data,
                                       CK_ULONG data_len,
                                       CK_ATTRIBUTE **rho,
                                       CK_ATTRIBUTE **seed,
                                       CK_ATTRIBUTE **tr,
                                       CK_ATTRIBUTE **s1,
                                       CK_ATTRIBUTE **s2,
                                       CK_ATTRIBUTE **t0,
                                       CK_ATTRIBUTE **t1,
                                       CK_ATTRIBUTE **priv_seed,
                                       CK_ATTRIBUTE **value,
                                       const struct pqc_oid **oid);

/* ML-KEM key encoding/decoding function prototypes */
CK_RV ber_encode_IBM_ML_KEM_PublicKey(CK_MECHANISM_TYPE mech,
                                      CK_BBOOL length_only,
                                      CK_BYTE **data, CK_ULONG *data_len,
                                      const CK_BYTE *oid, CK_ULONG oid_len,
                                      CK_ATTRIBUTE *pk);

CK_RV ber_decode_IBM_ML_KEM_PublicKey(CK_MECHANISM_TYPE mech,
                                      CK_BYTE *data,
                                      CK_ULONG data_len,
                                      CK_ATTRIBUTE **pk_attr,
                                      CK_ATTRIBUTE **value_attr,
                                      const struct pqc_oid **oid);

CK_RV ber_encode_IBM_ML_KEM_PrivateKey(CK_MECHANISM_TYPE mech,
                                       CK_BBOOL length_only,
                                       CK_BYTE **data,
                                       CK_ULONG *data_len,
                                       const CK_BYTE *oid, CK_ULONG oid_len,
                                       CK_ATTRIBUTE *sk,
                                       CK_ATTRIBUTE *pk,
                                       CK_ATTRIBUTE *priv_seed);

CK_RV ber_decode_IBM_ML_KEM_PrivateKey(CK_MECHANISM_TYPE mech,
                                       CK_BYTE *data,
                                       CK_ULONG data_len,
                                       CK_ATTRIBUTE **sk,
                                       CK_ATTRIBUTE **pk,
                                       CK_ATTRIBUTE **priv_seed,
                                       CK_ATTRIBUTE **value,
                                       const struct pqc_oid **oid);


/* Helper function to free attributes */
static void free_attributes(CK_ATTRIBUTE **attrs, int count)
{
    for (int i = 0; i < count; i++) {
        if (attrs[i])
            free(attrs[i]);
    }
}


/* ============================================================================
 * RSA Private Key Tests
 * ============================================================================ */

/* Test ber_encode_RSAPrivateKey with basic RSA key components */
int test_encode_rsa_private_key_basic(void)
{
    /* Small RSA key components for testing - no leading zeros to avoid BER padding issues */
    CK_BYTE modulus_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A};
    CK_BYTE pub_exp_data[] = {0x01, 0x00, 0x01};  /* 65537 */
    CK_BYTE priv_exp_data[] = {0x5A, 0x3B, 0x7C, 0x8D, 0x9E, 0x2F, 0x1A, 0x0B};
    CK_BYTE prime1_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F};
    CK_BYTE prime2_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A};
    CK_BYTE exp1_data[] = {0x7B, 0x4C, 0x8D, 0x9E};
    CK_BYTE exp2_data[] = {0x6A, 0x3B, 0x7C, 0x8D};
    CK_BYTE coeff_data[] = {0x5C, 0x2D, 0x9E, 0x7F};

    CK_ATTRIBUTE *modulus = NULL, *pub_exp = NULL, *priv_exp = NULL;
    CK_ATTRIBUTE *prime1 = NULL, *prime2 = NULL, *exp1 = NULL, *exp2 = NULL, *coeff = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Create attributes */
    modulus = create_attribute(CKA_MODULUS, modulus_data, sizeof(modulus_data));
    pub_exp = create_attribute(CKA_PUBLIC_EXPONENT, pub_exp_data, sizeof(pub_exp_data));
    priv_exp = create_attribute(CKA_PRIVATE_EXPONENT, priv_exp_data, sizeof(priv_exp_data));
    prime1 = create_attribute(CKA_PRIME_1, prime1_data, sizeof(prime1_data));
    prime2 = create_attribute(CKA_PRIME_2, prime2_data, sizeof(prime2_data));
    exp1 = create_attribute(CKA_EXPONENT_1, exp1_data, sizeof(exp1_data));
    exp2 = create_attribute(CKA_EXPONENT_2, exp2_data, sizeof(exp2_data));
    coeff = create_attribute(CKA_COEFFICIENT, coeff_data, sizeof(coeff_data));

    if (!modulus || !pub_exp || !priv_exp || !prime1 || !prime2 || !exp1 || !exp2 || !coeff) {
        fprintf(stderr, "[FAIL] test_encode_rsa_private_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_RSAPrivateKey(FALSE, &encoded, &encoded_len, modulus, pub_exp,
                                  priv_exp, prime1, prime2, exp1, exp2, coeff);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_rsa_private_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify we got some encoded data */
    if (encoded == NULL || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_rsa_private_key_basic: no encoded data\n");
        result = 1;
        goto cleanup;
    }

    /* Basic sanity check: should start with SEQUENCE tag (0x30) for PrivateKeyInfo */
    if (encoded[0] != 0x30) {
        fprintf(stderr, "[FAIL] test_encode_rsa_private_key_basic: invalid tag (expected 0x30, got 0x%02X)\n",
                encoded[0]);
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_rsa_private_key_basic\n");

cleanup:
    {
        CK_ATTRIBUTE *attrs[] = {modulus, pub_exp, priv_exp, prime1, prime2, exp1, exp2, coeff};
        free_attributes(attrs, 8);
    }
    if (encoded)
        free(encoded);
    return result;
}

/* Test ber_encode_RSAPrivateKey in length_only mode */
int test_encode_rsa_private_key_length_only(void)
{
    CK_BYTE modulus_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A};
    CK_BYTE pub_exp_data[] = {0x01, 0x00, 0x01};
    CK_BYTE priv_exp_data[] = {0x5A, 0x3B, 0x7C, 0x8D, 0x9E, 0x2F, 0x1A, 0x0B};
    CK_BYTE prime1_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F};
    CK_BYTE prime2_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A};
    CK_BYTE exp1_data[] = {0x7B, 0x4C, 0x8D, 0x9E};
    CK_BYTE exp2_data[] = {0x6A, 0x3B, 0x7C, 0x8D};
    CK_BYTE coeff_data[] = {0x5C, 0x2D, 0x9E, 0x7F};

    CK_ATTRIBUTE *modulus = NULL, *pub_exp = NULL, *priv_exp = NULL;
    CK_ATTRIBUTE *prime1 = NULL, *prime2 = NULL, *exp1 = NULL, *exp2 = NULL, *coeff = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    modulus = create_attribute(CKA_MODULUS, modulus_data, sizeof(modulus_data));
    pub_exp = create_attribute(CKA_PUBLIC_EXPONENT, pub_exp_data, sizeof(pub_exp_data));
    priv_exp = create_attribute(CKA_PRIVATE_EXPONENT, priv_exp_data, sizeof(priv_exp_data));
    prime1 = create_attribute(CKA_PRIME_1, prime1_data, sizeof(prime1_data));
    prime2 = create_attribute(CKA_PRIME_2, prime2_data, sizeof(prime2_data));
    exp1 = create_attribute(CKA_EXPONENT_1, exp1_data, sizeof(exp1_data));
    exp2 = create_attribute(CKA_EXPONENT_2, exp2_data, sizeof(exp2_data));
    coeff = create_attribute(CKA_COEFFICIENT, coeff_data, sizeof(coeff_data));

    if (!modulus || !pub_exp || !priv_exp || !prime1 || !prime2 || !exp1 || !exp2 || !coeff) {
        fprintf(stderr, "[FAIL] test_encode_rsa_private_key_length_only: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_RSAPrivateKey(TRUE, &encoded, &encoded_len, modulus, pub_exp,
                                  priv_exp, prime1, prime2, exp1, exp2, coeff);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_rsa_private_key_length_only: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* In length_only mode, encoded should be NULL but length should be set */
    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_rsa_private_key_length_only: encoded should be NULL\n");
        result = 1;
        goto cleanup;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_rsa_private_key_length_only: length should be non-zero\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_rsa_private_key_length_only\n");

cleanup:
    {
        CK_ATTRIBUTE *attrs[] = {modulus, pub_exp, priv_exp, prime1, prime2, exp1, exp2, coeff};
        free_attributes(attrs, 8);
    }
    return result;
}

/* Test ber_decode_RSAPrivateKey with valid encoded data */
int test_decode_rsa_private_key_valid(void)
{
    CK_BYTE modulus_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A};
    CK_BYTE pub_exp_data[] = {0x01, 0x00, 0x01};
    CK_BYTE priv_exp_data[] = {0x5A, 0x3B, 0x7C, 0x8D, 0x9E, 0x2F, 0x1A, 0x0B};
    CK_BYTE prime1_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F};
    CK_BYTE prime2_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A};
    CK_BYTE exp1_data[] = {0x7B, 0x4C, 0x8D, 0x9E};
    CK_BYTE exp2_data[] = {0x6A, 0x3B, 0x7C, 0x8D};
    CK_BYTE coeff_data[] = {0x5C, 0x2D, 0x9E, 0x7F};

    CK_ATTRIBUTE *enc_modulus = NULL, *enc_pub_exp = NULL, *enc_priv_exp = NULL;
    CK_ATTRIBUTE *enc_prime1 = NULL, *enc_prime2 = NULL, *enc_exp1 = NULL;
    CK_ATTRIBUTE *enc_exp2 = NULL, *enc_coeff = NULL;
    CK_ATTRIBUTE *dec_modulus = NULL, *dec_pub_exp = NULL, *dec_priv_exp = NULL;
    CK_ATTRIBUTE *dec_prime1 = NULL, *dec_prime2 = NULL, *dec_exp1 = NULL;
    CK_ATTRIBUTE *dec_exp2 = NULL, *dec_coeff = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* First encode */
    enc_modulus = create_attribute(CKA_MODULUS, modulus_data, sizeof(modulus_data));
    enc_pub_exp = create_attribute(CKA_PUBLIC_EXPONENT, pub_exp_data, sizeof(pub_exp_data));
    enc_priv_exp = create_attribute(CKA_PRIVATE_EXPONENT, priv_exp_data, sizeof(priv_exp_data));
    enc_prime1 = create_attribute(CKA_PRIME_1, prime1_data, sizeof(prime1_data));
    enc_prime2 = create_attribute(CKA_PRIME_2, prime2_data, sizeof(prime2_data));
    enc_exp1 = create_attribute(CKA_EXPONENT_1, exp1_data, sizeof(exp1_data));
    enc_exp2 = create_attribute(CKA_EXPONENT_2, exp2_data, sizeof(exp2_data));
    enc_coeff = create_attribute(CKA_COEFFICIENT, coeff_data, sizeof(coeff_data));

    if (!enc_modulus || !enc_pub_exp || !enc_priv_exp || !enc_prime1 ||
        !enc_prime2 || !enc_exp1 || !enc_exp2 || !enc_coeff) {
        fprintf(stderr, "[FAIL] test_decode_rsa_private_key_valid: failed to create encode attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_RSAPrivateKey(FALSE, &encoded, &encoded_len, enc_modulus, enc_pub_exp,
                                  enc_priv_exp, enc_prime1, enc_prime2, enc_exp1, enc_exp2, enc_coeff);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_rsa_private_key_valid: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_RSAPrivateKey(encoded, encoded_len, &dec_modulus, &dec_pub_exp,
                                  &dec_priv_exp, &dec_prime1, &dec_prime2,
                                  &dec_exp1, &dec_exp2, &dec_coeff);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_rsa_private_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify all components were decoded */
    if (!dec_modulus || !dec_pub_exp || !dec_priv_exp || !dec_prime1 ||
        !dec_prime2 || !dec_exp1 || !dec_exp2 || !dec_coeff) {
        fprintf(stderr, "[FAIL] test_decode_rsa_private_key_valid: missing decoded attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Verify modulus matches */
    if (dec_modulus->ulValueLen != sizeof(modulus_data) ||
        memcmp(dec_modulus->pValue, modulus_data, sizeof(modulus_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_rsa_private_key_valid: modulus mismatch\n");
        result = 1;
        goto cleanup;
    }

    /* Verify public exponent matches */
    if (dec_pub_exp->ulValueLen != sizeof(pub_exp_data) ||
        memcmp(dec_pub_exp->pValue, pub_exp_data, sizeof(pub_exp_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_rsa_private_key_valid: public exponent mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_rsa_private_key_valid\n");

cleanup:
    {
        CK_ATTRIBUTE *enc_attrs[] = {enc_modulus, enc_pub_exp, enc_priv_exp, enc_prime1,
                                      enc_prime2, enc_exp1, enc_exp2, enc_coeff};
        CK_ATTRIBUTE *dec_attrs[] = {dec_modulus, dec_pub_exp, dec_priv_exp, dec_prime1,
                                      dec_prime2, dec_exp1, dec_exp2, dec_coeff};
        free_attributes(enc_attrs, 8);
        free_attributes(dec_attrs, 8);
    }
    if (encoded)
        free(encoded);
    return result;
}

/* Test ber_decode_RSAPrivateKey with invalid algorithm identifier */
int test_decode_rsa_private_key_invalid_alg(void)
{
    /* Create a PrivateKeyInfo with wrong algorithm OID (using DSA OID instead of RSA) */
    CK_BYTE invalid_data[] = {
        0x30, 0x20,  /* SEQUENCE */
        0x02, 0x01, 0x00,  /* version = 0 */
        0x30, 0x09,  /* AlgorithmIdentifier SEQUENCE */
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01,  /* DSA OID */
        0x04, 0x10,  /* OCTET STRING (private key) */
        0x30, 0x0E,  /* SEQUENCE */
        0x02, 0x01, 0x00,  /* version */
        0x02, 0x03, 0x01, 0x00, 0x01,  /* some integer */
        0x02, 0x04, 0x01, 0x02, 0x03, 0x04  /* another integer */
    };

    CK_ATTRIBUTE *modulus = NULL, *pub_exp = NULL, *priv_exp = NULL;
    CK_ATTRIBUTE *prime1 = NULL, *prime2 = NULL, *exp1 = NULL, *exp2 = NULL, *coeff = NULL;
    CK_RV rv;

    rv = ber_decode_RSAPrivateKey(invalid_data, sizeof(invalid_data), &modulus, &pub_exp,
                                  &priv_exp, &prime1, &prime2, &exp1, &exp2, &coeff);

    /* Should fail with wrong algorithm */
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_rsa_private_key_invalid_alg: should have failed with invalid algorithm\n");
        CK_ATTRIBUTE *attrs[] = {modulus, pub_exp, priv_exp, prime1, prime2, exp1, exp2, coeff};
        free_attributes(attrs, 8);
        return 1;
    }

    printf("[PASS] test_decode_rsa_private_key_invalid_alg\n");
    return 0;
}

/* Test round-trip encoding and decoding of RSA private key */
int test_roundtrip_rsa_private_key(void)
{
    CK_BYTE modulus_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A, 0x55, 0x66};
    CK_BYTE pub_exp_data[] = {0x01, 0x00, 0x01};
    CK_BYTE priv_exp_data[] = {0x5A, 0x3B, 0x7C, 0x8D, 0x9E, 0x2F, 0x1A, 0x0B, 0x77, 0x11};
    CK_BYTE prime1_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F, 0x22};
    CK_BYTE prime2_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A, 0x33};
    CK_BYTE exp1_data[] = {0x7B, 0x4C, 0x8D, 0x9E, 0x11};
    CK_BYTE exp2_data[] = {0x6A, 0x3B, 0x7C, 0x8D, 0x22};
    CK_BYTE coeff_data[] = {0x5C, 0x2D, 0x9E, 0x7F, 0x33};

    CK_ATTRIBUTE *orig_modulus = NULL, *orig_pub_exp = NULL, *orig_priv_exp = NULL;
    CK_ATTRIBUTE *orig_prime1 = NULL, *orig_prime2 = NULL, *orig_exp1 = NULL;
    CK_ATTRIBUTE *orig_exp2 = NULL, *orig_coeff = NULL;
    CK_ATTRIBUTE *dec_modulus = NULL, *dec_pub_exp = NULL, *dec_priv_exp = NULL;
    CK_ATTRIBUTE *dec_prime1 = NULL, *dec_prime2 = NULL, *dec_exp1 = NULL;
    CK_ATTRIBUTE *dec_exp2 = NULL, *dec_coeff = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Create original attributes */
    orig_modulus = create_attribute(CKA_MODULUS, modulus_data, sizeof(modulus_data));
    orig_pub_exp = create_attribute(CKA_PUBLIC_EXPONENT, pub_exp_data, sizeof(pub_exp_data));
    orig_priv_exp = create_attribute(CKA_PRIVATE_EXPONENT, priv_exp_data, sizeof(priv_exp_data));
    orig_prime1 = create_attribute(CKA_PRIME_1, prime1_data, sizeof(prime1_data));
    orig_prime2 = create_attribute(CKA_PRIME_2, prime2_data, sizeof(prime2_data));
    orig_exp1 = create_attribute(CKA_EXPONENT_1, exp1_data, sizeof(exp1_data));
    orig_exp2 = create_attribute(CKA_EXPONENT_2, exp2_data, sizeof(exp2_data));
    orig_coeff = create_attribute(CKA_COEFFICIENT, coeff_data, sizeof(coeff_data));

    if (!orig_modulus || !orig_pub_exp || !orig_priv_exp || !orig_prime1 ||
        !orig_prime2 || !orig_exp1 || !orig_exp2 || !orig_coeff) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_RSAPrivateKey(FALSE, &encoded, &encoded_len, orig_modulus, orig_pub_exp,
                                  orig_priv_exp, orig_prime1, orig_prime2, orig_exp1,
                                  orig_exp2, orig_coeff);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_RSAPrivateKey(encoded, encoded_len, &dec_modulus, &dec_pub_exp,
                                  &dec_priv_exp, &dec_prime1, &dec_prime2,
                                  &dec_exp1, &dec_exp2, &dec_coeff);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify all components match */
    if (dec_modulus->ulValueLen != sizeof(modulus_data) ||
        memcmp(dec_modulus->pValue, modulus_data, sizeof(modulus_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: modulus mismatch\n");
        result = 1;
    }

    if (dec_pub_exp->ulValueLen != sizeof(pub_exp_data) ||
        memcmp(dec_pub_exp->pValue, pub_exp_data, sizeof(pub_exp_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: public exponent mismatch\n");
        result = 1;
    }

    if (dec_priv_exp->ulValueLen != sizeof(priv_exp_data) ||
        memcmp(dec_priv_exp->pValue, priv_exp_data, sizeof(priv_exp_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: private exponent mismatch\n");
        result = 1;
    }

    if (dec_prime1->ulValueLen != sizeof(prime1_data) ||
        memcmp(dec_prime1->pValue, prime1_data, sizeof(prime1_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: prime1 mismatch\n");
        result = 1;
    }

    if (dec_prime2->ulValueLen != sizeof(prime2_data) ||
        memcmp(dec_prime2->pValue, prime2_data, sizeof(prime2_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: prime2 mismatch\n");
        result = 1;
    }

    if (dec_exp1->ulValueLen != sizeof(exp1_data) ||
        memcmp(dec_exp1->pValue, exp1_data, sizeof(exp1_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: exponent1 mismatch\n");
        result = 1;
    }

    if (dec_exp2->ulValueLen != sizeof(exp2_data) ||
        memcmp(dec_exp2->pValue, exp2_data, sizeof(exp2_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: exponent2 mismatch\n");
        result = 1;
    }

    if (dec_coeff->ulValueLen != sizeof(coeff_data) ||
        memcmp(dec_coeff->pValue, coeff_data, sizeof(coeff_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_private_key: coefficient mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_rsa_private_key\n");

cleanup:
    {
        CK_ATTRIBUTE *orig_attrs[] = {orig_modulus, orig_pub_exp, orig_priv_exp, orig_prime1,
                                       orig_prime2, orig_exp1, orig_exp2, orig_coeff};
        CK_ATTRIBUTE *dec_attrs[] = {dec_modulus, dec_pub_exp, dec_priv_exp, dec_prime1,
                                      dec_prime2, dec_exp1, dec_exp2, dec_coeff};
        free_attributes(orig_attrs, 8);
        free_attributes(dec_attrs, 8);
    }
    if (encoded)
        free(encoded);
    return result;
}

/* ============================================================================
 * RSA Public Key Tests
 * ============================================================================ */

/* Test ber_encode_RSAPublicKey with basic RSA public key components */
int test_encode_rsa_public_key_basic(void)
{
    CK_BYTE modulus_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A};
    CK_BYTE pub_exp_data[] = {0x01, 0x00, 0x01};  /* 65537 */

    CK_ATTRIBUTE *modulus = NULL, *pub_exp = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    modulus = create_attribute(CKA_MODULUS, modulus_data, sizeof(modulus_data));
    pub_exp = create_attribute(CKA_PUBLIC_EXPONENT, pub_exp_data, sizeof(pub_exp_data));

    if (!modulus || !pub_exp) {
        fprintf(stderr, "[FAIL] test_encode_rsa_public_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_RSAPublicKey(FALSE, &encoded, &encoded_len, modulus, pub_exp);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_rsa_public_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify we got some encoded data */
    if (encoded == NULL || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_rsa_public_key_basic: no encoded data\n");
        result = 1;
        goto cleanup;
    }

    /* Basic sanity check: should start with SEQUENCE tag (0x30) for SubjectPublicKeyInfo */
    if (encoded[0] != 0x30) {
        fprintf(stderr, "[FAIL] test_encode_rsa_public_key_basic: invalid tag (expected 0x30, got 0x%02X)\n",
                encoded[0]);
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_rsa_public_key_basic\n");

cleanup:
    if (modulus)
        free(modulus);
    if (pub_exp)
        free(pub_exp);
    if (encoded)
        free(encoded);
    return result;
}

/* Test ber_decode_RSAPublicKey with valid encoded data */
int test_decode_rsa_public_key_valid(void)
{
    CK_BYTE modulus_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A};
    CK_BYTE pub_exp_data[] = {0x01, 0x00, 0x01};

    CK_ATTRIBUTE *enc_modulus = NULL, *enc_pub_exp = NULL;
    CK_ATTRIBUTE *dec_modulus = NULL, *dec_pub_exp = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* First encode */
    enc_modulus = create_attribute(CKA_MODULUS, modulus_data, sizeof(modulus_data));
    enc_pub_exp = create_attribute(CKA_PUBLIC_EXPONENT, pub_exp_data, sizeof(pub_exp_data));

    if (!enc_modulus || !enc_pub_exp) {
        fprintf(stderr, "[FAIL] test_decode_rsa_public_key_valid: failed to create encode attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_RSAPublicKey(FALSE, &encoded, &encoded_len, enc_modulus, enc_pub_exp);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_rsa_public_key_valid: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_RSAPublicKey(encoded, encoded_len, &dec_modulus, &dec_pub_exp);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_rsa_public_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify components were decoded */
    if (!dec_modulus || !dec_pub_exp) {
        fprintf(stderr, "[FAIL] test_decode_rsa_public_key_valid: missing decoded attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Verify modulus matches */
    if (dec_modulus->ulValueLen != sizeof(modulus_data) ||
        memcmp(dec_modulus->pValue, modulus_data, sizeof(modulus_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_rsa_public_key_valid: modulus mismatch\n");
        result = 1;
        goto cleanup;
    }

    /* Verify public exponent matches */
    if (dec_pub_exp->ulValueLen != sizeof(pub_exp_data) ||
        memcmp(dec_pub_exp->pValue, pub_exp_data, sizeof(pub_exp_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_rsa_public_key_valid: public exponent mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_rsa_public_key_valid\n");

cleanup:
    if (enc_modulus)
        free(enc_modulus);
    if (enc_pub_exp)
        free(enc_pub_exp);
    if (dec_modulus)
        free(dec_modulus);
    if (dec_pub_exp)
        free(dec_pub_exp);
    if (encoded)
        free(encoded);
    return result;
}

/* Test ber_decode_RSAPublicKey with invalid algorithm identifier */
int test_decode_rsa_public_key_invalid_alg(void)
{
    /* Create a SubjectPublicKeyInfo with wrong algorithm OID (using DSA OID instead of RSA) */
    CK_BYTE invalid_data[] = {
        0x30, 0x1E,  /* SEQUENCE */
        0x30, 0x09,  /* AlgorithmIdentifier SEQUENCE */
        0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x01,  /* DSA OID */
        0x03, 0x11,  /* BIT STRING */
        0x00,  /* unused bits */
        0x30, 0x0C,  /* SEQUENCE */
        0x02, 0x05, 0x00, 0xC5, 0x3A, 0x7F, 0x8E,  /* modulus */
        0x02, 0x03, 0x01, 0x00, 0x01  /* exponent */
    };

    CK_ATTRIBUTE *modulus = NULL, *pub_exp = NULL;
    CK_RV rv;

    rv = ber_decode_RSAPublicKey(invalid_data, sizeof(invalid_data), &modulus, &pub_exp);

    /* Should fail with wrong algorithm */
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_rsa_public_key_invalid_alg: should have failed with invalid algorithm\n");
        if (modulus)
            free(modulus);
        if (pub_exp)
            free(pub_exp);
        return 1;
    }

    printf("[PASS] test_decode_rsa_public_key_invalid_alg\n");
    return 0;
}

/* Test round-trip encoding and decoding of RSA public key */
int test_roundtrip_rsa_public_key(void)
{
    CK_BYTE modulus_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A, 0x55, 0x66, 0x77};
    CK_BYTE pub_exp_data[] = {0x01, 0x00, 0x01};

    CK_ATTRIBUTE *orig_modulus = NULL, *orig_pub_exp = NULL;
    CK_ATTRIBUTE *dec_modulus = NULL, *dec_pub_exp = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Create original attributes */
    orig_modulus = create_attribute(CKA_MODULUS, modulus_data, sizeof(modulus_data));
    orig_pub_exp = create_attribute(CKA_PUBLIC_EXPONENT, pub_exp_data, sizeof(pub_exp_data));

    if (!orig_modulus || !orig_pub_exp) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_public_key: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_RSAPublicKey(FALSE, &encoded, &encoded_len, orig_modulus, orig_pub_exp);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_public_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_RSAPublicKey(encoded, encoded_len, &dec_modulus, &dec_pub_exp);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_public_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify components match */
    if (dec_modulus->ulValueLen != sizeof(modulus_data) ||
        memcmp(dec_modulus->pValue, modulus_data, sizeof(modulus_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_public_key: modulus mismatch\n");
        result = 1;
    }

    if (dec_pub_exp->ulValueLen != sizeof(pub_exp_data) ||
        memcmp(dec_pub_exp->pValue, pub_exp_data, sizeof(pub_exp_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_rsa_public_key: public exponent mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_rsa_public_key\n");

cleanup:
    if (orig_modulus)
        free(orig_modulus);
    if (orig_pub_exp)
        free(orig_pub_exp);
    if (dec_modulus)
        free(dec_modulus);
    if (dec_pub_exp)
        free(dec_pub_exp);
    if (encoded)
        free(encoded);

    return result;
}

/* ============================================================================
 * DSA Private Key Tests
 * ============================================================================ */

/* Test ber_encode_DSAPrivateKey with basic DSA key components */
int test_encode_dsa_private_key_basic(void)
{
    /* DSA key components for testing - no leading zeros */
    CK_BYTE prime_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A};
    CK_BYTE subprime_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A};
    CK_BYTE base_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F};
    CK_BYTE priv_key_data[] = {0x5A, 0x3B, 0x7C, 0x8D};

    CK_ATTRIBUTE *prime = NULL, *subprime = NULL, *base = NULL, *priv_key = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Create attributes */
    prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    subprime = create_attribute(CKA_SUBPRIME, subprime_data, sizeof(subprime_data));
    base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    priv_key = create_attribute(CKA_VALUE, priv_key_data, sizeof(priv_key_data));

    if (!prime || !subprime || !base || !priv_key) {
        fprintf(stderr, "[FAIL] test_encode_dsa_private_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_DSAPrivateKey(FALSE, &encoded, &encoded_len, prime, subprime, base, priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_dsa_private_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify we got some encoded data */
    if (encoded == NULL || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_dsa_private_key_basic: no encoded data\n");
        result = 1;
        goto cleanup;
    }

    /* Basic sanity check: should start with SEQUENCE tag (0x30) for PrivateKeyInfo */
    if (encoded[0] != 0x30) {
        fprintf(stderr, "[FAIL] test_encode_dsa_private_key_basic: invalid tag (expected 0x30, got 0x%02X)\n",
                encoded[0]);
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_dsa_private_key_basic\n");

cleanup:
    if (prime)
        free(prime);
    if (subprime)
        free(subprime);
    if (base)
        free(base);
    if (priv_key)
        free(priv_key);
    if (encoded)
        free(encoded);
    return result;
}

/* Test ber_encode_DSAPrivateKey in length_only mode */
int test_encode_dsa_private_key_length_only(void)
{
    CK_BYTE prime_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A};
    CK_BYTE subprime_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A};
    CK_BYTE base_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F};
    CK_BYTE priv_key_data[] = {0x5A, 0x3B, 0x7C, 0x8D};

    CK_ATTRIBUTE *prime = NULL, *subprime = NULL, *base = NULL, *priv_key = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    subprime = create_attribute(CKA_SUBPRIME, subprime_data, sizeof(subprime_data));
    base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    priv_key = create_attribute(CKA_VALUE, priv_key_data, sizeof(priv_key_data));

    if (!prime || !subprime || !base || !priv_key) {
        fprintf(stderr, "[FAIL] test_encode_dsa_private_key_length_only: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_DSAPrivateKey(TRUE, &encoded, &encoded_len, prime, subprime, base, priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_dsa_private_key_length_only: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* In length_only mode, encoded should be NULL but length should be set */
    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_dsa_private_key_length_only: encoded should be NULL\n");
        result = 1;
        goto cleanup;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_dsa_private_key_length_only: length should be non-zero\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_dsa_private_key_length_only\n");

cleanup:
    if (prime)
        free(prime);
    if (subprime)
        free(subprime);
    if (base)
        free(base);
    if (priv_key)
        free(priv_key);
    return result;
}

/* Test ber_decode_DSAPrivateKey with valid encoded data */
int test_decode_dsa_private_key_valid(void)
{
    CK_BYTE prime_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A};
    CK_BYTE subprime_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A};
    CK_BYTE base_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F};
    CK_BYTE priv_key_data[] = {0x5A, 0x3B, 0x7C, 0x8D};

    CK_ATTRIBUTE *enc_prime = NULL, *enc_subprime = NULL, *enc_base = NULL, *enc_priv_key = NULL;
    CK_ATTRIBUTE *dec_prime = NULL, *dec_subprime = NULL, *dec_base = NULL, *dec_priv_key = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* First encode */
    enc_prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    enc_subprime = create_attribute(CKA_SUBPRIME, subprime_data, sizeof(subprime_data));
    enc_base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    enc_priv_key = create_attribute(CKA_VALUE, priv_key_data, sizeof(priv_key_data));

    if (!enc_prime || !enc_subprime || !enc_base || !enc_priv_key) {
        fprintf(stderr, "[FAIL] test_decode_dsa_private_key_valid: failed to create encode attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_DSAPrivateKey(FALSE, &encoded, &encoded_len, enc_prime, enc_subprime, enc_base, enc_priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_dsa_private_key_valid: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_DSAPrivateKey(encoded, encoded_len, &dec_prime, &dec_subprime, &dec_base, &dec_priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_dsa_private_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify all components were decoded */
    if (!dec_prime || !dec_subprime || !dec_base || !dec_priv_key) {
        fprintf(stderr, "[FAIL] test_decode_dsa_private_key_valid: missing decoded attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Verify prime matches */
    if (dec_prime->ulValueLen != sizeof(prime_data) ||
        memcmp(dec_prime->pValue, prime_data, sizeof(prime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_dsa_private_key_valid: prime mismatch\n");
        result = 1;
        goto cleanup;
    }

    /* Verify subprime matches */
    if (dec_subprime->ulValueLen != sizeof(subprime_data) ||
        memcmp(dec_subprime->pValue, subprime_data, sizeof(subprime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_dsa_private_key_valid: subprime mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_dsa_private_key_valid\n");

cleanup:
    if (enc_prime)
        free(enc_prime);
    if (enc_subprime)
        free(enc_subprime);
    if (enc_base)
        free(enc_base);
    if (enc_priv_key)
        free(enc_priv_key);
    if (dec_prime)
        free(dec_prime);
    if (dec_subprime)
        free(dec_subprime);
    if (dec_base)
        free(dec_base);
    if (dec_priv_key)
        free(dec_priv_key);
    if (encoded)
        free(encoded);
    return result;
}

/* Test round-trip encoding and decoding of DSA private key */
int test_roundtrip_dsa_private_key(void)
{
    CK_BYTE prime_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A, 0x55};
    CK_BYTE subprime_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A, 0x66};
    CK_BYTE base_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F, 0x77};
    CK_BYTE priv_key_data[] = {0x5A, 0x3B, 0x7C, 0x8D, 0x88};

    CK_ATTRIBUTE *orig_prime = NULL, *orig_subprime = NULL, *orig_base = NULL, *orig_priv_key = NULL;
    CK_ATTRIBUTE *dec_prime = NULL, *dec_subprime = NULL, *dec_base = NULL, *dec_priv_key = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Create original attributes */
    orig_prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    orig_subprime = create_attribute(CKA_SUBPRIME, subprime_data, sizeof(subprime_data));
    orig_base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    orig_priv_key = create_attribute(CKA_VALUE, priv_key_data, sizeof(priv_key_data));

    if (!orig_prime || !orig_subprime || !orig_base || !orig_priv_key) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_private_key: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_DSAPrivateKey(FALSE, &encoded, &encoded_len, orig_prime, orig_subprime, orig_base, orig_priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_private_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_DSAPrivateKey(encoded, encoded_len, &dec_prime, &dec_subprime, &dec_base, &dec_priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_private_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify all components match */
    if (dec_prime->ulValueLen != sizeof(prime_data) ||
        memcmp(dec_prime->pValue, prime_data, sizeof(prime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_private_key: prime mismatch\n");
        result = 1;
    }

    if (dec_subprime->ulValueLen != sizeof(subprime_data) ||
        memcmp(dec_subprime->pValue, subprime_data, sizeof(subprime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_private_key: subprime mismatch\n");
        result = 1;
    }

    if (dec_base->ulValueLen != sizeof(base_data) ||
        memcmp(dec_base->pValue, base_data, sizeof(base_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_private_key: base mismatch\n");
        result = 1;
    }

    if (dec_priv_key->ulValueLen != sizeof(priv_key_data) ||
        memcmp(dec_priv_key->pValue, priv_key_data, sizeof(priv_key_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_private_key: private key mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_dsa_private_key\n");

cleanup:
    if (orig_prime)
        free(orig_prime);
    if (orig_subprime)
        free(orig_subprime);
    if (orig_base)
        free(orig_base);
    if (orig_priv_key)
        free(orig_priv_key);
    if (dec_prime)
        free(dec_prime);
    if (dec_subprime)
        free(dec_subprime);
    if (dec_base)
        free(dec_base);
    if (dec_priv_key)
        free(dec_priv_key);
    if (encoded)
        free(encoded);
    return result;
}

/* ============================================================================
 * DSA Public Key Tests
 * ============================================================================ */

/* Test ber_encode_DSAPublicKey with basic DSA public key components */
int test_encode_dsa_public_key_basic(void)
{
    CK_BYTE prime_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A};
    CK_BYTE subprime_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A};
    CK_BYTE base_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F};
    CK_BYTE value_data[] = {0x5A, 0x3B, 0x7C, 0x8D};

    CK_ATTRIBUTE *prime = NULL, *subprime = NULL, *base = NULL, *value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    subprime = create_attribute(CKA_SUBPRIME, subprime_data, sizeof(subprime_data));
    base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!prime || !subprime || !base || !value) {
        fprintf(stderr, "[FAIL] test_encode_dsa_public_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_DSAPublicKey(FALSE, &encoded, &encoded_len, prime, subprime, base, value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_dsa_public_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify we got some encoded data */
    if (encoded == NULL || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_dsa_public_key_basic: no encoded data\n");
        result = 1;
        goto cleanup;
    }

    /* Basic sanity check: should start with SEQUENCE tag (0x30) for SubjectPublicKeyInfo */
    if (encoded[0] != 0x30) {
        fprintf(stderr, "[FAIL] test_encode_dsa_public_key_basic: invalid tag (expected 0x30, got 0x%02X)\n",
                encoded[0]);
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_dsa_public_key_basic\n");

cleanup:
    if (prime)
        free(prime);
    if (subprime)
        free(subprime);
    if (base)
        free(base);
    if (value)
        free(value);
    if (encoded)
        free(encoded);
    return result;
}

/* Test ber_decode_DSAPublicKey with valid encoded data */
int test_decode_dsa_public_key_valid(void)
{
    CK_BYTE prime_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A};
    CK_BYTE subprime_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A};
    CK_BYTE base_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F};
    CK_BYTE value_data[] = {0x5A, 0x3B, 0x7C, 0x8D};

    CK_ATTRIBUTE *enc_prime = NULL, *enc_subprime = NULL, *enc_base = NULL, *enc_value = NULL;
    CK_ATTRIBUTE *dec_prime = NULL, *dec_subprime = NULL, *dec_base = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* First encode */
    enc_prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    enc_subprime = create_attribute(CKA_SUBPRIME, subprime_data, sizeof(subprime_data));
    enc_base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    enc_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!enc_prime || !enc_subprime || !enc_base || !enc_value) {
        fprintf(stderr, "[FAIL] test_decode_dsa_public_key_valid: failed to create encode attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_DSAPublicKey(FALSE, &encoded, &encoded_len, enc_prime, enc_subprime, enc_base, enc_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_dsa_public_key_valid: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_DSAPublicKey(encoded, encoded_len, &dec_prime, &dec_subprime, &dec_base, &dec_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_dsa_public_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify components were decoded */
    if (!dec_prime || !dec_subprime || !dec_base || !dec_value) {
        fprintf(stderr, "[FAIL] test_decode_dsa_public_key_valid: missing decoded attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Verify prime matches */
    if (dec_prime->ulValueLen != sizeof(prime_data) ||
        memcmp(dec_prime->pValue, prime_data, sizeof(prime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_dsa_public_key_valid: prime mismatch\n");
        result = 1;
        goto cleanup;
    }

    /* Verify subprime matches */
    if (dec_subprime->ulValueLen != sizeof(subprime_data) ||
        memcmp(dec_subprime->pValue, subprime_data, sizeof(subprime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_dsa_public_key_valid: subprime mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_dsa_public_key_valid\n");

cleanup:
    if (enc_prime)
        free(enc_prime);
    if (enc_subprime)
        free(enc_subprime);
    if (enc_base)
        free(enc_base);
    if (enc_value)
        free(enc_value);
    if (dec_prime)
        free(dec_prime);
    if (dec_subprime)
        free(dec_subprime);
    if (dec_base)
        free(dec_base);
    if (dec_value)
        free(dec_value);
    if (encoded)
        free(encoded);
    return result;
}

/* Test round-trip encoding and decoding of DSA public key */
int test_roundtrip_dsa_public_key(void)
{
    CK_BYTE prime_data[] = {0xC5, 0x3A, 0x7F, 0x8E, 0x9B, 0x2C, 0x1D, 0x0A, 0x55};
    CK_BYTE subprime_data[] = {0xD9, 0x8C, 0x4E, 0x6F, 0x2A, 0x66};
    CK_BYTE base_data[] = {0xE7, 0x9A, 0x3B, 0x5C, 0x1F, 0x77};
    CK_BYTE value_data[] = {0x5A, 0x3B, 0x7C, 0x8D, 0x88};

    CK_ATTRIBUTE *orig_prime = NULL, *orig_subprime = NULL, *orig_base = NULL, *orig_value = NULL;
    CK_ATTRIBUTE *dec_prime = NULL, *dec_subprime = NULL, *dec_base = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Create original attributes */
    orig_prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    orig_subprime = create_attribute(CKA_SUBPRIME, subprime_data, sizeof(subprime_data));
    orig_base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_prime || !orig_subprime || !orig_base || !orig_value) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_public_key: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_DSAPublicKey(FALSE, &encoded, &encoded_len, orig_prime, orig_subprime, orig_base, orig_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_public_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_DSAPublicKey(encoded, encoded_len, &dec_prime, &dec_subprime, &dec_base, &dec_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_public_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify components match */
    if (dec_prime->ulValueLen != sizeof(prime_data) ||
        memcmp(dec_prime->pValue, prime_data, sizeof(prime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_public_key: prime mismatch\n");
        result = 1;
    }

    if (dec_subprime->ulValueLen != sizeof(subprime_data) ||
        memcmp(dec_subprime->pValue, subprime_data, sizeof(subprime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_public_key: subprime mismatch\n");
        result = 1;
    }

    if (dec_base->ulValueLen != sizeof(base_data) ||
        memcmp(dec_base->pValue, base_data, sizeof(base_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_public_key: base mismatch\n");
        result = 1;
    }

    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dsa_public_key: value mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_dsa_public_key\n");

cleanup:
    if (orig_prime)
        free(orig_prime);
    if (orig_subprime)
        free(orig_subprime);
    if (orig_base)
        free(orig_base);
    if (orig_value)
        free(orig_value);
    if (dec_prime)
        free(dec_prime);
    if (dec_subprime)
        free(dec_subprime);
    if (dec_base)
        free(dec_base);
    if (dec_value)
        free(dec_value);
    if (encoded)
        free(encoded);
    return result;
}

/* ========================================================================
 * DH Private Key Tests
 * ======================================================================== */

int test_encode_dh_private_key_basic(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *prime = NULL, *base = NULL, *priv_key = NULL;
    int result = 0;

    /* Test data - DH has 3 components: prime (p), base (g), private key (x) */
    CK_BYTE prime_data[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    CK_BYTE base_data[] = {
        0x11, 0x22, 0x33, 0x44
    };
    CK_BYTE priv_key_data[] = {
        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC
    };

    printf("Testing ber_encode_DHPrivateKey (basic)... ");

    /* Create attributes */
    prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    priv_key = create_attribute(CKA_VALUE, priv_key_data, sizeof(priv_key_data));

    if (!prime || !base || !priv_key) {
        fprintf(stderr, "[FAIL] test_encode_dh_private_key_basic: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_DHPrivateKey(FALSE, &encoded, &encoded_len, prime, base, priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_dh_private_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_dh_private_key_basic: No data encoded\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS]\n");

cleanup:
    if (prime)
        free(prime);
    if (base)
        free(base);
    if (priv_key)
        free(priv_key);
    if (encoded)
        free(encoded);
    return result;
}

int test_encode_dh_private_key_length_only(void)
{
    CK_RV rv;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *prime = NULL, *base = NULL, *priv_key = NULL;
    int result = 0;

    CK_BYTE prime_data[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    CK_BYTE base_data[] = {
        0x11, 0x22, 0x33, 0x44
    };
    CK_BYTE priv_key_data[] = {
        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC
    };

    printf("Testing ber_encode_DHPrivateKey (length only)... ");

    prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    priv_key = create_attribute(CKA_VALUE, priv_key_data, sizeof(priv_key_data));

    if (!prime || !base || !priv_key) {
        fprintf(stderr, "[FAIL] test_encode_dh_private_key_length_only: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Get length only */
    rv = ber_encode_DHPrivateKey(TRUE, NULL, &encoded_len, prime, base, priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_dh_private_key_length_only: length calculation failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_dh_private_key_length_only: Length is zero\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS]\n");

cleanup:
    if (prime)
        free(prime);
    if (base)
        free(base);
    if (priv_key)
        free(priv_key);
    return result;
}

int test_decode_dh_private_key_valid(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_prime = NULL, *orig_base = NULL, *orig_priv_key = NULL;
    CK_ATTRIBUTE *dec_prime = NULL, *dec_base = NULL, *dec_priv_key = NULL;
    int result = 0;

    CK_BYTE prime_data[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    CK_BYTE base_data[] = {
        0x11, 0x22, 0x33, 0x44
    };
    CK_BYTE priv_key_data[] = {
        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC
    };

    printf("Testing ber_decode_DHPrivateKey (valid)... ");

    /* Create and encode */
    orig_prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    orig_base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    orig_priv_key = create_attribute(CKA_VALUE, priv_key_data, sizeof(priv_key_data));

    if (!orig_prime || !orig_base || !orig_priv_key) {
        fprintf(stderr, "[FAIL] test_decode_dh_private_key_valid: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_DHPrivateKey(FALSE, &encoded, &encoded_len, orig_prime, orig_base, orig_priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_dh_private_key_valid: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_DHPrivateKey(encoded, encoded_len, &dec_prime, &dec_base, &dec_priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_dh_private_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify components */
    if (dec_prime->ulValueLen != sizeof(prime_data) ||
        memcmp(dec_prime->pValue, prime_data, sizeof(prime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_dh_private_key_valid: prime mismatch\n");
        result = 1;
    }

    if (dec_base->ulValueLen != sizeof(base_data) ||
        memcmp(dec_base->pValue, base_data, sizeof(base_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_dh_private_key_valid: base mismatch\n");
        result = 1;
    }

    if (dec_priv_key->ulValueLen != sizeof(priv_key_data) ||
        memcmp(dec_priv_key->pValue, priv_key_data, sizeof(priv_key_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_dh_private_key_valid: private key mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_prime)
        free(orig_prime);
    if (orig_base)
        free(orig_base);
    if (orig_priv_key)
        free(orig_priv_key);
    if (dec_prime)
        free(dec_prime);
    if (dec_base)
        free(dec_base);
    if (dec_priv_key)
        free(dec_priv_key);
    if (encoded)
        free(encoded);
    return result;
}

int test_roundtrip_dh_private_key(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_prime = NULL, *orig_base = NULL, *orig_priv_key = NULL;
    CK_ATTRIBUTE *dec_prime = NULL, *dec_base = NULL, *dec_priv_key = NULL;
    int result = 0;

    CK_BYTE prime_data[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    CK_BYTE base_data[] = {
        0x11, 0x22, 0x33, 0x44
    };
    CK_BYTE priv_key_data[] = {
        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC
    };

    printf("Testing DH private key roundtrip... ");

    /* Create attributes */
    orig_prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    orig_base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    orig_priv_key = create_attribute(CKA_VALUE, priv_key_data, sizeof(priv_key_data));

    if (!orig_prime || !orig_base || !orig_priv_key) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_private_key: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_DHPrivateKey(FALSE, &encoded, &encoded_len, orig_prime, orig_base, orig_priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_private_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_DHPrivateKey(encoded, encoded_len, &dec_prime, &dec_base, &dec_priv_key);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_private_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify all components match */
    if (dec_prime->ulValueLen != sizeof(prime_data) ||
        memcmp(dec_prime->pValue, prime_data, sizeof(prime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_private_key: prime mismatch\n");
        result = 1;
    }

    if (dec_base->ulValueLen != sizeof(base_data) ||
        memcmp(dec_base->pValue, base_data, sizeof(base_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_private_key: base mismatch\n");
        result = 1;
    }

    if (dec_priv_key->ulValueLen != sizeof(priv_key_data) ||
        memcmp(dec_priv_key->pValue, priv_key_data, sizeof(priv_key_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_private_key: private key mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_prime)
        free(orig_prime);
    if (orig_base)
        free(orig_base);
    if (orig_priv_key)
        free(orig_priv_key);
    if (dec_prime)
        free(dec_prime);
    if (dec_base)
        free(dec_base);
    if (dec_priv_key)
        free(dec_priv_key);
    if (encoded)
        free(encoded);
    return result;
}

/* ========================================================================
 * DH Public Key Tests
 * ======================================================================== */

int test_encode_dh_public_key_basic(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *prime = NULL, *base = NULL, *value = NULL;
    int result = 0;

    /* Test data - DH public key has 3 components: prime (p), base (g), public value (y) */
    CK_BYTE prime_data[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    CK_BYTE base_data[] = {
        0x11, 0x22, 0x33, 0x44
    };
    CK_BYTE value_data[] = {
        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC
    };

    printf("Testing ber_encode_DHPublicKey (basic)... ");

    /* Create attributes */
    prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!prime || !base || !value) {
        fprintf(stderr, "[FAIL] test_encode_dh_public_key_basic: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_DHPublicKey(FALSE, &encoded, &encoded_len, prime, base, value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_dh_public_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_dh_public_key_basic: No data encoded\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS]\n");

cleanup:
    if (prime)
        free(prime);
    if (base)
        free(base);
    if (value)
        free(value);
    if (encoded)
        free(encoded);
    return result;
}

int test_decode_dh_public_key_valid(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_prime = NULL, *orig_base = NULL, *orig_value = NULL;
    CK_ATTRIBUTE *dec_prime = NULL, *dec_base = NULL, *dec_value = NULL;
    int result = 0;

    CK_BYTE prime_data[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    CK_BYTE base_data[] = {
        0x11, 0x22, 0x33, 0x44
    };
    CK_BYTE value_data[] = {
        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC
    };

    printf("Testing ber_decode_DHPublicKey (valid)... ");

    /* Create and encode */
    orig_prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    orig_base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_prime || !orig_base || !orig_value) {
        fprintf(stderr, "[FAIL] test_decode_dh_public_key_valid: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_DHPublicKey(FALSE, &encoded, &encoded_len, orig_prime, orig_base, orig_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_dh_public_key_valid: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_DHPublicKey(encoded, encoded_len, &dec_prime, &dec_base, &dec_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_dh_public_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify components */
    if (dec_prime->ulValueLen != sizeof(prime_data) ||
        memcmp(dec_prime->pValue, prime_data, sizeof(prime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_dh_public_key_valid: prime mismatch\n");
        result = 1;
    }

    if (dec_base->ulValueLen != sizeof(base_data) ||
        memcmp(dec_base->pValue, base_data, sizeof(base_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_dh_public_key_valid: base mismatch\n");
        result = 1;
    }

    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_dh_public_key_valid: value mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_prime)
        free(orig_prime);
    if (orig_base)
        free(orig_base);
    if (orig_value)
        free(orig_value);
    if (dec_prime)
        free(dec_prime);
    if (dec_base)
        free(dec_base);
    if (dec_value)
        free(dec_value);
    if (encoded)
        free(encoded);
    return result;
}

int test_roundtrip_dh_public_key(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_prime = NULL, *orig_base = NULL, *orig_value = NULL;
    CK_ATTRIBUTE *dec_prime = NULL, *dec_base = NULL, *dec_value = NULL;
    int result = 0;

    CK_BYTE prime_data[] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10
    };
    CK_BYTE base_data[] = {
        0x11, 0x22, 0x33, 0x44
    };
    CK_BYTE value_data[] = {
        0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC
    };

    printf("Testing DH public key roundtrip... ");

    /* Create attributes */
    orig_prime = create_attribute(CKA_PRIME, prime_data, sizeof(prime_data));
    orig_base = create_attribute(CKA_BASE, base_data, sizeof(base_data));
    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_prime || !orig_base || !orig_value) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_public_key: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_DHPublicKey(FALSE, &encoded, &encoded_len, orig_prime, orig_base, orig_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_public_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_DHPublicKey(encoded, encoded_len, &dec_prime, &dec_base, &dec_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_public_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify all components match */
    if (dec_prime->ulValueLen != sizeof(prime_data) ||
        memcmp(dec_prime->pValue, prime_data, sizeof(prime_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_public_key: prime mismatch\n");
        result = 1;
    }

    if (dec_base->ulValueLen != sizeof(base_data) ||
        memcmp(dec_base->pValue, base_data, sizeof(base_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_public_key: base mismatch\n");
        result = 1;
    }

    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_dh_public_key: value mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_prime)
        free(orig_prime);
    if (orig_base)
        free(orig_base);
    if (orig_value)
        free(orig_value);
    if (dec_prime)
        free(dec_prime);
    if (dec_base)
        free(dec_base);
    if (dec_value)
        free(dec_value);
    if (encoded)
        free(encoded);
    return result;
}

/* ========================================================================
 * EC Private Key Tests (CKK_EC)
 * ======================================================================== */

int test_encode_ec_private_key_basic(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *privkey = NULL, *pubkey = NULL;
    int result = 0;

    /* EC params: prime256v1 curve OID */
    CK_BYTE params_data[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    /* Private key value (32 bytes for P-256) */
    CK_BYTE privkey_data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };
    /* Public key point (BER-encoded OCTET STRING containing uncompressed point) */
    CK_BYTE pubkey_data[] = {
        0x04, 0x41,  /* OCTET STRING, length 65 */
        0x04,  /* Uncompressed point indicator */
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48
    };

    printf("Testing der_encode_ECPrivateKey (basic)... ");

    params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    privkey = create_attribute(CKA_VALUE, privkey_data, sizeof(privkey_data));
    pubkey = create_attribute(CKA_EC_POINT, pubkey_data, sizeof(pubkey_data));

    if (!params || !privkey || !pubkey) {
        fprintf(stderr, "[FAIL] test_encode_ec_private_key_basic: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = der_encode_ECPrivateKey(FALSE, &encoded, &encoded_len, params, privkey, pubkey, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ec_private_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ec_private_key_basic: No data encoded\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS]\n");

cleanup:
    if (params) free(params);
    if (privkey) free(privkey);
    if (pubkey) free(pubkey);
    if (encoded) free(encoded);
    return result;
}

int test_encode_ec_private_key_length_only(void)
{
    CK_RV rv;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *privkey = NULL;
    int result = 0;

    CK_BYTE params_data[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    CK_BYTE privkey_data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };

    printf("Testing der_encode_ECPrivateKey (length only)... ");

    params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    privkey = create_attribute(CKA_VALUE, privkey_data, sizeof(privkey_data));

    if (!params || !privkey) {
        fprintf(stderr, "[FAIL] test_encode_ec_private_key_length_only: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = der_encode_ECPrivateKey(TRUE, NULL, &encoded_len, params, privkey, NULL, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ec_private_key_length_only: length calculation failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ec_private_key_length_only: Length is zero\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS]\n");

cleanup:
    if (params) free(params);
    if (privkey) free(privkey);
    return result;
}

int test_decode_ec_private_key_valid(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_params = NULL, *orig_privkey = NULL, *orig_pubkey = NULL;
    CK_ATTRIBUTE *dec_params = NULL, *dec_privkey = NULL, *dec_pubkey = NULL;
    int result = 0;

    CK_BYTE params_data[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    CK_BYTE privkey_data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };

    printf("Testing der_decode_ECPrivateKey (valid)... ");

    orig_params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    orig_privkey = create_attribute(CKA_VALUE, privkey_data, sizeof(privkey_data));

    if (!orig_params || !orig_privkey) {
        fprintf(stderr, "[FAIL] test_decode_ec_private_key_valid: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = der_encode_ECPrivateKey(FALSE, &encoded, &encoded_len, orig_params, orig_privkey, NULL, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ec_private_key_valid: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    rv = der_decode_ECPrivateKey(encoded, encoded_len, &dec_params, &dec_pubkey, &dec_privkey, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ec_private_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (dec_params->ulValueLen != sizeof(params_data) ||
        memcmp(dec_params->pValue, params_data, sizeof(params_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ec_private_key_valid: params mismatch (expected %lu bytes, got %lu bytes)\n",
                (unsigned long)sizeof(params_data), (unsigned long)dec_params->ulValueLen);
        if (dec_params->ulValueLen > 0 && dec_params->ulValueLen <= 20) {
            {
                CK_ULONG i;
                fprintf(stderr, "  Expected: ");
                for (i = 0; i < sizeof(params_data); i++)
                    fprintf(stderr, "%02X ", params_data[i]);
                fprintf(stderr, "\n  Got:      ");
                for (i = 0; i < dec_params->ulValueLen; i++)
                    fprintf(stderr, "%02X ", ((CK_BYTE*)dec_params->pValue)[i]);
                fprintf(stderr, "\n");
            }
        }
        result = 1;
    }

    if (dec_privkey->ulValueLen != sizeof(privkey_data) ||
        memcmp(dec_privkey->pValue, privkey_data, sizeof(privkey_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ec_private_key_valid: private key mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_params) free(orig_params);
    if (orig_privkey) free(orig_privkey);
    if (orig_pubkey) free(orig_pubkey);
    if (dec_params) free(dec_params);
    if (dec_privkey) free(dec_privkey);
    if (dec_pubkey) free(dec_pubkey);
    if (encoded) free(encoded);
    return result;
}

int test_roundtrip_ec_private_key(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_params = NULL, *orig_privkey = NULL;
    CK_ATTRIBUTE *dec_params = NULL, *dec_privkey = NULL, *dec_pubkey = NULL;
    int result = 0;

    CK_BYTE params_data[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    CK_BYTE privkey_data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };

    printf("Testing EC private key roundtrip... ");

    orig_params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    orig_privkey = create_attribute(CKA_VALUE, privkey_data, sizeof(privkey_data));

    if (!orig_params || !orig_privkey) {
        fprintf(stderr, "[FAIL] test_roundtrip_ec_private_key: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = der_encode_ECPrivateKey(FALSE, &encoded, &encoded_len, orig_params, orig_privkey, NULL, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ec_private_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    rv = der_decode_ECPrivateKey(encoded, encoded_len, &dec_params, &dec_pubkey, &dec_privkey, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ec_private_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (dec_params->ulValueLen != sizeof(params_data) ||
        memcmp(dec_params->pValue, params_data, sizeof(params_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ec_private_key: params mismatch (expected %lu bytes, got %lu bytes)\n",
                (unsigned long)sizeof(params_data), (unsigned long)dec_params->ulValueLen);
        if (dec_params->ulValueLen > 0 && dec_params->ulValueLen <= 20) {
            {
                CK_ULONG i;
                fprintf(stderr, "  Expected: ");
                for (i = 0; i < sizeof(params_data); i++)
                    fprintf(stderr, "%02X ", params_data[i]);
                fprintf(stderr, "\n  Got:      ");
                for (i = 0; i < dec_params->ulValueLen; i++)
                    fprintf(stderr, "%02X ", ((CK_BYTE*)dec_params->pValue)[i]);
                fprintf(stderr, "\n");
            }
        }
        result = 1;
    }

    if (dec_privkey->ulValueLen != sizeof(privkey_data) ||
        memcmp(dec_privkey->pValue, privkey_data, sizeof(privkey_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ec_private_key: private key mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_params) free(orig_params);
    if (orig_privkey) free(orig_privkey);
    if (dec_params) free(dec_params);
    if (dec_privkey) free(dec_privkey);
    if (dec_pubkey) free(dec_pubkey);
    if (encoded) free(encoded);
    return result;
}

/* ========================================================================
 * Edwards Curve (CKK_EC_EDWARDS) Private Key Tests
 * ======================================================================== */

int test_encode_edwards_private_key_basic(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *privkey = NULL;
    int result = 0;

    /* Ed25519 OID: 1.3.101.112 */
    CK_BYTE params_data[] = {
        0x06, 0x03, 0x2B, 0x65, 0x70
    };
    CK_BYTE privkey_data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };

    printf("Testing der_encode_ECPrivateKey (Edwards basic)... ");

    params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    privkey = create_attribute(CKA_VALUE, privkey_data, sizeof(privkey_data));

    if (!params || !privkey) {
        fprintf(stderr, "[FAIL] test_encode_edwards_private_key_basic: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = der_encode_ECPrivateKey(FALSE, &encoded, &encoded_len, params, privkey, NULL, CKK_EC_EDWARDS);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_edwards_private_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_edwards_private_key_basic: No data encoded\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS]\n");

cleanup:
    if (params) free(params);
    if (privkey) free(privkey);
    if (encoded) free(encoded);
    return result;
}

int test_roundtrip_edwards_private_key(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_params = NULL, *orig_privkey = NULL;
    CK_ATTRIBUTE *dec_params = NULL, *dec_privkey = NULL, *dec_pubkey = NULL;
    int result = 0;

    /* Ed25519 OID: 1.3.101.112 */
    CK_BYTE params_data[] = {
        0x06, 0x03, 0x2B, 0x65, 0x70
    };
    CK_BYTE privkey_data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };

    printf("Testing Edwards private key roundtrip... ");

    orig_params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    orig_privkey = create_attribute(CKA_VALUE, privkey_data, sizeof(privkey_data));

    if (!orig_params || !orig_privkey) {
        fprintf(stderr, "[FAIL] test_roundtrip_edwards_private_key: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = der_encode_ECPrivateKey(FALSE, &encoded, &encoded_len, orig_params, orig_privkey, NULL, CKK_EC_EDWARDS);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_edwards_private_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    rv = der_decode_ECPrivateKey(encoded, encoded_len, &dec_params, &dec_pubkey, &dec_privkey, CKK_EC_EDWARDS);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_edwards_private_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (dec_params->ulValueLen != sizeof(params_data) ||
        memcmp(dec_params->pValue, params_data, sizeof(params_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_edwards_private_key: params mismatch\n");
        result = 1;
    }

    if (dec_privkey->ulValueLen != sizeof(privkey_data) ||
        memcmp(dec_privkey->pValue, privkey_data, sizeof(privkey_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_edwards_private_key: private key mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_params) free(orig_params);
    if (orig_privkey) free(orig_privkey);
    if (dec_params) free(dec_params);
    if (dec_privkey) free(dec_privkey);
    if (dec_pubkey) free(dec_pubkey);
    if (encoded) free(encoded);
    return result;
}

/* ========================================================================
 * Edwards Curve (CKK_EC_EDWARDS) Public Key Tests
 * ======================================================================== */

int test_encode_edwards_public_key_basic(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *point = NULL;
    int result = 0;

    /* Ed25519 OID: 1.3.101.112 */
    CK_BYTE params_data[] = {
        0x06, 0x03, 0x2B, 0x65, 0x70
    };
    /* Raw Ed25519 public key (32 bytes) */
    CK_BYTE point_data[] = {
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78
    };

    printf("Testing ber_encode_ECPublicKey (Edwards basic)... ");

    params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    point = create_attribute(CKA_EC_POINT, point_data, sizeof(point_data));

    if (!params || !point) {
        fprintf(stderr, "[FAIL] test_encode_edwards_public_key_basic: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_ECPublicKey(FALSE, &encoded, &encoded_len, params, point, CKK_EC_EDWARDS);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_edwards_public_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_edwards_public_key_basic: No data encoded\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS]\n");

cleanup:
    if (params) free(params);
    if (point) free(point);
    if (encoded) free(encoded);
    return result;
}

int test_roundtrip_edwards_public_key(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_params = NULL, *orig_point = NULL;
    CK_ATTRIBUTE *dec_params = NULL, *dec_point = NULL;
    int result = 0;

    /* Ed25519 OID: 1.3.101.112 */
    CK_BYTE params_data[] = {
        0x06, 0x03, 0x2B, 0x65, 0x70
    };
    /* Raw Ed25519 public key (32 bytes) */
    CK_BYTE point_data[] = {
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78
    };

    printf("Testing Edwards public key roundtrip... ");

    orig_params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    orig_point = create_attribute(CKA_EC_POINT, point_data, sizeof(point_data));

    if (!orig_params || !orig_point) {
        fprintf(stderr, "[FAIL] test_roundtrip_edwards_public_key: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_ECPublicKey(FALSE, &encoded, &encoded_len, orig_params, orig_point, CKK_EC_EDWARDS);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_edwards_public_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    rv = der_decode_ECPublicKey(encoded, encoded_len, &dec_params, &dec_point, CKK_EC_EDWARDS);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_edwards_public_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (dec_params->ulValueLen != sizeof(params_data) ||
        memcmp(dec_params->pValue, params_data, sizeof(params_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_edwards_public_key: params mismatch\n");
        result = 1;
    }

    if (dec_point->ulValueLen != sizeof(point_data) ||
        memcmp(dec_point->pValue, point_data, sizeof(point_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_edwards_public_key: point mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_params) free(orig_params);
    if (orig_point) free(orig_point);
    if (dec_params) free(dec_params);
    if (dec_point) free(dec_point);
    if (encoded) free(encoded);
    return result;
}

/* ========================================================================
 * Montgomery Curve (CKK_EC_MONTGOMERY) Private Key Tests
 * ======================================================================== */

int test_encode_montgomery_private_key_basic(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *privkey = NULL;
    int result = 0;

    /* X25519 OID: 1.3.101.110 */
    CK_BYTE params_data[] = {
        0x06, 0x03, 0x2B, 0x65, 0x6E
    };
    CK_BYTE privkey_data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };

    printf("Testing der_encode_ECPrivateKey (Montgomery basic)... ");

    params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    privkey = create_attribute(CKA_VALUE, privkey_data, sizeof(privkey_data));

    if (!params || !privkey) {
        fprintf(stderr, "[FAIL] test_encode_montgomery_private_key_basic: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = der_encode_ECPrivateKey(FALSE, &encoded, &encoded_len, params, privkey, NULL, CKK_EC_MONTGOMERY);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_montgomery_private_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_montgomery_private_key_basic: No data encoded\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS]\n");

cleanup:
    if (params) free(params);
    if (privkey) free(privkey);
    if (encoded) free(encoded);
    return result;
}

int test_roundtrip_montgomery_private_key(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_params = NULL, *orig_privkey = NULL;
    CK_ATTRIBUTE *dec_params = NULL, *dec_privkey = NULL, *dec_pubkey = NULL;
    int result = 0;

    /* X25519 OID: 1.3.101.110 */
    CK_BYTE params_data[] = {
        0x06, 0x03, 0x2B, 0x65, 0x6E
    };
    CK_BYTE privkey_data[] = {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38
    };

    printf("Testing Montgomery private key roundtrip... ");

    orig_params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    orig_privkey = create_attribute(CKA_VALUE, privkey_data, sizeof(privkey_data));

    if (!orig_params || !orig_privkey) {
        fprintf(stderr, "[FAIL] test_roundtrip_montgomery_private_key: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = der_encode_ECPrivateKey(FALSE, &encoded, &encoded_len, orig_params, orig_privkey, NULL, CKK_EC_MONTGOMERY);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_montgomery_private_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    rv = der_decode_ECPrivateKey(encoded, encoded_len, &dec_params, &dec_pubkey, &dec_privkey, CKK_EC_MONTGOMERY);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_montgomery_private_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (dec_params->ulValueLen != sizeof(params_data) ||
        memcmp(dec_params->pValue, params_data, sizeof(params_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_montgomery_private_key: params mismatch\n");
        result = 1;
    }

    if (dec_privkey->ulValueLen != sizeof(privkey_data) ||
        memcmp(dec_privkey->pValue, privkey_data, sizeof(privkey_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_montgomery_private_key: private key mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_params) free(orig_params);
    if (orig_privkey) free(orig_privkey);
    if (dec_params) free(dec_params);
    if (dec_privkey) free(dec_privkey);
    if (dec_pubkey) free(dec_pubkey);
    if (encoded) free(encoded);
    return result;
}

/* ========================================================================
 * Montgomery Curve (CKK_EC_MONTGOMERY) Public Key Tests
 * ======================================================================== */

int test_encode_montgomery_public_key_basic(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *point = NULL;
    int result = 0;

    /* X25519 OID: 1.3.101.110 */
    CK_BYTE params_data[] = {
        0x06, 0x03, 0x2B, 0x65, 0x6E
    };
    /* Raw X25519 public key (32 bytes) */
    CK_BYTE point_data[] = {
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78
    };

    printf("Testing ber_encode_ECPublicKey (Montgomery basic)... ");

    params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    point = create_attribute(CKA_EC_POINT, point_data, sizeof(point_data));

    if (!params || !point) {
        fprintf(stderr, "[FAIL] test_encode_montgomery_public_key_basic: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_ECPublicKey(FALSE, &encoded, &encoded_len, params, point, CKK_EC_MONTGOMERY);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_montgomery_public_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_montgomery_public_key_basic: No data encoded\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS]\n");

cleanup:
    if (params) free(params);
    if (point) free(point);
    if (encoded) free(encoded);
    return result;
}

int test_roundtrip_montgomery_public_key(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_params = NULL, *orig_point = NULL;
    CK_ATTRIBUTE *dec_params = NULL, *dec_point = NULL;
    int result = 0;

    /* X25519 OID: 1.3.101.110 */
    CK_BYTE params_data[] = {
        0x06, 0x03, 0x2B, 0x65, 0x6E
    };
    /* Raw X25519 public key (32 bytes) */
    CK_BYTE point_data[] = {
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78
    };

    printf("Testing Montgomery public key roundtrip... ");

    orig_params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    orig_point = create_attribute(CKA_EC_POINT, point_data, sizeof(point_data));

    if (!orig_params || !orig_point) {
        fprintf(stderr, "[FAIL] test_roundtrip_montgomery_public_key: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_ECPublicKey(FALSE, &encoded, &encoded_len, orig_params, orig_point, CKK_EC_MONTGOMERY);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_montgomery_public_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    rv = der_decode_ECPublicKey(encoded, encoded_len, &dec_params, &dec_point, CKK_EC_MONTGOMERY);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_montgomery_public_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (dec_params->ulValueLen != sizeof(params_data) ||
        memcmp(dec_params->pValue, params_data, sizeof(params_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_montgomery_public_key: params mismatch\n");
        result = 1;
    }

    if (dec_point->ulValueLen != sizeof(point_data) ||
        memcmp(dec_point->pValue, point_data, sizeof(point_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_montgomery_public_key: point mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_params) free(orig_params);
    if (orig_point) free(orig_point);
    if (dec_params) free(dec_params);
    if (dec_point) free(dec_point);
    if (encoded) free(encoded);
    return result;
}


/* ========================================================================
 * EC Public Key Tests (CKK_EC)
 * ======================================================================== */

int test_encode_ec_public_key_basic(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *params = NULL, *point = NULL;
    int result = 0;

    CK_BYTE params_data[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    CK_BYTE point_data[] = {
        0x04, 0x41,  /* OCTET STRING, length 65 */
        0x04,  /* Uncompressed point */
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48
    };

    printf("Testing ber_encode_ECPublicKey (basic)... ");

    params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    point = create_attribute(CKA_EC_POINT, point_data, sizeof(point_data));

    if (!params || !point) {
        fprintf(stderr, "[FAIL] test_encode_ec_public_key_basic: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_ECPublicKey(FALSE, &encoded, &encoded_len, params, point, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ec_public_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ec_public_key_basic: No data encoded\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS]\n");

cleanup:
    if (params) free(params);
    if (point) free(point);
    if (encoded) free(encoded);
    return result;
}

int test_decode_ec_public_key_valid(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_params = NULL, *orig_point = NULL;
    CK_ATTRIBUTE *dec_params = NULL, *dec_point = NULL;
    int result = 0;

    CK_BYTE params_data[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    CK_BYTE point_data[] = {
        0x04, 0x41,  /* OCTET STRING, length 65 */
        0x04,  /* Uncompressed point */
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48
    };

    printf("Testing der_decode_ECPublicKey (valid)... ");

    orig_params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    orig_point = create_attribute(CKA_EC_POINT, point_data, sizeof(point_data));

    if (!orig_params || !orig_point) {
        fprintf(stderr, "[FAIL] test_decode_ec_public_key_valid: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_ECPublicKey(FALSE, &encoded, &encoded_len, orig_params, orig_point, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ec_public_key_valid: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    rv = der_decode_ECPublicKey(encoded, encoded_len, &dec_params, &dec_point, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ec_public_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (dec_params->ulValueLen != sizeof(params_data) ||
        memcmp(dec_params->pValue, params_data, sizeof(params_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ec_public_key_valid: params mismatch\n");
        result = 1;
    }

    if (dec_point->ulValueLen != sizeof(point_data) ||
        memcmp(dec_point->pValue, point_data, sizeof(point_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ec_public_key_valid: point mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_params) free(orig_params);
    if (orig_point) free(orig_point);
    if (dec_params) free(dec_params);
    if (dec_point) free(dec_point);
    if (encoded) free(encoded);
    return result;
}

int test_roundtrip_ec_public_key(void)
{
    CK_RV rv;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_ATTRIBUTE *orig_params = NULL, *orig_point = NULL;
    CK_ATTRIBUTE *dec_params = NULL, *dec_point = NULL;
    int result = 0;

    CK_BYTE params_data[] = {
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07
    };
    CK_BYTE point_data[] = {
        0x04, 0x41,  /* OCTET STRING, length 65 */
        0x04,  /* Uncompressed point */
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,
        0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58,
        0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68,
        0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78,
        0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
        0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28,
        0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38,
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48
    };

    printf("Testing EC public key roundtrip... ");

    orig_params = create_attribute(CKA_EC_PARAMS, params_data, sizeof(params_data));
    orig_point = create_attribute(CKA_EC_POINT, point_data, sizeof(point_data));

    if (!orig_params || !orig_point) {
        fprintf(stderr, "[FAIL] test_roundtrip_ec_public_key: Failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_encode_ECPublicKey(FALSE, &encoded, &encoded_len, orig_params, orig_point, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ec_public_key: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    rv = der_decode_ECPublicKey(encoded, encoded_len, &dec_params, &dec_point, CKK_EC);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ec_public_key: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (dec_params->ulValueLen != sizeof(params_data) ||
        memcmp(dec_params->pValue, params_data, sizeof(params_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ec_public_key: params mismatch\n");
        result = 1;
    }

    if (dec_point->ulValueLen != sizeof(point_data) ||
        memcmp(dec_point->pValue, point_data, sizeof(point_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ec_public_key: point mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS]\n");

cleanup:
    if (orig_params) free(orig_params);
    if (orig_point) free(orig_point);
    if (dec_params) free(dec_params);
    if (dec_point) free(dec_point);
    if (encoded) free(encoded);
    return result;
}
