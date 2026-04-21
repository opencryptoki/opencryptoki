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
 * Post-Quantum Cryptography (PQC) key encoding/decoding unit tests
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "unittest.h"
#include "asn1test_pqckeys.h"


/* Helper function to create a CK_ATTRIBUTE with data */
CK_ATTRIBUTE *create_attribute(CK_ATTRIBUTE_TYPE type, CK_BYTE *data, CK_ULONG data_len);

/* Function prototypes from asn1.c */
CK_RV ber_encode_IBM_ML_DSA_PublicKey(CK_MECHANISM_TYPE mech, CK_BBOOL length_only,
                                       CK_BYTE **data, CK_ULONG *data_len,
                                       const CK_BYTE *oid, CK_ULONG oid_len,
                                       CK_ATTRIBUTE *rho, CK_ATTRIBUTE *t1);

CK_RV ber_decode_IBM_ML_DSA_PublicKey(CK_MECHANISM_TYPE mech, CK_BYTE *data,
                                       CK_ULONG data_len, CK_ATTRIBUTE **rho,
                                       CK_ATTRIBUTE **t1, CK_ATTRIBUTE **value,
                                       const struct pqc_oid **oid);

CK_RV ber_encode_IBM_ML_DSA_PrivateKey(CK_MECHANISM_TYPE mech, CK_BBOOL length_only,
                                        CK_BYTE **data, CK_ULONG *data_len,
                                        const CK_BYTE *oid, CK_ULONG oid_len,
                                        CK_ATTRIBUTE *rho, CK_ATTRIBUTE *seed,
                                        CK_ATTRIBUTE *tr, CK_ATTRIBUTE *s1,
                                        CK_ATTRIBUTE *s2, CK_ATTRIBUTE *t0,
                                        CK_ATTRIBUTE *t1, CK_ATTRIBUTE *priv_seed);

CK_RV ber_decode_IBM_ML_DSA_PrivateKey(CK_MECHANISM_TYPE mech, CK_BYTE *data,
                                        CK_ULONG data_len, CK_ATTRIBUTE **rho,
                                        CK_ATTRIBUTE **seed, CK_ATTRIBUTE **tr,
                                        CK_ATTRIBUTE **s1, CK_ATTRIBUTE **s2,
                                        CK_ATTRIBUTE **t0, CK_ATTRIBUTE **t1,
                                        CK_ATTRIBUTE **priv_seed,
                                        CK_ATTRIBUTE **value,
                                        const struct pqc_oid **oid);

CK_RV ber_encode_IBM_ML_KEM_PublicKey(CK_MECHANISM_TYPE mech, CK_BBOOL length_only,
                                       CK_BYTE **data, CK_ULONG *data_len,
                                       const CK_BYTE *oid, CK_ULONG oid_len,
                                       CK_ATTRIBUTE *pk);

CK_RV ber_decode_IBM_ML_KEM_PublicKey(CK_MECHANISM_TYPE mech, CK_BYTE *data,
                                       CK_ULONG data_len, CK_ATTRIBUTE **pk,
                                       CK_ATTRIBUTE **value,
                                       const struct pqc_oid **oid);

CK_RV ber_encode_IBM_ML_KEM_PrivateKey(CK_MECHANISM_TYPE mech, CK_BBOOL length_only,
                                        CK_BYTE **data, CK_ULONG *data_len,
                                        const CK_BYTE *oid, CK_ULONG oid_len,
                                        CK_ATTRIBUTE *sk, CK_ATTRIBUTE *pk,
                                        CK_ATTRIBUTE *priv_seed);

CK_RV ber_decode_IBM_ML_KEM_PrivateKey(CK_MECHANISM_TYPE mech, CK_BYTE *data,
                                        CK_ULONG data_len, CK_ATTRIBUTE **sk,
                                        CK_ATTRIBUTE **pk,
                                        CK_ATTRIBUTE **priv_seed,
                                        CK_ATTRIBUTE **value,
                                        const struct pqc_oid **oid);

CK_RV ber_encode_ML_DSA_PublicKey(CK_BBOOL length_only, CK_BYTE **data,
                                   CK_ULONG *data_len, const CK_BYTE *oid,
                                   CK_ULONG oid_len, CK_ATTRIBUTE *value);

CK_RV ber_decode_ML_DSA_PublicKey(CK_BYTE *data, CK_ULONG data_len,
                                   CK_ATTRIBUTE **value,
                                   const struct pqc_oid **oid);

CK_RV ber_encode_ML_DSA_PrivateKey(CK_BBOOL length_only, CK_BYTE **data,
                                    CK_ULONG *data_len, const CK_BYTE *oid,
                                    CK_ULONG oid_len, CK_ATTRIBUTE *value,
                                    CK_ATTRIBUTE *seed);

CK_RV ber_decode_ML_DSA_PrivateKey(CK_BYTE *data, CK_ULONG data_len,
                                    CK_ATTRIBUTE **value,
                                    CK_ATTRIBUTE **seed,
                                    const struct pqc_oid **oid);

CK_RV ber_encode_ML_KEM_PublicKey(CK_BBOOL length_only, CK_BYTE **data,
                                   CK_ULONG *data_len, const CK_BYTE *oid,
                                   CK_ULONG oid_len, CK_ATTRIBUTE *value);

CK_RV ber_decode_ML_KEM_PublicKey(CK_BYTE *data, CK_ULONG data_len,
                                   CK_ATTRIBUTE **value,
                                   const struct pqc_oid **oid);

CK_RV ber_encode_ML_KEM_PrivateKey(CK_BBOOL length_only, CK_BYTE **data,
                                    CK_ULONG *data_len, const CK_BYTE *oid,
                                    CK_ULONG oid_len, CK_ATTRIBUTE *value,
                                    CK_ATTRIBUTE *seed);

CK_RV ber_decode_ML_KEM_PrivateKey(CK_BYTE *data, CK_ULONG data_len,
                                    CK_ATTRIBUTE **value,
                                    CK_ATTRIBUTE **seed,
                                    const struct pqc_oid **oid);

/* External OID constants from asn1test_stubs.c */
extern const CK_BYTE ber_idML_DSA_65[];
extern const CK_ULONG ber_idML_DSA_65Len;
extern const CK_BYTE ber_idML_KEM_768[];
extern const CK_ULONG ber_idML_KEM_768Len;

/* ============================================================================
 * IBM Dilithium (Round 2) Tests
 * ============================================================================ */

/* Test ber_encode_IBM_ML_DSA_PublicKey with basic ML-DSA-65 key components */
int test_encode_ibm_ml_dsa_public_key_basic(void)
{
    /* ML-DSA-65 public key components for testing */
    CK_BYTE rho_data[32] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
                            0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
                            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
    CK_BYTE t1_data[1920];  /* ML-DSA-65 t1 size */
    CK_ATTRIBUTE *rho = NULL, *t1 = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize t1 with test data */
    memset(t1_data, 0x42, sizeof(t1_data));

    /* Create attributes */
    rho = create_attribute(CKA_IBM_ML_DSA_RHO, rho_data, sizeof(rho_data));
    t1 = create_attribute(CKA_IBM_ML_DSA_T1, t1_data, sizeof(t1_data));

    if (!rho || !t1) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_public_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Use external OID constant */
    extern const CK_BYTE ber_idML_DSA_65[];
    extern const CK_ULONG ber_idML_DSA_65Len;

    rv = ber_encode_IBM_ML_DSA_PublicKey(CKM_IBM_ML_DSA, FALSE, &encoded, &encoded_len,
                                         ber_idML_DSA_65, ber_idML_DSA_65Len,
                                         rho, t1);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_public_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify we got some encoded data */
    if (encoded == NULL || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_public_key_basic: no encoded data\n");
        result = 1;
        goto cleanup;
    }

    /* Basic sanity check: should start with SEQUENCE tag (0x30) for SPKI */
    if (encoded[0] != 0x30) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_public_key_basic: invalid tag (expected 0x30, got 0x%02X)\n",
                encoded[0]);
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ibm_ml_dsa_public_key_basic\n");

cleanup:
    if (rho) free(rho);
    if (t1) free(t1);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_IBM_ML_DSA_PublicKey with valid encoded data */
int test_decode_ibm_ml_dsa_public_key_valid(void)
{
    CK_BYTE rho_data[32] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
                            0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
                            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
    CK_BYTE t1_data[1920];
    CK_ATTRIBUTE *orig_rho = NULL, *orig_t1 = NULL;
    CK_ATTRIBUTE *dec_rho = NULL, *dec_t1 = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(t1_data, 0x42, sizeof(t1_data));

    orig_rho = create_attribute(CKA_IBM_ML_DSA_RHO, rho_data, sizeof(rho_data));
    orig_t1 = create_attribute(CKA_IBM_ML_DSA_T1, t1_data, sizeof(t1_data));

    if (!orig_rho || !orig_t1) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_dsa_public_key_valid: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_DSA_65[];
    extern const CK_ULONG ber_idML_DSA_65Len;

    /* First encode */
    rv = ber_encode_IBM_ML_DSA_PublicKey(CKM_IBM_ML_DSA, FALSE, &encoded, &encoded_len,
                                         ber_idML_DSA_65, ber_idML_DSA_65Len,
                                         orig_rho, orig_t1);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_dsa_public_key_valid: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_IBM_ML_DSA_PublicKey(CKM_IBM_ML_DSA, encoded, encoded_len,
                                         &dec_rho, &dec_t1, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_dsa_public_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify decoded data matches original */
    if (!dec_rho || dec_rho->ulValueLen != sizeof(rho_data) ||
        memcmp(dec_rho->pValue, rho_data, sizeof(rho_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_dsa_public_key_valid: rho mismatch\n");
        result = 1;
    }

    if (!dec_t1 || dec_t1->ulValueLen != sizeof(t1_data) ||
        memcmp(dec_t1->pValue, t1_data, sizeof(t1_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_dsa_public_key_valid: t1 mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_decode_ibm_ml_dsa_public_key_valid\n");

cleanup:
    if (orig_rho) free(orig_rho);
    if (orig_t1) free(orig_t1);
    if (dec_rho) free(dec_rho);
    if (dec_t1) free(dec_t1);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-DSA public key encode/decode roundtrip */
int test_roundtrip_ibm_ml_dsa_public_key(void)
{
    CK_BYTE rho_data[32] = {0xA1, 0xB2, 0xC3, 0xD4, 0xE5, 0xF6, 0x07, 0x18,
                            0x29, 0x3A, 0x4B, 0x5C, 0x6D, 0x7E, 0x8F, 0x90,
                            0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                            0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00};
    CK_BYTE t1_data[1920];
    CK_ATTRIBUTE *orig_rho = NULL, *orig_t1 = NULL;
    CK_ATTRIBUTE *dec_rho = NULL, *dec_t1 = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(t1_data, 0x42, sizeof(t1_data));

    orig_rho = create_attribute(CKA_IBM_ML_DSA_RHO, rho_data, sizeof(rho_data));
    orig_t1 = create_attribute(CKA_IBM_ML_DSA_T1, t1_data, sizeof(t1_data));

    if (!orig_rho || !orig_t1) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_dsa_public_key: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_DSA_65[];
    extern const CK_ULONG ber_idML_DSA_65Len;

    /* Encode */
    rv = ber_encode_IBM_ML_DSA_PublicKey(CKM_IBM_ML_DSA, FALSE, &encoded, &encoded_len,
                                         ber_idML_DSA_65, ber_idML_DSA_65Len,
                                         orig_rho, orig_t1);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_dsa_public_key: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_IBM_ML_DSA_PublicKey(CKM_IBM_ML_DSA, encoded, encoded_len,
                                         &dec_rho, &dec_t1, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_dsa_public_key: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip */
    if (dec_rho->ulValueLen != sizeof(rho_data) ||
        memcmp(dec_rho->pValue, rho_data, sizeof(rho_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_dsa_public_key: rho mismatch\n");
        result = 1;
    }

    if (dec_t1->ulValueLen != sizeof(t1_data) ||
        memcmp(dec_t1->pValue, t1_data, sizeof(t1_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_dsa_public_key: t1 mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ibm_ml_dsa_public_key\n");

cleanup:
    if (orig_rho) free(orig_rho);
    if (orig_t1) free(orig_t1);
    if (dec_rho) free(dec_rho);
    if (dec_t1) free(dec_t1);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* ============================================================================
 * ML-DSA Private Key Tests
 * ============================================================================ */

/* Test ber_encode_IBM_ML_DSA_PrivateKey with basic ML-DSA-65 key components */
int test_encode_ibm_ml_dsa_private_key_basic(void)
{
    /* ML-DSA-65 private key components */
    CK_BYTE rho_data[32], seed_data[32], tr_data[64];
    CK_BYTE s1_data[640], s2_data[768], t0_data[2496], t1_data[1920];
    CK_ATTRIBUTE *rho = NULL, *seed = NULL, *tr = NULL;
    CK_ATTRIBUTE *s1 = NULL, *s2 = NULL, *t0 = NULL, *t1 = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize with test data */
    memset(rho_data, 0xA1, sizeof(rho_data));
    memset(seed_data, 0xB2, sizeof(seed_data));
    memset(tr_data, 0xC3, sizeof(tr_data));
    memset(s1_data, 0xD4, sizeof(s1_data));
    memset(s2_data, 0xE5, sizeof(s2_data));
    memset(t0_data, 0xF6, sizeof(t0_data));
    memset(t1_data, 0x07, sizeof(t1_data));

    /* Create attributes */
    rho = create_attribute(CKA_IBM_ML_DSA_RHO, rho_data, sizeof(rho_data));
    seed = create_attribute(CKA_IBM_ML_DSA_SEED, seed_data, sizeof(seed_data));
    tr = create_attribute(CKA_IBM_ML_DSA_TR, tr_data, sizeof(tr_data));
    s1 = create_attribute(CKA_IBM_ML_DSA_S1, s1_data, sizeof(s1_data));
    s2 = create_attribute(CKA_IBM_ML_DSA_S2, s2_data, sizeof(s2_data));
    t0 = create_attribute(CKA_IBM_ML_DSA_T0, t0_data, sizeof(t0_data));
    t1 = create_attribute(CKA_IBM_ML_DSA_T1, t1_data, sizeof(t1_data));

    if (!rho || !seed || !tr || !s1 || !s2 || !t0 || !t1) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_private_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_DSA_65[];
    extern const CK_ULONG ber_idML_DSA_65Len;

    rv = ber_encode_IBM_ML_DSA_PrivateKey(CKM_IBM_ML_DSA, FALSE, &encoded, &encoded_len,
                                          ber_idML_DSA_65, ber_idML_DSA_65Len,
                                          rho, seed, tr, s1, s2, t0, t1, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_private_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded == NULL || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_private_key_basic: no encoded data\n");
        result = 1;
        goto cleanup;
    }

    if (encoded[0] != 0x30) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_private_key_basic: invalid tag\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ibm_ml_dsa_private_key_basic\n");

cleanup:
    if (rho) free(rho);
    if (seed) free(seed);
    if (tr) free(tr);
    if (s1) free(s1);
    if (s2) free(s2);
    if (t0) free(t0);
    if (t1) free(t1);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_IBM_ML_DSA_PrivateKey with length_only mode */
int test_encode_ibm_ml_dsa_private_key_length_only(void)
{
    CK_BYTE rho_data[32], seed_data[32], tr_data[64];
    CK_BYTE s1_data[640], s2_data[768], t0_data[2496], t1_data[1920];
    CK_ATTRIBUTE *rho = NULL, *seed = NULL, *tr = NULL;
    CK_ATTRIBUTE *s1 = NULL, *s2 = NULL, *t0 = NULL, *t1 = NULL;
    CK_ULONG len1 = 0, len2 = 0;
    CK_BYTE *encoded = NULL;
    CK_RV rv;
    int result = 0;

    memset(rho_data, 0xA1, sizeof(rho_data));
    memset(seed_data, 0xB2, sizeof(seed_data));
    memset(tr_data, 0xC3, sizeof(tr_data));
    memset(s1_data, 0xD4, sizeof(s1_data));
    memset(s2_data, 0xE5, sizeof(s2_data));
    memset(t0_data, 0xF6, sizeof(t0_data));
    memset(t1_data, 0x07, sizeof(t1_data));

    rho = create_attribute(CKA_IBM_ML_DSA_RHO, rho_data, sizeof(rho_data));
    seed = create_attribute(CKA_IBM_ML_DSA_SEED, seed_data, sizeof(seed_data));
    tr = create_attribute(CKA_IBM_ML_DSA_TR, tr_data, sizeof(tr_data));
    s1 = create_attribute(CKA_IBM_ML_DSA_S1, s1_data, sizeof(s1_data));
    s2 = create_attribute(CKA_IBM_ML_DSA_S2, s2_data, sizeof(s2_data));
    t0 = create_attribute(CKA_IBM_ML_DSA_T0, t0_data, sizeof(t0_data));
    t1 = create_attribute(CKA_IBM_ML_DSA_T1, t1_data, sizeof(t1_data));

    if (!rho || !seed || !tr || !s1 || !s2 || !t0 || !t1) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_private_key_length_only: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_DSA_65[];
    extern const CK_ULONG ber_idML_DSA_65Len;

    /* Get length */
    rv = ber_encode_IBM_ML_DSA_PrivateKey(CKM_IBM_ML_DSA, TRUE, NULL, &len1,
                                          ber_idML_DSA_65, ber_idML_DSA_65Len,
                                          rho, seed, tr, s1, s2, t0, t1, NULL);
    if (rv != CKR_OK || len1 == 0) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_private_key_length_only: length calculation failed\n");
        result = 1;
        goto cleanup;
    }

    /* Actual encode */
    rv = ber_encode_IBM_ML_DSA_PrivateKey(CKM_IBM_ML_DSA, FALSE, &encoded, &len2,
                                          ber_idML_DSA_65, ber_idML_DSA_65Len,
                                          rho, seed, tr, s1, s2, t0, t1, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_private_key_length_only: encode failed\n");
        result = 1;
        goto cleanup;
    }

    if (len1 != len2) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_dsa_private_key_length_only: length mismatch (%lu vs %lu)\n",
                len1, len2);
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ibm_ml_dsa_private_key_length_only\n");

cleanup:
    if (rho) free(rho);
    if (seed) free(seed);
    if (tr) free(tr);
    if (s1) free(s1);
    if (s2) free(s2);
    if (t0) free(t0);
    if (t1) free(t1);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_IBM_ML_DSA_PrivateKey with valid encoded data */
int test_decode_ibm_ml_dsa_private_key_valid(void)
{
    CK_BYTE rho_data[32], seed_data[32], tr_data[64];
    CK_BYTE s1_data[640], s2_data[768], t0_data[2496], t1_data[1920];
    CK_ATTRIBUTE *orig_rho = NULL, *orig_seed = NULL, *orig_tr = NULL;
    CK_ATTRIBUTE *orig_s1 = NULL, *orig_s2 = NULL, *orig_t0 = NULL, *orig_t1 = NULL;
    CK_ATTRIBUTE *dec_rho = NULL, *dec_seed = NULL, *dec_tr = NULL;
    CK_ATTRIBUTE *dec_s1 = NULL, *dec_s2 = NULL, *dec_t0 = NULL, *dec_t1 = NULL;
    CK_ATTRIBUTE *dec_priv_seed = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(rho_data, 0xA1, sizeof(rho_data));
    memset(seed_data, 0xB2, sizeof(seed_data));
    memset(tr_data, 0xC3, sizeof(tr_data));
    memset(s1_data, 0xD4, sizeof(s1_data));
    memset(s2_data, 0xE5, sizeof(s2_data));
    memset(t0_data, 0xF6, sizeof(t0_data));
    memset(t1_data, 0x07, sizeof(t1_data));

    orig_rho = create_attribute(CKA_IBM_ML_DSA_RHO, rho_data, sizeof(rho_data));
    orig_seed = create_attribute(CKA_IBM_ML_DSA_SEED, seed_data, sizeof(seed_data));
    orig_tr = create_attribute(CKA_IBM_ML_DSA_TR, tr_data, sizeof(tr_data));
    orig_s1 = create_attribute(CKA_IBM_ML_DSA_S1, s1_data, sizeof(s1_data));
    orig_s2 = create_attribute(CKA_IBM_ML_DSA_S2, s2_data, sizeof(s2_data));
    orig_t0 = create_attribute(CKA_IBM_ML_DSA_T0, t0_data, sizeof(t0_data));
    orig_t1 = create_attribute(CKA_IBM_ML_DSA_T1, t1_data, sizeof(t1_data));

    if (!orig_rho || !orig_seed || !orig_tr || !orig_s1 || !orig_s2 || !orig_t0 || !orig_t1) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_dsa_private_key_valid: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_DSA_65[];
    extern const CK_ULONG ber_idML_DSA_65Len;

    /* Encode */
    rv = ber_encode_IBM_ML_DSA_PrivateKey(CKM_IBM_ML_DSA, FALSE, &encoded, &encoded_len,
                                          ber_idML_DSA_65, ber_idML_DSA_65Len,
                                          orig_rho, orig_seed, orig_tr, orig_s1, orig_s2,
                                          orig_t0, orig_t1, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_dsa_private_key_valid: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_IBM_ML_DSA_PrivateKey(CKM_IBM_ML_DSA, encoded, encoded_len,
                                          &dec_rho, &dec_seed, &dec_tr, &dec_s1, &dec_s2,
                                          &dec_t0, &dec_t1, &dec_priv_seed, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_dsa_private_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify decoded data */
    if (!dec_rho || dec_rho->ulValueLen != sizeof(rho_data) ||
        memcmp(dec_rho->pValue, rho_data, sizeof(rho_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_dsa_private_key_valid: rho mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_decode_ibm_ml_dsa_private_key_valid\n");

cleanup:
    if (orig_rho) free(orig_rho);
    if (orig_seed) free(orig_seed);
    if (orig_tr) free(orig_tr);
    if (orig_s1) free(orig_s1);
    if (orig_s2) free(orig_s2);
    if (orig_t0) free(orig_t0);
    if (orig_t1) free(orig_t1);
    if (dec_rho) free(dec_rho);
    if (dec_seed) free(dec_seed);
    if (dec_tr) free(dec_tr);
    if (dec_s1) free(dec_s1);
    if (dec_s2) free(dec_s2);
    if (dec_t0) free(dec_t0);
    if (dec_t1) free(dec_t1);
    if (dec_priv_seed) free(dec_priv_seed);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-DSA private key encode/decode roundtrip */
int test_roundtrip_ibm_ml_dsa_private_key(void)
{
    CK_BYTE rho_data[32], seed_data[32], tr_data[64];
    CK_BYTE s1_data[640], s2_data[768], t0_data[2496], t1_data[1920];
    CK_ATTRIBUTE *orig_rho = NULL, *orig_seed = NULL, *orig_tr = NULL;
    CK_ATTRIBUTE *orig_s1 = NULL, *orig_s2 = NULL, *orig_t0 = NULL, *orig_t1 = NULL;
    CK_ATTRIBUTE *dec_rho = NULL, *dec_seed = NULL, *dec_tr = NULL;
    CK_ATTRIBUTE *dec_s1 = NULL, *dec_s2 = NULL, *dec_t0 = NULL, *dec_t1 = NULL;
    CK_ATTRIBUTE *dec_priv_seed = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(rho_data, 0xA1, sizeof(rho_data));
    memset(seed_data, 0xB2, sizeof(seed_data));
    memset(tr_data, 0xC3, sizeof(tr_data));
    memset(s1_data, 0xD4, sizeof(s1_data));
    memset(s2_data, 0xE5, sizeof(s2_data));
    memset(t0_data, 0xF6, sizeof(t0_data));
    memset(t1_data, 0x07, sizeof(t1_data));

    orig_rho = create_attribute(CKA_IBM_ML_DSA_RHO, rho_data, sizeof(rho_data));
    orig_seed = create_attribute(CKA_IBM_ML_DSA_SEED, seed_data, sizeof(seed_data));
    orig_tr = create_attribute(CKA_IBM_ML_DSA_TR, tr_data, sizeof(tr_data));
    orig_s1 = create_attribute(CKA_IBM_ML_DSA_S1, s1_data, sizeof(s1_data));
    orig_s2 = create_attribute(CKA_IBM_ML_DSA_S2, s2_data, sizeof(s2_data));
    orig_t0 = create_attribute(CKA_IBM_ML_DSA_T0, t0_data, sizeof(t0_data));
    orig_t1 = create_attribute(CKA_IBM_ML_DSA_T1, t1_data, sizeof(t1_data));

    if (!orig_rho || !orig_seed || !orig_tr || !orig_s1 || !orig_s2 || !orig_t0 || !orig_t1) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_dsa_private_key: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_DSA_65[];
    extern const CK_ULONG ber_idML_DSA_65Len;

    /* Encode */
    rv = ber_encode_IBM_ML_DSA_PrivateKey(CKM_IBM_ML_DSA, FALSE, &encoded, &encoded_len,
                                          ber_idML_DSA_65, ber_idML_DSA_65Len,
                                          orig_rho, orig_seed, orig_tr, orig_s1, orig_s2,
                                          orig_t0, orig_t1, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_dsa_private_key: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_IBM_ML_DSA_PrivateKey(CKM_IBM_ML_DSA, encoded, encoded_len,
                                          &dec_rho, &dec_seed, &dec_tr, &dec_s1, &dec_s2,
                                          &dec_t0, &dec_t1, &dec_priv_seed, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_dsa_private_key: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip */
    if (dec_rho->ulValueLen != sizeof(rho_data) ||
        memcmp(dec_rho->pValue, rho_data, sizeof(rho_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_dsa_private_key: rho mismatch\n");
        result = 1;
    }

    if (dec_seed->ulValueLen != sizeof(seed_data) ||
        memcmp(dec_seed->pValue, seed_data, sizeof(seed_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_dsa_private_key: seed mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ibm_ml_dsa_private_key\n");

cleanup:
    if (orig_rho) free(orig_rho);
    if (orig_seed) free(orig_seed);
    if (orig_tr) free(orig_tr);
    if (orig_s1) free(orig_s1);
    if (orig_s2) free(orig_s2);
    if (orig_t0) free(orig_t0);
    if (orig_t1) free(orig_t1);
    if (dec_rho) free(dec_rho);
    if (dec_seed) free(dec_seed);
    if (dec_tr) free(dec_tr);
    if (dec_s1) free(dec_s1);
    if (dec_s2) free(dec_s2);
    if (dec_t0) free(dec_t0);
    if (dec_t1) free(dec_t1);
    if (dec_priv_seed) free(dec_priv_seed);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* ============================================================================
 * ML-KEM Public Key Tests
 * ============================================================================ */

/* Test ber_encode_IBM_ML_KEM_PublicKey with basic ML-KEM-768 key components */
int test_encode_ibm_ml_kem_public_key_basic(void)
{
    /* ML-KEM-768 public key size */
    CK_BYTE pk_data[1184];
    CK_ATTRIBUTE *pk = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(pk_data, 0x55, sizeof(pk_data));

    pk = create_attribute(CKA_IBM_ML_KEM_PK, pk_data, sizeof(pk_data));

    if (!pk) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_public_key_basic: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_KEM_768[];
    extern const CK_ULONG ber_idML_KEM_768Len;

    rv = ber_encode_IBM_ML_KEM_PublicKey(CKM_IBM_ML_KEM, FALSE, &encoded, &encoded_len,
                                         ber_idML_KEM_768, ber_idML_KEM_768Len, pk);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_public_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded == NULL || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_public_key_basic: no encoded data\n");
        result = 1;
        goto cleanup;
    }

    if (encoded[0] != 0x30) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_public_key_basic: invalid tag\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ibm_ml_kem_public_key_basic\n");

cleanup:
    if (pk) free(pk);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_IBM_ML_KEM_PublicKey with valid encoded data */
int test_decode_ibm_ml_kem_public_key_valid(void)
{
    CK_BYTE pk_data[1184];
    CK_ATTRIBUTE *orig_pk = NULL;
    CK_ATTRIBUTE *dec_pk = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(pk_data, 0x55, sizeof(pk_data));

    orig_pk = create_attribute(CKA_IBM_ML_KEM_PK, pk_data, sizeof(pk_data));

    if (!orig_pk) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_kem_public_key_valid: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_KEM_768[];
    extern const CK_ULONG ber_idML_KEM_768Len;

    /* Encode */
    rv = ber_encode_IBM_ML_KEM_PublicKey(CKM_IBM_ML_KEM, FALSE, &encoded, &encoded_len,
                                         ber_idML_KEM_768, ber_idML_KEM_768Len, orig_pk);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_kem_public_key_valid: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_IBM_ML_KEM_PublicKey(CKM_IBM_ML_KEM, encoded, encoded_len,
                                         &dec_pk, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_kem_public_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify decoded data */
    if (!dec_pk || dec_pk->ulValueLen != sizeof(pk_data) ||
        memcmp(dec_pk->pValue, pk_data, sizeof(pk_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_kem_public_key_valid: pk mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_decode_ibm_ml_kem_public_key_valid\n");

cleanup:
    if (orig_pk) free(orig_pk);
    if (dec_pk) free(dec_pk);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-KEM public key encode/decode roundtrip */
int test_roundtrip_ibm_ml_kem_public_key(void)
{
    CK_BYTE pk_data[1184];
    CK_ATTRIBUTE *orig_pk = NULL;
    CK_ATTRIBUTE *dec_pk = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(pk_data, 0x55, sizeof(pk_data));

    orig_pk = create_attribute(CKA_IBM_ML_KEM_PK, pk_data, sizeof(pk_data));

    if (!orig_pk) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_kem_public_key: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_KEM_768[];
    extern const CK_ULONG ber_idML_KEM_768Len;

    /* Encode */
    rv = ber_encode_IBM_ML_KEM_PublicKey(CKM_IBM_ML_KEM, FALSE, &encoded, &encoded_len,
                                         ber_idML_KEM_768, ber_idML_KEM_768Len, orig_pk);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_kem_public_key: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_IBM_ML_KEM_PublicKey(CKM_IBM_ML_KEM, encoded, encoded_len,
                                         &dec_pk, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_kem_public_key: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip */
    if (dec_pk->ulValueLen != sizeof(pk_data) ||
        memcmp(dec_pk->pValue, pk_data, sizeof(pk_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_kem_public_key: pk mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ibm_ml_kem_public_key\n");

cleanup:
    if (orig_pk) free(orig_pk);
    if (dec_pk) free(dec_pk);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* ============================================================================
 * ML-KEM Private Key Tests
 * ============================================================================ */

/* Test ber_encode_IBM_ML_KEM_PrivateKey with basic ML-KEM-768 key components */
int test_encode_ibm_ml_kem_private_key_basic(void)
{
    /* ML-KEM-768 key sizes */
    CK_BYTE sk_data[2400];
    CK_BYTE pk_data[1184];
    CK_ATTRIBUTE *sk = NULL, *pk = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(sk_data, 0x66, sizeof(sk_data));
    memset(pk_data, 0x77, sizeof(pk_data));

    sk = create_attribute(CKA_IBM_ML_KEM_SK, sk_data, sizeof(sk_data));
    pk = create_attribute(CKA_IBM_ML_KEM_PK, pk_data, sizeof(pk_data));

    if (!sk || !pk) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_private_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_KEM_768[];
    extern const CK_ULONG ber_idML_KEM_768Len;

    rv = ber_encode_IBM_ML_KEM_PrivateKey(CKM_IBM_ML_KEM, FALSE, &encoded, &encoded_len,
                                          ber_idML_KEM_768, ber_idML_KEM_768Len,
                                          sk, pk, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_private_key_basic: encode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded == NULL || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_private_key_basic: no encoded data\n");
        result = 1;
        goto cleanup;
    }

    if (encoded[0] != 0x30) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_private_key_basic: invalid tag\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ibm_ml_kem_private_key_basic\n");

cleanup:
    if (sk) free(sk);
    if (pk) free(pk);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_IBM_ML_KEM_PrivateKey with length_only mode */
int test_encode_ibm_ml_kem_private_key_length_only(void)
{
    CK_BYTE sk_data[2400];
    CK_BYTE pk_data[1184];
    CK_ATTRIBUTE *sk = NULL, *pk = NULL;
    CK_ULONG len1 = 0, len2 = 0;
    CK_BYTE *encoded = NULL;
    CK_RV rv;
    int result = 0;

    memset(sk_data, 0x66, sizeof(sk_data));
    memset(pk_data, 0x77, sizeof(pk_data));

    sk = create_attribute(CKA_IBM_ML_KEM_SK, sk_data, sizeof(sk_data));
    pk = create_attribute(CKA_IBM_ML_KEM_PK, pk_data, sizeof(pk_data));

    if (!sk || !pk) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_private_key_length_only: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_KEM_768[];
    extern const CK_ULONG ber_idML_KEM_768Len;

    /* Get length */
    rv = ber_encode_IBM_ML_KEM_PrivateKey(CKM_IBM_ML_KEM, TRUE, NULL, &len1,
                                          ber_idML_KEM_768, ber_idML_KEM_768Len,
                                          sk, pk, NULL);
    if (rv != CKR_OK || len1 == 0) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_private_key_length_only: length calculation failed\n");
        result = 1;
        goto cleanup;
    }

    /* Actual encode */
    rv = ber_encode_IBM_ML_KEM_PrivateKey(CKM_IBM_ML_KEM, FALSE, &encoded, &len2,
                                          ber_idML_KEM_768, ber_idML_KEM_768Len,
                                          sk, pk, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_private_key_length_only: encode failed\n");
        result = 1;
        goto cleanup;
    }

    if (len1 != len2) {
        fprintf(stderr, "[FAIL] test_encode_ibm_ml_kem_private_key_length_only: length mismatch (%lu vs %lu)\n",
                len1, len2);
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ibm_ml_kem_private_key_length_only\n");

cleanup:
    if (sk) free(sk);
    if (pk) free(pk);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_IBM_ML_KEM_PrivateKey with valid encoded data */
int test_decode_ibm_ml_kem_private_key_valid(void)
{
    CK_BYTE sk_data[2400];
    CK_BYTE pk_data[1184];
    CK_ATTRIBUTE *orig_sk = NULL, *orig_pk = NULL;
    CK_ATTRIBUTE *dec_sk = NULL, *dec_pk = NULL;
    CK_ATTRIBUTE *dec_priv_seed = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(sk_data, 0x66, sizeof(sk_data));
    memset(pk_data, 0x77, sizeof(pk_data));

    orig_sk = create_attribute(CKA_IBM_ML_KEM_SK, sk_data, sizeof(sk_data));
    orig_pk = create_attribute(CKA_IBM_ML_KEM_PK, pk_data, sizeof(pk_data));

    if (!orig_sk || !orig_pk) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_kem_private_key_valid: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_KEM_768[];
    extern const CK_ULONG ber_idML_KEM_768Len;

    /* Encode */
    rv = ber_encode_IBM_ML_KEM_PrivateKey(CKM_IBM_ML_KEM, FALSE, &encoded, &encoded_len,
                                          ber_idML_KEM_768, ber_idML_KEM_768Len,
                                          orig_sk, orig_pk, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_kem_private_key_valid: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_IBM_ML_KEM_PrivateKey(CKM_IBM_ML_KEM, encoded, encoded_len,
                                          &dec_sk, &dec_pk, &dec_priv_seed, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_kem_private_key_valid: decode failed with rv=%lu\n", rv);
        result = 1;
        goto cleanup;
    }

    /* Verify decoded data */
    if (!dec_sk || dec_sk->ulValueLen != sizeof(sk_data) ||
        memcmp(dec_sk->pValue, sk_data, sizeof(sk_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_ml_kem_private_key_valid: sk mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_decode_ibm_ml_kem_private_key_valid\n");

cleanup:
    if (orig_sk) free(orig_sk);
    if (orig_pk) free(orig_pk);
    if (dec_sk) free(dec_sk);
    if (dec_pk) free(dec_pk);
    if (dec_priv_seed) free(dec_priv_seed);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-KEM private key encode/decode roundtrip */
int test_roundtrip_ibm_ml_kem_private_key(void)
{
    CK_BYTE sk_data[2400];
    CK_BYTE pk_data[1184];
    CK_ATTRIBUTE *orig_sk = NULL, *orig_pk = NULL;
    CK_ATTRIBUTE *dec_sk = NULL, *dec_pk = NULL;
    CK_ATTRIBUTE *dec_priv_seed = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(sk_data, 0x66, sizeof(sk_data));
    memset(pk_data, 0x77, sizeof(pk_data));

    orig_sk = create_attribute(CKA_IBM_ML_KEM_SK, sk_data, sizeof(sk_data));
    orig_pk = create_attribute(CKA_IBM_ML_KEM_PK, pk_data, sizeof(pk_data));

    if (!orig_sk || !orig_pk) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_kem_private_key: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idML_KEM_768[];
    extern const CK_ULONG ber_idML_KEM_768Len;

    /* Encode */
    rv = ber_encode_IBM_ML_KEM_PrivateKey(CKM_IBM_ML_KEM, FALSE, &encoded, &encoded_len,
                                          ber_idML_KEM_768, ber_idML_KEM_768Len,
                                          orig_sk, orig_pk, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_kem_private_key: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_IBM_ML_KEM_PrivateKey(CKM_IBM_ML_KEM, encoded, encoded_len,
                                          &dec_sk, &dec_pk, &dec_priv_seed, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_kem_private_key: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip */
    if (dec_sk->ulValueLen != sizeof(sk_data) ||
        memcmp(dec_sk->pValue, sk_data, sizeof(sk_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_ml_kem_private_key: sk mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ibm_ml_kem_private_key\n");

cleanup:
    if (orig_sk) free(orig_sk);
    if (orig_pk) free(orig_pk);
    if (dec_sk) free(dec_sk);
    if (dec_pk) free(dec_pk);
    if (dec_priv_seed) free(dec_priv_seed);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* ============================================================================
 * IBM Dilithium Public Key Tests
 * ============================================================================ */

/* Test ber_encode_IBM_DilithiumPublicKey with basic Dilithium R2-65 key components */
int test_encode_ibm_dilithium_public_key_basic(void)
{
    /* Dilithium R2-65 public key components for testing */
    CK_BYTE rho_data[32] = {0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
                            0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
                            0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
                            0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0};
    CK_BYTE t1_data[1728];  /* Dilithium R2-65 t1 size */
    CK_ATTRIBUTE *rho = NULL, *t1 = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize t1 with test data */
    memset(t1_data, 0x52, sizeof(t1_data));

    /* Create attributes */
    rho = create_attribute(CKA_IBM_DILITHIUM_RHO, rho_data, sizeof(rho_data));
    t1 = create_attribute(CKA_IBM_DILITHIUM_T1, t1_data, sizeof(t1_data));

    if (!rho || !t1) {
        fprintf(stderr, "[FAIL] test_encode_ibm_dilithium_public_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Use external OID constant */
    extern const CK_BYTE ber_idDilithium_r2_65[];
    extern const CK_ULONG ber_idDilithium_r2_65Len;

    rv = ber_encode_IBM_ML_DSA_PublicKey(CKM_IBM_DILITHIUM, FALSE, &encoded, &encoded_len,
                                           ber_idDilithium_r2_65, ber_idDilithium_r2_65Len,
                                           rho, t1);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ibm_dilithium_public_key_basic: ber_encode_IBM_DilithiumPublicKey failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ibm_dilithium_public_key_basic: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ibm_dilithium_public_key_basic\n");

cleanup:
    if (rho) free(rho);
    if (t1) free(t1);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_IBM_DilithiumPublicKey with encoded data */
int test_decode_ibm_dilithium_public_key_basic(void)
{
    CK_BYTE rho_data[32] = {0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
                            0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
                            0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
                            0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0};
    CK_BYTE t1_data[1728];
    CK_ATTRIBUTE *rho = NULL, *t1 = NULL;
    CK_ATTRIBUTE *dec_rho = NULL, *dec_t1 = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(t1_data, 0x52, sizeof(t1_data));

    rho = create_attribute(CKA_IBM_DILITHIUM_RHO, rho_data, sizeof(rho_data));
    t1 = create_attribute(CKA_IBM_DILITHIUM_T1, t1_data, sizeof(t1_data));

    if (!rho || !t1) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_public_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idDilithium_r2_65[];
    extern const CK_ULONG ber_idDilithium_r2_65Len;

    rv = ber_encode_IBM_ML_DSA_PublicKey(CKM_IBM_DILITHIUM, FALSE, &encoded, &encoded_len,
                                           ber_idDilithium_r2_65, ber_idDilithium_r2_65Len,
                                           rho, t1);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_public_key_basic: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_decode_IBM_ML_DSA_PublicKey(CKM_IBM_DILITHIUM, encoded, encoded_len,
                                           &dec_rho, &dec_t1, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_public_key_basic: ber_decode_IBM_DilithiumPublicKey failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_rho || !dec_t1) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_public_key_basic: decoded attributes are NULL\n");
        result = 1;
        goto cleanup;
    }

    if (dec_rho->ulValueLen != sizeof(rho_data) ||
        memcmp(dec_rho->pValue, rho_data, sizeof(rho_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_public_key_basic: rho mismatch\n");
        result = 1;
        goto cleanup;
    }

    if (dec_t1->ulValueLen != sizeof(t1_data) ||
        memcmp(dec_t1->pValue, t1_data, sizeof(t1_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_public_key_basic: t1 mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ibm_dilithium_public_key_basic\n");

cleanup:
    if (rho) free(rho);
    if (t1) free(t1);
    if (dec_rho) free(dec_rho);
    if (dec_t1) free(dec_t1);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test Dilithium public key encode/decode roundtrip */
int test_roundtrip_ibm_dilithium_public_key(void)
{
    CK_BYTE rho_data[32] = {0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
                            0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
                            0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
                            0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0};
    CK_BYTE t1_data[1728];
    CK_ATTRIBUTE *orig_rho = NULL, *orig_t1 = NULL;
    CK_ATTRIBUTE *dec_rho = NULL, *dec_t1 = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(t1_data, 0x52, sizeof(t1_data));

    orig_rho = create_attribute(CKA_IBM_DILITHIUM_RHO, rho_data, sizeof(rho_data));
    orig_t1 = create_attribute(CKA_IBM_DILITHIUM_T1, t1_data, sizeof(t1_data));

    if (!orig_rho || !orig_t1) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_dilithium_public_key: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idDilithium_r2_65[];
    extern const CK_ULONG ber_idDilithium_r2_65Len;

    rv = ber_encode_IBM_ML_DSA_PublicKey(CKM_IBM_DILITHIUM, FALSE, &encoded, &encoded_len,
                                           ber_idDilithium_r2_65, ber_idDilithium_r2_65Len,
                                           orig_rho, orig_t1);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_dilithium_public_key: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_decode_IBM_ML_DSA_PublicKey(CKM_IBM_DILITHIUM, encoded, encoded_len,
                                           &dec_rho, &dec_t1, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_dilithium_public_key: decoding failed\n");
        result = 1;
        goto cleanup;
    }

    if (dec_rho->ulValueLen != orig_rho->ulValueLen ||
        memcmp(dec_rho->pValue, orig_rho->pValue, orig_rho->ulValueLen) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_dilithium_public_key: rho roundtrip failed\n");
        result = 1;
        goto cleanup;
    }

    if (dec_t1->ulValueLen != orig_t1->ulValueLen ||
        memcmp(dec_t1->pValue, orig_t1->pValue, orig_t1->ulValueLen) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_dilithium_public_key: t1 roundtrip failed\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_roundtrip_ibm_dilithium_public_key\n");

cleanup:
    if (orig_rho) free(orig_rho);
    if (orig_t1) free(orig_t1);
    if (dec_rho) free(dec_rho);
    if (dec_t1) free(dec_t1);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* ============================================================================
 * IBM Dilithium Private Key Tests
 * ============================================================================ */

/* Test ber_encode_IBM_DilithiumPrivateKey with basic Dilithium R2-65 key components */
int test_encode_ibm_dilithium_private_key_basic(void)
{
    /* Dilithium R2-65 private key components for testing */
    CK_BYTE rho_data[32] = {0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
                            0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
                            0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
                            0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0};
    CK_BYTE seed_data[32];
    CK_BYTE tr_data[48];
    CK_BYTE s1_data[480];
    CK_BYTE s2_data[576];
    CK_BYTE t0_data[2688];
    CK_BYTE t1_data[1728];
    CK_ATTRIBUTE *rho = NULL, *seed = NULL, *tr = NULL;
    CK_ATTRIBUTE *s1 = NULL, *s2 = NULL, *t0 = NULL, *t1 = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize test data */
    memset(seed_data, 0x53, sizeof(seed_data));
    memset(tr_data, 0x54, sizeof(tr_data));
    memset(s1_data, 0x55, sizeof(s1_data));
    memset(s2_data, 0x56, sizeof(s2_data));
    memset(t0_data, 0x57, sizeof(t0_data));
    memset(t1_data, 0x58, sizeof(t1_data));

    /* Create attributes */
    rho = create_attribute(CKA_IBM_DILITHIUM_RHO, rho_data, sizeof(rho_data));
    seed = create_attribute(CKA_IBM_DILITHIUM_SEED, seed_data, sizeof(seed_data));
    tr = create_attribute(CKA_IBM_DILITHIUM_TR, tr_data, sizeof(tr_data));
    s1 = create_attribute(CKA_IBM_DILITHIUM_S1, s1_data, sizeof(s1_data));
    s2 = create_attribute(CKA_IBM_DILITHIUM_S2, s2_data, sizeof(s2_data));
    t0 = create_attribute(CKA_IBM_DILITHIUM_T0, t0_data, sizeof(t0_data));
    t1 = create_attribute(CKA_IBM_DILITHIUM_T1, t1_data, sizeof(t1_data));

    if (!rho || !seed || !tr || !s1 || !s2 || !t0 || !t1) {
        fprintf(stderr, "[FAIL] test_encode_ibm_dilithium_private_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idDilithium_r2_65[];
    extern const CK_ULONG ber_idDilithium_r2_65Len;

    rv = ber_encode_IBM_ML_DSA_PrivateKey(CKM_IBM_DILITHIUM, FALSE, &encoded, &encoded_len,
                                            ber_idDilithium_r2_65, ber_idDilithium_r2_65Len,
                                            rho, seed, tr, s1, s2, t0, t1, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ibm_dilithium_private_key_basic: ber_encode_IBM_DilithiumPrivateKey failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ibm_dilithium_private_key_basic: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ibm_dilithium_private_key_basic\n");

cleanup:
    if (rho) free(rho);
    if (seed) free(seed);
    if (tr) free(tr);
    if (s1) free(s1);
    if (s2) free(s2);
    if (t0) free(t0);
    if (t1) free(t1);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_IBM_DilithiumPrivateKey with encoded data */
int test_decode_ibm_dilithium_private_key_basic(void)
{
    CK_BYTE rho_data[32] = {0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
                            0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
                            0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
                            0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0};
    CK_BYTE seed_data[32], tr_data[48], s1_data[480], s2_data[576], t0_data[2688], t1_data[1728];
    CK_ATTRIBUTE *rho = NULL, *seed = NULL, *tr = NULL, *s1 = NULL, *s2 = NULL, *t0 = NULL, *t1 = NULL;
    CK_ATTRIBUTE *dec_rho = NULL, *dec_seed = NULL, *dec_tr = NULL;
    CK_ATTRIBUTE *dec_s1 = NULL, *dec_s2 = NULL, *dec_t0 = NULL, *dec_t1 = NULL, *dec_value = NULL;
    CK_ATTRIBUTE *dec_priv_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(seed_data, 0x53, sizeof(seed_data));
    memset(tr_data, 0x54, sizeof(tr_data));
    memset(s1_data, 0x55, sizeof(s1_data));
    memset(s2_data, 0x56, sizeof(s2_data));
    memset(t0_data, 0x57, sizeof(t0_data));
    memset(t1_data, 0x58, sizeof(t1_data));

    rho = create_attribute(CKA_IBM_DILITHIUM_RHO, rho_data, sizeof(rho_data));
    seed = create_attribute(CKA_IBM_DILITHIUM_SEED, seed_data, sizeof(seed_data));
    tr = create_attribute(CKA_IBM_DILITHIUM_TR, tr_data, sizeof(tr_data));
    s1 = create_attribute(CKA_IBM_DILITHIUM_S1, s1_data, sizeof(s1_data));
    s2 = create_attribute(CKA_IBM_DILITHIUM_S2, s2_data, sizeof(s2_data));
    t0 = create_attribute(CKA_IBM_DILITHIUM_T0, t0_data, sizeof(t0_data));
    t1 = create_attribute(CKA_IBM_DILITHIUM_T1, t1_data, sizeof(t1_data));

    if (!rho || !seed || !tr || !s1 || !s2 || !t0 || !t1) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_private_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idDilithium_r2_65[];
    extern const CK_ULONG ber_idDilithium_r2_65Len;

    rv = ber_encode_IBM_ML_DSA_PrivateKey(CKM_IBM_DILITHIUM, FALSE, &encoded, &encoded_len,
                                            ber_idDilithium_r2_65, ber_idDilithium_r2_65Len,
                                            rho, seed, tr, s1, s2, t0, t1, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_private_key_basic: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_decode_IBM_ML_DSA_PrivateKey(CKM_IBM_DILITHIUM, encoded, encoded_len,
                                            &dec_rho, &dec_seed, &dec_tr,
                                            &dec_s1, &dec_s2, &dec_t0, &dec_t1,
                                            &dec_priv_seed, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_private_key_basic: ber_decode_IBM_DilithiumPrivateKey failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_rho || !dec_seed || !dec_tr || !dec_s1 || !dec_s2 || !dec_t0 || !dec_t1) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_private_key_basic: decoded attributes are NULL\n");
        result = 1;
        goto cleanup;
    }

    if (dec_rho->ulValueLen != sizeof(rho_data) ||
        memcmp(dec_rho->pValue, rho_data, sizeof(rho_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_dilithium_private_key_basic: rho mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ibm_dilithium_private_key_basic\n");

cleanup:
    if (rho) free(rho);
    if (seed) free(seed);
    if (tr) free(tr);
    if (s1) free(s1);
    if (s2) free(s2);
    if (t0) free(t0);
    if (t1) free(t1);
    if (dec_rho) free(dec_rho);
    if (dec_seed) free(dec_seed);
    if (dec_tr) free(dec_tr);
    if (dec_s1) free(dec_s1);
    if (dec_s2) free(dec_s2);
    if (dec_t0) free(dec_t0);
    if (dec_t1) free(dec_t1);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test Dilithium private key encode/decode roundtrip */
int test_roundtrip_ibm_dilithium_private_key(void)
{
    CK_BYTE rho_data[32] = {0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
                            0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
                            0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
                            0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0};
    CK_BYTE seed_data[32], tr_data[48], s1_data[480], s2_data[576], t0_data[2688], t1_data[1728];
    CK_ATTRIBUTE *orig_rho = NULL, *orig_seed = NULL, *orig_tr = NULL;
    CK_ATTRIBUTE *orig_s1 = NULL, *orig_s2 = NULL, *orig_t0 = NULL, *orig_t1 = NULL;
    CK_ATTRIBUTE *dec_rho = NULL, *dec_seed = NULL, *dec_tr = NULL;
    CK_ATTRIBUTE *dec_s1 = NULL, *dec_s2 = NULL, *dec_t0 = NULL, *dec_t1 = NULL, *dec_value = NULL;
    CK_ATTRIBUTE *dec_priv_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(seed_data, 0x53, sizeof(seed_data));
    memset(tr_data, 0x54, sizeof(tr_data));
    memset(s1_data, 0x55, sizeof(s1_data));
    memset(s2_data, 0x56, sizeof(s2_data));
    memset(t0_data, 0x57, sizeof(t0_data));
    memset(t1_data, 0x58, sizeof(t1_data));

    orig_rho = create_attribute(CKA_IBM_DILITHIUM_RHO, rho_data, sizeof(rho_data));
    orig_seed = create_attribute(CKA_IBM_DILITHIUM_SEED, seed_data, sizeof(seed_data));
    orig_tr = create_attribute(CKA_IBM_DILITHIUM_TR, tr_data, sizeof(tr_data));
    orig_s1 = create_attribute(CKA_IBM_DILITHIUM_S1, s1_data, sizeof(s1_data));
    orig_s2 = create_attribute(CKA_IBM_DILITHIUM_S2, s2_data, sizeof(s2_data));
    orig_t0 = create_attribute(CKA_IBM_DILITHIUM_T0, t0_data, sizeof(t0_data));
    orig_t1 = create_attribute(CKA_IBM_DILITHIUM_T1, t1_data, sizeof(t1_data));

    if (!orig_rho || !orig_seed || !orig_tr || !orig_s1 || !orig_s2 || !orig_t0 || !orig_t1) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_dilithium_private_key: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idDilithium_r2_65[];
    extern const CK_ULONG ber_idDilithium_r2_65Len;

    rv = ber_encode_IBM_ML_DSA_PrivateKey(CKM_IBM_DILITHIUM, FALSE, &encoded, &encoded_len,
                                            ber_idDilithium_r2_65, ber_idDilithium_r2_65Len,
                                            orig_rho, orig_seed, orig_tr,
                                            orig_s1, orig_s2, orig_t0, orig_t1, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_dilithium_private_key: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_decode_IBM_ML_DSA_PrivateKey(CKM_IBM_DILITHIUM, encoded, encoded_len,
                                            &dec_rho, &dec_seed, &dec_tr,
                                            &dec_s1, &dec_s2, &dec_t0, &dec_t1,
                                            &dec_priv_seed, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_dilithium_private_key: decoding failed\n");
        result = 1;
        goto cleanup;
    }

    if (dec_rho->ulValueLen != orig_rho->ulValueLen ||
        memcmp(dec_rho->pValue, orig_rho->pValue, orig_rho->ulValueLen) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_dilithium_private_key: rho roundtrip failed\n");
        result = 1;
        goto cleanup;
    }

    if (dec_s1->ulValueLen != orig_s1->ulValueLen ||
        memcmp(dec_s1->pValue, orig_s1->pValue, orig_s1->ulValueLen) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_dilithium_private_key: s1 roundtrip failed\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_roundtrip_ibm_dilithium_private_key\n");

cleanup:
    if (orig_rho) free(orig_rho);
    if (orig_seed) free(orig_seed);
    if (orig_tr) free(orig_tr);
    if (orig_s1) free(orig_s1);
    if (orig_s2) free(orig_s2);
    if (orig_t0) free(orig_t0);
    if (orig_t1) free(orig_t1);
    if (dec_rho) free(dec_rho);
    if (dec_seed) free(dec_seed);
    if (dec_tr) free(dec_tr);
    if (dec_s1) free(dec_s1);
    if (dec_s2) free(dec_s2);
    if (dec_t0) free(dec_t0);
    if (dec_t1) free(dec_t1);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test Dilithium private key with NULL optional attributes */
int test_ibm_dilithium_private_key_null_optional(void)
{
    CK_BYTE rho_data[32] = {0xD1, 0xD2, 0xD3, 0xD4, 0xD5, 0xD6, 0xD7, 0xD8,
                            0xD9, 0xDA, 0xDB, 0xDC, 0xDD, 0xDE, 0xDF, 0xE0,
                            0xE1, 0xE2, 0xE3, 0xE4, 0xE5, 0xE6, 0xE7, 0xE8,
                            0xE9, 0xEA, 0xEB, 0xEC, 0xED, 0xEE, 0xEF, 0xF0};
    CK_BYTE seed_data[32], tr_data[48], s1_data[480], s2_data[576], t0_data[2688];
    CK_ATTRIBUTE *rho = NULL, *seed = NULL, *tr = NULL, *s1 = NULL, *s2 = NULL, *t0 = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(seed_data, 0x53, sizeof(seed_data));
    memset(tr_data, 0x54, sizeof(tr_data));
    memset(s1_data, 0x55, sizeof(s1_data));
    memset(s2_data, 0x56, sizeof(s2_data));
    memset(t0_data, 0x57, sizeof(t0_data));

    rho = create_attribute(CKA_IBM_DILITHIUM_RHO, rho_data, sizeof(rho_data));
    seed = create_attribute(CKA_IBM_DILITHIUM_SEED, seed_data, sizeof(seed_data));
    tr = create_attribute(CKA_IBM_DILITHIUM_TR, tr_data, sizeof(tr_data));
    s1 = create_attribute(CKA_IBM_DILITHIUM_S1, s1_data, sizeof(s1_data));
    s2 = create_attribute(CKA_IBM_DILITHIUM_S2, s2_data, sizeof(s2_data));
    t0 = create_attribute(CKA_IBM_DILITHIUM_T0, t0_data, sizeof(t0_data));

    if (!rho || !seed || !tr || !s1 || !s2 || !t0) {
        fprintf(stderr, "[FAIL] test_ibm_dilithium_private_key_null_optional: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idDilithium_r2_65[];
    extern const CK_ULONG ber_idDilithium_r2_65Len;

    /* Test with NULL t1 (optional) */
    rv = ber_encode_IBM_ML_DSA_PrivateKey(CKM_IBM_DILITHIUM, FALSE, &encoded, &encoded_len,
                                            ber_idDilithium_r2_65, ber_idDilithium_r2_65Len,
                                            rho, seed, tr, s1, s2, t0, NULL, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_ibm_dilithium_private_key_null_optional: encoding with NULL t1 failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_ibm_dilithium_private_key_null_optional: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_ibm_dilithium_private_key_null_optional\n");

cleanup:
    if (rho) free(rho);
    if (seed) free(seed);
    if (tr) free(tr);
    if (s1) free(s1);
    if (s2) free(s2);
    if (t0) free(t0);
    if (encoded) free(encoded);
    return result;
}

/* ============================================================================
 * IBM Kyber Public Key Tests
 * ============================================================================ */

/* Test ber_encode_IBM_KyberPublicKey with basic Kyber R2-1024 key components */
int test_encode_ibm_kyber_public_key_basic(void)
{
    /* Kyber R2-1024 public key for testing */
    CK_BYTE pk_data[1568];  /* Kyber R2-1024 pk size */
    CK_ATTRIBUTE *pk = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize pk with test data */
    memset(pk_data, 0x4B, sizeof(pk_data));

    /* Create attribute */
    pk = create_attribute(CKA_IBM_KYBER_PK, pk_data, sizeof(pk_data));

    if (!pk) {
        fprintf(stderr, "[FAIL] test_encode_ibm_kyber_public_key_basic: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Use external OID constant */
    extern const CK_BYTE ber_idKyber_r2_1024[];
    extern const CK_ULONG ber_idKyber_r2_1024Len;

    rv = ber_encode_IBM_ML_KEM_PublicKey(CKM_IBM_KYBER, FALSE, &encoded, &encoded_len,
                                       ber_idKyber_r2_1024, ber_idKyber_r2_1024Len,
                                       pk);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ibm_kyber_public_key_basic: ber_encode_IBM_KyberPublicKey failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ibm_kyber_public_key_basic: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ibm_kyber_public_key_basic\n");

cleanup:
    if (pk) free(pk);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_IBM_KyberPublicKey with encoded data */
int test_decode_ibm_kyber_public_key_basic(void)
{
    CK_BYTE pk_data[1568];
    CK_ATTRIBUTE *pk = NULL;
    CK_ATTRIBUTE *dec_pk = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(pk_data, 0x4B, sizeof(pk_data));

    pk = create_attribute(CKA_IBM_KYBER_PK, pk_data, sizeof(pk_data));

    if (!pk) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_public_key_basic: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idKyber_r2_1024[];
    extern const CK_ULONG ber_idKyber_r2_1024Len;

    rv = ber_encode_IBM_ML_KEM_PublicKey(CKM_IBM_KYBER, FALSE, &encoded, &encoded_len,
                                       ber_idKyber_r2_1024, ber_idKyber_r2_1024Len,
                                       pk);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_public_key_basic: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_decode_IBM_ML_KEM_PublicKey(CKM_IBM_KYBER, encoded, encoded_len,
                                       &dec_pk, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_public_key_basic: ber_decode_IBM_KyberPublicKey failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_pk) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_public_key_basic: decoded attribute is NULL\n");
        result = 1;
        goto cleanup;
    }

    if (dec_pk->ulValueLen != sizeof(pk_data) ||
        memcmp(dec_pk->pValue, pk_data, sizeof(pk_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_public_key_basic: pk mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ibm_kyber_public_key_basic\n");

cleanup:
    if (pk) free(pk);
    if (dec_pk) free(dec_pk);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test Kyber public key encode/decode roundtrip */
int test_roundtrip_ibm_kyber_public_key(void)
{
    CK_BYTE pk_data[1568];
    CK_ATTRIBUTE *orig_pk = NULL;
    CK_ATTRIBUTE *dec_pk = NULL, *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(pk_data, 0x4B, sizeof(pk_data));

    orig_pk = create_attribute(CKA_IBM_KYBER_PK, pk_data, sizeof(pk_data));

    if (!orig_pk) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_kyber_public_key: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idKyber_r2_1024[];
    extern const CK_ULONG ber_idKyber_r2_1024Len;

    rv = ber_encode_IBM_ML_KEM_PublicKey(CKM_IBM_KYBER, FALSE, &encoded, &encoded_len,
                                       ber_idKyber_r2_1024, ber_idKyber_r2_1024Len,
                                       orig_pk);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_kyber_public_key: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_decode_IBM_ML_KEM_PublicKey(CKM_IBM_KYBER, encoded, encoded_len,
                                       &dec_pk, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_kyber_public_key: decoding failed\n");
        result = 1;
        goto cleanup;
    }

    if (dec_pk->ulValueLen != orig_pk->ulValueLen ||
        memcmp(dec_pk->pValue, orig_pk->pValue, orig_pk->ulValueLen) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_kyber_public_key: pk roundtrip failed\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_roundtrip_ibm_kyber_public_key\n");

cleanup:
    if (orig_pk) free(orig_pk);
    if (dec_pk) free(dec_pk);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* ============================================================================
 * IBM Kyber Private Key Tests
 * ============================================================================ */

/* Test ber_encode_IBM_KyberPrivateKey with basic Kyber R2-1024 key components */
int test_encode_ibm_kyber_private_key_basic(void)
{
    /* Kyber R2-1024 private key components for testing */
    CK_BYTE sk_data[3168];  /* Kyber R2-1024 sk size */
    CK_BYTE pk_data[1568];  /* Kyber R2-1024 pk size */
    CK_ATTRIBUTE *sk = NULL, *pk = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize test data */
    memset(sk_data, 0x4C, sizeof(sk_data));
    memset(pk_data, 0x4D, sizeof(pk_data));

    /* Create attributes */
    sk = create_attribute(CKA_IBM_KYBER_SK, sk_data, sizeof(sk_data));
    pk = create_attribute(CKA_IBM_KYBER_PK, pk_data, sizeof(pk_data));

    if (!sk || !pk) {
        fprintf(stderr, "[FAIL] test_encode_ibm_kyber_private_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idKyber_r2_1024[];
    extern const CK_ULONG ber_idKyber_r2_1024Len;

    rv = ber_encode_IBM_ML_KEM_PrivateKey(CKM_IBM_KYBER, FALSE, &encoded, &encoded_len,
                                        ber_idKyber_r2_1024, ber_idKyber_r2_1024Len,
                                        sk, pk, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ibm_kyber_private_key_basic: ber_encode_IBM_KyberPrivateKey failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ibm_kyber_private_key_basic: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ibm_kyber_private_key_basic\n");

cleanup:
    if (sk) free(sk);
    if (pk) free(pk);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_IBM_KyberPrivateKey with encoded data */
int test_decode_ibm_kyber_private_key_basic(void)
{
    CK_BYTE sk_data[3168];
    CK_BYTE pk_data[1568];
    CK_ATTRIBUTE *sk = NULL, *pk = NULL;
    CK_ATTRIBUTE *dec_sk = NULL, *dec_pk = NULL, *dec_value = NULL;
    CK_ATTRIBUTE *dec_priv_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(sk_data, 0x4C, sizeof(sk_data));
    memset(pk_data, 0x4D, sizeof(pk_data));

    sk = create_attribute(CKA_IBM_KYBER_SK, sk_data, sizeof(sk_data));
    pk = create_attribute(CKA_IBM_KYBER_PK, pk_data, sizeof(pk_data));

    if (!sk || !pk) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_private_key_basic: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idKyber_r2_1024[];
    extern const CK_ULONG ber_idKyber_r2_1024Len;

    rv = ber_encode_IBM_ML_KEM_PrivateKey(CKM_IBM_KYBER, FALSE, &encoded, &encoded_len,
                                        ber_idKyber_r2_1024, ber_idKyber_r2_1024Len,
                                        sk, pk, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_private_key_basic: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_decode_IBM_ML_KEM_PrivateKey(CKM_IBM_KYBER, encoded, encoded_len,
                                        &dec_sk, &dec_pk, &dec_priv_seed, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_private_key_basic: ber_decode_IBM_KyberPrivateKey failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_sk || !dec_pk) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_private_key_basic: decoded attributes are NULL\n");
        result = 1;
        goto cleanup;
    }

    if (dec_sk->ulValueLen != sizeof(sk_data) ||
        memcmp(dec_sk->pValue, sk_data, sizeof(sk_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_private_key_basic: sk mismatch\n");
        result = 1;
        goto cleanup;
    }

    if (dec_pk->ulValueLen != sizeof(pk_data) ||
        memcmp(dec_pk->pValue, pk_data, sizeof(pk_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ibm_kyber_private_key_basic: pk mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ibm_kyber_private_key_basic\n");

cleanup:
    if (sk) free(sk);
    if (pk) free(pk);
    if (dec_sk) free(dec_sk);
    if (dec_pk) free(dec_pk);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test Kyber private key encode/decode roundtrip */
int test_roundtrip_ibm_kyber_private_key(void)
{
    CK_BYTE sk_data[3168];
    CK_BYTE pk_data[1568];
    CK_ATTRIBUTE *orig_sk = NULL, *orig_pk = NULL;
    CK_ATTRIBUTE *dec_sk = NULL, *dec_pk = NULL, *dec_value = NULL;
    CK_ATTRIBUTE *dec_priv_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(sk_data, 0x4C, sizeof(sk_data));
    memset(pk_data, 0x4D, sizeof(pk_data));

    orig_sk = create_attribute(CKA_IBM_KYBER_SK, sk_data, sizeof(sk_data));
    orig_pk = create_attribute(CKA_IBM_KYBER_PK, pk_data, sizeof(pk_data));

    if (!orig_sk || !orig_pk) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_kyber_private_key: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idKyber_r2_1024[];
    extern const CK_ULONG ber_idKyber_r2_1024Len;

    rv = ber_encode_IBM_ML_KEM_PrivateKey(CKM_IBM_KYBER, FALSE, &encoded, &encoded_len,
                                        ber_idKyber_r2_1024, ber_idKyber_r2_1024Len,
                                        orig_sk, orig_pk, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_kyber_private_key: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    rv = ber_decode_IBM_ML_KEM_PrivateKey(CKM_IBM_KYBER, encoded, encoded_len,
                                        &dec_sk, &dec_pk, &dec_priv_seed, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_kyber_private_key: decoding failed\n");
        result = 1;
        goto cleanup;
    }

    if (dec_sk->ulValueLen != orig_sk->ulValueLen ||
        memcmp(dec_sk->pValue, orig_sk->pValue, orig_sk->ulValueLen) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_kyber_private_key: sk roundtrip failed\n");
        result = 1;
        goto cleanup;
    }

    if (dec_pk->ulValueLen != orig_pk->ulValueLen ||
        memcmp(dec_pk->pValue, orig_pk->pValue, orig_pk->ulValueLen) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ibm_kyber_private_key: pk roundtrip failed\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_roundtrip_ibm_kyber_private_key\n");

cleanup:
    if (orig_sk) free(orig_sk);
    if (orig_pk) free(orig_pk);
    if (dec_sk) free(dec_sk);
    if (dec_pk) free(dec_pk);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test Kyber private key with NULL optional attributes */
int test_ibm_kyber_private_key_null_optional(void)
{
    CK_BYTE sk_data[3168];
    CK_ATTRIBUTE *sk = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(sk_data, 0x4C, sizeof(sk_data));

    sk = create_attribute(CKA_IBM_KYBER_SK, sk_data, sizeof(sk_data));

    if (!sk) {
        fprintf(stderr, "[FAIL] test_ibm_kyber_private_key_null_optional: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    extern const CK_BYTE ber_idKyber_r2_1024[];
    extern const CK_ULONG ber_idKyber_r2_1024Len;

    /* Test with NULL pk (optional) */
    rv = ber_encode_IBM_ML_KEM_PrivateKey(CKM_IBM_KYBER, FALSE, &encoded, &encoded_len,
                                        ber_idKyber_r2_1024, ber_idKyber_r2_1024Len,
                                        sk, NULL, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_ibm_kyber_private_key_null_optional: encoding with NULL pk failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_ibm_kyber_private_key_null_optional: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_ibm_kyber_private_key_null_optional\n");

cleanup:
    if (sk) free(sk);
    if (encoded) free(encoded);
    return result;
}

/* ============================================================================
 * ML-DSA (NIST standardized) Tests
 * ============================================================================ */

/* Test ber_encode_ML_DSA_PublicKey with basic ML-DSA-65 key */
int test_encode_ml_dsa_public_key_basic(void)
{
    /* ML-DSA-65 public key value for testing (1952 bytes) */
    CK_BYTE value_data[1952];
    CK_ATTRIBUTE *value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize value with test data */
    memset(value_data, 0xA5, sizeof(value_data));

    /* Create attribute */
    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!value) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_public_key_basic: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with ML-DSA-65 OID */
    rv = ber_encode_ML_DSA_PublicKey(FALSE, &encoded, &encoded_len,
                                      ber_idML_DSA_65, ber_idML_DSA_65Len,
                                      value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_public_key_basic: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_public_key_basic: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_dsa_public_key_basic\n");

cleanup:
    if (value) free(value);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_ML_DSA_PublicKey with valid encoded data */
int test_decode_ml_dsa_public_key_valid(void)
{
    CK_BYTE value_data[1952];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0xB6, sizeof(value_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_value) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_public_key_valid: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* First encode */
    rv = ber_encode_ML_DSA_PublicKey(FALSE, &encoded, &encoded_len,
                                      ber_idML_DSA_65, ber_idML_DSA_65Len,
                                      orig_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_public_key_valid: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_ML_DSA_PublicKey(encoded, encoded_len, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_public_key_valid: decoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_value || !oid) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_public_key_valid: decode produced NULL output\n");
        result = 1;
        goto cleanup;
    }

    /* Verify decoded value matches original */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_public_key_valid: value mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ml_dsa_public_key_valid\n");

cleanup:
    if (orig_value) free(orig_value);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-DSA public key encode/decode roundtrip */
int test_roundtrip_ml_dsa_public_key(void)
{
    CK_BYTE value_data[1952];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0xC7, sizeof(value_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_value) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_public_key: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_ML_DSA_PublicKey(FALSE, &encoded, &encoded_len,
                                      ber_idML_DSA_65, ber_idML_DSA_65Len,
                                      orig_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_public_key: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_ML_DSA_PublicKey(encoded, encoded_len, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_public_key: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_public_key: value mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ml_dsa_public_key\n");

cleanup:
    if (orig_value) free(orig_value);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_DSA_PrivateKey with basic ML-DSA-65 key */
int test_encode_ml_dsa_private_key_basic(void)
{
    /* ML-DSA-65 private key value for testing (4032 bytes) */
    CK_BYTE value_data[4032];
    CK_ATTRIBUTE *value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize value with test data */
    memset(value_data, 0xD8, sizeof(value_data));

    /* Create attribute */
    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!value) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_basic: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with ML-DSA-65 OID */
    rv = ber_encode_ML_DSA_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       value, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_basic: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_basic: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_dsa_private_key_basic\n");

cleanup:
    if (value) free(value);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_DSA_PrivateKey with length_only mode */
int test_encode_ml_dsa_private_key_length_only(void)
{
    CK_BYTE value_data[4032];
    CK_ATTRIBUTE *value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0xE9, sizeof(value_data));

    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!value) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_length_only: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with length_only = TRUE */
    rv = ber_encode_ML_DSA_PrivateKey(TRUE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       value, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_length_only: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_length_only: encoded should be NULL in length_only mode\n");
        result = 1;
        goto cleanup;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_length_only: encoded_len should be non-zero\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_dsa_private_key_length_only\n");

cleanup:
    if (value) free(value);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_ML_DSA_PrivateKey with valid encoded data */
int test_decode_ml_dsa_private_key_valid(void)
{
    CK_BYTE value_data[4032];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0xFA, sizeof(value_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_value) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_valid: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* First encode */
    rv = ber_encode_ML_DSA_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       orig_value, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_valid: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_ML_DSA_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_valid: decoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_value || !oid) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_valid: decode produced NULL output\n");
        result = 1;
        goto cleanup;
    }

    /* Verify decoded value matches original */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_valid: value mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ml_dsa_private_key_valid\n");

cleanup:
    if (orig_value) free(orig_value);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-DSA private key encode/decode roundtrip */
int test_roundtrip_ml_dsa_private_key(void)
{
    CK_BYTE value_data[4032];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0x0B, sizeof(value_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_value) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_ML_DSA_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       orig_value, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_ML_DSA_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key: value mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ml_dsa_private_key\n");

cleanup:
    if (orig_value) free(orig_value);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_DSA_PrivateKey with seed value */
int test_encode_ml_dsa_private_key_with_seed(void)
{
    /* ML-DSA-65 private key value for testing (4032 bytes) */
    CK_BYTE value_data[4032];
    CK_BYTE seed_data[32];  /* Seed is 32 bytes */
    CK_ATTRIBUTE *value = NULL;
    CK_ATTRIBUTE *seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize value and seed with test data */
    memset(value_data, 0xD8, sizeof(value_data));
    memset(seed_data, 0xAB, sizeof(seed_data));

    /* Create attributes */
    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));
    seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!value || !seed) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_with_seed: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with ML-DSA-65 OID and seed */
    rv = ber_encode_ML_DSA_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       value, seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_with_seed: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_with_seed: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_dsa_private_key_with_seed\n");

cleanup:
    if (value) free(value);
    if (seed) free(seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_DSA_PrivateKey with seed in length_only mode */
int test_encode_ml_dsa_private_key_with_seed_length_only(void)
{
    CK_BYTE value_data[4032];
    CK_BYTE seed_data[32];
    CK_ATTRIBUTE *value = NULL;
    CK_ATTRIBUTE *seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0xE9, sizeof(value_data));
    memset(seed_data, 0xCD, sizeof(seed_data));

    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));
    seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!value || !seed) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_with_seed_length_only: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with length_only = TRUE and seed */
    rv = ber_encode_ML_DSA_PrivateKey(TRUE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       value, seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_with_seed_length_only: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_with_seed_length_only: encoded should be NULL in length_only mode\n");
        result = 1;
        goto cleanup;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_with_seed_length_only: encoded_len should be non-zero\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_dsa_private_key_with_seed_length_only\n");

cleanup:
    if (value) free(value);
    if (seed) free(seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_ML_DSA_PrivateKey with seed in encoded data */
int test_decode_ml_dsa_private_key_with_seed(void)
{
    CK_BYTE value_data[4032];
    CK_BYTE seed_data[32];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *orig_seed = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0xFA, sizeof(value_data));
    memset(seed_data, 0xEF, sizeof(seed_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));
    orig_seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!orig_value || !orig_seed) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_with_seed: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* First encode with seed */
    rv = ber_encode_ML_DSA_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       orig_value, orig_seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_with_seed: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_ML_DSA_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_with_seed: decoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_value || !dec_seed || !oid) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_with_seed: decode produced NULL output\n");
        result = 1;
        goto cleanup;
    }

    /* Verify decoded value matches original */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_with_seed: value mismatch\n");
        result = 1;
        goto cleanup;
    }

    /* Verify decoded seed matches original */
    if (dec_seed->ulValueLen != sizeof(seed_data) ||
        memcmp(dec_seed->pValue, seed_data, sizeof(seed_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_with_seed: seed mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ml_dsa_private_key_with_seed\n");

cleanup:
    if (orig_value) free(orig_value);
    if (orig_seed) free(orig_seed);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-DSA private key with seed encode/decode roundtrip */
int test_roundtrip_ml_dsa_private_key_with_seed(void)
{
    CK_BYTE value_data[4032];
    CK_BYTE seed_data[32];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *orig_seed = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0x0B, sizeof(value_data));
    memset(seed_data, 0x12, sizeof(seed_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));
    orig_seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!orig_value || !orig_seed) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key_with_seed: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with seed */
    rv = ber_encode_ML_DSA_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       orig_value, orig_seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key_with_seed: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_ML_DSA_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key_with_seed: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip for value */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key_with_seed: value mismatch\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip for seed */
    if (dec_seed->ulValueLen != sizeof(seed_data) ||
        memcmp(dec_seed->pValue, seed_data, sizeof(seed_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key_with_seed: seed mismatch\n");
        result = 1;
        goto cleanup;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ml_dsa_private_key_with_seed\n");

cleanup:
    if (orig_value) free(orig_value);
    if (orig_seed) free(orig_seed);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_DSA_PrivateKey with seed-only (no value) */
int test_encode_ml_dsa_private_key_seed_only(void)
{
    /* ML-DSA-65 seed for testing (32 bytes) */
    CK_BYTE seed_data[32];
    CK_ATTRIBUTE *seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize seed with test data */
    memset(seed_data, 0xAB, sizeof(seed_data));

    /* Create seed attribute */
    seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!seed) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_seed_only: failed to create seed attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with ML-DSA-65 OID, NULL value, and seed */
    rv = ber_encode_ML_DSA_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       NULL, seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_seed_only: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_seed_only: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_dsa_private_key_seed_only\n");

cleanup:
    if (seed) free(seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_DSA_PrivateKey with seed-only in length_only mode */
int test_encode_ml_dsa_private_key_seed_only_length_only(void)
{
    CK_BYTE seed_data[32];
    CK_ATTRIBUTE *seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(seed_data, 0xCD, sizeof(seed_data));

    seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!seed) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_seed_only_length_only: failed to create seed attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with length_only = TRUE, NULL value, and seed */
    rv = ber_encode_ML_DSA_PrivateKey(TRUE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       NULL, seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_seed_only_length_only: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_seed_only_length_only: encoded should be NULL in length_only mode\n");
        result = 1;
        goto cleanup;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_dsa_private_key_seed_only_length_only: encoded_len should be non-zero\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_dsa_private_key_seed_only_length_only\n");

cleanup:
    if (seed) free(seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_ML_DSA_PrivateKey with seed-only in encoded data */
int test_decode_ml_dsa_private_key_seed_only(void)
{
    CK_BYTE seed_data[32];
    CK_ATTRIBUTE *orig_seed = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(seed_data, 0xEF, sizeof(seed_data));

    orig_seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!orig_seed) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_seed_only: failed to create seed attribute\n");
        result = 1;
        goto cleanup;
    }

    /* First encode with NULL value and seed */
    rv = ber_encode_ML_DSA_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       NULL, orig_seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_seed_only: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_ML_DSA_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_seed_only: decoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_seed || !oid) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_seed_only: decode produced NULL output\n");
        result = 1;
        goto cleanup;
    }

    /* Verify decoded seed matches original */
    if (dec_seed->ulValueLen != sizeof(seed_data) ||
        memcmp(dec_seed->pValue, seed_data, sizeof(seed_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_seed_only: seed mismatch\n");
        result = 1;
        goto cleanup;
    }

    /* Value should be NULL for seed-only keys */
    if (dec_value != NULL) {
        fprintf(stderr, "[FAIL] test_decode_ml_dsa_private_key_seed_only: value should be NULL for seed-only key\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ml_dsa_private_key_seed_only\n");

cleanup:
    if (orig_seed) free(orig_seed);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-DSA private key seed-only encode/decode roundtrip */
int test_roundtrip_ml_dsa_private_key_seed_only(void)
{
    CK_BYTE seed_data[32];
    CK_ATTRIBUTE *orig_seed = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(seed_data, 0x12, sizeof(seed_data));

    orig_seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!orig_seed) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key_seed_only: failed to create seed attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with NULL value and seed */
    rv = ber_encode_ML_DSA_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_DSA_65, ber_idML_DSA_65Len,
                                       NULL, orig_seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key_seed_only: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_ML_DSA_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key_seed_only: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify value is NULL */
    if (dec_value != NULL) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key_seed_only: value should be NULL\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip for seed */
    if (dec_seed->ulValueLen != sizeof(seed_data) ||
        memcmp(dec_seed->pValue, seed_data, sizeof(seed_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_dsa_private_key_seed_only: seed mismatch\n");
        result = 1;
        goto cleanup;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ml_dsa_private_key_seed_only\n");

cleanup:
    if (orig_seed) free(orig_seed);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* ============================================================================
 * ML-KEM (NIST standardized) Tests
 * ============================================================================ */

/* Test ber_encode_ML_KEM_PublicKey with basic ML-KEM-768 key */
int test_encode_ml_kem_public_key_basic(void)
{
    /* ML-KEM-768 public key value for testing (1184 bytes) */
    CK_BYTE value_data[1184];
    CK_ATTRIBUTE *value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize value with test data */
    memset(value_data, 0x1C, sizeof(value_data));

    /* Create attribute */
    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!value) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_public_key_basic: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with ML-KEM-768 OID */
    rv = ber_encode_ML_KEM_PublicKey(FALSE, &encoded, &encoded_len,
                                      ber_idML_KEM_768, ber_idML_KEM_768Len,
                                      value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_public_key_basic: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_public_key_basic: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_kem_public_key_basic\n");

cleanup:
    if (value) free(value);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_ML_KEM_PublicKey with valid encoded data */
int test_decode_ml_kem_public_key_valid(void)
{
    CK_BYTE value_data[1184];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0x2D, sizeof(value_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_value) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_public_key_valid: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* First encode */
    rv = ber_encode_ML_KEM_PublicKey(FALSE, &encoded, &encoded_len,
                                      ber_idML_KEM_768, ber_idML_KEM_768Len,
                                      orig_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_public_key_valid: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_ML_KEM_PublicKey(encoded, encoded_len, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_public_key_valid: decoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_value || !oid) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_public_key_valid: decode produced NULL output\n");
        result = 1;
        goto cleanup;
    }

    /* Verify decoded value matches original */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_public_key_valid: value mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ml_kem_public_key_valid\n");

cleanup:
    if (orig_value) free(orig_value);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-KEM public key encode/decode roundtrip */
int test_roundtrip_ml_kem_public_key(void)
{
    CK_BYTE value_data[1184];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0x3E, sizeof(value_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_value) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_public_key: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_ML_KEM_PublicKey(FALSE, &encoded, &encoded_len,
                                      ber_idML_KEM_768, ber_idML_KEM_768Len,
                                      orig_value);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_public_key: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_ML_KEM_PublicKey(encoded, encoded_len, &dec_value, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_public_key: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_public_key: value mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ml_kem_public_key\n");

cleanup:
    if (orig_value) free(orig_value);
    if (dec_value) free(dec_value);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_KEM_PrivateKey with basic ML-KEM-768 key */
int test_encode_ml_kem_private_key_basic(void)
{
    /* ML-KEM-768 private key value for testing (2400 bytes) */
    CK_BYTE value_data[2400];
    CK_ATTRIBUTE *value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize value with test data */
    memset(value_data, 0x4F, sizeof(value_data));

    /* Create attribute */
    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!value) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_basic: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with ML-KEM-768 OID */
    rv = ber_encode_ML_KEM_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       value, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_basic: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_basic: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_kem_private_key_basic\n");

cleanup:
    if (value) free(value);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_KEM_PrivateKey with length_only mode */
int test_encode_ml_kem_private_key_length_only(void)
{
    CK_BYTE value_data[2400];
    CK_ATTRIBUTE *value = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0x50, sizeof(value_data));

    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!value) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_length_only: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with length_only = TRUE */
    rv = ber_encode_ML_KEM_PrivateKey(TRUE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       value, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_length_only: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_length_only: encoded should be NULL in length_only mode\n");
        result = 1;
        goto cleanup;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_length_only: encoded_len should be non-zero\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_kem_private_key_length_only\n");

cleanup:
    if (value) free(value);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_ML_KEM_PrivateKey with valid encoded data */
int test_decode_ml_kem_private_key_valid(void)
{
    CK_BYTE value_data[2400];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0x61, sizeof(value_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_value) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_valid: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* First encode */
    rv = ber_encode_ML_KEM_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       orig_value, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_valid: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_ML_KEM_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_valid: decoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_value || !oid) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_valid: decode produced NULL output\n");
        result = 1;
        goto cleanup;
    }

    /* Verify decoded value matches original */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_valid: value mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ml_kem_private_key_valid\n");

cleanup:
    if (orig_value) free(orig_value);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-KEM private key encode/decode roundtrip */
int test_roundtrip_ml_kem_private_key(void)
{
    CK_BYTE value_data[2400];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0x72, sizeof(value_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));

    if (!orig_value) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key: failed to create attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode */
    rv = ber_encode_ML_KEM_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       orig_value, NULL);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_ML_KEM_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key: value mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ml_kem_private_key\n");

cleanup:
    if (orig_value) free(orig_value);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_KEM_PrivateKey with seed value */
int test_encode_ml_kem_private_key_with_seed(void)
{
    /* ML-KEM-768 private key value for testing (2400 bytes) */
    CK_BYTE value_data[2400];
    CK_BYTE seed_data[64];  /* Seed is 64 bytes for ML-KEM */
    CK_ATTRIBUTE *value = NULL;
    CK_ATTRIBUTE *seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize value and seed with test data */
    memset(value_data, 0x4F, sizeof(value_data));
    memset(seed_data, 0xBC, sizeof(seed_data));

    /* Create attributes */
    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));
    seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!value || !seed) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_with_seed: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with ML-KEM-768 OID and seed */
    rv = ber_encode_ML_KEM_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       value, seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_with_seed: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_with_seed: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_kem_private_key_with_seed\n");

cleanup:
    if (value) free(value);
    if (seed) free(seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_KEM_PrivateKey with seed in length_only mode */
int test_encode_ml_kem_private_key_with_seed_length_only(void)
{
    CK_BYTE value_data[2400];
    CK_BYTE seed_data[64];
    CK_ATTRIBUTE *value = NULL;
    CK_ATTRIBUTE *seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0x60, sizeof(value_data));
    memset(seed_data, 0xDE, sizeof(seed_data));

    value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));
    seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!value || !seed) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_with_seed_length_only: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with length_only = TRUE and seed */
    rv = ber_encode_ML_KEM_PrivateKey(TRUE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       value, seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_with_seed_length_only: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_with_seed_length_only: encoded should be NULL in length_only mode\n");
        result = 1;
        goto cleanup;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_with_seed_length_only: encoded_len should be non-zero\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_kem_private_key_with_seed_length_only\n");

cleanup:
    if (value) free(value);
    if (seed) free(seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_ML_KEM_PrivateKey with seed in encoded data */
int test_decode_ml_kem_private_key_with_seed(void)
{
    CK_BYTE value_data[2400];
    CK_BYTE seed_data[64];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *orig_seed = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0x71, sizeof(value_data));
    memset(seed_data, 0xF0, sizeof(seed_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));
    orig_seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!orig_value || !orig_seed) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_with_seed: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* First encode with seed */
    rv = ber_encode_ML_KEM_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       orig_value, orig_seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_with_seed: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_ML_KEM_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_with_seed: decoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_value || !dec_seed || !oid) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_with_seed: decode produced NULL output\n");
        result = 1;
        goto cleanup;
    }

    /* Verify decoded value matches original */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_with_seed: value mismatch\n");
        result = 1;
        goto cleanup;
    }

    /* Verify decoded seed matches original */
    if (dec_seed->ulValueLen != sizeof(seed_data) ||
        memcmp(dec_seed->pValue, seed_data, sizeof(seed_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_with_seed: seed mismatch\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ml_kem_private_key_with_seed\n");

cleanup:
    if (orig_value) free(orig_value);
    if (orig_seed) free(orig_seed);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-KEM private key with seed encode/decode roundtrip */
int test_roundtrip_ml_kem_private_key_with_seed(void)
{
    CK_BYTE value_data[2400];
    CK_BYTE seed_data[64];
    CK_ATTRIBUTE *orig_value = NULL;
    CK_ATTRIBUTE *orig_seed = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(value_data, 0x82, sizeof(value_data));
    memset(seed_data, 0x23, sizeof(seed_data));

    orig_value = create_attribute(CKA_VALUE, value_data, sizeof(value_data));
    orig_seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!orig_value || !orig_seed) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key_with_seed: failed to create attributes\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with seed */
    rv = ber_encode_ML_KEM_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       orig_value, orig_seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key_with_seed: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_ML_KEM_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key_with_seed: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip for value */
    if (dec_value->ulValueLen != sizeof(value_data) ||
        memcmp(dec_value->pValue, value_data, sizeof(value_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key_with_seed: value mismatch\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip for seed */
    if (dec_seed->ulValueLen != sizeof(seed_data) ||
        memcmp(dec_seed->pValue, seed_data, sizeof(seed_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key_with_seed: seed mismatch\n");
        result = 1;
        goto cleanup;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ml_kem_private_key_with_seed\n");

cleanup:
    if (orig_value) free(orig_value);
    if (orig_seed) free(orig_seed);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_KEM_PrivateKey with seed-only (no value) */
int test_encode_ml_kem_private_key_seed_only(void)
{
    /* ML-KEM-768 seed for testing (64 bytes) */
    CK_BYTE seed_data[64];
    CK_ATTRIBUTE *seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Initialize seed with test data */
    memset(seed_data, 0xBC, sizeof(seed_data));

    /* Create seed attribute */
    seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!seed) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_seed_only: failed to create seed attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with ML-KEM-768 OID, NULL value, and seed */
    rv = ber_encode_ML_KEM_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       NULL, seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_seed_only: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!encoded || encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_seed_only: encoding produced no data\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_kem_private_key_seed_only\n");

cleanup:
    if (seed) free(seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_encode_ML_KEM_PrivateKey with seed-only in length_only mode */
int test_encode_ml_kem_private_key_seed_only_length_only(void)
{
    CK_BYTE seed_data[64];
    CK_ATTRIBUTE *seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(seed_data, 0xDE, sizeof(seed_data));

    seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!seed) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_seed_only_length_only: failed to create seed attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with length_only = TRUE, NULL value, and seed */
    rv = ber_encode_ML_KEM_PrivateKey(TRUE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       NULL, seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_seed_only_length_only: encoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_seed_only_length_only: encoded should be NULL in length_only mode\n");
        result = 1;
        goto cleanup;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_ml_kem_private_key_seed_only_length_only: encoded_len should be non-zero\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_encode_ml_kem_private_key_seed_only_length_only\n");

cleanup:
    if (seed) free(seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ber_decode_ML_KEM_PrivateKey with seed-only in encoded data */
int test_decode_ml_kem_private_key_seed_only(void)
{
    CK_BYTE seed_data[64];
    CK_ATTRIBUTE *orig_seed = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(seed_data, 0xF0, sizeof(seed_data));

    orig_seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!orig_seed) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_seed_only: failed to create seed attribute\n");
        result = 1;
        goto cleanup;
    }

    /* First encode with NULL value and seed */
    rv = ber_encode_ML_KEM_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       NULL, orig_seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_seed_only: encoding failed\n");
        result = 1;
        goto cleanup;
    }

    /* Now decode */
    rv = ber_decode_ML_KEM_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_seed_only: decoding failed with rv=0x%lx\n", rv);
        result = 1;
        goto cleanup;
    }

    if (!dec_seed || !oid) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_seed_only: decode produced NULL output\n");
        result = 1;
        goto cleanup;
    }

    /* Verify decoded seed matches original */
    if (dec_seed->ulValueLen != sizeof(seed_data) ||
        memcmp(dec_seed->pValue, seed_data, sizeof(seed_data)) != 0) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_seed_only: seed mismatch\n");
        result = 1;
        goto cleanup;
    }

    /* Value should be NULL for seed-only keys */
    if (dec_value != NULL) {
        fprintf(stderr, "[FAIL] test_decode_ml_kem_private_key_seed_only: value should be NULL for seed-only key\n");
        result = 1;
        goto cleanup;
    }

    printf("[PASS] test_decode_ml_kem_private_key_seed_only\n");

cleanup:
    if (orig_seed) free(orig_seed);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}

/* Test ML-KEM private key seed-only encode/decode roundtrip */
int test_roundtrip_ml_kem_private_key_seed_only(void)
{
    CK_BYTE seed_data[64];
    CK_ATTRIBUTE *orig_seed = NULL;
    CK_ATTRIBUTE *dec_value = NULL;
    CK_ATTRIBUTE *dec_seed = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    const struct pqc_oid *oid = NULL;
    CK_RV rv;
    int result = 0;

    memset(seed_data, 0x23, sizeof(seed_data));

    orig_seed = create_attribute(CKA_VALUE, seed_data, sizeof(seed_data));

    if (!orig_seed) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key_seed_only: failed to create seed attribute\n");
        result = 1;
        goto cleanup;
    }

    /* Encode with NULL value and seed */
    rv = ber_encode_ML_KEM_PrivateKey(FALSE, &encoded, &encoded_len,
                                       ber_idML_KEM_768, ber_idML_KEM_768Len,
                                       NULL, orig_seed);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key_seed_only: encode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Decode */
    rv = ber_decode_ML_KEM_PrivateKey(encoded, encoded_len, &dec_value, &dec_seed, &oid);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key_seed_only: decode failed\n");
        result = 1;
        goto cleanup;
    }

    /* Verify value is NULL */
    if (dec_value != NULL) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key_seed_only: value should be NULL\n");
        result = 1;
        goto cleanup;
    }

    /* Verify roundtrip for seed */
    if (dec_seed->ulValueLen != sizeof(seed_data) ||
        memcmp(dec_seed->pValue, seed_data, sizeof(seed_data)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_ml_kem_private_key_seed_only: seed mismatch\n");
        result = 1;
        goto cleanup;
    }

    if (result == 0)
        printf("[PASS] test_roundtrip_ml_kem_private_key_seed_only\n");

cleanup:
    if (orig_seed) free(orig_seed);
    if (dec_value) free(dec_value);
    if (dec_seed) free(dec_seed);
    if (encoded) free(encoded);
    return result;
}
