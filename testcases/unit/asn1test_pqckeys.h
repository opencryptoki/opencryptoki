/*
 * COPYRIGHT (c) International Business Machines Corp. 2026
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef ASN1TEST_PQCKEYS_H
#define ASN1TEST_PQCKEYS_H

/* IBM ML-DSA Public Key Tests */
int test_encode_ibm_ml_dsa_public_key_basic(void);
int test_decode_ibm_ml_dsa_public_key_valid(void);
int test_roundtrip_ibm_ml_dsa_public_key(void);

/* IBM ML-DSA Private Key Tests */
int test_encode_ibm_ml_dsa_private_key_basic(void);
int test_encode_ibm_ml_dsa_private_key_length_only(void);
int test_decode_ibm_ml_dsa_private_key_valid(void);
int test_roundtrip_ibm_ml_dsa_private_key(void);

/* IBM ML-KEM Public Key Tests */
int test_encode_ibm_ml_kem_public_key_basic(void);
int test_decode_ibm_ml_kem_public_key_valid(void);
int test_roundtrip_ibm_ml_kem_public_key(void);

/* IBM ML-KEM Private Key Tests */
int test_encode_ibm_ml_kem_private_key_basic(void);
int test_encode_ibm_ml_kem_private_key_length_only(void);
int test_decode_ibm_ml_kem_private_key_valid(void);
int test_roundtrip_ibm_ml_kem_private_key(void);

/* IBM Dilithium Public Key Tests */
int test_encode_ibm_dilithium_public_key_basic(void);
int test_decode_ibm_dilithium_public_key_basic(void);
int test_roundtrip_ibm_dilithium_public_key(void);

/* IBM Dilithium Private Key Tests */
int test_encode_ibm_dilithium_private_key_basic(void);
int test_decode_ibm_dilithium_private_key_basic(void);
int test_roundtrip_ibm_dilithium_private_key(void);
int test_ibm_dilithium_private_key_null_optional(void);

/* IBM Kyber Public Key Tests */
int test_encode_ibm_kyber_public_key_basic(void);
int test_decode_ibm_kyber_public_key_basic(void);
int test_roundtrip_ibm_kyber_public_key(void);

/* IBM Kyber Private Key Tests */
int test_encode_ibm_kyber_private_key_basic(void);
int test_decode_ibm_kyber_private_key_basic(void);
int test_roundtrip_ibm_kyber_private_key(void);
int test_ibm_kyber_private_key_null_optional(void);

/* ML-DSA (NIST standardized) Public Key Tests */
int test_encode_ml_dsa_public_key_basic(void);
int test_decode_ml_dsa_public_key_valid(void);
int test_roundtrip_ml_dsa_public_key(void);

/* ML-DSA (NIST standardized) Private Key Tests */
int test_encode_ml_dsa_private_key_basic(void);
int test_encode_ml_dsa_private_key_length_only(void);
int test_decode_ml_dsa_private_key_valid(void);
int test_roundtrip_ml_dsa_private_key(void);

/* ML-DSA (NIST standardized) Private Key Tests with Seed */
int test_encode_ml_dsa_private_key_with_seed(void);
int test_encode_ml_dsa_private_key_with_seed_length_only(void);
int test_decode_ml_dsa_private_key_with_seed(void);
int test_roundtrip_ml_dsa_private_key_with_seed(void);

/* ML-DSA (NIST standardized) Private Key Tests with Seed-Only */
int test_encode_ml_dsa_private_key_seed_only(void);
int test_encode_ml_dsa_private_key_seed_only_length_only(void);
int test_decode_ml_dsa_private_key_seed_only(void);
int test_roundtrip_ml_dsa_private_key_seed_only(void);

/* ML-KEM (NIST standardized) Public Key Tests */
int test_encode_ml_kem_public_key_basic(void);
int test_decode_ml_kem_public_key_valid(void);
int test_roundtrip_ml_kem_public_key(void);

/* ML-KEM (NIST standardized) Private Key Tests */
int test_encode_ml_kem_private_key_basic(void);
int test_encode_ml_kem_private_key_length_only(void);
int test_decode_ml_kem_private_key_valid(void);
int test_roundtrip_ml_kem_private_key(void);

/* ML-KEM (NIST standardized) Private Key Tests with Seed */
int test_encode_ml_kem_private_key_with_seed(void);
int test_encode_ml_kem_private_key_with_seed_length_only(void);
int test_decode_ml_kem_private_key_with_seed(void);
int test_roundtrip_ml_kem_private_key_with_seed(void);

/* ML-KEM (NIST standardized) Private Key Tests with Seed-Only */
int test_encode_ml_kem_private_key_seed_only(void);
int test_encode_ml_kem_private_key_seed_only_length_only(void);
int test_decode_ml_kem_private_key_seed_only(void);
int test_roundtrip_ml_kem_private_key_seed_only(void);

#endif /* ASN1TEST_PQCKEYS_H */
