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
 * Unit tests for cryptographic key encoding/decoding functions in asn1.c
 * This header declares test functions for RSA, DSA, DH, EC, Edwards, and Montgomery keys
 */

#ifndef ASNT1TEST_KEYS_H
#define ASNT1TEST_KEYS_H

/* RSA Private Key Tests */
int test_encode_rsa_private_key_basic(void);
int test_encode_rsa_private_key_length_only(void);
int test_decode_rsa_private_key_valid(void);
int test_decode_rsa_private_key_invalid_alg(void);
int test_roundtrip_rsa_private_key(void);

/* RSA Public Key Tests */
int test_encode_rsa_public_key_basic(void);
int test_decode_rsa_public_key_valid(void);
int test_decode_rsa_public_key_invalid_alg(void);
int test_roundtrip_rsa_public_key(void);

/* DSA Private Key Tests */
int test_encode_dsa_private_key_basic(void);
int test_encode_dsa_private_key_length_only(void);
int test_decode_dsa_private_key_valid(void);
int test_roundtrip_dsa_private_key(void);

/* DSA Public Key Tests */
int test_encode_dsa_public_key_basic(void);
int test_decode_dsa_public_key_valid(void);
int test_roundtrip_dsa_public_key(void);

/* DH Private Key Tests */
int test_encode_dh_private_key_basic(void);
int test_encode_dh_private_key_length_only(void);
int test_decode_dh_private_key_valid(void);
int test_roundtrip_dh_private_key(void);

/* DH Public Key Tests */
int test_encode_dh_public_key_basic(void);
int test_decode_dh_public_key_valid(void);
int test_roundtrip_dh_public_key(void);

/* EC Private Key Tests (CKK_EC) */
int test_encode_ec_private_key_basic(void);
int test_encode_ec_private_key_length_only(void);
int test_decode_ec_private_key_valid(void);
int test_roundtrip_ec_private_key(void);

/* EC Public Key Tests (CKK_EC) */
int test_encode_ec_public_key_basic(void);
int test_decode_ec_public_key_valid(void);
int test_roundtrip_ec_public_key(void);

/* Edwards Curve Private Key Tests (CKK_EC_EDWARDS) */
int test_encode_edwards_private_key_basic(void);
int test_roundtrip_edwards_private_key(void);

/* Edwards Curve Public Key Tests (CKK_EC_EDWARDS) */
int test_encode_edwards_public_key_basic(void);
int test_roundtrip_edwards_public_key(void);

/* Montgomery Curve Private Key Tests (CKK_EC_MONTGOMERY) */
int test_encode_montgomery_private_key_basic(void);
int test_roundtrip_montgomery_private_key(void);

/* Montgomery Curve Public Key Tests (CKK_EC_MONTGOMERY) */
int test_encode_montgomery_public_key_basic(void);
int test_roundtrip_montgomery_public_key(void);

#endif /* ASNT1TEST_KEYS_H */
