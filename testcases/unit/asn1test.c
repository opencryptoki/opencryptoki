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
 * Unit tests for BER encoding and decoding functions in asn1.c
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
#include "asn1test_pqckeys.h"

/* Function prototypes from asn1.c */
CK_ULONG ber_encode_INTEGER(CK_BBOOL length_only,
                            CK_BYTE **ber_int,
                            CK_ULONG *ber_int_len, CK_BYTE *data,
                            CK_ULONG data_len);

CK_RV ber_decode_INTEGER(CK_BYTE *ber_int, CK_ULONG ber_int_len,
                         CK_BYTE **data, CK_ULONG *data_len,
                         CK_ULONG *field_len);

CK_RV ber_encode_OCTET_STRING(CK_BBOOL length_only,
                              CK_BYTE **str,
                              CK_ULONG *str_len, CK_BYTE *data,
                              CK_ULONG data_len);

CK_RV ber_decode_OCTET_STRING(CK_BYTE *str, CK_ULONG str_len,
                              CK_BYTE **data,
                              CK_ULONG *data_len, CK_ULONG *field_len);

CK_ULONG ber_encode_BIT_STRING(CK_BBOOL length_only,
                            CK_BYTE **ber_str,
                            CK_ULONG *ber_str_len, CK_BYTE *data,
                            CK_ULONG data_len,
                            CK_BYTE unused_bits);

CK_RV ber_decode_BIT_STRING(CK_BYTE *str, CK_ULONG str_len,
                            CK_BYTE **data,
                            CK_ULONG *data_len, CK_ULONG *field_len);

CK_RV ber_encode_SEQUENCE(CK_BBOOL length_only,
                          CK_BYTE **seq,
                          CK_ULONG *seq_len, CK_BYTE *data, CK_ULONG data_len);

CK_RV ber_decode_SEQUENCE(CK_BYTE *seq, CK_ULONG seq_len,
                          CK_BYTE **data, CK_ULONG *data_len,
                          CK_ULONG *field_len);

CK_RV ber_encode_CHOICE(CK_BBOOL length_only,
                        CK_BYTE option,
                        CK_BYTE **str,
                        CK_ULONG *str_len, CK_BYTE *data, CK_ULONG data_len,
                        CK_BBOOL constructed);

CK_RV ber_decode_CHOICE(CK_BYTE *choice, CK_ULONG choice_len,
                        CK_BBOOL constructed,
                        CK_BYTE **data,
                        CK_ULONG *data_len, CK_ULONG *field_len,
                        CK_ULONG *option);

CK_RV ber_encode_PrivateKeyInfo(CK_BBOOL length_only,
                                CK_BYTE **data,
                                CK_ULONG *data_len,
                                const CK_BYTE *algorithm_id,
                                const CK_ULONG algorithm_id_len,
                                CK_BYTE *priv_key, CK_ULONG priv_key_len);

CK_RV ber_decode_PrivateKeyInfo(CK_BYTE *data, CK_ULONG data_len,
                                CK_BYTE **algorithm, CK_ULONG *alg_len,
                                CK_BYTE **priv_key, CK_ULONG *priv_key_len);

CK_RV ber_decode_SPKI(CK_BYTE *spki, CK_ULONG spki_len,
                      CK_BYTE **alg_oid, CK_ULONG *alg_oid_len,
                      CK_BYTE **param, CK_ULONG *param_len,
                      CK_BYTE **key, CK_ULONG *key_len);

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


/* Helper function to compare byte arrays */
static int compare_bytes(const char *test_name, CK_BYTE *expected,
                        CK_BYTE *actual, CK_ULONG len)
{
    if (memcmp(expected, actual, len) != 0) {
        fprintf(stderr, "[FAIL] %s: Data mismatch\n", test_name);
        fprintf(stderr, "  Expected: ");
        for (CK_ULONG i = 0; i < len; i++)
            fprintf(stderr, "%02X ", expected[i]);
        fprintf(stderr, "\n  Actual:   ");
        for (CK_ULONG i = 0; i < len; i++)
            fprintf(stderr, "%02X ", actual[i]);
        fprintf(stderr, "\n");
        return 1;
    }
    return 0;
}

/* Test ber_encode_INTEGER with short form length (< 128 bytes) */
static int test_encode_integer_short(void)
{
    CK_BYTE data[] = {0x01, 0x02, 0x03};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Expected: 0x02 (INTEGER tag), 0x03 (length), data */
    CK_BYTE expected[] = {0x02, 0x03, 0x01, 0x02, 0x03};

    rv = ber_encode_INTEGER(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_integer_short: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_encode_integer_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), encoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_encode_integer_short", expected, encoded, encoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_integer_short\n");
    return result;
}

/* Test ber_encode_INTEGER with MSB set (requires padding) */
static int test_encode_integer_padding(void)
{
    CK_BYTE data[] = {0x80, 0x01, 0x02};  /* MSB set, needs 0x00 padding */
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Expected: 0x02 (INTEGER tag), 0x04 (length), 0x00 (padding), data */
    CK_BYTE expected[] = {0x02, 0x04, 0x00, 0x80, 0x01, 0x02};

    rv = ber_encode_INTEGER(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_integer_padding: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_encode_integer_padding: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), encoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_encode_integer_padding", expected, encoded, encoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_integer_padding\n");
    return result;
}

/* Test ber_encode_INTEGER with long form length (128-255 bytes) */
static int test_encode_integer_long_form(void)
{
    CK_BYTE data[200];
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Fill with non-MSB-set data to avoid padding */
    memset(data, 0x42, sizeof(data));

    rv = ber_encode_INTEGER(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_integer_long_form: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Expected: 0x02 (INTEGER tag), 0x81 (long form, 1 byte length), 0xC8 (200), data */
    if (encoded_len != 1 + 2 + 200) {
        fprintf(stderr, "[FAIL] test_encode_integer_long_form: length mismatch (expected 203, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x02 || encoded[1] != 0x81 || encoded[2] != 200) {
        fprintf(stderr, "[FAIL] test_encode_integer_long_form: header mismatch\n");
        result = 1;
    } else if (memcmp(&encoded[3], data, 200) != 0) {
        fprintf(stderr, "[FAIL] test_encode_integer_long_form: data mismatch\n");
        result = 1;
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_integer_long_form\n");
    return result;
}

/* Test ber_encode_INTEGER with 3-byte long form length (256-65535 bytes) */
static int test_encode_integer_3byte_long_form(void)
{
    CK_BYTE *data = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG data_size = 300;  /* 256+ bytes to trigger 3-byte long form */

    /* Allocate and fill with non-MSB-set data to avoid padding */
    data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "[FAIL] test_encode_integer_3byte_long_form: malloc failed\n");
        return 1;
    }
    memset(data, 0x42, data_size);

    rv = ber_encode_INTEGER(FALSE, &encoded, &encoded_len, data, data_size);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_integer_3byte_long_form: encode failed with rv=%lu\n", rv);
        free(data);
        return 1;
    }

    /* Expected: 0x02 (INTEGER tag), 0x82 (long form, 2 bytes length),
     * 0x01 0x2C (300 in big-endian), data */
    if (encoded_len != 1 + 3 + 300) {
        fprintf(stderr, "[FAIL] test_encode_integer_3byte_long_form: length mismatch (expected 304, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x02 || encoded[1] != 0x82 ||
               encoded[2] != 0x01 || encoded[3] != 0x2C) {
        fprintf(stderr, "[FAIL] test_encode_integer_3byte_long_form: header mismatch\n");
        fprintf(stderr, "  Expected: 02 82 01 2C\n");
        fprintf(stderr, "  Got:      %02X %02X %02X %02X\n",
                encoded[0], encoded[1], encoded[2], encoded[3]);
        result = 1;
    } else if (memcmp(&encoded[4], data, 300) != 0) {
        fprintf(stderr, "[FAIL] test_encode_integer_3byte_long_form: data mismatch\n");
        result = 1;
    }

    free(data);
    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_integer_3byte_long_form\n");
    return result;
}

/* Test ber_encode_INTEGER with 4-byte long form length (65536+ bytes) */
static int test_encode_integer_4byte_long_form(void)
{
    CK_BYTE *data = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG data_size = 70000;  /* 65536+ bytes to trigger 4-byte long form */

    /* Allocate and fill with non-MSB-set data to avoid padding */
    data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "[FAIL] test_encode_integer_4byte_long_form: malloc failed\n");
        return 1;
    }
    memset(data, 0x42, data_size);

    rv = ber_encode_INTEGER(FALSE, &encoded, &encoded_len, data, data_size);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_integer_4byte_long_form: encode failed with rv=%lu\n", rv);
        free(data);
        return 1;
    }

    /* Expected: 0x02 (INTEGER tag), 0x83 (long form, 3 bytes length),
     * 0x01 0x11 0x70 (70000 in big-endian), data */
    if (encoded_len != 1 + 4 + 70000) {
        fprintf(stderr, "[FAIL] test_encode_integer_4byte_long_form: length mismatch (expected 70005, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x02 || encoded[1] != 0x83 ||
               encoded[2] != 0x01 || encoded[3] != 0x11 || encoded[4] != 0x70) {
        fprintf(stderr, "[FAIL] test_encode_integer_4byte_long_form: header mismatch\n");
        fprintf(stderr, "  Expected: 02 83 01 11 70\n");
        fprintf(stderr, "  Got:      %02X %02X %02X %02X %02X\n",
                encoded[0], encoded[1], encoded[2], encoded[3], encoded[4]);
        result = 1;
    } else if (memcmp(&encoded[5], data, 70000) != 0) {
        fprintf(stderr, "[FAIL] test_encode_integer_4byte_long_form: data mismatch\n");
        result = 1;
    }

    free(data);
    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_integer_4byte_long_form\n");
    return result;
}

/* Test ber_encode_INTEGER length_only mode */
static int test_encode_integer_length_only(void)
{
    CK_BYTE data[] = {0x01, 0x02, 0x03};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;

    rv = ber_encode_INTEGER(TRUE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_integer_length_only: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Expected length: 1 (tag) + 1 (length) + 3 (data) = 5 */
    if (encoded_len != 5) {
        fprintf(stderr, "[FAIL] test_encode_integer_length_only: length mismatch (expected 5, got %lu)\n",
                encoded_len);
        return 1;
    }

    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_integer_length_only: encoded should be NULL in length_only mode\n");
        return 1;
    }

    printf("[PASS] test_encode_integer_length_only\n");
    return 0;
}

/* Test ber_encode_INTEGER with zero-length data */
static int test_encode_integer_zero_length(void)
{
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Expected: 0x02 (INTEGER tag), 0x00 (length 0) */
    CK_BYTE expected[] = {0x02, 0x00};

    rv = ber_encode_INTEGER(FALSE, &encoded, &encoded_len, NULL, 0);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_integer_zero_length: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_encode_integer_zero_length: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), encoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_encode_integer_zero_length", expected, encoded, encoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_integer_zero_length\n");
    return result;
}

/* Test ber_encode_INTEGER at boundary (127 bytes - last short form) */
static int test_encode_integer_boundary_127(void)
{
    CK_BYTE data[127];
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(data, 0x42, sizeof(data));

    rv = ber_encode_INTEGER(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_integer_boundary_127: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Should use short form: tag + length + data = 1 + 1 + 127 = 129 */
    if (encoded_len != 129) {
        fprintf(stderr, "[FAIL] test_encode_integer_boundary_127: length mismatch (expected 129, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x02 || encoded[1] != 127) {
        fprintf(stderr, "[FAIL] test_encode_integer_boundary_127: header mismatch (got %02X %02X)\n",
                encoded[0], encoded[1]);
        result = 1;
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_integer_boundary_127\n");
    return result;
}

/* Test ber_encode_INTEGER at boundary (128 bytes - first long form) */
static int test_encode_integer_boundary_128(void)
{
    CK_BYTE data[128];
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(data, 0x42, sizeof(data));

    rv = ber_encode_INTEGER(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_integer_boundary_128: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Should use long form: tag + 0x81 + length + data = 1 + 1 + 1 + 128 = 131 */
    if (encoded_len != 131) {
        fprintf(stderr, "[FAIL] test_encode_integer_boundary_128: length mismatch (expected 131, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x02 || encoded[1] != 0x81 || encoded[2] != 128) {
        fprintf(stderr, "[FAIL] test_encode_integer_boundary_128: header mismatch (got %02X %02X %02X)\n",
                encoded[0], encoded[1], encoded[2]);
        result = 1;
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_integer_boundary_128\n");
    return result;
}

/* Test ber_decode_INTEGER with short form length */
static int test_decode_integer_short(void)
{
    CK_BYTE encoded[] = {0x02, 0x03, 0x01, 0x02, 0x03};
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;

    CK_BYTE expected[] = {0x01, 0x02, 0x03};

    rv = ber_decode_INTEGER(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_integer_short: decode failed with rv=%lu\n", rv);
        return 1;
    }

    if (data_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_decode_integer_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), data_len);
        result = 1;
    } else if (field_len != sizeof(encoded)) {
        fprintf(stderr, "[FAIL] test_decode_integer_short: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(encoded), field_len);
        result = 1;
    } else {
        result = compare_bytes("test_decode_integer_short", expected, data, data_len);
    }

    if (result == 0)
        printf("[PASS] test_decode_integer_short\n");
    return result;
}

/* Test ber_decode_INTEGER with padding removal */
static int test_decode_integer_padding(void)
{
    CK_BYTE encoded[] = {0x02, 0x04, 0x00, 0x80, 0x01, 0x02};
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;

    /* Expected: padding byte removed */
    CK_BYTE expected[] = {0x80, 0x01, 0x02};

    rv = ber_decode_INTEGER(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_integer_padding: decode failed with rv=%lu\n", rv);
        return 1;
    }

    if (data_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_decode_integer_padding: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), data_len);
        result = 1;
    } else {
        result = compare_bytes("test_decode_integer_padding", expected, data, data_len);
    }

    if (result == 0)
        printf("[PASS] test_decode_integer_padding\n");
    return result;
}

/* Test ber_decode_INTEGER with 3-byte long form length (256-65535 bytes) */
static int test_decode_integer_3byte_long_form(void)
{
    CK_BYTE *encoded = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG expected_data_size = 300;

    /* Build encoded data: 0x02 (tag), 0x82 (long form 2 bytes), 0x01 0x2C (300), data */
    encoded = malloc(1 + 3 + expected_data_size);
    if (encoded == NULL) {
        fprintf(stderr, "[FAIL] test_decode_integer_3byte_long_form: malloc failed\n");
        return 1;
    }

    encoded[0] = 0x02;  /* INTEGER tag */
    encoded[1] = 0x82;  /* Long form: 2 length bytes follow */
    encoded[2] = 0x01;  /* Length high byte */
    encoded[3] = 0x2C;  /* Length low byte (300 = 0x012C) */
    memset(&encoded[4], 0x42, expected_data_size);

    rv = ber_decode_INTEGER(encoded, 1 + 3 + expected_data_size, &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_integer_3byte_long_form: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    if (data_len != expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_integer_3byte_long_form: data length mismatch (expected %lu, got %lu)\n",
                expected_data_size, data_len);
        result = 1;
    } else if (field_len != 1 + 3 + expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_integer_3byte_long_form: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)(1 + 3 + expected_data_size), field_len);
        result = 1;
    } else {
        /* Verify data content */
        for (CK_ULONG i = 0; i < expected_data_size; i++) {
            if (data[i] != 0x42) {
                fprintf(stderr, "[FAIL] test_decode_integer_3byte_long_form: data mismatch at byte %lu\n", i);
                result = 1;
                break;
            }
        }
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_decode_integer_3byte_long_form\n");
    return result;
}

/* Test ber_decode_INTEGER with 4-byte long form length (65536+ bytes) */
static int test_decode_integer_4byte_long_form(void)
{
    CK_BYTE *encoded = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG expected_data_size = 70000;

    /* Build encoded data: 0x02 (tag), 0x83 (long form 3 bytes), 0x01 0x11 0x70 (70000), data */
    encoded = malloc(1 + 4 + expected_data_size);
    if (encoded == NULL) {
        fprintf(stderr, "[FAIL] test_decode_integer_4byte_long_form: malloc failed\n");
        return 1;
    }

    encoded[0] = 0x02;  /* INTEGER tag */
    encoded[1] = 0x83;  /* Long form: 3 length bytes follow */
    encoded[2] = 0x01;  /* Length high byte */
    encoded[3] = 0x11;  /* Length middle byte */
    encoded[4] = 0x70;  /* Length low byte (70000 = 0x011170) */
    memset(&encoded[5], 0x42, expected_data_size);

    rv = ber_decode_INTEGER(encoded, 1 + 4 + expected_data_size, &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_integer_4byte_long_form: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    if (data_len != expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_integer_4byte_long_form: data length mismatch (expected %lu, got %lu)\n",
                expected_data_size, data_len);
        result = 1;
    } else if (field_len != 1 + 4 + expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_integer_4byte_long_form: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)(1 + 4 + expected_data_size), field_len);
        result = 1;
    } else {
        /* Verify data content - check first and last bytes to avoid long loop */
        if (data[0] != 0x42 || data[expected_data_size - 1] != 0x42) {
            fprintf(stderr, "[FAIL] test_decode_integer_4byte_long_form: data mismatch\n");
            result = 1;
        }
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_decode_integer_4byte_long_form\n");
    return result;
}

/* Test ber_decode_INTEGER with invalid tag */
static int test_decode_integer_invalid_tag(void)
{
    CK_BYTE encoded[] = {0x04, 0x03, 0x01, 0x02, 0x03};  /* Wrong tag (OCTET STRING) */
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_INTEGER(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_integer_invalid_tag: should have failed\n");
        return 1;
    }

    printf("[PASS] test_decode_integer_invalid_tag\n");
    return 0;
}

/* Test ber_decode_INTEGER with truncated data */
static int test_decode_integer_truncated(void)
{
    CK_BYTE encoded[] = {0x02, 0x05, 0x01, 0x02};  /* Says length 5 but only 2 bytes follow */
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_INTEGER(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_integer_truncated: should have failed on truncated data\n");
        return 1;
    }

    printf("[PASS] test_decode_integer_truncated\n");
    return 0;
}

/* Test ber_decode_INTEGER with NULL input */
static int test_decode_integer_null_input(void)
{
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_INTEGER(NULL, 10, &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_integer_null_input: should have failed on NULL input\n");
        return 1;
    }

    printf("[PASS] test_decode_integer_null_input\n");
    return 0;
}

/* Test ber_decode_INTEGER with too short buffer */
static int test_decode_integer_too_short(void)
{
    CK_BYTE encoded[] = {0x02};  /* Only tag, no length */
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_INTEGER(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_integer_too_short: should have failed on too short buffer\n");
        return 1;
    }

    printf("[PASS] test_decode_integer_too_short\n");
    return 0;
}

/* Test round-trip: encode then decode INTEGER */
static int test_roundtrip_integer(void)
{
    CK_BYTE original[] = {0x12, 0x34, 0x56, 0x78, 0x9A};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE *decoded = NULL;
    CK_ULONG decoded_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;

    /* Encode */
    rv = ber_encode_INTEGER(FALSE, &encoded, &encoded_len, original, sizeof(original));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_integer: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Decode */
    rv = ber_decode_INTEGER(encoded, encoded_len, &decoded, &decoded_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_integer: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    /* Compare */
    if (decoded_len != sizeof(original)) {
        fprintf(stderr, "[FAIL] test_roundtrip_integer: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(original), decoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_roundtrip_integer", original, decoded, decoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_roundtrip_integer\n");
    return result;
}

/* Test ber_encode_OCTET_STRING with short form length */
static int test_encode_octet_string_short(void)
{
    CK_BYTE data[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};  /* "Hello" */
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Expected: 0x04 (OCTET STRING tag), 0x05 (length), data */
    CK_BYTE expected[] = {0x04, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F};

    rv = ber_encode_OCTET_STRING(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_short: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), encoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_encode_octet_string_short", expected, encoded, encoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_octet_string_short\n");
    return result;
}

/* Test ber_encode_OCTET_STRING with long form length */
static int test_encode_octet_string_long_form(void)
{
    CK_BYTE data[150];
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(data, 0x55, sizeof(data));

    rv = ber_encode_OCTET_STRING(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_long_form: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Expected: 0x04 (OCTET STRING tag), 0x81 (long form, 1 byte), 0x96 (150), data */
    if (encoded_len != 1 + 2 + 150) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_long_form: length mismatch (expected 153, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x04 || encoded[1] != 0x81 || encoded[2] != 150) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_long_form: header mismatch\n");
        result = 1;
    } else if (memcmp(&encoded[3], data, 150) != 0) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_long_form: data mismatch\n");
        result = 1;
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_octet_string_long_form\n");
    return result;
}

/* Test ber_encode_OCTET_STRING with 3-byte long form length (256-65535 bytes) */
static int test_encode_octet_string_3byte_long_form(void)
{
    CK_BYTE *data = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG data_size = 400;  /* 256+ bytes to trigger 3-byte long form */

    /* Allocate and fill data */
    data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_3byte_long_form: malloc failed\n");
        return 1;
    }
    memset(data, 0x55, data_size);

    rv = ber_encode_OCTET_STRING(FALSE, &encoded, &encoded_len, data, data_size);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_3byte_long_form: encode failed with rv=%lu\n", rv);
        free(data);
        return 1;
    }

    /* Expected: 0x04 (OCTET STRING tag), 0x82 (long form, 2 bytes length),
     * 0x01 0x90 (400 in big-endian), data */
    if (encoded_len != 1 + 3 + 400) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_3byte_long_form: length mismatch (expected 404, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x04 || encoded[1] != 0x82 ||
               encoded[2] != 0x01 || encoded[3] != 0x90) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_3byte_long_form: header mismatch\n");
        fprintf(stderr, "  Expected: 04 82 01 90\n");
        fprintf(stderr, "  Got:      %02X %02X %02X %02X\n",
                encoded[0], encoded[1], encoded[2], encoded[3]);
        result = 1;
    } else if (memcmp(&encoded[4], data, 400) != 0) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_3byte_long_form: data mismatch\n");
        result = 1;
    }

    free(data);
    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_octet_string_3byte_long_form\n");
    return result;
}

/* Test ber_encode_OCTET_STRING with 4-byte long form length (65536+ bytes) */
static int test_encode_octet_string_4byte_long_form(void)
{
    CK_BYTE *data = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG data_size = 80000;  /* 65536+ bytes to trigger 4-byte long form */

    /* Allocate and fill data */
    data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_4byte_long_form: malloc failed\n");
        return 1;
    }
    memset(data, 0x55, data_size);

    rv = ber_encode_OCTET_STRING(FALSE, &encoded, &encoded_len, data, data_size);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_4byte_long_form: encode failed with rv=%lu\n", rv);
        free(data);
        return 1;
    }

    /* Expected: 0x04 (OCTET STRING tag), 0x83 (long form, 3 bytes length),
     * 0x01 0x38 0x80 (80000 in big-endian), data */
    if (encoded_len != 1 + 4 + 80000) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_4byte_long_form: length mismatch (expected 80005, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x04 || encoded[1] != 0x83 ||
               encoded[2] != 0x01 || encoded[3] != 0x38 || encoded[4] != 0x80) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_4byte_long_form: header mismatch\n");
        fprintf(stderr, "  Expected: 04 83 01 38 80\n");
        fprintf(stderr, "  Got:      %02X %02X %02X %02X %02X\n",
                encoded[0], encoded[1], encoded[2], encoded[3], encoded[4]);
        result = 1;
    } else if (memcmp(&encoded[5], data, 80000) != 0) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_4byte_long_form: data mismatch\n");
        result = 1;
    }

    free(data);
    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_octet_string_4byte_long_form\n");
    return result;
}

/* Test ber_encode_OCTET_STRING with single byte */
static int test_encode_octet_string_single_byte(void)
{
    CK_BYTE data[] = {0xFF};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Expected: 0x04 (OCTET STRING tag), 0x01 (length), data */
    CK_BYTE expected[] = {0x04, 0x01, 0xFF};

    rv = ber_encode_OCTET_STRING(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_single_byte: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_single_byte: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), encoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_encode_octet_string_single_byte", expected, encoded, encoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_octet_string_single_byte\n");
    return result;
}

/* Test ber_encode_OCTET_STRING with all zeros */
static int test_encode_octet_string_all_zeros(void)
{
    CK_BYTE data[10] = {0};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    rv = ber_encode_OCTET_STRING(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_all_zeros: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Verify encoding and that all data bytes are zero */
    if (encoded_len != 12) {  /* 1 + 1 + 10 */
        fprintf(stderr, "[FAIL] test_encode_octet_string_all_zeros: length mismatch (expected 12, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x04 || encoded[1] != 10) {
        fprintf(stderr, "[FAIL] test_encode_octet_string_all_zeros: header mismatch\n");
        result = 1;
    } else {
        for (int i = 2; i < 12; i++) {
            if (encoded[i] != 0x00) {
                fprintf(stderr, "[FAIL] test_encode_octet_string_all_zeros: data not all zeros\n");
                result = 1;
                break;
            }
        }
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_octet_string_all_zeros\n");
    return result;
}

/* Test ber_decode_OCTET_STRING with short form length */
static int test_decode_octet_string_short(void)
{
    CK_BYTE encoded[] = {0x04, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F};
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;

    CK_BYTE expected[] = {0x48, 0x65, 0x6C, 0x6C, 0x6F};

    rv = ber_decode_OCTET_STRING(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_short: decode failed with rv=%lu\n", rv);
        return 1;
    }

    if (data_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), data_len);
        result = 1;
    } else if (field_len != sizeof(encoded)) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_short: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(encoded), field_len);
        result = 1;
    } else {
        result = compare_bytes("test_decode_octet_string_short", expected, data, data_len);
    }

    if (result == 0)
        printf("[PASS] test_decode_octet_string_short\n");
    return result;
}

/* Test ber_decode_OCTET_STRING with 3-byte long form length (256-65535 bytes) */
static int test_decode_octet_string_3byte_long_form(void)
{
    CK_BYTE *encoded = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG expected_data_size = 400;

    /* Build encoded data: 0x04 (tag), 0x82 (long form 2 bytes), 0x01 0x90 (400), data */
    encoded = malloc(1 + 3 + expected_data_size);
    if (encoded == NULL) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_3byte_long_form: malloc failed\n");
        return 1;
    }

    encoded[0] = 0x04;  /* OCTET STRING tag */
    encoded[1] = 0x82;  /* Long form: 2 length bytes follow */
    encoded[2] = 0x01;  /* Length high byte */
    encoded[3] = 0x90;  /* Length low byte (400 = 0x0190) */
    memset(&encoded[4], 0x55, expected_data_size);

    rv = ber_decode_OCTET_STRING(encoded, 1 + 3 + expected_data_size, &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_3byte_long_form: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    if (data_len != expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_3byte_long_form: data length mismatch (expected %lu, got %lu)\n",
                expected_data_size, data_len);
        result = 1;
    } else if (field_len != 1 + 3 + expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_3byte_long_form: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)(1 + 3 + expected_data_size), field_len);
        result = 1;
    } else {
        /* Verify data content */
        for (CK_ULONG i = 0; i < expected_data_size; i++) {
            if (data[i] != 0x55) {
                fprintf(stderr, "[FAIL] test_decode_octet_string_3byte_long_form: data mismatch at byte %lu\n", i);
                result = 1;
                break;
            }
        }
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_decode_octet_string_3byte_long_form\n");
    return result;
}

/* Test ber_decode_OCTET_STRING with 4-byte long form length (65536+ bytes) */
static int test_decode_octet_string_4byte_long_form(void)
{
    CK_BYTE *encoded = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG expected_data_size = 80000;

    /* Build encoded data: 0x04 (tag), 0x83 (long form 3 bytes), 0x01 0x38 0x80 (80000), data */
    encoded = malloc(1 + 4 + expected_data_size);
    if (encoded == NULL) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_4byte_long_form: malloc failed\n");
        return 1;
    }

    encoded[0] = 0x04;  /* OCTET STRING tag */
    encoded[1] = 0x83;  /* Long form: 3 length bytes follow */
    encoded[2] = 0x01;  /* Length high byte */
    encoded[3] = 0x38;  /* Length middle byte */
    encoded[4] = 0x80;  /* Length low byte (80000 = 0x013880) */
    memset(&encoded[5], 0x55, expected_data_size);

    rv = ber_decode_OCTET_STRING(encoded, 1 + 4 + expected_data_size, &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_4byte_long_form: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    if (data_len != expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_4byte_long_form: data length mismatch (expected %lu, got %lu)\n",
                expected_data_size, data_len);
        result = 1;
    } else if (field_len != 1 + 4 + expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_4byte_long_form: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)(1 + 4 + expected_data_size), field_len);
        result = 1;
    } else {
        /* Verify data content - check first and last bytes */
        if (data[0] != 0x55 || data[expected_data_size - 1] != 0x55) {
            fprintf(stderr, "[FAIL] test_decode_octet_string_4byte_long_form: data mismatch\n");
            result = 1;
        }
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_decode_octet_string_4byte_long_form\n");
    return result;
}

/* Test ber_decode_OCTET_STRING with invalid tag */
static int test_decode_octet_string_invalid_tag(void)
{
    CK_BYTE encoded[] = {0x02, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F};  /* Wrong tag (INTEGER) */
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_OCTET_STRING(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_invalid_tag: should have failed\n");
        return 1;
    }

    printf("[PASS] test_decode_octet_string_invalid_tag\n");
    return 0;
}

/* Test ber_decode_OCTET_STRING with NULL input */
static int test_decode_octet_string_null_input(void)
{
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_OCTET_STRING(NULL, 10, &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_octet_string_null_input: should have failed on NULL input\n");
        return 1;
    }

    printf("[PASS] test_decode_octet_string_null_input\n");
    return 0;
}

/* Test round-trip: encode then decode OCTET_STRING */
static int test_roundtrip_octet_string(void)
{
    CK_BYTE original[] = "Test data for round-trip encoding";
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE *decoded = NULL;
    CK_ULONG decoded_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;

    /* Encode */
    rv = ber_encode_OCTET_STRING(FALSE, &encoded, &encoded_len, original, sizeof(original) - 1);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_octet_string: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Decode */
    rv = ber_decode_OCTET_STRING(encoded, encoded_len, &decoded, &decoded_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_octet_string: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    /* Compare */
    if (decoded_len != sizeof(original) - 1) {
        fprintf(stderr, "[FAIL] test_roundtrip_octet_string: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)(sizeof(original) - 1), decoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_roundtrip_octet_string", original, decoded, decoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_roundtrip_octet_string\n");
    return result;
}

/* Test ber_encode_BIT_STRING with short form length */
static int test_encode_bit_string_short(void)
{
    CK_BYTE data[] = {0x01, 0x02, 0x03};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    CK_BYTE unused_bits = 0x00;

    /* Expected: 0x03 (BIT STRING tag), 0x04 (length = data + unused_bits byte),
     * 0x00 (unused bits), data */
    CK_BYTE expected[] = {0x03, 0x04, 0x00, 0x01, 0x02, 0x03};

    rv = ber_encode_BIT_STRING(FALSE, &encoded, &encoded_len, data, sizeof(data), unused_bits);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_short: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), encoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_encode_bit_string_short", expected, encoded, encoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_bit_string_short\n");
    return result;
}

/* Test ber_encode_BIT_STRING with long form length (128-255 bytes) */
static int test_encode_bit_string_long_form(void)
{
    CK_BYTE data[150];
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    CK_BYTE unused_bits = 0x03;  /* 3 unused bits */

    /* Fill with test data */
    memset(data, 0x55, sizeof(data));

    rv = ber_encode_BIT_STRING(FALSE, &encoded, &encoded_len, data, sizeof(data), unused_bits);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_long_form: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Expected: 0x03 (BIT STRING tag), 0x81 (long form, 1 byte length),
     * 0x97 (151 = 150 + 1), 0x03 (unused bits), data */
    if (encoded_len != 1 + 2 + 1 + 150) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_long_form: length mismatch (expected 154, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x03 || encoded[1] != 0x81 || encoded[2] != 151 || encoded[3] != 0x03) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_long_form: header mismatch\n");
        result = 1;
    } else if (memcmp(&encoded[4], data, 150) != 0) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_long_form: data mismatch\n");
        result = 1;
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_bit_string_long_form\n");
    return result;
}

/* Test ber_encode_BIT_STRING with 3-byte long form length (256-65535 bytes) */
static int test_encode_bit_string_3byte_long_form(void)
{
    CK_BYTE *data = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG data_size = 300;
    CK_BYTE unused_bits = 0x05;  /* 5 unused bits */

    /* Allocate and fill with test data */
    data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_3byte_long_form: malloc failed\n");
        return 1;
    }
    memset(data, 0xAA, data_size);

    rv = ber_encode_BIT_STRING(FALSE, &encoded, &encoded_len, data, data_size, unused_bits);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_3byte_long_form: encode failed with rv=%lu\n", rv);
        free(data);
        return 1;
    }

    /* Expected: 0x03 (BIT STRING tag), 0x82 (long form, 2 bytes length),
     * 0x01 0x2D (301 = 300 + 1 in big-endian), 0x05 (unused bits), data */
    if (encoded_len != 1 + 3 + 1 + 300) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_3byte_long_form: length mismatch (expected 305, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x03 || encoded[1] != 0x82 ||
               encoded[2] != 0x01 || encoded[3] != 0x2D || encoded[4] != 0x05) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_3byte_long_form: header mismatch\n");
        fprintf(stderr, "  Expected: 03 82 01 2D 05\n");
        fprintf(stderr, "  Got:      %02X %02X %02X %02X %02X\n",
                encoded[0], encoded[1], encoded[2], encoded[3], encoded[4]);
        result = 1;
    } else if (memcmp(&encoded[5], data, 300) != 0) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_3byte_long_form: data mismatch\n");
        result = 1;
    }

    free(data);
    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_bit_string_3byte_long_form\n");
    return result;
}

/* Test ber_encode_BIT_STRING with 4-byte long form length (65536+ bytes) */
static int test_encode_bit_string_4byte_long_form(void)
{
    CK_BYTE *data = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG data_size = 70000;
    CK_BYTE unused_bits = 0x07;  /* 7 unused bits */

    /* Allocate and fill with test data */
    data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_4byte_long_form: malloc failed\n");
        return 1;
    }
    memset(data, 0xCC, data_size);

    rv = ber_encode_BIT_STRING(FALSE, &encoded, &encoded_len, data, data_size, unused_bits);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_4byte_long_form: encode failed with rv=%lu\n", rv);
        free(data);
        return 1;
    }

    /* Expected: 0x03 (BIT STRING tag), 0x83 (long form, 3 bytes length),
     * 0x01 0x11 0x71 (70001 = 70000 + 1 in big-endian), 0x07 (unused bits), data */
    if (encoded_len != 1 + 4 + 1 + 70000) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_4byte_long_form: length mismatch (expected 70006, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x03 || encoded[1] != 0x83 ||
               encoded[2] != 0x01 || encoded[3] != 0x11 || encoded[4] != 0x71 || encoded[5] != 0x07) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_4byte_long_form: header mismatch\n");
        fprintf(stderr, "  Expected: 03 83 01 11 71 07\n");
        fprintf(stderr, "  Got:      %02X %02X %02X %02X %02X %02X\n",
                encoded[0], encoded[1], encoded[2], encoded[3], encoded[4], encoded[5]);
        result = 1;
    } else if (encoded[6] != 0xCC || encoded[encoded_len - 1] != 0xCC) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_4byte_long_form: data mismatch\n");
        result = 1;
    }

    free(data);
    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_bit_string_4byte_long_form\n");
    return result;
}

/* Test ber_encode_BIT_STRING with length_only mode */
static int test_encode_bit_string_length_only(void)
{
    CK_BYTE data[] = {0x01, 0x02, 0x03};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    CK_BYTE unused_bits = 0x00;

    rv = ber_encode_BIT_STRING(TRUE, &encoded, &encoded_len, data, sizeof(data), unused_bits);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_length_only: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Expected length: tag (1) + length (1) + unused_bits (1) + data (3) = 6 */
    if (encoded_len != 6) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_length_only: length mismatch (expected 6, got %lu)\n",
                encoded_len);
        return 1;
    }

    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_length_only: encoded should be NULL in length_only mode\n");
        return 1;
    }

    printf("[PASS] test_encode_bit_string_length_only\n");
    return 0;
}

/* Test ber_encode_BIT_STRING with various unused_bits values */
static int test_encode_bit_string_unused_bits(void)
{
    CK_BYTE data[] = {0xFF};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    CK_BYTE unused_bits = 0x04;  /* 4 unused bits */

    /* Expected: 0x03 (BIT STRING tag), 0x02 (length), 0x04 (unused bits), 0xFF (data) */
    CK_BYTE expected[] = {0x03, 0x02, 0x04, 0xFF};

    rv = ber_encode_BIT_STRING(FALSE, &encoded, &encoded_len, data, sizeof(data), unused_bits);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_unused_bits: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_encode_bit_string_unused_bits: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), encoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_encode_bit_string_unused_bits", expected, encoded, encoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_bit_string_unused_bits\n");
    return result;
}

/* Test ber_decode_BIT_STRING with short form length */
static int test_decode_bit_string_short(void)
{
    /* BIT STRING with unused bits byte (0x00) followed by data */
    CK_BYTE encoded[] = {0x03, 0x04, 0x00, 0x01, 0x02, 0x03};
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;

    /* Expected: includes unused bits byte */
    CK_BYTE expected[] = {0x00, 0x01, 0x02, 0x03};

    rv = ber_decode_BIT_STRING(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_bit_string_short: decode failed with rv=%lu\n", rv);
        return 1;
    }

    if (data_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_decode_bit_string_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), data_len);
        result = 1;
    } else if (field_len != sizeof(encoded)) {
        fprintf(stderr, "[FAIL] test_decode_bit_string_short: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(encoded), field_len);
        result = 1;
    } else {
        result = compare_bytes("test_decode_bit_string_short", expected, data, data_len);
    }

    if (result == 0)
        printf("[PASS] test_decode_bit_string_short\n");
    return result;
}

/* Test ber_decode_BIT_STRING with invalid tag */
static int test_decode_bit_string_invalid_tag(void)
{
    CK_BYTE encoded[] = {0x04, 0x04, 0x00, 0x01, 0x02, 0x03};  /* Wrong tag (OCTET STRING) */
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_BIT_STRING(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_bit_string_invalid_tag: should have failed\n");
        return 1;
    }

    printf("[PASS] test_decode_bit_string_invalid_tag\n");
    return 0;
}

/* Test ber_decode_BIT_STRING with NULL input */
static int test_decode_bit_string_null_input(void)
{
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_BIT_STRING(NULL, 10, &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_bit_string_null_input: should have failed on NULL input\n");
        return 1;
    }

    printf("[PASS] test_decode_bit_string_null_input\n");
    return 0;
}

/* Test ber_decode_BIT_STRING with too short length (no unused bits byte) */
static int test_decode_bit_string_no_unused_byte(void)
{
    CK_BYTE encoded[] = {0x03, 0x00};  /* BIT STRING with length 0 - invalid */
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_BIT_STRING(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_bit_string_no_unused_byte: should have failed (no unused bits byte)\n");
        return 1;
    }

    printf("[PASS] test_decode_bit_string_no_unused_byte\n");
    return 0;
}

/* Test ber_encode_BIT_STRING roundtrip */
static int test_roundtrip_bit_string(void)
{
    CK_BYTE original[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE *decoded = NULL;
    CK_ULONG decoded_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;
    CK_BYTE unused_bits = 0x02;  /* 2 unused bits */

    /* Encode */
    rv = ber_encode_BIT_STRING(FALSE, &encoded, &encoded_len, original, sizeof(original), unused_bits);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_bit_string: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Decode */
    rv = ber_decode_BIT_STRING(encoded, encoded_len, &decoded, &decoded_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_bit_string: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    /* Verify: decoded includes unused_bits byte + original data */
    if (decoded_len != sizeof(original) + 1) {
        fprintf(stderr, "[FAIL] test_roundtrip_bit_string: decoded length mismatch (expected %lu, got %lu)\n",
                (unsigned long)(sizeof(original) + 1), decoded_len);
        result = 1;
    } else if (decoded[0] != unused_bits) {
        fprintf(stderr, "[FAIL] test_roundtrip_bit_string: unused_bits mismatch (expected 0x%02X, got 0x%02X)\n",
                unused_bits, decoded[0]);
        result = 1;
    } else if (memcmp(&decoded[1], original, sizeof(original)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_bit_string: data mismatch\n");
        result = 1;
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_roundtrip_bit_string\n");
    return result;
}

/* Test ber_encode_SEQUENCE with short form length */
static int test_encode_sequence_short(void)
{
    CK_BYTE data[] = {0x02, 0x01, 0x05};  /* INTEGER 5 */
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    /* Expected: 0x30 (SEQUENCE tag), 0x03 (length), data */
    CK_BYTE expected[] = {0x30, 0x03, 0x02, 0x01, 0x05};

    rv = ber_encode_SEQUENCE(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_sequence_short: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_encode_sequence_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), encoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_encode_sequence_short", expected, encoded, encoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_sequence_short\n");
    return result;
}

/* Test ber_encode_SEQUENCE with long form length */
static int test_encode_sequence_long_form(void)
{
    CK_BYTE data[200];
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    memset(data, 0x42, sizeof(data));

    rv = ber_encode_SEQUENCE(FALSE, &encoded, &encoded_len, data, sizeof(data));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_sequence_long_form: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Expected: 0x30 (SEQUENCE tag), 0x81 (long form, 1 byte), 0xC8 (200), data */
    if (encoded_len != 1 + 2 + 200) {
        fprintf(stderr, "[FAIL] test_encode_sequence_long_form: length mismatch (expected 203, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x30 || encoded[1] != 0x81 || encoded[2] != 200) {
        fprintf(stderr, "[FAIL] test_encode_sequence_long_form: header mismatch\n");
        result = 1;
    } else if (memcmp(&encoded[3], data, 200) != 0) {
        fprintf(stderr, "[FAIL] test_encode_sequence_long_form: data mismatch\n");
        result = 1;
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_sequence_long_form\n");
    return result;
}

/* Test ber_encode_SEQUENCE with 3-byte long form length (256-65535 bytes) */
static int test_encode_sequence_3byte_long_form(void)
{
    CK_BYTE *data = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG data_size = 350;  /* 256+ bytes to trigger 3-byte long form */

    /* Allocate and fill data */
    data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "[FAIL] test_encode_sequence_3byte_long_form: malloc failed\n");
        return 1;
    }
    memset(data, 0x33, data_size);

    rv = ber_encode_SEQUENCE(FALSE, &encoded, &encoded_len, data, data_size);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_sequence_3byte_long_form: encode failed with rv=%lu\n", rv);
        free(data);
        return 1;
    }

    /* Expected: 0x30 (SEQUENCE tag), 0x82 (long form, 2 bytes length),
     * 0x01 0x5E (350 in big-endian), data */
    if (encoded_len != 1 + 3 + 350) {
        fprintf(stderr, "[FAIL] test_encode_sequence_3byte_long_form: length mismatch (expected 354, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x30 || encoded[1] != 0x82 ||
               encoded[2] != 0x01 || encoded[3] != 0x5E) {
        fprintf(stderr, "[FAIL] test_encode_sequence_3byte_long_form: header mismatch\n");
        fprintf(stderr, "  Expected: 30 82 01 5E\n");
        fprintf(stderr, "  Got:      %02X %02X %02X %02X\n",
                encoded[0], encoded[1], encoded[2], encoded[3]);
        result = 1;
    } else if (memcmp(&encoded[4], data, 350) != 0) {
        fprintf(stderr, "[FAIL] test_encode_sequence_3byte_long_form: data mismatch\n");
        result = 1;
    }

    free(data);
    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_sequence_3byte_long_form\n");
    return result;
}

/* Test ber_encode_SEQUENCE with 4-byte long form length (65536+ bytes) */
static int test_encode_sequence_4byte_long_form(void)
{
    CK_BYTE *data = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG data_size = 90000;  /* 65536+ bytes to trigger 4-byte long form */

    /* Allocate and fill data */
    data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "[FAIL] test_encode_sequence_4byte_long_form: malloc failed\n");
        return 1;
    }
    memset(data, 0x33, data_size);

    rv = ber_encode_SEQUENCE(FALSE, &encoded, &encoded_len, data, data_size);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_sequence_4byte_long_form: encode failed with rv=%lu\n", rv);
        free(data);
        return 1;
    }

    /* Expected: 0x30 (SEQUENCE tag), 0x83 (long form, 3 bytes length),
     * 0x01 0x5F 0x90 (90000 in big-endian), data */
    if (encoded_len != 1 + 4 + 90000) {
        fprintf(stderr, "[FAIL] test_encode_sequence_4byte_long_form: length mismatch (expected 90005, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x30 || encoded[1] != 0x83 ||
               encoded[2] != 0x01 || encoded[3] != 0x5F || encoded[4] != 0x90) {
        fprintf(stderr, "[FAIL] test_encode_sequence_4byte_long_form: header mismatch\n");
        fprintf(stderr, "  Expected: 30 83 01 5F 90\n");
        fprintf(stderr, "  Got:      %02X %02X %02X %02X %02X\n",
                encoded[0], encoded[1], encoded[2], encoded[3], encoded[4]);
        result = 1;
    } else if (memcmp(&encoded[5], data, 90000) != 0) {
        fprintf(stderr, "[FAIL] test_encode_sequence_4byte_long_form: data mismatch\n");
        result = 1;
    }

    free(data);
    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_sequence_4byte_long_form\n");
    return result;
}

/* Test ber_decode_SEQUENCE with short form length */
static int test_decode_sequence_short(void)
{
    CK_BYTE encoded[] = {0x30, 0x03, 0x02, 0x01, 0x05};
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;

    CK_BYTE expected[] = {0x02, 0x01, 0x05};

    rv = ber_decode_SEQUENCE(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_sequence_short: decode failed with rv=%lu\n", rv);
        return 1;
    }

    if (data_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_decode_sequence_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), data_len);
        result = 1;
    } else if (field_len != sizeof(encoded)) {
        fprintf(stderr, "[FAIL] test_decode_sequence_short: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(encoded), field_len);
        result = 1;
    } else {
        result = compare_bytes("test_decode_sequence_short", expected, data, data_len);
    }

    if (result == 0)
        printf("[PASS] test_decode_sequence_short\n");
    return result;
}

/* Test ber_decode_SEQUENCE with 3-byte long form length (256-65535 bytes) */
static int test_decode_sequence_3byte_long_form(void)
{
    CK_BYTE *encoded = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG expected_data_size = 350;

    /* Build encoded data: 0x30 (tag), 0x82 (long form 2 bytes), 0x01 0x5E (350), data */
    encoded = malloc(1 + 3 + expected_data_size);
    if (encoded == NULL) {
        fprintf(stderr, "[FAIL] test_decode_sequence_3byte_long_form: malloc failed\n");
        return 1;
    }

    encoded[0] = 0x30;  /* SEQUENCE tag */
    encoded[1] = 0x82;  /* Long form: 2 length bytes follow */
    encoded[2] = 0x01;  /* Length high byte */
    encoded[3] = 0x5E;  /* Length low byte (350 = 0x015E) */
    memset(&encoded[4], 0x33, expected_data_size);

    rv = ber_decode_SEQUENCE(encoded, 1 + 3 + expected_data_size, &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_sequence_3byte_long_form: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    if (data_len != expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_sequence_3byte_long_form: data length mismatch (expected %lu, got %lu)\n",
                expected_data_size, data_len);
        result = 1;
    } else if (field_len != 1 + 3 + expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_sequence_3byte_long_form: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)(1 + 3 + expected_data_size), field_len);
        result = 1;
    } else {
        /* Verify data content */
        for (CK_ULONG i = 0; i < expected_data_size; i++) {
            if (data[i] != 0x33) {
                fprintf(stderr, "[FAIL] test_decode_sequence_3byte_long_form: data mismatch at byte %lu\n", i);
                result = 1;
                break;
            }
        }
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_decode_sequence_3byte_long_form\n");
    return result;
}

/* Test ber_decode_SEQUENCE with 4-byte long form length (65536+ bytes) */
static int test_decode_sequence_4byte_long_form(void)
{
    CK_BYTE *encoded = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG expected_data_size = 90000;

    /* Build encoded data: 0x30 (tag), 0x83 (long form 3 bytes), 0x01 0x5F 0x90 (90000), data */
    encoded = malloc(1 + 4 + expected_data_size);
    if (encoded == NULL) {
        fprintf(stderr, "[FAIL] test_decode_sequence_4byte_long_form: malloc failed\n");
        return 1;
    }

    encoded[0] = 0x30;  /* SEQUENCE tag */
    encoded[1] = 0x83;  /* Long form: 3 length bytes follow */
    encoded[2] = 0x01;  /* Length high byte */
    encoded[3] = 0x5F;  /* Length middle byte */
    encoded[4] = 0x90;  /* Length low byte (90000 = 0x015F90) */
    memset(&encoded[5], 0x33, expected_data_size);

    rv = ber_decode_SEQUENCE(encoded, 1 + 4 + expected_data_size, &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_sequence_4byte_long_form: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    if (data_len != expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_sequence_4byte_long_form: data length mismatch (expected %lu, got %lu)\n",
                expected_data_size, data_len);
        result = 1;
    } else if (field_len != 1 + 4 + expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_sequence_4byte_long_form: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)(1 + 4 + expected_data_size), field_len);
        result = 1;
    } else {
        /* Verify data content - check first and last bytes */
        if (data[0] != 0x33 || data[expected_data_size - 1] != 0x33) {
            fprintf(stderr, "[FAIL] test_decode_sequence_4byte_long_form: data mismatch\n");
            result = 1;
        }
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_decode_sequence_4byte_long_form\n");
    return result;
}

/* Test ber_decode_SEQUENCE with invalid tag */
static int test_decode_sequence_invalid_tag(void)
{
    CK_BYTE encoded[] = {0x04, 0x03, 0x02, 0x01, 0x05};  /* Wrong tag (OCTET STRING) */
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_SEQUENCE(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_sequence_invalid_tag: should have failed\n");
        return 1;
    }

    printf("[PASS] test_decode_sequence_invalid_tag\n");
    return 0;
}

/* Test ber_decode_SEQUENCE with empty sequence */
static int test_decode_sequence_empty(void)
{
    CK_BYTE encoded[] = {0x30, 0x00};  /* Empty SEQUENCE */
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_SEQUENCE(encoded, sizeof(encoded), &data, &data_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_sequence_empty: decode failed with rv=%lu\n", rv);
        return 1;
    }

    if (data_len != 0) {
        fprintf(stderr, "[FAIL] test_decode_sequence_empty: expected empty data, got %lu bytes\n", data_len);
        return 1;
    }

    if (field_len != 2) {
        fprintf(stderr, "[FAIL] test_decode_sequence_empty: field_len mismatch (expected 2, got %lu)\n", field_len);
        return 1;
    }

    printf("[PASS] test_decode_sequence_empty\n");
    return 0;
}

/* Test ber_decode_SEQUENCE with NULL input */
static int test_decode_sequence_null_input(void)
{
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;

    rv = ber_decode_SEQUENCE(NULL, 10, &data, &data_len, &field_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_sequence_null_input: should have failed on NULL input\n");
        return 1;
    }

    printf("[PASS] test_decode_sequence_null_input\n");
    return 0;
}

/* Test round-trip: encode then decode SEQUENCE */
static int test_roundtrip_sequence(void)
{
    CK_BYTE original[] = {0x02, 0x01, 0x05, 0x04, 0x03, 0x61, 0x62, 0x63};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE *decoded = NULL;
    CK_ULONG decoded_len = 0;
    CK_ULONG field_len = 0;
    CK_RV rv;
    int result = 0;

    /* Encode */
    rv = ber_encode_SEQUENCE(FALSE, &encoded, &encoded_len, original, sizeof(original));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_sequence: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Decode */
    rv = ber_decode_SEQUENCE(encoded, encoded_len, &decoded, &decoded_len, &field_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_sequence: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    /* Compare */
    if (decoded_len != sizeof(original)) {
        fprintf(stderr, "[FAIL] test_roundtrip_sequence: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(original), decoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_roundtrip_sequence", original, decoded, decoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_roundtrip_sequence\n");
    return result;
}

/* Test ber_encode_CHOICE with primitive (non-constructed) short form */
static int test_encode_choice_primitive_short(void)
{
    CK_BYTE data[] = {0x01, 0x02, 0x03};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE option = 0x05;  /* Option/tag number */
    CK_RV rv;
    int result = 0;

    /* Expected: 0x85 (context-specific, primitive, tag 5), 0x03 (length), data */
    CK_BYTE expected[] = {0x85, 0x03, 0x01, 0x02, 0x03};

    rv = ber_encode_CHOICE(FALSE, option, &encoded, &encoded_len, data, sizeof(data), FALSE);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_choice_primitive_short: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_encode_choice_primitive_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), encoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_encode_choice_primitive_short", expected, encoded, encoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_choice_primitive_short\n");
    return result;
}

/* Test ber_encode_CHOICE with constructed short form */
static int test_encode_choice_constructed_short(void)
{
    CK_BYTE data[] = {0x02, 0x01, 0x05};  /* INTEGER 5 */
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE option = 0x00;  /* Option/tag number 0 */
    CK_RV rv;
    int result = 0;

    /* Expected: 0xA0 (context-specific, constructed, tag 0), 0x03 (length), data */
    CK_BYTE expected[] = {0xA0, 0x03, 0x02, 0x01, 0x05};

    rv = ber_encode_CHOICE(FALSE, option, &encoded, &encoded_len, data, sizeof(data), TRUE);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_choice_constructed_short: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_encode_choice_constructed_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), encoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_encode_choice_constructed_short", expected, encoded, encoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_choice_constructed_short\n");
    return result;
}

/* Test ber_encode_CHOICE with long form length */
static int test_encode_choice_long_form(void)
{
    CK_BYTE data[150];
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE option = 0x03;
    CK_RV rv;
    int result = 0;

    memset(data, 0x42, sizeof(data));

    rv = ber_encode_CHOICE(FALSE, option, &encoded, &encoded_len, data, sizeof(data), FALSE);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_choice_long_form: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Expected: 0x83 (context-specific, primitive, tag 3), 0x81 (long form, 1 byte), 0x96 (150), data */
    if (encoded_len != 1 + 2 + 150) {
        fprintf(stderr, "[FAIL] test_encode_choice_long_form: length mismatch (expected 153, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x83 || encoded[1] != 0x81 || encoded[2] != 150) {
        fprintf(stderr, "[FAIL] test_encode_choice_long_form: header mismatch (got %02X %02X %02X)\n",
                encoded[0], encoded[1], encoded[2]);
        result = 1;
    } else if (memcmp(&encoded[3], data, 150) != 0) {
        fprintf(stderr, "[FAIL] test_encode_choice_long_form: data mismatch\n");
        result = 1;
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_choice_long_form\n");
    return result;
}

/* Test ber_encode_CHOICE with 3-byte long form length (256-65535 bytes) */
static int test_encode_choice_3byte_long_form(void)
{
    CK_BYTE *data = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG data_size = 500;  /* 256+ bytes to trigger 3-byte long form */

    /* Allocate and fill data */
    data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "[FAIL] test_encode_choice_3byte_long_form: malloc failed\n");
        return 1;
    }
    memset(data, 0x42, data_size);

    /* Encode with option 3, constructed=FALSE */
    rv = ber_encode_CHOICE(FALSE, 0x03, &encoded, &encoded_len, data, data_size, FALSE);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_choice_3byte_long_form: encode failed with rv=%lu\n", rv);
        free(data);
        return 1;
    }

    /* Expected: 0x83 (option 3, primitive), 0x82 (long form, 2 bytes length),
     * 0x01 0xF4 (500 in big-endian), data */
    if (encoded_len != 1 + 3 + 500) {
        fprintf(stderr, "[FAIL] test_encode_choice_3byte_long_form: length mismatch (expected 504, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x83 || encoded[1] != 0x82 ||
               encoded[2] != 0x01 || encoded[3] != 0xF4) {
        fprintf(stderr, "[FAIL] test_encode_choice_3byte_long_form: header mismatch\n");
        fprintf(stderr, "  Expected: 83 82 01 F4\n");
        fprintf(stderr, "  Got:      %02X %02X %02X %02X\n",
                encoded[0], encoded[1], encoded[2], encoded[3]);
        result = 1;
    } else if (memcmp(&encoded[4], data, 500) != 0) {
        fprintf(stderr, "[FAIL] test_encode_choice_3byte_long_form: data mismatch\n");
        result = 1;
    }

    free(data);
    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_choice_3byte_long_form\n");
    return result;
}

/* Test ber_encode_CHOICE with 4-byte long form length (65536+ bytes) */
static int test_encode_choice_4byte_long_form(void)
{
    CK_BYTE *data = NULL;
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG data_size = 100000;  /* 65536+ bytes to trigger 4-byte long form */

    /* Allocate and fill data */
    data = malloc(data_size);
    if (data == NULL) {
        fprintf(stderr, "[FAIL] test_encode_choice_4byte_long_form: malloc failed\n");
        return 1;
    }
    memset(data, 0x42, data_size);

    /* Encode with option 3, constructed=FALSE */
    rv = ber_encode_CHOICE(FALSE, 0x03, &encoded, &encoded_len, data, data_size, FALSE);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_choice_4byte_long_form: encode failed with rv=%lu\n", rv);
        free(data);
        return 1;
    }

    /* Expected: 0x83 (option 3, primitive), 0x83 (long form, 3 bytes length),
     * 0x01 0x86 0xA0 (100000 in big-endian), data */
    if (encoded_len != 1 + 4 + 100000) {
        fprintf(stderr, "[FAIL] test_encode_choice_4byte_long_form: length mismatch (expected 100005, got %lu)\n",
                encoded_len);
        result = 1;
    } else if (encoded[0] != 0x83 || encoded[1] != 0x83 ||
               encoded[2] != 0x01 || encoded[3] != 0x86 || encoded[4] != 0xA0) {
        fprintf(stderr, "[FAIL] test_encode_choice_4byte_long_form: header mismatch\n");
        fprintf(stderr, "  Expected: 83 83 01 86 A0\n");
        fprintf(stderr, "  Got:      %02X %02X %02X %02X %02X\n",
                encoded[0], encoded[1], encoded[2], encoded[3], encoded[4]);
        result = 1;
    } else if (memcmp(&encoded[5], data, 100000) != 0) {
        fprintf(stderr, "[FAIL] test_encode_choice_4byte_long_form: data mismatch\n");
        result = 1;
    }

    free(data);
    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_choice_4byte_long_form\n");
    return result;
}

/* Test ber_encode_CHOICE length_only mode */
static int test_encode_choice_length_only(void)
{
    CK_BYTE data[] = {0x01, 0x02, 0x03};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE option = 0x05;
    CK_RV rv;

    rv = ber_encode_CHOICE(TRUE, option, &encoded, &encoded_len, data, sizeof(data), FALSE);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_choice_length_only: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Expected length: 1 (tag) + 1 (length) + 3 (data) = 5 */
    if (encoded_len != 5) {
        fprintf(stderr, "[FAIL] test_encode_choice_length_only: length mismatch (expected 5, got %lu)\n",
                encoded_len);
        return 1;
    }

    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_choice_length_only: encoded should be NULL in length_only mode\n");
        return 1;
    }

    printf("[PASS] test_encode_choice_length_only\n");
    return 0;
}

/* Test ber_encode_CHOICE with maximum option value (0x1F) */
static int test_encode_choice_max_option(void)
{
    CK_BYTE data[] = {0x01, 0x02};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE option = 0x1F;  /* Maximum 5-bit value */
    CK_RV rv;
    int result = 0;

    rv = ber_encode_CHOICE(FALSE, option, &encoded, &encoded_len, data, sizeof(data), FALSE);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_choice_max_option: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Expected: 0x9F (context-specific, primitive, tag 31), length, data */
    if (encoded[0] != 0x9F) {
        fprintf(stderr, "[FAIL] test_encode_choice_max_option: tag mismatch (expected 0x9F, got %02X)\n",
                encoded[0]);
        result = 1;
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_choice_max_option\n");
    return result;
}

/* Test ber_decode_CHOICE with primitive short form */
static int test_decode_choice_primitive_short(void)
{
    CK_BYTE encoded[] = {0x85, 0x03, 0x01, 0x02, 0x03};
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_ULONG option = 0;
    CK_RV rv;
    int result = 0;

    CK_BYTE expected[] = {0x01, 0x02, 0x03};

    rv = ber_decode_CHOICE(encoded, sizeof(encoded), FALSE, &data, &data_len, &field_len, &option);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_choice_primitive_short: decode failed with rv=%lu\n", rv);
        return 1;
    }

    if (option != 0x05) {
        fprintf(stderr, "[FAIL] test_decode_choice_primitive_short: option mismatch (expected 5, got %lu)\n",
                option);
        result = 1;
    } else if (data_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_decode_choice_primitive_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), data_len);
        result = 1;
    } else if (field_len != sizeof(encoded)) {
        fprintf(stderr, "[FAIL] test_decode_choice_primitive_short: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(encoded), field_len);
        result = 1;
    } else {
        result = compare_bytes("test_decode_choice_primitive_short", expected, data, data_len);
    }

    if (result == 0)
        printf("[PASS] test_decode_choice_primitive_short\n");
    return result;
}

/* Test ber_decode_CHOICE with constructed short form */
static int test_decode_choice_constructed_short(void)
{
    CK_BYTE encoded[] = {0xA0, 0x03, 0x02, 0x01, 0x05};
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_ULONG option = 0;
    CK_RV rv;
    int result = 0;

    CK_BYTE expected[] = {0x02, 0x01, 0x05};

    rv = ber_decode_CHOICE(encoded, sizeof(encoded), TRUE, &data, &data_len, &field_len, &option);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_choice_constructed_short: decode failed with rv=%lu\n", rv);
        return 1;
    }

    if (option != 0x00) {
        fprintf(stderr, "[FAIL] test_decode_choice_constructed_short: option mismatch (expected 0, got %lu)\n",
                option);
        result = 1;
    } else if (data_len != sizeof(expected)) {
        fprintf(stderr, "[FAIL] test_decode_choice_constructed_short: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected), data_len);
        result = 1;
    } else if (field_len != sizeof(encoded)) {
        fprintf(stderr, "[FAIL] test_decode_choice_constructed_short: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(encoded), field_len);
        result = 1;
    } else {
        result = compare_bytes("test_decode_choice_constructed_short", expected, data, data_len);
    }

    if (result == 0)
        printf("[PASS] test_decode_choice_constructed_short\n");
    return result;
}

/* Test ber_decode_CHOICE with invalid constructed flag */
static int test_decode_choice_invalid_constructed(void)
{
    CK_BYTE encoded[] = {0xA0, 0x03, 0x02, 0x01, 0x05};  /* Constructed tag */
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_ULONG option = 0;
    CK_RV rv;

    /* Try to decode as primitive - should fail */
    rv = ber_decode_CHOICE(encoded, sizeof(encoded), FALSE, &data, &data_len, &field_len, &option);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_choice_invalid_constructed: should have failed\n");
        return 1;
    }

    printf("[PASS] test_decode_choice_invalid_constructed\n");
    return 0;
}

/* Test ber_decode_CHOICE with long form length */
static int test_decode_choice_long_form(void)
{
    CK_BYTE encoded[153];
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_ULONG option = 0;
    CK_RV rv;
    int result = 0;

    /* Build encoded data: tag, long form length, data */
    encoded[0] = 0x83;  /* context-specific, primitive, tag 3 */
    encoded[1] = 0x81;  /* long form, 1 byte length */
    encoded[2] = 150;   /* length = 150 */
    memset(&encoded[3], 0x42, 150);

    rv = ber_decode_CHOICE(encoded, sizeof(encoded), FALSE, &data, &data_len, &field_len, &option);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_choice_long_form: decode failed with rv=%lu\n", rv);
        return 1;
    }

    if (option != 0x03) {
        fprintf(stderr, "[FAIL] test_decode_choice_long_form: option mismatch (expected 3, got %lu)\n",
                option);
        result = 1;
    } else if (data_len != 150) {
        fprintf(stderr, "[FAIL] test_decode_choice_long_form: length mismatch (expected 150, got %lu)\n",
                data_len);
        result = 1;
    } else if (field_len != 153) {
        fprintf(stderr, "[FAIL] test_decode_choice_long_form: field_len mismatch (expected 153, got %lu)\n",
                field_len);
        result = 1;
    } else {
        /* Verify data content */
        for (CK_ULONG i = 0; i < 150; i++) {
            if (data[i] != 0x42) {
                fprintf(stderr, "[FAIL] test_decode_choice_long_form: data mismatch at position %lu\n", i);
                result = 1;
                break;
            }
        }
    }

    if (result == 0)
        printf("[PASS] test_decode_choice_long_form\n");
    return result;
}

/* Test ber_decode_CHOICE with 3-byte long form length (256-65535 bytes) */
static int test_decode_choice_3byte_long_form(void)
{
    CK_BYTE *encoded = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_ULONG option = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG expected_data_size = 500;

    /* Build encoded data: 0x83 (option 3, primitive), 0x82 (long form 2 bytes),
     * 0x01 0xF4 (500), data */
    encoded = malloc(1 + 3 + expected_data_size);
    if (encoded == NULL) {
        fprintf(stderr, "[FAIL] test_decode_choice_3byte_long_form: malloc failed\n");
        return 1;
    }

    encoded[0] = 0x83;  /* Option 3, primitive */
    encoded[1] = 0x82;  /* Long form: 2 length bytes follow */
    encoded[2] = 0x01;  /* Length high byte */
    encoded[3] = 0xF4;  /* Length low byte (500 = 0x01F4) */
    memset(&encoded[4], 0x42, expected_data_size);

    rv = ber_decode_CHOICE(encoded, 1 + 3 + expected_data_size, FALSE,
                           &data, &data_len, &field_len, &option);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_choice_3byte_long_form: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    if (option != 0x03) {
        fprintf(stderr, "[FAIL] test_decode_choice_3byte_long_form: option mismatch (expected 3, got %lu)\n",
                option);
        result = 1;
    } else if (data_len != expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_choice_3byte_long_form: data length mismatch (expected %lu, got %lu)\n",
                expected_data_size, data_len);
        result = 1;
    } else if (field_len != 1 + 3 + expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_choice_3byte_long_form: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)(1 + 3 + expected_data_size), field_len);
        result = 1;
    } else {
        /* Verify data content */
        for (CK_ULONG i = 0; i < expected_data_size; i++) {
            if (data[i] != 0x42) {
                fprintf(stderr, "[FAIL] test_decode_choice_3byte_long_form: data mismatch at byte %lu\n", i);
                result = 1;
                break;
            }
        }
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_decode_choice_3byte_long_form\n");
    return result;
}

/* Test ber_decode_CHOICE with 4-byte long form length (65536+ bytes) */
static int test_decode_choice_4byte_long_form(void)
{
    CK_BYTE *encoded = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_ULONG option = 0;
    CK_RV rv;
    int result = 0;
    const CK_ULONG expected_data_size = 100000;

    /* Build encoded data: 0x83 (option 3, primitive), 0x83 (long form 3 bytes),
     * 0x01 0x86 0xA0 (100000), data */
    encoded = malloc(1 + 4 + expected_data_size);
    if (encoded == NULL) {
        fprintf(stderr, "[FAIL] test_decode_choice_4byte_long_form: malloc failed\n");
        return 1;
    }

    encoded[0] = 0x83;  /* Option 3, primitive */
    encoded[1] = 0x83;  /* Long form: 3 length bytes follow */
    encoded[2] = 0x01;  /* Length high byte */
    encoded[3] = 0x86;  /* Length middle byte */
    encoded[4] = 0xA0;  /* Length low byte (100000 = 0x0186A0) */
    memset(&encoded[5], 0x42, expected_data_size);

    rv = ber_decode_CHOICE(encoded, 1 + 4 + expected_data_size, FALSE,
                           &data, &data_len, &field_len, &option);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_choice_4byte_long_form: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    if (option != 0x03) {
        fprintf(stderr, "[FAIL] test_decode_choice_4byte_long_form: option mismatch (expected 3, got %lu)\n",
                option);
        result = 1;
    } else if (data_len != expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_choice_4byte_long_form: data length mismatch (expected %lu, got %lu)\n",
                expected_data_size, data_len);
        result = 1;
    } else if (field_len != 1 + 4 + expected_data_size) {
        fprintf(stderr, "[FAIL] test_decode_choice_4byte_long_form: field_len mismatch (expected %lu, got %lu)\n",
                (unsigned long)(1 + 4 + expected_data_size), field_len);
        result = 1;
    } else {
        /* Verify data content - check first and last bytes */
        if (data[0] != 0x42 || data[expected_data_size - 1] != 0x42) {
            fprintf(stderr, "[FAIL] test_decode_choice_4byte_long_form: data mismatch\n");
            result = 1;
        }
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_decode_choice_4byte_long_form\n");
    return result;
}

/* Test ber_decode_CHOICE with NULL input */
static int test_decode_choice_null_input(void)
{
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_ULONG option = 0;
    CK_RV rv;

    rv = ber_decode_CHOICE(NULL, 10, FALSE, &data, &data_len, &field_len, &option);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_choice_null_input: should have failed on NULL input\n");
        return 1;
    }

    printf("[PASS] test_decode_choice_null_input\n");
    return 0;
}

/* Test ber_decode_CHOICE with too short buffer */
static int test_decode_choice_too_short(void)
{
    CK_BYTE encoded[] = {0xA0};  /* Only tag, no length */
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_ULONG field_len = 0;
    CK_ULONG option = 0;
    CK_RV rv;

    rv = ber_decode_CHOICE(encoded, sizeof(encoded), TRUE, &data, &data_len, &field_len, &option);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_choice_too_short: should have failed on too short buffer\n");
        return 1;
    }

    printf("[PASS] test_decode_choice_too_short\n");
    return 0;
}

/* Test round-trip: encode then decode CHOICE */
static int test_roundtrip_choice(void)
{
    CK_BYTE original[] = {0x02, 0x01, 0x05, 0x04, 0x03, 0x61, 0x62, 0x63};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE *decoded = NULL;
    CK_ULONG decoded_len = 0;
    CK_ULONG field_len = 0;
    CK_ULONG option = 0;
    CK_BYTE test_option = 0x07;
    CK_RV rv;
    int result = 0;

    /* Encode as constructed CHOICE */
    rv = ber_encode_CHOICE(FALSE, test_option, &encoded, &encoded_len, original, sizeof(original), TRUE);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_choice: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Decode */
    rv = ber_decode_CHOICE(encoded, encoded_len, TRUE, &decoded, &decoded_len, &field_len, &option);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_choice: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    /* Compare */
    if (option != test_option) {
        fprintf(stderr, "[FAIL] test_roundtrip_choice: option mismatch (expected %u, got %lu)\n",
                test_option, option);
        result = 1;
    } else if (decoded_len != sizeof(original)) {
        fprintf(stderr, "[FAIL] test_roundtrip_choice: length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(original), decoded_len);
        result = 1;
    } else {
        result = compare_bytes("test_roundtrip_choice", original, decoded, decoded_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_roundtrip_choice\n");
    return result;
}

/* Test ber_encode_PrivateKeyInfo with basic data */
static int test_encode_privatekeyinfo_basic(void)
{
    /* Simple algorithm ID (SEQUENCE with OID) */
    CK_BYTE algorithm_id[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                              0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};
    CK_BYTE priv_key[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;
    int result = 0;

    rv = ber_encode_PrivateKeyInfo(FALSE, &encoded, &encoded_len,
                                   algorithm_id, sizeof(algorithm_id),
                                   priv_key, sizeof(priv_key));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_privatekeyinfo_basic: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Verify it's a SEQUENCE */
    if (encoded[0] != 0x30) {
        fprintf(stderr, "[FAIL] test_encode_privatekeyinfo_basic: not a SEQUENCE (got %02X)\n",
                encoded[0]);
        result = 1;
    }

    /* Verify non-zero length */
    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_privatekeyinfo_basic: zero length\n");
        result = 1;
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_encode_privatekeyinfo_basic\n");
    return result;
}

/* Test ber_encode_PrivateKeyInfo length_only mode */
static int test_encode_privatekeyinfo_length_only(void)
{
    CK_BYTE algorithm_id[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                              0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};
    CK_BYTE priv_key[] = {0x01, 0x02, 0x03, 0x04, 0x05};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_RV rv;

    rv = ber_encode_PrivateKeyInfo(TRUE, &encoded, &encoded_len,
                                   algorithm_id, sizeof(algorithm_id),
                                   priv_key, sizeof(priv_key));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_encode_privatekeyinfo_length_only: encode failed with rv=%lu\n", rv);
        return 1;
    }

    if (encoded_len == 0) {
        fprintf(stderr, "[FAIL] test_encode_privatekeyinfo_length_only: zero length returned\n");
        return 1;
    }

    if (encoded != NULL) {
        fprintf(stderr, "[FAIL] test_encode_privatekeyinfo_length_only: encoded should be NULL\n");
        return 1;
    }

    printf("[PASS] test_encode_privatekeyinfo_length_only\n");
    return 0;
}

/* Test ber_decode_PrivateKeyInfo with valid data */
static int test_decode_privatekeyinfo_valid(void)
{
    /* Manually constructed PrivateKeyInfo:
     * SEQUENCE {
     *   INTEGER 0 (version)
     *   SEQUENCE { OID, NULL } (algorithm)
     *   OCTET STRING (private key)
     * }
     */
    CK_BYTE encoded[] = {
        0x30, 0x1C,  /* SEQUENCE, length 28 (contents after this header) */
        0x02, 0x01, 0x00,  /* INTEGER 0 (version) - 3 bytes */
        0x30, 0x0D,  /* SEQUENCE (algorithm ID) - 15 bytes total (2 + 13) */
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,  /* OID - 11 bytes */
        0x05, 0x00,  /* NULL - 2 bytes */
        0x04, 0x08,  /* OCTET STRING, length 8 - 10 bytes total (2 + 8) */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08  /* private key data - 8 bytes */
    };
    CK_BYTE *algorithm = NULL;
    CK_ULONG alg_len = 0;
    CK_BYTE *priv_key = NULL;
    CK_ULONG priv_key_len = 0;
    CK_RV rv;
    int result = 0;

    rv = ber_decode_PrivateKeyInfo(encoded, sizeof(encoded),
                                   &algorithm, &alg_len,
                                   &priv_key, &priv_key_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_privatekeyinfo_valid: decode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Verify algorithm length (OID + NULL = 13 bytes, the SEQUENCE contents) */
    if (alg_len != 13) {
        fprintf(stderr, "[FAIL] test_decode_privatekeyinfo_valid: algorithm length mismatch (expected 13, got %lu)\n",
                alg_len);
        result = 1;
    }

    /* Verify private key length */
    if (priv_key_len != 8) {
        fprintf(stderr, "[FAIL] test_decode_privatekeyinfo_valid: private key length mismatch (expected 8, got %lu)\n",
                priv_key_len);
        result = 1;
    }

    /* Verify private key data */
    CK_BYTE expected_key[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    if (priv_key_len == 8 && memcmp(priv_key, expected_key, 8) != 0) {
        fprintf(stderr, "[FAIL] test_decode_privatekeyinfo_valid: private key data mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_decode_privatekeyinfo_valid\n");
    return result;
}

/* Test ber_decode_PrivateKeyInfo with NULL input */
static int test_decode_privatekeyinfo_null_input(void)
{
    CK_BYTE *algorithm = NULL;
    CK_ULONG alg_len = 0;
    CK_BYTE *priv_key = NULL;
    CK_ULONG priv_key_len = 0;
    CK_RV rv;

    rv = ber_decode_PrivateKeyInfo(NULL, 10, &algorithm, &alg_len,
                                   &priv_key, &priv_key_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_privatekeyinfo_null_input: should have failed\n");
        return 1;
    }

    printf("[PASS] test_decode_privatekeyinfo_null_input\n");
    return 0;
}

/* Test ber_decode_PrivateKeyInfo with zero length */
static int test_decode_privatekeyinfo_zero_length(void)
{
    CK_BYTE encoded[] = {0x30, 0x00};
    CK_BYTE *algorithm = NULL;
    CK_ULONG alg_len = 0;
    CK_BYTE *priv_key = NULL;
    CK_ULONG priv_key_len = 0;
    CK_RV rv;

    rv = ber_decode_PrivateKeyInfo(encoded, 0, &algorithm, &alg_len,
                                   &priv_key, &priv_key_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_privatekeyinfo_zero_length: should have failed\n");
        return 1;
    }

    printf("[PASS] test_decode_privatekeyinfo_zero_length\n");
    return 0;
}

/* Test round-trip: encode then decode PrivateKeyInfo */
static int test_roundtrip_privatekeyinfo(void)
{
    /* Full AlgorithmIdentifier SEQUENCE for encoding */
    CK_BYTE algorithm_id[] = {0x30, 0x0D, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                              0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};
    /* Expected contents (13 bytes: OID + NULL, the SEQUENCE contents) after decoding */
    CK_BYTE expected_alg_contents[] = {0x06, 0x09, 0x2A, 0x86, 0x48, 0x86,
                                       0xF7, 0x0D, 0x01, 0x01, 0x01, 0x05, 0x00};
    CK_BYTE original_key[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    CK_BYTE *encoded = NULL;
    CK_ULONG encoded_len = 0;
    CK_BYTE *decoded_alg = NULL;
    CK_ULONG decoded_alg_len = 0;
    CK_BYTE *decoded_key = NULL;
    CK_ULONG decoded_key_len = 0;
    CK_RV rv;
    int result = 0;

    /* Encode */
    rv = ber_encode_PrivateKeyInfo(FALSE, &encoded, &encoded_len,
                                   algorithm_id, sizeof(algorithm_id),
                                   original_key, sizeof(original_key));
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_privatekeyinfo: encode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Decode */
    rv = ber_decode_PrivateKeyInfo(encoded, encoded_len,
                                   &decoded_alg, &decoded_alg_len,
                                   &decoded_key, &decoded_key_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_roundtrip_privatekeyinfo: decode failed with rv=%lu\n", rv);
        free(encoded);
        return 1;
    }

    /* Verify algorithm - decode returns contents without SEQUENCE wrapper */
    if (decoded_alg_len != sizeof(expected_alg_contents)) {
        fprintf(stderr, "[FAIL] test_roundtrip_privatekeyinfo: algorithm length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(expected_alg_contents), decoded_alg_len);
        result = 1;
    } else if (memcmp(decoded_alg, expected_alg_contents, sizeof(expected_alg_contents)) != 0) {
        fprintf(stderr, "[FAIL] test_roundtrip_privatekeyinfo: algorithm data mismatch\n");
        result = 1;
    }

    /* Verify private key */
    if (decoded_key_len != sizeof(original_key)) {
        fprintf(stderr, "[FAIL] test_roundtrip_privatekeyinfo: key length mismatch (expected %lu, got %lu)\n",
                (unsigned long)sizeof(original_key), decoded_key_len);
        result = 1;
    } else {
        result = compare_bytes("test_roundtrip_privatekeyinfo", original_key, decoded_key, decoded_key_len);
    }

    free(encoded);
    if (result == 0)
        printf("[PASS] test_roundtrip_privatekeyinfo\n");
    return result;
}

/* Test ber_decode_SPKI with valid data */
static int test_decode_spki_valid(void)
{
    /* Manually constructed SPKI:
     * SEQUENCE {
     *   SEQUENCE {  // AlgorithmIdentifier
     *     OID
     *     NULL (parameters)
     *   }
     *   BIT STRING (public key)
     * }
     */
    CK_BYTE spki[] = {
        0x30, 0x22,  /* SEQUENCE, length 34 */
        0x30, 0x0D,  /* SEQUENCE (AlgorithmIdentifier) */
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,  /* OID (RSA) */
        0x05, 0x00,  /* NULL */
        0x03, 0x11,  /* BIT STRING, length 17 */
        0x00,  /* unused bits */
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,  /* key data */
        0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10
    };
    CK_BYTE *alg_oid = NULL;
    CK_ULONG alg_oid_len = 0;
    CK_BYTE *param = NULL;
    CK_ULONG param_len = 0;
    CK_BYTE *key = NULL;
    CK_ULONG key_len = 0;
    CK_RV rv;
    int result = 0;

    rv = ber_decode_SPKI(spki, sizeof(spki),
                         &alg_oid, &alg_oid_len,
                         &param, &param_len,
                         &key, &key_len);
    if (rv != CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_spki_valid: decode failed with rv=%lu\n", rv);
        return 1;
    }

    /* Verify OID length (tag + length + 9 bytes = 11) */
    if (alg_oid_len != 11) {
        fprintf(stderr, "[FAIL] test_decode_spki_valid: OID length mismatch (expected 11, got %lu)\n",
                alg_oid_len);
        result = 1;
    }

    /* Verify parameters length (NULL = 2 bytes) */
    if (param_len != 2) {
        fprintf(stderr, "[FAIL] test_decode_spki_valid: param length mismatch (expected 2, got %lu)\n",
                param_len);
        result = 1;
    }

    /* Verify key length (16 bytes, unused bits byte removed) */
    if (key_len != 16) {
        fprintf(stderr, "[FAIL] test_decode_spki_valid: key length mismatch (expected 16, got %lu)\n",
                key_len);
        result = 1;
    }

    /* Verify key data */
    CK_BYTE expected_key[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                              0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10};
    if (key_len == 16 && memcmp(key, expected_key, 16) != 0) {
        fprintf(stderr, "[FAIL] test_decode_spki_valid: key data mismatch\n");
        result = 1;
    }

    if (result == 0)
        printf("[PASS] test_decode_spki_valid\n");
    return result;
}

/* Test ber_decode_SPKI with invalid/truncated data */
static int test_decode_spki_truncated(void)
{
    CK_BYTE spki[] = {0x30, 0x05, 0x30, 0x03};  /* Incomplete SPKI */
    CK_BYTE *alg_oid = NULL;
    CK_ULONG alg_oid_len = 0;
    CK_BYTE *param = NULL;
    CK_ULONG param_len = 0;
    CK_BYTE *key = NULL;
    CK_ULONG key_len = 0;
    CK_RV rv;

    rv = ber_decode_SPKI(spki, sizeof(spki),
                         &alg_oid, &alg_oid_len,
                         &param, &param_len,
                         &key, &key_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_spki_truncated: should have failed on truncated data\n");
        return 1;
    }

    printf("[PASS] test_decode_spki_truncated\n");
    return 0;
}

/* Test ber_decode_SPKI with too short AlgorithmIdentifier */
static int test_decode_spki_short_algid(void)
{
    /* SPKI with AlgorithmIdentifier that's too short (< 2 bytes) */
    CK_BYTE spki[] = {
        0x30, 0x10,  /* SEQUENCE */
        0x30, 0x01,  /* SEQUENCE (AlgorithmIdentifier) - too short */
        0x06,  /* OID tag but no length/data */
        0x03, 0x0A,  /* BIT STRING */
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08
    };
    CK_BYTE *alg_oid = NULL;
    CK_ULONG alg_oid_len = 0;
    CK_BYTE *param = NULL;
    CK_ULONG param_len = 0;
    CK_BYTE *key = NULL;
    CK_ULONG key_len = 0;
    CK_RV rv;

    rv = ber_decode_SPKI(spki, sizeof(spki),
                         &alg_oid, &alg_oid_len,
                         &param, &param_len,
                         &key, &key_len);
    if (rv == CKR_OK) {
        fprintf(stderr, "[FAIL] test_decode_spki_short_algid: should have failed on short AlgorithmIdentifier\n");
        return 1;
    }

    printf("[PASS] test_decode_spki_short_algid\n");
    return 0;
}

int main(void)
{
    int failed = 0;

    printf("=== BER Encoding/Decoding Unit Tests ===\n\n");

    /* INTEGER tests */
    printf("--- INTEGER Tests ---\n");
    failed += test_encode_integer_short();
    failed += test_encode_integer_padding();
    failed += test_encode_integer_long_form();
    failed += test_encode_integer_3byte_long_form();
    failed += test_encode_integer_4byte_long_form();
    failed += test_encode_integer_length_only();
    failed += test_encode_integer_zero_length();
    failed += test_encode_integer_boundary_127();
    failed += test_encode_integer_boundary_128();
    failed += test_decode_integer_short();
    failed += test_decode_integer_padding();
    failed += test_decode_integer_3byte_long_form();
    failed += test_decode_integer_4byte_long_form();
    failed += test_decode_integer_invalid_tag();
    failed += test_decode_integer_truncated();
    failed += test_decode_integer_null_input();
    failed += test_decode_integer_too_short();
    failed += test_roundtrip_integer();

    /* OCTET_STRING tests */
    printf("\n--- OCTET_STRING Tests ---\n");
    failed += test_encode_octet_string_short();
    failed += test_encode_octet_string_long_form();
    failed += test_encode_octet_string_3byte_long_form();
    failed += test_encode_octet_string_4byte_long_form();
    failed += test_encode_octet_string_single_byte();
    failed += test_encode_octet_string_all_zeros();
    failed += test_decode_octet_string_short();
    failed += test_decode_octet_string_3byte_long_form();
    failed += test_decode_octet_string_4byte_long_form();
    failed += test_decode_octet_string_invalid_tag();
    failed += test_decode_octet_string_null_input();
    failed += test_roundtrip_octet_string();

    /* BIT_STRING tests */
    printf("\n--- BIT_STRING Tests ---\n");
    failed += test_encode_bit_string_short();
    failed += test_encode_bit_string_long_form();
    failed += test_encode_bit_string_3byte_long_form();
    failed += test_encode_bit_string_4byte_long_form();
    failed += test_encode_bit_string_length_only();
    failed += test_encode_bit_string_unused_bits();
    failed += test_decode_bit_string_short();
    failed += test_decode_bit_string_invalid_tag();
    failed += test_decode_bit_string_null_input();
    failed += test_decode_bit_string_no_unused_byte();
    failed += test_roundtrip_bit_string();

    /* SEQUENCE tests */
    printf("\n--- SEQUENCE Tests ---\n");
    failed += test_encode_sequence_short();
    failed += test_encode_sequence_long_form();
    failed += test_encode_sequence_3byte_long_form();
    failed += test_encode_sequence_4byte_long_form();
    failed += test_decode_sequence_short();
    failed += test_decode_sequence_3byte_long_form();
    failed += test_decode_sequence_4byte_long_form();
    failed += test_decode_sequence_invalid_tag();
    failed += test_decode_sequence_empty();
    failed += test_decode_sequence_null_input();
    failed += test_roundtrip_sequence();

    /* CHOICE tests */
    printf("\n--- CHOICE Tests ---\n");
    failed += test_encode_choice_primitive_short();
    failed += test_encode_choice_constructed_short();
    failed += test_encode_choice_long_form();
    failed += test_encode_choice_3byte_long_form();
    failed += test_encode_choice_4byte_long_form();
    failed += test_encode_choice_length_only();
    failed += test_encode_choice_max_option();
    failed += test_decode_choice_primitive_short();
    failed += test_decode_choice_constructed_short();
    failed += test_decode_choice_invalid_constructed();
    failed += test_decode_choice_long_form();
    failed += test_decode_choice_3byte_long_form();
    failed += test_decode_choice_4byte_long_form();
    failed += test_decode_choice_null_input();
    failed += test_decode_choice_too_short();
    failed += test_roundtrip_choice();

    /* PrivateKeyInfo tests */
    printf("\n--- PrivateKeyInfo Tests ---\n");
    failed += test_encode_privatekeyinfo_basic();
    failed += test_encode_privatekeyinfo_length_only();
    failed += test_decode_privatekeyinfo_valid();
    failed += test_decode_privatekeyinfo_null_input();
    failed += test_decode_privatekeyinfo_zero_length();
    failed += test_roundtrip_privatekeyinfo();

    /* SPKI tests */
    printf("\n--- SPKI Tests ---\n");
    failed += test_decode_spki_valid();
    failed += test_decode_spki_truncated();
    failed += test_decode_spki_short_algid();

    /* RSA Private Key tests */
    printf("\n--- RSA Private Key Tests ---\n");
    failed += test_encode_rsa_private_key_basic();
    failed += test_encode_rsa_private_key_length_only();
    failed += test_decode_rsa_private_key_valid();
    failed += test_decode_rsa_private_key_invalid_alg();
    failed += test_roundtrip_rsa_private_key();

    /* RSA Public Key tests */
    printf("\n--- RSA Public Key Tests ---\n");
    failed += test_encode_rsa_public_key_basic();
    failed += test_decode_rsa_public_key_valid();
    failed += test_decode_rsa_public_key_invalid_alg();
    failed += test_roundtrip_rsa_public_key();

    /* DSA Private Key tests */
    printf("\n--- DSA Private Key Tests ---\n");
    failed += test_encode_dsa_private_key_basic();
    failed += test_encode_dsa_private_key_length_only();
    failed += test_decode_dsa_private_key_valid();
    failed += test_roundtrip_dsa_private_key();

    /* DSA Public Key tests */
    printf("\n--- DSA Public Key Tests ---\n");
    failed += test_encode_dsa_public_key_basic();
    failed += test_decode_dsa_public_key_valid();
    failed += test_roundtrip_dsa_public_key();

    /* DH Private Key tests */
    printf("\n--- DH Private Key Tests ---\n");
    failed += test_encode_dh_private_key_basic();
    failed += test_encode_dh_private_key_length_only();
    failed += test_decode_dh_private_key_valid();
    failed += test_roundtrip_dh_private_key();

    /* DH Public Key tests */
    printf("\n--- DH Public Key Tests ---\n");
    failed += test_encode_dh_public_key_basic();
    failed += test_decode_dh_public_key_valid();
    failed += test_roundtrip_dh_public_key();

    /* EC Private Key tests */
    printf("\n--- EC Private Key Tests ---\n");
    failed += test_encode_ec_private_key_basic();
    failed += test_encode_ec_private_key_length_only();
    failed += test_decode_ec_private_key_valid();
    failed += test_roundtrip_ec_private_key();

    /* EC Public Key tests */
    printf("\n--- EC Public Key Tests ---\n");
    failed += test_encode_ec_public_key_basic();
    failed += test_decode_ec_public_key_valid();
    failed += test_roundtrip_ec_public_key();

    /* Edwards Curve Private Key tests */
    printf("\n--- Edwards Curve Private Key Tests ---\n");
    failed += test_encode_edwards_private_key_basic();
    failed += test_roundtrip_edwards_private_key();

    /* Edwards Curve Public Key tests */
    printf("\n--- Edwards Curve Public Key Tests ---\n");
    failed += test_encode_edwards_public_key_basic();
    failed += test_roundtrip_edwards_public_key();

    /* Montgomery Curve Private Key tests */
    printf("\n--- Montgomery Curve Private Key Tests ---\n");
    failed += test_encode_montgomery_private_key_basic();
    failed += test_roundtrip_montgomery_private_key();

    /* Montgomery Curve Public Key tests */
    printf("\n--- Montgomery Curve Public Key Tests ---\n");
    failed += test_encode_montgomery_public_key_basic();
    failed += test_roundtrip_montgomery_public_key();

    /* IBM ML-DSA Private Key tests */
    printf("\n--- IBM ML-DSA Private Key Tests ---\n");
    failed += test_encode_ibm_ml_dsa_private_key_basic();
    failed += test_encode_ibm_ml_dsa_private_key_length_only();
    failed += test_decode_ibm_ml_dsa_private_key_valid();
    failed += test_roundtrip_ibm_ml_dsa_private_key();

    /* IBM ML-DSA Public Key tests */
    printf("\n--- IBM ML-DSA Public Key Tests ---\n");
    failed += test_encode_ibm_ml_dsa_public_key_basic();
    failed += test_decode_ibm_ml_dsa_public_key_valid();
    failed += test_roundtrip_ibm_ml_dsa_public_key();

    /* IBM ML-KEM Private Key tests */
    printf("\n--- IBM ML-KEM Private Key Tests ---\n");
    failed += test_encode_ibm_ml_kem_private_key_basic();
    failed += test_encode_ibm_ml_kem_private_key_length_only();
    failed += test_decode_ibm_ml_kem_private_key_valid();
    failed += test_roundtrip_ibm_ml_kem_private_key();

    /* IBM ML-KEM Public Key tests */
    printf("\n--- IBM ML-KEM Public Key Tests ---\n");
    failed += test_encode_ibm_ml_kem_public_key_basic();
    failed += test_decode_ibm_ml_kem_public_key_valid();
    failed += test_roundtrip_ibm_ml_kem_public_key();

    /* IBM Dilithium Tests */
    printf("\n--- IBM Dilithium Private Key Tests ---\n");
    failed += test_encode_ibm_dilithium_private_key_basic();
    failed += test_decode_ibm_dilithium_private_key_basic();
    failed += test_roundtrip_ibm_dilithium_private_key();
    failed += test_ibm_dilithium_private_key_null_optional();

    printf("\n--- IBM Dilithium Public Key Tests ---\n");
    failed += test_encode_ibm_dilithium_public_key_basic();
    failed += test_decode_ibm_dilithium_public_key_basic();
    failed += test_roundtrip_ibm_dilithium_public_key();

    /* IBM Kyber Tests */
    printf("\n--- IBM Kyber Private Key Tests ---\n");
    failed += test_encode_ibm_kyber_private_key_basic();
    failed += test_decode_ibm_kyber_private_key_basic();
    failed += test_roundtrip_ibm_kyber_private_key();
    failed += test_ibm_kyber_private_key_null_optional();

    printf("\n--- IBM Kyber Public Key Tests ---\n");
    failed += test_encode_ibm_kyber_public_key_basic();
    failed += test_decode_ibm_kyber_public_key_basic();
    failed += test_roundtrip_ibm_kyber_public_key();

    printf("\n--- ML-DSA Public Key Tests ---\n");
    failed += test_encode_ml_dsa_public_key_basic();
    failed += test_decode_ml_dsa_public_key_valid();
    failed += test_roundtrip_ml_dsa_public_key();

    printf("\n--- ML-DSA Private Key Tests ---\n");
    failed += test_encode_ml_dsa_private_key_basic();
    failed += test_encode_ml_dsa_private_key_length_only();
    failed += test_decode_ml_dsa_private_key_valid();
    failed += test_roundtrip_ml_dsa_private_key();

    printf("\n--- ML-DSA Private Key Tests with Seed ---\n");
    failed += test_encode_ml_dsa_private_key_with_seed();
    failed += test_encode_ml_dsa_private_key_with_seed_length_only();
    failed += test_decode_ml_dsa_private_key_with_seed();
    failed += test_roundtrip_ml_dsa_private_key_with_seed();

    printf("\n--- ML-DSA Private Key Tests with Seed-Only ---\n");
    failed += test_encode_ml_dsa_private_key_seed_only();
    failed += test_encode_ml_dsa_private_key_seed_only_length_only();
    failed += test_decode_ml_dsa_private_key_seed_only();
    failed += test_roundtrip_ml_dsa_private_key_seed_only();

    printf("\n--- ML-KEM Public Key Tests ---\n");
    failed += test_encode_ml_kem_public_key_basic();
    failed += test_decode_ml_kem_public_key_valid();
    failed += test_roundtrip_ml_kem_public_key();

    printf("\n--- ML-KEM Private Key Tests ---\n");
    failed += test_encode_ml_kem_private_key_basic();
    failed += test_encode_ml_kem_private_key_length_only();
    failed += test_decode_ml_kem_private_key_valid();
    failed += test_roundtrip_ml_kem_private_key();

    printf("\n--- ML-KEM Private Key Tests with Seed ---\n");
    failed += test_encode_ml_kem_private_key_with_seed();
    failed += test_encode_ml_kem_private_key_with_seed_length_only();
    failed += test_decode_ml_kem_private_key_with_seed();
    failed += test_roundtrip_ml_kem_private_key_with_seed();

    printf("\n--- ML-KEM Private Key Tests with Seed-Only ---\n");
    failed += test_encode_ml_kem_private_key_seed_only();
    failed += test_encode_ml_kem_private_key_seed_only_length_only();
    failed += test_decode_ml_kem_private_key_seed_only();
    failed += test_roundtrip_ml_kem_private_key_seed_only();

    printf("\n=== Test Summary ===\n");
    if (failed == 0) {
        printf("All tests passed!\n");
        return TEST_PASS;
    } else {
        printf("%d test(s) failed.\n", failed);
        return TEST_FAIL;
    }
}
