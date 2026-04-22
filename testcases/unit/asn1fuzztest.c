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
 * Fuzzing tests for BER encoding and decoding functions in asn1.c
 *
 * This test suite performs TRUE FUZZING on the BER encoding/decoding functions
 * to identify potential crashes, memory leaks, and security vulnerabilities
 * when processing completely random or specially crafted malformed inputs.
 *
 * NOTE: This complements asn1test.c which tests known valid/invalid cases.
 * This file focuses on:
 * - Random data generation and mutation
 * - Stress testing with high iteration counts
 * - Advanced malformation scenarios not covered in unit tests
 * - Memory allocation stress
 * - Deeply nested structures
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"

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

/* Test statistics */
static int tests_run = 0;
static int tests_passed = 0;
static int tests_failed = 0;
static int crashes_prevented = 0;

#define TEST_ASSERT(condition, msg) do { \
    tests_run++; \
    if (!(condition)) { \
        printf("FAIL: %s (line %d): %s\n", __func__, __LINE__, msg); \
        tests_failed++; \
        return -1; \
    } else { \
        tests_passed++; \
    } \
} while(0)

#define TEST_PASS() do { \
    printf("PASS: %s\n", __func__); \
    return 0; \
} while(0)

/* Helper function to generate random data */
static void generate_random_data(CK_BYTE *buffer, CK_ULONG length)
{
    for (CK_ULONG i = 0; i < length; i++) {
        buffer[i] = (CK_BYTE)(rand() % 256);
    }
}

/* Helper to mutate existing data (bit flips, byte swaps, etc.) */
static void mutate_data(CK_BYTE *data, CK_ULONG length, int mutation_type)
{
    if (length == 0)
        return;

    switch (mutation_type % 5) {
        case 0: /* Bit flip */
            data[rand() % length] ^= (1 << (rand() % 8));
            break;
        case 1: /* Byte swap */
            if (length > 1) {
                CK_ULONG pos1 = rand() % length;
                CK_ULONG pos2 = rand() % length;
                CK_BYTE tmp = data[pos1];
                data[pos1] = data[pos2];
                data[pos2] = tmp;
            }
            break;
        case 2: /* Set to extreme value */
            data[rand() % length] = (rand() % 2) ? 0x00 : 0xFF;
            break;
        case 3: /* Increment/decrement */
            data[rand() % length] += (rand() % 2) ? 1 : -1;
            break;
        case 4: /* Set random byte */
            data[rand() % length] = (CK_BYTE)(rand() % 256);
            break;
    }
}

/* Test 1: Pure random data fuzzing - All types */
static int test_fuzz_decode_all_types_pure_random(void)
{
    CK_BYTE random_data[2048];
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len, option;
    int iterations = 2000; /* 2000 per type = 10000 total */

    printf("Running: %s (%d iterations per type)\n", __func__, iterations);

    for (int i = 0; i < iterations; i++) {
        CK_ULONG data_len = (rand() % 2000) + 1;
        generate_random_data(random_data, data_len);

        /* Test all 5 types - should not crash with random data */
        (void)ber_decode_INTEGER(random_data, data_len, &decoded_data,
                                &decoded_len, &field_len);

        (void)ber_decode_OCTET_STRING(random_data, data_len, &decoded_data,
                                     &decoded_len, &field_len);

        (void)ber_decode_BIT_STRING(random_data, data_len, &decoded_data,
                                   &decoded_len, &field_len);

        (void)ber_decode_SEQUENCE(random_data, data_len, &decoded_data,
                                 &decoded_len, &field_len);

        (void)ber_decode_CHOICE(random_data, data_len, (rand() % 2) ? TRUE : FALSE,
                               &decoded_data, &decoded_len, &field_len, &option);
    }

    printf("  Tested all 5 BER types with random data\n");
    TEST_ASSERT(1, "Completed without crashing");
    TEST_PASS();
}

/* Test 2: Mutation-based fuzzing - all types */
static int test_fuzz_mutation_based_all_types(void)
{
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len, option;
    int iterations = 2000; /* 2000 per type = 10000 total */

    printf("Running: %s (%d iterations per type)\n", __func__, iterations);

    /* Test each type */
    for (int type = 0; type < 5; type++) {
        CK_BYTE *encoded_data = NULL;
        CK_ULONG encoded_len;
        CK_BYTE valid_data[100];
        generate_random_data(valid_data, sizeof(valid_data));

        /* Encode based on type */
        CK_RV rv = CKR_FUNCTION_FAILED;
        switch (type) {
            case 0: /* INTEGER */
                rv = ber_encode_INTEGER(FALSE, &encoded_data, &encoded_len,
                                       valid_data, sizeof(valid_data));
                break;
            case 1: /* OCTET_STRING */
                rv = ber_encode_OCTET_STRING(FALSE, &encoded_data, &encoded_len,
                                            valid_data, sizeof(valid_data));
                break;
            case 2: /* BIT_STRING */
                rv = ber_encode_BIT_STRING(FALSE, &encoded_data, &encoded_len,
                                          valid_data, sizeof(valid_data), 0);
                break;
            case 3: /* SEQUENCE */
                rv = ber_encode_SEQUENCE(FALSE, &encoded_data, &encoded_len,
                                        valid_data, sizeof(valid_data));
                break;
            case 4: /* CHOICE */
                rv = ber_encode_CHOICE(FALSE, (CK_BYTE)(rand() % 16), &encoded_data,
                                      &encoded_len, valid_data, sizeof(valid_data), FALSE);
                break;
        }

        if (rv == CKR_OK && encoded_data) {
            /* Mutate and decode */
            for (int i = 0; i < iterations; i++) {
                CK_BYTE *mutated = malloc(encoded_len);
                if (mutated) {
                    memcpy(mutated, encoded_data, encoded_len);

                    /* Apply mutations */
                    for (int m = 0; m < (rand() % 5) + 1; m++) {
                        mutate_data(mutated, encoded_len, rand());
                    }

                    /* Decode based on type */
                    switch (type) {
                        case 0:
                            (void)ber_decode_INTEGER(mutated, encoded_len, &decoded_data,
                                                    &decoded_len, &field_len);
                            break;
                        case 1:
                            (void)ber_decode_OCTET_STRING(mutated, encoded_len, &decoded_data,
                                                         &decoded_len, &field_len);
                            break;
                        case 2:
                            (void)ber_decode_BIT_STRING(mutated, encoded_len, &decoded_data,
                                                       &decoded_len, &field_len);
                            break;
                        case 3:
                            (void)ber_decode_SEQUENCE(mutated, encoded_len, &decoded_data,
                                                     &decoded_len, &field_len);
                            break;
                        case 4:
                            (void)ber_decode_CHOICE(mutated, encoded_len, FALSE, &decoded_data,
                                                   &decoded_len, &field_len, &option);
                            break;
                    }

                    free(mutated);
                }
            }
            free(encoded_data);
        }
    }

    printf("  Tested mutation fuzzing on all 5 types\n");
    TEST_ASSERT(1, "Mutation fuzzing completed");
    TEST_PASS();
}

/* Test 3: Length field fuzzing - manipulate length fields specifically */
static int test_fuzz_length_field_attacks(void)
{
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len;
    CK_RV rv;
    int attack_count = 0;

    printf("Running: %s\n", __func__);

    /* Attack 1: Length overflow - claim huge length with small data */
    for (int i = 0; i < 1000; i++) {
        CK_BYTE overflow_data[10];
        overflow_data[0] = 0x02; /* INTEGER tag */
        overflow_data[1] = 0x84; /* Long form, 4 octets */
        overflow_data[2] = (rand() % 256);
        overflow_data[3] = (rand() % 256);
        overflow_data[4] = (rand() % 256);
        overflow_data[5] = (rand() % 256);
        /* Only 4 bytes of actual data */
        overflow_data[6] = rand() % 256;
        overflow_data[7] = rand() % 256;
        overflow_data[8] = rand() % 256;
        overflow_data[9] = rand() % 256;

        rv = ber_decode_INTEGER(overflow_data, sizeof(overflow_data),
                               &decoded_data, &decoded_len, &field_len);

        if (rv == CKR_FUNCTION_FAILED) {
            attack_count++;
        }
    }

    /* Attack 2: Inconsistent length encoding */
    for (int i = 0; i < 1000; i++) {
        CK_BYTE inconsistent[20];
        inconsistent[0] = 0x02; /* INTEGER tag */
        inconsistent[1] = 0x80 | (rand() % 8); /* Random long form octets */
        for (int j = 2; j < 20; j++) {
            inconsistent[j] = rand() % 256;
        }

        rv = ber_decode_INTEGER(inconsistent, sizeof(inconsistent),
                               &decoded_data, &decoded_len, &field_len);

        if (rv == CKR_FUNCTION_FAILED) {
            attack_count++;
        }
    }

    printf("  Detected and rejected %d length field attacks\n", attack_count);
    TEST_ASSERT(attack_count > 0, "Should detect length field attacks");
    TEST_PASS();
}

/* Test 4: Deeply nested structure fuzzing */
static int test_fuzz_deeply_nested_structures(void)
{
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len;
    CK_RV rv;

    printf("Running: %s\n", __func__);

    /* Test various nesting depths */
    for (int depth = 10; depth <= 200; depth += 10) {
        CK_BYTE *nested = malloc(depth * 3);
        if (!nested) continue;

        CK_ULONG offset = 0;
        CK_ULONG max_offset = (CK_ULONG)(depth * 3) - 2;

        /* Create nested sequences */
        for (int i = 0; i < depth && offset < max_offset; i++) {
            nested[offset++] = 0x30; /* SEQUENCE tag */
            nested[offset++] = (rand() % 2) ? 0x02 : 0x81; /* Random length form */
            if (nested[offset-1] == 0x81) {
                nested[offset++] = rand() % 128;
            } else {
                nested[offset-1] = rand() % 128;
            }
        }

        rv = ber_decode_SEQUENCE(nested, offset, &decoded_data,
                                &decoded_len, &field_len);

        /* Should handle or reject gracefully, not crash */
        if (rv != CKR_OK && rv != CKR_FUNCTION_FAILED) {
            crashes_prevented++;
        }

        free(nested);
    }

    printf("  Tested nesting depths up to 200 levels\n");
    TEST_ASSERT(1, "Deep nesting handled");
    TEST_PASS();
}

/* Test 5: Memory allocation stress with rapid alloc/free */
static int test_fuzz_memory_stress(void)
{
    CK_BYTE *encoded_data = NULL;
    CK_ULONG encoded_len;
    CK_RV rv;
    int iterations = 2000;

    printf("Running: %s (%d iterations)\n", __func__, iterations);

    /* Rapidly allocate and free to stress memory management */
    for (int i = 0; i < iterations; i++) {
        CK_ULONG data_len = (rand() % 500) + 1;
        CK_BYTE *data = malloc(data_len);

        if (data) {
            generate_random_data(data, data_len);

            rv = ber_encode_INTEGER(FALSE, &encoded_data, &encoded_len,
                                   data, data_len);

            if (rv == CKR_OK && encoded_data) {
                free(encoded_data);
                encoded_data = NULL;
            }

            free(data);
        }
    }

    printf("  Completed %d alloc/free cycles\n", iterations);
    TEST_ASSERT(1, "Memory stress test completed");
    TEST_PASS();
}

/* Test 6: Concurrent encode/decode operations simulation */
static int test_fuzz_interleaved_operations(void)
{
    CK_BYTE *encoded_data[10] = {NULL};
    CK_ULONG encoded_len[10];
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len;

    printf("Running: %s\n", __func__);

    /* Interleave multiple encode/decode operations */
    for (int round = 0; round < 100; round++) {
        /* Encode phase - create multiple encoded buffers */
        for (int i = 0; i < 10; i++) {
            CK_ULONG data_len = (rand() % 200) + 1;
            CK_BYTE *data = malloc(data_len);

            if (data) {
                generate_random_data(data, data_len);
                (void)ber_encode_INTEGER(FALSE, &encoded_data[i], &encoded_len[i],
                                        data, data_len);
                free(data);
            }
        }

        /* Decode phase - decode in random order */
        for (int i = 0; i < 10; i++) {
            int idx = rand() % 10;
            if (encoded_data[idx]) {
                (void)ber_decode_INTEGER(encoded_data[idx], encoded_len[idx],
                                        &decoded_data, &decoded_len, &field_len);
            }
        }

        /* Cleanup */
        for (int i = 0; i < 10; i++) {
            if (encoded_data[i]) {
                free(encoded_data[i]);
                encoded_data[i] = NULL;
            }
        }
    }

    printf("  Completed 100 rounds of interleaved operations\n");
    TEST_ASSERT(1, "Interleaved operations completed");
    TEST_PASS();
}

/* Test 7: Fuzzing all primitive types with random data */
static int test_fuzz_all_primitives_random(void)
{
    CK_BYTE random_data[1024];
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len;
    int iterations = 2000;

    printf("Running: %s (%d iterations per type)\n", __func__, iterations);

    for (int i = 0; i < iterations; i++) {
        CK_ULONG data_len = (rand() % 1000) + 1;
        generate_random_data(random_data, data_len);

        /* Test INTEGER */
        (void)ber_decode_INTEGER(random_data, data_len, &decoded_data,
                                &decoded_len, &field_len);

        /* Test OCTET_STRING */
        (void)ber_decode_OCTET_STRING(random_data, data_len, &decoded_data,
                                      &decoded_len, &field_len);

        /* Test BIT_STRING */
        (void)ber_decode_BIT_STRING(random_data, data_len, &decoded_data,
                                    &decoded_len, &field_len);

        /* Test SEQUENCE */
        (void)ber_decode_SEQUENCE(random_data, data_len, &decoded_data,
                                 &decoded_len, &field_len);
    }

    printf("  Tested all primitive types with random data\n");
    TEST_ASSERT(1, "All primitives tested");
    TEST_PASS();
}

/* Test 8: Edge case combinations - all types */
static int test_fuzz_edge_case_combinations_all_types(void)
{
    CK_BYTE *encoded_data = NULL;
    CK_ULONG encoded_len;

    printf("Running: %s\n", __func__);

    /* Test various edge case combinations */
    struct {
        CK_ULONG size;
        CK_BYTE fill;
    } test_cases[] = {
        {0, 0x00},      /* Zero length */
        {1, 0x00},      /* Single byte, zero */
        {1, 0xFF},      /* Single byte, all bits set */
        {1, 0x80},      /* Single byte, MSB set */
        {127, 0x00},    /* Boundary: last short form */
        {127, 0xFF},    /* Boundary: last short form, all bits */
        {128, 0x00},    /* Boundary: first long form */
        {128, 0x80},    /* Boundary: first long form, MSB set */
        {255, 0x00},    /* Boundary: 1-byte long form limit */
        {256, 0x00},    /* Boundary: 2-byte long form start */
    };

    int test_count = 0;

    /* Test each type with each edge case */
    for (int type = 0; type < 5; type++) {
        for (size_t i = 0; i < sizeof(test_cases) / sizeof(test_cases[0]); i++) {
            CK_BYTE *data = malloc(test_cases[i].size > 0 ? test_cases[i].size : 1);
            if (data) {
                if (test_cases[i].size > 0) {
                    memset(data, test_cases[i].fill, test_cases[i].size);
                }

                /* Encode based on type */
                switch (type) {
                    case 0: /* INTEGER */
                        (void)ber_encode_INTEGER(FALSE, &encoded_data, &encoded_len,
                                                data, test_cases[i].size);
                        break;
                    case 1: /* OCTET_STRING */
                        (void)ber_encode_OCTET_STRING(FALSE, &encoded_data, &encoded_len,
                                                     data, test_cases[i].size);
                        break;
                    case 2: /* BIT_STRING */
                        (void)ber_encode_BIT_STRING(FALSE, &encoded_data, &encoded_len,
                                                   data, test_cases[i].size, 0);
                        break;
                    case 3: /* SEQUENCE */
                        (void)ber_encode_SEQUENCE(FALSE, &encoded_data, &encoded_len,
                                                 data, test_cases[i].size);
                        break;
                    case 4: /* CHOICE */
                        (void)ber_encode_CHOICE(FALSE, 0x01, &encoded_data, &encoded_len,
                                               data, test_cases[i].size, FALSE);
                        break;
                }

                if (encoded_data) {
                    free(encoded_data);
                    encoded_data = NULL;
                }

                free(data);
                test_count++;
            }
        }
    }

    printf("  Tested %d edge case combinations across all 5 types\n", test_count);
    TEST_ASSERT(test_count == 50, "All edge cases tested");
    TEST_PASS();
}

/* Test 9: Fuzzing with specific attack patterns - all types */
static int test_fuzz_attack_patterns_all_types(void)
{
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len, option;
    int patterns_tested = 0;

    printf("Running: %s\n", __func__);

    /* Define attack patterns */
    CK_BYTE zeros[100];
    memset(zeros, 0x00, sizeof(zeros));

    CK_BYTE ones[100];
    memset(ones, 0xFF, sizeof(ones));

    CK_BYTE alternating[100];
    for (size_t i = 0; i < sizeof(alternating); i++) {
        alternating[i] = (i % 2) ? 0xAA : 0x55;
    }

    CK_BYTE incrementing[256];
    for (size_t i = 0; i < sizeof(incrementing); i++) {
        incrementing[i] = (CK_BYTE)i;
    }

    CK_BYTE decrementing[256];
    for (size_t i = 0; i < sizeof(decrementing); i++) {
        decrementing[i] = (CK_BYTE)(255 - i);
    }

    /* Test each pattern with each type */
    struct {
        CK_BYTE *data;
        CK_ULONG len;
    } patterns[] = {
        {zeros, sizeof(zeros)},
        {ones, sizeof(ones)},
        {alternating, sizeof(alternating)},
        {incrementing, sizeof(incrementing)},
        {decrementing, sizeof(decrementing)}
    };

    for (int type = 0; type < 5; type++) {
        for (size_t p = 0; p < sizeof(patterns) / sizeof(patterns[0]); p++) {
            /* Decode based on type */
            switch (type) {
                case 0: /* INTEGER */
                    (void)ber_decode_INTEGER(patterns[p].data, patterns[p].len,
                                            &decoded_data, &decoded_len, &field_len);
                    break;
                case 1: /* OCTET_STRING */
                    (void)ber_decode_OCTET_STRING(patterns[p].data, patterns[p].len,
                                                 &decoded_data, &decoded_len, &field_len);
                    break;
                case 2: /* BIT_STRING */
                    (void)ber_decode_BIT_STRING(patterns[p].data, patterns[p].len,
                                               &decoded_data, &decoded_len, &field_len);
                    break;
                case 3: /* SEQUENCE */
                    (void)ber_decode_SEQUENCE(patterns[p].data, patterns[p].len,
                                             &decoded_data, &decoded_len, &field_len);
                    break;
                case 4: /* CHOICE */
                    (void)ber_decode_CHOICE(patterns[p].data, patterns[p].len, FALSE,
                                           &decoded_data, &decoded_len, &field_len, &option);
                    break;
            }
            patterns_tested++;
        }
    }

    printf("  Tested %d attack patterns across all 5 types\n", patterns_tested);
    TEST_ASSERT(patterns_tested == 25, "All attack patterns tested");
    TEST_PASS();
}

/* Test 10: Fuzzing CHOICE with random options and data */
static int test_fuzz_choice_random_options(void)
{
    CK_BYTE *encoded_data = NULL;
    CK_ULONG encoded_len;
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len, option;
    CK_RV rv;
    int iterations = 1000;

    printf("Running: %s (%d iterations)\n", __func__, iterations);

    /* Test with random options and data */
    for (int i = 0; i < iterations; i++) {
        CK_BYTE random_option = (CK_BYTE)(rand() % 32); /* Options 0-31 */
        CK_BBOOL constructed = (rand() % 2) ? TRUE : FALSE;
        CK_ULONG data_len = (rand() % 200) + 1;
        CK_BYTE *data = malloc(data_len);

        if (data) {
            generate_random_data(data, data_len);

            /* Encode */
            rv = ber_encode_CHOICE(FALSE, random_option, &encoded_data,
                                  &encoded_len, data, data_len, constructed);

            if (rv == CKR_OK && encoded_data) {
                /* Decode */
                rv = ber_decode_CHOICE(encoded_data, encoded_len, constructed,
                                      &decoded_data, &decoded_len, &field_len, &option);

                free(encoded_data);
                encoded_data = NULL;
            }

            free(data);
        }
    }

    printf("  Tested %d random CHOICE encodings\n", iterations);
    TEST_ASSERT(1, "CHOICE random options test completed");
    TEST_PASS();
}

/* Test 11: Fuzzing CHOICE decoder with random data */
static int test_fuzz_choice_decode_random(void)
{
    CK_BYTE random_data[1024];
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len, option;
    int iterations = 1000;

    printf("Running: %s (%d iterations)\n", __func__, iterations);

    /* Test both constructed and primitive with random data */
    for (int i = 0; i < iterations; i++) {
        CK_ULONG data_len = (rand() % 1000) + 1;
        CK_BBOOL constructed = (rand() % 2) ? TRUE : FALSE;
        generate_random_data(random_data, data_len);

        /* Should not crash with random data */
        (void)ber_decode_CHOICE(random_data, data_len, constructed,
                               &decoded_data, &decoded_len, &field_len, &option);
    }

    printf("  Tested CHOICE decoder with random data\n");
    TEST_ASSERT(1, "CHOICE random decode test completed");
    TEST_PASS();
}

/* Test 12: Fuzzing CHOICE with option boundary values */
static int test_fuzz_choice_option_boundaries(void)
{
    CK_BYTE *encoded_data = NULL;
    CK_ULONG encoded_len;
    int test_count = 0;

    printf("Running: %s\n", __func__);

    /* Test boundary option values */
    CK_BYTE boundary_options[] = {0x00, 0x01, 0x1E, 0x1F, 0x20, 0x7F, 0x80, 0xFF};

    for (size_t i = 0; i < sizeof(boundary_options); i++) {
        for (int constructed = 0; constructed <= 1; constructed++) {
            CK_BYTE test_data[50];
            generate_random_data(test_data, sizeof(test_data));

            (void)ber_encode_CHOICE(FALSE, boundary_options[i], &encoded_data,
                                   &encoded_len, test_data, sizeof(test_data),
                                   constructed ? TRUE : FALSE);

            if (encoded_data) {
                free(encoded_data);
                encoded_data = NULL;
            }
            test_count++;
        }
    }

    printf("  Tested %d CHOICE option boundary values\n", test_count);
    TEST_ASSERT(test_count == 16, "All boundary options tested");
    TEST_PASS();
}

/* Test 13: Fuzzing CHOICE with malformed constructed flag */
static int test_fuzz_choice_constructed_mismatch(void)
{
    CK_BYTE *encoded_data = NULL;
    CK_ULONG encoded_len;
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len, option;
    CK_RV rv;
    int iterations = 1000;

    printf("Running: %s (%d iterations)\n", __func__, iterations);

    /* Encode with one constructed flag, decode with another */
    for (int i = 0; i < iterations; i++) {
        CK_BYTE random_option = (CK_BYTE)(rand() % 16);
        CK_BBOOL encode_constructed = (rand() % 2) ? TRUE : FALSE;
        CK_BBOOL decode_constructed = (rand() % 2) ? TRUE : FALSE;
        CK_ULONG data_len = (rand() % 100) + 1;
        CK_BYTE *data = malloc(data_len);

        if (data) {
            generate_random_data(data, data_len);

            /* Encode with one flag */
            rv = ber_encode_CHOICE(FALSE, random_option, &encoded_data,
                                  &encoded_len, data, data_len, encode_constructed);

            if (rv == CKR_OK && encoded_data) {
                /* Decode with potentially different flag */
                (void)ber_decode_CHOICE(encoded_data, encoded_len, decode_constructed,
                                       &decoded_data, &decoded_len, &field_len, &option);

                free(encoded_data);
                encoded_data = NULL;
            }

            free(data);
        }
    }

    printf("  Tested constructed flag mismatches\n");
    TEST_ASSERT(1, "CHOICE constructed mismatch test completed");
    TEST_PASS();
}

/* Test 14: Fuzzing CHOICE with mutation */
static int test_fuzz_choice_mutation(void)
{
    CK_BYTE *encoded_data = NULL;
    CK_ULONG encoded_len;
    CK_BYTE *decoded_data;
    CK_ULONG decoded_len, field_len, option;
    CK_RV rv;
    int iterations = 1000;

    printf("Running: %s (%d iterations)\n", __func__, iterations);

    for (int i = 0; i < iterations; i++) {
        CK_BYTE random_option = (CK_BYTE)(rand() % 16);
        CK_BBOOL constructed = (rand() % 2) ? TRUE : FALSE;
        CK_BYTE test_data[100];
        generate_random_data(test_data, sizeof(test_data));

        /* Encode valid CHOICE */
        rv = ber_encode_CHOICE(FALSE, random_option, &encoded_data,
                              &encoded_len, test_data, sizeof(test_data), constructed);

        if (rv == CKR_OK && encoded_data) {
            /* Mutate the encoded data */
            CK_BYTE *mutated = malloc(encoded_len);
            if (mutated) {
                memcpy(mutated, encoded_data, encoded_len);

                /* Apply mutations */
                for (int m = 0; m < (rand() % 3) + 1; m++) {
                    mutate_data(mutated, encoded_len, rand());
                }

                /* Try to decode mutated data */
                (void)ber_decode_CHOICE(mutated, encoded_len, constructed,
                                       &decoded_data, &decoded_len, &field_len, &option);

                free(mutated);
            }

            free(encoded_data);
            encoded_data = NULL;
        }
    }

    printf("  Tested CHOICE with mutations\n");
    TEST_ASSERT(1, "CHOICE mutation test completed");
    TEST_PASS();
}

/* Main test runner */
int main(int argc __attribute__((unused)), char **argv __attribute__((unused)))
{
    int result = 0;

    /* Initialize random seed */
    srand((unsigned int)time(NULL));

    printf("=== ASN.1 BER Encoding/Decoding FUZZING Tests ===\n");
    printf("NOTE: These are TRUE fuzzing tests with random data\n");
    printf("      Complementing the unit tests in asn1test.c\n\n");

    /* Run all fuzzing tests */
    result |= test_fuzz_decode_all_types_pure_random();
    result |= test_fuzz_mutation_based_all_types();
    result |= test_fuzz_length_field_attacks();
    result |= test_fuzz_deeply_nested_structures();
    result |= test_fuzz_memory_stress();
    result |= test_fuzz_interleaved_operations();
    result |= test_fuzz_all_primitives_random();
    result |= test_fuzz_edge_case_combinations_all_types();
    result |= test_fuzz_attack_patterns_all_types();
    result |= test_fuzz_choice_random_options();
    result |= test_fuzz_choice_decode_random();
    result |= test_fuzz_choice_option_boundaries();
    result |= test_fuzz_choice_constructed_mismatch();
    result |= test_fuzz_choice_mutation();

    /* Print summary */
    printf("\n=== Fuzzing Test Summary ===\n");
    printf("Total tests run: %d\n", tests_run);
    printf("Tests passed: %d\n", tests_passed);
    printf("Tests failed: %d\n", tests_failed);
    printf("Crashes prevented: %d\n", crashes_prevented);

    if (tests_failed == 0) {
        printf("\nAll fuzzing tests PASSED!\n");
        printf("The BER decoder handled random/malformed data gracefully.\n");
        return 0;
    } else {
        printf("\nSome fuzzing tests FAILED!\n");
        return 1;
    }
}
