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
 * Unit test for add_pkcs_padding() and strip_pkcs_padding() in utility.c
 */

#include <stdio.h>
#include <string.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "unittest.h"

#define MAX_BUF         256
#define FILL_BYTE       0xAA
#define LEN_UNTOUCHED   ((CK_ULONG)0xDEADBEEF)

/*
 * The buffer is built as follows: it is first filled with FILL_BYTE, then the
 * last 'pad_count' bytes are set to 'pad_value'. Finally, if 'corrupt_idx' is
 * not 0, the byte 'corrupt_idx' bytes from the end (1 = last byte) is set to
 * 'corrupt_val'.
 */
struct strip_test {
    const char *name;
    CK_ULONG block_size;
    CK_ULONG total_len;
    CK_BYTE pad_value;
    CK_ULONG pad_count;
    CK_ULONG corrupt_idx;
    CK_BYTE corrupt_val;
    CK_RV exp_rc;
    CK_ULONG exp_data_len;
};

static const struct strip_test strip_tests[] = {
    /* valid padding */
    { "AES: 1 pad byte", 16, 16, 1, 1, 0, 0, CKR_OK, 15 },
    { "AES: 3 pad bytes", 16, 16, 3, 3, 0, 0, CKR_OK, 13 },
    { "AES: full padding block", 16, 16, 16, 16, 0, 0, CKR_OK, 0 },
    { "AES: full padding block, 2 blocks", 16, 32, 16, 16, 0, 0, CKR_OK, 16 },
    { "AES: 15 pad bytes, 2 blocks", 16, 32, 15, 15, 0, 0, CKR_OK, 17 },
    { "AES: byte before padding equals pad value", 16, 32, 15, 16, 0, 0,
      CKR_OK, 17 },
    { "DES: full padding block", 8, 8, 8, 8, 0, 0, CKR_OK, 0 },
    { "DES: 1 pad byte, 3 blocks", 8, 24, 1, 1, 0, 0, CKR_OK, 23 },

    /* invalid pad value */
    { "pad value 0", 16, 16, 0, 1, 0, 0, CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "pad value 0, all bytes 0", 16, 16, 0, 16, 0, 0,
      CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "AES: pad value 17 > block size", 16, 16, 17, 16, 0, 0,
      CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "AES: pad value 32 > block size, 2 blocks", 16, 32, 32, 32, 0, 0,
      CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "DES: pad value 9 > block size", 8, 16, 9, 9, 0, 0,
      CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "pad value 255", 16, 32, 255, 32, 0, 0, CKR_ENCRYPTED_DATA_INVALID, 0 },

    /* invalid pad bytes */
    { "only last byte is the pad value", 16, 16, 3, 1, 0, 0,
      CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "middle pad byte differs", 16, 16, 3, 3, 2, 2,
      CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "first pad byte differs", 16, 16, 4, 4, 4, FILL_BYTE,
      CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "first pad byte of full block differs", 16, 16, 16, 16, 16, 0,
      CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "DES: first pad byte of full block differs", 8, 8, 8, 8, 8, 0,
      CKR_ENCRYPTED_DATA_INVALID, 0 },

    /* invalid lengths */
    { "total length 0", 16, 0, 1, 0, 0, 0, CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "total length not a multiple of block size", 16, 20, 1, 1, 0, 0,
      CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "total length smaller than block size", 16, 8, 1, 1, 0, 0,
      CKR_ENCRYPTED_DATA_INVALID, 0 },

    /* invalid block size */
    { "block size 0", 0, 16, 1, 1, 0, 0, CKR_ENCRYPTED_DATA_INVALID, 0 },
    { "block size 256", 256, 256, 1, 1, 0, 0, CKR_ENCRYPTED_DATA_INVALID, 0 },
};

static int test_strip_pkcs_padding(void)
{
    const struct strip_test *t;
    CK_BYTE buf[MAX_BUF];
    CK_ULONG data_len;
    CK_RV rc;
    size_t i;
    int result = 0, failed;

    for (i = 0; i < ARRAYSIZE(strip_tests); i++) {
        t = &strip_tests[i];
        failed = 0;

        memset(buf, FILL_BYTE, sizeof(buf));
        if (t->pad_count > 0)
            memset(buf + t->total_len - t->pad_count, t->pad_value,
                   t->pad_count);
        if (t->corrupt_idx > 0)
            buf[t->total_len - t->corrupt_idx] = t->corrupt_val;

        data_len = LEN_UNTOUCHED;
        rc = strip_pkcs_padding(buf, t->block_size, t->total_len, &data_len);

        if (rc != t->exp_rc) {
            fprintf(stderr, "FAIL: strip [%zu] %s: unexpected rc 0x%lx "
                    "(expected 0x%lx)\n", i, t->name, rc, t->exp_rc);
            failed = 1;
        } else if (t->exp_rc == CKR_OK) {
            if (data_len != t->exp_data_len) {
                fprintf(stderr, "FAIL: strip [%zu] %s: unexpected data_len "
                        "%lu (expected %lu)\n", i, t->name, data_len,
                        t->exp_data_len);
                failed = 1;
            }
        } else if (data_len != LEN_UNTOUCHED) {
            fprintf(stderr, "FAIL: strip [%zu] %s: data_len modified on "
                    "failure\n", i, t->name);
            failed = 1;
        }

        if (failed)
            result++;
        else
            printf("PASS: strip [%zu] %s\n", i, t->name);
    }

    return result;
}

/*
 * Round trip: add_pkcs_padding() followed by strip_pkcs_padding() must return
 * the original data length for all data lengths and both block sizes.
 */
static int test_round_trip(void)
{
    static const CK_ULONG block_sizes[] = { 8, 16 };
    CK_BYTE buf[MAX_BUF];
    CK_ULONG bs, data_len, total_len, out_len;
    CK_RV rc;
    size_t i;
    int result = 0, failed;

    for (i = 0; i < ARRAYSIZE(block_sizes); i++) {
        bs = block_sizes[i];
        failed = 0;

        for (data_len = 0; data_len <= 3 * bs; data_len++) {
            total_len = bs * (data_len / bs + 1);

            memset(buf, FILL_BYTE, sizeof(buf));
            rc = add_pkcs_padding(buf + data_len, bs, data_len, total_len);
            if (rc != CKR_OK) {
                fprintf(stderr, "FAIL: round trip (bs=%lu, len=%lu): "
                        "add_pkcs_padding rc 0x%lx\n", bs, data_len, rc);
                failed++;
                continue;
            }

            out_len = LEN_UNTOUCHED;
            rc = strip_pkcs_padding(buf, bs, total_len, &out_len);
            if (rc != CKR_OK || out_len != data_len) {
                fprintf(stderr, "FAIL: round trip (bs=%lu, len=%lu): "
                        "strip_pkcs_padding rc 0x%lx, out_len %lu\n",
                        bs, data_len, rc, out_len);
                failed++;
            }
        }

        result += failed;
        if (failed == 0)
            printf("PASS: round trip, block size %lu, data lengths 0..%lu\n",
                   bs, 3 * bs);
        else
            fprintf(stderr, "FAIL: round trip, block size %lu, data lengths "
                    "0..%lu: %d failure(s)\n", bs, 3 * bs, failed);
    }

    return result;
}

int main(void)
{
    int result = 0;

    result += test_strip_pkcs_padding();
    result += test_round_trip();

    if (result != 0) {
        fprintf(stderr, "padtest: %d failure(s)\n", result);
        return TEST_FAIL;
    }

    printf("padtest: all tests passed\n");

    return TEST_PASS;
}
