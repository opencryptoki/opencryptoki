/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <buffer.h>
#include "unittest.h"

#define STDERR_RC_UNEXP(n, func, rc, exp_rc)                    \
    fprintf(stderr, "[%d] %s: %s (curr: %ld, expected: %ld)\n", \
            n, func, "unexpected return value", rc, exp_rc)

static char *short_string = "abc";
static char *long_string  = "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                            "abcdefghijklmnopqrstuvwxyz"
                            "ABCDEFGHIJKLMNOPQRSTUVWXYZ";

static int test_buffer_api(char *s)
{
    int result = 0;
    long rc, exp_rc;
    size_t s_len = strlen(s);
    p11_buffer_t *buf = p11_buffer_new();

    /* check for buffer length and size */
    if ((*p11_buffer_char(buf)        != '\0') ||
        (p11_buffer_char(buf)         == NULL) ||
        (p11_buffer_size(buf)         == 0)    ||
        (strlen(p11_buffer_char(buf)) != 0)) {
        fprintf(stderr, "[%d] %s: %s\n",
                0, "p11_buffer_new()",
                "wrong initial buffer values");
        result++;
    }

    /* check corner case s == NULL */
    exp_rc = strlen(p11_buffer_char(buf));
    rc = p11_buffer_append(buf, NULL);
    if (rc != exp_rc) {
        STDERR_RC_UNEXP(1, "p11_buffer_append()", rc, exp_rc);
        result++;
    }

    /* check corner case s == NULL, len == 0 */
    exp_rc = strlen(p11_buffer_char(buf));
    rc = p11_buffer_append_len(buf, NULL, 0);
    if (rc != exp_rc) {
        STDERR_RC_UNEXP(2, "p11_buffer_append_len()", rc, exp_rc);
        result++;
    }

    /* check corner case len == 0 */
    exp_rc = strlen(p11_buffer_char(buf));
    rc = p11_buffer_append_len(buf, s, 0);
    if (rc != exp_rc) {
        STDERR_RC_UNEXP(3, "p11_buffer_append_len()", rc, exp_rc);
        result++;
    }

    /* normal append */
    exp_rc = strlen(p11_buffer_char(buf)) + s_len;
    rc = p11_buffer_append(buf, s);
    if (rc != exp_rc) {
        STDERR_RC_UNEXP(4, "p11_buffer_append()", rc, exp_rc);
        result++;
    }

    /* normal append with length */
    exp_rc = strlen(p11_buffer_char(buf)) + s_len;
    rc = p11_buffer_append_len(buf, s, s_len);
    if (rc != exp_rc) {
        STDERR_RC_UNEXP(5, "p11_buffer_append()", rc, exp_rc);
        result++;
    }

    /* normal append with printf */
    exp_rc = strlen(p11_buffer_char(buf)) + 14 + s_len;
    rc = p11_buffer_append_printf(buf, "append_prinf(%s)", s);
    if (rc != exp_rc) {
        STDERR_RC_UNEXP(6, "p11_buffer_append()", rc, exp_rc);
        result++;
    }

    /* reset buffer */
    p11_buffer_reset(buf);
    if ((*p11_buffer_char(buf)        != '\0') ||
        (strlen(p11_buffer_char(buf)) != 0)) {
        fprintf(stderr, "[%d] %s: %s\n",
                7, "p11_buffer_reset()",
                "wrong buffer values after reset");
        result++;
    }

    p11_buffer_free(buf);
    return result;
}

int main(void)
{
    if (test_buffer_api(short_string))
        return TEST_FAIL;
    if (test_buffer_api(long_string))
        return TEST_FAIL;

    return TEST_PASS;
}
