/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "platform.h"
#include "buffer.h"

#define BUFFER_INIT_SIZE	(128ul)

struct _buffer {
    size_t b_size;
    char *b;
};

p11_buffer_t *p11_buffer_new(void)
{
    p11_buffer_t *ret = malloc(sizeof(p11_buffer_t));
    if (ret == NULL)
        goto err;

    ret->b_size = BUFFER_INIT_SIZE;
    ret->b = calloc(BUFFER_INIT_SIZE, sizeof(char));

    if (ret->b == NULL)
        goto err_free;

    return ret;

err_free:
    free(ret);
err:
    return NULL;
}

void p11_buffer_free(p11_buffer_t *buf)
{
    free(buf->b);
    free(buf);
}

void p11_buffer_reset(p11_buffer_t *buf)
{
    memset(buf->b, 0, buf->b_size);
}

const char *p11_buffer_char(const p11_buffer_t *buf)
{
    return (const char *) buf->b;
}

size_t p11_buffer_size(const p11_buffer_t *buf)
{
    return buf->b_size;
}

long p11_buffer_append_len(p11_buffer_t *buf, const char *s, size_t len)
{
    size_t new_len = strlen(buf->b) + len;
    char *b_end;

    if (!s || (len == 0))
        return strlen(buf->b);

    /* extend buffer if required */
    if ((new_len + 1) > buf->b_size) {
        size_t new_b_size =
            (((new_len + 1) / BUFFER_INIT_SIZE) + 1) * BUFFER_INIT_SIZE;
        char *new_b = realloc(buf->b, new_b_size);

        /* ENOMEM */
        if (new_b == NULL)
            return -1;

        buf->b = new_b;
        buf->b_size = new_b_size;
    }

    /*
     * workaround: the obvious way to concatenate buf->b and s with
     * strncat(buf->b, s, len) is insecure, therefore do it manually.
     */

    /* copy len bytes to the end of buf->b */
    b_end = buf->b + strnlen(buf->b, buf->b_size);
    memcpy(b_end, s, len);

    /* terminate with \0 */
    b_end += len;
    *b_end = '\0';

    return new_len;
}

long p11_buffer_append(p11_buffer_t *buf, const char *s)
{
    if (!s)
        return strlen(buf->b);
    return p11_buffer_append_len(buf, s, strlen(s));
}

long p11_buffer_append_printf(p11_buffer_t *buf, const char *fmt, ...)
{
    va_list ap;
    int len, rc = 0;
    char *tmp = NULL;

    va_start(ap, fmt);
    len = vasprintf(&tmp, fmt, ap);
    va_end(ap);

    if (len < 0)
        goto err;

    rc = p11_buffer_append_len(buf, tmp, len);
err:
    free(tmp);
    return rc;
}
