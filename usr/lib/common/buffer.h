/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef __BUFFER_H
#define __BUFFER_H

#include <stddef.h>

typedef struct _buffer p11_buffer_t;

p11_buffer_t *p11_buffer_new(void);
void p11_buffer_free(p11_buffer_t *buf);
void p11_buffer_reset(p11_buffer_t *buf);

const char *p11_buffer_char(const p11_buffer_t *buf);
size_t p11_buffer_size(const p11_buffer_t *buf);

long p11_buffer_append_len(p11_buffer_t *buf, const char *s, size_t len);
long p11_buffer_append(p11_buffer_t *buf, const char *s);
long p11_buffer_append_printf(p11_buffer_t *buf, const char *fmt, ...);

#endif                          /* __BUFFER_H */
