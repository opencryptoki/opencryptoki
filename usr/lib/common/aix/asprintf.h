/*
 * COPYRIGHT (c) International Business Machines Corp. 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef UTIL_LINUX_ASPRINTF_H
#define UTIL_LINUX_ASPRINTF_H

#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#ifndef HAVE_VASPRINTF
static inline
int vasprintf(char **strp, const char *fmt, va_list ap)
{
    int str_size = -1, len;
    va_list cap;

    va_copy(cap, ap);

    len = vsnprintf(0, 0, fmt, cap);
    va_end(cap);

    if (len < 0)
        return -1;

    *strp = (char *)malloc (len + 1);

    if (!*strp)
            return -1;

    str_size = vsnprintf(*strp, len + 1, fmt, ap);
    if (str_size < 0 || str_size >= len + 1) {
        free(*strp);
        str_size = -1;
    }
    return str_size;
}
#endif

#ifndef HAVE_ASPRINTF
static inline
int asprintf(char **strp, const char *fmt, ...)
{
    int res;
    va_list ap;

    va_start (ap, fmt);
    res = vasprintf (strp, fmt, ap);
    va_end (ap);

    return res;
}
#endif

#endif
