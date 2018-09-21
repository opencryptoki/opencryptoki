/*
 * COPYRIGHT (c) International Business Machines Corp. 2018
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef OCK_SYSLOG_H
#define OCK_SYSLOG_H

#include <stdarg.h>
#include <string.h>
#include <syslog.h>

#define OCK_SYSLOG_MAX	512

#define OCK_SYSLOG(priority, ...)	\
    _ock_syslog(priority, __FILE__, __VA_ARGS__)


static inline void _ock_syslog(int priority, const char *file,
                               const char *fmt, ...) {
    char buf[OCK_SYSLOG_MAX];
    size_t off;
    va_list ap;

    snprintf(buf, sizeof(buf), "%s ", file);
    off = strlen(buf);

    va_start(ap, fmt);
    vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
    va_end(ap);

    syslog(priority, "%s", buf);
}

#endif
