/*
 * COPYRIGHT (c) International Business Machines Corp. 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef SECURE_GETENV_H
#define SECURE_GETENV_H

#include <stdlib.h>
#include <unistd.h>

static inline char* secure_getenv(char const *name)
{
    if (geteuid() != getuid() || getegid() != getgid())
        return NULL;
    return getenv(name);
}
#endif /* SECURE_GETENV_H */
