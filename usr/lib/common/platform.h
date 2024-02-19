/*
 * COPYRIGHT (c) International Business Machines Corp. 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#include <dlfcn.h>

#if defined(_AIX)
#include "aix/getopt.h"
#include "aix/secure_getenv.h"
#include "aix/endian.h"
#include "aix/asprintf.h"
#include "aix/err.h"

#define OCK_API_LIBNAME "libopencryptoki.a(libopencryptoki.so.0)"
#define DYNLIB_LDFLAGS (RTLD_NOW | RTLD_MEMBER)

#else /* _AIX */
/* for getopt, getopt_long */
#include <getopt.h>
/* for secure_getenv */
#ifndef _GNU_SOURCE
    #define _GNU_SOURCE
#endif /* _GNU_SOURCE */
#include <stdlib.h>
/* for htobexx, htolexx, bexxtoh and lexxtoh macros */
#include <endian.h>
/* macros from bsdlog and friends */
#include <stdio.h>
#include <err.h>

#define OCK_API_LIBNAME "libopencryptoki.so"
#define DYNLIB_LDFLAGS (RTLD_NOW)

#endif /* _AIX */
