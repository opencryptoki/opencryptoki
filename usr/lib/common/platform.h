/*
 * COPYRIGHT (c) International Business Machines Corp. 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef PLATFORM_H
#define PLATFORM_H

#include <dlfcn.h>
#include <stdarg.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <dirent.h>

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
#include <err.h>

#define OCK_API_LIBNAME "libopencryptoki.so"
#define DYNLIB_LDFLAGS (RTLD_NOW)

#endif /* _AIX */

/*
 * Check for O_NOFOLLOW support at compile time.
 * If not available, fall back to lstat() + fopen() (has TOCTOU race).
 */
#ifndef O_NOFOLLOW
#define OCK_NO_O_NOFOLLOW 1
#warning "O_NOFOLLOW not supported, symlink protection uses racy lstat() fallback!"
#endif

/*
 * CWE-59 fix: Open file without following symlinks.
 *
 * On platforms with O_NOFOLLOW support:
 *   Uses open(O_NOFOLLOW) + fdopen() for atomic symlink rejection.
 *
 * On platforms without O_NOFOLLOW (e.g., older AIX):
 *   Falls back to lstat() + fopen(). This has a TOCTOU race condition,
 *   but still catches pre-planted symlinks which is the common attack
 *   scenario. Better than no protection at all.
 *
 * Returns NULL with errno=ELOOP if path is a symlink.
 */
static inline FILE *fopen_nofollow(const char *path, const char *mode)
{
#ifdef OCK_NO_O_NOFOLLOW
    /*
     * Fallback for platforms without O_NOFOLLOW: use lstat() check.
     * This has a TOCTOU race but catches pre-planted symlinks.
     */
    struct stat sb;

    if (lstat(path, &sb) == 0) {
        if (S_ISLNK(sb.st_mode)) {
            errno = ELOOP;
            return NULL;
        }
    }
    /* Note: if lstat fails (e.g., file doesn't exist for "w" mode),
     * we proceed with fopen() which will handle the error appropriately */
    return fopen(path, mode);
#else
    /* Preferred: atomic symlink rejection via O_NOFOLLOW */
    int flags = O_NOFOLLOW;
    int fd;
    FILE *fp;

    /* Determine flags based on mode */
    if (mode[0] == 'r') {
        flags |= (mode[1] == '+') ? O_RDWR : O_RDONLY;
    } else if (mode[0] == 'w') {
        flags |= O_CREAT | O_TRUNC | ((mode[1] == '+') ? O_RDWR : O_WRONLY);
    } else if (mode[0] == 'a') {
        flags |= O_CREAT | O_APPEND | ((mode[1] == '+') ? O_RDWR : O_WRONLY);
    } else {
        return NULL;
    }

    fd = open(path, flags, 0600);
    if (fd < 0)
        return NULL;

    fp = fdopen(fd, mode);
    if (fp == NULL) {
        close(fd);
        return NULL;
    }
    return fp;
#endif
}

/*
 * CWE-59 fix: Open file without following symlinks.
 *
 * On platforms with O_NOFOLLOW support:
 *   Uses open(flags | O_NOFOLLOW) for atomic symlink rejection.
 *
 * On platforms without O_NOFOLLOW (e.g., older AIX):
 *   Falls back to lstat() + open(). This has a TOCTOU race condition,
 *   but still catches pre-planted symlinks which is the common attack
 *   scenario. Better than no protection at all.
 *
 * Returns -1 with errno=ELOOP if path is a symlink.
 */
static inline int open_nofollow(const char *path, int flags, ...)
{
    mode_t mode = 0;
    va_list ap;

    if (flags & O_CREAT) {
        va_start(ap, flags);
        mode = va_arg(ap, int); /* mode_t is promoted to int in varargs */
        va_end(ap);
    }

#ifdef OCK_NO_O_NOFOLLOW
    {
        /*
         * Fallback for platforms without O_NOFOLLOW: use lstat() check.
         * This has a TOCTOU race but catches pre-planted symlinks.
         */
        struct stat sb;

        if (lstat(path, &sb) == 0) {
            if (S_ISLNK(sb.st_mode)) {
                errno = ELOOP;
                return -1;
            }
        }
    }
    /* Note: if lstat fails (e.g., file doesn't exist for "w" mode),
     * we proceed with open() which will handle the error appropriately */
    return open(path, flags, mode);
#else
    /* Preferred: atomic symlink rejection via O_NOFOLLOW */
    return open(path, flags | O_NOFOLLOW, mode);
#endif
}

/*
 * CWE-59 fix: Open a directory without following symlinks.
 *
 * On platforms with O_NOFOLLOW support:
 *   Uses open(O_NOFOLLOW | O_DIRECTORY) + fdopendir() for atomic symlink
 *   rejection.  fdopendir() takes ownership of the fd; it is closed by
 *   closedir().
 *
 * On platforms without O_NOFOLLOW (e.g., older AIX):
 *   Falls back to lstat() + opendir(). This has a TOCTOU race condition,
 *   but still catches pre-planted symlinks which is the common attack
 *   scenario. Better than no protection at all.
 *
 * Returns NULL with errno=ELOOP if path is a symlink.
 */
static inline DIR *opendir_nofollow(const char *path)
{
#ifdef OCK_NO_O_NOFOLLOW
    /*
     * Fallback for platforms without O_NOFOLLOW: use lstat() check.
     * This has a TOCTOU race but catches pre-planted symlinks.
     */
    struct stat sb;

    if (lstat(path, &sb) == 0) {
        if (S_ISLNK(sb.st_mode)) {
            errno = ELOOP;
            return NULL;
        }
    }
    return opendir(path);
#else
    /* Preferred: atomic symlink rejection via O_NOFOLLOW */
    int fd;
    DIR *dir;

    fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0)
        return NULL;

    dir = fdopendir(fd);
    if (dir == NULL) {
        close(fd);
        return NULL;
    }
    return dir;
#endif
}

#endif /* PLATFORM_H */
