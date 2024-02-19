/*
 * Implementation of the err/errx/verr/verrx/warn/warnx/vwarn/vwarnx
 * functions from BSD.
 *
 * This file is public-domain; anyone may deal in it without restriction.
 *
 * Written by Graue <graue@oceanbase.org> on January 16, 2006.
 */

#if defined(__WIN32) || defined(_AIX)
    #define NEED_ERR
#endif

#ifndef NEED_ERR
    #include <err.h> /* system version of this file */
#else

#ifndef _ERR_H
#define _ERR_H

#include <stdarg.h>

void  err  (int eval, const char *fmt, ...);
void  errx (int eval, const char *fmt, ...);
void verr  (int eval, const char *fmt, va_list args);
void verrx (int eval, const char *fmt, va_list args);

void  warn (          const char *fmt, ...);
void  warnx(          const char *fmt, ...);
void vwarn (          const char *fmt, va_list args);
void vwarnx(          const char *fmt, va_list args);

#endif

#endif
