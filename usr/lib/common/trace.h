/*
 * COPYRIGHT (c) International Business Machines Corp. 2015-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef _TRACE_H
#define _TRACE_H

#if defined(__GNUC__) && __GNUC__ >= 7 || defined(__clang__) && __clang_major__ >= 12
    #define PRINTF_FORMAT __attribute__ ((format(printf, 5, 6)))
#else
    #define PRINTF_FORMAT
#endif

#include "defs.h"
#include "host_defs.h"

/* pkcs11 error messages */

enum errmsg {
    ERR_HOST_MEMORY = 0,
    ERR_SLOT_ID_INVALID,
    ERR_GENERAL_ERROR,
    ERR_FUNCTION_FAILED,
    ERR_ARGUMENTS_BAD,
    ERR_NO_EVENT,
    ERR_ATTRIBUTE_READ_ONLY,
    ERR_ATTRIBUTE_SENSITIVE,
    ERR_ATTRIBUTE_TYPE_INVALID,
    ERR_ATTRIBUTE_VALUE_INVALID,
    ERR_DATA_INVALID,
    ERR_DATA_LEN_RANGE,
    ERR_DEVICE_ERROR,
    ERR_DEVICE_MEMORY,
    ERR_DEVICE_REMOVED,
    ERR_ENCRYPTED_DATA_INVALID,
    ERR_ENCRYPTED_DATA_LEN_RANGE,
    ERR_FUNCTION_CANCELED,
    ERR_FUNCTION_NOT_PARALLEL,
    ERR_FUNCTION_NOT_SUPPORTED,
    ERR_KEY_CHANGED,
    ERR_KEY_FUNCTION_NOT_PERMITTED,
    ERR_KEY_HANDLE_INVALID,
    ERR_KEY_INDIGESTIBLE,
    ERR_KEY_NEEDED,
    ERR_KEY_NOT_NEEDED,
    ERR_KEY_NOT_WRAPPABLE,
    ERR_KEY_SIZE_RANGE,
    ERR_KEY_TYPE_INCONSISTENT,
    ERR_KEY_UNEXTRACTABLE,
    ERR_MECHANISM_INVALID,
    ERR_MECHANISM_PARAM_INVALID,
    ERR_OBJECT_HANDLE_INVALID,
    ERR_OPERATION_ACTIVE,
    ERR_OPERATION_NOT_INITIALIZED,
    ERR_PIN_INCORRECT,
    ERR_PIN_INVALID,
    ERR_PIN_LEN_RANGE,
    ERR_PIN_EXPIRED,
    ERR_PIN_LOCKED,
    ERR_SESSION_CLOSED,
    ERR_SESSION_COUNT,
    ERR_SESSION_HANDLE_INVALID,
    ERR_SESSION_PARALLEL_NOT_SUPPORTED,
    ERR_SESSION_READ_ONLY,
    ERR_SESSION_EXISTS,
    ERR_SESSION_READ_ONLY_EXISTS,
    ERR_SESSION_READ_WRITE_SO_EXISTS,
    ERR_SIGNATURE_INVALID,
    ERR_SIGNATURE_LEN_RANGE,
    ERR_TEMPLATE_INCOMPLETE,
    ERR_TEMPLATE_INCONSISTENT,
    ERR_TOKEN_NOT_PRESENT,
    ERR_TOKEN_NOT_RECOGNIZED,
    ERR_TOKEN_WRITE_PROTECTED,
    ERR_UNWRAPPING_KEY_HANDLE_INVALID,
    ERR_UNWRAPPING_KEY_SIZE_RANGE,
    ERR_UNWRAPPING_KEY_TYPE_INCONSISTENT,
    ERR_USER_ALREADY_LOGGED_IN,
    ERR_USER_NOT_LOGGED_IN,
    ERR_USER_PIN_NOT_INITIALIZED,
    ERR_USER_TYPE_INVALID,
    ERR_USER_ANOTHER_ALREADY_LOGGED_IN,
    ERR_USER_TOO_MANY_TYPES,
    ERR_WRAPPED_KEY_INVALID,
    ERR_WRAPPED_KEY_LEN_RANGE,
    ERR_WRAPPING_KEY_HANDLE_INVALID,
    ERR_WRAPPING_KEY_SIZE_RANGE,
    ERR_WRAPPING_KEY_TYPE_INCONSISTENT,
    ERR_RANDOM_SEED_NOT_SUPPORTED,
    ERR_DOMAIN_PARAMS_INVALID,
    ERR_BUFFER_TOO_SMALL,
    ERR_SAVED_STATE_INVALID,
    ERR_INFORMATION_SENSITIVE,
    ERR_STATE_UNSAVEABLE,
    ERR_CRYPTOKI_NOT_INITIALIZED,
    ERR_CRYPTOKI_ALREADY_INITIALIZED,
    ERR_MUTEX_BAD,
    ERR_MUTEX_NOT_LOCKED,
    ERR_MAX,
};

/* Log levels */
typedef enum {
    TRACE_LEVEL_NONE = 0,
    TRACE_LEVEL_ERROR,
    TRACE_LEVEL_WARNING,
    TRACE_LEVEL_INFO,
    TRACE_LEVEL_DEVEL,
    TRACE_LEVEL_DEBUG
} trace_level_t;


/* Encapsulate all trace variables */
struct trace_handle_t {
    int fd;                     /* file descriptor for filename */
    trace_level_t level;        /* trace level */
};

extern struct trace_handle_t trace;

void set_trace(struct trace_handle_t t);
CK_RV trace_initialize(void);
void trace_finalize(void);
void ock_traceit(trace_level_t level, const char *file, int line,
                 const char *stdll_name, const char *fmt, ...)
                 PRINTF_FORMAT;
const char *ock_err(int num);


#define TRACE_ERROR(...)						\
    ock_traceit(TRACE_LEVEL_ERROR, __FILE__, __LINE__, STDLL_NAME, __VA_ARGS__)

#define TRACE_WARNING(...)						\
    ock_traceit(TRACE_LEVEL_WARNING, __FILE__, __LINE__, STDLL_NAME,	\
                __VA_ARGS__)

#define TRACE_INFO(...)							\
    ock_traceit(TRACE_LEVEL_INFO, __FILE__, __LINE__, STDLL_NAME, __VA_ARGS__)

#define TRACE_DEVEL(...)						\
    ock_traceit(TRACE_LEVEL_DEVEL, __FILE__, __LINE__, STDLL_NAME, __VA_ARGS__)

#ifdef DEBUG
#define TRACE_DEBUG(...)						\
    ock_traceit(TRACE_LEVEL_DEBUG, __FILE__, __LINE__, STDLL_NAME, __VA_ARGS__)

void dump_shm(LW_SHM_TYPE *, const char *);
#define DUMP_SHM(x,y) dump_shm(x,y)
#else
#define TRACE_DEBUG(...)
#define DUMP_SHM(x,y)
#endif

#ifdef DEBUG
/* a simple function for dumping out a memory area */
void hexdump(const char *prestr, void *buf, size_t buflen);
#define TRACE_DEBUG_DUMP(_prestr, _buf, _buflen) hexdump(_prestr, _buf, _buflen)
#else
#define TRACE_DEBUG_DUMP(...)
#endif

#endif
