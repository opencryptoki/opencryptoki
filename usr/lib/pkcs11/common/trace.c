/*
 * COPYRIGHT (c) International Business Machines Corp. 2015-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _GNU_SOURCE
#include <errno.h>
#include <grp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>
#include <sys/file.h>
#include <sys/types.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"

pthread_mutex_t tlmtx = PTHREAD_MUTEX_INITIALIZER;
struct trace_handle_t trace;

static const char *ock_err_msg[] = {
    "Malloc Failed",            /*ERR_HOST_MEMORY */
    "Slot Invalid",             /*ERR_SLOT_ID_INVALID */
    "General Error",            /*ERR_GENERAL_ERROR */
    "Function Failed",          /*ERR_FUNCTION_FAILED */
    "Bad Arguments",            /*ERR_ARGUMENTS_BAD */
    "No Event",                 /*ERR_NO_EVENT */
    "Attribute Read Only",      /*ERR_ATTRIBUTE_READ_ONLY */
    "Attribute Sensitive",      /*ERR_ATTRIBUTE_SENSITIVE */
    "Attribute Type Invalid",   /*ERR_ATTRIBUTE_TYPE_INVALID */
    "Attribute Value Invalid",  /*ERR_ATTRIBUTE_VALUE_INVALID */
    "Data Invalid",             /*ERR_DATA_INVALID */
    "Data Length out of Range", /*ERR_DATA_LEN_RANGE */
    "Device Error",             /*ERR_DEVICE_ERROR */
    "Device does not have Sufficient Memory",   /*ERR_DEVICE_MEMORY */
    "Device Removed",           /*ERR_DEVICE_REMOVED */
    "Encrypted Data Invalid",   /*ERR_ENCRYPTED_DATA_INVALID */
    "Encrypted Data Length out of Range",   /*ERR_ENCRYPTED_DATA_LEN_RANGE */
    "Function Cancelled",       /*ERR_FUNCTION_CANCELED */
    "Function Not Parallel",    /*ERR_FUNCTION_NOT_PARALLEL */
    "Function Not Supported",   /*ERR_FUNCTION_NOT_SUPPORTED */
    "Key Changed",              /*ERR_KEY_CHANGED */
    "Key Function Not Permitted",       /*ERR_KEY_FUNCTION_NOT_PERMITTED */
    "Key Handle Invalid",       /*ERR_KEY_HANDLE_INVALID */
    "Key Indigestible",         /*ERR_KEY_INDIGESTIBLE */
    "Key Needed",               /*ERR_KEY_NEEDED */
    "Key Not Needed",           /*ERR_KEY_NOT_NEEDED */
    "Key Not Wrappable",        /*ERR_KEY_NOT_WRAPPABLE */
    "Key Size out of Range",    /*ERR_KEY_SIZE_RANGE */
    "Key Type Inconsistent",    /*ERR_KEY_TYPE_INCONSISTENT */
    "Key Unextractable",        /*ERR_KEY_UNEXTRACTABLE */
    "Mechanism Invalid",        /*ERR_MECHANISM_INVALID */
    "Mechanism Param Invalid",  /*ERR_MECHANISM_PARAM_INVALID */
    "Object Handle Invalid",    /*ERR_OBJECT_HANDLE_INVALID */
    "Operation Active",         /*ERR_OPERATION_ACTIVE */
    "Operation Not Initialized",        /*ERR_OPERATION_NOT_INITIALIZED */
    "Pin Incorrect",            /*ERR_PIN_INCORRECT */
    "Pin Invalid",              /*ERR_PIN_INVALID */
    "Pin Length out of Range",  /*ERR_PIN_LEN_RANGE */
    "Pin Expired",              /*ERR_PIN_EXPIRED */
    "Pin Locked",               /*ERR_PIN_LOCKED */
    "Session Closed",           /*ERR_SESSION_CLOSED */
    "Session Count",            /*ERR_SESSION_COUNT */
    "Session Handle Invalid",   /*ERR_SESSION_HANDLE_INVALID */
    "Parallel Session Not Supported",   /*ERR_SESSION_PARALLEL_NOT_SUPPORTED */
    "Session Read Only",        /*ERR_SESSION_READ_ONLY */
    "Session Exists",           /*ERR_SESSION_EXISTS */
    "Session Read only Exists", /*ERR_SESSION_READ_ONLY_EXISTS */
    "Session Read Write Exists",        /*ERR_SESSION_READ_WRITE_SO_EXISTS */
    "Signature Invalid",        /*ERR_SIGNATURE_INVALID */
    "Signature Length out of Range",    /*ERR_SIGNATURE_LEN_RANGE */
    "Template Incomplete",      /*ERR_TEMPLATE_INCOMPLETE */
    "Template Inconsistent",    /*ERR_TEMPLATE_INCONSISTENT */
    "Token Not Present",        /*ERR_TOKEN_NOT_PRESENT */
    "Token Not Recognized",     /*ERR_TOKEN_NOT_RECOGNIZED */
    "Token Write Protected",    /*ERR_TOKEN_WRITE_PROTECTED */
    "Unwrapping Key Handle Invalid",    /*ERR_UNWRAPPING_KEY_HANDLE_INVALID */
    "Unwrapping Key Size Range Invalid",    /*ERR_UNWRAPPING_KEY_SIZE_RANGE */
    "Unwrapping Key Type Inconsistent", /*ERR_UNWRAPPING_KEY_TYPE_INCONSISTENT */
    "User Already Logged In",   /*ERR_USER_ALREADY_LOGGED_IN */
    "User Not Logged In",       /*ERR_USER_NOT_LOGGED_IN */
    "User PIN Not Initialized", /*ERR_USER_PIN_NOT_INITIALIZED */
    "User Type Invalid",        /*ERR_USER_TYPE_INVALID */
    "Another User Already Logged In",   /*ERR_USER_ANOTHER_ALREADY_LOGGED_IN */
    "Too Many User Types",      /*ERR_USER_TOO_MANY_TYPES */
    "Wrapped Key Invalid",      /*ERR_WRAPPED_KEY_INVALID */
    "Wrapped Key Length Invalid",       /*ERR_WRAPPED_KEY_LEN_RANGE */
    "Wrapping Key Handle Invalid",      /*ERR_WRAPPING_KEY_HANDLE_INVALID */
    "Wrapping Key Size out of Range",   /*ERR_WRAPPING_KEY_SIZE_RANGE */
    "Wrapping Key Type Inconsistent",   /*ERR_WRAPPING_KEY_TYPE_INCONSISTENT */
    "Random Seed Not Supported",        /*ERR_RANDOM_SEED_NOT_SUPPORTED */
    "Domain Parameter Invalid", /*ERR_DOMAIN_PARAMS_INVALID */
    "Buffer Too Small",         /*ERR_BUFFER_TOO_SMALL */
    "Saved State Invalid",      /*ERR_SAVED_STATE_INVALID */
    "Information Sensitive",    /*ERR_INFORMATION_SENSITIVE */
    "State Unsaveable",         /*ERR_STATE_UNSAVEABLE */
    "API not initialized",      /*ERR_CRYPTOKI_NOT_INITIALIZED */
    "API already Initialized",  /*ERR_CRYPTOKI_ALREADY_INITIALIZED */
    "Mutex Invalid",            /*ERR_MUTEX_BAD */
    "Mutex was not locked",     /*ERR_MUTEX_NOT_LOCKED */
    "Unknown error",            /*ERR_MAX */
};

void set_trace(struct trace_handle_t t_handle)
{
    trace.fd = t_handle.fd;
    trace.level = t_handle.level;
}

void trace_finalize(void)
{
    if (trace.fd)
        close(trace.fd);
    trace.fd = -1;
    trace.level = 0;
}

CK_RV trace_initialize(void)
{
    char *opt = NULL;
    char *end;
    long int num;
    struct group *grp;
    char tracefile[PATH_MAX];

    /* initialize the trace values */
    trace.level = 0;
    trace.fd = -1;

    opt = getenv("OPENCRYPTOKI_TRACE_LEVEL");
    if (!opt)
        return (CKR_FUNCTION_FAILED);

    num = strtol(opt, &end, 10);
    if (*end) {
        OCK_SYSLOG(LOG_WARNING, "OPENCRYPTOKI_TRACE_LEVEL '%s' is "
                   "invalid. Tracing disabled.", opt);
        return (CKR_FUNCTION_FAILED);
    }

    switch (num) {
    case TRACE_LEVEL_NONE:
        return CKR_OK;
    case TRACE_LEVEL_ERROR:
    case TRACE_LEVEL_WARNING:
    case TRACE_LEVEL_INFO:
    case TRACE_LEVEL_DEVEL:
#ifdef DEBUG
    case TRACE_LEVEL_DEBUG:
#endif
        trace.level = num;
        break;
    default:
        OCK_SYSLOG(LOG_WARNING, "Trace level %ld is out of range. "
                   "Tracing disabled.", num);
        return (CKR_FUNCTION_FAILED);
    }

    grp = getgrnam("pkcs11");
    if (grp == NULL) {
        OCK_SYSLOG(LOG_ERR, "getgrnam(pkcs11) failed: %s."
                   "Tracing is disabled.\n", strerror(errno));
        goto error;
    }

    /* open trace file */
    snprintf(tracefile, sizeof(tracefile), "/%s/%s.%d", OCK_LOGDIR,
             "trace", getpid());

    trace.fd = open(tracefile, O_RDWR | O_APPEND | O_CREAT,
                    S_IRUSR | S_IWUSR | S_IRGRP);

    if (trace.fd < 0) {
        OCK_SYSLOG(LOG_WARNING,
                   "open(%s) failed: %s. Tracing disabled.\n",
                   tracefile, strerror(errno));
        goto error;
    }

    /* set pkcs11 group permission on tracefile */
    if (fchown(trace.fd, -1, grp->gr_gid) == -1) {
        OCK_SYSLOG(LOG_ERR, "fchown(%s,-1,pkcs11) failed: %s."
                   "Tracing is disabled.\n", tracefile, strerror(errno));
        goto error;
    }

    return (CKR_OK);

error:
    trace.level = 0;
    trace.fd = -1;

    return (CKR_FUNCTION_FAILED);
}

void ock_traceit(trace_level_t level, const char *fmt, ...)
{
    va_list ap;
    time_t t;
    struct tm *tm;
    char buf[1024];
    char *pbuf;
    int buflen, len;

    if (trace.fd < 0)
        return;

    if (level <= trace.level) {
        pbuf = buf;
        buflen = sizeof(buf);

        /* add the current time */
        t = time(0);
        tm = localtime(&t);
        len = strftime(pbuf, buflen, "%m/%d/%Y %H:%M:%S ", tm);
        pbuf += len;
        buflen -= len;
        /* add the current time */

        /* add the format */
        va_start(ap, fmt);
        vsnprintf(pbuf, buflen, fmt, ap);
        va_end(ap);

        /* serialize appends to the file */
        pthread_mutex_lock(&tlmtx);
        if (write(trace.fd, buf, strlen(buf)) == -1)
            fprintf(stderr, "cannot write to trace file\n");
        pthread_mutex_unlock(&tlmtx);
    }
}

const char *ock_err(int num)
{
    if (num < 0 || num > ERR_MAX)
        num = ERR_MAX;

    return ock_err_msg[num];
}
