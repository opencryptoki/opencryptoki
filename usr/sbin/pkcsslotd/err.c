/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <sys/types.h>

#include "log.h"
#include "slotmgr.h"
#include "err.h"


static ConstInfo SysErrorInfo[] = {

    CONSTINFO(EPERM),
    CONSTINFO(ENOENT),
    CONSTINFO(ESRCH),
    CONSTINFO(EINTR),
    CONSTINFO(EIO),
    CONSTINFO(ENXIO),
    CONSTINFO(E2BIG),
    CONSTINFO(ENOEXEC),
    CONSTINFO(EBADF),
    CONSTINFO(ECHILD),
    CONSTINFO(EAGAIN),
    CONSTINFO(ENOMEM),
    CONSTINFO(EACCES),
    CONSTINFO(EFAULT),
    CONSTINFO(ENOTBLK),
    CONSTINFO(EBUSY),
    CONSTINFO(EEXIST),
    CONSTINFO(EXDEV),
    CONSTINFO(ENODEV),
    CONSTINFO(ENOTDIR),
    CONSTINFO(EISDIR),
    CONSTINFO(EINVAL),
    CONSTINFO(ENFILE),
    CONSTINFO(EMFILE),
    CONSTINFO(ENOTTY),
    CONSTINFO(ETXTBSY),
    CONSTINFO(EFBIG),
    CONSTINFO(ENOSPC),
    CONSTINFO(ESPIPE),
    CONSTINFO(EROFS),
    CONSTINFO(EMLINK),
    CONSTINFO(EPIPE),
    CONSTINFO(EDOM),
    CONSTINFO(ERANGE),
    CONSTINFO(ENOMSG),
    CONSTINFO(EIDRM),
#ifdef ECHRNG
    CONSTINFO(ECHRNG),
#endif
#ifdef EL2NSYNC
    CONSTINFO(EL2NSYNC),
#endif
#ifdef EL3HLT
    CONSTINFO(EL3HLT),
#endif
#ifdef EL3RST
    CONSTINFO(EL3RST),
#endif
#ifdef ELNRNG
    CONSTINFO(ELNRNG),
#endif
#ifdef EUNATCH
    CONSTINFO(EUNATCH),
#endif
#ifdef ENOCSI
    CONSTINFO(ENOCSI),
#endif
#ifdef EL2HLT
    CONSTINFO(EL2HLT),
#endif
    CONSTINFO(EDEADLK),
    CONSTINFO(ESTALE),
    CONSTINFO(EWOULDBLOCK),
    CONSTINFO(EINPROGRESS),
    CONSTINFO(EALREADY),
    CONSTINFO(ENOTSOCK),
    CONSTINFO(EDESTADDRREQ),
    CONSTINFO(EMSGSIZE),
    CONSTINFO(EPROTOTYPE),
    CONSTINFO(ENOPROTOOPT),
    CONSTINFO(EPROTONOSUPPORT),
    CONSTINFO(ESOCKTNOSUPPORT),
    CONSTINFO(EOPNOTSUPP),
    CONSTINFO(EPFNOSUPPORT),
    CONSTINFO(EAFNOSUPPORT),
    CONSTINFO(EADDRINUSE),
    CONSTINFO(EADDRNOTAVAIL),
    CONSTINFO(ENETDOWN),
    CONSTINFO(ENETUNREACH),
    CONSTINFO(ENETRESET),
    CONSTINFO(ECONNABORTED),
    CONSTINFO(ECONNRESET),
    CONSTINFO(ENOBUFS),
    CONSTINFO(EISCONN),
    CONSTINFO(ENOTCONN),
    CONSTINFO(ESHUTDOWN),
    CONSTINFO(ETIMEDOUT),
    CONSTINFO(ECONNREFUSED),
    CONSTINFO(EHOSTDOWN),
    CONSTINFO(EHOSTUNREACH),
#ifdef ERESTART
    CONSTINFO(ERESTART),
#endif
    CONSTINFO(EUSERS),
    CONSTINFO(ELOOP),
    CONSTINFO(ENAMETOOLONG),
    CONSTINFO(ENOTEMPTY),
    CONSTINFO(EDQUOT),
    CONSTINFO(EREMOTE),
    CONSTINFO(ENOSYS),
    CONSTINFO(ETOOMANYREFS),
    CONSTINFO(EILSEQ),
    CONSTINFO(ECANCELED),
#ifdef ENOSR
    CONSTINFO(ENOSR),
#endif
#ifdef ETIME
    CONSTINFO(ETIME),
#endif
#ifdef EBADMSG
    CONSTINFO(EBADMSG),
#endif
#ifdef EPROTO
    CONSTINFO(EPROTO),
#endif
#ifdef ENODATA
    CONSTINFO(ENODATA),
#endif
#ifdef ENOSTR
    CONSTINFO(ENOSTR),
#endif
    CONSTINFO(ENOTSUP),
#ifdef EMULTIHOP
    CONSTINFO(EMULTIHOP),
#endif
#ifdef ENOLINK
    CONSTINFO(ENOLINK),
#endif
#ifdef EOVERFLOW
    CONSTINFO(EOVERFLOW),
#endif

};

static int SysErrorSize = (sizeof(SysErrorInfo) / sizeof(SysErrorInfo[0]));



static ConstInfo SignalInfo[] = {

    CONSTINFO(SIGHUP),
    CONSTINFO(SIGINT),
    CONSTINFO(SIGQUIT),
    CONSTINFO(SIGILL),
    CONSTINFO(SIGTRAP),
    CONSTINFO(SIGABRT),
    CONSTINFO(SIGFPE),
    CONSTINFO(SIGKILL),
    CONSTINFO(SIGBUS),
    CONSTINFO(SIGSEGV),
    CONSTINFO(SIGSYS),
    CONSTINFO(SIGPIPE),
    CONSTINFO(SIGALRM),
    CONSTINFO(SIGTERM),
    CONSTINFO(SIGURG),
    CONSTINFO(SIGSTOP),
    CONSTINFO(SIGTSTP),
    CONSTINFO(SIGCONT),
    CONSTINFO(SIGCHLD),
    CONSTINFO(SIGTTIN),
    CONSTINFO(SIGTTOU),
    CONSTINFO(SIGIO),
    CONSTINFO(SIGXCPU),
    CONSTINFO(SIGXFSZ),
    CONSTINFO(SIGWINCH),
#ifdef SIGPWR
    CONSTINFO(SIGPWR),
#endif
    CONSTINFO(SIGUSR1),
    CONSTINFO(SIGUSR2),
    CONSTINFO(SIGPROF),
    CONSTINFO(SIGVTALRM),
    CONSTINFO(SIGIOT),
#ifdef SIGCLD
    CONSTINFO(SIGCLD),
#endif
#ifdef SIGPOLL
    CONSTINFO(SIGPOLL),
#endif
#if 0
    CONSTINFO(SIG_DFL),
    CONSTINFO(SIG_IGN),
    CONSTINFO(SIG_HOLD),
    CONSTINFO(SIG_CATCH),
    CONSTINFO(SIG_ERR),
#endif                          /* 0 */

};

static int SignalInfoSize = (sizeof(SignalInfo) / sizeof(SignalInfo[0]));

const unsigned char *ConstName(pConstInfo pInfoArray,
                               unsigned int InfoArraySize,
                               unsigned int ConstValue)
{

    unsigned int i;
    unsigned const char *retval = NULL;


    for (i = 0; i < InfoArraySize; i++) {
        if (pInfoArray[i].Code == ConstValue) {
            retval = (unsigned char *)&(pInfoArray[i].Name[0]);
            break;
        }
        /* end if */
    }                           /* end for i */

    if (retval == NULL) {
        if (ConstValue == 0) {
            retval = (const unsigned char *) "NULL";
        } else {
            retval = (const unsigned char *) "\"<*>CONSTANT NOT FOUND<*>\"";
        }
    }

    return retval;
}

const unsigned char *SignalConst(unsigned int Val)
{
    return ConstName(SignalInfo, SignalInfoSize, Val);
}

const unsigned char *SysConst(unsigned int Val)
{
    return ConstName(SysErrorInfo, SysErrorSize, Val);
}

