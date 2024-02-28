/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <unistd.h>
#include <errno.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <grp.h>
#include <string.h>

#include "log.h"
#include "slotmgr.h"

static int xplfd = -1;

int CreateXProcLock(void)
{
    struct group *grp;

    if (xplfd == -1)
        xplfd = open(OCK_API_LOCK_FILE, OPEN_MODE);

    if (xplfd == -1) {
        xplfd = open(OCK_API_LOCK_FILE, O_CREAT | OPEN_MODE, MODE_BITS);

        if (xplfd != -1) {
            if (fchmod(xplfd, MODE_BITS) == -1) {
                DbgLog(DL0, "%s:fchmod(%s):%s\n",
                       __func__, OCK_API_LOCK_FILE, strerror(errno));
                goto error;
            }

            grp = getgrnam(PKCS_GROUP);
            if (grp != NULL) {
                if (fchown(xplfd, -1, grp->gr_gid) == -1) {
                    DbgLog(DL0, "%s:fchown(%s):%s\n",
                           __func__,
                           OCK_API_LOCK_FILE, strerror(errno));
                    goto error;
                }
            } else {
                DbgLog(DL0, "%s:getgrnam():%s\n",
                       __func__, strerror(errno));
                goto error;
            }
        } else {
            DbgLog(DL0, "open(%s): %s\n", OCK_API_LOCK_FILE, strerror(errno));
            return FALSE;
        }
    }

    return TRUE;

error:
    if (xplfd != -1)
        close(xplfd);

    return FALSE;
}

void DestroyXProcLock(void)
{
    close(xplfd);
    unlink(OCK_API_LOCK_FILE);
}

int XProcLock(void)
{
    if (xplfd != -1)
        flock(xplfd, LOCK_EX);

    return TRUE;
}

int XProcUnLock(void)
{
    if (xplfd != -1)
        flock(xplfd, LOCK_UN);

    return TRUE;
}

/******************************************************************************
 *
 * InitializeMutexes -
 *
 *   Initializes the global shared memory mutex, and sets up mtxattr,
 *   the attribute identifier used to create all the per-process mutexes
 *
 ******************************************************************************/

int InitializeMutexes(void)
{
    int err;

    if ((err = CreateXProcLock()) != TRUE) {
        DbgLog(DL0,
               "InitializeMutexes: CreateXProcLock() failed - returned %#x\n",
               err);
        return FALSE;
    }

    return TRUE;
}

/***********************************************************************
 *   DestroyMutexes -
 *
 *   Destroys all the mutexes used by the program
 *
 ***********************************************************************/

int DestroyMutexes(void)
{
    DestroyXProcLock();
    return TRUE;
}
