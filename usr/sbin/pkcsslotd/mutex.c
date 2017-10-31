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

static int xplfd=-1;

int
CreateXProcLock(void)
{
	struct group *grp;
	mode_t mode = (S_IRUSR|S_IRGRP);
	struct stat statbuf;

	if (xplfd == -1) {
		if (stat(OCK_API_LOCK_FILE, &statbuf) == 0)
			xplfd = open(OCK_API_LOCK_FILE, O_RDONLY, mode);
		else {
			xplfd = open(OCK_API_LOCK_FILE, O_CREAT|O_RDONLY, mode);

			if (xplfd != -1) {
				if (fchmod(xplfd, mode) == -1) {
					DbgLog(DL0,"%s:fchmod(%s):%s\n",
					       __FUNCTION__, OCK_API_LOCK_FILE,
					       strerror(errno));
					goto error;
				}

				grp = getgrnam("pkcs11");
				if (grp != NULL) {
					if (fchown(xplfd,-1,grp->gr_gid) == -1) {
						DbgLog(DL0,"%s:fchown(%s):%s\n",
						       __FUNCTION__,
						       OCK_API_LOCK_FILE,
						       strerror(errno));
						goto error;
					}
				} else {
					DbgLog(DL0,"%s:getgrnam():%s\n",
					       __FUNCTION__, strerror(errno));
					goto error;
				}
			}
		}
		if (xplfd == -1) {
			DbgLog(DL0,"open(%s): %s\n", OCK_API_LOCK_FILE,
			       strerror(errno));
			return FALSE;
		}
	}
	return TRUE;

error:
	if (xplfd != -1)
		close(xplfd);
	return FALSE;
}

int
XProcLock(void)
{
	if (xplfd != -1)
		flock(xplfd, LOCK_EX);

	return TRUE;
}

int
XProcUnLock(void)
{
	if (xplfd != -1)
		flock(xplfd, LOCK_UN);

	return TRUE;
}

/*********************************************************************************
 *
 * InitializeMutexes -
 *
 *   Initializes the global shared memory mutex, and sets up mtxattr,
 *   the attribute identifier used to create all the per-process mutexes
 *
 *********************************************************************************/

int InitializeMutexes ( void ) {

  int err;

  if ((err = CreateXProcLock()) != TRUE){
    DbgLog(DL0,"InitializeMutexes: CreateXProcLock() failed - returned %#x\n", err);
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

int DestroyMutexes ( void ) {

  /* Get the global shared memory mutex */
  XProcLock();

  /* Give up the global shared memory mutex */

  XProcUnLock();

  return TRUE;

}
