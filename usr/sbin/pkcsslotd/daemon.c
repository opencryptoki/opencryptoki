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
#include <libgen.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "log.h"
#include "slotmgr.h"
#include "pkcsslotd.h"
#include "err.h"

/*
 * We export Daemon so that we can daemonize or
 * not based on a command-line argument
 */
BOOL Daemon = (BOOL) BECOME_DAEMON;
BOOL IveDaemonized = FALSE;

BOOL IsDaemon(void)
{
    return (BOOL) ((Daemon) && (IveDaemonized));
}

