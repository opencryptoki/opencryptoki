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
   We export Daemon so that we can daemonize or
   not based on a command-line argument
 */
BOOL               Daemon         = (BOOL) BECOME_DAEMON;
BOOL               IveDaemonized  = FALSE;
static u_int32     PathSize       = PATH_MAX + 1;
static char       *StartDir       = NULL;


BOOL IsDaemon ( void ) {

  return (BOOL) ( (Daemon) && (IveDaemonized) );

}



BOOL SaveStartupDirectory ( char *Arg0 ) {

  unsigned int        Err;
  char                cwd[PATH_MAX+1];
  char                arg[PATH_MAX+1];
  char                *dname = NULL;


  ASSERT( Arg0 != NULL );

  if ( getcwd ( cwd, PathSize ) == NULL ) {
    Err = errno;
    DbgLog(DL0,"SaveStartupDirectory: getcwd returned %s (%d)", SysConst(Err), Err);
    return FALSE;
  }

  /* Free previous copy */
  if ( StartDir != NULL ) {
    free(StartDir);
    StartDir = NULL;
  }

  /* Allocate memory */
  if ( (StartDir = calloc ( PathSize, sizeof(char) ) ) == NULL ) {
    Err = errno;
    DbgLog(DL0,"SaveStartupDirectory: Unable to allocate %d bytes of memory for storage of the CWD. %s (%d)\n", SysConst(Err), Err );
    exit(1);
  }


  /* If Arg0 contains a /, then dirname(Arg0) is appended to cwd */
      /* This will handle the case where you were in directory foo, and started the daemon
       * as bar/daemon
       */

  /* FIXME: This will not work properly if the daemon was found by searching the PATH */

  /* Make a local copy of the string because dirname() modifies it's arguments */
  strcpy( arg, Arg0 );

  dname = dirname ( arg );          /* note that dirname("daemon") and dirname("./daemon") will return "." */
  if ( strcmp( dname, "." ) != 0 ) {
    /* there's a / in it... */
    sprintf(StartDir, "%s/%s", cwd, dname);
  } else {
    sprintf(StartDir, "%s", cwd);
  }

  return TRUE;

}



BOOL GetStartDirectory ( char *Buffer, u_int32 BufSize ) {

  ASSERT(Buffer != NULL);

  if ( StartDir == NULL ) {
    DbgLog(DL0,"GetStartDirectory: Function called before SaveStartupDirectory()");
    return FALSE;
  }

  /* what the hell is this? */
  if ( BufSize < PathSize )  { return FALSE; }

  memcpy(Buffer, StartDir, strlen(StartDir) + 1 );
  return TRUE;

}
