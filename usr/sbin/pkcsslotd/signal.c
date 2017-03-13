/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <stdlib.h>
#include <signal.h>

#include "log.h"
#include "slotmgr.h"
#include "pkcsslotd.h"
#include "err.h"


extern BOOL        IsValidProcessEntry  ( pid_t_64 pid, time_t_64 RegTime );

static int SigsToIntercept[] = {
  SIGHUP,      SIGINT,       SIGQUIT,    SIGPIPE,      SIGALRM,
  SIGTERM,     SIGTSTP,      SIGTTIN,
  SIGTTOU,     SIGUSR1,      SIGUSR2,    SIGPROF
};

/* SIGCONT - Don't want to exit on SIGCONT; it'll in fact
   mask other signals - kill -HUP actually sends SIGCONT before SIGHUP */

/* SIGCHLD - Don't want to exit.  Should never receive, but we do, apparently when
   something tries to cancel the GC Thread */

static int SigsToIgnore[] = {
  SIGCHLD,
};



/**************************************************
 * slotdGenericSignalHandler
 *
 *   Main signal handler for the daemon.  Doesn't
 *   allow the daemon to be killed unless we're
 *   not in use
 ***************************************************/
void slotdGenericSignalHandler( int Signal ) {

  int procindex;
  BOOL OkToExit = TRUE;

  /********************************************************
   *    DbgLog calls (possibly) printf, syslog_r, etc.
   *    The behavior of these functions is "undefined"
   *    when called from a signal handler according to
   *    the sigaction man page.
   *
   *    Thus, they're only called in development
   *    versions of the code.
   ********************************************************/

   #ifdef DEV
     DbgLog(DL2, "slotdGenericSignalHandler got %s (%d; %#x)", SignalConst(Signal), Signal, Signal);
   #endif /* DEV */

#if !defined(NOGARBAGE)
   StopGCThread(shmp);
   CheckForGarbage(shmp);
#endif

   for ( procindex = 0; (procindex < NUMBER_PROCESSES_ALLOWED); procindex++ ) {

     Slot_Mgr_Proc_t_64 *pProc = &(shmp->proc_table[procindex]);

     if ( shmp == NULL ) {
       break;
     }
     if ( ( pProc->inuse )
#if !(NOGARBAGE)
	   && ( IsValidProcessEntry( pProc->proc_id, pProc->reg_time))
#endif
	  ) {
       /* Someone's still using us...  Log it */
       OkToExit = FALSE;
       #ifdef DEV
         WarnLog("Process %d is still registered", pProc->proc_id);
       #endif
     }
   }

   if ( !OkToExit ) {
     DbgLog(DL1,"Continuing execution");
#if !defined(NOGARBAGE)
     StartGCThread(shmp);
#endif
     return;
   }

   InfoLog("Exiting on %s (%d; %#x)", SignalConst(Signal), Signal, Signal);

   DetachSocketListener(socketfd);
   DestroyMutexes();
   DetachFromSharedMemory();
   DestroySharedMemory();
   exit(0);

}


/***************************************************
 *  SetupSignalHandlers -
 *
 *  Installs slotdGenericSignalHandler for the listed signals
 *
 ***************************************************/
int SetupSignalHandlers ( void ) {

  unsigned int i;
  struct sigaction 	new_action;

  new_action.sa_handler = slotdGenericSignalHandler;
  sigemptyset(&(new_action.sa_mask));
  sigaddset(&(new_action.sa_mask), SIGCHLD);
  /* sigaddset(&(new_action.sa_mask), SA_NOCLDWAIT); */
  /* sigaddset(&(new_action.sa_mask), SA_NOCLDSTOP); */

  new_action.sa_flags = (RESTART_SYS_CALLS ? SA_RESTART : 0);


  for ( i = 0; i < (sizeof(SigsToIntercept) / sizeof(SigsToIntercept[0])); i++ ) {

    if ( sigaction ( SigsToIntercept[i], &new_action, NULL ) != 0 ) {
      //DbgLog("SetupSignalHandlers - sigaction failed for %s (%d; %#x)", SignalConst(SigsToIntercept[i]), SigsToIntercept[i], SigsToIntercept[i]);
      return FALSE;
    }

  }


  new_action.sa_handler = SIG_IGN;
  sigemptyset(&(new_action.sa_mask));
  for ( i = 0; i < (sizeof ( SigsToIgnore ) / sizeof (SigsToIgnore[0]) ); i++ ) {
    if ( sigaction ( SigsToIgnore[i], &new_action, NULL ) != 0 ) {
      //DbgLog ( "Failed to ignore signal.");
      return FALSE;
    }
  }

  return TRUE;

}



/***********************************************************************
 * GCBlockSignals -
 *
 *    Garbage collector calls this to prevent signals from getting
 *    sent to the GC thread.
 *
 ***********************************************************************/

BOOL GCBlockSignals (void) {

  unsigned int i;
  int ret;
  sigset_t SigSet;

  sigemptyset(&SigSet);
  for ( i = 0; i < (sizeof(SigsToIntercept) / sizeof(SigsToIntercept[0]) ); i++ ) {
    sigaddset(&SigSet, SigsToIntercept[i]);
  }

  ret = pthread_sigmask(SIG_SETMASK, &SigSet, NULL);

  return ret;

}
