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
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <fcntl.h>
#include <stdlib.h>

#include "log.h"
#include "slotmgr.h"
#include "pkcsslotd.h"
#include "err.h"

#if defined(_AIX)
    #include <sys/procfs.h>
#endif

#define PROC_BASE "/proc"

#if !defined(NOGARBAGE)

#include "garbage_linux.h"

BOOL IsValidProcessEntry(pid_t_64 pid, time_t_64 RegTime);

int Stat2Proc(int pid, proc_t *p);

pthread_t GCThread;             /* Garbage Collection thread's handle */
static BOOL ThreadRunning = FALSE;      /* If we're already running or not */

#if THREADED
static void *GCMain(void *Ptr);
static void GCCancel(void *Ptr);
#else
void *GCMain(void *Ptr);
void GCCancel(void *Ptr);
#endif





/******************************************************************************
 * StartGCThread -
 *
 *   Entry point that starts the garbage collection thread
 *
 ******************************************************************************/

BOOL StartGCThread(Slot_Mgr_Shr_t *MemPtr)
{
    int err;

#if !(THREADED)
    return TRUE;
#endif

    if (ThreadRunning) {
        DbgLog(DL0, "StartGCThread: Thread already running.");
        return FALSE;
    }

    err =  pthread_create(&GCThread, NULL, GCMain, ((void *) MemPtr));
    if (err != 0) {
        DbgLog(DL0, "StartGCThread: pthread_create returned %s (%d; %#x)",
               SysConst(err), err, err);
        return FALSE;
    }

    ThreadRunning = TRUE;

#ifdef DEV
    // Only development builds
    LogLog("StartGCThread: garbage collection thread started as ID "
           "%lu by ID %lu",
           GCThread, pthread_self());
#endif

    return TRUE;
}




/*****************************************************************************
 * StopGCThread -
 *
 *   Entry point which causes the Garbage collection thread to terminate
 *   Waits for the thread to terminate before continuing
 *
 ******************************************************************************/

BOOL StopGCThread(void *Ptr)
{
    int err;

    void *Status;

    UNUSED(Ptr);

#if !(THREADED)
    return TRUE;
#endif
    if (!ThreadRunning) {
        DbgLog(DL0, "StopGCThread was called when the garbage collection "
               "thread was not running");
        return FALSE;
    }

    DbgLog(DL0, "StopGCThread: tid %lu is stopping the garbage collection "
           "thread (tid %lu)",
           pthread_self(), GCThread);

    /* Cause the GC thread to be cancelled */
    if ((err = pthread_cancel(GCThread)) != 0) {
        DbgLog(DL0, "StopGCThread: pthread_cancel returned %s (%d; %#x)",
               SysConst(err), err, err);
        return FALSE;
    }

    /* Synchronize with the GC thread (aka: wait for it to terminate) */
    if ((err = pthread_join(GCThread, &Status)) != 0) {
        DbgLog(DL0, "StopGCThread: pthread_join returned %s (%d; %#x)",
               SysConst(err), err, err);
        return FALSE;
    }

    if (Status != PTHREAD_CANCELED) {
        DbgLog(DL0, "Hmm. Thread was cancelled, but didn't return the "
               "appropriate return status");
    }

    ThreadRunning = FALSE;

    return TRUE;
}



/******************************************************************************
 * GCMain -
 *
 *     The Garbage collection thread's main()
 *     Basically, run until cancelled by another thread
 *
 ******************************************************************************/

void *GCMain(void *Ptr)
{
#if THREADED
    int OrigCancelState;
    int OrigCancelType;
    int LastCancelState;
#endif
    Slot_Mgr_Shr_t *MemPtr = (Slot_Mgr_Shr_t *) Ptr;



    ASSERT(MemPtr != NULL);


    sleep(2);                   //  SAB  Linux likes to have us delay
// Linux threading model appears to have some issues with regards to
// signals....  Need to look at this FIXME..

    /* setup */
    /* Block the signals that go to the main thread */
    /* FIXME: We probably want to make it so that signals go only to
     * the main thread by default */
// SBADE ....  FIXME... remove the blocking of signals see what happens..
//  GCBlockSignals();


    /* Make it so that we can only be cancelled when we reach a
     * cancellation point */
    /* PTHREAD_CANCEL_DEFERRED should be the default */
#if THREADED
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &OrigCancelState);
    pthread_setcanceltype(PTHREAD_CANCEL_DEFERRED, &OrigCancelType);

    /* push cleanup routines */
    pthread_cleanup_push(GCCancel, MemPtr);
#endif

    DbgLog(DL0, "Garbage collection running... PID %d\n", getpid());
    while (1) {

        DbgLog(DL0, "Garbage collection running...");

        /* Don't allow cancellations while mucking with shared memory or
         * holding mutexes */
#if THREADED
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &LastCancelState);

#endif

        CheckForGarbage(MemPtr);

#if THREADED
        /* re-enable cancellations */
        pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &LastCancelState);

        /* Test for cancellation by the main thread */
        pthread_testcancel();
#endif

        DbgLog(DL5, "Garbage collection finished.");

        /* now we pause */
        sleep(10);
    }                           /* end while 1 */


#if THREADED
    /* Yeah, yeah. Has to be here because some implementations
     * use macros that have to be balanced */
    pthread_cleanup_pop(0);
#endif

    /* return implicitly calls pthread_cancel() */
    /* but it'll never really get executed; pthread_testcancel()
     * implicitly calls pthread_exit() if there's a cancellation pending */
    return NULL;

}


/*****************************************************************************
 * GCCancel -
 *
 *      Cleanup routine called when Garbage collection thread exits/is cancelled
 *
 ******************************************************************************/

void GCCancel(void *Ptr)
{
    UNUSED(Ptr);

    /* Yeah, yeah.  Doesn't do anything, but I had plans */
    DbgLog(DL3, "GCCancel: tid: %lu running cleanup routine", pthread_self());

    return;
}



/*****************************************************************************
 * CheckForGarbage -
 *
 *       The routine that actually does cleanup
 *
 ******************************************************************************/

BOOL CheckForGarbage(Slot_Mgr_Shr_t *MemPtr)
{
    int SlotIndex;
    int ProcIndex;
    int Err;
    BOOL ValidPid;

    ASSERT(MemPtr != NULL_PTR);
#ifdef DEV
    DbgLog(DL5, "Thread %lu is checking for garbage", pthread_self());
#endif                          /* DEV */


#ifdef DEV
    DbgLog(DL5, "Garbage collection attempting global shared memory lock");
#endif                          /* DEV */

    /* Grab the global Shared mem mutex since we might modify
     * global_session_count */

    Err = XProcLock();
    if (Err != TRUE) {
        DbgLog(DL0, "Garbage collection: Locking attempt for global "
               "shmem mutex returned %s",
               SysConst(Err));
        return FALSE;
    }
#ifdef DEV
    DbgLog(DL5, "Garbage collection: Got global shared memory lock");
#endif                          /* DEV */


    for (ProcIndex = 0; ProcIndex < NUMBER_PROCESSES_ALLOWED; ProcIndex++) {

        Slot_Mgr_Proc_t_64 *pProc = &(MemPtr->proc_table[ProcIndex]);

        ASSERT(pProc != NULL_PTR);

        if (!(pProc->inuse)) {
            continue;
        }

        ValidPid = ((IsValidProcessEntry(pProc->proc_id, pProc->reg_time))
                    && (pProc->proc_id != 0));


        if ((pProc->inuse) && (!ValidPid)) {

#ifdef DEV
            DbgLog(DL1, "Garbage collection routine found bad entry for pid "
                   "%d (Index: %d); removing from table",
                   pProc->proc_id, ProcIndex);
#endif                          /* DEV */

            /*                         */
            /* Clean up session counts */
            /*                         */
            for (SlotIndex = 0; SlotIndex < NUMBER_SLOTS_MANAGED; SlotIndex++) {

                unsigned int *pGlobalSessions =
                    &(MemPtr->slot_global_sessions[SlotIndex]);
                unsigned int *pGlobalRWSessions =
                    &(MemPtr->slot_global_rw_sessions[SlotIndex]);
                unsigned int *pGlobalTokspecCount =
                    &(MemPtr->slot_global_tokspec_count[SlotIndex]);
                unsigned int *pProcSessions =
                    &(pProc->slot_session_count[SlotIndex]);
                unsigned int *pProcRWSessions =
                    &(pProc->slot_rw_session_count[SlotIndex]);
                unsigned int *pProcTokspecCount =
                    &(pProc->slot_tokspec_count[SlotIndex]);

                if (*pProcSessions > 0) {

#ifdef DEV
                    DbgLog(DL2, "GC: Invalid pid (%d) is holding %u sessions "
                           "open on slot %d.  Global session count for this "
                           "slot is %u",
                           pProc->proc_id, *pProcSessions, SlotIndex,
                           *pGlobalSessions);
#endif                          /* DEV */

                    if (*pProcSessions > *pGlobalSessions) {
#ifdef DEV
                        WarnLog("Garbage Collection: Illegal values in table "
                                "for defunct process");
                        DbgLog(DL0, "Garbage collection: A process "
                               "( Index: %d, pid: %d ) showed %u sessions "
                               "open on slot %d, but the global count for this "
                               "slot is only %u",
                               ProcIndex, pProc->proc_id, *pProcSessions,
                               SlotIndex, *pGlobalSessions);
#endif                          /* DEV */
                        *pGlobalSessions = 0;
                        *pGlobalRWSessions = 0;
                    } else {
                        *pGlobalSessions -= *pProcSessions;
                        *pGlobalRWSessions -= *pProcRWSessions;
                    }

                    *pProcSessions = 0;
                    *pProcRWSessions = 0;

                }
                /* end if *pProcSessions */

                if (*pGlobalTokspecCount > 0) {
                    if (*pProcTokspecCount > *pGlobalTokspecCount)
                        *pGlobalTokspecCount = 0;
                    else
                        *pGlobalTokspecCount -= *pProcTokspecCount;
                    *pProcTokspecCount = 0;
                }
            }                   /* end for SlotIndex */


            /*                                      */
            /* NULL out everything except the mutex */
            /*                                      */

            memset(&(pProc->inuse), '\0', sizeof(pProc->inuse));
            memset(&(pProc->proc_id), '\0', sizeof(pProc->proc_id));
            memset(&(pProc->slotmap), '\0', sizeof(pProc->slotmap));
            memset(&(pProc->blocking), '\0', sizeof(pProc->blocking));
            memset(&(pProc->error), '\0', sizeof(pProc->error));
            memset(&(pProc->slot_session_count), '\0',
                   sizeof(pProc->slot_session_count));
            memset(&(pProc->reg_time), '\0', sizeof(pProc->reg_time));

        }
        /* end if inuse && ValidPid */
    }                           /* end for ProcIndex */

    XProcUnLock();
    DbgLog(DL5, "Garbage collection: Released global shared memory lock");

    return TRUE;
}



/******************************************************************************
 * Stat2Proc -
 *
 *     Fills a proc_t structure (defined in garbage_linux.h)
 *     with a given pid's stat information found in the /proc/<pid>/stat file
 *
 ******************************************************************************/

int Stat2Proc(int pid, proc_t *p)
{
#if defined(_AIX)
    struct psinfo psinfo;
#else
    char buf[800 + 1];      // about 40 fields, 64-bit decimal is about 20 chars
#endif
    char fbuf[800];         // about 40 fields, 64-bit decimal is about 20 chars
    char *tmp;
    int fd, num;

#if defined(_AIX)
    sprintf(fbuf, "%s/%d/psinfo", PROC_BASE, pid);
#else
    sprintf(fbuf, "%s/%d/stat", PROC_BASE, pid);
#endif
    fflush(stdout);
    if ((fd = open(fbuf, O_RDONLY, 0)) == -1)
        return FALSE;

#if defined(_AIX)
    num = read(fd, &psinfo, sizeof(psinfo));
#else
    num = read(fd, buf, 800);
#endif

    close(fd);

#if defined(_AIX)
    if (num != sizeof(psinfo))
        return FALSE;

    /* on AIX only set those fields that are used by the caller */
    p->pid = psinfo.pr_pid;
    p->start_time = psinfo.pr_start.tv_sec;
    p->flags = psinfo.pr_flag;
    p->state = 0;

#else
    if (num < 80)
        return FALSE;

    buf[num] = '\0';

    tmp = strrchr(buf, ')');    // split into "PID (cmd" and "<rest>"
    *tmp = '\0';                // replacing trailing ')' with NULL
    // Tmp now points to the rest of the buffer.
    // buff points to the command...


    /* fill in default values for older kernels */
    p->exit_signal = SIGCHLD;
    p->processor = 0;

    /* now parse the two strings, tmp & buf, separately,
     * skipping the leading "(" */
    memset(p->cmd, 0, sizeof(p->cmd));
    sscanf(buf, "%d (%15c", &p->pid, p->cmd);   // comm[16] in kernel
    num = sscanf(tmp + 2,       // skip space after ')' as well
                 "%c "
                 "%d %d %d %d %d "
                 "%lu %lu %lu %lu %lu %lu %lu "
                 "%ld %ld %ld %ld %ld %ld "
                 "%lu %lu "
                 "%ld "
                 "%lu %lu %lu %lu %lu %lu "
                 "%*s %*s %*s %*s " // discard, no RT signals &
                 "%lu %lu %lu "    // Linux 2.1 used hex (no use for RT signals)
                 "%d %d",
                 &p->state,
                 &p->ppid, &p->pgrp, &p->session, &p->tty, &p->tpgid,
                 &p->flags, &p->min_flt, &p->cmin_flt, &p->maj_flt,
                 &p->cmaj_flt, &p->utime, &p->stime, &p->cutime, &p->cstime,
                 &p->priority, &p->nice, &p->timeout, &p->it_real_value,
                 &p->start_time, &p->vsize, &p->rss, &p->rss_rlim,
                 &p->start_code, &p->end_code, &p->start_stack, &p->kstk_esp,
                 &p->kstk_eip,
                 /*  p->signal, p->blocked, p->sigignore, p->sigcatch,
                  * can't use */
                 &p->wchan, &p->nswap, &p->cnswap,
                 /* -- Linux 2.0.35 ends here -- */
                 &p->exit_signal, &p->processor /* 2.2.1 ends with exit_signal*/
                 /* -- Linux 2.2.8 and 2.3.47 end here -- */
        );

    /* fprintf(stderr, "Stat2Proc() converted %d fields.\n", num); */
    if (p->tty == 0)
        p->tty = -1;            // the old notty val,
                                // updated elsewhere before moving to 0

    p->vsize /= 1024;

    if (num < 30)
        return FALSE;
    if (p->pid != pid)
        return FALSE;
#endif

    return TRUE;
}



/******************************************************************************
 * IsValidProcessEntry -
 *
 *     Checks to see if the process identifed by pid is the same process
 *     that registered with us
 *
 ******************************************************************************/

BOOL IsValidProcessEntry(pid_t_64 pid, time_t_64 RegTime)
{
    int Err;
    proc_t *p;
    proc_t procstore;

    /*
     * If kill(pid, 0) returns -1 and errno/Err = ESRCH the pid doesn't exist.
     * In case of EPERM we assume that the process exist and try to read its
     * stats.
     */
    if (kill(pid, 0) == -1) {
        Err = errno;
        if (Err == ESRCH) {
            /* The process was not found */
            DbgLog(DL3, "IsValidProcessEntry: PID %lld was not found in the "
                   "process table (kill() returned %s)",
                   pid, SysConst(Err));
            return FALSE;
        } else if (Err != EPERM) {
            /* some other error occurred */
            DbgLog(DL3, "IsValidProcessEntry: kill() returned %s (%d; %#x)",
                   SysConst(Err), Err, Err);
            return FALSE;
        }
    }


    /* end if kill */
    /* Okay, the process exists, now we see if it's really ours */
#ifdef ALLOCATE
    p = (proc_t *) malloc(sizeof(proc_t));
#else
    p = &procstore;
    memset(p, 0, sizeof(proc_t));
#endif

    if (!Stat2Proc((int) pid, p))
        return FALSE;

    if (p->pid == pid) {
        if (RegTime >= p->start_time) { // checking for matching start times
            return TRUE;
        } else {
            /* p->start_time contains the time at which the process began ??
             * (22nd element in /proc/<pid>/stat file) */
            DbgLog(DL1, "IsValidProcessEntry: PID %lld started at %lu; "
                   "registered at %ld",
                   pid, p->start_time, RegTime);
            DbgLog(DL4, "IsValidProcessEntry: PID Returned %d flags at "
                   "%#lx; state at %#x",
                   p->pid, p->flags, p->state);
        }
    }

    return FALSE;
}

#endif                          // NO Garbage
