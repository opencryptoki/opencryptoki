 /*
  * COPYRIGHT (c) International Business Machines Corp. 2001-2017
  *
  * This program is provided under the terms of the Common Public License,
  * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
  * software constitutes recipient's acceptance of CPL-1.0 terms which can be
  * found in the file LICENSE file or at
  * https://opensource.org/licenses/cpl1.0.php
  */

#ifndef GARBAGE_LINUX_H
#define GARBAGE_LINUX_H

typedef struct {
  int
    pid;            /* process id */

  char
    cmd[16],        /* command line string vector for /proc/<pid>/cmdline */
    state;          /* single-char code for process state [R, S, D, Z, or T] */

  int
    ppid,           /* pid of parent process */
    pgrp,           /* process group id */
    session,        /* session id */
    tty,            /* full device number of controlling terminal */
    tpgid;          /* terminal process group id */

  unsigned long
    flags,          /* kernel flags for the process */
    min_flt,        /* number of minor page faults since process start */
    cmin_flt,       /* cumulative min_flt of process and child processes */
    maj_flt,        /* number of major page faults since process start */
    cmaj_flt,       /* cumulative maj_flt of process and child processes */
    utime,          /* user-mode CPU time accumulated by process */
    stime;          /* kernel-mode CPU time accumulated by process */

  long
    cutime,         /* cumulative utime of process and reaped children */
    cstime,         /* cumulative stime of process and reaped children */
    priority,       /* kernel scheduling priority */
    nice,           /* standard unix nice level of process */
    timeout,        /* ? */
    it_real_value;  /* ? */

  unsigned long
    start_time,     /* start time of process -- seconds since 1-1-70 */
    vsize;          /* number of pages of virtual memory ... */

  long
    rss;            /* resident set size from /proc/<pid>/stat (pages) */

  unsigned long
    rss_rlim,       /* resident set size limit? */
    start_code,     /* address of beginning of code segment */
    end_code,       /* address of end of code segment */
    start_stack,    /* address of the bottom of stack for the process */
    kstk_esp,       /* kernel stack pointer */
    kstk_eip;       /* kernel instruction pointer */

  char
    /* Linux 2.1.7x and up have more signals. This handles 88. */
    /* long long (instead of char xxxxxx[24]) handles 64 */
    signal[24],     /* mask of pending signals */
    blocked[24],    /* mask of blocked signals */
    sigignore[24],  /* mask of ignored signals */
    sigcatch[24];   /* mask of caught  signals */

  unsigned long
    wchan,          /* address of kernel wait channel proc is sleeping in */
    nswap,          /* ? */
    cnswap;         /* cumulative nswap ? */

  int
    exit_signal,
    processor;

} proc_t;

#endif
