
/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */


#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/syslog.h>

#include <sys/ipc.h>

#include <stdarg.h>
#include <pthread.h>

#include <pkcs11/pkcs11types.h>
#include <pkcs11/stdll.h>

#include "defs.h"
#include "host_defs.h"

#include "tok_spec_struct.h"
extern token_spec_t token_specific;

#include "tokenlocal.h"



#include "msg.h"  // HACK  

void stlogit(char *, ...);
//extern char **err_msg;

#include <sys/types.h>
#include <sys/stat.h>

#if 0
extern FILE  *debugfile;
char  lfname[1024];
#else
extern int  debugfile;
#endif
pthread_mutex_t  lmtx=PTHREAD_MUTEX_INITIALIZER;

static int enabled=0;
static int logging=0;
static int env_log_check=0; 

// Logging types.  Ultimately this will allow
// us to log to different log files.  The logger will also
// handle keeping the files to a decent size.
// Much work needs to be done on this capability... 
// Other logging types need to be implemented

void 
stloginit(){
   char *logval;
   if (!env_log_check){
      logval = getenv("PKCS_ERROR_LOG");
      env_log_check = 1;
      if (logval != NULL)
         logging = 1;
      else
         logging = 0;
   }
   if (!enabled && logging){
      enabled=1;
      openlog(DBGTAG,LOG_PID|LOG_NDELAY,LOG_LOCAL6);
      setlogmask(LOG_UPTO(LOG_DEBUG));


#ifdef DEBUG
      debugfile = 1;
#else
      debugfile = 0;
#endif
#if 0
      sprintf(lfname,"/etc/pkcs11/%s.%d",DBGTAG,getpid());
      debugfile = fopen(lfname,"w+");
      if (debugfile) {
         fchmod(fileno(debugfile),
         S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH|S_IWOTH);
      }
#endif
      stlogit("Logg initialized");
   }
}

void
stlogterm()
{
  enabled = 0;
}

void
stlogit2(int type,char *fmt, ...)
{
      int n;
      va_list pvar;
      char *env;
      char buffer[4096*4];
      char buf1[4096];

   if (!enabled)  stloginit();

   if ( enabled && debugfile){
//         sprintf(buf1,"Tid %d",pthread_self());
//         syslog_r(LOG_DEBUG,&log_data,buf1);
         va_start(pvar, fmt);
         vsprintf(buffer,fmt,pvar);
         va_end(pvar);
         pthread_mutex_lock(&lmtx);
         syslog(LOG_DEBUG,buffer);
         pthread_mutex_unlock(&lmtx);
#if 0
	if (debugfile) {
         pthread_mutex_lock(&lmtx);
         fprintf(debugfile,"[%d]:%s\n",getpid(),buffer);
          fflush(debugfile);
         pthread_mutex_unlock(&lmtx);
 	}
#endif
   }

}



void
stlogit(char *fmt, ...)
{
      int n;
      va_list pvar;
      char *env;
      char buffer[4096*4];

   if (!enabled)  stloginit();

   if ( enabled && debugfile){
         va_start(pvar, fmt);
         vsprintf(buffer,fmt,pvar);
         va_end(pvar);
         pthread_mutex_lock(&lmtx);
         syslog(LOG_DEBUG,buffer);
         pthread_mutex_unlock(&lmtx);
#if 0
	if (debugfile) {
         pthread_mutex_lock(&lmtx);
         fprintf(debugfile,"[%d]:%s\n",getpid(),buffer);
          fflush(debugfile);
         pthread_mutex_unlock(&lmtx);
 	}
#endif
   }

}
/*
void
st_err_log(char *fmt, ...)
{
      int n;
      va_list pvar;
      char *env;
      char buffer[4096*4];

   if (!enabled)  stloginit();

   if ( enabled ){
         va_start(pvar, fmt);
         vsprintf(buffer,fmt,pvar);
         va_end(pvar);
         pthread_mutex_lock(&lmtx);
         syslog(LOG_ERR,buffer);
         pthread_mutex_unlock(&lmtx);
   }

}

void
st_err_log(int num, ...)
{
      int n;
      va_list pvar;
      char *env;
      char buffer[4096*4];

   if (!enabled && logging)  stloginit();

   if ( enabled ){
         va_start(pvar,num);
         vsprintf(buffer,err_msg[num].msg,pvar);
         va_end(pvar);
         pthread_mutex_lock(&lmtx);
         syslog(LOG_ERR,buffer);
         pthread_mutex_unlock(&lmtx);
   }

}
*/

