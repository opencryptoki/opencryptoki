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
#include <string.h>
#include <syslog.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/types.h>

#include "log.h"
#include "err.h"
#include "slotmgr.h"
#include "pkcsslotd.h"


#define DEFAULT_PROGRAM_NAME "Program"

#ifndef PROGRAM_NAME
  #define PROGRAM_NAME DEFAULT_PROGRAM_NAME
#endif /* PROGRAM_NAME */


#ifdef DEV

  #ifndef DEFAULT_LOG_FILE
    #define DEFAULT_LOG_FILE "/tmp/" ## PROGRAM_NAME ## ".log"
  #endif /* DEFAULT_LOG_FILE */

#else /* production build */

  #ifndef DEFAULT_LOG_FILE
    #define DEFAULT_LOG_FILE NULL
  #endif /* DEFAULT_LOG_FILE */

#endif /* DEV */


#ifndef LOG_FILE
  #define LOG_FILE DEFAULT_LOG_FILE
#endif /* LOG_FILE */


#ifndef DEFAULT_DEBUG_LEVEL

  /*********************
     DEFAULT_DEBUG_LEVEL is generally defined in another file (pkcsslotd.h?)
     The #defines here generally won't change much.
   *********************/

  #ifdef DEV
      #define DEFAULT_DEBUG_LEVEL DEBUG_LEVEL0
  #else
      #define DEFAULT_DEBUG_LEVEL DEBUG_NONE
  #endif /* DEFAULT_DEBUG_LEVEL */

#endif /* DEFAULT_DEBUG_LEVEL */



static u_int32                   DefaultLogOption                   = ( LOG_CONS | LOG_NOWAIT | LOG_ODELAY | LOG_PID );
static BOOL                      Initialized                        = FALSE;
static BOOL                      LoggingInitialized                 = FALSE;
static u_int32                   SysDebugLevel                      = DEFAULT_DEBUG_LEVEL;
static char                     *ProgramName                        = PROGRAM_NAME;
static LoggingFacilityInfo       LogInfo[MAX_LOGGING_FACILITIES];
static LogHandle                 hLogDebug;
static LogHandle                 hLogErr;
static LogHandle                 hLogLog;
static LogHandle                 hLogTrace;
static LogHandle                 hLogWarn;
static LogHandle                 hLogInfo;


static LoggingFacility SystemLogFacilities[]   = {
                                                   { "  DEBUG",   &hLogDebug,   LOG_FILE,  TRUE,  LOG_DEBUG    },
						   { "   INFO",   &hLogInfo,    LOG_FILE,  TRUE,  LOG_INFO     },
                                                   { "  TRACE",   &hLogTrace,   LOG_FILE,  TRUE,  LOG_INFO     },
                                                   { "    LOG",   &hLogLog,     LOG_FILE,  TRUE,  LOG_NOTICE   },
                                                   { "WARNING",   &hLogWarn,    LOG_FILE,  TRUE,  LOG_WARNING  },
                                                   { "  ERROR",   &hLogErr,     LOG_FILE,  TRUE,  LOG_ERR      }
                                                 };



/*****************************************
 *        Function Prototypes            *
 *****************************************/

static int                      InitDataStructs           ( void );
static BOOL                     InitLogging               ( void );
static pLoggingFacilityInfo     GetLogInfoPtr             ( LogHandle   hLog );
static BOOL                     GetFreeLogInfo            ( pLogHandle  Dest );
static void                     CloseAllLoggingFacilities ( void );
static BOOL                     SyslogOpen                ( pLoggingFacilityInfo pInfo );



/*************************************************************
 *  GetCurrentTimeString -
 *
 *     Writes the current date & time into *Buffer
 *
 *************************************************************/

BOOL GetCurrentTimeString ( char *Buffer ) {
  /* Note: The specs for ctime_r and asctime_r say that Buffer needs to be 26 characters long.  Not sure if that includes a triling NULL - SCM */

  time_t t;
  struct tm   tm;

  ASSERT(Buffer != NULL);

  time(&t);
  localtime_r(&t, &tm);
  asctime_r( &tm , &(Buffer[0]) );
  /* asctime_r puts a \n at the end, so we'll remove that */
  Buffer[strlen(Buffer)-1] = '\0';
  return TRUE;

}



/***********************************************************************
 *  InitDataStructs -
 *
 *  Called durining initalization to set up the LogInfo array
 *
 ***********************************************************************/

static int InitDataStructs ( void ) {

  unsigned int i;

  for ( i = 0; i < (sizeof(LogInfo) / sizeof(LogInfo[0])); i++ ) {
    LogInfo[i].Initialized    = FALSE;
    LogInfo[i].Descrip[0]     = '\0';
    LogInfo[i].LogOption      = DefaultLogOption;
  }

  Initialized = TRUE;

  return TRUE;

}





/**********************************************************************
 *  GetFreeLogInfo -
 *
 *  Return the handle for the next available Log Facility structure
 *
 *  After calling this function, the facility will be marked as in use
 *
 ***********************************************************************/

static BOOL GetFreeLogInfo ( pLogHandle Dest ) {

  u_int32 i;

  if ( ! Initialized ) {
    InitDataStructs();
  }

  for ( i = 0; i < ( sizeof(LogInfo) / sizeof(LogInfo[0]) ); i++ ) {
    if ( LogInfo[i].Initialized == FALSE ) {
      /*
	 Set this here so that we don't return the same identifier twice
	 in the case where GetFreeLogInfo() is called twice in a row
       */
      LogInfo[i].Initialized = TRUE;
      *Dest = i;
      return TRUE;
    }
  }
#ifdef DEV
  fprintf(stderr, "No available thread logging structs.\n");
#endif
  return FALSE;

}





/**********************************************************************
 *  GetLogInfoPtr -
 *
 *  Given a handle, return a pointer to the appropriate LoggingFacilityInfo structure
 *
 ***********************************************************************/

static pLoggingFacilityInfo GetLogInfoPtr ( LogHandle hLog ) {

  if ( hLog >= (sizeof(LogInfo) / sizeof(LogInfo[0]) ) ) {
#ifdef DEV
    fprintf(stderr, "Illegal LogHandle value: %#X\n", hLog);
#endif
    return NULL;
  }

  if ( LogInfo[hLog].Initialized != TRUE ) {
#ifdef DEV
    fprintf(stderr, "GetLogInfoPtr() called for a non-initialized handle\n");
#endif
    return NULL;
  }

  return &(LogInfo[hLog]);

}




/***********************************************************************
 *  NewLoggingFacility -
 *
 *  Given an ID ( char string which will appear in the messages ),
 *  open a logging facility and return a handle to it in
 *  pLoggingStuff->phLog
 *
 ***********************************************************************/

BOOL NewLoggingFacility ( char *ID, pLoggingFacility pStuff ) {

  pLoggingFacilityInfo      pInfo = NULL;
  LogHandle                 hLog;
  pLogHandle                Result;

  /* See if there's room in the array.  This'd be nice if it were dynamically allocated */
  if ( ! GetFreeLogInfo(&hLog) ) {
    return FALSE;
  }

  /* Get a pointer to the syslog_data structure */
  if ( (pInfo = GetLogInfoPtr(hLog)) == NULL ) {
    return FALSE;
  }

  Result              = pStuff->phLog;


  /*
      Set this before the filename is checked because we
      may want to use the descrip and/or filename in the logs
   */
  pInfo->UseSyslog    = pStuff->UseSyslog;
  pInfo->LogOption    = DefaultLogOption;
  pInfo->pid          = 0;
  pInfo->LogLevel     = pStuff->LogLevel;

  sprintf( pInfo->Descrip, "%s %s", pStuff->Label, ID );

  /* ensure that the last character is a NULL */
  pInfo->Descrip[sizeof(pInfo->Descrip)-1] = '\0';




  /* Some sanity checking on filename... */
  if ( (pStuff->Filename != NULL) && (strlen(pStuff->Filename) > 0) ) {

    FILE *fd;

    #if TRUNCATE_LOGS_ON_START

    /*
     *  Truncating files on the start will present problems if the user creates
     *  their own logging facilities after the program's been running for a while
     *  But the non-syslog logging is intended for debug purposes only, anyway.
     *
     */

      char FileMode[] = "w";
    #else
      char FileMode[] = "a";
    #endif /* TRUNCATE_LOGS_ON_START */

    if ( ( fd = fopen((pStuff->Filename), FileMode ) ) == NULL ) {
#ifdef DEV
      fprintf(stderr, "%s could not be opened\n", pStuff->Filename);
#endif
      pInfo->Filename     = NULL;
    } else {
	/* Tag the file */

	char buf[100];

	GetCurrentTimeString( &(buf[0]) );

#ifdef DEV
        #if TRUNCATE_LOGS_ON_START
          /* buf contains the date stamp */
	  fprintf(fd, "********* %s %s truncated *********\n", buf, pStuff->Filename);
	#else
	  fprintf(fd, "********* %s \"%s\" logging to %s *********\n", buf, pInfo->Descrip, pStuff->Filename);
        #endif /* TRUNCATE_LOGS_ON_START */
#endif

	fflush(fd);
	fclose(fd);
	pInfo->Filename     = pStuff->Filename;
    }

  } else {

    pInfo->Filename       = NULL;

  }


  if ( pInfo->UseSyslog ) {
    /* open the logging facility */
    if (! SyslogOpen( pInfo ) ) {
      return FALSE;
    }
  }

  /* Redundant; Initialized is set to 1 in GetFreeLogInfo */
  pInfo->Initialized = TRUE;
  *Result = hLog;

  return TRUE;

}




/***********************************************************************
 *  CloseLoggingFacility -
 *
 *  Closes the logging facility whose handle is hLog.
 *  Sets up the data structure for reuse later if desired
 *
 ***********************************************************************/

BOOL CloseLoggingFacility ( LogHandle hLog ) {

  pLoggingFacilityInfo      pInfo               = NULL;

  if ( (pInfo = GetLogInfoPtr(hLog)) == NULL ) {
    return FALSE;
  }

  pInfo->Descrip[0]     = '\0';
  pInfo->LogOption      = 0;
  pInfo->Filename       = NULL;
  pInfo->pid            = 0;

  if ( pInfo->UseSyslog ) {
    closelog(  );
  }

  pInfo->Initialized    = FALSE;

  return TRUE;

}




/*****************************************
 * CloseAllLoggingFacilities -
 *
 * Closes down all the logging stuff we've set up
 *****************************************/
static void CloseAllLoggingFacilities ( void ) {
  u_int32      i = 0;

  for ( i = 0; i < (sizeof(LogInfo) / sizeof(LogInfo[0])); i++ ) {
    /* Makes assumption that these handles all are sequential.  Bad Style */
    if ( LogInfo[i].Initialized ) {
      CloseLoggingFacility(i);
    }
  }

  return;

}

/***********************************************************************
 *  PKCS_Log -
 *
 *  The primitive logging function which logs a message on hLog
 *
 ***********************************************************************/

BOOL PKCS_Log ( pLogHandle phLog, char *Format, va_list ap ) {

  char                    Buffer[PATH_MAX];
  pLoggingFacilityInfo    pInfo;

  if ( Format == NULL ) { return FALSE; }

  if ( (pInfo = GetLogInfoPtr(*phLog)) == NULL ) {
    return FALSE;
  }

  if ( (pInfo->pid != getpid() ) && (pInfo->UseSyslog) ) {
    /* Looks like our PID changed since the last call.  We have to re-open */
    if (! SyslogOpen(pInfo) ) {
      return FALSE;
    }
  }

  if ( vsprintf(&(Buffer[0]), Format, ap) < 0 ) {
    /* Error reporting functions should be rather robust, don't you think? */
    /* vsprintf reporting an error */
    //fprintf(stderr, "PKCS_ErrLog - vsprintf error for format string %s\n", Format);
    return FALSE;
  }

  /* Get rid of trailing newlines. */
  while ( strlen(Buffer) && (Buffer[strlen(Buffer)-1] == '\n') ) {
    Buffer[strlen(Buffer)-1] = '\0';
  }



  // Development work only.   No loging to anything other than syslog for
  // production level code

  /*
     1/17/00 SCM - If we're not a daemon, we need to print something to stderr for
     warnings and errors regardless of development/production.  This is for errors
     that occur during startup.  I'll agree that we don't need to write to a log
     file in production mode, however.
   */

  /*
     Production mode:   Write to stderr if we're not a daemon, and the priority of the message is at least LOG_WARNING
     Development mode:  Write to stderr if we're not a daemon
   */

  if ( ! IsDaemon() ) {
    BOOL WriteNow;

    #ifdef DEV
        WriteNow = TRUE;
    #else
	WriteNow = (pInfo->LogLevel <= LOG_WARNING);
    #endif /* DEV */

    if ( WriteNow ) {
      fprintf(stderr, "%s[%d.%d]: %s\n", pInfo->Descrip, getpid(), (int)pthread_self(), Buffer);
    }

  }



  /* Don't log to a separate log file in production mode */
  #ifdef DEV
  if ( pInfo->Filename != NULL ) {

    FILE *fd;

    if ( (fd = fopen ( pInfo->Filename, "a+" ) ) == NULL ) {
      fprintf(stderr, "PKCS_Log: fopen failed for %s\n", pInfo->Filename);
    } else {
      char buf[32]; /* Specs say 26-character array */

      GetCurrentTimeString( &(buf[0]) );

      /* Date/Time stamp, descrip, Error message */
      fprintf ( fd, "%s %s[%d.%d]: ", buf, pInfo->Descrip, getpid(), pthread_self() );
      fprintf ( fd, "%s\n", Buffer);
      fflush  ( fd );
      fclose  ( fd );
    }

  } /* end if pInfo->Filename */
  #endif /* DEV */



  /* Always log to syslog, if we're using it */
  if ( pInfo->UseSyslog ) {
    syslog(pInfo->LogLevel, "%s", Buffer);
  }

  return TRUE;

}



/****************************************************************************
 *
 *  Would like to have a generic function to which I pass the hLog where I'd
 *  like to do the logging and have a #defined macro which passes it along...
 *
 *  But the preprocessor and variable # args don't work & play well together
 *
 ****************************************************************************/



/*****************************************
 * DbgLog -
 *
 *   Log messages using the debug facility
 *****************************************/

void DbgLog ( u_int32 DebugLevel, char *Format, ... ) {

  va_list ap;

  if ( DebugLevel > SysDebugLevel ) { return; }
  if ( ! LoggingInitialized ) {
    InitLogging();
  }

  va_start( ap, Format );
  PKCS_Log( &hLogDebug, Format, ap);
  va_end ( ap ) ;
  return;

}



/*****************************************
 * ErrLog -
 *
 *   Log Messges using the error facility
 *****************************************/

void ErrLog ( char *Format, ... ) {
  va_list ap;

  if ( ! LoggingInitialized ) {
    InitLogging();
  }
  va_start( ap, Format );
  PKCS_Log( &hLogErr, Format, ap);
  va_end ( ap ) ;
  return;

}

/*****************************************
 * LogLog -
 *
 *   Log messages using the log facility
 *****************************************/
void LogLog ( char *Format, ... ) {
  va_list ap;

  if ( ! LoggingInitialized ) {
    InitLogging();
  }
  va_start( ap, Format );
  PKCS_Log( &hLogLog, Format, ap);
  va_end ( ap ) ;
  return;

}

/*****************************************
 * WarnLog -
 *
 *   Log messages using the warning facility
 *****************************************/
void WarnLog ( char *Format, ... ) {
  va_list ap;

  if ( ! LoggingInitialized ) {
    InitLogging();
  }
  va_start( ap, Format );
  PKCS_Log( &hLogWarn, Format, ap);
  va_end ( ap ) ;
  return;

}

/*****************************************
 * TraceLog -
 *
 *   Log messages using the trace facility
 *****************************************/
void TraceLog ( char *Format, ... ) {
  va_list ap;

  if ( ! LoggingInitialized ) {
    InitLogging();
  }
  va_start( ap, Format );
  PKCS_Log( &hLogTrace, Format, ap);
  va_end ( ap ) ;
  return;

}




/*****************************************
 * InfoLog -
 *
 *   Log messages using the info facility
 *****************************************/

void InfoLog ( char *Format, ... ) {
  va_list ap;

  if ( ! LoggingInitialized ) {
    InitLogging();
  }
  va_start( ap, Format );
  PKCS_Log( &hLogInfo, Format, ap);
  va_end ( ap ) ;
  return;

}



/***********************************************************************
 * InitLogging -
 *
 *   Sets up the various logging facilities.  Must be called before
 *   any of the logging functions can be used.
 ***********************************************************************/

static BOOL InitLogging ( void ) {

  unsigned int i;
  char *s = ProgramName;


  /* if ProgramName is NULL, we'll just print the level... */
  if ( ProgramName == NULL ) {
    s = "";
  }

  /* Set up logging for all the facilities in SystemLogFacilities[] */
  for ( i = 0; i < ( sizeof(SystemLogFacilities) / (sizeof(SystemLogFacilities[0])) ); i++ ) {

    if (! NewLoggingFacility(s, &(SystemLogFacilities[i]) ) ) {
#ifdef DEV
      fprintf(stderr, "InitLogging: NewLoggingFacility failed: %s\n", s);
#endif
      return FALSE;
    }

  } /* end for i */

  atexit(CloseAllLoggingFacilities);
  LoggingInitialized = TRUE;
  return TRUE;

}



/*************************************************************
 * SetDebugLevel -
 *
 *
 *  Sets the level at which debug messages get logged to Val.
 *  Returns the old value
 *************************************************************/

u_int32 SetDebugLevel ( u_int32 Val ) {
  u_int32  OldVal = SysDebugLevel;

  SysDebugLevel = Val;
  return OldVal;
}




/*************************************************************
 * GetDebugLevel
 *
 *   Returns the level at which the program will log debug messages
 *
 *************************************************************/

u_int32 GetDebugLevel ( void ) {
  return SysDebugLevel;
}



#if 0
int main ( int argc, char *argv[], char *envp[] ) {

  ErrLog("This is an error test, attempt 1");
  DbgLog(DEBUG_LEVEL0, "This is a DEBUG test level 0, attempt 1");
  DbgLog(DEBUG_LEVEL1, "This is a DEBUG test level 1, attempt 1");
  SetDebugLevel(DEBUG_NONE);
  DbgLog(DEBUG_LEVEL1, "This is a DEBUG test level 1, attempt 2");
  DbgLog(DEBUG_LEVEL0, "This is a DEBUG test level 0, attempt 2");
  ErrLog("This is an error test, attempt 2");
  return 0;

}
#endif /* 0 */



static BOOL SyslogOpen ( pLoggingFacilityInfo pInfo ) {

  ASSERT(pInfo != NULL);

  if ( !( pInfo->UseSyslog ) ) {
    /* it's not really an error to call SyslogOpen for a facility that doesn't use it */
    return TRUE;
  }

  if ( pInfo->pid != 0 ) {
    /* We've been initialized before, so close the previous instance */
    closelog();
  }

  /* Default to log all messages. */
  setlogmask( LOG_UPTO(LOG_DEBUG));

  /* Mark this as having been set by this process */
  pInfo->pid = getpid();

  return TRUE;

}
