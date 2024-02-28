/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef _LOG_H
#define _LOG_H 1

#ifndef FALSE
#define FALSE 0
#endif                          /* FALSE */

#ifndef TRUE
#define TRUE (!(FALSE))
#endif                          /* TRUE */

#ifndef MAX_LOGGING_FACILITIES
#define MAX_LOGGING_FACILITIES   16
#endif                          /* MAX_LOGGING_FACILITIES */

#ifndef TRUNCATE_LOGS_ON_START
#define TRUNCATE_LOGS_ON_START  0
#endif                          /* TRUNCATE_LOGS_ON_START */

/* Use an enum here?  */
#define DEBUG_NONE      (0)
#define DEBUG_LEVEL0    (100)                       /* Less detail */
#define DEBUG_LEVEL1    (DEBUG_LEVEL0 + 100)        /*     .       */
#define DEBUG_LEVEL2    (DEBUG_LEVEL1 + 100)        /*     v       */
#define DEBUG_LEVEL3    (DEBUG_LEVEL2 + 100)        /* More detail */
#define DEBUG_LEVEL4    (DEBUG_LEVEL3 + 100)
#define DEBUG_LEVEL5    (DEBUG_LEVEL4 + 100)

#define DNONE   (DEBUG_NONE)
#define DL0     (DEBUG_LEVEL0)
#define DL1     (DEBUG_LEVEL1)
#define DL2     (DEBUG_LEVEL2)
#define DL3     (DEBUG_LEVEL3)
#define DL4     (DEBUG_LEVEL4)
#define DL5     (DEBUG_LEVEL5)

#ifndef DbgPrint
#define DbgPrint DbgLog
#endif                          /* DbgPrint */

/**************
 * Structures *
 **************/



/************************************************************************
 *  Yes, the structures are somewhat redundant; this is an evolutionary
 *  side-effect.  They should probably be combined into a single struct
 *  - SCM
 ************************************************************************/

#if !defined(_ALL_SOURCE)
typedef unsigned int u_int32;
#endif

typedef u_int32 LogHandle, *pLogHandle;
typedef u_int32 BOOL, bool, BOOLEAN, boolean;

typedef struct _logging_facility_info {
    BOOL Initialized;
    char Descrip[255];
    u_int32 LogOption;
    char *Filename;
    BOOL UseSyslog;
    u_int32 LogLevel;
    pid_t pid;
} LoggingFacilityInfo, *pLoggingFacilityInfo;


typedef struct _LoggingFacility {
    char *Label;
    pLogHandle phLog;
    char *Filename;
    BOOL UseSyslog;
    u_int32 LogLevel;
} LoggingFacility, *pLoggingFacility;


/********************************
 * Exported Function Prototypes *
 ********************************/

void DbgLog(u_int32 DebugLevel, char *Format, ...);
void ErrLog(char *Format, ...);
void LogLog(char *Format, ...);
void WarnLog(char *Format, ...);
void TraceLog(char *Format, ...);
void InfoLog(char *Format, ...);

BOOL PKCS_Log(LogHandle *phLog, char *Format, va_list ap);
BOOL NewLoggingFacility(char *ID, pLoggingFacility pStuff);
BOOL CloseLoggingFacility(LogHandle hLog);
BOOL GetCurrentTimeString(char *Buffer);

u_int32 SetDebugLevel(u_int32 Val);
u_int32 GetDebugLevel(void);

#endif                          /* _LOG_H */
