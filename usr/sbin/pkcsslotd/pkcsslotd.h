/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/***********************************************************************
 *
 *  Slot Manager Daemon header file
 *
 ***********************************************************************/

#ifndef _PKCSSLOTMGR_H
#define _PKCSSLOTMGR_H  1

#include <configparser.h>

/***********
 * Defines *
 ***********/

#define UNUSED(var)            ((void)(var))

#ifdef DEV
#ifndef BECOME_DAEMON
#define BECOME_DAEMON   FALSE
#endif                          /* BECOME_DAEMON */

#ifndef DEFAULT_LOG_FILE
#define DEFAULT_LOG_FILE    (TOK_PATH ".log")
#endif                          /* DEFAULT_LOG_FILE */

#ifndef DEFAULT_DEBUG_LEVEL
#define DEFAULT_DEBUG_LEVEL DEBUG_LEVEL0
#endif                          /* DEFAULT_DEBUG_LEVEL */

#else                           /* DEV not defined */
#define BECOME_DAEMON          TRUE
#define DEFAULT_DEBUG_LEVEL    DEBUG_NONE

#endif                          /* DEV */

#define HASH_SHA1   1
#define HASH_MD5    2
#define compute_md5(a,b,c)      compute_hash(HASH_MD5,b,a,c)

int compute_hash(int hash_type, int buf_size, char *buf, char *digest);

/********************
 * Global Variables *
 ********************/

extern Slot_Mgr_Shr_t *shmp;    // pointer to the shared memory region.
extern int shmid;
extern key_t tok;

extern Slot_Info_t_64 sinfo[NUMBER_SLOTS_MANAGED];
extern unsigned int NumberSlotsInDB;

extern int socketfd;
extern Slot_Mgr_Socket_t socketData;


/***********************
 * Function Prototypes *
 ***********************/

BOOL IsDaemon(void);
BOOL StopGCThread(void *Ptr);
BOOL StartGCThread(Slot_Mgr_Shr_t *MemPtr);
BOOL CheckForGarbage(Slot_Mgr_Shr_t *MemPtr);
int InitializeMutexes(void);
int DestroyMutexes(void);
int CreateSharedMemory(void);
int AttachToSharedMemory(void);
int InitSharedMemory(Slot_Mgr_Shr_t *sp);
void DetachFromSharedMemory(void);
void DestroySharedMemory(void);
int SetupSignalHandlers(void);
void slotdGenericSignalHandler(int Signal);
void PopulateCKInfo(CK_INFO_PTR_64 ckinf);
void PopulateSlotInfo(Slot_Info_t_64 *slot_info, unsigned int *processed);

int XProcLock(void);
int XProcUnLock(void);
int CreateXProcLock(void);

int CreateListenerSocket(void);
int InitSocketData(Slot_Mgr_Socket_t *sp);
int SocketConnectionHandler(int socketfd, int timeout_secs);
void DetachSocketListener(int socketfd);

#endif                          /* _SLOTMGR_H */
