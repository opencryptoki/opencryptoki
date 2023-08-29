/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

//
//Slot Manager Daemon  Constants...
//
//

#include <stdint.h>
#include <pkcs11types.h>
#include <limits.h>
#include <local_types.h>
#include <pthread.h>
#include <sys/mman.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "local_types.h"

#ifndef _SLOTMGR_H
#define _SLOTMGR_H

#define TOK_PATH  SBIN_PATH "/pkcsslotd"
#define OCK_API_LOCK_FILE LOCKDIR_PATH "/LCK..APIlock"
#define OCK_HSM_MK_CHANGE_PATH CONFIG_PATH "/HSM_MK_CHANGE"
#define OCK_HSM_MK_CHANGE_LOCK_FILE LOCKDIR_PATH "/LCK..HSM_MK_CHANGElock"

#define PROC_SOCKET_FILE_PATH "/run/opencryptoki/pkcsslotd.socket"
#define ADMIN_SOCKET_FILE_PATH "/run/opencryptoki/pkcsslotd.admin.socket"

#define PID_FILE_PATH "/run/opencryptoki/pkcsslotd.pid"
#define OCK_CONFIG OCK_CONFDIR "/opencryptoki.conf"

#ifndef PKCSSLOTD_USER
#error "PKCSSLOTD_USER is not defined"
#endif

#ifndef PKCS_GROUP
#error "PKCS_GROUP is not defined"
#endif

#ifndef CK_BOOL
#define CK_BOOL  CK_BBOOL
#endif                          /* CK_BOOL */

#ifndef TEST_COND_VARS
#define TEST_COND_VARS 0
#endif                          /* TEST_COND_VARS */

#define NUMBER_SLOTS_MANAGED 1024
#define NUMBER_PROCESSES_ALLOWED  1000
#define NUMBER_ADMINS_ALLOWED     1000

//
// Per Process Data structure
// one entry in the table is grabbed by each process
// when it attaches to the shared memory and released
// when the C_Finalize is called.

typedef struct {
    pthread_mutex_t proc_mutex;
    pthread_cond_t proc_slot_cond;

    CK_BOOL inuse;              // flag indicating if the entry is in use
    pid_t proc_id;              /* This could also be used to indicate inuse.
                                 * however we will actualy use it to provide
                                 * a check for a bad process which did not
                                 * C_finalize and remove itself properly.
                                 */
    uint32 slotmap;             /* Bit map of the slots with events App uses
                                 * in the C_WaitForSlotEvent call
                                 */

    uint8 blocking;             /* Flag to use if a thread is blocking on the
                                 * condition variable Used by C_Finalize to
                                 * wake up the
                                 */

    uint8 error;                /* indication of an error causing the thread
                                 * sleeping on the condition variable to wakeup.
                                 */
    uint32 slot_session_count[NUMBER_SLOTS_MANAGED];    /* Per process session
                                                         * count for garbage
                                                         * collection clean up
                                                         * of the global
                                                         * session count.
                                                         */
    time_t reg_time;            // Time application registered
} Slot_Mgr_Proc_t;


// Slot info structure which contains the PKCS11 CK_SLOT_INFO
// as well as the local information
typedef struct {
    CK_SLOT_ID slot_number;
    CK_BOOL present;
    CK_SLOT_INFO pk_slot;
    char dll_location[NAME_MAX + 1];    // location of slot management  DLL
    char slot_init_fcn[NAME_MAX + 1];   /* function to call to initialize the
                                         * token in the slot
                                         */
    LW_SHM_TYPE *shm_addr;      // token specific shm address
} Slot_Info_t;

#define FLAG_EVENT_SUPPORT_DISABLED   0x01
#define FLAG_STATISTICS_ENABLED       0x02
#define FLAG_STATISTICS_IMPLICIT      0x04
#define FLAG_STATISTICS_INTERNAL      0x08

#ifdef PKCS64

/*
 * Constant size types and structures to allow 32-bit daemon to work with
 * 64-bit libraries.
 *
 * Note - ulong long is 8 bytes for both 32-bit and 64-bit applications.
 *
 */

typedef signed long long pid_t_64;
typedef unsigned long long time_t_64;
typedef unsigned long long CK_SLOT_ID_64;
typedef unsigned long long CK_FLAGS_64;

typedef struct CK_INFO_64 {
    CK_VERSION cryptokiVersion; /* Cryptoki interface ver */
    CK_CHAR manufacturerID[32]; /* blank padded */
    CK_CHAR pad1[6];            /* pad for dword alignment */
    CK_FLAGS_64 flags;          /* must be zero */

    /* libraryDescription and libraryVersion are new for v2.0 */
    CK_CHAR libraryDescription[32];     /* blank padded */
    CK_VERSION libraryVersion;  /* version of library */
    CK_CHAR pad2[6];            /* pad for dword alignment */
} CK_INFO_64;

typedef CK_INFO_64 CK_PTR CK_INFO_PTR_64;

typedef struct CK_SLOT_INFO_64 {
    CK_CHAR slotDescription[64];        /* blank padded */
    CK_CHAR manufacturerID[32]; /* blank padded */
    CK_FLAGS_64 flags;

    /* hardwareVersion and firmwareVersion are new for v2.0 */
    CK_VERSION hardwareVersion; /* version of hardware */
    CK_VERSION firmwareVersion; /* version of firmware */
    CK_CHAR pad[4];             /* pad for dword alignment */
} CK_SLOT_INFO_64;


typedef struct Slot_Mgr_Proc_t_64 {
    // pthread_cond_t   proc_slot_cond;

    CK_BOOL inuse;              // flag indicating if the entry is in use
    pid_t proc_id;              /* pid of the process (in pkcsslotd-namespace).
                                 * This could also be used to indicate inuse.
                                 * however we will actualy use it to provide
                                 * a check for a bad process which did not
                                 * C_finalize and remove itself properly.
                                 */
    uint32 slotmap;             /* Bit map of the slots with events App uses
                                 * this in the C_WaitForSlotEvent call
                                 */

    uint8 blocking;             /* Flag to use if a thread is blocking on the
                                 * condition variable Used by C_Finalize to
                                 * wake up the
                                 */

    uint8 error;                /* indication of an error causing the thread
                                 * sleeping on the condition variable to wakeup.
                                 */
    uint32 slot_session_count[NUMBER_SLOTS_MANAGED];    /* Per process session
                                                         * counts for garbage
                                                         * collection clean up
                                                         * of the global
                                                         * session count.
                                                         */
    uint32 slot_rw_session_count[NUMBER_SLOTS_MANAGED];
    uint32 slot_tokspec_count[NUMBER_SLOTS_MANAGED];
    time_t_64 reg_time;         // Time application registered
} Slot_Mgr_Proc_t_64;

//
// Shared Memory Region of Slot information
//

// Slot info structure which contains the PKCS11 CK_SLOT_INFO
// as well as the local information
typedef struct {
    CK_SLOT_ID_64 slot_number;
    CK_BOOL present;
    char pad1[7];               // pad for dword alignment
    CK_SLOT_INFO_64 pk_slot;
    char dll_location[NAME_MAX + 1];    // location of slot's  DLL
    char confname[NAME_MAX + 1];        // token specific config file
    char tokname[NAME_MAX + 1]; // token specific directory
    LW_SHM_TYPE *shm_addr;      // token specific shm address
    uint32_t version; // version: major<<16|minor
} Slot_Info_t_64;

typedef Slot_Info_t_64 SLOT_INFO;

typedef struct {

    /* Information that the API calls will use. */
    uint32 slot_global_sessions[NUMBER_SLOTS_MANAGED];
    uint32 slot_global_rw_sessions[NUMBER_SLOTS_MANAGED];
    uint32 slot_global_tokspec_count[NUMBER_SLOTS_MANAGED];
    Slot_Mgr_Proc_t_64 proc_table[NUMBER_PROCESSES_ALLOWED];
} Slot_Mgr_Shr_t;

typedef struct {
    pid_t real_pid; /* pid of client process in pkcsslotd namespace */
    uid_t real_uid; /* uid of client process in pkcsslotd namespace */
    gid_t real_gid; /* gid of client process in pkcsslotd namespace */
} Slot_Mgr_Client_Cred_t;

typedef struct {
    uint32 num_slots;
    uint8 flags;
    CK_INFO_64 ck_info;
    Slot_Info_t_64 slot_info[NUMBER_SLOTS_MANAGED];
} Slot_Mgr_Socket_t;

#else                           // PKCS64

typedef struct {
    /* Information that the API calls will use. */
    uint32 slot_global_sessions[NUMBER_SLOTS_MANAGED];
    Slot_Mgr_Proc_t proc_table[NUMBER_PROCESSES_ALLOWED];
} Slot_Mgr_Shr_t;

typedef struct {
    pid_t real_pid; /* pid of client process in pkcsslotd namespace */
    uid_t real_uid; /* uid of client process in pkcsslotd namespace */
    gid_t real_gid; /* gid of client process in pkcsslotd namespace */
} Slot_Mgr_Client_Cred_t;

typedef struct {
    uint32 num_slots;
    uint8 flags;
    CK_INFO ck_info;
    Slot_Info_t slot_info[NUMBER_SLOTS_MANAGED];
} Slot_Mgr_Socket_t;

typedef Slot_Info_t SLOT_INFO;

#endif                          // PKCS64


// Loging type constants
//
#define ERROR 1
#define INFO  2


//  Call to populate the shared memory
#define STR "01234567890123456789012345678901"
#define MFG "IBM                             "
#define LIB "openCryptoki                    "

#ifndef CRYPTOKI_API_MAJOR_V
#define CRYPTOKI_API_MAJOR_V 0x3
#endif

#ifndef CRYPTOKI_API_MINOR_V
#define CRYPTOKI_API_MINOR_V 0x0
#endif

#define LIB_MAJOR_V 1
#define LIB_MINOR_V 4

#define RESTART_SYS_CALLS 1

#if defined(__GNUC__) || defined(__clang__)
__attribute__((__format__ (__printf__, 3, 4)))
#endif
static inline int ock_snprintf(char *buf, size_t buflen, const char *fmt, ...)
{
    va_list ap;
    int n;

    va_start(ap, fmt);
    n = vsnprintf(buf, buflen, fmt, ap);
    va_end(ap);

    if (n < 0 || (size_t)n >= buflen)
        return -1;

    return 0;
}


#endif                          /* _SLOTMGR_H */
