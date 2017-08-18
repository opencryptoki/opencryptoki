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


#include <pkcs11types.h>
#include <limits.h>
#include <local_types.h>
#include <pthread.h>

#include <sys/mman.h>

#ifndef _SLOTMGR_H
#define _SLOTMGR_H

#define TOK_PATH  SBIN_PATH "/pkcsslotd"
#define OCK_API_LOCK_FILE LOCKDIR_PATH "/LCK..APIlock"

#define SOCKET_FILE_PATH "/var/run/pkcsslotd.socket"

#define PID_FILE_PATH "/var/run/pkcsslotd.pid"
#define OCK_CONFIG OCK_CONFDIR "/opencryptoki.conf"

#ifndef CK_BOOL
    #define CK_BOOL  CK_BBOOL
#endif /* CK_BOOL */

#ifndef TEST_COND_VARS
    #define TEST_COND_VARS 0
#endif /* TEST_COND_VARS */

#define NUMBER_SLOTS_MANAGED 1024
#define NUMBER_PROCESSES_ALLOWED  1000

//
// Per Process Data structure
// one entry in the table is grabbed by each process
// when it attaches to the shared memory and released
// when the C_Finalize is called.

typedef struct{
   pthread_mutex_t  proc_mutex;
   pthread_cond_t   proc_slot_cond;

   CK_BOOL    inuse;  // flag indicating if the entry is in use
   pid_t    proc_id; // This could also be used to indicate inuse. however
                     // we will actualy use it to provide a check for a bad
                     // process which did not C_finalize and remove itself
                     // properly.
   uint32   slotmap; // Bit map of the slots with events App uses this
                     // in the C_WaitForSlotEvent call

   uint8    blocking;  // Flag to use if a thread is blocking on the condition
                       // variable Used by C_Finalize to wake up the

   uint8    error ;     // indication of an error causing the thread sleeping on the
                        // condition variable to wakeup.
   uint32   slot_session_count[NUMBER_SLOTS_MANAGED];  // Per process session
                        // count for garbage collection clean up of the global
                        // session count.
   time_t   reg_time; // Time application registered
} Slot_Mgr_Proc_t;

//
// Shared Memory Region of Slot information
//
typedef struct _LW_SHM_TYPE LW_SHM_TYPE;

// Slot info structure which contains the PKCS11 CK_SLOT_INFO
// as well as the local information
typedef struct{
   CK_SLOT_ID          slot_number;
   CK_BOOL          present;
   CK_SLOT_INFO  pk_slot;
   char          dll_location[NAME_MAX+1];   // location of slot management  DLL
   char          slot_init_fcn[NAME_MAX+1];  // function to call to initialize the token in the slot
   LW_SHM_TYPE   *shm_addr;                  // token specific shm address
}Slot_Info_t;


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
  CK_VERSION    cryptokiVersion;     /* Cryptoki interface ver */
  CK_CHAR       manufacturerID[32];  /* blank padded */
  CK_CHAR	pad1[6];             /* pad for dword alignment */
  CK_FLAGS_64   flags;               /* must be zero */

  /* libraryDescription and libraryVersion are new for v2.0 */
  CK_CHAR       libraryDescription[32];  /* blank padded */
  CK_VERSION    libraryVersion;          /* version of library */
  CK_CHAR       pad2[6];             /* pad for dword alignment */
} CK_INFO_64;

typedef CK_INFO_64 CK_PTR CK_INFO_PTR_64;

typedef struct CK_SLOT_INFO_64 {
  CK_CHAR       slotDescription[64];  /* blank padded */
  CK_CHAR       manufacturerID[32];   /* blank padded */
  CK_FLAGS_64   flags;

  /* hardwareVersion and firmwareVersion are new for v2.0 */
  CK_VERSION    hardwareVersion;  /* version of hardware */
  CK_VERSION    firmwareVersion;  /* version of firmware */
  CK_CHAR	pad[4];           /* pad for dword alignment */
} CK_SLOT_INFO_64;


typedef struct Slot_Mgr_Proc_t_64 {
  // pthread_cond_t   proc_slot_cond;

   CK_BOOL    inuse;  // flag indicating if the entry is in use
   pid_t      proc_id;// This could also be used to indicate inuse. however
                     // we will actualy use it to provide a check for a bad
                     // process which did not C_finalize and remove itself
                     // properly.
   uint32   slotmap; // Bit map of the slots with events App uses this
                     // in the C_WaitForSlotEvent call

   uint8    blocking;  // Flag to use if a thread is blocking on the condition
                       // variable Used by C_Finalize to wake up the

   uint8    error ;     // indication of an error causing the thread sleeping on the
                        // condition variable to wakeup.
   uint32   slot_session_count[NUMBER_SLOTS_MANAGED];  // Per process session
                        // count for garbage collection clean up of the global
                        // session count.
   time_t_64   reg_time; // Time application registered
} Slot_Mgr_Proc_t_64;

//
// Shared Memory Region of Slot information
//

// Slot info structure which contains the PKCS11 CK_SLOT_INFO
// as well as the local information
typedef struct {
	CK_SLOT_ID_64	slot_number;
	CK_BOOL		present;
	char		pad1[7];		// pad for dword alignment
	CK_SLOT_INFO_64 pk_slot;
	char		dll_location[NAME_MAX+1];   // location of slot's  DLL
	char		confname[NAME_MAX+1];	// token specific config file
	char		tokname[NAME_MAX+1];	// token specific directory
	LW_SHM_TYPE	*shm_addr;		// token specific shm address
}Slot_Info_t_64;

typedef Slot_Info_t_64 SLOT_INFO;

typedef struct {

  /* Information that the API calls will use. */
  uint32                slot_global_sessions[NUMBER_SLOTS_MANAGED];
  Slot_Mgr_Proc_t_64    proc_table[NUMBER_PROCESSES_ALLOWED];
} Slot_Mgr_Shr_t;

typedef struct {
   uint8                 num_slots;
   CK_INFO_64            ck_info;
   Slot_Info_t_64        slot_info[NUMBER_SLOTS_MANAGED];
} Slot_Mgr_Socket_t;

#else	// PKCS64

typedef struct {
  /* Information that the API calls will use. */
  uint32                slot_global_sessions[NUMBER_SLOTS_MANAGED];
  Slot_Mgr_Proc_t       proc_table[NUMBER_PROCESSES_ALLOWED];
} Slot_Mgr_Shr_t;

typedef struct {
  uint8                 num_slots;
  CK_INFO               ck_info;
  Slot_Info_t           slot_info[NUMBER_SLOTS_MANAGED];
} Slot_Mgr_Socket_t;

typedef Slot_Info_t SLOT_INFO;

#endif	// PKCS64


// Loging type constants
//
#define ERROR 1
#define INFO  2


//  Call to populate the shared memory
#define STR "01234567890123456789012345678901"
#define MFG "IBM                             "
#define LIB "Meta PKCS11 LIBRARY             "


#define MAJOR_V   1
#define MINOR_V   2

#ifndef CRYPTOKI_API_MAJOR_V
#define CRYPTOKI_API_MAJOR_V 0x2
#endif

#ifndef CRYPTOKI_API_MINOR_V
#define CRYPTOKI_API_MINOR_V 0x14
#endif

#define LIB_MAJOR_V 1
#define LIB_MINOR_V 4

#define RESTART_SYS_CALLS 1

#endif /* _SLOTMGR_H */
