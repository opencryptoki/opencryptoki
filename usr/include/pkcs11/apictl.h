 /*
  * COPYRIGHT (c) International Business Machines Corp. 2001-2017
  *
  * This program is provided under the terms of the Common Public License,
  * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
  * software constitutes recipient's acceptance of CPL-1.0 terms which can be
  * found in the file LICENSE file or at
  * https://opensource.org/licenses/cpl1.0.php
  */

#include <pkcs11types.h>
#include <limits.h>
#include <local_types.h>
#include <stdll.h>
#include <slotmgr.h>

#ifndef _APILOCAL_H
#define _APILOCAL_H

// SAB Add a linked list of STDLL's loaded to
// only load and get list once, but let multiple slots us it.

typedef struct{
   CK_BOOL     DLLoaded;    // Flag to indicate if the STDDL has been loaded
   char *dll_name;  // Malloced space to copy the name.
   void *dlop_p;
   int  dll_load_count;
//   STDLL_FcnList_t   *FcnList;  // Function list pointer for the STDLL
} DLL_Load_t;

typedef struct {
   CK_BOOL     DLLoaded;    // Flag to indicate if the STDDL has been loaded
   void        *dlop_p;     // Pointer to the value returned from the DL open
   STDLL_FcnList_t   *FcnList;  // Function list pointer for the STDLL
   STDLL_TokData_t   *TokData;  // Pointer to Token specific data
   DLL_Load_t  *dll_information;
   void            (*pSTfini)();  // Addition of Final function.
   CK_RV           (*pSTcloseall)();  // Addition of close all for leeds code
} API_Slot_t;


// Per process API structure.
// Allocate one per process on the C_Initialize.  This will be
// a global type for the API and will be used through out.
//
typedef struct {
   pid_t    Pid;
   pthread_mutex_t  ProcMutex;      // Mutex for the process level should this be necessary
   key_t             shm_tok;

   struct btree     sess_btree;
   pthread_mutex_t  SessListMutex; /*used to lock around btree accesses */
   void              *SharedMemP;
   Slot_Mgr_Socket_t SocketDataP;
   uint16            MgrProcIndex; // Index into shared memory for This process ctl block
   API_Slot_t        SltList[NUMBER_SLOTS_MANAGED];
   DLL_Load_t        DLLs[NUMBER_SLOTS_MANAGED]; // worst case we have a separate DLL per slot
} API_Proc_Struct_t;

#endif
