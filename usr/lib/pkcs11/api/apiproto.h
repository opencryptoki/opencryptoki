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
//  API local internal function prototypes
//
//
//


#ifndef _APIEXT_H
#define _APIEXT_H

#include "apictl.h"

void *attach_shared_memory();
void  detach_shared_memory(char *);


int API_Initialized();
void Terminate_All_Process_Sessions();
int API_Register();
void API_UnRegister();
int DL_Load_and_Init(API_Slot_t *, CK_SLOT_ID);


CK_RV CreateProcLock();
CK_RV ProcLock(void);
CK_RV ProcUnLock(void);
CK_RV ProcClose(void);

void _init(void);
void get_sess_count(CK_SLOT_ID, CK_ULONG *);
void incr_sess_counts(CK_SLOT_ID);
void decr_sess_counts(CK_SLOT_ID);
unsigned long AddToSessionList(ST_SESSION_T *);
void RemoveFromSessionList(CK_SESSION_HANDLE);
int Valid_Session(CK_SESSION_HANDLE, ST_SESSION_T *);
void DL_UnLoad( API_Slot_t  *, CK_SLOT_ID);
void DL_Unload(API_Slot_t  *);

void CK_Info_From_Internal (CK_INFO_PTR dest, CK_INFO_PTR_64 src);

int sessions_exist(CK_SLOT_ID);

void CloseAllSessions(CK_SLOT_ID slot_id);
int init_socket_data();

#define OCK_SYSLOG(priority, fmt, ...) \
        syslog(priority, "%s " fmt, __FILE__, ##__VA_ARGS__);

#endif
