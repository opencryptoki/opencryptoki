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
//
//AIX Pkcs11 Api Utility functions
//

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <alloca.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/syslog.h>

#include <sys/ipc.h>

#include <pkcs11types.h>
#include <apiclient.h>		// Function prototypes for PKCS11
#include <slotmgr.h>
#include <apictl.h>
#include <apiproto.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>

static int xplfd = -1;

#include <libgen.h>

#define LIBLOCATION  LIB_PATH

extern API_Proc_Struct_t *Anchor;

#include <stdarg.h>
#include "trace.h"

CK_RV CreateProcLock(void)
{
	struct stat statbuf;

	if (xplfd == -1) {

		/* The slot mgr daemon should have already created lock,
		 * so just open it so we can get a lock...
		 */
		if (stat(OCK_API_LOCK_FILE, &statbuf) == 0)
			xplfd = open(OCK_API_LOCK_FILE, O_RDONLY);

		if (xplfd == -1) {
			OCK_SYSLOG(LOG_ERR, "Could not open %s\n",
				   OCK_API_LOCK_FILE);
			return CKR_FUNCTION_FAILED;
		}
	}

	return CKR_OK;
}

CK_RV ProcLock(void)
{
	if (xplfd != -1)
		flock(xplfd, LOCK_EX);
	else
		TRACE_DEVEL("No file descriptor to lock with.\n");

	return CKR_OK;
}

CK_RV ProcUnLock(void)
{
	if (xplfd != -1)
		flock(xplfd, LOCK_UN);
	else
		TRACE_DEVEL("No file descriptor to unlock with.\n");

	return CKR_OK;
}

CK_RV ProcClose(void)
{
	if (xplfd != -1)
		close(xplfd);
	else
		TRACE_DEVEL("ProcClose: No file descriptor open to close.\n");

	return CKR_OK;
}

unsigned long AddToSessionList(ST_SESSION_T * pSess)
{
	unsigned long handle;

	handle = bt_node_add(&(Anchor->sess_btree), pSess);

	return handle;
}

void RemoveFromSessionList(CK_SESSION_HANDLE handle)
{
	bt_node_free(&(Anchor->sess_btree), handle, free);
}

/* CloseMe
 *
 * Callback function used to close an individual session for a slot
 */
void CloseMe(STDLL_TokData_t *tokdata, void *node_value, unsigned long node_handle, void *arg)
{
	CK_RV rv;
	CK_SLOT_ID slot_id = *(CK_SLOT_ID *) arg;
	ST_SESSION_T *s = (ST_SESSION_T *) node_value;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;

	if (s->slotID == slot_id) {
		/* the single ugliest part about moving to a binary tree: these are the guts of
		 * the C_CloseSession function, copied here without tests for validity, since if we're
		 * here, they must already have been valid */
		sltp = &(Anchor->SltList[slot_id]);
		fcn = sltp->FcnList;
		rv = fcn->ST_CloseSession(sltp->TokData, s);
		if (rv == CKR_OK) {
			decr_sess_counts(slot_id);
			bt_node_free(&(Anchor->sess_btree), node_handle, free);
		}
	}
}

/* CloseAllSessions
 *
 * Run through all the nodes in the binary tree and call CloseMe on each one. CloseMe will look at
 * @slot_id and if it matches, will close the session. Once all the nodes are closed, we check
 * to see if the tree is empty and if so, destroy it
 */
void CloseAllSessions(CK_SLOT_ID slot_id)
{
	API_Slot_t *sltp = &(Anchor->SltList[slot_id]);

	/* for every node in the API-level session tree, call CloseMe on it */
	bt_for_each_node(sltp->TokData, &(Anchor->sess_btree), CloseMe,
			 (void *)&slot_id);

	if (bt_is_empty(&(Anchor->sess_btree)))
		bt_destroy(&(Anchor->sess_btree), NULL);
}

int Valid_Session(CK_SESSION_HANDLE handle, ST_SESSION_T * rSession)
{
	ST_SESSION_T *tmp;

	tmp = bt_get_node_value(&(Anchor->sess_btree), handle);
	if (tmp) {
		rSession->slotID = tmp->slotID;
		rSession->sessionh = tmp->sessionh;
	}

	return (tmp ? TRUE : FALSE);
}

int API_Initialized()
{

	if (Anchor == NULL)
		return FALSE;

	return TRUE;
}

int slot_present(CK_SLOT_ID id)
{
	Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);
#ifdef PKCS64
	Slot_Info_t_64 *sinfp;
#else
	Slot_Info_t *sinfp;
#endif

	sinfp = &(shData->slot_info[id]);
	if (sinfp->present == FALSE) {
		return FALSE;
	}

	return TRUE;

}

void get_sess_count(CK_SLOT_ID slotID, CK_ULONG * ret)
{
	Slot_Mgr_Shr_t *shm;

	shm = Anchor->SharedMemP;
	ProcLock();
	*ret = shm->slot_global_sessions[slotID];
	ProcUnLock();
}

void incr_sess_counts(CK_SLOT_ID slotID)
{
	Slot_Mgr_Shr_t *shm;
#ifdef PKCS64
	Slot_Mgr_Proc_t_64 *procp;
#else
	Slot_Mgr_Proc_t *procp;
#endif

	// Get the slot mutex
	shm = Anchor->SharedMemP;

	ProcLock();

	shm->slot_global_sessions[slotID]++;

	procp = &shm->proc_table[Anchor->MgrProcIndex];
	procp->slot_session_count[slotID]++;

	ProcUnLock();

}

void decr_sess_counts(CK_SLOT_ID slotID)
{
	Slot_Mgr_Shr_t *shm;
#ifdef PKCS64
	Slot_Mgr_Proc_t_64 *procp;
#else
	Slot_Mgr_Proc_t *procp;
#endif

	// Get the slot mutex
	shm = Anchor->SharedMemP;

	ProcLock();

	if (shm->slot_global_sessions[slotID] > 0) {
		shm->slot_global_sessions[slotID]--;
	}

	procp = &shm->proc_table[Anchor->MgrProcIndex];
	if (procp->slot_session_count[slotID] > 0) {
		procp->slot_session_count[slotID]++;
	}

	ProcUnLock();

}

// Check if any sessions from other applicaitons exist on this particular
// token.... This will also validate our own sessions as well.
// There might be an issue with the fact that a session is created but the
// number is not incremented until the session allocation is completed by
// the token.  The API may need to lock the shared memory prior to creating
// the session and then unlock when the stdll has completed its work.
// Closing sessions should probably behave the same way.
int sessions_exist(CK_SLOT_ID slotID)
{
	Slot_Mgr_Shr_t *shm;
	uint32 numSessions;

	// Get the slot mutex
	shm = Anchor->SharedMemP;

	ProcLock();
        numSessions = shm->slot_global_sessions[slotID];
	ProcUnLock();

	return numSessions != 0;
}

// Terminates all sessions associated with a given process
// this cleans up any lingering sessions with the process
// and does not
//
// It is only called from the C_Finalize routine
void Terminate_All_Process_Sessions()
{
	CK_SLOT_ID id;
	CK_RV rv;

	TRACE_DEBUG("Terminate_All_Process_Sessions\n");
	for (id = 0; id < NUMBER_SLOTS_MANAGED; id++) {
		// Check if the slot is present in the slot manager
		// if not just skip it...
		if (slot_present(id) == TRUE) {
			rv = C_CloseAllSessions(id);
		} else {
			continue;
		}
		// If the return code is not OK, we are really hosed
		// since we are terminating the session.
		// For now we will just log it
		if (rv != CKR_OK) {
			TRACE_DEBUG("Terminate_All_Process_Sessions RV %lx\n",
				      rv);
		}
	}

}

// Register the process with PKCSSLOTD in the
// shared memory.
// This call must be made with the API Global Mutex Locked
// and the Anchor control block initialized with the
// shared memory.  No checking for shared memory validity is done
int API_Register()
{

	long int reuse = -1, free = -1;
	Slot_Mgr_Shr_t *shm;

#ifdef PKCS64
	Slot_Mgr_Proc_t_64 *procp;
#else
	Slot_Mgr_Proc_t *procp;
#endif

	uint16 indx;

	// Grab the Shared Memory lock to prevent other updates to the
	// SHM Process
	// The registration is done to allow for future handling of
	// the Slot Event List.  Which is maintained by the Slotd.

	shm = Anchor->SharedMemP;

	ProcLock();

	procp = shm->proc_table;
	for (indx = 0; indx < NUMBER_PROCESSES_ALLOWED; indx++, procp++) {
		// Is the entry in use

		if (procp->inuse == TRUE) {
			// Handle the weird case of the process terminating without
			// un-registering, and restarting with exactly the same PID
			// before the slot manager garbage collection can performed.
			// To eliminate the race condition between garbage collection
			// the lock should protect us.
			// This should be a VERY rare (if ever) occurance, given the
			// way AIX deals with re-allocation of PID;s, however if this
			// ever gets ported over to another platform we want to deal
			// with this accordingly since it may re-use pids differently
			// (Linux appears to re-use pids more rapidly).
			if (procp->proc_id == getpid()) {
				if (reuse == -1) {
					reuse = indx;
				}
			}
		} else {
			//Already found the first free
			if (free == -1) {
				free = indx;
			}
		}
	}

	// If we did not find a free entry then we fail the routine
	if ((reuse == -1) && (free == -1)) {
		ProcUnLock();
		return FALSE;
	}
	// check if we are reusing a control block or taking the first free.
	// Since th mutex is helt, we don;t have to worry about some other
	// process grabbing the slot...  Garbage collection from
	// the slotd should not affect this since it will grab the mutex
	// before doing its thing.
	if (reuse != -1) {
		procp = &(shm->proc_table[reuse]);
		indx = reuse;
	} else {
		procp = &(shm->proc_table[free]);
		indx = free;
	}

#ifdef PKCS64
	memset((char *)procp, 0, sizeof(Slot_Mgr_Proc_t_64));
#else
	memset((char *)procp, 0, sizeof(Slot_Mgr_Proc_t));
#endif
	procp->inuse = TRUE;
	procp->proc_id = getpid();
	procp->reg_time = time(NULL);

	Anchor->MgrProcIndex = indx;

	TRACE_DEVEL("API_Register MgrProcIndc %d  pid %ld \n", procp->proc_id,
		      (long int)Anchor->MgrProcIndex);

	//??? What to do about the Mutex and cond variable
	//Does initializing them in the slotd allow for them to not be
	//initialized in the application.

	ProcUnLock();

	return TRUE;
}

// DeRegister the process with PKCSSLOTD in the
// shared memory.
// This call must be made with the API Global Mutex Locked
// and the Anchor control block initialized with the
// shared memory.  No checking for shared memory validity is done
void API_UnRegister()
{

	Slot_Mgr_Shr_t *shm;

#ifdef PKCS64
	Slot_Mgr_Proc_t_64 *procp;
#else
	Slot_Mgr_Proc_t *procp;
#endif

	// Grab the Shared Memory lock to prevent other updates to the
	// SHM Process
	// The registration is done to allow for future handling of
	// the Slot Event List.  Which is maintained by the Slotd.

	shm = Anchor->SharedMemP;

	ProcLock();

	procp = &(shm->proc_table[Anchor->MgrProcIndex]);

#ifdef PKCS64
	memset((char *)procp, 0, sizeof(Slot_Mgr_Proc_t_64));
#else
	memset((char *)procp, 0, sizeof(Slot_Mgr_Proc_t));
#endif

	Anchor->MgrProcIndex = 0;

	//??? What to do about the Mutex and cond variable
	//Does initializing them in the slotd allow for them to not be
	//initialized in the application.

	ProcUnLock();

}

void DL_UnLoad(API_Slot_t *sltp, CK_SLOT_ID slotID)
{
	Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);
#ifdef PKCS64
	Slot_Info_t_64 *sinfp;
#else
	Slot_Info_t *sinfp;
#endif

	sinfp = &(shData->slot_info[slotID]);

	if (sinfp->present == FALSE) {
		return;
	}
	if (!sltp->dlop_p) {
		return;
	}
	// Call the routine to properly unload the DLL
	DL_Unload(sltp);

	return;

}

int DL_Loaded(location, dllload)
char *location;
DLL_Load_t *dllload;
{
	int i;

	for (i = 0; i < NUMBER_SLOTS_MANAGED; i++) {
		if (dllload[i].dll_name != NULL) {
			TRACE_DEBUG("DL_LOADED Looking for index %d name %s\n",
				     i, dllload[i].dll_name);
			if (strcmp(location, dllload[i].dll_name) == 0) {
				return i;	// Return the index of the dll
			}
		}
	}
	return -1;		// Indicate failure to find the dll
}

int DL_Load(sinfp, sltp, dllload)
#ifdef PKCS64
Slot_Info_t_64 *sinfp;
#else
Slot_Info_t *sinfp;
#endif

API_Slot_t *sltp;
DLL_Load_t *dllload;
{
	int i;

	TRACE_DEBUG("DL_LOAD\n");
	for (i = 0; i < NUMBER_SLOTS_MANAGED; i++) {
		if (dllload[i].dll_name == NULL) {
			TRACE_DEBUG("Empty slot at %d \n", i);
			break;
		}
	}
	if (i == NUMBER_SLOTS_MANAGED) {
		TRACE_DEBUG("No empty slots.\n");
		return 0;	// Failed to find it..
	}

	dllload[i].dll_name = sinfp->dll_location;	// Point to the location

	dllload[i].dlop_p =
	    dlopen(sinfp->dll_location, (RTLD_GLOBAL | RTLD_LAZY));

	if (dllload[i].dlop_p != NULL) {
		sltp->dlop_p = dllload[i].dlop_p;
		sltp->dll_information = &dllload[i];
		dllload[i].dll_load_count++;;

	} else {
		char *e = dlerror();
		OCK_SYSLOG(LOG_WARNING,
			   "%s: dlopen() failed for [%s]; dlerror = [%s]\n",
			   __FUNCTION__, sinfp->dll_location, e);
		TRACE_DEVEL("DL_Load of %s failed, dlerror: %s\n",
			      sinfp->dll_location, e);
		sltp->dlop_p = NULL;
		return 0;
	}
	return 1;

}

void DL_Unload(sltp)
API_Slot_t *sltp;
{
	DLL_Load_t *dllload;

	// Decrement the count of loads.  When 0 then unload this thing;
	//
	dllload = sltp->dll_information;
	dllload->dll_load_count--;
	if (dllload->dll_load_count == 0) {
		dlclose(dllload->dlop_p);
		dllload->dll_name = NULL;
	}
	// Clear out the slot information
	sltp->DLLoaded = FALSE;
	sltp->dlop_p = NULL;
	sltp->pSTfini = NULL;
	sltp->pSTcloseall = NULL;

}

int DL_Load_and_Init(API_Slot_t *sltp, CK_SLOT_ID slotID)
{
	Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);
#ifdef PKCS64
	Slot_Info_t_64 *sinfp;
#else
	Slot_Info_t *sinfp;
#endif

	int (*pSTinit) ();
	void (*pSTfini) ();
	CK_RV rv;
	int dll_len, dl_index;
	DLL_Load_t *dllload;

	// Get pointer to shared memory from the anchor block
	//

	sinfp = &(shData->slot_info[slotID]);
	dllload = Anchor->DLLs;	// list of dll's in the system

	if (sinfp->present == FALSE) {
		return FALSE;
	}

	if ((dll_len = strlen(sinfp->dll_location))) {
		// Check if this DLL has been loaded already.. If so, just increment
		// the counter in the dllload structure and copy the data to
		// the slot pointer.
		if ((dl_index = DL_Loaded(sinfp->dll_location, dllload)) != -1) {
			dllload[dl_index].dll_load_count++;
			sltp->dll_information = &dllload[dl_index];
			sltp->dlop_p = dllload[dl_index].dlop_p;
		} else {
			TRACE_DEBUG("DL_Load_and_Init dll_location %s\n",
				      sinfp->dll_location);
			DL_Load(sinfp, sltp, dllload);
		}
	} else {
		return FALSE;
	}

	if (!sltp->dlop_p) {
		TRACE_DEBUG("DL_Load_and_Init pointer %p\n", sltp->dlop_p);

		return FALSE;
	}

	pSTinit = (int (*)())dlsym(sltp->dlop_p, "ST_Initialize");
	if (!pSTinit) {
		// Unload the DLL
		DL_Unload(sltp);
		return FALSE;
	}
	// Returns true or false
	rv = pSTinit(sltp, slotID, sinfp, trace);
	TRACE_DEBUG("return from STDDLL Init = %lx\n", rv);

	if (rv != CKR_OK) {
		// clean up and unload
		DL_Unload(sltp);
		sltp->DLLoaded = FALSE;
		return FALSE;
	} else {
		sltp->DLLoaded = TRUE;
		// Check if a SC_Finalize function has been exported
		pSTfini = (void (*)())dlsym(sltp->dlop_p, "SC_Finalize");
		sltp->pSTfini = pSTfini;

		sltp->pSTcloseall =
		    (CK_RV(*)())dlsym(sltp->dlop_p, "SC_CloseAllSessions");
		return TRUE;
	}

	return TRUE;

}

// copies internal representation of ck_info structure to local process
// representation
void
CK_Info_From_Internal (CK_INFO_PTR dest, CK_INFO_PTR_64 src)
{
	memset(dest, 0, sizeof(*dest));

	dest->cryptokiVersion = src->cryptokiVersion;
	memset(dest->manufacturerID, '\0', 32);
	memcpy(dest->manufacturerID, src->manufacturerID, 32);
	dest->flags = src->flags;
	memcpy(dest->libraryDescription, src->libraryDescription, 32);
	dest->libraryVersion = src->libraryVersion;
}
