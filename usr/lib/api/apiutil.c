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
#include <pthread.h>

#include <sys/ipc.h>

#include <pkcs11types.h>
#include <apiclient.h>          // Function prototypes for PKCS11
#include <slotmgr.h>
#include <apictl.h>
#include <apiproto.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/file.h>
#include <grp.h>
#include <pwd.h>

static int xplfd = -1;
pthread_rwlock_t xplfd_rwlock = PTHREAD_RWLOCK_INITIALIZER;

#include <libgen.h>

#define LIBLOCATION  LIB_PATH

#if defined(_AIX)
    /* GNU extension, provides a replacement */
    void populate_progname(void);
    extern char *program_invocation_short_name;

    #define SO_LDFLAGS (RTLD_LOCAL | RTLD_LAZY | RTLD_MEMBER)
#else
    #define SO_LDFLAGS (RTLD_LOCAL | RTLD_LAZY)
#endif

extern API_Proc_Struct_t *Anchor;

#include <stdarg.h>
#include "trace.h"
#include "ock_syslog.h"
#include "platform.h"

CK_RV CreateProcLock(void)
{
    if (xplfd == -1) {

        /* The slot mgr daemon should have already created lock,
         * so just open it so we can get a lock...
         */
        xplfd = open(OCK_API_LOCK_FILE, OPEN_MODE);

        if (xplfd == -1) {
            OCK_SYSLOG(LOG_ERR, "C_Initialize: Could not open '%s': %s. "
                       "Possible reasons are that pkcsslotd is not running, "
                       "or that the current user '%s' is not in the '%s' "
                       "group.\n", OCK_API_LOCK_FILE, strerror(errno),
                       cuserid(NULL), PKCS_GROUP);
            return CKR_FUNCTION_FAILED;
        }
    }

    return CKR_OK;
}

CK_RV ProcLock(void)
{
    if (pthread_rwlock_wrlock(&xplfd_rwlock)) {
        TRACE_ERROR("Lock failed.\n");
        return CKR_CANT_LOCK;
    }

    if (xplfd != -1) {
        flock(xplfd, LOCK_EX);
    } else {
        TRACE_DEVEL("No file descriptor to lock with.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

CK_RV ProcUnLock(void)
{
    if (xplfd != -1) {
        flock(xplfd, LOCK_UN);
    } else {
        TRACE_DEVEL("No file descriptor to unlock with.\n");
        return CKR_CANT_LOCK;
    }

    if (pthread_rwlock_unlock(&xplfd_rwlock)) {
        TRACE_ERROR("Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

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

unsigned long AddToSessionList(ST_SESSION_T *pSess)
{
    unsigned long handle;

    handle = bt_node_add(&(Anchor->sess_btree), pSess);

    return handle;
}

void RemoveFromSessionList(CK_SESSION_HANDLE handle)
{
    bt_node_free(&(Anchor->sess_btree), handle, TRUE);
}

struct closeme_arg {
    CK_SLOT_ID slot_id;
    CK_BBOOL in_fork_initializer;
};

/* CloseMe
 *
 * Callback function used to close an individual session for a slot
 */
void CloseMe(STDLL_TokData_t *tokdata, void *node_value,
             unsigned long node_handle, void *arg)
{
    CK_RV rv;
    struct closeme_arg *closeme_arg = (struct closeme_arg *) arg;
    ST_SESSION_T *s = (ST_SESSION_T *) node_value;
    API_Slot_t *sltp;
    STDLL_FcnList_t *fcn;

    UNUSED(tokdata);

    if (s->slotID == closeme_arg->slot_id) {
        /* the single ugliest part about moving to a binary tree: these are the
         * guts of the C_CloseSession function, copied here without tests for
         * validity, since if we're here, they must already have been valid */
        sltp = &(Anchor->SltList[closeme_arg->slot_id]);
        fcn = sltp->FcnList;
        BEGIN_HSM_MK_CHANGE_LOCK(sltp, rv)
        rv = fcn->ST_CloseSession(sltp->TokData, s,
                                  closeme_arg->in_fork_initializer);
        END_HSM_MK_CHANGE_LOCK(sltp, rv)
        if (rv == CKR_OK) {
            decr_sess_counts(closeme_arg->slot_id, s->rw_session);
            bt_node_free(&(Anchor->sess_btree), node_handle, TRUE);
        }
    }
}

/* CloseAllSessions
 *
 * Run through all the nodes in the binary tree and call CloseMe on each one.
 * CloseMe will look at @slot_id and if it matches, will close the session.
 * Once all the nodes are closed, we check to see if the tree is empty and if
 * so, destroy it
 */
void CloseAllSessions(CK_SLOT_ID slot_id, CK_BBOOL in_fork_initializer)
{
    API_Slot_t *sltp = &(Anchor->SltList[slot_id]);
    struct closeme_arg arg;

    arg.slot_id = slot_id;
    arg.in_fork_initializer = in_fork_initializer;

    /* for every node in the API-level session tree, call CloseMe on it */
    bt_for_each_node(sltp->TokData, &(Anchor->sess_btree), CloseMe,
                     (void *)&arg);

}

int Valid_Session(CK_SESSION_HANDLE handle, ST_SESSION_T *rSession)
{
    ST_SESSION_T *tmp;
    int rc;

    tmp = bt_get_node_value(&(Anchor->sess_btree), handle);
    if (tmp) {
        rSession->slotID = tmp->slotID;
        rSession->sessionh = tmp->sessionh;
        rSession->rw_session = tmp->rw_session;
    }
    rc = tmp ? TRUE : FALSE;
    bt_put_node_value(&(Anchor->sess_btree), tmp);
    tmp = NULL;

    return rc;
}

int API_Initialized(void)
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

void get_sess_counts(CK_SLOT_ID slotID, CK_ULONG *ret, CK_ULONG *rw_ret)
{
    Slot_Mgr_Shr_t *shm;

    shm = Anchor->SharedMemP;
    ProcLock();
    *ret = shm->slot_global_sessions[slotID];
    *rw_ret = shm->slot_global_rw_sessions[slotID];
    ProcUnLock();
}

void incr_sess_counts(CK_SLOT_ID slotID, CK_BBOOL rw_session)
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
    if (rw_session)
        shm->slot_global_rw_sessions[slotID]++;

    procp = &shm->proc_table[Anchor->MgrProcIndex];
    procp->slot_session_count[slotID]++;
    if (rw_session)
        procp->slot_rw_session_count[slotID]++;

    ProcUnLock();
}

void decr_sess_counts(CK_SLOT_ID slotID, CK_BBOOL rw_session)
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
    if (rw_session && shm->slot_global_rw_sessions[slotID] > 0) {
        shm->slot_global_rw_sessions[slotID]--;
    }

    procp = &shm->proc_table[Anchor->MgrProcIndex];
    if (procp->slot_session_count[slotID] > 0) {
        procp->slot_session_count[slotID]--;
    }
    if (rw_session && procp->slot_rw_session_count[slotID] > 0) {
        procp->slot_rw_session_count[slotID]--;
    }

    ProcUnLock();
}

uint32_t get_tokspec_count(STDLL_TokData_t *tokdata)
{
    Slot_Mgr_Shr_t *shm;
    uint32_t ret;

    shm = Anchor->SharedMemP;
    if (ProcLock() != CKR_OK)
        return 0;

    ret = shm->slot_global_tokspec_count[tokdata->slot_id];

    ProcUnLock();

    return ret;
}

void incr_tokspec_count(STDLL_TokData_t *tokdata)
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

    shm->slot_global_tokspec_count[tokdata->slot_id]++;

    procp = &shm->proc_table[Anchor->MgrProcIndex];
    procp->slot_tokspec_count[tokdata->slot_id]++;

    ProcUnLock();
}

void decr_tokspec_count(STDLL_TokData_t *tokdata)
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

    if (shm->slot_global_tokspec_count[tokdata->slot_id] > 0)
        shm->slot_global_tokspec_count[tokdata->slot_id]--;

    procp = &shm->proc_table[Anchor->MgrProcIndex];
    if (procp->slot_tokspec_count[tokdata->slot_id] > 0)
        procp->slot_tokspec_count[tokdata->slot_id]--;

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

// Register the process with PKCSSLOTD in the shared memory.
// This call must be made with the API Global Mutex Locked
// and the Anchor control block initialized with the
// shared memory.  No checking for shared memory validity is done
int API_Register(void)
{
    long int reuse = -1, free = -1;
    Slot_Mgr_Shr_t *shm;

#ifdef PKCS64
    Slot_Mgr_Proc_t_64 *procp;
#else
    Slot_Mgr_Proc_t *procp;
#endif

    uint16 indx;

#if defined(_AIX)
    /* populate program_invocation_short_name for later use */
    populate_progname();
#endif

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
            // This should be a VERY rare (if ever) occurrence, given the
            // way AIX deals with re-allocation of PID;s, however if this
            // ever gets ported over to another platform we want to deal
            // with this accordingly since it may re-use pids differently
            // (Linux appears to re-use pids more rapidly).
            if (procp->proc_id == Anchor->ClientCred.real_pid) {
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
    // Since the mutex is held, we don;t have to worry about some other
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
    memset((char *) procp, 0, sizeof(Slot_Mgr_Proc_t_64));
#else
    memset((char *) procp, 0, sizeof(Slot_Mgr_Proc_t));
#endif
    procp->inuse = TRUE;
    procp->proc_id = Anchor->ClientCred.real_pid;
    procp->reg_time = time(NULL);

    Anchor->MgrProcIndex = indx;

    TRACE_DEVEL("API_Register MgrProcIndc %ld (real) pid %d \n",
                (long int) Anchor->MgrProcIndex, procp->proc_id);

    //??? What to do about the Mutex and cond variable
    //Does initializing them in the slotd allow for them to not be
    //initialized in the application.

    ProcUnLock();

    return TRUE;
}

// DeRegister the process with PKCSSLOTD in the shared memory.
// This call must be made with the API Global Mutex Locked
// and the Anchor control block initialized with the
// shared memory.  No checking for shared memory validity is done
void API_UnRegister(void)
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
    memset((char *) procp, 0, sizeof(Slot_Mgr_Proc_t_64));
#else
    memset((char *) procp, 0, sizeof(Slot_Mgr_Proc_t));
#endif

    Anchor->MgrProcIndex = 0;

    //??? What to do about the Mutex and cond variable
    //Does initializing them in the slotd allow for them to not be
    //initialized in the application.

    ProcUnLock();
}

void DL_UnLoad(API_Slot_t *sltp, CK_SLOT_ID slotID, CK_BBOOL inchildforkinit)
{
    Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);
#ifdef PKCS64
    Slot_Info_t_64 *sinfp;
#else
    Slot_Info_t *sinfp;
#endif

    if (sltp->TokData) {
        pthread_rwlock_destroy(&sltp->TokData->sess_list_rwlock);
        pthread_mutex_destroy(&sltp->TokData->login_mutex);
        if (sltp->TokData->hsm_mk_change_supported)
            pthread_rwlock_destroy(&sltp->TokData->hsm_mk_change_rwlock);
        free(sltp->TokData);
        sltp->TokData = NULL;
    }

    sinfp = &(shData->slot_info[slotID]);

    if (sinfp->present == FALSE) {
        return;
    }
    if (!sltp->dlop_p) {
        return;
    }
    if (inchildforkinit)
        return;
    // Call the routine to properly unload the DLL
    DL_Unload(sltp);

    return;
}

int DL_Loaded(char *location, DLL_Load_t *dllload)
{
    int i;

    for (i = 0; i < NUMBER_SLOTS_MANAGED; i++) {
        if (dllload[i].dll_name != NULL) {
            TRACE_DEBUG("DL_LOADED Looking for index %d name %s\n",
                        i, dllload[i].dll_name);
            if (strcmp(location, dllload[i].dll_name) == 0) {
                return i;       // Return the index of the dll
            }
        }
    }

    return -1;                  // Indicate failure to find the dll
}

#ifdef PKCS64
int DL_Load(Slot_Info_t_64 *sinfp, API_Slot_t *sltp, DLL_Load_t *dllload)
#else
int DL_Load(Slot_Info_t *sinfp, API_Slot_t *sltp, DLL_Load_t *dllload)
#endif
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
        return 0;               // Failed to find it..
    }

    dllload[i].dll_name = sinfp->dll_location;  // Point to the location

    dllload[i].dlop_p = dlopen(sinfp->dll_location, SO_LDFLAGS);

    if (dllload[i].dlop_p != NULL) {
        sltp->dlop_p = dllload[i].dlop_p;
        sltp->dll_information = &dllload[i];
        dllload[i].dll_load_count++;;

    } else {
        char *e = dlerror();
        OCK_SYSLOG(LOG_WARNING,
                   "%s: dlopen() failed for [%s]; dlerror = [%s]\n",
                   __func__, sinfp->dll_location, e);
        TRACE_DEVEL("DL_Load of %s failed, dlerror: %s\n",
                    sinfp->dll_location, e);
        sltp->dlop_p = NULL;
        return 0;
    }

    return 1;
}

void DL_Unload(API_Slot_t *sltp)
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

CK_RV check_user_and_group(const char *group)
{
    int i;
    uid_t euid;
    struct passwd *epw;
    struct group *grp;

    if (group == NULL || group[0] == '\0')
        group = PKCS_GROUP;

    /*
     * Check for root user or Group PKCS#11 Membership.
     * Only these are allowed.
     */
    euid = geteuid();

    /* effective Root is ok */
    if (euid == 0)
        return CKR_OK;

    /*
     * Check for member of group. SAB get login seems to not work
     * with some instances of application invocations (particularly
     * when forked). So we need to get the group information.
     * Really need to take the uid and map it to a name.
     */
    grp = getgrnam(group);
    if (grp == NULL) {
        OCK_SYSLOG(LOG_ERR, "C_Initialize: Group '%s' does not exists\n",
                   group);
        goto error;
    }

    if (getegid() == grp->gr_gid)
        return CKR_OK;

    /* Check if effective user is member of the group */
    epw = getpwuid(euid);
    for (i = 0; grp->gr_mem[i]; i++) {
        if ((epw && (strncmp(epw->pw_name, grp->gr_mem[i],
                             strlen(epw->pw_name)) == 0)))
            return CKR_OK;
    }

error:
    TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}

int DL_Load_and_Init(API_Slot_t *sltp, CK_SLOT_ID slotID, policy_t policy,
                     statistics_t statistics)
{
    Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);
#ifdef PKCS64
    Slot_Info_t_64 *sinfp;
#else
    Slot_Info_t *sinfp;
#endif
    CK_RV (*pSTinit)(API_Slot_t *, CK_SLOT_ID, SLOT_INFO *,
                    struct trace_handle_t);
    CK_RV rv;
    int dl_index;
    DLL_Load_t *dllload;

    // Get pointer to shared memory from the anchor block
    //

    sinfp = &(shData->slot_info[slotID]);
    dllload = Anchor->DLLs;     // list of dll's in the system

    if (sinfp->present == FALSE) {
        return FALSE;
    }

    if (sltp->TokData != NULL) {
        TRACE_ERROR("Already initialized.\n");
        return FALSE;
    }

    if (check_user_and_group(sinfp->usergroup) != CKR_OK) {
        TRACE_DEVEL("check_user_and_group failed for slot %lu, token will not "
                    "be available.\n", slotID);

        /* Issue warning message if running in pkcshsm_mk_change tool */
        if (strcmp(program_invocation_short_name, "pkcshsm_mk_change") == 0 &&
            sinfp->usergroup[0] != '\0') {
            warnx("The current user '%s' is not a member of group '%s' used by "
                  "slot %lu.", cuserid(NULL), sinfp->usergroup, slotID);
            warnx("The token in slot %lu will not be available!", slotID);
        }

        return FALSE;
    }

    /*
     * Create separate memory area for each token specific data
     */
    sltp->TokData = (STDLL_TokData_t *) calloc(1, sizeof(STDLL_TokData_t));
    if (!sltp->TokData) {
        TRACE_ERROR("Allocating host memory failed.\n");
        return FALSE;
    }
    sltp->TokData->slot_id = slotID;
    sltp->TokData->real_pid = Anchor->ClientCred.real_pid;
    sltp->TokData->real_uid = Anchor->ClientCred.real_uid;
    sltp->TokData->real_gid = Anchor->ClientCred.real_gid;
    strncpy(sltp->TokData->tokgroup, sinfp->usergroup,
            sizeof(sltp->TokData->tokgroup) - 1);
    sltp->TokData->tokgroup[sizeof(sltp->TokData->tokgroup) - 1] = '\0';
    sltp->TokData->tokspec_counter.get_tokspec_count = get_tokspec_count;
    sltp->TokData->tokspec_counter.incr_tokspec_count = incr_tokspec_count;
    sltp->TokData->tokspec_counter.decr_tokspec_count = decr_tokspec_count;
    sltp->TokData->ro_session_count = 0;
    sltp->TokData->global_login_state = CKS_RO_PUBLIC_SESSION;
    sltp->TokData->spinxplfd = -1;
    sltp->TokData->spinxplfd_count = 0;
    if (pthread_rwlock_init(&sltp->TokData->sess_list_rwlock, NULL) != 0) {
        TRACE_ERROR("Initializing session list lock failed.\n");
        free(sltp->TokData);
        sltp->TokData = NULL;
        return FALSE;
    }
    if (pthread_mutex_init(&sltp->TokData->login_mutex, NULL) != 0) {
        TRACE_ERROR("Initializing login mutex failed.\n");
        free(sltp->TokData);
        sltp->TokData = NULL;
        return FALSE;
    }
    sltp->TokData->policy = policy;
    sltp->TokData->mechtable_funcs = &mechtable_funcs;
    sltp->TokData->statistics = statistics;
    
    if (strlen(sinfp->dll_location) > 0) {
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
        free(sltp->TokData);
        sltp->TokData = NULL;
        return FALSE;
    }

    if (!sltp->dlop_p) {
        TRACE_DEBUG("DL_Load_and_Init pointer NULL\n");
        DL_UnLoad(sltp, slotID, FALSE);
        return FALSE;
    }

    *(void **)(&pSTinit) = dlsym(sltp->dlop_p, "ST_Initialize");
    if (!pSTinit) {
        // Unload the DLL
        DL_UnLoad(sltp, slotID, FALSE);
        return FALSE;
    }
    // Returns true or false
    rv = pSTinit(sltp, slotID, sinfp, trace);
    TRACE_DEBUG("return from STDDLL Init = %lx\n", rv);

    if (rv != CKR_OK) {
        // clean up and unload
        DL_UnLoad(sltp, slotID, FALSE);
        sltp->DLLoaded = FALSE;
        return FALSE;
    } else {
        sltp->DLLoaded = TRUE;
        sinfp->pk_slot.flags |= CKF_TOKEN_PRESENT;
        // Check if a SC_Finalize function has been exported
        *(void **)(&sltp->pSTfini) = dlsym(sltp->dlop_p, "SC_Finalize");
        *(void **)(&sltp->pSTcloseall) =
            dlsym(sltp->dlop_p, "SC_CloseAllSessions");
        return TRUE;
    }

    return TRUE;
}

// copies internal representation of ck_info structure to local process
// representation
void CK_Info_From_Internal(CK_INFO_PTR dest, CK_INFO_PTR_64 src)
{
    dest->cryptokiVersion = src->cryptokiVersion;

    memcpy(dest->manufacturerID, src->manufacturerID,
           sizeof(dest->manufacturerID));

    dest->flags = src->flags;

    memcpy(dest->libraryDescription, src->libraryDescription,
           sizeof(dest->libraryDescription));

    dest->libraryVersion = src->libraryVersion;
}
