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
#include <defs.h>

#ifndef _APILOCAL_H
#define _APILOCAL_H

#if OPENSSL_VERSION_PREREQ(3, 0)
    #include <openssl/crypto.h>
    #include <openssl/provider.h>
#endif

#define BEGIN_HSM_MK_CHANGE_LOCK(sltp, rv)                                  \
        do {                                                                \
            if ((sltp)->TokData->hsm_mk_change_supported) {                 \
                if (pthread_rwlock_rdlock(                                  \
                            &(sltp)->TokData->hsm_mk_change_rwlock) != 0) { \
                    TRACE_DEVEL("HSM-MK-change Read-Lock failed.\n");       \
                    (rv) = CKR_CANT_LOCK;                                   \
                    break;                                                  \
                }                                                           \
            }

#define END_HSM_MK_CHANGE_LOCK(sltp, rv)                                    \
            if ((sltp)->TokData->hsm_mk_change_supported) {                 \
                if (pthread_rwlock_unlock(                                  \
                            &(sltp)->TokData->hsm_mk_change_rwlock) != 0) { \
                    TRACE_DEVEL("HSM-MK-change Unlock failed.\n");          \
                    if ((rv) == CKR_OK)                                     \
                        (rv) = CKR_CANT_LOCK;                               \
                    break;                                                  \
                }                                                           \
            }                                                               \
        } while (0);

// SAB Add a linked list of STDLL's loaded to
// only load and get list once, but let multiple slots us it.

typedef struct {
    CK_BOOL DLLoaded;           // Flag to indicate if the STDDL has been loaded
    char *dll_name;             // Malloced space to copy the name.
    void *dlop_p;
    int dll_load_count;
//   STDLL_FcnList_t   *FcnList;  // Function list pointer for the STDLL
} DLL_Load_t;

struct API_Slot {
    CK_BOOL DLLoaded;           // Flag to indicate if the STDDL has been loaded
    void *dlop_p;              // Pointer to the value returned from the DL open
    STDLL_FcnList_t *FcnList;   // Function list pointer for the STDLL
    STDLL_TokData_t *TokData;   // Pointer to Token specific data
    DLL_Load_t *dll_information;
    CK_RV (*pSTfini)(STDLL_TokData_t *, CK_SLOT_ID, SLOT_INFO *,
                     struct trace_handle_t *, CK_BBOOL);
    CK_RV(*pSTcloseall)(STDLL_TokData_t *, CK_SLOT_ID);
};


// Per process API structure.
// Allocate one per process on the C_Initialize.  This will be
// a global type for the API and will be used through out.
//
typedef struct {
    key_t shm_tok;

    struct btree sess_btree;
    void *SharedMemP;
    Slot_Mgr_Socket_t SocketDataP;
    Slot_Mgr_Client_Cred_t ClientCred;
    uint16 MgrProcIndex;  // Index into shared memory for This process ctl block
    API_Slot_t SltList[NUMBER_SLOTS_MANAGED];
    DLL_Load_t DLLs[NUMBER_SLOTS_MANAGED];  // worst case we have a separate DLL
                                            // per slot
    int socketfd;
    pthread_t event_thread;
#if OPENSSL_VERSION_PREREQ(3, 0)
    OSSL_LIB_CTX *openssl_libctx;
    OSSL_PROVIDER *openssl_default_provider;
    OSSL_PROVIDER *openssl_legacy_provider;
#endif
} API_Proc_Struct_t;

#endif
