/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#if NGPTH
#include <pth.h>
#else
#include <pthread.h>
#endif

#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <sys/types.h>
#include <stdio.h>
#include <syslog.h>

#include <stdlib.h>
#include <stdint.h>

#include <errno.h>

#include <apiclient.h>
#include <slotmgr.h>
#include <stdll.h>
#include <apictl.h>

#include <apiproto.h>
#include "trace.h"

void api_init();

// NOTES:
// In many cases the specificaiton does not allow returns
// of CKR_ARGUMENTSB_BAD.  We break the spec, since validation of parameters
// to the function are best represented by this return code (where
// specific RC's such as CKR_INVALID_SESSION do not exist).
// NOTE NOTE NOTE NOTE
//    The parameter checking on the update operations may need to be
//    modified (as well as the encrypt/decrypt) to call the stdll
//    anyway with sanatized parameters since on error, the encrypt/decrypt
//    sign operations are all supposed to complete.
//    Therefor the parameter checking here might need to be done in
//    the STDLL instead of the API.
//    This would affect ALL the Multipart operations which have
//    an init followed by one or more operations.

// Globals for the API

API_Proc_Struct_t *Anchor = NULL;	// Initialized to NULL
unsigned int Initialized = 0;	// Initialized flag
pthread_mutex_t GlobMutex;	// Global Mutex
CK_FUNCTION_LIST FuncList;

int slot_loaded[NUMBER_SLOTS_MANAGED];	// Array of flags to indicate
				       // if the STDLL loaded

// For linux only at this time... if it works out we can get rid
// of the stupid pid tracking.... Linux we kind of have to do this
// since new threads are processes also, and we will be hosed
void child_fork_initializer()
{
	if (Anchor) {
		free(Anchor);
		Anchor = NULL;
	}
}

//------------------------------------------------------------------------
// API function C_CancelFunction
//------------------------------------------------------------------------
// This is a legacy function and performs no operations per the
// specification.
CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession)
{
	TRACE_INFO("C_CancelFunction\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR( "%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_PARALLEL));
	return CKR_FUNCTION_NOT_PARALLEL;   // PER PKCS#11v2.20,Sec 11.16
}

//------------------------------------------------------------------------
// API function C_CloseAllSessions
//------------------------------------------------------------------------
//  Netscape Required
//
//   This is a special one since the API can do this by removing
//   all active sessions on the slot... The STDLL does not have to implement
//   this.  however this function will fail if any Session removal fails
//   in the walk.  Which could lead to undetermined results.
//
//------------------------------------------------------------------------

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID)
{
	// Although why does modutil do a close all sessions.  It is a single
	// application it can only close its sessions...
	// And all sessions should be closed anyhow.

	TRACE_INFO("CloseAllSessions\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (slotID >= NUMBER_SLOTS_MANAGED) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		return CKR_SLOT_ID_INVALID;
	}

	/* for every node in the API-level session tree, if the session's slot matches slotID,
	 * close it */
	CloseAllSessions(slotID);

	return CKR_OK;

}				// end of C_CloseAllSessions

//------------------------------------------------------------------------
// API function C_CloseSession
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_CloseSession\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!Valid_Session(hSession, &rSession)) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
		return CKR_SESSION_HANDLE_INVALID;
	}
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_CloseSession) {
		// Map the Session to the slot session
		rv = fcn->ST_CloseSession(sltp->TokData, &rSession);
		TRACE_DEVEL("Called STDLL rv = 0x%lx\n", rv);
		//  If the STDLL successfully closed the session
		//  we can free it.. Otherwise we will have to leave it
		//  lying arround.
		if (rv == CKR_OK) {
			RemoveFromSessionList(hSession);
			// Need to decrement the global slot session count as well
			// as the per process slot session count to allow for
			// proper tracking of the number of sessions on a slot.
			// This allows things like InitToken to properly work in case
			// other applications have the token active.
			decr_sess_counts(rSession.slotID);
		} else
			TRACE_DEVEL("fcn->ST_CloseSession failed:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_CloseSession

//------------------------------------------------------------------------
// API function C_CopyObject
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_CopyObject(CK_SESSION_HANDLE hSession,
	     CK_OBJECT_HANDLE hObject,
	     CK_ATTRIBUTE_PTR pTemplate,
	     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_CopyObject\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!Valid_Session(hSession, &rSession)) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
		return CKR_SESSION_HANDLE_INVALID;
	}
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	if (!phNewObject) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
	// null template with a count... will cause the lower layer
	// to have problems
	// Template with 0 count is not a problem.  we can let
	// the STDLL handle that...
	if (!pTemplate && ulCount) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_CopyObject) {
		// Map the Session to the slot session
		rv = fcn->ST_CopyObject(sltp->TokData, &rSession, hObject,
					pTemplate, ulCount, phNewObject);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_CopyObject

//------------------------------------------------------------------------
// API function C_CreateObject
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_CreateObject(CK_SESSION_HANDLE hSession,
	       CK_ATTRIBUTE_PTR pTemplate,
	       CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_CreateObject\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	// Null template is invalid...    An object needs a minimal
	// template for creation.
	if (!pTemplate) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}
	// A 0 count for the template is bad
	if (ulCount == 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}

	// A Null pointer to return the handle in is also bad
	// since we could de-reference incorrectly.
	if (!phObject) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_CreateObject) {
		// Map the Session to the slot session
		rv = fcn->ST_CreateObject(sltp->TokData, &rSession, pTemplate,
					  ulCount, phObject);
		TRACE_DEVEL("fcn->ST_CreateObject returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_CreateObject

//------------------------------------------------------------------------
// API function C_Decrypt
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------
CK_RV
C_Decrypt(CK_SESSION_HANDLE hSession,
	  CK_BYTE_PTR pEncryptedData,
	  CK_ULONG ulEncryptedDataLen,
	  CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_Decrypt\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	// Null encrypted data is invalid, null pData buffer is invalid
	// as is null location to put the response into.
	if (!pEncryptedData || !pulDataLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_Decrypt) {
		// Map the Session to the slot session
		rv = fcn->ST_Decrypt(sltp->TokData, &rSession, pEncryptedData,
				     ulEncryptedDataLen, pData, pulDataLen);
		TRACE_DEVEL("fcn->ST_Decrypt returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_Decrypt

//------------------------------------------------------------------------
// API function C_DecryptDigestUpdate
//------------------------------------------------------------------------
//  Netscape Required

CK_RV
C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen,
		      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DecryptDigestUpdate\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	// This may have to go to the STDLL for validation
	if (!pEncryptedPart || !pulPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DecryptDigestUpdate) {
		// Map the Session to the slot session
		rv = fcn->ST_DecryptDigestUpdate(sltp->TokData, &rSession,
						 pEncryptedPart,
						 ulEncryptedPartLen, pPart,
						 pulPartLen);
		TRACE_DEVEL("fcn->ST_DecryptDigestUpdate returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;
}

//------------------------------------------------------------------------
// API function C_DecryptFinal
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_DecryptFinal(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DecryptFinal\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	// This may have to go to the STDLL for validation
	// It is acceptable to have a Null pointer for the data since
	// it is trying to get the length of the last part....
	// The spec is unclear if a second call to Final is needed
	// if there is no data in the last part.
	if (!pulLastPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DecryptFinal) {
		// Map the Session to the slot session
		rv = fcn->ST_DecryptFinal(sltp->TokData, &rSession, pLastPart,
					  pulLastPartLen);
		TRACE_DEVEL("fcn->ST_DecryptFinal returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_DecryptFinal

//------------------------------------------------------------------------
// API function C_DecryptInit
//------------------------------------------------------------------------
//
//
//
//------------------------------------------------------------------------

CK_RV
C_DecryptInit(CK_SESSION_HANDLE hSession,
	      CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DecryptInit\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	// Null mechanism pointer is not good
	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DecryptInit) {
		// Map the Session to the slot session
		rv = fcn->ST_DecryptInit(sltp->TokData, &rSession,
					 pMechanism, hKey);
		TRACE_DEVEL("fcn->ST_DecryptInit returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_DecryptInit

//------------------------------------------------------------------------
// API function C_DecryptUpdate
//------------------------------------------------------------------------
//
//
//
//------------------------------------------------------------------------

CK_RV
C_DecryptUpdate(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pEncryptedPart,
		CK_ULONG ulEncryptedPartLen,
		CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DecryptUpdate\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	// May have to let these go through and let the STDLL handle them
	if (!pulPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DecryptUpdate) {
		// Map the Session to the slot session
		rv = fcn->ST_DecryptUpdate(sltp->TokData, &rSession,
					   pEncryptedPart, ulEncryptedPartLen,
					   pPart, pulPartLen);
		TRACE_DEVEL("fcn->ST_DecryptUpdate:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_DecryptUpdate

//------------------------------------------------------------------------
// API function C_DecryptVerifyUpdate
//------------------------------------------------------------------------

CK_RV
C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG ulEncryptedPartLen,
		      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DecryptVerifyUpdate\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	// May have to let these go through and let the STDLL handle them
	if (!pEncryptedPart || !pulPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DecryptVerifyUpdate) {
		// Map the Session to the slot session
		rv = fcn->ST_DecryptVerifyUpdate(sltp->TokData, &rSession, pEncryptedPart,
						 ulEncryptedPartLen, pPart,
						 pulPartLen);
		TRACE_DEVEL("fcn->ST_DecryptVerifyUpdate returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;
}

//------------------------------------------------------------------------
// API function C_DeriveKey
//------------------------------------------------------------------------

CK_RV
C_DeriveKey(CK_SESSION_HANDLE hSession,
	    CK_MECHANISM_PTR pMechanism,
	    CK_OBJECT_HANDLE hBaseKey,
	    CK_ATTRIBUTE_PTR pTemplate,
	    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DeriveKey\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	// Null phKey is invalid
	// Null mechanism pointer  is invalid
	// This is allowed for some SSL3 mechs.  the STDLL has to catch this
	// condition since it validates the mechanism
	//if (!phKey ) return CKR_ARGUMENTS_BAD;

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
	// Null template with attribute count is bad
	//  but we will let a template with len 0 pass through
	if (!pTemplate && ulAttributeCount) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DeriveKey) {
		// Map the Session to the slot session
		rv = fcn->ST_DeriveKey(sltp->TokData, &rSession, pMechanism,
				       hBaseKey, pTemplate, ulAttributeCount,
				       phKey);
		TRACE_DEVEL("fcn->ST_DeriveKey returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_DestroyObject
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DestrypObject\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DestroyObject) {
		// Map the Session to the slot session
		rv = fcn->ST_DestroyObject(sltp->TokData, &rSession, hObject);
		TRACE_DEVEL("fcn->ST_DestroyObject returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_DestroyObject

//------------------------------------------------------------------------
// API function C_Digest
//------------------------------------------------------------------------

CK_RV
C_Digest(CK_SESSION_HANDLE hSession,
	 CK_BYTE_PTR pData,
	 CK_ULONG ulDataLen, CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_Digest\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	// Null data for digest is bad
	if (!pData || !pulDigestLen)
		return CKR_ARGUMENTS_BAD;

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_Digest) {
		// Map the Session to the slot session
		rv = fcn->ST_Digest(sltp->TokData, &rSession, pData, ulDataLen,
				    pDigest, pulDigestLen);
		TRACE_DEVEL("fcn->ST_Digest:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_DigestEncryptUpdate
//------------------------------------------------------------------------

CK_RV
C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
		      CK_BYTE_PTR pPart,
		      CK_ULONG ulPartLen,
		      CK_BYTE_PTR pEncryptedPart,
		      CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DigestEncryptUpdate\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	// May have to pass on through to the STDLL
	if (!pPart || !pulEncryptedPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}

	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DigestEncryptUpdate) {
		// Map the Session to the slot session
		rv = fcn->ST_DigestEncryptUpdate(sltp->TokData, &rSession,
						 pPart, ulPartLen,
						 pEncryptedPart,
						 pulEncryptedPartLen);
		TRACE_DEVEL("fcn->ST_DigestEncryptUpdate returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_DigestFinal
//------------------------------------------------------------------------

CK_RV
C_DigestFinal(CK_SESSION_HANDLE hSession,
	      CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DigestFinal\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pulDigestLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DigestFinal) {
		// Map the Session to the slot session
		rv = fcn->ST_DigestFinal(sltp->TokData, &rSession, pDigest,
					 pulDigestLen);
		TRACE_DEVEL("fcn->ST_DigestFinal returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

//------------------------------------------------------------------------
// API function C_DigestInit
//------------------------------------------------------------------------

CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DigestInit\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DigestInit) {
		// Map the Session to the slot session
		rv = fcn->ST_DigestInit(sltp->TokData, &rSession, pMechanism);
		TRACE_DEVEL("fcn->ST_DigestInit returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_DigestKey
//------------------------------------------------------------------------

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DigestKey\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DigestKey) {
		// Map the Session to the slot session
		rv = fcn->ST_DigestKey(sltp->TokData, &rSession, hKey);
		TRACE_DEBUG("fcn->ST_DigestKey returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_DigestUpdate
//------------------------------------------------------------------------

CK_RV
C_DigestUpdate(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_DigestUpdate\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_DigestUpdate) {
		// Map the Session to the slot session
		rv = fcn->ST_DigestUpdate(sltp->TokData, &rSession, pPart,
					  ulPartLen);
		TRACE_DEVEL("fcn->ST_DigestUpdate returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_Encrypt
//------------------------------------------------------------------------

CK_RV
C_Encrypt(CK_SESSION_HANDLE hSession,
	  CK_BYTE_PTR pData,
	  CK_ULONG ulDataLen,
	  CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_Encrypt\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pData || !pulEncryptedDataLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_Encrypt) {
		// Map the Session to the slot session
		rv = fcn->ST_Encrypt(sltp->TokData, &rSession, pData,
				     ulDataLen, pEncryptedData,
				     pulEncryptedDataLen);
		TRACE_DEVEL("fcn->ST_Encrypt returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_EncryptFinal
//------------------------------------------------------------------------

CK_RV
C_EncryptFinal(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pLastEncryptedPart,
	       CK_ULONG_PTR pulLastEncryptedPartLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_EncryptFinal\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	// See comments for DecryptFinal
	if (!pulLastEncryptedPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_EncryptFinal) {
		// Map the Session to the slot session
		rv = fcn->ST_EncryptFinal(sltp->TokData, &rSession,
					  pLastEncryptedPart,
					  pulLastEncryptedPartLen);
		TRACE_DEVEL("fcn->ST_EncryptFinal: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_EncryptInit
//------------------------------------------------------------------------

CK_RV
C_EncryptInit(CK_SESSION_HANDLE hSession,
	      CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_EncryptInit\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_EncryptInit) {
		// Map the Session to the slot session
		rv = fcn->ST_EncryptInit(sltp->TokData, &rSession,
					 pMechanism, hKey);
		TRACE_INFO("fcn->ST_EncryptInit returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

//------------------------------------------------------------------------
// API function C_EncryptUpdate
//------------------------------------------------------------------------

CK_RV
C_EncryptUpdate(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pPart,
		CK_ULONG ulPartLen,
		CK_BYTE_PTR pEncryptedPart, CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_EncryptUpdate\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pulEncryptedPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_EncryptUpdate) {
		// Map the Session to the slot session
		rv = fcn->ST_EncryptUpdate(sltp->TokData, &rSession, pPart,
					   ulPartLen, pEncryptedPart,
					   pulEncryptedPartLen);
		TRACE_DEVEL("fcn->ST_EncryptUpdate returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_Finalize
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV C_Finalize(CK_VOID_PTR pReserved)
{
	API_Slot_t *sltp;
	CK_SLOT_ID slotID;
	Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);
	SLOT_INFO *sinfp;

	TRACE_INFO("C_Finalize\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (pReserved != NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	pthread_mutex_lock(&GlobMutex);	// Grab Process level Global MUTEX

	Terminate_All_Process_Sessions();	// Terminate the sessions

	// unload all the STDLL's from the application
	// This is in case the APP decides to do the re-initialize and
	// continue on
	// //

	for (slotID = 0; slotID < NUMBER_SLOTS_MANAGED; slotID++) {
		sltp = &(Anchor->SltList[slotID]);
		if (sltp->pSTcloseall) {
#if 0
			(void)sltp->pSTcloseall(slotID);	// call the terminate function..
#else
			/* pSTcloseall is just a pointer to the STDLL's SC_CloseAllSessions() function, so calling
			 * it won't clean up shared memory, or the API layer's session btree. Instead, call
			 * CloseAllSessions, which will clean everything up */
			CloseAllSessions(slotID);
#endif
		}
		if (sltp->pSTfini) {
			sinfp = &(shData->slot_info[slotID]);
			if (slot_loaded[slotID])
				sltp->pSTfini(sltp->TokData, slotID, sinfp);	// call the terminate function..
		}

		DL_UnLoad(sltp, slotID);
	}

	// Un register from Slot D
	API_UnRegister();

	detach_shared_memory(Anchor->SharedMemP);
	free(Anchor);		// Free API Proc Struct
	Anchor = NULL;

	// Unlock
	pthread_mutex_unlock(&GlobMutex);

	trace_finalize();

	//close the lock file descriptor here to avoid memory leak
	ProcClose();

	return CKR_OK;
}				// end of C_Finalize

//------------------------------------------------------------------------
// API function C_FindObjects
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_FindObjects(CK_SESSION_HANDLE hSession,
	      CK_OBJECT_HANDLE_PTR phObject,
	      CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_FindObjects\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!phObject || !pulObjectCount) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_FindObjects) {
		// Map the Session to the slot session
		rv = fcn->ST_FindObjects(sltp->TokData, &rSession, phObject,
					 ulMaxObjectCount, pulObjectCount);
		TRACE_DEVEL("fcn->ST_FindObjects returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_FindObjects

//------------------------------------------------------------------------
// API function C_FindObjectsFinal
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_FindObjectsFinal\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_FindObjectsFinal) {
		// Map the Session to the slot session
		rv = fcn->ST_FindObjectsFinal(sltp->TokData, &rSession);
		TRACE_DEVEL("fcn->ST_FindObjectsFinal returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_FindObjectsFinal

//------------------------------------------------------------------------
// API function
// C_FindObjectsInit
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_FindObjectsInit(CK_SESSION_HANDLE hSession,
		  CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_FindObjectsInit\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	// What does a NULL template really mean

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_FindObjectsInit) {
		// Map the Session to the slot session
		rv = fcn->ST_FindObjectsInit(sltp->TokData, &rSession,
					     pTemplate, ulCount);
		TRACE_DEVEL("fcn->ST_FindObjectsInit returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_FindObjectsInit

//------------------------------------------------------------------------
// API function C_GenerateKey
//------------------------------------------------------------------------
//  Netscape Required

CK_RV
C_GenerateKey(CK_SESSION_HANDLE hSession,
	      CK_MECHANISM_PTR pMechanism,
	      CK_ATTRIBUTE_PTR pTemplate,
	      CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_GenerateKey\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
	if (!phKey) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_GenerateKey) {
		// Map the Session to the slot session
		rv = fcn->ST_GenerateKey(sltp->TokData, &rSession, pMechanism,
					 pTemplate, ulCount, phKey);
		TRACE_DEVEL("fcn->ST_GenerateKey returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_GenerateKeyPair
//------------------------------------------------------------------------
//  Netscape Required

CK_RV
C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism,
		  CK_ATTRIBUTE_PTR pPublicKeyTemplate,
		  CK_ULONG ulPublicKeyAttributeCount,
		  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
		  CK_ULONG ulPrivateKeyAttributeCount,
		  CK_OBJECT_HANDLE_PTR phPublicKey,
		  CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_GenerateKeyPair\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
	if (!phPublicKey || !phPrivateKey) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
	//   what other validation of parameters ... What about
	// template pointers is a Null template pointer valid in generate
	// key...  Are there defaults.

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);


	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_GenerateKeyPair) {
		// Map the Session to the slot session
		rv = fcn->ST_GenerateKeyPair(sltp->TokData, &rSession,
					     pMechanism,
					     pPublicKeyTemplate,
					     ulPublicKeyAttributeCount,
					     pPrivateKeyTemplate,
					     ulPrivateKeyAttributeCount,
					     phPublicKey, phPrivateKey);
		TRACE_DEVEL("fcn->ST_GenerateKeyPair returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_GenerateRandom
//------------------------------------------------------------------------
//  Netscape Required

CK_RV
C_GenerateRandom(CK_SESSION_HANDLE hSession,
		 CK_BYTE_PTR RandomData, CK_ULONG ulRandomLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_GenerateRandom\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!RandomData)
		return CKR_ARGUMENTS_BAD;

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_GenerateRandom) {
		// Map the Session to the slot session
		rv = fcn->ST_GenerateRandom(sltp->TokData, &rSession,
					    RandomData, ulRandomLen);
		TRACE_DEVEL("fcn->ST_GenerateRandom returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

//------------------------------------------------------------------------
// API function C_GetAttributeValue
//------------------------------------------------------------------------
// Netscape Required
//
//
//------------------------------------------------------------------------

CK_RV
C_GetAttributeValue(CK_SESSION_HANDLE hSession,
		    CK_OBJECT_HANDLE hObject,
		    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_GetAttributeValue\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pTemplate) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}
	if (ulCount == 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_GetAttributeValue) {
		// Map the Session to the slot session
		rv = fcn->ST_GetAttributeValue(sltp->TokData, &rSession,
					       hObject, pTemplate, ulCount);
		TRACE_DEVEL("fcn->ST_GetAttributeValue returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_GetAttributeValue

//------------------------------------------------------------------------
// API function C_GetFunctionList
//------------------------------------------------------------------------
//  Netscape Required

CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList)
{

	api_init();

	TRACE_INFO("C_GetFunctionList\n");
	FuncList.version.major = VERSION_MAJOR;
	FuncList.version.minor = VERSION_MINOR;
	FuncList.C_Initialize = C_Initialize;
	FuncList.C_Finalize = C_Finalize;
	FuncList.C_GetInfo = C_GetInfo;
	FuncList.C_GetFunctionList = C_GetFunctionList;
	FuncList.C_GetSlotList = C_GetSlotList;
	FuncList.C_GetSlotInfo = C_GetSlotInfo;
	FuncList.C_GetTokenInfo = C_GetTokenInfo;
	FuncList.C_GetMechanismList = C_GetMechanismList;
	FuncList.C_GetMechanismInfo = C_GetMechanismInfo;
	FuncList.C_InitToken = C_InitToken;
	FuncList.C_InitPIN = C_InitPIN;
	FuncList.C_SetPIN = C_SetPIN;
	FuncList.C_OpenSession = C_OpenSession;
	FuncList.C_CloseSession = C_CloseSession;
	FuncList.C_CloseAllSessions = C_CloseAllSessions;
	FuncList.C_GetSessionInfo = C_GetSessionInfo;
	FuncList.C_GetOperationState = C_GetOperationState;
	FuncList.C_SetOperationState = C_SetOperationState;
	FuncList.C_Login = C_Login;
	FuncList.C_Logout = C_Logout;
	FuncList.C_CreateObject = C_CreateObject;
	FuncList.C_CopyObject = C_CopyObject;
	FuncList.C_DestroyObject = C_DestroyObject;
	FuncList.C_GetObjectSize = C_GetObjectSize;
	FuncList.C_GetAttributeValue = C_GetAttributeValue;
	FuncList.C_SetAttributeValue = C_SetAttributeValue;
	FuncList.C_FindObjectsInit = C_FindObjectsInit;
	FuncList.C_FindObjects = C_FindObjects;
	FuncList.C_FindObjectsFinal = C_FindObjectsFinal;
	FuncList.C_EncryptInit = C_EncryptInit;
	FuncList.C_Encrypt = C_Encrypt;
	FuncList.C_EncryptUpdate = C_EncryptUpdate;
	FuncList.C_EncryptFinal = C_EncryptFinal;
	FuncList.C_DecryptInit = C_DecryptInit;
	FuncList.C_Decrypt = C_Decrypt;
	FuncList.C_DecryptUpdate = C_DecryptUpdate;
	FuncList.C_DecryptFinal = C_DecryptFinal;
	FuncList.C_DigestInit = C_DigestInit;
	FuncList.C_Digest = C_Digest;
	FuncList.C_DigestUpdate = C_DigestUpdate;
	FuncList.C_DigestKey = C_DigestKey;
	FuncList.C_DigestFinal = C_DigestFinal;
	FuncList.C_SignInit = C_SignInit;
	FuncList.C_Sign = C_Sign;
	FuncList.C_SignUpdate = C_SignUpdate;
	FuncList.C_SignFinal = C_SignFinal;
	FuncList.C_SignRecoverInit = C_SignRecoverInit;
	FuncList.C_SignRecover = C_SignRecover;
	FuncList.C_VerifyInit = C_VerifyInit;
	FuncList.C_Verify = C_Verify;
	FuncList.C_VerifyUpdate = C_VerifyUpdate;
	FuncList.C_VerifyFinal = C_VerifyFinal;
	FuncList.C_VerifyRecoverInit = C_VerifyRecoverInit;
	FuncList.C_VerifyRecover = C_VerifyRecover;
	FuncList.C_DigestEncryptUpdate = C_DigestEncryptUpdate;
	FuncList.C_DecryptDigestUpdate = C_DecryptDigestUpdate;
	FuncList.C_SignEncryptUpdate = C_SignEncryptUpdate;
	FuncList.C_DecryptVerifyUpdate = C_DecryptVerifyUpdate;
	FuncList.C_GenerateKey = C_GenerateKey;
	FuncList.C_GenerateKeyPair = C_GenerateKeyPair;
	FuncList.C_WrapKey = C_WrapKey;
	FuncList.C_UnwrapKey = C_UnwrapKey;
	FuncList.C_DeriveKey = C_DeriveKey;
	FuncList.C_SeedRandom = C_SeedRandom;
	FuncList.C_GenerateRandom = C_GenerateRandom;
	FuncList.C_GetFunctionStatus = C_GetFunctionStatus;
	FuncList.C_CancelFunction = C_CancelFunction;
	FuncList.C_WaitForSlotEvent = C_WaitForSlotEvent;

	if (ppFunctionList) {
		(*ppFunctionList) = &FuncList;
		return CKR_OK;
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
}

//------------------------------------------------------------------------
// API function C_GetFunctionStatus
//------------------------------------------------------------------------

CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession)
{
	TRACE_INFO("C_GetFunctionStatus\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_PARALLEL));
	return CKR_FUNCTION_NOT_PARALLEL;	// PER Specification PG 170
}

//------------------------------------------------------------------------
// API function C_GetInfo
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV C_GetInfo(CK_INFO_PTR pInfo)
{
	Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);

	TRACE_INFO("C_GetInfo\n");
	if (!API_Initialized()) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pInfo) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;
	}

	CK_Info_From_Internal(pInfo, &(shData->ck_info));

	return CKR_OK;
}				// end of C_GetInfo


//------------------------------------------------------------------------
// API function C_GetMechanismInfo
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_GetMechanismInfo(CK_SLOT_ID slotID,
		   CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;

	TRACE_INFO("C_GetMechansimInfo %lu  %lx  %p\n", slotID, type, pInfo);
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (slotID >= NUMBER_SLOTS_MANAGED) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		return CKR_SLOT_ID_INVALID;
	}

	sltp = &(Anchor->SltList[slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_GetMechanismInfo) {
		rv = fcn->ST_GetMechanismInfo(sltp->TokData, slotID,
					      type, pInfo);
		TRACE_DEVEL("fcn->ST_GetMechanismInfo returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_GetMechanismInfo

//------------------------------------------------------------------------
// API function C_GetMechanismList
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_GetMechanismList(CK_SLOT_ID slotID,
		   CK_MECHANISM_TYPE_PTR pMechanismList, CK_ULONG_PTR pulCount)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;

	TRACE_INFO("C_GetMechanismList\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	// Always have to have a pulCount
	if (!pulCount) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	TRACE_DEVEL("Slot %lu MechList %p Count %lu\n",
			slotID, pMechanismList, *pulCount);

	// Null PMechanism is valid to get a count of mechanisms

	if (slotID >= NUMBER_SLOTS_MANAGED) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		return CKR_SLOT_ID_INVALID;
	}

	sltp = &(Anchor->SltList[slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_GetMechanismList) {
		rv = fcn->ST_GetMechanismList(sltp->TokData, slotID,
					      pMechanismList, pulCount);
		TRACE_DEVEL("fcn->ST_GetMechanismList returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}

	if (rv == CKR_OK) {
		if (pMechanismList) {
			unsigned long i;
			for (i = 0; i < *pulCount; i++) {
				TRACE_DEVEL("Mechanism[%lu] 0x%08lX \n", i,
					    pMechanismList[i]);
			}
		}
	}
	return rv;

}				// end of C_GetMechanismList

//------------------------------------------------------------------------
// API function C_GetObjectSize
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_GetObjectSize(CK_SESSION_HANDLE hSession,
		CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_GetObjectSize\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pulSize) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_GetObjectSize) {
		// Map the Session to the slot session
		rv = fcn->ST_GetObjectSize(sltp->TokData, &rSession,
					   hObject, pulSize);
		TRACE_DEVEL("fcn->ST_GetObjectSize retuned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_GetObjectSize

//------------------------------------------------------------------------
// API function C_GetOperationState
//------------------------------------------------------------------------

CK_RV
C_GetOperationState(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pOperationState,
		    CK_ULONG_PTR pulOperationStateLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_GetOperateionState\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	// NULL pOperationState is valid to get buffer
	// size
	if (!pulOperationStateLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_GetOperationState) {
		// Map the Session to the slot session
		rv = fcn->ST_GetOperationState(sltp->TokData, &rSession,
					       pOperationState,
					       pulOperationStateLen);
		TRACE_DEVEL("fcn->ST_GetOperationState returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_GetSessionInfo
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_GetSessionInfo  %lx  %p\n", hSession, pInfo);
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pInfo) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_GetSessionInfo) {
		// Map the Session to the slot session
		rv = fcn->ST_GetSessionInfo(sltp->TokData, &rSession, pInfo);

		TRACE_DEVEL("fcn->ST_GetSessionInfo returned: 0x%lx\n", rv);
		TRACE_DEVEL("Slot %lu  State %lx  Flags %lx DevErr %lx\n",
			    pInfo->slotID, pInfo->state, pInfo->flags,
			    pInfo->ulDeviceError);

	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_GetSessionInfo

//------------------------------------------------------------------------
// API function C_GetSlotInfo
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

#ifdef PKCS64

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	Slot_Info_t_64 *sinfp;
	Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);

	TRACE_INFO("C_GetSlotInfo Slot=%lu  ptr=%p\n", slotID, pInfo);

	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pInfo) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;
	}

	sinfp = shData->slot_info;
	sinfp += slotID;

	if (slotID >= NUMBER_SLOTS_MANAGED) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		return CKR_SLOT_ID_INVALID;
	}
	// Netscape and others appear to call
	// this for every slot.  If the slot does not have
	// a registered STDLL, then this is a FUnction Failed case
	if (sinfp->present == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;

	}

#ifdef __64BIT__

	memcpy(pInfo, (char *)&(sinfp->pk_slot), sizeof(CK_SLOT_INFO));

#else

	memcpy((char *)&(pInfo->slotDescription[0]),
	       (char *)&(sinfp->pk_slot.slotDescription[0]), 64);
	memcpy((char *)&(pInfo->manufacturerID[0]),
	       (char *)&(sinfp->pk_slot.manufacturerID[0]), 32);

	pInfo->flags = sinfp->pk_slot.flags;
	pInfo->hardwareVersion = sinfp->pk_slot.hardwareVersion;
	pInfo->firmwareVersion = sinfp->pk_slot.firmwareVersion;

#endif

	return CKR_OK;
}				// end of C_GetSlotInfo

#else

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo)
{
	uint16 count;
	uint16 index;
	uint16 sindx;
	Slot_Info_t *sinfp;
	Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);

	TRACE_INFO("C_GetSlotInfo Slot=%d  ptr=%p\n", slotID, pInfo);
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pInfo) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;
	}

	sinfp = shData->slot_info;
	sinfp += slotID;
	count = 0;

	if (slotID >= NUMBER_SLOTS_MANAGED) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		return CKR_SLOT_ID_INVALID;
	}
	// Netscape and others appear to call
	// this for every slot.  If the slot does not have
	// a registered STDLL, then this is a FUnction Failed case
	if (sinfp->present == FALSE) {
		TRACE_ERROR("%s: No STDLL present.\n",
			    ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;

	}
	memcpy(pInfo, (char *)&(sinfp->pk_slot), sizeof(CK_SLOT_INFO));

	return CKR_OK;
}				// end of C_GetSlotInfo

#endif

//------------------------------------------------------------------------
// API function C_GetSlotList
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_GetSlotList(CK_BBOOL tokenPresent,
	      CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount)
{
	CK_ULONG count;
	uint16 index;
	uint16 sindx;
	Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);

#ifdef PKCS64
	Slot_Info_t_64 *sinfp;
#else
	Slot_Info_t *sinfp;
#endif

	TRACE_INFO("C_GetSlotList\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	// Null pSlotList is valid to get count for array allocation
	if (pulCount == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;
	}
	TRACE_DEVEL(" Present %d Count %lu\n", tokenPresent, *pulCount);

	sinfp = shData->slot_info;
	count = 0;
	// Count the slots based off the present flag
	// Go through all the slots and count them up
	// Remember if the tokenPresent Flag is set do not count the
	// not present ones.
	//
	// ------------------------------------------------------------
	//
	// Present indicates that the slot is managed by the Slot manager
	// and that an appropriate registration has been made in the DB
	//
	// It does not imply that a token is present.
	// Slots with STDLL's are ALWAYS present in the system wether they
	// have a token or not is determined from the token functions.
	//
	// According to the spec the tokenPresent flag indicates if all
	// slots are wanted, or those which have tokens present.  We will
	// use this to mean if a STDLL is present or not.  All slots
	// are in the system, if a STDLL is attached to a slot, then it is
	// present( not to be confused with the Tokens  flags indicating
	// presence).  Presence of a STDLL on a slot indicates that there
	// is a "token reader" available.
	//
	// Note: All slots should be named by the slot manager with the
	// slot id in them...
	// ------------------------------------------------------------
	//
	// Note: The CK_INFO_STRUCT present flag indicates that a token is present
	// in the reader located in the slot.  Right now we are dealing only
	// with non-removable tokens, so the slot flags set in the slot DB
	// are fixed by the STDLL.  Ultimately when we get to removable tokens, the
	// slot manager will have to monitor the device in the slot and set the flag
	// accordingly.
	//
	// This does however change the reporting back of Slot Lists...
	//
	// We were using the presence of a STDLL to indicate if a Token is present
	// or not.  however we need to report back based on 2 flags.
	//
	// First a stdll must be in the table, second the slot info flags must be
	// set to present to return.
	// ----------------------------------------------
	//
	// Also need to validate that the STDLL successfully loaded.

	for (index = 0; index < NUMBER_SLOTS_MANAGED; index++) {
		// if there is a STDLL in the slot then we have to count it
		// otherwise the slot is NOT counted.
		if (sinfp[index].present == TRUE && slot_loaded[index] == TRUE) {
			if (tokenPresent) {
				if ((sinfp[index].pk_slot.
				     flags & CKF_TOKEN_PRESENT)) {
					count++;
				}
			} else {
				count++;
			}
		}
	}

	*pulCount = count;
	// If only the count is wanted then we set the value and exit
	if (pSlotList == NULL) {
		return CKR_OK;
	} else {
		// Verify that the buffer passed is large enough
		if (*pulCount < count) {
			TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
			return CKR_BUFFER_TOO_SMALL;
		}
		// Walk through the slot manager information and copy in the
		// slot id to the list of slot indexes.
		//
		//     This is incorrectly going to assume that the slots are
		//     sequentialy allocated.  While most likely we should be robust
		//     and handle it.
		//     Count should correct based on the first loop.
		//
		for (sindx = 0, index = 0;
		     (index < NUMBER_SLOTS_MANAGED) && (sindx < count);
		     index++) {
			if (sinfp[index].present == TRUE
			    && slot_loaded[index] == TRUE) {
				if (tokenPresent) {
					if (sinfp[index].pk_slot.
					    flags & CKF_TOKEN_PRESENT) {
						pSlotList[sindx] =
						    sinfp[index].slot_number;
						sindx++;	// only increment when we have used it.
					}
				} else {
					pSlotList[sindx] =
					    sinfp[index].slot_number;
					sindx++;	// only increment when we have used it.
				}
			}

		}
	}
	return CKR_OK;
}				// end of C_GetSlotList

//------------------------------------------------------------------------
// API function C_GetTokenInfo
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	Slot_Mgr_Socket_t *shData = &(Anchor->SocketDataP);

#ifdef PKCS64
	Slot_Info_t_64 *sinfp;
#else
	Slot_Info_t *sinfp;
#endif

	TRACE_INFO("C_GetTokenInfo\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pInfo) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
	if (slotID >= NUMBER_SLOTS_MANAGED) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		return CKR_SLOT_ID_INVALID;
	}

	sltp = &(Anchor->SltList[slotID]);
	TRACE_DEVEL("Slot p = %p id %lu\n", sltp, slotID);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	// Need to check if the slot is not populated
	// then we can return the proper return code for a
	// slot that has no content.
	sinfp = shData->slot_info;
	if (sinfp[slotID].present == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_GetTokenInfo) {
		rv = fcn->ST_GetTokenInfo(sltp->TokData, slotID, pInfo);
		if (rv == CKR_OK) {
			get_sess_count(slotID, &(pInfo->ulSessionCount));
		}
		TRACE_DEVEL("rv %lu CK_TOKEN_INFO Flags %lx\n", rv, pInfo->flags);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;
}				// end of C_GetTokenInfo

void Call_Finalize()
{
	C_Finalize(NULL);
	return;
}

//------------------------------------------------------------------------
// API function C_Initialize
//------------------------------------------------------------------------
//  Netscape Required
//
//
//------------------------------------------------------------------------
CK_RV C_Initialize(CK_VOID_PTR pVoid)
{
	CK_C_INITIALIZE_ARGS *pArg;
	char fcnmap = 0;

	trace_initialize();

	TRACE_INFO("C_Initialize\n");
	//if ( API_Proc_Struct NOT allocated )
	//       allocate Structure
	//    if ( allocation fails )
	//       return CKR_HOST_MEMORY
	//else
	//    if ( API_Proc_Struct owned by current process )
	//        process has called C_Initialize twice Fail routine
	//        return CKR_FUNCTION_FAILED
	if (!Anchor) {
		Anchor =
		    (API_Proc_Struct_t *) malloc(sizeof(API_Proc_Struct_t));
		if (Anchor == NULL) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			return CKR_HOST_MEMORY;
		}
	} else {
		// Linux the atfork routines handle this
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_ALREADY_INITIALIZED));
		return CKR_CRYPTOKI_ALREADY_INITIALIZED;
	}

	memset(slot_loaded, 0, sizeof(int) * NUMBER_SLOTS_MANAGED);	// Clear out the load list

	TRACE_DEBUG("Anchor allocated at %s\n", (char *)Anchor);

	// Validation of the parameters passed

	// if pVoid is NULL, then everything is OK.  The applicaiton
	// will not be doing multi thread accesses.  We can use the OS
	// locks anyhow.
	//
	if (pVoid != NULL) {
		TRACE_DEVEL("Initialization arg = %p  Flags %lu\n", pVoid,
			      ((CK_C_INITIALIZE_ARGS *) pVoid)->flags);

		pArg = (CK_C_INITIALIZE_ARGS *) pVoid;

		// Check for a pReserved set
		if (pArg->pReserved != NULL) {
			free(Anchor);
			Anchor = NULL;
			TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
			return CKR_ARGUMENTS_BAD;
		}

		// Set up a bit map indicating the presense of the functions.
		fcnmap = (pArg->CreateMutex ? 0x01 << 0 : 0);
		fcnmap |= (pArg->DestroyMutex ? 0x01 << 1 : 0);
		fcnmap |= (pArg->LockMutex ? 0x01 << 2 : 0);
		fcnmap |= (pArg->UnlockMutex ? 0x01 << 3 : 0);

		// Verify that all or none of the functions are set
		if (fcnmap != 0) {
			if (fcnmap != 0x0f) {
				free(Anchor);
				Anchor = NULL;
				OCK_SYSLOG(LOG_ERR, "C_Initialize: Invalid "
				           "number of functions passed in "
					   "argument structure.\n");
				return CKR_ARGUMENTS_BAD;
			}
		}
		// If we EVER need to create threads from this library we must
		// check the Flags for the Can_Create_OS_Threads flag
		// Right now the library DOES NOT create threads and therefore this
		// check is irrelavant.
		if (pArg->flags & CKF_LIBRARY_CANT_CREATE_OS_THREADS) {
			TRACE_DEVEL("Can't create OS threads...This is OK\n");
		}
		// Since this is an initialization path, we will be verbose in the
		// code rather than efficient.
		//
		// in reality, we only need to check for case 3 since all others
		// are acceptable to us... for one reason or another.
		//
		// Case 1  Flag not set and functiopn pointers NOT supplied
		if (!(pArg->flags & CKF_OS_LOCKING_OK) && !(fcnmap)) {
			;	// This is COOL.  Same as a NUL pointer  Locking is irrelavent.
		} else {
			//  Case 2.  Flags set and Fcn pointers NOT supplied.
			if ((pArg->flags & CKF_OS_LOCKING_OK) && !(fcnmap)) {
				;	// This to is COOL since we require native locking
			} else {
				// Case 3  Flag Not set and pointers supplied.  Can't handle this
				// one.
				if (!(pArg->flags & CKF_OS_LOCKING_OK)
				    && fcnmap) {
					free(Anchor);
					Anchor = NULL;
					OCK_SYSLOG(LOG_ERR, "C_Initialize: "
						   "Application specified that "
						   "OS locking is invalid. "
						   "PKCS11 Module requires OS "
						   "locking.\n");
					// Only support Native OS locking.
					return CKR_CANT_LOCK;
				} else {
					// Case 4  Flag set and fcn pointers set
					if ((pArg->flags & CKF_OS_LOCKING_OK)
					    && fcnmap) {
						;	// This is also cool.
					} else {
						// Were really hosed here since this should not have
						// occured
						free(Anchor);
						Anchor = NULL;
						TRACE_ERROR("%s\n",
						    ock_err(ERR_GENERAL_ERROR));
						return CKR_GENERAL_ERROR;
					}
				}
			}
		}

	} else {
		// Pointer to void...
		// This is OK we can go on from here.
		;
	}

	// Create the shared memory lock.
	if (CreateProcLock() != CKR_OK) {
		free((void *)Anchor);
		Anchor = NULL;
		TRACE_ERROR("Process Lock Failed.\n");
		return CKR_FUNCTION_FAILED;
	}
	//Zero out API_Proc_Struct
	//Map Shared Memory Region
	//if ( Shared Memory Mapped not Successful )
	//                Free allocated Memory
	//                Return CKR_HOST_MEMORY
	memset((char *)Anchor, 0, sizeof(API_Proc_Struct_t));
	pthread_mutex_init(&(Anchor->ProcMutex), NULL);	// This is not shared across apps.
	pthread_mutex_init(&(Anchor->SessListMutex), NULL);	// This is not shared across apps.
	pthread_mutex_init(&GlobMutex, NULL);
	pthread_mutex_lock(&GlobMutex);
	Anchor->Pid = getpid();

	if ((Anchor->SharedMemP = attach_shared_memory()) == NULL) {	// Get shared memory
		free((void *)Anchor);
		Anchor = NULL;
		pthread_mutex_unlock(&GlobMutex);
		OCK_SYSLOG(LOG_ERR, "C_Initialize: Module failed to attach to "
			   "shared memory. Verify that the slot management "
			   "daemon is running, errno=%d\n", errno);
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}
	TRACE_DEBUG("Shared memory %p \n", Anchor->SharedMemP);

	if (!init_socket_data()) {
		OCK_SYSLOG(LOG_ERR, "C_Initialize: Module failed to create a "
			   "socket. Verify that the slot management daemon is "
			   "running.\n");
		TRACE_ERROR("Cannot attach to socket.\n");
		detach_shared_memory(Anchor->SharedMemP);
		free((void *)Anchor); Anchor=NULL;
		pthread_mutex_unlock(&GlobMutex);
		return CKR_FUNCTION_FAILED;
	}

	// Initialize structure values

	//Register with pkcsslotd
	if (!API_Register()) {
		//   free memory allocated
		//   return CKR_FUNCTION_FAILED
		//   return CKR_FUNCTION_NOT_SUPPORTED;
		detach_shared_memory(Anchor->SharedMemP);
		free((void *)Anchor);
		Anchor = NULL;
		pthread_mutex_unlock(&GlobMutex);
		TRACE_ERROR("Failed to register process with pkcsslotd.\n");
		return CKR_FUNCTION_FAILED;
	}
	//
	// load all the slot DLL's here
	{
		CK_SLOT_ID slotID;
		API_Slot_t *sltp;

		for (slotID = 0; slotID < NUMBER_SLOTS_MANAGED; slotID++) {
			sltp = &(Anchor->SltList[slotID]);
			slot_loaded[slotID] = DL_Load_and_Init(sltp, slotID);
		}

	}
	// Attempt to force C_Finalize to be called
	// This causes Netscape to core dump since it unloads the module
	//atexit(*Call_Finalize);

	pthread_mutex_unlock(&GlobMutex);
	return CKR_OK;		// Good return code.

}				// end of C_Initialize

//------------------------------------------------------------------------
// API function C_InitPIN
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_InitPin\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	// A Null Pin with a Len is invalid
	// A  Null pin with a 0 len is no pin at all?
	if (!pPin && ulPinLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	// XXX Remove me, this test should be completely unnecessary
	// Move this to after the session validation...
	if (rSession.slotID >= NUMBER_SLOTS_MANAGED) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		return CKR_SLOT_ID_INVALID;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_InitPIN) {
		// Map the Session to the slot session
		rv = fcn->ST_InitPIN(sltp->TokData, &rSession, pPin, ulPinLen);
		TRACE_DEVEL("fcn->ST_InitPIN returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_InitPIN

//------------------------------------------------------------------------
// API function C_InitToken
//------------------------------------------------------------------------
//Netscape NEVER Calls this according to the Netscape documentation

CK_RV
C_InitToken(CK_SLOT_ID slotID,
	    CK_CHAR_PTR pPin, CK_ULONG ulPinLen, CK_CHAR_PTR pLabel)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;

	TRACE_INFO("C_InitToken\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (slotID >= NUMBER_SLOTS_MANAGED) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		return CKR_SLOT_ID_INVALID;
	}
	// Null pPin and a pinlen is a problem
	if (!pPin && ulPinLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
	if (!pLabel) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
	// Prior to invoking the Tokens initialization, the
	// API needs to verify that NO other applications have any
	// sessions established with this particular slot
	//
	// Hooks into the shared memory to determine how many sessions
	// on a given token are open need to be added.
	// When a session is opened, it increments the count.  When
	// closed it decrements the count.  Protected by an MUTEX
	// In the shared memory region  the slot_info[slotID].sesscount
	// variable needs to be checked, and held locked until the operation
	// is complete.
	if (sessions_exist(slotID)) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_EXISTS));
		return CKR_SESSION_EXISTS;
	}

	sltp = &(Anchor->SltList[slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_InitToken) {
		rv = fcn->ST_InitToken(sltp->TokData, slotID, pPin, ulPinLen, pLabel);
		TRACE_DEVEL("fcn->ST_InitToken returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;
}

//------------------------------------------------------------------------
// API function C_Login
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_Login(CK_SESSION_HANDLE hSession,
	CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_Login\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
#if 0
	/* Allow incorrect PIN checks to fall into the SC_Login
	 * function, since v2.11 requires flags to be set. - KEY
	 */
	if (!pPin) {
		return CKR_PIN_INCORRECT;
	}
#endif

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_Login) {
		// Map the Session to the slot session
		rv = fcn->ST_Login(sltp->TokData, &rSession, userType, pPin,
				   ulPinLen);
		TRACE_DEVEL("fcn->ST_Login returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_Login

//------------------------------------------------------------------------
// API function C_Logout
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV C_Logout(CK_SESSION_HANDLE hSession)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_Logout\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_Logout) {
		// Map the Session to the slot session
		rv = fcn->ST_Logout(sltp->TokData, &rSession);
		TRACE_DEVEL("fcn->ST_Logout returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_Logout

//------------------------------------------------------------------------
// API function C_OpenSession
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------
//
// Note: Need to worry about handling the Notify and Applicaiton call backs
// that are here...   STDLL will NEVER deal with these... The
// usage of them appears to be optional from the specification
// but we may need to do something with them at a later date.
//
CK_RV
C_OpenSession(CK_SLOT_ID slotID,
	      CK_FLAGS flags,
	      CK_VOID_PTR pApplication,
	      CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T *apiSessp;

	TRACE_INFO("C_OpenSession  %lu %lx %p %p %p\n", slotID, flags,
		    pApplication, Notify, phSession);
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (slotID >= NUMBER_SLOTS_MANAGED) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		return CKR_SLOT_ID_INVALID;
	}

	if (!phSession) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	sltp = &(Anchor->SltList[slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
		//
		// Need to handle the failure of a load here...
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}

	if ((apiSessp = (ST_SESSION_T *) malloc(sizeof(ST_SESSION_T))) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}

	if (fcn->ST_OpenSession) {
		rv = fcn->ST_OpenSession(sltp->TokData, slotID, flags,
					 &(apiSessp->sessionh));
		TRACE_DEVEL("fcn->ST_OpenSession returned: 0x%lx\n", rv);

		// If the session allocation is successful, then we need to
		// complete the API session block and  return.  Otherwise
		// we free the API session block and exit
		if (rv == CKR_OK) {
			/* add a refernece to this handle/slot_id pair to the binary tree we maintain at the
			 * API level, returning the API-level object's handle as the session handle the app
			 * will get */
			*phSession = AddToSessionList(apiSessp);
			if (*phSession == 0) {
				/* failed to add the object to the API-level tree, close the STDLL-level session
				 * and return failure */
				fcn->ST_CloseSession(sltp->TokData, apiSessp);
				free(apiSessp);
				rv = CKR_HOST_MEMORY;
				goto done;
			}
			apiSessp->slotID = slotID;

			// NOTE:  Need to add Session counter to the shared
			// memory slot value.... Atomic operation.
			// sharedmem->slot_info[slotID].sessioncount incremented
			// when ever a session is attached.
			//  Also increment the per process slot counter to indicate
			//  how many sessions this process owns of the total amount.  This
			//  way if the process abends garbage collection in the slot manager
			//  can adequatly clean up the total count value...
			incr_sess_counts(slotID);

		} else {
			free(apiSessp);
		}
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		free(apiSessp);
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
done:
	return rv;

}				// end of C_OpenSession

//------------------------------------------------------------------------
// API function C_SeedRandom
//------------------------------------------------------------------------

CK_RV
C_SeedRandom(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_SeedRandom\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pSeed && ulSeedLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_SeedRandom) {
		// Map the Session to the slot session
		rv = fcn->ST_SeedRandom(sltp->TokData, &rSession, pSeed, ulSeedLen);
		TRACE_DEVEL("fcn->ST_SeedRandom returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

//------------------------------------------------------------------------
// API function C_SetAttributeValue
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_SetAttributeValue(CK_SESSION_HANDLE hSession,
		    CK_OBJECT_HANDLE hObject,
		    CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_SetAttributeValue\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	if (!pTemplate) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}
	if (!ulCount) {
		TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
		return CKR_TEMPLATE_INCOMPLETE;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_SetAttributeValue) {
		// Map the Session to the slot session
		rv = fcn->ST_SetAttributeValue(sltp->TokData, &rSession,
					       hObject, pTemplate, ulCount);
		TRACE_DEVEL("fcn->ST_SetAttributeValue returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_SetAttributeValue

//------------------------------------------------------------------------
// API function C_SetOperationState
//------------------------------------------------------------------------

CK_RV
C_SetOperationState(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pOperationState,
		    CK_ULONG ulOperationStateLen,
		    CK_OBJECT_HANDLE hEncryptionKey,
		    CK_OBJECT_HANDLE hAuthenticationKey)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_SetOperationState\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	if (!pOperationState || ulOperationStateLen == 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_SetOperationState) {
		// Map the Session to the slot session
		rv = fcn->ST_SetOperationState(sltp->TokData, &rSession,
					       pOperationState,
					       ulOperationStateLen,
					       hEncryptionKey,
					       hAuthenticationKey);
		TRACE_DEVEL("fcn->ST_SetOperationState returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

//------------------------------------------------------------------------
// API function C_SetPIN
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_SetPIN(CK_SESSION_HANDLE hSession,
	 CK_CHAR_PTR pOldPin,
	 CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_SetPIN\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pOldPin || !pNewPin)
		return CKR_PIN_INVALID;

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_SetPIN) {
		// Map the Session to the slot session
		rv = fcn->ST_SetPIN(sltp->TokData, &rSession, pOldPin,
				    ulOldLen, pNewPin, ulNewLen);
		TRACE_DEVEL("fcn->ST_SetPIN returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_SetPIN

//------------------------------------------------------------------------
// API function C_Sign
//------------------------------------------------------------------------
//  Netscape Required
//
//
//
//------------------------------------------------------------------------

CK_RV
C_Sign(CK_SESSION_HANDLE hSession,
       CK_BYTE_PTR pData,
       CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_Sign\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pData || !pulSignatureLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_Sign) {
		// Map the Session to the slot session
		rv = fcn->ST_Sign(sltp->TokData, &rSession, pData, ulDataLen,
				  pSignature, pulSignatureLen);
		TRACE_DEVEL("fcn->ST_Sign returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_Sign

//------------------------------------------------------------------------
// API function C_SignEncryptUpdate
//------------------------------------------------------------------------

CK_RV
C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
		    CK_BYTE_PTR pPart,
		    CK_ULONG ulPartLen,
		    CK_BYTE_PTR pEncryptedPart,
		    CK_ULONG_PTR pulEncryptedPartLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_SignEncryptUpdate\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pPart || !pulEncryptedPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_SignEncryptUpdate) {
		// Map the Session to the slot session
		rv = fcn->ST_SignEncryptUpdate(sltp->TokData, &rSession, pPart,
					       ulPartLen, pEncryptedPart,
					       pulEncryptedPartLen);
		TRACE_DEVEL("fcn->ST_SignEncryptUpdate return: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

//------------------------------------------------------------------------
// API function C_SignFinal
//------------------------------------------------------------------------
//
//
//
//------------------------------------------------------------------------

CK_RV
C_SignFinal(CK_SESSION_HANDLE hSession,
	    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_SignEncryptUpdate\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pulSignatureLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_SignFinal) {
		// Map the Session to the slot session
		rv = fcn->ST_SignFinal(sltp->TokData, &rSession, pSignature,
				       pulSignatureLen);
		TRACE_DEVEL("fcn->ST_SignFinal returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}				// end of C_SignFinal

//------------------------------------------------------------------------
// API function C_SignInit
//------------------------------------------------------------------------
//
//
//
//------------------------------------------------------------------------

CK_RV
C_SignInit(CK_SESSION_HANDLE hSession,
	   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_SignInit\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));

		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_SignInit) {
		// Map the Session to the slot session
		rv = fcn->ST_SignInit(sltp->TokData, &rSession,
				      pMechanism, hKey);
		TRACE_DEVEL("fcn->ST_SignInit returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}				// end of C_SignInit

//------------------------------------------------------------------------
// API function C_SignRecover
//------------------------------------------------------------------------

CK_RV
C_SignRecover(CK_SESSION_HANDLE hSession,
	      CK_BYTE_PTR pData,
	      CK_ULONG ulDataLen,
	      CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_SignRecover\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pData || !pulSignatureLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_SignRecover) {
		// Map the Session to the slot session
		rv = fcn->ST_SignRecover(sltp->TokData, &rSession, pData,
					 ulDataLen, pSignature,
					 pulSignatureLen);
		TRACE_DEVEL("fcn->ST_SignRecover returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

//------------------------------------------------------------------------
// API function C_SignRecoverInit
//------------------------------------------------------------------------

CK_RV
C_SignRecoverInit(CK_SESSION_HANDLE hSession,
		  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_SignRecoverInit\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_SignRecoverInit) {
		// Map the Session to the slot session
		rv = fcn->ST_SignRecoverInit(sltp->TokData, &rSession,
					     pMechanism, hKey);
		TRACE_DEVEL("fcn->ST_SignRecoverInit returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

//------------------------------------------------------------------------
// API function C_SignUpdate
//------------------------------------------------------------------------
//
//
//
//------------------------------------------------------------------------

CK_RV
C_SignUpdate(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_SignUpdate\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_SignUpdate) {
		// Map the Session to the slot session
		rv = fcn->ST_SignUpdate(sltp->TokData, &rSession, pPart,
					ulPartLen);
		TRACE_DEVEL("fcn->ST_SignUpdate returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}				// end of C_SignUpdate

//------------------------------------------------------------------------
// API function C_UnwrapKey
//------------------------------------------------------------------------
//  Netscape Required

CK_RV
C_UnwrapKey(CK_SESSION_HANDLE hSession,
	    CK_MECHANISM_PTR pMechanism,
	    CK_OBJECT_HANDLE hUnwrappingKey,
	    CK_BYTE_PTR pWrappedKey,
	    CK_ULONG ulWrappedKeyLen,
	    CK_ATTRIBUTE_PTR pTemplate,
	    CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_UnwrapKey\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
	if (!phKey) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
	//  what about the other pointers... probably need
	// to be set correctly

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_UnwrapKey) {
		// Map the Session to the slot session
		rv = fcn->ST_UnwrapKey(sltp->TokData, &rSession, pMechanism,
				       hUnwrappingKey, pWrappedKey,
				       ulWrappedKeyLen, pTemplate,
				       ulAttributeCount, phKey);
		TRACE_DEVEL("fcn->ST_UnwrapKey returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

//------------------------------------------------------------------------
// API function C_Verify
//------------------------------------------------------------------------
//  Netscape Required

CK_RV
C_Verify(CK_SESSION_HANDLE hSession,
	 CK_BYTE_PTR pData,
	 CK_ULONG ulDataLen, CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_Verify\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pData || !pSignature) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_Verify) {
		// Map the Session to the slot session
		rv = fcn->ST_Verify(sltp->TokData, &rSession, pData, ulDataLen,
				    pSignature, ulSignatureLen);
		TRACE_DEVEL("fcn->ST_Verify returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_VerifyFinal
//------------------------------------------------------------------------

CK_RV
C_VerifyFinal(CK_SESSION_HANDLE hSession,
	      CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_VerifyFinal\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pSignature) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_VerifyFinal) {
		// Map the Session to the slot session
		rv = fcn->ST_VerifyFinal(sltp->TokData, &rSession, pSignature,
					 ulSignatureLen);
		TRACE_DEVEL("fcn->ST_VerifyFinal returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

//------------------------------------------------------------------------
// API function C_VerifyInit
//------------------------------------------------------------------------

CK_RV
C_VerifyInit(CK_SESSION_HANDLE hSession,
	     CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_VerifyInit\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_VerifyInit) {
		// Map the Session to the slot session
		rv = fcn->ST_VerifyInit(sltp->TokData, &rSession,
					pMechanism, hKey);
		TRACE_DEVEL("fcn->ST_VerifyInit returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_VerifyRecover
//------------------------------------------------------------------------
//  Netscape Required

CK_RV
C_VerifyRecover(CK_SESSION_HANDLE hSession,
		CK_BYTE_PTR pSignature,
		CK_ULONG ulSignatureLen,
		CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{

	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_VerifyRecover\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (!pSignature || !pulDataLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_VerifyRecover) {
		// Map the Session to the slot session
		rv = fcn->ST_VerifyRecover(sltp->TokData, &rSession, pSignature,
					   ulSignatureLen, pData, pulDataLen);
		TRACE_DEVEL("fcn->ST_VerifyRecover returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_VerifyRecoverInit
//------------------------------------------------------------------------

CK_RV
C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
		    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_VerifyRecoverInit\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_VerifyRecoverInit) {
		// Map the Session to the slot session
		rv = fcn->ST_VerifyRecoverInit(sltp->TokData, &rSession,
					       pMechanism, hKey);
		TRACE_DEVEL("fcn->ST_VerifyRecoverInit returned:0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_VerifyUpdate
//------------------------------------------------------------------------

CK_RV
C_VerifyUpdate(CK_SESSION_HANDLE hSession,
	       CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_VerifyUpdate\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_VerifyUpdate) {
		// Map the Session to the slot session
		rv = fcn->ST_VerifyUpdate(sltp->TokData, &rSession, pPart,
					  ulPartLen);
		TRACE_DEVEL("fcn->ST_VerifyUpdate returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

//------------------------------------------------------------------------
// API function C_WaitForSlotEvent
//------------------------------------------------------------------------
//
//
//NOTE: We need to implement this one even though Netscape does not
//make use of this...
//
//Standard code template won't work with this.  We need to look at
//the slot manager and the shared memory indicating the slot bitmap
//Blocking needs to be worked out.  At the initial release do not
//support BLocked calls on wait for slot event.
//
//Support Note:
//This function is really used for removable tokens, and is pretty
//inefficient.  It may be best to return CKR_FUNCTION_UNSUPPORTED
//if it becomes a field issue, until removable token support is fully
//implemented.  Be forewarned.
//------------------------------------------------------------------------

CK_RV
C_WaitForSlotEvent(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
#ifdef PLUGGABLE_TOKENS_SUPPORTED
#ifdef PKCS64
	Slot_Mgr_Proc_t_64 *procp;
#else
	Slot_Mgr_Proc_t *procp;
#endif
#endif

	TRACE_INFO("C_WaitForSlotEvent\n");

	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
#ifndef PLUGGABLE_TOKENS_SUPPORTED
	// Since there are no tokens which we support that have the
	// ability to create slot events, and slotd does not
	// fully support this (it needs to be aware of the functions exported
	// by an STDLL to poll the slot for a token event and this
	// has not been fully implemented at this time, although the
	// design and structure of the shared memory in slotd do.

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
#else
	//  Get the pointer to the process element..
	//  This could be done in a single line, but for readability we do it
	//  in 2 steps.

	shm = Anchor->SharedMemP;
	procp = &shm->proc_table[Anchor->MgrProcIndex];

	// Grab the mutex for the application in shared memory
	// Check the bit mask for non-zero.  If the bit mask is non-zero
	// find the first slot which is set and set the pSlot value
	// and return CKR_OK.

	// for now we will just lock the whole shared memory
	//  REally should be the procp->proc_mutex
	// but this is such an infrequent thing that we will simply get
	// the global shared memory lock
	ProcLock();
	if (procp->slotmap) {
		// find the first bit set
		// This will have to change if more than 32 slots ever get supported
		// including the test for a bit turned on..
		for (i = 0; NUMBER_SLOTS_MANAGED; i++) {
			if (procp->slotmap & (1 << i)) {
				break;
			}
		}
		*pSlot = i;	// set the flag
		ProcUnLock();
		return CKR_OK;
	} else {
		if (flags & CKF_DONT_BLOCK) {
			ProcUnLock();
			return CKR_NO_EVENT;
		} else {
			// WE need to
			// 1.  Set the blocking variable in the system map to true.
			// 2. clear the condition variable
			//
			//  Note:  for now we will just poll the bitmap every
			//  second or look for the error field to go to true.

			// Check first if we are already blocking on another thread
			// for this process.  According to the spec this behavior is undefined.
			// We will choose to fail the call.
			if (procp->blocking) {
				TRACE_DEVEL("WaitForSlot event called by process twice.\n");
				ProcUnLock();	// Unlock aftersetting
				TRACE_ERROR("%s\n",
					    ock_err(ERR_FUNCTION_FAILED));
				return CKR_FUNCTION_FAILED;
			}
			procp->error = 0;
			procp->blocking = 0x01;
			ProcUnLock();	// Unlock aftersetting

			// NOTE:  We need to have an asynchronous mechanism for
			// the slot manager to wake up anyone blocking on this.
			// But Since we are not supporting removable tokens, this
			// call should be almos never made.   It might be best to
			// return CKR_FUNCTION_UNSUPPORTED, but we'll wait and see.
			while (!procp->slotmap && !procp->error) {
				sleep(1);	// Note This is really bad form.  But what the heck
			}
			ProcLock();
			procp->blocking = 0;
			if (procp->error) {
				ProcUnLock();
				TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
				return CKR_GENERAL_ERROR;	// We bailed on this because we were terminating
				// General error should cause the calling thread to not try anything
				// else...  We need to look at how this holds up in practice.
			} else {	// must have fallen out of loop because of a slot getting an
				// event
				for (i = 0; NUMBER_SLOTS_MANAGED; i++) {
					if (procp->slotmap & (1 << i)) {
						break;
					}
				}
				*pSlot = i;	// set the flag
				ProcUnLock();
				return CKR_OK;
			}
		}
	}
#endif
}				// end of C_WaitForSlotEvent

//------------------------------------------------------------------------
// API function
// C_WrapKey
//------------------------------------------------------------------------
//  Netscape Required

CK_RV
C_WrapKey(CK_SESSION_HANDLE hSession,
	  CK_MECHANISM_PTR pMechanism,
	  CK_OBJECT_HANDLE hWrappingKey,
	  CK_OBJECT_HANDLE hKey,
	  CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	CK_RV rv;
	API_Slot_t *sltp;
	STDLL_FcnList_t *fcn;
	ST_SESSION_T rSession;

	TRACE_INFO("C_WrapKey\n");
	if (API_Initialized() == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}
	//   other pointers???

    if (!Valid_Session(hSession, &rSession)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        TRACE_ERROR("Session handle id: %lu\n", hSession);
        return CKR_SESSION_HANDLE_INVALID;
    }
    TRACE_INFO("Valid Session handle id: %lu\n", rSession.sessionh);

	sltp = &(Anchor->SltList[rSession.slotID]);
	if (sltp->DLLoaded == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if ((fcn = sltp->FcnList) == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_TOKEN_NOT_PRESENT));
		return CKR_TOKEN_NOT_PRESENT;
	}
	if (fcn->ST_WrapKey) {
		// Map the Session to the slot session
		rv = fcn->ST_WrapKey(sltp->TokData, &rSession, pMechanism,
				     hWrappingKey, hKey,
				     pWrappedKey, pulWrappedKeyLen);
		TRACE_DEVEL("fcn->ST_WrapKey returned: 0x%lx\n", rv);
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
		rv = CKR_FUNCTION_NOT_SUPPORTED;
	}
	return rv;

}

#ifdef __sun
#pragma init(api_init)
#else
void api_init(void) __attribute__ ((constructor));
#endif

void api_init(void)
{

	// Should only have to do the atfork stuff at load time...
	if (!Initialized) {
		pthread_atfork(NULL, NULL, (void (*)())child_fork_initializer);
		Initialized = 1;
	}

}

#ifdef __sun
#pragma fini(api_fini)
#else
void api_fini(void) __attribute__ ((destructor));
#endif

void api_fini()
{
	if (API_Initialized() == TRUE) {
		Call_Finalize();
	}

}
