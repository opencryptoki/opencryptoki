/*
 * COPYRIGHT (c) International Business Machines Corp. 2015-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <time.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <syslog.h>

#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <grp.h>
#include <pwd.h>

#include "pkcs11types.h"
#include "stdll.h"

#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"
#include "trace.h"
#include "ep11_specific.h"

#include "../api/apiproto.h"

/* Declared in obj_mgr.c */
extern pthread_rwlock_t obj_list_rw_mutex;

void SC_SetFunctionList(void);

CK_ULONG  usage_count = 0;	/* track DLL usage */

void Fork_Initializer(void)
{

	/* Initialize spinlock. */
	XProcLock_Init();

	/* Force logout.  This cleans out the private session and list
	 * and cleans out the private object map
	 */
	session_mgr_logout_all(NULL);

	/* Clean out the public object map
	 * First parm is no longer used..
	 */
	object_mgr_purge_map(NULL, (SESSION *)0xFFFF, PUBLIC);
	object_mgr_purge_map(NULL, (SESSION *)0xFFFF, PRIVATE);

	/* This should clear the entire session list out */
	session_mgr_close_all_sessions();

	/* Clean out the global login state variable
	 * When implemented...  Although logout_all should clear this up.
	 */

	bt_destroy(&priv_token_obj_btree, call_free);
	bt_destroy(&publ_token_obj_btree, call_free);

	/* Need to do something to prevent the shared memory from
	 * having the objects loaded again.... The most likely place
	 * is in the obj_mgr file where the object is added to shared
	 * memory (object_mgr_add_to_shm) a query should be done to
	 * the appropriate object list....
	 */
}

/* verify that the mech specified is in the
 * mech list for this token...
 */
CK_RV valid_mech(STDLL_TokData_t *tokdata, CK_MECHANISM_PTR m, CK_FLAGS f)
{
	CK_RV rc;
	CK_MECHANISM_INFO info;

	if (m) {
		memset(&info, 0, sizeof(info));
		rc = ep11tok_get_mechanism_info(tokdata, m->mechanism, &info);
		if (rc != CKR_OK || !(info.flags & (f)))
			return CKR_MECHANISM_INVALID;
	}
	return CKR_OK;
}


/* In an STDLL this is called once for each card in the system
 * therefore the initialized only flags certain one time things.
 */
CK_RV ST_Initialize(API_Slot_t *sltp, CK_SLOT_ID SlotNumber,
		    SLOT_INFO *sinfp, struct trace_handle_t t)
{
	CK_RV rc = CKR_OK;
	char abs_tokdir_name[PATH_MAX];

	if ((rc = check_user_and_group()) != CKR_OK)
		return rc;

	/* assume that the upper API prevents multiple calls of initialize
	 * since that only happens on C_Initialize and that is the
	 * resonsibility of the upper layer..
	 */

	/* If we're not already initialized, grab the mutex and do the
	 * initialization.  Check to see if another thread did so while we
	 * were waiting...
	 *
	 * One of the things we do during initialization is create the mutex
	 * for PKCS#11 operations; until we do so, we have to use the native
	 * mutex...
	 */
	if (pthread_mutex_lock(&native_mutex)) {
		rc = CKR_FUNCTION_FAILED;
		TRACE_ERROR("Failed to lock mutex.\n");
	}

	/* SAB need to call Fork_Initializer here
	 * instead of at the end of the loop...
	 * it may also need to call destroy of the following 3 mutexes..
	 * it may not matter...
	 */
	Fork_Initializer();

	/* set trace info */
	set_trace(t);

	MY_CreateMutex(&pkcs_mutex);
	MY_CreateMutex(&obj_list_mutex);
	if (pthread_rwlock_init(&obj_list_rw_mutex, NULL)) {
		TRACE_ERROR("Mutex lock failed.\n");
	}
	MY_CreateMutex(&sess_list_mutex);
	MY_CreateMutex(&login_mutex);

	/* Create lockfile */
	if (CreateXProcLock(sinfp->tokname) != CKR_OK) {
		TRACE_ERROR("Process lock failed.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/*
	 * Create separate memory area for each token specific data
	 */
	sltp->TokData = (STDLL_TokData_t *)calloc(1, sizeof(STDLL_TokData_t));
	if (!sltp->TokData) {
		TRACE_ERROR("Allocating host memory failed.\n");
		goto done;
	}

	if (strlen(sinfp->tokname)) {
		sprintf(abs_tokdir_name,"%s/%s", CONFIG_PATH, sinfp->tokname);
		TRACE_DEVEL("Token directory: %s\n", abs_tokdir_name);
		init_data_store((char *)abs_tokdir_name, sltp->TokData->data_store);
	}
	else
		init_data_store((char *)PK_DIR, sltp->TokData->data_store);

	/* Handle global initialization issues first if we have not
	 * been initialized.
	 */
	if (sltp->TokData->initialized == FALSE) {

		rc = attach_shm(SlotNumber, &(sltp->TokData->global_shm));
		if (rc != CKR_OK) {
			TRACE_ERROR("Could not attach to shared memory.\n");
			goto done;
		}

		sltp->TokData->nv_token_data = &(sltp->TokData->global_shm->nv_token_data);
		SC_SetFunctionList();

		rc =  ep11tok_init(sltp->TokData, SlotNumber, sinfp->confname);
		if (rc != 0) {
			sltp->FcnList = NULL;
			if (sltp->TokData)
				free(sltp->TokData);
			sltp->TokData = NULL;
			TRACE_DEVEL("Token Specific Init failed.\n");
			goto done;
		}
		sltp->TokData->initialized = TRUE;
	}

	rc = load_token_data(sltp->TokData, SlotNumber);
	if (rc != CKR_OK) {
		sltp->FcnList = NULL;
		if (sltp->TokData)
			free(sltp->TokData);
		sltp->TokData = NULL;
		TRACE_DEVEL("Failed to load token data. (rc=0x%02lx)\n", rc);
		goto done;
	}

	/* no need to return error here, we load the token data we can
	 * and syslog the rest
	 */
	load_public_token_objects(sltp->TokData);

	XProcLock();
	sltp->TokData->global_shm->publ_loaded = TRUE;
	XProcUnLock();

	init_slotInfo(&(sltp->TokData->slot_info));

	usage_count++;
	(sltp->FcnList) = &function_list;

done:
	if (pthread_mutex_unlock(&native_mutex)) {
		TRACE_ERROR("Failed to unlock mutex.\n");
		rc = CKR_FUNCTION_FAILED;
	}
	return rc;
}

/* What does this really have to do in this new token...  probably
 * need to close the adapters that are opened, and clear the other
 * stuff
 */
CK_RV SC_Finalize(STDLL_TokData_t *tokdata, CK_SLOT_ID sid, SLOT_INFO *sinfp)
{
	CK_RV rc;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	/* If somebody else has taken care of things, leave... */
	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	__transaction_atomic { /* start transaction */
		usage_count--;
		if (usage_count == 0) {
			tokdata->initialized = FALSE;
		}
	} /* end transaction */

	session_mgr_close_all_sessions();
	object_mgr_purge_token_objects(tokdata);
	detach_shm(tokdata->global_shm);
	/* close spin lock file	*/
	CloseXProcLock();
	rc = ep11tok_final(tokdata);
	if (rc != CKR_OK) {
		TRACE_ERROR("Token specific final call failed.\n");
		return rc;
	}

	if (tokdata)
		free(tokdata);

	return rc;
}

CK_RV SC_GetTokenInfo(STDLL_TokData_t *tokdata, CK_SLOT_ID sid,
		      CK_TOKEN_INFO_PTR pInfo)
{
	CK_RV rc = CKR_OK;
	time_t now;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	if (!pInfo) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	if (sid > MAX_SLOT_ID) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		rc = CKR_SLOT_ID_INVALID;
		goto done;
	}
	copy_token_contents_sensibly(pInfo, tokdata->nv_token_data);

	/* Set the time	*/
	now = time ((time_t *)NULL);
	strftime((char *)pInfo->utcTime, 16, "%X", localtime(&now));

done:
	TRACE_INFO("C_GetTokenInfo: rc = 0x%08lx\n", rc);
	return rc;
}

CK_RV SC_WaitForSlotEvent(STDLL_TokData_t *tokdata, CK_FLAGS flags,
			  CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved)
{
	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}

/*
 * Get the mechanism type list for the current token.
 */
CK_RV SC_GetMechanismList(STDLL_TokData_t *tokdata, CK_SLOT_ID sid,
			  CK_MECHANISM_TYPE_PTR pMechList,
                          CK_ULONG_PTR count)
{
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto out;
	}
	if (count == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto out;
	}
	if (sid > MAX_SLOT_ID) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		rc = CKR_SLOT_ID_INVALID;
		goto out;
	}

	rc = ep11tok_get_mechanism_list(tokdata, pMechList, count);
	if (rc == CKR_OK) {
		/* To accomodate certain special cases, we may need to
		 * make adjustments to the token's mechanism list.
		 */
		mechanism_list_transformations(pMechList, count);
	}
out:
	TRACE_INFO("C_GetMechanismList:  rc = 0x%08lx, # mechanisms: %lu\n",
		    rc, *count);
	return rc;
}

/*
 * Get the mechanism info for the current type and token.
 */
CK_RV SC_GetMechanismInfo(STDLL_TokData_t *tokdata, CK_SLOT_ID sid,
			  CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo)
{
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto out;
	}
	if (pInfo == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto out;
	}
	if (sid > MAX_SLOT_ID) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		rc = CKR_SLOT_ID_INVALID;
		goto out;
	}

	rc = ep11tok_get_mechanism_info(tokdata, type, pInfo);
out:
	TRACE_INFO("C_GetMechanismInfo: rc = 0x%08lx, mech type = 0x%08lx\n",
		     rc, type);

	return rc;
}

/*
 * This routine should only be called if no other processes are
 * attached to the token.  we need to somehow check that this is the
 * only process Meta API should prevent this since it knows session
 * states in the shared memory.
*/
CK_RV SC_InitToken(STDLL_TokData_t *tokdata, CK_SLOT_ID sid, CK_CHAR_PTR pPin,
		   CK_ULONG ulPinLen, CK_CHAR_PTR pLabel)
{
	CK_RV rc = CKR_OK;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	if (!pPin || !pLabel) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	if (tokdata->nv_token_data->token_info.flags & CKF_SO_PIN_LOCKED) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_LOCKED));
		rc = CKR_PIN_LOCKED;
		goto done;
	}

	rc = compute_sha1(tokdata, pPin, ulPinLen, hash_sha);
	if (memcmp(tokdata->nv_token_data->so_pin_sha, hash_sha, SHA1_HASH_SIZE) != 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
		rc = CKR_PIN_INCORRECT;
		goto done;
	}

	/* Before we reconstruct all the data, we should delete the
	 * token objects from the filesystem.
	 */
	object_mgr_destroy_token_objects(tokdata);
	delete_token_data(tokdata);

	init_token_data(tokdata, sid);
	init_slotInfo(&(tokdata->slot_info));
	memcpy(tokdata->nv_token_data->so_pin_sha, hash_sha, SHA1_HASH_SIZE);
	tokdata->nv_token_data->token_info.flags |= CKF_TOKEN_INITIALIZED;
	memcpy(tokdata->nv_token_data->token_info.label, pLabel, 32);

	rc = save_token_data(tokdata, sid);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Failed to save token data.\n");
		goto done;
	}
done:
	TRACE_INFO("C_InitToken: rc = 0x%08lx\n", rc);
	return rc;
}


CK_RV SC_InitPIN(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		 CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	SESSION *sess = NULL;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	CK_BYTE hash_md5[MD5_HASH_SIZE];
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	if (!pPin) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}
	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	if (pin_locked(&sess->session_info,
		       tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_LOCKED));
		rc = CKR_PIN_LOCKED;
		goto done;
	}
	if (sess->session_info.state != CKS_RW_SO_FUNCTIONS) {
		TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
		rc = CKR_USER_NOT_LOGGED_IN;
		goto done;
	}

	if ((ulPinLen < MIN_PIN_LEN) || (ulPinLen > MAX_PIN_LEN)) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_LEN_RANGE));
		rc = CKR_PIN_LEN_RANGE;
		goto done;
	}
	/* compute the SHA and MD5 hashes of the user pin */
	rc  = compute_sha1(tokdata, pPin, ulPinLen, hash_sha);
	rc |= compute_md5( tokdata, pPin, ulPinLen, hash_md5 );
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to compute sha or md5 for user pin.\n");
		goto done;
	}
	rc = XProcLock();
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to get process lock.\n");
		goto done;
	}
	memcpy(tokdata->nv_token_data->user_pin_sha, hash_sha, SHA1_HASH_SIZE);
	tokdata->nv_token_data->token_info.flags |= CKF_USER_PIN_INITIALIZED;
	tokdata->nv_token_data->token_info.flags &= ~(CKF_USER_PIN_TO_BE_CHANGED);
	tokdata->nv_token_data->token_info.flags &= ~(CKF_USER_PIN_LOCKED);
	XProcUnLock();
	memcpy(tokdata->nv_token_data->user_pin_md5, hash_md5, MD5_HASH_SIZE);
	rc = save_token_data(tokdata, sess->session_info.slotID);
	if (rc != CKR_OK) {
		TRACE_DEVEL("Failed to save token data.\n");
		goto done;
	}
	rc = save_masterkey_user(tokdata);
	if (rc != CKR_OK)
		TRACE_DEVEL("Failed to save user's masterkey.\n");

done:
	TRACE_INFO("C_InitPin: rc = 0x%08lx, session = %lu\n",
		   rc, sSession->sessionh);
	return rc;
}

CK_RV SC_SetPIN(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession, CK_CHAR_PTR pOldPin,
		CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	SESSION *sess = NULL;
	CK_BYTE old_hash_sha[SHA1_HASH_SIZE];
	CK_BYTE new_hash_sha[SHA1_HASH_SIZE];
	CK_BYTE hash_md5[MD5_HASH_SIZE];
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	if (pin_locked(&sess->session_info,
		       tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_LOCKED));
		rc = CKR_PIN_LOCKED;
		goto done;
	}

	/* Check if token has a specific handler for this, otherwise fall back
	 * to default behaviour.
	 */

	if ((ulNewLen < MIN_PIN_LEN) || (ulNewLen > MAX_PIN_LEN)) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_LEN_RANGE));
		rc = CKR_PIN_LEN_RANGE;
		goto done;
	}
	rc = compute_sha1(tokdata, pOldPin, ulOldLen, old_hash_sha);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to compute sha for old pin.\n");
		goto done;
	}
	/* From the PKCS#11 2.20 spec: "C_SetPIN modifies the PIN of
	 * the user that is currently logged in, or the CKU_USER PIN
	 * if the session is not logged in."  A non R/W session fails
	 * with CKR_SESSION_READ_ONLY.
	 */
	if ((sess->session_info.state == CKS_RW_USER_FUNCTIONS) ||
	    (sess->session_info.state == CKS_RW_PUBLIC_SESSION)) {
		if (memcmp(tokdata->nv_token_data->user_pin_sha, old_hash_sha,
			   SHA1_HASH_SIZE) != 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
			rc = CKR_PIN_INCORRECT;
			goto done;
		}
		rc  = compute_sha1(tokdata, pNewPin, ulNewLen, new_hash_sha);
		rc |= compute_md5(tokdata, pNewPin, ulNewLen, hash_md5);
		if (rc != CKR_OK) {
			TRACE_ERROR("Failed to compute hash for new pin.\n");
			goto done;
		}
		/* The old PIN matches, now make sure its different
		 * than the new and is not the default. */
		if ((memcmp(old_hash_sha, new_hash_sha, SHA1_HASH_SIZE) == 0) ||
		    (memcmp(new_hash_sha, default_user_pin_sha, SHA1_HASH_SIZE)
		     == 0)) {
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INVALID));
			rc = CKR_PIN_INVALID;
			goto done;
		}
		rc = XProcLock();
		if (rc != CKR_OK) {
			TRACE_DEVEL("Failed to get process lock.\n");
			goto done;
		}
		memcpy(tokdata->nv_token_data->user_pin_sha, new_hash_sha,
		       SHA1_HASH_SIZE);
		memcpy(tokdata->nv_token_data->user_pin_md5, hash_md5,
		       MD5_HASH_SIZE);
		tokdata->nv_token_data->token_info.flags &=
			~(CKF_USER_PIN_TO_BE_CHANGED);
		XProcUnLock();
		rc = save_token_data(tokdata, sess->session_info.slotID);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Failed to save token data.\n");
			goto done;
		}
		rc = save_masterkey_user(tokdata);
	} else if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
		if (memcmp(tokdata->nv_token_data->so_pin_sha, old_hash_sha,
			   SHA1_HASH_SIZE) != 0) {
			rc = CKR_PIN_INCORRECT;
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
			goto done;
		}
		rc = compute_sha1(tokdata, pNewPin, ulNewLen, new_hash_sha);
		rc |= compute_md5(tokdata, pNewPin, ulNewLen, hash_md5);
		if (rc != CKR_OK) {
			TRACE_ERROR("Failed to compute hash for new pin.\n");
			goto done;
		}
		/* The old PIN matches, now make sure its different
		 * than the new and is not the default.
		 */
		if ((memcmp(old_hash_sha, new_hash_sha, SHA1_HASH_SIZE) == 0) ||
		    (memcmp(new_hash_sha, default_so_pin_sha, SHA1_HASH_SIZE)
		     == 0)) {
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INVALID));
			rc = CKR_PIN_INVALID;
			goto done;
		}
		rc = XProcLock();
		if (rc != CKR_OK) {
			TRACE_DEVEL("Failed to get process lock.\n");
			goto done;
		}
		memcpy(tokdata->nv_token_data->so_pin_sha, new_hash_sha, SHA1_HASH_SIZE);
		memcpy(tokdata->nv_token_data->so_pin_md5, hash_md5, MD5_HASH_SIZE);
		tokdata->nv_token_data->token_info.flags &= ~(CKF_SO_PIN_TO_BE_CHANGED);
		XProcUnLock();
		rc = save_token_data(tokdata, sess->session_info.slotID);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Failed to save token data.\n");
			goto done;
		}
		rc = save_masterkey_so(tokdata);
		if (rc != CKR_OK)
			TRACE_DEVEL("Failed to save SO's masterkey.\n");
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
		rc = CKR_SESSION_READ_ONLY;
	}
done:
	TRACE_INFO("C_SetPin: rc = 0x%08lx, session = %lu\n",
		   rc, sSession->sessionh);
	return rc;
}

CK_RV SC_OpenSession(STDLL_TokData_t *tokdata, CK_SLOT_ID sid, CK_FLAGS flags,
		     CK_SESSION_HANDLE_PTR phSession)
{
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	if (phSession == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}
	if (sid > MAX_SLOT_ID) {
		TRACE_ERROR("%s\n", ock_err(ERR_SLOT_ID_INVALID));
		return CKR_SLOT_ID_INVALID;
	}
	flags |= CKF_SERIAL_SESSION;
	if ((flags & CKF_RW_SESSION) == 0) {
		if (session_mgr_so_session_exists()) {
			TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_WRITE_SO_EXISTS));
			return CKR_SESSION_READ_WRITE_SO_EXISTS;
		}
	}
	rc = session_mgr_new(flags, sid, phSession);
	if (rc != CKR_OK) {
		TRACE_DEVEL("session_mgr_new() failed\n");
		return rc;
	}

	TRACE_INFO("C_OpenSession: rc = 0x%08lx\n", rc);
	return rc;
}

CK_RV SC_CloseSession(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession)
{
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	rc = session_mgr_close_session(tokdata, sSession->sessionh);
done:
	TRACE_INFO("C_CloseSession: rc = 0x%08lx  sess = %lu\n",
		   rc, sSession->sessionh);
	return rc;
}

CK_RV SC_CloseAllSessions(STDLL_TokData_t *tokdata, CK_SLOT_ID sid)
{
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	rc = session_mgr_close_all_sessions();
	if (rc != CKR_OK)
		TRACE_DEVEL("session_mgr_close_all_sessions() failed.\n");
done:
	TRACE_INFO("C_CloseAllSessions: rc = 0x%08lx slot = %lu\n", rc, sid);
	return rc;
}

CK_RV SC_GetSessionInfo(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
			CK_SESSION_INFO_PTR pInfo)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pInfo) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	memcpy(pInfo, &sess->session_info, sizeof(CK_SESSION_INFO));

done:
	TRACE_INFO("C_GetSessionInfo: session = %lu\n", sSession->sessionh);
	return rc;
}

CK_RV SC_GetOperationState(STDLL_TokData_t *tokdata,
			   ST_SESSION_HANDLE *sSession,
			   CK_BYTE_PTR pOperationState,
			   CK_ULONG_PTR pulOperationStateLen)
{
	SESSION *sess = NULL;
	CK_BBOOL length_only = FALSE;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pulOperationStateLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	if (!pOperationState)
		length_only = TRUE;

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = session_mgr_get_op_state(sess, length_only, pOperationState,
				      pulOperationStateLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("session_mgr_get_op_state() failed.\n");
done:
	TRACE_INFO("C_GetOperationState: rc = 0x%08lx, session = %lu\n",
		   rc, sSession->sessionh);
	return rc;
}


CK_RV SC_SetOperationState(STDLL_TokData_t *tokdata,
			   ST_SESSION_HANDLE *sSession,
			   CK_BYTE_PTR pOperationState,
			   CK_ULONG ulOperationStateLen,
			   CK_OBJECT_HANDLE hEncryptionKey,
			   CK_OBJECT_HANDLE hAuthenticationKey)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pOperationState || (ulOperationStateLen == 0)) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = session_mgr_set_op_state(sess, hEncryptionKey, hAuthenticationKey,
				      pOperationState, ulOperationStateLen);

	if (rc != CKR_OK)
		TRACE_DEVEL("session_mgr_set_op_state() failed.\n");
done:
	TRACE_INFO("C_SetOperationState: rc = 0x%08lx, session = %lu\n",
		   rc, sSession->sessionh);
	return rc;
}


CK_RV SC_Login(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
	       CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	SESSION *sess = NULL;
	CK_FLAGS_32 *flags = NULL;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	CK_RV rc = CKR_OK;

	/* In v2.11, logins should be exclusive, since token
	 * specific flags may need to be set for a bad login. - KEY
	 */
	rc = MY_LockMutex(&login_mutex);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to get mutex lock.\n");
		return CKR_FUNCTION_FAILED;
	}

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	flags = &tokdata->nv_token_data->token_info.flags;

	if (!pPin || ulPinLen > MAX_PIN_LEN) {
		set_login_flags(userType, flags);
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
		rc = CKR_PIN_INCORRECT;
		goto done;
	}

	/* PKCS #11 v2.01 requires that all sessions have the same login status:
	 * --> all sessions are public, all are SO or all are USER
	 */
	if (userType == CKU_USER) {
		if (session_mgr_so_session_exists()) {
			TRACE_ERROR("%s\n",
				   ock_err(ERR_USER_ANOTHER_ALREADY_LOGGED_IN));
			rc = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		}
		if (session_mgr_user_session_exists()) {
			TRACE_ERROR("%s\n",ock_err(ERR_USER_ALREADY_LOGGED_IN));
			rc = CKR_USER_ALREADY_LOGGED_IN;
		}
	}
	else if (userType == CKU_SO) {
		if (session_mgr_user_session_exists()) {
			TRACE_ERROR("%s\n",
				   ock_err(ERR_USER_ANOTHER_ALREADY_LOGGED_IN));
			rc = CKR_USER_ANOTHER_ALREADY_LOGGED_IN;
		}
		if (session_mgr_so_session_exists()) {
			TRACE_ERROR("%s\n",ock_err(ERR_USER_ALREADY_LOGGED_IN));
			rc = CKR_USER_ALREADY_LOGGED_IN;
		}
		if (session_mgr_readonly_session_exists()) {
			TRACE_ERROR("%s\n",
				    ock_err(ERR_SESSION_READ_ONLY_EXISTS));
			rc = CKR_SESSION_READ_ONLY_EXISTS;
		}
	}
	else {
		rc = CKR_USER_TYPE_INVALID;
		TRACE_ERROR("%s\n", ock_err(ERR_USER_TYPE_INVALID));
	}
	if (rc != CKR_OK)
		goto done;


	if (userType == CKU_USER) {
		if (*flags & CKF_USER_PIN_LOCKED) {
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_LOCKED));
			rc = CKR_PIN_LOCKED;
			goto done;
		}

		if (memcmp(tokdata->nv_token_data->user_pin_sha,
			   "00000000000000000000", SHA1_HASH_SIZE) == 0) {
			TRACE_ERROR("%s\n",
				    ock_err(ERR_USER_PIN_NOT_INITIALIZED));
			rc = CKR_USER_PIN_NOT_INITIALIZED;
			goto done;
		}

		rc = compute_sha1(tokdata, pPin, ulPinLen, hash_sha);
		if (memcmp(tokdata->nv_token_data->user_pin_sha, hash_sha,
			   SHA1_HASH_SIZE) != 0) {
			set_login_flags(userType, flags);
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
			rc = CKR_PIN_INCORRECT;
			goto done;
		}
		/* Successful login, clear flags */
		*flags &=	~(CKF_USER_PIN_LOCKED |
				  CKF_USER_PIN_FINAL_TRY |
				  CKF_USER_PIN_COUNT_LOW);

		compute_md5(tokdata, pPin, ulPinLen,
			    tokdata->nv_token_data->user_pin_md5);
		memset(tokdata->nv_token_data->so_pin_md5, 0x0, MD5_HASH_SIZE);

		rc = load_masterkey_user(tokdata);
		if (rc != CKR_OK){
			TRACE_DEVEL("Failed to load user's masterkey.\n");
			goto done;
		}

		/* no need to return error here, we load the token data
		 * we can and syslog the rest
		 */
		load_private_token_objects(tokdata);

		XProcLock();
		tokdata->global_shm->priv_loaded = TRUE;
		XProcUnLock();
	} else {
		if (*flags & CKF_SO_PIN_LOCKED) {
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_LOCKED));
			rc = CKR_PIN_LOCKED;
			goto done;
		}

		rc = compute_sha1(tokdata, pPin, ulPinLen, hash_sha);
		if (memcmp(tokdata->nv_token_data->so_pin_sha, hash_sha,
			   SHA1_HASH_SIZE) != 0) {
			set_login_flags(userType, flags);
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
			rc = CKR_PIN_INCORRECT;
			goto done;
		}
		/* Successful login, clear flags */
		*flags &= ~(CKF_SO_PIN_LOCKED | CKF_SO_PIN_FINAL_TRY |
			    CKF_SO_PIN_COUNT_LOW);

		compute_md5(tokdata, pPin, ulPinLen,
			    tokdata->nv_token_data->so_pin_md5);
		memset(tokdata->nv_token_data->user_pin_md5, 0x0, MD5_HASH_SIZE);

		rc = load_masterkey_so(tokdata);
		if (rc != CKR_OK)
			TRACE_DEVEL("Failed to load SO's masterkey.\n");
	}
done:
	if (rc == CKR_OK) {
		rc = session_mgr_login_all(tokdata, userType);
		if (rc != CKR_OK)
			TRACE_DEVEL("session_mgr_login_all failed.\n");
	}

	TRACE_INFO("C_Login: rc = 0x%08lx\n", rc);
	save_token_data(tokdata, sess->session_info.slotID);
	MY_UnlockMutex(&login_mutex);
	return rc;
}


CK_RV SC_Logout(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	/* all sessions have the same state so we just have to check one */
	if (session_mgr_public_session_exists()) {
		TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
		rc = CKR_USER_NOT_LOGGED_IN;
		goto done;
	}

	rc = session_mgr_logout_all(tokdata);
	if (rc != CKR_OK)
		TRACE_DEVEL("session_mgr_logout_all failed.\n");

	memset(tokdata->nv_token_data->user_pin_md5, 0x0, MD5_HASH_SIZE);
	memset(tokdata->nv_token_data->so_pin_md5, 0x0, MD5_HASH_SIZE);

	object_mgr_purge_private_token_objects(tokdata);

done:
	TRACE_INFO("C_Logout: rc = 0x%08lx\n", rc);
	return rc;
}


CK_RV SC_CreateObject(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		      CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
		      CK_OBJECT_HANDLE_PTR phObject)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags)) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = object_mgr_add(tokdata, sess, pTemplate, ulCount, phObject);
	if (rc != CKR_OK)
		TRACE_DEVEL("object_mgr_add() failed.\n");

done:
	TRACE_INFO("C_CreateObject: rc = 0x%08lx\n", rc);

#ifdef DEBUG
	int i;

	for (i = 0; i < ulCount; i++) {
		if (pTemplate[i].type == CKA_CLASS) {
			TRACE_DEBUG("Object Type:  0x%02lx\n",
				      *((CK_ULONG *) pTemplate[i].pValue));
		}
	}
	if (rc == CKR_OK)
		TRACE_DEBUG("Handle: %lu\n", *phObject);
#endif

	return rc;
}


CK_RV  SC_CopyObject(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		     CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
		     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = object_mgr_copy(tokdata, sess, pTemplate, ulCount, hObject,
			     phNewObject);
	if (rc != CKR_OK)
		TRACE_DEVEL("object_mgr_copy() failed\n");

done:
	TRACE_INFO("C_CopyObject:rc = 0x%08lx,old handle = %lu, "
		   "new handle = %lu\n", rc, hObject, *phNewObject);
	return rc;
}


CK_RV SC_DestroyObject(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		       CK_OBJECT_HANDLE hObject)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = object_mgr_destroy_object(tokdata, sess, hObject);
	if (rc != CKR_OK)
		TRACE_DEVEL("*_destroy_object() failed\n");
done:
	TRACE_INFO("C_DestroyObject: rc = 0x%08lx, handle = %lu\n", rc, hObject);
	return rc;
}


CK_RV SC_GetObjectSize(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		       CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = object_mgr_get_object_size(tokdata, hObject, pulSize);
	if (rc != CKR_OK)
		TRACE_ERROR("object_mgr_get_object_size() failed.\n");

done:
	TRACE_INFO("C_GetObjectSize: rc = 0x%08lx, handle = %lu\n", rc, hObject);
	return rc;
}


CK_RV SC_GetAttributeValue(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
			   CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
			   CK_ULONG ulCount)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = object_mgr_get_attribute_values(tokdata, sess, hObject, pTemplate,
					     ulCount);
	if (rc != CKR_OK)
		TRACE_DEVEL("obj_mgr_get_attribute_value() failed.\n");

done:
	TRACE_INFO("C_GetAttributeValue: rc = 0x%08lx, handle = %lu\n",
		    rc, hObject);

#ifdef DEBUG
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE *ptr = NULL;
	int i;

	attr = pTemplate;
	for (i = 0; i < ulCount; i++, attr++) {
		ptr = (CK_BYTE *)attr->pValue;

		TRACE_DEBUG("%d: Attribute type: 0x%08lx, Value Length: %lu\n",
			    i, attr->type, attr->ulValueLen);

		if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
			TRACE_DEBUG("First 4 bytes: %02x %02x %02x %02x\n",
				    ptr[0], ptr[1], ptr[2], ptr[3]);
	}
#endif
	return rc;
}


CK_RV SC_SetAttributeValue(STDLL_TokData_t *tokdata,
			   ST_SESSION_HANDLE *sSession,
			   CK_OBJECT_HANDLE hObject,
			   CK_ATTRIBUTE_PTR pTemplate,
			   CK_ULONG ulCount)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = object_mgr_set_attribute_values(tokdata, sess, hObject, pTemplate,
					     ulCount);
	if (rc != CKR_OK)
		TRACE_DEVEL("obj_mgr_set_attribute_values() failed.\n");

done:
	TRACE_INFO("C_SetAttributeValue: rc = 0x%08lx, handle = %lu\n",
		   rc, hObject);
#ifdef DEBUG
	CK_ATTRIBUTE *attr = NULL;
	int i;

	attr = pTemplate;
	for (i = 0; i < ulCount; i++, attr++) {
		CK_BYTE *ptr = (CK_BYTE *)attr->pValue;

		TRACE_DEBUG("%d: Attribute type: 0x%08lx, Value Length: %lu\n",
			     i, attr->type, attr->ulValueLen);

		if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
			TRACE_DEBUG("First 4 bytes: %02x %02x %02x %02x\n",
				     ptr[0], ptr[1], ptr[2], ptr[3]);
	}
#endif

	return rc;
}


CK_RV SC_FindObjectsInit(STDLL_TokData_t *tokdata,
			 ST_SESSION_HANDLE *sSession,
			 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->find_active == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = object_mgr_find_init(tokdata, sess, pTemplate, ulCount);

done:
	TRACE_INFO("C_FindObjectsInit:  rc = 0x%08lx\n", rc);

#ifdef DEBUG
	CK_ATTRIBUTE *attr = NULL;
	int i;

	attr = pTemplate;
	for (i = 0; i < ulCount; i++, attr++) {
		CK_BYTE *ptr = (CK_BYTE *)attr->pValue;

		TRACE_DEBUG("%d: Attribute type: 0x%08lx, Value Length: %lu\n",
			    i, attr->type, attr->ulValueLen);

		if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
			TRACE_DEBUG("First 4 bytes: %02x %02x %02x %02x\n",
				    ptr[0], ptr[1], ptr[2], ptr[3]);
	}
#endif

	return rc;
}


CK_RV SC_FindObjects(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		     CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
		     CK_ULONG_PTR pulObjectCount)
{
	SESSION *sess = NULL;
	CK_ULONG count = 0;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!phObject || !pulObjectCount) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->find_active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (!sess->find_list) {
		TRACE_DEVEL("sess->find_list is NULL.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	count = MIN(ulMaxObjectCount, (sess->find_count - sess->find_idx));

	memcpy(phObject, sess->find_list + sess->find_idx,
	       count * sizeof(CK_OBJECT_HANDLE));
	*pulObjectCount = count;

	sess->find_idx += count;
	rc = CKR_OK;

done:
	TRACE_INFO("C_FindObjects: rc = 0x%08lx, returned %lu objects\n",
		    rc, count);
	return rc;
}


CK_RV SC_FindObjectsFinal(STDLL_TokData_t *tokdata,
			  ST_SESSION_HANDLE *sSession)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->find_active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (sess->find_list)
		free(sess->find_list);

	sess->find_list = NULL;
	sess->find_len = 0;
	sess->find_idx = 0;
	sess->find_active = FALSE;

	rc = CKR_OK;

done:
	TRACE_INFO("C_FindObjectsFinal: rc = 0x%08lx\n", rc);
	return rc;
}


CK_RV SC_EncryptInit(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		     CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	rc = valid_mech(tokdata, pMechanism, CKF_ENCRYPT);
	if (rc != CKR_OK)
		goto done;

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->encr_ctx.active == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = ep11tok_encrypt_init(tokdata, sess, pMechanism, hKey);

done:
	TRACE_INFO("C_EncryptInit: rc = 0x%08lx, sess = %ld, mech = 0x%lx\n",
		   rc, (sess == NULL) ? -1 : (CK_LONG)sess->handle,
		   pMechanism->mechanism);

	return rc;
}


CK_RV SC_Encrypt(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		 CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		 CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen)
{
	SESSION *sess = NULL;
	CK_BBOOL length_only = FALSE;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pData || !pulEncryptedDataLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->encr_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (!pEncryptedData)
		length_only = TRUE;

	rc = ep11tok_encrypt(tokdata, sess, pData, ulDataLen, pEncryptedData,
			     pulEncryptedDataLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_encrypt() failed.\n");

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		encr_mgr_cleanup( &sess->encr_ctx );

	TRACE_INFO("C_Encrypt: rc = 0x%08lx, sess = %ld, amount = %lu\n",
		   rc, (sess == NULL) ? -1 : (CK_LONG)sess->handle, ulDataLen);

	return rc;
}


CK_RV SC_EncryptUpdate(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		       CK_BYTE_PTR pPart, CK_ULONG ulPartLen,
		       CK_BYTE_PTR pEncryptedPart,
		       CK_ULONG_PTR pulEncryptedPartLen)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if ((!pPart && ulPartLen != 0) || !pulEncryptedPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->encr_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	rc = ep11tok_encrypt_update(tokdata, sess, pPart, ulPartLen, pEncryptedPart,
				    pulEncryptedPartLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_encrypt_update() failed.\n");

done:
	if (rc != CKR_OK && rc != CKR_BUFFER_TOO_SMALL)
		encr_mgr_cleanup( &sess->encr_ctx );

	TRACE_INFO("C_EncryptUpdate: rc = 0x%08lx, sess = %ld, amount = %lu\n",
		   rc, (sess == NULL) ? -1 : (CK_LONG) sess->handle, ulPartLen);

	return rc;
}


CK_RV SC_EncryptFinal(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		      CK_BYTE_PTR pLastEncryptedPart,
		      CK_ULONG_PTR pulLastEncryptedPartLen)
{
	SESSION *sess = NULL;
	CK_BBOOL length_only = FALSE;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pulLastEncryptedPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->encr_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (!pLastEncryptedPart)
		length_only = TRUE;

	rc = ep11tok_encrypt_final(tokdata, sess, pLastEncryptedPart,
				   pulLastEncryptedPartLen);
	if (rc != CKR_OK)
		TRACE_ERROR("ep11tok_encrypt_final() failed.\n");

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		encr_mgr_cleanup( &sess->encr_ctx );

	TRACE_INFO("C_EncryptFinal: rc = 0x%08lx, sess = %ld\n",
		   rc, (sess == NULL) ? -1 : (CK_LONG) sess->handle);

	return rc;
}


CK_RV SC_DecryptInit(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		     CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	rc = valid_mech(tokdata, pMechanism, CKF_DECRYPT);
	if (rc != CKR_OK)
		goto done;

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->decr_ctx.active == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = ep11tok_decrypt_init(tokdata, sess, pMechanism, hKey);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_decrypt_init() failed.\n");

done:
	TRACE_INFO("C_DecryptInit: rc = 0x%08lx, sess = %ld, mech = 0x%lx\n",
		   rc, (sess == NULL) ? -1 : (CK_LONG)sess->handle,
		   pMechanism->mechanism);

	return rc;
}


CK_RV SC_Decrypt(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		 CK_BYTE_PTR pEncryptedData, CK_ULONG ulEncryptedDataLen,
		 CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	SESSION *sess = NULL;
	CK_BBOOL length_only = FALSE;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pEncryptedData || !pulDataLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->decr_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (!pData)
		length_only = TRUE;

	rc = ep11tok_decrypt(tokdata, sess, pEncryptedData, ulEncryptedDataLen,
			     pData, pulDataLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_decrypt() failed.\n");

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		decr_mgr_cleanup( &sess->decr_ctx );

	TRACE_INFO("C_Decrypt: rc = 0x%08lx, sess = %ld, amount = %lu\n",
		   rc, (sess == NULL) ? -1 : (CK_LONG)sess->handle,
		   ulEncryptedDataLen);

	return rc;
}


CK_RV SC_DecryptUpdate(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		       CK_BYTE_PTR pEncryptedPart, CK_ULONG ulEncryptedPartLen,
		       CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if ((!pEncryptedPart && ulEncryptedPartLen != 0) || !pulPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->decr_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	rc = ep11tok_decrypt_update(tokdata, sess, pEncryptedPart,
				    ulEncryptedPartLen, pPart, pulPartLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_decrypt_update() failed.\n");

done:
	if (rc != CKR_OK && rc != CKR_BUFFER_TOO_SMALL)
		decr_mgr_cleanup( &sess->decr_ctx );

	TRACE_INFO("C_DecryptUpdate: rc = 0x%08lx, sess = %ld, amount = %lu\n",
		   rc, (sess == NULL) ? -1 : (CK_LONG)sess->handle,
		   ulEncryptedPartLen);

	return rc;
}


CK_RV SC_DecryptFinal(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		      CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen)
{
	SESSION *sess = NULL;
	CK_BBOOL length_only = FALSE;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pulLastPartLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->decr_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (!pLastPart)
		length_only = TRUE;

	rc = ep11tok_decrypt_final(tokdata, sess, pLastPart, pulLastPartLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_decrypt_final() failed.\n");
done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		decr_mgr_cleanup( &sess->decr_ctx );

	TRACE_INFO("C_DecryptFinal:  rc = 0x%08lx, sess = %ld, amount = %lu\n",
		   rc, (sess == NULL) ? -1 : (CK_LONG)sess->handle,
		   *pulLastPartLen);

	return rc;
}


CK_RV SC_DigestInit(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		    CK_MECHANISM_PTR pMechanism)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	if (!pMechanism) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	rc = valid_mech(tokdata, pMechanism, CKF_DIGEST);
	if (rc != CKR_OK)
		goto done;

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->digest_ctx.active == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	rc = digest_mgr_init(tokdata, sess, &sess->digest_ctx, pMechanism);
	if (rc != CKR_OK)
		TRACE_DEVEL("digest_mgr_init() failed.\n");

done:
	TRACE_INFO("C_DigestInit: rc = 0x%08lx, sess = %ld, mech = 0x%lx\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle,
		   pMechanism->mechanism);

	return rc;
}


CK_RV SC_Digest(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pDigest,
		CK_ULONG_PTR pulDigestLen)
{
	SESSION *sess = NULL;
	CK_BBOOL length_only = FALSE;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	/* Netscape has been known to pass a null pData to DigestUpdate
	 * but never for Digest.  It doesn't really make sense to allow it here
	 */
	if (!pData || !pulDigestLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->digest_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (!pDigest)
		length_only = TRUE;

	rc = digest_mgr_digest(tokdata, sess, length_only, &sess->digest_ctx,
			       pData, ulDataLen, pDigest, pulDigestLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("digest_mgr_digest() failed.\n");

done:
	TRACE_INFO("C_Digest: rc = 0x%08lx, sess = %ld, datalen = %lu\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulDataLen);

	return rc;
}


CK_RV SC_DigestUpdate(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		      CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pPart && ulPartLen != 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->digest_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	/* If there is data to hash, do so. */
	if (ulPartLen) {
		rc = digest_mgr_digest_update(tokdata, sess, &sess->digest_ctx,
					      pPart, ulPartLen);
		if (rc != CKR_OK)
			TRACE_DEVEL("digest_mgr_digest_update() failed.\n");
	}
done:
	TRACE_INFO("C_DigestUpdate: rc = 0x%08lx, sess = %ld, datalen = %lu\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulPartLen);

	return rc;
}


CK_RV SC_DigestKey(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		   CK_OBJECT_HANDLE hKey)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->digest_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	rc = digest_mgr_digest_key(tokdata, sess, &sess->digest_ctx, hKey);
	if (rc != CKR_OK)
		TRACE_DEVEL("digest_mgr_digest_key() failed.\n");

done:
	TRACE_INFO("C_DigestKey: rc = 0x%08lx, sess = %ld, key = %lu\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle, hKey);

	return rc;
}


CK_RV SC_DigestFinal(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		     CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen)
{
	SESSION *sess = NULL;
	CK_BBOOL length_only = FALSE;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pulDigestLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->digest_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (!pDigest)
		length_only = TRUE;

	rc = digest_mgr_digest_final(tokdata, sess, length_only,
				     &sess->digest_ctx, pDigest,
				     pulDigestLen);
	if (rc != CKR_OK)
		TRACE_ERROR("digest_mgr_digest_final() failed.\n");

done:
	TRACE_INFO("C_DigestFinal: rc = 0x%08lx, sess = %ld\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle);

	return rc;
}


CK_RV SC_SignInit(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		  CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pMechanism ) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = valid_mech(tokdata, pMechanism, CKF_SIGN);
	if (rc != CKR_OK)
		goto done;

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->sign_ctx.active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
		goto done;
	}

	rc = ep11tok_sign_init(tokdata, sess, pMechanism, FALSE, hKey);
	if (rc != CKR_OK)
		TRACE_DEVEL("*_sign_init() failed.\n");

done:
	TRACE_INFO("C_SignInit: rc = 0x%08lx, sess = %ld, mech = 0x%lx\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle,
		   pMechanism->mechanism);

	return rc;
}


CK_RV SC_Sign(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
	      CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
	      CK_ULONG_PTR pulSignatureLen)
{
	SESSION *sess = NULL;
	CK_BBOOL length_only = FALSE;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pData || !pulSignatureLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->sign_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (!pSignature)
		length_only = TRUE;

	rc = ep11tok_sign(tokdata, sess, length_only, pData, ulDataLen, pSignature,
			  pulSignatureLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_sign() failed.\n");

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		sign_mgr_cleanup(&sess->sign_ctx);

	TRACE_INFO("C_Sign: rc = 0x%08lx, sess = %ld, datalen = %lu\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulDataLen);

	return rc;
}


CK_RV SC_SignUpdate(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		    CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pPart && ulPartLen != 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->sign_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	rc = ep11tok_sign_update(tokdata, sess, pPart, ulPartLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_sign_update() failed.\n");

done:
	if (rc != CKR_OK)
		sign_mgr_cleanup(&sess->sign_ctx);

	TRACE_INFO("C_SignUpdate: rc = 0x%08lx, sess = %ld, datalen = %lu\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulPartLen);

	return rc;
}


CK_RV SC_SignFinal(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		   CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{
	SESSION *sess = NULL;
	CK_BBOOL length_only = FALSE;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pulSignatureLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->sign_ctx.active == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		rc = CKR_OPERATION_NOT_INITIALIZED;
		goto done;
	}

	if (!pSignature)
		length_only = TRUE;

	rc = ep11tok_sign_final(tokdata, sess, length_only, pSignature,
				pulSignatureLen);
	if (rc != CKR_OK)
		TRACE_ERROR("ep11tok_sign_final() failed.\n");

done:
	if (rc != CKR_BUFFER_TOO_SMALL && (rc != CKR_OK || length_only != TRUE))
		sign_mgr_cleanup(&sess->sign_ctx);

	TRACE_INFO("C_SignFinal: rc = 0x%08lx, sess = %ld\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle);

	return rc;
}


CK_RV SC_SignRecoverInit(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
			 CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;

}


CK_RV SC_SignRecover(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		     CK_BYTE_PTR pData, CK_ULONG ulDataLen,
		     CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen)
{

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;

}


CK_RV SC_VerifyInit(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}
	if (!pMechanism ) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	rc = valid_mech(tokdata, pMechanism, CKF_VERIFY);
	if (rc != CKR_OK)
		goto done;

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	if (sess->verify_ctx.active == TRUE) {
		rc = CKR_OPERATION_ACTIVE;
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
		goto done;
	}

	rc = ep11tok_verify_init(tokdata, sess, pMechanism, FALSE, hKey);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_verify_init() failed.\n");

done:
	TRACE_INFO("C_VerifyInit: rc = 0x%08lx, sess = %ld, mech = 0x%lx\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle,
		   pMechanism->mechanism);

	return rc;
}


CK_RV SC_Verify(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		CK_BYTE_PTR pData, CK_ULONG ulDataLen, CK_BYTE_PTR pSignature,
		CK_ULONG ulSignatureLen)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pData || !pSignature) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->verify_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		goto done;
	}

	rc = ep11tok_verify(tokdata, sess, pData, ulDataLen, pSignature,
			    ulSignatureLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_verify() failed.\n");

done:
	verify_mgr_cleanup(&sess->verify_ctx);

	TRACE_INFO("C_Verify: rc = 0x%08lx, sess = %ld, datalen = %lu\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulDataLen);

	return rc;
}


CK_RV SC_VerifyUpdate(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		      CK_BYTE_PTR pPart, CK_ULONG ulPartLen)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pPart && ulPartLen != 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->verify_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		goto done;
	}

	rc = ep11tok_verify_update(tokdata, sess, pPart, ulPartLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_verify_update() failed.\n");

done:
	if (rc != CKR_OK)
		verify_mgr_cleanup(&sess->verify_ctx);

	TRACE_INFO("C_VerifyUpdate: rc = 0x%08lx, sess = %ld, datalen = %lu\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle, ulPartLen);

	return rc;
}


CK_RV SC_VerifyFinal(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		     CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pSignature) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (sess->verify_ctx.active == FALSE) {
		rc = CKR_OPERATION_NOT_INITIALIZED;
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
		goto done;
	}

	rc = ep11tok_verify_final(tokdata, sess, pSignature, ulSignatureLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_verify_final() failed.\n");

done:
	verify_mgr_cleanup(&sess->verify_ctx);

	TRACE_INFO("C_VerifyFinal: rc = 0x%08lx, sess = %ld\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle);

	return rc;
}


CK_RV SC_VerifyRecoverInit(STDLL_TokData_t *tokdata,
			   ST_SESSION_HANDLE *sSession,
			   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey)
{

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;

}


CK_RV SC_VerifyRecover(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		       CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen,
		       CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen)
{
	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV SC_DigestEncryptUpdate(STDLL_TokData_t *tokdata,
			     ST_SESSION_HANDLE *sSession, CK_BYTE_PTR pPart,
			     CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
			     CK_ULONG_PTR pulEncryptedPartLen)
{
	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV SC_DecryptDigestUpdate(STDLL_TokData_t *tokdata,
			     ST_SESSION_HANDLE *sSession,
			     CK_BYTE_PTR pEncryptedPart,
			     CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
			     CK_ULONG_PTR pulPartLen)
{
	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV SC_SignEncryptUpdate(STDLL_TokData_t *tokdata,
			   ST_SESSION_HANDLE *sSession, CK_BYTE_PTR pPart,
			   CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
			   CK_ULONG_PTR pulEncryptedPartLen)
{
	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV SC_DecryptVerifyUpdate(STDLL_TokData_t *tokdata,
			     ST_SESSION_HANDLE *sSession,
			     CK_BYTE_PTR pEncryptedPart,
			     CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
			     CK_ULONG_PTR pulPartLen)
{
	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_SUPPORTED));
	return CKR_FUNCTION_NOT_SUPPORTED;
}


CK_RV SC_GenerateKey(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		     CK_MECHANISM_PTR pMechanism, CK_ATTRIBUTE_PTR pTemplate,
		     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pMechanism || !phKey || (pTemplate == NULL && ulCount != 0)) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	rc = valid_mech(tokdata, pMechanism, CKF_GENERATE);
	if (rc != CKR_OK)
		goto done;

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = ep11tok_generate_key(tokdata, sess, pMechanism, pTemplate,
				  ulCount, phKey);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_generate_key() failed.\n");

done:
	TRACE_INFO("C_GenerateKey: rc = 0x%08lx, sess = %ld, mech = 0x%lx\n", rc,
		    (sess == NULL) ? -1 : (CK_LONG) sess->handle,
		    pMechanism->mechanism);

#ifdef DEBUG
	CK_ATTRIBUTE *attr = NULL;
	int i;

	attr = pTemplate;
	for (i = 0; i < ulCount; i++, attr++) {
		CK_BYTE *ptr = (CK_BYTE *) attr->pValue;
		TRACE_DEBUG("%d: Attribute type: 0x%08lx, Value Length: %lu\n",
			    i, attr->type, attr->ulValueLen);
		if (attr->ulValueLen != ((CK_ULONG) -1) && (ptr != NULL)) {
			TRACE_DEBUG("First 4 bytes: %02x %02x %02x %02x\n",
				    ptr[0], ptr[1], ptr[2], ptr[3]);
		}
	}
#endif

	return rc;
}


CK_RV SC_GenerateKeyPair(STDLL_TokData_t *tokdata,
			 ST_SESSION_HANDLE *sSession,
			 CK_MECHANISM_PTR pMechanism,
			 CK_ATTRIBUTE_PTR pPublicKeyTemplate,
			 CK_ULONG ulPublicKeyAttributeCount,
			 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
			 CK_ULONG ulPrivateKeyAttributeCount,
			 CK_OBJECT_HANDLE_PTR phPublicKey,
			 CK_OBJECT_HANDLE_PTR phPrivateKey)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pMechanism || !phPublicKey || !phPrivateKey ||
	   (!pPublicKeyTemplate && (ulPublicKeyAttributeCount != 0)) ||
	   (!pPrivateKeyTemplate && (ulPrivateKeyAttributeCount != 0))) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	rc = valid_mech(tokdata, pMechanism, CKF_GENERATE_KEY_PAIR);
	if (rc != CKR_OK)
		goto done;

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = ep11tok_generate_key_pair(tokdata, sess, pMechanism,
				       pPublicKeyTemplate,
				       ulPublicKeyAttributeCount,
				       pPrivateKeyTemplate,
				       ulPrivateKeyAttributeCount,
				       phPublicKey, phPrivateKey);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_generate_key_pair() failed.\n");

done:
	TRACE_INFO("C_GenerateKeyPair: rc = 0x%08lx, sess = %ld, mech = 0x%lx\n",
		   rc, (sess == NULL) ? -1 : ((CK_LONG) sess->handle),
		   pMechanism->mechanism);

#ifdef DEBUG
	CK_ATTRIBUTE *attr = NULL;
	int i;

	if (rc == CKR_OK) {
		TRACE_DEBUG("Public handle: %lu, Private handle: %lu\n",
			    *phPublicKey, *phPrivateKey);
	}

	TRACE_DEBUG("Public Template:\n");
	attr = pPublicKeyTemplate;
	for (i = 0; i < ulPublicKeyAttributeCount; i++, attr++) {
		CK_BYTE *ptr = (CK_BYTE *) attr->pValue;
		TRACE_DEBUG("%d: Attribute type: 0x%08lx, Value Length: %lu\n",
			    i, attr->type, attr->ulValueLen);
		if (attr->ulValueLen != ((CK_ULONG) -1) && (ptr != NULL))
			TRACE_DEBUG("First 4 bytes: %02x %02x %02x %02x\n",
				    ptr[0], ptr[1], ptr[2], ptr[3]);
	}

	TRACE_DEBUG("Private Template:\n");
	attr = pPublicKeyTemplate;
	for (i = 0; i < ulPublicKeyAttributeCount; i++, attr++) {
		CK_BYTE *ptr = (CK_BYTE *) attr->pValue;
		TRACE_DEBUG("%d: Attribute type: 0x%08lx, Value Length: %lu\n",
			    i, attr->type, attr->ulValueLen);
		if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
			TRACE_DEBUG("First 4 bytes: %02x %02x %02x %02x\n",
				    ptr[0], ptr[1], ptr[2], ptr[3]);
	}
#endif
	return rc;
}


CK_RV SC_WrapKey(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		 CK_MECHANISM_PTR pMechanism,
		 CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
		 CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pMechanism || !pulWrappedKeyLen) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	rc = valid_mech(tokdata, pMechanism, CKF_WRAP);
	if (rc != CKR_OK)
		goto done;

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = ep11tok_wrap_key(tokdata, sess, pMechanism, hWrappingKey, hKey,
			      pWrappedKey, pulWrappedKeyLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_wrap_key() failed.\n");

done:
	TRACE_INFO("C_WrapKey: rc = 0x%08lx, sess = %ld, encrypting key = %lu, "
		   "wrapped key = %lu\n", rc,
		   (sess == NULL) ? -1 : (CK_LONG) sess->handle,
		   hWrappingKey, hKey);

	return rc;
}


CK_RV SC_UnwrapKey(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		   CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
		   CK_ULONG ulWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
		   CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pMechanism || !pWrappedKey ||
	    (!pTemplate && ulCount != 0) || !phKey) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	rc = valid_mech(tokdata, pMechanism, CKF_UNWRAP);
	if (rc != CKR_OK)
		goto done;

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = ep11tok_unwrap_key(tokdata, sess, pMechanism, pTemplate, ulCount,
				pWrappedKey, ulWrappedKeyLen, hUnwrappingKey,
				phKey);
	if (rc != CKR_OK)
		TRACE_DEVEL("ep11tok_unwrap_key() failed.\n");

done:
	TRACE_INFO("C_UnwrapKey: rc = 0x%08lx, sess = %ld, decrypting key = %lu,"
		   "unwrapped key = %lu\n", rc,
		   (sess == NULL) ? -1 : (CK_LONG) sess->handle,
		   hUnwrappingKey, *phKey);

#ifdef DEBUG
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE *ptr = NULL;
	int i;

	attr = pTemplate;
	for (i = 0; i < ulCount; i++, attr++) {
		ptr = (CK_BYTE *)attr->pValue;
		TRACE_DEBUG("%d: Attribute type:  0x%08lx, Value Length: %lu\n",
			    i, attr->type, attr->ulValueLen);
		if (attr->ulValueLen != ((CK_ULONG) -1) && (ptr != NULL))
			TRACE_DEBUG("First 4 bytes:  %02x %02x %02x %02x\n",
				    ptr[0], ptr[1], ptr[2], ptr[3]);

	}
#endif
	return rc;
}


CK_RV SC_DeriveKey(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		   CK_MECHANISM_PTR pMechanism,
		   CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
		   CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pMechanism || !phKey || (!pTemplate && ulCount != 0)) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	rc = valid_mech(tokdata, pMechanism, CKF_DERIVE);
	if (rc != CKR_OK)
		goto done;

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	if (pin_expired(&sess->session_info,
			tokdata->nv_token_data->token_info.flags) == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_EXPIRED));
		rc = CKR_PIN_EXPIRED;
		goto done;
	}

	rc = ep11tok_derive_key(tokdata, sess, pMechanism, hBaseKey, phKey,
				pTemplate, ulCount);
	if (rc != CKR_OK)
		TRACE_DEVEL("epl11tok_derive_key() failed.\n");

done:
	TRACE_INFO("C_DeriveKey: rc = 0x%08lx, sess = %ld, mech = 0x%lx\n",
		   rc, (sess == NULL)?-1:(CK_LONG)sess->handle,
		   pMechanism->mechanism);
#ifdef DEBUG
	CK_ATTRIBUTE *attr = NULL;
	CK_BYTE *ptr = NULL;
	int i;

	if (rc == CKR_OK) {
		switch (pMechanism->mechanism) {
		case CKM_SSL3_KEY_AND_MAC_DERIVE:
		{
			CK_SSL3_KEY_MAT_PARAMS *pReq;
			CK_SSL3_KEY_MAT_OUT    *pPtr;
			pReq = (CK_SSL3_KEY_MAT_PARAMS *)pMechanism->pParameter;
			pPtr = pReq->pReturnedKeyMaterial;

			TRACE_DEBUG("Client MAC key: %lu, Server MAC key: %lu, "
				    "Client Key: %lu, Server Key: %lu\n",
				    pPtr->hClientMacSecret,
				    pPtr->hServerMacSecret, pPtr->hClientKey,
				    pPtr->hServerKey);
		}
		break;

		case CKM_DH_PKCS_DERIVE:
		{
			TRACE_DEBUG("DH Shared Secret:\n");
		}
		break ;

		default:
			TRACE_DEBUG("Derived key: %lu\n", *phKey);
		}
	}

	attr = pTemplate;
	for (i = 0; i < ulCount; i++, attr++) {
		ptr = (CK_BYTE *)attr->pValue;

		TRACE_DEBUG("%d: Attribute type: 0x%08lx, Value Length: %lu\n",
			    i, attr->type, attr->ulValueLen);

		if (attr->ulValueLen != (CK_ULONG)(-1) && (ptr != NULL))
			TRACE_DEBUG("First 4 bytes: %02x %02x %02x %02x\n",
				    ptr[0], ptr[1], ptr[2], ptr[3]);

	}

#endif /* DEBUG */

	return rc;
}


CK_RV SC_SeedRandom(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
		    CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen)
{
	if (tokdata->initialized == FALSE){
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}

	TRACE_ERROR("%s\n", ock_err(ERR_RANDOM_SEED_NOT_SUPPORTED));
	return CKR_RANDOM_SEED_NOT_SUPPORTED;
}


CK_RV SC_GenerateRandom(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
			CK_BYTE_PTR pRandomData,
			CK_ULONG ulRandomLen)
{
	SESSION *sess = NULL;
	CK_RV rc = CKR_OK;

	if (tokdata->initialized == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		rc = CKR_CRYPTOKI_NOT_INITIALIZED;
		goto done;
	}

	if (!pRandomData && ulRandomLen != 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		rc = CKR_ARGUMENTS_BAD;
		goto done;
	}

	sess = session_mgr_find(sSession->sessionh);
	if (!sess) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	rc = rng_generate(tokdata, pRandomData, ulRandomLen);
	if (rc != CKR_OK)
		TRACE_DEVEL("rng_generate() failed.\n");

done:
	TRACE_INFO("C_GenerateRandom: rc = 0x%08lx, %lu bytes\n", rc, ulRandomLen);
	return rc;
}


CK_RV SC_GetFunctionStatus(STDLL_TokData_t *tokdata,
			   ST_SESSION_HANDLE *sSession)
{
	if (tokdata->initialized == FALSE){
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_PARALLEL));
	return CKR_FUNCTION_NOT_PARALLEL;
}


CK_RV SC_CancelFunction(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession)
{
	if (tokdata->initialized == FALSE){
		TRACE_ERROR("%s\n", ock_err(ERR_CRYPTOKI_NOT_INITIALIZED));
		return CKR_CRYPTOKI_NOT_INITIALIZED;
	}
	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_NOT_PARALLEL));
	return CKR_FUNCTION_NOT_PARALLEL;
}


void SC_SetFunctionList(void) {
	function_list.ST_Initialize          = (void *)ST_Initialize;
	function_list.ST_GetTokenInfo        = SC_GetTokenInfo;
	function_list.ST_GetMechanismList    = SC_GetMechanismList;
	function_list.ST_GetMechanismInfo    = SC_GetMechanismInfo;
	function_list.ST_InitToken           = SC_InitToken;
	function_list.ST_InitPIN             = SC_InitPIN;
	function_list.ST_SetPIN              = SC_SetPIN;
	function_list.ST_OpenSession         = SC_OpenSession;
	function_list.ST_CloseSession        = SC_CloseSession;
	function_list.ST_GetSessionInfo      = SC_GetSessionInfo;
	function_list.ST_GetOperationState   = SC_GetOperationState;
	function_list.ST_SetOperationState   = SC_SetOperationState;
	function_list.ST_Login               = SC_Login;
	function_list.ST_Logout              = SC_Logout;
	function_list.ST_CreateObject        = SC_CreateObject;
	function_list.ST_CopyObject          = SC_CopyObject;
	function_list.ST_DestroyObject       = SC_DestroyObject;
	function_list.ST_GetObjectSize       = SC_GetObjectSize;
	function_list.ST_GetAttributeValue   = SC_GetAttributeValue;
	function_list.ST_SetAttributeValue   = SC_SetAttributeValue;
	function_list.ST_FindObjectsInit     = SC_FindObjectsInit;
	function_list.ST_FindObjects         = SC_FindObjects;
	function_list.ST_FindObjectsFinal    = SC_FindObjectsFinal;
	function_list.ST_EncryptInit         = SC_EncryptInit;
	function_list.ST_Encrypt             = SC_Encrypt;
	function_list.ST_EncryptUpdate       = SC_EncryptUpdate;
	function_list.ST_EncryptFinal        = SC_EncryptFinal;
	function_list.ST_DecryptInit         = SC_DecryptInit;
	function_list.ST_Decrypt             = SC_Decrypt;
	function_list.ST_DecryptUpdate       = SC_DecryptUpdate;
	function_list.ST_DecryptFinal        = SC_DecryptFinal;
	function_list.ST_DigestInit          = SC_DigestInit;
	function_list.ST_Digest              = SC_Digest;
	function_list.ST_DigestUpdate        = SC_DigestUpdate;
	function_list.ST_DigestKey           = SC_DigestKey;
	function_list.ST_DigestFinal         = SC_DigestFinal;
	function_list.ST_SignInit            = SC_SignInit;
	function_list.ST_Sign                = SC_Sign;
	function_list.ST_SignUpdate          = SC_SignUpdate;
	function_list.ST_SignFinal           = SC_SignFinal;
	function_list.ST_SignRecoverInit     = SC_SignRecoverInit;
	function_list.ST_SignRecover         = SC_SignRecover;
	function_list.ST_VerifyInit          = SC_VerifyInit;
	function_list.ST_Verify              = SC_Verify;
	function_list.ST_VerifyUpdate        = SC_VerifyUpdate;
	function_list.ST_VerifyFinal         = SC_VerifyFinal;
	function_list.ST_VerifyRecoverInit   = SC_VerifyRecoverInit;
	function_list.ST_VerifyRecover       = SC_VerifyRecover;
	function_list.ST_DigestEncryptUpdate = NULL; // SC_DigestEncryptUpdate;
	function_list.ST_DecryptDigestUpdate = NULL; // SC_DecryptDigestUpdate;
	function_list.ST_SignEncryptUpdate   = NULL; //SC_SignEncryptUpdate;
	function_list.ST_DecryptVerifyUpdate = NULL; // SC_DecryptVerifyUpdate;
	function_list.ST_GenerateKey         = SC_GenerateKey;
	function_list.ST_GenerateKeyPair     = SC_GenerateKeyPair;
	function_list.ST_WrapKey             = SC_WrapKey;
	function_list.ST_UnwrapKey           = SC_UnwrapKey;
	function_list.ST_DeriveKey           = SC_DeriveKey;
	function_list.ST_SeedRandom          = SC_SeedRandom ;
	function_list.ST_GenerateRandom      = SC_GenerateRandom;
	function_list.ST_GetFunctionStatus   = NULL; // SC_GetFunctionStatus;
	function_list.ST_CancelFunction      = NULL; // SC_CancelFunction;
}
