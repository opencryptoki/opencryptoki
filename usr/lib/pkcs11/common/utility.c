/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"
#include "shared_memory.h"
#include "trace.h"

#include <sys/file.h>
#include <syslog.h>

// Function:  dlist_add_as_first()
//
// Adds the specified node to the start of the list
//
// Returns:  pointer to the start of the list
//
DL_NODE *dlist_add_as_first(DL_NODE * list, void *data)
{
	DL_NODE *node = NULL;

	if (!data)
		return list;

	node = (DL_NODE *) malloc(sizeof(DL_NODE));
	if (!node)
		return NULL;

	node->data = data;
	node->prev = NULL;
	node->next = list;
	if (list)
		list->prev = node;

	return node;
}

// Function:  dlist_add_as_last()
//
// Adds the specified node to the end of the list
//
// Returns:  pointer to the start of the list
//
DL_NODE *dlist_add_as_last(DL_NODE * list, void *data)
{
	DL_NODE *node = NULL;

	if (!data)
		return list;

	node = (DL_NODE *) malloc(sizeof(DL_NODE));
	if (!node)
		return NULL;

	node->data = data;
	node->next = NULL;

	if (!list) {
		node->prev = NULL;
		return node;
	} else {
		DL_NODE *temp = dlist_get_last(list);
		temp->next = node;
		node->prev = temp;

		return list;
	}
}

// Function:  dlist_find()
//
DL_NODE *dlist_find(DL_NODE * list, void *data)
{
	DL_NODE *node = list;

	while (node && node->data != data)
		node = node->next;

	return node;
}

// Function:  dlist_get_first()
//
// Returns the last node in the list or NULL if list is empty
//
DL_NODE *dlist_get_first(DL_NODE * list)
{
	DL_NODE *temp = list;

	if (!list)
		return NULL;

	while (temp->prev != NULL)
		temp = temp->prev;

	return temp;
}

// Function:  dlist_get_last()
//
// Returns the last node in the list or NULL if list is empty
//
DL_NODE *dlist_get_last(DL_NODE * list)
{
	DL_NODE *temp = list;

	if (!list)
		return NULL;

	while (temp->next != NULL)
		temp = temp->next;

	return temp;
}

//
//
CK_ULONG dlist_length(DL_NODE * list)
{
	DL_NODE *temp = list;
	CK_ULONG len = 0;

	while (temp) {
		len++;
		temp = temp->next;
	}

	return len;
}

//
//
DL_NODE *dlist_next(DL_NODE * node)
{
	if (!node)
		return NULL;

	return node->next;
}

//
//
DL_NODE *dlist_prev(DL_NODE * node)
{
	if (!node)
		return NULL;

	return node->prev;
}

//
//
void dlist_purge(DL_NODE * list)
{
	DL_NODE *node;

	if (!list)
		return;

	do {
		node = list->next;
		free(list);
		list = node;
	} while (list);
}

// Function:  dlist_remove_node()
//
// Attempts to remove the specified node from the list.  The caller is
// responsible for freeing the data associated with the node prior to
// calling this routine
//
DL_NODE *dlist_remove_node(DL_NODE * list, DL_NODE * node)
{
	DL_NODE *temp = list;

	if (!list || !node)
		return NULL;

	// special case:  removing head of the list
	//
	if (list == node) {
		temp = list->next;
		if (temp)
			temp->prev = NULL;

		free(list);
		return temp;
	}
	// we have no guarantee that the node is in the list
	// so search through the list to find it
	//
	while ((temp != NULL) && (temp->next != node))
		temp = temp->next;

	if (temp != NULL) {
		DL_NODE *next = node->next;

		temp->next = next;
		if (next)
			next->prev = temp;

		free(node);
	}

	return list;
}

// NOTE about Mutexes and cross process locking....
//
// The code uses 2 types of locks... internal locks to prevent threads within the same
// process space from stomping on each other  (pthread_mutex's suffice for
// this).... and Cross Process Locks....
// On AIX we use it's variation of Posix semaphores for this.... Idealy on other
// platforms either POSIXSEMaphores or PTHREADXPL (pthreads xprocess lock) would
// be used.  On Linux unfortunatly  neither of these are available so we need to
// use the old standby of  SYSV semaphores (YECH.... GAG....)....  The only
// pieces which have been tested are the AIX and SYSV portions although
// we expect that the others work correctly.
//
// we use alot more mutexes in the redesign than we did in the original
// design.  so instead of just the single global "pkcs_mutex" we have to
// deal with a number of mutexes.  so we'll make the mutex routines a
// bit more generic.
//

CK_RV _CreateMutex(MUTEX * mutex)
{
	// on AIX we make this a no-op since we assume that
	// the mutex was created in the initialization
	pthread_mutex_init(mutex, NULL);
	return CKR_OK;
}

CK_RV _DestroyMutex(MUTEX * mutex)
{
	// no-op in AIX
	pthread_mutex_destroy((pthread_mutex_t *) mutex);
	return CKR_OK;

}

CK_RV _LockMutex(MUTEX * mutex)
{
	pthread_mutex_lock(mutex);
	return CKR_OK;

}

CK_RV _UnlockMutex(MUTEX * mutex)
{
	pthread_mutex_unlock(mutex);
	return CKR_OK;

}

CK_RV CreateXProcLock(char *tokname, STDLL_TokData_t *tokdata)
{
	CK_BYTE lockfile[2*PATH_MAX + sizeof(LOCKDIR_PATH) + 6];
	CK_BYTE lockdir[PATH_MAX + sizeof(LOCKDIR_PATH)];
	struct group *grp;
	struct stat statbuf;
	mode_t mode = (S_IRUSR | S_IRGRP);
	int ret = -1;

	if (tokdata->spinxplfd == -1) {

		if (token_specific.t_creatlock != NULL) {
			tokdata->spinxplfd = token_specific.t_creatlock();
			if (tokdata->spinxplfd != -1)
				return CKR_OK;
			else
				return CKR_FUNCTION_FAILED;
		}

		/** create lock subdir for each token if it doesn't exist.
		  * The root directory should be created in slotmgr daemon **/
		if (strlen(tokname) > 0)
			sprintf(lockdir, "%s/%s", LOCKDIR_PATH, tokname);
		else
			sprintf(lockdir, "%s/%s", LOCKDIR_PATH, SUB_DIR);

		ret = stat(lockdir, &statbuf);
		if (ret != 0 && errno == ENOENT) {
			/* dir does not exist, try to create it */
			ret  = mkdir(lockdir, S_IRWXU|S_IRWXG);
			if (ret != 0) {
				OCK_SYSLOG(LOG_ERR,
						"Directory(%s) missing: %s\n",
						lockdir,
						strerror(errno));
				goto err;
			}
			grp = getgrnam("pkcs11");
			if (grp == NULL) {
				fprintf(stderr, "getgrname(pkcs11): %s",
					strerror(errno));
				goto err;
			}
			/* set ownership to euid, and pkcs11 group */
			if (chown(lockdir, geteuid(), grp->gr_gid) != 0) {
				fprintf(stderr, "Failed to set owner:group \
						ownership\
						on %s directory", lockdir);
				goto err;
			}
			/* mkdir does not set group permission right, so
			 ** trying explictly here again */
			if (chmod(lockdir, S_IRWXU|S_IRWXG) != 0){
				fprintf(stderr, "Failed to change \
						permissions\
						on %s directory", lockdir);
				goto err;
			}
		}

		/* create user lock file */
		if (strlen(tokname) > 0)
			sprintf(lockfile, "%s/%s/LCK..%s",
				LOCKDIR_PATH, tokname, tokname);
		else
			sprintf(lockfile, "%s/%s/LCK..%s",
				LOCKDIR_PATH, SUB_DIR, SUB_DIR);

		if (stat(lockfile, &statbuf) == 0)
			tokdata->spinxplfd = open(lockfile, O_RDONLY, mode);
		else {
			tokdata->spinxplfd = open(lockfile, O_CREAT | O_RDONLY, mode);
			if (tokdata->spinxplfd != -1) {
				/* umask may prevent correct mode,so set it. */
				if (fchmod(tokdata->spinxplfd, mode) == -1) {
					OCK_SYSLOG(LOG_ERR, "fchmod(%s): %s\n",
							lockfile, strerror(errno));
					goto err;
				}

				grp = getgrnam("pkcs11");
				if (grp != NULL) {
					if (fchown(tokdata->spinxplfd, -1,
						   grp->gr_gid) == -1) {
						OCK_SYSLOG(LOG_ERR,
								"fchown(%s): %s\n",
								lockfile,
								strerror(errno));
						goto err;
					}
				} else {
					OCK_SYSLOG(LOG_ERR, "getgrnam(): %s\n",
							strerror(errno));
					goto err;
				}
			}
		}
		if (tokdata->spinxplfd == -1) {
			OCK_SYSLOG(LOG_ERR, "open(%s): %s\n",
					lockfile, strerror(errno));
			return CKR_FUNCTION_FAILED;
		}
	}

	return CKR_OK;

err:
	if (tokdata->spinxplfd != -1)
		close(tokdata->spinxplfd);
	return CKR_FUNCTION_FAILED;
}

void CloseXProcLock(STDLL_TokData_t *tokdata)
{
	if (tokdata->spinxplfd != -1)
		close(tokdata->spinxplfd);
}

CK_RV XProcLock(STDLL_TokData_t *tokdata)
{
	if (tokdata->spinxplfd != -1)
		flock(tokdata->spinxplfd, LOCK_EX);
	else {
		TRACE_DEVEL("No file descriptor to lock with.\n");
		return CKR_CANT_LOCK;
	}

	return CKR_OK;
}

CK_RV XProcUnLock(STDLL_TokData_t *tokdata)
{
	if (tokdata->spinxplfd != -1)
		flock(tokdata->spinxplfd, LOCK_UN);
	else {
		TRACE_DEVEL("No file descriptor to unlock with.\n");
		return CKR_CANT_LOCK;
	}

	return CKR_OK;
}

void XProcLock_Init(STDLL_TokData_t *tokdata)
{
	tokdata->spinxplfd = -1;
}

//
//

extern CK_CHAR manuf[];
extern CK_CHAR model[];
extern CK_CHAR descr[];
extern CK_CHAR label[];

//
//
void init_slotInfo(CK_SLOT_INFO *slot_info)
{
	memset(slot_info->slotDescription, ' ',
	       sizeof(slot_info->slotDescription));
	memset(slot_info->manufacturerID, ' ',
	       sizeof(slot_info->manufacturerID));

	memcpy(slot_info->slotDescription, descr, strlen((char *)descr));
	memcpy(slot_info->manufacturerID, manuf, strlen((char *)manuf));

	slot_info->hardwareVersion.major = 1;
	slot_info->hardwareVersion.minor = 0;
	slot_info->firmwareVersion.major = 1;
	slot_info->firmwareVersion.minor = 0;
	slot_info->flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
}

//
//
void init_tokenInfo(TOKEN_DATA *nv_token_data)
{
	CK_TOKEN_INFO_32 *token_info = &nv_token_data->token_info;

	memset(token_info->manufacturerID, ' ',
	       sizeof(token_info->manufacturerID));
	memset(token_info->model, ' ', sizeof(token_info->model));
	memset(token_info->serialNumber, ' ', sizeof(token_info->serialNumber));

	memcpy(token_info->label, label, strlen((char *)label));

	memcpy(token_info->manufacturerID, manuf, strlen((char *)manuf));
	memcpy(token_info->model, model, strlen((char *)model));

	// use the 41-xxxxx serial number from the coprocessor
	//
	memcpy(token_info->serialNumber, "123", 3);

	// I don't see any API support for changing the clock so
	// we will use the system clock for the token's clock.
	//

	token_info->flags = CKF_RNG | CKF_LOGIN_REQUIRED | CKF_CLOCK_ON_TOKEN | CKF_SO_PIN_TO_BE_CHANGED;	// XXX New in v2.11 - KEY

	if (memcmp
	    (nv_token_data->user_pin_sha, "00000000000000000000",
	     SHA1_HASH_SIZE) != 0)
		token_info->flags |= CKF_USER_PIN_INITIALIZED;
	else
		token_info->flags |= CKF_USER_PIN_TO_BE_CHANGED;	// XXX New in v2.11 - KEY

	// For the release, we made these
	// values as CK_UNAVAILABLE_INFORMATION
	//
	token_info->ulMaxSessionCount =
	    (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
	token_info->ulSessionCount = (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
	token_info->ulMaxRwSessionCount =
	    (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
	token_info->ulRwSessionCount = (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
	token_info->ulMaxPinLen = MAX_PIN_LEN;
	token_info->ulMinPinLen = MIN_PIN_LEN;
	token_info->ulTotalPublicMemory =
	    (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
	token_info->ulFreePublicMemory =
	    (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
	token_info->ulTotalPrivateMemory =
	    (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;
	token_info->ulFreePrivateMemory =
	    (CK_ULONG_32) CK_UNAVAILABLE_INFORMATION;

	token_info->hardwareVersion.major = 1;
	token_info->hardwareVersion.minor = 0;
	token_info->firmwareVersion.major = 1;
	token_info->firmwareVersion.minor = 0;

	memset(token_info->utcTime, ' ', sizeof(token_info->utcTime));
}

//
//
CK_RV init_token_data(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
	CK_RV rc;

	memset((char *)tokdata->nv_token_data, 0, sizeof(TOKEN_DATA));

	// the normal USER pin is not set when the token is initialized
	//
	memcpy(tokdata->nv_token_data->user_pin_sha, "00000000000000000000",
	       SHA1_HASH_SIZE);
	memcpy(tokdata->nv_token_data->so_pin_sha, default_so_pin_sha, SHA1_HASH_SIZE);

	memset(tokdata->user_pin_md5, 0x0, MD5_HASH_SIZE);
	memcpy(tokdata->so_pin_md5, default_so_pin_md5, MD5_HASH_SIZE);

	memcpy(tokdata->nv_token_data->next_token_object_name, "00000000", 8);

	// generate the master key used for signing the Operation State information
	//                          `
	memset(tokdata->nv_token_data->token_info.label, ' ',
	       sizeof(tokdata->nv_token_data->token_info.label));
	memcpy(tokdata->nv_token_data->token_info.label, label, strlen((char *)label));

	tokdata->nv_token_data->tweak_vector.allow_weak_des = TRUE;
	tokdata->nv_token_data->tweak_vector.check_des_parity = FALSE;
	tokdata->nv_token_data->tweak_vector.allow_key_mods = TRUE;
	tokdata->nv_token_data->tweak_vector.netscape_mods = TRUE;

	init_tokenInfo(tokdata->nv_token_data);

	if (token_specific.t_init_token_data) {
		rc = token_specific.t_init_token_data(tokdata, slot_id);
		if (rc != CKR_OK)
			return rc;
	} else {
		//
		// FIXME: erase the token object index file (and all token objects)
		//
		rc = generate_master_key(tokdata, tokdata->master_key);
		if (rc != CKR_OK) {
			TRACE_DEVEL("generate_master_key failed.\n");
			return CKR_FUNCTION_FAILED;
		}

		rc = save_masterkey_so(tokdata);
		if (rc != CKR_OK) {
			TRACE_DEVEL("save_masterkey_so failed.\n");
			return rc;
		}
	}

	rc = save_token_data(tokdata, slot_id);

	return rc;
}

// Function:  compute_next_token_obj_name()
//
// Given a token object name (8 bytes in the range [0-9A-Z]) increment by one
// adjusting as necessary
//
// This gives us a namespace of 36^8 = 2,821,109,907,456 objects before wrapping around
//
CK_RV compute_next_token_obj_name(CK_BYTE * current, CK_BYTE * next)
{
	int val[8];
	int i;

	if (!current || !next) {
		TRACE_ERROR("Invalid function arguments.\n");
		return CKR_FUNCTION_FAILED;
	}
	// Convert to integral base 36
	//
	for (i = 0; i < 8; i++) {
		if (current[i] >= '0' && current[i] <= '9')
			val[i] = current[i] - '0';

		if (current[i] >= 'A' && current[i] <= 'Z')
			val[i] = current[i] - 'A' + 10;
	}

	val[0]++;

	i = 0;

	while (val[i] > 35) {
		val[i] = 0;

		if (i + 1 < 8) {
			val[i + 1]++;
			i++;
		} else {
			val[0]++;
			i = 0;	// start pass 2
		}
	}

	// now, convert back to [0-9A-Z]
	//
	for (i = 0; i < 8; i++) {
		if (val[i] < 10)
			next[i] = '0' + val[i];
		else
			next[i] = 'A' + val[i] - 10;
	}

	return CKR_OK;
}

//
//
CK_RV
build_attribute(CK_ATTRIBUTE_TYPE type,
		CK_BYTE * data, CK_ULONG data_len, CK_ATTRIBUTE ** attrib)
{
	CK_ATTRIBUTE *attr = NULL;

	attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + data_len);
	if (!attr) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}
	attr->type = type;
	attr->ulValueLen = data_len;

	if (data_len > 0) {
		attr->pValue = (CK_BYTE *) attr + sizeof(CK_ATTRIBUTE);
		memcpy(attr->pValue, data, data_len);
	} else
		attr->pValue = NULL;

	*attrib = attr;

	return CKR_OK;
}

/*
 * Find an attribute in an attribute array.
 *
 * Returns CKR_FUNCTION_FAILED when attribute is not found,
 * CKR_ATTRIBUTE_TYPE_INVALID when length doesn't match the expected and
 * CKR_OK when values is returned in the `value` argument.
 */
CK_RV
find_bbool_attribute(CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
		     CK_ATTRIBUTE_TYPE type, CK_BBOOL *value)
{
	CK_ULONG i;

	for (i = 0; i < attrs_len; i++) {
		if (attrs[i].type == type) {
			/* Check size */
			if (attrs[i].ulValueLen != sizeof(*value))
				return CKR_ATTRIBUTE_TYPE_INVALID;

			/* Get value */
			*value = *((CK_BBOOL *) attrs[i].pValue);
		}
	}

	return CKR_FUNCTION_FAILED;
}

//
//
CK_RV
add_pkcs_padding(CK_BYTE * ptr,
		 CK_ULONG block_size, CK_ULONG data_len, CK_ULONG total_len)
{
	CK_ULONG i, pad_len;
	CK_BYTE pad_value;

	pad_len = block_size - (data_len % block_size);
	pad_value = (CK_BYTE) pad_len;

	if (data_len + pad_len > total_len) {
		TRACE_ERROR("The total length is too small to add padding.\n");
		return CKR_FUNCTION_FAILED;
	}
	for (i = 0; i < pad_len; i++)
		ptr[i] = pad_value;

	return CKR_OK;
}

//
//
CK_RV strip_pkcs_padding(CK_BYTE * ptr, CK_ULONG total_len, CK_ULONG * data_len)
{
	CK_BYTE pad_value;

	pad_value = ptr[total_len - 1];
	if (pad_value > total_len) {
		TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_INVALID));
		return CKR_ENCRYPTED_DATA_INVALID;
	}
	// thus, we have 'pad_value' bytes of 'pad_value' appended to the end
	//
	*data_len = total_len - pad_value;

	return CKR_OK;
}

//
//
CK_BYTE parity_adjust(CK_BYTE b)
{
	if (parity_is_odd(b) == FALSE)
		b = (b & 0xFE) | ((~b) & 0x1);

	return b;
}

//
//
CK_RV parity_is_odd(CK_BYTE b)
{
	b = ((b >> 4) ^ b) & 0x0f;
	b = ((b >> 2) ^ b) & 0x03;
	b = ((b >> 1) ^ b) & 0x01;

	if (b == 1)
		return TRUE;
	else
		return FALSE;
}

CK_RV attach_shm(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
	CK_RV rc = CKR_OK;
	int ret;
	char buf[PATH_MAX];
	LW_SHM_TYPE **shm = &tokdata->global_shm;

	if (token_specific.t_attach_shm != NULL)
		return token_specific.t_attach_shm(tokdata, slot_id);

	XProcLock(tokdata);

	/*
	 * Attach to an existing shared memory region or create it if it doesn't
	 * exists. When it's created (ret=0) the region is initialized with
	 * zeros.
	 */
	ret = sm_open(get_pk_dir(buf), 0666, (void**) shm, sizeof(**shm), 0);
	if (ret < 0) {
		TRACE_DEVEL("sm_open failed.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

done:
	XProcUnLock(tokdata);
	return rc;
}

CK_RV detach_shm(STDLL_TokData_t *tokdata)
{
	CK_RV rc = CKR_OK;

	XProcLock(tokdata);

	if (sm_close((void *)tokdata->global_shm, 0)) {
		TRACE_DEVEL("sm_close failed.\n");
		rc = CKR_FUNCTION_FAILED;
	}

	XProcUnLock(tokdata);

	return rc;
}

CK_RV get_sha_size(CK_ULONG mech, CK_ULONG *hsize)
{
	switch(mech) {
	case CKM_SHA_1:
		*hsize = SHA1_HASH_SIZE;
		break;
	case CKM_SHA256:
		*hsize = SHA2_HASH_SIZE;
		break;
	case CKM_SHA384:
		*hsize = SHA3_HASH_SIZE;
		break;
	case CKM_SHA512:
		*hsize = SHA5_HASH_SIZE;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}
	return CKR_OK;
}

/* Compute specified SHA using either software or token implementation */
CK_RV compute_sha(STDLL_TokData_t *tokdata, CK_BYTE * data, CK_ULONG len,
		  CK_BYTE *hash, CK_ULONG mech)
{
	DIGEST_CONTEXT ctx;
	CK_ULONG hash_len;
	CK_RV rv;

	memset(&ctx, 0x0, sizeof(ctx));
	ctx.mech.mechanism = mech;

	rv = get_sha_size(mech, &hash_len);
	if (rv != CKR_OK)
		return rv;

	rv = sha_init(tokdata, NULL, &ctx, &ctx.mech);
	if (rv != CKR_OK) {
		TRACE_DEBUG("failed to create digest.\n");
		return rv;
	}
	return sha_hash(tokdata, NULL, FALSE, &ctx, data, len, hash, &hash_len);
}

/* Compute SHA1 using software implementation */
CK_RV compute_sha1(STDLL_TokData_t *tokdata, CK_BYTE * data, CK_ULONG len,
		   CK_BYTE *hash)
{
	// XXX KEY
	DIGEST_CONTEXT ctx;
	CK_ULONG hash_len = SHA1_HASH_SIZE;

	memset(&ctx, 0x0, sizeof(ctx));

	sw_sha1_init(&ctx);
	if (ctx.context == NULL)
		return CKR_HOST_MEMORY;

	return sw_sha1_hash(&ctx, data, len, hash, &hash_len);
}

CK_RV compute_md5(STDLL_TokData_t  *tokdata, CK_BYTE * data, CK_ULONG len,
		  CK_BYTE * hash)
{
	MD5_CONTEXT ctx;

	memset(&ctx, 0x0, sizeof(ctx));

	ckm_md5_init(tokdata, &ctx);
	ckm_md5_update(tokdata, &ctx, data, len);
	ckm_md5_final(tokdata, &ctx, hash, MD5_HASH_SIZE);

	return CKR_OK;
}

CK_RV get_keytype(STDLL_TokData_t *tokdata, CK_OBJECT_HANDLE hkey,
		  CK_KEY_TYPE *keytype)
{
	CK_RV rc;
	OBJECT *key_obj = NULL;
	CK_ATTRIBUTE *attr = NULL;

	rc = object_mgr_find_in_map1(tokdata, hkey, &key_obj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
		return rc;
	}
	rc = template_attribute_find(key_obj->template, CKA_KEY_TYPE, &attr);
	if (rc == FALSE) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
		return CKR_KEY_TYPE_INCONSISTENT;
	} else {
		*keytype = *(CK_KEY_TYPE *)attr->pValue;
		return CKR_OK;
	}
}

CK_RV check_user_and_group()
{
	int i;
	uid_t uid, euid;
	struct passwd *pw, *epw;
	struct group *grp;

	/*
	 * Check for root user or Group PKCS#11 Membershp.
	 * Only these are allowed.
	 */
	uid = getuid();
	euid = geteuid();

	/* Root or effective Root is ok */
	if (uid == 0 && euid == 0)
		return CKR_OK;

	/*
	 * Check for member of group. SAB get login seems to not work
	 * with some instances of application invocations (particularly
	 * when forked). So we need to get the group information.
	 * Really need to take the uid and map it to a name.
	 */
	grp = getgrnam("pkcs11");
	if (grp == NULL) {
		OCK_SYSLOG(LOG_ERR, "getgrnam() failed: %s\n", strerror(errno));
		goto error;
	}

	if (getgid() == grp->gr_gid || getegid() == grp->gr_gid)
		return CKR_OK;
	/* Check if user or effective user is member of pkcs11 group */
	pw = getpwuid(uid);
	epw = getpwuid(euid);
	for (i = 0; grp->gr_mem[i]; i++) {
		if ((pw && (strncmp(pw->pw_name, grp->gr_mem[i],
		    strlen(pw->pw_name)) == 0)) ||
		    (epw && (strncmp(epw->pw_name, grp->gr_mem[i],
		    strlen(epw->pw_name)) == 0)))
			return CKR_OK;
	}

error:
	TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
	return CKR_FUNCTION_FAILED;
}

void copy_token_contents_sensibly(CK_TOKEN_INFO_PTR pInfo,
				  TOKEN_DATA *nv_token_data)
{
	memcpy(pInfo, &nv_token_data->token_info, sizeof(CK_TOKEN_INFO_32));
	pInfo->flags = nv_token_data->token_info.flags;
	pInfo->ulMaxPinLen = nv_token_data->token_info.ulMaxPinLen;
	pInfo->ulMinPinLen = nv_token_data->token_info.ulMinPinLen;

	if (nv_token_data->token_info.ulTotalPublicMemory ==
	    (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION)
		pInfo->ulTotalPublicMemory = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	else
		pInfo->ulTotalPublicMemory = nv_token_data->token_info.ulTotalPublicMemory;

	if (nv_token_data->token_info.ulFreePublicMemory ==
	    (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION)
		pInfo->ulFreePublicMemory = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	else
		pInfo->ulFreePublicMemory = nv_token_data->token_info.ulFreePublicMemory;

	if (nv_token_data->token_info.ulTotalPrivateMemory ==
	    (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION)
		pInfo->ulTotalPrivateMemory = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	else
		pInfo->ulTotalPrivateMemory = nv_token_data->token_info.ulTotalPrivateMemory;

	if (nv_token_data->token_info.ulFreePrivateMemory ==
	   (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION)
		pInfo->ulFreePrivateMemory = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
	else
		pInfo->ulFreePrivateMemory = nv_token_data->token_info.ulFreePrivateMemory;

	pInfo->hardwareVersion = nv_token_data->token_info.hardwareVersion;
	pInfo->firmwareVersion = nv_token_data->token_info.firmwareVersion;
	pInfo->ulMaxSessionCount = ULONG_MAX - 1;
	/* pInfo->ulSessionCount is set at the API level */
	pInfo->ulMaxRwSessionCount = ULONG_MAX - 1;
	pInfo->ulRwSessionCount = CK_UNAVAILABLE_INFORMATION;
}
