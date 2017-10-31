/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// loadsave.c
//
// routines associated with loading/saving files
//
//
#define _GNU_SOURCE
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/file.h>
#include <errno.h>
#include <syslog.h>
#include <pwd.h>
#include <grp.h>
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"
#include "sw_crypt.h"
#include "trace.h"

/* #include "../api/apiproto.h" */

char *pk_dir;

CK_BYTE *get_pk_dir(char *fname)
{
	struct passwd *pw = NULL;

	if (token_specific.data_store.per_user &&
	    (pw = getpwuid(getuid())) != NULL)
		sprintf(fname,"%s/%s", pk_dir, pw->pw_name);
	else
		sprintf(fname, "%s", pk_dir);

	return fname;
}

static CK_RV get_encryption_info_for_clear_key(CK_ULONG *p_key_len,
					       CK_ULONG *p_block_size)
{
	CK_ULONG key_len = 0L;
	CK_ULONG block_size = 0L;

	switch (token_specific.data_store.encryption_algorithm) {
	case CKM_DES3_CBC:
		key_len = 3 * DES_KEY_SIZE;
		block_size = DES_BLOCK_SIZE;
		break;
	case CKM_AES_CBC:
		key_len = AES_KEY_SIZE_256;
		block_size = AES_BLOCK_SIZE;
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return ERR_MECHANISM_INVALID;
	}

	if (p_key_len)
		*p_key_len = key_len;
	if (p_block_size)
		*p_block_size = block_size;

	return CKR_OK;
}

static CK_RV get_encryption_info(CK_ULONG *p_key_len,
				 CK_ULONG *p_block_size)
{
	CK_RV rc;

	rc = get_encryption_info_for_clear_key(p_key_len, p_block_size);
	if (rc != CKR_OK)
		return rc;

	/* Tokens that use a secure key have a different size for key because
	 * it's just an indentifier not a real key. token_keysize > 0 indicates
	 * that a token uses a specific key format.
	 */
	if (token_specific.token_keysize) {
		if (p_key_len)
			*p_key_len = token_specific.token_keysize;
	}
	return CKR_OK;
}

static CK_BYTE *duplicate_initial_vector(const CK_BYTE *iv)
{
	CK_ULONG block_size = 0L;
	CK_BYTE *initial_vector = NULL;

	if (iv == NULL)
		goto done;

	if (get_encryption_info(NULL, &block_size) != CKR_OK)
		goto done;

	initial_vector = malloc(block_size);
	if (initial_vector == NULL) {
		goto done;
	}
	memcpy(initial_vector, iv, block_size);

done:
	return initial_vector;
}

static CK_RV encrypt_data(STDLL_TokData_t *tokdata, CK_BYTE *key,
			  CK_ULONG keylen, const CK_BYTE *iv,
			  CK_BYTE *clear, CK_ULONG clear_len,
			  CK_BYTE *cipher, CK_ULONG *p_cipher_len)
{
#ifndef  CLEARTEXT
	CK_RV rc = CKR_OK;
	CK_BYTE *initial_vector = NULL;
	OBJECT *keyobj = NULL;
	CK_KEY_TYPE     keyType;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE key_tmpl[] =
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_VALUE, key, keylen}
	};

	switch (token_specific.data_store.encryption_algorithm) {
	case CKM_DES3_CBC:
		keyType = CKK_DES3;
		break;
	case CKM_AES_CBC:
		keyType = CKK_AES;
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return ERR_MECHANISM_INVALID;
	}
	rc = object_create_skel(tokdata, key_tmpl, 3, MODE_CREATE,
				CKO_SECRET_KEY, keyType, &keyobj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("object_create_skel failed.\n");
		return rc;
	}

	initial_vector = duplicate_initial_vector(iv);
	if (initial_vector == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return ERR_HOST_MEMORY;
	}

	switch (token_specific.data_store.encryption_algorithm) {
	case CKM_DES3_CBC:
		rc = ckm_des3_cbc_encrypt(tokdata, clear, clear_len,
					  cipher, p_cipher_len,
					  initial_vector, keyobj);
		break;
	case CKM_AES_CBC:
		rc = ckm_aes_cbc_encrypt(tokdata, clear, clear_len,
		                         cipher, p_cipher_len,
					 initial_vector, keyobj);
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = ERR_MECHANISM_INVALID;
	}

	if (initial_vector)
		free(initial_vector);

	return rc;

#else
	memcpy(cipher, clear, clear_len);
	return CKR_OK;
#endif
}

static CK_RV encrypt_data_with_clear_key(STDLL_TokData_t * tokdata,
					 CK_BYTE *key, CK_ULONG keylen,
					 const CK_BYTE *iv,
					 CK_BYTE *clear, CK_ULONG clear_len,
					 CK_BYTE *cipher, CK_ULONG *p_cipher_len)
{
#ifndef CLEARTEXT
	CK_RV rc = CKR_OK;
	CK_BYTE *initial_vector = NULL;

	/* If token doesn't have a specific key size that means that it uses a
	 * clear key.
	 */
	if (token_specific.token_keysize == 0) {
		return encrypt_data(tokdata, key, keylen, iv, clear, clear_len,
				    cipher, p_cipher_len);
	}

	/* Fall back to a software alternative if key is secure. */
	initial_vector = duplicate_initial_vector(iv);
	if (initial_vector == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return ERR_HOST_MEMORY;
	}

	switch (token_specific.data_store.encryption_algorithm) {
	case CKM_DES3_CBC:
		rc = sw_des3_cbc_encrypt(clear, clear_len,
					 cipher, p_cipher_len,
					 initial_vector, key);
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = ERR_MECHANISM_INVALID;
	}

	if (initial_vector)
		free(initial_vector);

	return rc;

#else
	memcpy(cipher, clear, clear_len);
	return CKR_OK;
#endif
}

static CK_RV decrypt_data(STDLL_TokData_t *tokdata,
			  CK_BYTE *key, CK_ULONG keylen, const CK_BYTE *iv,
			  CK_BYTE *cipher, CK_ULONG cipher_len,
			  CK_BYTE *clear, CK_ULONG *p_clear_len)
{
#ifndef  CLEARTEXT
	CK_RV rc = CKR_OK;
	CK_BYTE *initial_vector = NULL;
	OBJECT *keyobj = NULL;
	CK_KEY_TYPE     keyType;
	CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
	CK_ATTRIBUTE key_tmpl[] =
	{
		{CKA_CLASS, &keyClass, sizeof(keyClass)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_VALUE, key, keylen}
	};

	switch (token_specific.data_store.encryption_algorithm) {
	case CKM_DES3_CBC:
		keyType = CKK_DES3;
		break;
	case CKM_AES_CBC:
		keyType = CKK_AES;
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return ERR_MECHANISM_INVALID;
	}
	rc = object_create_skel(tokdata, key_tmpl, 3, MODE_CREATE,
				CKO_SECRET_KEY, keyType, &keyobj);
	if (rc != CKR_OK) {
		TRACE_DEVEL("object_create_skel failed.\n");
		return rc;
	}

	initial_vector = duplicate_initial_vector(iv);
	if (initial_vector == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return ERR_HOST_MEMORY;
	}

	switch (token_specific.data_store.encryption_algorithm) {
	case CKM_DES3_CBC:
		rc = ckm_des3_cbc_decrypt(tokdata, cipher, cipher_len,
					  clear, p_clear_len,
					  initial_vector, keyobj);
		break;
	case CKM_AES_CBC:
		rc = ckm_aes_cbc_decrypt(tokdata, cipher, cipher_len,
					 clear, p_clear_len,
					 initial_vector, keyobj);
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = ERR_MECHANISM_INVALID;
	}

	if (initial_vector)
		free(initial_vector);

	return rc;

#else
	memcpy(clear, cipher, cipher_len);
	return CKR_OK;
#endif
}

static CK_RV decrypt_data_with_clear_key(STDLL_TokData_t *tokdata,
					 CK_BYTE *key, CK_ULONG keylen,
					 const CK_BYTE *iv,
					 CK_BYTE *cipher, CK_ULONG cipher_len,
					 CK_BYTE *clear, CK_ULONG *p_clear_len)
{
#ifndef CLEARTEXT
	CK_RV rc = CKR_OK;
	CK_BYTE *initial_vector = NULL;

	/* If token doesn't have a specific key size that means that it uses a
	 * clear key.
	 */
	if (token_specific.token_keysize == 0) {
		return decrypt_data(tokdata, key, keylen, iv, cipher,
				    cipher_len, clear, p_clear_len);
	}

	/* Fall back to a software alternative if key is secure. */
	initial_vector = duplicate_initial_vector(iv);
	if (initial_vector == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return ERR_HOST_MEMORY;
	}

	switch (token_specific.data_store.encryption_algorithm) {
	case CKM_DES3_CBC:
		rc = sw_des3_cbc_decrypt(cipher, cipher_len, clear, p_clear_len,
					 initial_vector, key);
		break;
	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = ERR_MECHANISM_INVALID;
	}

	if (initial_vector)
		free(initial_vector);

	return rc;

#else
	memcpy(clear, cipher, cipher_len);
	return CKR_OK;
#endif
}

void set_perm(int file)
{
	struct group *grp;

	if (token_specific.data_store.per_user) {
		/* In the TPM token, with per user data stores, we don't share
		 * the token object amongst a group. In fact, we want to
		 * restrict access to a single user */
		fchmod(file,S_IRUSR|S_IWUSR);
	} else {
		// Set absolute permissions or rw-rw----
		fchmod(file, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

		grp = getgrnam("pkcs11");	// Obtain the group id
		if (grp) {
			// set ownership to root, and pkcs11 group
			if (fchown(file, getuid(), grp->gr_gid) != 0) {
				goto error;
			}
		} else {
			goto error;
		}
	}

	return;

error:
	TRACE_DEVEL("Unable to set permissions on file.\n");
}

//
//
CK_RV
load_token_data(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
	FILE *fp = NULL;
	CK_BYTE fname[PATH_MAX];
	TOKEN_DATA td;
	CK_RV rc;

	rc = XProcLock(tokdata);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to get Process Lock.\n");
		goto out_nolock;
	}

	sprintf(fname, "%s/%s", tokdata->data_store, PK_LITE_NV);
	fp = fopen((char *)fname, "r");
	if (!fp) {
		/* Better error checking added */
		if (errno == ENOENT) {
			/* init_token_data may call save_token_data, which
			 * grabs the lock, so we must release it around this
			 * call */
			XProcUnLock(tokdata);
			init_token_data(tokdata, slot_id);
			rc = XProcLock(tokdata);
			if (rc != CKR_OK) {
				TRACE_ERROR("Failed to get Process Lock.\n");
				goto out_nolock;
			}

			fp = fopen((char *)fname, "r");
			if (!fp) {
				// were really hosed here since the created
				// did not occur
				TRACE_ERROR("fopen(%s): %s\n",
					     fname, strerror(errno));
				rc = CKR_FUNCTION_FAILED;
				goto out_unlock;
			}
		} else {
			/* Could not open file for some unknown reason */
			TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
			rc = CKR_FUNCTION_FAILED;
			goto out_unlock;
		}
	}
	set_perm(fileno(fp));

	/* Load generic token data */
	if (!fread(&td, sizeof(TOKEN_DATA), 1, fp)) {
		rc = CKR_FUNCTION_FAILED;
		goto out_unlock;
	}
	memcpy(tokdata->nv_token_data, &td, sizeof(TOKEN_DATA));

	/* Load token-specific data */
	if (token_specific.t_load_token_data) {
		rc = token_specific.t_load_token_data(tokdata, slot_id, fp);
		if (rc)
			goto out_unlock;
	}

	rc = CKR_OK;

out_unlock:
	XProcUnLock(tokdata);

out_nolock:
	if (fp)
		fclose(fp);
	return rc;
}

//
//
CK_RV save_token_data(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id)
{
	FILE *fp = NULL;
	TOKEN_DATA td;
	CK_RV rc;
	CK_BYTE fname[PATH_MAX];

	rc = XProcLock(tokdata);
	if (rc != CKR_OK) {
		TRACE_ERROR("Failed to get Process Lock.\n");
		goto out_nolock;
	}

	sprintf(fname, "%s/%s", tokdata->data_store, PK_LITE_NV);
	fp = fopen((char *)fname, "w");
	if (!fp) {
		TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	set_perm(fileno(fp));

	/* Write generic token data */
	memcpy(&td, tokdata->nv_token_data, sizeof(TOKEN_DATA));
	if (!fwrite(&td, sizeof(TOKEN_DATA), 1, fp)) {
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Write token-specific data */
	if (token_specific.t_save_token_data) {
		rc = token_specific.t_save_token_data(tokdata, slot_id, fp);
		if (rc)
			goto done;
	}

	rc = CKR_OK;

done:
	XProcUnLock(tokdata);

out_nolock:
	if (fp)
		fclose(fp);
	return rc;
}

//
//
CK_RV save_token_object(STDLL_TokData_t *tokdata, OBJECT * obj)
{
	FILE *fp = NULL;
	CK_BYTE line[100];
	CK_RV rc;
	CK_BYTE fname[PATH_MAX];

	if (object_is_private(obj) == TRUE)
		rc = save_private_token_object(tokdata, obj);
	else
		rc = save_public_token_object(tokdata, obj);

	if (rc != CKR_OK)
		return rc;

	// update the index file if it exists
	sprintf(fname, "%s/%s/%s", tokdata->data_store, PK_LITE_OBJ_DIR,
		PK_LITE_OBJ_IDX);
	fp = fopen((char *)fname, "r");
	if (fp) {
		set_perm(fileno(fp));
		while (fgets((char *)line, 50, fp)) {
			line[strlen(line) - 1] = 0;
			if (strcmp(line, obj->name) == 0) {
				fclose(fp);
				// object is already in the list
				return CKR_OK;
			}
		}
		fclose(fp);
	}
	// we didn't find it...either the index file doesn't exist or this
	// is a new object...
	//
	fp = fopen((char *)fname, "a");
	if (!fp) {
		TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
		return CKR_FUNCTION_FAILED;
	}

	set_perm(fileno(fp));
	fprintf(fp, "%s\n", obj->name);
	fclose(fp);

	return CKR_OK;
}

// this is the same as the old version.  public token objects are stored in the
// clear
//
CK_RV save_public_token_object(STDLL_TokData_t *tokdata, OBJECT * obj)
{
	FILE *fp = NULL;
	CK_BYTE *clear = NULL;
	CK_BYTE fname[PATH_MAX];
	CK_ULONG clear_len;
	CK_BBOOL flag = FALSE;
	CK_RV rc;
	CK_ULONG_32 total_len;

	rc = object_flatten(obj, &clear, &clear_len);
	if (rc != CKR_OK) {
		goto error;
	}

	sprintf(fname, "%s/%s/", tokdata->data_store, PK_LITE_OBJ_DIR);
	strncat((char *)fname, (char *)obj->name, 8);
	fp = fopen((char *)fname, "w");
	if (!fp) {
		TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
		rc = CKR_FUNCTION_FAILED;
		goto error;
	}

	set_perm(fileno(fp));

	total_len = clear_len + sizeof(CK_ULONG_32) + sizeof(CK_BBOOL);

	(void)fwrite(&total_len, sizeof(CK_ULONG_32), 1, fp);
	(void)fwrite(&flag, sizeof(CK_BBOOL), 1, fp);
	(void)fwrite(clear, clear_len, 1, fp);

	fclose(fp);
	free(clear);

	return CKR_OK;

error:
	if (fp)
		fclose(fp);
	if (clear)
		free(clear);
	return rc;
}

//
//
CK_RV save_private_token_object(STDLL_TokData_t *tokdata, OBJECT * obj)
{
	FILE *fp = NULL;
	CK_BYTE *obj_data = NULL;
	CK_BYTE *clear = NULL;
	CK_BYTE *cipher = NULL;
	CK_BYTE *ptr = NULL;
	CK_BYTE fname[100];
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	CK_BYTE *key = NULL;
	CK_ULONG key_len = 0L;
	CK_ULONG block_size = 0L;
	CK_ULONG obj_data_len, clear_len, cipher_len;
	CK_ULONG padded_len;
	CK_BBOOL flag;
	CK_RV rc;
	CK_ULONG_32 obj_data_len_32;
	CK_ULONG_32 total_len;

	rc = object_flatten(obj, &obj_data, &obj_data_len);
	obj_data_len_32 = obj_data_len;
	if (rc != CKR_OK) {
		goto error;
	}
	//
	// format for the object file:
	//    private flag
	//    ---- begin encrypted part        <--+
	//       length of object data            |
	//       object data                      +---- sensitive part
	//       SHA of (object data)             |
	//    ---- end encrypted part          <--+
	//
	compute_sha1(tokdata, obj_data, obj_data_len, hash_sha);

	// encrypt the sensitive object data.  need to be careful.
	// if I use the normal high-level encryption routines I'll need to
	// create a tepmorary key object containing the master key, perform the
	// encryption, then destroy the key object.  There is a race condition
	// here if the application is multithreaded (if a thread-switch occurs,
	// the other application thread could do a FindObject and be able to
	// access the master key object.
	//
	// So I have to use the low-level encryption routines.
	//

	if ((rc = get_encryption_info(&key_len, &block_size)) != CKR_OK)
		goto error;

	// Duplicate key
	key = malloc(key_len);
	if (!key)
		goto oom_error;
	memcpy(key, tokdata->master_key, key_len);


	clear_len = sizeof(CK_ULONG_32) + obj_data_len_32 + SHA1_HASH_SIZE;
	cipher_len = padded_len = block_size * (clear_len / block_size + 1);

	clear = malloc(padded_len);
	cipher = malloc(padded_len);
	if (!clear || !cipher)
		goto oom_error;

	// Build data that will be encrypted
	ptr = clear;
	memcpy(ptr, &obj_data_len_32, sizeof(CK_ULONG_32));
	ptr += sizeof(CK_ULONG_32);
	memcpy(ptr, obj_data, obj_data_len_32);
	ptr += obj_data_len_32;
	memcpy(ptr, hash_sha, SHA1_HASH_SIZE);

	add_pkcs_padding(clear + clear_len, block_size, clear_len,
			 padded_len);

	rc = encrypt_data_with_clear_key(tokdata, key, key_len,
			  token_specific.data_store.obj_initial_vector,
			  clear, padded_len, cipher, &cipher_len);
	if (rc != CKR_OK) {
		goto error;
	}

	sprintf(fname, "%s/%s/", tokdata->data_store, PK_LITE_OBJ_DIR);
	strncat((char *)fname, (char *)obj->name, 8);
	fp = fopen((char *)fname, "w");
	if (!fp) {
		TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
		rc = CKR_FUNCTION_FAILED;
		goto error;
	}

	set_perm(fileno(fp));

	total_len = sizeof(CK_ULONG_32) + sizeof(CK_BBOOL) + cipher_len;

	flag = TRUE;

	(void)fwrite(&total_len, sizeof(CK_ULONG_32), 1, fp);
	(void)fwrite(&flag, sizeof(CK_BBOOL), 1, fp);
	(void)fwrite(cipher, cipher_len, 1, fp);

	fclose(fp);
	free(obj_data);
	free(clear);
	free(cipher);
	free(key);
	return CKR_OK;

oom_error:
	rc = CKR_HOST_MEMORY;

error:
	if (fp)
		fclose(fp);
	if (obj_data)
		free(obj_data);
	if (clear)
		free(clear);
	if (cipher)
		free(cipher);
	if (key)
		free(key);

	return rc;
}

//
//
CK_RV load_public_token_objects(STDLL_TokData_t *tokdata)
{
	FILE *fp1 = NULL, *fp2 = NULL;
	CK_BYTE *buf = NULL;
	CK_BYTE tmp[PATH_MAX], fname[PATH_MAX], iname[PATH_MAX];
	CK_BBOOL priv;
	CK_ULONG_32 size;
	size_t read_size;

	sprintf(iname, "%s/%s/%s", tokdata->data_store, PK_LITE_OBJ_DIR,
		PK_LITE_OBJ_IDX);

	fp1 = fopen((char *)iname, "r");
	if (!fp1)
		return CKR_OK;	// no token objects

	while (fgets((char *)tmp, 50, fp1)) {
		tmp[strlen((char *)tmp) - 1] = 0;

		sprintf((char *)fname, "%s/%s/", tokdata->data_store,
			PK_LITE_OBJ_DIR);
		strcat((char *)fname, (char *)tmp);

		fp2 = fopen((char *)fname, "r");
		if (!fp2)
			continue;

		if (!fread(&size, sizeof(CK_ULONG_32), 1, fp2)) {
			fclose(fp2);
			OCK_SYSLOG(LOG_ERR, "Cannot read size\n");
			continue;
		}
		if (!fread(&priv, sizeof(CK_BBOOL), 1, fp2)) {
			fclose(fp2);
			OCK_SYSLOG(LOG_ERR, "Cannot read boolean\n");
			continue;
		}
		if (priv == TRUE) {
			fclose(fp2);
			continue;
		}
		// size--;
		size = size - sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);
		buf = (CK_BYTE *) malloc(size);
		if (!buf) {
			fclose(fp2);
			OCK_SYSLOG(LOG_ERR,
				   "Cannot malloc %u bytes to read in "
				   "token object %s (ignoring it)",
				   size, fname);
			continue;
		}

		read_size = fread(buf, 1, size, fp2);
		if (read_size != size) {
			fclose(fp2);
			free(buf);
			OCK_SYSLOG(LOG_ERR,
				   "Cannot read token object %s "
				   "(ignoring it)", fname);
			continue;
		}
		// ... grab object mutex here.
		if (object_mgr_restore_obj_withSize(tokdata, buf,
						    NULL, size) !=
						    CKR_OK) {
			OCK_SYSLOG(LOG_ERR,
				   "Cannot restore token object %s "
				   "(ignoring it)", fname);
		}
		free(buf);
		fclose(fp2);
	}
	fclose(fp1);

	return CKR_OK;
}

//
//
CK_RV load_private_token_objects(STDLL_TokData_t *tokdata)
{
	FILE *fp1 = NULL, *fp2 = NULL;
	CK_BYTE *buf = NULL;
	CK_BYTE tmp[PATH_MAX], fname[PATH_MAX], iname[PATH_MAX];
	CK_BBOOL priv;
	CK_ULONG_32 size;
	CK_RV rc;
	size_t read_size;

	sprintf(iname, "%s/%s/%s", tokdata->data_store, PK_LITE_OBJ_DIR,
		PK_LITE_OBJ_IDX);

	fp1 = fopen((char *)iname, "r");
	if (!fp1)
		return CKR_OK;	// no token objects

	while (fgets((char *)tmp, 50, fp1)) {
		tmp[strlen((char *)tmp) - 1] = 0;

		sprintf((char *)fname, "%s/%s/", tokdata->data_store,
			PK_LITE_OBJ_DIR);
		strcat((char *)fname, (char *)tmp);

		fp2 = fopen((char *)fname, "r");
		if (!fp2)
			continue;

		if (!fread(&size, sizeof(CK_ULONG_32), 1, fp2)) {
			fclose(fp2);
			OCK_SYSLOG(LOG_ERR, "Cannot read size\n");
			continue;
		}
		if (!fread(&priv, sizeof(CK_BBOOL), 1, fp2)) {
			fclose(fp2);
			OCK_SYSLOG(LOG_ERR, "Cannot read boolean\n");
			continue;
		}
		if (priv == FALSE) {
			fclose(fp2);
			continue;
		}
		//size--;
		size = size - sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);
		buf = (CK_BYTE *) malloc(size);
		if (!buf) {
			fclose(fp2);
			OCK_SYSLOG(LOG_ERR,
				   "Cannot malloc %u bytes to read in "
				   "token object %s (ignoring it)",
				   size, fname);
			continue;
		}

		read_size = fread((char *)buf, 1, size, fp2);
		if (read_size != size) {
			free(buf);
			fclose(fp2);
			OCK_SYSLOG(LOG_ERR,
				   "Cannot read token object %s "
				   "(ignoring it)", fname);
			continue;
		}
		// Grab object list  mutex
		MY_LockMutex(&obj_list_mutex);
		rc = restore_private_token_object(tokdata, buf,
						  size, NULL);
		MY_UnlockMutex(&obj_list_mutex);
		if (rc != CKR_OK)
			goto error;

		free(buf);
		fclose(fp2);
	}
	fclose(fp1);

	return CKR_OK;

error:
	if (buf)
		free(buf);
	if (fp1)
		fclose(fp1);
	if (fp2)
		fclose(fp2);
	return rc;
}

//
//
CK_RV restore_private_token_object(STDLL_TokData_t *tokdata, CK_BYTE * data,
				   CK_ULONG len, OBJECT * pObj)
{
	CK_BYTE *clear = NULL;
	CK_BYTE *obj_data = NULL;
        CK_BYTE *ptr = NULL;
	CK_BYTE *key = NULL;
	CK_ULONG key_len;
	CK_ULONG block_size;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	CK_ULONG clear_len, obj_data_len;
	CK_RV rc;

	// format for the object data:
	//    (private flag has already been read at this point)
	//    ---- begin encrypted part
	//       length of object data
	//       object data
	//       SHA of object data
	//    ---- end encrypted part
	//

	clear_len = len;

	clear = (CK_BYTE *) malloc(len);
	if (!clear) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_HOST_MEMORY;
		goto done;
	}

	if ((rc = get_encryption_info(&key_len, &block_size)) != CKR_OK)
		goto done;

	// decrypt the encrypted chunk
	key = malloc(key_len);
	if (!key) {
		rc = ERR_HOST_MEMORY;
		goto done;
	}
	memcpy(key, tokdata->master_key, key_len);

	rc = decrypt_data_with_clear_key(tokdata, key, key_len,
			  token_specific.data_store.obj_initial_vector,
			  data, len, clear, &clear_len);
	if (rc != CKR_OK) {
		goto done;
	}

	rc = strip_pkcs_padding(clear, len, &clear_len);

	// if the padding extraction didn't work it means the object was
	// tampered with or the key was incorrect
	//
	if (rc != CKR_OK || (clear_len > len)) {
		TRACE_DEVEL("strip_pkcs_padding failed.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	ptr = clear;

	obj_data_len = *(CK_ULONG_32 *) ptr;

	// prevent buffer overflow in sha_update
	if (obj_data_len > clear_len) {
		TRACE_ERROR("stripped length is greater than clear length\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	ptr += sizeof(CK_ULONG_32);
	obj_data = ptr;

	// check the hash
	//
	rc = compute_sha1(tokdata, ptr, obj_data_len, hash_sha);
	if (rc != CKR_OK) {
		goto done;
	}
	ptr += obj_data_len;

	if (memcmp(ptr, hash_sha, SHA1_HASH_SIZE) != 0) {
		TRACE_ERROR("stored hash does not match restored data hash.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	// okay.  at this point, we're satisfied that nobody has tampered with
	// the token object...
	//

	rc = object_mgr_restore_obj(tokdata, obj_data, pObj);
	if (rc != CKR_OK) {
		goto done;
	}
	rc = CKR_OK;

done:
	if (clear)
		free(clear);
	if (key)
		free(key);

	return rc;
}

//
//
CK_RV load_masterkey_so(STDLL_TokData_t *tokdata)
{
	FILE *fp = NULL;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	CK_BYTE *cipher = NULL;
	CK_BYTE *clear = NULL;
	CK_BYTE *key = NULL;
	CK_ULONG data_len;
	CK_ULONG cipher_len, clear_len;
	CK_RV rc;
	CK_BYTE fname[PATH_MAX];
	CK_ULONG key_len = 0L;
	CK_ULONG master_key_len = 0L;
	CK_ULONG block_size = 0L;

	if ((rc = get_encryption_info_for_clear_key(&key_len,
						    &block_size)) != CKR_OK)
		goto done;

	if ((rc = get_encryption_info(&master_key_len, NULL)) != CKR_OK)
		goto done;

	memset(tokdata->master_key, 0x0, master_key_len);

	data_len = master_key_len + SHA1_HASH_SIZE;
	clear_len = cipher_len = (data_len + block_size - 1)
		& ~(block_size - 1);

	key = malloc(key_len);
	cipher = malloc(cipher_len);
	clear = malloc(clear_len);
	if (key == NULL || cipher == NULL || clear == NULL) {
		rc = ERR_HOST_MEMORY;
		goto done;
	}

	// this file gets created on C_InitToken so we can assume that it always
	// exists
	//
	sprintf(fname, "%s/MK_SO", tokdata->data_store);
	fp = fopen((char *)fname, "r");
	if (!fp) {
		TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	set_perm(fileno(fp));

	rc = fread(cipher, cipher_len, 1, fp);
	if (rc != 1) {
		TRACE_ERROR("fread() failed.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	// decrypt the master key data using the MD5 of the SO key
	// (we can't use the SHA of the SO key since the SHA of the key is
	// stored in the token data file).
	memcpy(key, tokdata->so_pin_md5, MD5_HASH_SIZE);
	memcpy(key + MD5_HASH_SIZE, tokdata->so_pin_md5,
	       key_len - MD5_HASH_SIZE);

	rc = decrypt_data_with_clear_key(tokdata, key, key_len,
					 token_specific.data_store.pin_initial_vector,
					 cipher, cipher_len,
					 clear, &clear_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("decrypt_data_with_clear_key failed.\n");
		goto done;
	}

	//
	// technically should strip PKCS padding here but since I already know
	// what the length should be, I don't bother.
	//

	// compare the hashes
	//
	rc = compute_sha1(tokdata, clear, master_key_len, hash_sha);
	if (rc != CKR_OK) {
		goto done;
	}

	if (memcmp(hash_sha, clear + master_key_len, SHA1_HASH_SIZE) != 0) {
		TRACE_ERROR("masterkey hashes do not match\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	memcpy(tokdata->master_key, clear, master_key_len);
	rc = CKR_OK;

done:
	if (fp)
		fclose(fp);
	if (clear)
		free(clear);
	if (cipher)
		free(cipher);
	if (key)
		free(key);
	return rc;
}

//
//
CK_RV load_masterkey_user(STDLL_TokData_t *tokdata)
{
	FILE *fp = NULL;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	CK_BYTE *cipher = NULL;
	CK_BYTE *clear = NULL;
	CK_BYTE *key = NULL;
	CK_ULONG data_len;
	CK_ULONG cipher_len, clear_len;
	CK_RV rc;
	CK_BYTE fname[PATH_MAX];
	CK_ULONG key_len = 0L;
	CK_ULONG master_key_len = 0L;
	CK_ULONG block_size = 0L;

	if ((rc = get_encryption_info_for_clear_key(&key_len,
						    &block_size)) != CKR_OK)
		goto done;

	if ((rc = get_encryption_info(&master_key_len, NULL)) != CKR_OK)
		goto done;

	memset(tokdata->master_key, 0x0, master_key_len);

	data_len = master_key_len + SHA1_HASH_SIZE;
	clear_len = cipher_len = (data_len + block_size - 1)
				 & ~(block_size - 1);

	key = malloc(key_len);
	cipher = malloc(cipher_len);
	clear = malloc(clear_len);
	if (key == NULL || cipher == NULL || clear == NULL) {
		rc = ERR_HOST_MEMORY;
		goto done;
	}

	// this file gets created on C_InitToken so we can assume that it always
	// exists
	//
	sprintf(fname, "%s/MK_USER", tokdata->data_store);
	fp = fopen((char *)fname, "r");
	if (!fp) {
		TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	set_perm(fileno(fp));

	rc = fread(cipher, cipher_len, 1, fp);
	if (rc != 1) {
		TRACE_ERROR("fread failed.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	// decrypt the master key data using the MD5 of the SO key
	// (we can't use the SHA of the SO key since the SHA of the key is
	// stored in the token data file).
	memcpy(key, tokdata->user_pin_md5, MD5_HASH_SIZE);
	memcpy(key + MD5_HASH_SIZE, tokdata->user_pin_md5,
	       key_len - MD5_HASH_SIZE);

	rc = decrypt_data_with_clear_key(tokdata, key, key_len,
					 token_specific.data_store.pin_initial_vector,
					 cipher, cipher_len,
					 clear, &clear_len);
	if (rc != CKR_OK) {
		TRACE_DEVEL("decrypt_data_with_clear_key failed.\n");
		goto done;
	}

	//
	// technically should strip PKCS padding here but since I already know
	// what the length should be, I don't bother.
	//

	// compare the hashes
	//
	rc = compute_sha1(tokdata, clear, master_key_len, hash_sha);
	if (rc != CKR_OK) {
		goto done;
	}

	if (memcmp(hash_sha, clear + master_key_len, SHA1_HASH_SIZE) != 0) {
		TRACE_ERROR("User's masterkey hashes do not match.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	memcpy(tokdata->master_key, clear, master_key_len);
	rc = CKR_OK;

done:
	if (fp)
		fclose(fp);
	if (key)
		free(key);
	if (clear)
		free(clear);
	if (cipher)
		free(cipher);
	return rc;
}

//
//
CK_RV save_masterkey_so(STDLL_TokData_t *tokdata)
{
	FILE *fp = NULL;
	CK_BYTE *clear = NULL;
	CK_ULONG clear_len = 0L;
	CK_BYTE *cipher = NULL;
	CK_ULONG cipher_len = 0L;
	CK_BYTE *key = NULL;
	CK_ULONG key_len = 0L;
	CK_ULONG master_key_len = 0L;
	CK_ULONG block_size = 0L;
	CK_ULONG data_len = 0L;
	CK_BYTE fname[PATH_MAX];
	CK_RV rc;

	/* Skip it if master key is not needed. */
	if (!token_specific.data_store.use_master_key)
		return CKR_OK;

	if ((rc = get_encryption_info_for_clear_key(&key_len,
						    &block_size)) != CKR_OK)
		goto done;

	if ((rc = get_encryption_info(&master_key_len, NULL)) != CKR_OK)
		goto done;

	data_len = master_key_len + SHA1_HASH_SIZE;
	cipher_len = clear_len = block_size * (data_len / block_size + 1);

	key = malloc(key_len);
	clear = malloc(clear_len);
	cipher = malloc(cipher_len);
	if (key == NULL || clear == NULL || cipher == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = ERR_HOST_MEMORY;
		goto done;
	}

	// Copy data to buffer (key+hash)
	memcpy(clear, tokdata->master_key, master_key_len);
	if ((rc = compute_sha1(tokdata, tokdata->master_key,
			       master_key_len, clear + master_key_len)) != CKR_OK)
		goto done;
	add_pkcs_padding(clear + data_len, block_size, data_len,
			 clear_len);

	// encrypt the key data
	memcpy(key, tokdata->so_pin_md5, MD5_HASH_SIZE);
	memcpy(key + MD5_HASH_SIZE, tokdata->so_pin_md5,
	       key_len - MD5_HASH_SIZE);

	rc = encrypt_data_with_clear_key(tokdata, key, key_len,
					 token_specific.data_store.pin_initial_vector,
					 clear, clear_len,
					 cipher, &cipher_len);
	if (rc != CKR_OK) {
		goto done;
	}

	// write the file
	//
	// probably ought to ensure the permissions are correct
	//
	sprintf(fname, "%s/MK_SO", tokdata->data_store);
	fp = fopen((char *)fname, "w");
	if (!fp) {
		TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	set_perm(fileno(fp));

	rc = fwrite(cipher, cipher_len, 1, fp);
	if (rc != 1) {
		TRACE_ERROR("fwrite failed.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	rc = CKR_OK;

done:
	if (fp)
		fclose(fp);
	if (key)
		free(key);
	if (clear)
		free(clear);
	if (cipher)
		free(cipher);
	return rc;
}

//
//
CK_RV save_masterkey_user(STDLL_TokData_t *tokdata)
{
	FILE *fp = NULL;
	CK_BYTE *clear = NULL;
	CK_ULONG clear_len = 0L;
	CK_BYTE *cipher = NULL;
	CK_ULONG cipher_len = 0L;
	CK_BYTE *key = NULL;
	CK_ULONG key_len = 0L;
	CK_ULONG master_key_len = 0L;
	CK_ULONG block_size = 0L;
	CK_ULONG data_len = 0L;
	CK_BYTE fname[PATH_MAX];
	CK_RV rc;

	if ((rc = get_encryption_info_for_clear_key(&key_len,
						    &block_size)) != CKR_OK)
		goto done;

	if ((rc = get_encryption_info(&master_key_len, NULL)) != CKR_OK)
		goto done;

	data_len = master_key_len + SHA1_HASH_SIZE;
	cipher_len = clear_len = block_size * (data_len/block_size + 1);

	key = malloc(key_len);
	clear = malloc(clear_len);
	cipher = malloc(cipher_len);
	if (key == NULL || clear == NULL || cipher == NULL) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = ERR_HOST_MEMORY;
		goto done;
	}

	// Copy data to buffer (key+hash)
	memcpy(clear, tokdata->master_key, master_key_len);
	if ((rc = compute_sha1(tokdata, tokdata->master_key,
			       master_key_len, clear + master_key_len)) != CKR_OK)
		goto done;
	add_pkcs_padding(clear + data_len, block_size , data_len,
			 clear_len);

	// encrypt the key data
	memcpy(key, tokdata->user_pin_md5, MD5_HASH_SIZE);
	memcpy(key + MD5_HASH_SIZE, tokdata->user_pin_md5,
	       key_len - MD5_HASH_SIZE);

	rc = encrypt_data_with_clear_key(tokdata, key, key_len,
					 token_specific.data_store.pin_initial_vector,
					 clear, clear_len,
					 cipher, &cipher_len);
	if (rc != CKR_OK) {
		goto done;
	}

	// write the file
	//
	// probably ought to ensure the permissions are correct
	//
	sprintf(fname, "%s/MK_USER", tokdata->data_store);
	fp = fopen((char *)fname, "w");
	if (!fp) {
		TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	set_perm(fileno(fp));
	rc = fwrite(cipher, cipher_len, 1, fp);
	if (rc != 1) {
		TRACE_ERROR("fwrite failed.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	rc = CKR_OK;

done:
	if (fp)
		fclose(fp);
	if (key)
		free(key);
	if (clear)
		free(clear);
	if (cipher)
		free(cipher);
	return rc;
}

//
//
CK_RV reload_token_object(STDLL_TokData_t *tokdata, OBJECT * obj)
{
	FILE *fp = NULL;
	CK_BYTE *buf = NULL;
	CK_BYTE fname[PATH_MAX];
	CK_BBOOL priv;
	CK_ULONG_32 size;
	CK_ULONG size_64;
	CK_RV rc;
	size_t read_size;

	memset((char *)fname, 0x0, sizeof(fname));

	sprintf((char *)fname, "%s/%s/", tokdata->data_store, PK_LITE_OBJ_DIR);

	strncat((char *)fname, (char *)obj->name, 8);

	fp = fopen((char *)fname, "r");
	if (!fp) {
		TRACE_ERROR("fopen(%s): %s\n", fname, strerror(errno));
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	set_perm(fileno(fp));

	if (!fread(&size, sizeof(CK_ULONG_32), 1, fp)) {
		OCK_SYSLOG(LOG_ERR, "Cannot read size\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (!fread(&priv, sizeof(CK_BBOOL), 1, fp)) {
		OCK_SYSLOG(LOG_ERR, "Cannot read boolean\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	size = size - sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);	// SAB

	buf = (CK_BYTE *) malloc(size);
	if (!buf) {
		rc = CKR_HOST_MEMORY;
		OCK_SYSLOG(LOG_ERR,
			   "Cannot malloc %u bytes to read in token object %s "
			   "(ignoring it)", size, fname);
		goto done;
	}

	read_size = fread(buf, 1, size, fp);
	if (read_size != size) {
		OCK_SYSLOG(LOG_ERR,
			   "Token object %s appears corrupted (ignoring it)",
			   fname);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	size_64 = size;

	if (priv)
		rc = restore_private_token_object(tokdata, buf, size_64, obj);
	else
		rc = object_mgr_restore_obj(tokdata, buf, obj);

done:
	if (fp)
		fclose(fp);
	if (buf)
		free(buf);
	return rc;
}

extern void set_perm(int);

//
//
CK_RV delete_token_object(STDLL_TokData_t *tokdata, OBJECT * obj)
{
	FILE *fp1, *fp2;
	CK_BYTE line[100];
	CK_BYTE objidx[PATH_MAX], idxtmp[PATH_MAX], fname[PATH_MAX];

	sprintf((char *)objidx, "%s/%s/%s", tokdata->data_store,
		PK_LITE_OBJ_DIR, PK_LITE_OBJ_IDX);
	sprintf((char *)idxtmp, "%s/%s/%s", tokdata->data_store,
		PK_LITE_OBJ_DIR, "IDX.TMP");

	// FIXME:  on UNIX, we need to make sure these guys aren't symlinks
	//         before we blindly write to these files...
	//

	// remove the object from the index file
	//

	fp1 = fopen((char *)objidx, "r");
	fp2 = fopen((char *)idxtmp, "w");
	if (!fp1 || !fp2) {
		if (fp1)
			fclose(fp1);
		if (fp2)
			fclose(fp2);
		TRACE_ERROR("fopen failed\n");
		return CKR_FUNCTION_FAILED;
	}

	set_perm(fileno(fp2));

	while (fgets((char *)line, 50, fp1)) {
		line[strlen((char *)line) - 1] = 0;
		if (strcmp((char *)line, (char *)obj->name) == 0)
			continue;
		else
			fprintf(fp2, "%s\n", line);
	}

	fclose(fp1);
	fclose(fp2);
	fp2 = fopen((char *)objidx, "w");
	fp1 = fopen((char *)idxtmp, "r");
	if (!fp1 || !fp2) {
		if (fp1)
			fclose(fp1);
		if (fp2)
			fclose(fp2);
		TRACE_ERROR("fopen failed\n");
		return CKR_FUNCTION_FAILED;
	}

	set_perm(fileno(fp2));

	while (fgets((char *)line, 50, fp1)) {
		fprintf(fp2, "%s", (char *)line);
	}

	fclose(fp1);
	fclose(fp2);

	sprintf((char *)fname, "%s/%s/%s", tokdata->data_store,
		PK_LITE_OBJ_DIR, (char *)obj->name);
	unlink((char *)fname);
	return CKR_OK;

}

CK_RV delete_token_data(STDLL_TokData_t *tokdata)
{
	CK_RV rc = CKR_OK;
	char *cmd = NULL;

	// Construct a string to delete the token objects.
	//
	// META This should be fine since the open session checking
	// should occur at the API not the STDLL
	//
	// TODO: Implement delete_all_files_in_dir() */
	if (asprintf(&cmd, "%s %s/%s/* > /dev/null 2>&1", DEL_CMD,
		     tokdata->data_store, PK_LITE_OBJ_DIR) < 0) {
		rc = CKR_HOST_MEMORY;
		goto done;
	}

	if (system(cmd))
		TRACE_ERROR("system() failed.\n");

done:
	free(cmd);
	return rc;
}

CK_RV generate_master_key(STDLL_TokData_t *tokdata, CK_BYTE *key)
{
	CK_RV rc = CKR_OK;
	CK_ULONG key_len = 0L;
	CK_ULONG master_key_len = 0L;

	/* Skip it if master key is not needed. */
   	if (!token_specific.data_store.use_master_key)
		return CKR_OK;

	if ((rc = get_encryption_info_for_clear_key(&key_len, NULL)) != CKR_OK ||
	    (rc = get_encryption_info(&master_key_len, NULL)) != CKR_OK)
		return ERR_FUNCTION_FAILED;

	/* For secure key tokens, object encrypt/decrypt uses
	 * software(openssl), not token. So generate masterkey via RNG.
	 */
	if (token_specific.token_keysize)
		return rng_generate(tokdata, key, key_len);

	/* For clear key tokens, let token generate masterkey
	 * since token will also encrypt/decrypt the objects.
	 */
	switch (token_specific.data_store.encryption_algorithm) {
	case CKM_DES3_CBC:
		return token_specific.t_des_key_gen(tokdata, key,
						    master_key_len, key_len);
	case CKM_AES_CBC:
		return token_specific.t_aes_key_gen(tokdata, key,
						    master_key_len, key_len);
	}

	return ERR_MECHANISM_INVALID;
}

void init_data_store(char *directory, char *data_store)
{
	char *pkdir;
	if ((pkdir = getenv("PKCS_APP_STORE")) != NULL) {
		pk_dir = (char *)malloc(strlen(pkdir) + 1024);
		memset(pk_dir, 0, strlen(pkdir) + 1024);
		sprintf(pk_dir, "%s/%s", pkdir, SUB_DIR);
		return;
	}

	if (directory) {
		pk_dir = (char *)malloc(strlen(directory) + 25);
		memset(pk_dir, 0, strlen(directory) + 25);
		sprintf(pk_dir, "%s", directory);
		memcpy(data_store, pk_dir, strlen(directory) + 25);
	}
	else {
		pk_dir = (char *)malloc(strlen(PK_DIR) + 25);
		memset(pk_dir, 0, strlen(PK_DIR) + 25);
		sprintf(pk_dir, "%s", PK_DIR);
		memcpy(data_store, pk_dir, strlen(PK_DIR) + 25);
	}
	return;
}
