/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki ICSF token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006, 2012
 *
 * Author: Marcelo Cerri (mhcerri@br.ibm.com)
 *
 * Based on CCC token.
 *
 */

#define _GNU_SOURCE
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <pthread.h>
#include <errno.h>
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "pbkdf.h"
#include "h_extern.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "icsf_config.h"
#include "pbkdf.h"
#include "list.h"
#include "attributes.h"
#include "../api/apiproto.h"
#include "trace.h"
#include "shared_memory.h"

/* Default token attributes */
CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "IBM ICSFTok ";
CK_CHAR descr[] = "IBM PKCS#11 ICSF token";
CK_CHAR label[] = "IBM OS PKCS#11   ";

/* mechanisms provided by this token */
MECH_LIST_ELEMENT mech_list[] = {
	{CKM_DES_KEY_GEN, {8, 8, CKF_HW|CKF_GENERATE}},
	{CKM_DES_ECB, {0, 0, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT}},
	{CKM_DES_CBC, {0, 0, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT}},
	{CKM_DES_CBC_PAD, {0, 0, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|
			   CKF_UNWRAP}},
	{CKM_DES3_ECB, {0, 0, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT}},
	{CKM_DES3_CBC, {0, 0, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT}},
	{CKM_DES3_CBC_PAD, {0, 0, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|
			    CKF_UNWRAP}},
	{CKM_DES3_KEY_GEN, {24, 24, CKF_HW|CKF_GENERATE}},
	{CKM_DES2_KEY_GEN, {24, 24, CKF_HW|CKF_GENERATE}},
	{CKM_RSA_PKCS_KEY_PAIR_GEN, {512, 4096, CKF_HW|CKF_GENERATE_KEY_PAIR}},
	{CKM_RSA_PKCS, {512, 4096, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|
			CKF_UNWRAP|CKF_SIGN|CKF_VERIFY|CKF_SIGN_RECOVER|
			CKF_VERIFY_RECOVER}},
	{CKM_RSA_X_509, {512, 4096, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_SIGN|
			 CKF_VERIFY|CKF_SIGN_RECOVER|CKF_VERIFY_RECOVER}},
	{CKM_MD5_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA1_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA256_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA384_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA512_RSA_PKCS, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA_1, {0, 0, CKF_HW|CKF_DIGEST}},
	{CKM_SHA_1_HMAC, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA256_HMAC, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA384_HMAC, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_SHA512_HMAC, {0, 0, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_MD5, {0, 0, CKF_DIGEST}},
	{CKM_MD5_HMAC, {0, 0, CKF_SIGN|CKF_VERIFY}},
	{CKM_AES_KEY_GEN, {16, 32, CKF_HW|CKF_GENERATE}},
	{CKM_AES_ECB, {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT}},
	{CKM_AES_CBC, {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT}},
	{CKM_AES_CBC_PAD, {16, 32, CKF_HW|CKF_ENCRYPT|CKF_DECRYPT|CKF_WRAP|
			   CKF_UNWRAP}},
	{CKM_DH_PKCS_KEY_PAIR_GEN, {512, 2048, CKF_GENERATE_KEY_PAIR}},
	{CKM_DH_PKCS_DERIVE, {512, 2048, CKF_DERIVE}},
	{CKM_DSA_KEY_PAIR_GEN, {512, 2048, CKF_HW|CKF_GENERATE_KEY_PAIR}},
	{CKM_DSA_SHA1, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_DSA, {512, 2048, CKF_HW|CKF_SIGN|CKF_VERIFY}},
	{CKM_ECDSA_SHA1, {512, 4096, CKF_HW|CKF_SIGN|CKF_VERIFY|CKF_EC_F_P|
			  CKF_EC_NAMEDCURVE|CKF_EC_UNCOMPRESS}},
	{CKM_ECDSA, {160, 521, CKF_HW|CKF_SIGN|CKF_VERIFY|CKF_EC_F_P|
		     CKF_EC_NAMEDCURVE|CKF_EC_UNCOMPRESS}},
	{CKM_EC_KEY_PAIR_GEN, {160, 521, CKF_HW|CKF_GENERATE_KEY_PAIR|
			       CKF_EC_F_P|CKF_EC_NAMEDCURVE|CKF_EC_UNCOMPRESS}},
	{CKM_SSL3_PRE_MASTER_KEY_GEN, {48, 48, CKF_HW|CKF_GENERATE}},
	{CKM_SSL3_MD5_MAC, {384, 384, CKF_SIGN|CKF_VERIFY}},
	{CKM_SSL3_SHA1_MAC, {384, 384, CKF_SIGN|CKF_VERIFY}},
	{CKM_SSL3_MASTER_KEY_DERIVE, {48, 48, CKF_DERIVE}},
	{CKM_SSL3_KEY_AND_MAC_DERIVE, {48, 48, CKF_DERIVE}},
	{CKM_TLS_KEY_AND_MAC_DERIVE, {48, 48, CKF_DERIVE}},
};

CK_ULONG mech_list_len = (sizeof(mech_list) / sizeof(MECH_LIST_ELEMENT));

/*
 * This list contains one element to each session and it's used to keep
 * session specific data. Any insertion or deletion in this list should
 * be protected by sess_list_mutex.
 *
 * This lock is intended to protect the linked list, not the content of each
 * element. Since PKCS#11 applications should not use the same session for
 * different threads, the only concurrency that we have to deal is when adding
 * or removing a session to or from the list.
 */
list_t sessions = LIST_INIT();
extern pthread_mutex_t sess_list_mutex;

/* Each element of the list sessions should have this type: */
struct session_state {
	CK_SESSION_HANDLE session_id;
	LDAP *ld;

	/* List element */
	list_entry_t sessions;
};

/*
 * This binary tree keeps the mapping between ICSF object handles and PKCS#11
 * object handles. The tree index is used as the PKCS#11 handle.
 *
 * Any insertion or deletion in this tree should be protected by
 * obj_list_rw_mutex.
 */
struct btree objects;
extern pthread_rwlock_t obj_list_rw_mutex;

/* Each element of the btree objects should have this type: */
struct icsf_object_mapping {
	CK_SESSION_HANDLE session_id;
	struct icsf_object_record icsf_object;
};

/*
 * Structure used to keep track of data used in multi-part operations.
 */
struct icsf_multi_part_context {
	int initiated;
	char chain_data[ICSF_CHAINING_DATA_LEN];
	char *data;
	size_t data_len;
	size_t used_data_len;
};

/*
 * Get the session specific structure.
 */
static struct session_state *get_session_state(CK_SESSION_HANDLE session_id)
{
	struct session_state *found = NULL;
	struct session_state *s;

	/* Lock sessions list */
	if (pthread_mutex_lock(&sess_list_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		return NULL;
	}

	for_each_list_entry(&sessions, struct session_state, s, sessions) {
		if (s->session_id == session_id) {
			found = s;
			goto done;
		}
	}

done:
	/* Unlock */
	if (pthread_mutex_unlock(&sess_list_mutex)) {
		TRACE_ERROR("Mutex Unlock failed.\n");
		return NULL;
	}

	return found;
}

/*
 * Remove all mapped objects.
 */
static CK_RV purge_object_mapping()
{
	if (pthread_rwlock_wrlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		return CKR_FUNCTION_FAILED;
	}

	bt_destroy(&objects, free);

	if (pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock failed.\n");
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

/* Store ICSF specific data for each slot*/
struct slot_data {
	int initialized;
	char conf_name[PATH_MAX + 1];
	char uri[PATH_MAX + 1];
	char dn[NAME_MAX + 1];
	char ca_file[PATH_MAX + 1];
	char cert_file[PATH_MAX + 1];
	char key_file[PATH_MAX + 1];
	int mech;
};
struct slot_data *slot_data[MAX_SLOT_ID + 1];

/*
 * Converts an ICSF reason code to an ock error code
 */
int icsf_to_ock_err(int icsf_return_code, int icsf_reason_code)
{
	switch(icsf_return_code) {
	case 0:
		return CKR_OK;
	case 4:
		switch(icsf_reason_code) {
		case 8000:
		case 11000:
			return CKR_SIGNATURE_INVALID;
		}
		break;
	case 8:
		switch(icsf_reason_code) {
		case 2154:
			return CKR_KEY_TYPE_INCONSISTENT;
		case 3003:
			return CKR_BUFFER_TOO_SMALL;
		case 3019:
			return CKR_SESSION_HANDLE_INVALID;
		case 3027:
			return CKR_SESSION_HANDLE_INVALID;
		case 3029:
			return CKR_ATTRIBUTE_TYPE_INVALID;
		case 3030:
			return CKR_ATTRIBUTE_VALUE_INVALID;
		case 3033:
			return CKR_TEMPLATE_INCOMPLETE;
		case 3034:
		case 3035:
			return CKR_ATTRIBUTE_READ_ONLY;
		case 3038:
			return CKR_KEY_FUNCTION_NOT_PERMITTED;
		case 3039:
			return CKR_KEY_TYPE_INCONSISTENT;
		case 3041:
			return CKR_KEY_NOT_WRAPPABLE;
		case 3043:
			return CKR_BUFFER_TOO_SMALL;
		case 3045:
			return CKR_KEY_UNEXTRACTABLE;
		case 3046:
			return CKR_BUFFER_TOO_SMALL;
		case 11000:
			return CKR_DATA_LEN_RANGE;
		}
		break;
	}
	return CKR_FUNCTION_FAILED;
}

/*
 * Called during C_Initialize.
 */
CK_RV icsftok_init(CK_SLOT_ID slot_id, char *conf_name)
{
	CK_RV rc = CKR_OK;
	struct slot_data *data;

	/* Check Slot ID */
	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	XProcLock();

	if (slot_data[slot_id] == NULL) {
		TRACE_ERROR("ICSF slot data not initialized.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	data = slot_data[slot_id];

	strncpy(data->conf_name, conf_name, sizeof(data->conf_name) - 1);
	data->conf_name[sizeof(data->conf_name) - 1] = '\0';

done:
	XProcUnLock();
	return rc;
}

CK_RV token_specific_init_token_data(CK_SLOT_ID slot_id)
{
	CK_RV rc = CKR_OK;
	const char *conf_name = NULL;
	struct icsf_config config;

	/* Check Slot ID */
	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	XProcLock();

	if (slot_data[slot_id] == NULL) {
		TRACE_ERROR("ICSF slot data not initialized.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Check if data needs to be retrieved for this slot */
	if (slot_data[slot_id]->initialized) {
		TRACE_DEVEL("Slot data already initialized for slot %lu. "
			      "Skipping it\n", slot_id);
		goto done;
	}

	/* Check config file */
	conf_name = slot_data[slot_id]->conf_name;
	if (!conf_name || !conf_name[0]) {
		TRACE_ERROR("Missing config for slot %lu.\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	TRACE_DEVEL("DEBUG: conf_name=\"%s\".\n", conf_name);
	if (parse_config_file(conf_name, slot_id, &config)) {
		TRACE_ERROR("Failed to parse file \"%s\" for slot %lu.\n",
			      conf_name, slot_id);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Copy general info */
	strcpy(nv_token_data->token_info.label, config.name);
	strcpy(nv_token_data->token_info.manufacturerID, config.manuf);
	strcpy(nv_token_data->token_info.model, config.model);
	strcpy(nv_token_data->token_info.serialNumber, config.serial);

	/* Copy ICSF specific info */
	strcpy(slot_data[slot_id]->uri, config.uri);
	strcpy(slot_data[slot_id]->dn, config.dn);
	strcpy(slot_data[slot_id]->ca_file, config.ca_file);
	strcpy(slot_data[slot_id]->cert_file, config.cert_file);
	strcpy(slot_data[slot_id]->key_file, config.key_file);
	slot_data[slot_id]->initialized = 1;
	slot_data[slot_id]->mech = config.mech;

done:
	XProcUnLock();
	return rc;
}

CK_RV token_specific_load_token_data(CK_SLOT_ID slot_id, FILE *fh)
{
	CK_RV rc = CKR_OK;
	struct slot_data data;

	/* Check Slot ID */
	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	if (!fread(&data, sizeof(data), 1, fh)) {
		TRACE_ERROR("Failed to read ICSF slot data.\n");
		return CKR_FUNCTION_FAILED;
	}

	XProcLock();

	if (slot_data[slot_id] == NULL) {
		TRACE_ERROR("ICSF slot data not initialized.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	memcpy(slot_data[slot_id], &data, sizeof(data));

done:
	XProcUnLock();
	return rc;
}

CK_RV
token_specific_save_token_data(CK_SLOT_ID slot_id, FILE *fh)
{
	CK_RV rc = CKR_OK;

	/* Check Slot ID */
	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	XProcLock();

	if (slot_data[slot_id] == NULL) {
		TRACE_ERROR("ICSF slot data not initialized.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (!fwrite(slot_data[slot_id], sizeof(**slot_data), 1, fh)) {
		TRACE_ERROR("Failed to write ICSF slot data.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

done:
	XProcUnLock();
	return rc;
}

/*
 * Initialize the shared memory region. ICSF has to use a custom method for
 * this because it uses additional data in the shared memory and in the future
 * multiple slots should be supported for ICSF.
 */
CK_RV token_specific_attach_shm(CK_SLOT_ID slot_id, LW_SHM_TYPE **shm)
{
	CK_RV rc = CKR_OK;
	int ret;
	void *ptr;
	size_t len = sizeof(**shm) + sizeof(**slot_data);
	char *shm_id = NULL;

	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	if (asprintf(&shm_id, "/icsf-%lu", slot_id) < 0) {
		TRACE_ERROR("Failed to allocate shared memory id "
			      "for slot %lu.\n", slot_id);
		return CKR_HOST_MEMORY;
	}
	TRACE_DEVEL("Attaching to shared memory \"%s\".\n", shm_id);

	XProcLock();

	/*
	 * Attach to an existing shared memory region or create it if it doesn't
	 * exists. When the it's created (ret=0) the region is initialized with
	 * zeroes.
	 */
	ret = sm_open(shm_id, 0666, (void**) &ptr, len, 1);
	if (ret < 0) {
		TRACE_ERROR("Failed to open shared memory \"%s\".\n", shm_id);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	*shm = ptr;
	slot_data[slot_id] = ptr + sizeof(**shm);

done:
	XProcUnLock();
	if (shm_id)
		free(shm_id);
	return rc;
}

CK_RV login(LDAP **ld, CK_SLOT_ID slot_id, CK_BYTE *pin, CK_ULONG pin_len,
	    const char *pass_file_type)
{
	CK_RV rc = CKR_OK;
	struct slot_data data;
	LDAP *ldapd = NULL;
	char *fname = NULL;
	int ret;

	/* Check Slot ID */
	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	XProcLock();

	/* Check slot data */
	if (slot_data[slot_id] == NULL || !slot_data[slot_id]->initialized) {
		TRACE_ERROR("ICSF slot data not initialized.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	memcpy(&data, slot_data[slot_id], sizeof(data));

	XProcUnLock();

	if (data.mech == ICSF_CFG_MECH_SIMPLE) {
		CK_BYTE mk[MAX_KEY_SIZE];
		CK_BYTE racf_pass[PIN_SIZE];
		int mk_len = sizeof(mk);
		int racf_pass_len = sizeof(racf_pass);
		CK_BYTE pk_dir_buf[PATH_MAX], fname[PATH_MAX];

		/* Load master key */
		sprintf(fname, "%s/MK_SO", get_pk_dir(pk_dir_buf));
		if (get_masterkey(pin, pin_len, fname, mk, &mk_len)) {
			TRACE_DEVEL("Failed to get masterkey \"%s\".\n", fname);
			return CKR_FUNCTION_FAILED;
		}

		/* Load RACF password */
		if (get_racf(mk, mk_len, racf_pass, &racf_pass_len)) {
			TRACE_DEVEL("Failed to get RACF password.\n");
			return CKR_FUNCTION_FAILED;
		}

		/* Simple bind */
		ret  = icsf_login(&ldapd, data.uri, data.dn, racf_pass);
	} else {
		/* SASL bind */
		ret = icsf_sasl_login(&ldapd, data.uri, data.cert_file,
				      data.key_file, data.ca_file, NULL);
	}

	if (ret) {
		TRACE_DEVEL("Failed to bind to %s\n", data.uri);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (icsf_check_pkcs_extension(ldapd)) {
		TRACE_ERROR("ICSF LDAP externsion not supported.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

done:
	if (rc == CKR_OK && ld)
		*ld = ldapd;

	if (fname)
		free(fname);

	return rc;
}

CK_RV reset_token_data(CK_SLOT_ID slot_id, CK_CHAR_PTR pin, CK_ULONG pin_len)
{
	CK_BYTE mk[MAX_KEY_SIZE];
	CK_BYTE racf_pass[PIN_SIZE];
	int mk_len = sizeof(mk);
	int racf_pass_len = sizeof(racf_pass);
	CK_BYTE pk_dir_buf[PATH_MAX], fname[PATH_MAX];

	/* Remove user's masterkey */
	if (slot_data[slot_id]->mech == ICSF_CFG_MECH_SIMPLE) {
		sprintf(fname, "%s/MK_USER", get_pk_dir(pk_dir_buf));
		if (unlink(fname) && errno == ENOENT)
			TRACE_WARNING("Failed to remove \"%s\".\n", fname);

		/* Load master key */
		sprintf(fname, "%s/MK_SO", get_pk_dir(pk_dir_buf));
		if (get_masterkey(pin, pin_len, fname, mk, &mk_len)) {
			TRACE_DEVEL("Failed to load masterkey \"%s\".\n",
				      fname);
			return CKR_FUNCTION_FAILED;
		}

		/* Load RACF password */
		if (get_racf(mk, mk_len, racf_pass, &racf_pass_len)) {
			TRACE_DEVEL("Failed to get RACF password.\n");
			return CKR_FUNCTION_FAILED;
		}

		/* Generate new key */
		if (get_randombytes(mk, mk_len)) {
			TRACE_DEVEL("Failed to generate new master key.\n");
			return CKR_FUNCTION_FAILED;
		}

		/* Save racf password using the new master key */
		if (secure_racf(racf_pass, racf_pass_len, mk, mk_len)) {
			TRACE_DEVEL("Failed to save racf password.\n");
			return CKR_FUNCTION_FAILED;
		}
	}

	/* Reset token data and keep token name */
	slot_data[slot_id]->initialized = 0;
	init_token_data(slot_id);
	init_slotInfo();
	nv_token_data->token_info.flags |= CKF_TOKEN_INITIALIZED;

	/* Reset SO pin to default and user pin to invalid */
	pin_len = strlen((pin = "87654321"));
	if (compute_sha1(pin, pin_len, nv_token_data->so_pin_sha)) {
		TRACE_ERROR("Failed to reset so pin.\n");
		return CKR_FUNCTION_FAILED;
	}
	memset(nv_token_data->user_pin_sha, '0',
	       sizeof(nv_token_data->user_pin_sha));

	if (slot_data[slot_id]->mech == ICSF_CFG_MECH_SIMPLE) {
		/* Save master key */
		if (secure_masterkey(mk, mk_len, pin, pin_len, fname)) {
			TRACE_DEVEL("Failed to save the new master key.\n");
			return CKR_FUNCTION_FAILED;
		}
	}

	if (save_token_data(slot_id)) {
		TRACE_DEVEL("Failed to save token data.\n");
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV destroy_objects(CK_SLOT_ID slot_id, CK_CHAR_PTR token_name,
		      CK_CHAR_PTR pin, CK_ULONG pin_len)
{
	CK_RV rc = CKR_OK;
	LDAP *ld = NULL;
	struct icsf_object_record records[16];
	struct icsf_object_record *previous = NULL;
	size_t i, records_len;
	int reason = 0;

	if (login(&ld, slot_id, pin, pin_len, RACFFILE))
		return CKR_FUNCTION_FAILED;

	TRACE_DEVEL("Destroying objects in slot %lu.\n", slot_id);
	do {
		records_len = sizeof(records)/sizeof(records[0]);

		rc = icsf_list_objects(ld, NULL, token_name, 0, NULL,
					previous, records, &records_len, 0);
		if (ICSF_RC_IS_ERROR(rc)) {
			TRACE_DEVEL("Failed to list objects for slot %lu.\n",
				      slot_id);
			rc = CKR_FUNCTION_FAILED;
			goto done;
		}

		for (i = 0; i < records_len; i++) {
			if ((rc = icsf_destroy_object(ld, &reason, &records[i]))) {
				TRACE_DEVEL("Failed to destroy object "
					      "%s/%lu/%c in slot %lu.\n",
					      records[i].token_name,
					      records[i].sequence,
					      records[i].id, slot_id);
				rc = icsf_to_ock_err(rc, reason);
				goto done;
			}
		}

		if (records_len)
			previous = &records[records_len - 1];
	} while (records_len);

done:
	if (icsf_logout(ld) && rc == CKR_OK)
		rc = CKR_FUNCTION_FAILED;

	return rc;
}

/*
 * Initialize token.
 */
CK_RV icsftok_init_token(CK_SLOT_ID slot_id, CK_CHAR_PTR pin, CK_ULONG pin_len,
			 CK_CHAR_PTR label)
{
	CK_RV rc = CKR_OK;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];

	/* Check pin */
	rc = compute_sha1(pin, pin_len, hash_sha);
	if (memcmp(nv_token_data->so_pin_sha, hash_sha, SHA1_HASH_SIZE) != 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
		rc = CKR_PIN_INCORRECT;
		goto done;
	}

	if ((rc = reset_token_data(slot_id, pin, pin_len)))
		goto done;

	if ((rc = destroy_objects(slot_id, nv_token_data->token_info.label,
				  pin, pin_len)))
		goto done;

	/* purge the object btree */
	if (purge_object_mapping()) {
		TRACE_DEVEL("Failed to purge objects.\n");
		rc = CKR_FUNCTION_FAILED;
	}

done:
	return rc;
}

CK_RV icsftok_init_pin(SESSION *sess, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rc = CKR_OK;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	CK_SLOT_ID sid;
	CK_BYTE fname[PATH_MAX];
	char pk_dir_buf[PATH_MAX];

	/* get slot id */
	sid = sess->session_info.slotID;

	/* compute the SHA of the user pin */
	rc = compute_sha1(pPin, ulPinLen, hash_sha);
	if (rc != CKR_OK) {
		TRACE_ERROR("Hash Computation Failed.\n");
		return rc;
	}

	/* encrypt the masterkey and store in MK_USER if using SIMPLE AUTH
	 * to authenticate to ldao server. The masterkey protects the
	 * racf passwd.
	 */
	if (slot_data[sid]->mech == ICSF_CFG_MECH_SIMPLE) {
		sprintf(fname, "%s/MK_USER", get_pk_dir(pk_dir_buf));

		rc = secure_masterkey(master_key, AES_KEY_SIZE_256, pPin,
					ulPinLen, fname);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Could not create MK_USER.\n");
			return rc;
		}
	}

	rc = XProcLock();
	if (rc != CKR_OK) {
		TRACE_ERROR("Process Lock Failed.\n");
		return rc;
	}
	memcpy(nv_token_data->user_pin_sha, hash_sha, SHA1_HASH_SIZE);
	nv_token_data->token_info.flags |= CKF_USER_PIN_INITIALIZED;
	nv_token_data->token_info.flags &= ~(CKF_USER_PIN_TO_BE_CHANGED);
	nv_token_data->token_info.flags &= ~(CKF_USER_PIN_LOCKED);
	XProcUnLock();

	return rc;
}

CK_RV icsftok_set_pin(SESSION *sess, CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen,
		      CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen)
{
	CK_RV rc = CKR_OK;
	CK_BYTE new_hash_sha[SHA1_HASH_SIZE];
	CK_BYTE old_hash_sha[SHA1_HASH_SIZE];
	CK_BYTE fname[PATH_MAX];
	CK_SLOT_ID sid;
	char pk_dir_buf[PATH_MAX];

	/* get slot id */
	sid = sess->session_info.slotID;

	rc = compute_sha1(pNewPin, ulNewLen, new_hash_sha );
	rc |= compute_sha1( pOldPin, ulOldLen, old_hash_sha );
	if (rc != CKR_OK) {
		TRACE_ERROR("Hash Computation Failed.\n");
		return rc;
	}

	/* check that the old pin  and new pin are not the same. */
	if (memcmp(old_hash_sha, new_hash_sha, SHA1_HASH_SIZE) == 0) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_INVALID));
		return CKR_PIN_INVALID;
	}

	/* check the length requirements */
	if ((ulNewLen < MIN_PIN_LEN) || (ulNewLen > MAX_PIN_LEN)) {
		TRACE_ERROR("%s\n", ock_err(ERR_PIN_LEN_RANGE));
		return CKR_PIN_LEN_RANGE;
	}

	if ((sess->session_info.state == CKS_RW_USER_FUNCTIONS) ||
	    (sess->session_info.state == CKS_RW_PUBLIC_SESSION)) {
		/* check that old pin matches what is in NVTOK.DAT */
		if (memcmp(nv_token_data->user_pin_sha, old_hash_sha, SHA1_HASH_SIZE) != 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
			return CKR_PIN_INCORRECT;
		}
		/* if using simple auth, encrypt masterkey with new pin */
		if (slot_data[sid]->mech == ICSF_CFG_MECH_SIMPLE) {
			sprintf (fname, "%s/MK_USER", get_pk_dir(pk_dir_buf));
			rc = secure_masterkey(master_key, AES_KEY_SIZE_256,
						pNewPin, ulNewLen, fname);
			if (rc != CKR_OK) {
				TRACE_ERROR("Save Master Key Failed.\n");
				return rc;
			}
		}

		/* grab lock and change shared memory */
		rc = XProcLock();
		if (rc != CKR_OK) {
			TRACE_ERROR("Process Lock Failed.\n");
			return rc;
		}
		memcpy(nv_token_data->user_pin_sha, new_hash_sha, SHA1_HASH_SIZE);
		nv_token_data->token_info.flags &= ~(CKF_USER_PIN_TO_BE_CHANGED);
		XProcUnLock();

	} else if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {

		/* check that old pin matches what is in NVTOK.DAT */
		if (memcmp(nv_token_data->so_pin_sha, old_hash_sha, SHA1_HASH_SIZE) != 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
			return CKR_PIN_INCORRECT;
		}

		/* check that new pin is not the default */
		if (memcmp(new_hash_sha, default_so_pin_sha, SHA1_HASH_SIZE) == 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INVALID));
			return CKR_PIN_INVALID;
		}

		if (slot_data[sid]->mech == ICSF_CFG_MECH_SIMPLE) {
			/*
			 * if using simle auth, encrypt masterkey with new pin
			 */
			sprintf (fname, "%s/MK_SO", get_pk_dir(pk_dir_buf));
			rc = secure_masterkey(master_key, AES_KEY_SIZE_256,
					      pNewPin, ulNewLen, fname);
			if (rc != CKR_OK) {
				TRACE_ERROR("Save Master Key Failed.\n");
				return rc;
			}
		}

		/* grab lock and change shared memory */
		rc = XProcLock();
		if (rc != CKR_OK) {
			TRACE_ERROR("Process Lock Failed.\n");
			return rc;
		}
		memcpy(nv_token_data->so_pin_sha, new_hash_sha, SHA1_HASH_SIZE);
		nv_token_data->token_info.flags &= ~(CKF_SO_PIN_TO_BE_CHANGED);
		XProcUnLock();
	} else {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
		return CKR_SESSION_READ_ONLY;
	}

	rc = save_token_data(sid);
	if (rc != CKR_OK) {
		TRACE_ERROR("Save Token Failed.\n");
		return rc;
	}

	return rc;
}

CK_RV icsftok_open_session(SESSION *sess)
{
	struct session_state *session_state;

	/* Add session to list */
	session_state = malloc(sizeof(struct session_state));
	if (!session_state) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_FUNCTION_FAILED;
	}
	session_state->session_id = sess->handle;
	session_state->ld = NULL;

	/* Lock to add a new session in the list */
	if (pthread_mutex_lock(&sess_list_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		free(session_state);
		return CKR_FUNCTION_FAILED;
	}

	list_insert_head(&sessions, &session_state->sessions);

	/* Unlock */
	if (pthread_mutex_unlock(&sess_list_mutex)) {
		TRACE_ERROR("Mutex Unlock Failed.\n");
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

/*
 * Close a session.
 *
 * Must be called with sess_list_mutex locked.
 */
static CK_RV close_session(struct session_state *session_state)
{
	CK_RV rc = CKR_OK;
	unsigned long i;
	int reason = 0;

	if (pthread_rwlock_wrlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		return CKR_FUNCTION_FAILED;
	}

	/* Remove each session object */
	for (i = 1; i <= objects.size; i++) {
		struct icsf_object_mapping *mapping;

		/* Skip missing ids */
		if(!(mapping = bt_get_node_value(&objects, i)))
			continue;

		/* Skip object from other sessions */
		if (mapping->session_id != session_state->session_id)
			continue;

		/* Skip token objects */
		if (mapping->icsf_object.id != ICSF_SESSION_OBJECT)
			continue;

		if ((rc = icsf_destroy_object(session_state->ld, &reason,
					      &mapping->icsf_object))) {
			/* Log error */
			TRACE_DEBUG("Failed to remove icsf object: %s/%lu/%c",
				      mapping->icsf_object.token_name,
				      mapping->icsf_object.sequence,
				      mapping->icsf_object.id);
			rc = icsf_to_ock_err(rc, reason);
			break;
		}

		/* Remove object from object list */
		bt_node_free(&objects, i, &free);
	}

	if (pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock Failed.\n");
		return CKR_FUNCTION_FAILED;
	}
	if (rc)
		return rc;

	/* Log off from LDAP server */
	if (session_state->ld) {
		if (icsf_logout(session_state->ld)) {
			TRACE_DEVEL("Failed to disconnect from LDAP server.\n");
			return CKR_FUNCTION_FAILED;
		}
		session_state->ld = NULL;
	}

	/* Remove session */
	list_remove(&session_state->sessions);
	if (list_is_empty(&sessions)) {
		if (purge_object_mapping()) {
			TRACE_DEVEL("Failed to purge objects.\n");
			rc = CKR_FUNCTION_FAILED;
		}
	}
	free(session_state);

	return rc;
}

/*
 * Called during C_CloseSession.
 */
CK_RV icsftok_close_session(SESSION *session)
{
	CK_RV rc;
	struct session_state *session_state;

	/* Get the related session_state */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("Session not found for session id %lu.\n",
			    (unsigned long) session);
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* Remove session_state from the list and free it */
	if (pthread_mutex_lock(&sess_list_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		return CKR_FUNCTION_FAILED;
	}

	if ((rc = close_session(session_state)))
		TRACE_ERROR("close_session failed\n");

	if (pthread_mutex_unlock(&sess_list_mutex)) {
		TRACE_ERROR("Mutex Unlock Failed.\n");
		rc = CKR_FUNCTION_FAILED;
	}

	return rc;
}

/*
 * Called during C_Finalize.
 */
CK_RV icsftok_final(void)
{
	CK_RV rc = CKR_OK;
	struct session_state *session_state;
	list_entry_t *e;

	/* Lock to add a new session in the list */
	if (pthread_mutex_lock(&sess_list_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		return CKR_FUNCTION_FAILED;
	}

	for_each_list_entry_safe(&sessions, struct session_state, session_state,
				 sessions, e) {
		if ((rc = close_session(session_state)))
			break;
	}

	/* Unlock */
	if (pthread_mutex_unlock(&sess_list_mutex)) {
		TRACE_ERROR("Mutex Unlock Failed.\n");
		return CKR_FUNCTION_FAILED;
	}

	return rc;
}

CK_RV icsftok_login(SESSION *sess, CK_USER_TYPE userType, CK_CHAR_PTR pPin,
		    CK_ULONG ulPinLen)
{
	CK_RV rc;
	char fname[PATH_MAX];
	CK_BYTE racfpwd[PIN_SIZE];
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	int racflen;
	int mklen;
	char pk_dir_buf[PATH_MAX];
	char *ca_dir = NULL;
	CK_SLOT_ID slot_id = sess->session_info.slotID;
	struct session_state *session_state;
	LDAP *ld;

	/* Check Slot ID */
	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		TRACE_ERROR("Invalid slot ID: %lu\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	/* compute the sha of the pin. */
	rc = compute_sha1(pPin, ulPinLen, hash_sha);
	if (rc != CKR_OK) {
		TRACE_ERROR("Hash Computation Failed.\n");
		return rc;
	}

	XProcLock();

	if (userType == CKU_USER) {
		/* check if pin initialized */
		if (memcmp(nv_token_data->user_pin_sha, "00000000000000000000", SHA1_HASH_SIZE) == 0) {
			TRACE_ERROR("%s\n",
				    ock_err(ERR_USER_PIN_NOT_INITIALIZED));
			rc = CKR_USER_PIN_NOT_INITIALIZED;
			goto done;
		}

		/* check that pin is the same as the one in NVTOK.DAT */
		if (memcmp(nv_token_data->user_pin_sha, hash_sha, SHA1_HASH_SIZE) != 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
			rc = CKR_PIN_INCORRECT;
			goto done;
		}

		/* now load the master key */
		if (slot_data[slot_id]->mech == ICSF_CFG_MECH_SIMPLE) {
			sprintf(fname, "%s/MK_USER", get_pk_dir(pk_dir_buf));
			rc = get_masterkey(pPin, ulPinLen, fname, master_key,
					   &mklen);
			if (rc != CKR_OK) {
				TRACE_DEVEL("Failed to load master key.\n");
				goto done;
			}
		}
	} else {
		/* if SO ... */

		/* check that pin is the same as the one in NVTOK.DAT */
		if (memcmp(nv_token_data->so_pin_sha, hash_sha, SHA1_HASH_SIZE) != 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_PIN_INCORRECT));
			rc = CKR_PIN_INCORRECT;
			goto done;
		}

		if (slot_data[slot_id]->mech == ICSF_CFG_MECH_SIMPLE) {
			/* now load the master key */
			sprintf(fname, "%s/MK_SO", get_pk_dir(pk_dir_buf));
			rc = get_masterkey(pPin, ulPinLen, fname, master_key,
					   &mklen);
			if (rc != CKR_OK) {
				TRACE_DEVEL("Failed to load master key.\n");
				goto done;
			}
		}
	}

	/* The pPin looks good, so now lets authenticate to ldap server */
	if (slot_data[slot_id] == NULL) {
		TRACE_ERROR("ICSF slot data not initialized.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Check if using sasl or simple auth */
	if (slot_data[slot_id]->mech == ICSF_CFG_MECH_SIMPLE) {
		TRACE_INFO("Using SIMPLE auth with slot ID: %lu\n", slot_id);

		/* get racf passwd */
		rc = get_racf(master_key, AES_KEY_SIZE_256, racfpwd, &racflen);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Failed to get racf passwd.\n");
			goto done;
		}

		/* ok got the passwd, perform simple ldap bind call */
		rc = icsf_login(&ld, slot_data[slot_id]->uri,
				slot_data[slot_id]->dn, racfpwd);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Failed to bind to ldap server.\n");
			goto done;
		}

	}
	else {
		TRACE_INFO("Using SASL auth with slot ID: %lu\n", slot_id);

		rc = icsf_sasl_login(&ld, slot_data[slot_id]->uri,
				     slot_data[slot_id]->cert_file,
				     slot_data[slot_id]->key_file,
				     slot_data[slot_id]->ca_file, ca_dir);
		if (rc != CKR_OK) {
			TRACE_DEVEL("Failed to bind to ldap server.\n");
			goto done;
		}
	}

	/* Save LDAP handle */
	if (!(session_state = get_session_state(sess->handle))) {
		TRACE_ERROR("Session not found for session id %lu.\n",
				(unsigned long) sess->handle);
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}
	session_state->ld = ld;

done:
	XProcUnLock();
	return rc;
}

static CK_RV
check_session_permissions(SESSION *sess, CK_ATTRIBUTE *attrs,
			  CK_ULONG attrs_len)
{
	CK_RV rc = CKR_OK;
	/* PKCS#11 default value for CKA_TOKEN is FALSE */
	CK_BBOOL is_token_obj = FALSE;
	/* ICSF default value for CKA_PRIVATE is TRUE */
	CK_BBOOL is_priv_obj = TRUE;

	/* Get attributes values */
	find_bbool_attribute(attrs, attrs_len, CKA_TOKEN, &is_token_obj);
	find_bbool_attribute(attrs, attrs_len, CKA_PRIVATE, &is_priv_obj);

	/*
	 * Check whether session has permissions to create the object, etc
	 *
	 * Object                  R/O      R/W      R/O     R/W    R/W
	 * Type                   Public   Public    User    User   SO
	 * -------------------------------------------------------------
	 * Public session          R/W      R/W      R/W     R/W    R/W
	 * Private session                           R/W     R/W
	 * Public token            R/O      R/W      R/O     R/W    R/W
	 * Private token                             R/O     R/W
	 */

	if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
		if (is_priv_obj) {
			TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
			rc = CKR_USER_NOT_LOGGED_IN;
			goto done;
		}
		if (is_token_obj) {
			TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
			rc = CKR_SESSION_READ_ONLY;
			goto done;
		}
	}

	if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
		if (is_token_obj) {
			TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
			rc = CKR_SESSION_READ_ONLY;
			goto done;
		}
	}

	if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
		if (is_priv_obj) {
			TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
			rc = CKR_USER_NOT_LOGGED_IN;
			goto done;
		}
	}

	if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
		if (is_priv_obj) {
			TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
			rc = CKR_USER_NOT_LOGGED_IN;
			goto done;
		}
	}

done:
	return rc;
}

/*
 * Copy an existing object.
 */
CK_RV icsftok_copy_object(SESSION * session, CK_ATTRIBUTE_PTR attrs,
			  CK_ULONG attrs_len, CK_OBJECT_HANDLE src,
			  CK_OBJECT_HANDLE_PTR dst)
{
	CK_RV rc = CKR_OK;
	struct session_state *session_state;
	struct icsf_object_mapping *mapping_dst = NULL;
	struct icsf_object_mapping *mapping_src = NULL;
	CK_ULONG node_number;
	int is_obj_locked = 0;
	int reason = 0;

	CK_BBOOL is_priv;
	CK_BBOOL is_token;
	CK_RV rc_permission = CKR_OK;

	CK_ATTRIBUTE priv_attrs[] = {
		{CKA_PRIVATE, &is_priv, sizeof(is_priv)},
		{CKA_TOKEN, &is_token, sizeof(is_token)},
	};

	CK_ATTRIBUTE_PTR temp_attrs;

	/* Get session state */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("Session not found for session id %lu.\n",
			    (unsigned long)session->handle);
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	/* Allocate structure for new object */
	if (!(mapping_dst = malloc(sizeof(*mapping_dst)))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_HOST_MEMORY;
		goto done;
	}

	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	mapping_src = bt_get_node_value(&objects, src);
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (!mapping_src) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_OBJECT_HANDLE_INVALID;
		goto done;
	}

	rc = icsf_get_attribute(session_state->ld, &reason, &mapping_src->icsf_object, priv_attrs, 2);
	if (rc != CKR_OK) {
		TRACE_ERROR("icsf_get_attribute failed\n");
		goto done;
	}

	if (attrs_len != 0) {
		/* looking for CKA_PRIVATE */
		temp_attrs = get_attribute_by_type(attrs, attrs_len, CKA_PRIVATE);
		if (temp_attrs != NULL) {
			priv_attrs[0].pValue = temp_attrs->pValue;
			priv_attrs[0].ulValueLen = temp_attrs->ulValueLen;
		}

		/* looking for CKA_TOKEN */
		temp_attrs = get_attribute_by_type(attrs, attrs_len, CKA_TOKEN);
		if (temp_attrs != NULL) {
			priv_attrs[1].pValue = temp_attrs->pValue;
			priv_attrs[1].ulValueLen = attrs->ulValueLen;
		}
	}

	/* Check permissions based on attributes and session */
	rc = check_session_permissions(session, priv_attrs, 2);
	if (rc_permission != CKR_OK) {
		TRACE_DEVEL("check_session_permissions failed\n");
		goto done;
	}

	/* Call ICSF service */
	rc = icsf_copy_object(session_state->ld, &reason, attrs, attrs_len,
			      &mapping_src->icsf_object,
			      &mapping_dst->icsf_object);
	if (rc != 0) {
		TRACE_DEVEL("Failed to Copy object.\n");
		rc = icsf_to_ock_err(rc, reason);
		goto done;
	}

	/* Lock the object list */
	if (pthread_rwlock_wrlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	is_obj_locked = 1;

	/* Add info about object into session */
	if (!(node_number = bt_node_add(&objects, mapping_dst))) {
		TRACE_ERROR("Failed to add object to binary tree.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Use node number as handle */
	*dst = node_number;

done:
	if (is_obj_locked && pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock Failed.\n");
		rc = CKR_FUNCTION_FAILED;
	}

	/* If allocated, object must be freed in case of failure */
	if (rc && mapping_dst)
		free(mapping_dst);

	return rc;
}

/*
 * Create a new object.
 */
CK_RV icsftok_create_object(SESSION *session, CK_ATTRIBUTE_PTR attrs,
			    CK_ULONG attrs_len, CK_OBJECT_HANDLE_PTR handle)
{
	CK_RV rc = CKR_OK;
	struct session_state *session_state;
	struct icsf_object_mapping *mapping;
	CK_ULONG node_number;
	char token_name[sizeof(nv_token_data->token_info.label)];
	int is_obj_locked = 0;
	int reason = 0;

	/* Check permissions based on attributes and session */
	rc = check_session_permissions(session, attrs, attrs_len);
	if (rc != CKR_OK)
		return rc;

	/* Copy token name from shared memory */
	XProcLock();
	memcpy(token_name, nv_token_data->token_info.label, sizeof(token_name));
	XProcUnLock();

	/* Allocate structure to keep ICSF object information */
	if (!(mapping = malloc(sizeof(*mapping)))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}
	memset(mapping, 0, sizeof(struct icsf_object_mapping));
	mapping->session_id = session->handle;

	/* Get session state */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("Session not found for session id %lu.\n",
			    (unsigned long) session->handle);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Call ICSF service */
	if ((rc = icsf_create_object(session_state->ld, &reason, token_name,
				     attrs, attrs_len,
				     &mapping->icsf_object))) {
		TRACE_DEVEL("icsf_create_object failed\n");
		rc = icsf_to_ock_err(rc, reason);
		goto done;
	}

	/* Lock the object list */
	if (pthread_rwlock_wrlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	is_obj_locked = 1;

	/* Add info about object into session */
	if(!(node_number = bt_node_add(&objects, mapping))) {
		TRACE_ERROR("Failed to add object to binary tree.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Use node number as handle */
	*handle = node_number;

done:
	if (is_obj_locked && pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock failed.\n");
		rc = CKR_FUNCTION_FAILED;
	}

	/* If allocated, object must be freed in case of failure */
	if (rc && mapping)
		free(mapping);

	return rc;
}

/*
 * Check if attribute values are valid and add default values for missing ones.
 *
 * It returns a new allocated array that must be freed with
 * free_attribute_array().
 */
static CK_RV
check_key_attributes(CK_ULONG class, CK_ULONG key_type,
		     CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
		     CK_ATTRIBUTE_PTR *p_attrs, CK_ULONG *p_attrs_len)
{

	CK_RV rc;
	CK_ULONG i;
	CK_ULONG check_types[] = { CKA_CLASS, CKA_KEY_TYPE };
	CK_ULONG *check_values[] = { &class, &key_type };

	if ((rc = dup_attribute_array(attrs, attrs_len, p_attrs, p_attrs_len)))
		return rc;

	for (i = 0; i < sizeof(check_types)/sizeof(*check_types); i++) {
		/* Search for the attribute */
		CK_ATTRIBUTE_PTR attr = get_attribute_by_type(*p_attrs,
				*p_attrs_len, check_types[i]);
		if (attr) {
			/* Check the expected value */
			if (*((CK_ULONG *) attr->pValue) != *check_values[i]) {
				TRACE_ERROR("%s\n",
					  ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
				rc = CKR_ATTRIBUTE_VALUE_INVALID;
				goto cleanup;
			}
		} else {
			/* Add default value */
			rc = add_to_attribute_array(p_attrs, p_attrs_len,
					check_types[i],
					(CK_BYTE *) check_values[i],
					sizeof(*check_values[i]));
			if (rc)
				goto cleanup;
		}
	}

	rc = CKR_OK;

cleanup:
	if (rc) {
		free_attribute_array(*p_attrs, *p_attrs_len);
		*p_attrs = NULL;
		*p_attrs_len = 0;
	}

	return rc;
}

/*
 * Get the type of the key that must be generated based on given mechanism.
 *
 * This functions is used by both symmetric and asymmetric key generation
 * functions.
 */
static CK_ULONG
get_generate_key_type(CK_MECHANISM_PTR mech)
{
	switch (mech->mechanism) {
	/* Symmetric keys */
	case CKM_AES_KEY_GEN:
		return CKK_AES;
	case CKM_DES_KEY_GEN:
		return CKK_DES;
	case CKM_DES2_KEY_GEN:
		return CKK_DES2;
	case CKM_DES3_KEY_GEN:
		return CKK_DES3;
	case CKM_SSL3_PRE_MASTER_KEY_GEN:
		return CKK_GENERIC_SECRET;
	/* Asymmetric keys */
	case CKM_RSA_PKCS_KEY_PAIR_GEN:
		return CKK_RSA;
	case CKM_DSA_KEY_PAIR_GEN:
		return CKK_DSA;
	case CKM_DH_PKCS_KEY_PAIR_GEN:
	case CKM_DH_PKCS_DERIVE:
		return CKK_DH;
	case CKM_EC_KEY_PAIR_GEN:
		return CKK_EC;
	case CKM_SSL3_MASTER_KEY_DERIVE:
	case CKM_SSL3_KEY_AND_MAC_DERIVE:
	case CKM_TLS_KEY_AND_MAC_DERIVE:
		return CKK_GENERIC_SECRET;
	}
	return -1;
}

/*
 * Generate a key pair.
 */
CK_RV icsftok_generate_key_pair(SESSION *session, CK_MECHANISM_PTR mech,
				CK_ATTRIBUTE_PTR pub_attrs,
				CK_ULONG pub_attrs_len,
				CK_ATTRIBUTE_PTR priv_attrs,
				CK_ULONG priv_attrs_len,
				CK_OBJECT_HANDLE_PTR p_pub_key,
				CK_OBJECT_HANDLE_PTR p_priv_key)
{
	CK_RV rc;
	char token_name[sizeof(nv_token_data->token_info.label)];
	struct session_state *session_state;
	struct icsf_object_mapping *pub_key_mapping = NULL;
	struct icsf_object_mapping *priv_key_mapping = NULL;
	int reason = 0;
	int is_obj_locked = 0;
	int pub_node_number, priv_node_number;
	CK_ATTRIBUTE_PTR new_pub_attrs = NULL;
	CK_ULONG new_pub_attrs_len = 0;
	CK_ATTRIBUTE_PTR new_priv_attrs = NULL;
	CK_ULONG new_priv_attrs_len = 0;
	CK_ULONG key_type;

	/* Check and set default attributes based on mech */
	if ((key_type = get_generate_key_type(mech)) == -1) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
		goto done;
	}
	rc = check_key_attributes(CKO_PUBLIC_KEY, key_type, pub_attrs,
			pub_attrs_len, &new_pub_attrs, &new_pub_attrs_len);
	if (rc != CKR_OK)
		goto done;

	rc = check_key_attributes(CKO_PRIVATE_KEY, key_type, priv_attrs,
			priv_attrs_len, &new_priv_attrs, &new_priv_attrs_len);
	if (rc != CKR_OK)
		goto done;

	/* Check permissions based on attributes and session */
	rc = check_session_permissions(session, new_pub_attrs,
			new_pub_attrs_len);
	if (rc != CKR_OK)
		goto done;
	rc = check_session_permissions(session, new_priv_attrs,
			new_priv_attrs_len);
	if (rc != CKR_OK)
		goto done;

	/* Get session state */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_DEVEL("Session not found for session id %lu.\n",
				(unsigned long) session->handle);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Copy token name from shared memory */
	XProcLock();
	memcpy(token_name, nv_token_data->token_info.label, sizeof(token_name));
	XProcUnLock();

	/* Allocate structure to keep ICSF objects information */
	if (!(pub_key_mapping = malloc(sizeof(*pub_key_mapping))) ||
	    !(priv_key_mapping = malloc(sizeof(*priv_key_mapping)))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_HOST_MEMORY;
		goto done;
	}

	/* Call ICSF service */
	if ((rc = icsf_generate_key_pair(session_state->ld, &reason, token_name,
					 new_pub_attrs, new_pub_attrs_len,
					 new_priv_attrs, new_priv_attrs_len,
					 &pub_key_mapping->icsf_object,
					 &priv_key_mapping->icsf_object))) {
		TRACE_DEVEL("icsf_generate_key_pair failed\n");
		rc = icsf_to_ock_err(rc, reason);
		goto done;
	}

	/* Lock the object list */
	if (pthread_rwlock_wrlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	is_obj_locked = 1;

	/* Add info about objects into session */
	if(!(pub_node_number = bt_node_add(&objects, pub_key_mapping)) ||
	   !(priv_node_number = bt_node_add(&objects, priv_key_mapping))) {
		TRACE_ERROR("Failed to add object to binary tree.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Use node numbers as handles */
	*p_pub_key = pub_node_number;
	*p_priv_key = priv_node_number;

done:
	if (is_obj_locked && pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to unlock mutex.\n");
		rc = CKR_FUNCTION_FAILED;
	}

	free_attribute_array(new_pub_attrs, new_pub_attrs_len);
	free_attribute_array(new_priv_attrs, new_priv_attrs_len);

	/* Object mappings must be freed in case of failure */
	if (rc && pub_key_mapping)
		free(pub_key_mapping);
	if (rc && priv_key_mapping)
		free(priv_key_mapping);

	return rc;
}

/*
 * Generate a symmetric key.
 */
CK_RV icsftok_generate_key(SESSION *session, CK_MECHANISM_PTR mech,
			   CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			   CK_OBJECT_HANDLE_PTR handle)
{
	CK_RV rc = CKR_OK;
	struct session_state *session_state;
	struct icsf_object_mapping *mapping = NULL;
	CK_ULONG node_number;
	char token_name[sizeof(nv_token_data->token_info.label)];
	int is_obj_locked = 0;
	CK_ATTRIBUTE_PTR new_attrs = NULL;
	CK_ULONG new_attrs_len = 0;
	CK_ULONG class = CKO_SECRET_KEY;
	CK_ULONG key_type = 0;
	int reason = 0;

	/* Check attributes */
	if ((key_type = get_generate_key_type(mech)) == -1) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
		goto done;
	}

	rc = check_key_attributes(class, key_type, attrs, attrs_len, &new_attrs,
				  &new_attrs_len);
	if (rc != CKR_OK)
		goto done;

	/* Check permissions based on attributes and session */
	rc = check_session_permissions(session, new_attrs, new_attrs_len);
	if (rc != CKR_OK)
		goto done;

	/* Copy token name from shared memory */
	XProcLock();
	memcpy(token_name, nv_token_data->token_info.label, sizeof(token_name));
	XProcUnLock();

	/* Allocate structure to keep ICSF object information */
	if (!(mapping = malloc(sizeof(*mapping)))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		goto done;
	}
	memset(mapping, 0, sizeof(struct icsf_object_mapping));
	mapping->session_id = session->handle;

	/* Get session state */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_DEVEL("Session not found for session id %lu.\n",
				(unsigned long) session->handle);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Call ICSF service */
	if ((rc = icsf_generate_secret_key(session_state->ld, &reason, token_name,
					   mech, new_attrs, new_attrs_len,
					   &mapping->icsf_object))) {
		TRACE_DEVEL("icsf_generate_secret_key failed\n");
		rc = icsf_to_ock_err(rc, reason);
		goto done;
	}

	/* Lock the object list */
	if (pthread_rwlock_wrlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	is_obj_locked = 1;

	/* Add info about object into session */
	if(!(node_number = bt_node_add(&objects, mapping))) {
		TRACE_ERROR("Failed to add object to binary tree.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Use node number as handle */
	*handle = node_number;

done:
	if (is_obj_locked && pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock failed.\n");
		rc = CKR_FUNCTION_FAILED;
	}

	if (new_attrs)
		free_attribute_array(new_attrs, new_attrs_len);

	/* If allocated, object must be freed in case of failure */
	if (rc && mapping)
		free(mapping);

	return rc;
}

/*
 * Free all data pointed by an encryption context and set everything to zero.
 */
static void
free_encr_ctx(ENCR_DECR_CONTEXT *encr_ctx)
{
	struct icsf_multi_part_context *multi_part_ctx;

	if (!encr_ctx)
		return;

	/* Initialize encryption context */
	multi_part_ctx = (struct icsf_multi_part_context *) encr_ctx->context;
	if (multi_part_ctx) {
		if (multi_part_ctx->data)
			free(multi_part_ctx->data);
		free(multi_part_ctx);
	}
	if (encr_ctx->mech.pParameter)
		free(encr_ctx->mech.pParameter);
	memset(encr_ctx, 0, sizeof(*encr_ctx));
}

/*
 * Return if the algorithm used by a mechanism is asymmetric or symmetric.
 */
static CK_RV
get_crypt_type(CK_MECHANISM_PTR mech, int *p_symmetric)
{
	switch (mech->mechanism) {
	case CKM_AES_ECB:
	case CKM_AES_CBC:
	case CKM_AES_CBC_PAD:
	case CKM_DES_ECB:
	case CKM_DES_CBC:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_ECB:
	case CKM_DES3_CBC:
	case CKM_DES3_CBC_PAD:
		*p_symmetric = 1;
		break;
	case CKM_RSA_PKCS:
	case CKM_RSA_X_509:
		*p_symmetric = 0;
		break;
	default:
		return CKR_MECHANISM_INVALID;
	}
	return CKR_OK;
}

/*
 * Initialize an encryption operation.
 */
CK_RV icsftok_encrypt_init(SESSION *session, CK_MECHANISM_PTR mech,
			   CK_OBJECT_HANDLE key)
{
	CK_RV rc = CKR_OK;
	ENCR_DECR_CONTEXT *encr_ctx = &session->encr_ctx;
	struct icsf_multi_part_context *multi_part_ctx = NULL;
	size_t block_size = 0;
	int symmetric = 0;

	/* Check session */
	if (!get_session_state(session->handle)) {
		rc = CKR_SESSION_HANDLE_INVALID;
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		goto done;
	}

	/* Get algorithm type */
	if ((rc = get_crypt_type(mech, &symmetric)))
		goto done;

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!bt_get_node_value(&objects, key)) {
		rc = CKR_KEY_HANDLE_INVALID;
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		goto done;

	/* Initialize encryption context */
	free_encr_ctx(encr_ctx);
	encr_ctx->key = key;
	encr_ctx->active = TRUE;

	/* Copy mechanism */
	if (mech->pParameter == NULL || mech->ulParameterLen == 0) {
		encr_ctx->mech.ulParameterLen = 0;
		encr_ctx->mech.pParameter = NULL;
	} else {
		encr_ctx->mech.pParameter = malloc(mech->ulParameterLen);
		if (!encr_ctx->mech.pParameter) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			rc = CKR_HOST_MEMORY;
			goto done;
		}
		encr_ctx->mech.ulParameterLen = mech->ulParameterLen;
		memcpy(encr_ctx->mech.pParameter, mech->pParameter,
				mech->ulParameterLen);
	}
	encr_ctx->mech.mechanism = mech->mechanism;

	/*
	 * Asymmetric algorithms don't support multi-part and then there's no
	 * need to allocate context.
	 */
	if (!symmetric)
		goto done;

	/* Allocate context for multi-part operations */
	if (!(multi_part_ctx = malloc(sizeof(*multi_part_ctx)))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	encr_ctx->context = (void *) multi_part_ctx;

	/* Chained data has always a fixed length */
	memset(multi_part_ctx, 0, sizeof(*multi_part_ctx));

	/* Check mechanism and get block size */
	rc = icsf_block_size(mech->mechanism, &block_size);
	if (rc != CKR_OK)
		goto done;

	/*
	 * data is used to retain data until at least the block size is reached.
	 */
	multi_part_ctx->data_len = block_size;
	multi_part_ctx->data = malloc(multi_part_ctx->data_len);
	if (!multi_part_ctx->data) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_HOST_MEMORY;
		goto done;
	}

done:
	if (rc != CKR_OK)
		free_encr_ctx(encr_ctx);

	return rc;
}

/*
 * Encrypt data and finalize an encryption operation.
 */
CK_RV icsftok_encrypt(SESSION *session, CK_BYTE_PTR input_data,
		       CK_ULONG input_data_len, CK_BYTE_PTR output_data,
		       CK_ULONG_PTR p_output_data_len)
{
	CK_RV rc = CKR_OK;
	CK_BBOOL is_length_only = (output_data == NULL);
	ENCR_DECR_CONTEXT *encr_ctx = &session->encr_ctx;
	struct session_state *session_state;
	struct icsf_object_mapping *mapping;
	char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	int reason = 0;
	int symmetric = 0;

	/* Get algorithm type */
	if ((rc = get_crypt_type(&encr_ctx->mech, &symmetric)))
		goto done;

	/* Check if there's a multi-part encryption in progress */
	if (encr_ctx->multi) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, encr_ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		goto done;

	/* Encrypt data using remote token. */
	if (symmetric) {
		rc = icsf_secret_key_encrypt(session_state->ld, &reason,
					     &mapping->icsf_object,
					     &encr_ctx->mech,
					     ICSF_CHAINING_ONLY, input_data,
					     input_data_len, output_data,
					     p_output_data_len, chain_data,
					     &chain_data_len);
	} else {
		rc = icsf_public_key_verify(session_state->ld, &reason, TRUE,
					    &mapping->icsf_object,
					    &encr_ctx->mech, input_data,
					    input_data_len, output_data,
					    p_output_data_len);
	}
	if (rc) {
		if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
			if (is_length_only) {
				/*
				 * Parameter too short is not a problem when
				 * querying the expect output size.
				 */
				rc = CKR_OK;
			} else {
				TRACE_ERROR("%s\n",
					    ock_err(ERR_BUFFER_TOO_SMALL));
				rc = CKR_BUFFER_TOO_SMALL;
			}
		} else {
			TRACE_ERROR("Failed to encrypt data. reason = %d\n",
				     reason);
			rc = icsf_to_ock_err(rc, reason);
		}
		goto done;
	}

done:
	if (rc != CKR_BUFFER_TOO_SMALL && !(rc == CKR_OK && is_length_only))
		free_encr_ctx(encr_ctx);

	return rc;
}

/*
 * Multi-part encryption.
 */
CK_RV icsftok_encrypt_update(SESSION *session, CK_BYTE_PTR input_part,
			      CK_ULONG input_part_len, CK_BYTE_PTR output_part,
			      CK_ULONG_PTR p_output_part_len)
{
	CK_RV rc = CKR_OK;
	CK_BBOOL is_length_only = (output_part == NULL);
	ENCR_DECR_CONTEXT *encr_ctx = &session->encr_ctx;
	struct icsf_multi_part_context *multi_part_ctx;
	struct session_state *session_state;
	struct icsf_object_mapping *mapping;
	char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	CK_ULONG total, remaining;
	char *buffer = NULL;
	int chaining;
	int reason = 0;
	int symmetric = 0;

	/* Multi-part is not supported for asymmetric algorithms. */
	if ((rc = get_crypt_type(&encr_ctx->mech, &symmetric)))
		goto done;
	if (!symmetric) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
		goto done;
	}

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, encr_ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		goto done;

	multi_part_ctx = (struct icsf_multi_part_context *) encr_ctx->context;

	/* Define the type of the call */
	switch (encr_ctx->mech.mechanism) {
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_AES_ECB:
		/* ICSF just support the chaining mode ONLY for ECB. */
		chaining = ICSF_CHAINING_ONLY;
		break;
	default:
		if (multi_part_ctx->initiated) {
			chaining = ICSF_CHAINING_CONTINUE;
			memcpy(chain_data, multi_part_ctx->chain_data,
					chain_data_len);
		} else {
			chaining = ICSF_CHAINING_INITIAL;
		}
	}

	/*
	 * Data needs to be sent to ICSF in chucks with size that is multiple of
	 * block size. Any remaining data is kept in the multi-part context and
	 * can be sent in a further call of the update function or when the
	 * finalize function is called.
	 */
	total = multi_part_ctx->used_data_len + input_part_len;
	remaining = total % multi_part_ctx->data_len;

	/*
	 * If there's no enough data to make a call, skip it.
	 */
	if (total < multi_part_ctx->data_len) {
		*p_output_part_len = 0;
		goto keep_remaining_data;
	}

	/*
	 * The data to be encrypted should have length that is multiple of the
	 * block size. It is composed by data kept in the multi-part context
	 * concatenated with part of the data given.
	 */
	if (!(buffer = malloc(total - remaining))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	memcpy(buffer, multi_part_ctx->data, multi_part_ctx->used_data_len);
	memcpy(buffer + multi_part_ctx->used_data_len, input_part,
			input_part_len - remaining);

	/* Encrypt data using remote token. */
	rc = icsf_secret_key_encrypt(session_state->ld, &reason,
				     &mapping->icsf_object,
				     &encr_ctx->mech, chaining,
				     buffer, total - remaining,
				     output_part, p_output_part_len,
				     chain_data, &chain_data_len);
	if (rc) {
		if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
			if (is_length_only) {
				/*
				 * Parameter too short is not a problem when
				 * querying the expect output size.
				 */
				rc = CKR_OK;
			} else {
				TRACE_ERROR("%s\n",
					    ock_err(ERR_BUFFER_TOO_SMALL));
				rc = CKR_BUFFER_TOO_SMALL;
			}
		} else {
			TRACE_DEVEL("Failed to encrypt data. reason = %d\n",
				    reason);
			rc = icsf_to_ock_err(rc, reason);
		}
		goto done;
	}

	/*
	 * When blocks are sent it's necessary to keep the chain data returned
	 * to be used in a subsequent call.
	 */
	if (!is_length_only) {
		/* Copy chain data into context */
		memcpy(multi_part_ctx->chain_data, chain_data, chain_data_len);

		/* Mark multi-part operation as initiated */
		multi_part_ctx->initiated = TRUE;

		/* Data stored in cache was used */
		multi_part_ctx->used_data_len = 0;
	}

keep_remaining_data:
	/* Keep the remaining data to a next call */
	if (!is_length_only) {
		/* Copy remaining part of input_part into context */
		if (total < multi_part_ctx->data_len) {
			memcpy(multi_part_ctx->data +
				multi_part_ctx->used_data_len,
				input_part, input_part_len);
		} else {
			memcpy(multi_part_ctx->data,
				input_part + input_part_len - remaining,
				remaining);
		}
		multi_part_ctx->used_data_len = remaining;
	}

done:
	/* Free resources */
	if (buffer)
		free(buffer);

	if (rc != CKR_OK && rc != CKR_BUFFER_TOO_SMALL)
		free_encr_ctx(encr_ctx);

	return rc;
}

/*
 * Finalize a multi-part encryption.
 */
CK_RV icsftok_encrypt_final(SESSION *session, CK_BYTE_PTR output_part,
			     CK_ULONG_PTR p_output_part_len)
{
	CK_RV rc = CKR_OK;
	CK_BBOOL is_length_only = (output_part == NULL);
	ENCR_DECR_CONTEXT *encr_ctx = &session->encr_ctx;
	struct icsf_multi_part_context *multi_part_ctx;
	struct session_state *session_state;
	struct icsf_object_mapping *mapping;
	char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	int chaining;
	int reason = 0;
	int symmetric = 0;

	/* Multi-part is not supported for asymmetric algorithms. */
	if ((rc = get_crypt_type(&encr_ctx->mech, &symmetric)))
		goto done;
	if (!symmetric) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
		goto done;
	}

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, encr_ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		goto done;

	/* Define the type of the call */
	multi_part_ctx = (struct icsf_multi_part_context *) encr_ctx->context;
	switch (encr_ctx->mech.mechanism) {
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
	case CKM_AES_ECB:
		/*
		 * When not using a chained algorithm and there's no remaining
		 * data, don't call ICSF.
		 */
		*p_output_part_len = 0;
		if (!multi_part_ctx->used_data_len)
			goto done;

		/* ICSF just support the chaining mode ONLY for ECB. */
		chaining = ICSF_CHAINING_ONLY;
		break;
	default:
		if (multi_part_ctx->initiated) {
			chaining = ICSF_CHAINING_FINAL;
			memcpy(chain_data, multi_part_ctx->chain_data,
					chain_data_len);
		} else {
			chaining = ICSF_CHAINING_ONLY;
		}
	}

	/*
	 * Encrypt data using remote token.
	 *
	 * All the data in multi-part context should be sent.
	 */
	rc = icsf_secret_key_encrypt(session_state->ld, &reason,
				     &mapping->icsf_object,
				     &encr_ctx->mech, chaining,
				     multi_part_ctx->data,
				     multi_part_ctx->used_data_len,
				     output_part, p_output_part_len,
				     chain_data, &chain_data_len);
	if (rc) {
		if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
			if (is_length_only) {
				/*
				 * Parameter too short is not a problem when
				 * querying the expect output size.
				 */
				rc = CKR_OK;
			} else {
				TRACE_ERROR("%s\n",
					    ock_err(ERR_BUFFER_TOO_SMALL));
				rc = CKR_BUFFER_TOO_SMALL;
			}
		} else {
			TRACE_DEVEL("Failed to encrypt data. reason = %d\n",
				    reason);
			rc = icsf_to_ock_err(rc, reason);
		}
		goto done;
	}

done:
	if ((is_length_only && rc != CKR_OK) ||
	   (!is_length_only && rc != CKR_BUFFER_TOO_SMALL))
		free_encr_ctx(encr_ctx);

	return rc;
}

/*
 * Initialize a decryption operation.
 */
CK_RV icsftok_decrypt_init(SESSION *session, CK_MECHANISM_PTR mech,
			    CK_OBJECT_HANDLE key)
{
	CK_RV rc = CKR_OK;
	ENCR_DECR_CONTEXT *decr_ctx = &session->decr_ctx;
	struct icsf_multi_part_context *multi_part_ctx = NULL;
	size_t block_size = 0;
	int symmetric = 0;

	/* Check session */
	if (!get_session_state(session->handle)) {
		rc = CKR_SESSION_HANDLE_INVALID;
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		goto done;
	}

	/* Get algorithm type */
	if ((rc = get_crypt_type(mech, &symmetric)))
		goto done;

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!bt_get_node_value(&objects, key)) {
		rc = CKR_KEY_HANDLE_INVALID;
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		goto done;

	/* Initialize decryption context */
	free_encr_ctx(decr_ctx);
	decr_ctx->key = key;
	decr_ctx->active = TRUE;

	/* Copy mechanism */
	if (mech->pParameter == NULL || mech->ulParameterLen == 0) {
		decr_ctx->mech.ulParameterLen = 0;
		decr_ctx->mech.pParameter = NULL;
	} else {
		decr_ctx->mech.pParameter = malloc(mech->ulParameterLen);
		if (!decr_ctx->mech.pParameter) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			rc = CKR_HOST_MEMORY;
			goto done;
		}
		decr_ctx->mech.ulParameterLen = mech->ulParameterLen;
		memcpy(decr_ctx->mech.pParameter, mech->pParameter,
				mech->ulParameterLen);
	}
	decr_ctx->mech.mechanism = mech->mechanism;

	/*
	 * Asymmetric algorithms don't support multi-part and then there's no
	 * need to allocate context.
	 */
	if (!symmetric)
		goto done;

	/* Allocate context for multi-part operations */
	if (!(multi_part_ctx = malloc(sizeof(*multi_part_ctx)))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	decr_ctx->context = (void *) multi_part_ctx;

	/* Chained data has always a fixed length */
	memset(multi_part_ctx, 0, sizeof(*multi_part_ctx));

	/* Check mechanism and get block size */
	rc = icsf_block_size(mech->mechanism, &block_size);
	if (rc != CKR_OK)
		goto done;

	/*
	 * data is used to retain data until at least the block size is reached.
	 */
	multi_part_ctx->data_len = block_size;
	multi_part_ctx->data = malloc(multi_part_ctx->data_len);
	if (!multi_part_ctx->data) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_HOST_MEMORY;
		goto done;
	}

done:
	if (rc != CKR_OK)
		free_encr_ctx(decr_ctx);

	return rc;
}

/*
 * Decrypt data and finalize a decryption operation.
 */
CK_RV icsftok_decrypt(SESSION *session, CK_BYTE_PTR input_data,
		       CK_ULONG input_data_len, CK_BYTE_PTR output_data,
		       CK_ULONG_PTR p_output_data_len)
{
	CK_RV rc = CKR_OK;
	CK_BBOOL is_length_only = (output_data == NULL);
	ENCR_DECR_CONTEXT *decr_ctx = &session->decr_ctx;
	struct session_state *session_state;
	struct icsf_object_mapping *mapping;
	char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	int reason = 0;
	int symmetric = 0;

	/* Get algorithm type */
	if ((rc = get_crypt_type(&decr_ctx->mech, &symmetric)))
		goto done;

	/* Check if there's a multi-part decryption in progress */
	if (decr_ctx->multi) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
		rc = CKR_OPERATION_ACTIVE;
		goto done;
	}

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, decr_ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		goto done;

	/* Decrypt data using remote token. */
	if (symmetric) {
		rc = icsf_secret_key_decrypt(session_state->ld, &reason,
					    &mapping->icsf_object,
					    &decr_ctx->mech,
					    ICSF_CHAINING_ONLY, input_data,
					    input_data_len, output_data,
					    p_output_data_len, chain_data,
					    &chain_data_len);
	} else {
		rc = icsf_private_key_sign(session_state->ld, &reason, TRUE,
					   &mapping->icsf_object,
					   &decr_ctx->mech, input_data,
					   input_data_len, output_data,
					   p_output_data_len);
	}
	if (rc) {
		if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
			if (is_length_only) {
				/*
				 * Parameter too short is not a problem when
				 * querying the expect output size.
				 */
				rc = CKR_OK;
			} else {
				TRACE_ERROR("%s\n",
					    ock_err(ERR_BUFFER_TOO_SMALL));
				rc = CKR_BUFFER_TOO_SMALL;
			}
		} else {
			TRACE_DEVEL("Failed to decrypt data. reason = %d\n",
				    reason);
			rc = icsf_to_ock_err(rc, reason);
		}
		goto done;
	}

done:
	if (rc != CKR_BUFFER_TOO_SMALL && !(rc == CKR_OK && is_length_only))
		free_encr_ctx(decr_ctx);

	return rc;
}

/*
 * Multi-part decryption.
 */
CK_RV icsftok_decrypt_update(SESSION *session, CK_BYTE_PTR input_part,
			      CK_ULONG input_part_len, CK_BYTE_PTR output_part,
			      CK_ULONG_PTR p_output_part_len)
{
	CK_RV rc = CKR_OK;
	CK_BBOOL is_length_only = (output_part == NULL);
	ENCR_DECR_CONTEXT *decr_ctx = &session->decr_ctx;
	struct icsf_multi_part_context *multi_part_ctx;
	struct session_state *session_state;
	struct icsf_object_mapping *mapping;
	char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	CK_ULONG total, remaining;
	char *buffer = NULL;
	int chaining;
	int reason = 0;
	int padding = 0;
	int symmetric = 0;

	/* Multi-part is not supported for asymmetric algorithms. */
	if ((rc = get_crypt_type(&decr_ctx->mech, &symmetric)))
		goto done;
	if (!symmetric) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
		goto done;
	}

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, decr_ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		goto done;

	multi_part_ctx = (struct icsf_multi_part_context *) decr_ctx->context;

	/* Define the type of the call */
	switch (decr_ctx->mech.mechanism) {
	case CKM_AES_ECB:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
		/* ICSF just support the chaining mode ONLY for ECB. */
		chaining = ICSF_CHAINING_ONLY;
		break;
	case CKM_AES_CBC_PAD:
	case CKM_DES_CBC_PAD:
	case CKM_DES3_CBC_PAD:
		padding = 1;
	default:
		if (multi_part_ctx->initiated) {
			chaining = ICSF_CHAINING_CONTINUE;
			memcpy(chain_data, multi_part_ctx->chain_data,
					chain_data_len);
		} else {
			chaining = ICSF_CHAINING_INITIAL;
		}
	}

	/*
	 * Data needs to be sent to ICSF in chucks with size that is multiple of
	 * block size. Any remaining data is kept in the multi-part context and
	 * can be sent in a further call of the update function or when the
	 * finalize function is called.
	 *
	 * When padding is used, there's no way to know if the current block of
	 * data is the one that contains the padding, So a block is kept in
	 * multi-part context when the data available is exactly multiple of the
	 * block size.
	 */
	total = multi_part_ctx->used_data_len + input_part_len;
	if (!padding) {
		remaining = total % multi_part_ctx->data_len;
	} else {
		remaining = MIN(((total - 1) % multi_part_ctx->data_len) + 1,
				total);
	}

	/*
	 * If there's no enough data to make a call, skip it.
	 */
	if (total < multi_part_ctx->data_len ||
	    (padding && total == multi_part_ctx->data_len)) {
		*p_output_part_len = 0;
		goto keep_remaining_data;
	}


	/*
	 * The data to be decrypted should have length that is multiple of the
	 * block size. It is composed by data kept in the multi-part context
	 * concatenated with part of the data given.
	 */
	if (!(buffer = malloc(total - remaining))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		rc = CKR_HOST_MEMORY;
		goto done;
	}
	memcpy(buffer, multi_part_ctx->data, multi_part_ctx->used_data_len);
	memcpy(buffer + multi_part_ctx->used_data_len, input_part,
			input_part_len - remaining);

	/* Decrypt data using remote token. */
	rc = icsf_secret_key_decrypt(session_state->ld, &reason,
				     &mapping->icsf_object,
				     &decr_ctx->mech, chaining,
				     buffer, total - remaining,
				     output_part, p_output_part_len,
				     chain_data, &chain_data_len);
	if (rc) {
		if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
			if (is_length_only) {
				/*
				 * Parameter too short is not a problem when
				 * querying the expect output size.
				 */
				rc = CKR_OK;
			} else {
				TRACE_ERROR("%s\n",
					    ock_err(ERR_BUFFER_TOO_SMALL));
				rc = CKR_BUFFER_TOO_SMALL;
			}
		} else {
			TRACE_DEVEL("Failed to decrypt data. reason = %d\n",
				    reason);
			rc = icsf_to_ock_err(rc, reason);
		}
		goto done;
	}

	/*
	 * When blocks are sent it's necessary to keep the chain data returned
	 * to be used in a subsequent call.
	 */
	if (!is_length_only) {
		/* Copy chain data into context */
		memcpy(multi_part_ctx->chain_data, chain_data, chain_data_len);

		/* Mark multi-part operation as initiated */
		multi_part_ctx->initiated = TRUE;

		/* Data stored in cache was used */
		multi_part_ctx->used_data_len = 0;
	}

keep_remaining_data:
	/* Keep the remaining data to a next call */
	if (!is_length_only) {
		/* Copy remaining part of input_part into context */
		if (total < multi_part_ctx->data_len ||
		    (padding && total == multi_part_ctx->data_len)) {
			memcpy(multi_part_ctx->data +
				multi_part_ctx->used_data_len,
				input_part, input_part_len);
		} else {
			memcpy(multi_part_ctx->data,
				input_part + input_part_len - remaining,
				remaining);
		}
		multi_part_ctx->used_data_len = remaining;
	}

done:
	/* Free resources */
	if (buffer)
		free(buffer);

	if (rc != CKR_OK && rc != CKR_BUFFER_TOO_SMALL)
		free_encr_ctx(decr_ctx);

	return rc;
}

/*
 * Finalize a multi-part decryption.
 */
CK_RV icsftok_decrypt_final(SESSION *session, CK_BYTE_PTR output_part,
			     CK_ULONG_PTR p_output_part_len)
{
	CK_RV rc = CKR_OK;
	CK_BBOOL is_length_only = (output_part == NULL);
	ENCR_DECR_CONTEXT *decr_ctx = &session->decr_ctx;
	struct icsf_multi_part_context *multi_part_ctx;
	struct session_state *session_state;
	struct icsf_object_mapping *mapping;
	char chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	int chaining;
	int reason = 0;
	int symmetric = 0;

	/* Multi-part is not supported for asymmetric algorithms. */
	if ((rc = get_crypt_type(&decr_ctx->mech, &symmetric)))
		goto done;
	if (!symmetric) {
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
		goto done;
	}

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, decr_ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		goto done;

	/* Define the type of the call */
	multi_part_ctx = (struct icsf_multi_part_context *) decr_ctx->context;
	switch (decr_ctx->mech.mechanism) {
	case CKM_AES_ECB:
	case CKM_DES_ECB:
	case CKM_DES3_ECB:
		/*
		 * When not using a chained algorithm and there's no remaining
		 * data, don't call ICSF.
		 */
		*p_output_part_len = 0;
		if (!multi_part_ctx->used_data_len)
			goto done;

		/* ICSF just support the chaining mode ONLY for ECB. */
		chaining = ICSF_CHAINING_ONLY;
		break;
	default:
		if (multi_part_ctx->initiated) {
			chaining = ICSF_CHAINING_FINAL;
			memcpy(chain_data, multi_part_ctx->chain_data,
					chain_data_len);
		} else {
			chaining = ICSF_CHAINING_ONLY;
		}
	}

	/*
	 * Decrypt data using remote token.
	 *
	 * All the data in multi-part context should be sent.
	 */
	rc = icsf_secret_key_decrypt(session_state->ld, &reason,
				     &mapping->icsf_object,
				     &decr_ctx->mech, chaining,
				     multi_part_ctx->data,
				     multi_part_ctx->used_data_len,
				     output_part, p_output_part_len,
				     chain_data, &chain_data_len);
	if (rc) {
		if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT) {
			if (is_length_only) {
				/*
				 * Parameter too short is not a problem when
				 * querying the expect output size.
				 */
				rc = CKR_OK;
			} else {
				TRACE_ERROR("%s\n",
					    ock_err(ERR_BUFFER_TOO_SMALL));
				rc = CKR_BUFFER_TOO_SMALL;
			}
		} else {
			TRACE_DEVEL("Failed to decrypt data. reason = %d\n",
				    reason);
			rc = icsf_to_ock_err(rc, reason);
		}
		goto done;
	}

done:
	if ((is_length_only && rc != CKR_OK) ||
	   (!is_length_only && rc != CKR_BUFFER_TOO_SMALL))
		free_encr_ctx(decr_ctx);

	return rc;
}

/*
 * Get the attribute values for a list of attributes.
 */
CK_RV icsftok_get_attribute_value(SESSION *sess, CK_OBJECT_HANDLE handle,
				   CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount)
{
	CK_RV rc = CKR_OK;
	CK_BBOOL priv_obj;
	struct session_state *session_state;
	struct icsf_object_mapping *mapping = NULL;
	int reason = 0;

	CK_ATTRIBUTE priv_attr[] = {
		{CKA_PRIVATE, &priv_obj, sizeof(priv_obj)},
	};

	/* Get session state */
	if (!(session_state = get_session_state(sess->handle))) {
		TRACE_ERROR("Session not found for session id %lu.\n",
			    (unsigned long) handle);
		return CKR_FUNCTION_FAILED;
	}

	/* get the object handle */
	/* get a read lock */
	if (pthread_rwlock_rdlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		return CKR_FUNCTION_FAILED;
	}

	mapping = bt_get_node_value(&objects, handle);

	if (!mapping) {
		TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
		rc = CKR_OBJECT_HANDLE_INVALID;
		goto done;
	}

	/* get the private attribute so we can check the permissions */
	rc = icsf_get_attribute(session_state->ld, &reason,
				&mapping->icsf_object, priv_attr, 1);
	if (rc != CKR_OK) {
		TRACE_DEVEL("icsf_get_attribute failed\n");
		rc = icsf_to_ock_err(rc, reason);
		goto done;
	}

	if (priv_obj == TRUE) {
		if (sess->session_info.state == CKS_RO_PUBLIC_SESSION ||
		    sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
			TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
			rc = CKR_USER_NOT_LOGGED_IN;
			goto done;
		}
	}

	/* Now call icsf to get the attribute values */
	rc = icsf_get_attribute(session_state->ld, &reason,
				&mapping->icsf_object, pTemplate, ulCount);
	if (rc != CKR_OK) {
		TRACE_DEVEL("icsf_get_attribute failed\n");
		rc = icsf_to_ock_err(rc, reason);
	}

done:
	if (pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock failed.\n");
		rc = CKR_FUNCTION_FAILED;
	}

	return rc;
}

/*
 * Set attribute values for a list of attributes.
 */
CK_RV icsftok_set_attribute_value(SESSION *sess, CK_OBJECT_HANDLE handle,
				  CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount)
{
	struct session_state *session_state;
	struct icsf_object_mapping *mapping = NULL;
	CK_BBOOL is_priv;
	CK_BBOOL is_token;
	CK_RV rc = CKR_OK;
	int reason = 0;

	CK_ATTRIBUTE priv_attrs[] = {
		{CKA_PRIVATE,   &is_priv,  sizeof(is_priv)},
		{CKA_TOKEN,	&is_token,  sizeof(is_token)},
	};

	/* Get session state */
	if (!(session_state = get_session_state(sess->handle))) {
		TRACE_ERROR("Session not found for session id %lu.\n",
			    (unsigned long) handle);
		return CKR_FUNCTION_FAILED;
	}

	/* get the object handle */
	/* get a read lock */
	if (pthread_rwlock_rdlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		return CKR_FUNCTION_FAILED;
	}
	mapping = bt_get_node_value(&objects, handle);

	if (!mapping) {
		TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
		rc = CKR_OBJECT_HANDLE_INVALID;
		goto done;
	}

	/* check permissions :
	 * first get CKA_PRIVATE since we need to check againse session
	 * icsf will check if the attributes are modifiable
	 */
	rc = icsf_get_attribute(session_state->ld, &reason,
				&mapping->icsf_object, priv_attrs, 2);
	if (rc != CKR_OK) {
		TRACE_DEVEL("icsf_get_attribute failed\n");
		rc = icsf_to_ock_err(rc, reason);
		goto done;
	}

	/* Check permissions based on attributes and session */
	rc = check_session_permissions(sess, priv_attrs, 2);
	if (rc != CKR_OK) {
		TRACE_DEVEL("check_session_permissions failed\n");
		goto done;
	}

	/* Now call into icsf to set the attribute values */
	rc = icsf_set_attribute(session_state->ld, &reason,
				&mapping->icsf_object, pTemplate, ulCount);
	if (rc != CKR_OK) {
		TRACE_ERROR("icsf_set_attribute failed\n");
		rc = icsf_to_ock_err(rc, reason);
		goto done;
	}

done:
	/* Unlock */
	if (pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock failed.\n");
		rc = CKR_FUNCTION_FAILED;
	}

	return rc;
}

/*
 * Initialize a search for token and session objects that match a template.
 */
CK_RV icsftok_find_objects_init(SESSION *sess, CK_ATTRIBUTE *pTemplate,
				CK_ULONG ulCount)
{
	char token_name[sizeof(nv_token_data->token_info.label)];
	struct session_state *session_state;
	struct icsf_object_record records[MAX_RECORDS];
	struct icsf_object_record *previous = NULL;
	size_t records_len;
	int i, j, node_number;
	int reason = 0;
	CK_RV rc = CKR_OK;

	/* Whether we retrieve public or private objects is determined by
	 * the caller's SAF authority on the token, something ock doesn't
	 * control.
	 * Since an app MUST have authenticated to ICSF token to use it,
	 * we can always assume it is an authenticated session and anything else
	 * is an error.
	 */
	if (sess->session_info.state == CKS_RO_PUBLIC_SESSION ||
	    sess->session_info.state == CKS_RW_PUBLIC_SESSION ||
	    sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
		TRACE_ERROR("You must authenticate to access ICSF token.\n");
		return CKR_FUNCTION_FAILED;
	}

	/* Initialize the found object list. In keeping with other tokens,
	 * if the list does not exist, allocate list big enough for MAX_RECORD
	 * handles. reallocate later if more needed.
	 */
	if (sess->find_list == NULL) {
		sess->find_list = (CK_OBJECT_HANDLE *) malloc(
					10 * sizeof(CK_OBJECT_HANDLE));
		if (!sess->find_list) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			return CKR_HOST_MEMORY;
		}
		sess->find_len = 10;
	}
	memset(sess->find_list, 0x0, sess->find_len*sizeof(CK_OBJECT_HANDLE));
	sess->find_count = 0;
	sess->find_idx   = 0;

	/* Prepare to query ICSF for list objects
	 * Copy token name from shared memory
	 */
	XProcLock();
	memcpy(token_name, nv_token_data->token_info.label, sizeof(token_name));
	XProcUnLock();

	/* Get session state */
	if (!(session_state = get_session_state(sess->handle))) {
		TRACE_ERROR("Session not found for session id %lu.\n",
			    (unsigned long) sess->handle);
		return CKR_FUNCTION_FAILED;
	}

	/* clear out records */
	memset(records, 0, MAX_RECORDS*(sizeof(struct icsf_object_record)));

	if (pthread_rwlock_wrlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		return CKR_FUNCTION_FAILED;
	}

	do {
		records_len = sizeof(records)/sizeof(struct icsf_object_record);
		rc = icsf_list_objects(session_state->ld, &reason, token_name,
				       ulCount, pTemplate, previous, records,
				       &records_len, 0);
		if (ICSF_RC_IS_ERROR(rc)) {
			TRACE_DEVEL("Failed to list objects.\n");
			rc = icsf_to_ock_err(rc, reason);
			goto done;
		}

		/* Now step thru the object btree so we can find the node
		 * value for any matching objects we retrieved from ICSF.
		 * If we cannot find a matching object in the btree,
		 * then add it so we can get a node value.
		 * And also because ICSF object database is authoritative.
		 */

		for (i = 0; i < records_len; i++) {

			/* mark not found */
			node_number = 0;

			for (j=1; j <= objects.size; j++) {
				struct icsf_object_mapping *mapping = NULL;

				/* skip missing ids */
				mapping = bt_get_node_value(&objects, j);
				if (mapping) {
					if (memcmp(&records[i],
					    &mapping->icsf_object,
					    sizeof(struct icsf_object_record)) == 0) {
						node_number = j;
						break;
					}
				} else
					continue;
			}
			/* if could not find in our object tree, then add it
			 * since ICSF object database is authoritative.
			 */
			if (!node_number) {
				struct icsf_object_mapping *new_mapping;

				if (!(new_mapping = malloc(sizeof(*new_mapping)))) {
					TRACE_ERROR("%s\n",
						    ock_err(ERR_HOST_MEMORY));
					rc = CKR_HOST_MEMORY;
					goto done;
				}
				new_mapping->session_id = sess->handle;
				new_mapping->icsf_object = records[i];

				if(!(node_number = bt_node_add(&objects,
								new_mapping))) {
					TRACE_ERROR("Failed to add object to "
						    "binary tree.\n");
					rc = CKR_FUNCTION_FAILED;
					goto done;
				}
			}

			/* Add to our findobject list */
			if (node_number) {
				sess->find_list[sess->find_count] = node_number;
				sess->find_count++;

				if (sess->find_count >= sess->find_len) {
					void *find_list;
					size_t find_len = sess->find_len + MAX_RECORDS;
					find_list = realloc(sess->find_list,
							find_len *
							sizeof(CK_OBJECT_HANDLE));
					if (!find_list) {
						TRACE_ERROR("%s\n",
						      ock_err(ERR_HOST_MEMORY));
						rc = CKR_HOST_MEMORY;
						goto done;
					}
					sess->find_list = find_list;
					sess->find_len = find_len;
				}
			}
		}

		if (records_len)
			previous = &records[records_len - 1];
	} while (records_len);

	sess->find_active = TRUE;

done:
	if (pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock failed.\n");
		return CKR_FUNCTION_FAILED;
	}

	return rc;
}

/*
 * Destroy an object.
 */
CK_RV icsftok_destroy_object(SESSION *sess, CK_OBJECT_HANDLE handle)
{
	struct session_state *session_state;
	struct icsf_object_mapping *mapping = NULL;
	int reason;
	CK_RV rc = CKR_OK;

        /* Get session state */
        if (!(session_state = get_session_state(sess->handle))) {
                TRACE_ERROR("Session not found for session id %lu.\n",
                            (unsigned long) handle);
                return CKR_FUNCTION_FAILED;
        }

	/* Lock the object list */
	if (pthread_rwlock_wrlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		return CKR_FUNCTION_FAILED;
	}

	/* get the object handle */
	mapping = bt_get_node_value(&objects, handle);

	if (!mapping) {
		TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
		rc = CKR_OBJECT_HANDLE_INVALID;
		goto done;
	}

	/* Now remove the object from ICSF */
	rc = icsf_destroy_object(session_state->ld, &reason,
				 &mapping->icsf_object);
	if (rc != 0) {
		TRACE_DEVEL("icsf_destroy_object failed\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Now remove the object from the object btree */
	bt_node_free(&objects, handle, free);

done:
        if (pthread_rwlock_unlock(&obj_list_rw_mutex)) {
                TRACE_ERROR("Mutex Unlock failed.\n");
                return CKR_FUNCTION_FAILED;
        }

	return rc;
}

/*
 * Free all data pointed by SIGN_VERIFY_CONTEXT and set everything to zero.
 */
static void
free_sv_ctx(SIGN_VERIFY_CONTEXT *ctx)
{
	struct icsf_multi_part_context *multi_part_ctx;

	if (!ctx)
		return;

	/* Initialize encryption context */
	multi_part_ctx = (struct icsf_multi_part_context *) ctx->context;
	if (multi_part_ctx) {
		if (multi_part_ctx->data)
			free(multi_part_ctx->data);
		free(multi_part_ctx);
	}
	if (ctx->mech.pParameter)
		free(ctx->mech.pParameter);
	memset(ctx, 0, sizeof(*ctx));
}

/*
 * get the hash size for hmacs.
 */
int
get_signverify_len(CK_MECHANISM mech)
{
	switch(mech.mechanism) {
	case CKM_MD5_HMAC:
	case CKM_SSL3_MD5_MAC:
		return MD5_HASH_SIZE;
	case CKM_SHA_1_HMAC:
	case CKM_SSL3_SHA1_MAC:
		return SHA1_HASH_SIZE;
	case CKM_SHA256_HMAC:
		return SHA2_HASH_SIZE;
	case CKM_SHA384_HMAC:
		return SHA3_HASH_SIZE;
	case CKM_SHA512_HMAC:
		return SHA5_HASH_SIZE;
	}
	return -1;
}

CK_RV icsftok_sign_init(SESSION *session, CK_MECHANISM *mech,
			CK_BBOOL recover_mode, CK_OBJECT_HANDLE key)
{
	struct session_state *session_state;
	SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
	struct icsf_multi_part_context *multi_part_ctx = NULL;
	struct icsf_object_mapping *mapping = NULL;
	CK_RV rc = CKR_OK;
	CK_BBOOL multi = FALSE;
	CK_BBOOL datacaching = FALSE;
	CK_MAC_GENERAL_PARAMS *param;

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		goto done;

	/* Check the mechanism info */
	switch (mech->mechanism) {
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_DSA:
	case CKM_ECDSA:

		/* these do not do multipart and do not require
		 * a mechanism parameter.
		 */
		if (mech->ulParameterLen != 0) {
			TRACE_ERROR("%s\n",
				    ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}
		multi = FALSE;
		break;

	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:

		/* hmacs can do mulitpart and do not require a
		 *  mechanism parameter.
		 */
		if (mech->ulParameterLen != 0) {
			TRACE_ERROR("%s\n",
				    ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}
		multi = TRUE;
		break;

	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:

		/* can do mulitpart and take a mech parameter */

		param = (CK_MAC_GENERAL_PARAMS *)mech->pParameter;

		if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)) {
			TRACE_ERROR("%s\n",
				    ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (((mech->mechanism == CKM_SSL3_MD5_MAC) && (*param != 16)) ||
		    ((mech->mechanism == CKM_SSL3_SHA1_MAC) && (*param != 20))){
			TRACE_ERROR("%s\n",
				    ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}

		multi = TRUE;
		break;

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_DSA_SHA1:
	case CKM_ECDSA_SHA1:

		/* these can do mulitpart and require data caching
		 * and do not require a mechanism parameter.
		 */
		if (mech->ulParameterLen != 0) {
			TRACE_ERROR("%s\n",
				    ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}
		multi = TRUE;
		datacaching = TRUE;
		break;

	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	/* Initialize sign context */
	free_sv_ctx(ctx);

        /* Copy mechanism */
	if (mech->pParameter == NULL || mech->ulParameterLen == 0) {
		ctx->mech.ulParameterLen = 0;
		ctx->mech.pParameter = NULL;
	} else {
		ctx->mech.pParameter = malloc(mech->ulParameterLen);
		if (!ctx->mech.pParameter) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			rc = CKR_HOST_MEMORY;
			goto done;
		}
		ctx->mech.ulParameterLen = mech->ulParameterLen;
		memcpy(ctx->mech.pParameter, mech->pParameter,
			mech->ulParameterLen);
	}
	ctx->mech.mechanism = mech->mechanism;

	/* If the mechanism supports multipart, prepare ctx */
	if (multi) {
		/* Allocate context for multi-part operations */
		if (!(multi_part_ctx = malloc(sizeof(*multi_part_ctx)))) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			rc = CKR_HOST_MEMORY;
			goto done;
		}
		ctx->context_len = sizeof(*multi_part_ctx);
		ctx->context = (void *) multi_part_ctx;
		memset(multi_part_ctx, 0, sizeof(*multi_part_ctx));

		/* keep a cache to ensure multiple of blocksize
		 * is sent to ICSF.
		 */

		if (datacaching) {
			size_t blocksize;

			rc = icsf_block_size(mech->mechanism, &blocksize);
			if (rc != CKR_OK)
				goto done;
			multi_part_ctx->data_len = blocksize;
			multi_part_ctx->data = malloc(multi_part_ctx->data_len);
			if (!multi_part_ctx->data) {
				TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
				rc = CKR_HOST_MEMORY;
				goto done;
			}
			memset(multi_part_ctx->data, 0, blocksize);
		}
	} else {
		ctx->context_len = 0;
		ctx->context = NULL;
	}

	ctx->key = key;
	ctx->multi = FALSE;
	ctx->active = TRUE;

done:
	if (rc != CKR_OK)
		free_sv_ctx(ctx);

	return rc;
}
CK_RV icsftok_sign(SESSION *session, CK_BBOOL length_only, CK_BYTE *in_data,
		   CK_ULONG in_data_len, CK_BYTE *signature, CK_ULONG *sig_len)
{
	struct session_state *session_state;
	SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
	struct icsf_object_mapping *mapping = NULL;
	CK_BYTE chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	CK_RV rc = CKR_OK;
	int hlen, reason;

	if (!ctx || !sig_len) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;
	}

	if ((length_only == FALSE) && (!in_data || !signature)) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;
	}

	if (ctx->multi == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
		return CKR_OPERATION_ACTIVE;
	}

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		return rc;

	switch (ctx->mech.mechanism) {
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:

		if (length_only) {
			hlen = get_signverify_len(ctx->mech);
			if (hlen < 0) {
				TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
				return CKR_MECHANISM_INVALID;
			}
			*sig_len = hlen;
			return CKR_OK;
		}

		rc = icsf_hmac_sign(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech, "ONLY",
				in_data, in_data_len, signature, sig_len,
				chain_data, &chain_data_len);
		if (rc != 0)
			rc = icsf_to_ock_err(rc, reason);
		break;

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_DSA:
	case CKM_ECDSA:
		rc = icsf_private_key_sign(session_state->ld, &reason, FALSE,
				&mapping->icsf_object, &ctx->mech, in_data,
				in_data_len, signature, sig_len);
		if (rc != 0) {
			if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT
					&& length_only) {
				rc = CKR_OK;
			} else {
				TRACE_DEVEL("icsf_private_key_sign failed\n");
				rc = icsf_to_ock_err(rc, reason);
			}
		}
		break;

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_DSA_SHA1:
	case CKM_ECDSA_SHA1:
		rc = icsf_hash_signverify(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech,
				"ONLY", in_data, in_data_len, signature,
				sig_len, chain_data, &chain_data_len, 0);
		if (rc != 0) {
			if (reason == ICSF_REASON_OUTPUT_PARAMETER_TOO_SHORT
					&& length_only) {
				rc = CKR_OK;
			} else {
				TRACE_DEVEL("icsf_hash_signverify failed\n");
				rc = icsf_to_ock_err(rc, reason);
			}
		}
		break;

	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
	}

	if (rc != CKR_OK)
		free_sv_ctx(ctx);

	return rc;
}

CK_RV icsftok_sign_update(SESSION *session, CK_BYTE *in_data,
			  CK_ULONG in_data_len)
{
	struct session_state *session_state;
	SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
	struct icsf_object_mapping *mapping = NULL;
	struct icsf_multi_part_context *multi_part_ctx = NULL;
	CK_BYTE chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	CK_RV rc = CKR_OK;
	int reason;
	size_t siglen = 0;
	CK_ULONG total, remain, out_len = 0;
	char *buffer = NULL;

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		return rc;

	/* indicate this is multipart operation and get chain info from ctx.
	 * if any mechanisms that cannot do multipart sign come here, they
	 * will not have had ctx->context allocated and will
	 * get an error in switch below.
	 */
	ctx->multi = TRUE;
	if (ctx->context) {
		multi_part_ctx = (struct icsf_multi_part_context *)ctx->context;
		if (multi_part_ctx->initiated)
			memcpy(chain_data, multi_part_ctx->chain_data,
				chain_data_len);
	}

	switch (ctx->mech.mechanism) {
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:

		rc = icsf_hmac_sign(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech,
				(multi_part_ctx->initiated) ? "MIDDLE":"FIRST",
				in_data, in_data_len, NULL, &siglen,
				chain_data, &chain_data_len);

		if (rc != 0) {
			TRACE_DEVEL("icsf_hmac_sign failed\n");
			rc = icsf_to_ock_err(rc, reason);
		} else {
			multi_part_ctx->initiated = TRUE;
			memcpy(multi_part_ctx->chain_data, chain_data,
			       chain_data_len);
		}

		break;

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_DSA_SHA1:
	case CKM_ECDSA_SHA1:

		/* caching data since ICSF wants in multiple of blocksize */
		if (multi_part_ctx && multi_part_ctx->data) {

			total = multi_part_ctx->used_data_len + in_data_len;
			remain  = total % multi_part_ctx->data_len;;

			/* if not enough to meet blocksize, cache and exit. */
			if (total < multi_part_ctx->data_len) {
				memcpy(multi_part_ctx->data + multi_part_ctx->used_data_len,
					in_data, in_data_len );
				multi_part_ctx->used_data_len += in_data_len;

				rc = CKR_OK;
				goto done;
			} else {
				/* there is at least 1 block */

				out_len = total - remain;

				/* prepare a buffer to send data in */
				if (!(buffer = malloc(out_len))) {
					TRACE_ERROR("%s\n",
						    ock_err(ERR_HOST_MEMORY));
					rc = CKR_HOST_MEMORY;
					goto done;
				}
				memcpy(buffer, multi_part_ctx->data,
				       multi_part_ctx->used_data_len);
				memcpy(buffer + multi_part_ctx->used_data_len,
				       in_data,
				       out_len - multi_part_ctx->used_data_len);

				/* copy remainder of data to ctx
				 * for next time. caching.
				 */
				if (remain != 0)
					memcpy(multi_part_ctx->data,
					       in_data + (in_data_len - remain),
					       remain);

				multi_part_ctx->used_data_len = remain;
			}
		}

		rc = icsf_hash_signverify(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech,
				(multi_part_ctx->initiated) ? "MIDDLE":"FIRST",
				buffer, out_len, NULL, NULL,
				chain_data, &chain_data_len, 0);

		if (rc != 0) {
			TRACE_DEVEL("icsf_hash_signverify failed\n");
			rc = icsf_to_ock_err(rc, reason);
		} else {
			multi_part_ctx->initiated = TRUE;
			memcpy(multi_part_ctx->chain_data, chain_data,
			       chain_data_len);
		}

		if (buffer)
			free(buffer);

		break;

	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
	}

done:
	if (rc != 0)
		free_sv_ctx(ctx);

	return rc;
}

CK_RV icsftok_sign_final(SESSION *session, CK_BBOOL length_only,
			 CK_BYTE *signature, CK_ULONG *sig_len)
{
	struct session_state *session_state;
	SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
	struct icsf_object_mapping *mapping = NULL;
	struct icsf_multi_part_context *multi_part_ctx = NULL;
	CK_BYTE chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	char *buffer = NULL;
	CK_RV rc = CKR_OK;
	int hlen, reason;

	if (!sig_len) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		return rc;

	/* get the chain data from ctx */
	if (ctx->context) {
		multi_part_ctx = (struct icsf_multi_part_context *)ctx->context;
		memcpy(chain_data, multi_part_ctx->chain_data, chain_data_len);
	}

	switch (ctx->mech.mechanism) {

	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:

		if (length_only) {
			hlen = get_signverify_len(ctx->mech);
			if (hlen < 0) {
				TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
				return CKR_MECHANISM_INVALID;
			}

			*sig_len = hlen;
			return CKR_OK;
		}

		rc = icsf_hmac_sign(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech,
				multi_part_ctx->initiated ? "LAST":"ONLY", "",
				0, signature, sig_len, chain_data,
				&chain_data_len);
		if (rc != 0)
			rc = icsf_to_ock_err(rc, reason);
		break;

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_DSA_SHA1:
	case CKM_ECDSA_SHA1:

		/* see if any data left in the cache */
		if (multi_part_ctx && multi_part_ctx->used_data_len) {
			if (!(buffer = malloc(multi_part_ctx->used_data_len))) {
				TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
				rc = CKR_HOST_MEMORY;
				goto done;
			}
			memcpy(buffer, multi_part_ctx->data,
			multi_part_ctx->used_data_len);
		}

		rc = icsf_hash_signverify(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech,
				multi_part_ctx->initiated ? "LAST":"ONLY",
				(buffer) ? buffer : NULL,
				multi_part_ctx->used_data_len, signature,
				sig_len, chain_data, &chain_data_len, 0);

		if (rc != 0) {
			if (length_only && reason == 3003)
					rc = CKR_OK;
			else {
				TRACE_DEVEL("icsf_hash_signverify failed\n");
				rc = icsf_to_ock_err(rc, reason);
			}
		}

		if (buffer)
			free(buffer);
		break;

	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
	}

done:
	if (rc != CKR_OK)
		free_sv_ctx(ctx);
	return rc;
}

CK_RV icsftok_verify_init(SESSION *session, CK_MECHANISM *mech,
				   CK_BBOOL recover_mode, CK_OBJECT_HANDLE key)
{
	struct session_state *session_state;
	SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
	struct icsf_multi_part_context *multi_part_ctx = NULL;
	struct icsf_object_mapping *mapping = NULL;
	CK_RV rc = CKR_OK;
	CK_BBOOL multi = FALSE;
	CK_BBOOL datacaching = FALSE;
	CK_MAC_GENERAL_PARAMS *param;

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		rc = CKR_SESSION_HANDLE_INVALID;
		goto done;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		return rc;

	/* Check the mechanism info */
	switch (mech->mechanism) {
	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_DSA:
	case CKM_ECDSA:

		/* these do not do multipart and do not require
		 * a mechanism parameter.
		 */
		if (mech->ulParameterLen != 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}
		multi = FALSE;
		break;

	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:

		/* hmacs can do mulitpart and do not require a
		 *  mechanism parameter.
		 */
		if (mech->ulParameterLen != 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}
		multi = TRUE;
		break;

	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:

		/* can do mulitpart and take a mech parameter */

		param = (CK_MAC_GENERAL_PARAMS *)mech->pParameter;

		if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS)) {
			TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}
		if (((mech->mechanism == CKM_SSL3_MD5_MAC) && (*param != 16)) ||
		    ((mech->mechanism == CKM_SSL3_SHA1_MAC) && (*param != 20))){
			TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}

		multi = TRUE;
		break;

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_DSA_SHA1:
	case CKM_ECDSA_SHA1:

		/* these can do mulitpart and require data caching
		 * but do not require a mechanism parameter
		 */
		if (mech->ulParameterLen != 0) {
			TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
			return CKR_MECHANISM_PARAM_INVALID;
		}
		multi = TRUE;
		datacaching = TRUE;
		break;

	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		return CKR_MECHANISM_INVALID;
	}

	/* Initialize ctx */
	free_sv_ctx(ctx);

        /* Copy mechanism */
	if (mech->pParameter == NULL || mech->ulParameterLen == 0) {
		ctx->mech.ulParameterLen = 0;
		ctx->mech.pParameter = NULL;
	} else {
		ctx->mech.pParameter = malloc(mech->ulParameterLen);
		if (!ctx->mech.pParameter) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			rc = CKR_HOST_MEMORY;
			goto done;
		}
		ctx->mech.ulParameterLen = mech->ulParameterLen;
		memcpy(ctx->mech.pParameter, mech->pParameter,
			mech->ulParameterLen);
	}
	ctx->mech.mechanism = mech->mechanism;

	/* If the mechanism supports multipart, prepare ctx */
	if (multi) {
		/* Allocate context for multi-part operations */
		if (!(multi_part_ctx = malloc(sizeof(*multi_part_ctx)))) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			rc = CKR_HOST_MEMORY;
			goto done;
		}
		ctx->context_len = sizeof(*multi_part_ctx);
		ctx->context = (void *) multi_part_ctx;
                memset(multi_part_ctx, 0, sizeof(*multi_part_ctx));

		/* keep a cache to ensure multiple of blocksize
		 * is sent to ICSF.
		 */

		if (datacaching) {
			size_t blocksize;

			rc = icsf_block_size(mech->mechanism, &blocksize);
			if (rc != CKR_OK)
				goto done;
			multi_part_ctx->data_len = blocksize;
			multi_part_ctx->data = malloc(multi_part_ctx->data_len);
			if (!multi_part_ctx->data) {
				TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
				rc = CKR_HOST_MEMORY;
				goto done;
			}
			memset(multi_part_ctx->data, 0, blocksize);
		}
	} else {
		ctx->context_len = 0;
		ctx->context = NULL;
	}

	ctx->key = key;
	ctx->multi = FALSE;
	ctx->active = TRUE;

done:
	if (rc != CKR_OK)
		free_sv_ctx(ctx);

	return rc;
}

CK_RV icsftok_verify(SESSION *session, CK_BYTE *in_data, CK_ULONG in_data_len,
		     CK_BYTE *signature, CK_ULONG sig_len)
{
	struct session_state *session_state;
	SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
	struct icsf_object_mapping *mapping = NULL;
	CK_BYTE chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	CK_RV rc = CKR_OK;
	int reason;

	if (!session || !ctx || !in_data || !signature) {
		TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
		return CKR_FUNCTION_FAILED;
	}

	if (ctx->multi == TRUE) {
		TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
		return CKR_OPERATION_ACTIVE;
	}

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		return rc;

	switch (ctx->mech.mechanism) {
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
		rc = icsf_hmac_verify(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech, "ONLY",
				in_data, in_data_len, signature, sig_len,
				chain_data, &chain_data_len);
		if (rc != 0)
			rc = icsf_to_ock_err(rc, reason);

		break;

	case CKM_RSA_X_509:
	case CKM_RSA_PKCS:
	case CKM_DSA:
	case CKM_ECDSA:
		rc = icsf_public_key_verify(session_state->ld, &reason, FALSE,
				&mapping->icsf_object, &ctx->mech, in_data,
				in_data_len, signature, &sig_len);
		if (rc != 0)
			rc = icsf_to_ock_err(rc, reason);
		break;

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_DSA_SHA1:
	case CKM_ECDSA_SHA1:
		rc = icsf_hash_signverify(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech,
				"ONLY", in_data, in_data_len, signature,
				&sig_len, chain_data, &chain_data_len, 1);
		if (rc != 0)
			rc = icsf_to_ock_err(rc, reason);

		break;

	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
	}

	if (rc != CKR_OK)
		free_sv_ctx(ctx);
	return rc;
}

CK_RV icsftok_verify_update(SESSION *session, CK_BYTE *in_data,
			    CK_ULONG in_data_len)
{
	struct session_state *session_state;
	SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
	struct icsf_object_mapping *mapping = NULL;
	struct icsf_multi_part_context *multi_part_ctx = NULL;
	CK_BYTE chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	CK_RV rc = CKR_OK;
	int reason;
	CK_ULONG total, remain, out_len = 0;
	char *buffer = NULL;

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		return rc;

	/* indicate this is multipart operation and get chain info from ctx.
	 * if any mechanisms that cannot do multipart verify come here, they
	 * will get an error in switch below.
	 */
	ctx->multi = TRUE;
	if (ctx->context) {
		multi_part_ctx = (struct icsf_multi_part_context *)ctx->context;
		if (multi_part_ctx->initiated)
			memcpy(chain_data, multi_part_ctx->chain_data,
				chain_data_len);
	}

	switch (ctx->mech.mechanism) {
	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:
		rc = icsf_hmac_verify(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech,
				(multi_part_ctx->initiated) ? "MIDDLE":"FIRST",
				in_data, in_data_len, "",  0,
				chain_data, &chain_data_len);

		if (rc != 0) {
			TRACE_DEVEL("icsf_hmac_verify failed\n");
			rc = icsf_to_ock_err(rc, reason);
		} else {
			multi_part_ctx->initiated = TRUE;
			memcpy(multi_part_ctx->chain_data, chain_data,
			       chain_data_len);
		}

		break;

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_DSA_SHA1:
	case CKM_ECDSA_SHA1:
		/* caching data since ICSF wants in multiple of blocksize */
		if (multi_part_ctx && multi_part_ctx->data) {

			total = multi_part_ctx->used_data_len + in_data_len;
			remain  = total % multi_part_ctx->data_len;;

			/* if not enough to meet blocksize, cache and exit. */
			if (total < multi_part_ctx->data_len) {
				memcpy(multi_part_ctx->data + multi_part_ctx->used_data_len,
					in_data, in_data_len );
				multi_part_ctx->used_data_len += in_data_len;

				rc = CKR_OK;
				goto done;
			} else {
				/* there is at least 1 block */

				out_len = total - remain;

				/* prepare a buffer to send data in */
				if (!(buffer = malloc(out_len))) {
					TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
					rc = CKR_HOST_MEMORY;
					goto done;
				}
				memcpy(buffer, multi_part_ctx->data,
				       multi_part_ctx->used_data_len);
				memcpy(buffer + multi_part_ctx->used_data_len,
				       in_data,
				       out_len - multi_part_ctx->used_data_len);

				/* copy remainder of data to ctx
				 * for next time. caching.
				 */
				if (remain != 0)
					memcpy(multi_part_ctx->data,
					       in_data + (in_data_len - remain),
					       remain);

				multi_part_ctx->used_data_len = remain;
			}
		}

		rc = icsf_hash_signverify(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech,
				(multi_part_ctx->initiated) ? "MIDDLE":"FIRST",
				buffer, out_len, NULL, NULL,
				chain_data, &chain_data_len, 1);

		if (rc != 0) {
			TRACE_DEVEL("icsf_hash_signverify failed\n");
			rc = icsf_to_ock_err(rc, reason);
		} else {
			multi_part_ctx->initiated = TRUE;
			memcpy(multi_part_ctx->chain_data, chain_data,
			       chain_data_len);
		}

		if (buffer)
			free(buffer);

		break;

	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
	}

done:
	if (rc != 0)
		free_sv_ctx(ctx);

	return rc;
}

CK_RV icsftok_verify_final(SESSION *session, CK_BYTE *signature,
			   CK_ULONG sig_len)
{
	struct session_state *session_state;
	SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
	struct icsf_object_mapping *mapping = NULL;
	struct icsf_multi_part_context *multi_part_ctx = NULL;
	CK_BYTE chain_data[ICSF_CHAINING_DATA_LEN] = { 0, };
	size_t chain_data_len = sizeof(chain_data);
	CK_RV rc = CKR_OK;
	int reason;
	char *buffer = NULL;

	if (!sig_len) {
		TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
		return CKR_ARGUMENTS_BAD;
	}

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		return CKR_SESSION_HANDLE_INVALID;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	if(!(mapping = bt_get_node_value(&objects, ctx->key))) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
	}
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (rc != CKR_OK)
		return rc;

	/* get the chain data from ctx */
	if (ctx->context) {
		multi_part_ctx = (struct icsf_multi_part_context *)ctx->context;
		memcpy(chain_data, multi_part_ctx->chain_data, chain_data_len);
	}

	switch (ctx->mech.mechanism) {

	case CKM_MD5_HMAC:
	case CKM_SHA_1_HMAC:
	case CKM_SHA256_HMAC:
	case CKM_SHA384_HMAC:
	case CKM_SHA512_HMAC:
	case CKM_SSL3_MD5_MAC:
	case CKM_SSL3_SHA1_MAC:

		/* get the chain data */
		rc = icsf_hmac_verify(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech,
				multi_part_ctx->initiated ? "LAST":"ONLY", "",
				0, signature, sig_len, chain_data,
				&chain_data_len);
		if (rc != 0)
			rc = icsf_to_ock_err(rc, reason);

		break;

	case CKM_MD5_RSA_PKCS:
	case CKM_SHA1_RSA_PKCS:
	case CKM_SHA256_RSA_PKCS:
	case CKM_SHA384_RSA_PKCS:
	case CKM_SHA512_RSA_PKCS:
	case CKM_DSA_SHA1:
	case CKM_ECDSA_SHA1:

		/* see if any data left in the cache */
		if (multi_part_ctx && multi_part_ctx->used_data_len) {
			if (!(buffer = malloc(multi_part_ctx->used_data_len))) {
				TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
				rc = CKR_HOST_MEMORY;
				goto done;
			}
			memcpy(buffer, multi_part_ctx->data,
			multi_part_ctx->used_data_len);
		}

		rc = icsf_hash_signverify(session_state->ld, &reason,
				&mapping->icsf_object, &ctx->mech,
				multi_part_ctx->initiated ? "LAST":"ONLY",
				(buffer) ? buffer : NULL,
				multi_part_ctx->used_data_len, signature,
				&sig_len, chain_data, &chain_data_len, 1);

		if (rc != 0)
			rc = icsf_to_ock_err(rc, reason);

		if (buffer)
			free(buffer);
		break;

	default:
		TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
		rc = CKR_MECHANISM_INVALID;
	}

done:
	if (rc != CKR_OK)
		free_sv_ctx(ctx);
	return rc;
}

/*
 * Wrap a key and return it as binary data.
 */
CK_RV icsftok_wrap_key(SESSION *session, CK_MECHANISM_PTR mech,
		       CK_OBJECT_HANDLE wrapping_key, CK_OBJECT_HANDLE key,
		       CK_BYTE_PTR wrapped_key, CK_ULONG_PTR p_wrapped_key_len)
{
	int rc;
	int reason = 0;
	struct session_state *session_state;
	struct icsf_object_mapping *wrapping_key_mapping = NULL;
	struct icsf_object_mapping *key_mapping = NULL;

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		return  CKR_SESSION_HANDLE_INVALID;
	}

	/* Check if keys exist */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	wrapping_key_mapping = bt_get_node_value(&objects, wrapping_key);
	key_mapping = bt_get_node_value(&objects, key);
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (!wrapping_key_mapping || !key_mapping) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		return CKR_KEY_HANDLE_INVALID;
	}

	/* Call ICSF service */
	rc = icsf_wrap_key(session_state->ld, &reason, mech,
			  &wrapping_key_mapping->icsf_object,
			  &key_mapping->icsf_object, wrapped_key,
			  p_wrapped_key_len);
	if (rc) {
		TRACE_DEVEL("icsf_wrap_key failed\n");
		return icsf_to_ock_err(rc, reason);
	}

	return CKR_OK;
}

/*
 * Unwrap a key from binary data and create a new key object.
 */
CK_RV icsftok_unwrap_key(SESSION *session, CK_MECHANISM_PTR mech,
			 CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			 CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_key_len,
			 CK_OBJECT_HANDLE wrapping_key,
			 CK_OBJECT_HANDLE_PTR p_key)
{
	int rc;
	int reason = 0;
	struct session_state *session_state;
	struct icsf_object_mapping *wrapping_key_mapping = NULL;
	struct icsf_object_mapping *key_mapping = NULL;
	int is_obj_locked = 0;
	CK_ULONG node_number;

	/* Check session */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
		return  CKR_SESSION_HANDLE_INVALID;
	}

	/* Check if key exists */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	wrapping_key_mapping = bt_get_node_value(&objects, wrapping_key);
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if (!wrapping_key_mapping) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		return CKR_KEY_HANDLE_INVALID;
	}

	/* Allocate structure to keep ICSF object information */
	if (!(key_mapping = malloc(sizeof(*key_mapping)))) {
		TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
		return CKR_HOST_MEMORY;
	}
	memset(key_mapping, 0, sizeof(*key_mapping));
	key_mapping->session_id = session->handle;

	/* Call ICSF service */
	rc = icsf_unwrap_key(session_state->ld, &reason, mech,
			     &wrapping_key_mapping->icsf_object,
			     wrapped_key, wrapped_key_len,
			     attrs, attrs_len, &key_mapping->icsf_object);
	if (rc) {
		TRACE_DEVEL("icsf_unwrap_key failed\n");
		rc = icsf_to_ock_err(rc, reason);
		goto done;
	}

	/* Lock the object list */
	if (pthread_rwlock_wrlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Failed to lock mutex.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	is_obj_locked = 1;

	/* Add info about object into session */
	if(!(node_number = bt_node_add(&objects, key_mapping))) {
		TRACE_ERROR("Failed to add object to binary tree.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Use node number as handle */
	*p_key = node_number;

done:
	if (is_obj_locked && pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock failed.\n");
		rc = CKR_FUNCTION_FAILED;
	}

	/* If allocated, object must be freed in case of failure */
	if (rc && key_mapping)
		free(key_mapping);

	return rc;
}

/*
 * Derive a key from a base key, creating a new key object.
 */
CK_RV icsftok_derive_key(SESSION *session, CK_MECHANISM_PTR mech,
			 CK_OBJECT_HANDLE hBaseKey, CK_OBJECT_HANDLE_PTR handle,
			 CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len)
{
	CK_RV rc = CKR_OK;
	struct session_state *session_state;
	struct icsf_object_mapping *base_key_mapping;
	CK_ULONG node_number;
	char token_name[sizeof(nv_token_data->token_info.label)];
	CK_SSL3_KEY_MAT_PARAMS *params = {0};
	int is_obj_locked = 0;
	int reason = 0;
	int i;

	/* Variable for multiple keys derivation */
	int multiple = 0;
	struct icsf_object_mapping *mappings[4] = { NULL, };
	CK_OBJECT_HANDLE *keys[4] = { NULL, };

	/* Check type of derivation */
	if (mech->mechanism == CKM_SSL3_KEY_AND_MAC_DERIVE ||
			mech->mechanism == CKM_TLS_KEY_AND_MAC_DERIVE) {
		multiple = 1;
		params = (CK_SSL3_KEY_MAT_PARAMS *) mech->pParameter;
  		keys[0] = &params->pReturnedKeyMaterial->hClientMacSecret;
		keys[1] = &params->pReturnedKeyMaterial->hServerMacSecret;
		keys[2] = &params->pReturnedKeyMaterial->hClientKey;
		keys[3] = &params->pReturnedKeyMaterial->hServerKey;
	} else {
		keys[0] = handle;
	}

	/* Check permissions based on attributes and session */
	rc = check_session_permissions(session, attrs, attrs_len);
	if (rc != CKR_OK)
		return rc;

	/* Copy token name from shared memory */
	XProcLock();
	memcpy(token_name, nv_token_data->token_info.label, sizeof(token_name));
	XProcUnLock();

	/* Allocate structure to keep ICSF object information */
	for (i = 0; i < sizeof(mappings)/sizeof(*mappings); i++) {
		if (!(mappings[i] = malloc(sizeof(*mappings[i])))) {
			TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
			rc = CKR_HOST_MEMORY;
			goto done;
		}
		memset(mappings[i], 0, sizeof(*mappings[i]));
		mappings[i]->session_id = session->handle;

		/* If not deriving multiple keys, just one key is needed */
		if (!multiple)
			break;
	}

	/* Get session state */
	if (!(session_state = get_session_state(session->handle))) {
		TRACE_ERROR("Session not found for session id %lu.\n",
			    (unsigned long) session->handle);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Convert the OCK_CK_OBJECT_HANDLE_PTR to ICSF */
	pthread_rwlock_rdlock(&obj_list_rw_mutex);
	base_key_mapping = bt_get_node_value(&objects, hBaseKey);
	pthread_rwlock_unlock(&obj_list_rw_mutex);
	if(!base_key_mapping) {
		TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
		rc = CKR_KEY_HANDLE_INVALID;
		goto done;
	}

	/* Call ICSF service */
	if (!multiple)
		rc = icsf_derive_key(session_state->ld, &reason, mech,
					&base_key_mapping->icsf_object,
					&mappings[0]->icsf_object, attrs,
					attrs_len);
	else
		rc = icsf_derive_multiple_keys(session_state->ld, &reason,
					mech, &base_key_mapping->icsf_object,
			 		attrs, attrs_len,
					&mappings[0]->icsf_object,
					&mappings[1]->icsf_object,
					&mappings[2]->icsf_object,
					&mappings[3]->icsf_object,
					params->pReturnedKeyMaterial->pIVClient,
					params->pReturnedKeyMaterial->pIVServer);
	if (rc) {
		rc = icsf_to_ock_err(rc, reason);
		goto done;
	}

	/* Lock the object list */
	if (pthread_rwlock_wrlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock failed.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	is_obj_locked = 1;

	for (i = 0; i < sizeof(mappings)/sizeof(*mappings); i++) {
		/* Add info about object into session */
		if(!(node_number = bt_node_add(&objects, mappings[i]))) {
			TRACE_ERROR("Failed to add object to binary tree.\n");
			rc = CKR_FUNCTION_FAILED;
			goto done;
		}

		/* Use node number as handle */
		*keys[i] = node_number;

		/* If not deriving multiple keys, just one key is returned */
		if (!multiple)
			break;
	}

done:
	if (is_obj_locked && pthread_rwlock_unlock(&obj_list_rw_mutex)) {
		TRACE_ERROR("Mutex Unlock failed.\n");
		rc = CKR_FUNCTION_FAILED;
	}

	/* If allocated, object must be freed in case of failure */
	if (rc) {
		for (i = 0; i < sizeof(mappings)/sizeof(*mappings); i++)
			if (mappings[i])
				free(mappings[i]);
	}

	return rc;
}
