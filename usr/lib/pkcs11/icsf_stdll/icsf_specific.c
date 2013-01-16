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
#include "../api/apiproto.h"

/* Default token attributes */
CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "IBM ICSFTok ";
CK_CHAR descr[] = "IBM PKCS#11 ICSF token";
CK_CHAR label[] = "IBM OS PKCS#11   ";

/* mechanisms provided by this token */
MECH_LIST_ELEMENT mech_list[] = {
  { CKM_RSA_PKCS_KEY_PAIR_GEN, {512,	4096,	CKF_HW | CKF_GENERATE_KEY_PAIR} },
  { CKM_DES_KEY_GEN, 	{8,	8,	CKF_HW | CKF_GENERATE} },
  { CKM_DES2_KEY_GEN, 	{24,	24,	CKF_HW | CKF_GENERATE} },
  { CKM_DES3_KEY_GEN, 	{24,	24,	CKF_HW | CKF_GENERATE} },
  { CKM_RSA_PKCS,	{512,	4096,	CKF_HW | CKF_ENCRYPT | CKF_DECRYPT |
			 		CKF_WRAP | CKF_UNWRAP |
			 		CKF_SIGN | CKF_VERIFY |
				 	CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER} },
  { CKM_RSA_X_509,	{512,	4096,	CKF_HW | CKF_ENCRYPT | CKF_DECRYPT |
				 	CKF_SIGN | CKF_VERIFY |
				 	CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER} },
  { CKM_MD2_RSA_PKCS,	{512,	4096,	CKF_SIGN | CKF_VERIFY} },
  { CKM_MD5_RSA_PKCS,	{512,	4096,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_SHA1_RSA_PKCS,	{512,	4096,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_SHA256_RSA_PKCS,	{512,	4096,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_SHA384_RSA_PKCS,	{512,	4096,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_SHA512_RSA_PKCS,	{512,	4096,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_DES_ECB,	{0,	0,	CKF_HW | CKF_ENCRYPT | CKF_DECRYPT} },
  { CKM_DES_CBC,	{0,	0,	CKF_HW | CKF_ENCRYPT | CKF_DECRYPT} },
  { CKM_DES_CBC_PAD,	{0,	0,	CKF_HW | CKF_ENCRYPT	| CKF_DECRYPT |
				 	CKF_WRAP | CKF_UNWRAP} },
  { CKM_DES3_ECB,	{0,	0,	CKF_HW | CKF_ENCRYPT | CKF_DECRYPT} }, 
  { CKM_DES3_CBC,	{0,	0,	CKF_HW | CKF_ENCRYPT | CKF_DECRYPT} },
  { CKM_DES3_CBC_PAD,	{0,	0,	CKF_HW | CKF_ENCRYPT | CKF_DECRYPT |
				 	CKF_WRAP | CKF_UNWRAP} },
  { CKM_SHA_1,		{0,	0,	CKF_HW | CKF_DIGEST } },
  { CKM_SHA256,		{0,	0,	CKF_HW | CKF_DIGEST } },
  { CKM_SHA384,		{0,	0,	CKF_HW | CKF_DIGEST } },
  { CKM_SHA512,		{0,	0,	CKF_HW | CKF_DIGEST } },
  { CKM_RIPEMD160,	{0,	0,	CKF_DIGEST } },
  { CKM_MD2,		{0,	0,	CKF_DIGEST } },
  { CKM_MD5,		{0,	0,	CKF_DIGEST } },
  { CKM_AES_KEY_GEN, 	{16,	32,	CKF_HW | CKF_GENERATE} },
  { CKM_AES_ECB,	{16,	32,	CKF_HW | CKF_ENCRYPT | CKF_DECRYPT} },
  { CKM_AES_CBC,	{16,	32,	CKF_HW | CKF_ENCRYPT | CKF_DECRYPT} },
  { CKM_AES_CBC_PAD,	{16,	32,	CKF_HW | CKF_ENCRYPT | CKF_DECRYPT |
				 	CKF_WRAP | CKF_UNWRAP} },
  { CKM_DSA_KEY_PAIR_GEN, 	{512,	2048,	CKF_HW | CKF_GENERATE_KEY_PAIR} },
  { CKM_DH_PKCS_KEY_PAIR_GEN, 	{512,	2048,	CKF_GENERATE_KEY_PAIR} },
  { CKM_EC_KEY_PAIR_GEN,	{160, 	521,	CKF_HW | CKF_GENERATE_KEY_PAIR |
					CKF_EC_F_P | CKF_EC_NAMEDCURVE |
					CKF_EC_UNCOMPRESS} },
  { CKM_SSL3_PRE_MASTER_KEY_GEN,	{48,	48,	CKF_HW | CKF_GENERATE} },
  { CKM_DSA_SHA1,	{512,	4096,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_DSA,		{512,	2048,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_ECDSA_SHA1,	{512,	4096,	CKF_HW | CKF_SIGN | CKF_VERIFY |
					CKF_EC_F_P | CKF_EC_NAMEDCURVE |
					CKF_EC_UNCOMPRESS} },
  { CKM_ECDSA,		{160,	521,	CKF_HW | CKF_SIGN | CKF_VERIFY |
					CKF_EC_F_P | CKF_EC_NAMEDCURVE |
					CKF_EC_UNCOMPRESS} },
  { CKM_MD5_HMAC,	{0,	0,	CKF_SIGN | CKF_VERIFY} },
  { CKM_SHA_1_HMAC,	{0,	0,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_SHA256_HMAC,	{0,	0,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_SHA384_HMAC,	{0,	0,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_SHA512_HMAC,	{0,	0,	CKF_HW | CKF_SIGN | CKF_VERIFY} },
  { CKM_SSL3_MD5_MAC,	{384,	384,	CKF_SIGN | CKF_VERIFY} },
  { CKM_SSL3_SHA1_MAC,	{384,	384,	CKF_SIGN | CKF_VERIFY} },
  { CKM_DH_PKCS_DERIVE,	{512,	2048,	CKF_DERIVE} },
  { CKM_SSL3_MASTER_KEY_DERIVE, {48,	48,	CKF_DERIVE} },
};

CK_ULONG mech_list_len = (sizeof(mech_list) / sizeof(MECH_LIST_ELEMENT));

/* Session state */
list_t sessions = LIST_INIT();

struct session_state {
	CK_SESSION_HANDLE session_id;
	LDAP *ld;
	struct btree objects;

	/* List element */
	list_entry_t sessions;
};

static struct session_state *
get_session_state(CK_SESSION_HANDLE session_id)
{
	struct session_state *s;

	for_each_list_entry(&sessions, struct session_state, s, sessions) {
		if (s->session_id == session_id)
			return s;
	}

	return NULL;
}

CK_RV
token_specific_get_mechanism_list(CK_MECHANISM_TYPE_PTR pMechanismList,
					CK_ULONG_PTR pulCount)
{
	int rc;
	rc = ock_generate_get_mechanism_list(pMechanismList, pulCount);
	return rc;
}

CK_RV
token_specific_get_mechanism_info(CK_MECHANISM_TYPE type,
				  CK_MECHANISM_INFO_PTR pInfo)
{
	int rc;
	/* common/mech_list.c */
	rc = ock_generate_get_mechanism_info(type, pInfo);
	return rc;
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
};
struct slot_data *slot_data[MAX_SLOT_ID + 1];

/*
 * Convert pkcs slot number to local representation
 */
int
tok_slot2local(CK_SLOT_ID snum)
{
	return 1;
}

/*
 * Called during C_Initialize.
 */
CK_RV
token_specific_init(char *correlator, CK_SLOT_ID slot_id, char *conf_name)
{
	CK_RV rc = CKR_OK;
	struct slot_data *data;

	/* Check Slot ID */
	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		OCK_LOG_DEBUG("Invalid slot ID: %d\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	XProcLock();

	if (slot_data[slot_id] == NULL) {
		OCK_LOG_DEBUG("ICSF slot data not initialized.\n");
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

CK_RV
token_specific_init_token_data(CK_SLOT_ID slot_id)
{
	CK_RV rc = CKR_OK;
	const char *conf_name = NULL;
	struct icsf_config config;

	/* Check Slot ID */
	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		OCK_LOG_DEBUG("Invalid slot ID: %d\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	XProcLock();

	if (slot_data[slot_id] == NULL) {
		OCK_LOG_DEBUG("ICSF slot data not initialized.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Check if data needs to be retrieved for this slot */
	if (slot_data[slot_id]->initialized) {
		OCK_LOG_DEBUG("Slot data already initialized for slot %d. "
			      "Skipping it\n", slot_id);
		goto done;
	}

	/* Check config file */
	conf_name = slot_data[slot_id]->conf_name;
	if (!conf_name || !conf_name[0]) {
		OCK_LOG_DEBUG("Missing config for slot %d.\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	OCK_LOG_DEBUG("DEBUG: conf_name=\"%s\".\n", conf_name);
	if (parse_config_file(conf_name, slot_id, &config)) {
		OCK_LOG_DEBUG("Failed to parse file \"%s\" for slot %d.\n",
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

done:
	XProcUnLock();
	return rc;
}

CK_RV
token_specific_load_token_data(CK_SLOT_ID slot_id, FILE *fh)
{
	CK_RV rc = CKR_OK;
	struct slot_data data;

	/* Check Slot ID */
	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		OCK_LOG_DEBUG("Invalid slot ID: %d\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	if (!fread(&data, sizeof(data), 1, fh)) {
		OCK_LOG_DEBUG("Failed to read ICSF slot data.\n");
		return CKR_FUNCTION_FAILED;
	}

	XProcLock();

	if (slot_data[slot_id] == NULL) {
		OCK_LOG_DEBUG("ICSF slot data not initialized.\n");
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
		OCK_LOG_DEBUG("Invalid slot ID: %d\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	XProcLock();

	if (slot_data[slot_id] == NULL) {
		OCK_LOG_DEBUG("ICSF slot data not initialized.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (!fwrite(slot_data[slot_id], sizeof(**slot_data), 1, fh)) {
		OCK_LOG_DEBUG("Failed to write ICSF slot data.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

done:
	XProcUnLock();
	return rc;
}

/*
 * Called during C_Finalize.
 */
CK_RV
token_specific_final()
{
	return CKR_OK;
}

/*
 * Initialize the shared memory region. ICSF has to use a custom method for
 * this because it uses additional data in the shared memory and in the future
 * multiple slots should be supported for ICSF.
 */
CK_RV
token_specific_attach_shm(CK_SLOT_ID slot_id, LW_SHM_TYPE **shm,
			  CK_BBOOL *created)
{
	CK_RV rc = CKR_OK;
	int ret;
	void *ptr;
	size_t len = sizeof(**shm) + sizeof(**slot_data);
	char *shm_id = NULL;

	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		OCK_LOG_DEBUG("Invalid slot ID: %d\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	if (asprintf(&shm_id, "/icsf-%d", slot_id) < 0) {
		OCK_LOG_DEBUG("Failed to allocate shared memory id "
			      "for slot %d.\n", slot_id);
		return CKR_HOST_MEMORY;
	}
	OCK_LOG_DEBUG("Attaching to shared memory \"%s\".\n", shm_id);

	XProcLock();

	/*
	 * Attach to an existing shared memory region or create it if it doesn't
	 * exists. When the it's created (ret=0) the region is initialized with
	 * zeroes.
	 */
	ret = sm_open(shm_id, 0666, (void**) &ptr, len, 1);
	if (ret < 0) {
		OCK_LOG_DEBUG("Failed to open shared memory \"%s\".\n", shm_id);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (created)
		*created = (ret == 0);

	*shm = ptr;
	slot_data[slot_id] = ptr + sizeof(**shm);

done:
	XProcUnLock();
	if (shm_id)
		free(shm_id);
	return rc;
}

CK_RV
login(LDAP **ld, CK_SLOT_ID slot_id, CK_BYTE *pin, CK_ULONG pin_len,
      const char *pass_file_type)
{
	CK_RV rc = CKR_OK;
	struct slot_data data;
	LDAP *ldapd = NULL;
	char *fname = NULL;
	int ret;

	/* Check Slot ID */
	if (slot_id < 0 || slot_id > MAX_SLOT_ID) {
		OCK_LOG_DEBUG("Invalid slot ID: %d\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	XProcLock();

	/* Check slot data */
	if (slot_data[slot_id] == NULL || !slot_data[slot_id]->initialized) {
		OCK_LOG_DEBUG("ICSF slot data not initialized.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	memcpy(&data, slot_data[slot_id], sizeof(data));

	XProcUnLock();

	if (*data.dn) {
		CK_BYTE mk[MAX_KEY_SIZE];
		CK_BYTE racf_pass[PIN_SIZE];
		int mk_len = sizeof(mk);
		int racf_pass_len = sizeof(racf_pass);
		CK_BYTE pk_dir_buf[PATH_MAX], fname[PATH_MAX];

		/* Load master key */
		sprintf(fname, "%s/MK_SO", get_pk_dir(pk_dir_buf));
		if (get_masterkey(pin, pin_len, fname, mk, &mk_len)) {
			OCK_LOG_DEBUG("Failed to load masterkey \"%s\".\n", fname);
			return CKR_FUNCTION_FAILED;
		}

		/* Load RACF password */
		if (get_racf(mk, mk_len, racf_pass, &racf_pass_len)) {
			OCK_LOG_DEBUG("Failed to get RACF password.\n");
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
		OCK_LOG_DEBUG("Failed to bind to %s\n", data.uri);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	if (icsf_check_pkcs_extension(ldapd)) {
		OCK_LOG_DEBUG("ICSF LDAP externsion not supported.\n");
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

CK_RV
reset_token_data(CK_SLOT_ID slot_id, CK_CHAR_PTR pin, CK_ULONG pin_len)
{
	CK_BYTE mk[MAX_KEY_SIZE];
	CK_BYTE racf_pass[PIN_SIZE];
	int mk_len = sizeof(mk);
	int racf_pass_len = sizeof(racf_pass);
	char token_name[sizeof(nv_token_data->token_info.label)];
	CK_BYTE pk_dir_buf[PATH_MAX], fname[PATH_MAX];

	/* Remove user's masterkey */
	sprintf(fname, "%s/MK_USER", get_pk_dir(pk_dir_buf));
	if (unlink(fname) && errno == ENOENT)
		OCK_LOG_DEBUG("Failed to remove \"%s\".\n", fname);

	/* Load master key */
	sprintf(fname, "%s/MK_SO", get_pk_dir(pk_dir_buf));
	if (get_masterkey(pin, pin_len, fname, mk, &mk_len)) {
		OCK_LOG_DEBUG("Failed to load masterkey \"%s\".\n", fname);
		return CKR_FUNCTION_FAILED;
	}

	/* Load RACF password */
	if (get_racf(mk, mk_len, racf_pass, &racf_pass_len)) {
		OCK_LOG_DEBUG("Failed to get RACF password.\n");
		return CKR_FUNCTION_FAILED;
	}

	/* Generate new key */
	if (get_randombytes(mk, mk_len)) {
		OCK_LOG_DEBUG("Failed to generate the new master key.\n");
		return CKR_FUNCTION_FAILED;
	}

	/* Save racf password using the new master key */
	if (secure_racf(racf_pass, racf_pass_len, mk, mk_len)) {
		OCK_LOG_DEBUG("Failed to save racf password.\n");
		return CKR_FUNCTION_FAILED;
	}

	/* Reset token data and keep token name */
	slot_data[slot_id]->initialized = 0;
	init_token_data(slot_id);
	init_slotInfo();
	nv_token_data->token_info.flags |= CKF_TOKEN_INITIALIZED;

	/* Reset SO pin to default and user pin to invalid */
	pin_len = strlen((pin = "87654321"));
	if (compute_sha(pin, pin_len, nv_token_data->so_pin_sha)) {
		OCK_LOG_DEBUG("Failed to reset so pin.\n");
		return CKR_FUNCTION_FAILED;
	}
	memset(nv_token_data->user_pin_sha, '0',
	       sizeof(nv_token_data->user_pin_sha));

	/* Save master key */
	if (secure_masterkey(mk, mk_len, pin, pin_len, fname)) {
		OCK_LOG_DEBUG("Failed to save the new master key.\n");
		return CKR_FUNCTION_FAILED;
	}

	if (save_token_data(slot_id)) {
		OCK_LOG_DEBUG("Failed to save token data.\n");
		return CKR_FUNCTION_FAILED;
	}

	return CKR_OK;
}

CK_RV
destroy_objects(CK_SLOT_ID slot_id, CK_CHAR_PTR token_name, CK_CHAR_PTR pin,
		CK_ULONG pin_len)
{
	CK_RV rc = CKR_OK;
	LDAP *ld = NULL;
	size_t object_num = 0;
	struct icsf_object_record records[16];
	struct icsf_object_record *previous = NULL;
	size_t i, records_len;

	if (login(&ld, slot_id, pin, pin_len, RACFFILE))
		return CKR_FUNCTION_FAILED;

	OCK_LOG_DEBUG("Destroying objects in slot %lu.\n", sid);
	do {
		records_len = sizeof(records)/sizeof(records[0]);

		if (icsf_list_objects(ld, token_name, previous, records,
				      &records_len, 0)) {
			OCK_LOG_DEBUG("Failed to list objects for slot %lu.\n",
				      sid);
			rc = CKR_FUNCTION_FAILED;
			goto done;
		}

		for (i = 0; i < records_len; i++) {
			if (icsf_destroy_object(ld, &records[i])) {
				OCK_LOG_DEBUG("Failed to destroy object "
					      "%s/%lu/%c in slot %lu.\n",
					      records[i].token_name,
					      records[i].sequence,
					      records[i].id, sid);
				rc = CKR_FUNCTION_FAILED;
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
CK_RV
token_specific_init_token(CK_SLOT_ID slot_id, CK_CHAR_PTR pin, CK_ULONG pin_len,
			  CK_CHAR_PTR label)
{
	CK_RV rc = CKR_OK;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];

	/* Check pin */
	rc = compute_sha(pin, pin_len, hash_sha);
	if (memcmp(nv_token_data->so_pin_sha, hash_sha, SHA1_HASH_SIZE) != 0) {
		OCK_LOG_ERR(ERR_PIN_INCORRECT);
		rc = CKR_PIN_INCORRECT;
		goto done;
	}

	if ((rc = reset_token_data(slot_id, pin, pin_len)))
		goto done;

	if ((rc = destroy_objects(slot_id, nv_token_data->token_info.label,
				  pin, pin_len)))
		goto done;

done:
	return rc;
}

CK_RV
token_specific_init_pin(SESSION *sess, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rc = CKR_OK;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	CK_SLOT_ID sid;
	CK_BYTE fname[PATH_MAX];
	char pk_dir_buf[PATH_MAX];

	/* get slot id */
	sid = sess->session_info.slotID;

	/* compute the SHA of the user pin */
	rc = compute_sha(pPin, ulPinLen, hash_sha);
	if (rc != CKR_OK) {
		OCK_LOG_ERR(ERR_HASH_COMPUTATION);
		return rc;
	}

	/* encrypt the masterkey and store in MK_USER if using SIMPLE AUTH
	 * to authenticate to ldao server. The masterkey protects the
	 * racf passwd.
	 */
	if (slot_data[sid]->dn[0]) { 
		sprintf(fname, "%s/MK_USER", get_pk_dir(pk_dir_buf));

		rc = secure_masterkey(master_key, AES_KEY_SIZE_256, pPin,
					ulPinLen, fname);
		if (rc != CKR_OK) {
			OCK_LOG_DEBUG("Could not create MK_USER.\n");
			return rc;
		}
	}

	rc = XProcLock();
	if (rc != CKR_OK) {
		OCK_LOG_ERR(ERR_PROCESS_LOCK);
		return rc;
	}
	memcpy(nv_token_data->user_pin_sha, hash_sha, SHA1_HASH_SIZE);
	nv_token_data->token_info.flags |= CKF_USER_PIN_INITIALIZED;
	nv_token_data->token_info.flags &= ~(CKF_USER_PIN_TO_BE_CHANGED);
	nv_token_data->token_info.flags &= ~(CKF_USER_PIN_LOCKED);
	XProcUnLock();

	return rc;
}

CK_RV
token_specific_set_pin(SESSION *sess, CK_CHAR_PTR pOldPin, CK_ULONG ulOldLen,
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

	rc = compute_sha(pNewPin, ulNewLen, new_hash_sha );
	rc |= compute_sha( pOldPin, ulOldLen, old_hash_sha );
	if (rc != CKR_OK) {
		OCK_LOG_ERR(ERR_HASH_COMPUTATION);
		return rc;
	}

	/* check that the old pin  and new pin are not the same. */
	if (memcmp(old_hash_sha, new_hash_sha, SHA1_HASH_SIZE) == 0) {
		OCK_LOG_ERR(ERR_PIN_INVALID);
		return CKR_PIN_INVALID;
	}

	/* check the length requirements */
	if ((ulNewLen < MIN_PIN_LEN) || (ulNewLen > MAX_PIN_LEN)) {
		OCK_LOG_ERR(ERR_PIN_LEN_RANGE);
		return CKR_PIN_LEN_RANGE;
	}

	if ((sess->session_info.state == CKS_RW_USER_FUNCTIONS) ||
	    (sess->session_info.state == CKS_RW_PUBLIC_SESSION)) {
		/* check that old pin matches what is in NVTOK.DAT */
		if (memcmp(nv_token_data->user_pin_sha, old_hash_sha, SHA1_HASH_SIZE) != 0) {
			OCK_LOG_ERR(ERR_PIN_INCORRECT);
			return CKR_PIN_INCORRECT;
		}
		/* if using simple auth, encrypt masterkey with new pin */
		if (slot_data[sid]->dn[0]) {
			sprintf (fname, "%s/MK_USER", get_pk_dir(pk_dir_buf));
			rc = secure_masterkey(master_key, AES_KEY_SIZE_256,
						pNewPin, ulNewLen, fname);
			if (rc != CKR_OK) {
				OCK_LOG_ERR(ERR_MASTER_KEY_SAVE);
				return rc;
			}
		}

		/* grab lock and change shared memory */
		rc = XProcLock();
		if (rc != CKR_OK) {
			OCK_LOG_ERR(ERR_PROCESS_LOCK);
			return rc;
		}
		memcpy(nv_token_data->user_pin_sha, new_hash_sha, SHA1_HASH_SIZE);
		nv_token_data->token_info.flags &= ~(CKF_USER_PIN_TO_BE_CHANGED);
		XProcUnLock();

	} else if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {

		/* check that old pin matches what is in NVTOK.DAT */
		if (memcmp(nv_token_data->so_pin_sha, old_hash_sha, SHA1_HASH_SIZE) != 0) {
			OCK_LOG_ERR(ERR_PIN_INCORRECT);
			return CKR_PIN_INCORRECT;
		}

		/* check that new pin is not the default */
		if (memcmp(new_hash_sha, default_so_pin_sha, SHA1_HASH_SIZE) == 0) {
			OCK_LOG_ERR(ERR_PIN_INVALID);
			return CKR_PIN_INVALID;
		}

		/* if using simle auth, encrypt masterkey with new pin */
		sprintf (fname, "%s/MK_SO", get_pk_dir(pk_dir_buf));
		rc = secure_masterkey(master_key, AES_KEY_SIZE_256, pNewPin,
					ulNewLen, fname);
		if (rc != CKR_OK) {
			OCK_LOG_ERR(ERR_MASTER_KEY_SAVE);
			return rc;
		}

		/* grab lock and change shared memory */
		rc = XProcLock();
		if (rc != CKR_OK) {
			OCK_LOG_ERR(ERR_PROCESS_LOCK);
			return rc;
		}
		memcpy(nv_token_data->so_pin_sha, new_hash_sha, SHA1_HASH_SIZE);
		nv_token_data->token_info.flags &= ~(CKF_SO_PIN_TO_BE_CHANGED);
		XProcUnLock();
	} else {
		OCK_LOG_ERR(ERR_SESSION_READ_ONLY);
		return CKR_SESSION_READ_ONLY;
	}

	rc = save_token_data(sid);
	if (rc != CKR_OK) {
		OCK_LOG_ERR(ERR_TOKEN_SAVE);
		return rc;
	}

	return rc;
}

CK_RV
token_specific_open_session(SESSION *sess)
{
	struct session_state *session_state;

	/* Add session to list */
	session_state = malloc(sizeof(struct session_state));
	if (!session_state) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		return CKR_FUNCTION_FAILED;
	}
	session_state->session_id = sess->handle;
	session_state->ld = NULL;
	memset(&session_state->objects, 0, sizeof(session_state->objects));
	list_insert_head(&sessions, &session_state->sessions);

	return CKR_OK;
}


CK_RV
token_specific_login(SESSION *sess, CK_USER_TYPE userType, CK_CHAR_PTR pPin,
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
		OCK_LOG_DEBUG("Invalid slot ID: %d\n", slot_id);
		return CKR_FUNCTION_FAILED;
	}

	/* compute the sha of the pin. */
	rc = compute_sha(pPin, ulPinLen, hash_sha);
	if (rc != CKR_OK) {
		OCK_LOG_ERR(ERR_HASH_COMPUTATION);
		return rc;
	}

	if (userType == CKU_USER) {
		/* check if pin initialized */
		if (memcmp(nv_token_data->user_pin_sha, "00000000000000000000", SHA1_HASH_SIZE) == 0) {
			OCK_LOG_ERR(ERR_USER_PIN_NOT_INITIALIZED);
			return CKR_USER_PIN_NOT_INITIALIZED;
		}

		/* check that pin is the same as the one in NVTOK.DAT */
		if (memcmp(nv_token_data->user_pin_sha, hash_sha, SHA1_HASH_SIZE) != 0) {
			OCK_LOG_ERR(ERR_PIN_INCORRECT);
			return CKR_PIN_INCORRECT;
		}

		/* now load the master key */
		sprintf(fname, "%s/MK_USER", get_pk_dir(pk_dir_buf));
		rc = get_masterkey(pPin, ulPinLen, fname, master_key, &mklen);
		if (rc != CKR_OK) {
			 OCK_LOG_DEBUG("Failed to load master key.\n");
			return rc;
		}

	} else {
		/* if SO ... */

		/* check that pin is the same as the one in NVTOK.DAT */
		if (memcmp(nv_token_data->so_pin_sha, hash_sha, SHA1_HASH_SIZE) != 0) {
			OCK_LOG_ERR(ERR_PIN_INCORRECT);
			return  CKR_PIN_INCORRECT;
		}

		/* now load the master key */
		sprintf(fname, "%s/MK_SO", get_pk_dir(pk_dir_buf));
		rc = get_masterkey(pPin, ulPinLen, fname, master_key, &mklen);
		if (rc != CKR_OK) {
			OCK_LOG_DEBUG("Failed to load master key.\n");
			return rc;
		}
	}

	/* The pPin looks good, so now lets authenticate to ldap server */
	XProcLock();

	if (slot_data[slot_id] == NULL) {
		OCK_LOG_DEBUG("ICSF slot data not initialized.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Check if using sasl or simple auth */
	if (slot_data[slot_id]->dn[0]) {
		OCK_LOG_DEBUG("Using SIMPLE auth with slot ID: %d\n", slot_id);

		/* get racf passwd */
		rc = get_racf(master_key, AES_KEY_SIZE_256, racfpwd, &racflen);
		if (rc != CKR_OK) {
			OCK_LOG_DEBUG("Failed to get racf passwd.\n");
			goto done;
		}

		/* ok got the passwd, perform simple ldap bind call */
		rc = icsf_login(&ld, slot_data[slot_id]->uri,
				slot_data[slot_id]->dn, racfpwd);
		if (rc != CKR_OK) {
			OCK_LOG_DEBUG("Failed to bind to ldap server.\n");
			goto done;
		}

	}
	else {
		OCK_LOG_DEBUG("Using SASL auth with slot ID: %d\n", slot_id);

		rc = icsf_sasl_login(&ld, slot_data[slot_id]->uri,
				     slot_data[slot_id]->cert_file,
				     slot_data[slot_id]->key_file,
				     slot_data[slot_id]->ca_file, ca_dir);
		if (rc != CKR_OK) {
			OCK_LOG_DEBUG("Failed to bind to ldap server.\n");
			goto done;
		}
	}

	/* Save LDAP handle */
	if (!(session_state = get_session_state(sess->handle))) {
		OCK_LOG_DEBUG("Session not found for session id %lu.\n",
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
	CK_ULONG i;

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
			OCK_LOG_ERR(ERR_USER_NOT_LOGGED_IN);
			rc = CKR_USER_NOT_LOGGED_IN;
			goto done;
		}
		if (is_token_obj) {
			OCK_LOG_ERR(ERR_SESSION_READ_ONLY);
			rc = CKR_SESSION_READ_ONLY;
			goto done;
		}
	}

	if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
		if (is_token_obj) {
			OCK_LOG_ERR(ERR_SESSION_READ_ONLY);
			rc = CKR_SESSION_READ_ONLY;
			goto done;
		}
	}

	if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
		if (is_priv_obj) {
			OCK_LOG_ERR(ERR_USER_NOT_LOGGED_IN);
			rc = CKR_USER_NOT_LOGGED_IN;
			goto done;
		}
	}

	if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
		if (is_priv_obj) {
			OCK_LOG_ERR(ERR_USER_NOT_LOGGED_IN);
			rc = CKR_USER_NOT_LOGGED_IN;
			goto done;
		}
	}

done:
	return rc;
}

/*
 * Generate a symmetric key.
 */
CK_RV
token_specific_generate_key(SESSION *sess, CK_MECHANISM_PTR mech,
			    CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
			    CK_OBJECT_HANDLE_PTR handle)
{
	CK_RV rc = CKR_OK;
	struct session_state *session_state;
	struct session_object *session_object;
	struct icsf_object_record *object;
	CK_ULONG node_number;

	/* Check permissions based on attributes and session */
	rc = check_session_permissions(sess, attrs, attrs_len);
	if (rc != CKR_OK)
		return rc;

	/* Allocate structure to keep ICSF object information */
	if (!(object = malloc(sizeof(*object)))) {
		OCK_LOG_ERR(ERR_HOST_MEMORY);
		return CKR_HOST_MEMORY;
	}

	XProcLock();

	/* Get session state */
	if (!(session_state = get_session_state(sess->handle))) {
		OCK_LOG_DEBUG("Session not found for session id %lu.\n",
				(unsigned long) sess->handle);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Call ICSF service */
	if (icsf_generate_secret_key(session_state->ld,
				     nv_token_data->token_info.label,
				     mech, attrs, attrs_len, object)) {
		OCK_LOG_DEBUG("Failed to call ICSF.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Add info about object into session */
	if(!(node_number = bt_node_add(&session_state->objects, object))) {
		OCK_LOG_DEBUG("Failed to add object to binary tree.\n");
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	/* Use node number as handle */
	*handle = node_number;

done:
	XProcUnLock();

	/* If allocated, object must be freed in case of failure */
	if (rc && !object)
		free(object);

	return rc;
}
