
/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/*
 * tpm_specific.c
 *
 * Feb 10, 2005
 *
 * Author: Kent Yoder <yoder1@us.ibm.com>
 *
 * Encryption routines are based on ../soft_stdll/soft_specific.c.
 *
 */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/evp.h>

#include <tss/tss.h>
#include <tss/trousers.h>

#include "pkcs11/pkcs11types.h"
#include "pkcs11/stdll.h"
#include "defs.h"
#include "host_defs.h"
#include "args.h"
#include "h_extern.h"
#include "tok_specific.h"
#include "tok_spec_struct.h"
#include "tok_struct.h"

#include "tpm_specific.h"

CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "TPM Token";
CK_CHAR descr[] = "Token for the Trusted Platform Module";
CK_CHAR label[] = "IBM PKCS#11 TPM Token";

/* The context we'll use globally to connect to the TSP */
TSS_HCONTEXT tspContext = NULL_HCONTEXT;
/* TSP key handles */
TSS_HKEY hSRK = NULL_HKEY;
TSS_HKEY hRootKey = NULL_HKEY;
TSS_HKEY hPubRootKey = NULL_HKEY;
TSS_HKEY hMigRootKey = NULL_HKEY;
TSS_HKEY hMigLeafKey = NULL_HKEY;
TSS_HKEY hUserBaseKey = NULL_HKEY;
TSS_HKEY hUserLeafKey = NULL_HKEY;

/* PKCS#11 key handles */
CK_OBJECT_HANDLE ckRootKey = 0;
CK_OBJECT_HANDLE ckMigRootKey = 0;
CK_OBJECT_HANDLE ckMigLeafKey = 0;
CK_OBJECT_HANDLE ckMigAsymKey = 0;
CK_OBJECT_HANDLE ckUserBaseKey = 0;
CK_OBJECT_HANDLE ckUserLeafKey = 0;
CK_OBJECT_HANDLE ckPubRootKey = 0;
CK_OBJECT_HANDLE ckAESKey = 0;

/* since logging in is such an intensive process, set a flag on logout,
 * so that we only have to load 1 key on a re-login
 */
int relogging_in = 0;
int not_initialized = 0;

CK_BYTE *TPMTOK_USERNAME = NULL;

/* SHA-1 of "12345678" */
CK_BYTE default_user_pin_sha[SHA1_HASH_SIZE] = {
	0x7c, 0x22, 0x2f, 0xb2, 0x92, 0x7d, 0x82, 0x8a,
	0xf2, 0x2f, 0x59, 0x21, 0x34, 0xe8, 0x93, 0x24,
	0x80, 0x63, 0x7c, 0x0d
};


CK_RV
token_specific_session(CK_SLOT_ID  slotid)
{
	return CKR_OK;
}

CK_RV
token_rng(CK_BYTE *output, CK_ULONG bytes)
{
        TSS_RESULT rc;
        TSS_HTPM hTPM;
        BYTE *random_bytes = NULL;

        rc = Tspi_Context_GetTpmObject(tspContext, &hTPM);
        if (rc != TSS_SUCCESS) {
                LogError("Tspi_Context_GetTpmObject: %x", rc);
                return CKR_FUNCTION_FAILED;
        }

        rc = Tspi_TPM_GetRandom(hTPM, bytes, &random_bytes);
        if (rc != TSS_SUCCESS) {
                st_err_log("CKR_FUNCTION_FAILED");
                return CKR_FUNCTION_FAILED;
        }

        memcpy(output, random_bytes, bytes);
        Tspi_Context_FreeMemory(tspContext, random_bytes);

        return CKR_OK;
}

// convert pkcs slot number to local representation
int
tok_slot2local(CK_SLOT_ID snum)
{
	return 1;
}


CK_RV
token_specific_init(char *Correlator, CK_SLOT_ID SlotNumber)
{
	TSS_RESULT result;

	result = Tspi_Context_Create(&tspContext);
	if (result != TSS_SUCCESS) {
                st_err_log("CKR_FUNCTION_FAILED");
                return CKR_FUNCTION_FAILED;
	}

	result = Tspi_Context_Connect(tspContext, NULL);
        if (result != TSS_SUCCESS) {
                LogError("Tspi_Context_Connect: %x", result);
                return CKR_FUNCTION_FAILED;
        }

	OpenSSL_add_all_algorithms();

	return CKR_OK;
}

CK_RV
token_find_key(int key_type, CK_OBJECT_HANDLE *handle)
{
	CK_BYTE *key_id = util_create_id(key_type);
	CK_RV rc = CKR_OK;
	CK_KEY_TYPE type = CKK_RSA;
	CK_OBJECT_CLASS priv_class = CKO_PRIVATE_KEY;
	CK_BBOOL true = TRUE;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_ID, key_id, strlen(key_id)},
		{CKA_CLASS, &priv_class, sizeof(priv_class)},
		{CKA_HIDDEN, &true, sizeof(CK_BBOOL)}
	};
	CK_OBJECT_HANDLE hObj;
	CK_ULONG ulObjCount;
	SESSION dummy_sess;

	/* init the dummy session state to something that will find any object on
	 * the token */
	memset(&dummy_sess, 0, sizeof(SESSION));
	dummy_sess.session_info.state = CKS_RO_USER_FUNCTIONS;

	rc = object_mgr_find_init(&dummy_sess, tmpl, 4);
	if (rc != CKR_OK) {
		goto done;
	}

	/* pulled from SC_FindObjects */
	ulObjCount = MIN(1, (dummy_sess.find_count - dummy_sess.find_idx));
	memcpy( &hObj, dummy_sess.find_list + dummy_sess.find_idx, ulObjCount * sizeof(CK_OBJECT_HANDLE) );
	dummy_sess.find_idx += ulObjCount;

	/* there should be 2 keys with this ID, the public and private. All we care about is
	 * the private, since the blob is in there */
	if (ulObjCount > 1) {
		LogError1("More than one matching key found in the store!");
		rc = CKR_KEY_NOT_FOUND;
		goto done;
	} else if (ulObjCount < 1) {
		LogError1("key not found in the store!");
		rc = CKR_KEY_NOT_FOUND;
		goto done;
	}

	*handle = hObj;
done:
	object_mgr_find_final(&dummy_sess);
	free(key_id);
	return rc;
}

CK_RV
token_get_key_blob(CK_OBJECT_HANDLE ckKey, CK_BYTE **ret_blob, CK_ULONG *blob_size)
{
	CK_RV rc = CKR_OK;
	CK_BYTE_PTR blob = NULL;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_KEY_BLOB, NULL_PTR, 0}
	};
	SESSION dummy_sess;

	/* set up dummy session */
	memset(&dummy_sess, 0, sizeof(SESSION));
	dummy_sess.session_info.state = CKS_RO_USER_FUNCTIONS;

	/* find object the first time to return the size of the buffer needed */
	rc = object_mgr_get_attribute_values(&dummy_sess, ckKey, tmpl, 1);
	if (rc != CKR_OK) {
		st_err_log("SC_GetAttributeValue");
		goto done;
	}

	blob = malloc(tmpl[0].ulValueLen);
	if (blob == NULL) {
		st_err_log("CKR_HOST_MEMORY");
		rc = CKR_HOST_MEMORY;
		goto done;
	}

	tmpl[0].pValue = blob;
	/* find object the 2nd time to fill the buffer with data */
	rc = object_mgr_get_attribute_values(&dummy_sess, ckKey, tmpl, 1);
	if (rc != CKR_OK) {
		st_err_log("SC_GetAttributeValue");
		goto done;
	}

	*ret_blob = blob;
	*blob_size = tmpl[0].ulValueLen;
done:
	return rc;
}

/*
 * load a key in the TSS hierarchy from its CK_OBJECT_HANDLE
 */
CK_RV
token_load_key(CK_OBJECT_HANDLE ckKey, TSS_HKEY hParentKey, CK_CHAR_PTR passHash, TSS_HKEY *hKey)
{
	TSS_RESULT result;
	TSS_HPOLICY hPolicy;
	CK_BYTE *blob;
	CK_ULONG ulBlobSize;
	CK_RV rc;

	rc = token_get_key_blob(ckKey, &blob, &ulBlobSize);
	if (rc != CKR_OK) {
		return rc;
	}

	/* load the key inside the TSS */
	result = Tspi_Context_LoadKeyByBlob(tspContext, hParentKey, ulBlobSize,
					    blob, hKey);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Context_LoadKeyByBlob: 0x%x", result);
		goto done;
	}

	result = Tspi_GetPolicyObject(*hKey, TSS_POLICY_USAGE, &hPolicy);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_GetPolicyObject: 0x%x", result);
		goto done;
	}

	if (passHash == NULL) {
		result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_NONE, 0, NULL);
	} else {
		result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1, 20, passHash);
	}
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Policy_SetSecret: 0x%x", result);
		goto done;
	}
done:
	free(blob);
	return result;
}

TSS_RESULT
token_load_srk()
{
	TSS_HPOLICY hPolicy;
	TSS_RESULT result;

	if (hSRK != NULL_HKEY)
		return TSS_SUCCESS;

	/* load the SRK */
	result = Tspi_Context_LoadKeyByUUID(tspContext, TSS_PS_TYPE_SYSTEM, SRK_UUID,
						&hSRK);
	if (result != TSS_SUCCESS) {
		st_err_log("Tspi_Context_LoadKeyByUUID");
		goto done;
	}

	result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hPolicy);
	if (result != TSS_SUCCESS) {
		st_err_log("Tspi_GetPolicyObject");
		goto done;
	}

	result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_PLAIN, 0, NULL);
	if (result != TSS_SUCCESS) {
		st_err_log("Tspi_Policy_SetSecret");
	}
done:
	return result;
}

TSS_RESULT
token_load_prk()
{
	TSS_RESULT result;
	CK_OBJECT_HANDLE ckPubRootKey;
	BYTE *blob;
	CK_ULONG blob_size;

	if (hPubRootKey != NULL_HKEY)
		return TSS_SUCCESS;

	if ((result = token_load_srk())) {
		LogError("token_load_srk failed. rc=0x%x", result);
		return result;
	}

	if ((result = token_find_key(TPMTOK_PUB_ROOT_KEY, &ckPubRootKey))) {
		LogError("token_find_key failed. rc=0x%x", result);
		return CKR_FUNCTION_FAILED;
	}

	if ((result = token_get_key_blob(ckPubRootKey, &blob, &blob_size))) {
		LogError("token_get_key_blob failed. rc=0x%x", result);
		return CKR_FUNCTION_FAILED;
	}

	/* load the PRK */
	result = Tspi_Context_LoadKeyByBlob(tspContext, hSRK, blob_size, blob, &hPubRootKey);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Context_LoadKeyByUUID failed. rc=0x%x", result);
		free(blob);
		return CKR_FUNCTION_FAILED;
	}
	free(blob);

	return result;
}

TSS_RESULT
tss_generate_key(TSS_FLAGS initFlags, BYTE *passHash, TSS_HKEY hParentKey, TSS_HKEY *phKey)
{
	TSS_RESULT result;
	TSS_HPOLICY hPolicy;

	result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_RSAKEY, initFlags, phKey);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Context_CreateObject failed with rc: %x", result);
		return result;
	}

	result = Tspi_GetPolicyObject(*phKey, TSS_POLICY_USAGE, &hPolicy);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_GetPolicyObject failed with rc: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
		return result;
	}

	if (passHash == NULL) {
		result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_NONE, 0, NULL);
	} else {
		result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1, 20, passHash);
	}
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Policy_SetSecret failed with rc: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
		return result;
	}

	result = Tspi_Key_CreateKey(*phKey, hParentKey, 0);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Key_CreateKey failed with rc: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
	}

	return result;
}

TSS_RESULT
tss_get_key_blob(TSS_HKEY hKey, UINT32 *ulBlobLen,  BYTE **rgbBlob)
{
	TSS_RESULT result;

	if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
				ulBlobLen, rgbBlob) != TSS_SUCCESS)) {
		LogError("Tspi_GetAttribData failed with rc: 0x%x", result);
	}

	return result;
}

TSS_RESULT
tss_change_auth(TSS_HKEY hObjectToChange, TSS_HKEY hParentObject, CK_CHAR *passHash)
{
	TSS_RESULT result;
	TSS_HPOLICY hPolicy;

	result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_POLICY,
						TSS_POLICY_USAGE, &hPolicy);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Context_CreateObject failed: 0x%x", result);
		return result;
	}

	result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1, SHA1_HASH_SIZE, passHash);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Policy_SetSecret failed: 0x%x", result);
		return result;
	}

	result = Tspi_ChangeAuth(hObjectToChange, hParentObject, hPolicy);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_ChangeAuth failed: 0x%x", result);
	}

	return result;
}

CK_RV
token_store_priv_key(TSS_HKEY hKey, int key_type, CK_OBJECT_HANDLE *ckKey)
{
	CK_ATTRIBUTE *priv_tmpl_init = NULL;
	CK_ATTRIBUTE *new_attr = NULL;
	OBJECT *priv_key_obj = NULL;
	BYTE *rgbBlob = NULL;
	UINT32 ulBlobLen = 0;
	CK_BBOOL flag;
	CK_BYTE *key_id = util_create_id(key_type);
	CK_RV rc;
	SESSION dummy_sess;

	/* set up dummy session */
	memset(&dummy_sess, 0, sizeof(SESSION));
	dummy_sess.session_info.state = CKS_RW_USER_FUNCTIONS;

	/* grab the entire key blob to put into the PKCS#11 private key object */
	rc = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_BLOB,
					&ulBlobLen, &rgbBlob);
	if (rc != TSS_SUCCESS) {
		LogError("Tspi_GetAttribData failed with rc: 0x%x", rc);
		free(key_id);
		return rc;
	}

	/* create skeleton for the private key object */
	rc = object_create_skel(priv_tmpl_init, 0, MODE_KEYGEN,	CKO_PRIVATE_KEY, CKK_RSA, &priv_key_obj);
	if (rc != CKR_OK) {
		LogError("object_mgr_create_skel: 0x%x", rc);
		free(key_id);
		return rc;
	}

	/* add the ID attribute */
	rc = build_attribute(CKA_ID, key_id, strlen(key_id), &new_attr);
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		free(key_id);
		return rc;
	}
	template_update_attribute( priv_key_obj->template, new_attr );
	free(key_id);

	/* add the HIDDEN attribute */
	flag = TRUE;
	rc = build_attribute(CKA_HIDDEN, &flag, sizeof(CK_BBOOL), &new_attr);
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		free(key_id);
		return rc;
	}
	template_update_attribute( priv_key_obj->template, new_attr );

	/* add the key blob to the PKCS#11 object template */
	rc = build_attribute(CKA_KEY_BLOB, rgbBlob, ulBlobLen, &new_attr);
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		return rc;
	}
	template_update_attribute( priv_key_obj->template, new_attr );

	/*  set CKA_ALWAYS_SENSITIVE to true */
	rc = build_attribute( CKA_ALWAYS_SENSITIVE, &flag, sizeof(CK_BBOOL), &new_attr );
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		return rc;
	}
	template_update_attribute( priv_key_obj->template, new_attr );

	/*  set CKA_NEVER_EXTRACTABLE to true */
	rc = build_attribute( CKA_NEVER_EXTRACTABLE, &flag, sizeof(CK_BBOOL), &new_attr );
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		return rc;
	}
	template_update_attribute( priv_key_obj->template, new_attr );

	/* make the object reside on the token, as if that were possible */
	rc = build_attribute( CKA_TOKEN, &flag, sizeof(CK_BBOOL), &new_attr );
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		return rc;
	}
	template_update_attribute( priv_key_obj->template, new_attr );

	/* make the object public, since the SO only has access to public token objects */
	flag = FALSE;
	rc = build_attribute( CKA_PRIVATE, &flag, sizeof(CK_BBOOL), &new_attr );
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		return rc;
	}
	template_update_attribute( priv_key_obj->template, new_attr );

	rc = object_mgr_create_final(&dummy_sess, priv_key_obj, ckKey);
	if (rc != CKR_OK){
		st_err_log(90, __FILE__, __LINE__);
	}

	return rc;
}

CK_RV
token_store_pub_key(TSS_HKEY hKey, int key_type, CK_OBJECT_HANDLE *ckKey)
{
	CK_RV rc;
	TSS_RESULT result;
	CK_ATTRIBUTE *new_attr = NULL;
	OBJECT *pub_key_obj;
	CK_BBOOL flag = TRUE;
	CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE type = CKK_RSA;
	CK_BYTE *key_id = util_create_id(key_type);
	CK_BYTE pub_exp[] = { 0x1, 0x0, 0x1 }; // 65537
	CK_ATTRIBUTE pub_tmpl[] = {
		{CKA_CLASS, &pub_class, sizeof(pub_class)},
		{CKA_KEY_TYPE, &type, sizeof(type)},
		{CKA_ID, key_id, strlen(key_id)},
		{CKA_PUBLIC_EXPONENT, pub_exp, sizeof(pub_exp)},
		{CKA_MODULUS, NULL_PTR, 0}
	};
	BYTE *rgbPubBlob = NULL;
	UINT32 ulBlobLen = 0;
	SESSION dummy_sess;

	/* set up dummy session */
	memset(&dummy_sess, 0, sizeof(SESSION));
	dummy_sess.session_info.state = CKS_RW_USER_FUNCTIONS;

	/* grab the public key  to put into the PKCS#11 public key object */
	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
					&ulBlobLen, &rgbPubBlob);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_GetAttribData failed with rc: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, hKey);
		free(key_id);
		return result;
	}

	pub_tmpl[4].pValue = rgbPubBlob;
	pub_tmpl[4].ulValueLen = ulBlobLen;

	/* create skeleton for the private key object */
	rc = object_create_skel(pub_tmpl, 5, MODE_CREATE, CKO_PUBLIC_KEY, CKK_RSA, &pub_key_obj);
	if (rc != CKR_OK) {
		LogError("object_mgr_create_skel: 0x%x", rc);
		Tspi_Context_CloseObject(tspContext, hKey);
		Tspi_Context_FreeMemory(tspContext, rgbPubBlob);
		free(key_id);
		return rc;
	}

	/* make the object reside on the token, as if that were possible */
	rc = build_attribute( CKA_TOKEN, &flag, sizeof(CK_BBOOL), &new_attr );
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		goto done;
	}
	template_update_attribute( pub_key_obj->template, new_attr );

	/* set the object to be hidden */
	rc = build_attribute( CKA_HIDDEN, &flag, sizeof(CK_BBOOL), &new_attr );
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		goto done;
	}
	template_update_attribute( pub_key_obj->template, new_attr );

	rc = object_mgr_create_final(&dummy_sess, pub_key_obj, ckKey);
	if (rc != CKR_OK){
		st_err_log(90, __FILE__, __LINE__);
		goto done;
	}

done:
	return rc;
}

CK_RV
token_update_private_key(TSS_HKEY hKey, int key_type)
{
	CK_OBJECT_HANDLE ckHandle;
	CK_RV rc;
	SESSION dummy_sess;

	/* set up dummy session */
	memset(&dummy_sess, 0, sizeof(SESSION));
	dummy_sess.session_info.state = CKS_RW_USER_FUNCTIONS;

	/* find the private key portion of the key */
	if ((rc = token_find_key(key_type, &ckHandle))) {
		LogError("token_find_key failed: 0x%x", rc);
		return rc;
	}

	/* destroy the private key and create a new one */
	if ((rc = object_mgr_destroy_object(&dummy_sess, ckHandle))) {
		LogError("object_mgr_destroy_object failed: 0x%x", rc);
		return rc;
	}

	if ((rc = token_store_priv_key(hKey, key_type, &ckHandle))) {
		LogError("token_store_priv_key failed: 0x%x", rc);
	}

	return rc;
}

CK_RV
token_store_tss_key(TSS_HKEY hKey, int key_type, CK_OBJECT_HANDLE *ckKey)
{
	CK_RV rc;

	/* create a PKCS#11 pub key object for the key */
	rc = token_store_pub_key(hKey, key_type, ckKey);
	if (rc != CKR_OK) {
		st_err_log("token_store_pub_key");
		return rc;
	}

	/* create a PKCS#11 private key object for the key */
	rc = token_store_priv_key(hKey, key_type, ckKey);
	if (rc != CKR_OK) {
		st_err_log("token_store_pub_key");
	}

	return rc;
}

CK_RV
token_generate_key(TSS_FLAGS initFlags, int key_type, CK_CHAR_PTR passHash, TSS_HKEY *phKey)
{
	CK_RV rc = CKR_FUNCTION_FAILED;
	TSS_RESULT result;
	TSS_HKEY hParentKey;
	CK_OBJECT_HANDLE *ckKey;

	switch (key_type) {
		case TPMTOK_MIG_LEAF_KEY:
			initFlags |= TSS_KEY_MIGRATABLE | TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048
				  | TSS_KEY_AUTHORIZATION;
			hParentKey = hMigRootKey;
			ckKey = &ckMigRootKey;
			break;
		case TPMTOK_USER_BASE_KEY:
			initFlags |= TSS_KEY_MIGRATABLE | TSS_KEY_TYPE_STORAGE;
			hParentKey = hRootKey;
			ckKey = &ckRootKey;
			break;
		case TPMTOK_USER_LEAF_KEY:
			initFlags |= TSS_KEY_MIGRATABLE | TSS_KEY_TYPE_BIND | TSS_KEY_SIZE_2048
				  | TSS_KEY_AUTHORIZATION;
			hParentKey = hUserBaseKey;
			ckKey = &ckUserBaseKey;
			break;
		case TPMTOK_USER_KEY:
			initFlags |= TSS_KEY_MIGRATABLE | TSS_KEY_AUTHORIZATION;
			hParentKey = hUserBaseKey;
			break;
		case TPMTOK_SO_KEY:
			initFlags |= TSS_KEY_MIGRATABLE | TSS_KEY_AUTHORIZATION;
			hParentKey = hMigRootKey;
			break;
		default:
			LogError1("Oh NO");
			goto done;
			break;
	}

	result = tss_generate_key(initFlags, passHash, hParentKey, phKey);
	if (result != TSS_SUCCESS) {
		LogError("tss_generate_key returned 0x%x", result);
		return result;
	}

	rc = token_store_tss_key(*phKey, key_type, ckKey);
	if (rc != CKR_OK) {
		st_err_log("token_store_tss_key");
	}

done:
	return rc;
}

CK_RV
token_generate_sw_key(char *filename, CK_BYTE *pPin, TSS_HKEY hParentKey, TSS_HKEY *phKey)
{
	RSA *rsa = NULL;
        unsigned char n[256], p[256];
        unsigned char null_auth[SHA1_HASH_SIZE];
        unsigned char priv_key[214]; /* its not magic, see TPM 1.1b spec p.71 */
        unsigned char enc_priv_key[214]; /* its not magic, see TPM 1.1b spec p.71 */
        int size_n, size_p, priv_key_len;
        UINT16 offset = 0, dig_offset = 0;
        TSS_RESULT result;
        BYTE blob_for_digest[1024], *blob;
        UINT32 blob_size;
        TCPA_DIGEST digest;
        TCPA_KEY key;

	/* all sw generated keys are 2048 bits */
	if ((rsa = openssl_gen_key()) == NULL)
		return CKR_HOST_MEMORY;

	memset(null_auth, 0, SHA1_HASH_SIZE);

	/* set up the private key structure */
	Trspi_LoadBlob_BYTE(&offset, TCPA_PT_ASYM, priv_key);
	Trspi_LoadBlob(&offset, SHA1_HASH_SIZE, priv_key, null_auth);
	Trspi_LoadBlob(&offset, SHA1_HASH_SIZE, priv_key, null_auth);

	/* create the TSS key object */
	result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_RSAKEY,
			TSS_KEY_SIZE_2048 | TSS_KEY_TYPE_STORAGE | TSS_KEY_MIGRATABLE |
			TSS_KEY_NO_AUTHORIZATION, phKey);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Context_CreateObject: 0x%x", result);
		return CKR_FUNCTION_FAILED;
	}

	if (openssl_get_modulus_and_prime(rsa, &size_n, n, &size_p, p) != 0) {
		Tspi_Context_CloseObject(tspContext, *phKey);
		*phKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	/* set the public key data in the TSS object */
	result = Tspi_SetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB,
			TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, size_n, n);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_SetAttribData: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
		*phKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	/* get the object's blob so that we can create a digest of the structure to
	 * stick inside the private key structure. */
	result = Tspi_GetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB,
			TSS_TSPATTRIB_KEYBLOB_BLOB, &blob_size, &blob);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_GetAttribData: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
		*phKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	/* unload the blob returned by the TSS, then load up one to create the
	 * private key's digest with. */
	if ((result = Trspi_UnloadBlob_KEY(tspContext, &dig_offset, blob, &key)) != TSS_SUCCESS) {
		LogError("Trspi_UnloadBlob_KEY: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
		*phKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}
	dig_offset = 0;
	Trspi_LoadBlob_PRIVKEY_DIGEST(&dig_offset, blob_for_digest, &key);

	result = Tspi_Context_FreeMemory(tspContext, blob);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Context_FreeMemory: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
		*phKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	/* blob_for_digest now has the correct data in it, create the digest */
	Trspi_Hash(TSS_HASH_SHA1, dig_offset, blob_for_digest, &digest.digest);

	/* load the digest of the TCPA_KEY structure */
	Trspi_LoadBlob(&offset, SHA1_HASH_SIZE, priv_key, &digest.digest);
	/* load the TCPA_STORE_PRIVKEY structure */
	Trspi_LoadBlob_UINT32(&offset, size_p, priv_key);
	Trspi_LoadBlob(&offset, size_p, priv_key, p);
	priv_key_len = offset;

	/* Now encrypt the private parts of this key with the SRK's public key */

	/* reuse blob here in getting the parent's public key */
	result = Tspi_GetAttribData(hParentKey, TSS_TSPATTRIB_KEY_BLOB,
			TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY, &blob_size, &blob);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_GetAttribData: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
		*phKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	if (Trspi_RSA_Encrypt(priv_key, priv_key_len, enc_priv_key, &priv_key_len,
				blob, blob_size)) {
		LogError("Tspi_Context_FreeMemory: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
		Tspi_Context_FreeMemory(tspContext, blob);
		*phKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	result = Tspi_Context_FreeMemory(tspContext, blob);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Context_FreeMemory: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
		*phKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	result = Tspi_SetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB,
			TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY, priv_key_len, enc_priv_key);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_SetAttribData: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, *phKey);
		*phKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	if (openssl_write_key(rsa, filename, pPin)) {
		LogError1("openssl_write_key");
		Tspi_Context_CloseObject(tspContext, *phKey);
		*phKey = NULL_HKEY;
		RSA_free(rsa);
		return CKR_FUNCTION_FAILED;
	}

	RSA_free(rsa);

	return CKR_OK;
}

CK_RV
token_verify_pin(TSS_HKEY hKey)
{
	TSS_HENCDATA hEncData;
	UINT32 ulUnboundDataLen;
	BYTE *rgbData = "CRAPPENFEST", *rgbUnboundData;
	TSS_RESULT result;
	CK_RV rc = CKR_FUNCTION_FAILED;

	result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_ENCDATA,
					   TSS_ENCDATA_BIND, &hEncData);
	if (result != TSS_SUCCESS) {
		st_err_log("Tspi_Context_CreateObject");
		goto done;
	}

	result = Tspi_Data_Bind(hEncData, hKey, strlen(rgbData), rgbData);
	if (result != TSS_SUCCESS) {
		LogError("%s: Bind returned 0x%x", __FUNCTION__, result);
		goto done;
	}

	/* unbind the junk data to test the key's auth data */
	result = Tspi_Data_Unbind(hEncData, hKey, &ulUnboundDataLen, &rgbUnboundData);
	if (result == TCPA_AUTHFAIL) {
		rc = CKR_PIN_INCORRECT;
		LogError("%s: Unbind returned TCPA_AUTHFAIL", __FUNCTION__);
		goto done;
	} else if (result != TSS_SUCCESS) {
		LogError("%s: Unbind returned 0x%x", __FUNCTION__, result);
		goto done;
	}

	rc = memcmp(rgbUnboundData, rgbData, ulUnboundDataLen);

	Tspi_Context_FreeMemory(tspContext, rgbUnboundData);
done:
	Tspi_Context_CloseObject(tspContext, hEncData);
	return rc;
}

CK_RV
token_create_user_tree(CK_BYTE *pinHash, CK_BYTE *pPin)
{
	CK_RV rc;
	char loc[80];
	TSS_RESULT result;

	/* XXX Make the user's directory to store token data in. This should eventually
	 * be tied to pluggable object storage routines */
	sprintf(loc, "%s/%s/%s", token_specific.token_directory, PK_LITE_OBJ_DIR, TPMTOK_USERNAME);

	if (util_create_user_dir(loc)) {
		LogError("%s: util_create_user_dir failed.", __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	/* XXX this is bad form */
	sprintf(loc, TPMTOK_USER_BASE_KEY_BACKUP_LOCATION, TPMTOK_USERNAME, TPMTOK_USERNAME);

	/* generate the software based user base key */
	rc = token_generate_sw_key(loc, pPin, hRootKey, &hUserBaseKey);
	if (rc != CKR_OK) {
		st_err_log("token_generate_sw_key");
		return rc;
	}

	/* store the user base key in a PKCS#11 object internally */
	rc = token_store_tss_key(hUserBaseKey, TPMTOK_USER_BASE_KEY, &ckUserBaseKey);
	if (rc != CKR_OK) {
		st_err_log("token_store_tss_key");
		return rc;
	}

	result = Tspi_Key_LoadKey(hUserBaseKey, hRootKey);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Key_LoadKey: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, hUserBaseKey);
		hUserBaseKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	/* generate the TPM user leaf key */
	rc = token_generate_key(0, TPMTOK_USER_LEAF_KEY, pinHash, &hUserLeafKey);
	if (rc != CKR_OK) {
		st_err_log("token_generate_key");
		return rc;
	}

	result = Tspi_Key_LoadKey(hUserLeafKey, hUserBaseKey);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Key_LoadKey: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, hUserBaseKey);
		hUserBaseKey = NULL_HKEY;
		Tspi_Context_CloseObject(tspContext, hUserLeafKey);
		hUserBaseKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	return rc;
}

CK_RV
token_create_so_tree(CK_BYTE *pinHash, CK_BYTE *pPin)
{
	CK_RV rc;
	TSS_RESULT result;

	/* create the public root key */
	rc = token_generate_sw_key(TPMTOK_PUB_ROOT_KEY_BACKUP_LOCATION, pPin, hSRK, &hPubRootKey);
	if (rc != CKR_OK) {
		LogError("token_generate_sw_key(hPubRootKey)");
		return rc;
	}

	result = Tspi_Key_LoadKey(hPubRootKey, hSRK);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Key_LoadKey: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, hPubRootKey);
		hPubRootKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	rc = token_store_tss_key(hPubRootKey, TPMTOK_PUB_ROOT_KEY, &ckPubRootKey);
	if (rc != CKR_OK) {
		st_err_log("token_store_tss_key");
		return rc;
	}

	/* create the user root key */
	rc = token_generate_sw_key(TPMTOK_ROOT_KEY_BACKUP_LOCATION, pPin, hSRK, &hRootKey);
	if (rc != CKR_OK) {
		st_err_log("token_generate_sw_key");
		return rc;
	}

	result = Tspi_Key_LoadKey(hRootKey, hSRK);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Key_LoadKey: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, hRootKey);
		hRootKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	rc = token_store_tss_key(hRootKey, TPMTOK_ROOT_KEY, &ckRootKey);
	if (rc != CKR_OK) {
		st_err_log("token_store_tss_key");
		return rc;
	}

	/* create the migratable root key */
	rc = token_generate_sw_key(TPMTOK_MIG_ROOT_KEY_BACKUP_LOCATION, pPin, hSRK, &hMigRootKey);
	if (rc != CKR_OK) {
		st_err_log("token_generate_sw_key");
		return rc;
	}

	result = Tspi_Key_LoadKey(hMigRootKey, hSRK);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Key_LoadKey: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, hRootKey);
		hRootKey = NULL_HKEY;
		Tspi_Context_CloseObject(tspContext, hMigRootKey);
		hMigRootKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	rc = token_store_tss_key(hMigRootKey, TPMTOK_MIG_ROOT_KEY, &ckMigRootKey);
	if (rc != CKR_OK) {
		st_err_log("token_store_tss_key");
		return rc;
	}

	/* create the SO's leaf key */
	rc = token_generate_key(0, TPMTOK_MIG_LEAF_KEY, pinHash, &hMigLeafKey);
	if (rc != CKR_OK) {
		st_err_log("token_generate_key");
		return rc;
	}

	result = Tspi_Key_LoadKey(hMigLeafKey, hMigRootKey);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_Key_LoadKey: 0x%x", result);
		Tspi_Context_CloseObject(tspContext, hRootKey);
		hRootKey = NULL_HKEY;
		Tspi_Context_CloseObject(tspContext, hMigRootKey);
		hMigRootKey = NULL_HKEY;
		Tspi_Context_CloseObject(tspContext, hMigLeafKey);
		hMigLeafKey = NULL_HKEY;
		return CKR_FUNCTION_FAILED;
	}

	return rc;
}

CK_RV
token_specific_login(CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_RV rc;
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	TSS_RESULT result;

	result = token_load_srk();
	if (result != TSS_SUCCESS) {
		st_err_log("CKR_FUNCTION_FAILED");
		return CKR_FUNCTION_FAILED;
	}

	compute_sha( pPin, ulPinLen, hash_sha );

	if (userType == CKU_USER) {
		rc = util_set_username((char **)&TPMTOK_USERNAME);
		if (rc != CKR_OK) {
			LogError("util_set_username failed");
			return rc;
		}

		/* since logging in is such an intensive process, set a flag on logout,
		 * so that we only have to load 1 key on a re-login
		 */
		if (relogging_in) {
			rc = token_load_key(ckUserLeafKey, hUserBaseKey, hash_sha,
					    &hUserLeafKey);
			if (rc != CKR_OK) {
				st_err_log("CKR_FUNCTION_FAILED");
				return CKR_FUNCTION_FAILED;
			}

			rc = token_verify_pin(hUserLeafKey);
			if (rc != CKR_OK) {
				return rc;
			}
		}

		/* find, load the root key */
		rc = token_find_key(TPMTOK_ROOT_KEY, &ckRootKey);
		if (rc != CKR_OK) {
			st_err_log("CKR_FUNCTION_FAILED");
			return CKR_USER_PIN_NOT_INITIALIZED;
		}

		rc = token_load_key(ckRootKey, hSRK, NULL, &hRootKey);
		if (rc != CKR_OK) {
			st_err_log("CKR_FUNCTION_FAILED");
			return CKR_FUNCTION_FAILED;
		}

		/* find, load this user's base key */
		rc = token_find_key(TPMTOK_USER_BASE_KEY, &ckUserBaseKey);
		if (rc != CKR_OK) {
			/* user's key chain not found, this must be the initial login */
			if (memcmp(hash_sha, default_user_pin_sha, SHA1_HASH_SIZE)) {
				LogError("token_find_key failed and PIN != default");
				return CKR_PIN_INCORRECT;
			}

			not_initialized = 1;
			return CKR_OK;
		}

		rc = token_load_key(ckUserBaseKey, hRootKey, NULL, &hUserBaseKey);
		if (rc != CKR_OK) {
			st_err_log("CKR_FUNCTION_FAILED");
			return CKR_FUNCTION_FAILED;
		}

		/* find, load this user's leaf key */
		rc = token_find_key(TPMTOK_USER_LEAF_KEY, &ckUserLeafKey);
		if (rc != CKR_OK) {
			st_err_log("CKR_FUNCTION_FAILED");
			return CKR_FUNCTION_FAILED;
		}

		rc = token_load_key(ckUserLeafKey, hUserBaseKey, hash_sha, &hUserLeafKey);
		if (rc != CKR_OK) {
			st_err_log("CKR_FUNCTION_FAILED");
			return CKR_FUNCTION_FAILED;
		}

		rc = token_verify_pin(hUserLeafKey);
		if (rc != CKR_OK) {
			st_err_log("token_verify_pin failed.");
			return rc;
		}
	} else {
		/* SO path --
		 * Since logging in is such an intensive process, set a flag on logout,
		 * so that we only have to load 1 key on a re-login
		 */
		if (relogging_in) {
			rc = token_load_key(ckUserLeafKey, hUserBaseKey, hash_sha,
					&hUserLeafKey);
			if (rc != CKR_OK) {
				st_err_log("CKR_FUNCTION_FAILED");
				return CKR_FUNCTION_FAILED;
			}

			rc = token_verify_pin(hUserLeafKey);
			if (rc != CKR_OK) {
				st_err_log("token_verify_pin failed.");
				return rc;
			}

			/* We have re-logged in successfully, do what's needed to read
			 * the master_key off disk
			 */
			goto legacy_so_ops;
		}

		/* find, load the root key */
		rc = token_find_key(TPMTOK_ROOT_KEY, &ckRootKey);
		if (rc != CKR_OK) {
			/* The SO hasn't set her PIN yet, compare the login pin with
			 * the hard-coded value */
			if (memcmp(default_so_pin_sha, hash_sha, SHA1_HASH_SIZE)) {
				LogError("token_find_key failed and PIN != default");
				return CKR_PIN_INCORRECT;
			}

			not_initialized = 1;
			return CKR_OK;
		}

		/* The SO's key hierarchy has previously been created, so load the key
		 * hierarchy and verify the pin using the TPM. */
		rc = token_load_key(ckRootKey, hSRK, NULL, &hRootKey);
		if (rc != CKR_OK) {
			LogError1("token_load_key(RootKey) Failed.");
			return CKR_FUNCTION_FAILED;
		}

		/* find, load the migratable root key */
		rc = token_find_key(TPMTOK_MIG_ROOT_KEY, &ckMigRootKey);
		if (rc != CKR_OK) {
			st_err_log("CKR_FUNCTION_FAILED");
			return CKR_FUNCTION_FAILED;
		}

		rc = token_load_key(ckMigRootKey, hSRK, NULL, &hMigRootKey);
		if (rc != CKR_OK) {
			LogError1("token_load_key(MigRootKey) Failed.");
			return CKR_FUNCTION_FAILED;
		}

		/* find, load the migratable leaf key */
		rc = token_find_key(TPMTOK_MIG_LEAF_KEY, &ckMigLeafKey);
		if (rc != CKR_OK) {
			st_err_log("CKR_FUNCTION_FAILED");
			return CKR_FUNCTION_FAILED;
		}

		rc = token_load_key(ckMigLeafKey, hMigRootKey, hash_sha, &hMigLeafKey);
		if (rc != CKR_OK) {
			LogError1("token_load_key(MigLeafKey) Failed.");
			return CKR_FUNCTION_FAILED;
		}

		rc = token_verify_pin(hMigLeafKey);
		if (rc != CKR_OK) {
			st_err_log("token_verify_pin failed.");
			return rc;
		}
legacy_so_ops:
		compute_md5( pPin, ulPinLen, so_pin_md5 );
		memset( user_pin_md5, 0, MD5_HASH_SIZE );

		memcpy(nv_token_data->so_pin_sha, hash_sha, SHA1_HASH_SIZE);

		rc = load_masterkey_so();
		if (rc != CKR_OK) {
			st_err_log(155, __FILE__, __LINE__);
		}
	}

	return rc;
}

CK_RV
token_specific_logout()
{
	if (hUserLeafKey != NULL_HKEY) {
		Tspi_Key_UnloadKey(hUserLeafKey);
		hUserLeafKey = NULL_HKEY;
	} else if (hMigLeafKey != NULL_HKEY) {
		Tspi_Key_UnloadKey(hMigLeafKey);
		hMigLeafKey = NULL_HKEY;
	}

	/* pulled from new_host.c */
	memset( user_pin_md5, 0, MD5_HASH_SIZE );
	memset( so_pin_md5,   0, MD5_HASH_SIZE );

	object_mgr_purge_private_token_objects();

	/* since logging in is such an intensive process, set a flag on logout,
	 * so that we only have to load 1 key on a re-login
	 */
	relogging_in = 1;

	free(TPMTOK_USERNAME);
	TPMTOK_USERNAME = NULL;

	return CKR_OK;
}

CK_RV
token_specific_init_pin(CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	/* Since the SO must log in before calling C_InitPIN, we will
	 * be able to return CKR_OK automatically here.
	 * This is because the USER key structure is created at the
	 * time of her first login, not at C_InitPIN time.
	 */
	return CKR_OK;
}

CK_RV
check_pin_properties(CK_USER_TYPE userType, CK_BYTE *pinHash, CK_ULONG ulPinLen)
{
	/* make sure the new PIN is different */
	if (userType == CKU_USER) {
		if (!memcmp(pinHash, default_user_pin_sha, SHA1_HASH_SIZE)) {
			LogError("new PIN must not be the default");
			return CKR_PIN_INVALID;
		}
	} else {
		if (!memcmp(pinHash, default_so_pin_sha, SHA1_HASH_SIZE)) {
			LogError("new PIN must not be the default");
			return CKR_PIN_INVALID;
		}
	}

	if (ulPinLen > MAX_PIN_LEN || ulPinLen < MIN_PIN_LEN) {
		LogError("New PIN is out of size range");
		return CKR_PIN_LEN_RANGE;
	}

	return CKR_OK;
}

CK_RV
token_specific_set_pin(ST_SESSION_HANDLE session,
		       CK_CHAR_PTR pOldPin, CK_ULONG ulOldPinLen,
		       CK_CHAR_PTR pNewPin, CK_ULONG ulNewPinLen)
{
	SESSION *sess = session_mgr_find( session.sessionh );
	CK_BYTE oldpin_hash[SHA1_HASH_SIZE], newpin_hash[SHA1_HASH_SIZE];
	CK_RV rc;
	RSA *rsa_base, *rsa_user_root, *rsa_pub_root;
	char loc[80];
	TSS_RESULT result;

	if (!sess) {
		st_err_log(40, __FILE__, __LINE__);
		return CKR_SESSION_HANDLE_INVALID;
	}

	compute_sha(pOldPin, ulOldPinLen, oldpin_hash);
	compute_sha(pNewPin, ulNewPinLen, newpin_hash);

	if (sess->session_info.state == CKS_RW_USER_FUNCTIONS) {
		if (not_initialized) {
			if (memcmp(oldpin_hash, default_user_pin_sha, SHA1_HASH_SIZE)) {
				LogError("old PIN != default for an uninitialized user");
				return CKR_PIN_INCORRECT;
			}

			if ((rc = check_pin_properties(CKU_USER, newpin_hash, ulNewPinLen))) {
				return rc;
			}

			rc = token_create_user_tree(newpin_hash, pNewPin);
			if (rc != CKR_OK) {
				LogError1("FAILED creating USER tree.");
				return CKR_FUNCTION_FAILED;
			}

			nv_token_data->token_info.flags &= ~(CKF_USER_PIN_TO_BE_CHANGED);

			return save_token_data();
		}

		if ((rc = check_pin_properties(CKU_USER, newpin_hash, ulNewPinLen))) {
			return rc;
		}

		/* change the auth on the TSS object */
		result = tss_change_auth(hUserLeafKey, hUserBaseKey, newpin_hash);
		if (result != TSS_SUCCESS) {
			LogError1("tss_change_auth failed");
			return CKR_FUNCTION_FAILED;
		}

		/* destroy the old PKCS#11 priv key object and create a new one */
		rc = token_update_private_key(hUserLeafKey, TPMTOK_USER_LEAF_KEY);
		if (rc != CKR_OK) {
			LogError1("token_update_private_key failed.");
			return rc;
		}

		/* now re-write the backup key using the new pin */
		sprintf(loc, TPMTOK_USER_BASE_KEY_BACKUP_LOCATION, TPMTOK_USERNAME, TPMTOK_USERNAME);

		/* read the backup key with the old pin */
		rc = openssl_read_key(loc, pOldPin, &rsa_base);
		if (rc != CKR_OK) {
			LogError1("openssl_read_key failed");
			return rc;
		}

		/* write it out using the new pin */
		rc = openssl_write_key(rsa_base, loc, pNewPin);
		if (rc != CKR_OK) {
			RSA_free(rsa_base);
			LogError1("openssl_write_key failed");
			return CKR_FUNCTION_FAILED;
		}
	} else if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
		if (not_initialized) {
			if (memcmp(default_so_pin_sha, oldpin_hash, SHA1_HASH_SIZE)) {
				LogError("old PIN != default for an uninitialized SO");
				return CKR_PIN_INCORRECT;
			}

			if ((rc = check_pin_properties(CKU_SO, newpin_hash, ulNewPinLen))) {
				return rc;
			}

			rc = token_create_so_tree(newpin_hash, pNewPin);
			if (rc != CKR_OK) {
				LogError1("FAILED creating SO tree.");
				return CKR_FUNCTION_FAILED;
			}

			nv_token_data->token_info.flags &= ~(CKF_SO_PIN_TO_BE_CHANGED);

			return save_token_data();
		}

		if ((rc = check_pin_properties(CKU_SO, newpin_hash, ulNewPinLen))) {
			return rc;
		}

		/* change auth on the SO's leaf key */
		result = tss_change_auth(hMigLeafKey, hMigRootKey, newpin_hash);
		if (result != TSS_SUCCESS) {
			LogError1("tss_change_auth failed");
			return CKR_FUNCTION_FAILED;
		}

		rc = token_update_private_key(hMigLeafKey, TPMTOK_MIG_LEAF_KEY);
		if (rc != CKR_OK) {
			LogError1("token_update_private_key failed.");
			return rc;
		}

		/* change auth on the migratable root key's openssl backup */
		rc = openssl_read_key(TPMTOK_MIG_ROOT_KEY_BACKUP_LOCATION, pOldPin, &rsa_base);
		if (rc != CKR_OK) {
			LogError1("openssl_read_key failed");
			return rc;
		}

		/* write it out using the new pin */
		rc = openssl_write_key(rsa_base, TPMTOK_MIG_ROOT_KEY_BACKUP_LOCATION, pNewPin);
		if (rc != CKR_OK) {
			RSA_free(rsa_base);
			LogError1("openssl_write_key failed");
			return CKR_FUNCTION_FAILED;
		}
		RSA_free(rsa_base);

		/* change auth on the user root key's openssl backup */
		rc = openssl_read_key(TPMTOK_ROOT_KEY_BACKUP_LOCATION, pOldPin, &rsa_user_root);
		if (rc != CKR_OK) {
			LogError1("openssl_read_key failed");
			return rc;
		}

		/* write it out using the new pin */
		rc = openssl_write_key(rsa_user_root, TPMTOK_ROOT_KEY_BACKUP_LOCATION, pNewPin);
		if (rc != CKR_OK) {
			LogError1("openssl_write_key failed");
			return CKR_FUNCTION_FAILED;
		}
		RSA_free(rsa_user_root);

		/* change auth on the public root key's openssl backup */
		rc = openssl_read_key(TPMTOK_PUB_ROOT_KEY_BACKUP_LOCATION, pOldPin, &rsa_pub_root);
		if (rc != CKR_OK) {
			LogError1("openssl_read_key failed");
			return rc;
		}

		/* write it out using the new pin */
		rc = openssl_write_key(rsa_pub_root, TPMTOK_PUB_ROOT_KEY_BACKUP_LOCATION, pNewPin);
		if (rc != CKR_OK) {
			LogError1("openssl_write_key failed");
			return CKR_FUNCTION_FAILED;
		}
		RSA_free(rsa_pub_root);
	} else {
		st_err_log(142, __FILE__, __LINE__);
		rc = CKR_SESSION_READ_ONLY;
	}

	return rc;
}

/* only called at token init time */
CK_RV
token_specific_verify_so_pin(CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
	CK_BYTE hash_sha[SHA1_HASH_SIZE];
	CK_RV rc;

	compute_sha( pPin, ulPinLen, hash_sha );

	/* find, load the migratable root key */
	rc = token_find_key(TPMTOK_MIG_ROOT_KEY, &ckMigRootKey);
	if (rc != CKR_OK) {
		/* The SO hasn't set her PIN yet, compare the login pin with
		 * the hard-coded value */
		if (memcmp(default_so_pin_sha, hash_sha, SHA1_HASH_SIZE)) {
			LogError("token_find_key failed and PIN != default");
			return CKR_PIN_INCORRECT;
		}

		return CKR_OK;
	}

	/* we found the root key, so check by loading the chain */
	rc = token_load_key(ckMigRootKey, hSRK, NULL, &hMigRootKey);
	if (rc != CKR_OK) {
		LogError1("token_load_key(MigRootKey) Failed.");
		return CKR_FUNCTION_FAILED;
	}

	/* find, load the migratable leaf key */
	rc = token_find_key(TPMTOK_MIG_LEAF_KEY, &ckMigLeafKey);
	if (rc != CKR_OK) {
		st_err_log("CKR_FUNCTION_FAILED");
		return CKR_FUNCTION_FAILED;
	}

	rc = token_load_key(ckMigLeafKey, hMigRootKey, hash_sha, &hMigLeafKey);
	if (rc != CKR_OK) {
		LogError1("token_load_key(MigLeafKey) Failed.");
		return CKR_FUNCTION_FAILED;
	}

	rc = token_verify_pin(hMigLeafKey);
	if (rc != CKR_OK) {
		st_err_log("token_verify_pin failed.");
		return rc;
	}

	return CKR_OK;
}

CK_RV
token_specific_final()
{
	TSS_RESULT rc;

        rc = Tspi_Context_Close(tspContext);
        if (rc != TSS_SUCCESS) {
                st_err_log("CKR_FUNCTION_FAILED");
                return CKR_FUNCTION_FAILED;
        }

	return CKR_OK;
}

CK_RV
token_specific_des_key_gen(CK_BYTE *des_key, CK_ULONG len)
{
	// Nothing different to do for DES or TDES here as this is just
	// random data...  Validation handles the rest
	rng_generate(des_key,len);

	// we really need to validate the key for parity etc...
	// we should do that here... The caller validates the single des keys
	// against the known and suspected poor keys..
	return CKR_OK;
}

CK_RV
token_specific_des_ecb(CK_BYTE * in_data,
		CK_ULONG in_data_len,
		CK_BYTE *out_data,
		CK_ULONG *out_data_len,
		CK_BYTE  *key_value,
		CK_BYTE  encrypt)
{
	CK_ULONG       rc;

	des_key_schedule des_key2;
	const_des_cblock key_val_SSL, in_key_data;
	des_cblock out_key_data;
	int i,j;

	// Create the key schedule
	memcpy(&key_val_SSL, key_value, 8);
	des_set_key_unchecked(&key_val_SSL, des_key2);

	// the des decrypt will only fail if the data length is not evenly divisible
	// by 8
	if (in_data_len % 8 ){
		st_err_log(11, __FILE__, __LINE__);
		return CKR_DATA_LEN_RANGE;
	}

	// Both the encrypt and the decrypt are done 8 bytes at a time
	if (encrypt) {
		for (i=0; i<in_data_len; i=i+8) {
			memcpy(in_key_data, in_data+i, 8);
			des_ecb_encrypt(&in_key_data, &out_key_data, des_key2, DES_ENCRYPT);
			memcpy(out_data+i, out_key_data, 8);
		}

		*out_data_len = in_data_len;
		rc = CKR_OK;
	} else {

		for(j=0; j < in_data_len; j=j+8) {
			memcpy(in_key_data, in_data+j, 8);
			des_ecb_encrypt(&in_key_data, &out_key_data, des_key2, DES_DECRYPT);
			memcpy(out_data+j, out_key_data, 8);
		}

		*out_data_len = in_data_len;
		rc = CKR_OK;
	}

	return rc;
}

CK_RV
token_specific_des_cbc(CK_BYTE * in_data,
		CK_ULONG in_data_len,
		CK_BYTE *out_data,
		CK_ULONG *out_data_len,
		CK_BYTE  *key_value,
		CK_BYTE *init_v,
		CK_BYTE  encrypt)
{
	CK_ULONG         rc;

	des_cblock ivec;

	des_key_schedule des_key2;
	const_DES_cblock key_val_SSL;

	// Create the key schedule
	memcpy(&key_val_SSL, key_value, 8);
	des_set_key_unchecked(&key_val_SSL, des_key2);

	memcpy(&ivec, init_v, 8);
	// the des decrypt will only fail if the data length is not evenly divisible
	// by 8
	if (in_data_len % 8 ){
		st_err_log(11, __FILE__, __LINE__);
		return CKR_DATA_LEN_RANGE;
	}


	if ( encrypt){
		des_ncbc_encrypt(in_data, out_data, in_data_len, des_key2, &ivec, DES_ENCRYPT);
		*out_data_len = in_data_len;
		rc = CKR_OK;
	} else {
		des_ncbc_encrypt(in_data, out_data, in_data_len, des_key2, &ivec, DES_DECRYPT);
		*out_data_len = in_data_len;
		rc = CKR_OK;
	}
	return rc;
}

CK_RV
token_specific_tdes_ecb(CK_BYTE * in_data,
		CK_ULONG in_data_len,
		CK_BYTE *out_data,
		CK_ULONG *out_data_len,
		CK_BYTE  *key_value,
		CK_BYTE  encrypt)
{
	CK_RV  rc;

	int k, j;
	des_key_schedule des_key1;
	des_key_schedule des_key2;
	des_key_schedule des_key3;

	const_des_cblock key_SSL1, key_SSL2, key_SSL3, in_key_data;
	des_cblock out_key_data;

	// The key as passed is a 24 byte long string containing three des keys
	// pick them apart and create the 3 corresponding key schedules
	memcpy(&key_SSL1, key_value, 8);
	memcpy(&key_SSL2, key_value+8, 8);
	memcpy(&key_SSL3, key_value+16, 8);
	des_set_key_unchecked(&key_SSL1, des_key1);
	des_set_key_unchecked(&key_SSL2, des_key2);
	des_set_key_unchecked(&key_SSL3, des_key3);

	// the des decrypt will only fail if the data length is not evenly divisible
	// by 8
	if (in_data_len % 8 ){
		st_err_log(11, __FILE__, __LINE__);
		return CKR_DATA_LEN_RANGE;
	}

	// the encrypt and decrypt are done 8 bytes at a time
	if (encrypt) {
		for(k=0;k<in_data_len;k=k+8){
			memcpy(in_key_data, in_data+k, 8);
			des_ecb3_encrypt(&in_key_data,
					&out_key_data,
					des_key1,
					des_key2,
					des_key3,
					DES_ENCRYPT);
			memcpy(out_data+k, out_key_data, 8);
		}
		*out_data_len = in_data_len;
		rc = CKR_OK;
	} else {
		for (j=0;j<in_data_len;j=j+8){
			memcpy(in_key_data, in_data+j, 8);
			des_ecb3_encrypt(&in_key_data,
					&out_key_data,
					des_key1,
					des_key2,
					des_key3,
					DES_DECRYPT);
			memcpy(out_data+j, out_key_data, 8);
		}
		*out_data_len = in_data_len;
		rc = CKR_OK;
	}
	return rc;
}

CK_RV
token_specific_tdes_cbc(CK_BYTE * in_data,
		CK_ULONG in_data_len,
		CK_BYTE *out_data,
		CK_ULONG *out_data_len,
		CK_BYTE  *key_value,
		CK_BYTE *init_v,
		CK_BYTE  encrypt)
{

	CK_RV rc = CKR_OK;
	des_key_schedule des_key1;
	des_key_schedule des_key2;
	des_key_schedule des_key3;

	const_des_cblock key_SSL1, key_SSL2, key_SSL3;
	des_cblock ivec;

	// The key as passed in is a 24 byte string containing 3 keys
	// pick it apart and create the key schedules
	memcpy(&key_SSL1, key_value, 8);
	memcpy(&key_SSL2, key_value+8, 8);
	memcpy(&key_SSL3, key_value+16, 8);
	des_set_key_unchecked(&key_SSL1, des_key1);
	des_set_key_unchecked(&key_SSL2, des_key2);
	des_set_key_unchecked(&key_SSL3, des_key3);

	memcpy(ivec, init_v, sizeof(ivec));

	// the des decrypt will only fail if the data length is not evenly divisible
	// by 8
	if (in_data_len % 8 ){
		st_err_log(11, __FILE__, __LINE__);
		return CKR_DATA_LEN_RANGE;
	}

	// Encrypt or decrypt the data
	if (encrypt){
		des_ede3_cbc_encrypt(in_data,
				out_data,
				in_data_len,
				des_key1,
				des_key2,
				des_key3,
				&ivec,
				DES_ENCRYPT);
		*out_data_len = in_data_len;
		rc = CKR_OK;
	}else {
		des_ede3_cbc_encrypt(in_data,
				out_data,
				in_data_len,
				des_key1,
				des_key2,
				des_key3,
				&ivec,
				DES_DECRYPT);

		*out_data_len = in_data_len;
		rc = CKR_OK;
	}

	return rc;
}

/* wrap the 20 bytes of auth data @authData and store in an object with ID @id,
 * which will be the SHA1 hash of the auth data's key's identifying features
 */
CK_RV
token_wrap_auth_data(CK_BYTE *authData, CK_BYTE *id, CK_OBJECT_HANDLE *ckDataObj)
{
	CK_RV		rc;
	CK_OBJECT_CLASS data_class = CKO_DATA;
	CK_BBOOL	true = TRUE;
	CK_ATTRIBUTE	data_tmpl[] = {
		{CKA_CLASS, &data_class, sizeof(data_class)},
		{CKA_ID, id, SHA1_HASH_SIZE},
		{CKA_VALUE, NULL, 0}
	};
	CK_ATTRIBUTE	*new_attr;
	OBJECT		*data_obj;
	SESSION		dummy_sess;

	/* set up dummy session */
	memset(&dummy_sess, 0, sizeof(SESSION));
	dummy_sess.session_info.state = CKS_RW_USER_FUNCTIONS;

	TSS_HKEY	hParentKey;
	TSS_HENCDATA	hEncData;
	BYTE		*blob;
	UINT32		blob_size;

	if ((hUserLeafKey == NULL_HKEY) && (hMigLeafKey == NULL_HKEY)) {
		LogError("Shouldn't be wrapping auth data in a public path!");
		return CKR_FUNCTION_FAILED;
	} else if (hMigLeafKey != NULL_HKEY) {
		hParentKey = hMigLeafKey;
	} else {
		hParentKey = hUserLeafKey;
	}

	/* create the encrypted data object */
	if ((rc = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_ENCDATA,
						TSS_ENCDATA_BIND, &hEncData))) {
		LogError("Tspi_Context_CreateObject failed. rc=0x%x", rc);
		return rc;
	}

	if ((rc = Tspi_Data_Bind(hEncData, hParentKey, SHA1_HASH_SIZE, authData))) {
		LogError("Tspi_Data_Bind failed. rc=0x%x", rc);
		return rc;
	}

	/* pull the encrypted data out of the encrypted data object */
	if ((rc = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
					TSS_TSPATTRIB_ENCDATABLOB_BLOB, &blob_size,
					&blob))) {
		LogError("Tspi_SetAttribData failed. rc=0x%x", rc);
		return rc;
	}

	data_tmpl[3].pValue = blob;
	data_tmpl[3].ulValueLen = blob_size;

	/* at this point the PKCS#11 data object is ready to be created */
	rc = object_create_skel(data_tmpl, 3, MODE_CREATE, CKO_DATA, 0, &data_obj);
	if (rc != CKR_OK) {
		LogError("object_mgr_create_skel: 0x%x", rc);
		Tspi_Context_FreeMemory(tspContext, blob);
		return rc;
	}
	Tspi_Context_FreeMemory(tspContext, blob);

	/* make the object reside on the token, as if that were possible */
	rc = build_attribute( CKA_TOKEN, &true, sizeof(CK_BBOOL), &new_attr );
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		return rc;
	}
	template_update_attribute( data_obj->template, new_attr );

	/* set the object to be hidden */
	rc = build_attribute( CKA_HIDDEN, &true, sizeof(CK_BBOOL), &new_attr );
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		return rc;
	}
	template_update_attribute( data_obj->template, new_attr );

	rc = object_mgr_create_final(&dummy_sess, data_obj, ckDataObj);
	if (rc != CKR_OK){
		st_err_log(90, __FILE__, __LINE__);
	}

	return rc;
}

// convert from the local PKCS11 template representation to
// the underlying requirement
// returns the pointer to the local key representation
CK_BYTE *
rsa_convert_public_key(OBJECT *key_obj)
{
	CK_ATTRIBUTE	*modulus = NULL;
	CK_BYTE		*ret;
	CK_RV		rc;

	rc  = template_attribute_find( key_obj->template, CKA_MODULUS, &modulus );
	if (rc == FALSE) {
		return NULL;
	}

	ret = malloc(modulus->ulValueLen);
	if (ret == NULL) {
		LogError("Out of memory.");
		return NULL;
	}

	memcpy(ret, modulus->pValue, modulus->ulValueLen);

	return ret;
}

void *
rsa_convert_private_key(OBJECT *key_obj)
{
	CK_ATTRIBUTE      * modulus  = NULL;
	CK_ATTRIBUTE      * priv_exp = NULL;
	CK_ATTRIBUTE      * prime1   = NULL;
	CK_ATTRIBUTE      * prime2   = NULL;
	CK_ATTRIBUTE      * exp1     = NULL;
	CK_ATTRIBUTE      * exp2     = NULL;
	CK_ATTRIBUTE      * coeff    = NULL;
	CK_BBOOL          rc;

	RSA *rsa;
	BIGNUM *bn_mod, *bn_priv_exp, *bn_p1, *bn_p2, *bn_e1, *bn_e2, *bn_cf;


	rc  = template_attribute_find( key_obj->template, CKA_MODULUS,          &modulus );
	rc &= template_attribute_find( key_obj->template, CKA_PRIVATE_EXPONENT, &priv_exp );
	rc &= template_attribute_find( key_obj->template, CKA_PRIME_1,          &prime1 );
	rc &= template_attribute_find( key_obj->template, CKA_PRIME_2,          &prime2 );
	rc &= template_attribute_find( key_obj->template, CKA_EXPONENT_1,       &exp1 );
	rc &= template_attribute_find( key_obj->template, CKA_EXPONENT_2,       &exp2 );
	rc &= template_attribute_find( key_obj->template, CKA_COEFFICIENT,      &coeff );

	if ( !prime2 && !modulus ){
		return NULL;
	}

	// Create and init all the RSA and BIGNUM structs we need.
	rsa = RSA_new();
	if (rsa == NULL)
		return NULL;
	RSA_blinding_off(rsa);

	bn_mod = BN_new();
	bn_priv_exp = BN_new();
	bn_p1 = BN_new();
	bn_p2 = BN_new();
	bn_e1 = BN_new();
	bn_e2 = BN_new();
	bn_cf = BN_new();

	if ((bn_cf == NULL) || (bn_e2 == NULL) || (bn_e1 == NULL) ||
			(bn_p2 == NULL) || (bn_p1 == NULL) || (bn_priv_exp == NULL) ||
			(bn_mod == NULL))
	{
		if (rsa)         RSA_free(rsa);
		if (bn_mod)      BN_free(bn_mod);
		if (bn_priv_exp) BN_free(bn_priv_exp);
		if (bn_p1)       BN_free(bn_p1);
		if (bn_p2)       BN_free(bn_p2);
		if (bn_e1)       BN_free(bn_e1);
		if (bn_e2)       BN_free(bn_e2);
		if (bn_cf)       BN_free(bn_cf);
		return NULL;
	}


	// CRT key?
	if ( prime1){
		if (!prime2 || !exp1 ||!exp2 || !coeff) {
			return NULL;
		}
		// Even though this is CRT key, OpenSSL requires the
		// modulus and exponents filled in or encrypt and decrypt will
		// not work
		BN_bin2bn((char *)modulus->pValue, modulus->ulValueLen, bn_mod);
		rsa->n = bn_mod;
		BN_bin2bn((char *)priv_exp->pValue, priv_exp->ulValueLen, bn_priv_exp);
		rsa->d = bn_priv_exp;
		BN_bin2bn((char *)prime1->pValue, prime1->ulValueLen, bn_p1);
		rsa->p = bn_p1;
		BN_bin2bn((char *)prime2->pValue, prime2->ulValueLen, bn_p2);
		rsa->q = bn_p2;
		BN_bin2bn((char *)exp1->pValue, exp1->ulValueLen, bn_e1);
		rsa->dmp1 = bn_e1;
		BN_bin2bn((char *)exp2->pValue, exp2->ulValueLen, bn_e2);
		rsa->dmq1 = bn_e2;
		BN_bin2bn((char *)coeff->pValue, coeff->ulValueLen, bn_cf);
		rsa->iqmp = bn_cf;

		return rsa;
	} else {   // must be a non-CRT key
		if (!priv_exp) {
			return NULL;
		}
		BN_bin2bn((char *)modulus->pValue, modulus->ulValueLen, bn_mod);
		rsa->n = bn_mod;
		BN_bin2bn((char *)priv_exp->pValue, priv_exp->ulValueLen, bn_priv_exp);
		rsa->d = bn_priv_exp;
	}
	return (void *)rsa;
}

CK_RV
token_specific_rsa_generate_keypair( TEMPLATE  * publ_tmpl,
		TEMPLATE  * priv_tmpl )
{
	CK_ATTRIBUTE		*publ_exp = NULL;
	CK_ATTRIBUTE		*attr     = NULL;
	CK_ULONG		mod_bits = 0;
	CK_BBOOL		flag;
	CK_RV			rc;
	CK_OBJECT_HANDLE	ckKey, ckDataObj;

	TSS_FLAGS	initFlags = 0;
	BYTE		authHash[SHA1_HASH_SIZE];
	BYTE		*authData = NULL;
	TSS_HKEY	hKey = NULL_HKEY;
	TSS_HKEY	hParentKey = NULL_HKEY;
	CK_BYTE		pub_exp[] = { 0x1, 0x0, 0x1 }; // 65537
	TSS_RESULT	result;
	UINT32		ulBlobLen;
	BYTE		*rgbBlob;

	LogError("Generating RSA keypair on the TPM...");

	flag = template_attribute_find( publ_tmpl, CKA_MODULUS_BITS, &attr );
	if (!flag){
		st_err_log(48, __FILE__, __LINE__);
		return CKR_TEMPLATE_INCOMPLETE;  // should never happen
	}
	mod_bits = *(CK_ULONG *)attr->pValue;

	flag = template_attribute_find( publ_tmpl, CKA_PUBLIC_EXPONENT, &publ_exp );
	if (!flag){
		st_err_log(48, __FILE__, __LINE__);
		return CKR_TEMPLATE_INCOMPLETE;
	}

	/* 65537 is the only allowable pub exp */
	if (memcmp(publ_exp->pValue, pub_exp, MIN(sizeof(pub_exp), publ_exp->ulValueLen))) {
		LogError("Template inconsistent");
		return CKR_TEMPLATE_INCONSISTENT;
	}

	if ((initFlags = util_get_keysize_flag(mod_bits)) == 0) {
		st_err_log(19, __FILE__, __LINE__);
		return CKR_KEY_SIZE_RANGE;
	}

	/* If we're not logged in, hUserLeafKey and hMigLeafKey should be NULL */
	if ((hUserLeafKey == NULL_HKEY) && (hMigLeafKey == NULL_HKEY)) {
		/* public session, wrap key with the PRK */
		initFlags |= TSS_KEY_TYPE_LEGACY | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_MIGRATABLE;

		if ((result = token_load_prk())) {
			LogError("token_load_prk failed. rc=%x", result);
			return CKR_FUNCTION_FAILED;
		}

		hParentKey = hPubRootKey;
	} else if (hUserLeafKey != NULL_HKEY) {
		/* logged in USER session */
		initFlags |= TSS_KEY_TYPE_LEGACY | TSS_KEY_AUTHORIZATION | TSS_KEY_MIGRATABLE;

		/* get a random SHA1 hash for the auth data */
		if ((rc = token_rng(authHash, SHA1_HASH_SIZE))) {
			LogError("token_rng failed. rc=%x", rc);
			return CKR_FUNCTION_FAILED;
		}

		authData = authHash;
		hParentKey = hUserBaseKey;
	} else {
		/* logged in SO session */
		initFlags |= TSS_KEY_TYPE_LEGACY | TSS_KEY_AUTHORIZATION | TSS_KEY_MIGRATABLE;

		/* get a random SHA1 hash for the auth data */
		if ((rc = token_rng(authHash, SHA1_HASH_SIZE))) {
			LogError("token_rng failed. rc=0x%x", rc);
			return CKR_FUNCTION_FAILED;
		}

		authData = authHash;
		hParentKey = hMigRootKey;
	}

	if ((result = tss_generate_key(initFlags, authData, hParentKey, &hKey))) {
		LogError("tss_generate_key returned 0x%x", result);
		return result;
	}

	if ((result = tss_get_key_blob(hKey, &ulBlobLen, &rgbBlob))) {
		LogError("tss_get_key_blob failed. rc=0x%x", result);
		return CKR_FUNCTION_FAILED;
	}

	/* add the key blob to the object template */
	rc = build_attribute(CKA_KEY_BLOB, rgbBlob, ulBlobLen, &attr);
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		Tspi_Context_FreeMemory(tspContext, rgbBlob);
		return rc;
	}
	template_update_attribute( priv_tmpl, attr );

	Tspi_Context_FreeMemory(tspContext, rgbBlob);

	/* grab the public key  to put into the public key object */
	result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB, TSS_TSPATTRIB_KEYBLOB_PUBLIC_KEY,
					&ulBlobLen, &rgbBlob);
	if (result != TSS_SUCCESS) {
		LogError("Tspi_GetAttribData failed with rc: 0x%x", result);
		return result;
	}

	/* add the public key blob to the object template */
	rc = build_attribute(CKA_MODULUS, rgbBlob, ulBlobLen, &attr);
	if (rc != CKR_OK){
		st_err_log(84, __FILE__, __LINE__);
		Tspi_Context_FreeMemory(tspContext, rgbBlob);
		return rc;
	}
	template_update_attribute( publ_tmpl, attr );

	/* wrap the authdata and put it into an object */
	if (authData != NULL) {
		CK_BYTE id[SHA1_HASH_SIZE];

		/* id will be a hash of the key's public data */
		compute_sha(rgbBlob, ulBlobLen, id);

		rc = token_wrap_auth_data(authData, id, &ckDataObj);
		LogError("token_wrap_auth_data failed with rc: 0x%x", rc);
	}

	Tspi_Context_FreeMemory(tspContext, rgbBlob);

	return rc;
}


CK_RV
token_specific_rsa_encrypt( CK_BYTE   * in_data,
		CK_ULONG    in_data_len,
		CK_BYTE   * out_data,
		OBJECT    * key_obj )
{
	CK_RV		rc = CKR_FUNCTION_FAILED;
	CK_BYTE		*modulus;
	CK_ATTRIBUTE	*attr;
	CK_ULONG	key_size;

	// Convert the local representation to an RSA representation
	modulus = rsa_convert_public_key(key_obj);
	if (modulus == NULL) {
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return rc;
	}

	rc  = template_attribute_find( key_obj->template, CKA_MODULUS_BITS, &attr );
	if (rc == FALSE) {
		LogError("template_attribute_find failed. rc=0x%x", rc);
		return CKR_FUNCTION_FAILED;
	}
	key_size = *(CK_ULONG *)attr->pValue;

	// Do an RSA public encryption
	LogError("TPM RSA encrypt: in_data_len: 0x%x, key_size: 0x%x", in_data_len, key_size);
#if 1
	rc = Trspi_RSA_Encrypt(in_data, in_data_len, out_data, &in_data_len, modulus, key_size);
	if (rc) {
		LogError("Trspi_RSA_Encrypt failed. rc=0x%x", rc);
		return CKR_FUNCTION_FAILED;
	}
#else
	rc = Tspi_Data_Bind(in_data, in_data_len, out_data, &in_data_len, modulus, key_size);
	if (rc) {
		LogError("Trspi_RSA_Encrypt failed. rc=0x%x", rc);
		return CKR_FUNCTION_FAILED;
	}
#endif
	return CKR_OK;
}


CK_RV
token_specific_rsa_decrypt( CK_BYTE   * in_data,
		CK_ULONG    in_data_len,
		CK_BYTE   * out_data,
		OBJECT    * key_obj )
{
	CK_RV		rc;
	CK_ATTRIBUTE	*attr;
	CK_BYTE		*blob = NULL;
	CK_ULONG	blobSize;

	TSS_RESULT	result;
	TSS_HKEY	hParentKey, hKey;
	TSS_HENCDATA	hEncData;
	UINT32		buf_size;
	BYTE		*buf;

	if ((hUserLeafKey == NULL_HKEY) && (hMigLeafKey == NULL_HKEY)) {
		hParentKey = hPubRootKey;
	} else if (hMigLeafKey != NULL_HKEY) {
		hParentKey = hMigRootKey;
	} else {
		hParentKey = hUserBaseKey;
	}

	rc  = template_attribute_find( key_obj->template, CKA_KEY_BLOB, &attr );
	if (rc == FALSE) {
		LogError("template_attribute_find failed. rc=0x%x", rc);
		return CKR_FUNCTION_FAILED;
	}

	blob = malloc(attr->ulValueLen);
	if (blob == NULL) {
		LogError("Out of memory.");
		return CKR_HOST_MEMORY;
	}

	memcpy(blob, (CK_ULONG *)attr->pValue, attr->ulValueLen);

	if ((result = Tspi_Context_LoadKeyByBlob(tspContext, hParentKey, blobSize, blob, &hKey))) {
		LogError("Tspi_Context_LoadKeyByBlob failed. rc=0x%x", result);
		return CKR_FUNCTION_FAILED;
	}

	/* push the data into the encrypted data object */
	if ((result = Tspi_SetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
					 TSS_TSPATTRIB_ENCDATABLOB_BLOB, in_data_len, in_data))) {
		LogError("Tspi_SetAttribData failed. rc=0x%x", result);
		return CKR_FUNCTION_FAILED;
	}

	/* unbind the data, receiving the plaintext back */
	if ((result = Tspi_Data_Unbind(hEncData, hKey, &buf_size, &buf))) {
		LogError("Tspi_Data_Bind failed: 0x%x", result);
		return CKR_FUNCTION_FAILED;
	}

	memcpy(out_data, buf, buf_size);

	return rc;
}

CK_RV
token_specific_aes_key_gen(CK_BYTE *key, CK_ULONG len)
{
	return token_rng(key, len);
}

CK_RV
token_specific_aes_ecb(	CK_BYTE	*in_data,
		CK_ULONG	in_data_len,
		CK_BYTE		*out_data,
		CK_ULONG	*out_data_len,
		CK_BYTE		*key_value,
		CK_ULONG	key_len,
		CK_BYTE		encrypt)
{
	AES_KEY		ssl_aes_key;
	int		i;
	/* There's a previous check that in_data_len % AES_BLOCK_SIZE == 0,
	 * so this is fine */
	CK_ULONG	loops = (CK_ULONG)(in_data_len/AES_BLOCK_SIZE);

	memset( &ssl_aes_key, 0, sizeof(AES_KEY));

	// AES_ecb_encrypt encrypts only a single block, so we have to break up the
	// input data here
	if (encrypt) {
		AES_set_encrypt_key((unsigned char *)key_value, (key_len*8), &ssl_aes_key);
		for( i=0; i<loops; i++ ) {
			AES_ecb_encrypt((unsigned char *)in_data + (i*AES_BLOCK_SIZE),
					(unsigned char *)out_data + (i*AES_BLOCK_SIZE),
					&ssl_aes_key,
					AES_ENCRYPT);
		}
	} else {
		AES_set_decrypt_key((unsigned char *)key_value, (key_len*8), &ssl_aes_key);
		for( i=0; i<loops; i++ ) {
			AES_ecb_encrypt((unsigned char *)in_data + (i*AES_BLOCK_SIZE),
					(unsigned char *)out_data + (i*AES_BLOCK_SIZE),
					&ssl_aes_key,
					AES_DECRYPT);
		}
	}
	*out_data_len = in_data_len;
	return CKR_OK;
}

CK_RV
token_specific_aes_cbc(	CK_BYTE		*in_data,
		CK_ULONG 	in_data_len,
		CK_BYTE 	*out_data,
		CK_ULONG	*out_data_len,
		CK_BYTE		*key_value,
		CK_ULONG	key_len,
		CK_BYTE		*init_v,
		CK_BYTE		encrypt)
{
	AES_KEY		ssl_aes_key;

	memset( &ssl_aes_key, 0, sizeof(AES_KEY));

	// AES_cbc_encrypt chunks the data into AES_BLOCK_SIZE blocks, unlike
	// AES_ecb_encrypt, so no looping required.
	if (encrypt) {
		AES_set_encrypt_key((unsigned char *)key_value, (key_len*8), &ssl_aes_key);
		AES_cbc_encrypt((unsigned char *)in_data, (unsigned char *)out_data,
				in_data_len, 		  &ssl_aes_key,
				init_v,			  AES_ENCRYPT);
	} else {
		AES_set_decrypt_key((unsigned char *)key_value, (key_len*8), &ssl_aes_key);
		AES_cbc_encrypt((unsigned char *)in_data, (unsigned char *)out_data,
				in_data_len,		  &ssl_aes_key,
				init_v,			  AES_DECRYPT);
	}
	*out_data_len = in_data_len;
	return CKR_OK;
}

/* Begin code contributed by Corrent corp. */ 

// This computes DH shared secret, where:
//     Output: z is computed shared secret
//     Input:  y is other party's public key
//             x is private key
//             p is prime
// All length's are in number of bytes. All data comes in as Big Endian.

CK_RV
token_specific_dh_pkcs_derive( CK_BYTE   *z,
		CK_ULONG  *z_len,
		CK_BYTE   *y,
		CK_ULONG  y_len,
		CK_BYTE   *x,
		CK_ULONG  x_len,
		CK_BYTE   *p,
		CK_ULONG  p_len)
{
	CK_RV  rc ;
	BIGNUM *bn_z, *bn_y, *bn_x, *bn_p ;
	BN_CTX *ctx;

	//  Create and Init the BIGNUM structures.
	bn_y = BN_new() ;
	bn_x = BN_new() ;
	bn_p = BN_new() ;
	bn_z = BN_new() ;

	if (bn_z == NULL || bn_p == NULL || bn_x == NULL || bn_y == NULL) {
		if (bn_y) BN_free(bn_y);
		if (bn_x) BN_free(bn_x);
		if (bn_p) BN_free(bn_p);
		if (bn_z) BN_free(bn_z);
		st_err_log(1, __FILE__, __LINE__);
		return CKR_HOST_MEMORY;
	}

	BN_init(bn_y) ;
	BN_init(bn_x) ;
	BN_init(bn_p) ;

	// Initialize context
	ctx=BN_CTX_new();
	if (ctx == NULL)
	{
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	// Add data into these new BN structures

	BN_bin2bn((char *)y, y_len, bn_y);
	BN_bin2bn((char *)x, x_len, bn_x);
	BN_bin2bn((char *)p, p_len, bn_p);

	rc = BN_mod_exp(bn_z,bn_y,bn_x,bn_p,ctx);
	if (rc == 0)
	{
		BN_free(bn_z);
		BN_free(bn_y);
		BN_free(bn_x);
		BN_free(bn_p);
		BN_CTX_free(ctx);

		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	*z_len = BN_num_bytes(bn_z);
	BN_bn2bin(bn_z, z);

	BN_free(bn_z);
	BN_free(bn_y);
	BN_free(bn_x);
	BN_free(bn_p);
	BN_CTX_free(ctx);

	return CKR_OK;

} /* end token_specific_dh_pkcs_derive() */

// This computes DH key pair, where:
//     Output: priv_tmpl is generated private key
//             pub_tmpl is computed public key
//     Input:  pub_tmpl is public key (prime and generator)
// All length's are in number of bytes. All data comes in as Big Endian.

CK_RV
token_specific_dh_pkcs_key_pair_gen( TEMPLATE  * publ_tmpl,
		TEMPLATE  * priv_tmpl )
{
	CK_BBOOL           rc;
	CK_ATTRIBUTE       *prime_attr = NULL;
	CK_ATTRIBUTE       *base_attr = NULL;
	CK_ATTRIBUTE       *temp_attr = NULL ;
	CK_ATTRIBUTE       *value_bits_attr = NULL;
	CK_BYTE            *temp_byte;
	CK_ULONG           temp_bn_len ;

	DH                 *dh ;
	BIGNUM             *bn_p ;
	BIGNUM             *bn_g ;
	BIGNUM             *temp_bn ;

	rc  = template_attribute_find( publ_tmpl, CKA_PRIME, &prime_attr );
	rc &= template_attribute_find( publ_tmpl, CKA_BASE, &base_attr );

	if (rc == FALSE) {
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	if ((prime_attr->ulValueLen > 256) || (prime_attr->ulValueLen < 64))
	{
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	dh = DH_new() ;
	if (dh == NULL)
	{
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	// Create and init BIGNUM structs to stick in the DH struct
	bn_p = BN_new();
	bn_g = BN_new();
	if (bn_g == NULL || bn_p == NULL) {
		if (bn_g) BN_free(bn_g);
		if (bn_p) BN_free(bn_p);
		st_err_log(1, __FILE__, __LINE__);
		return CKR_HOST_MEMORY;
	}
	BN_init(bn_p);
	BN_init(bn_g);

	// Convert from strings to BIGNUMs and stick them in the DH struct
	BN_bin2bn((char *)prime_attr->pValue, prime_attr->ulValueLen, bn_p);
	dh->p = bn_p;
	BN_bin2bn((char *)base_attr->pValue, base_attr->ulValueLen, bn_g);
	dh->g = bn_g;

	// Generate the DH Key
	if (!DH_generate_key(dh))
	{
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	// Extract the public and private key components from the DH struct,
	// and insert them in the publ_tmpl and priv_tmpl

	//
	// pub_key
	//
	//temp_bn = BN_new();
	temp_bn = dh->pub_key;
	temp_bn_len = BN_num_bytes(temp_bn);
	temp_byte = malloc(temp_bn_len);
	temp_bn_len = BN_bn2bin(temp_bn, temp_byte);
	rc = build_attribute( CKA_VALUE, temp_byte, temp_bn_len, &temp_attr ); // in bytes
	if (rc != CKR_OK)
	{
		st_err_log(84, __FILE__, __LINE__);
		return CKR_FUNCTION_FAILED;
	}
	template_update_attribute( publ_tmpl, temp_attr );
	free(temp_byte);

	//
	// priv_key
	//
	//temp_bn = BN_new();
	temp_bn = dh->priv_key;
	temp_bn_len = BN_num_bytes(temp_bn);
	temp_byte = malloc(temp_bn_len);
	temp_bn_len = BN_bn2bin(temp_bn, temp_byte);
	rc = build_attribute( CKA_VALUE, temp_byte, temp_bn_len, &temp_attr ); // in bytes
	if (rc != CKR_OK)
	{
		st_err_log(84, __FILE__, __LINE__);
		return CKR_FUNCTION_FAILED;
	}
	template_update_attribute( priv_tmpl, temp_attr );
	free(temp_byte);

	// Update CKA_VALUE_BITS attribute in the private key
	value_bits_attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG) );
	value_bits_attr->type       = CKA_VALUE_BITS;
	value_bits_attr->ulValueLen = sizeof(CK_ULONG);
	value_bits_attr->pValue     = (CK_BYTE *)value_bits_attr + sizeof(CK_ATTRIBUTE);
	*(CK_ULONG *)value_bits_attr->pValue = 8*temp_bn_len;
	template_update_attribute( priv_tmpl, value_bits_attr );

	// Add prime and base to the private key template
	rc = build_attribute( CKA_PRIME,(char *)prime_attr->pValue,
			prime_attr->ulValueLen, &temp_attr ); // in bytes
	if (rc != CKR_OK)
	{
		st_err_log(84, __FILE__, __LINE__);
		return CKR_FUNCTION_FAILED;
	}
	template_update_attribute( priv_tmpl, temp_attr );

	rc = build_attribute( CKA_BASE,(char *)base_attr->pValue,
			base_attr->ulValueLen, &temp_attr ); // in bytes
	if (rc != CKR_OK)
	{
		st_err_log(84, __FILE__, __LINE__);
		return CKR_FUNCTION_FAILED;
	}
	template_update_attribute( priv_tmpl, temp_attr );

	// Cleanup DH key
	DH_free(dh) ;

	return CKR_OK ;

} /* end token_specific_dh_key_pair_gen() */
/* End code contributed by Corrent corp. */


