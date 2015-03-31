// File: ssl3_func.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"
#include "mech_to_str.h"

static CK_BBOOL  true  = TRUE;
static CK_BBOOL  false = FALSE;

//
//
CK_RV do_SignVerify_SSL3_MD5_MAC(CK_SESSION_HANDLE session)
{
	CK_MECHANISM      mech;
	CK_ULONG          mac_size;
	CK_ULONG          i;
	CK_RV             rc = CKR_OK;

	CK_OBJECT_HANDLE  h_key;
	CK_OBJECT_CLASS   key_class  = CKO_SECRET_KEY;
	CK_KEY_TYPE       key_type   = CKK_GENERIC_SECRET;
	CK_BBOOL          false      = FALSE;
	CK_BYTE           hash[MD5_HASH_LEN];
	CK_BYTE           data[50];
	CK_BYTE           data2[500];
	CK_BYTE           key_data[48];
	CK_ULONG          hash_len;
	CK_ULONG          data_len;
	CK_ATTRIBUTE      key_attribs[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
		{CKA_TOKEN, &false, sizeof(false)},
		{CKA_VALUE, &key_data, sizeof(key_data)}
	};
	CK_SLOT_ID        slot_id = SLOT_ID;

	testcase_begin("starting do_SignVerify_SSL3_MD5_MAC...\n");

	mac_size = 16;

	mech.mechanism      = CKM_SSL3_MD5_MAC;
	mech.ulParameterLen = sizeof(CK_ULONG);
	mech.pParameter     = &mac_size;


	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, mech.mechanism)){
		testsuite_skip(48, "Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(mech.mechanism),
			(unsigned int)mech.mechanism);
		goto skipped;
	}

	for (i=0; i < 48; i++)
		key_data[i] = i;

	memset(data, 0xb, 50);
	data_len = 50;

	rc = funcs->C_CreateObject(session, key_attribs, 4, &h_key);
	if (rc != CKR_OK) {
		testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
		return rc;
	}

	testcase_new_assertion();
	rc = funcs->C_SignInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		testcase_error("C_SignInit() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	hash_len = sizeof(hash);
	rc = funcs->C_Sign(session, data, data_len, hash, &hash_len);
	if (rc != CKR_OK) {
		testcase_fail("C_Sign() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	if (hash_len != mac_size) {
		testcase_fail("Error: C_Sign generated bad MAC length\n");
		goto done;
	} else
		testcase_pass("Successfully signed.");

	testcase_new_assertion();
	rc = funcs->C_VerifyInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_VerifyInit() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	rc = funcs->C_Verify(session, data, data_len, hash, hash_len);
	if (rc != CKR_OK)
		testcase_fail("C_Verify() rc = %s", p11_get_ckr(rc));
	else
		testcase_pass("Successfully verified.");

	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	// TESTCASE #2

	for (i=0; i < 48; i++)
		key_data[i] = i;

	memset(data2, 0xb, 500);
	data_len = 500;

	rc = funcs->C_CreateObject(session, key_attribs, 4, &h_key);
	if (rc != CKR_OK) {
		testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	testcase_new_assertion();
	rc = funcs->C_SignInit( session, &mech, h_key );
	if (rc != CKR_OK) {
		testcase_error("C_SignInit() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	for (i=0; i < 500; i+=100) {
		rc = funcs->C_SignUpdate(session, &data2[i], 100);
		if (rc != CKR_OK) {
			testcase_error("Iteration #%ld, C_SignUpdate() rc = %s", i / 100, p11_get_ckr(rc));
			goto done;
		}
	}

	hash_len = sizeof(hash);
	rc = funcs->C_SignFinal(session, hash, &hash_len);
	if (rc != CKR_OK) {
		testcase_error("C_SignFinal() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	if (hash_len != mac_size) {
		testcase_fail("Error: C_SignUpdate/Final generated bad MAC length\n");
		goto done;
	} else
		testcase_pass("Sucessfully signed in multipart.");

	testcase_new_assertion();
	rc = funcs->C_VerifyInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_VerifyInit() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	for (i=0; i < 500; i+=100) {
		rc = funcs->C_VerifyUpdate(session, &data2[i], 100);
		if (rc != CKR_OK) {
			testcase_error("Iteration #%ld, C_VerifyUpdate() rc = %s", i/100, p11_get_ckr(rc));
			goto done;
		}
	}

	rc = funcs->C_VerifyFinal( session, hash, hash_len );
	if (rc != CKR_OK)
		testcase_fail("C_VerifyFinal rc = %s", p11_get_ckr(rc));
	else
		testcase_pass("Successfully verified signature in multipart.");

done:
	if (funcs->C_DestroyObject(session, h_key) != CKR_OK)
		testcase_error("C_DestroyObject failed.");

skipped:
	return rc;
}


//
//
CK_RV do_SignVerify_SSL3_SHA1_MAC(CK_SESSION_HANDLE session)
{
	CK_MECHANISM      mech;
	CK_ULONG          mac_size;
	CK_ULONG          i;
	CK_RV             rc = CKR_OK;

	CK_OBJECT_HANDLE  h_key;
	CK_OBJECT_CLASS   key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE       key_type = CKK_GENERIC_SECRET;
	CK_BBOOL          false = FALSE;
	CK_BYTE           hash[SHA1_HASH_LEN];
	CK_BYTE           data[50];
	CK_BYTE           key_data[48];
	CK_ULONG          hash_len;
	CK_ULONG          data_len;
	CK_ATTRIBUTE      key_attribs[] =
	{
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
		{CKA_TOKEN, &false, sizeof(false)},
		{CKA_VALUE, &key_data, sizeof(key_data)}
	};
	CK_SLOT_ID        slot_id = SLOT_ID;

	testcase_begin("starting do_SignVerify_SSL3_SHA1_MAC...\n");

	mac_size = 20;

	mech.mechanism = CKM_SSL3_SHA1_MAC;
	mech.ulParameterLen = sizeof(CK_ULONG);
	mech.pParameter = &mac_size;

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, mech.mechanism)){
		testsuite_skip(48, "Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(mech.mechanism),
			(unsigned int)mech.mechanism);
		goto skipped;
	}

	for (i=0; i < 48; i++)
		key_data[i] = i;

	memset(data, 0xb, 50);
	data_len = 50;

	rc = funcs->C_CreateObject(session, key_attribs, 4, &h_key);
	if (rc != CKR_OK) {
		testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
		return rc;
	}

	testcase_new_assertion();
	rc = funcs->C_SignInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		testcase_fail("C_SignInit() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	hash_len = sizeof(hash);
	rc = funcs->C_Sign(session, data, data_len, hash, &hash_len);
	if (rc != CKR_OK) {
		testcase_fail("C_Sign() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	if (hash_len != mac_size) {
		testcase_fail("Error: C_Sign generated bad MAC length\n");
		goto done;
	} else
		testcase_pass("Successfully signed.");

	testcase_new_assertion();
	rc = funcs->C_VerifyInit(session, &mech, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_VerifyInit() rc = %s", p11_get_ckr(rc));
		goto done;
	}

	rc = funcs->C_Verify(session, data, data_len, hash, hash_len);
	if (rc != CKR_OK)
		testcase_fail("C_Verify() rc = %s", p11_get_ckr(rc));
	else
		testcase_pass("Successfully verified signature.");

done:
	if (funcs->C_DestroyObject(session, h_key) != CKR_OK)
		testcase_error("C_DestroyObject() failed.");

skipped:
	return rc;
}


//
//
CK_RV do_SSL3_PreMasterKeyGen(CK_SESSION_HANDLE session)
{
	CK_MECHANISM      mech;
	CK_VERSION        version;
	CK_OBJECT_HANDLE  h_key;
	CK_RV             rc = CKR_OK;
	CK_SLOT_ID        slot_id = SLOT_ID;

	testcase_begin("starting do_SSL3_PreMasterKeyGen...\n");

	version.major = 3;
	version.minor = 0;

	mech.mechanism      = CKM_SSL3_PRE_MASTER_KEY_GEN;
	mech.pParameter     = &version;
	mech.ulParameterLen = sizeof(CK_VERSION);

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, mech.mechanism)){
		testsuite_skip(1, "Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(mech.mechanism),
			(unsigned int)mech.mechanism);
		goto done;
	}

	testcase_new_assertion();
	rc = funcs->C_GenerateKey(session, &mech, NULL, 0, &h_key);
	if (rc != CKR_OK)
		testcase_fail("C_GenerateKey() rc = %s", p11_get_ckr(rc));
	else
		testcase_pass("Successfully generated a generic secret key.");

	if (funcs->C_DestroyObject(session, h_key) != CKR_OK)
		testcase_error("C_DestroyObject() failed");

done:
	return rc;
}


//
//
CK_RV do_SSL3_MasterKeyDerive(CK_SESSION_HANDLE session)
{
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_pm_secret;
	CK_OBJECT_HANDLE h_mk;
	CK_RV rc = CKR_OK;

	CK_VERSION version = { 3, 0 };
	CK_ATTRIBUTE pm_tmpl[] =
	{
		{CKA_SENSITIVE, &false, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &true, sizeof(CK_BBOOL)}
	};

	CK_BYTE  client_random_data[256];
	CK_BYTE  server_random_data[256];
	CK_ATTRIBUTE  m_tmpl[] =
	{
		{CKA_SENSITIVE, &true, sizeof(CK_BBOOL)},
		{CKA_EXTRACTABLE, &false, sizeof(CK_BBOOL)}
	};

	CK_SSL3_MASTER_KEY_DERIVE_PARAMS  mk_params;
	CK_ULONG i;

	CK_OBJECT_CLASS class;
	CK_KEY_TYPE keyType;
	CK_ATTRIBUTE  test_tmpl[] =
	{
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)}
	};
	CK_SLOT_ID        slot_id = SLOT_ID;
	
	testcase_begin("starting do_SSL3_MasterKeyDerive...\n");

	// generate the pre-master secret key
	//
	mech.mechanism      = CKM_SSL3_PRE_MASTER_KEY_GEN;
	mech.pParameter     = &version;
	mech.ulParameterLen = sizeof(CK_VERSION);

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, mech.mechanism)){
		testsuite_skip(32, "Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(mech.mechanism),
			(unsigned int)mech.mechanism);
		goto skipped;
	}

	testcase_new_assertion();
	rc = funcs->C_GenerateKey(session, &mech, pm_tmpl, 2, &h_pm_secret);
	if (rc != CKR_OK) {
		testcase_fail("C_GenerateKey() rc= %s", p11_get_ckr(rc));
		goto done;
	} else
		testcase_pass("Successfully generated a generic secret key.");

	// derive a master key
	//

	for (i=0; i < 32; i++) {
		client_random_data[i] = i;
		server_random_data[i] = 32 - i;
	}

	mk_params.pVersion = &version;

	mk_params.RandomInfo.pClientRandom = client_random_data;
	mk_params.RandomInfo.pServerRandom = server_random_data;
	mk_params.RandomInfo.ulClientRandomLen = 32;
	mk_params.RandomInfo.ulServerRandomLen = 32;

	mech.mechanism = CKM_SSL3_MASTER_KEY_DERIVE;
	mech.pParameter = &mk_params;
	mech.ulParameterLen = sizeof(CK_SSL3_MASTER_KEY_DERIVE_PARAMS);

	testcase_new_assertion();
	rc = funcs->C_DeriveKey(session, &mech, h_pm_secret, m_tmpl, 2, &h_mk);
	if (rc != CKR_OK) {
		testcase_fail("C_DeriveKey() rc= %s", p11_get_ckr(rc));
		goto done;
	} else
		testcase_pass("Successfully derived a key from pre-master.");

	/*	
	 * This mechanism provides the following attributes:
	 * CKA_CLASS = CKO_SECRET_KEY
	 * CKA_KEY_TYPE = CKK_GENERIC_SECRET
	 * CKA_VALUE_LEN = 48
	 * Check that the newly derived key has these.
	 */
	testcase_new_assertion();
	rc = funcs->C_GetAttributeValue(session, h_pm_secret, test_tmpl, 2);
	if (rc != CKR_OK) {
		testcase_error("C_GetAttributeValue() rc= %s", p11_get_ckr(rc));
		goto done;
	}
	if (*(CK_OBJECT_CLASS *)test_tmpl[0].pValue != CKO_SECRET_KEY) {
		testcase_fail("Derived key has incorrect class.");	
		goto done;
	}
	
	if (*(CK_KEY_TYPE *)test_tmpl[1].pValue != CKK_GENERIC_SECRET) {
		testcase_fail("Derived key has incorrect key type.");
		goto done;
	} else 
		testcase_pass("Derived key has correct attributes.");

done:
	if (funcs->C_DestroyObject(session, h_mk) != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

	if (funcs->C_DestroyObject(session, h_pm_secret) != CKR_OK)
		testcase_error("C_DestroyObject() failed");

skipped:
	return rc;
}

CK_RV do_SSL3_MultipleKeysDerive(CK_SESSION_HANDLE session)
{
	CK_MECHANISM mech;
	CK_OBJECT_HANDLE h_pm_secret;
	CK_RV rc = CKR_OK;
	CK_ULONG i;

	CK_VERSION version = { 3, 0 };
	CK_BBOOL true_value = TRUE;
	CK_BBOOL false_value = FALSE;
	CK_ATTRIBUTE pm_tmpl[] =
	{
		{CKA_TOKEN, &true_value, sizeof(true_value)},
	};

	CK_BYTE client_random_data[32];
	CK_BYTE server_random_data[32];
	CK_ATTRIBUTE  incomplete_tmpl[] =
	{
		{CKA_TOKEN, &false_value, sizeof(false_value)},
		{CKA_SENSITIVE, &false_value, sizeof(false_value)},
		{CKA_EXTRACTABLE, &true_value, sizeof(true_value)}
	};

	CK_OBJECT_CLASS class = CKO_SECRET_KEY;
	CK_KEY_TYPE key_type = CKK_AES;
	CK_ULONG key_len = 16;
	CK_ATTRIBUTE  complete_tmpl[] =
	{
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_KEY_TYPE, &key_type, sizeof(key_type)},
		{CKA_VALUE_LEN, &key_len, sizeof(CK_ULONG)},
		{CKA_TOKEN, &false_value, sizeof(false_value)},
		{CKA_SENSITIVE, &false_value, sizeof(false_value)},
		{CKA_EXTRACTABLE, &true_value, sizeof(true_value)}
	};

	CK_BYTE iv_client[128/8] = { 0, };
	CK_BYTE iv_server[128/8] = { 0, };

	CK_SSL3_KEY_MAT_OUT param_out = {
		.hClientMacSecret = 0,
		.hServerMacSecret = 0,
		.hClientKey = 0,
		.hServerKey = 0,
		.pIVClient = iv_client,
		.pIVServer = iv_server,
	};

	CK_SSL3_KEY_MAT_PARAMS params = {
		.ulMacSizeInBits = 128,
		.ulKeySizeInBits = key_len * 8,
		.ulIVSizeInBits = 128,
		.bIsExport = FALSE,
		.RandomInfo = {
			.pClientRandom = client_random_data,
			.ulClientRandomLen = sizeof(client_random_data),
			.pServerRandom = server_random_data,
			.ulServerRandomLen = sizeof(server_random_data),
		},
		.pReturnedKeyMaterial = &param_out,
	};
	CK_SLOT_ID        slot_id = SLOT_ID;

	testcase_begin("starting do_SSL3_MultipleKeysDerive...\n");

	// generate the pre-master secret key
	//
	mech.mechanism      = CKM_SSL3_PRE_MASTER_KEY_GEN;
	mech.pParameter     = &version;
	mech.ulParameterLen = sizeof(CK_VERSION);

	/** skip test if the slot doesn't support this mechanism **/
	if (! mech_supported(slot_id, mech.mechanism)){
		testsuite_skip(3, "Slot %u doesn't support %s (%u)",
			(unsigned int) slot_id,
			mech_to_str(mech.mechanism),
			(unsigned int)mech.mechanism);
		goto skipped;
	}

	testcase_new_assertion();
	rc = funcs->C_GenerateKey(session, &mech, pm_tmpl,
			sizeof(pm_tmpl)/sizeof(*pm_tmpl), &h_pm_secret);
	if (rc != CKR_OK) {
		testcase_fail("C_GenerateKey() rc= %s", p11_get_ckr(rc));
		goto done;
	} else
		testcase_pass("Successfully generated a generic secret key.");

	for (i = 0; i < sizeof(client_random_data); i++) {
		client_random_data[i] = i;
		server_random_data[i] = sizeof(client_random_data) - i;
	}

	mech.mechanism = CKM_SSL3_KEY_AND_MAC_DERIVE;
	mech.pParameter = &params;
	mech.ulParameterLen = sizeof(params);

	/* 
	 * Try deriving the key without required attributes...
	 */
	testcase_new_assertion();
	rc = funcs->C_DeriveKey(session, &mech, h_pm_secret, incomplete_tmpl,
			sizeof(incomplete_tmpl)/sizeof(*incomplete_tmpl), NULL);
	if (rc != CKR_TEMPLATE_INCOMPLETE) {
		testcase_fail("C_DeriveKey did not recognize missing attributes.");
		goto done;
	} else
		testcase_pass("Success, could not derive key without required attributes.");

	/*
	 * Now derive key with required attributes...
	 */
	
	testcase_new_assertion();
	rc = funcs->C_DeriveKey(session, &mech, h_pm_secret, complete_tmpl,
			sizeof(complete_tmpl)/sizeof(*complete_tmpl), NULL);
	if (rc != CKR_OK) {
		testcase_fail("C_DeriveKey() rc= %s", p11_get_ckr(rc));
		goto done;
	} else
		testcase_pass("Successfully derived a keys from pre-master.");


	if (funcs->C_DestroyObject(session, param_out.hClientMacSecret))
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
	if (funcs->C_DestroyObject(session, param_out.hServerMacSecret))
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
	if (funcs->C_DestroyObject(session, param_out.hClientKey))
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
	if (funcs->C_DestroyObject(session, param_out.hServerKey))
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

done:
	if (funcs->C_DestroyObject(session, h_pm_secret) != CKR_OK)
		testcase_error("C_DestroyObject() failed");

skipped:
	return rc;
}

CK_RV ssl3_functions()
{
	CK_RV rc;
	SYSTEMTIME t1, t2;
	CK_SLOT_ID slot_id = SLOT_ID;
	CK_SESSION_HANDLE session;
	CK_FLAGS flags;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;

	testcase_rw_session();
	testcase_user_login();

	GetSystemTime(&t1);
	rc = do_SSL3_PreMasterKeyGen(session);
	if (rc && !no_stop)
		goto testcase_cleanup;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_SSL3_MasterKeyDerive(session);
	if (rc && !no_stop)
		goto testcase_cleanup;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_SSL3_MultipleKeysDerive(session);
	if (rc && !no_stop)
		goto testcase_cleanup;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_SignVerify_SSL3_SHA1_MAC(session);
	if (rc && !no_stop)
		goto testcase_cleanup;
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_SignVerify_SSL3_MD5_MAC(session);
	if (rc && !no_stop)
		return rc;
	GetSystemTime(&t2);
	process_time( t1, t2 );

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		testcase_error("C_CloseSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;

	return rc;
}

int main(int argc, char **argv)
{
	CK_C_INITIALIZE_ARGS cinit_args;
	int rc;
	CK_RV rv;
	
	rc = do_ParseArgs(argc, argv);
	if ( rc != 1)
		return rc;
	
	printf("Using slot #%lu...\n\n", SLOT_ID );
	printf("With option: no_init: %d\n", no_init);

	rc = do_GetFunctionList();
	if (!rc) {
		PRINT_ERR("ERROR do_GetFunctionList() Failed , rc = 0x%0x\n", rc);
		return rc;
	}
	
	memset( &cinit_args, 0x0, sizeof(cinit_args) );
	cinit_args.flags = CKF_OS_LOCKING_OK;

	// SAB Add calls to ALL functions before the C_Initialize gets hit

	funcs->C_Initialize( &cinit_args );

	{
		CK_SESSION_HANDLE  hsess = 0;

		rc = funcs->C_GetFunctionStatus(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)  
			return rc;

		rc = funcs->C_CancelFunction(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

	}

	rv = ssl3_functions();
	testcase_print_result();

	/* make sure we return non-zero if rv is non-zero */
	return ((rv==0) || (rv % 256) ? rv : -1);
}
