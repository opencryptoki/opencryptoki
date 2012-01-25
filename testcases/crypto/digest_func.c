#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "digest.h"
#include "common.c"

#define MAX_HASH_LEN	512

/** Tests messge digest with published test vectors. **/
CK_RV do_Digest(struct digest_test_suite_info *tsuite)
{

	int		i;
	CK_BYTE		data[MAX_DATA_SIZE];
	CK_ULONG	data_len;
	CK_BYTE		actual[MAX_HASH_SIZE];
	CK_ULONG	actual_len;
	CK_BYTE		expected[MAX_HASH_SIZE];
	CK_ULONG	expected_len;
	CK_MECHANISM	mech;

	CK_SESSION_HANDLE       session;
	CK_SLOT_ID		slot_id = SLOT_ID;
	CK_ULONG		flags;
	CK_RV		   	rc;


	/** begin test suite **/
	testsuite_begin("%s Digest.", tsuite->name);
	testcase_rw_session();

	/** skip test if mech is not supported with this slot **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"mechanism %s is not supported with slot %ld",
			 tsuite->name, slot_id);
		goto testcase_cleanup;
	}

	/** iterate over test vectors **/
	for(i = 0; i < tsuite->tvcount; i++){

		rc = CKR_OK;    // set rc

		/** clear buffers **/
		memset(data, 0, sizeof(data));
		memset(actual, 0, sizeof(actual));
		memset(expected, 0, sizeof(expected));

		/** get test vector info **/
		data_len = tsuite->tv[i].data_len;
		expected_len = tsuite->tv[i].hash_len;
		memcpy(data, tsuite->tv[i].data, data_len);
		memcpy(expected, tsuite->tv[i].hash, expected_len);

		/** get mech **/
		mech = tsuite->mech;

		/** initialize single digest **/
		rc = funcs->C_DigestInit(session, &mech);
		if (rc != CKR_OK) {
			testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		actual_len = sizeof(actual);    // set digest buffer size

		/** do single digest **/
		rc = funcs->C_Digest(session, data, data_len, actual, &actual_len);
		if (rc != CKR_OK) {
			testcase_error("C_Digest rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** compare digest results with expected results **/
		testcase_new_assertion();

		if (actual_len != expected_len) {
			testcase_fail("hashed data length does not match test vector's"					" hashed data length.\nexpected length=%ld, found "
				 "length=%ld.", expected_len, actual_len);
			}

		else if (memcmp(actual, expected, expected_len)){
			testcase_fail("hashed data does not match test vector's"
				" hashed data.");
		}

		else {
			testcase_pass("%s Digest with test vector %d passed.",
				tsuite->name, i);
		}
	}

testcase_cleanup:
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

/** Tests multipart message digest with published test vectors. **/
CK_RV do_DigestUpdate(struct digest_test_suite_info *tsuite)
{
	int		i;
	CK_BYTE		data[MAX_DATA_SIZE];
	CK_ULONG	data_len;
	CK_BYTE		actual[MAX_HASH_SIZE];
	CK_ULONG	actual_len;
	CK_BYTE		expected[MAX_HASH_SIZE];
	CK_ULONG	expected_len;
	CK_MECHANISM	mech;

	CK_SESSION_HANDLE       session;
	CK_SLOT_ID	      	slot_id = SLOT_ID;
	CK_ULONG		flags;
	CK_RV		   	rc;

	/** begin test **/
	testsuite_begin("Starting %s Multipart Digest.", tsuite->name);
	testcase_rw_session();

	/** skip test if mech is not supported with this slot **/
	if (! mech_supported(slot_id, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"mechanism %s is not supported with slot %ld",
			tsuite->name, slot_id);
		goto testcase_cleanup;
	}

	/** iterate over test vectors **/
	for(i = 0; i < tsuite->tvcount; i++){

		/** begin test **/
		testcase_begin("Starting %s Multipart Digest with test vector %d.",
			tsuite->name, i);

		rc = CKR_OK;    // set rc

		/** clear buffers **/
		memset(data, 0, sizeof(data));
		memset(actual, 0, sizeof(actual));
		memset(expected, 0, sizeof(expected));

		/** get test vector info **/
		data_len = tsuite->tv[i].data_len;
		expected_len = tsuite->tv[i].hash_len;
		memcpy(data, tsuite->tv[i].data, data_len);
		memcpy(expected, tsuite->tv[i].hash, expected_len);

		/** get mechanism **/
		mech = tsuite->mech;

		/** initialize multipart digest **/
		rc = funcs->C_DigestInit(session, &mech);
		if (rc != CKR_OK) {
			testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		actual_len = sizeof(actual);

		/** do multipart digest **/
		if (data_len > 0) {
			rc = funcs->C_DigestUpdate(session, &data[0], data_len);
			if (rc != CKR_OK) {
				testcase_error("C_DigestUpdate rc=%s",
					p11_get_ckr(rc));
				goto testcase_cleanup;
			}
		}

		/** finalize multipart digest **/
		rc = funcs->C_DigestFinal(session, actual, &actual_len);
		if (rc != CKR_OK) {
			testcase_error("C_DigestFinal rc=%s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}

		/** compare multipart digest results with expected results **/
		testcase_new_assertion();

		if (actual_len != expected_len) {
			testcase_fail("hashed multipart data length does not "
				"match test vector's hashed data length.\n");
		}

		else if (memcmp(actual, expected, expected_len)){
			testcase_fail("hashed multipart data does not match "
				"test vector's hashed data.\n");
		}

		else {
			testcase_pass("%s Multipart Digest with test vector "
				"%d passed.", tsuite->name, i);
		}

	}

testcase_cleanup:
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

/** Tests signature verification with published test vectors. **/
CK_RV do_SignVerify_HMAC(struct HMAC_TEST_SUITE_INFO *tsuite){

	int	     	i;
	CK_MECHANISM    mech;
	CK_BYTE	 	key[MAX_KEY_SIZE];
	CK_ULONG	key_len;
	CK_BYTE	 	data[MAX_DATA_SIZE];
	CK_ULONG	data_len;
	CK_BYTE	 	actual[MAX_HASH_SIZE];
	CK_ULONG	actual_len;
	CK_BYTE	 	expected[MAX_HASH_SIZE];
	CK_ULONG	expected_len;

	CK_SESSION_HANDLE 	session;
	CK_SLOT_ID		slot_id = SLOT_ID;
	CK_ULONG	  	flags;
	CK_RV	     		rc;
	CK_OBJECT_HANDLE  	h_key;

	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len;

	/** begin testsuite **/
	testsuite_begin("%s Sign Verify.", tsuite->name);
	testcase_rw_session();
	testcase_user_login();

	rc = CKR_OK;    // set rc

	/** skip test if mech is not supported with this slot **/
	if (! mech_supported(SLOT_ID, tsuite->mech.mechanism)){
		testsuite_skip(tsuite->tvcount,
			"mechanism %s is not supported with slot %ld",
			tsuite->name, slot_id);
		goto testcase_cleanup;
	}

	/** iterate over test vectors **/
	for(i = 0; i < tsuite->tvcount; i++){

		/** begin test **/
		testcase_begin("Sign Verify %s with test vector %d.",
			tsuite->name, i);

		/** clear buffers **/
		memset(key, 0, sizeof(key));
		memset(data, 0, sizeof(data));
		memset(actual, 0, sizeof(actual));
		memset(expected, 0, sizeof(expected));

		/** get test vector info **/
		key_len = tsuite->tv[i].key_len;
		data_len = tsuite->tv[i].data_len;
		actual_len = sizeof(actual);
		expected_len = tsuite->tv[i].hash_len;
		memcpy(key, tsuite->tv[i].key, key_len);
		memcpy(data, tsuite->tv[i].data, data_len);
		memcpy(expected, tsuite->tv[i].result, expected_len);

		/** get mechanism **/
		mech = tsuite->mech;

		/** create key object **/
		rc = create_GenericSecretKey(session, key, key_len, &h_key);
		if(rc != CKR_OK){
			testcase_error("create_GenericSecretKey rc=%s",
				p11_get_ckr(rc));
			goto error;
		}

		/** initialize signing **/
		rc = funcs->C_SignInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** do signing  **/
		rc = funcs->C_Sign(session,
				data,
				data_len,
				actual,
				&actual_len);

		if (rc != CKR_OK) {
			testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** initilaize verification **/
		rc = funcs->C_VerifyInit(session, &mech, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** do verification **/
		rc = funcs->C_Verify(session,
				data,
				data_len,
				actual,
				actual_len);

		if (rc != CKR_OK) {
			testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
			goto error;
		}

		/** compare sign/verify results with expected results **/
		testcase_new_assertion();

		if(actual_len != expected_len){
			testcase_fail("hashed data length does not match test "
				"vector's hashed data length\nexpected length="
				"%ld, found length=%ld",
				expected_len, actual_len);
		}

		else if(memcmp(actual, expected, expected_len)){
			testcase_fail("hashed data does not match test "
				"vector's hashed data");
		}

		else {
			testcase_pass("%s Sign Verify with test vector %d "
				"passed.", tsuite->name, i);
		}

		/** clean up **/
		rc = funcs->C_DestroyObject(session, h_key);
		if (rc != CKR_OK) {
			testcase_error("C_DestroyObject rc=%s.",
				p11_get_ckr(rc));
			goto testcase_cleanup;
		}
	}
	goto testcase_cleanup;

error:
	rc = funcs->C_DestroyObject(session, h_key);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
	}

testcase_cleanup:
	testcase_user_logout();
	rc = funcs->C_CloseAllSessions(slot_id);
	if (rc != CKR_OK) {
		testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

CK_RV digest_funcs() {
	CK_RV rc;
	int i;

	/** Digest tests **/
	for (i = 0; i < NUM_DIGEST_TEST_SUITES; i++){
		rc = do_Digest(&digest_test_suites[i]);
		if (rc && !no_stop) {
			return rc;
		}
	}

	/** Multipart Digest tests **/
	for (i = 0; i < NUM_DIGEST_TEST_SUITES; i++){
		rc = do_DigestUpdate(&digest_test_suites[i]);
		if (rc && !no_stop) {
			return rc;
		}
	}
	/** HMAC tests **/
	for(i = 0; i < NUM_OF_HMAC_TEST_SUITES; i++){
		rc = do_SignVerify_HMAC(&hmac_test_suites[i]);
		if (rc && !no_stop) {
			return rc;
		}
	}

	return rc;
}

int main(int argc, char **argv)
{
	CK_C_INITIALIZE_ARGS cinit_args;
	int rc;
	CK_BBOOL no_init, no_stop;
	CK_RV rv;

	SLOT_ID = 0;
	no_init = FALSE;
	no_stop = FALSE;


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
	testcase_setup(0); //TODO
	rv = digest_funcs();
	testcase_print_result();
	/* make sure we return non-zero if rv is non-zero */
	return ((rv==0) || (rv % 256) ? rv : -1);
}
