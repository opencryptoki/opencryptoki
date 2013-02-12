#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"

/* API Routines exercised:
 * C_FindObjectsInit
 * C_FindObjects
 * C_CreateObject
 *
 * 3 TestCases
 * Setup: Create 2 3des objects and 2 aes private objects
 * Testcase 1: Find only the 3des key objects.
 * Testcase 2: Find only the aes session objects that were created.
 * Testcase 3: Find all the objects.
 */

CK_RV do_FindObjects(void)
{
	CK_FLAGS          flags;
	CK_SESSION_HANDLE session;
	CK_RV             rc = 0;
	CK_BYTE           user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG          user_pin_len;

	CK_ULONG		find_count;
	CK_OBJECT_HANDLE	keyobj[4];
	CK_OBJECT_HANDLE	obj_list[10];

	CK_ULONG not_found = 0;
	CK_ULONG num_objs = 0;
	CK_ULONG i;

	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_KEY_TYPE aes_type = CKK_AES;
	CK_KEY_TYPE des3_type = CKK_DES3;
	CK_BBOOL false = FALSE;
	CK_CHAR aes_value[] = "This is a fake aes key.";
	CK_CHAR des3_value[] = "This is a fake des key.";
	CK_CHAR test1_id[] = "My Testcase 1 keys.";
	CK_CHAR test2_id[] = "My Testcase 2 keys.";

	CK_ATTRIBUTE des3_tmpl[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_KEY_TYPE, &des3_type, sizeof(des3_type)},
		{CKA_ID, &test1_id, sizeof(test1_id)},
		{CKA_VALUE, &des3_value, sizeof(des3_value)}
	};

	CK_ATTRIBUTE aes_tmpl[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_KEY_TYPE, &aes_type, sizeof(aes_type)},
		{CKA_PRIVATE, &false, sizeof(false)},
		{CKA_ID, &test2_id, sizeof(test2_id)},
		{CKA_VALUE, &aes_value, sizeof(aes_value)}
	};

	CK_ATTRIBUTE search_des3_tmpl[] = {
		{CKA_KEY_TYPE, &des3_type, sizeof(des3_type)},
		{CKA_ID, &test1_id, sizeof(test1_id)}
	};

	CK_ATTRIBUTE search_tmpl[] = {
		{CKA_KEY_TYPE, &aes_type, sizeof(aes_type)},
		{CKA_ID, &test2_id, sizeof(test2_id)},
	};


	testcase_begin("starting...");
	testcase_rw_session();
	testcase_user_login();

	/* Create 2 des3 session key objects */
	rc = funcs->C_CreateObject(session, des3_tmpl, 4, &keyobj[num_objs]);
	if (rc != CKR_OK) {
		testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
		return rc;
	}
	num_objs++;

	rc = funcs->C_CreateObject(session, des3_tmpl, 4, &keyobj[num_objs]);
	if (rc != CKR_OK) {
		testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	num_objs++;

	/* Create 2 aes private session key objects */
	rc = funcs->C_CreateObject(session, aes_tmpl, 5, &keyobj[num_objs]);
	if (rc != CKR_OK) {
		testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	num_objs++;

	rc = funcs->C_CreateObject(session, aes_tmpl, 5, &keyobj[num_objs]);
	if (rc != CKR_OK) {
		testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/* Testcase 1: Now find the the 2 des3 key objects */
	rc = funcs->C_FindObjectsInit(session, search_des3_tmpl, 2);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjectsInit() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_FindObjects(session, obj_list, 10, &find_count);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjects() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/* We should have gotten back 2 des3 key objects */
	if (find_count != 2) {
		testcase_fail("Should have found 2 des3 key objects, found %d", (int)find_count);
		goto testcase_cleanup;
	}

	/* Examine the 2 objects... */
	for (i = 0; i < find_count; i++) {
		if ((obj_list[i] != keyobj[0]) && (obj_list[i] != keyobj[1]))
			not_found++;
	}

	rc = funcs->C_FindObjectsFinal(session);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjectsFinal() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	if (not_found) {
		testcase_fail("Wrong objects found!");
		goto testcase_cleanup;
	} else
		testcase_pass("Found the 2 des3 key objects.");


	/* Testcase 2: Now find 2 aes keys with aes_id. */
	/* Note in ICSF, all secret keys are marked private by default. */
	not_found = 0;
	find_count = 0;

	rc = funcs->C_FindObjectsInit(session, search_tmpl, 2);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjectsInit() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_FindObjects(session, obj_list, 10, &find_count);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjects() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/* We should have gotten back 2 key objects */
	if (find_count != 2) {
		testcase_fail("Should have found 2 key objects, found %d", (int)find_count);
		goto testcase_cleanup;
	}

	/* Examine the 2 objects... */
	for (i = 0; i < find_count; i++) {
		if ((obj_list[i] != keyobj[2]) && (obj_list[i] != keyobj[3]))
			not_found++;
	}

	rc = funcs->C_FindObjectsFinal(session);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjectsFinal() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	if (not_found) {
		testcase_fail("Wrong objects found!");
		goto testcase_cleanup;
	} else
		testcase_pass("Found the 2 non-private objects.");

	/* Testcase 3: Find all the objects */
	not_found = 0;
	find_count = 0;

	rc = funcs->C_FindObjectsInit(session, NULL, 0);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjectsInit() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_FindObjects(session, obj_list, 10, &find_count);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjects() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_FindObjectsFinal(session);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjectsFinal() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/* We should have gotten back 4 key objects
	 * testing for more than 4 just in case some other pkcs#11 app is
	 * running.
	 */
	if (find_count < 4) {
		testcase_fail("Should have found at least 6 objects, found %d", (int)find_count);
		goto testcase_cleanup;
	} else
		testcase_pass("Found all the objects.");

testcase_cleanup:

/*	for (i=0; i<num_objs; i++)
		funcs->C_DestroyObject(session, keyobj[i]);
*/

	testcase_user_logout();
	rc = funcs->C_CloseSession(session);
	if (rc != CKR_OK) {
		testcase_error("C_CloseSession rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

int
main(int argc, char **argv)
{
	int rc;
	CK_C_INITIALIZE_ARGS cinit_args;
	CK_RV rv = 0;

	rc = do_ParseArgs(argc, argv);
	if (rc != 1)
		return rc;

	printf("Using slot #%lu...\n\n", SLOT_ID );
	printf("With option: nostop: %d\n", no_stop);

	rc = do_GetFunctionList();
	if (!rc) {
		testcase_error("do_getFunctionList(), rc=%s", p11_get_ckr(rc));
		return rc;
	}

	memset( &cinit_args, 0x0, sizeof(cinit_args) );
	cinit_args.flags = CKF_OS_LOCKING_OK;

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

	rc = do_FindObjects();
	testcase_print_result();

	/* make sure we return non-zero if rv is non-zero */
	return ((rv == 0) || (rv % 256) ? rv : -1);
}
