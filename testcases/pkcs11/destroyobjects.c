#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"


/* API Routines exercised:
 * C_DestroyObject
 *
 * TestCases
 * Setup: Create several key objects and generate several key objects.
 * Testcase 1: Destroy only a few objects. Verify they were deleted.
 * Testcase 2: Verify the other objects were not deleted.
 * Testcase 3: Destroy all objects and verify all were removed.
 */

CK_RV do_DestroyObjects(void)
{
	CK_FLAGS          flags;
	CK_SESSION_HANDLE session;
	CK_RV             rc = 0;
	CK_BYTE           user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG          user_pin_len;
	CK_OBJECT_HANDLE  keyobj[8];
	CK_OBJECT_HANDLE  obj_list[10];
	CK_ULONG	  i, num_objs=0, find_count, found=0;
	CK_MECHANISM	  mech;

	CK_BBOOL true = TRUE;
	CK_KEY_TYPE aes_type = CKK_AES;
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_CHAR aes_value[] = "This is a fake aes key.";
	CK_CHAR test_id[5] = "abcde";
	CK_ULONG aesgen_keylen = 32;

	CK_ATTRIBUTE aes_tmpl[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_KEY_TYPE, &aes_type, sizeof(aes_type)},
		{CKA_ID, &test_id, sizeof(test_id)},
		{CKA_VALUE, &aes_value, sizeof(aes_value)}
	};

	CK_ATTRIBUTE aesgen_tmpl[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_KEY_TYPE, &aes_type, sizeof(aes_type)},
		{CKA_ID, &test_id, sizeof(test_id)},
		{CKA_VALUE_LEN, &aesgen_keylen, sizeof(aesgen_keylen)},
		{CKA_TOKEN, &true, sizeof(true)}
	};

	CK_ATTRIBUTE find_tmpl[] = {
		{CKA_KEY_TYPE, &aes_type, sizeof(aes_type)},
		{CKA_ID, &test_id, sizeof(test_id)}
	};

	testcase_begin("starting...");
	testcase_rw_session();
	testcase_user_login();

	/* Create a few  session key objects */
	for (i = 0; i < 4; i++) {
		rc = funcs->C_CreateObject(session, aes_tmpl, 4, &keyobj[num_objs]);
		if (rc != CKR_OK) {
			testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}
		num_objs++;
	}

	/* Generate a few token key objects */
	mech.mechanism = CKM_AES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

	for (i = 4; i < 8; i++) {
		rc = funcs->C_GenerateKey(session, &mech, aesgen_tmpl, 5, &keyobj[num_objs]);
		if (rc != CKR_OK) {
			testcase_error("C_GenerateObject() rc = %s", p11_get_ckr(rc));
			goto testcase_cleanup;
		}
		num_objs++;
	}

	/* Now delete 2 session key objects */
	rc = funcs->C_DestroyObject(session, keyobj[7]);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjects() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	num_objs--;

	rc = funcs->C_DestroyObject(session, keyobj[6]);
	if (rc != CKR_OK) {
		testcase_fail("C_FindObjects() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	num_objs--;

	/* Now see if only 2 session key objects were destroyed */
	rc = funcs->C_FindObjectsInit(session, find_tmpl, 2);
	if (rc != CKR_OK) {
		testcase_error("C_FindObjectsInit() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_FindObjects(session, obj_list, 10, &find_count);
	if (rc != CKR_OK) {
		testcase_error("C_FindObjects() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_FindObjectsFinal(session);
	if (rc != CKR_OK) {
		testcase_error("C_FindObjectsFinal() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/* Testcase 1: step thru and see if objects were deleted. */
	if (find_count != 6) {
		testcase_fail("Did not find 6 objects!");
		goto testcase_cleanup;
	}

	for (i = 0; i < find_count; i++) {
		if ((obj_list[i] == keyobj[6]) || (obj_list[i] == keyobj[7]))
			found++;
	}

	if (found) {
		testcase_fail("Objects were not deleted.");
		goto testcase_cleanup;
	} else
		testcase_pass("The 2 objects were successfully deleted.");

	/* Testcase 2: Now make sure the other objects are still there */

	for (i = 0; i < find_count; i++) {
		if ((obj_list[i] == keyobj[0]) || (obj_list[i] == keyobj[1]) ||
		   (obj_list[i] == keyobj[2]) || (obj_list[i] == keyobj[3]) ||
		   (obj_list[i] == keyobj[4]) || (obj_list[i] == keyobj[5]))
			found++;
	}

	if (found != 6) {
		testcase_fail("Some Objects were not found!");
		goto testcase_cleanup;
	} else
		testcase_pass("The other objects are intact.");

	/* Testcase 3: Remove all the objects */
	find_count = 0;

	/* Now delete the rest of the objects */
	for (i = 0; i < num_objs; i++)
		funcs->C_DestroyObject(session, keyobj[i]);

	/* Now see if all the objects were deleted. */
	rc = funcs->C_FindObjectsInit(session, find_tmpl, 2);
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

	if (find_count) {
		testcase_fail("The remaining objects were not deleted.");
		goto testcase_cleanup;
	} else
		testcase_pass("All objects were deleted.");

testcase_cleanup:

	if (num_objs) {
		for (i = 0; i < num_objs; i++)
			funcs->C_DestroyObject(session, keyobj[i]);
	}

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

	memset(&cinit_args, 0x0, sizeof(cinit_args));
	cinit_args.flags = CKF_OS_LOCKING_OK;

	funcs->C_Initialize(&cinit_args);

	{
		CK_SESSION_HANDLE  hsess = 0;

		rc = funcs->C_GetFunctionStatus(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

		rc = funcs->C_CancelFunction(hsess);
		if (rc  != CKR_FUNCTION_NOT_PARALLEL)
			return rc;
	}

	rc = do_DestroyObjects();
	testcase_print_result();

	/* make sure we return non-zero if rv is non-zero */
	return ((rv == 0) || (rv % 256) ? rv : -1);
}
