#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"

/* API Routines exercised:
 * C_CreateObject
 * C_CopyObject
 * C_DestroyObject
 *
 * 3 TestCases
 * Setup: Create a key object. 
 * Testcase 1: Make an exact copy of the object with empty attribute list.
 * Testcase 2: make an exact copy of the object with one additional attribute.
 */

CK_RV do_CopyObjects(void)
{

	CK_FLAGS flags;
	CK_SESSION_HANDLE session;
	CK_RV rc = 0;
	CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG user_pin_len;

	CK_OBJECT_HANDLE keyobj, firstnewobj, secondnewobj, thirdnewobj;

	CK_BBOOL true = TRUE;
	CK_BBOOL false = FALSE;
	CK_KEY_TYPE aes_type = CKK_AES;
	CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
	CK_CHAR aes_value[] = "This is a fake aes key.";
	CK_ATTRIBUTE aes_tmpl[] = {
		{CKA_CLASS, &key_class, sizeof(key_class)},
		{CKA_KEY_TYPE, &aes_type, sizeof(aes_type)},
		{CKA_VALUE, &aes_value, sizeof(aes_value)},
		{CKA_SENSITIVE, &true, sizeof(true)}
	};

	CK_KEY_TYPE new_aes_type;
	CK_OBJECT_CLASS new_key_class;
	CK_CHAR new_aes_value[50];
	CK_ATTRIBUTE test_tmpl[] = {
		{CKA_CLASS, &new_key_class, sizeof(new_key_class)},
		{CKA_KEY_TYPE, &new_aes_type, sizeof(new_aes_type)},
		{CKA_VALUE, &new_aes_value, sizeof(new_aes_value)},
		{CKA_SENSITIVE, &true, sizeof(true)}
	};

	CK_ATTRIBUTE copy_tmpl[] = {
		{CKA_TOKEN, &true, sizeof(true)}
	};

	CK_ATTRIBUTE false_sensitive_tmpl[] = {
		{CKA_SENSITIVE, &false, sizeof(false)}
	};

	CK_ATTRIBUTE empty_tmpl[] = { };

	// Do some setup and login to the token
	testcase_begin("starting...");
	testcase_rw_session();
	testcase_user_login();

	// Create an AES Key Object.
	rc = funcs->C_CreateObject(session, aes_tmpl, 3, &keyobj);
	if (rc != CKR_OK) {
		testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	// Testcase #1 - Copy object exactly with no additional attributes.

	// Now copy the object, without any attributes.
	rc = funcs->C_CopyObject(session, keyobj, empty_tmpl, 0, &firstnewobj);
	if (rc != CKR_OK) {
		testcase_fail("C_CopyObject() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	// Verify that new object has same attribute values as original.
	rc = funcs->C_GetAttributeValue(session, firstnewobj, test_tmpl, 3);
	if (rc != CKR_OK) {
		testcase_fail("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	// Step thru template to see if new object matches original...
	if ((memcmp
	     (test_tmpl[0].pValue, aes_tmpl[0].pValue,
	      aes_tmpl[0].ulValueLen) == 0)
	    &&
	    (memcmp
	     (test_tmpl[1].pValue, aes_tmpl[1].pValue,
	      aes_tmpl[1].ulValueLen) == 0)
	    &&
	    (memcmp
	     (test_tmpl[2].pValue, aes_tmpl[2].pValue,
	      aes_tmpl[2].ulValueLen) == 0)
	    &&
	    (memcmp
	     (test_tmpl[3].pValue, aes_tmpl[3].pValue,
	      aes_tmpl[3].ulValueLen) == 0))
		testcase_pass("Copied object's attributes are the same.");
	else
		testcase_fail("Copied object's attributes are different.");

	// Testcase #2 - Copy an object and include one additional attribute.

	rc = funcs->C_CopyObject(session, keyobj, copy_tmpl, 1, &secondnewobj);
	if (rc != CKR_OK) {
		testcase_fail("C_CopyObject() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	// Verify that new object has the new attribute and value (CKA_TOKEN).
	// NOTE: Since passing in same template, original value will be
	//       over-written.
	rc = funcs->C_GetAttributeValue(session, secondnewobj, copy_tmpl, 1);
	if (rc != CKR_OK) {
		testcase_fail("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	if (*(CK_BBOOL *) copy_tmpl[0].pValue == TRUE)
		testcase_pass("Copied object's attributes are the same.");
	else
		testcase_fail("Copied object's attributes are different.");

	// Testcase #3 - Copy object changing the value of CKA_SENSITIVE to FALSE
	
	CK_ATTRIBUTE tmp2_tmpl[] = {
		{CKA_SENSITIVE, &true, sizeof(true)}
	};

	rc = funcs->C_CopyObject(session, keyobj, false_sensitive_tmpl, 1, &thirdnewobj);
	if (rc != CKR_OK) {
		testcase_fail("C_CopyObject() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	// Verify that new object has the new attribute and value (CKA_SENSITIVE).
	// NOTE: Since passing in same template, original value will be
	//       over-written.
	rc = funcs->C_GetAttributeValue(session, thirdnewobj, tmp2_tmpl, 1);
	if (rc != CKR_OK) {
		testcase_fail("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	if (*(CK_BBOOL *) tmp2_tmpl[0].pValue == TRUE){
		testcase_pass("Copied object's attributes are different.");
	} else if (*(CK_BBOOL *) tmp2_tmpl[0].pValue == FALSE) {
		testcase_fail("Copied object's attributes are the same.");
	}

testcase_cleanup:
	rc = funcs->C_DestroyObject(session, keyobj);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

	rc = funcs->C_DestroyObject(session, firstnewobj);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

	rc = funcs->C_DestroyObject(session, secondnewobj);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

	rc = funcs->C_DestroyObject(session, thirdnewobj);
	if (rc != CKR_OK)
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));

	testcase_user_logout();
	rc = funcs->C_CloseSession(session);
	if (rc != CKR_OK) {
		testcase_error("C_CloseSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

int main(int argc, char **argv)
{
	int rc;
	CK_C_INITIALIZE_ARGS cinit_args;
	CK_RV rv = 0;

	rc = do_ParseArgs(argc, argv);
	if (rc != 1)
		return rc;

	printf("Using slot #%lu...\n\n", SLOT_ID);
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
		CK_SESSION_HANDLE hsess = 0;

		rc = funcs->C_GetFunctionStatus(hsess);
		if (rc != CKR_FUNCTION_NOT_PARALLEL)
			return rc;

		rc = funcs->C_CancelFunction(hsess);
		if (rc != CKR_FUNCTION_NOT_PARALLEL)
			return rc;
	}

	rc = do_CopyObjects();
	testcase_print_result();

	/* make sure we return non-zero if rv is non-zero */
	return ((rv == 0) || (rv % 256) ? rv : -1);
}
