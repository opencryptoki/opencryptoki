#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"

CK_RV do_TestAttributes(void)
{

	CK_OBJECT_HANDLE	obj_handle;
	CK_SESSION_HANDLE	session;
	CK_RV			rc = 0;
	CK_FLAGS		flags;
	CK_BYTE			user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG		user_pin_len;

	CK_BYTE modulus[] =     { 0xa5,0x6e,0x4a,0x0e,0x70,0x10,0x17,0x58,
                                0x9a,0x51,0x87,0xdc,0x7e,0xa8,0x41,0xd1,
                                0x56,0xf2,0xec,0x0e,0x36,0xad,0x52,0xa4,
                                0x4d,0xfe,0xb1,0xe6,0x1f,0x7a,0xd9,0x91,
                                0xd8,0xc5,0x10,0x56,0xff,0xed,0xb1,0x62,
                                0xb4,0xc0,0xf2,0x83,0xa1,0x2a,0x88,0xa3,
                                0x94,0xdf,0xf5,0x26,0xab,0x72,0x91,0xcb,
                                0xb3,0x07,0xce,0xab,0xfc,0xe0,0xb1,0xdf,
                                0xd5,0xcd,0x95,0x08,0x09,0x6d,0x5b,0x2b,
                                0x8b,0x6d,0xf5,0xd6,0x71,0xef,0x63,0x77,
                                0xc0,0x92,0x1c,0xb2,0x3c,0x27,0x0a,0x70,
                                0xe2,0x59,0x8e,0x6f,0xf8,0x9d,0x19,0xf1,
                                0x05,0xac,0xc2,0xd3,0xf0,0xcb,0x35,0xf2,
                                0x92,0x80,0xe1,0x38,0x6b,0x6f,0x64,0xc4,
                                0xef,0x22,0xe1,0xe1,0xf2,0x0d,0x0c,0xe8,
                                0xcf,0xfb,0x22,0x49,0xbd,0x9a,0x21,0x37 };

	CK_BYTE publicExponent[] = { 0x01,0x00,0x01 };
	int modulus_len = 128;
	int publicExponent_len = 3;

	CK_OBJECT_CLASS		class = CKO_PUBLIC_KEY;
	CK_KEY_TYPE		keyType = CKK_RSA;
	CK_CHAR			label[] = "An RSA public key object";
	CK_CHAR			newlabel[] = "Updated RSA public key object";
	CK_CHAR			labelbuf[100];
	CK_BBOOL		false = FALSE;
	CK_BBOOL		boolval;

	CK_ATTRIBUTE	pub_template[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_KEY_TYPE, &keyType, sizeof(keyType)},
		{CKA_TOKEN, &false, sizeof(false)},
		{CKA_LABEL, label, sizeof(label)-1},
		{CKA_MODULUS, modulus, modulus_len},
		{CKA_PUBLIC_EXPONENT, publicExponent, publicExponent_len}
	};

	CK_ATTRIBUTE	new_attrs[] = {
		{CKA_ENCRYPT, &false, sizeof(false)},
		{CKA_WRAP, &false, sizeof(false)},
	};

	CK_ATTRIBUTE	update_label[] = {
		{CKA_LABEL, newlabel, sizeof(newlabel)-1},
	};

	CK_ATTRIBUTE	verify_attrs[] = {
		{CKA_ENCRYPT, &boolval, sizeof(boolval)},
		{CKA_WRAP, &boolval, sizeof(boolval)},
		{CKA_LABEL, labelbuf, sizeof(labelbuf)},
	};

	testcase_begin("starting...");
	testcase_rw_session();
	testcase_user_login();

	/* create a public key object */
	rc = funcs->C_CreateObject(session, pub_template, 6, &obj_handle);
	if (rc != CKR_OK) {
		testcase_fail("C_CreateObject() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/* Now add new attributes */
	rc = funcs->C_SetAttributeValue(session, obj_handle, new_attrs, 2);
	if (rc != CKR_OK) {
		testcase_fail("C_SetAttributeValue() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/* Now update an existing attribute */
	rc = funcs->C_SetAttributeValue(session, obj_handle, update_label, 1);
	if (rc != CKR_OK) {
		testcase_fail("C_SetAttributeValue() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/* Now get the attributes that were updated */
	rc = funcs->C_GetAttributeValue(session, obj_handle, verify_attrs, 3);
	if (rc != CKR_OK) {
		testcase_fail("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	/* verify the attribute values retrieved */
	if (*(CK_BBOOL *)verify_attrs[0].pValue != false)
		testcase_fail("CKA_ENCRYPT mismatch");

	if (*(CK_BBOOL *)verify_attrs[1].pValue != false)
		testcase_fail("CKA_WRAP mismatch");

	if (memcmp(verify_attrs[2].pValue, newlabel, verify_attrs[2].ulValueLen) != 0)
		testcase_fail("CKA_LABEL mismatch");

testcase_cleanup:

/*	rc = funcs->C_DestroyObject(session, obj_handle);
	if (rc != CKR_OK) {
		testcase_error("C_DestroyObject rc=%s", p11_get_ckr(rc));
	}
*/

	testcase_user_logout();
	rc = funcs->C_CloseSession(session);
	if (rc != CKR_OK) {
		testcase_error("C_CloseSessions rc=%s", p11_get_ckr(rc));
	}
	return rc;
}

int main  (int argc, char **argv) {
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

	rc = do_TestAttributes();
	testcase_print_result();

	/* make sure we return non-zero if rv is non-zero */
	return ((rv == 0) || (rv % 256) ? rv : -1);
}
