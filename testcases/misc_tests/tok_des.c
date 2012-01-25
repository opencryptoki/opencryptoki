// File: driver.c
//
//
// Test driver.  In-depth regression test for PKCS #11
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include <dlfcn.h>
#include <sys/timeb.h>

#include "pkcs11types.h"
#include "regress.h"

int do_GetFunctionList(void);

CK_FUNCTION_LIST  *funcs;
CK_SLOT_ID  SLOT_ID;

CK_RV
do_VerifyTokenSymKey(CK_SESSION_HANDLE sess, CK_BYTE *label)
{
	CK_OBJECT_HANDLE    obj_handles[20];
	CK_ULONG	    pulCount = 0, obj_class = CKO_SECRET_KEY, i;
	CK_RV               rv;
	CK_BBOOL	    true = 1;

	printf("do_VerifyTokenSymKey...\n");

	/* Find token objects based on the label */
	{
		CK_ATTRIBUTE tmpl[] =
		{
			{CKA_LABEL, label, (CK_ULONG)strlen((char *)label) + 1 },
			{CKA_TOKEN, &true, sizeof(CK_BBOOL) },
			{CKA_CLASS, &obj_class, sizeof(obj_class) }
		};

		rv = funcs->C_FindObjectsInit(sess, tmpl, 3);
		if (rv != CKR_OK) {
			show_error("   C_FindObjectsInit #1", rv );
			return rv;
		}
		rv = funcs->C_FindObjects(sess, obj_handles, 20, &pulCount);
		if (rv != CKR_OK) {
			show_error("   C_FindObjects #1", rv );
			return rv;
		}
		rv = funcs->C_FindObjectsFinal(sess);
		if (rv != CKR_OK) {
			show_error("   C_FindObjectsFinal #1", rv );
			return rv;
		}
	}

	for (i = 0; i < pulCount; i++) {
		CK_ULONG valueLen = 0;
		CK_BYTE value[256] = { 0, };
		CK_ATTRIBUTE tmpl[] = {
			{CKA_VALUE, NULL, valueLen }
		};

		rv = funcs->C_GetAttributeValue(sess, obj_handles[i], tmpl, 1);
		if (rv != CKR_OK) {
			show_error("   C_GetAttributeValue #1", rv );
			return rv;
		}

		tmpl[0].pValue = value;

		rv = funcs->C_GetAttributeValue(sess, obj_handles[i], tmpl, 1);
		if (rv != CKR_OK) {
			show_error("   C_GetAttributeValue", rv );
			return rv;
		}

		/* The public exponent is element 0 and modulus is element 1 */
		if (tmpl[0].ulValueLen > 256 || tmpl[0].ulValueLen < 8) {
			PRINT_ERR("secret key value (%lu) OOB!", tmpl[1].ulValueLen);
			return CKR_FUNCTION_FAILED;
		}

		printf("%lu byte secret key found.\nValue:\n", tmpl[0].ulValueLen);
		print_hex(tmpl[0].pValue, tmpl[0].ulValueLen);

		rv = funcs->C_DestroyObject(sess, obj_handles[i]);
		if (rv != CKR_OK) {
			show_error("   C_DestroyObject", rv );
		} else {
			printf("Object destroyed.\n");
		}
	}

	printf("%s: Success\n", __FUNCTION__);
	return CKR_OK;
}

CK_RV
do_GenerateTokenSymKey(CK_SESSION_HANDLE sess, CK_BYTE *label, CK_ULONG type)
{
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    key;
	CK_RV               rv;
	CK_BBOOL	    true = 1;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_LABEL, label, (CK_ULONG)strlen((char *)label) + 1 },
		{CKA_TOKEN, &true, sizeof(CK_BBOOL) }
	};

	printf("do_GenerateTokenSymKey...\n");

	mech.mechanism      = type;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	rv = funcs->C_GenerateKey( sess,      &mech,
				   tmpl,   2, &key );
	if (rv != CKR_OK) {
		show_error("   C_GenerateKey #1", rv );
		return rv;
	}

	printf("Success\n");
	return CKR_OK;
}


//
//
int
main( int argc, char **argv )
{
	CK_C_INITIALIZE_ARGS  cinit_args;
	int  i, nodelete = 0;
	CK_RV rv;
	SLOT_ID = 0;
	CK_BYTE             user_pin[128];
	CK_ULONG            user_pin_len;
	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_FLAGS            flags;
	CK_BYTE		    tdes_label[] = "XXX DELETE ME TEST 3DES KEY";
	CK_BYTE		    des_label[] = "XXX DELETE ME TEST DES KEY";


	for (i=1; i < argc; i++) {
		if (strcmp(argv[i], "-slot") == 0) {
			++i;
			SLOT_ID = atoi(argv[i]);
		}

		if (strcmp(argv[i], "-nodelete") == 0) {
			nodelete = 1;
		}

		if (strcmp(argv[i], "-h") == 0) {
			printf("usage:  %s [-noskip] [-slot <num>] [-h]\n\n", argv[0] );
			printf("By default, Slot #1 is used\n\n");
			printf("By default we skip anything that creates or modifies\n");
			printf("token objects to preserve flash lifetime.\n");
			return -1;
		}
	}

	printf("Using slot #%lu...\n\n", SLOT_ID );

	slot_id = SLOT_ID;

	rv = do_GetFunctionList();
	if (rv != TRUE) {
		show_error("do_GetFunctionList", rv);
		return -1;
	}

	memset( &cinit_args, 0x0, sizeof(cinit_args) );
	cinit_args.flags = CKF_OS_LOCKING_OK;

	// SAB Add calls to ALL functions before the C_Initialize gets hit

	if ((rv = funcs->C_Initialize( &cinit_args ))) {
		show_error("C_Initialize", rv);
		return -1;
	}

	if (get_user_pin(user_pin))
		return CKR_FUNCTION_FAILED;
	user_pin_len = (CK_ULONG)strlen((char *)user_pin);

	flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
	rv = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rv != CKR_OK) {
		show_error("   C_OpenSession #1", rv );
		return rv;
	}

	rv = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
	if (rv != CKR_OK) {
		show_error("   C_Login #1", rv );
		return rv;
	}

	rv = do_GenerateTokenSymKey(session, des_label, CKM_DES_KEY_GEN);
	if (rv != CKR_OK) {
		show_error("do_GenerateTokenRSAKeyPair(512)", rv);
		return -1;
	}

	rv = do_GenerateTokenSymKey(session, tdes_label, CKM_DES3_KEY_GEN);
	if (rv != CKR_OK) {
		show_error("do_GenerateTokenRSAKeyPair(512)", rv);
		return -1;
	}

	rv = funcs->C_CloseSession( session );
	if (rv != CKR_OK) {
		show_error("   C_CloseSession #3", rv );
		return rv;
	}

	rv = funcs->C_Finalize( NULL );
	if (rv != CKR_OK) {
		show_error("C_Finalize", rv);
		return -1;
	}

	if (nodelete)
		return 0;

	/* Open a new session and re-login */
	if ((rv = funcs->C_Initialize( &cinit_args ))) {
		show_error("C_Initialize", rv);
		return -1;
	}

	rv = funcs->C_OpenSession( slot_id, flags, NULL, NULL, &session );
	if (rv != CKR_OK) {
		show_error("   C_OpenSession #2", rv );
		goto finalize;
	}

	rv = funcs->C_Login( session, CKU_USER, user_pin, user_pin_len );
	if (rv != CKR_OK) {
		show_error("   C_Login #2", rv );
		goto close_session;
	}

	rv = do_VerifyTokenSymKey(session, des_label);
	if (rv != CKR_OK) {
		show_error("do_VerifyTokenRSAKeyPair(512)", rv);
		goto close_session;
	}

	rv = do_VerifyTokenSymKey(session, tdes_label);
	if (rv != CKR_OK) {
		show_error("do_VerifyTokenRSAKeyPair(1024)", rv);
		goto close_session;
	}

close_session:
	rv = funcs->C_CloseSession( session );
	if (rv != CKR_OK) {
		show_error("   C_CloseSession #3", rv );
		return rv;
	}
finalize:
	rv = funcs->C_Finalize( NULL );
	if (rv != CKR_OK) {
		show_error("C_Finalize", rv);
		return -1;
	}

	printf("%s: Success\n", argv[0]);

	return 0;
}
