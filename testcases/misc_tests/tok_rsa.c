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
do_VerifyTokenRSAKeyPair(CK_SESSION_HANDLE sess, CK_BYTE *label, CK_ULONG bits)
{
	CK_OBJECT_HANDLE    obj_handles[20];
	CK_ULONG	    pulCount = 0, obj_class, i;
	CK_RV               rv;
	CK_BBOOL	    true = 1;

	printf("do_VerifyTokenRSAKeyPair...\n");

	/* Find token objects based on the label */
	{
		CK_ATTRIBUTE tmpl[] =
		{
			{CKA_LABEL, label, (CK_ULONG)strlen((char *)label) + 1 },
			{CKA_TOKEN, &true, sizeof(CK_BBOOL) }
		};

		rv = funcs->C_FindObjectsInit(sess, tmpl, 2);
		if (rv != CKR_OK) {
			show_error("   C_FindObjectsInit #1", rv );
			return rv;
		}
		rv = funcs->C_FindObjects(sess, obj_handles, 2, &pulCount);
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
		CK_ATTRIBUTE tmpl[] = {
			{CKA_CLASS, &obj_class, sizeof(obj_class) }
		};

		rv = funcs->C_GetAttributeValue(sess, obj_handles[i], tmpl, 1);
		if (rv != CKR_OK) {
			show_error("   C_GetAttributeValue #1", rv );
			return rv;
		}

		if (obj_class == CKO_PUBLIC_KEY) {
			CK_BYTE n[256], e[256];
			CK_ULONG exp_size = 0, mod_size = 0;
			CK_ATTRIBUTE pub_attrs[] = {
				{ CKA_PUBLIC_EXPONENT, NULL, exp_size },
				{ CKA_MODULUS, NULL, mod_size }
			};

			rv = funcs->C_GetAttributeValue(sess, obj_handles[i], pub_attrs, 2);
			if (rv != CKR_OK) {
				show_error("   C_GetAttributeValue", rv );
				return rv;
			}

			/* The public exponent is element 0 and modulus is element 1 */
			if (pub_attrs[0].ulValueLen > 256 || pub_attrs[1].ulValueLen > 256) {
				PRINT_ERR("e_size (%lu) or n_size (%lu) too big!",
					  pub_attrs[0].ulValueLen, pub_attrs[1].ulValueLen);
				return CKR_FUNCTION_FAILED;
			}

			pub_attrs[0].pValue = e;
			pub_attrs[1].pValue = n;

			rv = funcs->C_GetAttributeValue(sess, obj_handles[i], pub_attrs, 2);
			if (rv != CKR_OK) {
				show_error("   C_GetAttributeValue", rv );
				return rv;
			}

			printf("Found public key with %lu bit modulus and %lu byte public exponent.\n",
			       pub_attrs[1].ulValueLen, pub_attrs[0].ulValueLen);

			printf("Public exponent:\n");
			print_hex(pub_attrs[0].pValue, pub_attrs[0].ulValueLen);

			printf("Public modulus:\n");
			print_hex(pub_attrs[1].pValue, pub_attrs[1].ulValueLen);

		} else if (obj_class == CKO_PRIVATE_KEY) {
			printf("Found a matching private key.\n");
		} else {
			fprintf(stderr, "Found an object that's not what we're"
				" looking for, skipping it...\n");
			continue;
		}

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
do_GenerateTokenRSAKeyPair(CK_SESSION_HANDLE sess, CK_BYTE *label, CK_ULONG bits)
{
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    publ_key, priv_key;
	CK_RV               rv;
	CK_BBOOL	    true = 1;

	printf("do_TokenGenerateRSAKey...\n");

	mech.mechanism      = CKM_RSA_PKCS_KEY_PAIR_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	// Use 65537 as pub exp
	{
		CK_BYTE   pub_exp[] = { 0x1, 0x0, 0x1 };

		CK_ATTRIBUTE pub_tmpl[] =
		{
			{CKA_MODULUS_BITS,    &bits,    sizeof(bits)    },
			{CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp) },
			{CKA_LABEL, label, (CK_ULONG)strlen((char *)label) + 1 },
			{CKA_TOKEN, &true, sizeof(CK_BBOOL) }
		};
		CK_ATTRIBUTE priv_tmpl[] =
		{
			{CKA_LABEL, label, (CK_ULONG)strlen((char *)label) + 1 },
			{CKA_TOKEN, &true, sizeof(CK_BBOOL) }
		};

		rv = funcs->C_GenerateKeyPair( sess,      &mech,
					       pub_tmpl,   4,
					       priv_tmpl,  2,
					       &publ_key, &priv_key );
		if (rv != CKR_OK) {
			show_error("   C_GenerateKeyPair #2", rv );
			return rv;
		}
	}

	printf("%s: Success\n", __FUNCTION__);
	return CKR_OK;
}


//
//
	int
main( int argc, char **argv )
{
	CK_C_INITIALIZE_ARGS  cinit_args;
	int  i;
	CK_RV rv;
	SLOT_ID = 0;
	CK_BYTE             user_pin[128];
	CK_ULONG            user_pin_len;
	CK_SLOT_ID          slot_id;
	CK_SESSION_HANDLE   session;
	CK_FLAGS            flags;


	for (i=1; i < argc; i++) {
		if (strcmp(argv[i], "-slot") == 0) {
			++i;
			SLOT_ID = atoi(argv[i]);
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

	rv = do_GenerateTokenRSAKeyPair(session, (CK_BYTE *)"XXX DELETE ME TEST LABEL 512bit", 512);
	if (rv != CKR_OK) {
		show_error("do_GenerateTokenRSAKeyPair(512)", rv);
		return -1;
	}

	rv = do_GenerateTokenRSAKeyPair(session, (CK_BYTE *)"XXX DELETE ME TEST LABEL 1024bit", 1024);
	if (rv != CKR_OK) {
		show_error("do_GenerateTokenRSAKeyPair(1024)", rv);
		return -1;
	}

	rv = do_GenerateTokenRSAKeyPair(session, (CK_BYTE *)"XXX DELETE ME TEST LABEL 2048bit", 2048);
	if (rv != CKR_OK) {
		show_error("do_GenerateTokenRSAKeyPair(2048)", rv);
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

	rv = do_VerifyTokenRSAKeyPair(session, (CK_BYTE *)"XXX DELETE ME TEST LABEL 512bit", 512);
	if (rv != CKR_OK) {
		show_error("do_VerifyTokenRSAKeyPair(512)", rv);
		goto close_session;
	}

	rv = do_VerifyTokenRSAKeyPair(session, (CK_BYTE *)"XXX DELETE ME TEST LABEL 1024bit", 1024);
	if (rv != CKR_OK) {
		show_error("do_VerifyTokenRSAKeyPair(1024)", rv);
		goto close_session;
	}

	rv = do_VerifyTokenRSAKeyPair(session, (CK_BYTE *)"XXX DELETE ME TEST LABEL 2048bit", 2048);
	if (rv != CKR_OK) {
		show_error("do_VerifyTokenRSAKeyPair(2048)", rv);
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
