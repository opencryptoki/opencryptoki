/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"

// these values are required when generating a PKCS DSA value.  they were
// obtained by generating a DSA key pair on the 4758 with the default (random)
// values.  these values are in big-endian format
//
CK_BYTE DSA_PUBL_PRIME[128] =
{
	0xba, 0xa2, 0x5b, 0xd9, 0x77, 0xb3, 0xf0, 0x2d, 0xa1, 0x65, 0xf1, 0x83, 0xa7, 0xc9, 0xf0,
	0x8a, 0x51, 0x3f, 0x74, 0xe8, 0xeb, 0x1f, 0xd7, 0x0a, 0xd5, 0x41, 0xfa, 0x52, 0x3c, 0x1f,
	0x79, 0x15, 0x55, 0x18, 0x45, 0x41, 0x29, 0x27, 0x12, 0x4a, 0xb4, 0x32, 0xa6, 0xd2, 0xec,
	0xe2, 0x82, 0x73, 0xf4, 0x30, 0x66, 0x1a, 0x31, 0x06, 0x37, 0xd2, 0xb0, 0xe4, 0x26, 0x39,
	0x2a, 0x0e, 0x48, 0xf6, 0x77, 0x94, 0x47, 0xea, 0x7d, 0x99, 0x22, 0xce, 0x65, 0x61, 0x82,
	0xd5, 0xe3, 0xfc, 0x15, 0x3f, 0xff, 0xff, 0xc8, 0xb9, 0x4f, 0x37, 0xbf, 0x7a, 0xa6, 0x6a,
	0xbe, 0xff, 0xa9, 0xdf, 0xfd, 0xed, 0x4a, 0xb6, 0x83, 0xd6, 0x0f, 0xea, 0xf6, 0x90, 0x4f,
	0x12, 0x8e, 0x09, 0x6e, 0x3c, 0x0a, 0x6d, 0x2e, 0xfb, 0xb3, 0x79, 0x90, 0x8e, 0x39, 0xc0,
	0x86, 0x0e, 0x5d, 0xf0, 0x56, 0xcd, 0x26, 0x45
};

CK_BYTE DSA_PUBL_SUBPRIME[20] =
{
	0x9f, 0x3d, 0x47, 0x13, 0xa3, 0xff, 0x93, 0xbb, 0x4a, 0xa6, 0xb0, 0xf1, 0x7e, 0x54, 0x1e,
	0xba, 0xf0, 0x66, 0x03, 0x61
};


CK_BYTE DSA_PUBL_BASE[128] =
{
	0x1a, 0x5b, 0xfe, 0x12, 0xba, 0x85, 0x8e, 0x9b, 0x08, 0x86, 0xd1, 0x43, 0x9b, 0x4a, 0xaf,
	0x44, 0x31, 0xdf, 0xa1, 0x57, 0xd8, 0xe0, 0xec, 0x34, 0x07, 0x4b, 0x78, 0x8e, 0x3c, 0x62,
	0x47, 0x4c, 0x2f, 0x5d, 0xd3, 0x31, 0x2c, 0xe9, 0xdd, 0x59, 0xc5, 0xe7, 0x2e, 0x06, 0x40,
	0x6c, 0x72, 0x9c, 0x95, 0xc6, 0xa4, 0x2a, 0x1c, 0x1c, 0x45, 0xb9, 0xf3, 0xdc, 0x83, 0xb6,
	0xc6, 0xdd, 0x94, 0x45, 0x4f, 0x74, 0xc6, 0x55, 0x36, 0x54, 0xba, 0x20, 0xad, 0x9a, 0xb6,
	0xe3, 0x20, 0xf2, 0xdd, 0xd3, 0x66, 0x19, 0xeb, 0x53, 0xf5, 0x88, 0x35, 0xe1, 0xea, 0xe8,
	0xd4, 0x57, 0xe1, 0x3d, 0xea, 0xd5, 0x00, 0xc2, 0xa4, 0xf5, 0xff, 0xfb, 0x0b, 0xfb, 0xa2,
	0xb9, 0xf1, 0x49, 0x46, 0x9d, 0x11, 0xa5, 0xb1, 0x94, 0x52, 0x47, 0x6e, 0x2e, 0x79, 0x4b,
	0xc5, 0x18, 0xe9, 0xbc, 0xff, 0xae, 0x34, 0x7f
};

//
//
CK_RV do_GenerateDSAKeyPair( void )
{
	CK_SLOT_ID          slot_id = SLOT_ID;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    publ_key, priv_key;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_RV               rc;

	CK_ATTRIBUTE  publ_tmpl[] =
	{
		{CKA_PRIME,    DSA_PUBL_PRIME,    sizeof(DSA_PUBL_PRIME)    },
		{CKA_SUBPRIME, DSA_PUBL_SUBPRIME, sizeof(DSA_PUBL_SUBPRIME) },
		{CKA_BASE,     DSA_PUBL_BASE,     sizeof(DSA_PUBL_BASE)     }
	};

	mech.mechanism      = CKM_DSA_KEY_PAIR_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	testcase_begin("GenerateDSAKeyPair");
	testcase_rw_session();
	testcase_user_login();

	testcase_new_assertion();

	rc = funcs->C_GenerateKeyPair(session, &mech, publ_tmpl, 3, NULL, 0,
				      &publ_key, &priv_key);
	if (rc != CKR_OK)
		testcase_fail("C_GenerateKeyPair rc=%s", p11_get_ckr(rc));
	else
		testcase_pass("GenerateDSAKeyPair passed");

testcase_cleanup:
	testcase_user_logout();
	if (funcs->C_CloseAllSessions(slot_id) != CKR_OK)
		testcase_error("C_CloseAllSession failed.");
	return rc;
}


// the generic DSA mechanism assumes that the data to be signed has already
// been hashed by SHA-1.  so the input data length must be 20 bytes
//
CK_RV do_SignDSA( void )
{
	CK_BYTE             data1[20];
	CK_BYTE             signature[256];
	CK_SLOT_ID          slot_id = SLOT_ID;
	CK_SESSION_HANDLE   session;
	CK_MECHANISM        mech;
	CK_OBJECT_HANDLE    publ_key, priv_key;
	CK_FLAGS            flags;
	CK_BYTE             user_pin[PKCS11_MAX_PIN_LEN];
	CK_ULONG            user_pin_len;
	CK_ULONG            i;
	CK_ULONG            len1, sig_len;
	CK_RV               rc;

	CK_ATTRIBUTE  publ_tmpl[] =
	{
		{CKA_PRIME,    DSA_PUBL_PRIME,    sizeof(DSA_PUBL_PRIME)    },
		{CKA_SUBPRIME, DSA_PUBL_SUBPRIME, sizeof(DSA_PUBL_SUBPRIME) },
		{CKA_BASE,     DSA_PUBL_BASE,     sizeof(DSA_PUBL_BASE)     }
	};

	mech.mechanism      = CKM_DSA_KEY_PAIR_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	testcase_begin("DSA Sign/Verify");
	testcase_rw_session();
	testcase_user_login();

	testcase_new_assertion();

	rc = funcs->C_GenerateKeyPair(session, &mech, publ_tmpl, 3, NULL, 0,
				      &publ_key, &priv_key);
	if (rc != CKR_OK) {
		testcase_error("C_GenerateKeyPair rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	// now, sign some data
	//
	len1 = sizeof(data1);
	sig_len = sizeof(signature);

	for (i=0; i < len1; i++)
		data1[i] = i % 255;

	mech.mechanism      = CKM_DSA;
	mech.ulParameterLen = 0;
	mech.pParameter     = NULL;

	rc = funcs->C_SignInit( session, &mech, priv_key );
	if (rc != CKR_OK) {
		testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_Sign( session, data1, len1, signature, &sig_len );
	if (rc != CKR_OK) {
		testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	// now, verify the signature
	//
	rc = funcs->C_VerifyInit( session, &mech, publ_key );
	if (rc != CKR_OK) {
		testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_Verify( session, data1, len1, signature, sig_len );
	if (rc != CKR_OK) {
		testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	// now, corrupt the signature and try to re-verify.
	//
	memcpy( signature, "ABCDEFGHIJKLMNOPQRSTUV", 26 );

	rc = funcs->C_VerifyInit( session, &mech, publ_key );
	if (rc != CKR_OK) {
		testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
		goto testcase_cleanup;
	}

	rc = funcs->C_Verify( session, data1, len1, signature, sig_len );
	if (rc != CKR_SIGNATURE_INVALID) {
		testcase_fail("Verify expected CKR_SIGNATURE_INVALID, got %s",
				p11_get_ckr(rc));
		goto testcase_cleanup;
	}
	else
		testcase_pass("DSA Sign/Verify passed");

testcase_cleanup:
	testcase_user_logout();
	if (funcs->C_CloseAllSessions(slot_id) != CKR_OK)
		testcase_error("C_CloseAllSessions failed.");

	return rc;
}

CK_RV dsa_functions()
{
	SYSTEMTIME t1, t2;
	CK_RV rc = CKR_OK;
	CK_SLOT_ID slot_id;

        /** skip tests if the slot doesn't support this mechanism **/
	slot_id = SLOT_ID;
        if (!(mech_supported(slot_id, CKM_DSA))) {
		printf("Slot %u doesn't support DSA\n", (unsigned int) slot_id);
		return rc;
        }

	GetSystemTime(&t1);
	rc = do_GenerateDSAKeyPair();
	if (rc) {
		PRINT_ERR("ERROR do_GenerateDSAKeyPair failed, rc = 0x%lx\n", rc);
		if (!no_stop)
			return rc;
	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

	GetSystemTime(&t1);
	rc = do_SignDSA();
	if (rc) {
		PRINT_ERR("ERROR do_SignDSA failed, rc = 0x%lx\n", rc);
		if (!no_stop)
			return rc;
	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

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

	testcase_setup(0);

	rv = dsa_functions();

	testcase_print_result();

	funcs->C_Finalize(NULL);

	/* make sure we return non-zero if rv is non-zero */
	return ((rv == 0) || (rv % 256) ? rv : -1);
}
