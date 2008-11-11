// File: driver.c
//
//
// Test driver.  In-depth regression test for PKCS #11
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include <dlfcn.h>
#include <sys/timeb.h>

#include "pkcs11types.h"
#include "regress.h"


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
int main (int argc, char **argv)
{
	CK_C_INITIALIZE_ARGS  cinit_args;
	int        rc, i;
	CK_BBOOL      no_init;

	SLOT_ID = 0;
	skip_token_obj = TRUE;
	no_init = FALSE;
	no_stop = FALSE;

	for (i = 1; i < argc; i++) {
		if (strcmp (argv[i], "-h") == 0 || strcmp (argv[i], "--help") == 0) {
			usage (argv [0]);
			return 0;
		}
		else if (strcmp (argv[i], "-noskip") == 0)
			skip_token_obj = FALSE;

		else if (strcmp (argv[i], "-slot") == 0) {
			SLOT_ID = atoi (argv[i+1]);
			i++;
		}
		else if (strcmp (argv[i], "-noinit") == 0)
			no_init = TRUE;
		
		else if (strcmp (argv[i], "-nostop") == 0)
			no_stop = TRUE;
		
		else {
			printf ("Invalid argument passed as option: %s\n", argv [i]);
			usage (argv [0]);
			return -1;
		}
	}

	printf("Using slot #%lu...\n\n", SLOT_ID );
	printf("With option: no_init: %d, noskip: %d\n", no_init, skip_token_obj);

	rc = do_GetFunctionList();
	if ( !rc )
		return rc;

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


#if 0
	fprintf (stderr, "\tMisc functions tests...\n");
	rc = misc_functions(); 
	if ( !rc && !no_stop)
		return rc;

	fprintf (stderr, "\tSession Mgmt functions tests...\n");
	rc = sess_mgmt_functions();
	if ( !rc && !no_stop)
		return rc;

	fprintf (stderr, "\tObject Mgmt functions tests...\n");
	rc = obj_mgmt_functions();
	if ( !rc && !no_stop)
		return rc;

	fprintf (stderr, "\tDES functions tests...\n");
	rc = des_functions();
	if ( !rc && !no_stop) {
		printf("Error executing DES functions\n");
		return rc;
	}

	fprintf (stderr, "\tDES3 functions tests...\n");
	rc = des3_functions();
	if ( !rc && !no_stop) {
		printf("Error executing DES3 functions\n");
		return rc;
	}

	fprintf (stderr, "\tDSA functions tests...\n");
	rc = dsa_functions();
	if ( !rc && !no_stop) {
		printf("Error executing DSA functions\n");
		return rc;
	}
	
	fprintf (stderr, "\tDES3 functions tests...\n");
	rc = des3_functions();
	if ( !rc && !no_stop)
		return rc;
	
	fprintf (stderr, "\tAES functions tests...\n");
	rc = aes_functions();
	if ( !rc && !no_stop) {
		printf("Error executing AES functions\n");
		return rc;
	}

	fprintf (stderr, "\tRijndael tests...\n");
	rc = rijndael_functions();
	if ( !rc && !no_stop) {
		printf("Error executing Rijndael functions\n");
		return rc;
	}
	
	fprintf (stderr, "\tDigest functions tests...\n");
	rc = digest_functions();
	if ( !rc && !no_stop) {
		printf("Error executing Digest functions\n");
		return rc;
	}

	fprintf (stderr, "\tRSA functions tests...\n");
	rc = rsa_functions();
	if ( !rc && !no_stop) {
		printf("Error executing RSA functions\n");
		return rc;
	}

	/* Begin code contributed by Corrent corp. */
	fprintf (stderr, "\tDH functions tests...\n");
	rc = dh_functions();
	if ( !rc && !no_stop) {
		printf("Error executing DH functions\n");
		return rc;
	}
	/* End code contributed by Corrent corp. */

	fprintf (stderr, "\tSSL3 functions tests...\n");
	rc = ssl3_functions();
	if ( !rc && !no_stop) { 
		printf("Error executing SSL3 functions\n");
		return rc;
	}
#endif
	printf("------------------ Completed pass --------------------\n");

	funcs->C_Finalize( NULL );

	return 0;
}
