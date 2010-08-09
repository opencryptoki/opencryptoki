// File: sess_perf.c
//

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"

#define DATALEN 1024
CK_BYTE DATA[DATALEN];
CK_BYTE DUMP[DATALEN];

typedef struct _context_table {
	CK_SESSION_HANDLE hsess;
	CK_OBJECT_HANDLE hkey;
} context_table_t;


//
//
void dump_session_info( CK_SESSION_INFO *info )
{
	printf("   CK_SESSION_INFO:\n");
	printf("      slotID:         %ld\n", info->slotID );
	printf("      state:          ");
	switch (info->state) {
		case CKS_RO_PUBLIC_SESSION:   printf("CKS_RO_PUBLIC_SESSION\n");
					      break;
		case CKS_RW_PUBLIC_SESSION:   printf("CKS_RW_PUBLIC_SESSION\n");
					      break;
		case CKS_RO_USER_FUNCTIONS:   printf("CKS_RO_USER_FUNCTIONS\n");
					      break;
		case CKS_RW_USER_FUNCTIONS:   printf("CKS_RW_USER_FUNCTIONS\n");
					      break;
		case CKS_RW_SO_FUNCTIONS:     printf("CKS_RW_SO_FUNCTIONS\n");
					      break;
	}
	printf("      flags:          %p\n",    (void *)info->flags );
	printf("      ulDeviceError:  %ld\n",    info->ulDeviceError );
}



//
//
int create_des_encrypt_context(CK_SESSION_HANDLE_PTR hsess, CK_OBJECT_HANDLE_PTR hkey)
{
	CK_SLOT_ID        slot_id;
	CK_FLAGS          flags;
	CK_RV             rc;
        CK_MECHANISM      mech;

	/* create session */
	slot_id = SLOT_ID;
	flags   = CKF_SERIAL_SESSION;   // read-only session

	rc = funcs->C_OpenSession( slot_id, flags, NULL, NULL, hsess );
	if (rc != CKR_OK) {
		show_error("   C_OpenSession #1", rc );
		return FALSE;
	}

	/* generate key in this specific session */
	mech.mechanism = CKM_DES_KEY_GEN;
	mech.ulParameterLen = 0;
	mech.pParameter = NULL;

        rc = funcs->C_GenerateKey(*hsess, &mech, NULL, 0, hkey);
	if (rc != CKR_OK) {
		show_error("   C_GenerateKey #1", rc);
		return FALSE;
	}

	/* Get Random for Initialization Vector */
	mech.mechanism = CKM_DES_CBC;
	mech.ulParameterLen = 8;
        mech.pParameter = "12345678";

	/* Create encryption context using this session and key */
	rc = funcs->C_EncryptInit(*hsess, &mech, *hkey);
	if (rc != CKR_OK) {
		show_error("   C_EncryptInit #1", rc);
		return FALSE;
	}

	return TRUE;
}

int encrypt_DATA(CK_SESSION_HANDLE hsess, CK_OBJECT_HANDLE hkey, CK_ULONG blocklen) {
	CK_RV             rc;
       CK_ULONG          outlen = 8;
        unsigned long int i;

	for (i = 0; i < DATALEN; i+=outlen) {
		rc = funcs->C_EncryptUpdate(hsess, (CK_BYTE_PTR)(DATA + i) , blocklen,
					    (CK_BYTE_PTR)(DUMP + i), &outlen);
		if (rc != CKR_OK) {
			show_error("   C_Encrypt #1", rc);
			return FALSE;
		}
	}

	return TRUE;
}


int finalize_des_encrypt_context(CK_SESSION_HANDLE hsess)
{
	CK_RV             rc;
       CK_ULONG          outlen = DATALEN;

	rc = funcs->C_EncryptFinal(hsess, DUMP, &outlen);
	if (rc != CKR_OK) {
		show_error("   C_EncryptFinal#1", rc);
		return FALSE;
	}

	rc = funcs->C_CloseSession(hsess);
	if (rc != CKR_OK) {
		show_error("   C_CloseSession #1", rc );
		return FALSE;
	}

	return TRUE;
}

//
//
int close_all_sess( void )
{
	CK_SLOT_ID        slot_id;
	CK_RV             rc;

	slot_id = SLOT_ID;

	rc = funcs->C_CloseAllSessions( slot_id );
	if (rc != CKR_OK) {
		show_error("   C_CloseAllSessions #1", rc );
		return FALSE;
	}

	return TRUE;
}

int do_SessionPerformance(unsigned int count)
{
	SYSTEMTIME        t1, t2;
	int               rc, i;
	context_table_t   *t = NULL;

	if (count == 0) {
		show_error("   do_SessionPerformance: zero session count", (CK_RV)0);
		return FALSE;
	}

	t = (context_table_t *) calloc(count, sizeof(context_table_t));
	if (t == NULL) {
		show_error("    do_SessionPerformance: insuficient memory", (CK_RV)0);
		return FALSE;
	}

	/* create encryption contexts */
	for (i = 0; i < count; i++) {
		rc = create_des_encrypt_context(&(t[i].hsess), &(t[i].hkey));
		if (rc == FALSE) {
			show_error("    create_des_encrypt_context", (CK_RV)0);
			return FALSE;
		}
	}

        /* Time encrypt operation in the first and last session */
	GetSystemTime(&t1);
	rc = encrypt_DATA(t[0].hsess, t[0].hkey, 8);
	if (rc == FALSE) {
		show_error("   encrypt_DATA #1", (CK_RV)0);
		return FALSE;

	}

	rc = encrypt_DATA(t[count - 1].hsess, t[count - 1].hkey, 8);
	if (rc == FALSE) {
		show_error("   encrypt_DATA #2", (CK_RV)0);
		return FALSE;

	}
	GetSystemTime(&t2);
	process_time( t1, t2 );

	for (i = 0; i < count; i++) {
		rc = finalize_des_encrypt_context(t[i].hsess);
		if (rc == FALSE) {
			show_error("    finalize_des_encrypt_context", (CK_RV)0);
			return FALSE;
		}
	}

	return TRUE;
}

int main(int argc, char **argv)
{
	CK_C_INITIALIZE_ARGS cinit_args;
	int rc, i;


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

        for (i = 100; i < 50000; i=1.2*i) {
		printf("timing do_SessionPerformance(%d)\n", i);
		do_SessionPerformance(i);
	}

       return 0;
}
