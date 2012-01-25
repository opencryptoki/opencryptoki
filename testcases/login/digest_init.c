
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include <dlfcn.h>
#include <sys/timeb.h>

#include "pkcs11types.h"

#include "regress.h"
#include "common.c"

CK_FUNCTION_LIST  *funcs;
int do_GetFunctionList(void);

int
do_digestInit(CK_FUNCTION_LIST *funcs, CK_SLOT_ID slot_id, CK_USER_TYPE userType, char *pass)
{
	CK_RV rc;
	CK_SESSION_HANDLE session;
	CK_FLAGS flags = CKF_SERIAL_SESSION;
	CK_MECHANISM mech;

	mech.mechanism = CKM_SHA_1;
	mech.pParameter = NULL;
	mech.ulParameterLen = 0;

	flags |= CKF_RW_SESSION;

	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("C_OpenSession", rc);
		return rc;
	}

	rc = funcs->C_Login(session, userType, (CK_CHAR_PTR)pass, strlen(pass));
	if (rc != CKR_OK) {
		show_error("C_Login", rc);
		return rc;
	}

	printf("Logged in successfully, calling C_DigestInit...\n");

	rc = funcs->C_DigestInit(session, &mech);
	if (rc != CKR_OK) {
		show_error("C_DigestInit", rc);
		funcs->C_Logout(session);
		funcs->C_CloseSession(session);
		return rc;
	} else {
		printf("Success.\n");
	}

	rc = funcs->C_Logout(session);
	if (rc != CKR_OK) {
		show_error("C_Logout", rc);
		return rc;
	}

	printf("Logged out.\n");

	rc = funcs->C_CloseSession(session);
	if (rc != CKR_OK) {
		show_error("C_CloseSession", rc);
		return rc;
	}

	return rc;
}

void digest_init_usage(char *argv0)
{
	printf("usage:  %s [-slot <num>] [-h] [-user|-so] -pass pass\n\n", argv0 );
	printf("By default, Slot #%lu is used, as user\n\n", SLOT_ID);
	exit(-1);
}
//
//
int
main( int argc, char **argv )
{
	CK_C_INITIALIZE_ARGS	cinit_args;
	CK_USER_TYPE		userType = CKU_USER;
	CK_RV			rc = 0;
	int			i;
	char			*pass = NULL;
	int			slot_id = 0;

	for (i=1; i < argc; i++) {
		if (strcmp(argv[i], "-pass") == 0) {
			++i;
			pass = argv[i];
		} else if (strcmp(argv[i], "-slot") == 0) {
			++i;
			slot_id = atoi(argv[i]);
		} else if (strcmp(argv[i], "-so") == 0) {
			userType = CKU_SO;
		} else if (strcmp(argv[i], "-user") == 0) {
			continue;
		} else {
			digest_init_usage(argv[0]);
		}
	}

	if (!pass)
		digest_init_usage(argv[0]);

	if (slot_id != SLOT_ID)
		printf("Using user specified slot %d.\n", slot_id);

	rc = do_GetFunctionList();
	if (funcs == NULL)
		return -1;

	memset( &cinit_args, 0, sizeof(cinit_args) );
	cinit_args.flags = CKF_OS_LOCKING_OK;

	rc = funcs->C_Initialize( &cinit_args );
	if (rc != CKR_OK) {
		show_error("C_Initialize", rc);
		return -1;
	}

	rc = do_digestInit(funcs, slot_id, userType, pass);

	funcs->C_Finalize( NULL );

	return rc;
}
