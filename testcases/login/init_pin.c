
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
do_InitPIN(CK_FUNCTION_LIST *funcs, CK_SLOT_ID slot_id, char *sologinpass, char *userinitpass)
{
	CK_RV rc;
	CK_SESSION_HANDLE session;
	CK_FLAGS flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

	rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
	if (rc != CKR_OK) {
		show_error("C_OpenSession", rc);
		return rc;
	}

	rc = funcs->C_Login(session, CKU_SO, (CK_CHAR_PTR)sologinpass, strlen(sologinpass));
	if (rc != CKR_OK) {
		show_error("C_Login", rc);
		return rc;
	}

	printf("Logged in the SO successfully, calling C_InitPIN...\n");

	rc = funcs->C_InitPIN(session, (CK_CHAR_PTR)userinitpass, strlen(userinitpass));
	if (rc != CKR_OK) {
		show_error("C_InitPIN", rc);
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
void
init_pin_usage(char *argv0)
{
	printf("usage:  %s [-slot <num>] [-h] -sopass pass -userpass pass\n\n", argv0 );
	printf("By default, Slot #%lu is used, as user\n\n", SLOT_ID);
	exit(-1);
}
//
//
int
main( int argc, char **argv )
{
	CK_C_INITIALIZE_ARGS	cinit_args;
	CK_RV			rc = 0;
	int			i;
	char			*sopass = NULL, *userpass = NULL;
	int			slot_id = 0;

	for (i=1; i < argc; i++) {
		if (strcmp(argv[i], "-sopass") == 0) {
			++i;
			sopass = argv[i];
		} else if (strcmp(argv[i], "-userpass") == 0) {
			++i;
			userpass = argv[i];
		} else if (strcmp(argv[i], "-slot") == 0) {
			++i;
			slot_id = atoi(argv[i]);
		} else {
			 init_pin_usage(argv[0]);
		}
	}

	if (!sopass || !userpass)
		init_pin_usage(argv[0]);

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

	rc = do_InitPIN(funcs, slot_id, sopass, userpass);

	funcs->C_Finalize( NULL );

	return rc;
}
