// File: tok_obj.c
//
// Test driver for testing the proper storage of token objects
//

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>

#include "pkcs11types.h"

#include "regress.h"
#include "common.c"

CK_FUNCTION_LIST  *funcs;
int  do_GetInfo(void);

CK_RV C_GetFunctionList( CK_FUNCTION_LIST ** ) ;
int do_GetFunctionList(void);

CK_SLOT_ID  SLOT_ID;

int do_inittoken( CK_FUNCTION_LIST *funcs, CK_BYTE *sopass )
{
   CK_BYTE           label[32];
   int               len;
   CK_RV             rc;

   memcpy( label,   "L13                                   ", 32 );

   for (len = 0; len <31;len++){
      if (label[len] == '\0'){
         label[len] = ' ';
         break;
      }
   }

   rc = funcs->C_InitToken( SLOT_ID, NULL, strlen((char *)sopass), label );
   if (rc != CKR_ARGUMENTS_BAD) {
      show_error(" C_InitToken Fail #1",rc);
      goto done;
   }

   rc = funcs->C_InitToken( SLOT_ID, sopass, strlen((char *)sopass), NULL );
   if (rc != CKR_ARGUMENTS_BAD) {
      show_error(" C_InitToken Fail #2",rc);
      goto done;
   }

   rc = funcs->C_InitToken( SLOT_ID, sopass, strlen((char *)sopass), label );
   if (rc != CKR_OK) {
      show_error("   C_InitToken #1", rc );
      goto done;
   }

done:
   return rc;
}


//
//
int
main( int argc, char **argv )
{
	CK_BYTE		   *pass = NULL;
	int rc;
	int i;

	SLOT_ID = 0;

	for (i=1; i < argc; i++) {
		if (strcmp(argv[i], "-slot") == 0) {
			SLOT_ID = atoi(argv[i+1]);
			i++;
		} else if (strcmp(argv[i], "-pass") == 0) {
                        pass = (CK_BYTE_PTR)strdup(argv[i+1]);
			i++;
		} else {
			printf("usage:  %s [-slot <num>] [-h] -pass pass\n\n", argv[0] );
			printf("By default, Slot 0 is used\n\n");
			return -1;
		}
	}

	if (!pass) {
		printf("usage:  %s [-slot <num>] [-h] [-pass pass]\n\n", argv[0] );
		printf("By default, Slot 0 is used\n\n");
		return -1;
	}

	printf("Using slot #%lu...\n\n", SLOT_ID );

	rc = do_GetFunctionList();
	if ((rc != TRUE) || (funcs == NULL)) {
		printf("do_GetFunctionList failed.\n");
		return rc;
	}

	funcs->C_Initialize( NULL );

	rc = do_inittoken(funcs, pass);

	free(pass);

	funcs->C_Finalize( NULL );

	return rc;
}
