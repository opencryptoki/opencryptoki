
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

#include "pkcs11types.h"
#include "regress.h"

CK_ULONG t_total = 0;		// total test assertions
CK_ULONG t_ran = 0;		// number of assertions ran
CK_ULONG t_passed = 0;		// number of assertions passed
CK_ULONG t_failed = 0;		// number of assertions failed
CK_ULONG t_skipped = 0;		// number of assertions skipped

int
get_so_pin(CK_BYTE *dest)
{
	char *val;

	val = getenv(PKCS11_SO_PIN_ENV_VAR);
	if (val == NULL) {
		fprintf(stderr, "The environment variable %s must be set "
			"before this testcase is run.\n", PKCS11_SO_PIN_ENV_VAR);
		return -1;
	}

	if ((strlen(val) + 1) > PKCS11_MAX_PIN_LEN) {
		fprintf(stderr, "The environment variable %s must hold a "
			"value less than %d chars in length.\n",
			PKCS11_SO_PIN_ENV_VAR, (int)PKCS11_MAX_PIN_LEN);
		return -1;
	}

	memcpy(dest, val, strlen(val) + 1);

	return 0;
}

int
get_user_pin(CK_BYTE *dest)
{
	char *val;

	val = getenv(PKCS11_USER_PIN_ENV_VAR);
	if (val == NULL) {
		fprintf(stderr, "The environment variable %s must be set "
			"before this testcase is run.\n", PKCS11_USER_PIN_ENV_VAR);
		return -1;
	}

	if ((strlen(val) + 1) > PKCS11_MAX_PIN_LEN) {
		fprintf(stderr, "The environment variable %s must hold a "
			"value less than %d chars in length.\n",
			PKCS11_SO_PIN_ENV_VAR, (int)PKCS11_MAX_PIN_LEN);
		return -1;
	}

	memcpy(dest, val, strlen(val) + 1);

	return 0;
}



void process_time(SYSTEMTIME t1, SYSTEMTIME t2)
{
   long ms   = t2.millitm - t1.millitm;
   long s    = t2.time - t1.time;

   while (ms < 0) {
      ms += 1000;
      s--;
   }

   ms += (s*1000);

   printf("Time:  %u msec\n", (unsigned int)ms );
}



//
//
void print_hex( CK_BYTE *buf, CK_ULONG len )
{
   CK_ULONG i, j;

   i = 0;

   while (i < len) {
      for (j=0; (j < 16) && (i < len); j++, i++)
         fprintf(stderr, "%02x ", buf[i] );
      fprintf(stderr, "\n");
   }
   fprintf(stderr, "\n");
}

void usage (char *fct)
{
	printf("usage:  %s [-noskip] [-noinit] [-slot <num>] [-h]\n\n", fct );
	printf("By default, Slot #1 (ie: Slot_Id 0) is used\n\n");
	printf("By default we skip anything that creates or modifies\n");
	printf("token objects to preserve flash lifetime.\n");

	return;
}
	

int do_ParseArgs(int argc, char **argv)
{
	int i;

	skip_token_obj = TRUE;
	no_stop = FALSE;
	no_init = FALSE;
	SLOT_ID = 0;


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
	return 1;
}

//
//
int do_GetFunctionList( void )
{
   CK_RV            rc;
   CK_RV  (*pfoo)();
   void    *d;
   char    *e;
   char    *f = "libopencryptoki.so";

   e = getenv("PKCSLIB");
   if ( e == NULL) {
      e = f;
     // return FALSE;
   }
   d = dlopen(e,RTLD_NOW);
   if ( d == NULL ) {
      return FALSE;
   }

   pfoo = (CK_RV (*)())dlsym(d,"C_GetFunctionList");
   if (pfoo == NULL ) {
      return FALSE;
   }
   rc = pfoo(&funcs);

   if (rc != CKR_OK) {
      show_error("   C_GetFunctionList", rc );
      return FALSE;
   }

   return TRUE;

}
