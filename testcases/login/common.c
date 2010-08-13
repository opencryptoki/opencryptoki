
/*
 * common.c
 *
 * Common test routines
 *
 * Kent Yoder <yoder1@us.ibm.com>
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include <dlfcn.h>
#include <sys/timeb.h>
#include "pkcs11types.h"

#include "common.h"
#include "p11util.h"

void process_time(struct timeb t1, struct timeb t2)
{
	long ms   = t2.millitm - t1.millitm;
	long s    = t2.time - t1.time;

	while (ms < 0) {
		ms += 1000;
		s--;
	}

	ms += (s*1000);

	printf("Time:  %ld msec\n", ms );

}

//
//
void show_error( char *str, CK_RV rc )
{
  printf("%s returned:  %ld - %s\n", str, rc, p11_get_ckr(rc) );
}


//
//
void print_hex( CK_BYTE *buf, CK_ULONG len )
{
	CK_ULONG i = 0, j;

	while (i < len) {
		for (j=0; (j < 15) && (i < len); j++, i++)
			printf("%02x ", buf[i] & 0xff);
		printf("\n");
	}
	printf("\n");
}


//
//
int do_GetFunctionList( CK_FUNCTION_LIST **funcs )
{
	CK_RV	rc;
	CK_RV	(*pfoo)();
	void	*d;
	char	*e;
	char	default_lib[] = PKCS11_API_DEFAULT_LIB;

	e = getenv("PKCSLIB");
	if ( e == NULL) {
		e = default_lib;
	}
	d = dlopen(e,RTLD_NOW);
	if ( d == NULL ) {
		PRINTERR("dlopen of %s failed: %s\n", e, dlerror());
		return -1;
	}

	pfoo = (CK_RV (*)())dlsym(d,"C_GetFunctionList");
	if (pfoo == NULL ) {
		PRINTERR("dlsym failed: %s\n", dlerror());
		return -1;
	}

	rc = pfoo(funcs);
	if (rc != CKR_OK) {
		show_error("   C_GetFunctionList", rc );
		return -1;
	}

	return 0;
}



