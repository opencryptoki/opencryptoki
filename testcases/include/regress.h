// regress.h
//
#ifndef _REGRESS_H
#define _REGRESS_H

#if !defined(TRUE)
#define TRUE 1
#endif

#if !defined(FALSE)
#define FALSE 0
#endif

#define DES_BLOCK_SIZE  8
#define DES_KEY_LEN     8

#define SHA1_HASH_LEN   20
#define MD2_HASH_LEN    16
#define MD5_HASH_LEN    16

#define BIG_REQUEST     4096

#define MIN(a, b)       ( (a) < (b) ? (a) : (b) )

#include <sys/timeb.h>
#define SYSTEMTIME   struct timeb
#define GetSystemTime(x) ftime((x))

#include "p11util.h"

void process_time(SYSTEMTIME t1, SYSTEMTIME t2);
void show_error( char *str, CK_RV rc );
void print_hex( CK_BYTE *buf, CK_ULONG len );

int do_GetFunctionList(void);

void init_coprocessor(void);

CK_RV C_GetFunctionList( CK_FUNCTION_LIST ** ) ;
CK_RV DummyFunction( CK_SLOT_ID id ) ;

int digest_functions(void);

CK_FUNCTION_LIST  *funcs;
CK_SLOT_ID  SLOT_ID;

void usage(char *fct);
int do_ParseArgs(int argc, char **argv);

// these values are required when generating a PKCS DSA value.  they were
// obtained by generating a DSA key pair on the 4758 with the default (random)
// values.  these values are in big-endian format
//
extern CK_BYTE DSA_PUBL_PRIME[128];
extern CK_BYTE DSA_PUBL_SUBPRIME[20];
extern CK_BYTE DSA_PUBL_BASE[128];

CK_BBOOL skip_token_obj;
CK_BBOOL no_stop;
CK_BBOOL no_init;

int get_so_pin(CK_BYTE_PTR);
int get_user_pin(CK_BYTE_PTR);

#define PKCS11_MAX_PIN_LEN	128
#define PKCS11_SO_PIN_ENV_VAR   "PKCS11_SO_PIN"
#define PKCS11_USER_PIN_ENV_VAR "PKCS11_USER_PIN"

#define PRINT_ERR(fmt, ...)     fprintf(stderr, "%s:%d " fmt "\n", __FILE__, __LINE__, \
                                        ## __VA_ARGS__)
#define PRINT(fmt, ...)         printf("%s:%d " fmt "\n", __FILE__, __LINE__, \
                                        ## __VA_ARGS__)


/* show_error(char *_str, unsigned long _rc); */
#define show_error(_str, _rc)						\
	fprintf(stderr, "%s:%d: %s returned %lu (0x%lx) %s\n",		\
		__FILE__, __LINE__, _str, _rc, _rc,			\
		p11_get_ckr(_rc))


#endif
