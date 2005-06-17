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

void process_time(SYSTEMTIME t1, SYSTEMTIME t2);
void process_ret_code( CK_RV rc );
int  do_GetInfo(void);
void show_error( CK_BYTE *str, CK_RV rc );
void print_hex( CK_BYTE *buf, CK_ULONG len );

void init_coprocessor(void);

CK_RV C_GetFunctionList( CK_FUNCTION_LIST ** ) ;
CK_RV DummyFunction( CK_SLOT_ID id ) ;

int misc_functions(void);
int sess_mgmt_functions(void);
int obj_mgmt_functions(void);
int des_functions(void);
int des3_functions(void);
int digest_functions(void);
int rsa_functions(void);
int dsa_functions(void);
/* Begin code contributed by Corrent corp. */
int dh_functions(void);
/* End code contributed by Corrent corp. */

extern CK_FUNCTION_LIST  *funcs;
extern CK_SLOT_ID  SLOT_ID;


// these values are required when generating a PKCS DSA value.  they were
// obtained by generating a DSA key pair on the 4758 with the default (random)
// values.  these values are in big-endian format
//
extern CK_BYTE DSA_PUBL_PRIME[128];
extern CK_BYTE DSA_PUBL_SUBPRIME[20];
extern CK_BYTE DSA_PUBL_BASE[128];

extern int skip_token_obj;

/* Right now the testcases will break if these PINs are any length
 * other than 8.
 */
#define DEFAULT_USER_PIN	"12345678"
#define DEFAULT_USER_PIN_LEN	8
#define DEFAULT_SO_PIN		"87654321"
#define DEFAULT_SO_PIN_LEN	8

#define NEW_USER_PIN		"01234567"
#define NEW_USER_PIN_LEN	8
#define NEW_SO_PIN		"76543210"
#define NEW_SO_PIN_LEN		8

#endif
