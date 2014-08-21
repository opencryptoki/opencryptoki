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

#include <sys/time.h>

#pragma GCC system_header
static struct timeval timev1;
static struct timeval timev2;
static struct timeval timevr;

#ifndef timersub
/* We just need timersub, so instead of requiring _BSD_SOURCE, *
 * define it just like glibc does                              */
#define timersub(t1, t2, tr)                                    \
        do {                                                    \
                (tr)->tv_sec = (t1)->tv_sec - (t2)->tv_sec;     \
                (tr)->tv_usec = (t1)->tv_usec - (t2)->tv_usec;  \
                if ((tr)->tv_usec < 0) {                        \
                        --(tr)->tv_sec;                         \
                        (tr)->tv_usec += 1000000;               \
                }                                               \
        } while (0)
#endif

#include "p11util.h"

extern CK_ULONG t_total;		// total test assertions
extern CK_ULONG t_ran;			// number of assertions ran
extern CK_ULONG t_passed;		// number of assertions passed
extern CK_ULONG t_failed;		// number of assertions failed
extern CK_ULONG t_skipped;		// number of assertions skipped
extern CK_ULONG t_errors;               // number of errors

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
CK_BBOOL securekey;

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

#define testcase_setup(total)						\
	t_total = 0;                                                    \
	t_errors = 0;

#define testsuite_begin(_fmt, ...)                                       \
        do {                                                            \
                printf("------\n* TESTSUITE %s BEGIN " _fmt "\n",        \
                        __func__, ## __VA_ARGS__);                      \
        } while (0)

#define testcase_begin(_fmt, ...)                                       \
        do {                                                            \
                printf("------\n* TESTCASE %s BEGIN " _fmt "\n",        \
                        __func__, ## __VA_ARGS__);                      \
		gettimeofday(&timev1, NULL);				\
        } while (0)

#define testcase_begin_f(_func, _fmt, ...)                              \
        do {                                                            \
                printf("------\n* TESTCASE %s BEGIN " _fmt "\n",        \
                        _func, ## __VA_ARGS__);                         \
		gettimeofday(&timev1, NULL);				\
        } while (0)

#define testcase_new_assertion()					\
		t_ran++;

#define testcase_pass(_fmt, ...)                                        \
        do {                                                            \
                gettimeofday(&timev2, NULL);                            \
                timersub(&timev2, &timev1, &timevr);                    \
                printf("* TESTCASE %s PASS (elapsed time %lds %ldus) " _fmt "\n\n",\
                        __func__, timevr.tv_sec, timevr.tv_usec,        \
                        ## __VA_ARGS__);                                \
		t_passed++;						\
        } while (0)

#define testcase_pass_f(_func, _fmt, ...)                               \
        do {                                                            \
                gettimeofday(&timev2, NULL);                            \
                timersub(&timev2, &timev1, &timevr);                    \
                printf("* TESTCASE %s PASS (elapsed time %lds %ldus) " _fmt "\n\n",\
                       _func, timevr.tv_sec, timevr.tv_usec,            \
                        ## __VA_ARGS__);                                \
		t_passed++;						\
        } while (0)

#define testsuite_skip(_n,_fmt, ...)                                    \
        do {                                                            \
                printf("* TESTSUITE %s SKIP " _fmt "\n\n",              \
                        __func__, ## __VA_ARGS__);                      \
		t_skipped+= _n;						\
        } while (0)

#define testcase_skip(_fmt, ...)                                        \
        do {                                                            \
                printf("* TESTCASE %s SKIP " _fmt "\n\n",               \
                        __func__, ## __VA_ARGS__);                      \
		t_skipped++;						\
        } while (0)

#define testcase_skip_f(_func, _fmt, ...)                               \
        do {                                                            \
                printf("* TESTCASE %s SKIP " _fmt "\n\n",               \
                        _func, ## __VA_ARGS__);                         \
                t_skipped++;						\
        } while (0)

#define testcase_notice(_fmt, ...)                                      \
	do {								\
		printf("* TESTCASE %s NOTICE " _fmt "\n",               \
			__func__, ## __VA_ARGS__);			\
	} while (0)

#define testcase_notice_f(_func, _fmt, ...)                             \
	do {								\
		printf("* TESTCASE %s NOTICE " _fmt "\n",               \
			__func, ## __VA_ARGS__);			\
	} while (0)

#define testcase_fail(_fmt, ...)                                        \
        do {                                                            \
		printf("* TESTCASE %s FAIL (%s:%d) " _fmt "\n",		\
                        __func__, __FILE__, __LINE__,                   \
                        ## __VA_ARGS__);				\
		t_failed++;						\
        } while (0)

#define testcase_fail_f(_func, _fmt, ...)                               \
        do {                                                            \
		printf("* TESTCASE %s FAIL (%s:%d) " _fmt "\n",		\
                        _func, __FILE__, __LINE__,                      \
                        ## __VA_ARGS__);				\
		t_failed++;						\
        } while (0)

#define testcase_error(_fmt, ...)                                       \
	do {								\
		printf("* TESTCASE %s ERROR (%s:%d)) " _fmt "\n",       \
                        __func__, __FILE__, __LINE__,                   \
                        ## __VA_ARGS__);                                \
		t_errors++;                                             \
	} while (0)

#define testcase_error_f(_func, _fmt, ...)                              \
	do {								\
		printf("* TESTCASE %s ERROR (%s:%d)) " _fmt "\n",       \
                        _func, __FILE__, __LINE__,                      \
                        ## __VA_ARGS__);                                \
		t_errors++;                                             \
	} while (0)

#define testcase_print_result()						\
	do {								\
		printf("Total=%lu, Ran=%lu, Passed=%lu, Failed=%lu, Skipped=%lu, Errors=%lu\n", \
			(t_ran + t_skipped), t_ran, t_passed, t_failed, t_skipped, t_errors);	\
	} while (0)

#define testcase_rw_session()                                           \
        do {                                                            \
                flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;            \
                rc = funcs->C_OpenSession(SLOT_ID, flags,               \
                        NULL, NULL, &session );                         \
                if (rc != CKR_OK) {                                     \
                        testcase_error("C_OpenSession() rc = %s",       \
                                p11_get_ckr(rc));                       \
                        session = CK_INVALID_HANDLE;                    \
                        goto testcase_cleanup;                          \
                }                                                       \
        } while (0)

#define testcase_ro_session()                                           \
        do {                                                            \
                flags = CKF_SERIAL_SESSION                              \
                rc = funcs->C_OpenSession(SLOT_ID, flags,               \
                        NULL, NULL, &session );                         \
                if (rc != CKR_OK) {                                     \
                        testcase_error("C_OpenSession() rc = %s",       \
                                p11_get_ckr(rc));                       \
                        session = CK_INVALID_HANDLE;                    \
                        goto testcase_cleanup;                          \
                }                                                       \
        } while (0)

#define testcase_close_session()                                                \
        do {                                                                    \
                if (session != CK_INVALID_HANDLE) {                             \
                        rc = funcs->C_CloseSession(session);                    \
                        if (rc != CKR_OK) {                                     \
                                testcase_error("C_CloseSession() rc = %s",      \
                                                p11_get_ckr(rc));               \
                        }                                                       \
                }                                                               \
        } while (0)

#define testcase_closeall_session()                                     \
        do {                                                            \
                rc = funcs->C_CloseAllSessions(SLOT_ID);                \
                if (rc != CKR_OK) {                                     \
                        testcase_error("C_CloseAllSessions() rc = %s",  \
                                p11_get_ckr(rc));                       \
                }                                                       \
        } while (0)


#define testcase_user_login()                                           \
        do {                                                            \
                if (get_user_pin(user_pin)) {                           \
                        testcase_error("get_user_pin() failed");        \
                        testcase_closeall_session();			\
			exit(-1);		                        \
                }                                                       \
                user_pin_len = (CK_ULONG) strlen( (char *) user_pin);   \
                rc = funcs->C_Login(session, CKU_USER,                  \
                        user_pin, user_pin_len);                        \
                if (rc != CKR_OK) {                                     \
                        testcase_error("C_Login() rc = %s",             \
                                p11_get_ckr(rc));                       \
                        goto testcase_cleanup;                          \
                }                                                       \
        } while (0)

#define testcase_user_logout()                                          \
	do {								\
		rc = funcs->C_Logout(session);				\
		if (rc != CKR_OK) {                                     \
			testcase_error("C_Logout() rc = %s",            \
					p11_get_ckr(rc));               \
			if (rc != CKR_USER_NOT_LOGGED_IN)               \
				goto testcase_cleanup;                  \
		}                                                       \
	} while (0)


#define testcase_so_login()                                             \
        do {                                                            \
                if (get_so_pin(so_pin)) {                               \
                        testcase_error("get_so_pin() failed");          \
                        rc = -1;                                        \
                        goto testcase_cleanup;                          \
                }                                                       \
                so_pin_len = (CK_ULONG) strlen( (char *) so_pin);       \
                rc = funcs->C_Login(session, CKU_SO,                    \
                        so_pin, so_pin_len);                            \
                if (rc != CKR_OK) {                                     \
                        testcase_error("C_Login() rc = %s",             \
                                p11_get_ckr(rc));                       \
                        goto testcase_cleanup;                          \
                }                                                       \
        } while (0)


#endif
