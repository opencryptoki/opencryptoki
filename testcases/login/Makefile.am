noinst_PROGRAMS=login init_tok set_pin init_pin digest_init login_flags_test

pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include
testdir=${top_srcdir}/testcases

AM_LDFLAGS =-L${testdir}/common -lc  -ldl -lpthread -lcommon

AM_CFLAGS=-I${testdir}/login	\
	  -I${incdir}/pkcs11	\
	  -I${testdir}/include	\
	  -I${testdir}/common	\
	  -I${pkcsdir}/common

login_SOURCES = ${pkcsdir}/common/p11util.c ${testdir}/login/login.c

init_tok_SOURCES = ${testdir}/login/init_tok.c

set_pin_SOURCES = ${testdir}/login/set_pin.c

init_pin_SOURCES = ${testdir}/login/init_pin.c

digest_init_SOURCES = ${testdir}/login/digest_init.c

login_flags_test_SOURCES = ${pkcsdir}/common/p11util.c ${testdir}/login/login_flags.c
