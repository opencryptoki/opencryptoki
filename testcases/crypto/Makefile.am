noinst_PROGRAMS=aes_tests des_tests des3_tests digest_tests \
		dsa_tests rsa_tests dh_tests ssl3_tests ec_tests \
		rsaupdate_tests

pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include
testdir=${top_srcdir}/testcases

AM_LDFLAGS=-L${testdir}/common -lc  -ldl -lpthread -lcommon

AM_CFLAGS=-I${testdir}/crypto	\
	  -I${incdir}/pkcs11	\
	  -I${testdir}/include	\
	  -I${testdir}/common	\
	  -I${pkcsdir}/common

aes_tests_SOURCES = ${pkcsdir}/common/p11util.c ${testdir}/crypto/aes_func.c
des3_tests_SOURCES = ${testdir}/crypto/des3_func.c
des_tests_SOURCES = ${testdir}/crypto/des_func.c
dh_tests_SOURCES = ${testdir}/crypto/dh_func.c
digest_tests_SOURCES = ${testdir}/crypto/digest_func.c 
dsa_tests_SOURCES = ${testdir}/crypto/dsa_func.c
rsa_tests_SOURCES = ${testdir}/crypto/rsa_func.c
ssl3_tests_SOURCES = ${testdir}/crypto/ssl3_func.c
ec_tests_SOURCES = ${testdir}/crypto/ec_func.c
rsaupdate_tests_SOURCES = ${testdir}/crypto/rsaupdate_func.c

noinst_HEADERS = ${testdir}/crypto/aes.h	\
		 ${testdir}/crypto/des.h	\
		 ${testdir}/crypto/des3.h	\
		 ${testdir}/crypto/digest.h	\
		 ${testdir}/crypto/ec.h		\
		 ${testdir}/crypto/rsa.h
