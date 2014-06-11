noinst_PROGRAMS=aes_tests des_tests des3_tests digest_tests \
		dsa_tests rsa_tests dh_tests ssl3_tests ec_tests \
		rsaupdate_tests

AM_CFLAGS=-I. -I../../usr/include/pkcs11 -I../include -I../common -I../../usr/lib/pkcs11/common -Wall

AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon

aes_tests_SOURCES = ../../usr/lib/pkcs11/common/p11util.c aes_func.c
des3_tests_SOURCES = des3_func.c
des_tests_SOURCES = des_func.c
dh_tests_SOURCES = dh_func.c
digest_tests_SOURCES = digest_func.c 
dsa_tests_SOURCES = dsa_func.c
rsa_tests_SOURCES = rsa_func.c
ssl3_tests_SOURCES = ssl3_func.c
ec_tests_SOURCES = ec_func.c
rsaupdate_tests_SOURCES = rsaupdate_func.c
