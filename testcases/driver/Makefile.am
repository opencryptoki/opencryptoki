noinst_PROGRAMS=aes_tests des_tests des3_tests digest_tests \
		dsa_tests misc_tests obj_mgmt_tests rsa_tests \
		dh_tests ssl3_tests rijndael_tests sess_mgmt_tests \
		sess_bench ec_tests

AM_CFLAGS=-I. -I../../usr/include/pkcs11 -I../include -I../../usr/lib/pkcs11/common -Wall

AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon

aes_tests_SOURCES = ../../usr/lib/pkcs11/common/p11util.c aes_func.c
des3_tests_SOURCES = des3_func.c
des_tests_SOURCES = des_func.c
dh_tests_SOURCES = dh_func.c
digest_tests_SOURCES = digest_func.c md5.c
dsa_tests_SOURCES = dsa_func.c
misc_tests_SOURCES = misc_func.c
rijndael_tests_SOURCES = rijndael_func.c
rsa_tests_SOURCES = rsa_func.c
ssl3_tests_SOURCES = ssl3_func.c
ec_tests_SOURCES = ec_func.c
obj_mgmt_tests_SOURCES = obj_mgmt.c
sess_mgmt_tests_SOURCES = sess_mgmt.c
sess_bench_SOURCES = sess_perf.c
