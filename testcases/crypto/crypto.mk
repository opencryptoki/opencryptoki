noinst_PROGRAMS += testcases/crypto/aes_tests				\
	testcases/crypto/des_tests testcases/crypto/des3_tests		\
	testcases/crypto/digest_tests testcases/crypto/dsa_tests	\
	testcases/crypto/rsa_tests testcases/crypto/dh_tests		\
	testcases/crypto/ssl3_tests testcases/crypto/ec_tests		\
	testcases/crypto/rsaupdate_tests				\
	testcases/crypto/dilithium_tests testcases/crypto/ab_tests	\
	testcases/crypto/kyber_tests
noinst_HEADERS +=							\
	testcases/crypto/aes.h testcases/crypto/des.h			\
	testcases/crypto/des3.h testcases/crypto/digest.h		\
	testcases/crypto/ec.h testcases/crypto/rsa.h			\
	testcases/crypto/dilithium.h testcases/crypto/kyber.h

testcases_crypto_aes_tests_CFLAGS = ${testcases_inc}
testcases_crypto_aes_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_aes_tests_SOURCES =					\
	usr/lib/common/p11util.c testcases/crypto/aes_func.c

testcases_crypto_des3_tests_CFLAGS = ${testcases_inc}
testcases_crypto_des3_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_des3_tests_SOURCES = testcases/crypto/des3_func.c

testcases_crypto_des_tests_CFLAGS = ${testcases_inc}
testcases_crypto_des_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_des_tests_SOURCES = testcases/crypto/des_func.c

testcases_crypto_dh_tests_CFLAGS = ${testcases_inc}
testcases_crypto_dh_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_dh_tests_SOURCES = testcases/crypto/dh_func.c

testcases_crypto_digest_tests_CFLAGS = ${testcases_inc}
testcases_crypto_digest_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_digest_tests_SOURCES =	testcases/crypto/digest_func.c

testcases_crypto_dsa_tests_CFLAGS = ${testcases_inc}
testcases_crypto_dsa_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_dsa_tests_SOURCES = testcases/crypto/dsa_func.c

testcases_crypto_rsa_tests_CFLAGS = ${testcases_inc}
testcases_crypto_rsa_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_rsa_tests_SOURCES = testcases/crypto/rsa_func.c

testcases_crypto_ssl3_tests_CFLAGS = ${testcases_inc}
testcases_crypto_ssl3_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_ssl3_tests_SOURCES = testcases/crypto/ssl3_func.c

testcases_crypto_ec_tests_CFLAGS = ${testcases_inc}
testcases_crypto_ec_tests_LDFLAGS = -lcrypto
testcases_crypto_ec_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_ec_tests_SOURCES = testcases/crypto/ec_func.c

testcases_crypto_dilithium_tests_CFLAGS = ${testcases_inc}
testcases_crypto_dilithium_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_dilithium_tests_SOURCES = testcases/crypto/dilithium_func.c

testcases_crypto_rsaupdate_tests_CFLAGS = ${testcases_inc}
testcases_crypto_rsaupdate_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_rsaupdate_tests_SOURCES = testcases/crypto/rsaupdate_func.c

testcases_crypto_ab_tests_CFLAGS = ${testcases_inc}
testcases_crypto_ab_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_ab_tests_SOURCES = testcases/crypto/abfunc.c

testcases_crypto_kyber_tests_CFLAGS = ${testcases_inc}
testcases_crypto_kyber_tests_LDADD = testcases/common/libcommon.la
testcases_crypto_kyber_tests_SOURCES = testcases/crypto/kyber_func.c
