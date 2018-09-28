noinst_PROGRAMS +=							\
	%D%/aes_tests %D%/des_tests %D%/des3_tests %D%/digest_tests	\
	%D%/dsa_tests %D%/rsa_tests %D%/dh_tests %D%/ssl3_tests		\
	%D%/ec_tests %D%/rsaupdate_tests
noinst_HEADERS +=							\
	%D%/aes.h %D%/des.h %D%/des3.h %D%/digest.h %D%/ec.h %D%/rsa.h

%C%_aes_tests_CFLAGS = ${testcases_inc}
%C%_aes_tests_LDADD = testcases/common/libcommon.la
%C%_aes_tests_SOURCES =	usr/lib/common/p11util.c %D%/aes_func.c

%C%_des3_tests_CFLAGS = ${testcases_inc}
%C%_des3_tests_LDADD = testcases/common/libcommon.la
%C%_des3_tests_SOURCES = %D%/des3_func.c

%C%_des_tests_CFLAGS = ${testcases_inc}
%C%_des_tests_LDADD = testcases/common/libcommon.la
%C%_des_tests_SOURCES = %D%/des_func.c

%C%_dh_tests_CFLAGS = ${testcases_inc}
%C%_dh_tests_LDADD = testcases/common/libcommon.la
%C%_dh_tests_SOURCES = %D%/dh_func.c

%C%_digest_tests_CFLAGS = ${testcases_inc}
%C%_digest_tests_LDADD = testcases/common/libcommon.la
%C%_digest_tests_SOURCES =	%D%/digest_func.c

%C%_dsa_tests_CFLAGS = ${testcases_inc}
%C%_dsa_tests_LDADD = testcases/common/libcommon.la
%C%_dsa_tests_SOURCES = %D%/dsa_func.c

%C%_rsa_tests_CFLAGS = ${testcases_inc}
%C%_rsa_tests_LDADD = testcases/common/libcommon.la
%C%_rsa_tests_SOURCES = %D%/rsa_func.c

%C%_ssl3_tests_CFLAGS = ${testcases_inc}
%C%_ssl3_tests_LDADD = testcases/common/libcommon.la
%C%_ssl3_tests_SOURCES = %D%/ssl3_func.c

%C%_ec_tests_CFLAGS = ${testcases_inc}
%C%_ec_tests_LDADD = testcases/common/libcommon.la
%C%_ec_tests_SOURCES = %D%/ec_func.c

%C%_rsaupdate_tests_CFLAGS = ${testcases_inc}
%C%_rsaupdate_tests_LDADD = testcases/common/libcommon.la
%C%_rsaupdate_tests_SOURCES = %D%/rsaupdate_func.c
