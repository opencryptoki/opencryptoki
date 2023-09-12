noinst_PROGRAMS +=							\
	testcases/login/login testcases/login/init_tok			\
	testcases/login/set_pin testcases/login/init_pin		\
	testcases/login/digest_init testcases/login/login_flags_test

EXTRA_DIST += testcases/login/login_test.sh

testcases_login_login_CFLAGS = ${testcases_inc}
testcases_login_login_LDADD = testcases/common/libcommon.la
testcases_login_login_SOURCES =						\
	usr/lib/common/p11util.c testcases/login/login.c

testcases_login_init_tok_CFLAGS = ${testcases_inc}
testcases_login_init_tok_LDADD = testcases/common/libcommon.la
testcases_login_init_tok_SOURCES = testcases/login/init_tok.c

testcases_login_set_pin_CFLAGS = ${testcases_inc}
testcases_login_set_pin_LDADD = testcases/common/libcommon.la
testcases_login_set_pin_SOURCES = testcases/login/set_pin.c

testcases_login_init_pin_CFLAGS = ${testcases_inc}
testcases_login_init_pin_LDADD = testcases/common/libcommon.la
testcases_login_init_pin_SOURCES = testcases/login/init_pin.c

testcases_login_digest_init_CFLAGS = ${testcases_inc}
testcases_login_digest_init_LDADD = testcases/common/libcommon.la
testcases_login_digest_init_SOURCES = testcases/login/digest_init.c

testcases_login_login_flags_test_CFLAGS = ${testcases_inc}
testcases_login_login_flags_test_LDADD = testcases/common/libcommon.la
testcases_login_login_flags_test_SOURCES =				\
	usr/lib/common/p11util.c testcases/login/login_flags.c
