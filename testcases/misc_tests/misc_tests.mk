noinst_PROGRAMS +=							\
	testcases/misc_tests/obj_mgmt_tests				\
	testcases/misc_tests/obj_mgmt_lock_tests			\
	testcases/misc_tests/speed testcases/misc_tests/threadmkobj	\
	testcases/misc_tests/tok_obj testcases/misc_tests/tok_rsa	\
	testcases/misc_tests/tok_des

testcases_misc_tests_obj_mgmt_tests_CFLAGS = ${testcases_inc}
testcases_misc_tests_obj_mgmt_tests_LDADD =				\
	testcases/common/libcommon.la
testcases_misc_tests_obj_mgmt_tests_SOURCES =				\
	testcases/misc_tests/obj_mgmt.c

testcases_misc_tests_obj_mgmt_lock_tests_CFLAGS = ${testcases_inc}
testcases_misc_tests_obj_mgmt_lock_tests_LDADD =			\
	testcases/common/libcommon.la
testcases_misc_tests_obj_mgmt_lock_tests_SOURCES =			\
	testcases/misc_tests/obj_mgmt_lock.c

testcases_misc_tests_speed_CFLAGS = ${testcases_inc}
testcases_misc_tests_speed_LDADD = testcases/common/libcommon.la
testcases_misc_tests_speed_SOURCES =					\
	usr/lib/common/p11util.c testcases/misc_tests/speed.c

testcases_misc_tests_threadmkobj_CFLAGS = ${testcases_inc}
testcases_misc_tests_threadmkobj_LDADD = testcases/common/libcommon.la
testcases_misc_tests_threadmkobj_SOURCES =				\
	usr/lib/common/p11util.c testcases/misc_tests/threadmkobj.c

testcases_misc_tests_tok_obj_CFLAGS = ${testcases_inc}
testcases_misc_tests_tok_obj_LDADD = testcases/common/libcommon.la
testcases_misc_tests_tok_obj_SOURCES =					\
	usr/lib/common/p11util.c testcases/misc_tests/tok_obj.c

testcases_misc_tests_tok_rsa_CFLAGS = ${testcases_inc}
testcases_misc_tests_tok_rsa_LDADD = testcases/common/libcommon.la
testcases_misc_tests_tok_rsa_SOURCES = testcases/misc_tests/tok_rsa.c

testcases_misc_tests_tok_des_CFLAGS = ${testcases_inc}
testcases_misc_tests_tok_des_LDADD = testcases/common/libcommon.la
testcases_misc_tests_tok_des_SOURCES = testcases/misc_tests/tok_des.c
