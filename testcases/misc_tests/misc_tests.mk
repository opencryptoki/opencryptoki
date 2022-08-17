noinst_PROGRAMS +=							\
	testcases/misc_tests/obj_mgmt_tests				\
	testcases/misc_tests/obj_mgmt_lock_tests			\
	testcases/misc_tests/speed testcases/misc_tests/threadmkobj	\
	testcases/misc_tests/tok_obj testcases/misc_tests/tok_rsa	\
	testcases/misc_tests/tok_des					\
	testcases/misc_tests/fork testcases/misc_tests/multi_instance   \
	testcases/misc_tests/obj_lock testcases/misc_tests/tok2tok_transport \
	testcases/misc_tests/obj_lock testcases/misc_tests/reencrypt    \
	testcases/misc_tests/cca_export_import_test			\
	testcases/misc_tests/events testcases/misc_tests/dual_functions

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

testcases_misc_tests_fork_CFLAGS = ${testcases_inc}
testcases_misc_tests_fork_LDADD = testcases/common/libcommon.la
testcases_misc_tests_fork_SOURCES = testcases/misc_tests/fork.c

testcases_misc_tests_multi_instance_CFLAGS = ${testcases_inc}
testcases_misc_tests_multi_instance_LDADD = testcases/common/libcommon.la
testcases_misc_tests_multi_instance_SOURCES = 				\
	testcases/misc_tests/multi_instance.c

testcases_misc_tests_obj_lock_CFLAGS = ${testcases_inc}
testcases_misc_tests_obj_lock_LDADD = testcases/common/libcommon.la
testcases_misc_tests_obj_lock_SOURCES = 				\
	testcases/misc_tests/obj_lock.c

testcases_misc_tests_tok2tok_transport_CFLAGS = ${testcases_inc}
testcases_misc_tests_tok2tok_transport_LDADD = testcases/common/libcommon.la
testcases_misc_tests_tok2tok_transport_SOURCES = 			\
	testcases/misc_tests/tok2tok_transport.c

testcases_misc_tests_reencrypt_CFLAGS = ${testcases_inc}
testcases_misc_tests_reencrypt_LDADD = testcases/common/libcommon.la
testcases_misc_tests_reencrypt_SOURCES = 			\
	testcases/misc_tests/reencrypt.c

testcases_misc_tests_cca_export_import_test_CFLAGS = ${testcases_inc}
testcases_misc_tests_cca_export_import_test_LDADD =			\
	testcases/common/libcommon.la
testcases_misc_tests_cca_export_import_test_SOURCES =			\
	testcases/misc_tests/cca_export_import_test.c
	
testcases_misc_tests_events_CFLAGS = ${testcases_inc}
testcases_misc_tests_events_LDADD = testcases/common/libcommon.la
testcases_misc_tests_events_SOURCES = testcases/misc_tests/events.c	\
	usr/lib/common/event_client.c

testcases_misc_tests_dual_functions_CFLAGS = ${testcases_inc}
testcases_misc_tests_dual_functions_LDADD = testcases/common/libcommon.la
testcases_misc_tests_dual_functions_SOURCES = 				\
	testcases/misc_tests/dual_functions.c
