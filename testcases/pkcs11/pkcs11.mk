noinst_PROGRAMS +=							\
	testcases/pkcs11/hw_fn testcases/pkcs11/sess_mgmt_tests		\
	testcases/pkcs11/sess_bench testcases/pkcs11/sess_opstate	\
	testcases/pkcs11/attribute testcases/pkcs11/findobjects		\
	testcases/pkcs11/destroyobjects	testcases/pkcs11/copyobjects	\
	testcases/pkcs11/generate_keypair testcases/pkcs11/gen_purpose	\
	testcases/pkcs11/getobjectsize

testcases_pkcs11_hw_fn_CFLAGS = ${testcases_inc}
testcases_pkcs11_hw_fn_LDADD = testcases/common/libcommon.la
testcases_pkcs11_hw_fn_SOURCES = testcases/pkcs11/hw_fn.c

testcases_pkcs11_sess_mgmt_tests_CFLAGS = ${testcases_inc}
testcases_pkcs11_sess_mgmt_tests_LDADD =				\
	testcases/common/libcommon.la
testcases_pkcs11_sess_mgmt_tests_SOURCES = testcases/pkcs11/sess_mgmt.c

testcases_pkcs11_sess_bench_CFLAGS = ${testcases_inc}
testcases_pkcs11_sess_bench_LDADD = testcases/common/libcommon.la
testcases_pkcs11_sess_bench_SOURCES = testcases/pkcs11/sess_perf.c

testcases_pkcs11_sess_opstate_CFLAGS = ${testcases_inc}
testcases_pkcs11_sess_opstate_LDADD = testcases/common/libcommon.la
testcases_pkcs11_sess_opstate_SOURCES = testcases/pkcs11/sess_opstate.c

testcases_pkcs11_attribute_CFLAGS = ${testcases_inc}
testcases_pkcs11_attribute_LDADD = testcases/common/libcommon.la
testcases_pkcs11_attribute_SOURCES = testcases/pkcs11/attribute.c

testcases_pkcs11_findobjects_CFLAGS = ${testcases_inc}
testcases_pkcs11_findobjects_LDADD = testcases/common/libcommon.la
testcases_pkcs11_findobjects_SOURCES = testcases/pkcs11/findobjects.c

testcases_pkcs11_destroyobjects_CFLAGS = ${testcases_inc}
testcases_pkcs11_destroyobjects_LDADD = testcases/common/libcommon.la
testcases_pkcs11_destroyobjects_SOURCES =				\
	testcases/pkcs11/destroyobjects.c

testcases_pkcs11_copyobjects_CFLAGS = ${testcases_inc}
testcases_pkcs11_copyobjects_LDADD = testcases/common/libcommon.la
testcases_pkcs11_copyobjects_SOURCES = testcases/pkcs11/copyobjects.c

testcases_pkcs11_generate_keypair_CFLAGS = ${testcases_inc}
testcases_pkcs11_generate_keypair_LDADD = testcases/common/libcommon.la
testcases_pkcs11_generate_keypair_SOURCES =				\
	testcases/pkcs11/generate_keypair.c

testcases_pkcs11_gen_purpose_CFLAGS = ${testcases_inc}
testcases_pkcs11_gen_purpose_LDADD = testcases/common/libcommon.la
testcases_pkcs11_gen_purpose_SOURCES = testcases/pkcs11/gen_purpose.c

testcases_pkcs11_getobjectsize_CFLAGS = ${testcases_inc}
testcases_pkcs11_getobjectsize_LDADD = testcases/common/libcommon.la
testcases_pkcs11_getobjectsize_SOURCES =				\
	testcases/pkcs11/getobjectsize.c
