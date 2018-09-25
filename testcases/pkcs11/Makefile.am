noinst_PROGRAMS=hw_fn sess_mgmt_tests sess_bench sess_opstate attribute findobjects destroyobjects copyobjects generate_keypair gen_purpose getobjectsize

pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include
testdir=${top_srcdir}/testcases

AM_LDFLAGS=-L${testdir}/common -lc -ldl -lpthread -lcommon

AM_CFLAGS=-I${testdir}/pkcs11	\
	  -I${incdir}/pkcs11	\
	  -I${testdir}/include	\
	  -I${testdir}/common	\
	  -I${pkcsdir}/common

hw_fn_SOURCES = ${testdir}/pkcs11/hw_fn.c
sess_mgmt_tests_SOURCES = ${testdir}/pkcs11/sess_mgmt.c
sess_bench_SOURCES = ${testdir}/pkcs11/sess_perf.c
sess_opstate_SOURCES = ${testdir}/pkcs11/sess_opstate.c
attribute_SOURCES = ${testdir}/pkcs11/attribute.c
findobjects_SOURCES = ${testdir}/pkcs11/findobjects.c
destroyobjects_SOURCES = ${testdir}/pkcs11/destroyobjects.c
copyobjects_SOURCES = ${testdir}/pkcs11/copyobjects.c
generate_keypair_SOURCES = ${testdir}/pkcs11/generate_keypair.c
gen_purpose_SOURCES = ${testdir}/pkcs11/gen_purpose.c
getobjectsize_SOURCES = ${testdir}/pkcs11/getobjectsize.c
