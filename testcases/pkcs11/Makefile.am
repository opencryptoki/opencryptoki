noinst_PROGRAMS=hw_fn sess_mgmt_tests sess_bench sess_opstate attribute findobjects destroyobjects copyobjects generate_keypair gen_purpose getobjectsize

AM_CFLAGS=-I. -I../../usr/include/pkcs11 -I../include -I../common -I../../usr/lib/pkcs11/common -Wall

AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon

hw_fn_SOURCES = hw_fn.c
sess_mgmt_tests_SOURCES = sess_mgmt.c
sess_bench_SOURCES = sess_perf.c
sess_opstate_SOURCES = sess_opstate.c
attribute_SOURCES = attribute.c
findobjects_SOURCES = findobjects.c
destroyobjects_SOURCES = destroyobjects.c
copyobjects_SOURCES = copyobjects.c
generate_keypair_SOURCES = generate_keypair.c
gen_purpose_SOURCES = gen_purpose.c
getobjectsize_SOURCES = getobjectsize.c
