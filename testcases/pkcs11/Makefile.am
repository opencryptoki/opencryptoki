noinst_PROGRAMS=hw_fn misc_tests sess_mgmt_tests sess_bench attribute findobjects destroyobjects copyobjects

AM_CFLAGS=-I. -I../../usr/include/pkcs11 -I../include -I../common -I../../usr/lib/pkcs11/common -Wall

AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon

hw_fn_SOURCES = hw_fn.c
misc_tests_SOURCES = misc_func.c
sess_mgmt_tests_SOURCES = sess_mgmt.c
sess_bench_SOURCES = sess_perf.c
attribute_SOURCES = attribute.c
findobjects_SOURCES = findobjects.c
destroyobjects_SOURCES = destroyobjects.c
copyobjects_SOURCES = copyobjects.c
