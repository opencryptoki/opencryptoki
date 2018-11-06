noinst_LTLIBRARIES += testcases/common/libcommon.la

testcases_common_libcommon_la_LIBADD = -lc -ldl -lpthread
testcases_common_libcommon_la_CFLAGS = -c ${testcases_inc}
testcases_common_libcommon_la_SOURCES =					\
	usr/lib/common/p11util.c testcases/common/common.c
