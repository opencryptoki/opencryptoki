noinst_LTLIBRARIES += %D%/libcommon.la

%C%_libcommon_la_LIBADD = -lc -ldl -lpthread
%C%_libcommon_la_CFLAGS = -c ${testcases_inc}
%C%_libcommon_la_SOURCES = usr/lib/common/p11util.c %D%/common.c
