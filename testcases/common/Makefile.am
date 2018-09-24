noinst_LTLIBRARIES=libcommon.la

libcommon_la_LDFLAGS=-lc  -ldl -lpthread

libcommon_la_CFLAGS=-c -I/usr/include -I. -I../../usr/include/pkcs11	\
		    -I../include -I../../usr/lib/pkcs11/common

libcommon_la_SOURCES=../../usr/lib/pkcs11/common/p11util.c	\
		     common.c
