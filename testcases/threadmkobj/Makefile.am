noinst_PROGRAMS=threadmkobj

AM_CFLAGS=-I/usr/include -I. -I../../usr/include/pkcs11 -I../include -I../../usr/lib/pkcs11/common
AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon
threadmkobj_LDFLAGS = $(AM_LDFLAGS)

threadmkobj_SOURCES=../../usr/lib/pkcs11/common/p11util.c threadmkobj.c
