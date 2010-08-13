noinst_PROGRAMS=speed

AM_CFLAGS=-I/usr/include -I. -I../../usr/include/pkcs11 -I../include -I../../usr/lib/pkcs11/common
AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon
speed_LDFLAGS = $(AM_LDFLAGS)

speed_SOURCES=../../usr/lib/pkcs11/common/p11util.c speed.c
