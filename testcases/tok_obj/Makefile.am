noinst_PROGRAMS=tok_obj tok_rsa tok_des

AM_CFLAGS=-I/usr/include -I. -I../../usr/include/pkcs11 -I../include -I../../usr/lib/pkcs11/common
AM_LDFLAGS=-L../common -lcommon -lc  -ldl -lpthread

tok_obj_LDFLAGS = $(AM_LDFLAGS)
tok_rsa_LDFLAGS = $(AM_LDFLAGS)
tok_des_LDFLAGS = $(AM_LDFLAGS)

tok_obj_SOURCES=../../usr/lib/pkcs11/common/p11util.c tok_obj.c
tok_rsa_SOURCES=tok_rsa.c
tok_des_SOURCES=tok_des.c
