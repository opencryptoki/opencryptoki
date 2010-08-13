noinst_PROGRAMS=rsa_keygen

AM_CFLAGS= -I/usr/include -I. -I../../usr/include/pkcs11 -I../include -I../../usr/lib/pkcs11/common
AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon
rsa_keygen_LDFLAGS = $(AM_LDFLAGS)

rsa_keygen_SOURCES=../../usr/lib/pkcs11/common/p11util.c rsa_keygen.c
