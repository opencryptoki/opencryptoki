noinst_PROGRAMS=login aes_func rijndael hw_fn

AM_CFLAGS=-I/usr/include -I. -I../../usr/include/pkcs11 -I../include -I../../usr/lib/pkcs11/common
AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon

login_LDFLAGS = $(AM_LDFLAGS)
aes_func_LDFLAGS = $(AM_LDFLAGS)
rijndael_LDFLAGS = $(AM_LDFLAGS)
hw_fn_LDFLAGS = $(AM_LDFLAGS)

login_SOURCES=../../usr/lib/pkcs11/common/p11util.c login.c
aes_func_SOURCES=aes_func.c
rijndael_SOURCES=rijndael.c
hw_fn_SOURCES=hw_fn.c

