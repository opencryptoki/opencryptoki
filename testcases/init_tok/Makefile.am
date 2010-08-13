noinst_PROGRAMS=init_tok

AM_CFLAGS=-I/usr/include -I. -I../../usr/include/pkcs11 -I../include -I../../usr/lib/pkcs11/common

init_tok_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon

init_tok_SOURCES=../../usr/lib/pkcs11/common/p11util.c init_tok.c
