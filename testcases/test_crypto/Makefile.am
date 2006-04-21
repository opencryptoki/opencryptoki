
noinst_PROGRAMS=test_crypto

INCS=-I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
AM_CFLAGS=$(INCS)

AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon
test_crypto_LDFLAGS = $(AM_LDFLAGS)

test_crypto_SOURCES=test_crypto.c
