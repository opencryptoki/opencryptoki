
noinst_PROGRAMS=test_crypto

INCS=-I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
AM_CFLAGS=$(INCS)

AM_LDFLAGS = -lc  -ldl -lpthread
test_crypto_LDFLAGS = $(AM_LDFLAGS)

test_crypto_SOURCES=test_crypto.c
