noinst_PROGRAMS=rsa_test rsa_thread_test rsa_test_genkey

AM_CFLAGS=-I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
AM_LDFLAGS = -lc  -ldl -lpthread

rsa_test_LDFLAGS = $(AM_LDFLAGS)
rsa_thread_test_LDFLAGS = $(AM_LDFLAGS)
rsa_test_genkey_LDFLAGS = $(AM_LDFLAGS)

rsa_test_SOURCES=rsa_test.c
rsa_thread_test_SOURCES=rsa_thread_test.c
rsa_test_genkey_SOURCES=rsa_test_genkey.c

