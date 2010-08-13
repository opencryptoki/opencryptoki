noinst_PROGRAMS=rsa_test rsa_thread_test rsa_test_genkey rsa_sign_test

AM_CFLAGS=-I/usr/include -I. -I../../usr/include/pkcs11 -I../include -I../../usr/lib/pkcs11/common
AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon

rsa_test_LDFLAGS = $(AM_LDFLAGS)
rsa_thread_test_LDFLAGS = $(AM_LDFLAGS)
rsa_test_genkey_LDFLAGS = $(AM_LDFLAGS)
rsa_sign_test_LDFLAGS = $(AM_LDFLAGS) -lcrypto

rsa_test_SOURCES=../../usr/lib/pkcs11/common/p11util.c rsa_test.c
rsa_thread_test_SOURCES=rsa_thread_test.c
rsa_test_genkey_SOURCES=rsa_test_genkey.c
rsa_sign_test_SOURCES=rsa_sign_test.c

