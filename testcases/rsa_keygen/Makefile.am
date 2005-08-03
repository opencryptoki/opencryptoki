noinst_PROGRAMS=rsa_keygen

AM_CFLAGS= -I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
AM_LDFLAGS = -lc  -ldl -lpthread
rsa_keygen_LDFLAGS = $(AM_LDFLAGS)

rsa_keygen_SOURCES=rsa_keygen.c
