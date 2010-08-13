noinst_PROGRAMS=oc-digest

AM_CFLAGS=-g -I/usr/include -I. -I../../usr/include/pkcs11 -I../include -I../../usr/lib/pkcs11/common
AM_LDFLAGS = -lc  -ldl -lpthread
oc_digest_LDFLAGS = $(AM_LDFLAGS)

oc_digest_SOURCES=../../usr/lib/pkcs11/common/p11util.c oc-digest.c
