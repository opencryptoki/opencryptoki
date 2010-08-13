noinst_PROGRAMS=login init_tok set_pin init_pin digest_init

AM_CFLAGS=-g -O0 -I/usr/include -I. -I../../usr/include/pkcs11 -I../include -I../../usr/lib/pkcs11/common
AM_LDFLAGS =-L../common -lc  -ldl -lpthread -lcommon

login_SOURCES = ../../usr/lib/pkcs11/common/p11util.c login.c

init_tok_SOURCES = init_tok.c

set_pin_SOURCES = set_pin.c

init_pin_SOURCES = init_pin.c

digest_init_SOURCES = digest_init.c

