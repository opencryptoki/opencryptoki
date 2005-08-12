noinst_PROGRAMS=login init_tok set_pin init_pin digest_init

AM_CFLAGS=-g -O0 -I/usr/include -I. -I../../usr/include/pkcs11 -I ../include
AM_LDFLAGS = -lc  -ldl -lpthread

login_SOURCES = login.c common.c

init_tok_SOURCES = init_tok.c common.c

set_pin_SOURCES = set_pin.c common.c

init_pin_SOURCES = init_pin.c common.c

digest_init_SOURCES = digest_init.c common.c

