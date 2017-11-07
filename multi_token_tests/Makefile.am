noinst_PROGRAMS=ock_multi_token_tests

AM_CFLAGS=-I. -I../../usr/include/pkcs11 -I../include -I../common -I../../usr/lib/pkcs11/common -Wall

AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon

ock_multi_token_tests_SOURCES = ock_multi_token.c

#INCS = -I/usr/include -I/usr/include/opencryptoki/ -I/usr/include/opencryptoki-3.6.2_mti/ -I/root/opencryptoki-3.6.2_mti/usr/include/pkcs11/
#CFLAGS = -D_REENTRANT $(INCS) -fno-caller-saves -O -g -Wall -lopencryptoki -ldl -pthread

#TARGETS = ock_multi_token

#all: $(TARGETS)

#%: %.c
#	$(CC) $(CFLAGS) $(CPPFLAGS) $^ -o $@

#clean:
#	rm -f $(TARGETS)
