bin_PROGRAMS=PKCS11_4758.so
bindir=/tmp
PKCS11_4758_so_LDFLAGS = $(SCC_LIB_DIRS) -nostartfiles -shared  -Wl,-Bsymbolic -Wl,-soname,$@.1 -lpthread -lscc -ldl

#LIBS = -lscc

PKCS11_4758_so_CFLAGS = -DDEV -D_THREAD_SAFE -DLINUX -DLEEDS_BUILD -DAIXSTDLL -D_LINUX_ 

PKCS11_4758_so_SOURCES = host_api.c util.c

INCLUDES = $(SCC_INC_DIRS) -I/usr/include -I. -I../../../include/pkcs11/stdll -I../../../include/pkcs11 

install-data-local:
	mkdir -p $(INSROOT)/usr/lib/pkcs11/stdll; \
	if [ $(shell uname -m) != s390x ] ;then cp PKCS11_4758.so \
	$(INSROOT)/usr/lib/pkcs11/stdll/PKCS11_4758.so; fi; \
	rm -f /tmp/PKCS11_4758.*;
