bin_PROGRAMS=4758_status
bindir=/tmp


4758_status_LDFLAGS = -ldl -lpthread -lscc
4758_status_CFLAGS = -DDEV -D_THREAD_SAFE -DDEBUG -DAPI

SOURCES = 4758_status.c
 
INCLUDES = $(CPPFLAGS) -I. -I../../../../include/pkcs11/

install-data-local:
	mkdir -p $(INSROOT)/usr/lib/pkcs11/methods; \
	cp 4758_status  $(INSROOT)/usr/lib/pkcs11/methods/; \
	rm -f /tmp/4758*;
