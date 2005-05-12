bin_PROGRAMS=PKCS11_4758.so
bindir=/tmp
PKCS11_4758_so_LDFLAGS = $(SCC_LIB_DIRS) -nostartfiles -shared  -Wl,-Bsymbolic -Wl,-soname,$@.1 -lpthread -lscc -ldl

#LIBS = -lscc

# Not all versions of automake observe libname_CFLAGS
PKCS11_4758_so_CFLAGS = -DDEV -D_THREAD_SAFE -DLEEDS_BUILD

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = -DDEV -D_THREAD_SAFE -DLEEDS_BUILD

PKCS11_4758_so_SOURCES = host_api.c util.c

INCLUDES = $(SCC_INC_DIRS) -I/usr/include -I. -I../../../include/pkcs11/stdll -I../../../include/pkcs11 

GOOD_LIBRARY_NAME=libpkcs11_4758.so
BAD_LIBRARY_NAME=PKCS11_4758.so

install-data-local:
	mkdir -p $(STDLL_PATH); \
	cp $(BAD_LIBRARY_NAME) $(STDLL_PATH)/$(GOOD_LIBRARY_NAME); \
	if [ $(shell uname -m) == s390x -o $(shell uname -m) == ppc64 ]; then \
		mkdir -p $(INSROOT)/usr/lib64/pkcs11/stdll; \
		ln -s $(STDLL_PATH)/$(GOOD_LIBRARY_NAME) $(INSROOT)/usr/lib64/pkcs11/stdll/$(BAD_LIBRARY_NAME); \
		ln -s $(STDLL_PATH)/$(GOOD_LIBRARY_NAME) $(INSROOT)/usr/lib64/$(BAD_LIBRARY_NAME); \
		ln -s $(STDLL_PATH)/$(GOOD_LIBRARY_NAME) $(INSROOT)/usr/lib64/; \
	else \
		mkdir -p $(INSROOT)/usr/lib/pkcs11/stdll; \
		ln -s $(STDLL_PATH)/$(GOOD_LIBRARY_NAME) $(INSROOT)/usr/lib/pkcs11/stdll/$(BAD_LIBRARY_NAME); \
		ln -s $(STDLL_PATH)/$(GOOD_LIBRARY_NAME) $(INSROOT)/usr/lib/$(BAD_LIBRARY_NAME); \
		ln -s $(STDLL_PATH)/$(GOOD_LIBRARY_NAME) $(INSROOT)/usr/lib/; \
	fi; \
	rm -f /tmp/$(BAD_LIBRARY_NAME);
