lib_LTLIBRARIES=libpkcs11_4758.la
libdir = $(exec_prefix)/lib/opencryptoki/stdll

libpkcs11_4758_la_LDFLAGS = $(SCC_LIB_DIRS) -nostartfiles -shared \
			    -Wl,-Bsymbolic -Wl,-soname,$@.1 -lpthread -lscc \
			    -ldl

# Not all versions of automake observe libname_CFLAGS
libpkcs11_4758_la_CFLAGS = -DDEV -D_THREAD_SAFE -DLEEDS_BUILD

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = -DDEV -D_THREAD_SAFE -DLEEDS_BUILD

libpkcs11_4758_la_SOURCES = host_api.c util.c

INCLUDES = $(SCC_INC_DIRS) -I/usr/include -I. -I../../../include/pkcs11/stdll \
	   -I../../../include/pkcs11 

install-data-local:
	cd $(STDLL_PATH) && rm -f PKCS11_4758.so && \
		ln -sf libpkcs11_4758.so PKCS11_4758.so
