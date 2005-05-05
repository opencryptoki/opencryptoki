#lib_LTLIBRARIES = libpkcs11_api.so
lib_LTLIBRARIES = libpkcs11_api.la
libdir = $(exec_prefix)/lib/opencryptoki

#libpkcs11_api_so_LDFLAGS = -g -nostartfiles -shared -Wl,-soname,$@ \
#			   -Wl,-Bsymbolic -lc -ldl -lpthread

libpkcs11_api_la_LDFLAGS = -g -nostartfiles -shared -Wl,-soname,$@ \
			   -Wl,-Bsymbolic -lc -ldl -lpthread

#LDADD = -nostartfiles

libpkcs11_api_la_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE -fPIC -I../. \
			  -I../../../include/pkcs11 -nostartfiles

AM_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE -fPIC -I../. \
	    -I../../../include/pkcs11 -nostartfiles

#libpkcs11_api_so_SOURCES = api_interface.c shrd_mem.c apiutil.c

libpkcs11_api_la_SOURCES = api_interface.c shrd_mem.c apiutil.c

install-data-local:
	ln -sf $(exec_prefix)/lib/opencryptoki/libpkcs11_api.so \
	       $(exec_prefix)/lib/libopencryptoki.so
	ln -sf $(exec_prefix)/lib/opencryptoki/libpkcs11_api.so \
	       $(exec_prefix)/lib/opencryptoki/PKCS11_API.so
	ln -sf $(exec_prefix)/sbin/ $(exec_prefix)/lib/opencryptoki/methods
	ln -sf $(exec_prefix)/sbin/ $(exec_prefix)/lib/pkcs11/methods
	mkdir -p $(exec_prefix)/lib/pkcs11
	ln -sf $(exec_prefix)/lib/opencryptoki/libpkcs11_api.so \
	       $(exec_prefix)/lib/pkcs11/PKCS11_API.so
	ln -sf $(exec_prefix)/lib/opencryptoki/stdll \
	       $(exec_prefix)/lib/pkcs11/stdll
	mkdir -p $(CONFIG_PATH)
	ln -sf $(CONFIG_PATH) $(CONFIG_PATH_ETC)
