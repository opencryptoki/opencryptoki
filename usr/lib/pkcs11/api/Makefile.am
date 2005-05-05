lib_LTLIBRARIES = libpkcs11_api.la
libdir = $(exec_prefix)/lib/opencryptoki

#libpkcs11_api_la_LDFLAGS = -g -nostartfiles -shared -Wl,-soname,$@ \
#			   -Wl,-Bsymbolic -lc -ldl -lpthread

libpkcs11_api_la_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE -fPIC -I../. \
			  -I../../../include/pkcs11

AM_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE -fPIC -I../. \
	    -I../../../include/pkcs11

libpkcs11_api_la_SOURCES = api_interface.c shrd_mem.c apiutil.c

install-data-local:
	cd $(exec_prefix)/lib && ln -sf opencryptoki/libpkcs11_api.so \
	                                libopencryptoki.so
	cd $(exec_prefix)/lib/opencryptoki && ln -sf libpkcs11_api.so \
	                                             PKCS11_API.so
	cd $(exec_prefix)/lib/opencryptoki && ln -sf ../../sbin/ methods
	mkdir -p $(exec_prefix)/lib/pkcs11
	cd $(exec_prefix)/lib/pkcs11 && ln -sf ../../sbin/ methods
	cd $(exec_prefix)/lib/pkcs11 \
        && ln -sf ../opencryptoki/libpkcs11_api.so PKCS11_API.so
	cd $(exec_prefix)/lib/pkcs11 && ln -sf ../opencryptoki/stdll/ stdll
	mkdir -p $(CONFIG_PATH)
	ln -sf $(CONFIG_PATH) $(CONFIG_PATH_ETC)
