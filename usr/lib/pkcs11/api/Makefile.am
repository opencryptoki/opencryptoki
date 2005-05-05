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
	cd $(LIB_ROOT_PATH) && ln -sf opencryptoki/libpkcs11_api.so \
	                              libopencryptoki.so
	cd $(LIB_ROOT_PATH)/opencryptoki && ln -sf libpkcs11_api.so \
	                                           PKCS11_API.so
	cd $(LIB_ROOT_PATH)/opencryptoki && ln -sf ../../sbin/ methods
	mkdir -p $(LIB_ROOT_PATH)/pkcs11
	cd $(LIB_ROOT_PATH)/pkcs11 && ln -sf ../../sbin/ methods
	cd $(LIB_ROOT_PATH)/pkcs11 \
        && ln -sf ../opencryptoki/libpkcs11_api.so PKCS11_API.so
	cd $(LIB_ROOT_PATH)/pkcs11 && ln -sf ../opencryptoki/stdll/ stdll
	mkdir -p $(CONFIG_PATH)
	ln -sf $(CONFIG_PATH) $(CONFIG_PATH_ETC)
