lib_LTLIBRARIES=libpkcs11_api.so
libdir = $(exec_prefix)/lib/opencryptoki

libpkcs11_api_so_LDFLAGS = -g -nostartfiles -shared -Wl,-soname,$@ \
			   -Wl,-Bsymbolic -lc -ldl -lpthread

libpkcs11_api_so_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE -fPIC -I../. \
			  -I../../../include/pkcs11

CFLAGS = @CFLAGS@ -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE -fPIC -I../. \
	 -I../../../include/pkcs11

libpkcs11_api_so_SOURCES = api_interface.c shrd_mem.c apiutil.c

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
	ln -sf $(exec_prefix)/var/lib/pkcs11 $(exec_prefix)/etc/
	mkdir -p $(CONFIG_PATH)