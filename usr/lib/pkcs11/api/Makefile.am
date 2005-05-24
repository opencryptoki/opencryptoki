lib_LTLIBRARIES = libopencryptoki.la
libdir = $(exec_prefix)/lib/opencryptoki

SO_CURRENT=0
SO_REVISION=0
SO_AGE=0

libopencryptoki_la_LDFLAGS = -shared -Wl,-Bsymbolic -lc -ldl -lpthread \
			     -version-info $(SO_CURRENT):$(SO_REVISION):\
			     $(SO_AGE)

# Not all versions of automake observe libname_CFLAGS
libopencryptoki_la_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE \
			    -fPIC -I../. -I../../../include/pkcs11

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE \
	    -fPIC -I../. -I../../../include/pkcs11

libopencryptoki_la_SOURCES = api_interface.c shrd_mem.c apiutil.c

install-data-local:
	cd $(LIB_ROOT_PATH) && rm -f libopencryptoki.so && \
		ln -sf opencryptoki/libopencryptoki.so libopencryptoki.so
	cd $(LIB_ROOT_PATH) && rm -f libopencryptoki.so.$(SO_CURRENT) && \
		ln -sf opencryptoki/libopencryptoki.so.$(SO_CURRENT) \
		libopencryptoki.so.$(SO_CURRENT)
	cd $(LIB_ROOT_PATH)/opencryptoki && rm -f PKCS11_API.so && \
		ln -sf libopencryptoki.so PKCS11_API.so
	cd $(LIB_ROOT_PATH)/opencryptoki && rm -f methods && \
		ln -sf ../../sbin/ methods
	mkdir -p $(LIB_ROOT_PATH)/pkcs11
	cd $(LIB_ROOT_PATH)/pkcs11 && rm -f methods && \
		ln -sf ../../sbin/ methods
	cd $(LIB_ROOT_PATH)/pkcs11 && rm -f PKCS11_API.so && \
		ln -sf ../opencryptoki/libopencryptoki.so PKCS11_API.so
	cd $(LIB_ROOT_PATH)/pkcs11 && rm -f stdll && \
		ln -sf ../opencryptoki/stdll/ stdll
	mkdir -p $(CONFIG_PATH)
	groupadd pkcs11
	chown root:pkcs11 $(CONFIG_PATH)
	chmod 775 $(CONFIG_PATH)
	if [ ! -L $(CONFIG_PATH_ETC)/pkcs11 ] ; then \
		if [ -e $(CONFIG_PATH_ETC)/pkcs11/* ] ; then \
			mv $(CONFIG_PATH_ETC)/pkcs11/* $(CONFIG_PATH) ;\
		fi; \
	fi
	cd $(CONFIG_PATH_ETC) && rm -rf pkcs11 && \
		ln -sf $(CONFIG_PATH) pkcs11
