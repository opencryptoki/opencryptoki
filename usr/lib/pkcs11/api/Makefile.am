bin_PROGRAMS=PKCS11_API.so
bindir=/tmp
PKCS11_API_so_LDFLAGS = -g -nostartfiles -shared -Wl,-soname,$@ -Wl,-Bsymbolic -lc -ldl -lpthread
PKCS11_API_so_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE -fPIC -I../. -I../../../include/pkcs11
CFLAGS = @CFLAGS@ -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE -fPIC -I../. -I../../../include/pkcs11
PKCS11_API_so_SOURCES = api_interface.c shrd_mem.c apiutil.c
#INCLUDES = -I../. -I../../../include/pkcs11 

install-data-local:
	mkdir -p $(LIB_PATH); \
	cp PKCS11_API.so $(LIB_PATH)/libpkcs11_api.so; \
	if [ $(shell uname -m) == s390x -o $(shell uname -m) == ppc64 ]; then \
		mkdir -p $(INSROOT)/usr/lib64/pkcs11; \
		ln -s $(LIB_PATH)/libpkcs11_api.so $(INSROOT)/usr/lib64/pkcs11/PKCS11_API.so; \
		ln -s $(LIB_PATH)/libpkcs11_api.so $(INSROOT)/usr/lib64/; \
		ln -s $(LIB_PATH)/libpkcs11_api.so $(INSROOT)/usr/lib64/libopencryptoki.so; \
	else \
		mkdir -p $(INSROOT)/usr/lib/pkcs11; \
		ln -s $(LIB_PATH)/libpkcs11_api.so $(INSROOT)/usr/lib/pkcs11/; \
		ln -s $(LIB_PATH)/libpkcs11_api.so $(INSROOT)/usr/lib/; \
		ln -s $(LIB_PATH)/libpkcs11_api.so $(INSROOT)/usr/lib/libopencryptoki.so; \
	fi; \
	rm -f /tmp/PKCS11_API.*;
