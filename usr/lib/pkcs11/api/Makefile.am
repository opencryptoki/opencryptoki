bin_PROGRAMS=PKCS11_API.so
bindir=/tmp
PKCS11_API_so_LDFLAGS = -g -nostartfiles -shared -Wl,-soname,$@ -Wl,-Bsymbolic -lc -ldl -lpthread
PKCS11_API_so_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE -fPIC -I../. -I../../../include/pkcs11
CFLAGS = @CFLAGS@ -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE -fPIC -I../. -I../../../include/pkcs11
PKCS11_API_so_SOURCES = api_interface.c shrd_mem.c apiutil.c
#INCLUDES = -I../. -I../../../include/pkcs11 

install-data-local:
	mkdir -p $(INSROOT)/usr/lib/pkcs11/stdll; \
	if [ $(shell uname -m) == s390x -o $(shell uname -m) == ppc64 ]; then \
		cp PKCS11_API.so $(INSROOT)/usr/lib64/pkcs11/PKCS11_API.so; ln -s $(INSROOT)/usr/lib64/pkcs11/PKCS11_API.so $(INSROOT)/usr/lib64/; \
	else \
		cp PKCS11_API.so $(INSROOT)/usr/lib/pkcs11/; ln -s $(INSROOT)/usr/lib/pkcs11/ $(INSROOT)/usr/lib/; \
	fi; \
	rm -f /tmp/PKCS11_API.*;
