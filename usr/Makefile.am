if BUILD_UTILS
SUBDIRS = lib sbin
else
SUBDIRS = lib
endif

install:
	-mkdir -p $(HEADER_PATH)/opencryptoki
	-mkdir -p $(HEADER_PATH)/opencryptoki/pkcs11
	-cp -f include/pkcs11/apiclient.h $(HEADER_PATH)/opencryptoki
	-cp -f include/pkcs11/pkcs11types.h $(HEADER_PATH)/opencryptoki
	-ln -s $(HEADER_PATH)/opencryptoki/apiclient.h $(HEADER_PATH)/opencryptoki/pkcs11
	-ln -s $(HEADER_PATH)/opencryptoki/pkcs11types.h $(HEADER_PATH)/opencryptoki/pkcs11