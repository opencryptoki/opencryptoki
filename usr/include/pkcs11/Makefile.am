install:
	-mkdir -p $(HEADER_PATH)/opencryptoki
	-mkdir -p $(HEADER_PATH)/opencryptoki/pkcs11
	-cp -f apiclient.h $(HEADER_PATH)/opencryptoki
	-cp -f pkcs11types.h $(HEADER_PATH)/opencryptoki
	-cp -f pkcs11.h $(HEADER_PATH)/opencryptoki
	-ln -s $(HEADER_PATH)/opencryptoki/apiclient.h $(HEADER_PATH)/opencryptoki/pkcs11
	-ln -s $(HEADER_PATH)/opencryptoki/pkcs11types.h $(HEADER_PATH)/opencryptoki/pkcs11
	-ln -s $(HEADER_PATH)/opencryptoki/pkcs11.h $(HEADER_PATH)/opencryptoki/pkcs11
