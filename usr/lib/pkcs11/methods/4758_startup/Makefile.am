bin_SCRIPTS = pkcs11_startup
bindir=/tmp

pkcs11_startup:
	cp pkcs11_startup.bash pkcs11_startup

clean:
	rm -f pkcs11_startup

install-data-local:
	mkdir -p $(INSROOT)/usr/lib/pkcs11/methods; \
	if [ $(shell uname -m) != s390x ] ;then cp pkcs11_startup \
	$(INSROOT)/usr/lib/pkcs11/methods/; fi; \
	rm -f /tmp/pkcs11_startup;
