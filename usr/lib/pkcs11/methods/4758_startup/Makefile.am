bin_SCRIPTS = pkcs11_startup
bindir=/tmp

clean:
	rm -f pkcs11_startup

install-data-local:
	chmod u+x pkcs11_startup
	mkdir -p $(INSROOT)@METHOD_PATH@; \
	if [ $(shell uname -m) != s390x ] ;then cp pkcs11_startup \
	$(INSROOT)@METHOD_PATH@; fi; \
	rm -f /tmp/pkcs11_startup;
