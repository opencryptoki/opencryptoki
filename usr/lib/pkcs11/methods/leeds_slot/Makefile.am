bin_SCRIPTS = pkcs_slot
bindir=/tmp

pkcs_slot:
	cp pkcs_slot.bash pkcs_slot

clean:
	rm -f pkcs_slot

install-data-local:
	mkdir -p $(INSROOT)/usr/lib/pkcs11/methods; \
	if [ $(shell uname -m) != s390x ] ;then cp pkcs_slot \
	$(INSROOT)/usr/lib/pkcs11/methods; fi; \
	rm -f /tmp/pkcs_slot;
