bin_SCRIPTS = pkcs_slot
bindir=/tmp

clean:
	rm -f pkcs_slot

install-data-local:
	chmod u+x pkcs_slot
	mkdir -p $(INSROOT)@METHOD_PATH@; \
	if [ $(shell uname -m) != s390x ] ;then cp pkcs_slot \
	$(INSROOT)@METHOD_PATH@; fi; \
	rm -f /tmp/pkcs_slot;
