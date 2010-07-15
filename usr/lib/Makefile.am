SUBDIRS = pkcs11

install-data-hook:
	$(MKDIR_P) $(DESTDIR)/etc/ld.so.conf.d
	echo "$(libdir)/opencryptoki" >\
		$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(host_cpu).conf
	echo "$(libdir)/opencryptoki/stdll" >>\
		$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(host_cpu).conf
	echo "**** Remember you must run ldconfig before using the above settings ****"

