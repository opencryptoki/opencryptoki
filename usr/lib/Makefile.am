SUBDIRS = pkcs11

install-data-hook:
	$(MKDIR_P) $(DESTDIR)/etc/ld.so.conf.d
	echo "$(libdir)/opencryptoki" >\
		$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	echo "$(libdir)/opencryptoki/stdll" >>\
		$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	echo "**** Remember you must run ldconfig before using the above settings ****"

uninstall-hook:
	rm -f $(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
