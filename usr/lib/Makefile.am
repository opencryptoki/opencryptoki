SUBDIRS = pkcs11

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(sysconfdir)/ld.so.conf.d
	echo "$(DESTDIR)$(libdir)/opencryptoki" >\
		$(DESTDIR)$(sysconfdir)/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	echo "$(DESTDIR)$(libdir)/opencryptoki/stdll" >>\
		$(DESTDIR)$(sysconfdir)/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	echo "**** Remember you must run ldconfig before using the above settings ****"

