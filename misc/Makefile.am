initdir = /etc/rc.d/init.d
init_SCRIPTS = pkcsslotd

install-data-local:
	mkdir -p $(DESTDIR)/etc/ld.so.conf.d
	echo "$(libdir)/opencryptoki" \
	>$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	echo "$(libdir)/opencryptoki/stdll" \
	>>$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf

