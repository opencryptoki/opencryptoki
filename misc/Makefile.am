if DAEMON
initdir = /etc/init.d
init_SCRIPTS = pkcsslotd
endif

install-data-local:
	mkdir -p $(DESTDIR)/etc/ld.so.conf.d
	echo "$(libdir)/opencryptoki" \
	>$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	echo "$(libdir)/opencryptoki/stdll" \
	>>$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf

