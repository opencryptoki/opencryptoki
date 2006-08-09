initdir = /etc/rc.d/init.d
init_SCRIPTS = pkcsslotd

install-data-local:
	mkdir -p $(DESTDIR)/$(CONFIG_PATH_ETC)/ld.so.conf.d
	echo "$(libdir)/opencryptoki" \
	>$(DESTDIR)/$(CONFIG_PATH_ETC)/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	echo "$(libdir)/opencryptoki/stdll" \
	>>$(DESTDIR)/$(CONFIG_PATH_ETC)/ld.so.conf.d/opencryptoki-$(target_cpu).conf

