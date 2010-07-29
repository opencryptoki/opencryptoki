initddir = $(sysconfdir)/rc.d/init.d

EXTRA_DIST = pkcsslotd.in

if ENABLE_DAEMON
initd_SCRIPTS = pkcsslotd

CLEANFILES = pkcsslotd

pkcsslotd: pkcsslotd.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@
endif
