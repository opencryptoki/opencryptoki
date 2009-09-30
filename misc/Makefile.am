EXTRA_DIST = pkcsslotd.in
if DAEMON
initdir = /etc/init.d
init_SCRIPTS = pkcsslotd
endif


CLEANFILES = pkcsslotd

pkcsslotd: pkcsslotd.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@
