EXTRA_DIST = pkcsslotd.in pkcsslotd.service.in

if ENABLE_DAEMON
if ENABLE_SYSTEMD
servicedir = $(unitdir)
service_DATA = pkcsslotd.service

CLEANFILES = pkcsslotd.service

pkcsslotd.service: pkcsslotd.service.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	mv $@-t $@
else
initddir = $(sysconfdir)/rc.d/init.d
initd_SCRIPTS = pkcsslotd

CLEANFILES = pkcsslotd
pkcsslotd: pkcsslotd.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@
endif
endif
