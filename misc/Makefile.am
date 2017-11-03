TOKENS = swtok

if ENABLE_ICATOK
TOKENS += lite
endif

if ENABLE_EP11TOK
TOKENS += ep11tok
endif

if ENABLE_TPMTOK
TOKENS += tpm
endif

if ENABLE_CCATOK
TOKENS += ccatok
endif

if ENABLE_ICSFTOK
TOKENS += icsf
endif

EXTRA_DIST = pkcsslotd.in pkcsslotd.service.in tmpfiles.conf.in

if ENABLE_DAEMON
if ENABLE_SYSTEMD
servicedir = $(unitdir)
service_DATA = pkcsslotd.service tmpfiles.conf

CLEANFILES = pkcsslotd.service tmpfiles.conf

pkcsslotd.service: pkcsslotd.service.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	mv $@-t $@

tmpfiles.conf: tmpfiles.conf.in
	@SED@ -e s!\@lockdir\@!$(lockdir)!g < $< > $@-t
	$(foreach TOK,$(TOKENS),\
		echo "D $(lockdir)/$(TOK) 0770 root pkcs11 -" >> $@-t;)
	mv $@-t $@

install-data-hook:
	mkdir -p $(DESTDIR)/usr/lib/tmpfiles.d
	cp tmpfiles.conf $(DESTDIR)/usr/lib/tmpfiles.d/opencryptoki.conf
	$(CHMOD) 0644 $(DESTDIR)/usr/lib/tmpfiles.d/opencryptoki.conf
	rm -f $(DESTDIR)/usr/lib/systemd/system/tmpfiles.conf

uninstall-hook:
	if test -e $(DESTDIR)/usr/lib/tmpfiles.d/opencryptoki.conf; then \
		rm -f $(DESTDIR)/usr/lib/tmpfiles.d/opencryptoki.conf; fi
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
