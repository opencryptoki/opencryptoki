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

EXTRA_DIST += misc/pkcsslotd.in misc/pkcsslotd.service.in 		\
	misc/tmpfiles.conf.in misc/opencryptoki.pc.in
	
pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = misc/opencryptoki.pc

if ENABLE_DAEMON
if ENABLE_SYSTEMD
servicedir = $(unitdir)
service_DATA = misc/pkcsslotd.service

tmpfilesdir = /usr/lib/tmpfiles.d
tmpfiles_DATA = misc/opencryptoki.conf

CLEANFILES += misc/pkcsslotd.service misc/opencryptoki.conf

${srcdir}/misc/pkcsslotd.service: ${srcdir}/misc/pkcsslotd.service.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	mv $@-t $@

${srcdir}/misc/opencryptoki.conf: ${srcdir}/misc/tmpfiles.conf.in
	@SED@ -e s!\@lockdir\@!$(lockdir)!g < $< > $@-t
	$(foreach TOK,$(TOKENS),\
		echo "D $(lockdir)/$(TOK) 0770 root pkcs11 -" >> $@-t;)
	mv $@-t $@
else
initddir = $(sysconfdir)/rc.d/init.d
initd_SCRIPTS = misc/pkcsslotd

CLEANFILES += misc/pkcsslotd
${srcdir}/misc/pkcsslotd: ${srcdir}/misc/pkcsslotd.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@
endif
endif
