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

EXTRA_DIST +=								\
	%D%/pkcsslotd.in %D%/pkcsslotd.service.in %D%/tmpfiles.conf.in

if ENABLE_DAEMON
if ENABLE_SYSTEMD
servicedir = $(unitdir)
service_DATA = %D%/pkcsslotd.service %D%/tmpfiles.conf

CLEANFILES += %D%/pkcsslotd.service %D%/tmpfiles.conf

${srcdir}/%D%/pkcsslotd.service: ${srcdir}/%D%/pkcsslotd.service.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	mv $@-t $@

${srcdir}/%D%/tmpfiles.conf: ${srcdir}/%D%/tmpfiles.conf.in
	@SED@ -e s!\@lockdir\@!$(lockdir)!g < $< > $@-t
	$(foreach TOK,$(TOKENS),\
		echo "D $(lockdir)/$(TOK) 0770 root pkcs11 -" >> $@-t;)
	mv $@-t $@
else
initddir = $(sysconfdir)/rc.d/init.d
initd_SCRIPTS = %D%/pkcsslotd

CLEANFILES += %D%/pkcsslotd
${srcdir}/%D%/pkcsslotd: ${srcdir}/%D%/pkcsslotd.in
	@SED@ -e s!\@sbindir\@!"@sbindir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@
endif
endif
