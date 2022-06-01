ACLOCAL_AMFLAGS = -I m4
EXTRA_DIST = opencryptoki.map opencryptoki_tok.map
CLEANFILES =
DISTCLEANFILES = *~
MAINTAINERCLEANFILES = test-driver \
	Makefile.in aclocal.m4 compile configure config.guess \
	config.sub depcomp install-sh ltmain.sh m4/* missing \
	depcomp ylwrap

AM_YFLAGS = -d -v
BUILT_SOURCES =

man1_MANS =
man5_MANS =
man7_MANS =
man8_MANS =
sbin_PROGRAMS =
nobase_lib_LTLIBRARIES =
noinst_HEADERS =
noinst_LTLIBRARIES =
noinst_PROGRAMS =
noinst_SCRIPTS =

if ENABLE_LIBRARY
include misc/misc.mk
else
if ENABLE_DAEMON
include misc/misc.mk
endif
endif
if ENABLE_TESTCASES
include testcases/testcases.mk
endif

include man/man.mk
include usr/usr.mk

include tools/tools.mk
include doc/doc.mk

install-data-hook:
	getent group pkcs11 > /dev/null || $(GROUPADD) -r pkcs11
if ENABLE_LIBRARY
	$(MKDIR_P) $(DESTDIR)$(libdir)/opencryptoki/stdll
	$(MKDIR_P) $(DESTDIR)$(libdir)/pkcs11
	cd $(DESTDIR)$(libdir)/opencryptoki && \
		ln -fs libopencryptoki.so PKCS11_API.so
	cd $(DESTDIR)$(libdir)/opencryptoki && \
		ln -nfs $(sbindir) methods
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -nfs $(sbindir) methods
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -fs ../opencryptoki/libopencryptoki.so PKCS11_API.so
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -fs ../opencryptoki/libopencryptoki.so libopencryptoki.so
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -nfs ../opencryptoki/stdll/ stdll
endif
if ENABLE_PKCSHSM_MK_CHANGE
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/HSM_MK_CHANGE
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/HSM_MK_CHANGE
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/HSM_MK_CHANGE
endif
if ENABLE_CCATOK
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_cca.so PKCS11_CCA.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok
	$(MKDIR_P) $(DESTDIR)$(lockdir)/ccatok
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/ccatok
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/ccatok
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/ccatok.conf || $(INSTALL) -m 644 $(srcdir)/usr/lib/cca_stdll/ccatok.conf $(DESTDIR)$(sysconfdir)/opencryptoki/ccatok.conf || true
endif
if ENABLE_EP11TOK
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_ep11.so PKCS11_EP11.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok
	$(MKDIR_P) $(DESTDIR)$(lockdir)/ep11tok
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/ep11tok
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/ep11tok
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/ep11tok.conf || $(INSTALL) -m 644 $(srcdir)/usr/lib/ep11_stdll/ep11tok.conf $(DESTDIR)$(sysconfdir)/opencryptoki/ep11tok.conf || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/ep11cpfilter.conf || $(INSTALL) -m 644 $(srcdir)/usr/lib/ep11_stdll/ep11cpfilter.conf $(DESTDIR)$(sysconfdir)/opencryptoki/ep11cpfilter.conf || true
endif
if ENABLE_P11SAK
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/p11sak_defined_attrs.conf || $(INSTALL) -g pkcs11 -m 0640 $(srcdir)/usr/sbin/p11sak/p11sak_defined_attrs.conf $(DESTDIR)$(sysconfdir)/opencryptoki/p11sak_defined_attrs.conf || true
endif
if ENABLE_ICATOK
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_ica.so PKCS11_ICA.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite
	$(MKDIR_P) $(DESTDIR)$(lockdir)/lite
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/lite
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/lite
endif
if ENABLE_SWTOK
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_sw.so PKCS11_SW.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok
	$(MKDIR_P) $(DESTDIR)$(lockdir)/swtok
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/swtok
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/swtok
endif
if ENABLE_TPMTOK
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_tpm.so PKCS11_TPM.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	$(MKDIR_P) $(DESTDIR)$(lockdir)/tpm
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/tpm
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/tpm
endif
if ENABLE_ICSFTOK
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_icsf.so PKCS11_ICSF.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	$(MKDIR_P) $(DESTDIR)$(lockdir)/icsf
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/icsf
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/icsf
endif
if ENABLE_DAEMON
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/opencryptoki.conf || $(INSTALL) -m 644 $(srcdir)/usr/sbin/pkcsslotd/opencryptoki.conf $(DESTDIR)$(sysconfdir)/opencryptoki/opencryptoki.conf || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/strength.conf || $(INSTALL) -m 640 -o root -g pkcs11 -T $(srcdir)/doc/strength-example.conf $(DESTDIR)$(sysconfdir)/opencryptoki/strength.conf || true
endif
	$(MKDIR_P) $(DESTDIR)/etc/ld.so.conf.d
	echo "$(libdir)/opencryptoki" >\
		$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	echo "$(libdir)/opencryptoki/stdll" >>\
		$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	@echo "--------------------------------------------------------------"
	@echo "Remember you must run ldconfig before using the above settings"
	@echo "--------------------------------------------------------------"
	$(MKDIR_P) $(DESTDIR)$(lockdir) $(DESTDIR)$(logdir)
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir) $(DESTDIR)$(logdir)
	$(CHMOD) 0770 $(DESTDIR)$(lockdir) $(DESTDIR)$(logdir)


uninstall-hook:
if ENABLE_LIBRARY
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki && \
		rm -f PKCS11_API.so && \
		rm -f methods; fi
	if test -d $(DESTDIR)$(libdir)/pkcs11; then \
		cd $(DESTDIR)$(libdir)/pkcs11 && \
		rm -f methods && \
		rm -f PKCS11_API.so && \
		rm -f libopencryptoki.so && \
		rm -f stdll; fi
endif
if ENABLE_CCATOK
	if test -d $(DESTDIR)/$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)/$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_CCA.so; fi
endif
if ENABLE_EP11TOK
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_EP11.so; fi
	rm -f $(DESTDIR)$(sysconfdir)/opencryptoki/ep11tok.conf 
	rm -f $(DESTDIR)$(sysconfdir)/opencryptoki/ep11cpfilter.conf
endif
if ENABLE_ICATOK
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_ICA.so; fi
endif
if ENABLE_SWTOK
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_SW.so; fi
endif
if ENABLE_TPMTOK
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -rf PKCS11_TPM.so; fi
endif
	rm -f $(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
if ENABLE_ICSFTOK
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -rf PKCS11_ICSF.so; fi
endif
if ENABLE_DAEMON
if ENABLE_SYSTEMD
	if test -e $(DESTDIR)/usr/lib/tmpfiles.d/opencryptoki.conf; then \
		rm -f $(DESTDIR)/usr/lib/tmpfiles.d/opencryptoki.conf; fi
endif
endif
if ENABLE_P11SAK
	rm -f $(DESTDIR)$(sysconfdir)/opencryptoki/p11sak_defined_attrs.conf || true
endif
	rm -f $(DESTDIR)$(sysconfdir)/opencryptoki/opencryptoki.conf || true
	rm -f $(DESTDIR)$(sysconfdir)/opencryptoki/strength.conf || true


if ENABLE_TESTCASES
PKCS11_SO_PIN ?= 76543210
PKCS11_USER_PIN ?= 01234567
PKCS11_VHSM_PIN ?= 1234567890

ci-prepare:
	killall -HUP pkcsslotd || true
	${srcdir}/testcases/ciconfig.sh "$(sysconfdir)/opencryptoki" "$(sysconfdir)/opencryptoki" "$(sysconfdir)/opencryptoki"
	@sbindir@/pkcsslotd
	@sbindir@/pkcsstats --reset-all
	for slot in `awk '/slot (.*)/ { print $$2; }' $(sysconfdir)/opencryptoki/opencryptoki.conf`; do @sbindir@/pkcsconf -c $$slot -t | grep "Flags:" | grep -q TOKEN_INITIALIZED || PKCS11_USER_PIN=$(PKCS11_USER_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) PKCSLIB=@libdir@/opencryptoki/libopencryptoki.so ${srcdir}/testcases/init_token.sh $$slot; done
#	cd ${srcdir}/testcases && PKCS11_USER_PIN=$(PKCS11_USER_PIN) PKCS11_VHSM_PIN=$(PKCS11_VHSM_PIN) PKCSLIB=@libdir@/opencryptoki/libopencryptoki.so ./init_vhsm.exp 42
#	echo "VHSM_MODE" >> "$(sysconfdir)/opencryptoki/ep11tok42.conf"

installcheck-local: all
	killall -HUP pkcsslotd || true
	@sbindir@/pkcsslotd
	if test ! -z ${PKCS11_TEST_USER}; then				\
		chmod 777 ${srcdir}/testcases &&			\
		cd ${srcdir}/testcases &&                               \
		su ${PKCS11_TEST_USER} -s /bin/bash -c "PKCS11_SO_PIN=$(PKCS11_SO_PIN) PKCS11_USER_PIN=$(PKCS11_USER_PIN) PKCSLIB=@libdir@/opencryptoki/libopencryptoki.so sh ./ock_tests.sh || true"; \
	else								\
		cd ${srcdir}/testcases && 				\
		PKCS11_SO_PIN=$(PKCS11_SO_PIN) PKCS11_USER_PIN=$(PKCS11_USER_PIN) PKCSLIB=@libdir@/opencryptoki/libopencryptoki.so sh ./ock_tests.sh || true; \
	fi
	killall -HUP pkcsslotd

ci-installcheck: ci-prepare installcheck
	killall -HUP pkcsslotd || true
	@sbindir@/pkcsslotd
	cd ${srcdir}/testcases						\
	&& export PKCSLIB=@libdir@/opencryptoki/libopencryptoki.so	\
	&& export PKCS11_USER_PIN=$(PKCS11_USER_PIN)			\
	&& ./misc_tests/p11sak_test.sh   | tee log-p11sak.txt		\
	&& ./misc_tests/pkcsconf_test.sh | tee log-pkcsconf.txt
	@sbindir@/pkcsstats --all
	killall -HUP pkcsslotd
	@echo "done"

ci-cleanup:
	@sbindir@/pkcsstats --delete-all || true
	killall -HUP pkcsslotd || true
#	@sbindir@/pkcsslotd
#	cd ${srcdir}/testcases && PKCS11_USER_PIN=$(PKCS11_USER_PIN) PKCSLIB=@libdir@/opencryptoki/libopencryptoki.so ./cleanup_vhsm.exp 42
#	killall -HUP pkcsslotd

ci-uninstall: uninstall
	rm -f $(sysconfdir)/opencryptoki/ep11tok*.conf
	rm -rf $(localstatedir)/lib/opencryptoki/*
	rm -rf $(lockdir)/*
	rm -rf $(logdir)/*

.PHONY: ci-prepare ci-installcheck ci-uninstall
endif

