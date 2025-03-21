ACLOCAL_AMFLAGS = -I m4
CLEANFILES =
DISTCLEANFILES = *~ opencryptoki.map.sym opencryptoki_tok.map.sym
MAINTAINERCLEANFILES = test-driver \
	Makefile.in aclocal.m4 compile configure config.guess \
	config.sub depcomp install-sh ltmain.sh m4/* missing \
	depcomp ylwrap

if AIX
EXTRA_DIST = opencryptoki.map opencryptoki_tok.map \
	opencryptoki.map.sym opencryptoki_tok.map.sym
SHLIBEXT=a
LNFLAG=fs
KILLALL = ./kill-all
else
EXTRA_DIST = opencryptoki.map opencryptoki_tok.map
SHLIBEXT=so
LNFLAG=nfs
KILLALL = killall
endif

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
if AIX
	lsgroup $(pkcs_group) > /dev/null || $(GROUPADD) -a pkcs11
	lsuser $(pkcsslotd_user) > /dev/null || $(USERADD) -g $(pkcs_group) -d $(DESTDIR)$(RUN_PATH)/opencryptoki -c "Opencryptoki pkcsslotd user" $(pkcsslotd_user)
else
	getent group $(pkcs_group) > /dev/null || $(GROUPADD) -r $(pkcs_group)
	getent passwd $(pkcsslotd_user) >/dev/null || $(USERADD) -r -g $(pkcs_group) -d $(RUN_PATH)/opencryptoki -s /sbin/nologin -c "Opencryptoki pkcsslotd user" $(pkcsslotd_user)
endif
	$(MKDIR_P) $(DESTDIR)$(RUN_PATH)/opencryptoki/
	$(CHOWN) $(pkcsslotd_user):$(pkcs_group) $(DESTDIR)$(RUN_PATH)/opencryptoki/
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(RUN_PATH)/opencryptoki/
	$(CHMOD) 0710 $(DESTDIR)$(RUN_PATH)/opencryptoki/
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki
if ENABLE_LIBRARY
	$(MKDIR_P) $(DESTDIR)$(libdir)/opencryptoki/stdll
	$(MKDIR_P) $(DESTDIR)$(libdir)/pkcs11
	cd $(DESTDIR)$(libdir)/opencryptoki && \
		ln -fs libopencryptoki.$(SHLIBEXT) PKCS11_API.$(SHLIBEXT)
	cd $(DESTDIR)$(libdir)/opencryptoki && \
		ln -$(LNFLAG) $(sbindir) methods
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -$(LNFLAG) $(sbindir) methods
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -fs ../opencryptoki/libopencryptoki.$(SHLIBEXT) PKCS11_API.$(SHLIBEXT)
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -fs ../opencryptoki/libopencryptoki.$(SHLIBEXT) libopencryptoki.$(SHLIBEXT)
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -$(LNFLAG) ../opencryptoki/stdll/ stdll
endif
if ENABLE_PKCSHSM_MK_CHANGE
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/HSM_MK_CHANGE
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/HSM_MK_CHANGE
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/HSM_MK_CHANGE
endif
if ENABLE_CCATOK
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_cca.$(SHLIBEXT) PKCS11_CCA.$(SHLIBEXT)
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok/TOK_OBJ
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok/TOK_OBJ
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok
	$(MKDIR_P) $(DESTDIR)$(lockdir)/ccatok
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(lockdir)/ccatok
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/ccatok
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/ccatok.conf || $(INSTALL) -m 644 $(srcdir)/usr/lib/cca_stdll/ccatok.conf $(DESTDIR)$(sysconfdir)/opencryptoki/ccatok.conf || true
endif
if ENABLE_EP11TOK
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_ep11.$(SHLIBEXT) PKCS11_EP11.$(SHLIBEXT)
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok/TOK_OBJ
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok/TOK_OBJ
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok
	$(MKDIR_P) $(DESTDIR)$(lockdir)/ep11tok
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(lockdir)/ep11tok
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/ep11tok
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/ep11tok.conf || $(INSTALL) -m 644 $(srcdir)/usr/lib/ep11_stdll/ep11tok.conf $(DESTDIR)$(sysconfdir)/opencryptoki/ep11tok.conf || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/ep11cpfilter.conf || $(INSTALL) -m 644 $(srcdir)/usr/lib/ep11_stdll/ep11cpfilter.conf $(DESTDIR)$(sysconfdir)/opencryptoki/ep11cpfilter.conf || true
endif
if ENABLE_P11SAK
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/p11sak_defined_attrs.conf || $(INSTALL) -g $(pkcs_group) -m 0640 $(srcdir)/usr/sbin/p11sak/p11sak_defined_attrs.conf $(DESTDIR)$(sysconfdir)/opencryptoki/p11sak_defined_attrs.conf || true
endif
if ENABLE_P11KMIP
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/p11kmip.conf || $(INSTALL) -g $(pkcs_group) -m 0640 $(srcdir)/usr/sbin/p11kmip/p11kmip.conf $(DESTDIR)$(sysconfdir)/opencryptoki/p11kmip.conf || true
endif
if ENABLE_ICATOK
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_ica.$(SHLIBEXT) PKCS11_ICA.$(SHLIBEXT)
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite/TOK_OBJ
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite/TOK_OBJ
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite
	$(MKDIR_P) $(DESTDIR)$(lockdir)/lite
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(lockdir)/lite
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/lite
endif
if ENABLE_SWTOK
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_sw.$(SHLIBEXT) PKCS11_SW.$(SHLIBEXT)
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok/TOK_OBJ
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok/TOK_OBJ
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok
	$(MKDIR_P) $(DESTDIR)$(lockdir)/swtok
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(lockdir)/swtok
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/swtok
endif
if ENABLE_TPMTOK
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_tpm.$(SHLIBEXT) PKCS11_TPM.$(SHLIBEXT)
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	$(MKDIR_P) $(DESTDIR)$(lockdir)/tpm
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(lockdir)/tpm
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/tpm
endif
if ENABLE_ICSFTOK
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -fs libpkcs11_icsf.$(SHLIBEXT) PKCS11_ICSF.$(SHLIBEXT)
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	$(MKDIR_P) $(DESTDIR)$(lockdir)/icsf
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(lockdir)/icsf
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/icsf
endif
if ENABLE_DAEMON
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/opencryptoki.conf || $(INSTALL) -m 644 $(srcdir)/usr/sbin/pkcsslotd/opencryptoki.conf $(DESTDIR)$(sysconfdir)/opencryptoki/opencryptoki.conf || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/strength.conf || $(INSTALL) -m 640 -o root -g $(pkcs_group) -T $(srcdir)/doc/strength-example.conf $(DESTDIR)$(sysconfdir)/opencryptoki/strength.conf || true
endif
if !AIX
	$(MKDIR_P) $(DESTDIR)/etc/ld.so.conf.d
	echo "$(libdir)/opencryptoki" >\
		$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	echo "$(libdir)/opencryptoki/stdll" >>\
		$(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
	@echo "--------------------------------------------------------------"
	@echo "Remember you must run ldconfig before using the above settings"
	@echo "--------------------------------------------------------------"
endif
	$(MKDIR_P) $(DESTDIR)$(lockdir) $(DESTDIR)$(logdir)
	$(CHGRP) $(pkcs_group) $(DESTDIR)$(lockdir) $(DESTDIR)$(logdir)
	$(CHMOD) 0770 $(DESTDIR)$(lockdir) $(DESTDIR)$(logdir)


uninstall-hook:
if ENABLE_LIBRARY
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki && \
		rm -f PKCS11_API.$(SHLIBEXT) && \
		rm -f methods; fi
	if test -d $(DESTDIR)$(libdir)/pkcs11; then \
		cd $(DESTDIR)$(libdir)/pkcs11 && \
		rm -f methods && \
		rm -f PKCS11_API.$(SHLIBEXT) && \
		rm -f libopencryptoki.$(SHLIBEXT) && \
		rm -f stdll; fi
endif
if ENABLE_CCATOK
	if test -d $(DESTDIR)/$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)/$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_CCA.$(SHLIBEXT); fi
	rm -f $(DESTDIR)$(sysconfdir)/opencryptoki/ccatok.conf 
endif
if ENABLE_EP11TOK
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_EP11.$(SHLIBEXT); fi
	rm -f $(DESTDIR)$(sysconfdir)/opencryptoki/ep11tok.conf 
	rm -f $(DESTDIR)$(sysconfdir)/opencryptoki/ep11cpfilter.conf
endif
if ENABLE_ICATOK
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_ICA.$(SHLIBEXT); fi
endif
if ENABLE_SWTOK
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_SW.$(SHLIBEXT); fi
endif
if ENABLE_TPMTOK
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -rf PKCS11_TPM.$(SHLIBEXT); fi
endif
if !AIX
	rm -f $(DESTDIR)/etc/ld.so.conf.d/opencryptoki-$(target_cpu).conf
endif
if ENABLE_ICSFTOK
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -rf PKCS11_ICSF.$(SHLIBEXT); fi
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

if AIX
PKCSLIB = '@libdir@/opencryptoki/libopencryptoki.a(libopencryptoki.so.0)'
else
PKCSLIB ?= @libdir@/opencryptoki/libopencryptoki.so
endif

ci-prepare:
	$(KILLALL) -HUP pkcsslotd || true
	${srcdir}/testcases/ciconfig.sh "$(sysconfdir)/opencryptoki" "$(sysconfdir)/opencryptoki" "$(sysconfdir)/opencryptoki" "${srcdir}/testcases/test_combined_extract.slots"
	@sbindir@/pkcsslotd
	@sbindir@/pkcsstats --reset-all
	for slot in `awk '/^slot (.*)/ { print $$2; }' $(sysconfdir)/opencryptoki/opencryptoki.conf`; do @sbindir@/pkcsconf -c $$slot -t | grep "Flags:" | grep -q TOKEN_INITIALIZED || PKCS11_USER_PIN=$(PKCS11_USER_PIN) PKCS11_SO_PIN=$(PKCS11_SO_PIN) PKCSLIB=$(PKCSLIB) ${srcdir}/testcases/init_token.sh $$slot || exit; done
#	cd ${srcdir}/testcases && PKCS11_USER_PIN=$(PKCS11_USER_PIN) PKCS11_VHSM_PIN=$(PKCS11_VHSM_PIN) PKCSLIB=$(PKCSLIB) ./init_vhsm.exp 42
#	echo "VHSM_MODE" >> "$(sysconfdir)/opencryptoki/ep11tok42.conf"

installcheck-local: all check
	$(KILLALL) -HUP pkcsslotd || true
	@sbindir@/pkcsslotd
	if test ! -z ${PKCS11_TEST_USER}; then				\
		chmod 777 ${srcdir}/testcases &&			\
		cd ${srcdir}/testcases &&                               \
		su ${PKCS11_TEST_USER} -s /bin/bash -c "PKCS11_SO_PIN=$(PKCS11_SO_PIN) PKCS11_USER_PIN=$(PKCS11_USER_PIN) PKCSLIB=$(PKCSLIB) /bin/bash ./ock_tests.sh || true"; \
	else								\
		cd ${srcdir}/testcases && 				\
		PKCS11_SO_PIN=$(PKCS11_SO_PIN) PKCS11_USER_PIN=$(PKCS11_USER_PIN) PKCSLIB=$(PKCSLIB) ./ock_tests.sh || true; \
	fi
	$(KILLALL) -HUP pkcsslotd

ci-installcheck: ci-prepare installcheck
	$(KILLALL) -HUP pkcsslotd || true
	@sbindir@/pkcsslotd
	cd ${srcdir}/testcases						\
	&& export PKCSLIB=$(PKCSLIB)	\
	&& export PKCS11_USER_PIN=$(PKCS11_USER_PIN)			\
	&& export PKCS11_SO_PIN=$(PKCS11_SO_PIN)			\
	&& SBINDIR=@sbindir@ ./misc_tests/p11sak_test.sh   | tee log-p11sak.txt		\
	&& SBINDIR=@sbindir@ ./misc_tests/pkcsconf_test.sh | tee log-pkcsconf.txt
	if [[ -n "${KMIP_IP}" ]] && [[ -n "${KMIP_REST_USER}" ]] && [[ -n "${KMIP_REST_PASSWORD}" ]]; then \
		cd ${srcdir}/testcases							\
		&& export PKCSLIB=$(PKCSLIB)						\
		&& export PKCS11_USER_PIN=$(PKCS11_USER_PIN)				\
		&& export PKCS11_SO_PIN=$(PKCS11_SO_PIN)				\
		&& SBINDIR=@sbindir@ ./misc_tests/p11kmip_test.sh | tee log-p11kmip.txt;\
	fi
	@sbindir@/pkcsstats --all
	$(KILLALL) -HUP pkcsslotd
	rm ${srcdir}/testcases/test_combined_extract.slots -f
	@echo "done"

ci-cleanup:
	@sbindir@/pkcsstats --delete-all || true
	$(KILLALL) -HUP pkcsslotd || true
#	@sbindir@/pkcsslotd
#	cd ${srcdir}/testcases && PKCS11_USER_PIN=$(PKCS11_USER_PIN) PKCSLIB=$(PKCLSIB) ./cleanup_vhsm.exp 42
#	$(KILLALL) -HUP pkcsslotd
	rm ${srcdir}/testcases/test_combined_extract.slots -f

ci-uninstall: uninstall
	rm -f $(sysconfdir)/opencryptoki/ep11tok*.conf
	rm -rf $(localstatedir)/lib/opencryptoki/*
	rm -rf $(lockdir)/*
	rm -rf $(logdir)/*

.PHONY: ci-prepare ci-installcheck ci-uninstall
endif

