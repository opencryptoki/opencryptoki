SUBDIRS=common crypto pkcs11 login misc_tests

noinst_SCRIPTS = ock_tests.sh init_token.sh

EXTRA_DIST = ock_tests.sh.in init_token.sh.in

CLEANFILES = ock_tests.sh init_token.sh

ock_tests.sh: ock_tests.sh.in
	@SED@	-e s!\@localstatedir\@!"@localstatedir@"!g	\
		-e s!\@sbindir\@!"@sbindir@"!g			\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@

init_token.sh: init_token.sh.in
	@SED@	-e s!\@localstatedir\@!"@localstatedir@"!g	\
		-e s!\@sbindir\@!"@sbindir@"!g			\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@


installcheck-local: all
	killall -HUP pkcsslotd || true
	@sbindir@/pkcs11_startup
	@sbindir@/pkcsslotd
	if test ! -z ${PKCS11_TEST_USER}; then \
		su ${PKCS11_TEST_USER} -c "PKCS11_SO_PIN=76543210 PKCS11_USER_PIN=01234567 PKCSLIB=@libdir@/opencryptoki/libopencryptoki.so sh ./ock_tests.sh"; \
	else \
		PKCS11_SO_PIN=76543210 PKCS11_USER_PIN=01234567 PKCSLIB=@libdir@/opencryptoki/libopencryptoki.so sh ./ock_tests.sh; \
	fi
	killall -HUP pkcsslotd
