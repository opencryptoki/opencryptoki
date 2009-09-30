noinst_SCRIPTS = ock_tests.sh

EXTRA_DIST = ock_tests.sh.in

CLEANFILES = ock_tests.sh

ock_tests.sh: ock_tests.sh.in
	@SED@	-e s!\@localstatedir\@!"@localstatedir@"!g	\
		-e s!\@sbindir\@!"@sbindir@"!g			\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@

SUBDIRS=common driver init_tok mkobj oc-digest rsa_keygen rsa_test speed test_crypto threadmkobj tok_obj v2.11 login
