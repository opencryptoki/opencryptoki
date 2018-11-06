testcases_inc =								\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/common		\
	-I${srcdir}/testcases/include -I${srcdir}/testcases/common	\
	-I${srcdir}/testcases/login -I${srcdir}/testcases/crypto	\
	-I${srcdir}/testcases/misc_tests -I${srcdir}/testcases/pkcs11

include testcases/include/include.mk
include testcases/common/common.mk
include testcases/crypto/crypto.mk
include testcases/login/login.mk
include testcases/misc_tests/misc_tests.mk
include testcases/pkcs11/pkcs11.mk

noinst_SCRIPTS += testcases/ock_tests.sh testcases/init_token.sh
CLEANFILES += testcases/ock_tests.sh testcases/init_token.sh
EXTRA_DIST += testcases/ock_tests.sh.in testcases/init_token.sh.in

testcases/ock_tests.sh: testcases/ock_tests.sh.in
	@SED@	-e s!\@sysconfdir\@!"@sysconfdir@"!g			\
		-e s!\@sbindir\@!"@sbindir@"!g				\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@

testcases/init_token.sh: testcases/init_token.sh.in
	@SED@	-e s!\@localstatedir\@!"@localstatedir@"!g		\
		-e s!\@sbindir\@!"@sbindir@"!g				\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@
