testcases_inc = -I${srcdir}/usr/include -I${srcdir}/usr/lib/common	\
	-I${srcdir}/testcases/include -I${srcdir}/testcases/common	\
	-I${srcdir}/testcases/login -I${srcdir}/testcases/crypto	\
	-I${srcdir}/testcases/misc_tests -I${srcdir}/testcases/pkcs11	\
	-I${srcdir}/usr/lib/api -I${top_builddir}/usr/lib/api

include testcases/include/include.mk
include testcases/common/common.mk
include testcases/crypto/crypto.mk
include testcases/login/login.mk
include testcases/misc_tests/misc_tests.mk
include testcases/pkcs11/pkcs11.mk
include testcases/build/build.mk
include testcases/unit/unit.mk
include testcases/policy/policy.mk

noinst_SCRIPTS += testcases/ock_tests.sh testcases/init_token.sh testcases/init_vhsm.exp testcases/cleanup_vhsm.exp
CLEANFILES += testcases/ock_tests.sh testcases/init_token.sh testcases/init_vhsm.exp testcases/cleanup_vhsm.exp
EXTRA_DIST += testcases/ock_tests.sh.in testcases/init_token.sh.in testcases/init_vhsm.exp.in testcases/cleanup_vhsm.exp.in

testcases/ock_tests.sh: testcases/ock_tests.sh.in
	$(AM_V_GEN)@SED@	-e s!\@sysconfdir\@!"@sysconfdir@"!g	\
		-e s!\@sbindir\@!"@sbindir@"!g				\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t &&		\
	@CHMOD@ a+x $@-t &&						\
	$(am__mv) $@-t $@

testcases/init_token.sh: testcases/init_token.sh.in
	$(AM_V_GEN)@SED@ -e s!\@localstatedir\@!"@localstatedir@"!g	\
		-e s!\@sbindir\@!"@sbindir@"!g				\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t &&		\
	@CHMOD@ a+x $@-t &&						\
	$(am__mv) $@-t $@

testcases/init_vhsm.exp: testcases/init_vhsm.exp.in
	$(AM_V_GEN)@SED@ -e s!\@localstatedir\@!"@localstatedir@"!g	\
		-e s!\@sbindir\@!"@sbindir@"!g				\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t &&		\
	@CHMOD@ a+x $@-t &&						\
	$(am__mv) $@-t $@

testcases/cleanup_vhsm.exp: testcases/cleanup_vhsm.exp.in
	$(AM_V_GEN)@SED@ -e s!\@localstatedir\@!"@localstatedir@"!g	\
		-e s!\@sbindir\@!"@sbindir@"!g				\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t &&		\
	@CHMOD@ a+x $@-t &&						\
	$(am__mv) $@-t $@
