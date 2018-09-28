testcases_inc =								\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/common		\
	-I${srcdir}/testcases/include -I${srcdir}/testcases/common	\
	-I${srcdir}/testcases/login -I${srcdir}/testcases/crypto	\
	-I${srcdir}/testcases/misc_tests -I${srcdir}/testcases/pkcs11

include %D%/include/include.mk
include %D%/common/common.mk
include %D%/crypto/crypto.mk
include %D%/login/login.mk
include %D%/misc_tests/misc_tests.mk
include %D%/pkcs11/pkcs11.mk

noinst_SCRIPTS += %D%/ock_tests.sh %D%/init_token.sh
CLEANFILES += %D%/ock_tests.sh %D%/init_token.sh
EXTRA_DIST += %D%/ock_tests.sh.in %D%/init_token.sh.in

%D%/ock_tests.sh: %D%/ock_tests.sh.in
	@SED@	-e s!\@sysconfdir\@!"@sysconfdir@"!g			\
		-e s!\@sbindir\@!"@sbindir@"!g				\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@

%D%/init_token.sh: %D%/init_token.sh.in
	@SED@	-e s!\@localstatedir\@!"@localstatedir@"!g		\
		-e s!\@sbindir\@!"@sbindir@"!g				\
		-e s!\@libdir\@!"@libdir@"!g < $< > $@-t
	@CHMOD@ a+x $@-t
	mv $@-t $@
