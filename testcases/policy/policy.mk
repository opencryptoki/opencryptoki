noinst_PROGRAMS += testcases/policy/policytest

testcases_policy_policytest_CFLAGS = ${testcases_inc}
testcases_policy_policytest_LDFLAGS = -ldl
testcases_policy_policytest_SOURCES = testcases/policy/policytest.c

noinst_SCRIPTS += testcases/policy/policytest.sh
CLEANFILES += testcases/policy/policytest.sh
EXTRA_DIST += testcases/policy/policytest.sh

testcases/policy/policytest.sh: testcases/policy/policytest.sh.in
	$(AM_V_GEN)@SED@	-e s!\@sysconfdir\@!"@sysconfdir@"!g	\
		-e s!\@sbindir\@!"@sbindir@"!g				\
		-e s!\@libdir\@!"@libdir@"!g 				\
		-e s!\@pkcsslotd_user\@!$(pkcsslotd_user)!g		\
		-e s!\@pkcs_group\@!$(pkcs_group)!g< $< > $@-t &&	\
	@CHMOD@ a+x $@-t &&						\
	$(am__mv) $@-t $@
