check_PROGRAMS = testcases/unit/policytest testcases/unit/hashmaptest	\
	testcases/unit/mechtabletest testcases/unit/configdump

TESTS = testcases/unit/policytest testcases/unit/hashmaptest		\
	testcases/unit/mechtabletest testcases/unit/configdump

testcases_unit_policytest_CFLAGS=-I${top_srcdir}/usr/lib/common		\
	-I${top_srcdir}/usr/lib/api -I${top_srcdir}/usr/include		\
	-DSTDLL_NAME=\"policytest\" -I${top_srcdir}/usr/lib/config	\
	-I${top_builddir}/usr/lib/config -I${top_builddir}/usr/lib/api

testcases_unit_policytest_SOURCES=testcases/unit/policytest.c	\
	usr/lib/api/policy.c usr/lib/api/hashmap.c		\
	usr/lib/common/ec_supported.c usr/lib/common/trace.c	\
	usr/lib/common/utility_common.c				\
	usr/lib/config/configuration.c				\
	usr/lib/common/ec_curve_translation.c			\
	usr/lib/common/kdf_translation.c			\
	usr/lib/common/mgf_translation.c			\
	usr/lib/api/supportedstrengths.c			\
	usr/lib/config/cfgparse.y usr/lib/config/cfglex.l

nodist_testcases_unit_policytest_SOURCES=usr/lib/api/mechtable.c

testcases_unit_hashmaptest_CFLAGS=-I${top_srcdir}/usr/lib/api		\
	-I${top_srcdir}/usr/include

testcases_unit_hashmaptest_SOURCES = testcases/unit/hashmaptest.c	\
	usr/lib/api/hashmap.c

testcases_unit_mechtabletest_CFLAGS=-I${top_srcdir}/usr/lib/api		\
	-I${top_srcdir}/usr/include -I${top_builddir}/usr/lib/api	\
	-I${top_srcdir}/usr/include

testcases_unit_mechtabletest_SOURCES=testcases/unit/mechtabletest.c

nodist_testcases_unit_mechtabletest_SOURCES=usr/lib/api/mechtable.c	

testcases_unit_configdump_SOURCES = testcases/unit/configdump.c	\
	usr/lib/config/cfglex.l usr/lib/config/cfgparse.y	\
	usr/lib/config/configuration.c

testcases_unit_configdump_CFLAGS=-I${top_srcdir}/usr/lib/config	\
	-I${top_builddir}/usr/lib/config
