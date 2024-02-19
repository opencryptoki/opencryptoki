check_PROGRAMS = testcases/unit/policytest testcases/unit/hashmaptest	\
	testcases/unit/mechtabletest testcases/unit/configdump		\
	testcases/unit/buffertest testcases/unit/uritest		\
	testcases/unit/pintest

TESTS = testcases/unit/policytest testcases/unit/hashmaptest		\
	testcases/unit/mechtabletest testcases/unit/configdump		\
	testcases/unit/buffertest testcases/unit/uritest		\
	testcases/unit/pintest.sh

EXTRA_DIST += testcases/unit/pintest.sh
noinst_HEADERS += testcases/unit/unittest.h

testcases_unit_policytest_CFLAGS=-I${top_srcdir}/usr/lib/common		\
	-I${top_srcdir}/usr/lib/api -I${top_srcdir}/usr/include		\
	-DSTDLL_NAME=\"policytest\" -I${top_srcdir}/usr/lib/config	\
	-I${top_builddir}/usr/lib/config -I${top_builddir}/usr/lib/api

if AIX
testcases_unit_policytest_LDFLAGS=-lpthread
endif

testcases_unit_policytest_SOURCES=testcases/unit/policytest.c	\
	usr/lib/api/policy.c usr/lib/api/hashmap.c		\
	usr/lib/common/ec_supported.c usr/lib/common/trace.c	\
	usr/lib/common/utility_common.c				\
	usr/lib/config/configuration.c				\
	usr/lib/common/ec_curve_translation.c			\
	usr/lib/common/kdf_translation.c			\
	usr/lib/common/mgf_translation.c			\
	usr/lib/api/supportedstrengths.c			\
	usr/lib/config/cfgparse.y usr/lib/config/cfglex.l	\
	usr/lib/common/pqc_supported.c

nodist_testcases_unit_policytest_SOURCES=usr/lib/api/mechtable.c

testcases_unit_hashmaptest_CFLAGS=-I${top_srcdir}/usr/lib/api		\
	-I${top_srcdir}/usr/include -I${srcdir}/usr/lib/common

testcases_unit_hashmaptest_SOURCES = testcases/unit/hashmaptest.c	\
	usr/lib/api/hashmap.c

if AIX
testcases_unit_hashmaptest_SOURCES += usr/lib/common/aix/getopt_long.c
endif

testcases_unit_mechtabletest_CFLAGS=-I${top_srcdir}/usr/lib/api		\
	-I${top_srcdir}/usr/include -I${top_builddir}/usr/lib/api

testcases_unit_mechtabletest_SOURCES=testcases/unit/mechtabletest.c

nodist_testcases_unit_mechtabletest_SOURCES=usr/lib/api/mechtable.c	

testcases_unit_configdump_SOURCES = testcases/unit/configdump.c	\
	usr/lib/config/cfglex.l usr/lib/config/cfgparse.y	\
	usr/lib/config/configuration.c

if AIX
testcases_unit_configdump_SOURCES += usr/lib/common/aix/err.c
endif

testcases_unit_configdump_CFLAGS=-I${top_srcdir}/usr/lib/config	\
	-I${top_builddir}/usr/lib/config -I${top_srcdir}/usr/include \
	-I${srcdir}/usr/lib/common

testcases_unit_buffertest_SOURCES=testcases/unit/buffertest.c	\
	usr/lib/common/buffer.c

testcases_unit_buffertest_CFLAGS=-I${top_srcdir}/usr/lib/common \
	-I$(top_srcdir)/usr/include

testcases_unit_uritest_SOURCES=testcases/unit/uritest.c		\
	usr/lib/common/uri.c usr/lib/common/buffer.c		\
	usr/lib/common/p11util.c

testcases_unit_uritest_CFLAGS=-I${top_srcdir}/usr/lib/common	\
	-I${top_srcdir}/usr/include -I${top_builddir}/usr/lib/api \
	-I${srcdir}/usr/lib/common -I${srcdir}/usr/include 	\
	-I${srcdir}/usr/lib/api

testcases_unit_pintest_SOURCES=testcases/unit/pintest.c		\
	usr/lib/common/buffer.c usr/lib/common/pin_prompt.c

testcases_unit_pintest_CFLAGS=-I${top_srcdir}/usr/lib/common \
	-I${top_srcdir}/usr/include
testcases_unit_pintest_LDFLAGS=-lcrypto
