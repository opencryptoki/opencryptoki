nobase_lib_LTLIBRARIES += opencryptoki/libopencryptoki.la

noinst_HEADERS += usr/lib/api/apiproto.h usr/lib/api/policy.h		\
	usr/lib/api/statistics.h usr/lib/api/hashmap.h			\
	usr/lib/api/mechtable.h usr/lib/api/supportedstrengths.h

SO_CURRENT=0
SO_REVISION=0
SO_AGE=0

opencryptoki_libopencryptoki_la_CFLAGS =				\
	-DAPI -DDEV -D_THREAD_SAFE -fPIC -I${srcdir}/usr/include	\
	-I${srcdir}/usr/lib/common -I${srcdir}/usr/lib/api		\
	-I${srcdir}/usr/lib/config -I${top_builddir}/usr/lib/config	\
	-DSTDLL_NAME=\"api\" -DHASHMAP_JENKINS_MIX  			\
	-I${top_builddir}/usr/lib/api

if AIX
opencryptoki_libopencryptoki_la_LDFLAGS =				\
	-shared -lc -ldl -lpthread -lcrypto -lrt -Wl,-binitfini:api_init:api_fini \
	-version-info $(SO_CURRENT):$(SO_REVISION):$(SO_AGE) \
	-Wl,-bnoautoexp -export-symbols ${srcdir}/opencryptoki.map.sym
else
opencryptoki_libopencryptoki_la_LDFLAGS =				\
	-shared	-Wl,-z,defs,-Bsymbolic -lc -ldl -lpthread -lcrypto -lrt	\
	-version-info $(SO_CURRENT):$(SO_REVISION):$(SO_AGE)		\
	-Wl,--version-script=${srcdir}/opencryptoki.map
endif

opencryptoki_libopencryptoki_la_SOURCES = usr/lib/api/api_interface.c	\
	usr/lib/api/shrd_mem.c usr/lib/api/socket_client.c		\
	usr/lib/api/apiutil.c usr/lib/common/trace.c			\
	usr/lib/api/policy.c usr/lib/api/hashmap.c			\
	usr/lib/api/statistics.c					\
	usr/lib/common/utility_common.c usr/lib/common/ec_supported.c	\
	usr/lib/config/configuration.c					\
	usr/lib/common/ec_curve_translation.c				\
	usr/lib/common/kdf_translation.c				\
	usr/lib/common/mgf_translation.c				\
	usr/lib/api/supportedstrengths.c				\
	usr/lib/common/pqc_supported.c					\
	usr/lib/config/cfgparse.y usr/lib/config/cfglex.l		\
	usr/lib/common/btree.c

if AIX
opencryptoki_libopencryptoki_la_SOURCES += usr/lib/common/aix/short_name.c
endif

nodist_opencryptoki_libopencryptoki_la_SOURCES =			\
	usr/lib/api/mechtable.c

usr/lib/api/mechtable.c usr/lib/api/mechtable-gen.h: tools/tableidxgen
	$(AM_V_GEN)$(MKDIR_P) usr/lib/api && ${abs_builddir}/tools/tableidxgen -c usr/lib/api/mechtable.c -d usr/lib/api/mechtable-gen.h -l usr/lib/api/mechtable.log

BUILT_SOURCES += usr/lib/api/mechtable-gen.h
EXTRA_DIST += usr/lib/api/mechtable.inc

CLEANFILES += usr/lib/api/shrd_mem.c usr/lib/api/mechtable.c $(BUILT_SOURCES) \
	usr/lib/api/mechtable.log
