sbin_PROGRAMS += usr/sbin/pkcsstats/pkcsstats

usr_sbin_pkcsstats_pkcsstats_LDFLAGS = -lcrypto -ldl -lrt

usr_sbin_pkcsstats_pkcsstats_CFLAGS  =			\
	-DOCK_TOOL					\
	-DSTDLL_NAME=\"pkcsstats\"			\
	-I${srcdir}/usr/include 			\
	-I${srcdir}/usr/lib/common 			\
	-I${srcdir}/usr/lib/api				\
	-I${top_builddir}/usr/lib/api

usr_sbin_pkcsstats_pkcsstats_SOURCES =			\
	usr/sbin/pkcsstats/pkcsstats.c			\
	usr/lib/common/p11util.c			\
	usr/lib/api/supportedstrengths.c		\
	usr/lib/api/mechtable.c
