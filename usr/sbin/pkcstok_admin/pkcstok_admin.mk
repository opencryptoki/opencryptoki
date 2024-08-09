sbin_PROGRAMS += usr/sbin/pkcstok_admin/pkcstok_admin

usr_sbin_pkcstok_admin_pkcstok_admin_LDFLAGS = -lrt

usr_sbin_pkcstok_admin_pkcstok_admin_CFLAGS  =		\
	-DSTDLL_NAME=\"pkcstok_admin\"			\
	-I${srcdir}/usr/include 			\
	-I${srcdir}/usr/lib/common			\
	-I${srcdir}/usr/sbin/pkcstok_admin

usr_sbin_pkcstok_admin_pkcstok_admin_SOURCES =		\
	usr/sbin/pkcstok_admin/pkcstok_admin.c

if AIX
usr_sbin_pkcstok_admin_pkcstok_admin_SOURCES += 	\
	usr/lib/common/aix/err.c \
	usr/lib/common/aix/getopt_long.c
endif
