sbin_PROGRAMS += usr/sbin/pkcstok_migrate/pkcstok_migrate

usr_sbin_pkcstok_migrate_pkcstok_migrate_LDFLAGS = -lcrypto -ldl -lrt

if AIX
usr_sbin_pkcstok_migrate_pkcstok_migrate_LDFLAGS += -lpthread
endif

usr_sbin_pkcstok_migrate_pkcstok_migrate_CFLAGS  =		\
	-DSTDLL_NAME=\"pkcstok_migrate\"			\
	-I${srcdir}/usr/include 				\
	-I${srcdir}/usr/lib/common				\
	-I${srcdir}/usr/sbin/pkcstok_migrate			\
	-I${srcdir}/usr/lib/api					\
	-I${top_builddir}/usr/lib/api				\
	-I${srcdir}/usr/lib/config				\
	-I${top_builddir}/usr/lib/config

usr_sbin_pkcstok_migrate_pkcstok_migrate_SOURCES =		\
	usr/lib/common/p11util.c 				\
	usr/lib/common/sw_crypt.c				\
	usr/lib/common/trace.c 					\
	usr/lib/common/pkcs_utils.c				\
	usr/lib/common/pin_prompt.c				\
	usr/sbin/pkcstok_migrate/pkcstok_migrate.c		\
	usr/lib/config/configuration.c				\
	usr/lib/config/cfgparse.y 				\
	usr/lib/config/cfglex.l

if AIX
usr_sbin_pkcstok_migrate_pkcstok_migrate_SOURCES += usr/lib/common/aix/err.c \
	usr/lib/common/aix/getopt_long.c
endif

nodist_usr_sbin_pkcstok_migrate_pkcstok_migrate_SOURCES = \
	usr/lib/api/mechtable.c
usr/sbin/pkcstok_migrate/pkcstok_migrate.$(OBJEXT): usr/lib/config/cfgparse.h
