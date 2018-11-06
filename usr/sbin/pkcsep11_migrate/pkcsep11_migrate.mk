sbin_PROGRAMS += usr/sbin/pkcsep11_migrate/pkcsep11_migrate
noinst_HEADERS += usr/sbin/pkcsep11_migrate/ep11adm.h

usr_sbin_pkcsep11_migrate_pkcsep11_migrate_LDFLAGS = -lc -ldl -lpthread

usr_sbin_pkcsep11_migrate_pkcsep11_migrate_CFLAGS  =			\
	-DLINUX -DPROGRAM_NAME=\"$(@)\"					\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/ep11_stdll/		\
	-I${srcdir}/usr/lib/common -I${srcdir}/usr/sbin/pkcsep11_migrate

usr_sbin_pkcsep11_migrate_pkcsep11_migrate_SOURCES =			\
	usr/lib/common/p11util.c					\
	usr/sbin/pkcsep11_migrate/pkcsep11_migrate.c
