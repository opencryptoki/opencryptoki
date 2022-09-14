sbin_PROGRAMS += usr/sbin/pkcsep11_migrate/pkcsep11_migrate

usr_sbin_pkcsep11_migrate_pkcsep11_migrate_LDFLAGS = -lc -ldl -lpthread -lcrypto

usr_sbin_pkcsep11_migrate_pkcsep11_migrate_CFLAGS = -DLINUX		\
	-DPROGRAM_NAME=\"$(@)\" -I${srcdir}/usr/include			\
	-I${srcdir}/usr/lib/ep11_stdll/ -I${srcdir}/usr/lib/common	\
	-I${srcdir}/usr/sbin/pkcsep11_migrate -I${srcdir}/usr/lib/api	\
	-I${top_builddir}/usr/lib/api

usr_sbin_pkcsep11_migrate_pkcsep11_migrate_SOURCES =			\
	usr/lib/common/p11util.c usr/lib/common/pin_prompt.c		\
	usr/sbin/pkcsep11_migrate/pkcsep11_migrate.c

nodist_usr_sbin_pkcsep11_migrate_pkcsep11_migrate_SOURCES =		\
	usr/lib/api/mechtable.c
