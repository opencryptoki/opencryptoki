sbin_PROGRAMS += %D%/pkcsep11_migrate
noinst_HEADERS += %D%/ep11adm.h

%C%_pkcsep11_migrate_LDFLAGS = -lc -ldl -lpthread

%C%_pkcsep11_migrate_CFLAGS  =						\
	-DLINUX -DPROGRAM_NAME=\"$(@)\"					\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/ep11_stdll/		\
	-I${srcdir}/usr/lib/common -I${srcdir}/%D%

%C%_pkcsep11_migrate_SOURCES =						\
	usr/lib/common/p11util.c %D%/pkcsep11_migrate.c
