sbin_PROGRAMS=pkcsep11_migrate

bindir=${top_srcdir}/usr/sbin
pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

pkcsep11_migrate_LDFLAGS = -lc -ldl -lpthread

pkcsep11_migrate_CFLAGS  = -I${incdir}/pkcs11/ 		\
			   -I${pkcsdir}/ep11_stdll/ 	\
			   -I${pkcsdir}/common		\
			   -I${bindir}/pkcsep11_migrate	\
			   -DLINUX -DPROGRAM_NAME=\"$(@)\"

pkcsep11_migrate_SOURCES = ${pkcsdir}/common/p11util.c	\
			   ${bindir}/pkcsep11_migrate/pkcsep11_migrate.c 

noinst_HEADERS = ${bindir}/pkcsep11_migrate/ep11adm.h
