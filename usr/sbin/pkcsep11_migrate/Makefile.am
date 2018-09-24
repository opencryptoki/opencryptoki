sbin_PROGRAMS=pkcsep11_migrate

pkcsep11_migrate_LDFLAGS = -lc -ldl -lpthread

pkcsep11_migrate_CFLAGS  = -I../../include/pkcs11/ 		\
			   -I../../lib/pkcs11/ep11_stdll/ -I.	\
			   -I../../lib/pkcs11/common		\
			   -DLINUX -DPROGRAM_NAME=\"$(@)\"

pkcsep11_migrate_SOURCES = ../../lib/pkcs11/common/p11util.c	\
			   pkcsep11_migrate.c 
