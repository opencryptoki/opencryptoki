sbin_PROGRAMS=pkcsslotd

pkcsslotd_LDFLAGS = -lpthread

# Not all versions of automake observe sbinname_CFLAGS
pkcsslotd_CFLAGS =  -DPROGRAM_NAME=\"$(@)\" -DNOODM -DNODAE \
		   -I../. -I../../include/pkcs11 -I../../include/pkcs11/stdll

# Not all versions of automake observe sbinname_CFLAGS
AM_CFLAGS = -DPROGRAM_NAME=\"$(@)\" -DNOODM -DNODAE \
	    -I../. -I../../include/pkcs11 -I../../include/pkcs11/stdll

pkcsslotd_SOURCES = slotmgr.c shmem.c signal.c mutex.c err.c log.c daemon.c \
		    no_odm.c garbage_linux.c
