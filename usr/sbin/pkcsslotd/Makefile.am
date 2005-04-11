sbin_PROGRAMS=pkcsslotd

pkcsslotd_LDFLAGS = -lpthread

pkcsslotd_CFLAGS = -DSPINXPL -DPROGRAM_NAME=\"$(@)\" -DNOODM -DNODAE
CFLAGS = @CFLAGS@ -DSPINXPL -DPROGRAM_NAME=\"$(@)\" -DNOODM -DNODAE

pkcsslotd_SOURCES = slotmgr.c shmem.c signal.c mutex.c err.c log.c daemon.c no_odm.c garbage_linux.c

INCLUDES = -I../. -I../../include/pkcs11 -I../../include/pkcs11/stdll

#install-data-local:
#	mkdir -p $(INSROOT)/usr/sbin; \
#	if [ $(shell uname -m) != s390x ] ;then cp pkcsslotd \
#	$(INSROOT)/usr/sbin/pkcsslotd; fi; \
#	rm -f /tmp/pkcsslotd;
