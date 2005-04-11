sbin_PROGRAMS=pkcsconf

pkcsconf_LDFLAGS = -lpthread -ldl

pkcsconf_CFLAGS = -DSPINXPL -D_THREAD_SAFE -DDEBUG -DDEV -DAPI

CFLAGS = @CFLAGS@ -DSPINXPL -D_THREAD_SAFE -DDEBUG -DDEV -DAPI

pkcsconf_SOURCES = pkcsconf.c

INCLUDES = -I../../include/pkcs11 -I.

#install-data-local:
#	mkdir -p $(METHOD_PATH); \
#	mkdir -p $(INSROOT)/usr/lib/pkcs11/methods; \
#	if [ $(shell uname -m) != s390x -a $(shell uname -m) != ppc64 ] ; then \
#		cp pkcsconf $(METHOD_PATH); \
#		ln -s $(METHOD_PATH)/pkcsconf $(INSROOT)/usr/lib/pkcs11/methods; \
#	fi; \
#	rm -f /tmp/pkcsconf;
