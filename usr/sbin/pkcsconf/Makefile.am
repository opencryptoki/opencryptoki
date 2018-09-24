sbin_PROGRAMS=pkcsconf

pkcsconf_LDFLAGS = -lpthread -ldl -lcrypto

pkcsconf_CFLAGS = -D_THREAD_SAFE -DDEBUG -DDEV -DAPI	\
		  -I../../include/pkcs11 -I.		\
		  -I../../lib/pkcs11/common

pkcsconf_SOURCES = ../../lib/pkcs11/common/p11util.c	\
		   pkcsconf.c
