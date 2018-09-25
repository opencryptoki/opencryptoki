sbin_PROGRAMS=pkcsconf

bindir=${top_srcdir}/usr/sbin
pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

pkcsconf_LDFLAGS = -lpthread -ldl -lcrypto

pkcsconf_CFLAGS = -D_THREAD_SAFE -DDEBUG -DDEV -DAPI	\
		  -I${incdir}/pkcs11			\
		  -I${bindir}/pkcsconf			\
		  -I${pkcsdir}/common

pkcsconf_SOURCES = ${pkcsdir}/common/p11util.c	\
		   ${bindir}/pkcsconf/pkcsconf.c

noinst_HEADERS = ${bindir}/pkcsconf/pkcsconf_msg.h
