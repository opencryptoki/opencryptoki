sbin_PROGRAMS=pkcscca

bindir=${top_srcdir}/usr/sbin
pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

pkcscca_LDFLAGS = -lcrypto -ldl

pkcscca_CFLAGS  = -DSTDLL_NAME=\"pkcscca\"	\
		  -I${bindir}/pkcscca		\
		  -I${incdir}/pkcs11		\
		  -I${pkcsdir}/common

pkcscca_SOURCES = ${pkcsdir}/common/p11util.c	\
		  ${pkcsdir}/common/sw_crypt.c	\
		  ${pkcsdir}/common/trace.c	\
		  ${bindir}/pkcscca/pkcscca.c

noinst_HEADERS = ${bindir}/pkcscca/pkcscca.h
