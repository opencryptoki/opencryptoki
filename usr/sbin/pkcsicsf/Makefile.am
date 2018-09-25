sbin_PROGRAMS=pkcsicsf

bindir=${top_srcdir}/usr/sbin
pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

pkcsicsf_LDFLAGS = -lldap -lssl -llber -lcrypto

pkcsicsf_CFLAGS = -D_THREAD_SAFE -DDEV -DAPI -DSTDLL_NAME=\"icsf\"	\
		  -I${bindir}/pkcsicsf		\
		  -I${incdir}/pkcs11		\
		  -I${pkcsdir}/icsf_stdll	\
		  -I${pkcsdir}/common

pkcsicsf_SOURCES = ${pkcsdir}/icsf_stdll/icsf.c	\
		   ${pkcsdir}/icsf_stdll/pbkdf.c\
		   ${pkcsdir}/common/trace.c	\
		   ${bindir}/pkcsicsf/pkcsicsf.c
