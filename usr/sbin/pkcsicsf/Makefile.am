sbin_PROGRAMS=pkcsicsf

pkcsicsf_LDFLAGS = -lldap -lssl -llber -lcrypto

# Not all versions of automake observe sbinname_CFLAGS
pkcsicsf_CFLAGS = -D_THREAD_SAFE -DDEV -DAPI -DSTDLL_NAME=\"icsf\"

# Not all versions of automake observe sbinname_CFLAGS
AM_CFLAGS = -D_THREAD_SAFE -DDEV -DAPI -DSTDLL_NAME=\"icsf\"

pkcsicsf_SOURCES = ../../lib/pkcs11/icsf_stdll/icsf.c	\
		   ../../lib/pkcs11/icsf_stdll/pbkdf.c	\
		   ../../lib/pkcs11/common/trace.c	\
		   pkcsicsf.c

INCLUDES = -I../../include/pkcs11 -I. -I../../lib/pkcs11/common -I../../lib/pkcs11/icsf_stdll
