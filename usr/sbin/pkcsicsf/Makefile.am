sbin_PROGRAMS=pkcsicsf

pkcsicsf_LDFLAGS = -lldap -lssl -llber -lcrypto

pkcsicsf_CFLAGS = -D_THREAD_SAFE -DDEV -DAPI -DSTDLL_NAME=\"icsf\"	\
		  -I../../include/pkcs11 -I. -I../../lib/pkcs11/common	\
		  -I../../lib/pkcs11/icsf_stdll

pkcsicsf_SOURCES = ../../lib/pkcs11/icsf_stdll/icsf.c	\
		   ../../lib/pkcs11/icsf_stdll/pbkdf.c	\
		   ../../lib/pkcs11/common/trace.c	\
		   pkcsicsf.c
