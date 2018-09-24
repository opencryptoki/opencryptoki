sbin_PROGRAMS=pkcscca

pkcscca_LDFLAGS = -lcrypto -ldl

pkcscca_CFLAGS  = -DSTDLL_NAME=\"pkcscca\" -I.	\
		  -I../../include/pkcs11	\
		  -I../../lib/pkcs11/common

pkcscca_SOURCES = ../../lib/pkcs11/common/p11util.c	\
		  ../../lib/pkcs11/common/sw_crypt.c	\
		  ../../lib/pkcs11/common/trace.c	\
		  pkcscca.c
