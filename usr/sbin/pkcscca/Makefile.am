sbin_PROGRAMS=pkcscca

pkcscca_CFLAGS  = -DSTDLL_NAME=\"pkcscca\"
pkcscca_LDFLAGS = -lcrypto -ldl

# Not all versions of automake observe sbinname_CFLAGS
AM_CFLAGS = -DSTDLL_NAME=\"pkcscca\"

pkcscca_SOURCES = ../../lib/pkcs11/common/p11util.c	\
		  ../../lib/pkcs11/common/sw_crypt.c	\
		  ../../lib/pkcs11/common/trace.c	\
		  pkcscca.c

INCLUDES = -I. -I../../include/pkcs11 -I../../lib/pkcs11/common
