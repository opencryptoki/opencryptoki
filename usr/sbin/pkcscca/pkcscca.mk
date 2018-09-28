sbin_PROGRAMS += %D%/pkcscca
noinst_HEADERS += %D%/pkcscca.h

%C%_pkcscca_LDFLAGS = -lcrypto -ldl

%C%_pkcscca_CFLAGS  =							\
	-DSTDLL_NAME=\"pkcscca\"					\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/common		\
	-I${srcdir}/%D%

%C%_pkcscca_SOURCES =							\
	usr/lib/common/p11util.c usr/lib/common/sw_crypt.c		\
	usr/lib/common/trace.c %D%/pkcscca.c
