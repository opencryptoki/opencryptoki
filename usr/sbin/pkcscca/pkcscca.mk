sbin_PROGRAMS += usr/sbin/pkcscca/pkcscca
noinst_HEADERS += usr/sbin/pkcscca/pkcscca.h

usr_sbin_pkcscca_pkcscca_LDFLAGS = -lcrypto -ldl

usr_sbin_pkcscca_pkcscca_CFLAGS  =					\
	-DSTDLL_NAME=\"pkcscca\"					\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/common		\
	-I${srcdir}/usr/sbin/pkcscca

usr_sbin_pkcscca_pkcscca_SOURCES =					\
	usr/lib/common/p11util.c usr/lib/common/sw_crypt.c		\
	usr/lib/common/trace.c usr/sbin/pkcscca/pkcscca.c
