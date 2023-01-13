sbin_PROGRAMS += usr/sbin/pkcsicsf/pkcsicsf

usr_sbin_pkcsicsf_pkcsicsf_LDFLAGS = -lldap -lssl -llber -lcrypto

usr_sbin_pkcsicsf_pkcsicsf_CFLAGS =					\
	-D_THREAD_SAFE -DDEV -DAPI -DSTDLL_NAME=\"icsf\"		\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/icsf_stdll		\
	-I${srcdir}/usr/lib/common -I${srcdir}/usr/sbin/pkcsicsf	\
	-I${srcdir}/usr/lib/config -I${top_builddir}/usr/lib/config	\
	-I${top_builddir}/usr/lib/api -I${srcdir}/usr/lib/api


usr_sbin_pkcsicsf_pkcsicsf_SOURCES =					\
	usr/lib/icsf_stdll/icsf.c usr/lib/icsf_stdll/pbkdf.c		\
	usr/lib/common/trace.c usr/lib/common/pin_prompt.c		\
	usr/sbin/pkcsicsf/pkcsicsf.c usr/lib/config/configuration.c	\
	usr/lib/config/cfgparse.y usr/lib/config/cfglex.l

usr/sbin/pkcsicsf/pkcsicsf.$(OBJEXT): usr/lib/config/cfgparse.h
