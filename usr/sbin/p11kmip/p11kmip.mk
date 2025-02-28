include usr/sbin/p11kmip/kmipclient/kmipclient.mk

sbin_PROGRAMS += usr/sbin/p11kmip/p11kmip
noinst_HEADERS += usr/sbin/p11kmip/p11kmip.h

usr_sbin_p11kmip_p11kmip_LDADD = usr/sbin/p11kmip/kmipclient/libkmipclient.a \
	-ldl -lcrypto -lssl

if AIX
usr_sbin_p11kmip_p11kmip_LDFLAGS = -Wl,-blibpath:$(libdir)/opencryptoki:$(libdir)/opencryptoki/stdll:/usr/lib:/usr/lib64
endif

EXTRA_DIST += usr/sbin/p11kmip/p11kmip.conf

usr_sbin_p11kmip_p11kmip_CFLAGS = -DLINUX -DPROGRAM_NAME=\"$(@)\"	\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/common		\
	-I${srcdir}/usr/sbin/p11kmip -I${srcdir}/usr/lib/config		\
	-I${top_builddir}/usr/lib/config -I${top_builddir}/usr/lib/api	\
	-I${srcdir}/usr/lib/api -I${srcdir}/usr/sbin/p11sak

if !AIX
usr_sbin_p11kmip_p11kmip_CFLAGS += -DLINUX
endif

usr_sbin_p11kmip_p11kmip_SOURCES = usr/lib/common/p11util.c		\
	usr/sbin/p11kmip/p11kmip.c usr/lib/common/pin_prompt.c		\
	usr/lib/config/configuration.c usr/lib/common/uri.c		\
	usr/lib/common/buffer.c	usr/sbin/p11sak/p11tool.c		\
	usr/lib/config/cfgparse.y usr/lib/config/cfglex.l

if AIX
usr_sbin_p11kmip_p11kmip_SOURCES += usr/lib/common/aix/err.c \
	usr/lib/common/aix/getopt_long.c
endif

nodist_usr_sbin_p11kmip_p11kmip_SOURCES = usr/lib/api/mechtable.c

usr/sbin/p11kmip/p11kmip.$(OBJEXT): usr/lib/config/cfgparse.h
