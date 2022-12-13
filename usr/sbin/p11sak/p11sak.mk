sbin_PROGRAMS += usr/sbin/p11sak/p11sak
noinst_HEADERS += usr/sbin/p11sak/p11sak.h

usr_sbin_p11sak_p11sak_LDFLAGS = -ldl -lcrypto

usr_sbin_p11sak_p11sak_CFLAGS = -DLINUX -DPROGRAM_NAME=\"$(@)\"		\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/common		\
	-I${srcdir}/usr/sbin/p11sak -I${srcdir}/usr/lib/config		\
	-I${top_builddir}/usr/lib/config -I${top_builddir}/usr/lib/api	\
	-I${srcdir}/usr/lib/api

usr_sbin_p11sak_p11sak_SOURCES = usr/lib/common/p11util.c		\
	usr/sbin/p11sak/p11sak.c usr/lib/common/pin_prompt.c		\
	usr/lib/config/configuration.c usr/lib/common/uri.c		\
	usr/lib/common/buffer.c						\
	usr/lib/config/cfgparse.y usr/lib/config/cfglex.l

nodist_usr_sbin_p11sak_p11sak_SOURCES = usr/lib/api/mechtable.c

usr/sbin/p11sak/p11sak.$(OBJEXT): usr/lib/config/cfgparse.h
