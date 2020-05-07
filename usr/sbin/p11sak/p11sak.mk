sbin_PROGRAMS += usr/sbin/p11sak/p11sak
noinst_HEADERS += usr/sbin/p11sak/p11sak.h

usr_sbin_p11sak_p11sak_LDFLAGS = -ldl

usr_sbin_p11sak_p11sak_CFLAGS  =			\
	-DLINUX -DPROGRAM_NAME=\"$(@)\"					\
	-I${srcdir}/usr/include \
	-I${srcdir}/usr/sbin/p11sak

usr_sbin_p11sak_p11sak_SOURCES =			\
	usr/sbin/p11sak/p11sak.c
