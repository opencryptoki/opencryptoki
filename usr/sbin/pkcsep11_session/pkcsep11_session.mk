sbin_PROGRAMS += usr/sbin/pkcsep11_session/pkcsep11_session

usr_sbin_pkcsep11_session_pkcsep11_session_LDFLAGS = -lc -ldl -lpthread

usr_sbin_pkcsep11_session_pkcsep11_session_CFLAGS  =			\
	-DLINUX -DPROGRAM_NAME=\"$(@)\"					\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/ep11_stdll/		\
	-I${srcdir}/usr/lib/common -I${srcdir}/usr/sbin/pkcsep11_session

usr_sbin_pkcsep11_session_pkcsep11_session_SOURCES =			\
	usr/lib/common/p11util.c					\
	usr/sbin/pkcsep11_session/pkcsep11_session.c
