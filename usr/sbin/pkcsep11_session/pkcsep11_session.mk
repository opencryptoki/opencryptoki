sbin_PROGRAMS += %D%/pkcsep11_session

%C%_pkcsep11_session_LDFLAGS = -lc -ldl -lpthread

%C%_pkcsep11_session_CFLAGS  =						\
	-DLINUX -DPROGRAM_NAME=\"$(@)\"					\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/ep11_stdll/		\
	-I${srcdir}/usr/lib/common -I${srcdir}/%D%

%C%_pkcsep11_session_SOURCES =						\
	usr/lib/common/p11util.c %D%/pkcsep11_session.c
