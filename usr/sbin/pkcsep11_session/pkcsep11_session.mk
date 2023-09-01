sbin_PROGRAMS += usr/sbin/pkcsep11_session/pkcsep11_session

usr_sbin_pkcsep11_session_pkcsep11_session_LDFLAGS = -lc -ldl -lpthread -lcrypto

usr_sbin_pkcsep11_session_pkcsep11_session_CFLAGS = -DLINUX		\
	-DPROGRAM_NAME=\"$(@)\" -I${srcdir}/usr/include			\
	-I${srcdir}/usr/lib/ep11_stdll/ -I${srcdir}/usr/lib/common	\
	-I${srcdir}/usr/sbin/pkcsep11_session -I${srcdir}/usr/lib/api	\
	-I${top_builddir}/usr/lib/api -I${top_builddir}/usr/lib/config	\
	-I${srcdir}/usr/lib/config -I${top_builddir}/usr/lib/ep11_stdll	\
	-I${srcdir}/usr/lib/ep11_stdll

usr_sbin_pkcsep11_session_pkcsep11_session_SOURCES =			\
	usr/lib/common/p11util.c usr/lib/common/pin_prompt.c		\
	usr/sbin/pkcsep11_session/pkcsep11_session.c

nodist_usr_sbin_pkcsep11_session_pkcsep11_session_SOURCES =		\
	usr/lib/api/mechtable.c
