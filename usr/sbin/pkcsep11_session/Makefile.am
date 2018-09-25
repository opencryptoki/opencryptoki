sbin_PROGRAMS=pkcsep11_session

bindir=${top_srcdir}/usr/sbin
pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

pkcsep11_session_LDFLAGS = -lc -ldl -lpthread

pkcsep11_session_CFLAGS  = -I${incdir}/pkcs11/		\
			   -I${pkcsdir}/ep11_stdll/	\
			   -I${pkcsdir}/common		\
			   -I${bindir}/pkcsep11_session	\
			   -DLINUX -DPROGRAM_NAME=\"$(@)\"

pkcsep11_session_SOURCES = ${pkcsdir}/common/p11util.c	\
			   ${bindir}/pkcsep11_session/pkcsep11_session.c 
