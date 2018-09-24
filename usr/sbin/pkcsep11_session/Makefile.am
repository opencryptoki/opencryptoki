sbin_PROGRAMS=pkcsep11_session

pkcsep11_session_LDFLAGS = -lc  -ldl -lpthread

pkcsep11_session_CFLAGS  = -I../../include/pkcs11/		\
			   -I../../lib/pkcs11/ep11_stdll/	\
			   -DLINUX -DPROGRAM_NAME=\"$(@)\"	\
			   -I. -I../../lib/pkcs11/common

pkcsep11_session_SOURCES = ../../lib/pkcs11/common/p11util.c pkcsep11_session.c 
