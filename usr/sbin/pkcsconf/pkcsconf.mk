sbin_PROGRAMS += %D%/pkcsconf
noinst_HEADERS += %D%/pkcsconf_msg.h

%C%_pkcsconf_LDFLAGS = -lpthread -ldl -lcrypto

%C%_pkcsconf_CFLAGS =							\
	-D_THREAD_SAFE -DDEBUG -DDEV -DAPI				\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/common		\
	-I${srcdir}/%D%

%C%_pkcsconf_SOURCES =							\
	usr/lib/common/p11util.c					\
	%D%/pkcsconf.c
