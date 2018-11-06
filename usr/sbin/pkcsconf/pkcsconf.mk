sbin_PROGRAMS += usr/sbin/pkcsconf/pkcsconf
noinst_HEADERS += usr/sbin/pkcsconf/pkcsconf_msg.h

usr_sbin_pkcsconf_pkcsconf_LDFLAGS = -lpthread -ldl -lcrypto

usr_sbin_pkcsconf_pkcsconf_CFLAGS =					\
	-D_THREAD_SAFE -DDEBUG -DDEV -DAPI				\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/common		\
	-I${srcdir}/usr/sbin/pkcsconf

usr_sbin_pkcsconf_pkcsconf_SOURCES =					\
	usr/lib/common/p11util.c					\
	usr/sbin/pkcsconf/pkcsconf.c
