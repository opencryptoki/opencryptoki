sbin_PROGRAMS += usr/sbin/pkcsslotd/pkcsslotd
noinst_HEADERS +=							\
	usr/sbin/pkcsslotd/err.h usr/sbin/pkcsslotd/garbage_linux.h	\
	usr/sbin/pkcsslotd/log.h usr/sbin/pkcsslotd/pkcsslotd.h

BUILT_SOURCES += usr/lib/common/parser.h
EXTRA_DIST += usr/sbin/pkcsslotd/opencryptoki.conf
CLEANFILES += usr/lib/common/parser.c usr/lib/common/parser.h	\
	usr/lib/common/parser.output usr/lib/common/lexer.c

usr_sbin_pkcsslotd_pkcsslotd_LDFLAGS = -lpthread -lcrypto

usr_sbin_pkcsslotd_pkcsslotd_CFLAGS =							\
	-DPROGRAM_NAME=\"$(@)\" -I${srcdir}/usr/include -I${srcdir}/usr/lib/common

usr_sbin_pkcsslotd_pkcsslotd_SOURCES =							\
	usr/sbin/pkcsslotd/slotmgr.c usr/sbin/pkcsslotd/shmem.c				\
	usr/sbin/pkcsslotd/signal.c usr/sbin/pkcsslotd/mutex.c usr/sbin/pkcsslotd/err.c	\
	usr/sbin/pkcsslotd/log.c usr/sbin/pkcsslotd/daemon.c				\
	usr/sbin/pkcsslotd/garbage_linux.c usr/sbin/pkcsslotd/pkcsslotd_util.c		\
	usr/sbin/pkcsslotd/socket_server.c usr/lib/common/parser.y			\
	usr/lib/common/lexer.l
