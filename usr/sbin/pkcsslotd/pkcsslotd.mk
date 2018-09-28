sbin_PROGRAMS += %D%/pkcsslotd
noinst_HEADERS +=							\
	%D%/err.h %D%/garbage_linux.h %D%/log.h	%D%/pkcsslotd.h

BUILT_SOURCES += %D%/parser.h
EXTRA_DIST += %D%/opencryptoki.conf
CLEANFILES += %D%/parser.c %D%/parser.h %D%/parser.output %D%/lexer.c

%C%_pkcsslotd_LDFLAGS = -lpthread -lcrypto

%C%_pkcsslotd_CFLAGS =							\
	-DPROGRAM_NAME=\"$(@)\" -I${srcdir}/usr/include

%C%_pkcsslotd_SOURCES =							\
	%D%/slotmgr.c %D%/shmem.c %D%/signal.c %D%/mutex.c %D%/err.c	\
	%D%/log.c %D%/daemon.c %D%/garbage_linux.c %D%/pkcsslotd_util.c	\
	%D%/socket_server.c %D%/parser.y %D%/lexer.l
