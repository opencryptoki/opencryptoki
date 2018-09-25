sbin_PROGRAMS=pkcsslotd

bindir=${top_srcdir}/usr/sbin
pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

AM_YFLAGS = -v -d
BUILT_SOURCES = ${bindir}/pkcsslotd/parser.h
EXTRA_DIST = ${bindir}/pkcsslotd/opencryptoki.conf

pkcsslotd_LDFLAGS = -lpthread -lcrypto

pkcsslotd_CFLAGS =  -DPROGRAM_NAME=\"$(@)\" \
		   -I${incdir}/pkcs11

pkcsslotd_SOURCES = ${bindir}/pkcsslotd/slotmgr.c	\
		    ${bindir}/pkcsslotd/shmem.c		\
		    ${bindir}/pkcsslotd/signal.c	\
		    ${bindir}/pkcsslotd/mutex.c		\
		    ${bindir}/pkcsslotd/err.c		\
		    ${bindir}/pkcsslotd/log.c		\
		    ${bindir}/pkcsslotd/daemon.c	\
		    ${bindir}/pkcsslotd/garbage_linux.c	\
		    ${bindir}/pkcsslotd/pkcsslotd_util.c\
		    ${bindir}/pkcsslotd/socket_server.c	\
		    ${bindir}/pkcsslotd/parser.y	\
		    ${bindir}/pkcsslotd/lexer.l

noinst_HEADERS = ${bindir}/pkcsslotd/err.h		\
		 ${bindir}/pkcsslotd/garbage_linux.h 	\
		 ${bindir}/pkcsslotd/log.h		\
		 ${bindir}/pkcsslotd/pkcsslotd.h

install-data-local:
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/opencryptoki.conf || $(INSTALL) -m 644 $(srcdir)/opencryptoki.conf $(DESTDIR)$(sysconfdir)/opencryptoki/opencryptoki.conf || true

uninstall-hook:
	rm -f $(DESTDIR)$(sysconfdir)/opencryptoki/opencryptoki.conf || true
