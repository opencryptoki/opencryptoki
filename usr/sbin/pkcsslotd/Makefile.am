sbin_PROGRAMS=pkcsslotd
BUILT_SOURCES = parser.h
AM_YFLAGS = -v -d
EXTRA_DIST=opencryptoki.conf

pkcsslotd_LDFLAGS = -lpthread

# Not all versions of automake observe sbinname_CFLAGS
pkcsslotd_CFLAGS =  -DPROGRAM_NAME=\"$(@)\" \
		   -I../. -I../../include/pkcs11 -I../../include/pkcs11/stdll

# Not all versions of automake observe sbinname_CFLAGS
AM_CFLAGS = -DPROGRAM_NAME=\"$(@)\" \
	    -I../. -I../../include/pkcs11 -I../../include/pkcs11/stdll

pkcsslotd_SOURCES = slotmgr.c shmem.c signal.c mutex.c err.c log.c daemon.c \
		    garbage_linux.c pkcsslotd_util.c socket_server.c \
		    parser.y lexer.l

install-data-local :
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/opencryptoki.conf || $(INSTALL) -m 644 $(srcdir)/opencryptoki.conf $(DESTDIR)$(sysconfdir)/opencryptoki/opencryptoki.conf || true
