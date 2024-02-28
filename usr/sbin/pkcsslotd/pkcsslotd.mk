sbin_PROGRAMS += usr/sbin/pkcsslotd/pkcsslotd
noinst_HEADERS +=							\
	usr/sbin/pkcsslotd/err.h usr/sbin/pkcsslotd/garbage_linux.h	\
	usr/sbin/pkcsslotd/log.h usr/sbin/pkcsslotd/pkcsslotd.h

EXTRA_DIST += usr/sbin/pkcsslotd/opencryptoki.conf

usr_sbin_pkcsslotd_pkcsslotd_LDFLAGS = -lpthread -lcrypto

if AIX
usr_sbin_pkcsslotd_pkcsslotd_LDFLAGS += -Wl,-blibpath:$(libdir)/opencryptoki:$(libdir)/opencryptoki/stdll:/usr/lib:/usr/lib64
else
usr_sbin_pkcsslotd_pkcsslotd_LDFLAGS += -lcap
endif

if HAVE_LIBUDEV
usr_sbin_pkcsslotd_pkcsslotd_LDFLAGS += -ludev
endif

usr_sbin_pkcsslotd_pkcsslotd_CFLAGS = -DPROGRAM_NAME=\"$(@)\"	\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/common	\
	-I${top_builddir}/usr/lib/common  			\
	-I${top_builddir}/usr/lib/api				\
	-I${srcdir}/usr/lib/config				\
	-I${top_builddir}/usr/lib/config

usr_sbin_pkcsslotd_pkcsslotd_SOURCES =							\
	usr/sbin/pkcsslotd/slotmgr.c usr/sbin/pkcsslotd/shmem.c				\
	usr/sbin/pkcsslotd/signal.c usr/sbin/pkcsslotd/mutex.c usr/sbin/pkcsslotd/err.c	\
	usr/sbin/pkcsslotd/log.c usr/sbin/pkcsslotd/daemon.c				\
	usr/sbin/pkcsslotd/garbage_linux.c usr/sbin/pkcsslotd/pkcsslotd_util.c		\
	usr/sbin/pkcsslotd/socket_server.c usr/lib/config/configuration.c		\
	usr/lib/config/cfgparse.y usr/lib/config/cfglex.l

if AIX
usr_sbin_pkcsslotd_pkcsslotd_LDFLAGS += -lbsd
endif

nodist_usr_sbin_pkcsslotd_pkcsslotd_SOURCES = \
	usr/lib/common/dlist.c
usr/sbin/pkcsslotd/slotmgr.$(OBJEXT): usr/lib/config/cfgparse.h
