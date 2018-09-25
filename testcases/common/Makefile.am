noinst_LTLIBRARIES=libcommon.la

pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include
testdir=${top_srcdir}/testcases

libcommon_la_LDFLAGS=-lc -ldl -lpthread

libcommon_la_CFLAGS=-c					\
		    -I${testdir}/common			\
		    -I${testdir}/include		\
		    -I${incdir}/pkcs11			\
		    -I${incdir}				\
		    -I${pkcsdir}/common

libcommon_la_SOURCES=${pkcsdir}/common/p11util.c	\
		     ${testdir}/common/common.c
