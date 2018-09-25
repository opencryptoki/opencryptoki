if ENABLE_TESTCASES
TESTDIR = testcases
endif
if ENABLE_LIBRARY
MISCDIR = misc
endif
if ENABLE_DAEMON
MISCDIR = misc
endif

ACLOCAL_AMFLAGS = -I m4

SUBDIRS = usr man $(MISCDIR) $(TESTDIR)

EXTRA_DIST = opencryptoki.map opencryptoki_tok.map
