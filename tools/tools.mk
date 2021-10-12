noinst_PROGRAMS += tools/tableidxgen

tools_tableidxgen_SOURCES = tools/tableidxgen.c usr/lib/common/mechtable.inc
tools_tableidxgen_CFLAGS = -I${srcdir}/usr/include -I${srcdir}/usr/lib/api
