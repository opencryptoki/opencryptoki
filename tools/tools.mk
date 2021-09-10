noinst_PROGRAMS += tools/tableidxgen tools/policyexamplegen

tools_tableidxgen_SOURCES = tools/tableidxgen.c usr/lib/api/mechtable.inc
tools_tableidxgen_CFLAGS = -I${srcdir}/usr/include -I${srcdir}/usr/lib/api

tools_policyexamplegen_SOURCES = tools/policyexamplegen.c usr/lib/api/mechtable.c
tools_policyexamplegen_CFLAGS = -I${srcdir}/usr/include -I${srcdir}/usr/lib/api -I${top_builddir}/usr/lib/api
