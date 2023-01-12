noinst_PROGRAMS += tools/tableidxgen tools/policyexamplegen

TOOLS_CFLAGS = -I${srcdir}/usr/include -I${srcdir}/usr/lib/api -I${top_builddir}/usr/lib/api

tools_tableidxgen_SOURCES = tools/tableidxgen.c usr/lib/api/mechtable.inc

tools_policyexamplegen_SOURCES = tools/policyexamplegen.c usr/lib/api/mechtable.c

if CROSS
tools_tableidxgen_LINK = $(CC_FOR_BUILD) $(CFLAGS_FOR_BUILD) $(LDFLAGS_FOR_BUILD) -o $@

$(tools_tableidxgen_OBJECTS): CC=$(CC_FOR_BUILD)
$(tools_tableidxgen_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD) $(TOOLS_CFLAGS)
$(tools_tableidxgen_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)

tools_policyexamplegen_LINK = $(CC_FOR_BUILD) $(CFLAGS_FOR_BUILD) $(LDFLAGS_FOR_BUILD) -o $@

$(tools_policyexamplegen_OBJECTS): CC=$(CC_FOR_BUILD)
$(tools_policyexamplegen_OBJECTS): CFLAGS=$(CFLAGS_FOR_BUILD)  $(TOOLS_CFLAGS)
$(tools_policyexamplegen_OBJECTS): LDFLAGS=$(LDFLAGS_FOR_BUILD)
else
tools_tableidxgen_LINK = $(LINK)
tools_tableidxgen_CFLAGS = $(TOOLS_CFLAGS)

tools_policyexamplegen_LINK = $(LINK)
tools_policyexamplegen_CFLAGS = $(TOOLS_CFLAGS)
endif
