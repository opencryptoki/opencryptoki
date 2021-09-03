noinst_HEADERS += usr/lib/config/configuration.h usr/lib/config/cfglex.h usr/lib/config/cfgparse.h

EXTRA_DIST += usr/lib/config/cfgparse.y usr/lib/config/cfglex.l

BUILT_SOURCES += usr/lib/config/cfglex.h usr/lib/config/cfgparse.h	\
		usr/lib/config/cfgparse.c

usr/lib/config/cfglex.c: usr/lib/config/cfgparse.h
usr/lib/config/cfgparse.c: usr/lib/config/cfglex.h

usr/lib/config/cfgparse.c usr/lib/config/cfgparse.h usr/lib/config/cfgparse.output: usr/lib/config/cfgparse.y
	$(AM_V_YACC)$(am__skipyacc) $(SHELL) $(YLWRAP) $< cfgparse.tab.c usr/lib/config/cfgparse.c cfgparse.tab.h usr/lib/config/cfgparse.h cfgparse.output usr/lib/config/cfgparse.output -- $(YACCCOMPILE)

usr/lib/config/cfglex.c usr/lib/config/cfglex.h: usr/lib/config/cfglex.l
	$(AM_V_LEX)$(am__skiplex) $(SHELL) $(YLWRAP) $< lex.config.c usr/lib/config/cfglex.c cfglex.h usr/lib/config/cfglex.h -- $(LEXCOMPILE)

CLEANFILES += usr/lib/config/cfglex.c usr/lib/config/cfglex.h	\
usr/lib/config/cfgparse.c usr/lib/config/cfgparse.h		\
usr/lib/config/cfgparse.output

