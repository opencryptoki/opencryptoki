noinst_HEADERS +=							\
	usr/lib/common/attributes.h usr/lib/common/ec_defs.h		\
	usr/lib/common/host_defs.h usr/lib/common/ock_syslog.h		\
	usr/lib/common/shared_memory.h usr/lib/common/tok_spec_struct.h	\
	usr/lib/common/trace.h usr/lib/common/h_extern.h		\
	usr/lib/common/sw_crypt.h usr/lib/common/defs.h			\
	usr/lib/common/p11util.h usr/lib/common/event_client.h		\
	usr/lib/common/list.h usr/lib/common/tok_specific.h

usr/lib/common/lexer.c: usr/lib/common/parser.h

usr/lib/common/parser.c usr/lib/common/parser.output: usr/lib/common/parser.y
	$(AM_V_YACC)$(am__skipyacc) $(SHELL) $(YLWRAP) $< parser.tab.c usr/lib/common/parser.c parser.tab.h usr/lib/common/parser.h parser.output usr/lib/common/parser.output -- $(YACCCOMPILE)

usr/lib/common/lexer.c usr/lib/common/lexer.h: usr/lib/common/lexer.l
	$(AM_V_LEX)$(am__skiplex) $(SHELL) $(YLWRAP) $< lex.yy.c usr/lib/common/lexer.c lex.yy.h usr/lib/common/lexer.h -- $(LEXCOMPILE)
