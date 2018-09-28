noinst_PROGRAMS +=							\
	%D%/login %D%/init_tok %D%/set_pin %D%/init_pin	%D%/digest_init	\
	%D%/login_flags_test

%C%_login_CFLAGS = ${testcases_inc}
%C%_login_LDADD = testcases/common/libcommon.la
%C%_login_SOURCES = usr/lib/common/p11util.c %D%/login.c

%C%_init_tok_CFLAGS = ${testcases_inc}
%C%_init_tok_LDADD = testcases/common/libcommon.la
%C%_init_tok_SOURCES = %D%/init_tok.c

%C%_set_pin_CFLAGS = ${testcases_inc}
%C%_set_pin_LDADD = testcases/common/libcommon.la
%C%_set_pin_SOURCES = %D%/set_pin.c

%C%_init_pin_CFLAGS = ${testcases_inc}
%C%_init_pin_LDADD = testcases/common/libcommon.la
%C%_init_pin_SOURCES = %D%/init_pin.c

%C%_digest_init_CFLAGS = ${testcases_inc}
%C%_digest_init_LDADD = testcases/common/libcommon.la
%C%_digest_init_SOURCES = %D%/digest_init.c

%C%_login_flags_test_CFLAGS = ${testcases_inc}
%C%_login_flags_test_LDADD = testcases/common/libcommon.la
%C%_login_flags_test_SOURCES = usr/lib/common/p11util.c %D%/login_flags.c
