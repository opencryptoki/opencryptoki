noinst_PROGRAMS +=							\
	%D%/hw_fn %D%/sess_mgmt_tests %D%/sess_bench %D%/sess_opstate	\
	%D%/attribute %D%/findobjects %D%/destroyobjects		\
	%D%/copyobjects	%D%/generate_keypair %D%/gen_purpose		\
	%D%/getobjectsize

%C%_hw_fn_CFLAGS = ${testcases_inc}
%C%_hw_fn_LDADD = testcases/common/libcommon.la
%C%_hw_fn_SOURCES = %D%/hw_fn.c

%C%_sess_mgmt_tests_CFLAGS = ${testcases_inc}
%C%_sess_mgmt_tests_LDADD = testcases/common/libcommon.la
%C%_sess_mgmt_tests_SOURCES = %D%/sess_mgmt.c

%C%_sess_bench_CFLAGS = ${testcases_inc}
%C%_sess_bench_LDADD = testcases/common/libcommon.la
%C%_sess_bench_SOURCES = %D%/sess_perf.c

%C%_sess_opstate_CFLAGS = ${testcases_inc}
%C%_sess_opstate_LDADD = testcases/common/libcommon.la
%C%_sess_opstate_SOURCES = %D%/sess_opstate.c

%C%_attribute_CFLAGS = ${testcases_inc}
%C%_attribute_LDADD = testcases/common/libcommon.la
%C%_attribute_SOURCES = %D%/attribute.c

%C%_findobjects_CFLAGS = ${testcases_inc}
%C%_findobjects_LDADD = testcases/common/libcommon.la
%C%_findobjects_SOURCES = %D%/findobjects.c

%C%_destroyobjects_CFLAGS = ${testcases_inc}
%C%_destroyobjects_LDADD = testcases/common/libcommon.la
%C%_destroyobjects_SOURCES = %D%/destroyobjects.c

%C%_copyobjects_CFLAGS = ${testcases_inc}
%C%_copyobjects_LDADD = testcases/common/libcommon.la
%C%_copyobjects_SOURCES = %D%/copyobjects.c

%C%_generate_keypair_CFLAGS = ${testcases_inc}
%C%_generate_keypair_LDADD = testcases/common/libcommon.la
%C%_generate_keypair_SOURCES = %D%/generate_keypair.c

%C%_gen_purpose_CFLAGS = ${testcases_inc}
%C%_gen_purpose_LDADD = testcases/common/libcommon.la
%C%_gen_purpose_SOURCES = %D%/gen_purpose.c

%C%_getobjectsize_CFLAGS = ${testcases_inc}
%C%_getobjectsize_LDADD = testcases/common/libcommon.la
%C%_getobjectsize_SOURCES = %D%/getobjectsize.c
