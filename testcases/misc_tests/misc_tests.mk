noinst_PROGRAMS +=							\
	%D%/obj_mgmt_tests %D%/obj_mgmt_lock_tests %D%/speed		\
	%D%/threadmkobj %D%/tok_obj %D%/tok_rsa %D%/tok_des

%C%_obj_mgmt_tests_CFLAGS = ${testcases_inc}
%C%_obj_mgmt_tests_LDADD = testcases/common/libcommon.la
%C%_obj_mgmt_tests_SOURCES = %D%/obj_mgmt.c

%C%_obj_mgmt_lock_tests_CFLAGS = ${testcases_inc}
%C%_obj_mgmt_lock_tests_LDADD = testcases/common/libcommon.la
%C%_obj_mgmt_lock_tests_SOURCES = %D%/obj_mgmt_lock.c

%C%_speed_CFLAGS = ${testcases_inc}
%C%_speed_LDADD = testcases/common/libcommon.la
%C%_speed_SOURCES = usr/lib/common/p11util.c %D%/speed.c

%C%_threadmkobj_CFLAGS = ${testcases_inc}
%C%_threadmkobj_LDADD = testcases/common/libcommon.la
%C%_threadmkobj_SOURCES = usr/lib/common/p11util.c %D%/threadmkobj.c

%C%_tok_obj_CFLAGS = ${testcases_inc}
%C%_tok_obj_LDADD = testcases/common/libcommon.la
%C%_tok_obj_SOURCES = usr/lib/common/p11util.c %D%/tok_obj.c

%C%_tok_rsa_CFLAGS = ${testcases_inc}
%C%_tok_rsa_LDADD = testcases/common/libcommon.la
%C%_tok_rsa_SOURCES = %D%/tok_rsa.c

%C%_tok_des_CFLAGS = ${testcases_inc}
%C%_tok_des_LDADD = testcases/common/libcommon.la
%C%_tok_des_SOURCES = %D%/tok_des.c
