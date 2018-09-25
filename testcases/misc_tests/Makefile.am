noinst_PROGRAMS=obj_mgmt_tests obj_mgmt_lock_tests speed threadmkobj tok_obj tok_rsa tok_des

pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include
testdir=${top_srcdir}/testcases

AM_LDFLAGS=-L${testdir}/common -lc  -ldl -lpthread -lcommon

AM_CFLAGS=-I${testdir}/misc_tests -I${incdir}/pkcs11 -I${testdir}/include -I${testdir}/common -I${pkcsdir}/common

obj_mgmt_tests_SOURCES = ${testdir}/misc_tests/obj_mgmt.c
obj_mgmt_lock_tests_SOURCES = ${testdir}/misc_tests/obj_mgmt_lock.c
speed_SOURCES=${pkcsdir}/common/p11util.c ${testdir}/misc_tests/speed.c
threadmkobj_SOURCES=${pkcsdir}/common/p11util.c ${testdir}/misc_tests/threadmkobj.c
tok_obj_SOURCES=${pkcsdir}/common/p11util.c ${testdir}/misc_tests/tok_obj.c
tok_rsa_SOURCES=${testdir}/misc_tests/tok_rsa.c
tok_des_SOURCES=${testdir}/misc_tests/tok_des.c
