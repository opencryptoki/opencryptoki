noinst_PROGRAMS=obj_mgmt_tests obj_mgmt_lock_tests speed threadmkobj tok_obj tok_rsa tok_des

AM_CFLAGS=-I. -I../../usr/include/pkcs11 -I../include -I../common -I../../usr/lib/pkcs11/common -Wall

AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon

obj_mgmt_tests_SOURCES = obj_mgmt.c
obj_mgmt_lock_tests_SOURCES = obj_mgmt_lock.c
speed_SOURCES=../../usr/lib/pkcs11/common/p11util.c speed.c
threadmkobj_SOURCES=../../usr/lib/pkcs11/common/p11util.c threadmkobj.c
tok_obj_SOURCES=../../usr/lib/pkcs11/common/p11util.c tok_obj.c
tok_rsa_SOURCES=tok_rsa.c
tok_des_SOURCES=tok_des.c
