noinst_PROGRAMS=obj_mgmt_tests obj_mgmt_lock_tests

AM_CFLAGS=-I. -I../../usr/include/pkcs11 -I../include -I../common -I../../usr/lib/pkcs11/common -Wall

AM_LDFLAGS=-L../common -lc  -ldl -lpthread -lcommon

obj_mgmt_tests_SOURCES = obj_mgmt.c
obj_mgmt_lock_tests_SOURCES = obj_mgmt_lock.c
