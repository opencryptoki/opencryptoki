noinst_PROGRAMS=driver

AM_CFLAGS=-I. -I../../usr/include/pkcs11 -I../include
driver_CFLAGS=$(AM_CFLAGS)

AM_LDFLAGS = -lc  -ldl -lpthread
driver_LDFLAGS=$(AM_LDFLAGS)

driver_SOURCES = aes_func.c des_func.c des3_func.c digest_func.c driver.c \
                 dsa_func.c misc_func.c obj_mgmt.c rsa_func.c  \
                 sess_mgmt.c ssl3_func.c md5.c dh_func.c

