sbin_PROGRAMS=pkcsconf

pkcsconf_LDFLAGS = -lpthread -ldl

# Not all versions of automake observe sbinname_CFLAGS
pkcsconf_CFLAGS = -D_THREAD_SAFE -DDEBUG -DDEV -DAPI

# Not all versions of automake observe sbinname_CFLAGS
AM_CFLAGS = -D_THREAD_SAFE -DDEBUG -DDEV -DAPI

pkcsconf_SOURCES = ../../lib/pkcs11/common/p11util.c pkcsconf.c

INCLUDES = -I../../include/pkcs11 -I. -I../../lib/pkcs11/common
