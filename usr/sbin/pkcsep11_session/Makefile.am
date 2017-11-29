sbin_PROGRAMS=pkcsep11_session

pkcsep11_session_SOURCES = ../../lib/pkcs11/common/p11util.c pkcsep11_session.c 
pkcsep11_session_CFLAGS  = -I ../../include/pkcs11/ -I../../lib/pkcs11/ep11_stdll/ -DLINUX -DPROGRAM_NAME=\"$(@)\"
pkcsep11_session_LDFLAGS = -lc  -ldl -lpthread
AM_CPPFLAGS = -I. -I../../lib/pkcs11/common

# Not all versions of automake observe sbinname_CFLAGS
# AM_CFLAGS = -DLINUX -DPROGRAM_NAME=\"$(@)\"
#
# AM_CPPFLAGS = -I. -I../../include/pkcs11
