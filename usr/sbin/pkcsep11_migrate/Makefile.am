sbin_PROGRAMS=pkcsep11_migrate

pkcsep11_migrate_SOURCES = pkcsep11_migrate.c 
pkcsep11_migrate_CFLAGS  = -I ../../include/pkcs11/ -I../../lib/pkcs11/ep11_stdll/ -DLINUX -DPROGRAM_NAME=\"$(@)\"
pkcsep11_migrate_LDFLAGS = -lc  -ldl -lpthread -Wl,--allow-shlib-undefined -Wl,--unresolved-symbols=ignore-all
INCLUDES = -I. 

# Not all versions of automake observe sbinname_CFLAGS
# AM_CFLAGS = -DLINUX -DPROGRAM_NAME=\"$(@)\"
#
# INCLUDES = -I. -I../../include/pkcs11
