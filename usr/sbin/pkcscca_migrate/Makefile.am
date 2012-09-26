
sbin_PROGRAMS=pkcscca_migrate
sbin_SCRIPTS=pkcscca_migrate.sh

pkcscca_migrate_SOURCES = cca_migrate.c loadsave_cca.c
pkcscca_migrate_CFLAGS  = -DLINUX -DPROGRAM_NAME=\"$(@)\"
pkcscca_migrate_LDFLAGS = -lcrypto -ldl

# Not all versions of automake observe sbinname_CFLAGS
AM_CFLAGS = -DLINUX -DPROGRAM_NAME=\"$(@)\"

INCLUDES = -I. -I../../include/pkcs11
