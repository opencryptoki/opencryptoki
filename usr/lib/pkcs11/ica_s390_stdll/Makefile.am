nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_ica.la

opencryptoki_stdll_libpkcs11_ica_la_LDFLAGS = $(LCRYPTO)		\
$(ICA_LIB_DIRS) -nostartfiles -shared -Wl,-Bsymbolic -Wl,-soname,$@	\
-Wl,-Bsymbolic -lc -lpthread -lica -ldl -lcrypto

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_ica_la_CFLAGS = -DSPINXPL -DDEV		\
-D_THREAD_SAFE -fPIC -DSHALLOW=0 -DSWTOK=0 -DLITE=1 -DNODH 		\
-DNOCDMF -DNOMD2 -DNODSA -DSTDLL_NAME=\"icatok\"

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = -DSPINXPL -DDEV -D_THREAD_SAFE -fPIC -DSHALLOW=0 -DSWTOK=0	\
-DLITE=1 -DNODH -DNOCDMF -DNOMD2 -DNODSA -DNORIPE

opencryptoki_stdll_libpkcs11_ica_la_SOURCES = asn1.c	\
cert.c hwf_obj.c dp_obj.c		\
data_obj.c decr_mgr.c dig_mgr.c	\
encr_mgr.c globals.c loadsave.c	\
key.c key_mgr.c mech_des.c	\
mech_des3.c mech_aes.c mech_md5.c	\
mech_md2.c mech_rng.c mech_rsa.c	\
mech_sha.c mech_ssl3.c new_host.c	\
obj_mgr.c object.c sess_mgr.c	\
sign_mgr.c template.c utility.c	\
verify_mgr.c log.c mech_list.c    \
ica_specific.c

INCLUDES = $(ICA_INC_DIRS) -I. -I../../../include/pkcs11/stdll	\
-I../../../include/pkcs11 -I../../../ica/inc	\
-I../../../../ica/include -I.. -I../../../../ica/src/inc

install-data-local:
	mkdir -p $(DESTDIR)/$(libdir)/opencryptoki/stdll
	cd $(DESTDIR)/$(libdir)/opencryptoki/stdll && rm -f PKCS11_ICA.so && \
		ln -sf libpkcs11_ica.so PKCS11_ICA.so
