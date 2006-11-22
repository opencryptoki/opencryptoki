nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_aep.la

opencryptoki_stdll_libpkcs11_aep_la_LDFLAGS = $(LCRYPTO)		\
$(AEP_LIB_DIRS) -nostartfiles -shared -Wl,-soname,PKCS11_AEP.so.1 -lc	\
-lpthread -lcrypto -laep

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_aep_la_CFLAGS = -DSPINXPL -DDEV		\
-D_THREAD_SAFE -fPIC -DSHALLOW=0 -DSWTOK=1 -DLITE=0 -DNOCDMF -DNOMD2	\
-DNODSA -DDEBUGON -DAEP_GENERIC -DNORIPE -DSTDLL_NAME=\"aeptok\"

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = @CFLAGS@ -DSPINXPL -DDEV -D_THREAD_SAFE -fPIC -DSHALLOW=0	\
-DSWTOK=1 -DLITE=0 -DNOCDMF -DNOMD2 -DNODSA -DDEBUGON -DAEP_GENERIC -DNORIPE

opencryptoki_stdll_libpkcs11_aep_la_SOURCES = asn1.c	\
		cert.c hwf_obj.c dp_obj.c		\
		data_obj.c decr_mgr.c dig_mgr.c		\
		encr_mgr.c globals.c loadsave.c		\
		key.c key_mgr.c mech_des.c		\
		mech_des3.c mech_dh.c mech_md5.c	\
		mech_md2.c mech_rng.c mech_rsa.c	\
		mech_sha.c mech_ssl3.c new_host.c	\
		obj_mgr.c object.c sess_mgr.c		\
		sign_mgr.c template.c utility.c		\
		verify_mgr.c log.c mech_list.c          \
		aeptok_specific.c aeptok_api.c
 
INCLUDES = -I/usr/include -I. -I../../../include/pkcs11/stdll	\
-I../../../include/pkcs11

install-data-local:
	cd $(DESTDIR)/$(libdir)/opencryptoki/stdll && rm -f PKCS11_AEP.so && \
		ln -sf libpkcs11_aep.so PKCS11_AEP.so
