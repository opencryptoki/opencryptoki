nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_cr.la

opencryptoki_stdll_libpkcs11_cr_la_LDFLAGS = $(LCRYPTO) $(CR_LIB_DIRS)	\
-nostartfiles -shared -Wl,-Bsymbolic -Wl,-soname,PKCS11_BC.so.1 -lc	\
-lpthread -lsocketarmor -ldl -lcrypto

VARIANT = -DSHALLOW=0 -DSWTOK=1 -DLITE=0

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_cr_la_CFLAGS = -DSPINXPL -DDEV		\
-D_THREAD_SAFE -fPIC $(VARIANT) -DNOCDMF -DNOMD2 -DNODSA -DDEBUGON

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = -DSPINXPL -DDEV -D_THREAD_SAFE -fPIC $(VARIANT) -DNOCDMF	\
-DNOMD2 -DNODSA -DDEBUGON -DSTDLL_NAME=\"crtok\"

opencryptoki_stdll_libpkcs11_cr_la_SOURCES = asn1.c	\
		cert.c hwf_obj.c dp_obj.c		\
		data_obj.c decr_mgr.c dig_mgr.c		\
		encr_mgr.c globals.c loadsave.c		\
		key.c key_mgr.c mech_des.c		\
		mech_des3.c mech_dh.c mech_md5.c	\
		mech_md2.c mech_rng.c mech_rsa.c	\
		mech_sha.c mech_ssl3.c new_host.c	\
		obj_mgr.c object.c sess_mgr.c		\
		sign_mgr.c template.c utility.c		\
		verify_mgr.c log.c mech_list.c    	\
		cr_specific.c

INCLUDES = $(CR_INC_DIRS) -I/usr/include			\
-I. -I../../../include/pkcs11/stdll -I../../../include/pkcs11	\
-I../../../ica/inc -I../../../../ica/include			\
-I.. -I../../../../ica/src/inc

install-data-local:
	cd $(DESTDIR)/$(libdir)/opencryptoki/stdll && rm -f PKCS11_CR.so && \
		ln -sf libpkcs11_cr.so PKCS11_CR.so
