nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_ica.la

opencryptoki_stdll_libpkcs11_ica_la_LDFLAGS = $(LCRYPTO)	\
$(ICA_LIB_DIRS) -nostartfiles -shared -Wl,-Bsymbolic		\
-Wl,-soname,PKCS11_ICA.so.1 -lc -lpthread -ldl -lica

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_ica_la_CFLAGS = -DSPINXPL -DDEV		\
-D_THREAD_SAFE -fPIC -DSHALLOW=0 -DSWTOK=0 -DLITE=1 -DNOCDMF -DNOMD2	\
-DNODSA -DNOAES -DNODH -DNORIPE -DSTDLL_NAME=\"icatok\"

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = -DSPINXPL -DDEV -D_THREAD_SAFE -fPIC -DSHALLOW=0 -DSWTOK=0	\
-DLITE=1 -DNOCDMF -DNOMD2 -DNODSA -DNOAES -DNODH -DNORIPE

opencryptoki_stdll_libpkcs11_ica_la_SOURCES= ../common/asn1.c	\
../common/btree.c ../common/cert.c ../common/hwf_obj.c ../common/dp_obj.c \
../common/data_obj.c ../common/decr_mgr.c ../common/dig_mgr.c	\
../common/encr_mgr.c ../common/globals.c ../common/loadsave.c	\
../common/key.c ../common/key_mgr.c ../common/mech_des.c	\
../common/mech_des3.c ../common/mech_md5.c ../common/mech_md2.c	\
../common/mech_rng.c ../common/mech_rsa.c ../common/mech_sha.c	\
../common/mech_ssl3.c ../common/new_host.c ../common/obj_mgr.c	\
../common/object.c ../common/sess_mgr.c ../common/sign_mgr.c	\
../common/template.c ../common/utility.c ../common/verify_mgr.c	\
../common/log.c ../common/mech_list.c ica_specific.c

INCLUDES = $(ICA_INC_DIRS) -I/usr/include			\
-I. -I../../../include/pkcs11/stdll -I../../../include/pkcs11	\
-I../common -I../../../ica/inc -I../../../../ica/include	\
-I.. -I../../../../ica/src/inc

install-data-hook:
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_ica.so PKCS11_ICA.so

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_ICA.so; fi
