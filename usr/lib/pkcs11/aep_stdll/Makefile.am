nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_aep.la

opencryptoki_stdll_libpkcs11_aep_la_LDFLAGS = $(LCRYPTO)		\
$(AEP_LIB_DIRS) -nostartfiles -shared -Wl,-soname,PKCS11_AEP.so.1 -lc	\
-lpthread -lcrypto -laep

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_aep_la_CFLAGS = -DSPINXPL -DDEV		\
-D_THREAD_SAFE -fPIC -DSHALLOW=0 -DSWTOK=1 -DLITE=0 -DNOCDMF -DNOMD2	\
-DNODSA -DAEP_GENERIC -DNORIPE -DSTDLL_NAME=\"aeptok\"

opencryptoki_stdll_libpkcs11_aep_la_SOURCES = ../common/asn1.c		\
../common/btree.c ../common/cert.c ../common/hwf_obj.c ../common/dp_obj.c \
../common/data_obj.c ../common/decr_mgr.c ../common/dig_mgr.c		\
../common/encr_mgr.c ../common/globals.c ../common/loadsave.c		\
../common/key.c ../common/key_mgr.c ../common/mech_des.c		\
../common/mech_des3.c ../common/mech_dh.c ../common/mech_md5.c		\
../common/mech_md2.c ../common/mech_rng.c ../common/mech_rsa.c		\
../common/mech_sha.c ../common/mech_ssl3.c ../common/new_host.c		\
../common/obj_mgr.c ../common/object.c ../common/sess_mgr.c		\
../common/sign_mgr.c ../common/template.c ../common/utility.c		\
../common/verify_mgr.c ../common/log.c ../common/mech_list.c            \
aeptok_specific.c aeptok_api.c
 
INCLUDES = -I/usr/include -I. -I../../../include/pkcs11/stdll	\
-I../../../include/pkcs11 -I ../common

install-data-hook:
	cd $(DESTDIR)/$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_aep.so PKCS11_AEP.so

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)/$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_AEP.so; fi
