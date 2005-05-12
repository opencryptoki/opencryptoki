lib_LTLIBRARIES=libpkcs11_sw.la
libdir = $(exec_prefix)/lib/opencryptoki/stdll

libpkcs11_sw_la_LDFLAGS = -shared -Wl,-Bsymbolic -lc -lpthread -lcrypto

# Not all versions of automake observe libname_CFLAGS
libpkcs11_sw_la_CFLAGS = -DSPINXPL -DDEV -D_THREAD_SAFE -DSHALLOW=0 \
			 -DSWTOK=1 -DLITE=0 -DNOCDMF -DNOMD2 -DNODSA \
			 -DDEBUGON -fPIC -I/usr/include -I. \
			 -I../../../include/pkcs11/stdll \
			 -I../../../include/pkcs11 -I../common

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = -DSPINXPL -DDEV -D_THREAD_SAFE -DSHALLOW=0 \
	    -DSWTOK=1 -DLITE=0 -DNOCDMF -DNOMD2 -DNODSA \
	    -DDEBUGON -fPIC -I/usr/include -I. \
	    -I../../../include/pkcs11/stdll \
	    -I../../../include/pkcs11 -I../common

libpkcs11_sw_la_SOURCES = ../common/asn1.c ../common/cert.c \
			  ../common/hwf_obj.c ../common/dp_obj.c \
			  ../common/data_obj.c ../common/decr_mgr.c \
			  ../common/dig_mgr.c ../common/encr_mgr.c \
			  ../common/globals.c ../common/loadsave.c \
			  ../common/key.c ../common/key_mgr.c \
			  ../common/mech_aes.c ../common/mech_des.c \
			  ../common/mech_des3.c ../common/mech_dh.c \
			  ../common/mech_md5.c ../common/mech_md2.c \
			  ../common/mech_rng.c ../common/mech_rsa.c \
			  ../common/mech_sha.c ../common/mech_ssl3.c \
			  ../common/new_host.c ../common/obj_mgr.c \
			  ../common/object.c ../common/sess_mgr.c \
			  ../common/sign_mgr.c ../common/template.c \
			  ../common/utility.c ../common/verify_mgr.c \
			  ../common/log.c soft_specific.c
 
install-data-local:
	cd $(STDLL_PATH) && rm -f PKCS11_SW.so && \
		ln -sf libpkcs11_sw.so PKCS11_SW.so
