lib_LTLIBRARIES=libpkcs11_sw.so
libdir = $(exec_prefix)/lib/opencryptoki/stdll

libpkcs11_sw_so_LDFLAGS = -nostartfiles -shared -Wl,-Bsymbolic -Wl,-soname,$@ -lc -lpthread -lcrypto

#libpkcs11_sw_so_CFLAGS = -DSPINXPL -DDEV -D_THREAD_SAFE -fPIC -DSHALLOW=0 -DSWTOK=1 -DLITE=0 -DNOCDMF -DNOMD2 -DNODSA -DDEBUGON

AM_CFLAGS = -DSPINXPL -DDEV -D_THREAD_SAFE -fPIC -DSHALLOW=0 -DSWTOK=1 -DLITE=0 -DNOCDMF -DNOMD2 -DNODSA -DDEBUGON

#VPATH= ./:../common

libpkcs11_sw_so_SOURCES = ../common/asn1.c ../common/cert.c ../common/hwf_obj.c ../common/dp_obj.c ../common/data_obj.c ../common/decr_mgr.c ../common/dig_mgr.c ../common/encr_mgr.c ../common/globals.c ../common/loadsave.c ../common/key.c ../common/key_mgr.c ../common/mech_aes.c ../common/mech_des.c ../common/mech_des3.c ../common/mech_dh.c ../common/mech_md5.c ../common/mech_md2.c ../common/mech_rng.c ../common/mech_rsa.c ../common/mech_sha.c ../common/mech_ssl3.c ../common/new_host.c ../common/obj_mgr.c ../common/object.c ../common/sess_mgr.c ../common/sign_mgr.c ../common/template.c ../common/utility.c ../common/verify_mgr.c ../common/log.c soft_specific.c
 
INCLUDES = -I/usr/include -I. -I../../../include/pkcs11/stdll -I../../../include/pkcs11 -I ../common

install-data-local:
	ln -sf $(exec_prefix)/lib/opencryptoki/stdll/libpkcs11_sw.so \
	       $(exec_prefix)/lib/opencryptoki/stdll/PKCS11_SW.so
