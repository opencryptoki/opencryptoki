bin_PROGRAMS=PKCS11_SW.so
bindir=/tmp

PKCS11_SW_so_LDFLAGS = -nostartfiles -shared -Wl,-Bsymbolic -Wl,-soname,PKCS11_SW.so.1 -lc -lpthread -lcrypto

PKCS11_SW_so_CFLAGS = -DSPINXPL -DDEV -D_THREAD_SAFE -DLINUX  -fPIC -DSHALLOW=0 -DSWTOK=1 -DLITE=0 -DNOCDMF -DNOMD2 -DNODSA -DDEBUGON

#VPATH= ./:../common

PKCS11_SW_so_SOURCES = ../common/asn1.c ../common/cert.c ../common/hwf_obj.c ../common/dp_obj.c ../common/data_obj.c ../common/decr_mgr.c ../common/dig_mgr.c ../common/encr_mgr.c ../common/globals.c ../common/loadsave.c ../common/key.c ../common/key_mgr.c ../common/mech_aes.c ../common/mech_des.c ../common/mech_des3.c ../common/mech_dh.c ../common/mech_md5.c ../common/mech_md2.c ../common/mech_rng.c ../common/mech_rsa.c ../common/mech_sha.c ../common/mech_ssl3.c ../common/new_host.c ../common/obj_mgr.c ../common/object.c ../common/sess_mgr.c ../common/sign_mgr.c ../common/template.c ../common/utility.c ../common/verify_mgr.c ../common/log.c soft_specific.c
 
INCLUDES = -I/usr/include -I. -I../../../include/pkcs11/stdll -I../../../include/pkcs11 -I ../common

install-data-local:
	mkdir -p $(INSROOT)/usr/lib/pkcs11/stdll; \
	if [ $(shell uname -m) != s390x ] ;then cp PKCS11_SW.so \
	$(INSROOT)/usr/lib/pkcs11/stdll/PKCS11_SW.so; fi; \
	rm -f /tmp/PKCS11_SW.*; 
