bin_PROGRAMS=PKCS11_BC.so
bindir=/tmp

PKCS11_BC_so_LDFLAGS = $(LCRYPTO) $(BC_LIB_DIRS) -nostartfiles -shared -Wl,-Bsymbolic -Wl,-soname,PKCS11_BC.so.1 -lc -lpthread -lubsec -ldl

VARIANT = -DSHALLOW=0 -DSWTOK=1 -DLITE=0
PKCS11_BC_so_CFLAGS = -DSPINXPL -DDEV -D_THREAD_SAFE -DLINUX  -fPIC $(VARIANT) -DNOCDMF -DNOMD2 -DNODSA -DNOAES -DNODH -DDEBUGON -D_LINUX -D_LINUX_ 

#VPATH= ./:../common

PKCS11_BC_so_SOURCES = ../common/asn1.c ../common/cert.c ../common/hwf_obj.c ../common/dp_obj.c ../common/data_obj.c ../common/decr_mgr.c ../common/dig_mgr.c ../common/encr_mgr.c ../common/globals.c ../common/loadsave.c ../common/key.c ../common/key_mgr.c ../common/mech_des.c ../common/mech_des3.c ../common/mech_md5.c ../common/mech_md2.c ../common/mech_rng.c ../common/mech_rsa.c ../common/mech_sha.c ../common/mech_ssl3.c ../common/new_host.c ../common/obj_mgr.c ../common/object.c ../common/sess_mgr.c ../common/sign_mgr.c ../common/template.c ../common/utility.c ../common/verify_mgr.c ../common/log.c bcom_specific.c

INCLUDES = $(BC_INC_DIRS) -I/usr/include -I. -I../../../include/pkcs11/stdll -I../../../include/pkcs11   -I../common -I../../../ica/inc -I../../../../ica/include -I.. -I../../../../ica/src/inc

install-data-local:
	mkdir -p $(INSROOT)/usr/lib/pkcs11/stdll; \
	if [ $(shell uname -m) != s390x ] ;then cp PKCS11_BC.so \
	$(INSROOT)/usr/lib/pkcs11/stdll/PKCS11_BC.so; fi; \
	rm -f /tmp/PKCS11_BC.*;
