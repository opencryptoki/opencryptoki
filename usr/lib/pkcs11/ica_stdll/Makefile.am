bin_PROGRAMS=PKCS11_ICA.so
bindir=/tmp

PKCS11_ICA_so_LDFLAGS = $(LCRYPTO) $(ICA_LIB_DIRS) -nostartfiles -shared -Wl,-Bsymbolic -Wl,-soname,PKCS11_ICA.so.1 -lc -lpthread -ldl -lica

PKCS11_ICA_so_CFLAGS = -DSPINXPL -DDEV -D_THREAD_SAFE -DLINUX  -fPIC -DSHALLOW=0 -DSWTOK=0 -DLITE=1 -DNOCDMF -DNOMD2 -DNODSA -DNOAES -DNODH -D_LINUX -D_LINUX_ 

PKCS11_ICA_so_SOURCES = ../common/asn1.c ../common/cert.c ../common/hwf_obj.c ../common/dp_obj.c ../common/data_obj.c ../common/decr_mgr.c ../common/dig_mgr.c ../common/encr_mgr.c ../common/globals.c ../common/loadsave.c ../common/key.c ../common/key_mgr.c ../common/mech_des.c ../common/mech_des3.c ../common/mech_md5.c ../common/mech_md2.c ../common/mech_rng.c ../common/mech_rsa.c ../common/mech_sha.c ../common/mech_ssl3.c ../common/new_host.c ../common/obj_mgr.c ../common/object.c ../common/sess_mgr.c ../common/sign_mgr.c ../common/template.c ../common/utility.c ../common/verify_mgr.c ../common/log.c ../common/mech_list.c ica_specific.c

#VPATH=./:../common

INCLUDES = $(ICA_INC_DIRS) -I/usr/include -I. -I../../../include/pkcs11/stdll -I../../../include/pkcs11   -I../common -I../../../ica/inc -I../../../../ica/include -I.. -I../../../../ica/src/inc

install-data-local:
	mkdir -p $(INSROOT)/usr/lib/pkcs11/stdll; \
	if [ $(shell uname -m) == ppc64 ]; then \
		cp PKCS11_ICA.so $(INSROOT)/usr/lib/pkcs11/stdll/PKCS11_ICA.so64; \
	elif [ $(shell uname -m) != s390x ]; then \
		cp PKCS11_ICA.so $(INSROOT)/usr/lib/pkcs11/stdll/PKCS11_ICA.so; \
	fi; \
	rm -f /tmp/PKCS11_ICA.*;

