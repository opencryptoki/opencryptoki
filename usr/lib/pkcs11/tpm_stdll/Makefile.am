# Makefile.am for common functions for openCryptoki
# Michael A. Halcrow <mhalcrow@us.ibm.com>
lib_LTLIBRARIES=libpkcs11_tpm.la
libdir = $(exec_prefix)/lib/opencryptoki/stdll

AUTOMAKE_OPTIONS = gnu

#MECH_DSA = mech_dsa.c

VPATH = ../common

# TODO: -DLINUX and -DSPINXPL should be controlled via configure.in

# Not all versions of automake observe libname_CFLAGS
libpkcs11_tpm_la_CFLAGS = -DLINUX -DSPINXPL -DNOCDMF -DNODSA \
			  -I../../../include -I../../../include/pkcs11 \
			  -I../common -I.

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = -DLINUX -DSPINXPL -DNOCDMF -DNODSA \
	    -I../../../include -I../../../include/pkcs11 \
	    -I../common -I.

libpkcs11_tpm_la_LDFLAGS = -shared -Wl,-Bsymbolic -lcrypto -ltspi -lpthread

libpkcs11_tpm_la_SOURCES = asn1.c dig_mgr.c hwf_obj.c log.c mech_dh.c mech_rng.c new_host.c sign_mgr.c cert.c dp_obj.c key.c mech_aes.c $(MECH_DSA) mech_rsa.c obj_mgr.c template.c data_obj.c encr_mgr.c key_mgr.c mech_md2.c mech_sha.c object.c utility.c decr_mgr.c globals.c loadsave.c mech_des.c mech_des3.c mech_md5.c mech_ssl3.c sess_mgr.c verify_mgr.c tpm_specific.c tpm_openssl.c tpm_util.c

noinst_HEADERS = args.h c_extern.h h_extern.h linuxdef.h tok_spec_struct.h tokenlocal.h c_defs.h defs.h host_defs.h msg.h tpm_specific.h tok_specific.h

