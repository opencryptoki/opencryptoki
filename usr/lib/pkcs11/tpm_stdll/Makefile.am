# Makefile.am for common functions for openCryptoki
# Michael A. Halcrow <mhalcrow@us.ibm.com>
nobase_lib_LTLIBRARIES=opencryptoki/stdll/libpkcs11_tpm.la

AUTOMAKE_OPTIONS = gnu

#VPATH = ../common

# TODO: -DLINUX should be controlled via configure.in

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_tpm_la_CFLAGS = -DLINUX -DNOCDMF		\
					     -DNODSA -DNODH		\
					     -I. -I../../../include	\
					     -I../../../include/pkcs11	\
					     -I../common -DMMAP		\
					     -DSTDLL_NAME=\"tpmtok\"

opencryptoki_stdll_libpkcs11_tpm_la_LDFLAGS = -shared -Wl,-Bsymbolic	\
					      -lcrypto -ltspi -lpthread	\
					      -lrt

opencryptoki_stdll_libpkcs11_tpm_la_SOURCES = ../common/asn1.c		\
					      ../common/btree.c		\
					      ../common/dig_mgr.c	\
					      ../common/hwf_obj.c	\
					      ../common/trace.c		\
					      ../common/key.c		\
					      ../common/mech_dh.c	\
					      ../common/mech_rng.c	\
					      ../common/new_host.c	\
					      ../common/sign_mgr.c	\
					      ../common/cert.c		\
					      ../common/dp_obj.c	\
					      ../common/mech_aes.c	\
					      ../common/$(MECH_DSA)	\
					      ../common/mech_rsa.c	\
					      ../common/mech_ec.c	\
					      ../common/obj_mgr.c	\
					      ../common/template.c	\
					      ../common/p11util.c	\
					      ../common/data_obj.c	\
					      ../common/encr_mgr.c	\
					      ../common/key_mgr.c	\
					      ../common/mech_md2.c	\
					      ../common/mech_sha.c	\
					      ../common/object.c	\
					      ../common/decr_mgr.c	\
					      ../common/globals.c	\
					      ../common/sw_crypt.c	\
					      ../common/loadsave.c	\
					      ../common/utility.c	\
					      ../common/mech_des.c	\
					      ../common/mech_des3.c	\
					      ../common/mech_md5.c	\
					      ../common/mech_ssl3.c	\
					      ../common/sess_mgr.c	\
					      ../common/verify_mgr.c	\
					      ../common/mech_list.c	\
					      ../common/shared_memory.c	\
					      tpm_specific.c		\
					      tpm_openssl.c		\
					      tpm_util.c


noinst_HEADERS = defs.h		\
		 tpm_specific.h

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_tpm.so PKCS11_TPM.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	$(MKDIR_P) $(DESTDIR)$(lockdir)/tpm
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/tpm 
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/tpm

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -rf PKCS11_TPM.so; fi
