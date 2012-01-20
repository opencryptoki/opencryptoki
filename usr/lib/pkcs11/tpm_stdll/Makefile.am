# Makefile.am for common functions for openCryptoki
# Michael A. Halcrow <mhalcrow@us.ibm.com>
nobase_lib_LTLIBRARIES=opencryptoki/stdll/libpkcs11_tpm.la

AUTOMAKE_OPTIONS = gnu

#VPATH = ../common

# TODO: -DLINUX and -DSPINXPL should be controlled via configure.in

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_tpm_la_CFLAGS = -DLINUX -DNOCDMF		\
					     -DNODSA -DNODH		\
					     -I. -I../../../include	\
					     -I../../../include/pkcs11	\
					     -I../common -DMMAP		\
					     -DSTDLL_NAME=\"tpmtok\"

opencryptoki_stdll_libpkcs11_tpm_la_LDFLAGS = -shared -Wl,-Bsymbolic	\
					      -lcrypto -ltspi -lpthread

opencryptoki_stdll_libpkcs11_tpm_la_SOURCES = ../common/asn1.c           \
					      ../common/btree.c		 \
                                              dig_mgr.c                  \
                                              ../common/hwf_obj.c        \
                                              ../common/log.c            \
					      ../common/key.c            \
                                              mech_dh.c        \
                                              ../common/mech_rng.c       \
                                              new_host.c sign_mgr.c      \
                                              ../common/cert.c           \
                                              ../common/dp_obj.c         \
                                              mech_aes.c       \
                                              ../common/$(MECH_DSA)      \
                                              mech_rsa.c                 \
                                              ../common/obj_mgr.c        \
                                              ../common/template.c       \
					      ../common/p11util.c        \
                                              ../common/data_obj.c       \
                                              encr_mgr.c key_mgr.c       \
                                              ../common/mech_md2.c       \
                                              mech_sha.c       \
                                              ../common/object.c         \
                                              decr_mgr.c globals.c       \
                                              loadsave.c utility.c       \
                                              mech_des.c       \
                                              mech_des3.c      \
                                              ../common/mech_md5.c       \
                                              ../common/mech_ssl3.c      \
                                              sess_mgr.c       \
                                              verify_mgr.c               \
                                              tpm_specific.c             \
                                              tpm_openssl.c tpm_util.c

noinst_HEADERS = h_extern.h tok_spec_struct.h defs.h	\
		 host_defs.h tpm_specific.h tok_specific.h

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/tpm
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_tpm.so PKCS11_TPM.so

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -rf PKCS11_TPM.so; fi
