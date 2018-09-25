# Makefile.am for common functions for openCryptoki
# Michael A. Halcrow <mhalcrow@us.ibm.com>
nobase_lib_LTLIBRARIES=opencryptoki/stdll/libpkcs11_tpm.la

pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

# TODO: -DLINUX should be controlled via configure.ac
opencryptoki_stdll_libpkcs11_tpm_la_CFLAGS = -DLINUX -DNOCDMF		\
					     -DNODSA -DNODH		\
					     -DMMAP			\
					     -I${pkcsdir}/tpm_stdll	\
					     -I${pkcsdir}/common 	\
					     -I${incdir}		\
					     -I${incdir}/pkcs11		\
					     -DSTDLL_NAME=\"tpmtok\"

if ENABLE_LOCKS
opencryptoki_stdll_libpkcs11_tpm_la_LDFLAGS = -shared -Wl,-z,defs,-Bsymbolic	\
					      -lcrypto -ltspi -lpthread	\
					      -lrt			\
					      -Wl,--version-script=${top_srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_tpm_la_SOURCES = ${pkcsdir}/common/asn1.c		\
					      ${pkcsdir}/common/lock_btree.c		\
					      ${pkcsdir}/common/dig_mgr.c	\
					      ${pkcsdir}/common/hwf_obj.c	\
					      ${pkcsdir}/common/trace.c		\
					      ${pkcsdir}/common/key.c		\
					      ${pkcsdir}/common/mech_dh.c	\
					      ${pkcsdir}/common/mech_rng.c	\
					      ${pkcsdir}/common/new_host.c	\
					      ${pkcsdir}/common/sign_mgr.c	\
					      ${pkcsdir}/common/cert.c		\
					      ${pkcsdir}/common/dp_obj.c	\
					      ${pkcsdir}/common/mech_aes.c	\
					      ${pkcsdir}/common/mech_rsa.c	\
					      ${pkcsdir}/common/mech_ec.c	\
					      ${pkcsdir}/common/obj_mgr.c	\
					      ${pkcsdir}/common/template.c	\
					      ${pkcsdir}/common/p11util.c	\
					      ${pkcsdir}/common/data_obj.c	\
					      ${pkcsdir}/common/encr_mgr.c	\
					      ${pkcsdir}/common/key_mgr.c	\
					      ${pkcsdir}/common/mech_md2.c	\
					      ${pkcsdir}/common/mech_sha.c	\
					      ${pkcsdir}/common/object.c	\
					      ${pkcsdir}/common/decr_mgr.c	\
					      ${pkcsdir}/common/globals.c	\
					      ${pkcsdir}/common/sw_crypt.c	\
					      ${pkcsdir}/common/loadsave.c	\
					      ${pkcsdir}/common/utility.c	\
					      ${pkcsdir}/common/mech_des.c	\
					      ${pkcsdir}/common/mech_des3.c	\
					      ${pkcsdir}/common/mech_md5.c	\
					      ${pkcsdir}/common/mech_ssl3.c	\
					      ${pkcsdir}/common/lock_sess_mgr.c	\
					      ${pkcsdir}/common/verify_mgr.c	\
					      ${pkcsdir}/common/mech_list.c	\
					      ${pkcsdir}/common/shared_memory.c	\
					      ${pkcsdir}/tpm_stdll/tpm_specific.c \
					      ${pkcsdir}/tpm_stdll/tpm_openssl.c \
					      ${pkcsdir}/tpm_stdll/tpm_util.c

else
opencryptoki_stdll_libpkcs11_tpm_la_LDFLAGS = -shared -Wl,-z,defs,-Bsymbolic	\
					      -lcrypto -ltspi -lpthread -litm -lrt \
					      -Wl,--version-script=${top_srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_tpm_la_SOURCES = ${pkcsdir}/common/asn1.c		\
					      ${pkcsdir}/common/btree.c		\
					      ${pkcsdir}/common/dig_mgr.c	\
					      ${pkcsdir}/common/hwf_obj.c	\
					      ${pkcsdir}/common/trace.c		\
					      ${pkcsdir}/common/key.c		\
					      ${pkcsdir}/common/mech_dh.c	\
					      ${pkcsdir}/common/mech_rng.c	\
					      ${pkcsdir}/common/new_host.c	\
					      ${pkcsdir}/common/sign_mgr.c	\
					      ${pkcsdir}/common/cert.c		\
					      ${pkcsdir}/common/dp_obj.c	\
					      ${pkcsdir}/common/mech_aes.c	\
					      ${pkcsdir}/common/mech_rsa.c	\
					      ${pkcsdir}/common/mech_ec.c	\
					      ${pkcsdir}/common/obj_mgr.c	\
					      ${pkcsdir}/common/template.c	\
					      ${pkcsdir}/common/p11util.c	\
					      ${pkcsdir}/common/data_obj.c	\
					      ${pkcsdir}/common/encr_mgr.c	\
					      ${pkcsdir}/common/key_mgr.c	\
					      ${pkcsdir}/common/mech_md2.c	\
					      ${pkcsdir}/common/mech_sha.c	\
					      ${pkcsdir}/common/object.c	\
					      ${pkcsdir}/common/decr_mgr.c	\
					      ${pkcsdir}/common/globals.c	\
					      ${pkcsdir}/common/sw_crypt.c	\
					      ${pkcsdir}/common/loadsave.c	\
					      ${pkcsdir}/common/utility.c	\
					      ${pkcsdir}/common/mech_des.c	\
					      ${pkcsdir}/common/mech_des3.c	\
					      ${pkcsdir}/common/mech_md5.c	\
					      ${pkcsdir}/common/mech_ssl3.c	\
					      ${pkcsdir}/common/sess_mgr.c	\
					      ${pkcsdir}/common/verify_mgr.c	\
					      ${pkcsdir}/common/mech_list.c	\
					      ${pkcsdir}/common/shared_memory.c	\
					      ${pkcsdir}/tpm_stdll/tpm_specific.c \
					      ${pkcsdir}/tpm_stdll/tpm_openssl.c \
					      ${pkcsdir}/tpm_stdll/tpm_util.c

endif

noinst_HEADERS = ${pkcsdir}/tpm_stdll/defs.h		\
		 ${pkcsdir}/tpm_stdll/tpm_specific.h	\
		 ${pkcsdir}/tpm_stdll/tok_struct.h

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
