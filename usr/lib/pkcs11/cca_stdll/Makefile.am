# Makefile.am for common functions for openCryptoki
# Michael A. Halcrow <mhalcrow@us.ibm.com>

#
# The PKCS#11 STDLL library
#
nobase_lib_LTLIBRARIES=opencryptoki/stdll/libpkcs11_cca.la

pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

opencryptoki_stdll_libpkcs11_cca_la_CFLAGS = -DLINUX -DNOCDMF		\
					     -DNODSA -DNODH -DNOECB	\
					     -I${pkcsdir}/cca_stdll	\
					     -I${pkcsdir}/common	\
					     -I${incdir}		\
					     -I${incdir}/pkcs11		\
					     -DSTDLL_NAME=\"ccatok\"

if ENABLE_LOCKS
opencryptoki_stdll_libpkcs11_cca_la_LDFLAGS = -shared -Wl,-z,defs,-Bsymbolic	\
					      -lcrypto -lpthread	\
					      -nostartfiles		\
					      -Wl,-soname,$@		\
					      -lrt -ldl			\
					      -Wl,--version-script=${top_srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_cca_la_SOURCES = ${pkcsdir}/common/asn1.c		\
					      ${pkcsdir}/common/lock_btree.c	\
					      ${pkcsdir}/common/dig_mgr.c	\
					      ${pkcsdir}/common/hwf_obj.c	\
					      ${pkcsdir}/common/trace.c		\
					      ${pkcsdir}/common/key.c		\
					      ${pkcsdir}/common/mech_list.c	\
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
					      ${pkcsdir}/common/data_obj.c	\
					      ${pkcsdir}/common/encr_mgr.c	\
					      ${pkcsdir}/common/key_mgr.c	\
					      ${pkcsdir}/common/mech_md2.c	\
					      ${pkcsdir}/common/mech_sha.c	\
					      ${pkcsdir}/common/object.c	\
					      ${pkcsdir}/common/decr_mgr.c	\
					      ${pkcsdir}/common/globals.c	\
					      ${pkcsdir}/common/loadsave.c	\
					      ${pkcsdir}/common/utility.c	\
					      ${pkcsdir}/common/mech_des.c	\
					      ${pkcsdir}/common/mech_des3.c	\
					      ${pkcsdir}/common/mech_md5.c	\
					      ${pkcsdir}/common/mech_ssl3.c	\
					      ${pkcsdir}/common/lock_sess_mgr.c	\
					      ${pkcsdir}/common/verify_mgr.c	\
					      ${pkcsdir}/common/p11util.c	\
					      ${pkcsdir}/common/sw_crypt.c	\
					      ${pkcsdir}/common/shared_memory.c	\
					      ${pkcsdir}/cca_stdll/cca_specific.c
else
opencryptoki_stdll_libpkcs11_cca_la_LDFLAGS = -shared -Wl,-z,defs,-Bsymbolic	\
					      -lcrypto -lpthread -litm \
					      -nostartfiles		\
					      -Wl,-soname,$@		\
					      -lrt -ldl			\
					      -Wl,--version-script=${top_srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_cca_la_SOURCES = ${pkcsdir}/common/asn1.c		\
					      ${pkcsdir}/common/btree.c		\
					      ${pkcsdir}/common/dig_mgr.c	\
					      ${pkcsdir}/common/hwf_obj.c	\
					      ${pkcsdir}/common/trace.c		\
					      ${pkcsdir}/common/key.c		\
					      ${pkcsdir}/common/mech_list.c	\
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
					      ${pkcsdir}/common/data_obj.c	\
					      ${pkcsdir}/common/encr_mgr.c	\
					      ${pkcsdir}/common/key_mgr.c	\
					      ${pkcsdir}/common/mech_md2.c	\
					      ${pkcsdir}/common/mech_sha.c	\
					      ${pkcsdir}/common/object.c	\
					      ${pkcsdir}/common/decr_mgr.c	\
					      ${pkcsdir}/common/globals.c	\
					      ${pkcsdir}/common/loadsave.c	\
					      ${pkcsdir}/common/utility.c	\
					      ${pkcsdir}/common/mech_des.c	\
					      ${pkcsdir}/common/mech_des3.c	\
					      ${pkcsdir}/common/mech_md5.c	\
					      ${pkcsdir}/common/mech_ssl3.c	\
					      ${pkcsdir}/common/sess_mgr.c	\
					      ${pkcsdir}/common/verify_mgr.c	\
					      ${pkcsdir}/common/p11util.c	\
					      ${pkcsdir}/common/sw_crypt.c	\
					      ${pkcsdir}/common/shared_memory.c	\
					      ${pkcsdir}/cca_stdll/cca_specific.c
endif

noinst_HEADERS = ${pkcsdir}/cca_stdll/defs.h		\
		 ${pkcsdir}/cca_stdll/csulincl.h	\
		 ${pkcsdir}/cca_stdll/cca_stdll.h	\
		 ${pkcsdir}/cca_stdll/cca_func.h	\
		 ${pkcsdir}/cca_stdll/tok_struct.h

install-data-hook:
	cd $(DESTDIR)/$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_cca.so PKCS11_CCA.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ccatok
	$(MKDIR_P) $(DESTDIR)$(lockdir)/ccatok
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/ccatok
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/ccatok

uninstall-hook:
	if test -d $(DESTDIR)/$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)/$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_CCA.so; fi
