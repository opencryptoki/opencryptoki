# Makefile.am for ICSF token for openCryptoki
#
nobase_lib_LTLIBRARIES=opencryptoki/stdll/libpkcs11_icsf.la

pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

BUILT_SOURCES = ${pkcsdir}/icsf_stdll/icsf_config_parse.h
AM_YFLAGS = -d -v

opencryptoki_stdll_libpkcs11_icsf_la_CFLAGS = -DNOCDMF			\
					      -DNODSA			\
					      -DNODH			\
					      -DMMAP			\
					      -I${pkcsdir}/icsf_stdll	\
					      -I${pkcsdir}/common	\
					      -I${incdir}		\
					      -I${incdir}/pkcs11	\
					      -DSTDLL_NAME=\"icsftok\"

if ENABLE_LOCKS
opencryptoki_stdll_libpkcs11_icsf_la_LDFLAGS = -shared			\
					       -Wl,-z,defs,-Bsymbolic	\
					       -lcrypto			\
					       -lldap			\
					       -lpthread		\
					       -lrt			\
					       -llber			\
					       -Wl,--version-script=${top_srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_icsf_la_SOURCES = ${pkcsdir}/common/asn1.c		\
					       ${pkcsdir}/common/lock_btree.c	\
					       ${pkcsdir}/common/dig_mgr.c	\
					       ${pkcsdir}/common/hwf_obj.c	\
					       ${pkcsdir}/common/trace.c	\
					       ${pkcsdir}/common/key.c		\
					       ${pkcsdir}/common/mech_dh.c	\
					       ${pkcsdir}/common/mech_rng.c	\
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
					       ${pkcsdir}/common/lock_sess_mgr.c\
					       ${pkcsdir}/common/verify_mgr.c	\
					       ${pkcsdir}/common/mech_list.c	\
					       ${pkcsdir}/common/shared_memory.c\
					       ${pkcsdir}/common/attributes.c	\
					       ${pkcsdir}/icsf_stdll/new_host.c	\
					       ${pkcsdir}/icsf_stdll/pbkdf.c	\
					       ${pkcsdir}/icsf_stdll/icsf_specific.c \
					       ${pkcsdir}/icsf_stdll/icsf_config_parse.y \
					       ${pkcsdir}/icsf_stdll/icsf_config_lexer.l \
					       ${pkcsdir}/icsf_stdll/icsf.c
else
opencryptoki_stdll_libpkcs11_icsf_la_LDFLAGS = -shared			\
					       -Wl,-z,defs,-Bsymbolic	\
					       -lcrypto			\
					       -lldap			\
					       -lpthread		\
					       -litm			\
					       -lrt			\
					       -llber			\
					       -Wl,--version-script=${top_srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_icsf_la_SOURCES = ${pkcsdir}/common/asn1.c		\
					       ${pkcsdir}/common/btree.c	\
					       ${pkcsdir}/common/dig_mgr.c	\
					       ${pkcsdir}/common/hwf_obj.c	\
					       ${pkcsdir}/common/trace.c	\
					       ${pkcsdir}/common/key.c		\
					       ${pkcsdir}/common/mech_dh.c	\
					       ${pkcsdir}/common/mech_rng.c	\
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
					       ${pkcsdir}/common/shared_memory.c\
					       ${pkcsdir}/common/attributes.c	\
					       ${pkcsdir}/icsf_stdll/new_host.c	\
					       ${pkcsdir}/icsf_stdll/pbkdf.c	\
					       ${pkcsdir}/icsf_stdll/icsf_specific.c \
					       ${pkcsdir}/icsf_stdll/icsf_config_parse.y \
					       ${pkcsdir}/icsf_stdll/icsf_config_lexer.l \
					       ${pkcsdir}/icsf_stdll/icsf.c
endif

noinst_HEADERS = ${pkcsdir}/icsf_stdll/icsf.h		\
		 ${pkcsdir}/icsf_stdll/pbkdf.h		\
		 ${pkcsdir}/icsf_stdll/icsf_config.h	\
		 ${pkcsdir}/icsf_stdll/icsf_specific.h	\
		 ${pkcsdir}/icsf_stdll/tok_struct.h

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_icsf.so PKCS11_ICSF.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/icsf
	$(MKDIR_P) $(DESTDIR)$(lockdir)/icsf
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/icsf 
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/icsf

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -rf PKCS11_ICSF.so; fi
