# Makefile.am for EP11 token for openCryptoki
#
nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_ep11.la

pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

opencryptoki_stdll_libpkcs11_ep11_la_CFLAGS = -DDEV -D_THREAD_SAFE		\
					    -DSHALLOW=0 -DEPSWTOK=1 -DLITE=0	\
					    -DNOCDMF -DNOMD2 -DNORIPE		\
					    -fPIC -DDEFENSIVE_MECHLIST		\
					    -I${pkcsdir}/ep11_stdll		\
					    -I${pkcsdir}/common			\
					    -I${incdir}				\
					    -I${incdir}/pkcs11			\
					    -DSTDLL_NAME=\"ep11tok\"

if ENABLE_LOCKS
opencryptoki_stdll_libpkcs11_ep11_la_LDFLAGS = -shared -Wl,-z,defs,-Bsymbolic	\
					     -lc -lpthread -lcrypto -lrt -llber	\
					     -ldl				\
					     -Wl,--version-script=${top_srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_ep11_la_SOURCES = ${pkcsdir}/common/asn1.c		\
					       ${pkcsdir}/common/lock_btree.c	\
					       ${pkcsdir}/common/cert.c		\
					       ${pkcsdir}/common/hwf_obj.c	\
					       ${pkcsdir}/common/dp_obj.c	\
					       ${pkcsdir}/common/data_obj.c	\
					       ${pkcsdir}/common/dig_mgr.c	\
					       ${pkcsdir}/common/encr_mgr.c	\
					       ${pkcsdir}/common/decr_mgr.c	\
					       ${pkcsdir}/common/globals.c	\
					       ${pkcsdir}/common/loadsave.c	\
					       ${pkcsdir}/common/mech_aes.c	\
					       ${pkcsdir}/common/mech_des.c	\
					       ${pkcsdir}/common/mech_des3.c	\
					       ${pkcsdir}/common/mech_ec.c	\
					       ${pkcsdir}/common/mech_md5.c	\
					       ${pkcsdir}/common/mech_md2.c	\
					       ${pkcsdir}/common/mech_rng.c	\
					       ${pkcsdir}/common/mech_rsa.c	\
					       ${pkcsdir}/common/mech_sha.c	\
					       ${pkcsdir}/common/mech_dsa.c	\
					       ${pkcsdir}/common/mech_dh.c	\
					       ${pkcsdir}/common/mech_ssl3.c	\
					       ${pkcsdir}/common/obj_mgr.c	\
					       ${pkcsdir}/common/object.c	\
					       ${pkcsdir}/common/lock_sess_mgr.c\
					       ${pkcsdir}/common/sign_mgr.c	\
					       ${pkcsdir}/common/verify_mgr.c	\
					       ${pkcsdir}/common/key.c		\
					       ${pkcsdir}/common/key_mgr.c	\
					       ${pkcsdir}/common/template.c	\
					       ${pkcsdir}/common/p11util.c	\
					       ${pkcsdir}/common/utility.c	\
					       ${pkcsdir}/common/trace.c	\
					       ${pkcsdir}/common/mech_list.c	\
					       ${pkcsdir}/common/shared_memory.c\
					       ${pkcsdir}/common/attributes.c	\
					       ${pkcsdir}/common/sw_crypt.c	\
					       ${pkcsdir}/ep11_stdll/new_host.c	\
					       ${pkcsdir}/ep11_stdll/ep11_specific.c

else
opencryptoki_stdll_libpkcs11_ep11_la_LDFLAGS = -shared -Wl,-z,defs,-Bsymbolic	\
					     -lc -lpthread -litm -lcrypto -lrt	\
					     -llber -ldl			\
					     -Wl,--version-script=${top_srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_ep11_la_SOURCES = ${pkcsdir}/common/asn1.c		\
					       ${pkcsdir}/common/btree.c	\
					       ${pkcsdir}/common/cert.c		\
					       ${pkcsdir}/common/hwf_obj.c	\
					       ${pkcsdir}/common/dp_obj.c	\
					       ${pkcsdir}/common/data_obj.c	\
					       ${pkcsdir}/common/dig_mgr.c	\
					       ${pkcsdir}/common/encr_mgr.c	\
					       ${pkcsdir}/common/decr_mgr.c	\
					       ${pkcsdir}/common/globals.c	\
					       ${pkcsdir}/common/loadsave.c	\
					       ${pkcsdir}/common/mech_aes.c	\
					       ${pkcsdir}/common/mech_des.c	\
					       ${pkcsdir}/common/mech_des3.c	\
					       ${pkcsdir}/common/mech_ec.c	\
					       ${pkcsdir}/common/mech_md5.c	\
					       ${pkcsdir}/common/mech_md2.c	\
					       ${pkcsdir}/common/mech_rng.c	\
					       ${pkcsdir}/common/mech_rsa.c	\
					       ${pkcsdir}/common/mech_sha.c	\
					       ${pkcsdir}/common/mech_dsa.c	\
					       ${pkcsdir}/common/mech_dh.c	\
					       ${pkcsdir}/common/mech_ssl3.c	\
					       ${pkcsdir}/common/obj_mgr.c	\
					       ${pkcsdir}/common/object.c	\
					       ${pkcsdir}/common/sess_mgr.c	\
					       ${pkcsdir}/common/sign_mgr.c	\
					       ${pkcsdir}/common/verify_mgr.c	\
					       ${pkcsdir}/common/key.c		\
					       ${pkcsdir}/common/key_mgr.c	\
					       ${pkcsdir}/common/template.c	\
					       ${pkcsdir}/common/p11util.c	\
					       ${pkcsdir}/common/utility.c	\
					       ${pkcsdir}/common/trace.c	\
					       ${pkcsdir}/common/mech_list.c	\
					       ${pkcsdir}/common/shared_memory.c\
					       ${pkcsdir}/common/attributes.c	\
					       ${pkcsdir}/common/sw_crypt.c	\
					       ${pkcsdir}/ep11_stdll/new_host.c	\
					       ${pkcsdir}/ep11_stdll/ep11_specific.c
endif

noinst_HEADERS = ${pkcsdir}/ep11_stdll/ep11.h		\
		 ${pkcsdir}/ep11_stdll/ep11_func.h	\
		 ${pkcsdir}/ep11_stdll/ep11_specific.h	\
		 ${pkcsdir}/ep11_stdll/tok_struct.h

install-data-hook:
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_ep11.so PKCS11_EP11.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/ep11tok
	$(MKDIR_P) $(DESTDIR)$(lockdir)/ep11tok
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/ep11tok
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/ep11tok

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_EP11.so; fi

install-data-local :
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki || $(MKDIR_P) $(DESTDIR)$(sysconfdir)/opencryptoki || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/ep11tok.conf || $(INSTALL) -m 644 $(srcdir)/ep11tok.conf $(DESTDIR)$(sysconfdir)/opencryptoki/ep11tok.conf || true
	test -f $(DESTDIR)$(sysconfdir)/opencryptoki/ep11cpfilter.conf || $(INSTALL) -m 644 $(srcdir)/ep11cpfilter.conf $(DESTDIR)$(sysconfdir)/opencryptoki/ep11cpfilter.conf || true
