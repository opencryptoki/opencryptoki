nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_sw.la

pkcsdir=${top_srcdir}/usr/lib/pkcs11
incdir=${top_srcdir}/usr/include

opencryptoki_stdll_libpkcs11_sw_la_CFLAGS = -DDEV -D_THREAD_SAFE		\
					    -DSHALLOW=0 -DSWTOK=1 -DLITE=0	\
					    -DNOCDMF -DNOMD2 -DNODSA -DNORIPE	\
					    -fPIC				\
					    -I${pkcsdir}/soft_stdll		\
					    -I${pkcsdir}/common			\
					    -I${incdir}/pkcs11			\
					    -DSTDLL_NAME=\"swtok\"

if ENABLE_LOCKS
opencryptoki_stdll_libpkcs11_sw_la_LDFLAGS = -shared -Wl,-z,defs,-Bsymbolic	\
					     -lc -lpthread -lcrypto -lrt	\
					     -Wl,--version-script=${top_srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_sw_la_SOURCES = ${pkcsdir}/common/asn1.c		\
					     ${pkcsdir}/common/lock_btree.c	\
					     ${pkcsdir}/common/cert.c		\
					     ${pkcsdir}/common/hwf_obj.c	\
					     ${pkcsdir}/common/dp_obj.c		\
					     ${pkcsdir}/common/data_obj.c	\
					     ${pkcsdir}/common/decr_mgr.c	\
					     ${pkcsdir}/common/dig_mgr.c	\
					     ${pkcsdir}/common/encr_mgr.c	\
					     ${pkcsdir}/common/globals.c	\
					     ${pkcsdir}/common/sw_crypt.c	\
					     ${pkcsdir}/common/loadsave.c	\
					     ${pkcsdir}/common/key.c		\
					     ${pkcsdir}/common/key_mgr.c	\
					     ${pkcsdir}/common/mech_aes.c	\
					     ${pkcsdir}/common/mech_des.c	\
					     ${pkcsdir}/common/mech_des3.c	\
					     ${pkcsdir}/common/mech_dh.c	\
					     ${pkcsdir}/common/mech_md5.c	\
					     ${pkcsdir}/common/mech_md2.c	\
					     ${pkcsdir}/common/mech_rng.c	\
					     ${pkcsdir}/common/mech_rsa.c	\
					     ${pkcsdir}/common/mech_sha.c	\
					     ${pkcsdir}/common/mech_ssl3.c	\
					     ${pkcsdir}/common/mech_ec.c	\
					     ${pkcsdir}/common/new_host.c	\
					     ${pkcsdir}/common/obj_mgr.c	\
					     ${pkcsdir}/common/object.c		\
					     ${pkcsdir}/common/lock_sess_mgr.c	\
					     ${pkcsdir}/common/sign_mgr.c	\
					     ${pkcsdir}/common/template.c	\
					     ${pkcsdir}/common/p11util.c	\
					     ${pkcsdir}/common/utility.c	\
					     ${pkcsdir}/common/verify_mgr.c	\
					     ${pkcsdir}/common/trace.c		\
					     ${pkcsdir}/common/mech_list.c      \
					     ${pkcsdir}/common/shared_memory.c	\
					     ${pkcsdir}/soft_stdll/soft_specific.c
else
opencryptoki_stdll_libpkcs11_sw_la_LDFLAGS = -shared -Wl,-z,defs,-Bsymbolic	\
					     -lc -lpthread -litm -lcrypto -lrt	\
					     -Wl,--version-script=${top_srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_sw_la_SOURCES = ${pkcsdir}/common/asn1.c		\
					     ${pkcsdir}/common/btree.c		\
					     ${pkcsdir}/common/cert.c		\
					     ${pkcsdir}/common/hwf_obj.c	\
					     ${pkcsdir}/common/dp_obj.c		\
					     ${pkcsdir}/common/data_obj.c	\
					     ${pkcsdir}/common/decr_mgr.c	\
					     ${pkcsdir}/common/dig_mgr.c	\
					     ${pkcsdir}/common/encr_mgr.c	\
					     ${pkcsdir}/common/globals.c	\
					     ${pkcsdir}/common/sw_crypt.c	\
					     ${pkcsdir}/common/loadsave.c	\
					     ${pkcsdir}/common/key.c		\
					     ${pkcsdir}/common/key_mgr.c	\
					     ${pkcsdir}/common/mech_aes.c	\
					     ${pkcsdir}/common/mech_des.c	\
					     ${pkcsdir}/common/mech_des3.c	\
					     ${pkcsdir}/common/mech_dh.c	\
					     ${pkcsdir}/common/mech_md5.c	\
					     ${pkcsdir}/common/mech_md2.c	\
					     ${pkcsdir}/common/mech_rng.c	\
					     ${pkcsdir}/common/mech_rsa.c	\
					     ${pkcsdir}/common/mech_sha.c	\
					     ${pkcsdir}/common/mech_ssl3.c	\
					     ${pkcsdir}/common/mech_ec.c	\
					     ${pkcsdir}/common/new_host.c	\
					     ${pkcsdir}/common/obj_mgr.c	\
					     ${pkcsdir}/common/object.c		\
					     ${pkcsdir}/common/sess_mgr.c	\
					     ${pkcsdir}/common/sign_mgr.c	\
					     ${pkcsdir}/common/template.c	\
					     ${pkcsdir}/common/p11util.c	\
					     ${pkcsdir}/common/utility.c	\
					     ${pkcsdir}/common/verify_mgr.c	\
					     ${pkcsdir}/common/trace.c		\
					     ${pkcsdir}/common/mech_list.c      \
					     ${pkcsdir}/common/shared_memory.c	\
					     ${pkcsdir}/soft_stdll/soft_specific.c
endif

noinst_HEADERS = ${pkcsdir}/soft_stdll/tok_struct.h

install-data-hook:
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_sw.so PKCS11_SW.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/swtok
	$(MKDIR_P) $(DESTDIR)$(lockdir)/swtok
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/swtok
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/swtok

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_SW.so; fi
