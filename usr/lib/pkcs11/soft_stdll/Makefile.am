nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_sw.la

opencryptoki_stdll_libpkcs11_sw_la_LDFLAGS = -shared -Wl,-Bsymbolic	\
					     -lc -lpthread -lcrypto -lrt

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_sw_la_CFLAGS = -DDEV -D_THREAD_SAFE            \
					    -DSHALLOW=0 -DSWTOK=1 -DLITE=0  \
					    -DNOCDMF -DNOMD2 -DNODSA -DNORIPE	    \
					    -fPIC		    \
					    -I/usr/include -I.		    \
					    -I../../../include/pkcs11/stdll \
					    -I../../../include/pkcs11	    \
					    -I../common -DSTDLL_NAME=\"swtok\"

opencryptoki_stdll_libpkcs11_sw_la_SOURCES = ../common/asn1.c		\
					     ../common/btree.c		\
					     ../common/cert.c		\
					     ../common/hwf_obj.c	\
					     ../common/dp_obj.c		\
					     ../common/data_obj.c	\
					     ../common/decr_mgr.c	\
					     ../common/dig_mgr.c	\
					     ../common/encr_mgr.c	\
					     ../common/globals.c	\
					     ../common/sw_crypt.c	\
					     ../common/loadsave.c	\
					     ../common/key.c		\
					     ../common/key_mgr.c	\
					     ../common/mech_aes.c	\
					     ../common/mech_des.c	\
					     ../common/mech_des3.c	\
					     ../common/mech_dh.c	\
					     ../common/mech_md5.c	\
					     ../common/mech_md2.c	\
					     ../common/mech_rng.c	\
					     ../common/mech_rsa.c	\
					     ../common/mech_sha.c	\
					     ../common/mech_ssl3.c	\
					     ../common/mech_ec.c	\
					     ../common/new_host.c	\
					     ../common/obj_mgr.c	\
					     ../common/object.c		\
					     ../common/sess_mgr.c	\
					     ../common/sign_mgr.c	\
					     ../common/template.c	\
					     ../common/p11util.c	\
					     ../common/utility.c	\
					     ../common/verify_mgr.c	\
					     ../common/trace.c		\
					     ../common/mech_list.c      \
					     ../common/shared_memory.c	\
					     soft_specific.c

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
