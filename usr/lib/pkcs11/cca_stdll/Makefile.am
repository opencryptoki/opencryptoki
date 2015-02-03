# Makefile.am for common functions for openCryptoki
# Michael A. Halcrow <mhalcrow@us.ibm.com>

#
# The PKCS#11 STDLL library
#
nobase_lib_LTLIBRARIES=opencryptoki/stdll/libpkcs11_cca.la

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_cca_la_CFLAGS = -DLINUX -DNOCDMF		\
					     -DNODSA -DNODH -DNOECB	\
					     -I. -I../../../include	\
					     -I../../../include/pkcs11	\
					     -I../common		\
					     -DSTDLL_NAME=\"ccatok\"

opencryptoki_stdll_libpkcs11_cca_la_LDFLAGS = -shared -Wl,-Bsymbolic	\
					      -lcrypto -lpthread	\
					      -nostartfiles		\
					      -Wl,-soname,$@		\
					      -lrt

opencryptoki_stdll_libpkcs11_cca_la_SOURCES = ../common/asn1.c		\
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
					      ../common/mech_rsa.c	\
					      ../common/mech_ec.c	\
					      ../common/obj_mgr.c	\
					      ../common/template.c	\
					      ../common/data_obj.c	\
					      ../common/encr_mgr.c	\
					      ../common/key_mgr.c	\
					      ../common/mech_md2.c	\
					      ../common/mech_sha.c	\
					      ../common/object.c	\
					      ../common/decr_mgr.c	\
					      ../common/globals.c	\
					      ../common/loadsave.c	\
					      ../common/utility.c	\
					      ../common/mech_des.c	\
					      ../common/mech_des3.c	\
					      ../common/mech_md5.c	\
					      ../common/mech_ssl3.c	\
					      ../common/sess_mgr.c	\
					      ../common/verify_mgr.c	\
					      ../common/p11util.c	\
					      ../common/sw_crypt.c	\
					      ../common/shared_memory.c	\
					      cca_specific.c

noinst_HEADERS = defs.h		\
		 csulincl.h	\
		 cca_stdll.h

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
