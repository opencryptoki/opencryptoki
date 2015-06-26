# Makefile.am for ICSF token for openCryptoki
#
nobase_lib_LTLIBRARIES=opencryptoki/stdll/libpkcs11_icsf.la

AUTOMAKE_OPTIONS = gnu

BUILT_SOURCES = icsf_config_parse.h
AM_YFLAGS = -d -v

# TODO: check which defines are really needed here
# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_icsf_la_CFLAGS = -DNOCDMF			\
					      -DNODSA			\
					      -DNODH			\
					      -DMMAP			\
					      -I.			\
					      -I../../../include	\
					      -I../../../include/pkcs11	\
					      -I../common		\
					      -DSTDLL_NAME=\"icsftok\"

opencryptoki_stdll_libpkcs11_icsf_la_LDFLAGS = -shared			\
					       -Wl,-Bsymbolic		\
					       -lcrypto			\
					       -lldap			\
					       -lpthread		\
					       -lrt			\
					       -llber

opencryptoki_stdll_libpkcs11_icsf_la_SOURCES = ../common/asn1.c		\
					       ../common/btree.c	\
					       ../common/dig_mgr.c	\
					       ../common/hwf_obj.c	\
					       ../common/trace.c	\
					       ../common/key.c		\
					       ../common/mech_dh.c	\
					       ../common/mech_rng.c	\
					       new_host.c		\
					       ../common/sign_mgr.c	\
					       ../common/cert.c		\
					       ../common/dp_obj.c	\
					       ../common/mech_aes.c	\
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
					       ../common/shared_memory.c\
					       ../common/attributes.c	\
					       pbkdf.c			\
					       icsf_specific.c		\
					       icsf_config_parse.y	\
					       icsf_config_lexer.l	\
					       icsf.c


noinst_HEADERS = icsf.h pbkdf.h

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
