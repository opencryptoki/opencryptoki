nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_ica.la

opencryptoki_stdll_libpkcs11_ica_la_LDFLAGS = $(LCRYPTO)		\
					     $(ICA_LIB_DIRS)		\
					     -nostartfiles -shared	\
					     -Wl,-Bsymbolic		\
					     -Wl,-soname,$@		\
					     -Wl,-Bsymbolic -lc		\
					     -lpthread -lica -ldl	\
					     -lcrypto

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_ica_la_CFLAGS = -DDEV			\
					     -D_THREAD_SAFE -fPIC	\
					     -DSHALLOW=0 -DSWTOK=0	\
					     -DLITE=1 -DNODH		\
					     -DNOCDMF -DNOMD2 -DNODSA	\
					     -DSTDLL_NAME=\"icatok\"	\
					     -lrt

opencryptoki_stdll_libpkcs11_ica_la_SOURCES = ../common/asn1.c		\
					      ../common/btree.c		\
					      ../common/cert.c		\
					      ../common/hwf_obj.c	\
					      ../common/dp_obj.c	\
					      ../common/data_obj.c	\
					      ../common/decr_mgr.c	\
					      ../common/dig_mgr.c	\
					      ../common/encr_mgr.c	\
					      ../common/globals.c	\
					      ../common/sw_crypt.c	\
					      ../common/loadsave.c	\
					      ../common/key.c		\
					      ../common/key_mgr.c	\
					      ../common/mech_des.c	\
					      ../common/mech_des3.c	\
					      ../common/mech_aes.c	\
					      ../common/mech_md5.c	\
					      ../common/mech_md2.c	\
					      ../common/mech_rng.c	\
					      ../common/mech_rsa.c	\
					      ../common/mech_sha.c	\
					      ../common/mech_ssl3.c	\
					      ../common/mech_ec.c	\
					      ../common/new_host.c	\
					      ../common/obj_mgr.c	\
					      ../common/object.c	\
					      ../common/sess_mgr.c	\
					      ../common/sign_mgr.c	\
					      ../common/template.c	\
					      ../common/p11util.c	\
					      ../common/utility.c	\
					      ../common/verify_mgr.c	\
					      ../common/trace.c		\
					      ../common/mech_list.c	\
					      ../common/shared_memory.c	\
					      ica_specific.c

INCLUDES = $(ICA_INC_DIRS) -I. -I../../../include/pkcs11/stdll		\
	   -I../../../include/pkcs11 -I../common -I../../../ica/inc	\
	   -I../../../../ica/include -I.. -I../../../../ica/src/inc

install-data-hook:
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_ica.so PKCS11_ICA.so
	$(MKDIR_P) $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite/TOK_OBJ
	$(CHGRP) pkcs11 $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite/TOK_OBJ
	$(CHMOD) 0770 $(DESTDIR)$(localstatedir)/lib/opencryptoki/lite
	$(MKDIR_P) $(DESTDIR)$(lockdir)/lite
	$(CHGRP) pkcs11 $(DESTDIR)$(lockdir)/lite
	$(CHMOD) 0770 $(DESTDIR)$(lockdir)/lite

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_ICA.so; fi
