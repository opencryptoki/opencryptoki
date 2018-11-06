nobase_lib_LTLIBRARIES += opencryptoki/stdll/libpkcs11_ica.la

noinst_HEADERS += usr/lib/ica_s390_stdll/tok_struct.h

opencryptoki_stdll_libpkcs11_ica_la_CFLAGS =				\
	-DDEV -D_THREAD_SAFE -fPIC -DSHALLOW=0 -DSWTOK=0 -DLITE=1	\
	-DNODH -DNOCDMF -DNOMD2 -DNODSA -DSTDLL_NAME=\"icatok\"		\
	$(ICA_INC_DIRS) -I${srcdir}/usr/lib/ica_s390_stdll		\
	-I${srcdir}/usr/lib/common -I${srcdir}/usr/include

opencryptoki_stdll_libpkcs11_ica_la_LDFLAGS =				\
	$(LCRYPTO) $(ICA_LIB_DIRS) -nostartfiles -shared		\
	-Wl,-z,defs,-Bsymbolic -Wl,-soname,$@ -lc -lpthread -lica -ldl	\
	-lcrypto -lrt							\
	-Wl,--version-script=${srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_ica_la_SOURCES =				\
	usr/lib/common/asn1.c usr/lib/common/cert.c			\
	usr/lib/common/hwf_obj.c usr/lib/common/dp_obj.c		\
	usr/lib/common/data_obj.c usr/lib/common/decr_mgr.c		\
	usr/lib/common/dig_mgr.c usr/lib/common/encr_mgr.c		\
	usr/lib/common/globals.c usr/lib/common/sw_crypt.c		\
	usr/lib/common/loadsave.c usr/lib/common/key.c			\
	usr/lib/common/key_mgr.c usr/lib/common/mech_des.c		\
	usr/lib/common/mech_des3.c usr/lib/common/mech_aes.c		\
	usr/lib/common/mech_md5.c usr/lib/common/mech_md2.c		\
	usr/lib/common/mech_rng.c usr/lib/common/mech_rsa.c		\
	usr/lib/common/mech_sha.c usr/lib/common/mech_ssl3.c		\
	usr/lib/common/mech_ec.c usr/lib/common/new_host.c		\
	usr/lib/common/obj_mgr.c usr/lib/common/object.c		\
	usr/lib/common/sign_mgr.c usr/lib/common/template.c		\
	usr/lib/common/p11util.c usr/lib/common/utility.c		\
	usr/lib/common/verify_mgr.c usr/lib/common/trace.c		\
	usr/lib/common/mech_list.c usr/lib/common/shared_memory.c	\
	usr/lib/ica_s390_stdll/ica_specific.c
if ENABLE_LOCKS
opencryptoki_stdll_libpkcs11_ica_la_SOURCES +=				\
	usr/lib/common/lock_btree.c usr/lib/common/lock_sess_mgr.c
else
opencryptoki_stdll_libpkcs11_ica_la_LDFLAGS += -litm
opencryptoki_stdll_libpkcs11_ica_la_SOURCES += 				\
	usr/lib/common/btree.c usr/lib/common/sess_mgr.c
endif
