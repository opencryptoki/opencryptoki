nobase_lib_LTLIBRARIES += opencryptoki/stdll/libpkcs11_ica.la

noinst_HEADERS += usr/lib/ica_s390_stdll/tok_struct.h

opencryptoki_stdll_libpkcs11_ica_la_CFLAGS =				\
	-DDEV -D_THREAD_SAFE -fPIC -DSHALLOW=0 -DSWTOK=0 -DLITE=1	\
	-DNODH -DNOMD2 -DNODSA -DSTDLL_NAME=\"icatok\"			\
	-DTOK_NEW_DATA_STORE=0x0003000c					\
	$(ICA_INC_DIRS) -I${srcdir}/usr/lib/ica_s390_stdll		\
	-I${srcdir}/usr/lib/common -I${srcdir}/usr/include		\
	-I${top_builddir}/usr/lib/api -I${srcdir}/usr/lib/api

opencryptoki_stdll_libpkcs11_ica_la_LDFLAGS =				\
	$(LCRYPTO) $(ICA_LIB_DIRS) -nostartfiles -shared		\
	-Wl,-z,defs,-Bsymbolic -Wl,-soname,$@ -lc -lpthread -lica -ldl	\
	-lcrypto -lrt -llber						\
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
	usr/lib/common/profile_obj.c usr/lib/common/attributes.c	\
	usr/lib/ica_s390_stdll/ica_specific.c usr/lib/common/dlist.c	\
	usr/lib/common/mech_openssl.c usr/lib/common/mech_pqc.c		\
	usr/lib/common/utility_common.c usr/lib/common/ec_supported.c	\
	usr/lib/api/policyhelper.c usr/lib/common/pqc_supported.c	\
	usr/lib/common/btree.c usr/lib/common/sess_mgr.c

if !HAVE_ALT_FIX_FOR_CVE_2022_4304
opencryptoki_stdll_libpkcs11_ica_la_SOURCES +=				\
	usr/lib/ica_s390_stdll/rsa_sup_mul.c
endif
