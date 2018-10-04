nobase_lib_LTLIBRARIES += opencryptoki/stdll/libpkcs11_ep11.la

noinst_HEADERS +=							\
	%D%/ep11.h %D%/ep11_func.h %D%/ep11_specific.h %D%/tok_struct.h

opencryptoki_stdll_libpkcs11_ep11_la_CFLAGS =				\
	-DDEV -D_THREAD_SAFE -DSHALLOW=0 -DEPSWTOK=1 -DLITE=0 -DNOCDMF	\
	-DNOMD2	-DNORIPE -fPIC -DDEFENSIVE_MECHLIST			\
	-DSTDLL_NAME=\"ep11tok\"					\
	-I${srcdir}/%D% -I${srcdir}/usr/lib/common			\
	-I${srcdir}/usr/include

opencryptoki_stdll_libpkcs11_ep11_la_LDFLAGS =				\
	-shared -Wl,-z,defs,-Bsymbolic -lc -lpthread -lcrypto -lrt	\
	-llber -ldl -Wl,--version-script=${srcdir}/opencryptoki_tok.map

opencryptoki_stdll_libpkcs11_ep11_la_SOURCES =				\
	usr/lib/common/asn1.c usr/lib/common/cert.c			\
	usr/lib/common/hwf_obj.c usr/lib/common/dp_obj.c		\
	usr/lib/common/data_obj.c usr/lib/common/dig_mgr.c		\
	usr/lib/common/encr_mgr.c usr/lib/common/decr_mgr.c		\
	usr/lib/common/globals.c usr/lib/common/loadsave.c		\
	usr/lib/common/mech_aes.c usr/lib/common/mech_des.c		\
	usr/lib/common/mech_des3.c usr/lib/common/mech_ec.c		\
	usr/lib/common/mech_md5.c usr/lib/common/mech_md2.c		\
	usr/lib/common/mech_rng.c usr/lib/common/mech_rsa.c		\
	usr/lib/common/mech_sha.c usr/lib/common/mech_dsa.c		\
	usr/lib/common/mech_dh.c usr/lib/common/mech_ssl3.c		\
	usr/lib/common/obj_mgr.c usr/lib/common/object.c		\
	usr/lib/common/sign_mgr.c usr/lib/common/verify_mgr.c		\
	usr/lib/common/key.c usr/lib/common/key_mgr.c			\
	usr/lib/common/template.c usr/lib/common/p11util.c		\
	usr/lib/common/utility.c usr/lib/common/trace.c			\
	usr/lib/common/mech_list.c usr/lib/common/shared_memory.c	\
	usr/lib/common/attributes.c usr/lib/common/sw_crypt.c		\
	usr/lib/ep11_stdll/new_host.c %D%/ep11_specific.c
if ENABLE_LOCKS
opencryptoki_stdll_libpkcs11_ep11_la_SOURCES +=				\
	usr/lib/common/lock_btree.c usr/lib/common/lock_sess_mgr.c
else
opencryptoki_stdll_libpkcs11_ep11_la_LDFLAGS += -litm
opencryptoki_stdll_libpkcs11_ep11_la_SOURCES +=				\
	usr/lib/common/btree.c usr/lib/common/sess_mgr.c
endif
