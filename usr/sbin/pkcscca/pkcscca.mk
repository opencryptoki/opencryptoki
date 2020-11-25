sbin_PROGRAMS += usr/sbin/pkcscca/pkcscca
noinst_HEADERS += usr/sbin/pkcscca/pkcscca.h
noinst_HEADERS += usr/lib/common/defs.h
noinst_HEADERS += usr/lib/common/host_defs.h
noinst_HEADERS += usr/include/local_types.h
noinst_HEADERS += usr/lib/common/h_extern.h
noinst_HEADERS += usr/lib/common/pkcs_utils.h

usr_sbin_pkcscca_pkcscca_LDFLAGS = -lcrypto -ldl -lrt

usr_sbin_pkcscca_pkcscca_CFLAGS  =					\
	-DSTDLL_NAME=\"pkcscca\"					\
	-DTOK_NEW_DATA_STORE=0x0003000c					\
	-DNOCDMF -DNODSA -DNODH						\
	-DOCK_NO_SET_PERM -DOCK_NO_LOCAL_RNG				\
	-I${srcdir}/usr/include 					\
	-I${srcdir}/usr/lib/common					\
	-I${srcdir}/usr/sbin/pkcscca

usr_sbin_pkcscca_pkcscca_SOURCES =					\
	usr/lib/common/asn1.c usr/lib/common/dig_mgr.c			\
	usr/lib/common/hwf_obj.c usr/lib/common/trace.c			\
	usr/lib/common/key.c usr/lib/common/mech_list.c			\
	usr/lib/common/mech_dh.c usr/lib/common/sign_mgr.c		\
	usr/lib/common/cert.c usr/lib/common/dp_obj.c			\
	usr/lib/common/mech_aes.c usr/lib/common/mech_rsa.c		\
	usr/lib/common/mech_ec.c usr/lib/common/obj_mgr.c		\
	usr/lib/common/template.c usr/lib/common/data_obj.c		\
	usr/lib/common/encr_mgr.c usr/lib/common/key_mgr.c		\
	usr/lib/common/mech_md2.c usr/lib/common/mech_sha.c		\
	usr/lib/common/object.c	usr/lib/common/decr_mgr.c		\
	usr/lib/common/globals.c usr/lib/common/loadsave.c		\
	usr/lib/common/utility.c usr/lib/common/mech_des.c		\
	usr/lib/common/mech_des3.c usr/lib/common/mech_md5.c		\
	usr/lib/common/mech_ssl3.c usr/lib/common/verify_mgr.c		\
	usr/lib/common/p11util.c usr/lib/common/sw_crypt.c		\
	usr/lib/common/shared_memory.c usr/lib/common/profile_obj.c	\
	usr/lib/common/attributes.c usr/lib/common/mech_rng.c		\
	usr/lib/common/pkcs_utils.c 					\
	usr/sbin/pkcscca/pkcscca.c
	
	
if ENABLE_LOCKS
usr_sbin_pkcscca_pkcscca_SOURCES +=				\
	usr/lib/common/lock_btree.c usr/lib/common/lock_sess_mgr.c
usr_sbin_pkcscca_pkcscca_LDFLAGS += -lpthread
else
usr_sbin_pkcscca_pkcscca_SOURCES +=				\
	usr/lib/common/btree.c usr/lib/common/sess_mgr.c
usr_sbin_pkcscca_pkcscca_LDFLAGS += -litm
endif
