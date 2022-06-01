sbin_PROGRAMS += usr/sbin/pkcshsm_mk_change/pkcshsm_mk_change

usr_sbin_pkcshsm_mk_change_pkcshsm_mk_change_LDFLAGS = -lcrypto -ldl -lrt

usr_sbin_pkcshsm_mk_change_pkcshsm_mk_change_CFLAGS  =	\
	-DOCK_TOOL					\
	-DSTDLL_NAME=\"pkcshsm_mk_change\"		\
	-I${srcdir}/usr/include				\
	-I${srcdir}/usr/lib/common			\
	-I${srcdir}/usr/lib/api				\
	-I${top_builddir}/usr/lib/api			\
	-I${srcdir}/usr/lib/hsm_mk_change

usr_sbin_pkcshsm_mk_change_pkcshsm_mk_change_SOURCES =	\
	usr/sbin/pkcshsm_mk_change/pkcshsm_mk_change.c	\
	usr/lib/common/p11util.c			\
	usr/lib/common/pkcs_utils.c			\
	usr/lib/common/event_client.c			\
	usr/lib/hsm_mk_change/hsm_mk_change.c
