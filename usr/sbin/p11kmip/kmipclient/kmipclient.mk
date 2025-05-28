noinst_LIBRARIES = usr/sbin/p11kmip/kmipclient/libkmipclient.a

noinst_HEADERS += usr/sbin/p11kmip/kmipclient/kmipclient.h		\
	usr/sbin/p11kmip/kmipclient/kmip.h				\
	usr/sbin/p11kmip/kmipclient/names.h				\
	usr/sbin/p11kmip/kmipclient/utils.h

usr_sbin_p11kmip_kmipclient_libkmipclient_a_CFLAGS =			\
	 -DLINUX -DPROGRAM_NAME=\"$(@)\"				\
	-I${srcdir}/usr/sbin/p11kmip/kmipclient				\
	-I${srcdir}/usr/lib/common
	
usr_sbin_p11kmip_kmipclient_libkmipclient_a_SOURCES =			\
	usr/sbin/p11kmip/kmipclient/attribute.c				\
	usr/sbin/p11kmip/kmipclient/https.c				\
	usr/sbin/p11kmip/kmipclient/json.c				\
	usr/sbin/p11kmip/kmipclient/key.c				\
	usr/sbin/p11kmip/kmipclient/kmip.c				\
	usr/sbin/p11kmip/kmipclient/names.c				\
	usr/sbin/p11kmip/kmipclient/request.c				\
	usr/sbin/p11kmip/kmipclient/response.c				\
	usr/sbin/p11kmip/kmipclient/tls.c				\
	usr/sbin/p11kmip/kmipclient/ttlv.c				\
	usr/sbin/p11kmip/kmipclient/utils.c				\
	usr/sbin/p11kmip/kmipclient/xml.c

EXTRA_DIST += usr/sbin/p11kmip/kmipclient/README.md
