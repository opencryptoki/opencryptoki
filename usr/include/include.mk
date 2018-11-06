opencryptokiincludedir = ${includedir}/opencryptoki

opencryptokiinclude_HEADERS =						\
	usr/include/apiclient.h	usr/include/pkcs11types.h		\
	usr/include/pkcs11.h

noinst_HEADERS +=							\
	usr/include/apictl.h usr/include/local_types.h			\
	usr/include/pkcs32.h usr/include/slotmgr.h usr/include/stdll.h
