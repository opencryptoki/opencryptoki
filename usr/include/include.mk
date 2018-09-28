opencryptokiincludedir = ${includedir}/opencryptoki

opencryptokiinclude_HEADERS =						\
	%D%/apiclient.h	%D%/pkcs11types.h %D%/pkcs11.h

noinst_HEADERS +=							\
	%D%/apictl.h %D%/local_types.h %D%/pkcs32.h %D%/slotmgr.h	\
	%D%/stdll.h
