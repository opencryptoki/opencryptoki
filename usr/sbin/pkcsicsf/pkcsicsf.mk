sbin_PROGRAMS += %D%/pkcsicsf

%C%_pkcsicsf_LDFLAGS = -lldap -lssl -llber -lcrypto

%C%_pkcsicsf_CFLAGS =							\
	-D_THREAD_SAFE -DDEV -DAPI -DSTDLL_NAME=\"icsf\"		\
	-I${srcdir}/usr/include -I${srcdir}/usr/lib/icsf_stdll		\
	-I${srcdir}/usr/lib/common -I${srcdir}/%D%

%C%_pkcsicsf_SOURCES =							\
	usr/lib/icsf_stdll/icsf.c usr/lib/icsf_stdll/pbkdf.c		\
	usr/lib/common/trace.c %D%/pkcsicsf.c
