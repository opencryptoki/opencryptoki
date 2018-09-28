nobase_lib_LTLIBRARIES += opencryptoki/libopencryptoki.la

noinst_HEADERS += %D%/apiproto.h

SO_CURRENT=0
SO_REVISION=0
SO_AGE=0

opencryptoki_libopencryptoki_la_CFLAGS =				\
	-DAPI -DDEV -D_THREAD_SAFE -fPIC -I${srcdir}/usr/include	\
	-I${srcdir}/usr/lib/common -I${srcdir}/%D% -DSTDLL_NAME=\"api\"

opencryptoki_libopencryptoki_la_LDFLAGS =				\
	-shared	-Wl,-z,defs,-Bsymbolic -lc -ldl -lpthread		\
	-version-info $(SO_CURRENT):$(SO_REVISION):$(SO_AGE)		\
	-Wl,--version-script=${srcdir}/opencryptoki.map

opencryptoki_libopencryptoki_la_SOURCES =				\
	%D%/api_interface.c %D%/shrd_mem.c %D%/socket_client.c		\
	%D%/apiutil.c usr/lib/common/trace.c
if ENABLE_LOCKS
opencryptoki_libopencryptoki_la_SOURCES +=				\
	usr/lib/common/lock_btree.c
else
opencryptoki_libopencryptoki_la_SOURCES +=				\
	usr/lib/common/btree.c
opencryptoki_libopencryptoki_la_LDFLAGS += -litm
endif
