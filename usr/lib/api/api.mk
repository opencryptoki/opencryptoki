nobase_lib_LTLIBRARIES += opencryptoki/libopencryptoki.la

noinst_HEADERS += usr/lib/api/apiproto.h

SO_CURRENT=0
SO_REVISION=0
SO_AGE=0

opencryptoki_libopencryptoki_la_CFLAGS =				\
	-DAPI -DDEV -D_THREAD_SAFE -fPIC -I${srcdir}/usr/include	\
	-I${srcdir}/usr/lib/common -I${srcdir}/usr/lib/api		\
	-DSTDLL_NAME=\"api\"

opencryptoki_libopencryptoki_la_LDFLAGS =				\
	-shared	-Wl,-z,defs,-Bsymbolic -lc -ldl -lpthread		\
	-version-info $(SO_CURRENT):$(SO_REVISION):$(SO_AGE)		\
	-Wl,--version-script=${srcdir}/opencryptoki.map

opencryptoki_libopencryptoki_la_SOURCES =				\
	usr/lib/api/api_interface.c usr/lib/api/shrd_mem.c		\
	usr/lib/api/socket_client.c usr/lib/api/apiutil.c		\
	usr/lib/common/trace.c
if ENABLE_LOCKS
opencryptoki_libopencryptoki_la_SOURCES +=				\
	usr/lib/common/lock_btree.c
else
opencryptoki_libopencryptoki_la_SOURCES +=				\
	usr/lib/common/btree.c
opencryptoki_libopencryptoki_la_LDFLAGS += -litm
endif
