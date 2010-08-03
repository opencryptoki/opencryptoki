nobase_lib_LTLIBRARIES=opencryptoki/stdll/libpkcs11_4758.la

opencryptoki_stdll_libpkcs11_4758_la_LDFLAGS = $(SCC_LIBS) -nostartfiles -shared	\
	-Wl,-Bsymbolic -Wl,-soname,$@.1 -lpthread -lscc -ldl

# Not all versions of automake observe libname_CFLAGS
opencryptoki_stdll_libpkcs11_4758_la_CFLAGS = -DDEV -D_THREAD_SAFE -DLEEDS_BUILD

opencryptoki_stdll_libpkcs11_4758_la_SOURCES = host_api.c util.c

INCLUDES = $(SCC_INC_DIRS) -I/usr/include -I. -I../../../include/pkcs11/stdll \
	   -I../../../include/pkcs11 

install-data-hook:
	cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		ln -sf libpkcs11_4758.so PKCS11_4758.so

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki/stdll && \
		rm -f PKCS11_4758.so; fi
