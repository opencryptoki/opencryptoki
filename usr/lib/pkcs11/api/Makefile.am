nobase_lib_LTLIBRARIES = opencryptoki/libopencryptoki.la

SO_CURRENT=0
SO_REVISION=0
SO_AGE=0

opencryptoki_libopencryptoki_la_LDFLAGS = -shared -Wl,-Bsymbolic -lc -ldl \
					  -lpthread -version-info         \
					  $(SO_CURRENT):$(SO_REVISION):$(SO_AGE)

# Not all versions of automake observe libname_CFLAGS
opencryptoki_libopencryptoki_la_CFLAGS = -DAPI -DDEV -D_THREAD_SAFE 		\
					 -fPIC -I../. -I../../../include/pkcs11 \
					 -I ../common -DSTDLL_NAME=\"api\"

opencryptoki_libopencryptoki_la_SOURCES = api_interface.c shrd_mem.c \
					  socket_client.c apiutil.c \
					  ../common/btree.c ../common/trace.c

install-data-hook:
	$(MKDIR_P) $(DESTDIR)$(libdir)/opencryptoki/stdll
	$(MKDIR_P) $(DESTDIR)$(libdir)/pkcs11
	cd $(DESTDIR)$(libdir)/opencryptoki && \
		ln -sf libopencryptoki.so PKCS11_API.so 
	cd $(DESTDIR)$(libdir)/opencryptoki && \
		ln -sf $(sbindir) methods
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -sf $(sbindir) methods
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -sf ../opencryptoki/libopencryptoki.so PKCS11_API.so
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -sf ../opencryptoki/libopencryptoki.so libopencryptoki.so
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -sf ../opencryptoki/stdll/ stdll

uninstall-hook:
	if test -d $(DESTDIR)$(libdir)/opencryptoki/stdll; then \
		cd $(DESTDIR)$(libdir)/opencryptoki && \
		rm -f PKCS11_API.so && \
		rm -f methods; fi
	if test -d $(DESTDIR)$(libdir)/pkcs11; then \
		cd $(DESTDIR)$(libdir)/pkcs11 && \
		rm -f methods && \
		rm -f PKCS11_API.so && \
		rm -f libopencryptoki.so && \
		rm -f stdll; fi
