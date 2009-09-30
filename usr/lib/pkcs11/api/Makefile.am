nobase_lib_LTLIBRARIES = opencryptoki/libopencryptoki.la

SO_CURRENT=0
SO_REVISION=0
SO_AGE=0

opencryptoki_libopencryptoki_la_LDFLAGS = -shared -Wl,-Bsymbolic -lc -ldl \
					  -lpthread -version-info         \
					  $(SO_CURRENT):$(SO_REVISION):$(SO_AGE)

# Not all versions of automake observe libname_CFLAGS
opencryptoki_libopencryptoki_la_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE \
					 -fPIC -I../. -I../../../include/pkcs11

opencryptoki_libopencryptoki_la_SOURCES = api_interface.c shrd_mem.c apiutil.c

install-data-hook:
	cd $(DESTDIR)$(libdir)/opencryptoki && \
		ln -sf libopencryptoki.so PKCS11_API.so 
	cd $(DESTDIR)$(libdir)/opencryptoki && \
		ln -sf $(DESTDIR)$(sbindir) methods
	$(MKDIR_P) $(DESTDIR)$(libdir)/pkcs11
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -sf $(DESTDIR)$(sbindir) methods
	cd $(DESTDIR)$(libdir)/pkcs11 && \
		ln -sf $(DESTDIR)$(libdir)/opencryptoki/libopencryptoki.so PKCS11_API.so
	cd $(DESTDIR)/$(libdir)/pkcs11 && \
		ln -sf $(DESTDIR)$(libdir)/opencryptoki/libopencryptoki.so libopencryptoki.so
	$(MKDIR_P) $(DESTDIR)/$(libdir)/opencryptoki/stdll
	cd $(DESTDIR)/$(libdir)/pkcs11 && \
		ln -sf $(DESTDIR)$(libdir)/opencryptoki/stdll/ stdll
