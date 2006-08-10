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

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE \
	    -fPIC -I../. -I../../../include/pkcs11

opencryptoki_libopencryptoki_la_SOURCES = api_interface.c shrd_mem.c apiutil.c

install-data-local:
	mkdir -p $(DESTDIR)/$(libdir)/opencryptoki
	cd $(DESTDIR)/$(libdir)/opencryptoki && rm -f methods && \
		ln -sf ../../sbin/ methods
	mkdir -p $(DESTDIR)/$(libdir)/opencryptoki/stdll
	mkdir -p $(DESTDIR)/$(libdir)/pkcs11
	cd $(DESTDIR)/$(libdir)/pkcs11 && rm -f libopencryptoki.so && \
		ln -sf ../opencryptoki/libopencryptoki.so libopencryptoki.so
	-groupadd pkcs11
	if test "x$(prefix)" = "x/usr"; then \
		mkdir -p $(DESTDIR)/var/lib/opencryptoki ; \
		chown root:pkcs11 $(DESTDIR)/var/lib/opencryptoki ; \
		chmod 775 $(DESTDIR)/var/lib/opencryptoki ; \
		if [ ! -L $(DESTDIR)/etc/pkcs11 ] ; then \
			if [ -e $(DESTDIR)/etc/pkcs11/* ] ; then \
				mv $(DESTDIR)/etc/pkcs11/* $(DESTDIR)/var/lib/opencryptoki ; \
			fi ; \
		fi ;\
		mkdir -p $(DESTDIR)/etc \
		cd $(DESTDIR)/etc && rm -rf pkcs11 && \
			ln -sf $(DESTDIR)/var/lib/opencryptoki pkcs11 ; \
	else \
		mkdir -p $(DESTDIR)/$(localstatedir)/lib/opencryptoki ; \
		chown root:pkcs11 $(DESTDIR)/$(localstatedir)/lib/opencryptoki ; \
		chmod 775 $(DESTDIR)/$(localstatedir)/lib/opencryptoki ; \
		if [ ! -L $(DESTDIR)/$(sysconfdir)/pkcs11 ] ; then \
			if [ -e $(DESTDIR)/$(sysconfdir)/pkcs11/* ] ; then \
				mv $(DESTDIR)/$(sysconfdir)/pkcs11/* \
				$(DESTDIR)/$(localstatedir)/lib/opencryptoki ; \
			fi ; \
		fi ; \
		mkdir -p $(DESTDIR)/$(sysconfdir) ; \
		cd $(DESTDIR)/$(sysconfdir) && rm -rf pkcs11 && \
			ln -sf $(DESTDIR)/$(localstatedir)/lib/opencryptoki pkcs11 ; \
	fi
