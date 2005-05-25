nobase_lib_LTLIBRARIES = opencryptoki/libopencryptoki.la

SO_CURRENT=0
SO_REVISION=0
SO_AGE=0

opencryptoki_libopencryptoki_la_LDFLAGS = -shared -Wl,-Bsymbolic -lc -ldl \
					  -lpthread -version-info         \
					  $(SO_CURRENT):$(SO_REVISION):   \
					  $(SO_AGE)

# Not all versions of automake observe libname_CFLAGS
opencryptoki_libopencryptoki_la_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE \
					 -fPIC -I../. -I../../../include/pkcs11

# Not all versions of automake observe libname_CFLAGS
AM_CFLAGS = -DSPINXPL -DAPI -DDEV -D_THREAD_SAFE \
	    -fPIC -I../. -I../../../include/pkcs11

opencryptoki_libopencryptoki_la_SOURCES = api_interface.c shrd_mem.c apiutil.c

install-data-local:
	cd $(libdir) && rm -f libopencryptoki.so && \
		ln -sf opencryptoki/libopencryptoki.so libopencryptoki.so
	cd $(libdir) && rm -f libopencryptoki.so.$(SO_CURRENT) && \
		ln -sf opencryptoki/libopencryptoki.so.$(SO_CURRENT) \
		libopencryptoki.so.$(SO_CURRENT)
	cd $(libdir)/opencryptoki && rm -f PKCS11_API.so && \
		ln -sf libopencryptoki.so PKCS11_API.so
	cd $(libdir)/opencryptoki && rm -f methods && \
		ln -sf ../../sbin/ methods
	mkdir -p $(libdir)/pkcs11
	cd $(libdir)/pkcs11 && rm -f methods && \
		ln -sf ../../sbin/ methods
	cd $(libdir)/pkcs11 && rm -f PKCS11_API.so && \
		ln -sf ../opencryptoki/libopencryptoki.so PKCS11_API.so
	cd $(libdir)/pkcs11 && rm -f stdll && \
		ln -sf ../opencryptoki/stdll/ stdll
	-groupadd pkcs11
	if test "x$(prefix)" = "x/usr"; then \
		mkdir -p /var/lib/opencryptoki ; \
		chown root:pkcs11 /var/lib/opencryptoki ; \
		chmod 775 /var/lib/opencryptoki ; \
		if [ ! -L /etc/pkcs11 ] ; then \
			if [ -e /etc/pkcs11/* ] ; then \
				mv /etc/pkcs11/* /var/lib/opencryptoki ; \
			fi ; \
		fi ;\
		cd /etc && rm -rf pkcs11 && \
			ln -sf /var/lib/opencryptoki pkcs11 ; \
	else \
		mkdir -p $(localstatedir)/lib/opencryptoki ; \
		chown root:pkcs11 $(localstatedir)/lib/opencryptoki ; \
		chmod 775 $(localstatedir)/lib/opencryptoki ; \
		if [ ! -L $(sysconfdir)/pkcs11 ] ; then \
			if [ -e $(sysconfdir)/pkcs11/* ] ; then \
				mv $(sysconfdir)/pkcs11/* $(localstatedir)/lib/opencryptoki ; \
			fi ; \
		fi ; \
		mkdir -p $(sysconfdir) ; \
		cd $(sysconfdir) && rm -rf pkcs11 && \
			ln -sf $(localstatedir)/lib/opencryptoki pkcs11 ; \
	fi
