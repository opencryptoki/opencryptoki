nobase_lib_LTLIBRARIES = opencryptoki/stdll/libpkcs11_sw.la

opencryptoki_stdll_libpkcs11_sw_la_LIBADD = ../common/opencryptoki/libcommon.la

AM_LDFLAGS = -shared -Wl,-Bsymbolic	\
	     -lc -lpthread -lcrypto     

AM_CFLAGS = -fPIC -I/usr/include -I. \
	    -I../../../include/pkcs11/stdll \
	    -I../../../include/pkcs11 -I../common

opencryptoki_stdll_libpkcs11_sw_la_SOURCES =  soft_specific.c 

install-data-local:
	cd $(DESTDIR)/$(libdir)/opencryptoki/stdll && rm -f PKCS11_SW.so && \
		ln -sf libpkcs11_sw.so PKCS11_SW.so
