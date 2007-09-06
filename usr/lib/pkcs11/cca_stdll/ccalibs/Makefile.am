
#
# The following lib builds create stub libraries. These stubs are not installed
# but are linked against during the openCryptoki build. When the customer
# installs the CCA libs, those libs will provide the symbols that the stub
# libs provide here.
#
nobase_lib_LTLIBRARIES=opencryptoki/stdll/libcsulsecy.la	\
	opencryptoki/stdll/libcsulcall.la			\
	opencryptoki/stdll/libcsulsapi.la			\
	opencryptoki/stdll/libds30.la

opencryptoki_stdll_libcsulsecy_la_SOURCES=libcsulsecy.c
opencryptoki_stdll_libcsulcall_la_SOURCES=libcsulcall.c
opencryptoki_stdll_libcsulsapi_la_SOURCES=libcsulsapi.c
opencryptoki_stdll_libds30_la_SOURCES=libds30.c

AM_LDFLAGS=-shared -version-info 1:0:0

AM_CFLAGS=-I..

