dnl Process this file with autoconf to produce a configure script.
AC_PREREQ([2.69])
AC_INIT([openCryptoki],[3.24],[https://github.com/opencryptoki/opencryptoki/issues],[],[https://github.com/opencryptoki/opencryptoki])
AC_CONFIG_SRCDIR([testcases/common/common.c])

dnl Needed for $target!
AC_CANONICAL_TARGET
AC_CANONICAL_HOST

AM_INIT_AUTOMAKE([-Wall -Wno-override -Wno-portability foreign subdir-objects])

dnl Checks for header files.
AC_DISABLE_STATIC
LT_INIT

AC_HEADER_STDC
AC_CHECK_HEADER_STDBOOL
AC_CHECK_HEADERS([arpa/inet.h fcntl.h libintl.h limits.h locale.h malloc.h \
		  nl_types.h stddef.h sys/file.h sys/socket.h sys/time.h   \
		  syslog.h termios.h])

dnl Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_C_RESTRICT
AC_C_CONST
AC_TYPE_UID_T
AC_TYPE_PID_T
AC_TYPE_SIZE_T
AC_TYPE_MODE_T
AC_TYPE_INT8_T
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT64_T
AC_STRUCT_TM

dnl Checks for library functions.
AC_FUNC_ALLOCA
AC_FUNC_CHOWN
AC_FUNC_FORK
AC_FUNC_MKTIME
AC_FUNC_MMAP
AC_FUNC_STRERROR_R
AC_CHECK_FUNCS([atexit ftruncate gettimeofday localtime_r memchr memmove \
		memset mkdir munmap regcomp select socket strchr strcspn \
		strdup strerror strncasecmp strrchr strstr strtol strtoul])

dnl Used in various scripts
AC_PATH_PROG([ID], [id], [/us/bin/id])
AC_PATH_PROG([USERMOD], [usermod], [/usr/sbin/usermod])
AC_PATH_PROG([GROUPADD], [mkgroup], [/usr/sbin/groupadd])
AC_PATH_PROG([USERADD], [useradd], [/usr/sbin/useradd])
AC_PATH_PROG([CAT], [cat], [/bin/cat])
AC_PATH_PROG([CHMOD], [chmod], [/bin/chmod])
AC_PATH_PROG([CHGRP], [chgrp], [/bin/chgrp])
AC_PATH_PROG([CHOWN], [chown], [/bin/chown])
AC_PROG_AWK
AC_PROG_INSTALL
AC_PROG_LN_S
AC_PROG_MAKE_SET

AM_PROG_LEX
if test "x$LEX" != "xflex"; then
    AC_MSG_ERROR(['flex' is missing on your system. Please install 'flex'.])
fi

AC_CHECK_PROG([YACC], [bison], [bison], [no])
if test "x$YACC" = "xno"; then
    AC_MSG_ERROR(['bison' program is missing on your system. Please install 'bison'.])
fi

AM_CONDITIONAL([CROSS], [test "x$cross_compiling" = xyes])

dnl ---
dnl --- Check all --enable/--disable-features
dnl ---

dnl --- Debugging support
AC_ARG_ENABLE([debug],
	AS_HELP_STRING([--enable-debug],[enable debugging build @<:@default=no@:>@]),
	[],
	[enable_debug=no])

dnl --- sanitizer support
AC_ARG_ENABLE([sanitizer],
	AS_HELP_STRING([--enable-sanitizer],[enable sanitizer build (may not work in all environments) @<:@default=no@:>@]),
	[],
	[enable_sanitizer=no])

dnl --- build testcases
AC_ARG_ENABLE([testcases],
	AS_HELP_STRING([--enable-testcases],[build the test cases @<:@default=no@:>@]),
	[],
	[enable_testcases=no])

dnl --- Check if building daemon
AC_ARG_ENABLE([daemon],
	AS_HELP_STRING([--enable-daemon],[build pkcsslotd daemon @<:@default=yes@:>@]),
	[],
	[enable_daemon=yes])

dnl --- Check if building library
AC_ARG_ENABLE([library],
	AS_HELP_STRING([--enable-library],[build opencryptoki libraries @<:@default=yes@:>@]),
	[],
	[enable_library=yes])

dnl --- Enable/disable tokens
dnl --- those have an additional 'check' state, which essentially means
dnl --- that it will enable it by default it dependencies are met

dnl --- ICA token
AC_ARG_ENABLE([icatok],
	AS_HELP_STRING([--enable-icatok],[build ica token @<:@default=enabled if
	libica is present@:>@]),
	[],
	[enable_icatok=check])

dnl --- CCA token
AC_ARG_ENABLE([ccatok],
	AS_HELP_STRING([--enable-ccatok],[build cca token (IBM Common Cryptographic
	Architecture) @<:@default=enabled@:>@]),
	[],
	[enable_ccatok=yes])

dnl --- software token
AC_ARG_ENABLE([swtok],
	AS_HELP_STRING([--enable-swtok],[build software token @<:@default=enabled@:>@]),
	[],
	[enable_swtok=yes])

dnl --- EP11 token
AC_ARG_ENABLE([ep11tok],
    AS_HELP_STRING([--enable-ep11tok],[build ep11 token @<:@default=enabled
	if libica development files are present@:>@]),
    [],
    [enable_ep11tok=check])

dnl --- TPM token
AC_ARG_ENABLE([tpmtok],
	AS_HELP_STRING([--enable-tpmtok],[build tpm token (Trusted Platform Module)
	@<:@default=enabled if TrouSerS is present@:>@]),
	[],
	[enable_tpmtok=check])

dnl -- icsf token (Integrated Cryptographic Service Facility remote token)
AC_ARG_ENABLE([icsftok],
	AS_HELP_STRING([--enable-icsftok],[build icsf token (Integrated
	Cryptographic Service Facility) @<:@default=enabled if OpenLDAP library
	is present@:>@]),
	[],
	[enable_icsftok=check])

dnl --- token-specific stuff
dnl --- pkcsep11_migrate
AC_ARG_ENABLE([pkcsep11_migrate],
	AS_HELP_STRING([--enable-pkcsep11_migrate],[build pkcsep11_migrate (EP11 token key migration tool) @<:@default=enabled if EP11 token is enabled@:>@]),
	[],
	[enable_pkcsep11_migrate=check])

dnl --- pkcsep11_session
AC_ARG_ENABLE([pkcsep11_session],
	AS_HELP_STRING([--enable-pkcsep11_session],[build pkcsep11_session (EP11 token session logout tool) @<:@default=enabled if EP11 token is enabled@:>@]),
	[],
	[enable_pkcsep11_session=check])

dnl --- locking support
AC_ARG_ENABLE([locks],
	AS_HELP_STRING([--disable-locks],[This option is no longer supported, ignored if specified.]))

dnl --- p11sak tool
AC_ARG_ENABLE([p11sak],
	AS_HELP_STRING([--enable-p11sak],[build p11sak tool @<:@default=enabled@:>@]),
	[],
	[enable_p11sak=yes])

dnl --- p11kmip tool
AC_ARG_ENABLE([p11kmip],
	AS_HELP_STRING([--enable-p11kmip],[build p11kmip tool @<:@default=no@:>@]),
	[],
	[enable_p11kmip=no])

dnl --- pkcstok_migrate
AC_ARG_ENABLE([pkcstok_migrate],
	AS_HELP_STRING([--enable-pkcstok_migrate],[build pkcstok_migrate tool @<:@default=enabled@:>@]),
	[],
	[enable_pkcstok_migrate=yes])

dnl --- pkcsstats
AC_ARG_ENABLE([pkcsstats],
	AS_HELP_STRING([--enable-pkcsstats],[build pkcsstats tool @<:@default=enabled@:>@]),
	[],
	[enable_pkcsstats=yes])

dnl --- pkcscca
AC_ARG_ENABLE([pkcscca],
	AS_HELP_STRING([--enable-pkcscca],[build pkcscca tool @<:@default=enabled@:>@ on non-AIX platforms]),
	[],
	[enable_pkcscca=yes])
	
dnl --- support for MD2
AC_ARG_ENABLE([md2],
	AS_HELP_STRING([--enable-md2],[build opencryptoki with support for MD2]))
	
dnl --- pkcshsm_mk_change
AC_ARG_ENABLE([pkcshsm_mk_change],
	AS_HELP_STRING([--enable-pkcshsm_mk_change],[build pkcshsm_mk_change tool @<:@default=enabled@:>@]),
	[],
	[enable_pkcshsm_mk_change=yes])

dnl --- pkcstok_admin
AC_ARG_ENABLE([pkcstok_admin],
	AS_HELP_STRING([--enable-pkcstok_admin],[build pkcstok_admin tool @<:@default=enabled@:>@]),
	[],
	[enable_pkcstok_admin=yes])

dnl ---
dnl --- Check for external software
dnl --- Define what to check based on enabled features

dnl --- Openssl development files
AC_ARG_WITH([openssl],
	AS_HELP_STRING([--with-openssl@<:@=DIR@:>@],[OpenSSL development files location]),
	[],
	[with_openssl=check])

dnl --- Libica development files
AC_ARG_WITH([libica],
	AS_HELP_STRING([--with-libica@<:@=DIR@:>@],[libica development files location]),
	[],
	[with_libica=check])

dnl --- TSS (TrouSerS) development files
AC_ARG_WITH([tss],
	AS_HELP_STRING([--with-tss@<:@=DIR@:>@],[TrouSerS development files location]),
	[],
	[with_tss=check])

dnl --- systemd system unit files location
AC_ARG_WITH([systemd],
	AS_HELP_STRING([--with-systemd@<:@=DIR@:>@],
	[Build a systemd service unit file for pkcsslotd (default yes), and optionally specify the systemd system unit files location. Specify '--without-systemd' to build an init-d script instead]),
	[],
	[with_systemd=yes])
	
dnl --- libudev development files
AC_ARG_WITH([libudev],
	AS_HELP_STRING([--with-libudev@<:@=DIR@:>@],[libudev development files location]),
	[],
	[with_libudev=check])

dnl --- pkcsslotd user
AC_ARG_WITH([pkcsslotd-user],
	AS_HELP_STRING([--with-pkcsslotd-user=USER],[set the user under which pkcsslotd runs (default: pkcsslotd)]),
	[pkcsslotd_user=$withval],
	[pkcsslotd_user=pkcsslotd])

dnl --- pkcs group
AC_ARG_WITH([pkcs-group],
	AS_HELP_STRING([--with-pkcs-group=GROUP],[set the group that all openCryptoki applications must belong to (default: pkcs11)]),
	[pkcs_group=$withval],
	[pkcs_group=pkcs11])

dnl ---
dnl ---
dnl --- Now that we have all the options, let's check for a valid build
dnl ---

dnl --- enable_pkey
enable_pkey=no

case $target in
	*s390x*)
		enable_pkey=yes
	;;
	*s390*)
		CFLAGS="$CFLAGS -m31"
		AC_DEFINE([NO_PKEY])
	;;
	*ppc64* | *x86_64*)
		AC_DEFINE([NO_PKEY])
	;;
	*ppc* | i*86*)
		CFLAGS="$CFLAGS -m32"
		AC_DEFINE([NO_PKEY])
	;;
	*)
		AC_DEFINE([NO_PKEY])
	;;
esac
AM_CONDITIONAL([NO_PKEY], [test "x$enable_pkey" != "xyes"])

dnl Check and save whether the platform is AIX
dnl Using the pthread library requires the _THREAD_SAFE macro to be set
build_aix=no
case "${host_os}" in
	aix*)
		build_aix=yes
		AC_DEFINE([_ALL_SOURCE])
		AC_DEFINE([_THREAD_SAFE])
		with_systemd=no
		with_libica=no
		enable_ccatok=yes
		enable_swtok=yes
		enable_tpmtok=no
		enable_icsftok=no
		enable_ep11tok=no
		echo "Disabling migration utilities on AIX: pkcscca pkcstok_migrate"
		enable_pkcscca=no
		enable_pkcstok_migrate=no
		echo "Disabling the following unsupported features on AIX: systemd libica tpmtok icsftok ep11tok"
		pkcsslotd_user=slotd
		echo "Shortening username to $pkcsslotd_user due to platform restrictions"
		function parse_map {
			grep -E '^[ ]+' $1 | tr -d ';' | tr -d ' ' > "$1".sym
		}
		parse_map opencryptoki.map
		parse_map opencryptoki_tok.map
		;;
esac

dnl Define custom variables
lockdir=${localstatedir}/lock/opencryptoki
logdir=${localstatedir}/log/opencryptoki

dnl runstatedir is only defined starting from autoconf 2.70
dnl this script has a prereq of 2.69, so instead build it from localstatedir
if test "x$build_aix" = "xyes"; then
	run_path=${localstatedir}/run
else
	run_path=/run
fi

AC_SUBST([lockdir])
AC_SUBST([logdir])
AC_SUBST(RUN_PATH, [$run_path])
AM_CONDITIONAL([AIX], [test "x$build_aix" = "xyes" ])

dnl define _GNU_SOURCE on non-AIX platforms
if test "x$build_aix" = "xno"; then
	AC_DEFINE([_GNU_SOURCE])
fi

dnl --- enable_debug
if test "x$enable_debug" = "xyes"; then
	if test "x$build_aix" = "xyes"; then
		CFLAGS="$CFLAGS -g3 -O0"
	else
		CFLAGS="$CFLAGS -gdwarf-2 -g3 -O0"
	fi
	AC_DEFINE([DEBUG])
else
	CFLAGS="$CFLAGS -O2 -g3"
fi

dnl --- enable_sanitizer
if test "x$enable_sanitizer" = "xyes"; then
	AC_CHECK_LIB([asan], [strcpy], [LDFLAGS="-lasan $LDFLAGS"],
			[AC_MSG_ERROR(['libasan' library is missing on your system. Please install 'libasan'.])])
	AC_CHECK_LIB([ubsan], [strcpy], [LDFLAGS="-lubsan $LDFLAGS"],
			[AC_MSG_ERROR(['libubsan' library is missing on your system. Please install 'libubsan'.])])
	if test "x$enable_debug" = "xyes"; then
		CFLAGS="$CFLAGS -O2 -g3 -DDEBUG"
	fi
	CFLAGS="$CFLAGS -fstack-protector-all -fsanitize=address,signed-integer-overflow,undefined -Wformat -Wformat-security -Werror=format-security -Warray-bounds -Werror=array-bounds -D_FORTIFY_SOURCE=2"
	AC_DEFINE([WITH_SANITIZER])
fi

if test "x$build_aix" = "xno"; then
	LIBCAP_LIBS=
	AC_CHECK_LIB([cap], [cap_get_proc], [LIBCAP_LIBS="-lcap"],
			[AC_MSG_ERROR(['libcap' library is missing on your system. Please install 'libcap-devel'.])])
	AC_SUBST([LIBCAP_LIBS])
fi

dnl --- cca and soft tokens need lber, icsf needs only ldap
OPENLDAP_LIBS=
AC_CHECK_HEADERS([lber.h ldap.h],
		[OPENLDAP_LIBS="-llber -lldap"],
		[AC_MSG_ERROR([lber.h and ldap.h are missing. Please install
			      'openldap-devel'.])])
AC_SUBST([OPENLDAP_LIBS])

dnl --- first, check what external software is present or specified
dnl --- with --with-package=DIR

dnl --- with_openssl
OPENSSL_CFLAGS=
OPENSSL_LIBS=
if test "x$with_openssl" != "xno"; then
	if test "x$with_openssl" != "xyes" -a "x$with_openssl" != "xcheck"; then
		OPENSSL_CFLAGS="-I$with_openssl/include"
		OPENSSL_LIBS="-L$with_openssl"
	fi
	old_cflags="$CFLAGS"
	old_libs="$LIBS"
	CFLAGS="$CFLAGS $OPENSSL_CFLAGS"
	LIBS="$LIBS $OPENSSL_LIBS"
	AC_CHECK_HEADER([openssl/evp.h], [], [
		AC_MSG_ERROR([OpenSSL 1.1.1 or later is required but OpenSSL headers couldn't be found])
	])
	AC_MSG_CHECKING([whether OpenSSL has alternate fix for CVE 2022-4304])
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
				[[
				#include <openssl/opensslv.h>
				#if OPENSSL_VERSION_NUMBER < 0x1010115fL
					#error "< OpenSSl 1.1.1u"
				#endif
				#if OPENSSL_VERSION_NUMBER >= 0x30000000L && OPENSSL_VERSION_NUMBER < 0x30000090L
					#error "< OpenSSl 3.0.9"
				#endif
				#if OPENSSL_VERSION_NUMBER >= 0x30100000L && OPENSSL_VERSION_NUMBER < 0x30100010L
					#error "< OpenSSl 3.1.1"
				#endif
				]],[[int dummy;]])],
			  [have_alt_fix_for_cve_2022_4304=yes
			   CFLAGS="$CFLAGS -DHAVE_ALT_FIX_FOR_CVE2022_4304"
			   AC_MSG_RESULT([yes])],
			  [have_alt_fix_for_cve_2022_4304=no
			  AC_MSG_RESULT([no])])
	if test "x$with_openssl" != "xno"; then
		AC_CHECK_LIB([crypto], [EVP_sha3_256], [
			OPENSSL_LIBS="$OPENSSL_LIBS -lcrypto"
			with_openssl=yes], [
			AC_MSG_ERROR([OpenSSL 1.1.1 or later is required but OpenSSL libraries version 1.1.1 or later couldn't be found])
		])
	fi
	if test "x$with_openssl" = "xno"; then
		CFLAGS="$old_cflags"
		LIBS="$old_libs"
	fi
fi
if test "x$with_openssl" != "xyes"; then
	AC_MSG_ERROR([OpenSSL 1.1.1 or later is required but build without OpenSSL was requested])
fi
AC_SUBST([OPENSSL_CFLAGS])
AC_SUBST([OPENSSL_LIBS])
AM_CONDITIONAL([HAVE_ALT_FIX_FOR_CVE_2022_4304], [test "x$have_alt_fix_for_cve_2022_4304" = "xyes"])

dnl --- with_libica
LIBICA_CFLAGS=
LIBICA_LIBS=
if test "x$with_libica" != "xno"; then
	if test "x$with_libica" != "xyes" -a "x$with_libica" != "xcheck"; then
		LIBICA_CFLAGS="-I$with_libica"
		LIBICA_LIBS="-L$with_libica"
	fi
	old_cflags="$CFLAGS"
	old_libs="$LIBS"
	CFLAGS="$CFLAGS $LIBICA_CFLAGS"
	LIBS="$LIBS $LIBICA_LIBS"
	AC_CHECK_HEADER([ica_api.h], [], [
		if test "x$with_libica" != "xcheck"; then
			AC_MSG_ERROR([Build with Libica requested but Libica headers couldn't be found])
		fi
		with_libica=no
	])
	if test "x$with_libica" != "xno"; then
		AC_CHECK_LIB([ica], [ica_open_adapter],
			[with_libica=yes], [
				if test "x$with_libica" != "xcheck"; then
					AC_MSG_ERROR([Build with Libica requested but Libica libraries (v 2.x or higher) couldn't be found])
				fi
				with_libica=no
		])
	fi
	if test "x$with_libica" = "xno"; then
		CFLAGS="$old_cflags"
		LIBS="$old_libs"
	fi
fi
AC_SUBST([LIBICA_CFLAGS])
AC_SUBST([LIBICA_LIBS])

dnl --- with_tss
TSS_CFLAGS=
TSS_LIBS=
if test "x$with_tss" != "xno"; then
	if test "x$with_tss" != "xyes" -a "x$with_tss" != "xcheck"; then
		TSS_CFLAGS="-I$with_tss"
		TSS_LIBS="-L$with_tss"
	fi
	old_cflags="$CFLAGS"
	old_libs="$LIBS"
	CFLAGS="$CFLAGS $TSS_CFLAGS"
	LIBS="$LIBS $TSS_LIBS"
	AC_CHECK_HEADER([tss/platform.h], [], [
		if test "x$with_tss" != "xcheck"; then
			AC_MSG_ERROR([Build with TSS requested but TSS headers couldn't be found])
		fi
		with_tss=no
	])
	if test "x$with_tss" != "xno"; then
		AC_CHECK_LIB([tspi], [Tspi_Context_Create],
			[with_tss=yes], [
				if test "x$with_tss" != "xcheck"; then
					AC_MSG_ERROR([Build with TSS requested but TSS libraries couldn't be found])
				fi
				with_tss=no
		])
	fi
	if test "x$with_tss" = "xno"; then
		CFLAGS="$old_cflags"
		LIBS="$old_libs"
	fi
fi
AC_SUBST([TSS_CFLAGS])
AC_SUBST([TSS_LIBS])

dnl --- with_libudev
LIBUDEV_CFLAGS=
LIBUDEV_LIBS=
if test "x$with_libudev" != "xno"; then
	if test "x$with_libudev" != "xyes" -a "x$with_libudev" != "xcheck"; then
		LIBUDEV_CFLAGS="-I$with_libudev"
		LIBUDEV_LIBS="-L$with_libudev"
	fi
	old_cflags="$CFLAGS"
	old_libs="$LIBS"
	CFLAGS="$CFLAGS $LIBUDEV_CFLAGS"
	LIBS="$LIBS $LIBUDEV_LIBS"
	# Use libudev only on s390 platforms, only s390 emits AP related uevents
	case $target in
	     *s390x* | *s390*)
		AC_DEFINE([WITH_LIBUDEV])
		;;
	     *)
		if test "x$with_libudev" != "xyes"; then
			with_libudev=no
			echo "Default to 'with_libudev=no' on non-s390 platforms"
		fi
		;;
	esac
	if test "x$with_libudev" != "xno"; then
		AC_CHECK_HEADER([libudev.h], [with_libudev=yes], [
			AC_MSG_ERROR([Build with libudev requested but libudev headers couldn't be found])
		])
		AC_CHECK_LIB([udev], [udev_monitor_new_from_netlink], [with_libudev=yes], [
			AC_MSG_ERROR([Build with libudev requested but libudev libraries couldn't be found])
		])
	fi
	if test "x$with_libudev" = "xno"; then
		CFLAGS="$old_cflags"
		LIBS="$old_libs"
	fi
fi
AC_SUBST([LIBUDEV_CFLAGS])
AC_SUBST([LIBUDEV_LIBS])
AM_CONDITIONAL([HAVE_LIBUDEV], [test "x$with_libudev" = "xyes"])

dnl ---
dnl --- Now check enabled features, while making sure every required
dnl --- package is available
dnl ---

dnl --- enable_testcases
if test "x$enable_testcases" = "xyes"; then
	AC_CHECK_PROG([HAVE_EXPECT], [expect], [yes], [no])

	if test "x$HAVE_EXPECT" = "xno"; then
		AC_MSG_ERROR([*** testcases requires 'expect' interpreter, which wasn't found])
		enable_testcases=no
	fi
fi
AM_CONDITIONAL([ENABLE_TESTCASES], [test "x$enable_testcases" = "xyes"])

dnl --- enable_daemon
AM_CONDITIONAL([ENABLE_DAEMON], [test "x$enable_daemon" = "xyes"])

dnl --- enable_library
AM_CONDITIONAL([ENABLE_LIBRARY], [test "x$enable_library" = "xyes"])

dnl --- enable systemd and set unit dir
if test "x$with_systemd" != "xno"; then
	if test "x$with_systemd" != "xyes" -a "x$with_systemd" != "xcheck"; then
		unitdir=$with_systemd
		enable_systemd=yes
	else
		if test "x$with_systemd" = "xyes"; then
			unitdir=${ac_default_prefix}/lib/systemd/system
			enable_systemd=yes
		else
			enable_systemd=no
		fi
	fi
else
	enable_systemd=no
fi
AM_CONDITIONAL([ENABLE_SYSTEMD], [test "x$enable_systemd" = "xyes"])
AC_SUBST(unitdir)

dnl --- enable_icatok
if test "x$enable_icatok" = "xyes"; then
	if test "x$with_libica" != "xyes"; then
		AC_MSG_ERROR([ica token build requested but libica development files not found])
		enable_icatok=no
	fi

	if test "x$with_openssl" != "xyes"; then
		AC_MSG_ERROR([ica token build requested but OpenSSL development files not found])
		enable_icatok=no
	fi
fi
if test "x$enable_icatok" != "xno" -a "x$with_libica" != "xno" -a "x$with_openssl" != "xno"; then
	enable_icatok=yes
else
	enable_icatok=no
fi
AM_CONDITIONAL([ENABLE_ICATOK], [test "x$enable_icatok" = "xyes"])

dnl --- enable_ccatok
if test "x$enable_ccatok" = "xyes" -a "x$enable_pkey" = "xyes"; then
	AC_CHECK_HEADER([asm/pkey.h], [], [
		AC_MSG_ERROR([cca token build requested but Kernel's pkey header couldn't be found])
	])	
fi
if test "x$enable_ccatok" != "xno"; then
	enable_ccatok=yes
	if test "x$enable_pkey" = "xyes"; then 
		AC_CHECK_HEADER([asm/pkey.h], [], [
			enable_ccatok=no
	])
	fi
else
	enable_ccatok=no
fi
AM_CONDITIONAL([ENABLE_CCATOK], [test "x$enable_ccatok" = "xyes"])

dnl --- enable_swtok
if test "x$enable_swtok" = "xyes"; then
	if test "x$with_openssl" != "xyes"; then
		AC_MSG_ERROR([software token build requested but OpenSSL development files not found])
		enable_swtok=no
	fi
fi
if test "x$enable_swtok" != "xno" -a "x$with_openssl" != "xno"; then
	enable_swtok=yes
else
	enable_swtok=no
fi
AM_CONDITIONAL([ENABLE_SWTOK], [test "x$enable_swtok" = "xyes"])

dnl --- enable_ep11tok
if test "x$enable_ep11tok" = "xyes"; then
	AC_CHECK_HEADER([ica_api.h], [], [
		AC_MSG_ERROR([ep11 token build requested but Libica headers couldn't be found])
	])
	AC_CHECK_HEADER([asm/pkey.h], [], [
		AC_MSG_ERROR([ep11 token build requested but Kernel's pkey header couldn't be found])
	])	
fi
if test "x$enable_ep11tok" != "xno"; then
	enable_ep11tok=yes
	AC_CHECK_HEADER([ica_api.h], [], [
		enable_ep11tok=no
	])
	AC_CHECK_HEADER([asm/pkey.h], [], [
		enable_ep11tok=no
	])
else
	enable_ep11tok=no
fi
AM_CONDITIONAL([ENABLE_EP11TOK], [test "x$enable_ep11tok" = "xyes"])

dnl --- enable_icsftok
if test "x$enable_icsftok" = "xyes"; then
	if test "x$with_openssl" != "xyes"; then
		AC_MSG_ERROR([ICSF token build requested but OpenSSL development files not found])
		enable_icsftok=no
	fi
fi
if test "x$enable_icsftok" != "xno" -a "x$with_openssl" != "xno"; then
	enable_icsftok=yes
else
	enable_icsftok=no
fi
AM_CONDITIONAL([ENABLE_ICSFTOK], [test "x$enable_icsftok" = "xyes"])

dnl --- enable_tpmtok
if test "x$enable_tpmtok" = "xyes"; then
	if test "x$with_tss" != "xyes"; then
		AC_MSG_ERROR([tpm token build requested but TSS development files not found])
		enable_tpmtok=no
	fi
fi
if test "x$enable_tpmtok" != "xno" -a "x$with_tss" != "xno"; then
	enable_tpmtok=yes
else
	enable_tpmtok=no
fi
AM_CONDITIONAL([ENABLE_TPMTOK], [test "x$enable_tpmtok" = "xyes"])


dnl --- enable_pkcsep11_migrate
if test "x$enable_pkcsep11_migrate" = "xyes"; then
	if test "x$enable_ep11tok" != "xyes"; then
		AC_MSG_ERROR([pkcsep11_migrate build requested but the ep11 token is not enabled])
		enable_pkcsep11_migrate=no
	fi
fi
if test "x$enable_pkcsep11_migrate" != "xno" -a "x$enable_ep11tok" = "xyes"; then
	enable_pkcsep11_migrate=yes
else
	enable_pkcsep11_migrate=no
fi
AM_CONDITIONAL([ENABLE_PKCSEP11_MIGRATE], [test "x$enable_pkcsep11_migrate" = "xyes"])

dnl --- enable_pkcsep11_session
if test "x$enable_pkcsep11_session" = "xyes"; then
	if test "x$enable_ep11tok" != "xyes"; then
		AC_MSG_ERROR([pkcsep11_session build requested but the ep11 token is not enabled])
		enable_pkcsep11_session=no
	fi
fi

if test "x$enable_pkcsep11_session" != "xno" -a "x$enable_ep11tok" = "xyes"; then
	enable_pkcsep11_session=yes
else
	enable_pkcsep11_session=no
fi

AM_CONDITIONAL([ENABLE_PKCSEP11_SESSION], [test "x$enable_pkcsep11_session" = "xyes"])

dnl --- enable_p11sak
AM_CONDITIONAL([ENABLE_P11SAK], [test "x$enable_p11sak" = "xyes"])

dnl --- enable_p11kmip
AM_CONDITIONAL([ENABLE_P11KMIP], [test "x$enable_p11kmip" = "xyes"])

dnl --- enable_pkcstok_migrate
AM_CONDITIONAL([ENABLE_PKCSTOK_MIGRATE], [test "x$enable_pkcstok_migrate" = "xyes"])

dnl --- enable_pkcsstats
AM_CONDITIONAL([ENABLE_PKCSSTATS], [test "x$enable_pkcsstats" = "xyes"])

dnl --- enable_pkcscca
AM_CONDITIONAL([ENABLE_PKCSCCA], [test "x$enable_pkcscca" = "xyes"])

dnl --- enable_pkcshsm_mk_change
AM_CONDITIONAL([ENABLE_PKCSHSM_MK_CHANGE], [test "x$enable_pkcshsm_mk_change" = "xyes"])

dnl --- enable_pkcstok_admin
AM_CONDITIONAL([ENABLE_PKCSTOK_ADMIN], [test "x$enable_pkcstok_admin" = "xyes"])

dnl --- enable_locks
if test "x$enable_locks" = "xno"; then
	AC_MSG_WARN([The --disable-locks option is no longer supported, it is ignored.])
fi

dnl --- enable_md2
if test "x$enable_md2" = "xyes"; then
	enable_md2=yes
else
	enable_md2=no
	AC_DEFINE([NOMD2])
fi
AM_CONDITIONAL([ENABLE_MD2], [test "x$enable_md2" = "xyes"])

AC_SUBST([pkcsslotd_user])
AC_SUBST([pkcs_group])
AC_DEFINE([PKCS64])
AC_DEFINE([_XOPEN_SOURCE], [600], [POSIX 2004])
AC_PROG_CC([xlc xlc_r gcc clang])
AC_PROG_CC_STDC
if test "x$build_aix" = "xyes"; then
	CFLAGS="$CFLAGS -qinfo=pro:cns:lan:nocmp:nocnv:nogot:notrd -qalign=natural -qarch=pwr7 -qsuppress=1506-1527:1500-029 -qlanglvl=stdc99 -qsrcmsg -lbsd -q64"
	# msg is used to ensure compilers that ignore the error pragma are still caught
	AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
		[[#if (__xlC__ >> 8) < 16
			#msg "xlc 16.x or newer required"
			#endif]]
		)],,
		[AC_MSG_ERROR([xlc 16.x or newer is required. Please install a newer release of the xlc compiler.])])
else
	CFLAGS="$CFLAGS -Wall -Wextra"
	CFLAGS+=" -std=c99 -Werror=implicit-int -Werror=implicit-function-declaration -Werror=int-conversion -Werror=strict-prototypes -Werror=old-style-definition -pedantic"
fi

AC_DEFINE_UNQUOTED([PKCSSLOTD_USER], "$pkcsslotd_user")
AC_DEFINE_UNQUOTED([PKCS_GROUP], "$pkcs_group")

CFLAGS="$CFLAGS"' -DCONFIG_PATH=\"$(localstatedir)/lib/opencryptoki\" -DSBIN_PATH=\"$(sbindir)\" -DLIB_PATH=\"$(libdir)\" -DRUN_PATH=\"$(RUN_PATH)\" -DLOCKDIR_PATH=\"$(lockdir)\" -DOCK_CONFDIR=\"$(sysconfdir)/opencryptoki\" -DOCK_LOGDIR=\"$(logdir)\"'

# At this point, CFLAGS is set to something sensible
AX_PROG_CC_FOR_BUILD
AC_PROG_CXX([xlC_r xlC g++ clang++])
# AC_PROG_CXX will return "g++" even if no c++ compiler is installed.
# Check for that case, and issue an error if so.
AC_LANG_PUSH([C++])
AC_COMPILE_IFELSE([AC_LANG_PROGRAM(
  [[#ifndef __cplusplus
    #error "broken C++"
    #endif]])],,
  [AC_MSG_ERROR([C++ compiler is missing on your system. Please install 'gcc-c++'.])])
AC_LANG_POP([C++])

AC_CONFIG_MACRO_DIRS([m4])

AM_COND_IF([ENABLE_ICSFTOK],
           [AC_CONFIG_FILES([man/man1/pkcsicsf.1])])
AM_COND_IF([ENABLE_PKCSCCA],
           [AC_CONFIG_FILES([man/man1/pkcscca.1])])
AM_COND_IF([ENABLE_PKCSHSM_MK_CHANGE],
           [AC_CONFIG_FILES([man/man1/pkcshsm_mk_change.1])])
AM_COND_IF([ENABLE_PKCSSTATS],
           [AC_CONFIG_FILES([man/man1/pkcsstats.1])])
AM_COND_IF([ENABLE_P11SAK],
           [AC_CONFIG_FILES([man/man1/p11sak.1])])
AM_COND_IF([ENABLE_P11KMIP],
           [AC_CONFIG_FILES([man/man1/p11kmip.1])])
AM_COND_IF([ENABLE_PKCSEP11_MIGRATE],
           [AC_CONFIG_FILES([man/man1/pkcsep11_migrate.1])])
AM_COND_IF([ENABLE_PKCSEP11_SESSION],
           [AC_CONFIG_FILES([man/man1/pkcsep11_session.1])])
AM_COND_IF([ENABLE_PKCSTOK_MIGRATE],
           [AC_CONFIG_FILES([man/man1/pkcstok_migrate.1])])

AC_CONFIG_FILES([Makefile				\
		 misc/opencryptoki.pc			\
		 usr/lib/api/shrd_mem.c			\
		 man/man1/pkcsconf.1			\
		 man/man5/opencryptoki.conf.5		\
		 man/man5/p11sak_defined_attrs.conf.5	\
		 man/man5/strength.conf.5		\
		 man/man5/policy.conf.5			\
		 man/man5/p11kmip.conf.5        \
		 man/man7/opencryptoki.7		\
		 man/man8/pkcsslotd.8])

AC_OUTPUT

echo "Enabled features:"
echo "	Debug build:		$enable_debug"
echo "	Testcases:		$enable_testcases"
echo "	Daemon build:		$enable_daemon"
echo "	Library build:		$enable_library"
echo "	Systemd service:	$enable_systemd"
echo "	Build with libudev:	$with_libudev"
echo "	Build p11sak tool:	$enable_p11sak"
echo "	Build p11kmip tool:	$enable_p11kmip"
echo "	token migrate tool:	$enable_pkcstok_migrate"
echo "	token admin tool:	$enable_pkcstok_admin"
echo "	statistics tool:	$enable_pkcsstats"
echo "	HSM MK change tool:	$enable_pkcshsm_mk_change"
echo
echo "Enabled token types:"
echo "	ICA token:		$enable_icatok"
echo "	CCA token:		$enable_ccatok"
echo "	Software token:		$enable_swtok"
echo "	EP11 token:		$enable_ep11tok"
echo "	TPM token:		$enable_tpmtok"
echo "	ICSF token:		$enable_icsftok"
echo
echo "Token-specific features:"
echo "	pkcsep11migrate build:	$enable_pkcsep11_migrate"
echo "	pkcsep11session build:	$enable_pkcsep11_session"
echo "	pkcscca build:		$enable_pkcscca"
echo
echo "pkcsslotd user:		$pkcsslotd_user"
echo "pkcs group:		$pkcs_group"
echo
echo "CFLAGS=$CFLAGS"
echo "LDFLAGS=$LDFLAGS"
echo
if test "x$enable_sanitizer" = "xyes"; then
	echo "Sanitizer is enabled, \"export LSAN_OPTIONS=fast_unwind_on_malloc=false\" may be required to get useful stack traces."
fi
