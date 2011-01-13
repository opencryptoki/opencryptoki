Name:			opencryptoki
Summary:		Implementation of the PKCS#11 (Cryptoki) specification v2.11
Version:		2.3.3
Release:		1%{?dist}
License:		CPL
Group:			System Environment/Base
URL:			http://sourceforge.net/projects/opencryptoki
Source:			http://downloads.sourceforge.net/%{name}/%{name}-%{version}.tar.gz
BuildRoot:		%(mktemp -ud %{_tmppath}/%{name}-%{version}-%{release}-XXXXXX)
Requires(pre):		shadow-utils coreutils sed
Requires(post):		chkconfig
Requires(preun):	chkconfig
# This is for /sbin/service
Requires(preun):	initscripts
Requires(postun):	initscripts
BuildRequires:		openssl-devel trousers-devel
BuildRequires:		autoconf automake libtool
%ifarch s390 s390x
BuildRequires:		libica-devel >= 2.0
%endif
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}

%description
Opencryptoki implements the PKCS#11 specification v2.11 for a set of
cryptographic hardware, such as IBM 4764 and 4765 crypto cards, and the
Trusted Platform Module (TPM) chip. Opencryptoki also brings a software
token implementation that can be used without any cryptographic
hardware.
This package contains the Slot Daemon (pkcsslotd) and general utilities.

%package libs
Group:			System Environment/Libraries
Summary:		The run-time libraries for the opencryptoki package

%description libs
Opencryptoki implements the PKCS#11 specification v2.11 for a set of
cryptographic hardware, such as IBM 4764 and 4765 crypto cards, and the
Trusted Platform Module (TPM) chip. Opencryptoki also brings a software
token implementation that can be used without any cryptographic
hardware.
This package contains the PKCS#11 library implementation, and requires
at least one token implementation (packaged separately) to be fully
functional.

%package swtok
Group:			System Environment/Libraries
Summary:		The software token implementation for the opencryptoki package
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}

%description swtok
Opencryptoki implements the PKCS#11 specification v2.11 for a set of
cryptographic hardware, such as IBM 4764 and 4765 crypto cards, and the
Trusted Platform Module (TPM) chip. Opencryptoki also brings a software
token implementation that can be used without any cryptographic
hardware.
This package brings the software token implementation to use opencryptoki
without any specific cryptographic hardware.

%package tpmtok
Group:			System Environment/Libraries
Summary:		Trusted Platform Module (TPM) device support for opencryptoki
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}

%description tpmtok
Opencryptoki implements the PKCS#11 specification v2.11 for a set of
cryptographic hardware, such as IBM 4764 and 4765 crypto cards, and the
Trusted Platform Module (TPM) chip. Opencryptoki also brings a software
token implementation that can be used without any cryptographic
hardware.
This package brings the necessary libraries and files to support
Trusted Platform Module (TPM) devices in the opencryptoki stack.

%package devel
Group:			Development/Libraries
Summary:		Development files for openCryptoki
Requires:		%{name}-libs = %{version}-%{release}

%description devel
This package contains the development header files for building
opencryptoki and PKCS#11 based applications

%ifarch s390 s390x
%package icatok
Group:			System Environment/Libraries
Summary:		ICA cryptographic devices (clear-key) support for opencryptoki
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}

%description icatok
Opencryptoki implements the PKCS#11 specification v2.11 for a set of
cryptographic hardware, such as IBM 4764 and 4765 crypto cards, and the
Trusted Platform Module (TPM) chip. Opencryptoki also brings a software
token implementation that can be used without any cryptographic
hardware.
This package brings the necessary libraries and files to support ICA
devices in the opencryptoki stack. ICA is an interface to IBM
cryptographic hardware such as IBM 4764 or 4765 that uses the
"accelerator" or "clear-key" path.

%package ccatok
Group:			System Environment/Libraries
Summary:		CCA cryptographic devices (secure-key) support for opencryptoki
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}

%description ccatok
Opencryptoki implements the PKCS#11 specification v2.11 for a set of
cryptographic hardware, such as IBM 4764 and 4765 crypto cards, and the
Trusted Platform Module (TPM) chip. Opencryptoki also brings a software
token implementation that can be used without any cryptographic
hardware.
This package brings the necessary libraries and files to support CCA
devices in the opencryptoki stack. CCA is an interface to IBM
cryptographic hardware such as IBM 4764 or 4765 that uses the
"co-processor" or "secure-key" path.
%endif

%prep
%setup -q

%build
./bootstrap.sh
%ifarch s390 s390x
%configure --enable-icatok --enable-ccatok
%else
%configure --disable-icatok --disable-ccatok
%endif
make %{?_smp_mflags}

%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{name}/*.la
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{name}/stdll/*.la

%clean
rm -rf $RPM_BUILD_ROOT

%preun
if [ "$1" = "0" ]; then
	/sbin/service pkcsslotd stop /dev/null 2>&1
	/sbin/chkconfig --del pkcsslotd
fi

%postun
if [ "$1" -ge "1" ] ; then
	/sbin/service pkcsslotd condrestart >/dev/null 2>&1
fi
exit 0

%postun libs -p /sbin/ldconfig
%postun swtok -p /sbin/ldconfig
%postun tpmtok -p /sbin/ldconfig
%ifarch s390 s390x
%postun icatok -p /sbin/ldconfig
%postun ccatok -p /sbin/ldconfig
%endif

%post
/sbin/chkconfig --add pkcsslotd
exit 0

%post libs -p /sbin/ldconfig
%post swtok -p /sbin/ldconfig
%post tpmtok -p /sbin/ldconfig
%ifarch s390 s390x
%post icatok -p /sbin/ldconfig
%post ccatok -p /sbin/ldconfig
%endif

%pre
# Create pkcs11 group
getent group pkcs11 >/dev/null || groupadd -r pkcs11
# Add root to the pkcs11 group
gpasswd -a root pkcs11

%files
%defattr(-,root,root,-)
%doc FAQ README LICENSE doc/README.token_data
%doc doc/openCryptoki-HOWTO.pdf
%{_mandir}/man*/*
%{_initddir}/pkcsslotd
%{_sbindir}/*
%{_libdir}/opencryptoki/methods
%{_libdir}/pkcs11/methods
%dir %attr(770,root,pkcs11) %{_localstatedir}/lib/opencryptoki

%files libs
%defattr(-,root,root,-)
%{_sysconfdir}/ld.so.conf.d/*
# Unversioned .so symlinks usually belong to -devel packages, but opencryptoki
# needs them in the main package, because:
#   pkcs11_startup looks for opencryptoki/stdll/*.so, and
#   documentation suggests that programs should dlopen "PKCS11_API.so".
%dir %attr(755, root, root) %{_libdir}/opencryptoki
%{_libdir}/opencryptoki/libopencryptoki.*
%{_libdir}/opencryptoki/PKCS11_API.so
%dir %attr(755, root, root) %{_libdir}/opencryptoki/stdll
%dir %attr(755, root, root) %{_libdir}/pkcs11
%{_libdir}/pkcs11/libopencryptoki.so
%{_libdir}/pkcs11/PKCS11_API.so
%{_libdir}/pkcs11/stdll


%files swtok
%defattr(-,root,root,-)
%{_libdir}/opencryptoki/stdll/libpkcs11_sw.*
%{_libdir}/opencryptoki/stdll/PKCS11_SW.so

%files tpmtok
%defattr(-,root,root,-)
%{_libdir}/opencryptoki/stdll/libpkcs11_tpm.*
%{_libdir}/opencryptoki/stdll/PKCS11_TPM.so
%doc doc/README.tpm_stdll

%files devel
%defattr(-,root,root,-)
%{_includedir}/*

%ifarch s390 s390x
%files icatok
%defattr(-,root,root,-)
%{_libdir}/opencryptoki/stdll/libpkcs11_ica.*
%{_libdir}/opencryptoki/stdll/PKCS11_ICA.so

%files ccatok
%defattr(-,root,root,-)
%{_libdir}/opencryptoki/stdll/libpkcs11_cca.*
%{_libdir}/opencryptoki/stdll/PKCS11_CCA.so
%doc doc/README-IBM_CCA_users
%doc doc/README.cca_stdll
%endif

%changelog
* Thu Jul 29 2010 Klaus H Kiwi <klausk@linux.vnet.ibm.com> 2.3.2-1
- Put STDLLs in separate packages
- General spec file cleanup
* Thu Aug 7 2006 Daniel H Jones <danjones@us.ibm.com> 
- spec file cleanup
* Tue Aug 1 2006 Daniel H Jones <danjones@us.ibm.com>
- sw token not created for s390
* Tue Jul 25 2006 Daniel H Jones <danjones@us.ibm.com> 
- fixed post section and /var/lib/opencryptoki perms
* Thu May 25 2006 Daniel H Jones <danjones@us.ibm.com> 2.2.4-1
- initial file created
