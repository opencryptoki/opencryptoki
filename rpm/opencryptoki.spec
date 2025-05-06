%global _hardened_build 1

Name:			opencryptoki
Summary:		Implementation of the PKCS#11 (Cryptoki) specification v3.0 and partially v3.1
Version:		3.25.0
Release:		1%{?dist}
License:		CPL
Group:			System Environment/Base
URL:			https://github.com/opencryptoki/opencryptoki
Source:			https://github.com/%{name}/%{name}/archive/v%{version}.tar.gz#/%{name}-%{version}.tar.gz

Requires(pre):		coreutils
BuildRequires:		gcc
BuildRequires:		openssl-devel >= 1.1.1
BuildRequires:		trousers-devel
BuildRequires:		openldap-devel
BuildRequires:		autoconf automake libtool autoconf-archive
BuildRequires:		bison flex
BuildRequires:		systemd-devel
BuildRequires:		libcap-devel
BuildRequires:		make
%ifarch s390 s390x
BuildRequires:		libica-devel >= 3.3
%endif
Requires(pre):		%{name}-libs%{?_isa} = %{version}-%{release}
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}
Requires:		%{name}(token)
Requires(post):		systemd
Requires(preun):	systemd
Requires(postun):	systemd


%description
Opencryptoki implements the PKCS#11 specification  v3.0 and partially v3.1
for a set of cryptographic hardware, such as IBM 4767, 4768, 4769 and 4770
crypto cards, and the Trusted Platform Module (TPM) chip. Opencryptoki also
brings a software token implementation that can be used without any cryptographic
hardware.
This package contains the Slot Daemon (pkcsslotd) and general utilities.


%package libs
Group:			System Environment/Libraries
Summary:		The run-time libraries for opencryptoki package
Requires(pre):		shadow-utils

%description libs
Opencryptoki implements the PKCS#11 specification  v3.0 and partially v3.1
for a set of cryptographic hardware, such as IBM 4767, 4768, 4769 and 4770
crypto cards, and the Trusted Platform Module (TPM) chip. Opencryptoki also
brings a software token implementation that can be used without any cryptographic
hardware.
This package contains the PKCS#11 library implementation, and requires
at least one token implementation (packaged separately) to be fully
functional.


%package devel
Group:			Development/Libraries
Summary:		Development files for openCryptoki
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}

%description devel
This package contains the development header files for building
opencryptoki and PKCS#11 based applications


%package swtok
Group:			System Environment/Libraries
Summary:		The software token implementation for opencryptoki
Requires(pre):		%{name}-libs%{?_isa} = %{version}-%{release}
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}
Provides:		%{name}(token)

%description swtok
Opencryptoki implements the PKCS#11 specification  v3.0 and partially v3.1
for a set of cryptographic hardware, such as IBM 4767, 4768, 4769 and 4770
crypto cards, and the Trusted Platform Module (TPM) chip. Opencryptoki also
brings a software token implementation that can be used without any cryptographic
hardware.
This package brings the software token implementation to use opencryptoki
without any specific cryptographic hardware.


%package tpmtok
Group:			System Environment/Libraries
Summary:		Trusted Platform Module (TPM) device support for opencryptoki
Requires(pre):		%{name}-libs%{?_isa} = %{version}-%{release}
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}
Provides:		%{name}(token)

%description tpmtok
Opencryptoki implements the PKCS#11 specification  v3.0 and partially v3.1
for a set of cryptographic hardware, such as IBM 4767, 4768, 4769 and 4770
crypto cards, and the Trusted Platform Module (TPM) chip. Opencryptoki also
brings a software token implementation that can be used without any cryptographic
hardware.
This package brings the necessary libraries and files to support
Trusted Platform Module (TPM) devices in the opencryptoki stack.


%package icsftok
Group:			System Environment/Libraries
Summary:		ICSF token support for opencryptoki
Requires(pre):		%{name}-libs%{?_isa} = %{version}-%{release}
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}
Provides:		%{name}(token)

%description icsftok
Opencryptoki implements the PKCS#11 specification  v3.0 and partially v3.1
for a set of cryptographic hardware, such as IBM 4767, 4768, 4769 and 4770
crypto cards, and the Trusted Platform Module (TPM) chip. Opencryptoki also
brings a software token implementation that can be used without any cryptographic
hardware.
This package brings the necessary libraries and files to support
ICSF token in the opencryptoki stack.


%ifarch s390 s390x
%package icatok
Group:			System Environment/Libraries
Summary:		ICA cryptographic devices (clear-key) support for opencryptoki
Requires(pre):		%{name}-libs%{?_isa} = %{version}-%{release}
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}
Provides:		%{name}(token)

%description icatok
Opencryptoki implements the PKCS#11 specification  v3.0 and partially v3.1
for a set of cryptographic hardware, such as IBM 4767, 4768, 4769 and 4770
crypto cards, and the Trusted Platform Module (TPM) chip. Opencryptoki also
brings a software token implementation that can be used without any cryptographic
hardware.
This package brings the necessary libraries and files to support ICA
devices in the opencryptoki stack. ICA is an interface to IBM
cryptographic hardware such as IBM 4767, 4768, 4769 and 4770 that uses the
"accelerator" or "clear-key" path.
%endif

%package ccatok
Group:			System Environment/Libraries
Summary:		CCA cryptographic devices (secure-key) support for opencryptoki
Requires(pre):		%{name}-libs%{?_isa} = %{version}-%{release}
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}
Provides:		%{name}(token)

%description ccatok
Opencryptoki implements the PKCS#11 specification  v3.0 and partially v3.1
for a set of cryptographic hardware, such as IBM 4767, 4768, 4769 and 4770
crypto cards, and the Trusted Platform Module (TPM) chip. Opencryptoki also
brings a software token implementation that can be used without any cryptographic
hardware.
This package brings the necessary libraries and files to support CCA
devices in the opencryptoki stack. CCA is an interface to IBM
cryptographic hardware such as IBM 4767, 4768, 4769 and 4770 that uses the
"co-processor" or "secure-key" path.

%ifarch s390 s390x
%package ep11tok
Group:			System Environment/Libraries
Summary:		EP11 cryptographic devices (secure-key) support for opencryptoki
Requires(pre):		%{name}-libs%{?_isa} = %{version}-%{release}
Requires:		%{name}-libs%{?_isa} = %{version}-%{release}
Provides:		%{name}(token)

%description ep11tok
Opencryptoki implements the PKCS#11 specification  v3.0 and partially v3.1
for a set of cryptographic hardware, such as IBM 4767, 4768, 4769 and 4770
crypto cards, and the Trusted Platform Module (TPM) chip. Opencryptoki also
brings a software token implementation that can be used without any cryptographic
hardware.
This package brings the necessary libraries and files to support EP11
tokens in the opencryptoki stack. The EP11 token is a token that uses
the IBM Crypto Express adapters (starting with Crypto Express 4S adapters)
configured with Enterprise PKCS#11 (EP11) firmware.
%endif


%prep
%setup -q -n %{name}-%{version}

%build
./bootstrap.sh

%configure --with-systemd=%{_unitdir}	\
    --with-pkcsslotd-user=pkcsslotd --with-pkcs-group=pkcs11	\
%ifarch s390 s390x
    --enable-icatok --enable-ccatok --enable-ep11tok --enable-pkcsep11_migrate
%else
    --disable-icatok --enable-ccatok --disable-ep11tok --disable-pkcsep11_migrate --enable-pkcscca_migrate
%endif

make %{?_smp_mflags} CHGRP=/bin/true

%install
make install DESTDIR=$RPM_BUILD_ROOT CHGRP=/bin/true

# Remove unwanted cruft
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{name}/*.la
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{name}/stdll/*.la

%post libs -p /sbin/ldconfig
%post swtok -p /sbin/ldconfig
%post tpmtok -p /sbin/ldconfig
%post icsftok -p /sbin/ldconfig
%ifarch s390 s390x
%post icatok -p /sbin/ldconfig
%endif
%post ccatok -p /sbin/ldconfig
%ifarch s390 s390x
%post ep11tok -p /sbin/ldconfig
%endif

%postun libs -p /sbin/ldconfig
%postun swtok -p /sbin/ldconfig
%postun tpmtok -p /sbin/ldconfig
%postun icsftok -p /sbin/ldconfig
%ifarch s390 s390x
%postun icatok -p /sbin/ldconfig
%endif
%postun ccatok -p /sbin/ldconfig
%ifarch s390 s390x
%postun ep11tok -p /sbin/ldconfig
%endif

%pre libs
# Create pkcs11 group and pkcsslotd user
getent group pkcs11 >/dev/null || groupadd -r pkcs11
getent passwd pkcsslotd >/dev/null || useradd -r -g pkcs11 -d /run/opencryptoki -s /sbin/nologin -c "Opencryptoki pkcsslotd user" pkcsslotd
exit 0

%post
%systemd_post pkcsslotd.service

%preun
%systemd_preun pkcsslotd.service

%postun
%systemd_postun_with_restart pkcsslotd.service


%files
%doc ChangeLog FAQ README.md
%doc doc/opencryptoki-howto.md
%doc doc/README.token_data
%doc doc/policy-example.conf
%doc doc/strength-example.conf
%dir %{_sysconfdir}/%{name}
%config(noreplace) %{_sysconfdir}/%{name}/%{name}.conf
%attr(0640, root, pkcs11) %config(noreplace) %{_sysconfdir}/%{name}/strength.conf
%attr(0640, root, pkcs11) %config(noreplace) %{_sysconfdir}/%{name}/p11sak_defined_attrs.conf
%attr(0640, root, pkcs11) %config(noreplace) %{_sysconfdir}/%{name}/p11kmip.conf
%{_prefix}/lib/tmpfiles.d/%{name}.conf
%{_unitdir}/pkcsslotd.service
%{_sbindir}/pkcsconf
%{_sbindir}/pkcsslotd
%{_sbindir}/p11kmip
%{_sbindir}/p11sak
%{_sbindir}/pkcstok_migrate
%{_sbindir}/pkcsstats
%{_sbindir}/pkcshsm_mk_change
%{_sbindir}/pkcstok_admin
%{_mandir}/man1/pkcsconf.1*
%{_mandir}/man1/p11kmip.1*
%{_mandir}/man1/p11sak.1*
%{_mandir}/man1/pkcstok_migrate.1*
%{_mandir}/man1/pkcsstats.1*
%{_mandir}/man1/pkcshsm_mk_change.1*
%{_mandir}/man1/pkcstok_admin.1*
%{_mandir}/man5/%{name}.conf.5*
%{_mandir}/man5/p11sak_defined_attrs.conf.5*
%{_mandir}/man5/policy.conf.5*
%{_mandir}/man5/strength.conf.5*
%{_mandir}/man5/p11kmip.conf.5*
%{_mandir}/man7/%{name}.7*
%{_mandir}/man8/pkcsslotd.8*
%{_libdir}/opencryptoki/methods
%{_libdir}/pkcs11/methods
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/HSM_MK_CHANGE/
%dir %attr(770,root,pkcs11) %{_localstatedir}/lock/%{name}
%dir %attr(770,root,pkcs11) %{_localstatedir}/lock/%{name}/*
%dir %attr(710,pkcsslotd,pkcs11) /run/%{name}/

%files libs
%license LICENSE
%{_sysconfdir}/ld.so.conf.d/*
# Unversioned .so symlinks usually belong to -devel packages, but opencryptoki
# needs them in the main package, because:
#   documentation suggests that programs should dlopen "PKCS11_API.so".
%dir %{_libdir}/opencryptoki
%{_libdir}/opencryptoki/libopencryptoki.*
%{_libdir}/opencryptoki/PKCS11_API.so
%dir %{_libdir}/opencryptoki/stdll
%dir %{_libdir}/pkcs11
%{_libdir}/pkcs11/libopencryptoki.so
%{_libdir}/pkcs11/PKCS11_API.so
%{_libdir}/pkcs11/stdll
%dir %attr(770,root,pkcs11) %{_localstatedir}/log/opencryptoki


%files devel
%{_includedir}/%{name}/
%{_libdir}/pkgconfig/%{name}.pc

%files swtok
%{_libdir}/opencryptoki/stdll/libpkcs11_sw.*
%{_libdir}/opencryptoki/stdll/PKCS11_SW.so
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/swtok/
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/swtok/TOK_OBJ/

%files tpmtok
%doc doc/README.tpm_stdll
%{_libdir}/opencryptoki/stdll/libpkcs11_tpm.*
%{_libdir}/opencryptoki/stdll/PKCS11_TPM.so
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/tpm/

%files icsftok
%doc doc/README.icsf_stdll
%{_sbindir}/pkcsicsf
%{_mandir}/man1/pkcsicsf.1*
%{_libdir}/opencryptoki/stdll/libpkcs11_icsf.*
%{_libdir}/opencryptoki/stdll/PKCS11_ICSF.so
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/icsf/

%ifarch s390 s390x
%files icatok
%{_libdir}/opencryptoki/stdll/libpkcs11_ica.*
%{_libdir}/opencryptoki/stdll/PKCS11_ICA.so
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/lite/
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/lite/TOK_OBJ/
%endif

%files ccatok
%doc doc/README.cca_stdll
%config(noreplace) %{_sysconfdir}/%{name}/ccatok.conf
%{_sbindir}/pkcscca
%{_mandir}/man1/pkcscca.1*
%{_libdir}/opencryptoki/stdll/libpkcs11_cca.*
%{_libdir}/opencryptoki/stdll/PKCS11_CCA.so
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/ccatok/
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/ccatok/TOK_OBJ/

%ifarch s390 s390x
%files ep11tok
%doc doc/README.ep11_stdll
%config(noreplace) %{_sysconfdir}/%{name}/ep11tok.conf
%config(noreplace) %{_sysconfdir}/%{name}/ep11cpfilter.conf
%{_sbindir}/pkcsep11_migrate
%{_sbindir}/pkcsep11_session
%{_mandir}/man1/pkcsep11_migrate.1.*
%{_mandir}/man1/pkcsep11_session.1.*
%{_libdir}/opencryptoki/stdll/libpkcs11_ep11.*
%{_libdir}/opencryptoki/stdll/PKCS11_EP11.so
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/ep11tok/
%dir %attr(770,root,pkcs11) %{_sharedstatedir}/%{name}/ep11tok/TOK_OBJ/
%endif


%changelog
* Fri Nov 15 2019 Patrick Steuer <patrick.steuer@de.ibm.com> 3.12.0
- Update build time requirements
* Thu Oct 26 2017 Eduardo Barretto <ebarretto@linux.vnet.ibm.com> 3.8.0
- Update URL and source
- Remove unnecessary steps from spec file
* Tue Apr 25 2017 Eduardo Barretto <ebarretto@linux.vnet.ibm.com> 3.7.0
- Update spec file according to Fedora 25
- Add libitm as build dependency
- Added icsftok
- Added s390x ep11tok
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
