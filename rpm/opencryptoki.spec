Name:          opencryptoki 
Version:       2.2.5
Release:        1%{?dist}
Summary:       An Implementation of PKCS#11 (Cryptoki) v2.11 

Group:         Applications/Productivity 
License:       CPL 
URL:           http://sourceforge.net/projects/opencryptoki 
Source0:       %{name}-%{version}.tar.bz2 
BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

Prereq: /sbin/chkconfig
BuildRequires: autoconf automake libtool openssl-devel 
#Requires:       


%description
The openCryptoki package implements the PKCS#11 version 2.11: Cryptographic 
Token Interface Standard (Cryptoki).


%package devel
Summary:       An Implementation of PKCS#11 (Cryptoki) v2.11
Group:         Applications/Productivity
Requires:      opencryptoki = %{version}-%{release}, glibc-devel


%description devel
The openCryptoki package implements the PKCS#11 version 2.11: Cryptographic
Token Interface Standard (Cryptoki).


%prep
%setup -q -n %{name}-%{version}


%build
autoreconf --force --install
%configure --disable-static
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT 
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{name}/*.la
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{name}/stdll/*.la


%preun
if [ "$1" = "0" ]; then
	/sbin/chkconfig --del pkcsslotd
fi


%postun -p /sbin/ldconfig 


%post
if [ "$1" = "0" ]; then
	/sbin/chkconfig --add pkcsslotd
fi
/sbin/ldconfig


%clean
rm -rf $RPM_BUILD_ROOT


%pre
/usr/sbin/groupadd -r pkcs11 2>/dev/null || true
/usr/sbin/usermod -G $(/usr/bin/id --groups --name root | /bin/sed -e '
# add the pkcs group if it is missing
/(^| )pkcs11( |$)/!s/$/ pkcs11/
# replace spaces by commas
y/ /,/
'),pkcs11  root


%files
%defattr(-,root,root,-)
%doc FAQ LICENSE README
%config(noreplace) %{_sysconfdir}/ld.so.conf.d/%{name}.conf
%config(noreplace) %{_sysconfdir}/ld.so.conf.d/%{name}-stdll.conf
%dir %attr(755,root,pkcs11) /var/lib/%{name}
%{_sbindir}/pkcsslotd
%{_sbindir}/pkcsconf
%{_sbindir}/pkcs_slot
%{_sbindir}/pkcs11_startup
%dir %{_libdir}/%{name}
%dir %{_libdir}/%{name}/stdll
%{_libdir}/libopencryptoki.so
%{_libdir}/libopencryptoki.so.0
%{_libdir}/%{name}/libopencryptoki.so
%{_libdir}/%{name}/libopencryptoki.so*.0
%{_libdir}/%{name}/methods
%{_libdir}/%{name}/stdll/libpkcs11_*.so
%{_libdir}/%{name}/stdll/libpkcs11_*.so*.0
%{_initrddir}/pkcsslotd
# symlinks for backward compatibility
%dir %{_libdir}/pkcs11
%dir %{_libdir}/pkcs11/stdll
%dir %{_libdir}/pkcs11/methods
%{_libdir}/pkcs11/PKCS11_API.so
%{_libdir}/%{name}/PKCS11_API.so
%{_libdir}/%{name}/stdll/PKCS11_SW.so


%files devel
%defattr(-,root,root,-)
%dir %{_includedir}/%{name}
%{_includedir}/%{name}/apiclient.h
%{_includedir}/%{name}/pkcs11.h
%{_includedir}/%{name}/pkcs11types.h


%changelog
* Thu May 25 2006 Daniel H Jones <danjones@us.ibm.com> 2.2.4-1
- initial file created

