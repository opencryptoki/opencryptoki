%define        base      opencryptoki

Name:          opencryptoki-libs 
Version:       2.2.4
Release:       1%{?dist}
Summary:       An Implementation of PKCS#11 (Cryptoki) v2.11 

Group:         Applications/Productivity 
License:       CPL 
URL:           http://sourceforge.net/projects/opencryptoki 
Source0:       %{base}-%{version}.tar.bz2 
BuildRoot:     %{_tmppath}/%{base}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf automake libtool openssl-devel 
#Requires:       

%description
The openCryptoki package implements the PKCS#11 version 2.11: Cryptographic 
Token Interface Standard (Cryptoki).


%prep
%setup -q -n %{base}-%{version}


%build
autoreconf --force --install
%configure --disable-static --disable-daemon 
make %{?_smp_mflags}


%install
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT 
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{base}/*.la
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{base}/stdll/*.la


%postun -p /sbin/ldconfig 


%post -p /sbin/ldconfig 


%clean
rm -rf $RPM_BUILD_ROOT


%files
%defattr(-,root,root,-)
%doc LICENSE
%config(noreplace) %{_sysconfdir}/ld.so.conf.d/%{base}*.conf
%dir %{_libdir}/%{base}
%dir %{_libdir}/%{base}/stdll
%{_libdir}/%{base}/libopencryptoki.so
%{_libdir}/%{base}/libopencryptoki.so.0
%attr(755,root,root) %{_libdir}/%{base}/libopencryptoki.so.0.0.0
%{_libdir}/%{base}/methods
%{_libdir}/%{base}/stdll/libpkcs11_*.so
%{_libdir}/%{base}/stdll/libpkcs11_*.so.0
%attr(755,root,root) %{_libdir}/%{base}/stdll/libpkcs11_*.so.0.0.0
# symlinks for backward compatibility
%dir %{_libdir}/pkcs11
%dir %{_libdir}/pkcs11/stdll
%dir %{_libdir}/pkcs11/methods
%{_libdir}/pkcs11/PKCS11_API.so
%{_libdir}/%{base}/PKCS11_API.so
%ifarch s390 s390x
%{_libdir}/%{base}/stdll/PKCS11_ICA.so
%else
%{_libdir}/%{base}/stdll/PKCS11_SW.so
%endif



%changelog
* Thu Aug 7 2006 Daniel H Jones <danjones@us.ibm.com> 
- initial file created

