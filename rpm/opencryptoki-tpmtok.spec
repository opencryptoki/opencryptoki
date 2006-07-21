%define       token     tpm

Name:          opencryptoki
Version:       2.3.0
Release:       1%{?dist}
Summary:       An opencryptoki %{token} token 

Group:         Applications/Productivity 
License:       CPL 
URL:           http://sourceforge.net/projects/opencryptoki 
Source0:       %{name}-%{version}.tar.bz2 
BuildRoot:     %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires: autoconf automake libtool openssl-devel 
#Requires:       


%description
The openCryptoki package implements the PKCS#11 version 2.11: Cryptographic
Token Interface Standard (Cryptoki).


%package %{token} 
Summary:       Provides an opencryptoki %{token} token. 
Group:         Applications/Productivity
Requires:      opencryptoki = %{version}-%{release}, glibc-devel


%description %{token}
Provides an opencryptoki %{token} token. 


%prep 
%setup -q -n %{name}-%{version}


%build 
autoreconf --force --install
%configure --disable-static --disable-daemon --disable-swtok --enable-%{token}tok
make %{?_smp_mflags}


%install 
rm -rf $RPM_BUILD_ROOT
make install DESTDIR=$RPM_BUILD_ROOT 
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{name}/*.la
rm -f $RPM_BUILD_ROOT/%{_libdir}/%{name}/stdll/*.la


%clean 
rm -rf $RPM_BUILD_ROOT


%files %{token}
%defattr(-,root,root,-)
%doc FAQ LICENSE README
%dir %{_libdir}/%{name}
%dir %{_libdir}/%{name}/stdll
%{_libdir}/%{name}/stdll/libpkcs11_%{token}.so
%{_libdir}/%{name}/stdll/libpkcs11_%{token}.so.0
%attr(755,root,root) %{_libdir}/%{name}/stdll/libpkcs11_%{token}.so.0.0.0


%changelog
* Tue Jul 2 2006 Daniel H Jones <danjones@us.ibm.com> 2.3.0-1
- initial file created

