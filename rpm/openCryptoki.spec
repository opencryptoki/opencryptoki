%define sub_version 6
Name: openCryptoki
Summary: Implementation of Cryptoki v2.11 for IBM Crypto Hardware
Version: 2.1.5
Release: 9
License: Other License(s), see package
Group: Productivity/Security
Source: %{name}-%{version}-%{sub_version}.tar.bz2
Source1: pkcsslotd.init
Url: http://oss.software.ibm.com/developerworks/opensource/opencryptoki
BuildRoot: %{_tmppath}/%{name}-%{version}-build
PreReq: shadow-utils coreutils sed
BuildPreReq: openssl-devel >= 0.9.7a-28

%description
The PKCS#11 Version 2.11 api implemented for the IBM Crypto cards.
This package includes support for the IBM 4758 Cryptographic
CoProcessor (with the PKCS#11 firmware loaded) and the IBM eServer
Cryptographic Accelerator (FC 4960 on pSeries)

Summary:      Implementation of PKCS#11 (Cryptoki) v2.11 for IBM Crypto Hardware
Group:        Productivity/Security

%prep
%setup -q -n openCryptoki-%{version}-%{sub_version}

%build

autoreconf --force --install
%configure
#./configure --libdir=%{_libdir}
make -f Makefile

%install
# according to the stuff, / can not be build root... So
# if build root is set, then we can muck with it
if [[ $RPM_BUILD_ROOT  ]] ;
then
	rm -rf $RPM_BUILD_ROOT
	mkdir -p $RPM_BUILD_ROOT
        # the makefiles want INSROOT set for an alternative install path
	export INSROOT=$RPM_BUILD_ROOT
fi
#make -f Makefile install
%makeinstall -f Makefile
mkdir -p $RPM_BUILD_ROOT/usr/include

# Install initscript
mkdir -p $RPM_BUILD_ROOT%{_sysconfdir}/rc.d/init.d
install -m 755 %{SOURCE1} $RPM_BUILD_ROOT%{_sysconfdir}/rc.d/init.d/pkcsslotd

%clean
#make -f Makefile clean

%pre
/usr/sbin/groupadd -r pkcs11 2>/dev/null || true
/usr/sbin/usermod -G $(/usr/bin/id --groups --name root | /bin/sed -e '
# add the pkcs group if it is missing
/(^| )pkcs11( |$)/!s/$/ pkcs11/
# replace spaces by commas
y/ /,/
'),pkcs11  root

%post
cd %{_libdir}/opencryptoki && ln -sf ./libopencryptoki.so PKCS11_API.so
rm -rf %{_libdir}/pkcs11/stdll
cd %{_libdir}/pkcs11 && ln -sf ../opencryptoki/stdll stdll
cd %{_libdir}/pkcs11/stdll && ln -sf ./libpkcs11_ica.so PKCS11_ICA.so \
	&& ln -sf ./libpkcs11_sw.so PKCS11_SW.so

# Symlink from /var/lib/opencryptoki to /etc/pkcs11
if [ ! -L %{_sysconfdir}/pkcs11 ] ; then
	if [ -e %{_sysconfdir}/pkcs11/* ] ; then
		mv %{_sysconfdir}/pkcs11/* %{_localstatedir}/lib/opencryptoki
	fi
fi
cd %{_sysconfdir} && rm -rf pkcs11 && \
			ln -sf %{_localstatedir}/lib/opencryptoki pkcs11

# Make sure the permissions are set correctly
chown root:pkcs11 %{_localstatedir}/lib/opencryptoki
chmod 755 %{_localstatedir}/lib/opencryptoki

%files
%defattr(-,root,root)
%{_sysconfdir}/rc.d/init.d/pkcsslotd
%{_sbindir}/pkcsslotd
%{_sbindir}/pkcs11_startup
%{_sbindir}/pkcsconf
%{_sbindir}/pkcs_slot
%{_libdir}/opencryptoki/libopencryptoki.so
%{_libdir}/opencryptoki/libopencryptoki.so.0.0.0
%{_libdir}/opencryptoki/libopencryptoki.la
%{_libdir}/pkcs11/PKCS11_API.so
%{_libdir}/opencryptoki/stdll/libpkcs11_ica.so
%{_libdir}/opencryptoki/stdll/libpkcs11_ica.so.0.0.0
%{_libdir}/opencryptoki/stdll/libpkcs11_ica.la
%{_libdir}/pkcs11/stdll/PKCS11_ICA.so
%{_libdir}/opencryptoki/stdll/libpkcs11_sw.so
%{_libdir}/opencryptoki/stdll/libpkcs11_sw.so.0.0.0
%{_libdir}/opencryptoki/stdll/libpkcs11_sw.la
%{_libdir}/pkcs11/stdll/PKCS11_SW.so
%{_includedir}/opencryptoki

%changelog
* Wed Mar 02 2005 Phil Knirsch <pknirsch@redhat.com> 2.1.5-6.9
- bump release and rebuild with gcc 4

* Mon Sep 27 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.5-6.8
- Fixed segfault for service status check of pkcsslotd (#133091)

* Tue Jun 15 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Tue Jun 15 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.5-6.1
- Updated to latest upstream version openCryptoki-2.1.5-6.tar.bz2

* Tue May 11 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.5-2
- Added requires for 32bit packages for 64bit package.

* Wed Apr 07 2004 Phil Knirsch <pknirsch@redhat.com>
- Update to latest version from IBM which includes important fixes (#119363)
- Create pkcs11 group.

* Thu Mar 25 2004 Tim Powers <timp@redhat.com> 2.1.3-12
- rebuilt to fix broken deps

* Tue Mar 16 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.3-11
- rebuilt

* Thu Mar 04 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.3-10
- Converted initsc
ript to UNIX file format, was in DOS.

* Wed Mar 03 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.3-9
- Minor fixes to pkcsslotd initscript.
- Really fixed permissions this time for initscript.

* Thu Feb 26 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.3-8
- Included updated initscript from IBM (#112542).
- Changed permission of /etc/init.d/pkcsslotd to be executable (#112542).

* Sat Feb 21 2004 Florian La Roche <Florian.LaRoche@redhat.de>
- mv /etc/init.d -> /etc/rc.d/init.d

* Thu Feb 19 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.3-7
- rebuilt

* Wed Feb 18 2004 Phil Knirsch <pknirsch@redhat.com>  2.1.3-6
- Fixed small bug in files section.

* Fri Feb 13 2004 Elliot Lee <sopwith@redhat.com>
- rebuilt

* Wed Feb 11 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.3-4
- Fixed some smaller build problems.
- Included and fixed new initscript for pkcs11 startup.
- Fixed filelist.

* Thu Jan 15 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.3-3
- rebuilt

* Thu Jan 15 2004 Phil Knirsch <pknirsch@redhat.com> 2.1.3-2
- Fixed missing defattr (#113343).

* Tue Nov 11 2003 Phil Knirsch <pknirsch@redhat.com> 2.1.3-1
- Initial Red Hat package.
