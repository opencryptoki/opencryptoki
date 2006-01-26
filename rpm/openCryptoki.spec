#
# spec file for package openCryptoki (Version 2.2.2)
#
# Copyright (c) 2006 SUSE LINUX Products GmbH, Nuernberg, Germany.
# This file and all modifications and additions to the pristine
# package are under the same license as the package itself.
#
# Please submit bugfixes or comments via http://bugs.opensuse.org
#

# norootforbuild
# neededforbuild  gpp libgpp libica openssl openssl-devel

BuildRequires: aaa_base acl attr bash bind-libs bind-utils bison bzip2 coreutils cpio cpp cracklib cvs cyrus-sasl db diffutils e2fsprogs file filesystem fillup findutils flex gawk gdbm-devel gettext-devel glibc glibc-devel glibc-locale gpm grep groff gzip info insserv klogd less libacl libattr libcom_err libgcc libnscd libstdc++ libxcrypt libzio m4 make man mktemp module-init-tools ncurses ncurses-devel net-tools netcfg openldap2-client openssl pam pam-modules patch permissions popt procinfo procps psmisc pwdutils rcs readline sed strace sysvinit tar tcpd texinfo timezone unzip util-linux vim zlib zlib-devel autoconf automake binutils gcc gcc-c++ gdbm gettext libica libstdc++-devel libtool openssl-devel perl rpm

Name:         openCryptoki
Summary:      An Implementation of PKCS#11 (Cryptoki) v2.11 for IBM Cryptographic Hardware
Version:      2.2.2
Release:      2
License:      IBM Public License, Other License(s), see package
Group:        Productivity/Security
# :pserver:anonymous@cvs.sourceforge.net:/cvsroot/opencryptoki
# cvs co -r openCryptoki-2-1-5 -d openCryptoki-2-1-5 .
Source:       openCryptoki-2.2.2-rc2.tar.bz2
Source1:      openCryptoki.pkcsslotd
Source2:      openCryptoki-TFAQ.html
Patch0:       openCryptoki-autoconf.patch
Patch1:       openCryptoki-config.patch
Patch3:       openCryptoki-compile-fixes.patch
Patch4:       openCryptoki-no_mmap.patch
Patch5:       openCryptoki-per_user.patch
URL:          http://oss.software.ibm.com/developerworks/opensource/opencryptoki
BuildRoot:    %{_tmppath}/%{name}-%{version}-build
PreReq:       /usr/sbin/groupadd /usr/bin/id /usr/sbin/usermod /bin/sed
Requires:     libica
%define oc_cvs_tag openCryptoki-2.2.2-rc2
# the userland tools are only maintained in 32bit, when a 32bit
# userland compatibility is available for the corresponding 64bit
# architecture.
#
# Thus, the user is supposed to install the 32bit package and the
# additional 64bit package together.
#
#
# openCryptoki         contains the common files. is always installed natively
# openCryptoki-32bit   contains the 32bit binaries for native use and
#                      for the 'other' distribution
# openCryptoki-64bit   contains the 64bit binaries for use on the 'other' distribution
%define openCryptoki_32bit_arch %ix86 s390 ppc %arm
# support in the workings for: ppc64
# no support in sight for: ia64 x86_64
%define openCryptoki_64bit_arch s390x ppc64
# autobuild:/work/cd/lib/misc/group
#   openCryptoki    pkcs11:x:64:
%define pkcs11_group_id 64
# IBM maintains openCryptoki on these architectures:
ExclusiveArch: %openCryptoki_32bit_arch %openCryptoki_64bit_arch
#

%description
The PKCS#11 version 2.11 API implemented for the IBM cryptographic
cards. This package includes support for the IBM 4758 cryptographic
co-processor (with the PKCS#11 firmware loaded) and the IBM eServer
Cryptographic Accelerator (FC 4960 on pSeries).



%ifarch %openCryptoki_32bit_arch
%package 32bit
%else
%package 64bit
%endif
Summary:      An Implementation of PKCS#11 (Cryptoki) v2.11 for IBM Cryptographic Hardware
Group:        Productivity/Security
# this is needed to make sure the pkcs11 group exists before
# installation:
PreReq:       openCryptoki
%ifarch %openCryptoki_32bit_arch

%description 32bit
This is a re-packaged binary rpm. For the package source, please look
for the source of the package without the "32bit" ending

The PKCS#11 version 2.11 API implemented for the IBM cryptographic
cards. This package includes support for the IBM 4758 cryptographic
co-processor (with the PKCS#11 firmware loaded) and the IBM eServer
Cryptographic Accelerator (FC 4960 on pSeries).



%else

%description 64bit
This is a re-packaged binary rpm. For the package source, please look
for the source of the package without the "64bit" ending

The PKCS#11 version 2.11 API implemented for the IBM cryptographic
cards. This package includes support for the IBM 4758 cryptographic
co-processor (with the PKCS#11 firmware loaded) and the IBM eServer
Cryptographic Accelerator (FC 4960 on pSeries).



%endif
%package devel
Summary:      An Implementation of PKCS#11 (Cryptoki) v2.11 for IBM Cryptographic Hardware
Group:        Productivity/Security
Requires:     openCryptoki = %{version}-%{release}, glibc-devel, openssl-devel

%description devel
The PKCS#11 version 2.11 API implemented for the IBM cryptographic
cards. This package includes support for the IBM 4758 cryptographic
co-processor (with the PKCS#11 firmware loaded) and the IBM eServer
Cryptographic Accelerator (FC 4960 on pSeries).



%prep
%setup -n %{oc_cvs_tag}
%patch1
%patch3
%patch4
%patch5
cp %{SOURCE2} .
#find -name CVS -type d -print0 | xargs -0 rm -rfv

%build
autoreconf --force --install
CFLAGS="$RPM_OPT_FLAGS -D__USE_BSD" ./configure --prefix=/usr --libdir=%{_libdir}
make

%install
make install DESTDIR=$RPM_BUILD_ROOT INSROOT=$RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/usr/include
mkdir -p $RPM_BUILD_ROOT/var/lib/opencryptoki
mkdir -p $RPM_BUILD_ROOT/etc/init.d
mkdir -p $RPM_BUILD_ROOT/usr/sbin
cp -av %{S:1} $RPM_BUILD_ROOT/etc/init.d/pkcsslotd
ln -sfv ../../etc/init.d/pkcsslotd $RPM_BUILD_ROOT/usr/sbin/rcpkcsslotd
rm -rf $RPM_BUILD_ROOT/tmp
# Remove all development files
rm -f $RPM_BUILD_ROOT${_libdir}/opencryptoki/libopencryptoki.la
#
#       FIX to build it  on ppc64
#
# %ifarch ppc64
# rm -f $RPM_BUILD_ROOT/usr/lib/pkcs11/methods/pkcs11_startup
# rm -f $RPM_BUILD_ROOT/usr/lib/pkcs11/methods/pkcs_slot
# rm -f $RPM_BUILD_ROOT/usr/lib/pkcs11/stdll/PKCS11_SW.so
# rm -f $RPM_BUILD_ROOT/usr/sbin/pkcsslotd
# %endif

%pre
# autobuild:/work/cd/lib/misc/group
# openCryptoki    pkcs11:x:64:
/usr/sbin/groupadd -g %pkcs11_group_id -o -r pkcs11 2>/dev/null || true
# add root to group pkcs11 to enable root to run pkcsconf
/usr/sbin/usermod -G $(/usr/bin/id --groups --name root | /bin/sed \
-e 's/root//' -e '
# add the pkcs group if it is missing
/(^| )pkcs11( |$)/!s/$/ pkcs11/
# replace spaces by commas
y/ /,/
'),pkcs11  root
%ifarch %openCryptoki_32bit_arch

%postun
if [ -L %{_sysconfdir}/pkcs11 ] ; then
	rm %{_sysconfdir}/pkcs11
fi

%postun 32bit
# remove the openCryptoki start script
%{insserv_cleanup}
%endif

%ifarch %openCryptoki_32bit_arch

%post 32bit
# Old library name links
cd %{_libdir}/opencryptoki && ln -sf ./libopencryptoki.so PKCS11_API.so
ln -sf %{_sbindir} %{_libdir}/opencryptoki/methods
rm -rf %{_libdir}/pkcs11/stdll
if [ -d %{_libdir}/pkcs11 ] ; then
    cd %{_libdir}/pkcs11
    ln -sf ../opencryptoki/stdll stdll
    cd stdll
    [ -f libpkcs11_ica.so ] && ln -sf ./libpkcs11_ica.so PKCS11_ICA.so
    [ -f libpkcs11_sw.so ] && ln -sf ./libpkcs11_sw.so PKCS11_SW.so
fi

%else

%post 64bit
# Old library name for 64bit libs were under /usr/lib/pkcs11. For migration purposes only.
cd %{_libdir}/opencryptoki && ln -sf ./libopencryptoki.so /usr/lib/pkcs11/PKCS11_API.so64

%endif

%post
# Symlink from /var/lib/opencryptoki to /etc/pkcs11
if [ ! -L %{_sysconfdir}/pkcs11 ] ; then
	if [ -e %{_sysconfdir}/pkcs11/pk_config_data ] ; then
		mv %{_sysconfdir}/pkcs11/* %{_localstatedir}/lib/opencryptoki
		cd %{_sysconfdir} && rm -rf pkcs11 && \
			ln -sf %{_localstatedir}/lib/opencryptoki pkcs11
	fi
fi
###################################################################
%ifarch %openCryptoki_32bit_arch

%files
%defattr(-,root,root)
%doc openCryptoki-TFAQ.html
  # configuration directory
%dir %attr(755,root,pkcs11) /var/lib/opencryptoki

/etc/init.d/pkcsslotd
/usr/sbin/rcpkcsslotd
  # utilities
/usr/sbin/pkcsslotd
/usr/sbin/pkcs11_startup
/usr/sbin/pkcsconf
/usr/sbin/pkcs_slot
%dir %{_libdir}/opencryptoki
%dir %{_libdir}/opencryptoki/stdll

%files 32bit
%defattr(-,root,root)
  # these don't conflict because they only exist as 64bit binaries if
  # there is no 32bit version of them usable
%{_libdir}/opencryptoki/*.so
%{_libdir}/opencryptoki/*.0
%{_libdir}/opencryptoki/stdll/*.so
%{_libdir}/opencryptoki/stdll/*.0
%{_libdir}/pkcs11
%{_libdir}/libopencryptoki.so
%{_libdir}/libopencryptoki.so.0

%files devel
%defattr(-,root,root)
%dir %{_libdir}/opencryptoki
%dir %{_libdir}/opencryptoki/stdll
%{_libdir}/opencryptoki/*.la
%{_libdir}/opencryptoki/stdll/*.la
%{_includedir}/opencryptoki

###################################################################
%else # not openCryptoki_32bit_arch  but  64bit arch

%files 64bit
%defattr(-,root,root)
%{_libdir}/opencryptoki/*.so
%{_libdir}/opencryptoki/*.0
%{_libdir}/opencryptoki/stdll/*.so
%{_libdir}/opencryptoki/stdll/*.0
%{_libdir}/pkcs11
%{_libdir}/libopencryptoki.so
%{_libdir}/libopencryptoki.so.0
%endif

%changelog -n openCryptoki
* Thu Jan 12 2006 - hare@suse.de
- Update to 2.2.2-rc2
* Wed Jan 11 2006 - hare@suse.de
- Update to 2.2.1-rc2
- Fixed build errors
- Cleaned up spec file.
* Wed Dec 14 2005 - ro@suse.de
- copy TFAQ to build directory (fix build)
* Mon Dec 12 2005 - hare@suse.de
- Update to 2.1.6-rc5.
- Port fixes from SLES9 SP3.
* Tue Nov 15 2005 - uli@suse.de
- enabled for ARM
* Thu Feb 17 2005 - od@suse.de
- fix #50050:
- ./configure.in: wrong test against $host makes ppc(64) miss
-DPKCS64 in CFLAGS
- corrected: S390 flag was set for ppc in this conditional
* Mon Aug 16 2004 - ro@suse.de
- run full autoreconf / simplify specfile a little
* Tue Apr 27 2004 - hare@suse.de
- Print correct error message (#37427 again).
* Fri Apr 23 2004 - hare@suse.de
- Check for the correct module on startup (#37427)
* Sun Apr 18 2004 - olh@suse.de
- update to openCryptoki-2.1.5, ppc64 version (#39026)
* Wed Feb 18 2004 - ro@suse.de
- adapt filelist on ppc
* Thu Feb 12 2004 - kukuk@suse.de
- Fix owner/group of files/directories
* Fri Dec 05 2003 - ro@suse.de
- no need to specify "root" as supplementary group for root,
  it's already primary
* Wed Jul 30 2003 - hare@suse.de
- Update to openCryptoki-2.1.3
- Fixed configure errors.
* Mon Jun 23 2003 - ro@suse.de
- added directories to filelist
* Wed Jun 04 2003 - ro@suse.de
- remove CVS subdirs
- remove unpackaged files from buildroot
* Thu Nov 21 2002 - ro@suse.de
- removed duplicates from configure.in
* Tue Oct 01 2002 - froh@suse.de
- exclude ppc64 from the architectures, the package is built for.
  64bit mode is not supported by IBM yet; dlopen wrappers are also
  missing 64bit filename handling. (#20380)
- actually compress the openCryptoki-1.4*.tar.bz2
* Tue Sep 24 2002 - ro@suse.de
- make it even build ...
* Tue Sep 24 2002 - froh@suse.de
- make openCryptoki-XXbit PreReq: openCryptoki to enforce pkcs11 group
  creation before package installation (#20079)
- correct version number (the patch actiually lifts openCryptoki to 1.5)
- fix groupadd call to no longer silently ignore errors in all cases
  using (hopefully) posix exit codes.  alternative would be to use
  undocumented '-f' option of groupadd.
* Fri Sep 20 2002 - froh@suse.de
- add user root to group pkcs11 to enable root to administrate the
  crypto hardware support (#19566)
* Mon Aug 26 2002 - okir@suse.de
- misc security fixes (#18377)
* Fri Aug 23 2002 - froh@suse.de
- replaced openCryptoki-tools with openCryptoki-32bit and
  openCryptoki-64bit
* Thu Aug 22 2002 - froh@suse.de
- moved dlopen objects that are available for non-x86 out of the
  ifarch ix86
- moved postun to tools subpackge (which contains the daemon)
- removed include files.  no development support for now.
- replaced %%ix86, etc by appropriate generic %%openCryptoki_tools_arch
  and %%openCryptoki_no_tools_arch
* Wed Aug 21 2002 - ro@suse.de
- replaced all i386 occurrences with %%ix86
- changed filelist to what's really built
* Tue Aug 20 2002 - froh@suse.de
- split package to openCryptoki and openCryptoki-tools to allow
  parallel installation of 32bit tools with 64bit dlopen objects for
  foreign middleware.
- removed automatical insserv on install, because the package needs
  manual configuration (#18031)
* Mon Aug 12 2002 - froh@suse.de
- added missing %%post before insserv (Bug #17600)
* Fri Aug 09 2002 - kukuk@suse.de
- Fix path in PreReq.
* Wed Aug 07 2002 - froh@suse.de
- add groupadd pkcs11 in %%pre install
* Mon Jul 29 2002 - froh@suse.de
- updated to current version
- removed old START_ variable
* Fri Jun 14 2002 - ro@suse.de
- always use macros when calling insserv
* Tue Apr 09 2002 - bk@suse.de
- add lib64 support
* Tue Feb 05 2002 - froh@suse.de
- Added openssl to #neededforbuild, which is needed in addition to
  openssl-devel
* Wed Jan 30 2002 - froh@suse.de
- initial version
