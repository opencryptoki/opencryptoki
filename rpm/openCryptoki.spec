#
# spec file for package openCryptoki
#
# This file respectfully borrowed from Suse's openCryptoki packaging.
#

Name:         openCryptoki
Summary:      Implementation of PKCS#11 (Cryptoki) v2.1.3 for IBM Crypto Hardware
Version:      2.1.5
Release:      6
License:      Other License(s), see package
Group:        Productivity/Security
Source:       openCryptoki.tar.gz
Url:          http://oss.software.ibm.com/developerworks/opensource/opencryptoki
#BuildRoot:    %{_tmppath}/%{name}-%{version}-build
PreReq:       /usr/sbin/groupadd /usr/bin/id /usr/sbin/usermod /bin/sed
%define _topdir /usr/src/openCryptoki
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
%define openCryptoki_32bit_arch %ix86 s390 ppc
# support in the workings for: ppc64
# no support in sight for: ia64 x86_64
%define openCryptoki_64bit_arch s390x ppc64
# autobuild:/work/cd/lib/misc/group
#   openCryptoki    pkcs11:x:64:
%define pkcs11_group_id 64
# IBM maintains openCryptoki on these architectures:
ExclusiveArch: %openCryptoki_32bit_arch %openCryptoki_64bit_arch
#
# this section makes 64bit platforms require the 32bit rpm before it will install
%ifos Linux
%ifarch %openCryptoki_32bit_arch
Provides: openCryptoki-2.1-0
%endif
%ifarch %openCryptoki_64bit_arch
Requires: openCryptoki-2.1-0, libica >= 1.3.4
%endif
%endif
#
# This is a hack, required because rpm 4.x is broken WRT the AutoReq:no and
# AutoReqProv:no directives. The hack disables rpm's ability to automatically
# find and fill in packages that it thinks openCryptoki requires. - KEY
#%define __find_requires %{nil}
%define __find_requires /usr/lib/rpm/find-requires

%description
The PKCS#11 Version 2.11 api implemented for the IBM Crypto cards.
This package includes support for the IBM 4758 Cryptographic
CoProcessor (with the PKCS#11 firmware loaded) and the IBM eServer
Cryptographic Accelerator (FC 4960 on pSeries)

%ifarch %openCryptoki_32bit_arch
%package 32bit
%else
%package 64bit
%endif
Summary:      Implementation of PKCS#11 (Cryptoki) v2.11 for IBM Crypto Hardware
Group:        Productivity/Security
# this is needed to make sure the pkcs11 group exists before
# installation:
PreReq:       openCryptoki
%ifarch %openCryptoki_32bit_arch

%description 32bit
The PKCS#11 Version 2.11 api implemented for the IBM Crypto cards.
This package includes support for the IBM 4758 Cryptographic
CoProcessor (with the PKCS#11 firmware loaded) and the IBM eServer
Cryptographic Accelerator (FC 4960 on pSeries)

%else

%description 64bit
The PKCS#11 Version 2.11 api implemented for the IBM Crypto cards.
This package includes support for the IBM 4758 Cryptographic
CoProcessor (with the PKCS#11 firmware loaded) and the IBM eServer
Cryptographic Accelerator (FC 4960 on pSeries)

%endif
%prep
#ln -s openCryptoki-1.4-1-CVS openCryptoki-1.4
#ln -s openCryptoki-1.4-1-CVS openCryptoki-1.5
#%setup -D
#%setup -T -D -a 1
#%patch0 -p1
%setup -c openCryptoki-%{version}

%build
# Create the pkcs11 group if it doesn't exist yet
/usr/sbin/groupadd -g %pkcs11_group_id -o -r pkcs11 || {
    RC=$?
    case $RC in
	9)  # the group pkcs11 already exists
	    echo "this is ok";;
	*)  # disgracefully fail
	    exit $RC;;
    esac
}
#./autoversion
#autoreconf --force --install
%ifarch %openCryptoki_64bit_arch
./configure --libdir=/usr/lib64
%endif
#/bin/pwd
#/usr/bin/aclocal
#/usr/bin/automake
#/usr/bin/autoconf
#./configure
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
mkdir -p $RPM_BUILD_ROOT/usr/include
make -f Makefile install
#cp -a SuSE/* $RPM_BUILD_ROOT
cp -a usr/include/opencryptoki $RPM_BUILD_ROOT/usr/include
# Create var/lib/opencryptoki and set the permissions correctly
mkdir -p $RPM_BUILD_ROOT/var/lib/opencryptoki
for f in /var/lib/opencryptoki /usr/lib/opencryptoki /usr/sbin/pkcsslotd
  do
  test -e $RPM_BUILD_ROOT/$f && chgrp -R pkcs11 $RPM_BUILD_ROOT/$f
done

%clean
#make -f Makefile clean

%pre
# autobuild:/work/cd/lib/misc/group
# openCryptoki    pkcs11:x:64:
/usr/sbin/groupadd -g %pkcs11_group_id -o -r pkcs11 2>/dev/null || true
# add root to group pkcs11 to enable root to run pkcsconf
/usr/sbin/usermod -G $(/usr/bin/id --groups --name root | /bin/sed -e '
# add the pkcs group if it is missing
/(^| )pkcs11( |$)/!s/$/ pkcs11/
# replace spaces by commas
y/ /,/
'),pkcs11  root
%ifarch %openCryptoki_32bit_arch

%postun 32bit
# remove the openCryptoki start script
#%{insserv_cleanup}
%endif
###################################################################

%files
###################################################################
# package shared objects if on a 64bit architecture
%ifarch %openCryptoki_32bit_arch
  # utilities
  /usr/sbin/pkcsslotd
  # these don't conflict because they only exist as 64bit binaries if
  # there is no 32bit version of them usable
  /usr/sbin/pkcs11_startup
  /usr/sbin/pkcsconf
  /usr/sbin/pkcs_slot
%files 32bit
  # these don't conflict because of the different suffix
  /usr/lib/opencryptoki/libpkcs11_api.so
  /usr/lib/opencryptoki/stdll/libpkcs11_ica.so
  %ifarch %ix86
%   /usr/lib/pkcs11/methods/4758_status
    /usr/lib/opencryptoki/stdll/libpkcs11_sw.so
    /usr/lib/opencryptoki/stdll/libpkcs11_4758.so
    /usr/lib/opencryptoki/stdll/libpkcs11_cr.so
    /usr/lib/opencryptoki/stdll/libpkcs11_bc.so
    /usr/lib/opencryptoki/stdll/libpkcs11_aep.so
  %endif
###################################################################
%else # not openCryptoki_32bit_arch  but  64bit arch

%files 64bit
/usr/lib64/opencryptoki/libpkcs11_api.so
/usr/lib64/opencryptoki/stdll/libpkcs11_ica.so
%endif

