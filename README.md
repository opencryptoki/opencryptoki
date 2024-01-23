[![Build Status](https://app.travis-ci.com/opencryptoki/opencryptoki.svg?branch=master)](https://app.travis-ci.com/opencryptoki/opencryptoki)
['![Coverity Scan Build Status](https://img.shields.io/coverity/scan/16802.svg)'](https://scan.coverity.com/projects/opencryptoki-opencryptoki)

# openCryptoki

Package version 3.23

Please see [ChangeLog](ChangeLog) for release specific information.

## OVERVIEW

openCryptoki version 3.23 implements the PKCS#11 specification version 3.0.

This package includes several cryptographic tokens:
CCA, ICA, TPM , SWToken, ICSF and EP11.

For a more in-depth overview of openCryptoki, please refer to manual
[openCryptoki - An Open Source Implementation of PKCS #11](https://www.ibm.com/docs/en/linux-on-systems?topic=11-version-317)

**Note:** The TPM token is deprecated, because it supports only TPM version 1.2.
Does not work with TPM version 2.0. We plan to remove the TPM token in a future 
openCryptoki release or version.

## REQUIREMENTS:

- IBM ICA - requires libica library version 3.3.0 or higher for accessing ICA
hardware crypto on IBM zSeries.

- IBM CCA - requires IBM XCrypto CEX3C card (or higher) and the CEX3C host
libraries and tools version 4.1 (or higher).

- TPM (**deprecated**) - requires a TPM, TPM tools, and TCG software stack.
Supports TPM version 1.2 only. 

- SWToken - The software token uses OpenSSL version 1.1.1 or higher.

- ICSF    - The Integrated Cryptographic Service Facility (ICSF) token requires
openldap and openldap client software version 2.4.23 or higher. Lex and Yacc are
also required to build this token.

- EP11    - The EP11 token is a token that uses the IBM Crypto Express adapters
(starting with Crypto Express 4S adapters) configured with Enterprise PKCS#11
(EP11) firmware.

## BUILD PROCESS

The simplest way to compile this package is to enter the source code main
directory and do the following:

1. Run the bootstrap.sh script by typing:

```
    $ ./bootstrap.sh
```

**Note:** This package used the `AX_PROG_CC_FOR_BUILD` autoconf macro
from the autoconf archive to support cross compiler builds.
If your system does not provide this macro, you might need to install the
`autoconf-archive` package or download the macro and place it into the
`m4` directory. 
See [https://www.gnu.org/software/autoconf-archive/ax_prog_cc_for_build.html](https://www.gnu.org/software/autoconf-archive/ax_prog_cc_for_build.html)
for a link to the latest version of `ax_prog_cc_for_build.m4`.

2. Configure the source code by typing:

```
    $ ./configure
```

   If you're planning to install the package into your home directory or to a
   location other than `/usr/local` then add the flag `--prefix=PATH` to
   `configure`. Fox example, if your home directory is `/home/luser` you can
   configure the package to install itself there by invoking:

```
    $ ./configure --prefix=/home/luser
```

   If your stdll headers and libraries are not under any standard path, you will
   need to pass the paths to your files to the configure script. For instance:

```
    $ CPPFLAGS="-L/path/lib" LDFLAGS="-I/path/include" ./configure
```

   See `./configure --help` for info on various options. The default behavior is
   to build a default token implicitly. For the s390 platform, the default token
   is ICA. For other platforms, the default token is the software token. Other
   tokens may be enabled using the corresponding `--enable-<tok>` configuration
   option provided the appropriate libraries are available.

   While running, `configure` prints some messages telling which features is it
   checking for.

3. Compile the package by typing:

```
    $ make
```
   **Note:** Do not specify `prefix=/foo/bar`, `libdir=/foo/bar` with
   the `make` invocation. Specify them with `configure` instead. Specifying
   them with `make` is not supported by the openCryptoki package and may
   produce unexpected results!

4. openCryptoki defaults to be usable by anyone who is in the group ``pkcs11``.
Add the pkcs11 group before installing it, by typing as root the command:

```
    # groupadd pkcs11
```

   In addition, add the necessary user to the pkcs11 group (root doesn't need to
   be in pkcs11 group):

```
    # usermod -a -G pkcs11 <user>
```

5. Type `make install` (as root) to install the programs and any data files and
documentation.  During installation, the following files go to the following
directories:

```
    /prefix/sbin/pkcsconf
    /prefix/sbin/pkcsslotd
    /prefix/sbin/pkcsicsf
    /prefix/libdir/libopencryptoki.so
    /prefix/libdir/libopencryptoki.so.0
    /prefix/libdir/opencryptoki/libopencryptoki.so
    /prefix/libdir/opencryptoki/libopencryptoki.so.0
    /prefix/libdir/opencryptoki/libopencryptoki.so.0.0.0
    /prefix/var/lib/opencryptoki
    /prefix/etc/opencryptoki/opencryptoki.conf
```

   Token objects, which may be optionally built, go to the following locations:

```
    /prefix/libdir/opencryptoki/stdll/libpkcs11_cca.so
    /prefix/libdir/opencryptoki/stdll/libpkcs11_cca.so.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_cca.so.0.0.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_ep11.so
    /prefix/libdir/opencryptoki/stdll/libpkcs11_ep11.so.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_ep11.so.0.0.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_ica.so
    /prefix/libdir/opencryptoki/stdll/libpkcs11_ica.so.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_ica.so.0.0.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_icsf.so
    /prefix/libdir/opencryptoki/stdll/libpkcs11_icsf.so.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_icsf.so.0.0.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_sw.so
    /prefix/libdir/opencryptoki/stdll/libpkcs11_sw.so.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_sw.so.0.0.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_tpm.so
    /prefix/libdir/opencryptoki/stdll/libpkcs11_tpm.so.0
    /prefix/libdir/opencryptoki/stdll/libpkcs11_tpm.so.0.0.0
```

   where `prefix` is either `/usr/local` or the PATH that you specified in the
   `--prefix` flag. `libdir` is the name of the library directory, for 32-bit
   libraries it is usually `lib` and for 64-bit libraries it is usually `lib64`.

   To maintain backwards compatibility, some additional symlinks are generated
   (note that these are deprecated and applications should migrate to use the
   LSB-compliant names and locations for libraries and executable):

```
    /prefix/lib/opencryptoki/PKCS11_API.so
    - Symlink to /prefix/lib/opencryptoki/libopencryptoki.so

    /prefix/lib/opencryptoki/stdll/PKCS11_CCA.so
    - Symlink to /prefix/lib/opencryptoki/stdll/libpkcs11_cca.so

    /prefix/lib/opencryptoki/stdll/PKCS11_EP11.so
    - Symlink to /prefix/lib/opencryptoki/stdll/libpkcs11_ep11.so

    /prefix/lib/opencryptoki/stdll/PKCS11_ICA.so
    - Symlink to /prefix/lib/opencryptoki/stdll/libpkcs11_ica.so

    /prefix/lib/opencryptoki/stdll/PKCS11_ICSF.so
    - Symlink to /prefix/lib/opencryptoki/stdll/libpkcs11_icsf.so

    /prefix/lib/opencryptoki/stdll/PKCS11_SW.so
    - Symlink to /prefix/lib/opencryptoki/stdll/libpkcs11_sw.so

    /prefix/lib/pkcs11/PKCS11_API.so
    - Symlink to /prefix/lib/opencryptoki/libopencryptoki.so

    /prefix/lib/pkcs11
    - Directory created if non-existent

    /prefix/lib/pkcs11/methods
    - Symlink to /prefix/sbin

    /prefix/lib/pkcs11/stdll
    - Symlink to /prefix/lib/opencryptoki/stdll

    /prefix/etc/pkcs11
    - Symlink to /prefix/var/lib/opencryptoki
```

   If any of these directories do not presently exist, they will be created on
   demand. Note that if `prefix` is `/usr`, then `/prefix/var` and `/prefix/etc`
   resolve to `/var` and `/etc`. On the `make install` stage, if content exists
   in the old `/prefix/etc/pkcs11` directory, it will be migrated to the new
   '/prefix/var/lib/opencryptoki` location.

   If you are installing in your home directory make sure that `/home/luser/bin`
   is in your path.  If you're using the bash shell add this line at the end of
   your `.bashrc` file:

```
    PATH="/home/luser/bin:${PATH}"
    export PATH
```

   If you are using csh or tcsh, then use this line instead:

```
    setenv PATH /home/luser/bin:${PATH}
```

   By prepending your home directory to the rest of the PATH you can override
   systemwide installed software with your own custom installation.

   For more installation information, please check [INSTALL](INSTALL).

## CONFIGURATION

See:
https://www.ibm.com/support/knowledgecenter/linuxonibm/com.ibm.linux.z.lxce/lxce_stackoverview.html

Prior to version 3, openCryptoki used `pk_config_data` as its configuration
file. This file was created upon running `pkcs11_startup`. In version 3,
`pkcs11_startup` and `pk_config_data` have been removed and replaced with a
customizable config file named, `opencryptoki.conf`. It contains an entry for
each token currently supported by openCryptoki. However, only those token, whose
hardware and software requirements are available on the local system, will show
up as present and available upon running the `pkcsconf -t` command.

Before using, each token must be first initialized. You can select the token
with the `-c` command line option; refer to the documentation linked to above
for further instructions.

Initialize a particular token by running `pkcsconf`:

```
    $ pkcsconf -I -c
```

In this version of openCryptoki, the default SO PIN is `87654321`. This should
be changed to a different PIN value before use.

You can change the SO PIN by running pkcsconf:

```
    $ pkcsconf -P -c
```

You can initialize and change the user PIN by typing:

```
    $ pkcsconf -u -c
```

You can later change the user PIN again by typing:

```
    $ pkcsconf -p -c
```

## CONTRIBUTING

See [CONTRIBUTING.md](CONTRIBUTING.md).
