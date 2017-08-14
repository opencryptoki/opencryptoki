# PKCS #11 openCryptoki for Linux HOWTO

v1 - Kristin Thomas - kristint@us.ibm.com

v2 - Eduardo Barretto - ebarretto@linux.vnet.ibm.com

This HOWTO describes the implementation of the RSA Security Inc./Organization
for the Advancement of Structured Information Standards (OASIS) Public Key
Cryptographic Standard #11 (PKCS #11) cryptoki application program interface
(API) on Linux (openCryptoki). The HOWTO explains what services openCryptoki
provides and how to build and install it. Additional resources and a simple
sample program are also provided.

## Table of contents
1. [Copyright Notice and Disclaimer](#1-copyright-notice-and-disclaimer)<br>
2. [Introduction](#2-introduction)<br>
3. [What is openCryptoki?](#3-what-is-opencryptoki)<br>
4. [Architectural Overview](#4-architectural-overview)<br>
    4.1. [Slot Manager](#41-slot-manager)<br>
    4.2. [Main API](#42-main-api)<br>
    4.3. [Slot Token Dynamic Link
    Libraries](#43-slot-token-dynamic-link-libraries)<br>
    4.4. [Shared Memory](#44-shared-memory)<br>
5. [Getting Started with openCryptoki](#5-getting-started-with-opencryptoki)<br>
    5.1. [System Requirements](#51-system-requirements)<br>
    5.2. [Obtaining openCryptoki](#52-obtaining-opencryptoki)<br>
    5.3. [Compiling and Installing
    openCryptoki](#53-compiling-and-installing-opencryptoki)<br>
6. [Configuring openCryptoki](#6-configuring-opencryptoki)<br>
7. [Components of openCryptoki](#7-components-of-opencryptoki)<br>
    7.1. [Slot Manager Daemon](#71-slot-manager-daemon)<br>
    7.2. [libopencryptoki.so](#72-libopencryptokiso)<br>
    7.3. [Slot Token DLLs](#73-slot-token-dlls)<br>
&nbsp;  7.3.1. [Trusted Module Platform](#731-trusted-module-platform-tpm)<br>
&nbsp;  7.3.2. [IBM Cryptographic Architecture (ICA)](#732-ibm-cryptographic-architecture-ica)<br>
&nbsp;  7.3.3. [IBM Common Cryptographic Architecture (CCA)](#733-ibm-common-cryptographic-architecture-cca)<br>
&nbsp;  7.3.4. [Software Token](#734-software-token)<br>
&nbsp;  7.3.5. [IBM Enterprise PKCS #11 (EP11)](#735-ibm-enterprise-pkcs-11-ep11)<br>
&nbsp;  7.3.6. [IBM Integrated Cryptographic Service Facility (ICSF)](#736-ibm-integrated-cryptographic-service-facility-icsf)<br>
8. [Applications and openCryptoki](#8-application-and-opencryptoki)<br>
    8.1. [Making openCryptoki Available to
    Applications](#81-making-opencryptoki-available-to-applications)<br>
    8.2. [Writing an Application](#82-writing-an-application)<br>
9. [Resources](#9-resources)<br>
10. [Appendix A: Sample Program](#10-appendix-a-sample-program)<br>
    10.1. [Sample Program](#101-sample-program)<br>
    10.2. [Makefile](#102-makefile)<br>


### 1. Copyright Notice and Disclaimer

Copyright © 2001 - 2017 IBM Corporation. All rights reserved.

This document may be reproduced or distributed in any form without prior
permission provided the copyright notice is retained on all copies. Modified
versions of this document may be freely distributed, provided that they are
clearly identified as such, and this copyright is included intact.

This document is provided "AS IS," with no express or implied warranties. Use
the information in this document at your own risk.

**Special Notices**

This publication/presentation was produced in the United States. IBM may not
offer the products, programs, services or features discussed herein in other
countries, and the information may be subject to change without notice. Consult
your local IBM business contact for information on the products, programs,
services, and features available in your area. Any reference to an IBM product,
program, service, or feature is not intended to state or imply that only IBM’s
product, program, service, or feature may be used. Any functionally equivalent
product, program, service, or feature that does not infringe on IBM’s
intellectual property rights may be used instead.

Questions on the capabilities of non-IBM products should be addressed to
suppliers of those products. IBM may have patents or pending patent applications
covering subject matter in this presentation. Furnishing this presentation does
not give you any license to these patents. Send license inquiries, in writing,
to IBM Director of Licensing, IBM Corporation, New Castle Drive, Armonk, NY
10504-1785 USA. All statements regarding IBM’s future direction and intent are
subject to change or withdrawal without notice, and represent goals and
objectives only. Contact your local IBM office or IBM authorized reseller for
the full text of a specific Statement of General Direction.

The information contained in this presentation has not been submitted to any
formal IBM test and is distributed "AS IS." While each item may have have been
reviewed by IBM for accuracy in a specific situation, there is no guarantee that
the same or similar results will be obtained elsewhere. The use of this
information or the implementation of any techniques described herein is a
customer responsibility and depends on the customer’s ability to evaluate and
integrate them into the customer’s operational environment. Customers attempting
to adapt these techniques to their own environments do so at their own risk.

The information contained in this document represents the current views of IBM
on the issues discussed as of the date of publication. IBM cannot guarantee the
accuracy of any information presented after the date of publication.

Any performance data in this document was determined in a controlled
environment. Therefore, the results obtained in other operating environments may
vary significantly. Some measurements quoted in this book may have been made on
development-level systems. There is no guarantee these measurements will be the
same on generally-available systems. Some measurements quoted in this book may
have been estimated through extrapolation. Actual results may vary. Users of
this book should verify the applicable data for their specific environment.

A full list of U.S. trademarks owned by IBM may be found at
http://www.ibm.com/legal/copytrade.shtml. Linux is a trademark of Linus
Torvalds. Other company, product, and service names may be trademarks or service
marks of others.


### 2. Introduction

Cryptography is rapidly becoming a critical part of our daily lives. However,
the application of cryptographic technology adds a heavy computational burden to
today's server platforms. More systems are beginning to use specialized hardware
to offload the computations, as well as to help ensure the security of secret
key material. In this HOWTO we will discuss openCryptoki, an API that is rapidly
becoming the defacto, non-Windows-platform industry standard for interfacing
between cryptographic hardware and user space applications. In particular we
will introduce the specifics of the PKCS #11 implementation to IBM cryptographic
hardware (openCryptoki).


### 3. What is openCryptoki?

openCryptoki is an implementation of the PKCS #11 API that allows interfacing to
devices (such as a smart card, smart disk, or PCMCIA card) that hold
cryptographic information and perform cryptographic functions. openCryptoki
provides application portability by isolating the application from the details
of the cryptographic device. Isolating the application also provides an added
level of security because all cryptographic information stays within the device.
The openCryptoki API provides a standard programming interface between
applications and all kinds of portable cryptographic devices.


### 4. Architectural Overview

openCryptoki consists of a slot manager and an API for Slot Token Dynamic Link
Libraries (STDLLs). The slot manager runs as a daemon to control the number of
slots provided to applications, and it interacts with applications using a
shared memory region. Each device that has a token associated with it places
that token into a slot in the slot manager database. The shared memory region
allows for proper sharing of state information between applications to help
ensure conformance with the PKCS #11 specification.

#### 4.1. Slot Manager

The Slot Manager Daemon (_pkcsslotd_) manages slots (and therefore tokens) in
the system. A fixed number of processes can be attached to _pkcsslotd_, so a
static table in shared memory is used. The current limit of the table is 1000
processes using the subsystem. The daemon sets up this shared memory upon
initialization and acts as a garbage collector thereafter, helping to ensure
that only active processes remain registered. When a process attaches to a slot
and opens a session, _pkcsslotd_ will make future processes aware that a process
has a session open and will lock out certain function calls, if the they need
exclusive access to the given token. The daemon will constantly search through
its region of shared memory and make sure that when a process is attached to a
token it is actually running. If an attached process terminates abnormally,
_pkcsslotd_ will "clean up" after the process and free the slot for use by other
processes.

#### 4.2. Main API

The main API for the STDLLs lies in /usr/lib/opencryptoki/libopencryptoki.so.
This API includes all the functions as outlined in the PKCS #11 API
specification. The main API provides each application with the slot management
facility. The API also loads token specific modules (STDLLs) the provide the
token specific operations (cryptographic operations and session and object
management). STDLLs are customized for each token type and have specific
functions, such as an initialization routine, to allow the token to work with
the slot manager. When an application initializes the subsystem with the
__C_Initialize__ call, the API will load the STDLL shared objects for all the
tokens that exist in the configuration (residing in the shared memory) and
invoke the token specific initialization routines.

#### 4.3. Slot Token Dynamic Link Libraries

STDLLs are plug-in modules to the main API. They provide token-specific
functions beyond the main API functions. Specific devices can be supported by
building an STDLLs for the device. Each STDLLs must provide at least a token
specific initialization function. If the device is an intelligent device, such
as a hardware adapter that supports multiple mechanisms, the STDLL can be thin
because much of the session information can be stored on the device. If the
device only performs a simple cryptographic function, all of the objects must be
managed by the software. This flexibility allows the STDLLs to support any
cryptographic device.

#### 4.4. Shared Memory

The slot manager sets up its database in a region of shared memory. Since the
maximum number of processes allowed to attach to _pkcsslotd_ is finite, a
fixed amount of memory can be set aside for token management. This fixed memory
allotment management allows applications easier access to token state
information and helps ensure conformance with the PKCS #11 specification.

### 5. Getting Started with openCryptoki

This section describes the system requirements for openCryptoki. It also
explains where you can get openCryptoki and how to compile and install it.

#### 5.1. System Requirements

openCryptoki installs by default a software token that relies on software to
deliver the crypto functions. So it is possible to install it even if you don't
have physical (hardware) token.

The following lists show the system requirements for running openCryptoki.

**Hardware Requirements**

- openCryptoki is supported on ppc64, s390x and x86.

**Software Requirements**

- Linux operating system running at least a 2.2.16 kernel
- Device drivers and associated support libraries for the installed tokens (some
of the header files from those distributions may also be required)

#### 5.2. Obtaining openCryptoki

The openCryptoki project and source code is hosted on
[GitHub](https://github.com/opencryptoki/opencryptoki). You can find
openCryptoki releases (tarball) on GitHub and, as well, on
[SourceForge](https://sourceforge.net/projects/opencryptoki/).
For any issue, questions or development related subjects, please contact us on
the [mailing list](https://sourceforge.net/p/opencryptoki/mailman/).

#### 5.3. Compiling and Installing openCryptoki

Assuming that the device support (and header files) for the required devices are
on the system, then you can build openCryptoki by entering the source code main
directory and do the following:

1. Run the bootstrap.sh script by typing:

``` $ ./bootstrap.sh ```

2. Configure the source code by typing:

``` $ ./configure ```

   If you're planning to install the package into your home directory or to a
   location other than `/usr/local` then add the flag `--prefix=PATH` to
   `configure`. For example, if your home directory is `/home/luser` you can
   configure the package to install itself there by invoking:

``` $ ./configure --prefix=/home/luser ```

   If your stdll headers and libraries are not under any standard path, you will
   need to pass the paths to your files for the configure script. For instance:

``` $ CPPFLAGS="-L/path/lib" LDFLAGS="-I/path/include" ./configure ```

   See `./configure --help` for info on various options. The default behavior is
   to build a default token implicitly. For the s390 platform, the default token
   is ICA. For other platforms, the default token is the software token. Other
   tokens may be enabled using the corresponding `--enable-<tok>` configuration
   option provided the appropriate libraries are available.

   While running, `configure` prints some messages telling which features is it
   checking for.

3. Compile the package by typing:

``` $ make ```

4. openCryptoki defaults to be usable by anyone who is in the group ``pkcs11``,
Add the pkcs11 group before installing it, by typing as root the command:

``` # groupadd pkcs11 ```

   In addition, add the necessary user to the pkcs11 group (root doesn't need to
   be in the pkcs11 group):

``` # usermod -G pkcs11 <user> ```

5. Type `make install` (as root) to install the programs and any data files and
documentation. During installation, the following files go to the following
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

   where `prefix` is either `/usr/local/` or the PATH that you specified in the
   `--prefix` flag. `libdir` is the name of the library directory, for 32-bit
   libraries it is usually `lib` and for 64-bit libraries it is usually `lib64`.

   To maintain backwards compatibility, some additional symlinks are generated
   (note that these are deprecated and applications should migrate to use the
   LSB-compliant name and locations for libraries and executable):

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
   `/prefix/var/lib/opencryptoki` location.

   If you are installing in your home directory make sure that `/home/luser/bin`
   is in your path. If you're using the bash shell add this line at the end of
   your `.bashrc` file:

```
    PATH="/home/luser/bin:${PATH}"
    export PATH
```

   If you are using csh or tcsh, then use this line instead:

``` setenv PATH /home/luser/bin:${PATH} ```

   By prepending your home directory to the rest of the PATH you can override
   systemwide installed software with your own custom installation.


### 6. Configuring openCryptoki

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

``` $ pkcsconf -I -c ```

In this version of openCryptoki, the default SO PIN is `87654321`. This should
be changed to a different PIN value before use.

You can change the SO PIN by running pkcsconf :

``` $ pkcsconf -P -c ```

You can initialize and change the user PIN by typing:

``` $ pkcsconf -u -c ```

You can later change the user PIN again by typing:

``` $ pkcsconf -p -c ```

### 7. Components of openCryptoki

This section describes the different components of the openCryptoki subsystem.

#### 7.1. Slot Manager Daemon

The slot manager daemon is an executable (`/usr/sbin/pkcsslotd`) that reads in
`/etc/opencryptoki/opencryptoki.conf`, populating shared memory according to
what devices have been found within the system. `pkcsslotd` then continues
running as a daemon. Any other applications attempting to use the subsystem must
first attach to the shared memory region and register as part of the API
initialization process, so `pkcsslotd` is aware of the application. If
`/etc/opencryptoki/opencryptoki.conf/` is changed, `pkcsslotd` must be stopped
and restarted to read in the new configuration file. The daemon can be stopped
by issuing the `pkill pkcsslotd` command or through systemd `systemctl stop
pkcsslotd`. The daemon will not terminate if there are any applications using
the subsystem.

#### 7.2. libopencryptoki.so

This library contains the main API (`/usr/lib/opencryptoki/libopencryptoki.so`)
and is loaded by any application that uses any PKCS #11 token managed by the
subsystem. Before an application uses a token, it must load the API and call
`C_Initialize`, as per the PKCS #11 specification. The loading operation is
performed by the application using the dlopen facilities.

#### 7.3. Slot Token DLLs

Six STDLLs ship in the initial offering. These support Trusted Platfrom Module
(TPM, <2.0), IBM Cryptographic Architecture (ICA), IBM Common Cryptographic
Architecture (CCA), Soft Token, IBM Enterprise PKCS #11 (EP11) and IBM
Integrated Cryptographic Service Facility (ICSF).

    **Note**: The compilation process attempts to build all of the tokens that
    are supported on the target platform, as well as all of the required support
    programs. If some of the headers and libraries are not present, those
    components will not be built.

##### 7.3.1. Trusted Module Platform (TPM)

In order to be able to build the TPM stdll you first need:

1. Enable tpm in BIOS settings.

2. Install trousers, trousers-devel, tpm-tools and tpm-tools-pkcs11 as root.
Package names can differ depending on the Linux distribution.

3. As root run the following commands:

```
    Start the tcsd daemon
    # /etc/init.d/tcsd start  or # systemctl start tcsd

    Enter tpm passwords
    # tpm_takeownership
    Enter owner password:
    Confirm password:
    Enter SRK password:
    Confirm password:

    # tpm_setpresence
    Enter owner password:
    Physical Presence Status:
        Command Enable: true
        Hardware Enable: false
        Lifetime Lock: true
        Physical presence: false
        Lock: true
```

After setting up the TPM the openCryptoki compilation should automatically
build the tpm stdll. If it doesn't, then please run:

``` ./configure --enable-tpmtok ```

For more information check [README.tpm_stdll](doc/README.tpm_stdll)

##### 7.3.2. IBM Cryptographic Architecture (ICA)

The IBM Cryptographic Architecture (ICA) is a hardware token that is available
only for s390 systems. If you are in this platform and have the necessary
hardware, you can build openCryptoki with the ICA stdll. To achieve it you need
first install the `libica` package. This package is available in the Linux
distributions repositories.

##### 7.3.3. IBM Common Cryptographic Architecture (CCA)

The IBM Common Cryptographic Architecture (CCA) is also a hardware token that is
only available for the s390 architecture. If you are in this platform and have
the necessary hardware then you can build openCryptoki with the CCA stdll.
First, you need to install the csulcca library on your system. To get this
package click
[here](https://www-03.ibm.com/security/cryptocards/pciecc2/lonzsoftware.shtml)
and be sure to choose the package corresponding to your crypto card version.

For more information about CCA, read [README.cca_stdll](doc/README.cca_stdll)
and [README.pkcscca_migrate](doc/README.pkcscca_migrate).

##### 7.3.4. Software Token

This token is a software emulation of a token. All the cryptographic operations
needed will be run in a software implementation of such cryptographic
algorithms. This implementation is given by OpenSSL and the Soft token is built
by default with openCryptoki.

##### 7.3.5. IBM Enterprise PKCS #11 (EP11)

This is another hardware token for the s390 architecture. In order to be able to
build openCryptoki with EP11 stdll download the necessary library from
[here](https://www-03.ibm.com/security/cryptocards/pciecc2/lonzsoftware.shtml).
Be sure to choose the driver corresponding to your crypto card version.

For more information about EP11, please refer to
[README.ep11_stdll](doc/README.ep11_stdll).

##### 7.3.6. IBM Integrated Cryptographic Service Facility (ICSF)

The ICSF token is a remote crypto token. The actual crypto operations are
performed remotely on a s390 server and all the PKCS #11 key objects are stored
remotely on the server. This calls to the remote server are done via LDAP. 

So, to build openCryptoki with LDAP, you need to install on the client side:
`openldap, openldap-clients and openldap-devel`.

For more information about ICSF, head over to
[README.icsf_stdll](doc/README.icsf_stdll).

### 8. Application and openCryptoki

This section describes how to make openCryptoki available to applications and
provides an example of how to write such an application.

#### 8.1. Making openCryptoki Available to Applications

Many applications use PKCS #11 tokens. Most of these applications must be
configured to load specific shared object (DLL) for the token. In the case of
openCryptoki, only one module (`/usr/lib/opencryptoki/libopencryptoki.so`) must
be loaded for access to all the tokens currently running in the subsystem.
Multiple token types are supported, with each type taking up a slot in the
subsystem according to the implementation specifics of the plug-in module.

If devices are added or removed, the PKCS #11 slot where the token resides may
change. For this reason, applications should locate the specific token by the
token label provided when the token is initialized and not assume that a
specific slot always contains the desired token.

For application-specific configuration information relating to the exploitations
of PKCS #11, refer to the application's documentation.

#### 8.2. Writing an Application

To develop an application that uses openCryptoki, you must first load the shared
object using the dynamic library calls. Then call C_GetFunctionList. For
example, the following routines loads the shared library and gets the function
list for subsequent calls.

```
CK_FUNCTION_LIST *funcs;

int do_GetFunctionList(void)
{
    CK_RV rc;
    CK_RV (*pfoo)();
    void *d;
    char *e;
    char f[]="/usr/lib/pkcs11/PKCS11_API.so"

    printf("do_GetFunctionList...\n");

    d = dlopen(f, RTLD_NOW);
    if (d == NULL)
        return FALSE;

    pfoo = (CK_RV (*)())dlsym(d, "C_GetFunctionList");
    if (pfoo == NULL)
        return FALSE;

    rc = pfoo(&funcs);

    if (rc != CKR_OK) {
        show_error("C_GetFunctionList rc=%d\n", rc);
        return FALSE;
    }

    printf("Looks okay...\n");
    return TRUE;
}
```

Once loaded, the application must call the `C_Initialize` function. In the
previous example, the function would be invoked with the following lines:

```
CK_C_INITIALIZE_ARGS cinit_args;
memset(&cinit_args, 0x0, sizeof(cinit_args));
funcs->C_Initialize(&cinit_args);
```

Refer to the PKCS #11 specification available from the OASIS web site
(https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11) for more
options.

   **Note**: openCryptoki requires that operating systems threads be allowed. If
   other thread routines are passed in, they are ignored. If the `no-os` threads
   argument is set in the initialize arguments structure, the call to
   C_Initialize will fail.


### 9. Resources

For additional information about PKCS #11 and openCryptoki, see the following
resources:

* openCryptoki on [GitHub](https://github.com/opencryptoki/opencryptoki)
* OASIS [PKCS #11 Specification](https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=pkcs11)
* [IBM Cryptocards](https://www-03.ibm.com/security/cryptocards/)
* openCryptoki
[mailing-list](https://sourceforge.net/projects/opencryptoki/lists/opencryptoki-tech)


### 10. Appendix A: Sample Program

The following sample program prints out all of the current tokens and slots in
use in the system. If you want to build the sample program, you will also need
the `Makefile` after the sample.

#### 10.1. Sample Program

```
#include <sys/stat.h>
#include <stdlib.h>
#include <errno.h>
#include <stdio.h>
#include <dlfcn.h>
#include <pkcs11types.h>

#define CFG_SLOT        0x0004
#define CFG_PKCS_INFO   0X0008
#define CFG_TOKEN_INFO  0x0010

CK_RV init(void);
CK_RV cleanup(void);
CK_RV get_slot_list(int, CK_CHAR_PTR);
CK_RV display_slot_info(void);
CK_RV display_token_info(void);

void *dll_ptr;
CK_FUNCTION_LIST_PTR    function_ptr = NULL;
CK_SLOT_ID_PTR          slot_list = NULL;
CK_ULONG                slot_count = 0;
int in_slot;

int main(int argc, char *argv[])
{
    CK_RV rc;                   /* Return Code */
    CK_FLAGS flags = 0;         /* Bit Mask for what options were passed in */
    CK_CHAR_PTR slot = NULL;    /* The PKCS slot number */

    /* Load the PKCS11 library */
    init();

    /* Get the slot list and indicate if a slot number was passed in or not */
    get_slot_list(flags, slot);

    /* Display the current token and slot info */
    display_token_info();
    display_slot_info();

    /* We are done, free the memory we may have allocated */
    free(slot);
    return rc;
}

CK_RV get_slot_list(int cond, CK_CHAR_PTR slot)
{
    CK_RV rc;   /* Return code */

    /* Find out how many tokens are present in the slots */
    rc = function_ptr->C_GetSlotList(TRUE, NULL_PTR, &slot_count);
    if (rc != CKR_OK) {
        printf("Error getting number of slots: 0x%X\n", rc);
        return rc;
    }

    /* Allocate enough space for the slots information */
    slot_list = (CK_SLOT_ID_PTR) malloc(slot_count*sizeof(CK_SLOT_ID));

    rc = function_ptr->C_GetSlotList(TRUE, slot_list, &slot_count);
    if (rc != CKR_OK) {
        printf("Error getting slot list: 0x%X\n", rc);
        return rc;
    }

    return rc;
}

CK_RV display_slot_info(void)
{
    CK_RV           rc;         /* Return Code */
    CK_SLOT_INFO    slot_info;   /* Structure to hold slot information */
    int             lcv;        /* Loop Control Variable */

    for (lcv = 0; lcv < slot_count; lcv++) {
        /* Get the info for the slot we are examining and store in slot_info */
        rc = function_ptr->C_GetSlotInfo(slot_list[lcv], &slot_info);
        if (rc != CKR_OK) {
            printf("Error getting the slot info: 0x%X\n", rc);
            return rc;
        }

        /* Display the slot information */
        printf("Slot #%d Info\n", slot_list[lcv]);
        printf("\tDescription: %.64s\n", slot_info.slotDescription);
        printf("\tManufacturer: %.32s\n", slot_info.manufacturerID);
        printf("\tFlags: 0x%X\n", slot_info.flags);
        printf("\tHardware Version: %d.%d\n", slot_info.hardwareVersion.major,
                                              slot_info.hardwareVersion.minor);
        printf("\tFirmware Version: %d.%d\n", slot_info.firmwareVersion.major,
                                              slot_info.firmwareVersion.minor);
    }
    return CKR_OK;
}

CK_RV display_token_info(void)
{
    CK_RV           rc;         /* Return Code */
    CK_TOKEN_INFO   token_info;  /* Structure to hold token information */
    int             lcv;        /* Loop Control Variable */

    for (lcv = 0; lcv < slot_count; lcv++) {
        /* Get the Token info for each slot in the system */
        rc = function_ptr->C_GetTokenInfo(slot_list[lcv], &token_info);
        if (rc != CKR_OK) {
            printf("Error getting token info: 0x%X\n", rc);
            return rc;
        }

        /* Display the token information */
        printf("Token #%d Info:\n", slot_list[lcv]);
        printf("\tLabel: %.32s\n", token_info.label);
        printf("\tManufacturer: %.32s\n", token_info.manufacturerID);
        printf("\tModel: %.16s\n", token_info.model);
        printf("\tSerial Number: %.16s\n", token_info.serialNumber);
        printf("\tFlags: 0x%X\n", token_info.flags);
        printf("\tSessions: %d/%d\n", token_info.ulSessionCount,
                                      token_info.ulMaxSessionCount);
        printf("\tR/W Sessions: %d/%d\n", token_info.ulRwSessionCount,
                                          token_info.ulMaxRwSessionCount);
        printf("\tPIN Length: %d-%d\n", token_info.ulMinPinLen,
                                        token_info.ulMaxPinLen);
        printf("\tPublic Memory: 0x%X/0x%X\n", token_info.ulFreePublicMemory,
                                               token_info.ulTotalPublicMemory);
        printf("\tPrivate Memory: 0x%X/0x%X\n", token_info.ulFreePrivateMemory,
                                               token_info.ulTotalPrivateMemory);
        printf("\tHardware Version: %d.%d\n", token_info.hardwareVersion.major,
                                              token_info.hardwareVersion.minor);
        printf("\tFirmware Version: %d.%d\n", token_info.firmwareVersion.major,
                                              token_info.firmwareVersion.minor);
        printf("\tTime: %.16s\n", token_info.utcTime);
    }
    return CKR_OK;
}

CK_RV init(void)
{
    CK_RV rc;           /* Return Code */
    void (*sym_ptr)();   /* Pointer for the DLL */

    /* Open the PKCS11 API Shared Library, and inform the user if there is an
     * error
     */
    dll_ptr = dlopen("/usr/lib/opencryptoki/libopencryptoki.so", RTLD_NOW);
    if (!dll_ptr) {
        rc = errno;
        printf("Error loading PKCS#11 library: 0x%X\n", rc);
        fflush(stdout);
        return rc;
    }

    /* Get the list of the PKCS11 functions this token supports */
    sym_ptr = (void (*) ())dlsym(dll_ptr, "C_GetFunctionList");
    if (!sym_ptr) {
        rc = errno;
        printf("Error getting function list: 0x%X\n", rc);
        fflush(stdout);
        cleanup();
    }

    sym_ptr(&function_ptr);

    /* If we get here, we know the slot manager is running and we can use PKCS11
     * calls, so we will execute the PKCS11 Initialize command.
     */
    rc = function_ptr->C_Initialize(NULL);
    if (rc != CKR_OK) {
        printf("Error initializing the PKCS11 library: 0x%X\n", rc);
        fflush(stdout);
        cleanup();
    }

    return CKR_OK;
}

CK_RV cleanup(void)
{
    CK_RV rc;   /* Return Code */

    /* To clean up we will free the slot list we create, call the Finalize
     * routine for PKCS11 and close the dynamically linked library
     */
    free(slot_list);
    rc = function_ptr->C_Finalize(NULL);
    if (dll_ptr)
        dlclose(dll_ptr);

    exit(rc);
}
```

#### 10.2. Makefile

```
VPATH = ...

INCS = -I../. -I../../../../../include/pkcs11
CFLAGS = $(OPTLVL) $(INCS) -DAPI -DDEV -D_THREAD_SAFE -DLINUX -DDEBUG -DSPINXL

CC = gcc
LD = gcc

LIBS = -ldl -lpthread

OBJS = sample.o

.c.o: ; $(CC) -c $(CFLAGS) -o $@ $<

all: sample

sample: $(OBJS)
${CC} ${OBJS} $(LIBS) -o $@

TARGET = sample

build: $(TARGET)

clean:
rm -f *.so *.o $(TARGET)
```
