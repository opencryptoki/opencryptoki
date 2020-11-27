/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * Test if our public header files can be savely included from C++.
 */

// pkcs11.h:
#include "apiclient.h"
#include "pkcs11types.h"

// Additional ECC stuff:
#include "ec_curves.h"

int main(void)
{
    int rv;

    rv = 0;
    /* make sure we return non-zero if rv is non-zero */
    return ((rv == 0) || (rv % 256) ? (int)rv : -1);
}
