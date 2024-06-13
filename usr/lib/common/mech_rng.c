/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  mech_rng.c
//
// Mechanisms for Random Numbers
//
// PKCS #11 doesn't consider random number generator to be a "mechanism"
//

#include <string.h>             // for memcmp() et al
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"

#include "tok_spec_struct.h"
#include "tok_specific.h"
#include "trace.h"

//
//
CK_RV local_rng(CK_BYTE *output, CK_ULONG bytes)
{
    int ranfd;
    int rlen;
    unsigned int totallen = 0;

    ranfd = open("/dev/prandom", O_RDONLY);
    if (ranfd < 0)
        ranfd = open("/dev/urandom", O_RDONLY);
    if (ranfd >= 0) {
        do {
            rlen = read(ranfd, output + totallen, bytes - totallen);
            if (rlen <= 0) {
                close(ranfd);
                return CKR_FUNCTION_FAILED;
            }
            totallen += rlen;
        } while (totallen < bytes);
        close(ranfd);
        return CKR_OK;
    }

    return CKR_FUNCTION_FAILED;
}

//
//
CK_RV rng_generate(STDLL_TokData_t *tokdata, CK_BYTE *output, CK_ULONG bytes)
{
    CK_RV rc;

    /* Do token specific rng if it exists. */
    if (token_specific.t_rng != NULL)
        rc = token_specific.t_rng(tokdata, output, bytes);
    else
        rc = local_rng(output, bytes);

    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific rng failed.\n");

    return rc;
}
