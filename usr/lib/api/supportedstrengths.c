/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <pkcs11types.h>
#include "supportedstrengths.h"

/* This file exists to allow external tools to access the supported
   strengths array without adding dependencies on the policy
   implementations. */

/* Specifies the strength value corresponding to the index of the
   strengths array.  KEEP IN SYNC!  ALSO KEEP IN DESCENDING ORDER! */
const CK_ULONG supportedstrengths[NUM_SUPPORTED_STRENGTHS] =
    { 256, 192, 128, 112 };
