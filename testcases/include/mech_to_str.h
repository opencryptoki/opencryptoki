/*
 * COPYRIGHT (c) International Business Machines Corp. 2013-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef _MECH_TO_STR_
#define _MECH_TO_STR_
#include "pkcs11types.h"
#include <mechtable.h>

static inline const char *mech_to_str(CK_ULONG mech)
{
    const struct mechrow *row = mechrow_from_numeric(mech);

    if (row)
        return row->string;
    return "(unknown mech)";
}

#endif
