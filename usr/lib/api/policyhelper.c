/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include "pkcs11types.h"
#include "h_extern.h"

CK_RV policy_get_attr_from_template(void *data,
                                    CK_ATTRIBUTE_TYPE type,
                                    CK_ATTRIBUTE **attr)
{
    TEMPLATE *t = data;

    return template_attribute_get_non_empty(t, type, attr);
}
