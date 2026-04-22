/*
 * COPYRIGHT (c) International Business Machines Corp. 2026
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * Stub implementations for objectflattentest
 * These stubs provide minimal implementations of functions that are
 * referenced by object.c, template.c, and attributes.c but not needed
 * for testing object_flatten and object_restore_withSize.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"

/* Global stubs */
token_spec_t token_specific = { 0 };

/* Stub implementations */
CK_RV build_attribute(CK_ATTRIBUTE_TYPE type, CK_BYTE *value,
                      CK_ULONG value_len, CK_ATTRIBUTE **attrib)
{
    CK_ATTRIBUTE *attr;

    attr = (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE));
    if (!attr)
        return CKR_HOST_MEMORY;

    attr->type = type;
    attr->ulValueLen = value_len;

    if (value_len > 0 && value != NULL) {
        attr->pValue = malloc(value_len);
        if (!attr->pValue) {
            free(attr);
            return CKR_HOST_MEMORY;
        }
        memcpy(attr->pValue, value, value_len);
    } else {
        attr->pValue = NULL;
    }

    *attrib = attr;
    return CKR_OK;
}

CK_RV policy_get_attr_from_template(void *data,
                                    CK_ATTRIBUTE_TYPE type,
                                    CK_ATTRIBUTE **attr)
{
    (void)data;
    (void)type;
    (void)attr;
    return CKR_ATTRIBUTE_TYPE_INVALID;
}

CK_BBOOL session_mgr_user_session_exists(STDLL_TokData_t *tokdata)
{
    (void)tokdata;
    return FALSE;
}
