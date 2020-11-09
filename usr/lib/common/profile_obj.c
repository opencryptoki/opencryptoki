/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"

CK_RV profile_object_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    /* CKO_PROFILE has no required attributes */
    return template_check_required_base_attributes(tmpl, mode);
}

CK_RV profile_object_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *class_attr = NULL;
    CK_ATTRIBUTE *profile_id_attr = NULL;
    CK_RV rc;

    UNUSED(mode);

    class_attr =
        (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS));
    profile_id_attr =
        (CK_ATTRIBUTE *)malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_PROFILE_ID));

    if (!class_attr || !profile_id_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    class_attr->type = CKA_CLASS;
    class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
    class_attr->pValue = (CK_BYTE *)class_attr + sizeof(CK_ATTRIBUTE);
    *(CK_OBJECT_CLASS *)class_attr->pValue = CKO_PROFILE;

    profile_id_attr->type = CKA_PROFILE_ID;
    profile_id_attr->ulValueLen = sizeof(CK_PROFILE_ID);
    profile_id_attr->pValue = (CK_BYTE *)profile_id_attr + sizeof(CK_ATTRIBUTE);
    *(CK_PROFILE_ID *)profile_id_attr->pValue = CKP_INVALID_ID;

    rc = template_update_attribute(tmpl, class_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    class_attr = NULL;
    rc = template_update_attribute(tmpl, profile_id_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    profile_id_attr = NULL;
    return CKR_OK;

error:
    if (class_attr)
        free(class_attr);
    if (profile_id_attr)
        free(profile_id_attr);

    return rc;
}

CK_RV profile_object_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                        CK_ULONG mode)
{
    if (!attr) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    switch (attr->type) {
    case CKA_PROFILE_ID:
        return CKR_OK;
    default:
        return template_validate_base_attribute(tmpl, attr, mode);
    }
}
