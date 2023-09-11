/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  data_obj.c
//
// Functions contained within:
//
//    data_object_check_required_attributes
//    data_object_set_default_attributes
//    data_object_validate_attribute
//

#include <pthread.h>
#include <stdlib.h>

#include <string.h>             // for memcmp() et al

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"


// data_object_check_required_attributes()
//
CK_RV data_object_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    // CKO_DATA has no required attributes
    //

    return template_check_required_base_attributes(tmpl, mode);
}


// data_object_set_default_attributes()
//
// Set the default attributes for data objects:
//
//    CKA_APPLICATION :  empty string
//    CKA_VALUE       :  empty byte array
//
CK_RV data_object_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *class_attr = NULL;
    CK_ATTRIBUTE *app_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *objid_attr = NULL;
    CK_RV rc;

    UNUSED(mode);

    // add the default CKO_DATA attributes
    //
    class_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS));
    app_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    objid_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!class_attr || !app_attr || !value_attr || !objid_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    app_attr->type = CKA_APPLICATION;
    app_attr->ulValueLen = 0;   // empty string
    app_attr->pValue = NULL;

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0; // empty byte array
    value_attr->pValue = NULL;

    objid_attr->type = CKA_OBJECT_ID;
    objid_attr->ulValueLen = 0; // empty byte array
    objid_attr->pValue = NULL;

    class_attr->type = CKA_CLASS;
    class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
    class_attr->pValue = (CK_BYTE *) class_attr + sizeof(CK_ATTRIBUTE);
    *(CK_OBJECT_CLASS *) class_attr->pValue = CKO_DATA;

    rc = template_update_attribute(tmpl, class_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    class_attr = NULL;
    rc = template_update_attribute(tmpl, app_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    app_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;
    rc = template_update_attribute(tmpl, objid_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    objid_attr = NULL;

    return CKR_OK;

error:
    if (class_attr)
        free(class_attr);
    if (app_attr)
        free(app_attr);
    if (value_attr)
        free(value_attr);
    if (objid_attr)
        free(objid_attr);

    return rc;
}


// data_object_validate_attribute()
//
// Determine whether a CKO_DATA object's attribute are valid.
//
CK_RV data_object_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                     CK_ULONG mode)
{
    if (!attr) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    switch (attr->type) {
    case CKA_APPLICATION:
    case CKA_VALUE:
    case CKA_OBJECT_ID:
        if (mode == MODE_CREATE)
            return CKR_OK;
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return template_validate_base_attribute(tmpl, attr, mode);
    }

    return CKR_OK;
}
