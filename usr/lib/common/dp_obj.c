/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  dp_obj.c
//
// Domain Parameter Object functions

#include <pthread.h>
#include <stdlib.h>

#include <string.h>             // for memcmp() et al

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"

#include "tok_spec_struct.h"


// dp_object_check_required_attributes()
//
// Check required common attributes for domain parameter objects
//
CK_RV dp_object_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ULONG val;
    CK_RV rc;

    rc = template_attribute_get_ulong(tmpl, CKA_KEY_TYPE, &val);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE\n");
            return rc;
        }
    }

    return template_check_required_base_attributes(tmpl, mode);
}

CK_RV dp_dsa_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG val;
    CK_RV rc;

    if (mode == MODE_CREATE) {
        rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_PRIME\n");
            return rc;
        }

        rc = template_attribute_get_non_empty(tmpl, CKA_SUBPRIME, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_SUBPRIME\n");
            return rc;
        }

        rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_BASE\n");
            return rc;
        }
    } else if (mode == MODE_KEYGEN) {
        rc = template_attribute_get_ulong(tmpl, CKA_PRIME_BITS, &val);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_PRIME_BITS\n");
            return rc;
        }
    }

    return dp_object_check_required_attributes(tmpl, mode);
}

CK_RV dp_dh_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG val;
    CK_RV rc;

    if (mode == MODE_CREATE) {
        rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_PRIME\n");
            return rc;
        }

        rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_BASE\n");
            return rc;
        }
    } else if (mode == MODE_KEYGEN) {
        rc = template_attribute_get_ulong(tmpl, CKA_PRIME_BITS, &val);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_PRIME_BITS\n");
            return rc;
        }
    }

    return dp_object_check_required_attributes(tmpl, mode);
}

CK_RV dp_x9dh_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG val;
    CK_RV rc;

    if (mode == MODE_CREATE) {
        rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_PRIME\n");
            return rc;
        }

        rc = template_attribute_get_non_empty(tmpl, CKA_SUBPRIME, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_SUBPRIME\n");
            return rc;
        }

        rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_BASE\n");
            return rc;
        }
    } else if (mode == MODE_KEYGEN) {
        rc = template_attribute_get_ulong(tmpl, CKA_PRIME_BITS, &val);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_PRIME_BITS\n");
            return rc;
        }
        rc = template_attribute_get_ulong(tmpl, CKA_SUBPRIME_BITS, &val);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_SUBPRIME_BITS\n");
            return rc;
        }
    }

    return dp_object_check_required_attributes(tmpl, mode);
}


// dp_object_set_default_attributes()
//
CK_RV dp_object_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *local_attr = NULL;
    CK_RV rc;

    UNUSED(mode);

    local_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));

    if (!local_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    local_attr->type = CKA_LOCAL;
    local_attr->ulValueLen = sizeof(CK_BBOOL);
    local_attr->pValue = (CK_BYTE *) local_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) local_attr->pValue = FALSE;

    rc = template_update_attribute(tmpl, local_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        free(local_attr);
        return rc;
    }

    return CKR_OK;
}


// dp_object_validate_attribute()
//
CK_RV dp_object_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                   CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_KEY_TYPE:
        if (attr->ulValueLen != sizeof(CK_KEY_TYPE) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_CREATE)
            return CKR_OK;

        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_LOCAL:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID),
                        attr->type);
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
        return CKR_OK;
    default:
        return template_validate_base_attribute(tmpl, attr, mode);
    }
}

//
//
CK_RV dp_dsa_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_PRIME:
        if (mode == MODE_KEYGEN) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    case CKA_PRIME_BITS:
        if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    case CKA_BASE:
        if (mode == MODE_KEYGEN) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    case CKA_SUBPRIME:
        if (mode == MODE_KEYGEN) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    default:
        return dp_object_validate_attribute(tmpl, attr, mode);
    }
}

//
//
CK_RV dp_dh_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                               CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_PRIME:
        if (mode == MODE_KEYGEN) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    case CKA_PRIME_BITS:
        if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    case CKA_BASE:
        if (mode == MODE_KEYGEN) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    default:
        return dp_object_validate_attribute(tmpl, attr, mode);
    }
}

//
//
CK_RV dp_x9dh_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                 CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_PRIME:
        if (mode == MODE_KEYGEN) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    case CKA_PRIME_BITS:
        if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    case CKA_BASE:
        if (mode == MODE_KEYGEN) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    case CKA_SUBPRIME:
        if (mode == MODE_KEYGEN) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    case CKA_SUBPRIME_BITS:
        if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_DOMAIN_PARAMS_INVALID));
            return CKR_DOMAIN_PARAMS_INVALID;
        }
        return CKR_OK;
    default:
        return dp_object_validate_attribute(tmpl, attr, mode);
    }
}


CK_RV dp_dsa_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_RV rc;
    CK_ATTRIBUTE *prime_attr;
    CK_ATTRIBUTE *subprime_attr;
    CK_ATTRIBUTE *base_attr;
    CK_ATTRIBUTE *primebits_attr;
    CK_ATTRIBUTE *type_attr;

    rc = dp_object_set_default_attributes(tmpl, mode);
    if (rc != CKR_OK)
        return rc;

    prime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    subprime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    base_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    primebits_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));

    if (!prime_attr || !subprime_attr || !base_attr || !primebits_attr
        || !type_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    prime_attr->type = CKA_PRIME;
    prime_attr->ulValueLen = 0;
    prime_attr->pValue = NULL;

    subprime_attr->type = CKA_SUBPRIME;
    subprime_attr->ulValueLen = 0;
    subprime_attr->pValue = NULL;

    base_attr->type = CKA_BASE;
    base_attr->ulValueLen = 0;
    base_attr->pValue = NULL;

    primebits_attr->type = CKA_PRIME_BITS;
    primebits_attr->ulValueLen = 0;
    primebits_attr->pValue = NULL;
#if 0
    primebits_attr->ulValueLen = sizeof(CK_ULONG);
    primebits_attr->pValue = (CK_ULONG *) primebits_attr + sizeof(CK_ATTRIBUTE);
    *(CK_ULONG *) primebits_attr->pValue = 0;
#endif
    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_DSA;

    rc = template_update_attribute(tmpl, prime_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    prime_attr = NULL;
    rc = template_update_attribute(tmpl, subprime_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    subprime_attr = NULL;
    rc = template_update_attribute(tmpl, base_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    base_attr = NULL;
    rc = template_update_attribute(tmpl, primebits_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    primebits_attr = NULL;
    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;

    return CKR_OK;

error:
    if (prime_attr)
        free(prime_attr);
    if (subprime_attr)
        free(subprime_attr);
    if (base_attr)
        free(base_attr);
    if (primebits_attr)
        free(primebits_attr);
    if (type_attr)
        free(type_attr);

    return rc;
}

CK_RV dp_dh_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_RV rc;
    CK_ATTRIBUTE *prime_attr;
    CK_ATTRIBUTE *base_attr;
    CK_ATTRIBUTE *primebits_attr;
    CK_ATTRIBUTE *type_attr;

    rc = dp_object_set_default_attributes(tmpl, mode);
    if (rc != CKR_OK)
        return rc;

    prime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    base_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    primebits_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));

    if (!prime_attr || !base_attr || !primebits_attr || !type_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    prime_attr->type = CKA_PRIME;
    prime_attr->ulValueLen = 0;
    prime_attr->pValue = NULL;

    base_attr->type = CKA_BASE;
    base_attr->ulValueLen = 0;
    base_attr->pValue = NULL;

    primebits_attr->type = CKA_PRIME_BITS;
    primebits_attr->ulValueLen = 0;
    primebits_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_DH;

    rc = template_update_attribute(tmpl, prime_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    prime_attr = NULL;
    rc = template_update_attribute(tmpl, base_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    base_attr = NULL;
    rc = template_update_attribute(tmpl, primebits_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    primebits_attr = NULL;
    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;

    return CKR_OK;

error:
    if (prime_attr)
        free(prime_attr);
    if (base_attr)
        free(base_attr);
    if (primebits_attr)
        free(primebits_attr);
    if (type_attr)
        free(type_attr);

    return rc;
}

CK_RV dp_x9dh_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_RV rc;
    CK_ATTRIBUTE *prime_attr;
    CK_ATTRIBUTE *subprime_attr;
    CK_ATTRIBUTE *base_attr;
    CK_ATTRIBUTE *primebits_attr;
    CK_ATTRIBUTE *subprimebits_attr;
    CK_ATTRIBUTE *type_attr;

    rc = dp_object_set_default_attributes(tmpl, mode);
    if (rc != CKR_OK)
        return rc;

    prime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    subprime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    base_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    primebits_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    subprimebits_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));

    if (!prime_attr || !subprime_attr || !base_attr ||
        !primebits_attr || !subprimebits_attr || !type_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    prime_attr->type = CKA_PRIME;
    prime_attr->ulValueLen = 0;
    prime_attr->pValue = NULL;

    subprime_attr->type = CKA_SUBPRIME;
    subprime_attr->ulValueLen = 0;
    subprime_attr->pValue = NULL;

    base_attr->type = CKA_BASE;
    base_attr->ulValueLen = 0;
    base_attr->pValue = NULL;

    primebits_attr->type = CKA_PRIME_BITS;
    primebits_attr->ulValueLen = 0;
    primebits_attr->pValue = NULL;

    subprimebits_attr->type = CKA_SUBPRIME_BITS;
    subprimebits_attr->ulValueLen = 0;
    subprimebits_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_DSA;

    rc = template_update_attribute(tmpl, prime_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    prime_attr = NULL;
    rc = template_update_attribute(tmpl, subprime_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    subprime_attr = NULL;
    rc = template_update_attribute(tmpl, base_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    base_attr = NULL;
    rc = template_update_attribute(tmpl, primebits_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    primebits_attr = NULL;
    rc = template_update_attribute(tmpl, subprimebits_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    subprimebits_attr = NULL;
    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;

    return CKR_OK;

error:
    if (prime_attr)
        free(prime_attr);
    if (subprime_attr)
        free(subprime_attr);
    if (base_attr)
        free(base_attr);
    if (primebits_attr)
        free(primebits_attr);
    if (subprimebits_attr)
        free(subprimebits_attr);
    if (type_attr)
        free(type_attr);

    return rc;
}
