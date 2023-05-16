/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  cert.c
//
// Functions contained within:
//
//    cert_check_required_attributes
//    cert_validate_attribute
//    cert_x509_check_required_attributes
//    cert_x509_set_default_attributes
//    cert_x509_validate_attribute
//    cert_vendor_check_required_attributes
//    cert_vendor_validate_attribute
//

#include <pthread.h>
#include <stdlib.h>

#include <string.h>             // for memcmp() et al

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"


// cert_check_required_attributes
//
// Checks for required attributes for generic CKO_CERTIFICATE objects
//
//    CKA_CERTIFICATE_TYPE : must be present on MODE_CREATE.
//
CK_RV cert_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ULONG val;
    CK_RV rc;

    if (!tmpl)
        return CKR_FUNCTION_FAILED;

    if (mode == MODE_CREATE) {
        rc = template_attribute_get_ulong(tmpl, CKA_CERTIFICATE_TYPE, &val);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CERTIFICATE_TYPE\n");
            return rc;
        }
        // don't bother checking the value.  it was checked in the 'validate'
        // routine.
    }

    return template_check_required_base_attributes(tmpl, mode);
}

// cert_set_default_attributes()
//
// Set the default attributes for X.509 certificates
//
//    CKA_TRUSTED               : FALSE
//    CKA_CERTIFICATE_CATEGORY  : CK_CERTIFICATE_CATEGORY_UNSPECIFIED
//    CKA_CHECK_VALUE           : empty byte array
//    CKA_START_DATE            : empty CK_DATE
//    CKA_END_DATE              : empty CK_DATE
//    CKA_PUBLIC_KEY_INFO       : empty byte array
//
CK_RV cert_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *trusted_attr = NULL;
    CK_ATTRIBUTE *category_attr = NULL;
    CK_ATTRIBUTE *chkval_attr = NULL;
    CK_ATTRIBUTE *start_attr = NULL;
    CK_ATTRIBUTE *end_attr = NULL;
    CK_ATTRIBUTE *pki_attr = NULL;
    CK_RV rc;

    UNUSED(mode);

    trusted_attr =
            (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    category_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) +
                                            sizeof(CK_CERTIFICATE_CATEGORY));
    chkval_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    start_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    end_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    pki_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!trusted_attr || !category_attr || !chkval_attr || !start_attr ||
        !end_attr || !pki_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    trusted_attr->type = CKA_TRUSTED;
    trusted_attr->ulValueLen = sizeof(CK_BBOOL);
    trusted_attr->pValue = (CK_BYTE *)trusted_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) trusted_attr->pValue = FALSE;

    category_attr->type = CKA_CERTIFICATE_CATEGORY;
    category_attr->ulValueLen = sizeof(CK_CERTIFICATE_CATEGORY);
    category_attr->pValue = (CK_BYTE *)category_attr + sizeof(CK_ATTRIBUTE);
    *(CK_CERTIFICATE_CATEGORY *) category_attr->pValue =
                                        CK_CERTIFICATE_CATEGORY_UNSPECIFIED;

    chkval_attr->type = CKA_CHECK_VALUE;
    chkval_attr->ulValueLen = 0;        // empty byte array
    chkval_attr->pValue = NULL;

    start_attr->type = CKA_START_DATE;
    start_attr->ulValueLen = 0;        // empty CK_DATE
    start_attr->pValue = NULL;

    end_attr->type = CKA_END_DATE;
    end_attr->ulValueLen = 0;        // empty CK_DATE
    end_attr->pValue = NULL;

    pki_attr->type = CKA_PUBLIC_KEY_INFO;
    pki_attr->ulValueLen = 0;        // empty byte array
    pki_attr->pValue = NULL;

    rc = template_update_attribute(tmpl, trusted_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    trusted_attr = NULL;
    rc = template_update_attribute(tmpl, category_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    category_attr = NULL;
    rc = template_update_attribute(tmpl, chkval_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    chkval_attr = NULL;
    rc = template_update_attribute(tmpl, start_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    start_attr = NULL;
    rc = template_update_attribute(tmpl, end_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    end_attr = NULL;
    rc = template_update_attribute(tmpl, pki_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    pki_attr = NULL;

    return CKR_OK;

error:
    if (trusted_attr != NULL)
        free(trusted_attr);
    if (category_attr != NULL)
        free(category_attr);
    if (chkval_attr != NULL)
        free(chkval_attr);
    if (start_attr != NULL)
        free(start_attr);
    if (end_attr != NULL)
        free(end_attr);
    if (pki_attr != NULL)
        free(pki_attr);

    return rc;
}

// cert_validate_attribute()
//
CK_RV cert_validate_attribute(STDLL_TokData_t *tokdata,
                              TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                              CK_ULONG mode)
{
    CK_CERTIFICATE_TYPE type;
    CK_CERTIFICATE_CATEGORY category;

    switch (attr->type) {
    case CKA_CERTIFICATE_TYPE:
        if (mode != MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        if (attr->ulValueLen != sizeof(CK_CERTIFICATE_TYPE) ||
            attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        type = *(CK_CERTIFICATE_TYPE *) attr->pValue;
        if (type == CKC_X_509 || type >= CKC_VENDOR_DEFINED) {
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    case CKA_TRUSTED:
        /* Can only be set to CK_TRUE by the SO user */
        if (attr->ulValueLen != sizeof(CK_BBOOL) ||
            attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (*((CK_BBOOL *)attr->pValue) == CK_TRUE &&
            !session_mgr_so_session_exists(tokdata)) {
            return CKR_USER_NOT_LOGGED_IN;
        }
        return CKR_OK;
    case CKA_CERTIFICATE_CATEGORY:
        if (attr->ulValueLen != sizeof(CK_CERTIFICATE_CATEGORY) ||
            attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        category = *(CK_CERTIFICATE_CATEGORY *) attr->pValue;
        switch (category) {
        case CK_CERTIFICATE_CATEGORY_UNSPECIFIED:
        case CK_CERTIFICATE_CATEGORY_TOKEN_USER:
        case CK_CERTIFICATE_CATEGORY_AUTHORITY:
        case CK_CERTIFICATE_CATEGORY_OTHER_ENTITY:
            return CKR_OK;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    case CKA_CHECK_VALUE:
    case CKA_START_DATE:
    case CKA_END_DATE:
    case CKA_PUBLIC_KEY_INFO:
        return CKR_OK;
    default:
        return template_validate_base_attribute(tmpl, attr, mode);
    }
}


// cert_x509_check_required_attributes()
//
CK_RV cert_x509_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_SUBJECT, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_SUBJECT\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_URL, &attr);
    if (rc != CKR_OK) {
        /* CKA_VALUE MUST be non-empty if CKA_URL is empty or not specified */
        rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    } else {
        /* Hashes can only be empty if CKA_URL is empty */
        rc = template_attribute_get_non_empty(tmpl,
                        CKA_HASH_OF_SUBJECT_PUBLIC_KEY, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_HASH_OF_SUBJECT_PUBLIC_KEY\n");
            return rc;
        }
        rc = template_attribute_get_non_empty(tmpl,
                        CKA_HASH_OF_ISSUER_PUBLIC_KEY, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_HASH_OF_ISSUER_PUBLIC_KEY\n");
            return rc;
        }

    }

    return cert_check_required_attributes(tmpl, mode);
}


// cert_x509_set_default_attributes()
//
// Set the default attributes for X.509 certificates
//
//    CKA_ID                          : empty string
//    CKA_ISSUER                      : empty string
//    CKA_SERIAL_NUMBER               : empty string
//    CKA_URL                         : empty string
//    CKA_HASH_OF_SUBJECT_PUBLIC_KEY  : empty string
//    CKA_HASH_OF_ISSUER_PUBLIC_KEY   : empty string
//    CKA_JAVA_MIDP_SECURITY_DOMAIN   : CK_SECURITY_DOMAIN_UNSPECIFIED
//    CKA_NAME_HASH_ALGORITHM         : CKM_SHA1
//
CK_RV cert_x509_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *id_attr = NULL;
    CK_ATTRIBUTE *issuer_attr = NULL;
    CK_ATTRIBUTE *serial_attr = NULL;
    CK_ATTRIBUTE *url_attr = NULL;
    CK_ATTRIBUTE *subject_hash_attr = NULL;
    CK_ATTRIBUTE *issuer_hash_attr = NULL;
    CK_ATTRIBUTE *sec_domain_attr = NULL;
    CK_ATTRIBUTE *hash_mech_attr = NULL;
    CK_RV rc;

    rc = cert_set_default_attributes(tmpl, mode);
    if (rc != CKR_OK) {
        TRACE_DEVEL("cert_set_default_attributes failed\n");
        return rc;
    }

    id_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    issuer_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    serial_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    url_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    subject_hash_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    issuer_hash_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    sec_domain_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) +
                                sizeof(CK_JAVA_MIDP_SECURITY_DOMAIN));
    hash_mech_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) +
                                sizeof(CK_MECHANISM_TYPE));

    if (!id_attr || !issuer_attr || !serial_attr || !url_attr ||
        !subject_hash_attr || !issuer_hash_attr || !sec_domain_attr ||
        !hash_mech_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    id_attr->type = CKA_ID;
    id_attr->ulValueLen = 0;    // empty string
    id_attr->pValue = NULL;

    issuer_attr->type = CKA_ISSUER;
    issuer_attr->ulValueLen = 0;        // empty byte array
    issuer_attr->pValue = NULL;

    serial_attr->type = CKA_SERIAL_NUMBER;
    serial_attr->ulValueLen = 0;        // empty byte array
    serial_attr->pValue = NULL;

    url_attr->type = CKA_URL;
    url_attr->ulValueLen = 0;        // empty byte array
    url_attr->pValue = NULL;

    subject_hash_attr->type = CKA_HASH_OF_SUBJECT_PUBLIC_KEY;
    subject_hash_attr->ulValueLen = 0;        // empty byte array
    subject_hash_attr->pValue = NULL;

    issuer_hash_attr->type = CKA_HASH_OF_ISSUER_PUBLIC_KEY;
    issuer_hash_attr->ulValueLen = 0;        // empty byte array
    issuer_hash_attr->pValue = NULL;

    sec_domain_attr->type = CKA_JAVA_MIDP_SECURITY_DOMAIN;
    sec_domain_attr->ulValueLen = sizeof(CK_JAVA_MIDP_SECURITY_DOMAIN);
    sec_domain_attr->pValue = (CK_BYTE *)sec_domain_attr + sizeof(CK_ATTRIBUTE);
    *(CK_JAVA_MIDP_SECURITY_DOMAIN *) sec_domain_attr->pValue =
                                            CK_SECURITY_DOMAIN_UNSPECIFIED;

    hash_mech_attr->type = CKA_NAME_HASH_ALGORITHM;
    hash_mech_attr->ulValueLen = sizeof(CK_MECHANISM_TYPE);
    hash_mech_attr->pValue = (CK_BYTE *)hash_mech_attr + sizeof(CK_ATTRIBUTE);
    *(CK_MECHANISM_TYPE *) hash_mech_attr->pValue = CKM_SHA_1;

    rc = template_update_attribute(tmpl, id_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    id_attr = NULL;
    rc = template_update_attribute(tmpl, issuer_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    issuer_attr = NULL;
    rc = template_update_attribute(tmpl, serial_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    serial_attr = NULL;
    rc = template_update_attribute(tmpl, url_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    url_attr = NULL;
    rc = template_update_attribute(tmpl, subject_hash_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    subject_hash_attr = NULL;
    rc = template_update_attribute(tmpl, issuer_hash_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    issuer_hash_attr = NULL;
    rc = template_update_attribute(tmpl, sec_domain_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    sec_domain_attr = NULL;
    rc = template_update_attribute(tmpl, hash_mech_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed\n");
        goto error;
    }
    hash_mech_attr = NULL;

    return CKR_OK;

error:
    if (id_attr)
        free(id_attr);
    if (issuer_attr)
        free(issuer_attr);
    if (serial_attr)
        free(serial_attr);
    if (url_attr)
        free(url_attr);
    if (subject_hash_attr)
        free(subject_hash_attr);
    if (issuer_hash_attr)
        free(issuer_hash_attr);
    if (sec_domain_attr)
        free(sec_domain_attr);
    if (hash_mech_attr)
        free(hash_mech_attr);

    return rc;
}


// cert_x509_validate_attributes()
//
CK_RV cert_x509_validate_attribute(STDLL_TokData_t *tokdata,
                                   TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                   CK_ULONG mode)
{
    CK_JAVA_MIDP_SECURITY_DOMAIN sec_domain;

    switch (attr->type) {
    case CKA_SUBJECT:
        if (mode != MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        return CKR_OK;
    case CKA_ID:
    case CKA_ISSUER:
    case CKA_SERIAL_NUMBER:
        return CKR_OK;
    case CKA_VALUE:
        if (mode != MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        return CKR_OK;
    case CKA_URL:
        if (mode != MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        return CKR_OK;
    case CKA_HASH_OF_SUBJECT_PUBLIC_KEY:
        if (mode != MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        return CKR_OK;
    case CKA_HASH_OF_ISSUER_PUBLIC_KEY:
        if (mode != MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        return CKR_OK;
    case CKA_JAVA_MIDP_SECURITY_DOMAIN:
        if (mode != MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        if (attr->ulValueLen != sizeof(CK_JAVA_MIDP_SECURITY_DOMAIN) ||
            attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        sec_domain = *(CK_CERTIFICATE_CATEGORY *) attr->pValue;
        switch (sec_domain) {
        case CK_SECURITY_DOMAIN_UNSPECIFIED:
        case CK_SECURITY_DOMAIN_MANUFACTURER:
        case CK_SECURITY_DOMAIN_OPERATOR:
        case CK_SECURITY_DOMAIN_THIRD_PARTY:
            return CKR_OK;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
     case CKA_NAME_HASH_ALGORITHM:
         if (mode != MODE_CREATE) {
             TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
             return CKR_ATTRIBUTE_READ_ONLY;
         }
        if (attr->ulValueLen != sizeof(CK_MECHANISM_TYPE) ||
            attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        return CKR_OK;
    default:
        return cert_validate_attribute(tokdata, tmpl, attr, mode);
    }
}


// cert_vendor_check_required_attributes()
//
CK_RV cert_vendor_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    // CKC_VENDOR has no required attributes
    //
    return cert_check_required_attributes(tmpl, mode);
}


// cert_vendor_validate_attribute()
//
CK_RV cert_vendor_validate_attribute(STDLL_TokData_t *tokdata,
                                     TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                     CK_ULONG mode)
{
    // cryptoki specifies no attributes for CKC_VENDOR certificates
    //
    return cert_validate_attribute(tokdata, tmpl, attr, mode);
}
