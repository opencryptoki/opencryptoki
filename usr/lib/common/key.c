/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  key.c
//
// Functions contained within:
//
//    key_object_check_required_attributes
//    key_object_set_default_attributes
//    key_object_validate_attribute
//
//    publ_key_check_required_attributes
//    publ_key_set_default_attributes
//    publ_key_validate_attribute
//
//    priv_key_check_required_attributes
//    priv_key_set_default_attributes
//    priv_key_validate_attribute
//
//    secret_key_check_required_attributes
//    secret_key_set_default_attributes
//    secret_key_validate_attribute
//
//    rsa_publ_check_required_attributes
//    rsa_publ_validate_attribute
//    rsa_priv_check_required_attributes
//    rsa_priv_validate_attribute
//    rsa_priv_check_exportability
//
//    dsa_publ_check_required_attributes
//    dsa_publ_validate_attribute
//    dsa_priv_check_required_attributes
//    dsa_priv_validate_attribute
//    dsa_priv_check_exportability
//
//    ecdsa_publ_check_required_attributes
//    ecdsa_publ_validate_attribute
//    ecdsa_priv_checK_required_attributes
//    ecdsa_priv_validate_attribute
//    ecdsa_priv_check_exportability
//
//    dh_publ_check_required_attributes
//    dh_publ_validate_attribute
//    dh_priv_check_required_attributes
//    dh_priv_validate_attribute
//    dh_priv_check_exportability
//
//    generic_secret_check_required_attributes
//    generic_secret_validate_attribute
//    generic_secret_set_default_attributes
//
//    des_check_required_attributes
//    des_validate_attribute
//    des_priv_check_exportability
//
//    des2_check_required_attributes
//    des2_validate_attribute
//    des2_priv_check_exportability
//
//    des3_check_required_attributes
//    des3_validate_attribute
//    des3_priv_check_exportability
//

#include <pthread.h>
#include <stdlib.h>

#include <string.h>             // for memcmp() et al

#include "pkcs11types.h"
#include "p11util.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "attributes.h"
#include "trace.h"
#include "pqc_defs.h"

#include "tok_spec_struct.h"


// key_object_check_required_attributes()
//
// Check required common attributes for key objects
//
CK_RV key_object_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
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


//  key_object_set_default_attributes()
//
CK_RV key_object_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *id_attr = NULL;
    CK_ATTRIBUTE *sdate_attr = NULL;
    CK_ATTRIBUTE *edate_attr = NULL;
    CK_ATTRIBUTE *derive_attr = NULL;
    CK_ATTRIBUTE *local_attr = NULL;
    CK_ATTRIBUTE *keygenmech_attr = NULL;
    CK_ATTRIBUTE *allowedmechs_attr = NULL;
    CK_ATTRIBUTE *pkey_attr = NULL;
    CK_RV rc;

    UNUSED(mode);

    id_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    sdate_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    edate_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    derive_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    local_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    keygenmech_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE)
                                              + sizeof(CK_MECHANISM_TYPE));
    allowedmechs_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    pkey_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));

    if (!id_attr || !sdate_attr || !edate_attr || !derive_attr || !local_attr
        || !keygenmech_attr || !allowedmechs_attr || !pkey_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    id_attr->type = CKA_ID;
    id_attr->ulValueLen = 0;
    id_attr->pValue = NULL;

    sdate_attr->type = CKA_START_DATE;
    sdate_attr->ulValueLen = 0;
    sdate_attr->pValue = NULL;

    edate_attr->type = CKA_END_DATE;
    edate_attr->ulValueLen = 0;
    edate_attr->pValue = NULL;

    derive_attr->type = CKA_DERIVE;
    derive_attr->ulValueLen = sizeof(CK_BBOOL);
    derive_attr->pValue = (CK_BYTE *) derive_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) derive_attr->pValue = FALSE;

    local_attr->type = CKA_LOCAL;
    local_attr->ulValueLen = sizeof(CK_BBOOL);
    local_attr->pValue = (CK_BYTE *) local_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) local_attr->pValue = FALSE;

    keygenmech_attr->type = CKA_KEY_GEN_MECHANISM;
    keygenmech_attr->ulValueLen = sizeof(CK_MECHANISM_TYPE);
    keygenmech_attr->pValue = (CK_BYTE *) keygenmech_attr + sizeof(CK_ATTRIBUTE);
    *(CK_MECHANISM_TYPE *) keygenmech_attr->pValue = CK_UNAVAILABLE_INFORMATION;

    allowedmechs_attr->type = CKA_ALLOWED_MECHANISMS;
    allowedmechs_attr->ulValueLen = 0;
    allowedmechs_attr->pValue = NULL;

    pkey_attr->type = CKA_IBM_PROTKEY_EXTRACTABLE;
    pkey_attr->ulValueLen = sizeof(CK_BBOOL);
    pkey_attr->pValue = (CK_BBOOL *) pkey_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) pkey_attr->pValue = FALSE;

    rc = template_update_attribute(tmpl, id_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    id_attr = NULL;
    rc = template_update_attribute(tmpl, sdate_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    sdate_attr = NULL;
    rc = template_update_attribute(tmpl, edate_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    edate_attr = NULL;
    rc = template_update_attribute(tmpl, derive_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    derive_attr = NULL;
    rc = template_update_attribute(tmpl, local_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    local_attr = NULL;
    rc = template_update_attribute(tmpl, keygenmech_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    keygenmech_attr = NULL;
    rc = template_update_attribute(tmpl, allowedmechs_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    allowedmechs_attr = NULL;
    rc = template_update_attribute(tmpl, pkey_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    pkey_attr = NULL;

    return CKR_OK;

error:
    if (id_attr)
        free(id_attr);
    if (sdate_attr)
        free(sdate_attr);
    if (edate_attr)
        free(edate_attr);
    if (derive_attr)
        free(derive_attr);
    if (local_attr)
        free(local_attr);
    if (keygenmech_attr)
        free(keygenmech_attr);
    if (allowedmechs_attr)
        free(allowedmechs_attr);
    if (pkey_attr)
        free(pkey_attr);

    return rc;
}


// key_object_validate_attribute()
//
CK_RV key_object_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                    CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_KEY_TYPE:
        if (attr->ulValueLen != sizeof(CK_KEY_TYPE) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (mode == MODE_CREATE || mode == MODE_DERIVE ||
            mode == MODE_KEYGEN || mode == MODE_UNWRAP)
            return CKR_OK;

        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_ID:
    case CKA_START_DATE:
    case CKA_END_DATE:
        return CKR_OK;
    case CKA_ALLOWED_MECHANISMS:
        if ((attr->ulValueLen > 0 && attr->pValue == NULL) ||
            attr->ulValueLen % sizeof(CK_MECHANISM_TYPE)) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_CREATE || mode == MODE_KEYGEN ||
            mode == MODE_DERIVE || mode == MODE_UNWRAP)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_DERIVE:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        return CKR_OK;
    case CKA_KEY_GEN_MECHANISM:
    case CKA_LOCAL:
        /*
         * CKA_LOCAL and CKA_KEY_GEN_MECHANISM are only set by the
         * key-generate routine
         */
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_IBM_PROTKEY_EXTRACTABLE:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        CK_BBOOL value = *(CK_BBOOL *) attr->pValue;
        if (mode != MODE_CREATE && mode != MODE_DERIVE &&
            mode != MODE_KEYGEN && mode != MODE_UNWRAP &&
            value != FALSE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        return CKR_OK;
        break;
    case CKA_IBM_ATTRBOUND:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_CREATE || mode == MODE_DERIVE || mode == MODE_KEYGEN
            || mode == MODE_UNWRAP)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_IBM_USE_AS_DATA:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_CREATE || mode == MODE_DERIVE || mode == MODE_KEYGEN
            || mode == MODE_UNWRAP)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return template_validate_base_attribute(tmpl, attr, mode);
    }

    TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID), attr->type);

    return CKR_ATTRIBUTE_TYPE_INVALID;
}

/*
 * Check if the specified mechanism is contained in the CKA_ALLOWED_MECHANISMS
 * attribute. If CKA_ALLOWED_MECHANISMS is not existing, or empty, then all
 * mechanisms are allowed.
 */
CK_BBOOL key_object_is_mechanism_allowed(TEMPLATE *tmpl, CK_MECHANISM_TYPE mech)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_MECHANISM_TYPE *mechs;
    CK_ULONG num_mechs, i;

    if (!template_attribute_find(tmpl, CKA_ALLOWED_MECHANISMS, &attr))
        return TRUE;

    if (attr->ulValueLen == 0 || attr->pValue == NULL)
        return TRUE;

    mechs = (CK_MECHANISM_TYPE *)attr->pValue;
    num_mechs = attr->ulValueLen / sizeof(CK_MECHANISM_TYPE);

    for (i = 0; i < num_mechs; i++) {
        if (mechs[i] == mech)
            return TRUE;
    }

    return FALSE;
}

/*
 * Check if the to be wrapped key template matches the wrap template of the
 * wrapping key (CKA_WRAP_TEMPLATE), if the wrapping key has one.
 */
CK_BBOOL key_object_wrap_template_matches(TEMPLATE *wrap_tmpl, TEMPLATE *tmpl)
{
    CK_ATTRIBUTE *attr = NULL;

    if (!template_attribute_find(wrap_tmpl, CKA_WRAP_TEMPLATE, &attr))
        return TRUE;

    if (attr->ulValueLen == 0 || attr->pValue == NULL)
        return TRUE;

    return template_compare((CK_ATTRIBUTE_PTR)attr->pValue,
                            attr->ulValueLen / sizeof(CK_ATTRIBUTE), tmpl);
}

CK_RV key_object_apply_template_attr(TEMPLATE *unwrap_tmpl,
                                     CK_ATTRIBUTE_TYPE attr_type,
                                     CK_ATTRIBUTE_PTR attrs,
                                     CK_ULONG attrs_count,
                                     CK_ATTRIBUTE_PTR *new_attrs,
                                     CK_ULONG *new_attrs_count)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE_PTR apply_attrs;
    CK_ULONG num_apply_attrs, i;
    CK_RV rc;

    rc = dup_attribute_array(attrs, attrs_count, new_attrs, new_attrs_count);
    if (rc != CKR_OK) {
        TRACE_DEVEL("dup_attribute_array failed\n");
        return rc;
    }

    if (!template_attribute_find(unwrap_tmpl, attr_type, &attr))
       return CKR_OK;

    if (attr->ulValueLen == 0 || attr->pValue == NULL)
        return CKR_OK;

    apply_attrs = (CK_ATTRIBUTE_PTR)attr->pValue;
    num_apply_attrs = attr->ulValueLen / sizeof (CK_ATTRIBUTE);

    for (i = 0; i < num_apply_attrs; i++) {
        /*
         * If the attribute to apply is already in the user supplied template,
         * make sure that it does not conflict.
         */
        attr = get_attribute_by_type(attrs, attrs_count, apply_attrs[i].type);
        if (attr != NULL) {
            if (compare_attribute(attr, &apply_attrs[i]) == FALSE) {
                TRACE_DEVEL("%s: %lu conflicts\n",
                            ock_err(ERR_TEMPLATE_INCONSISTENT),
                            apply_attrs[i].type);
                return CKR_TEMPLATE_INCONSISTENT;
            }
        } else {
            rc = add_to_attribute_array(new_attrs, new_attrs_count,
                                        apply_attrs[i].type,
                                        apply_attrs[i].pValue,
                                        apply_attrs[i].ulValueLen);
            if (rc != CKR_OK) {
                TRACE_DEVEL("add_to_attribute_array failed\n");
                return rc;
            }
        }
    }

    return CKR_OK;
}

// publ_key_check_required_attributes()
//
CK_RV publ_key_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    // CKO_PUBLIC_KEY has no required attributes
    //
    return key_object_check_required_attributes(tmpl, mode);
}


// publ_key_set_default_attributes()
//
// some of the common public key attributes have defaults but none of the
// specific public keytypes have default attributes
//
CK_RV publ_key_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *class_attr = NULL;
    CK_ATTRIBUTE *subject_attr = NULL;
    CK_ATTRIBUTE *encrypt_attr = NULL;
    CK_ATTRIBUTE *verify_attr = NULL;
    CK_ATTRIBUTE *verify_recover_attr = NULL;
    CK_ATTRIBUTE *wrap_attr = NULL;
    CK_ATTRIBUTE *trusted_attr = NULL;
    CK_ATTRIBUTE *pki_attr = NULL;
    CK_ATTRIBUTE *wraptmpl_attr = NULL;
    CK_RV rc;


    rc = key_object_set_default_attributes(tmpl, mode);
    if (rc != CKR_OK) {
        TRACE_DEVEL("key_object_set_default_attributes failed\n");
        return rc;
    }
    // add the default CKO_PUBLIC_KEY attributes
    //
    class_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS));
    subject_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    encrypt_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    verify_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    verify_recover_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    wrap_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    trusted_attr =
            (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    pki_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    wraptmpl_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!class_attr || !subject_attr || !encrypt_attr ||
        !verify_attr || !verify_recover_attr || !wrap_attr || !trusted_attr ||
        !pki_attr || !wraptmpl_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    class_attr->type = CKA_CLASS;
    class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
    class_attr->pValue = (CK_BYTE *) class_attr + sizeof(CK_ATTRIBUTE);
    *(CK_OBJECT_CLASS *) class_attr->pValue = CKO_PUBLIC_KEY;

    subject_attr->type = CKA_SUBJECT;
    subject_attr->ulValueLen = 0;       // empty string
    subject_attr->pValue = NULL;

    encrypt_attr->type = CKA_ENCRYPT;
    encrypt_attr->ulValueLen = sizeof(CK_BBOOL);
    encrypt_attr->pValue = (CK_BYTE *) encrypt_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) encrypt_attr->pValue = TRUE;

    verify_attr->type = CKA_VERIFY;
    verify_attr->ulValueLen = sizeof(CK_BBOOL);
    verify_attr->pValue = (CK_BYTE *) verify_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) verify_attr->pValue = TRUE;

    verify_recover_attr->type = CKA_VERIFY_RECOVER;
    verify_recover_attr->ulValueLen = sizeof(CK_BBOOL);
    verify_recover_attr->pValue =
        (CK_BYTE *) verify_recover_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) verify_recover_attr->pValue = TRUE;

    wrap_attr->type = CKA_WRAP;
    wrap_attr->ulValueLen = sizeof(CK_BBOOL);
    wrap_attr->pValue = (CK_BYTE *) wrap_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) wrap_attr->pValue = TRUE;

    trusted_attr->type = CKA_TRUSTED;
    trusted_attr->ulValueLen = sizeof(CK_BBOOL);
    trusted_attr->pValue = (CK_BYTE *)trusted_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) trusted_attr->pValue = FALSE;

    pki_attr->type = CKA_PUBLIC_KEY_INFO;
    pki_attr->ulValueLen = 0;       // empty string
    pki_attr->pValue = NULL;

    wraptmpl_attr->type = CKA_WRAP_TEMPLATE;
    wraptmpl_attr->ulValueLen = 0;
    wraptmpl_attr->pValue = NULL;

    rc = template_update_attribute(tmpl, class_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    class_attr = NULL;
    rc = template_update_attribute(tmpl, subject_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    subject_attr = NULL;
    rc = template_update_attribute(tmpl, encrypt_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    encrypt_attr = NULL;
    rc = template_update_attribute(tmpl, verify_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    verify_attr = NULL;
    rc = template_update_attribute(tmpl, verify_recover_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    verify_recover_attr = NULL;
    rc = template_update_attribute(tmpl, wrap_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    wrap_attr = NULL;
    rc = template_update_attribute(tmpl, trusted_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    trusted_attr = NULL;
    rc = template_update_attribute(tmpl, pki_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    pki_attr = NULL;
    rc = template_update_attribute(tmpl, wraptmpl_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    wraptmpl_attr = NULL;

    return CKR_OK;

error:
    if (class_attr)
        free(class_attr);
    if (subject_attr)
        free(subject_attr);
    if (encrypt_attr)
        free(encrypt_attr);
    if (verify_attr)
        free(verify_attr);
    if (verify_recover_attr)
        free(verify_recover_attr);
    if (wrap_attr)
        free(wrap_attr);
    if (trusted_attr)
        free(trusted_attr);
    if (pki_attr)
        free(pki_attr);
    if (wraptmpl_attr)
        free(wraptmpl_attr);

    return rc;
}


// publ_key_validate_attribute
//
CK_RV publ_key_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    CK_RV rc;

    switch (attr->type) {
    case CKA_SUBJECT:
        return CKR_OK;
    case CKA_ENCRYPT:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
    case CKA_WRAP:
        if (mode == MODE_MODIFY) {
            if (tokdata->nv_token_data->tweak_vector.allow_key_mods == TRUE)
                return CKR_OK;

            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        return CKR_OK;
    case CKA_TRUSTED:
        /* Can only be set to CK_TRUE by the SO user */
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (*((CK_BBOOL *)attr->pValue) == CK_TRUE &&
            !session_mgr_so_session_exists(tokdata)) {
            TRACE_ERROR("CKA_TRUSTED can only be set to TRUE by SO\n");
            return CKR_USER_NOT_LOGGED_IN;
        }
        return CKR_OK;
    case CKA_PUBLIC_KEY_INFO:
        if (mode == MODE_CREATE || mode == MODE_UNWRAP)
            return CKR_OK;
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_WRAP_TEMPLATE:
        if ((attr->ulValueLen > 0 && attr->pValue == NULL) ||
            attr->ulValueLen % sizeof(CK_ATTRIBUTE)) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        rc = validate_attribute_array((CK_ATTRIBUTE_PTR)attr->pValue,
                                      attr->ulValueLen / sizeof(CK_ATTRIBUTE));
        if (rc != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(rc));
            return rc;
        }
        if (mode == MODE_CREATE || mode == MODE_KEYGEN ||
            mode == MODE_DERIVE || mode == MODE_UNWRAP)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return key_object_validate_attribute(tmpl, attr, mode);
    }

    TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID), attr->type);

    return CKR_ATTRIBUTE_TYPE_INVALID;
}

/*
 * Extract the SubjectPublicKeyInfo from the public key
 */
CK_RV publ_key_get_spki(TEMPLATE *tmpl, CK_ULONG keytype, CK_BBOOL length_only,
                        CK_BYTE **data, CK_ULONG *data_len)
{
    CK_RV rc;

    switch (keytype) {
    case CKK_RSA:
        rc = rsa_publ_get_spki(tmpl, length_only, data, data_len);
        break;
    case CKK_DSA:
        rc = dsa_publ_get_spki(tmpl, length_only, data, data_len);
        break;
    case CKK_DH:
        rc = dh_publ_get_spki(tmpl, length_only, data, data_len);
        break;
    case CKK_EC:
        rc = ec_publ_get_spki(tmpl, length_only, data, data_len);
        break;
    case CKK_IBM_PQC_DILITHIUM:
        rc = ibm_dilithium_publ_get_spki(tmpl, length_only, data, data_len);
        break;
    case CKK_IBM_PQC_KYBER:
        rc = ibm_kyber_publ_get_spki(tmpl, length_only, data, data_len);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    return rc;
}

// priv_key_check_required_attributes()
//
CK_RV priv_key_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    // CKO_PRIVATE_KEY has no required attributes
    //
    return key_object_check_required_attributes(tmpl, mode);
}


// priv_key_set_default_attributes()
//
// some of the common private key attributes have defaults but none of the
// specific private keytypes have default attributes
//
CK_RV priv_key_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *class_attr = NULL;
    CK_ATTRIBUTE *subject_attr = NULL;
    CK_ATTRIBUTE *sensitive_attr = NULL;
    CK_ATTRIBUTE *decrypt_attr = NULL;
    CK_ATTRIBUTE *sign_attr = NULL;
    CK_ATTRIBUTE *sign_recover_attr = NULL;
    CK_ATTRIBUTE *unwrap_attr = NULL;
    CK_ATTRIBUTE *extractable_attr = NULL;
    CK_ATTRIBUTE *never_extr_attr = NULL;
    CK_ATTRIBUTE *always_sens_attr = NULL;
    CK_ATTRIBUTE *always_auth_attr = NULL;
    CK_ATTRIBUTE *wrap_trusted_attr = NULL;
    CK_ATTRIBUTE *pki_attr = NULL;
    CK_ATTRIBUTE *unwraptmpl_attr = NULL;
    CK_ATTRIBUTE *derivetmpl_attr = NULL;
    CK_RV rc;


    rc = key_object_set_default_attributes(tmpl, mode);
    if (rc != CKR_OK) {
        TRACE_DEVEL("key_object_set_default_attributes failed\n");
        return rc;
    }
    // add the default CKO_PUBLIC_KEY attributes
    //
    class_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS));
    subject_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    sensitive_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    decrypt_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    sign_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    sign_recover_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    unwrap_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    extractable_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    never_extr_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    always_sens_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    always_auth_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    wrap_trusted_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    pki_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    unwraptmpl_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    derivetmpl_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!class_attr || !subject_attr || !sensitive_attr || !decrypt_attr ||
        !sign_attr || !sign_recover_attr || !unwrap_attr || !extractable_attr ||
        !never_extr_attr || !always_sens_attr || !always_auth_attr ||
        !wrap_trusted_attr || !pki_attr || !unwraptmpl_attr ||
        !derivetmpl_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    class_attr->type = CKA_CLASS;
    class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
    class_attr->pValue = (CK_BYTE *) class_attr + sizeof(CK_ATTRIBUTE);
    *(CK_OBJECT_CLASS *) class_attr->pValue = CKO_PRIVATE_KEY;

    subject_attr->type = CKA_SUBJECT;
    subject_attr->ulValueLen = 0;       // empty string
    subject_attr->pValue = NULL;

    sensitive_attr->type = CKA_SENSITIVE;
    sensitive_attr->ulValueLen = sizeof(CK_BBOOL);
    sensitive_attr->pValue = (CK_BYTE *) sensitive_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) sensitive_attr->pValue = FALSE;

    decrypt_attr->type = CKA_DECRYPT;
    decrypt_attr->ulValueLen = sizeof(CK_BBOOL);
    decrypt_attr->pValue = (CK_BYTE *) decrypt_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) decrypt_attr->pValue = TRUE;

    sign_attr->type = CKA_SIGN;
    sign_attr->ulValueLen = sizeof(CK_BBOOL);
    sign_attr->pValue = (CK_BYTE *) sign_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) sign_attr->pValue = TRUE;

    sign_recover_attr->type = CKA_SIGN_RECOVER;
    sign_recover_attr->ulValueLen = sizeof(CK_BBOOL);
    sign_recover_attr->pValue =
        (CK_BYTE *) sign_recover_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) sign_recover_attr->pValue = TRUE;

    unwrap_attr->type = CKA_UNWRAP;
    unwrap_attr->ulValueLen = sizeof(CK_BBOOL);
    unwrap_attr->pValue = (CK_BYTE *) unwrap_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) unwrap_attr->pValue = TRUE;

    extractable_attr->type = CKA_EXTRACTABLE;
    extractable_attr->ulValueLen = sizeof(CK_BBOOL);
    extractable_attr->pValue =
        (CK_BYTE *) extractable_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) extractable_attr->pValue = TRUE;

    // by default, we'll set NEVER_EXTRACTABLE == FALSE and
    // ALWAYS_SENSITIVE == FALSE
    // If the key is being created with KEYGEN, it will adjust as necessary.
    //
    never_extr_attr->type = CKA_NEVER_EXTRACTABLE;
    never_extr_attr->ulValueLen = sizeof(CK_BBOOL);
    never_extr_attr->pValue =
        (CK_BYTE *) never_extr_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) never_extr_attr->pValue = FALSE;

    always_sens_attr->type = CKA_ALWAYS_SENSITIVE;
    always_sens_attr->ulValueLen = sizeof(CK_BBOOL);
    always_sens_attr->pValue =
        (CK_BYTE *) always_sens_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) always_sens_attr->pValue = FALSE;

    always_auth_attr->type = CKA_ALWAYS_AUTHENTICATE;
    always_auth_attr->ulValueLen = sizeof(CK_BBOOL);
    always_auth_attr->pValue =
        (CK_BYTE *) always_auth_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) always_auth_attr->pValue = FALSE;

    wrap_trusted_attr->type = CKA_WRAP_WITH_TRUSTED;
    wrap_trusted_attr->ulValueLen = sizeof(CK_BBOOL);
    wrap_trusted_attr->pValue =
        (CK_BYTE *) wrap_trusted_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) wrap_trusted_attr->pValue = FALSE;

    pki_attr->type = CKA_SUBJECT;
    pki_attr->ulValueLen = 0;       // empty string
    pki_attr->pValue = NULL;

    unwraptmpl_attr->type = CKA_UNWRAP_TEMPLATE;
    unwraptmpl_attr->ulValueLen = 0;
    unwraptmpl_attr->pValue = NULL;

    derivetmpl_attr->type = CKA_DERIVE_TEMPLATE;
    derivetmpl_attr->ulValueLen = 0;
    derivetmpl_attr->pValue = NULL;

    rc = template_update_attribute(tmpl, class_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    class_attr = NULL;
    rc = template_update_attribute(tmpl, subject_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    subject_attr = NULL;
    rc = template_update_attribute(tmpl, sensitive_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    sensitive_attr = NULL;
    rc = template_update_attribute(tmpl, decrypt_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    decrypt_attr = NULL;
    rc = template_update_attribute(tmpl, sign_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    sign_attr = NULL;
    rc = template_update_attribute(tmpl, sign_recover_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    sign_recover_attr = NULL;
    rc = template_update_attribute(tmpl, unwrap_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    unwrap_attr = NULL;
    rc = template_update_attribute(tmpl, extractable_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    extractable_attr = NULL;
    rc = template_update_attribute(tmpl, never_extr_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    never_extr_attr = NULL;
    rc = template_update_attribute(tmpl, always_sens_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    always_sens_attr = NULL;
    rc = template_update_attribute(tmpl, always_auth_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    always_auth_attr = NULL;
    rc = template_update_attribute(tmpl, wrap_trusted_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    wrap_trusted_attr = NULL;
    rc = template_update_attribute(tmpl, pki_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    pki_attr = NULL;
    rc = template_update_attribute(tmpl, unwraptmpl_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    unwraptmpl_attr = NULL;
    rc = template_update_attribute(tmpl, derivetmpl_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    derivetmpl_attr = NULL;

    return CKR_OK;

error:
    if (class_attr)
        free(class_attr);
    if (subject_attr)
        free(subject_attr);
    if (sensitive_attr)
        free(sensitive_attr);
    if (decrypt_attr)
        free(decrypt_attr);
    if (sign_attr)
        free(sign_attr);
    if (sign_recover_attr)
        free(sign_recover_attr);
    if (unwrap_attr)
        free(unwrap_attr);
    if (extractable_attr)
        free(extractable_attr);
    if (always_sens_attr)
        free(always_sens_attr);
    if (never_extr_attr)
        free(never_extr_attr);
    if (always_auth_attr)
        free(always_auth_attr);
    if (wrap_trusted_attr)
        free(wrap_trusted_attr);
    if (pki_attr)
        free(pki_attr);
    if (unwraptmpl_attr)
        free(unwraptmpl_attr);
    if (derivetmpl_attr)
        free(derivetmpl_attr);

    return rc;
}


//
//
CK_RV priv_key_unwrap(TEMPLATE *tmpl,
                      CK_ULONG keytype,
                      CK_BYTE *data, CK_ULONG data_len)
{
    CK_ATTRIBUTE *extractable = NULL;
    CK_ATTRIBUTE *always_sens = NULL;
    CK_ATTRIBUTE *never_extract = NULL;
    CK_ATTRIBUTE *sensitive = NULL;
    CK_ATTRIBUTE *local = NULL;
    CK_ATTRIBUTE *pub_key_info = NULL;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_BYTE *spki = NULL;
    CK_ULONG spki_length = 0;
    CK_RV rc;

    switch (keytype) {
    case CKK_RSA:
        rc = rsa_priv_unwrap(tmpl, data, data_len);
        break;
    case CKK_DSA:
        rc = dsa_priv_unwrap(tmpl, data, data_len);
        break;
    case CKK_DH:
        rc = dh_priv_unwrap(tmpl, data, data_len);
        break;
    case CKK_EC:
        rc = ec_priv_unwrap(tmpl, data, data_len);
        break;
    case CKK_IBM_PQC_DILITHIUM:
        rc = ibm_dilithium_priv_unwrap(tmpl, data, data_len, TRUE);
        break;
    case CKK_IBM_PQC_KYBER:
        rc = ibm_kyber_priv_unwrap(tmpl, data, data_len, TRUE);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_WRAPPED_KEY_INVALID));
        return CKR_WRAPPED_KEY_INVALID;
    }

    if (rc != CKR_OK) {
        TRACE_DEVEL("priv unwrap failed\n");
        return rc;
    }
    // make sure
    //    CKA_LOCAL             == FALSE
    //    CKA_ALWAYS_SENSITIVE  == FALSE
    //    CKA_EXTRACTABLE       == TRUE
    //    CKA_NEVER_EXTRACTABLE == FALSE
    //
    rc = build_attribute(CKA_LOCAL, &false, 1, &local);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    rc = build_attribute(CKA_ALWAYS_SENSITIVE, &false, 1, &always_sens);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    rc = build_attribute(CKA_SENSITIVE, &false, 1, &sensitive);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    rc = build_attribute(CKA_EXTRACTABLE, &true, 1, &extractable);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    rc = build_attribute(CKA_NEVER_EXTRACTABLE, &false, 1, &never_extract);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }

    /*
     * Try to extract the SPKI and add CKA_PUBLIC_KEY_INFO to the key.
     * This may fail if the public key info can not be reconstructed from
     * the private key (e.g. because its a secure key token).
     */
    rc = publ_key_get_spki(tmpl, keytype, FALSE, &spki, &spki_length);
    if (rc == CKR_OK && spki != NULL && spki_length > 0) {
        rc = build_attribute(CKA_PUBLIC_KEY_INFO, spki, spki_length,
                             &pub_key_info);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto cleanup;
        }

        rc = template_update_attribute(tmpl, pub_key_info);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_update_attribute failed.\n");
            goto cleanup;
        }
        pub_key_info = NULL;
    }

    rc = template_update_attribute(tmpl, local);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto cleanup;
    }
    local = NULL;
    rc = template_update_attribute(tmpl, always_sens);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto cleanup;
    }
    always_sens = NULL;
    rc = template_update_attribute(tmpl, sensitive);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto cleanup;
    }
    sensitive = NULL;
    rc = template_update_attribute(tmpl, extractable);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto cleanup;
    }
    extractable = NULL;
    rc = template_update_attribute(tmpl, never_extract);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto cleanup;
    }
    never_extract = NULL;

    if (spki != NULL)
        free(spki);

    return CKR_OK;

cleanup:
    if (local)
        free(local);
    if (always_sens)
        free(always_sens);
    if (sensitive)
        free(sensitive);
    if (extractable)
        free(extractable);
    if (never_extract)
        free(never_extract);
    if (pub_key_info)
        free(pub_key_info);
    if (spki != NULL)
        free(spki);

    return rc;
}


// priv_key_validate_attribute()
//
CK_RV priv_key_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    CK_RV rc;

    switch (attr->type) {
    case CKA_SUBJECT:
        return CKR_OK;
    case CKA_DECRYPT:
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_UNWRAP:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        // we might want to do this for MODE_COPY too
        //
        if (mode == MODE_MODIFY) {
            if (tokdata->nv_token_data->tweak_vector.allow_key_mods == TRUE)
                return CKR_OK;

            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        return CKR_OK;
        /*
         * After key creation, CKA_SENSITIVE and CKA_WRAP_WITH_TRUSTED may only
         * be set to TRUE
         */
    case CKA_SENSITIVE:
    case CKA_WRAP_WITH_TRUSTED:
        {
            CK_BBOOL value;

            if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }

            if (mode == MODE_CREATE || mode == MODE_KEYGEN)
                return CKR_OK;

            value = *(CK_BBOOL *) attr->pValue;
            if (value != TRUE) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
                return CKR_ATTRIBUTE_READ_ONLY;
            }
            return CKR_OK;
        }
        // after key creation, CKA_EXTRACTABLE may only be set to FALSE
        //
    case CKA_EXTRACTABLE:
        {
            CK_BBOOL value;

            if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }

            value = *(CK_BBOOL *) attr->pValue;
            if ((mode != MODE_CREATE && mode != MODE_KEYGEN) &&
                value != FALSE) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
                return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (value == FALSE) {
                CK_ATTRIBUTE *attr;

                attr =
                    (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) +
                                            sizeof(CK_BBOOL));
                if (!attr) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    return CKR_HOST_MEMORY;
                }
                attr->type = CKA_NEVER_EXTRACTABLE;
                attr->ulValueLen = sizeof(CK_BBOOL);
                attr->pValue = (CK_BYTE *) attr + sizeof(CK_ATTRIBUTE);
                *(CK_BBOOL *) attr->pValue = FALSE;

                rc = template_update_attribute(tmpl, attr);
                if (rc != CKR_OK) {
                    TRACE_DEVEL("template_update_attribute failed.\n");
                    free(attr);
                    return rc;
                }
            }
            return CKR_OK;
        }
    case CKA_ALWAYS_SENSITIVE:
    case CKA_NEVER_EXTRACTABLE:
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_PUBLIC_KEY_INFO:
        /*
         * PKCS#11: A token MAY choose not to support the CKA_PUBLIC_KEY_INFO
         * attribute for commands which create new private keys. If it does not
         * support the attribute, the command SHALL return
         * CKR_ATTRIBUTE_TYPE_INVALID.
         */
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID));
        return CKR_ATTRIBUTE_TYPE_INVALID;
    case CKA_UNWRAP_TEMPLATE:
    case CKA_DERIVE_TEMPLATE:
        if ((attr->ulValueLen > 0 && attr->pValue == NULL) ||
            attr->ulValueLen % sizeof(CK_ATTRIBUTE)) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        rc = validate_attribute_array((CK_ATTRIBUTE_PTR)attr->pValue,
                                      attr->ulValueLen / sizeof(CK_ATTRIBUTE));
        if (rc != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(rc));
            return rc;
        }
        if (mode == MODE_CREATE || mode == MODE_KEYGEN ||
            mode == MODE_DERIVE || mode == MODE_UNWRAP)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;

    default:
        return key_object_validate_attribute(tmpl, attr, mode);
    }

    TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID), attr->type);

    return CKR_ATTRIBUTE_TYPE_INVALID;
}




// secret_key_check_required_attributes()
//
CK_RV secret_key_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    return key_object_check_required_attributes(tmpl, mode);
}


// secret_key_set_default_attributes()
//
// some of the common secret key attributes have defaults but none of the
// specific secret keytypes have default attributes
//
CK_RV secret_key_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *class_attr = NULL;
    CK_ATTRIBUTE *sensitive_attr = NULL;
    CK_ATTRIBUTE *encrypt_attr = NULL;
    CK_ATTRIBUTE *decrypt_attr = NULL;
    CK_ATTRIBUTE *sign_attr = NULL;
    CK_ATTRIBUTE *verify_attr = NULL;
    CK_ATTRIBUTE *wrap_attr = NULL;
    CK_ATTRIBUTE *unwrap_attr = NULL;
    CK_ATTRIBUTE *extractable_attr = NULL;
    CK_ATTRIBUTE *never_extr_attr = NULL;
    CK_ATTRIBUTE *always_sens_attr = NULL;
    CK_ATTRIBUTE *trusted_attr = NULL;
    CK_ATTRIBUTE *wrap_trusted_attr = NULL;
    CK_ATTRIBUTE *chkval_attr = NULL;
    CK_ATTRIBUTE *wraptmpl_attr = NULL;
    CK_ATTRIBUTE *unwraptmpl_attr = NULL;
    CK_ATTRIBUTE *derivetmpl_attr = NULL;
    CK_RV rc;


    rc = key_object_set_default_attributes(tmpl, mode);
    if (rc != CKR_OK)
        return rc;

    // add the default CKO_DATA attributes
    //
    class_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS));
    sensitive_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    encrypt_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    decrypt_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    sign_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    verify_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    wrap_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    unwrap_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    extractable_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    never_extr_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    always_sens_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    trusted_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    wrap_trusted_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    chkval_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    wraptmpl_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    unwraptmpl_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    derivetmpl_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!class_attr || !sensitive_attr || !encrypt_attr || !decrypt_attr ||
        !sign_attr || !verify_attr || !wrap_attr ||
        !unwrap_attr || !extractable_attr || !never_extr_attr
        || !always_sens_attr  || !trusted_attr || !wrap_trusted_attr ||
        !chkval_attr || !wraptmpl_attr || !unwraptmpl_attr ||
        !derivetmpl_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    class_attr->type = CKA_CLASS;
    class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
    class_attr->pValue = (CK_BYTE *) class_attr + sizeof(CK_ATTRIBUTE);
    *(CK_OBJECT_CLASS *) class_attr->pValue = CKO_SECRET_KEY;

    sensitive_attr->type = CKA_SENSITIVE;
    sensitive_attr->ulValueLen = sizeof(CK_BBOOL);
    sensitive_attr->pValue = (CK_BYTE *) sensitive_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) sensitive_attr->pValue = FALSE;

    encrypt_attr->type = CKA_ENCRYPT;
    encrypt_attr->ulValueLen = sizeof(CK_BBOOL);
    encrypt_attr->pValue = (CK_BYTE *) encrypt_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) encrypt_attr->pValue = TRUE;

    decrypt_attr->type = CKA_DECRYPT;
    decrypt_attr->ulValueLen = sizeof(CK_BBOOL);
    decrypt_attr->pValue = (CK_BYTE *) decrypt_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) decrypt_attr->pValue = TRUE;

    sign_attr->type = CKA_SIGN;
    sign_attr->ulValueLen = sizeof(CK_BBOOL);
    sign_attr->pValue = (CK_BYTE *) sign_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) sign_attr->pValue = TRUE;

    verify_attr->type = CKA_VERIFY;
    verify_attr->ulValueLen = sizeof(CK_BBOOL);
    verify_attr->pValue = (CK_BYTE *) verify_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) verify_attr->pValue = TRUE;

    wrap_attr->type = CKA_WRAP;
    wrap_attr->ulValueLen = sizeof(CK_BBOOL);
    wrap_attr->pValue = (CK_BYTE *) wrap_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) wrap_attr->pValue = TRUE;

    unwrap_attr->type = CKA_UNWRAP;
    unwrap_attr->ulValueLen = sizeof(CK_BBOOL);
    unwrap_attr->pValue = (CK_BYTE *) unwrap_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) unwrap_attr->pValue = TRUE;

    extractable_attr->type = CKA_EXTRACTABLE;
    extractable_attr->ulValueLen = sizeof(CK_BBOOL);
    extractable_attr->pValue =
        (CK_BYTE *) extractable_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) extractable_attr->pValue = TRUE;

    // by default, we'll set NEVER_EXTRACTABLE == FALSE and
    // ALWAYS_SENSITIVE == FALSE
    // If the key is being created with KEYGEN, it will adjust as necessary.
    //
    always_sens_attr->type = CKA_ALWAYS_SENSITIVE;
    always_sens_attr->ulValueLen = sizeof(CK_BBOOL);
    always_sens_attr->pValue =
        (CK_BYTE *) always_sens_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) always_sens_attr->pValue = FALSE;

    never_extr_attr->type = CKA_NEVER_EXTRACTABLE;
    never_extr_attr->ulValueLen = sizeof(CK_BBOOL);
    never_extr_attr->pValue =
        (CK_BYTE *) never_extr_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) never_extr_attr->pValue = FALSE;

    trusted_attr->type = CKA_TRUSTED;
    trusted_attr->ulValueLen = sizeof(CK_BBOOL);
    trusted_attr->pValue = (CK_BYTE *)trusted_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) trusted_attr->pValue = FALSE;

    wrap_trusted_attr->type = CKA_WRAP_WITH_TRUSTED;
    wrap_trusted_attr->ulValueLen = sizeof(CK_BBOOL);
    wrap_trusted_attr->pValue =
        (CK_BYTE *) wrap_trusted_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) wrap_trusted_attr->pValue = FALSE;

    chkval_attr->type = CKA_CHECK_VALUE;
    chkval_attr->ulValueLen = 0;
    chkval_attr->pValue = NULL;

    wraptmpl_attr->type = CKA_WRAP_TEMPLATE;
    wraptmpl_attr->ulValueLen = 0;
    wraptmpl_attr->pValue = NULL;

    unwraptmpl_attr->type = CKA_UNWRAP_TEMPLATE;
    unwraptmpl_attr->ulValueLen = 0;
    unwraptmpl_attr->pValue = NULL;

    derivetmpl_attr->type = CKA_DERIVE_TEMPLATE;
    derivetmpl_attr->ulValueLen = 0;
    derivetmpl_attr->pValue = NULL;

    rc = template_update_attribute(tmpl, class_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    class_attr = NULL;
    rc = template_update_attribute(tmpl, sensitive_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    sensitive_attr = NULL;
    rc = template_update_attribute(tmpl, encrypt_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    encrypt_attr = NULL;
    rc = template_update_attribute(tmpl, decrypt_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    decrypt_attr = NULL;
    rc = template_update_attribute(tmpl, sign_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    sign_attr = NULL;
    rc = template_update_attribute(tmpl, verify_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    verify_attr = NULL;
    rc = template_update_attribute(tmpl, wrap_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    wrap_attr = NULL;
    rc = template_update_attribute(tmpl, unwrap_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    unwrap_attr = NULL;
    rc = template_update_attribute(tmpl, extractable_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    extractable_attr = NULL;
    rc = template_update_attribute(tmpl, never_extr_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    never_extr_attr = NULL;
    rc = template_update_attribute(tmpl, always_sens_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    always_sens_attr = NULL;
    rc = template_update_attribute(tmpl, trusted_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    trusted_attr = NULL;
    rc = template_update_attribute(tmpl, wrap_trusted_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    wrap_trusted_attr = NULL;
    rc = template_update_attribute(tmpl, chkval_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    chkval_attr = NULL;
    rc = template_update_attribute(tmpl, wraptmpl_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    wraptmpl_attr = NULL;
    rc = template_update_attribute(tmpl, unwraptmpl_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    unwraptmpl_attr = NULL;
    rc = template_update_attribute(tmpl, derivetmpl_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    derivetmpl_attr = NULL;

    return CKR_OK;

error:
    if (class_attr)
        free(class_attr);
    if (sensitive_attr)
        free(sensitive_attr);
    if (encrypt_attr)
        free(encrypt_attr);
    if (decrypt_attr)
        free(decrypt_attr);
    if (sign_attr)
        free(sign_attr);
    if (verify_attr)
        free(verify_attr);
    if (wrap_attr)
        free(wrap_attr);
    if (unwrap_attr)
        free(unwrap_attr);
    if (extractable_attr)
        free(extractable_attr);
    if (never_extr_attr)
        free(never_extr_attr);
    if (always_sens_attr)
        free(always_sens_attr);
    if (trusted_attr)
        free(trusted_attr);
    if (wrap_trusted_attr)
        free(wrap_trusted_attr);
    if (chkval_attr)
        free(chkval_attr);
    if (wraptmpl_attr)
        free(wraptmpl_attr);
    if (unwraptmpl_attr)
        free(unwraptmpl_attr);
    if (derivetmpl_attr)
        free(derivetmpl_attr);

    return rc;
}


//
//
CK_RV secret_key_unwrap(STDLL_TokData_t *tokdata,
                        TEMPLATE *tmpl,
                        CK_ULONG keytype,
                        CK_BYTE *data,
                        CK_ULONG data_len, CK_BBOOL fromend)
{
    CK_ATTRIBUTE *local = NULL;
    CK_ATTRIBUTE *always_sens = NULL;
    CK_ATTRIBUTE *sensitive = NULL;
    CK_ATTRIBUTE *extractable = NULL;
    CK_ATTRIBUTE *never_extract = NULL;
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_RV rc;

    switch (keytype) {
    case CKK_DES:
        rc = des_unwrap(tokdata, tmpl, data, data_len, fromend);
        break;
    case CKK_DES3:
        rc = des3_unwrap(tokdata, tmpl, data, data_len, fromend);
        break;
    case CKK_AES:
    case CKK_AES_XTS:
        rc = aes_unwrap(tokdata, tmpl, data, data_len, fromend,
                        keytype == CKK_AES_XTS);
        break;
    case CKK_GENERIC_SECRET:
        rc = generic_secret_unwrap(tmpl, data, data_len, fromend);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_WRAPPED_KEY_INVALID));
        return CKR_WRAPPED_KEY_INVALID;
    }

    if (rc != CKR_OK)
        return rc;

    // make sure
    //    CKA_LOCAL             == FALSE
    //    CKA_ALWAYS_SENSITIVE  == FALSE
    //    CKA_EXTRACTABLE       == TRUE
    //    CKA_NEVER_EXTRACTABLE == FALSE
    //
    rc = build_attribute(CKA_LOCAL, &false, 1, &local);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build attribute failed\n");
        goto cleanup;
    }
    rc = build_attribute(CKA_ALWAYS_SENSITIVE, &false, 1, &always_sens);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build attribute failed\n");
        goto cleanup;
    }
    rc = build_attribute(CKA_SENSITIVE, &false, 1, &sensitive);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    rc = build_attribute(CKA_EXTRACTABLE, &true, 1, &extractable);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    rc = build_attribute(CKA_NEVER_EXTRACTABLE, &false, 1, &never_extract);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto cleanup;
    }
    rc = template_update_attribute(tmpl, local);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto cleanup;
    }
    local = NULL;
    rc = template_update_attribute(tmpl, always_sens);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto cleanup;
    }
    always_sens = NULL;
    rc = template_update_attribute(tmpl, sensitive);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto cleanup;
    }
    sensitive = NULL;
    rc = template_update_attribute(tmpl, extractable);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto cleanup;
    }
    extractable = NULL;
    rc = template_update_attribute(tmpl, never_extract);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto cleanup;
    }
    never_extract = NULL;

    return CKR_OK;

cleanup:
    if (local)
        free(local);
    if (sensitive)
        free(sensitive);
    if (extractable)
        free(extractable);
    if (always_sens)
        free(always_sens);
    if (never_extract)
        free(never_extract);

    return rc;
}




// secret_key_validate_attribute()
//
CK_RV secret_key_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                    CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    CK_RV rc;

    switch (attr->type) {
    case CKA_ENCRYPT:
    case CKA_DECRYPT:
    case CKA_SIGN:
    case CKA_VERIFY:
    case CKA_WRAP:
    case CKA_UNWRAP:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_MODIFY) {
            if (tokdata->nv_token_data->tweak_vector.allow_key_mods == TRUE)
                return CKR_OK;

            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        return CKR_OK;
    case CKA_TRUSTED:
        /* Can only be set to CK_TRUE by the SO user */
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (*((CK_BBOOL *)attr->pValue) == CK_TRUE &&
            !session_mgr_so_session_exists(tokdata)) {
            TRACE_ERROR("CKA_TRUSTED can only be set to TRUE by SO\n");
            return CKR_USER_NOT_LOGGED_IN;
        }
        return CKR_OK;
        /*
         * After key creation, CKA_SENSITIVE and CKA_WRAP_WITH_TRUSTED may only
         * be set to TRUE
         */
    case CKA_SENSITIVE:
    case CKA_WRAP_WITH_TRUSTED:
        {
            CK_BBOOL value;

            if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            value = *(CK_BBOOL *) attr->pValue;
            if ((mode != MODE_CREATE && mode != MODE_DERIVE &&
                 mode != MODE_KEYGEN) && (value != TRUE)) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
                return CKR_ATTRIBUTE_READ_ONLY;
            }
            return CKR_OK;
        }
        // after key creation, CKA_EXTRACTABLE may only be set to FALSE
        //
    case CKA_EXTRACTABLE:
        {
            CK_BBOOL value;

            // the unwrap routine will automatically set extractable to TRUE
            //
            if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            value = *(CK_BBOOL *) attr->pValue;
            if ((mode != MODE_CREATE && mode != MODE_DERIVE &&
                 mode != MODE_KEYGEN) && (value != FALSE)) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
                return CKR_ATTRIBUTE_READ_ONLY;
            }
            if (value == FALSE) {
                CK_ATTRIBUTE *attr;

                attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) +
                                               sizeof(CK_BBOOL));
                if (!attr) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    return CKR_HOST_MEMORY;
                }
                attr->type = CKA_NEVER_EXTRACTABLE;
                attr->ulValueLen = sizeof(CK_BBOOL);
                attr->pValue = (CK_BYTE *) attr + sizeof(CK_ATTRIBUTE);
                *(CK_BBOOL *) attr->pValue = FALSE;

                rc = template_update_attribute(tmpl, attr);
                if (rc != CKR_OK) {
                    TRACE_DEVEL("template_update_attribute failed.\n");
                    free(attr);
                    return rc;
                }
            }
            return CKR_OK;
        }
    case CKA_ALWAYS_SENSITIVE:
    case CKA_NEVER_EXTRACTABLE:
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_CHECK_VALUE:
        if (mode != MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        return CKR_OK;
    case CKA_WRAP_TEMPLATE:
    case CKA_UNWRAP_TEMPLATE:
    case CKA_DERIVE_TEMPLATE:
        if ((attr->ulValueLen > 0 && attr->pValue == NULL) ||
            attr->ulValueLen % sizeof(CK_ATTRIBUTE)) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        rc = validate_attribute_array((CK_ATTRIBUTE_PTR)attr->pValue,
                                      attr->ulValueLen / sizeof(CK_ATTRIBUTE));
        if (rc != CKR_OK) {
            TRACE_ERROR("%s\n", ock_err(rc));
            return rc;
        }
        if (mode == MODE_CREATE || mode == MODE_KEYGEN ||
            mode == MODE_DERIVE || mode == MODE_UNWRAP)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return key_object_validate_attribute(tmpl, attr, mode);
    }

    TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID), attr->type);

    return CKR_ATTRIBUTE_TYPE_INVALID;
}


// secret_key_check_exportability()
//
CK_BBOOL secret_key_check_exportability(CK_ATTRIBUTE_TYPE type)
{
    switch (type) {
    case CKA_VALUE:
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_UNEXTRACTABLE));
        return FALSE;
    }

    return TRUE;
}


// rsa_publ_check_required_attributes()
//
CK_RV rsa_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG val;
    CK_RV rc;

    if (mode == MODE_CREATE &&
        token_specific.secure_key_token == TRUE &&
        template_attribute_get_non_empty(tmpl, CKA_IBM_OPAQUE, &attr) == CKR_OK) {
        /*
         * Import of an already existing secure key. Only
         * do the base checks for public key templates.
         */
        return publ_key_check_required_attributes(tmpl, mode);
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_MODULUS, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_MODULUS\n");
            return rc;
        }
    }

    rc = template_attribute_get_ulong(tmpl, CKA_MODULUS_BITS, &val);
    if (rc != CKR_OK) {
        if (mode == MODE_KEYGEN) {
            TRACE_ERROR("Could not find CKA_MODULUS_BITS\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_PUBLIC_EXPONENT, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_PUBLIC_EXPONENT\n");
            return rc;
        }
    }

    return publ_key_check_required_attributes(tmpl, mode);
}


//  rsa_publ_set_default_attributes()
//
CK_RV rsa_publ_set_default_attributes(TEMPLATE *tmpl, TEMPLATE *basetmpl,
                                      CK_ULONG mode)
{
    CK_ATTRIBUTE *type_attr = NULL;
    CK_ATTRIBUTE *modulus_attr = NULL;
    CK_ATTRIBUTE *modulus_bits_attr = NULL;
    CK_ATTRIBUTE *public_exp_attr = NULL;
    CK_ATTRIBUTE *tmpattr = NULL;
    CK_ULONG bits = 0L;
    CK_BYTE pubExp[3] = { 0x01, 0x00, 0x01 };
    CK_RV rc;

    publ_key_set_default_attributes(tmpl, mode);

    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    modulus_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    modulus_bits_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG));
    public_exp_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(pubExp));

    if (!type_attr || !modulus_attr || !modulus_bits_attr || !public_exp_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_RSA;

    modulus_attr->type = CKA_MODULUS;
    modulus_attr->ulValueLen = 0;
    modulus_attr->pValue = NULL;

    modulus_bits_attr->type = CKA_MODULUS_BITS;
    modulus_bits_attr->ulValueLen = sizeof(CK_ULONG);
    modulus_bits_attr->pValue =
        (CK_BYTE *) modulus_bits_attr + sizeof(CK_ATTRIBUTE);

    if (template_attribute_find(basetmpl, CKA_MODULUS, &tmpattr)) {
        *(CK_ULONG *) modulus_bits_attr->pValue = 8 * tmpattr->ulValueLen;
    } else {
        *(CK_ULONG *) modulus_bits_attr->pValue = bits;
    }

    public_exp_attr->type = CKA_PUBLIC_EXPONENT;
    public_exp_attr->ulValueLen = sizeof(pubExp);
    public_exp_attr->pValue =
        (CK_BYTE *) public_exp_attr + sizeof(CK_ATTRIBUTE);
    memcpy(public_exp_attr->pValue, pubExp, sizeof(pubExp));

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, modulus_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    modulus_attr = NULL;
    rc = template_update_attribute(tmpl, modulus_bits_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    modulus_bits_attr = NULL;
    rc = template_update_attribute(tmpl, public_exp_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    public_exp_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (modulus_attr)
        free(modulus_attr);
    if (modulus_bits_attr)
        free(modulus_bits_attr);
    if (public_exp_attr)
        free(public_exp_attr);

    return rc;
}


// rsa_publ_validate_attributes()
//
CK_RV rsa_publ_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_MODULUS_BITS:
        if (mode == MODE_KEYGEN) {
            if (attr->ulValueLen != sizeof(CK_ULONG) ||
                attr->pValue == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            } else {
                CK_ULONG mod_bits = *(CK_ULONG *) attr->pValue;

                if (mod_bits < 512 || mod_bits > 4096) {
                    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }

                if (mod_bits % 8 != 0) {
                    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                return CKR_OK;
            }
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_MODULUS:
        if (mode == MODE_CREATE) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_PUBLIC_EXPONENT:
        if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return publ_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}

/*
 * Extract the SubjectPublicKeyInfo from the RSA public key
 */
CK_RV rsa_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                        CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *modulus = NULL;
    CK_ATTRIBUTE *publ_exp = NULL;
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_MODULUS, &modulus);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_PUBLIC_EXPONENT, &publ_exp);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_PUBLIC_EXPONENT for the key.\n");
        return rc;
    }

    rc = ber_encode_RSAPublicKey(length_only, data,data_len, modulus, publ_exp);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_RSAPublicKey failed.\n");
        return rc;
    }

    return CKR_OK;
}

// rsa_priv_check_required_attributes()
//
CK_RV rsa_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL, *coef = NULL;
    CK_ATTRIBUTE *prime1 = NULL, *prime2 = NULL, *exp1 = NULL, *exp2 = NULL;
    CK_RV rc;

    if (mode == MODE_CREATE &&
        token_specific.secure_key_token == TRUE &&
        template_attribute_get_non_empty(tmpl, CKA_IBM_OPAQUE, &attr) == CKR_OK) {
        /*
         * Import of an already existing secure key. Only
         * do the base checks for private key templates.
         */
        return priv_key_check_required_attributes(tmpl, mode);
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_MODULUS, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_MODULUS\n");
            return rc;
        }
    }

    /*
     * PKCS#11 is flexible with respect to which attributes must be present
     * in an RSA key. Keys can be specified in Chinese-Remainder format or
     * they can be specified in modular-exponent format. Effective with version
     * 2.40, tokens MUST store CKA_PUBLIC_EXPONENT in any case. This permits the
     * retrieval of sufficient data to reconstitute the associated public key.
     */

    rc = template_attribute_get_non_empty(tmpl, CKA_PUBLIC_EXPONENT, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_PUBLIC_EXPONENT\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_PRIVATE_EXPONENT, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_PRIVATE_EXPONENT\n");
            return rc;
        }
    }

    /* The RSA CRT components are optional, no return code checking */
    template_attribute_get_non_empty(tmpl, CKA_PRIME_1, &prime1);
    template_attribute_get_non_empty(tmpl, CKA_PRIME_2, &prime2);
    template_attribute_get_non_empty(tmpl, CKA_EXPONENT_1, &exp1);
    template_attribute_get_non_empty(tmpl, CKA_EXPONENT_2, &exp2);
    template_attribute_get_non_empty(tmpl, CKA_COEFFICIENT, &coef);

    /* For CREATE either all CRT components or none of them must be specified */
    if (mode == MODE_CREATE &&
        !((prime1 == NULL && prime2 == NULL && exp1 == NULL &&
           exp2 == NULL && coef == NULL) ||
          (prime1 != NULL && prime2 != NULL && exp1 != NULL &&
           exp2 != NULL && coef != NULL))) {
        TRACE_ERROR("Either all CRT attrs must be specified or none of them\n");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    return priv_key_check_required_attributes(tmpl, mode);
}


//  rsa_priv_set_default_attributes()
//
CK_RV rsa_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *modulus_attr = NULL;
    CK_ATTRIBUTE *public_exp_attr = NULL;
    CK_ATTRIBUTE *private_exp_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_RV rc;

    priv_key_set_default_attributes(tmpl, mode);

    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    modulus_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    public_exp_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    private_exp_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!type_attr || !modulus_attr || !public_exp_attr || !private_exp_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    modulus_attr->type = CKA_MODULUS;
    modulus_attr->ulValueLen = 0;
    modulus_attr->pValue = NULL;

    public_exp_attr->type = CKA_PUBLIC_EXPONENT;
    public_exp_attr->ulValueLen = 0;
    public_exp_attr->pValue = NULL;

    private_exp_attr->type = CKA_PRIVATE_EXPONENT;
    private_exp_attr->ulValueLen = 0;
    private_exp_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_RSA;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, modulus_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    modulus_attr = NULL;
    rc = template_update_attribute(tmpl, private_exp_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    private_exp_attr = NULL;
    rc = template_update_attribute(tmpl, public_exp_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    public_exp_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (modulus_attr)
        free(modulus_attr);
    if (private_exp_attr)
        free(private_exp_attr);
    if (public_exp_attr)
        free(public_exp_attr);

    return rc;
}


// rsa_priv_validate_attributes()
//
CK_RV rsa_priv_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_MODULUS:
    case CKA_PRIVATE_EXPONENT:
        if (mode == MODE_CREATE) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_PUBLIC_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
        if (mode == MODE_CREATE) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return priv_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}


// rsa_priv_check_exportability()
//
CK_BBOOL rsa_priv_check_exportability(CK_ATTRIBUTE_TYPE type)
{
    switch (type) {
    case CKA_PRIVATE_EXPONENT:
    case CKA_PRIME_1:
    case CKA_PRIME_2:
    case CKA_EXPONENT_1:
    case CKA_EXPONENT_2:
    case CKA_COEFFICIENT:
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_UNEXTRACTABLE));
        return FALSE;
    }

    return TRUE;
}


// create the ASN.1 encoding for the private key for wrapping as defined
// in PKCS #8
//
// ASN.1 type PrivateKeyInfo ::= SEQUENCE {
//    version Version
//    privateKeyAlgorithm  PrivateKeyAlgorithmIdentifier
//    privateKey PrivateKey
//    attributes OPTIONAL
// }
//
// Where PrivateKey is defined as follows for RSA:
//
// ASN.1 type RSAPrivateKey
//
// RSAPrivateKey ::= SEQUENCE {
//   version Version
//   modulus INTEGER
//   publicExponent INTEGER
//   privateExponent INTEGER
//   prime1 INTEGER
//   prime2 INTEGER
//   exponent1 INTEGER
//   exponent2 INTEGER
//   coefficient INTEGER
// }
//
CK_RV rsa_priv_wrap_get_data(TEMPLATE *tmpl,
                             CK_BBOOL length_only,
                             CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *modulus = NULL;
    CK_ATTRIBUTE *publ_exp = NULL, *priv_exp = NULL;
    CK_ATTRIBUTE *prime1 = NULL, *prime2 = NULL;
    CK_ATTRIBUTE *exponent1 = NULL, *exponent2 = NULL;
    CK_ATTRIBUTE *coeff = NULL;
    CK_BBOOL crt_alloced = FALSE;
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_MODULUS, &modulus);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_PUBLIC_EXPONENT, &publ_exp);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_PUBLIC_EXPONENT for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_PRIVATE_EXPONENT,
                                          &priv_exp);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_PRIVATE_EXPONENT for the key.\n");
        return rc;
    }

    /* CRT attributes are optional */
    template_attribute_get_non_empty(tmpl, CKA_PRIME_1, &prime1);
    template_attribute_get_non_empty(tmpl, CKA_PRIME_2, &prime2);
    template_attribute_get_non_empty(tmpl, CKA_EXPONENT_1, &exponent1);
    template_attribute_get_non_empty(tmpl, CKA_EXPONENT_2, &exponent2);
    template_attribute_get_non_empty(tmpl, CKA_COEFFICIENT, &coeff);
    if (prime1 == NULL || prime2 == NULL || exponent1 == NULL ||
        exponent2 == NULL || coeff == NULL) {
        /* no CRT components, calculate them */
        rc = calc_rsa_crt_from_me(modulus, publ_exp, priv_exp, &prime1,
                                  &prime2, &exponent1, &exponent2, &coeff);
        if (rc != CKR_OK) {
            TRACE_ERROR("calc_rsa_crt_from_me failed\n");
            return rc;
        }
        crt_alloced = TRUE;
    }

    rc = ber_encode_RSAPrivateKey(length_only, data, data_len, modulus,
                                  publ_exp, priv_exp, prime1, prime2,
                                  exponent1, exponent2, coeff);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_RSAPrivateKey failed\n");
    }

    if (crt_alloced) {
        OPENSSL_cleanse(prime1->pValue, prime1->ulValueLen);
        free(prime1);
        OPENSSL_cleanse(prime2->pValue, prime2->ulValueLen);
        free(prime2);
        OPENSSL_cleanse(exponent1->pValue, exponent1->ulValueLen);
        free(exponent1);
        OPENSSL_cleanse(exponent2->pValue, exponent2->ulValueLen);
        free(exponent2);
        OPENSSL_cleanse(coeff->pValue, coeff->ulValueLen);
        free(coeff);
    }

    return rc;
}


//
//
CK_RV rsa_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG total_length)
{
    CK_ATTRIBUTE *modulus = NULL;
    CK_ATTRIBUTE *publ_exp = NULL;
    CK_ATTRIBUTE *priv_exp = NULL;
    CK_ATTRIBUTE *prime1 = NULL;
    CK_ATTRIBUTE *prime2 = NULL;
    CK_ATTRIBUTE *exponent1 = NULL;
    CK_ATTRIBUTE *exponent2 = NULL;
    CK_ATTRIBUTE *coeff = NULL;
    CK_RV rc;

    rc = ber_decode_RSAPrivateKey(data,
                                  total_length,
                                  &modulus,
                                  &publ_exp,
                                  &priv_exp,
                                  &prime1,
                                  &prime2,
                                  &exponent1,
                                  &exponent2, &coeff);

    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_RSAPrivateKey failed\n");
        return rc;
    }
    p11_attribute_trim(modulus);
    p11_attribute_trim(publ_exp);
    p11_attribute_trim(priv_exp);
    p11_attribute_trim(prime1);
    p11_attribute_trim(prime2);
    p11_attribute_trim(exponent1);
    p11_attribute_trim(exponent2);
    p11_attribute_trim(coeff);

    rc = template_update_attribute(tmpl, modulus);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    modulus = NULL;
    rc = template_update_attribute(tmpl, publ_exp);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    publ_exp = NULL;
    rc = template_update_attribute(tmpl, priv_exp);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    priv_exp = NULL;
    rc = template_update_attribute(tmpl, prime1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    prime1 = NULL;
    rc = template_update_attribute(tmpl, prime2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    prime2 = NULL;
    rc = template_update_attribute(tmpl, exponent1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    exponent1 = NULL;
    rc = template_update_attribute(tmpl, exponent2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    exponent2 = NULL;
    rc = template_update_attribute(tmpl, coeff);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    coeff = NULL;

    return CKR_OK;

error:
    if (modulus)
        free(modulus);
    if (publ_exp)
        free(publ_exp);
    if (priv_exp)
        free(priv_exp);
    if (prime1)
        free(prime1);
    if (prime2)
        free(prime2);
    if (exponent1)
        free(exponent1);
    if (exponent2)
        free(exponent2);
    if (coeff)
        free(coeff);

    return rc;
}


CK_RV rsa_priv_unwrap_get_data(TEMPLATE *tmpl,
                              CK_BYTE *data, CK_ULONG total_length)
{
    CK_ATTRIBUTE *modulus = NULL;
    CK_ATTRIBUTE *publ_exp = NULL;
    CK_RV rc;

    rc = ber_decode_RSAPublicKey(data, total_length, &modulus, &publ_exp);

    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_RSAPublicKey failed\n");
        return rc;
    }

    p11_attribute_trim(modulus);
    p11_attribute_trim(publ_exp);

    rc = template_update_attribute(tmpl, modulus);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    modulus = NULL;
    rc = template_update_attribute(tmpl, publ_exp);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    publ_exp = NULL;

    return CKR_OK;

error:
    if (modulus)
        free(modulus);
    if (publ_exp)
        free(publ_exp);

    return rc;
}

CK_RV rsa_priv_check_and_swap_pq(TEMPLATE *tmpl)
{
    CK_ATTRIBUTE *prime1 = NULL, *prime2 = NULL;
    CK_ATTRIBUTE *exponent1 = NULL, *exponent2 = NULL;
    CK_ATTRIBUTE *coeff = NULL;
    BIGNUM *bn_tmp = NULL;
    BIGNUM *bn_p = NULL;
    BIGNUM *bn_q = NULL;
    BIGNUM *bn_invq = NULL;
    BN_CTX *ctx = NULL;
    CK_RV rc = CKR_OK;
    CK_ULONG len;
    CK_BYTE *buf = NULL;

    if (template_attribute_find(tmpl, CKA_PRIME_1, &prime1) == FALSE ||
        prime1->ulValueLen == 0 || prime1->pValue == NULL) {
        TRACE_DEVEL("Could not find CKA_PRIME_1 for the key, not CRT format.\n");
        return CKR_OK;
    }

    if (template_attribute_find(tmpl, CKA_PRIME_2, &prime2) == FALSE ||
        prime2->ulValueLen == 0 || prime2->pValue == NULL) {
        TRACE_DEVEL("Could not find CKA_PRIME_2 for the key, not CRT format.\n");
        return CKR_OK;
    }

    if (template_attribute_find(tmpl, CKA_EXPONENT_1, &exponent1) == FALSE ||
        exponent1->ulValueLen == 0 || exponent1->pValue == NULL) {
        TRACE_DEVEL("Could not find CKA_EXPONENT_1 for the key, not CRT format.\n");
        return CKR_OK;
    }

    if (template_attribute_find(tmpl, CKA_EXPONENT_2, &exponent2) == FALSE ||
        exponent2->ulValueLen == 0 || exponent2->pValue == NULL) {
        TRACE_DEVEL("Could not find CKA_EXPONENT_2 for the key, not CRT format.\n");
        return CKR_OK;
    }

    if (template_attribute_find(tmpl, CKA_COEFFICIENT, &coeff) == FALSE ||
        coeff->ulValueLen == 0 || coeff->pValue == NULL) {
        TRACE_DEVEL("Could not find CKA_COEFFICIENT for the key, not CRT format.\n");
        return CKR_OK;
    }

    ctx = BN_CTX_secure_new();
    if (ctx == NULL) {
        TRACE_ERROR("BN_CTX_secure_new failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    bn_p = BN_CTX_get(ctx);
    bn_q = BN_CTX_get(ctx);
    bn_invq = BN_CTX_get(ctx);

    if (bn_p == NULL || bn_q == NULL || bn_invq== NULL) {
        TRACE_ERROR("BN_CTX_get failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (BN_bin2bn(prime1->pValue, prime1->ulValueLen, bn_p) == NULL ||
        BN_bin2bn(prime2->pValue, prime2->ulValueLen, bn_q) == NULL){
        TRACE_ERROR("BN_bin2bn failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    /* check if p > q  */
    if (BN_ucmp(bn_p, bn_q) != 1) {
        /* Unprivileged key format, swap p and q, swap dp and dq, recalc qinv */
        bn_tmp = bn_p;
        bn_p = bn_q;
        bn_q = bn_tmp;

        /* qInv = (1/q) mod p */
        if (BN_mod_inverse(bn_invq, bn_q, bn_p, ctx) == NULL) {
            TRACE_ERROR("BN_mod_inverse failed.\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        len = BN_num_bytes(bn_invq);
        buf = OPENSSL_secure_zalloc(len);
        if (buf == NULL) {
            TRACE_ERROR("OPENSSL_secure_zalloc failed.\n");
            rc = CKR_HOST_MEMORY;
            goto out;
        }

        if (BN_bn2binpad(bn_invq, buf, len) <= 0) {
            TRACE_ERROR("BN_bn2binpad failed.\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        prime1->type = CKA_PRIME_2;
        prime2->type = CKA_PRIME_1;

        exponent1->type = CKA_EXPONENT_2;
        exponent2->type = CKA_EXPONENT_1;

        rc = build_attribute(CKA_COEFFICIENT, buf, len, &coeff);
        if (rc != CKR_OK) {
            TRACE_ERROR("build_attribute for CKA_COEFFICIENT failed.\n");
            goto out;
        }

        rc = template_update_attribute(tmpl, coeff);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute for CKA_COEFFICIENT failed.\n");
            free(coeff);
            goto out;
        }
    }

out:
    if (bn_p != NULL)
        BN_clear(bn_p);
    if (bn_q != NULL)
        BN_clear(bn_q);
    if (ctx != NULL)
        BN_CTX_free(ctx);
    if (buf != NULL)
        OPENSSL_clear_free(buf, len);

    return rc;
}

static CK_RV ibm_pqc_keyform_mode_attrs_by_mech(CK_MECHANISM_TYPE mech,
                                                CK_ATTRIBUTE_TYPE *keyform_attr,
                                                CK_ATTRIBUTE_TYPE *mode_attr,
                                                const struct pqc_oid **oids)
{
    switch (mech) {
    case CKM_IBM_DILITHIUM:
        *keyform_attr = CKA_IBM_DILITHIUM_KEYFORM;
        *mode_attr = CKA_IBM_DILITHIUM_MODE;
        *oids = dilithium_oids;
        break;
    case CKM_IBM_KYBER:
        *keyform_attr = CKA_IBM_KYBER_KEYFORM;
        *mode_attr = CKA_IBM_KYBER_MODE;
        *oids = kyber_oids;
        break;
    default:
        TRACE_ERROR("Unsupported mechanims: 0x%lx\n", mech);
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

const struct pqc_oid *ibm_pqc_get_keyform_mode(TEMPLATE *tmpl,
                                               CK_MECHANISM_TYPE mech)
{
    CK_ATTRIBUTE *attr = NULL;
    const struct pqc_oid *oids = NULL, *oid;
    CK_ATTRIBUTE_TYPE keyform_attr = 0;
    CK_ATTRIBUTE_TYPE mode_attr = 0;

    if (ibm_pqc_keyform_mode_attrs_by_mech(mech, &keyform_attr,
                                           &mode_attr, &oids) != CKR_OK)
        return NULL;

    if (template_attribute_find(tmpl, keyform_attr, &attr) &&
        attr->ulValueLen == sizeof(CK_ULONG) && attr->pValue != NULL) {
        oid = find_pqc_by_keyform(oids, *(CK_ULONG *)(attr->pValue));
        if (oid == NULL) {
            TRACE_ERROR("KEYFORM attribute specifies an invalid value: %lu\n",
                        *(CK_ULONG *)(attr->pValue));
            return NULL;
        }
        return oid;
    }

    if (template_attribute_find(tmpl, mode_attr, &attr) &&
        attr->ulValueLen != 0 && attr->pValue != NULL) {
        oid = find_pqc_by_oid(oids, attr->pValue, attr->ulValueLen);
        if (oid == NULL) {
            TRACE_ERROR("MODE attribute specifies an invalid value\n");
            return NULL;
        }
        return oid;
    }

    TRACE_ERROR("Neither KEYFORM nor MODE found\n");
    return NULL;
}

CK_RV ibm_pqc_add_keyform_mode(TEMPLATE *tmpl, const struct pqc_oid *oid,
                               CK_MECHANISM_TYPE mech)
{
    CK_ATTRIBUTE *mode = NULL;
    CK_ATTRIBUTE *keyform = NULL;
    CK_RV rc;
    CK_ATTRIBUTE_TYPE keyform_attr = 0;
    CK_ATTRIBUTE_TYPE mode_attr = 0;
    const struct pqc_oid *oids;

    if (ibm_pqc_keyform_mode_attrs_by_mech(mech, &keyform_attr,
                                           &mode_attr, &oids) != CKR_OK)
        return CKR_MECHANISM_INVALID;

    rc = build_attribute(mode_attr, (CK_BYTE *)oid->oid, oid->oid_len, &mode);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(tmpl, mode);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    mode = NULL;

    rc = build_attribute(keyform_attr, (CK_BYTE *)&oid->keyform,
                         sizeof(CK_ULONG), &keyform);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(tmpl, keyform);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    keyform = NULL;

    return CKR_OK;

error:
    if (mode)
        free(mode);
    if (keyform)
        free(keyform);

    return rc;
}

/*
 * Extract the SubjectPublicKeyInfo from the Dilithium public key
 */
CK_RV ibm_dilithium_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                                  CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *rho = NULL;
    CK_ATTRIBUTE *t1 = NULL;
    const struct pqc_oid *oid;
    CK_RV rc;

    oid = ibm_pqc_get_keyform_mode(tmpl, CKM_IBM_DILITHIUM);
    if (oid == NULL)
       return CKR_TEMPLATE_INCOMPLETE;

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_DILITHIUM_RHO, &rho);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_RHO for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_DILITHIUM_T1, &t1);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_PUBLIC_EXPONENT for the key.\n");
        return rc;
    }

    rc = ber_encode_IBM_DilithiumPublicKey(length_only, data, data_len,
                                           oid->oid, oid->oid_len,
                                           rho, t1);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_IBM_DilithiumPublicKey failed.\n");
        return rc;
    }

    return CKR_OK;
}


CK_RV ibm_dilithium_priv_wrap_get_data(TEMPLATE *tmpl,
                                       CK_BBOOL length_only,
                                       CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *rho = NULL, *seed = NULL;
    CK_ATTRIBUTE *tr = NULL, *s1 = NULL, *s2 = NULL;
    CK_ATTRIBUTE *t0 = NULL, *t1 = NULL;
    const struct pqc_oid *oid;
    CK_RV rc;

    oid = ibm_pqc_get_keyform_mode(tmpl, CKM_IBM_DILITHIUM);
    if (oid == NULL)
       return CKR_TEMPLATE_INCOMPLETE;

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_DILITHIUM_RHO, &rho);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_RHO for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_DILITHIUM_SEED, &seed);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_SEED for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_DILITHIUM_TR, &tr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_TR for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_DILITHIUM_S1, &s1);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_S1 for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_DILITHIUM_S2, &s2);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_S2 for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_DILITHIUM_T0, &t0);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_T0 for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_DILITHIUM_T1, &t1);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_T1 for the key.\n");
        return rc;
    }

    rc = ber_encode_IBM_DilithiumPrivateKey(length_only, data, data_len,
                                            oid->oid, oid->oid_len,
                                            rho, seed, tr, s1, s2, t0, t1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_IBM_DilithiumPrivateKey failed\n");
    }

    return rc;
}

CK_RV ibm_dilithium_priv_unwrap_get_data(TEMPLATE *tmpl, CK_BYTE *data,
                                         CK_ULONG total_length,
                                         CK_BBOOL add_value)
{
    CK_ATTRIBUTE *rho = NULL;
    CK_ATTRIBUTE *t1 = NULL;
    CK_ATTRIBUTE *value = NULL;
    const struct pqc_oid *oid;
    CK_RV rc;

    rc = ber_decode_IBM_DilithiumPublicKey(data, total_length, &rho, &t1,
                                           &value, &oid);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_decode_DilithiumPublicKey failed\n");
        return rc;
    }

    rc = ibm_pqc_add_keyform_mode(tmpl, oid, CKM_IBM_DILITHIUM);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
        goto error;
    }

    rc = template_update_attribute(tmpl, rho);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    rho = NULL;
    rc = template_update_attribute(tmpl, t1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    t1 = NULL;
    if (add_value) {
        rc = template_update_attribute(tmpl, value);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_update_attribute failed.\n");
            goto error;
        }
    } else {
        free(value);
    }
    value = NULL;

    return CKR_OK;

error:
    if (rho)
        free(rho);
    if (t1)
        free(t1);
    if (value)
        free(value);

    return rc;
}

//
//
CK_RV ibm_dilithium_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data,
                                CK_ULONG total_length, CK_BBOOL add_value)
{
    CK_ATTRIBUTE *rho = NULL, *seed = NULL, *tr = NULL, *value = NULL;
    CK_ATTRIBUTE *s1 = NULL, *s2 = NULL, *t0 = NULL, *t1 = NULL;
    const struct pqc_oid *oid;
    CK_RV rc;

    rc = ber_decode_IBM_DilithiumPrivateKey(data, total_length,
                                            &rho, &seed, &tr, &s1, &s2, &t0,
                                            &t1, &value, &oid);
    if (rc != CKR_OK) {
        TRACE_ERROR("der_decode_IBM_DilithiumPrivateKey failed\n");
        return rc;
    }

    rc = ibm_pqc_add_keyform_mode(tmpl, oid, CKM_IBM_DILITHIUM);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
        goto error;
    }

    rc = template_update_attribute(tmpl, rho);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    rho = NULL;
    rc = template_update_attribute(tmpl, seed);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    seed = NULL;
    rc = template_update_attribute(tmpl, tr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    tr = NULL;
    rc = template_update_attribute(tmpl, s1);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    s1 = NULL;
    rc = template_update_attribute(tmpl, s2);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    s2 = NULL;
    rc = template_update_attribute(tmpl, t0);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    t0 = NULL;
    if (t1 != NULL) {
        rc = template_update_attribute(tmpl, t1);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
    }
    t1 = NULL;
    if (add_value) {
        rc = template_update_attribute(tmpl, value);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_update_attribute failed.\n");
            goto error;
        }
    } else {
        free(value);
    }
    value = NULL;

    return CKR_OK;

error:
    if (rho)
        free(rho);
    if (seed)
        free(seed);
    if (tr)
        free(tr);
    if (s1)
        free(s1);
    if (s2)
        free(s2);
    if (t0)
        free(t0);
    if (t1)
        free(t1);
    if (value)
        free(value);

    return rc;
}

/*
 * Extract the SubjectPublicKeyInfo from the Kyber public key
 */
CK_RV ibm_kyber_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                              CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *pk = NULL;
    const struct pqc_oid *oid;
    CK_RV rc;

    oid = ibm_pqc_get_keyform_mode(tmpl, CKM_IBM_KYBER);
    if (oid == NULL)
       return CKR_TEMPLATE_INCOMPLETE;

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_KYBER_PK, &pk);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_KYBER_PK for the key.\n");
        return rc;
    }

    rc = ber_encode_IBM_KyberPublicKey(length_only, data, data_len,
                                       oid->oid, oid->oid_len, pk);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_IBM_KyberPublicKey failed.\n");
        return rc;
    }

    return CKR_OK;
}


CK_RV ibm_kyber_priv_wrap_get_data(TEMPLATE *tmpl,
                                   CK_BBOOL length_only,
                                   CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *sk = NULL, *pk = NULL;
    const struct pqc_oid *oid;
    CK_RV rc;

    oid = ibm_pqc_get_keyform_mode(tmpl, CKM_IBM_KYBER);
    if (oid == NULL)
       return CKR_TEMPLATE_INCOMPLETE;

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_KYBER_SK, &sk);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_KYBER_SK for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_IBM_KYBER_PK, &pk);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_KYBER_PK for the key.\n");
        return rc;
    }

    rc = ber_encode_IBM_KyberPrivateKey(length_only, data, data_len,
                                        oid->oid, oid->oid_len, sk, pk);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_IBM_KyberPrivateKey failed\n");
    }

    return rc;
}

CK_RV ibm_kyber_priv_unwrap_get_data(TEMPLATE *tmpl, CK_BYTE *data,
                                     CK_ULONG total_length,
                                     CK_BBOOL add_value)
{
    CK_ATTRIBUTE *pk = NULL;
    CK_ATTRIBUTE *value = NULL;
    const struct pqc_oid *oid;
    CK_RV rc;

    rc = ber_decode_IBM_KyberPublicKey(data, total_length, &pk,
                                       &value, &oid);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_decode_IBM_KyberPublicKey failed\n");
        return rc;
    }

    rc = ibm_pqc_add_keyform_mode(tmpl, oid, CKM_IBM_KYBER);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
        goto error;
    }

    rc = template_update_attribute(tmpl, pk);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    pk = NULL;
    if (add_value) {
        rc = template_update_attribute(tmpl, value);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_update_attribute failed.\n");
            goto error;
        }
    } else {
        free(value);
    }
    value = NULL;

    return CKR_OK;

error:
    if (pk)
        free(pk);
    if (value)
        free(value);

    return rc;
}

//
//
CK_RV ibm_kyber_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data,
                            CK_ULONG total_length, CK_BBOOL add_value)
{
    CK_ATTRIBUTE *sk = NULL, *pk = NULL, *value = NULL;
    const struct pqc_oid *oid;
    CK_RV rc;

    rc = ber_decode_IBM_KyberPrivateKey(data, total_length,
                                        &sk, &pk, &value, &oid);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_decode_IBM_KyberPrivateKey failed\n");
        return rc;
    }

    rc = ibm_pqc_add_keyform_mode(tmpl, oid, CKM_IBM_KYBER);
    if (rc != CKR_OK) {
        TRACE_ERROR("ibm_pqc_add_keyform_mode failed\n");
        goto error;
    }

    rc = template_update_attribute(tmpl, sk);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    sk = NULL;
    rc = template_update_attribute(tmpl, pk);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    pk = NULL;
    if (add_value) {
        rc = template_update_attribute(tmpl, value);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_update_attribute failed.\n");
            goto error;
        }
    } else {
        free(value);
    }
    value = NULL;

    return CKR_OK;

error:
    if (sk)
        free(sk);
    if (pk)
        free(pk);
    if (value)
        free(value);

    return rc;
}

CK_RV ibm_pqc_publ_get_spki(TEMPLATE *tmpl, CK_KEY_TYPE keytype,
                            CK_BBOOL length_only,
                            CK_BYTE **data, CK_ULONG *data_len)
{
    switch (keytype) {
    case CKK_IBM_PQC_DILITHIUM:
        return ibm_dilithium_publ_get_spki(tmpl, length_only, data, data_len);
    case CKK_IBM_PQC_KYBER:
        return ibm_kyber_publ_get_spki(tmpl, length_only, data, data_len);
    default:
        TRACE_DEVEL("Key type 0x%lx not supported.\n", keytype);
        return CKR_KEY_TYPE_INCONSISTENT;
    }
}

CK_RV ibm_pqc_priv_wrap_get_data(TEMPLATE *tmpl, CK_KEY_TYPE keytype,
                                 CK_BBOOL length_only,
                                 CK_BYTE **data, CK_ULONG *data_len)
{
    switch (keytype) {
    case CKK_IBM_PQC_DILITHIUM:
        return ibm_dilithium_priv_wrap_get_data(tmpl, length_only, data,
                                                data_len);
    case CKK_IBM_PQC_KYBER:
        return ibm_kyber_priv_wrap_get_data(tmpl, length_only, data, data_len);
    default:
        TRACE_DEVEL("Key type 0x%lx not supported.\n", keytype);
        return CKR_KEY_TYPE_INCONSISTENT;
    }
}

CK_RV ibm_pqc_priv_unwrap(TEMPLATE *tmpl, CK_KEY_TYPE keytype, CK_BYTE *data,
                          CK_ULONG total_length, CK_BBOOL add_value)
{
    switch (keytype) {
    case CKK_IBM_PQC_DILITHIUM:
        return ibm_dilithium_priv_unwrap(tmpl, data, total_length, add_value);
    case CKK_IBM_PQC_KYBER:
        return ibm_kyber_priv_unwrap(tmpl, data, total_length, add_value);
    default:
        TRACE_DEVEL("Key type 0x%lx not supported.\n", keytype);
        return CKR_KEY_TYPE_INCONSISTENT;
    }
}

CK_RV ibm_pqc_priv_unwrap_get_data(TEMPLATE *tmpl, CK_KEY_TYPE keytype,
                                   CK_BYTE *data, CK_ULONG total_length,
                                   CK_BBOOL add_value)
{
    switch (keytype) {
    case CKK_IBM_PQC_DILITHIUM:
        return ibm_dilithium_priv_unwrap_get_data(tmpl, data, total_length,
                                                  add_value);
    case CKK_IBM_PQC_KYBER:
        return ibm_kyber_priv_unwrap_get_data(tmpl, data, total_length,
                                                   add_value);
    default:
        TRACE_DEVEL("Key type 0x%lx not supported.\n", keytype);
        return CKR_KEY_TYPE_INCONSISTENT;
    }
}

// dsa_publ_check_required_attributes()
//
CK_RV dsa_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_PRIME\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_SUBPRIME, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_SUBPRIME\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_BASE\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    }

    return publ_key_check_required_attributes(tmpl, mode);
}


//  dsa_publ_set_default_attributes()
//
CK_RV dsa_publ_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *subprime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_RV rc;

    publ_key_set_default_attributes(tmpl, mode);

    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    prime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    subprime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    base_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!type_attr || !prime_attr || !subprime_attr || !base_attr
        || !value_attr) {
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

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_DSA;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, prime_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    prime_attr = NULL;
    rc = template_update_attribute(tmpl, subprime_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    subprime_attr = NULL;
    rc = template_update_attribute(tmpl, base_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    base_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (prime_attr)
        free(prime_attr);
    if (subprime_attr)
        free(subprime_attr);
    if (base_attr)
        free(base_attr);
    if (value_attr)
        free(value_attr);

    return rc;
}


// dsa_publ_validate_attributes()
//
CK_RV dsa_publ_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_PRIME:
        {
            CK_ULONG size;

            if (mode != MODE_CREATE && mode != MODE_KEYGEN) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
                return CKR_ATTRIBUTE_READ_ONLY;
            }
            // must be between [512, 1024] bits, and a multiple of 64 bits
            //
            size = attr->ulValueLen;
            if (size < 64 || (size % 8 != 0)) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            p11_attribute_trim(attr);
            return CKR_OK;
        }
    case CKA_SUBPRIME:
        if (mode != MODE_CREATE && mode != MODE_KEYGEN) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        // subprime must be 160 bits
        //
        if (attr->ulValueLen < 20) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        p11_attribute_trim(attr);
        return CKR_OK;
    case CKA_BASE:
        if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_VALUE:
        if (mode == MODE_CREATE) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return publ_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}

/*
 * Extract the SubjectPublicKeyInfo from the DSA public key
 */
CK_RV dsa_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                        CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *prime = NULL;
    CK_ATTRIBUTE *subprime = NULL;
    CK_ATTRIBUTE *base = NULL;
    CK_ATTRIBUTE *value = NULL;
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &prime);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_PRIME for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &base);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_BASE for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_SUBPRIME, &subprime);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_SUBPRIME for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &value);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    rc = ber_encode_DSAPublicKey(length_only, data,data_len, prime, subprime,
                                 base, value);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_DSAPublicKey failed.\n");
        return rc;
    }

    return CKR_OK;
}

// dsa_priv_check_required_attributes()
//
CK_RV dsa_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_PRIME\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_SUBPRIME, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_SUBPRIME\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_BASE\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    }

    return priv_key_check_required_attributes(tmpl, mode);
}


//  dsa_priv_set_default_attributes()
//
CK_RV dsa_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *subprime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_RV rc;

    priv_key_set_default_attributes(tmpl, mode);

    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    prime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    subprime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    base_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!type_attr || !prime_attr || !subprime_attr || !base_attr
        || !value_attr) {
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

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_DSA;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, prime_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    prime_attr = NULL;
    rc = template_update_attribute(tmpl, subprime_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    subprime_attr = NULL;
    rc = template_update_attribute(tmpl, base_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    base_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (prime_attr)
        free(prime_attr);
    if (subprime_attr)
        free(subprime_attr);
    if (base_attr)
        free(base_attr);
    if (value_attr)
        free(value_attr);

    return rc;
}


// dsa_priv_validate_attributes()
//
CK_RV dsa_priv_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_PRIME:
        {
            CK_ULONG size;

            if (mode != MODE_CREATE) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
                return CKR_ATTRIBUTE_READ_ONLY;
            }
            // must be between [512, 1024] bits, and a multiple of 64 bits
            //
            size = attr->ulValueLen;
            if (size < 64 || size > 128 || (size % 8 != 0)) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            p11_attribute_trim(attr);
            return CKR_OK;
        }
    case CKA_SUBPRIME:
        if (mode != MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        // subprime must be 160 bits
        //
        if (attr->ulValueLen != 20) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        p11_attribute_trim(attr);
        return CKR_OK;
    case CKA_BASE:
    case CKA_VALUE:
        if (mode == MODE_CREATE) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return priv_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}


// dsa_priv_check_exportability()
//
CK_BBOOL dsa_priv_check_exportability(CK_ATTRIBUTE_TYPE type)
{
    switch (type) {
    case CKA_VALUE:
        return FALSE;
    }

    return TRUE;
}


// create the ASN.1 encoding for the private key for wrapping as defined
// in PKCS #8
//
// ASN.1 type PrivateKeyInfo ::= SEQUENCE {
//    version Version
//    privateKeyAlgorithm  PrivateKeyAlgorithmIdentifier
//    privateKey PrivateKey
//    attributes OPTIONAL
// }
//
// PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
//
// AlgorithmIdentifier ::= SEQUENCE {
//    algorithm OBJECT IDENTIFIER
//    parameters ANY DEFINED BY algorithm OPTIONAL
// }
//
// paramters ::= SEQUENCE {
//    p  INTEGER
//    q  INTEGER
//    g  INTEGER
// }
//
// privateKey ::= INTEGER
//
//
CK_RV dsa_priv_wrap_get_data(TEMPLATE *tmpl,
                             CK_BBOOL length_only,
                             CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *prime = NULL;
    CK_ATTRIBUTE *subprime = NULL;
    CK_ATTRIBUTE *base = NULL;
    CK_ATTRIBUTE *value = NULL;
    CK_RV rc;

    // compute the total length of the BER-encoded data
    //
    rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &prime);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_PRIME for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_SUBPRIME, &subprime);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_SUBPRIME for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &base);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_BASE for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &value);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }
    rc = ber_encode_DSAPrivateKey(length_only, data, data_len,
                                  prime, subprime, base, value);
    if (rc != CKR_OK)
        TRACE_DEVEL("ber_encode_DSAPrivateKey failed\n");

    return rc;
}


//
//
CK_RV dsa_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG total_length)
{
    CK_ATTRIBUTE *prime = NULL;
    CK_ATTRIBUTE *subprime = NULL;
    CK_ATTRIBUTE *base = NULL;
    CK_ATTRIBUTE *value = NULL;
    CK_RV rc;

    rc = ber_decode_DSAPrivateKey(data, total_length,
                                  &prime, &subprime, &base, &value);

    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_DSAPrivateKey failed\n");
        return rc;
    }
    p11_attribute_trim(prime);
    p11_attribute_trim(subprime);
    p11_attribute_trim(base);
    p11_attribute_trim(value);

    rc = template_update_attribute(tmpl, prime);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    prime = NULL;
    rc = template_update_attribute(tmpl, subprime);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    subprime = NULL;
    rc = template_update_attribute(tmpl, base);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    base = NULL;
    rc = template_update_attribute(tmpl, value);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value = NULL;

    return CKR_OK;

error:
    if (prime)
        free(prime);
    if (subprime)
        free(subprime);
    if (base)
        free(base);
    if (value)
        free(value);

    return rc;
}

CK_RV dsa_priv_unwrap_get_data(TEMPLATE *tmpl,
                              CK_BYTE *data, CK_ULONG total_length)
{
    CK_ATTRIBUTE *prime = NULL;
    CK_ATTRIBUTE *subprime = NULL;
    CK_ATTRIBUTE *base = NULL;
    CK_ATTRIBUTE *value = NULL;
    CK_RV rc;

    rc = ber_decode_DSAPublicKey(data, total_length, &prime, &subprime,
                                 &base, &value);

    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_DSAPublicKey failed\n");
        return rc;
    }

    p11_attribute_trim(prime);
    p11_attribute_trim(subprime);
    p11_attribute_trim(base);
    p11_attribute_trim(value);

    rc = template_update_attribute(tmpl, prime);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    prime = NULL;
    rc = template_update_attribute(tmpl, subprime);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    subprime = NULL;
    rc = template_update_attribute(tmpl, base);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    base = NULL;
    rc = template_update_attribute(tmpl, value);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value = NULL;

    return CKR_OK;

error:
    if (prime)
        free(prime);
    if (subprime)
        free(subprime);
    if (base)
        free(base);
    if (value)
        free(value);

    return rc;
}


// ecdsa_publ_check_required_attributes()
//
CK_RV ecdsa_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    if (mode == MODE_CREATE &&
        token_specific.secure_key_token == TRUE &&
        template_attribute_get_non_empty(tmpl, CKA_IBM_OPAQUE, &attr) == CKR_OK) {
	    /*
         * Import of an already existing secure key. Only
         * do the base checks for a public key templates.
         */
        return publ_key_check_required_attributes(tmpl, mode);
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_ECDSA_PARAMS, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
            TRACE_ERROR("Could not find CKA_ECDSA_PARAMS\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_EC_POINT, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_EC_POINT\n");
            return rc;
        }
    }

    return publ_key_check_required_attributes(tmpl, mode);
}


//  ecdsa_publ_set_default_attributes()
//
CK_RV ecdsa_publ_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *params_attr = NULL;
    CK_ATTRIBUTE *ec_point_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_RV rc;

    publ_key_set_default_attributes(tmpl, mode);

    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    params_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    ec_point_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!type_attr || !params_attr || !ec_point_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    params_attr->type = CKA_ECDSA_PARAMS;
    params_attr->ulValueLen = 0;
    params_attr->pValue = NULL;

    ec_point_attr->type = CKA_EC_POINT;
    ec_point_attr->ulValueLen = 0;
    ec_point_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_ECDSA;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, params_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    params_attr = NULL;
    rc = template_update_attribute(tmpl, ec_point_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    ec_point_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (params_attr)
        free(params_attr);
    if (ec_point_attr)
        free(ec_point_attr);

    return rc;
}


// ecdsa_publ_validate_attributes()
//
CK_RV ecdsa_publ_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                    CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_ECDSA_PARAMS:
        if (mode == MODE_CREATE || mode == MODE_KEYGEN || mode == MODE_DERIVE)
            return CKR_OK;

        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_EC_POINT:
        if (mode == MODE_CREATE)
            return CKR_OK;

        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return publ_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}

/*
 * Extract the SubjectPublicKeyInfo from the EC public key
 */
CK_RV ec_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                       CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *ec_parms = NULL;
    CK_ATTRIBUTE *ec_point = NULL;
    CK_ATTRIBUTE *value = NULL;
    CK_BYTE *buf = NULL;
    CK_ULONG buf_len = 0;
    CK_ATTRIBUTE point = { .type = CKA_EC_POINT,
                           .pValue = NULL, .ulValueLen = 0 };
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_EC_PARAMS, &ec_parms);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_EC_PARAMS for the key.\n");
        return rc;
    }
    /* CKA_EC_POINT is optional in EC private keys */
    rc = template_attribute_get_non_empty(tmpl, CKA_EC_POINT, &ec_point);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Could not find CKA_EC_POINT, possibly EC private key.\n");

        /*
         * For a secure key token, we can't calculate the public key from the
         * private key
         */
        if (token_specific.secure_key_token) {
            TRACE_DEVEL("Its a secure key token, no SPKI avaiable.\n");
            *data = NULL;
            *data_len = 0;
            return CKR_OK;
        }

        rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &value);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
            return rc;
        }

        rc = ec_point_from_priv_key(ec_parms->pValue, ec_parms->ulValueLen,
                                    value->pValue, value->ulValueLen,
                                    &buf, &buf_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("ec_point_from_priv_key failed.\n");
            return rc;
        }

        rc = ber_encode_OCTET_STRING(FALSE, (CK_BYTE **)&point.pValue,
                                     &point.ulValueLen, buf, buf_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
            goto out;
        }

        ec_point = &point;
    }

    rc = ber_encode_ECPublicKey(length_only, data,data_len, ec_parms, ec_point);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_ECPublicKey failed.\n");
        goto out;
    }

out:
    if (buf != NULL)
        free(buf);
    if (point.pValue != NULL)
        free(point.pValue);

    return rc;
}

// ecdsa_priv_check_required_attributes()
//
CK_RV ecdsa_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    if (mode == MODE_CREATE &&
        token_specific.secure_key_token == TRUE &&
        template_attribute_get_non_empty(tmpl, CKA_IBM_OPAQUE, &attr) == CKR_OK) {
        /*
         * Import of an already existing secure key. Only
         * do the base checks for private key templates.
         */
        return priv_key_check_required_attributes(tmpl, mode);
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_ECDSA_PARAMS, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_ECDSA_PARAMS\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    }

    return priv_key_check_required_attributes(tmpl, mode);
}


//  ecdsa_priv_set_default_attributes()
//
CK_RV ecdsa_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *params_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_RV rc;

    priv_key_set_default_attributes(tmpl, mode);

    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    params_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!type_attr || !params_attr || !value_attr) {
        if (type_attr)
            free(type_attr);
        if (params_attr)
            free(params_attr);
        if (value_attr)
            free(value_attr);
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));

        return CKR_HOST_MEMORY;
    }

    params_attr->type = CKA_ECDSA_PARAMS;
    params_attr->ulValueLen = 0;
    params_attr->pValue = NULL;

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_ECDSA;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, params_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    params_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (params_attr)
        free(params_attr);
    if (value_attr)
        free(value_attr);

    return rc;
}


// ecdsa_priv_validate_attributes()
//
CK_RV ecdsa_priv_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                    CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_ECDSA_PARAMS:
        if (mode == MODE_CREATE || mode == MODE_DERIVE)
            return CKR_OK;

        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_VALUE:
        if (mode == MODE_CREATE) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_EC_POINT:
        if (mode == MODE_CREATE) {
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return priv_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}


// ecdsa_priv_check_exportability()
//
CK_BBOOL ecdsa_priv_check_exportability(CK_ATTRIBUTE_TYPE type)
{
    switch (type) {
    case CKA_VALUE:
        return FALSE;
    }

    return TRUE;
}

/*
 * create the ASN.1 encoding for the private key for wrapping as defined
 * in PKCS #8
 *
 * ASN.1 type PrivateKeyInfo ::= SEQUENCE {
 *    version Version
 *    privateKeyAlgorithm  PrivateKeyAlgorithmIdentifier
 *    privateKey PrivateKey
 *    attributes OPTIONAL
 * }
 *
 * Where PrivateKey is defined as follows for EC:
 *
 * ASN.1 type RSAPrivateKey
 *
 * ECPrivateKey ::= SEQUENCE {
 *   version Version
 *   privateKey OCTET STRING
 *   parameters [0] ECParameters (OPTIONAL)
 *   publicKey  [1] BIT STRING (OPTIONAL)
 * }
 */
CK_RV ecdsa_priv_wrap_get_data(TEMPLATE *tmpl,
                               CK_BBOOL length_only,
                               CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *params = NULL;
    CK_ATTRIBUTE *point = NULL;
    CK_ATTRIBUTE *pubkey = NULL;
    CK_RV rc;

    // compute the total length of the BER-encoded data
    //
    rc = template_attribute_get_non_empty(tmpl, CKA_EC_PARAMS, &params);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_EC_PARAMS for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &point);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    /* check if optional public-key part was defined */
    template_attribute_get_non_empty(tmpl, CKA_EC_POINT, &pubkey);

    rc = der_encode_ECPrivateKey(length_only, data, data_len, params,
                                 point, pubkey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("der_encode_ECPrivateKey failed\n");
    }

    return rc;
}

CK_RV ecdsa_priv_unwrap_get_data(TEMPLATE *tmpl,
                                 CK_BYTE *data, CK_ULONG total_length)
{
    CK_ATTRIBUTE *params = NULL;
    CK_ATTRIBUTE *point = NULL;
    CK_RV rc;

    rc = der_decode_ECPublicKey(data, total_length, &params, &point);

    if (rc != CKR_OK) {
        TRACE_DEVEL("der_decode_ECPublicKey failed\n");
        return rc;
    }

    rc = template_update_attribute(tmpl, params);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    params = NULL;
    rc = template_update_attribute(tmpl, point);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    point = NULL;

    return CKR_OK;

error:
    if (params)
        free(params);
    if (point)
        free(point);

    return rc;
}

//
//
CK_RV ec_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG total_length)
{
    CK_ATTRIBUTE *pubkey = NULL;
    CK_ATTRIBUTE *privkey = NULL;
    CK_ATTRIBUTE *ecparam = NULL;
    CK_RV rc;

    rc = der_decode_ECPrivateKey(data, total_length, &ecparam,
                                 &pubkey, &privkey);

    if (rc != CKR_OK) {
        TRACE_DEVEL("der_decode_ECPrivateKey failed\n");
        return rc;
    }
    p11_attribute_trim(privkey);

    if (pubkey) {
        rc = template_update_attribute(tmpl, pubkey);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        pubkey = NULL;
    }
    if (privkey) {
        rc = template_update_attribute(tmpl, privkey);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        privkey = NULL;
    }
    rc = template_update_attribute(tmpl, ecparam);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    ecparam = NULL;

    return CKR_OK;

error:
    if (pubkey)
        free(pubkey);
    if (privkey)
        free(privkey);
    if (ecparam)
        free(ecparam);

    return rc;
}

// dh_publ_check_required_attributes()
//
CK_RV dh_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;


    rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
            TRACE_ERROR("Could not find CKA_PRIME\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
            TRACE_ERROR("Could not find CKA_BASE\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    }

    return publ_key_check_required_attributes(tmpl, mode);
}


//  dh_publ_set_default_attributes()
//
CK_RV dh_publ_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_RV rc;

    publ_key_set_default_attributes(tmpl, mode);

    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    prime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    base_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!type_attr || !prime_attr || !base_attr || !value_attr) {
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

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_DH;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, prime_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    prime_attr = NULL;
    rc = template_update_attribute(tmpl, base_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    base_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (prime_attr)
        free(prime_attr);
    if (base_attr)
        free(base_attr);
    if (value_attr)
        free(value_attr);

    return rc;
}




// dh_publ_validate_attribute()
//
CK_RV dh_publ_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_PRIME:
    case CKA_BASE:
        if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_VALUE:
        if (mode == MODE_CREATE) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return publ_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}

/*
 * Extract the SubjectPublicKeyInfo from the DH public key
 */
CK_RV dh_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                       CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *prime = NULL;
    CK_ATTRIBUTE *base = NULL;
    CK_ATTRIBUTE *value = NULL;
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &prime);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_PRIME for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &base);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_BASE for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &value);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    rc = ber_encode_DHPublicKey(length_only, data,data_len, prime, base, value);
    if (rc != CKR_OK) {
        TRACE_ERROR("ber_encode_DHPublicKey failed.\n");
        return rc;
    }

    return CKR_OK;
}


// dh_priv_check_required_attributes()
//
CK_RV dh_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG val;
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_PRIME\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_BASE\n");
            return rc;
        }
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    }

    rc = template_attribute_get_ulong(tmpl, CKA_VALUE_BITS, &val);
    if (rc != CKR_TEMPLATE_INCOMPLETE) {
        if (mode == MODE_CREATE || mode == MODE_UNWRAP) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
    }

    return priv_key_check_required_attributes(tmpl, mode);
}


//  dh_priv_set_default_attributes()
//
CK_RV dh_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *value_bits_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_ULONG bits = 0L;
    CK_RV rc;

    priv_key_set_default_attributes(tmpl, mode);

    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    prime_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    base_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    if (mode != MODE_CREATE && mode != MODE_UNWRAP)
        value_bits_attr =
            (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG));

    if (!type_attr || !prime_attr || !base_attr || !value_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc =  CKR_HOST_MEMORY;
        goto error;
    }
    if (mode != MODE_CREATE && mode != MODE_UNWRAP && !value_bits_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc =  CKR_HOST_MEMORY;
        goto error;
    }

    prime_attr->type = CKA_PRIME;
    prime_attr->ulValueLen = 0;
    prime_attr->pValue = NULL;

    base_attr->type = CKA_BASE;
    base_attr->ulValueLen = 0;
    base_attr->pValue = NULL;

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    if (mode != MODE_CREATE && mode != MODE_UNWRAP) {
        value_bits_attr->type = CKA_VALUE_BITS;
        value_bits_attr->ulValueLen = sizeof(CK_ULONG);
        value_bits_attr->pValue =
            (CK_BYTE *) value_bits_attr + sizeof(CK_ATTRIBUTE);
        *(CK_ULONG *) value_bits_attr->pValue = bits;
    }

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_DH;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, prime_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    prime_attr = NULL;
    rc = template_update_attribute(tmpl, base_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    base_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;
    if (mode != MODE_CREATE && mode != MODE_UNWRAP) {
        rc = template_update_attribute(tmpl, value_bits_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        value_bits_attr = NULL;
    }

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (prime_attr)
        free(prime_attr);
    if (base_attr)
        free(base_attr);
    if (value_attr)
        free(value_attr);
    if (value_bits_attr)
        free(value_bits_attr);

    return rc;
}


// dh_priv_validate_attribute()
//
CK_RV dh_priv_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_PRIME:
    case CKA_BASE:
    case CKA_VALUE:
        if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
            p11_attribute_trim(attr);
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
        // I'm not sure what to do about VALUE_BITS...we don't really support
        // Diffie-Hellman keys other than for storage...when the object is
        // created, we're supposed to add CKA_VALUE_BITS outselves...which we
        // don't do at this time.  (we'd need to add code in C_CreateObject to
        // call some sort of objecttype-specific callback)
        //
        // kapil 05/08/03 : Commented out error flagging, as CKA_VALUE_BITS is
        //                  valid attribute for creating DH priv object. The
        //                  above is an older comment.
    case CKA_VALUE_BITS:
        //   TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        //   return CKR_ATTRIBUTE_READ_ONLY;
        if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        return CKR_OK;
        break;
    default:
        return priv_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}


// dh_priv_check_exportability()
//
CK_BBOOL dh_priv_check_exportability(CK_ATTRIBUTE_TYPE type)
{
    switch (type) {
    case CKA_VALUE:
        return FALSE;
    }

    return TRUE;
}

//
//
CK_RV dh_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG total_length)
{
    CK_ATTRIBUTE *prime = NULL;
    CK_ATTRIBUTE *base = NULL;
    CK_ATTRIBUTE *value = NULL;
    CK_RV rc;

    rc = ber_decode_DHPrivateKey(data, total_length, &prime, &base, &value);

    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_DHPrivateKey failed\n");
        return rc;
    }
    p11_attribute_trim(prime);
    p11_attribute_trim(base);
    p11_attribute_trim(value);

    rc = template_update_attribute(tmpl, prime);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    prime = NULL;
    rc = template_update_attribute(tmpl, base);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    base = NULL;
    rc = template_update_attribute(tmpl, value);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value = NULL;

    return CKR_OK;

error:
    if (prime)
        free(prime);
    if (base)
        free(base);
    if (value)
        free(value);

    return rc;
}

CK_RV dh_priv_unwrap_get_data(TEMPLATE *tmpl,
                              CK_BYTE *data, CK_ULONG total_length)
{
    CK_ATTRIBUTE *prime = NULL;
    CK_ATTRIBUTE *base = NULL;
    CK_ATTRIBUTE *value = NULL;
    CK_ATTRIBUTE *value_bits = NULL;
    CK_ULONG num_bits;
    CK_RV rc;

    rc = ber_decode_DHPublicKey(data, total_length, &prime, &base, &value);

    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_DHPublicKey failed\n");
        return rc;
    }

    p11_attribute_trim(prime);
    p11_attribute_trim(base);
    p11_attribute_trim(value);
    num_bits = value->ulValueLen * 8;

    rc = template_update_attribute(tmpl, prime);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    prime = NULL;
    rc = template_update_attribute(tmpl, base);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    base = NULL;
    rc = template_update_attribute(tmpl, value);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value = NULL;

    rc = build_attribute(CKA_VALUE_BITS, (CK_BYTE *)&num_bits, sizeof(num_bits),
                         &value_bits);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(tmpl, value_bits);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_bits = NULL;

    return CKR_OK;

error:
    if (prime)
        free(prime);
    if (base)
        free(base);
    if (value)
        free(value);
    if (value_bits)
        free(value_bits);

    return rc;
}

// create the ASN.1 encoding for the private key for wrapping as defined
// in PKCS #8
//
// ASN.1 type PrivateKeyInfo ::= SEQUENCE {
//    version Version
//    privateKeyAlgorithm  PrivateKeyAlgorithmIdentifier
//    privateKey PrivateKey
//    attributes OPTIONAL
// }
//
// PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
//
// AlgorithmIdentifier ::= SEQUENCE {
//    algorithm OBJECT IDENTIFIER
//    parameters ANY DEFINED BY algorithm OPTIONAL
// }
//
// paramters ::= SEQUENCE {
//    p  INTEGER
//    g  INTEGER
// }
//
// privateKey ::= INTEGER
//
//
CK_RV dh_priv_wrap_get_data(TEMPLATE *tmpl,
                            CK_BBOOL length_only,
                            CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *prime = NULL;
    CK_ATTRIBUTE *base = NULL;
    CK_ATTRIBUTE *value = NULL;
    CK_RV rc;

    // compute the total length of the BER-encoded data
    rc = template_attribute_get_non_empty(tmpl, CKA_PRIME, &prime);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_PRIME for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_BASE, &base);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_BASE for the key.\n");
        return rc;
    }
    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &value);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }
    rc = ber_encode_DHPrivateKey(length_only, data, data_len,
                                 prime, base, value);
    if (rc != CKR_OK)
        TRACE_DEVEL("ber_encode_DHPrivateKey failed\n");

    return rc;
}

//  ibm_dilithium_publ_set_default_attributes()
//
CK_RV ibm_dilithium_publ_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *type_attr = NULL;
    CK_ATTRIBUTE *rho_attr = NULL;
    CK_ATTRIBUTE *t1_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_RV rc;

    publ_key_set_default_attributes(tmpl, mode);

    type_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    rho_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    t1_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!type_attr || !rho_attr || !t1_attr || !value_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_IBM_PQC_DILITHIUM;

    rho_attr->type = CKA_IBM_DILITHIUM_RHO;
    rho_attr->ulValueLen = 0;
    rho_attr->pValue = NULL;

    t1_attr->type = CKA_IBM_DILITHIUM_T1;
    t1_attr->ulValueLen = 0;
    t1_attr->pValue = NULL;

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, rho_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    rho_attr = NULL;
    rc = template_update_attribute(tmpl, t1_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    t1_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (rho_attr)
        free(rho_attr);
    if (t1_attr)
        free(t1_attr);
    if (value_attr)
        free(value_attr);

   return rc;
}

//  ibm_dilithium_priv_set_default_attributes()
//
CK_RV ibm_dilithium_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *type_attr = NULL;
    CK_ATTRIBUTE *rho_attr = NULL;
    CK_ATTRIBUTE *seed_attr = NULL;
    CK_ATTRIBUTE *tr_attr = NULL;
    CK_ATTRIBUTE *s1_attr = NULL;
    CK_ATTRIBUTE *s2_attr = NULL;
    CK_ATTRIBUTE *t0_attr = NULL;
    CK_ATTRIBUTE *t1_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_RV rc;

    priv_key_set_default_attributes(tmpl, mode);

    type_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    rho_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    seed_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    tr_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    s1_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    s2_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    t0_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    t1_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!type_attr || !rho_attr || !seed_attr || !tr_attr || !s1_attr
        || !s2_attr || !t0_attr || !t1_attr || !value_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_IBM_PQC_DILITHIUM;

    rho_attr->type = CKA_IBM_DILITHIUM_RHO;
    rho_attr->ulValueLen = 0;
    rho_attr->pValue = NULL;

    seed_attr->type = CKA_IBM_DILITHIUM_SEED;
    seed_attr->ulValueLen = 0;
    seed_attr->pValue = NULL;

    tr_attr->type = CKA_IBM_DILITHIUM_TR;
    tr_attr->ulValueLen = 0;
    tr_attr->pValue = NULL;

    s1_attr->type = CKA_IBM_DILITHIUM_S1;
    s1_attr->ulValueLen = 0;
    s1_attr->pValue = NULL;

    s2_attr->type = CKA_IBM_DILITHIUM_S2;
    s2_attr->ulValueLen = 0;
    s2_attr->pValue = NULL;

    t0_attr->type = CKA_IBM_DILITHIUM_T0;
    t0_attr->ulValueLen = 0;
    t0_attr->pValue = NULL;

    t1_attr->type = CKA_IBM_DILITHIUM_T1;
    t1_attr->ulValueLen = 0;
    t1_attr->pValue = NULL;

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, rho_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    rho_attr = NULL;
    rc = template_update_attribute(tmpl, seed_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    seed_attr = NULL;
    rc = template_update_attribute(tmpl, tr_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    tr_attr = NULL;
    rc = template_update_attribute(tmpl, s1_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    s1_attr = NULL;
    rc = template_update_attribute(tmpl, s2_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    s2_attr = NULL;
    rc = template_update_attribute(tmpl, t0_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    t0_attr = NULL;
    rc = template_update_attribute(tmpl, t1_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    t1_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (rho_attr)
        free(rho_attr);
    if (seed_attr)
        free(seed_attr);
    if (tr_attr)
        free(tr_attr);
    if (s1_attr)
        free(s1_attr);
    if (s2_attr)
        free(s2_attr);
    if (t0_attr)
        free(t0_attr);
    if (t1_attr)
        free(t1_attr);
    if (value_attr)
        free(value_attr);

    return rc;
}

//  ibm_dilithium_publ_set_default_attributes()
//
CK_RV ibm_kyber_publ_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *type_attr = NULL;
    CK_ATTRIBUTE *pk_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_RV rc;

    publ_key_set_default_attributes(tmpl, mode);

    type_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    pk_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!type_attr || !pk_attr ||!value_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_IBM_PQC_KYBER;

    pk_attr->type = CKA_IBM_KYBER_PK;
    pk_attr->ulValueLen = 0;
    pk_attr->pValue = NULL;

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, pk_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    pk_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (pk_attr)
        free(pk_attr);
    if (value_attr)
        free(value_attr);

   return rc;
}

//  ibm_dilithium_priv_set_default_attributes()
//
CK_RV ibm_kyber_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *type_attr = NULL;
    CK_ATTRIBUTE *sk_attr = NULL;
    CK_ATTRIBUTE *pk_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_RV rc;

    priv_key_set_default_attributes(tmpl, mode);

    type_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    sk_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    pk_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));

    if (!type_attr || !sk_attr || !pk_attr || !value_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_IBM_PQC_KYBER;

    sk_attr->type = CKA_IBM_KYBER_SK;
    sk_attr->ulValueLen = 0;
    sk_attr->pValue = NULL;

    pk_attr->type = CKA_IBM_KYBER_PK;
    pk_attr->ulValueLen = 0;
    pk_attr->pValue = NULL;

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, sk_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    sk_attr = NULL;
    rc = template_update_attribute(tmpl, pk_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    pk_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (sk_attr)
        free(sk_attr);
    if (pk_attr)
        free(pk_attr);
    if (value_attr)
        free(value_attr);

    return rc;
}

static CK_RV ibm_pqc_check_attributes(TEMPLATE *tmpl, CK_ULONG mode,
                                      CK_MECHANISM_TYPE mech,
                                      CK_ULONG *req_attrs,
                                      CK_ULONG num_req_attrs)
{
    CK_ATTRIBUTE_TYPE keyform_attr;
    CK_ATTRIBUTE_TYPE mode_attr;
    CK_ATTRIBUTE *attr = NULL;
    CK_BBOOL keyform_present = FALSE;
    CK_BBOOL mode_present = FALSE;
    const struct pqc_oid *oids, *oid;
    CK_ULONG i;
    CK_RV rc;

    if (ibm_pqc_keyform_mode_attrs_by_mech(mech, &keyform_attr,
                                           &mode_attr, &oids) != CKR_OK)
        return CKR_MECHANISM_INVALID;

    if (template_attribute_find(tmpl, keyform_attr, &attr) &&
        attr->ulValueLen == sizeof(CK_ULONG) && attr->pValue != NULL) {
        oid = find_pqc_by_keyform(oids, *(CK_ULONG *)(attr->pValue));
        if (oid == NULL) {
            TRACE_ERROR("%s, attribute KEYFORM has an unsupported value.\n",
                        ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        keyform_present = TRUE;
    }

    if (template_attribute_find(tmpl, mode_attr, &attr) &&
        attr->ulValueLen > 0 && attr->pValue != NULL) {
        oid = find_pqc_by_oid(oids, attr->pValue, attr->ulValueLen);
        if (oid == NULL) {
            TRACE_ERROR("%s, attribute MODE has an unsupported value.\n",
                        ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        mode_present = TRUE;
    }

    switch (mode) {
    case MODE_CREATE:
        /* Import of an already existing secure key via CKA_IBM_OPAQUE */
        if (token_specific.secure_key_token == TRUE &&
            template_attribute_get_non_empty(tmpl, CKA_IBM_OPAQUE,
                                             &attr) == CKR_OK)
            break;
        /* Either CKA_VALUE or all other attrs must be present */
        if (template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr) == CKR_OK)
            break;
        for (i = 0; i < num_req_attrs; i++) {
            rc = template_attribute_get_non_empty(tmpl, req_attrs[i], &attr);
            if (rc != CKR_OK) {
                if (rc != CKR_ATTRIBUTE_VALUE_INVALID)
                    TRACE_ERROR("%s, attribute %08lX missing.\n",
                               ock_err(ERR_TEMPLATE_INCOMPLETE), req_attrs[i]);
                return rc;
            }
        }
        /* fallthrough */
    case MODE_KEYGEN:
        /* Either keyform or mode or none of it must be present */
        if (keyform_present && mode_present) {
            TRACE_ERROR("%s, only one of KEYFORM or MODE can be specified .\n",
                        ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        break;
    case MODE_UNWRAP:
        /* neither keyform or mode must be present */
        if (keyform_present || mode_present) {
            TRACE_ERROR("%s, none of KEYFORM or MODE can be specified .\n",
                        ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        break;
    case MODE_COPY:
        /* All attributes must be present */
        if (!keyform_present || !mode_present) {
            TRACE_ERROR("%s, KEYFORM or MODE must be specified .\n",
                        ock_err(ERR_TEMPLATE_INCOMPLETE));
            return CKR_TEMPLATE_INCOMPLETE;
        }
        for (i = 0; i < num_req_attrs; i++) {
            if (!template_attribute_find(tmpl, req_attrs[i], &attr)) {
                TRACE_ERROR("%s, attribute %08lX missing.\n",
                            ock_err(ERR_TEMPLATE_INCOMPLETE), req_attrs[i]);
                return CKR_TEMPLATE_INCOMPLETE;
            }
        }
        break;
    }

    return CKR_OK;
}

// ibm_dilithium_publ_check_required_attributes()
//
CK_RV ibm_dilithium_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    static CK_ULONG req_attrs[] = {
        CKA_IBM_DILITHIUM_RHO,
        CKA_IBM_DILITHIUM_T1,
    };
    CK_RV rc;

    rc = ibm_pqc_check_attributes(tmpl, mode, CKM_IBM_DILITHIUM, req_attrs,
                                  sizeof(req_attrs) / sizeof(req_attrs[0]));
    if (rc != CKR_OK)
        return rc;

    /* All required attrs found, check them */
    return publ_key_check_required_attributes(tmpl, mode);
}

// ibm_dilithium_priv_check_required_attributes()
//
CK_RV ibm_dilithium_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    static CK_ULONG req_attrs[] = {
        CKA_IBM_DILITHIUM_RHO,
        CKA_IBM_DILITHIUM_SEED,
        CKA_IBM_DILITHIUM_TR,
        CKA_IBM_DILITHIUM_S1,
        CKA_IBM_DILITHIUM_S2,
        CKA_IBM_DILITHIUM_T0,
        CKA_IBM_DILITHIUM_T1,
    };
    CK_RV rc;

    rc = ibm_pqc_check_attributes(tmpl, mode, CKM_IBM_DILITHIUM, req_attrs,
                                  sizeof(req_attrs) / sizeof(req_attrs[0]));
    if (rc != CKR_OK)
        return rc;

    /* All required attrs found, check them */
    return priv_key_check_required_attributes(tmpl, mode);
}

// ibm_kyber_publ_check_required_attributes()
//
CK_RV ibm_kyber_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    static CK_ULONG req_attrs[] = {
        CKA_IBM_KYBER_PK,
    };
    CK_RV rc;

    rc = ibm_pqc_check_attributes(tmpl, mode, CKM_IBM_KYBER, req_attrs,
                                  sizeof(req_attrs) / sizeof(req_attrs[0]));
    if (rc != CKR_OK)
        return rc;

    /* All required attrs found, check them */
    return publ_key_check_required_attributes(tmpl, mode);
}

// ibm_kyber_priv_check_required_attributes()
//
CK_RV ibm_kyber_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    static CK_ULONG req_attrs[] = {
        CKA_IBM_KYBER_SK,
        CKA_IBM_KYBER_PK,
    };
    CK_RV rc;

    rc = ibm_pqc_check_attributes(tmpl, mode, CKM_IBM_KYBER, req_attrs,
                                  sizeof(req_attrs) / sizeof(req_attrs[0]));
    if (rc != CKR_OK)
        return rc;

    /* All required attrs found, check them */
    return priv_key_check_required_attributes(tmpl, mode);
}

static CK_RV ibm_pqc_validate_keyform_mode(CK_ATTRIBUTE *attr, CK_ULONG mode,
                                           CK_MECHANISM_TYPE mech)
{
    CK_ATTRIBUTE_TYPE keyform_attr;
    CK_ATTRIBUTE_TYPE mode_attr;
    const struct pqc_oid *oids, *oid;

    if (ibm_pqc_keyform_mode_attrs_by_mech(mech, &keyform_attr,
                                           &mode_attr, &oids) != CKR_OK)
        return CKR_MECHANISM_INVALID;

    if (attr->type == keyform_attr) {
        if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
            if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            oid = find_pqc_by_keyform(oids, *((CK_ULONG *)attr->pValue));
            if (oid == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    }
    if (attr->type == mode_attr) {
        if (mode == MODE_CREATE || mode == MODE_KEYGEN) {
            if (attr->ulValueLen == 0 || attr->pValue == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            oid = find_pqc_by_oid(oids, attr->pValue, attr->ulValueLen);
            if (oid == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    }

    return CKR_OK;
}

// ibm_dilithium_publ_validate_attribute()
//
CK_RV ibm_dilithium_publ_validate_attribute(STDLL_TokData_t *tokdata,
                                            TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                            CK_ULONG mode)
{
    CK_RV rc;

    switch (attr->type) {
    case CKA_IBM_DILITHIUM_KEYFORM:
    case CKA_IBM_DILITHIUM_MODE:
        rc = ibm_pqc_validate_keyform_mode(attr, mode, CKM_IBM_DILITHIUM);
        if (rc != CKR_OK)
            return rc;
        return CKR_OK;
    case CKA_IBM_DILITHIUM_RHO:
    case CKA_IBM_DILITHIUM_T1:
    case CKA_VALUE:
        if (mode == MODE_CREATE)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return publ_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}

// ibm_dilithium_priv_validate_attribute()
//
CK_RV ibm_dilithium_priv_validate_attribute(STDLL_TokData_t *tokdata,
                                            TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                            CK_ULONG mode)
{
    CK_RV rc;

    switch (attr->type) {
    case CKA_IBM_DILITHIUM_KEYFORM:
    case CKA_IBM_DILITHIUM_MODE:
        rc = ibm_pqc_validate_keyform_mode(attr, mode, CKM_IBM_DILITHIUM);
        if (rc != CKR_OK)
            return rc;
        return CKR_OK;
    case CKA_IBM_DILITHIUM_RHO:
    case CKA_IBM_DILITHIUM_SEED:
    case CKA_IBM_DILITHIUM_TR:
    case CKA_IBM_DILITHIUM_S1:
    case CKA_IBM_DILITHIUM_S2:
    case CKA_IBM_DILITHIUM_T0:
    case CKA_IBM_DILITHIUM_T1:
    case CKA_VALUE:
        if (mode == MODE_CREATE)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return priv_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}

CK_BBOOL ibm_dilithium_priv_check_exportability(CK_ATTRIBUTE_TYPE type)
{
    switch (type) {
    case CKA_VALUE:
    case CKA_IBM_DILITHIUM_SEED:
    case CKA_IBM_DILITHIUM_TR:
    case CKA_IBM_DILITHIUM_S1:
    case CKA_IBM_DILITHIUM_S2:
    case CKA_IBM_DILITHIUM_T0:
        return FALSE;
    }

    return TRUE;
}

// ibm_kyber_publ_validate_attribute()
//
CK_RV ibm_kyber_publ_validate_attribute(STDLL_TokData_t *tokdata,
                                        TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                        CK_ULONG mode)
{
    CK_RV rc;

    switch (attr->type) {
    case CKA_IBM_KYBER_KEYFORM:
    case CKA_IBM_KYBER_MODE:
        rc = ibm_pqc_validate_keyform_mode(attr, mode, CKM_IBM_KYBER);
        if (rc != CKR_OK)
            return rc;
        return CKR_OK;
    case CKA_IBM_KYBER_PK:
    case CKA_VALUE:
        if (mode == MODE_CREATE)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return publ_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}

// ibm_kyber_priv_validate_attribute()
//
CK_RV ibm_kyber_priv_validate_attribute(STDLL_TokData_t *tokdata,
                                        TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                        CK_ULONG mode)
{
    CK_RV rc;

    switch (attr->type) {
    case CKA_IBM_KYBER_KEYFORM:
    case CKA_IBM_KYBER_MODE:
        rc = ibm_pqc_validate_keyform_mode(attr, mode, CKM_IBM_KYBER);
        if (rc != CKR_OK)
            return rc;
        return CKR_OK;
    case CKA_IBM_KYBER_SK:
    case CKA_IBM_KYBER_PK:
    case CKA_VALUE:
        if (mode == MODE_CREATE)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return priv_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}

CK_BBOOL ibm_kyber_priv_check_exportability(CK_ATTRIBUTE_TYPE type)
{
    switch (type) {
    case CKA_VALUE:
    case CKA_IBM_KYBER_SK:
        return FALSE;
    }

    return TRUE;
}

// generic_secret_check_required_attributes()
//
CK_RV generic_secret_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG val;
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    }

    rc = template_attribute_get_ulong(tmpl, CKA_VALUE_LEN, &val);
    if (rc != CKR_OK) {
        // here's another place where PKCS #11 deviates from its own
        // specification.
        // the spec states that VALUE_LEN must be present for KEYGEN but later
        // it's merely optional if the mechanism is CKM_SSL3_PRE_MASTER_KEY_GEN.
        // Unfortunately, we can't check the mechanism at this point
        //
        return CKR_OK;
    } else {
        // Another contradiction within the spec:  When describing the key types
        // the spec says that VALUE_LEN must not be specified when unwrapping
        // a key. In the section describing the mechanisms, though, it's allowed
        // for most unwrapping mechanisms. Netscape DOES does specify this
        // attribute when unwrapping.
        //
        if (mode == MODE_CREATE) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
    }

    return secret_key_check_required_attributes(tmpl, mode);
}


//  generic_secret_set_default_attributes()
//
CK_RV generic_secret_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *value_len_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_ATTRIBUTE *class_attr = NULL;
    CK_ATTRIBUTE *sensitive_attr = NULL;
    CK_ATTRIBUTE *encrypt_attr = NULL;
    CK_ATTRIBUTE *decrypt_attr = NULL;
    CK_ATTRIBUTE *sign_attr = NULL;
    CK_ATTRIBUTE *verify_attr = NULL;
    CK_ATTRIBUTE *wrap_attr = NULL;
    CK_ATTRIBUTE *unwrap_attr = NULL;
    CK_ATTRIBUTE *extractable_attr = NULL;
    CK_ATTRIBUTE *never_extr_attr = NULL;
    CK_ATTRIBUTE *always_sens_attr = NULL;
    CK_ATTRIBUTE *id_attr = NULL;
    CK_ATTRIBUTE *sdate_attr = NULL;
    CK_ATTRIBUTE *edate_attr = NULL;
    CK_ATTRIBUTE *derive_attr = NULL;
    CK_ATTRIBUTE *local_attr = NULL;
    CK_ULONG len = 0L;
    CK_RV rc;

    /* First set the Common Key Attributes's defaults for Generic Secret Keys */

    id_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    sdate_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    edate_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    derive_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    local_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));

    if (!id_attr || !sdate_attr || !edate_attr || !derive_attr || !local_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    id_attr->type = CKA_ID;
    id_attr->ulValueLen = 0;
    id_attr->pValue = NULL;

    sdate_attr->type = CKA_START_DATE;
    sdate_attr->ulValueLen = 0;
    sdate_attr->pValue = NULL;

    edate_attr->type = CKA_END_DATE;
    edate_attr->ulValueLen = 0;
    edate_attr->pValue = NULL;

    derive_attr->type = CKA_DERIVE;
    derive_attr->ulValueLen = sizeof(CK_BBOOL);
    derive_attr->pValue = (CK_BYTE *) derive_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) derive_attr->pValue = TRUE;

    /* should be safe to set CKA_LOCAL here...  */
    local_attr->type = CKA_LOCAL;
    local_attr->ulValueLen = sizeof(CK_BBOOL);
    local_attr->pValue = (CK_BYTE *) local_attr + sizeof(CK_ATTRIBUTE);
    if (mode == MODE_KEYGEN)
        *(CK_BBOOL *) local_attr->pValue = TRUE;
    else
        *(CK_BBOOL *) local_attr->pValue = FALSE;

    rc = template_update_attribute(tmpl, id_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    id_attr = NULL;
    rc = template_update_attribute(tmpl, sdate_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    sdate_attr = NULL;
    rc = template_update_attribute(tmpl, edate_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    edate_attr = NULL;
    rc = template_update_attribute(tmpl, derive_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    derive_attr = NULL;
    rc = template_update_attribute(tmpl, local_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    local_attr = NULL;

    /* Next, set the Common Secret Key Attributes and defaults for
     * Generic Secret Keys.
     */

    class_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS));
    sensitive_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    encrypt_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    decrypt_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    sign_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    verify_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    wrap_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    unwrap_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    extractable_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    never_extr_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    always_sens_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    if (!class_attr || !sensitive_attr || !encrypt_attr || !decrypt_attr
        || !sign_attr || !verify_attr || !wrap_attr || !unwrap_attr
        || !extractable_attr || !never_extr_attr || !always_sens_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    class_attr->type = CKA_CLASS;
    class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
    class_attr->pValue = (CK_BYTE *) class_attr + sizeof(CK_ATTRIBUTE);
    *(CK_OBJECT_CLASS *) class_attr->pValue = CKO_SECRET_KEY;

    sensitive_attr->type = CKA_SENSITIVE;
    sensitive_attr->ulValueLen = sizeof(CK_BBOOL);
    sensitive_attr->pValue = (CK_BYTE *) sensitive_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) sensitive_attr->pValue = FALSE;

    encrypt_attr->type = CKA_ENCRYPT;
    encrypt_attr->ulValueLen = sizeof(CK_BBOOL);
    encrypt_attr->pValue = (CK_BYTE *) encrypt_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) encrypt_attr->pValue = FALSE;

    decrypt_attr->type = CKA_DECRYPT;
    decrypt_attr->ulValueLen = sizeof(CK_BBOOL);
    decrypt_attr->pValue = (CK_BYTE *) decrypt_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) decrypt_attr->pValue = FALSE;

    sign_attr->type = CKA_SIGN;
    sign_attr->ulValueLen = sizeof(CK_BBOOL);
    sign_attr->pValue = (CK_BYTE *) sign_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) sign_attr->pValue = TRUE;

    verify_attr->type = CKA_VERIFY;
    verify_attr->ulValueLen = sizeof(CK_BBOOL);
    verify_attr->pValue = (CK_BYTE *) verify_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) verify_attr->pValue = TRUE;

    wrap_attr->type = CKA_WRAP;
    wrap_attr->ulValueLen = sizeof(CK_BBOOL);
    wrap_attr->pValue = (CK_BYTE *) wrap_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) wrap_attr->pValue = FALSE;

    unwrap_attr->type = CKA_UNWRAP;
    unwrap_attr->ulValueLen = sizeof(CK_BBOOL);
    unwrap_attr->pValue = (CK_BYTE *) unwrap_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) unwrap_attr->pValue = FALSE;

    extractable_attr->type = CKA_EXTRACTABLE;
    extractable_attr->ulValueLen = sizeof(CK_BBOOL);
    extractable_attr->pValue =
        (CK_BYTE *) extractable_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) extractable_attr->pValue = TRUE;

    /* by default, we'll set NEVER_EXTRACTABLE == FALSE and
     * ALWAYS_SENSITIVE == FALSE
     * If the key is being created with KEYGEN, it will adjust as necessary.
     */
    always_sens_attr->type = CKA_ALWAYS_SENSITIVE;
    always_sens_attr->ulValueLen = sizeof(CK_BBOOL);
    always_sens_attr->pValue =
        (CK_BYTE *) always_sens_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) always_sens_attr->pValue = FALSE;

    never_extr_attr->type = CKA_NEVER_EXTRACTABLE;
    never_extr_attr->ulValueLen = sizeof(CK_BBOOL);
    never_extr_attr->pValue =
        (CK_BYTE *) never_extr_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) never_extr_attr->pValue = FALSE;

    rc = template_update_attribute(tmpl, class_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    class_attr = NULL;
    rc = template_update_attribute(tmpl, sensitive_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    sensitive_attr = NULL;
    rc = template_update_attribute(tmpl, encrypt_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    encrypt_attr = NULL;
    rc = template_update_attribute(tmpl, decrypt_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    decrypt_attr = NULL;
    rc = template_update_attribute(tmpl, sign_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    sign_attr = NULL;
    rc = template_update_attribute(tmpl, verify_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    verify_attr = NULL;
    rc = template_update_attribute(tmpl, wrap_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    wrap_attr = NULL;
    rc = template_update_attribute(tmpl, unwrap_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    unwrap_attr = NULL;
    rc = template_update_attribute(tmpl, extractable_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    extractable_attr = NULL;
    rc = template_update_attribute(tmpl, never_extr_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    never_extr_attr = NULL;
    rc = template_update_attribute(tmpl, always_sens_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    always_sens_attr = NULL;

    /* Now set the type, value and value_len */
    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    value_len_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG));

    if (!type_attr || !value_attr || !value_len_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    value_len_attr->type = CKA_VALUE_LEN;
    value_len_attr->ulValueLen = sizeof(CK_ULONG);
    value_len_attr->pValue = (CK_BYTE *) value_len_attr + sizeof(CK_ATTRIBUTE);
    *(CK_ULONG *) value_len_attr->pValue = len;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_GENERIC_SECRET;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;
    rc = template_update_attribute(tmpl, value_len_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_len_attr = NULL;

    return CKR_OK;

error:
    if (id_attr)
        free(id_attr);
    if (sdate_attr)
        free(sdate_attr);
    if (edate_attr)
        free(edate_attr);
    if (derive_attr)
        free(derive_attr);
    if (local_attr)
        free(local_attr);
    if (class_attr)
        free(class_attr);
    if (sensitive_attr)
        free(sensitive_attr);
    if (encrypt_attr)
        free(encrypt_attr);
    if (decrypt_attr)
        free(decrypt_attr);
    if (sign_attr)
        free(sign_attr);
    if (verify_attr)
        free(verify_attr);
    if (wrap_attr)
        free(wrap_attr);
    if (unwrap_attr)
        free(unwrap_attr);
    if (extractable_attr)
        free(extractable_attr);
    if (never_extr_attr)
        free(never_extr_attr);
    if (always_sens_attr)
        free(always_sens_attr);
    if (type_attr)
        free(type_attr);
    if (value_attr)
        free(value_attr);
    if (value_len_attr)
        free(value_len_attr);

    return rc;
}

// generic_secret_validate_attribute()
//
CK_RV generic_secret_validate_attribute(STDLL_TokData_t *tokdata,
                                        TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                        CK_ULONG mode)
{
    switch (attr->type) {
    case CKA_VALUE:
        if (mode == MODE_CREATE)
            return CKR_OK;

        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
        // Another contradiction within the spec:  When describing the key types
        // the spec says that VALUE_LEN must not be specified when unwrapping
        // a key. In the section describing the mechanisms, though, it's allowed
        // for most unwrapping mechanisms. Netscape DOES does specify this
        // attribute when unwrapping.
        //
    case CKA_VALUE_LEN:
        if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_KEYGEN || mode == MODE_DERIVE)
            return CKR_OK;
        if (mode == MODE_UNWRAP) {
            if (tokdata->nv_token_data->tweak_vector.netscape_mods == TRUE)
                return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return secret_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}


// generic_secret_check_exportability()
//
CK_BBOOL generic_secret_check_exportability(CK_ATTRIBUTE_TYPE type)
{
    switch (type) {
    case CKA_VALUE:
        return FALSE;
    }

    return TRUE;
}


//
//
CK_RV generic_secret_wrap_get_data(TEMPLATE *tmpl,
                                   CK_BBOOL length_only,
                                   CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_RV rc;


    if (!tmpl || !data_len) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc !=  CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    *data_len = attr->ulValueLen;

    if (length_only == FALSE) {
        ptr = (CK_BYTE *) malloc(attr->ulValueLen);
        if (!ptr) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }
        memcpy(ptr, attr->pValue, attr->ulValueLen);

        *data = ptr;
    }

    return CKR_OK;
}


//
//
CK_RV generic_secret_unwrap(TEMPLATE *tmpl,
                            CK_BYTE *data,
                            CK_ULONG data_len,
                            CK_BBOOL fromend)
{
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *value_len_attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_ULONG rc, len = 0;


    if (fromend == TRUE)
        ptr = data + data_len;
    else
        ptr = data;

    // it's possible that the user specified CKA_VALUE_LEN in the
    // template.  if so, try to use it.  by default, CKA_VALUE_LEN is 0
    //
    rc = template_attribute_get_ulong(tmpl, CKA_VALUE_LEN, &len);
    if (rc == CKR_OK) {
        if (len > data_len) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            rc = CKR_ATTRIBUTE_VALUE_INVALID;
            goto error;
        }

        if (len != 0)
            data_len = len;
    }

    if (fromend == TRUE)
        ptr -= data_len;

    rc = build_attribute(CKA_VALUE, ptr, data_len, &value_attr);

    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    if (data_len != len) {
        rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *) & data_len,
                             sizeof(CK_ULONG), &value_len_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("build_attribute failed\n");
            goto error;
        }
    }

    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    if (data_len != len) {
        rc = template_update_attribute(tmpl, value_len_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        value_len_attr = NULL;
    }

    return CKR_OK;

error:
    if (value_attr)
        free(value_attr);
    if (value_len_attr)
        free(value_len_attr);

    return rc;
}

//
//
CK_RV des_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    if (mode == MODE_CREATE &&
        token_specific.secure_key_token == TRUE &&
        template_attribute_get_non_empty(tmpl, CKA_IBM_OPAQUE, &attr) == CKR_OK) {
        /*
         * Import of an already existing secure key. Only
         * do the base checks for des key templates.
         */
        return secret_key_check_required_attributes(tmpl, mode);
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    }

    return secret_key_check_required_attributes(tmpl, mode);
}


//
//
CK_BBOOL des_check_weak_key(CK_BYTE *key)
{
    CK_ULONG i;

    for (i = 0; i < des_weak_count; i++) {
        if (memcmp(key, des_weak_keys[i], DES_KEY_SIZE) == 0)
            return TRUE;
    }

    for (i = 0; i < des_semi_weak_count; i++) {
        if (memcmp(key, des_semi_weak_keys[i], DES_KEY_SIZE) == 0)
            return TRUE;
    }

    for (i = 0; i < des_possibly_weak_count; i++) {
        if (memcmp(key, des_possibly_weak_keys[i], DES_KEY_SIZE) == 0)
            return TRUE;
    }

    return FALSE;
}



//
//
CK_RV des_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_RV rc;

    secret_key_set_default_attributes(tmpl, mode);

    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));

    if (!value_attr || !type_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_DES;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (value_attr)
        free(value_attr);
    if (type_attr)
        free(type_attr);

    return rc;
}


//
//
CK_RV des_unwrap(STDLL_TokData_t *tokdata,
                 TEMPLATE *tmpl,
                 CK_BYTE *data,
                 CK_ULONG data_len, CK_BBOOL fromend)
{
    CK_ATTRIBUTE *value_attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_ULONG i;
    CK_RV rc;

    if (data_len < DES_BLOCK_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_WRAPPED_KEY_INVALID));
        return CKR_WRAPPED_KEY_INVALID;
    }
    if (fromend == TRUE)
        ptr = data + data_len - DES_BLOCK_SIZE;
    else
        ptr = data;

    if (tokdata->nv_token_data->tweak_vector.check_des_parity == TRUE) {
        for (i = 0; i < DES_KEY_SIZE; i++) {
            if (parity_is_odd(ptr[i]) == FALSE) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
        }
    }
    value_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + DES_BLOCK_SIZE);
    if (!value_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = DES_BLOCK_SIZE;
    value_attr->pValue = (CK_BYTE *) value_attr + sizeof(CK_ATTRIBUTE);
    memcpy(value_attr->pValue, ptr, DES_BLOCK_SIZE);

    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(value_attr);
        return rc;
    }

    return CKR_OK;
}


// des_validate_attribute()
//
CK_RV des_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                             CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    CK_BYTE *ptr = NULL;
    CK_ULONG i;

    switch (attr->type) {
    case CKA_VALUE:
        // key length always 8 bytes
        //
        if (mode == MODE_CREATE) {
            if (attr->ulValueLen != DES_KEY_SIZE) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            if (tokdata->nv_token_data->tweak_vector.check_des_parity == TRUE) {
                ptr = attr->pValue;
                if (ptr == NULL) {
                    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                for (i = 0; i < DES_KEY_SIZE; i++) {
                    if (parity_is_odd(ptr[i]) == FALSE) {
                        TRACE_ERROR("%s\n",
                                    ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                }
            }
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_VALUE_LEN:
        // Cryptoki doesn't allow this but Netscape tries uses it
        //
        if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (tokdata->nv_token_data->tweak_vector.netscape_mods == TRUE) {
            if (mode == MODE_CREATE || mode == MODE_DERIVE ||
                mode == MODE_KEYGEN || mode == MODE_UNWRAP) {
                CK_ULONG len = *(CK_ULONG *) attr->pValue;
                if (len != DES_KEY_SIZE) {
                    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                return CKR_OK;
            }
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID));
        return CKR_ATTRIBUTE_TYPE_INVALID;
    default:
        return secret_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}


//
//
CK_RV des_wrap_get_data(TEMPLATE *tmpl,
                        CK_BBOOL length_only,
                        CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_RV rc;

    if (!tmpl || !data_len) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc !=  CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    *data_len = attr->ulValueLen;

    if (length_only == FALSE) {
        ptr = (CK_BYTE *) malloc(attr->ulValueLen);
        if (!ptr) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }
        memcpy(ptr, attr->pValue, attr->ulValueLen);

        *data = ptr;
    }

    return CKR_OK;
}


// des2_check_required_attributes()
//
CK_RV des2_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    }

    return secret_key_check_required_attributes(tmpl, mode);
}


//  des2_set_default_attributes()
//
CK_RV des2_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_RV rc;

    secret_key_set_default_attributes(tmpl, mode);

    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));

    if (!value_attr || !type_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_DES2;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (value_attr)
        free(value_attr);
    if (type_attr)
        free(type_attr);

    return rc;
}


// des2_validate_attribute()
//
CK_RV des2_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                              CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    CK_BYTE *ptr = NULL;
    CK_ULONG i;

    switch (attr->type) {
    case CKA_VALUE:
        // key length always 16 bytes
        //
        if (mode == MODE_CREATE) {
            if (attr->ulValueLen != (2 * DES_KEY_SIZE)) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            if (tokdata->nv_token_data->tweak_vector.check_des_parity == TRUE) {
                ptr = attr->pValue;
                if (ptr == NULL) {
                    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                for (i = 0; i < 2 * DES_KEY_SIZE; i++) {
                    if (parity_is_odd(ptr[i]) == FALSE) {
                        TRACE_ERROR("%s\n",
                                    ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                }
            }
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_VALUE_LEN:
        if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        // Cryptoki doesn't allow this but Netscape tries uses it
        //
        if (tokdata->nv_token_data->tweak_vector.netscape_mods == TRUE) {
            if (mode == MODE_CREATE || mode == MODE_DERIVE ||
                mode == MODE_KEYGEN || mode == MODE_UNWRAP) {
                CK_ULONG len = *(CK_ULONG *) attr->pValue;
                if (len != (2 * DES_KEY_SIZE)) {
                    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                return CKR_OK;
            }
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID));
        return CKR_ATTRIBUTE_TYPE_INVALID;
    default:
        return secret_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}


// des3_check_required_attributes()
//
CK_RV des3_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    if (mode == MODE_CREATE &&
        token_specific.secure_key_token == TRUE &&
        template_attribute_get_non_empty(tmpl, CKA_IBM_OPAQUE, &attr) == CKR_OK) {
        /*
         * Import of an already existing secure key. Only
         * do the base checks for des3 key templates.
         */
        return secret_key_check_required_attributes(tmpl, mode);
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    }

    return secret_key_check_required_attributes(tmpl, mode);
}


//  des3_set_default_attributes()
//
CK_RV des3_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_RV rc;

    secret_key_set_default_attributes(tmpl, mode);

    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));

    if (!value_attr || !type_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = CKK_DES3;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    return CKR_OK;

error:
    if (value_attr)
        free(value_attr);
    if (type_attr)
        free(type_attr);

    return rc;
}


//
//
CK_RV des3_unwrap(STDLL_TokData_t *tokdata,
                  TEMPLATE *tmpl,
                  CK_BYTE *data,
                  CK_ULONG data_len, CK_BBOOL fromend)
{
    CK_ATTRIBUTE *value_attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_ULONG i;
    CK_RV rc;

    if (data_len < 3 * DES_BLOCK_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_WRAPPED_KEY_INVALID));
        return CKR_WRAPPED_KEY_INVALID;
    }
    if (fromend == TRUE)
        ptr = data + data_len - (3 * DES_BLOCK_SIZE);
    else
        ptr = data;

    if (tokdata->nv_token_data->tweak_vector.check_des_parity == TRUE) {
        for (i = 0; i < 3 * DES_KEY_SIZE; i++) {
            if (parity_is_odd(ptr[i]) == FALSE) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
        }
    }
    value_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + (3 * DES_BLOCK_SIZE));

    if (!value_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 3 * DES_BLOCK_SIZE;
    value_attr->pValue = (CK_BYTE *) value_attr + sizeof(CK_ATTRIBUTE);
    memcpy(value_attr->pValue, ptr, 3 * DES_BLOCK_SIZE);

    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(value_attr);
        return rc;
    }

    return CKR_OK;
}


//
//
CK_RV des3_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                              CK_ATTRIBUTE *attr, CK_ULONG mode)
{
    CK_BYTE *ptr = NULL;
    CK_ULONG i;

    switch (attr->type) {
    case CKA_VALUE:
        // key length always 24 bytes
        //
        if (mode == MODE_CREATE) {
            if (attr->ulValueLen != (3 * DES_KEY_SIZE)) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            if (tokdata->nv_token_data->tweak_vector.check_des_parity == TRUE) {
                ptr = attr->pValue;
                if (ptr == NULL) {
                    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                    return CKR_ATTRIBUTE_VALUE_INVALID;
                }
                for (i = 0; i < 3 * DES_KEY_SIZE; i++) {
                    if (parity_is_odd(ptr[i]) == FALSE) {
                        TRACE_ERROR("%s\n",
                                    ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                        return CKR_ATTRIBUTE_VALUE_INVALID;
                    }
                }
            }
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_VALUE_LEN:
        if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        // Cryptoki doesn't allow this but Netscape tries uses it
        //
        if (tokdata->nv_token_data->tweak_vector.netscape_mods == TRUE) {
            if (mode == MODE_CREATE || mode == MODE_DERIVE ||
                mode == MODE_KEYGEN || mode == MODE_UNWRAP) {
                return CKR_OK;
            }
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID));
        return CKR_ATTRIBUTE_TYPE_INVALID;
    default:
        return secret_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}


//
//
CK_RV des3_wrap_get_data(TEMPLATE *tmpl,
                         CK_BBOOL length_only,
                         CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_RV rc;

    if (!tmpl || !data_len) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc !=  CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    *data_len = attr->ulValueLen;

    if (length_only == FALSE) {
        ptr = (CK_BYTE *) malloc(attr->ulValueLen);
        if (!ptr) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }
        memcpy(ptr, attr->pValue, attr->ulValueLen);

        *data = ptr;
    }

    return CKR_OK;
}

//  aes_set_default_attributes()
//
CK_RV aes_set_default_attributes(TEMPLATE *tmpl, TEMPLATE *basetmpl,
                                 CK_ULONG mode, CK_BBOOL xts)
{
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *type_attr = NULL;
    CK_ATTRIBUTE *len_attr = NULL;
    CK_ULONG keysize;
    CK_RV rc;

    secret_key_set_default_attributes(tmpl, mode);

    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE));
    type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));

    if (!value_attr || !type_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 0;
    value_attr->pValue = NULL;

    type_attr->type = CKA_KEY_TYPE;
    type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    type_attr->pValue = (CK_BYTE *) type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) type_attr->pValue = xts ? CKK_AES_XTS : CKK_AES;

    rc = template_update_attribute(tmpl, type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    type_attr = NULL;
    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;

    /* If CKA_VALUE specified in base tmpl, add CKA_VALUE_LEN to tmpl. */
    if (template_attribute_find(basetmpl, CKA_VALUE, &value_attr) &&
        !template_attribute_find(basetmpl, CKA_VALUE_LEN, &len_attr)) {
        keysize = value_attr->ulValueLen;
        rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *)&keysize, sizeof(CK_ULONG), &len_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("build_attribute failed\n");
            goto error;
        }
        rc = template_update_attribute(tmpl, len_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        value_attr = NULL;
    }

    return CKR_OK;

error:
    if (type_attr)
        free(type_attr);
    if (value_attr)
        free(value_attr);

    return rc;
}

// aes_check_required_attributes()
//
CK_RV aes_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;

    if (mode == MODE_CREATE &&
        token_specific.secure_key_token == TRUE &&
        template_attribute_get_non_empty(tmpl, CKA_IBM_OPAQUE, &attr) == CKR_OK) {
        /*
         * Import of an already existing secure key. Only
         * do the base checks for aes key templates.
         */
        return secret_key_check_required_attributes(tmpl, mode);
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        if (mode == MODE_CREATE) {
            TRACE_ERROR("Could not find CKA_VALUE\n");
            return rc;
        }
    }

    return secret_key_check_required_attributes(tmpl, mode);
}

//
//
CK_RV aes_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                             CK_ATTRIBUTE *attr, CK_ULONG mode, CK_BBOOL xts)
{
    CK_ULONG val;

    switch (attr->type) {
    case CKA_VALUE:
        // key length is either 16, 24 or 32 bytes
        //
        if (mode == MODE_CREATE) {
            if (attr->ulValueLen != (AES_KEY_SIZE_128 * (xts ? 2 : 1)) &&
                (xts || attr->ulValueLen != AES_KEY_SIZE_192) &&
                attr->ulValueLen != (AES_KEY_SIZE_256 * (xts ? 2 : 1))) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    case CKA_VALUE_LEN:
        if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_CREATE || mode == MODE_DERIVE ||
            mode == MODE_KEYGEN || mode == MODE_UNWRAP) {
            if (attr->ulValueLen != sizeof(CK_ULONG) ||
                attr->pValue == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            val = *(CK_ULONG *) attr->pValue;
            if (val != (AES_KEY_SIZE_128 * (xts ? 2 : 1)) &&
                (xts || val != AES_KEY_SIZE_192) &&
                val != (AES_KEY_SIZE_256 * (xts ? 2 : 1))) {
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            return CKR_OK;
        }
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
        return CKR_ATTRIBUTE_READ_ONLY;
    default:
        return secret_key_validate_attribute(tokdata, tmpl, attr, mode);
    }
}

//
//
CK_RV aes_wrap_get_data(TEMPLATE *tmpl,
                        CK_BBOOL length_only,
                        CK_BYTE **data, CK_ULONG *data_len)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_RV rc;


    if (!tmpl || !data_len) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = template_attribute_get_non_empty(tmpl, CKA_VALUE, &attr);
    if (rc !=  CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    *data_len = attr->ulValueLen;

    if (length_only == FALSE) {
        ptr = (CK_BYTE *) malloc(attr->ulValueLen);
        if (!ptr) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }
        memcpy(ptr, attr->pValue, attr->ulValueLen);

        *data = ptr;
    }

    return CKR_OK;
}

//
//
CK_RV aes_unwrap(STDLL_TokData_t *tokdata,
                 TEMPLATE *tmpl,
                 CK_BYTE *data,
                 CK_ULONG data_len, CK_BBOOL fromend, CK_BBOOL xts)
{
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *val_len_attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_ULONG key_size;
    CK_BBOOL found = FALSE;
    CK_RV rc;

    UNUSED(tokdata);

    /* accept CKA_VALUE_LEN. pkcs11v2.20 doesn't want this attribute when
     * unwrapping an AES key, but we need it for several reasons:
     *   - because some mechanisms may have added padding
     *   - AES keys come in several sizes
     * If not a available, try datalen and see if matches an aes key size.
     * Otherwise, fail because we need to return CKA_VALUE_LEN and we cannot
     * unless user tells us what it is.
     */
    rc = template_attribute_get_ulong(tmpl, CKA_VALUE_LEN, &key_size);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK)
        found = TRUE;
    else
        key_size = data_len;

    /* key_size should be one of AES's possible sizes */
    if (key_size != (AES_KEY_SIZE_128  * (xts ? 2 : 1)) &&
        (xts || key_size != AES_KEY_SIZE_192) &&
        key_size != (AES_KEY_SIZE_256  * (xts ? 2 : 1))) {
        TRACE_ERROR("%s\n", ock_err(ERR_WRAPPED_KEY_LEN_RANGE));
        return CKR_WRAPPED_KEY_LEN_RANGE;
    }

    if (fromend == TRUE)
        ptr = data + data_len - key_size;
    else
        ptr = data;

    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + key_size);

    if (!value_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = key_size;
    value_attr->pValue = (CK_BYTE *) value_attr + sizeof(CK_ATTRIBUTE);
    memcpy(value_attr->pValue, ptr, key_size);

    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(value_attr);
        return rc;
    }

    /* pkcs11v2-20: CKA_VALUE and CKA_VALUE_LEN given for aes key object. */
    if (!found) {
        val_len_attr =
            (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG));
        if (!val_len_attr) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }

        val_len_attr->type = CKA_VALUE_LEN;
        val_len_attr->ulValueLen = sizeof(CK_ULONG);
        val_len_attr->pValue = (CK_BYTE *) val_len_attr + sizeof(CK_ATTRIBUTE);
        *((CK_ULONG *) val_len_attr->pValue) = key_size;

        rc = template_update_attribute(tmpl, val_len_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            free(val_len_attr);
            return rc;
        }
    }

    return CKR_OK;
}
