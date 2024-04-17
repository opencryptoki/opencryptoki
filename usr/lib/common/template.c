/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File:  template.c
 *
 * Attribute template management routines
 *
 * Functions contained in this file:
 *
 *    template_add_attributes
 *    template_add_default_attributes
 *    template_attribute_find
 *    template_check_required_attributes
 *    template_check_required_base_attributes
 *    template_free
 *    template_set_default_common_attributes
 *    template_update_attribute
 *    template_validate_attribute
 *    template_validate_attributes
 *    template_validate_base_attribute
 */

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <openssl/rand.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"
#include "p11util.h"
#include "attributes.h"
#include "trace.h"

static CK_ULONG attribute_get_compressed_size(CK_ATTRIBUTE_PTR attr);

/* Random 32 byte string is unique with overwhelming probability. */
#define UNIQUE_ID_LEN 32

static CK_RV get_unique_id_str(char unique_id_str[2 * UNIQUE_ID_LEN + 1])
{
    unsigned char buf[UNIQUE_ID_LEN];
    size_t i;

    if (RAND_bytes(buf, sizeof(buf)) != 1)
        return CKR_FUNCTION_FAILED;

    for (i = 0; i < sizeof(buf); i++)
        sprintf(&unique_id_str[i * 2], "%02x", buf[i]);

    return CKR_OK;
}

/* template_add_attributes()
 *
 * blindly add the given attributes to the template. do no sanity checking
 * at this point. sanity checking will occur later.
 */
CK_RV template_add_attributes(TEMPLATE *tmpl, CK_ATTRIBUTE *pTemplate,
                              CK_ULONG ulCount)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc;
    unsigned int i;

    for (i = 0; i < ulCount; i++) {
        if (!is_attribute_defined(pTemplate[i].type)) {
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID),
                        pTemplate[i].type);
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }
        if (pTemplate[i].ulValueLen > 0 && pTemplate[i].pValue == NULL) {
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        pTemplate[i].type);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) +
                                       pTemplate[i].ulValueLen);
        if (!attr) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }
        attr->type = pTemplate[i].type;
        attr->ulValueLen = pTemplate[i].ulValueLen;

        if (attr->ulValueLen != 0) {
            attr->pValue = (CK_BYTE *) attr + sizeof(CK_ATTRIBUTE);
            if (is_attribute_attr_array(pTemplate[i].type)) {
                rc = dup_attribute_array_no_alloc(
                                (CK_ATTRIBUTE_PTR)pTemplate[i].pValue,
                                attr->ulValueLen / sizeof(CK_ATTRIBUTE),
                                (CK_ATTRIBUTE_PTR)attr->pValue);
                if (rc !=CKR_OK) {
                    if (attr->pValue != NULL)
                        OPENSSL_cleanse(attr->pValue, attr->ulValueLen);
                    free(attr);
                    TRACE_DEVEL("dup_attribute_array_no_alloc failed.\n");
                    return rc;
                }
            } else {
                memcpy(attr->pValue, pTemplate[i].pValue, attr->ulValueLen);
            }
        } else {
            attr->pValue = NULL;
        }

        rc = template_update_attribute(tmpl, attr);
        if (rc != CKR_OK) {
            if (attr->pValue != NULL)
                OPENSSL_cleanse(attr->pValue, attr->ulValueLen);
            free(attr);
            TRACE_DEVEL("template_update_attribute failed.\n");
            return rc;
        }
    }

    return CKR_OK;
}


/* template_add_default_attributes()
 * Add default attributes to '*tmpl'.
 * '*basetmpl' may be used to derive values to the default attributes
 */
CK_RV template_add_default_attributes(TEMPLATE *tmpl, TEMPLATE *basetmpl,
                                      CK_ULONG class, CK_ULONG subclass,
                                      CK_ULONG mode)
{
    CK_RV rc;

    /* first add the default common attributes */
    rc = template_set_default_common_attributes(tmpl);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_set_default_common_attributes failed.\n");
        return rc;
    }

    /* set the template class-specific default attributes */
    switch (class) {
    case CKO_DATA:
        return data_object_set_default_attributes(tmpl, mode);
    case CKO_CERTIFICATE:
        if (subclass == CKC_X_509)
            return cert_x509_set_default_attributes(tmpl, mode);
        else
            return CKR_OK;
    case CKO_PUBLIC_KEY:
        switch (subclass) {
        case CKK_RSA:
            return rsa_publ_set_default_attributes(tmpl, basetmpl, mode);
        case CKK_DSA:
            return dsa_publ_set_default_attributes(tmpl, mode);
        case CKK_ECDSA:
            return ecdsa_publ_set_default_attributes(tmpl, mode);
        case CKK_DH:
            return dh_publ_set_default_attributes(tmpl, mode);
        case CKK_IBM_PQC_DILITHIUM:
            return ibm_dilithium_publ_set_default_attributes(tmpl, mode);
        case CKK_IBM_PQC_KYBER:
            return ibm_kyber_publ_set_default_attributes(tmpl, mode);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
        }
    case CKO_PRIVATE_KEY:
        switch (subclass) {
        case CKK_RSA:
            return rsa_priv_set_default_attributes(tmpl, mode);
        case CKK_DSA:
            return dsa_priv_set_default_attributes(tmpl, mode);
        case CKK_ECDSA:
            return ecdsa_priv_set_default_attributes(tmpl, mode);
        case CKK_DH:
            return dh_priv_set_default_attributes(tmpl, mode);
        case CKK_IBM_PQC_DILITHIUM:
            return ibm_dilithium_priv_set_default_attributes(tmpl, mode);
        case CKK_IBM_PQC_KYBER:
            return ibm_kyber_priv_set_default_attributes(tmpl, mode);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
        }
    case CKO_SECRET_KEY:
        switch (subclass) {
        case CKK_GENERIC_SECRET:
            return generic_secret_set_default_attributes(tmpl, mode);
        case CKK_DES:
            return des_set_default_attributes(tmpl, mode);
        case CKK_DES2:
            return des2_set_default_attributes(tmpl, mode);
        case CKK_DES3:
            return des3_set_default_attributes(tmpl, mode);
        case CKK_AES:
            return aes_set_default_attributes(tmpl, basetmpl, mode, FALSE);
        case CKK_AES_XTS:
            return aes_set_default_attributes(tmpl, basetmpl, mode, TRUE);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
        }
    case CKO_HW_FEATURE:
        if (subclass >= CKH_VENDOR_DEFINED)
            return CKR_OK;
        switch (subclass) {
        case CKH_CLOCK:
            return clock_set_default_attributes(tmpl, mode);
        case CKH_MONOTONIC_COUNTER:
            return counter_set_default_attributes(tmpl, mode);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    case CKO_DOMAIN_PARAMETERS:
        switch (subclass) {
        case CKK_DSA:
            return dp_dsa_set_default_attributes(tmpl, mode);
        case CKK_DH:
            return dp_dh_set_default_attributes(tmpl, mode);
        case CKK_X9_42_DH:
            return dp_x9dh_set_default_attributes(tmpl, mode);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    case CKO_PROFILE:
        return profile_object_set_default_attributes(tmpl, mode);
    default:
        TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID), class);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
}


/* template_attribute_find()
 *
 * find the attribute in the list and return its value
 */
CK_BBOOL template_attribute_find(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
                                 CK_ATTRIBUTE **attr)
{
    DL_NODE *node = NULL;
    CK_ATTRIBUTE *a = NULL;

    if (!tmpl || !attr)
        return FALSE;

    node = tmpl->attribute_list;

    while (node != NULL) {
        a = (CK_ATTRIBUTE *) node->data;

        if (type == a->type) {
            *attr = a;
            return TRUE;
        }

        node = node->next;
    }

    *attr = NULL;

    return FALSE;
}

/*
 * Find the ULONG attribute in the list and check that the value length is
 * sizeof(CK_ULONG) and that it is non-empty.
 * Returns CKR_TEMPLATE_INCOMPLETE if the attribute is not found.
 * Returns CKR_ATTRIBUTE_VALUE_INVALID if the attribute value is empty or of
 * invalid size.
 */
CK_RV template_attribute_get_ulong(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
                                      CK_ULONG *value)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BBOOL found;

    found = template_attribute_find(tmpl, type, &attr);
    if (!found || attr == NULL)
        return CKR_TEMPLATE_INCOMPLETE;

    if (attr->ulValueLen != sizeof(CK_LONG) || attr->pValue == NULL) {
        TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID), type);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    *value = *(CK_ULONG *)attr->pValue;
    return CKR_OK;
}

/*
 * Find the BOOL attribute in the list and check that the value length is
 * sizeof(CK_ULONG) and that it is non-empty.
 * Returns CKR_TEMPLATE_INCOMPLETE if the attribute is not found.
 * Returns CKR_ATTRIBUTE_VALUE_INVALID if the attribute value is empty or of
 * invalid size.
 */
CK_RV template_attribute_get_bool(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
                                  CK_BBOOL *value)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BBOOL found;

    found = template_attribute_find(tmpl, type, &attr);
    if (!found || attr == NULL)
        return CKR_TEMPLATE_INCOMPLETE;

    if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
        TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID), type);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    *value = *(CK_BBOOL *)attr->pValue;
    return CKR_OK;
}

/*
 * Find the attribute in the list and check that the value length is > 0  and
 * that it is non-empty.
 * Returns CKR_TEMPLATE_INCOMPLETE if the attribute is not found.
 * Returns CKR_ATTRIBUTE_VALUE_INVALID if the attribute value is empty or of
 * invalid size.
 */
CK_RV template_attribute_get_non_empty(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
                                       CK_ATTRIBUTE **attr)
{
    CK_BBOOL found;

    found = template_attribute_find(tmpl, type, attr);
    if (!found || *attr == NULL) {
        *attr = NULL;
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if ((*attr)->ulValueLen == 0 || (*attr)->pValue == NULL) {
        *attr = NULL;
        TRACE_DEVEL("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID), type);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    return CKR_OK;
}

/* template_attribute_find_multiple()
 *
 * find the attributes in the list and return their values
 */
void template_attribute_find_multiple(TEMPLATE *tmpl,
                                      ATTRIBUTE_PARSE_LIST *parselist,
                                      CK_ULONG plcount)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG i;
    CK_RV rc;

    for (i = 0; i < plcount; i++) {
        parselist[i].found = template_attribute_find(tmpl,
                                                     parselist[i].type, &attr);

        if (parselist[i].found && parselist[i].ptr != NULL) {
            if (attr->ulValueLen <= parselist[i].len)
                parselist[i].len = attr->ulValueLen;
            if (attr->pValue != NULL) {
                if (is_attribute_attr_array(attr->type)) {
                    rc = dup_attribute_array_no_alloc(
                                    (CK_ATTRIBUTE_PTR)attr->pValue,
                                    attr->ulValueLen / sizeof(CK_ATTRIBUTE),
                                    (CK_ATTRIBUTE_PTR)parselist[i].ptr);
                    if (rc != CKR_OK) {
                        parselist[i].found = FALSE;
                        TRACE_DEVEL("dup_attribute_array_no_alloc failed\n");
                    }
                } else {
                    memcpy(parselist[i].ptr, attr->pValue, parselist[i].len);
                }
            }
        }
    }
}


/* template_check_required_attributes() */
CK_RV template_check_required_attributes(TEMPLATE *tmpl, CK_ULONG class,
                                         CK_ULONG subclass, CK_ULONG mode)
{
    if (class == CKO_DATA) {
        return data_object_check_required_attributes(tmpl, mode);
    } else if (class == CKO_CERTIFICATE) {
        if (subclass == CKC_X_509)
            return cert_x509_check_required_attributes(tmpl, mode);
        else
            return cert_vendor_check_required_attributes(tmpl, mode);
    } else if (class == CKO_PUBLIC_KEY) {
        switch (subclass) {
        case CKK_RSA:
            return rsa_publ_check_required_attributes(tmpl, mode);
        case CKK_DSA:
            return dsa_publ_check_required_attributes(tmpl, mode);
        case CKK_ECDSA:
            return ecdsa_publ_check_required_attributes(tmpl, mode);
        case CKK_DH:
            return dh_publ_check_required_attributes(tmpl, mode);
        case CKK_IBM_PQC_DILITHIUM:
            return ibm_dilithium_publ_check_required_attributes(tmpl, mode);
        case CKK_IBM_PQC_KYBER:
            return ibm_kyber_publ_check_required_attributes(tmpl, mode);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return CKR_ATTRIBUTE_VALUE_INVALID; // unknown keytype
        }
    } else if (class == CKO_PRIVATE_KEY) {
        switch (subclass) {
        case CKK_RSA:
            return rsa_priv_check_required_attributes(tmpl, mode);
        case CKK_DSA:
            return dsa_priv_check_required_attributes(tmpl, mode);
        case CKK_ECDSA:
            return ecdsa_priv_check_required_attributes(tmpl, mode);
        case CKK_DH:
            return dh_priv_check_required_attributes(tmpl, mode);
        case CKK_IBM_PQC_DILITHIUM:
            return ibm_dilithium_priv_check_required_attributes(tmpl, mode);
        case CKK_IBM_PQC_KYBER:
            return ibm_kyber_priv_check_required_attributes(tmpl, mode);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
        }
    } else if (class == CKO_SECRET_KEY) {
        switch (subclass) {
        case CKK_GENERIC_SECRET:
            return generic_secret_check_required_attributes(tmpl, mode);
        case CKK_DES:
            return des_check_required_attributes(tmpl, mode);
        case CKK_DES2:
            return des2_check_required_attributes(tmpl, mode);
        case CKK_DES3:
            return des3_check_required_attributes(tmpl, mode);
        case CKK_AES:
        case CKK_AES_XTS:
            return aes_check_required_attributes(tmpl, mode);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
        }
    } else if (class == CKO_HW_FEATURE) {
        if (subclass >= CKH_VENDOR_DEFINED)
            return CKR_OK;
        switch (subclass) {
        case CKH_CLOCK:
            return clock_check_required_attributes(tmpl, mode);
        case CKH_MONOTONIC_COUNTER:
            return counter_check_required_attributes(tmpl, mode);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    } else if (class == CKO_DOMAIN_PARAMETERS) {
        switch (subclass) {
        case CKK_DSA:
            return dp_dsa_check_required_attributes(tmpl, mode);
        case CKK_DH:
            return dp_dh_check_required_attributes(tmpl, mode);
        case CKK_X9_42_DH:
            return dp_x9dh_check_required_attributes(tmpl, mode);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    } else if (class == CKO_PROFILE) {
        return profile_object_check_required_attributes(tmpl, mode);
    }

    TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                class);

    return CKR_ATTRIBUTE_VALUE_INVALID; // default fallthru
}


/* template_check_required_base_attributes()
 *
 * check to make sure that attributes required by Cryptoki are
 * present.  does not check to see if the attribute makes sense
 * for the particular object (that is done in the 'validate' routines)
 */
CK_RV template_check_required_base_attributes(TEMPLATE *tmpl, CK_ULONG mode)
{
    CK_ULONG val;
    CK_RV rc;

    rc = template_attribute_get_ulong(tmpl, CKA_CLASS, &val);
    if (mode == MODE_CREATE && rc != CKR_OK)
        return CKR_TEMPLATE_INCOMPLETE;

    return CKR_OK;
}

/* template_compare() */
CK_BBOOL template_compare(CK_ATTRIBUTE *t1, CK_ULONG ulCount, TEMPLATE *t2)
{
    CK_ATTRIBUTE *attr1 = NULL;
    CK_ATTRIBUTE *attr2 = NULL;
    CK_ULONG i;
    CK_RV rc;

    if (!t1 || !t2)
        return FALSE;

    attr1 = t1;

    for (i = 0; i < ulCount; i++) {
        rc = template_attribute_find(t2, attr1->type, &attr2);
        if (rc == FALSE)
            return FALSE;

        if (!compare_attribute(attr1, attr2))
            return FALSE;

        attr1++;
    }

    return TRUE;
}


/* template_copy()
 *
 * This doesn't copy the template items verbatim.  The new template is in
 * the reverse order of the old one.  This should not have any effect.
 *
 * This is very similar to template_merge().  template_merge() can also
 * be used to copy a list (of unique attributes) but is slower because for
 * each attribute, it must search through the list.
 */
CK_RV template_copy(TEMPLATE *dest, TEMPLATE *src)
{
    char unique_id_str[2 * UNIQUE_ID_LEN + 1];
    DL_NODE *node, *list;
    CK_RV rc;

    if (!dest || !src) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    node = src->attribute_list;

    while (node) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) node->data;
        CK_ATTRIBUTE *new_attr = NULL;
        CK_ULONG len;

        len = sizeof(CK_ATTRIBUTE) + attr->ulValueLen;

        new_attr = (CK_ATTRIBUTE *) malloc(len);
        if (!new_attr) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }

        memcpy(new_attr, attr, len);
        if (new_attr->ulValueLen > 0)
            new_attr->pValue = (CK_BYTE *) new_attr + sizeof(CK_ATTRIBUTE);
        else
            new_attr->pValue = NULL;

        if (is_attribute_attr_array(new_attr->type) &&
            new_attr->ulValueLen > 0) {
            rc = dup_attribute_array_no_alloc((CK_ATTRIBUTE_PTR)attr->pValue,
                                    attr->ulValueLen / sizeof(CK_ATTRIBUTE),
                                    (CK_ATTRIBUTE_PTR)new_attr->pValue);
            if (rc != CKR_OK) {
                if (new_attr->pValue != NULL)
                    OPENSSL_cleanse(new_attr->pValue, new_attr->ulValueLen);
                free(new_attr);
                TRACE_ERROR("dup_attribute_array_no_alloc failed\n");
                return rc;
            }
         }

        if (attr->type == CKA_UNIQUE_ID) {
            if (attr->ulValueLen < 2 * UNIQUE_ID_LEN) {
                if (new_attr->pValue != NULL)
                    OPENSSL_cleanse(new_attr->pValue, new_attr->ulValueLen);
                free(new_attr);
                TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            if (get_unique_id_str(unique_id_str) != CKR_OK) {
                if (new_attr->pValue != NULL)
                    OPENSSL_cleanse(new_attr->pValue, new_attr->ulValueLen);
                free(new_attr);
                TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
                return CKR_FUNCTION_FAILED;
            }
            memcpy(new_attr->pValue, unique_id_str, 2 * UNIQUE_ID_LEN);
            new_attr->ulValueLen = 2 * UNIQUE_ID_LEN;
        }

        list = dlist_add_as_first(dest->attribute_list, new_attr);
        if (list == NULL) {
            if (is_attribute_attr_array(new_attr->type))
                cleanse_and_free_attribute_array2(
                                (CK_ATTRIBUTE_PTR)new_attr->pValue,
                                new_attr->ulValueLen / sizeof(CK_ATTRIBUTE),
                                FALSE);
            if (new_attr->pValue != NULL)
                OPENSSL_cleanse(new_attr->pValue, new_attr->ulValueLen);
            free(new_attr);
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }
        dest->attribute_list = list;
        node = node->next;
    }

    return CKR_OK;
}


static CK_BBOOL flatten_ulong_attribute_as_ulong32(CK_ATTRIBUTE_TYPE type)
{
    /*
     * Note: The attributes mentioned here are by far not all ULONG attribute
     * types. However, for backward compatibility, we need to keep the list as
     * is, since previous version of OCK has not flattened the other ULONG
     * attributes as 32 bit ULONG, but 'as-is', so we need to continue to do so
     * to not break backward compatibility.
     */
    switch (type) {
    case CKA_CLASS:
    case CKA_KEY_TYPE:
    case CKA_MODULUS_BITS:
    case CKA_VALUE_BITS:
    case CKA_CERTIFICATE_TYPE:
    case CKA_VALUE_LEN:
        return TRUE;
    default:
        return FALSE;
    }
}

static CK_RV attribute_array_flatten(CK_ATTRIBUTE_PTR array_attr,
                                     CK_BYTE **dest)
{
    CK_ULONG_32 long_len = sizeof(CK_ULONG);
    CK_ATTRIBUTE_32 attr_32, element_32;
    CK_ULONG_32 Val_32;
    CK_ATTRIBUTE attr;
    CK_BYTE *ptr = *dest;
    CK_ATTRIBUTE_PTR attrs;
    CK_ULONG num_attrs, i;
    CK_RV rc;

    if (!is_attribute_attr_array(array_attr->type))
        return CKR_ATTRIBUTE_TYPE_INVALID;

    attrs = (CK_ATTRIBUTE_PTR)array_attr->pValue;
    num_attrs = array_attr->ulValueLen / sizeof(CK_ATTRIBUTE);

    if (long_len == 4) {
        attr.type = array_attr->type;
        attr.ulValueLen = 0;
        attr.pValue = NULL;
        for (i = 0; i < num_attrs; i++)
            attr.ulValueLen += attribute_get_compressed_size(&attrs[i]);

        memcpy(ptr, &attr, sizeof(CK_ATTRIBUTE));
        ptr += sizeof(CK_ATTRIBUTE);

        for (i = 0; i < num_attrs; i++) {
            if(is_attribute_attr_array(attrs[i].type)) {
                rc = attribute_array_flatten(&attrs[i], &ptr);
                if (rc != CKR_OK) {
                    TRACE_ERROR("attribute_array_flatten failed\n");
                    return rc;
                }
            } else {
                memcpy(ptr, &attrs[i],
                       sizeof(CK_ATTRIBUTE) + attrs[i].ulValueLen);
                ptr += sizeof(CK_ATTRIBUTE) + attrs[i].ulValueLen;
            }
        }
    } else {
        attr_32.type = array_attr->type;
        attr_32.pValue = 0x00;
        attr_32.ulValueLen = 0;
        for (i = 0; i < num_attrs; i++)
            attr_32.ulValueLen += attribute_get_compressed_size(&attrs[i]);
        memcpy(ptr, &attr_32, sizeof(CK_ATTRIBUTE_32));
        ptr += sizeof(CK_ATTRIBUTE_32);
        for (i = 0; i < num_attrs; i++) {
            if(is_attribute_attr_array(attrs[i].type)) {
                rc = attribute_array_flatten(&attrs[i], &ptr);
                if (rc != CKR_OK) {
                    TRACE_ERROR("attribute_array_flatten failed\n");
                    return rc;
                }
            } else {
                element_32.type = attrs[i].type;
                element_32.pValue = 0x00;

                if (flatten_ulong_attribute_as_ulong32(attrs[i].type) &&
                    attrs[i].ulValueLen != 0) {
                    element_32.ulValueLen = sizeof(CK_ULONG_32);

                    memcpy(ptr, &element_32, sizeof(CK_ATTRIBUTE_32));
                    ptr += sizeof(CK_ATTRIBUTE_32);

                    Val_32 = (CK_ULONG_32) *((CK_ULONG *) attrs[i].pValue);
                    memcpy(ptr, &Val_32, sizeof(CK_ULONG_32));
                    ptr += sizeof(CK_ULONG_32);
                } else {
                    element_32.ulValueLen = attrs[i].ulValueLen;
                    memcpy(ptr, &element_32, sizeof(CK_ATTRIBUTE_32));
                    ptr += sizeof(CK_ATTRIBUTE_32);

                    if (attrs[i].ulValueLen != 0) {
                        memcpy(ptr, attrs[i].pValue, attrs[i].ulValueLen);
                        ptr += attrs[i].ulValueLen;
                    }
                }
            }
        }
    }

    *dest = ptr;

    return CKR_OK;
}

/* template_flatten()
 * this still gets used when saving token objects to disk
 */
CK_RV template_flatten(TEMPLATE *tmpl, CK_BYTE *dest)
{
    DL_NODE *node = NULL;
    CK_BYTE *ptr = NULL;
    CK_ULONG_32 long_len = sizeof(CK_ULONG);
    CK_ATTRIBUTE_32 attr_32;
    CK_ULONG_32 Val_32;
    CK_RV rc;

    if (!tmpl || !dest) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    ptr = dest;
    node = tmpl->attribute_list;
    while (node) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) node->data;

        if (is_attribute_attr_array(attr->type)) {
            rc = attribute_array_flatten(attr, &ptr);
            if (rc != CKR_OK) {
                TRACE_ERROR("attribute_array_flatten failed\n");
                return rc;
            }

            node = node->next;
            continue;
        }

        if (long_len == 4) {
            memcpy(ptr, attr, sizeof(CK_ATTRIBUTE) + attr->ulValueLen);
            ptr += sizeof(CK_ATTRIBUTE) + attr->ulValueLen;
        } else {
            attr_32.type = attr->type;
            attr_32.pValue = 0x00;
            if (flatten_ulong_attribute_as_ulong32(attr->type) &&
                attr->ulValueLen != 0) {

                attr_32.ulValueLen = sizeof(CK_ULONG_32);

                memcpy(ptr, &attr_32, sizeof(CK_ATTRIBUTE_32));
                ptr += sizeof(CK_ATTRIBUTE_32);

                Val_32 = (CK_ULONG_32) *((CK_ULONG *) attr->pValue);
                memcpy(ptr, &Val_32, sizeof(CK_ULONG_32));
                ptr += sizeof(CK_ULONG_32);
            } else {
                attr_32.ulValueLen = attr->ulValueLen;
                memcpy(ptr, &attr_32, sizeof(CK_ATTRIBUTE_32));
                ptr += sizeof(CK_ATTRIBUTE_32);
                if (attr->ulValueLen != 0) {
                    memcpy(ptr, attr->pValue, attr->ulValueLen);
                    ptr += attr->ulValueLen;
                }
            }
        }

        node = node->next;
    }

    return CKR_OK;
}

static CK_RV attribute_array_unflatten(CK_BYTE **buf, CK_ATTRIBUTE_PTR *attrs,
                                       CK_ULONG *num_attrs)
{
    CK_ULONG_32 long_len = sizeof(CK_ULONG);
    CK_ATTRIBUTE *a1 = NULL, *a2 = NULL;
    CK_ATTRIBUTE_32 a1_32, a2_32;
    CK_BYTE *ptr = *buf;
    CK_ULONG ofs = 0, num_elements = 0;
    CK_ATTRIBUTE_PTR elements = NULL;
    CK_ULONG_32 attr_ulong_32;
    CK_ULONG attr_ulong;
    CK_RV rc;

    *attrs = NULL;
    *num_attrs = 0;

    if (long_len == 4) {
        a1 = (CK_ATTRIBUTE *)ptr;
        ptr += sizeof(CK_ATTRIBUTE);

        if (!is_attribute_attr_array(a1->type))
            return CKR_ATTRIBUTE_TYPE_INVALID;

        while(ofs < a1->ulValueLen) {
            a2 = (CK_ATTRIBUTE *)ptr;

            if (is_attribute_attr_array(a2->type)) {
                rc = attribute_array_unflatten(&ptr, &elements, &num_elements);
                if (rc != CKR_OK) {
                    TRACE_ERROR("attribute_array_unflatten failed\n");
                    goto error;
                }

                rc = add_to_attribute_array(attrs, num_attrs, a2->type,
                                            (CK_BYTE *)elements, num_elements *
                                                        sizeof(CK_ATTRIBUTE));
                if (rc != CKR_OK) {
                    TRACE_ERROR("attribute_array_unflatten failed\n");
                    goto error;
                }

                cleanse_and_free_attribute_array(elements, num_elements);
                elements = NULL;
                num_elements = 0;
            } else {
                rc = add_to_attribute_array(attrs, num_attrs, a2->type,
                                       ptr + sizeof(CK_ATTRIBUTE),
                                       a2->ulValueLen);
                if (rc != CKR_OK) {
                    TRACE_ERROR("attribute_array_unflatten failed\n");
                    goto error;
                }

                ptr += sizeof(CK_ATTRIBUTE) + a2->ulValueLen;
            }

            ofs += sizeof(CK_ATTRIBUTE) + a2->ulValueLen;
        }
    } else {
        memcpy(&a1_32, ptr, sizeof(a1_32));
        ptr += sizeof(CK_ATTRIBUTE_32);

        if (!is_attribute_attr_array(a1_32.type))
            return CKR_ATTRIBUTE_TYPE_INVALID;

        while(ofs < a1_32.ulValueLen) {
            memcpy(&a2_32, ptr, sizeof(a2_32));

            if (is_attribute_attr_array(a2_32.type)) {
                rc = attribute_array_unflatten(&ptr, &elements, &num_elements);
                if (rc != CKR_OK) {
                    TRACE_ERROR("attribute_array_unflatten failed\n");
                    goto error;
                }

                rc = add_to_attribute_array(attrs, num_attrs, a2_32.type,
                                            (CK_BYTE *)elements, num_elements *
                                                        sizeof(CK_ATTRIBUTE));
                if (rc != CKR_OK) {
                    TRACE_ERROR("attribute_array_unflatten failed\n");
                    goto error;
                }

                cleanse_and_free_attribute_array(elements, num_elements);
                elements = NULL;
                num_elements = 0;
            } else {
                if (flatten_ulong_attribute_as_ulong32(a2_32.type) &&
                    a2_32.ulValueLen > 0) {
                    memcpy(&attr_ulong_32, ptr + sizeof(CK_ATTRIBUTE_32),
                                           sizeof(attr_ulong_32));
                    attr_ulong = attr_ulong_32;
                    rc = add_to_attribute_array(attrs, num_attrs, a2_32.type,
                                                (CK_BYTE *)&attr_ulong,
                                                sizeof(attr_ulong));
                } else {
                    rc = add_to_attribute_array(attrs, num_attrs, a2_32.type,
                                                ptr + sizeof(CK_ATTRIBUTE_32),
                                                a2_32.ulValueLen);
                }
                if (rc != CKR_OK) {
                    TRACE_ERROR("attribute_array_unflatten failed\n");
                    goto error;
                }

                ptr += sizeof(CK_ATTRIBUTE_32) + a2_32.ulValueLen;
            }

            ofs += sizeof(CK_ATTRIBUTE_32) + a2_32.ulValueLen;
        }
    }

    *buf = ptr;

    return CKR_OK;

error:
    cleanse_and_free_attribute_array(*attrs, *num_attrs);
    *attrs = NULL;
    *num_attrs = 0;
    cleanse_and_free_attribute_array(elements, num_elements);

    return rc;
}

CK_RV template_unflatten(TEMPLATE **new_tmpl, CK_BYTE *buf, CK_ULONG count)
{
    return template_unflatten_withSize(new_tmpl, buf, count, -1);
}

/* Modified version of template_unflatten that checks
 * that buf isn't overread.  buf_size=-1 turns off checking
 * (for backwards compatability)
 */
CK_RV template_unflatten_withSize(TEMPLATE **new_tmpl, CK_BYTE *buf,
                                  CK_ULONG count, int buf_size)
{
    TEMPLATE *tmpl = NULL;
    CK_ATTRIBUTE *a2 = NULL;
    CK_BYTE *ptr = NULL;
    CK_ULONG i, len;
    CK_RV rc;
    CK_ULONG_32 long_len = sizeof(CK_ULONG);
    CK_ULONG_32 attr_ulong_32;
    CK_ULONG attr_ulong;
    CK_ATTRIBUTE *a1 = NULL;
    CK_ATTRIBUTE_32 a1_32;
    CK_ATTRIBUTE_PTR attrs = NULL;
    CK_ULONG num_attrs = 0;

    if (!new_tmpl) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    tmpl = (TEMPLATE *) malloc(sizeof(TEMPLATE));
    if (!tmpl) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    memset(tmpl, 0x0, sizeof(TEMPLATE));

    ptr = buf;
    for (i = 0; i < count; i++) {
        if (long_len == 4) {
            if (buf_size >= 0 &&
                ((ptr + sizeof(CK_ATTRIBUTE)) > (buf + buf_size))) {
                template_free(tmpl);
                return CKR_FUNCTION_FAILED;
            }

            a1 = (CK_ATTRIBUTE *) ptr;

            if (is_attribute_attr_array(a1->type)) {
                if (buf_size >= 0 &&
                    (ptr + sizeof(CK_ATTRIBUTE) + a1->ulValueLen ) >
                                                     (buf + buf_size)) {
                    template_free(tmpl);
                    return CKR_FUNCTION_FAILED;
                }
                rc = attribute_array_unflatten(&ptr, &attrs, &num_attrs);
                if (rc != CKR_OK) {
                    TRACE_ERROR("attribute_array_unflatten failed\n");
                    template_free(tmpl);
                    return rc;
                }

                len = sizeof(CK_ATTRIBUTE) + num_attrs * sizeof(CK_ATTRIBUTE);
                a2 = (CK_ATTRIBUTE *) malloc(len);
                if (!a2) {
                    template_free(tmpl);
                    cleanse_and_free_attribute_array(attrs, num_attrs);
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    return CKR_HOST_MEMORY;
                }

                a2->type = a1->type;
                a2->ulValueLen = num_attrs * sizeof(CK_ATTRIBUTE);

                if (a2->ulValueLen > 0) {
                    a2->pValue = ((CK_BYTE *)a2) + sizeof(CK_ATTRIBUTE);
                    memcpy(a2->pValue, attrs, a2->ulValueLen);
                } else {
                    a2->pValue = NULL;
                }

                free(attrs); /* Array elements were copied, don't free them! */
                goto add_it;
            }

            len = sizeof(CK_ATTRIBUTE) + a1->ulValueLen;
            a2 = (CK_ATTRIBUTE *) malloc(len);
            if (!a2) {
                template_free(tmpl);
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                return CKR_HOST_MEMORY;
            }

            /* if a buffer size is given, make sure it
             * doesn't get overrun
             */
            if (buf_size >= 0 &&
                (((unsigned char *) a1 + len)
                 > ((unsigned char *) buf + buf_size))) {
                free(a2);
                template_free(tmpl);
                return CKR_FUNCTION_FAILED;
            }
            memcpy(a2, a1, len);

            if (a2->ulValueLen > 0)
                a2->pValue = ((CK_BYTE *)a2) + sizeof(CK_ATTRIBUTE);
            else
                a2->pValue = NULL;

            ptr += len;
        } else {
            if (buf_size >= 0 &&
                ((ptr + sizeof(CK_ATTRIBUTE_32)) > (buf + buf_size))) {
                template_free(tmpl);
                return CKR_FUNCTION_FAILED;
            }

            memcpy(&a1_32, ptr, sizeof(a1_32));

            if (is_attribute_attr_array(a1_32.type)) {
                if (buf_size >= 0 &&
                    (ptr + sizeof(CK_ATTRIBUTE_32) + a1_32.ulValueLen ) >
                                                     (buf + buf_size)) {
                    template_free(tmpl);
                    return CKR_FUNCTION_FAILED;
                }
                rc = attribute_array_unflatten(&ptr, &attrs, &num_attrs);
                if (rc != CKR_OK) {
                    TRACE_ERROR("attribute_array_unflatten failed\n");
                    template_free(tmpl);
                    return rc;
                }

                len = sizeof(CK_ATTRIBUTE) + num_attrs * sizeof(CK_ATTRIBUTE);
                a2 = (CK_ATTRIBUTE *) malloc(len);
                if (!a2) {
                    template_free(tmpl);
                    cleanse_and_free_attribute_array(attrs, num_attrs);
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    return CKR_HOST_MEMORY;
                }

                a2->type = a1_32.type;
                a2->ulValueLen = num_attrs * sizeof(CK_ATTRIBUTE);
                if (a2->ulValueLen > 0) {
                    a2->pValue = ((CK_BYTE *)a2) + sizeof(CK_ATTRIBUTE);
                    memcpy(a2->pValue, attrs, a2->ulValueLen);
                } else {
                    a2->pValue = NULL;
                }

                free(attrs); /* Array elements were copied, don't free them! */
                goto add_it;
            }

            if (flatten_ulong_attribute_as_ulong32(a1_32.type)
                && a1_32.ulValueLen != 0) {
                len = sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG);
            } else {
                len = sizeof(CK_ATTRIBUTE) + a1_32.ulValueLen;
            }

            a2 = (CK_ATTRIBUTE *) malloc(len);
            if (!a2) {
                template_free(tmpl);
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                return CKR_HOST_MEMORY;
            }
            a2->type = a1_32.type;
            a2->ulValueLen = 0;

            if (a1_32.ulValueLen != 0)
                a2->pValue = (CK_BYTE *)a2 + sizeof(CK_ATTRIBUTE);
            else
                a2->pValue = NULL;

            if (flatten_ulong_attribute_as_ulong32(a1_32.type)
                && a1_32.ulValueLen != 0) {

                a2->ulValueLen = sizeof(CK_ULONG);

                memcpy(&attr_ulong_32, ptr + sizeof(CK_ATTRIBUTE_32),
                       sizeof(attr_ulong_32));
                attr_ulong = attr_ulong_32;

                memcpy(a2->pValue, (CK_BYTE *)&attr_ulong, sizeof(CK_ULONG));
            } else if (a1_32.ulValueLen != 0) {
                a2->ulValueLen = a1_32.ulValueLen;
                /* if a buffer size is given, make sure it
                 * doesn't get overrun
                 */
                if (buf_size >= 0 &&
                    (ptr + sizeof(CK_ATTRIBUTE_32) + a1_32.ulValueLen) >
                                                            (buf + buf_size)) {
                    free(a2);
                    template_free(tmpl);
                    return CKR_FUNCTION_FAILED;
                }
                memcpy(a2->pValue, ptr + sizeof(CK_ATTRIBUTE_32),
                       a1_32.ulValueLen);
            }

            ptr += sizeof(CK_ATTRIBUTE_32) + a1_32.ulValueLen;
        }

add_it:
        rc = template_update_attribute(tmpl, a2);
        if (rc != CKR_OK) {
            if (is_attribute_attr_array(a2->type))
                cleanse_and_free_attribute_array2((CK_ATTRIBUTE_PTR)a2->pValue,
                                    a2->ulValueLen / sizeof(CK_ATTRIBUTE),
                                    FALSE);
            free(a2);
            template_free(tmpl);
            return rc;
        }
    }

    *new_tmpl = tmpl;

    return CKR_OK;
}


/* template_free() */
CK_RV template_free(TEMPLATE *tmpl)
{
    if (!tmpl)
        return CKR_OK;

    while (tmpl->attribute_list) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) tmpl->attribute_list->data;

        if (attr) {
            if (is_attribute_attr_array(attr->type)) {
                cleanse_and_free_attribute_array2(
                                    (CK_ATTRIBUTE_PTR)attr->pValue,
                                    attr->ulValueLen / sizeof(CK_ATTRIBUTE),
                                    FALSE);
            }
            if (attr->pValue != NULL)
                OPENSSL_cleanse(attr->pValue, attr->ulValueLen);
            free(attr);
        }

        tmpl->attribute_list = dlist_remove_node(tmpl->attribute_list,
                                                 tmpl->attribute_list);
    }

    free(tmpl);

    return CKR_OK;
}

/* template_get_class */
CK_BBOOL template_get_class(TEMPLATE *tmpl, CK_ULONG *class,
                            CK_ULONG *subclass)
{
    DL_NODE *node;
    CK_BBOOL found = FALSE;

    if (!tmpl || !class || !subclass)
        return FALSE;

    node = tmpl->attribute_list;

    /* have to iterate through all attributes. no early exits */
    while (node) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) node->data;

        if (attr->type == CKA_CLASS &&
            attr->ulValueLen == sizeof(CK_OBJECT_CLASS) &&
            attr->pValue != NULL) {
            *class = *(CK_OBJECT_CLASS *) attr->pValue;
            found = TRUE;
        }

        /* underneath, these guys are both CK_ULONG so we
         * could combine this
         */
        if (attr->type == CKA_CERTIFICATE_TYPE &&
            attr->ulValueLen == sizeof(CK_CERTIFICATE_TYPE) &&
            attr->pValue != NULL)
            *subclass = *(CK_CERTIFICATE_TYPE *) attr->pValue;

        if (attr->type == CKA_KEY_TYPE &&
            attr->ulValueLen == sizeof(CK_KEY_TYPE) &&
            attr->pValue != NULL)
            *subclass = *(CK_KEY_TYPE *) attr->pValue;

        if (attr->type == CKA_HW_FEATURE_TYPE &&
            attr->ulValueLen == sizeof(CK_HW_FEATURE_TYPE) &&
            attr->pValue != NULL)
            *subclass = *(CK_HW_FEATURE_TYPE *) attr->pValue;

        node = node->next;
    }

    return found;
}

CK_ULONG template_get_count(TEMPLATE *tmpl)
{
    if (tmpl == NULL)
        return 0;

    return dlist_length(tmpl->attribute_list);
}

CK_ULONG template_get_size(TEMPLATE *tmpl)
{
    DL_NODE *node;
    CK_ULONG size = 0, i, num_attrs;
    CK_ATTRIBUTE_PTR attrs;

    if (tmpl == NULL)
        return 0;

    node = tmpl->attribute_list;
    while (node) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) node->data;

        size += sizeof(CK_ATTRIBUTE) + attr->ulValueLen;

        if (is_attribute_attr_array(attr->type)) {
            num_attrs = attr->ulValueLen / sizeof(CK_ATTRIBUTE);
            attrs = (CK_ATTRIBUTE_PTR)attr->pValue;
            for (i = 0; i< num_attrs; i++)
                size += sizeof(CK_ATTRIBUTE) + attrs[i].ulValueLen;
        }

        node = node->next;
    }

    return size;
}

static CK_ULONG attribute_get_compressed_size(CK_ATTRIBUTE_PTR attr)
{
    CK_ULONG size = 0, i, num_attrs;
    CK_ATTRIBUTE_PTR attrs;

    size += sizeof(CK_ATTRIBUTE_32);
    if (flatten_ulong_attribute_as_ulong32(attr->type)
        && attr->ulValueLen != 0) {
        size += sizeof(CK_ULONG_32);
    } else if (is_attribute_attr_array(attr->type)) {
        num_attrs = attr->ulValueLen / sizeof(CK_ATTRIBUTE);
        attrs = (CK_ATTRIBUTE_PTR)attr->pValue;
        for (i = 0; i< num_attrs; i++)
            size += attribute_get_compressed_size(&attrs[i]);
    } else {
        size += attr->ulValueLen;
    }

    return size;
}

CK_ULONG template_get_compressed_size(TEMPLATE *tmpl)
{
    DL_NODE *node;
    CK_ULONG size = 0;

    if (tmpl == NULL)
        return 0;
    node = tmpl->attribute_list;
    while (node) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) node->data;

        size += attribute_get_compressed_size(attr);

        node = node->next;
    }

    return size;
}

/* template_is_okay_to_reveal_attribute()
 *
 * determines whether the specified CK_ATTRIBUTE_TYPE is allowed to
 * be leave the card in the clear.  note: the specified template doesn't need
 * to actually posess an attribute of type 'type'.  The template is
 * provided mainly to determine the object class and subclass
 *
 * this routine is called by C_GetAttributeValue which exports the attributes
 * in the clear.  this routine is NOT called when wrapping a key.
 */
CK_BBOOL template_check_exportability(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type)
{
    CK_ULONG class = 0;
    CK_ULONG subclass = 0;
    CK_BBOOL sensitive_val;
    CK_BBOOL extractable_val;

    if (!tmpl)
        return FALSE;

    /*
     * Early exit: A protected key shall not be exported. Otherwise an application
     * could use the protected key outside of this environment and separately
     * from the secure key object.
     */
    if (type == CKA_IBM_OPAQUE_PKEY)
        return FALSE;

    /* since 'tmpl' belongs to a validated object, it's safe
     * to assume that the following routine works
     */
    template_get_class(tmpl, &class, &subclass);

    /* Early exits:
     * 1) CKA_SENSITIVE and CKA_EXTRACTABLE only apply to private key
     * and secret key objects.  If object type is any other, then
     * by default the attribute is exportable.
     *
     * 2) If CKA_SENSITIVE = FALSE  and CKA_EXTRACTABLE = TRUE then
     * all attributes are exportable
     */
    if (class != CKO_PRIVATE_KEY && class != CKO_SECRET_KEY)
        return TRUE;

    if (template_attribute_get_bool(tmpl, CKA_SENSITIVE,
                                    &sensitive_val) != CKR_OK)
        return FALSE;
    if (template_attribute_get_bool(tmpl, CKA_EXTRACTABLE,
                                    &extractable_val) != CKR_OK)
        return FALSE;
    if (sensitive_val == FALSE && extractable_val == TRUE)
        return TRUE;

    /* at this point, we know the object must have CKA_SENSITIVE = TRUE
     * or CKA_EXTRACTABLE = FALSE (or both).
     * need to determine whether the particular attribute in question is
     * a "sensitive" attribute.
     */

    if (class == CKO_PRIVATE_KEY) {
        switch (subclass) {
        case CKK_RSA:
            return rsa_priv_check_exportability(type);
        case CKK_DSA:
            return dsa_priv_check_exportability(type);
        case CKK_ECDSA:
            return ecdsa_priv_check_exportability(type);
        case CKK_X9_42_DH:
        case CKK_DH:
            return dh_priv_check_exportability(type);
        case CKK_IBM_DILITHIUM:
            return ibm_dilithium_priv_check_exportability(type);
        case CKK_IBM_KYBER:
            return ibm_kyber_priv_check_exportability(type);
        default:
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                        subclass);
            return TRUE;
        }
    } else if (class == CKO_SECRET_KEY) {
        return secret_key_check_exportability(type);
    }

    TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID),
                class);

    return TRUE;
}

/*  template_merge()
 *
 * Merge two templates together:  dest = dest U src
 *
 * src is destroyed in the process
 */
CK_RV template_merge(TEMPLATE *dest, TEMPLATE **src)
{
    DL_NODE *node;
    CK_RV rc;

    if (!dest || !src) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    node = (*src)->attribute_list;

    while (node) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) node->data;

        rc = template_update_attribute(dest, attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_update_attribute failed.\n");
            return rc;
        }
        /* we've assigned the node's data to a node in 'dest' */
        node->data = NULL;
        node = node->next;
    }

    template_free(*src);
    *src = NULL;

    return CKR_OK;
}

/* template_set_default_common_attributes()
 *
 * Set the default attributes common to all objects:
 *
 * CKA_TOKEN: FALSE
 * CKA_PRIVATE: TRUE -- Cryptoki leaves this up to the token to decide
 * CKA_MODIFIABLE: TRUE
 * CKA_LABEL: empty string
 */
CK_RV template_set_default_common_attributes(TEMPLATE *tmpl)
{
    char unique_id_str[2 * UNIQUE_ID_LEN + 1];
    CK_ATTRIBUTE *token_attr;
    CK_ATTRIBUTE *priv_attr;
    CK_ATTRIBUTE *mod_attr;
    CK_ATTRIBUTE *label_attr;
    CK_ATTRIBUTE *unique_id_attr;
    CK_ATTRIBUTE *copy_attr;
    CK_ATTRIBUTE *destr_attr;
    CK_RV rc;

    if (get_unique_id_str(unique_id_str) != CKR_OK)
        return CKR_FUNCTION_FAILED;

    /* add the default common attributes */
    token_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE)
                                         + sizeof(CK_BBOOL));
    priv_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE)
                                        + sizeof(CK_BBOOL));
    mod_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE)
                                       + sizeof(CK_BBOOL));
    label_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + 0);
    unique_id_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + UNIQUE_ID_LEN * 2);
    copy_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE)
                                       + sizeof(CK_BBOOL));
    destr_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE)
                                       + sizeof(CK_BBOOL));

    if (!token_attr || !priv_attr || !mod_attr || !label_attr ||
        !unique_id_attr || !copy_attr || !destr_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    token_attr->type = CKA_TOKEN;
    token_attr->ulValueLen = sizeof(CK_BBOOL);
    token_attr->pValue = (CK_BYTE *) token_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) token_attr->pValue = FALSE;

    priv_attr->type = CKA_PRIVATE;
    priv_attr->ulValueLen = sizeof(CK_BBOOL);
    priv_attr->pValue = (CK_BYTE *) priv_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) priv_attr->pValue = FALSE;

    mod_attr->type = CKA_MODIFIABLE;
    mod_attr->ulValueLen = sizeof(CK_BBOOL);
    mod_attr->pValue = (CK_BYTE *) mod_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) mod_attr->pValue = TRUE;

    label_attr->type = CKA_LABEL;
    label_attr->ulValueLen = 0; // empty string
    label_attr->pValue = NULL;

    unique_id_attr->type = CKA_UNIQUE_ID;
    unique_id_attr->ulValueLen = UNIQUE_ID_LEN * 2;
    unique_id_attr->pValue = (CK_BYTE *) unique_id_attr + sizeof(CK_ATTRIBUTE);
    memcpy(unique_id_attr->pValue, unique_id_str, UNIQUE_ID_LEN * 2);

    copy_attr->type = CKA_COPYABLE;
    copy_attr->ulValueLen = sizeof(CK_BBOOL);
    copy_attr->pValue = (CK_BYTE *) copy_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) copy_attr->pValue = TRUE;

    destr_attr->type = CKA_DESTROYABLE;
    destr_attr->ulValueLen = sizeof(CK_BBOOL);
    destr_attr->pValue = (CK_BYTE *) destr_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) destr_attr->pValue = TRUE;

    rc = template_update_attribute(tmpl, token_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    token_attr = NULL;
    rc = template_update_attribute(tmpl, priv_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    priv_attr = NULL;
    rc = template_update_attribute(tmpl, mod_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    mod_attr = NULL;
    rc = template_update_attribute(tmpl, label_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    label_attr = NULL;
    rc = template_update_attribute(tmpl, unique_id_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    unique_id_attr = NULL;
    rc = template_update_attribute(tmpl, copy_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    copy_attr = NULL;
    rc = template_update_attribute(tmpl, destr_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    destr_attr = NULL;

    /* the TEMPLATE 'owns' the attributes now.
     * it is responsible for freeing them upon deletion...
     */
    return CKR_OK;

error:
    if (token_attr)
        free(token_attr);
    if (priv_attr)
        free(priv_attr);
    if (mod_attr)
        free(mod_attr);
    if (label_attr)
        free(label_attr);
    if (unique_id_attr)
        free(unique_id_attr);
    if (copy_attr)
        free(copy_attr);
    if (destr_attr)
        free(destr_attr);

    return rc;
}

/* template_remove_attribute()
 *
 * removes an attribute (if existing) from the template.
 *
 * Returns:  CKR_OK on success, other CKR error on failure
 */
CK_RV template_remove_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type)
{
    DL_NODE *node = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BBOOL found = FALSE;

    if (!tmpl) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_ARGUMENTS_BAD;
    }
    node = tmpl->attribute_list;

    while (node != NULL) {
        attr = (CK_ATTRIBUTE *) node->data;

        if (type == attr->type) {
            found = TRUE;
            if (is_attribute_attr_array(attr->type)) {
                 cleanse_and_free_attribute_array2(
                                     (CK_ATTRIBUTE_PTR)attr->pValue,
                                     attr->ulValueLen / sizeof(CK_ATTRIBUTE),
                                     FALSE);
            }
            if (attr->pValue != NULL)
                OPENSSL_cleanse(attr->pValue, attr->ulValueLen);
            free(attr);
            tmpl->attribute_list =
                dlist_remove_node(tmpl->attribute_list, node);
            break;
        }

        node = node->next;
    }

    return found ? CKR_OK : CKR_ATTRIBUTE_TYPE_INVALID;
}

/* template_update_attribute()
 *
 * modifies an existing attribute or adds a new attribute to the template
 *
 * Returns:  CKR_OK on success, other CKR error on failure
 */
CK_RV template_update_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *new_attr)
{
    DL_NODE *list;
    CK_RV rc;

    if (!tmpl || !new_attr) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_ARGUMENTS_BAD;
    }

    /* if the attribute already exists in the list, remove it.
     * this algorithm will limit an attribute to appearing at most
     * once in the list
     */
    rc = template_remove_attribute(tmpl, new_attr->type);
    if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID)
        return rc;

    /* add the new attribute */
    list = dlist_add_as_first(tmpl->attribute_list, new_attr);
    if (list == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    tmpl->attribute_list = list;
    return CKR_OK;
}

/* template_validate_attribute()
 *
 * essentially a group of if-then-else-switch clauses.  separated from
 * template_validate_attributes() to make that routine more readable
 */
CK_RV template_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG class,
                                  CK_ULONG subclass, CK_ULONG mode)
{
    if (attr->ulValueLen > 0 && attr->pValue == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    if (class == CKO_DATA) {
        return data_object_validate_attribute(tmpl, attr, mode);
    } else if (class == CKO_CERTIFICATE) {
        if (subclass == CKC_X_509)
            return cert_x509_validate_attribute(tokdata, tmpl, attr, mode);
        else
            return cert_vendor_validate_attribute(tokdata, tmpl, attr, mode);
    } else if (class == CKO_PUBLIC_KEY) {
        switch (subclass) {
        case CKK_RSA:
            return rsa_publ_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_DSA:
            return dsa_publ_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_ECDSA:
            return ecdsa_publ_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_DH:
            return dh_publ_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_IBM_PQC_DILITHIUM:
            return ibm_dilithium_publ_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_IBM_PQC_KYBER:
            return ibm_kyber_publ_validate_attribute(tokdata, tmpl, attr, mode);
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
        }
    } else if (class == CKO_PRIVATE_KEY) {
        switch (subclass) {
        case CKK_RSA:
            return rsa_priv_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_DSA:
            return dsa_priv_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_ECDSA:
            return ecdsa_priv_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_DH:
            return dh_priv_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_IBM_PQC_DILITHIUM:
            return ibm_dilithium_priv_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_IBM_PQC_KYBER:
            return ibm_kyber_priv_validate_attribute(tokdata, tmpl, attr, mode);
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
        }
    } else if (class == CKO_SECRET_KEY) {
        switch (subclass) {
        case CKK_GENERIC_SECRET:
            return generic_secret_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_DES:
            return des_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_DES2:
            return des2_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_DES3:
            return des3_validate_attribute(tokdata, tmpl, attr, mode);
        case CKK_AES:
            return aes_validate_attribute(tokdata, tmpl, attr, mode, FALSE);
        case CKK_AES_XTS:
            return aes_validate_attribute(tokdata, tmpl, attr, mode, TRUE);
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID; // unknown key type
        }
    } else if (class == CKO_HW_FEATURE) {
        if (subclass >= CKH_VENDOR_DEFINED)
            return CKR_OK;
        switch (subclass) {
        case CKH_CLOCK:
            return clock_validate_attribute(tmpl, attr, mode);
        case CKH_MONOTONIC_COUNTER:
            return counter_validate_attribute(tmpl, attr, mode);
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    } else if (class == CKO_DOMAIN_PARAMETERS) {
        switch (subclass) {
        case CKK_DSA:
            return dp_dsa_validate_attribute(tmpl, attr, mode);
        case CKK_DH:
            return dp_dh_validate_attribute(tmpl, attr, mode);
        case CKK_X9_42_DH:
            return dp_x9dh_validate_attribute(tmpl, attr, mode);
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
    } else if (class == CKO_PROFILE) {
        return profile_object_validate_attribute(tmpl, attr, mode);
    }

    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));

    return CKR_ATTRIBUTE_VALUE_INVALID; // default fallthru
}


/* template_validate_attributes()
 *
 * walk through the list of attributes in the template validating each one
 */
CK_RV template_validate_attributes(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                   CK_ULONG class, CK_ULONG subclass,
                                   CK_ULONG mode)
{
    DL_NODE *node;
    CK_RV rc = CKR_OK;

    node = tmpl->attribute_list;

    while (node) {
        CK_ATTRIBUTE *attr = (CK_ATTRIBUTE *) node->data;

        rc = template_validate_attribute(tokdata, tmpl, attr, class,
                                         subclass, mode);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_validate_attribute failed.\n");
            return rc;
        }
        node = node->next;
    }

    return CKR_OK;
}


/* template_validate_base_attribute() */
CK_RV template_validate_base_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                       CK_ULONG mode)
{
    if (!tmpl || !attr) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    switch (attr->type) {
    case CKA_CLASS:
        if (attr->ulValueLen != sizeof(CK_OBJECT_CLASS) ||
            attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if ((mode & (MODE_CREATE | MODE_DERIVE | MODE_KEYGEN | MODE_UNWRAP)) !=
            0)
            return CKR_OK;
        break;
    case CKA_TOKEN:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if ((mode & (MODE_CREATE | MODE_COPY | MODE_DERIVE | MODE_KEYGEN |
                     MODE_UNWRAP)) != 0)
            return CKR_OK;
        break;
    case CKA_PRIVATE:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if ((mode & (MODE_CREATE | MODE_COPY | MODE_DERIVE | MODE_KEYGEN |
                     MODE_UNWRAP)) != 0)
            return CKR_OK;
        break;
    case CKA_ALWAYS_AUTHENTICATE:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if (mode == MODE_MODIFY || mode == MODE_COPY) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
            return CKR_ATTRIBUTE_READ_ONLY;
        }
        if (*(CK_BBOOL *)attr->pValue == FALSE)
            return CKR_OK;
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    case CKA_LABEL:
        return CKR_OK;
    case CKA_IBM_OPAQUE:
    case CKA_IBM_OPAQUE_REENC:
    case CKA_IBM_OPAQUE_OLD:
        /* Allow this attribute to be modified in order to support
         * migratable keys on secure key tokens.
         */
        if ((mode & (MODE_CREATE | MODE_COPY | MODE_MODIFY)) != 0)
            return CKR_OK;
        break;
    case CKA_MODIFIABLE:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        /* CKA_MODIFIABLE can only be set on creation and copy */
        if ((mode & (MODE_CREATE | MODE_COPY | MODE_DERIVE | MODE_KEYGEN |
                     MODE_UNWRAP)) != 0)
            return CKR_OK;
        break;
    case CKA_DESTROYABLE:
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        return CKR_OK;
    case CKA_COPYABLE:
        /* CKA_COPYABLE can not be set to TRUE once it was set to FALSE */
        if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }
        if ((mode & (MODE_CREATE | MODE_DERIVE | MODE_KEYGEN |
                     MODE_UNWRAP)) != 0)
            return CKR_OK;
        if (attr->pValue != NULL && *(CK_BBOOL *)attr->pValue == FALSE)
            return CKR_OK;
        break;
    case CKA_UNIQUE_ID:
        break;
    default:
        TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID),
                    attr->type);
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));

    return CKR_ATTRIBUTE_READ_ONLY;
}

#ifdef DEBUG
/* Debug function: dump list of attribues from a template */
void dump_template(TEMPLATE *tmpl)
{
    DL_NODE *node = NULL;
    CK_ATTRIBUTE *a = NULL;

    node = tmpl->attribute_list;
    while (node) {
        a = (CK_ATTRIBUTE *) node->data;
	TRACE_DEBUG_DUMPATTR(a);
        node = node->next;
    }
}
#endif
