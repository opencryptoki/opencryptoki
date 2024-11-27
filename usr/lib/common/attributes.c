/*
 * COPYRIGHT (c) International Business Machines Corp. 2012-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * OpenCryptoki ICSF token - LDAP functions
 *
 * Author: Marcelo Cerri (mhcerri@br.ibm.com)
 *
 */

#include <stdlib.h>
#include <string.h>
#include "attributes.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "p11util.h"
#include "trace.h"
#include <openssl/crypto.h>

static void __cleanse_and_free_attribute_array(CK_ATTRIBUTE_PTR attrs,
                                               CK_ULONG attrs_len,
                                               CK_BBOOL cleanse,
                                               CK_BBOOL free_array)
{
    CK_ULONG i;

    if (!attrs)
        return;

    for (i = 0; i < attrs_len; i++)
        if (attrs[i].pValue) {
            if (is_attribute_attr_array(attrs[i].type)) {
                __cleanse_and_free_attribute_array(
                        (CK_ATTRIBUTE_PTR)attrs[i].pValue,
                        attrs[i].ulValueLen / sizeof(CK_ATTRIBUTE), cleanse,
                        TRUE);
                continue;
            }
            if (cleanse)
                OPENSSL_cleanse(attrs[i].pValue, attrs[i].ulValueLen);
            free(attrs[i].pValue);
        }
    if (free_array)
        free(attrs);
}

/*
 * Free an array of attributes allocated with dup_attribute_array().
 */
void free_attribute_array(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len)
{
    __cleanse_and_free_attribute_array(attrs, attrs_len, FALSE, TRUE);
}

/*
 * Free an array of attributes allocated with dup_attribute_array() and cleanse
 * all attribute values.
 */
void cleanse_and_free_attribute_array2(CK_ATTRIBUTE_PTR attrs,
                                       CK_ULONG attrs_len,
                                       CK_BBOOL free_array)
{
    __cleanse_and_free_attribute_array(attrs, attrs_len, TRUE, free_array);
}

/*
 * Free an array of attributes allocated with dup_attribute_array() and cleanse
 * all attribute values.
 */
void cleanse_and_free_attribute_array(CK_ATTRIBUTE_PTR attrs,
                                      CK_ULONG attrs_len)
{
    __cleanse_and_free_attribute_array(attrs, attrs_len, TRUE, TRUE);
}

/*
 * Duplicate an array of attributes and all its values.
 * The array itself must have been allocated by the caller, and must be the
 * same size as the original array.
 *
 * The returned array must be freed with free_attribute_array().
 */
CK_RV dup_attribute_array_no_alloc(CK_ATTRIBUTE_PTR orig, CK_ULONG num_attrs,
                                   CK_ATTRIBUTE_PTR dest)
{
    CK_RV rc = CKR_OK;
    CK_ATTRIBUTE_PTR it;

    memset(dest, 0, num_attrs * sizeof(CK_ATTRIBUTE));

    /* Copy each element */
    for (it = dest; it != (dest + num_attrs); it++, orig++) {
        it->type = orig->type;
        it->ulValueLen = orig->ulValueLen;
        if (it->ulValueLen > 0) {
            if (is_attribute_attr_array(it->type)) {
                rc = dup_attribute_array((CK_ATTRIBUTE_PTR)orig->pValue,
                                orig->ulValueLen / sizeof(CK_ATTRIBUTE),
                                (CK_ATTRIBUTE_PTR *)&it->pValue,
                                &it->ulValueLen);
                if (rc != CKR_OK)
                    goto done;
                it->ulValueLen *= sizeof(CK_ATTRIBUTE);
            } else {
                it->pValue = malloc(it->ulValueLen);
                if (it->pValue == NULL) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    rc = CKR_HOST_MEMORY;
                    goto done;
                }
                memcpy(it->pValue, orig->pValue, orig->ulValueLen);
            }
        } else {
            it->pValue = NULL;
        }
    }

done:
    if (rc != CKR_OK)
        __cleanse_and_free_attribute_array(dest, num_attrs, TRUE, FALSE);

    return rc;
}

/*
 * Duplicate an array of attributes and all its values.
 *
 * The returned array must be freed with free_attribute_array().
 */
CK_RV dup_attribute_array(CK_ATTRIBUTE_PTR orig, CK_ULONG orig_len,
                          CK_ATTRIBUTE_PTR *p_dest, CK_ULONG *p_dest_len)
{
    CK_RV rc = CKR_OK;
    CK_ATTRIBUTE_PTR dest;
    CK_ULONG dest_len;

    if (orig == NULL || orig_len == 0) {
        *p_dest = NULL;
        *p_dest_len = 0;
        return CKR_OK;
    }

    /* Allocate the new array */
    dest_len = orig_len;
    dest = malloc(dest_len * sizeof(*dest));
    if (dest == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    rc = dup_attribute_array_no_alloc(orig, orig_len, dest);
    if (rc != CKR_OK) {
        free(dest);
        return rc;
    }

    *p_dest = dest;
    *p_dest_len = dest_len;

    return CKR_OK;
}

/*
 * Return the attribute structure for a given type.
 */
CK_ATTRIBUTE_PTR get_attribute_by_type(CK_ATTRIBUTE_PTR attrs,
                                       CK_ULONG attrs_len, CK_ULONG type)
{
    CK_ATTRIBUTE_PTR it;

    if (attrs == NULL || attrs_len == 0)
        return NULL;

    for (it = attrs; it != attrs + attrs_len; it++)
        if (it->type == type)
            return it;

    return NULL;
}

/*
 * Return the ULONG attribute value for a given type
 */
CK_RV get_ulong_attribute_by_type(CK_ATTRIBUTE_PTR attrs,
                                   CK_ULONG attrs_len, CK_ULONG type,
                                   CK_ULONG *value)
{
    CK_ATTRIBUTE_PTR attr;

    attr = get_attribute_by_type(attrs, attrs_len, type);
    if (attr == NULL)
        return CKR_TEMPLATE_INCOMPLETE;

    if (attr->ulValueLen != sizeof(CK_ULONG) || attr->pValue == NULL) {
        TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID), type);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    *value = *(CK_ULONG *)attr->pValue;
    return CKR_OK;
}

/*
 * Return the BOOL attribute value for a given type
 */
CK_RV get_bool_attribute_by_type(CK_ATTRIBUTE_PTR attrs,
                                   CK_ULONG attrs_len, CK_ULONG type,
                                   CK_BBOOL *value)
{
    CK_ATTRIBUTE_PTR attr;

    attr = get_attribute_by_type(attrs, attrs_len, type);
    if (attr == NULL)
        return CKR_TEMPLATE_INCOMPLETE;

    if (attr->ulValueLen != sizeof(CK_BBOOL) || attr->pValue == NULL) {
        TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID), type);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    *value = *(CK_BBOOL *)attr->pValue;
    return CKR_OK;
}
/*
 * Reallocate the attribute array and add the new element.
 */
CK_RV add_to_attribute_array(CK_ATTRIBUTE_PTR *p_attrs,
                             CK_ULONG_PTR p_attrs_len, CK_ULONG type,
                             CK_BYTE_PTR value, CK_ULONG value_len)
{
    CK_ATTRIBUTE_PTR attrs;
    CK_BYTE_PTR copied_value = NULL;
    CK_RV rc;

    if (value_len > 0) {
        if (is_attribute_attr_array(type)) {
            rc = dup_attribute_array((CK_ATTRIBUTE_PTR)value,
                                     value_len / sizeof(CK_ATTRIBUTE),
                                     (CK_ATTRIBUTE_PTR *)&copied_value,
                                     &value_len);
            if (rc != CKR_OK)
                return rc;
            value_len *= sizeof(CK_ATTRIBUTE);
        } else {
            copied_value = malloc(value_len);
            if (copied_value == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                return CKR_HOST_MEMORY;
            }
            memcpy(copied_value, value, value_len);
        }
    }

    attrs = realloc(*p_attrs, sizeof(**p_attrs) * (*p_attrs_len + 1));
    if (attrs == NULL) {
        if (is_attribute_attr_array(type))
            free_attribute_array((CK_ATTRIBUTE_PTR)copied_value,
                                 value_len / sizeof(CK_ATTRIBUTE));
        else
            free(copied_value);
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    attrs[*p_attrs_len].type = type;
    attrs[*p_attrs_len].pValue = copied_value;
    attrs[*p_attrs_len].ulValueLen = value_len;
    *p_attrs = attrs;
    *p_attrs_len += 1;

    return CKR_OK;
}

CK_BBOOL compare_attribute(CK_ATTRIBUTE_PTR a1, CK_ATTRIBUTE_PTR a2)
{
    if (a1->type != a2->type)
         return FALSE;

    if (a1->ulValueLen != a2->ulValueLen)
         return FALSE;

     if (a1->ulValueLen == 0)
         return TRUE;

     if (a1->pValue == NULL || a2->pValue == NULL)
         return FALSE;

     if (is_attribute_attr_array(a1->type)) {
         if (!compare_attribute_array((CK_ATTRIBUTE_PTR)a1->pValue,
                             a1->ulValueLen / sizeof(CK_ATTRIBUTE),
                             (CK_ATTRIBUTE_PTR)a2->pValue,
                             a2->ulValueLen / sizeof(CK_ATTRIBUTE)))
             return FALSE;
     } else {
         if (memcmp(a1->pValue, a2->pValue, a1->ulValueLen) != 0)
             return FALSE;
     }

     return TRUE;
}

/*
 * Compares two attribute arrays. Returns true if a1 and a2 contain the same
 * attributes. The order of the attributes does not care.
 */
CK_BBOOL compare_attribute_array(CK_ATTRIBUTE_PTR a1, CK_ULONG a1_len,
                                 CK_ATTRIBUTE_PTR a2, CK_ULONG a2_len)
{
    CK_ATTRIBUTE_PTR attr;
    CK_ULONG i;

    if (a1_len != a2_len)
        return FALSE;
    if (a1_len == 0)
        return TRUE;
    if (a1 == NULL || a2 == NULL)
        return FALSE;

    for (i = 0; i < a1_len; i++) {
        attr = get_attribute_by_type(a2, a2_len, a1[i].type);
        if (attr == NULL)
            return FALSE;

        if (!compare_attribute(&a1[i], attr))
            return FALSE;
    }

    return TRUE;
}

CK_RV validate_attribute_array(CK_ATTRIBUTE_PTR attrs, CK_ULONG num_attrs)
{
    CK_ULONG i;
    CK_RV rc;

    if (num_attrs > 0 && attrs == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    for (i = 0; i < num_attrs; i++) {
        if (!is_attribute_defined(attrs[i].type)) {
            TRACE_ERROR("%s: element %lu\n",
                        ock_err(ERR_ATTRIBUTE_TYPE_INVALID), i);
            return CKR_ATTRIBUTE_TYPE_INVALID;
        }

        if (attrs[i].ulValueLen > 0 && attrs[i].pValue == NULL) {
            TRACE_ERROR("%s: element %lu\n",
                        ock_err(ERR_ATTRIBUTE_VALUE_INVALID), i);
            return CKR_ATTRIBUTE_VALUE_INVALID;
        }

        if (is_attribute_attr_array(attrs[i].type)) {
            if (attrs[i].ulValueLen % sizeof(CK_ATTRIBUTE)) {
                TRACE_ERROR("%s: element %lu\n",
                            ock_err(ERR_ATTRIBUTE_VALUE_INVALID), i);
                return CKR_ATTRIBUTE_VALUE_INVALID;
            }
            rc = validate_attribute_array((CK_ATTRIBUTE_PTR)attrs[i].pValue,
                                attrs[i].ulValueLen / sizeof(CK_ATTRIBUTE));
            if (rc != CKR_OK) {
                TRACE_ERROR("validate_attribute_array rc=0x%lx: element %lu\n",
                            rc, i);
                return rc;
            }
        }
    }

    return CKR_OK;
}

#ifdef DEBUG
void dump_array_attr(CK_ATTRIBUTE_PTR a)
{
    CK_ATTRIBUTE_PTR attrs;
    CK_ULONG num_attrs, i;
    const char *typestr = p11_get_cka(a->type);

    attrs = (CK_ATTRIBUTE_PTR)a->pValue;
    num_attrs = a->ulValueLen / sizeof(CK_ATTRIBUTE);

    TRACE_DEBUG("  %s: begin array: num_elements=%lu\n", typestr, num_attrs);
    for (i = 0; i < num_attrs; i++)
        dump_attr(&attrs[i]);
    TRACE_DEBUG("  %s: end array\n", p11_get_cka(a->type));
}

void dump_attr(CK_ATTRIBUTE_PTR a)
{
    const char *typestr;

    if (is_attribute_attr_array(a->type)) {
        dump_array_attr(a);
        return;
    }

    typestr = p11_get_cka(a->type);

    switch (a->ulValueLen) {
    case 0:
        TRACE_DEBUG("  %s: len=0 pValue=%p\n", typestr, a->pValue);
        break;
    case 1:
        TRACE_DEBUG("  %s: len=%lu value=0x%02hhx\n",
                    typestr, a->ulValueLen, *((uint8_t *)(a->pValue)));
        break;
    case 2:
        TRACE_DEBUG("  %s: len=%lu value=0x%04hx\n",
                    typestr, a->ulValueLen, *((uint16_t *)(a->pValue)));
        break;
    case 4:
        TRACE_DEBUG("  %s: len=%lu value=0x%08x\n",
                    typestr, a->ulValueLen, *((uint32_t *)(a->pValue)));
        break;
    case 8:
        TRACE_DEBUG("  %s: len=%lu value=0x%016lx\n",
                    typestr, a->ulValueLen, *((uint64_t *)(a->pValue)));
        break;
    default:
        TRACE_DEBUG("  %s: len=%lu value:\n", typestr, a->ulValueLen);
        TRACE_DEBUG_DUMP("  ", a->pValue, a->ulValueLen);
        break;
    }
}
#endif
