/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  object.c
//
// Object manager related functions
//
// Functions contained within:
//
//    object_create
//    object_free
//    object_is_modifiable
//    object_is_private
//    object_is_token_object
//    object_is_session_object
//

#include <pthread.h>
#include <stdlib.h>
#include <memory.h>
#include <string.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "attributes.h"
#include "p11util.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"
#include "trace.h"
#include "../api/policy.h"

// object_create()
//
// Args:   void *  attributes : (INPUT)  pointer to data block containing
//                              ATTRIBUTEs
//         OBJECT *       obj : (OUTPUT) destination object
//
// Creates an object with the specified attributes. Verifies that all required
// attributes are present and adds any missing attributes that have
// Cryptoki-defined default values. This routine does not check whether the
// session is authorized to create the object. That is done elsewhere
// (see object_mgr_create())
//
CK_RV object_create(STDLL_TokData_t * tokdata,
                    CK_ATTRIBUTE * pTemplate, CK_ULONG ulCount, OBJECT ** obj)
{
    OBJECT *o = NULL;
    CK_BBOOL subclass_given = FALSE;
    CK_ULONG class, subclass = 0xFFFFFFFF;
    CK_RV rc;

    if (!pTemplate) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    // extract the object class and subclass
    //
    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_CLASS,
                                     &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        return rc;
    }

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_CERTIFICATE_TYPE,
                                     &subclass);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK)
        subclass_given = TRUE;

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_KEY_TYPE,
                                     &subclass);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK)
        subclass_given = TRUE;

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_HW_FEATURE_TYPE,
                                     &subclass);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK)
        subclass_given = TRUE;

    // Return CKR_ATTRIBUTE_TYPE_INVALID when trying to create a
    // vendor-defined object.
    if (class >= CKO_VENDOR_DEFINED) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID));
        return CKR_ATTRIBUTE_TYPE_INVALID;
    }

    if (subclass_given != TRUE
        && class != CKO_DATA && class != CKO_PROFILE) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        return CKR_TEMPLATE_INCONSISTENT;
    }

    rc = object_create_skel(tokdata, pTemplate, ulCount,
                            MODE_CREATE, class, subclass, &o);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_create_skel failed.\n");
        return rc;
    }

    *obj = o;
    return CKR_OK;
}


// object_copy()
//
// Args:   OBJECT *   old_obj : (INPUT)  pointer to the source object
//         void *  attributes : (INPUT)  pointer to data block containing
//                              additional ATTRIBUTEs
//         CK_ULONG     count : (INPUT)  number of new attributes
//         OBJECT **  new_obj : (OUTPUT) destination object
//
// Builds a copy of the specified object. The new object gets the original
// object's attribute template plus any additional attributes that are specified
// Verifies that all required attributes are present. This routine does not
// check whether the session is authorized to copy the object -- routines at
// the individual object level don't have the concept of "session". These checks
// are done by the object manager.
//
// The old_obj must hold the READ lock!
//
CK_RV object_copy(STDLL_TokData_t * tokdata, SESSION *sess,
                  CK_ATTRIBUTE * pTemplate,
                  CK_ULONG ulCount, OBJECT * old_obj, OBJECT ** new_obj)
{
    TEMPLATE *tmpl, *new_tmpl;
    OBJECT *o = NULL;
    CK_BBOOL found;
    CK_ULONG class, subclass;
    CK_RV rc;


    if (!old_obj || (!pTemplate && ulCount) || !new_obj) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    o = (OBJECT *) malloc(sizeof(OBJECT));
    tmpl = (TEMPLATE *) malloc(sizeof(TEMPLATE));
    new_tmpl = (TEMPLATE *) malloc(sizeof(TEMPLATE));

    if (!o || !tmpl || !new_tmpl) {
        rc = CKR_HOST_MEMORY;
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        if (o)
            free(o);
        if (tmpl)
            free(tmpl);
        if (new_tmpl)
            free(new_tmpl);

        return rc;      // do not goto done -- memory might not be initialized
    }

    memset(o, 0x0, sizeof(OBJECT));
    memset(tmpl, 0x0, sizeof(TEMPLATE));
    memset(new_tmpl, 0x0, sizeof(TEMPLATE));
    o->template = tmpl;

    rc = object_init_lock(o);
    if (rc != CKR_OK)
        goto error;

    rc = object_init_ex_data_lock(o);
    if (rc != CKR_OK)
        goto error;

    // copy the original object's attribute template
    //
    rc = template_copy(o->template, old_obj->template);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to copy template.\n");
        goto error;
    }

    rc = template_add_attributes(new_tmpl, pTemplate, ulCount);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_add_attributes failed.\n");
        goto error;
    }
    // at this point, the new object has the list of attributes. we need
    // to do some more checking now:
    //    1) invalid attribute values
    //    2) missing required attributes
    //    3) attributes inappropriate for the object class
    //    4) conflicting attributes/values
    //

    found = template_get_class(o->template, &class, &subclass);
    if (found == FALSE) {
        TRACE_ERROR("Could not find CKA_CLASS in object's template.\n");
        rc = CKR_TEMPLATE_INCONSISTENT;
        goto error;
    }

    // the user cannot change object classes so we assume the existing
    // object attributes are valid.  we still need to check the new attributes.
    // we cannot merge the new attributes in with the old ones and then check
    // for validity because some attributes are added internally and are not
    // allowed to be specified by the user (ie. CKA_LOCAL for key types) but
    // may still be part of the old template.
    //
    rc = template_validate_attributes(tokdata, new_tmpl, class, subclass,
                                      MODE_COPY);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_validate_attributes failed.\n");
        goto error;
    }

    /*
     * Let the token know that attributes of the copied object have been
     * changed.
     */
    if (token_specific.t_set_attribute_values != NULL) {
        rc = token_specific.t_set_attribute_values(tokdata, sess, o, new_tmpl);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_specific_set_attribute_values failed with %lu\n",
                        rc);
            goto error;
        }
   }

    // merge in the new attributes
    //
    rc = template_merge(o->template, &new_tmpl);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_merge failed.\n");
        goto error;
    }
    // do we need this?  since an attribute cannot be removed, the original
    // object's template (contained in tmpl) already has the required attributes
    // present
    //
    rc = template_check_required_attributes(o->template, class, subclass,
                                            MODE_COPY);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_check_required_attributes failed.\n");
        goto error;
    }
    // at this point, we should have a valid object with correct attributes
    //
    *new_obj = o;

    return CKR_OK;

error:
    if (new_tmpl)
        template_free(new_tmpl);
    if (o)
        object_free(o);

    return rc;
}


// object_flatten() - this is still used when saving token objects
//
CK_RV object_flatten(OBJECT * obj, CK_BYTE ** data, CK_ULONG * len)
{
    CK_BYTE *buf = NULL;
    CK_ULONG tmpl_len, total_len;
    CK_ULONG offset;
    CK_ULONG_32 count;
    CK_OBJECT_CLASS_32 class32;
    long rc;

    if (!obj) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    count = template_get_count(obj->template);
    tmpl_len = template_get_compressed_size(obj->template);

    total_len = tmpl_len + sizeof(CK_OBJECT_CLASS_32) + sizeof(CK_ULONG_32) + 8;

    buf = (CK_BYTE *) malloc(total_len);
    if (!buf) {                 // SAB  XXX FIXME  This was DATA
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    memset((CK_BYTE *) buf, 0x0, total_len);

    offset = 0;

    class32 = obj->class;
    memcpy(buf + offset, &class32, sizeof(CK_OBJECT_CLASS_32));
    offset += sizeof(CK_OBJECT_CLASS_32);

    memcpy(buf + offset, &count, sizeof(CK_ULONG_32));
    offset += sizeof(CK_ULONG_32);

    memcpy(buf + offset, &obj->name, sizeof(CK_BYTE) * 8);
    offset += 8;
    rc = template_flatten(obj->template, buf + offset);
    if (rc != CKR_OK) {
        free(buf);
        return rc;
    }

    *data = buf;
    *len = total_len;

    return CKR_OK;
}



// object_free()
//
// does what it says...
//
void object_free(OBJECT * obj)
{
    /* refactorization here to do actual free - fix from coverity scan */
    if (obj) {
        if (obj->ex_data != NULL) {
            if (obj->ex_data_free != NULL)
                obj->ex_data_free(obj, obj->ex_data, obj->ex_data_len);
            else
                free(obj->ex_data);
        }
        object_destroy_ex_data_lock(obj);
        if (obj->template)
            template_free(obj->template);
        object_destroy_lock(obj);
        free(obj);
    }
}

//call_object_free()
//This function is added to silence the compiler during implicit void (*)(void*)
//function pointer casting in call back functions.
//
void call_object_free(void *ptr)
{
    if (ptr)
        object_free((OBJECT *) ptr);
}

CK_BBOOL object_is_modifiable(OBJECT * obj)
{
    CK_BBOOL val;
    CK_RV rc;

    rc = template_attribute_get_bool(obj->template, CKA_MODIFIABLE, &val);
    if (rc != CKR_OK)
        return TRUE;

    return val;

}

CK_BBOOL object_is_copyable(OBJECT * obj)
{
    CK_BBOOL val;
    CK_RV rc;

    rc = template_attribute_get_bool(obj->template, CKA_COPYABLE, &val);
     if (rc != CKR_OK)
         return TRUE;

    return val;
}

CK_BBOOL object_is_destroyable(OBJECT * obj)
{
    CK_BBOOL val;
    CK_RV rc;

    rc = template_attribute_get_bool(obj->template, CKA_DESTROYABLE, &val);
     if (rc != CKR_OK)
         return TRUE;

    return val;
}

// object_is_private()
//
// an is_private member should probably be added to OBJECT
//
CK_BBOOL object_is_private(OBJECT * obj)
{
    CK_BBOOL val;
    CK_RV rc;

    rc = template_attribute_get_bool(obj->template, CKA_PRIVATE, &val);
     if (rc != CKR_OK)
         return TRUE;

    return val;
}


// object_is_public()
//
CK_BBOOL object_is_public(OBJECT * obj)
{
    CK_BBOOL rc;

    rc = object_is_private(obj);

    if (rc)
        return FALSE;

    return TRUE;
}


// object_is_token_object()
//
CK_BBOOL object_is_token_object(OBJECT * obj)
{
    CK_BBOOL val;
    CK_RV rc;

    rc = template_attribute_get_bool(obj->template, CKA_TOKEN, &val);
    if (rc != CKR_OK)
        return FALSE;

    return val;
}


// object_is_session_object()
//
CK_BBOOL object_is_session_object(OBJECT * obj)
{
    CK_BBOOL rc;

    rc = object_is_token_object(obj);

    if (rc)
        return FALSE;
    else
        return TRUE;
}

// object_is_extractable()
//
CK_BBOOL object_is_extractable(OBJECT * obj)
{
    CK_BBOOL val;
    CK_RV rc;

    rc = template_attribute_get_bool(obj->template, CKA_EXTRACTABLE, &val);
    if (rc != CKR_OK)
        return TRUE;

    return val;
}

// object_is_pkey_extractable()
//
CK_BBOOL object_is_pkey_extractable(OBJECT * obj)
{
    CK_BBOOL val;
    CK_RV rc;

    rc = template_attribute_get_bool(obj->template, CKA_IBM_PROTKEY_EXTRACTABLE, &val);
    if (rc != CKR_OK)
        return FALSE;

    return val;
}

// object_is_attr_bound()
//
CK_BBOOL object_is_attr_bound(OBJECT * obj)
{
    CK_BBOOL val;
    CK_RV rc;

    rc = template_attribute_get_bool(obj->template, CKA_IBM_ATTRBOUND, &val);
    if (rc != CKR_OK)
        return FALSE;

    return val;
}

// object_get_size()
//
CK_ULONG object_get_size(OBJECT * obj)
{
    CK_ULONG size;

    size = sizeof(OBJECT) + template_get_size(obj->template);

    return size;
}

static CK_RV object_get_attribute_array(CK_ATTRIBUTE *array_attr,
                                        CK_ATTRIBUTE *tmpl_attr)
{
    CK_RV rc = CKR_OK, rc2;
    CK_ULONG num_elemets, i;
    CK_ATTRIBUTE_PTR array_elements;
    CK_ATTRIBUTE_PTR tmpl_elements;

    if (!is_attribute_attr_array(array_attr->type))
        return CKR_ATTRIBUTE_TYPE_INVALID;

    if (tmpl_attr->pValue == NULL) {
        tmpl_attr->ulValueLen = array_attr->ulValueLen;
        return CKR_OK;
    }
    if (tmpl_attr->ulValueLen < array_attr->ulValueLen) {
        tmpl_attr->ulValueLen = CK_UNAVAILABLE_INFORMATION;
        return CKR_BUFFER_TOO_SMALL;
    }

    num_elemets = array_attr->ulValueLen / sizeof(CK_ATTRIBUTE);
    array_elements = (CK_ATTRIBUTE_PTR)array_attr->pValue;
    tmpl_elements = (CK_ATTRIBUTE_PTR)tmpl_attr->pValue;

    for (i = 0; i < num_elemets; i++) {
        tmpl_elements[i].type = array_elements[i].type;

        if (tmpl_elements[i].pValue == NULL) {
            tmpl_elements[i].ulValueLen = array_elements[i].ulValueLen;
        } else if (tmpl_elements[i].ulValueLen >=
                                            array_elements[i].ulValueLen) {
            if (array_elements[i].pValue != NULL) {
                if (is_attribute_attr_array(array_elements[i].type)) {
                    rc2 = object_get_attribute_array(&array_elements[i],
                                                     &tmpl_elements[i]);
                    if (rc2 == CKR_BUFFER_TOO_SMALL)
                        rc = rc2;
                    else if (rc2 != CKR_OK) {
                        TRACE_ERROR("object_get_attribute_array failed\n");
                        rc = rc2;
                        break;
                    }
                } else {
                    memcpy(tmpl_elements[i].pValue, array_elements[i].pValue,
                           array_elements[i].ulValueLen);
                }
            }
            tmpl_elements[i].ulValueLen = array_elements[i].ulValueLen;
        } else {
            TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
            rc = CKR_BUFFER_TOO_SMALL;
            tmpl_elements[i].ulValueLen = CK_UNAVAILABLE_INFORMATION;
        }
    }

    return rc;
}

//
//
CK_RV object_get_attribute_values(OBJECT * obj,
                                  CK_ATTRIBUTE * pTemplate, CK_ULONG ulCount)
{
    TEMPLATE *obj_tmpl = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG i;
    CK_BBOOL flag;
    CK_RV rc, rc2;

    rc = CKR_OK;

    obj_tmpl = obj->template;

    for (i = 0; i < ulCount; i++) {
        flag = template_check_exportability(obj_tmpl, pTemplate[i].type);
        if (flag == FALSE) {
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_SENSITIVE),
                        pTemplate[i].type);
            rc = CKR_ATTRIBUTE_SENSITIVE;
            pTemplate[i].ulValueLen = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
            continue;
        }

        flag = template_attribute_find(obj_tmpl, pTemplate[i].type, &attr);
        if (flag == FALSE) {
            TRACE_ERROR("%s: %lx\n", ock_err(ERR_ATTRIBUTE_TYPE_INVALID),
                        pTemplate[i].type);
            rc = CKR_ATTRIBUTE_TYPE_INVALID;
            pTemplate[i].ulValueLen = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
            continue;
        }

        if (pTemplate[i].pValue == NULL) {
            pTemplate[i].ulValueLen = attr->ulValueLen;
        } else if (pTemplate[i].ulValueLen >= attr->ulValueLen) {
            if (attr->pValue != NULL) {
                if (is_attribute_attr_array(attr->type)) {
                    rc2 = object_get_attribute_array(attr, &pTemplate[i]);
                    if (rc2 == CKR_BUFFER_TOO_SMALL)
                        rc = rc2;
                    else if (rc2 != CKR_OK) {
                        TRACE_ERROR("object_get_attribute_array failed\n");
                        rc = rc2;
                        break;
                    }
                } else {
                    memcpy(pTemplate[i].pValue, attr->pValue, attr->ulValueLen);
                }
            }
            pTemplate[i].ulValueLen = attr->ulValueLen;
        } else {
            TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
            rc = CKR_BUFFER_TOO_SMALL;
            pTemplate[i].ulValueLen = (CK_ULONG)CK_UNAVAILABLE_INFORMATION;
        }
    }

    return rc;
}

// object_set_attribute_values()
//
CK_RV object_set_attribute_values(STDLL_TokData_t * tokdata, SESSION *sess,
                                  OBJECT * obj,
                                  CK_ATTRIBUTE * pTemplate, CK_ULONG ulCount)
{
    TEMPLATE *new_tmpl = NULL;
    CK_BBOOL found;
    CK_ULONG class, subclass;
    CK_RV rc;


    if (!obj || !pTemplate) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    found = template_get_class(obj->template, &class, &subclass);
    if (found == FALSE) {
        TRACE_ERROR("Failed to find CKA_CLASS in object template.\n");
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    new_tmpl = (TEMPLATE *) malloc(sizeof(TEMPLATE));
    if (!new_tmpl) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    memset(new_tmpl, 0x0, sizeof(TEMPLATE));

    rc = template_add_attributes(new_tmpl, pTemplate, ulCount);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_add_attributes failed.\n");
        goto error;
    }
    // the user cannot change object classes so we assume the existing
    // object attributes are valid.  we still need to check the new attributes.
    // we cannot merge the new attributes in with the old ones and then check
    // for validity because some attributes are added internally and are not
    // allowed to be specified by the user (ie. CKA_LOCAL for key types) but
    // may still be part of the old template.
    //
    rc = template_validate_attributes(tokdata, new_tmpl, class, subclass,
                                      MODE_MODIFY);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_validate_attributes failed.\n");
        goto error;
    }

    if (token_specific.t_set_attribute_values != NULL) {
        rc = token_specific.t_set_attribute_values(tokdata, sess,
                                                   obj, new_tmpl);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_specific_set_attribute_values failed with %lu\n",
                        rc);
            goto error;
        }
   }

    // merge in the new attributes
    //
    rc = template_merge(obj->template, &new_tmpl);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_merge failed.\n");
        return rc;
    }

    return CKR_OK;

error:
    // we only free the template if there was an error...otherwise the
    // object "owns" the template
    //
    if (new_tmpl)
        template_free(new_tmpl);

    return rc;
}


//
//Modified object_restore to prevent buffer overflow
//If data_size=-1, won't do bounds checking
CK_RV object_restore_withSize(struct policy *policy,
                              CK_BYTE * data, OBJECT ** new_obj,
                              CK_BBOOL replace, int data_size,
                              const char *fname)
{
    TEMPLATE *tmpl = NULL;
    OBJECT *obj = NULL;
    CK_ULONG offset = 0;
    CK_ULONG_32 count = 0;
    CK_RV rc;
    CK_OBJECT_CLASS_32 class32;
    const char *obj_name;

    if (!data || !new_obj) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    obj = (OBJECT *) malloc(sizeof(OBJECT));
    if (!obj) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    memset(obj, 0x0, sizeof(OBJECT));

    memcpy(&class32, data + offset, sizeof(CK_OBJECT_CLASS_32));
    obj->class = class32;
    offset += sizeof(CK_OBJECT_CLASS_32);

    memcpy(&count, data + offset, sizeof(CK_ULONG_32));
    offset += sizeof(CK_ULONG_32);

    memcpy(&obj->name, data + offset, 8);
    offset += 8;

    if (fname != NULL) {
        /* The last path element of the file name must match the object name */
        obj_name = strrchr(fname, '/');
        if (obj_name == NULL) {
            TRACE_ERROR("File name has invalid format: '%s'\n", fname);
            rc = CKR_FUNCTION_FAILED;
            goto error;
        }

        obj_name++;
        if (strlen(obj_name) != 8) {
            TRACE_ERROR("File name has invalid format: '%s'\n", fname);
            rc = CKR_FUNCTION_FAILED;
            goto error;
        }

        if (memcmp(obj->name, obj_name, 8) != 0) {
            TRACE_ERROR("Object name '%.8s' does not match the file name it was loaded from: '%s'\n",
                        obj->name, fname);
            rc = CKR_FUNCTION_FAILED;
            goto error;
        }
    }

    rc = template_unflatten_withSize(&tmpl, data + offset, count, data_size);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_unflatten_withSize failed.\n");
        goto error;
    }
    /* External tools (e.g., pkcscca) might use this function and not
       be aware of any policy.  Allow them to pass NULL. */
    if (policy) {
        /* Ignore policy violations here since the point is to get the
           correct strength classification for the usage scenario
           which will then allow or block key usage. */
        policy->store_object_strength(policy, &obj->strength,
                                      policy_get_attr_from_template,
                                      tmpl, NULL, NULL);
    }

    obj->template = tmpl;
    tmpl = NULL;

    if (replace == FALSE) {
        rc = object_init_lock(obj);
        if (rc != CKR_OK)
            goto error;

        rc = object_init_ex_data_lock(obj);
        if (rc != CKR_OK) {
            object_destroy_lock(obj);
            goto error;
        }

        *new_obj = obj;
    } else {
        /* Reload of existing object only changes the template */
        template_free((*new_obj)->template);
        (*new_obj)->template = obj->template;
        (*new_obj)->strength.strength = obj->strength.strength;
        (*new_obj)->strength.siglen = obj->strength.siglen;
        (*new_obj)->strength.allowed = obj->strength.allowed;
        free(obj);              // don't want to do object_free() here!
    }

    return CKR_OK;

error:
    if (obj)
        object_free(obj);
    if (tmpl)
        template_free(tmpl);

    return rc;
}


//
//
CK_RV object_create_skel(STDLL_TokData_t * tokdata,
                         CK_ATTRIBUTE * pTemplate,
                         CK_ULONG ulCount,
                         CK_ULONG mode,
                         CK_ULONG class, CK_ULONG subclass, OBJECT ** obj)
{
    TEMPLATE *tmpl = NULL;
    TEMPLATE *tmpl2 = NULL;
    OBJECT *o = NULL;
    CK_RV rc;


    if (!obj) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (!pTemplate && (ulCount != 0)) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    o = (OBJECT *) calloc(1, sizeof(OBJECT));
    tmpl = (TEMPLATE *) calloc(1, sizeof(TEMPLATE));
    tmpl2 = (TEMPLATE *) calloc(1, sizeof(TEMPLATE));

    if (!o || !tmpl || !tmpl2) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    rc = template_add_attributes(tmpl2, pTemplate, ulCount);
    if (rc != CKR_OK)
        goto done;


    // at this point, the new template has the list of attributes.  we need
    // to do some more checking now:
    //    1) invalid attribute values
    //    2) missing required attributes
    //    3) attributes inappropriate for the object class
    //    4) conflicting attributes/values
    //

    rc = template_validate_attributes(tokdata, tmpl2, class, subclass, mode);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_validate_attributes failed.\n");
        goto done;
    }

    rc = template_check_required_attributes(tmpl2, class, subclass, mode);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_check_required_attributes failed.\n");
        goto done;
    }

    rc = template_add_default_attributes(tokdata, tmpl, tmpl2, class, subclass,
                                         mode);
    if (rc != CKR_OK)
        goto done;

    if (token_specific.t_set_attrs_for_new_object != NULL) {
        rc = token_specific.t_set_attrs_for_new_object(tokdata, class,
                                                       mode, tmpl2);
        if (rc != CKR_OK) {
            TRACE_ERROR("token_specific.t_set_pkey_attr failed with rc=%lx\n",rc);
            goto done;
        }
    }

    rc = template_merge(tmpl, &tmpl2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_merge failed.\n");
        goto done;
    }
    // at this point, we should have a valid object with correct attributes
    //
    o->template = tmpl;
    tmpl = NULL;

    rc = object_init_lock(o);
    if (rc != CKR_OK)
        goto done;

    rc = object_init_ex_data_lock(o);
    if (rc != CKR_OK) {
        object_destroy_lock(o);
        goto done;
    }

    *obj = o;

    return CKR_OK;

done:
    if (o) {
        if (o->template)
            template_free(o->template);
        free(o);
    }
    if (tmpl)
        template_free(tmpl);
    if (tmpl2)
        template_free(tmpl2);

    return rc;
}

CK_RV object_init_lock(OBJECT *obj)
{
    if (pthread_rwlock_init(&obj->template_rwlock, NULL) != 0) {
        TRACE_DEVEL("Object Lock init failed.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

CK_RV object_destroy_lock(OBJECT *obj)
{
    if (pthread_rwlock_destroy(&obj->template_rwlock) != 0) {
        TRACE_DEVEL("Object Lock destroy failed.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

/*
 * Do NOT try to get an object lock, if the current thread holds the
 * XProcLock! This might case a deadlock !
 * Always first acquire the Object lock, and then the XProcLock.
 */
CK_RV object_lock(OBJECT *obj, OBJ_LOCK_TYPE type)
{
    switch (type) {
    case NO_LOCK:
        break;
    case READ_LOCK:
        if (pthread_rwlock_rdlock(&obj->template_rwlock) != 0) {
            TRACE_DEVEL("Object Read-Lock failed.\n");
            return CKR_CANT_LOCK;
        }
        break;
    case WRITE_LOCK:
        if (pthread_rwlock_wrlock(&obj->template_rwlock) != 0) {
            TRACE_DEVEL("Object Write-Lock failed.\n");
            return CKR_CANT_LOCK;
        }
        break;
    }

    return CKR_OK;
}

CK_RV object_unlock(OBJECT *obj)
{
    if (pthread_rwlock_unlock(&obj->template_rwlock) != 0) {
        TRACE_DEVEL("Object Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

CK_RV object_init_ex_data_lock(OBJECT *obj)
{
    if (pthread_rwlock_init(&obj->ex_data_rwlock, NULL) != 0) {
        TRACE_DEVEL("Ex_data Lock init failed.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

CK_RV object_destroy_ex_data_lock(OBJECT *obj)
{
    if (pthread_rwlock_destroy(&obj->ex_data_rwlock) != 0) {
        TRACE_DEVEL("Ex_data Lock destroy failed.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}

CK_RV object_ex_data_lock(OBJECT *obj, OBJ_LOCK_TYPE type)
{
    switch (type) {
    case NO_LOCK:
        break;
    case READ_LOCK:
        if (pthread_rwlock_rdlock(&obj->ex_data_rwlock) != 0) {
            TRACE_DEVEL("Ex_data Read-Lock failed.\n");
            return CKR_CANT_LOCK;
        }
        break;
    case WRITE_LOCK:
        if (pthread_rwlock_wrlock(&obj->ex_data_rwlock) != 0) {
            TRACE_DEVEL("Ex_data Write-Lock failed.\n");
            return CKR_CANT_LOCK;
        }
        break;
    }

    return CKR_OK;
}

CK_RV object_ex_data_unlock(OBJECT *obj)
{
    if (pthread_rwlock_unlock(&obj->ex_data_rwlock) != 0) {
        TRACE_DEVEL("Ex_data Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

    return CKR_OK;
}
