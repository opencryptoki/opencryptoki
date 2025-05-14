/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  obj_mgr.c
//
// Object manager related functions
//

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <unistd.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "attributes.h"
#include "tok_spec_struct.h"
#include "trace.h"
#include "ock_syslog.h"

#include "../api/apiproto.h"
#include "../api/policy.h"

static CK_RV object_mgr_check_session(SESSION *sess, CK_BBOOL priv_obj,
                                      CK_BBOOL sess_obj)
{
    // check whether session has permissions to create the object, etc
    //
    // Object                  R/O      R/W      R/O     R/W    R/W
    // Type                   Public   Public    User    User   SO
    // -------------------------------------------------------------
    // Public session          R/W      R/W      R/W     R/W    R/W
    // Private session                           R/W     R/W
    // Public token            R/O      R/W      R/O     R/W    R/W
    // Private token                             R/O     R/W
    //
    if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
        if (priv_obj) {
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            return CKR_USER_NOT_LOGGED_IN;
        }

        if (!sess_obj) {
            TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
            return CKR_SESSION_READ_ONLY;
        }
    }

    if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
        if (!sess_obj) {
            TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
            return CKR_SESSION_READ_ONLY;
        }
    }

    if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
        if (priv_obj) {
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            return CKR_USER_NOT_LOGGED_IN;
        }
    }

    if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
        if (priv_obj) {
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            return CKR_USER_NOT_LOGGED_IN;
        }
    }

    return CKR_OK;
}

CK_RV object_mgr_add(STDLL_TokData_t *tokdata,
                     SESSION *sess,
                     CK_ATTRIBUTE *pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE *handle)
{
    OBJECT *o = NULL;
    CK_BBOOL priv_obj, sess_obj;
    CK_RV rc;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE keytype;
    CK_BYTE *spki = NULL;
    CK_ULONG spki_len = 0;
    CK_ATTRIBUTE *spki_attr = NULL, *value_attr = NULL, *vallen_attr = NULL;

    if (!sess || !pTemplate || !handle) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_ARGUMENTS_BAD;
    }

    rc = object_create(tokdata, pTemplate, ulCount, &o);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Create failed.\n");
        goto done;
    }

    if (token_specific.t_check_obj_access != NULL) {
        rc = token_specific.t_check_obj_access(tokdata, o, TRUE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("check_obj_access rejected access to object.\n");
            goto done;
        }
    }

    if (token_specific.t_object_add != NULL) {
        rc = token_specific.t_object_add(tokdata, sess, o);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Token specific object add failed.\n");
            goto done;
        }
    }

    rc = template_attribute_get_ulong(o->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the object.\n");
        goto done;
    }

    switch(class) {
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
        /* Skip if there is already a non-empty CKA_PUBLIC_KEY_INFO */
        if (template_attribute_get_non_empty(o->template, CKA_PUBLIC_KEY_INFO,
                                             &spki_attr) == CKR_OK)
            break;

        rc = template_attribute_get_ulong(o->template, CKA_KEY_TYPE, &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key object.\n");
            goto done;
        }

        /*
         * Try to extract the SPKI and add CKA_PUBLIC_KEY_INFO to the key.
         * This may fail if the public key info can not be reconstructed from
         * the private key (e.g. because its a secure key token).
         */
        rc = publ_key_get_spki(o->template, keytype, FALSE, &spki, &spki_len);
        if (rc == CKR_OK && spki != NULL && spki_len > 0) {
            rc = build_attribute(CKA_PUBLIC_KEY_INFO, spki, spki_len,
                                 &spki_attr);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_attribute failed\n");
                goto done;
            }
            rc = template_update_attribute(o->template, spki_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("template_update_attribute failed\n");
                free(spki_attr);
                goto done;
            }
        }
        break;
    case CKO_SECRET_KEY:
        rc = template_attribute_get_ulong(o->template, CKA_KEY_TYPE, &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key object.\n");
            goto done;
        }

        switch (keytype) {
        case CKK_GENERIC_SECRET:
        case CKK_AES:
        case CKK_AES_XTS:
            rc = template_attribute_get_non_empty(o->template, CKA_VALUE,
                                                  &value_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("Could not find CKA_VALUE for the key object.\n");
                goto done;
            }
            rc = build_attribute(CKA_VALUE_LEN,
                                 (CK_BYTE *)&value_attr->ulValueLen,
                                 sizeof(CK_ULONG), &vallen_attr);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_attribute failed\n");
                goto done;
            }
            rc = template_update_attribute(o->template, vallen_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("template_update_attribute failed\n");
                free(vallen_attr);
                goto done;
            }
            break;
        default:
            break;
        }
        break;
    default:
        break;
    }

    sess_obj = object_is_session_object(o);
    priv_obj = object_is_private(o);

    rc = object_mgr_check_session(sess, priv_obj, sess_obj);
    if (rc != CKR_OK)
        goto done;

    // okay, object is created and the session permissions look okay.
    // add the object to the appropriate list and assign an object handle
    //
    rc = object_mgr_create_final(tokdata, sess, o, handle);

done:
    if ((rc != CKR_OK) && (o != NULL)) {
        object_free(o);
        o = NULL;
    }
    if (spki != NULL)
        free(spki);

    if (rc == CKR_OK)
        TRACE_DEVEL("Object created: handle: %lu\n", *handle);

    return rc;
}


// object_mgr_add_to_map()
//
CK_RV object_mgr_add_to_map(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            OBJECT *obj,
                            unsigned long obj_handle,
                            CK_OBJECT_HANDLE *map_handle)
{
    OBJECT_MAP *map_node = NULL;

    UNUSED(tokdata);

    if (!sess || !obj || !map_handle) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    //
    // this guy doesn't lock a mutex because it's calling routines should have
    // already locked it
    //

    map_node = (OBJECT_MAP *) malloc(sizeof(OBJECT_MAP));
    if (!map_node) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    map_node->session = sess;

    if (obj->session != NULL)
        map_node->is_session_obj = TRUE;
    else
        map_node->is_session_obj = FALSE;

    map_node->is_private = object_is_private(obj);

    // map_node->obj_handle will store the index of the btree node in one of
    // these lists:
    // publ_token_obj_btree - for public token object
    // priv_token_obj_btree - for private token objects
    // sess_obj_btree - for session objects
    //
    // *map_handle, the application's CK_OBJECT_HANDLE, will then be the index
    // of the btree node in the object_map_btree
    //
    map_node->obj_handle = obj_handle;
    *map_handle = bt_node_add(&tokdata->object_map_btree, map_node);

    if (*map_handle == 0) {
        free(map_node);
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    obj->map_handle = *map_handle;

    return CKR_OK;
}


// object_mgr_copy()
//
// algorithm:
//    1) find the old object
//    2) get the template from the old object
//    3) merge in the new object's template
//    4) perform class-specific sanity checks
//
CK_RV object_mgr_copy(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      CK_ATTRIBUTE *pTemplate,
                      CK_ULONG ulCount,
                      CK_OBJECT_HANDLE old_handle,
                      CK_OBJECT_HANDLE *new_handle)
{
    OBJECT *old_obj = NULL;
    OBJECT *new_obj = NULL;
    CK_BBOOL priv_obj;
    CK_BBOOL sess_obj;
    CK_RV rc;

    if (!sess || (!pTemplate && ulCount) || !new_handle) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_find_in_map1(tokdata, old_handle, &old_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
        goto done;
    }

    if (!object_is_copyable(old_obj)) {
        TRACE_ERROR("Object is not copyable\n");
        rc = CKR_ACTION_PROHIBITED;
        goto done;
    }

    rc = object_copy(tokdata, sess, pTemplate, ulCount, old_obj, &new_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Copy failed.\n");
        goto done;
    }

    sess_obj = object_is_session_object(new_obj);
    priv_obj = object_is_private(new_obj);

    rc = object_mgr_check_session(sess, priv_obj, sess_obj);
    if (rc != CKR_OK)
        goto done;

    if (token_specific.t_check_obj_access != NULL) {
        rc = token_specific.t_check_obj_access(tokdata, new_obj, TRUE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("check_obj_access rejected access to object.\n");
            goto done;
        }
    }

    // okay, object is created and the session permissions look okay.
    // add the object to the appropriate list and assign an object handle
    //
    rc = object_mgr_create_final(tokdata, sess, new_obj, new_handle);

done:
    if ((rc != CKR_OK) && (new_obj != NULL)) {
        object_free(new_obj);
        new_obj = NULL;
    }
    object_put(tokdata, old_obj, TRUE);
    old_obj = NULL;

    return rc;
}


// determines whether the session is allowed to create an object. creates
// the object but doesn't add the object to any object lists or to the
// process' object map.
//
CK_RV object_mgr_create_skel(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_ATTRIBUTE *pTemplate,
                             CK_ULONG ulCount,
                             CK_ULONG mode,
                             CK_ULONG obj_type,
                             CK_ULONG sub_class, OBJECT **obj)
{
    OBJECT *o = NULL;
    CK_RV rc;
    CK_BBOOL priv_obj;
    CK_BBOOL sess_obj;

    if (!sess || !obj) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (!pTemplate && (ulCount != 0)) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    //
    // we don't need to lock mutex for this routine
    //

    rc = object_create_skel(tokdata, pTemplate, ulCount,
                            mode, obj_type, sub_class, &o);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_create_skel failed.\n");
        return rc;
    }
    sess_obj = object_is_session_object(o);
    priv_obj = object_is_private(o);

    if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
        if (priv_obj) {
            object_free(o);
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            return CKR_USER_NOT_LOGGED_IN;
        }

        if (!sess_obj) {
            object_free(o);
            TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
            return CKR_SESSION_READ_ONLY;
        }
    }

    if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
        if (!sess_obj) {
            object_free(o);
            TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
            return CKR_SESSION_READ_ONLY;
        }
    }

    if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
        if (priv_obj) {
            object_free(o);
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            return CKR_USER_NOT_LOGGED_IN;
        }
    }

    if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
        if (priv_obj) {
            object_free(o);
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            return CKR_USER_NOT_LOGGED_IN;
        }
    }

    if (token_specific.t_check_obj_access != NULL) {
        rc = token_specific.t_check_obj_access(tokdata, o, TRUE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("check_obj_access rejected access to object.\n");
            object_free(o);
            return rc;
        }
    }

    *obj = o;

    return CKR_OK;
}

/*
 * Finalizes the object creation and adds the object into the appropriate
 * btree and also the object map btree.
 * When this function succeeds, object obj must not be freed! It has been added
 * to the btree and thus must be kept intact.
 * When this function fails, then the object obj must be freed by the caller
 * using object_free() (not object_put() nor bt_put_node_value() !)
 */
CK_RV object_mgr_create_final(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              OBJECT *obj, CK_OBJECT_HANDLE *handle)
{
    CK_BBOOL sess_obj;
    CK_BBOOL priv_obj;
    CK_BBOOL locked = FALSE;
    CK_RV rc;
    unsigned long obj_handle;
    char fname[PATH_MAX] = "";
    int fd;

    if (!sess || !obj || !handle) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    TRACE_DEBUG("Attributes at create final:\n");
    TRACE_DEBUG_DUMPTEMPL(obj->template);

    rc = tokdata->policy->store_object_strength(tokdata->policy, &obj->strength,
                                                policy_get_attr_from_template,
                                                obj->template, NULL, sess);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to store acceptable object strength.\n");
        return rc;
    }

    sess_obj = object_is_session_object(obj);
    priv_obj = object_is_private(obj);

    if (sess_obj) {
        obj->session = sess;
        memset(obj->name, 0x0, sizeof(CK_BYTE) * 8);

        if ((obj_handle = bt_node_add(&tokdata->sess_obj_btree, obj)) == 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }
    } else {
        // we'll be modifying nv_token_data so we should protect this part
        // with 'XProcLock'
        //
        rc = XProcLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to get Process Lock.\n");
            return rc;
        }
        locked = TRUE;

        // Determine if we have already reached our Max Token Objects
        //
        if (priv_obj) {
            if (tokdata->global_shm->num_priv_tok_obj >= MAX_TOK_OBJS) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                goto done;
            }
        } else {
            if (tokdata->global_shm->num_publ_tok_obj >= MAX_TOK_OBJS) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                goto done;
            }
        }

        /* create unique file name in token directory */
        if (ock_snprintf(fname, sizeof(fname), "%s/" PK_LITE_OBJ_DIR "/%s",
                         tokdata->data_store, "OBXXXXXX") != 0) {
            TRACE_ERROR("buffer overflow for object path");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        fd = mkstemp(fname);
        if (fd < 0) {
            TRACE_ERROR("mkstemp failed with: %s\n", strerror(errno));
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
        close(fd); /* written and permissions set by save_token_object */

        obj->session = NULL;
        memcpy(&obj->name, &fname[strlen(fname) - 8], 8);

        rc = save_token_object(tokdata, obj);
        if (rc != CKR_OK)
            goto done;

        // add the object identifier to the shared memory segment
        //
        object_mgr_add_to_shm(obj, tokdata->global_shm);

        // now, store the object in the token object btree
        //
        if (priv_obj)
            obj_handle = bt_node_add(&tokdata->priv_token_obj_btree, obj);
        else
            obj_handle = bt_node_add(&tokdata->publ_token_obj_btree, obj);

        if (!obj_handle) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
    }

    rc = object_mgr_add_to_map(tokdata, sess, obj, obj_handle, handle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_add_to_map failed.\n");
        // this is messy but we need to remove the object from whatever
        // list we just added it to
        //
        if (sess_obj) {
            // put the binary tree node which holds obj on the free list, but
            // pass NULL here, so that obj (the binary tree node's value
            // pointer) isn't touched.
            // It is free'd by the caller of object_mgr_create_final
            bt_node_free(&tokdata->sess_obj_btree, obj_handle, FALSE);
        } else {
            delete_token_object(tokdata, obj);

            if (priv_obj) {
                // put the binary tree node which holds obj on the free list,
                // but pass NULL here, so that obj (the binary tree node's value
                // pointer) isn't touched. It is free'd by the caller of
                // object_mgr_create_final
                bt_node_free(&tokdata->priv_token_obj_btree, obj_handle, FALSE);
            } else {
                // put the binary tree node which holds obj on the free list,
                // but pass NULL here, so that obj (the binary tree node's value
                // pointer) isn't touched. It is free'd by the caller of
                // object_mgr_create_final
                bt_node_free(&tokdata->publ_token_obj_btree, obj_handle, FALSE);
            }

            object_mgr_del_from_shm(obj, tokdata->global_shm);
        }
    }

done:
    if (locked) {
        if (rc == CKR_OK) {
            rc = XProcUnLock(tokdata);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to release Process Lock.\n");
            }
        } else {
            /* return error that occurred first */
            XProcUnLock(tokdata);
        }
    }

    if (rc == CKR_OK)
        TRACE_DEVEL("Object created: handle: %lu\n", *handle);
    else if (fname[0] != '\0')
        remove(fname);

    return rc;
}

CK_RV object_mgr_destroy_object(STDLL_TokData_t *tokdata,
                                SESSION *sess, CK_OBJECT_HANDLE handle)
{
    CK_RV rc = CKR_OK;
    OBJECT_MAP *map;
    OBJECT *o = NULL;
    CK_BBOOL locked = FALSE;
    CK_BBOOL priv_obj;
    CK_BBOOL sess_obj;

    UNUSED(sess);

    rc = object_mgr_find_in_map1(tokdata, handle, &o, READ_LOCK);
    if (rc != CKR_OK || o == NULL) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
        return CKR_OBJECT_HANDLE_INVALID;
    }

    if (!object_is_destroyable(o)) {
        TRACE_ERROR("Object is not destroyable\n");
        object_put(tokdata, o, TRUE);
        o = NULL;
        return CKR_ACTION_PROHIBITED;
    }

    sess_obj = object_is_session_object(o);
    priv_obj = object_is_private(o);

    rc = object_mgr_check_session(sess, priv_obj, sess_obj);
    object_put(tokdata, o, TRUE);
    o = NULL;
    if (rc != CKR_OK)
        return rc;

    /* Don't use a delete callback, the map will be freed below */
    map = bt_node_free(&tokdata->object_map_btree, handle, FALSE);
    if (map == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
        return CKR_OBJECT_HANDLE_INVALID;
    }

    if (map->is_session_obj) {
        bt_node_free(&tokdata->sess_obj_btree, map->obj_handle, TRUE);
    } else {
        if (XProcLock(tokdata)) {
            TRACE_ERROR("Failed to get Process Lock.\n");
            return CKR_CANT_LOCK;
        }
        locked = TRUE;

        if (map->is_private)
            o = bt_get_node_value(&tokdata->priv_token_obj_btree,
                                  map->obj_handle);
        else
            o = bt_get_node_value(&tokdata->publ_token_obj_btree,
                                  map->obj_handle);

        if (!o) {
            rc = CKR_OBJECT_HANDLE_INVALID;
            goto done;
        }


        delete_token_object(tokdata, o);

        DUMP_SHM(tokdata->global_shm, "before");
        object_mgr_del_from_shm(o, tokdata->global_shm);
        DUMP_SHM(tokdata->global_shm, "after");

        if (map->is_private) {
            bt_put_node_value(&tokdata->priv_token_obj_btree, o);
            bt_node_free(&tokdata->priv_token_obj_btree, map->obj_handle, TRUE);
        } else {
            bt_put_node_value(&tokdata->publ_token_obj_btree, o);
            bt_node_free(&tokdata->publ_token_obj_btree, map->obj_handle, TRUE);
        }
        o = NULL;
    }

done:
    bt_put_node_value(&tokdata->object_map_btree, map);

    if (locked) {
        if (rc == CKR_OK) {
            rc = XProcUnLock(tokdata);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to release Process Lock.\n");
            }
        } else {
            /* return error that occurred first */
            XProcUnLock(tokdata);
        }
    }

    return rc;
}

/* delete_token_obj_cb
 *
 * Callback to delete an object if its a token object
 */
void delete_token_obj_cb(STDLL_TokData_t *tokdata, void *node,
                         unsigned long map_handle, void *p3)
{
    OBJECT_MAP *map = (OBJECT_MAP *) node;
    OBJECT *o = NULL;
    CK_BBOOL locked = FALSE;

    UNUSED(p3);

    if (!(map->is_session_obj)) {
        if (map->is_private)
            o = bt_get_node_value(&tokdata->priv_token_obj_btree,
                                  map->obj_handle);
        else
            o = bt_get_node_value(&tokdata->publ_token_obj_btree,
                                  map->obj_handle);

        if (!o)
            goto done;

        /* Use the same calling convention as the old code, if
         * XProcLock fails, don't delete from shm and don't free
         * the object in its other btree
         */
        if (XProcLock(tokdata)) {
            TRACE_ERROR("Failed to get Process Lock.\n");
            goto done;
        }
        locked = TRUE;

        delete_token_object(tokdata, o);

        object_mgr_del_from_shm(o, tokdata->global_shm);

        if (map->is_private) {
            bt_put_node_value(&tokdata->priv_token_obj_btree, o);
            bt_node_free(&tokdata->priv_token_obj_btree, map->obj_handle, TRUE);
        }
        else {
            bt_put_node_value(&tokdata->publ_token_obj_btree, o);
            bt_node_free(&tokdata->publ_token_obj_btree, map->obj_handle, TRUE);
        }
        o = NULL;
    }

done:
    if (o != NULL) {
        if (map->is_private)
            bt_put_node_value(&tokdata->priv_token_obj_btree, o);
        else
            bt_put_node_value(&tokdata->publ_token_obj_btree, o);
        o = NULL;
    }
    /* delete @node from this btree */
    bt_node_free(&tokdata->object_map_btree, map_handle, TRUE);

    if (locked) {
        if (XProcUnLock(tokdata)) {
            TRACE_ERROR("Failed to release Process Lock.\n");
        }
    }
}

// this routine will destroy all token objects in the system
//
CK_RV object_mgr_destroy_token_objects(STDLL_TokData_t *tokdata)
{
    CK_RV rc;

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get Process Lock.\n");
        goto done;
    }

    bt_for_each_node(tokdata, &tokdata->object_map_btree, delete_token_obj_cb,
                     NULL);

    // now we want to purge the token object list in shared memory
    //
    tokdata->global_shm->num_priv_tok_obj = 0;
    tokdata->global_shm->num_publ_tok_obj = 0;

    memset(&tokdata->global_shm->publ_tok_objs, 0x0,
           MAX_TOK_OBJS * sizeof(TOK_OBJ_ENTRY));
    memset(&tokdata->global_shm->priv_tok_objs, 0x0,
           MAX_TOK_OBJS * sizeof(TOK_OBJ_ENTRY));

    rc = XProcUnLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to release Process Lock.\n");
        goto done;
    }

done:
    return rc;
}





// object_mgr_find_in_map_nocache()
//
// Locates the specified object in the map
// without going and checking for cache update
//
// The returned Object must be put back (using object_put()) by the
// caller to decrease the reference count!
//
// The returned object is locked (depending on lock_type), and must be unlocked
// by the caller!
//
CK_RV object_mgr_find_in_map_nocache(STDLL_TokData_t *tokdata,
                                     CK_OBJECT_HANDLE handle, OBJECT **ptr,
                                     OBJ_LOCK_TYPE lock_type)
{
    OBJECT_MAP *map = NULL;
    OBJECT *obj = NULL;
    CK_RV rc = CKR_OK;


    if (!ptr) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    if (!handle) {
        TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
        return CKR_OBJECT_HANDLE_INVALID;
    }
    //
    // no mutex here.  the calling function should have locked the mutex
    //

    map = bt_get_node_value(&tokdata->object_map_btree, handle);
    if (!map) {
        TRACE_ERROR("%s handle: %lu\n", ock_err(ERR_OBJECT_HANDLE_INVALID),
                    handle);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    if (map->is_session_obj)
        obj = bt_get_node_value(&tokdata->sess_obj_btree, map->obj_handle);
    else if (map->is_private)
        obj = bt_get_node_value(&tokdata->priv_token_obj_btree, map->obj_handle);
    else
        obj = bt_get_node_value(&tokdata->publ_token_obj_btree, map->obj_handle);

    bt_put_node_value(&tokdata->object_map_btree, map);
    map = NULL;

    if (!obj) {
        TRACE_ERROR("%s handle: %lu\n", ock_err(ERR_OBJECT_HANDLE_INVALID),
                    handle);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    rc = object_lock(obj, lock_type);
    if (rc != CKR_OK) {
        object_put(tokdata, obj, FALSE);
        obj = NULL;
        return rc;
    }

    if (token_specific.t_check_obj_access != NULL) {
        rc = token_specific.t_check_obj_access(tokdata, obj, FALSE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("check_obj_access rejected access to object.\n");
            object_put(tokdata, obj, lock_type != NO_LOCK);
            obj = NULL;
            return rc;
        }
    }

    TRACE_DEVEL("Object found: handle: %lu\n", handle);
    *ptr = obj;

    return rc;
}

// object_mgr_find_in_map1()
//
// Locates the specified object in the map
//
// The returned Object must be put back (using object_put()) by the
// caller to decrease the reference count!
//
// The returned object is locked (depending on lock_type), and must be unlocked
// by the caller!
//
CK_RV object_mgr_find_in_map1(STDLL_TokData_t *tokdata,
                              CK_OBJECT_HANDLE handle, OBJECT **ptr,
                              OBJ_LOCK_TYPE lock_type)
{
    OBJECT_MAP *map = NULL;
    OBJECT *obj = NULL;
    CK_RV rc = CKR_OK;
    CK_BBOOL session_obj, locked = FALSE;

    if (!ptr) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    map = bt_get_node_value(&tokdata->object_map_btree, handle);
    if (!map) {
        TRACE_ERROR("%s handle: %lu\n", ock_err(ERR_OBJECT_HANDLE_INVALID),
                    handle);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    session_obj = map->is_session_obj;
    if (map->is_session_obj)
        obj = bt_get_node_value(&tokdata->sess_obj_btree, map->obj_handle);
    else if (map->is_private)
        obj = bt_get_node_value(&tokdata->priv_token_obj_btree, map->obj_handle);
    else
        obj = bt_get_node_value(&tokdata->publ_token_obj_btree, map->obj_handle);

    bt_put_node_value(&tokdata->object_map_btree, map);
    map = NULL;

    if (!obj) {
        TRACE_ERROR("%s handle: %lu\n", ock_err(ERR_OBJECT_HANDLE_INVALID),
                    handle);
        return CKR_OBJECT_HANDLE_INVALID;
    }

    /* SAB XXX Fix me.. need to make it more efficient than just looking
     * for the object to be changed. set a global flag that contains the
     * ref count to all objects.. if the shm ref count changes, then we
     * update the object. if not
     */

    /* Note: Each C_Initialize call loads up the public token objects
     * and build corresponding tree(s). The same for private token  objects
     * upon successful C_Login. Since token objects can be shared, it is
     * possible another process or session has deleted a token object.
     * Accounting is done in shm, so check shm to see if object still exists.
     */
    if (!session_obj) {
        /* object_mgr_check_shm() needs the object to hold the object lock */
        rc = object_lock(obj, lock_type);
        if (rc != CKR_OK)
            goto done;
        locked = TRUE;

        rc = object_mgr_check_shm(tokdata, obj, lock_type);
        if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_check_shm failed.\n");
            goto done;
        }
    }

    if (!locked) {
        rc = object_lock(obj, lock_type);
        if (rc != CKR_OK)
            goto done;
    }

    if (token_specific.t_check_obj_access != NULL) {
        rc = token_specific.t_check_obj_access(tokdata, obj, FALSE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("check_obj_access rejected access to object.\n");
            goto done;
        }
    }

done:
    if (rc == CKR_OK) {
        TRACE_DEVEL("Object found: handle: %lu\n", handle);
        *ptr = obj;
    } else {
        object_put(tokdata, obj, locked);
        obj = NULL;
    }

    return rc;
}

void find_obj_cb(STDLL_TokData_t *tokdata, void *node,
                 unsigned long map_handle, void *p3)
{
    OBJECT_MAP *map = (OBJECT_MAP *) node;
    OBJECT *obj;
    struct find_args *fa = (struct find_args *) p3;

    UNUSED(tokdata);

    if (fa->done)
        return;

    if (map->is_session_obj)
        obj = bt_get_node_value(&tokdata->sess_obj_btree, map->obj_handle);
    else if (map->is_private)
        obj = bt_get_node_value(&tokdata->priv_token_obj_btree, map->obj_handle);
    else
        obj = bt_get_node_value(&tokdata->publ_token_obj_btree, map->obj_handle);

    if (!obj)
        return;

    /* if this object is the one we're looking for (matches p3->obj), return
     * its map_handle in p3->map_handle */
    if (obj == fa->obj) {
        fa->map_handle = map_handle;
        fa->done = TRUE;
    }

    if (map->is_session_obj)
        bt_put_node_value(&tokdata->sess_obj_btree, obj);
    else if (map->is_private)
        bt_put_node_value(&tokdata->priv_token_obj_btree, obj);
    else
        bt_put_node_value(&tokdata->publ_token_obj_btree, obj);
    obj = NULL;
}

// object_mgr_find_in_map2()
//
// The caller must already have locked the passed object (READ_LOCK)!
//
CK_RV object_mgr_find_in_map2(STDLL_TokData_t *tokdata,
                              OBJECT *obj, CK_OBJECT_HANDLE *handle)
{
    struct find_args fa;
    CK_RV rc;

    if (!obj || !handle) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    fa.done = FALSE;
    fa.obj = obj;
    fa.map_handle = 0;

    // pass the fa structure with the values to operate on in the find_obj_cb
    // function
    bt_for_each_node(tokdata, &tokdata->object_map_btree, find_obj_cb, &fa);

    if (fa.done == FALSE || fa.map_handle == 0) {
        return CKR_OBJECT_HANDLE_INVALID;
    }

    *handle = fa.map_handle;

    if (!object_is_session_object(obj)) {
        rc = object_mgr_check_shm(tokdata, obj, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_check_shm failed.\n");
            return rc;
        }
    }

    return CKR_OK;
}

void find_build_list_cb(STDLL_TokData_t *tokdata, void *node,
                        unsigned long obj_handle, void *p3)
{
    OBJECT *obj = (OBJECT *) node;
    struct find_build_list_args *fa = (struct find_build_list_args *) p3;
    CK_OBJECT_HANDLE map_handle = CK_INVALID_HANDLE;
    CK_BBOOL match = FALSE, flag = FALSE;
    CK_OBJECT_HANDLE *find_list;
    CK_ULONG find_len;
    CK_OBJECT_CLASS class;
    CK_RV rc;

    if (object_lock(obj, READ_LOCK) != CKR_OK)
        return;

    if ((object_is_private(obj) == FALSE) || (fa->public_only == FALSE)) {
        // if the user doesn't specify any template attributes then we return
        // all objects
        //
        if (fa->pTemplate == NULL || fa->ulCount == 0)
            match = TRUE;
        else
            match = template_compare(fa->pTemplate, fa->ulCount, obj->template);
    }
    // if we have a match, find the object in the map (add it if necessary)
    // then add the object to the list of found objects //
    if (match) {
        rc = object_mgr_find_in_map2(tokdata, obj, &map_handle);
        if (rc != CKR_OK) {
            rc = object_mgr_add_to_map(tokdata, fa->sess, obj, obj_handle,
                                       &map_handle);
            if (rc != CKR_OK) {
                TRACE_DEVEL("object_mgr_add_to_map failed.\n");
                goto done;
            }
        }
        // If hw_feature is false here, we need to filter out all objects
        // that have the CKO_HW_FEATURE attribute set. - KEY
        if (fa->hw_feature == FALSE &&
            template_attribute_get_ulong(obj->template, CKA_CLASS,
                                         &class) == CKR_OK) {
             if (class == CKO_HW_FEATURE)
                goto done;
        }

        /* Don't find objects that have been created with the CKA_HIDDEN
         * attribute set */
        if (fa->hidden_object == FALSE &&
            template_attribute_get_bool(obj->template, CKA_HIDDEN,
                                        &flag) == CKR_OK) {
            if (flag == TRUE)
                goto done;
        }

        if (token_specific.t_check_obj_access != NULL) {
            rc = token_specific.t_check_obj_access(tokdata, obj, FALSE);
            if (rc != CKR_OK) {
                TRACE_DEVEL("check_obj_access rejected access to object.\n");
                goto done;
            }
        }

        fa->sess->find_list[fa->sess->find_count] = map_handle;
        fa->sess->find_count++;

        if (fa->sess->find_count >= fa->sess->find_len) {
            fa->sess->find_len += 15;
            find_len = fa->sess->find_len + 15;
            find_list = (CK_OBJECT_HANDLE *)realloc(fa->sess->find_list,
                                        find_len * sizeof(CK_OBJECT_HANDLE));
            if (!find_list) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                goto done;
            }
            fa->sess->find_list = find_list;
            fa->sess->find_len = find_len;
        }
    }

done:
    object_unlock(obj);
}

CK_RV object_mgr_find_init(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount)
{
    struct find_build_list_args fa;
    CK_OBJECT_CLASS class = 0;
    CK_BBOOL flag = FALSE;
    CK_RV rc;
    // it is possible the pTemplate == NULL
    //

    if (!sess) {
        TRACE_ERROR("Invalid function argument.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (sess->find_active != FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        return CKR_OPERATION_ACTIVE;
    }
    // initialize the found object list.  if it doesn't exist, allocate
    // a list big enough for 10 handles.  we'll reallocate if we need more
    //
    if (sess->find_list != NULL) {
        memset(sess->find_list, 0x0, sess->find_len * sizeof(CK_OBJECT_HANDLE));
    } else {
        sess->find_list =
            (CK_OBJECT_HANDLE *) malloc(10 * sizeof(CK_OBJECT_HANDLE));
        if (!sess->find_list) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        } else {
            memset(sess->find_list, 0x0, 10 * sizeof(CK_OBJECT_HANDLE));
            sess->find_len = 10;
        }
    }

    sess->find_count = 0;
    sess->find_idx = 0;

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get Process Lock.\n");
        return rc;
    }

    object_mgr_update_from_shm(tokdata);

    rc = XProcUnLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to release Process Lock.\n");
        return rc;
    }

    fa.hw_feature = FALSE;
    fa.hidden_object = FALSE;
    fa.sess = sess;
    fa.pTemplate = pTemplate;
    fa.ulCount = ulCount;

    // which objects can be returned:
    //
    //   Public Session:   public session objects, public token objects
    //   User Session:     all session objects,    all token objects
    //   SO session:       public session objects, public token objects
    //
    // PKCS#11 v2.11 (pg. 79): "When searching using C_FindObjectsInit
    // and C_FindObjects, hardware feature objects are not returned
    // unless the CKA_CLASS attribute in the template has the value
    // CKO_HW_FEATURE." So, we check for CKO_HW_FEATURE and if its set,
    // we'll find these objects below. - KEY
    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_CLASS, &class);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && class == CKO_HW_FEATURE)
        fa.hw_feature = TRUE;

    rc = get_bool_attribute_by_type(pTemplate, ulCount, CKA_HIDDEN, &flag);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && flag == TRUE)
        fa.hidden_object = TRUE;

    switch (sess->session_info.state) {
    case CKS_RO_PUBLIC_SESSION:
    case CKS_RW_PUBLIC_SESSION:
    case CKS_RW_SO_FUNCTIONS:
        fa.public_only = TRUE;

        bt_for_each_node(tokdata, &tokdata->publ_token_obj_btree,
                         find_build_list_cb, &fa);
        bt_for_each_node(tokdata, &tokdata->sess_obj_btree, find_build_list_cb,
                         &fa);
        break;
    case CKS_RO_USER_FUNCTIONS:
    case CKS_RW_USER_FUNCTIONS:
        fa.public_only = FALSE;

        bt_for_each_node(tokdata, &tokdata->priv_token_obj_btree,
                         find_build_list_cb, &fa);
        bt_for_each_node(tokdata, &tokdata->publ_token_obj_btree,
                         find_build_list_cb, &fa);
        bt_for_each_node(tokdata, &tokdata->sess_obj_btree, find_build_list_cb,
                         &fa);
        break;
    }

    sess->find_active = TRUE;

    return CKR_OK;
}

//
//
CK_RV object_mgr_find_final(SESSION *sess)
{
    if (!sess) {
        TRACE_ERROR("Invalid function argument.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (sess->find_active == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    free(sess->find_list);
    sess->find_list = NULL;
    sess->find_count = 0;
    sess->find_idx = 0;
    sess->find_active = FALSE;

    return CKR_OK;
}


//
//
CK_RV object_mgr_get_attribute_values(STDLL_TokData_t *tokdata,
                                      SESSION *sess,
                                      CK_OBJECT_HANDLE handle,
                                      CK_ATTRIBUTE *pTemplate,
                                      CK_ULONG ulCount)
{
    OBJECT *obj;
    CK_BBOOL priv_obj;
    CK_RV rc;

    if (!pTemplate) {
        TRACE_ERROR("Invalid function argument.\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_find_in_map1(tokdata, handle, &obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
        return rc;
    }
    priv_obj = object_is_private(obj);

    if (priv_obj == TRUE) {
        if (sess->session_info.state == CKS_RO_PUBLIC_SESSION ||
            sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
            TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
            rc = CKR_USER_NOT_LOGGED_IN;
            goto done;
        }
    }

    rc = object_get_attribute_values(obj, pTemplate, ulCount);
    if (rc != CKR_OK)
        TRACE_DEVEL("object_get_attribute_values failed.\n");

done:
    object_put(tokdata, obj, TRUE);
    obj = NULL;

    return rc;
}


//
//
CK_RV object_mgr_get_object_size(STDLL_TokData_t *tokdata,
                                 CK_OBJECT_HANDLE handle, CK_ULONG *size)
{
    OBJECT *obj;
    CK_RV rc;

    rc = object_mgr_find_in_map1(tokdata, handle, &obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
        return rc;
    }

    *size = object_get_size(obj);

    object_put(tokdata, obj, TRUE);
    obj = NULL;

    return rc;
}

void purge_session_obj_cb(STDLL_TokData_t *tokdata, void *node,
                          unsigned long obj_handle, void *p3)
{
    OBJECT *obj = (OBJECT *) node;
    struct purge_args *pa = (struct purge_args *) p3;
    CK_BBOOL del = FALSE;

    UNUSED(tokdata);

    if (obj->session == pa->sess) {
        if (object_lock(obj, READ_LOCK) != CKR_OK)
            return;

        if (pa->type == PRIVATE) {
            if (object_is_private(obj))
                del = TRUE;
        } else if (pa->type == PUBLIC) {
            if (object_is_public(obj))
                del = TRUE;
        } else if (pa->type == ALL) {
            del = TRUE;
        }

        object_unlock(obj);

        if (del == TRUE) {
            if (obj->map_handle)
                bt_node_free(&tokdata->object_map_btree, obj->map_handle, TRUE);

            bt_node_free(&tokdata->sess_obj_btree, obj_handle, TRUE);
        }
    }
}

// object_mgr_purge_session_objects()
//
// Args:    SESSION *
//          SESS_OBJ_TYPE:  can be ALL, PRIVATE or PUBLIC
//
// Remove all session objects owned by the specified session satisfying
// the 'type' requirements
//
CK_BBOOL object_mgr_purge_session_objects(STDLL_TokData_t *tokdata,
                                          SESSION *sess, SESS_OBJ_TYPE type)
{
    struct purge_args pa = { sess, type };

    UNUSED(tokdata);

    if (!sess)
        return FALSE;

    bt_for_each_node(tokdata, &tokdata->sess_obj_btree, purge_session_obj_cb,
                     &pa);

    return TRUE;
}

/* purge_token_obj_cb
 *
 * @p3 is the btree we're purging from
 */
void purge_token_obj_cb(STDLL_TokData_t *tokdata, void *node,
                        unsigned long obj_handle, void *p3)
{
    OBJECT *obj = (OBJECT *) node;
    struct btree *t = (struct btree *) p3;

    UNUSED(tokdata);

    if (obj->map_handle)
        bt_node_free(&tokdata->object_map_btree, obj->map_handle, TRUE);

    bt_node_free(t, obj_handle, TRUE);
}

// this routine cleans up the list of token objects. in general, we don't
// need to do this but when tracing memory leaks, it's best that we free
// everything that we've allocated
//
CK_BBOOL object_mgr_purge_token_objects(STDLL_TokData_t *tokdata)
{
    bt_for_each_node(tokdata, &tokdata->priv_token_obj_btree, purge_token_obj_cb,
                     &tokdata->priv_token_obj_btree);
    bt_for_each_node(tokdata, &tokdata->publ_token_obj_btree, purge_token_obj_cb,
                     &tokdata->publ_token_obj_btree);

    return TRUE;
}


CK_BBOOL object_mgr_purge_private_token_objects(STDLL_TokData_t *tokdata)
{
    bt_for_each_node(tokdata, &tokdata->priv_token_obj_btree, purge_token_obj_cb,
                     &tokdata->priv_token_obj_btree);

    return TRUE;
}

//
//
CK_RV object_mgr_restore_obj(STDLL_TokData_t *tokdata, CK_BYTE *data,
                             OBJECT *oldObj, const char *fname)
{
    return object_mgr_restore_obj_withSize(tokdata, data, oldObj, -1, fname);
}

//
//Modified verrsion of object_mgr_restore_obj to bounds check
//If data_size==-1, won't check bounds
CK_RV object_mgr_restore_obj_withSize(STDLL_TokData_t *tokdata, CK_BYTE *data,
                                      OBJECT *oldObj, int data_size,
                                      const char *fname)
{
    OBJECT *obj = NULL;
    CK_BBOOL priv;
    CK_RV rc, tmp;
    TOK_OBJ_ENTRY *entry = NULL;

    if (!data) {
        TRACE_ERROR("Invalid function argument.\n");
        return CKR_FUNCTION_FAILED;
    }
    // The calling stack MUST have the mutex
    // to many grab it now.

    obj = oldObj;
    rc = object_restore_withSize(tokdata->policy,
                                 data, &obj, oldObj != NULL, data_size, fname);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_restore_withSize failed.\n");
        return rc;
    }

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get Process Lock.\n");
        if (oldObj == NULL)
            object_free(obj);
        return rc;
    }

    if (oldObj != NULL) {
        /* Update of existing object */
        rc = object_mgr_get_shm_entry_for_obj(tokdata, obj, &entry);
        if (rc == CKR_OK) {
            obj->count_lo = entry->count_lo;
            obj->count_hi = entry->count_hi;
        }
    } else {
        /* New object */
        priv = object_is_private(obj);

        if (priv) {
            if (!bt_node_add(&tokdata->priv_token_obj_btree, obj)) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                object_free(obj);
                goto unlock;
            }
        } else {
            if (!bt_node_add(&tokdata->publ_token_obj_btree, obj)) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                object_free(obj);
                goto unlock;
            }
        }

        if (priv) {
            if (tokdata->global_shm->priv_loaded == FALSE) {
                if (tokdata->global_shm->num_priv_tok_obj < MAX_TOK_OBJS) {
                    object_mgr_add_to_shm(obj, tokdata->global_shm);
                } else {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    rc = CKR_HOST_MEMORY;
                    goto unlock;
                }
            } else {
                rc = object_mgr_get_shm_entry_for_obj(tokdata, obj, &entry);
                if (rc == CKR_OK) {
                    obj->count_lo = entry->count_lo;
                    obj->count_hi = entry->count_hi;
                }
            }
        } else {
            if (tokdata->global_shm->publ_loaded == FALSE) {
                if (tokdata->global_shm->num_publ_tok_obj < MAX_TOK_OBJS) {
                    object_mgr_add_to_shm(obj, tokdata->global_shm);
                } else {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    rc = CKR_HOST_MEMORY;
                    goto unlock;
                }
            } else {
                rc = object_mgr_get_shm_entry_for_obj(tokdata, obj, &entry);
                if (rc == CKR_OK) {
                    obj->count_lo = entry->count_lo;
                    obj->count_hi = entry->count_hi;
                }
            }
        }
    }

unlock:
    tmp = XProcUnLock(tokdata);
    if (tmp != CKR_OK)
        TRACE_ERROR("Failed to release Process Lock.\n");
    if (rc == CKR_OK)
        rc = tmp;

    return rc;
}

/**
 * Save the token object to disk and update the shared memory segment.
 */
CK_RV object_mgr_save_token_object(STDLL_TokData_t *tokdata, OBJECT *obj)
{
    TOK_OBJ_ENTRY *entry = NULL;
    CK_ULONG index;
    CK_RV rc;

    obj->count_lo++;
    if (obj->count_lo == 0)
        obj->count_hi++;

    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get Process Lock.\n");
        goto done;
    }

    if (object_is_private(obj)) {
        if (tokdata->global_shm->num_priv_tok_obj == 0) {
            TRACE_DEVEL("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
            rc = CKR_OBJECT_HANDLE_INVALID;
            XProcUnLock(tokdata);
            goto done;
        }
        rc = object_mgr_search_shm_for_obj(tokdata->global_shm->
                                           priv_tok_objs, 0,
                                           tokdata->global_shm->
                                           num_priv_tok_obj - 1, obj,
                                           &index);

        if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_search_shm_for_obj failed.\n");
            XProcUnLock(tokdata);
            goto done;
        }

        entry = &tokdata->global_shm->priv_tok_objs[index];
    } else {
        if (tokdata->global_shm->num_publ_tok_obj == 0) {
            TRACE_DEVEL("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
            rc = CKR_OBJECT_HANDLE_INVALID;
            XProcUnLock(tokdata);
            goto done;
        }
        rc = object_mgr_search_shm_for_obj(tokdata->global_shm->
                                           publ_tok_objs, 0,
                                           tokdata->global_shm->
                                           num_publ_tok_obj - 1, obj,
                                           &index);
        if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_search_shm_for_obj failed.\n");
            XProcUnLock(tokdata);
            goto done;
        }

        entry = &tokdata->global_shm->publ_tok_objs[index];
    }

    rc = save_token_object(tokdata, obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to save token object, rc=0x%lx.\n",rc);
        XProcUnLock(tokdata);
        goto done;
    }

    entry->count_lo = obj->count_lo;
    entry->count_hi = obj->count_hi;

    rc = XProcUnLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to release Process Lock.\n");
        goto done;
    }

done:
    return rc;
}

static CK_BBOOL modifiable_override(CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount)
{
    CK_ULONG i, k;
    CK_BBOOL found;

    const CK_ATTRIBUTE_TYPE always_modifiable_attrs[] = {
       CKA_IBM_OPAQUE,
       CKA_IBM_OPAQUE_REENC,
       CKA_IBM_OPAQUE_OLD,
    };

    if (!token_specific.secure_key_token)
        return CK_FALSE;

    /* Check if template only contains always modifiable attrs */
    for (i = 0; i < ulCount; i++) {
        found = CK_FALSE;
        for (k = 0; k < sizeof(always_modifiable_attrs) /
                                        sizeof(CK_ATTRIBUTE_TYPE); k++) {
            if (pTemplate[i].type == always_modifiable_attrs[k]) {
                found = CK_TRUE;
                break;
            }
        }

        if (!found)
            return CK_FALSE;
    }

    return CK_TRUE;
}

//
//
CK_RV object_mgr_set_attribute_values(STDLL_TokData_t *tokdata,
                                      SESSION *sess,
                                      CK_OBJECT_HANDLE handle,
                                      CK_ATTRIBUTE *pTemplate,
                                      CK_ULONG ulCount)
{
    OBJECT *obj;
    CK_BBOOL sess_obj, priv_obj;
    CK_BBOOL modifiable;
    CK_RV rc;


    if (!pTemplate) {
        TRACE_ERROR("Invalid function argument.\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_find_in_map1(tokdata, handle, &obj, WRITE_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
        return rc;
    }
    // determine whether the session is allowed to modify the object
    //
    modifiable = object_is_modifiable(obj);
    sess_obj = object_is_session_object(obj);
    priv_obj = object_is_private(obj);

    // if object is not modifiable, it doesn't matter what kind of session
    // is issuing the request...
    //
    if (!modifiable && !modifiable_override(pTemplate, ulCount)) {
        TRACE_ERROR("Object is not modifiable\n");
        rc = CKR_ACTION_PROHIBITED;
        goto done;
    }

    rc = object_mgr_check_session(sess, priv_obj, sess_obj);
    if (rc != CKR_OK)
        goto done;

    rc = object_set_attribute_values(tokdata, sess, obj, pTemplate, ulCount);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_set_attribute_values failed.\n");
        goto done;
    }
    // okay.  the object has been updated.  if it's a session object,
    // we're finished.  if it's a token object, we need to update
    // non-volatile storage.
    //
    if (!sess_obj) {
        rc = object_mgr_save_token_object(tokdata, obj);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to save token object, rc=%lx.\n",rc);
            goto done;
        }
    }

    TRACE_DEBUG("Attributes after set:\n");
    TRACE_DEBUG_DUMPTEMPL(obj->template);

done:
    object_put(tokdata, obj, TRUE);
    obj = NULL;

    return rc;
}


//
//
void object_mgr_add_to_shm(OBJECT *obj, LW_SHM_TYPE *global_shm)
{
    // TODO: Can't this function fail?
    TOK_OBJ_ENTRY *entry = NULL;
    CK_BBOOL priv;

    // the calling routine is responsible for locking the global_shm mutex
    //
    priv = object_is_private(obj);

    if (priv)
        entry = &global_shm->priv_tok_objs[global_shm->num_priv_tok_obj];
    else
        entry = &global_shm->publ_tok_objs[global_shm->num_publ_tok_obj];

    entry->deleted = FALSE;
    entry->count_lo = 0;
    entry->count_hi = 0;
    memcpy(entry->name, obj->name, 8);

    if (priv)
        global_shm->num_priv_tok_obj++;
    else
        global_shm->num_publ_tok_obj++;

    return;
}


//
//
CK_RV object_mgr_del_from_shm(OBJECT *obj, LW_SHM_TYPE *global_shm)
{
    CK_ULONG index, count;
    CK_BBOOL priv;
    CK_RV rc;


    // the calling routine is responsible for locking the global_shm mutex
    //

    priv = object_is_private(obj);

    if (priv) {
        if (global_shm->num_priv_tok_obj == 0) {
            TRACE_DEVEL("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
            return CKR_OBJECT_HANDLE_INVALID;
        }
        rc = object_mgr_search_shm_for_obj(global_shm->priv_tok_objs,
                                           0, global_shm->num_priv_tok_obj - 1,
                                           obj, &index);
        if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_search_shm_for_obj failed.\n");
            return rc;
        }
        // Since the number of objects starts at 1 and index starts at zero, we
        // decrement before we get count.  This eliminates the need to perform
        // this operation later as well as decrementing the number of objects.
        // (i.e. If we have 10 objects, num will be 10 but the last index is 9.
        // If we want to delete the last object we need to subtract 9 from 9 not
        // 10 from 9.)
        //
        global_shm->num_priv_tok_obj--;
        if (index > global_shm->num_priv_tok_obj) {
            count = index - global_shm->num_priv_tok_obj;
        } else {
            count = global_shm->num_priv_tok_obj - index;
        }

        if (count > 0) {
            // If we aren't deleting the last element in the list
            // Move up count number of elements effectively deleting the index
            // NB: memmove is required since the copied regions may overlap
            memmove((char *) &global_shm->priv_tok_objs[index],
                    (char *) &global_shm->priv_tok_objs[index + 1],
                    sizeof(TOK_OBJ_ENTRY) * count);
            // We need to zero out the last entry... Since the memcopy
            // does not zero it out...
            memset((char *) &global_shm->
                   priv_tok_objs[global_shm->num_priv_tok_obj + 1], 0,
                   sizeof(TOK_OBJ_ENTRY));
        } else {
            // We are deleting the last element which is in num_priv_tok_obj
            memset((char *) &global_shm->
                   priv_tok_objs[global_shm->num_priv_tok_obj], 0,
                   sizeof(TOK_OBJ_ENTRY));
        }
    } else {
        if (global_shm->num_publ_tok_obj == 0) {
            TRACE_DEVEL("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
            return CKR_OBJECT_HANDLE_INVALID;
        }
        rc = object_mgr_search_shm_for_obj(global_shm->publ_tok_objs,
                                           0, global_shm->num_publ_tok_obj - 1,
                                           obj, &index);
        if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_search_shm_for_obj failed.\n");
            return rc;
        }
        global_shm->num_publ_tok_obj--;


        if (index > global_shm->num_publ_tok_obj) {
            count = index - global_shm->num_publ_tok_obj;
        } else {
            count = global_shm->num_publ_tok_obj - index;
        }

        if (count > 0) {
            // NB: memmove is required since the copied regions may overlap
            memmove((char *) &global_shm->publ_tok_objs[index],
                    (char *) &global_shm->publ_tok_objs[index + 1],
                    sizeof(TOK_OBJ_ENTRY) * count);
            // We need to zero out the last entry... Since the memcopy
            // does not zero it out...
            memset((char *) &global_shm->
                   publ_tok_objs[global_shm->num_publ_tok_obj + 1], 0,
                   sizeof(TOK_OBJ_ENTRY));
        } else {
            memset((char *) &global_shm->
                   publ_tok_objs[global_shm->num_publ_tok_obj], 0,
                   sizeof(TOK_OBJ_ENTRY));
        }
    }

    return CKR_OK;
}

CK_RV object_mgr_get_shm_entry_for_obj(STDLL_TokData_t *tokdata, OBJECT *obj,
                                       TOK_OBJ_ENTRY **entry)
{
    CK_ULONG index;
    CK_RV rc;

    *entry = NULL;

    if (object_is_private(obj)) {
        /* first check the object count. If it is 0, then just return. */
        if (tokdata->global_shm->num_priv_tok_obj == 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
            return CKR_OBJECT_HANDLE_INVALID;
        }
        rc = object_mgr_search_shm_for_obj(tokdata->global_shm->priv_tok_objs,
                                           0,
                                           tokdata->global_shm->
                                           num_priv_tok_obj - 1, obj, &index);
        if (rc != CKR_OK) {
            TRACE_ERROR("object_mgr_search_shm_for_obj failed.\n");
            return rc;
        }
        *entry = &tokdata->global_shm->priv_tok_objs[index];
    } else {
        /* first check the object count. If it is 0, then just return. */
        if (tokdata->global_shm->num_publ_tok_obj == 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
            return CKR_OBJECT_HANDLE_INVALID;
        }
        rc = object_mgr_search_shm_for_obj(tokdata->global_shm->publ_tok_objs,
                                           0,
                                           tokdata->global_shm->num_publ_tok_obj
                                           - 1,
                                           obj, &index);
        if (rc != CKR_OK) {
            TRACE_ERROR("object_mgr_search_shm_for_obj failed.\n");
            return rc;
        }
        *entry = &tokdata->global_shm->publ_tok_objs[index];
    }

    return CKR_OK;
}


// The object must hold the READ or WRITE lock when this function is called!
//
CK_RV object_mgr_check_shm(STDLL_TokData_t *tokdata, OBJECT *obj,
                           OBJ_LOCK_TYPE lock_type)
{
    TOK_OBJ_ENTRY *entry = NULL;
    CK_BBOOL rd_locked = FALSE, wr_locked = FALSE;
    CK_RV rc;

    switch (lock_type) {
    case READ_LOCK:
        rd_locked = TRUE;
        break;
    case WRITE_LOCK:
        wr_locked = TRUE;
        break;
    case NO_LOCK:
        TRACE_ERROR("Function must be called with READ or WRITE lock.\n");
        return CKR_FUNCTION_FAILED;
    }

retry:
    rc = XProcLock(tokdata);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to get Process Lock.\n");
       goto done_no_xproc_unlock;
    }

    rc = object_mgr_get_shm_entry_for_obj(tokdata, obj, &entry);
    if (rc != CKR_OK)
        goto done;

    if ((obj->count_hi == entry->count_hi)
        && (obj->count_lo == entry->count_lo)) {
        rc = CKR_OK;
        goto done;
    }

    /* We need to acquire the WRITE lock on the object because we are modifying
     * the attributes. Since the object already holds the READ lock, we need to
     * unlock it first, then get the WRITE lock, and finally unlock again and
     * get the READ lock again. The caller assumes that the object still holds
     * the READ lock when we return.
     *
     * We must not hold the XProcLock when trying to get the WRITE lock on the
     * Objects. This might cause a deadlock, if another thread holds a READ or
     * WRITE lock on the object, and is also trying to get the XProcLock.
     */

    if (rd_locked) {
        rc = object_unlock(obj);
        if (rc != CKR_OK)
            goto done;
        rd_locked = FALSE;
    }

    if (!wr_locked) {
        /* Try to get the WRITE lock, although we hold the XProcLock. If we get
         * it we take the fast path, if not, we release the XProcLock, then get
         * the WRITE lock and then get the XProcLock again. Since we have
         * released the XProcLock, we then need to re-do the SHM checking.
         */
        if (pthread_rwlock_trywrlock(&obj->template_rwlock) != 0) {
            /* Did not get the WRITE lock */
            rc = XProcUnLock(tokdata);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to release Process Lock.\n");
                goto done;
            }

            rc = object_lock(obj, WRITE_LOCK);
            if (rc != CKR_OK)
                goto done;
            wr_locked = TRUE;

            goto retry;
        }

        wr_locked = TRUE;
    }

    /* If we reach here, we do have the WRITE lock on the object */

    rc = reload_token_object(tokdata, obj);
    if (rc != CKR_OK)
        goto done;

    rc = object_ex_data_lock(obj, WRITE_LOCK);
    if (rc != CKR_OK)
        goto done;

    if (obj->ex_data != NULL && obj->ex_data_reload != NULL) {
        rc = obj->ex_data_reload(obj, obj->ex_data, obj->ex_data_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("ex_data_reload failed 0x%lx\n", rc);
            object_ex_data_unlock(obj);
            goto done;
        }
    }

    rc = object_ex_data_unlock(obj);
    if (rc != CKR_OK)
        goto done;

    if (lock_type == READ_LOCK) {
        rc = object_unlock(obj);
        if (rc != CKR_OK)
            goto done;
        wr_locked = FALSE;
        /* Re-acquire the READ lock only after we have released the XProcLock! */
    }

done:
    if (rc == CKR_OK) {
        rc = XProcUnLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to release Process Lock.\n");
        }
    } else {
        XProcUnLock(tokdata);
    }

done_no_xproc_unlock:
    if (lock_type == READ_LOCK && wr_locked)
        object_unlock(obj);
    if (lock_type == READ_LOCK && !rd_locked) {
        if (rc == CKR_OK)
            rc = object_lock(obj, READ_LOCK);
        else
            object_lock(obj, READ_LOCK);
    }

    return rc;
}


// I'd use the standard bsearch() routine but I want an index, not a pointer.
// Converting the pointer to an index might cause problems when switching
// to a 64-bit environment...
//
CK_RV object_mgr_search_shm_for_obj(TOK_OBJ_ENTRY *obj_list,
                                    CK_ULONG lo,
                                    CK_ULONG hi, OBJECT *obj, CK_ULONG *index)
{
// SAB  XXX reduce the search time since this is what seems to be burning cycles
    CK_ULONG idx;

    UNUSED(lo);

    if (obj->index == 0) {
        for (idx = 0; idx <= hi; idx++) {
            if (memcmp(obj->name, obj_list[idx].name, 8) == 0) {
                *index = idx;
                obj->index = idx;
                return CKR_OK;
            }
        }
    } else {
        // SAB better double check
        if (memcmp(obj->name, obj_list[obj->index].name, 8) == 0) {
            *index = obj->index;
            return CKR_OK;
        } else {
            // something is hosed.. go back to the brute force method
            for (idx = 0; idx <= hi; idx++) {
                if (memcmp(obj->name, obj_list[idx].name, 8) == 0) {
                    *index = idx;
                    obj->index = idx;
                    return CKR_OK;
                }
            }
        }
    }

    TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));

    return CKR_OBJECT_HANDLE_INVALID;
}

// this routine scans the local token object lists and updates any objects that
// have changed. it also adds any new token objects that have been added by
// other processes and deletes any objects that have been deleted by other
// processes
//
CK_RV object_mgr_update_from_shm(STDLL_TokData_t *tokdata)
{
    object_mgr_update_publ_tok_obj_from_shm(tokdata);
    object_mgr_update_priv_tok_obj_from_shm(tokdata);

    return CKR_OK;
}

void delete_objs_from_btree_cb(STDLL_TokData_t *tokdata, void *node,
                               unsigned long obj_handle, void *p3)
{
    struct update_tok_obj_args *ua = (struct update_tok_obj_args *) p3;
    TOK_OBJ_ENTRY *shm_te = NULL;
    OBJECT *obj = (OBJECT *) node;
    CK_ULONG index;

    UNUSED(tokdata);

    /* for each TOK_OBJ_ENTRY in the SHM list */
    for (index = 0; index < *(ua->num_entries); index++) {
        shm_te = &(ua->entries[index]);

        /* found it, return */
        if (!memcmp(obj->name, shm_te->name, 8)) {
            return;
        }
    }

    /* didn't find it in SHM, delete it from its btree and the object map */
    bt_node_free(&tokdata->object_map_btree, obj->map_handle, TRUE);
    bt_node_free(ua->t, obj_handle, TRUE);
}

void find_by_name_cb(STDLL_TokData_t *tokdata, void *node,
                     unsigned long obj_handle, void *p3)
{
    OBJECT *obj = (OBJECT *) node;
    struct find_by_name_args *fa = (struct find_by_name_args *) p3;

    UNUSED(tokdata);
    UNUSED(obj_handle);

    if (fa->done)
        return;

    if (!memcmp(obj->name, fa->name, 8)) {
        fa->done = TRUE;
    }
}

CK_RV object_mgr_update_publ_tok_obj_from_shm(STDLL_TokData_t *tokdata)
{
    struct update_tok_obj_args ua;
    struct find_by_name_args fa;
    TOK_OBJ_ENTRY *shm_te = NULL;
    CK_ULONG index;
    OBJECT *new_obj;
    CK_RV rc;

    ua.entries = tokdata->global_shm->publ_tok_objs;
    ua.num_entries = &(tokdata->global_shm->num_publ_tok_obj);
    ua.t = &tokdata->publ_token_obj_btree;

    /* delete any objects not in SHM from the btree */
    bt_for_each_node(tokdata, &tokdata->publ_token_obj_btree,
                     delete_objs_from_btree_cb, &ua);

    /* for each item in SHM, add it to the btree if its not there */
    for (index = 0; index < tokdata->global_shm->num_publ_tok_obj; index++) {
        shm_te = &tokdata->global_shm->publ_tok_objs[index];

        fa.done = FALSE;
        fa.name = shm_te->name;

        /* find an object from SHM in the btree */
        bt_for_each_node(tokdata, &tokdata->publ_token_obj_btree,
                         find_by_name_cb, &fa);

        /* we didn't find it in the btree, so add it */
        if (fa.done == FALSE) {
            new_obj = (OBJECT *) malloc(sizeof(OBJECT));
            if (new_obj == NULL)
                return CKR_HOST_MEMORY;
            memset(new_obj, 0x0, sizeof(OBJECT));

            rc = object_init_lock(new_obj);
            if (rc != CKR_OK) {
                free(new_obj);
                continue;
            }

            rc = object_init_ex_data_lock(new_obj);
            if (rc != CKR_OK) {
                object_destroy_lock(new_obj);
                free(new_obj);
                continue;
            }

            memcpy(new_obj->name, shm_te->name, 8);
            rc = reload_token_object(tokdata, new_obj);
            if (rc == CKR_OK)
                bt_node_add(&tokdata->publ_token_obj_btree, new_obj);
            else
                object_free(new_obj);
        }
    }

    return CKR_OK;
}

CK_RV object_mgr_update_priv_tok_obj_from_shm(STDLL_TokData_t *tokdata)
{
    struct update_tok_obj_args ua;
    struct find_by_name_args fa;
    TOK_OBJ_ENTRY *shm_te = NULL;
    CK_ULONG index;
    OBJECT *new_obj;
    CK_RV rc;

    // SAB XXX don't bother doing this call if we are not in the correct
    // login state
    if (!session_mgr_user_session_exists(tokdata))
        return CKR_OK;

    ua.entries = tokdata->global_shm->priv_tok_objs;
    ua.num_entries = &(tokdata->global_shm->num_priv_tok_obj);
    ua.t = &tokdata->priv_token_obj_btree;

    /* delete any objects not in SHM from the btree */
    bt_for_each_node(tokdata, &tokdata->priv_token_obj_btree, delete_objs_from_btree_cb,
                     &ua);

    /* for each item in SHM, add it to the btree if its not there */
    for (index = 0; index < tokdata->global_shm->num_priv_tok_obj; index++) {
        shm_te = &tokdata->global_shm->priv_tok_objs[index];

        fa.done = FALSE;
        fa.name = shm_te->name;

        /* find an object from SHM in the btree */
        bt_for_each_node(tokdata, &tokdata->priv_token_obj_btree, find_by_name_cb, &fa);

        /* we didn't find it in the btree, so add it */
        if (fa.done == FALSE) {
            new_obj = (OBJECT *) malloc(sizeof(OBJECT));
            if (new_obj == NULL)
                return CKR_HOST_MEMORY;
            memset(new_obj, 0x0, sizeof(OBJECT));

            rc = object_init_lock(new_obj);
            if (rc != CKR_OK) {
                free(new_obj);
                continue;
            }

            rc = object_init_ex_data_lock(new_obj);
            if (rc != CKR_OK) {
                object_destroy_lock(new_obj);
                free(new_obj);
                continue;
            }

            memcpy(new_obj->name, shm_te->name, 8);
            rc = reload_token_object(tokdata, new_obj);
            if (rc == CKR_OK)
                bt_node_add(&tokdata->priv_token_obj_btree, new_obj);
            else
                object_free(new_obj);
        }
    }

    return CKR_OK;
}

// SAB FIXME FIXME

void purge_map_by_type_cb(STDLL_TokData_t *tokdata, void *node,
                          unsigned long map_handle, void *p3)
{
    OBJECT_MAP *map = (OBJECT_MAP *) node;
    SESS_OBJ_TYPE type = *(SESS_OBJ_TYPE *) p3;

    if (type == PRIVATE) {
        if (map->is_private) {
            bt_node_free(&tokdata->object_map_btree, map_handle, TRUE);
        }
    } else if (type == PUBLIC) {
        if (!map->is_private) {
            bt_node_free(&tokdata->object_map_btree, map_handle, TRUE);
        }
    }
}

CK_BBOOL object_mgr_purge_map(STDLL_TokData_t *tokdata,
                              SESSION *sess, SESS_OBJ_TYPE type)
{
    UNUSED(sess);

    bt_for_each_node(tokdata, &tokdata->object_map_btree, purge_map_by_type_cb, &type);
    return TRUE;
}

/* Put back the object using its btree */
CK_RV object_put(STDLL_TokData_t *tokdata, OBJECT *obj, CK_BBOOL unlock)
{
    CK_BBOOL sess, priv;
    CK_RV rc;

    if (obj == NULL)
        return CKR_OBJECT_HANDLE_INVALID;

    if (!unlock) {
        rc = object_lock(obj, READ_LOCK);
        if (rc != CKR_OK)
            return rc;
    }

    sess = object_is_session_object(obj);
    priv = object_is_private(obj);

    rc = object_unlock(obj);
    if (rc != CKR_OK)
        return rc;

    if (sess)
       bt_put_node_value(&tokdata->sess_obj_btree, obj);
    else if (priv)
        bt_put_node_value(&tokdata->priv_token_obj_btree, obj);
    else
        bt_put_node_value(&tokdata->publ_token_obj_btree, obj);

    return CKR_OK;
}

#ifdef DEBUG
void dump_shm(LW_SHM_TYPE *global_shm, const char *s)
{
    CK_ULONG i;
    TRACE_DEBUG("%s: dump_shm priv:\n", s);

    for (i = 0; i < global_shm->num_priv_tok_obj; i++) {
        TRACE_DEBUG("[%lu]: %.8s\n", i, global_shm->priv_tok_objs[i].name);
    }
    TRACE_DEBUG("%s: dump_shm publ:\n", s);
    for (i = 0; i < global_shm->num_publ_tok_obj; i++) {
        TRACE_DEBUG("[%lu]: %.8s\n", i, global_shm->publ_tok_objs[i].name);
    }
}
#endif

/*
 * Re-enciphers a key that has a secure key in attribute CKA_IBM_OPAQUE by
 * calling the reenc callback function.
 * Returns CKR_ATTRIBUTE_TYPE_INVALID if the key does not contain a secure key.
 * The object must hold the WRITE lock when this function is called!
 */
CK_RV obj_mgr_reencipher_secure_key(STDLL_TokData_t *tokdata, OBJECT *obj,
                                    CK_RV (*reenc)(CK_BYTE *sec_key,
                                                   CK_BYTE *reenc_sec_key,
                                                   CK_ULONG sec_key_len,
                                                   void *private),
                                    void *private)
{
    CK_ATTRIBUTE *opaque_attr = NULL, *reenc_attr = NULL;
    CK_KEY_TYPE key_type;
    CK_RV rc;

    /* Update token object from SHM, if needed */
    if (object_is_token_object(obj)) {
        rc = object_mgr_check_shm(tokdata, obj, WRITE_LOCK);
        if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_check_shm failed.\n");
            goto out;
        }
    }

    if (template_attribute_get_ulong(obj->template, CKA_KEY_TYPE, &key_type)
                                                                != CKR_OK) {
        rc = CKR_ATTRIBUTE_TYPE_INVALID;
        goto out;
    }

    if (!template_attribute_find(obj->template, CKA_IBM_OPAQUE, &opaque_attr)) {
        rc = CKR_ATTRIBUTE_TYPE_INVALID;
        goto out;
    }

    rc = build_attribute(CKA_IBM_OPAQUE_REENC, opaque_attr->pValue,
                         opaque_attr->ulValueLen, &reenc_attr);
    if (rc != CKR_OK)
        goto out;

    if (key_type == CKK_AES_XTS) {
        /*
         * AES-XTS has 2 secure keys concatenated to each other.
         * Re-encipher both keys separately.
         */
        rc = reenc(opaque_attr->pValue, reenc_attr->pValue,
                   reenc_attr->ulValueLen / 2, private);
        if (rc != CKR_OK) {
            TRACE_ERROR("Reencipher callback has failed, rc=0x%lx.\n",rc);
            goto out;
        }

        rc = reenc((CK_BYTE *)opaque_attr->pValue + reenc_attr->ulValueLen / 2,
                   reenc_attr->pValue, reenc_attr->ulValueLen / 2,
                   private);
        if (rc != CKR_OK) {
            TRACE_ERROR("Reencipher callback has failed, rc=0x%lx.\n",rc);
            goto out;
        }
    } else {
        rc = reenc(opaque_attr->pValue, reenc_attr->pValue, reenc_attr->ulValueLen,
                   private);
        if (rc != CKR_OK) {
            TRACE_ERROR("Reencipher callback has failed, rc=0x%lx.\n",rc);
            goto out;
        }
    }

    rc = template_update_attribute(obj->template, reenc_attr);
    if (rc != CKR_OK)
        goto out;
    reenc_attr = NULL;

    if (!object_is_session_object(obj)) {
        rc = object_mgr_save_token_object(tokdata, obj);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to save token object, rc=%lx.\n",rc);
            goto out;
        }
    }

out:
    if (reenc_attr != NULL)
        free(reenc_attr);

    return rc;
}

/*
 * Moves the re-enciphered secure key from attribute CKA_IBM_OPAQUE_REENC to
 * CKA_IBM_OPAQUE, and the previous secure key from CKA_IBM_OPAQUE to
 * CKA_IBM_OPAQUE_OLD.
 * If the is_blob_new_mk_cb callback function is specified, then it is called to
 * determine if the key blob in CKA_IBM_OPAQUE is already enciphered with the
 * new master key. If it returns TRUE, then the key blob from CKA_IBM_OPAQUE
 * is not moved to CKA_IBM_OPAQUE_OLD, and CKA_IBM_OPAQUE_REENC is removed.
 * Returns CKR_ATTRIBUTE_TYPE_INVALID if the key does not contain a secure key.
 * The object must hold the WRITE lock when this function is called!
 */
CK_RV obj_mgr_reencipher_secure_key_finalize(STDLL_TokData_t *tokdata,
                                             OBJECT *obj,
                                             CK_BBOOL is_blob_new_mk_cb(
                                                 STDLL_TokData_t *tokdata,
                                                 OBJECT *obj,
                                                 CK_BYTE *sec_key,
                                                 CK_ULONG sec_key_len,
                                                 void *cb_private),
                                             void *cb_private)
{
    CK_ATTRIBUTE *opaque_attr = NULL, *old_attr = NULL, *reenc_attr = NULL;
    CK_ATTRIBUTE *new_opaque_attr = NULL;
    CK_KEY_TYPE key_type;
    CK_RV rc;

    /* Update token object from SHM, if needed */
    if (object_is_token_object(obj)) {
        rc = object_mgr_check_shm(tokdata, obj, WRITE_LOCK);
        if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_check_shm failed.\n");
            goto out;
        }
    }

    if (template_attribute_get_ulong(obj->template, CKA_KEY_TYPE, &key_type)
                                                                != CKR_OK) {
        rc = CKR_ATTRIBUTE_TYPE_INVALID;
        goto out;
    }

    if (!template_attribute_find(obj->template, CKA_IBM_OPAQUE_REENC,
                                 &reenc_attr)) {
        rc = CKR_ATTRIBUTE_TYPE_INVALID;
        goto out;
    }

    if (!template_attribute_find(obj->template, CKA_IBM_OPAQUE, &opaque_attr)) {
        rc = CKR_ATTRIBUTE_TYPE_INVALID;
        goto out;
    }

    if (is_blob_new_mk_cb != NULL &&
        is_blob_new_mk_cb(tokdata, obj, opaque_attr->pValue,
                          key_type == CKK_AES_XTS ?
                                              opaque_attr->ulValueLen / 2 :
                                              opaque_attr->ulValueLen,
                          cb_private) == TRUE) {
        TRACE_DEVEL("is_blob_new_mk_cb returned TRUE, don't move blobs\n");

        rc = template_remove_attribute(obj->template, CKA_IBM_OPAQUE_REENC);
        if (rc == CKR_ATTRIBUTE_TYPE_INVALID)
            rc = CKR_OK;
        if (rc != CKR_OK)
            goto out;

        goto remove;
    }

    rc = build_attribute(CKA_IBM_OPAQUE_OLD, opaque_attr->pValue,
                         opaque_attr->ulValueLen, &old_attr);
    if (rc != CKR_OK)
        goto out;

    rc = template_update_attribute(obj->template, old_attr);
    if (rc != CKR_OK)
        goto out;
    old_attr = NULL;

    rc = build_attribute(CKA_IBM_OPAQUE, reenc_attr->pValue,
                         reenc_attr->ulValueLen, &new_opaque_attr);
    if (rc != CKR_OK)
        goto out;

    rc = template_update_attribute(obj->template, new_opaque_attr);
    if (rc != CKR_OK)
        goto out;
    new_opaque_attr = NULL;

remove:
    rc = template_remove_attribute(obj->template, CKA_IBM_OPAQUE_REENC);
    if (rc == CKR_ATTRIBUTE_TYPE_INVALID)
        rc = CKR_OK;
    if (rc != CKR_OK)
        goto out;

    if (!object_is_session_object(obj)) {
        rc = object_mgr_save_token_object(tokdata, obj);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to save token object, rc=%lx.\n", rc);
            goto out;
        }
    }

out:
    if (old_attr != NULL)
        free(old_attr);
    if (new_opaque_attr != NULL)
        free(new_opaque_attr);

    return rc;
}

/*
 * Removes the re-enciphered secure key from attribute CKA_IBM_OPAQUE_REENC
 * and also CKA_IBM_OPAQUE_OLD.
 * Returns CKR_ATTRIBUTE_TYPE_INVALID if the key does not contain a secure key.
 * The object must hold the WRITE lock when this function is called!
 */
CK_RV obj_mgr_reencipher_secure_key_cancel(STDLL_TokData_t *tokdata,
                                           OBJECT *obj)
{
    CK_RV rc;

    /* Update token object from SHM, if needed */
    if (object_is_token_object(obj)) {
        rc = object_mgr_check_shm(tokdata, obj, WRITE_LOCK);
        if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_check_shm failed.\n");
            goto out;
        }
    }

    rc = template_remove_attribute(obj->template, CKA_IBM_OPAQUE_REENC);
    if (rc == CKR_ATTRIBUTE_TYPE_INVALID)
        rc = CKR_OK;
    if (rc != CKR_OK)
        goto out;

    rc = template_remove_attribute(obj->template, CKA_IBM_OPAQUE_OLD);
    if (rc == CKR_ATTRIBUTE_TYPE_INVALID)
        rc = CKR_OK;
    if (rc != CKR_OK)
        goto out;

    if (!object_is_session_object(obj)) {
        rc = object_mgr_save_token_object(tokdata, obj);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to save token object, rc=%lx.\n",rc);
            goto out;
        }
    }

out:
    return rc;
}

struct iterate_obj_data {
    CK_BBOOL (*filter)(STDLL_TokData_t *tokdata, OBJECT *obj,
                       void *filter_data);
    void *filter_data;
    CK_RV (*cb)(STDLL_TokData_t *tokdata, OBJECT *obj, void *cb_data);
    void *cb_data;
    const char *msg;
    CK_BBOOL syslog;
    CK_RV error;
};

static void obj_mgr_iterate_key_objects_cb(STDLL_TokData_t *tokdata, void *p1,
                                           unsigned long p2, void *p3)
{
    struct iterate_obj_data *iod = p3;
    OBJECT *obj = p1;
    CK_OBJECT_CLASS class;
    CK_RV rc;

    UNUSED(p2);

    if (iod->error != CKR_OK) /* Skip if previous reported an error */
        return;

    rc = object_lock(obj, WRITE_LOCK);
    if (rc != CKR_OK) {
        if (iod->syslog)
            OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to get the object lock\n",
                       tokdata->slot_id);
        return;
    }

    rc = template_attribute_get_ulong(obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to get object class: 0x%lx\n", __func__, rc);
        if (iod->syslog)
            OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to get object class: 0x%lx\n",
                       tokdata->slot_id, rc);
        iod->error = rc;
        goto out;
    }

    switch (class) {
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
    case CKO_SECRET_KEY:
        break;
    default:
        /* Not a key object */
        goto out;
    }

    if (iod->filter != NULL &&
        !iod->filter(tokdata, obj, iod->filter_data))
        goto out;

    if (obj->session != NULL) {
        TRACE_INFO("%s %s session object 0x%lx of session 0x%lx\n",
                   __func__, iod->msg, p2, obj->session->handle);
        if (iod->syslog)
            OCK_SYSLOG(LOG_DEBUG, "Slot %lu: %s session object 0x%lx of "
                       "session 0x%lx\n", tokdata->slot_id, iod->msg, p2,
                       obj->session->handle);
    } else {
        TRACE_INFO("%s %s token object %s\n", __func__, iod->msg, obj->name);
        if (iod->syslog)
            OCK_SYSLOG(LOG_DEBUG, "Slot %lu: %s token object '%s'\n",
                       tokdata->slot_id, iod->msg, obj->name);
    }

    rc = iod->cb(tokdata, obj, iod->cb_data);
    if (rc != CKR_OK) {
        if (obj->session != NULL) {
            TRACE_ERROR("%s callback failed to process session object: 0x%lx\n",
                        __func__, rc);
            if (iod->syslog)
                OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to %s session object "
                           "0x%lx of session 0x%lx: 0x%lx\n", tokdata->slot_id,
                           iod->msg, p2, obj->session->handle, rc);
        } else {
            TRACE_ERROR("%s callback failed to process token object %s: 0x%lx\n",
                        __func__, obj->name, rc);
            if (iod->syslog)
                OCK_SYSLOG(LOG_ERR,
                           "Slot %lu: Failed to %s token object '%s': 0x%lx\n",
                           tokdata->slot_id, iod->msg, obj->name, rc);
        }
        iod->error = rc;
        goto out;
    }

out:
    object_unlock(obj);
}

CK_RV obj_mgr_iterate_key_objects(STDLL_TokData_t *tokdata,
                                  CK_BBOOL session_objects,
                                  CK_BBOOL token_objects,
                                  CK_BBOOL(*filter)(STDLL_TokData_t *tokdata,
                                                    OBJECT *obj,
                                                    void *filter_data),
                                  void *filter_data,
                                  CK_RV (*cb)(STDLL_TokData_t *tokdata,
                                              OBJECT *obj, void *cb_data),
                                  void *cb_data, CK_BBOOL syslog,
                                  const char *msg)
{
    struct iterate_obj_data iod;
    CK_RV rc;

    iod.filter = filter;
    iod.filter_data = filter_data;
    iod.cb = cb;
    iod.cb_data = cb_data;
    iod.syslog = syslog;
    iod.msg = msg;
    iod.error = CKR_OK;

    if (session_objects) {
        /* Session objects */
        bt_for_each_node(tokdata, &tokdata->sess_obj_btree,
                         obj_mgr_iterate_key_objects_cb, &iod);
        if (iod.error != CKR_OK) {
            TRACE_ERROR("%s failed to %s session objects: 0x%lx\n",
                        __func__, msg, iod.error);
            if (syslog)
                OCK_SYSLOG(LOG_ERR,
                           "Slot %lu: Failed to %s session objects: 0x%lx\n",
                           tokdata->slot_id, msg, iod.error);
            return iod.error;
        }
    }

    if (token_objects) {
        /* Update token objects */
        rc = XProcLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to get Process Lock.\n");
            if (syslog)
                OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to get Process Lock\n",
                           tokdata->slot_id);
            return rc;
        }

        object_mgr_update_from_shm(tokdata);

        rc = XProcUnLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to release Process Lock.\n");
            if (syslog)
                OCK_SYSLOG(LOG_ERR,
                           "Slot %lu: Failed to release Process Lock\n",
                           tokdata->slot_id);
            return rc;
        }

        /* Public token objects */
        bt_for_each_node(tokdata, &tokdata->publ_token_obj_btree,
                         obj_mgr_iterate_key_objects_cb, &iod);
        if (iod.error != CKR_OK) {
            TRACE_ERROR("%s failed to %s public token objects: 0x%lx\n",
                        __func__, msg, iod.error);
            if (syslog)
                OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to %s public token "
                           "objects: 0x%lx\n", tokdata->slot_id, msg,
                           iod.error);
            return iod.error;
        }

        /* Private token objects */
        bt_for_each_node(tokdata, &tokdata->priv_token_obj_btree,
                         obj_mgr_iterate_key_objects_cb, &iod);
        if (iod.error != CKR_OK) {
            TRACE_ERROR("%s failed to %s private token objects: 0x%lx\n",
                        __func__, msg, iod.error);
            if (syslog)
                OCK_SYSLOG(LOG_ERR,"Slot %lu: Failed to %s private token "
                           "objects: 0x%lx\n", tokdata->slot_id, msg,
                           iod.error);
            return iod.error;
        }
    }

    return CKR_OK;
}
