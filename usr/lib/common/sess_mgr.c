/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  session.c
//
// Session manager related functions
//
#include <stdlib.h>
#include <string.h>             // for memcmp() et al
#include <pthread.h>

#include "pkcs11types.h"
#include "local_types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"

// session_mgr_find()
//
// search for the specified session. returning a pointer to the session
// might be dangerous, but performs well.
//
// The returned session must be put back (using bt_put_node_value()) by the
// caller to decrease the reference count!
//
// Returns:  SESSION * or NULL
//
SESSION *session_mgr_find(STDLL_TokData_t *tokdata, CK_SESSION_HANDLE handle)
{
    SESSION *result = NULL;

    if (!handle) {
        return NULL;
    }

    result = bt_get_node_value(&tokdata->sess_btree, handle);

    return result;
}

// session_mgr_find_reset_error()
//
// search for the specified session and reset the ulDeviceError field
// in the session info. returning a pointer to the session might be
// dangerous, but performs well
//
// The returned session must be put back (using bt_put_node_value()) by the
// caller to decrease the reference count!
//
// Returns:  SESSION * or NULL
//
SESSION *session_mgr_find_reset_error(STDLL_TokData_t *tokdata,
                                      CK_SESSION_HANDLE handle)
{
    SESSION *res = session_mgr_find(tokdata, handle);

    if (res)
        res->session_info.ulDeviceError = 0;
    return res;
}

void session_mgr_put(STDLL_TokData_t *tokdata, SESSION *session)
{
    bt_put_node_value(&tokdata->sess_btree, session);
}

// session_mgr_new()
//
// creates a new session structure and adds it to the process's list
// of sessions
//
// Args:  CK_ULONG      flags : session flags                   (INPUT)
//        SESSION **     sess : new session pointer             (OUTPUT)
//
// Returns:  CK_RV
//
CK_RV session_mgr_new(STDLL_TokData_t *tokdata, CK_ULONG flags,
                      CK_SLOT_ID slot_id, CK_SESSION_HANDLE_PTR phSession)
{
    SESSION *new_session = NULL;
    CK_BBOOL user_session = FALSE;
    CK_BBOOL so_session = FALSE;
    CK_RV rc = CKR_OK;


    new_session = (SESSION *) malloc(sizeof(SESSION));
    if (!new_session) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    memset(new_session, 0x0, sizeof(SESSION));

    // find an unused session handle. session handles will wrap automatically...
    //
    new_session->session_info.slotID = slot_id;
    new_session->session_info.flags = flags;
    new_session->session_info.ulDeviceError = 0;


    // determine the login/logout status of the new session. PKCS 11 requires
    // that all sessions belonging to a process have the same login/logout
    // status
    //
    so_session = session_mgr_so_session_exists(tokdata);
    user_session = session_mgr_user_session_exists(tokdata);

    if (pthread_rwlock_wrlock(&tokdata->sess_list_rwlock)) {
        TRACE_ERROR("Write Lock failed.\n");
        rc = CKR_CANT_LOCK;
        goto done;
    }

    // we don't have to worry about having a user and SO session at the same
    // time. that is prevented in the login routine
    //
    if (user_session) {
        if (new_session->session_info.flags & CKF_RW_SESSION) {
            new_session->session_info.state = CKS_RW_USER_FUNCTIONS;
        } else {
            new_session->session_info.state = CKS_RO_USER_FUNCTIONS;
            tokdata->ro_session_count++;
        }
    } else if (so_session) {
        new_session->session_info.state = CKS_RW_SO_FUNCTIONS;
    } else {
        if (new_session->session_info.flags & CKF_RW_SESSION) {
            new_session->session_info.state = CKS_RW_PUBLIC_SESSION;
        } else {
            new_session->session_info.state = CKS_RO_PUBLIC_SESSION;
            tokdata->ro_session_count++;
        }
    }

    pthread_rwlock_unlock(&tokdata->sess_list_rwlock);

    *phSession = bt_node_add(&tokdata->sess_btree, new_session);
    if (*phSession == 0) {
        rc = CKR_HOST_MEMORY;
        /* new_session will be free'd below */
    }

done:
    if (rc != CKR_OK && new_session != NULL) {
        TRACE_ERROR("Failed to add session to the btree.\n");
        free(new_session);
    }

    return rc;
}


// session_mgr_so_session_exists()
//
// determines whether a RW_SO session exists for the specified process
//
// Returns:  TRUE or FALSE
//
CK_BBOOL session_mgr_so_session_exists(STDLL_TokData_t *tokdata)
{
    CK_BBOOL result;

    /* we must acquire sess_list_rwlock in order to inspect
     * global_login_state */
    if (pthread_rwlock_rdlock(&tokdata->sess_list_rwlock)) {
        TRACE_ERROR("Read Lock failed.\n");
        return FALSE;
    }
    result = (tokdata->global_login_state == CKS_RW_SO_FUNCTIONS);
    pthread_rwlock_unlock(&tokdata->sess_list_rwlock);

    return result;
}


// session_mgr_user_session_exists()
//
// determines whether a USER session exists for the specified process
//
// Returns:  TRUE or FALSE
//
CK_BBOOL session_mgr_user_session_exists(STDLL_TokData_t *tokdata)
{
    CK_BBOOL result;

    /* we must acquire sess_list_rwlock in order to inspect
     * glogal_login_state */
    if (pthread_rwlock_rdlock(&tokdata->sess_list_rwlock)) {
        TRACE_ERROR("Read Lock failed.\n");
        return FALSE;
    }
    result = ((tokdata->global_login_state == CKS_RO_USER_FUNCTIONS) ||
              (tokdata->global_login_state == CKS_RW_USER_FUNCTIONS));

    pthread_rwlock_unlock(&tokdata->sess_list_rwlock);

    return result;
}


// session_mgr_public_session_exists()
//
// determines whether a PUBLIC session exists for the specified process
//
// Returns:  TRUE or FALSE
//
CK_BBOOL session_mgr_public_session_exists(STDLL_TokData_t *tokdata)
{
    CK_BBOOL result;

    /* we must acquire sess_list_rwlock in order to inspect
     * global_login_state */
    if (pthread_rwlock_rdlock(&tokdata->sess_list_rwlock)) {
        TRACE_ERROR("Read Lock failed.\n");
        return FALSE;
    }
    result = ((tokdata->global_login_state == CKS_RO_PUBLIC_SESSION) ||
              (tokdata->global_login_state == CKS_RW_PUBLIC_SESSION));

    pthread_rwlock_unlock(&tokdata->sess_list_rwlock);

    return result;
}


// session_mgr_readonly_exists()
//
// determines whether the specified process owns any read-only sessions. this is
// useful because the SO cannot log in if a read-only session exists.
//
CK_BBOOL session_mgr_readonly_session_exists(STDLL_TokData_t *tokdata)
{
    CK_BBOOL result;

    /* we must acquire sess_list_rwlock in order to inspect ro_session_count */
    if (pthread_rwlock_rdlock(&tokdata->sess_list_rwlock)) {
        TRACE_ERROR("Read Lock failed.\n");
        return FALSE;
    }

    result = (tokdata->ro_session_count > 0);

    pthread_rwlock_unlock(&tokdata->sess_list_rwlock);

    return result;
}


// session_mgr_close_session()
//
// removes the specified session from the process' session list
//
// Args:   PROCESS *    proc  :  parent process
//         SESSION * session  :  session to remove
//
// Returns:  TRUE on success else FALSE
//
CK_RV session_mgr_close_session(STDLL_TokData_t *tokdata,
                                CK_SESSION_HANDLE handle)
{
    SESSION *sess;
    CK_RV rc = CKR_OK;

    sess = bt_get_node_value(&tokdata->sess_btree, handle);
    if (!sess) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;
    }

    if (pthread_rwlock_wrlock(&tokdata->sess_list_rwlock)) {
        TRACE_ERROR("Write Lock failed.\n");
        bt_put_node_value(&tokdata->sess_btree, sess);
        sess = NULL;
        return CKR_CANT_LOCK;
    }

    object_mgr_purge_session_objects(tokdata, sess, ALL);

    if ((sess->session_info.state == CKS_RO_PUBLIC_SESSION) ||
        (sess->session_info.state == CKS_RO_USER_FUNCTIONS)) {
        tokdata->ro_session_count--;
    }

    // Make sure this address is now invalid
    sess->handle = CK_INVALID_HANDLE;

    if (sess->find_list)
        free(sess->find_list);

    if (sess->encr_ctx.context) {
        if (sess->encr_ctx.context_free_func != NULL)
            sess->encr_ctx.context_free_func(tokdata, sess,
                                             sess->encr_ctx.context,
                                             sess->encr_ctx.context_len);
        else
            free(sess->encr_ctx.context);
    }

    if (sess->encr_ctx.mech.pParameter)
        free(sess->encr_ctx.mech.pParameter);

    if (sess->decr_ctx.context) {
        if (sess->decr_ctx.context_free_func != NULL)
            sess->decr_ctx.context_free_func(tokdata, sess,
                                             sess->decr_ctx.context,
                                             sess->decr_ctx.context_len);
        else
            free(sess->decr_ctx.context);
    }

    if (sess->decr_ctx.mech.pParameter)
        free(sess->decr_ctx.mech.pParameter);

    if (sess->digest_ctx.context) {
        if (sess->digest_ctx.context_free_func != NULL)
            sess->digest_ctx.context_free_func(tokdata, sess,
                                               sess->digest_ctx.context,
                                               sess->digest_ctx.context_len);
        else
            free(sess->digest_ctx.context);
    }

    if (sess->digest_ctx.mech.pParameter)
        free(sess->digest_ctx.mech.pParameter);

    if (sess->sign_ctx.context) {
        if (sess->sign_ctx.context_free_func != NULL)
            sess->sign_ctx.context_free_func(tokdata, sess,
                                             sess->sign_ctx.context,
                                             sess->sign_ctx.context_len);
        else
            free(sess->sign_ctx.context);
    }

    if (sess->sign_ctx.mech.pParameter)
        free(sess->sign_ctx.mech.pParameter);

    if (sess->verify_ctx.context) {
        if (sess->verify_ctx.context_free_func != NULL)
            sess->verify_ctx.context_free_func(tokdata, sess,
                                               sess->verify_ctx.context,
                                               sess->verify_ctx.context_len);
        else
            free(sess->verify_ctx.context);
    }

    if (sess->verify_ctx.mech.pParameter)
        free(sess->verify_ctx.mech.pParameter);

    bt_put_node_value(&tokdata->sess_btree, sess);
    sess = NULL;
    bt_node_free(&tokdata->sess_btree, handle, TRUE);

    // XXX XXX  Not having this is a problem
    //  for IHS.  The spec states that there is an implicit logout
    //  when the last session is closed.  Cannonicaly this is what other
    //  implementaitons do.  however on linux for some reason IHS can't seem
    //  to keep the session open, which means that they go through the login
    //  path EVERY time, which of course causes a reload of the private
    //  objects EVERY time.   If we are logged out, we MUST purge the private
    //  objects from this process..
    //
    if (bt_is_empty(&tokdata->sess_btree)) {
        // SAB  XXX  if all sessions are closed.  Is this effectivly logging out
        if (token_specific.t_logout) {
            rc = token_specific.t_logout(tokdata);
        }
        object_mgr_purge_private_token_objects(tokdata);

        tokdata->global_login_state = CKS_RO_PUBLIC_SESSION;
        // The objects really need to be purged .. but this impacts the
        // performance under linux.   So we need to make sure that the
        // login state is valid.    I don't really like this.
        object_mgr_purge_map(tokdata, (SESSION *) 0xFFFF, PRIVATE);
    }

    pthread_rwlock_unlock(&tokdata->sess_list_rwlock);
    return rc;
}

/* session_free
 *
 * Callback used to free an individual SESSION object
 */
void session_free(STDLL_TokData_t *tokdata, void *node_value,
                  unsigned long node_idx, void *p3)
{
    SESSION *sess = (SESSION *) node_value;

    UNUSED(p3);

    object_mgr_purge_session_objects(tokdata, sess, ALL);
    sess->handle = CK_INVALID_HANDLE;

    if (sess->find_list)
        free(sess->find_list);

    if (sess->encr_ctx.context) {
        if (sess->encr_ctx.context_free_func != NULL)
            sess->encr_ctx.context_free_func(tokdata, sess,
                                             sess->encr_ctx.context,
                                             sess->encr_ctx.context_len);
        else
            free(sess->encr_ctx.context);
    }

    if (sess->encr_ctx.mech.pParameter)
        free(sess->encr_ctx.mech.pParameter);

    if (sess->decr_ctx.context) {
        if (sess->decr_ctx.context_free_func != NULL)
            sess->decr_ctx.context_free_func(tokdata, sess,
                                             sess->decr_ctx.context,
                                             sess->decr_ctx.context_len);
        else
            free(sess->decr_ctx.context);
    }

    if (sess->decr_ctx.mech.pParameter)
        free(sess->decr_ctx.mech.pParameter);

    if (sess->digest_ctx.context) {
        if (sess->digest_ctx.context_free_func != NULL)
            sess->digest_ctx.context_free_func(tokdata, sess,
                                               sess->digest_ctx.context,
                                               sess->digest_ctx.context_len);
        else
            free(sess->digest_ctx.context);
    }

    if (sess->digest_ctx.mech.pParameter)
        free(sess->digest_ctx.mech.pParameter);

    if (sess->sign_ctx.context) {
        if (sess->sign_ctx.context_free_func != NULL)
            sess->sign_ctx.context_free_func(tokdata, sess,
                                             sess->sign_ctx.context,
                                             sess->sign_ctx.context_len);
        else
            free(sess->sign_ctx.context);
    }

    if (sess->sign_ctx.mech.pParameter)
        free(sess->sign_ctx.mech.pParameter);

    if (sess->verify_ctx.context) {
        if (sess->verify_ctx.context_free_func != NULL)
            sess->verify_ctx.context_free_func(tokdata, sess,
                                               sess->verify_ctx.context,
                                               sess->verify_ctx.context_len);
        else
            free(sess->verify_ctx.context);
    }

    if (sess->verify_ctx.mech.pParameter)
        free(sess->verify_ctx.mech.pParameter);

    /* NB: any access to sess or @node_value after this returns will segfault */
    bt_node_free(&tokdata->sess_btree, node_idx, TRUE);
}

// session_mgr_close_all_sessions()
//
// removes all sessions from the specified process.
// If tokdata is not NULL, then only sessions for that token instance are
// removed.
//
CK_RV session_mgr_close_all_sessions(STDLL_TokData_t *tokdata)
{
    bt_for_each_node(tokdata, &tokdata->sess_btree, session_free, NULL);

    if (pthread_rwlock_wrlock(&tokdata->sess_list_rwlock)) {
        TRACE_ERROR("Write Lock failed.\n");
        return CKR_CANT_LOCK;
    }

    tokdata->global_login_state = CKS_RO_PUBLIC_SESSION;
    tokdata->ro_session_count = 0;

    pthread_rwlock_unlock(&tokdata->sess_list_rwlock);

    return CKR_OK;
}

/* session_login
 *
 * Callback used to update a SESSION object's login state to logged in based on
 * user type
 */
void session_login(STDLL_TokData_t *tokdata, void *node_value,
                   unsigned long node_idx, void *p3)
{
    SESSION *s = (SESSION *) node_value;
    CK_USER_TYPE user_type = *(CK_USER_TYPE *) p3;

    UNUSED(tokdata);
    UNUSED(node_idx);

    if (s->session_info.flags & CKF_RW_SESSION) {
        if (user_type == CKU_USER)
            s->session_info.state = CKS_RW_USER_FUNCTIONS;
        else
            s->session_info.state = CKS_RW_SO_FUNCTIONS;
    } else {
        if (user_type == CKU_USER)
            s->session_info.state = CKS_RO_USER_FUNCTIONS;
    }

    tokdata->global_login_state = s->session_info.state; // SAB
}

// session_mgr_login_all()
//
// changes the login status of all sessions in the token
//
// Arg:  CK_USER_TYPE  user_type : USER or SO
//
CK_RV session_mgr_login_all(STDLL_TokData_t *tokdata, CK_USER_TYPE user_type)
{
    if (pthread_rwlock_wrlock(&tokdata->sess_list_rwlock)) {
        TRACE_ERROR("Write Lock failed.\n");
        return CKR_CANT_LOCK;
    }

    bt_for_each_node(tokdata, &tokdata->sess_btree, session_login,
                     (void *)&user_type);

    pthread_rwlock_unlock(&tokdata->sess_list_rwlock);

    return CKR_OK;
}

/* session_logout
 *
 * Callback used to update a SESSION object's login state to be logged out
 */
void session_logout(STDLL_TokData_t *tokdata, void *node_value,
                    unsigned long node_idx, void *p3)
{
    SESSION *s = (SESSION *) node_value;

    UNUSED(node_idx);
    UNUSED(p3);

    // all sessions get logged out so destroy any private objects
    // public objects are left alone
    //
    object_mgr_purge_session_objects(tokdata, s, PRIVATE);

    if (s->session_info.flags & CKF_RW_SESSION)
        s->session_info.state = CKS_RW_PUBLIC_SESSION;
    else
        s->session_info.state = CKS_RO_PUBLIC_SESSION;

    tokdata->global_login_state = s->session_info.state; // SAB
}

// session_mgr_logout_all()
//
// changes the login status of all sessions in the token
//
CK_RV session_mgr_logout_all(STDLL_TokData_t *tokdata)
{
    if (pthread_rwlock_wrlock(&tokdata->sess_list_rwlock)) {
        TRACE_ERROR("Write Lock failed.\n");
        return CKR_CANT_LOCK;
    }

    bt_for_each_node(tokdata, &tokdata->sess_btree, session_logout, NULL);

    pthread_rwlock_unlock(&tokdata->sess_list_rwlock);

    return CKR_OK;
}


//
//
CK_RV session_mgr_get_op_state(STDLL_TokData_t *tokdata, SESSION *sess,
                               CK_BBOOL length_only,
                               CK_BYTE *data, CK_ULONG *data_len)
{
    OP_STATE_DATA *op_data = NULL;
    CK_ULONG max_data_len = *data_len;
    CK_ULONG op_data_len;
    CK_ULONG all_data_len = 0;
    CK_ULONG offset, active_ops;

    if (!sess) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    if (sess->find_active == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
        return CKR_STATE_UNSAVEABLE;
    }

    // ensure that at least one operation is active
    //
    active_ops = 0;

    if (sess->encr_ctx.active == TRUE) {
        if (sess->encr_ctx.state_unsaveable) {
            TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
            return CKR_STATE_UNSAVEABLE;
        }
        active_ops++;
        op_data_len = sizeof(OP_STATE_DATA) +
            sizeof(ENCR_DECR_CONTEXT) +
            sess->encr_ctx.context_len + sess->encr_ctx.mech.ulParameterLen;
        all_data_len += op_data_len;

        if (length_only == FALSE) {
            op_data = (OP_STATE_DATA *) data;

            if (max_data_len < op_data_len) {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                 return CKR_BUFFER_TOO_SMALL;
            }

            memset(op_data, 0, sizeof(*op_data));
#ifdef PACKAGE_VERSION
            strncpy((char *)op_data->library_version, PACKAGE_VERSION,
                    sizeof(op_data->library_version));
#endif
            memcpy(op_data->manufacturerID,
                   tokdata->nv_token_data->token_info.manufacturerID,
                   sizeof(op_data->manufacturerID));
            memcpy(op_data->model, tokdata->nv_token_data->token_info.model,
                   sizeof(op_data->model));
            op_data->data_len = op_data_len - sizeof(OP_STATE_DATA);
            op_data->session_state = sess->session_info.state;
            op_data->active_operation = STATE_ENCR;

            offset = sizeof(OP_STATE_DATA);

            memcpy((CK_BYTE *) op_data + offset,
                   &sess->encr_ctx, sizeof(ENCR_DECR_CONTEXT));

            offset += sizeof(ENCR_DECR_CONTEXT);

            if (sess->encr_ctx.context_len != 0) {
                memcpy((CK_BYTE *) op_data + offset,
                       sess->encr_ctx.context, sess->encr_ctx.context_len);

                offset += sess->encr_ctx.context_len;
            }

            if (sess->encr_ctx.mech.ulParameterLen != 0) {
                memcpy((CK_BYTE *) op_data + offset,
                       sess->encr_ctx.mech.pParameter,
                       sess->encr_ctx.mech.ulParameterLen);
            }

            max_data_len -= op_data_len;
            data += op_data_len;
        }
    }

    if (sess->decr_ctx.active == TRUE) {
        if (sess->decr_ctx.state_unsaveable) {
            TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
            return CKR_STATE_UNSAVEABLE;
        }
        active_ops++;
        op_data_len = sizeof(OP_STATE_DATA) +
            sizeof(ENCR_DECR_CONTEXT) +
            sess->decr_ctx.context_len + sess->decr_ctx.mech.ulParameterLen;
        all_data_len += op_data_len;

        if (length_only == FALSE) {
            op_data = (OP_STATE_DATA *) data;

            if (max_data_len < op_data_len) {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                 return CKR_BUFFER_TOO_SMALL;
            }

            memset(op_data, 0, sizeof(*op_data));
#ifdef PACKAGE_VERSION
            strncpy((char *)op_data->library_version, PACKAGE_VERSION,
                    sizeof(op_data->library_version));
#endif
            memcpy(op_data->manufacturerID,
                   tokdata->nv_token_data->token_info.manufacturerID,
                   sizeof(op_data->manufacturerID));
            memcpy(op_data->model, tokdata->nv_token_data->token_info.model,
                   sizeof(op_data->model));
            op_data->data_len = op_data_len - sizeof(OP_STATE_DATA);
            op_data->session_state = sess->session_info.state;
            op_data->active_operation = STATE_DECR;

            offset = sizeof(OP_STATE_DATA);

            memcpy((CK_BYTE *) op_data + offset,
                   &sess->decr_ctx, sizeof(ENCR_DECR_CONTEXT));

            offset += sizeof(ENCR_DECR_CONTEXT);

            if (sess->decr_ctx.context_len != 0) {
                memcpy((CK_BYTE *) op_data + offset,
                       sess->decr_ctx.context, sess->decr_ctx.context_len);

                offset += sess->decr_ctx.context_len;
            }

            if (sess->decr_ctx.mech.ulParameterLen != 0) {
                memcpy((CK_BYTE *) op_data + offset,
                       sess->decr_ctx.mech.pParameter,
                       sess->decr_ctx.mech.ulParameterLen);
            }

            max_data_len -= op_data_len;
            data += op_data_len;
        }
    }

    if (sess->digest_ctx.active == TRUE) {
        if (sess->digest_ctx.state_unsaveable) {
            TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
            return CKR_STATE_UNSAVEABLE;
        }
        active_ops++;
        op_data_len = sizeof(OP_STATE_DATA) +
            sizeof(DIGEST_CONTEXT) +
            sess->digest_ctx.context_len + sess->digest_ctx.mech.ulParameterLen;
        all_data_len += op_data_len;

        if (length_only == FALSE) {
            op_data = (OP_STATE_DATA *) data;

            if (max_data_len < op_data_len) {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                 return CKR_BUFFER_TOO_SMALL;
            }

            memset(op_data, 0, sizeof(*op_data));
#ifdef PACKAGE_VERSION
            strncpy((char *)op_data->library_version, PACKAGE_VERSION,
                    sizeof(op_data->library_version));
#endif
            memcpy(op_data->manufacturerID,
                   tokdata->nv_token_data->token_info.manufacturerID,
                   sizeof(op_data->manufacturerID));
            memcpy(op_data->model, tokdata->nv_token_data->token_info.model,
                   sizeof(op_data->model));
            op_data->data_len = op_data_len - sizeof(OP_STATE_DATA);
            op_data->session_state = sess->session_info.state;
            op_data->active_operation = STATE_DIGEST;

            offset = sizeof(OP_STATE_DATA);

            memcpy((CK_BYTE *) op_data + offset,
                   &sess->digest_ctx, sizeof(DIGEST_CONTEXT));

            offset += sizeof(DIGEST_CONTEXT);

            if (sess->digest_ctx.context_len != 0) {
                memcpy((CK_BYTE *) op_data + offset,
                       sess->digest_ctx.context, sess->digest_ctx.context_len);

                offset += sess->digest_ctx.context_len;
            }

            if (sess->digest_ctx.mech.ulParameterLen != 0) {
                memcpy((CK_BYTE *) op_data + offset,
                       sess->digest_ctx.mech.pParameter,
                       sess->digest_ctx.mech.ulParameterLen);
            }

            max_data_len -= op_data_len;
            data += op_data_len;
        }
    }

    if (sess->sign_ctx.active == TRUE) {
        if (sess->sign_ctx.state_unsaveable) {
            TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
            return CKR_STATE_UNSAVEABLE;
        }
        active_ops++;
        op_data_len = sizeof(OP_STATE_DATA) +
            sizeof(SIGN_VERIFY_CONTEXT) +
            sess->sign_ctx.context_len + sess->sign_ctx.mech.ulParameterLen;
        all_data_len += op_data_len;

        if (length_only == FALSE) {
            op_data = (OP_STATE_DATA *) data;

            if (max_data_len < op_data_len) {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                 return CKR_BUFFER_TOO_SMALL;
            }

            memset(op_data, 0, sizeof(*op_data));
#ifdef PACKAGE_VERSION
            strncpy((char *)op_data->library_version, PACKAGE_VERSION,
                    sizeof(op_data->library_version));
#endif
            memcpy(op_data->manufacturerID,
                   tokdata->nv_token_data->token_info.manufacturerID,
                   sizeof(op_data->manufacturerID));
            memcpy(op_data->model, tokdata->nv_token_data->token_info.model,
                   sizeof(op_data->model));
            op_data->data_len = op_data_len - sizeof(OP_STATE_DATA);
            op_data->session_state = sess->session_info.state;
            op_data->active_operation = STATE_SIGN;

            offset = sizeof(OP_STATE_DATA);

            memcpy((CK_BYTE *) op_data + offset,
                   &sess->sign_ctx, sizeof(SIGN_VERIFY_CONTEXT));

            offset += sizeof(SIGN_VERIFY_CONTEXT);

            if (sess->sign_ctx.context_len != 0) {
                memcpy((CK_BYTE *) op_data + offset,
                       sess->sign_ctx.context, sess->sign_ctx.context_len);

                offset += sess->sign_ctx.context_len;
            }

            if (sess->sign_ctx.mech.ulParameterLen != 0) {
                memcpy((CK_BYTE *) op_data + offset,
                       sess->sign_ctx.mech.pParameter,
                       sess->sign_ctx.mech.ulParameterLen);
            }

            max_data_len -= op_data_len;
            data += op_data_len;
        }
    }

    if (sess->verify_ctx.active == TRUE) {
        if (sess->verify_ctx.state_unsaveable) {
            TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
            return CKR_STATE_UNSAVEABLE;
        }
        active_ops++;
        op_data_len = sizeof(OP_STATE_DATA) +
            sizeof(SIGN_VERIFY_CONTEXT) +
            sess->verify_ctx.context_len + sess->verify_ctx.mech.ulParameterLen;
        all_data_len += op_data_len;

        if (length_only == FALSE) {
            op_data = (OP_STATE_DATA *) data;

            if (max_data_len < op_data_len) {
                TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
                 return CKR_BUFFER_TOO_SMALL;
            }

            memset(op_data, 0, sizeof(*op_data));
#ifdef PACKAGE_VERSION
            strncpy((char *)op_data->library_version, PACKAGE_VERSION,
                    sizeof(op_data->library_version));
#endif
            memcpy(op_data->manufacturerID,
                   tokdata->nv_token_data->token_info.manufacturerID,
                   sizeof(op_data->manufacturerID));
            memcpy(op_data->model, tokdata->nv_token_data->token_info.model,
                   sizeof(op_data->model));
            op_data->data_len = op_data_len - sizeof(OP_STATE_DATA);
            op_data->session_state = sess->session_info.state;
            op_data->active_operation = STATE_VERIFY;

            offset = sizeof(OP_STATE_DATA);

            memcpy((CK_BYTE *) op_data + offset,
                   &sess->verify_ctx, sizeof(SIGN_VERIFY_CONTEXT));

            offset += sizeof(SIGN_VERIFY_CONTEXT);

            if (sess->verify_ctx.context_len != 0) {
                memcpy((CK_BYTE *) op_data + offset,
                       sess->verify_ctx.context, sess->verify_ctx.context_len);

                offset += sess->verify_ctx.context_len;
            }

            if (sess->verify_ctx.mech.ulParameterLen != 0) {
                memcpy((CK_BYTE *) op_data + offset,
                       sess->verify_ctx.mech.pParameter,
                       sess->verify_ctx.mech.ulParameterLen);
            }

            max_data_len -= op_data_len;
            data += op_data_len;
        }
    }

    if (active_ops == 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
        return CKR_OPERATION_NOT_INITIALIZED;
    }

    *data_len = all_data_len;
    return CKR_OK;
}


//
//
CK_RV session_mgr_set_op_state(STDLL_TokData_t *tokdata, SESSION *sess,
                               CK_OBJECT_HANDLE encr_key,
                               CK_OBJECT_HANDLE auth_key,
                               CK_BYTE *data, CK_ULONG data_len)
{
    CK_BYTE *cur_data;
    CK_ULONG cur_data_len;
    OP_STATE_DATA *op_data = NULL;
    CK_BYTE *mech_param = NULL;
    CK_BYTE *context = NULL;
    CK_BYTE *ptr1 = NULL;
    CK_BYTE *ptr2 = NULL;
    CK_BYTE *ptr3 = NULL;
    CK_ULONG len;
    CK_ULONG encr_key_needed = 0;
    CK_ULONG auth_key_needed = 0;

    if (!sess || !data) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    /*
     * Validate the new state information. Don't touch the session
     * until the new state is valid.
     */
    cur_data = data;
    cur_data_len = data_len;
    while (cur_data_len >= sizeof(OP_STATE_DATA)) {
        op_data = (OP_STATE_DATA *)cur_data;

        if (cur_data_len < op_data->data_len + sizeof(OP_STATE_DATA)) {
            TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
            return CKR_SAVED_STATE_INVALID;
        }

        /*
         * Make sure the session states are compatible: same OCK version,
         * same token model, same session state.
         */
#ifdef PACKAGE_VERSION
        if (strncmp((char *)op_data->library_version, PACKAGE_VERSION,
                sizeof(op_data->library_version)) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
            return CKR_SAVED_STATE_INVALID;
        }
#endif
        if (memcmp(op_data->manufacturerID,
                   tokdata->nv_token_data->token_info.manufacturerID,
                   sizeof(op_data->manufacturerID)) != 0 ||
            memcmp(op_data->model, tokdata->nv_token_data->token_info.model,
                   sizeof(op_data->model)) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
            return CKR_SAVED_STATE_INVALID;
        }
        if (sess->session_info.state != op_data->session_state) {
            TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
            return CKR_SAVED_STATE_INVALID;
        }

        switch (op_data->active_operation) {
        case STATE_ENCR:
        case STATE_DECR:
            {
                ENCR_DECR_CONTEXT *ctx =
                    (ENCR_DECR_CONTEXT *)(cur_data + sizeof(OP_STATE_DATA));

                len = sizeof(ENCR_DECR_CONTEXT) + ctx->context_len +
                                                ctx->mech.ulParameterLen;
                if (len != op_data->data_len) {
                    TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
                    return CKR_SAVED_STATE_INVALID;
                }

                encr_key_needed++;
            }
            break;

        case STATE_SIGN:
        case STATE_VERIFY:
            {
                SIGN_VERIFY_CONTEXT *ctx =
                    (SIGN_VERIFY_CONTEXT *)(cur_data + sizeof(OP_STATE_DATA));

                len = sizeof(SIGN_VERIFY_CONTEXT) + ctx->context_len +
                                                ctx->mech.ulParameterLen;
                if (len != op_data->data_len) {
                    TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
                    return CKR_SAVED_STATE_INVALID;
                }

                auth_key_needed++;
            }
            break;

        case STATE_DIGEST:
            {
                DIGEST_CONTEXT *ctx =
                    (DIGEST_CONTEXT *) (cur_data + sizeof(OP_STATE_DATA));

                len = sizeof(DIGEST_CONTEXT) + ctx->context_len +
                                                ctx->mech.ulParameterLen;
                if (len != op_data->data_len) {
                    TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
                    return CKR_SAVED_STATE_INVALID;
                }
            }
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
            return CKR_SAVED_STATE_INVALID;
        }

        /* move on to next operation */
        cur_data_len -= (op_data->data_len + sizeof(OP_STATE_DATA));
        cur_data += (op_data->data_len + sizeof(OP_STATE_DATA));
    }
    /* nothing must be left over */
    if (cur_data_len > 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
        return CKR_SAVED_STATE_INVALID;
    }

    if (encr_key_needed > 0 && encr_key == CK_INVALID_HANDLE) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_NEEDED));
        return CKR_KEY_NEEDED;
    }
    if (encr_key_needed == 0 && encr_key != CK_INVALID_HANDLE) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_NOT_NEEDED));
        return CKR_KEY_NOT_NEEDED;
    }
    if (auth_key_needed > 0 && auth_key == CK_INVALID_HANDLE) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_NEEDED));
        return CKR_KEY_NEEDED;
    }
    if (auth_key_needed == 0 && auth_key != CK_INVALID_HANDLE) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_NOT_NEEDED));
        return CKR_KEY_NOT_NEEDED;
    }

    /* State information looks okay. Cleanup the current session state, first */
    if (sess->encr_ctx.active)
        encr_mgr_cleanup(tokdata, sess, &sess->encr_ctx);
    if (sess->decr_ctx.active)
        decr_mgr_cleanup(tokdata, sess, &sess->decr_ctx);
    if (sess->digest_ctx.active)
        digest_mgr_cleanup(tokdata, sess, &sess->digest_ctx);
    if (sess->sign_ctx.active)
        sign_mgr_cleanup(tokdata, sess, &sess->sign_ctx);
    if (sess->verify_ctx.active)
        verify_mgr_cleanup(tokdata, sess, &sess->verify_ctx);

    /* Now process the saved operation states */
    cur_data = data;
    cur_data_len = data_len;
    while (cur_data_len >= sizeof(OP_STATE_DATA)) {
        op_data = (OP_STATE_DATA *)cur_data;

        if (cur_data_len < op_data->data_len + sizeof(OP_STATE_DATA)) {
            TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
            return CKR_SAVED_STATE_INVALID;
        }

        switch (op_data->active_operation) {
        case STATE_ENCR:
        case STATE_DECR:
            {
                ENCR_DECR_CONTEXT *ctx =
                    (ENCR_DECR_CONTEXT *)(cur_data + sizeof(OP_STATE_DATA));

                len = sizeof(ENCR_DECR_CONTEXT) + ctx->context_len +
                                                ctx->mech.ulParameterLen;
                if (len != op_data->data_len) {
                    TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
                    return CKR_SAVED_STATE_INVALID;
                }
                if (encr_key == CK_INVALID_HANDLE) {
                    TRACE_ERROR("%s\n", ock_err(ERR_KEY_NEEDED));
                    return CKR_KEY_NEEDED;
                }
                ptr1 = (CK_BYTE *) ctx;
                ptr2 = ptr1 + sizeof(ENCR_DECR_CONTEXT);
                ptr3 = ptr2 + ctx->context_len;

                if (ctx->context_len) {
                    context = (CK_BYTE *) malloc(ctx->context_len);
                    if (!context) {
                        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                        return CKR_HOST_MEMORY;
                    }
                    memcpy(context, ptr2, ctx->context_len);
                }

                if (ctx->mech.ulParameterLen) {
                    mech_param = (CK_BYTE *) malloc(ctx->mech.ulParameterLen);
                    if (!mech_param) {
                        if (context)
                            free(context);
                        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                        return CKR_HOST_MEMORY;
                    }
                    memcpy(mech_param, ptr3, ctx->mech.ulParameterLen);
                }
            }
            break;

        case STATE_SIGN:
        case STATE_VERIFY:
            {
                SIGN_VERIFY_CONTEXT *ctx =
                    (SIGN_VERIFY_CONTEXT *)(cur_data + sizeof(OP_STATE_DATA));

                len = sizeof(SIGN_VERIFY_CONTEXT) + ctx->context_len +
                                                    ctx->mech.ulParameterLen;
                if (len != op_data->data_len) {
                    TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
                    return CKR_SAVED_STATE_INVALID;
                }
                if (auth_key == CK_INVALID_HANDLE) {
                    TRACE_ERROR("%s\n", ock_err(ERR_KEY_NEEDED));
                    return CKR_KEY_NEEDED;
                }
                ptr1 = (CK_BYTE *) ctx;
                ptr2 = ptr1 + sizeof(SIGN_VERIFY_CONTEXT);
                ptr3 = ptr2 + ctx->context_len;

                if (ctx->context_len) {
                    context = (CK_BYTE *) malloc(ctx->context_len);
                    if (!context) {
                        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                        return CKR_HOST_MEMORY;
                    }
                    memcpy(context, ptr2, ctx->context_len);
                }

                if (ctx->mech.ulParameterLen) {
                    mech_param = (CK_BYTE *) malloc(ctx->mech.ulParameterLen);
                    if (!mech_param) {
                        if (context)
                            free(context);
                        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                        return CKR_HOST_MEMORY;
                    }
                    memcpy(mech_param, ptr3, ctx->mech.ulParameterLen);
                }
            }
            break;

        case STATE_DIGEST:
            {
                DIGEST_CONTEXT *ctx =
                    (DIGEST_CONTEXT *)(cur_data + sizeof(OP_STATE_DATA));

                len = sizeof(DIGEST_CONTEXT) + ctx->context_len +
                                                ctx->mech.ulParameterLen;
                if (len != op_data->data_len) {
                    TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
                    return CKR_SAVED_STATE_INVALID;
                }
                ptr1 = (CK_BYTE *) ctx;
                ptr2 = ptr1 + sizeof(DIGEST_CONTEXT);
                ptr3 = ptr2 + ctx->context_len;

                if (ctx->context_len) {
                    context = (CK_BYTE *) malloc(ctx->context_len);
                    if (!context) {
                        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                        return CKR_HOST_MEMORY;
                    }
                    memcpy(context, ptr2, ctx->context_len);
                }

                if (ctx->mech.ulParameterLen) {
                    mech_param = (CK_BYTE *) malloc(ctx->mech.ulParameterLen);
                    if (!mech_param) {
                        if (context)
                            free(context);
                        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                        return CKR_HOST_MEMORY;
                    }
                    memcpy(mech_param, ptr3, ctx->mech.ulParameterLen);
                }
            }
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
            return CKR_SAVED_STATE_INVALID;
        }

        /* copy the new state information */
        switch (op_data->active_operation) {
        case STATE_ENCR:
            memcpy(&sess->encr_ctx, ptr1, sizeof(ENCR_DECR_CONTEXT));

            sess->encr_ctx.key = encr_key;
            sess->encr_ctx.context = context;
            sess->encr_ctx.mech.pParameter = mech_param;
            break;

        case STATE_DECR:
            memcpy(&sess->decr_ctx, ptr1, sizeof(ENCR_DECR_CONTEXT));

            sess->decr_ctx.key = encr_key;
            sess->decr_ctx.context = context;
            sess->decr_ctx.mech.pParameter = mech_param;
            break;

        case STATE_SIGN:
            memcpy(&sess->sign_ctx, ptr1, sizeof(SIGN_VERIFY_CONTEXT));

            sess->sign_ctx.key = auth_key;
            sess->sign_ctx.context = context;
            sess->sign_ctx.mech.pParameter = mech_param;
            break;

        case STATE_VERIFY:
            memcpy(&sess->verify_ctx, ptr1, sizeof(SIGN_VERIFY_CONTEXT));

            sess->verify_ctx.key = auth_key;
            sess->verify_ctx.context = context;
            sess->verify_ctx.mech.pParameter = mech_param;
            break;

        case STATE_DIGEST:
            memcpy(&sess->digest_ctx, ptr1, sizeof(DIGEST_CONTEXT));

            sess->digest_ctx.context = context;
            sess->digest_ctx.mech.pParameter = mech_param;
            break;
        }

        context = NULL;
        mech_param = NULL;

        /* move on to next operation */
        cur_data_len -= (op_data->data_len + sizeof(OP_STATE_DATA));
        cur_data += (op_data->data_len + sizeof(OP_STATE_DATA));
    }

    return CKR_OK;
}

CK_RV session_mgr_cancel(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_FLAGS flags)
{
    if ((flags & CKF_ENCRYPT) && sess->encr_ctx.active)
        encr_mgr_cleanup(tokdata, sess, &sess->encr_ctx);

    if ((flags & CKF_DECRYPT) && sess->decr_ctx.active)
        decr_mgr_cleanup(tokdata, sess, &sess->decr_ctx);

    if ((flags & CKF_DIGEST) && sess->digest_ctx.active)
        digest_mgr_cleanup(tokdata, sess, &sess->digest_ctx);

    if ((flags & CKF_SIGN) && sess->sign_ctx.active &&
        !sess->sign_ctx.recover)
        sign_mgr_cleanup(tokdata, sess, &sess->sign_ctx);

    if ((flags & CKF_SIGN_RECOVER) && sess->sign_ctx.active &&
        sess->sign_ctx.recover)
        sign_mgr_cleanup(tokdata, sess, &sess->sign_ctx);

    if ((flags & CKF_VERIFY) && sess->verify_ctx.active &&
        !sess->verify_ctx.recover)
        verify_mgr_cleanup(tokdata, sess, &sess->verify_ctx);

    if ((flags & CKF_VERIFY_RECOVER) && sess->verify_ctx.active &&
        sess->verify_ctx.recover)
        verify_mgr_cleanup(tokdata, sess, &sess->verify_ctx);

    if ((flags & CKF_FIND_OBJECTS) && sess->find_active) {
        if (sess->find_list)
            free(sess->find_list);
        sess->find_list = NULL;
        sess->find_len = 0;
        sess->find_idx = 0;
        sess->find_active = FALSE;
    }

    return CKR_OK;
}

// Return TRUE if the session we're in has its PIN expired.
CK_BBOOL pin_expired(CK_SESSION_INFO *si, CK_FLAGS flags)
{
    // If this is an SO session
    if ((flags & CKF_SO_PIN_TO_BE_CHANGED) &&
        (si->state == CKS_RW_SO_FUNCTIONS))
        return TRUE;

    // Else we're a User session
    return ((flags & CKF_USER_PIN_TO_BE_CHANGED) &&
            ((si->state == CKS_RO_USER_FUNCTIONS) ||
             (si->state == CKS_RW_USER_FUNCTIONS)));
}

// Return TRUE if the session we're in has its PIN locked.
CK_BBOOL pin_locked(CK_SESSION_INFO *si, CK_FLAGS flags)
{
    // If this is an SO session
    if ((flags & CKF_SO_PIN_LOCKED) && (si->state == CKS_RW_SO_FUNCTIONS))
        return TRUE;

    // Else we're a User session
    return ((flags & CKF_USER_PIN_LOCKED) &&
            ((si->state == CKS_RO_USER_FUNCTIONS) ||
             (si->state == CKS_RW_USER_FUNCTIONS)));
}

// Increment the login flags after an incorrect password
// has been passed to C_Login. New for v2.11. - KEY
void set_login_flags(CK_USER_TYPE userType, CK_FLAGS_32 *flags)
{
    if (userType == CKU_USER) {
        if (*flags & CKF_USER_PIN_FINAL_TRY) {
            *flags |= CKF_USER_PIN_LOCKED;
            *flags &= ~(CKF_USER_PIN_FINAL_TRY);
        } else if (*flags & CKF_USER_PIN_COUNT_LOW) {
            *flags |= CKF_USER_PIN_FINAL_TRY;
            *flags &= ~(CKF_USER_PIN_COUNT_LOW);
        } else {
            *flags |= CKF_USER_PIN_COUNT_LOW;
        }
    } else {
        if (*flags & CKF_SO_PIN_FINAL_TRY) {
            *flags |= CKF_SO_PIN_LOCKED;
            *flags &= ~(CKF_SO_PIN_FINAL_TRY);
        } else if (*flags & CKF_SO_PIN_COUNT_LOW) {
            *flags |= CKF_SO_PIN_FINAL_TRY;
            *flags &= ~(CKF_SO_PIN_COUNT_LOW);
        } else {
            *flags |= CKF_SO_PIN_COUNT_LOW;
        }
    }
}

struct session_iterate_data {
    CK_RV (*cb)(STDLL_TokData_t *tokdata, SESSION *session, CK_ULONG ctx_type,
                CK_MECHANISM *mech, CK_OBJECT_HANDLE key,
                CK_BYTE *context, CK_ULONG context_len,
                CK_BBOOL init_pending, CK_BBOOL pkey_active, CK_BBOOL recover,
                void *private);
    void *private;
    CK_RV error;
};

static void session_mgr_iterate_session_ops_cb(STDLL_TokData_t *tokdata,
                                               void *p1, unsigned long p2,
                                               void *p3)
{
    struct session_iterate_data *sid = p3;
    SESSION *session = p1;
    CK_RV rc = CKR_OK;

    UNUSED(p2);

    if (sid->error != CKR_OK)
        return;

    if (session->digest_ctx.active &&
        session->digest_ctx.context != NULL &&
        session->digest_ctx.context_len > 0) {
        rc = sid->cb(tokdata, session, CONTEXT_TYPE_DIGEST,
                     &session->digest_ctx.mech, CK_INVALID_HANDLE,
                     session->digest_ctx.context,
                     session->digest_ctx.context_len,
                     FALSE, FALSE, FALSE, sid->private);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s callback function failed: 0x%lx\n",
                        __func__, rc);
            goto out;
        }
    }

    if (session->sign_ctx.active &&
        session->sign_ctx.context != NULL &&
        session->sign_ctx.context_len > 0) {
        rc = sid->cb(tokdata, session, CONTEXT_TYPE_SIGN,
                     &session->sign_ctx.mech, session->sign_ctx.key,
                     session->sign_ctx.context,
                     session->sign_ctx.context_len,
                     session->sign_ctx.init_pending,
                     session->sign_ctx.pkey_active,
                     session->sign_ctx.recover,
                     sid->private);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s callback function failed: 0x%lx\n",
                        __func__, rc);
            goto out;
        }
    }

    if (session->verify_ctx.active &&
        session->verify_ctx.context != NULL &&
        session->verify_ctx.context_len > 0) {
        rc = sid->cb(tokdata, session, CONTEXT_TYPE_VERIFY,
                     &session->verify_ctx.mech, session->verify_ctx.key,
                     session->verify_ctx.context,
                     session->verify_ctx.context_len,
                     session->verify_ctx.init_pending,
                     session->verify_ctx.pkey_active,
                     session->verify_ctx.recover,
                     sid->private);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s callback function failed: 0x%lx\n",
                        __func__, rc);
            goto out;
        }
    }

    if (session->encr_ctx.active &&
        session->encr_ctx.context != NULL &&
        session->encr_ctx.context_len > 0) {
        rc = sid->cb(tokdata, session, CONTEXT_TYPE_ENCRYPT,
                     &session->encr_ctx.mech, session->encr_ctx.key,
                     session->encr_ctx.context,
                     session->encr_ctx.context_len,
                     session->encr_ctx.init_pending,
                     session->encr_ctx.pkey_active, FALSE,
                     sid->private);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s callback function failed: 0x%lx\n",
                        __func__, rc);
            goto out;
        }
    }

    if (session->decr_ctx.active &&
        session->decr_ctx.context != NULL &&
        session->decr_ctx.context_len > 0) {
        rc = sid->cb(tokdata, session, CONTEXT_TYPE_DECRYPT,
                     &session->decr_ctx.mech, session->decr_ctx.key,
                     session->decr_ctx.context,
                     session->decr_ctx.context_len,
                     session->decr_ctx.init_pending,
                     session->decr_ctx.pkey_active, FALSE,
                     sid->private);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s callback function failed: 0x%lx\n",
                        __func__, rc);
            goto out;
        }
    }

out:
    if (rc != CKR_OK)
        sid->error = rc;
}

CK_RV session_mgr_iterate_session_ops(STDLL_TokData_t *tokdata,
                                      SESSION *session,
                                      CK_RV (*cb)(STDLL_TokData_t *tokdata,
                                                  SESSION *session,
                                                  CK_ULONG ctx_type,
                                                  CK_MECHANISM *mech,
                                                  CK_OBJECT_HANDLE key,
                                                  CK_BYTE *context,
                                                  CK_ULONG context_len,
                                                  CK_BBOOL init_pending,
                                                  CK_BBOOL pkey_active,
                                                  CK_BBOOL recover,
                                                  void *private),
                                      void *private)
{
    struct session_iterate_data sid;

    sid.cb = cb;
    sid.private = private;
    sid.error = CKR_OK;

    if (session != NULL)
        session_mgr_iterate_session_ops_cb(tokdata, session, 0, &sid);
    else
        bt_for_each_node(tokdata, &tokdata->sess_btree,
                         session_mgr_iterate_session_ops_cb, &sid);

    return sid.error;
}
