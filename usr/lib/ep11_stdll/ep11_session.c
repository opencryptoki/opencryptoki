/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2023
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _GNU_SOURCE
#define OCK_NO_EP11_DEFINES
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "attributes.h"
#include "trace.h"
#include "ock_syslog.h"
#include "stdll.h"

#include <sys/time.h>
#include <time.h>
#include <stdint.h>

#include "ep11_specific.h"

CK_RV SC_CreateObject(STDLL_TokData_t *tokdata,
                      ST_SESSION_HANDLE *sSession, CK_ATTRIBUTE_PTR pTemplate,
                      CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
CK_RV SC_DestroyObject(STDLL_TokData_t *tokdata,
                       ST_SESSION_HANDLE *sSession, CK_OBJECT_HANDLE hObject);
CK_RV SC_FindObjectsInit(STDLL_TokData_t *tokdata,
                         ST_SESSION_HANDLE *sSession,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV SC_FindObjects(STDLL_TokData_t *tokdata,
                     ST_SESSION_HANDLE *sSession,
                     CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                     CK_ULONG_PTR pulObjectCount);
CK_RV SC_FindObjectsFinal(STDLL_TokData_t *tokdata,
                          ST_SESSION_HANDLE *sSession);
CK_RV SC_GetAttributeValue(STDLL_TokData_t *tokdata,
                           ST_SESSION_HANDLE *sSession,
                           CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                           CK_ULONG ulCount);
CK_RV SC_OpenSession(STDLL_TokData_t *tokdata, CK_SLOT_ID sid, CK_FLAGS flags,
                     CK_SESSION_HANDLE_PTR phSession);
CK_RV SC_CloseSession(STDLL_TokData_t *tokdata, ST_SESSION_HANDLE *sSession,
                      CK_BBOOL in_fork_initializer);

CK_BOOL ep11_is_session_object(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len)
{
    CK_ATTRIBUTE_PTR attr;

    attr = get_attribute_by_type(attrs, attrs_len, CKA_TOKEN);
    if (attr == NULL)
        return TRUE;

    if (attr->pValue == NULL)
        return TRUE;

    if (*((CK_BBOOL *)attr->pValue) == FALSE)
        return TRUE;

    return FALSE;
}

CK_BOOL ep11_is_private_object(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len)
{
    CK_ATTRIBUTE_PTR attr;

    attr = get_attribute_by_type(attrs, attrs_len, CKA_PRIVATE);
    if (attr == NULL)
        return FALSE;

    if (attr->pValue == NULL)
        return FALSE;

    return *((CK_BBOOL *)attr->pValue);
}

CK_RV ep11tok_relogin_session(STDLL_TokData_t *tokdata, SESSION *session)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_session_t *ep11_session = (ep11_session_t *)session->private_data;
    login_logout_data_t data = { 0 };
    CK_RV rc;

    TRACE_INFO("%s session=%lu\n", __func__, session->handle);

    if (!ep11_data->strict_mode && !ep11_data->vhsm_mode &&
        !ep11_data->fips_session_mode)
        return CKR_OK;

    if (ep11_data->strict_mode && ep11_session == NULL) {
        TRACE_INFO("%s Session not yet logged in\n", __func__);
        return CKR_USER_NOT_LOGGED_IN;
    }

    if (ep11_data->vhsm_mode || ep11_data->fips_session_mode) {
        if (pthread_mutex_lock(&ep11_data->session_mutex)) {
            TRACE_ERROR("%s Failed to lock session lock\n", __func__);
            return CKR_CANT_LOCK;
        }
    }

    data.tokdata = tokdata;
    data.ep11_session = ep11_session;
    data.relogin = TRUE;
    rc = handle_all_ep11_cards(&ep11_data->target_list, ep11_login_handler,
                               &data);
    if (rc != CKR_OK)
        TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n", __func__, rc);

    if (ep11_data->vhsm_mode || ep11_data->fips_session_mode) {
        if (pthread_mutex_unlock(&ep11_data->session_mutex)) {
            TRACE_ERROR("%s Failed to unlock session lock\n", __func__);
        }
    }

    return CKR_OK;
}

void ep11_get_pin_blob(STDLL_TokData_t *tokdata, ep11_session_t *ep11_session,
                       CK_BOOL is_session_obj, CK_BOOL is_private_obj,
                       CK_BYTE **pin_blob, CK_ULONG *pin_blob_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    if (ep11_data->strict_mode && ep11_session != NULL &&
        ep11_session->pin_blob_valid && is_session_obj && is_private_obj) {
        *pin_blob = ep11_session->session_pin_blob;
        *pin_blob_len = sizeof(ep11_session->session_pin_blob);
        TRACE_DEVEL("%s Strict mode with CKA_TOKEN=FALSE & CKA_PRIVATE=TRUE "
                    "-> pass session pin_blob\n", __func__);
    } else if (ep11_data->vhsm_mode && ep11_data->vhsm_pin_blob_valid &&
               is_private_obj) {
        *pin_blob = ep11_data->vhsm_pin_blob;
        *pin_blob_len = sizeof(ep11_data->vhsm_pin_blob);
        TRACE_DEVEL("%s VHSM mode with CKA_PRIVATE=TRUE -> pass VHSM pin_blob\n",
                    __func__);
    } else {
        *pin_blob = NULL;
        *pin_blob_len = 0;
    }
}

static CK_RV ep11_open_helper_session(STDLL_TokData_t *tokdata, SESSION *sess,
                                      CK_SESSION_HANDLE_PTR phSession)
{
    CK_RV rc;

    TRACE_INFO("%s\n", __func__);

    rc = SC_OpenSession(tokdata, sess->session_info.slotID,
                        CKF_RW_SESSION | CKF_SERIAL_SESSION |
                        CKF_EP11_HELPER_SESSION, phSession);
    if (rc != CKR_OK)
        TRACE_ERROR("%s SC_OpenSession failed: 0x%lx\n", __func__, rc);

    return rc;
}

static CK_RV ep11_close_helper_session(STDLL_TokData_t *tokdata,
                                       ST_SESSION_HANDLE *sSession,
                                       CK_BBOOL in_fork_initializer)
{
    CK_RV rc;

    TRACE_INFO("%s\n", __func__);

    rc = SC_CloseSession(tokdata, sSession, in_fork_initializer);
    if (rc != CKR_OK)
        TRACE_ERROR("%s SC_CloseSession failed: 0x%lx\n", __func__, rc);

    return rc;
}

static CK_RV generate_ep11_session_id(STDLL_TokData_t *tokdata,
                                      SESSION *session,
                                      ep11_session_t *ep11_session)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    struct {
        CK_SESSION_HANDLE handle;
        CK_SLOT_ID slot;
        struct timeval timeofday;
        clock_t clock;
        pid_t pid;
        CK_BYTE nonce[32];
    } session_id_data;
    CK_MECHANISM mech;
    CK_ULONG len;
    libica_sha_context_t ctx;
    ep11_target_info_t* target_info;

    session_id_data.handle = session->handle;
    session_id_data.slot = session->session_info.slotID;
    gettimeofday(&session_id_data.timeofday, NULL);
    session_id_data.clock = clock();
    session_id_data.pid = tokdata->real_pid;
    rc = rng_generate(tokdata, session_id_data.nonce,
                      sizeof(session_id_data.nonce));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s rng_generate failed: 0x%lx\n", __func__, rc);
        return rc;
    }

    target_info = get_target_info(tokdata);
    if (target_info == NULL)
        return CKR_FUNCTION_FAILED;

    mech.mechanism = CKM_SHA256;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    len = sizeof(ep11_session->session_id);
    if (ep11tok_libica_digest_available(tokdata, ep11_data, mech.mechanism)) {
        rc = ep11tok_libica_digest(tokdata, ep11_data, mech.mechanism, &ctx,
                                   (CK_BYTE_PTR)&session_id_data,
                                   sizeof(session_id_data),
                                   ep11_session->session_id, &len,
                                   SHA_MSG_PART_ONLY);
    } else {
        RETRY_SINGLE_APQN_START(tokdata, rc)
            rc = dll_m_DigestSingle(&mech, (CK_BYTE_PTR)&session_id_data,
                                    sizeof(session_id_data),
                                    ep11_session->session_id, &len,
                                    target_info->target);
        RETRY_SINGLE_APQN_END(rc, tokdata, target_info)
    }

    put_target_info(tokdata, target_info);

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s Digest failed: 0x%lx\n", __func__, rc);
        return rc;
    }

    return CKR_OK;
}

static CK_RV create_ep11_object(STDLL_TokData_t *tokdata,
                                ST_SESSION_HANDLE *handle,
                                CK_BYTE *session_id,
                                CK_ULONG session_id_len,
                                CK_BYTE *pin_blob, CK_ULONG pin_blob_len,
                                CK_OBJECT_HANDLE *obj)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_OBJECT_CLASS class = CKO_HW_FEATURE;
    CK_HW_FEATURE_TYPE type = CKH_IBM_EP11_SESSION;
    CK_BYTE subject[] = "EP11 Session Object";
    pid_t pid;
    CK_DATE date;
    CK_BYTE cktrue = TRUE;
    time_t t;
    struct tm *tm;
    char tmp[40];

    CK_ATTRIBUTE attrs[] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_TOKEN, &cktrue, sizeof(cktrue) },
        { CKA_PRIVATE, &cktrue, sizeof(cktrue) },
        { CKA_HIDDEN, &cktrue, sizeof(cktrue) },
        { CKA_HW_FEATURE_TYPE, &type, sizeof(type) },
        { CKA_SUBJECT, &subject, sizeof(subject) },
        { CKA_VALUE, pin_blob, pin_blob_len },
        { CKA_ID, session_id, session_id_len },
        { CKA_APPLICATION, &ep11_data->target_list, sizeof(ep11_target_t) },
        { CKA_OWNER, &pid, sizeof(pid) },
        { CKA_START_DATE, &date, sizeof(date) }
    };

    pid = tokdata->real_pid;
    time(&t);
    tm = localtime(&t);
    sprintf(tmp, "%04d%02d%02d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    memcpy(date.year, tmp, 4);
    memcpy(date.month, tmp + 4, 2);
    memcpy(date.day, tmp + 4 + 2, 2);

    rc = SC_CreateObject(tokdata, handle,
                         attrs, sizeof(attrs) / sizeof(CK_ATTRIBUTE), obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s SC_CreateObject failed: 0x%lx\n", __func__, rc);
        return rc;
    }

    return CKR_OK;
}

static CK_RV get_pin(STDLL_TokData_t *tokdata, SESSION *session,
                     CK_HW_FEATURE_TYPE type, CK_BYTE *pin, CK_ULONG pin_len)
{
    CK_RV rc;
    ST_SESSION_HANDLE handle = {
        .slotID = session->session_info.slotID,
        .sessionh = session->handle
    };
    CK_OBJECT_HANDLE obj_store[16];
    CK_ULONG objs_found = 0;
    CK_OBJECT_CLASS class = CKO_HW_FEATURE;
    CK_BBOOL cktrue = TRUE;
    CK_ATTRIBUTE pinobj_template[] = {
        { CKA_CLASS, &class, sizeof(class) },
        { CKA_TOKEN, &cktrue, sizeof(cktrue) },
        { CKA_PRIVATE, &cktrue, sizeof(cktrue) },
        { CKA_HIDDEN, &cktrue, sizeof(cktrue) },
        { CKA_HW_FEATURE_TYPE, &type, sizeof(type) },
    };
    CK_ATTRIBUTE attrs[] = {
        { CKA_VALUE, pin, pin_len },
    };

    rc = SC_FindObjectsInit(tokdata, &handle, pinobj_template,
                            sizeof(pinobj_template) / sizeof(CK_ATTRIBUTE));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s SC_FindObjectsInit failed: 0x%lx\n", __func__, rc);
        goto out;
    }

    rc = SC_FindObjects(tokdata, &handle, obj_store, 16, &objs_found);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s SC_FindObjects failed: 0x%lx\n", __func__, rc);
        goto out;
    }

    if (objs_found == 0) {
        rc = CKR_FUNCTION_FAILED;
        TRACE_ERROR("%s No VHSMPIN object found\n", __func__);
        goto out;
    }

    rc = SC_GetAttributeValue(tokdata, &handle, obj_store[0],
                              attrs, sizeof(attrs) / sizeof(CK_ATTRIBUTE));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s SC_GetAttributeValue failed: 0x%lx\n", __func__, rc);
        goto out;
    }

out:
    SC_FindObjectsFinal(tokdata, &handle);
    return rc;
}

CK_RV ep11_login_handler(uint_32 adapter, uint_32 domain, void *handler_data)
{
    login_logout_data_t *data = (login_logout_data_t *)handler_data;
    ep11_private_data_t *ep11_data = data->tokdata->private_data;
    target_t target;
    CK_RV rc;
    CK_BYTE pin_blob[MAX(sizeof(ep11_data->vhsm_pin_blob),
                         sizeof(data->ep11_session->session_pin_blob))];
    CK_ULONG pin_blob_len;
    CK_BYTE *pin = (CK_BYTE *)DEFAULT_EP11_PIN;
    CK_ULONG pin_len = strlen(DEFAULT_EP11_PIN);
    CK_BYTE *nonce = NULL;
    CK_ULONG nonce_len = 0;
    session_nonce_t session_nonce;

    TRACE_INFO("Logging in adapter %02X.%04X\n", adapter, domain);

    rc = get_ep11_target_for_apqn(adapter, domain, &target, 0);
    if (rc != CKR_OK)
        return rc;

    if (ep11_data->vhsm_mode) {
        pin = ep11_data->vhsm_pin;
        pin_len = sizeof(ep11_data->vhsm_pin);
    }

    if (ep11_data->vhsm_mode &&
        (ep11_data->session_refcount == 0 || data->relogin)) {
        session_nonce.slot_id = htobe32(data->tokdata->slot_id);
        memcpy(session_nonce.purpose, VHSM_NONCE_PURPOSE, 12);
        nonce = (CK_BYTE *)&session_nonce;
        nonce_len = sizeof(session_nonce);

        pin_blob_len = sizeof(ep11_data->vhsm_pin_blob);
        rc = dll_m_Login(pin, pin_len, nonce, nonce_len,
                         pin_blob, &pin_blob_len, target);
        if (rc != CKR_OK || pin_blob_len != sizeof(ep11_data->vhsm_pin_blob)) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s dll_m_Login failed: 0x%lx pin_blob_len: %lu\n",
                        __func__, rc, pin_blob_len);
            /* ignore the error here, the adapter may not be able to perform
             * m_Login at this moment */
            rc = CKR_OK;
            goto strict_mode;
        }
#ifdef DEBUG
        TRACE_DEBUG("EP11 VHSM Pin blob:\n");
        TRACE_DEBUG_DUMP("    ", pin_blob, pin_blob_len);
#endif

        if (ep11_data->vhsm_pin_blob_valid) {
            /* First part of pin-blob (keypart and session) must be equal */
            if (memcmp(ep11_data->vhsm_pin_blob, pin_blob, XCP_WK_BYTES) !=
                0) {
                TRACE_ERROR("%s VHSM-Pin blob not equal to previous one\n",
                            __func__);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: VHSM-Pin blob of adapter %02X.%04X is "
                           "not equal to other adapters for same session\n",
                           __func__, adapter, domain);
                rc = CKR_DEVICE_ERROR;
                goto out;
            }
        } else {
            memcpy(ep11_data->vhsm_pin_blob, pin_blob,
                   sizeof(ep11_data->vhsm_pin_blob));
            ep11_data->vhsm_pin_blob_valid = TRUE;
        }
    }

strict_mode:
    if (ep11_data->strict_mode && data->ep11_session != NULL) {
        nonce = data->ep11_session->session_id;
        nonce_len = sizeof(data->ep11_session->session_id);
        /* pin is already set to default pin or vhsm pin (if VHSM mode) */

        pin_blob_len = sizeof(data->ep11_session->session_pin_blob);
        rc = dll_m_Login(pin, pin_len, nonce, nonce_len,
                         pin_blob, &pin_blob_len, target);
        if (rc != CKR_OK ||
            pin_blob_len != sizeof(data->ep11_session->session_pin_blob)) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s dll_m_Login failed: 0x%lx pin_blob_len: %lu\n",
                        __func__, rc, pin_blob_len);
            /* ignore the error here, the adapter may not be able to perform
             * m_Login at this moment */
            rc = CKR_OK;
            goto out;
        }
#ifdef DEBUG
        TRACE_DEBUG("EP11 Session Pin blob:\n");
        TRACE_DEBUG_DUMP("    ", pin_blob, pin_blob_len);
#endif

        if (data->ep11_session->pin_blob_valid) {
            /* First part of pin-blob (keypart and session) must be equal */
            if (memcmp(data->ep11_session->session_pin_blob, pin_blob,
                       XCP_WK_BYTES)
                != 0) {
                TRACE_ERROR("%s Pin blob not equal to previous one\n",
                            __func__);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: Pin blob of adapter %02X.%04X is not "
                           "equal to other adapters for same session\n",
                           __func__, adapter, domain);
                rc = CKR_DEVICE_ERROR;
                goto out;
            }
        } else {
            memcpy(data->ep11_session->session_pin_blob, pin_blob,
                   sizeof(data->ep11_session->session_pin_blob));
            data->ep11_session->pin_blob_valid = TRUE;
        }
    }

out:
    free_ep11_target_for_apqn(target);
    return rc;
}

static CK_RV ep11_logout_handler(uint_32 adapter, uint_32 domain,
                                 void *handler_data)
{
    login_logout_data_t *data = (login_logout_data_t *)handler_data;
    ep11_private_data_t *ep11_data = data->tokdata->private_data;
    target_t target;
    CK_RV rc;

    TRACE_INFO("Logging out adapter %02X.%04X\n", adapter, domain);

    rc = get_ep11_target_for_apqn(adapter, domain, &target, 0);
    if (rc != CKR_OK)
        return rc;

    if (ep11_data->strict_mode && data->ep11_session != NULL &&
        data->ep11_session->pin_blob_valid) {
#ifdef DEBUG
        TRACE_DEBUG("EP11 Session Pin blob\n");
        TRACE_DEBUG_DUMP("    ", data->ep11_session->session_pin_blob,
                         sizeof(data->ep11_session->session_pin_blob));
#endif

        rc = dll_m_Logout(data->ep11_session->session_pin_blob,
                          sizeof(data->ep11_session->session_pin_blob),
                          target);
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s dll_m_Logout failed: 0x%lx\n", __func__, rc);
          /* ignore any errors during m_logout */
        }
    }

    if (ep11_data->vhsm_mode &&
        ep11_data->get_session_refcount(data->tokdata) == 0 &&
        ep11_data->vhsm_pin_blob_valid) {
#ifdef DEBUG
        TRACE_DEBUG("EP11 VHSM Pin blob:\n");
        TRACE_DEBUG_DUMP("    ", ep11_data->vhsm_pin_blob,
                         sizeof(ep11_data->vhsm_pin_blob));
#endif

        rc = dll_m_Logout(ep11_data->vhsm_pin_blob,
                          sizeof(ep11_data->vhsm_pin_blob),
                          target);
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s dll_m_Logout failed: 0x%lx\n", __func__, rc);
            /* ignore any errors during m_logout */
        }
    }

    free_ep11_target_for_apqn(target);
    return CKR_OK;
}

CK_RV ep11tok_login_session(STDLL_TokData_t *tokdata, SESSION *session)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_session_t *ep11_session = NULL;
    CK_RV rc;
    CK_RV rc2;
    ST_SESSION_HANDLE handle = {
        .slotID = session->session_info.slotID,
        .sessionh = session->handle
    };
    CK_SESSION_HANDLE helper_session = CK_INVALID_HANDLE;
    login_logout_data_t data = { 0 };
    CK_BBOOL cnt_incr = FALSE;

    TRACE_INFO("%s session=%lu\n", __func__, session->handle);

    if (!ep11_data->strict_mode && !ep11_data->vhsm_mode &&
        !ep11_data->fips_session_mode)
        return CKR_OK;

    if (session->session_info.flags & CKF_EP11_HELPER_SESSION)
        return CKR_OK;

    switch (session->session_info.state) {
    case CKS_RW_SO_FUNCTIONS:
    case CKS_RO_PUBLIC_SESSION:
    case CKS_RW_PUBLIC_SESSION:
        TRACE_INFO("%s Public or SO session\n", __func__);
        return CKR_OK;
    case CKS_RO_USER_FUNCTIONS:
        rc = ep11_open_helper_session(tokdata, session, &helper_session);
        if (rc != CKR_OK)
            return rc;
        handle.sessionh = helper_session;
        break;
    default:
        break;
    }

    if (session->private_data != NULL) {
        TRACE_INFO("%s Session already logged in\n", __func__);
        rc = CKR_USER_ALREADY_LOGGED_IN;
        goto done_no_lock;
    }

    if (ep11_data->vhsm_mode || ep11_data->fips_session_mode) {
        if (pthread_mutex_lock(&ep11_data->session_mutex)) {
            TRACE_ERROR("%s Failed to lock session lock\n", __func__);
            rc = CKR_CANT_LOCK;
            goto done_no_lock;
        }

        TRACE_DEVEL("%s global session refcount: %u\n", __func__,
                    ep11_data->get_session_refcount(tokdata));
        TRACE_DEVEL("%s session refcount: %u\n", __func__,
                    ep11_data->session_refcount);
    }

    if (ep11_data->strict_mode) {
        ep11_session = calloc(1, sizeof(ep11_session_t));
        if (ep11_session == NULL) {
            TRACE_ERROR("%s Memory allocation failed\n", __func__);
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        ep11_session->session = session;
        ep11_session->session_object = CK_INVALID_HANDLE;
        session->private_data = ep11_session;

        rc = generate_ep11_session_id(tokdata, session, ep11_session);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s _generate_ep11_session_id failed: 0x%lx\n",
                        __func__, rc);
            goto done;
        }
    #ifdef DEBUG
        TRACE_DEBUG("EP11 Session-ID for PKCS#11 session %lu:\n",
                    session->handle);
        TRACE_DEBUG_DUMP("    ", ep11_session->session_id,
                         sizeof(ep11_session->session_id));
    #endif
    }

    if (ep11_data->fips_session_mode && !ep11_data->fips_pin_valid) {
        rc = get_pin(tokdata, session, CKH_IBM_EP11_FIPSPIN,
                     ep11_data->fips_pin, sizeof(ep11_data->fips_pin));
        if (rc != CKR_OK) {
            TRACE_ERROR("%s get_pin(FIPS) failed: 0x%lx\n", __func__, rc);
            OCK_SYSLOG(LOG_ERR,
                       "%s: Error: A FIPS-PIN is required for FIPS_SESSION_MODE.\n",
                       __func__);
            goto done;
        }
        ep11_data->fips_pin_valid = TRUE;
    }

    if (ep11_data->vhsm_mode && !ep11_data->vhsm_pin_valid) {
        rc = get_pin(tokdata, session, CKH_IBM_EP11_VHSMPIN,
                     ep11_data->vhsm_pin, sizeof(ep11_data->vhsm_pin));
        if (rc != CKR_OK) {
            TRACE_ERROR("%s get_pin(VHSM) failed: 0x%lx\n", __func__, rc);
            OCK_SYSLOG(LOG_ERR,
                       "%s: Error: A VHSM-PIN is required for VHSM_MODE.\n",
                       __func__);
            goto done;
        }
        ep11_data->vhsm_pin_valid = TRUE;
    }

    data.tokdata = tokdata;
    data.ep11_session = ep11_session;
    rc = handle_all_ep11_cards(&ep11_data->target_list, ep11_login_handler,
                               &data);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n", __func__, rc);
        goto done;
    }

    if (ep11_data->vhsm_mode || ep11_data->fips_session_mode) {
        ep11_data->session_refcount++;
        ep11_data->incr_session_refcount(tokdata);

        TRACE_DEVEL("%s global session refcount: %u\n", __func__,
                    ep11_data->get_session_refcount(tokdata));
        TRACE_DEVEL("%s session refcount: %u\n", __func__,
                    ep11_data->session_refcount);

        cnt_incr = TRUE;
    }

    if (ep11_data->strict_mode) {
        if (!ep11_session->pin_blob_valid) {
            rc = CKR_DEVICE_ERROR;
            TRACE_ERROR("%s no pinblob available\n", __func__);
            goto done;
        }

        rc = create_ep11_object(tokdata, &handle, ep11_session->session_id,
                                PUBLIC_SESSION_ID_LENGTH,
                                ep11_session->session_pin_blob,
                                sizeof(ep11_session->session_pin_blob),
                                &ep11_session->session_object);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s _create_ep11_object failed: 0x%lx\n", __func__, rc);
            goto done;
        }
    }

    if (ep11_data->vhsm_mode) {
        if (!ep11_data->vhsm_pin_blob_valid) {
            rc = CKR_DEVICE_ERROR;
            TRACE_ERROR("%s no VHSM pinblob available\n", __func__);
            goto done;
        }
    }

done:
    if (rc != CKR_OK) {
        if ((ep11_session != NULL && ep11_session->pin_blob_valid) ||
            ep11_data->vhsm_pin_blob_valid) {
            if (cnt_incr) {
                if (ep11_data->session_refcount > 0)
                    ep11_data->session_refcount--;
                ep11_data->decr_session_refcount(tokdata);
            }

            data.tokdata = tokdata;
            data.ep11_session = ep11_session;
            rc2 = handle_all_ep11_cards(&ep11_data->target_list,
                                        ep11_logout_handler, &data);
            if (rc2 != CKR_OK)
                TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n",
                            __func__, rc2);
        }

        if (ep11_data->strict_mode && ep11_session != NULL &&
            ep11_session->session_object != CK_INVALID_HANDLE) {
            rc2 = SC_DestroyObject(tokdata, &handle,
                                   ep11_session->session_object);
            if (rc2 != CKR_OK)
                TRACE_ERROR("%s SC_DestroyObject failed: 0x%lx\n", __func__,
                            rc2);
        }

        if (ep11_session != NULL) {
            free(ep11_session);
            session->private_data = NULL;
        }

        TRACE_ERROR("%s: failed: 0x%lx\n", __func__, rc);
    }

    if (ep11_data->vhsm_mode || ep11_data->fips_session_mode) {
        if (pthread_mutex_unlock(&ep11_data->session_mutex)) {
            TRACE_ERROR("%s Failed to unlock session lock\n", __func__);
        }
    }

done_no_lock:
    if (helper_session != CK_INVALID_HANDLE) {
        rc2 = ep11_close_helper_session(tokdata, &handle, FALSE);
        if (rc2 != CKR_OK)
            TRACE_ERROR("%s ep11_close_helper_session failed: 0x%lx\n",
                        __func__, rc2);
    }

    return rc;
}

CK_RV ep11tok_logout_session(STDLL_TokData_t *tokdata, SESSION *session,
                             CK_BBOOL in_fork_initializer)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_session_t *ep11_session = (ep11_session_t *)session->private_data;
    CK_RV rc = CKR_OK, rc2;
    ST_SESSION_HANDLE handle = {
        .slotID = session->session_info.slotID,
        .sessionh = session->handle
    };
    CK_SESSION_HANDLE helper_session = CK_INVALID_HANDLE;
    login_logout_data_t data = { 0 };

    TRACE_INFO("%s session=%lu\n", __func__, session->handle);

    if (!ep11_data->strict_mode && !ep11_data->vhsm_mode &&
        !ep11_data->fips_session_mode)
        return CKR_OK;

    if (session->session_info.flags & CKF_EP11_HELPER_SESSION)
        return CKR_OK;

    if (in_fork_initializer)
        goto free_session;

    switch (session->session_info.state) {
    case CKS_RW_SO_FUNCTIONS:
    case CKS_RO_PUBLIC_SESSION:
    case CKS_RW_PUBLIC_SESSION:
        TRACE_INFO("%s Public or SO session\n", __func__);
        return CKR_OK;
    case CKS_RO_USER_FUNCTIONS:
        rc = ep11_open_helper_session(tokdata, session, &helper_session);
        if (rc != CKR_OK)
            return rc;
        handle.sessionh = helper_session;
        break;
    default:
        break;
    }

    if (ep11_data->strict_mode && ep11_session == NULL) {
        TRACE_INFO("%s CKR_USER_NOT_LOGGED_IN\n", __func__);
        rc = CKR_USER_NOT_LOGGED_IN;
        goto done_no_lock;
    }

    if (ep11_data->vhsm_mode || ep11_data->fips_session_mode) {
        if (pthread_mutex_lock(&ep11_data->session_mutex)) {
            TRACE_ERROR("%s Failed to lock session lock\n", __func__);
            rc = CKR_CANT_LOCK;
            goto done_no_lock;
        }

        if (ep11_data->session_refcount > 0)
            ep11_data->session_refcount--;
        ep11_data->decr_session_refcount(tokdata);

        TRACE_DEVEL("%s global session refcount: %u\n", __func__,
                    ep11_data->get_session_refcount(tokdata));
        TRACE_DEVEL("%s session refcount: %u\n", __func__,
                    ep11_data->session_refcount);
    }

    data.tokdata = tokdata;
    data.ep11_session = ep11_session;
    rc = handle_all_ep11_cards(&ep11_data->target_list, ep11_logout_handler,
                               &data);
    if (rc != CKR_OK)
        TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n", __func__, rc);

    if (ep11_data->strict_mode && ep11_session != NULL &&
        ep11_session->session_object != CK_INVALID_HANDLE) {
        rc = SC_DestroyObject(tokdata, &handle, ep11_session->session_object);
        if (rc != CKR_OK)
            TRACE_ERROR("%s SC_DestroyObject failed: 0x%lx\n", __func__, rc);
    }

free_session:
    if (ep11_session != NULL) {
        memset(ep11_session->session_pin_blob, 0,
               sizeof(ep11_session->session_pin_blob));
        free(ep11_session);
        session->private_data = NULL;
    }

    if (ep11_data->vhsm_mode || ep11_data->fips_session_mode) {
        if (ep11_data->session_refcount == 0) {
            ep11_data->vhsm_pin_blob_valid = FALSE;
            memset(ep11_data->vhsm_pin_blob, 0,
                   sizeof(ep11_data->vhsm_pin_blob));
        }

        if (pthread_mutex_unlock(&ep11_data->session_mutex)) {
            TRACE_ERROR("%s Failed to unlock session lock\n", __func__);
        }
    }

done_no_lock:
    if (helper_session != CK_INVALID_HANDLE) {
        rc2 = ep11_close_helper_session(tokdata, &handle, in_fork_initializer);
        if (rc2 != CKR_OK)
            TRACE_ERROR("%s ep11_close_helper_session failed: 0x%lx\n",
                        __func__, rc2);
    }

    return rc;
}
