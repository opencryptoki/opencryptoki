/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2023
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define OCK_NO_EP11_DEFINES
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "attributes.h"
#include "trace.h"
#include "ock_syslog.h"
#include "stdll.h"

#include "events.h"
#include "hsm_mk_change.h"
#include "cfgparser.h"
#include "ep11_specific.h"

#include <strings.h>
#include <err.h>

CK_BBOOL ep11tok_is_blob_new_wkid(STDLL_TokData_t *tokdata,
                                   CK_BYTE *blob, CK_ULONG blob_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_ULONG data_len = 0, spki_len = 0, wkid_len = 0;
    CK_BYTE *data;
    CK_RV rc;

    /*
     * Check if MACed SPKI or key/state blob. From the EP11 structure document:
     *    Session identifiers are guaranteed not to have 0x30 as their first
     *    byte. This allows a single-byte check to differentiate between blobs
     *    starting with session identifiers, and MACed SPKIs, which may be
     *    used as blobs under other conditions.
     * Key and state blobs start with the session identifier (32 bytes).
     * SPKIs start with a DER encoded SPKI, which itself stars with a SEQUENCE
     * denoted by 0x30 followed by the DER encoded length of the SPKI.
     */
    if (blob_len > 5 && blob[0] == 0x30 &&
        ber_decode_SEQUENCE(blob, &data, &data_len, &spki_len) == CKR_OK) {
        /* Its a SPKI, WKID follows as OCTET STRING right after SPKI data */
        if (blob_len < spki_len + 2 + XCP_WKID_BYTES) {
            TRACE_ERROR("MACed SPKI is too small\n");
            return CK_FALSE;
        }

        rc = ber_decode_OCTET_STRING(blob + spki_len, &data, &data_len,
                                     &wkid_len);
        if (rc != CKR_OK || data_len != XCP_WKID_BYTES) {
            TRACE_ERROR("Invalid MACed SPKI encoding\n");
            return CK_FALSE;
        }

        if (memcmp(data, ep11_data->new_wkvp, XCP_WKID_BYTES) == 0)
            return CK_TRUE;

        return CK_FALSE;
    }

    /* Key or state blob */
    if (blob_len < EP11_BLOB_WKID_OFFSET + XCP_WKID_BYTES) {
        TRACE_ERROR("EP11 blob is too small\n");
        return CK_FALSE;
    }

    if (memcmp(blob + EP11_BLOB_WKID_OFFSET, ep11_data->new_wkvp,
               XCP_WKID_BYTES) == 0)
        return CK_TRUE;

    return CK_FALSE;
}

CK_RV ep11tok_reencipher_blob(STDLL_TokData_t *tokdata, SESSION *session,
                              ep11_target_info_t **target_info,
                              CK_BYTE *blob, CK_ULONG blob_len,
                              CK_BYTE *new_blob)
{
    CK_BYTE req[MAX_BLOBSIZE];
    CK_BYTE resp[MAX_BLOBSIZE];
    CK_LONG req_len = 0;
    size_t resp_len = 0;
    struct XCPadmresp rb;
    struct XCPadmresp lrb;
    CK_ULONG retry_count = 0;
    CK_RV rc;

    UNUSED(tokdata);

    TRACE_DEVEL("%s blob: %p blob_len: %lu\n", __func__,
                (void *)blob, blob_len);

    if ((*target_info)->single_apqn == 0) {
        TRACE_ERROR("%s must be used with single APQN target\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

retry:
    memset(&rb, 0, sizeof(rb));
    memset(&lrb, 0, sizeof(lrb));

    RETRY_SINGLE_APQN_START(tokdata, rc)
        rb.domain = (*target_info)->domain;
        lrb.domain = (*target_info)->domain;

        resp_len = MAX_BLOBSIZE;

        req_len = dll_xcpa_cmdblock(req, MAX_BLOBSIZE, XCP_ADM_REENCRYPT, &rb,
                                    NULL, blob, blob_len);

        if (req_len < 0) {
            TRACE_ERROR("%s reencrypt cmd block construction failed\n",
                        __func__);
            rc = CKR_FUNCTION_FAILED;
            break;
        }

        rc = dll_m_admin(resp, &resp_len, NULL, 0, req, req_len, NULL, 0,
                         (*target_info)->target);

        if (session != NULL && rc == CKR_SESSION_CLOSED) {
            rc = ep11tok_relogin_session(tokdata, session);
            if (rc != CKR_OK)
                break;
            continue;
        }
    RETRY_SINGLE_APQN_END(rc, tokdata, *target_info)
    if (rc != CKR_OK || resp_len == 0) {
        TRACE_ERROR("%s reencryption failed: 0x%lx %ld\n", __func__, rc, req_len);
        return resp_len == 0 ? CKR_FUNCTION_FAILED : rc;
    }

    if (dll_xcpa_internal_rv(resp, resp_len, &lrb, &rc) < 0) {
        TRACE_ERROR("%s reencryption response malformed: 0x%lx\n", __func__, rc);
        return CKR_FUNCTION_FAILED;
    }

    if (session != NULL && rc == CKR_SESSION_CLOSED &&
        retry_count < MAX_RETRY_COUNT) {
        rc = ep11tok_relogin_session(tokdata, session);
        if (rc == CKR_OK) {
            retry_count++;
            goto retry;
        }
    }

    if (rc != 0) {
        TRACE_ERROR("%s reencryption failed: rc: 0x%lx reason: %u\n", __func__,
                    rc, lrb.reason);
        switch (lrb.reason) {
        case XCP_RSC_WK_MISSING:
        case XCP_RSC_NEXT_WK_MISSING:
            rc = CKR_IBM_WK_NOT_INITIALIZED;
        }
        return rc;
    }

    if (blob_len != lrb.pllen) {
        TRACE_ERROR("%s reencryption blob size changed: 0x%lx 0x%lx 0x%lx 0x%lx\n",
                    __func__, blob_len, lrb.pllen, resp_len, req_len);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(new_blob, lrb.payload, blob_len);

    if (!ep11tok_is_blob_new_wkid(tokdata, new_blob, blob_len)) {
        TRACE_ERROR("%s Re-enciphered key blob is not enciphered by expected "
                    "new WK\n", __func__);
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Re-enciphered key blob is not enciphered"
                   " by expected new WK\n", tokdata->slot_id);
        return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
}

static CK_RV ep11tok_mk_change_is_affected(STDLL_TokData_t *tokdata,
                                           struct hsm_mk_change_info *info)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    unsigned int i;
    CK_BBOOL affected = FALSE;

    if (hsm_mk_change_mkvps_find(info->mkvps, info->num_mkvps,
                                 HSM_MK_TYPE_EP11, 0) == NULL)
        goto out;

    /* APQN_ANY: token is affected independently of APQNs changed */
    if (ep11_data->target_list.length == 0) {
        affected = TRUE;
        goto out;
    }

    /* APQN_ALLOWLIST */
    for (i = 0; i < (unsigned int)ep11_data->target_list.length; i++) {
        if (hsm_mk_change_apqns_find(info->apqns, info->num_apqns,
                                     ep11_data->target_list.apqns[2 * i],
                                     ep11_data->target_list.apqns[2 * i + 1]))
            affected = TRUE;
    }

out:
    TRACE_DEVEL("%s affected: %d\n", __func__, affected);

    return affected ? CKR_OK : CKR_FUNCTION_NOT_SUPPORTED;
}

static CK_RV ep11tok_activate_mk_change_op(STDLL_TokData_t *tokdata,
                                           const char *id,
                                           const struct hsm_mk_change_info *info)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    ep11_data->mk_change_apqns = calloc(info->num_apqns, sizeof(struct apqn));
    if (ep11_data->mk_change_apqns == NULL) {
        TRACE_ERROR("%s Failed to allocate list of MK change APQNs\n",
                    __func__);
        return CKR_HOST_MEMORY;
    }

    ep11_data->num_mk_change_apqns = info->num_apqns;
    memcpy(ep11_data->mk_change_apqns, info->apqns,
           info->num_apqns * sizeof(struct apqn));

    strncpy(ep11_data->mk_change_op, id, sizeof(ep11_data->mk_change_op) - 1);
    ep11_data->mk_change_op[sizeof(ep11_data->mk_change_op) - 1] = '\0';

    ep11_data->mk_change_active = 1;

    return CKR_OK;
}

static CK_RV ep11tok_mk_change_check_pending_ops_cb(struct hsm_mk_change_op *op,
                                                    void *private)
{
    STDLL_TokData_t *tokdata = private;
    ep11_private_data_t *ep11_data;
    struct hsm_mkvp *mkvps = NULL;
    unsigned int num_mkvps = 0;
    const unsigned char *wkvp;
    int new_wkvp_set = 0;
    CK_RV rc;

    ep11_data = tokdata->private_data;

    rc = ep11tok_mk_change_is_affected(tokdata, &op->info);
    if (rc != CKR_OK)
        return CKR_OK;

    switch (op->state) {
    case HSM_MK_CH_STATE_REENCIPHERING:
    case HSM_MK_CH_STATE_REENCIPHERED:
        /*
         * There can only be one active MK change op for the EP11 token.
         * No need to have the hsm_mk_change_rwlock, we're in token init
         * function, and the API layer starts the event thread only after all
         * token init's have been performed.
         */
        if (ep11_data->mk_change_active) {
            TRACE_ERROR("%s Another MK change is already active: %s\n",
                        __func__, ep11_data->mk_change_op);
            return CKR_FUNCTION_FAILED;
        }

        /* Activate this MK change op for the token */
        rc = ep11tok_activate_mk_change_op(tokdata, op->id, &op->info);
        if (rc != CKR_OK)
            return rc;

        TRACE_DEVEL("%s active MK change op: %s\n", __func__,
                    ep11_data->mk_change_op);

        wkvp = hsm_mk_change_mkvps_find(op->info.mkvps, op->info.num_mkvps,
                                        HSM_MK_TYPE_EP11,
                                        sizeof(ep11_data->new_wkvp));
        if (wkvp != NULL) {
            memcpy(ep11_data->new_wkvp, wkvp, sizeof(ep11_data->new_wkvp));
            new_wkvp_set = 1;
        }

        if (new_wkvp_set == 0) {
            TRACE_ERROR("%s No EP11 WKVP found in MK change operation: %s\n",
                        __func__, ep11_data->mk_change_op);
            return CKR_FUNCTION_FAILED;
        }

        TRACE_DEBUG_DUMP("New WKVP: ", ep11_data->new_wkvp,
                         sizeof(ep11_data->new_wkvp));

        /* Load expected current WKVP */
        rc = hsm_mk_change_token_mkvps_load(op->id, tokdata->slot_id,
                                            &mkvps, &num_mkvps);
        /* Ignore if this failed, no expected current WKVP is set then */
        if (rc == CKR_OK) {
            wkvp = hsm_mk_change_mkvps_find(mkvps, num_mkvps, HSM_MK_TYPE_EP11,
                                            sizeof(ep11_data->expected_wkvp));
            if (wkvp != NULL) {
                memcpy(ep11_data->expected_wkvp, wkvp,
                       sizeof(ep11_data->expected_wkvp));
                ep11_data->expected_wkvp_set = 1;

                TRACE_DEBUG_DUMP("Current WKVP: ", ep11_data->expected_wkvp,
                                 sizeof(ep11_data->expected_wkvp));
            }
        }
        break;

    default:
        break;
    }

    if (mkvps != NULL) {
        hsm_mk_change_mkvps_clean(mkvps, num_mkvps);
        free(mkvps);
    }

    return CKR_OK;
}

CK_RV ep11tok_mk_change_check_pending_ops(STDLL_TokData_t *tokdata)
{
    CK_RV rc;

    rc = hsm_mk_change_lock_create();
    if (rc != CKR_OK)
        return rc;

    rc = hsm_mk_change_lock(false);
    if (rc != CKR_OK)
        goto out;

    rc = hsm_mk_change_op_iterate(ep11tok_mk_change_check_pending_ops_cb,
                                  tokdata);

    hsm_mk_change_unlock();

out:
    hsm_mk_change_lock_destroy();

    return rc;
}

struct apqn_check_data {
    ep11_private_data_t *ep11_data;
    CK_SLOT_ID slot;
    event_mk_change_data_t *op;
    struct hsm_mk_change_info *info;
    CK_BBOOL finalize;
    CK_BBOOL cancel;
    CK_BBOOL error;
};

/*
 * Note: This function is called EVENT_TYPE_MK_CHANGE_INITIATE_QUERY event
 * handling within the pkcshsm_mk_change tool's process only. It is supposed
 * to print error messages to stderr to inform the user about errors.
 *
 */
static CK_RV mk_change_apqn_check_handler(uint_32 adapter, uint_32 domain,
                                          void *handler_data)
{
    struct apqn_check_data *ac = (struct apqn_check_data *)handler_data;

    CK_IBM_DOMAIN_INFO domain_info;
    CK_ULONG domain_info_len = sizeof(domain_info);
    const unsigned char *wkvp;
    CK_RV rc;
    target_t target;

    /*
     * Check that this APQN is part of the MK change operation, even if it is
     * offline (this only applies to an APQN_ALLOWLIST configuration, for a
     * APQN_ANY configuration, we will only be called for currently online
     * APQNs anyway).
     */
    if (hsm_mk_change_apqns_find(ac->info->apqns, ac->info->num_apqns,
                                 adapter, domain) == FALSE) {
        TRACE_ERROR("%s APQN %02X.%04X is not part of MK change '%s'\n",
                    __func__, adapter, domain, ac->op->id);
        warnx("Slot %lu: APQN %02X.%04X must be included into this operation.",
              ac->slot, adapter, domain);

        ac->error = TRUE;
        return CKR_OK;
    }

    /* Check that current and new WK is as expected */
    rc = get_ep11_target_for_apqn(adapter, domain, &target, 0);
    if (rc != CKR_OK) {
        warnx("Slot %lu: Failed to get target for APQN %02X.%04X",
              ac->slot, adapter, domain);
        ac->error = TRUE;
        return rc;
    }

    rc = dll_m_get_xcp_info(&domain_info, &domain_info_len, CK_IBM_XCPQ_DOMAIN,
                            0, target);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to query domain info from APQN %02X.%04X: "
                    "0x%lx\n", __func__, adapter, domain, rc);
        /* card may no longer be online, so ignore this error situation */
        rc = CKR_OK;
        goto out;
    }

    if ((domain_info.flags & CK_IBM_DOM_CURR_WK) == 0) {
        TRACE_ERROR("%s No current EP11 wrapping key is set on APQN %02X.%04X\n",
                    __func__, adapter, domain);
        warnx("Slot %lu: No current EP11 wrapping key is set on APQN %02X.%04X",
              ac->slot, adapter, domain);
        ac->error = TRUE;
        goto out;
    }

    TRACE_DEBUG("%s Current WKVP of APQN %02X.%04X:\n", __func__, adapter, domain);
    TRACE_DEBUG_DUMP("full WKVP: ", domain_info.wk, sizeof(domain_info.wk));

    if (ac->finalize) {
        /* Current WK must be the new WK.
         * hsm_mk_change_rwlock is held by caller, if check_new_wk_set is TRUE.
         */
        if (memcmp(domain_info.wk, ac->ep11_data->new_wkvp,
                   XCP_WKID_BYTES) != 0) {
            TRACE_ERROR("EP11 wrapping key on APQN %02X.%04X does not "
                        "match the new wrapping key\n", adapter, domain);
            warnx("Slot %lu: The current EP11 WK on APQN %02X.%04X does not match "
                  "the new WK", ac->slot, adapter, domain);
            ac->error = TRUE;
        }
        goto out;
    }

    /* Current WK must be the expected WK */
    if (memcmp(domain_info.wk, ac->ep11_data->expected_wkvp,
               XCP_WKID_BYTES) != 0) {
        TRACE_ERROR("EP11 wrapping key on APQN %02X.%04X does not "
                    "match the expected wrapping key\n", adapter, domain);
        warnx("Slot %lu: The current EP11 WK on APQN %02X.%04X does not match "
              "the expected one", ac->slot, adapter, domain);
        ac->error = TRUE;
        goto out;
    }

    if (ac->cancel) /* Skip new WK check in case of cancel */
        goto out;

    if ((domain_info.flags & CK_IBM_DOM_COMMITTED_NWK) == 0) {
        TRACE_ERROR("%s No new EP11 wrapping key is set/committed on APQN %02X.%04X\n",
                    __func__, adapter, domain);
        warnx("Slot %lu: No new EP11 wrapping key is set/committed on APQN %02X.%04X",
              ac->slot, adapter, domain);
        ac->error = TRUE;
        goto out;
    }

    TRACE_DEBUG("%s New WKVP of APQN %02X.%04X:\n", __func__, adapter, domain);
    TRACE_DEBUG_DUMP("full WKVP: ", domain_info.nextwk,
                     sizeof(domain_info.nextwk));

    wkvp = hsm_mk_change_mkvps_find(ac->info->mkvps, ac->info->num_mkvps,
                                    HSM_MK_TYPE_EP11, XCP_WKID_BYTES);
    if (wkvp != NULL &&
        memcmp(domain_info.nextwk, wkvp, XCP_WKID_BYTES) != 0) {
        TRACE_ERROR("New EP11 wrapping key on APQN %02X.%04X does not "
                    "match the specified wrapping key\n", adapter, domain);
        warnx("Slot %lu: The new EP11 WK on APQN %02X.%04X does not match "
              "the specified WKVP", ac->slot, adapter, domain);
        ac->error = TRUE;
        goto out;
    }

out:
    free_ep11_target_for_apqn(target);

    return CKR_OK;
}

struct reencipher_data {
    STDLL_TokData_t *tokdata;
    SESSION *session;
    ep11_target_info_t *target_info;
};

static CK_RV ep11tok_reencipher_objects_reenc(CK_BYTE *sec_key,
                                              CK_BYTE *reenc_sec_key,
                                              CK_ULONG sec_key_len,
                                              void *private)
{
    struct reencipher_data *rd = private;

    return ep11tok_reencipher_blob(rd->tokdata, rd->session, &rd->target_info,
                                   sec_key, sec_key_len, reenc_sec_key);
}

static CK_RV ep11tok_reencipher_objects_cb(STDLL_TokData_t *tokdata,
                                           OBJECT *obj, void *cb_data)
{
    struct reencipher_data *rd = cb_data;
    SESSION *session_save;
    CK_RV rc;

    session_save = rd->session;
    if (obj->session != NULL) /* session is NULL for token objects */
        rd->session = obj->session;
    rc = obj_mgr_reencipher_secure_key(tokdata, obj,
                                       ep11tok_reencipher_objects_reenc, rd);
    if (rc == CKR_OBJECT_HANDLE_INVALID) /* Obj was deleted by other proc */
        rc = CKR_OK;
    rd->session = session_save;

    return rc;
}

static CK_BBOOL ep11tok_reencipher_filter_cb(STDLL_TokData_t *tokdata,
                                             OBJECT *obj, void *filter_data)
{
    CK_ATTRIBUTE *attr;

    UNUSED(tokdata);
    UNUSED(filter_data);

    return template_attribute_find(obj->template, CKA_IBM_OPAQUE_REENC, &attr);
}

static CK_RV ep11tok_reencipher_cancel_objects_cb(STDLL_TokData_t *tokdata,
                                                  OBJECT *obj, void *cb_data)
{
    CK_RV rc;

    UNUSED(cb_data);

    rc = obj_mgr_reencipher_secure_key_cancel(tokdata, obj);
    if (rc == CKR_ATTRIBUTE_TYPE_INVALID)
        rc = CKR_OK;
    if (rc == CKR_OBJECT_HANDLE_INVALID) /* Obj was deleted by other proc */
        rc = CKR_OK;

    return rc;
}

static CK_BBOOL ep11tok_reencipher_finalize_is_new_wk_cb(
                                                 STDLL_TokData_t *tokdata,
                                                 OBJECT *obj,
                                                 CK_BYTE *sec_key,
                                                 CK_ULONG sec_key_len,
                                                 void *cb_private)
{
    UNUSED(cb_private);
    UNUSED(obj);

    return ep11tok_is_blob_new_wkid(tokdata, sec_key, sec_key_len);
}

static CK_RV ep11tok_reencipher_finalize_objects_cb(STDLL_TokData_t *tokdata,
                                                    OBJECT *obj, void *cb_data)
{
    CK_RV rc;

    UNUSED(cb_data);

    rc = obj_mgr_reencipher_secure_key_finalize(tokdata, obj,
                                ep11tok_reencipher_finalize_is_new_wk_cb, NULL);
    if (rc == CKR_ATTRIBUTE_TYPE_INVALID)
        rc = CKR_OK;
    if (rc == CKR_OBJECT_HANDLE_INVALID) /* Obj was deleted by other proc */
        rc = CKR_OK;

    return rc;
}

static CK_RV ep11tok_reencipher_session_op_ctx(STDLL_TokData_t *tokdata,
                                               SESSION *session,
                                               CK_BYTE *context,
                                               CK_ULONG context_len,
                                               ep11_target_info_t **target_info,
                                               const char *ctx_type,
                                               CK_BBOOL finalize)
{
    CK_RV rc;

    TRACE_INFO("%s %s %s state blob of session 0x%lx\n", __func__,
               finalize ? "Finalize" : "Re-encipher",
               ctx_type, session->handle);
    OCK_SYSLOG(LOG_DEBUG, "Slot %lu: %s %s state blob of session 0x%lx\n",
               tokdata->slot_id, finalize ? "Finalize" : "Re-encipher",
               ctx_type, session->handle);

    /* The context is allocated at least twice as large as needed */
    if (finalize == FALSE) {
        rc = ep11tok_reencipher_blob(tokdata, session, target_info,
                                     context, context_len / 2,
                                     context + (context_len / 2));
        if (rc != CKR_OK) {
            TRACE_ERROR("%s failed to re-encipher %s state blob of session "
                        "0x%lx: 0x%lx\n", __func__, ctx_type, session->handle,
                        rc);
            OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to re-encipher %s state blob"
                       "of session 0x%lx: 0x%lx\n", tokdata->slot_id, ctx_type,
                       session->handle, rc);
            return rc;
        }
    } else {
        memcpy(context, context + (context_len / 2), context_len / 2);
    }

    return CKR_OK;
}

struct reencipher_session_data {
    ep11_target_info_t *target_info;
    CK_BBOOL finalize;
    CK_RV (*func)(STDLL_TokData_t *tokdata, SESSION *session,
                  CK_BYTE *context, CK_ULONG context_len,
                  ep11_target_info_t **target_info, const char *ctx_type,
                  CK_BBOOL finalize);
};

static CK_RV ep11tok_reencipher_sessions_cb(STDLL_TokData_t *tokdata,
                                            SESSION *session,
                                            CK_ULONG ctx_type,
                                            CK_MECHANISM *mech,
                                            CK_OBJECT_HANDLE key,
                                            CK_BYTE *context,
                                            CK_ULONG context_len,
                                            CK_BBOOL init_pending,
                                            CK_BBOOL pkey_active,
                                            CK_BBOOL recover,
                                            void *private)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    struct reencipher_session_data *rsd = private;
    const char *ctx_type_str = NULL;

    UNUSED(recover);

    /* Check preconditions */
    switch (ctx_type) {
    case CONTEXT_TYPE_DIGEST:
        if (ep11tok_libica_digest_available(tokdata, ep11_data,
                                            mech->mechanism))
            return CKR_OK;

        ctx_type_str = "digest";
        break;

    case CONTEXT_TYPE_SIGN:
        if (init_pending || pkey_active)
            return CKR_OK;
        if (ep11tok_libica_mech_available(tokdata, mech->mechanism, key))
            return CKR_OK;

        ctx_type_str = "sign";
        break;

    case CONTEXT_TYPE_VERIFY:
        if (init_pending || pkey_active)
            return CKR_OK;
        if (ep11tok_libica_mech_available(tokdata, mech->mechanism, key))
            return CKR_OK;

        ctx_type_str = "verify";
        break;

    case CONTEXT_TYPE_ENCRYPT:
        if (init_pending || pkey_active)
            return CKR_OK;

        ctx_type_str = "encrypt";
        break;

    case CONTEXT_TYPE_DECRYPT:
        if (init_pending || pkey_active)
            return CKR_OK;

        ctx_type_str = "decrypt";
        break;

    default:
        return CKR_OK;
    }

    return rsd->func(tokdata, session, context, context_len, &rsd->target_info,
                     ctx_type_str, rsd->finalize);
}

static CK_RV ep11tok_reencipher_sessions(STDLL_TokData_t *tokdata,
                                         ep11_target_info_t **target_info,
                                         CK_BBOOL finalize)
{
    struct reencipher_session_data rsd = { 0 };
    CK_RV rc;

    if (target_info != NULL)
        rsd.target_info = *target_info;
    rsd.finalize = finalize;
    rsd.func = ep11tok_reencipher_session_op_ctx;

    rc = session_mgr_iterate_session_ops(tokdata, NULL,
                                         ep11tok_reencipher_sessions_cb, &rsd);

    if (target_info != NULL)
        *target_info = rsd.target_info;

    return rc;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV ep11tok_mk_change_init_query(STDLL_TokData_t *tokdata,
                                          event_mk_change_data_t *op,
                                          struct hsm_mk_change_info *info)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    struct apqn_check_data acd;
    struct hsm_mkvp mkvp;
    CK_RV rc;

    TRACE_DEVEL("%s initial query for MK change op: %s\n", __func__, op->id);

    memset(&acd, 0, sizeof(acd));
    acd.ep11_data = ep11_data;
    acd.slot = tokdata->slot_id;
    acd.op = op;
    acd.info = info;
    acd.error = FALSE;

    rc = handle_all_ep11_cards(&ep11_data->target_list,
                               mk_change_apqn_check_handler, &acd);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n", __func__, rc);
        return rc;
    }

    if (acd.error)
        return CKR_FUNCTION_FAILED;

    /* Save current WKVP of this token */
    mkvp.type = HSM_MK_TYPE_EP11;
    mkvp.mkvp_len = XCP_WKID_BYTES;
    mkvp.mkvp = ep11_data->expected_wkvp;

    rc = hsm_mk_change_lock_create();
    if (rc != CKR_OK)
        return rc;

    rc = hsm_mk_change_lock(true);
    if (rc != CKR_OK)
        goto out;

    rc = hsm_mk_change_token_mkvps_save(op->id, tokdata->slot_id, &mkvp, 1);

    hsm_mk_change_unlock();

out:
    hsm_mk_change_lock_destroy();

    return rc;
}

static void ep11tok_mk_change_find_rw_session_cb(STDLL_TokData_t *tokdata,
                                                 void *node_value,
                                                 unsigned long node_idx,
                                                 void *p3)
{
    SESSION *s = (SESSION *)node_value;
    CK_SESSION_HANDLE *ret = (CK_SESSION_HANDLE *)p3;

    UNUSED(tokdata);
    UNUSED(node_idx);

    if (*ret != CK_INVALID_HANDLE)
        return;

    if ((s->session_info.flags & CKF_RW_SESSION) != 0 &&
        s->session_info.state == CKS_RW_USER_FUNCTIONS)
        *ret = s->handle;
}

static CK_RV ep11tok_mk_change_find_rw_session(STDLL_TokData_t *tokdata,
                                               SESSION **session)
{
    CK_SESSION_HANDLE handle = CK_INVALID_HANDLE;

    if (pthread_rwlock_wrlock(&tokdata->sess_list_rwlock)) {
        TRACE_ERROR("Write Lock failed.\n");
        return CKR_CANT_LOCK;
    }

    bt_for_each_node(tokdata, &tokdata->sess_btree,
                     ep11tok_mk_change_find_rw_session_cb, &handle);

    pthread_rwlock_unlock(&tokdata->sess_list_rwlock);

    if (handle == CK_INVALID_HANDLE) {
        TRACE_ERROR("No R/W session found.\n");
        return CKR_FUNCTION_FAILED;
    }

    *session = session_mgr_find(tokdata, handle);
    if (*session == NULL) {
        TRACE_ERROR("No R/W session found.\n");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV ep11tok_mk_change_reencipher(STDLL_TokData_t *tokdata,
                                          event_mk_change_data_t *op,
                                          struct hsm_mk_change_info *info)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    struct reencipher_data rd = { 0 };
    CK_RV rc = CKR_OK;
    const unsigned char *wkvp;
    int new_wkvp_set = 0;
    CK_BBOOL token_objs = FALSE;

    if ((op->flags & EVENT_MK_CHANGE_FLAGS_TOK_OBJS) != 0) {
        token_objs = TRUE;
        /* The tool should have logged in a R/W USER session */
        rc = ep11tok_mk_change_find_rw_session(tokdata, &rd.session);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s No user session exists\n", __func__);
            OCK_SYSLOG(LOG_ERR, "Slot %lu: No user session exists\n",
                       tokdata->slot_id);
            return CKR_FUNCTION_FAILED;
        }
    }

    if (pthread_rwlock_wrlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("HSM-MK-change Write-Lock failed.\n");
        OCK_SYSLOG(LOG_ERR, "Slot %lu: HSM-MK-change Write-Lock failed\n",
                   tokdata->slot_id);
        rc = CKR_CANT_LOCK;
        goto out;
    }

    if (token_objs == TRUE && ep11_data->mk_change_active == FALSE) {
        TRACE_DEVEL("HSM-MK-change must already be active\n");
        OCK_SYSLOG(LOG_ERR, "Slot %lu: HSM-MK-change must already be active\n",
                   tokdata->slot_id);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    /* Activate this MK change operation */
    if (ep11_data->mk_change_active == FALSE) {
        rc = ep11tok_activate_mk_change_op(tokdata, op->id, info);
        if (rc != CKR_OK)
            goto out;
    }

    TRACE_DEVEL("%s active MK change op: %s\n", __func__,
                ep11_data->mk_change_op);

    wkvp = hsm_mk_change_mkvps_find(info->mkvps, info->num_mkvps,
                                    HSM_MK_TYPE_EP11,
                                    sizeof(ep11_data->new_wkvp));
    if (wkvp != NULL) {
        memcpy(ep11_data->new_wkvp, wkvp, sizeof(ep11_data->new_wkvp));
        new_wkvp_set = 1;
    }

    if (new_wkvp_set == 0) {
        TRACE_ERROR("%s No EP11 WKVP found in MK change operation: %s\n",
                    __func__, ep11_data->mk_change_op);
        OCK_SYSLOG(LOG_ERR,
                   "Slot %lu: No EP11 WKVP found in MK change operation: %s\n",
                   tokdata->slot_id, ep11_data->mk_change_op);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    TRACE_DEBUG_DUMP("New WKVP: ", ep11_data->new_wkvp,
                     sizeof(ep11_data->new_wkvp));

    /* Switch to single APQN mode (only for first event - token_objs = FALSE) */
    if (token_objs == FALSE) {
        rc = refresh_target_info(tokdata, FALSE);
        if (rc != CKR_OK) {
            OCK_SYSLOG(LOG_ERR,
                       "Slot %lu: Failed to select a single APQN: 0x%lx\n",
                       tokdata->slot_id, rc);
            goto out;
        }
    }

    rd.tokdata = tokdata;
    rd.target_info = get_target_info(tokdata);
    if (rd.target_info == NULL) {
        rc = CKR_FUNCTION_FAILED;
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to select a single APQN\n",
                   tokdata->slot_id);
        goto out;
    }

    if (rd.target_info->single_apqn == FALSE) {
        TRACE_ERROR("%s Must operate in single-APQN mode\n", __func__);
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to select a single APQN\n",
                   tokdata->slot_id);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    /* Re-encipher key objects */
    rc = obj_mgr_iterate_key_objects(tokdata, !token_objs, token_objs,
                                     NULL, NULL,
                                     ep11tok_reencipher_objects_cb, &rd,
                                     TRUE, "re-encipher");
    if (rc != CKR_OK)
        goto out;

    if (!token_objs) {
        /* Re-encipher session state blobs */
        rc = ep11tok_reencipher_sessions(tokdata, &rd.target_info, FALSE);
        if (rc != CKR_OK) {
            OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to re-encipher session "
                       "states: 0x%lx\n", tokdata->slot_id, rc);
            goto out;
        }

        /* Re-enciper the wrap blob */
        TRACE_INFO("Re-encipher the wrap blob\n");
        rc = ep11tok_reencipher_blob(tokdata, NULL, &rd.target_info,
                                     ep11_data->raw2key_wrap_blob,
                                     ep11_data->raw2key_wrap_blob_l,
                                     ep11_data->raw2key_wrap_blob_reenc);
        if (rc != CKR_OK) {
            TRACE_ERROR("Re-encipher of wrap blob failed.\n");
            OCK_SYSLOG(LOG_ERR,
                       "Slot %lu: Failed to re-encipher the wrap blob: 0x%lx\n",
                       tokdata->slot_id, rc);
            goto out;
        }
    }

out:
    if (rc != CKR_OK && rd.target_info != NULL) {
        obj_mgr_iterate_key_objects(tokdata, !token_objs, token_objs,
                                    ep11tok_reencipher_filter_cb, NULL,
                                    ep11tok_reencipher_cancel_objects_cb, NULL,
                                    TRUE, "cancel");
        /*
         * The pkcshsm_mk_change tool will send a CANCEL event, so leave the
         * operation active for now.
         */
    }

    put_target_info(tokdata, rd.target_info);

    if (rd.session != NULL)
        session_mgr_put(tokdata, rd.session);

    if (pthread_rwlock_unlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("HSM-MK-change Unlock failed.\n");
        OCK_SYSLOG(LOG_ERR, "Slot %lu: HSM-MK-change unlock failed\n",
                   tokdata->slot_id);
        if (rc == CKR_OK)
            rc = CKR_CANT_LOCK;
    }

    return rc;
}

static CK_RV ep11tok_set_operation_state_cb(STDLL_TokData_t *tokdata,
                                            SESSION *session,
                                            CK_BYTE *context,
                                            CK_ULONG context_len,
                                            ep11_target_info_t **target_info,
                                            const char *ctx_type,
                                            CK_BBOOL finalize)
{
    TRACE_INFO("%s Re-encipher %s state blob of session 0x%lx\n", __func__,
               ctx_type, session->handle);

    if (ep11tok_is_blob_new_wkid(tokdata, context, context_len / 2)) {
        TRACE_DEVEL("%s state blob is already enciphered with new WK\n",
                    __func__);
        return CKR_OK;
    }

    if (ep11tok_is_blob_new_wkid(tokdata, context + (context_len / 2),
                                 context_len / 2)) {
        TRACE_DEVEL("%s state blob is already reenciphered\n", __func__);
        return CKR_OK;
    }

    if ((*target_info)->single_apqn_has_new_wk) {
        TRACE_ERROR("%s New WK already activated, state blob can not be "
                    "reenciphered\n", __func__);
        return CKR_SAVED_STATE_INVALID;
    }

    return ep11tok_reencipher_session_op_ctx(tokdata, session,
                                             context, context_len, target_info,
                                             ctx_type, finalize);
}

CK_RV ep11tok_set_operation_state(STDLL_TokData_t *tokdata, SESSION *session)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    struct reencipher_session_data rsd = { 0 };
    CK_RV rc;

    if (ep11_data->mk_change_active == FALSE)
        return CKR_OK;

    /* Re-encipher the newly set session (if needed) */
    rsd.target_info = get_target_info(tokdata);
    if (rsd.target_info == NULL)
        return CKR_FUNCTION_FAILED;

    rsd.finalize = FALSE;
    rsd.func = ep11tok_set_operation_state_cb;

    rc = session_mgr_iterate_session_ops(tokdata, session,
                                         ep11tok_reencipher_sessions_cb, &rsd);

    put_target_info(tokdata, rsd.target_info);

    return rc;
}

static CK_RV parse_expected_wkvp(ep11_private_data_t *ep11_data,
                                 const char *fname, const char *strval,
                                 unsigned char expected_wkvp[XCP_WKID_BYTES])
{
    unsigned int i, val;

    if (strncasecmp(strval, "0x", 2) == 0)
        strval += 2;

    if (strlen(strval) < XCP_WKID_BYTES * 2) {
        TRACE_ERROR("%s expected WKVP is too short: '%s', expected %lu hex "
                    "characters in config file '%s'\n", __func__, strval,
                    sizeof(ep11_data->expected_wkvp) * 2, fname);
        return CKR_FUNCTION_FAILED;
    }

    if (strlen(strval) > XCP_WKID_BYTES * 2) {
        TRACE_INFO("%s only the first %lu characters of the expected WKVP in "
                   "config file '%s' are used: %s\n", __func__,
                    sizeof(ep11_data->expected_wkvp) * 2, fname, strval);
    }

    for (i = 0; i < XCP_WKID_BYTES; i++) {
        if (sscanf(strval + (i * 2), "%02x", &val) != 1) {
            TRACE_ERROR("%s failed to parse expected WKVP: '%s' at character "
                        "%u in config file '%s'\n", __func__, strval, (i * 2),
                        fname);
            return CKR_FUNCTION_FAILED;
        }
        expected_wkvp[i] = val;
    }

    TRACE_DEBUG_DUMP("Expected WKVP:  ", expected_wkvp, XCP_WKID_BYTES);

    return CKR_OK;
}

static CK_RV check_token_config_expected_wkvp(STDLL_TokData_t *tokdata,
                                              CK_BBOOL new_wk)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    struct ConfigBaseNode *c, *config = NULL;
    struct ConfigBareStringConstNode *barestr;
    unsigned char wkvp[XCP_WKID_BYTES];
    char *strval = NULL;
    FILE *fp;
    CK_RV rc = CKR_OK;
    int rc2, i;

    fp = fopen(ep11_data->token_config_filename, "r");
    if (fp == NULL) {
        TRACE_ERROR("Failed to open config file '%s'\n",
                    ep11_data->token_config_filename);
        return CKR_FUNCTION_FAILED;
    }

    rc2 = parse_configlib_file(fp, &config, ep11_config_parse_error, 0);
    fclose(fp);
    if (rc2 != 0) {
        TRACE_ERROR("Error parsing config file '%s'\n",
                    ep11_data->token_config_filename);
        return CKR_FUNCTION_FAILED;
    }

    confignode_foreach(c, config, i) {
        TRACE_DEBUG("Config node: '%s' type: %u line: %u\n",
                    c->key, c->type, c->line);

        if (strcmp(c->key, "EXPECTED_WKVP") == 0) {
            if (confignode_hastype(c, CT_STRINGVAL) ||
                confignode_hastype(c, CT_BAREVAL)) {
                /* New style (key = value) tokens */
                strval = confignode_getstr(c);
                break;
            } else if (confignode_hastype(c, CT_BARECONST)) {
                rc = ep11_config_next(&c, CT_BARESTRINGCONST,
                                      ep11_data->token_config_filename,
                                      "WKID as quoted hex string");
                if (rc != CKR_OK)
                    break;

                barestr = confignode_to_barestringconst(c);
                strval = barestr->base.key;
                break;
            }

            ep11_config_error_token(ep11_data->token_config_filename,
                                    c->key, c->line, NULL);
            rc = CKR_FUNCTION_FAILED;
            break;
        }
    }

    if (strval == NULL) {
        TRACE_DEVEL("No 'EXPECTED_WKVP' in config file '%s'\n",
                    ep11_data->token_config_filename);
        goto out;
    }

    rc = parse_expected_wkvp(ep11_data, ep11_data->token_config_filename,
                             strval, wkvp);
    if (rc != CKR_OK)
        goto out;

    if (memcmp(wkvp, new_wk ? ep11_data->new_wkvp : ep11_data->expected_wkvp,
               XCP_WKID_BYTES) != 0) {
        TRACE_ERROR("Expected WKVP in config file '%s' does not specify the %s WKVP\n",
                    ep11_data->token_config_filename,
                    new_wk ? "new" : "current");
        warnx("Expected WKVP in config file '%s' does not specify the %s WKVP.",
              ep11_data->token_config_filename, new_wk ? "new" : "current");
        rc = CKR_FUNCTION_FAILED;
    }

out:
    confignode_deepfree(config);
    return rc;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV ep11tok_mk_change_finalize_query(STDLL_TokData_t *tokdata,
                                              event_mk_change_data_t *op,
                                              struct hsm_mk_change_info *info)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    struct apqn_check_data acd;
    CK_RV rc;

    TRACE_DEVEL("%s finalize query for MK change op: %s\n", __func__, op->id);

    if (pthread_rwlock_rdlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("MK-change Read-Lock failed.\n");
        return CKR_CANT_LOCK;
    }

    memset(&acd, 0, sizeof(acd));
    acd.ep11_data = ep11_data;
    acd.slot = tokdata->slot_id;
    acd.op = op;
    acd.info = info;
    acd.finalize = TRUE; /* New WK must be set */
    acd.error = FALSE;

    rc = handle_all_ep11_cards(&ep11_data->target_list,
                               mk_change_apqn_check_handler, &acd);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n", __func__, rc);
        goto out;
    }

    if (acd.error) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = check_token_config_expected_wkvp(tokdata, TRUE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s check_token_config_expected_wkvp failed: 0x%lx\n",
                    __func__, rc);
        goto out;
    }

out:
    if (pthread_rwlock_unlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("MK-change Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

    return rc;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV ep11tok_mk_change_finalize_cancel(STDLL_TokData_t *tokdata,
                                               event_mk_change_data_t *op,
                                               struct hsm_mk_change_info *info,
                                               CK_BBOOL cancel)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_BBOOL token_objs = FALSE;

    UNUSED(info);

    TRACE_DEVEL("%s %s MK change op: %s\n", __func__,
                cancel ? "canceling" : "finalizing", op->id);

    if ((op->flags & EVENT_MK_CHANGE_FLAGS_TOK_OBJS) != 0 ||
        (op->flags & EVENT_MK_CHANGE_FLAGS_TOK_OBJS_FINAL) != 0) {
        token_objs = TRUE;
        /* The tool should have logged in a R/W USER session */
        if (!session_mgr_user_session_exists(tokdata)) {
            TRACE_ERROR("%s No user session exists\n", __func__);
            OCK_SYSLOG(LOG_ERR, "Slot %lu: No user session exists\n",
                       tokdata->slot_id);
            return CKR_FUNCTION_FAILED;
        }
    }

    if (pthread_rwlock_wrlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("HSM-MK-change Write-Lock failed.\n");
        OCK_SYSLOG(LOG_ERR, "Slot %lu: HSM-MK-change Write-Lock failed\n",
                   tokdata->slot_id);
        rc = CKR_CANT_LOCK;
        goto out;
    }

    if (ep11_data->mk_change_active == FALSE)
        goto out;

    /*
     * Finalize/cancel token objects.
     * If flag EVENT_MK_CHANGE_FLAGS_TOK_OBJS_FINAL is on, only process such
     * token objects that do have the CKA_IBM_OPAQUE_REENC attribute. Those
     * Objects have been newly created by another process after the first token
     * finalization/cancellation (flag EVENT_MK_CHANGE_FLAGS_TOK_OBJS) has
     * been performed, and before all processes have deactivated the MK change
     * operation. Thus, they were created with the re-enciphered secure key,
     * and now need to be finalized/canceled.
     */
    rc = obj_mgr_iterate_key_objects(tokdata, !token_objs, token_objs,
                                     token_objs && (op->flags &
                                         EVENT_MK_CHANGE_FLAGS_TOK_OBJS_FINAL) ?
                                         ep11tok_reencipher_filter_cb : NULL,
                                     NULL,
                                     cancel ?
                                         ep11tok_reencipher_cancel_objects_cb :
                                         ep11tok_reencipher_finalize_objects_cb,
                                     NULL, TRUE,
                                     cancel ? "cancel" : "finalize");
    if (rc != CKR_OK)
        goto out;

    if (!token_objs && !cancel) {
        /* finalize session state blobs */
        rc = ep11tok_reencipher_sessions(tokdata, NULL, TRUE);
        if (rc != CKR_OK) {
            OCK_SYSLOG(LOG_ERR,
                       "Slot %lu: Failed to finalize session states: 0x%lx\n",
                       tokdata->slot_id, rc);
            goto out;
        }

        /* Finalize the wrap blob */
        TRACE_INFO("Finalize the wrap blob\n");
        memcpy(ep11_data->raw2key_wrap_blob,
               ep11_data->raw2key_wrap_blob_reenc,
               ep11_data->raw2key_wrap_blob_l);
    }

    /*
     * Deactivate this MK change operation.
     * For the pkcshsm_mk_change tool: Deactivate only after 2nd token object
     * processing.
     */
    if ((token_objs == FALSE && op->tool_pid != tokdata->real_pid) ||
        (op->flags & EVENT_MK_CHANGE_FLAGS_TOK_OBJS_FINAL) != 0) {

        if (!cancel) {
            /* From now on the new WK is the expected one */
            memcpy(ep11_data->expected_wkvp, ep11_data->new_wkvp,
                   XCP_WKID_BYTES);
        }

        ep11_data->mk_change_active = 0;
        memset(ep11_data->mk_change_op, 0, sizeof(ep11_data->mk_change_op));
        free(ep11_data->mk_change_apqns);
        ep11_data->mk_change_apqns = NULL;
        ep11_data->num_mk_change_apqns = 0;

        /* Switch to multiple APQN mode */
        rc = refresh_target_info(tokdata, FALSE);
        if (rc != CKR_OK) {
            OCK_SYSLOG(LOG_ERR,
                       "Slot %lu: Failed to switch back to multi-APQN mode\n",
                       tokdata->slot_id);
            goto out;
        }

        TRACE_DEVEL("%s %s MK change op: %s\n", __func__,
                    cancel ? "canceled" : "finalized", op->id);
        OCK_SYSLOG(LOG_INFO, "Slot %lu: Concurrent HSM master key change "
                   "operation %s is %s, EP11 token now use multi-APQN mode\n",
                   tokdata->slot_id, op->id, cancel ? "canceled" : "finalized");
    }

out:
    if (pthread_rwlock_unlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("HSM-MK-change Unlock failed.\n");
        OCK_SYSLOG(LOG_ERR, "Slot %lu: HSM-MK-change unlock failed\n",
                   tokdata->slot_id);
        rc = CKR_CANT_LOCK;
        goto out;
    }

    return rc;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV ep11tok_mk_change_cancel_query(STDLL_TokData_t *tokdata,
                                            event_mk_change_data_t *op,
                                            struct hsm_mk_change_info *info)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    struct apqn_check_data acd;
    CK_RV rc;

    TRACE_DEVEL("%s cancel query for MK change op: %s\n", __func__, op->id);

    if (pthread_rwlock_rdlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("MK-change Read-Lock failed.\n");
        return CKR_CANT_LOCK;
    }

    memset(&acd, 0, sizeof(acd));
    acd.ep11_data = ep11_data;
    acd.slot = tokdata->slot_id;
    acd.op = op;
    acd.info = info;
    acd.cancel = TRUE; /* No new WK must be set */
    acd.error = FALSE;

    rc = handle_all_ep11_cards(&ep11_data->target_list,
                               mk_change_apqn_check_handler, &acd);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n", __func__, rc);
        goto out;
    }

    if (acd.error) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = check_token_config_expected_wkvp(tokdata, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s check_token_config_expected_wkvp failed: 0x%lx\n",
                    __func__, rc);
        goto out;
    }

out:
    if (pthread_rwlock_unlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("MK-change Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

    return rc;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
CK_RV ep11tok_handle_mk_change_event(STDLL_TokData_t *tokdata,
                                     unsigned int event_type,
                                     unsigned int event_flags,
                                     const char *payload,
                                     unsigned int payload_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    size_t bytes_read = 0;
    struct hsm_mk_change_info info = { 0 };
    event_mk_change_data_t *hdr = (event_mk_change_data_t *)payload;

    UNUSED(event_flags);

    TRACE_DEVEL("%s event: 0x%x\n", __func__, event_type);

    if (payload_len <= sizeof (*hdr))
        return CKR_DATA_LEN_RANGE;

    TRACE_DEVEL("%s id: '%s' flags: 0x%x tool_pid: %d\n", __func__, hdr->id,
                hdr->flags, hdr->tool_pid);

    rc = hsm_mk_change_info_unflatten((unsigned char *)payload + sizeof(*hdr),
                                      payload_len - sizeof(*hdr),
                                      &bytes_read, &info);
    if (rc != CKR_OK)
        return rc;
    if (bytes_read < payload_len - sizeof(*hdr)) {
        rc = CKR_DATA_LEN_RANGE;
        goto out;
    }

    rc = ep11tok_mk_change_is_affected(tokdata, &info);
    if (rc != CKR_OK)
        goto out;

    if (pthread_rwlock_rdlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("HSM-MK-change Read-Lock failed.\n");
        rc = CKR_CANT_LOCK;
        goto out;
    }

    if (ep11_data->mk_change_active &&
        strcmp(ep11_data->mk_change_op, hdr->id) != 0) {
        TRACE_ERROR("%s Must be currently active operation: '%s' vs '%s'\n",
                    __func__, ep11_data->mk_change_op, hdr->id);
        rc = CKR_FUNCTION_FAILED;
        pthread_rwlock_unlock(&tokdata->hsm_mk_change_rwlock);
        goto out;
    }

    if (pthread_rwlock_unlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("HSM-MK-change Unlock failed.\n");
        rc = CKR_CANT_LOCK;
        goto out;
    }

    switch (event_type) {
    case EVENT_TYPE_MK_CHANGE_INITIATE_QUERY:
        rc = ep11tok_mk_change_init_query(tokdata, hdr, &info);
        break;
    case EVENT_TYPE_MK_CHANGE_REENCIPHER:
        rc = ep11tok_mk_change_reencipher(tokdata, hdr, &info);
        break;
    case EVENT_TYPE_MK_CHANGE_FINALIZE_QUERY:
        rc = ep11tok_mk_change_finalize_query(tokdata, hdr, &info);
        break;
    case EVENT_TYPE_MK_CHANGE_FINALIZE:
        rc = ep11tok_mk_change_finalize_cancel(tokdata, hdr, &info, FALSE);
        break;
    case EVENT_TYPE_MK_CHANGE_CANCEL_QUERY:
        rc = ep11tok_mk_change_cancel_query(tokdata, hdr, &info);
        break;
    case EVENT_TYPE_MK_CHANGE_CANCEL:
        rc = ep11tok_mk_change_finalize_cancel(tokdata, hdr, &info, TRUE);
        break;
    default:
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        break;
    }

out:
    hsm_mk_change_info_clean(&info);

    TRACE_DEVEL("%s rc: 0x%lx\n", __func__, rc);
    return rc;
}
