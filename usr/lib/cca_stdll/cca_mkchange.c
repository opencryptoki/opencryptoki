/*
 * COPYRIGHT (c) International Business Machines Corp. 2023
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include "platform.h"
#include "p11util.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "ock_syslog.h"
#include "trace.h"
#include "events.h"
#include "cfgparser.h"
#include "cca_stdll.h"

static CK_RV cca_reencipher_sec_key(STDLL_TokData_t *tokdata,
                                    struct cca_mk_change_op *mk_change_op,
                                    CK_BYTE *sec_key, CK_BYTE *reenc_sec_key,
                                    CK_ULONG sec_key_len, CK_BBOOL from_old);

struct cca_select_single_data {
    struct cca_mk_change_op *mk_change_op;
    struct cca_mk_change_op *mk_change_op2;
    CK_BBOOL prefer_new_mk;
    enum cca_mk_type mk_type;
    enum cca_mk_type mk_type2;
    char serialno[CCA_SERIALNO_LENGTH + 1];
    unsigned short card;
    unsigned short domain;
    CK_BBOOL found;
    CK_BBOOL preferred_found;
};

static CK_BBOOL cca_select_single_apqn_check_mkvp(
                                    STDLL_TokData_t *tokdata,
                                    const struct cca_mk_change_op *mk_change_op,
                                    enum cca_mk_type mk_type,
                                    CK_BBOOL prefer_new_mk,
                                    const unsigned char *cur_sym,
                                    const unsigned char *cur_aes,
                                    const unsigned char *cur_apka)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    CK_BBOOL preferred_found = FALSE;

    switch (mk_type) {
    case CCA_MK_SYM:
        if (prefer_new_mk && mk_change_op->new_sym_mkvp_set &&
            memcmp(cur_sym, mk_change_op->new_sym_mkvp,
                   CCA_MKVP_LENGTH) == 0)
            preferred_found = TRUE;
        if (prefer_new_mk == FALSE &&
            memcmp(cur_sym, cca_private->expected_sym_mkvp,
                   CCA_MKVP_LENGTH) == 0)
            preferred_found = TRUE;
        break;
    case CCA_MK_AES:
        if (prefer_new_mk && mk_change_op->new_aes_mkvp_set &&
            memcmp(cur_aes, mk_change_op->new_aes_mkvp,
                   CCA_MKVP_LENGTH) == 0)
            preferred_found = TRUE;
        if (prefer_new_mk == FALSE &&
            memcmp(cur_aes, cca_private->expected_aes_mkvp,
                   CCA_MKVP_LENGTH) == 0)
            preferred_found = TRUE;
        break;
    case CCA_MK_APKA:
        if (prefer_new_mk && mk_change_op->new_apka_mkvp_set &&
            memcmp(cur_apka, mk_change_op->new_apka_mkvp,
                   CCA_MKVP_LENGTH) == 0)
            preferred_found = TRUE;
        if (prefer_new_mk == FALSE &&
            memcmp(cur_apka, cca_private->expected_apka_mkvp,
                   CCA_MKVP_LENGTH) == 0)
            preferred_found = TRUE;
        break;
    default:
        return FALSE;
    }

    return preferred_found;
}

static CK_RV cca_select_single_apqn_cb(STDLL_TokData_t *tokdata,
                                       const char *adapter,
                                       unsigned short card,
                                       unsigned short domain,
                                       void *private)
{
    struct cca_select_single_data *ssd = private;
    unsigned char cur_sym[CCA_MKVP_LENGTH];
    unsigned char cur_aes[CCA_MKVP_LENGTH];
    unsigned char cur_apka[CCA_MKVP_LENGTH];
    CK_RV rc;

    if (ssd->preferred_found)
        return CKR_OK;

    TRACE_DEVEL("%s Adapter %s (%02X.%04X)\n", __func__, adapter, card, domain);

    rc = cca_get_mkvps(cur_sym, NULL, cur_aes, NULL, cur_apka, NULL);
    if (rc != CKR_OK)
        return CKR_OK; /* adapter may be offline */

    ssd->preferred_found =
            cca_select_single_apqn_check_mkvp(tokdata, ssd->mk_change_op,
                                              ssd->mk_type, ssd->prefer_new_mk,
                                              cur_sym, cur_aes, cur_apka);

    if (ssd->mk_change_op2 != NULL)
        ssd->preferred_found &=
            cca_select_single_apqn_check_mkvp(tokdata, ssd->mk_change_op2,
                                              ssd->mk_type2, ssd->prefer_new_mk,
                                              cur_sym, cur_aes, cur_apka);

    rc = cca_get_adapter_serial_number(ssd->serialno);
    if (rc != CKR_OK)
        return CKR_OK; /* adapter may be offline */

    ssd->card = card;
    ssd->domain = domain;
    ssd->found = TRUE;

    return CKR_OK;
}

static enum cca_mk_type cca_mk_type_from_key_type(enum cca_token_type keytype)
{
    switch (keytype) {
    case sec_des_data_key:
        return CCA_MK_SYM;
    case sec_aes_data_key:
    case sec_aes_cipher_key:
    case sec_hmac_key:
        return CCA_MK_AES;
    case sec_rsa_priv_key:
    case sec_ecc_priv_key:
    case sec_qsa_priv_key:
        return CCA_MK_APKA;
    default:
        return -1;
    }
}

struct cca_mk_change_op *cca_mk_change_find_op_by_keytype(
                                                   STDLL_TokData_t *tokdata,
                                                   enum cca_token_type keytype)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    enum cca_mk_type mk_type = cca_mk_type_from_key_type(keytype);
    unsigned int idx;

    if (cca_mk_change_find_mkvp_in_ops(tokdata, mk_type, &idx) == NULL)
        return NULL;

    return &cca_private->mk_change_ops[idx];
}

/*
 * Must NOT hold the CCA adapter lock when called !
 * When a single APQN was selected (rc = CKR_OK), it holds the WRITE lock on
 * return. The lock must be released by the caller, once selection has been
 * turned back to default by using cca_deselect_single_apqn().
 * No lock is held in case of an error.
 */
static CK_RV cca_select_single_apqn(STDLL_TokData_t *tokdata,
                                    struct cca_mk_change_op *mk_change_op,
                                    struct cca_mk_change_op *mk_change_op2,
                                    CK_BBOOL prefer_new_mk,
                                    enum cca_token_type keytype,
                                    enum cca_token_type keytype2,
                                    char *serialno, CK_BBOOL *preferred_selected,
                                    CK_BBOOL wait_for_new_wk)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long return_code, reason_code, rule_array_count, device_name_len;
    unsigned char *device_name;
    struct cca_select_single_data ssd = { 0 };
    int retries = 0;
    CK_RV rc;

retry:
    ssd.mk_change_op = mk_change_op;
    ssd.mk_change_op2 = mk_change_op2;
    ssd.prefer_new_mk = prefer_new_mk;
    ssd.mk_type = cca_mk_type_from_key_type(keytype);
    ssd.mk_type2 = cca_mk_type_from_key_type(keytype2);

    rc = cca_iterate_adapters(tokdata, cca_select_single_apqn_cb, &ssd);
    if (rc != CKR_OK)
        return rc;

    if (ssd.found == FALSE) {
        TRACE_ERROR("No single CCA APQN found\n");
        return CKR_DEVICE_ERROR;
    }

    TRACE_DEVEL("single APQN %02X.%04X (Serialno %s) selected\n",
                ssd.card, ssd.domain, ssd.serialno);
    TRACE_DEVEL("APQN with preferred MK found: %d\n", ssd.preferred_found);

    if (preferred_selected != NULL)
        *preferred_selected = ssd.preferred_found;

    if (prefer_new_mk && wait_for_new_wk && !ssd.preferred_found) {
        TRACE_DEVEL("%s no APQN with new MK set found, retry in 1 second\n",
                    __func__);

        retries++;
        if (retries > 3600) /* Retry for max 1 hour */
            return CKR_DEVICE_ERROR;

        sleep(1);
        goto retry;
    }

    /*
     * If neither DEV-ANY, nor DOM-ANY is specified, no need to allocate the
     * adapter, it's a single adapter/domain configuration anyway.
     */
    if (!cca_private->dev_any && !cca_private->dom_any)
        goto done;

    /* Allocate the adapter */
    memcpy(rule_array, "SERIAL  ", CCA_KEYWORD_SIZE );
    rule_array_count = 1;
    device_name_len = strlen(ssd.serialno);
    device_name = (unsigned char *)ssd.serialno;

    if (cca_private->dom_any) {
        sprintf((char *)(rule_array + CCA_KEYWORD_SIZE), "DOMN%04u", ssd.domain);
        rule_array_count = 2;

        if (pthread_rwlock_wrlock(&cca_adapter_rwlock) != 0) {
            TRACE_DEVEL("CCA adapter WR-Lock failed.\n");
            return CKR_CANT_LOCK;
        }
    }

    dll_CSUACRA(&return_code, &reason_code,
                NULL, NULL,
                &rule_array_count, rule_array,
                &device_name_len, device_name);

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUACRA failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);

        if (pthread_rwlock_unlock(&cca_adapter_rwlock) != 0) {
            TRACE_DEVEL("CCA adapter Unlock failed.\n");
            return CKR_CANT_LOCK;
        }

        return CKR_FUNCTION_FAILED;
    }

done:
    strncpy(serialno, ssd.serialno, CCA_SERIALNO_LENGTH + 1);
    serialno[CCA_SERIALNO_LENGTH] = '\0';

    return CKR_OK;
}

/* Does NOT unlock the CCA adapter lock ! */
CK_RV cca_deselect_single_apqn(STDLL_TokData_t *tokdata, char *serialno)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long return_code, reason_code, rule_array_count, device_name_len;
    unsigned char *device_name;

    /*
     * If neither DEV-ANY, nor DOM-ANY is specified, no need to deallocate the
     * adapter, it's a single adapter/domain configuration anyway.
     */
    if (!cca_private->dev_any && !cca_private->dom_any)
        return CKR_OK;

    /* Deallocate the adapter */
    memcpy(rule_array, "SERIAL  ", CCA_KEYWORD_SIZE);
    rule_array_count = 1;
    device_name_len = strlen(serialno);
    device_name = (unsigned char *)serialno;

    if (cca_private->dom_any) {
        memcpy(rule_array + CCA_KEYWORD_SIZE, "DOMN-DEF", CCA_KEYWORD_SIZE);
        rule_array_count = 2;
    }

    dll_CSUACRD(&return_code, &reason_code,
                NULL, NULL,
                &rule_array_count, rule_array,
                &device_name_len, device_name);

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("CSUACRD failed. return:%ld, reason:%ld\n",
                    return_code, reason_code);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

/* Must NOT hold the CCA adapter lock when called ! */
CK_RV cca_reencipher_created_key(STDLL_TokData_t *tokdata,
                                 TEMPLATE* tmpl,  CK_BYTE *sec_key,
                                 CK_ULONG sec_key_len, CK_BBOOL new_mk,
                                 enum cca_token_type keytype,
                                 CK_BBOOL aes_xts_2dn_key)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    struct cca_mk_change_op *mk_change_op;
    char serialno[CCA_SERIALNO_LENGTH + 1];
    CK_BBOOL new_selected = FALSE;
    CK_BYTE reenc_sec_key[CCA_KEY_TOKEN_SIZE] = { 0 };
    CK_RV rc, rc2;
    CK_ULONG retries = 0;
    CK_ATTRIBUTE *reenc_attr = NULL;
    CK_BYTE reenc_buf[CCA_KEY_TOKEN_SIZE * 2] = { 0 };

    if (sec_key_len > sizeof(reenc_sec_key)) {
        TRACE_ERROR("%s sec_key_len too large: %lu\n", __func__, sec_key_len);
        return CKR_ARGUMENTS_BAD;
    }

    mk_change_op = cca_mk_change_find_op_by_keytype(tokdata, keytype);
    if (mk_change_op == NULL)
        return CKR_OK;

    if (new_mk) {
        memcpy(reenc_sec_key, sec_key, sec_key_len);
        goto add_attr;
    }

    /* Try to re-encipher to new MK */
    rc = cca_reencipher_sec_key(tokdata, mk_change_op, sec_key, reenc_sec_key,
                                sec_key_len, FALSE);
    if (rc == CKR_OK)
        goto add_attr;

    TRACE_ERROR("%s cca_reencipher_sec_key failed: 0x%lx\n", __func__, rc);
    if (rc != CKR_DEVICE_ERROR)
        return rc;

retry:
    /* Try to select a APQN with new MK set/activated */
    rc = cca_select_single_apqn(tokdata, mk_change_op, NULL, TRUE, keytype, 0,
                                serialno, &new_selected, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s cca_select_single_apqn failed: 0x%lx\n", __func__, rc);
        return rc;
    }

    TRACE_DEVEL("%s new_selected: %d\n", __func__, new_selected);

    /*
     * Retry re-enciphering, from-OLD if APQN with new MK was selected,
     * otherwise try to-NEW again.
     */
    rc = cca_reencipher_sec_key(tokdata, mk_change_op, sec_key, reenc_sec_key,
                                sec_key_len, new_selected);
    if (rc != CKR_OK)
        TRACE_ERROR("%s cca_reencipher_sec_key (2) failed: 0x%lx\n", __func__,
                    rc);

    rc2 = cca_deselect_single_apqn(tokdata, serialno);

    /* cca_select_single_apqn() got the WRITE lock, unlock it now */
    if (cca_private->dom_any) {
        if (pthread_rwlock_unlock(&cca_adapter_rwlock) != 0) {
            TRACE_ERROR("CCA adapter Unlock failed.\n");
            return CKR_CANT_LOCK;
        }
    }

    if (rc2 != CKR_OK) {
        TRACE_ERROR("%s cca_deselect_single_apqn failed: 0x%lx\n", __func__,
                    rc2);
        return rc2;
    }

    if (rc == CKR_OK)
        goto add_attr;

    /*
     * If re-enciphering to-New has failed because the selected single APQN
     * with old MK set has just got the new MK set, re-select a single APQN
     * (preferably with new MK set) and retry. We should then get an APQN with
     * the new MK set and then perform a re-encipher from-OLD.
     */
    if (new_selected == FALSE && rc == CKR_DEVICE_ERROR && retries < 2) {
        retries++;
        goto retry;
    }

    return rc;

add_attr:
    if (aes_xts_2dn_key) {
        rc = template_attribute_get_non_empty(tmpl, CKA_IBM_OPAQUE_REENC,
                                              &reenc_attr);
        if (rc == CKR_OK && reenc_attr->ulValueLen == sec_key_len) {
            memcpy(reenc_buf, reenc_attr->pValue, sec_key_len);
            memcpy(reenc_buf + reenc_attr->ulValueLen, reenc_sec_key,
                   sec_key_len);

            rc = build_update_attribute(tmpl, CKA_IBM_OPAQUE_REENC,
                                        reenc_buf, sec_key_len * 2);
            if (rc != CKR_OK) {
                TRACE_DEVEL("build_update_attribute(CKA_IBM_OPAQUE_REENC) failed\n");
                return rc;
            }

            return CKR_OK;
        }
    }

    rc = build_update_attribute(tmpl, CKA_IBM_OPAQUE_REENC,
                                reenc_sec_key, sec_key_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_update_attribute(CKA_IBM_OPAQUE_REENC) failed\n");
        return rc;
    }

    return CKR_OK;
}

/* Called with CCA adapter READ lock held (if DOM-ANY) */
CK_BBOOL cca_check_blob_select_single_apqn(STDLL_TokData_t *tokdata,
                                           const CK_BYTE *sec_key1,
                                           CK_ULONG sec_key1_len,
                                           const CK_BYTE *sec_key2,
                                           CK_ULONG sec_key2_len,
                                           char *serialno)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    enum cca_token_type keytype1, keytype2 = -1;
    unsigned int keybitsize1, keybitsize2;
    const CK_BYTE *mkvp1, *mkvp2;
    CK_BBOOL new_mk1 = FALSE, new_mk2 = FALSE, new_selected = FALSE;
    struct cca_mk_change_op *mk_change_op1 = NULL, *mk_change_op2 = NULL;

    if (analyse_cca_key_token(sec_key1, sec_key1_len, &keytype1, &keybitsize1,
                              &mkvp1) == FALSE)
        return FALSE;

    if (check_expected_mkvp(tokdata, keytype1, mkvp1, &new_mk1) != CKR_OK)
        return FALSE;

    TRACE_DEVEL("%s new_mk1: %d\n", __func__, new_mk1);

    mk_change_op1 = cca_mk_change_find_op_by_keytype(tokdata, keytype1);

    if (sec_key2 != NULL) {
        if (analyse_cca_key_token(sec_key2, sec_key2_len, &keytype2, &keybitsize2,
                                  &mkvp2) == FALSE)
            return FALSE;

        if (check_expected_mkvp(tokdata, keytype1, mkvp1, &new_mk1) != CKR_OK)
            return FALSE;

        TRACE_DEVEL("%s new_mk1: %d\n", __func__, new_mk1);

        mk_change_op2 = cca_mk_change_find_op_by_keytype(tokdata, keytype2);
    }

    if (new_mk1 == FALSE && new_mk2 == FALSE)
        return FALSE;

    if (mk_change_op1 == NULL && mk_change_op2 == NULL)
        return FALSE;

    /*
     * Unlock CCA adapter lock (if DOM-ANY), cca_select_single_apqn() will
     * get WRITE lock.
     */
    if (cca_private->dom_any) {
        if (pthread_rwlock_unlock(&cca_adapter_rwlock) != 0) {
            TRACE_ERROR("CCA adapter Unlock failed.\n");
            return FALSE;
        }
    }

    /* Select a single APQN with new MK(s) set, wait if required */
    TRACE_DEVEL("%s select single APQN with new MK set, wait if needed\n",
                __func__);
    if (cca_select_single_apqn(tokdata, mk_change_op1, mk_change_op2, TRUE,
                               keytype1, keytype2, serialno,
                               &new_selected, TRUE) != CKR_OK)
        new_selected = FALSE;

    /* Need to get RD-lock again in case no new APQN was selected */
    if (!new_selected && cca_private->dom_any) {
        if (pthread_rwlock_rdlock(&cca_adapter_rwlock) != 0) {
            TRACE_ERROR("CCA adapter RD-Lock failed.\n");
            return FALSE;
        }
    }

    return new_selected;
}

struct cca_affected_data {
    struct hsm_mk_change_info *info;
    CK_BBOOL affected;
};

static CK_RV cca_mk_change_is_affected_cb(STDLL_TokData_t *tokdata,
                                          const char *adapter,
                                          unsigned short card,
                                          unsigned short domain,
                                          void *private)
{
    struct cca_affected_data *ad = private;

    UNUSED(tokdata);

    if (hsm_mk_change_apqns_find(ad->info->apqns, ad->info->num_apqns,
                                 card, domain)) {
        TRACE_DEVEL("%s APQN %02X.%04X (%s) is affected by MK change\n",
                    __func__, card, domain, adapter);
        ad->affected = TRUE;
    }

    return CKR_OK;
}

static CK_RV cca_mk_change_is_affected(STDLL_TokData_t *tokdata,
                                       struct hsm_mk_change_info *info)
{
    unsigned int i;
    CK_BBOOL affected = FALSE;
    struct cca_affected_data ad;
    CK_RV rc;

    for (i = 0; i < info->num_mkvps; i++) {
        TRACE_DEVEL("%s MK type: %d\n", __func__, info->mkvps[i].type);
        switch (info->mkvps[i].type) {
        case HSM_MK_TYPE_CCA_SYM:
        case HSM_MK_TYPE_CCA_AES:
        case HSM_MK_TYPE_CCA_APKA:
            affected = TRUE;
            break;
        default:
            break;
        }
    }
    if (!affected)
        goto out;

    ad.info = info;
    ad.affected = FALSE;
    rc = cca_iterate_adapters(tokdata, cca_mk_change_is_affected_cb, &ad);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s cca_iterate_adapters failed: 0x%lx\n", __func__, rc);
        return rc;
    }

    affected = ad.affected;

out:
    TRACE_DEVEL("%s affected: %d\n", __func__, affected);

    return affected ? CKR_OK : CKR_FUNCTION_NOT_SUPPORTED;
}

unsigned char *cca_mk_change_find_mkvp_in_ops(STDLL_TokData_t *tokdata,
                                              enum cca_mk_type mk_type,
                                              unsigned int *idx)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned int i;

    for (i = 0; i < CCA_NUM_MK_TYPES; i++) {
        if (cca_private->mk_change_ops[i].mk_change_active) {
            switch (mk_type) {
            case CCA_MK_SYM:
                if (cca_private->mk_change_ops[i].new_sym_mkvp_set) {
                    if (idx != NULL)
                        *idx = i;
                    return cca_private->mk_change_ops[i].new_sym_mkvp;
                }
                break;
            case CCA_MK_AES:
                if (cca_private->mk_change_ops[i].new_aes_mkvp_set) {
                    if (idx != NULL)
                        *idx = i;
                    return cca_private->mk_change_ops[i].new_aes_mkvp;
                }
                break;
            case CCA_MK_APKA:
                if (cca_private->mk_change_ops[i].new_apka_mkvp_set) {
                    if (idx != NULL)
                        *idx = i;
                    return cca_private->mk_change_ops[i].new_apka_mkvp;
                }
                break;
            default:
                break;
            }
        }
    }

    return NULL;
}

static struct cca_mk_change_op *cca_mk_change_find_op(STDLL_TokData_t *tokdata,
                                                      const char *op,
                                                      unsigned int *idx)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned int i;

    for (i = 0; i < CCA_NUM_MK_TYPES; i++) {
        if (cca_private->mk_change_ops[i].mk_change_active &&
            strcmp(cca_private->mk_change_ops[i].mk_change_op, op) == 0) {
            if (idx != NULL)
                *idx = i;
            return &cca_private->mk_change_ops[i];
        }
    }

    return NULL;
}

static CK_RV cca_mk_change_activate_op(STDLL_TokData_t *tokdata, const char *id,
                                       struct hsm_mk_change_info *info,
                                       const unsigned char *new_sym_mk,
                                       const unsigned char *new_aes_mk,
                                       const unsigned char *new_apka_mk,
                                       unsigned int *idx)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    unsigned int i;
    int op_idx;

    /* Find a free operation slot */
    for (i = 0, op_idx = -1; i < CCA_NUM_MK_TYPES; i++) {
        if (cca_private->mk_change_ops[i].mk_change_active == FALSE) {
            op_idx = i;
            break;
        }
    }
    if (op_idx == -1) {
        TRACE_ERROR("%s More than %d MK change ops are already active\n",
                    __func__, CCA_NUM_MK_TYPES);
        return CKR_FUNCTION_FAILED;
    }

    /* remember the infos of this MK change op */
    memset(&cca_private->mk_change_ops[op_idx], 0,
           sizeof(cca_private->mk_change_ops[op_idx]));
    strncpy(cca_private->mk_change_ops[op_idx].mk_change_op, id,
            sizeof(cca_private->mk_change_ops[op_idx].mk_change_op) - 1);
    cca_private->mk_change_ops[op_idx].mk_change_op
       [sizeof(cca_private->mk_change_ops[op_idx].mk_change_op) - 1] = '\0';

    if (new_sym_mk != NULL) {
        memcpy(cca_private->mk_change_ops[op_idx].new_sym_mkvp, new_sym_mk,
               CCA_MKVP_LENGTH);
        cca_private->mk_change_ops[op_idx].new_sym_mkvp_set = TRUE;
        TRACE_DEBUG_DUMP("New SYM MK: ", (void *)new_sym_mk,
                         CCA_MKVP_LENGTH);
    }
    if (new_aes_mk != NULL) {
        memcpy(cca_private->mk_change_ops[op_idx].new_aes_mkvp, new_aes_mk,
               CCA_MKVP_LENGTH);
        cca_private->mk_change_ops[op_idx].new_aes_mkvp_set = TRUE;
        TRACE_DEBUG_DUMP("New AES MK: ", (void *)new_aes_mk,
                         CCA_MKVP_LENGTH);
    }
    if (new_apka_mk != NULL) {
        memcpy(cca_private->mk_change_ops[op_idx].new_apka_mkvp, new_apka_mk,
               CCA_MKVP_LENGTH);
        cca_private->mk_change_ops[op_idx].new_apka_mkvp_set = TRUE;
        TRACE_DEBUG_DUMP("New APKA MK: ", (void *)new_apka_mk,
                         CCA_MKVP_LENGTH);
    }

    cca_private->mk_change_ops[op_idx].apqns = calloc(info->num_apqns,
                                                      sizeof(struct apqn));
    if (cca_private->mk_change_ops[op_idx].apqns == NULL) {
        TRACE_ERROR("%s Failed to allocate list of MK change APQNs\n",
                    __func__);
        return CKR_HOST_MEMORY;
    }

    cca_private->mk_change_ops[op_idx].num_apqns = info->num_apqns;
    memcpy(cca_private->mk_change_ops[op_idx].apqns, info->apqns,
           info->num_apqns * sizeof(struct apqn));

    cca_private->mk_change_ops[op_idx].mk_change_active = TRUE;

    TRACE_DEVEL("%s active MK change op (idx %u): %s\n", __func__, op_idx,
                cca_private->mk_change_ops[op_idx].mk_change_op);
    OCK_SYSLOG(LOG_INFO, "Slot %lu: A concurrent HSM master key change "
               "operation (%s) is active for CCA %s%s%s%s%s\n",
               tokdata->slot_id,
               cca_private->mk_change_ops[op_idx].mk_change_op,
               new_sym_mk != NULL ? "SYM" : "",
               (new_sym_mk != NULL && new_aes_mk != NULL) ? ", " : "",
               new_aes_mk != NULL ? "AES" : "",
               ((new_aes_mk != NULL && new_apka_mk != NULL) ||
                (new_aes_mk == NULL && new_sym_mk != NULL &&
                 new_apka_mk != NULL)) ? ", " : "",
               new_apka_mk != NULL ? "APKA" : "");

    *idx = op_idx;

    return CKR_OK;
}

static CK_RV cca_mk_change_check_pending_ops_cb(struct hsm_mk_change_op *op,
                                                void *private)
{
    STDLL_TokData_t *tokdata = private;
    struct cca_private_data *cca_private;
    struct hsm_mkvp *mkvps = NULL;
    unsigned int num_mkvps = 0;
    unsigned int i;
    const unsigned char *new_sym_mk = NULL;
    const unsigned char *new_aes_mk = NULL;
    const unsigned char *new_apka_mk = NULL;
    const unsigned char *mkvp;
    CK_RV rc;

    cca_private = tokdata->private_data;

    rc = cca_mk_change_is_affected(tokdata, &op->info);
    if (rc != CKR_OK)
        return CKR_OK;

    new_sym_mk = hsm_mk_change_mkvps_find(op->info.mkvps, op->info.num_mkvps,
                                          HSM_MK_TYPE_CCA_SYM,
                                          CCA_MKVP_LENGTH);
    new_aes_mk = hsm_mk_change_mkvps_find(op->info.mkvps, op->info.num_mkvps,
                                          HSM_MK_TYPE_CCA_AES,
                                          CCA_MKVP_LENGTH);
    new_apka_mk = hsm_mk_change_mkvps_find(op->info.mkvps, op->info.num_mkvps,
                                           HSM_MK_TYPE_CCA_APKA,
                                           CCA_MKVP_LENGTH);
    if (new_sym_mk == NULL && new_aes_mk == NULL && new_apka_mk == NULL) {
        TRACE_ERROR("%s No CCA MK type found in MK change operation: %s\n",
                    __func__, op->id);
        return CKR_FUNCTION_FAILED;
    }

    switch (op->state) {
    case HSM_MK_CH_STATE_REENCIPHERING:
    case HSM_MK_CH_STATE_REENCIPHERED:
        /*
         * There can be up to 3 active MK change ops for the CCA token,
         * one for each MK type, if the MKs are changed individually.
         * However, these ops can not have intersecting MK types.
         * No need to have the hsm_mk_change_rwlock, we're in token init
         * function, and the API layer starts the event thread only after all
         * token init's have been performed.
         */
        if (new_sym_mk != NULL &&
            cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_SYM, &i) != NULL) {
            TRACE_ERROR("%s Another MK change for CCA SYM is already "
                        "active: %s\n", __func__,
                        cca_private->mk_change_ops[i].mk_change_op);
            return CKR_FUNCTION_FAILED;
        }
        if (new_aes_mk != NULL &&
            cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_AES, &i) != NULL) {
            TRACE_ERROR("%s Another MK change for CCA AES is already "
                        "active: %s\n", __func__,
                        cca_private->mk_change_ops[i].mk_change_op);
            return CKR_FUNCTION_FAILED;
        }
        if (new_apka_mk != NULL &&
            cca_mk_change_find_mkvp_in_ops(tokdata, CCA_MK_APKA, &i) != NULL) {
            TRACE_ERROR("%s Another MK change for CCA APKA is already "
                        "active: %s\n", __func__,
                        cca_private->mk_change_ops[i].mk_change_op);
            return CKR_FUNCTION_FAILED;
        }

        rc = cca_mk_change_activate_op(tokdata, op->id, &op->info,
                                       new_sym_mk, new_aes_mk, new_apka_mk,
                                       &i);
        if (rc != CKR_OK)
            return rc;

        /* Load expected current MKVPs */
        rc = hsm_mk_change_token_mkvps_load(op->id, tokdata->slot_id,
                                            &mkvps, &num_mkvps);
        /* Ignore if this failed, no expected current MKVP is set then */
        if (rc == CKR_OK) {
            mkvp = hsm_mk_change_mkvps_find(mkvps, num_mkvps,
                                            HSM_MK_TYPE_CCA_SYM,
                                            CCA_MKVP_LENGTH);
            if (mkvp != NULL) {
                memcpy(cca_private->expected_sym_mkvp, mkvp, CCA_MKVP_LENGTH);
                cca_private->expected_sym_mkvp_set = TRUE;
                TRACE_DEBUG_DUMP("Current SYM MKVP: ",
                                 cca_private->expected_sym_mkvp,
                                 CCA_MKVP_LENGTH);
            }

            mkvp = hsm_mk_change_mkvps_find(mkvps, num_mkvps,
                                            HSM_MK_TYPE_CCA_AES,
                                            CCA_MKVP_LENGTH);
            if (mkvp != NULL) {
                memcpy(cca_private->expected_aes_mkvp, mkvp, CCA_MKVP_LENGTH);
                cca_private->expected_aes_mkvp_set = TRUE;
                TRACE_DEBUG_DUMP("Current AES MKVP: ",
                                 cca_private->expected_aes_mkvp,
                                 CCA_MKVP_LENGTH);
            }

            mkvp = hsm_mk_change_mkvps_find(mkvps, num_mkvps,
                                            HSM_MK_TYPE_CCA_APKA,
                                            CCA_MKVP_LENGTH);
            if (mkvp != NULL) {
                memcpy(cca_private->expected_apka_mkvp, mkvp, CCA_MKVP_LENGTH);
                cca_private->expected_apka_mkvp_set = TRUE;
                TRACE_DEBUG_DUMP("Current APKA MKVP: ",
                                 cca_private->expected_apka_mkvp,
                                 CCA_MKVP_LENGTH);
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

CK_RV cca_mk_change_check_pending_ops(STDLL_TokData_t *tokdata)
{
    CK_RV rc;

    rc = hsm_mk_change_lock_create();
    if (rc != CKR_OK)
        return rc;

    rc = hsm_mk_change_lock(FALSE);
    if (rc != CKR_OK)
        goto out;

    rc = hsm_mk_change_op_iterate(cca_mk_change_check_pending_ops_cb,
                                  tokdata);

    hsm_mk_change_unlock();

out:
    hsm_mk_change_lock_destroy();

    return rc;
}

static const char *mk_type_to_string(enum cca_mk_type mk_type)
{
    switch (mk_type) {
    case CCA_MK_SYM:
        return "SYM";
    case CCA_MK_AES:
        return "AES";
    case CCA_MK_APKA:
        return "APKA";
    default:
        return "UNKNOWN";
    }
}

static CK_RV cca_mk_change_apqn_check_mk_state(enum cca_mk_type mk_type,
                                               const char *adapter,
                                               unsigned short card,
                                               unsigned short domain,
                                               CK_SLOT_ID slot,
                                               CK_BBOOL finalize,
                                               CK_BBOOL cancel,
                                               CK_BBOOL *error)
{
    const char *mk_type_str = mk_type_to_string(mk_type);
    enum cca_cmk_state cur_mk_state;
    enum cca_nmk_state new_mk_state;
    CK_RV rc;

    rc = cca_get_mk_state(mk_type, &cur_mk_state, &new_mk_state);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_get_mk_state (%s) failed for %s (%02X.%04X)\n",
                mk_type_str, adapter, card, domain);
        return rc;
    }

    /* Ensure that a current master key is set in the card */
    if (cur_mk_state != CCA_CMK_STATUS_FULL) {
        TRACE_ERROR("%s No CURRENT CCA %s master key is set on APQN %02X.%04X (%s)\n",
                    __func__, mk_type_str, card, domain, adapter);
        warnx("Slot %lu: No CURRENT CCA %s master key is set on APQN %02X.%04X (%s)",
              slot, mk_type_str, card, domain, adapter);
        *error = TRUE;
    }

    if (finalize) {
        /* Ensure that the new master key register is empty */
         if (new_mk_state != CCA_NMK_STATUS_CLEAR) {
             TRACE_ERROR("%s The NEW CCA %s master key register must be empty on APQN %02X.%04X (%s)\n",
                         __func__, mk_type_str, card, domain, adapter);
              warnx("Slot %lu: The NEW CCA %s master key register must be empty on APQN %02X.%04X (%s)",
                    slot, mk_type_str, card, domain, adapter);
             *error = TRUE;
         }
    } else if (!cancel) {
        /* Ensure that the new master key is set in the card */
        if (new_mk_state != CCA_NMK_STATUS_FULL) {
            TRACE_ERROR("%s No NEW CCA %s master key is set on APQN %02X.%04X (%s)\n",
                        __func__, mk_type_str, card, domain, adapter);
             warnx("Slot %lu: No NEW CCA %s master key is set on APQN %02X.%04X (%s)",
                   slot, mk_type_str, card, domain, adapter);
            *error = TRUE;
        }
    }

    return CKR_OK;
}

static void cca_mk_change_apqn_check_mkvp(enum cca_mk_type mk_type,
                                          const unsigned char *queried_mkvp,
                                          const unsigned char *expected_mkvp,
                                          const char *adapter,
                                          unsigned short card,
                                          unsigned short domain,
                                          CK_SLOT_ID slot,
                                          CK_BBOOL new_mk,
                                          const char *msg,
                                          CK_BBOOL *error)
{
    const char *mk_type_str = mk_type_to_string(mk_type);

    if (memcmp(queried_mkvp, expected_mkvp, CCA_MKVP_LENGTH) != 0) {
        TRACE_ERROR("%s CCA %s master key on APQN %02X.%04X (%s) does not "
                    "match the %s master key\n",
                    new_mk ? "NEW" : "CURRENT", mk_type_str, card, domain,
                    adapter, msg);
        warnx("Slot %lu: The %s CCA %s MK on APQN %02X.%04X (%s) does not "
              "match the %s MKVP", slot, new_mk ? "NEW" : "CURRENT",
              mk_type_str, card, domain, adapter, msg);
        *error = TRUE;
    }
}

struct apqn_check_data {
    CK_SLOT_ID slot;
    event_mk_change_data_t *op;
    struct hsm_mk_change_info *info;
    const unsigned char *sym_new_mk;
    const unsigned char *aes_new_mk;
    const unsigned char *apka_new_mk;
    CK_BBOOL finalize;
    CK_BBOOL cancel;
    CK_BBOOL error;
};

static CK_RV cca_mk_change_apqn_check_cb(STDLL_TokData_t *tokdata,
                                         const char *adapter,
                                         unsigned short card,
                                         unsigned short domain,
                                         void *private)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    struct apqn_check_data *ac = (struct apqn_check_data *)private;
    unsigned char sym_cur_mkvp[CCA_MKVP_LENGTH];
    unsigned char sym_new_mkvp[CCA_MKVP_LENGTH];
    unsigned char aes_cur_mkvp[CCA_MKVP_LENGTH];
    unsigned char aes_new_mkvp[CCA_MKVP_LENGTH];
    unsigned char apka_cur_mkvp[CCA_MKVP_LENGTH];
    unsigned char apka_new_mkvp[CCA_MKVP_LENGTH];
    CK_RV rc;

    /* Check that this APQN is part of the MK change operation */
    if (hsm_mk_change_apqns_find(ac->info->apqns, ac->info->num_apqns,
                                 card, domain) == FALSE) {
        TRACE_ERROR("%s APQN %02X.%04X (%s) is not part of MK change '%s'\n",
                    __func__, card, domain, adapter, ac->op->id);
        warnx("Slot %lu: APQN %02X.%04X must be included into this operation.",
              ac->slot, card, domain);

        ac->error = TRUE;
        return CKR_OK;
    }

    if (ac->sym_new_mk != NULL) {
        /* Check status of AES master key (DES, 3DES keys) */
        rc = cca_mk_change_apqn_check_mk_state(CCA_MK_SYM, adapter, card,
                                               domain, ac->slot,
                                               ac->finalize, ac->cancel,
                                               &ac->error);
        if (rc != CKR_OK)
            return rc;
    }

    if (ac->aes_new_mk != NULL) {
        /* Check status of AES master key (AES, HMAC keys) */
        rc = cca_mk_change_apqn_check_mk_state(CCA_MK_AES, adapter, card,
                                               domain, ac->slot,
                                               ac->finalize, ac->cancel,
                                               &ac->error);
        if (rc != CKR_OK)
            return rc;
    }

    if (ac->apka_new_mk != NULL) {
        /* Check status of APKA master key (RSA and ECC keys) */
        rc = cca_mk_change_apqn_check_mk_state(CCA_MK_APKA, adapter, card,
                                               domain, ac->slot,
                                               ac->finalize, ac->cancel,
                                               &ac->error);
        if (rc != CKR_OK)
            return rc;
    }

    /* Get master key verification patterns */
    rc = cca_get_mkvps(sym_cur_mkvp, sym_new_mkvp, aes_cur_mkvp, aes_new_mkvp,
                       apka_cur_mkvp, apka_new_mkvp);
    if (rc != CKR_OK) {
        TRACE_ERROR("cca_get_mkvps failed for %s (%02X.%04X)\n",
                    adapter, card, domain);
        return rc;
    }

    TRACE_DEBUG("Master key verification patterns for %s (%02X.%04X)\n",
                adapter, card, domain);
    TRACE_DEBUG_DUMP("SYM CUR MKVP:  ", sym_cur_mkvp, CCA_MKVP_LENGTH);
    TRACE_DEBUG_DUMP("SYM NEW MKVP:  ", sym_new_mkvp, CCA_MKVP_LENGTH);
    TRACE_DEBUG_DUMP("AES CUR MKVP:  ", aes_cur_mkvp, CCA_MKVP_LENGTH);
    TRACE_DEBUG_DUMP("AES NEW MKVP:  ", aes_new_mkvp, CCA_MKVP_LENGTH);
    TRACE_DEBUG_DUMP("APKA CUR MKVP: ", apka_cur_mkvp, CCA_MKVP_LENGTH);
    TRACE_DEBUG_DUMP("APKA NEW MKVP: ", apka_new_mkvp, CCA_MKVP_LENGTH);

    /* Current MKs (only those included in the op) must be the expected MKs */
    if (ac->sym_new_mk != NULL)
        cca_mk_change_apqn_check_mkvp(CCA_MK_SYM, sym_cur_mkvp,
                                      ac->finalize ?
                                              ac->sym_new_mk :
                                              cca_private->expected_sym_mkvp,
                                      adapter, card, domain, ac->slot,
                                      FALSE, ac->finalize ? "operation's NEW" :
                                                      "expected",
                                      &ac->error);
    if (ac->aes_new_mk != NULL)
            cca_mk_change_apqn_check_mkvp(CCA_MK_AES, aes_cur_mkvp,
                                      ac->finalize ?
                                              ac->aes_new_mk :
                                              cca_private->expected_aes_mkvp,
                                      adapter, card, domain, ac->slot,
                                      FALSE, ac->finalize ? "operation's NEW" :
                                                      "expected",
                                      &ac->error);
    if (ac->apka_new_mk != NULL)
        cca_mk_change_apqn_check_mkvp(CCA_MK_APKA, apka_cur_mkvp,
                                      ac->finalize ?
                                              ac->apka_new_mk :
                                              cca_private->expected_apka_mkvp,
                                      adapter, card, domain, ac->slot,
                                      FALSE, ac->finalize ? "operation's NEW" :
                                                      "expected",
                                      &ac->error);

    if (ac->finalize || ac->cancel)
        return CKR_OK; /* Don't check New MKs for finalize or cancel */

    /* New MKs must be the expected new MKs of the operation */
    if (ac->sym_new_mk != NULL)
        cca_mk_change_apqn_check_mkvp(CCA_MK_SYM, sym_new_mkvp, ac->sym_new_mk,
                                      adapter, card, domain, ac->slot, TRUE,
                                      "specified", &ac->error);
    if (ac->aes_new_mk != NULL)
        cca_mk_change_apqn_check_mkvp(CCA_MK_AES, aes_new_mkvp, ac->aes_new_mk,
                                      adapter, card, domain, ac->slot, TRUE,
                                      "specified", &ac->error);
    if (ac->apka_new_mk != NULL)
        cca_mk_change_apqn_check_mkvp(CCA_MK_APKA, apka_new_mkvp, ac->apka_new_mk,
                                      adapter, card, domain, ac->slot, TRUE,
                                      "specified", &ac->error);

    return CKR_OK;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread safe and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV cca_mk_change_init_query(STDLL_TokData_t *tokdata,
                                      event_mk_change_data_t *op,
                                      struct hsm_mk_change_info *info)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    struct apqn_check_data acd;
    struct hsm_mkvp mkvps[3];
    unsigned int num_mkvps = 0;
    CK_RV rc;

    TRACE_DEVEL("%s initial query for MK change op: %s\n", __func__, op->id);

    memset(&acd, 0, sizeof(acd));
    acd.slot = tokdata->slot_id;
    acd.op = op;
    acd.info = info;

    acd.sym_new_mk = hsm_mk_change_mkvps_find(info->mkvps, info->num_mkvps,
                                              HSM_MK_TYPE_CCA_SYM,
                                              CCA_MKVP_LENGTH);
    acd.aes_new_mk = hsm_mk_change_mkvps_find(info->mkvps, info->num_mkvps,
                                              HSM_MK_TYPE_CCA_AES,
                                              CCA_MKVP_LENGTH);
    acd.apka_new_mk = hsm_mk_change_mkvps_find(info->mkvps, info->num_mkvps,
                                               HSM_MK_TYPE_CCA_APKA,
                                               CCA_MKVP_LENGTH);

    /* Check if selected APQNs have the expected MKs set/loaded */
    rc = cca_iterate_adapters(tokdata, cca_mk_change_apqn_check_cb, &acd);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s cca_iterate_adapters failed: 0x%lx\n", __func__, rc);
        return rc;
    }

    if (acd.error)
        return CKR_FUNCTION_FAILED;

    /* Save current MKVPs of affected MK types of this token */
    if (acd.sym_new_mk != NULL) {
        mkvps[num_mkvps].type = HSM_MK_TYPE_CCA_SYM;
        mkvps[num_mkvps].mkvp_len = CCA_MKVP_LENGTH;
        mkvps[num_mkvps].mkvp = cca_private->expected_sym_mkvp;
        num_mkvps++;
    }
    if (acd.aes_new_mk != NULL) {
        mkvps[num_mkvps].type = HSM_MK_TYPE_CCA_AES;
        mkvps[num_mkvps].mkvp_len = CCA_MKVP_LENGTH;
        mkvps[num_mkvps].mkvp = cca_private->expected_aes_mkvp;
        num_mkvps++;
    }
    if (acd.apka_new_mk != NULL) {
        mkvps[num_mkvps].type = HSM_MK_TYPE_CCA_APKA;
        mkvps[num_mkvps].mkvp_len = CCA_MKVP_LENGTH;
        mkvps[num_mkvps].mkvp = cca_private->expected_apka_mkvp;
        num_mkvps++;
    }

    rc = hsm_mk_change_lock_create();
    if (rc != CKR_OK)
        return rc;

    rc = hsm_mk_change_lock(TRUE);
    if (rc != CKR_OK)
        goto out;

    rc = hsm_mk_change_token_mkvps_save(op->id, tokdata->slot_id,
                                        mkvps, num_mkvps);

    hsm_mk_change_unlock();

out:
    hsm_mk_change_lock_destroy();

    return rc;
}

static CK_RV cca_check_token_config_expected_mkvp(STDLL_TokData_t *tokdata,
                                        struct cca_mk_change_op *mk_change_op,
                                        CK_BBOOL new_mk)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    FILE *file;
    struct ConfigBaseNode *c, *config = NULL;
    struct ConfigStructNode *struct_node;
    unsigned char exp_sym_mkvp[CCA_MKVP_LENGTH];
    unsigned char exp_aes_mkvp[CCA_MKVP_LENGTH];
    unsigned char exp_apka_mkvp[CCA_MKVP_LENGTH];
    CK_BBOOL exp_sym_mkvp_set = FALSE;
    CK_BBOOL exp_aes_mkvp_set = FALSE;
    CK_BBOOL exp_apka_mkvp_set = FALSE;
    CK_RV rc = CKR_OK;
    int ret, i;

    if (cca_private->token_config_filename[0] == '\0')
        return CKR_OK;

    file = fopen(cca_private->token_config_filename, "r");
    if (file == NULL) {
        TRACE_ERROR("%s fopen('%s') failed with errno: %s\n", __func__,
                    cca_private->token_config_filename, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    ret = parse_configlib_file(file, &config, cca_config_parse_error, 0);
    if (ret != 0) {
        TRACE_ERROR("Error parsing config file '%s'\n",
                    cca_private->token_config_filename);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    confignode_foreach(c, config, i) {
        TRACE_DEBUG("Config node: '%s' type: %u line: %u\n",
                    c->key, c->type, c->line);

        if (confignode_hastype(c, CT_STRUCT)) {
            struct_node = confignode_to_struct(c);
            if (strcasecmp(struct_node->base.key,
                           CCA_CFG_EXPECTED_MKVPS) == 0) {
                rc = cca_config_parse_exp_mkvps(
                            cca_private->token_config_filename, struct_node,
                            exp_sym_mkvp, &exp_sym_mkvp_set,
                            exp_aes_mkvp, &exp_aes_mkvp_set,
                            exp_apka_mkvp, &exp_apka_mkvp_set);
                if (rc != CKR_OK)
                    break;
                continue;
            }
        }
    }

    if (mk_change_op->new_sym_mkvp_set && exp_sym_mkvp_set &&
        memcmp(exp_sym_mkvp, new_mk ? mk_change_op->new_sym_mkvp :
                                            cca_private->expected_sym_mkvp,
               CCA_MKVP_LENGTH) != 0) {
        TRACE_ERROR("Expected SYM MKVP in config file '%s' does not specify "
                    "the %s MKVP\n", cca_private->token_config_filename,
                    new_mk ? "new" : "current");
        warnx("Expected SYM MKVP in config file '%s' does not specify the %s "
              "MKVP.", cca_private->token_config_filename,
              new_mk ? "new" : "current");
        rc = CKR_FUNCTION_FAILED;
    }

    if (mk_change_op->new_aes_mkvp_set && exp_aes_mkvp_set &&
        memcmp(exp_aes_mkvp, new_mk ? mk_change_op->new_aes_mkvp :
                                            cca_private->expected_aes_mkvp,
               CCA_MKVP_LENGTH) != 0) {
        TRACE_ERROR("Expected AES MKVP in config file '%s' does not specify "
                    "the %s MKVP\n", cca_private->token_config_filename,
                    new_mk ? "new" : "current");
        warnx("Expected AES MKVP in config file '%s' does not specify the %s "
              "MKVP.", cca_private->token_config_filename,
              new_mk ? "new" : "current");
        rc = CKR_FUNCTION_FAILED;
    }

    if (mk_change_op->new_apka_mkvp_set && exp_apka_mkvp_set &&
        memcmp(exp_apka_mkvp, new_mk ? mk_change_op->new_apka_mkvp :
                                            cca_private->expected_apka_mkvp,
               CCA_MKVP_LENGTH) != 0) {
        TRACE_ERROR("Expected APKA MKVP in config file '%s' does not specify "
                    "the %s MKVP\n", cca_private->token_config_filename,
                    new_mk ? "new" : "current");
        warnx("Expected APKA MKVP in config file '%s' does not specify the %s "
              "MKVP.", cca_private->token_config_filename,
              new_mk ? "new" : "current");
        rc = CKR_FUNCTION_FAILED;
    }

done:
    confignode_deepfree(config);
    fclose(file);

    return rc;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV cca_mk_change_finalize_query(STDLL_TokData_t *tokdata,
                                          event_mk_change_data_t *op,
                                          struct hsm_mk_change_info *info)
{
    struct cca_mk_change_op *mk_change_op;
    struct apqn_check_data acd;
    CK_RV rc;

    TRACE_DEVEL("%s finalize query for MK change op: %s\n", __func__, op->id);

    if (pthread_rwlock_rdlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("MK-change Read-Lock failed.\n");
        return CKR_CANT_LOCK;
    }

    mk_change_op = cca_mk_change_find_op(tokdata, op->id, NULL);
    if (mk_change_op == NULL) {
        TRACE_ERROR("%s operation '%s' not active\n", __func__, op->id);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    memset(&acd, 0, sizeof(acd));
    acd.slot = tokdata->slot_id;
    acd.op = op;
    acd.info = info;
    acd.finalize = TRUE; /* New MKs must be current ones */

    if (mk_change_op->new_sym_mkvp_set)
        acd.sym_new_mk = mk_change_op->new_sym_mkvp;
    if (mk_change_op->new_aes_mkvp_set)
        acd.aes_new_mk = mk_change_op->new_aes_mkvp;
    if (mk_change_op->new_apka_mkvp_set)
        acd.apka_new_mk = mk_change_op->new_apka_mkvp;

    /* Check if selected APQNs have the expected MKs set/loaded */
    rc = cca_iterate_adapters(tokdata, cca_mk_change_apqn_check_cb, &acd);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s cca_iterate_adapters failed: 0x%lx\n", __func__, rc);
        goto out;
    }

    if (acd.error) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = cca_check_token_config_expected_mkvp(tokdata, mk_change_op, TRUE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s cca_check_token_config_expected_mkvp failed: 0x%lx\n",
                    __func__, rc);
        goto out;
    }

out:
    if (pthread_rwlock_unlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("HSM-MK-change Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

    return rc;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV cca_mk_change_cancel_query(STDLL_TokData_t *tokdata,
                                        event_mk_change_data_t *op,
                                        struct hsm_mk_change_info *info)
{
    struct cca_mk_change_op *mk_change_op;
    struct apqn_check_data acd;
    CK_RV rc;

    TRACE_DEVEL("%s cancel query for MK change op: %s\n", __func__, op->id);

    if (pthread_rwlock_rdlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("MK-change Read-Lock failed.\n");
        return CKR_CANT_LOCK;
    }

    mk_change_op = cca_mk_change_find_op(tokdata, op->id, NULL);
    if (mk_change_op == NULL) {
        TRACE_ERROR("%s operation '%s' not active\n", __func__, op->id);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    memset(&acd, 0, sizeof(acd));
    acd.slot = tokdata->slot_id;
    acd.op = op;
    acd.info = info;
    acd.cancel = TRUE; /* No new MKs must be set */

    if (mk_change_op->new_sym_mkvp_set)
        acd.sym_new_mk = mk_change_op->new_sym_mkvp;
    if (mk_change_op->new_aes_mkvp_set)
        acd.aes_new_mk = mk_change_op->new_aes_mkvp;
    if (mk_change_op->new_apka_mkvp_set)
        acd.apka_new_mk = mk_change_op->new_apka_mkvp;

    /* Check if selected APQNs have the expected MKs set/loaded */
    rc = cca_iterate_adapters(tokdata, cca_mk_change_apqn_check_cb, &acd);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s cca_iterate_adapters failed: 0x%lx\n", __func__, rc);
        goto out;
    }

    if (acd.error) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = cca_check_token_config_expected_mkvp(tokdata, mk_change_op, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s cca_check_token_config_expected_mkvp failed: 0x%lx\n",
                    __func__, rc);
        goto out;
    }

out:
    if (pthread_rwlock_unlock(&tokdata->hsm_mk_change_rwlock) != 0) {
        TRACE_DEVEL("HSM-MK-change Unlock failed.\n");
        return CKR_CANT_LOCK;
    }

    return rc;
}

static CK_RV cca_reencipher_sec_key(STDLL_TokData_t *tokdata,
                                    struct cca_mk_change_op *mk_change_op,
                                    CK_BYTE *sec_key, CK_BYTE *reenc_sec_key,
                                    CK_ULONG sec_key_len, CK_BBOOL from_old)
{
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp = NULL;
    const CK_BYTE *new_mkvp = NULL;
    const char *mk_type;
    const char *verb;
    enum cca_ktc_type ktc_type;
    unsigned char rule_array[CCA_RULE_ARRAY_SIZE] = { 0, };
    long return_code, reason_code, rule_array_count, exit_data_len = 0;
    long token_length = sec_key_len;

    if (analyse_cca_key_token(sec_key, sec_key_len, &keytype, &keybitsize,
                              &mkvp) == FALSE) {
        TRACE_ERROR("%s Blob is not a valid secure key token\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    memset(rule_array, 0, sizeof(rule_array));
    if (from_old)
        memcpy(rule_array, "RTCMK   ", CCA_KEYWORD_SIZE);
    else
        memcpy(rule_array, "RTNMK   ", CCA_KEYWORD_SIZE);
    rule_array_count = 2;

    switch (keytype) {
    case sec_des_data_key:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "DES     ", CCA_KEYWORD_SIZE);
        mk_type = "SYM";
        new_mkvp = mk_change_op->new_sym_mkvp;
        ktc_type = CCA_KTC_DATA;
        break;
    case sec_aes_data_key:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "AES     ", CCA_KEYWORD_SIZE);
        mk_type = "AES";
        new_mkvp = mk_change_op->new_aes_mkvp;
        ktc_type = CCA_KTC_DATA;
        break;
    case sec_aes_cipher_key:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "AES     ", CCA_KEYWORD_SIZE);
        mk_type = "AES";
        new_mkvp = mk_change_op->new_aes_mkvp;
        ktc_type = CCA_KTC_CIPHER;
        break;
    case sec_hmac_key:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "HMAC    ", CCA_KEYWORD_SIZE);
        mk_type = "AES";
        new_mkvp = mk_change_op->new_aes_mkvp;
        ktc_type = CCA_KTC_CIPHER;
        break;
    case sec_rsa_priv_key:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "RSA     ", CCA_KEYWORD_SIZE);
        mk_type = "APKA";
        new_mkvp = mk_change_op->new_apka_mkvp;
        ktc_type = CCA_KTC_PKA;
        break;
    case sec_ecc_priv_key:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "ECC     ", CCA_KEYWORD_SIZE);
        mk_type = "APKA";
        new_mkvp = mk_change_op->new_apka_mkvp;
        ktc_type = CCA_KTC_PKA;
        break;
    case sec_qsa_priv_key:
        memcpy(rule_array + CCA_KEYWORD_SIZE, "QSA     ", CCA_KEYWORD_SIZE);
        mk_type = "APKA";
        new_mkvp = mk_change_op->new_apka_mkvp;
        ktc_type = CCA_KTC_PKA;
        break;
    default:
        TRACE_ERROR("%s Blob is an invalid secure key type: %d\n",
                    __func__, keytype);
        return CKR_FUNCTION_FAILED;
    }

    if (new_mkvp == NULL) {
        TRACE_ERROR("%s Master key type %s is not affected by operation %s\n",
                    __func__, mk_type, mk_change_op->mk_change_op);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(reenc_sec_key, sec_key, sec_key_len);

    switch (ktc_type) {
    case CCA_KTC_DATA:
        verb = "CSNBKTC";
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNBKTC(&return_code, &reason_code,
                        &exit_data_len, NULL,
                        &rule_array_count, rule_array,
                        reenc_sec_key);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)
        break;
    case CCA_KTC_CIPHER:
        verb = "CSNBKTC2";
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNBKTC2(&return_code, &reason_code,
                         &exit_data_len, NULL,
                         &rule_array_count, rule_array,
                         &token_length, reenc_sec_key);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)
        break;
    case CCA_KTC_PKA:
        verb = "CSNDKTC";
        USE_CCA_ADAPTER_START(tokdata, return_code, reason_code)
            dll_CSNDKTC(&return_code, &reason_code,
                        &exit_data_len, NULL,
                        &rule_array_count, rule_array,
                        &token_length, reenc_sec_key);
        USE_CCA_ADAPTER_END(tokdata, return_code, reason_code)
        break;
    default:
        return CKR_FUNCTION_FAILED;
    }

    if (return_code != CCA_SUCCESS) {
        TRACE_ERROR("%s (%s) failed. return:%ld, reason:%ld\n", verb,
                    rule_array, return_code, reason_code);
        if (return_code == 8 && reason_code == 48)
            return CKR_DEVICE_ERROR; /* MKVP of key not valid */
        return CKR_FUNCTION_FAILED;
    }

    /* check for expected new MK */
    if (analyse_cca_key_token(reenc_sec_key, sec_key_len, &keytype, &keybitsize,
                              &mkvp) == FALSE) {
        TRACE_ERROR("%s Blob is not a valid secure key token\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (memcmp(mkvp, new_mkvp, CCA_MKVP_LENGTH) != 0) {
        TRACE_ERROR("%s Re-enciphered key blob is not enciphered by expected "
                    "new %s MK\n", __func__, mk_type);
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Re-enciphered key blob is not enciphered"
                   " by expected new %s MK\n", tokdata->slot_id, mk_type);
        return CKR_DEVICE_ERROR;
    }

    return CKR_OK;
}

struct reencipher_data {
    STDLL_TokData_t *tokdata;
    struct cca_mk_change_op *mk_change_op;
};

static CK_RV cca_reencipher_objects_reenc(CK_BYTE *sec_key,
                                          CK_BYTE *reenc_sec_key,
                                          CK_ULONG sec_key_len,
                                          void *private)
{
    struct reencipher_data *rd = private;

    return cca_reencipher_sec_key(rd->tokdata, rd->mk_change_op,
                                  sec_key, reenc_sec_key, sec_key_len, FALSE);
}

static CK_RV cca_reencipher_objects_cb(STDLL_TokData_t *tokdata,
                                       OBJECT *obj, void *cb_data)
{
    struct reencipher_data *rd = cb_data;
    CK_RV rc;

    rc = obj_mgr_reencipher_secure_key(tokdata, obj,
                                       cca_reencipher_objects_reenc, rd);
    if (rc == CKR_OBJECT_HANDLE_INVALID) /* Obj was deleted by other proc */
        rc = CKR_OK;

    return rc;
}

static CK_BBOOL cca_reencipher_filter_cb(STDLL_TokData_t *tokdata,
                                         OBJECT *obj, void *filter_data)
{
    struct cca_mk_change_op *mk_change_op  = filter_data;
    CK_ATTRIBUTE *attr;
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp = NULL;

    UNUSED(tokdata);

    if (template_attribute_find(obj->template, CKA_IBM_OPAQUE, &attr) == FALSE)
        return FALSE;

    if (analyse_cca_key_token(attr->pValue, attr->ulValueLen,
                              &keytype, &keybitsize, &mkvp) == FALSE)
        return FALSE;

    switch (keytype) {
    case sec_des_data_key:
        return mk_change_op->new_sym_mkvp_set;

    case sec_aes_data_key:
    case sec_aes_cipher_key:
    case sec_hmac_key:
        return mk_change_op->new_aes_mkvp_set;

    case sec_rsa_priv_key:
    case sec_ecc_priv_key:
    case sec_qsa_priv_key:
        return mk_change_op->new_apka_mkvp_set;

    default:
        return FALSE;
    }
}

static CK_BBOOL cca_reencipher_cancel_filter_cb(STDLL_TokData_t *tokdata,
                                                OBJECT *obj, void *filter_data)
{
    CK_ATTRIBUTE *attr;

    if (template_attribute_find(obj->template, CKA_IBM_OPAQUE_REENC,
                                &attr) == FALSE)
        return FALSE;

    return cca_reencipher_filter_cb(tokdata, obj, filter_data);
}

static CK_RV cca_reencipher_cancel_objects_cb(STDLL_TokData_t *tokdata,
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

static CK_BBOOL cca_reencipher_finalize_is_new_mk_cb(STDLL_TokData_t *tokdata,
                                                     OBJECT *obj,
                                                     CK_BYTE *sec_key,
                                                     CK_ULONG sec_key_len,
                                                     void *cb_private)
{
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp = NULL;
    CK_BBOOL new_mk = FALSE;

    UNUSED(cb_private);
    UNUSED(obj);

    if (analyse_cca_key_token(sec_key, sec_key_len,
                              &keytype, &keybitsize, &mkvp) == FALSE)
        return FALSE;

    if (check_expected_mkvp(tokdata, keytype, mkvp, &new_mk) != CKR_OK)
        return FALSE;

    return new_mk;
}

static CK_RV cca_reencipher_finalize_objects_cb(STDLL_TokData_t *tokdata,
                                                OBJECT *obj, void *cb_data)
{
    CK_RV rc;

    UNUSED(cb_data);

    rc = obj_mgr_reencipher_secure_key_finalize(tokdata, obj,
                                    cca_reencipher_finalize_is_new_mk_cb, NULL);
    if (rc == CKR_ATTRIBUTE_TYPE_INVALID)
        rc = CKR_OK;
    if (rc == CKR_OBJECT_HANDLE_INVALID) /* Obj was deleted by other proc */
        rc = CKR_OK;

    return rc;
}

static CK_RV cca_finalize_sessions_cb(STDLL_TokData_t *tokdata,
                                      SESSION *session, CK_ULONG ctx_type,
                                      CK_MECHANISM *mech, CK_OBJECT_HANDLE key,
                                      CK_BYTE *context, CK_ULONG context_len,
                                      CK_BBOOL init_pending,
                                      CK_BBOOL pkey_active, CK_BBOOL recover,
                                      void *private)
{
    struct cca_mk_change_op *mk_change_op  = private;
    CK_ATTRIBUTE *opaque_attr = NULL;
    OBJECT *key_obj = NULL;
    CK_OBJECT_CLASS class;
    enum cca_token_type keytype;
    unsigned int keybitsize;
    const CK_BYTE *mkvp;
    CK_RV rc;

    UNUSED(session);
    UNUSED(ctx_type);
    UNUSED(mech);
    UNUSED(context);
    UNUSED(context_len);
    UNUSED(init_pending);
    UNUSED(pkey_active);
    UNUSED(recover);

    if (key == CK_INVALID_HANDLE)
        return CKR_OK;

    /*
     * Update the key object from disk if it is a token object, the secure key
     * is affected by the MK change operation, and it has been changed by
     * another process, i.e. due to re-enciphering of the object by the
     * pkcshsm_mk_change tool.
     */
    rc = object_mgr_find_in_map_nocache(tokdata, key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to get key object: 0x%lx\n",
                   tokdata->slot_id, rc);
        goto done;
    }

    if (!object_is_token_object(key_obj))
        goto done;

    rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to get object class: 0x%lx\n", __func__, rc);
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to get object class: 0x%lx\n",
                   tokdata->slot_id, rc);
        goto done;
    }

    switch (class) {
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
    case CKO_SECRET_KEY:
        break;
    default:
        /* Not a key object */
        goto done;
    }

    if (!template_attribute_find(key_obj->template, CKA_IBM_OPAQUE,
                                 &opaque_attr)) {
        rc = CKR_ATTRIBUTE_TYPE_INVALID;
        TRACE_ERROR("%s Failed to get CKA_IBM_OPAQUE\n", __func__);
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to gCKA_IBM_OPAQUE\n",
                   tokdata->slot_id);
        rc = CKR_TEMPLATE_INCOMPLETE;
        goto done;
    }

    if (analyse_cca_key_token(opaque_attr->pValue, opaque_attr->ulValueLen,
                              &keytype, &keybitsize, &mkvp) == FALSE) {
        TRACE_ERROR("%s Key token is not valid: handle: %lu\n", __func__, key);
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Key token is not valid: handle: %lu\n",
                   tokdata->slot_id, key);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    switch (keytype) {
    case sec_des_data_key:
        if (mk_change_op->new_sym_mkvp_set == FALSE)
            goto done;
        break;
    case sec_aes_data_key:
    case sec_aes_cipher_key:
    case sec_hmac_key:
        if (mk_change_op->new_aes_mkvp_set == FALSE)
            goto done;
        break;
    case sec_rsa_priv_key:
    case sec_ecc_priv_key:
    case sec_qsa_priv_key:
        if (mk_change_op->new_apka_mkvp_set == FALSE)
            goto done;
        break;
    default:
        goto done;
    }

    TRACE_INFO("%s Update token key object '%s' referenced by state of session "
               "0x%lx\n", __func__, key_obj->name, session->handle);
    OCK_SYSLOG(LOG_DEBUG, "Slot %lu: Update token key object '%s' referenced "
               "by state of session 0x%lx\n", tokdata->slot_id, key_obj->name,
               session->handle);

    rc = object_mgr_check_shm(tokdata, key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_check_shm failed.\n");
        OCK_SYSLOG(LOG_ERR, "Slot %lu: Failed to update token key object '%s' "
                   "from SHM: 0x%lx\n", tokdata->slot_id, key_obj->name, rc);
        goto done;
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

/*
 * ATTENTION: This function is called in a separate thread. All actions
 * performed by this function must be thread save and use locks to lock
 * against concurrent access by other threads.
 */
static CK_RV cca_mk_change_reencipher(STDLL_TokData_t *tokdata,
                                      event_mk_change_data_t *op,
                                      struct hsm_mk_change_info *info)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    struct cca_mk_change_op *mk_change_op;
    const unsigned char *new_sym_mk = NULL;
    const unsigned char *new_aes_mk = NULL;
    const unsigned char *new_apka_mk = NULL;
    struct reencipher_data rd = { 0 };
    CK_RV rc = CKR_OK;
    unsigned int op_idx;
    CK_BBOOL token_objs = FALSE;

    if ((op->flags & EVENT_MK_CHANGE_FLAGS_TOK_OBJS) != 0) {
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

    mk_change_op = cca_mk_change_find_op(tokdata, op->id, NULL);
    if (token_objs == TRUE && mk_change_op == NULL) {
        TRACE_DEVEL("HSM-MK-change op %s must already be active\n", op->id);
        OCK_SYSLOG(LOG_ERR,
                   "Slot %lu: HSM-MK-change %s must already be active\n",
                   tokdata->slot_id, op->id);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    /* Activate this MK change operation if not already active */
    if (mk_change_op == NULL) {
        new_sym_mk = hsm_mk_change_mkvps_find(info->mkvps, info->num_mkvps,
                                              HSM_MK_TYPE_CCA_SYM,
                                              CCA_MKVP_LENGTH);
        new_aes_mk = hsm_mk_change_mkvps_find(info->mkvps, info->num_mkvps,
                                              HSM_MK_TYPE_CCA_AES,
                                              CCA_MKVP_LENGTH);
        new_apka_mk = hsm_mk_change_mkvps_find(info->mkvps, info->num_mkvps,
                                               HSM_MK_TYPE_CCA_APKA,
                                               CCA_MKVP_LENGTH);
        if (new_sym_mk == NULL && new_aes_mk == NULL && new_apka_mk == NULL) {
            TRACE_ERROR("%s No CCA MK type found in MK change operation: %s\n",
                        __func__, op->id);
            OCK_SYSLOG(LOG_ERR, "Slot %lu: No CCA MK type found in MK change "
                       "operation: %s\n", tokdata->slot_id, op->id);
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        rc = cca_mk_change_activate_op(tokdata, op->id, info,
                                       new_sym_mk, new_aes_mk, new_apka_mk,
                                       &op_idx);
        if (rc != CKR_OK)
            goto out;

         mk_change_op = &cca_private->mk_change_ops[op_idx];
    }

    TRACE_DEVEL("%s MK change op: %s\n", __func__,
                mk_change_op->mk_change_op);
    if (mk_change_op->new_sym_mkvp_set) {
        TRACE_DEBUG_DUMP("New SYM MK: ", (void *)mk_change_op->new_sym_mkvp,
                         CCA_MKVP_LENGTH);
    }
    if (mk_change_op->new_aes_mkvp_set) {
        TRACE_DEBUG_DUMP("New AES MK: ", (void *)mk_change_op->new_aes_mkvp,
                         CCA_MKVP_LENGTH);
    }
    if (mk_change_op->new_apka_mkvp_set) {
        TRACE_DEBUG_DUMP("New APKA MK: ", (void *)mk_change_op->new_apka_mkvp,
                         CCA_MKVP_LENGTH);
    }

    /* Re-encipher key objects */
    rd.tokdata = tokdata;
    rd.mk_change_op = mk_change_op;

    rc = obj_mgr_iterate_key_objects(tokdata, !token_objs, token_objs,
                                     cca_reencipher_filter_cb, mk_change_op,
                                     cca_reencipher_objects_cb, &rd,
                                     TRUE, "re-encipher");
    if (rc != CKR_OK) {
        obj_mgr_iterate_key_objects(tokdata, !token_objs, token_objs,
                                    cca_reencipher_cancel_filter_cb, mk_change_op,
                                    cca_reencipher_cancel_objects_cb, NULL,
                                    TRUE, "cancel");
        /*
         * The pkcshsm_mk_change tool will send a CANCEL event, so leave the
         * operation active for now.
         */
        goto out;
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
static CK_RV cca_mk_change_finalize_cancel(STDLL_TokData_t *tokdata,
                                           event_mk_change_data_t *op,
                                           struct hsm_mk_change_info *info,
                                           CK_BBOOL cancel)
{
    struct cca_private_data *cca_private = tokdata->private_data;
    struct cca_mk_change_op *mk_change_op;
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

    mk_change_op = cca_mk_change_find_op(tokdata, op->id, NULL);
    if (mk_change_op == NULL)
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
                                             cca_reencipher_cancel_filter_cb :
                                             cca_reencipher_filter_cb,
                                     mk_change_op,
                                     cancel ?
                                         cca_reencipher_cancel_objects_cb :
                                         cca_reencipher_finalize_objects_cb,
                                     NULL, TRUE,
                                     cancel ? "cancel" : "finalize");
    if (rc != CKR_OK)
        goto out;

    if (!token_objs && !cancel) {
        /* update token keys referenced in active sessions */
        rc = session_mgr_iterate_session_ops(tokdata, NULL,
                                             cca_finalize_sessions_cb,
                                             mk_change_op);
        if (rc != CKR_OK) {
            OCK_SYSLOG(LOG_ERR,
                       "Slot %lu: Failed to finalize sessions: 0x%lx\n",
                       tokdata->slot_id, rc);
            goto out;
        }
    }

    /*
     * Deactivate this MK change operation.
     * For the pkcshsm_mk_change tool: Deactivate only after 2nd token object
     * processing.
     */
    if ((token_objs == FALSE && op->tool_pid != tokdata->real_pid) ||
        (op->flags & EVENT_MK_CHANGE_FLAGS_TOK_OBJS_FINAL) != 0) {

        if (!cancel) {
            /* From now on the new MKs are the expected one */
            if (mk_change_op->new_sym_mkvp_set)
                memcpy(cca_private->expected_sym_mkvp,
                       mk_change_op->new_sym_mkvp, CCA_MKVP_LENGTH);
            if (mk_change_op->new_aes_mkvp_set)
                memcpy(cca_private->expected_aes_mkvp,
                       mk_change_op->new_aes_mkvp, CCA_MKVP_LENGTH);
            if (mk_change_op->new_apka_mkvp_set)
                memcpy(cca_private->expected_apka_mkvp,
                       mk_change_op->new_apka_mkvp, CCA_MKVP_LENGTH);
        }

        mk_change_op->mk_change_active = 0;
        memset(mk_change_op->mk_change_op, 0,
               sizeof(mk_change_op->mk_change_op));
        if (mk_change_op->apqns != NULL)
            free(mk_change_op->apqns);
        mk_change_op->apqns = NULL;
        mk_change_op->num_apqns = 0;

        TRACE_DEVEL("%s %s MK change op: %s\n", __func__,
                    cancel ? "canceled" : "finalized", op->id);
        OCK_SYSLOG(LOG_INFO, "Slot %lu: Concurrent HSM master key change "
                   "operation %s is %s\n",
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
CK_RV cca_handle_mk_change_event(STDLL_TokData_t *tokdata,
                                 unsigned int event_type,
                                 unsigned int event_flags,
                                 const char *payload,
                                 unsigned int payload_len)
{
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

    rc = cca_mk_change_is_affected(tokdata, &info);
    if (rc != CKR_OK)
        goto out;

    if (event_type != EVENT_TYPE_MK_CHANGE_INITIATE_QUERY &&
        event_type != EVENT_TYPE_MK_CHANGE_REENCIPHER) {
        /* Operation must be active */
        if (pthread_rwlock_rdlock(&tokdata->hsm_mk_change_rwlock) != 0) {
            TRACE_DEVEL("HSM-MK-change Read-Lock failed.\n");
            rc = CKR_CANT_LOCK;
            goto out;
        }

        if (cca_mk_change_find_op(tokdata, hdr->id, NULL) == NULL) {
            TRACE_ERROR("%s Must be a currently active operation: '%s'\n",
                        __func__, hdr->id);
            rc = CKR_FUNCTION_FAILED;
            pthread_rwlock_unlock(&tokdata->hsm_mk_change_rwlock);
            goto out;
        }

        if (pthread_rwlock_unlock(&tokdata->hsm_mk_change_rwlock) != 0) {
            TRACE_DEVEL("HSM-MK-change Unlock failed.\n");
            rc = CKR_CANT_LOCK;
            goto out;
        }
    }

    switch (event_type) {
    case EVENT_TYPE_MK_CHANGE_INITIATE_QUERY:
        rc = cca_mk_change_init_query(tokdata, hdr, &info);
        break;
    case EVENT_TYPE_MK_CHANGE_REENCIPHER:
        rc = cca_mk_change_reencipher(tokdata, hdr, &info);
        break;
    case EVENT_TYPE_MK_CHANGE_FINALIZE_QUERY:
        rc = cca_mk_change_finalize_query(tokdata, hdr, &info);
        break;
    case EVENT_TYPE_MK_CHANGE_CANCEL_QUERY:
        rc = cca_mk_change_cancel_query(tokdata, hdr, &info);
        break;
    case EVENT_TYPE_MK_CHANGE_FINALIZE:
        rc = cca_mk_change_finalize_cancel(tokdata, hdr, &info, FALSE);
        break;
    case EVENT_TYPE_MK_CHANGE_CANCEL:
        rc = cca_mk_change_finalize_cancel(tokdata, hdr, &info, TRUE);
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
