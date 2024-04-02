/*
 * COPYRIGHT (c) International Business Machines Corp. 2024
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"

CK_RV ckm_ibm_dilithium_key_pair_gen(STDLL_TokData_t *tokdata,
                                     TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    const struct pqc_oid *pqc_oid;
    CK_RV rc;

    if (token_specific.t_ibm_dilithium_generate_keypair == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    pqc_oid = ibm_pqc_get_keyform_mode(publ_tmpl, CKM_IBM_DILITHIUM);
    if (pqc_oid == NULL)
        pqc_oid = ibm_pqc_get_keyform_mode(priv_tmpl, CKM_IBM_DILITHIUM);
    if (pqc_oid == NULL)
        pqc_oid = find_pqc_by_keyform(dilithium_oids,
                                      CK_IBM_DILITHIUM_KEYFORM_ROUND2_65);
    if (pqc_oid == NULL) {
        TRACE_ERROR("%s Failed to determine dilithium OID\n", __func__);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    rc = token_specific.t_ibm_dilithium_generate_keypair(tokdata, pqc_oid,
                                                         publ_tmpl, priv_tmpl);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific dilithium keypair generation failed.\n");

    return rc;
}

CK_RV ibm_dilithium_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_OBJECT_CLASS class;
    const struct pqc_oid *oid;
    CK_RV rc;

    if (token_specific.t_ibm_dilithium_sign == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        goto done;
    }

    if (class != CKO_PRIVATE_KEY) {
        TRACE_ERROR("This operation requires a private key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    oid = ibm_pqc_get_keyform_mode(key_obj->template, CKM_IBM_DILITHIUM);
    if (oid == NULL) {
        TRACE_DEVEL("No keyform/mode found in key object\n");
        rc = CKR_TEMPLATE_INCOMPLETE;
        goto done;
    }

    rc = token_specific.t_ibm_dilithium_sign(tokdata, sess, length_only, oid,
                                             in_data, in_data_len,
                                             out_data, out_data_len, key_obj);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific ibm dilithium sign failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ibm_dilithium_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *in_data, CK_ULONG in_data_len,
                           CK_BYTE *signature, CK_ULONG sig_len)
{
    OBJECT *key_obj = NULL;
    CK_OBJECT_CLASS class;
    const struct pqc_oid *oid;
    CK_RV rc;

    if (token_specific.t_ibm_dilithium_verify == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        goto done;
    }

    if (class != CKO_PUBLIC_KEY) {
        TRACE_ERROR("This operation requires a public key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    oid = ibm_pqc_get_keyform_mode(key_obj->template, CKM_IBM_DILITHIUM);
    if (oid == NULL) {
        TRACE_DEVEL("No keyform/mode found in key object\n");
        rc = CKR_TEMPLATE_INCOMPLETE;
        goto done;
    }

    rc = token_specific.t_ibm_dilithium_verify(tokdata, sess, oid,
                                               in_data, in_data_len,
                                               signature, sig_len, key_obj);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific ibm dilithium verify failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}
