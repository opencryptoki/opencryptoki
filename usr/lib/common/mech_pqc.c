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

#define PACK_PART(attr, explen, buf, buflen, ofs)                       \
    if ((attr)->ulValueLen != (explen)) {                               \
        TRACE_ERROR("Key part #attr length not as expected\n");         \
        return CKR_ATTRIBUTE_VALUE_INVALID;                             \
    }                                                                   \
    if ((ofs) + (attr)->ulValueLen > (buflen)) {                        \
        TRACE_ERROR("Buffer is too small\n");                           \
        return CKR_BUFFER_TOO_SMALL;                                    \
    }                                                                   \
    memcpy(&(buf)[(ofs)], (attr)->pValue, (attr)->ulValueLen);          \
    (ofs) += (attr)->ulValueLen

CK_RV ibm_dilithium_pack_priv_key(TEMPLATE *templ, const struct pqc_oid *oid,
                                  CK_BYTE *buf, CK_ULONG *buf_len)
{
    CK_ATTRIBUTE *rho = NULL, *seed = NULL;
    CK_ATTRIBUTE *tr = NULL, *s1 = NULL, *s2 = NULL;
    CK_ATTRIBUTE *t0 = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    if (buf == NULL) {
        *buf_len = oid->len_info.dilithium.rho_len +
                   oid->len_info.dilithium.seed_len +
                   oid->len_info.dilithium.tr_len +
                   oid->len_info.dilithium.s1_len +
                   oid->len_info.dilithium.s2_len +
                   oid->len_info.dilithium.t0_len;
        return CKR_OK;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_DILITHIUM_RHO,
                                          &rho);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_RHO for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_DILITHIUM_SEED,
                                          &seed);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_SEED for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_DILITHIUM_TR,
                                          &tr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_TR for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_DILITHIUM_S1,
                                          &s1);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_S1 for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_DILITHIUM_S2,
                                          &s2);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_S2 for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_DILITHIUM_T0,
                                          &t0);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_T0 for the key.\n");
        return rc;
    }

    PACK_PART(rho, oid->len_info.dilithium.rho_len, buf, *buf_len, ofs);
    PACK_PART(seed, oid->len_info.dilithium.seed_len, buf, *buf_len, ofs);
    PACK_PART(tr, oid->len_info.dilithium.tr_len, buf, *buf_len, ofs);
    PACK_PART(s1, oid->len_info.dilithium.s1_len, buf, *buf_len, ofs);
    PACK_PART(s2, oid->len_info.dilithium.s2_len, buf, *buf_len, ofs);
    PACK_PART(t0, oid->len_info.dilithium.t0_len, buf, *buf_len, ofs);

    *buf_len = ofs;

    return CKR_OK;
}

CK_RV ibm_dilithium_pack_pub_key(TEMPLATE *templ, const struct pqc_oid *oid,
                                 CK_BYTE *buf, CK_ULONG *buf_len)
{
    CK_ATTRIBUTE *rho = NULL, *t1 = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    if (buf == NULL) {
        *buf_len = oid->len_info.dilithium.rho_len +
                   oid->len_info.dilithium.t1_len;
        return CKR_OK;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_DILITHIUM_RHO,
                                          &rho);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_RHO for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_DILITHIUM_T1,
                                          &t1);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_DILITHIUM_T1 for the key.\n");
        return rc;
    }

    PACK_PART(rho, oid->len_info.dilithium.rho_len, buf, *buf_len, ofs);
    PACK_PART(t1, oid->len_info.dilithium.t1_len, buf, *buf_len, ofs);

    *buf_len = ofs;

    return CKR_OK;
}

#define UNPACK_PART(attr, attr_type, len, buf, buflen, ofs, rc, label)     \
    if ((ofs) + (len) > (buflen)) {                                        \
        TRACE_ERROR("Buffer is too small\n");                              \
        (rc) = CKR_BUFFER_TOO_SMALL;                                       \
        goto label;                                                        \
    }                                                                      \
    (rc) = build_attribute(attr_type, &(buf)[(ofs)], (len), &(attr));      \
    if ((rc) != CKR_OK) {                                                  \
        TRACE_ERROR("build_attribute for #attr failed\n");                 \
        goto label;                                                        \
    }                                                                      \
    (ofs) += (len);

CK_RV ibm_dilithium_unpack_priv_key(CK_BYTE *buf, CK_ULONG buf_len,
                                    const struct pqc_oid *oid,
                                    TEMPLATE *templ)
{
    CK_ATTRIBUTE *rho = NULL, *seed = NULL;
    CK_ATTRIBUTE *tr = NULL, *s1 = NULL, *s2 = NULL;
    CK_ATTRIBUTE *t0 = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    UNPACK_PART(rho, CKA_IBM_DILITHIUM_RHO, oid->len_info.dilithium.rho_len,
                buf, buf_len, ofs, rc, out);
    UNPACK_PART(seed, CKA_IBM_DILITHIUM_SEED, oid->len_info.dilithium.seed_len,
                buf, buf_len, ofs, rc, out);
    UNPACK_PART(tr, CKA_IBM_DILITHIUM_TR, oid->len_info.dilithium.tr_len,
                buf, buf_len, ofs, rc, out);
    UNPACK_PART(s1, CKA_IBM_DILITHIUM_S1, oid->len_info.dilithium.s1_len,
                buf, buf_len, ofs, rc, out);
    UNPACK_PART(s2, CKA_IBM_DILITHIUM_S2, oid->len_info.dilithium.s2_len,
                buf, buf_len, ofs, rc, out);
    UNPACK_PART(t0, CKA_IBM_DILITHIUM_T0, oid->len_info.dilithium.t0_len,
                buf, buf_len, ofs, rc, out);

    rc = template_update_attribute(templ, rho);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update forCKA_IBM_DILITHIUM_RHO failed\n");
        goto out;
    }
    rho = NULL;

    rc = template_update_attribute(templ, seed);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update forCKA_IBM_DILITHIUM_SEED failed\n");
        goto out;
    }
    seed = NULL;

    rc = template_update_attribute(templ, tr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update forCKA_IBM_DILITHIUM_TR failed\n");
        goto out;
    }
    tr = NULL;

    rc = template_update_attribute(templ, s1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update forCKA_IBM_DILITHIUM_S1 failed\n");
        goto out;
    }
    s1 = NULL;

    rc = template_update_attribute(templ, s2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update forCKA_IBM_DILITHIUM_S2 failed\n");
        goto out;
    }
    s2 = NULL;

    rc = template_update_attribute(templ, t0);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update forCKA_IBM_DILITHIUM_T0 failed\n");
        goto out;
    }
    t0 = NULL;

out:
    if (rho != NULL)
        free(rho);
    if (seed != NULL)
        free(seed);
    if (tr != NULL)
        free(tr);
    if (s1 != NULL)
        free(s1);
    if (s2 != NULL)
        free(s2);
    if (t0 != NULL)
        free(t0);

    return rc;
}

CK_RV ibm_dilithium_unpack_pub_key(CK_BYTE *buf, CK_ULONG buf_len,
                                   const struct pqc_oid *oid,
                                   TEMPLATE *templ)
{
    CK_ATTRIBUTE *rho = NULL, *t1 = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    UNPACK_PART(rho, CKA_IBM_DILITHIUM_RHO, oid->len_info.dilithium.rho_len,
                buf, buf_len, ofs, rc, out);
    UNPACK_PART(t1, CKA_IBM_DILITHIUM_T1, oid->len_info.dilithium.t1_len,
                buf, buf_len, ofs, rc, out);

    rc = template_update_attribute(templ, rho);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update forCKA_IBM_DILITHIUM_RHO failed\n");
        goto out;
    }
    rho = NULL;

    rc = template_update_attribute(templ, t1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update forCKA_IBM_DILITHIUM_T1 failed\n");
        goto out;
    }
    t1 = NULL;

out:
    if (rho != NULL)
        free(rho);
    if (t1 != NULL)
        free(t1);

    return rc;
}
