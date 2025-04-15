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
#include "attributes.h"

CK_RV ckm_ibm_ml_dsa_key_pair_gen(STDLL_TokData_t *tokdata, CK_MECHANISM *mech,
                                  TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    const struct pqc_oid *pqc_oid;
    CK_RV rc;

    if (token_specific.t_ibm_ml_dsa_generate_keypair == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    pqc_oid = pqc_get_keyform_mode(publ_tmpl, mech->mechanism);
    if (pqc_oid == NULL)
        pqc_oid = pqc_get_keyform_mode(priv_tmpl, mech->mechanism);
    if (pqc_oid == NULL && mech->mechanism == CKM_IBM_DILITHIUM)
        pqc_oid = find_pqc_by_keyform(dilithium_oids,
                                      CK_IBM_DILITHIUM_KEYFORM_ROUND2_65);
    if (pqc_oid == NULL) {
        TRACE_ERROR("%s Failed to determine ML-DSA OID\n", __func__);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    rc = token_specific.t_ibm_ml_dsa_generate_keypair(tokdata, mech, pqc_oid,
                                                      publ_tmpl, priv_tmpl);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific ML-DSA keypair generation failed.\n");

    return rc;
}

CK_RV ibm_ml_dsa_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_OBJECT_CLASS class;
    const struct pqc_oid *oid;
    CK_RV rc;

    if (token_specific.t_ibm_ml_dsa_sign == NULL) {
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

    oid = pqc_get_keyform_mode(key_obj->template, ctx->mech.mechanism);
    if (oid == NULL) {
        TRACE_DEVEL("No keyform/mode found in key object\n");
        rc = CKR_TEMPLATE_INCOMPLETE;
        goto done;
    }

    rc = token_specific.t_ibm_ml_dsa_sign(tokdata, sess, length_only, oid,
                                          &ctx->mech, in_data, in_data_len,
                                          out_data, out_data_len, key_obj);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific IBM ML-DSA sign failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ibm_ml_dsa_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                        SIGN_VERIFY_CONTEXT *ctx,
                        CK_BYTE *in_data, CK_ULONG in_data_len,
                        CK_BYTE *signature, CK_ULONG sig_len)
{
    OBJECT *key_obj = NULL;
    CK_OBJECT_CLASS class;
    const struct pqc_oid *oid;
    CK_RV rc;

    if (token_specific.t_ibm_ml_dsa_verify == NULL) {
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

    oid = pqc_get_keyform_mode(key_obj->template, ctx->mech.mechanism);
    if (oid == NULL) {
        TRACE_DEVEL("No keyform/mode found in key object\n");
        rc = CKR_TEMPLATE_INCOMPLETE;
        goto done;
    }

    rc = token_specific.t_ibm_ml_dsa_verify(tokdata, sess, oid, &ctx->mech,
                                            in_data, in_data_len,
                                            signature, sig_len, key_obj);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific IBM ML-DSA verify failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV ckm_ibm_ml_kem_key_pair_gen(STDLL_TokData_t *tokdata, CK_MECHANISM *mech,
                                  TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    const struct pqc_oid *pqc_oid;
    CK_RV rc;

    if (token_specific.t_ibm_ml_kem_generate_keypair == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    pqc_oid = pqc_get_keyform_mode(publ_tmpl, mech->mechanism);
    if (pqc_oid == NULL)
        pqc_oid = pqc_get_keyform_mode(priv_tmpl, mech->mechanism);
    if (pqc_oid == NULL && mech->mechanism == CKM_IBM_KYBER)
        pqc_oid = find_pqc_by_keyform(kyber_oids,
                                      CK_IBM_KYBER_KEYFORM_ROUND2_1024);
    if (pqc_oid == NULL) {
        TRACE_ERROR("%s Failed to determine ML-KEM OID\n", __func__);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    rc = token_specific.t_ibm_ml_kem_generate_keypair(tokdata, mech, pqc_oid,
                                                      publ_tmpl, priv_tmpl);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific ML-KEM keypair generation failed.\n");

    return rc;
}

CK_RV ibm_ml_kem_derive(STDLL_TokData_t *tokdata, SESSION *sess,
                        CK_MECHANISM *mech, OBJECT *base_key_obj,
                        CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                        CK_OBJECT_HANDLE *derived_key_handle)

{
    const struct pqc_oid *oid;
    OBJECT *derived_key_obj = NULL;
    CK_ULONG  allowed_keysize = 0;
    CK_ULONG derived_keytype = 0, derived_keylen = 0;
    CK_ULONG base_key_class, base_key_type;
    CK_RV rc;

    if (token_specific.t_ibm_ml_kem_derive == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    oid = pqc_get_keyform_mode(base_key_obj->template, mech->mechanism);
    if (oid == NULL) {
        TRACE_DEVEL("No keyform/mode found in key object\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if (!template_get_class(base_key_obj->template, &base_key_class,
                            &base_key_type)) {
        TRACE_ERROR("Could not find CKA_CLASS in the template\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if (base_key_class != CKO_PRIVATE_KEY && base_key_class != CKO_PUBLIC_KEY) {
        TRACE_ERROR("Base key is not a private or public key\n");
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_VALUE_LEN,
                                     &derived_keylen);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return rc;
    }

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_KEY_TYPE,
                                     &derived_keytype);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return rc;
    }

    /*
     * - no key length and no key type: CKR_TEMPLATE_INCOMPLETE
     * - no key type, but length given: CKK_GENERIC_SECRET of specified length.
     * - no key length but key type specified: key must have a well-defined
     *                                         length, otherwise error.
     * - key length and key type specified: length must be compatible with key
     *                                      type, otherwise error.
     */
    if (derived_keytype == 0 && derived_keylen == 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if (derived_keytype == 0)
        derived_keytype = CKK_GENERIC_SECRET;

    switch (derived_keytype) {
    case CKK_GENERIC_SECRET:
        if (derived_keylen == 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        allowed_keysize = derived_keylen;
        break;
    case CKK_DES:
        allowed_keysize = DES_KEY_SIZE;
        break;
    case CKK_DES2:
        allowed_keysize = 2 * DES_KEY_SIZE;
        break;
    case CKK_DES3:
        allowed_keysize = 3 * DES_KEY_SIZE;
        break;
    case CKK_AES:
        switch (derived_keylen) {
        case AES_KEY_SIZE_128:
        case AES_KEY_SIZE_192:
        case AES_KEY_SIZE_256:
            allowed_keysize = derived_keylen;
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        break;
    case CKK_AES_XTS:
        switch (derived_keylen) {
        case 2 * AES_KEY_SIZE_128:
        case 2 * AES_KEY_SIZE_256:
            allowed_keysize = derived_keylen;
            break;
        default:
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        return CKR_TEMPLATE_INCONSISTENT;
    }

    if (derived_keylen == 0)
        derived_keylen = allowed_keysize;

    if (derived_keylen != allowed_keysize) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        return CKR_TEMPLATE_INCONSISTENT;
    }

    rc = object_mgr_create_skel(tokdata, sess, pTemplate, ulCount, MODE_DERIVE,
                                CKO_SECRET_KEY, derived_keytype,
                                &derived_key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("Object Mgr create skeleton failed, rc=0x%lx.\n", rc);
        return rc;
    }

    rc = token_specific.t_ibm_ml_kem_derive(tokdata, sess, oid, mech,
                                            base_key_obj, base_key_class,
                                            base_key_type,
                                            derived_key_obj, derived_keytype,
                                            derived_keylen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Token specific ML-KEM derive failed.\n");
        goto end;
    }

    rc = object_mgr_create_final(tokdata, sess, derived_key_obj,
                                 derived_key_handle);
    if (rc != CKR_OK) {
        TRACE_ERROR("Object Mgr create final failed, rc=0x%lx.\n", rc);
        goto end;
    }

    INC_COUNTER(tokdata, sess, mech, base_key_obj, POLICY_STRENGTH_IDX_0);

    rc = CKR_OK;

end:
    if (rc != CKR_OK && derived_key_obj != NULL) {
        object_free(derived_key_obj);
        derived_key_handle = CK_INVALID_HANDLE;
    }

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

static CK_RV ibm_ml_dsa_pack_priv_key(TEMPLATE *templ,
                                      const struct pqc_oid *oid,
                                      CK_MECHANISM_TYPE mech,
                                      CK_BYTE *priv, CK_ULONG *priv_len)
{
    CK_ATTRIBUTE *rho = NULL, *seed = NULL;
    CK_ATTRIBUTE *tr = NULL, *s1 = NULL, *s2 = NULL;
    CK_ATTRIBUTE *t0 = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    UNUSED(mech);

    if (priv == NULL) {
        *priv_len = oid->len_info.ml_dsa.rho_len +
                    oid->len_info.ml_dsa.seed_len +
                    oid->len_info.ml_dsa.tr_len +
                    oid->len_info.ml_dsa.s1_len +
                    oid->len_info.ml_dsa.s2_len +
                    oid->len_info.ml_dsa.t0_len;
        return CKR_OK;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_ML_DSA_RHO,
                                          &rho);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_ML_DSA_RHO for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_ML_DSA_SEED,
                                          &seed);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_ML_DSA_SEED for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_ML_DSA_TR,
                                          &tr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_ML_DSA_TR for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_ML_DSA_S1,
                                          &s1);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_ML_DSA_S1 for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_ML_DSA_S2,
                                          &s2);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_ML_DSA_S2 for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_ML_DSA_T0,
                                          &t0);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_ML_DSA_T0 for the key.\n");
        return rc;
    }

    PACK_PART(rho, oid->len_info.ml_dsa.rho_len, priv, *priv_len, ofs);
    PACK_PART(seed, oid->len_info.ml_dsa.seed_len, priv, *priv_len, ofs);
    PACK_PART(tr, oid->len_info.ml_dsa.tr_len, priv, *priv_len, ofs);
    PACK_PART(s1, oid->len_info.ml_dsa.s1_len, priv, *priv_len, ofs);
    PACK_PART(s2, oid->len_info.ml_dsa.s2_len, priv, *priv_len, ofs);
    PACK_PART(t0, oid->len_info.ml_dsa.t0_len, priv, *priv_len, ofs);

    *priv_len = ofs;

    return CKR_OK;
}

static CK_RV ibm_ml_dsa_pack_pub_key(TEMPLATE *templ,
                                     const struct pqc_oid *oid,
                                     CK_MECHANISM_TYPE mech,
                                     CK_BYTE *pub, CK_ULONG *pub_len)
{
    CK_ATTRIBUTE *rho = NULL, *t1 = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    UNUSED(mech);

    if (pub == NULL) {
        *pub_len = oid->len_info.ml_dsa.rho_len +
                   oid->len_info.ml_dsa.t1_len;
        return CKR_OK;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_ML_DSA_RHO,
                                          &rho);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_ML_DSA_RHO for the key.\n");
        return rc;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_ML_DSA_T1,
                                          &t1);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_ML_DSA_T1 for the key.\n");
        return rc;
    }

    PACK_PART(rho, oid->len_info.ml_dsa.rho_len, pub, *pub_len, ofs);
    PACK_PART(t1, oid->len_info.ml_dsa.t1_len, pub, *pub_len, ofs);

    *pub_len = ofs;

    return CKR_OK;
}

static CK_RV ibm_ml_dsa_unpack_priv_key(CK_BYTE *priv, CK_ULONG priv_len,
                                        const struct pqc_oid *oid,
                                        CK_MECHANISM_TYPE mech,
                                        TEMPLATE *templ)
{
    CK_ATTRIBUTE *rho = NULL, *seed = NULL;
    CK_ATTRIBUTE *tr = NULL, *s1 = NULL, *s2 = NULL;
    CK_ATTRIBUTE *t0 = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    UNUSED(mech);

    UNPACK_PART(rho, CKA_IBM_ML_DSA_RHO, oid->len_info.ml_dsa.rho_len,
                priv, priv_len, ofs, rc, out);
    UNPACK_PART(seed, CKA_IBM_ML_DSA_SEED, oid->len_info.ml_dsa.seed_len,
                priv, priv_len, ofs, rc, out);
    UNPACK_PART(tr, CKA_IBM_ML_DSA_TR, oid->len_info.ml_dsa.tr_len,
                priv, priv_len, ofs, rc, out);
    UNPACK_PART(s1, CKA_IBM_ML_DSA_S1, oid->len_info.ml_dsa.s1_len,
                priv, priv_len, ofs, rc, out);
    UNPACK_PART(s2, CKA_IBM_ML_DSA_S2, oid->len_info.ml_dsa.s2_len,
                priv, priv_len, ofs, rc, out);
    UNPACK_PART(t0, CKA_IBM_ML_DSA_T0, oid->len_info.ml_dsa.t0_len,
                priv, priv_len, ofs, rc, out);

    rc = template_update_attribute(templ, rho);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update for CKA_IBM_ML_DSA_RHO failed\n");
        goto out;
    }
    rho = NULL;

    rc = template_update_attribute(templ, seed);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update for CKA_IBM_ML_DSA_SEED failed\n");
        goto out;
    }
    seed = NULL;

    rc = template_update_attribute(templ, tr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update for CKA_IBM_ML_DSA_TR failed\n");
        goto out;
    }
    tr = NULL;

    rc = template_update_attribute(templ, s1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update for CKA_IBM_ML_DSA_S1 failed\n");
        goto out;
    }
    s1 = NULL;

    rc = template_update_attribute(templ, s2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update for CKA_IBM_ML_DSA_S2 failed\n");
        goto out;
    }
    s2 = NULL;

    rc = template_update_attribute(templ, t0);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update for CKA_IBM_ML_DSA_T0 failed\n");
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

static CK_RV ibm_ml_dsa_unpack_pub_key(CK_BYTE *pub, CK_ULONG pub_len,
                                       const struct pqc_oid *oid,
                                       CK_MECHANISM_TYPE mech,
                                       TEMPLATE *templ)
{
    CK_ATTRIBUTE *rho = NULL, *t1 = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    UNUSED(mech);

    UNPACK_PART(rho, CKA_IBM_ML_DSA_RHO, oid->len_info.ml_dsa.rho_len,
                pub, pub_len, ofs, rc, out);
    UNPACK_PART(t1, CKA_IBM_ML_DSA_T1, oid->len_info.ml_dsa.t1_len,
                pub, pub_len, ofs, rc, out);

    rc = template_update_attribute(templ, rho);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update for CKA_IBM_ML_DSA_RHO failed\n");
        goto out;
    }
    rho = NULL;

    rc = template_update_attribute(templ, t1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update for CKA_IBM_ML_DSA_T1 failed\n");
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

static CK_RV ibm_ml_kem_pack_priv_key(TEMPLATE *templ,
                                      const struct pqc_oid *oid,
                                      CK_MECHANISM_TYPE mech,
                                      CK_BYTE *priv, CK_ULONG *priv_len)
{
    CK_ATTRIBUTE *sk = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    UNUSED(mech);

    if (priv == NULL) {
        *priv_len = oid->len_info.ml_kem.sk_len;
        return CKR_OK;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_ML_KEM_SK, &sk);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_ML_KEM_SK for the key.\n");
        return rc;
    }

    PACK_PART(sk, oid->len_info.ml_kem.sk_len, priv, *priv_len, ofs);

    *priv_len = ofs;

    return CKR_OK;
}

static CK_RV ibm_ml_kem_pack_pub_key(TEMPLATE *templ,
                                     const struct pqc_oid *oid,
                                     CK_MECHANISM_TYPE mech,
                                     CK_BYTE *pub, CK_ULONG *pub_len)
{
    CK_ATTRIBUTE *pk = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    UNUSED(mech);

    if (pub == NULL) {
        *pub_len = oid->len_info.ml_kem.pk_len;
        return CKR_OK;
    }

    rc = template_attribute_get_non_empty(templ, CKA_IBM_ML_KEM_PK, &pk);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_IBM_ML_KEM_PK for the key.\n");
        return rc;
    }

    PACK_PART(pk, oid->len_info.ml_kem.pk_len, pub, *pub_len, ofs);

    *pub_len = ofs;

    return CKR_OK;
}

static CK_RV ibm_ml_kem_unpack_priv_key(CK_BYTE *priv, CK_ULONG priv_len,
                                        const struct pqc_oid *oid,
                                        CK_MECHANISM_TYPE mech,
                                        TEMPLATE *templ)
{
    CK_ATTRIBUTE *sk = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    UNUSED(mech);

    UNPACK_PART(sk, CKA_IBM_ML_KEM_SK, oid->len_info.ml_kem.sk_len,
                priv, priv_len, ofs, rc, out);

    rc = template_update_attribute(templ, sk);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update for CKA_IBM_ML_KEM_SK failed\n");
        goto out;
    }
    sk = NULL;

out:
    if (sk != NULL)
        free(sk);

    return rc;
}

static CK_RV ibm_ml_kem_unpack_pub_key(CK_BYTE *pub, CK_ULONG pub_len,
                                       const struct pqc_oid *oid,
                                       CK_MECHANISM_TYPE mech,
                                       TEMPLATE *templ)
{
    CK_ATTRIBUTE *pk = NULL;
    CK_ULONG ofs = 0;
    CK_RV rc;

    UNUSED(mech);

    UNPACK_PART(pk, CKA_IBM_ML_KEM_PK, oid->len_info.ml_kem.pk_len,
                pub, pub_len, ofs, rc, out);

    rc = template_update_attribute(templ, pk);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Template update for CKA_IBM_ML_KEM_PK failed\n");
        goto out;
    }
    pk = NULL;

out:
    if (pk != NULL)
        free(pk);

    return rc;
}

#undef PACK_PART
#undef UNPACK_PART

CK_RV pqc_pack_priv_key(TEMPLATE *templ, const struct pqc_oid *oid,
                        CK_MECHANISM_TYPE mech, CK_BYTE *priv,
                        CK_ULONG *priv_len)
{
    switch(mech) {
    case CKM_IBM_DILITHIUM:
    case CKM_IBM_ML_DSA:
    case CKM_IBM_ML_DSA_KEY_PAIR_GEN:
        return ibm_ml_dsa_pack_priv_key(templ, oid, mech, priv, priv_len);
    case CKM_IBM_ML_KEM:
    case CKM_IBM_ML_KEM_KEY_PAIR_GEN:
    case CKM_IBM_ML_KEM_WITH_ECDH:
        return ibm_ml_kem_pack_priv_key(templ, oid, mech, priv, priv_len);
    default:
        return CKR_MECHANISM_INVALID;
    }
}

CK_RV pqc_pack_pub_key(TEMPLATE *templ, const struct pqc_oid *oid,
                       CK_MECHANISM_TYPE mech, CK_BYTE *pub,
                       CK_ULONG *pub_len)
{
    switch(mech) {
    case CKM_IBM_DILITHIUM:
    case CKM_IBM_ML_DSA:
    case CKM_IBM_ML_DSA_KEY_PAIR_GEN:
        return ibm_ml_dsa_pack_pub_key(templ, oid, mech, pub, pub_len);
    case CKM_IBM_ML_KEM:
    case CKM_IBM_ML_KEM_KEY_PAIR_GEN:
    case CKM_IBM_ML_KEM_WITH_ECDH:
        return ibm_ml_kem_pack_pub_key(templ, oid, mech, pub, pub_len);
    default:
        return CKR_MECHANISM_INVALID;
    }
}

CK_RV pqc_unpack_priv_key(CK_BYTE *priv, CK_ULONG priv_len,
                          const struct pqc_oid *oid,
                          CK_MECHANISM_TYPE mech, TEMPLATE *templ)
{
    switch(mech) {
    case CKM_IBM_DILITHIUM:
    case CKM_IBM_ML_DSA:
    case CKM_IBM_ML_DSA_KEY_PAIR_GEN:
        return ibm_ml_dsa_unpack_priv_key(priv, priv_len, oid, mech, templ);
    case CKM_IBM_ML_KEM:
    case CKM_IBM_ML_KEM_KEY_PAIR_GEN:
    case CKM_IBM_ML_KEM_WITH_ECDH:
        return ibm_ml_kem_unpack_priv_key(priv, priv_len, oid, mech, templ);
    default:
        return CKR_MECHANISM_INVALID;
    }
}

CK_RV pqc_unpack_pub_key(CK_BYTE *pub, CK_ULONG pub_len,
                         const struct pqc_oid *oid,
                         CK_MECHANISM_TYPE mech, TEMPLATE *templ)
{
    switch(mech) {
    case CKM_IBM_DILITHIUM:
    case CKM_IBM_ML_DSA:
    case CKM_IBM_ML_DSA_KEY_PAIR_GEN:
        return ibm_ml_dsa_unpack_pub_key(pub, pub_len, oid, mech, templ);
    case CKM_IBM_ML_KEM:
    case CKM_IBM_ML_KEM_KEY_PAIR_GEN:
    case CKM_IBM_ML_KEM_WITH_ECDH:
        return ibm_ml_kem_unpack_pub_key(pub, pub_len, oid, mech, templ);
    default:
        return CKR_MECHANISM_INVALID;
    }
}

CK_RV ibm_ml_dsa_dup_param(CK_VOID_PTR src, CK_VOID_PTR dst, CK_ULONG len)
{
    CK_IBM_SIGN_ADDITIONAL_CONTEXT *param_src = src;
    CK_IBM_SIGN_ADDITIONAL_CONTEXT *param_dst = dst;

    if (param_src == NULL || len == 0)
        return CKR_OK;

    if (len != sizeof(CK_IBM_SIGN_ADDITIONAL_CONTEXT))
        return CKR_MECHANISM_PARAM_INVALID;

    if(param_src->pContext == NULL || param_src->ulContextLen == 0)
        return CKR_OK;

    if (param_dst == NULL)
        return CKR_ARGUMENTS_BAD;

    param_dst->pContext = malloc(param_src->ulContextLen);
    if (param_dst->pContext == NULL) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    memcpy(param_dst->pContext, param_src->pContext, param_src->ulContextLen);
    param_dst->ulContextLen = param_src->ulContextLen;

    return CKR_OK;
}

CK_RV ibm_ml_dsa_free_param(CK_VOID_PTR p, CK_ULONG len)
{
    CK_IBM_SIGN_ADDITIONAL_CONTEXT *param = p;

    if (param == NULL || len == 0)
        return CKR_OK;

    if (len != sizeof(CK_IBM_SIGN_ADDITIONAL_CONTEXT))
        return CKR_MECHANISM_PARAM_INVALID;

    if (param->pContext != NULL)
        free(param->pContext);

    memset(param, 0, sizeof(*param));

    return CKR_OK;
}
