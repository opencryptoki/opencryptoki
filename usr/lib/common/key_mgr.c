/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/***************************************************************************
                          Change Log
                          ==========
       4/25/03    Kapil Sood (kapil@corrent.com)
                  Added DH key pair generation and DH shared key derivation
                  functions.



****************************************************************************/


// File:  key_mgr.c
//

#include <pthread.h>
#include <stdlib.h>

#include <string.h>             // for memcmp() et al

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "attributes.h"
#include "tok_spec_struct.h"
#include "trace.h"
#include "pqc_defs.h"

#include "../api/policy.h"
#include "../api/statistics.h"

#include <openssl/crypto.h>

static CK_BBOOL true = TRUE;

CK_RV key_mgr_apply_always_sensitive_never_extractable_attrs(
                                    STDLL_TokData_t *tokdata, OBJECT *key_obj)
{
    CK_BBOOL ck_true = TRUE;
    CK_ATTRIBUTE *new_attr = NULL;
    CK_BBOOL flag;
    CK_RV rc;

    UNUSED(tokdata);

    rc = template_attribute_get_bool(key_obj->template, CKA_SENSITIVE, &flag);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find CKA_SENSITIVE in key object template.\n");
        goto error;
    }

    rc = build_attribute(CKA_ALWAYS_SENSITIVE, &flag, sizeof(CK_BBOOL),
                         &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build attribute failed.\n");
        goto error;
    }
    rc = template_update_attribute(key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    new_attr = NULL;

    rc = template_attribute_get_bool(key_obj->template, CKA_EXTRACTABLE, &flag);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find CKA_EXTRACTABLE in key object template.\n");
        goto error;
    }

    rc = build_attribute(CKA_NEVER_EXTRACTABLE, &ck_true, sizeof(CK_BBOOL),
                         &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    if (flag == TRUE)
        *(CK_BBOOL *)new_attr->pValue = FALSE;

    rc = template_update_attribute(key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    new_attr = NULL;

error:
    if (new_attr != NULL)
        free(new_attr);

    return rc;
}

//
//
CK_RV key_mgr_generate_key(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           CK_MECHANISM *mech,
                           CK_ATTRIBUTE *pTemplate,
                           CK_ULONG ulCount, CK_OBJECT_HANDLE *handle)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *new_attr = NULL;
    CK_ULONG keyclass, subclass = 0;
    CK_RV rc;

    if (!sess || !mech || !handle) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (!pTemplate && (ulCount != 0)) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech, NULL,
                                          POLICY_CHECK_KEYGEN, sess);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Key generation mechanism not allowed\n");
        return rc;
    }

    // it's silly but Cryptoki allows the user to specify the CKA_CLASS
    // in the template.  so we have to iterate through the provided template
    // and make sure that if CKA_CLASS is CKO_SECRET_KEY, if it is present.
    //
    // it would have been more logical for Cryptoki to forbid specifying
    // the CKA_CLASS attribute when generating a key
    //
    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_CLASS,
                                     &keyclass);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && keyclass != CKO_SECRET_KEY) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        return CKR_TEMPLATE_INCONSISTENT;
    }

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_KEY_TYPE,
                                     &subclass);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    switch (mech->mechanism) {
    case CKM_DES_KEY_GEN:
        if (subclass != 0 && subclass != CKK_DES) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }

        subclass = CKK_DES;
        break;
    case CKM_DES3_KEY_GEN:
        if (subclass != 0 && subclass != CKK_DES3) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }

        subclass = CKK_DES3;
        break;
    case CKM_SSL3_PRE_MASTER_KEY_GEN:
        if (subclass != 0 && subclass != CKK_GENERIC_SECRET) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        if (mech->ulParameterLen != sizeof(CK_VERSION) ||
            mech->pParameter == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            return CKR_MECHANISM_PARAM_INVALID;
        }

        subclass = CKK_GENERIC_SECRET;
        break;
    case CKM_AES_KEY_GEN:
        if (subclass != 0 && subclass != CKK_AES) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }

        subclass = CKK_AES;
        break;
    case CKM_AES_XTS_KEY_GEN:
            if (subclass != 0 && subclass != CKK_AES_XTS) {
                TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
                return CKR_TEMPLATE_INCONSISTENT;
            }

            subclass = CKK_AES_XTS;
            break;
    case CKM_GENERIC_SECRET_KEY_GEN:
        if (subclass != 0 && subclass != CKK_GENERIC_SECRET) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }

        subclass = CKK_GENERIC_SECRET;
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }


    rc = object_mgr_create_skel(tokdata, sess,
                                pTemplate, ulCount,
                                MODE_KEYGEN,
                                CKO_SECRET_KEY, subclass, &key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_skel failed.\n");
        goto error;
    }
    // at this point, 'key_obj' should contain a skeleton key.  depending on
    // the key type, we may need to extract one or more attributes from
    // the object prior to generating the key data (ie. variable key length)
    //

    switch (mech->mechanism) {
    case CKM_DES_KEY_GEN:
        rc = ckm_des_key_gen(tokdata, key_obj->template);
        break;
    case CKM_DES3_KEY_GEN:
        rc = ckm_des3_key_gen(tokdata, key_obj->template);
        break;
    case CKM_SSL3_PRE_MASTER_KEY_GEN:
        rc = ckm_ssl3_pre_master_key_gen(tokdata, key_obj->template, mech);
        break;
    case CKM_AES_KEY_GEN:
        rc = ckm_aes_key_gen(tokdata, key_obj->template, FALSE);
        break;
    case CKM_AES_XTS_KEY_GEN:
        rc = ckm_aes_key_gen(tokdata, key_obj->template, TRUE);
        break;
    case CKM_GENERIC_SECRET_KEY_GEN:
        rc = ckm_generic_secret_key_gen(tokdata, key_obj->template);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

    if (rc != CKR_OK) {
        TRACE_ERROR("Key generation failed.\n");
        goto error;
    }
    // we can now set CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE
    // to their appropriate values.  this only applies to CKO_SECRET_KEY
    // and CKO_PRIVATE_KEY objects
    //
    rc = key_mgr_apply_always_sensitive_never_extractable_attrs(tokdata,
                                                                 key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s key_mgr_apply_always_sensitive_never_extractable_attrs "
                    "failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    /* add/update CKA_LOCAL with value true to the template */
    rc = build_attribute(CKA_LOCAL, &true, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    new_attr = NULL;

    /* add CKA_KEY_GEN_MECHANISM */
    rc = build_attribute(CKA_KEY_GEN_MECHANISM, (CK_BYTE *)&mech->mechanism,
                         sizeof(CK_MECHANISM_TYPE), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    new_attr = NULL;

    // at this point, the key should be fully constructed...assign
    // an object handle and store the key
    // Enforce policy
    rc = object_mgr_create_final(tokdata, sess, key_obj, handle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_final failed.\n");
        goto error;
    }

    if (rc == CKR_OK)
        INC_COUNTER(tokdata, sess, mech, key_obj, POLICY_STRENGTH_IDX_0);

    return rc;

error:
    if (key_obj)
        object_free(key_obj);
    if (new_attr != NULL)
        free(new_attr);

    *handle = 0;

    return rc;
}


//
//
CK_RV key_mgr_generate_key_pair(STDLL_TokData_t *tokdata,
                                SESSION *sess,
                                CK_MECHANISM *mech,
                                CK_ATTRIBUTE *publ_tmpl,
                                CK_ULONG publ_count,
                                CK_ATTRIBUTE *priv_tmpl,
                                CK_ULONG priv_count,
                                CK_OBJECT_HANDLE *publ_key_handle,
                                CK_OBJECT_HANDLE *priv_key_handle)
{
    OBJECT *publ_key_obj = NULL;
    OBJECT *priv_key_obj = NULL;
    CK_ATTRIBUTE *new_attr = NULL;
    CK_ULONG keyclass, subclass = 0;
    CK_BYTE *spki = NULL;
    CK_ULONG temp, spki_length = 0;
    CK_RV rc;

    if (!sess || !mech || !publ_key_handle || !priv_key_handle) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (!publ_tmpl && (publ_count != 0)) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (!priv_tmpl && (priv_count != 0)) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech, NULL,
                                          POLICY_CHECK_KEYGEN, sess);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: Keypair generation mechanism not allowed\n");
        return rc;
    }
    // it's silly but Cryptoki allows the user to specify the CKA_CLASS
    // in the template.  so we have to iterate through the provided template
    // and make sure that if CKA_CLASS is valid, if it is present.
    //
    // it would have been more logical for Cryptoki to forbid specifying
    // the CKA_CLASS attribute when generating a key
    //
    rc = get_ulong_attribute_by_type(publ_tmpl, publ_count, CKA_CLASS,
                                     &keyclass);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && keyclass != CKO_PUBLIC_KEY) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        return CKR_TEMPLATE_INCONSISTENT;
    }

    rc = get_ulong_attribute_by_type(publ_tmpl, publ_count, CKA_KEY_TYPE,
                                     &subclass);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    rc = get_ulong_attribute_by_type(priv_tmpl, priv_count, CKA_CLASS,
                                     &keyclass);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && keyclass != CKO_PRIVATE_KEY) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        return CKR_TEMPLATE_INCONSISTENT;
    }

    rc = get_ulong_attribute_by_type(priv_tmpl, priv_count, CKA_KEY_TYPE,
                                     &temp);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && temp != subclass) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        return CKR_TEMPLATE_INCONSISTENT;
    }

    switch (mech->mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        if (subclass != 0 && subclass != CKK_RSA) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }

        subclass = CKK_RSA;
        break;
    case CKM_EC_KEY_PAIR_GEN:
        if (subclass != 0 && subclass != CKK_EC) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }

        subclass = CKK_EC;
        break;
#if !(NODSA)
    case CKM_DSA_KEY_PAIR_GEN:
        if (subclass != 0 && subclass != CKK_DSA) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        subclass = CKK_DSA;
        break;
#endif
/* Begin code contributed by Corrent corp. */
#if !(NODH)
    case CKM_DH_PKCS_KEY_PAIR_GEN:
        if (subclass != 0 && subclass != CKK_DH) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        subclass = CKK_DH;
        break;
#endif
/* End  code contributed by Corrent corp. */
    case CKM_IBM_DILITHIUM:
        if (subclass != 0 && subclass != CKK_IBM_PQC_DILITHIUM) {
            TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
            return CKR_TEMPLATE_INCONSISTENT;
        }
        subclass = CKK_IBM_DILITHIUM;
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }


    rc = object_mgr_create_skel(tokdata, sess,
                                publ_tmpl, publ_count,
                                MODE_KEYGEN,
                                CKO_PUBLIC_KEY, subclass, &publ_key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_skel failed.\n");
        goto error;
    }
    rc = object_mgr_create_skel(tokdata, sess,
                                priv_tmpl, priv_count,
                                MODE_KEYGEN,
                                CKO_PRIVATE_KEY, subclass, &priv_key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_skel failed.\n");
        goto error;
    }
    // at this point, 'key_obj' should contain a skeleton key.  depending on
    // the key type, we may need to extract one or more attributes from
    // the object prior to generating the key data (ie. variable key length)
    //

    switch (mech->mechanism) {
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        rc = ckm_rsa_key_pair_gen(tokdata, publ_key_obj->template,
                                  priv_key_obj->template);
        break;
    case CKM_EC_KEY_PAIR_GEN:
        rc = ckm_ec_key_pair_gen(tokdata, publ_key_obj->template,
                                 priv_key_obj->template);
        break;
#if !(NODSA)
    case CKM_DSA_KEY_PAIR_GEN:
        rc = ckm_dsa_key_pair_gen(tokdata, publ_key_obj->template,
                                  priv_key_obj->template);
        break;
#endif

/* Begin code contributed by Corrent corp. */
#if !(NODH)
    case CKM_DH_PKCS_KEY_PAIR_GEN:
        rc = ckm_dh_pkcs_key_pair_gen(tokdata, publ_key_obj->template,
                                      priv_key_obj->template);
        break;
#endif
/* End code contributed by Corrent corp. */
    case CKM_IBM_DILITHIUM:
        rc = ckm_ibm_dilithium_key_pair_gen(tokdata, publ_key_obj->template,
                                            priv_key_obj->template);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        break;
    }

    if (rc != CKR_OK) {
        TRACE_DEVEL("Key Generation failed.\n");
        goto error;
    }
    // we can now set CKA_ALWAYS_SENSITIVE and CKA_NEVER_EXTRACTABLE
    // to their appropriate values.  this only applies to CKO_SECRET_KEY
    // and CKO_PRIVATE_KEY objects
    //
    rc = key_mgr_apply_always_sensitive_never_extractable_attrs(tokdata,
                                                                priv_key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s key_mgr_apply_always_sensitive_never_extractable_attrs "
                    "failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    /* add/update CKA_LOCAL with value true to the keypair templates */
    rc = build_attribute(CKA_LOCAL, &true, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(publ_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    new_attr = NULL;

    rc = build_attribute(CKA_LOCAL, &true, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    new_attr = NULL;

    /* add CKA_KEY_GEN_MECHANISM */
    rc = build_attribute(CKA_KEY_GEN_MECHANISM, (CK_BYTE *)&mech->mechanism,
                         sizeof(CK_MECHANISM_TYPE), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(publ_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    new_attr = NULL;

    rc = build_attribute(CKA_KEY_GEN_MECHANISM, (CK_BYTE *)&mech->mechanism,
                         sizeof(CK_MECHANISM_TYPE), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    new_attr = NULL;

    /* Extract the SPKI and add CKA_PUBLIC_KEY_INFO to both keys */
    rc = publ_key_get_spki(publ_key_obj->template, subclass, FALSE,
                           &spki, &spki_length);
    if (rc != CKR_OK) {
        TRACE_DEVEL("publ_key_get_spki failed\n");
        goto error;
    }
    rc = build_attribute(CKA_PUBLIC_KEY_INFO, spki, spki_length, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(publ_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    new_attr = NULL;

    rc = build_attribute(CKA_PUBLIC_KEY_INFO, spki, spki_length, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto error;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute failed.\n");
        goto error;
    }
    new_attr = NULL;
    free(spki);
    spki = NULL;

    // at this point, the keys should be fully constructed...assign
    // object handles and store the keys
    // Enforce policy
    rc = object_mgr_create_final(tokdata, sess, publ_key_obj, publ_key_handle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_final failed.\n");
        goto error;
    }
    rc = object_mgr_create_final(tokdata, sess, priv_key_obj, priv_key_handle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_final failed.\n");
        object_mgr_destroy_object(tokdata, sess, *publ_key_handle);
        publ_key_obj = NULL;
        goto error;
    }

    if (rc == CKR_OK)
        INC_COUNTER(tokdata, sess, mech, priv_key_obj, POLICY_STRENGTH_IDX_0);

    return rc;

error:
    if (publ_key_obj)
        object_free(publ_key_obj);
    if (priv_key_obj)
        object_free(priv_key_obj);
    if (spki != NULL)
        free(spki);
    if (new_attr != NULL)
        free(new_attr);

    *publ_key_handle = 0;
    *priv_key_handle = 0;

    return rc;
}


//
//
CK_RV key_mgr_wrap_key(STDLL_TokData_t *tokdata,
                       SESSION *sess,
                       CK_BBOOL length_only,
                       CK_MECHANISM *mech,
                       CK_OBJECT_HANDLE h_wrapping_key,
                       CK_OBJECT_HANDLE h_key,
                       CK_BYTE *wrapped_key, CK_ULONG *wrapped_key_len)
{
    ENCR_DECR_CONTEXT *ctx = NULL;
    OBJECT *wrapping_key_obj = NULL;
    OBJECT *key_obj = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE keytype;
    CK_BBOOL flag, not_opaque = FALSE;
    CK_RV rc;

    if (!sess || !wrapped_key_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_find_in_map1(tokdata, h_wrapping_key, &wrapping_key_obj,
                                 READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_WRAPPING_KEY_HANDLE_INVALID));
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            rc = CKR_WRAPPING_KEY_HANDLE_INVALID;
        goto done;
    }

    rc = object_mgr_find_in_map1(tokdata, h_key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &wrapping_key_obj->strength,
                                          POLICY_CHECK_WRAP, sess);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: key wrap\n");
        goto done;
    }
    rc = tokdata->policy->is_key_allowed(tokdata->policy, &key_obj->strength,
                                         sess);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: key wrap\n");
        goto done;
    }
    if (!key_object_is_mechanism_allowed(wrapping_key_obj->template,
                                         mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    if (!key_object_wrap_template_matches(wrapping_key_obj->template,
                                          key_obj->template)) {
        TRACE_ERROR("Wrap template does not match.\n");
        rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    // is the key-to-be-wrapped EXTRACTABLE?
    //
    rc = template_attribute_get_bool(key_obj->template, CKA_EXTRACTABLE, &flag);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find CKA_EXTRACTABLE in key template.\n");
        // could happen if user tries to wrap a public key
        rc = CKR_KEY_NOT_WRAPPABLE;
        goto done;
    }

    if (flag == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_UNEXTRACTABLE));
        rc = CKR_KEY_UNEXTRACTABLE;
        goto done;
    }

    rc = template_attribute_get_bool(wrapping_key_obj->template, CKA_WRAP,
                                     &flag);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_WRAP for the wrapping key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    if (flag == FALSE) {
        TRACE_ERROR("CKA_WRAP is set to FALSE.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /* Is a wrapping key with CKA_TRUSTED = CK_TRUE required? */
    rc = template_attribute_get_bool(key_obj->template, CKA_WRAP_WITH_TRUSTED,
                                     &flag);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        goto done;
    }
    if (rc == CKR_OK && flag == TRUE) {
        rc = template_attribute_get_bool(wrapping_key_obj->template,
                                        CKA_TRUSTED, &flag);
        if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
            TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
            goto done;
        }
         if (rc != CKR_OK || flag == FALSE) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_NOT_WRAPPABLE));
            rc = CKR_KEY_NOT_WRAPPABLE;
            goto done;
        }
    }

    // what kind of key are we trying to wrap?  make sure the mechanism is
    // allowed to wrap this kind of key
    //
    rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        goto done;
    }

    // pkcs11v2-20rc3, page 178
    // C_WrapKey can be used in following situations:
    // - To wrap any secret key with a public key that supports encryption
    // and decryption.
    // - To wrap any secret key with any other secret key. Consideration
    // must be given to key size and mechanism strength or the token may
    // not allow the operation.
    // - To wrap a private key with any secret key.
    //
    //  These can be deduced to:
    //  A public key or a secret key can be used to wrap a secret key.
    //  A secret key can be used to wrap a private key.

    switch (mech->mechanism) {
    case CKM_DES_CBC:
    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
    case CKM_AES_CTR:
    case CKM_DES_CBC_PAD:
    case CKM_DES3_CBC_PAD:
    case CKM_AES_CBC_PAD:
    case CKM_AES_OFB:
    case CKM_AES_CFB8:
    case CKM_AES_CFB64:
    case CKM_AES_CFB128:
    case CKM_AES_XTS:
        if ((class != CKO_SECRET_KEY) && (class != CKO_PRIVATE_KEY)) {
            TRACE_ERROR
                ("Specified mechanism only wraps secret & private keys.\n");
            rc = CKR_KEY_NOT_WRAPPABLE;
            goto done;
        }
        break;
    case CKM_DES_ECB:
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_RSA_PKCS_OAEP:
    case CKM_RSA_PKCS:
    case CKM_RSA_X_509:
        if (class != CKO_SECRET_KEY) {
            TRACE_ERROR("Specified mechanism only wraps secret keys.\n");
            rc = CKR_KEY_NOT_WRAPPABLE;
            goto done;
        }
        break;
    default:
        TRACE_ERROR("The mechanism does not support wrapping keys.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    if (token_specific.t_key_wrap == NULL && token_specific.secure_key_token) {
        TRACE_ERROR("Need a token specific wrap for a secure key token\n");
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        goto done;
    }

    if (token_specific.t_key_wrap != NULL) {
        rc = token_specific.t_key_wrap(tokdata, sess, mech, length_only,
                                       wrapping_key_obj, key_obj,
                                       wrapped_key, wrapped_key_len,
                                       &not_opaque);
        if (rc != CKR_OK) {
            TRACE_ERROR("token specific wrap function failed\n");
            goto done;
        }
        if (rc == CKR_OK && not_opaque == FALSE)
            goto done;
    }

    // extract the secret data to be wrapped
    //
    rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                      &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
        goto done;
    }

    switch (keytype) {
    case CKK_DES:
        rc = des_wrap_get_data(key_obj->template, length_only, &data,
                               &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("des_wrap_get_data failed.\n");
            goto done;
        }
        break;
    case CKK_DES3:
        rc = des3_wrap_get_data(key_obj->template, length_only, &data,
                                &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("des3_wrap_get_data failed.\n");
            goto done;
        }
        break;
    case CKK_RSA:
        rc = rsa_priv_wrap_get_data(key_obj->template, length_only, &data,
                                    &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("rsa_priv_wrap_get_data failed.\n");
            goto done;
        }
        break;
#if !(NODSA)
    case CKK_DSA:
        rc = dsa_priv_wrap_get_data(key_obj->template, length_only, &data,
                                    &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("dsa_priv_wrap_get_data failed.\n");
            goto done;
        }
        break;
#endif
#if !(NODH)
    case CKK_DH:
        rc = dh_priv_wrap_get_data(key_obj->template, length_only, &data,
                                   &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("dh_priv_wrap_get_data failed.\n");
            goto done;
        }
        break;
#endif
    case CKK_GENERIC_SECRET:
        rc = generic_secret_wrap_get_data(key_obj->template, length_only,
                                          &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("generic_secret_wrap_get_data failed.\n");
            goto done;
        }
        break;
    case CKK_AES:
    case CKK_AES_XTS:
        rc = aes_wrap_get_data(key_obj->template, length_only, &data,
                               &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("aes_wrap_get_data failed.\n");
            goto done;
        }
        break;
    case CKK_EC:
        rc = ecdsa_priv_wrap_get_data(key_obj->template, length_only, &data,
                                      &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ecdsa_priv_wrap_get_data failed.\n");
            goto done;
        }
        break;
    case CKK_IBM_PQC_DILITHIUM:
        rc = ibm_dilithium_priv_wrap_get_data(key_obj->template, length_only,
                                              &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ibm_dilithium_priv_wrap_get_data failed.\n");
            goto done;
        }
        break;
    case CKK_IBM_PQC_KYBER:
        rc = ibm_kyber_priv_wrap_get_data(key_obj->template, length_only,
                                          &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ibm_kyber_priv_wrap_get_data failed.\n");
            goto done;
        }
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_NOT_WRAPPABLE));
        rc = CKR_KEY_NOT_WRAPPABLE;
        goto done;
    }

    // we might need to format the wrapped data based on the mechanism
    //
    switch (mech->mechanism) {
    case CKM_DES_ECB:
    case CKM_DES_CBC:
    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
        rc = ckm_des_wrap_format(tokdata, length_only, &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ckm_des_wrap_format failed.\n");
            if (data) {
                OPENSSL_cleanse(data, data_len);
                free(data);
            }
            goto done;
        }
        break;
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CTR:
    case CKM_AES_OFB:
    case CKM_AES_CFB8:
    case CKM_AES_CFB64:
    case CKM_AES_CFB128:
        rc = ckm_aes_wrap_format(tokdata, length_only, &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("ckm_aes_wrap_format failed.\n");
            if (data) {
                OPENSSL_cleanse(data, data_len);
                free(data);
            }
            goto done;
        }
        break;
    case CKM_DES_CBC_PAD:
    case CKM_DES3_CBC_PAD:
    case CKM_AES_CBC_PAD:
        // these mechanisms pad themselves
        //
        break;
    case CKM_RSA_PKCS_OAEP:
    case CKM_RSA_PKCS:
    case CKM_RSA_X_509:
    case CKM_AES_XTS:
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        if (data) {
            OPENSSL_cleanse(data, data_len);
            free(data);
        }
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    ctx = (ENCR_DECR_CONTEXT *) malloc(sizeof(ENCR_DECR_CONTEXT));
    if (!ctx) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        if (data) {
            OPENSSL_cleanse(data, data_len);
            free(data);
        }
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    memset(ctx, 0x0, sizeof(ENCR_DECR_CONTEXT));

    // prepare to do the encryption
    //
    /* Policy already checked */
    rc = encr_mgr_init(tokdata, sess, ctx, OP_WRAP, mech, h_wrapping_key,
                       FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("encr_mgr_init failed.\n");
        free(ctx);
        if (data) {
            OPENSSL_cleanse(data, data_len);
            free(data);
        }
        goto done;
    }
    // do the encryption and clean up.  at this point, 'value' may or may not
    // be NULL depending on 'length_only'
    //
    rc = encr_mgr_encrypt(tokdata, sess, length_only,
                          ctx, data, data_len, wrapped_key, wrapped_key_len);
    if (data != NULL) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    encr_mgr_cleanup(tokdata, sess, ctx);
    free(ctx);

done:
    if (rc == CKR_OK)
        INC_COUNTER(tokdata, sess, mech, wrapping_key_obj,
                    POLICY_STRENGTH_IDX_0);

    if (wrapping_key_obj != NULL) {
        object_put(tokdata, wrapping_key_obj, TRUE);
        wrapping_key_obj = NULL;
    }
    if (key_obj != NULL) {
        object_put(tokdata, key_obj, TRUE);
        key_obj = NULL;
    }

    return rc;
}


//
//
CK_RV key_mgr_unwrap_key(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_MECHANISM *mech,
                         CK_ATTRIBUTE *attributes,
                         CK_ULONG attrib_count,
                         CK_BYTE *wrapped_key,
                         CK_ULONG wrapped_key_len,
                         CK_OBJECT_HANDLE h_unwrapping_key,
                         CK_OBJECT_HANDLE *h_unwrapped_key)
{
    ENCR_DECR_CONTEXT *ctx = NULL;
    OBJECT *key_obj = NULL, *unwrapping_key_obj = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len, value_len = 0;
    CK_ULONG keyclass = 0, keytype = 0, priv_keytype = 0;
    CK_BBOOL fromend, not_opaque = FALSE, flag;
    CK_ATTRIBUTE *new_attrs = NULL;
    CK_ULONG new_attr_count = 0;
    CK_RV rc;

    if (!sess || !wrapped_key || !h_unwrapped_key) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_find_in_map1(tokdata, h_unwrapping_key, &unwrapping_key_obj,
                                 READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            rc = CKR_UNWRAPPING_KEY_HANDLE_INVALID;
        goto done;
    }

    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &unwrapping_key_obj->strength,
                                          POLICY_CHECK_UNWRAP, sess);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: key unwrap\n");
        goto done;
    }
    if (!key_object_is_mechanism_allowed(unwrapping_key_obj->template,
                                         mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = template_attribute_get_bool(unwrapping_key_obj->template, CKA_UNWRAP,
                                     &flag);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_UNWRAP for the key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    if (flag == FALSE) {
        TRACE_ERROR("CKA_UNWRAP is set to FALSE.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /*
     * pkcs11v2-20
     * C_WrapKey can be used in following situations:
     * - To wrap any secret key with a public key that supports encryption
     *   and decryption.
     * - To wrap any secret key with any other secret key. Consideration
     *    must be given to key size and mechanism strength or the token may
     *    not allow the operation.
     * - To wrap a private key with any secret key.
     *
     * extract key type and key class from the passed in attributes
     */
    rc = get_ulong_attribute_by_type(attributes, attrib_count, CKA_CLASS,
                                     &keyclass);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        goto done;
    }

    rc = get_ulong_attribute_by_type(attributes, attrib_count, CKA_KEY_TYPE,
                                     &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
        goto done;
    }

    switch (mech->mechanism) {
    case CKM_DES_ECB:
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_RSA_PKCS_OAEP:
    case CKM_RSA_PKCS:
    case CKM_RSA_X_509:
        if (keyclass != CKO_SECRET_KEY) {
            TRACE_ERROR("The specified mechanism unwraps secret keys only.\n");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }
        break;
    case CKM_DES_CBC:
    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
    case CKM_AES_CTR:
    case CKM_AES_OFB:
    case CKM_AES_CFB8:
    case CKM_AES_CFB64:
    case CKM_AES_CFB128:
    case CKM_DES_CBC_PAD:
    case CKM_DES3_CBC_PAD:
    case CKM_AES_CBC_PAD:
    case CKM_AES_XTS:
        if ((keyclass != CKO_SECRET_KEY) && (keyclass != CKO_PRIVATE_KEY)) {
            TRACE_ERROR("Specified mech unwraps secret & private keys only.\n");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }
        break;
    default:
        TRACE_ERROR("The specified mechanism cannot unwrap keys.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = key_object_apply_template_attr(unwrapping_key_obj->template,
                                        CKA_UNWRAP_TEMPLATE,
                                        attributes, attrib_count,
                                        &new_attrs, &new_attr_count);
    if (rc != CKR_OK) {
        TRACE_DEVEL("key_object_apply_template_attr failed.\n");
        goto done;
    }

    rc = get_ulong_attribute_by_type(new_attrs, new_attr_count, CKA_VALUE_LEN,
                                     &value_len);
    if (rc == CKR_OK) {
        /*
         * Only some wrapping mechanisms allow CKA_VALUE_LEN to be specified
         * in the unwrapping template for certain key types.
         */
        switch (mech->mechanism) {
        case CKM_RSA_X_509:
        case CKM_DES_ECB:
        case CKM_AES_ECB:
        case CKM_AES_CBC:
        case CKM_DES_CBC:
        case CKM_DES3_ECB:
        case CKM_DES3_CBC:
        case CKM_AES_CTR:
        case CKM_AES_OFB:
        case CKM_AES_CFB8:
        case CKM_AES_CFB64:
        case CKM_AES_CFB128:
        case CKM_AES_XTS:
            if (keytype != CKK_AES && keytype != CKK_AES_XTS &&
                keytype != CKK_GENERIC_SECRET) {
                TRACE_ERROR("The key type does not allow CKA_VALUE_LEN to be "
                            "specified in the unwrapping template.\n");
                rc = CKR_TEMPLATE_INCONSISTENT;
                goto done;
            }
            break;
        default:
            TRACE_ERROR("The specified mechanism does not allow CKA_VALUE_LEN "
                        "to be specified in the unwrapping template.\n");
            rc = CKR_TEMPLATE_INCONSISTENT;
            goto done;
        }
    }

    rc = object_mgr_create_skel(tokdata, sess, new_attrs, new_attr_count,
                                MODE_UNWRAP, keyclass, keytype, &key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_skel failed.\n");
        goto done;
    }

    if (token_specific.t_key_unwrap == NULL &&
        token_specific.secure_key_token) {
        TRACE_ERROR("Need a token specific unwrap for a secure key token\n");
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        goto done;
    }

    if (token_specific.t_key_unwrap != NULL) {
        rc = token_specific.t_key_unwrap(tokdata, sess, mech,
                                         wrapped_key, wrapped_key_len,
                                         unwrapping_key_obj, key_obj,
                                         &not_opaque);
        if (rc != CKR_OK) {
            TRACE_ERROR("token specific unwrap function failed\n");
            goto done;
        }
        if (rc == CKR_OK && not_opaque == FALSE)
            goto final;
    }

    // looks okay... do the decryption
    ctx = (ENCR_DECR_CONTEXT *) malloc(sizeof(ENCR_DECR_CONTEXT));
    if (!ctx) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    memset(ctx, 0x0, sizeof(ENCR_DECR_CONTEXT));

    /* Policy already checked */
    rc = decr_mgr_init(tokdata, sess, ctx, OP_UNWRAP, mech, h_unwrapping_key,
                       FALSE);
    if (rc != CKR_OK)
        goto done;

    rc = decr_mgr_decrypt(tokdata, sess,
                          TRUE,
                          ctx, wrapped_key, wrapped_key_len, data, &data_len);
    if (rc != CKR_OK) {
        if (rc == CKR_ENCRYPTED_DATA_LEN_RANGE)
            rc = CKR_WRAPPED_KEY_LEN_RANGE;
        TRACE_DEVEL("decr_mgr_decrypt failed.\n");
        goto done;
    }
    data = (CK_BYTE *) malloc(data_len);
    if (!data) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    rc = decr_mgr_decrypt(tokdata, sess,
                          FALSE,
                          ctx, wrapped_key, wrapped_key_len, data, &data_len);

    decr_mgr_cleanup(tokdata, sess, ctx);
    free(ctx);
    ctx = NULL;

    if (rc != CKR_OK) {
        if (rc == CKR_ENCRYPTED_DATA_LEN_RANGE)
            rc = CKR_WRAPPED_KEY_LEN_RANGE;
        TRACE_DEVEL("decr_mgr_decrypt failed.\n");
        goto done;
    }
    // if we use X.509, the data will be padded from the front with zeros.
    // PKCS #11 specifies that for this mechanism, CK_VALUE is to be read
    // from the end of the data.
    //
    // Note: the PKCS #11 reference implementation gets this wrong.
    //
    if (mech->mechanism == CKM_RSA_X_509)
        fromend = TRUE;
    else
        fromend = FALSE;

    // extract the key type from the PrivateKeyInfo::AlgorithmIndicator
    if (keyclass == CKO_PRIVATE_KEY) {
        rc = key_mgr_get_private_key_type(data, data_len, &priv_keytype);
        if (rc != CKR_OK) {
            TRACE_DEVEL("key_mgr_get_private_key_type failed.\n");
            goto done;
        }

        if (priv_keytype != keytype) {
            rc = CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
            TRACE_DEVEL("keytype in template (%lu) does not match the unwrapped"
                        " key (%lu).\n", keytype, priv_keytype);
            goto done;
        }
    }

    // at this point, 'key_obj' should contain a skeleton key.  depending on
    // the key type.  we're now ready to plug in the decrypted key data.
    // in some cases, the data will be BER-encoded so we'll need to decode it.
    //
    // this routine also ensires that CKA_EXTRACTABLE == FALSE,
    // CKA_ALWAYS_SENSITIVE == FALSE and CKA_LOCAL == FALSE
    //
    switch (keyclass) {
    case CKO_SECRET_KEY:
        rc = secret_key_unwrap(tokdata, key_obj->template, keytype, data,
                               data_len, fromend);
        break;
    case CKO_PRIVATE_KEY:
        rc = priv_key_unwrap(key_obj->template, keytype, data, data_len);
        break;
    default:
        rc = CKR_WRAPPED_KEY_INVALID;
        break;
    }

    if (rc != CKR_OK) {
        TRACE_DEVEL("key_unwrap failed.\n");
        goto done;
    }

final:
    // at this point, the key should be fully constructed...assign
    // an object handle and store the key
    //
    rc = object_mgr_create_final(tokdata, sess, key_obj, h_unwrapped_key);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_final failed.\n");
        goto done;
    }

done:
    if (rc == CKR_OK)
        INC_COUNTER(tokdata, sess, mech, unwrapping_key_obj,
                    POLICY_STRENGTH_IDX_0);

    if (rc != CKR_OK && key_obj)
        object_free(key_obj);
    if (unwrapping_key_obj != NULL) {
        object_put(tokdata, unwrapping_key_obj, TRUE);
        unwrapping_key_obj = NULL;
    }
    if (new_attrs != NULL)
        cleanse_and_free_attribute_array(new_attrs, new_attr_count);
    if (data) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    if (ctx != NULL) {
        decr_mgr_cleanup(tokdata, sess, ctx);
        free(ctx);
    }

    return rc;
}


CK_RV key_mgr_get_private_key_type(CK_BYTE *keydata,
                                   CK_ULONG keylen, CK_KEY_TYPE *keytype)
{
    CK_BYTE *alg = NULL;
    CK_BYTE *priv_key = NULL;
    CK_ULONG alg_len, i;
    CK_RV rc;

    rc = ber_decode_PrivateKeyInfo(keydata, keylen, &alg, &alg_len, &priv_key);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_decode_PrivateKeyInfo failed.\n");
        return rc;
    }
    // check the entire AlgorithmIdentifier for RSA
    //
    if (alg_len >= ber_rsaEncryptionLen) {
        if (memcmp(alg, ber_rsaEncryption, ber_rsaEncryptionLen) == 0) {
            *keytype = CKK_RSA;
            return CKR_OK;
        }
    }
    // Check only the OBJECT IDENTIFIER for DSA
    //
    if (alg_len >= ber_idDSALen) {
        if (memcmp(alg, ber_idDSA, ber_idDSALen) == 0) {
            *keytype = CKK_DSA;
            return CKR_OK;
        }
    }
    // Check only the OBJECT IDENTIFIER for EC
    //
    if (alg_len >= der_AlgIdECBaseLen) {
        if (memcmp(alg, ber_idEC, ber_idECLen) == 0) {
            *keytype = CKK_EC;
            return CKR_OK;
        }
    }
    // Check only the OBJECT IDENTIFIER for DH
    //
    if (alg_len >= ber_idDHLen) {
        if (memcmp(alg, ber_idDH, ber_idDHLen) == 0) {
            *keytype = CKK_DH;
            return CKR_OK;
        }
    }
    // Check only the OBJECT IDENTIFIERs for DILITHIUM
    //
    for (i = 0; dilithium_oids[i].oid != NULL; i++) {
        if (alg_len == dilithium_oids[i].oid_len + ber_NULLLen &&
            memcmp(alg, dilithium_oids[i].oid,
                   dilithium_oids[i].oid_len) == 0 &&
            memcmp(alg + dilithium_oids[i].oid_len,
                   ber_NULL, ber_NULLLen) == 0) {
            *keytype = CKK_IBM_PQC_DILITHIUM;
            return CKR_OK;
        }
    }
    // Check only the OBJECT IDENTIFIERs for KYBER
    //
    for (i = 0; kyber_oids[i].oid != NULL; i++) {
        if (alg_len == kyber_oids[i].oid_len + ber_NULLLen &&
            memcmp(alg, kyber_oids[i].oid, kyber_oids[i].oid_len) == 0 &&
            memcmp(alg + kyber_oids[i].oid_len, ber_NULL, ber_NULLLen) == 0) {
            *keytype = CKK_IBM_PQC_KYBER;
            return CKR_OK;
        }
    }

    TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
    return CKR_TEMPLATE_INCOMPLETE;
}


//
//
CK_RV key_mgr_derive_key(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_MECHANISM *mech,
                         CK_OBJECT_HANDLE base_key,
                         CK_OBJECT_HANDLE *derived_key,
                         CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount)
{
    OBJECT *base_key_obj = NULL;
    CK_ATTRIBUTE *new_attrs = NULL;
    CK_ULONG new_attr_count = 0;
    CK_BBOOL flag;
    CK_RV rc;

    if (!sess || !mech) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (!pTemplate && (ulCount != 0)) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_find_in_map1(tokdata, base_key, &base_key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                          &base_key_obj->strength,
                                          POLICY_CHECK_DERIVE, sess);
    if (rc != CKR_OK) {
        TRACE_ERROR("POLICY VIOLATION: derive key\n");
        goto done;
    }

    if (!key_object_is_mechanism_allowed(base_key_obj->template,
                                         mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = template_attribute_get_bool(base_key_obj->template, CKA_DERIVE, &flag);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_DERIVE for the base key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    if (flag == FALSE) {
        TRACE_ERROR("CKA_DERIVE is set to FALSE.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    rc = key_object_apply_template_attr(base_key_obj->template,
                                        CKA_DERIVE_TEMPLATE,
                                        pTemplate, ulCount,
                                        &new_attrs, &new_attr_count);
    if (rc != CKR_OK) {
        TRACE_DEVEL("key_object_apply_template_attr failed.\n");
        goto done;
    }

    switch (mech->mechanism) {
    case CKM_SSL3_MASTER_KEY_DERIVE:
        if (!derived_key) {
            TRACE_ERROR("%s received bad argument(s)\n", __func__);
            rc = CKR_FUNCTION_FAILED;
            break;
        }
        rc = ssl3_master_key_derive(tokdata, sess, mech, base_key_obj,
                                    new_attrs, new_attr_count, derived_key);
        break;
    case CKM_SSL3_KEY_AND_MAC_DERIVE:
        rc = ssl3_key_and_mac_derive(tokdata, sess, mech, base_key_obj,
                                     new_attrs, new_attr_count);
        break;
/* Begin code contributed by Corrent corp. */
#ifndef NODH
    case CKM_DH_PKCS_DERIVE:
        if (!derived_key) {
            TRACE_ERROR("%s received bad argument(s)\n", __func__);
            rc = CKR_FUNCTION_FAILED;
            break;
        }
        rc = dh_pkcs_derive(tokdata, sess, mech, base_key_obj,
                            new_attrs, new_attr_count, derived_key);
        break;
#endif
/* End code contributed by Corrent corp. */
    case CKM_ECDH1_DERIVE:
        if (!derived_key) {
            TRACE_ERROR("%s received bad argument(s)\n", __func__);
            rc = CKR_FUNCTION_FAILED;
            break;
        }
        rc = ecdh_pkcs_derive(tokdata, sess, mech, base_key_obj, new_attrs,
                              new_attr_count, derived_key);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        break;
    }

done:
    if (new_attrs != NULL)
        cleanse_and_free_attribute_array(new_attrs, new_attr_count);
    if (base_key_obj != NULL) {
        object_put(tokdata, base_key_obj, TRUE);
        base_key_obj = NULL;
    }

    return rc;
}
