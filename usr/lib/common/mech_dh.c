/*
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/************************************************************************
*                                                                       *
*      Copyright:       Corrent Corporation (c) 2000-2003               *
*                                                                       *
*      Filename:        mech_dh.c                                       *
*      Created By:      Kapil Sood                                      *
*      Created On:      Jan 18, 2003                                    *
*      Description:     This is the file implementing Diffie-Hellman    *
*                       key pair generation and shared key derivation   *
*                       operations.                                     *
*                                                                       *
************************************************************************/

// File:  mech_dh.c
//
// Mechanisms for DH
//
// Routines contained within:

#include <pthread.h>
#include <string.h>             // for memcmp() et al
#include <stdlib.h>
#include <sys/syslog.h>
#include <stdio.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "attributes.h"
#include "tok_spec_struct.h"
#include "trace.h"
#include "p11util.h"

#ifndef NODH

static CK_ULONG keylen_from_keytype(CK_ULONG keytype)
{
    switch (keytype) {
    case CKK_DES:
        return 8;
    case CKK_DES2:
        return 16;
    case CKK_DES3:
        return 24;
        /* for all other keytypes CKA_VALUE_LEN must be specified */
    default:
        return 0;
    }
}

//
//
CK_RV dh_pkcs_derive(STDLL_TokData_t *tokdata,
                     SESSION *sess,
                     CK_MECHANISM *mech,
                     OBJECT *base_key_obj,
                     CK_ATTRIBUTE *pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE *handle,
                     CK_BBOOL count_statistic)
{
    CK_RV rc;
    CK_ULONG keyclass = 0, keytype = 0;
    CK_ATTRIBUTE *new_attr;
    CK_ULONG value_len = 0, secret_len;
    OBJECT *temp_obj = NULL;

    CK_BYTE secret_key_value[256];
    CK_ULONG secret_key_value_len = 256;

    // Prelim checking of sess, mech, pTemplate, and ulCount was
    // done in the calling function (key_mgr_derive_key).

    // Perform DH checking of parameters
    // Check the existance of the public-value in mechanism
    if (mech->pParameter == NULL || mech->ulParameterLen == 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return (CKR_MECHANISM_PARAM_INVALID);
    }
    // Check valid object handle pointer of derived key
    if (handle == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        return CKR_KEY_HANDLE_INVALID;
    }
    // Extract the object class and keytype from the supplied template.
    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_CLASS,
                                     &keyclass);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && keyclass != CKO_SECRET_KEY) {
        TRACE_ERROR("This operation requires a secret key.\n");
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_KEY_TYPE,
                                     &keytype);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    // Extract public-key from mechanism parameters. base-key contains the
    // private key, prime, and base. The return value will be in the handle.

    rc = ckm_dh_pkcs_derive(tokdata, sess,
                            mech->pParameter, mech->ulParameterLen,
                            base_key_obj, secret_key_value, &secret_key_value_len,
                            mech, count_statistic);
    if (rc != CKR_OK)
        return rc;

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_VALUE_LEN,
                                     &value_len);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    secret_len = keylen_from_keytype(keytype);
    if (secret_len == 0)
        secret_len = value_len;
    if (secret_len == 0) {
        /* Neither CKA_VALUE_LEN nor predefined length by key type */
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        return CKR_TEMPLATE_INCONSISTENT;
    }
    if (secret_len > secret_key_value_len) {
        /* Requested key size can not be derived */
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        return CKR_KEY_SIZE_RANGE;
    }

    // Build the attribute from the vales that were returned back
    rc = build_attribute(CKA_VALUE, secret_key_value +
                                        secret_key_value_len - secret_len,
                         secret_len, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to build the new attribute.\n");
        return rc;
    }
    // Create the object that will be passed back as a handle. This will
    // contain the new (computed) value of the attribute.

    rc = object_mgr_create_skel(tokdata, sess,
                                pTemplate, ulCount,
                                MODE_DERIVE, keyclass, keytype, &temp_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr create skeleton failed.\n");
        free(new_attr);
        return rc;
    }
    // Update the template in the object with the new attribute
    rc = template_update_attribute(temp_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        object_free(temp_obj);
        temp_obj = NULL;
        return rc;
    }

    // at this point, the derived key is fully constructed...assign an
    // object handle and store the key
    //
    rc = object_mgr_create_final(tokdata, sess, temp_obj, handle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr create final failed.\n");
        object_free(temp_obj);
        temp_obj = NULL;
        return rc;
    }

    return rc;
}

//
// mechanisms
//

//
//
CK_RV ckm_dh_pkcs_derive(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_VOID_PTR other_pubkey,
                         CK_ULONG other_pubkey_len,
                         OBJECT *base_key_obj,
                         CK_BYTE *secret_value, CK_ULONG *secret_value_len,
                         CK_MECHANISM_PTR mech,
                         CK_BBOOL count_statistic)
{
    CK_RV rc;
    CK_ATTRIBUTE *x_attr, *p_attr;

    // Extract secret (x) from base_key
    rc = template_attribute_get_non_empty(base_key_obj->template, CKA_VALUE,
                                          &x_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the base key\n");
        goto done;
    }

    // Extract prime (p) from base_key
    rc = template_attribute_get_non_empty(base_key_obj->template, CKA_PRIME,
                                          &p_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_PRIME for the base key\n");
        goto done;
    }

    // Perform: z = other_pubkey^x mod p
    rc = token_specific.t_dh_pkcs_derive(tokdata, secret_value,
                                         secret_value_len,
                                         (CK_BYTE *)other_pubkey,
                                         other_pubkey_len,
                                         (CK_BYTE *)x_attr->pValue,
                                         x_attr->ulValueLen,
                                         (CK_BYTE *)p_attr->pValue,
                                         p_attr->ulValueLen);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific dh pkcs derive failed.\n");

done:
    if (count_statistic == TRUE && rc == CKR_OK)
        INC_COUNTER(tokdata, sess, mech, base_key_obj, POLICY_STRENGTH_IDX_0);

    return rc;
}

//
//
CK_RV ckm_dh_pkcs_key_pair_gen(STDLL_TokData_t *tokdata,
                               TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    CK_RV rc;

    rc = token_specific.t_dh_pkcs_key_pair_gen(tokdata, publ_tmpl, priv_tmpl);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific dh pkcs key pair gen failed.\n");

    return rc;
}

CK_RV dh_encapsulate_key(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_BBOOL length_only, CK_MECHANISM *mech,
                         OBJECT *public_key,
                         CK_ATTRIBUTE *pTemplate,
                         CK_ULONG ulAttributeCount,
                         CK_BYTE *pCiphertext,
                         CK_ULONG *pulCiphertextLen,
                         CK_OBJECT_HANDLE *phKey)
{
    CK_MECHANISM dh_keygen_mech = { CKM_DH_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_MECHANISM dh_mech;
    CK_ATTRIBUTE *pub_key_value, *prime, *base;
    CK_OBJECT_HANDLE gen_dh_publ_key_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE gen_dh_priv_key_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
    OBJECT *gen_pub_key_obj = NULL;
    CK_ATTRIBUTE *gen_pub_key_value;
    CK_BBOOL ck_true = TRUE;
    CK_BBOOL ck_false = TRUE;
    CK_RV rc, rc2;

    CK_ATTRIBUTE dh_publ_key_tmpl[] = {
        { CKA_PRIME, NULL, 0 },
        { CKA_BASE, NULL, 0 },
        { CKA_HIDDEN, &ck_true, sizeof(ck_true) },
        { CKA_TOKEN, &ck_false, sizeof(ck_false) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        { CKA_ENCAPSULATE, &ck_true, sizeof(ck_true) },
        { CKA_WRAP, &ck_false, sizeof(ck_false) },
        { CKA_ENCRYPT, &ck_false, sizeof(ck_false) },
        { CKA_VERIFY, &ck_false, sizeof(ck_false) },
        { CKA_VERIFY_RECOVER, &ck_false, sizeof(ck_false) },
        { CKA_DERIVE, &ck_true, sizeof(ck_true) },
    };
    CK_ATTRIBUTE dh_priv_key_tmpl[] = {
        { CKA_HIDDEN, &ck_true, sizeof(ck_true) },
        { CKA_SENSITIVE, &ck_true, sizeof(ck_true) },
        { CKA_TOKEN, &ck_false, sizeof(ck_false) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        { CKA_UNWRAP, &ck_false, sizeof(ck_false) },
        { CKA_DECRYPT, &ck_false, sizeof(ck_false) },
        { CKA_SIGN, &ck_false, sizeof(ck_false) },
        { CKA_SIGN_RECOVER, &ck_false, sizeof(ck_false) },
        { CKA_DERIVE, &ck_true, sizeof(ck_true) },
        { CKA_DECAPSULATE, &ck_true, sizeof(ck_true) },
    };

    /* Mechanism parameter (= public key) must be NULL and 0 */
    if (mech->ulParameterLen != 0 || mech->pParameter != NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* Generate a temporary DH key pair using the same DH parameters */
    rc = template_attribute_get_non_empty(public_key->template,
                                          CKA_PRIME, &prime);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to get CKA_PRIME.\n");
        goto done;
    }

    rc = template_attribute_get_non_empty(public_key->template,
                                          CKA_BASE, &base);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to get CKA_BASE.\n");
        goto done;
    }

    if (length_only) {
        *pulCiphertextLen = prime->ulValueLen;
        goto done;
    }

    if (*pulCiphertextLen < prime->ulValueLen) {
        *pulCiphertextLen = prime->ulValueLen;
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    dh_publ_key_tmpl[0].pValue = prime->pValue;
    dh_publ_key_tmpl[0].ulValueLen = prime->ulValueLen;
    dh_publ_key_tmpl[1].pValue = base->pValue;
    dh_publ_key_tmpl[1].ulValueLen = base->ulValueLen;

    if (token_specific.t_encapsulate_dh_ecdh_key_pair_gen != NULL) {
        rc = token_specific.t_encapsulate_dh_ecdh_key_pair_gen(
                                       tokdata, sess,&dh_keygen_mech,
                                       dh_publ_key_tmpl,
                                       sizeof(dh_publ_key_tmpl) /
                                                           sizeof(CK_ATTRIBUTE),
                                       dh_priv_key_tmpl,
                                       sizeof(dh_priv_key_tmpl) /
                                                           sizeof(CK_ATTRIBUTE),
                                       &gen_dh_publ_key_handle,
                                       &gen_dh_priv_key_handle);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token specific encapsulate_dh_ecdh_key_pair_gen "
                        "failed to generate temporary DH key pair: %s "
                        "(0x%lx)\n", p11_get_ckr(rc), rc);
            goto done;
        }
    } else {
        rc = key_mgr_generate_key_pair(tokdata, sess, &dh_keygen_mech,
                                       dh_publ_key_tmpl,
                                       sizeof(dh_publ_key_tmpl) /
                                                           sizeof(CK_ATTRIBUTE),
                                       dh_priv_key_tmpl,
                                       sizeof(dh_priv_key_tmpl) /
                                                           sizeof(CK_ATTRIBUTE),
                                       &gen_dh_publ_key_handle,
                                       &gen_dh_priv_key_handle,
                                       FALSE, OP_ENCAPSULATE);
        if (rc != CKR_OK) {
            TRACE_ERROR("key_mgr_generate_key_pair failed to generate "
                        "temporary DH key pair: %s (0x%lx)\n",
                        p11_get_ckr(rc), rc);
            goto done;
        }
    }

    /* Get the size of the generated DH public value */
    rc = object_mgr_find_in_map1(tokdata, gen_dh_publ_key_handle,
                                 &gen_pub_key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from DH public key handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    rc = template_attribute_get_non_empty(gen_pub_key_obj->template,
                                          CKA_VALUE, &gen_pub_key_value);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to get CKA_VALUE.\n");
        goto done;
    }

    if (gen_pub_key_value->ulValueLen > prime->ulValueLen) {
        TRACE_DEVEL("DH Public key is larger than prime.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = template_attribute_get_non_empty(public_key->template,
                                          CKA_VALUE, &pub_key_value);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to get CKA_VALUE.\n");
        goto done;
    }

    dh_mech.mechanism = CKM_DH_PKCS_DERIVE;
    dh_mech.pParameter = pub_key_value->pValue;
    dh_mech.ulParameterLen = pub_key_value->ulValueLen;

    if (token_specific.t_en_decapsulate_dh_ecdh_derive_key != NULL) {
        rc = token_specific.t_en_decapsulate_dh_ecdh_derive_key(
                                            tokdata, sess, &dh_mech,
                                            gen_dh_priv_key_handle,
                                            &hKey, pTemplate, ulAttributeCount,
                                            OP_ENCAPSULATE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token specific en_decapsulate_dh_ecdh_derive_key "
                        "failed.\n");
            goto done;
        }
    } else {
        rc = key_mgr_derive_key(tokdata, sess, &dh_mech,
                                gen_dh_priv_key_handle,
                                &hKey, pTemplate, ulAttributeCount,
                                FALSE, OP_ENCAPSULATE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("key_mgr_derive_key failed.\n");
            goto done;
        }
    }

    *pulCiphertextLen = prime->ulValueLen;
    if (gen_pub_key_value->ulValueLen < prime->ulValueLen)
        memset(pCiphertext, 0,
               prime->ulValueLen - gen_pub_key_value->ulValueLen);
    memcpy(pCiphertext + prime->ulValueLen - gen_pub_key_value->ulValueLen,
           gen_pub_key_value->pValue, gen_pub_key_value->ulValueLen);

    *phKey = hKey;

done:
    if (gen_dh_publ_key_handle != CK_INVALID_HANDLE) {
        rc2 = object_mgr_destroy_object(tokdata, sess,
                                        gen_dh_publ_key_handle);
        if (rc2 != CKR_OK) {
            TRACE_ERROR("Failed to destroy temporary DH public key: %s "
                        "(0x%lx)\n", p11_get_ckr(rc2), rc2);
            if (rc == CKR_OK)
                rc = rc2;
        }
    }
    if (gen_dh_priv_key_handle != CK_INVALID_HANDLE) {
        rc2 = object_mgr_destroy_object(tokdata, sess,
                                        gen_dh_priv_key_handle);
        if (rc2 != CKR_OK) {
            TRACE_ERROR("Failed to destroy temporary DH private key: %s "
                        "(0x%lx)\n", p11_get_ckr(rc2), rc2);
            if (rc == CKR_OK)
                rc = rc2;
        }
    }

    if (rc != CKR_OK && hKey != CK_INVALID_HANDLE) {
        rc2 = object_mgr_destroy_object(tokdata, sess, hKey);
        if (rc2 != CKR_OK) {
            TRACE_ERROR("Failed to destroy derived secret key: %s "
                        "(0x%lx)\n", p11_get_ckr(rc2), rc2);
            if (rc == CKR_OK)
                rc = rc2;
        }
    }

    object_put(tokdata, gen_pub_key_obj, TRUE);
    gen_pub_key_obj = NULL;

    return rc;
}

CK_RV dh_decapsulate_key(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_MECHANISM *mech, OBJECT *private_key,
                         CK_ATTRIBUTE *pTemplate,
                         CK_ULONG ulAttributeCount,
                         CK_BYTE *pCiphertext,
                         CK_ULONG ulCiphertextLen,
                         CK_OBJECT_HANDLE *phKey)
{
    CK_MECHANISM dh_mech;
    CK_OBJECT_HANDLE hKey = CK_INVALID_HANDLE;
    CK_RV rc;

    /* Mechanism parameter (= public key) must be NULL and 0 */
    if (mech->ulParameterLen != 0 || mech->pParameter != NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    dh_mech.mechanism = CKM_DH_PKCS_DERIVE;
    dh_mech.pParameter = pCiphertext;
    dh_mech.ulParameterLen = ulCiphertextLen;

    if (token_specific.t_en_decapsulate_dh_ecdh_derive_key != NULL) {
        rc = token_specific.t_en_decapsulate_dh_ecdh_derive_key(
                                            tokdata, sess, &dh_mech,
                                            private_key->map_handle,
                                            &hKey, pTemplate, ulAttributeCount,
                                            OP_DECAPSULATE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token specific en_decapsulate_dh_ecdh_derive_key "
                        "failed.\n");
            goto done;
        }
    } else {
        rc = key_mgr_derive_key(tokdata, sess, &dh_mech,
                                private_key->map_handle,
                                &hKey, pTemplate, ulAttributeCount,
                                FALSE, OP_DECAPSULATE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("key_mgr_derive_key failed.\n");
            goto done;
        }
    }

    *phKey = hKey;

done:
    return rc;
}

#endif
