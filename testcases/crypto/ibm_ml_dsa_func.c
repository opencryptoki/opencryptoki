/*
 * COPYRIGHT (c) International Business Machines Corp. 2025
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"
#include "defs.h"
#include "mechtable.h"
#include "ibm_ml_dsa.h"

/**
 * Support for IBM ML-DSA keys and signatures
 * with oid = 2.16.840.1.101.3.4.3.xxx
 *
 * Only SignInit and Sign(Single) is supported with ML-DSA.
 * SignUpdate/SignFinal are not supported. Same with Verify.
 */
typedef struct signVerifyParam {
    CK_MECHANISM mech;
    CK_ULONG inputlen;
} _signVerifyParam;

CK_BYTE context[] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef };

CK_IBM_SIGN_ADDITIONAL_CONTEXT no_ctx_preferred =
                                { CKH_IBM_HEDGE_PREFERRED, NULL, 0 };
CK_IBM_SIGN_ADDITIONAL_CONTEXT no_ctx_required =
                                { CKH_IBM_HEDGE_REQUIRED, NULL, 0 };
CK_IBM_SIGN_ADDITIONAL_CONTEXT no_ctx_deterministic =
                                { CKH_IBM_DETERMINISTIC_REQUIRED, NULL, 0 };
CK_IBM_SIGN_ADDITIONAL_CONTEXT with_ctx_preferred =
                                { CKH_IBM_HEDGE_PREFERRED,
                                  context, sizeof(context) };

const _signVerifyParam signVerifyInput[] = {
    {{CKM_IBM_ML_DSA, NULL, 0}, 0},
    {{CKM_IBM_ML_DSA, NULL, 0}, 1},
    {{CKM_IBM_ML_DSA, NULL, 0}, 32},
    {{CKM_IBM_ML_DSA, NULL, 0}, 59},
    {{CKM_IBM_ML_DSA, NULL, 0}, 3000}, /* Not all variants support larger sizes */
    {{CKM_IBM_ML_DSA, &no_ctx_preferred, sizeof(no_ctx_preferred)}, 32},
    {{CKM_IBM_ML_DSA, &no_ctx_required, sizeof(no_ctx_required)}, 32},
    {{CKM_IBM_ML_DSA, &no_ctx_deterministic, sizeof(no_ctx_required)}, 32},
    {{CKM_IBM_ML_DSA, &with_ctx_preferred, sizeof(with_ctx_preferred)}, 32},
};


typedef struct variant_info {
    const char *name;
    CK_IBM_ML_DSA_PARAMETER_SET_TYPE parameter_set;
} _variant_info;

const _variant_info variants[] = {
    { "ML_DSA_44", CKP_IBM_ML_DSA_44, },
    { "ML_DSA_65", CKP_IBM_ML_DSA_65, },
    { "ML_DSA_87", CKP_IBM_ML_DSA_87, },
};

const CK_ULONG num_variants = sizeof(variants) / sizeof(_variant_info);

CK_RV run_SignVerifyMLDSA(CK_SESSION_HANDLE session,
                          CK_MECHANISM *mech,
                          CK_ULONG inputlen,
                          CK_OBJECT_HANDLE priv_key,
                          CK_OBJECT_HANDLE publ_key)
{
    CK_BYTE_PTR data = NULL, signature = NULL;
    CK_ULONG i, signaturelen;
    CK_RV rc;

    /* Query the slot, check if this mech if supported */
    if (!mech_supported(SLOT_ID, mech->mechanism)) {
        testcase_notice("Slot %u doesn't support %s",
                        (unsigned int) SLOT_ID,
                        p11_get_ckm(&mechtable_funcs, mech->mechanism));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto testcase_cleanup;
    }

    data = calloc(inputlen > 0 ? inputlen : 1, sizeof(CK_BYTE));
    if (data == NULL) {
        testcase_error("Can't allocate memory for %lu bytes",
                       sizeof(CK_BYTE) * inputlen);
        rc = -1;
        goto testcase_cleanup;
    }

    for (i = 0; i < inputlen; i++) {
        data[i] = (i + 1) % 255;
    }

    /* Sign */
    rc = funcs->C_SignInit(session, mech, priv_key);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_PARAM_INVALID &&
            mech->pParameter != NULL &&
            ((CK_IBM_SIGN_ADDITIONAL_CONTEXT *)mech->pParameter)->hedgeVariant
                                    == CKH_IBM_DETERMINISTIC_REQUIRED) {
            testcase_skip("Sign with CKH_IBM_DETERMINISTIC_REQUIRED not supported");
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        if (rc == CKR_MECHANISM_PARAM_INVALID &&
            mech->pParameter != NULL &&
            ((CK_IBM_SIGN_ADDITIONAL_CONTEXT *)mech->pParameter)->ulContextLen
                                                                    > 0) {
            testcase_skip("Sign with Context not supported");
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_Sign(session, data, inputlen, NULL, &signaturelen);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_PARAM_INVALID &&
            mech->pParameter != NULL &&
            ((CK_IBM_SIGN_ADDITIONAL_CONTEXT *)mech->pParameter)->hedgeVariant
                                    == CKH_IBM_DETERMINISTIC_REQUIRED) {
            testcase_skip("Sign with hedge type CKH_IBM_DETERMINISTIC_REQUIRED is not supported");
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        if (rc == CKR_MECHANISM_PARAM_INVALID &&
            mech->pParameter != NULL &&
            ((CK_IBM_SIGN_ADDITIONAL_CONTEXT *)mech->pParameter)->ulContextLen
                                                                    > 0) {
            testcase_skip("Sign with non-empty context not supported");
            rc = CKR_OK;
            goto testcase_cleanup;
        }
        testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }
    signature = calloc(signaturelen, sizeof(CK_BYTE));
    if (signature == NULL) {
        testcase_error("Can't allocate memory for %lu bytes",
                       sizeof(CK_BYTE) * signaturelen);
        rc = -1;
        goto testcase_cleanup;
    }

    rc = funcs->C_Sign(session, data, inputlen, signature, &signaturelen);
    if (rc != CKR_OK) {
        testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Verify */
    rc = funcs->C_VerifyInit(session, mech, publ_key);
    if (rc != CKR_OK) {
        testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_Verify(session, data, inputlen, signature, signaturelen);
    if (rc != CKR_OK) {
        testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Corrupt the signature and re-verify */
    memcpy(signature, "ABCDEFGHIJKLMNOPQRSTUV",
           strlen("ABCDEFGHIJKLMNOPQRSTUV"));

    rc = funcs->C_VerifyInit(session, mech, publ_key);
    if (rc != CKR_OK) {
        testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_Verify(session, data, inputlen, signature, signaturelen);
    if (rc != CKR_SIGNATURE_INVALID) {
        testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
        PRINT_ERR("		Expected CKR_SIGNATURE_INVALID\n");
        goto testcase_cleanup;
    }

    rc = CKR_OK;

testcase_cleanup:
    if (data)
        free(data);
    if (signature)
        free(signature);

    return rc;
}

CK_RV run_GenerateMLDSAKeyPairSignVerify(void)
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, j, i;
    CK_FLAGS flags;
    CK_RV rc;

    testcase_begin("Starting IBM ML-DSA generate key pair.");

    testcase_rw_session();
    testcase_user_login();

    mech.mechanism = CKM_IBM_ML_DSA_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    /* query the slot, check if this mech is supported */
    if (!mech_supported(SLOT_ID, mech.mechanism)) {
        testcase_skip("Slot %u doesn't support %s",
                      (unsigned int) SLOT_ID,
                      p11_get_ckm(&mechtable_funcs, mech.mechanism));
        rc = CKR_OK;
        goto testcase_cleanup;
    }

    for (i = 0; i < num_variants; i++) {
        /* Setup attributes for public/private ML-DSA key */
        CK_BBOOL attr_sign = TRUE;
        CK_BBOOL attr_verify = TRUE;
        CK_ATTRIBUTE ml_dsa_attr_private[] = {
            {CKA_SIGN, &attr_sign, sizeof(CK_BBOOL)},
            {CKA_IBM_PARAMETER_SET,
             (CK_BYTE *)&variants[i].parameter_set,
             sizeof(CK_IBM_ML_DSA_PARAMETER_SET_TYPE)},
        };
        CK_ATTRIBUTE ml_dsa_attr_public[] = {
            {CKA_VERIFY, &attr_verify, sizeof(CK_BBOOL)},
            {CKA_IBM_PARAMETER_SET,
             (CK_BYTE *)&variants[i].parameter_set,
             sizeof(CK_IBM_ML_DSA_PARAMETER_SET_TYPE)},
        };
        CK_ULONG num_ml_dsa_attrs = 2;

        /* Generate ML_DSA key pair */
        rc = funcs->C_GenerateKeyPair(session, &mech,
                       ml_dsa_attr_public, num_ml_dsa_attrs,
                       ml_dsa_attr_private, num_ml_dsa_attrs,
                       &publ_key, &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_GenerateKeyPair with %s not supported",
                     variants[i].name);
                goto next;
            } else {
                testcase_new_assertion();
                testcase_fail("C_GenerateKeyPair with %s and valid input failed, rc=%s",
                     variants[i].name, p11_get_ckr(rc));
                goto testcase_cleanup;
            }
        }
        testcase_new_assertion();
        testcase_pass("Generate ML-DSA key pair with %s passed.",
                      variants[i].name);

        /* Sign/verify with this key pair */
        for (j = 0; j < (sizeof(signVerifyInput) / sizeof(_signVerifyParam)); j++) {
            rc = run_SignVerifyMLDSA(session,
                                     (CK_MECHANISM *)&signVerifyInput[j].mech,
                                     signVerifyInput[j].inputlen,
                                     priv_key, publ_key);
            if (rc == CKR_MECHANISM_INVALID) {
                testcase_skip("run_SignVerifyMLDSA with %s index=%lu.",
                                              variants[i].name, j);
            } else if (rc != 0) {
                testcase_new_assertion();
                testcase_fail("run_SignVerifyMLDSA with %s failed index=%lu.",
                              variants[i].name, j);
                if (funcs3 != NULL)
                    funcs3->C_SessionCancel(session, CKF_SIGN | CKF_VERIFY);
                continue;
            } else {
                testcase_new_assertion();
                testcase_pass("*Sign & verify with %s j=%lu passed.",
                              variants[i].name, j);
            }
        }

next:
        if (publ_key != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, publ_key);
        publ_key = CK_INVALID_HANDLE;
        if (priv_key != CK_INVALID_HANDLE)
            funcs->C_DestroyObject(session, priv_key);
        priv_key = CK_INVALID_HANDLE;
    }

    rc = CKR_OK;

testcase_cleanup:
    if (publ_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_key);
    if (priv_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_key);

    testcase_user_logout();
    testcase_close_session();

    return rc;
}

CK_RV run_ImportMLDSAKeyPairSignVerify(void)
{
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i;
    CK_FLAGS flags;
    CK_MECHANISM sign_mech = {CKM_IBM_ML_DSA, NULL, 0};
    CK_RV rc;

    testcase_rw_session();
    testcase_user_login();

    /* query the slot, check if this mech is supported */
    if (!mech_supported(SLOT_ID, CKM_IBM_ML_DSA)) {
        testcase_skip("Slot %u doesn't support CKM_IBM_ML_DSA",
                      (unsigned int) SLOT_ID);
        rc = CKR_OK;
        goto testcase_cleanup;
    }

    for (i = 0; i < ML_DSA_TV_NUM; i++) {

        testcase_begin("Starting IBM ML-DSA import key pair, Sign/Verify, %s index=%lu",
                       ml_dsa_tv[i].name, i);

        /* Create IBM ML-DSA private key */
        rc = create_IBM_ML_DSA_PrivateKey(session,
                                          ml_dsa_tv[i].pkcs8,
                                          ml_dsa_tv[i].pkcs8_len,
                                          ml_dsa_tv[i].parameter_set,
                                          ml_dsa_tv[i].rho, ml_dsa_tv[i].rho_len,
                                          ml_dsa_tv[i].seed, ml_dsa_tv[i].seed_len,
                                          ml_dsa_tv[i].tr, ml_dsa_tv[i].tr_len,
                                          ml_dsa_tv[i].s1, ml_dsa_tv[i].s1_len,
                                          ml_dsa_tv[i].s2, ml_dsa_tv[i].s2_len,
                                          ml_dsa_tv[i].t0, ml_dsa_tv[i].t0_len,
                                          ml_dsa_tv[i].t1, ml_dsa_tv[i].t1_len,
                                          ml_dsa_tv[i].priv_seed,
                                          ml_dsa_tv[i].priv_seed_len,
                                          &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              ml_dsa_tv[i].name);
                continue;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM ML-DSA key import is not allowed by policy");
                continue;
            }
            testcase_new_assertion();
            testcase_fail("C_CreateObject (IBM ML-DSA Private Key) failed at "
                          "i=%lu, rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import IBM ML-DSA private key (%s) index=%lu passed.",
                      ml_dsa_tv[i].name, i);

        /* Create IBM ML-DSA public key */
        rc = create_IBM_ML_DSA_PublicKey(session,
                                         ml_dsa_tv[i].spki,
                                         ml_dsa_tv[i].spki_len,
                                         ml_dsa_tv[i].parameter_set,
                                         ml_dsa_tv[i].rho, ml_dsa_tv[i].rho_len,
                                         ml_dsa_tv[i].t1, ml_dsa_tv[i].t1_len,
                                         &publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              ml_dsa_tv[i].name);
                goto testcase_cleanup;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM ML-DSA key import is not allowed by policy");
                goto testcase_cleanup;
            }
            testcase_new_assertion();
            testcase_fail("C_CreateObject (IBM ML-DSA Public Key) failed at "
                          "i=%lu, rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import IBM ML-DSA public key (%s) index=%lu passed.",
                      ml_dsa_tv[i].name, i);

        /* Test sign/verify */
        rc = run_SignVerifyMLDSA(session, &sign_mech, 32, priv_key, publ_key);
        if (rc == CKR_MECHANISM_INVALID) {
            testcase_skip("run_SignVerifyMLDSA index=%lu.", i);
        } else if (rc != 0) {
            testcase_new_assertion();
            testcase_fail("run_SignVerifyMLDSA failed index=%lu.", i);
            goto testcase_cleanup;
        } else {
            testcase_new_assertion();
            testcase_pass("*Sign & verify, i=%lu passed.", i);
        }

        /* Clean up */
        rc = funcs->C_DestroyObject(session, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }

        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }
    }

    goto done;

testcase_cleanup:
    if (publ_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_key);
    if (priv_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_key);

done:
    testcase_user_logout();
    testcase_close_session();

    return rc;
}

/**
 * Wraps the given key with the given secret key using the given wrapping
 * mechanism.
 */
CK_RV wrapKey(CK_SESSION_HANDLE session, CK_MECHANISM *wrap_mech,
              CK_OBJECT_HANDLE secret_key, CK_OBJECT_HANDLE key_to_wrap,
              CK_BYTE_PTR *wrapped_key, CK_ULONG *wrapped_keylen)
{
    CK_BYTE_PTR tmp_key;
    CK_ULONG tmp_len;
    CK_RV rc;

    /* Determine length of wrapped key */
    rc = funcs->C_WrapKey(session, wrap_mech, secret_key, key_to_wrap,
                          NULL, &tmp_len);
    if (rc != CKR_OK)
        goto done;

    /* Allocate memory for wrapped_key */
    tmp_key = calloc(tmp_len, sizeof(CK_BYTE));
    if (!tmp_key) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    /* Now wrap the key */
    rc = funcs->C_WrapKey(session, wrap_mech, secret_key, key_to_wrap,
                          tmp_key, &tmp_len);
    if (rc != CKR_OK) {
        free(tmp_key);
        tmp_key = NULL;
        goto done;
    }

    *wrapped_key = tmp_key;
    *wrapped_keylen = tmp_len;

    rc = CKR_OK;

done:

    return rc;
}

/**
 * Unwraps the given wrapped_key using the given secret_key and wrapping
 * mechanism.
 */
CK_RV unwrapKey(CK_SESSION_HANDLE session, CK_MECHANISM *wrap_mech,
                CK_BYTE_PTR wrapped_key, CK_ULONG wrapped_keylen,
                CK_OBJECT_HANDLE secret_key, CK_OBJECT_HANDLE *unwrapped_key)
{
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE key_type = CKK_IBM_ML_DSA;
    CK_OBJECT_HANDLE tmp_key = CK_INVALID_HANDLE;
    CK_BYTE unwrap_label[] = "unwrapped_private_IBM_ML_DSA_Key";
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_BBOOL true = TRUE;
    CK_RV rc;

    CK_ATTRIBUTE unwrap_tmpl[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, &unwrap_label, sizeof(unwrap_label)},
        {CKA_SUBJECT, subject, sizeof(subject)},
        {CKA_ID, id, sizeof(id)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_DECRYPT, &true, sizeof(true)},
        {CKA_SIGN, &true, sizeof(true)},
    };

    rc = funcs->C_UnwrapKey(session, wrap_mech, secret_key,
                            wrapped_key, wrapped_keylen,
                            unwrap_tmpl,
                            sizeof(unwrap_tmpl) / sizeof(CK_ATTRIBUTE),
                            &tmp_key);
    if (rc != CKR_OK)
        goto done;

    *unwrapped_key = tmp_key;

    rc = CKR_OK;

done:

    return rc;
}

CK_RV run_TransferMLDSAKeyPairSignVerify(void)
{
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i;
    CK_FLAGS flags;
    CK_RV rc;
    CK_OBJECT_HANDLE secret_key = CK_INVALID_HANDLE;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_ULONG wrapped_keylen;
    CK_OBJECT_HANDLE unwrapped_key = CK_INVALID_HANDLE;
    CK_MECHANISM wrap_mech, wkey_mech;
    CK_MECHANISM sign_mech = {CKM_IBM_ML_DSA, NULL, 0};

    testcase_rw_session();
    testcase_user_login();

    /* query the slot, check if this mech is supported */
    if (!mech_supported(SLOT_ID, CKM_IBM_ML_DSA)) {
        testcase_skip("Slot %u doesn't support CKM_IBM_ML_DSA",
                      (unsigned int) SLOT_ID);
        rc = CKR_OK;
        goto testcase_cleanup;
    }
    if (!mech_supported(SLOT_ID, CKM_AES_KEY_GEN)) {
        testcase_skip("Slot %u doesn't support CKM_AES_KEY_GEN",
                      (unsigned int) SLOT_ID);
        rc = CKR_OK;
        goto testcase_cleanup;
    }
    if (!mech_supported_flags(SLOT_ID, CKM_AES_CBC_PAD, CKF_WRAP)) {
        testcase_skip("Slot %u doesn't support key wrapping with CKM_AES_CBC_PAD",
                      (unsigned int) SLOT_ID);
        rc = CKR_OK;
        goto testcase_cleanup;
    }

    for (i = 0; i < ML_DSA_TV_NUM; i++) {

        testcase_begin("Starting IBM ML-DSA transfer key pair, Sign/Verify %s index=%lu.",
                       ml_dsa_tv[i].name, i);

        /* Create IBM ML-DSA private key */
        rc = create_IBM_ML_DSA_PrivateKey(session,
                                          ml_dsa_tv[i].pkcs8,
                                          ml_dsa_tv[i].pkcs8_len,
                                          ml_dsa_tv[i].parameter_set,
                                          ml_dsa_tv[i].rho, ml_dsa_tv[i].rho_len,
                                          ml_dsa_tv[i].seed, ml_dsa_tv[i].seed_len,
                                          ml_dsa_tv[i].tr, ml_dsa_tv[i].tr_len,
                                          ml_dsa_tv[i].s1, ml_dsa_tv[i].s1_len,
                                          ml_dsa_tv[i].s2, ml_dsa_tv[i].s2_len,
                                          ml_dsa_tv[i].t0, ml_dsa_tv[i].t0_len,
                                          ml_dsa_tv[i].t1, ml_dsa_tv[i].t1_len,
                                          ml_dsa_tv[i].priv_seed,
                                          ml_dsa_tv[i].priv_seed_len,
                                          &priv_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              ml_dsa_tv[i].name);
                continue;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM ML-DSA key import is not allowed by policy");
                continue;
            }
            testcase_new_assertion();
            testcase_fail("C_CreateObject (IBM ML-DSA Private Key) failed at "
                          "i=%lu, rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import IBM ML-DSA private key (%s) index=%lu passed.",
                      ml_dsa_tv[i].name, i);

        /* Create IBM ML-DSA public key */
        rc = create_IBM_ML_DSA_PublicKey(session,
                                         ml_dsa_tv[i].spki,
                                         ml_dsa_tv[i].spki_len,
                                         ml_dsa_tv[i].parameter_set,
                                         ml_dsa_tv[i].rho, ml_dsa_tv[i].rho_len,
                                         ml_dsa_tv[i].t1, ml_dsa_tv[i].t1_len,
                                         &publ_key);
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              ml_dsa_tv[i].name);
                goto testcase_cleanup;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("IBM ML-DSA key import is not allowed by policy");
                goto testcase_cleanup;
            }
            testcase_new_assertion();
            testcase_fail("C_CreateObject (IBM ML-DSA Public Key) failed at "
                          "i=%lu,rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_new_assertion();
        testcase_pass("*Import IBM ML-DSA public key (%s) index=%lu passed.",
                      ml_dsa_tv[i].name, i);

        /* Create wrapping key (secret key) */
        wkey_mech.mechanism = CKM_AES_KEY_GEN;
        wkey_mech.pParameter = NULL;
        wkey_mech.ulParameterLen = 0;
        rc = generate_AESKey(session, 32, CK_TRUE, &wkey_mech, &secret_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("AES key generation is not allowed by policy");
                goto testcase_cleanup;
            }

            testcase_error("generate_AESKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /* Setup wrapping mechanism */
        wrap_mech.mechanism = CKM_AES_CBC_PAD;
        wrap_mech.pParameter = "0123456789abcdef";
        wrap_mech.ulParameterLen = 16;

        /* Wrap IBM ML-DSA private key with secret key */
        rc = wrapKey(session, &wrap_mech, secret_key, priv_key,
                     &wrapped_key, &wrapped_keylen);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            testcase_error("wrapKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Wrap IBM ML-DSA private key (%s) index=%lu passed.",
                      ml_dsa_tv[i].name, i);

        /* Unwrap IBM ML-DSA private key */
        rc = unwrapKey(session, &wrap_mech, wrapped_key, wrapped_keylen,
                       secret_key, &unwrapped_key);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            testcase_error("unwrapKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Unwrap IBM ML-DSA private key (%s) index=%lu passed.",
                      ml_dsa_tv[i].name, i);

        free(wrapped_key);
        wrapped_key = NULL;

        /* Test sign/verify using unwrapped private key and untouched public key */
        rc = run_SignVerifyMLDSA(session, &sign_mech, 32, priv_key, publ_key);
        if (rc == CKR_MECHANISM_INVALID) {
            testcase_skip("run_SignVerifyMLDSA index=%lu.", i);
        } else if (rc != 0) {
            testcase_new_assertion();
            testcase_fail("run_SignVerifyMLDSA failed index=%lu.", i);
            goto testcase_cleanup;
        } else {
            testcase_new_assertion();
            testcase_pass("*Sign & verify, i=%lu passed.", i);
        }

        /* Clean up */
        rc = funcs->C_DestroyObject(session, publ_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }

        rc = funcs->C_DestroyObject(session, priv_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }

        rc = funcs->C_DestroyObject(session, secret_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }

        rc = funcs->C_DestroyObject(session, unwrapped_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject(), rc=%s.", p11_get_ckr(rc));
        }
    }

    goto done;

testcase_cleanup:
    if (publ_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, publ_key);
    if (priv_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, priv_key);
    if (secret_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, secret_key);
    if (unwrapped_key != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, unwrapped_key);

    if (wrapped_key)
        free(wrapped_key);

done:
    testcase_user_logout();
    testcase_close_session();

    return rc;
}

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int rc;
    CK_RV rv;

    rc = do_ParseArgs(argc, argv);
    if (rc != 1)
        return rc;

    printf("Using slot #%lu...\n\n", SLOT_ID);
    printf("With option: no_init: %d\n", no_init);

    rc = do_GetFunctionList();
    if (!rc) {
        PRINT_ERR("ERROR do_GetFunctionList() Failed , rc = 0x%0x\n", rc);
        return rc;
    }

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    funcs->C_Initialize(&cinit_args);

    {
        CK_SESSION_HANDLE hsess = 0;

        rc = funcs->C_GetFunctionStatus(hsess);
        if (rc != CKR_FUNCTION_NOT_PARALLEL)
            return rc;

        rc = funcs->C_CancelFunction(hsess);
        if (rc != CKR_FUNCTION_NOT_PARALLEL)
            return rc;
    }

    testcase_setup();

    rv = run_GenerateMLDSAKeyPairSignVerify();
    rv |= run_ImportMLDSAKeyPairSignVerify();
    rv |= run_TransferMLDSAKeyPairSignVerify();

    testcase_print_result();

    funcs->C_Finalize(NULL);

    return testcase_return(rv);
}
