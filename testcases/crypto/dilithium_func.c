/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
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
#include "dilithium.h"
#include "mechtable.h"
#include "pqc_oids.h"

/**
 * Experimental Support for Dilithium keys and signatures
 * with oid = 1.3.6.1.4.1.2.267.xxx
 *
 * Only SignInit and Sign(Single) is supported with Dilithium.
 * SignUpdate/SignFinal are not supported. Same with Verify.
 */
typedef struct signVerifyParam {
    CK_MECHANISM_TYPE mechtype;
    CK_ULONG inputlen;
} _signVerifyParam;

const _signVerifyParam signVerifyInput[] = {
    {CKM_IBM_DILITHIUM, 0},
    {CKM_IBM_DILITHIUM, 1},
    {CKM_IBM_DILITHIUM, 32},
    {CKM_IBM_DILITHIUM, 59},
    {CKM_IBM_DILITHIUM, 3000}, /* Not all variants support larger sizes */
};

const CK_BYTE dilithium_r2_65[] = OCK_DILITHIUM_R2_65;
const CK_BYTE dilithium_r2_87[] = OCK_DILITHIUM_R2_87;
const CK_BYTE dilithium_r3_44[] = OCK_DILITHIUM_R3_44;
const CK_BYTE dilithium_r3_65[] = OCK_DILITHIUM_R3_65;
const CK_BYTE dilithium_r3_87[] = OCK_DILITHIUM_R3_87;

typedef struct variant_info {
    const char *name;
    CK_ULONG keyform;
    const CK_BYTE *oid;
    CK_ULONG oid_len;
} _variant_info;

const _variant_info variants[] = {
    { "DEFAULT (DILITHIUM_R2_65)", 0, NULL, 0 },
    { "DILITHIUM_R2_65", CK_IBM_DILITHIUM_KEYFORM_ROUND2_65,
      dilithium_r2_65, sizeof(dilithium_r2_65) },
    { "DILITHIUM_R2_87", CK_IBM_DILITHIUM_KEYFORM_ROUND2_87,
      dilithium_r2_87, sizeof(dilithium_r2_87) },
    { "DILITHIUM_R3_44", CK_IBM_DILITHIUM_KEYFORM_ROUND3_44,
      dilithium_r3_44, sizeof(dilithium_r3_44) },
    { "DILITHIUM_R3_65", CK_IBM_DILITHIUM_KEYFORM_ROUND3_65,
      dilithium_r3_65, sizeof(dilithium_r3_65) },
    { "DILITHIUM_R3_87", CK_IBM_DILITHIUM_KEYFORM_ROUND3_87,
      dilithium_r3_87, sizeof(dilithium_r3_87) },
};

const CK_ULONG num_variants = sizeof(variants) / sizeof(_variant_info);

CK_RV run_SignVerifyDilithium(CK_SESSION_HANDLE session,
                              CK_MECHANISM_TYPE mechType,
                              CK_ULONG inputlen,
                              CK_OBJECT_HANDLE priv_key,
                              CK_OBJECT_HANDLE publ_key)
{
    CK_MECHANISM mech;
    CK_BYTE_PTR data = NULL, signature = NULL;
    CK_ULONG i, signaturelen;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    mech.mechanism = mechType;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    /* Query the slot, check if this mech if supported */
    rc = funcs->C_GetMechanismInfo(SLOT_ID, mech.mechanism, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for Dilithium? skip */
            testcase_skip("Slot %u doesn't support %s",
                          (unsigned int) SLOT_ID,
                          p11_get_ckm(&mechtable_funcs, mechType));
            rc = CKR_OK;
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    data = calloc(sizeof(CK_BYTE), inputlen);
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
    rc = funcs->C_SignInit(session, &mech, priv_key);
    if (rc != CKR_OK) {
        testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_Sign(session, data, inputlen, NULL, &signaturelen);
    if (rc != CKR_OK) {
        testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }
    signature = calloc(sizeof(CK_BYTE), signaturelen);
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
    rc = funcs->C_VerifyInit(session, &mech, publ_key);
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

    rc = funcs->C_VerifyInit(session, &mech, publ_key);
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

CK_RV run_SignVerifyDilithiumKAT(CK_SESSION_HANDLE session,
                                 CK_ULONG index,
                                 CK_OBJECT_HANDLE priv_key,
                                 CK_OBJECT_HANDLE publ_key)
{
    CK_MECHANISM mech;
    CK_BYTE_PTR signature = NULL;
    CK_ULONG siglen;
    CK_RV rc;

    mech.mechanism = CKM_IBM_DILITHIUM;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    /* Initialize */
    rc = funcs->C_SignInit(session, &mech, priv_key);
    if (rc != CKR_OK) {
        testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Determine signature length */
    rc = funcs->C_Sign(session, dilithium_tv[index].msg, dilithium_tv[index].msg_len,
                       NULL, &siglen);
    if (rc != CKR_OK) {
        testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Allocate buffer for signature */
    signature = calloc(sizeof(CK_BYTE), siglen);
    if (signature == NULL) {
        testcase_error("Can't allocate memory for %lu bytes",
                       sizeof(CK_BYTE) *siglen);
        rc = -1;
        goto testcase_cleanup;
    }

    /* Create signature */
    rc = funcs->C_Sign(session, dilithium_tv[index].msg, dilithium_tv[index].msg_len,
                       signature, &siglen);
    if (rc != CKR_OK) {
        testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Check if calculated signature len matches with known signature len */
    if (siglen != dilithium_tv[index].sig_len) {
        testcase_error("Calculated signature length %lu does not match known length %lu.",
                       siglen, dilithium_tv[index].sig_len);
        goto testcase_cleanup;
    }

    /* Check if signature matches with known signature */
    if (memcmp(signature, dilithium_tv[index].sig, siglen) != 0) {
        testcase_error("Signature bad.");
        goto testcase_cleanup;
    }

    /* Verify signature */
    rc = funcs->C_VerifyInit(session, &mech, publ_key);
    if (rc != CKR_OK) {
        testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_Verify(session, dilithium_tv[index].msg, dilithium_tv[index].msg_len,
                         signature, siglen);
    if (rc != CKR_OK) {
        testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = CKR_OK;

testcase_cleanup:

    free(signature);

    return rc;
}

CK_RV run_GenerateDilithiumKeyPairSignVerify(void)
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, j, i;
    CK_FLAGS flags;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    testcase_begin("Starting Dilithium generate key pair.");

    testcase_rw_session();
    testcase_user_login();

    mech.mechanism = CKM_IBM_DILITHIUM;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    /* query the slot, check if this mech is supported */
    rc = funcs->C_GetMechanismInfo(SLOT_ID, mech.mechanism, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for Dilithium key gen? skip */
            testcase_skip("Slot %u doesn't support CKM_IBM_DILITHIUM ",
                          (unsigned int) SLOT_ID);
            rc = CKR_OK;
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    for (i = 0; i < 2 * num_variants; i++) {
        /* Setup attributes for public/private Dilithium key */
        CK_BBOOL attr_sign = TRUE;
        CK_BBOOL attr_verify = TRUE;
        CK_ATTRIBUTE dilithium_attr_private_keyform[] = {
            {CKA_SIGN, &attr_sign, sizeof(CK_BBOOL)},
            {CKA_IBM_DILITHIUM_KEYFORM,
             (CK_BYTE *)&variants[i % num_variants].keyform, sizeof(CK_ULONG)},
        };
        CK_ATTRIBUTE dilithium_attr_public_keyform[] = {
            {CKA_VERIFY, &attr_verify, sizeof(CK_BBOOL)},
            {CKA_IBM_DILITHIUM_KEYFORM,
             (CK_BYTE *)&variants[i % num_variants].keyform, sizeof(CK_ULONG)},
        };
        CK_ATTRIBUTE dilithium_attr_private_mode[] = {
            {CKA_SIGN, &attr_sign, sizeof(CK_BBOOL)},
            {CKA_IBM_DILITHIUM_MODE,
            (CK_BYTE *)variants[i % num_variants].oid, variants[i % num_variants].oid_len},
        };
        CK_ATTRIBUTE dilithium_attr_public_mode[] = {
            {CKA_VERIFY, &attr_verify, sizeof(CK_BBOOL)},
            {CKA_IBM_DILITHIUM_MODE,
            (CK_BYTE *)variants[i % num_variants].oid, variants[i % num_variants].oid_len},
        };
        CK_ATTRIBUTE *dilithium_attr_private = i < num_variants ?
                                            dilithium_attr_private_keyform :
                                            dilithium_attr_private_mode;
        CK_ATTRIBUTE *dilithium_attr_public = i < num_variants ?
                                            dilithium_attr_public_keyform :
                                            dilithium_attr_public_mode;
        CK_ULONG num_dilithium_attrs =
                            (variants[i % num_variants].oid == NULL) ? 1 : 2;

        /* Generate Dilithium key pair */
        rc = funcs->C_GenerateKeyPair(session, &mech,
                       dilithium_attr_public, num_dilithium_attrs,
                       dilithium_attr_private, num_dilithium_attrs,
                       &publ_key, &priv_key);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_GenerateKeyPair with %s (%s) not supported",
                     variants[i % num_variants].name,
                     i < num_variants ? "KEYFORM" : "MODE");
                goto next;
            } else {
                testcase_fail("C_GenerateKeyPair with %s (%s) and valid input failed, rc=%s",
                     variants[i % num_variants].name,
                     i < num_variants ? "KEYFORM" : "MODE", p11_get_ckr(rc));
                goto testcase_cleanup;
            }
        }
        testcase_pass("*Generate Dilithium key pair with %s (%s) passed.",
                      variants[i % num_variants].name,
                      i < num_variants ? "KEYFORM" : "MODE");

        /* Sign/verify with this key pair */
        for (j = 0; j < (sizeof(signVerifyInput) / sizeof(_signVerifyParam)); j++) {
            testcase_new_assertion();
            rc = run_SignVerifyDilithium(session,
                                   signVerifyInput[j].mechtype,
                                   signVerifyInput[j].inputlen,
                                   priv_key, publ_key);
            if (rc != 0) {
                testcase_fail("run_SignVerifyDilithium with %s failed index=%lu.",
                              variants[i % num_variants].name, j);
                goto next;
            }
            testcase_pass("*Sign & verify with %s j=%lu passed.",
                          variants[i % num_variants].name, j);
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

CK_RV run_ImportDilithiumKeyPairSignVerify(void)
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i;
    CK_FLAGS flags;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    testcase_rw_session();
    testcase_user_login();

    mech.mechanism = CKM_IBM_DILITHIUM;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    /* query the slot, check if this mech is supported */
    rc = funcs->C_GetMechanismInfo(SLOT_ID, mech.mechanism, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for Dilithium key gen? skip */
            testcase_skip("Slot %u doesn't support CKM_IBM_DILITHIUM",
                          (unsigned int) SLOT_ID);
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    for (i = 0; i < DILITHIUM_TV_NUM; i++) {

        testcase_begin("Starting Dilithium import key pair, Sign/Verify, %s index=%lu",
                       dilithium_tv[i].name, i);

        /* Create Dilithium private key */
        rc = create_DilithiumPrivateKey(session,
                            dilithium_tv[i].pkcs8, dilithium_tv[i].pkcs8_len,
                            dilithium_tv[i].keyform,
                            dilithium_tv[i].rho, dilithium_tv[i].rho_len,
                            dilithium_tv[i].seed, dilithium_tv[i].seed_len,
                            dilithium_tv[i].tr, dilithium_tv[i].tr_len,
                            dilithium_tv[i].s1, dilithium_tv[i].s1_len,
                            dilithium_tv[i].s2, dilithium_tv[i].s2_len,
                            dilithium_tv[i].t0, dilithium_tv[i].t0_len,
                            dilithium_tv[i].t1, dilithium_tv[i].t1_len,
                            &priv_key);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              dilithium_tv[i].name);
                continue;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("Dilithium key import is not allowed by policy");
                continue;
            }
            testcase_fail("C_CreateObject (Dilithium Private Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Import Dilithium private key (%s) index=%lu passed.",
                      dilithium_tv[i].name, i);

        /* Create Dilithium public key */
        rc = create_DilithiumPublicKey(session,
                                dilithium_tv[i].spki, dilithium_tv[i].spki_len,
                                dilithium_tv[i].keyform,
                                dilithium_tv[i].rho, dilithium_tv[i].rho_len,
                                dilithium_tv[i].t1, dilithium_tv[i].t1_len,
                                &publ_key);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              dilithium_tv[i].name);
                goto testcase_cleanup;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("Dilithium key import is not allowed by policy");
                goto testcase_cleanup;
            }
            testcase_fail("C_CreateObject (Dilithium Public Key) failed at i=%lu, "
                          "rc=%s", i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Import Dilithium public key (%s) index=%lu passed.",
                      dilithium_tv[i].name, i);

        /* Test sign/verify with KAT */
        testcase_new_assertion();
        rc = run_SignVerifyDilithiumKAT(session, i, priv_key, publ_key);
        if (rc != 0) {
            testcase_fail("run_SignVerifyDilithiumKAT failed index=%lu.", i);
            goto testcase_cleanup;
        }
        testcase_pass("*Sign & verify KAT, i=%lu passed.", i);

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
    tmp_key = calloc(sizeof(CK_BYTE), tmp_len);
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
    CK_KEY_TYPE key_type = CKK_IBM_PQC_DILITHIUM;
    CK_OBJECT_HANDLE tmp_key = CK_INVALID_HANDLE;
    CK_BYTE unwrap_label[] = "unwrapped_private_Dilithium_Key";
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

CK_RV run_TransferDilithiumKeyPairSignVerify(void)
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, i;
    CK_FLAGS flags;
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;
    CK_OBJECT_HANDLE secret_key = CK_INVALID_HANDLE;
    CK_BYTE_PTR wrapped_key = NULL;
    CK_ULONG wrapped_keylen;
    CK_OBJECT_HANDLE unwrapped_key = CK_INVALID_HANDLE;
    CK_MECHANISM wrap_mech, wkey_mech;

    testcase_rw_session();
    testcase_user_login();

    mech.mechanism = CKM_IBM_DILITHIUM;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    /* query the slot, check if this mech is supported */
    rc = funcs->C_GetMechanismInfo(SLOT_ID, mech.mechanism, &mech_info);
    if (rc != CKR_OK) {
        if (rc == CKR_MECHANISM_INVALID) {
            /* no support for Dilithium key gen? skip */
            testcase_skip("Slot %u doesn't support CKM_IBM_DILITHIUM",
                          (unsigned int) SLOT_ID);
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    for (i = 0; i < DILITHIUM_TV_NUM; i++) {

        testcase_begin("Starting Dilithium transfer key pair, Sign/Verify %s index=%lu.",
                       dilithium_tv[i].name, i);

        /* Create Dilithium private key */
        rc = create_DilithiumPrivateKey(session,
                            dilithium_tv[i].pkcs8, dilithium_tv[i].pkcs8_len,
                            dilithium_tv[i].keyform,
                            dilithium_tv[i].rho, dilithium_tv[i].rho_len,
                            dilithium_tv[i].seed, dilithium_tv[i].seed_len,
                            dilithium_tv[i].tr, dilithium_tv[i].tr_len,
                            dilithium_tv[i].s1, dilithium_tv[i].s1_len,
                            dilithium_tv[i].s2, dilithium_tv[i].s2_len,
                            dilithium_tv[i].t0, dilithium_tv[i].t0_len,
                            dilithium_tv[i].t1, dilithium_tv[i].t1_len,
                            &priv_key);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              dilithium_tv[i].name);
                continue;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("Dilithium key import is not allowed by policy");
                continue;
            }
            testcase_fail
                ("C_CreateObject (Dilithium Private Key) failed at i=%lu, rc=%s", i,
                 p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Import Dilithium private key (%s) index=%lu passed.",
                      dilithium_tv[i].name, i);

        /* Create Dilithium public key */
        rc = create_DilithiumPublicKey(session,
                                dilithium_tv[i].spki, dilithium_tv[i].spki_len,
                                dilithium_tv[i].keyform,
                                dilithium_tv[i].rho, dilithium_tv[i].rho_len,
                                dilithium_tv[i].t1, dilithium_tv[i].t1_len,
                                &publ_key);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            if (rc == CKR_KEY_SIZE_RANGE) {
                testcase_skip("C_CreateObject with %s not supported",
                              dilithium_tv[i].name);
                goto testcase_cleanup;
            } else if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("Dilithium key import is not allowed by policy");
                goto testcase_cleanup;
            }
            testcase_fail
                ("C_CreateObject (Dilithium Public Key) failed at i=%lu, rc=%s", i,
                 p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Import Dilithium public key (%s) index=%lu passed.",
                      dilithium_tv[i].name, i);

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

        /* Wrap Dilithium private key with secret key */
        rc = wrapKey(session, &wrap_mech, secret_key, priv_key,
                     &wrapped_key, &wrapped_keylen);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            testcase_error("wrapKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Wrap Dilithium private key (%s) index=%lu passed.",
                      dilithium_tv[i].name, i);

        /* Unwrap Dilithium private key */
        rc = unwrapKey(session, &wrap_mech, wrapped_key, wrapped_keylen,
                       secret_key, &unwrapped_key);
        testcase_new_assertion();
        if (rc != CKR_OK) {
            testcase_error("unwrapKey, rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Unwrap Dilithium private key (%s) index=%lu passed.",
                      dilithium_tv[i].name, i);

        free(wrapped_key);
        wrapped_key = NULL;

        /* Test sign/verify using unwrapped private key and untouched public key */
        testcase_new_assertion();
        rc = run_SignVerifyDilithiumKAT(session, i, unwrapped_key, publ_key);
        if (rc != 0) {
            testcase_fail("Sign & verify KAT using unwrapped key failed, index=%lu, rc=%s.",
                          i, p11_get_ckr(rc));
            goto testcase_cleanup;
        }
        testcase_pass("*Sign & verify KAT using unwrapped key, i=%lu passed.", i);

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

    rv = run_GenerateDilithiumKeyPairSignVerify();

    rv = run_ImportDilithiumKeyPairSignVerify();

    rv = run_TransferDilithiumKeyPairSignVerify();

    testcase_print_result();

    funcs->C_Finalize(NULL);

    return testcase_return(rv);
}
