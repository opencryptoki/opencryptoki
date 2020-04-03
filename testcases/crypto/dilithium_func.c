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

#include <openssl/crypto.h>

/**
 * Experimental Support for Dilithium keys and signatures
 * with oid = 1.3.6.1.4.1.2.267.1.6.5
 *
 * Only SignInit and Sign(Single) is supported with Dilithium.
 * SignUpdate/SignFinal are not supported. Same with Verify.
 */
typedef struct signVerifyParam {
    CK_MECHANISM_TYPE mechtype;
    CK_ULONG inputlen;
} _signVerifyParam;

_signVerifyParam signVerifyInput[] = {
    {CKM_IBM_DILITHIUM, 0},
    {CKM_IBM_DILITHIUM, 1},
    {CKM_IBM_DILITHIUM, 32},
    {CKM_IBM_DILITHIUM, 59},
    {CKM_IBM_DILITHIUM, 5900},
};

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
                          (unsigned int) SLOT_ID, p11_get_ckm(mechType));
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

CK_RV run_GenerateDilithiumKeyPairSignVerify()
{
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE publ_key = CK_INVALID_HANDLE, priv_key = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, j;
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
            /* no support for EC key gen? skip */
            testcase_skip("Slot %u doesn't support CKM_IBM_DILITHIUM ",
                          (unsigned int) SLOT_ID);
            rc = CKR_OK;
            goto testcase_cleanup;
        } else {
            testcase_error("C_GetMechanismInfo() rc = %s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

    /* Setup attributes for public/private Dilithium key */
    CK_BBOOL attr_sign = TRUE;
    CK_BBOOL attr_verify = TRUE;
    CK_ATTRIBUTE dilithium_attr_private[] = {
        {CKA_SIGN, &attr_sign, sizeof(CK_BBOOL)},
    };
    CK_ATTRIBUTE dilithium_attr_public[] = {
        {CKA_VERIFY, &attr_verify, sizeof(CK_BBOOL)},
    };

    /* Generate Dilithium key pair */
    rc = funcs->C_GenerateKeyPair(session, &mech,
                   dilithium_attr_public, 1,
                   dilithium_attr_private, 1,
                   &publ_key, &priv_key);
    testcase_new_assertion();
    if (rc != CKR_OK) {
        testcase_fail
            ("C_GenerateKeyPair with valid input failed, rc=%s",
             p11_get_ckr(rc));
        goto testcase_cleanup;
    }
    testcase_pass("*Generate Dilithium key pair passed.");

    /* Sign/verify with this key pair */
    for (j = 0; j < (sizeof(signVerifyInput) / sizeof(_signVerifyParam)); j++) {
        testcase_new_assertion();
        rc = run_SignVerifyDilithium(session,
                               signVerifyInput[j].mechtype,
                               signVerifyInput[j].inputlen,
                               priv_key, publ_key);
        if (rc != 0) {
            testcase_fail("run_SignVerifyDilithium failed index=%lu.", j);
            goto testcase_cleanup;
        }
        testcase_pass("*Sign & verify j=%lu passed.", j);
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

    testcase_setup(total_assertions);

    rv = run_GenerateDilithiumKeyPairSignVerify();

    testcase_print_result();

    funcs->C_Finalize(NULL);

    /* make sure we return non-zero if rv is non-zero */
    return ((rv == 0) || (rv % 256) ? (int)rv : -1);
}
