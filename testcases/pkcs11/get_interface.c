/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "pkcs11types.h"
#include "regress.h"

static int get_interface_test(void)
{
    CK_FUNCTION_LIST_3_0 *tfn;
    CK_INTERFACE *interface;
    CK_VERSION version, *v;
    CK_SLOT_ID slot;
    CK_FLAGS flags;
    CK_RV rv;
    int rc = -1;

    testcase_new_assertion();

    flags = 0ULL;
    rv = funcs3->C_GetInterface(NULL, NULL, NULL, flags);
    if (rv != CKR_ARGUMENTS_BAD) {
        testcase_fail("C_GetInterface returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }

    flags = ~0UL;
    rv = funcs3->C_GetInterface((CK_UTF8CHAR *)"PKCS 11",
                                NULL, &interface, flags);
    if (rv != CKR_FUNCTION_FAILED) {
        testcase_fail("C_GetInterface returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }

    version.major = 0;
    version.minor = 0;
    flags = 0ULL;
    rv = funcs3->C_GetInterface((CK_UTF8CHAR *)"PKCS 11",
                                &version, &interface, flags);
    if (rv != CKR_FUNCTION_FAILED) {
        testcase_fail("C_GetInterface returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }

    flags = 0ULL;
    rv = funcs3->C_GetInterface((CK_UTF8CHAR *)"INVALID",
                                NULL, &interface, flags);
    if (rv != CKR_FUNCTION_FAILED) {
        testcase_fail("C_GetInterface returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }

    flags = 0ULL;
    rv = funcs3->C_GetInterface(NULL, NULL, &interface, flags);
    if (rv != CKR_OK) {
        testcase_fail("C_GetInterface returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }
    v = (CK_VERSION *)interface->pFunctionList;
    printf("%s\n", "Default interface:");
    printf("pInterfaceName         %s\n", interface->pInterfaceName);
    printf("pFunctionList version  %u.%u\n", v->major, v->minor);
    printf("flags                  0x%016lx\n", interface->flags);

    flags = 0ULL;
    rv = funcs3->C_GetInterface((CK_UTF8CHAR *)"PKCS 11",
                                NULL, &interface, flags);
    if (rv != CKR_OK) {
        testcase_fail("C_GetInterface returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }
    if (strcmp((char *)interface->pInterfaceName, "PKCS 11") != 0) {
        testcase_fail("Returned interface name: %s.\n",
                           interface->pInterfaceName);
        goto ret;
    }
    v = (CK_VERSION *)interface->pFunctionList;
    printf("%s\n", "Default PKCS #11 interface:");
    printf("pInterfaceName         %s\n", interface->pInterfaceName);
    printf("pFunctionList version  %u.%u\n", v->major, v->minor);
    printf("flags                  0x%016lx\n", interface->flags);

    version.major = 1;
    version.minor = 0;
    flags = 0ULL;
    rv = funcs3->C_GetInterface((CK_UTF8CHAR *)"Vendor IBM",
                                NULL, &interface, flags);
    if (rv != CKR_OK) {
        testcase_fail("C_GetInterface returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }
    if (strcmp((char *)interface->pInterfaceName, "Vendor IBM") != 0) {
        testcase_fail("Returned interface name: %s.\n",
                      interface->pInterfaceName);
        goto ret;
    }
    v = (CK_VERSION *)interface->pFunctionList;
    printf("%s\n", "Vendor defined interface (IBM):");
    printf("pInterfaceName         %s\n", interface->pInterfaceName);
    printf("pFunctionList version  %u.%u\n", v->major, v->minor);
    printf("flags                  0x%016lx\n", interface->flags);

    version.major = 2;
    version.minor = 40;
    flags = 0ULL;
    rv = funcs3->C_GetInterface((CK_UTF8CHAR *)"PKCS 11",
                                &version, &interface, flags);
    if (rv != CKR_OK) {
        testcase_fail("C_GetInterface returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }
    if (strcmp((char *)interface->pInterfaceName, "PKCS 11") != 0) {
        testcase_fail("Returned interface name: %s.\n",
                      interface->pInterfaceName);
        goto ret;
    }
    v = (CK_VERSION *)interface->pFunctionList;
    if (v->major != version.major || v->minor != version.minor) {
        testcase_fail("Returned version: %u.%u.\n", v->major, v->minor);
        goto ret;
    }
    printf("%s\n", "PKCS #11 version 2.40 interface:");
    printf("pInterfaceName         %s\n", interface->pInterfaceName);
    printf("pFunctionList version  %u.%u\n", v->major, v->minor);
    printf("flags                  0x%016lx\n", interface->flags);

    version.major = 3;
    version.minor = 0;
    flags = 0ULL;
    rv = funcs3->C_GetInterface((CK_UTF8CHAR *)"PKCS 11",
                                &version, &interface, flags);
    if (rv != CKR_OK) {
        testcase_fail("C_GetInterface returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }
    if (strcmp((char *)interface->pInterfaceName, "PKCS 11") != 0) {
        testcase_fail("Returned interface name: %s.\n",
                           interface->pInterfaceName);
        goto ret;
    }
    v = (CK_VERSION *)interface->pFunctionList;
    if (v->major != version.major || v->minor != version.minor) {
        testcase_fail("Returned version: %u.%u.\n", v->major, v->minor);
        goto ret;
    }
    printf("%s\n", "PKCS #11 version 3.0 interface:");
    printf("pInterfaceName         %s\n", interface->pInterfaceName);
    printf("pFunctionList version  %u.%u\n", v->major, v->minor);
    printf("flags                  0x%016lx\n", interface->flags);

    tfn = (CK_FUNCTION_LIST_3_0 *)interface->pFunctionList;
    if (tfn->C_Initialize == NULL
        || tfn->C_Finalize == NULL
        || tfn->C_GetInfo == NULL
        || tfn->C_GetFunctionList == NULL
        || tfn->C_GetSlotList == NULL
        || tfn->C_GetSlotInfo == NULL
        || tfn->C_GetTokenInfo == NULL
        || tfn->C_GetMechanismList == NULL
        || tfn->C_GetMechanismInfo == NULL
        || tfn->C_InitToken == NULL
        || tfn->C_InitPIN == NULL
        || tfn->C_SetPIN == NULL
        || tfn->C_OpenSession == NULL
        || tfn->C_CloseSession == NULL
        || tfn->C_CloseAllSessions == NULL
        || tfn->C_GetSessionInfo == NULL
        || tfn->C_GetOperationState == NULL
        || tfn->C_SetOperationState == NULL
        || tfn->C_Login == NULL
        || tfn->C_Logout == NULL
        || tfn->C_CreateObject == NULL
        || tfn->C_CopyObject == NULL
        || tfn->C_DestroyObject == NULL
        || tfn->C_GetObjectSize == NULL
        || tfn->C_GetAttributeValue == NULL
        || tfn->C_SetAttributeValue == NULL
        || tfn->C_FindObjectsInit == NULL
        || tfn->C_FindObjects == NULL
        || tfn->C_FindObjectsFinal == NULL
        || tfn->C_EncryptInit == NULL
        || tfn->C_Encrypt == NULL
        || tfn->C_EncryptUpdate == NULL
        || tfn->C_EncryptFinal == NULL
        || tfn->C_DecryptInit == NULL
        || tfn->C_Decrypt == NULL
        || tfn->C_DecryptUpdate == NULL
        || tfn->C_DecryptFinal == NULL
        || tfn->C_DigestInit == NULL
        || tfn->C_Digest == NULL
        || tfn->C_DigestUpdate == NULL
        || tfn->C_DigestKey == NULL
        || tfn->C_DigestFinal == NULL
        || tfn->C_SignInit == NULL
        || tfn->C_Sign == NULL
        || tfn->C_SignUpdate == NULL
        || tfn->C_SignFinal == NULL
        || tfn->C_SignRecoverInit == NULL
        || tfn->C_SignRecover == NULL
        || tfn->C_VerifyInit == NULL
        || tfn->C_Verify == NULL
        || tfn->C_VerifyUpdate == NULL
        || tfn->C_VerifyFinal == NULL
        || tfn->C_VerifyRecoverInit == NULL
        || tfn->C_VerifyRecover == NULL
        || tfn->C_DigestEncryptUpdate == NULL
        || tfn->C_DecryptDigestUpdate == NULL
        || tfn->C_SignEncryptUpdate == NULL
        || tfn->C_DecryptVerifyUpdate == NULL
        || tfn->C_GenerateKey == NULL
        || tfn->C_GenerateKeyPair == NULL
        || tfn->C_WrapKey == NULL
        || tfn->C_UnwrapKey == NULL
        || tfn->C_DeriveKey == NULL
        || tfn->C_SeedRandom == NULL
        || tfn->C_GenerateRandom == NULL
        || tfn->C_GetFunctionStatus == NULL
        || tfn->C_CancelFunction == NULL
        || tfn->C_WaitForSlotEvent == NULL
        /* Additional PKCS #11 3.0 functions */
        || tfn->C_GetInterfaceList == NULL
        || tfn->C_GetInterface == NULL
        || tfn->C_LoginUser == NULL
        || tfn->C_SessionCancel == NULL
        || tfn->C_MessageEncryptInit == NULL
        || tfn->C_EncryptMessage == NULL
        || tfn->C_EncryptMessageBegin == NULL
        || tfn->C_EncryptMessageNext == NULL
        || tfn->C_MessageEncryptFinal == NULL
        || tfn->C_MessageDecryptInit == NULL
        || tfn->C_DecryptMessage == NULL
        || tfn->C_DecryptMessageBegin == NULL
        || tfn->C_DecryptMessageNext == NULL
        || tfn->C_MessageDecryptFinal == NULL
        || tfn->C_MessageSignInit == NULL
        || tfn->C_SignMessage == NULL
        || tfn->C_SignMessageBegin == NULL
        || tfn->C_SignMessageNext == NULL
        || tfn->C_MessageSignFinal == NULL
        || tfn->C_MessageVerifyInit == NULL
        || tfn->C_VerifyMessage == NULL
        || tfn->C_VerifyMessageBegin == NULL
        || tfn->C_VerifyMessageNext == NULL
        || tfn->C_MessageVerifyFinal == NULL) {
        testcase_fail("%s", "Returned CK_FUNCTION_LIST_3_0 contains"
                      " a NULL function pointer.\n");
        goto ret;
    }
    /*
     * Function pointers are != NULL.
     * Now check if they are valid.
     */
    slot = 0;
    tfn->C_Initialize(NULL);
    tfn->C_Finalize(NULL);
    tfn->C_GetInfo(NULL);
    tfn->C_GetFunctionList(NULL);
    tfn->C_GetSlotList(CK_FALSE, NULL, NULL);
    tfn->C_GetSlotInfo(slot, NULL);
    tfn->C_GetTokenInfo(slot, NULL);
    tfn->C_GetMechanismList(slot, NULL, NULL);
    tfn->C_GetMechanismInfo(slot, 0UL, NULL);
    tfn->C_InitToken(slot, NULL, 0UL, NULL);
    tfn->C_InitPIN(0UL, NULL, 0UL);
    tfn->C_SetPIN(0UL, NULL, 0UL, NULL, 0UL);
    tfn->C_OpenSession(slot, 0UL, NULL, NULL, NULL);
    tfn->C_CloseSession(0UL);
    tfn->C_CloseAllSessions(slot);
    tfn->C_GetSessionInfo(0UL, NULL);
    tfn->C_GetOperationState(0UL, NULL, NULL);
    tfn->C_SetOperationState(0UL, NULL, 0UL, 0UL, 0UL);
    tfn->C_Login(0UL, 0UL, NULL, 0UL);
    tfn->C_Logout(0UL);
    tfn->C_CreateObject(0UL, NULL, 0UL, NULL);
    tfn->C_CopyObject(0UL, 0UL, NULL, 0UL, NULL);
    tfn->C_DestroyObject(0UL, 0UL);
    tfn->C_GetObjectSize(0UL, 0UL, NULL);
    tfn->C_GetAttributeValue(0UL, 0UL, NULL, 0UL);
    tfn->C_SetAttributeValue(0UL, 0UL, NULL, 0UL);
    tfn->C_FindObjectsInit(0UL, NULL, 0UL);
    tfn->C_FindObjects(0UL, NULL, 0UL, NULL);
    tfn->C_FindObjectsFinal(0UL);
    tfn->C_EncryptInit(0UL, NULL, 0UL);
    tfn->C_Encrypt(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_EncryptUpdate(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_EncryptFinal(0UL, NULL, NULL);
    tfn->C_DecryptInit(0UL, NULL, 0UL);
    tfn->C_Decrypt(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_DecryptUpdate(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_DecryptFinal(0UL, NULL, NULL);
    tfn->C_DigestInit(0UL, NULL);
    tfn->C_Digest(0UL, NULL, 0UL, NULL, 0UL);
    tfn->C_DigestUpdate(0UL, NULL, 0UL);
    tfn->C_DigestKey(0UL, 0UL);
    tfn->C_DigestFinal(0UL, NULL, NULL);
    tfn->C_SignInit(0UL, NULL, 0UL);
    tfn->C_Sign(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_SignUpdate(0UL, NULL, 0UL);
    tfn->C_SignFinal(0UL, NULL, NULL);
    tfn->C_SignRecoverInit(0UL, NULL, 0UL);
    tfn->C_SignRecover(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_VerifyInit(0UL, NULL, 0UL);
    tfn->C_Verify(0UL, NULL, 0UL, NULL, 0UL);
    tfn->C_VerifyUpdate(0UL, NULL, 0UL);
    tfn->C_VerifyFinal(0UL, NULL, 0UL);
    tfn->C_VerifyRecoverInit(0UL, NULL, 0UL);
    tfn->C_VerifyRecover(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_DigestEncryptUpdate(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_DecryptDigestUpdate(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_SignEncryptUpdate(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_DecryptVerifyUpdate(0UL, NULL, 0UL, NULL, NULL);
    tfn->C_GenerateKey(0UL, NULL, NULL, 0UL, NULL);
    tfn->C_GenerateKeyPair(0UL, NULL, NULL, 0UL, NULL, 0UL, NULL, NULL);
    tfn->C_WrapKey(0UL, NULL, 0UL, 0UL, NULL, NULL);
    tfn->C_UnwrapKey(0UL, NULL, 0UL, NULL, 0UL, NULL, 0UL, NULL);
    tfn->C_DeriveKey(0UL, NULL, 0UL, NULL, 0UL, NULL);
    tfn->C_SeedRandom(0UL, NULL, 0UL);
    tfn->C_GenerateRandom(0UL, NULL, 0UL);
    tfn->C_GetFunctionStatus(0UL);
    tfn->C_CancelFunction(0UL);
    tfn->C_WaitForSlotEvent(0UL, &slot, NULL);
    /* Additional PKCS #11 3.0 functions */
    tfn->C_GetInterfaceList(NULL, NULL);
    tfn->C_GetInterface(NULL, NULL, NULL, 0UL);
    tfn->C_LoginUser(0UL, 0UL, NULL, 0UL, NULL, 0UL);
    tfn->C_SessionCancel(0UL, 0UL);
    tfn->C_MessageEncryptInit(0UL, NULL, 0UL);
    tfn->C_EncryptMessage(0UL, NULL, 0UL, NULL, 0UL, NULL, 0UL, NULL, 0UL);
    tfn->C_EncryptMessageBegin(0UL, NULL, 0UL, NULL, 0UL);
    tfn->C_EncryptMessageNext(0UL, NULL, 0UL, NULL, 0UL, NULL, NULL, 0UL);
    tfn->C_MessageEncryptFinal(0UL);
    tfn->C_MessageDecryptInit(0UL, NULL, 0UL);
    tfn->C_DecryptMessage(0UL, NULL, 0UL, NULL, 0UL, NULL, 0UL, NULL, 0UL);
    tfn->C_DecryptMessageBegin(0UL, NULL, 0UL, NULL, 0UL);
    tfn->C_DecryptMessageNext(0UL, NULL, 0UL, NULL, 0UL, NULL, NULL, 0UL);
    tfn->C_MessageDecryptFinal(0UL);
    tfn->C_MessageSignInit(0UL, NULL, 0UL);
    tfn->C_SignMessage(0UL, NULL, 0UL, NULL, 0UL, NULL, NULL);
    tfn->C_SignMessageBegin(0UL, NULL, 0UL);
    tfn->C_SignMessageNext(0UL, NULL, 0UL, NULL, 0UL, NULL, NULL);
    tfn->C_MessageSignFinal(0UL);
    tfn->C_MessageVerifyInit(0UL, NULL, 0UL);
    tfn->C_VerifyMessage(0UL, NULL, 0UL, NULL, 0UL, NULL, 0UL);
    tfn->C_VerifyMessageBegin(0UL, NULL, 0UL);
    tfn->C_VerifyMessageNext(0UL, NULL, 0UL, NULL, 0UL, NULL, 0UL);
    tfn->C_MessageVerifyFinal(0UL);

    testcase_pass("C_GetInterface works.\n");
    rc = 0;
ret:
    return rc;
}

static int get_interface_list_test(void)
{
    CK_INTERFACE *il = NULL;
    CK_ULONG nmemb = 0UL, i;
    CK_VERSION *version;
    CK_RV rv;
    int rc = -1;

    testcase_new_assertion();

    rv = funcs3->C_GetInterfaceList(NULL, NULL);
    if (rv != CKR_ARGUMENTS_BAD) {
        testcase_fail("C_GetInterfaceList returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }

    rv = funcs3->C_GetInterfaceList(NULL, &nmemb);
    if (rv != CKR_OK) {
        testcase_fail("C_GetInterfaceList returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }
    if (nmemb == 0) {
        testcase_fail("C_GetInterfaceList interface list has"
                      " %lu elements.\n", nmemb);
        goto ret;
    }

    il = calloc(nmemb, sizeof(*il));
    if (il == NULL) {
        testcase_error("calloc failed.\n");
        goto ret;
    }

    nmemb--;
    rv = funcs3->C_GetInterfaceList(il, &nmemb);
    if (rv != CKR_BUFFER_TOO_SMALL) {
        testcase_fail("C_GetInterfaceList returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }

    rv = funcs3->C_GetInterfaceList(il, &nmemb);
    if (rv != CKR_OK) {
        testcase_fail("C_GetInterfaceList returned %s.\n", p11_get_ckr(rv));
        goto ret;
    }

    for (i = 0UL; i < nmemb; i++) {
        if (strncmp((char *)il[i].pInterfaceName,
                    "PKCS 11", strlen("PKCS 11")) != 0
            && strncmp((char *)il[i].pInterfaceName,
                       "Vendor ", strlen("Vendor ")) != 0) {
            testcase_fail("Invalid interface name.\n");
            goto ret;
	}

        if (il[i].pFunctionList == NULL) {
            testcase_fail("%s", "Interface with NULL function list.\n");
            goto ret;
	}

        if ((il[i].flags & ~CKF_INTERFACE_FORK_SAFE) != 0) {
            testcase_fail("Interface with unknown flags: 0x%016lx.\n",
                          il[i].flags);
            goto ret;
        }

        version = (CK_VERSION *)il[i].pFunctionList;

        printf("Interface %lu:\n", i);
        printf("pInterfaceName         %s\n", il[i].pInterfaceName);
        printf("pFunctionList version  %u.%u\n",
               version->major, version->minor);
        printf("flags                  0x%016lx\n", il[i].flags);
    }

    testcase_pass("C_GetInterfaceList works.\n");
    rc = 0;
ret:
    free(il);
    return rc;
}

int main(void)
{
    int rc = -1;

    testcase_setup();

    if (do_GetFunctionList() != TRUE) {
        testcase_error("%s", "do_GetFunctionList() failed.\n");
        goto ret;
    }

    rc = get_interface_list_test();
    if (rc)
        goto ret;

    rc = get_interface_test();

ret:
    testcase_print_result();
    return testcase_return(rc);
}
