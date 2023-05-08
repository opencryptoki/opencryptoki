/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File: multi_instance.c
 *
 * Test driver.  In-depth regression test for PKCS #11
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>

#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "pkcs11types.h"
#include "regress.h"

CK_RV do_GenerateTokenRSAKeyPair(CK_SLOT_ID slot_id, CK_SESSION_HANDLE sess,
                                 CK_BYTE *label, CK_ULONG bits,
                                 CK_OBJECT_HANDLE *hPubKey,
                                 CK_OBJECT_HANDLE *hPrivKey)
{
    CK_MECHANISM mech;
    CK_RV rv;
    CK_MECHANISM_INFO rsakeygeninfo;
    CK_BBOOL false = 0;
    CK_BYTE pub_exp[] = { 0x1, 0x0, 0x1 };
    CK_ATTRIBUTE pub_tmpl[] = {
        {CKA_MODULUS_BITS, &bits, sizeof(bits)},
        {CKA_PUBLIC_EXPONENT, &pub_exp, sizeof(pub_exp)},
        {CKA_LABEL, label, (CK_ULONG) strlen((char *) label) + 1},
        {CKA_TOKEN, &false, sizeof(CK_BBOOL)}
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        {CKA_LABEL, label, (CK_ULONG) strlen((char *) label) + 1},
        {CKA_TOKEN, &false, sizeof(CK_BBOOL)}
    };

    rv = funcs->C_GetMechanismInfo(slot_id, CKM_RSA_PKCS_KEY_PAIR_GEN,
                                   &rsakeygeninfo);
    if (rv != CKR_OK) {
        testcase_fail("C_GetMechanismInfo(CKM_RSA_PKCS_KEY_PAIR_GEN) rc = %s", p11_get_ckr(rv));
        return rv;
    }

    mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_GenerateKeyPair(sess, &mech, pub_tmpl, 4, priv_tmpl, 2,
                                  hPubKey, hPrivKey);
    if (rv != CKR_OK) {
        testcase_fail("C_GenerateKeyPair rc = %s", p11_get_ckr(rv));
        return rv;
    }
    return CKR_OK;
}


int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int i, ret = 1;
    CK_BYTE user_pin[128];
    CK_ULONG user_pin_len;
    CK_BYTE label[256];
    CK_SLOT_ID slot_id1 = 1, slot_id2 = 2;
    CK_RV rv;
    CK_SESSION_HANDLE session1 = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session2 = CK_INVALID_HANDLE;
    CK_FLAGS flags;
    CK_OBJECT_HANDLE hPubKey1, hPrivKey1;
    CK_OBJECT_HANDLE hPubKey2, hPrivKey2;
    CK_BBOOL false = 0;
    CK_OBJECT_HANDLE obj_list[10];
    CK_ULONG num_objs, num_wrong;

    CK_ATTRIBUTE attrs[] = {
        {CKA_LABEL, label, sizeof(label) - 1},
    };

    CK_ATTRIBUTE search_tmpl[] = {
        {CKA_TOKEN, &false, sizeof(false)},
    };

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-slot1") == 0) {
            ++i;
            if (i >= argc) {
                printf("Slot number missing\n");
                return -1;
            }
            slot_id1 = atoi(argv[i]);
        }
        else if (strcmp(argv[i], "-slot2") == 0) {
            ++i;
            if (i >= argc) {
                printf("Slot number missing\n");
                return -1;
            }
            slot_id2 = atoi(argv[i]);
        }

        if (strcmp(argv[i], "-h") == 0) {
            printf("usage:  %s [-slot1 <num>] [-slot2 <num>] [-h]\n\n", argv[0]);
            printf("By default, Slot #1 and #2 are used\n\n");
            return -1;
        }
    }

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;
    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    printf("Using slots #%lu and #%lu...\n\n", slot_id1, slot_id2);

    rv = do_GetFunctionList();
    if (rv != TRUE) {
        testcase_fail("do_GetFunctionList() rc = %s", p11_get_ckr(rv));
        goto out;
    }

    testcase_setup();
    testcase_begin("Starting...");

    // Initialize
    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    if ((rv = funcs->C_Initialize(&cinit_args))) {
        testcase_fail("C_Initialize() rc = %s", p11_get_ckr(rv));
        goto out;
    }

    // Open Session and login for slot 1
    testcase_new_assertion();
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = funcs->C_OpenSession(slot_id1, flags, NULL, NULL, &session1);
    if (rv != CKR_OK) {
        testcase_fail("C_OpenSession() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto finalize;
    }
    testcase_pass("C_OpenSession on slot %lu", slot_id1);

    testcase_new_assertion();
    rv = funcs->C_Login(session1, CKU_USER, user_pin, user_pin_len);
    if (rv != CKR_OK) {
        testcase_fail("C_Login() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto close_session;
    }
    testcase_pass("C_Login as User on slot %lu", slot_id1);

    // Open Session and login for slot 2
    testcase_new_assertion();
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = funcs->C_OpenSession(slot_id2, flags, NULL, NULL, &session2);
    if (rv != CKR_OK) {
        testcase_fail("C_OpenSession() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto close_session;
    }
    testcase_pass("C_OpenSession on slot %lu", slot_id2);

    testcase_new_assertion();
    rv = funcs->C_Login(session2, CKU_USER, user_pin, user_pin_len);
    if (rv != CKR_OK) {
        testcase_fail("C_Login() on slot %lu rc = %s\n", slot_id1, p11_get_ckr(rv));
        // ignore error
    } else {
        testcase_pass("C_Login as User on slot %lu", slot_id2);
    }

    // generate a key pair for slot 1
    testcase_new_assertion();
    rv = do_GenerateTokenRSAKeyPair(slot_id1, session1,
                                    (CK_BYTE *)"RSA-2048-SLOT1",
                                    2048, &hPubKey1, &hPrivKey1);
    if (rv != CKR_OK) {
        testcase_fail("do_GenerateTokenRSAKeyPair() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto close_session;
    }
    testcase_pass("do_GenerateTokenRSAKeyPair on slot %lu", slot_id1);

    // generate a key pair for slot 2
    testcase_new_assertion();
    rv = do_GenerateTokenRSAKeyPair(slot_id2, session2,
                                    (CK_BYTE *)"RSA-2048-SLOT2",
                                    2048, &hPubKey2, &hPrivKey2);
    if (rv != CKR_OK) {
        testcase_fail("do_GenerateTokenRSAKeyPair() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto close_session;
    }
    testcase_pass("do_GenerateTokenRSAKeyPair on slot %lu", slot_id2);

    // Try to access an object from session2 in session 1
    testcase_new_assertion();
    attrs[0].ulValueLen = sizeof(label) - 1;
    memset(label, 0, sizeof(label));
    rv = funcs->C_GetAttributeValue(session1, hPubKey2, attrs, 1);
    if (rv == CKR_OK) {
        // different sessions may use the same object handle namespace, so the
        // object handle may actually be valid. Check the returned label to
        // check if it is our object (expected), or the one from the other
        // session
        label[attrs[0].ulValueLen] = '\0';
        if (strcmp((char *)label, "RSA-2048-SLOT1") == 0) {
            testcase_pass("C_GetAttributeValue for hPubKey2 on slot %lu got our object", slot_id1);
        } else if (strcmp((char *)label, "RSA-2048-SLOT2") == 0) {
            testcase_fail("C_GetAttributeValue for hPubKey2 on slot %lu got foreign object: %s\n", slot_id1, label);
        } else {
            testcase_pass("C_GetAttributeValue for hPubKey2 on slot %lu got a totaly different object", slot_id1);
        }
    }
    else if (rv != CKR_OBJECT_HANDLE_INVALID) {
        testcase_fail("C_GetAttributeValue for hPubKey2 on slot %lu rc = %s (expected CKR_OBJECT_HANDLE_INVALID)\n", slot_id1, p11_get_ckr(rv));
    } else {
        testcase_pass("C_GetAttributeValue for hPubKey2 on slot %lu got expected error", slot_id1);
    }

    // Try to access an object from session1 in session 2
    testcase_new_assertion();
    attrs[0].ulValueLen = sizeof(label) - 1;
    memset(label, 0, sizeof(label));
    rv = funcs->C_GetAttributeValue(session2, hPubKey1, attrs, 1);
    if (rv == CKR_OK) {
        // different sessions may use the same object handle namespace, so the
        // object handle may actually be valid. Check the returned label to
        // check if it is our object (expected), or the one from the other
        // session
        label[attrs[0].ulValueLen] = '\0';
        if (strcmp((char *)label, "RSA-2048-SLOT2") == 0) {
            testcase_pass("C_GetAttributeValue for hPubKey2 on slot %lu got our object", slot_id2);
        } else if (strcmp((char *)label, "RSA-2048-SLOT1") == 0) {
            testcase_fail("C_GetAttributeValue for hPubKey2 on slot %lu got foreign object: %s\n", slot_id2, label);
        } else {
            testcase_pass("C_GetAttributeValue for hPubKey2 on slot %lu got a totaly different object", slot_id2);
        }
    }
    else if (rv != CKR_OBJECT_HANDLE_INVALID) {
        testcase_fail("C_GetAttributeValue for hPubKey1 on slot %lu rc = %s (expected CKR_OBJECT_HANDLE_INVALID)\n", slot_id2, p11_get_ckr(rv));
    } else {
        testcase_pass("C_GetAttributeValue for hPubKey1 on slot %lu got expected error", slot_id2);
    }

    // Find all session object of session 1
    testcase_new_assertion();
    rv = funcs->C_FindObjectsInit(session1, search_tmpl, 1);
    if (rv != CKR_OK) {
        testcase_fail("C_FindObjectsInit() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto close_session;
    }

    num_objs = 0;
    rv = funcs->C_FindObjects(session1, obj_list, 10, &num_objs);
    if (rv != CKR_OK) {
        testcase_fail("C_FindObjects() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto close_session;
    }

    /* We should have gotten back 2 RSA key objects */
    if (num_objs != 2) {
        testcase_fail("C_FindObjects() on slot %lu found %lu objects (expected 2)\n", slot_id1, num_objs);
    } else {
        testcase_pass("C_FindObjects() on slot %lu found %lu objects (as expected)", slot_id1, num_objs);
    }

     /* Examine the 2 objects... */
    testcase_new_assertion();
    num_wrong = 0;
    for (i = 0; i < (int)num_objs; i++) {
        // Check the label
        attrs[0].ulValueLen = sizeof(label) - 1;
        memset(label, 0, sizeof(label));
        rv = funcs->C_GetAttributeValue(session1, obj_list[i], attrs, 1);
        if (rv != CKR_OK ||
            strcmp((char *)label, "RSA-2048-SLOT1") != 0) {
            num_wrong++;
            testcase_fail("C_FindObjects() on slot %lu found foreign object: %s\n", slot_id1, label);
        }
    }
    if (num_wrong == 0) {
        testcase_pass("C_FindObjects() on slot %lu found expected objects", slot_id1);
    }

    rv = funcs->C_FindObjectsFinal(session1);
    if (rv != CKR_OK) {
        testcase_fail("C_FindObjectsFinal() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto close_session;
    }

    // Find all session object of session 2
    testcase_new_assertion();
    rv = funcs->C_FindObjectsInit(session2, search_tmpl, 1);
    if (rv != CKR_OK) {
        testcase_fail("C_FindObjectsInit() on slot %lu rc = %s", slot_id2, p11_get_ckr(rv));
        goto close_session;
    }

    num_objs = 0;
    rv = funcs->C_FindObjects(session2, obj_list, 10, &num_objs);
    if (rv != CKR_OK) {
        testcase_fail("C_FindObjects() on slot %lu rc = %s", slot_id2, p11_get_ckr(rv));
        goto close_session;
    }

    /* We should have gotten back 2 RSA key objects */
    if (num_objs != 2) {
        testcase_fail("C_FindObjects() on slot %lu found %lu objects (expected 2)\n", slot_id2, num_objs);
    } else {
        testcase_pass("C_FindObjects() on slot %lu found %lu objects (as expected)", slot_id2, num_objs);
    }

     /* Examine the 2 objects... */
    testcase_new_assertion();
    num_wrong = 0;
    for (i = 0; i < (int)num_objs; i++) {
        // Check the label
        attrs[0].ulValueLen = sizeof(label) - 1;
        memset(label, 0, sizeof(label));
        rv = funcs->C_GetAttributeValue(session2, obj_list[i], attrs, 1);
        if (rv != CKR_OK ||
            strcmp((char *)label, "RSA-2048-SLOT2") != 0) {
            num_wrong++;
            testcase_fail("C_FindObjects() on slot %lu found foreign object: %s\n", slot_id2, label);
            //goto close_session;
        }
    }
    if (num_wrong == 0) {
        testcase_pass("C_FindObjects() on slot %lu found expected objects", slot_id2);
    }

    rv = funcs->C_FindObjectsFinal(session2);
    if (rv != CKR_OK) {
        testcase_fail("C_FindObjectsFinal() on slot %lu rc = %s", slot_id2, p11_get_ckr(rv));
        goto close_session;
    }

    // destroy objects for slot_id 1
    rv = funcs->C_DestroyObject(session1, hPubKey1);
    if (rv != CKR_OK) {
        testcase_fail("C_DestroyObject() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto close_session;
    }

    rv = funcs->C_DestroyObject(session1, hPrivKey1);
    if (rv != CKR_OK) {
        testcase_fail("C_DestroyObject() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto close_session;
    }

    // destroy objects for slot_id 2
    rv = funcs->C_DestroyObject(session2, hPubKey2);
    if (rv != CKR_OK) {
        testcase_fail("C_DestroyObject() on slot %lu rc = %s", slot_id2, p11_get_ckr(rv));
        goto close_session;
    }

    rv = funcs->C_DestroyObject(session2, hPrivKey2);
    if (rv != CKR_OK) {
        testcase_fail("C_DestroyObject() on slot %lu rc = %s", slot_id2, p11_get_ckr(rv));
        goto close_session;
    }

    // close all sessions of slot 1
    testcase_new_assertion();
    rv = funcs->C_CloseAllSessions(slot_id1);
    if (rv != CKR_OK) {
        testcase_fail("C_CloseAllSessions() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        goto close_session;
    }

    // Close session 2 (should still be valid)
    rv = funcs->C_CloseSession(session2);
    if (rv != CKR_OK) {
        testcase_fail("C_CloseSession() on slot %lu rc = %s", slot_id2, p11_get_ckr(rv));
        goto finalize;
    }
    testcase_pass("C_CloseAllSessions() on slot %lu only closed sessions of slot %lu", slot_id1, slot_id1);

    ret = 0;
    goto finalize;

close_session:
    if (session1 != CK_INVALID_HANDLE) {
        rv = funcs->C_CloseSession(session1);
        if (rv != CKR_OK) {
            testcase_fail("C_CloseSession() on slot %lu rc = %s", slot_id1, p11_get_ckr(rv));
        }
    }
    if (session2 != CK_INVALID_HANDLE) {
        rv = funcs->C_CloseSession(session2);
        if (rv != CKR_OK) {
            testcase_fail("C_CloseSession() on slot %lu rc = %s", slot_id2, p11_get_ckr(rv));
        }
    }
finalize:
    rv = funcs->C_Finalize(NULL);
    if (rv != CKR_OK) {
        testcase_fail("C_Finalize() rc = %s", p11_get_ckr(rv));
    }
out:
    testcase_print_result();
    return testcase_return(ret);
}
