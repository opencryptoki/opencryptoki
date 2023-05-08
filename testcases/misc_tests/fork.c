/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File: fork.c
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
#include "common.c"

CK_BYTE user_pin[128];
CK_ULONG user_pin_len;
CK_SLOT_ID slot_id = 0;

CK_RV do_GenerateTokenRSAKeyPair(CK_SESSION_HANDLE sess, CK_BYTE *label,
                                 CK_ULONG bits, CK_OBJECT_HANDLE *hPubKey,
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
        if (rv == CKR_MECHANISM_INVALID) {
            testcase_skip("Mechanism CKM_RSA_PKCS_KEY_PAIR_GEN not supported");
            return CKR_POLICY_VIOLATION;
        }
        testcase_fail("C_GetMechanismInfo(CKM_RSA_PKCS_KEY_PAIR_GEN) rc = %s", p11_get_ckr(rv));
        return rv;
    }

    mech.mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rv = funcs->C_GenerateKeyPair(sess, &mech, pub_tmpl, 4, priv_tmpl, 2,
                                  hPubKey, hPrivKey);
    if (rv != CKR_OK) {
        if (is_rejected_by_policy(rv, sess)) {
            testcase_skip("Key generation is not allowed by policy");
            return CKR_POLICY_VIOLATION;
        }

        testcase_fail("C_GenerateKeyPair rc = %s", p11_get_ckr(rv));
        return rv;
    }
    return CKR_OK;
}

CK_RV do_fork(CK_SESSION_HANDLE parent_session, CK_OBJECT_HANDLE parent_object)
{
    pid_t child_pid;
    int status = 1;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_RV rv;
    CK_C_INITIALIZE_ARGS cinit_args;
    CK_OBJECT_HANDLE hPubKey, hPrivKey;

    child_pid = fork();
    if (child_pid != 0) {
        // parent process: wait until child exits
        waitpid(child_pid, &status, 0);
        return status;
    }

    // child process flows here
    testcase_setup();
    t_ran = 0;
    t_passed = 0;
    t_skipped = 0;
    t_failed = 0;
    testcase_begin(".. in client process: %u", getpid());

    // Ensure that OCK is not initialized in this fork now
    testcase_new_assertion();
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
    if (rv != CKR_CRYPTOKI_NOT_INITIALIZED) {
        testcase_fail("C_OpenSession (client) (expected CKR_CRYPTOKI_NOT_INITIALIZED) rc = %s", p11_get_ckr(rv));
        goto out;
    }
    testcase_pass("C_OpenSession (client)");

    // Initialize
    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;
    if ((rv = funcs->C_Initialize(&cinit_args))) {
        testcase_fail("C_Initialize (client) rc = %s", p11_get_ckr(rv));
        goto out;
    }

    // Check access to parent session
    if (parent_session != CK_INVALID_HANDLE) {
        testcase_new_assertion();
        rv = funcs->C_CloseSession(parent_session);
        if (rv != CKR_SESSION_HANDLE_INVALID) {
            testcase_fail("C_CloseSession (client) (expected CKR_SESSION_HANDLE_INVALID) rc = %s", p11_get_ckr(rv));
            goto close_session;
        }
        testcase_pass("C_CloseSession got expected error (client)");
    }

    // Open a session
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
    if (rv != CKR_OK) {
        testcase_fail("C_OpenSession (client) rc = %s", p11_get_ckr(rv));
        goto finalize;
    }

    // Log in
    rv = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
    if (rv != CKR_OK) {
        testcase_fail("C_Login (client) rc = %s", p11_get_ckr(rv));
        goto close_session;
    }

    // Check access to parent object
    if (parent_object != CK_INVALID_HANDLE) {
        testcase_new_assertion();
        rv = funcs->C_DestroyObject(session, parent_object);
        if (rv != CKR_OBJECT_HANDLE_INVALID) {
            testcase_fail("C_DestroyObject (client) (expected CKR_OBJECT_HANDLE_INVALID) rc = %s", p11_get_ckr(rv));
            goto close_session;
        }
        testcase_pass("C_DestroyObject got expected error (client)");
    }

    // generate a key pair
    rv = do_GenerateTokenRSAKeyPair(session, (CK_BYTE *)"RSA-2048-CLIENT",
                                    2048, &hPubKey, &hPrivKey);
    if (rv != CKR_OK) {
        if (rv == CKR_POLICY_VIOLATION) {
            rv = 0;
            goto close_session;
        }
        testcase_fail("do_GenerateTokenRSAKeyPair (client) rc = %s", p11_get_ckr(rv));
        goto close_session;
    }

    rv = funcs->C_DestroyObject(session, hPubKey);
    if (rv != CKR_OK) {
        testcase_fail("C_DestroyObject (client) rc = %s", p11_get_ckr(rv));
        goto close_session;
    }

    rv = funcs->C_DestroyObject(session, hPrivKey);
    if (rv != CKR_OK) {
        testcase_fail("C_DestroyObject (client) rc = %s", p11_get_ckr(rv));
        goto close_session;
    }

    rv = 0;
close_session:
    rv = funcs->C_CloseSession(session);
    if (rv != CKR_OK) {
        testcase_fail("C_CloseSession (client) rc = %s", p11_get_ckr(rv));
    }
finalize:
    rv = funcs->C_Finalize(NULL);
    if (rv != CKR_OK) {
        testcase_fail("C_Finalize (client) rc = %s", p11_get_ckr(rv));
        goto out;
    }
out:

    testcase_print_result();
    exit(testcase_return(rv));
}

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int i, ret = 1;
    CK_RV rv;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_OBJECT_HANDLE hPubKey, hPrivKey;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-slot") == 0) {
            ++i;
            if (i >= argc) {
                printf("Slot number missing\n");
                return -1;
            }
            slot_id = atoi(argv[i]);
        }

        if (strcmp(argv[i], "-h") == 0) {
            printf("usage:  %s [-slot <num>] [-h]\n\n", argv[0]);
            printf("By default, Slot #1 is used\n\n");
            return -1;
        }
    }

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;
    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    printf("Using slot #%lu...\n\n", slot_id);

    rv = do_GetFunctionList();
    if (rv != TRUE) {
        testcase_fail("do_GetFunctionList() rc = %s", p11_get_ckr(rv));
        goto out;
    }

    testcase_setup();
    testcase_begin("Starting...  Parent process: %u", getpid());

    // Test fork before C_Initialize
    testcase_new_assertion();
    rv = do_fork(CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    if (rv != CKR_OK) {
        testcase_fail("do_fork() before C_Initialize rc = %s", p11_get_ckr(rv));
        goto out;
    }
    testcase_pass("do_fork() before C_Initialize");

    // Initialize
    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    if ((rv = funcs->C_Initialize(&cinit_args))) {
        testcase_fail("C_Initialize (parent) rc = %s", p11_get_ckr(rv));
        goto out;
    }

    // Test fork after C_Initialize
    testcase_new_assertion();
    rv = do_fork(CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    if (rv != CKR_OK) {
        testcase_fail("do_fork() after C_Initialize rc = %s", p11_get_ckr(rv));
        goto out;
    }
    testcase_pass("do_fork() after C_Initialize");

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
    if (rv != CKR_OK) {
        testcase_fail("C_OpenSession (parent) rc = %s", p11_get_ckr(rv));
        goto finalize;
    }

    rv = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
    if (rv != CKR_OK) {
        testcase_fail("C_Login (parent) rc = %s", p11_get_ckr(rv));
        goto close_session;
    }

    // Test fork after C_OpenSession/C_Login
    testcase_new_assertion();
    rv = do_fork(session, CK_INVALID_HANDLE);
    if (rv != CKR_OK) {
        testcase_fail("do_fork() after C_OpenSession rc = %s", p11_get_ckr(rv));
        goto out;
    }
    testcase_pass("do_fork() after C_OpenSession");

    // generate a key pair
    rv = do_GenerateTokenRSAKeyPair(session, (CK_BYTE *)"RSA-2048-PARENT",
                                    2048, &hPubKey, &hPrivKey);
    if (rv != CKR_OK) {
        if (rv == CKR_POLICY_VIOLATION) {
            ret = 0;
            goto close_session;
        }
        testcase_fail("do_GenerateTokenRSAKeyPair (parent) rc = %s", p11_get_ckr(rv));
        goto close_session;
    }

    // Test fork after Key Gen
    testcase_new_assertion();
    rv = do_fork(session, hPrivKey);
    if (rv != CKR_OK) {
        testcase_fail("do_fork() after KeyGen rc = %s", p11_get_ckr(rv));
        goto out;
    }
    testcase_pass("do_fork() after KeyGen");

    rv = funcs->C_DestroyObject(session, hPubKey);
    if (rv != CKR_OK) {
        testcase_fail("C_DestroyObject (parent) rc = %s", p11_get_ckr(rv));
        goto close_session;
    }

    rv = funcs->C_DestroyObject(session, hPrivKey);
    if (rv != CKR_OK) {
        testcase_fail("C_DestroyObject (parent) rc = %s", p11_get_ckr(rv));
        goto close_session;
    }

    rv = funcs->C_CloseSession(session);
    if (rv != CKR_OK) {
        testcase_fail("C_CloseSession (parent) rc = %s", p11_get_ckr(rv));
        goto finalize;
    }

    // Test fork before C_Finalize
    testcase_new_assertion();
    rv = do_fork(CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    if (rv != CKR_OK) {
        testcase_fail("do_fork() before C_Finalize rc = %s", p11_get_ckr(rv));
        goto out;
    }
    testcase_pass("do_fork() before C_Finalize");

    rv = funcs->C_Finalize(NULL);
    if (rv != CKR_OK) {
        testcase_fail("C_Finalize (parent) rc = %s", p11_get_ckr(rv));
        goto out;
    }

    // Test fork after C_Finalize
    testcase_new_assertion();
    rv = do_fork(CK_INVALID_HANDLE, CK_INVALID_HANDLE);
    if (rv != CKR_OK) {
        testcase_fail("do_fork() after C_Finalize rc = %s", p11_get_ckr(rv));
        goto out;
    }
    testcase_pass("do_fork() after C_Finalize");

    ret = 0;
    goto out;

close_session:
    rv = funcs->C_CloseSession(session);
    if (rv != CKR_OK) {
        testcase_fail("C_CloseSession (parent) rc = %s", p11_get_ckr(rv));
        ret = 1;
    }
finalize:
    rv = funcs->C_Finalize(NULL);
    if (rv != CKR_OK) {
        testcase_fail("C_Finalize (parent) rc = %s", p11_get_ckr(rv));
        ret = 1;
    }
out:
    testcase_print_result();
    return testcase_return(ret);
}
