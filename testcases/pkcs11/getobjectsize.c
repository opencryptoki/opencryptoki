/*
 * COPYRIGHT (c) International Business Machines Corp. 2016-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"


/* API Routines exercised:
 * C_CreateObject
 * C_GetObjectSize
 * C_DestroyObject
 *
 * 2 TestCases
 * Setup: Create a key object.
 * Get the object size
 * Destroy the object
 * Get the object size
 */
CK_RV do_GetObjectSize(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_RV rc = 0;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    CK_OBJECT_HANDLE keyobj = CK_INVALID_HANDLE;

    CK_BBOOL false = FALSE;
    CK_KEY_TYPE aes_type = CKK_AES;
    CK_OBJECT_CLASS key_class = CKO_SECRET_KEY;
    CK_CHAR aes_value[] = "This is a fake aes key.";
    CK_ATTRIBUTE aes_tmpl[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &aes_type, sizeof(aes_type)},
        {CKA_VALUE, &aes_value, sizeof(aes_value)},
        {CKA_SENSITIVE, &false, sizeof(false)}
    };

    CK_ULONG obj_size = 0;

    // Do some setup and login to the token
    testcase_begin("starting...");
    testcase_rw_session();
    testcase_user_login();

    // Create an AES Key Object.
    rc = funcs->C_CreateObject(session, aes_tmpl, 4, &keyobj);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session)) {
            testcase_skip("Key import is not allowed by policy");
            goto testcase_cleanup;
        }
        testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* now, get the size of the object */
    rc = funcs->C_GetObjectSize(session, keyobj, &obj_size);
    if (rc != CKR_OK) {
        testcase_fail("C_GetObjectSize() rc = %s", p11_get_ckr(rc));
        return rc;
    }

    printf("\nSize of object = %lu\n", obj_size);

        /** Destroy the object */
    rc = funcs->C_DestroyObject(session, keyobj);
    if (rc != CKR_OK) {
        testcase_fail("C_DestroyObject() rc = %s", p11_get_ckr(rc));
        return rc;
    }

    /* now, get the size of a non-existent object */
    rc = funcs->C_GetObjectSize(session, keyobj, &obj_size);
    if (rc != CKR_OBJECT_HANDLE_INVALID) {
        testcase_fail("C_GetObjectSize () rc = %s (expected "
                      "CKR_OBJECT_HANDLE_INVALID)", p11_get_ckr(rc));
        return rc;
    }

    printf("C_GetObjectSize test passed\n");

testcase_cleanup:
    funcs->C_DestroyObject(session, keyobj);

    testcase_user_logout();
    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK) {
        testcase_error("C_CloseSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

int main(int argc, char **argv)
{
    int rc;
    CK_C_INITIALIZE_ARGS cinit_args;
    CK_RV rv = 0;

    rc = do_ParseArgs(argc, argv);
    if (rc != 1)
        return rc;

    printf("Using slot #%lu...\n\n", SLOT_ID);

    rc = do_GetFunctionList();
    if (!rc) {
        testcase_error("do_getFunctionList(), rc=%s", p11_get_ckr(rc));
        return rc;
    }

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    funcs->C_Initialize(&cinit_args);

    {
        CK_SESSION_HANDLE hsess = 0;

        rv = funcs->C_GetFunctionStatus(hsess);
        if (rv != CKR_FUNCTION_NOT_PARALLEL)
            return rv;

        rv = funcs->C_CancelFunction(hsess);
        if (rv != CKR_FUNCTION_NOT_PARALLEL)
            return rv;
    }

    rv = do_GetObjectSize();

    funcs->C_Finalize(NULL);

    /* make sure we return non-zero if rv is non-zero */
    return testcase_return(rv);
}
