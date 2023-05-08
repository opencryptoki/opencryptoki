/*
 * COPYRIGHT (c) International Business Machines Corp. 2015-2017
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
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"

CK_RV do_GetInfo(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_RV rc = 0;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_INFO info;

    // Do some setup and login to the token
    testcase_begin("C_GetInfo function check");
    testcase_rw_session();
    testcase_user_login();

    testcase_new_assertion();

    rc = funcs->C_GetInfo(&info);
    if (rc != CKR_OK) {
        testcase_fail("C_GetInfo() rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Library info successfully sourced");

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK)
        testcase_error("C_CloseSession() failed.");

    return rc;
}

CK_RV do_GetSlotList(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_RV rc = 0;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    CK_BBOOL tokenPresent;
    CK_SLOT_ID_PTR pSlotList = NULL;
    CK_ULONG ulCount = 0;

    tokenPresent = TRUE;

    testcase_begin("testing C_GetSlotList");
    testcase_rw_session();
    testcase_user_login();

    testcase_new_assertion();

    /* pkcs#11v2.20, Section 11.5
     * If pSlotList is NULL_PTR, then all that C_GetSlotList does is
     * return (in *pulCount) the number of slots, without actually
     * returning a list of slots.
     */
    rc = funcs->C_GetSlotList(tokenPresent, NULL, &ulCount);
    if (rc != CKR_OK) {
        testcase_fail("C_GetSlotList rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (ulCount)
        testcase_pass("C_GetSlotList received slot count.");
    else
        testcase_fail("C_GetSlotList did not receive slot count.");

    pSlotList = (CK_SLOT_ID *) malloc(ulCount * sizeof(CK_SLOT_ID));
    if (!pSlotList) {
        testcase_error("malloc failed to allocate memory for list\n");
        rc = CKR_HOST_MEMORY;
        goto testcase_cleanup;
    }

    testcase_new_assertion();

    /* Get the slots */
    rc = funcs->C_GetSlotList(tokenPresent, pSlotList, &ulCount);
    if (rc != CKR_OK) {
        testcase_fail("C_GetSlotList rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Slot list returned successfully");

testcase_cleanup:
    if (pSlotList)
        free(pSlotList);

    testcase_user_logout();
    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK)
        testcase_error("C_CloseSession failed.");

    return rc;
}

CK_RV do_GetSlotInfo(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_RV rc = 0;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    CK_SLOT_ID slot_id = SLOT_ID;
    CK_SLOT_INFO info;

    testcase_begin("testing C_GetSlotInfo");
    testcase_rw_session();
    testcase_user_login();

    /* Test expected values */
    testcase_new_assertion();

    rc = funcs->C_GetSlotInfo(slot_id, &info);
    if (rc != CKR_OK) {
        testcase_fail("C_GetSlotInfo() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Slot info of in-use slot received successfully");

    /* Test for invalid slot */
    testcase_new_assertion();

    rc = funcs->C_GetSlotInfo(9999, &info);
    if (rc != CKR_SLOT_ID_INVALID) {
        testcase_fail("C_GetSlotInfo returned %s instead of"
                      " CKR_SLOT_ID_INVALID.", p11_get_ckr(rc));
        rc = CKR_FUNCTION_FAILED;       // dont confuse loop in main
        goto testcase_cleanup;
    }

    testcase_pass("C_GetSlotInfo correctly returned " "CKR_SLOT_ID_INVALID.");
    rc = 0;                     // don't confuse loop in main

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK)
        testcase_error("C_CloseSessions failed.");

    return rc;
}

CK_RV do_GetTokenInfo(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_RV rc = 0;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_TOKEN_INFO info;

    testcase_begin("testing C_GetTokenInfo()");
    testcase_rw_session();
    testcase_user_login();

    testcase_new_assertion();

    rc = funcs->C_GetTokenInfo(slot_id, &info);
    if (rc != CKR_OK) {
        testcase_fail("C_GetTokenInfo rc=%s", p11_get_ckr(rc));
        return rc;
    }

    testcase_pass("C_GetTokenInfo returned successfully");

    /* Test with an invalid slot id */
    testcase_new_assertion();

    rc = funcs->C_GetTokenInfo(9999, &info);
    if (rc != CKR_SLOT_ID_INVALID) {
        testcase_fail("C_GetTokenInfo() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("C_GetTokenInfo returned error when given invalid slot.");

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK)
        testcase_error("C_CloseSessions failed.");

    return rc;
}

CK_RV do_GetMechanismList(void)
{
    CK_FLAGS flags = 0;
    CK_SESSION_HANDLE session = 0;
    CK_RV rc = 0;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN] = {0};
    CK_ULONG user_pin_len = 0;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG count = 0;
    CK_MECHANISM_TYPE *mech_list = NULL;

    testcase_begin("testing C_GetMechanismList");
    testcase_rw_session();
    testcase_user_login();

    /* pkcs11v2.20, page 111
     * If pMechanismList is NULL_PTR, then all that C_GetMechanismList
     * does is return (in *pulCount) the number of mechanisms, without
     * actually returning a list of mechanisms. The contents of
     * *pulCount on entry to C_GetMechanismList has no meaning in this
     * case, and the call returns the value CKR_OK.
     */
    testcase_new_assertion();

    rc = funcs->C_GetMechanismList(slot_id, NULL, &count);
    if (rc != CKR_OK) {
        testcase_fail("C_GetMechanismList 1 rc=%s", p11_get_ckr(rc));
        return rc;
    }

    if (count)
        testcase_pass("C_GetMechanismList returned mechanism count.");
    else
        testcase_fail("C_GetMechanismList did not not return "
                      "mechanism count.");

    mech_list = (CK_MECHANISM_TYPE *) calloc(1, count * sizeof(CK_MECHANISM_TYPE));
    if (!mech_list) {
        testcase_fail();
        rc = CKR_HOST_MEMORY;
        goto testcase_cleanup;
    }

    testcase_new_assertion();
    rc = funcs->C_GetMechanismList(slot_id, mech_list, &count);
    if (rc != CKR_OK) {
        testcase_fail("C_GetMechanismList 2 rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Mechanism listing from current slot");

    /* Test for invalid slot */
    testcase_new_assertion();

    rc = funcs->C_GetMechanismList(9999, NULL, &count);
    if (rc != CKR_SLOT_ID_INVALID) {
        testcase_fail("C_GetMechanismList() returned %s instead of"
                      " CKR_SLOT_ID_INVALID.", p11_get_ckr(rc));
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    testcase_pass("C_GetMechanismList correctly returned "
                  "CKR_SLOT_ID_INVALID.");
    rc = CKR_OK;

testcase_cleanup:
    if (mech_list)
        free(mech_list);

    testcase_user_logout();
    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK)
        testcase_error("C_CloseSessions failed.");

    return rc;
}

CK_RV do_GetMechanismInfo(void)
{
    CK_FLAGS flags = 0;
    CK_SESSION_HANDLE session = 0;
    CK_RV rc = 0;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN] = {0};
    CK_ULONG user_pin_len = 0;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_MECHANISM_INFO info;
    CK_ULONG i = 0, count = 0;
    CK_MECHANISM_TYPE *mech_list = NULL;

    memset(&info, 0, sizeof(info));

    testcase_begin("testing C_GetMechanismInfo");
    testcase_rw_session();
    testcase_user_login();

    testcase_new_assertion();

    rc = funcs->C_GetMechanismList(slot_id, NULL, &count);
    if (rc != CKR_OK) {
        testcase_error("C_GetMechanismList #1 rc=%s", p11_get_ckr(rc));
        return rc;
    }

    mech_list = (CK_MECHANISM_TYPE *) calloc(1, count * sizeof(CK_MECHANISM_TYPE));
    if (!mech_list) {
        rc = CKR_HOST_MEMORY;
        goto testcase_cleanup;
    }

    rc = funcs->C_GetMechanismList(slot_id, mech_list, &count);
    if (rc != CKR_OK) {
        testcase_error("C_GetMechanismList #2 rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    for (i = 0; i < count; i++) {
        rc = funcs->C_GetMechanismInfo(slot_id, mech_list[i], &info);
        if (rc != CKR_OK)
            break;
    }

    if (rc != CKR_OK)
        testcase_fail("C_GetMechanismInfo rc=%s", p11_get_ckr(rc));
    else
        testcase_pass("C_GetMechanismInfo was successful.");

    testcase_new_assertion();

    rc = funcs->C_GetMechanismInfo(slot_id, 0x12345678, &info);

    if (rc != CKR_MECHANISM_INVALID)
        testcase_fail("C_GetMechanismInfo returned rc=%s instead "
                          "of CKR_MECHANISM_INVALID", p11_get_ckr(rc));
    else
        testcase_pass("C_GetMechanismInfo correctly returned CKR_MECHANISM_INVALID.");

testcase_cleanup:
    if (mech_list)
        free(mech_list);

    testcase_user_logout();
    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK)
        testcase_error("C_CloseSessions rc=%s", p11_get_ckr(rc));

    return rc;
}

CK_RV do_InitToken(void)
{
    CK_BYTE label[32] = {0};
    int len = 0;
    CK_CHAR so_pin[PKCS11_MAX_PIN_LEN] = {0};
    CK_RV rc = 0;

    testcase_begin("testing C_InitToken");

    memcpy(label, "L13                                   ", 32);
    for (len = 0; len < 31; len++) {
        if (label[len] == '\0') {
            label[len] = ' ';
            break;
        }
    }

    testcase_new_assertion();
    /* test with invalid SO PIN */
    rc = funcs->C_InitToken(SLOT_ID, NULL, strlen((char *) so_pin), label);
    if (rc != CKR_ARGUMENTS_BAD) {
        testcase_fail("C_InitToken returned %s instead of "
                      "CKR_ARGUMENTS_BAD", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("C_InitToken correctly returned CKR_ARGUMENS_BAD.");

    /* test with invalid slot id */
    testcase_new_assertion();
    rc = funcs->C_InitToken(9999, so_pin, strlen((char *) so_pin), label);
    if (rc != CKR_SLOT_ID_INVALID) {
        testcase_fail("C_InitToken returned %s instead of "
                      "CKR_SLOT_ID_INVALID.", p11_get_ckr(rc));
        rc = CKR_FUNCTION_FAILED;
    } else {
        testcase_pass("C_InitToken correctly returned CKR_SLOT_ID_INVALID.");
        rc = CKR_OK;
    }

testcase_cleanup:
    return rc;
}

CK_RV do_InitPIN(void)
{
    CK_SLOT_ID slot_id;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_CHAR so_pin[PKCS11_MAX_PIN_LEN];
    CK_CHAR user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG so_pin_len;
    CK_ULONG user_pin_len;
    CK_RV rc;

    testcase_begin("Testing C_InitPIN");

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;

    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    if (get_so_pin(so_pin))
        return CKR_FUNCTION_FAILED;

    so_pin_len = (CK_ULONG) strlen((char *) so_pin);

    slot_id = SLOT_ID;
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;

    // try to call C_InitPIN from a public session
    testcase_new_assertion();
    rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
    if (rc != CKR_OK) {
        testcase_error("C_OpenSession rc=%s", p11_get_ckr(rc));
        return rc;
    }

    rc = funcs->C_InitPIN(session, user_pin, user_pin_len);
    if (rc != CKR_USER_NOT_LOGGED_IN) {
        testcase_fail("C_InitPIN returned %s instead of "
                      "CKR_USER_NOT_LOGGED_IN", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("C_InitPin correctly returned CKR_USER_NOT_LOGGED_IN.");

    // try to call C_InitPIN from an SO session
    testcase_new_assertion();
    rc = funcs->C_Login(session, CKU_SO, so_pin, so_pin_len);
    if (rc != CKR_OK) {
        testcase_error("C_Login #1 failed: rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_InitPIN(session, user_pin, user_pin_len);
    if (rc != CKR_OK)
        testcase_fail("C_InitPIN failed: rc=%s", p11_get_ckr(rc));
    else
        testcase_pass("C_InitPIN #1 was successful.");

    rc = funcs->C_Logout(session);
    if (rc != CKR_OK) {
        testcase_error("C_Logout #1 failed.");
        goto testcase_cleanup;
    }
    // try to call C_InitPIN from a normal user session
    testcase_new_assertion();
    rc = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        testcase_error("C_Login failed: rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_InitPIN(session, user_pin, user_pin_len);
    if (rc != CKR_USER_NOT_LOGGED_IN) {
        testcase_fail("C_InitPIN returned %s instead of "
                      "CKR_USER_NOT_LOGGED_IN.", p11_get_ckr(rc));
        rc = CKR_FUNCTION_FAILED;
    } else {
        testcase_pass("C_InitPIN #2 was successful.");
        rc = CKR_OK;
    }

    rc = funcs->C_Logout(session);
    if (rc != CKR_OK)
        testcase_error("C_Logout #2 rc=%s", p11_get_ckr(rc));

testcase_cleanup:
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK)
        testcase_error("C_CloseAllSessions #1 rc=%s", p11_get_ckr(rc));

    return rc;
}

CK_RV do_SetPIN(void)
{
    CK_SLOT_ID slot_id;
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_CHAR old_pin[PKCS11_MAX_PIN_LEN];
    CK_CHAR new_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG old_len;
    CK_ULONG new_len;
    CK_RV rc;

    testcase_begin("Testing C_SetPIN");

    // first, try to get the user PIN
    if (get_user_pin(old_pin))
        return CKR_FUNCTION_FAILED;

    old_len = (CK_ULONG) strlen((char *) old_pin);

    memcpy(new_pin, "ABCDEF", 6);
    new_len = 6;

    slot_id = SLOT_ID;

    /* try to call C_SetPIN from a R/O public session, it should fail.
     */
    flags = CKF_SERIAL_SESSION;
    testcase_new_assertion();
    rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
    if (rc != CKR_OK) {
        testcase_error("C_OpenSession #1 rc=%s", p11_get_ckr(rc));
        return rc;
    }

    rc = funcs->C_SetPIN(session, old_pin, old_len, new_pin, new_len);
    if (rc != CKR_SESSION_READ_ONLY) {
        testcase_fail("C_SetPIN #1 returned %s instead of "
                      "CKR_SESSION_READ_ONLY.", p11_get_ckr(rc));
        rc = CKR_FUNCTION_FAILED;
        goto testcase_cleanup;
    }

    testcase_pass("C_SetPIN successful in public session.");

    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK) {
        testcase_error("C_CloseSession #1 failed.");
        goto testcase_cleanup;
    }

    /* try to call C_SetPIN from a R/W public session, it should work.
     */
    testcase_new_assertion();

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
    if (rc != CKR_OK) {
        testcase_error("C_OpenSession #1 rc=%s", p11_get_ckr(rc));
        return rc;
    }

    rc = funcs->C_SetPIN(session, old_pin, old_len, new_pin, new_len);
    if (rc != CKR_OK) {
        testcase_fail("C_SetPIN failed: rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("C_SetPIN successful in r/w public session.");

    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK) {
        testcase_error("C_CloseSession #1 failed.");
        goto testcase_cleanup;
    }

    /* open a new session and try logging in with new pin */
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &session);
    if (rc != CKR_OK) {
        testcase_error("C_OpenSession #1 rc=%s", p11_get_ckr(rc));
        return rc;
    }

    testcase_new_assertion();

    rc = funcs->C_Login(session, CKU_USER, new_pin, new_len);
    if (rc != CKR_OK) {
        testcase_fail("C_Login #1 failed: rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully logged in with new pin.");

    /* try to call C_SetPIN from a normal user session, r/w user.
     * set back to original user pin. this should work.
     */
    testcase_new_assertion();

    rc = funcs->C_SetPIN(session, new_pin, new_len, old_pin, old_len);
    if (rc != CKR_OK) {
        testcase_fail("C_SetPIN #2 rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("C_SetPIN successful.");

    rc = funcs->C_Logout(session);
    if (rc != CKR_OK) {
        testcase_error("C_Logout #1 failed: rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /*
     *  done with user tests...now try with the SO
     */

    if (get_so_pin(old_pin))
        return CKR_FUNCTION_FAILED;

    /* try to call C_SetPIN from a normal user session */
    testcase_new_assertion();

    rc = funcs->C_Login(session, CKU_SO, old_pin, old_len);
    if (rc != CKR_OK) {
        testcase_error("C_Login #3 failed: rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_SetPIN(session, old_pin, old_len, new_pin, new_len);
    if (rc != CKR_OK) {
        testcase_fail("C_SetPIN #4 failed: rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("C_SetPIN successfully set SO PIN.");

    rc = funcs->C_Logout(session);
    if (rc != CKR_OK) {
        testcase_error("C_Logout #3 failed.");
        goto testcase_cleanup;
    }

    /* now login with new pin. should work. */
    testcase_new_assertion();

    rc = funcs->C_Login(session, CKU_SO, new_pin, new_len);
    if (rc != CKR_OK)
        testcase_fail("C_Login #5 failed: rc=%s", p11_get_ckr(rc));
    else
        testcase_pass("C_Login #5 was successful.");

    /* change the PIN back to the original so the rest of this program
     * doesn't break
     */
    rc = funcs->C_SetPIN(session, new_pin, new_len, old_pin, old_len);
    if (rc != CKR_OK)
        testcase_error("C_SetPIN #5 failed to set back to the original "
                       "SO PIN, rc=%s", p11_get_ckr(rc));

    rc = funcs->C_Logout(session);
    if (rc != CKR_OK)
        testcase_error("C_Logout #4 failed.");

testcase_cleanup:
    rc = funcs->C_CloseSession(session);
    if (rc != CKR_OK)
        testcase_error("C_CloseSession #1 failed.");

    return rc;
}


CK_RV api_driver(void)
{
    CK_RV rc;

    rc = do_GetInfo();
    if (rc && !no_stop)
        return rc;

    rc = do_GetSlotList();
    if (rc && !no_stop)
        return rc;

    rc = do_GetSlotInfo();
    if (rc && !no_stop)
        return rc;

    rc = do_GetTokenInfo();
    if (rc && !no_stop)
        return rc;

    rc = do_GetMechanismList();
    if (rc && !no_stop)
        return rc;

    rc = do_GetMechanismInfo();
    if (rc && !no_stop)
        return rc;

    /* do not run on icsf token */
    if (!is_icsf_token(SLOT_ID)) {
        rc = do_InitToken();
        if (rc && !no_stop)
            return rc;
    }

    rc = do_InitPIN();
    if (rc && !no_stop)
        return rc;

    rc = do_SetPIN();
    if (rc && !no_stop)
        return rc;

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
    printf("With option: nostop: %d\n", no_stop);

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

    testcase_setup();
    rv = api_driver();
    testcase_print_result();

    funcs->C_Finalize(NULL_PTR);

    return testcase_return(rv);
}
