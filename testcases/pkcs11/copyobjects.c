/*
 * COPYRIGHT (c) International Business Machines Corp. 2013-2017
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
 * C_CopyObject
 * C_DestroyObject
 *
 * 3 TestCases
 * Setup: Create a key object.
 * Testcase 1: Make an exact copy of the object with empty attribute list.
 * Testcase 2: make an exact copy of the object with one additional attribute.
 */
CK_RV do_CopyObjects(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE session;
    CK_RV rc = 0;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_ATTRIBUTE empty_tmpl;

    CK_OBJECT_HANDLE keyobj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE keyobj_no_copy = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE keyobj_copy = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE firstobj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE secondobj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE thirdobj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE fourthobj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE fifthobj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE sixthobj = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE seventhobj = CK_INVALID_HANDLE;

    CK_BBOOL true = TRUE;
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
    CK_ATTRIBUTE aes_tmpl_no_copy[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &aes_type, sizeof(aes_type)},
        {CKA_VALUE, &aes_value, sizeof(aes_value)},
        {CKA_SENSITIVE, &false, sizeof(false)},
        {CKA_COPYABLE, &false, sizeof(false)}
    };
    CK_ATTRIBUTE aes_tmpl_copy[] = {
        {CKA_CLASS, &key_class, sizeof(key_class)},
        {CKA_KEY_TYPE, &aes_type, sizeof(aes_type)},
        {CKA_VALUE, &aes_value, sizeof(aes_value)},
        {CKA_SENSITIVE, &false, sizeof(false)},
        {CKA_COPYABLE, &true, sizeof(true)}
    };

    CK_KEY_TYPE new_aes_type;
    CK_OBJECT_CLASS new_key_class;
    CK_CHAR new_aes_value[50];
    CK_BBOOL sensitive;
    CK_ATTRIBUTE test_tmpl[] = {
        {CKA_CLASS, &new_key_class, sizeof(new_key_class)},
        {CKA_KEY_TYPE, &new_aes_type, sizeof(new_aes_type)},
        {CKA_VALUE, &new_aes_value, sizeof(new_aes_value)},
        {CKA_SENSITIVE, &sensitive, sizeof(sensitive)}
    };

    CK_ATTRIBUTE copy_tmpl[] = {
        {CKA_TOKEN, &true, sizeof(true)}
    };

    CK_ATTRIBUTE true_sensitive_tmpl[] = {
        {CKA_SENSITIVE, &true, sizeof(true)}
    };

    CK_ATTRIBUTE false_sensitive_tmpl[] = {
        {CKA_SENSITIVE, &false, sizeof(false)}
    };

    CK_ATTRIBUTE test_sensitive_tmpl[] = {
        {CKA_SENSITIVE, &sensitive, sizeof(sensitive)}
    };

    memset(&empty_tmpl, 0, sizeof(empty_tmpl));

    CK_ATTRIBUTE *null_tmpl = NULL;

    // Do some setup and login to the token
    testcase_begin("");
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

    rc = funcs->C_CreateObject(session, aes_tmpl_no_copy, 5, &keyobj_no_copy);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session)) {
            testcase_skip("Key import is not allowed by policy");
            goto testcase_cleanup;
        }
        testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_CreateObject(session, aes_tmpl_copy, 5, &keyobj_copy);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session)) {
            testcase_skip("Key import is not allowed by policy");
            goto testcase_cleanup;
        }
        testcase_error("C_CreateObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    // Testcase #1 - Copy object exactly with no additional attributes, by
    // passing a null object
    testcase_new_assertion();

    rc = funcs->C_CopyObject(session, keyobj, null_tmpl, 0, &firstobj);
    if (rc != CKR_OK) {
        testcase_fail("C_CopyObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    // Pull up some attributes and verify that new object has
    // same attribute values as original.
    rc = funcs->C_GetAttributeValue(session, firstobj, test_tmpl, 4);
    if (rc != CKR_OK) {
        testcase_error("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    // Step thru template to see if new object matches original...
    if ((memcmp(test_tmpl[0].pValue, aes_tmpl[0].pValue,
                aes_tmpl[0].ulValueLen) == 0) &&
        (memcmp(test_tmpl[1].pValue, aes_tmpl[1].pValue,
                aes_tmpl[1].ulValueLen) == 0) &&
        (memcmp(test_tmpl[3].pValue, aes_tmpl[3].pValue,
                aes_tmpl[3].ulValueLen) == 0)) {

        /* CKA_VALUE is suppose to be zeroed out for
         * secure key tokens after importing the key.
         */
        if ((is_cca_token(SLOT_ID)) || (is_ep11_token(SLOT_ID))) {
            if (*(CK_BYTE *) test_tmpl[2].pValue == 0)
                testcase_pass("Copied object's attributes are correct");
            else
                testcase_fail("Copied object's attributes are incorrect.");
        } else {
            if (memcmp(test_tmpl[2].pValue, aes_tmpl[2].pValue,
                       aes_tmpl[2].ulValueLen) == 0)
                testcase_pass("Copied object's attributes are the same.");
            else
                testcase_fail("Copied object's attributes are different.");
        }
    } else {
        testcase_fail("Copied object's attributes are different.");
    }



    // Testcase #2 - Copy object exactly with no additional attributes, by
    // passing an empty template.
    testcase_new_assertion();

    rc = funcs->C_CopyObject(session, keyobj, &empty_tmpl, 0, &secondobj);
    if (rc != CKR_OK) {
        testcase_fail("C_CopyObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    // Pull up some attributes and verify that new object has
    // same attribute values as original.
    rc = funcs->C_GetAttributeValue(session, secondobj, test_tmpl, 4);
    if (rc != CKR_OK) {
        testcase_error("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    // Step thru template to see if new object matches original...
    if ((memcmp(test_tmpl[0].pValue, aes_tmpl[0].pValue,
                aes_tmpl[0].ulValueLen) == 0) &&
        (memcmp(test_tmpl[1].pValue, aes_tmpl[1].pValue,
                aes_tmpl[1].ulValueLen) == 0) &&
        (memcmp(test_tmpl[3].pValue, aes_tmpl[3].pValue,
                aes_tmpl[3].ulValueLen) == 0)) {

        /* CKA_VALUE is suppose to be zeroed out for
         * secure key tokens after importing the key.
         */
        if ((is_cca_token(SLOT_ID)) || (is_ep11_token(SLOT_ID))) {
            if (*(CK_BYTE *)test_tmpl[2].pValue == 0)
                testcase_pass("Copied object's attributes are correct");
            else
                testcase_fail("Copied object's attributes are incorrect.");
        } else {
            if (memcmp(test_tmpl[2].pValue, aes_tmpl[2].pValue,
                       aes_tmpl[2].ulValueLen) == 0)
                testcase_pass("Copied object's attributes are the same.");
            else
                testcase_fail("Copied object's attributes are different.");
        }
    } else {
        testcase_fail("Copied object's attributes are different.");
    }



    // Testcase #3 - Copy an object and include one additional attribute.
    testcase_new_assertion();

    rc = funcs->C_CopyObject(session, keyobj, copy_tmpl, 1, &thirdobj);
    if (rc != CKR_OK) {
        testcase_fail("C_CopyObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    // Verify that new object has the new attribute and value (CKA_TOKEN).
    // NOTE: Since passing in same template, original value will be
    //       over-written.
    rc = funcs->C_GetAttributeValue(session, thirdobj, copy_tmpl, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (*(CK_BBOOL *) copy_tmpl[0].pValue == TRUE)
        testcase_pass("Copied object's attributes are the same.");
    else
        testcase_fail("Copied object's attributes are different.");



    // Testcase #4 - Copy object changing the value of CKA_SENSITIVE
    // 	     from true to false. This should be allowed on copy.
    testcase_new_assertion();

    rc = funcs->C_CopyObject(session, keyobj,
                             true_sensitive_tmpl, 1, &fourthobj);
    if (rc != CKR_OK) {
        testcase_fail("C_CopyObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    // Verify that new object has CKA_SENSITIVE == true;
    rc = funcs->C_GetAttributeValue(session, fourthobj,
                                    test_sensitive_tmpl, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    if (*(CK_BBOOL *) test_sensitive_tmpl[0].pValue == TRUE)
        testcase_pass("Copied object's CKA_SENSITIVE == TRUE.");
    else
        testcase_fail("Copied object's CKA_SENSITIVE != TRUE.");


    // Testcase #5 - Now try changing CKA_SENSITIVE from TRUE to False.
    // This should not be allowed.
    testcase_new_assertion();

    rc = funcs->C_CopyObject(session, fourthobj,
                             false_sensitive_tmpl, 1, &fifthobj);
    if (rc == CKR_ATTRIBUTE_READ_ONLY)
        testcase_pass("C_CopyObject() did not copy the object. rc = %s "
                      "(as expected)", p11_get_ckr(rc));
    else
        testcase_fail("C_CopyObject() should have failed.");

    // Testcase #6 - Copy object that has CKA_COPYABLE=FALSE,
    // this should fail with CKR_ACTION_PROHIBITED
    testcase_new_assertion();

    rc = funcs->C_CopyObject(session, keyobj_no_copy, null_tmpl, 0, &sixthobj);
    if (rc == CKR_ACTION_PROHIBITED)
        testcase_pass("C_CopyObject() did not copy the object. rc = %s "
                      "(as expected)", p11_get_ckr(rc));
    else
        testcase_fail("C_CopyObject() should have failed with "
                      "CKR_ACTION_PROHIBITED, but got rc = %s.",
                      p11_get_ckr(rc));

    // Testcase #7 - Copy object that has CKA_COPYABLE=TRUE,
    // this should be allowed
    testcase_new_assertion();

    rc = funcs->C_CopyObject(session, keyobj_copy, null_tmpl, 0, &seventhobj);
    if (rc != CKR_OK) {
        testcase_fail("C_CopyObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }
    testcase_pass("C_CopyObject) succeeded");

testcase_cleanup:
    funcs->C_DestroyObject(session, keyobj);
    funcs->C_DestroyObject(session, keyobj_no_copy);
    funcs->C_DestroyObject(session, keyobj_copy);
    funcs->C_DestroyObject(session, firstobj);
    funcs->C_DestroyObject(session, secondobj);
    funcs->C_DestroyObject(session, thirdobj);
    funcs->C_DestroyObject(session, fourthobj);
    funcs->C_DestroyObject(session, fifthobj);
    funcs->C_DestroyObject(session, sixthobj);
    funcs->C_DestroyObject(session, seventhobj);

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
    rc = do_CopyObjects();
    testcase_print_result();

    funcs->C_Finalize(NULL);

    return testcase_return(rc);
}
