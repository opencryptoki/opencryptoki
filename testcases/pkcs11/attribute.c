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

CK_RV do_TestAttributes(void)
{
    CK_OBJECT_HANDLE obj_handle = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE obj_handle_no_mod = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_RV rc = 0, rv = 0;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_BYTE so_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG so_pin_len;
    CK_ULONG find_count;
    CK_OBJECT_HANDLE obj_list[10];

    CK_BYTE modulus[] = {
        0xa5, 0x6e, 0x4a, 0x0e, 0x70, 0x10, 0x17, 0x58,
        0x9a, 0x51, 0x87, 0xdc, 0x7e, 0xa8, 0x41, 0xd1,
        0x56, 0xf2, 0xec, 0x0e, 0x36, 0xad, 0x52, 0xa4,
        0x4d, 0xfe, 0xb1, 0xe6, 0x1f, 0x7a, 0xd9, 0x91,
        0xd8, 0xc5, 0x10, 0x56, 0xff, 0xed, 0xb1, 0x62,
        0xb4, 0xc0, 0xf2, 0x83, 0xa1, 0x2a, 0x88, 0xa3,
        0x94, 0xdf, 0xf5, 0x26, 0xab, 0x72, 0x91, 0xcb,
        0xb3, 0x07, 0xce, 0xab, 0xfc, 0xe0, 0xb1, 0xdf,
        0xd5, 0xcd, 0x95, 0x08, 0x09, 0x6d, 0x5b, 0x2b,
        0x8b, 0x6d, 0xf5, 0xd6, 0x71, 0xef, 0x63, 0x77,
        0xc0, 0x92, 0x1c, 0xb2, 0x3c, 0x27, 0x0a, 0x70,
        0xe2, 0x59, 0x8e, 0x6f, 0xf8, 0x9d, 0x19, 0xf1,
        0x05, 0xac, 0xc2, 0xd3, 0xf0, 0xcb, 0x35, 0xf2,
        0x92, 0x80, 0xe1, 0x38, 0x6b, 0x6f, 0x64, 0xc4,
        0xef, 0x22, 0xe1, 0xe1, 0xf2, 0x0d, 0x0c, 0xe8,
        0xcf, 0xfb, 0x22, 0x49, 0xbd, 0x9a, 0x21, 0x37
    };

    CK_BYTE publicExponent[] = { 0x01, 0x00, 0x01 };
    int modulus_len = 128;
    int publicExponent_len = 3;

    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_RSA;
    CK_CHAR label[] = "An RSA public key object";
    CK_CHAR newlabel[] = "Updated RSA public key object";
    CK_CHAR label2[] = "Another RSA public key object";
    CK_CHAR labelbuf[100];
    CK_BBOOL false = FALSE;
    CK_BBOOL true = TRUE;
    CK_BBOOL boolval, boolval2;

    CK_ATTRIBUTE pub_template[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_MODULUS, modulus, modulus_len},
        {CKA_PUBLIC_EXPONENT, publicExponent, publicExponent_len}
    };

    CK_ATTRIBUTE pub_template_no_modify[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_MODULUS, modulus, modulus_len},
        {CKA_PUBLIC_EXPONENT, publicExponent, publicExponent_len},
        {CKA_MODIFIABLE, &false, sizeof(false)},
    };

    CK_ATTRIBUTE new_attrs[] = {
        {CKA_ENCRYPT, &false, sizeof(false)},
        {CKA_WRAP, &false, sizeof(false)},
    };

    CK_ATTRIBUTE update_label[] = {
        {CKA_LABEL, newlabel, sizeof(newlabel) - 1},
    };

    CK_ATTRIBUTE verify_attrs[] = {
        {CKA_ENCRYPT, &boolval, sizeof(boolval)},
        {CKA_WRAP, &boolval, sizeof(boolval)},
        {CKA_LABEL, labelbuf, sizeof(labelbuf)},
    };

    CK_ATTRIBUTE update_modifiable_false[] = {
        {CKA_MODIFIABLE, &false, sizeof(false)},
    };

    CK_ATTRIBUTE update_modifiable_true[] = {
        {CKA_MODIFIABLE, &true, sizeof(true)},
    };

    CK_ATTRIBUTE update_copyable_false[] = {
        {CKA_COPYABLE, &false, sizeof(false)},
    };

    CK_ATTRIBUTE update_copyable_true[] = {
        {CKA_COPYABLE, &true, sizeof(true)},
    };

    CK_ATTRIBUTE update_destroyable_false[] = {
        {CKA_DESTROYABLE, &false, sizeof(false)},
    };

    CK_ATTRIBUTE update_destroyable_true[] = {
        {CKA_DESTROYABLE, &true, sizeof(true)},
    };

    CK_ATTRIBUTE update_trusted_true[] = {
        {CKA_TRUSTED, &true, sizeof(true)},
    };

    CK_ATTRIBUTE update_trusted_false[] = {
        {CKA_TRUSTED, &false, sizeof(false)},
    };

    CK_ATTRIBUTE array_attrs[] = {
        {CKA_ENCRYPT, &true, sizeof(true)},
        {CKA_WRAP, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label) - 1},
    };

    CK_ATTRIBUTE pub_template_private[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_PRIVATE, &true, sizeof(true)},
        {CKA_LABEL, label2, sizeof(label2) - 1},
        {CKA_MODULUS, modulus, modulus_len},
        {CKA_PUBLIC_EXPONENT, publicExponent, publicExponent_len},
        {CKA_WRAP_TEMPLATE, array_attrs, sizeof(array_attrs)},
    };

    CK_ATTRIBUTE find_label[] = {
        {CKA_LABEL, label2, sizeof(label2) - 1},
    };

    CK_ATTRIBUTE verify_array_attrs[] = {
        {CKA_ENCRYPT, &boolval, sizeof(boolval)},
        {CKA_WRAP, &boolval2, sizeof(boolval2)},
        {CKA_LABEL, labelbuf, sizeof(labelbuf)},
    };

    CK_ATTRIBUTE verify_array[] = {
        {CKA_WRAP_TEMPLATE, &verify_array_attrs, sizeof(verify_array_attrs)},
    };

    testcase_begin("");
    testcase_rw_session();
    testcase_user_login();

    /* create a public key object */
    rc = funcs->C_CreateObject(session, pub_template, 6, &obj_handle);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session)) {
            testcase_skip("Key generation is not allowed by policy");
            goto testcase_cleanup;
        }
        testcase_fail("C_CreateObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Now add new attributes */
    testcase_new_assertion();
    rc = funcs->C_SetAttributeValue(session, obj_handle, new_attrs, 2);
    if (rc != CKR_OK) {
        testcase_fail("C_SetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully added new attributes.");

    /* Now update an existing attribute */
    testcase_new_assertion();
    rc = funcs->C_SetAttributeValue(session, obj_handle, update_label, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_SetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully updated existing attribute.");

    /* Now get the attributes that were updated */
    testcase_new_assertion();
    rc = funcs->C_GetAttributeValue(session, obj_handle, verify_attrs, 3);
    if (rc != CKR_OK) {
        testcase_fail("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* verify the attribute values retrieved */
    if (*(CK_BBOOL *) verify_attrs[0].pValue != false) {
        testcase_fail("CKA_ENCRYPT mismatch");
        goto testcase_cleanup;
    }

    if (*(CK_BBOOL *) verify_attrs[1].pValue != false) {
        testcase_fail("CKA_WRAP mismatch");
        goto testcase_cleanup;
    }

    if (memcmp(verify_attrs[2].pValue,
               newlabel, verify_attrs[2].ulValueLen) != 0)
        testcase_fail("CKA_LABEL mismatch");
    else
        testcase_pass("Successfully verified updated attributes.");

    /* Try to update attributes of an object which has CKA_MODIFIABLE=FALSE */
    testcase_new_assertion();

    /* create a public key object with CKA_MODIFIABLE=FALSE*/
    rc = funcs->C_CreateObject(session, pub_template_no_modify, 7,
                               &obj_handle_no_mod);
    if (rc != CKR_OK) {
        testcase_fail("C_CreateObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_SetAttributeValue(session, obj_handle_no_mod,
                                    update_label, 1);
    if (rc == CKR_ACTION_PROHIBITED)
        testcase_pass("C_SetAttributeValue() did not update the object rc = %s "
                      "(as ecpected)", p11_get_ckr(rc));
    else
        testcase_fail("C_SetAttributeValue() to update CKA_MODIFIABLE should "
                      "have failed with CKR_ACTION_PROHIBITED, but got "
                      "rc = %s.", p11_get_ckr(rc));

    /*
     * Try to update CKA_MODIFIABLE on the object that has CKA_MODIFIABLE=TRUE.
     * This should fail. CKA_MODIFIABLE can not be changed after creation of
     * the object.
     */
    testcase_new_assertion();

    rc = funcs->C_SetAttributeValue(session, obj_handle,
                                    update_modifiable_false, 1);
    if (rc == CKR_ATTRIBUTE_READ_ONLY)
        testcase_pass("C_SetAttributeValue() did not update CKA_MODIFIABLE to "
                      "FALSE rc = %s (as ecpected)", p11_get_ckr(rc));
    else
        testcase_fail("C_SetAttributeValue() to update CKA_MODIFIABLE should "
                      "have failed with CKR_ATTRIBUTE_READ_ONLY, but got "
                      "rc = %s.", p11_get_ckr(rc));

    testcase_new_assertion();

    rc = funcs->C_SetAttributeValue(session, obj_handle,
                                    update_modifiable_true, 1);
    if (rc == CKR_ATTRIBUTE_READ_ONLY)
        testcase_pass("C_SetAttributeValue() did not update CKA_MODIFIABLE to "
                      "TRUE rc = %s (as ecpected)", p11_get_ckr(rc));
    else
        testcase_fail("C_SetAttributeValue() to update CKA_MODIFIABLE should "
                      "have failed with CKR_ATTRIBUTE_READ_ONLY, but got"
                      " rc = %s.", p11_get_ckr(rc));

    /*
     * Try to update CKA_COPYABLE on the object that has CKA_COPYABLE=TRUE.
     * CKA_MODIFIABLE can not be changed to TRUE once it has been set to FALSE.
     */
    testcase_new_assertion();

    rc = funcs->C_SetAttributeValue(session, obj_handle,
                                    update_copyable_false, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_SetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }
    testcase_pass("Successfully set CKA_COPYABLE to FALSE.");

    testcase_new_assertion();

    rc = funcs->C_SetAttributeValue(session, obj_handle,
                                    update_copyable_true, 1);
    if (rc == CKR_ATTRIBUTE_READ_ONLY)
        testcase_pass("C_SetAttributeValue() did not update CKA_COPYABLE to "
                      "TRUE rc = %s (as ecpected)", p11_get_ckr(rc));
    else
        testcase_fail("C_SetAttributeValue() to update CKA_COPYABLE back to "
                      "TRUE should have failed with CKR_ATTRIBUTE_READ_ONLY, "
                      "but got rc = %s.", p11_get_ckr(rc));

    /*
     * Try to update CKA_DESTROYABLE on the object that has CKA_DESTROYABLE=TRUE.
     */
    testcase_new_assertion();

    rc = funcs->C_SetAttributeValue(session, obj_handle,
                                    update_destroyable_false, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_SetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully set CKA_DESTROYABLE to FALSE.");

    testcase_new_assertion();

    rc = funcs->C_SetAttributeValue(session, obj_handle,
                                    update_destroyable_true, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_SetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully set CKA_DESTROYABLE to TRUE.");

    /*
     * Try to update CKA_TRUSTED when logged in a user.
     * This is expected to fail with CKR_USER_NOT_LOGGED_IN.
     */
    testcase_new_assertion();

    rc = funcs->C_SetAttributeValue(session, obj_handle,
                                    update_trusted_true, 1);
    if (rc == CKR_USER_NOT_LOGGED_IN)
        testcase_pass("C_SetAttributeValue() did not update CKA_TRUSTED to "
                      "TRUE rc = %s (as ecpected, because only SO can set "
                      "CKA_TRUSTED to TRUE)", p11_get_ckr(rc));
    else
        testcase_fail("C_SetAttributeValue() to update CKA_TRUSTED should "
                      "have failed with CKR_USER_NOT_LOGGED_IN, but got "
                      "rc = %s.", p11_get_ckr(rc));

    /* Login a SO */
    testcase_user_logout();
    testcase_so_login();

    /* Now add new attribute CKA_TRUSTED */
    testcase_new_assertion();
    rc = funcs->C_SetAttributeValue(session, obj_handle,
                                    update_trusted_true, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_SetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully added CKA_TRUSTED=TRUE (as SO).");

    /* Login a User */
    testcase_user_logout();
    testcase_user_login();

    /* Now set attribute CKA_TRUSTED to FALSE */
    testcase_new_assertion();
    rc = funcs->C_SetAttributeValue(session, obj_handle,
                                    update_trusted_false, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_SetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully added CKA_TRUSTED=FALSE (as User).");

    testcase_new_assertion();
    rv = funcs->C_DestroyObject(session, obj_handle);
    if (rv != CKR_OK)
        testcase_error("C_DestroyObject rv=%s", p11_get_ckr(rv));


    /* create a public key object with an array-attribute */
    rc = funcs->C_CreateObject(session, pub_template_private, 8, &obj_handle);
    if (rc != CKR_OK) {
        testcase_fail("C_CreateObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully created an object with an attribute-array attribute.");

    testcase_new_assertion();
    /*
     * Logout and Login again to force a reload of private token objects.
     * This tests that the object is stored correctly into the token directory
     * and that it can be successfully be loaded again.
     */
    testcase_user_logout();
    testcase_user_login();

    rc = funcs->C_FindObjectsInit(session, find_label, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_FindObjectsInit() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    rc = funcs->C_FindObjects(session, obj_list, 10, &find_count);
    if (rc != CKR_OK) {
        testcase_fail("C_FindObjects() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* We should have gotten back 2 des3 key objects */
    if (find_count != 1) {
        testcase_fail("Should have found 1 objects, found %d",
                      (int) find_count);
        goto testcase_cleanup;
    }

    obj_handle = obj_list[0];

    rc = funcs->C_FindObjectsFinal(session);
    if (rc != CKR_OK) {
        testcase_fail("C_FindObjectsFinal() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully found the previously created object.");

    /* Now get the attribute-array attribute and verify it */
    testcase_new_assertion();
    rc = funcs->C_GetAttributeValue(session, obj_handle, verify_array, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* verify the attribute values retrieved */
    if (verify_array[0].ulValueLen != sizeof(verify_array_attrs)) {
        testcase_fail("CKA_WRAP_TEMPLATE array length mismatch");
        goto testcase_cleanup;
    }

    if (verify_array_attrs[0].ulValueLen != sizeof(boolval) ||
        *(CK_BBOOL *) verify_array_attrs[0].pValue != true) {
        testcase_fail("Array element CKA_ENCRYPT mismatch");
        goto testcase_cleanup;
    }

    if (verify_array_attrs[1].ulValueLen != sizeof(boolval) ||
        *(CK_BBOOL *) verify_array_attrs[1].pValue != true) {
        testcase_fail("Array element CKA_WRAP mismatch");
        goto testcase_cleanup;
    }

    if (memcmp(verify_array_attrs[2].pValue,
               label, verify_array_attrs[2].ulValueLen) != 0)
        testcase_fail("Array element CKA_LABEL mismatch");
    else
        testcase_pass("Successfully verified attribute-array elements.");

testcase_cleanup:
    if (obj_handle != CK_INVALID_HANDLE) {
        rv = funcs->C_DestroyObject(session, obj_handle);
        if (rv != CKR_OK)
            testcase_error("C_DestroyObject rv=%s", p11_get_ckr(rv));
    }

    if (obj_handle_no_mod != CK_INVALID_HANDLE) {
        rv = funcs->C_DestroyObject(session, obj_handle_no_mod);
         if (rv != CKR_OK)
             testcase_error("C_DestroyObject rv=%s", p11_get_ckr(rv));
    }

    testcase_user_logout();
    rv = funcs->C_CloseSession(session);
    if (rv != CKR_OK)
        testcase_error("C_CloseSessions rv=%s", p11_get_ckr(rv));

    return rc;
}

CK_RV do_TestAttributesAESXTS(void)
{
    CK_OBJECT_HANDLE obj_handle = CK_INVALID_HANDLE;
    CK_SESSION_HANDLE session;
    CK_RV rc = 0, rv = 0;
    CK_FLAGS flags;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    CK_BYTE key[] = {
        0xa5, 0x6e, 0x4a, 0x0e, 0x70, 0x10, 0x17, 0x58,
        0x9a, 0x51, 0x87, 0xdc, 0x7e, 0xa8, 0x41, 0xd1,
        0x56, 0xf2, 0xec, 0x0e, 0x36, 0xad, 0x52, 0xa4,
        0x4d, 0xfe, 0xb1, 0xe6, 0x1f, 0x7a, 0xd9, 0x91,
        0xd8, 0xc5, 0x10, 0x56, 0xff, 0xed, 0xb1, 0x62,
        0xb4, 0xc0, 0xf2, 0x83, 0xa1, 0x2a, 0x88, 0xa3,
        0x94, 0xdf, 0xf5, 0x26, 0xab, 0x72, 0x91, 0xcb,
        0xb3, 0x07, 0xce, 0xab, 0xfc, 0xe0, 0xb1, 0xdf,
    };

    int keylen = 64;

    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES_XTS;
    CK_CHAR label[] = "An AES XTS key object";
    CK_BBOOL false = FALSE;
    CK_BBOOL true = TRUE;
    CK_BBOOL boolval;

    CK_ATTRIBUTE keyTemplate[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &keyType, sizeof(keyType)},
        {CKA_TOKEN, &false, sizeof(false)},
        {CKA_LABEL, label, sizeof(label) - 1},
        {CKA_VALUE, key, keylen},
        {CKA_EXTRACTABLE, &false, sizeof(CK_BBOOL)},
        {CKA_IBM_PROTKEY_EXTRACTABLE, &true, sizeof(CK_BBOOL)},
    };
    CK_ULONG keyTemplate_len = sizeof(keyTemplate) / sizeof(CK_ATTRIBUTE);

    CK_ATTRIBUTE new_attrs[] = {
        {CKA_ENCRYPT, &false, sizeof(false)},
    };

    CK_ATTRIBUTE verify_attrs[] = {
        {CKA_ENCRYPT, &boolval, sizeof(boolval)},
    };

    testcase_begin("");
    testcase_rw_session();
    testcase_user_login();

    /** skip test if the slot doesn't support this mechanism **/
    if (!mech_supported(SLOT_ID, CKM_AES_XTS)) {
        testcase_skip("Skip test as CKM_AES_XTS not supported");
        goto testcase_cleanup;
    }

    /* create a aes xts key object */
    rc = funcs->C_CreateObject(session, keyTemplate, keyTemplate_len, &obj_handle);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session)) {
            testcase_skip("Key generation is not allowed by policy");
            goto testcase_cleanup;
        }
        testcase_fail("C_CreateObject() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* Now add new attributes */
    testcase_new_assertion();
    rc = funcs->C_SetAttributeValue(session, obj_handle, new_attrs, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_SetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    testcase_pass("Successfully added new attribute.");

    /* Now get the attributes that were updated */
    testcase_new_assertion();
    rc = funcs->C_GetAttributeValue(session, obj_handle, verify_attrs, 1);
    if (rc != CKR_OK) {
        testcase_fail("C_GetAttributeValue() rc = %s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    /* verify the attribute values retrieved */
    if (*(CK_BBOOL *) verify_attrs[0].pValue != false) {
        testcase_fail("CKA_ENCRYPT mismatch");
        goto testcase_cleanup;
    }
    testcase_pass("Successfully verified newly added attribute.");

testcase_cleanup:
    if (obj_handle != CK_INVALID_HANDLE) {
        rv = funcs->C_DestroyObject(session, obj_handle);
        if (rv != CKR_OK)
            testcase_error("C_DestroyObject rv=%s", p11_get_ckr(rv));
    }

    testcase_user_logout();
    rv = funcs->C_CloseSession(session);
    if (rv != CKR_OK)
        testcase_error("C_CloseSessions rv=%s", p11_get_ckr(rv));

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
    rc = do_TestAttributes();
    rc = do_TestAttributesAESXTS();
    testcase_print_result();

    funcs->C_Finalize(NULL);

    return testcase_return(rc);
}
