/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
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
#include <strings.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "digest.h"
#include "common.c"
#include "mech_to_str.h"

#define DIGEST_UPDATE_SIZE 32

/** Tests messge digest with published test vectors. **/
CK_RV do_Digest(struct digest_test_suite_info *tsuite)
{
    unsigned int i;
    CK_BYTE data[MAX_DATA_SIZE];
    CK_ULONG data_len;
    CK_BYTE actual[MAX_HASH_SIZE];
    CK_ULONG actual_len;
    CK_BYTE expected[MAX_HASH_SIZE];
    CK_ULONG expected_len;
    CK_MECHANISM mech;

    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;


    /** begin test suite **/
    testsuite_begin("%s Digest.", tsuite->name);
    testcase_rw_session();

    /** skip test if mech is not supported with this slot **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "mechanism %s is not supported with slot %lu",
                       tsuite->name, slot_id);
        goto testcase_cleanup;
    }

    /** iterate over test vectors **/
    for (i = 0; i < tsuite->tvcount; i++) {

        /** begin test **/
        testcase_begin("Starting %s Digest with test vector %u.",
                       tsuite->name, i);

        rc = CKR_OK;            // set rc

        /** clear buffers **/
        memset(data, 0, sizeof(data));
        memset(actual, 0, sizeof(actual));
        memset(expected, 0, sizeof(expected));

        /** get test vector info **/
        data_len = tsuite->tv[i].data_len;
        expected_len = tsuite->tv[i].hash_len;
        memcpy(data, tsuite->tv[i].data, data_len);
        memcpy(expected, tsuite->tv[i].hash, expected_len);

        /** get mech **/
        mech = tsuite->mech;

        /** initialize single digest **/
        rc = funcs->C_DigestInit(session, &mech);
        if (rc != CKR_OK) {
            testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        actual_len = sizeof(actual);    // set digest buffer size

        /** do single digest **/
        rc = funcs->C_Digest(session, data, data_len, actual, &actual_len);
        if (rc != CKR_OK) {
            testcase_error("C_Digest rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** compare digest results with expected results **/
        testcase_new_assertion();

        if (actual_len != expected_len) {
            testcase_fail("hashed data length does not match test "
                          "vector's hashed data length.\n expected"
                          " length=%lu, found length=%lu.",
                          expected_len, actual_len);
        } else if (memcmp(actual, expected, expected_len)) {
            testcase_fail("hashed data does not match test vector's"
                          " hashed data.");
        } else {
            testcase_pass("%s Digest with test vector %u passed.",
                          tsuite->name, i);
        }
    }

testcase_cleanup:
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Tests multipart message digest with published test vectors. **/
CK_RV do_DigestUpdate(struct digest_test_suite_info * tsuite)
{
    unsigned int i;
    CK_BYTE data[MAX_DATA_SIZE];
    CK_ULONG data_len, data_done;
    CK_BYTE actual[MAX_HASH_SIZE];
    CK_ULONG actual_len;
    CK_BYTE expected[MAX_HASH_SIZE];
    CK_ULONG len, expected_len;
    CK_MECHANISM mech;

    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;

    /** begin test **/
    testsuite_begin("Starting %s Multipart Digest.", tsuite->name);
    testcase_rw_session();

    /** skip test if mech is not supported with this slot **/
    if (!mech_supported(slot_id, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "mechanism %s is not supported with slot %lu",
                       tsuite->name, slot_id);
        goto testcase_cleanup;
    }

    /** iterate over test vectors **/
    for (i = 0; i < tsuite->tvcount; i++) {

        /** begin test **/
        testcase_begin("Starting %s Multipart Digest with test vector %u.",
                       tsuite->name, i);

        rc = CKR_OK;            // set rc

        /** clear buffers **/
        memset(data, 0, sizeof(data));
        memset(actual, 0, sizeof(actual));
        memset(expected, 0, sizeof(expected));

        /** get test vector info **/
        data_done = 0;
        data_len = tsuite->tv[i].data_len;
        expected_len = tsuite->tv[i].hash_len;
        memcpy(data, tsuite->tv[i].data, data_len);
        memcpy(expected, tsuite->tv[i].hash, expected_len);

        /** get mechanism **/
        mech = tsuite->mech;

        /** initialize multipart digest **/
        rc = funcs->C_DigestInit(session, &mech);
        if (rc != CKR_OK) {
            testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        actual_len = sizeof(actual);

        /* do multipart digest
         * if test vector contains chunks, use that.
         * Otherwise, just call update on entire data.
         *
         * Note: for chunks, -1 is NULL, and 0 is empty string,
         *       and a value > 0 is amount of data from test vector's
         *       plaintext data. This way we test chunks that
         *       are NULL or empty string when updating.
         */
        if (tsuite->tv[i].num_chunks) {
            int j;
            CK_BYTE *data_chunk = NULL;

            for (j = 0; j < tsuite->tv[i].num_chunks; j++) {
                if (tsuite->tv[i].chunks[j] == -1) {
                    len = 0;
                    data_chunk = NULL;
                } else if (tsuite->tv[i].chunks[j] == 0) {
                    len = 0;
                    data_chunk = (CK_BYTE *) "";
                } else {
                    len = tsuite->tv[i].chunks[j];
                    data_chunk = data + data_done;
                }

                rc = funcs->C_DigestUpdate(session, data_chunk, len);
                if (rc != CKR_OK) {
                    testcase_error("C_DigestUpdate rc=%s", p11_get_ckr(rc));
                    goto testcase_cleanup;
                }

                data_done += len;
            }
        } else {
            rc = funcs->C_DigestUpdate(session, data, data_len);
            if (rc != CKR_OK) {
                testcase_error("C_DigestUpdate rc=%s", p11_get_ckr(rc));
                goto testcase_cleanup;
            }
        }

        /** finalize multipart digest **/
        rc = funcs->C_DigestFinal(session, actual, &actual_len);
        if (rc != CKR_OK) {
            testcase_error("C_DigestFinal rc=%s", p11_get_ckr(rc));
            goto testcase_cleanup;
        }

        /** compare multipart digest results with expected results **/
        testcase_new_assertion();

        if (actual_len != expected_len) {
            testcase_fail("hashed multipart data length does not "
                          "match test vector's hashed data length.\n");
        } else if (memcmp(actual, expected, expected_len)) {
            testcase_fail("hashed multipart data does not match "
                          "test vector's hashed data.\n");
        } else {
            testcase_pass("%s Multipart Digest with test vector "
                          "%u passed.", tsuite->name, i);
        }

    }

testcase_cleanup:
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Tests signature verification with published test vectors. **/
CK_RV do_Sign_FIPS_HMAC_GENERAL(struct HMAC_TEST_SUITE_INFO * tsuite)
{
    unsigned int i;
    CK_MECHANISM mech;
    CK_BYTE key[MAX_KEY_SIZE], data[MAX_DATA_SIZE];
    CK_ULONG key_len, data_len, actual_mac_len, expected_mac_len, mac_size;
    CK_BYTE actual_mac[MAX_HASH_SIZE], expected_mac[MAX_HASH_SIZE];
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    CK_OBJECT_HANDLE h_key;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    /** begin testsuite **/
    testsuite_begin("%s Sign.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    rc = CKR_OK;                // set rc

    /** skip test if mech is not supported with this slot **/
    if (!mech_supported(SLOT_ID, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "mechanism %s is not supported with slot %lu",
                       tsuite->name, slot_id);
        goto testcase_cleanup;
    }

    /** iterate over test vectors **/
    for (i = 0; i < tsuite->tvcount; i++) {

        /** begin test **/
        testcase_begin("Sign %s with test vector %u.", tsuite->name, i);

        /** get mechanism and set parameter **/
        mech = tsuite->mech;
        mac_size = tsuite->tv[i].mac_len;

        mech.ulParameterLen = sizeof(CK_ULONG);
        mech.pParameter = &mac_size;

        /** clear buffers **/
        memset(key, 0, sizeof(key));
        memset(data, 0, sizeof(data));
        memset(actual_mac, 0, sizeof(actual_mac));
        memset(expected_mac, 0, sizeof(expected_mac));

        /** get test vector info **/
        data_len = tsuite->tv[i].data_len;
        actual_mac_len = sizeof(actual_mac);
        expected_mac_len = tsuite->tv[i].mac_len;
        key_len = tsuite->tv[i].key_len;
        memcpy(key, tsuite->tv[i].key, key_len);
        memcpy(data, tsuite->tv[i].data, data_len);
        memcpy(expected_mac, tsuite->tv[i].mac, expected_mac_len);

        /** create key object **/
        rc = create_GenericSecretKey(session, CKK_GENERIC_SECRET,
                                     key, key_len, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("generic secret key generation is not allowed by policy");
                continue;
            }

            testcase_error("create_GenericSecretKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initialize signing **/
        rc = funcs->C_SignInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("C_SignInit with mech %s is not allowed by policy",
                              mech_to_str(mech.mechanism));
                goto error;
            }

            testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** do signing  **/
        rc = funcs->C_Sign(session, data, data_len, actual_mac,
                           &actual_mac_len);
        if (rc != CKR_OK) {
            testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** compare sign/verify results with expected results **/
        testcase_new_assertion();

        if (actual_mac_len != expected_mac_len) {
            testcase_fail("hashed data length does not match test "
                          "vector's hashed data length\nexpected "
                          "length=%lu, found length=%lu",
                          expected_mac_len, actual_mac_len);
            goto error;
        } else if (memcmp(actual_mac, expected_mac, expected_mac_len)) {
            testcase_fail("hashed data does not match test "
                          "vector's hashed data");
            goto error;
        } else {
            testcase_pass("%s Sign with test vector %u passed",
                          tsuite->name, i);
        }
error:
        /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Tests signature verification with published test vectors. **/
CK_RV do_Verify_FIPS_HMAC_GENERAL(struct HMAC_TEST_SUITE_INFO * tsuite)
{
    unsigned int i;
    CK_MECHANISM mech;
    CK_BYTE key[MAX_KEY_SIZE], data[MAX_DATA_SIZE];
    CK_ULONG key_len, data_len, expected_mac_len, mac_size;
    CK_BYTE expected_mac[MAX_HASH_SIZE];
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    CK_OBJECT_HANDLE h_key;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    /** begin testsuite **/
    testsuite_begin("%s Verify.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    rc = CKR_OK;                // set rc

    /** skip test if mech is not supported with this slot **/
    if (!mech_supported(SLOT_ID, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "mechanism %s is not supported with slot %lu",
                       tsuite->name, slot_id);
        goto testcase_cleanup;
    }

    /** iterate over test vectors **/
    for (i = 0; i < tsuite->tvcount; i++) {

        /** begin test **/
        testcase_begin("Verify %s with test vector %u.", tsuite->name, i);

        /** get mechanism and set parameter **/
        mech = tsuite->mech;
        mac_size = tsuite->tv[i].mac_len;

        mech.ulParameterLen = sizeof(CK_ULONG);
        mech.pParameter = &mac_size;

        /** clear buffers **/
        memset(key, 0, sizeof(key));
        memset(data, 0, sizeof(data));
        memset(expected_mac, 0, sizeof(expected_mac));

        /** get test vector info **/
        data_len = tsuite->tv[i].data_len;
        expected_mac_len = tsuite->tv[i].mac_len;
        key_len = tsuite->tv[i].key_len;
        memcpy(key, tsuite->tv[i].key, key_len);
        memcpy(data, tsuite->tv[i].data, data_len);
        memcpy(expected_mac, tsuite->tv[i].mac, expected_mac_len);

        /** create key object **/
        rc = create_GenericSecretKey(session, CKK_GENERIC_SECRET,
                                     key, key_len, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("generic secret key generation is not allowed by policy");
                continue;
            }

            testcase_error("create_GenericSecretKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initilaize verification **/
        rc = funcs->C_VerifyInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("C_VerifyInit with mech %s is not allowed by policy",
                              mech_to_str(mech.mechanism));
                goto error;
            }

            testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** see if signature verifies **/
        testcase_new_assertion();

        /** do verification **/
        rc = funcs->C_Verify(session, data, data_len, expected_mac,
                             expected_mac_len);
        if (rc != CKR_OK)
            testcase_fail("C_Verify rc=%s", p11_get_ckr(rc));
        else
            testcase_pass("%s C_Verify with test vector %u passed",
                          tsuite->name, i);

error:
        /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}


/** Tests signature generation with published test vectors. **/
CK_RV do_Sign_FIPS_HMAC(struct HMAC_TEST_SUITE_INFO * tsuite)
{
    unsigned int i;
    CK_MECHANISM mech;
    CK_BYTE key[MAX_KEY_SIZE], data[MAX_DATA_SIZE];
    CK_ULONG key_len, data_len, actual_mac_len, expected_mac_len;
    CK_BYTE actual_mac[MAX_HASH_SIZE], expected_mac[MAX_HASH_SIZE];
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    CK_OBJECT_HANDLE h_key;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    /** begin testsuite **/
    testsuite_begin("%s Sign.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    rc = CKR_OK;                // set rc

    /** skip test if mech is not supported with this slot **/
    if (!mech_supported(SLOT_ID, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "mechanism %s is not supported with slot %lu",
                       tsuite->name, slot_id);
        goto testcase_cleanup;
    }

    /** iterate over test vectors **/
    for (i = 0; i < tsuite->tvcount; i++) {

        /** begin test **/
        testcase_begin("Sign %s with test vector %u.", tsuite->name, i);

        /** get mechanism **/
        mech = tsuite->mech;

        /* only run hmac testcases with appropriate mac length */
        switch (mech.mechanism) {
        case CKM_SHA_1_HMAC:
            if (tsuite->tv[i].mac_len != 20) {
                testcase_skip("Skip, this testcase is not" " for SHA1 HMAC");
                continue;
            }
            break;
        case CKM_SHA224_HMAC:
            if (tsuite->tv[i].mac_len != 28) {
                testcase_skip("Skip, this testcase is not" " for SHA224 HMAC");
                continue;
            }
            break;
        case CKM_SHA256_HMAC:
            if (tsuite->tv[i].mac_len != 32) {
                testcase_skip("Skip, this testcase is not" " for SHA256 HMAC");
                continue;
            }
            break;
        case CKM_SHA384_HMAC:
            if (tsuite->tv[i].mac_len != 48) {
                testcase_skip("Skip, this testcase is not" " for SHA384 HMAC");
                continue;
            }
            break;
        case CKM_SHA512_HMAC:
            if (tsuite->tv[i].mac_len != 64) {
                testcase_skip("Skip, this testcase is not" " for SHA512 HMAC");
                continue;
            }
            break;
        default:
            testcase_error("Invalid Mechanism\n");
            goto testcase_cleanup;
        }

        /** clear buffers **/
        memset(key, 0, sizeof(key));
        memset(data, 0, sizeof(data));
        memset(actual_mac, 0, sizeof(actual_mac));
        memset(expected_mac, 0, sizeof(expected_mac));

        /** get test vector info **/
        data_len = tsuite->tv[i].data_len;
        actual_mac_len = sizeof(actual_mac);
        expected_mac_len = tsuite->tv[i].mac_len;
        key_len = tsuite->tv[i].key_len;
        memcpy(key, tsuite->tv[i].key, key_len);
        memcpy(data, tsuite->tv[i].data, data_len);
        memcpy(expected_mac, tsuite->tv[i].mac, expected_mac_len);

        /** create key object **/
        rc = create_GenericSecretKey(session, CKK_GENERIC_SECRET,
                                     key, key_len, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("generic secret key generation is not allowed by policy");
                continue;
            }

            testcase_error("create_GenericSecretKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initialize signing **/
        rc = funcs->C_SignInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** do signing  **/
        rc = funcs->C_Sign(session, data, data_len, actual_mac,
                           &actual_mac_len);
        if (rc != CKR_OK) {
            testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
            goto error;
        }
        /** compare sign results with expected results **/
        testcase_new_assertion();

        if (actual_mac_len != expected_mac_len) {
            testcase_fail("hashed data length does not match test "
                          "vector's hashed data length\nexpected "
                          "length=%lu, found length=%lu",
                          expected_mac_len, actual_mac_len);
        } else if (memcmp(actual_mac, expected_mac, expected_mac_len)) {
            testcase_fail("hashed data does not match test "
                          "vector's hashed data");
        } else {
            testcase_pass("%s C_Sign with test vector %u passed.",
                          tsuite->name, i);
        }
error:
        /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }
testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }
    return rc;
}


/** Tests signature generation with published test vectors. **/
CK_RV do_Verify_FIPS_HMAC(struct HMAC_TEST_SUITE_INFO * tsuite)
{
    unsigned int i;
    CK_MECHANISM mech;
    CK_BYTE key[MAX_KEY_SIZE], data[MAX_DATA_SIZE];
    CK_ULONG key_len, data_len, expected_mac_len;
    CK_BYTE expected_mac[MAX_HASH_SIZE];
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    CK_OBJECT_HANDLE h_key;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    /** begin testsuite **/
    testsuite_begin("%s Verify.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    rc = CKR_OK;                // set rc

    /** skip test if mech is not supported with this slot **/
    if (!mech_supported(SLOT_ID, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "mechanism %s is not supported with slot %lu",
                       tsuite->name, slot_id);
        goto testcase_cleanup;
    }

    /** iterate over test vectors **/
    for (i = 0; i < tsuite->tvcount; i++) {

        /** begin test **/
        testcase_begin("Verify %s with test vector %u.", tsuite->name, i);

        /** get mechanism **/
        mech = tsuite->mech;

        /* only run hmac testcases with appropriate mac length */
        switch (mech.mechanism) {
        case CKM_SHA_1_HMAC:
            if (tsuite->tv[i].mac_len != 20) {
                testcase_skip("Skip, this testcase is not" " for SHA1 HMAC");
                continue;
            }
            break;
        case CKM_SHA224_HMAC:
            if (tsuite->tv[i].mac_len != 28) {
                testcase_skip("Skip, this testcase is not" " for SHA224 HMAC");
                continue;
            }
            break;
        case CKM_SHA256_HMAC:
            if (tsuite->tv[i].mac_len != 32) {
                testcase_skip("Skip, this testcase is not" " for SHA256 HMAC");
                continue;
            }
            break;
        case CKM_SHA384_HMAC:
            if (tsuite->tv[i].mac_len != 48) {
                testcase_skip("Skip, this testcase is not" " for SHA384 HMAC");
                continue;
            }
            break;
        case CKM_SHA512_HMAC:
            if (tsuite->tv[i].mac_len != 64) {
                testcase_skip("Skip, this testcase is not" " for SHA512 HMAC");
                continue;
            }
            break;
        default:
            testcase_error("Invalid Mechanism\n");
            goto testcase_cleanup;
        }

        /** clear buffers **/
        memset(key, 0, sizeof(key));
        memset(data, 0, sizeof(data));
        memset(expected_mac, 0, sizeof(expected_mac));

        /** get test vector info **/
        data_len = tsuite->tv[i].data_len;
        expected_mac_len = tsuite->tv[i].mac_len;
        key_len = tsuite->tv[i].key_len;
        memcpy(key, tsuite->tv[i].key, key_len);
        memcpy(data, tsuite->tv[i].data, data_len);
        memcpy(expected_mac, tsuite->tv[i].mac, expected_mac_len);

        /** create key object **/
        rc = create_GenericSecretKey(session, CKK_GENERIC_SECRET,
                                     key, key_len, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("generic secret key generation is not allowed by policy");
                continue;
            }

            testcase_error("create_GenericSecretKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initilaize verification **/
        rc = funcs->C_VerifyInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        testcase_new_assertion();

        /** do verification **/
        rc = funcs->C_Verify(session, data, data_len, expected_mac,
                             expected_mac_len);
        if (rc != CKR_OK)
            testcase_fail("C_Verify rc=%s", p11_get_ckr(rc));

        else
            testcase_pass("%s C_Verify with test vector %u passed.",
                          tsuite->name, i);
error:
        /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}


/** Tests signature generation with published test vectors. **/
CK_RV do_SignUpdate_FIPS_HMAC(struct HMAC_TEST_SUITE_INFO * tsuite)
{
    unsigned int i;
    CK_MECHANISM mech;
    CK_BYTE key[MAX_KEY_SIZE], data[MAX_DATA_SIZE];
    CK_ULONG key_len, data_len, actual_mac_len, expected_mac_len;
    CK_BYTE actual_mac[MAX_HASH_SIZE], expected_mac[MAX_HASH_SIZE];
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    CK_OBJECT_HANDLE h_key;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    /** begin testsuite **/
    testsuite_begin("%s SignUpdate.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    rc = CKR_OK;                // set rc

    /** skip test if mech is not supported with this slot **/
    if (!mech_supported(SLOT_ID, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "mechanism %s is not supported with slot %lu",
                       tsuite->name, slot_id);
        goto testcase_cleanup;
    }

    /** iterate over test vectors **/
    for (i = 0; i < tsuite->tvcount; i++) {

        /** begin test **/
        testcase_begin("Multipart SignUpdate %s with test vector %u.",
                       tsuite->name, i);

        /** get mechanism and set parameter **/
        mech = tsuite->mech;

        /* only run hmac testcases with appropriate mac length */
        switch (mech.mechanism) {
        case CKM_SHA_1_HMAC:
            if (tsuite->tv[i].mac_len != 20) {
                testcase_skip("Skip, testcase not applicable" " to SHA1 HMAC");
                continue;
            }
            break;
        case CKM_SHA224_HMAC:
            if (tsuite->tv[i].mac_len != 28) {
                testcase_skip("Skip, testcase not applicable"
                              " to SHA224 HMAC");
                continue;
            }
            break;
        case CKM_SHA256_HMAC:
            if (tsuite->tv[i].mac_len != 32) {
                testcase_skip("Skip, testcase not applicable"
                              " to SHA256 HMAC");
                continue;
            }
            break;
        case CKM_SHA384_HMAC:
            if (tsuite->tv[i].mac_len != 48) {
                testcase_skip("Skip, testcase not applicable"
                              " to SHA384 HMAC");
                continue;
            }
            break;
        case CKM_SHA512_HMAC:
            if (tsuite->tv[i].mac_len != 64) {
                testcase_skip("Skip, testcase not applicable"
                              " to SHA512 HMAC");
                continue;
            }
            break;
        default:
            testcase_error("Invalid Mechanism\n");
            goto testcase_cleanup;
        }

        /** clear buffers **/
        memset(key, 0, sizeof(key));
        memset(data, 0, sizeof(data));
        memset(actual_mac, 0, sizeof(actual_mac));
        memset(expected_mac, 0, sizeof(expected_mac));

        /** get test vector info **/
        data_len = tsuite->tv[i].data_len;
        actual_mac_len = sizeof(actual_mac);
        expected_mac_len = tsuite->tv[i].mac_len;
        key_len = tsuite->tv[i].key_len;
        memcpy(key, tsuite->tv[i].key, key_len);
        memcpy(data, tsuite->tv[i].data, data_len);
        memcpy(expected_mac, tsuite->tv[i].mac, expected_mac_len);

        /** create key object **/
        rc = create_GenericSecretKey(session, CKK_GENERIC_SECRET,
                                     key, key_len, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("generic secret key generation is not allowed by policy");
                continue;
            }

            testcase_error("create_GenericSecretKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initialize signing **/
        rc = funcs->C_SignInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /* for chunks, -1 is NULL, and 0 is empty string,
         * and a value > 0 is amount of data from test vector's
         * plaintext data. This way we test vary-sized chunks.
         */
        if (tsuite->tv[i].num_chunks) {
            int j, k = 0;
            CK_ULONG len;
            CK_BYTE *data_chunk = NULL;

            for (j = 0; j < tsuite->tv[i].num_chunks; j++) {
                if (tsuite->tv[i].chunks[j] == -1) {
                    len = 0;
                    data_chunk = NULL;
                } else if (tsuite->tv[i].chunks[j] == 0) {
                    len = 0;
                    data_chunk = (CK_BYTE *) "";
                } else {
                    len = tsuite->tv[i].chunks[j];
                    data_chunk = data + k;
                }

                rc = funcs->C_SignUpdate(session, data_chunk, len);
                if (rc != CKR_OK) {
                    testcase_error("C_SignUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }
                k += len;
            }
        } else {
            rc = funcs->C_SignUpdate(session, data, data_len);
            if (rc != CKR_OK) {
                testcase_error("C_SignUpdate rc=%s", p11_get_ckr(rc));
                goto error;
            }
        }

        rc = funcs->C_SignFinal(session, actual_mac, &actual_mac_len);
        if (rc != CKR_OK) {
            testcase_error("C_SignFinal rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** compare results with expected results **/
        testcase_new_assertion();
        if (actual_mac_len != expected_mac_len) {
            testcase_fail("hashed data length does not match test "
                          "vector's hashed data length\nexpected "
                          "length=%lu, found length=%lu",
                          expected_mac_len, actual_mac_len);
        } else if (memcmp(actual_mac, expected_mac, expected_mac_len)) {
            testcase_fail("hashed data does not match test "
                          "vector's hashed data");
        } else {
            testcase_pass("%s Sign with test vector %u passed.",
                          tsuite->name, i);
        }

error:
        /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK)
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));

    return rc;
}

/** Tests signature verification with published test vectors. **/
CK_RV do_VerifyUpdate_FIPS_HMAC(struct HMAC_TEST_SUITE_INFO * tsuite)
{
    unsigned int i;
    CK_MECHANISM mech;
    CK_BYTE key[MAX_KEY_SIZE], data[MAX_DATA_SIZE];
    CK_ULONG key_len, data_len, expected_mac_len;
    CK_BYTE expected_mac[MAX_HASH_SIZE];
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    CK_OBJECT_HANDLE h_key;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    /** begin testsuite **/
    testsuite_begin("%s VerifyUpdate.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    rc = CKR_OK;                // set rc

    /** skip test if mech is not supported with this slot **/
    if (!mech_supported(SLOT_ID, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "mechanism %s is not supported with slot %lu",
                       tsuite->name, slot_id);
        goto testcase_cleanup;
    }

    /** iterate over test vectors **/
    for (i = 0; i < tsuite->tvcount; i++) {

        /** begin test **/
        testcase_begin("Multipart VerifyUpdate %s with test vector %u.",
                       tsuite->name, i);

        /** get mechanism and set parameter **/
        mech = tsuite->mech;

        /* only run hmac testcases with appropriate mac length */
        switch (mech.mechanism) {
        case CKM_SHA_1_HMAC:
            if (tsuite->tv[i].mac_len != 20) {
                testcase_skip("Skip, testcase not applicable" " to SHA1 HMAC");
                continue;
            }
            break;
        case CKM_SHA224_HMAC:
            if (tsuite->tv[i].mac_len != 28) {
                testcase_skip("Skip, testcase not applicable"
                              " to SHA224 HMAC");
                continue;
            }
            break;
        case CKM_SHA256_HMAC:
            if (tsuite->tv[i].mac_len != 32) {
                testcase_skip("Skip, testcase not applicable"
                              " to SHA256 HMAC");
                continue;
            }
            break;
        case CKM_SHA384_HMAC:
            if (tsuite->tv[i].mac_len != 48) {
                testcase_skip("Skip, testcase not applicable"
                              " to SHA384 HMAC");
                continue;
            }
            break;
        case CKM_SHA512_HMAC:
            if (tsuite->tv[i].mac_len != 64) {
                testcase_skip("Skip, testcase not applicable"
                              " to SHA512 HMAC");
                continue;
            }
            break;
        default:
            testcase_error("Invalid Mechanism\n");
            goto testcase_cleanup;
        }

        /** clear buffers **/
        memset(key, 0, sizeof(key));
        memset(data, 0, sizeof(data));
        memset(expected_mac, 0, sizeof(expected_mac));

        /** get test vector info **/
        data_len = tsuite->tv[i].data_len;
        expected_mac_len = tsuite->tv[i].mac_len;
        key_len = tsuite->tv[i].key_len;
        memcpy(key, tsuite->tv[i].key, key_len);
        memcpy(data, tsuite->tv[i].data, data_len);
        memcpy(expected_mac, tsuite->tv[i].mac, expected_mac_len);

        /** create key object **/
        rc = create_GenericSecretKey(session, CKK_GENERIC_SECRET,
                                     key, key_len, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("generic secret key generation is not allowed by policy");
                continue;
            }

            testcase_error("create_GenericSecretKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initialize signing **/
        rc = funcs->C_VerifyInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /* for chunks, -1 is NULL, and 0 is empty string,
         * and a value > 0 is amount of data from test vector's
         * plaintext data. This way we test vary-sized chunks.
         */
        if (tsuite->tv[i].num_chunks) {
            int j, k = 0;
            CK_ULONG len;
            CK_BYTE *data_chunk = NULL;

            for (j = 0; j < tsuite->tv[i].num_chunks; j++) {
                if (tsuite->tv[i].chunks[j] == -1) {
                    len = 0;
                    data_chunk = NULL;
                } else if (tsuite->tv[i].chunks[j] == 0) {
                    len = 0;
                    data_chunk = (CK_BYTE *) "";
                } else {
                    len = tsuite->tv[i].chunks[j];
                    data_chunk = data + k;
                }

                rc = funcs->C_VerifyUpdate(session, data_chunk, len);
                if (rc != CKR_OK) {
                    testcase_error("C_VerifyUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }
                k += len;
            }
        } else {
            rc = funcs->C_VerifyUpdate(session, data, data_len);
            if (rc != CKR_OK) {
                testcase_error("C_SignUpdate rc=%s", p11_get_ckr(rc));
                goto error;
            }
        }

        testcase_new_assertion();

        rc = funcs->C_VerifyFinal(session, expected_mac, expected_mac_len);
        if (rc != CKR_OK)
            testcase_fail("C_VerifyFinal rc=%s", p11_get_ckr(rc));
        else
            testcase_pass("%s Verfied with test vector %u passed.",
                          tsuite->name, i);
error:
        /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK)
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));

    return rc;
}

/** Tests signature verification with published test vectors. **/
CK_RV do_SignVerify_HMAC(struct HMAC_TEST_SUITE_INFO * tsuite)
{
    unsigned int i;
    CK_MECHANISM mech;
    CK_BYTE key[MAX_KEY_SIZE];
    CK_ULONG key_len;
    CK_BYTE data[MAX_DATA_SIZE];
    CK_ULONG data_len;
    CK_BYTE actual[MAX_HASH_SIZE];
    CK_ULONG actual_len;
    CK_BYTE expected[MAX_HASH_SIZE];
    CK_ULONG expected_len;

    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    CK_OBJECT_HANDLE h_key;

    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    /** begin testsuite **/
    testsuite_begin("%s Sign Verify.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    rc = CKR_OK;                // set rc

    /** skip test if mech is not supported with this slot **/
    if (!mech_supported(SLOT_ID, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "mechanism %s is not supported with slot %lu",
                       tsuite->name, slot_id);
        goto testcase_cleanup;
    }

    /** iterate over test vectors **/
    for (i = 0; i < tsuite->tvcount; i++) {

        /** begin test **/
        testcase_begin("Sign Verify %s with test vector %u.", tsuite->name, i);

        /** get mechanism **/
        mech = tsuite->mech;

        /* for ep11, check if key len is supported */
        key_len = tsuite->tv[i].key_len;

        if ((is_ep11_token(SLOT_ID) || is_cca_token(SLOT_ID)) &&
            (!check_supp_keysize(SLOT_ID, mech.mechanism, key_len * 8))) {
            testcase_skip("keysize %lu is not supported in slot %lu",
                          key_len, slot_id);
            continue;
        }

        /** clear buffers **/
        memset(key, 0, sizeof(key));
        memset(data, 0, sizeof(data));
        memset(actual, 0, sizeof(actual));
        memset(expected, 0, sizeof(expected));

        /** get test vector info **/
        data_len = tsuite->tv[i].data_len;
        actual_len = sizeof(actual);
        expected_len = tsuite->tv[i].mac_len;
        memcpy(key, tsuite->tv[i].key, key_len);
        memcpy(data, tsuite->tv[i].data, data_len);
        memcpy(expected, tsuite->tv[i].mac, expected_len);

        /** create key object **/
        rc = create_GenericSecretKey(session, CKK_GENERIC_SECRET,
                                     key, key_len, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("generic secret key generation is not allowed by policy");
                continue;
            }

            testcase_error("create_GenericSecretKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initialize signing **/
        rc = funcs->C_SignInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            if (is_rejected_by_policy(rc, session)) {
                testcase_skip("C_SignInit with mech %s is not allowed by policy",
                              mech_to_str(mech.mechanism));
                goto error;
            }

            testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** do signing  **/
        rc = funcs->C_Sign(session, data, data_len, actual, &actual_len);
        if (rc != CKR_OK) {
            testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initilaize verification **/
        rc = funcs->C_VerifyInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** do verification **/
        rc = funcs->C_Verify(session, data, data_len, actual, actual_len);
        if (rc != CKR_OK) {
            testcase_error("C_Verify rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** compare sign/verify results with expected results **/
        testcase_new_assertion();

        if (actual_len != expected_len) {
            testcase_fail("hashed data length does not match test "
                          "vector's hashed data length\nexpected length="
                          "%lu, found length=%lu", expected_len, actual_len);
        } else if (memcmp(actual, expected, expected_len)) {
            testcase_fail("hashed data does not match test "
                          "vector's hashed data");
        } else {
            testcase_pass("%s Sign Verify with test vector %u "
                          "passed.", tsuite->name, i);
        }

error:
        /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

/** Tests signature verification with published test vectors. **/
CK_RV do_SignVerify_HMAC_Update(struct HMAC_TEST_SUITE_INFO * tsuite)
{
    int len1 = 0, len2 = 0;
    unsigned int i;
    CK_MECHANISM mech;
    CK_BYTE key[MAX_KEY_SIZE];
    CK_ULONG key_len;
    CK_BYTE data[MAX_DATA_SIZE];
    CK_ULONG data_len;
    CK_BYTE actual[MAX_HASH_SIZE];
    CK_ULONG actual_len;
    CK_BYTE expected[MAX_HASH_SIZE];
    CK_ULONG expected_len;

    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    CK_OBJECT_HANDLE h_key;

    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    /** begin testsuite **/
    testsuite_begin("%s Sign Verify.", tsuite->name);
    testcase_rw_session();
    testcase_user_login();

    rc = CKR_OK;                // set rc

    /** skip test if mech is not supported with this slot **/
    if (!mech_supported(SLOT_ID, tsuite->mech.mechanism)) {
        testsuite_skip(tsuite->tvcount,
                       "mechanism %s is not supported with slot %lu",
                       tsuite->name, slot_id);
        goto testcase_cleanup;
    }

    /** iterate over test vectors **/
    for (i = 0; i < tsuite->tvcount; i++) {

        /** begin test **/
        testcase_begin("Multipart Sign Verify %s with test vector %u.",
                       tsuite->name, i);

        /** get mechanism **/
        mech = tsuite->mech;

        /* for ep11, check if key len is supported */
        key_len = tsuite->tv[i].key_len;

        if ((is_ep11_token(SLOT_ID) || is_cca_token(SLOT_ID)) &&
            (!check_supp_keysize(SLOT_ID, mech.mechanism, key_len * 8))) {
            testcase_skip("keysize %lu is not supported in slot %lu",
                          key_len, slot_id);
            continue;
        }

        /** clear buffers **/
        memset(key, 0, sizeof(key));
        memset(data, 0, sizeof(data));
        memset(actual, 0, sizeof(actual));
        memset(expected, 0, sizeof(expected));

        /** get test vector info **/
        data_len = tsuite->tv[i].data_len;
        actual_len = sizeof(actual);
        expected_len = tsuite->tv[i].mac_len;
        memcpy(key, tsuite->tv[i].key, key_len);
        memcpy(data, tsuite->tv[i].data, data_len);
        memcpy(expected, tsuite->tv[i].mac, expected_len);

        /** create key object **/
        rc = create_GenericSecretKey(session, CKK_GENERIC_SECRET,
                                     key, key_len, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("generic secret key generation is not allowed by policy");
                continue;
            }

            testcase_error("create_GenericSecretKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initialize signing **/
        rc = funcs->C_SignInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_SignInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** do multipart signing  **/
        if (data_len > 0) {
            /* do in 2 parts */
            if (data_len < 20) {
                len1 = data_len;
            } else {
                len1 = data_len - 20;
                len2 = 20;
            }

            rc = funcs->C_SignUpdate(session, data, len1);
            if (rc != CKR_OK) {
                testcase_error("C_SignUpdate rc=%s", p11_get_ckr(rc));
                goto error;
            }

            if (len2) {
                rc = funcs->C_SignUpdate(session, data + len1, len2);
                if (rc != CKR_OK) {
                    testcase_error("C_SignUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }
            }
        } else {
            rc = funcs->C_SignUpdate(session, NULL, 0);
            if (rc != CKR_OK) {
                testcase_error("C_SignUpdate rc=%s", p11_get_ckr(rc));
                goto error;
            }
        }
        rc = funcs->C_SignFinal(session, actual, &actual_len);
        if (rc != CKR_OK) {
            testcase_error("C_SignFinal rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initilaize verification **/
        rc = funcs->C_VerifyInit(session, &mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** do verification **/
        if (data_len > 0) {
            rc = funcs->C_VerifyUpdate(session, data, len1);
            if (rc != CKR_OK) {
                testcase_error("C_VerifyUpdate rc=%s", p11_get_ckr(rc));
                goto error;
            }

            if (len2) {
                rc = funcs->C_VerifyUpdate(session, data + len1, len2);
                if (rc != CKR_OK) {
                    testcase_error("C_VerifyUpdate rc=%s", p11_get_ckr(rc));
                    goto error;
                }
            }
        } else {
            rc = funcs->C_VerifyUpdate(session, NULL, 0);
            if (rc != CKR_OK) {
                testcase_error("C_VerifyUpdate rc=%s", p11_get_ckr(rc));
                goto error;
            }
        }
        rc = funcs->C_VerifyFinal(session, actual, actual_len);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyFinal rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** compare sign/verify results with expected results **/
        testcase_new_assertion();

        if (actual_len != expected_len) {
            testcase_fail("hashed data length does not match test "
                          "vector's hashed data length\nexpected length="
                          "%lu, found length=%lu", expected_len, actual_len);
        } else if (memcmp(actual, expected, expected_len)) {
            testcase_fail("hashed data does not match test "
                          "vector's hashed data");
        } else {
            testcase_pass("%s Sign Verify Multipart with test vector %u "
                          "passed.", tsuite->name, i);
        }

error:
        /** clean up **/
        rc = funcs->C_DestroyObject(session, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
            goto testcase_cleanup;
        }
    }

testcase_cleanup:
    testcase_user_logout();
    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));
    }

    return rc;
}

static struct hmac_mech_info {
    CK_MECHANISM keygen_mech;
    CK_MECHANISM hmac_mech;
    CK_ULONG key_len;
    CK_RV exp_rc;
} hmac_mechs[] = {
    { { CKM_GENERIC_SECRET_KEY_GEN, 0, 0 }, { CKM_SHA_1_HMAC, 0, 0 }, 20, CKR_OK },
    { { CKM_SHA_1_KEY_GEN, 0, 0 }, { CKM_SHA_1_HMAC, 0, 0 }, 20, CKR_OK },
    { { CKM_SHA224_KEY_GEN, 0, 0 }, { CKM_SHA224_HMAC, 0, 0 }, 28, CKR_OK },
    { { CKM_SHA256_KEY_GEN, 0, 0 }, { CKM_SHA256_HMAC, 0, 0 }, 32, CKR_OK },
    { { CKM_SHA384_KEY_GEN, 0, 0 }, { CKM_SHA384_HMAC, 0, 0 }, 48, CKR_OK },
    { { CKM_SHA512_KEY_GEN, 0, 0 }, { CKM_SHA512_HMAC, 0, 0 }, 64, CKR_OK },
    { { CKM_SHA512_224_KEY_GEN, 0, 0 }, { CKM_SHA512_224_HMAC, 0, 0 }, 28, CKR_OK },
    { { CKM_SHA512_256_KEY_GEN, 0, 0 }, { CKM_SHA512_256_HMAC, 0, 0 }, 32, CKR_OK },
    { { CKM_SHA3_224_KEY_GEN, 0, 0 }, { CKM_SHA3_224_HMAC, 0, 0 }, 28, CKR_OK },
    { { CKM_SHA3_256_KEY_GEN, 0, 0 }, { CKM_SHA3_256_HMAC, 0, 0 }, 32, CKR_OK },
    { { CKM_SHA3_384_KEY_GEN, 0, 0 }, { CKM_SHA3_384_HMAC, 0, 0 }, 48, CKR_OK },
    { { CKM_SHA3_512_KEY_GEN, 0, 0 }, { CKM_SHA3_512_HMAC, 0, 0 }, 64, CKR_OK },
    { { CKM_SHA_1_KEY_GEN, 0, 0 }, { CKM_SHA256_HMAC, 0, 0 }, 20, CKR_KEY_TYPE_INCONSISTENT },
};

/* This function tests generating a generic secret key to be used
 * with hmac sign and verify.
 */
CK_RV do_HMAC_SignVerify_WithGenKey(void)
{
    CK_BYTE data[] = { "Hi There" };
    CK_ULONG data_len = 8;
    CK_BYTE actual[MAX_HASH_SIZE];
    CK_ULONG actual_len;
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_ULONG i;

    /** begin test **/
    testsuite_begin("do_HMAC_SignVerify_WithGenKey");
    testcase_rw_session();
    testcase_user_login();

    for (i = 0; i < sizeof(hmac_mechs) / sizeof(struct hmac_mech_info); i++) {
        testcase_begin("Generate HMAC Key with %s (0x%lx) and Sign/Verify "
                       "with %s (0x%lx).",
                       mech_to_str(hmac_mechs[i].keygen_mech.mechanism),
                       hmac_mechs[i].keygen_mech.mechanism,
                       mech_to_str(hmac_mechs[i].hmac_mech.mechanism),
                       hmac_mechs[i].hmac_mech.mechanism);

        rc = CKR_OK;

        /* skip test if mech is not supported with this slot,
         * checking for generic secret key mechanism
         * and also sha1-hmac mechanism
         */
        if (!mech_supported(SLOT_ID, hmac_mechs[i].keygen_mech.mechanism)) {
            testcase_skip("mechanism %s (0x%lx) is not supported with slot %lu",
                          mech_to_str(hmac_mechs[i].keygen_mech.mechanism),
                          hmac_mechs[i].keygen_mech.mechanism, slot_id);
            goto error;
        }
        if (!mech_supported(SLOT_ID, hmac_mechs[i].hmac_mech.mechanism)) {
            testcase_skip("mechanism %s (0x%lx) is not supported with slot %lu",
                          mech_to_str(hmac_mechs[i].hmac_mech.mechanism),
                          hmac_mechs[i].hmac_mech.mechanism, slot_id);
            goto error;
        }

        /** clear buffers **/
        memset(actual, 0, sizeof(actual));

        /** get test vector info **/
        actual_len = sizeof(actual);

        /** generate key object **/
        rc = generate_SecretKey(session, hmac_mechs[i].key_len,
                                &hmac_mechs[i].keygen_mech, &h_key);
        if (rc != CKR_OK) {
            if (rc == CKR_POLICY_VIOLATION) {
                testcase_skip("generic secret key generation is not allowed by "
                              "policy");
                goto error;
            }

            testcase_error("generate_SecretKey rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** initialize signing **/
        rc = funcs->C_SignInit(session, &hmac_mechs[i].hmac_mech, h_key);
        if (rc != hmac_mechs[i].exp_rc) {
            testcase_error("C_SignInit rc=%s (expected: %s)", p11_get_ckr(rc),
                           p11_get_ckr(hmac_mechs[i].exp_rc));
            goto error;
        }
        if (rc != CKR_OK)
            goto error;

        /** do signing  **/
        rc = funcs->C_Sign(session, data, data_len, actual, &actual_len);
        if (rc != CKR_OK) {
            testcase_error("C_Sign rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /* Ensure the generated key can verify what it signed */
        testcase_new_assertion();

        /** initilaize verification **/
        rc = funcs->C_VerifyInit(session, &hmac_mechs[i].hmac_mech, h_key);
        if (rc != CKR_OK) {
            testcase_error("C_VerifyInit rc=%s", p11_get_ckr(rc));
            goto error;
        }

        /** do verification **/
        rc = funcs->C_Verify(session, data, data_len, actual, actual_len);
        if (rc != CKR_OK)
            testcase_fail("C_Verify rc=%s", p11_get_ckr(rc));
        else
            testcase_pass("Generate HMAC Key with %s (0x%lx) and Sign/Verify "
                          "with %s (0x%lx) passed.",
                          mech_to_str(hmac_mechs[i].keygen_mech.mechanism),
                          hmac_mechs[i].keygen_mech.mechanism,
                          mech_to_str(hmac_mechs[i].hmac_mech.mechanism),
                          hmac_mechs[i].hmac_mech.mechanism);

error:
        if (h_key != CK_INVALID_HANDLE &&
            funcs->C_DestroyObject(session, h_key) != CKR_OK)
            testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
        h_key = CK_INVALID_HANDLE;
    }

testcase_cleanup:
    testcase_user_logout();
    if (funcs->C_CloseAllSessions(slot_id) != CKR_OK)
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));

    return rc;
}

CK_RV do_SHA_derive_key(void)
{
    CK_MECHANISM secret_mech = { CKM_AES_KEY_GEN, 0, 0 };
    CK_ULONG key_len;
    CK_SESSION_HANDLE session;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    CK_OBJECT_HANDLE h_key = CK_INVALID_HANDLE;
    CK_OBJECT_HANDLE h_derived_key = CK_INVALID_HANDLE;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    unsigned int i, k;
    CK_BBOOL true = CK_TRUE;
    CK_ATTRIBUTE key_gen_tmpl[] = {
        {CKA_EXTRACTABLE, &true, sizeof(CK_BBOOL)},
        {CKA_VALUE_LEN, &key_len, sizeof(CK_ULONG)},
        {CKA_DERIVE, &true, sizeof(CK_BBOOL)},
        {CKA_IBM_USE_AS_DATA, &true, sizeof(CK_BBOOL)},
    };
    CK_ULONG key_gen_tmpl_len = sizeof(key_gen_tmpl) / sizeof(CK_ATTRIBUTE);
    CK_ATTRIBUTE  derive_tmpl[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_VALUE_LEN, &key_len, sizeof(CK_ULONG)},
    };
    CK_ULONG derive_tmpl_len = sizeof(derive_tmpl) / sizeof(CK_ATTRIBUTE);

    CK_MECHANISM derive_mechs[13] = {
        { CKM_SHA1_KEY_DERIVATION, 0, 0 },
        { CKM_SHA224_KEY_DERIVATION, 0, 0 },
        { CKM_SHA256_KEY_DERIVATION, 0, 0 },
        { CKM_SHA384_KEY_DERIVATION, 0, 0 },
        { CKM_SHA512_KEY_DERIVATION, 0, 0 },
        { CKM_SHA512_224_KEY_DERIVATION, 0, 0 },
        { CKM_SHA512_256_KEY_DERIVATION, 0, 0 },
        { CKM_SHA3_224_KEY_DERIVATION, 0, 0 },
        { CKM_SHA3_256_KEY_DERIVATION, 0, 0 },
        { CKM_SHA3_384_KEY_DERIVATION, 0, 0 },
        { CKM_SHA3_512_KEY_DERIVATION, 0, 0 },
        { CKM_SHAKE_128_KEY_DERIVATION, 0, 0 },
        { CKM_SHAKE_256_KEY_DERIVATION, 0, 0 }
    };

    struct {
        CK_KEY_TYPE keytype;
        CK_ULONG key_len;
    } attributes[5] = {
        { -1, 0 },
        { CKK_GENERIC_SECRET, 0 },
        { CKK_GENERIC_SECRET, 20 },
        { CKK_DES3, 0 },
        { CKK_AES, 16 },
    };

    testsuite_begin("do_SHA_derive_key");

    testcase_rw_session();
    testcase_user_login();

    if (!mech_supported(SLOT_ID, secret_mech.mechanism)) {
        testsuite_skip(1, "mechanism %lu not supported with slot %lu",
                       secret_mech.mechanism, slot_id);
        goto testcase_cleanup;
    }

    key_len = 32;
    rc = funcs->C_GenerateKey(session, &secret_mech, key_gen_tmpl,
                              key_gen_tmpl_len, &h_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, session)) {
            testsuite_skip(1, "AES key generation is not allowed by policy");
            goto testcase_cleanup;
        }

        testcase_error("generate_SecretKey rc=%s", p11_get_ckr(rc));
        goto testcase_cleanup;
    }

    for (i = 0; i < sizeof(derive_mechs) / sizeof(CK_MECHANISM); i++) {
        for (k = 0; k < sizeof(attributes) / sizeof(attributes[0]); k++) {
            key_type = attributes[k].keytype;
            key_len = attributes[k].key_len;

            /* SHA-1 can produce only 20 bytes, not sufficient for a 3DES key */
            if (key_type == CKK_DES3 &&
                derive_mechs[i].mechanism == CKM_SHA1_KEY_DERIVATION)
                continue;

            /*
             * SHAKE doesn't have a default digest size, so key type and/or
             * length must be specified
             */
            if ((derive_mechs[i].mechanism == CKM_SHAKE_128_KEY_DERIVATION ||
                 derive_mechs[i].mechanism == CKM_SHAKE_256_KEY_DERIVATION) &&
                 (key_type == (CK_ULONG)-1 ||
                  (key_type == CKK_GENERIC_SECRET && key_len == 0)))
                continue;

            testcase_begin("Derive key with %s keytype=0x%lx, value_len=%lu",
                           mech_to_str(derive_mechs[i].mechanism),
                           key_type, key_len);

            if (!mech_supported(SLOT_ID, derive_mechs[i].mechanism)) {
                 testcase_skip("mechanism %lu not supported with slot %lu",
                               derive_mechs[i].mechanism, slot_id);
                 continue;
             }

            if (key_type == (CK_ULONG)-1)
                derive_tmpl_len = 1;
            else if (key_len == 0)
                derive_tmpl_len = 2;
            else
                derive_tmpl_len = 3;

            rc = funcs->C_DeriveKey(session, &derive_mechs[i],
                                    h_key, derive_tmpl,
                                    derive_tmpl_len, &h_derived_key);
            if (rc != CKR_OK) {
                if (rc == CKR_POLICY_VIOLATION) {
                    testcase_skip("key derivation is not allowed by policy");
                    continue;
                }

                testcase_new_assertion();
                testcase_fail("Derive key with %s keytype=0x%lx, value_len=%lu: rc: %s",
                              mech_to_str(derive_mechs[i].mechanism),
                              key_type, key_len, p11_get_ckr(rc));
            } else {
                testcase_new_assertion();
                testcase_pass("Derive key with %s keytype=0x%lx, value_len=%lu",
                              mech_to_str(derive_mechs[i].mechanism),
                              key_type, key_len);
            }

            if (h_derived_key != CK_INVALID_HANDLE &&
                (rc = funcs->C_DestroyObject(session, h_derived_key)) != CKR_OK)
                testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
            h_derived_key = CK_INVALID_HANDLE;
        }
    }

    if (h_key != CK_INVALID_HANDLE &&
        (rc = funcs->C_DestroyObject(session, h_key)) != CKR_OK)
        testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));
    if (h_derived_key != CK_INVALID_HANDLE &&
        (rc = funcs->C_DestroyObject(session, h_derived_key)) != CKR_OK)
        testcase_error("C_DestroyObject rc=%s.", p11_get_ckr(rc));

testcase_cleanup:
    testcase_user_logout();
    if ((rc = funcs->C_CloseAllSessions(slot_id)) != CKR_OK)
        testcase_error("C_CloseAllSessions rc=%s", p11_get_ckr(rc));

    return rc;
}

CK_RV digest_funcs(void)
{
    CK_RV rc;
    unsigned int i;

    /** Digest tests **/
    for (i = 0; i < NUM_DIGEST_TEST_SUITES; i++) {
        rc = do_Digest(&digest_test_suites[i]);
        if (rc && !no_stop) {
            return rc;
        }
    }

    /** Multipart Digest tests **/
    for (i = 0; i < NUM_DIGEST_TEST_SUITES; i++) {
        rc = do_DigestUpdate(&digest_test_suites[i]);
        if (rc && !no_stop) {
            return rc;
        }
    }


    /**  RFC HMAC tests **/
    for (i = 0; i < NUM_OF_HMAC_TEST_SUITES; i++) {
        rc = do_SignVerify_HMAC(&hmac_test_suites[i]);
        if (rc && !no_stop)
            return rc;
    }

    /** FIPS HMAC tests **/
    for (i = 0; i < NUM_OF_FIPS_HMAC_TEST_SUITES; i++) {
        rc = do_Sign_FIPS_HMAC(&fips_hmac_test_suites[i]);
        if (rc && !no_stop)
            break;

        rc = do_Verify_FIPS_HMAC(&fips_hmac_test_suites[i]);
        if (rc && !no_stop)
            break;

        rc = do_Sign_FIPS_HMAC_GENERAL(&fips_hmac_general_test_suites[i]);
        if (rc && !no_stop)
            break;

        rc = do_Verify_FIPS_HMAC_GENERAL(&fips_hmac_general_test_suites[i]);
        if (rc && !no_stop)
            break;
    }

    /** HMAC Multipart tests **/
    for (i = 0; i < NUM_OF_FIPS_HMAC_TEST_SUITES; i++) {
        rc = do_SignUpdate_FIPS_HMAC(&fips_hmac_test_suites[i]);
        if (rc && !no_stop)
            break;

        rc = do_VerifyUpdate_FIPS_HMAC(&fips_hmac_test_suites[i]);
        if (rc && !no_stop)
            break;
    }

    /* HMAC test with a generated generic secret key */
    rc = do_HMAC_SignVerify_WithGenKey();

    rc = do_SHA_derive_key();

    return rc;
}

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int rc;
    CK_BBOOL no_init;
    CK_RV rv;

    SLOT_ID = 0;
    no_init = FALSE;


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

    // SAB Add calls to ALL functions before the C_Initialize gets hit

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
    rv = digest_funcs();
    testcase_print_result();

    funcs->C_Finalize(NULL);

    return testcase_return(rv);
}
