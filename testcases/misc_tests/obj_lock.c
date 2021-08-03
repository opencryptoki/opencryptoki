/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File: obj_lock.c
 *
 * Test driver.  In-depth regression test for PKCS #11
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <unistd.h>
#include <pthread.h>

#include <dlfcn.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"

void *usage_thread_func(CK_OBJECT_HANDLE *h_key)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_FLAGS flags;
    time_t t1, t2;
    CK_BYTE original[1024];
    CK_BYTE cipher[1024];
    CK_BYTE clear[1024];
    CK_ULONG i, count, orig_len, cipher_len, clear_len;
    CK_MECHANISM mech;

    CK_BYTE init_v[16] = {
        0x01, 0x02, 0x03, 0x04, 0x05,
        0x06, 0x07, 0x08, 0x09, 0x0A,
        0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10
    };

    // open a session for this thread
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = funcs->C_OpenSession(SLOT_ID, flags, NULL, NULL, &session);
    if (rv != CKR_OK) {
        testcase_error("Thread %lu: C_OpenSession() rc = %s", pthread_self(),
                       p11_get_ckr(rv));
        goto end_thread;
    }

    // clear buffers
    memset(original, 0, sizeof(original));
    memset(clear, 0, sizeof(clear));
    memset(cipher, 0, sizeof(cipher));

    // encrypt some data
    orig_len = sizeof(original);
    for (i = 0; i < orig_len; i++)
        original[i] = i % 255;

    mech.mechanism = CKM_AES_CBC;
    mech.ulParameterLen = 16;
    mech.pParameter = init_v;

    testcase_begin("Thread %lu: Encrypt/Decrypt", pthread_self());

    count = 0;
    time(&t1);
    do {
        rv = funcs->C_EncryptInit(session, &mech, *h_key);
        if (rv != CKR_OK) {
            testcase_error("Thread %lu: C_EncryptInit rc=%s", pthread_self(),
                           p11_get_ckr(rv));
            goto close_session;
        }

        cipher_len = sizeof(cipher);
        rv = funcs->C_Encrypt(session, original, orig_len, cipher, &cipher_len);
        if (rv != CKR_OK) {
            testcase_error("Thread %lu: C_Encrypt rc=%s", pthread_self(),
                           p11_get_ckr(rv));
            goto close_session;
        }

        rv = funcs->C_DecryptInit(session, &mech, *h_key);
        if (rv != CKR_OK) {
            testcase_error("Thread %lu: C_DecryptInit rc=%s", pthread_self(),
                           p11_get_ckr(rv));
            goto close_session;
        }

        clear_len = sizeof(clear);
        rv = funcs->C_Decrypt(session, cipher, cipher_len, clear, &clear_len);
        if (rv != CKR_OK) {
            testcase_error("Thread %lu: C_Decrypt rc=%s", pthread_self(),
                           p11_get_ckr(rv));
            goto close_session;
        }

        time(&t2);
        count++;
    } while (difftime(t2, t1) < 10);

    testcase_notice("Thread %lu: ran %lu pairs of Encrypt/Decrypt",
                    pthread_self(), count);

close_session:
    // close the session
    rv = funcs->C_CloseSession(session);
    if (rv != CKR_OK) {
        testcase_error("Thread %lu: C_CloseSession() rc = %s",pthread_self(),
                       p11_get_ckr(rv));
    }

end_thread:
    return NULL;
}

void *alter_thread_func(CK_OBJECT_HANDLE *h_key)
{
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_FLAGS flags;
    CK_ULONG count;
    time_t t1, t2;
    CK_BYTE id[100];
    CK_ATTRIBUTE attribs[] = {
        {CKA_ID, &id, sizeof(id)},
    };

    // open a session for this thread
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rv = funcs->C_OpenSession(SLOT_ID, flags, NULL, NULL, &session);
    if (rv != CKR_OK) {
        testcase_error("Thread %lu: C_OpenSession() rc = %s", pthread_self(),
                       p11_get_ckr(rv));
        goto end_thread;
    }

    testcase_begin("Thread %lu: Get/SetAttribute", pthread_self());

    count = 0;
    time(&t1);
    do {
        // Get attribute
        attribs[0].ulValueLen = sizeof(id);
        rv = funcs->C_GetAttributeValue(session, *h_key, attribs, 1);
        if (rv != CKR_OK) {
            testcase_error("Thread %lu: C_GetAttributeValue() rc = %s", pthread_self(),
                           p11_get_ckr(rv));
            goto close_session;
        }

        // Set attribute
        attribs[0].ulValueLen = sizeof(id);
        memset(id, count, sizeof(id));

        rv = funcs->C_SetAttributeValue(session, *h_key, attribs, 1);
        if (rv != CKR_OK) {
            testcase_error("Thread %lu: C_SetAttributeValue() rc = %s", pthread_self(),
                           p11_get_ckr(rv));
            goto close_session;
        }

        time(&t2);
        count++;
    } while (difftime(t2, t1) < 10);

    testcase_notice("Thread %lu: ran %lu pairs of Get/SetAttribute",
                    pthread_self(), count);

close_session:
    // close the session
    rv = funcs->C_CloseSession(session);
    if (rv != CKR_OK) {
        testcase_error("Thread %lu: C_CloseSession() rc = %s",pthread_self(),
                       p11_get_ckr(rv));
    }

end_thread:
    return NULL;
}

int generate_key(CK_SESSION_HANDLE session,
                CK_ULONG key_len, CK_BBOOL token_obj,
                CK_MECHANISM * mechkey, CK_OBJECT_HANDLE * h_key,
                CK_BBOOL extractable)
{
    CK_CHAR label[] = "OBJ_LOCK_TEST_KEY";
    CK_BYTE id[100] = { 0 };
    CK_ATTRIBUTE key_gen_tmpl[] = {
        {CKA_EXTRACTABLE, &extractable, sizeof(CK_BBOOL)},
        {CKA_VALUE_LEN, &key_len, sizeof(CK_ULONG)},
        {CKA_TOKEN, &token_obj, sizeof(token_obj)},
        {CKA_ID, id, sizeof(id)},
        {CKA_LABEL, label, sizeof(label) - 1},
    };

    CK_RV rc = funcs->C_GenerateKey(session, mechkey, key_gen_tmpl, 5, h_key);

    return rc;
}

int find_key(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE * h_key)
{
    CK_RV rc;
    CK_CHAR label[] = "OBJ_LOCK_TEST_KEY";
    CK_BBOOL true = TRUE;
    CK_OBJECT_HANDLE obj_list[1] = { 0 };
    CK_ULONG find_count = 0;
    CK_ATTRIBUTE find_tmpl[] = {
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_LABEL, label, sizeof(label) - 1},
    };

    rc = funcs->C_FindObjectsInit(session, find_tmpl, 2);
    if (rc != CKR_OK)
        return rc;

    rc = funcs->C_FindObjects(session, obj_list, 1, &find_count);
    if (rc != CKR_OK)
        goto done;

    if (find_count != 1) {
        rc = CKR_OBJECT_HANDLE_INVALID;
        goto done;
    }

    *h_key = obj_list[0];

done:
    funcs->C_FindObjectsFinal(session);
    return rc;
}

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int k;
    CK_BYTE user_pin[128];
    CK_ULONG user_pin_len;
    CK_ULONG num_usage_threads = 2;
    CK_ULONG num_alter_threads = 2;
    CK_BBOOL token_obj = FALSE;
    CK_BBOOL create_obj = TRUE;
    CK_BBOOL destroy_obj = TRUE;
    CK_RV rv;
    CK_SESSION_HANDLE session = CK_INVALID_HANDLE;
    CK_FLAGS flags;
    CK_MECHANISM mech;
    CK_OBJECT_HANDLE h_key;
    CK_ULONG i;
    pthread_t id[1000];

    for (k = 1; k < argc; k++) {
        if (strcmp(argv[k], "-slot") == 0) {
            ++k;
            SLOT_ID = atoi(argv[k]);
        }
        else if (strcmp(argv[k], "-usage-threads") == 0) {
            ++k;
            num_usage_threads = atoi(argv[k]);
        }
        else if (strcmp(argv[k], "-alter-threads") == 0) {
            ++k;
            num_alter_threads = atoi(argv[k]);
        }
        else if (strcmp(argv[k], "-token_obj") == 0) {
            token_obj = TRUE;
        }
        else if (strcmp(argv[k], "-reuse_obj") == 0) {
            create_obj = FALSE;
        }
        else if (strcmp(argv[k], "-keep_obj") == 0) {
            destroy_obj = FALSE;
        }
        else if (strcmp(argv[k], "-pkey") == 0) {
            pkey = TRUE;
        }

        if (strcmp(argv[k], "-h") == 0) {
            printf("usage:  %s [-slot <num>] [-usage-threads <num>] [-alter-threads <num>] [-token_obj] [-reuse_obj] [-keep_obj] [-pkey] [-h]\n\n", argv[0]);
            printf("By default, Slot #1 are used with 2 usage and 2 alter threads\n\n");
            return -1;
        }
    }

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;
    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    printf("Using slot #%lu ...\n\n", SLOT_ID);

    rv = do_GetFunctionList();
    if (rv != TRUE) {
        testcase_fail("do_GetFunctionList() rc = %s", p11_get_ckr(rv));
        goto out;
    }

    testcase_setup(0);
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
    rv = funcs->C_OpenSession(SLOT_ID, flags, NULL, NULL, &session);
    if (rv != CKR_OK) {
        testcase_fail("C_OpenSession() rc = %s", p11_get_ckr(rv));
        goto finalize;
    }
    testcase_pass("C_OpenSession");

    if (pkey) {
        /*
         * The pkey parm makes the test key non-extractable and therefore
         * eligible for protected key support in tokens supporting protected
         * keys (currently only ep11). Protected key support heavily depends
         * on the PKEY_MODE token option, so check your token config file
         * before using this test option.
         */
        if (!is_ep11_token(SLOT_ID)) {
            testcase_notice("Slot %lu doesn't support protected keys.", SLOT_ID);
            goto close_session;
        } else {
            testcase_notice("Check your token config file.");
            testcase_notice("Protected key support depends on the PKEY_MODE token option.");
        }
    }

    testcase_new_assertion();
    rv = funcs->C_Login(session, CKU_USER, user_pin, user_pin_len);
    if (rv != CKR_OK) {
        testcase_fail("C_Login() rc = %s", p11_get_ckr(rv));
        goto close_session;
    }
    testcase_pass("C_Login as User");

    if (!token_obj || create_obj) {
        // generate an AES key
        testcase_new_assertion();
        mech.mechanism = CKM_AES_KEY_GEN;
        mech.ulParameterLen = 0;
        mech.pParameter = NULL;

        rv = generate_key(session, 256 / 8, token_obj, &mech, &h_key, !pkey);
        if (rv != CKR_OK) {
            testcase_error("C_GenerateKey rc=%s", p11_get_ckr(rv));
            goto close_session;
        }
        testcase_pass("C_GenerateKey");
    } else {
        // find the existing AES key
        testcase_new_assertion();

        rv = find_key(session, &h_key);
        if (rv != CKR_OK) {
            testcase_error("find_key rc=%s", p11_get_ckr(rv));
            goto close_session;
        }
        testcase_pass("find_key");
    }
    // create the usage threads
    for (i = 0; i < num_usage_threads; i++) {
        testcase_new_assertion();
        pthread_create(&id[i], NULL, (void *(*)(void *)) usage_thread_func,
                       (void *)&h_key);
        testcase_pass("Creating usage thread %lu\n", i);
    }

    // create the alter threads
    for (i = 0; i < num_alter_threads; i++) {
        testcase_new_assertion();
        pthread_create(&id[num_usage_threads + i], NULL,
                       (void *(*)(void *)) alter_thread_func, (void *)&h_key);
        testcase_pass("Creating alter thread %lu\n", i);
    }

    // wait for all threads to end
    for (i = 0; i < num_usage_threads + num_alter_threads; i++) {
        pthread_join(id[i], NULL);
    }
    testcase_notice("All threads have ended.");

    if (!token_obj || destroy_obj) {
        testcase_new_assertion();
        rv = funcs->C_DestroyObject(session, h_key);
        if (rv != CKR_OK) {
            testcase_fail("C_DestroyObject() rc = %s", p11_get_ckr(rv));
        }
        testcase_pass("C_DestroyObject");
    }

close_session:
    testcase_new_assertion();
    if (session != CK_INVALID_HANDLE) {
        rv = funcs->C_CloseSession(session);
        if (rv != CKR_OK) {
            testcase_fail("C_CloseSession() rc = %s", p11_get_ckr(rv));
        }
    }
    testcase_pass("C_CloseSession");

finalize:
    testcase_new_assertion();
    rv = funcs->C_Finalize(NULL);
    if (rv != CKR_OK) {
        testcase_fail("C_Finalize() rc = %s", p11_get_ckr(rv));
    }
    testcase_pass("C_Finalize");

out:
    testcase_print_result();
    return testcase_return(rv);
}
