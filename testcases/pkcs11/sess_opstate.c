/*
 * COPYRIGHT (c) International Business Machines Corp. 2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * Testcase for
 * C_GetOperationState / C_SetOperationState
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <time.h>

#include "pkcs11types.h"
#include "regress.h"
#include "common.c"


CK_BYTE_PTR alloc_random_buf(CK_SESSION_HANDLE sess, CK_LONG nbytes)
{
    CK_RV rc;
    CK_BYTE_PTR ptr = malloc(nbytes);
    if (ptr == NULL) {
        testcase_error("malloc(%ld) failed", nbytes);
        return NULL;
    }

    rc = funcs->C_GenerateRandom(sess, ptr, nbytes);
    if (rc != CKR_OK) {
        testcase_error("C_GenerateRandom() rc=%s", p11_get_ckr(rc));
        free(ptr);
        return NULL;
    }

    return ptr;
}

int sess_opstate_funcs(int loops)
{
    CK_SESSION_HANDLE s1, s2;
    CK_SLOT_ID slot_id = SLOT_ID;
    CK_ULONG flags;
    CK_RV rc;
    unsigned int i;
    int counter, rbytes;
    CK_BYTE *rdata = NULL;
    CK_MECHANISM mech1 = { CKM_SHA256, 0, 0 };
    CK_MECHANISM mech2 = { CKM_SHA_1, 0, 0 };
    CK_ULONG r1hlen, r2hlen, hlen;
    CK_BYTE r1hash[32], r2hash[32], hash[32];
    CK_ULONG opstatelen;
    CK_BYTE *opstate = NULL;

    testcase_begin("Get/SetOperationState digest test");

    // open 2 sessions
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &s1);
    if (rc != CKR_OK) {
        testcase_error("C_OpenSession() rc=%s", p11_get_ckr(rc));
        goto out;
    }

    rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, &s2);
    if (rc != CKR_OK) {
        testcase_error("C_OpenSession() rc=%s", p11_get_ckr(rc));
        goto out;
    }

    if (!mech_supported(SLOT_ID, mech1.mechanism)) {
        testcase_skip("Mechanism CKM_SHA256 is not supported with slot "
                      "%lu. Skipping key check", SLOT_ID);
        goto out;
    }

    // init digest for both sessions
    rc = funcs->C_DigestInit(s1, &mech1);
    if (rc != CKR_OK) {
        testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
        goto out;
    }

    rc = funcs->C_DigestInit(s2, &mech1);
    if (rc != CKR_OK) {
        testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
        goto out;
    }

    // now loop over some digest updates
    for (counter = 0; counter < loops; counter++) {
        // create some random data
        rbytes = 1 + random() % sizeof(rdata);
        rdata = alloc_random_buf(s1, rbytes);
        if (!rdata)
            goto out;

        // digest update on session 1
        rc = funcs->C_DigestUpdate(s1, rdata, rbytes);
        if (rc != CKR_OK) {
            testcase_error("C_DigestUpdate rc=%s", p11_get_ckr(rc));
            goto out;
        }

        // restore op state on session 2
        if (opstate != NULL) {
            rc = funcs->C_SetOperationState(s2, opstate, opstatelen, 0, 0);
            if (rc != CKR_OK) {
                testcase_error("C_SetOperationState rc=%s", p11_get_ckr(rc));
                goto out;
            }
            free(opstate);
            opstate = NULL;
        }

        // digest update on session 2
        rc = funcs->C_DigestUpdate(s2, rdata, rbytes);
        if (rc != CKR_OK) {
            testcase_error("C_DigestUpdate rc=%s", p11_get_ckr(rc));
            goto out;
        }

        // fetch op state on session 2
        opstatelen = 0;
        rc = funcs->C_GetOperationState(s2, NULL, &opstatelen);
        if (rc != CKR_OK) {
            if (rc == CKR_STATE_UNSAVEABLE) {
                testcase_skip("Get/SetOperationState digest test: state unsavable");
                rc = CKR_OK;
                goto out;
            }
            testcase_error("C_GetOperationState rc=%s", p11_get_ckr(rc));
            goto out;
        }

        opstate = malloc(opstatelen);
        if (opstate == NULL) {
            testcase_error("malloc(%lu) failed", opstatelen);
            goto out;
        }

        rc = funcs->C_GetOperationState(s2, opstate, &opstatelen);
        if (rc != CKR_OK) {
            if (rc == CKR_STATE_UNSAVEABLE) {
                testcase_skip("Get/SetOperationState digest test: state unsavable");
                rc = CKR_OK;
                goto out;
            }
            testcase_error("C_GetOperationState rc=%s", p11_get_ckr(rc));
            goto out;
        }

        free(rdata);
        rdata = NULL;

        // now do something different on session 2, but first
        // we have to wipe out the started digest operation
        hlen = sizeof(hash);
        rc = funcs->C_DigestFinal(s2, hash, &hlen);
        if (rc != CKR_OK) {
            testcase_error("C_DigestFinal rc=%s", p11_get_ckr(rc));
            goto out;
        }

        if (!mech_supported(SLOT_ID, mech2.mechanism)) {
            testcase_skip("Mechanism CKM_SHA_1 is not supported with slot "
                          "%lu. Skipping key check", SLOT_ID);
            continue;
        }

        // so now let's do a digest init/update/finish
        // to randomize the memory a little
        rc = funcs->C_DigestInit(s2, &mech2);
        if (rc != CKR_OK) {
            testcase_error("C_DigestInit rc=%s", p11_get_ckr(rc));
            goto out;
        }

        for (i = 0; i < (unsigned int)loops; i++) {
            rbytes = 1 + random() % sizeof(rdata);
            rdata = alloc_random_buf(s1, rbytes);
            if (!rdata)
                goto out;

            rc = funcs->C_DigestUpdate(s2, rdata, rbytes);
            if (rc != CKR_OK) {
                testcase_error("C_DigestUpdate rc=%s", p11_get_ckr(rc));
                goto out;
            }
            free(rdata);
            rdata = NULL;
        }
        hlen = sizeof(hash);

        rc = funcs->C_DigestFinal(s2, hash, &hlen);
        if (rc != CKR_OK) {
            testcase_error("C_DigestFinal rc=%s", p11_get_ckr(rc));
            goto out;
        }
    }

    // restore op state on session 2
    rc = funcs->C_SetOperationState(s2, opstate, opstatelen, 0, 0);
    if (rc != CKR_OK) {
        testcase_error("C_SetOperationState rc=%s", p11_get_ckr(rc));
        goto out;
    }

    // digest finish
    r1hlen = sizeof(r1hash);
    rc = funcs->C_DigestFinal(s1, r1hash, &r1hlen);
    if (rc != CKR_OK) {
        testcase_error("C_DigestFinal rc=%s", p11_get_ckr(rc));
        goto out;
    }

    r2hlen = sizeof(r2hash);
    rc = funcs->C_DigestFinal(s2, r2hash, &r2hlen);
    if (rc != CKR_OK) {
        testcase_error("C_DigestFinal rc=%s", p11_get_ckr(rc));
        goto out;
    }

    // check both hashes
    if (r1hlen != r2hlen) {
        testcase_fail("hash length differ");
        goto out;
    }
    if (memcmp(r1hash, r2hash, r1hlen) != 0) {
        testcase_fail("hash values differs");
        goto out;
    }

    testcase_new_assertion();
    testcase_pass("Get/SetOperationState digest test");

out:
    if (opstate)
        free(opstate);
    if (rdata)
        free(rdata);
    funcs->C_CloseAllSessions(slot_id);

    return rc;
}

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int rc, i, j, loops = 0;
    CK_RV rv;

    SLOT_ID = 0;
    no_init = FALSE;

    srandom(time(0));

    for (i = 0; i < argc; i++) {
        if (strncmp(argv[i], "loops=", 6) == 0) {
            sscanf(argv[i] + 6, "%i", &loops);
            for (j = i; j < argc; j++)
                argv[j] = argv[j + 1];
            argc--;
        }
    }

    if (loops < 1)
        loops = 100;

    rc = do_ParseArgs(argc, argv);
    if (rc != 1)
        return rc;

    printf("Using slot #%lu...\n\n", SLOT_ID);
    printf("With option: no_init: %d\n", no_init);
    printf("Running %d loops...\n", loops);

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

        rv = funcs->C_GetFunctionStatus(hsess);
        if (rv != CKR_FUNCTION_NOT_PARALLEL)
            return rv;

        rv = funcs->C_CancelFunction(hsess);
        if (rv != CKR_FUNCTION_NOT_PARALLEL)
            return rv;
    }
    testcase_setup();
    rc = sess_opstate_funcs(loops);
    testcase_print_result();

    return testcase_return(rc);
}
