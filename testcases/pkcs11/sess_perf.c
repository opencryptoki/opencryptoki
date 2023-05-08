/*
 * COPYRIGHT (c) International Business Machines Corp. 2010-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File: sess_perf.c */

#include <windows.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "regress.h"
#include "defs.h"

#define DATALEN 1024
CK_BYTE DATA[DATALEN];
CK_BYTE DUMP[DATALEN];

typedef struct _context_table {
    CK_SESSION_HANDLE hsess;
    CK_OBJECT_HANDLE hkey;
} context_table_t;

void dump_session_info(CK_SESSION_INFO * info)
{
    printf("   CK_SESSION_INFO:\n");
    printf("      slotID:         %lu\n", info->slotID);
    printf("      state:          ");
    switch (info->state) {
    case CKS_RO_PUBLIC_SESSION:
        printf("CKS_RO_PUBLIC_SESSION\n");
        break;
    case CKS_RW_PUBLIC_SESSION:
        printf("CKS_RW_PUBLIC_SESSION\n");
        break;
    case CKS_RO_USER_FUNCTIONS:
        printf("CKS_RO_USER_FUNCTIONS\n");
        break;
    case CKS_RW_USER_FUNCTIONS:
        printf("CKS_RW_USER_FUNCTIONS\n");
        break;
    case CKS_RW_SO_FUNCTIONS:
        printf("CKS_RW_SO_FUNCTIONS\n");
        break;
    }
    printf("      flags:          0x%lx\n", info->flags);
    printf("      ulDeviceError:  %lu\n", info->ulDeviceError);
}

int create_aes_encrypt_context(CK_SESSION_HANDLE_PTR hsess,
                               CK_OBJECT_HANDLE_PTR hkey)
{
    CK_SLOT_ID slot_id;
    CK_FLAGS flags;
    CK_RV rc;
    CK_MECHANISM mech;
    CK_ULONG key_len = 16;
    CK_ATTRIBUTE tkey = { CKA_VALUE_LEN, &key_len, sizeof(CK_ULONG) };

    /* create session */
    slot_id = SLOT_ID;
    flags = CKF_SERIAL_SESSION; // read-only session

    rc = funcs->C_OpenSession(slot_id, flags, NULL, NULL, hsess);
    if (rc != CKR_OK) {
        testcase_error("C_OpenSession #1, rc=%lx, %s", rc, p11_get_ckr(rc));
        return FALSE;
    }

    /* generate key in this specific session */
    mech.mechanism = CKM_AES_KEY_GEN;
    mech.ulParameterLen = 0;
    mech.pParameter = NULL;

    rc = funcs->C_GenerateKey(*hsess, &mech, &tkey, 1, hkey);
    if (rc != CKR_OK) {
        testcase_error("C_GenerateKey #1, rc=%lx, %s", rc, p11_get_ckr(rc));
        return FALSE;
    }

    /* Get Random for Initialization Vector */
    mech.mechanism = CKM_AES_CBC;
    mech.ulParameterLen = 16;
    mech.pParameter = "1234567890123456";

    /* Create encryption context using this session and key */
    rc = funcs->C_EncryptInit(*hsess, &mech, *hkey);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptInit #1, rc=%lx, %s", rc, p11_get_ckr(rc));
        return FALSE;
    }

    return TRUE;
}

int encrypt_DATA(CK_SESSION_HANDLE hsess, CK_OBJECT_HANDLE hkey,
                 CK_ULONG blocklen)
{
    CK_RV rc;
    CK_ULONG outlen = 16;
    unsigned long int i;

    UNUSED(hkey);

    for (i = 0; i < DATALEN; i += outlen) {
        rc = funcs->C_EncryptUpdate(hsess, (CK_BYTE_PTR) (DATA + i), blocklen,
                                    (CK_BYTE_PTR) (DUMP + i), &outlen);
        if (rc != CKR_OK) {
            testcase_error("C_Encrypt #1, rc=%lx, %s", rc, p11_get_ckr(rc));
            return FALSE;
        }
    }

    return TRUE;
}


int finalize_aes_encrypt_context(CK_SESSION_HANDLE hsess)
{
    CK_RV rc;
    CK_ULONG outlen = DATALEN;

    rc = funcs->C_EncryptFinal(hsess, DUMP, &outlen);
    if (rc != CKR_OK) {
        testcase_error("C_EncryptFinal#1, rc=%lx, %s", rc, p11_get_ckr(rc));
        return FALSE;
    }

    rc = funcs->C_CloseSession(hsess);
    if (rc != CKR_OK) {
        testcase_error("C_CloseSession #1, rc=%lx, %s", rc, p11_get_ckr(rc));
        return FALSE;
    }

    return TRUE;
}

int close_all_sess(void)
{
    CK_SLOT_ID slot_id;
    CK_RV rc;

    slot_id = SLOT_ID;

    rc = funcs->C_CloseAllSessions(slot_id);
    if (rc != CKR_OK) {
        testcase_error("C_CloseAllSessions #1, rc=%lx, %s", rc, p11_get_ckr(rc));
        return FALSE;
    }

    return TRUE;
}

int do_SessionPerformance(unsigned int count)
{
    SYSTEMTIME t1, t2;
    int rc;
    unsigned int i;
    context_table_t *t = NULL;

    if (count == 0) {
        testcase_error("do_SessionPerformance: zero session count");
        return FALSE;
    }

    t = (context_table_t *) calloc(count, sizeof(context_table_t));
    if (t == NULL) {
        testcase_error("do_SessionPerformance: insufficient memory");
        return FALSE;
    }

    /* create encryption contexts */
    for (i = 0; i < count; i++) {
        rc = create_aes_encrypt_context(&(t[i].hsess), &(t[i].hkey));
        if (rc == FALSE) {
            testcase_error("create_aes_encrypt_context");
            goto ret;
        }
    }

    /* Time encrypt operation in the first and last session */
    GetSystemTime(&t1);
    rc = encrypt_DATA(t[0].hsess, t[0].hkey, 16);
    if (rc == FALSE) {
        testcase_error("encrypt_DATA #1");
        goto ret;
    }

    rc = encrypt_DATA(t[count - 1].hsess, t[count - 1].hkey, 16);
    if (rc == FALSE) {
        testcase_error("encrypt_DATA #2");
        goto ret;
    }
    GetSystemTime(&t2);
    process_time(t1, t2);

    for (i = 0; i < count; i++) {
        rc = finalize_aes_encrypt_context(t[i].hsess);
        if (rc == FALSE) {
            testcase_error("finalize_aes_encrypt_context");
            goto ret;
        }
    }

    rc = TRUE;
ret:
    if (t != NULL)
        free(t);
    return rc;
}

int main(int argc, char **argv)
{
    CK_C_INITIALIZE_ARGS cinit_args;
    int rc, i;


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
    testcase_begin("do_SessionPerformance");
    testcase_new_assertion();

    for (i = 100; i < 50000; i = 1.2 * i) {
        printf("timing do_SessionPerformance(%d)\n", i);
        do_SessionPerformance(i);
    }

    if (t_errors > 0)
        testcase_notice("do_SessionPerformance ran with %ld error(s)", t_errors);
    else
        testcase_pass("do_SessionPerformance passed");

    testcase_print_result();

    return 0;
}
