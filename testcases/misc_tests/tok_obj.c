/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File: tok_obj.c
 *
 * Test driver for testing the proper storage of token objects
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>
#include <dlfcn.h>

#include "pkcs11types.h"
#include "regress.h"

int do_GetInfo(void);
void init_coprocessor(void);

CK_RV C_GetFunctionList(CK_FUNCTION_LIST **);

// do_create_token_object()
int do_create_token_object(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE h_session;
    CK_RV rc;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    CK_BYTE true = TRUE;
    CK_BYTE false = FALSE;

    CK_OBJECT_HANDLE h_cert1;
    CK_OBJECT_CLASS cert1_class = CKO_CERTIFICATE;
    CK_CERTIFICATE_TYPE cert1_type = CKC_X_509;
    CK_BYTE cert1_subject[] = "Certificate subject #1";
    CK_BYTE cert1_id[] = "Certificate ID #1";
    CK_BYTE cert1_value[] =
        "AaBbCcDdEeFfGgHhIiJjKkLlMmNnOoPpQqRrSsTtUuVvWwXxYyZz";

    CK_ATTRIBUTE cert1_attribs[] = {
        {CKA_CLASS, &cert1_class, sizeof(cert1_class)},
        {CKA_TOKEN, &true, sizeof(true)},
        {CKA_CERTIFICATE_TYPE, &cert1_type, sizeof(cert1_type)},
        {CKA_SUBJECT, &cert1_subject, sizeof(cert1_subject)},
        {CKA_VALUE, &cert1_value, sizeof(cert1_value)},
        {CKA_PRIVATE, &true, sizeof(false)}
    };
    CK_ATTRIBUTE cert_id_attr[] = {
        {CKA_ID, &cert1_id, sizeof(cert1_id)}
    };
    CK_OBJECT_HANDLE obj_list[20];
    CK_ULONG objcount;

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;

    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    // create a USER R/W session
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    printf("open ing session \n");
    rc = funcs->C_OpenSession(SLOT_ID, flags, NULL, NULL, &h_session);
    if (rc != CKR_OK) {
        show_error("   C_OpenSession #1", rc);
        rc = FALSE;
        goto done;
    }

    printf("login ing session \n");
    rc = funcs->C_Login(h_session, CKU_USER, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        show_error("   C_Login #1", rc);
        rc = FALSE;
        goto done;
    }
    // create the token objects
    printf("create ing session \n");
    rc = funcs->C_CreateObject(h_session, cert1_attribs, 6, &h_cert1);
    if (rc != CKR_OK) {
        show_error("   C_CreateObject #1", rc);
        rc = FALSE;
        goto done;
    }

    printf("set ing session \n");
    rc = funcs->C_SetAttributeValue(h_session, h_cert1, cert_id_attr, 1);
    if (rc != CKR_OK) {
        show_error("   C_SetAttribute #1", rc);
        rc = FALSE;
        goto done;
    }

    // now, retrieve a list of all object handles
    printf("find init ing session \n");
    rc = funcs->C_FindObjectsInit(h_session, cert_id_attr, 1);
    if (rc != CKR_OK) {
        show_error("   C_FindObjectsInit #1", rc);
        rc = FALSE;
        goto done;
    }

    printf("find  session \n");
    rc = funcs->C_FindObjects(h_session, obj_list, 20, &objcount);
    if (rc != CKR_OK) {
        show_error("   C_FindObjects #1", rc);
        rc = FALSE;
        goto done;
    }

    printf("find final  session \n");
    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error("   C_FindObjectsFinal #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = TRUE;

done:
    printf("close all  session \n");
    funcs->C_CloseAllSessions(SLOT_ID);

    return rc;
}

// do_count_token_objects()
int do_count_token_objects(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE h_session;
    CK_RV rc;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_OBJECT_HANDLE obj_list[20];
    CK_ULONG find_count;

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;

    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    // create a USER R/W session
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rc = funcs->C_OpenSession(SLOT_ID, flags, NULL, NULL, &h_session);
    if (rc != CKR_OK) {
        show_error("   C_OpenSession #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_Login(h_session, CKU_USER, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        show_error("   C_Login #1", rc);
        rc = FALSE;
        goto done;
    }
    //
    //---------------------------------------------------------------------
    //

    // now, retrieve a list of all object handles
    rc = funcs->C_FindObjectsInit(h_session, NULL, 0);
    if (rc != CKR_OK) {
        show_error("   C_FindObjectsInit #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_FindObjects(h_session, obj_list, 20, &find_count);
    if (rc != CKR_OK) {
        show_error("   C_FindObjects #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error("   C_FindObjectsFinal #1", rc);
        rc = FALSE;
        goto done;
    }

    printf("Found:  %lu objects\n", find_count);
    rc = TRUE;

done:
    funcs->C_CloseAllSessions(SLOT_ID);

    return rc;
}


// do_verify_token_object()
int do_verify_token_object(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE h_session;
    CK_RV rc;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_OBJECT_HANDLE obj_list[20];
    CK_ULONG find_count;

    CK_BYTE cert1_id[] = "Certificate ID #1";

    CK_BYTE buf1[100];
    CK_ATTRIBUTE verify_attribs[] = {
        {CKA_ID, &buf1, sizeof(buf1)}
    };

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;

    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    // create a USER R/W session
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rc = funcs->C_OpenSession(SLOT_ID, flags, NULL, NULL, &h_session);
    if (rc != CKR_OK) {
        show_error("   C_OpenSession #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_Login(h_session, CKU_USER, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        show_error("   C_Login #1", rc);
        rc = FALSE;
        goto done;
    }
    //
    //---------------------------------------------------------------------
    //

    // now, retrieve a list of all object handles
    rc = funcs->C_FindObjectsInit(h_session, NULL, 0);
    if (rc != CKR_OK) {
        show_error("   C_FindObjectsInit #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_FindObjects(h_session, obj_list, 20, &find_count);
    if (rc != CKR_OK) {
        show_error("   C_FindObjects #1", rc);
        rc = FALSE;
        goto done;
    }

    if (find_count == 0) {
        printf("ERROR:  no objects to examine\n");
        rc = FALSE;
        goto done;
    }
    // now, try to extract the CKA_APPLICATION attribute from the original
    // this will pull in the token's default value for CKA_APPLICATION which
    verify_attribs[0].ulValueLen = sizeof(buf1);
    rc = funcs->C_GetAttributeValue(h_session, obj_list[0], verify_attribs, 1);
    if (rc != CKR_OK) {
        show_error("   C_GetAttributeValue #1", rc);
        rc = FALSE;
        goto done;
    }

    if (memcmp(&cert1_id, verify_attribs[0].pValue, sizeof(cert1_id)) != 0) {
        printf("   ERROR:  extracted attribute doesn't match\n");
        rc = FALSE;
        goto done;
    }

    printf("Attribute matches!  Good.\n");
    rc = TRUE;

done:
    funcs->C_CloseAllSessions(SLOT_ID);

    return rc;
}

int do_destroy_all_token_objects(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE h_session;
    CK_RV rc;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    CK_OBJECT_HANDLE obj_list[20];
    CK_ULONG find_count;
    CK_ULONG i;

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;

    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    // create a USER R/W session
    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rc = funcs->C_OpenSession(SLOT_ID, flags, NULL, NULL, &h_session);
    if (rc != CKR_OK) {
        show_error("   C_OpenSession #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_Login(h_session, CKU_USER, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        show_error("   C_Login #1", rc);
        rc = FALSE;
        goto done;
    }
    //
    //---------------------------------------------------------------------
    //

    // now, retrieve a list of all object handles
    rc = funcs->C_FindObjectsInit(h_session, NULL, 0);
    if (rc != CKR_OK) {
        show_error("   C_FindObjectsInit #1", rc);
        rc = FALSE;
        goto done;
    }

    do {
        rc = funcs->C_FindObjects(h_session, obj_list, 20, &find_count);
        if (rc != CKR_OK) {
            show_error("   C_FindObjects #1", rc);
            rc = FALSE;
            goto done;
        }

        for (i = 0; i < find_count; i++) {
            rc = funcs->C_DestroyObject(h_session, obj_list[i]);
            if (rc != CKR_OK) {
                printf("   C_DestroyObject #%lu returned", i);
                show_error(" ", rc);
                rc = FALSE;
                goto done;
            }
        }
    } while (find_count != 0);

    rc = funcs->C_FindObjectsFinal(h_session);
    if (rc != CKR_OK) {
        show_error("   C_FindObjectsFinal #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = TRUE;

done:
    funcs->C_CloseAllSessions(SLOT_ID);

    return rc;
}


int do_inittoken(void)
{
    CK_BYTE label[32];
    CK_BYTE so_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG so_pin_len;
    int len;
    CK_RV rc;

    if (get_so_pin(so_pin))
        return CKR_FUNCTION_FAILED;

    so_pin_len = (CK_ULONG) strlen((char *) so_pin);

    //   memcpy( label, "A new label                           ", 32 );
    memcpy(label, "                                      ", 32);

    printf("Enter Token Label:");
    if (!fgets((char *)label, 32, stdin)) {
        show_error("fgets failed", (unsigned long)CKR_FUNCTION_FAILED);
        rc = FALSE;
        goto done;
    }
    printf("\nLabel is: %s", label);

    for (len = 0; len < 31; len++) {
        if (label[len] == '\0') {
            label[len] = ' ';
            break;
        }
    }
    printf("\n");

    //   memcpy( label,   "RemoteLeeds                           ", 32 );

    rc = funcs->C_InitToken(SLOT_ID, NULL, so_pin_len, label);
    if (rc != CKR_ARGUMENTS_BAD) {
        show_error(" C_InitToken Fail #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_InitToken(SLOT_ID, so_pin, so_pin_len, NULL);
    if (rc != CKR_ARGUMENTS_BAD) {
        show_error(" C_InitToken Fail #2", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_InitToken(SLOT_ID, so_pin, so_pin_len, label);
    if (rc != CKR_OK) {
        show_error("   C_InitToken #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = TRUE;

done:
    return rc;
}


int do_setUserPIN(void)
{
    CK_BYTE so_pin[PKCS11_MAX_PIN_LEN];
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len, so_pin_len;
    CK_FLAGS flags;
    CK_SESSION_HANDLE h_session;
    CK_ULONG rc;

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;

    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    if (get_so_pin(so_pin))
        return CKR_FUNCTION_FAILED;

    so_pin_len = (CK_ULONG) strlen((char *) so_pin);

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    rc = funcs->C_OpenSession(SLOT_ID, flags, NULL, NULL, &h_session);
    if (rc != CKR_OK) {
        show_error("   C_OpenSession #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_Login(h_session, CKU_SO, so_pin, so_pin_len);
    if (rc != CKR_OK) {
        show_error("   C_Login #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = funcs->C_InitPIN(h_session, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        show_error("   C_InitPIN #1", rc);
        rc = FALSE;
        goto done;
    }

    rc = TRUE;

done:
    funcs->C_CloseAllSessions(SLOT_ID);

    return rc;
}


int do_GetTokenInfo(void)
{
    CK_SLOT_ID slot_id;
    CK_TOKEN_INFO info;
    CK_RV rc;

    printf("do_GetTokenInfo...\n");

    slot_id = SLOT_ID;

    rc = funcs->C_GetTokenInfo(slot_id, &info);
    if (rc != CKR_OK) {
        show_error("   C_GetTokenInfo", rc);
        return FALSE;
    }

    printf("   CK_TOKEN_INFO for slot #1:  \n");
    printf("      label:                   %32.32s\n", info.label);
    printf("      manufacturerID:          %32.32s\n", info.manufacturerID);
    printf("      model:                   %16.16s\n", info.model);
    printf("      serialNumber:            %16.16s\n", info.serialNumber);
    printf("      flags:                   %p\n", (void *) info.flags);
    printf("      ulMaxSessionCount:       %lu\n", info.ulMaxSessionCount);
    printf("      ulSessionCount:          %lu\n", info.ulSessionCount);
    printf("      ulMaxRwSessionCount:     %lu\n", info.ulMaxRwSessionCount);
    printf("      ulRwSessionCount:        %lu\n", info.ulRwSessionCount);
    printf("      ulMaxPinLen:             %lu\n", info.ulMaxPinLen);
    printf("      ulMinPinLen:             %lu\n", info.ulMinPinLen);
    printf("      ulTotalPublicMemory:     %lu\n", info.ulTotalPublicMemory);
    printf("      ulFreePublicMemory:      %lu\n", info.ulFreePublicMemory);
    printf("      ulTotalPrivateMemory:    %lu\n", info.ulTotalPrivateMemory);
    printf("      ulFreePrivateMemory:     %lu\n", info.ulFreePrivateMemory);
    printf("      hardwareVersion:         %d.%d\n", info.hardwareVersion.major,
           info.hardwareVersion.minor);
    printf("      firmwareVersion:         %d.%d\n", info.firmwareVersion.major,
           info.firmwareVersion.minor);
    printf("      time:                    %16.16s\n", info.utcTime);

    printf("Looks okay...\n");

    return TRUE;
}

void menu(void)
{
    printf("\n1.  Create a token object\n");
    printf("2.  Count token objects\n");
    printf("3.  Verify contents of the first token object\n");
    printf("4.  Destroy all token objects\n");
    printf("5.  Initialize Token\n");
    printf("6.  Set USER PIN\n");
    printf("7.  Get Token Info\n");
    printf("8.  Create Data Object\n");
    printf("9.  Exit\n");
    printf("Selection:   ");
    fflush(stdout);
}

int do_CreateDataObject(void)
{
    CK_FLAGS flags;
    CK_SESSION_HANDLE h_session;
    CK_RV rc;
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;

    CK_OBJECT_HANDLE h_obj;
    CK_OBJECT_CLASS class = CKO_DATA;
    CK_UTF8CHAR label[] = "A data object";
    CK_UTF8CHAR application[] = "An application";
    CK_BYTE data[] = "Sample data";
    CK_BBOOL true = CK_TRUE;
    CK_ATTRIBUTE attrs[] = {
      {CKA_CLASS, &class, sizeof(class)},
      {CKA_TOKEN, &true, sizeof(true)},
      {CKA_LABEL, label, sizeof(label) - 1},
      {CKA_APPLICATION, application, sizeof(application) - 1},
      {CKA_VALUE, data, sizeof(data)}
    };
    CK_ULONG num_attrs = sizeof(attrs) / sizeof(CK_ATTRIBUTE);

    if (get_user_pin(user_pin))
        return CKR_FUNCTION_FAILED;

    user_pin_len = (CK_ULONG) strlen((char *) user_pin);

    flags = CKF_SERIAL_SESSION | CKF_RW_SESSION;
    printf("open session\n");
    rc = funcs->C_OpenSession(SLOT_ID, flags, NULL, NULL, &h_session);
    if (rc != CKR_OK) {
        show_error("  C_OpenSession #1", rc);
        rc = FALSE;
        goto done;
    }

    printf("login session\n");
    rc = funcs->C_Login(h_session, CKU_USER, user_pin, user_pin_len);
    if (rc != CKR_OK) {
        show_error("  C_Login #1", rc);
        rc = FALSE;
        goto done;
    }

    printf("create data object\n");
    rc = funcs->C_CreateObject(h_session, attrs, num_attrs, &h_obj);
    if (rc != CKR_OK) {
        show_error("  C_CreateObject #1", rc);
        rc = FALSE;
        goto done;
    }

    printf("Data object created successfully.\n");
    rc = TRUE;

done:
    printf("close session\n");
    funcs->C_CloseAllSessions(SLOT_ID);

    return rc;
}

int main(int argc, char **argv)
{
    CK_BYTE line[20];
    CK_ULONG val;
    int i, rc;

    SLOT_ID = 0;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-slot") == 0) {
            if (i + 1 >= argc) {
                printf("Slot number missing\n");
                return -1;
            }
            SLOT_ID = atoi(argv[i + 1]);
            i++;
        }

        if (strcmp(argv[i], "-h") == 0) {
            printf("usage:  %s [-slot <num>] [-h]\n\n", argv[0]);
            printf("By default, Slot #1 is used\n\n");
            return -1;
        }
    }

    printf("Using slot #%lu...\n\n", SLOT_ID);

    rc = do_GetFunctionList();
    if (!rc)
        return rc;

    funcs->C_Initialize(NULL);

    menu();

    while (fgets((char *) line, 10, stdin)) {
        val = atoi((char *) line);

        switch (val) {
        case 1:
            do_create_token_object();
            break;
        case 2:
            do_count_token_objects();
            break;
        case 3:
            do_verify_token_object();
            break;
        case 4:
            do_destroy_all_token_objects();
            break;
        case 5:
            do_inittoken();
            break;
        case 6:
            do_setUserPIN();
            break;
        case 7:
            do_GetTokenInfo();
            break;
        case 8:
            do_CreateDataObject();
            break;
        case 9:
            goto done;
            break;
        }
        menu();
    }

done:
    rc = funcs->C_Finalize(NULL);

    return rc;
}
