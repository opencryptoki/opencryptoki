/*
 * COPYRIGHT (c) International Business Machines Corp. 2006-2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
 
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <memory.h>

#include "pkcs11types.h"
#include "common.c"
#include "regress.h"
#include "mech_to_str.h"
#include "ec_curves.h"

#define NUMKEYS 16

struct keys {
    union keysunion {
        struct details {
            // AB keys
            CK_OBJECT_HANDLE aes;
            CK_OBJECT_HANDLE des2;
            CK_OBJECT_HANDLE des3;
            CK_OBJECT_HANDLE generic;
            CK_OBJECT_HANDLE rsapub;
            CK_OBJECT_HANDLE rsapriv;
            CK_OBJECT_HANDLE ecpub;
            CK_OBJECT_HANDLE ecpriv;
            CK_OBJECT_HANDLE dsapub;
            CK_OBJECT_HANDLE dsapriv;
            CK_OBJECT_HANDLE dhpub;
            CK_OBJECT_HANDLE dhpriv;
            // non-AB key
            CK_OBJECT_HANDLE nonabpub;
            CK_OBJECT_HANDLE nonabpriv;
            CK_OBJECT_HANDLE nonabecpub;
            CK_OBJECT_HANDLE nonabecpriv;
        } d;
        CK_OBJECT_HANDLE keys[NUMKEYS];
    } u;
} keys;

CK_BYTE DSA_PUBL_PRIME[128] = {
    0xba, 0xa2, 0x5b, 0xd9, 0x77, 0xb3, 0xf0, 0x2d, 0xa1, 0x65,
    0xf1, 0x83, 0xa7, 0xc9, 0xf0, 0x8a, 0x51, 0x3f, 0x74, 0xe8,
    0xeb, 0x1f, 0xd7, 0x0a, 0xd5, 0x41, 0xfa, 0x52, 0x3c, 0x1f,
    0x79, 0x15, 0x55, 0x18, 0x45, 0x41, 0x29, 0x27, 0x12, 0x4a,
    0xb4, 0x32, 0xa6, 0xd2, 0xec, 0xe2, 0x82, 0x73, 0xf4, 0x30,
    0x66, 0x1a, 0x31, 0x06, 0x37, 0xd2, 0xb0, 0xe4, 0x26, 0x39,
    0x2a, 0x0e, 0x48, 0xf6, 0x77, 0x94, 0x47, 0xea, 0x7d, 0x99,
    0x22, 0xce, 0x65, 0x61, 0x82, 0xd5, 0xe3, 0xfc, 0x15, 0x3f,
    0xff, 0xff, 0xc8, 0xb9, 0x4f, 0x37, 0xbf, 0x7a, 0xa6, 0x6a,
    0xbe, 0xff, 0xa9, 0xdf, 0xfd, 0xed, 0x4a, 0xb6, 0x83, 0xd6,
    0x0f, 0xea, 0xf6, 0x90, 0x4f, 0x12, 0x8e, 0x09, 0x6e, 0x3c,
    0x0a, 0x6d, 0x2e, 0xfb, 0xb3, 0x79, 0x90, 0x8e, 0x39, 0xc0,
    0x86, 0x0e, 0x5d, 0xf0, 0x56, 0xcd, 0x26, 0x45
};

CK_BYTE DSA_PUBL_SUBPRIME[20] = {
    0x9f, 0x3d, 0x47, 0x13, 0xa3, 0xff, 0x93, 0xbb, 0x4a, 0xa6,
    0xb0, 0xf1, 0x7e, 0x54, 0x1e, 0xba, 0xf0, 0x66, 0x03, 0x61
};


CK_BYTE DSA_PUBL_BASE[128] = {
    0x1a, 0x5b, 0xfe, 0x12, 0xba, 0x85, 0x8e, 0x9b, 0x08, 0x86,
    0xd1, 0x43, 0x9b, 0x4a, 0xaf, 0x44, 0x31, 0xdf, 0xa1, 0x57,
    0xd8, 0xe0, 0xec, 0x34, 0x07, 0x4b, 0x78, 0x8e, 0x3c, 0x62,
    0x47, 0x4c, 0x2f, 0x5d, 0xd3, 0x31, 0x2c, 0xe9, 0xdd, 0x59,
    0xc5, 0xe7, 0x2e, 0x06, 0x40, 0x6c, 0x72, 0x9c, 0x95, 0xc6,
    0xa4, 0x2a, 0x1c, 0x1c, 0x45, 0xb9, 0xf3, 0xdc, 0x83, 0xb6,
    0xc6, 0xdd, 0x94, 0x45, 0x4f, 0x74, 0xc6, 0x55, 0x36, 0x54,
    0xba, 0x20, 0xad, 0x9a, 0xb6, 0xe3, 0x20, 0xf2, 0xdd, 0xd3,
    0x66, 0x19, 0xeb, 0x53, 0xf5, 0x88, 0x35, 0xe1, 0xea, 0xe8,
    0xd4, 0x57, 0xe1, 0x3d, 0xea, 0xd5, 0x00, 0xc2, 0xa4, 0xf5,
    0xff, 0xfb, 0x0b, 0xfb, 0xa2, 0xb9, 0xf1, 0x49, 0x46, 0x9d,
    0x11, 0xa5, 0xb1, 0x94, 0x52, 0x47, 0x6e, 0x2e, 0x79, 0x4b,
    0xc5, 0x18, 0xe9, 0xbc, 0xff, 0xae, 0x34, 0x7f
};

CK_BYTE DH_PUBL_PRIME[128] = {
    0xd5, 0xb1, 0xaa, 0x6a, 0x3b, 0x85, 0x50, 0xf0, 0xe2,
    0xea, 0x6b, 0xec, 0x26, 0x3b, 0xe0, 0xbf, 0x7a, 0x82,
    0x45, 0x1b, 0xa8, 0x0a, 0x54, 0x2e, 0x14, 0x2c, 0xc2,
    0x58, 0xb1, 0xf5, 0x59, 0xec, 0x7d, 0x16, 0x9e, 0x00,
    0x62, 0xb3, 0xa7, 0xdc, 0x38, 0x6f, 0x64, 0x40, 0xfc,
    0x0d, 0x3e, 0x0b, 0x66, 0x13, 0x5e, 0xa5, 0x84, 0x90,
    0x26, 0x62, 0xcf, 0x5a, 0x14, 0x72, 0x2d, 0x1b, 0x37,
    0x7e, 0x8a, 0x4b, 0xc0, 0xb7, 0xf2, 0x63, 0xd1, 0xaa,
    0x51, 0x92, 0x96, 0x18, 0xae, 0xb9, 0xfd, 0x5f, 0x9d,
    0x5d, 0xdf, 0x75, 0xa9, 0x80, 0x3d, 0xaa, 0xc2, 0x54,
    0x00, 0xcc, 0xc1, 0x9e, 0x31, 0x4d, 0x22, 0x31, 0x44,
    0xe9, 0x69, 0x34, 0xae, 0xcf, 0xcd, 0x6d, 0xf6, 0xe9,
    0x37, 0x20, 0xa4, 0xd3, 0x85, 0x24, 0xff, 0x9f, 0x39,
    0xeb, 0x78, 0xf2, 0xd1, 0xc3, 0xf9, 0x66, 0xab, 0xbd,
    0x2d, 0xd3
};


CK_BYTE DH_PUBL_BASE[128] = {
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x02
};

CK_BYTE AES_KEY_VAL[] = {
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
};

CK_BYTE DSA1024_BASE[128] = {
    0xf7, 0xe1, 0xa0, 0x85, 0xd6, 0x9b, 0x3d, 0xde, 0xcb, 0xbc,
    0xab, 0x5c, 0x36, 0xb8, 0x57, 0xb9, 0x79, 0x94, 0xaf, 0xbb,
    0xfa, 0x3a, 0xea, 0x82, 0xf9, 0x57, 0x4c, 0x0b, 0x3d, 0x07,
    0x82, 0x67, 0x51, 0x59, 0x57, 0x8e, 0xba, 0xd4, 0x59, 0x4f,
    0xe6, 0x71, 0x07, 0x10, 0x81, 0x80, 0xb4, 0x49, 0x16, 0x71,
    0x23, 0xe8, 0x4c, 0x28, 0x16, 0x13, 0xb7, 0xcf, 0x09, 0x32,
    0x8c, 0xc8, 0xa6, 0xe1, 0x3c, 0x16, 0x7a, 0x8b, 0x54, 0x7c,
    0x8d, 0x28, 0xe0, 0xa3, 0xae, 0x1e, 0x2b, 0xb3, 0xa6, 0x75,
    0x91, 0x6e, 0xa3, 0x7f, 0x0b, 0xfa, 0x21, 0x35, 0x62, 0xf1,
    0xfb, 0x62, 0x7a, 0x01, 0x24, 0x3b, 0xcc, 0xa4, 0xf1, 0xbe,
    0xa8, 0x51, 0x90, 0x89, 0xa8, 0x83, 0xdf, 0xe1, 0x5a, 0xe5,
    0x9f, 0x06, 0x92, 0x8b, 0x66, 0x5e, 0x80, 0x7b, 0x55, 0x25,
    0x64, 0x01, 0x4c, 0x3b, 0xfe, 0xcf, 0x49, 0x2a
};

CK_BYTE DSA1024_PRIME[128] = {
    0xfd, 0x7f, 0x53, 0x81, 0x1d, 0x75, 0x12, 0x29, 0x52, 0xdf,
    0x4a, 0x9c, 0x2e, 0xec, 0xe4, 0xe7, 0xf6, 0x11, 0xb7, 0x52,
    0x3c, 0xef, 0x44, 0x00, 0xc3, 0x1e, 0x3f, 0x80, 0xb6, 0x51,
    0x26, 0x69, 0x45, 0x5d, 0x40, 0x22, 0x51, 0xfb, 0x59, 0x3d,
    0x8d, 0x58, 0xfa, 0xbf, 0xc5, 0xf5, 0xba, 0x30, 0xf6, 0xcb,
    0x9b, 0x55, 0x6c, 0xd7, 0x81, 0x3b, 0x80, 0x1d, 0x34, 0x6f,
    0xf2, 0x66, 0x60, 0xb7, 0x6b, 0x99, 0x50, 0xa5, 0xa4, 0x9f,
    0x9f, 0xe8, 0x04, 0x7b, 0x10, 0x22, 0xc2, 0x4f, 0xbb, 0xa9,
    0xd7, 0xfe, 0xb7, 0xc6, 0x1b, 0xf8, 0x3b, 0x57, 0xe7, 0xc6,
    0xa8, 0xa6, 0x15, 0x0f, 0x04, 0xfb, 0x83, 0xf6, 0xd3, 0xc5,
    0x1e, 0xc3, 0x02, 0x35, 0x54, 0x13, 0x5a, 0x16, 0x91, 0x32,
    0xf6, 0x75, 0xf3, 0xae, 0x2b, 0x61, 0xd7, 0x2a, 0xef, 0xf2,
    0x22, 0x03, 0x19, 0x9d, 0xd1, 0x48, 0x01, 0xc7
};

CK_BYTE DSA1024_SUBPRIME[20] = {
    0x97, 0x60, 0x50, 0x8f, 0x15, 0x23, 0x0b, 0xcc, 0xb2, 0x92,
    0xb9, 0x82, 0xa2, 0xeb, 0x84, 0x0b, 0xf0, 0x58, 0x1c, 0xf5
};

CK_BYTE DSA1024_PUBLIC[128] = {
    0xa2, 0x8a, 0x43, 0xb9, 0x5d, 0x73, 0x6b, 0x5a, 0x5a, 0xfe,
    0xb5, 0xa0, 0x7d, 0x2c, 0x89, 0x65, 0xeb, 0xf3, 0x52, 0xa3,
    0xe2, 0x9b, 0xa7, 0xe3, 0x65, 0x11, 0x12, 0x0c, 0xcc, 0xa2,
    0xb7, 0x60, 0x51, 0xcd, 0xfb, 0x87, 0xfd, 0x9e, 0xe7, 0x58,
    0xe5, 0xb1, 0x15, 0x98, 0x66, 0x63, 0x18, 0x6f, 0x46, 0x83,
    0x27, 0xbf, 0x5a, 0xc5, 0x00, 0xf1, 0x89, 0xcb, 0x70, 0x6f,
    0x62, 0x16, 0xab, 0xbc, 0x4b, 0xb7, 0x25, 0x8f, 0x92, 0x15,
    0x06, 0x06, 0x5d, 0xb3, 0x36, 0x98, 0x3c, 0x31, 0x26, 0x7c,
    0xe7, 0x8c, 0x94, 0x27, 0xfa, 0xb8, 0xda, 0xd0, 0xc6, 0x4b,
    0x54, 0xf1, 0xef, 0xf6, 0x0e, 0xc6, 0x01, 0xdd, 0x1a, 0xbc,
    0x25, 0xd9, 0x56, 0x93, 0x80, 0x37, 0x94, 0xd9, 0x67, 0x33,
    0xd5, 0x65, 0x69, 0x93, 0x1f, 0x07, 0xc7, 0x72, 0xa5, 0x13,
    0x23, 0x83, 0xac, 0x6e, 0xab, 0xda, 0xfb, 0xc4
};

CK_BYTE DSA1024_PRIVATE[20] = {
    0x87, 0xa0, 0x68, 0x97, 0x5e, 0xf2, 0x51, 0xb4, 0x50, 0x51,
    0x0d, 0xee, 0x08, 0x73, 0x41, 0x19, 0x5c, 0xa6, 0x8c, 0x16
};

/// Helper functions
#define ARRAY_SIZE(A) (sizeof(A) / sizeof((A)[0]))

static void dumpEP11Blob(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                         const char *fmt, ...)
{
    CK_ATTRIBUTE blobattr = { CKA_IBM_OPAQUE, NULL, 0 };
    unsigned char *blob = NULL;
    char fname[1024];
    FILE *f = NULL;
    va_list va;
    int rc;

    va_start(va, fmt);
    vsnprintf(fname, sizeof(fname), fmt, va);
    va_end(va);
    rc = funcs->C_GetAttributeValue(session, key, &blobattr, 1);
    if (rc != CKR_OK)
        return;
    blob = (unsigned char *)malloc(blobattr.ulValueLen);
    if (!blob)
        return;
    blobattr.pValue = blob;
    rc = funcs->C_GetAttributeValue(session, key, &blobattr, 1);
    if (rc != CKR_OK)
        goto out;
    f = fopen(fname, "wb");
    if (!f)
        goto out;
    fwrite(blob, blobattr.ulValueLen, 1, f);
 out:
    free(blob);
    if (f)
        fclose(f);
}

static void dumpSPKI(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE key,
                     const char *fmt, ...)
{
    CK_ATTRIBUTE blobattr = { CKA_PUBLIC_KEY_INFO, NULL, 0 };
    unsigned char *blob = NULL;
    char fname[1024];
    FILE *f = NULL;
    va_list va;
    int rc;

    va_start(va, fmt);
    vsnprintf(fname, sizeof(fname), fmt, va);
    va_end(va);
    rc = funcs->C_GetAttributeValue(session, key, &blobattr, 1);
    if (rc != CKR_OK)
        return;
    blob = (unsigned char *)malloc(blobattr.ulValueLen);
    if (!blob)
        return;
    blobattr.pValue = blob;
    rc = funcs->C_GetAttributeValue(session, key, &blobattr, 1);
    if (rc != CKR_OK)
        goto out;
    f = fopen(fname, "wb");
    if (!f)
        goto out;
    fwrite(blob, blobattr.ulValueLen, 1, f);
 out:
    free(blob);
    if (f)
        fclose(f);
}

CK_RV compareDESKeys(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE source,
                     CK_OBJECT_HANDLE dest)
{
    CK_BYTE data[16] = {0};
    CK_BYTE iv[] = {1,2,3,4,5,6,7,8};
    CK_MECHANISM mech = {CKM_DES3_CBC_PAD, iv, sizeof(iv)};
    CK_BYTE resultsource[24];
    CK_BYTE resultdest[24];
    CK_ULONG reslensource = 24;
    CK_ULONG reslendest = 24;
    CK_RV rc;

    rc = funcs->C_EncryptInit(session, &mech, source);
    if (rc != CKR_OK)
        return rc;
    rc = funcs->C_Encrypt(session, data, sizeof(data), resultsource, &reslensource);
    if (rc != CKR_OK)
        return rc;

    rc = funcs->C_EncryptInit(session, &mech, dest);
    if (rc != CKR_OK)
        return rc;
    rc = funcs->C_Encrypt(session, data, sizeof(data), resultdest, &reslendest);
    if (rc != CKR_OK)
        return rc;

    if (reslensource != reslendest || memcmp(resultsource, resultdest, reslendest))
        return CKR_FUNCTION_FAILED;
    return CKR_OK;
}

CK_RV compareECKeys(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE sign,
                    CK_OBJECT_HANDLE verify)
{
    CK_BYTE data[16] = {0};
    CK_BYTE *signature = NULL;
    CK_MECHANISM signmech = {CKM_ECDSA, 0, 0};
    CK_MECHANISM verifymech = {CKM_ECDSA, 0, 0};
    CK_ULONG signaturelen = 0;
    CK_RV rc;

    rc = funcs->C_SignInit(session, &signmech, sign);
    if (rc != CKR_OK)
        return rc;
    rc = funcs->C_Sign(session, data, sizeof(data), signature, &signaturelen);
    if (rc != CKR_OK)
        return rc;
    signature = calloc(1, signaturelen);
    if (!signature)
        return CKR_HOST_MEMORY;
    rc = funcs->C_Sign(session, data, sizeof(data), signature, &signaturelen);
    if (rc != CKR_OK)
        goto out;

    rc = funcs->C_VerifyInit(session, &verifymech, verify);
    if (rc != CKR_OK)
        goto out;
    rc = funcs->C_Verify(session, data, sizeof(data), signature, signaturelen);
 out:
    free(signature);
    return rc;
}

// expected to fail
CK_RV createABAESKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *handle)
{
    CK_BBOOL true = TRUE;
    CK_BBOOL false = FALSE;
    CK_OBJECT_CLASS keyClass = CKO_SECRET_KEY;
    CK_KEY_TYPE keyType = CKK_AES;
    CK_ATTRIBUTE keyTemplate[] = {
        {CKA_CLASS,         &keyClass,   sizeof(keyClass)},
        {CKA_KEY_TYPE,      &keyType,    sizeof(keyType)},
        {CKA_ENCRYPT,       &true,       sizeof(true)},
        {CKA_TOKEN,         &false,      sizeof(false)},
        {CKA_VALUE,         AES_KEY_VAL, sizeof(AES_KEY_VAL)},
        {CKA_IBM_ATTRBOUND, &true,       sizeof(true)},
        {CKA_SENSITIVE,     &true,       sizeof(true)}
    };

    return funcs->C_CreateObject(session, keyTemplate,
                                 ARRAY_SIZE(keyTemplate), handle);
}

CK_RV createABPublicDSAKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *handle)
{
    CK_OBJECT_CLASS class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;
    CK_UTF8CHAR label[] = "A DSA public key object";
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS,         &class,           sizeof(class)},
        {CKA_KEY_TYPE,      &keyType,         sizeof(keyType)},
        {CKA_TOKEN,         &true,            sizeof(true)},
        {CKA_LABEL,         label,            sizeof(label)},
        {CKA_ENCRYPT,       &true,            sizeof(true)},
        {CKA_VERIFY,        &true,            sizeof(true)},
        {CKA_PRIME,         DSA1024_PRIME,    sizeof(DSA1024_PRIME)},
        {CKA_SUBPRIME,      DSA1024_SUBPRIME, sizeof(DSA1024_SUBPRIME)},
        {CKA_BASE,          DSA1024_BASE,     sizeof(DSA1024_BASE)},
        {CKA_VALUE,         DSA1024_PUBLIC,   sizeof(DSA1024_PUBLIC)},
        {CKA_IBM_ATTRBOUND, &true,            sizeof(true)}
     };

    return funcs->C_CreateObject(session, template,
                                 ARRAY_SIZE(template), handle);
}

// expected to fail
CK_RV createABPrivateDSAKey(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE *handle)
{
    CK_OBJECT_CLASS class = CKO_PRIVATE_KEY;
    CK_KEY_TYPE keyType = CKK_DSA;
    CK_UTF8CHAR label[] = "An DSA private key object";
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };

    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE template[] = {
        {CKA_CLASS,         &class,           sizeof(class)},
        {CKA_KEY_TYPE,      &keyType,         sizeof(keyType)},
        {CKA_TOKEN,         &true,            sizeof(true)},
        {CKA_LABEL,         label,            sizeof(label)},
        {CKA_SUBJECT,       subject,          0},
        {CKA_ID,            id,               sizeof(id)},
        {CKA_SENSITIVE,     &true,            sizeof(true)},
        {CKA_DECRYPT,       &true,            sizeof(true)},
        {CKA_SIGN,          &true,            sizeof(true)},
        {CKA_PRIME,         DSA1024_PRIME,    sizeof(DSA1024_PRIME)},
        {CKA_SUBPRIME,      DSA1024_SUBPRIME, sizeof(DSA1024_SUBPRIME)},
        {CKA_BASE,          DSA1024_BASE,     sizeof(DSA1024_BASE)},
        {CKA_VALUE,         DSA1024_PRIVATE,  sizeof(DSA1024_PRIVATE)},
        {CKA_IBM_ATTRBOUND, &true,            sizeof(true)},
        {CKA_SENSITIVE,     &true,            sizeof(true)}
    };

    return funcs->C_CreateObject(session, template,
                                 ARRAY_SIZE(template), handle);
}

CK_RV generateABAESKey(CK_SESSION_HANDLE session, CK_ULONG key_len,
                       CK_OBJECT_HANDLE *handle)
{
    CK_BBOOL cktrue = TRUE;
    CK_ATTRIBUTE key_gen_tmpl[] = {
        {CKA_VALUE_LEN,     &key_len, sizeof(CK_ULONG)},
        {CKA_IBM_ATTRBOUND, &cktrue,  sizeof(CK_BBOOL)},
        {CKA_SENSITIVE,     &cktrue,  sizeof(CK_BBOOL)}
    };
    CK_MECHANISM mech = {
        .mechanism = CKM_AES_KEY_GEN,
        .ulParameterLen = 0,
        .pParameter = NULL,
    };

    return funcs->C_GenerateKey(session, &mech, key_gen_tmpl,
                                ARRAY_SIZE(key_gen_tmpl), handle);
}

CK_RV generateABDESKey(CK_SESSION_HANDLE session, CK_MECHANISM_TYPE type,
                       CK_OBJECT_HANDLE *handle)
{
    CK_MECHANISM mech = { type, NULL, 0 };
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_IBM_ATTRBOUND, &true, sizeof(true)},
        {CKA_SENSITIVE,     &true, sizeof(true)}
    };

    return funcs->C_GenerateKey(session, &mech, tmpl, ARRAY_SIZE(tmpl), handle);
}

CK_RV generateABGenericSecret(CK_SESSION_HANDLE session,
                              CK_OBJECT_HANDLE *handle)
{
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_BBOOL true = TRUE;
    CK_ULONG keylen = 20;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_CLASS,         &class,  sizeof(class)},
        {CKA_VALUE_LEN,     &keylen, sizeof(keylen)},
        {CKA_IBM_ATTRBOUND, &true,   sizeof(true)},
        {CKA_SENSITIVE,     &true,   sizeof(true)}
    };
    CK_MECHANISM mech = { CKM_GENERIC_SECRET_KEY_GEN, NULL, 0 };

    return funcs->C_GenerateKey(session, &mech, tmpl, ARRAY_SIZE(tmpl), handle);
}

CK_RV generateABRSAKey(CK_SESSION_HANDLE session,
                       CK_BBOOL abpub, CK_BBOOL abpriv, CK_BBOOL sensitive,
                       CK_OBJECT_HANDLE *pubkey, CK_OBJECT_HANDLE *privkey)
{
    CK_MECHANISM mech = { CKM_RSA_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = {123};
    CK_BBOOL cktrue = TRUE;
    CK_ULONG modulusBits = 4096;
    CK_BYTE publicExponent[] = {0x01, 0x00, 0x01};
    CK_ATTRIBUTE pubkeyTemplate[] = {
        {CKA_ENCRYPT,         &cktrue,        sizeof(cktrue)},
        {CKA_VERIFY,          &cktrue,        sizeof(cktrue)},
        {CKA_WRAP,            &cktrue,        sizeof(cktrue)},
        {CKA_MODULUS_BITS,    &modulusBits,   sizeof(modulusBits)},
        {CKA_PUBLIC_EXPONENT, publicExponent, sizeof(publicExponent)},
        {CKA_IBM_ATTRBOUND,   &abpub,         sizeof(abpub)}
    };
    CK_ATTRIBUTE privkeyTemplate[] = {
        {CKA_TOKEN,           &cktrue,        sizeof(cktrue)},
        {CKA_PRIVATE,         &cktrue,        sizeof(cktrue)},
        {CKA_SUBJECT,         subject,        0},
        {CKA_ID,              id,             sizeof(id)},
        {CKA_DECRYPT,         &cktrue,        sizeof(cktrue)},
        {CKA_SIGN,            &cktrue,        sizeof(cktrue)},
        {CKA_UNWRAP,          &cktrue,        sizeof(cktrue)},
        {CKA_IBM_ATTRBOUND,   &abpriv,        sizeof(abpriv)},
        {CKA_SENSITIVE,       &sensitive,     sizeof(sensitive)}
    };

    return funcs->C_GenerateKeyPair(session, &mech,
                                    pubkeyTemplate, ARRAY_SIZE(pubkeyTemplate),
                                    privkeyTemplate, ARRAY_SIZE(privkeyTemplate),
                                    pubkey, privkey);
}

CK_RV generateABECKey(CK_SESSION_HANDLE session, CK_BBOOL ab,
                      CK_OBJECT_HANDLE *pubkey, CK_OBJECT_HANDLE *privkey)
{
    CK_BYTE prime256v1[] = OCK_PRIME256V1;
    CK_MECHANISM mech = { CKM_EC_KEY_PAIR_GEN, NULL, 0 };
    CK_BYTE subject[] = {0};
    CK_BYTE id[] = { 123 };
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE publicKeyTemplate[] = {
        {CKA_VERIFY,        &true,       sizeof(true)},
        {CKA_EC_PARAMS,     &prime256v1, sizeof(prime256v1)},
        {CKA_IBM_ATTRBOUND, &ab,         sizeof(true)}
    };
    CK_ATTRIBUTE privateKeyTemplate[] = {
        {CKA_TOKEN,         &true,   sizeof(true)},
        {CKA_PRIVATE,       &true,   sizeof(true)},
        {CKA_SUBJECT,       subject, 0},
        {CKA_ID,            id,      sizeof(id)},
        {CKA_SENSITIVE,     &true,   sizeof(true)},
        {CKA_SIGN,          &true,   sizeof(true)},
        {CKA_DERIVE,        &true,   sizeof(true)},
        {CKA_IBM_ATTRBOUND, &ab,     sizeof(true)},
        {CKA_SENSITIVE,     &true,   sizeof(true)}
    };

    return funcs->C_GenerateKeyPair(session, &mech,
                                    publicKeyTemplate, ARRAY_SIZE(publicKeyTemplate),
                                    privateKeyTemplate, ARRAY_SIZE(privateKeyTemplate),
                                    pubkey, privkey);
}

CK_RV generateABDSAKey(CK_SESSION_HANDLE session,
                       CK_OBJECT_HANDLE *pubkey, CK_OBJECT_HANDLE *privkey)
{
    CK_MECHANISM mech = { CKM_DSA_KEY_PAIR_GEN, NULL, 0 };
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE publ_tmpl[] = {
        {CKA_PRIME,         DSA_PUBL_PRIME,    sizeof(DSA_PUBL_PRIME)},
        {CKA_SUBPRIME,      DSA_PUBL_SUBPRIME, sizeof(DSA_PUBL_SUBPRIME)},
        {CKA_BASE,          DSA_PUBL_BASE,     sizeof(DSA_PUBL_BASE)},
        {CKA_IBM_ATTRBOUND, &true,             sizeof(true)}
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        {CKA_IBM_ATTRBOUND, &true, sizeof(true)},
        {CKA_SENSITIVE,     &true, sizeof(true)}
    };

    return funcs->C_GenerateKeyPair(session, &mech,
                                    publ_tmpl, ARRAY_SIZE(publ_tmpl),
                                    priv_tmpl, ARRAY_SIZE(priv_tmpl),
                                    pubkey, privkey);
}

CK_RV generateABDHKey(CK_SESSION_HANDLE session,
                      CK_OBJECT_HANDLE *pubkey, CK_OBJECT_HANDLE *privkey)
{
    CK_MECHANISM mech = { CKM_DH_PKCS_KEY_PAIR_GEN, NULL, 0 };
    CK_BBOOL true = TRUE;
    CK_OBJECT_CLASS pub_key_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE key_type = CKK_DH;
    CK_UTF8CHAR publ_label[] = "An AB DH public key object";
    CK_OBJECT_CLASS priv_key_class = CKO_PRIVATE_KEY;
    CK_UTF8CHAR priv_label[] = "An AB DH private key object";
    CK_ATTRIBUTE publ_tmpl[] = {
        {CKA_CLASS,         &pub_key_class, sizeof(pub_key_class)},
        {CKA_KEY_TYPE,      &key_type,      sizeof(key_type)},
        {CKA_LABEL,         publ_label,     sizeof(publ_label) - 1},
        {CKA_PRIME,         DH_PUBL_PRIME,  sizeof(DH_PUBL_PRIME)},
        {CKA_BASE,          DH_PUBL_BASE,   sizeof(DH_PUBL_BASE)},
        {CKA_IBM_ATTRBOUND, &true,          sizeof(true)}
    };
    CK_ATTRIBUTE priv_tmpl[] = {
        {CKA_CLASS,         &priv_key_class, sizeof(priv_key_class)},
        {CKA_KEY_TYPE,      &key_type,       sizeof(key_type)},
        {CKA_LABEL,         priv_label,      sizeof(priv_label) - 1},
        {CKA_DERIVE,        &true,           sizeof(true)},
        {CKA_IBM_ATTRBOUND, &true,           sizeof(true)},
        {CKA_SENSITIVE,     &true,           sizeof(true)}
    };

    return funcs->C_GenerateKeyPair(session, &mech,
                                    publ_tmpl, ARRAY_SIZE(publ_tmpl),
                                    priv_tmpl, ARRAY_SIZE(priv_tmpl),
                                    pubkey, privkey);
}

// Expected to fail
CK_RV generateABDilithiumKey(CK_SESSION_HANDLE session,
                             CK_OBJECT_HANDLE *pubkey, CK_OBJECT_HANDLE *privkey)
{
    CK_MECHANISM mech = { CKM_IBM_DILITHIUM, NULL, 0 };
    CK_BBOOL cktrue = TRUE;
    CK_ATTRIBUTE pubkeyTemplate[] = {
        {CKA_VERIFY,        &cktrue, sizeof(cktrue)},
        {CKA_IBM_ATTRBOUND, &cktrue, sizeof(cktrue)}
    };
    CK_ATTRIBUTE privkeyTemplate[] = {
        {CKA_SIGN,          &cktrue, sizeof(cktrue)},
        {CKA_IBM_ATTRBOUND, &cktrue, sizeof(cktrue)},
        {CKA_SENSITIVE,     &cktrue, sizeof(cktrue)}
    };

    return funcs->C_GenerateKeyPair(session, &mech,
                                    pubkeyTemplate, ARRAY_SIZE(pubkeyTemplate),
                                    privkeyTemplate, ARRAY_SIZE(privkeyTemplate),
                                    pubkey, privkey);
}

void teardown(CK_SESSION_HANDLE session) {
    int i;

    for (i = 0; i < NUMKEYS; ++i)
        funcs->C_DestroyObject(session, keys.u.keys[i]);
}

/// Test functions

CK_RV do_CheckMechanismInfo(void)
{
    CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS params = {
        .hSignVerifyKey = CK_INVALID_HANDLE
    };
    CK_MECHANISM mech = {
        .mechanism = CKM_IBM_ATTRIBUTEBOUND_WRAP,
        .pParameter = &params,
        .ulParameterLen = sizeof(params)
    };
    CK_RV res = CKR_OK;

    // begin testsuite
    testsuite_begin("Check CKM_IBM_ATTRIBUTEBOUND_WRAP mechanism info.");

    // skip tests if the slot doesn't support this mechanism
    if (!mech_supported(SLOT_ID, CKM_IBM_ATTRIBUTEBOUND_WRAP)) {
        testsuite_skip(2,
                      "Slot %u doesn't support CKM_IBM_ATTRIBUTEBOUND_WRAP (0x%x)",
                      (unsigned int) SLOT_ID,
                      (unsigned int) CKM_IBM_ATTRIBUTEBOUND_WRAP);
        res = CKR_FUNCTION_NOT_SUPPORTED;
        goto testcase_cleanup;
    }
    testcase_new_assertion();
    testcase_begin("CKM_IBM_ATTRIBUTEBOUND_WRAP supported for wrapping");
    if (!wrap_supported(SLOT_ID, mech))
        testcase_fail("CKM_IBM_ATTRIBUTEBOUND_WRAP does NOT support wrapping");
    else
        testcase_pass("CKM_IBM_ATTRIBUTEBOUND_WRAP does support wrapping");
    testcase_new_assertion();
    testcase_begin("CKM_IBM_ATTRIBUTEBOUND_WRAP supported for unwrapping");
    if (!unwrap_supported(SLOT_ID, mech))
        testcase_fail("CKM_IBM_ATTRIBUTEBOUND_WRAP does NOT support unwrapping");
    else
        testcase_pass("CKM_IBM_ATTRIBUTEBOUND_WRAP does support unwrapping");    
 testcase_cleanup:
    return res;
}

void do_TestInvalidKeys(CK_SESSION_HANDLE session)
{
    CK_OBJECT_HANDLE pubkey = CK_INVALID_HANDLE, privkey = CK_INVALID_HANDLE;
    CK_RV rc;

    // Expected to fail with CKR_TEMPLATE_INCONSISTENT
    testcase_begin("Create RSA AB key without CKA_SENSITIVE");
    testcase_new_assertion();
    rc = generateABRSAKey(session, TRUE, TRUE, FALSE, &pubkey, &privkey);
    if (rc != CKR_TEMPLATE_INCONSISTENT)
        testcase_fail("Create RSA AB key without CKA_SENSITIVE did not return CKR_TEMPLATE_INCONSISTENT but %s", p11_get_ckr(rc));
    else
        testcase_pass("Create RSA AB key without CKA_SENSITIVE returned CKR_TEMPLATE_INCONSISTENT as expected");

    if (pubkey != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, pubkey);
    if (privkey != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, privkey);

    testcase_begin("Create RSA AB key with non-AB private key");
    testcase_new_assertion();
    rc = generateABRSAKey(session, FALSE, TRUE, TRUE, &pubkey, &privkey);
    if (rc != CKR_TEMPLATE_INCONSISTENT)
        testcase_fail("Create RSA AB key with non-AB private key did not return CKR_TEMPLATE_INCONSISTENT but %s", p11_get_ckr(rc));
    else
        testcase_pass("Create RSA AB key with non-AB private key returned CKR_TEMPLATE_INCONSISTENT as expected");

    if (pubkey != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, pubkey);
    if (privkey != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, privkey);

    testcase_begin("Create RSA AB key with non-AB public key");
    testcase_new_assertion();
    rc = generateABRSAKey(session, TRUE, FALSE, TRUE, &pubkey, &privkey);
    if (rc != CKR_TEMPLATE_INCONSISTENT)
        testcase_fail("Create RSA AB key with non-AB public key did not return CKR_TEMPLATE_INCONSISTENT but %s", p11_get_ckr(rc));
    else
        testcase_pass("Create RSA AB key with non-AB public key returned CKR_TEMPLATE_INCONSISTENT as expected");

    if (pubkey != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, pubkey);
    if (privkey != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, privkey);
}

void do_CreateKeyObjects(CK_SESSION_HANDLE session)
{
    CK_RV rc;
    CK_OBJECT_HANDLE handle = CK_INVALID_HANDLE;

    testcase_begin("Create AB AES key via C_CreateObject");
    testcase_new_assertion();
    rc = createABAESKey(session, &handle);
    if (is_rejected_by_policy(rc, session))
        testcase_skip("Key import is not allowed by policy");
    else if (rc != CKR_ATTRIBUTE_VALUE_INVALID)
        testcase_fail("C_CreateObject for AB AES key returned %s (expected CKR_ATTRIBUTE_VALUE_INVALID)", p11_get_ckr(rc));
    else
        testcase_pass("C_CreateObject for AB AES key returned CKR_ATTRIBUTE_VALUE_INVALID as expected");
    if (handle != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, handle);

    testcase_begin("Create AB DSA private key via C_CreateObject");
    testcase_new_assertion();
    rc = createABPrivateDSAKey(session, &handle);
    if (is_rejected_by_policy(rc, session))
        testcase_skip("Key import is not allowed by policy");
    else if (rc != CKR_ATTRIBUTE_VALUE_INVALID)
        testcase_fail("C_CreateObject for AB DSA private key returned %s (expected CKR_ATTRIBUTE_VALUE_INVALID)", p11_get_ckr(rc));
    else
        testcase_pass("C_CreateObject for AB DSA private key returned CKR_ATTRIBUTE_VALUE_INVALID as expected");
    if (handle != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, handle);

    testcase_begin("Create AB DSA public key via C_CreateObject");
    testcase_new_assertion();
    rc = createABPublicDSAKey(session, &handle);
    if (is_rejected_by_policy(rc, session))
        testcase_skip("Key import is not allowed by policy");
    else if (rc != CKR_OK)
        testcase_fail("C_CreateObject for AB DSA public key returned %s (expected CKR_OK)", p11_get_ckr(rc));
    else
        testcase_pass("C_CreateObject for AB DSA public key returned CKR_OK as expected");
    if (handle != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, handle);
}

CK_RV do_SetupKeys(CK_SESSION_HANDLE session)
{
    CK_RV rc;
    int i;

    for (i = 0; i < NUMKEYS; ++i)
        keys.u.keys[i] = CK_INVALID_HANDLE;
    
    testcase_begin("Create AB AES key");
    testcase_new_assertion();
    rc = generateABAESKey(session, 32, &keys.u.d.aes);
    if (is_rejected_by_policy(rc, session))
        testcase_skip("Key generation is not allowed by policy");
    else if (rc != CKR_OK)
        testcase_fail("Create AB AES key failed with rc=%s", p11_get_ckr(rc));
    else
        testcase_pass("Successfully created AB AES key");
    testcase_begin("Create AB DES2 key");
    testcase_new_assertion();
    rc = generateABDESKey(session, CKM_DES2_KEY_GEN, &keys.u.d.des2);
    if (is_rejected_by_policy(rc, session))
        testcase_skip("Key generation is not allowed by policy");
    else if (rc != CKR_OK)
        testcase_fail("Create AB DES2 key failed with rc=%s", p11_get_ckr(rc));
    else
        testcase_pass("Successfully created AB DES2 key");
    testcase_begin("Create AB DES3 key");
    testcase_new_assertion();
    rc = generateABDESKey(session, CKM_DES3_KEY_GEN, &keys.u.d.des3);
    if (is_rejected_by_policy(rc, session))
        testcase_skip("Key generation is not allowed by policy");
    else if (rc != CKR_OK)
        testcase_fail("Create AB DES3 key failed with rc=%s", p11_get_ckr(rc));
    else
        testcase_pass("Successfully created AB DES3 key");
    testcase_begin("Create AB generic secret key");
    testcase_new_assertion();
    if (!mech_supported(SLOT_ID, CKM_GENERIC_SECRET_KEY_GEN)) {
        testcase_skip("CKM_GENERIC_SECRET_KEY_GEN not supported");
    } else {
        rc = generateABGenericSecret(session, &keys.u.d.generic);
        if (is_rejected_by_policy(rc, session))
            testcase_skip("Key generation is not allowed by policy");
        else if (rc != CKR_OK)
            testcase_fail("Create AB generic secret key failed with rc=%s", p11_get_ckr(rc));
        else
            testcase_pass("Successfully created AB generic secret key");
    }
    testcase_begin("Create AB RSA key");
    testcase_new_assertion();
    rc = generateABRSAKey(session, TRUE, TRUE, TRUE, &keys.u.d.rsapub, &keys.u.d.rsapriv);
    if (is_rejected_by_policy(rc, session))
        testcase_skip("Key generation is not allowed by policy");
    else if (rc != CKR_OK)
        testcase_fail("Create AB RSA key failed with rc=%s", p11_get_ckr(rc));
    else
        testcase_pass("Successfully created AB RSA key");
    testcase_begin("Create AB EC key");
    testcase_new_assertion();
    rc = generateABECKey(session, TRUE, &keys.u.d.ecpub, &keys.u.d.ecpriv);
    if (is_rejected_by_policy(rc, session))
        testcase_skip("Key generation is not allowed by policy");
    else if (rc != CKR_OK)
        testcase_fail("Create AB EC key failed with rc=%s", p11_get_ckr(rc));
    else
        testcase_pass("Successfully created AB EC key");
    testcase_begin("Create AB DSA key");
    testcase_new_assertion();
    rc = generateABDSAKey(session, &keys.u.d.dsapub, &keys.u.d.dsapriv);
    if (is_rejected_by_policy(rc, session))
        testcase_skip("Key generation is not allowed by policy");
    else if (rc != CKR_OK)
        testcase_fail("Create AB DSA key failed with rc=%s", p11_get_ckr(rc));
    else
        testcase_pass("Successfully created AB DSA key");
    testcase_begin("Create AB DH key");
    testcase_new_assertion();
    rc = generateABDHKey(session, &keys.u.d.dhpub, &keys.u.d.dhpriv);
    if (is_rejected_by_policy(rc, session))
        testcase_skip("Key generation is not allowed by policy");
    else if (rc != CKR_OK)
        testcase_fail("Create AB DH key failed with rc=%s", p11_get_ckr(rc));
    else
        testcase_pass("Successfully created AB DH key");
    // These are not a test in this suite since it is covered by other suites...
    rc = generateABRSAKey(session, FALSE, FALSE, FALSE, &keys.u.d.nonabpub, &keys.u.d.nonabpriv);
    if (is_rejected_by_policy(rc, session)) {
        testcase_skip("Key generation is not allowed by policy");
        rc = CKR_POLICY_VIOLATION;
    }
    if (rc != CKR_OK)
        return rc;
    rc = generateABECKey(session, FALSE, &keys.u.d.nonabecpub, &keys.u.d.nonabecpriv);
    if (is_rejected_by_policy(rc, session)) {
        testcase_skip("Key generation is not allowed by policy");
        rc = CKR_POLICY_VIOLATION;
    }

    for (i = 0; i < NUMKEYS; ++i) {
        if (keys.u.keys[i] == CK_INVALID_HANDLE)
            rc = CKR_POLICY_VIOLATION;
    }

    return rc;
}

void do_TestKeyWrappingUnwrapping(CK_SESSION_HANDLE session)
{
    CK_BYTE wrappedkey[16384];
    CK_ULONG wrappedkeylen;
    CK_RV rc;
    unsigned i;
    static CK_KEY_TYPE deskt = CKK_DES3, eckt = CKK_EC;
    static CK_OBJECT_CLASS secretoc = CKO_SECRET_KEY, privateoc = CKO_PRIVATE_KEY;
    static CK_BBOOL cktrue = TRUE;
    static CK_ATTRIBUTE desunwrapattrs[] = {
        {CKA_CLASS,         &secretoc, sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE,      &deskt,    sizeof(CK_KEY_TYPE)},
        {CKA_IBM_ATTRBOUND, &cktrue,   sizeof(CK_BBOOL)}
    };
    static CK_ATTRIBUTE ecprivunwrapattrs[] = {
        {CKA_CLASS,         &privateoc, sizeof(CK_OBJECT_CLASS)},
        {CKA_KEY_TYPE,      &eckt,      sizeof(CK_KEY_TYPE)},
        {CKA_IBM_ATTRBOUND, &cktrue,    sizeof(CK_BBOOL)}
    };
    static const struct {
        CK_OBJECT_HANDLE *keytowrap;
        CK_OBJECT_HANDLE *wrappingkey;
        CK_OBJECT_HANDLE *signingkey;
        CK_OBJECT_HANDLE *unwrappingkey;
        CK_OBJECT_HANDLE *verificationkey;
        CK_RV             wrapres;
        CK_RV             unwrapres;// ignored if wrapres != CKR_OK
        // ignored if wrapres != CKR_OK or unwrapres != CKR_OK
        CK_RV             (*compare)(CK_SESSION_HANDLE session,
                                     CK_OBJECT_HANDLE source,
                                     CK_OBJECT_HANDLE dest);
        CK_OBJECT_HANDLE *comparedest;
        CK_ATTRIBUTE     *unwraptemplate;
        CK_ULONG          unwraptemplatesize;
    } config[] = {
        // symm, symm, symm
        /*0*/{&keys.u.d.des3,    &keys.u.d.aes,    &keys.u.d.aes,    &keys.u.d.aes,    &keys.u.d.aes,    CKR_OK, CKR_OK, compareDESKeys, &keys.u.d.des3, desunwrapattrs, ARRAY_SIZE(desunwrapattrs)},
        // symm, symm, asymm
        /*1*/{&keys.u.d.des3,    &keys.u.d.aes,    &keys.u.d.ecpriv, &keys.u.d.aes,    &keys.u.d.ecpub,  CKR_OK, CKR_OK, compareDESKeys, &keys.u.d.des3, desunwrapattrs, ARRAY_SIZE(desunwrapattrs)},
        // symm, asymm, symm
        /*2*/{&keys.u.d.des3,    &keys.u.d.rsapub, &keys.u.d.ecpriv, &keys.u.d.rsapriv, &keys.u.d.ecpub, CKR_OK, CKR_OK, compareDESKeys, &keys.u.d.des3, desunwrapattrs, ARRAY_SIZE(desunwrapattrs)},
        // symm, asymm, asymm
        /*3*/{&keys.u.d.des3,    &keys.u.d.rsapub, &keys.u.d.ecpriv, &keys.u.d.rsapriv, &keys.u.d.ecpub, CKR_OK, CKR_OK, compareDESKeys, &keys.u.d.des3, desunwrapattrs, ARRAY_SIZE(desunwrapattrs)},
        // asymm, symm, symm
        /*4*/{&keys.u.d.ecpriv,  &keys.u.d.aes,    &keys.u.d.aes,    &keys.u.d.aes,     &keys.u.d.aes,   CKR_OK, CKR_OK, compareECKeys, &keys.u.d.ecpub, ecprivunwrapattrs, ARRAY_SIZE(ecprivunwrapattrs)},
        // asymm, symm, asymm
        /*5*/{&keys.u.d.ecpriv,  &keys.u.d.aes,    &keys.u.d.ecpriv, &keys.u.d.aes,     &keys.u.d.ecpub, CKR_OK, CKR_OK, compareECKeys, &keys.u.d.ecpub, ecprivunwrapattrs, ARRAY_SIZE(ecprivunwrapattrs)},
        // asymm, asymm, symm
        /*6*/{&keys.u.d.ecpriv,  &keys.u.d.rsapub, &keys.u.d.ecpriv, &keys.u.d.rsapriv, &keys.u.d.ecpub, CKR_OK, CKR_OK, compareECKeys, &keys.u.d.ecpub, ecprivunwrapattrs, ARRAY_SIZE(ecprivunwrapattrs)},
        // asymm, asymm, asymm
        /*7*/{&keys.u.d.ecpriv,  &keys.u.d.rsapub, &keys.u.d.ecpriv, &keys.u.d.rsapriv, &keys.u.d.ecpub, CKR_OK, CKR_OK, compareECKeys, &keys.u.d.ecpub, ecprivunwrapattrs, ARRAY_SIZE(ecprivunwrapattrs)},
        // kek unsupported
        /*8*/{&keys.u.d.des3, &keys.u.d.ecpub,  &keys.u.d.aes, &keys.u.d.ecpriv,  &keys.u.d.aes, CKR_WRAPPING_KEY_TYPE_INCONSISTENT, CKR_OK, 0, 0, 0, 0},
        /*9*/{&keys.u.d.des3, &keys.u.d.rsapub, &keys.u.d.aes, &keys.u.d.dsapriv, &keys.u.d.aes, CKR_OK, CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT, 0, 0, desunwrapattrs, ARRAY_SIZE(desunwrapattrs)},
        // kek not ab
        /*10*/{&keys.u.d.des3, &keys.u.d.nonabpub, &keys.u.d.aes, &keys.u.d.nonabpriv, &keys.u.d.aes, CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_OK, 0, 0, 0, 0},
        /*11*/{&keys.u.d.des3, &keys.u.d.rsapub,   &keys.u.d.aes, &keys.u.d.nonabpriv, &keys.u.d.aes, CKR_OK, CKR_KEY_FUNCTION_NOT_PERMITTED, 0, 0, desunwrapattrs, ARRAY_SIZE(desunwrapattrs)},
        // sign/verify key not ab
        /*12*/{&keys.u.d.des3, &keys.u.d.rsapub, &keys.u.d.nonabpriv, &keys.u.d.rsapriv, &keys.u.d.aes,      CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_OK, 0, 0, 0, 0},
        /*13*/{&keys.u.d.des3, &keys.u.d.rsapub, &keys.u.d.aes,       &keys.u.d.rsapriv, &keys.u.d.nonabpub, CKR_OK, CKR_KEY_FUNCTION_NOT_PERMITTED, 0, 0, desunwrapattrs, ARRAY_SIZE(desunwrapattrs)},
        // signing key not able to sign
        /*14*/{&keys.u.d.des3, &keys.u.d.rsapub, &keys.u.d.ecpub,  &keys.u.d.rsapriv, &keys.u.d.ecpub,  CKR_KEY_FUNCTION_NOT_PERMITTED, CKR_OK, 0, 0, 0, 0},
        /*15*/{&keys.u.d.des3, &keys.u.d.rsapub, &keys.u.d.ecpriv, &keys.u.d.rsapriv, &keys.u.d.ecpriv, CKR_OK, CKR_KEY_FUNCTION_NOT_PERMITTED, 0, 0, desunwrapattrs, ARRAY_SIZE(desunwrapattrs)},
        // target non-ab
        /*16*/{&keys.u.d.nonabpriv, &keys.u.d.rsapub, &keys.u.d.aes, &keys.u.d.rsapriv, &keys.u.d.aes, CKR_KEY_NOT_WRAPPABLE, CKR_OK, 0, 0, 0, 0},
        // Wrong key type in unwrap template
        /*17*/{&keys.u.d.des3, &keys.u.d.aes, &keys.u.d.aes, &keys.u.d.aes, &keys.u.d.aes, CKR_OK, CKR_TEMPLATE_INCONSISTENT, 0, 0, ecprivunwrapattrs, ARRAY_SIZE(ecprivunwrapattrs)}
    };

    for (i = 0; i < ARRAY_SIZE(config); ++i) {
        CK_OBJECT_HANDLE unwrapped;
        CK_IBM_ATTRIBUTEBOUND_WRAP_PARAMS params;
        CK_MECHANISM mech = {CKM_IBM_ATTRIBUTEBOUND_WRAP, &params, sizeof(params)};
        params.hSignVerifyKey = *(config[i].signingkey);
        testcase_begin("AB Wrap/Unwrap test %u", i);
        testcase_new_assertion();
        wrappedkeylen = sizeof(wrappedkey);
        rc = funcs->C_WrapKey(session, &mech, *(config[i].wrappingkey),
                              *(config[i].keytowrap), wrappedkey, &wrappedkeylen);
        if (rc != config[i].wrapres) {
            testcase_fail("Wrap/Unwrap test %u: wrapping: expected %s, got %s",
                          i, p11_get_ckr(config[i].wrapres), p11_get_ckr(rc));
            // Skip rest of the test
            continue;
        } else if (rc != CKR_OK) {
            testcase_pass("Wrap/Unwrap test %u: wrapping failed as expected", i);
            // Wrapping failed as expected.  So skip unwrapping.
            continue;
        }
        params.hSignVerifyKey = *(config[i].verificationkey);
        rc = funcs->C_UnwrapKey(session, &mech, *(config[i].unwrappingkey),
                                wrappedkey, wrappedkeylen, config[i].unwraptemplate,
                                config[i].unwraptemplatesize, &unwrapped);
        if (rc != config[i].unwrapres) {
            testcase_fail("Wrap/Unwrap test %u: unwrapping: expected %s, got %s",
                          i, p11_get_ckr(config[i].unwrapres), p11_get_ckr(rc));
            // Skip rest of the test
            continue;
        } else if (rc != CKR_OK) {
            testcase_pass("Wrap/Unwrap test %u: unwrapping failed as expected", i);
            continue;
        }
        rc = config[i].compare(session, unwrapped, *(config[i].comparedest));
        if (rc != CKR_OK) {
            dumpEP11Blob(session, *(config[i].wrappingkey), "dump-wrappingkey-%u", i);
            dumpEP11Blob(session, *(config[i].keytowrap), "dump-keytowrap-%u", i);
            dumpEP11Blob(session, *(config[i].signingkey), "dump-signingkey-%u", i);
            dumpEP11Blob(session, unwrapped, "dump-unwrapped-%u", i);
            dumpSPKI(session, *(config[i].keytowrap), "dump-keytowrap-spki-%u", i);
            dumpSPKI(session, unwrapped, "dump-unwrapped-spki-%u", i);
            testcase_fail("Wrap/Unwrap test %u: compare returned %s", i, p11_get_ckr(rc));
        } else {
            testcase_pass("Wrap/Unwrap test %u: cycle passed", i);
        }
        funcs->C_DestroyObject(session, unwrapped);
    }
}

void do_TestAttributeChange(CK_SESSION_HANDLE session)
{
    CK_BBOOL cktrue = TRUE, ckfalse=FALSE;
    CK_ATTRIBUTE attr = {
        .type = CKA_IBM_ATTRBOUND,
        .ulValueLen = sizeof(CK_BBOOL)
    };
    CK_RV rc;
    CK_OBJECT_HANDLE copyres = CK_INVALID_HANDLE;

    testcase_begin("Set CKA_IBM_ATTRBOUND to TRUE via C_SetAttributeValue");
    testcase_new_assertion();
    attr.pValue = &cktrue;
    rc = funcs->C_SetAttributeValue(session, keys.u.d.nonabpub, &attr, 1);
    if (rc != CKR_ATTRIBUTE_READ_ONLY)
        testcase_fail("Changed CKA_IBM_ATTRBOUND via C_SetAttributeValue to TRUE");
    else
        testcase_pass("Could not change CKA_IBM_ATTRBOUND via C_SetAttributeValue to TRUE");

    testcase_begin("Set CKA_IBM_ATTRBOUND to TRUE via C_CopyObject");
    testcase_new_assertion();
    attr.pValue = &cktrue;
    rc = funcs->C_CopyObject(session, keys.u.d.nonabpub, &attr, 1, &copyres);
    if (rc != CKR_ATTRIBUTE_READ_ONLY)
        testcase_fail("Changed CKA_IBM_ATTRBOUND via C_CopyObject to TRUE");
    else
        testcase_pass("Could not change CKA_IBM_ATTRBOUND via C_CopyObject to TRUE");
    if (copyres != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, copyres);
    copyres = CK_INVALID_HANDLE;

    testcase_begin("Set CKA_IBM_ATTRBOUND to FALSE via C_SetAttributeValue");
    testcase_new_assertion();
    attr.pValue = &ckfalse;
    rc = funcs->C_SetAttributeValue(session, keys.u.d.des2, &attr, 1);
    if (rc != CKR_ATTRIBUTE_READ_ONLY)
        testcase_fail("Changed CKA_IBM_ATTRBOUND via C_SetAttributeValue to FALSE");
    else
        testcase_pass("Could not change CKA_IBM_ATTRBOUND via C_SetAttributeValue to FALSE");

    testcase_begin("Set CKA_IBM_ATTRBOUND to FALSE via C_CopyObject");
    testcase_new_assertion();
    attr.pValue = &ckfalse;
    rc = funcs->C_CopyObject(session, keys.u.d.des2, &attr, 1, &copyres);
    if (rc != CKR_ATTRIBUTE_READ_ONLY)
        testcase_fail("Changed CKA_IBM_ATTRBOUND via C_CopyObject to FALSE");
    else
        testcase_pass("Could not change CKA_IBM_ATTRBOUND via C_CopyObject to FALSE");
    if (copyres != CK_INVALID_HANDLE)
        funcs->C_DestroyObject(session, copyres);
}

void do_TestDerive(CK_SESSION_HANDLE session)
{
    CK_RV rc;
    unsigned i;
    CK_BBOOL val, checkval, true = TRUE;
    CK_OBJECT_CLASS class = CKO_SECRET_KEY;
    CK_KEY_TYPE key_type = CKK_GENERIC_SECRET;
    CK_ULONG valuelen = 10;
    // Cannot be static because of @val
    CK_ATTRIBUTE derive_tmpl[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_VALUE_LEN, &valuelen, sizeof(CK_ULONG)},
        {CKA_IBM_ATTRBOUND, &val, sizeof(CK_BBOOL)}
    };
    CK_ATTRIBUTE derive_tmpl_noab[] = {
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_KEY_TYPE, &key_type, sizeof(key_type)},
        {CKA_SENSITIVE, &true, sizeof(true)},
        {CKA_VALUE_LEN, &valuelen, sizeof(CK_ULONG)}
    };
    // Workaround since templates are not static
    CK_ATTRIBUTE *tmpls[] = {
        derive_tmpl,
        derive_tmpl_noab
    };
    CK_ULONG tmplsizes[] = {
        ARRAY_SIZE(derive_tmpl),
        ARRAY_SIZE(derive_tmpl_noab)
    };
    CK_ATTRIBUTE checkattr = {CKA_IBM_ATTRBOUND, &checkval, sizeof(CK_BBOOL)};
    CK_ECDH1_DERIVE_PARAMS parm;
    CK_MECHANISM mech = {CKM_ECDH1_DERIVE, &parm, sizeof(parm)};
    CK_BYTE pubkey_value[256];
    CK_ATTRIBUTE extr_tmpl = {CKA_EC_POINT, pubkey_value, sizeof(pubkey_value)};
    CK_OBJECT_HANDLE handle;
    static const struct {
        CK_OBJECT_HANDLE *basekey;
        CK_OBJECT_HANDLE *pubkey;
        CK_ULONG          tmplidx;
        CK_BBOOL          abval;
        CK_RV             exprc;
        CK_BBOOL          expabval;
    } config[] = {
        // AB from AB with explicit template
        /*0*/{&keys.u.d.ecpriv, &keys.u.d.ecpub, 0, TRUE, CKR_OK, TRUE},
        // AB from AB with implicit template
        /*1*/{&keys.u.d.ecpriv, &keys.u.d.ecpub, 1, TRUE, CKR_OK, TRUE},
        // non-AB from AB
        /*2*/{&keys.u.d.ecpriv, &keys.u.d.ecpub, 0, FALSE, CKR_OK, FALSE},
        // AB from non-AB (expected to fail)
        /*3*/{&keys.u.d.nonabecpriv, &keys.u.d.nonabecpub, 0, TRUE, CKR_TEMPLATE_INCONSISTENT, FALSE}
    };

    for (i = 0; i < ARRAY_SIZE(config); ++i) {
        handle = CK_INVALID_HANDLE;
        val = config[i].abval;
        testcase_begin("Derive Test %u", i);
        testcase_new_assertion();
        rc = funcs->C_GetAttributeValue(session, *(config[i].pubkey),
                                        &extr_tmpl, 1);
        if (rc != CKR_OK) {
            testcase_fail("Derive Test %u failed to extract EC point (rc=%s)",
                          i, p11_get_ckr(rc));
            continue;
        }
        parm.kdf = CKD_NULL;
        parm.pSharedData = NULL;
        parm.ulSharedDataLen = 0;
        parm.pPublicData = extr_tmpl.pValue;
        parm.ulPublicDataLen = extr_tmpl.ulValueLen;
        rc = funcs->C_DeriveKey(session, &mech, *(config[i].basekey),
                                tmpls[config[i].tmplidx],
                                tmplsizes[config[i].tmplidx],
                                &handle);
        if (rc == CKR_MECHANISM_INVALID) {
            /* Special handling for bug in EP11: ECDH only supported for newer cards. */
            testcase_skip("Derive Test %u skipped due to bad card level\n", i);
            continue;
        }else if (rc != config[i].exprc) {
            testcase_fail("Derive Test %u got unexpected derive result (got: %s; expected %s)",
                          i, p11_get_ckr(rc), p11_get_ckr(config[i].exprc));
            continue;
        }
        if (rc == CKR_OK) {
            rc = funcs->C_GetAttributeValue(session, handle, &checkattr, 1);
            if (rc == CKR_TEMPLATE_INCOMPLETE) {
                // Treat this as okay, but non-AB
                rc = CKR_OK;
                checkval = FALSE;
            }
            if (rc != CKR_OK) {
                testcase_fail("Derive Test %u failed to retrieve AB attribute (rc=%s)",
                              i, p11_get_ckr(rc));
            } else if (checkval == config[i].expabval) {
                testcase_pass("Derive Test %u: cycle completed", i);
            } else {
                testcase_fail("Derive Test %u got wrong AB value (expected %s)",
                              i, config[i].expabval ? "TRUE" : "FALSE");
            }
        } else {
            testcase_pass("Derive Test %u failed as expected", i);
        }
        funcs->C_DestroyObject(session, handle);
    }
}

void testdriver(void)
{
    CK_BYTE user_pin[PKCS11_MAX_PIN_LEN];
    CK_ULONG user_pin_len;
    CK_SESSION_HANDLE session;
    CK_FLAGS flags;
    CK_RV rc = CKR_OK;

    testsuite_begin("Attribute Bound Keys Tests");
    testcase_rw_session();
    testcase_user_login();

    do_TestInvalidKeys(session);

    do_CreateKeyObjects(session);

    rc = do_SetupKeys(session);
    if (rc == CKR_POLICY_VIOLATION) {
        rc = CKR_OK;
        goto testcase_cleanup;
    }
    if (rc != CKR_OK) {
        testcase_error("Bail out since keys were not properly created!");
        goto testcase_cleanup;
    }
    do_TestKeyWrappingUnwrapping(session);
    do_TestDerive(session);
    do_TestAttributeChange(session);
 testcase_cleanup:
    teardown(session);
    testcase_user_logout();
    testcase_close_session();
}

int main(int argc, char **argv)
{
    int rc;
    CK_C_INITIALIZE_ARGS cinit_args;

    rc = do_ParseArgs(argc, argv);
    if (rc != 1) {
        return rc;
    }

    printf("Using slot #%lu...\n\n", SLOT_ID);
    printf("With option: no_stop: %d\n", no_stop);

    rc = do_GetFunctionList();
    if (!rc) {
        PRINT_ERR("ERROR do_GetFunctionList() Failed, rx = 0x%0x\n", rc);
        return rc;
    }

    memset(&cinit_args, 0x0, sizeof(cinit_args));
    cinit_args.flags = CKF_OS_LOCKING_OK;

    funcs->C_Initialize(&cinit_args);
    {
        CK_SESSION_HANDLE hsess = 0;
        rc = funcs->C_GetFunctionStatus(hsess);
        if (rc != CKR_FUNCTION_NOT_PARALLEL) {
            return rc;
        }

        rc = funcs->C_CancelFunction(hsess);
        if (rc != CKR_FUNCTION_NOT_PARALLEL) {
            return rc;
        }
    }

    if (is_ep11_token(SLOT_ID)) {
        testcase_setup();
        rc = do_CheckMechanismInfo();
        if (rc != CKR_OK) {
            // Skip, but don't crash the test executor
            rc = 0;
        } else {
            testdriver();
            testcase_print_result();
        }
    } else {
        rc = 0;
        testcase_begin("%s\n", __func__);
        testcase_skip("%s only supported on the EP11 token.\n", argv[0]);
    }

    funcs->C_Finalize(NULL);

    return testcase_return(rc);
}
