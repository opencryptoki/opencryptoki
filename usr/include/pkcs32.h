/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

//
// File: PKCS11Types.h
//
//
//----------------------------------------------------------------------------


#ifndef _PKCS1132_H_
#define _PKCS1132_H_


#ifdef __cplusplus
extern "C" {
#endif


/* These are the new definitions need for the structures in
 * leeds_stdll largs.h (and elsewhere)
 */

typedef unsigned int CK_ULONG_32;
typedef int CK_LONG_32;
typedef unsigned int *CK_ULONG_PTR_32;

typedef CK_ULONG_32 CK_MECHANISM_TYPE_32;
typedef CK_ULONG_32 CK_SESSION_HANDLE_32;
typedef CK_ULONG_32 CK_SLOT_ID_32;
typedef CK_ULONG_32 CK_FLAGS_32;
typedef CK_ULONG_32 CK_USER_TYPE_32;
typedef CK_ULONG_32 CK_OBJECT_HANDLE_32;
typedef CK_OBJECT_HANDLE_32 *CK_OBJECT_HANDLE__PTR_32;
typedef CK_ULONG_32 CK_ATTRIBUTE_TYPE_32;
typedef CK_ULONG_32 CK_STATE_32;
typedef CK_ULONG_32 CK_OBJECT_CLASS_32;

typedef CK_BYTE CK_PTR CK_BYTE_PTR_32;
typedef CK_CHAR CK_PTR CK_CHAR_PTR_32;

typedef CK_ULONG_32 CK_MAC_GENERAL_PARAMS_32;

typedef CK_MAC_GENERAL_PARAMS_32 CK_PTR CK_MAC_GENERAL_PARAMS_PTR_32;

// SSL 3 Mechanism pointers for the Leeds card.
typedef struct CK_SSL3_RANDOM_DATA_32 {
    CK_BYTE_PTR_32 pClientRandom;
    CK_ULONG_32 ulClientRandomLen;
    CK_BYTE_PTR_32 pServerRandom;
    CK_ULONG_32 ulServerRandomLen;
} CK_SSL3_RANDOM_DATA_32;


typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS_32 {
    CK_SSL3_RANDOM_DATA_32 RandomInfo;
    CK_VERSION_PTR pVersion;
} CK_SSL3_MASTER_KEY_DERIVE_PARAMS_32;

typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS_32 CK_PTR
    CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR_32;


typedef struct CK_SSL3_KEY_MAT_OUT_32 {
    CK_OBJECT_HANDLE_32 hClientMacSecret;
    CK_OBJECT_HANDLE_32 hServerMacSecret;
    CK_OBJECT_HANDLE_32 hClientKey;
    CK_OBJECT_HANDLE_32 hServerKey;
    CK_BYTE_PTR_32 pIVClient;
    CK_BYTE_PTR_32 pIVServer;
} CK_SSL3_KEY_MAT_OUT_32;

typedef CK_SSL3_KEY_MAT_OUT_32 CK_PTR CK_SSL3_KEY_MAT_OUT_PTR_32;


typedef struct CK_SSL3_KEY_MAT_PARAMS_32 {
    CK_ULONG_32 ulMacSizeInBits;
    CK_ULONG_32 ulKeySizeInBits;
    CK_ULONG_32 ulIVSizeInBits;
    CK_BBOOL bIsExport;
    CK_SSL3_RANDOM_DATA_32 RandomInfo;
    CK_SSL3_KEY_MAT_OUT_PTR_32 pReturnedKeyMaterial;
} CK_SSL3_KEY_MAT_PARAMS_32;

typedef CK_SSL3_KEY_MAT_PARAMS_32 CK_PTR CK_SSL3_KEY_MAT_PARAMS_PTR_32;


typedef struct CK_KEY_DERIVATION_STRING_DATA_32 {
    CK_BYTE_PTR_32 pData;
    CK_ULONG_32 ulLen;
} CK_KEY_DERIVATION_STRING_DATA_32;

typedef CK_KEY_DERIVATION_STRING_DATA_32 CK_PTR
    CK_KEY_DERIVATION_STRING_DATA_PTR_32;


typedef struct CK_TOKEN_INFO_32 {
    CK_CHAR label[32];          /* blank padded */
    CK_CHAR manufacturerID[32]; /* blank padded */
    CK_CHAR model[16];          /* blank padded */
    CK_CHAR serialNumber[16];   /* blank padded */
    CK_FLAGS_32 flags;          /* see below */
    // SAB FIXME needs to be 32 bit

    /* ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount,
     * ulRwSessionCount, ulMaxPinLen, and ulMinPinLen have all been
     * changed from CK_USHORT to CK_ULONG for v2.0 */
    CK_ULONG_32 ulMaxSessionCount;      /* max open sessions */
    CK_ULONG_32 ulSessionCount; /* sess. now open */
    CK_ULONG_32 ulMaxRwSessionCount;    /* max R/W sessions */
    CK_ULONG_32 ulRwSessionCount;       /* R/W sess. now open */
    CK_ULONG_32 ulMaxPinLen;    /* in bytes */
    CK_ULONG_32 ulMinPinLen;    /* in bytes */
    CK_ULONG_32 ulTotalPublicMemory;    /* in bytes */
    CK_ULONG_32 ulFreePublicMemory;     /* in bytes */
    CK_ULONG_32 ulTotalPrivateMemory;   /* in bytes */
    CK_ULONG_32 ulFreePrivateMemory;    /* in bytes */

    /* hardwareVersion, firmwareVersion, and time are new for
     * v2.0 */
    CK_VERSION hardwareVersion; /* version of hardware */
    CK_VERSION firmwareVersion; /* version of firmware */
    CK_CHAR utcTime[16];        /* time */
} CK_TOKEN_INFO_32;


typedef struct CK_SESSION_INFO_32 {
    CK_SLOT_ID_32 slotID;
    CK_STATE_32 state;
    CK_FLAGS_32 flags;          /* see below */

    /* ulDeviceError was changed from CK_USHORT to CK_ULONG for
     * v2.0 */
    CK_ULONG_32 ulDeviceError;  /* device-dependent error code */
} CK_SESSION_INFO_32;


typedef struct CK_MECHANISM_INFO_32 {
    CK_ULONG_32 ulMinKeySize;
    CK_ULONG_32 ulMaxKeySize;
    CK_FLAGS_32 flags;
} CK_MECHANISM_INFO_32;

/* CK_MECHANISM_32 is a structure that specifies a particular
 * mechanism  */
typedef struct CK_MECHANISM_32 {
    CK_MECHANISM_TYPE_32 mechanism;
    CK_VOID_PTR pParameter;

    /* ulParameterLen was changed from CK_USHORT to CK_ULONG for
     * v2.0 */
    CK_ULONG_32 ulParameterLen; /* in bytes */
} CK_MECHANISM_32;

/* CK_ATTRIBUTE is a structure that includes the type, length
 * and value of an attribute */
typedef struct CK_ATTRIBUTE_32 {
    CK_ATTRIBUTE_TYPE_32 type;
    CK_ULONG_32 pValue;         // SAB XXX XXX Was CK_VOID_PTR which is 64Bit

    /* ulValueLen went from CK_USHORT to CK_ULONG for v2.0 */
    CK_ULONG_32 ulValueLen;     /* in bytes */
} CK_ATTRIBUTE_32;

#ifdef __cplusplus
}
#endif

#endif                          // _PKCS1132_HS_H_
