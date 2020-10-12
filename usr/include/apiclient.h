/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef _APICLIENT_H
#define _APICLIENT_H


#include "pkcs11types.h"

#ifdef __cplusplus
extern "C" {
#endif

    CK_RV C_CancelFunction(CK_SESSION_HANDLE);

    CK_RV C_CloseAllSessions(CK_SLOT_ID);

    CK_RV C_CloseSession(CK_SESSION_HANDLE);

    CK_RV C_CopyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                       CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

    CK_RV C_CreateObject(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG,
                         CK_OBJECT_HANDLE_PTR);

    CK_RV C_Decrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                    CK_ULONG_PTR);

    CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV C_DecryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV C_DecryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);

    CK_RV C_DecryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                          CK_ULONG_PTR);

    CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV C_DeriveKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                      CK_ATTRIBUTE_PTR, CK_ULONG, CK_OBJECT_HANDLE_PTR);

    CK_RV C_DestroyObject(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);

    CK_RV C_Digest(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                   CK_ULONG_PTR);

    CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                                CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV C_DigestFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV C_DigestInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR);

    CK_RV C_DigestKey(CK_SESSION_HANDLE, CK_OBJECT_HANDLE);

    CK_RV C_DigestUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

    CK_RV C_Encrypt(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                    CK_ULONG_PTR);

    CK_RV C_EncryptFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV C_EncryptInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);

    CK_RV C_EncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                          CK_ULONG_PTR);

    CK_RV C_Finalize(CK_VOID_PTR);

    CK_RV C_FindObjects(CK_SESSION_HANDLE, CK_OBJECT_HANDLE_PTR, CK_ULONG,
                        CK_ULONG_PTR);

    CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE);

    CK_RV C_FindObjectsInit(CK_SESSION_HANDLE, CK_ATTRIBUTE_PTR, CK_ULONG);

    CK_RV C_GenerateKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR,
                        CK_ULONG, CK_OBJECT_HANDLE_PTR);

    CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                            CK_ATTRIBUTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR,
                            CK_ULONG, CK_OBJECT_HANDLE_PTR,
                            CK_OBJECT_HANDLE_PTR);

    CK_RV C_GenerateRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

    CK_RV C_GetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                              CK_ATTRIBUTE_PTR, CK_ULONG);

    CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR);

    CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE);

    CK_RV C_GetInfo(CK_INFO_PTR);

    CK_RV C_GetMechanismInfo(CK_SLOT_ID, CK_MECHANISM_TYPE,
                             CK_MECHANISM_INFO_PTR);

    CK_RV C_GetMechanismList(CK_SLOT_ID, CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);

    CK_RV C_GetObjectSize(CK_SESSION_HANDLE, CK_OBJECT_HANDLE, CK_ULONG_PTR);

    CK_RV C_GetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV C_GetSessionInfo(CK_SESSION_HANDLE, CK_SESSION_INFO_PTR);

    CK_RV C_GetSlotInfo(CK_SLOT_ID, CK_SLOT_INFO_PTR);

    CK_RV C_GetSlotList(CK_BBOOL, CK_SLOT_ID_PTR, CK_ULONG_PTR);

    CK_RV C_GetTokenInfo(CK_SLOT_ID, CK_TOKEN_INFO_PTR);

    CK_RV C_Initialize(CK_VOID_PTR);

    CK_RV C_InitPIN(CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG);

    CK_RV C_InitToken(CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR);

    CK_RV C_Login(CK_SESSION_HANDLE, CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);

    CK_RV C_Logout(CK_SESSION_HANDLE);

    CK_RV C_OpenSession(CK_SLOT_ID, CK_FLAGS, CK_VOID_PTR, CK_NOTIFY,
                        CK_SESSION_HANDLE_PTR);

    CK_RV C_SeedRandom(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

    CK_RV C_SetAttributeValue(CK_SESSION_HANDLE, CK_OBJECT_HANDLE,
                              CK_ATTRIBUTE_PTR, CK_ULONG);

    CK_RV C_SetOperationState(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                              CK_OBJECT_HANDLE, CK_OBJECT_HANDLE);

    CK_RV C_SetPIN(CK_SESSION_HANDLE, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR,
                   CK_ULONG);

    CK_RV C_Sign(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                 CK_ULONG_PTR);

    CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG,
                              CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV C_SignFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV C_SignInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);

    CK_RV C_SignRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                        CK_ULONG_PTR);

    CK_RV C_SignRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                            CK_OBJECT_HANDLE);

    CK_RV C_SignUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

    CK_RV C_UnwrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                      CK_BYTE_PTR, CK_ULONG, CK_ATTRIBUTE_PTR, CK_ULONG,
                      CK_OBJECT_HANDLE_PTR);

    CK_RV C_Verify(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                   CK_ULONG);

    CK_RV C_VerifyFinal(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

    CK_RV C_VerifyInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE);

    CK_RV C_VerifyRecover(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG, CK_BYTE_PTR,
                          CK_ULONG_PTR);

    CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                              CK_OBJECT_HANDLE);

    CK_RV C_VerifyUpdate(CK_SESSION_HANDLE, CK_BYTE_PTR, CK_ULONG);

    CK_RV C_WaitForSlotEvent(CK_FLAGS, CK_SLOT_ID_PTR, CK_VOID_PTR);

    CK_RV C_WrapKey(CK_SESSION_HANDLE, CK_MECHANISM_PTR, CK_OBJECT_HANDLE,
                    CK_OBJECT_HANDLE, CK_BYTE_PTR, CK_ULONG_PTR);

    CK_RV C_GetInterfaceList(CK_INTERFACE_PTR, CK_ULONG_PTR);

    CK_RV C_GetInterface(CK_UTF8CHAR_PTR, CK_VERSION_PTR,
                         CK_INTERFACE_PTR_PTR, CK_FLAGS);

    CK_RV C_LoginUser(CK_SESSION_HANDLE, CK_USER_TYPE,
                      CK_UTF8CHAR *, CK_ULONG,
                      CK_UTF8CHAR *, CK_ULONG);

    CK_RV C_SessionCancel(CK_SESSION_HANDLE, CK_FLAGS);

    CK_RV C_MessageEncryptInit(CK_SESSION_HANDLE,
                               CK_MECHANISM *, CK_OBJECT_HANDLE);

    CK_RV C_EncryptMessage(CK_SESSION_HANDLE ,
                           void *, CK_ULONG,
                           CK_BYTE *, CK_ULONG,
                           CK_BYTE *, CK_ULONG,
                           CK_BYTE *, CK_ULONG *);

    CK_RV C_EncryptMessageBegin(CK_SESSION_HANDLE,
                                void *, CK_ULONG,
                                CK_BYTE *,
                                CK_ULONG);

    CK_RV C_EncryptMessageNext(CK_SESSION_HANDLE,
                               void *, CK_ULONG,
                               CK_BYTE *,
                               CK_ULONG,
                               CK_BYTE *,
                               CK_ULONG *,
                               CK_ULONG);

    CK_RV C_MessageEncryptFinal(CK_SESSION_HANDLE);

    CK_RV C_MessageDecryptInit(CK_SESSION_HANDLE,
                           CK_MECHANISM *, CK_OBJECT_HANDLE);

    CK_RV C_DecryptMessage(CK_SESSION_HANDLE,
                           void *, CK_ULONG,
                           CK_BYTE *, CK_ULONG,
                           CK_BYTE *, CK_ULONG,
                           CK_BYTE *, CK_ULONG *);

    CK_RV C_DecryptMessageBegin(CK_SESSION_HANDLE,
                                void *, CK_ULONG,
                                CK_BYTE *,
                                CK_ULONG);

    CK_RV C_DecryptMessageNext(CK_SESSION_HANDLE,
                               void *, CK_ULONG,
                               CK_BYTE *,
                               CK_ULONG,
                               CK_BYTE *,
                               CK_ULONG *,
                               CK_FLAGS);

    CK_RV C_MessageDecryptFinal(CK_SESSION_HANDLE);

    CK_RV C_MessageSignInit(CK_SESSION_HANDLE,
                            CK_MECHANISM *, CK_OBJECT_HANDLE);

    CK_RV C_SignMessage(CK_SESSION_HANDLE,
                        void *, CK_ULONG,
                        CK_BYTE *, CK_ULONG,
                        CK_BYTE *, CK_ULONG *);

    CK_RV C_SignMessageBegin(CK_SESSION_HANDLE,
                             void *, CK_ULONG);

    CK_RV C_SignMessageNext(CK_SESSION_HANDLE,
                            void *, CK_ULONG,
                            CK_BYTE *, CK_ULONG,
                            CK_BYTE *, CK_ULONG *);

    CK_RV C_MessageSignFinal(CK_SESSION_HANDLE);

    CK_RV C_MessageVerifyInit(CK_SESSION_HANDLE,
                              CK_MECHANISM *, CK_OBJECT_HANDLE);

    CK_RV C_VerifyMessage(CK_SESSION_HANDLE,
                          void *, CK_ULONG,
                          CK_BYTE *, CK_ULONG,
                          CK_BYTE *, CK_ULONG);

    CK_RV C_VerifyMessageBegin(CK_SESSION_HANDLE,
                               void *, CK_ULONG);

    CK_RV C_VerifyMessageNext(CK_SESSION_HANDLE,
                              void *, CK_ULONG,
                              CK_BYTE *, CK_ULONG,
                              CK_BYTE *, CK_ULONG);

    CK_RV C_MessageVerifyFinal(CK_SESSION_HANDLE);

    CK_RV C_IBM_ReencryptSingle(CK_SESSION_HANDLE, CK_MECHANISM_PTR,
                                CK_OBJECT_HANDLE, CK_MECHANISM_PTR,
                                CK_OBJECT_HANDLE, CK_BYTE_PTR,
                                CK_ULONG, CK_BYTE_PTR, CK_ULONG_PTR);
#ifdef __cplusplus
}
#endif
#endif                          // _APICLIENT_H
