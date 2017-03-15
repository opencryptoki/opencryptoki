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
//  API Local control blocks within the PKCS11 Meta API
//
//
//


#include <pkcs11types.h>
#include <limits.h>
#include <local_types.h>
#include <slotmgr.h>

#ifndef _STDLL_H
#define _STDLL_H



typedef struct {
   CK_SLOT_ID  slotID;
   CK_SESSION_HANDLE  sessionh;
} ST_SESSION_T ;


typedef ST_SESSION_T ST_SESSION_HANDLE;

/* CK_FUNCTION_LIST is a structure holding a Cryptoki spec
 * version and pointers of appropriate types to all the
 * Cryptoki functions */
/* CK_FUNCTION_LIST is new for v2.0 */



typedef CK_RV (CK_PTR ST_C_Initialize) (void **ppFunctionList,
					CK_SLOT_ID slotID,
					CK_CHAR_PTR pConfName);

typedef CK_RV	(CK_PTR  ST_C_Finalize)
						(CK_VOID_PTR pReserved);
typedef CK_RV	(CK_PTR  ST_C_Terminate)
						(void);
typedef CK_RV	(CK_PTR  ST_C_GetInfo)
						(CK_INFO_PTR pInfo);
typedef CK_RV	(CK_PTR  ST_C_GetFunctionList)
						(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV	(CK_PTR  ST_C_GetSlotList)
						(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
						 CK_ULONG_PTR pusCount);
typedef CK_RV	(CK_PTR  ST_C_GetSlotInfo)
						(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV	(CK_PTR  ST_C_GetTokenInfo)
						(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV	(CK_PTR  ST_C_GetMechanismList)
						(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
						 CK_ULONG_PTR pusCount);
typedef CK_RV	(CK_PTR  ST_C_GetMechanismInfo)
						(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
						 CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV	(CK_PTR  ST_C_InitToken)
						(CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_ULONG usPinLen,
						 CK_CHAR_PTR pLabel);
typedef CK_RV	(CK_PTR  ST_C_InitPIN)
						(ST_SESSION_T *hSession, CK_CHAR_PTR pPin,
						 CK_ULONG usPinLen);
typedef CK_RV	(CK_PTR  ST_C_SetPIN)
						(ST_SESSION_T *hSession, CK_CHAR_PTR pOldPin,
						 CK_ULONG usOldLen, CK_CHAR_PTR pNewPin,
						 CK_ULONG usNewLen);

// typedef CK_RV	(CK_PTR  ST_C_OpenSession)
// 						(CK_SLOT_ID slotID, CK_FLAGS flags,
// 						 CK_VOID_PTR pApplication,
// 						 CK_RV  (*Notify) (CK_SESSION_HANDLE hSession,
// 						 CK_NOTIFICATION event, CK_VOID_PTR pApplication),
// 						 CK_SESSION_HANDLE_PTR phSession);

typedef CK_RV	(CK_PTR  ST_C_OpenSession)
						(CK_SLOT_ID slotID, CK_FLAGS flags,
						 CK_SESSION_HANDLE_PTR phSession);

typedef CK_RV	(CK_PTR  ST_C_CloseSession)
						(ST_SESSION_T *hSession);
typedef CK_RV	(CK_PTR  ST_C_CloseAllSessions)
						(CK_SLOT_ID slotID);
typedef CK_RV	(CK_PTR  ST_C_GetSessionInfo)
						(ST_SESSION_T *hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_RV	(CK_PTR  ST_C_GetOperationState)
						(ST_SESSION_T *hSession, CK_BYTE_PTR pOperationState,
						 CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV	(CK_PTR  ST_C_SetOperationState)
						(ST_SESSION_T *hSession, CK_BYTE_PTR pOperationState,
						 CK_ULONG ulOperationStateLen,
						 CK_OBJECT_HANDLE hEncryptionKey,
						 CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV	(CK_PTR  ST_C_Login)(ST_SESSION_T *hSession,
						 CK_USER_TYPE userType, CK_CHAR_PTR pPin,
						 CK_ULONG usPinLen);
typedef CK_RV	(CK_PTR  ST_C_Logout)(ST_SESSION_T *hSession);
typedef CK_RV	(CK_PTR  ST_C_CreateObject)
						(ST_SESSION_T *hSession, CK_ATTRIBUTE_PTR pTemplate,
						 CK_ULONG usCount, CK_OBJECT_HANDLE_PTR phObject);

typedef CK_RV	(CK_PTR  ST_C_CopyObject)
						(ST_SESSION_T *hSession, CK_OBJECT_HANDLE hObject,
						 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount,
						 CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (CK_PTR  ST_C_DestroyObject)
                       (ST_SESSION_T *hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV(CK_PTR  ST_C_GetObjectSize)
                       (ST_SESSION_T *hSession, CK_OBJECT_HANDLE hObject,
                        CK_ULONG_PTR pusSize);
typedef CK_RV(CK_PTR  ST_C_GetAttributeValue)
                       (ST_SESSION_T *hSession, CK_OBJECT_HANDLE hObject,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount);
typedef CK_RV(CK_PTR  ST_C_SetAttributeValue)
                       (ST_SESSION_T *hSession, CK_OBJECT_HANDLE hObject,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount);
typedef CK_RV (CK_PTR  ST_C_FindObjectsInit)
                       (ST_SESSION_T *hSession, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG usCount);
typedef CK_RV (CK_PTR  ST_C_FindObjects)
                       (ST_SESSION_T *hSession,
                        CK_OBJECT_HANDLE_PTR phObject, CK_ULONG usMaxObjectCount,
                        CK_ULONG_PTR pusObjectCount);
typedef CK_RV (CK_PTR  ST_C_FindObjectsFinal)
                       (ST_SESSION_T *hSession);
typedef CK_RV (CK_PTR  ST_C_EncryptInit)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  ST_C_Encrypt)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pData,
                        CK_ULONG usDataLen, CK_BYTE_PTR pEncryptedData,
                        CK_ULONG_PTR pusEncryptedDataLen);
typedef CK_RV (CK_PTR  ST_C_EncryptUpdate)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pPart,
                        CK_ULONG usPartLen, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG_PTR pusEncryptedPartLen);
typedef CK_RV (CK_PTR  ST_C_EncryptFinal)
                       (ST_SESSION_T *hSession,
                        CK_BYTE_PTR pLastEncryptedPart,
                        CK_ULONG_PTR pusLastEncryptedPartLen);
typedef CK_RV (CK_PTR  ST_C_DecryptInit)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  ST_C_Decrypt)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pEncryptedData,
                        CK_ULONG usEncryptedDataLen, CK_BYTE_PTR pData,
                        CK_ULONG_PTR pusDataLen);
typedef CK_RV (CK_PTR  ST_C_DecryptUpdate)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG usEncryptedPartLen, CK_BYTE_PTR pPart,
                        CK_ULONG_PTR pusPartLen);
typedef CK_RV (CK_PTR  ST_C_DecryptFinal)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pLastPart,
                        CK_ULONG_PTR pusLastPartLen);
typedef CK_RV (CK_PTR  ST_C_DigestInit)
                       (ST_SESSION_T *hSession,
                        CK_MECHANISM_PTR pMechanism);
typedef CK_RV (CK_PTR  ST_C_Digest)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pData,
                        CK_ULONG usDataLen, CK_BYTE_PTR pDigest,
                        CK_ULONG_PTR pusDigestLen);
typedef CK_RV (CK_PTR  ST_C_DigestUpdate)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pPart,
                        CK_ULONG usPartLen);
typedef CK_RV (CK_PTR  ST_C_DigestKey)
                       (ST_SESSION_T *hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  ST_C_DigestFinal)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pDigest,
                        CK_ULONG_PTR pusDigestLen);
typedef CK_RV (CK_PTR  ST_C_SignInit)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  ST_C_Sign)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pData,
                        CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
                        CK_ULONG_PTR pusSignatureLen);
typedef CK_RV (CK_PTR  ST_C_SignUpdate)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pPart,
                        CK_ULONG usPartLen);
typedef CK_RV (CK_PTR  ST_C_SignFinal)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pSignature,
                        CK_ULONG_PTR pusSignatureLen);
typedef CK_RV (CK_PTR  ST_C_SignRecoverInit)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  ST_C_SignRecover)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pData,
                        CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
                        CK_ULONG_PTR pusSignatureLen);
typedef CK_RV (CK_PTR  ST_C_VerifyInit)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  ST_C_Verify)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pData,
                        CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
                        CK_ULONG usSignatureLen);
typedef CK_RV (CK_PTR  ST_C_VerifyUpdate)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pPart,
                        CK_ULONG usPartLen);
typedef CK_RV (CK_PTR  ST_C_VerifyFinal)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pSignature,
                        CK_ULONG usSignatureLen);
typedef CK_RV (CK_PTR  ST_C_VerifyRecoverInit)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  ST_C_VerifyRecover)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pSignature,
                        CK_ULONG usSignatureLen, CK_BYTE_PTR pData,
                        CK_ULONG_PTR pusDataLen);
typedef CK_RV (CK_PTR  ST_C_DigestEncryptUpdate)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pPart,
                        CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (CK_PTR  ST_C_DecryptDigestUpdate)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                        CK_ULONG_PTR pulPartLen);
typedef CK_RV (CK_PTR  ST_C_SignEncryptUpdate)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pPart,
                        CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (CK_PTR  ST_C_DecryptVerifyUpdate)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                        CK_ULONG_PTR pulPartLen);
typedef CK_RV (CK_PTR  ST_C_GenerateKey)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount,
                        CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_PTR  ST_C_GenerateKeyPair)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG usPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG usPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPrivateKey,
                        CK_OBJECT_HANDLE_PTR phPublicKey);
typedef CK_RV (CK_PTR  ST_C_WrapKey)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                        CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pusWrappedKeyLen);
typedef CK_RV (CK_PTR  ST_C_UnwrapKey)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                        CK_ULONG usWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG usAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_PTR  ST_C_DeriveKey)
                       (ST_SESSION_T *hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG usAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_PTR  ST_C_SeedRandom)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pSeed,
                        CK_ULONG usSeedLen);
typedef CK_RV (CK_PTR  ST_C_GenerateRandom)
                       (ST_SESSION_T *hSession, CK_BYTE_PTR pRandomData,
                        CK_ULONG usRandomLen);
typedef CK_RV (CK_PTR  ST_C_GetFunctionStatus)
                       (ST_SESSION_T *hSession);
typedef CK_RV (CK_PTR  ST_C_CancelFunction)
                       (ST_SESSION_T *hSession);
typedef CK_RV	(CK_PTR  ST_Notify)
						(ST_SESSION_T *hSession, CK_NOTIFICATION event,
						 CK_VOID_PTR pApplication);
typedef CK_RV	(CK_PTR  ST_C_WaitForSlotEvent)
						(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
						 CK_VOID_PTR pReserved);



struct ST_FCN_LIST{

   // Need initialization function But it is different than
   // the C_Initialize
	ST_C_Initialize ST_Initialize;

	ST_C_GetTokenInfo ST_GetTokenInfo;
	ST_C_GetMechanismList ST_GetMechanismList;
	ST_C_GetMechanismInfo ST_GetMechanismInfo;
	ST_C_InitToken ST_InitToken;
	ST_C_InitPIN ST_InitPIN;
	ST_C_SetPIN ST_SetPIN;

	ST_C_OpenSession ST_OpenSession;
	ST_C_CloseSession ST_CloseSession;
	ST_C_GetSessionInfo ST_GetSessionInfo;
	ST_C_GetOperationState ST_GetOperationState;  // Not used by Netscape
	ST_C_SetOperationState ST_SetOperationState;  // Not used by Netscape
	ST_C_Login ST_Login;
	ST_C_Logout ST_Logout;

	ST_C_CreateObject ST_CreateObject;
	ST_C_CopyObject ST_CopyObject;
	ST_C_DestroyObject ST_DestroyObject;
	ST_C_GetObjectSize ST_GetObjectSize;
	ST_C_GetAttributeValue ST_GetAttributeValue;
	ST_C_SetAttributeValue ST_SetAttributeValue;
	ST_C_FindObjectsInit ST_FindObjectsInit;
	ST_C_FindObjects ST_FindObjects;
	ST_C_FindObjectsFinal ST_FindObjectsFinal;


	ST_C_EncryptInit ST_EncryptInit;
	ST_C_Encrypt ST_Encrypt;
	ST_C_EncryptUpdate ST_EncryptUpdate;  // Not used by Netscape
	ST_C_EncryptFinal ST_EncryptFinal;  // Not used by Netscape
	ST_C_DecryptInit ST_DecryptInit;
	ST_C_Decrypt ST_Decrypt;
	ST_C_DecryptUpdate ST_DecryptUpdate;  // Not used by Netscape
	ST_C_DecryptFinal ST_DecryptFinal;  // Not used by Netscape
	ST_C_DigestInit ST_DigestInit;
	ST_C_Digest ST_Digest;
	ST_C_DigestUpdate ST_DigestUpdate;
	ST_C_DigestKey ST_DigestKey;
	ST_C_DigestFinal ST_DigestFinal;
	ST_C_SignInit ST_SignInit;
	ST_C_Sign ST_Sign;
	ST_C_SignUpdate ST_SignUpdate;
	ST_C_SignFinal ST_SignFinal;
	ST_C_SignRecoverInit ST_SignRecoverInit;
	ST_C_SignRecover ST_SignRecover;
	ST_C_VerifyInit ST_VerifyInit;
	ST_C_Verify ST_Verify;
	ST_C_VerifyUpdate ST_VerifyUpdate;
	ST_C_VerifyFinal ST_VerifyFinal;
	ST_C_VerifyRecoverInit ST_VerifyRecoverInit;
	ST_C_VerifyRecover ST_VerifyRecover;
	ST_C_DigestEncryptUpdate ST_DigestEncryptUpdate;
	ST_C_DecryptDigestUpdate ST_DecryptDigestUpdate;
	ST_C_SignEncryptUpdate ST_SignEncryptUpdate;
	ST_C_DecryptVerifyUpdate ST_DecryptVerifyUpdate;
	ST_C_GenerateKey ST_GenerateKey;
	ST_C_GenerateKeyPair ST_GenerateKeyPair;
	ST_C_WrapKey ST_WrapKey;    // Netscape optionsl will use En/Decrypt
	ST_C_UnwrapKey ST_UnwrapKey;
	ST_C_DeriveKey ST_DeriveKey;
	ST_C_SeedRandom ST_SeedRandom;
	ST_C_GenerateRandom ST_GenerateRandom;
   // Question if these have to be implemented for Netscape support
	ST_C_GetFunctionStatus ST_GetFunctionStatus;
	ST_C_CancelFunction ST_CancelFunction;

};

typedef struct ST_FCN_LIST  STDLL_FcnList_t;

#endif
