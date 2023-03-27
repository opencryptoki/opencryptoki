/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/***************************************************************************
                          Change Log
                          ==========
       4/25/03    Kapil Sood (kapil@corrent.com)
                  Added DH key pair generation and DH shared key derivation
                  functions.



****************************************************************************/


#ifndef _H_EXTERN_H
#define _H_EXTERN_H

#include <stdio.h>
#include "dlist.h"
#include "host_defs.h"
#include "pqc_defs.h"

#include <openssl/evp.h>

/* Forward declaration to keep dependencies as small as possible. */
struct policy;

// global variables
//
#define SO_PIN_DEFAULT			"87654321"
#define SO_KDF_LOGIN_IT			100000ULL
#define SO_KDF_LOGIN_PURPOSE		"so_login_purpose________________"
#define SO_KDF_WRAP_IT			100000ULL
#define SO_KDF_WRAP_PURPOSE		"so_wrap_purpose_________________"

#define USER_PIN_DEFAULT		"12345678"
#define USER_KDF_LOGIN_IT		100000ULL
#define USER_KDF_LOGIN_PURPOSE		"user_login_purpose______________"
#define USER_KDF_WRAP_IT		100000ULL
#define USER_KDF_WRAP_PURPOSE		"user_wrap_purpose_______________"

extern const CK_BYTE default_user_pin_sha[SHA1_HASH_SIZE];
extern const CK_BYTE default_so_pin_sha[SHA1_HASH_SIZE];
extern const CK_BYTE default_so_pin_md5[MD5_HASH_SIZE];

extern const CK_BYTE ber_AlgIdRSAEncryption[];
extern const CK_ULONG ber_AlgIdRSAEncryptionLen;
extern const CK_BYTE ber_rsaEncryption[];
extern const CK_ULONG ber_rsaEncryptionLen;
extern const CK_BYTE der_AlgIdECBase[];
extern const CK_ULONG der_AlgIdECBaseLen;
extern const CK_BYTE ber_idDSA[];
extern const CK_ULONG ber_idDSALen;
extern const CK_BYTE ber_idDH[];
extern const CK_ULONG ber_idDHLen;
extern const CK_BYTE ber_idEC[];
extern const CK_ULONG ber_idECLen;
extern const CK_BYTE ber_NULL[];
extern const CK_ULONG ber_NULLLen;

#if !(NOMD2)
extern const CK_BYTE ber_md2WithRSAEncryption[];
extern const CK_ULONG ber_md2WithRSAEncryptionLen;
#endif
extern const CK_BYTE ber_md5WithRSAEncryption[];
extern const CK_ULONG ber_md5WithRSAEncryptionLen;
extern const CK_BYTE ber_sha1WithRSAEncryption[];
extern const CK_ULONG ber_sha1WithRSAEncryptionLen;
#if !(NOMD2)
extern const CK_BYTE ber_AlgMd2[];
extern const CK_ULONG ber_AlgMd2Len;
#endif
extern const CK_BYTE ber_AlgMd5[];
extern const CK_ULONG ber_AlgMd5Len;
extern const CK_BYTE ber_AlgSha1[];
extern const CK_ULONG ber_AlgSha1Len;
extern const CK_BYTE ber_AlgSha224[];
extern const CK_ULONG ber_AlgSha224Len;
extern const CK_BYTE ber_AlgSha256[];
extern const CK_ULONG ber_AlgSha256Len;
extern const CK_BYTE ber_AlgSha384[];
extern const CK_ULONG ber_AlgSha384Len;
extern const CK_BYTE ber_AlgSha512[];
extern const CK_ULONG ber_AlgSha512Len;

extern const CK_ULONG des_weak_count;
extern const CK_ULONG des_semi_weak_count;
extern const CK_ULONG des_possibly_weak_count;
extern const CK_BYTE des_weak_keys[4][8];
extern const CK_BYTE des_semi_weak_keys[12][8];
extern const CK_BYTE des_possibly_weak_keys[48][8];

extern struct ST_FCN_LIST function_list;

// General-purpose functions
//
CK_RV C_Initialize(CK_VOID_PTR pInitArgs);
CK_RV C_Finalize(CK_VOID_PTR pReserved);
CK_RV C_GetInfo(CK_INFO_PTR pInfo);
CK_RV C_GetFunctionList(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);

// Slot and token management functions
//
CK_RV C_GetSlotList(CK_BBOOL tokenPresent,
                    CK_SLOT_ID_PTR pSlotList, CK_ULONG_PTR pulCount);

CK_RV C_GetSlotInfo(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);

CK_RV C_GetTokenInfo(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);

CK_RV C_WaitForSlotEvent(CK_FLAGS flags,
                         CK_SLOT_ID_PTR pSlot, CK_VOID_PTR pReserved);

CK_RV C_GetMechanismList(CK_SLOT_ID slotID,
                         CK_MECHANISM_TYPE_PTR pMechanismList,
                         CK_ULONG_PTR pulCount);

CK_RV C_GetMechanismInfo(CK_SLOT_ID slotID,
                         CK_MECHANISM_TYPE type, CK_MECHANISM_INFO_PTR pInfo);

CK_RV C_InitToken(CK_SLOT_ID slotID,
                  CK_CHAR_PTR pPin, CK_ULONG ulPinLen, CK_CHAR_PTR pLabel);

CK_RV C_InitPIN(CK_SESSION_HANDLE hSession,
                CK_CHAR_PTR pPin, CK_ULONG ulPinLen);

CK_RV C_SetPIN(CK_SESSION_HANDLE hSession,
               CK_CHAR_PTR pOldPin,
               CK_ULONG ulOldLen, CK_CHAR_PTR pNewPin, CK_ULONG ulNewLen);

// Session management functions
//
CK_RV C_OpenSession(CK_SLOT_ID slotID,
                    CK_FLAGS flags,
                    CK_VOID_PTR pApplication,
                    CK_NOTIFY Notify, CK_SESSION_HANDLE_PTR phSession);

CK_RV C_CloseSession(CK_SESSION_HANDLE hSession);

CK_RV C_CloseAllSessions(CK_SLOT_ID slotID);

CK_RV C_GetSessionInfo(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);

CK_RV C_GetOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG_PTR pulOperationStateLen);

CK_RV C_SetOperationState(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pOperationState,
                          CK_ULONG ulOperationStateLen,
                          CK_OBJECT_HANDLE hEncryptionKey,
                          CK_OBJECT_HANDLE hAuthenticationKey);

CK_RV C_Login(CK_SESSION_HANDLE hSession,
              CK_USER_TYPE userType, CK_CHAR_PTR pPin, CK_ULONG uPinLen);

CK_RV C_Logout(CK_SESSION_HANDLE hSession);


// Object management functions
//
CK_RV C_CreateObject(CK_SESSION_HANDLE hSession,
                     CK_ATTRIBUTE_PTR pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);

CK_RV C_CopyObject(CK_SESSION_HANDLE hSession,
                   CK_OBJECT_HANDLE hObject,
                   CK_ATTRIBUTE_PTR pTemplate,
                   CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phNewObject);

CK_RV C_DestroyObject(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);

CK_RV C_GetObjectSize(CK_SESSION_HANDLE hSession,
                      CK_OBJECT_HANDLE hObject, CK_ULONG_PTR pulSize);

CK_RV C_GetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV C_SetAttributeValue(CK_SESSION_HANDLE hSession,
                          CK_OBJECT_HANDLE hObject,
                          CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV C_FindObjectsInit(CK_SESSION_HANDLE hSession,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);

CK_RV C_FindObjects(CK_SESSION_HANDLE hSession,
                    CK_OBJECT_HANDLE_PTR phObject,
                    CK_ULONG ulMaxObjectCount, CK_ULONG_PTR pulObjectCount);

CK_RV C_FindObjectsFinal(CK_SESSION_HANDLE hSession);


// Encryption functions
//
CK_RV C_EncryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

CK_RV C_Encrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pData,
                CK_ULONG ulDataLen,
                CK_BYTE_PTR pEncryptedData, CK_ULONG_PTR pulEncryptedDataLen);

CK_RV C_EncryptUpdate(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pPart,
                      CK_ULONG ulPartLen,
                      CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG_PTR pulEncryptedPartLen);

CK_RV C_EncryptFinal(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pLastEncryptedPart,
                     CK_ULONG_PTR pulLastEncryptedPartLen);


// Decryption functions
//
CK_RV C_DecryptInit(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

CK_RV C_Decrypt(CK_SESSION_HANDLE hSession,
                CK_BYTE_PTR pEncryptedData,
                CK_ULONG ulEncryptedDataLen,
                CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);

CK_RV C_DecryptUpdate(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pEncryptedPart,
                      CK_ULONG ulEncryptedPartLen,
                      CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);

CK_RV C_DecryptFinal(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pLastPart, CK_ULONG_PTR pulLastPartLen);


// Message digesting functions
//
CK_RV C_DigestInit(CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism);

CK_RV C_Digest(CK_SESSION_HANDLE hSession,
               CK_BYTE_PTR pData,
               CK_ULONG ulDataLen,
               CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);

CK_RV C_DigestUpdate(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

CK_RV C_DigestKey(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);

CK_RV C_DigestFinal(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR pDigest, CK_ULONG_PTR pulDigestLen);


// Signing and MAC functions
//
CK_RV C_SignInit(CK_SESSION_HANDLE hSession,
                 CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

CK_RV C_Sign(CK_SESSION_HANDLE hSession,
             CK_BYTE_PTR pData,
             CK_ULONG ulDataLen,
             CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

CK_RV C_SignUpdate(CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

CK_RV C_SignFinal(CK_SESSION_HANDLE hSession,
                  CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);

CK_RV C_SignRecoverInit(CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

CK_RV C_SignRecover(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR pData,
                    CK_ULONG ulDataLen,
                    CK_BYTE_PTR pSignature, CK_ULONG_PTR pulSignatureLen);


// Signature/MAC verification functions
//
CK_RV C_VerifyInit(CK_SESSION_HANDLE hSession,
                   CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

CK_RV C_Verify(CK_SESSION_HANDLE hSession,
               CK_BYTE_PTR pData,
               CK_ULONG ulDataLen,
               CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

CK_RV C_VerifyUpdate(CK_SESSION_HANDLE hSession,
                     CK_BYTE_PTR pPart, CK_ULONG ulPartLen);

CK_RV C_VerifyFinal(CK_SESSION_HANDLE hSession,
                    CK_BYTE_PTR pSignature, CK_ULONG ulSignatureLen);

CK_RV C_VerifyRecoverInit(CK_SESSION_HANDLE hSession,
                          CK_MECHANISM_PTR pMechanism, CK_OBJECT_HANDLE hKey);

CK_RV C_VerifyRecover(CK_SESSION_HANDLE hSession,
                      CK_BYTE_PTR pSignature,
                      CK_ULONG ulSignatureLen,
                      CK_BYTE_PTR pData, CK_ULONG_PTR pulDataLen);


// Dual-function cryptographics functions
//
CK_RV C_DigestEncryptUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pPart,
                            CK_ULONG ulPartLen,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG_PTR pulEncryptedPartLen);

CK_RV C_DecryptDigestUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);

CK_RV C_SignEncryptUpdate(CK_SESSION_HANDLE hSession,
                          CK_BYTE_PTR pPart,
                          CK_ULONG ulPartLen,
                          CK_BYTE_PTR pEncryptedPart,
                          CK_ULONG_PTR pulEncryptedPartLen);

CK_RV C_DecryptVerifyUpdate(CK_SESSION_HANDLE hSession,
                            CK_BYTE_PTR pEncryptedPart,
                            CK_ULONG ulEncryptedPartLen,
                            CK_BYTE_PTR pPart, CK_ULONG_PTR pulPartLen);


// Key management functions
//
CK_RV C_GenerateKey(CK_SESSION_HANDLE hSession,
                    CK_MECHANISM_PTR pMechanism,
                    CK_ATTRIBUTE_PTR pTemplate,
                    CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phKey);

CK_RV C_GenerateKeyPair(CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG ulPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG ulPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPublicKey,
                        CK_OBJECT_HANDLE_PTR phPrivateKey);

CK_RV C_WrapKey(CK_SESSION_HANDLE hSession,
                CK_MECHANISM_PTR pMechanism,
                CK_OBJECT_HANDLE hWrappingKey,
                CK_OBJECT_HANDLE hKey,
                CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pulWrappedKeyLen);

CK_RV C_UnwrapKey(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hUnwrappingKey,
                  CK_BYTE_PTR pWrappedKey,
                  CK_ULONG ulWrappedKeyLen,
                  CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);

CK_RV C_DeriveKey(CK_SESSION_HANDLE hSession,
                  CK_MECHANISM_PTR pMechanism,
                  CK_OBJECT_HANDLE hBaseKey,
                  CK_ATTRIBUTE_PTR pTemplate,
                  CK_ULONG ulAttributeCount, CK_OBJECT_HANDLE_PTR phKey);


// Random number generation functions
//
CK_RV C_SeedRandom(CK_SESSION_HANDLE hSession,
                   CK_BYTE_PTR pSeed, CK_ULONG ulSeedLen);

CK_RV C_GenerateRandom(CK_SESSION_HANDLE hSession,
                       CK_BYTE_PTR pRandomData, CK_ULONG ulRandomLen);

// Parallel function management functions
//
CK_RV C_GetFunctionStatus(CK_SESSION_HANDLE hSession);

CK_RV C_CancelFunction(CK_SESSION_HANDLE hSession);


//
// internal routines are below this point
//
CK_RV clock_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV clock_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV clock_validate_attribute(TEMPLATE *tmpl,
                               CK_ATTRIBUTE *attr, CK_ULONG mode);

CK_RV counter_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV counter_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV counter_validate_attribute(TEMPLATE *tmpl,
                                 CK_ATTRIBUTE *attr, CK_ULONG mode);

CK_RV dp_dsa_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dp_dsa_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dp_dsa_validate_attribute(TEMPLATE *tmpl,
                                CK_ATTRIBUTE *attr, CK_ULONG mode);

CK_RV dp_dh_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dp_dh_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dp_dh_validate_attribute(TEMPLATE *tmpl,
                               CK_ATTRIBUTE *attr, CK_ULONG mode);

CK_RV dp_x9dh_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dp_x9dh_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dp_x9dh_validate_attribute(TEMPLATE *tmpl,
                                 CK_ATTRIBUTE *attr, CK_ULONG mode);

CK_RV save_token_object(STDLL_TokData_t *tokdata, OBJECT *obj);
CK_RV save_private_token_object(STDLL_TokData_t *tokdata, OBJECT *obj);
CK_RV save_public_token_object(STDLL_TokData_t *tokdata, OBJECT *obj);

CK_RV load_public_token_objects(STDLL_TokData_t *tokdata);
CK_RV load_private_token_objects(STDLL_TokData_t *tokdata);

CK_RV reload_token_object(STDLL_TokData_t *tokdata, OBJECT *obj);

CK_RV restore_private_token_object(STDLL_TokData_t *tokdata,
                                   CK_BYTE *header,
                                   CK_BYTE *data, CK_ULONG len,
                                   CK_BYTE *footer,
                                   OBJECT *pObj,
                                   const char *fname);

CK_RV delete_token_object(STDLL_TokData_t *tokdata, OBJECT *ptr);
CK_RV delete_token_data(STDLL_TokData_t *tokdata);

char *get_pk_dir(STDLL_TokData_t *tokdata, char *, size_t);

CK_RV init_token_data(STDLL_TokData_t *, CK_SLOT_ID);
CK_RV load_token_data(STDLL_TokData_t *, CK_SLOT_ID);
CK_RV save_token_data(STDLL_TokData_t *, CK_SLOT_ID);

CK_RV load_masterkey_so(STDLL_TokData_t *tokdata);
CK_RV load_masterkey_user(STDLL_TokData_t *tokdata);
CK_RV save_masterkey_so(STDLL_TokData_t *tokdata);
CK_RV save_masterkey_user(STDLL_TokData_t *tokdata);

CK_RV generate_master_key(STDLL_TokData_t *tokdata, CK_BYTE *key);

CK_RV init_data_store(STDLL_TokData_t *tokdata, char *directory,
                      char *data_store, size_t len);
void final_data_store(STDLL_TokData_t * tokdata);

void copy_token_contents_sensibly(CK_TOKEN_INFO_PTR pInfo,
                                  TOKEN_DATA *nv_token_data);

CK_RV init_hsm_mk_change_lock(STDLL_TokData_t *tokdata);

CK_RV compute_PKCS5_PBKDF2_HMAC(STDLL_TokData_t *tokdata,
                                CK_CHAR *pPin, CK_ULONG ulPinLen,
                                CK_BYTE *salt, CK_ULONG salt_len,
                                CK_ULONG it_count, const EVP_MD *digest,
                                CK_ULONG key_len, CK_BYTE *key);
CK_RV compute_md5(STDLL_TokData_t *tokdata, CK_BYTE *data, CK_ULONG len,
                  CK_BYTE *hash);
CK_RV compute_sha1(STDLL_TokData_t *tokdata, CK_BYTE *data, CK_ULONG len,
                   CK_BYTE *hash);
CK_RV compute_sha(STDLL_TokData_t *tokdata, CK_BYTE *data, CK_ULONG len,
                  CK_BYTE *hash, CK_ULONG mech);
CK_RV get_sha_size(CK_ULONG mech, CK_ULONG *hsize);
CK_RV get_sha_block_size(CK_ULONG mech, CK_ULONG *bsize);

CK_RV get_hmac_digest(CK_ULONG mech, CK_ULONG *digest_mech, CK_BBOOL *general);

CK_RV mgf1(STDLL_TokData_t *tokdata, CK_BYTE *seed, CK_ULONG seedlen,
           CK_BYTE *mask, CK_ULONG maskLen, CK_RSA_PKCS_MGF_TYPE mgf);

CK_RV get_ecsiglen(OBJECT *key_obj, CK_ULONG *size);

//CK_RV load_FCV( void );
//CK_RV save_FCV( FUNCTION_CTRL_VEC_RECORD *new_FCV );

//CK_RV update_tweak_values( void *attributes, CK_ULONG count );
//CK_RV query_tweak_values( CK_ATTRIBUTE_TYPE  * attributes,
//                          CK_ULONG             count,
//                          CK_BYTE           ** reply,
//                          CK_ULONG           * reply_len );

void init_slotInfo(CK_SLOT_INFO *);
void init_tokenInfo(TOKEN_DATA *nv_token_data);

CK_BYTE parity_adjust(CK_BYTE b);
CK_RV parity_is_odd(CK_BYTE b);

CK_RV build_attribute(CK_ATTRIBUTE_TYPE type,
                      CK_BYTE *data, CK_ULONG data_len, CK_ATTRIBUTE **attr);

CK_RV find_bbool_attribute(CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
                           CK_ATTRIBUTE_TYPE type, CK_BBOOL *value);

CK_RV add_pkcs_padding(CK_BYTE *ptr,   // where to start appending
                       CK_ULONG block_size,
                       CK_ULONG data_len, CK_ULONG total_len);

CK_RV strip_pkcs_padding(CK_BYTE *ptr,
                         CK_ULONG total_len, CK_ULONG *data_len);


// RNG routines
//
CK_RV rng_generate(STDLL_TokData_t *tokdata, CK_BYTE *output, CK_ULONG bytes);


// SSL3 routines
//
CK_RV ssl3_mac_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV ssl3_mac_sign_update(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV ssl3_mac_sign_final(STDLL_TokData_t *tokdata,
                          SESSION *sess,
                          CK_BBOOL length_only,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV ssl3_mac_verify(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *signature, CK_ULONG sig_len);

CK_RV ssl3_mac_verify_update(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             SIGN_VERIFY_CONTEXT *ctx,
                             CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV ssl3_mac_verify_final(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            SIGN_VERIFY_CONTEXT *ctx,
                            CK_BYTE *signature, CK_ULONG sig_len);

CK_RV ssl3_master_key_derive(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_MECHANISM *mech,
                             OBJECT *base_key_obj,
                             CK_ATTRIBUTE *attributes,
                             CK_ULONG count, CK_OBJECT_HANDLE *handle);

CK_RV ssl3_key_and_mac_derive(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              CK_MECHANISM *mech,
                              OBJECT *base_key_obj,
                              CK_ATTRIBUTE *attributes, CK_ULONG count);

CK_RV ckm_ssl3_pre_master_key_gen(STDLL_TokData_t *tokdata,
                                  TEMPLATE *tmpl, CK_MECHANISM *mech);


// RSA routines
//
CK_RV rsa_pkcs_encrypt(STDLL_TokData_t *tokdata,
                       SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV rsa_pkcs_decrypt(STDLL_TokData_t *tokdata,
                       SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV rsa_pkcs_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV rsa_pkcs_verify(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *signature, CK_ULONG sig_len);

CK_RV rsa_pkcs_verify_recover(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              CK_BBOOL length_only,
                              SIGN_VERIFY_CONTEXT *ctx,
                              CK_BYTE *signature,
                              CK_ULONG sig_len,
                              CK_BYTE *out_data, CK_ULONG *out_len);

CK_RV rsa_oaep_crypt(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_BBOOL length_only,
                     ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                     CK_ULONG in_data_len, CK_BYTE *out_data,
                     CK_ULONG *out_data_len, CK_BBOOL encrypt);

CK_RV rsa_x509_encrypt(STDLL_TokData_t *tokdata,
                       SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV rsa_x509_decrypt(STDLL_TokData_t *tokdata,
                       SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV rsa_x509_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV rsa_x509_verify(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *signature, CK_ULONG sig_len);

CK_RV rsa_x509_verify_recover(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              CK_BBOOL length_only,
                              SIGN_VERIFY_CONTEXT *ctx,
                              CK_BYTE *signature,
                              CK_ULONG sig_len,
                              CK_BYTE *out_data, CK_ULONG *out_len);

CK_RV rsa_hash_pkcs_sign(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_BBOOL length_only,
                         SIGN_VERIFY_CONTEXT *ctx,
                         CK_BYTE *in_data,
                         CK_ULONG in_data_len,
                         CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV rsa_hash_pkcs_verify(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *in_data,
                           CK_ULONG in_data_len,
                           CK_BYTE *signature, CK_ULONG sig_len);

CK_RV rsa_hash_pkcs_sign_update(STDLL_TokData_t *tokdata,
                                SESSION *sess,
                                SIGN_VERIFY_CONTEXT *ctx,
                                CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV rsa_hash_pkcs_verify_update(STDLL_TokData_t *tokdata,
                                  SESSION *sess,
                                  SIGN_VERIFY_CONTEXT *ctx,
                                  CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV rsa_hash_pkcs_sign_final(STDLL_TokData_t *tokdata,
                               SESSION *sess,
                               CK_BBOOL length_only,
                               SIGN_VERIFY_CONTEXT *ctx,
                               CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV rsa_hash_pkcs_verify_final(STDLL_TokData_t *tokdata,
                                 SESSION *sess,
                                 SIGN_VERIFY_CONTEXT *ctx,
                                 CK_BYTE *signature, CK_ULONG sig_len);

CK_RV rsa_pss_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                   CK_BBOOL length_only,
                   SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                   CK_ULONG in_data_len, CK_BYTE *out_data,
                   CK_ULONG *out_data_len);

CK_RV rsa_hash_pss_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                        CK_BBOOL length_only,
                        SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                        CK_ULONG in_data_len, CK_BYTE *sig,
                        CK_ULONG *sig_len);

CK_RV rsa_hash_pss_update(STDLL_TokData_t *tokdata, SESSION *sess,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV rsa_hash_pss_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only,
                              SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *signature,
                              CK_ULONG *sig_len);

CK_RV rsa_pss_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                     SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                     CK_ULONG in_data_len, CK_BYTE *signature,
                     CK_ULONG sig_len);

CK_RV rsa_hash_pss_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *signature, CK_ULONG sig_len);

CK_RV rsa_hash_pss_verify_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                SIGN_VERIFY_CONTEXT *ctx,
                                CK_BYTE *signature, CK_ULONG sig_len);

CK_RV rsa_format_block(STDLL_TokData_t *tokdata,
                       CK_BYTE *in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data,
                       CK_ULONG out_data_len, CK_ULONG type);

CK_RV rsa_parse_block(CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *out_data,
                      CK_ULONG *out_data_len, CK_ULONG type);

CK_RV get_mgf_mech(CK_RSA_PKCS_MGF_TYPE mgf, CK_MECHANISM_TYPE *mech);

// RSA mechanisms
//
CK_RV ckm_rsa_key_pair_gen(STDLL_TokData_t *tokdata, TEMPLATE *publ_tmpl,
                           TEMPLATE *priv_tmpl);

CK_RV ckm_rsa_encrypt(STDLL_TokData_t *tokdata,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *out_data,
                      CK_ULONG *out_data_len, OBJECT *key_obj);

CK_RV ckm_rsa_decrypt(STDLL_TokData_t *tokdata,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *out_data,
                      CK_ULONG *out_data_len, OBJECT *key_obj);

CK_RV ckm_rsa_compute_priv_exp(STDLL_TokData_t *tokdata, TEMPLATE *tmpl);

CK_RV ckm_rsa_sign(STDLL_TokData_t *tokdata,
                   CK_BYTE *in_data,
                   CK_ULONG in_data_len,
                   CK_BYTE *out_data,
                   CK_ULONG *out_data_len, OBJECT *key_obj);

CK_RV ckm_rsa_verify(STDLL_TokData_t *tokdata,
                     CK_BYTE *in_data,
                     CK_ULONG in_data_len,
                     CK_BYTE *out_data,
                     CK_ULONG out_data_len, OBJECT *key_obj);

// RSA mechanism - EME-OAEP encoding
//
CK_RV encode_eme_oaep(STDLL_TokData_t *tokdata, CK_BYTE *mData, CK_ULONG mLen,
                      CK_BYTE *emData, CK_ULONG modLength,
                      CK_RSA_PKCS_MGF_TYPE mgf, CK_BYTE *hash, CK_ULONG hlen);

CK_RV decode_eme_oaep(STDLL_TokData_t *tokdata, CK_BYTE *emData,
                      CK_ULONG emLen, CK_BYTE *out_data,
                      CK_ULONG *out_data_len, CK_RSA_PKCS_MGF_TYPE mgf,
                      CK_BYTE *hash, CK_ULONG hlen);

CK_RV emsa_pss_encode(STDLL_TokData_t *tokdata,
                      CK_RSA_PKCS_PSS_PARAMS_PTR pssParms, CK_BYTE *in_data,
                      CK_ULONG in_data_len, CK_BYTE *emData,
                      CK_ULONG *modbytes);

CK_RV emsa_pss_verify(STDLL_TokData_t *tokdata,
                      CK_RSA_PKCS_PSS_PARAMS_PTR pssParms, CK_BYTE *in_data,
                      CK_ULONG in_data_len, CK_BYTE *sig, CK_ULONG modbytes);

CK_RV check_pss_params(CK_MECHANISM *mechanism, CK_ULONG);

#ifndef NODSA
// DSA routines
//
CK_RV dsa_sign(STDLL_TokData_t *tokdata,
               SESSION *sess,
               CK_BBOOL length_only,
               SIGN_VERIFY_CONTEXT *ctx,
               CK_BYTE *in_data,
               CK_ULONG in_data_len, CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV dsa_verify(STDLL_TokData_t *tokdata,
                 SESSION *sess,
                 SIGN_VERIFY_CONTEXT *ctx,
                 CK_BYTE *in_data,
                 CK_ULONG in_data_len, CK_BYTE *signature, CK_ULONG sig_len);


// DSA mechanisms
//
CK_RV ckm_dsa_key_pair_gen(STDLL_TokData_t *tokdata, TEMPLATE *publ_tmpl,
                           TEMPLATE *priv_tmpl);

CK_RV ckm_dsa_sign(STDLL_TokData_t *tokdata,
                   CK_BYTE *in_data,   // must be 20 bytes
                   CK_BYTE *signature, // must be 40 bytes
                   OBJECT *priv_key);

CK_RV ckm_dsa_verify(STDLL_TokData_t *tokdata,
                     CK_BYTE *signature,       // must be 40 bytes
                     CK_BYTE *data,    // must be 20 bytes
                     OBJECT *publ_key);

#endif

/* Begin code contributed by Corrent corp. */
// DH routines
//
#ifndef NODH

CK_RV dh_pkcs_derive(STDLL_TokData_t *tokdata,
                     SESSION *sess,
                     CK_MECHANISM *mech,
                     OBJECT *base_key_obj,
                     CK_ATTRIBUTE *pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE *handle);

// DH mechanisms
//
CK_RV ckm_dh_pkcs_derive(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_VOID_PTR other_pubkey,
                         CK_ULONG other_pubkey_len,
                         OBJECT *base_key_obj,
                         CK_BYTE *secret, CK_ULONG *secret_len,
                         CK_MECHANISM_PTR mech);

CK_RV ckm_dh_key_pair_gen(STDLL_TokData_t *tokdata, TEMPLATE *publ_tmpl,
                          TEMPLATE *priv_tmpl);

CK_RV ckm_dh_pkcs_key_pair_gen(STDLL_TokData_t *tokdata,
                               TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl);
#endif
/* End code contributed by Corrent corp. */

CK_RV digest_from_kdf(CK_EC_KDF_TYPE kdf, CK_MECHANISM_TYPE *mech);

CK_RV pkcs_get_keytype(CK_ATTRIBUTE *attrs, CK_ULONG attrs_len,
                       CK_MECHANISM_PTR mech, CK_ULONG *type, CK_ULONG *class);

CK_RV ecdh_get_derived_key_size(CK_ULONG prime_len, CK_BYTE *curve_oid,
                                CK_ULONG curve_oid_len, CK_EC_KDF_TYPE kdf,
                                CK_ULONG key_type, CK_ULONG value_len,
                                CK_ULONG *key_len);

CK_RV ecdh_pkcs_derive(STDLL_TokData_t *tokdata, SESSION *sess,
                 CK_MECHANISM *mech, OBJECT *base_key_obj,
                 CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                 CK_OBJECT_HANDLE *derived_key_obj);

// DES routines - I have to provide two different versions of these
//                because encryption routines are also used internally
//                so we can't assume that external-to-external buffering
//                will be possible and combining them into a single
//                function is messy.
//
CK_RV pk_des_ecb_encrypt(STDLL_TokData_t *tokdata,
                         SESSION *sess, CK_BBOOL length_only,
                         ENCR_DECR_CONTEXT *context,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_ecb_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only,
                      ENCR_DECR_CONTEXT *context,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV pk_des_cbc_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_BBOOL length_only,
                         ENCR_DECR_CONTEXT *context,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only,
                      ENCR_DECR_CONTEXT *context,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_pad_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                          CK_BBOOL length_only,
                          ENCR_DECR_CONTEXT *context,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_pad_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                          CK_BBOOL length_only,
                          ENCR_DECR_CONTEXT *context,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_ecb_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_ecb_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_pad_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                 CK_BBOOL length_only,
                                 ENCR_DECR_CONTEXT *context,
                                 CK_BYTE *in_data, CK_ULONG in_data_len,
                                 CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_pad_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                 CK_BBOOL length_only,
                                 ENCR_DECR_CONTEXT *context,
                                 CK_BYTE *in_data, CK_ULONG in_data_len,
                                 CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_ecb_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_ecb_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_pad_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                CK_BBOOL length_only,
                                ENCR_DECR_CONTEXT *context,
                                CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_cbc_pad_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                CK_BBOOL length_only,
                                ENCR_DECR_CONTEXT *context,
                                CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des_ecb_wrap_key(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BBOOL length_only, CK_MECHANISM *mech,
                       OBJECT *key, OBJECT *encr_key,
                       CK_BYTE *data, CK_ULONG *data_len);


// DES mechanisms
//
CK_RV ckm_des_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl);

CK_RV ckm_des_ecb_encrypt(STDLL_TokData_t *tokdata,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len,
                          OBJECT *key);

CK_RV ckm_des_ecb_decrypt(STDLL_TokData_t *tokdata,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len,
                          OBJECT *key);

CK_RV ckm_des_cbc_encrypt(STDLL_TokData_t *tokdata,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len,
                          CK_BYTE *init_v, OBJECT *key);

CK_RV ckm_des_cbc_decrypt(STDLL_TokData_t *tokdata,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len,
                          CK_BYTE *init_v, OBJECT *key);

CK_RV ckm_des_wrap_format(STDLL_TokData_t *tokdata, CK_BBOOL length_only,
                          CK_BYTE **data, CK_ULONG *data_len);


// DES3 routines
//
CK_RV des3_ecb_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *context,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_ecb_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *context,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *context,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *context,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_pad_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                           CK_BBOOL length_only,
                           ENCR_DECR_CONTEXT *context,
                           CK_BYTE *in_data, CK_ULONG in_data_len,
                           CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_pad_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                           CK_BBOOL length_only,
                           ENCR_DECR_CONTEXT *context,
                           CK_BYTE *in_data, CK_ULONG in_data_len,
                           CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_ecb_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_ecb_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_pad_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                  CK_BBOOL length_only,
                                  ENCR_DECR_CONTEXT *context,
                                  CK_BYTE *in_data, CK_ULONG in_data_len,
                                  CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_pad_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                  CK_BBOOL length_only,
                                  ENCR_DECR_CONTEXT *context,
                                  CK_BYTE *in_data, CK_ULONG in_data_len,
                                  CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_ecb_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *context,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_ecb_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *context,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *context,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *context,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_pad_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                 CK_BBOOL length_only,
                                 ENCR_DECR_CONTEXT *context,
                                 CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cbc_pad_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                 CK_BBOOL length_only,
                                 ENCR_DECR_CONTEXT *context,
                                 CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_mac_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                    CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data, CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_mac_sign_update(STDLL_TokData_t *tokdata, SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV des3_mac_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
                          CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_mac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG out_data_len);

CK_RV des3_mac_verify_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             SIGN_VERIFY_CONTEXT *ctx,
                             CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV des3_mac_verify_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            SIGN_VERIFY_CONTEXT *ctx,
                            CK_BYTE *signature, CK_ULONG signature_len);

CK_RV des3_cmac_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                     CK_BYTE *in_data, CK_ULONG in_data_len,
                     CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cmac_sign_update(STDLL_TokData_t *tokdata, SESSION *sess,
                            SIGN_VERIFY_CONTEXT *ctx,
                            CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV des3_cmac_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
                           CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                       SIGN_VERIFY_CONTEXT *ctx,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG out_data_len);

CK_RV des3_cmac_verify_update(STDLL_TokData_t *tokdata, SESSION *sess,
                              SIGN_VERIFY_CONTEXT *ctx,
                              CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV des3_cmac_verify_final(STDLL_TokData_t *tokdata, SESSION *sess,
                             SIGN_VERIFY_CONTEXT *ctx,
                             CK_BYTE *signature, CK_ULONG signature_len);


// DES3 mechanisms
//
CK_RV ckm_des3_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl);

CK_RV ckm_des3_ecb_encrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                           CK_ULONG in_data_len,
                           CK_BYTE *out_data, CK_ULONG *out_data_len,
                           OBJECT *key);

CK_RV ckm_des3_ecb_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                           CK_ULONG in_data_len,
                           CK_BYTE *out_data, CK_ULONG *out_data_len,
                           OBJECT *key);

CK_RV ckm_des3_cbc_encrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                           CK_ULONG in_data_len,
                           CK_BYTE *out_data, CK_ULONG *out_data_len,
                           CK_BYTE *init_v, OBJECT *key);

CK_RV ckm_des3_cbc_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                           CK_ULONG in_data_len,
                           CK_BYTE *out_data, CK_ULONG *out_data_len,
                           CK_BYTE *init_v, OBJECT *key);

CK_RV des3_ofb_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                       CK_ULONG in_data_len, CK_BYTE *out_data,
                       CK_ULONG *out_data_len);

CK_RV des3_ofb_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                       CK_ULONG in_data_len, CK_BYTE *out_data,
                       CK_ULONG *out_data_len);

CK_RV des3_ofb_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                              CK_ULONG in_data_len, CK_BYTE *out_data,
                              CK_ULONG *out_data_len);

CK_RV des3_ofb_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);


CK_RV des3_ofb_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_ofb_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV des3_cfb_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len,
                       CK_ULONG cfb_len);

CK_RV des3_cfb_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len,
                       CK_ULONG cfb_len);

CK_RV des3_cfb_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len,
                              CK_ULONG cfb_len);

CK_RV des3_cfb_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             CK_ULONG cfb_len);

CK_RV des3_cfb_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len,
                              CK_ULONG cfb_len);

CK_RV des3_cfb_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             CK_ULONG cfb_len);

// AES routines
//
CK_RV aes_ecb_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_ecb_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cbc_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cbc_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cbc_pad_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                          CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cbc_pad_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                          CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_ctr_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_ctr_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_ecb_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_ecb_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cbc_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cbc_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cbc_pad_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                 CK_BBOOL length_only,
                                 ENCR_DECR_CONTEXT *context, CK_BYTE *in_data,
                                 CK_ULONG in_data_len, CK_BYTE *out_data,
                                 CK_ULONG *out_data_len);

CK_RV aes_cbc_pad_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                 CK_BBOOL length_only,
                                 ENCR_DECR_CONTEXT *context, CK_BYTE *in_data,
                                 CK_ULONG in_data_len, CK_BYTE *out_data,
                                 CK_ULONG *out_data_len);

CK_RV aes_ctr_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_ctr_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_xts_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_xts_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_ecb_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_ecb_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cbc_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cbc_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cbc_pad_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                CK_BBOOL length_only,
                                ENCR_DECR_CONTEXT *context, CK_BYTE *out_data,
                                CK_ULONG *out_data_len);

CK_RV aes_cbc_pad_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                CK_BBOOL length_only,
                                ENCR_DECR_CONTEXT *context, CK_BYTE *out_data,
                                CK_ULONG *out_data_len);

CK_RV aes_ctr_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_ctr_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_xts_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_xts_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only, ENCR_DECR_CONTEXT *context,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_mac_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                   CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                   CK_BYTE *in_data, CK_ULONG in_data_len,
                   CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_mac_sign_update(STDLL_TokData_t *tokdata, SESSION *sess,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV aes_mac_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                         CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_mac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                     SIGN_VERIFY_CONTEXT *ctx,
                     CK_BYTE *in_data, CK_ULONG in_data_len,
                     CK_BYTE *out_data, CK_ULONG out_data_len);

CK_RV aes_mac_verify_update(STDLL_TokData_t *tokdata, SESSION *sess,
                            SIGN_VERIFY_CONTEXT *ctx,
                            CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV aes_mac_verify_final(STDLL_TokData_t *tokdata, SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *signature, CK_ULONG signature_len);

CK_RV aes_cmac_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                    CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data, CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cmac_sign_update(STDLL_TokData_t *tokdata, SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV aes_cmac_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
                          CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_cmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG out_data_len);

CK_RV aes_cmac_verify_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             SIGN_VERIFY_CONTEXT *ctx,
                             CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV aes_cmac_verify_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            SIGN_VERIFY_CONTEXT *ctx,
                            CK_BYTE *signature, CK_ULONG signature_len);


// AES mechanisms
//
CK_RV ckm_aes_key_gen(STDLL_TokData_t *, TEMPLATE *tmpl, CK_BBOOL xts);

CK_RV ckm_aes_ecb_encrypt(STDLL_TokData_t *, SESSION *sess, CK_BYTE *in_data,
                          CK_ULONG in_data_len, CK_BYTE *out_data,
                          CK_ULONG *out_data_len, OBJECT *key);

CK_RV ckm_aes_ecb_decrypt(STDLL_TokData_t *, SESSION *sess, CK_BYTE *in_data,
                          CK_ULONG in_data_len, CK_BYTE *out_data,
                          CK_ULONG *out_data_len, OBJECT *key);

CK_RV ckm_aes_cbc_encrypt(STDLL_TokData_t *, SESSION *sess, CK_BYTE *in_data,
                          CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len,
                          CK_BYTE *init_v, OBJECT *key);

CK_RV ckm_aes_cbc_decrypt(STDLL_TokData_t *, SESSION *sess, CK_BYTE *in_data,
                          CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len,
                          CK_BYTE *init_v, OBJECT *key);

CK_RV ckm_aes_ctr_encrypt(STDLL_TokData_t *, CK_BYTE *in_data,
                          CK_ULONG in_data_len, CK_BYTE *out_data,
                          CK_ULONG *out_data_len, CK_BYTE *counterblock,
                          CK_ULONG counter_width, OBJECT *key);

CK_RV ckm_aes_ctr_decrypt(STDLL_TokData_t *, CK_BYTE *in_data,
                          CK_ULONG in_data_len, CK_BYTE *out_data,
                          CK_ULONG *out_data_len, CK_BYTE *counterblock,
                          CK_ULONG counter_width, OBJECT *key);
CK_RV ckm_aes_xts_crypt(STDLL_TokData_t *tokdata,
                        CK_BYTE *in_data,
                        CK_ULONG in_data_len,
                        CK_BYTE *out_data,
                        CK_ULONG *out_data_len,
                        CK_BYTE *tweak, OBJECT *key,
                        CK_BBOOL initial, CK_BBOOL final,
                        CK_BYTE *iv, CK_BBOOL encrypt);

CK_RV aes_xts_cipher(CK_BYTE *in_data, CK_ULONG in_data_len,
                     CK_BYTE *out_data, CK_ULONG *out_data_len,
                     CK_BYTE *tweak, CK_BOOL encrypt, CK_BBOOL initial,
                     CK_BBOOL final, CK_BYTE* iv,
                     CK_RV (*iv_from_tweak)(CK_BYTE *tweak, CK_BYTE* iv,
                                            void * cb_data),
                     CK_RV (*cipher_blocks)(CK_BYTE *in, CK_BYTE *out,
                                            CK_ULONG len, CK_BYTE *iv,
                                            void * cb_data),
                     void *cb_data);

CK_RV ckm_aes_wrap_format(STDLL_TokData_t *, CK_BBOOL length_only,
                          CK_BYTE **data, CK_ULONG *data_len);

CK_RV aes_gcm_init(STDLL_TokData_t *tokdata, SESSION *, ENCR_DECR_CONTEXT *,
                   CK_MECHANISM *, CK_OBJECT_HANDLE, CK_BYTE);

CK_RV aes_gcm_encrypt(STDLL_TokData_t *tokdata, SESSION *, CK_BBOOL,
                      ENCR_DECR_CONTEXT *, CK_BYTE *,
                      CK_ULONG, CK_BYTE *, CK_ULONG *);

CK_RV aes_gcm_encrypt_update(STDLL_TokData_t *tokdata, SESSION *, CK_BBOOL,
                             ENCR_DECR_CONTEXT *,
                             CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);

CK_RV aes_gcm_encrypt_final(STDLL_TokData_t *tokdata, SESSION *, CK_BBOOL,
                            ENCR_DECR_CONTEXT *, CK_BYTE *, CK_ULONG *);

CK_RV aes_gcm_decrypt(STDLL_TokData_t *tokdata, SESSION *, CK_BBOOL,
                      ENCR_DECR_CONTEXT *, CK_BYTE *,
                      CK_ULONG, CK_BYTE *, CK_ULONG *);

CK_RV aes_gcm_decrypt_update(STDLL_TokData_t *tokdata, SESSION *, CK_BBOOL,
                             ENCR_DECR_CONTEXT *,
                             CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *);

CK_RV aes_gcm_decrypt_final(STDLL_TokData_t *tokdata, SESSION *, CK_BBOOL,
                            ENCR_DECR_CONTEXT *, CK_BYTE *, CK_ULONG *);

CK_RV aes_gcm_dup_param(CK_GCM_PARAMS *from, CK_GCM_PARAMS *to);

CK_RV aes_gcm_free_param(CK_GCM_PARAMS *params);

void aes_gcm_param_from_compat(const CK_GCM_PARAMS_COMPAT *from,
                               CK_GCM_PARAMS *to);

CK_RV aes_ofb_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only,
                      ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                      CK_ULONG in_data_len, CK_BYTE *out_data,
                      CK_ULONG *out_data_len);

CK_RV aes_ofb_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             CK_ULONG *out_data_len);

CK_RV aes_ofb_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
                            CK_ULONG *out_data_len);

CK_RV aes_ofb_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV aes_ofb_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             CK_ULONG *out_data_len);

CK_RV aes_ofb_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
                            CK_ULONG *out_data_len);

CK_RV aes_cfb_encrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only,
                      ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                      CK_ULONG in_data_len, CK_BYTE *out_data,
                      CK_ULONG *out_data_len, CK_ULONG cfb_len);

CK_RV aes_cfb_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             CK_ULONG cfb_len);

CK_RV aes_cfb_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
                            CK_ULONG *out_data_len, CK_ULONG cfb_len);

CK_RV aes_cfb_decrypt(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                      CK_BYTE *in_data, CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len,
                      CK_ULONG cfb_len);

CK_RV aes_cfb_decrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             CK_ULONG *out_data_len, CK_ULONG cfb_len);

CK_RV aes_cfb_decrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
                            CK_ULONG *out_data_len, CK_ULONG cfb_len);
CK_RV aes_xts_encrypt(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      CK_BBOOL length_only,
                      ENCR_DECR_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);
CK_RV aes_xts_decrypt(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      CK_BBOOL length_only,
                      ENCR_DECR_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len);

// SHA mechanisms
//

CK_RV sw_sha1_init(DIGEST_CONTEXT *ctx);

CK_RV sw_sha1_hash(DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
                   CK_ULONG in_data_len, CK_BYTE *out_data,
                   CK_ULONG *out_data_len);

CK_RV sha_init(STDLL_TokData_t *tokdata, SESSION *sess, DIGEST_CONTEXT *ctx,
               CK_MECHANISM *mech);

CK_RV sha_hash(STDLL_TokData_t *tokdata, SESSION *sess, CK_BBOOL length_only,
               DIGEST_CONTEXT *ctx, CK_BYTE *in_data, CK_ULONG in_data_len,
               CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV sha_hash_update(STDLL_TokData_t *tokdata, SESSION *sess,
                      DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
                      CK_ULONG in_data_len);

CK_RV sha_hash_final(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_BBOOL length_only, DIGEST_CONTEXT *ctx,
                     CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV hmac_sign_init(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_MECHANISM *mech, CK_OBJECT_HANDLE key);

CK_RV hmac_sign_update(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV hmac_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
                      CK_BYTE *in_data, CK_ULONG *in_data_len);

CK_RV hmac_verify_update(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV hmac_verify_final(STDLL_TokData_t *tokdata, SESSION *sess,
                        CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV hmac_verify_init(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_MECHANISM *mech, CK_OBJECT_HANDLE key);

CK_RV sha_hmac_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess, CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV sha_hmac_verify(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *signature, CK_ULONG sig_len);

//adding the hmac secret key generation here
CK_RV ckm_generic_secret_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl);

#if !(NOMD2)
// MD2 mechanisms
//
CK_RV md2_hash(STDLL_TokData_t *tokdata, SESSION *sess, CK_BBOOL length_only,
               DIGEST_CONTEXT *ctx,
               CK_BYTE *in_data, CK_ULONG in_data_len,
               CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV md2_hash_update(STDLL_TokData_t *tokdata, SESSION *sess,
                      DIGEST_CONTEXT *ctx,
                      CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV md2_hash_final(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_BBOOL length_only, DIGEST_CONTEXT *ctx,
                     CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV md2_hmac_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess, CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV md2_hmac_verify(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *signature, CK_ULONG sig_len);

CK_RV ckm_md2_update(STDLL_TokData_t *tokdata, MD2_CONTEXT *context,
                     CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV ckm_md2_final(STDLL_TokData_t *tokdata, MD2_CONTEXT *context,
                    CK_BYTE *out_data, CK_ULONG out_data_len);

void ckm_md2_transform(STDLL_TokData_t *tokdata, CK_BYTE *state,
                       CK_BYTE *checksum, CK_BYTE *block);
#endif


// MD5 mechanisms
//
CK_RV md5_hash(STDLL_TokData_t *tokdata, SESSION *sess,
               CK_BBOOL length_only, DIGEST_CONTEXT *ctx,
               CK_BYTE *in_data, CK_ULONG in_data_len,
               CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV md5_hash_update(STDLL_TokData_t *tokdata, SESSION *sess,
                      DIGEST_CONTEXT *ctx,
                      CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV md5_hash_final(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_BBOOL length_only, DIGEST_CONTEXT *ctx,
                     CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV md5_hmac_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess, CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV md5_hmac_verify(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *signature, CK_ULONG sig_len);

CK_RV sw_md5_init(DIGEST_CONTEXT *ctx);

CK_RV sw_md5_hash(DIGEST_CONTEXT *ctx, CK_BYTE *in_data,
                  CK_ULONG in_data_len, CK_BYTE *out_data,
                  CK_ULONG *out_data_len);

CK_RV md5_init(STDLL_TokData_t *tokdata, SESSION *sess, DIGEST_CONTEXT *ctx,
               CK_MECHANISM *mech);

//Elliptic curve (EC) mechanisms
//
CK_RV ckm_ec_key_pair_gen(STDLL_TokData_t *tokdata, TEMPLATE *publ_tmpl,
                          TEMPLATE *priv_tmpl);

CK_RV ckm_ec_sign(STDLL_TokData_t *tokdata,
                  SESSION *sess,
                  CK_BYTE *in_data,
                  CK_ULONG in_data_len,
                  CK_BYTE *out_data,
                  CK_ULONG *out_data_len, OBJECT *key_obj);

CK_RV ec_sign(STDLL_TokData_t *tokdata,
              SESSION *sess,
              CK_BBOOL length_only,
              SIGN_VERIFY_CONTEXT *ctx,
              CK_BYTE *in_data,
              CK_ULONG in_data_len,
              CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV ckm_ec_verify(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data,
                    CK_ULONG out_data_len, OBJECT *key_obj);

CK_RV ec_verify(STDLL_TokData_t *tokdata,
                SESSION *sess,
                SIGN_VERIFY_CONTEXT *ctx,
                CK_BYTE *in_data,
                CK_ULONG in_data_len, CK_BYTE *signature, CK_ULONG sig_len);

CK_RV ec_hash_sign(STDLL_TokData_t *tokdata,
                   SESSION *sess,
                   CK_BBOOL length_only,
                   SIGN_VERIFY_CONTEXT *ctx,
                   CK_BYTE *in_data,
                   CK_ULONG in_data_len,
                   CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV ec_hash_sign_update(STDLL_TokData_t *tokdata,
                          SESSION *sess,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV ec_hash_sign_final(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_BBOOL length_only,
                         SIGN_VERIFY_CONTEXT *ctx,
                         CK_BYTE *signature, CK_ULONG *sig_len);

CK_RV ec_hash_verify(STDLL_TokData_t *tokdata,
                     SESSION *sess,
                     SIGN_VERIFY_CONTEXT *ctx,
                     CK_BYTE *in_data,
                     CK_ULONG in_data_len,
                     CK_BYTE *signature, CK_ULONG sig_len);

CK_RV ec_hash_verify_update(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            SIGN_VERIFY_CONTEXT *ctx,
                            CK_BYTE *in_data, CK_ULONG in_data_len);


CK_RV ec_hash_verify_final(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *signature, CK_ULONG sig_len);

CK_RV ec_uncompress_public_key(CK_BYTE *curve, CK_ULONG curve_len,
                               CK_BYTE *pubkey, CK_ULONG pubkey_len,
                               CK_ULONG privkey_len,
                               CK_BYTE *out_pubkey, CK_ULONG *out_len);

CK_RV ec_point_from_priv_key(CK_BYTE *parms, CK_ULONG parms_len,
                             CK_BYTE *d, CK_ULONG d_len,
                             CK_BYTE **point, CK_ULONG *point_len);

int ec_point_from_public_data(const CK_BYTE *data, CK_ULONG data_len,
                              CK_ULONG prime_len, CK_BBOOL allow_raw,
                              CK_BBOOL *allocated, CK_BYTE **ec_point,
                              CK_ULONG *ec_point_len);

CK_RV attach_shm(STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id);
CK_RV detach_shm(STDLL_TokData_t *tokdata, CK_BBOOL ignore_ref_count);

//get keytype
CK_RV get_keytype(STDLL_TokData_t *tokdata, CK_OBJECT_HANDLE hkey,
                  CK_KEY_TYPE *keytype);

//lock and unlock routines
CK_RV XProcLock(STDLL_TokData_t *tokdata);
CK_RV XProcUnLock(STDLL_TokData_t *tokdata);
CK_RV XThreadLock(STDLL_TokData_t *tokdata);
CK_RV XThreadUnLock(STDLL_TokData_t *tokdata);
CK_RV CreateXProcLock(char *tokname, STDLL_TokData_t *tokdata);
CK_RV XProcLock_Init(STDLL_TokData_t *tokdata);
void CloseXProcLock(STDLL_TokData_t *tokdata);

//list mechanisms
//
void mechanism_list_transformations(CK_MECHANISM_TYPE_PTR mech_arr_ptr,
                                    CK_ULONG_PTR count_ptr);

// encryption manager routines
//
CK_RV encr_mgr_init(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    ENCR_DECR_CONTEXT *ctx,
                    CK_ULONG operation,
                    CK_MECHANISM *mech, CK_OBJECT_HANDLE key_handle,
                    CK_BBOOL checkpolicy);

CK_RV encr_mgr_cleanup(STDLL_TokData_t *tokdata, SESSION *sess,
                       ENCR_DECR_CONTEXT *ctx);

CK_RV encr_mgr_encrypt(STDLL_TokData_t *tokdata,
                       SESSION *sess, CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV encr_mgr_encrypt_final(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV encr_mgr_encrypt_update(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV encr_mgr_reencrypt_single(STDLL_TokData_t *tokdata, SESSION *sess,
                                ENCR_DECR_CONTEXT *decr_ctx,
                                CK_MECHANISM *decr_mech,
                                CK_OBJECT_HANDLE decr_key,
                                ENCR_DECR_CONTEXT *encr_ctx,
                                CK_MECHANISM *encr_mech,
                                CK_OBJECT_HANDLE encr_key,
                                CK_BYTE *in_data, CK_ULONG in_data_len,
                                CK_BYTE *out_data, CK_ULONG *out_data_len);

// decryption manager routines
//
CK_RV decr_mgr_init(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    ENCR_DECR_CONTEXT *ctx,
                    CK_ULONG operation,
                    CK_MECHANISM *mech, CK_OBJECT_HANDLE key_handle,
                    CK_BBOOL checkpolicy);

CK_RV decr_mgr_cleanup(STDLL_TokData_t *tokdata, SESSION *sess,
                       ENCR_DECR_CONTEXT *ctx);

CK_RV decr_mgr_decrypt(STDLL_TokData_t *tokdata,
                       SESSION *sess, CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV decr_mgr_decrypt_final(STDLL_TokData_t *tokdata,
                             SESSION *sess, CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV decr_mgr_decrypt_update(STDLL_TokData_t *tokdata,
                              SESSION *sess, CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *ctx,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV decr_mgr_update_des_ecb(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV decr_mgr_update_des_cbc(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV decr_mgr_update_des3_ecb(STDLL_TokData_t *tokdata, SESSION *sess,
                               CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV decr_mgr_update_des3_cbc(STDLL_TokData_t *tokdata, SESSION *sess,
                               CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *out_data, CK_ULONG *out_data_len);

// digest manager routines
//
CK_RV digest_mgr_cleanup(STDLL_TokData_t *tokdata, SESSION *sess,
                         DIGEST_CONTEXT *ctx);

CK_RV digest_mgr_init(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      DIGEST_CONTEXT *ctx, CK_MECHANISM *mech,
                      CK_BBOOL checkpolicy);

CK_RV digest_mgr_digest(STDLL_TokData_t *tokdata,
                        SESSION *sess, CK_BBOOL length_only,
                        DIGEST_CONTEXT *ctx,
                        CK_BYTE *data, CK_ULONG data_len,
                        CK_BYTE *hash, CK_ULONG *hash_len);

CK_RV digest_mgr_digest_update(STDLL_TokData_t *tokdata,
                               SESSION *sess,
                               DIGEST_CONTEXT *ctx,
                               CK_BYTE *data, CK_ULONG data_len);

CK_RV digest_mgr_digest_key(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            DIGEST_CONTEXT *ctx, CK_OBJECT_HANDLE key_handle);

CK_RV digest_mgr_digest_final(STDLL_TokData_t *tokdata,
                              SESSION *sess, CK_BBOOL length_only,
                              DIGEST_CONTEXT *ctx,
                              CK_BYTE *hash, CK_ULONG *hash_len);


// key manager routines
//
CK_RV key_mgr_generate_key(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           CK_MECHANISM *mech,
                           CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                           CK_OBJECT_HANDLE *key_handle);

CK_RV key_mgr_generate_key_pair(STDLL_TokData_t *tokdata,
                                SESSION *sess,
                                CK_MECHANISM *mech,
                                CK_ATTRIBUTE *publ_tmpl, CK_ULONG publ_count,
                                CK_ATTRIBUTE *priv_tmpl, CK_ULONG priv_count,
                                CK_OBJECT_HANDLE *publ_key_handle,
                                CK_OBJECT_HANDLE *priv_key_handle);

CK_RV key_mgr_get_private_key_type(CK_BYTE *keydata,
                                   CK_ULONG keylen, CK_KEY_TYPE *keytype);

CK_RV key_mgr_derive_key(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_MECHANISM *mech,
                         CK_OBJECT_HANDLE base_key,
                         CK_OBJECT_HANDLE *derived_key,
                         CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);

CK_RV key_mgr_wrap_key(STDLL_TokData_t *tokdata,
                       SESSION *sess,
                       CK_BBOOL length_only,
                       CK_MECHANISM *mech,
                       CK_OBJECT_HANDLE h_wrapping_key,
                       CK_OBJECT_HANDLE h_key,
                       CK_BYTE *wrapped_key, CK_ULONG *wrapped_key_len);

CK_RV key_mgr_unwrap_key(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_MECHANISM *mech,
                         CK_ATTRIBUTE *pTemplate,
                         CK_ULONG ulCount,
                         CK_BYTE *wrapped_key,
                         CK_ULONG wrapped_key_len,
                         CK_OBJECT_HANDLE unwrapping_key,
                         CK_OBJECT_HANDLE *unwrapped_key);

CK_RV key_mgr_derive_prolog(SESSION *sess,
                            CK_ATTRIBUTE *attributes,
                            CK_ULONG attrcount,
                            CK_OBJECT_HANDLE base_key,
                            OBJECT *base_key_obj,
                            CK_BYTE *base_key_value,
                            CK_KEY_TYPE base_key_type,
                            ATTRIBUTE_PARSE_LIST *parselist, CK_ULONG plcount);


// signature manager routines
//
CK_RV sign_mgr_init(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_MECHANISM *mech,
                    CK_BBOOL recover_mode, CK_OBJECT_HANDLE key_handle,
                    CK_BBOOL checkpolicy);

CK_RV sign_mgr_cleanup(STDLL_TokData_t *tokdata, SESSION *sess,
                       SIGN_VERIFY_CONTEXT *ctx);

CK_RV sign_mgr_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV sign_mgr_sign_recover(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            CK_BBOOL length_only,
                            SIGN_VERIFY_CONTEXT *ctx,
                            CK_BYTE *in_data,
                            CK_ULONG in_data_len,
                            CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV sign_mgr_sign_final(STDLL_TokData_t *tokdata,
                          SESSION *sess,
                          CK_BBOOL length_only,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV sign_mgr_sign_update(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *in_data, CK_ULONG in_data_len);

// signature verify manager routines
//
CK_RV verify_mgr_init(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_MECHANISM *mech,
                      CK_BBOOL recover_mode, CK_OBJECT_HANDLE key_handle,
                      CK_BBOOL checkpolicy);

CK_RV verify_mgr_cleanup(STDLL_TokData_t *tokdata, SESSION *sess,
                         SIGN_VERIFY_CONTEXT *ctx);

CK_RV verify_mgr_verify(STDLL_TokData_t *tokdata,
                        SESSION *sess,
                        SIGN_VERIFY_CONTEXT *ctx,
                        CK_BYTE *in_data,
                        CK_ULONG in_data_len,
                        CK_BYTE *signature, CK_ULONG sig_len);

CK_RV verify_mgr_verify_recover(STDLL_TokData_t *tokdata,
                                SESSION *sess,
                                CK_BBOOL length_only,
                                SIGN_VERIFY_CONTEXT *ctx,
                                CK_BYTE *signature,
                                CK_ULONG sig_len,
                                CK_BYTE *out_data, CK_ULONG *out_len);

CK_RV verify_mgr_verify_update(STDLL_TokData_t *tokdata,
                               SESSION *sess,
                               SIGN_VERIFY_CONTEXT *ctx,
                               CK_BYTE *in_data, CK_ULONG in_data_len);

CK_RV verify_mgr_verify_final(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              SIGN_VERIFY_CONTEXT *ctx,
                              CK_BYTE *signature, CK_ULONG sig_len);


// session manager routines
//
CK_RV session_mgr_close_all_sessions(STDLL_TokData_t *tokdata);
CK_RV session_mgr_close_session(STDLL_TokData_t *tokdata, CK_SESSION_HANDLE);
CK_RV session_mgr_new(STDLL_TokData_t *tokdata, CK_ULONG flags,
                      CK_SLOT_ID slot_id, CK_SESSION_HANDLE_PTR phSession);
SESSION *session_mgr_find(STDLL_TokData_t *tokdata, CK_SESSION_HANDLE handle);
SESSION *session_mgr_find_reset_error(STDLL_TokData_t *tokdata,
                                      CK_SESSION_HANDLE handle);
void session_mgr_put(STDLL_TokData_t *tokdata, SESSION *session);
CK_RV session_mgr_login_all(STDLL_TokData_t *tokdata, CK_USER_TYPE user_type);
CK_RV session_mgr_logout_all(STDLL_TokData_t *tokdata);

CK_BBOOL session_mgr_readonly_session_exists(STDLL_TokData_t *tokdata);
CK_BBOOL session_mgr_so_session_exists(STDLL_TokData_t *tokdata);
CK_BBOOL session_mgr_user_session_exists(STDLL_TokData_t *tokdata);
CK_BBOOL session_mgr_public_session_exists(STDLL_TokData_t *tokdata);

CK_RV session_mgr_get_op_state(STDLL_TokData_t *tokdata, SESSION *sess,
                               CK_BBOOL length_only,
                               CK_BYTE *data, CK_ULONG *data_len);

CK_RV session_mgr_set_op_state(STDLL_TokData_t *tokdata, SESSION *sess,
                               CK_OBJECT_HANDLE encr_key,
                               CK_OBJECT_HANDLE auth_key, CK_BYTE *data,
                               CK_ULONG data_len);
CK_RV session_mgr_cancel(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_FLAGS flags);
CK_BBOOL pin_expired(CK_SESSION_INFO *, CK_FLAGS);
CK_BBOOL pin_locked(CK_SESSION_INFO *, CK_FLAGS);
void set_login_flags(CK_USER_TYPE, CK_FLAGS_32 *);

#define CONTEXT_TYPE_DIGEST     1
#define CONTEXT_TYPE_SIGN       2
#define CONTEXT_TYPE_VERIFY     3
#define CONTEXT_TYPE_ENCRYPT    4
#define CONTEXT_TYPE_DECRYPT    5

CK_RV session_mgr_iterate_session_ops(STDLL_TokData_t *tokdata,
                                      SESSION *session,
                                      CK_RV (*cb)(STDLL_TokData_t *tokdata,
                                                  SESSION *session,
                                                  CK_ULONG ctx_type,
                                                  CK_MECHANISM *mech,
                                                  CK_OBJECT_HANDLE key,
                                                  CK_BYTE *context,
                                                  CK_ULONG context_len,
                                                  CK_BBOOL init_pending,
                                                  CK_BBOOL pkey_active,
                                                  CK_BBOOL recover,
                                                  void *private),
                                      void *private);

// object manager routines
//
CK_RV object_mgr_add(STDLL_TokData_t *tokdata,
                     SESSION *sess,
                     CK_ATTRIBUTE *pTemplate,
                     CK_ULONG ulCount, CK_OBJECT_HANDLE *handle);

CK_RV object_mgr_add_to_map(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            OBJECT *obj,
                            unsigned long obj_handle,
                            CK_OBJECT_HANDLE *handle);

void object_mgr_add_to_shm(OBJECT *obj, LW_SHM_TYPE *shm);
CK_RV object_mgr_del_from_shm(OBJECT *obj, LW_SHM_TYPE *shm);
CK_RV object_mgr_get_shm_entry_for_obj(STDLL_TokData_t *tokdata, OBJECT *obj,
                                       TOK_OBJ_ENTRY **entry);
CK_RV object_mgr_check_shm(STDLL_TokData_t *tokdata, OBJECT *obj,
                           OBJ_LOCK_TYPE lock_type);
CK_RV object_mgr_search_shm_for_obj(TOK_OBJ_ENTRY *list,
                                    CK_ULONG lo,
                                    CK_ULONG hi,
                                    OBJECT *obj, CK_ULONG *index);
CK_RV object_mgr_update_from_shm(STDLL_TokData_t *tokdata);
CK_RV object_mgr_update_publ_tok_obj_from_shm(STDLL_TokData_t *tokdata);
CK_RV object_mgr_update_priv_tok_obj_from_shm(STDLL_TokData_t *tokdata);

CK_RV object_mgr_copy(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      CK_ATTRIBUTE *pTemplate,
                      CK_ULONG ulCount,
                      CK_OBJECT_HANDLE old_obj, CK_OBJECT_HANDLE *new_obj);

CK_RV object_mgr_create_final(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              OBJECT *obj, CK_OBJECT_HANDLE *handle);

CK_RV object_mgr_create_skel(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_ATTRIBUTE *pTemplate,
                             CK_ULONG ulCount,
                             CK_ULONG mode,
                             CK_ULONG class, CK_ULONG subclass, OBJECT **obj);

CK_RV object_mgr_destroy_object(STDLL_TokData_t *tokdata,
                                SESSION *sess, CK_OBJECT_HANDLE handle);

CK_RV object_mgr_destroy_token_objects(STDLL_TokData_t *tokdata);

CK_RV object_mgr_find_in_map_nocache(STDLL_TokData_t *tokdata,
                                     CK_OBJECT_HANDLE handle, OBJECT **ptr,
                                     OBJ_LOCK_TYPE lock_type);

CK_RV object_mgr_find_in_map1(STDLL_TokData_t *tokdata,
                              CK_OBJECT_HANDLE handle, OBJECT **ptr,
                              OBJ_LOCK_TYPE lock_type);

CK_RV object_mgr_find_in_map2(STDLL_TokData_t *tokdata,
                              OBJECT *ptr, CK_OBJECT_HANDLE *handle);

CK_RV object_mgr_find_init(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);

CK_RV object_mgr_find_build_list(SESSION *sess,
                                 CK_ATTRIBUTE *pTemplate,
                                 CK_ULONG ulCount,
                                 DL_NODE *obj_list, CK_BBOOL public_only);

CK_RV object_mgr_find_final(SESSION *sess);

CK_RV object_mgr_get_attribute_values(STDLL_TokData_t *tokdata,
                                      SESSION *sess,
                                      CK_OBJECT_HANDLE handle,
                                      CK_ATTRIBUTE *pTemplate,
                                      CK_ULONG ulCount);

CK_RV object_mgr_get_object_size(STDLL_TokData_t *tokdata,
                                 CK_OBJECT_HANDLE handle, CK_ULONG *size);

CK_BBOOL object_mgr_purge_session_objects(STDLL_TokData_t *tokdata,
                                          SESSION *sess, SESS_OBJ_TYPE type);

CK_BBOOL object_mgr_purge_token_objects(STDLL_TokData_t *tokdata);

CK_BBOOL object_mgr_purge_private_token_objects(STDLL_TokData_t *tokdata);

CK_RV object_mgr_restore_obj(STDLL_TokData_t *tokdata, CK_BYTE *data,
                             OBJECT *oldObj, const char *fname);

CK_RV object_mgr_restore_obj_withSize(STDLL_TokData_t *tokdata,
                                      CK_BYTE *data, OBJECT *oldObj,
                                      int data_size,
                                      const char *fname);

CK_RV object_mgr_save_token_object(STDLL_TokData_t *tokdata, OBJECT *obj);

CK_RV object_mgr_set_attribute_values(STDLL_TokData_t *tokdata,
                                      SESSION *sess,
                                      CK_OBJECT_HANDLE handle,
                                      CK_ATTRIBUTE *pTemplate,
                                      CK_ULONG ulCount);

// SAB FIXME FIXME
CK_BBOOL object_mgr_purge_map(STDLL_TokData_t *tokdata,
                              SESSION *sess, SESS_OBJ_TYPE type);

CK_RV object_put(STDLL_TokData_t *tokdata, OBJECT *obj, CK_BBOOL unlock);

CK_RV obj_mgr_reencipher_secure_key(STDLL_TokData_t *tokdata, OBJECT *obj,
                                    CK_RV (*reenc)(CK_BYTE *sec_key,
                                                   CK_BYTE *reenc_sec_key,
                                                   CK_ULONG sec_key_len,
                                                   void *private),
                                    void *private);

CK_RV obj_mgr_reencipher_secure_key_finalize(STDLL_TokData_t *tokdata,
                                             OBJECT *obj,
                                             CK_BBOOL is_blob_new_mk_cb(
                                                 STDLL_TokData_t *tokdata,
                                                 OBJECT *obj,
                                                 CK_BYTE *sec_key,
                                                 CK_ULONG sec_key_len,
                                                 void *cb_private),
                                             void *cb_private);

CK_RV obj_mgr_reencipher_secure_key_cancel(STDLL_TokData_t *tokdata,
                                           OBJECT *obj);

CK_RV obj_mgr_iterate_key_objects(STDLL_TokData_t *tokdata,
                                  CK_BBOOL session_objects,
                                  CK_BBOOL token_objects,
                                  CK_BBOOL(*filter)(STDLL_TokData_t *tokdata,
                                                    OBJECT *obj,
                                                    void *filter_data),
                                  void *filter_data,
                                  CK_RV (*cb)(STDLL_TokData_t *tokdata,
                                              OBJECT *obj, void *cb_data),
                                  void *cb_data, CK_BBOOL syslog,
                                  const char *msg);

/* structures used to hold arguments to callback functions triggered by either
 * bt_for_each_node or bt_node_free */
struct find_args {
    int done;
    OBJECT *obj;
    CK_OBJECT_HANDLE map_handle;
};

struct find_by_name_args {
    int done;
    char *name;
};

struct find_build_list_args {
    CK_ATTRIBUTE *pTemplate;
    SESSION *sess;
    CK_ULONG ulCount;
    CK_BBOOL hw_feature;
    CK_BBOOL hidden_object;
    CK_BBOOL public_only;
};

struct purge_args {
    SESSION *sess;
    SESS_OBJ_TYPE type;
};

struct update_tok_obj_args {
    TOK_OBJ_ENTRY *entries;
    CK_ULONG_32 *num_entries;
    struct btree *t;
};


// object routines
//
CK_RV object_create(STDLL_TokData_t *tokdata,
                    CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount, OBJECT **obj);

CK_RV object_create_skel(STDLL_TokData_t *tokdata,
                         CK_ATTRIBUTE *pTemplate,
                         CK_ULONG ulCount,
                         CK_ULONG mode,
                         CK_ULONG class, CK_ULONG subclass, OBJECT **key);

CK_RV object_copy(STDLL_TokData_t *tokdata, SESSION *sess,
                  CK_ATTRIBUTE *pTemplate,
                  CK_ULONG ulCount, OBJECT *old_obj, OBJECT **new_obj);

CK_RV object_flatten(OBJECT *obj, CK_BYTE **data, CK_ULONG *len);

void object_free(OBJECT *obj);

void call_object_free(void *ptr);

CK_RV object_get_attribute_values(OBJECT *obj,
                                  CK_ATTRIBUTE *pTemplate, CK_ULONG count);

CK_ULONG object_get_size(OBJECT *obj);

CK_RV object_restore_withSize(struct policy *policy, CK_BYTE *data,
                              OBJECT **obj, CK_BBOOL replace, int data_size,
                              const char *fname);

CK_RV object_set_attribute_values(STDLL_TokData_t *tokdata, SESSION *sess,
                                  OBJECT *obj,
                                  CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount);

CK_BBOOL object_is_modifiable(OBJECT *obj);
CK_BBOOL object_is_copyable(OBJECT *obj);
CK_BBOOL object_is_destroyable(OBJECT *obj);
CK_BBOOL object_is_private(OBJECT *obj);
CK_BBOOL object_is_public(OBJECT *obj);
CK_BBOOL object_is_token_object(OBJECT *obj);
CK_BBOOL object_is_session_object(OBJECT *obj);
CK_BBOOL object_is_extractable(OBJECT *obj);
CK_BBOOL object_is_pkey_extractable(OBJECT *obj);
CK_BBOOL object_is_attr_bound(OBJECT *obj);

CK_RV object_init_lock(OBJECT *obj);
CK_RV object_destroy_lock(OBJECT *obj);
CK_RV object_lock(OBJECT *obj, OBJ_LOCK_TYPE type);
CK_RV object_unlock(OBJECT *obj);

CK_RV object_init_ex_data_lock(OBJECT *obj);
CK_RV object_destroy_ex_data_lock(OBJECT *obj);
CK_RV object_ex_data_lock(OBJECT *obj, OBJ_LOCK_TYPE type);
CK_RV object_ex_data_unlock(OBJECT *obj);

// object attribute template routines
//

CK_RV template_add_attributes(TEMPLATE *tmpl,
                              CK_ATTRIBUTE *attr, CK_ULONG ulCount);

CK_RV template_add_default_attributes(TEMPLATE *tmpl,
                                      TEMPLATE *basetmpl,
                                      CK_ULONG class,
                                      CK_ULONG subclass, CK_ULONG mode);

CK_BBOOL template_attribute_find(TEMPLATE *tmpl,
                                 CK_ATTRIBUTE_TYPE type, CK_ATTRIBUTE **attr);

CK_RV template_attribute_get_ulong(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
                                      CK_ULONG *value);
CK_RV template_attribute_get_bool(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
                                  CK_BBOOL *value);
CK_RV template_attribute_get_non_empty(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type,
                                       CK_ATTRIBUTE **attr);

void template_attribute_find_multiple(TEMPLATE *tmpl,
                                      ATTRIBUTE_PARSE_LIST *parselist,
                                      CK_ULONG plcount);

CK_BBOOL template_check_exportability(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type);

CK_RV template_check_required_attributes(TEMPLATE *tmpl,
                                         CK_ULONG class,
                                         CK_ULONG subclass, CK_ULONG mode);

CK_RV template_check_required_base_attributes(TEMPLATE *tmpl, CK_ULONG mode);

CK_BBOOL template_compare(CK_ATTRIBUTE *t1, CK_ULONG ulCount, TEMPLATE *t2);

CK_RV template_copy(TEMPLATE *dest, TEMPLATE *src);

CK_RV template_flatten(TEMPLATE *tmpl, CK_BYTE *dest);

CK_RV template_free(TEMPLATE *tmpl);

CK_BBOOL template_get_class(TEMPLATE *tmpl,
                            CK_ULONG *class, CK_ULONG *subclass);

CK_ULONG template_get_count(TEMPLATE *tmpl);

CK_ULONG template_get_size(TEMPLATE *tmpl);

CK_ULONG template_get_compressed_size(TEMPLATE *tmpl);

CK_RV template_set_default_common_attributes(TEMPLATE *tmpl);

CK_RV template_merge(TEMPLATE *dest, TEMPLATE **src);

CK_RV  template_remove_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type);

CK_RV template_update_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr);

CK_RV template_unflatten(TEMPLATE **tmpl, CK_BYTE *data, CK_ULONG count);

CK_RV template_unflatten_withSize(TEMPLATE **new_tmpl,
                                  CK_BYTE *buf, CK_ULONG count, int buf_size);

CK_RV template_validate_attribute(STDLL_TokData_t *tokdata,
                                  TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr,
                                  CK_ULONG class,
                                  CK_ULONG subclass, CK_ULONG mode);

CK_RV template_validate_attributes(STDLL_TokData_t *tokdata,
                                   TEMPLATE *tmpl,
                                   CK_ULONG class,
                                   CK_ULONG subclass, CK_ULONG mode);

CK_RV template_validate_base_attribute(TEMPLATE *tmpl,
                                       CK_ATTRIBUTE *attr, CK_ULONG mode);
#ifdef DEBUG
void dump_template(TEMPLATE *tmpl);
#define TRACE_DEBUG_DUMPTEMPL(x) dump_template(x)
#else
#define TRACE_DEBUG_DUMPTEMPL(...)
#endif


// DATA OBJECT ROUTINES
//
CK_RV data_object_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV data_object_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV data_object_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                     CK_ULONG mode);

// PROFILE OBJECT ROUTINES
CK_RV profile_object_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV profile_object_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV profile_object_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                        CK_ULONG mode);

// CERTIFICATE ROUTINES
//
CK_RV cert_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV cert_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV cert_validate_attribute(STDLL_TokData_t *tokdata,
                              TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                              CK_ULONG mode);

CK_RV cert_x509_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV cert_x509_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV cert_x509_validate_attribute(STDLL_TokData_t *tokdata,
                                   TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                   CK_ULONG mode);
CK_RV cert_vendor_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV cert_vendor_validate_attribute(STDLL_TokData_t *tokdata,
                                     TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                     CK_ULONG mode);

//
// KEY ROUTINES
//

CK_RV key_object_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV key_object_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV key_object_validate_attribute(TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                    CK_ULONG mode);
CK_BBOOL key_object_is_mechanism_allowed(TEMPLATE *tmpl,
                                         CK_MECHANISM_TYPE mech);
CK_BBOOL key_object_wrap_template_matches(TEMPLATE *wrap_tmpl, TEMPLATE *tmpl);
CK_RV key_object_apply_template_attr(TEMPLATE *unwrap_tmpl,
                                     CK_ATTRIBUTE_TYPE attr_type,
                                     CK_ATTRIBUTE_PTR attrs,
                                     CK_ULONG attrs_count,
                                     CK_ATTRIBUTE_PTR *new_attrs,
                                     CK_ULONG *new_attrs_count);

CK_RV publ_key_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV publ_key_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV publ_key_validate_attribute(STDLL_TokData_t *tokdata,
                                  TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV publ_key_get_spki(TEMPLATE *tmpl, CK_ULONG keytype, CK_BBOOL length_only,
                        CK_BYTE **data, CK_ULONG *data_len);

CK_RV priv_key_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV priv_key_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV priv_key_unwrap(TEMPLATE *tmpl, CK_ULONG keytype, CK_BYTE *data,
                      CK_ULONG data_len);
CK_RV priv_key_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode);

CK_BBOOL secret_key_check_exportability(CK_ATTRIBUTE_TYPE type);
CK_RV secret_key_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV secret_key_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV secret_key_unwrap(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                        CK_ULONG keytype, CK_BYTE *data, CK_ULONG data_len,
                        CK_BBOOL fromend);
CK_RV secret_key_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                    CK_ATTRIBUTE *attr, CK_ULONG mode);

// rsa routines
//
CK_RV rsa_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV rsa_publ_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV rsa_publ_set_default_attributes(TEMPLATE *tmpl, TEMPLATE *basetmpl,
                                      CK_ULONG mode);
CK_RV rsa_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                        CK_BYTE **data, CK_ULONG *data_len);
CK_BBOOL rsa_priv_check_exportability(CK_ATTRIBUTE_TYPE type);
CK_RV rsa_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV rsa_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV rsa_priv_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV rsa_priv_wrap_get_data(TEMPLATE *tmpl, CK_BBOOL length_only,
                             CK_BYTE **data, CK_ULONG *data_len);
CK_RV rsa_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len);
CK_RV rsa_priv_unwrap_get_data(TEMPLATE *tmpl,
                              CK_BYTE *data, CK_ULONG total_length);

// dsa routines
//
CK_RV dsa_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dsa_publ_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dsa_publ_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV dsa_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                        CK_BYTE **data, CK_ULONG *data_len);
CK_BBOOL dsa_priv_check_exportability(CK_ATTRIBUTE_TYPE type);
CK_RV dsa_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dsa_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dsa_priv_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                  CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV dsa_priv_wrap_get_data(TEMPLATE *tmpl, CK_BBOOL length_only,
                             CK_BYTE **data, CK_ULONG *data_len);
CK_RV dsa_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len);
CK_RV dsa_priv_unwrap_get_data(TEMPLATE *tmpl,
                              CK_BYTE *data, CK_ULONG total_length);

// ecdsa routines
//
CK_RV ecdsa_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ecdsa_publ_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ecdsa_publ_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                    CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV ec_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                       CK_BYTE **data, CK_ULONG *data_len);
CK_BBOOL ecdsa_priv_check_exportability(CK_ATTRIBUTE_TYPE type);
CK_RV ecdsa_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ecdsa_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ecdsa_priv_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                    CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV ecdsa_priv_wrap_get_data(TEMPLATE *tmpl, CK_BBOOL length_only,
                               CK_BYTE **data, CK_ULONG *data_len);
CK_RV ecdsa_priv_unwrap_get_data(TEMPLATE *tmpl, CK_BYTE *data,
                                 CK_ULONG data_len);
CK_RV ec_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len);

// Dilithium routines
//
CK_RV ibm_dilithium_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ibm_dilithium_publ_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ibm_dilithium_publ_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                            CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV ibm_dilithium_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                                  CK_BYTE **data, CK_ULONG *data_len);
CK_RV ibm_dilithium_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ibm_dilithium_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ibm_dilithium_priv_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                            CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV ibm_dilithium_priv_wrap_get_data(TEMPLATE *tmpl, CK_BBOOL length_only,
                                       CK_BYTE **data, CK_ULONG *data_len);
CK_RV ibm_dilithium_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data,
                                CK_ULONG total_length, CK_BBOOL add_value);
CK_RV ibm_dilithium_priv_unwrap_get_data(TEMPLATE *tmpl,
                                         CK_BYTE *data, CK_ULONG total_length,
                                         CK_BBOOL add_value);

// Kyber routines
//
CK_RV ibm_kyber_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ibm_kyber_publ_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ibm_kyber_publ_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                        CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV ibm_kyber_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                              CK_BYTE **data, CK_ULONG *data_len);
CK_RV ibm_kyber_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ibm_kyber_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV ibm_kyber_priv_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                        CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV ibm_kyber_priv_wrap_get_data(TEMPLATE *tmpl, CK_BBOOL length_only,
                                   CK_BYTE **data, CK_ULONG *data_len);
CK_RV ibm_kyber_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data,
                            CK_ULONG total_length, CK_BBOOL add_value);
CK_RV ibm_kyber_priv_unwrap_get_data(TEMPLATE *tmpl,
                                     CK_BYTE *data, CK_ULONG total_length,
                                     CK_BBOOL add_value);

// PQC helper routines
//
CK_RV ibm_pqc_publ_get_spki(TEMPLATE *tmpl, CK_KEY_TYPE keytype,
                            CK_BBOOL length_only,
                            CK_BYTE **data, CK_ULONG *data_len);
CK_RV ibm_pqc_priv_wrap_get_data(TEMPLATE *tmpl, CK_KEY_TYPE keytype,
                                 CK_BBOOL length_only,
                                 CK_BYTE **data, CK_ULONG *data_len);
CK_RV ibm_pqc_priv_unwrap(TEMPLATE *tmpl, CK_KEY_TYPE keytype, CK_BYTE *data,
                          CK_ULONG total_length, CK_BBOOL add_value);
CK_RV ibm_pqc_priv_unwrap_get_data(TEMPLATE *tmpl, CK_KEY_TYPE keytype,
                                   CK_BYTE *data, CK_ULONG total_length,
                                   CK_BBOOL add_value);
const struct pqc_oid *ibm_pqc_get_keyform_mode(TEMPLATE *tmpl,
                                               CK_MECHANISM_TYPE mech);
CK_RV ibm_pqc_add_keyform_mode(TEMPLATE *tmpl, const struct pqc_oid *oid,
                               CK_MECHANISM_TYPE mech);

// diffie-hellman routines
//
CK_RV dh_publ_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dh_publ_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dh_publ_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV dh_publ_get_spki(TEMPLATE *tmpl, CK_BBOOL length_only,
                       CK_BYTE **data, CK_ULONG *data_len);
CK_BBOOL dh_priv_check_exportability(CK_ATTRIBUTE_TYPE type);
CK_RV dh_priv_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dh_priv_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dh_priv_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV dh_priv_wrap_get_data(TEMPLATE *tmpl,
                            CK_BBOOL length_only, CK_BYTE **data,
                            CK_ULONG *data_len);
CK_RV dh_priv_unwrap_get_data(TEMPLATE *tmpl,
                              CK_BYTE *data, CK_ULONG total_length);
CK_RV dh_priv_unwrap(TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len);

// Generic secret key routines
CK_RV generic_secret_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV generic_secret_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV generic_secret_validate_attribute(STDLL_TokData_t *tokdata,
                                        TEMPLATE *tmpl, CK_ATTRIBUTE *attr,
                                        CK_ULONG mode);
CK_RV generic_secret_wrap_get_data(TEMPLATE *tmpl, CK_BBOOL length_only,
                                   CK_BYTE **data, CK_ULONG *data_len);
CK_RV generic_secret_unwrap(TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len,
                            CK_BBOOL fromend);

// DES routines
CK_RV des_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_BBOOL des_check_weak_key(CK_BYTE *key);
CK_RV des_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV des_unwrap(STDLL_TokData_t *tokdata, TEMPLATE *tmpl, CK_BYTE *data,
                 CK_ULONG data_len, CK_BBOOL fromend);
CK_RV des_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                             CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV des_wrap_get_data(TEMPLATE *tmpl, CK_BBOOL length_only, CK_BYTE **data,
                        CK_ULONG *data_len);

// DES2 routines
CK_RV des2_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV des2_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV des2_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                              CK_ATTRIBUTE *attr, CK_ULONG mode);

// DES3 routines
CK_RV des3_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV des3_set_default_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV des3_unwrap(STDLL_TokData_t *tokdata, TEMPLATE *tmpl, CK_BYTE *data,
                  CK_ULONG data_len, CK_BBOOL fromend);
CK_RV des3_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                              CK_ATTRIBUTE *attr, CK_ULONG mode);
CK_RV des3_wrap_get_data(TEMPLATE *tmpl, CK_BBOOL length_only, CK_BYTE **data,
                         CK_ULONG *data_len);

// AES routines
CK_RV aes_check_required_attributes(TEMPLATE *tmpl, CK_ULONG mode);
CK_RV aes_set_default_attributes(TEMPLATE *tmpl, TEMPLATE *basetmpl,
                                 CK_ULONG mode, CK_BBOOL xts);
CK_RV aes_unwrap(STDLL_TokData_t *tokdata, TEMPLATE *tmpl, CK_BYTE *data,
                 CK_ULONG data_len, CK_BBOOL fromend, CK_BBOOL xts);
CK_RV aes_validate_attribute(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                             CK_ATTRIBUTE *attr, CK_ULONG mode, CK_BBOOL xts);
CK_RV aes_wrap_get_data(TEMPLATE *tmpl, CK_BBOOL length_only, CK_BYTE **data,
                        CK_ULONG *data_len);

// modular math routines
//
CK_RV mp_subtract(CK_BYTE *bigint, CK_ULONG val, CK_ULONG len);

CK_RV mp_mult(CK_BYTE *bigint_a, CK_ULONG a_len,
              CK_BYTE *bigint_b, CK_ULONG b_len,
              CK_BYTE *bigint_c, CK_ULONG c_len,
              CK_BYTE *result, CK_ULONG *result_len);

CK_RV mp_exp(CK_BYTE *bigint_a, CK_ULONG a_len,
             CK_BYTE *bigint_b, CK_ULONG b_len,
             CK_BYTE *bigint_c, CK_ULONG c_len,
             CK_BYTE *result, CK_ULONG *result_len);

// ASN.1 routines
//
CK_ULONG ber_encode_INTEGER(CK_BBOOL length_only,
                            CK_BYTE **ber_int,
                            CK_ULONG *ber_int_len,
                            CK_BYTE *data, CK_ULONG data_len);

CK_RV ber_decode_INTEGER(CK_BYTE *ber_int,
                         CK_BYTE **data,
                         CK_ULONG *data_len, CK_ULONG *field_len);

CK_RV ber_decode_BIT_STRING(CK_BYTE *str,
                            CK_BYTE **data,
                            CK_ULONG *data_len, CK_ULONG *field_len);

CK_RV ber_encode_OCTET_STRING(CK_BBOOL length_only,
                              CK_BYTE **str,
                              CK_ULONG *str_len,
                              CK_BYTE *data, CK_ULONG data_len);

CK_RV ber_decode_OCTET_STRING(CK_BYTE *str,
                              CK_BYTE **data,
                              CK_ULONG *data_len, CK_ULONG *field_len);

CK_RV ber_encode_SEQUENCE(CK_BBOOL length_only,
                          CK_BYTE **seq,
                          CK_ULONG *seq_len,
                          CK_BYTE *data, CK_ULONG data_len);

CK_RV ber_decode_SEQUENCE(CK_BYTE *seq,
                          CK_BYTE **data,
                          CK_ULONG *data_len, CK_ULONG *field_len);

CK_RV ber_encode_PrivateKeyInfo(CK_BBOOL length_only,
                                CK_BYTE **data,
                                CK_ULONG *data_len,
                                const CK_BYTE *algorithm_id,
                                const CK_ULONG algorithm_id_len,
                                CK_BYTE *priv_key, CK_ULONG priv_key_len);

CK_RV ber_decode_PrivateKeyInfo(CK_BYTE *data,
                                CK_ULONG data_len,
                                CK_BYTE **algorithm_id,
                                CK_ULONG *alg_len, CK_BYTE **priv_key);

CK_RV ber_decode_SPKI(CK_BYTE *spki, CK_BYTE **alg_oid, CK_ULONG *alg_oid_len,
                      CK_BYTE **param, CK_ULONG *param_len,
                      CK_BYTE **key, CK_ULONG *key_len);

CK_RV ber_encode_RSAPrivateKey(CK_BBOOL length_only,
                               CK_BYTE **data,
                               CK_ULONG *data_len,
                               CK_ATTRIBUTE *modulus,
                               CK_ATTRIBUTE *publ_exp,
                               CK_ATTRIBUTE *priv_exp,
                               CK_ATTRIBUTE *prime1,
                               CK_ATTRIBUTE *prime2,
                               CK_ATTRIBUTE *exponent1,
                               CK_ATTRIBUTE *exponent2,
                               CK_ATTRIBUTE *coeff);

CK_RV ber_decode_RSAPrivateKey(CK_BYTE *data,
                               CK_ULONG data_len,
                               CK_ATTRIBUTE **modulus,
                               CK_ATTRIBUTE **publ_exp,
                               CK_ATTRIBUTE **priv_exp,
                               CK_ATTRIBUTE **prime1,
                               CK_ATTRIBUTE **prime2,
                               CK_ATTRIBUTE **exponent1,
                               CK_ATTRIBUTE **exponent2,
                               CK_ATTRIBUTE **coeff);

CK_RV ber_encode_RSAPublicKey(CK_BBOOL length_only, CK_BYTE **data,
                              CK_ULONG *data_len, CK_ATTRIBUTE *modulus,
                              CK_ATTRIBUTE *publ_exp);

CK_RV ber_decode_RSAPublicKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **modulus,
                              CK_ATTRIBUTE **publ_exp);

CK_RV der_encode_ECPrivateKey(CK_BBOOL length_only,
                              CK_BYTE **data,
                              CK_ULONG *data_len,
                              CK_ATTRIBUTE *params,
                              CK_ATTRIBUTE *point,
                              CK_ATTRIBUTE *pubkey);

CK_RV der_decode_ECPrivateKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **params,
                              CK_ATTRIBUTE **pub_key,
                              CK_ATTRIBUTE **priv_key);

CK_RV ber_encode_ECPublicKey(CK_BBOOL length_only, CK_BYTE **data,
                             CK_ULONG *data_len, CK_ATTRIBUTE *params,
                             CK_ATTRIBUTE *point);

CK_RV der_decode_ECPublicKey(CK_BYTE *data,
                             CK_ULONG data_len,
                             CK_ATTRIBUTE **params, CK_ATTRIBUTE **point);

CK_RV ber_encode_DSAPrivateKey(CK_BBOOL length_only,
                               CK_BYTE **data,
                               CK_ULONG *data_len,
                               CK_ATTRIBUTE *prime1,
                               CK_ATTRIBUTE *prime2,
                               CK_ATTRIBUTE *base, CK_ATTRIBUTE *priv_key);

CK_RV ber_decode_DSAPrivateKey(CK_BYTE *data,
                               CK_ULONG data_len,
                               CK_ATTRIBUTE **prime,
                               CK_ATTRIBUTE **subprime,
                               CK_ATTRIBUTE **base, CK_ATTRIBUTE **priv_key);

CK_RV ber_encode_DSAPublicKey(CK_BBOOL length_only, CK_BYTE **data,
                              CK_ULONG *data_len, CK_ATTRIBUTE *prime,
                              CK_ATTRIBUTE *subprime, CK_ATTRIBUTE *base,
                              CK_ATTRIBUTE *value);

CK_RV ber_decode_DSAPublicKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **prime,
                              CK_ATTRIBUTE **subprime,
                              CK_ATTRIBUTE **base,
                              CK_ATTRIBUTE **value);

CK_RV ber_encode_DHPrivateKey(CK_BBOOL length_only,
                              CK_BYTE **data,
                              CK_ULONG *data_len,
                              CK_ATTRIBUTE *prime,
                              CK_ATTRIBUTE *base, CK_ATTRIBUTE *priv_key);

CK_RV ber_decode_DHPrivateKey(CK_BYTE *data,
                              CK_ULONG data_len,
                              CK_ATTRIBUTE **prime,
                              CK_ATTRIBUTE **base, CK_ATTRIBUTE **priv_key);

CK_RV ber_encode_DHPublicKey(CK_BBOOL length_only, CK_BYTE **data,
                             CK_ULONG *data_len, CK_ATTRIBUTE *prime,
                             CK_ATTRIBUTE *base, CK_ATTRIBUTE *value);

CK_RV ber_decode_DHPublicKey(CK_BYTE *data,
                             CK_ULONG data_len,
                             CK_ATTRIBUTE **prime,
                             CK_ATTRIBUTE **base,
                             CK_ATTRIBUTE **value);

CK_RV ber_decode_ECDHPrivateKey(CK_BYTE *data,
                                CK_ULONG data_len,
                                CK_ATTRIBUTE **ecparam,
                                CK_ATTRIBUTE **pub_key,
                                CK_ATTRIBUTE **priv_key);

CK_RV ber_encode_IBM_DilithiumPublicKey(CK_BBOOL length_only,
                                        CK_BYTE **data, CK_ULONG *data_len,
                                        const CK_BYTE *oid, CK_ULONG oid_len,
                                        CK_ATTRIBUTE *rho, CK_ATTRIBUTE *t1);

CK_RV ber_decode_IBM_DilithiumPublicKey(CK_BYTE *data,
                                        CK_ULONG data_len,
                                        CK_ATTRIBUTE **rho_attr,
                                        CK_ATTRIBUTE **t1_attr,
                                        CK_ATTRIBUTE **value_attr,
                                        const struct pqc_oid **oid);

CK_RV ber_encode_IBM_DilithiumPrivateKey(CK_BBOOL length_only,
                                         CK_BYTE **data,
                                         CK_ULONG *data_len,
                                         const CK_BYTE *oid, CK_ULONG oid_len,
                                         CK_ATTRIBUTE *rho,
                                         CK_ATTRIBUTE *seed,
                                         CK_ATTRIBUTE *tr,
                                         CK_ATTRIBUTE *s1,
                                         CK_ATTRIBUTE *s2,
                                         CK_ATTRIBUTE *t0,
                                         CK_ATTRIBUTE *t1);

CK_RV ber_decode_IBM_DilithiumPrivateKey(CK_BYTE *data,
                                         CK_ULONG data_len,
                                         CK_ATTRIBUTE **rho,
                                         CK_ATTRIBUTE **seed,
                                         CK_ATTRIBUTE **tr,
                                         CK_ATTRIBUTE **s1,
                                         CK_ATTRIBUTE **s2,
                                         CK_ATTRIBUTE **t0,
                                         CK_ATTRIBUTE **t1,
                                         CK_ATTRIBUTE **value,
                                         const struct pqc_oid **oid);

CK_RV ber_encode_IBM_KyberPublicKey(CK_BBOOL length_only,
                                    CK_BYTE **data, CK_ULONG *data_len,
                                    const CK_BYTE *oid, CK_ULONG oid_len,
                                    CK_ATTRIBUTE *pk);

CK_RV ber_decode_IBM_KyberPublicKey(CK_BYTE *data,
                                    CK_ULONG data_len,
                                    CK_ATTRIBUTE **pk_attr,
                                    CK_ATTRIBUTE **value_attr,
                                    const struct pqc_oid **oid);

CK_RV ber_encode_IBM_KyberPrivateKey(CK_BBOOL length_only,
                                     CK_BYTE **data,
                                     CK_ULONG *data_len,
                                     const CK_BYTE *oid, CK_ULONG oid_len,
                                     CK_ATTRIBUTE *sk,
                                     CK_ATTRIBUTE *pk);

CK_RV ber_decode_IBM_KyberPrivateKey(CK_BYTE *data,
                                     CK_ULONG data_len,
                                     CK_ATTRIBUTE **sk,
                                     CK_ATTRIBUTE **pk,
                                     CK_ATTRIBUTE **value,
                                     const struct pqc_oid **oid);

typedef CK_RV (*t_rsa_encrypt)(STDLL_TokData_t *, CK_BYTE *in_data,
                               CK_ULONG in_data_len, CK_BYTE *out_data,
                               OBJECT *key_obj);
typedef CK_RV (*t_rsa_decrypt)(STDLL_TokData_t *, CK_BYTE *in_data,
                               CK_ULONG in_data_len, CK_BYTE *out_data,
                               OBJECT *key_obj);

struct openssl_ex_data {
    EVP_PKEY *pkey;
};

void openssl_free_ex_data(OBJECT *obj, void *ex_data, size_t ex_data_len);
CK_RV openssl_get_ex_data(OBJECT *obj, void **ex_data, size_t ex_data_len,
                          CK_BBOOL (*need_wr_lock)(OBJECT *obj,
                                                   void *ex_data,
                                                   size_t ex_data_len),
                          void (*ex_data_free)(struct _OBJECT *obj,
                                               void *ex_data,
                                               size_t ex_data_len));

CK_RV openssl_specific_rsa_keygen(TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl);
CK_RV openssl_specific_rsa_encrypt(STDLL_TokData_t *, CK_BYTE *in_data,
                                   CK_ULONG in_data_len,
                                   CK_BYTE *out_data, OBJECT *key_obj);
CK_RV openssl_specific_rsa_decrypt(STDLL_TokData_t *, CK_BYTE *in_data,
                                   CK_ULONG in_data_len,
                                   CK_BYTE *out_data, OBJECT *key_obj);
CK_RV openssl_specific_rsa_pkcs_decrypt(STDLL_TokData_t *, CK_BYTE *,
                                        CK_ULONG, CK_BYTE *, CK_ULONG *,
                                        OBJECT *, t_rsa_decrypt);
CK_RV openssl_specific_rsa_pkcs_encrypt(STDLL_TokData_t *, CK_BYTE *,
                                        CK_ULONG, CK_BYTE *, CK_ULONG *,
                                        OBJECT *, t_rsa_encrypt);
CK_RV openssl_specific_rsa_pkcs_sign(STDLL_TokData_t *, SESSION *, CK_BYTE *,
                                     CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *,
                                     t_rsa_decrypt);
CK_RV openssl_specific_rsa_pkcs_verify(STDLL_TokData_t *tokdata, SESSION *,
                                       CK_BYTE *, CK_ULONG, CK_BYTE *,
                                       CK_ULONG, OBJECT *, t_rsa_encrypt);
CK_RV openssl_specific_rsa_pkcs_verify_recover(STDLL_TokData_t *tokdata,
                                               CK_BYTE *, CK_ULONG, CK_BYTE *,
                                               CK_ULONG *, OBJECT *,
                                               t_rsa_encrypt);
CK_RV openssl_specific_rsa_pss_sign(STDLL_TokData_t *, SESSION *,
                                    SIGN_VERIFY_CONTEXT *, CK_BYTE *, CK_ULONG,
                                    CK_BYTE *, CK_ULONG *, t_rsa_decrypt);
CK_RV openssl_specific_rsa_pss_verify(STDLL_TokData_t *, SESSION *,
                                      SIGN_VERIFY_CONTEXT *, CK_BYTE *,
                                      CK_ULONG, CK_BYTE *, CK_ULONG,
                                      t_rsa_encrypt);
CK_RV openssl_specific_rsa_x509_encrypt(STDLL_TokData_t *tokdata, CK_BYTE *,
                                        CK_ULONG, CK_BYTE *, CK_ULONG *,
                                        OBJECT *, t_rsa_encrypt);
CK_RV openssl_specific_rsa_x509_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *,
                                        CK_ULONG, CK_BYTE *, CK_ULONG *,
                                        OBJECT *, t_rsa_decrypt);
CK_RV openssl_specific_rsa_x509_sign(STDLL_TokData_t *tokdata, CK_BYTE *,
                                     CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *,
                                     t_rsa_decrypt);
CK_RV openssl_specific_rsa_x509_verify(STDLL_TokData_t *tokdata, CK_BYTE *,
                                       CK_ULONG, CK_BYTE *, CK_ULONG, OBJECT *,
                                       t_rsa_encrypt);
CK_RV openssl_specific_rsa_x509_verify_recover(STDLL_TokData_t *tokdata,
                                               CK_BYTE *, CK_ULONG, CK_BYTE *,
                                               CK_ULONG *, OBJECT *,
                                               t_rsa_encrypt);
CK_RV openssl_specific_rsa_oaep_encrypt(STDLL_TokData_t *, ENCR_DECR_CONTEXT *,
                                        CK_BYTE *, CK_ULONG, CK_BYTE *,
                                        CK_ULONG *, CK_BYTE *, CK_ULONG,
                                        t_rsa_encrypt);
CK_RV openssl_specific_rsa_oaep_decrypt(STDLL_TokData_t *, ENCR_DECR_CONTEXT *,
                                        CK_BYTE *, CK_ULONG, CK_BYTE *,
                                        CK_ULONG *, CK_BYTE *, CK_ULONG,
                                        t_rsa_decrypt);

CK_RV openssl_make_ec_key_from_template(TEMPLATE *template, EVP_PKEY **pkey);
CK_RV openssl_specific_ec_generate_keypair(STDLL_TokData_t *tokdata,
                                           TEMPLATE *publ_tmpl,
                                           TEMPLATE *priv_tmpl);
CK_RV openssl_specific_ec_sign(STDLL_TokData_t *tokdata,  SESSION *sess,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *out_data, CK_ULONG *out_data_len,
                               OBJECT *key_obj);
CK_RV openssl_specific_ec_verify(STDLL_TokData_t *tokdata,
                                 SESSION *sess,
                                 CK_BYTE *in_data,
                                 CK_ULONG in_data_len,
                                 CK_BYTE *signature,
                                 CK_ULONG signature_len, OBJECT *key_obj);
CK_RV openssl_specific_ecdh_pkcs_derive(STDLL_TokData_t *tokdata,
                                        CK_BYTE *priv_bytes,
                                        CK_ULONG priv_length,
                                        CK_BYTE *pub_bytes,
                                        CK_ULONG pub_length,
                                        CK_BYTE *secret_value,
                                        CK_ULONG *secret_value_len,
                                        CK_BYTE *oid, CK_ULONG oid_length);

CK_RV openssl_specific_sha_init(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                CK_MECHANISM *mech);
CK_RV openssl_specific_sha(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                           CK_BYTE *in_data, CK_ULONG in_data_len,
                           CK_BYTE *out_data, CK_ULONG *out_data_len);
CK_RV openssl_specific_sha_update(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                  CK_BYTE *in_data, CK_ULONG in_data_len);
CK_RV openssl_specific_sha_final(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                 CK_BYTE *out_data, CK_ULONG *out_data_len);

CK_RV openssl_specific_aes_ecb(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               CK_ULONG *out_data_len,
                               OBJECT *key, CK_BYTE encrypt);
CK_RV openssl_specific_aes_cbc(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               CK_ULONG *out_data_len,
                               OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt);
CK_RV openssl_specific_aes_ctr(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               CK_ULONG *out_data_len,
                               OBJECT *key,
                               CK_BYTE *counterblock,
                               CK_ULONG counter_width, CK_BYTE encrypt);
CK_RV openssl_specific_aes_ofb(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               OBJECT *key,
                               CK_BYTE *init_v, CK_BYTE encrypt);
CK_RV openssl_specific_aes_cfb(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               OBJECT *key,
                               CK_BYTE *init_v, CK_ULONG cfb_len,
                               CK_BYTE encrypt);
CK_RV openssl_specific_aes_gcm_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                    ENCR_DECR_CONTEXT *ctx, CK_MECHANISM *mech,
                                    CK_OBJECT_HANDLE hkey, CK_BYTE encrypt);
CK_RV openssl_specific_aes_gcm(STDLL_TokData_t *tokdata, SESSION *sess,
                               ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                               CK_ULONG in_data_len, CK_BYTE *out_data,
                               CK_ULONG *out_data_len, CK_BYTE encrypt);
CK_RV openssl_specific_aes_gcm_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                      ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                                      CK_ULONG in_data_len, CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE encrypt);
CK_RV openssl_specific_aes_gcm_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                     ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
                                     CK_ULONG *out_data_len, CK_BYTE encrypt);
CK_RV openssl_specific_aes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                               CK_ULONG message_len, OBJECT *key, CK_BYTE *mac);
CK_RV openssl_specific_aes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                                CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                                CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx);
CK_RV openssl_specific_aes_xts(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *out_data, CK_ULONG *out_data_len,
                               OBJECT *key_obj, CK_BYTE *tweak,
                               CK_BOOL encrypt, CK_BBOOL initial,
                               CK_BBOOL final, CK_BYTE* iv);

CK_RV openssl_specific_des_ecb(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               CK_ULONG *out_data_len,
                               OBJECT *key, CK_BYTE encrypt);
CK_RV openssl_specific_des_cbc(STDLL_TokData_t *tokdata,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *out_data,
                               CK_ULONG *out_data_len,
                               OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt);
CK_RV openssl_specific_tdes_ecb(STDLL_TokData_t *tokdata,
                                CK_BYTE *in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE *out_data,
                                CK_ULONG *out_data_len,
                                OBJECT *key, CK_BYTE encrypt);
CK_RV openssl_specific_tdes_cbc(STDLL_TokData_t *tokdata,
                                CK_BYTE *in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE *out_data,
                                CK_ULONG *out_data_len,
                                OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt);
CK_RV openssl_specific_tdes_ofb(STDLL_TokData_t *tokdata,
                                CK_BYTE *in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE *out_data,
                                OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt);
CK_RV openssl_specific_tdes_cfb(STDLL_TokData_t *tokdata,
                                CK_BYTE *in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE *out_data,
                                OBJECT *key,
                                CK_BYTE *init_v, CK_ULONG cfb_len,
                                CK_BYTE encrypt);
CK_RV openssl_specific_tdes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                                CK_ULONG message_len, OBJECT *key, CK_BYTE *mac);
CK_RV openssl_specific_tdes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                                 CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                                 CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx);

CK_RV openssl_specific_hmac_init(STDLL_TokData_t *tokdata,
                                 SIGN_VERIFY_CONTEXT *ctx,
                                 CK_MECHANISM_PTR mech,
                                 CK_OBJECT_HANDLE Hkey);
CK_RV openssl_specific_hmac(SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                            CK_ULONG in_data_len, CK_BYTE *signature,
                            CK_ULONG *sig_len, CK_BBOOL sign);
CK_RV openssl_specific_hmac_update(SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                                   CK_ULONG in_data_len, CK_BBOOL sign);
CK_RV openssl_specific_hmac_final(SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *signature,
                                  CK_ULONG *sig_len, CK_BBOOL sign);

#include "tok_spec_struct.h"
extern token_spec_t token_specific;


/* CKA_HIDDEN will be used to filter return results on a C_FindObjects call.
 * Used for objects internal to a token for management of that token */
#define CKA_HIDDEN              CKA_VENDOR_DEFINED + 0x01000000

#endif
