/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki CCA token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
 *
 * Author: Kent E. Yoder <yoder1@us.ibm.com>
 *
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
#include "msg.h"

#if (LEEDS_BUILD)
#pragma options align=packed
#endif


extern char * pk_dir;
// global variables
//
extern CK_BBOOL  initialized;
extern char *card_function_names[];
extern char *total_function_names[];

extern MECH_LIST_ELEMENT  mech_list[];
extern CK_ULONG           mech_list_len;

extern pthread_mutex_t  native_mutex;

extern MUTEX    pkcs_mutex, obj_list_mutex, sess_list_mutex, login_mutex;

extern struct btree sess_btree;
extern struct btree sess_obj_btree;
extern struct btree priv_token_obj_btree;
extern struct btree publ_token_obj_btree;
extern struct btree object_map_btree;

extern CK_BYTE master_key[MASTER_KEY_SIZE];

extern CK_BYTE so_pin_md5[MD5_HASH_SIZE];
extern CK_BYTE user_pin_md5[MD5_HASH_SIZE];

extern CK_BYTE default_user_pin_sha[SHA1_HASH_SIZE];
extern CK_BYTE default_so_pin_sha[SHA1_HASH_SIZE];
extern CK_BYTE default_so_pin_md5[MD5_HASH_SIZE];

extern LW_SHM_TYPE *global_shm;

extern TOKEN_DATA        *nv_token_data;
extern CK_SLOT_INFO       slot_info;

// extern CK_ULONG next_object_handle;
// extern CK_ULONG next_session_handle;

extern CK_ULONG  ro_session_count;

extern CK_STATE  global_login_state;


extern CK_BYTE            ber_AlgIdRSAEncryption[];
extern CK_ULONG           ber_AlgIdRSAEncryptionLen;
extern CK_BYTE            ber_rsaEncryption[];
extern CK_ULONG           ber_rsaEncryptionLen;
extern CK_BYTE            ber_idDSA[];
extern CK_ULONG           ber_idDSALen;

extern CK_BYTE   ber_md2WithRSAEncryption[];
extern CK_ULONG  ber_md2WithRSAEncryptionLen;
extern CK_BYTE   ber_md4WithRSAEncryption[];
extern CK_ULONG  ber_md4WithRSAEncryptionLen;
extern CK_BYTE   ber_md5WithRSAEncryption[];
extern CK_ULONG  ber_md5WithRSAEncryptionLen;
extern CK_BYTE   ber_sha1WithRSAEncryption[];
extern CK_ULONG  ber_sha1WithRSAEncryptionLen;
extern CK_BYTE   ber_AlgMd2[];
extern CK_ULONG  ber_AlgMd2Len;
extern CK_BYTE   ber_AlgMd5[];
extern CK_ULONG  ber_AlgMd5Len;
extern CK_BYTE   ber_AlgSha1[];
extern CK_ULONG  ber_AlgSha1Len;
extern CK_BYTE   ber_AlgSha256[];
extern CK_ULONG  ber_AlgSha256Len;


extern CK_ULONG           des_weak_count;
extern CK_ULONG           des_semi_weak_count;
extern CK_ULONG           des_possibly_weak_count;
extern CK_BYTE            des_weak_keys[4][8];
extern CK_BYTE            des_semi_weak_keys[12][8];
extern CK_BYTE            des_possibly_weak_keys[48][8];

extern struct ST_FCN_LIST   function_list;

extern CK_C_INITIALIZE_ARGS cinit_args;

CK_ULONG long_reverse( CK_ULONG x );


// VACPP C runtime initialization/cleanup entry points
//
int  _CRT_init(void);
int  _CRT_term(void);


CK_RV DummyFunction( CK_SLOT_ID   slot_id, int arg );

// General-purpose functions
//
CK_RV C_Initialize          ( CK_VOID_PTR              pInitArgs           );
CK_RV C_Finalize            ( CK_VOID_PTR              pReserved           );
CK_RV C_GetInfo             ( CK_INFO_PTR              pInfo               );
CK_RV C_GetFunctionList     ( CK_FUNCTION_LIST_PTR_PTR ppFunctionList      );

// Slot and token management functions
//
CK_RV C_GetSlotList         ( CK_BBOOL                 tokenPresent,
                              CK_SLOT_ID_PTR           pSlotList,
                              CK_ULONG_PTR             pulCount            );

CK_RV C_GetSlotInfo         ( CK_SLOT_ID               slotID,
                              CK_SLOT_INFO_PTR         pInfo               );

CK_RV C_GetTokenInfo        ( CK_SLOT_ID               slotID,
                              CK_TOKEN_INFO_PTR        pInfo               );

CK_RV C_WaitForSlotEvent    ( CK_FLAGS                 flags,
                              CK_SLOT_ID_PTR           pSlot,
                              CK_VOID_PTR              pReserved           );

CK_RV C_GetMechanismList    ( CK_SLOT_ID               slotID,
                              CK_MECHANISM_TYPE_PTR    pMechanismList,
                              CK_ULONG_PTR             pulCount            );

CK_RV C_GetMechanismInfo    ( CK_SLOT_ID               slotID,
                              CK_MECHANISM_TYPE        type,
                              CK_MECHANISM_INFO_PTR    pInfo               );

CK_RV C_InitToken           ( CK_SLOT_ID               slotID,
                              CK_CHAR_PTR              pPin,
                              CK_ULONG                 ulPinLen,
                              CK_CHAR_PTR              pLabel              );

CK_RV C_InitPIN             ( CK_SESSION_HANDLE        hSession,
                              CK_CHAR_PTR              pPin,
                              CK_ULONG                 ulPinLen            );

CK_RV C_SetPIN              ( CK_SESSION_HANDLE        hSession,
                              CK_CHAR_PTR              pOldPin,
                              CK_ULONG                 ulOldLen,
                              CK_CHAR_PTR              pNewPin,
                              CK_ULONG                 ulNewLen            );

// Session management functions
//
CK_RV C_OpenSession         ( CK_SLOT_ID               slotID,
                              CK_FLAGS                 flags,
                              CK_VOID_PTR              pApplication,
                              CK_NOTIFY                Notify,
                              CK_SESSION_HANDLE_PTR    phSession            );

CK_RV C_CloseSession        ( CK_SESSION_HANDLE        hSession             );

CK_RV C_CloseAllSessions    ( CK_SLOT_ID               slotID               );

CK_RV C_GetSessionInfo      ( CK_SESSION_HANDLE        hSession,
                              CK_SESSION_INFO_PTR      pInfo                );

CK_RV C_GetOperationState   ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pOperationState,
                              CK_ULONG_PTR             pulOperationStateLen );

CK_RV C_SetOperationState   ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pOperationState,
                              CK_ULONG                 ulOperationStateLen,
                              CK_OBJECT_HANDLE         hEncryptionKey,
                              CK_OBJECT_HANDLE         hAuthenticationKey   );

CK_RV C_Login               ( CK_SESSION_HANDLE        hSession,
                              CK_USER_TYPE             userType,
                              CK_CHAR_PTR              pPin,
                              CK_ULONG                 uPinLen              );

CK_RV C_Logout              ( CK_SESSION_HANDLE        hSession             );


// Object management functions
//
CK_RV C_CreateObject        ( CK_SESSION_HANDLE        hSession,
                              CK_ATTRIBUTE_PTR         pTemplate,
                              CK_ULONG                 ulCount,
                              CK_OBJECT_HANDLE_PTR     phObject             );

CK_RV C_CopyObject          ( CK_SESSION_HANDLE        hSession,
                              CK_OBJECT_HANDLE         hObject,
                              CK_ATTRIBUTE_PTR         pTemplate,
                              CK_ULONG                 ulCount,
                              CK_OBJECT_HANDLE_PTR     phNewObject          );

CK_RV C_DestroyObject       ( CK_SESSION_HANDLE        hSession,
                              CK_OBJECT_HANDLE         hObject              );

CK_RV C_GetObjectSize       ( CK_SESSION_HANDLE        hSession,
                              CK_OBJECT_HANDLE         hObject,
                              CK_ULONG_PTR             pulSize              );

CK_RV C_GetAttributeValue   ( CK_SESSION_HANDLE        hSession,
                              CK_OBJECT_HANDLE         hObject,
                              CK_ATTRIBUTE_PTR         pTemplate,
                              CK_ULONG                 ulCount              );

CK_RV C_SetAttributeValue   ( CK_SESSION_HANDLE        hSession,
                              CK_OBJECT_HANDLE         hObject,
                              CK_ATTRIBUTE_PTR         pTemplate,
                              CK_ULONG                 ulCount              );

CK_RV C_FindObjectsInit     ( CK_SESSION_HANDLE        hSession,
                              CK_ATTRIBUTE_PTR         pTemplate,
                              CK_ULONG                 ulCount              );

CK_RV C_FindObjects         ( CK_SESSION_HANDLE        hSession,
                              CK_OBJECT_HANDLE_PTR     phObject,
                              CK_ULONG                 ulMaxObjectCount,
                              CK_ULONG_PTR             pulObjectCount       );

CK_RV C_FindObjectsFinal    ( CK_SESSION_HANDLE        hSession             );


// Encryption functions
//
CK_RV C_EncryptInit         ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_OBJECT_HANDLE         hKey                 );

CK_RV C_Encrypt             ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pData,
                              CK_ULONG                 ulDataLen,
                              CK_BYTE_PTR              pEncryptedData,
                              CK_ULONG_PTR             pulEncryptedDataLen  );

CK_RV C_EncryptUpdate       ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pPart,
                              CK_ULONG                 ulPartLen,
                              CK_BYTE_PTR              pEncryptedPart,
                              CK_ULONG_PTR             pulEncryptedPartLen  );

CK_RV C_EncryptFinal        ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pLastEncryptedPart,
                              CK_ULONG_PTR             pulLastEncryptedPartLen);


// Decryption functions
//
CK_RV C_DecryptInit         ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_OBJECT_HANDLE         hKey                 );

CK_RV C_Decrypt             ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pEncryptedData,
                              CK_ULONG                 ulEncryptedDataLen,
                              CK_BYTE_PTR              pData,
                              CK_ULONG_PTR             pulDataLen           );

CK_RV C_DecryptUpdate       ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pEncryptedPart,
                              CK_ULONG                 ulEncryptedPartLen,
                              CK_BYTE_PTR              pPart,
                              CK_ULONG_PTR             pulPartLen           );

CK_RV C_DecryptFinal        ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pLastPart,
                              CK_ULONG_PTR             pulLastPartLen       );


// Message digesting functions
//
CK_RV C_DigestInit          ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism           );

CK_RV C_Digest              ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pData,
                              CK_ULONG                 ulDataLen,
                              CK_BYTE_PTR              pDigest,
                              CK_ULONG_PTR             pulDigestLen         );

CK_RV C_DigestUpdate        ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pPart,
                              CK_ULONG                 ulPartLen            );

CK_RV C_DigestKey           ( CK_SESSION_HANDLE        hSession,
                              CK_OBJECT_HANDLE         hKey                 );

CK_RV C_DigestFinal         ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pDigest,
                              CK_ULONG_PTR             pulDigestLen         );


// Signing and MAC functions
//
CK_RV C_SignInit            ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_OBJECT_HANDLE         hKey                 );

CK_RV C_Sign                ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pData,
                              CK_ULONG                 ulDataLen,
                              CK_BYTE_PTR              pSignature,
                              CK_ULONG_PTR             pulSignatureLen      );

CK_RV C_SignUpdate          ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pPart,
                              CK_ULONG                 ulPartLen            );

CK_RV C_SignFinal           ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pSignature,
                              CK_ULONG_PTR             pulSignatureLen      );

CK_RV C_SignRecoverInit     ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_OBJECT_HANDLE         hKey                 );

CK_RV C_SignRecover         ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pData,
                              CK_ULONG                 ulDataLen,
                              CK_BYTE_PTR              pSignature,
                              CK_ULONG_PTR             pulSignatureLen      );


// Signature/MAC verification functions
//
CK_RV C_VerifyInit          ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_OBJECT_HANDLE         hKey                 );

CK_RV C_Verify              ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pData,
                              CK_ULONG                 ulDataLen,
                              CK_BYTE_PTR              pSignature,
                              CK_ULONG                 ulSignatureLen      );

CK_RV C_VerifyUpdate        ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pPart,
                              CK_ULONG                 ulPartLen            );

CK_RV C_VerifyFinal         ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pSignature,
                              CK_ULONG                 ulSignatureLen       );

CK_RV C_VerifyRecoverInit   ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_OBJECT_HANDLE         hKey                 );

CK_RV C_VerifyRecover       ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pSignature,
                              CK_ULONG                 ulSignatureLen,
                              CK_BYTE_PTR              pData,
                              CK_ULONG_PTR             pulDataLen           );


// Dual-function cryptographics functions
//
CK_RV C_DigestEncryptUpdate ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pPart,
                              CK_ULONG                 ulPartLen,
                              CK_BYTE_PTR              pEncryptedPart,
                              CK_ULONG_PTR             pulEncryptedPartLen  );

CK_RV C_DecryptDigestUpdate ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pEncryptedPart,
                              CK_ULONG                 ulEncryptedPartLen,
                              CK_BYTE_PTR              pPart,
                              CK_ULONG_PTR             pulPartLen           );

CK_RV C_SignEncryptUpdate   ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pPart,
                              CK_ULONG                 ulPartLen,
                              CK_BYTE_PTR              pEncryptedPart,
                              CK_ULONG_PTR             pulEncryptedPartLen  );

CK_RV C_DecryptVerifyUpdate ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pEncryptedPart,
                              CK_ULONG                 ulEncryptedPartLen,
                              CK_BYTE_PTR              pPart,
                              CK_ULONG_PTR             pulPartLen           );


// Key management functions
//
CK_RV C_GenerateKey         ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_ATTRIBUTE_PTR         pTemplate,
                              CK_ULONG                 ulCount,
                              CK_OBJECT_HANDLE_PTR     phKey                );

CK_RV C_GenerateKeyPair     ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_ATTRIBUTE_PTR         pPublicKeyTemplate,
                              CK_ULONG                 ulPublicKeyAttributeCount,
                              CK_ATTRIBUTE_PTR         pPrivateKeyTemplate,
                              CK_ULONG                 ulPrivateKeyAttributeCount,
                              CK_OBJECT_HANDLE_PTR     phPublicKey,
                              CK_OBJECT_HANDLE_PTR     phPrivateKey         );

CK_RV C_WrapKey             ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_OBJECT_HANDLE         hWrappingKey,
                              CK_OBJECT_HANDLE         hKey,
                              CK_BYTE_PTR              pWrappedKey,
                              CK_ULONG_PTR             pulWrappedKeyLen     );

CK_RV C_UnwrapKey           ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_OBJECT_HANDLE         hUnwrappingKey,
                              CK_BYTE_PTR              pWrappedKey,
                              CK_ULONG                 ulWrappedKeyLen,
                              CK_ATTRIBUTE_PTR         pTemplate,
                              CK_ULONG                 ulAttributeCount,
                              CK_OBJECT_HANDLE_PTR     phKey                );

CK_RV C_DeriveKey           ( CK_SESSION_HANDLE        hSession,
                              CK_MECHANISM_PTR         pMechanism,
                              CK_OBJECT_HANDLE         hBaseKey,
                              CK_ATTRIBUTE_PTR         pTemplate,
                              CK_ULONG                 ulAttributeCount,
                              CK_OBJECT_HANDLE_PTR     phKey                );


// Random number generation functions
//
CK_RV C_SeedRandom          ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pSeed,
                              CK_ULONG                 ulSeedLen            );

CK_RV C_GenerateRandom      ( CK_SESSION_HANDLE        hSession,
                              CK_BYTE_PTR              pRandomData,
                              CK_ULONG                 ulRandomLen          );

// Parallel function management functions
//
CK_RV C_GetFunctionStatus   ( CK_SESSION_HANDLE        hSession             );

CK_RV C_CancelFunction      ( CK_SESSION_HANDLE        hSession             );


//
// internal routines are below this point
//
CK_RV clock_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV clock_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV clock_validate_attribute( TEMPLATE *tmpl, 
				CK_ATTRIBUTE *attr, 
				CK_ULONG mode);

CK_RV counter_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV counter_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV counter_validate_attribute( TEMPLATE *tmpl, 
				  CK_ATTRIBUTE *attr, 
				  CK_ULONG mode);

CK_RV dp_dsa_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dp_dsa_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV dp_dsa_validate_attribute( TEMPLATE *tmpl, 
				 CK_ATTRIBUTE *attr, 
				 CK_ULONG mode);

CK_RV dp_dh_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dp_dh_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV dp_dh_validate_attribute( TEMPLATE *tmpl, 
				CK_ATTRIBUTE *attr, 
				CK_ULONG mode);

CK_RV dp_x9dh_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode);
CK_RV dp_x9dh_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV dp_x9dh_validate_attribute( TEMPLATE *tmpl, 
				  CK_ATTRIBUTE *attr, 
				  CK_ULONG mode);

CK_RV communicate( CK_ULONG cmd_id,
                   CK_VOID_PTR pReq,   CK_ULONG     req_len,
                   CK_VOID_PTR pRep,   CK_ULONG_PTR repl_len,
                   CK_BYTE_PTR pOut,   CK_ULONG     out_len,
                   CK_BYTE_PTR pIn,    CK_ULONG     in_len );

CK_RV compute_next_token_obj_name( CK_BYTE *current, CK_BYTE *next );

CK_RV save_token_object        ( OBJECT *obj );
CK_RV save_public_token_object ( OBJECT *obj );
CK_RV save_private_token_object( OBJECT *obj );

CK_RV load_public_token_objects ( void );
CK_RV load_private_token_objects( void );

CK_RV reload_token_object( OBJECT *obj );

CK_RV restore_private_token_object( CK_BYTE  * data,
                                    CK_ULONG   len,
                                    OBJECT   * pObj );

CK_RV delete_token_object( OBJECT *ptr );

CK_RV init_token_data( void );
CK_RV load_token_data( void );
CK_RV save_token_data( void );

CK_RV load_masterkey_so  ( void );
CK_RV load_masterkey_user( void );
CK_RV save_masterkey_so  ( void );
CK_RV save_masterkey_user( void );

CK_RV compute_md5( CK_BYTE *data, CK_ULONG len, CK_BYTE *hash );
CK_RV compute_sha( CK_BYTE *data, CK_ULONG len, CK_BYTE *hash );

CK_ULONG long_reverse( CK_ULONG x );

//CK_RV load_FCV( void );
//CK_RV save_FCV( FUNCTION_CTRL_VEC_RECORD *new_FCV );

//CK_RV update_tweak_values( void *attributes, CK_ULONG count );
//CK_RV query_tweak_values( CK_ATTRIBUTE_TYPE  * attributes,
//                          CK_ULONG             count,
//                          CK_BYTE           ** reply,
//                          CK_ULONG           * reply_len );

void  init_slotInfo(void);
void  init_tokenInfo(void);

CK_BYTE  parity_adjust( CK_BYTE b );
CK_RV    parity_is_odd( CK_BYTE b );

CK_RV build_attribute( CK_ATTRIBUTE_TYPE  type,
                       CK_BYTE           *data,
                       CK_ULONG           data_len,
                       CK_ATTRIBUTE       **attr );


CK_RV    add_pkcs_padding( CK_BYTE   * ptr,       // where to start appending
                           CK_ULONG    block_size,
                           CK_ULONG    data_len,
                           CK_ULONG    total_len );

CK_RV    strip_pkcs_padding( CK_BYTE  * ptr,
                             CK_ULONG   total_len,
                             CK_ULONG * data_len );


// RNG routines
//
CK_RV  rng_generate( CK_BYTE *output, CK_ULONG bytes );


// SSL3 routines
//
CK_RV  ssl3_mac_sign( SESSION *sess,  CK_BBOOL length_only,
                      SIGN_VERIFY_CONTEXT * ctx,
                      CK_BYTE             * in_data,
                      CK_ULONG              in_data_len,
                      CK_BYTE             * out_data,
                      CK_ULONG            * out_data_len );

CK_RV  ssl3_mac_sign_update( SESSION             * sess,
                             SIGN_VERIFY_CONTEXT * ctx,
                             CK_BYTE             * in_data,
                             CK_ULONG              in_data_len );

CK_RV  ssl3_mac_sign_final( SESSION *sess,  CK_BBOOL length_only,
                            SIGN_VERIFY_CONTEXT * ctx,
                            CK_BYTE             * out_data,
                            CK_ULONG            * out_data_len );

CK_RV  ssl3_mac_verify( SESSION             * sess,
                        SIGN_VERIFY_CONTEXT * ctx,
                        CK_BYTE             * in_data,
                        CK_ULONG              in_data_len,
                        CK_BYTE             * signature,
                        CK_ULONG              sig_len );

CK_RV  ssl3_mac_verify_update( SESSION             * sess,
                               SIGN_VERIFY_CONTEXT * ctx,
                               CK_BYTE             * in_data,
                               CK_ULONG              in_data_len );

CK_RV  ssl3_mac_verify_final( SESSION             * sess,
                              SIGN_VERIFY_CONTEXT * ctx,
                              CK_BYTE             * signature,
                              CK_ULONG              sig_len );

CK_RV  ssl3_master_key_derive( SESSION          * sess,
                               CK_MECHANISM     * mech,
                               CK_OBJECT_HANDLE   base_key,
                               CK_ATTRIBUTE     * attributes,
                               CK_ULONG           count,
                               CK_OBJECT_HANDLE * handle );

CK_RV  ssl3_key_and_mac_derive( SESSION          * sess,
                                CK_MECHANISM     * mech,
                                CK_OBJECT_HANDLE   base_key,
                                CK_ATTRIBUTE     * attributes,
                                CK_ULONG           count );

CK_RV  ckm_ssl3_pre_master_key_gen( TEMPLATE *tmpl, CK_MECHANISM *mech );


// RSA routines
//
CK_RV  rsa_pkcs_encrypt( SESSION           * sess,
                         CK_BBOOL            length_only,
                         ENCR_DECR_CONTEXT * ctx,
                         CK_BYTE           * in_data,
                         CK_ULONG            in_data_len,
                         CK_BYTE           * out_data,
                         CK_ULONG          * out_data_len );

CK_RV  rsa_pkcs_decrypt( SESSION           * sess,
                         CK_BBOOL            length_only,
                         ENCR_DECR_CONTEXT * ctx,
                         CK_BYTE           * in_data,
                         CK_ULONG            in_data_len,
                         CK_BYTE           * out_data,
                         CK_ULONG          * out_data_len );

CK_RV  rsa_pkcs_sign   ( SESSION             * sess,
                         CK_BBOOL              length_only,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * in_data,
                         CK_ULONG              in_data_len,
                         CK_BYTE             * signature,
                         CK_ULONG            * sig_len );

CK_RV  rsa_pkcs_verify ( SESSION             * sess,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * in_data,
                         CK_ULONG              in_data_len,
                         CK_BYTE             * signature,
                         CK_ULONG              sig_len );

CK_RV  rsa_pkcs_verify_recover ( SESSION             * sess,
                                 CK_BBOOL              length_only,
                                 SIGN_VERIFY_CONTEXT * ctx,
                                 CK_BYTE             * signature,
                                 CK_ULONG              sig_len,
                                 CK_BYTE             * out_data,
                                 CK_ULONG            * out_len );

CK_RV  rsa_x509_encrypt ( SESSION           * sess,
                          CK_BBOOL            length_only,
                          ENCR_DECR_CONTEXT * ctx,
                          CK_BYTE           * in_data,
                          CK_ULONG            in_data_len,
                          CK_BYTE           * out_data,
                          CK_ULONG          * out_data_len );

CK_RV  rsa_x509_decrypt ( SESSION           * sess,
                          CK_BBOOL            length_only,
                          ENCR_DECR_CONTEXT * ctx,
                          CK_BYTE           * in_data,
                          CK_ULONG            in_data_len,
                          CK_BYTE           * out_data,
                          CK_ULONG          * out_data_len );

CK_RV  rsa_x509_sign   ( SESSION             * sess,
                         CK_BBOOL              length_only,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * in_data,
                         CK_ULONG              in_data_len,
                         CK_BYTE             * signature,
                         CK_ULONG            * sig_len );

CK_RV  rsa_x509_verify ( SESSION             * sess,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * in_data,
                         CK_ULONG              in_data_len,
                         CK_BYTE             * signature,
                         CK_ULONG              sig_len );

CK_RV  rsa_x509_verify_recover( SESSION             * sess,
                                 CK_BBOOL              length_only,
                                 SIGN_VERIFY_CONTEXT * ctx,
                                 CK_BYTE             * signature,
                                 CK_ULONG              sig_len,
                                 CK_BYTE             * out_data,
                                 CK_ULONG            * out_len );

CK_RV  rsa_hash_pkcs_sign   ( SESSION             * sess,
                              CK_BBOOL              length_only,
                              SIGN_VERIFY_CONTEXT * ctx,
                              CK_BYTE             * in_data,
                              CK_ULONG              in_data_len,
                              CK_BYTE             * signature,
                              CK_ULONG            * sig_len );

CK_RV  rsa_hash_pkcs_verify ( SESSION             * sess,
                              SIGN_VERIFY_CONTEXT * ctx,
                              CK_BYTE             * in_data,
                              CK_ULONG              in_data_len,
                              CK_BYTE             * signature,
                              CK_ULONG              sig_len );

CK_RV  rsa_hash_pkcs_sign_update   ( SESSION             * sess,
                                     SIGN_VERIFY_CONTEXT * ctx,
                                     CK_BYTE             * in_data,
                                     CK_ULONG              in_data_len );

CK_RV  rsa_hash_pkcs_verify_update ( SESSION             * sess,
                                     SIGN_VERIFY_CONTEXT * ctx,
                                     CK_BYTE             * in_data,
                                     CK_ULONG              in_data_len );

CK_RV  rsa_hash_pkcs_sign_final   ( SESSION              * sess,
                                    CK_BBOOL               length_only,
                                    SIGN_VERIFY_CONTEXT  * ctx,
                                    CK_BYTE              * signature,
                                    CK_ULONG             * sig_len );

CK_RV  rsa_hash_pkcs_verify_final ( SESSION             * sess,
                                    SIGN_VERIFY_CONTEXT * ctx,
                                    CK_BYTE             * signature,
                                    CK_ULONG              sig_len );


// RSA mechanisms
//
CK_RV  ckm_rsa_key_pair_gen( TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl );
#if 0
CK_RV  ckm_rsa_encrypt( CK_BYTE  * in_data,
                        CK_ULONG   in_data_len,
                        CK_BYTE  * out_data,
                        OBJECT   * key_obj );

CK_RV  ckm_rsa_decrypt( CK_BYTE  * in_data,
                        CK_ULONG   in_data_len,
                        CK_BYTE  * out_data,
                        OBJECT   * key_obj );
#else
CK_RV  ckm_rsa_encrypt( CK_BYTE  * in_data,
			CK_ULONG   in_data_len,
			CK_BYTE  * out_data,
			CK_ULONG * out_data_len,
			OBJECT   * key_obj );

CK_RV  ckm_rsa_decrypt( CK_BYTE  * in_data,
			CK_ULONG   in_data_len,
			CK_BYTE  * out_data,
			CK_ULONG * out_data_len,
			OBJECT   * key_obj );

CK_RV  ckm_rsa_sign( CK_BYTE  * in_data,
		     CK_ULONG   in_data_len,
		     CK_BYTE  * out_data,
		     CK_ULONG * out_data_len,
		     OBJECT   * key_obj );

CK_RV  ckm_rsa_verify( CK_BYTE  * in_data,
		       CK_ULONG   in_data_len,
		       CK_BYTE  * out_data,
		       CK_ULONG   out_data_len,
		       OBJECT   * key_obj );
#endif

CK_RV  ckm_rsa_compute_priv_exp( TEMPLATE *tmpl );


#ifndef NODSA
// DSA routines
//
CK_RV  dsa_sign   ( SESSION             * sess,
                    CK_BBOOL              length_only,
                    SIGN_VERIFY_CONTEXT * ctx,
                    CK_BYTE             * in_data,
                    CK_ULONG              in_data_len,
                    CK_BYTE             * signature,
                    CK_ULONG            * sig_len );

CK_RV  dsa_verify ( SESSION             * sess,
                    SIGN_VERIFY_CONTEXT * ctx,
                    CK_BYTE             * in_data,
                    CK_ULONG              in_data_len,
                    CK_BYTE             * signature,
                    CK_ULONG              sig_len );


// DSA mechanisms
//
CK_RV  ckm_dsa_key_pair_gen( TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl );

CK_RV  ckm_dsa_sign( CK_BYTE *in_data,      // must be 20 bytes
                     CK_BYTE *signature,    // must be 40 bytes
                     OBJECT  *priv_key );

CK_RV  ckm_dsa_verify( CK_BYTE *signature,  // must be 40 bytes
                       CK_BYTE *data,       // must be 20 bytes
                       OBJECT  *publ_key );

#endif
 
/* Begin code contributed by Corrent corp. */
// DH routines
//
#ifndef NODH
 
CK_RV
dh_pkcs_derive( SESSION           * sess,
                CK_MECHANISM      * mech,
                CK_OBJECT_HANDLE    base_key,
                CK_ATTRIBUTE      * pTemplate,
                CK_ULONG            ulCount,
                CK_OBJECT_HANDLE  * handle ) ;
 
// DH mechanisms
//
CK_RV
ckm_dh_pkcs_derive( CK_VOID_PTR        other_pubkey,
                    CK_ULONG           other_pubkey_len,
                    CK_OBJECT_HANDLE   base_key,
                    CK_BYTE            *secret,
                    CK_ULONG           *secret_len ) ;
 
CK_RV
ckm_dh_key_pair_gen( TEMPLATE *publ_tmpl,
                     TEMPLATE *priv_tmpl );
 
CK_RV
ckm_dh_pkcs_key_pair_gen( TEMPLATE  * publ_tmpl,
                          TEMPLATE  * priv_tmpl );
#endif
/* End code contributed by Corrent corp. */

// DES routines - I have to provide two different versions of these
//                because encryption routines are also used internally
//                so we can't assume that external-to-external buffering
//                will be possible and combining them into a single
//                function is messy.
//
CK_RV  pk_des_ecb_encrypt( SESSION  *sess,     CK_BBOOL  length_only,
                        ENCR_DECR_CONTEXT *context,
                        CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                        CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des_ecb_decrypt( SESSION  *sess,     CK_BBOOL  length_only,
                        ENCR_DECR_CONTEXT *context,
                        CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                        CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  pk_des_cbc_encrypt( SESSION  *sess,     CK_BBOOL  length_only,
                        ENCR_DECR_CONTEXT *context,
                        CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                        CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des_cbc_decrypt( SESSION  *sess,     CK_BBOOL  length_only,
                        ENCR_DECR_CONTEXT *context,
                        CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                        CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des_cbc_pad_encrypt( SESSION  *sess,     CK_BBOOL  length_only,
                            ENCR_DECR_CONTEXT *context,
                            CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                            CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des_cbc_pad_decrypt( SESSION  *sess,     CK_BBOOL  length_only,
                            ENCR_DECR_CONTEXT *context,
                            CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                            CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des_ecb_encrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des_ecb_decrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des_cbc_encrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des_cbc_decrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des_cbc_pad_encrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                   ENCR_DECR_CONTEXT *context,
                                   CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                   CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des_cbc_pad_decrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                   ENCR_DECR_CONTEXT *context,
                                   CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                   CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des_ecb_encrypt_final( SESSION *sess,      CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des_ecb_decrypt_final( SESSION *sess,      CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des_cbc_encrypt_final( SESSION *sess,      CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des_cbc_decrypt_final( SESSION *sess,      CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des_cbc_pad_encrypt_final( SESSION *sess,      CK_BBOOL length_only,
                                  ENCR_DECR_CONTEXT *context,
                                  CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des_cbc_pad_decrypt_final( SESSION *sess,      CK_BBOOL length_only,
                                  ENCR_DECR_CONTEXT *context,
                                  CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des_ecb_wrap_key( SESSION      *sess, CK_BBOOL  length_only,
                         CK_MECHANISM *mech,
                         OBJECT       *key,  OBJECT   *encr_key,
                         CK_BYTE      *data, CK_ULONG *data_len );


// DES mechanisms
//
CK_RV  ckm_des_key_gen ( TEMPLATE *tmpl );
CK_RV  ckm_cdmf_key_gen( TEMPLATE *tmpl );

CK_RV  ckm_des_ecb_encrypt( CK_BYTE *in_data,   CK_ULONG in_data_len,
                            CK_BYTE *out_data,  CK_ULONG *out_data_len,
                            CK_BYTE *key_value );
CK_RV  ckm_des_ecb_decrypt( CK_BYTE *in_data,  CK_ULONG in_data_len,
                            CK_BYTE *out_data,  CK_ULONG *out_data_len,
                            CK_BYTE *key_value );

CK_RV  ckm_des_cbc_encrypt( CK_BYTE *in_data,   CK_ULONG in_data_len,
                            CK_BYTE *out_data,  CK_ULONG *out_data_len,
                            CK_BYTE *init_v,
                            CK_BYTE *key_value );
CK_RV  ckm_des_cbc_decrypt( CK_BYTE *in_data,   CK_ULONG in_data_len,
                            CK_BYTE *out_data,  CK_ULONG *out_data_len,
                            CK_BYTE *init_v,
                            CK_BYTE *key_value );

CK_RV  ckm_des_wrap_format( CK_BBOOL length_only,
                            CK_BYTE  **data, CK_ULONG *data_len );


// DES3 routines
//
CK_RV  des3_ecb_encrypt( SESSION  *sess,     CK_BBOOL  length_only,
                         ENCR_DECR_CONTEXT *context,
                         CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                         CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des3_ecb_decrypt( SESSION  *sess,     CK_BBOOL  length_only,
                         ENCR_DECR_CONTEXT *context,
                         CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                         CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des3_cbc_encrypt( SESSION  *sess,     CK_BBOOL  length_only,
                         ENCR_DECR_CONTEXT *context,
                         CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                         CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des3_cbc_decrypt( SESSION  *sess,     CK_BBOOL  length_only,
                         ENCR_DECR_CONTEXT *context,
                         CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                         CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des3_cbc_pad_encrypt( SESSION  *sess,     CK_BBOOL  length_only,
                             ENCR_DECR_CONTEXT *context,
                             CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                             CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des3_cbc_pad_decrypt( SESSION  *sess,     CK_BBOOL  length_only,
                             ENCR_DECR_CONTEXT *context,
                             CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                             CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des3_ecb_encrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                ENCR_DECR_CONTEXT *context,
                                CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des3_ecb_decrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                ENCR_DECR_CONTEXT *context,
                                CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des3_cbc_encrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                ENCR_DECR_CONTEXT *context,
                                CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des3_cbc_decrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                ENCR_DECR_CONTEXT *context,
                                CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des3_cbc_pad_encrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                    ENCR_DECR_CONTEXT *context,
                                    CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                    CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des3_cbc_pad_decrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                    ENCR_DECR_CONTEXT *context,
                                    CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                    CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des3_ecb_encrypt_final( SESSION *sess,  CK_BBOOL length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des3_ecb_decrypt_final( SESSION *sess,  CK_BBOOL length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des3_cbc_encrypt_final( SESSION *sess,  CK_BBOOL length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des3_cbc_decrypt_final( SESSION *sess,  CK_BBOOL length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  des3_cbc_pad_encrypt_final( SESSION *sess,  CK_BBOOL length_only,
                                   ENCR_DECR_CONTEXT *context,
                                   CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  des3_cbc_pad_decrypt_final( SESSION *sess,  CK_BBOOL length_only,
                                   ENCR_DECR_CONTEXT *context,
                                   CK_BYTE  *out_data, CK_ULONG *out_data_len );

// DES3 mechanisms
//
CK_RV  ckm_des3_key_gen( TEMPLATE *tmpl );

CK_RV  ckm_des3_ecb_encrypt( CK_BYTE *in_data,   CK_ULONG    in_data_len,
                             CK_BYTE *out_data,  CK_ULONG   *out_data_len,
                             CK_BYTE *key_value );
CK_RV  ckm_des3_ecb_decrypt( CK_BYTE *in_data,   CK_ULONG    in_data_len,
                             CK_BYTE *out_data,  CK_ULONG   *out_data_len,
                             CK_BYTE *key_value );

CK_RV  ckm_des3_cbc_encrypt( CK_BYTE *in_data,   CK_ULONG    in_data_len,
                             CK_BYTE *out_data,  CK_ULONG   *out_data_len,
                             CK_BYTE *init_v,    CK_BYTE    *key_value );
CK_RV  ckm_des3_cbc_decrypt( CK_BYTE *in_data,   CK_ULONG    in_data_len,
                             CK_BYTE *out_data,  CK_ULONG   *out_data_len,
                             CK_BYTE *init_v,    CK_BYTE    *key_value );


// AES routines
//
CK_RV  aes_ecb_encrypt( SESSION  *sess,     CK_BBOOL  length_only,
                        ENCR_DECR_CONTEXT *context,
                        CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                        CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  aes_ecb_decrypt( SESSION  *sess,     CK_BBOOL  length_only,
                        ENCR_DECR_CONTEXT *context,
                        CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                        CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  aes_cbc_encrypt( SESSION  *sess,     CK_BBOOL  length_only,
                        ENCR_DECR_CONTEXT *context,
                        CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                        CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  aes_cbc_decrypt( SESSION  *sess,     CK_BBOOL  length_only,
                        ENCR_DECR_CONTEXT *context,
                        CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                        CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  aes_cbc_pad_encrypt( SESSION  *sess,     CK_BBOOL  length_only,
                            ENCR_DECR_CONTEXT *context,
                            CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                            CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  aes_cbc_pad_decrypt( SESSION  *sess,     CK_BBOOL  length_only,
                            ENCR_DECR_CONTEXT *context,
                            CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                            CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  aes_ecb_encrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  aes_ecb_decrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  aes_cbc_encrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  aes_cbc_decrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                               ENCR_DECR_CONTEXT *context,
                               CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                               CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  aes_cbc_pad_encrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                   ENCR_DECR_CONTEXT *context,
                                   CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                   CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  aes_cbc_pad_decrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                   ENCR_DECR_CONTEXT *context,
                                   CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                   CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  aes_ecb_encrypt_final( SESSION *sess,  CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  aes_ecb_decrypt_final( SESSION *sess,  CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  aes_cbc_encrypt_final( SESSION *sess,  CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  aes_cbc_decrypt_final( SESSION *sess,  CK_BBOOL length_only,
                              ENCR_DECR_CONTEXT *context,
                              CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  aes_cbc_pad_encrypt_final( SESSION *sess,  CK_BBOOL length_only,
                                  ENCR_DECR_CONTEXT *context,
                                  CK_BYTE  *out_data, CK_ULONG *out_data_len );
CK_RV  aes_cbc_pad_decrypt_final( SESSION *sess,  CK_BBOOL length_only,
                                  ENCR_DECR_CONTEXT *context,
                                  CK_BYTE  *out_data, CK_ULONG *out_data_len );




// AES mechanisms
//
CK_RV  ckm_aes_key_gen( TEMPLATE *tmpl );

CK_RV  ckm_aes_ecb_encrypt( CK_BYTE *in_data,   CK_ULONG    in_data_len,
                            CK_BYTE *out_data,  CK_ULONG   *out_data_len,
                            CK_BYTE *key_value, CK_ULONG    key_len );
CK_RV  ckm_aes_ecb_decrypt( CK_BYTE *in_data,   CK_ULONG    in_data_len,
                            CK_BYTE *out_data,  CK_ULONG   *out_data_len,
                            CK_BYTE *key_value, CK_ULONG    key_len );

CK_RV  ckm_aes_cbc_encrypt( CK_BYTE  *in_data,   CK_ULONG    in_data_len,
                            CK_BYTE  *out_data,  CK_ULONG   *out_data_len,
                            CK_BYTE  *init_v,    CK_BYTE    *key_value, 
			    CK_ULONG  key_len );
CK_RV  ckm_aes_cbc_decrypt( CK_BYTE  *in_data,   CK_ULONG    in_data_len,
                            CK_BYTE  *out_data,  CK_ULONG   *out_data_len,
                            CK_BYTE  *init_v,    CK_BYTE    *key_value,
			    CK_ULONG  key_len );

CK_RV ckm_aes_wrap_format( CK_BBOOL    length_only,
			   CK_BYTE  ** data,
			   CK_ULONG  * data_len );

// SHA-1 mechanisms
//
CK_RV  sha1_hash( SESSION  *sess,     CK_BBOOL  length_only,
                  DIGEST_CONTEXT *ctx,
                  CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                  CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  sha1_hash_update( SESSION *sess,    DIGEST_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len );

CK_RV  sha1_hash_final( SESSION  *sess,     CK_BBOOL  length_only,
                        DIGEST_CONTEXT *ctx,
                        CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  sha1_hmac_sign( SESSION *sess,  CK_BBOOL length_only,
                       SIGN_VERIFY_CONTEXT * ctx,
                       CK_BYTE             * in_data,
                       CK_ULONG              in_data_len,
                       CK_BYTE             * out_data,
                       CK_ULONG            * out_data_len );

CK_RV  sha1_hmac_verify( SESSION             * sess,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * in_data,
                         CK_ULONG              in_data_len,
                         CK_BYTE             * signature,
                         CK_ULONG              sig_len );

void   ckm_sha1_init( DIGEST_CONTEXT *ctx );

CK_RV  ckm_sha1_update( DIGEST_CONTEXT *ctx,
                        CK_BYTE      *in_data,  CK_ULONG in_data_len );

CK_RV  ckm_sha1_final( DIGEST_CONTEXT *ctx,
                       CK_BYTE      *out_data, CK_ULONG  *out_data_len );

// SHA-256 mechanisms
//
CK_RV  sha2_hash( SESSION  *sess,     CK_BBOOL  length_only,
                  DIGEST_CONTEXT *ctx,
                  CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                  CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  sha2_hash_update( SESSION *sess,    DIGEST_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len );

CK_RV  sha2_hash_final( SESSION  *sess,     CK_BBOOL  length_only,
                        DIGEST_CONTEXT *ctx,
                        CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  sha2_hmac_sign( SESSION *sess,  CK_BBOOL length_only,
                       SIGN_VERIFY_CONTEXT * ctx,
                       CK_BYTE             * in_data,
                       CK_ULONG              in_data_len,
                       CK_BYTE             * out_data,
                       CK_ULONG            * out_data_len );

CK_RV  sha2_hmac_verify( SESSION             * sess,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * in_data,
                         CK_ULONG              in_data_len,
                         CK_BYTE             * signature,
                         CK_ULONG              sig_len );

void   ckm_sha2_init( DIGEST_CONTEXT *ctx );

CK_RV  ckm_sha2_update( DIGEST_CONTEXT *ctx,
                        CK_BYTE      *in_data,  CK_ULONG in_data_len );

CK_RV  ckm_sha2_final( DIGEST_CONTEXT *ctx,
                       CK_BYTE      *out_data, CK_ULONG  *out_data_len );


// MD2 mechanisms
//
CK_RV  md2_hash( SESSION  *sess,     CK_BBOOL  length_only,
                 DIGEST_CONTEXT *ctx,
                 CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                 CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  md2_hash_update( SESSION *sess,    DIGEST_CONTEXT *ctx,
                        CK_BYTE *in_data, CK_ULONG in_data_len );

CK_RV  md2_hash_final( SESSION  *sess,     CK_BBOOL  length_only,
                       DIGEST_CONTEXT *ctx,
                       CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  md2_hmac_sign( SESSION *sess,  CK_BBOOL length_only,
                      SIGN_VERIFY_CONTEXT * ctx,
                      CK_BYTE             * in_data,
                      CK_ULONG              in_data_len,
                      CK_BYTE             * out_data,
                      CK_ULONG            * out_data_len );

CK_RV  md2_hmac_verify( SESSION             * sess,
                        SIGN_VERIFY_CONTEXT * ctx,
                        CK_BYTE             * in_data,
                        CK_ULONG              in_data_len,
                        CK_BYTE             * signature,
                        CK_ULONG              sig_len );

CK_RV  ckm_md2_update( MD2_CONTEXT *context,
                       CK_BYTE     *in_data,  CK_ULONG in_data_len );

CK_RV  ckm_md2_final( MD2_CONTEXT  *context,
                      CK_BYTE      *out_data, CK_ULONG  out_data_len );

void   ckm_md2_transform( CK_BYTE *state, CK_BYTE *checksum, CK_BYTE *block );


// MD5 mechanisms
//
CK_RV  md5_hash( SESSION  *sess,     CK_BBOOL  length_only,
                 DIGEST_CONTEXT *ctx,
                 CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                 CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  md5_hash_update( SESSION *sess,    DIGEST_CONTEXT *ctx,
                        CK_BYTE *in_data, CK_ULONG in_data_len );

CK_RV  md5_hash_final( SESSION  *sess,     CK_BBOOL  length_only,
                       DIGEST_CONTEXT *ctx,
                       CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV  md5_hmac_sign( SESSION *sess,  CK_BBOOL length_only,
                      SIGN_VERIFY_CONTEXT * ctx,
                      CK_BYTE             * in_data,
                      CK_ULONG              in_data_len,
                      CK_BYTE             * out_data,
                      CK_ULONG            * out_data_len );

CK_RV  md5_hmac_verify( SESSION             * sess,
                        SIGN_VERIFY_CONTEXT * ctx,
                        CK_BYTE             * in_data,
                        CK_ULONG              in_data_len,
                        CK_BYTE             * signature,
                        CK_ULONG              sig_len );

void   ckm_md5_init( MD5_CONTEXT *context );

CK_RV  ckm_md5_update( MD5_CONTEXT *context,
                       CK_BYTE     *in_data,  CK_ULONG in_data_len );

CK_RV  ckm_md5_final( MD5_CONTEXT  *context,
                      CK_BYTE      *out_data, CK_ULONG  out_data_len );

void   ckm_md5_transform( CK_ULONG *buf, CK_ULONG *in );


// linked-list routines
//
DL_NODE * dlist_add_as_first( DL_NODE *list, void *data );
DL_NODE * dlist_add_as_last( DL_NODE *list, void *data );
DL_NODE * dlist_find( DL_NODE *list, void *data );
DL_NODE * dlist_get_first( DL_NODE *list );
DL_NODE * dlist_get_last( DL_NODE *list );
CK_ULONG  dlist_length( DL_NODE *list );
DL_NODE * dlist_next( DL_NODE *list );
DL_NODE * dlist_prev( DL_NODE *list );
void      dlist_purge( DL_NODE *list );
DL_NODE * dlist_remove_node( DL_NODE *list, DL_NODE *node );

CK_RV _CreateMutex( MUTEX *mutex );
CK_RV _DestroyMutex( MUTEX *mutex );
CK_RV _LockMutex( MUTEX *mutex );
CK_RV _UnlockMutex( MUTEX *mutex );

CK_RV attach_shm(void);
CK_RV detach_shm(void);

// encryption manager routines
//
CK_RV     encr_mgr_init( SESSION           * sess,
                         ENCR_DECR_CONTEXT * ctx,
                         CK_ULONG            operation,
                         CK_MECHANISM      * mech,
                         CK_OBJECT_HANDLE    key_handle );

CK_RV     encr_mgr_cleanup( ENCR_DECR_CONTEXT *ctx );

CK_RV     encr_mgr_encrypt( SESSION  *sess,     CK_BBOOL  length_only,
                            ENCR_DECR_CONTEXT *ctx,
                            CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                            CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV     encr_mgr_encrypt_final( SESSION  *sess,     CK_BBOOL  length_only,
                                  ENCR_DECR_CONTEXT *ctx,
                                  CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV     encr_mgr_encrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                   ENCR_DECR_CONTEXT *ctx,
                                   CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                   CK_BYTE  *out_data, CK_ULONG *out_data_len );

// decryption manager routines
//
CK_RV     decr_mgr_init( SESSION           * sess,
                         ENCR_DECR_CONTEXT * ctx,
                         CK_ULONG            operation,
                         CK_MECHANISM      * mech,
                         CK_OBJECT_HANDLE    key_handle );

CK_RV     decr_mgr_cleanup( ENCR_DECR_CONTEXT * ctx );

CK_RV     decr_mgr_decrypt( SESSION  *sess,     CK_BBOOL  length_only,
                            ENCR_DECR_CONTEXT * ctx,
                            CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                            CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV     decr_mgr_decrypt_final( SESSION  *sess,     CK_BBOOL  length_only,
                                  ENCR_DECR_CONTEXT * ctx,
                                  CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV     decr_mgr_decrypt_update( SESSION  *sess,     CK_BBOOL  length_only,
                                   ENCR_DECR_CONTEXT * ctx,
                                   CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                   CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV     decr_mgr_update_des_ecb( SESSION  *sess,     CK_BBOOL  length_only,
                                   ENCR_DECR_CONTEXT * ctx,
                                   CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                   CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV     decr_mgr_update_des_cbc( SESSION  *sess,     CK_BBOOL  length_only,
                                   ENCR_DECR_CONTEXT * ctx,
                                   CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                   CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV     decr_mgr_update_des3_ecb( SESSION  *sess,     CK_BBOOL  length_only,
                                    ENCR_DECR_CONTEXT * ctx,
                                    CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                    CK_BYTE  *out_data, CK_ULONG *out_data_len );

CK_RV     decr_mgr_update_des3_cbc( SESSION  *sess,     CK_BBOOL  length_only,
                                    ENCR_DECR_CONTEXT * ctx,
                                    CK_BYTE  *in_data,  CK_ULONG  in_data_len,
                                    CK_BYTE  *out_data, CK_ULONG *out_data_len );

// digest manager routines
//
CK_RV    digest_mgr_cleanup( DIGEST_CONTEXT *ctx );

CK_RV    digest_mgr_init( SESSION        *sess,
                          DIGEST_CONTEXT *ctx,
                          CK_MECHANISM   *mech );

CK_RV    digest_mgr_digest( SESSION        *sess, CK_BBOOL  length_only,
                            DIGEST_CONTEXT *ctx,
                            CK_BYTE        *data, CK_ULONG  data_len,
                            CK_BYTE        *hash, CK_ULONG *hash_len );

CK_RV    digest_mgr_digest_update( SESSION        *sess,
                                   DIGEST_CONTEXT *ctx,
                                   CK_BYTE        *data,  CK_ULONG data_len );

CK_RV    digest_mgr_digest_key( SESSION          *sess,
                                DIGEST_CONTEXT   *ctx,
                                CK_OBJECT_HANDLE  key_handle );

CK_RV    digest_mgr_digest_final( SESSION        *sess, CK_BBOOL  length_only,
                                  DIGEST_CONTEXT *ctx,
                                  CK_BYTE        *hash, CK_ULONG *hash_len );


// key manager routines
//
CK_RV     key_mgr_generate_key( SESSION *sess,
                                CK_MECHANISM *mech,
                                CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount,
                                CK_OBJECT_HANDLE *key_handle );

CK_RV     key_mgr_generate_key_pair( SESSION *sess,
                                     CK_MECHANISM *mech,
                                     CK_ATTRIBUTE *publ_tmpl, CK_ULONG publ_count,
                                     CK_ATTRIBUTE *priv_tmpl, CK_ULONG priv_count,
                                     CK_OBJECT_HANDLE *publ_key_handle,
                                     CK_OBJECT_HANDLE *priv_key_handle );

CK_RV     key_mgr_get_private_key_type( CK_BYTE     *keydata,
                                        CK_ULONG     keylen,
                                        CK_KEY_TYPE *keytype );

CK_RV     key_mgr_derive_key( SESSION           * sess,
                              CK_MECHANISM      * mech,
                              CK_OBJECT_HANDLE    base_key,
                              CK_OBJECT_HANDLE  * derived_key,
                              CK_ATTRIBUTE      * pTemplate,
                              CK_ULONG            ulCount );

CK_RV     key_mgr_wrap_key( SESSION           *sess,
                            CK_BBOOL           length_only,
                            CK_MECHANISM      *mech,
                            CK_OBJECT_HANDLE   h_wrapping_key,
                            CK_OBJECT_HANDLE   h_key,
                            CK_BYTE           *wrapped_key,
                            CK_ULONG          *wrapped_key_len );

CK_RV     key_mgr_unwrap_key( SESSION          *sess,
                              CK_MECHANISM     *mech,
                              CK_ATTRIBUTE     *pTemplate,
                              CK_ULONG          ulCount,
                              CK_BYTE          *wrapped_key,
                              CK_ULONG          wrapped_key_len,
                              CK_OBJECT_HANDLE  unwrapping_key,
                              CK_OBJECT_HANDLE *unwrapped_key );

CK_RV     key_mgr_derive_prolog( SESSION              *sess,
                                 CK_ATTRIBUTE         *attributes,
                                 CK_ULONG              attrcount,
                                 CK_OBJECT_HANDLE      base_key,
                                 OBJECT               *base_key_obj,
                                 CK_BYTE              *base_key_value,
                                 CK_KEY_TYPE           base_key_type,
                                 ATTRIBUTE_PARSE_LIST *parselist,
                                 CK_ULONG              plcount );


// signature manager routines
//
CK_RV     sign_mgr_init( SESSION             * sess,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_MECHANISM        * mech,
                         CK_BBOOL              recover_mode,
                         CK_OBJECT_HANDLE      key_handle );

CK_RV     sign_mgr_cleanup( SIGN_VERIFY_CONTEXT *ctx );

CK_RV     sign_mgr_sign( SESSION             * sess,
                         CK_BBOOL              length_only,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * in_data,
                         CK_ULONG              in_data_len,
                         CK_BYTE             * out_data,
                         CK_ULONG            * out_data_len );

CK_RV     sign_mgr_sign_recover( SESSION             * sess,
                                 CK_BBOOL              length_only,
                                 SIGN_VERIFY_CONTEXT * ctx,
                                 CK_BYTE             * in_data,
                                 CK_ULONG              in_data_len,
                                 CK_BYTE             * out_data,
                                 CK_ULONG            * out_data_len );

CK_RV     sign_mgr_sign_final( SESSION             * sess,
                               CK_BBOOL              length_only,
                               SIGN_VERIFY_CONTEXT * ctx,
                               CK_BYTE             * out_data,
                               CK_ULONG            * out_data_len );

CK_RV     sign_mgr_sign_update( SESSION             * sess,
                                SIGN_VERIFY_CONTEXT * ctx,
                                CK_BYTE             * in_data,
                                CK_ULONG              in_data_len );

// signature verify manager routines
//
CK_RV     verify_mgr_init( SESSION             * sess,
                           SIGN_VERIFY_CONTEXT * ctx,
                           CK_MECHANISM        * mech,
                           CK_BBOOL              recover_mode,
                           CK_OBJECT_HANDLE      key_handle );

CK_RV     verify_mgr_cleanup( SIGN_VERIFY_CONTEXT *ctx );

CK_RV     verify_mgr_verify( SESSION             * sess,
                             SIGN_VERIFY_CONTEXT * ctx,
                             CK_BYTE             * in_data,
                             CK_ULONG              in_data_len,
                             CK_BYTE             * signature,
                             CK_ULONG              sig_len );

CK_RV     verify_mgr_verify_recover( SESSION             * sess,
                                     CK_BBOOL              length_only,
                                     SIGN_VERIFY_CONTEXT * ctx,
                                     CK_BYTE             * signature,
                                     CK_ULONG              sig_len,
                                     CK_BYTE             * out_data,
                                     CK_ULONG            * out_len );

CK_RV     verify_mgr_verify_update( SESSION             * sess,
                                    SIGN_VERIFY_CONTEXT * ctx,
                                    CK_BYTE             * in_data,
                                    CK_ULONG              in_data_len );

CK_RV     verify_mgr_verify_final( SESSION             * sess,
                                   SIGN_VERIFY_CONTEXT * ctx,
                                   CK_BYTE             * signature,
                                   CK_ULONG              sig_len );


// session manager routines
//
CK_RV  session_mgr_close_all_sessions( void );
CK_RV  session_mgr_close_session( CK_SESSION_HANDLE );
SESSION * session_mgr_find( CK_SESSION_HANDLE handle );
CK_RV  session_mgr_login_all ( CK_USER_TYPE user_type );
CK_RV  session_mgr_logout_all( void );
CK_RV  session_mgr_new( CK_ULONG flags, CK_SLOT_ID, CK_SESSION_HANDLE_PTR );

CK_BBOOL  session_mgr_readonly_session_exists( void );
CK_BBOOL  session_mgr_so_session_exists    ( void );
CK_BBOOL  session_mgr_user_session_exists  ( void );
CK_BBOOL  session_mgr_public_session_exists( void );

CK_RV    session_mgr_get_op_state( SESSION *sess, CK_BBOOL  length_only,
                                   CK_BYTE *data, CK_ULONG *data_len );

CK_RV    session_mgr_set_op_state( SESSION          *sess,
                                   CK_OBJECT_HANDLE  encr_key, CK_OBJECT_HANDLE  auth_key,
                                   CK_BYTE          *data,     CK_ULONG          data_len );

// object manager routines
//
CK_RV    object_mgr_add( SESSION          * sess,
                         CK_ATTRIBUTE     * pTemplate,
                         CK_ULONG           ulCount,
                         CK_OBJECT_HANDLE * handle );

CK_RV    object_mgr_add_to_map( SESSION          * sess,
                                OBJECT           * obj,
				unsigned long      obj_handle,
                                CK_OBJECT_HANDLE * handle );

CK_RV    object_mgr_add_to_shm  ( OBJECT *obj );
CK_RV    object_mgr_del_from_shm( OBJECT *obj );
CK_RV    object_mgr_check_shm   ( OBJECT *obj );
CK_RV    object_mgr_search_shm_for_obj( TOK_OBJ_ENTRY  * list,
                                        CK_ULONG         lo,
                                        CK_ULONG         hi,
                                        OBJECT         * obj,
                                        CK_ULONG       * index );
CK_RV    object_mgr_sort_priv_shm( void );
CK_RV    object_mgr_sort_publ_shm( void );
CK_RV    object_mgr_update_from_shm( void );
CK_RV    object_mgr_update_publ_tok_obj_from_shm();
CK_RV    object_mgr_update_priv_tok_obj_from_shm();

CK_RV    object_mgr_copy( SESSION          * sess,
                          CK_ATTRIBUTE     * pTemplate,
                          CK_ULONG           ulCount,
                          CK_OBJECT_HANDLE   old_obj,
                          CK_OBJECT_HANDLE * new_obj );

CK_RV    object_mgr_create_final( SESSION           *sess,
                                  OBJECT            *obj,
                                  CK_OBJECT_HANDLE  *handle );

CK_RV    object_mgr_create_skel( SESSION      * sess,
                                 CK_ATTRIBUTE * pTemplate,
                                 CK_ULONG       ulCount,
                                 CK_ULONG       mode,
                                 CK_ULONG       class,
                                 CK_ULONG       subclass,
                                 OBJECT      ** obj );

CK_RV    object_mgr_destroy_object( SESSION         * sess,
                                    CK_OBJECT_HANDLE  handle );

CK_RV    object_mgr_destroy_token_objects( void );

CK_RV    object_mgr_find_in_map_nocache( CK_OBJECT_HANDLE    handle,
					 OBJECT           ** ptr );

CK_RV    object_mgr_find_in_map1( CK_OBJECT_HANDLE   handle,
                                  OBJECT           ** ptr );

CK_RV    object_mgr_find_in_map2( OBJECT           * ptr,
                                  CK_OBJECT_HANDLE * handle );

CK_RV    object_mgr_find_init( SESSION      * sess,
                               CK_ATTRIBUTE * pTemplate,
                               CK_ULONG       ulCount );

CK_RV    object_mgr_find_build_list( SESSION       * sess,
                                     CK_ATTRIBUTE  * pTemplate,
                                     CK_ULONG        ulCount,
                                     DL_NODE       * obj_list,
                                     CK_BBOOL        public_only );

CK_RV    object_mgr_find_final( SESSION *sess );

CK_RV    object_mgr_get_attribute_values( SESSION           * sess,
                                          CK_OBJECT_HANDLE    handle,
                                          CK_ATTRIBUTE      * pTemplate,
                                          CK_ULONG            ulCount );

CK_RV    object_mgr_get_object_size( CK_OBJECT_HANDLE   handle,
                                     CK_ULONG         * size );

CK_BBOOL object_mgr_invalidate_handle1( CK_OBJECT_HANDLE handle );

CK_BBOOL object_mgr_invalidate_handle2( OBJECT *obj );

CK_BBOOL object_mgr_purge_session_objects( SESSION       * sess,
                                           SESS_OBJ_TYPE   type );

CK_BBOOL object_mgr_purge_token_objects( void );

CK_BBOOL object_mgr_purge_private_token_objects( void );

CK_RV    object_mgr_restore_obj( CK_BYTE *data, OBJECT *oldObj );

CK_RV    object_mgr_restore_obj_withSize( CK_BYTE *data, OBJECT *oldObj, int data_size );

CK_RV    object_mgr_set_attribute_values( SESSION          * sess,
                                          CK_OBJECT_HANDLE   handle,
                                          CK_ATTRIBUTE     * pTemplate,
                                          CK_ULONG           ulCount );

// SAB FIXME FIXME
CK_BBOOL object_mgr_purge_map( SESSION       * sess,
                               SESS_OBJ_TYPE   type );

/* structures used to hold arguments to callback functions triggered by either bt_for_each_node
 * or bt_node_free */
struct find_args
{
	int done;
	OBJECT *obj;
	CK_OBJECT_HANDLE map_handle;
};

struct find_by_name_args
{
	int done;
	char *name;
};

struct find_build_list_args
{
	CK_ATTRIBUTE *pTemplate;
	SESSION *sess;
	CK_ULONG ulCount;
	CK_BBOOL hw_feature;
	CK_BBOOL hidden_object;
	CK_BBOOL public_only;
};

struct purge_args
{
	SESSION *sess;
	SESS_OBJ_TYPE type;
};

struct update_tok_obj_args
{
	TOK_OBJ_ENTRY *entries;
	CK_ULONG_32 *num_entries;
	struct btree *t;
};

// object routines
//
CK_RV     object_create( CK_ATTRIBUTE  * pTemplate,
                         CK_ULONG        ulCount,
                         OBJECT       ** obj );

CK_RV     object_create_skel( CK_ATTRIBUTE * pTemplate,
                              CK_ULONG       ulCount,
                              CK_ULONG       mode,
                              CK_ULONG       class,
                              CK_ULONG       subclass,
                              OBJECT      ** key );

CK_RV     object_copy( CK_ATTRIBUTE * pTemplate,
                       CK_ULONG       ulCount,
                       OBJECT       * old_obj,
                       OBJECT      ** new_obj );

CK_RV     object_flatten( OBJECT    * obj,
                          CK_BYTE  ** data,
                          CK_ULONG  * len );

CK_BBOOL  object_free( OBJECT *obj );

CK_RV     object_get_attribute_values( OBJECT       * obj,
                                       CK_ATTRIBUTE * pTemplate,
                                       CK_ULONG       count );

CK_ULONG  object_get_size( OBJECT *obj );

CK_RV     object_restore( CK_BYTE  * data,
                          OBJECT  ** obj,
                          CK_BBOOL   replace );

CK_RV     object_restore_withSize( CK_BYTE  * data,
				   OBJECT  ** obj,
				   CK_BBOOL   replace,
				   int        data_size );


CK_RV     object_set_attribute_values( OBJECT       * obj,
                                       CK_ATTRIBUTE * pTemplate,
                                       CK_ULONG       ulCount );

CK_BBOOL  object_is_modifiable    ( OBJECT * obj );
CK_BBOOL  object_is_private       ( OBJECT * obj );
CK_BBOOL  object_is_public        ( OBJECT * obj );
CK_BBOOL  object_is_token_object  ( OBJECT * obj );
CK_BBOOL  object_is_session_object( OBJECT * obj );



// object attribute template routines
//

CK_RV     template_add_attributes( TEMPLATE     * tmpl,
                                   CK_ATTRIBUTE * attr,
                                   CK_ULONG       ulCount );

CK_RV     template_add_default_attributes( TEMPLATE * tmpl,
                                           CK_ULONG   class,
                                           CK_ULONG   subclass,
                                           CK_ULONG   mode );

CK_BBOOL  template_attribute_find( TEMPLATE           * tmpl,
                                   CK_ATTRIBUTE_TYPE    type,
                                   CK_ATTRIBUTE      ** attr);

void      template_attribute_find_multiple( TEMPLATE             *tmpl,
                                            ATTRIBUTE_PARSE_LIST *parselist,
                                            CK_ULONG              plcount );

CK_BBOOL  template_check_exportability( TEMPLATE *tmpl, CK_ATTRIBUTE_TYPE type );

CK_RV     template_check_required_attributes( TEMPLATE * tmpl,
                                              CK_ULONG   class,
                                              CK_ULONG   subclass,
                                              CK_ULONG   mode );

CK_RV     template_check_required_base_attributes( TEMPLATE * tmpl,
                                                   CK_ULONG   mode );

CK_BBOOL  template_compare( CK_ATTRIBUTE * t1,
                            CK_ULONG       ulCount,
                            TEMPLATE     * t2 );

CK_RV     template_copy( TEMPLATE * dest,
                         TEMPLATE * src );

CK_RV     template_flatten( TEMPLATE * tmpl,
                            CK_BYTE  * dest );

CK_RV     template_free( TEMPLATE *tmpl );

CK_BBOOL  template_get_class( TEMPLATE * tmpl,
                              CK_ULONG * class,
                              CK_ULONG * subclass );

CK_ULONG  template_get_count( TEMPLATE *tmpl );

CK_ULONG  template_get_size( TEMPLATE *tmpl );

CK_ULONG  template_get_compressed_size( TEMPLATE *tmpl );

CK_RV     template_set_default_common_attributes( TEMPLATE *tmpl );

CK_RV     template_merge( TEMPLATE *dest, TEMPLATE **src );

CK_RV     template_update_attribute( TEMPLATE * tmpl, CK_ATTRIBUTE * attr );

CK_RV     template_unflatten( TEMPLATE ** tmpl,
                              CK_BYTE   * data,
                              CK_ULONG    count );

CK_RV     template_unflatten_withSize( TEMPLATE ** new_tmpl,
				       CK_BYTE   * buf,
				       CK_ULONG    count,
				       int buf_size );

CK_RV     template_validate_attribute( TEMPLATE     * tmpl,
                                       CK_ATTRIBUTE * attr,
                                       CK_ULONG       class,
                                       CK_ULONG       subclass,
                                       CK_ULONG       mode );

CK_RV     template_validate_attributes( TEMPLATE * tmpl,
                                        CK_ULONG   class,
                                        CK_ULONG   subclass,
                                        CK_ULONG   mode );

CK_RV     template_validate_base_attribute( TEMPLATE     * tmpl,
                                            CK_ATTRIBUTE * attr,
                                            CK_ULONG       mode );



// DATA OBJECT ROUTINES
//
CK_RV     data_object_check_required_attributes ( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     data_object_set_default_attributes    ( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     data_object_validate_attribute        ( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// CERTIFICATE ROUTINES
//
CK_RV     cert_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cert_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

CK_RV     cert_x509_check_required_attributes   ( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cert_x509_set_default_attributes      ( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cert_x509_validate_attribute          ( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_RV     cert_vendor_check_required_attributes ( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cert_vendor_validate_attribute        ( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

//
// KEY ROUTINES
//

CK_RV     key_object_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     key_object_set_default_attributes   ( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     key_object_validate_attribute       ( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

CK_RV     publ_key_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     publ_key_set_default_attributes   ( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     publ_key_validate_attribute       ( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

CK_RV     priv_key_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     priv_key_set_default_attributes   ( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     priv_key_unwrap( TEMPLATE *tmpl, CK_ULONG keytype, CK_BYTE *data, CK_ULONG data_len );
CK_RV     priv_key_validate_attribute       ( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

CK_BBOOL  secret_key_check_exportability( CK_ATTRIBUTE_TYPE type );
CK_RV     secret_key_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     secret_key_set_default_attributes   ( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     secret_key_unwrap( TEMPLATE *tmpl, CK_ULONG keytype, CK_BYTE *data, CK_ULONG data_len, CK_BBOOL fromend );
CK_RV     secret_key_validate_attribute       ( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// rsa routines
//
CK_RV     rsa_publ_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     rsa_publ_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_RV     rsa_publ_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_BBOOL  rsa_priv_check_exportability( CK_ATTRIBUTE_TYPE type );
CK_RV     rsa_priv_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     rsa_priv_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     rsa_priv_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_RV     rsa_priv_wrap_get_data( TEMPLATE *tmpl, CK_BBOOL length_only, CK_BYTE **data, CK_ULONG *data_len );
CK_RV     rsa_priv_unwrap( TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len );

// dsa routines
//
CK_RV     dsa_publ_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     dsa_publ_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     dsa_publ_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_BBOOL  dsa_priv_check_exportability( CK_ATTRIBUTE_TYPE type );
CK_RV     dsa_priv_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     dsa_priv_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     dsa_priv_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_RV     dsa_priv_wrap_get_data( TEMPLATE *tmpl, CK_BBOOL length_only, CK_BYTE **data, CK_ULONG *data_len );
CK_RV     dsa_priv_unwrap( TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len );

// ecdsa routines
//
CK_RV     ecdsa_publ_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     ecdsa_publ_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     ecdsa_publ_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_BBOOL  ecdsa_priv_check_exportability( CK_ATTRIBUTE_TYPE type );
CK_RV     ecdsa_priv_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     ecdsa_priv_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     ecdsa_priv_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// diffie-hellman routines
//
CK_RV     dh_publ_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     dh_publ_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     dh_publ_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_BBOOL  dh_priv_check_exportability( CK_ATTRIBUTE_TYPE type );
CK_RV     dh_priv_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     dh_priv_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     dh_priv_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// KEA routines
//
CK_RV     kea_publ_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     kea_publ_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     kea_publ_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_BBOOL  kea_priv_check_exportability( CK_ATTRIBUTE_TYPE type );
CK_RV     kea_priv_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     kea_priv_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     kea_priv_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );


// Generic secret key routines
CK_RV     generic_secret_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     generic_secret_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     generic_secret_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_RV     generic_secret_wrap_get_data( TEMPLATE *tmpl, CK_BBOOL length_only, CK_BYTE **data, CK_ULONG *data_len );
CK_RV     generic_secret_unwrap( TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len, CK_BBOOL fromend );

// RC2 routines
CK_RV     rc2_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     rc2_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     rc2_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// RC4 routines
CK_RV     rc4_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     rc4_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     rc4_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// RC5 routines
CK_RV     rc5_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     rc5_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     rc5_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// DES routines
CK_RV     des_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_BBOOL  des_check_weak_key( CK_BYTE *key );
CK_RV     des_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     des_unwrap( TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len, CK_BBOOL fromend );
CK_RV     des_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_RV     des_wrap_get_data( TEMPLATE *tmpl, CK_BBOOL length_only, CK_BYTE **data, CK_ULONG *data_len );

// DES2 routines
CK_RV     des2_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     des2_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     des2_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// DES3 routines
CK_RV     des3_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     des3_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     des3_unwrap( TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len, CK_BBOOL fromend );
CK_RV     des3_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_RV     des3_wrap_get_data( TEMPLATE *tmpl, CK_BBOOL length_only, CK_BYTE **data, CK_ULONG *data_len );

// AES routines
CK_RV     aes_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     aes_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     aes_unwrap( TEMPLATE *tmpl, CK_BYTE *data, CK_ULONG data_len, CK_BBOOL fromend );
CK_RV     aes_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );
CK_RV     aes_wrap_get_data( TEMPLATE *tmpl, CK_BBOOL length_only, CK_BYTE **data, CK_ULONG *data_len );

// CAST routines
CK_RV     cast_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cast_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cast_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// CAST3 routines
CK_RV     cast3_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cast3_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cast3_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// CAST5 routines
CK_RV     cast5_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cast5_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cast5_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// IDEA routines
CK_RV     idea_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     idea_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     idea_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// CDMF routines
CK_RV     cdmf_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cdmf_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     cdmf_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// SKIPJACK routines
CK_RV     skipjack_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     skipjack_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     skipjack_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// BATON routines
CK_RV     baton_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     baton_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     baton_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );

// JUNIPER routines
CK_RV     juniper_check_required_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     juniper_set_default_attributes( TEMPLATE *tmpl, CK_ULONG mode );
CK_RV     juniper_validate_attribute( TEMPLATE *tmpl, CK_ATTRIBUTE *attr, CK_ULONG mode );


// modular math routines
//
CK_RV mp_subtract( CK_BYTE *bigint, CK_ULONG val, CK_ULONG len );

CK_RV mp_mult( CK_BYTE *bigint_a,  CK_ULONG a_len,
               CK_BYTE *bigint_b,  CK_ULONG b_len,
               CK_BYTE *bigint_c,  CK_ULONG c_len,
               CK_BYTE *result,    CK_ULONG *result_len );

CK_RV mp_exp( CK_BYTE *bigint_a,  CK_ULONG a_len,
              CK_BYTE *bigint_b,  CK_ULONG b_len,
              CK_BYTE *bigint_c,  CK_ULONG c_len,
              CK_BYTE *result,    CK_ULONG *result_len );

// ASN.1 routines
//
CK_ULONG ber_encode_INTEGER( CK_BBOOL    length_only,
                             CK_BYTE  ** ber_int,
                             CK_ULONG  * ber_int_len,
                             CK_BYTE   * data,
                             CK_ULONG    data_len );

CK_RV    ber_decode_INTEGER( CK_BYTE   * ber_int,
                             CK_BYTE  ** data,
                             CK_ULONG  * data_len,
                             CK_ULONG  * field_len );

CK_RV    ber_encode_OCTET_STRING( CK_BBOOL    length_only,
                                  CK_BYTE  ** str,
                                  CK_ULONG  * str_len,
                                  CK_BYTE   * data,
                                  CK_ULONG    data_len );

CK_RV    ber_decode_OCTET_STRING( CK_BYTE   * str,
                                  CK_BYTE  ** data,
                                  CK_ULONG  * data_len,
                                  CK_ULONG  * field_len );

CK_RV    ber_encode_SEQUENCE( CK_BBOOL    length_only,
                              CK_BYTE  ** seq,
                              CK_ULONG  * seq_len,
                              CK_BYTE   * data,
                              CK_ULONG    data_len );

CK_RV    ber_decode_SEQUENCE( CK_BYTE   * seq,
                              CK_BYTE  ** data,
                              CK_ULONG  * data_len,
                              CK_ULONG  * field_len );

CK_RV    ber_encode_PrivateKeyInfo( CK_BBOOL     length_only,
                                    CK_BYTE   ** data,
                                    CK_ULONG   * data_len,
                                    CK_BYTE    * algorithm_id,
                                    CK_ULONG     algorithm_id_len,
                                    CK_BYTE    * priv_key,
                                    CK_ULONG     priv_key_len );

CK_RV    ber_decode_PrivateKeyInfo( CK_BYTE    * data,
                                    CK_ULONG     data_len,
                                    CK_BYTE   ** algorithm_id,
                                    CK_ULONG   * alg_len,
                                    CK_BYTE   ** priv_key );

CK_RV    ber_encode_RSAPrivateKey( CK_BBOOL     length_only,
                                   CK_BYTE   ** data,
                                   CK_ULONG   * data_len,
                                   CK_ATTRIBUTE * modulus,
                                   CK_ATTRIBUTE * publ_exp,
#if 0
                                   CK_ATTRIBUTE * priv_exp,
                                   CK_ATTRIBUTE * prime1,
                                   CK_ATTRIBUTE * prime2,
                                   CK_ATTRIBUTE * exponent1,
                                   CK_ATTRIBUTE * exponent2,
                                   CK_ATTRIBUTE * coeff );
#else
				   CK_ATTRIBUTE * opaque );
#endif

CK_RV    ber_decode_RSAPrivateKey( CK_BYTE     * data,
                                   CK_ULONG      data_len,
                                   CK_ATTRIBUTE ** modulus,
                                   CK_ATTRIBUTE ** publ_exp,
#if 0
                                   CK_ATTRIBUTE ** priv_exp,
                                   CK_ATTRIBUTE ** prime1,
                                   CK_ATTRIBUTE ** prime2,
                                   CK_ATTRIBUTE ** exponent1,
                                   CK_ATTRIBUTE ** exponent2,
                                   CK_ATTRIBUTE ** coeff );
#else
				   CK_ATTRIBUTE ** opaque );
#endif


CK_RV    ber_encode_DSAPrivateKey( CK_BBOOL      length_only,
                                   CK_BYTE    ** data,
                                   CK_ULONG    * data_len,
                                   CK_ATTRIBUTE  * prime1,
                                   CK_ATTRIBUTE  * prime2,
                                   CK_ATTRIBUTE  * base,
                                   CK_ATTRIBUTE  * priv_key );

CK_RV    ber_decode_DSAPrivateKey( CK_BYTE     * data,
                                   CK_ULONG      data_len,
                                   CK_ATTRIBUTE ** prime,
                                   CK_ATTRIBUTE ** subprime,
                                   CK_ATTRIBUTE ** base,
                                   CK_ATTRIBUTE ** priv_key );


#include "tok_spec_struct.h"
extern token_spec_t token_specific;

#if (LEEDS_BUILD)
#pragma options align=full
#endif

/* logging */

void ock_err_log(int num, const char *layer, const char *file, int line);
void ock_logit(const char *fmt, ...);

#ifdef DEBUG
#define OCK_LOG_ERR(errnum)	ock_err_log(errnum, STDLL_NAME, __FILE__, __LINE__)
#define OCK_LOG_DEBUG(fmt, ...)           ock_logit("%s:%d " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
void dump_shm(const char *);
#define DUMP_SHM(x)		dump_shm(x)

#else

#define OCK_LOG_ERR(errnum)
#define OCK_LOG_DEBUG(fmt, ...)
#define DUMP_SHM(x)

#endif

#define OCK_SYSLOG(priority, fmt, ...) \
	syslog(priority, "%s " fmt, __FILE__, ##__VA_ARGS__); 


/* CKA_HIDDEN will be used to filter return results on a C_FindObjects call.
 * Used for objects internal to a token for management of that token */
#define CKA_HIDDEN              CKA_VENDOR_DEFINED + 0x01000000

CK_RV sw_des3_cbc(CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
		  CK_BYTE  *, CK_BYTE *, CK_BYTE);

#endif
