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

// Token specific functions that tokens must implement.....
//
// Prototypes


#ifndef _TOK_SPECIFIC
#define _TOK_SPECIFIC

#include "pqc_defs.h"

int token_specific_creatlock(STDLL_TokData_t *);
CK_RV token_specific_attach_shm(STDLL_TokData_t *, CK_ULONG);
CK_RV token_specific_rng(STDLL_TokData_t *, CK_BYTE *, CK_ULONG);
CK_RV token_specific_init(STDLL_TokData_t *, CK_SLOT_ID, char *);

CK_RV token_specific_init_token_data(STDLL_TokData_t *, CK_SLOT_ID slot_id);
CK_RV token_specific_load_token_data(STDLL_TokData_t *, CK_SLOT_ID slot_id,
                                     FILE *fh);
CK_RV token_specific_save_token_data(STDLL_TokData_t *, CK_SLOT_ID slot_id,
                                     FILE *fh);

CK_RV token_specific_final(STDLL_TokData_t *, CK_BBOOL);
CK_RV token_specific_init_token(STDLL_TokData_t *, CK_SLOT_ID, CK_CHAR_PTR,
                                CK_ULONG, CK_CHAR_PTR);
CK_RV token_specific_login(STDLL_TokData_t *, SESSION *, CK_USER_TYPE,
                           CK_CHAR_PTR, CK_ULONG);
CK_RV token_specific_logout(STDLL_TokData_t *);
CK_RV token_specific_init_pin(STDLL_TokData_t *, SESSION *, CK_CHAR_PTR,
                              CK_ULONG);
CK_RV token_specific_set_pin(STDLL_TokData_t *, SESSION *, CK_CHAR_PTR,
                             CK_ULONG, CK_CHAR_PTR, CK_ULONG);

CK_RV token_specific_des_key_gen(STDLL_TokData_t *, TEMPLATE *tmpl, CK_BYTE **,
                                 CK_ULONG *, CK_ULONG, CK_BBOOL *);

CK_RV token_specific_des_ecb(STDLL_TokData_t *,
                             CK_BYTE *,
                             CK_ULONG,
                             CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE);

CK_RV token_specific_des_cbc(STDLL_TokData_t *,
                             CK_BYTE *,
                             CK_ULONG,
                             CK_BYTE *,
                             CK_ULONG *, OBJECT *, CK_BYTE *, CK_BYTE);

CK_RV token_specific_tdes_ecb(STDLL_TokData_t *,
                              CK_BYTE *,
                              CK_ULONG,
                              CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE);

CK_RV token_specific_tdes_cbc(STDLL_TokData_t *,
                              CK_BYTE *,
                              CK_ULONG,
                              CK_BYTE *,
                              CK_ULONG *, OBJECT *, CK_BYTE *, CK_BYTE);

CK_RV token_specific_tdes_mac(STDLL_TokData_t *,
                              CK_BYTE *, CK_ULONG, OBJECT *, CK_BYTE *);

CK_RV token_specific_tdes_cmac(STDLL_TokData_t *,
                               CK_BYTE *, CK_ULONG, OBJECT *, CK_BYTE *,
                               CK_BBOOL, CK_BBOOL, CK_VOID_PTR *);

CK_RV token_specific_tdes_ofb(STDLL_TokData_t *,
                              CK_BYTE *,
                              CK_BYTE *,
                              CK_ULONG, OBJECT *, CK_BYTE *, uint_32);

CK_RV token_specific_tdes_cfb(STDLL_TokData_t *,
                              CK_BYTE *,
                              CK_BYTE *,
                              CK_ULONG, OBJECT *, CK_BYTE *, uint_32, uint_32);

CK_RV token_specific_rsa_decrypt(STDLL_TokData_t *,
                                 CK_BYTE *,
                                 CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *);

CK_RV token_specific_rsa_encrypt(STDLL_TokData_t *,
                                 CK_BYTE *,
                                 CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *);

CK_RV token_specific_rsa_generate_keypair(STDLL_TokData_t *tokdata, TEMPLATE *,
                                          TEMPLATE *);

CK_RV token_specific_rsa_sign(STDLL_TokData_t *, SESSION *, CK_BYTE *, CK_ULONG,
                              CK_BYTE *, CK_ULONG *, OBJECT *);

CK_RV token_specific_rsa_verify(STDLL_TokData_t *tokdata, SESSION *, CK_BYTE *,
                                CK_ULONG, CK_BYTE *, CK_ULONG, OBJECT *);

CK_RV token_specific_rsa_verify_recover(STDLL_TokData_t *tokdata, CK_BYTE *,
                                        CK_ULONG, CK_BYTE *, CK_ULONG *,
                                        OBJECT *);

CK_RV token_specific_rsa_x509_encrypt(STDLL_TokData_t *tokdata, CK_BYTE *,
                                      CK_ULONG, CK_BYTE *, CK_ULONG *,
                                      OBJECT *);

CK_RV token_specific_rsa_x509_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *,
                                      CK_ULONG, CK_BYTE *, CK_ULONG *,
                                      OBJECT *);

CK_RV token_specific_rsa_x509_sign(STDLL_TokData_t *tokdata, CK_BYTE *,
                                   CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *);

CK_RV token_specific_rsa_x509_verify(STDLL_TokData_t *tokdata, CK_BYTE *,
                                     CK_ULONG, CK_BYTE *, CK_ULONG, OBJECT *);

CK_RV token_specific_rsa_x509_verify_recover(STDLL_TokData_t *tokdata,
                                             CK_BYTE *, CK_ULONG, CK_BYTE *,
                                             CK_ULONG *, OBJECT *);

CK_RV token_specific_rsa_oaep_encrypt(STDLL_TokData_t *, ENCR_DECR_CONTEXT *,
                                      CK_BYTE *, CK_ULONG, CK_BYTE *,
                                      CK_ULONG *, CK_BYTE *, CK_ULONG);

CK_RV token_specific_rsa_oaep_decrypt(STDLL_TokData_t *, ENCR_DECR_CONTEXT *,
                                      CK_BYTE *, CK_ULONG, CK_BYTE *,
                                      CK_ULONG *, CK_BYTE *, CK_ULONG);

CK_RV token_specific_rsa_pss_sign(STDLL_TokData_t *, SESSION *,
                                  SIGN_VERIFY_CONTEXT *, CK_BYTE *, CK_ULONG,
                                  CK_BYTE *, CK_ULONG *);

CK_RV token_specific_rsa_pss_verify(STDLL_TokData_t *, SESSION *,
                                    SIGN_VERIFY_CONTEXT *, CK_BYTE *, CK_ULONG,
                                    CK_BYTE *, CK_ULONG);

CK_RV token_specific_ec_sign(STDLL_TokData_t *,
                             SESSION *,
                             CK_BYTE *,
                             CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *);

CK_RV token_specific_ec_verify(STDLL_TokData_t *,
                               SESSION *,
                               CK_BYTE *,
                               CK_ULONG, CK_BYTE *, CK_ULONG, OBJECT *);

CK_RV token_specific_ecdh_pkcs_derive(STDLL_TokData_t *tokdata, CK_BYTE *,
                                      CK_ULONG, CK_BYTE *, CK_ULONG, CK_BYTE *,
                                      CK_ULONG *, CK_BYTE *, CK_ULONG);

CK_RV token_specific_copy_object(SESSION *, CK_ATTRIBUTE_PTR, CK_ULONG,
                                 CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR);

CK_RV token_specific_ec_generate_keypair(STDLL_TokData_t *, TEMPLATE *,
                                         TEMPLATE *);

CK_RV token_specific_create_object(SESSION *, CK_ATTRIBUTE_PTR, CK_ULONG,
                                   CK_OBJECT_HANDLE_PTR);

CK_RV token_specific_generate_key(SESSION *, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR,
                                  CK_ULONG, CK_OBJECT_HANDLE_PTR);

CK_RV token_specific_generate_key_pair(SESSION *, CK_MECHANISM_PTR,
                                       CK_ATTRIBUTE_PTR, CK_ULONG,
                                       CK_ATTRIBUTE_PTR, CK_ULONG,
                                       CK_OBJECT_HANDLE_PTR,
                                       CK_OBJECT_HANDLE_PTR);


/* Begin code contributed by Corrent corp. */
#ifndef NODH
CK_RV token_specific_dh_pkcs_derive(STDLL_TokData_t *tokdata, CK_BYTE *,
                                    CK_ULONG *, CK_BYTE *, CK_ULONG, CK_BYTE *,
                                    CK_ULONG, CK_BYTE *, CK_ULONG);

CK_RV token_specific_dh_pkcs_key_pair_gen(STDLL_TokData_t *tokdata,
                                          TEMPLATE *publ_tmpl,
                                          TEMPLATE *priv_tmpl);
#endif
/* End code contributed by Corrent corp. */
CK_RV tok_cdmv_transform(CK_VOID_PTR, CK_ULONG);


CK_RV token_specific_sha_init(STDLL_TokData_t *, DIGEST_CONTEXT *,
                              CK_MECHANISM *);

CK_RV token_specific_sha(STDLL_TokData_t *, DIGEST_CONTEXT *, CK_BYTE *,
                         CK_ULONG, CK_BYTE *, CK_ULONG *);

CK_RV token_specific_sha_update(STDLL_TokData_t *, DIGEST_CONTEXT *, CK_BYTE *,
                                CK_ULONG);

CK_RV token_specific_sha_final(STDLL_TokData_t *, DIGEST_CONTEXT *, CK_BYTE *,
                               CK_ULONG *);

CK_RV token_specific_hmac_sign_init(STDLL_TokData_t *, SESSION *,
                                    CK_MECHANISM *, CK_OBJECT_HANDLE);

CK_RV token_specific_hmac_sign(STDLL_TokData_t *, SESSION *, CK_BYTE *,
                               CK_ULONG, CK_BYTE *, CK_ULONG *);

CK_RV token_specific_hmac_sign_update(STDLL_TokData_t *, SESSION *, CK_BYTE *,
                                      CK_ULONG);

CK_RV token_specific_hmac_sign_final(STDLL_TokData_t *, SESSION *, CK_BYTE *,
                                     CK_ULONG *);

CK_RV token_specific_hmac_verify_init(STDLL_TokData_t *, SESSION *,
                                      CK_MECHANISM *, CK_OBJECT_HANDLE);

CK_RV token_specific_hmac_verify(STDLL_TokData_t *, SESSION *, CK_BYTE *,
                                 CK_ULONG, CK_BYTE *, CK_ULONG);

CK_RV token_specific_hmac_verify_update(STDLL_TokData_t *, SESSION *,
                                        CK_BYTE *, CK_ULONG);

CK_RV token_specific_hmac_verify_final(STDLL_TokData_t *, SESSION *,
                                       CK_BYTE *, CK_ULONG);

CK_RV token_specific_generic_secret_key_gen(STDLL_TokData_t *,
                                            TEMPLATE *template);

CK_RV token_specific_aes_key_gen(STDLL_TokData_t *, TEMPLATE *tmpl,
                                 CK_BYTE **, CK_ULONG *, CK_ULONG, CK_BBOOL *);

CK_RV token_specific_aes_xts_key_gen(STDLL_TokData_t *, TEMPLATE *tmpl,
                                     CK_BYTE **, CK_ULONG *, CK_ULONG,
                                     CK_BBOOL *);

CK_RV token_specific_aes_ecb(STDLL_TokData_t *, SESSION *,
                             CK_BYTE *,
                             CK_ULONG,
                             CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE);

CK_RV token_specific_aes_cbc(STDLL_TokData_t *, SESSION *,
                             CK_BYTE *,
                             CK_ULONG,
                             CK_BYTE *,
                             CK_ULONG *, OBJECT *, CK_BYTE *, CK_BYTE);

CK_RV token_specific_aes_ctr(STDLL_TokData_t *,
                             CK_BYTE *,
                             CK_ULONG,
                             CK_BYTE *,
                             CK_ULONG *,
                             OBJECT *, CK_BYTE *, CK_ULONG, CK_BYTE);

CK_RV token_specific_aes_gcm_init(STDLL_TokData_t *, SESSION *,
                                  ENCR_DECR_CONTEXT *, CK_MECHANISM *,
                                  CK_OBJECT_HANDLE, CK_BYTE);

CK_RV token_specific_aes_gcm(STDLL_TokData_t *, SESSION *, ENCR_DECR_CONTEXT *,
                             CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
                             CK_BYTE);

CK_RV token_specific_aes_gcm_update(STDLL_TokData_t *, SESSION *,
                                    ENCR_DECR_CONTEXT *, CK_BYTE *,
                                    CK_ULONG, CK_BYTE *, CK_ULONG *, CK_BYTE);

CK_RV token_specific_aes_gcm_final(STDLL_TokData_t *, SESSION *,
                                   ENCR_DECR_CONTEXT *, CK_BYTE *,
                                   CK_ULONG *, CK_BYTE);

CK_RV token_specific_aes_ofb(STDLL_TokData_t *,
                             CK_BYTE *,
                             CK_ULONG, CK_BYTE *, OBJECT *, CK_BYTE *, uint_32);

CK_RV token_specific_aes_cfb(STDLL_TokData_t *,
                             CK_BYTE *,
                             CK_ULONG,
                             CK_BYTE *, OBJECT *, CK_BYTE *, uint_32, uint_32);

CK_RV token_specific_aes_mac(STDLL_TokData_t *,
                             CK_BYTE *, CK_ULONG, OBJECT *, CK_BYTE *);

CK_RV token_specific_aes_cmac(STDLL_TokData_t *,
                              CK_BYTE *, CK_ULONG, OBJECT *, CK_BYTE *,
                              CK_BBOOL, CK_BBOOL, CK_VOID_PTR *);

CK_RV token_specific_aes_xts(STDLL_TokData_t *, SESSION  *,
                             CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
                             OBJECT *, CK_BYTE *, CK_BBOOL, CK_BBOOL,
                             CK_BBOOL, CK_BYTE*);

CK_RV token_specific_dsa_generate_keypair(STDLL_TokData_t *,
                                          TEMPLATE *, TEMPLATE *);
CK_RV token_specific_dsa_sign(STDLL_TokData_t *, CK_BYTE *, CK_ULONG, CK_ULONG);

CK_RV token_specific_dsa_verify(STDLL_TokData_t *,
                                CK_BYTE *, CK_BYTE *, OBJECT *);

CK_RV token_specific_ibm_dilithium_generate_keypair(STDLL_TokData_t *,
                                                    const struct pqc_oid *,
                                                    TEMPLATE *, TEMPLATE *);

CK_RV token_specific_ibm_dilithium_sign(STDLL_TokData_t *, SESSION *, CK_BBOOL,
                                        const struct pqc_oid *,
                                        CK_BYTE *, CK_ULONG,
                                        CK_BYTE *, CK_ULONG *, OBJECT *);

CK_RV token_specific_ibm_dilithium_verify(STDLL_TokData_t *, SESSION *,
                                          const struct pqc_oid *,
                                          CK_BYTE *, CK_ULONG,
                                          CK_BYTE *, CK_ULONG, OBJECT *);

CK_RV token_specific_get_mechanism_list(STDLL_TokData_t *,
                                        CK_MECHANISM_TYPE_PTR pMechanismList,
                                        CK_ULONG_PTR pulCount);

CK_RV token_specific_get_mechanism_info(STDLL_TokData_t *,
                                        CK_MECHANISM_TYPE type,
                                        CK_MECHANISM_INFO_PTR pInfo);

CK_RV token_specific_object_add(STDLL_TokData_t *, SESSION *, OBJECT *);

CK_RV token_specific_key_wrap(STDLL_TokData_t *, SESSION *, CK_MECHANISM *,
                              CK_BBOOL, OBJECT *, OBJECT *, CK_BYTE *,
                              CK_ULONG *, CK_BBOOL *);

CK_RV token_specific_key_unwrap(STDLL_TokData_t *, SESSION *, CK_MECHANISM *,
                                CK_BYTE *, CK_ULONG, OBJECT *, OBJECT *,
                                CK_BBOOL *);

CK_RV token_specific_reencrypt_single(STDLL_TokData_t *, SESSION *,
                                      ENCR_DECR_CONTEXT *, CK_MECHANISM *,
                                      OBJECT *, ENCR_DECR_CONTEXT *,
                                      CK_MECHANISM *, OBJECT *, CK_BYTE *,
                                      CK_ULONG , CK_BYTE *, CK_ULONG *);

CK_RV token_specific_set_attribute_values(STDLL_TokData_t *, SESSION *,
                                          OBJECT *, TEMPLATE *);

CK_RV token_specific_set_attrs_for_new_object(STDLL_TokData_t *,
                                              CK_OBJECT_CLASS, CK_ULONG,
                                              TEMPLATE *);

CK_RV token_specific_handle_event(STDLL_TokData_t *tokdata,
                                  unsigned int event_type,
                                  unsigned int event_flags,
                                  const char *payload,
                                  unsigned int payload_len);

CK_RV token_specific_check_obj_access(STDLL_TokData_t *tokdata,
                                      OBJECT *obj, CK_BBOOL create);

#endif
