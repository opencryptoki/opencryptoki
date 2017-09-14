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

int token_specific_creatlock(void);
CK_RV token_specific_attach_shm(CK_SLOT_ID slot_id, LW_SHM_TYPE **shmem);
CK_RV token_specific_rng(CK_BYTE *,  CK_ULONG);
CK_RV token_specific_init(STDLL_TokData_t *,CK_SLOT_ID, char *);

CK_RV token_specific_init_token_data(CK_SLOT_ID slot_id);
CK_RV token_specific_load_token_data(CK_SLOT_ID slot_id, FILE *fh);
CK_RV token_specific_save_token_data(CK_SLOT_ID slot_id, FILE *fh);

CK_RV token_specific_final(void);
CK_RV token_specific_init_token(STDLL_TokData_t *, CK_SLOT_ID, CK_CHAR_PTR,
				CK_ULONG, CK_CHAR_PTR);
CK_RV token_specific_login(STDLL_TokData_t *, SESSION *, CK_USER_TYPE,
			   CK_CHAR_PTR, CK_ULONG);
CK_RV token_specific_logout();
CK_RV token_specific_init_pin(STDLL_TokData_t *, SESSION *, CK_CHAR_PTR, CK_ULONG);
CK_RV token_specific_set_pin(STDLL_TokData_t *, SESSION *, CK_CHAR_PTR,
			     CK_ULONG, CK_CHAR_PTR, CK_ULONG);

CK_RV token_specific_des_key_gen(STDLL_TokData_t *, CK_BYTE  *,CK_ULONG, CK_ULONG) ;

CK_RV token_specific_des_ecb(STDLL_TokData_t *,
		  CK_BYTE *,
                  CK_ULONG ,
                  CK_BYTE *,
                  CK_ULONG *,
                  OBJECT  *,
                  CK_BYTE );

CK_RV token_specific_des_cbc(STDLL_TokData_t *,
		  CK_BYTE *,
                  CK_ULONG ,
                  CK_BYTE *,
                  CK_ULONG *,
                  OBJECT  *,
                  CK_BYTE  *,
                  CK_BYTE );

CK_RV token_specific_tdes_ecb(CK_BYTE *,
                  CK_ULONG ,
                  CK_BYTE *,
                  CK_ULONG *,
                  OBJECT  *,
                  CK_BYTE );

CK_RV token_specific_tdes_cbc(CK_BYTE *,
                  CK_ULONG ,
                  CK_BYTE *,
                  CK_ULONG *,
                  OBJECT  *,
                  CK_BYTE  *,
                  CK_BYTE );

CK_RV token_specific_tdes_mac(CK_BYTE *,
                       CK_ULONG ,
                       OBJECT  *,
                       CK_BYTE *);

CK_RV token_specific_tdes_ofb(CK_BYTE *,
                       CK_BYTE  *,
                       CK_ULONG  ,
                       OBJECT   *,
                       CK_BYTE  *,
                       uint_32 );

CK_RV token_specific_tdes_cfb(CK_BYTE *,
                       CK_BYTE *,
                       CK_ULONG ,
                       OBJECT  *,
                       CK_BYTE *,
                       uint_32,
                       uint_32 );

CK_RV
token_specific_rsa_decrypt( CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   *,
                  CK_ULONG  *,
                  OBJECT    *);

CK_RV
token_specific_rsa_encrypt( CK_BYTE   * ,
                   CK_ULONG    ,
                   CK_BYTE   * ,
                   CK_ULONG  *,
                   OBJECT    * );

CK_RV
token_specific_rsa_generate_keypair( TEMPLATE  * ,
                            TEMPLATE  * );

CK_RV
token_specific_rsa_sign(CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
                                OBJECT *);

CK_RV
token_specific_rsa_verify(CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG,
                                OBJECT *);

CK_RV
token_specific_rsa_verify_recover(CK_BYTE *, CK_ULONG, CK_BYTE *,
                                CK_ULONG *, OBJECT *);

CK_RV
token_specific_rsa_x509_encrypt(CK_BYTE *, CK_ULONG, CK_BYTE *,
                                CK_ULONG *, OBJECT *);

CK_RV
token_specific_rsa_x509_decrypt(CK_BYTE *, CK_ULONG, CK_BYTE *,
                                CK_ULONG *, OBJECT *);

CK_RV
token_specific_rsa_x509_sign(CK_BYTE *, CK_ULONG, CK_BYTE *,
			     CK_ULONG *, OBJECT *);

CK_RV
token_specific_rsa_x509_verify(CK_BYTE *, CK_ULONG, CK_BYTE *,
				CK_ULONG, OBJECT *);

CK_RV
token_specific_rsa_x509_verify_recover(CK_BYTE *, CK_ULONG, CK_BYTE *,
					CK_ULONG *, OBJECT *);

CK_RV token_specific_rsa_oaep_encrypt(ENCR_DECR_CONTEXT *, CK_BYTE *,
				      CK_ULONG, CK_BYTE *, CK_ULONG *,
				      CK_BYTE *, CK_ULONG);

CK_RV token_specific_rsa_oaep_decrypt(ENCR_DECR_CONTEXT *, CK_BYTE *,
				      CK_ULONG, CK_BYTE *, CK_ULONG *,
				      CK_BYTE *, CK_ULONG);

CK_RV token_specific_rsa_pss_sign(SIGN_VERIFY_CONTEXT *, CK_BYTE *, CK_ULONG,
				  CK_BYTE *, CK_ULONG *);

CK_RV token_specific_rsa_pss_verify(SIGN_VERIFY_CONTEXT *, CK_BYTE *,
				    CK_ULONG, CK_BYTE *, CK_ULONG);

CK_RV
token_specific_ec_sign(STDLL_TokData_t *,
		  CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   * ,
                  CK_ULONG  * ,
                  OBJECT    * );

CK_RV
token_specific_ec_verify(STDLL_TokData_t *,
		  CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   * ,
                  CK_ULONG    ,
                  OBJECT    * );

CK_RV
token_specific_copy_object(SESSION *, CK_ATTRIBUTE_PTR, CK_ULONG,
			   CK_OBJECT_HANDLE, CK_OBJECT_HANDLE_PTR);

CK_RV
token_specific_ec_generate_keypair( STDLL_TokData_t *, TEMPLATE  * , TEMPLATE  * );

CK_RV
token_specific_create_object(SESSION *, CK_ATTRIBUTE_PTR, CK_ULONG,
			     CK_OBJECT_HANDLE_PTR);

CK_RV
token_specific_generate_key(SESSION *, CK_MECHANISM_PTR, CK_ATTRIBUTE_PTR,
			    CK_ULONG, CK_OBJECT_HANDLE_PTR);

CK_RV
token_specific_generate_key_pair(SESSION *, CK_MECHANISM_PTR,
				 CK_ATTRIBUTE_PTR, CK_ULONG,
				 CK_ATTRIBUTE_PTR, CK_ULONG,
				 CK_OBJECT_HANDLE_PTR, CK_OBJECT_HANDLE_PTR);


/* Begin code contributed by Corrent corp. */
#ifndef NODH
CK_RV
token_specific_dh_pkcs_derive( STDLL_TokData_t *tokdata, CK_BYTE *, CK_ULONG *,
                               CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG,
                               CK_BYTE *, CK_ULONG ) ;

CK_RV
token_specific_dh_pkcs_key_pair_gen(STDLL_TokData_t *tokdata,
				    TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl);
#endif
/* End code contributed by Corrent corp. */
CK_RV
tok_cdmv_transform(CK_VOID_PTR, CK_ULONG);


CK_RV token_specific_sha_init(DIGEST_CONTEXT *, CK_MECHANISM *);

CK_RV token_specific_sha(DIGEST_CONTEXT *, CK_BYTE *, CK_ULONG, CK_BYTE *,
			 CK_ULONG *);

CK_RV token_specific_sha_update(DIGEST_CONTEXT *, CK_BYTE *, CK_ULONG);

CK_RV token_specific_sha_final(DIGEST_CONTEXT *, CK_BYTE *, CK_ULONG *);

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
					CK_BYTE *,CK_ULONG);

CK_RV token_specific_hmac_verify_final(STDLL_TokData_t *, SESSION *,
				       CK_BYTE *, CK_ULONG);

CK_RV token_specific_generic_secret_key_gen(STDLL_TokData_t *,
					    TEMPLATE *template);

#ifndef NOAES
CK_RV
token_specific_aes_key_gen( CK_BYTE *,
                            CK_ULONG,
			    CK_ULONG );

CK_RV
token_specific_aes_ecb( CK_BYTE  *,
                        CK_ULONG  ,
                        CK_BYTE  *,
                        CK_ULONG *,
                        OBJECT  *,
                        CK_BYTE     );

CK_RV
token_specific_aes_cbc( CK_BYTE  *,
                        CK_ULONG  ,
                        CK_BYTE  *,
                        CK_ULONG *,
                        OBJECT  *,
                        CK_BYTE  *,
                        CK_BYTE     );

CK_RV
token_specific_aes_ctr( CK_BYTE  *,
                        CK_ULONG  ,
                        CK_BYTE  *,
                        CK_ULONG *,
                        OBJECT *,
                        CK_BYTE  *,
			CK_ULONG  ,
                        CK_BYTE     );

CK_RV token_specific_aes_gcm_init(SESSION *, ENCR_DECR_CONTEXT *,
				  CK_MECHANISM *, CK_OBJECT_HANDLE, CK_BYTE);

CK_RV token_specific_aes_gcm(SESSION *, ENCR_DECR_CONTEXT *, CK_BYTE *,
			     CK_ULONG, CK_BYTE *, CK_ULONG *, CK_BYTE);

CK_RV token_specific_aes_gcm_update(SESSION *, ENCR_DECR_CONTEXT *, CK_BYTE *,
				    CK_ULONG, CK_BYTE *, CK_ULONG *, CK_BYTE);

CK_RV token_specific_aes_gcm_final(SESSION *, ENCR_DECR_CONTEXT *, CK_BYTE *,
				   CK_ULONG *, CK_BYTE);

CK_RV
token_specific_aes_ofb( CK_BYTE *,
                        CK_ULONG,
                        CK_BYTE *,
                        OBJECT *,
                        CK_BYTE *,
                        uint_32 );

CK_RV
token_specific_aes_cfb( CK_BYTE *,
                        CK_ULONG,
                        CK_BYTE *,
                        OBJECT *,
                        CK_BYTE *,
                        uint_32,
                        uint_32 );

CK_RV token_specific_aes_mac(CK_BYTE *,
                             CK_ULONG ,
                             OBJECT *,
                             CK_BYTE *);

#endif

CK_RV
token_specific_dsa_generate_keypair( TEMPLATE *,
                            TEMPLATE *);
CK_RV
token_specific_dsa_sign( CK_BYTE *,
                         CK_ULONG,
                         CK_ULONG );

CK_RV
token_specific_dsa_verify( CK_BYTE *,
                           CK_BYTE *,
                           OBJECT * );

CK_RV
token_specific_get_mechanism_list(STDLL_TokData_t *,
				  CK_MECHANISM_TYPE_PTR pMechanismList,
                                  CK_ULONG_PTR pulCount);

CK_RV
token_specific_get_mechanism_info(CK_MECHANISM_TYPE type,
                                  CK_MECHANISM_INFO_PTR pInfo);

CK_RV
token_specific_object_add(OBJECT *);

#endif
