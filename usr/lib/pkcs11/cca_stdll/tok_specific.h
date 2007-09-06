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

// Token specific functions that tokens must implement.....
//
// Prototypes


#ifndef _TOK_SPECIFIC
#define _TOK_SPECIFIC

CK_RV token_rng(CK_BYTE *,  CK_ULONG);
int tok_slot2local(CK_SLOT_ID);
CK_RV token_specific_init(char *,CK_SLOT_ID );
CK_RV  token_specific_session(CK_SLOT_ID);
CK_RV token_specific_final(void);

CK_RV token_specific_des_key_gen(CK_BYTE *, CK_ULONG, CK_ULONG);

CK_RV token_specific_des_ecb(CK_BYTE *,
                  CK_ULONG ,
                  CK_BYTE *,
                  CK_ULONG *,
                  CK_BYTE  *,
                  CK_BYTE );

CK_RV token_specific_des_cbc(CK_BYTE *,
                  CK_ULONG ,
                  CK_BYTE *,
                  CK_ULONG *,
                  CK_BYTE  *,
                  CK_BYTE  *,
                  CK_BYTE );

CK_RV token_specific_tdes_ecb(CK_BYTE *,
                  CK_ULONG ,
                  CK_BYTE *,
                  CK_ULONG *,
                  CK_BYTE  *,
                  CK_BYTE );

CK_RV token_specific_tdes_cbc(CK_BYTE *,
                  CK_ULONG ,
                  CK_BYTE *,
                  CK_ULONG *,
                  CK_BYTE  *,
                  CK_BYTE  *,
                  CK_BYTE );

#if 0
CK_RV
token_specific_rsa_decrypt( CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   *,
                  OBJECT    *);

CK_RV
token_specific_rsa_encrypt( CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   * ,
                  OBJECT    * );
#else
CK_RV
token_specific_rsa_decrypt(CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   * ,
                  CK_ULONG  * ,
                  OBJECT    *);

CK_RV
token_specific_rsa_encrypt(CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   * ,
                  CK_ULONG  * ,
                  OBJECT    * );

CK_RV
token_specific_rsa_sign(CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   * ,
                  CK_ULONG  * ,
                  OBJECT    * );

CK_RV
token_specific_rsa_verify(CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   * ,
                  CK_ULONG    ,
                  OBJECT    * );
#endif

CK_RV
token_specific_rsa_generate_keypair( TEMPLATE  * ,
                            TEMPLATE  * );
/* Begin code contributed by Corrent corp. */
#ifndef NODH
CK_RV
token_specific_dh_pkcs_derive( CK_BYTE *,
                               CK_ULONG *,
                               CK_BYTE *,
                               CK_ULONG,
                               CK_BYTE *,
                               CK_ULONG,
                               CK_BYTE *,
                               CK_ULONG ) ;
 
CK_RV
token_specific_dh_pkcs_key_pair_gen( TEMPLATE  * publ_tmpl,
                                     TEMPLATE  * priv_tmpl );
#endif
/* End code contributed by Corrent corp. */
CK_RV
tok_cdmv_transform(CK_VOID_PTR, CK_ULONG);

CK_RV
ckm_dsa_sign( CK_BYTE   * ,
              CK_BYTE   * ,
              OBJECT    * );

CK_RV
ckm_dsa_key_pair_gen( TEMPLATE  * publ_tmpl,
                      TEMPLATE  * priv_tmpl );

CK_RV
ckm_dsa_verify( CK_BYTE   *,
                CK_BYTE   *,
                OBJECT    * );

CK_RV
token_specific_sha_init( DIGEST_CONTEXT * );

CK_RV
token_specific_sha_update(      DIGEST_CONTEXT  *,
                                CK_BYTE         *,
                                CK_ULONG);

CK_RV
token_specific_sha_final(       DIGEST_CONTEXT  *,
                                CK_BYTE         *,
                                CK_ULONG        * );
CK_RV
token_specific_sha2_init( DIGEST_CONTEXT * );

CK_RV
token_specific_sha2_update(      DIGEST_CONTEXT  *,
                                CK_BYTE         *,
                                CK_ULONG);

CK_RV
token_specific_sha2_final(       DIGEST_CONTEXT  *,
                                CK_BYTE         *,
                                CK_ULONG        * );
#ifndef NOAES
CK_RV
token_specific_aes_key_gen( CK_BYTE *,
                            CK_ULONG );

CK_RV
token_specific_aes_ecb( CK_BYTE  *,
                        CK_ULONG  ,
                        CK_BYTE  *,
                        CK_ULONG *,
                        CK_BYTE  *,
                        CK_ULONG  ,
                        CK_BYTE     );

CK_RV
token_specific_aes_cbc( CK_BYTE  *,
                        CK_ULONG  ,
                        CK_BYTE  *,
                        CK_ULONG *,
                        CK_BYTE  *,
                        CK_ULONG  ,
                        CK_BYTE  *,
                        CK_BYTE     );
#endif

CK_RV
token_specific_get_mechanism_list(CK_MECHANISM_TYPE_PTR pMechanismList,
                                  CK_ULONG_PTR pulCount);

CK_RV
token_specific_get_mechanism_info(CK_MECHANISM_TYPE type,
                                  CK_MECHANISM_INFO_PTR pInfo);

#endif

