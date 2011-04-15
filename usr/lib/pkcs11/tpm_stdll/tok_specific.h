/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */

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

CK_RV token_specific_des_key_gen(CK_BYTE  *,CK_ULONG) ;

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

CK_RV
token_specific_rsa_decrypt( CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   * ,
		  CK_ULONG  * ,
                  OBJECT    *);

CK_RV
token_specific_rsa_encrypt( CK_BYTE   * ,
                   CK_ULONG    ,
                   CK_BYTE   * ,
		   CK_ULONG  * ,
                   OBJECT    * );

CK_RV
token_specific_rsa_sign( CK_BYTE   * ,
                   CK_ULONG    ,
                   CK_BYTE   * ,
		   CK_ULONG  * ,
                   OBJECT    * );

CK_RV
token_specific_rsa_verify( CK_BYTE   * ,
                   CK_ULONG    ,
                   CK_BYTE   * ,
		   CK_ULONG    ,
                   OBJECT    * );

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

CK_RV token_specific_login(CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
CK_RV token_specific_logout();
CK_RV token_specific_init_pin(CK_CHAR_PTR, CK_ULONG);
CK_RV token_specific_set_pin(SESSION *, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_ULONG);
CK_RV token_specific_verify_so_pin(CK_CHAR_PTR, CK_ULONG);
#endif

