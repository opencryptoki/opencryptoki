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
CK_RV

token_specific_ec_sign(CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   * ,
                  CK_ULONG  * ,
                  OBJECT    * );

CK_RV
token_specific_ec_verify(CK_BYTE   * ,
                  CK_ULONG    ,
                  CK_BYTE   * ,
                  CK_ULONG    ,
                  OBJECT    * );
#endif

CK_RV
token_specific_rsa_generate_keypair( TEMPLATE  * ,
                            TEMPLATE  * );

CK_RV
token_specific_ec_generate_keypair( TEMPLATE  * ,
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

// Elliptic Curve type
//
#define PRIME_CURVE		0x00
#define BRAINPOOL_CURVE		0x01

// Elliptic Curve length in bits
//
#define CURVE160		0x00A0
#define CURVE192		0x00C0
#define CURVE224		0x00E0
#define CURVE256		0x0100
#define CURVE320		0x0140
#define CURVE384		0x0180
#define CURVE512		0x0200
#define CURVE521		0x0209

/* Supported Elliptic Curves */
#define NUMEC			12	/* number of supported curves */
CK_BYTE brainpoolP160r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x01 };
CK_BYTE brainpoolP192r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x03 };
CK_BYTE brainpoolP224r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x05 };
CK_BYTE brainpoolP256r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07 };
CK_BYTE brainpoolP320r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x09 };
CK_BYTE brainpoolP384r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0B };
CK_BYTE brainpoolP512r1[] = { 0x06, 0x09, 0x2B, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0D };
CK_BYTE prime192[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x01 };
CK_BYTE secp224[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x21 };
CK_BYTE prime256[] = { 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07 };
CK_BYTE secp384[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x22 };
CK_BYTE secp521[] = { 0x06, 0x05, 0x2B, 0x81, 0x04, 0x00, 0x23 };

// structure of supported Elliptic Curves

struct _ec {
	uint8_t		curve_type;	/* uint8_t - prime or brainpool curve */
	uint16_t	len_bits;	/* uint16_t - len in bits */
	CK_ULONG	data_size;
	CK_VOID_PTR	data;
}__attribute__ ((__packed__));

struct _ec der_ec_supported[NUMEC] = {
	{BRAINPOOL_CURVE, CURVE160, sizeof(brainpoolP160r1), &brainpoolP160r1},
	{BRAINPOOL_CURVE, CURVE192, sizeof(brainpoolP192r1), &brainpoolP192r1},
	{BRAINPOOL_CURVE, CURVE224, sizeof(brainpoolP224r1), &brainpoolP224r1},
	{BRAINPOOL_CURVE, CURVE256, sizeof(brainpoolP256r1), &brainpoolP256r1},
	{BRAINPOOL_CURVE, CURVE320, sizeof(brainpoolP320r1), &brainpoolP320r1},
	{BRAINPOOL_CURVE, CURVE384, sizeof(brainpoolP384r1), &brainpoolP384r1},
	{BRAINPOOL_CURVE, CURVE512, sizeof(brainpoolP512r1), &brainpoolP512r1},
	{PRIME_CURVE, CURVE192, sizeof(prime192), &prime192},
	{PRIME_CURVE, CURVE224, sizeof(secp224), &secp224},
	{PRIME_CURVE, CURVE256, sizeof(prime256), &prime256},
	{PRIME_CURVE, CURVE384, sizeof(secp384), &secp384},
	{PRIME_CURVE, CURVE521, sizeof(secp521), &secp521},
};

#endif

