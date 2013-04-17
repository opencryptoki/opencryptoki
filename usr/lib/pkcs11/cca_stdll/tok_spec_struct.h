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

#ifndef _TOK_SPECIFIC_STRUCT
#define _TOK_SPECIFIC_STRUCT

struct token_specific_struct{
   CK_BYTE  token_directory[2048];  // Used to be in the token_local.h as a #def
   CK_BYTE  token_subdir[2048];     // subdirectory
   CK_BYTE  token_debug_tag[2048];  // debug logging tag

   CK_RV  (*t_init)(char *,CK_SLOT_ID);             // Initialization function
   int  (*t_slot2local)();       // convert the PKCS#11 slot to a local index
                                   // generaly not used but if a STDLL actually
                                   // managed multiple devices, this would conv
                                   
   CK_RV  (*t_rng)(CK_BYTE *,CK_ULONG);          // Random Number Gen
   CK_RV  (*t_session)(CK_SLOT_ID);   //perform anything specific needed by the token takes a slot id
   CK_RV  (*t_final)();     // any specific final code
   CK_RV  (*t_des_key_gen)(CK_BYTE *, CK_ULONG, CK_ULONG);
   CK_RV  (*t_des_ecb)(
                         CK_BYTE *, CK_ULONG,
                         CK_BYTE *, CK_ULONG *, CK_BYTE *, CK_BYTE);
   CK_RV  (*t_des_cbc)(
                         CK_BYTE *, CK_ULONG,
                         CK_BYTE *, CK_ULONG *, CK_BYTE *,CK_BYTE *, CK_BYTE);

   CK_RV  (*t_tdes_ecb)(
                         CK_BYTE *, CK_ULONG,
                         CK_BYTE *, CK_ULONG *, CK_BYTE *, CK_BYTE);
   CK_RV  (*t_tdes_cbc)(
                         CK_BYTE *, CK_ULONG,
                         CK_BYTE *, CK_ULONG *, CK_BYTE *,CK_BYTE *, CK_BYTE);

#if 0
   CK_RV (*t_rsa_decrypt)(    CK_BYTE *,
                              CK_ULONG,
                              CK_BYTE *,
                              OBJECT *);
             
   CK_RV (*t_rsa_encrypt)(
                              CK_BYTE *,
                              CK_ULONG, 
                              CK_BYTE *,
                              OBJECT *);
#else
   CK_RV (*t_rsa_decrypt)(CK_BYTE *,
                          CK_ULONG,
                          CK_BYTE *,
                          CK_ULONG *,
                          OBJECT *);

   CK_RV (*t_rsa_encrypt)(CK_BYTE *,
                          CK_ULONG,
                          CK_BYTE *,
                          CK_ULONG *,
                          OBJECT *);

   CK_RV (*t_rsa_sign)(CK_BYTE *,
                       CK_ULONG,
                       CK_BYTE *,
                       CK_ULONG *,
                       OBJECT *);

   CK_RV (*t_rsa_verify)(CK_BYTE *,
                         CK_ULONG,
                         CK_BYTE *,
                         CK_ULONG,
                         OBJECT *);

   CK_RV (*t_ec_sign)(CK_BYTE *,
                       CK_ULONG,
                       CK_BYTE *,
                       CK_ULONG *,
                       OBJECT *);

   CK_RV (*t_ec_verify)(CK_BYTE *,
                         CK_ULONG,
                         CK_BYTE *,
                         CK_ULONG,
                         OBJECT *);
#endif

   CK_RV (*t_rsa_generate_keypair)(TEMPLATE *, TEMPLATE *);
   CK_RV (*t_ec_generate_keypair)(TEMPLATE *, TEMPLATE *);
/* Begin code contributed by Corrent corp. */
#ifndef NODH
   // Token Specific DH functions
 
   CK_RV (*t_dh_pkcs_derive) ( CK_BYTE *,
                               CK_ULONG *,
                               CK_BYTE *,
                               CK_ULONG,
                               CK_BYTE *,
                               CK_ULONG,
                               CK_BYTE *,
                               CK_ULONG ) ;
 
   CK_RV (*t_dh_pkcs_key_pair_gen)(TEMPLATE *, TEMPLATE *);
#endif
/* End code contributed by Corrent corp. */
   // Token Specific SHA1 functions
   CK_RV (*t_sha_init)(DIGEST_CONTEXT *);
 
   CK_RV (*t_sha_update)(
		   	DIGEST_CONTEXT *,
			CK_BYTE	*,
			CK_ULONG);
 
   CK_RV (*t_sha_final)(
		   	DIGEST_CONTEXT *,
			CK_BYTE *,
			CK_ULONG *);
   // Token Specific SHA256 functions
   CK_RV (*t_sha2_init)(DIGEST_CONTEXT *);
 
   CK_RV (*t_sha2_update)(
		   	DIGEST_CONTEXT *,
			CK_BYTE	*,
			CK_ULONG);
 
   CK_RV (*t_sha2_final)(
		   	DIGEST_CONTEXT *,
			CK_BYTE *,
			CK_ULONG *);
#ifndef NOAES
   // Token Specific AES functions
   CK_RV (*t_aes_key_gen)(
			CK_BYTE *,
			CK_ULONG);
 
   CK_RV (*t_aes_ecb)(
		   	CK_BYTE *,
			CK_ULONG,
			CK_BYTE *,
			CK_ULONG *,
			CK_BYTE *,
			CK_ULONG,
			CK_BYTE);
 
   CK_RV (*t_aes_cbc)(
		   	CK_BYTE *,
			CK_ULONG,
			CK_BYTE *,
			CK_ULONG *,
			CK_BYTE *,
			CK_ULONG,
			CK_BYTE *,
			CK_BYTE);
#endif
	CK_RV (*t_get_mechanism_list)(CK_MECHANISM_TYPE_PTR,
				      CK_ULONG_PTR);
	CK_RV (*t_get_mechanism_info)(CK_MECHANISM_TYPE,
				      CK_MECHANISM_INFO_PTR);
	CK_RV (*t_object_add)(OBJECT *);
};

typedef struct token_specific_struct token_spec_t;

#endif

