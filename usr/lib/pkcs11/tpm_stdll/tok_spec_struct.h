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

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2002, 2005 */

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
   CK_BYTE  token_directory[PATH_MAX];  // Used to be in the token_local.h as a #def
   CK_BYTE  token_subdir[PATH_MAX];     // subdirectory
   CK_BYTE  token_debug_tag[PATH_MAX];  // debug logging tag

   CK_RV  (*t_init)(char *,CK_SLOT_ID);             // Initialization function
   int  (*t_slot2local)();       // convert the PKCS#11 slot to a local index
                                   // generaly not used but if a STDLL actualy
                                   // managed multiple devices, this would conv

   CK_RV  (*t_rng)(CK_BYTE *,CK_ULONG);          // Random Number Gen
   CK_RV  (*t_session)(CK_SLOT_ID);   //perform anything specific needed by the token takes a slot id
   CK_RV  (*t_final)();     // any specific final code
   CK_RV  (*t_des_key_gen)(CK_BYTE *,CK_ULONG);
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


   CK_RV (*t_rsa_decrypt)(CK_BYTE *,
			  CK_ULONG,
			  CK_BYTE *,
			  CK_ULONG *,
			  OBJECT *);

   CK_RV (*t_rsa_encrypt)(
			  CK_BYTE *,
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

   CK_RV (*t_rsa_generate_keypair)(TEMPLATE *, TEMPLATE *);
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
   CK_RV (*t_login)(CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
   CK_RV (*t_logout)();
   CK_RV (*t_init_pin)(CK_CHAR_PTR, CK_ULONG);
   CK_RV (*t_set_pin)(SESSION *, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR, CK_ULONG);
   CK_RV (*t_verify_so_pin)(CK_CHAR_PTR, CK_ULONG);
};

typedef  struct token_specific_struct token_spec_t;





#endif

