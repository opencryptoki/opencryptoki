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

#ifndef _TOK_SPECIFIC_STRUCT
#define _TOK_SPECIFIC_STRUCT


struct token_specific_struct {
	// Used to be in the token_local.h as a #def
	CK_BYTE token_directory[PATH_MAX];

	// Subdirectory
	CK_BYTE token_subdir[PATH_MAX];

	// Set to keysize for secure key tokens
	int token_keysize;

	// Information about how token's data should be stored.
	struct {
		// Use a separate directory for each user
		CK_BBOOL per_user;

		// Use data store?
		CK_BBOOL use_master_key;

		// Algorithm used to store private data (should be one of the
		// CKM_* macros).
		CK_MECHANISM_TYPE encryption_algorithm;

		// Default Initialization vectors used for each token. Its size
		// depends on the used algorithm.
		CK_BYTE *pin_initial_vector;
		CK_BYTE *obj_initial_vector;
	} data_store;

	// Create lockfile if different from standard way.
	int (*t_creatlock) (void);

	// Create or attach to token's shared memory
	CK_RV (*t_attach_shm) (CK_SLOT_ID slot_id, LW_SHM_TYPE **shmem);

	// Initialization function
	CK_RV(*t_init) (CK_SLOT_ID, char *);

	// Token data functions
	CK_RV (*t_init_token_data) (CK_SLOT_ID slot_id);
	CK_RV (*t_load_token_data) (CK_SLOT_ID slot_id, FILE *fh);
	CK_RV (*t_save_token_data) (CK_SLOT_ID slot_id, FILE *fh);

	// Random Number Gen
	CK_RV(*t_rng) (CK_BYTE *, CK_ULONG);

	// any specific final code
	CK_RV(*t_final) ();

	CK_RV(*t_init_token) (CK_SLOT_ID, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR);
	CK_RV(*t_login) (SESSION *, CK_USER_TYPE, CK_CHAR_PTR, CK_ULONG);
	CK_RV(*t_logout) ();
	CK_RV(*t_init_pin) (SESSION *, CK_CHAR_PTR, CK_ULONG);
	CK_RV(*t_set_pin) (SESSION *, CK_CHAR_PTR, CK_ULONG, CK_CHAR_PTR,
			   CK_ULONG);

	CK_RV(*t_des_key_gen) (CK_BYTE *, CK_ULONG, CK_ULONG);
	CK_RV(*t_des_ecb) (CK_BYTE *, CK_ULONG,
			   CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE);
	CK_RV(*t_des_cbc) (CK_BYTE *, CK_ULONG,
			   CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE *,
			   CK_BYTE);

	CK_RV(*t_tdes_ecb) (CK_BYTE *, CK_ULONG,
			    CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE);
	CK_RV(*t_tdes_cbc) (CK_BYTE *, CK_ULONG,
			    CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE *,
			    CK_BYTE);

	CK_RV(*t_tdes_ofb)(CK_BYTE *, CK_BYTE *, CK_ULONG, OBJECT *, CK_BYTE *,
			   uint_32);

	CK_RV(*t_tdes_cfb)(CK_BYTE *, CK_BYTE *, CK_ULONG, OBJECT *, CK_BYTE *,
			   uint_32, uint_32);

	CK_RV(*t_tdes_mac)(CK_BYTE *, CK_ULONG, OBJECT *, CK_BYTE *);

	CK_RV(*t_rsa_decrypt) (CK_BYTE *,
				CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *);

	CK_RV(*t_rsa_encrypt) (CK_BYTE *,
				CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *);

	CK_RV(*t_rsa_sign) (CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
			    OBJECT *);
	CK_RV(*t_rsa_verify) (CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG,
			      OBJECT *);

	CK_RV(*t_rsa_verify_recover) (CK_BYTE *, CK_ULONG, CK_BYTE *,
				      CK_ULONG *, OBJECT *);

	CK_RV(*t_rsa_x509_decrypt) (CK_BYTE *, CK_ULONG, CK_BYTE *,
				    CK_ULONG *, OBJECT *);

	CK_RV(*t_rsa_x509_encrypt) (CK_BYTE *, CK_ULONG, CK_BYTE *,
				    CK_ULONG *, OBJECT *);

	CK_RV(*t_rsa_x509_sign) (CK_BYTE *, CK_ULONG, CK_BYTE *,
				 CK_ULONG *, OBJECT *);

	CK_RV(*t_rsa_x509_verify) (CK_BYTE *, CK_ULONG, CK_BYTE *,
				   CK_ULONG, OBJECT *);

	CK_RV(*t_rsa_x509_verify_recover) (CK_BYTE *, CK_ULONG, CK_BYTE *,
					   CK_ULONG *, OBJECT *);

        CK_RV(*t_rsa_oaep_decrypt) (ENCR_DECR_CONTEXT *, CK_BYTE *, CK_ULONG,
                                    CK_BYTE *, CK_ULONG *, CK_BYTE *, CK_ULONG);

        CK_RV(*t_rsa_oaep_encrypt) (ENCR_DECR_CONTEXT *, CK_BYTE *, CK_ULONG,
                                    CK_BYTE *, CK_ULONG *, CK_BYTE *, CK_ULONG);

        CK_RV(*t_rsa_pss_sign) (SIGN_VERIFY_CONTEXT *, CK_BYTE *, CK_ULONG,
                                CK_BYTE *, CK_ULONG *);

        CK_RV(*t_rsa_pss_verify) (SIGN_VERIFY_CONTEXT *, CK_BYTE *, CK_ULONG,
                                  CK_BYTE *, CK_ULONG);

	CK_RV(*t_rsa_generate_keypair) (TEMPLATE *, TEMPLATE *);

	CK_RV(*t_ec_sign) (CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
			   OBJECT *);
	CK_RV(*t_ec_verify) (CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG,
			     OBJECT *);
	CK_RV(*t_ec_generate_keypair) (TEMPLATE *, TEMPLATE *);


	/* Begin code contributed by Corrent corp. */

	// Token Specific DH functions
	CK_RV(*t_dh_pkcs_derive) (CK_BYTE *,
				  CK_ULONG *,
				  CK_BYTE *,
				  CK_ULONG,
				  CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG);

	CK_RV(*t_dh_pkcs_key_pair_gen) (TEMPLATE *, TEMPLATE *);

	/* End code contributed by Corrent corp. */

	// Token Specific SHA1 functions
	CK_RV(*t_sha_init) (DIGEST_CONTEXT *, CK_MECHANISM *);
	CK_RV(*t_sha) (DIGEST_CONTEXT *, CK_BYTE *, CK_ULONG, CK_BYTE *,
		       CK_ULONG *);
	CK_RV(*t_sha_update) (DIGEST_CONTEXT *, CK_BYTE *, CK_ULONG);
	CK_RV(*t_sha_final) (DIGEST_CONTEXT *, CK_BYTE *, CK_ULONG *);

	// Token Specific HMAC
	CK_RV(*t_hmac_sign_init) (SESSION *, CK_MECHANISM *, CK_OBJECT_HANDLE);
	CK_RV(*t_hmac_sign) (SESSION *, CK_BYTE *, CK_ULONG, CK_BYTE *,
			     CK_ULONG *);
	CK_RV(*t_hmac_sign_update) (SESSION *, CK_BYTE *, CK_ULONG);
	CK_RV(*t_hmac_sign_final) (SESSION *, CK_BYTE *, CK_ULONG *);

	CK_RV(*t_hmac_verify_init) (SESSION *, CK_MECHANISM *,
				    CK_OBJECT_HANDLE);
	CK_RV(*t_hmac_verify) (SESSION *, CK_BYTE *, CK_ULONG, CK_BYTE *,
			       CK_ULONG);
	CK_RV(*t_hmac_verify_update) (SESSION *, CK_BYTE *, CK_ULONG);
	CK_RV(*t_hmac_verify_final) (SESSION *, CK_BYTE *, CK_ULONG);

	CK_RV (*t_generic_secret_key_gen) (TEMPLATE *);

	// Token Specific AES functions
	CK_RV(*t_aes_key_gen) (CK_BYTE *, CK_ULONG, CK_ULONG);

	CK_RV(*t_aes_ecb) (CK_BYTE *,
			   CK_ULONG,
			   CK_BYTE *,
			   CK_ULONG *, OBJECT *, CK_BYTE);

	CK_RV(*t_aes_cbc) (CK_BYTE *,
			   CK_ULONG,
			   CK_BYTE *,
			   CK_ULONG *,
			   OBJECT *, CK_BYTE *, CK_BYTE);

	CK_RV(*t_aes_ctr) (CK_BYTE *,
			   CK_ULONG,
			   CK_BYTE *,
			   CK_ULONG *,
			   OBJECT *, CK_BYTE *, CK_ULONG, CK_BYTE);

	CK_RV(*t_aes_gcm_init) (SESSION *, ENCR_DECR_CONTEXT *, CK_MECHANISM *,
				CK_OBJECT_HANDLE, CK_BYTE);

	CK_RV(*t_aes_gcm) (SESSION *, ENCR_DECR_CONTEXT *, CK_BYTE *, CK_ULONG,
			   CK_BYTE *, CK_ULONG *, CK_BYTE);

	CK_RV(*t_aes_gcm_update) (SESSION *, ENCR_DECR_CONTEXT *, CK_BYTE *,
				  CK_ULONG, CK_BYTE *, CK_ULONG *, CK_BYTE);

	CK_RV(*t_aes_gcm_final) (SESSION *, ENCR_DECR_CONTEXT *, CK_BYTE *,
				 CK_ULONG *, CK_BYTE);

	CK_RV(*t_aes_ofb)(CK_BYTE *, CK_ULONG, CK_BYTE *, OBJECT *, CK_BYTE *,
			  uint_32);

	CK_RV(*t_aes_cfb)(CK_BYTE *, CK_ULONG, CK_BYTE *, OBJECT *, CK_BYTE *,
			  uint_32 , uint_32);

        CK_RV(*t_aes_mac)(CK_BYTE *, CK_ULONG,   OBJECT *, CK_BYTE *);

	// Token Specific DSA functions
	CK_RV(*t_dsa_generate_keypair) (TEMPLATE *, TEMPLATE *);

	CK_RV(*t_dsa_sign) (CK_BYTE *,
			   CK_BYTE *,
			   OBJECT *);

	CK_RV(*t_dsa_verify) (CK_BYTE *,
			   CK_BYTE *,
			   OBJECT *);

	CK_RV(*t_get_mechanism_list) (CK_MECHANISM_TYPE_PTR, CK_ULONG_PTR);
	CK_RV(*t_get_mechanism_info) (CK_MECHANISM_TYPE,
				      CK_MECHANISM_INFO_PTR);

	CK_RV (*t_object_add)(OBJECT *);

};

typedef struct token_specific_struct token_spec_t;

#endif
