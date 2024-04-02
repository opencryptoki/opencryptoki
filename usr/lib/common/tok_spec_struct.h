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

#include "pqc_defs.h"

struct token_specific_struct {
    // Used to be in the token_local.h as a #def
    char token_directory[PATH_MAX];

    // Subdirectory
    char token_subdir[PATH_MAX];

    // Specifies if the token is using secure keys
    CK_BBOOL secure_key_token;

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
    CK_RV(*t_attach_shm) (STDLL_TokData_t *, CK_SLOT_ID slot_id);

    // Initialization function
    CK_RV(*t_init) (STDLL_TokData_t *, CK_SLOT_ID, char *);

    // Token data functions
    CK_RV(*t_init_token_data) (STDLL_TokData_t *tokdata, CK_SLOT_ID slot_id);
    CK_RV(*t_load_token_data) (STDLL_TokData_t *tokdata,
                               CK_SLOT_ID slot_id, FILE *fh);
    CK_RV(*t_save_token_data) (STDLL_TokData_t *tokdata,
                               CK_SLOT_ID slot_id, FILE *fh);

    // Random Number Gen
    CK_RV(*t_rng) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG);

    // any specific final code
    CK_RV(*t_final) (STDLL_TokData_t *, CK_BBOOL);

    CK_RV(*t_init_token) (STDLL_TokData_t *, CK_SLOT_ID, CK_CHAR_PTR,
                          CK_ULONG, CK_CHAR_PTR);
    CK_RV(*t_login) (STDLL_TokData_t *, SESSION *, CK_USER_TYPE,
                     CK_CHAR_PTR, CK_ULONG);
    CK_RV(*t_logout) (STDLL_TokData_t *);
    CK_RV(*t_init_pin) (STDLL_TokData_t *, SESSION *, CK_CHAR_PTR, CK_ULONG);
    CK_RV(*t_set_pin) (STDLL_TokData_t *, SESSION *, CK_CHAR_PTR, CK_ULONG,
                       CK_CHAR_PTR, CK_ULONG);

    CK_RV(*t_des_key_gen) (STDLL_TokData_t *, TEMPLATE *, CK_BYTE **,
                           CK_ULONG *, CK_ULONG, CK_BBOOL *);
    CK_RV(*t_des_ecb) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG,
                       CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE);
    CK_RV(*t_des_cbc) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG,
                       CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE *, CK_BYTE);

    CK_RV(*t_tdes_ecb) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG,
                        CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE);
    CK_RV(*t_tdes_cbc) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG,
                        CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE *, CK_BYTE);

    CK_RV(*t_tdes_ofb) (STDLL_TokData_t *, CK_BYTE *, CK_BYTE *, CK_ULONG,
                        OBJECT *, CK_BYTE *, uint_32);

    CK_RV(*t_tdes_cfb) (STDLL_TokData_t *, CK_BYTE *, CK_BYTE *, CK_ULONG,
                        OBJECT *, CK_BYTE *, uint_32, uint_32);

    CK_RV(*t_tdes_mac) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG, OBJECT *,
                        CK_BYTE *);

    CK_RV(*t_tdes_cmac) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG, OBJECT *,
                         CK_BYTE *,CK_BBOOL, CK_BBOOL, CK_VOID_PTR *);

    CK_RV(*t_rsa_decrypt) (STDLL_TokData_t *, CK_BYTE *,
                           CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *);

    CK_RV(*t_rsa_encrypt) (STDLL_TokData_t *, CK_BYTE *,
                           CK_ULONG, CK_BYTE *, CK_ULONG *, OBJECT *);

    CK_RV(*t_rsa_sign) (STDLL_TokData_t *, SESSION *, CK_BYTE *, CK_ULONG,
                        CK_BYTE *, CK_ULONG *, OBJECT *);
    CK_RV(*t_rsa_verify) (STDLL_TokData_t *, SESSION *, CK_BYTE *, CK_ULONG,
                          CK_BYTE *, CK_ULONG, OBJECT *);

    CK_RV(*t_rsa_verify_recover) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG,
                                  CK_BYTE *, CK_ULONG *, OBJECT *);

    CK_RV(*t_rsa_x509_decrypt) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG,
                                CK_BYTE *, CK_ULONG *, OBJECT *);

    CK_RV(*t_rsa_x509_encrypt) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG,
                                CK_BYTE *, CK_ULONG *, OBJECT *);

    CK_RV(*t_rsa_x509_sign) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG,
                             CK_BYTE *, CK_ULONG *, OBJECT *);

    CK_RV(*t_rsa_x509_verify) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG,
                               CK_BYTE *, CK_ULONG, OBJECT *);

    CK_RV(*t_rsa_x509_verify_recover) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG,
                                       CK_BYTE *, CK_ULONG *, OBJECT *);

    CK_RV(*t_rsa_oaep_decrypt) (STDLL_TokData_t *, ENCR_DECR_CONTEXT *,
                                CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
                                CK_BYTE *, CK_ULONG);

    CK_RV(*t_rsa_oaep_encrypt) (STDLL_TokData_t *, ENCR_DECR_CONTEXT *,
                                CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
                                CK_BYTE *, CK_ULONG);

        CK_RV(*t_rsa_pss_sign) (STDLL_TokData_t *, SESSION *,
                                SIGN_VERIFY_CONTEXT *, CK_BYTE *, CK_ULONG,
                                CK_BYTE *, CK_ULONG *);

        CK_RV(*t_rsa_pss_verify) (STDLL_TokData_t *, SESSION *,
                                  SIGN_VERIFY_CONTEXT *, CK_BYTE *, CK_ULONG,
                                  CK_BYTE *, CK_ULONG);

    CK_RV(*t_rsa_generate_keypair) (STDLL_TokData_t *tokdata, TEMPLATE *,
                                    TEMPLATE *);

    CK_RV(*t_ec_sign) (STDLL_TokData_t *tokdata, SESSION *, CK_BYTE *, CK_ULONG,
                       CK_BYTE *, CK_ULONG *, OBJECT *);
    CK_RV(*t_ec_verify) (STDLL_TokData_t *tokdata, SESSION *, CK_BYTE *,
	                     CK_ULONG, CK_BYTE *, CK_ULONG, OBJECT *);
    CK_RV(*t_ec_generate_keypair) (STDLL_TokData_t *tokdata, TEMPLATE *,
                                   TEMPLATE *);


    CK_RV(*t_ecdh_pkcs_derive) (STDLL_TokData_t *tokdata, CK_BYTE *, CK_ULONG,
                                CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *,
                                CK_BYTE *, CK_ULONG);

    /* Begin code contributed by Corrent corp. */

    // Token Specific DH functions
    CK_RV(*t_dh_pkcs_derive) (STDLL_TokData_t *tokdata, CK_BYTE *,
                              CK_ULONG *, CK_BYTE *, CK_ULONG,
                              CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG);

    CK_RV(*t_dh_pkcs_key_pair_gen) (STDLL_TokData_t *tokdata, TEMPLATE *,
                                    TEMPLATE *);

    /* End code contributed by Corrent corp. */

    // Token Specific SHA1 functions
    CK_RV(*t_sha_init) (STDLL_TokData_t *, DIGEST_CONTEXT *, CK_MECHANISM *);
    CK_RV(*t_sha) (STDLL_TokData_t *, DIGEST_CONTEXT *, CK_BYTE *, CK_ULONG,
                   CK_BYTE *, CK_ULONG *);
    CK_RV(*t_sha_update) (STDLL_TokData_t *, DIGEST_CONTEXT *, CK_BYTE *,
                          CK_ULONG);
    CK_RV(*t_sha_final) (STDLL_TokData_t *, DIGEST_CONTEXT *, CK_BYTE *,
                         CK_ULONG *);

    // Token Specific HMAC
    CK_RV(*t_hmac_sign_init) (STDLL_TokData_t *, SESSION *, CK_MECHANISM *,
                              CK_OBJECT_HANDLE);
    CK_RV(*t_hmac_sign) (STDLL_TokData_t *, SESSION *, CK_BYTE *, CK_ULONG,
                         CK_BYTE *, CK_ULONG *);
    CK_RV(*t_hmac_sign_update) (STDLL_TokData_t *, SESSION *, CK_BYTE *,
                                CK_ULONG);
    CK_RV(*t_hmac_sign_final) (STDLL_TokData_t *, SESSION *, CK_BYTE *,
                               CK_ULONG *);

    CK_RV(*t_hmac_verify_init) (STDLL_TokData_t *, SESSION *,
                                CK_MECHANISM *, CK_OBJECT_HANDLE);
    CK_RV(*t_hmac_verify) (STDLL_TokData_t *, SESSION *, CK_BYTE *,
                           CK_ULONG, CK_BYTE *, CK_ULONG);
    CK_RV(*t_hmac_verify_update) (STDLL_TokData_t *, SESSION *, CK_BYTE *,
                                  CK_ULONG);
    CK_RV(*t_hmac_verify_final) (STDLL_TokData_t *, SESSION *, CK_BYTE *,
                                 CK_ULONG);

    CK_RV(*t_generic_secret_key_gen) (STDLL_TokData_t *, TEMPLATE *);

    // Token Specific AES functions
    CK_RV(*t_aes_key_gen) (STDLL_TokData_t *, TEMPLATE *, CK_BYTE **,
                           CK_ULONG *, CK_ULONG, CK_BBOOL *);

    CK_RV(*t_aes_xts_key_gen) (STDLL_TokData_t *, TEMPLATE *, CK_BYTE **,
                               CK_ULONG *, CK_ULONG, CK_BBOOL *);

    CK_RV(*t_aes_ecb) (STDLL_TokData_t *tokdata, SESSION *, CK_BYTE *, CK_ULONG,
                       CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE);

    CK_RV(*t_aes_cbc) (STDLL_TokData_t *tokdata, SESSION *, CK_BYTE *, CK_ULONG,
                       CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE *, CK_BYTE);

    CK_RV(*t_aes_ctr) (STDLL_TokData_t *tokdata, CK_BYTE *, CK_ULONG,
                       CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE *, CK_ULONG,
                       CK_BYTE);

    CK_RV(*t_aes_gcm_init) (STDLL_TokData_t *, SESSION *,
                            ENCR_DECR_CONTEXT *, CK_MECHANISM *,
                            CK_OBJECT_HANDLE, CK_BYTE);

    CK_RV(*t_aes_gcm) (STDLL_TokData_t *, SESSION *, ENCR_DECR_CONTEXT *,
                       CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *, CK_BYTE);

    CK_RV(*t_aes_gcm_update) (STDLL_TokData_t *, SESSION *,
                              ENCR_DECR_CONTEXT *, CK_BYTE *,
                              CK_ULONG, CK_BYTE *, CK_ULONG *, CK_BYTE);

    CK_RV(*t_aes_gcm_final) (STDLL_TokData_t *, SESSION *,
                             ENCR_DECR_CONTEXT *, CK_BYTE *,
                             CK_ULONG *, CK_BYTE);

    CK_RV(*t_aes_ofb) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG, CK_BYTE *,
                       OBJECT *, CK_BYTE *, uint_32);

    CK_RV(*t_aes_cfb) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG, CK_BYTE *,
                       OBJECT *, CK_BYTE *, uint_32, uint_32);

    CK_RV(*t_aes_mac) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG, OBJECT *,
                       CK_BYTE *);

    CK_RV(*t_aes_cmac) (STDLL_TokData_t *, CK_BYTE *, CK_ULONG, OBJECT *,
                        CK_BYTE *, CK_BBOOL, CK_BBOOL, CK_VOID_PTR *);

    CK_RV(*t_aes_xts) (STDLL_TokData_t *tokdata, SESSION *, CK_BYTE *, CK_ULONG,
                       CK_BYTE *, CK_ULONG *, OBJECT *, CK_BYTE *, CK_BBOOL,
                       CK_BBOOL, CK_BBOOL, CK_BYTE*);

    // Token Specific DSA functions
    CK_RV(*t_dsa_generate_keypair) (STDLL_TokData_t *, TEMPLATE *, TEMPLATE *);

    CK_RV(*t_dsa_sign) (STDLL_TokData_t *, CK_BYTE *, CK_BYTE *, OBJECT *);

    CK_RV(*t_dsa_verify) (STDLL_TokData_t *, CK_BYTE *, CK_BYTE *, OBJECT *);

    // Token Specific PQC functions
    CK_RV (*t_ibm_dilithium_generate_keypair)(STDLL_TokData_t *,
                                              const struct pqc_oid *,
                                              TEMPLATE *, TEMPLATE *);

    CK_RV (*t_ibm_dilithium_sign)(STDLL_TokData_t *, SESSION *, CK_BBOOL,
                                  const struct pqc_oid *,
                                  CK_BYTE *, CK_ULONG,
                                  CK_BYTE *, CK_ULONG *, OBJECT *);

    CK_RV (*t_ibm_dilithium_verify)(STDLL_TokData_t *, SESSION *,
                                    const struct pqc_oid *,
                                    CK_BYTE *, CK_ULONG,
                                    CK_BYTE *, CK_ULONG, OBJECT *);

    CK_RV(*t_get_mechanism_list) (STDLL_TokData_t *, CK_MECHANISM_TYPE_PTR,
                                  CK_ULONG_PTR);
    CK_RV(*t_get_mechanism_info) (STDLL_TokData_t *, CK_MECHANISM_TYPE,
                                  CK_MECHANISM_INFO_PTR);

    CK_RV(*t_object_add) (STDLL_TokData_t *, SESSION *, OBJECT *);

    CK_RV(*t_key_wrap) (STDLL_TokData_t *, SESSION *, CK_MECHANISM *, CK_BBOOL,
                        OBJECT *, OBJECT *, CK_BYTE *, CK_ULONG *, CK_BBOOL *);

    CK_RV(*t_key_unwrap) (STDLL_TokData_t *, SESSION *, CK_MECHANISM *,
                          CK_BYTE *, CK_ULONG, OBJECT *, OBJECT *, CK_BBOOL *);

    CK_RV(*t_reencrypt_single) (STDLL_TokData_t *, SESSION *,
                                ENCR_DECR_CONTEXT *, CK_MECHANISM *, OBJECT *,
                                ENCR_DECR_CONTEXT *, CK_MECHANISM *, OBJECT *,
                                CK_BYTE *, CK_ULONG , CK_BYTE *, CK_ULONG *);

    CK_RV(*t_set_attribute_values) (STDLL_TokData_t *, SESSION *,
                                    OBJECT *, TEMPLATE *);

    CK_RV(*t_set_attrs_for_new_object) (STDLL_TokData_t *, CK_OBJECT_CLASS,
                                        CK_ULONG, TEMPLATE *);

    CK_RV(*t_handle_event) (STDLL_TokData_t *tokdata, unsigned int event_type,
                            unsigned int event_flags, const char *payload,
                            unsigned int payload_len);

    CK_RV (*t_check_obj_access) (STDLL_TokData_t *tokdata, OBJECT *obj,
                                 CK_BBOOL create);
};

typedef struct token_specific_struct token_spec_t;

#endif
