/*
 * COPYRIGHT (c) International Business Machines Corp. 2002-2017
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

// SAB FIXME  need to figure out a better way...
// // to get the variant dependency out
#ifndef __TOK_STRUCT_H
#define __TOK_STRUCT_H
#include <pkcs11types.h>

#include "tok_spec_struct.h"

// #define PK_LITE_DIR  "/etc/pkcs11/lite"
//
// #define PK_DIR      PK_LITE_DIR
// #define SUB_DIR     "lite"
//
//
// #define DBGTAG  "ICA_STDLL_Debug"
//
//
//

#ifndef SW_CONFIG_PATH

#ifndef CONFIG_PATH
#warning CONFIG_PATH not set, using default (/usr/local/var/lib/opencryptoki)
#define CONFIG_PATH "/usr/local/var/lib/opencryptoki"
#endif                          // #ifndef CONFIG_PATH

#define SW_CONFIG_PATH CONFIG_PATH "/swtok"
#endif                          // #ifndef SW_CONFIG_PATH

token_spec_t token_specific = {
    SW_CONFIG_PATH,
    "swtok",
    FALSE,
    // Token data info:
    {
        FALSE,                     // Don't use per guest data store
        TRUE,                      // Use master key
        CKM_DES3_CBC,              // Data store encryption
        (CK_BYTE *)"12345678",     // Default initialization vector for pins
        (CK_BYTE *)"10293847",     // Default initialization vector for objects
     },
    NULL,                       // t_creatlock
    NULL,                       // t_attach_shm
    &token_specific_init,
    NULL,                       // init_token_data
    NULL,                       // load_token_data
    NULL,                       // save_token_data
    NULL,                       // random number generator
    &token_specific_final,
    NULL,                       // init_token
    NULL,                       // login
    NULL,                       // logout
    NULL,                       // init_pin
    NULL,                       // set_pin
    // DES
    &token_specific_des_key_gen,
    &token_specific_des_ecb,
    &token_specific_des_cbc,
    // Triple DES
    &token_specific_tdes_ecb,
    &token_specific_tdes_cbc,
    &token_specific_tdes_ofb,
    &token_specific_tdes_cfb,
    &token_specific_tdes_mac,
    &token_specific_tdes_cmac,
    // RSA
    &token_specific_rsa_decrypt,
    &token_specific_rsa_encrypt,
    &token_specific_rsa_sign,
    &token_specific_rsa_verify,
    &token_specific_rsa_verify_recover,
    &token_specific_rsa_x509_decrypt,
    &token_specific_rsa_x509_encrypt,
    &token_specific_rsa_x509_sign,
    &token_specific_rsa_x509_verify,
    &token_specific_rsa_x509_verify_recover,
    &token_specific_rsa_oaep_decrypt,
    &token_specific_rsa_oaep_encrypt,
    &token_specific_rsa_pss_sign,
    &token_specific_rsa_pss_verify,
    &token_specific_rsa_generate_keypair,
#ifndef NO_EC
    // Elliptic Curve
    &token_specific_ec_sign,
    &token_specific_ec_verify,
    &token_specific_ec_generate_keypair,
    &token_specific_ecdh_pkcs_derive,
    NULL,                       // ecdh_derive_kdf
#else
    NULL,                       // ec_sign
    NULL,                       // ec_verify
    NULL,                       // ec_generate_keypair
    NULL,                       // ecdh_derive
    NULL,                       // ecdh_derive_kdf
#endif
/* Begin code contributed by Corrent corp. */
    // DH
#ifndef NODH
    &token_specific_dh_pkcs_derive,
    &token_specific_dh_pkcs_key_pair_gen,
#else
    NULL,                       // dh_pkcs_derive
    NULL,                       // dh_pkcs_key_pair_gen
#endif
/* End code contributed by Corrent corp. */
    &token_specific_sha_init,
    &token_specific_sha,
    &token_specific_sha_update,
    &token_specific_sha_final,
    // SHAKE derive
    &token_specific_shake_key_derive,
    // HMAC
    &token_specific_hmac_sign_init,
    &token_specific_hmac_sign,
    &token_specific_hmac_sign_update,
    &token_specific_hmac_sign_final,
    &token_specific_hmac_verify_init,
    &token_specific_hmac_verify,
    &token_specific_hmac_verify_update,
    &token_specific_hmac_verify_final,
    &token_specific_generic_secret_key_gen,
    // AES
    &token_specific_aes_key_gen,
    &token_specific_aes_xts_key_gen,
    &token_specific_aes_ecb,
    &token_specific_aes_cbc,
    &token_specific_aes_ctr,
    &token_specific_aes_gcm_init,
    &token_specific_aes_gcm,
    &token_specific_aes_gcm_update,
    &token_specific_aes_gcm_final,
    &token_specific_aes_ofb,
    &token_specific_aes_cfb,
    &token_specific_aes_mac,
    &token_specific_aes_cmac,
    &token_specific_aes_xts,
    &token_specific_aes_key_wrap,
    // DSA
    NULL,                       // dsa_generate_keypair
    NULL,                       // dsa_sign
    NULL,                       // dsa_verify
    // PQC
#if OPENSSL_VERSION_PREREQ(3, 0)
    &token_specific_ibm_dilithium_generate_keypair,
    &token_specific_ibm_dilithium_sign,
    &token_specific_ibm_dilithium_verify,
#else
    NULL,                       // ibm_dilithium_generate_keypair
    NULL,                       // ibm_dilithium_sign
    NULL,                       // ibm_dilithium_verify
#endif
    &token_specific_get_mechanism_list,
    &token_specific_get_mechanism_info,
    &token_specific_object_add,
    NULL,                       // key_wrap
    NULL,                       // key_unwrap
    NULL,                       // reencrypt_single
    NULL,                       // set_attribute_values
    &token_specific_set_attrs_for_new_object,
    NULL,                       // handle_event
    NULL,                       // check_obj_access
};

#endif
