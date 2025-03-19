/*
 * COPYRIGHT (c) International Business Machines Corp. 2013-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * openCryptoki ICSF token
 *
 */

#ifndef __TOK_STRUCT_H
#define __TOK_STRUCT_H

#include <pkcs11types.h>
#include "tok_spec_struct.h"

#ifndef ICSF_CONFIG_PATH

#ifndef CONFIG_PATH
#warning CONFIG_PATH not set, using default (/usr/local/var/lib/opencryptoki)
#define CONFIG_PATH "/usr/local/var/lib/opencryptoki"
#endif                          // #ifndef CONFIG_PATH

#define ICSF_CONFIG_PATH CONFIG_PATH "/icsf"
#endif                          // #ifndef ICSF_CONFIG_PATH

token_spec_t token_specific = {
    ICSF_CONFIG_PATH,
    "icsf",
    FALSE,
    // Token data info:
    {
        FALSE,             // Don't use per guest data store
        FALSE,             // Don't use master key. Remaining fields are ignored
        0,                 // Data store encryption
        NULL,              // Default initialization vector for pins
        NULL,              // Default initialization vector for objects
    },
    NULL,                       // creatlock
    &token_specific_attach_shm,
    NULL,
    &token_specific_init_token_data,
    &token_specific_load_token_data,
    &token_specific_save_token_data,
    NULL,                       // get_token_info
    NULL,                       // rng
    NULL,                       // final
    NULL,                       // init token
    NULL,                       // login
    NULL,                       // logout
    NULL,                       // initpin
    NULL,                       // setpin
    // DES
    NULL,                       // des_key_gen
    NULL,                       // des_ecb
    NULL,                       // des_cb
    // Triple DES
    NULL,                       // tdes_ecb
    NULL,                       // tdes_cbc
    NULL,                       // tdes_ofb
    NULL,                       // tdes_cfb
    NULL,                       // tdes_mac
    NULL,                       // tdes_cmac
    // RSA
    NULL,                       // rsa_decrypt
    NULL,                       // rsa_encrypt
    NULL,                       // rsa_sign
    NULL,                       // rsa_verify
    NULL,                       // rsa_verify_recover
    NULL,                       // rsa_x509_decrypt
    NULL,                       // rsa_x509_encrypt
    NULL,                       // rsa_x509_sign
    NULL,                       // rsa_x509_verify
    NULL,                       // rsa_x509_verify_recover
    NULL,                       // rsa_oaep_decrypt
    NULL,                       // rsa_oaep_encrypt
    NULL,                       // rsa_pss_sign
    NULL,                       // rsa_pss_verify
    NULL,                       // rsa_generate_keypair
    // Elliptic Curve
    NULL,                       // ec_sign
    NULL,                       // ec_verify
    NULL,                       // ec_generate_keypair
    NULL,                       // ecdh_derive
    NULL,                       // ecdh_derive_kdf
    // DH
    NULL,                       // dh_pkcs_derive
    NULL,                       // dh_pkcs_key_pair_gen
    // SHA
    &token_specific_sha_init,
    &token_specific_sha,
    &token_specific_sha_update,
    &token_specific_sha_final,
    // SHAKE derive
    NULL,                       // shake_key_derive
    //HMAC
    NULL,                       // hmac_sign_init
    NULL,                       // hmac_sign
    NULL,                       // hmac_sign_update
    NULL,                       // hmac_sign_final
    NULL,                       // hmac_verify_init
    NULL,                       // hmac_verify
    NULL,                       // hmac_verify_update
    NULL,                       // hmac_verify_final
    NULL,                       // generic_secret_key_gen
    // AES
    NULL,                       // aes_key_gen
    NULL,                       // aes_xts_key_gen
    NULL,                       // aes_ecb
    NULL,                       // aes_cbc
    NULL,                       // aes_ctr
    NULL,                       // aes_gcm_init
    NULL,                       // aes_gcm
    NULL,                       // aes_gcm_update
    NULL,                       // aes_gcm_final
    NULL,                       // aes_ofb
    NULL,                       // aes_cfb
    NULL,                       // aes_mac
    NULL,                       // aes_cmac
    NULL,                       // aes_xts
    NULL,                       // aes_key_wrap
    // DSA
    NULL,                       // dsa_generate_keypair
    NULL,                       // dsa_sign
    NULL,                       // dsa_verify
    // PQC
    NULL,                       // ibm_ml_dsa_generate_keypair
    NULL,                       // ibm_ml_dsa_sign
    NULL,                       // ibm_ml_dsa_verify
    NULL,                       // ibm_ml_kem_generate_keypair
    NULL,                       // ibm_ml_kem_derive
    NULL,                       // get_mechanism_list
    NULL,                       // get_mechanism_info
    NULL,                       // object_add
    NULL,                       // key_wrap
    NULL,                       // key_unwrap
    NULL,                       // reencrypt_single
    NULL,                       // set_attribute_values
    NULL,                       // set_attrs_for_new_object
    NULL,                       // handle_event
    NULL,                       // check_obj_access
};

#endif
