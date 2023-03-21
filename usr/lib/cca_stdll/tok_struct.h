/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * openCryptoki CCA token
 *
 */

#ifndef __TOK_STRUCT_H
#define __TOK_STRUCT_H
#include <pkcs11types.h>

#include "tok_spec_struct.h"

#ifndef CCA_CONFIG_PATH

#ifndef CONFIG_PATH
#warning CONFIG_PATH not set, using default (/usr/local/var/lib/opencryptoki)
#define CONFIG_PATH "/usr/local/var/lib/opencryptoki"
#endif                          // #ifndef CONFIG_PATH

#define CCA_CONFIG_PATH CONFIG_PATH "/ccatok"
#endif                          // #ifndef CCA_CONFIG_PATH

token_spec_t token_specific = {
    CCA_CONFIG_PATH,
    "ccatok",
    TRUE,
    // Token data info:
    {
        FALSE,                     // Don't use per guest data store
        TRUE,                      // Use master key
        CKM_DES3_CBC,              // Data store encryption
        (CK_BYTE *)"12345678",     // Default initialization vector for pins
        (CK_BYTE *)"10293847",     // Default initialization vector for objects
    },
    NULL,                       // creatlock
    NULL,                       // attach_shm
    &token_specific_init,
    NULL,                       // init_token_data
    NULL,                       // load_token_data
    NULL,                       // save_token_data
    &token_specific_rng,
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
    NULL,                       // tdes_ofb
    NULL,                       // tdes_cfb
    NULL,                       // tdes_mac
    NULL,                       // tdes_cmac
    // RSA
    &token_specific_rsa_decrypt,
    &token_specific_rsa_encrypt,
    &token_specific_rsa_sign,
    &token_specific_rsa_verify,
    NULL,                       // rsa_verify_recover
    NULL,                       // rsa_x509_decrypt
    NULL,                       // rsa_x509_encrypt
    NULL,                       // rsa_x509_sign
    NULL,                       // rsa_x509_verify
    NULL,                       // rsa_x509_verify_recover
    &token_specific_rsa_oaep_decrypt,
    &token_specific_rsa_oaep_encrypt,
    &token_specific_rsa_pss_sign,
    &token_specific_rsa_pss_verify,
    &token_specific_rsa_generate_keypair,
    // Elliptic Curve
    &token_specific_ec_sign,
    &token_specific_ec_verify,
    &token_specific_ec_generate_keypair,
    NULL,                       // ecdh_derive
    NULL,                       // dh_pkcs_derive
    NULL,                       // dh_pkcs_key_pair_gen
    // SHA
    token_specific_sha_init,
    token_specific_sha,
    token_specific_sha_update,
    token_specific_sha_final,
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
    NULL,                       // aes_xts_key_gen
    &token_specific_aes_ecb,
    &token_specific_aes_cbc,
    NULL,                       // aes_ctr
    NULL,                       // aes_gcm_init,
    NULL,                       // aes_gcm
    NULL,                       // aes_gcm_update
    NULL,                       // aes_gcm_final
    NULL,                       // aes_ofb
    NULL,                       // aes_cfb
    NULL,                       // aes_mac
    NULL,                       // aes_cmac
    NULL,                       // aes_xts
    // DSA
    NULL,                       // dsa_generate_keypair
    NULL,                       // dsa_sign
    NULL,                       // dsa_verify
    &token_specific_get_mechanism_list,
    &token_specific_get_mechanism_info,
    &token_specific_object_add,
    &token_specific_key_wrap,
    &token_specific_key_unwrap,
    &token_specific_reencrypt_single,
    NULL,                       // set_attribute_values
#ifndef NO_PKEY
    &token_specific_set_attrs_for_new_object,
#else
    NULL,
#endif
    &token_specific_handle_event,
};

#endif
