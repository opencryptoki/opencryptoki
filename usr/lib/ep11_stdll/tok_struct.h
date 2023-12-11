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

#ifndef SW_CONFIG_PATH

#ifndef CONFIG_PATH
#warning CONFIG_PATH not set, using default (/usr/local/var/lib/opencryptoki)
#define CONFIG_PATH "/usr/local/var/lib/opencryptoki"
#endif                          // #ifndef CONFIG_PATH

#define SW_CONFIG_PATH CONFIG_PATH "/ep11tok"
#endif                          // #ifndef SW_CONFIG_PATH

token_spec_t token_specific = {
    SW_CONFIG_PATH,
    "ep11tok",
    TRUE,                          // secure key token
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
    NULL,                       // init
    NULL,                       // init_token_data
    NULL,                       // load_token_data
    NULL,                       // save_token_data
    &token_specific_rng,
    NULL,                       // final
    NULL,                       // init_token
    NULL,                       // token_specific_login,
    NULL,                       // token_specific_logout,
    NULL,                       // init_pin,
    NULL,                       // set_pin
    // DES
    NULL,                       // des_key_gen,
    NULL,                       // des_ecb,
    NULL,                       // des_cbc,
    // Triple DES
    NULL,                       // tdes_ecb,
    NULL,                       // tdes_cbc,
    NULL,                       // des3_ofb
    NULL,                       // des3_cfb
    NULL,                       // des3_mac
    NULL,                       // des3_cmac
    // RSA
    NULL,                       // rsa_decrypt
    NULL,                       // rsa_encrypt
    &token_specific_rsa_sign,
    &token_specific_rsa_verify,
    NULL,                       // rsa_verify_recover
    NULL,                       // rsa_x509_decrypt
    NULL,                       // rsa_x509_encrypt
    NULL,                       // rsa_x509_sign
    NULL,                       // rsa_x509_verify
    NULL,                       // rsa_x509_verify_recover
    NULL,                       // rsa_oaep_decrypt
    NULL,                       // rsa_oaep_encrypt
    &token_specific_rsa_pss_sign,
    &token_specific_rsa_pss_verify,
    NULL,                       // rsa_generate_keypair
    // Elliptic Curve
    &token_specific_ec_sign,
    &token_specific_ec_verify,
    NULL,                       // ec_generate_keypair
    NULL,                       // ecdh_derive
    NULL,                       // ecdh_derive_kdf
    // DH
    NULL,                       // dh_pkcs_derive,
    NULL,                       // dh_pkcs_key_pair_gen
    // SHA
    &token_specific_sha_init,
    &token_specific_sha,
    &token_specific_sha_update,
    &token_specific_sha_final,
    // SHAKE derive
    NULL,                       // shake_key_derive
    // HMAC
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
    NULL,                       // aes_key_gen,
    NULL,                       // aes_xts_key_gen
#ifndef NO_PKEY
    &token_specific_aes_ecb,
    &token_specific_aes_cbc,
#else
    NULL,                       // aes_ecb
    NULL,                       // aes_cbc
#endif
    NULL,                       // aes_ctr
    NULL,                       // aes_gcm_init
    NULL,                       // aes_gcm
    NULL,                       // aes_gcm_update
    NULL,                       // aes_gcm_final
    NULL,                       // aes_ofb
    NULL,                       // aes_cfb
    NULL,                       // aes_mac
#ifndef NO_PKEY
    &token_specific_aes_cmac,
    &token_specific_aes_xts,    // aes_xts
#else
    NULL,                       // aes_cmac
    NULL,                       // aes_xts
#endif
    // DSA
    NULL,                       // dsa_generate_keypair,
    NULL,                       // dsa_sign
    NULL,                       // dsa_verify
    // PQC
    NULL,                       // ibm_dilithium_generate_keypair
    NULL,                       // ibm_dilithium_sign
    NULL,                       // ibm_dilithium_verify
    NULL,                       // get_mechanism_list
    NULL,                       // get mechanism_info
    &token_specific_object_add,
    NULL,                       // key_wrap
    NULL,                       // key_unwrap
    &token_specific_reencrypt_single,
    &token_specific_set_attribute_values,
    &token_specific_set_attrs_for_new_object,
    &token_specific_handle_event,
    &token_specific_check_obj_access,
};

#endif
