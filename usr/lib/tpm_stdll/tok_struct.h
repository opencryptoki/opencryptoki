/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include "tpm_specific.h"

#ifndef TPM_CONFIG_PATH

#ifndef CONFIG_PATH
#warning CONFIG_PATH not set, using default (/usr/local/var/lib/opencryptoki)
#define CONFIG_PATH "/usr/local/var/lib/opencryptoki"
#endif                          // #ifndef CONFIG_PATH

#define TPM_CONFIG_PATH CONFIG_PATH "/tpm"
#endif                          // #ifndef TPM_CONFIG_PATH

struct token_specific_struct token_specific = {
    TPM_CONFIG_PATH,
    "tpm",
    TRUE,
    // Token data info:
    {
        TRUE,                      // Use per guest data store
        TRUE,                      // Use master key
        CKM_AES_CBC,               // Data store encryption
        NULL,                      // Default initialization vector for pins
        (CK_BYTE *)")#%&!*)^!()$&!&N",// Default initialization vector
                                      //  for objects
    },
    token_specific_creatlock,
    NULL,                       // attach_shm
    &token_specific_init,
    &token_specific_init_token_data,
    NULL,                       // load_token_data
    NULL,                       // save_token_data
    NULL,                       // get_token_info
    &token_specific_rng,
    &token_specific_final,
    &token_specific_init_token,
    &token_specific_login,
    &token_specific_logout,
    &token_specific_init_pin,
    &token_specific_set_pin,
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
    &token_specific_rsa_verify_recover,
    NULL,                       // rsa_x509_decrypt
    NULL,                       // rsa_x509_encrypt
    NULL,                       // rsa_x509_sign
    NULL,                       // rsa_x509_verify
    NULL,                       // rsa_x509_verify_recover
    NULL,                       // rsa_oaep_decrypt
    NULL,                       // rsa_oaep_encrypt
    NULL,                       // rsa_pss_sign
    NULL,                       // rsa_pss_verify
    &token_specific_rsa_generate_keypair,
    // Elliptic Curve
    NULL,                       // ec_sign
    NULL,                       // ec_verify
    NULL,                       // ec_generate_keypair
    NULL,                       // ecdh_derive
    NULL,                       // ecdh_derive_kdf
    NULL,                       // dh_pkcs_derive
    NULL,                       // dh_pkcs_key_pair_gen
    // SHA
    NULL,                       // sha_init
    NULL,                       // sha
    NULL,                       // sha_update
    NULL,                       // sha_final
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
    &token_specific_aes_key_gen,
    NULL,                       // aes_xts_key_gen
    &token_specific_aes_ecb,
    &token_specific_aes_cbc,
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
    &token_specific_get_mechanism_list,
    &token_specific_get_mechanism_info,
    NULL,                       // object_add
    &token_specific_key_wrap,
    &token_specific_key_unwrap,
    NULL,                       // reencrypt_single
    NULL,                       // set_attribute_values
    NULL,                       // set_attrs_for_new_object
    NULL,                       // handle_event
    NULL,                       // check_obj_access
};
