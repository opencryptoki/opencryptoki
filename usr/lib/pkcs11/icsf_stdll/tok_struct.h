/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki ICSF token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2013
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
#endif // #ifndef CONFIG_PATH

#define ICSF_CONFIG_PATH CONFIG_PATH "/icsf"
#endif // #ifndef ICSF_CONFIG_PATH

token_spec_t token_specific = {
	ICSF_CONFIG_PATH,
	"icsf",
	// Key token size (0 is default)
	0,
	// Token data info:
	{
		FALSE,			// Don't use per guest data store
		FALSE,			// Don't use master key. Remaining fields are ignored
		0,			// Data store encryption
		NULL,			// Default initialization vector for pins
		NULL,			// Default initialization vector for objects
	},
	NULL,			// creatlock
	&token_specific_attach_shm,
	&token_specific_init,
	&token_specific_init_token_data,
	&token_specific_load_token_data,
	&token_specific_save_token_data,
	&tok_slot2local,
	NULL,			// rng
	&token_specific_open_session,
	&token_specific_close_session,
	&token_specific_final,
	&token_specific_init_token,
	&token_specific_login,
	NULL,			// logout
	&token_specific_init_pin,
	&token_specific_set_pin,
	&token_specific_copy_object,
	&token_specific_create_object,
	&token_specific_get_attribute_value,
	&token_specific_set_attribute_value,
	&token_specific_find_objects_init,
	&token_specific_destroy_object,
	&token_specific_generate_key,
	&token_specific_generate_key_pair,
	&token_specific_encrypt_init,
	&token_specific_encrypt,
	&token_specific_encrypt_update,
	&token_specific_encrypt_final,
	&token_specific_decrypt_init,
	&token_specific_decrypt,
	&token_specific_decrypt_update,
	&token_specific_decrypt_final,
	&token_specific_derive_key,
	&token_specific_wrap_key,
	&token_specific_unwrap_key,
	token_specific_sign_init,
	token_specific_sign,
	token_specific_sign_update,
	token_specific_sign_final,
	token_specific_verify_init,
	token_specific_verify,
	token_specific_verify_update,
	token_specific_verify_final,
	// DES
	NULL, 			// des_key_gen
	NULL, 			// des_ecb
	NULL, 			// des_cb
	// Triple DES
	NULL,			// tdes_ecb
	NULL,			// tdes_cbc
	NULL,			// tdes_ofb
	NULL,			// tdes_cfb
	NULL,			// tdes_mac
	// RSA
	NULL,			// rsa_decrypt
	NULL,			// rsa_encrypt
	NULL,			// rsa_sign
	NULL,			// rsa_verify
	NULL,			// rsa_verify_recover
	NULL,			// rsa_x509_decrypt
	NULL,			// rsa_x509_encrypt
	NULL,			// rsa_x509_sign
	NULL,			// rsa_x509_verify
	NULL,			// rsa_x509_verify_recover
        NULL,                   // rsa_oaep_decrypt
        NULL,                   // rsa_oaep_encrypt
        NULL,                   // rsa_pss_sign
        NULL,                   // rsa_pss_verify
	NULL,			// rsa_generate_keypair
	// Elliptic Curve
	NULL,			// ec_sign
	NULL,			// ec_verify
	NULL,			// ec_generate_keypair
#ifndef NODH
	// DH
	NULL,			// dh_pkcs_derive
	NULL,			// dh_pkcs_key_pair_gen
#else
	NULL,
	NULL,
#endif
	// SHA-1
	NULL,			// sha_init
	NULL,			// sha
	NULL,			// sha_update
	NULL,			// sha_final
	// SHA-256
	NULL,			// sha2_init
	NULL,			// sha2
	NULL,			// sha2_update
	NULL,			// sha2_final
	// SHA-384
	NULL,			// sha3_init
	NULL,			// sha3
	NULL,			// sha3_update
	NULL,			// sha3_final
	// SHA-512
	NULL,			// sha5_init
	NULL,			// sha5
	NULL,			// sha5_update
	NULL,			// sha5_final
	// AES
	NULL,			// aes_key_gen
	NULL,			// aes_ecb
	NULL,			// aes_cbc
	NULL,			// aes_ctr
	NULL,			// aes_ofb
	NULL,			// aes_cfb
	NULL,			// aes_mac
	// DSA
	NULL,			// dsa_generate_keypair
	NULL,			// dsa_sign
	NULL,			// dsa_verify
	&token_specific_get_mechanism_list,	// get_mechanism_list
	&token_specific_get_mechanism_info,	// get_mechanism_info
};

#endif
