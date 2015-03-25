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
	NULL,
	&token_specific_init_token_data,
	&token_specific_load_token_data,
	&token_specific_save_token_data,
	NULL,			// rng
	NULL,			// final
	NULL,			// init token
	NULL,			// login
	NULL,			// logout
	NULL,			// initpin
	NULL,			// setpin
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
	NULL,			// get_mechanism_list
	NULL,			// get_mechanism_info
	NULL,			// object_add
};

#endif
