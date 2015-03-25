
/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki CCA token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
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
#endif // #ifndef CONFIG_PATH

#define CCA_CONFIG_PATH CONFIG_PATH "/ccatok"
#endif // #ifndef CCA_CONFIG_PATH

token_spec_t token_specific = {
	CCA_CONFIG_PATH,
	"ccatok",
	64,
	// Token data info:
	{
		FALSE,			// Don't use per guest data store
		TRUE,			// Use master key
		CKM_DES3_CBC,		// Data store encryption
		"12345678",		// Default initialization vector for pins
		"10293847",		// Default initialization vector for objects
	},
	NULL,			// creatlock
	NULL,			// attach_shm
	&token_specific_init,
	NULL,			// init_token_data
	NULL,			// load_token_data
	NULL,			// save_token_data
	&token_specific_rng,
	&token_specific_final,
	NULL,			// init_token
	NULL,			// login
	NULL,			// logout
	NULL,			// init_pin
	NULL,			// set_pin
	// DES
	&token_specific_des_key_gen,
	&token_specific_des_ecb,
	&token_specific_des_cbc,
	// Triple DES
	&token_specific_tdes_ecb,
	&token_specific_tdes_cbc,
	NULL,			// tdes_ofb
	NULL,			// tdes_cfb
	NULL,			// tdes_mac
	// RSA
	&token_specific_rsa_decrypt,
	&token_specific_rsa_encrypt,
	&token_specific_rsa_sign,
	&token_specific_rsa_verify,
	NULL,			// rsa_verify_recover
	NULL,			// rsa_x509_decrypt
	NULL,			// rsa_x509_encrypt
	NULL,			// rsa_x509_sign
	NULL,			// rsa_x509_verify
	NULL,			// rsa_x509_verify_recover
        NULL,                   // rsa_oaep_decrypt
	NULL,			// rsa_oaep_encrypt
        NULL,                   // rsa_pss_sign
        NULL,                   // rsa_pss_verify
	&token_specific_rsa_generate_keypair,
	// Elliptic Curve
	&token_specific_ec_sign,
	&token_specific_ec_verify,
	&token_specific_ec_generate_keypair,
#ifndef NODH
/* Begin code contributed by Corrent corp. */
	// DH
	&token_specific_dh_pkcs_derive,
	&token_specific_dh_pkcs_key_pair_gen,
/* End code contributed by Corrent corp. */
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
	token_specific_sha2_init,
	token_specific_sha2,
	token_specific_sha2_update,
	token_specific_sha2_final,
	// SHA-384
	token_specific_sha3_init,
	token_specific_sha3,
	token_specific_sha3_update,
	token_specific_sha3_final,
	// SHA-512
	token_specific_sha5_init,
	token_specific_sha5,
	token_specific_sha5_update,
	token_specific_sha5_final,
#ifndef NOAES
	// AES
	&token_specific_aes_key_gen,
	&token_specific_aes_ecb,
	&token_specific_aes_cbc,
#else
	NULL,
	NULL,
	NULL,
#endif
	NULL,			// aes_ctr
	NULL,			// aes_ofb
	NULL,			// aes_cfb
	NULL,			// aes_mac
	// DSA
	NULL,			// dsa_generate_keypair
	NULL,			// dsa_sign
	NULL,			// dsa_verify
	&token_specific_get_mechanism_list,
	&token_specific_get_mechanism_info,
	&token_specific_object_add
};

#endif
