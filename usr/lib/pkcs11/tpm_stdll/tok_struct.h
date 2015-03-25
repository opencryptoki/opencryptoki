/*
 * The Initial Developer of the Original Code is International
 * Business Machines Corporation. Portions created by IBM
 * Corporation are Copyright (C) 2005 International Business
 * Machines Corporation. All Rights Reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the Common Public License as published by
 * IBM Corporation; either version 1 of the License, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * Common Public License for more details.
 *
 * You should have received a copy of the Common Public License
 * along with this program; if not, a copy can be viewed at
 * http://www.opensource.org/licenses/cpl1.0.php.
 */

#include "tpm_specific.h"

#ifndef TPM_CONFIG_PATH

#ifndef CONFIG_PATH
#warning CONFIG_PATH not set, using default (/usr/local/var/lib/opencryptoki)
#define CONFIG_PATH "/usr/local/var/lib/opencryptoki"
#endif // #ifndef CONFIG_PATH

#define TPM_CONFIG_PATH CONFIG_PATH "/tpm"
#endif // #ifndef TPM_CONFIG_PATH

struct token_specific_struct token_specific = {
	TPM_CONFIG_PATH,
	"tpm",
	0,
	// Token data info:
	{
		TRUE,			// Use per guest data store
		TRUE,			// Use master key
		CKM_AES_CBC,		// Data store encryption
		NULL,			// Default initialization vector for pins
		")#%&!*)^!()$&!&N",	// Default initialization vector for objects
	},
	token_specific_creatlock,
	NULL,			// attach_shm
	&token_specific_init,
	&token_specific_init_token_data,
	NULL,			// load_token_data
	NULL,			// save_token_data
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
	NULL,			// tdes_ofb
	NULL,			// tdes_cfb
	NULL,			// tdes_mac
	// RSA
	&token_specific_rsa_decrypt,
	&token_specific_rsa_encrypt,
	&token_specific_rsa_sign,
	&token_specific_rsa_verify,
	&token_specific_rsa_verify_recover,
	NULL,			// rsa_x509_decrypt
	NULL,			// rsa_x509_encrypt
	NULL,			// rsa_x509_sign
	NULL,			// rsa_x509_verify
	NULL,			// rsa_x509_verify_recover
        NULL,                   // rsa_oaep_decrypt
        NULL,                   // rsa_oaep_encrypt
        NULL,                   // rsa_pss_sign
        NULL,                   // rsa_pss_verify
	&token_specific_rsa_generate_keypair,
	// Elliptic Curve
	NULL,			// ec_sign
	NULL,			// ec_verify
	NULL,			// ec_generate_keypair
#ifndef NODH
	&token_specific_dh_pkcs_derive,
	&token_specific_dh_pkcs_key_pair_gen,
#else
	NULL,
	NULL,
#endif
	// SHA-1 - use the internal implementation
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
	&token_specific_aes_key_gen,
	&token_specific_aes_ecb,
	&token_specific_aes_cbc,
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
	NULL			// object_add
};
