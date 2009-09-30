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
#endif	// #ifndef CONFIG_PATH

#define TPM_CONFIG_PATH CONFIG_PATH "/tpm"
#endif	// #ifndef TPM_CONFIG_PATH

struct token_specific_struct token_specific = {
     TPM_CONFIG_PATH,
     "tpm",
     "TPM_STDLL_Debug",
     &token_specific_init,
     &tok_slot2local,
     &token_rng,
     &token_specific_session,
     &token_specific_final,
     &token_specific_des_key_gen,
     &token_specific_des_ecb,
     &token_specific_des_cbc,
     &token_specific_tdes_ecb,
     &token_specific_tdes_cbc,
     &token_specific_rsa_decrypt,
     &token_specific_rsa_encrypt,
     &token_specific_rsa_sign,
     &token_specific_rsa_verify,
     &token_specific_rsa_generate_keypair,
#ifndef NODH
     &token_specific_dh_pkcs_derive,
     &token_specific_dh_pkcs_key_pair_gen,
#endif
     // SHA-1 - use the internal implementation
     NULL,
     NULL,
     NULL,
     &token_specific_aes_key_gen,
     &token_specific_aes_ecb,
     &token_specific_aes_cbc,
     &token_specific_login,
     &token_specific_logout,
     &token_specific_init_pin,
     &token_specific_set_pin,
     &token_specific_verify_so_pin
};
