
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
#endif  // #ifndef CONFIG_PATH

#define CCA_CONFIG_PATH CONFIG_PATH "/ccatok"
#endif  // #ifndef CCA_CONFIG_PATH

token_spec_t token_specific  = {
     CCA_CONFIG_PATH,
     "ccatok",
     "CCA_STDLL_Debug",
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
     &token_specific_ec_sign,
     &token_specific_ec_verify,
     &token_specific_rsa_generate_keypair,
     &token_specific_ec_generate_keypair,
#ifndef NODH
/* Begin code contributed by Corrent corp. */
     // DH
     &token_specific_dh_pkcs_derive,
     &token_specific_dh_pkcs_key_pair_gen,
/* End code contributed by Corrent corp. */
#endif
     // SHA-1
     NULL,
     NULL,
     NULL,
     // SHA-256
     token_specific_sha2_init,
     token_specific_sha2_update,
     token_specific_sha2_final,
#ifndef NOAES
     // AES
     &token_specific_aes_key_gen,
     &token_specific_aes_ecb,
     &token_specific_aes_cbc,
#endif
     &token_specific_get_mechanism_list,
     &token_specific_get_mechanism_info
};

#endif
