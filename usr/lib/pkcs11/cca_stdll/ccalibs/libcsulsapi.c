
#include "csulincl.h"

/* PKA Key Generate */
void CSNDPKG (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * regeneration_data_length,
              unsigned char * regeneration_data,
              long          * skeleton_key_token_length,
              unsigned char * skeleton_key_token,
              unsigned char * transport_key_identifier,
              long          * generated_key_identifier_length,
              unsigned char * generated_key_identifier)
{
}

/* Digital Signature Verify */
void CSNDDSV (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * PKA_public_key_id_length,
              unsigned char * PKA_public_key_id,
              long          * hash_length,
              unsigned char * hash,
              long          * signature_field_length,
              unsigned char * signature_field)
{
}

/* Crypto Facility Query */
void CSUACFQ (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * verb_data_length,
              unsigned char * verb_data)
{
}

/* Des Key Token Change */
void CSNBKTC (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier)
{
}

/* PKA Key Token Change */
void CSNDKTC (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_id_length,
              unsigned char * key_id)
{
}

