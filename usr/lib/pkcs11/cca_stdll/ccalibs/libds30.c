
#include "csulincl.h"


/* Decipher */
void CSNBDEC (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_identifier,
              long          * text_length,
              unsigned char * ciphertext,
              unsigned char * initialization_vector,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * chaining_vector,
              unsigned char * plaintext)
{
}

/* Encipher */
void CSNBENC (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_identifier,
              long          * text_length,
              unsigned char * plaintext,
              unsigned char * initialization_vector,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * pad_character,
              unsigned char * chaining_vector,
              unsigned char * ciphertext)
{
}

/* PKA Decrypt */
void CSNDPKD (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * enciphered_key_length,
              unsigned char * enciphered_key,
              long          * data_struct_length,
              unsigned char * data_struct,
              long          * RSA_private_key_length,
              unsigned char * RSA_private_key,
              long          * key_value_length,
              unsigned char * key_value)
{
}

