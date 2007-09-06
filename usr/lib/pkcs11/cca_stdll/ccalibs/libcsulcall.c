
#include "csulincl.h"


/* Random Number Generate */
void CSNBRNG (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * form,
              unsigned char * random_number)
{
}

/* PKA Key Token Build */
void CSNDPKB (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_values_structure_length,
              unsigned char * key_values_structure,
              long          * key_name_ln,
              unsigned char * key_name,
              long          * reserved_1_length,
              unsigned char * reserved_1,
              long          * reserved_2_length,
              unsigned char * reserved_2,
              long          * reserved_3_length,
              unsigned char * reserved_3,
              long          * reserved_4_length,
              unsigned char * reserved_4,
              long          * reserved_5_length,
              unsigned char * reserved_5,
              long          * token_length,
              unsigned char * token)
{
}

/* Digital Signature Generate */
void CSNDDSG (long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * PKA_private_key_id_length,
              unsigned char * PKA_private_key_id,
              long          * hash_length,
              unsigned char * hash,
              long          * signature_field_length,
              long          * signature_bit_length,
              unsigned char * signature_field)
{
}

