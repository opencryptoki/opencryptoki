/*
 * COPYRIGHT (c) International Business Machines Corp. 1997-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/******************************************************************************/
/*  US Government Users Restricted Rights - Use, duplication or disclosure    */
/* restricted by GSA ADP Schedule Contract with IBM Corp.                     */
/******************************************************************************/
/*                                                                            */
/*  This header file contains the Security API C language                     */
/*  prototypes.  See the user publications for more information.              */
/*                                                                            */
/******************************************************************************/

/* Clear Key Import */
typedef void (**CSNBCKI_t) (long *return_code,
                            long *reason_code,
                            long *exit_data_length,
                            unsigned char *exit_data,
                            unsigned char *clear_key,
                            unsigned char *target_key_identifier);

/* Clear Key Import Multiple */
typedef void (*CSNBCKM_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *clear_key_length,
                           unsigned char *clear_key,
                           unsigned char *target_key_identifier);

/* Data Key Export */
typedef void (*CSNBDKX_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *source_key_identifier,
                           unsigned char *exporter_key_identifier,
                           unsigned char *target_key_token);

/* Data    Key Import */
typedef void (*CSNBDKM_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *source_key_token,
                           unsigned char *importer_key_identifier,
                           unsigned char *target_key_identifier);

/* DES Master Key Process */
typedef void (*CSNBMKP_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array, unsigned char *key_part);

/* Key Export */
typedef void (*CSNBKEX_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_type,
                           unsigned char *source_key_identifier,
                           unsigned char *exporter_key_identifier,
                           unsigned char *target_key_token);

/* Key Generate */
typedef void (*CSNBKGN_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_form,
                           unsigned char *key_length,
                           unsigned char *key_type_1,
                           unsigned char *key_type_2,
                           unsigned char *KEK_key_identifier_1,
                           unsigned char *KEK_key_identifier_2,
                           unsigned char *generated_key_identifier_1,
                           unsigned char *generated_key_identifier_2);

/* Key Generate2 */
typedef void (*CSNBKGN2_t) (long *return_code,
                            long *reason_code,
                            long *exit_data_length,
                            unsigned char *exit_data,
                            long *rule_array_count,
                            unsigned char *rule_array,
                            long *clear_key_bit_length,
                            unsigned char *key_type_1,
                            unsigned char *key_type_2,
                            long *key_name_1_length,
                            unsigned char *key_name_1,
                            long *key_name_2_length,
                            unsigned char *key_name_2,
                            long *user_associated_data_1_length,
                            unsigned char *user_associated_data_1,
                            long *user_associated_data_2_length,
                            unsigned char *user_associated_data_2,
                            long *key_encrypting_key_identifier_1_length,
                            unsigned char *key_encrypting_key_identifier_1,
                            long *key_encrypting_key_identifier_2_length,
                            unsigned char *key_encrypting_key_identifier_2,
                            long *generated_key_identifier_1_length,
                            unsigned char *generated_key_identifier_1,
                            long *generated_key_identifier_2_length,
                            unsigned char *generated_key_identifier_2);

/* Key Import */
typedef void (*CSNBKIM_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_type,
                           unsigned char *source_key_token,
                           unsigned char *importer_key_identifier,
                           unsigned char *target_key_identifier);

/* Key Part Import */
typedef void (*CSNBKPI_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_part,
                           unsigned char *key_identifier);

/* Key Part Import2 */
typedef void (*CSNBKPI2_t) (long *return_code,
                            long *reason_code,
                            long *exit_data_length,
                            unsigned char *exit_data,
                            long *rule_array_count,
                            unsigned char *rule_array,
                            long *clear_key_part_length,
                            unsigned char *clear_key_part,
                            long *key_identifier_length,
                            unsigned char *key_identifier);

/* Key Storage Initialization */
typedef void (*CSNBKSI_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *file_name_length,
                           unsigned char *file_name,
                           long *description_length,
                           unsigned char *description,
                           unsigned char *clear_master_key);

/* Key Record Create */
typedef void (*CSNBKRC_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data, unsigned char *key_label);
/* AES Key Record Create */
typedef void (*CSNBAKRC_t) (long *return_code,
                            long *reason_code,
                            long *exit_data_length,
                            unsigned char *exit_data,
                            unsigned char *key_label,
                            long *key_token_length, unsigned char *key_token);

/* Key Record Delete */
typedef void (*CSNBKRD_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_identifier);

/* Key Record List */
typedef void (*CSNBKRL_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_label,
                           long *data_set_name_length,
                           unsigned char *data_set_name,
                           unsigned char *security_server_name);

/* Key Record Read */
typedef void (*CSNBKRR_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_label, unsigned char *key_token);

/* Key Record Write */
typedef void (*CSNBKRW_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_token, unsigned char *key_label);

/* PKA Key Record Create */
typedef void (*CSNDKRC_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_label,
                           long *key_token_length, unsigned char *key_token);

/* PKA Key Record Delete */
typedef void (*CSNDKRD_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_identifier);

/* PKA Key Record List */
typedef void (*CSNDKRL_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_label,
                           long *data_set_name_length,
                           unsigned char *data_set_name,
                           unsigned char *security_server_name);

/* PKA Key Record Read */
typedef void (*CSNDKRR_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_label,
                           long *key_token_length, unsigned char *key_token);

/* PKA Key Record Write */
typedef void (*CSNDKRW_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_label,
                           long *key_token_length, unsigned char *key_token);

/* Key Test */
typedef void (*CSNBKYT_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_identifier,
                           unsigned char *random_number,
                           unsigned char *verification_pattern);

/* Key Test Extended @b3a*/
typedef void (*CSNBKYTX_t) (long *return_code,
                            long *reason_code,
                            long *exit_data_length,
                            unsigned char *exit_data,
                            long *rule_array_count,
                            unsigned char *rule_array,
                            unsigned char *key_identifier,
                            unsigned char *random_number,
                            unsigned char *verification_pattern,
                            unsigned char *kek_key_identifier);

/* Des Key Token Change */
typedef void (*CSNBKTC_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_identifier);

/* Key Token Change 2 */
typedef void (*CSNBKTC2_t) (long *return_code,
                            long *reason_code,
                            long *exit_data_length,
                            unsigned char *exit_data,
                            long *rule_array_count,
                            unsigned char *rule_array,
                            long *key_identifier_length,
                            unsigned char *key_identifier);

/* Key Translate */
typedef void (*CSNBKTR_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *input_key_token,
                           unsigned char *input_KEK_key_identifier,
                           unsigned char *output_KEK_key_identifier,
                           unsigned char *output_key_token);

/* Random Number Generate */
typedef void (*CSNBRNG_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *form, unsigned char *random_number);

/* Random Number Generate Long */
typedef void (*CSNBRNGL_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *seed_length,
                           unsigned char *seed,
                           long *random_number_length,
                           unsigned char *random_number);

typedef void (*CSNBSAE_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *key_identifier_length,
                           unsigned char *key_identifier,
                           long *key_params_length,
                           unsigned char *key_params,
                           long *block_size,
                           long *initialization_vector_length,
                           unsigned char *initialization_vector,
                           long *chaining_vector_length,
                           unsigned char *chaining_vector,
                           long *text_length,
                           unsigned char *text,
                           long *ciphertext_length,
                           unsigned char *ciphertext,
                           long *optional_data_length,
                           unsigned char *optional_data);

typedef void (*CSNBSAD_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *key_identifier_length,
                           unsigned char *key_identifier,
                           long *key_params_length,
                           unsigned char *key_params,
                           long *block_size,
                           long *initialization_vector_length,
                           unsigned char *initialization_vector,
                           long *chaining_vector_length,
                           unsigned char *chaining_vector,
                           long *ciphertext_length,
                           unsigned char *ciphertext,
                           long *text_length,
                           unsigned char *text,
                           long *optional_data_length,
                           unsigned char *optional_data);

/* Decipher */
typedef void (*CSNBDEC_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_identifier,
                           long *text_length,
                           unsigned char *ciphertext,
                           unsigned char *initialization_vector,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *chaining_vector,
                           unsigned char *plaintext);

/* Encipher */
typedef void (*CSNBENC_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_identifier,
                           long *text_length,
                           unsigned char *plaintext,
                           unsigned char *initialization_vector,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *pad_character,
                           unsigned char *chaining_vector,
                           unsigned char *ciphertext);

/* MAC Generate */
typedef void (*CSNBMGN_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_identifier,
                           long *text_length,
                           unsigned char *text,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *chaining_vector, unsigned char *MAC);

/* MAC Verify */
typedef void (*CSNBMVR_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_identifier,
                           long *text_length,
                           unsigned char *text,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *chaining_vector, unsigned char *MAC);

/* Key Token Build */
typedef void (*CSNBKTB_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_token,
                           unsigned char *key_type,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_value,
                           void *reserved_field_1,
                           long *reserved_field_2,
                           unsigned char *reserved_field_3,
                           unsigned char *control_vector,
                           unsigned char *reserved_field_4,
                           long *reserved_field_5,
                           unsigned char *reserved_field_6,
                           unsigned char *master_key_verification_number);


/* Key Token Build2 */
typedef void (*CSNBKTB2_t) (long *return_code,
                            long *reason_code,
                            long *exit_data_length,
                            unsigned char *exit_data,
                            long *rule_array_count,
                            unsigned char *rule_array,
                            long *clear_key_bit_length,
                            unsigned char *clear_key_value,
                            long *key_name_length,
                            unsigned char *key_name,
                            long *user_associated_data_length,
                            unsigned char *user_associated_data,
                            long *token_data_length,
                            unsigned char *token_data,
                            long *reserved_length,
                            unsigned char *reserved,
                            long *target_key_token_length,
                            unsigned char *target_key_token);

/* PKA Key Generate */
typedef void (*CSNDPKG_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *regeneration_data_length,
                           unsigned char *regeneration_data,
                           long *skeleton_key_token_length,
                           unsigned char *skeleton_key_token,
                           unsigned char *transport_key_identifier,
                           long *generated_key_identifier_length,
                           unsigned char *generated_key_identifier);

/* PKA Key Token Build */
typedef void (*CSNDPKB_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *key_values_structure_length,
                           unsigned char *key_values_structure,
                           long *key_name_ln,
                           unsigned char *key_name,
                           long *reserved_1_length,
                           unsigned char *reserved_1,
                           long *reserved_2_length,
                           unsigned char *reserved_2,
                           long *reserved_3_length,
                           unsigned char *reserved_3,
                           long *reserved_4_length,
                           unsigned char *reserved_4,
                           long *reserved_5_length,
                           unsigned char *reserved_5,
                           long *token_length, unsigned char *token);

/* One Way Hash */
typedef void (*CSNBOWH_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *text_length,
                           unsigned char *text,
                           long *chaining_vector_length,
                           unsigned char *chaining_vector,
                           long *hash_length, unsigned char *hash);

/* PKA Key Import */
typedef void (*CSNDPKI_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *source_key_token_length,
                           unsigned char *source_key_token,
                           unsigned char *importer_key_identifier,
                           long *target_key_identifier_length,
                           unsigned char *target_key_identifier);

/* Digital Signature Generate */
typedef void (*CSNDDSG_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *PKA_private_key_id_length,
                           unsigned char *PKA_private_key_id,
                           long *hash_length,
                           unsigned char *hash,
                           long *signature_field_length,
                           long *signature_bit_length,
                           unsigned char *signature_field);

/* Digital Signature Verify */
typedef void (*CSNDDSV_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *PKA_public_key_id_length,
                           unsigned char *PKA_public_key_id,
                           long *hash_length,
                           unsigned char *hash,
                           long *signature_field_length,
                           unsigned char *signature_field);

/* PKA Key Token Change */
typedef void (*CSNDKTC_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *key_id_length, unsigned char *key_id);

/* PKA Public Key Extract */
typedef void (*CSNDPKX_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *source_key_identifier_length,
                           unsigned char *source_key_identifier,
                           long *target_key_token_length,
                           unsigned char *target_key_token);

/* PKA Symmetric Key Import */
typedef void (*CSNDSYI_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *RSA_enciphered_key_length,
                           unsigned char *RSA_enciphered_key,
                           long *RSA_private_key_identifier_len,
                           unsigned char *RSA_private_key_identifier,
                           long *target_key_identifier_length,
                           unsigned char *target_key_identifier);

/* PKA Symmetric Key Export */
typedef void (*CSNDSYX_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *source_key_identifier_length,
                           unsigned char *source_key_identifier,
                           long *RSA_public_key_identifier_len,
                           unsigned char *RSA_public_key_identifier,
                           long *RSA_enciphered_key_length,
                           unsigned char *RSA_enciphered_key);

/* Crypto Facility Query */
typedef void (*CSUACFQ_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *verb_data_length, unsigned char *verb_data);

/* Crypto Facility Control */
typedef void (*CSUACFC_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *verb_data_length, unsigned char *verb_data);

/* Compose SET Block */
typedef void (*CSNDSBC_t) (long *ReturnCode,
                           long *ReasonCode,
                           long *ExitDataLength,
                           unsigned char *ExitData,
                           long *RuleArrayCount,
                           unsigned char *RuleArray,
                           unsigned char *BlockContentsIdentifier,
                           long *XDataStringLength,
                           unsigned char *XDataString,
                           long *DataToEncryptLength,
                           unsigned char *DataToEncrypt,
                           long *DataToHashLength,
                           unsigned char *DataToHash,
                           unsigned char *InitializationVector,
                           long *RSAPublicKeyIdentifierLength,
                           unsigned char *RSAPublicKeyIdentifier,
                           long *DESKeyBLockLength,
                           unsigned char *DESKeyBlock,
                           long *RSAOAEPBlockLength,
                           unsigned char *RSAOAEPBlock,
                           unsigned char *ChainingVector,
                           unsigned char *DESEncryptedDataBlock);

/* Decompose SET Block */
typedef void (*CSNDSBD_t) (long *ReturnCode,
                           long *ReasonCode,
                           long *ExitDataLength,
                           unsigned char *ExitData,
                           long *RuleArrayCount,
                           unsigned char *RuleArray,
                           long *RSAOAEPBlockLength,
                           unsigned char *RSAOAEPBlock,
                           long *DESEncryptedDataBlockLength,
                           unsigned char *DESEncryptedDataBlock,
                           unsigned char *InitializationVector,
                           long *RSAPrivateKeyIdentifierLength,
                           unsigned char *RSAPrivateKeyIdentifier,
                           long *DESKeyBLockLength,
                           unsigned char *DESKeyBlock,
                           unsigned char *BlockContentsIdentifier,
                           long *XDataStringLength,
                           unsigned char *XDataString,
                           unsigned char *ChainingVector,
                           unsigned char *DataBlock,
                           long *HashBlockLength, unsigned char *HashBlock);

/* Access Control Logon */
typedef void (*CSUALCT_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *user_id,
                           long *auth_parm_length,
                           unsigned char *auth_parm,
                           long *auth_data_length, unsigned char *auth_data);

/* Access Control Maintenance */
typedef void (*CSUAACM_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *name,
                           long *output_data_length,
                           unsigned char *output_data);

/* Access Control Initialization */
typedef void (*CSUAACI_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *verb_data_1_length,
                           unsigned char *verb_data_1,
                           long *verb_data_2_length,
                           unsigned char *verb_data_2);


/* PKA Public Key Hash Register */
typedef void (*CSNDPKH_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *public_key_name,
                           long *hash_data_length, unsigned char *hash_data);


/* PKA Public Key Register */
typedef void (*CSNDPKR_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *public_key_name,
                           long *public_key_certificate_length,
                           unsigned char *public_key_certificate);


/* Master Key Distribution */
typedef void (*CSUAMKD_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *share_index,
                           unsigned char *private_key_name,
                           unsigned char *certifying_key_name,
                           long *certificate_length,
                           unsigned char *certificate,
                           long *clone_info_encrypting_key_length,
                           unsigned char *clone_info_encrypting_key,
                           long *clone_info_length, unsigned char *clone_info);


/* Retained Key Delete */
typedef void (*CSNDRKD_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array, unsigned char *key_label);


/* Retained Key List */
typedef void (*CSNDRKL_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_label_mask,
                           long *retained_keys_count,
                           long *key_labels_count, unsigned char *key_labels);

/* Symmetric Key Generate */
typedef void (*CSNDSYG_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_encrypting_key,
                           long *rsapub_key_length,
                           unsigned char *rsapub_key,
                           long *locenc_key_length,
                           unsigned char *locenc_key,
                           long *rsaenc_key_length, unsigned char *rsaenc_key);


/* Encrypted PIN Translate */
typedef void (*CSNBPTR_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *in_PIN_enc_key_id,
                           unsigned char *out_PIN_enc_key_id,
                           unsigned char *in_PIN_profile,
                           unsigned char *in_PAN_data,
                           unsigned char *in_PIN_blk,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *out_PIN_profile,
                           unsigned char *out_PAN_data,
                           long *sequence_number, unsigned char *put_PIN_blk);


/* Clear PIN Encrypt */
typedef void (*CSNBCPE_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *PIN_enc_key_id,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *clear_PIN,
                           unsigned char *PIN_profile,
                           unsigned char *PAN_data,
                           long *sequence_number,
                           unsigned char *encrypted_PIN_blk);


/* Clear PIN Generate Alternate */
typedef void (*CSNBCPA_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *PIN_enc_key_id,
                           unsigned char *PIN_gen_key_id,
                           unsigned char *PIN_profile,
                           unsigned char *PAN_data,
                           unsigned char *encrypted_PIN_blk,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *PIN_check_length,
                           unsigned char *data_array,
                           unsigned char *returned_result);


/* Clear PIN Generate */
typedef void (*CSNBPGN_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *PIN_gen_key_id,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *PIN_length,
                           long *PIN_check_length,
                           unsigned char *data_array,
                           unsigned char *returned_result);


/* Encrypted PIN Verify */
typedef void (*CSNBPVR_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *PIN_enc_key_id,
                           unsigned char *PIN_ver_key_id,
                           unsigned char *PIN_profile,
                           unsigned char *PAN_data,
                           unsigned char *encrypted_PIN_blk,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *PIN_check_length, unsigned char *data_array);

/* Diversified Key Generate */
typedef void (*CSNBDKG_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *generating_key_id,
                           long *data_length,
                           unsigned char *data,
                           unsigned char *decrypting_key_id,
                           unsigned char *generated_key_id);

/* Encrypted PIN Generate */
typedef void (*CSNBEPG_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *PIN_gen_key_id,
                           unsigned char *outPIN_enc_key_id,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *PIN_length,
                           unsigned char *data_array,
                           unsigned char *outPIN_profile,
                           unsigned char *PAN_data,
                           long *sequence_number,
                           unsigned char *encrypted_PIN_blk);

/* Cryptographic Variable Encipher */
typedef void (*CSNBCVE_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *cvarenc_key_id,
                           long *text_length,
                           unsigned char *plain_text,
                           unsigned char *init_vector,
                           unsigned char *cipher_text);

/* CVV Generate */
typedef void (*CSNBCSG_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *PAN_data,
                           unsigned char *expiration_date,
                           unsigned char *service_code,
                           unsigned char *key_a_id,
                           unsigned char *key_b_id,
                           unsigned char *generated_cvv);

/* CVV Verify */
typedef void (*CSNBCSV_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *PAN_data,
                           unsigned char *expiration_date,
                           unsigned char *service_code,
                           unsigned char *key_a_id,
                           unsigned char *key_b_id,
                           unsigned char *generated_cvv);

/* Control Vector Generate */
typedef void (*CSNBCVG_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_type,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *reserved_field_1,
                           unsigned char *control_vector);

/* Key Token Parse */
typedef void (*CSNBKTP_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_token,
                           unsigned char *key_type,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *key_value,
                           void *master_key_verification_pattern_v03,
                           long *reserved_field_1,
                           unsigned char *reserved_field_2,
                           unsigned char *control_vector,
                           unsigned char *reserved_field_3,
                           long *reserved_field_4,
                           unsigned char *reserved_field_5,
                           unsigned char *master_key_verification_pattern_v00);

/* PKA Encrypt */
typedef void (*CSNDPKE_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *key_value_length,
                           unsigned char *key_value,
                           long *data_struct_length,
                           unsigned char *data_struct,
                           long *RSA_public_key_length,
                           unsigned char *RSA_public_key,
                           long *RSA_encipher_length,
                           unsigned char *RSA_encipher);

/* PKA Decrypt */
typedef void (*CSNDPKD_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *enciphered_key_length,
                           unsigned char *enciphered_key,
                           long *data_struct_length,
                           unsigned char *data_struct,
                           long *RSA_private_key_length,
                           unsigned char *RSA_private_key,
                           long *key_value_length, unsigned char *key_value);

/* Prohibit Export */
typedef void (*CSNBPEX_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *key_identifier);

/* Prohibit Export Extended */
typedef void (*CSNBPEXX_t) (long *return_code,
                            long *reason_code,
                            long *exit_data_length,
                            unsigned char *exit_data,
                            unsigned char *Source_key_token,
                            unsigned char *Kek_key_identifier);

/* Random Number/Known Answer Test */
typedef void (*CSUARNT_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count, unsigned char *rule_array);

/* Control Vector Translate */
typedef void (*CSNBCVT_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           unsigned char *kek_key_identifier,
                           unsigned char *source_key_token,
                           unsigned char *array_key_left,
                           unsigned char *mask_array_left,
                           unsigned char *array_key_right,
                           unsigned char *mask_array_right,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *target_key_token);

/* MDC Generate */
typedef void (*CSNBMDG_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *text_length,
                           unsigned char *text_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *chaining_vector, unsigned char *MDC);

/* Cryptographic Resource Allocate */
typedef void (*CSUACRA_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *resource_name_length,
                           unsigned char *resource_name);

/* Cryptographic Resource Deallocate */
typedef void (*CSUACRD_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *resource_name_length,
                           unsigned char *resource_name);

/* Transaction Validation */
typedef void (*CSNBTRV_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *transaction_key_length,
                           unsigned char *transaction_key,
                           long *transaction_info_length,
                           unsigned char *transaction_info,
                           long *validation_values_length,
                           unsigned char *validation_values);

/* Secure Messaging for Keys */
typedef void (*CSNBSKY_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *input_key_indentifier,
                           unsigned char *key_encrypting_key,
                           unsigned char *session_key,
                           long *text_length,
                           unsigned char *clear_text,
                           unsigned char *initialization_vector,
                           long *key_offset,
                           long *key_offset_field_length,
                           unsigned char *cipher_text,
                           unsigned char *output_chaining_value);

/* Secure Messaging for PINs */
typedef void (*CSNBSPN_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           unsigned char *in_PIN_blk,
                           unsigned char *in_PIN_enc_key_id,
                           unsigned char *in_PIN_profile,
                           unsigned char *in_PAN_data,
                           unsigned char *secmsg_key,
                           unsigned char *out_PIN_profile,
                           unsigned char *out_PAN_data,
                           long *text_length,
                           unsigned char *clear_text,
                           unsigned char *initialization_vector,
                           long *PIN_offset,
                           long *PIN_offset_field_length,
                           unsigned char *cipher_text,
                           unsigned char *output_chaining_value);

/* PIN Change/Unblock */
typedef void (*CSNBPCU_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *authenticationMasterKeyLength,
                           unsigned char *authenticationMasterKey,
                           long *issuerMasterKeyLength,
                           unsigned char *issuerMasterKey,
                           long *keyGenerationDataLength,
                           unsigned char *keyGenerationData,
                           long *newRefPinKeyLength,
                           unsigned char *newRefPinKey,
                           unsigned char *newRefPinBlock,
                           unsigned char *newRefPinProfile,
                           unsigned char *newRefPanData,
                           long *currentRefPinKeyLength,
                           unsigned char *currentRefPinKey,
                           unsigned char *currentRefPinBlock,
                           unsigned char *currentRefPinProfile,
                           unsigned char *currentRefPanData,
                           long *outputPinDataLength,
                           unsigned char *outputPinData,
                           unsigned char *outputPinProfile,
                           long *outputPinMessageLength,
                           unsigned char *outputPinMessage);

/*Process Request Block*/
typedef void (*CSUAPRB_t) (long *pReturnCode,
                           long *pReasonCode,
                           long *pExitDataLength,
                           unsigned char *pExitData,
                           long *pRuleArrayCount,
                           unsigned char *pRuleArray,
                           long *pSourceLength,
                           unsigned char *pSource,
                           long *pOutFileNameLength,
                           unsigned char *pOutFileName,
                           long *pReplyLength, unsigned char *pReply);

/* Trusted Block Create */
typedef void (*CSNDTBC_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *input_block_length,
                           unsigned char *input_block_identifier,
                           unsigned char *transport_key_identifier,
                           long *trusted_blokc_length,
                           unsigned char *trusted_blokc_identifier);

/* Remote Key Export */
typedef void (*CSNDRKX_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *trusted_block_length,
                           unsigned char *trusted_block_identifier,
                           long *certificate_length,
                           unsigned char *certificate,
                           long *certificate_parms_length,
                           unsigned char *certificate_parms,
                           long *transport_key_length,
                           unsigned char *transport_key_identifier,
                           long *rule_id_length,
                           unsigned char *rule_id,
                           long *export_key_kek_length,
                           unsigned char *export_key_kek_identifier,
                           long *export_key_length,
                           unsigned char *export_key_identifier,
                           long *asym_encrypted_key_length,
                           unsigned char *asym_encrypted_key,
                           long *sym_encrypted_key_length,
                           unsigned char *sym_encrypted_key,
                           long *extra_data_length,
                           unsigned char *extra_data,
                           long *key_check_parameters_length,
                           unsigned char *key_check_parameters,
                           long *key_check_length,
                           unsigned char *key_check_value);

/* Key Encryption Translate */
typedef void (*CSNBKET_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *kek_identifier_length,
                           unsigned char *kek_identifier,
                           long *key_in_length,
                           unsigned char *key_in,
                           long *key_out_length, unsigned char *key_out);


/* HMAC Generate */
typedef void (*CSNBHMG_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *key_identifier_length,
                           unsigned char *key_identifier,
                           long *message_text_length,
                           unsigned char *message_text,
                           long *chaining_vector_length,
                           unsigned char *chaining_vector,
                           long *MAC_length, unsigned char *MAC_text);

/* HMAC Verify */
typedef void (*CSNBHMV_t) (long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *key_identifier_length,
                           unsigned char *key_identifier,
                           long *message_text_length,
                           unsigned char *message_text,
                           long *chaining_vector_length,
                           unsigned char *chaining_vector,
                           long *MAC_length, unsigned char *MAC_text);

/* Cipher Text Translate 2 */
typedef void (*CSNBCTT2_t)(long *return_code,
                           long *reason_code,
                           long *exit_data_length,
                           unsigned char *exit_data,
                           long *rule_array_count,
                           unsigned char *rule_array,
                           long *key_identifier_in_length,
                           unsigned char *key_identifier_in,
                           long *init_vector_in_length,
                           unsigned char *init_vector_in,
                           long *cipher_text_in_length,
                           unsigned char *cipher_text_in,
                           long *chaining_vector_length,
                           unsigned char *chaining_vector,
                           long *key_identifier_out_length,
                           unsigned char *key_identifier_out,
                           long *init_vector_out_length,
                           unsigned char *init_vector_out,
                           long *cipher_text_out_length,
                           unsigned char *cipher_text_out,
                           long *reserved1_length,
                           unsigned long *reserved1,
                           long *reserved2_length,
                           unsigned char *reserved2);

/* Cryptographic Facility Version */
typedef void (*CSUACFV_t)(long *return_code,
                          long *reason_code,
                          long *exit_data_length,
                          unsigned char *exit_data,
                          long *version_data_length,
                          unsigned char *version_data);
