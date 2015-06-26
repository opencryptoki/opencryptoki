/******************************************************************************/
/*  Licensed Materials Property of IBM                                        */
/*  (C) Copyright IBM Corporation, 1997, 2005                                 */
/*  All Rights Reserved                                                       */
/*  US Government Users Restricted Rights -                                   */
/*  Use, duplication or disclosure restricted by                              */
/*  GSA ADP Schedule Contract with IBM Corp.                                  */
/******************************************************************************/
/*                                                                            */
/*  This header file contains the Security API C language                     */
/*  prototypes.  See the user publications for more information.              */
/*                                                                            */
/******************************************************************************/

#ifndef __CSULINCL
#define __CSULINCL

/*
 * define system linkage macros for the target platform
 */

    #define SECURITYAPI

/*
 * define system linkage to the security API
 */

  #define CSNBCKI   CSNBCKI_32
  #define CSNBCKM   CSNBCKM_32
  #define CSNBDKX   CSNBDKX_32
  #define CSNBDKM   CSNBDKM_32
  #define CSNBMKP   CSNBMKP_32
  #define CSNBKEX   CSNBKEX_32
  #define CSNBKGN   CSNBKGN_32
  #define CSNBKIM   CSNBKIM_32
  #define CSNBKPI   CSNBKPI_32
  #define CSNBKRC   CSNBKRC_32
  #define CSNBAKRC  CSNBAKRC_32
  #define CSNBKRD   CSNBKRD_32
  #define CSNBKRL   CSNBKRL_32
  #define CSNBKRR   CSNBKRR_32
  #define CSNBKRW   CSNBKRW_32
  #define CSNDKRC   CSNDKRC_32
  #define CSNDKRD   CSNDKRD_32
  #define CSNDKRL   CSNDKRL_32
  #define CSNDKRR   CSNDKRR_32
  #define CSNDKRW   CSNDKRW_32
  #define CSNBKYT   CSNBKYT_32
  #define CSNBKSI   CSNBKSI_32
  #define CSNBKTC   CSNBKTC_32
  #define CSNBKTR   CSNBKTR_32
  #define CSNBRNG   CSNBRNG_32
  #define CSNBDEC   CSNBDEC_32
  #define CSNBENC   CSNBENC_32
  #define CSNBMGN   CSNBMGN_32
  #define CSNBMVR   CSNBMVR_32
  #define CSNBKTB   CSNBKTB_32
  #define CSNDPKG   CSNDPKG_32
  #define CSNDPKB   CSNDPKB_32
  #define CSNBOWH   CSNBOWH_32
  #define CSNDPKI   CSNDPKI_32
  #define CSNDDSG   CSNDDSG_32
  #define CSNDDSV   CSNDDSV_32
  #define CSNDKTC   CSNDKTC_32
  #define CSNDPKX   CSNDPKX_32
  #define CSNDSYI   CSNDSYI_32
  #define CSNDSYX   CSNDSYX_32
  #define CSUACFQ   CSUACFQ_32
  #define CSUACFC   CSUACFC_32
  #define CSNDSBC   CSNDSBC_32
  #define CSNDSBD   CSNDSBD_32
  #define CSUALCT   CSUALCT_32
  #define CSUAACM   CSUAACM_32
  #define CSUAACI   CSUAACI_32
  #define CSNDPKH   CSNDPKH_32
  #define CSNDPKR   CSNDPKR_32
  #define CSUAMKD   CSUAMKD_32
  #define CSNDRKD   CSNDRKD_32
  #define CSNDRKL   CSNDRKL_32
  #define CSNBPTR   CSNBPTR_32
  #define CSNBCPE   CSNBCPE_32
  #define CSNBCPA   CSNBCPA_32
  #define CSNBPGN   CSNBPGN_32
  #define CSNBPVR   CSNBPVR_32
  #define CSNDSYG   CSNDSYG_32
  #define CSNBDKG   CSNBDKG_32
  #define CSNBEPG   CSNBEPG_32
  #define CSNBCVE   CSNBCVE_32
  #define CSNBCSG   CSNBCSG_32
  #define CSNBCSV   CSNBCSV_32
  #define CSNBCVG   CSNBCVG_32
  #define CSNBKTP   CSNBKTP_32
  #define CSNDPKE   CSNDPKE_32
  #define CSNDPKD   CSNDPKD_32
  #define CSNBPEX   CSNBPEX_32
  #define CSNBPEXX  CSNBPEXX_32
  #define CSUARNT   CSUARNT_32
  #define CSNBCVT   CSNBCVT_32
  #define CSNBMDG   CSNBMDG_32
  #define CSUACRA   CSUACRA_32
  #define CSUACRD   CSUACRD_32
  #define CSNBTRV   CSNBTRV_32
  #define CSUAPCV   CSUAPCV_32
  #define CSNBKYTX  CSNBKYTX_32
  #define CSNBSPN   CSNBSPN_32
  #define CSNBSKY   CSNBSKY_32
  #define CSNBPCU   CSNBPCU_32
  #define CSUAPRB   CSUAPRB_32
  #define CSUADHK   CSUADHK_32
  #define CSUADHQ   CSUADHQ_32
  #define CSNDTBC   CSNDTBC_32
  #define CSNDRKX   CSNDRKX_32
  #define CSNBKET   CSNBKET_32
  #define CSNBSAE   CSNBSAE_32
  #define CSNBSAD   CSNBSAD_32

/*
 * security API prototypes
 */

/* Clear Key Import */
extern void SECURITYAPI
   CSNBCKI_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * clear_key,
              unsigned char * target_key_identifier);

/* Clear Key Import Multiple */
extern void SECURITYAPI
   CSNBCKM_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * clear_key_length,
              unsigned char * clear_key,
              unsigned char * target_key_identifier);


/* Data Key Export */
extern void SECURITYAPI
   CSNBDKX_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * source_key_identifier,
              unsigned char * exporter_key_identifier,
              unsigned char * target_key_token);

/* Data Key Import */
extern void SECURITYAPI
   CSNBDKM_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * source_key_token,
              unsigned char * importer_key_identifier,
              unsigned char * target_key_identifier);

/* DES Master Key Process */
extern void SECURITYAPI
   CSNBMKP_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_part);

/* Key Export */
extern void SECURITYAPI
   CSNBKEX_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_type,
              unsigned char * source_key_identifier,
              unsigned char * exporter_key_identifier,
              unsigned char * target_key_token);

/* Key Generate */
extern void SECURITYAPI
   CSNBKGN_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_form,
              unsigned char * key_length,
              unsigned char * key_type_1,
              unsigned char * key_type_2,
              unsigned char * KEK_key_identifier_1,
              unsigned char * KEK_key_identifier_2,
              unsigned char * generated_key_identifier_1,
              unsigned char * generated_key_identifier_2);

/* Key Import */
extern void SECURITYAPI
   CSNBKIM_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_type,
              unsigned char * source_key_token,
              unsigned char * importer_key_identifier,
              unsigned char * target_key_identifier);

/* Key Part Import */
extern void SECURITYAPI
   CSNBKPI_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_part,
              unsigned char * key_identifier);

/* Key Storage Initialization */
extern void SECURITYAPI
   CSNBKSI_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * file_name_length,
              unsigned char * file_name,
              long          * description_length,
              unsigned char * description,
              unsigned char * clear_master_key);

/* Key Record Create */
extern void SECURITYAPI
   CSNBKRC_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_label);
/* AES Key Record Create */
extern void SECURITYAPI
   CSNBAKRC_32(long          * return_code,
              	long          * reason_code,
              	long          * exit_data_length,
              	unsigned char * exit_data,
              	unsigned char * key_label,
		long	      * key_token_length,
		unsigned char *	key_token);

/* Key Record Delete */
extern void SECURITYAPI
   CSNBKRD_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier);

/* Key Record List */
extern void SECURITYAPI
   CSNBKRL_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_label,
              long          * data_set_name_length,
              unsigned char * data_set_name,
              unsigned char * security_server_name);

/* Key Record Read */
extern void SECURITYAPI
   CSNBKRR_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_label,
              unsigned char * key_token);

/* Key Record Write */
extern void SECURITYAPI
   CSNBKRW_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_token,
              unsigned char * key_label);

/* PKA Key Record Create */
extern void SECURITYAPI
   CSNDKRC_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label,
              long          * key_token_length,
              unsigned char * key_token);

/* PKA Key Record Delete */
extern void SECURITYAPI
   CSNDKRD_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier);

/* PKA Key Record List */
extern void SECURITYAPI
   CSNDKRL_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label,
              long          * data_set_name_length,
              unsigned char * data_set_name,
              unsigned char * security_server_name);

/* PKA Key Record Read */
extern void SECURITYAPI
   CSNDKRR_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label,
              long          * key_token_length,
              unsigned char * key_token);

/* PKA Key Record Write */
extern void SECURITYAPI
   CSNDKRW_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label,
              long          * key_token_length,
              unsigned char * key_token );

/* Key Test */
extern void SECURITYAPI
   CSNBKYT_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier,
              unsigned char * random_number,
              unsigned char * verification_pattern);

/* Key Test Extended @b3a*/
extern void SECURITYAPI
  CSNBKYTX_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier,
              unsigned char * random_number,
              unsigned char * verification_pattern,
              unsigned char * kek_key_identifier);

/* Des Key Token Change */
extern void SECURITYAPI
   CSNBKTC_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier);

/* Key Translate */
extern void SECURITYAPI
   CSNBKTR_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * input_key_token,
              unsigned char * input_KEK_key_identifier,
              unsigned char * output_KEK_key_identifier,
              unsigned char * output_key_token);

/* Random Number Generate */
extern void SECURITYAPI
   CSNBRNG_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * form,
              unsigned char * random_number);

extern void SECURITYAPI
   CSNBSAE_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long	    * rule_array_count,
	      unsigned char * rule_array,
	      long	    * key_identifier_length,
	      unsigned char * key_identifier,
              long	    * key_params_length,
	      unsigned char * key_params,
	      long	    * block_size,
              long          * initialization_vector_length,
              unsigned char * initialization_vector,
              long          * chaining_vector_length,
              unsigned char * chaining_vector,
              long          * text_length,
              unsigned char * text,
              long          * ciphertext_length,
              unsigned char * ciphertext,
              long          * optional_data_length,
              unsigned char * optional_data);

extern void SECURITYAPI
   CSNBSAD_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long	    * rule_array_count,
	      unsigned char * rule_array,
	      long	    * key_identifier_length,
	      unsigned char * key_identifier,
              long	    * key_params_length,
	      unsigned char * key_params,
	      long	    * block_size,
              long          * initialization_vector_length,
              unsigned char * initialization_vector,
              long          * chaining_vector_length,
              unsigned char * chaining_vector,
              long          * ciphertext_length,
              unsigned char * ciphertext,
              long          * text_length,
              unsigned char * text,
              long          * optional_data_length,
              unsigned char * optional_data);

/* Decipher */
extern void SECURITYAPI
   CSNBDEC_32(long          * return_code,
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
              unsigned char * plaintext);

/* Encipher */
extern void SECURITYAPI
   CSNBENC_32(long          * return_code,
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
              unsigned char * ciphertext);

/* MAC Generate */
extern void SECURITYAPI
   CSNBMGN_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_identifier,
              long          * text_length,
              unsigned char * text,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * chaining_vector,
              unsigned char * MAC);

/* MAC Verify */
extern void SECURITYAPI
   CSNBMVR_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_identifier,
              long          * text_length,
              unsigned char * text,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * chaining_vector,
              unsigned char * MAC);

/* Key Token Build */
extern void SECURITYAPI
   CSNBKTB_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_token,
              unsigned char * key_type,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_value,
              void          * reserved_field_1,
              long          * reserved_field_2,
              unsigned char * reserved_field_3,
              unsigned char * control_vector,
              unsigned char * reserved_field_4,
              long          * reserved_field_5,
              unsigned char * reserved_field_6,
              unsigned char * master_key_verification_number );


/* PKA Key Generate */
extern void SECURITYAPI
   CSNDPKG_32(long          * return_code,
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
              unsigned char * generated_key_identifier);

/* PKA Key Token Build */
extern void SECURITYAPI
   CSNDPKB_32(long          * return_code,
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
              unsigned char * token);

/* One Way Hash */
extern void SECURITYAPI
   CSNBOWH_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * text_length,
              unsigned char * text,
              long          * chaining_vector_length,
              unsigned char * chaining_vector,
              long          * hash_length,
              unsigned char * hash);

/* PKA Key Import */
extern void SECURITYAPI
   CSNDPKI_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * source_key_token_length,
              unsigned char * source_key_token,
              unsigned char * importer_key_identifier,
              long          * target_key_identifier_length,
              unsigned char * target_key_identifier);

/* Digital Signature Generate */
extern void SECURITYAPI
   CSNDDSG_32(long          * return_code,
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
              unsigned char * signature_field);

/* Digital Signature Verify */
extern void SECURITYAPI
   CSNDDSV_32(long          * return_code,
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
              unsigned char * signature_field);

/* PKA Key Token Change */
extern void SECURITYAPI
   CSNDKTC_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_id_length,
              unsigned char * key_id);

/* PKA Public Key Extract */
extern void SECURITYAPI
   CSNDPKX_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * source_key_identifier_length,
              unsigned char * source_key_identifier,
              long          * target_key_token_length,
              unsigned char * target_key_token);

/* PKA Symmetric Key Import */
extern void SECURITYAPI
   CSNDSYI_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * RSA_enciphered_key_length,
              unsigned char * RSA_enciphered_key,
              long          * RSA_private_key_identifier_len,
              unsigned char * RSA_private_key_identifier,
              long          * target_key_identifier_length,
              unsigned char * target_key_identifier);

/* PKA Symmetric Key Export */
extern void SECURITYAPI
   CSNDSYX_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * source_key_identifier_length,
              unsigned char * source_key_identifier,
              long          * RSA_public_key_identifier_len,
              unsigned char * RSA_public_key_identifier,
              long          * RSA_enciphered_key_length,
              unsigned char * RSA_enciphered_key);

/* Crypto Facility Query */
extern void 
   CSUACFQ_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * verb_data_length,
              unsigned char * verb_data);

/* Crypto Facility Control */
extern void SECURITYAPI
   CSUACFC_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * verb_data_length,
              unsigned char * verb_data);

/* Compose SET Block */
extern void SECURITYAPI
   CSNDSBC_32(long          * ReturnCode,
              long          * ReasonCode,
              long          * ExitDataLength,
              unsigned char * ExitData,
              long          * RuleArrayCount,
              unsigned char * RuleArray,
              unsigned char * BlockContentsIdentifier,
              long          * XDataStringLength,
              unsigned char * XDataString,
              long          * DataToEncryptLength,
              unsigned char * DataToEncrypt,
              long          * DataToHashLength,
              unsigned char * DataToHash,
              unsigned char * InitializationVector,
              long          * RSAPublicKeyIdentifierLength,
              unsigned char * RSAPublicKeyIdentifier,
              long          * DESKeyBLockLength,
              unsigned char * DESKeyBlock,
              long          * RSAOAEPBlockLength,
              unsigned char * RSAOAEPBlock,
              unsigned char * ChainingVector,
              unsigned char * DESEncryptedDataBlock );

/* Decompose SET Block */
extern void SECURITYAPI
   CSNDSBD_32(long          * ReturnCode,
              long          * ReasonCode,
              long          * ExitDataLength,
              unsigned char * ExitData,
              long          * RuleArrayCount,
              unsigned char * RuleArray,
              long          * RSAOAEPBlockLength,
              unsigned char * RSAOAEPBlock,
              long          * DESEncryptedDataBlockLength,
              unsigned char * DESEncryptedDataBlock,
              unsigned char * InitializationVector,
              long          * RSAPrivateKeyIdentifierLength,
              unsigned char * RSAPrivateKeyIdentifier,
              long          * DESKeyBLockLength,
              unsigned char * DESKeyBlock,
              unsigned char * BlockContentsIdentifier,
              long          * XDataStringLength,
              unsigned char * XDataString,
              unsigned char * ChainingVector,
              unsigned char * DataBlock,
              long          * HashBlockLength,
              unsigned char * HashBlock );

/* Access Control Logon */
extern void SECURITYAPI
   CSUALCT_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * user_id,
              long          * auth_parm_length,
              unsigned char * auth_parm,
              long          * auth_data_length,
              unsigned char * auth_data);

/* Access Control Maintenance */
extern void SECURITYAPI
   CSUAACM_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * name,
              long          * output_data_length,
              unsigned char * output_data);

/* Access Control Initialization */
extern void SECURITYAPI
   CSUAACI_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * verb_data_1_length,
              unsigned char * verb_data_1,
              long          * verb_data_2_length,
              unsigned char * verb_data_2);


/* PKA Public Key Hash Register */
extern void SECURITYAPI
   CSNDPKH_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * public_key_name,
              long          * hash_data_length,
              unsigned char * hash_data);


/* PKA Public Key Register */
extern void SECURITYAPI
   CSNDPKR_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * public_key_name,
              long          * public_key_certificate_length,
              unsigned char * public_key_certificate);


/* Master Key Distribution */
extern void SECURITYAPI
   CSUAMKD_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * share_index,
              unsigned char * private_key_name,
              unsigned char * certifying_key_name,
              long          * certificate_length,
              unsigned char * certificate,
              long          * clone_info_encrypting_key_length,
              unsigned char * clone_info_encrypting_key,
              long          * clone_info_length,
              unsigned char * clone_info);


/* Retained Key Delete */
extern void SECURITYAPI
   CSNDRKD_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label);


/* Retained Key List */
extern void SECURITYAPI
   CSNDRKL_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label_mask,
              long          * retained_keys_count,
              long          * key_labels_count,
              unsigned char * key_labels);

/* Symmetric Key Generate */
extern void SECURITYAPI
   CSNDSYG_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_encrypting_key,
              long          * rsapub_key_length,
              unsigned char * rsapub_key,
              long          * locenc_key_length,
              unsigned char * locenc_key,
              long          * rsaenc_key_length,
              unsigned char * rsaenc_key);


/* Encrypted PIN Translate */
extern void SECURITYAPI
   CSNBPTR_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * in_PIN_enc_key_id,
              unsigned char * out_PIN_enc_key_id,
              unsigned char * in_PIN_profile,
              unsigned char * in_PAN_data,
              unsigned char * in_PIN_blk,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * out_PIN_profile,
              unsigned char * out_PAN_data,
              long          * sequence_number,
              unsigned char * put_PIN_blk);


/* Clear PIN Encrypt */
extern void SECURITYAPI
   CSNBCPE_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * PIN_enc_key_id,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * clear_PIN,
              unsigned char * PIN_profile,
              unsigned char * PAN_data,
              long          * sequence_number,
              unsigned char * encrypted_PIN_blk);


/* Clear PIN Generate Alternate */
extern void SECURITYAPI
   CSNBCPA_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * PIN_enc_key_id,
              unsigned char * PIN_gen_key_id,
              unsigned char * PIN_profile,
              unsigned char * PAN_data,
              unsigned char * encrypted_PIN_blk,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * PIN_check_length,
              unsigned char * data_array,
              unsigned char * returned_result);


/* Clear PIN Generate */
extern void SECURITYAPI
   CSNBPGN_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * PIN_gen_key_id,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * PIN_length,
              long          * PIN_check_length,
              unsigned char * data_array,
              unsigned char * returned_result);


/* Encrypted PIN Verify */
extern void SECURITYAPI
   CSNBPVR_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * PIN_enc_key_id,
              unsigned char * PIN_ver_key_id,
              unsigned char * PIN_profile,
              unsigned char * PAN_data,
              unsigned char * encrypted_PIN_blk,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * PIN_check_length,
              unsigned char * data_array);

/* Diversified Key Generate */
extern void SECURITYAPI
   CSNBDKG_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * generating_key_id,
              long          * data_length,
              unsigned char * data,
              unsigned char * decrypting_key_id,
              unsigned char * generated_key_id);

/* Encrypted PIN Generate */
extern void SECURITYAPI
   CSNBEPG_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * PIN_gen_key_id,
              unsigned char * outPIN_enc_key_id,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * PIN_length,
              unsigned char * data_array,
              unsigned char * outPIN_profile,
              unsigned char * PAN_data,
              long          * sequence_number,
              unsigned char * encrypted_PIN_blk);

/* Cryptographic Variable Encipher */
extern void SECURITYAPI
   CSNBCVE_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * cvarenc_key_id,
              long          * text_length,
              unsigned char * plain_text,
              unsigned char * init_vector,
              unsigned char * cipher_text);

/* CVV Generate */
extern void SECURITYAPI
   CSNBCSG_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * PAN_data,
              unsigned char * expiration_date,
              unsigned char * service_code,
              unsigned char * key_a_id,
              unsigned char * key_b_id,
              unsigned char * generated_cvv);

/* CVV Verify */
extern void SECURITYAPI
   CSNBCSV_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * PAN_data,
              unsigned char * expiration_date,
              unsigned char * service_code,
              unsigned char * key_a_id,
              unsigned char * key_b_id,
              unsigned char * generated_cvv);

/* Control Vector Generate */
extern void SECURITYAPI
   CSNBCVG_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_type,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * reserved_field_1,
              unsigned char * control_vector);

/* Key Token Parse */
extern void SECURITYAPI
   CSNBKTP_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_token,
              unsigned char * key_type,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_value,
              void          * master_key_verification_pattern_v03,
              long          * reserved_field_1,
              unsigned char * reserved_field_2,
              unsigned char * control_vector,
              unsigned char * reserved_field_3,
              long          * reserved_field_4,
              unsigned char * reserved_field_5,
              unsigned char * master_key_verification_pattern_v00);

/* PKA Encrypt */
extern void   SECURITYAPI
   CSNDPKE_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_value_length,
              unsigned char * key_value,
              long          * data_struct_length,
              unsigned char * data_struct,
              long          * RSA_public_key_length,
              unsigned char * RSA_public_key,
              long          * RSA_encipher_length,
              unsigned char * RSA_encipher);

/* PKA Decrypt */
extern void   SECURITYAPI
   CSNDPKD_32(long          * return_code,
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
              unsigned char * key_value);

/* Prohibit Export */
extern void   SECURITYAPI
   CSNBPEX_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_identifier);

/* Prohibit Export Extended */
extern void   SECURITYAPI
  CSNBPEXX_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * Source_key_token,
              unsigned char * Kek_key_identifier);

/* Random Number/Known Answer Test */
extern void   SECURITYAPI
   CSUARNT_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array);

/* Control Vector Translate */
extern void  SECURITYAPI
   CSNBCVT_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * kek_key_identifier,
              unsigned char * source_key_token,
              unsigned char * array_key_left,
              unsigned char * mask_array_left,
              unsigned char * array_key_right,
              unsigned char * mask_array_right,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * target_key_token);

/* MDC Generate */
extern void SECURITYAPI
   CSNBMDG_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * text_length,
              unsigned char * text_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * chaining_vector,
              unsigned char * MDC);

/* Cryptographic Resource Allocate */
extern void SECURITYAPI
   CSUACRA_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * resource_name_length,
              unsigned char * resource_name);

/* Cryptographic Resource Deallocate */
extern void SECURITYAPI
   CSUACRD_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * resource_name_length,
              unsigned char * resource_name);

/* Transaction Validation */
extern void SECURITYAPI
   CSNBTRV_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * transaction_key_length,
              unsigned char * transaction_key,
              long          * transaction_info_length,
              unsigned char * transaction_info,
              long          * validation_values_length,
              unsigned char * validation_values);

/* Secure Messaging for Keys */
extern void  SECURITYAPI
   CSNBSKY_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * input_key_indentifier,
              unsigned char * key_encrypting_key,
              unsigned char * session_key,
              long          * text_length,
              unsigned char * clear_text,
              unsigned char * initialization_vector,
              long          * key_offset,
              long          * key_offset_field_length,
              unsigned char * cipher_text,
              unsigned char * output_chaining_value);

/* Secure Messaging for PINs */
extern void  SECURITYAPI
   CSNBSPN_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * in_PIN_blk,
              unsigned char * in_PIN_enc_key_id,
              unsigned char * in_PIN_profile,
              unsigned char * in_PAN_data,
              unsigned char * secmsg_key,
              unsigned char * out_PIN_profile,
              unsigned char * out_PAN_data,
              long          * text_length,
              unsigned char * clear_text,
              unsigned char * initialization_vector,
              long          * PIN_offset,
              long          * PIN_offset_field_length,
              unsigned char * cipher_text,
              unsigned char * output_chaining_value);

/* PIN Change/Unblock */
extern void  SECURITYAPI
   CSNBPCU_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * authenticationMasterKeyLength,
              unsigned char * authenticationMasterKey,
              long          * issuerMasterKeyLength,
              unsigned char * issuerMasterKey,
              long          * keyGenerationDataLength,
              unsigned char * keyGenerationData,
              long          * newRefPinKeyLength,
              unsigned char * newRefPinKey,
              unsigned char * newRefPinBlock,
              unsigned char * newRefPinProfile,
              unsigned char * newRefPanData,
              long          * currentRefPinKeyLength,
              unsigned char * currentRefPinKey,
              unsigned char * currentRefPinBlock,
              unsigned char * currentRefPinProfile,
              unsigned char * currentRefPanData,
              long          * outputPinDataLength,
              unsigned char * outputPinData,
              unsigned char * outputPinProfile,
              long          * outputPinMessageLength,
              unsigned char * outputPinMessage);

/* PCF/CUSP Key Conversion */
extern void SECURITYAPI
   CSUAPCV_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * KEK_key_identifier_length,
              unsigned char * KEK_key_identifier,
              long          * PCF_key_list_length,
              unsigned char * PCF_key_list,
              long          * output_key_list_length,
              unsigned char * output_key_list);

/*Process Request Block*/
extern void SECURITYAPI
   CSUAPRB_32(long          * pReturnCode,
              long          * pReasonCode,
              long          * pExitDataLength,
              unsigned char * pExitData,
              long          * pRuleArrayCount,
              unsigned char * pRuleArray,
              long          * pSourceLength,
              unsigned char * pSource,
              long          * pOutFileNameLength,
              unsigned char * pOutFileName,
              long          * pReplyLength,
              unsigned char * pReply);

/* Diffie-Hellman Key Load */
extern void SECURITYAPI
   CSUADHK_32(long          * ReturnCode,
              long          * ReasonCode,
              long          * ExitDataLength,
              unsigned char * ExitData,
              long          * RuleArrayCount,
              unsigned char * RuleArray,
              unsigned char * DHModulus,
              unsigned char * DHGenerator,
              unsigned char * DHKeyPart,
              long          * TransportKeyHashLength,
              unsigned char * TransportKeyHash,
              unsigned char * Reserved1,
              unsigned char * Reserved2,
              unsigned char * Reserved3,
              unsigned char * Reserved4);

/* Diffie-Hellman Key Query */
extern void SECURITYAPI
   CSUADHQ_32(long          * ReturnCode,
              long          * ReasonCode,
              long          * ExitDataLength,
              unsigned char * ExitData,
              long          * RuleArrayCount,
              unsigned char * RuleArray,
              unsigned char * DHModulus,
              unsigned char * DHGenerator,
              unsigned char * DHKeyPart,
              long          * TransportKeyHashLength,
              unsigned char * TransportKeyHash,
              unsigned char * Reserved1,
              unsigned char * Reserved2,
              unsigned char * Reserved3,
              unsigned char * Reserved4);

/* Trusted Block Create */
extern void SECURITYAPI
   CSNDTBC_32 ( long            * return_code,
                long            * reason_code,
                long            * exit_data_length,
                unsigned char   * exit_data,
                long            * rule_array_count,
                unsigned char   * rule_array,
                long            * input_block_length,
                unsigned char   * input_block_identifier,
                unsigned char   * transport_key_identifier,
                long            * trusted_blokc_length,
                unsigned char   * trusted_blokc_identifier );

/* Remote Key Export */
extern void SECURITYAPI
   CSNDRKX_32 ( long            * return_code,
                long            * reason_code,
                long            * exit_data_length,
                unsigned char   * exit_data,
                long            * rule_array_count,
                unsigned char   * rule_array,
                long            * trusted_block_length,
                unsigned char   * trusted_block_identifier,
                long            * certificate_length,
                unsigned char   * certificate,
                long            * certificate_parms_length,
                unsigned char   * certificate_parms,
                long            * transport_key_length,
                unsigned char   * transport_key_identifier,
                long            * rule_id_length,
                unsigned char   * rule_id,
                long            * export_key_kek_length,
                unsigned char   * export_key_kek_identifier,
                long            * export_key_length,
                unsigned char   * export_key_identifier,
                long            * asym_encrypted_key_length,
                unsigned char   * asym_encrypted_key,
                long            * sym_encrypted_key_length,
                unsigned char   * sym_encrypted_key,
                long            * extra_data_length,
                unsigned char   * extra_data,
                long            * key_check_parameters_length,
                unsigned char   * key_check_parameters,
                long            * key_check_length,
                unsigned char   * key_check_value );

/* Key Encryption Translate */
extern void SECURITYAPI
   CSNBKET_32(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * kek_identifier_length,
              unsigned char * kek_identifier,
              long          * key_in_length,
              unsigned char * key_in,
              long          * key_out_length,
              unsigned char * key_out);


#endif
