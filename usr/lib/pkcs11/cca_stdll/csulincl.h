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
/* Module Name: csulincl.h                                                    */
/*                                                                            */
/* US Government Users Restricted Rights - Use, duplication or disclosure     */
/* restricted by GSA ADP Schedule Contract with IBM Corp.                     */
/*                                                                            */
/* Function:                                                                  */
/* This header file contains the Security API C language prototypes for the   */
/* Linux platform.                                                            */
/*                                                                            */
/* User publications are available at:                                        */
/*                                                                            */
/* http://www.ibm.com/security/cryptocards                                    */
/******************************************************************************/

/*
 * Following check assures that this include file is included only once.
 */
#ifndef __CSULINCL__
#define __CSULINCL__

/*
 * Define system linkage macros for the target platform.
 */

#define SECURITYAPI

/*
 * The following defintion statements are provided for backward compatibility in case
 * some old version of applications are referring to these statements. This definitions
 * will be removed in future.
 */

  #define CSNBAKRC  CSNBAKRC
  #define CSNBAKRD  CSNBAKRD
  #define CSNBAKRL  CSNBAKRL
  #define CSNBAKRR  CSNBAKRR
  #define CSNBAKRW  CSNBAKRW
  #define CSNBAPG   CSNBAPG
  #define CSNBCKC   CSNBCKC
  #define CSNBCKI   CSNBCKI
  #define CSNBCKM   CSNBCKM
  #define CSNBCPA   CSNBCPA
  #define CSNBCPE   CSNBCPE
  #define CSNBCSG   CSNBCSG
  #define CSNBCSV   CSNBCSV
  #define CSNBCVE   CSNBCVE
  #define CSNBCVG   CSNBCVG
  #define CSNBCVT   CSNBCVT
  #define CSNBDEC   CSNBDEC
  #define CSNBDKG   CSNBDKG
  #define CSNBDKG2  CSNBDKG2
  #define CSNBDKM   CSNBDKM
  #define CSNBDKX   CSNBDKX
  #define CSNBDMP   CSNBDMP
  #define CSNBDPC   CSNBDPC
  #define CSNBDPCG  CSNBDPCG
  #define CSNBDPMT  CSNBDPMT
  #define CSNBDPNU  CSNBDPNU
  #define CSNBDPT   CSNBDPT
  #define CSNBDPV   CSNBDPV
  #define CSNBDRP   CSNBDRP
  #define CSNBDRPG  CSNBDRPG
  #define CSNBDDPG  CSNBDDPG
  #define CSNBENC   CSNBENC
  #define CSNBEPG   CSNBEPG
  #define CSNBFPED  CSNBFPED
  #define CSNBFPEE  CSNBFPEE
  #define CSNBFPET  CSNBFPET
  #define CSNBHMG   CSNBHMG
  #define CSNBHMV   CSNBHMV
  #define CSNBKET   CSNBKET
  #define CSNBKEX   CSNBKEX
  #define CSNBKGN   CSNBKGN
  #define CSNBKGN2  CSNBKGN2
  #define CSNBKIM   CSNBKIM
  #define CSNBKPI   CSNBKPI
  #define CSNBKPI2  CSNBKPI2
  #define CSNBKRC   CSNBKRC
  #define CSNBKRD   CSNBKRD
  #define CSNBKRL   CSNBKRL
  #define CSNBKRR   CSNBKRR
  #define CSNBKRW   CSNBKRW
  #define CSNBKSI   CSNBKSI
  #define CSNBKTB   CSNBKTB
  #define CSNBKTB2  CSNBKTB2
  #define CSNBKTC   CSNBKTC
  #define CSNBKTC2  CSNBKTC2
  #define CSNBKTP   CSNBKTP
  #define CSNBKTP2  CSNBKTP2
  #define CSNBKTR   CSNBKTR
  #define CSNBKTR2  CSNBKTR2
  #define CSNBKYT   CSNBKYT
  #define CSNBKYTX  CSNBKYTX
  #define CSNBKYT2  CSNBKYT2
  #define CSNBMDG   CSNBMDG
  #define CSNBMGN   CSNBMGN
  #define CSNBMGN2  CSNBMGN2
  #define CSNBMKP   CSNBMKP
  #define CSNBMVR   CSNBMVR
  #define CSNBMVR2  CSNBMVR2
  #define CSNBOWH   CSNBOWH
  #define CSNBPCU   CSNBPCU
  #define CSNBPEX   CSNBPEX
  #define CSNBPEXX  CSNBPEXX
  #define CSNBPEX2  CSNBPEX2
  #define CSNBPFO   CSNBPFO
  #define CSNBPGN   CSNBPGN
  #define CSNBPTR   CSNBPTR
  #define CSNBPTRE  CSNBPTRE
  #define CSNBPVR   CSNBPVR
  #define CSNBRKA   CSNBRKA
  #define CSNBRNG   CSNBRNG
  #define CSNBRNGL  CSNBRNGL
  #define CSNBSAD   CSNBSAD
  #define CSNBSAE   CSNBSAE
  #define CSNBSKY   CSNBSKY
  #define CSNBSPN   CSNBSPN
  #define CSNBTRV   CSNBTRV
  #define CSNBUKD   CSNBUKD
  #define CSNBXEA   CSNBXEA
  #define CSNDDSG   CSNDDSG
  #define CSNDDSV   CSNDDSV
  #define CSNDEDH   CSNDEDH
  #define CSNDKRC   CSNDKRC
  #define CSNDKRD   CSNDKRD
  #define CSNDKRL   CSNDKRL
  #define CSNDKRR   CSNDKRR
  #define CSNDKRW   CSNDKRW
  #define CSNDKTC   CSNDKTC
  #define CSNDPKB   CSNDPKB
  #define CSNDPKD   CSNDPKD
  #define CSNDPKE   CSNDPKE
  #define CSNDPKG   CSNDPKG
  #define CSNDPKH   CSNDPKH
  #define CSNDPKI   CSNDPKI
  #define CSNDPKR   CSNDPKR
  #define CSNDPKT   CSNDPKT
  #define CSNDPKX   CSNDPKX
  #define CSNDRKD   CSNDRKD
  #define CSNDRKL   CSNDRKL
  #define CSNDRKX   CSNDRKX
  #define CSNDSBC   CSNDSBC
  #define CSNDSBD   CSNDSBD
  #define CSNDSXD   CSNDSXD
  #define CSNDSYG   CSNDSYG
  #define CSNDSYI   CSNDSYI
  #define CSNDSYI2  CSNDSYI2
  #define CSNDSYX   CSNDSYX
  #define CSNDTBC   CSNDTBC
  #define CSUAACI   CSUAACI
  #define CSUAACM   CSUAACM
  #define CSUACFC   CSUACFC
  #define CSUACFQ   CSUACFQ
  #define CSUACFV   CSUACFV
  #define CSUACRA   CSUACRA
  #define CSUACRD   CSUACRD
  #define CSUALCT   CSUALCT
  #define CSUALGQ   CSUALGQ
  #define CSUAMKD   CSUAMKD
  #define CSUAPRB   CSUAPRB
  #define CSUARNT   CSUARNT
  #define CSNBT31O  CSNBT31O
  #define CSNBT31P  CSNBT31P
  #define CSNBT31R  CSNBT31R
  #define CSNBT31I  CSNBT31I
  #define CSNBT31X  CSNBT31X
  #define CSNBCTT2  CSNBCTT2
#ifdef TKE_WKSTN
  #define CSUADHK   CSUADHK
  #define CSUADHQ   CSUADHQ
  #define CSUACIE   CSUACIE
  #define CSUAKIX   CSUAKIX
  #define CSUAKTX   CSUAKTX
  #define CSUAMKX   CSUAMKX
  #define CSUARNX   CSUARNX
  #define CSUASKE   CSUASKE
#endif


/*
 * security API prototypes
 */

/* Authentication Parameter Generate */
extern void SECURITYAPI
     CSNBAPG(long         * pReturnCode,
             long         * pReasonCode,
             long         * pExitdatalength,
             unsigned char* pExitdata,
             long         * pRule_array_count,
             unsigned char* pRule_array,
             long         * pInboundPINEncryptingKeyLength,
             unsigned char* pInboundPINEncryptingKey,
             unsigned char* pEncryptedPINBlock,
             unsigned char* pIssuerDomesticCode,
             unsigned char* pCardSecureCode,
             unsigned char* pPANData,
             long         * pAPEncryptingKeyIdLength,
             unsigned char* pAPEncryptingKeyId,
             unsigned char* pAPValue );

/* TR-31 CVV Combine   */
extern void SECURITYAPI
      CSNBCKC(long          * pReturnCode,
              long          * pReasonCode,
              long          * pExitDataLength,
              unsigned char * pExitData,
              long          * pRuleArrayCount,
              unsigned char * pRuleArray,
              long          * pKeyAIdentifierLength,
              unsigned char * pKeyAIdentifier,
              long          * pKeyBIdentifierLength,
              unsigned char * pKeyBIdentifier,
              long          * pOutputKeyIdentifierLength,
              unsigned char * pOutputKeyIdentifier);

/* Clear Key Import */
extern void SECURITYAPI
      CSNBCKI(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * clear_key,
              unsigned char * target_key_identifier);

/* Clear Key Import Multiple */
extern void SECURITYAPI
      CSNBCKM(long          * return_code,
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
      CSNBDKX(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * source_key_identifier,
              unsigned char * exporter_key_identifier,
              unsigned char * target_key_token);

/* Data Key Import */
extern void SECURITYAPI
      CSNBDKM(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * source_key_token,
              unsigned char * importer_key_identifier,
              unsigned char * target_key_identifier);

/* DK Migrate PIN */
extern void SECURITYAPI
     CSNBDMP(long          * return_code,
             long          * reason_code,
             long          * exit_data_length,
             unsigned char * exit_data,
             long          * rule_array_count,
             unsigned char * rule_array,
             long          * PAN_data_length,
             unsigned char * PAN_data,
             long          * card_p_data_length,
             unsigned char * card_p_data,
             long          * card_t_data_length,
             unsigned char * card_t_data,
             long          * ISO1_PIN_block_length,
             unsigned char * ISO1_PIN_block,
             long          * IPIN_encryption_key_identifier_length,
             unsigned char * IPIN_encryption_key_identifier,
             long          * PRW_key_identifier_length,
             unsigned char * PRW_key_identifier,
             long          * OPIN_encryption_key_identifier_length,
             unsigned char * OPIN_encryption_key_identifier,
             long          * OEPB_MAC_key_identifier_length,
             unsigned char * OEPB_MAC_key_identifier,
             long          * PIN_reference_value_length,
             unsigned char * PIN_reference_value,
             long          * PRW_random_number_length,
             unsigned char * PRW_random_number,
             long          * output_encrypted_PIN_block_length,
             unsigned char * output_encrypted_PIN_block,
             long          * PIN_block_MAC_length,
             unsigned char * PIN_block_MAC);

/* DK PIN Change                */
extern void SECURITYAPI
     CSNBDPC(long          * return_code,
             long          * reason_code,
             long          * exit_data_length,
             unsigned char * exit_data,
             long          * rule_array_count,
             unsigned char * rule_array,
             long          * PAN_data_length,
             unsigned char * PAN_data,
             long          * card_p_data_length,
             unsigned char * card_p_data,
             long          * card_t_data_length,
             unsigned char * card_t_data,
             long          * cur_ISO1_PIN_block_length,
             unsigned char * cur_ISO1_PIN_block,
             long          * new_ISO1_PIN_block_length,
             unsigned char * new_ISO1_PIN_block,
             long          * card_script_data_length,
             unsigned char * card_script_data,
             long          * script_offset,
             long          * script_offset_field_length,
             long          * script_initialization_vector_length,
             unsigned char * script_initialization_vector,
             unsigned char * output_PIN_profile,
             long          * PIN_reference_value_length,
             unsigned char * PIN_reference_value,
             long          * PRW_random_number_length,
             unsigned char * PRW_random_number,
             long          * PRW_key_identifier_length,
             unsigned char * PRW_key_identifier,
             long          * current_IPIN_encryption_key_identifier_length,
             unsigned char * current_IPIN_encryption_key_identifier,
             long          * new_IPIN_encryption_key_identifier_length,
             unsigned char * new_IPIN_encryption_key_identifier,
             long          * script_key_identifier_length,
             unsigned char * script_key_identifier,
             long          * script_MAC_key_identifier_length,
             unsigned char * script_MAC_key_identifier,
             long          * new_PRW_key_identifier_length,
             unsigned char * new_PRW_key_identifier,
             long          * OPIN_encryption_key_identifier_length,
             unsigned char * OPIN_encryption_key_identifier,
             long          * OEPB_MAC_key_identifier_length,
             unsigned char * OEPB_MAC_key_identifier,
             long          * script_length,
             unsigned char * script,
             long          * script_MAC_length,
             unsigned char * script_MAC,
             long          * new_PIN_reference_value_length,
             unsigned char * new_PIN_reference_value,
             long          * new_PRW_random_number_length,
             unsigned char * new_PRW_random_number,
             long          * output_encrypted_PIN_block_length,
             unsigned char * output_encrypted_PIN_block,
             long          * PIN_block_MAC_length,
             unsigned char * PIN_block_MAC);

/* DK PRW CMAC Generate */
extern void SECURITYAPI
      CSNBDPCG(long          * return_code,
               long          * reason_code,
               long          * exit_data_length,
               unsigned char * exit_data,
               long          * rule_array_count,
               unsigned char * rule_array,
               long          * current_PAN_data_length,
               unsigned char * current_PAN_data,
               long          * new_PAN_data_length,
               unsigned char * new_PAN_data,
               long          * current_card_data_length,
               unsigned char * current_card_data,
               long          * new_card_data_length,
               unsigned char * new_card_data,
               long          * PIN_reference_value_length,
               unsigned char * PIN_reference_value,
               long          * CMAC_FUS_key_identifier_length,
               unsigned char * CMAC_FUS_key_identifier,
               long          * CMAC_FUS_length,
               unsigned char * CMAC_FUS);

/* DK PAN Modify in Transaction */
extern void SECURITYAPI
     CSNBDPMT(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * current_PAN_data_length,
              unsigned char * current_PAN_data,
              long          * new_PAN_data_length,
              unsigned char * new_PAN_data,
              long          * current_card_p_data_length,
              unsigned char * current_card_p_data,
              long          * current_card_t_data_length,
              unsigned char * current_card_t_data,
              long          * new_card_p_data_length,
              unsigned char * new_card_p_data,
              long          * new_card_t_data_length,
              unsigned char * new_card_t_data,
              long          * CMAC_FUS_length,
              unsigned char * CMAC_FUS,
              long          * ISO_encrypted_PIN_block_length,
              unsigned char * ISO_encrypted_PIN_block,
              long          * current_PIN_reference_value_length,
              unsigned char * current_PIN_reference_value,
              long          * current_PRW_random_number_length,
              unsigned char * current_PRW_random_number,
              long          * CMAC_FUS_key_identifier_length,
              unsigned char * CMAC_FUS_key_identifier,
              long          * IPIN_encryption_key_identifier_length,
              unsigned char * IPIN_encryption_key_identifier,
              long          * PRW_key_identifier_length,
              unsigned char * PRW_key_identifier,
              long          * new_PRW_key_identifier_length,
              unsigned char * new_PRW_key_identifier,
              long          * new_PIN_reference_value_length,
              unsigned char * new_PIN_reference_value,
              long          * new_PRW_random_number_length,
              unsigned char * new_PRW_random_number);

/* DK PRW Card Number Update */
extern void SECURITYAPI
     CSNBDPNU(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * card_p_data_length,
              unsigned char * card_p_data,
              long          * card_t_data_length,
              unsigned char * card_t_data,
              long          * encrypted_PIN_block_length,
              unsigned char * encrypted_PIN_block,
              long          * PIN_block_MAC_length,
              unsigned char * PIN_block_MAC,
              long          * PRW_key_identifier_length,
              unsigned char * PRW_key_identifier,
              long          * IPIN_encryption_key_identifier_length,
              unsigned char * IPIN_encryption_key_identifier,
              long          * IEPB_MAC_key_identifier_length,
              unsigned char * IEPB_MAC_key_identifier,
              long          * OPIN_encryption_key_identifier_length,
              unsigned char * OPIN_encryption_key_identifier,
              long          * OEPB_MAC_key_identifier_length,
              unsigned char * OEPB_MAC_key_identifier,
              long          * PIN_reference_value_length,
              unsigned char * PIN_reference_value,
              long          * PRW_random_number_length,
              unsigned char * PRW_random_number,
              long          * new_encrypted_PIN_block_length,
              unsigned char * new_encrypted_PIN_block,
              long          * new_PIN_block_MAC_length,
              unsigned char * new_PIN_block_MAC);

/* DK PAN Translate */
extern void SECURITYAPI
        CSNBDPT(long          * return_code,
                long          * reason_code,
                long          * exit_data_length,
                unsigned char * exit_data,
                long          * rule_array_count,
                unsigned char * rule_array,
                long          * card_p_data_length,
                unsigned char * card_p_data,
                long          * card_t_data_length,
                unsigned char * card_t_data,
                long          * new_PAN_data_length,
                unsigned char * new_PAN_data,
                long          * new_card_p_data_length,
                unsigned char * new_card_p_data,
                long          * PIN_reference_value_length,
                unsigned char * PIN_reference_value,
                long          * PRW_random_number_length,
                unsigned char * PRW_random_number,
                long          * current_encrypted_PIN_block_length,
                unsigned char * current_encrypted_PIN_block,
                long          * current_PIN_block_MAC_length,
                unsigned char * current_PIN_block_MAC,
                long          * PRW_MAC_key_identifier_length,
                unsigned char * PRW_MAC_key_identifier,
                long          * IPIN_encryption_key_identifier_length,
                unsigned char * IPIN_encryption_key_identifier,
                long          * IEPB_MAC_key_identifier_length,
                unsigned char * IEPB_MAC_key_identifier,
                long          * OPIN_encryption_key_identifier_length,
                unsigned char * OPIN_encryption_key_identifier,
                long          * OEPB_MAC_key_identifier_length,
                unsigned char * OEPB_MAC_key_identifier,
                long          * new_encrypted_PIN_block_length,
                unsigned char * new_encrypted_PIN_block,
                long          * new_PIN_block_MAC_length,
                unsigned char * new_PIN_block_MAC);

/* DK PIN Verify */
extern void SECURITYAPI
      CSNBDPV (long          * return_code,
               long          * reason_code,
               long          * exit_data_length,
               unsigned char * exit_data,
               long          * rule_array_count,
               unsigned char * rule_array,
               long          * PAN_data_length,
               unsigned char * PAN_data,
               long          * card_data_length,
               unsigned char * card_data,
               long          * PIN_reference_value_length,
               unsigned char * PIN_reference_value,
               long          * PRW_random_number_length,
               unsigned char * PRW_random_number,
               long          * ISO_encrypted_PIN_block_length,
               unsigned char * ISO_encrypted_PIN_block,
               long          * PRW_key_identifier_length,
               unsigned char * PRW_key_identifier,
               long          * IPIN_encryption_key_identifier_length,
               unsigned char * IPIN_encryption_key_identifier);

/* DK Regenerate PRW*/
extern void SECURITYAPI
      CSNBDRP (long          * return_code,
               long          * reason_code,
               long          * exit_data_length,
               unsigned char * exit_data,
               long          * rule_array_count,
               unsigned char * rule_array,
               long          * card_p_data_length,
               unsigned char * card_p_data,
               long          * card_t_data_length,
               unsigned char * card_t_data,
               long          * encrypted_PIN_block_length,
               unsigned char * encrypted_PIN_block,
               long          * PIN_block_MAC_length,
               unsigned char * PIN_block_MAC,
               long          * PRW_key_identifier_length,
               unsigned char * PRW_key_identifier,
               long          * IPIN_encryption_key_identifier_length,
               unsigned char * IPIN_encryption_key_identifier,
               long          * IEPB_MAC_key_identifier_length,
               unsigned char * IEPB_MAC_key_identifier,
               long          * OPIN_encryption_key_identifier_length,
               unsigned char * OPIN_encryption_key_identifier,
               long          * OEPB_MAC_key_identifier_length,
               unsigned char * OEPB_MAC_key_identifier,
               long          * PIN_reference_value_length,
               unsigned char * PIN_reference_value,
               long          * PRW_random_number_length,
               unsigned char * PRW_random_number,
               long          * new_encrypted_PIN_block_length,
               unsigned char * new_encrypted_PIN_block,
               long          * new_PIN_block_MAC_length,
               unsigned char * new_PIN_block_MAC);

/* DK Random PIN Generate*/
extern void SECURITYAPI
     CSNBDRPG(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * PAN_data_length,
              unsigned char * PAN_data,
              long          * card_p_data_length,
              unsigned char * card_p_data,
              long          * card_t_data_length,
              unsigned char * card_t_data,
              long          * PIN_length,
              long          * PRW_key_identifier_length,
              unsigned char * PRW_key_identifier,
              long          * PIN_print_key_identifier_length,
              unsigned char * PIN_print_key_identifier,
              long          * OPIN_encryption_key_identifier_length,
              unsigned char * OPIN_encryption_key_identifier,
              long          * OEPB_MAC_key_identifier_length,
              unsigned char * OEPB_MAC_key_identifier,
              long          * PIN_reference_value_length,
              unsigned char * PIN_reference_value,
              long          * PRW_random_number_length,
              unsigned char * PRW_random_number,
              long          * PIN_print_block_length,
              unsigned char * PIN_print_block,
              long          * encrypted_PIN_block_length,
              unsigned char * encrypted_PIN_block,
              long          * PIN_block_MAC_length,
              unsigned char * PIN_block_MAC);

/* DK Deterministic PIN Generate*/
extern void SECURITYAPI
     CSNBDDPG(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * account_info_ER_length,
              unsigned char * account_info_ER,
              long          * PAN_data_length,
              unsigned char * PAN_data,
              long          * card_p_data_length,
              unsigned char * card_p_data,
              long          * card_t_data_length,
              unsigned char * card_t_data,
              long          * PIN_length,
              long          * PIN_generation_key_identifier_length,
              unsigned char * PIN_generation_key_identifier,
              long          * PRW_key_identifier_length,
              unsigned char * PRW_key_identifier,
              long          * PIN_print_key_identifier_length,
              unsigned char * PIN_print_key_identifier,
              long          * OPIN_encryption_key_identifier_length,
              unsigned char * OPIN_encryption_key_identifier,
              long          * OEPB_MAC_key_identifier_length,
              unsigned char * OEPB_MAC_key_identifier,
              long          * PIN_reference_value_length,
              unsigned char * PIN_reference_value,
              long          * PRW_random_number_length,
              unsigned char * PRW_random_number,
              long          * PIN_print_block_length,
              unsigned char * PIN_print_block,
              long          * encrypted_PIN_block_length,
              unsigned char * encrypted_PIN_block,
              long          * PIN_block_MAC_length,
              unsigned char * PIN_block_MAC);


/* DES Master Key Process */
extern void SECURITYAPI
      CSNBMKP(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_part);

/* Key Export */
extern void SECURITYAPI
      CSNBKEX(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_type,
              unsigned char * source_key_identifier,
              unsigned char * exporter_key_identifier,
              unsigned char * target_key_token);

/* Key Generate */
extern void SECURITYAPI
      CSNBKGN(long          * return_code,
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

/* Key Generate2 */
extern void SECURITYAPI
     CSNBKGN2(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * clear_key_bit_length,
              unsigned char * key_type_1,
              unsigned char * key_type_2,
              long          * key_name_1_length,
              unsigned char * key_name_1,
              long          * key_name_2_length,
              unsigned char * key_name_2,
              long          * user_associated_data_1_length,
              unsigned char * user_associated_data_1,
              long          * user_associated_data_2_length,
              unsigned char * user_associated_data_2,
              long          * KEK_key_identifier_1_length,
              unsigned char * KEK_key_identifier_1,
              long          * KEK_key_identifier_2_length,
              unsigned char * KEK_key_identifier_2,
              long          * generated_key_identifier_1_length,
              unsigned char * generated_key_identifier_1,
              long          * generated_key_identifier_2_length,
              unsigned char * generated_key_identifier_2);

/* Key Import */
extern void SECURITYAPI
      CSNBKIM(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_type,
              unsigned char * source_key_token,
              unsigned char * importer_key_identifier,
              unsigned char * target_key_identifier);

/* Key Part Import */
extern void SECURITYAPI
      CSNBKPI(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_part,
              unsigned char * key_identifier);

/* Key Part Import2 */
extern void SECURITYAPI
      CSNBKPI2(long          * return_code,
               long          * reason_code,
               long          * exit_data_length,
               unsigned char * exit_data,
               long          * rule_array_count,
               unsigned char * rule_array,
               long          * clear_key_part_length,
               unsigned char * clear_key_part,
               long          * key_identifier_length,
               unsigned char * key_identifier);


/* Key Storage Initialization */
extern void SECURITYAPI
      CSNBKSI(long          * return_code,
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
      CSNBKRC(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_label);

/* Key Record Delete */
extern void SECURITYAPI
      CSNBKRD(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier);

/* Key Record List */
extern void SECURITYAPI
      CSNBKRL(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_label,
              long          * data_set_name_length,
              unsigned char * data_set_name,
              unsigned char * security_server_name);

/* Key Record Read */
extern void SECURITYAPI
      CSNBKRR(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_label,
              unsigned char * key_token);

/* Key Record Write */
extern void SECURITYAPI
      CSNBKRW(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_token,
              unsigned char * key_label);

/* PKA Key Record Create */
extern void SECURITYAPI
      CSNDKRC(long          * return_code,
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
      CSNDKRD(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier);

/* PKA Key Record List */
extern void SECURITYAPI
      CSNDKRL(long          * return_code,
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
      CSNDKRR(long          * return_code,
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
      CSNDKRW(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label,
              long          * key_token_length,
              unsigned char * key_token);

/* AES Key Record Create */
extern void SECURITYAPI
     CSNBAKRC(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label,
              long          * key_token_length,
              unsigned char * key_token);

/* AES Key Record Delete */
extern void SECURITYAPI
     CSNBAKRD(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier);

/* AES Key Record List */
extern void SECURITYAPI
     CSNBAKRL(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label,
              long          * data_set_name_length,
              unsigned char * data_set_name,
              unsigned char * security_server_name);

/* AES Key Record Read */
extern void SECURITYAPI
     CSNBAKRR(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label,
              long          * key_token_length,
              unsigned char * key_token);

/* AES Key Record Write */
extern void SECURITYAPI
     CSNBAKRW(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label,
              long          * key_token_length,
              unsigned char * key_token);

/* Key Test */
extern void SECURITYAPI
      CSNBKYT(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier,
              unsigned char * value_1,
              unsigned char * value_2);

/* Key Test Extended */
extern void SECURITYAPI
     CSNBKYTX(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier,
              unsigned char * random_number,
              unsigned char * verification_pattern,
              unsigned char * kek_key_identifier);

/* Key Test2 */
extern void SECURITYAPI
     CSNBKYT2(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_identifier_length,
              unsigned char * key_identifier,
              long          * KEK_key_identifier_length,
              unsigned char * KEK_key_identifier,
              long          * reserved_length,
              unsigned char * reserved,
              long          * verification_pattern_length,
              unsigned char * verification_pattern);

/* DES Key Token Change */
extern void SECURITYAPI
      CSNBKTC(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_identifier);

/*  Key Token Change 2 */
extern void SECURITYAPI
      CSNBKTC2(long          * return_code,
               long          * reason_code,
               long          * exit_data_length,
               unsigned char * exit_data,
               long          * rule_array_count,
               unsigned char * rule_array,
               long          * key_identifier_length,
               unsigned char * key_identifier);

/* Key Translate */
extern void SECURITYAPI
      CSNBKTR(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * input_key_token,
              unsigned char * input_KEK_key_identifier,
              unsigned char * output_KEK_key_identifier,
              unsigned char * output_key_token);

/* Key Translate2 */
extern void SECURITYAPI
     CSNBKTR2(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * input_key_token_length,
              unsigned char * input_key_token,
              long          * input_KEK_key_identifier_length,
              unsigned char * input_KEK_key_identifier,
              long          * output_KEK_key_identifier_length,
              unsigned char * output_KEK_key_identifier,
              long          * output_key_token_length,
              unsigned char * output_key_token);

/* Random Number Generate */
extern void SECURITYAPI
      CSNBRNG(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * form,
              unsigned char * random_number);

/* Random Number Generate Long */
extern void SECURITYAPI
     CSNBRNGL(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * reserved_length,
              unsigned char * reserved,
              long          * random_number_length,
              unsigned char * random_number);

/* Decipher */
extern void SECURITYAPI
      CSNBDEC(long          * return_code,
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
      CSNBENC(long          * return_code,
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
      CSNBMGN(long          * return_code,
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

/* MAC Generate 2 */
extern void SECURITYAPI
      CSNBMGN2(long          * return_code,
               long          * reason_code,
               long          * exit_data_length,
               unsigned char * exit_data,
               long          * rule_array_count,
               unsigned char * rule_array,
               long          * key_identifier_length,
               unsigned char * key_identifier,
               long          * message_text_length,
               unsigned char * message_text,
               long          * chaining_vector_length,
               unsigned char * chaining_vector,
               long          * MAC_length,
               unsigned char * MAC_text);

/* MAC Verify */
extern void SECURITYAPI
      CSNBMVR(long          * return_code,
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

/* MAC Verify 2 */
extern void SECURITYAPI
      CSNBMVR2(long          * return_code,
               long          * reason_code,
               long          * exit_data_length,
               unsigned char * exit_data,
               long          * rule_array_count,
               unsigned char * rule_array,
               long          * key_identifier_length,
               unsigned char * key_identifier,
               long          * message_text_length,
               unsigned char * message_text,
               long          * chaining_vector_length,
               unsigned char * chaining_vector,
               long          * MAC_length,
               unsigned char * MAC_text);

/* HMAC Generate */
extern void SECURITYAPI
      CSNBHMG(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_identifier_length,
              unsigned char * key_identifier,
              long          * message_text_length,
              unsigned char * message_text,
              long          * chaining_vector_length,
              unsigned char * chaining_vector,
              long          * MAC_length,
              unsigned char * MAC_text);

/* HMAC Verify */
extern void SECURITYAPI
      CSNBHMV(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_identifier_length,
              unsigned char * key_identifier,
              long          * message_text_length,
              unsigned char * message_text,
              long          * chaining_vector_length,
              unsigned char * chaining_vector,
              long          * MAC_length,
              unsigned char * MAC_text);

/* Key Token Build */
extern void SECURITYAPI
      CSNBKTB(long          * return_code,
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
              unsigned char * master_key_verification_number);

/* Key Token Build2 */
extern void SECURITYAPI
     CSNBKTB2(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * clear_key_bit_length,
              unsigned char * clear_key_value,
              long          * key_name_length,
              unsigned char * key_name,
              long          * user_associated_data_length,
              unsigned char * user_associated_data,
              long          * token_data_length,
              unsigned char * token_data,
              long          * reserved_length,
              unsigned char * reserved,
              long          * target_key_token_length,
              unsigned char * target_key_token);

/* PKA Key Generate */
extern void SECURITYAPI
      CSNDPKG(long          * return_code,
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
      CSNDPKB(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_values_structure_length,
              unsigned char * key_values_structure,
              long          * key_name_ln,
              unsigned char * key_name,
              long          * customer_data_length,
              unsigned char * customer_data,
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
      CSNBOWH(long          * return_code,
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
      CSNDPKI(long          * return_code,
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
      CSNDDSG(long          * return_code,
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
      CSNDDSV(long          * return_code,
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
      CSNDKTC(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_id_length,
              unsigned char * key_id);

/* PKA Public Key Extract */
extern void SECURITYAPI
      CSNDPKX(long          * return_code,
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
      CSNDSYI(long          * return_code,
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

/* PKA Symmetric Key Import 2 */
extern void SECURITYAPI
     CSNDSYI2(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * RSA_enciphered_key_length,
              unsigned char * RSA_enciphered_key,
              long          * RSA_private_key_identifier_length,
              unsigned char * RSA_private_key_identifier,
              long          * user_mod_data_length,
              unsigned char * user_mod_data,
              long          * target_key_identifier_length,
              unsigned char * target_key_identifier);

/* PKA Symmetric Key Export */
extern void SECURITYAPI
      CSNDSYX(long          * return_code,
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
extern void SECURITYAPI
      CSUACFQ(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * verb_data_length,
              unsigned char * verb_data);

/* Crypto Facility Control */
extern void SECURITYAPI
      CSUACFC(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * verb_data_length,
              unsigned char * verb_data);

/* SET Block Compose */
extern void SECURITYAPI
      CSNDSBC(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * block_contents_identifier,
              long          * x_data_string_length,
              unsigned char * x_data_string,
              long          * data_to_encrypt_length,
              unsigned char * data_to_encrypt,
              long          * data_to_hash_length,
              unsigned char * data_to_hash,
              unsigned char * initialization_vector,
              long          * rsa_public_key_identifier_length,
              unsigned char * rsa_public_key_identifier,
              long          * des_key_block_length,
              unsigned char * des_key_block,
              long          * rsa_oaep_block_length,
              unsigned char * rsa_oaep_block,
              unsigned char * chaining_vector,
              unsigned char * des_encrypted_data_block);

/* SET Block Decompose */
extern void SECURITYAPI
      CSNDSBD(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * rsa_oaep_block_length,
              unsigned char * rsa_oaep_block,
              long          * des_encrypted_data_block_length,
              unsigned char * des_encrypted_data_block,
              unsigned char * initialization_vector,
              long          * rsa_private_key_identifier_length,
              unsigned char * rsa_private_key_identifier,
              long          * des_key_block_length,
              unsigned char * des_key_block,
              unsigned char * block_contents_identifier,
              long          * x_data_string_length,
              unsigned char * x_data_string,
              unsigned char * chaining_vector,
              unsigned char * data_block,
              long          * hash_block_length,
              unsigned char * hash_block);

// Symmetric Key Export with Data
extern void SECURITYAPI
      CSNDSXD(long          * ReturnCode,
              long          * ReasonCode,
              long          * ExitDataLength,
              unsigned char * ExitData,
              long          * RuleArrayCount,
              unsigned char * RuleArray,
              long          * SourceKeyLength,
              unsigned char * SourceKey,
              long          * Data_length,
              long          * Data_offset,
              unsigned char * Data,
              long          * RSA_PublicKeyLength,
              unsigned char * RSA_PublicKey,
              long          * EncipheredKeyLength,
              unsigned char * EncipheredKey);

/* Access Control Logon */
extern void SECURITYAPI
      CSUALCT(long          * return_code,
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

/* Log Query */
extern void SECURITYAPI
      CSUALGQ(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * log_number,
              long          * reserved0,
              long          * log_data_length,
              unsigned char * log_data,
              long          * reserved1_length,
              unsigned char * reserved1,
              long          * reserved2_length,
              unsigned char * reserved2);

/* Access Control Maintenance */
extern void SECURITYAPI
      CSUAACM(long          * return_code,
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
      CSUAACI(long          * return_code,
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
      CSNDPKH(long          * return_code,
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
      CSNDPKR(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * public_key_name,
              long          * public_key_certificate_length,
              unsigned char * public_key_certificate);

/* PKA Key Translate */
extern void SECURITYAPI
      CSNDPKT(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * source_key_identifier_length,
              unsigned char * source_key_identifier,
              long          * source_transport_key_identifier_length,
              unsigned char * source_transport_key_identifier,
              long          * target_transport_key_identifier_length,
              unsigned char * target_transport_key_identifier,
              long          * target_key_token_length,
              unsigned char * target_key_token);

/* Master Key Distribution */
extern void SECURITYAPI
      CSUAMKD(long          * return_code,
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
      CSNDRKD(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_label);

/* Retained Key List */
extern void SECURITYAPI
      CSNDRKL(long          * return_code,
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
      CSNDSYG(long          * return_code,
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
      CSNBPTR(long          * return_code,
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

/* Encrypted PIN Translate Extended */
extern void SECURITYAPI
     CSNBPTRE(long          * pReturnCode,
              long          * pReasonCode,
              long          * pExitDataLength,
              unsigned char * pExitData,
              long          * pRuleArrayCount,
              unsigned char * pRuleArray,
              long          * pInPINEncKeyIDLength,
              unsigned char * pInPINEncKeyID,
              long          * pOutPINEncKeyIDLength,
              unsigned char * pOutPINEncKeyID,
              long          * pPANEncKeyIDLength,
              unsigned char * pPANEncKeyID,
              long          * pInPINProfileLength,
              unsigned char * pInPINProfile,
              long          * pPANDataLength,
              unsigned char * pPANData,
              long          * pInPINBlkLength,
              unsigned char * pInPINBlk,
              long          * pOutPINProfileLength,
              unsigned char * pOutPINProfile,
              long          * pSequenceNumber,
              long          * pOutPINBlkLength,
              unsigned char * pOutPINBlk,
              long          * pReserved1Length,
              unsigned char * pReserved1,
              long          * pReserved2Length,
              unsigned char * pReserved2);

/* Clear PIN Encrypt */
extern void SECURITYAPI
      CSNBCPE(long          * return_code,
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
      CSNBCPA(long          * return_code,
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
      CSNBPGN(long          * return_code,
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
      CSNBPVR(long          * return_code,
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
      CSNBDKG(long          * return_code,
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

/* Diversified Key Generate2 */
extern void SECURITYAPI
      CSNBDKG2(long          * return_code,
               long          * reason_code,
               long          * exit_data_length,
               unsigned char * exit_data,
               long          * rule_array_count,
               unsigned char * rule_array,
               long          * generating_key_id_length,
               unsigned char * generating_key_id,
               long          * derivation_data_length,
               unsigned char * derivation_data,
               long          * reserved1_length,
               unsigned char * reserved1,
               long          * reserved2_length,
               unsigned char * reserved2,
               long          * generated_key_id1_length,
               unsigned char * generated_key_id1,
               long          * generated_key_id2_length,
               unsigned char * generated_key_id2);

/* Encrypted PIN Generate */
extern void SECURITYAPI
      CSNBEPG(long          * return_code,
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

/* FPE Decipher */
extern void SECURITYAPI
  CSNBFPED(long          * pReturnCode,
           long          * pReasonCode,
           long          * pExitDataLength,
           unsigned char * pExitData,
           long          * pRuleArrayCount,
           unsigned char * pRuleArray,
           long          * pEncPanLength,
           unsigned char * pEncPan,
           long          * pEncChNameLength,
           unsigned char * pEncChName,
           long          * pEncTrack1DdataLength,
           unsigned char * pEncTrack1Ddata,
           long          * pEncTrack2DdataLength,
           unsigned char * pEncTrack2Ddata,
           long          * pKeyIdentifierLength,
           unsigned char * pKeyIdentifier,
           long          * pDerivationDataLength,
           unsigned char * pDerivationData,
           long          * pClearPanLength,
           unsigned char * pClearPan,
           long          * pClearChNameLength,
           unsigned char * pClearChName,
           long          * pClearTrack1DdataLength,
           unsigned char * pClearTrack1Ddata,
           long          * pClearTrack2DdataLength,
           unsigned char * pClearTrack2Ddata,
           long          * pDukptPinKeyIdentifierLength,
           unsigned char * pDukptPinKeyIdentifier,
           long          * pReserved1Length,
           unsigned char * pReserved1,
           long          * pReserved2Length,
           unsigned char * pReserved2);

/* FPE Encipher */
extern void SECURITYAPI
  CSNBFPEE(long         * pReturnCode,
           long         * pReasonCode,
           long         * pExitDataLength,
           unsigned char* pExitData,
           long         * pRuleArrayCount,
           unsigned char* pRuleArray,
           long         * pClearPanLength,
           unsigned char* pClearPan,
           long         * pClearChNameLength,
           unsigned char* pClearChName,
           long         * pClearTrack1DdataLength,
           unsigned char* pClearTrack1Ddata,
           long         * pClearTrack2DdataLength,
           unsigned char* pClearTrack2Ddata,
           long         * pKeyIdentifierLength,
           unsigned char* pKeyIdentifier,
           long         * pDerivationDataLength,
           unsigned char* pDerivationData,
           long         * pEncPanLength,
           unsigned char* pEncPan,
           long         * pEncChNameLength,
           unsigned char* pEncChName,
           long         * pEncTrack1DdataLength,
           unsigned char* pEncTrack1Ddata,
           long         * pEncTrack2DdataLength,
           unsigned char* pEncTrack2Ddata,
           long         * pDukptPinKeyIdentifierLength,
           unsigned char* pDukptPinKeyIdentifier,
           long         * pReserved1Length,
           unsigned char* pReserved1,
           long         * pReserved2Length,
           unsigned char* pReserved2);

/* FPE_Translate */
extern void SECURITYAPI
  CSNBFPET(long         * pReturnCode,
           long         * pReasonCode,
           long         * pExitDataLength,
           unsigned char* pExitData,
           long         * pRuleArrayCount,
           unsigned char* pRuleArray,
           long         * pInputPanLength,
           unsigned char* pInputPan,
           long         * pInputChNameLength,
           unsigned char* pInputChName,
           long         * pInputTrack1DdataLength,
           unsigned char* pInputTrack1Ddata,
           long         * pInputTrack2DdataLength,
           unsigned char* pInputTrack2Ddata,
           long         * pInputKeyIdentifierLength,
           unsigned char* pInputKeyIdentifier,
           long         * pOutputKeyIdentifierLength,
           unsigned char* pOutputKeyIdentifier,
           long         * pDerivationDataLength,
           unsigned char* pDerivationData,
           long         * pOutputPanLength,
           unsigned char* pOutputPan,
           long         * pOutputChNameLength,
           unsigned char* pOutputChName,
          long         * pOutputTrack1DdataLength,
           unsigned char* pOutputTrack1Ddata,
           long         * pOutputTrack2DdataLength,
           unsigned char* pOutputTrack2Ddata,
           long         * pDukptPinKeyIdentifierLength,
           unsigned char* pDukptPinKeyIdentifier,
           long         * pReserved1Length,
           unsigned char* pReserved1,
           long         * pReserved2Length,
           unsigned char* pReserved2);

/* Cryptographic Variable Encipher */
extern void SECURITYAPI
      CSNBCVE(long          * return_code,
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
      CSNBCSG(long          * return_code,
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
      CSNBCSV(long          * return_code,
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
      CSNBCVG(long          * return_code,
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
      CSNBKTP(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_token,
              unsigned char * key_type,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * key_value,
              void          * master_key_verification_pattern_v03,
              long          * reserved_field_2,
              unsigned char * reserved_field_3,
              unsigned char * control_vector,
              unsigned char * reserved_field_4,
              long          * reserved_field_5,
              unsigned char * reserved_field_6,
              unsigned char * master_key_verification_pattern_v00);

/* Key Token Parse2 */
extern void SECURITYAPI
    CSNBKTP2(long           *pReturnCode,
             long           *pReasonCode,
             long           *pExitDataLength,
             unsigned char  *pExitData,
             long           *pKeyTokenLength,
             unsigned char  *pKeyToken,
             unsigned char  *pKeyType,
             long           *pRuleArrayCount,
             unsigned char  *pRuleArray,
             long           *pKeyMaterialState,
             long           *pPayloadBitLength,
             unsigned char  *pPayload,
             long           *pKeyVerificationType,
             long           *pKeyVerificationPatternLength,
             unsigned char  *pKeyVerificationPattern,
             long           *pKeyWrappingMethod,
             long           *pKeyHashMethod,
             long           *pKeyNameLength,
             unsigned char  *pKeyName,
             long           *pTLVDataLength,
             unsigned char  *pTLVData,
             long           *pUserAssocDataLength,
             unsigned char  *pUserAssocData,
             long           *pReservedLength,
             unsigned char  *pReserved );

/* PKA Encrypt */
extern void SECURITYAPI
      CSNDPKE(long          * return_code,
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
extern void SECURITYAPI
      CSNDPKD(long          * return_code,
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
extern void SECURITYAPI
      CSNBPEX(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * key_identifier);

/* Prohibit Export Extended */
extern void SECURITYAPI
     CSNBPEXX(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              unsigned char * Source_key_token,
              unsigned char * Kek_key_identifier);

/* Prohibit Export 2 */
extern void SECURITYAPI
     CSNBPEX2(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_identifier_length,
              unsigned char * key_identifier,
              long          * KEK_key_identifier_length,
              unsigned char * KEK_key_identifier);

/* Pin From Offset */
extern void SECURITYAPI
      CSNBPFO(long       * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * PIN_enc_key_id_length,
              unsigned char * PIN_enc_key_id,
              long          * PIN_gen_key_id_length,
              unsigned char * PIN_gen_key_id,
              unsigned char * PIN_profile,
              unsigned char * PAN_data,
              unsigned char * offset,
              long          * reserved_1,
              unsigned char * data_array,
              long          * encrypted_PIN_blk_length,
              unsigned char * encrypted_PIN_blk);

/* Restrict Key Attribute */
extern void SECURITYAPI
      CSNBRKA(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_identifier_length,
              unsigned char * key_identifier,
              long          * KEK_key_identifier_length,
              unsigned char * KEK_key_identifier,
              long          * opt_parameter1_length,
              unsigned char * opt_parameter1,
              long          * opt_parameter2_length,
              unsigned char * opt_parameter2);


/* Random Number/Known Answer Test */
extern void SECURITYAPI
      CSUARNT(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array);

/* Control Vector Translate */
extern void SECURITYAPI
      CSNBCVT(long          * return_code,
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
      CSNBMDG(long          * return_code,
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
      CSUACRA(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * resource_name_length,
              unsigned char * resource_name);

/* Cryptographic Resource Deallocate */
extern void SECURITYAPI
      CSUACRD(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * resource_name_length,
              unsigned char * resource_name);

/* Transaction Validation */
extern void SECURITYAPI
      CSNBTRV(long          * return_code,
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
extern void SECURITYAPI
      CSNBSKY(long          * return_code,
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
extern void SECURITYAPI
      CSNBSPN(long          * return_code,
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
extern void SECURITYAPI
      CSNBPCU(long          * return_code,
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

/* DUKPT Key Generate verb                                                   */
void SECURITYAPI
     CSNBUKD(long          * ReturnCode,
             long          * ReasonCode,
             long          * ExitDataLength,
             unsigned char * ExitData,
             long          * pRuleArrayCount,
             unsigned char * RuleArray,
             long          * pBaseDerivationKeyIdentifierLength,
             unsigned char * pBaseDerivationKeyIdentifier,
             long          * pDerivationDataLength,
             unsigned char * pDerivationData,
             long          * pGeneratedKeyIdentifier1Length,
             unsigned char * GeneratedKeyIdentifier1,
             long          * pGeneratedKeyIdentifier2Length,
             unsigned char * GeneratedKeyIdentifier2,
             long          * pGeneratedKeyIdentifier3Length,
             unsigned char * GeneratedKeyIdentifier3,
             long          * pTransportKeyIdentifierLength,
             unsigned char * TransportKeyIdentifier,
             long          * pReserved2Length,
             unsigned char * Reserved2,
             long          * pReserved3Length,
             unsigned char * Reserved3,
             long          * pReserved4Length,
             unsigned char * Reserved4,
             long          * pReserved5Length,
             unsigned char * Reserved5,
             long          * pReserved6Length,
             unsigned char * Reserved6);

/*Translate Characters */
extern void SECURITYAPI
      CSNBXEA(long          * ReturnCode,
              long          * ReasonCode,
              long          * ExitDataLength,
              unsigned char * ExitData,
              long          * RuleArrayCount,
              unsigned char * RuleArray,
              long          * TextLength,
              unsigned char * SourceText,
              unsigned char * TargetText,
              long          * CodeTableLength,
              unsigned char * CodeTable);

/*Process Request Block*/
extern void SECURITYAPI
      CSUAPRB(long          * pReturnCode,
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

/* Trusted Block Create */
extern void SECURITYAPI
      CSNDTBC(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * input_block_length,
              unsigned char * input_block_identifier,
              unsigned char * transport_key_identifier,
              long          * trusted_block_length,
              unsigned char * trusted_block_identifier);

/* Remote Key Export */
extern void SECURITYAPI
      CSNDRKX(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * trusted_block_length,
              unsigned char * trusted_block_identifier,
              long          * certificate_length,
              unsigned char * certificate,
              long          * certificate_parms_length,
              unsigned char * certificate_parms,
              long          * transport_key_length,
              unsigned char * transport_key_identifier,
              long          * rule_id_length,
              unsigned char * rule_id,
              long          * export_key_kek_length,
              unsigned char * export_key_kek_identifier,
              long          * export_key_length,
              unsigned char * export_key_identifier,
              long          * asym_encrypted_key_length,
              unsigned char * asym_encrypted_key,
              long          * sym_encrypted_key_length,
              unsigned char * sym_encrypted_key,
              long          * extra_data_length,
              unsigned char * extra_data,
              long          * key_check_parameters_length,
              unsigned char * key_check_parameters,
              long          * key_check_length,
              unsigned char * key_check_value);

/* Key Encryption Translate */
extern void SECURITYAPI
      CSNBKET(long          * return_code,
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

/* Symmetric Algorithm Encipher */
extern void SECURITYAPI
      CSNBSAE(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_length,
              unsigned char * key_identifier,
              long          * key_parms_length,
              unsigned char * key_parms,
              long          * block_size,
              long          * initialization_vector_length,
              unsigned char * initialization_vector,
              long          * chain_data_length,
              unsigned char * chain_data,
              long          * clear_text_length,
              unsigned char * clear_text,
              long          * cipher_text_length,
              unsigned char * cipher_text,
              long          * optional_data_length,
              unsigned char * optional_data);

/* Symmetric Algorithm Decipher */
extern void SECURITYAPI
      CSNBSAD(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_length,
              unsigned char * key_identifier,
              long          * key_parms_length,
              unsigned char * key_parms,
              long          * block_size,
              long          * initialization_vector_length,
              unsigned char * initialization_vector,
              long          * chain_data_length,
              unsigned char * chain_data,
              long          * cipher_text_length,
              unsigned char * cipher_text,
              long          * clear_text_length,
              unsigned char * clear_text,
              long          * optional_data_length,
              unsigned char * optional_data);

/* Crypto Facility Version (SAPI_ONLY) */
extern void SECURITYAPI
      CSUACFV(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * version_data_length,
              unsigned char * version_data);

/* TR-31 Optional Data Build */
extern void SECURITYAPI
      CSNBT31O (long          * pReturnCode,
                long          * pReasonCode,
                long          * pExitDataLength,
                unsigned char * pExitData,
                long          * pRuleArrayCount,
                unsigned char * pRuleArray,
                long          * pOptBlocksBfrLength,
                long          * pOptBlocksLength,
                unsigned char * pOptBlocks,
                long          * pNumOptBlocks,
                unsigned char * pOptBlockID,
                long          * pOptBlockDataLength,
                unsigned char * pOptBlockData );

/* TR-31 Key Token Parse */
extern void SECURITYAPI
     CSNBT31P(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * tr31_key_length,
              unsigned char * tr31_key,
	      unsigned char * key_block_version,
	      long          * key_block_length,
	      unsigned char * key_usage,
	      unsigned char * algorithm,
	      unsigned char * mode,
	      unsigned char * key_version_number,
	      unsigned char * exportability,
	      long          * num_opt_blocks     );

/* TR-31 Key Import */
extern void SECURITYAPI
     CSNBT31I( long        *return_code,
	       long        *reason_code,
	       long        *exit_data_length,
	       unsigned char *exit_data,
	       long        *rule_array_count,
	       unsigned char *rule_array,
	       long        *tr31_key_block_length,
	       unsigned char *tr31_key_block,
	       long        *unwrap_kek_identifier_length,
	       unsigned char *unwrap_kek_identifier,
	       long        *wrap_kek_identifier_length,
	       unsigned char *wrap_kek_identifier,
	       long        *output_key_identifier_length,
	       unsigned char *output_key_identifier,
	       long        *num_opt_blks,
	       long        *cv_source,
	       long        *protection_method);

/* TR-31 Key Export */
extern void SECURITYAPI
     CSNBT31X( long        *return_code,
	       long        *reason_code,
	       long        *exit_data_length,
	       unsigned char *exit_data,
	       long        *rule_array_count,
	       unsigned char *rule_array,
	       unsigned char *key_version_number,
	       long        *key_field_length,
	       long        *source_key_identifier_length,
	       unsigned char *source_key_identifier,
	       long        *unwrap_kek_identifier_length,
	       unsigned char *unwrap_kek_identifier,
	       long        *wrap_kek_identifier_length,
	       unsigned char *wrap_kek_identifier,
	       long        *opt_blks_length,
	       unsigned char *opt_blks,
	       long        *tr31_key_block_length,
	       unsigned char *tr31_key_block);

/* TR-31 Optional Data Read */
extern void SECURITYAPI
     CSNBT31R(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * tr31_key_length,
              unsigned char * tr31_key,
	      unsigned char * opt_block_id,
	      long          * num_opt_blocks,
	      unsigned char * opt_block_ids,
	      unsigned char * opt_block_lengths,
	      long          * opt_block_data_length,
	      unsigned char * opt_block_data        );

/* Elliptic Curve Diffie-Hellman */
extern void SECURITYAPI
      CSNDEDH(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * private_key_identifier_length,
              unsigned char * private_key_identifier,
              long          * private_KEK_key_identifier_length,
              unsigned char * private_KEK_key_identifier,
              long          * public_key_identifier_length,
              unsigned char * public_key_identifier,
              long          * chaining_vector_length,
              unsigned char * chaining_vector,
              long          * party_identifier_length,
              unsigned char * party_identifier,
              long          * key_bit_length,
              long          * reserved_length,
              unsigned char * reserved,
              long          * reserved2_length,
              unsigned char * reserved2,
              long          * reserved3_length,
              unsigned char * reserved3,
              long          * reserved4_length,
              unsigned char * reserved4,
              long          * reserved5_length,
              unsigned char * reserved5,
              long          * output_KEK_key_identifier_length,
              unsigned char * output_KEK_key_identifier,
              long          * output_key_identifier_length,
              unsigned char * output_key_identifier);

/* Cipher Text Translate 2 */
extern void SECURITYAPI
     CSNBCTT2(long          * pReturnCode,
              long          * pReasonCode,
              long          * pExitDataLength,
              unsigned char * pExitData,
              long          * pRuleArrayCount,
              unsigned char * pRuleArray,
              long          * pKeyIdInLen,
              unsigned char * pKeyIdIn,
              long          * pInitVectorInLen,
              unsigned char * pInitVectorIn,
              long          * pCipherTextInLen,
              unsigned char * pCipherTextIn,
              long          * pChainingVectorLen,
              unsigned char * pChainingVector,
              long          * pKeyIdOutLen,
              unsigned char * pKeyIdOut,
              long          * pInitVectorOutLen,
              unsigned char * pInitVectorOut,
              long          * pCipherTextOutLen,
              unsigned char * pCipherTextOut,
              long          * pReserved1Len,
              unsigned char * pReserved1,
              long          * pReserved2Len,
              unsigned char * pReserved2 );


#ifdef TKE_WKSTN
/* Diffie-Hellman Key Load */
extern void SECURITYAPI
      CSUADHK(long          * ReturnCode,
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
              long          * DHModulusLength,
              unsigned char * PartyID,
              unsigned char * Reserved1,
              unsigned char * Reserved2);

/* Diffie-Hellman Key Query */
extern void SECURITYAPI
      CSUADHQ(long          * ReturnCode,
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
              long          * DHModulusLength,
              unsigned char * PartyID,
              unsigned char * Reserved1,
              unsigned char * Reserved2);

/* Certificate Import Export */
extern void SECURITYAPI
      CSUACIE(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * public_key_certificate_length,
              unsigned char * public_key_certificate);

/* Random Number Extend */
extern void SECURITYAPI
      CSUARNX(long          *  return_code,
              long          *  reason_code,
              long          *  exit_data_length,
              unsigned char *  exit_data,
              long          *  rule_array_count,
              unsigned char *  rule_array,
              long          *  key_length,
              unsigned char *  key,
              long          *  rnum_length,
              unsigned char *  rnum,
              long          *  rnum_hash_length,
              unsigned char *  rnum_hash,
              long          *  sk_hash_length,
              unsigned char *  sk_hash,
              long          *  secdata_length,
              unsigned char *  secdata,
              long          *  optdata_length,
              unsigned char *  optdata);

/* Session Key Establish */
extern void SECURITYAPI
      CSUASKE(long          *  return_code,
              long          *  reason_code,
              long          *  exit_data_length,
              unsigned char *  exit_data,
              long          *  rule_array_count,
              unsigned char *  rule_array,
              long          *  cert_in_length,
              unsigned char *  cert_in,
              long          *  cert_out_length,
              unsigned char *  cert_out,
              long          *  key_block_length,
              unsigned char *  key_block,
              long          *  key_signature_length,
              unsigned char *  key_signature,
              long          *  key_vp_length,
              unsigned char *  key_vp,
              long          *  rnum_length,
              unsigned char *  rnum);

/* Key Transport to Export */
extern void SECURITYAPI
      CSUAKTX(long          * ReturnCode,
              long          * ReasonCode,
              long          * ExitDataLength,
              unsigned char * ExitData,
              long          * rule_array_count,
              unsigned char * rule_array,
              long          * key_data_length,
              unsigned char * key_data,
              long          * secure_data_length,
              unsigned char * secure_data,
              long          * key_data_vp_length,
              unsigned char * key_data_vp,
              long          * session_key_vp_length,
              unsigned char * session_key_vp,
              long          * xport_key_vp_length,
              unsigned char * xport_key_vp,
              long          * xlt_key_data_length,
              unsigned char * xlt_key_data,
              long          * xlt_secure_data_length,
              unsigned char * xlt_secure_data);

/* Master Key Process Extended */
extern void SECURITYAPI
      CSUAMKX(long          * return_code,
              long          * reason_code,
              long          * exit_data_length,
              unsigned char * exit_data,
              long          * rule_array_count,
              unsigned char * rule_array,
              unsigned char * Key_part,
              long          * Seskey_vp_length,
              unsigned char * Seskey_vp,
              long          * Keypart_vp_length,
              unsigned char * Keypart_vp);

/* Key Part Import Extended    */
extern void SECURITYAPI
      CSUAKIX(long          * pReturnCode,
              long          * pReasonCode,
              long          * pExitDataLength,
              unsigned char * pExitData,
              long          * pRuleArrayCount,
              unsigned char * pRuleArray,
              unsigned char * pKeyPart,
              unsigned char * pKeyIdentifier,
              long          * pSeskey_vp_length,
              unsigned char * pSeskey_vp,
              long          * pKeypart_vp_length,
              unsigned char * pKeypart_vp);


#endif // TKE_WKSTN
#endif // __CSULINCL__
