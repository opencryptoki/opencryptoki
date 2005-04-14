
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

/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */


// File:  mech_rsa.c
//
// Mechanisms for RSA
//
// Routines contained within:

#include <pthread.h>
#include <stdio.h>

#include <string.h>            // for memcmp() et al
#include <stdlib.h>

#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"

//
//
CK_RV
rsa_pkcs_oaep_encrypt( SESSION           *sess,
                  CK_BBOOL           length_only,
                  ENCR_DECR_CONTEXT *ctx,
                  CK_BYTE           *in_data,
                  CK_ULONG           in_data_len,
                  CK_BYTE           *out_data,
                  CK_ULONG          *out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (in_data_len > (modulus_bytes - (2 * SHA1_HASH_SIZE) + 1)){
      st_err_log(109, __FILE__, __LINE__);
      return CKR_DATA_LEN_RANGE;
   }

   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   if (*out_data_len < modulus_bytes) {
      *out_data_len = modulus_bytes;
      st_err_log(111, __FILE__, __LINE__);
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = ckm_rsa_oaep_encrypt( in_data, in_data_len, out_data, out_data_len, key_obj );
   if (rc != CKR_OK)
      st_err_log(132, __FILE__, __LINE__);
   return rc;
}


//
//
CK_RV
rsa_pkcs_oaep_decrypt( SESSION           *sess,
                  CK_BBOOL           length_only,
                  ENCR_DECR_CONTEXT *ctx,
                  CK_BYTE           *in_data,
                  CK_ULONG           in_data_len,
                  CK_BYTE           *out_data,
                  CK_ULONG          *out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_ULONG         i, modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE)
      return CKR_FUNCTION_FAILED;
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (in_data_len != modulus_bytes){
      st_err_log(112, __FILE__, __LINE__);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      // this is not exact but it's the upper bound; otherwise we'll need
      // to do the RSA operation just to get the required length
      //
      *out_data_len = modulus_bytes - (2 * SHA1_HASH_SIZE + 1);
      return CKR_OK;
   }

   //rc = ckm_rsa_decrypt( in_data, modulus_bytes, out, key_obj );
   rc = ckm_rsa_oaep_decrypt( in_data, modulus_bytes, out_data, out_data_len, key_obj );
   if (rc != CKR_OK)
      st_err_log(133, __FILE__, __LINE__);

   if (rc == CKR_DATA_LEN_RANGE){
      st_err_log(109, __FILE__, __LINE__);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   return rc;
}


//
//
CK_RV
rsa_pkcs_oaep_sign( SESSION             *sess,
               CK_BBOOL             length_only,
               SIGN_VERIFY_CONTEXT *ctx,
               CK_BYTE             *in_data,
               CK_ULONG             in_data_len,
               CK_BYTE             *out_data,
               CK_ULONG            *out_data_len )
{
   OBJECT          *key_obj   = NULL;
   CK_ATTRIBUTE    *attr      = NULL;
   CK_BYTE          data[256], sig[256];  // max size: 256 bytes == 2048 bits
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   if (!sess || !ctx || !out_data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE)
      return CKR_FUNCTION_FAILED;
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (in_data_len > (modulus_bytes - (2 * SHA1_HASH_SIZE + 1))){
      st_err_log(109, __FILE__, __LINE__);
      return CKR_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   if (*out_data_len < modulus_bytes) {
      *out_data_len = modulus_bytes;
      st_err_log(111, __FILE__, __LINE__);
      return CKR_BUFFER_TOO_SMALL;
   }

   // signing is a private key operation --> decrypt
   //
   rc = ckm_rsa_oaep_decrypt( data, in_data_len, out_data, out_data_len, key_obj );
   if (rc != CKR_OK)
      st_err_log(133, __FILE__, __LINE__);
   return rc;
}


//
//
CK_RV
rsa_pkcs_oaep_verify( SESSION             * sess,
                 SIGN_VERIFY_CONTEXT * ctx,
                 CK_BYTE             * in_data,
                 CK_ULONG              in_data_len,
                 CK_BYTE             * signature,
                 CK_ULONG              sig_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_BYTE          out[256];  // 2048 bits
   CK_ULONG         i, modulus_bytes, out_len = 256;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (sig_len != modulus_bytes){
      st_err_log(46, __FILE__, __LINE__);
      return CKR_SIGNATURE_LEN_RANGE;
   }
   // verifying is a public key operation --> encrypt
   //
   rc = ckm_rsa_oaep_encrypt( signature, modulus_bytes, out, &out_len, key_obj );
   if (rc == CKR_OK) {
      if (out_len != in_data_len){
         st_err_log(47, __FILE__, __LINE__);
         return CKR_SIGNATURE_INVALID;
      }

      if (memcmp(in_data, &out, out_len) != 0){
         st_err_log(47, __FILE__, __LINE__);
         return CKR_SIGNATURE_INVALID;
      }
      return CKR_OK;
   }
   else
      st_err_log(132, __FILE__, __LINE__);

   return rc;
}


//
//
CK_RV
rsa_pkcs_oaep_verify_recover( SESSION             * sess,
                         CK_BBOOL              length_only,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * signature,
                         CK_ULONG              sig_len,
                         CK_BYTE             * out_data,
                         CK_ULONG            * out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_ULONG         i, modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   if (!sess || !ctx || !out_data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (sig_len != modulus_bytes){
      st_err_log(46, __FILE__, __LINE__);
      return CKR_SIGNATURE_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = modulus_bytes - (2 * SHA1_HASH_SIZE + 1);
      return CKR_OK;
   }

   // verify is a public key operation --> encrypt
   //
   rc = ckm_rsa_oaep_encrypt( signature, modulus_bytes, out_data, out_data_len, key_obj );
   if (rc != CKR_OK)
      st_err_log(132, __FILE__, __LINE__);

   return rc;
}


//
//
CK_RV
ckm_rsa_key_pair_gen( TEMPLATE  * publ_tmpl,
                      TEMPLATE  * priv_tmpl )
{
   CK_RV                rc;

   rc = token_specific.t_rsa_generate_keypair(publ_tmpl, priv_tmpl);
   if (rc != CKR_OK)
      st_err_log(91, __FILE__, __LINE__);

   return rc;
}


//
//
CK_RV
ckm_rsa_oaep_encrypt( CK_BYTE   * in_data,
                 CK_ULONG    in_data_len,
                 CK_BYTE   * out_data,
		 CK_ULONG  * out_data_len,
                 OBJECT    * key_obj )
{
   CK_ATTRIBUTE      * attr    = NULL;
   CK_ATTRIBUTE      * modulus = NULL;
   CK_OBJECT_CLASS     keyclass;
   CK_RV               rc;


   rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a public key
   //
   if (keyclass != CKO_PUBLIC_KEY){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   rc = token_specific.t_rsa_oaep_encrypt(in_data, in_data_len, out_data, out_data_len, key_obj);
   if (rc != CKR_OK)
      st_err_log(134, __FILE__, __LINE__);

   return rc;
}


//
//
CK_RV
ckm_rsa_oaep_decrypt( CK_BYTE   * in_data,
                 CK_ULONG    in_data_len,
                 CK_BYTE   * out_data,
		 CK_ULONG  * out_data_len,
                 OBJECT    * key_obj )
{
   CK_ATTRIBUTE      * attr     = NULL;
   CK_OBJECT_CLASS     keyclass;
   CK_RV               rc;


   rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a private key
   //
   if (keyclass != CKO_PRIVATE_KEY){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = token_specific.t_rsa_oaep_decrypt(in_data, in_data_len, out_data, out_data_len, key_obj);
   if (rc != CKR_OK)
      st_err_log(135, __FILE__, __LINE__);

   return rc;
}


// in the Shallow token we have the modulus so we can just get it
// from that attribute... in the cryptolite token we have to use the
// CK_VALUE cheat
// This should only be used with private operations
CK_ULONG
rsa_get_key_len(OBJECT  *keyobj)
{
   CK_ATTRIBUTE    *attr     = NULL;
   CK_BBOOL         flag;
   flag = template_attribute_find( keyobj->template, CKA_MODULUS, &attr );
   if (flag == FALSE)
      return 0;
   else
      return attr->ulValueLen;

}

CK_RV
rsa_format_block( CK_BYTE   * in_data,
                  CK_ULONG    in_data_len,
                  CK_BYTE   * out_data,
                  CK_ULONG    mod_len,
                  CK_ULONG    type )
{
   CK_BYTE   buf[256];
   CK_BYTE   rnd_buf[32];
   CK_ULONG  i, end, tmp;
   CK_RV     rc;

   if (!in_data || !out_data){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   // temporary storage
   //
   memcpy( buf, in_data, in_data_len );

   // PKCS Block Formatting:
   //
   // EB == 00 | BT | (K - 3 - DATALEN) bytes of PS | 00 | D
   //
   // Block Type 1:  PS = 0xFF
   // Block Type 2:  PS = Random Data
   //
   if (type == PKCS_BT_1) {
      out_data[0] = 0x0;
      out_data[1] = 0x1;

      tmp = mod_len - 3 - in_data_len;
      memset( &out_data[2], 0xFF, tmp );

      tmp += 2;

      out_data[tmp] = 0x0;
      tmp++;

      memcpy( &out_data[tmp], buf, in_data_len );
   }
   else if (type == PKCS_BT_2) {
      out_data[0] = 0x0;
      out_data[1] = 0x2;

      tmp = 2;
      end = mod_len - 3 - in_data_len;

      while (end > 0) {
         rc = rng_generate( rnd_buf, 32 );
         if (rc != CKR_OK){
            st_err_log(130, __FILE__, __LINE__);
            return rc;
         }
         for (i=0; (i < 32) && (end > 0); i++) {
            if (rnd_buf[i] != 0) {
               out_data[ tmp++ ] = rnd_buf[i];
               end--;
            }
         }
      }

      out_data[tmp] = 0x0;
      tmp++;

      memcpy( &out_data[tmp], buf, in_data_len );
   }

   return CKR_OK;
}



//
//
CK_RV
rsa_pkcs_encrypt( SESSION           *sess,
                  CK_BBOOL           length_only,
                  ENCR_DECR_CONTEXT *ctx,
                  CK_BYTE           *in_data,
                  CK_ULONG           in_data_len,
                  CK_BYTE           *out_data,
                  CK_ULONG          *out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_BYTE          clear[256], cipher[256];  // 2048 bits
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (in_data_len > (modulus_bytes - 11)){
      st_err_log(109, __FILE__, __LINE__);
      return CKR_DATA_LEN_RANGE;
   }

   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   if (*out_data_len < modulus_bytes) {
      *out_data_len = modulus_bytes;
      st_err_log(111, __FILE__, __LINE__);
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = rsa_format_block( in_data, in_data_len, clear, modulus_bytes, PKCS_BT_2 );
   if (rc != CKR_OK){
      st_err_log(131, __FILE__, __LINE__);
      return rc;
   }
   rc = ckm_rsa_encrypt( clear, modulus_bytes, cipher, key_obj );
   if (rc == CKR_OK) {
      memcpy( out_data, cipher, modulus_bytes );
      *out_data_len = modulus_bytes;
   }
   else
      st_err_log(132, __FILE__, __LINE__);
   return rc;
}


//
//
CK_RV
rsa_pkcs_decrypt( SESSION           *sess,
                  CK_BBOOL           length_only,
                  ENCR_DECR_CONTEXT *ctx,
                  CK_BYTE           *in_data,
                  CK_ULONG           in_data_len,
                  CK_BYTE           *out_data,
                  CK_ULONG          *out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_BYTE          out[256];  // 2048 bits
   CK_ULONG         i, modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   modulus_bytes = rsa_get_key_len(key_obj);

   // check input data length restrictions
   //
   if (in_data_len != modulus_bytes){
      st_err_log(112, __FILE__, __LINE__);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      // this is not exact but it's the upper bound; otherwise we'll need
      // to do the RSA operation just to get the required length
      //
      *out_data_len = modulus_bytes - 11;
      return CKR_OK;
   }

   rc = ckm_rsa_decrypt( in_data, modulus_bytes, out, key_obj );
   if (rc == CKR_OK) {
      CK_ULONG len;

      // strip off the PKCS block formatting data
      //
      // 00 | BT | PADDING | 00 | DATA
      //
      for (i=2; i < in_data_len; i++) {
         if (out[i] == 0x0) {
            i++;  // point i at the first data byte
            break;
         }
      }

      if (i == in_data_len){
         st_err_log(14, __FILE__, __LINE__);
         return CKR_ENCRYPTED_DATA_INVALID;
      }
      len = in_data_len - i;

      if (len > *out_data_len) {
         *out_data_len = len;
         st_err_log(111, __FILE__, __LINE__);
         return CKR_BUFFER_TOO_SMALL;
      }

      memcpy( out_data, &out[i], len );
      *out_data_len = len;
   }
   else 
      st_err_log(133, __FILE__, __LINE__);

   if (rc == CKR_DATA_LEN_RANGE){
      st_err_log(109, __FILE__, __LINE__);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   return rc;
}


//
//
CK_RV
rsa_pkcs_sign( SESSION             *sess,
               CK_BBOOL             length_only,
               SIGN_VERIFY_CONTEXT *ctx,
               CK_BYTE             *in_data,
               CK_ULONG             in_data_len,
               CK_BYTE             *out_data,
               CK_ULONG            *out_data_len )
{
   OBJECT          *key_obj   = NULL;
   CK_ATTRIBUTE    *attr      = NULL;
   CK_BYTE          data[256], sig[256];  // max size: 256 bytes == 2048 bits
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   if (!sess || !ctx || !out_data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   modulus_bytes = rsa_get_key_len(key_obj);

   // check input data length restrictions
   //
   if (in_data_len > (modulus_bytes - 11)){
      st_err_log(109, __FILE__, __LINE__);
      return CKR_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   if (*out_data_len < modulus_bytes) {
      *out_data_len = modulus_bytes;
      st_err_log(111, __FILE__, __LINE__);
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = rsa_format_block( in_data, in_data_len, data, modulus_bytes, PKCS_BT_1 );
   if (rc != CKR_OK){
      st_err_log(131, __FILE__, __LINE__);
      return rc;
   }
   // signing is a private key operation --> decrypt
   //
   rc = ckm_rsa_decrypt( data, modulus_bytes, sig, key_obj );
   if (rc == CKR_OK) {
      memcpy( out_data, sig, modulus_bytes );
      *out_data_len = modulus_bytes;
   }
   else
      st_err_log(133, __FILE__, __LINE__);
   return rc;
}


//
//
CK_RV
rsa_pkcs_verify( SESSION             * sess,
                 SIGN_VERIFY_CONTEXT * ctx,
                 CK_BYTE             * in_data,
                 CK_ULONG              in_data_len,
                 CK_BYTE             * signature,
                 CK_ULONG              sig_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_BYTE          out[256];  // 2048 bits
   CK_ULONG         i, modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (sig_len != modulus_bytes){
      st_err_log(46, __FILE__, __LINE__);
      return CKR_SIGNATURE_LEN_RANGE;
   }
   // verifying is a public key operation --> encrypt
   //
   rc = ckm_rsa_encrypt( signature, modulus_bytes, out, key_obj );
   if (rc == CKR_OK) {
      CK_ULONG len;

      // skip past the PKCS block formatting data
      //
      // 00 | BT | PADDING | 00 | DATA
      //
      for (i=2; i < modulus_bytes; i++) {
         if (out[i] == 0x0) {
            i++;  // point i at the first data byte
            break;
         }
      }

      len = modulus_bytes - i;

      if (len != in_data_len){
         st_err_log(47, __FILE__, __LINE__);
         return CKR_SIGNATURE_INVALID;
      }

      if (memcmp(in_data, &out[i], len) != 0){
         st_err_log(47, __FILE__, __LINE__);
         return CKR_SIGNATURE_INVALID;
      }
      return CKR_OK;
   }
   else
      st_err_log(132, __FILE__, __LINE__);

   return rc;
}


//
//
CK_RV
rsa_pkcs_verify_recover( SESSION             * sess,
                         CK_BBOOL              length_only,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * signature,
                         CK_ULONG              sig_len,
                         CK_BYTE             * out_data,
                         CK_ULONG            * out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_BYTE          out[256];  // 2048 bits
   CK_ULONG         i, modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   if (!sess || !ctx || !out_data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (sig_len != modulus_bytes){
      st_err_log(46, __FILE__, __LINE__);
      return CKR_SIGNATURE_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = modulus_bytes - 11;
      return CKR_OK;
   }

   // verify is a public key operation --> encrypt
   //
   rc = ckm_rsa_encrypt( signature, modulus_bytes, out, key_obj );
   if (rc == CKR_OK) {
      CK_ULONG len;

      // skip past the PKCS block formatting data
      //
      // 00 | BT | PADDING | 00 | DATA
      //
      for (i=2; i < modulus_bytes; i++) {
         if (out[i] == 0x0) {
            i++;  // point i at the first data byte
            break;
         }
      }

      len = modulus_bytes - i;

      if (*out_data_len < len) {
         *out_data_len = len;
         st_err_log(111, __FILE__, __LINE__);
         return CKR_BUFFER_TOO_SMALL;
      }

      memcpy( out_data, &out[i], len );
      *out_data_len = len;

      return CKR_OK;
   }
   else
      st_err_log(132, __FILE__, __LINE__);

   return rc;
}


//
//
CK_RV
rsa_x509_encrypt( SESSION           *sess,
                  CK_BBOOL           length_only,
                  ENCR_DECR_CONTEXT *ctx,
                  CK_BYTE           *in_data,
                  CK_ULONG           in_data_len,
                  CK_BYTE           *out_data,
                  CK_ULONG          *out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_BYTE          clear[256], cipher[256];  // max size: 256 bytes == 2048 bits
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // CKM_RSA_X_509 requires input data length to be no bigger than the modulus
   //
   if (in_data_len > modulus_bytes){
      st_err_log(109, __FILE__, __LINE__);
      return CKR_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   if (*out_data_len < modulus_bytes) {
      *out_data_len = modulus_bytes;
      st_err_log(111, __FILE__, __LINE__);
      return CKR_BUFFER_TOO_SMALL;
   }

   // prepad with zeros
   //
   memset( clear, 0x0, modulus_bytes - in_data_len);
   memcpy( &clear[modulus_bytes - in_data_len], in_data, in_data_len );

   rc = ckm_rsa_encrypt( clear, modulus_bytes, cipher, key_obj );
   if (rc == CKR_OK) {
      memcpy( out_data, cipher, modulus_bytes );
      *out_data_len = modulus_bytes;
   }
   else
      st_err_log(132, __FILE__, __LINE__);

   return rc;
}


//
//
CK_RV
rsa_x509_decrypt( SESSION           *sess,
                  CK_BBOOL           length_only,
                  ENCR_DECR_CONTEXT *ctx,
                  CK_BYTE           *in_data,
                  CK_ULONG           in_data_len,
                  CK_BYTE           *out_data,
                  CK_ULONG          *out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_BYTE          out[256];  // 2048 bits
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
#if 0
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE)
      return CKR_FUNCTION_FAILED;
   else
      modulus_bytes = attr->ulValueLen;
#else
   modulus_bytes = rsa_get_key_len(key_obj);
#endif

   // check input data length restrictions
   //
   if (in_data_len != modulus_bytes){
      st_err_log(112, __FILE__, __LINE__);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   // Although X.509 prepads with zeros, we don't strip it after
   // decryption (PKCS #11 specifies that X.509 decryption is supposed
   // to produce K bytes of cleartext where K is the modulus length)
   //
   if (*out_data_len < modulus_bytes) {
      *out_data_len = modulus_bytes;
      st_err_log(111, __FILE__, __LINE__);
      return CKR_BUFFER_TOO_SMALL;
   }

   rc = ckm_rsa_decrypt( in_data, modulus_bytes, out, key_obj );
   if (rc == CKR_OK) {
      memcpy( out_data, out, modulus_bytes );
      *out_data_len = modulus_bytes;
   }
   else
      st_err_log(133, __FILE__, __LINE__);
   // ckm_rsa_operation is used for all RSA operations so we need to adjust
   // the return code accordingly
   //
   if (rc == CKR_DATA_LEN_RANGE){
      st_err_log(112, __FILE__, __LINE__);
      return CKR_ENCRYPTED_DATA_LEN_RANGE;
   }
   return rc;
}


//
//
CK_RV
rsa_x509_sign( SESSION             *sess,
               CK_BBOOL             length_only,
               SIGN_VERIFY_CONTEXT *ctx,
               CK_BYTE             *in_data,
               CK_ULONG             in_data_len,
               CK_BYTE             *out_data,
               CK_ULONG            *out_data_len )
{
   OBJECT          *key_obj   = NULL;
   CK_ATTRIBUTE    *attr      = NULL;
   CK_BYTE          data[256], sig[256];  // max size: 256 bytes == 2048 bits
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   if (!sess || !ctx || !out_data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
#if 0
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE)
      return CKR_FUNCTION_FAILED;
   else
      modulus_bytes = attr->ulValueLen;
#else
   modulus_bytes = rsa_get_key_len(key_obj);
#endif

   // check input data length restrictions
   //
   if (in_data_len > modulus_bytes){
      st_err_log(109, __FILE__, __LINE__);
      return CKR_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   if (*out_data_len < modulus_bytes) {
      *out_data_len = modulus_bytes;
      st_err_log(111, __FILE__, __LINE__);
      return CKR_BUFFER_TOO_SMALL;
   }

   memset( data, 0x0, modulus_bytes - in_data_len );
   memcpy( &data[modulus_bytes - in_data_len], in_data, in_data_len );

   // signing is a private key operation --> decrypt
   //
   rc = ckm_rsa_decrypt( data, modulus_bytes, sig, key_obj );
   if (rc == CKR_OK) {
      memcpy( out_data, sig, modulus_bytes );
      *out_data_len = modulus_bytes;
   }
   else
      st_err_log(133, __FILE__, __LINE__);
   return rc;
}


//
//
CK_RV
rsa_x509_verify( SESSION             * sess,
                 SIGN_VERIFY_CONTEXT * ctx,
                 CK_BYTE             * in_data,
                 CK_ULONG              in_data_len,
                 CK_BYTE             * signature,
                 CK_ULONG              sig_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_BYTE          out[256];  // 2048 bits
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (sig_len != modulus_bytes){
      st_err_log(46, __FILE__, __LINE__);
      return CKR_SIGNATURE_LEN_RANGE;
   }
   // verify is a public key operation --> encrypt
   //
   rc = ckm_rsa_encrypt( signature, modulus_bytes, out, key_obj );
   if (rc == CKR_OK) {
      CK_ULONG pos1, pos2, len;

      // it should be noted that in_data_len is not necessarily
      // the same as the modulus length
      //
      for (pos1=0; pos1 < in_data_len; pos1++)
         if (in_data[pos1] != 0)
            break;

      for (pos2=0; pos2 < modulus_bytes; pos2++)
         if (out[pos2] != 0)
            break;

      // at this point, pos1 and pos2 point to the first non-zero bytes
      // in the input data and the decrypted signature (the recovered data),
      // respectively.
      //

      if ((in_data_len - pos1) != (modulus_bytes - pos2)){
         st_err_log(47, __FILE__, __LINE__);
         return CKR_SIGNATURE_INVALID;
      }
      len = in_data_len - pos1;

      if (memcmp(&in_data[pos1], &out[pos2], len) != 0){
         st_err_log(47, __FILE__, __LINE__);
         return CKR_SIGNATURE_INVALID;
      }
      return CKR_OK;
   }
   else
      st_err_log(132, __FILE__, __LINE__);

   return rc;
}


//
//
CK_RV
rsa_x509_verify_recover( SESSION             * sess,
                         CK_BBOOL              length_only,
                         SIGN_VERIFY_CONTEXT * ctx,
                         CK_BYTE             * signature,
                         CK_ULONG              sig_len,
                         CK_BYTE             * out_data,
                         CK_ULONG            * out_data_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_BYTE          out[256];  // 2048 bits
   CK_ULONG         modulus_bytes;
   CK_BBOOL         flag;
   CK_RV            rc;


   if (!sess || !ctx || !out_data_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      return rc;
   }
   flag = template_attribute_find( key_obj->template, CKA_MODULUS, &attr );
   if (flag == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      modulus_bytes = attr->ulValueLen;

   // check input data length restrictions
   //
   if (sig_len != modulus_bytes){
      st_err_log(46, __FILE__, __LINE__);
      return CKR_SIGNATURE_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = modulus_bytes;
      return CKR_OK;
   }

   // we perform no stripping of prepended zero bytes here
   //
   if (*out_data_len < modulus_bytes) {
      *out_data_len = modulus_bytes;
      st_err_log(111, __FILE__, __LINE__);
      return CKR_BUFFER_TOO_SMALL;
   }

   // verify is a public key operation --> encrypt
   //
   rc = ckm_rsa_encrypt( signature, modulus_bytes, out, key_obj );
   if (rc == CKR_OK) {
      memcpy( out_data, out, modulus_bytes );
      *out_data_len = modulus_bytes;

      return CKR_OK;
   }
   else
      st_err_log(132, __FILE__, __LINE__);

   return rc;
}


//
//
CK_RV
rsa_hash_pkcs_sign( SESSION              * sess,
                    CK_BBOOL               length_only,
                    SIGN_VERIFY_CONTEXT  * ctx,
                    CK_BYTE              * in_data,
                    CK_ULONG               in_data_len,
                    CK_BYTE              * signature,
                    CK_ULONG             * sig_len )
{
   CK_BYTE            * ber_data  = NULL;
   CK_BYTE            * octet_str = NULL;
   CK_BYTE            * oid       = NULL;
   CK_BYTE            * tmp       = NULL;

   CK_ULONG             buf1[16];  // 64 bytes is more than enough

   CK_BYTE              hash[SHA1_HASH_SIZE];  // big enough for SHA1, MD5 or MD2
   DIGEST_CONTEXT       digest_ctx;
   SIGN_VERIFY_CONTEXT  sign_ctx;
   CK_MECHANISM         digest_mech;
   CK_MECHANISM         sign_mech;
   CK_ULONG             ber_data_len, hash_len, octet_str_len, oid_len;
   CK_RV                rc;

   if (!sess || !ctx || !in_data){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   memset( &digest_ctx, 0x0, sizeof(digest_ctx) );
   memset( &sign_ctx,   0x0, sizeof(sign_ctx)   );

   if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS) {
      digest_mech.mechanism      = CKM_MD2;
      oid = ber_md2WithRSAEncryption;
      oid_len = ber_md2WithRSAEncryptionLen;

   }
   else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
      digest_mech.mechanism      = CKM_MD5;
      oid = ber_md5WithRSAEncryption;
      oid_len = ber_md5WithRSAEncryptionLen;
   }
   else {
      digest_mech.mechanism      = CKM_SHA_1;
      oid = ber_sha1WithRSAEncryption;
      oid_len = ber_sha1WithRSAEncryptionLen;
   }

   digest_mech.ulParameterLen = 0;
   digest_mech.pParameter     = NULL;

   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK){
      st_err_log(123, __FILE__, __LINE__);
      goto error;
   }
   hash_len = sizeof(hash);
   rc = digest_mgr_digest( sess, length_only, &digest_ctx, in_data, in_data_len, hash, &hash_len );
   if (rc != CKR_OK){
      st_err_log(124, __FILE__, __LINE__);
      goto error;
   }
      // build the BER-encodings
     
    rc = ber_encode_OCTET_STRING( FALSE, &octet_str, &octet_str_len, hash, hash_len );
    if (rc != CKR_OK){
       st_err_log(77, __FILE__, __LINE__);
       goto error;
    }
    tmp = (CK_BYTE *)buf1;
    memcpy( tmp,           oid,       oid_len );
    memcpy( tmp + oid_len, octet_str, octet_str_len);
      
    rc = ber_encode_SEQUENCE( FALSE, &ber_data, &ber_data_len, tmp, (oid_len + octet_str_len) );
    if (rc != CKR_OK){
       st_err_log(78, __FILE__, __LINE__);
       goto error;
    }
    // sign the BER-encoded data block
   

   sign_mech.mechanism      = CKM_RSA_PKCS;
   sign_mech.ulParameterLen = 0;
   sign_mech.pParameter     = NULL;

   rc = sign_mgr_init( sess, &sign_ctx, &sign_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      st_err_log(127, __FILE__, __LINE__);
      goto error;
   }
   //rc = sign_mgr_sign( sess, length_only, &sign_ctx, hash, hash_len, signature, sig_len );
   rc = sign_mgr_sign( sess, length_only, &sign_ctx, ber_data, ber_data_len, signature, sig_len );
   if (rc != CKR_OK)
      st_err_log(128, __FILE__, __LINE__);

error:
   if (octet_str) free( octet_str );
   if (ber_data)  free( ber_data );
   digest_mgr_cleanup( &digest_ctx );
   sign_mgr_cleanup( &sign_ctx );
   return rc;
}


//
//
CK_RV
rsa_hash_pkcs_sign_update( SESSION              * sess,
                           SIGN_VERIFY_CONTEXT  * ctx,
                           CK_BYTE              * in_data,
                           CK_ULONG               in_data_len )
{
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_MECHANISM          digest_mech;
   CK_RV                 rc;

   if (!sess || !ctx || !in_data){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   if (context->flag == FALSE) {
      if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS)
         digest_mech.mechanism = CKM_MD2;
      else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS)
         digest_mech.mechanism = CKM_MD5;
      else
         digest_mech.mechanism = CKM_SHA_1;

      digest_mech.ulParameterLen = 0;
      digest_mech.pParameter     = NULL;

      rc = digest_mgr_init( sess, &context->hash_context, &digest_mech );
      if (rc != CKR_OK){
         st_err_log(123, __FILE__, __LINE__);
         goto error;
      }
      context->flag = TRUE;
   }

   rc = digest_mgr_digest_update( sess, &context->hash_context, in_data, in_data_len );
   if (rc != CKR_OK){
      st_err_log(123, __FILE__, __LINE__);
      goto error;
   }
   return CKR_OK;

error:
   digest_mgr_cleanup( &context->hash_context );
   return rc;
}


//
//
CK_RV
rsa_hash_pkcs_verify( SESSION              * sess,
                      SIGN_VERIFY_CONTEXT  * ctx,
                      CK_BYTE              * in_data,
                      CK_ULONG               in_data_len,
                      CK_BYTE              * signature,
                      CK_ULONG               sig_len )
{
   CK_BYTE            * ber_data  = NULL;
   CK_BYTE            * octet_str = NULL;
   CK_BYTE            * oid       = NULL;
   CK_BYTE            * tmp       = NULL;

   CK_ULONG             buf1[16];  // 64 bytes is more than enough
   CK_BYTE              hash[SHA1_HASH_SIZE];
   DIGEST_CONTEXT       digest_ctx;
   SIGN_VERIFY_CONTEXT  verify_ctx;
   CK_MECHANISM         digest_mech;
   CK_MECHANISM         verify_mech;
   CK_ULONG             ber_data_len, hash_len, octet_str_len, oid_len;
   CK_RV                rc;

   if (!sess || !ctx || !in_data){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   memset( &digest_ctx, 0x0, sizeof(digest_ctx) );
   memset( &verify_ctx, 0x0, sizeof(verify_ctx) );

   if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS) {
      digest_mech.mechanism      = CKM_MD2;
      oid = ber_md2WithRSAEncryption;
      oid_len = ber_md2WithRSAEncryptionLen;
   }
   else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
      digest_mech.mechanism      = CKM_MD5;
      oid = ber_md5WithRSAEncryption;
      oid_len = ber_md5WithRSAEncryptionLen;
   }
   else {
      digest_mech.mechanism      = CKM_SHA_1;
      oid = ber_sha1WithRSAEncryption;
      oid_len = ber_sha1WithRSAEncryptionLen;
   }


   digest_mech.ulParameterLen = 0;
   digest_mech.pParameter     = NULL;

   rc = digest_mgr_init( sess, &digest_ctx, &digest_mech );
   if (rc != CKR_OK){
      st_err_log(123, __FILE__, __LINE__);
      goto done;
   }
   hash_len = sizeof(hash);
   rc = digest_mgr_digest( sess, FALSE, &digest_ctx, in_data, in_data_len, hash, &hash_len );
   if (rc != CKR_OK){
      st_err_log(124, __FILE__, __LINE__);
      goto done;
   }

   // Build the BER encoding
   //
   rc = ber_encode_OCTET_STRING( FALSE, &octet_str, &octet_str_len, hash, hash_len );
   if (rc != CKR_OK){
      st_err_log(77, __FILE__, __LINE__);
      goto done;
   }
   tmp = (CK_BYTE *)buf1;
   memcpy( tmp,           oid,       oid_len );
   memcpy( tmp + oid_len, octet_str, octet_str_len );

   rc = ber_encode_SEQUENCE( FALSE, &ber_data, &ber_data_len, tmp, (oid_len + octet_str_len) );
   if (rc != CKR_OK){
      st_err_log(78, __FILE__, __LINE__);
      goto done;
   }
   // Verify the Signed BER-encoded Data block
   //
   verify_mech.mechanism      = CKM_RSA_PKCS;
   verify_mech.ulParameterLen = 0;
   verify_mech.pParameter     = NULL;

   rc = verify_mgr_init( sess, &verify_ctx, &verify_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      st_err_log(167, __FILE__, __LINE__);
      goto done;
   }
   //rc = verify_mgr_verify( sess, &verify_ctx, hash, hash_len, signature, sig_len );
   rc = verify_mgr_verify( sess, &verify_ctx, ber_data, ber_data_len, signature, sig_len );
   if (rc != CKR_OK)
      st_err_log(168, __FILE__, __LINE__);
done:
   if (octet_str) free( octet_str );
   if (ber_data)  free( ber_data );
   
   digest_mgr_cleanup( &digest_ctx );
   sign_mgr_cleanup( &verify_ctx );
   return rc;
}

//
//
CK_RV
rsa_hash_pkcs_verify_update( SESSION              * sess,
                             SIGN_VERIFY_CONTEXT  * ctx,
                             CK_BYTE              * in_data,
                             CK_ULONG               in_data_len )
{
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_MECHANISM          digest_mech;
   CK_RV                 rc;

   if (!sess || !ctx || !in_data){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   if (context->flag == FALSE) {
      if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS)
         digest_mech.mechanism = CKM_MD2;
      else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS)
         digest_mech.mechanism = CKM_MD5;
      else
         digest_mech.mechanism = CKM_SHA_1;

      digest_mech.ulParameterLen = 0;
      digest_mech.pParameter     = NULL;

      rc = digest_mgr_init( sess, &context->hash_context, &digest_mech );
      if (rc != CKR_OK){
         st_err_log(123, __FILE__, __LINE__);
         goto error;
      }
      context->flag = TRUE;
   }

   rc = digest_mgr_digest_update( sess, &context->hash_context, in_data, in_data_len );
   if (rc != CKR_OK){
      st_err_log(123, __FILE__, __LINE__);
      goto error;
   }
   return CKR_OK;

error:
   digest_mgr_cleanup( &context->hash_context );
   return rc;
}


//
//
CK_RV
rsa_hash_pkcs_sign_final( SESSION              * sess,
                          CK_BBOOL               length_only,
                          SIGN_VERIFY_CONTEXT  * ctx,
                          CK_BYTE              * signature,
                          CK_ULONG             * sig_len )
{
   CK_BYTE            * ber_data  = NULL;
   CK_BYTE            * octet_str = NULL;
   CK_BYTE            * oid       = NULL;
   CK_BYTE            * tmp       = NULL;

   CK_ULONG              buf1[16];  // 64 bytes is more than enough

   CK_BYTE               hash[SHA1_HASH_SIZE];
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_ULONG              ber_data_len, hash_len, octet_str_len, oid_len;
   CK_MECHANISM          sign_mech;
   SIGN_VERIFY_CONTEXT   sign_ctx;
   CK_RV                 rc;

   if (!sess || !ctx || !sig_len){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS) {
      oid = ber_md2WithRSAEncryption;
      oid_len = ber_md2WithRSAEncryptionLen;
   }
   else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
      oid = ber_md5WithRSAEncryption;
      oid_len = ber_md5WithRSAEncryptionLen;
   }
   else {
      oid = ber_sha1WithRSAEncryption;
      oid_len = ber_sha1WithRSAEncryptionLen;
   }

   memset( &sign_ctx, 0x0, sizeof(sign_ctx));

   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, length_only, &context->hash_context, hash, &hash_len );
   if (rc != CKR_OK){
      st_err_log(126, __FILE__, __LINE__);
      goto done;
   }
   // Build the BER Encoded Data block
   //
   rc = ber_encode_OCTET_STRING( FALSE, &octet_str, &octet_str_len, hash, hash_len );
   if (rc != CKR_OK){
      st_err_log(77, __FILE__, __LINE__);
      goto done;
   }
   tmp = (CK_BYTE *)buf1;
   memcpy( tmp,           oid,       oid_len );
   memcpy( tmp + oid_len, octet_str, octet_str_len );

   rc = ber_encode_SEQUENCE( FALSE, &ber_data, &ber_data_len, tmp, (oid_len + octet_str_len) );
   if (rc != CKR_OK){
      st_err_log(78, __FILE__, __LINE__);
      goto done;
   }
   // sign the BER-encoded data block
   //   

   sign_mech.mechanism      = CKM_RSA_PKCS;
   sign_mech.ulParameterLen = 0;
   sign_mech.pParameter     = NULL;

   rc = sign_mgr_init( sess, &sign_ctx, &sign_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      st_err_log(127, __FILE__, __LINE__);
      goto done;
   }
   //rc = sign_mgr_sign( sess, length_only, &sign_ctx, hash, hash_len, signature, sig_len );
   rc = sign_mgr_sign( sess, length_only, &sign_ctx, ber_data, ber_data_len, signature, sig_len );
   if (rc != CKR_OK)
      st_err_log(128, __FILE__, __LINE__);

   if (length_only == TRUE || rc == CKR_BUFFER_TOO_SMALL) {
      sign_mgr_cleanup( &sign_ctx );
      return rc;
   }

done:
   if (octet_str) free( octet_str );
   if (ber_data)  free( ber_data );

   digest_mgr_cleanup( &context->hash_context );
   sign_mgr_cleanup( &sign_ctx );
   return rc;
}


//
//
CK_RV
rsa_hash_pkcs_verify_final( SESSION              * sess,
                            SIGN_VERIFY_CONTEXT  * ctx,
                            CK_BYTE              * signature,
                            CK_ULONG               sig_len )
{
   CK_BYTE            * ber_data  = NULL;
   CK_BYTE            * octet_str = NULL;
   CK_BYTE            * oid       = NULL;
   CK_BYTE            * tmp       = NULL;

   CK_ULONG             buf1[16];   // 64 bytes is more than enough
   CK_BYTE               hash[SHA1_HASH_SIZE];
   RSA_DIGEST_CONTEXT  * context = NULL;
   CK_ULONG              ber_data_len, hash_len, octet_str_len, oid_len;
   CK_MECHANISM          verify_mech;
   SIGN_VERIFY_CONTEXT   verify_ctx;
   CK_RV                 rc;

   if (!sess || !ctx || !signature){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->mech.mechanism == CKM_MD2_RSA_PKCS) {
      oid = ber_md2WithRSAEncryption;
      oid_len = ber_md2WithRSAEncryptionLen;
   }
   else if (ctx->mech.mechanism == CKM_MD5_RSA_PKCS) {
      oid = ber_md5WithRSAEncryption;
      oid_len = ber_md5WithRSAEncryptionLen;
   }
   else {
      oid = ber_sha1WithRSAEncryption;
      oid_len = ber_sha1WithRSAEncryptionLen;
   }

   memset( &verify_ctx, 0x0, sizeof(verify_ctx));

   context = (RSA_DIGEST_CONTEXT *)ctx->context;

   hash_len = sizeof(hash);
   rc = digest_mgr_digest_final( sess, FALSE, &context->hash_context, hash, &hash_len );
   if (rc != CKR_OK){
      st_err_log(126, __FILE__, __LINE__);
      goto done;
   }
   // Build the BER encoding
   //
   rc = ber_encode_OCTET_STRING( FALSE, &octet_str, &octet_str_len, hash, hash_len );
   if (rc != CKR_OK){
      st_err_log(77, __FILE__, __LINE__);
      goto done;
   }
   tmp = (CK_BYTE *)buf1;
   memcpy( tmp,           oid,       oid_len );
   memcpy( tmp + oid_len, octet_str, octet_str_len );

   rc = ber_encode_SEQUENCE( FALSE, &ber_data, &ber_data_len, tmp, (oid_len + octet_str_len) );
   if (rc != CKR_OK){
      st_err_log(78, __FILE__, __LINE__);
      goto done;
   }
   // verify the signed BER-encoded data block
   //

   verify_mech.mechanism      = CKM_RSA_PKCS;
   verify_mech.ulParameterLen = 0;
   verify_mech.pParameter     = NULL;

   rc = verify_mgr_init( sess, &verify_ctx, &verify_mech, FALSE, ctx->key );
   if (rc != CKR_OK){
      st_err_log(167, __FILE__, __LINE__);
      goto done;
   }
   //rc = verify_mgr_verify( sess, &verify_ctx, hash, hash_len, signature, sig_len );
   rc = verify_mgr_verify( sess, &verify_ctx, ber_data, ber_data_len, signature, sig_len );
   if (rc != CKR_OK)
      st_err_log(168, __FILE__, __LINE__);
done:
   if (octet_str) free( octet_str );
   if (ber_data)  free( ber_data );
   digest_mgr_cleanup( &context->hash_context );
   verify_mgr_cleanup( &verify_ctx );
   return rc;
}

//
//
CK_RV
ckm_rsa_encrypt( CK_BYTE   * in_data,
                 CK_ULONG    in_data_len,
                 CK_BYTE   * out_data,
                 OBJECT    * key_obj )
{
   CK_ATTRIBUTE      * attr    = NULL;
   CK_ATTRIBUTE      * modulus = NULL;
   CK_ATTRIBUTE      * pub_exp = NULL;
   CK_BYTE           * ptr     = NULL;

   CK_ULONG            buffer[80];  // plenty of room...
   CK_OBJECT_CLASS     keyclass;
   CK_ULONG            req_len, repl_len, key_len;
   CK_RV               rc;


   rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a public key
   //
   if (keyclass != CKO_PUBLIC_KEY){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   
   rc = token_specific.t_rsa_encrypt(in_data,in_data_len,out_data,key_obj);
   if (rc != CKR_OK)
      st_err_log(134, __FILE__, __LINE__);

done:
   return rc;
}


//
//
CK_RV
ckm_rsa_decrypt( CK_BYTE   * in_data,
                 CK_ULONG    in_data_len,
                 CK_BYTE   * out_data,
                 OBJECT    * key_obj )
{
   CK_ATTRIBUTE      * attr     = NULL;
   CK_ATTRIBUTE      * modulus  = NULL;
   CK_ATTRIBUTE      * pub_exp  = NULL;
   CK_ATTRIBUTE      * prime1   = NULL;
   CK_ATTRIBUTE      * prime2   = NULL;
   CK_ATTRIBUTE      * exp1     = NULL;
   CK_ATTRIBUTE      * exp2     = NULL;
   CK_ATTRIBUTE      * coeff    = NULL;
   CK_BYTE           * ptr      = NULL;

   CK_ULONG            buffer[80];  // plenty of room...
   CK_OBJECT_CLASS     keyclass;
   CK_ULONG            key_size;
   CK_ULONG            req_len, repl_len;
   CK_RV               rc;


   rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a private key
   //
   if (keyclass != CKO_PRIVATE_KEY){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   rc = token_specific.t_rsa_decrypt(in_data,in_data_len,out_data,key_obj);
   if (rc != CKR_OK)
      st_err_log(135, __FILE__, __LINE__);

done:
   return rc;
}



