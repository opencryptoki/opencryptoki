
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


// File:  mech_dsa.c
//
// Mechanisms for DSA
//
// Routines contained within:

#include <pthread.h>
#include <string.h>            // for memcmp() et al
#include <stdlib.h>

#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
//#include "tok_spec_struct.h"



//
//
CK_RV
dsa_sign( SESSION             * sess,
          CK_BBOOL              length_only,
          SIGN_VERIFY_CONTEXT * ctx,
          CK_BYTE             * in_data,
          CK_ULONG              in_data_len,
          CK_BYTE             * out_data,
          CK_ULONG            * out_data_len )
{
   OBJECT          *key_obj   = NULL;
   CK_ATTRIBUTE    *attr      = NULL;
   CK_BYTE          sig[DSA_SIGNATURE_SIZE];
   CK_OBJECT_CLASS  class;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(118, __FILE__, __LINE__);
      return rc;
   }
   // must be a PRIVATE key operation
   //
   flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (flag == FALSE){
      st_err_log(118, __FILE__, __LINE__);
      return CKR_FUNCTION_FAILED;
   }
   else
      class = *(CK_OBJECT_CLASS *)attr->pValue;

   // if it's not a private DSA key then we have an internal failure...means
   // that somehow a public key got assigned a CKA_SIGN attribute
   //
   if (class != CKO_PRIVATE_KEY){
      st_err_log(118, __FILE__, __LINE__);
      return CKR_FUNCTION_FAILED;
   }

   // check input data length restrictions.  Generic DSA works on the SHA-1
   // hash of the data so the input to the DSA operation must be 20 bytes
   //
   if (in_data_len != 20){
      st_err_log(109, __FILE__, __LINE__);
      return CKR_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = DSA_SIGNATURE_SIZE;
      return CKR_OK;
   }

   rc = ckm_dsa_sign( in_data, sig, key_obj );
   if (rc == CKR_OK) {
      memcpy( out_data, sig, DSA_SIGNATURE_SIZE );
      *out_data_len = DSA_SIGNATURE_SIZE;
   }

   return rc;
}


//
//
CK_RV
dsa_verify( SESSION             * sess,
            SIGN_VERIFY_CONTEXT * ctx,
            CK_BYTE             * in_data,
            CK_ULONG              in_data_len,
            CK_BYTE             * signature,
            CK_ULONG              sig_len )
{
   OBJECT          *key_obj  = NULL;
   CK_ATTRIBUTE    *attr     = NULL;
   CK_OBJECT_CLASS  class;
   CK_BBOOL         flag;
   CK_RV            rc;


   rc = object_mgr_find_in_map1( ctx->key, &key_obj );
   if (rc != CKR_OK){
      st_err_log(118, __FILE__, __LINE__);
      return rc;
   }
   // must be a PUBLIC key operation
   //
   flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (flag == FALSE){
      st_err_log(118, __FILE__, __LINE__);
      return CKR_FUNCTION_FAILED;
   }
   else
      class = *(CK_OBJECT_CLASS *)attr->pValue;

   if (class != CKO_PUBLIC_KEY){
      st_err_log(118, __FILE__, __LINE__);
      return CKR_FUNCTION_FAILED;
   }

   // check input data length restrictions
   //
   if (sig_len != DSA_SIGNATURE_SIZE){
      st_err_log(46, __FILE__, __LINE__);
      return CKR_SIGNATURE_LEN_RANGE;
   }
   if (in_data_len != 20){
      st_err_log(109, __FILE__, __LINE__);
      return CKR_DATA_LEN_RANGE;
   }
   rc = ckm_dsa_verify( signature, in_data, key_obj );
   if (rc != CKR_OK)
      st_err_log(121, __FILE__, __LINE__);
   return rc;
}


//
// mechanisms
//


//
//
CK_RV
ckm_dsa_key_pair_gen( TEMPLATE  * publ_tmpl,
                      TEMPLATE  * priv_tmpl )
{
   CK_ATTRIBUTE       * prime     = NULL;
   CK_ATTRIBUTE       * subprime  = NULL;
   CK_ATTRIBUTE       * base      = NULL;
   CK_ATTRIBUTE       * priv_exp  = NULL;
   CK_ATTRIBUTE       * publ_exp  = NULL;
   CK_ATTRIBUTE       * attr      = NULL;
   CK_BYTE            * ptr       = NULL;
   CK_BYTE              repl_buf[5500];
   CK_ULONG             req_len, repl_len;
   CK_BBOOL             flag;
   CK_RV                rc;


   rc = token_specific_dsa_generate_keypair(publ_tmpl,priv_tmpl);
   if (rc != CKR_OK)
      st_err_log(91, __FILE__, __LINE__);
   return rc;
}


//
//
CK_RV
ckm_dsa_sign( CK_BYTE   * in_data,
              CK_BYTE   * signature,
              OBJECT    * priv_key )
{
   CK_ATTRIBUTE     * prime     = NULL;
   CK_ATTRIBUTE     * subprime  = NULL;
   CK_ATTRIBUTE     * base      = NULL;
   CK_ATTRIBUTE     * exponent  = NULL;
   CK_ATTRIBUTE     * attr      = NULL;
   CK_BYTE          * ptr       = NULL;
   CK_ULONG           req_len, repl_len, keylen;
   CK_OBJECT_CLASS    keyclass;
   CK_RV              rc;

   rc = template_attribute_find( priv_key->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      st_err_log(118, __FILE__, __LINE__);
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a private key
   //
   if (keyclass != CKO_PRIVATE_KEY){
      st_err_log(118, __FILE__, __LINE__);
      return CKR_FUNCTION_FAILED;
   }

   rc = tok_dsa_sign(in_data, signature, priv_key);
   if (rc != CKR_OK)
      st_err_log(122, __FILE__, __LINE__);
   return rc;
}


//
//
CK_RV
ckm_dsa_verify( CK_BYTE   * signature,
                CK_BYTE   * data,
                OBJECT    * publ_key )
{
   CK_ATTRIBUTE     * prime     = NULL;
   CK_ATTRIBUTE     * subprime  = NULL;
   CK_ATTRIBUTE     * base      = NULL;
   CK_ATTRIBUTE     * exponent  = NULL;
   CK_ATTRIBUTE     * attr      = NULL;
   CK_BYTE          * ptr       = NULL;
   CK_ULONG           req_len, repl_len, keylen;
   CK_OBJECT_CLASS    keyclass;
   CK_RV              rc;

   rc = template_attribute_find( publ_key->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      st_err_log(118, __FILE__, __LINE__);
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a private key
   //
   if (keyclass != CKO_PUBLIC_KEY){
      st_err_log(118, __FILE__, __LINE__);
      return CKR_FUNCTION_FAILED;
   }
   rc = tok_dsa_verify( signature, data, publ_key);
   if (rc != CKR_OK)
      st_err_log(121, __FILE__, __LINE__);
   return rc;
}

