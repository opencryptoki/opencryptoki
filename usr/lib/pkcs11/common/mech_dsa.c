/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  mech_dsa.c
//
// Mechanisms for DSA
//
// Routines contained within:

#include <pthread.h>
#include <string.h>            // for memcmp() et al
#include <stdlib.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"


//
//
CK_RV
dsa_sign( STDLL_TokData_t     * tokdata,
	  SESSION             * sess,
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


   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
   if (rc != CKR_OK) {
      TRACE_ERROR("Failed to acquire key from specified handle");
      if (rc == CKR_OBJECT_HANDLE_INVALID)
          return CKR_KEY_HANDLE_INVALID;
      else
        return rc;
   }

   // must be a PRIVATE key operation
   //
   flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (flag == FALSE){
      TRACE_ERROR("Could not find <the_attribute_name> in the template\n");
      return CKR_FUNCTION_FAILED;
   }
   else
      class = *(CK_OBJECT_CLASS *)attr->pValue;

   // if it's not a private DSA key then we have an internal failure...means
   // that somehow a public key got assigned a CKA_SIGN attribute
   //
   if (class != CKO_PRIVATE_KEY){
      TRACE_ERROR("This operation requires a private key.\n");
      return CKR_KEY_FUNCTION_NOT_PERMITTED;
   }

   // check input data length restrictions.  Generic DSA works on the SHA-1
   // hash of the data so the input to the DSA operation must be 20 bytes
   //
   if (in_data_len != 20){
      TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
      return CKR_DATA_LEN_RANGE;
   }
   if (length_only == TRUE) {
      *out_data_len = DSA_SIGNATURE_SIZE;
      return CKR_OK;
   }

   rc = ckm_dsa_sign( tokdata, in_data, sig, key_obj );
   if (rc == CKR_OK) {
      memcpy( out_data, sig, DSA_SIGNATURE_SIZE );
      *out_data_len = DSA_SIGNATURE_SIZE;
   }

   return rc;
}


//
//
CK_RV
dsa_verify( STDLL_TokData_t     * tokdata,
	    SESSION             * sess,
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


   rc = object_mgr_find_in_map1( tokdata, ctx->key, &key_obj );
   if (rc != CKR_OK) {
      TRACE_ERROR("Failed to acquire key from specified handle");
      if (rc == CKR_OBJECT_HANDLE_INVALID)
          return CKR_KEY_HANDLE_INVALID;
      else
        return rc;
   }

   // must be a PUBLIC key operation
   //
   flag = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (flag == FALSE){
      TRACE_ERROR("Could not find CKA_CLASS in the template\n");
      return CKR_FUNCTION_FAILED;
   }
   else
      class = *(CK_OBJECT_CLASS *)attr->pValue;

   if (class != CKO_PUBLIC_KEY){
      TRACE_ERROR("This operation requires a public key.\n");
      return CKR_KEY_FUNCTION_NOT_PERMITTED;
   }

   // check input data length restrictions
   //
   if (sig_len != DSA_SIGNATURE_SIZE){
      TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
      return CKR_SIGNATURE_LEN_RANGE;
   }
   if (in_data_len != 20){
      TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
      return CKR_DATA_LEN_RANGE;
   }
   rc = ckm_dsa_verify( tokdata, signature, in_data, key_obj );
   return rc;
}


//
// mechanisms
//


//
//
CK_RV
ckm_dsa_key_pair_gen( STDLL_TokData_t *tokdata,
		      TEMPLATE  * publ_tmpl,
                      TEMPLATE  * priv_tmpl )
{
   CK_RV                rc;


   if (token_specific.t_dsa_generate_keypair == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
      return CKR_MECHANISM_INVALID;
   }

   rc = token_specific.t_dsa_generate_keypair(tokdata, publ_tmpl,priv_tmpl);
   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific dsa keypair generation failed.\n");
   return rc;
}


//
//
CK_RV
ckm_dsa_sign( STDLL_TokData_t *tokdata,
	      CK_BYTE   * in_data,
              CK_BYTE   * signature,
              OBJECT    * priv_key )
{
   CK_ATTRIBUTE     * attr      = NULL;
   CK_OBJECT_CLASS    keyclass;
   CK_RV              rc;

   rc = template_attribute_find( priv_key->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      TRACE_ERROR("Could not find CKA_CLASS in the template\n");
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a private key
   //
   if (keyclass != CKO_PRIVATE_KEY){
      TRACE_ERROR("This operation requires a private key.\n");
      return CKR_KEY_FUNCTION_NOT_PERMITTED;
   }

   if (token_specific.t_dsa_sign == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
      return CKR_MECHANISM_INVALID;
   }

   rc = token_specific.t_dsa_sign(tokdata, in_data, signature, priv_key);
   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific dsa sign failed.\n");
   return rc;
}


//
//
CK_RV
ckm_dsa_verify( STDLL_TokData_t *tokdata,
		CK_BYTE   * signature,
                CK_BYTE   * data,
                OBJECT    * publ_key )
{
   CK_ATTRIBUTE     * attr      = NULL;
   CK_OBJECT_CLASS    keyclass;
   CK_RV              rc;

   rc = template_attribute_find( publ_key->template, CKA_CLASS, &attr );
   if (rc == FALSE){
      TRACE_ERROR("Could not find CKA_CLASS in the template\n");
      return CKR_FUNCTION_FAILED;
   }
   else
      keyclass = *(CK_OBJECT_CLASS *)attr->pValue;

   // this had better be a private key
   //
   if (keyclass != CKO_PUBLIC_KEY){
      TRACE_ERROR("This operation requires a public key.\n");
      return CKR_KEY_FUNCTION_NOT_PERMITTED;
   }

   if (token_specific.t_dsa_verify == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
      return CKR_MECHANISM_INVALID;
   }
   rc = token_specific.t_dsa_verify(tokdata, signature, data, publ_key);
   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific dsa verify failed.\n");
   return rc;
}
