/*
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/************************************************************************
*                                                                       *
*      Copyright:       Corrent Corporation (c) 2000-2003               *
*                                                                       *
*      Filename:        mech_dh.c                                       *
*      Created By:      Kapil Sood                                      *
*      Created On:      Jan 18, 2003                                    *
*      Description:     This is the file implementing Diffie-Hellman    *
*                       key pair generation and shared key derivation   *
*                       operations.                                     *
*                                                                       *
************************************************************************/

// File:  mech_dh.c
//
// Mechanisms for DH
//
// Routines contained within:

#include <pthread.h>
#include <string.h>            // for memcmp() et al
#include <stdlib.h>
#include <sys/syslog.h>
#include <stdio.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"

#ifndef NODH

//
//
CK_RV
dh_pkcs_derive( STDLL_TokData_t   * tokdata,
		SESSION           * sess,
                CK_MECHANISM      * mech,
                CK_OBJECT_HANDLE    base_key,
                CK_ATTRIBUTE      * pTemplate,
                CK_ULONG            ulCount,
                CK_OBJECT_HANDLE  * handle )
{
   CK_RV		rc;
   CK_ULONG		i, keyclass = 0, keytype = 0 ;
   CK_ATTRIBUTE         *new_attr ;
   OBJECT               *temp_obj = NULL;

   CK_BYTE             secret_key_value[256] ;
   CK_ULONG            secret_key_value_len = 256 ;

   // Prelim checking of sess, mech, pTemplate, and ulCount was
   // done in the calling function (key_mgr_derive_key).

   // Perform DH checking of parameters
   // Check the existance of the public-value in mechanism
   if ((!mech->pParameter) ||
       ((mech->ulParameterLen != 64) &&
        (mech->ulParameterLen != 96) &&
        (mech->ulParameterLen != 128) &&
        (mech->ulParameterLen != 192) &&
        (mech->ulParameterLen != 256))) {
     TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
      return(CKR_MECHANISM_PARAM_INVALID) ;
   }

   // Check valid object handle pointer of derived key
   if (handle == NULL) {
      TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
      return CKR_KEY_HANDLE_INVALID;
   }

   // Extract the object class and keytype from the supplied template.
      for (i=0; i < ulCount; i++) {
         if (pTemplate[i].type == CKA_CLASS) {
            keyclass = *(CK_OBJECT_CLASS *)pTemplate[i].pValue;
            if (keyclass != CKO_SECRET_KEY) {
	       TRACE_ERROR("This operation requires a secret key.\n");
               return CKR_KEY_FUNCTION_NOT_PERMITTED;
            }
         }

         if (pTemplate[i].type == CKA_KEY_TYPE)
            keytype = *(CK_ULONG *)pTemplate[i].pValue;
      }

   // Extract public-key from mechanism parameters. base-key contains the
   // private key, prime, and base. The return value will be in the handle.

   rc = ckm_dh_pkcs_derive( tokdata, mech->pParameter, mech->ulParameterLen,
                            base_key, secret_key_value, &secret_key_value_len );
   if (rc != CKR_OK)
      return rc;

   // Build the attribute from the vales that were returned back
   rc = build_attribute( CKA_VALUE, secret_key_value, secret_key_value_len, &new_attr );
   if (rc != CKR_OK) {
      TRACE_DEVEL("Failed to build the new attribute.\n");
      return rc ;
   }

   // Create the object that will be passed back as a handle. This will
   // contain the new (computed) value of the attribute.

   rc = object_mgr_create_skel( tokdata, sess,
                                pTemplate,       ulCount,
                                MODE_KEYGEN,
                                keyclass,  keytype,
                                &temp_obj );
   if (rc != CKR_OK){
      TRACE_DEVEL("Object Mgr create skeleton failed.\n");
      free(new_attr);
      return rc;
   }

   // Update the template in the object with the new attribute
   template_update_attribute( temp_obj->template, new_attr );

   // at this point, the derived key is fully constructed...assign an
   // object handle and store the key
   //
   rc = object_mgr_create_final( tokdata, sess, temp_obj, handle );
   if (rc != CKR_OK) {
      TRACE_DEVEL("Object Mgr create final failed.\n");
      object_free( temp_obj );
      return rc;
   }

   return rc;
}

//
// mechanisms
//

//
//
CK_RV
ckm_dh_pkcs_derive( STDLL_TokData_t   *tokdata,
		    CK_VOID_PTR        other_pubkey,
                    CK_ULONG           other_pubkey_len,
                    CK_OBJECT_HANDLE   base_key,
                    CK_BYTE            *secret_value,
                    CK_ULONG           *secret_value_len )
{
   CK_RV          rc;
   CK_BYTE        p[256] ;
   CK_ULONG       p_len ;
   CK_BYTE        x[256] ;
   CK_ULONG       x_len ;
   CK_ATTRIBUTE   *temp_attr ;
   OBJECT         *base_key_obj = NULL ;
   CK_BYTE        *p_other_pubkey ;

   rc = object_mgr_find_in_map1( tokdata, base_key, &base_key_obj );
   if (rc != CKR_OK){
      TRACE_ERROR("Failed to acquire key from specified handle");
      if (rc == CKR_OBJECT_HANDLE_INVALID)
	 return CKR_KEY_HANDLE_INVALID;
      else
	 return rc;
   }

   // Extract secret (x) from base_key
   rc = template_attribute_find( base_key_obj->template, CKA_VALUE, &temp_attr );
   if (rc == FALSE) {
      TRACE_ERROR("Could not find CKA_VALUE in the template\n");
      return CKR_FUNCTION_FAILED;
   }
   else
   {
      memset(x, 0, sizeof(x)) ;
      x_len = temp_attr->ulValueLen ;
      memcpy(x, (CK_BYTE *)temp_attr->pValue, x_len) ;
   }

   // Extract prime (p) from base_key
   rc = template_attribute_find( base_key_obj->template, CKA_PRIME, &temp_attr );
   if (rc == FALSE) {
      TRACE_ERROR("Could not find CKA_PRIME in the template\n");
      return CKR_FUNCTION_FAILED;
   }
   else
   {
      memset(p, 0, sizeof(p)) ;
      p_len = temp_attr->ulValueLen ;
      memcpy(p, (CK_BYTE *)temp_attr->pValue, p_len) ;
   }

   p_other_pubkey = (CK_BYTE *) other_pubkey ;

   // Perform: z = other_pubkey^x mod p
   rc = token_specific.t_dh_pkcs_derive(tokdata, secret_value, secret_value_len,
					p_other_pubkey, other_pubkey_len, x,
					x_len, p, p_len );
   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific dh pkcs derive failed.\n");

   return rc;
}

//
//
CK_RV
ckm_dh_pkcs_key_pair_gen( STDLL_TokData_t *tokdata,
			  TEMPLATE  * publ_tmpl,
                          TEMPLATE  * priv_tmpl )
{
   CK_RV                rc;

   rc = token_specific.t_dh_pkcs_key_pair_gen(tokdata, publ_tmpl,priv_tmpl);
   if (rc != CKR_OK)
      TRACE_DEVEL("Token specific dh pkcs key pair gen failed.\n");

   return rc;
}

#endif
