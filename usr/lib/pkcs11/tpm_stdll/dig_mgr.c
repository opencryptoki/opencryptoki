
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


// File:  dig_mgr.c
//
// Digest manager routines
//

//#include <windows.h>

#include <pthread.h>
  #include <string.h>            // for memcmp() et al
  #include <stdlib.h>


#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
//#include "args.h"


//
//
CK_RV
digest_mgr_init( SESSION           *sess,
                 DIGEST_CONTEXT    *ctx,
                 CK_MECHANISM      *mech )
{
   CK_BYTE  * ptr = NULL;


   if (!sess || !ctx){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active != FALSE){
      st_err_log(31, __FILE__, __LINE__);     
      return CKR_OPERATION_ACTIVE;
   }

   // is the mechanism supported?  is the parameter present if required?
   //
   switch (mech->mechanism) {
      case CKM_SHA_1:
         {
            if (mech->ulParameterLen != 0){
               st_err_log(29, __FILE__, __LINE__);     
               return CKR_MECHANISM_PARAM_INVALID;
            }
	    
            ctx->context = NULL;
            ckm_sha1_init( ctx );
	    
            if (!ctx->context) {
               st_err_log(1, __FILE__, __LINE__);     
               return CKR_HOST_MEMORY;
            }
         }
         break;

      case CKM_MD2:
         {
            if (mech->ulParameterLen != 0){
               st_err_log(29, __FILE__, __LINE__);     
               return CKR_MECHANISM_PARAM_INVALID;
            }
            ctx->context_len = sizeof(MD2_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(MD2_CONTEXT));
            if (!ctx->context){
               st_err_log(1, __FILE__, __LINE__);     
               return CKR_HOST_MEMORY;
            }
            memset( ctx->context, 0x0, sizeof(MD2_CONTEXT) );
         }
         break;

      case CKM_MD5:
         {
            if (mech->ulParameterLen != 0){
               st_err_log(29, __FILE__, __LINE__);     
               return CKR_MECHANISM_PARAM_INVALID;
            }
            ctx->context_len = sizeof(MD5_CONTEXT);
            ctx->context     = (CK_BYTE *)malloc(sizeof(MD5_CONTEXT));
            if (!ctx->context){
               st_err_log(1, __FILE__, __LINE__);     
               return CKR_HOST_MEMORY;
            }
            ckm_md5_init( (MD5_CONTEXT *)ctx->context );
         }
         break;

      default:
         st_err_log(28, __FILE__, __LINE__);     
         return CKR_MECHANISM_INVALID;
   }


   if (mech->ulParameterLen > 0) {
      ptr = (CK_BYTE *)malloc(mech->ulParameterLen);
      if (!ptr){
         st_err_log(1, __FILE__, __LINE__);     
         return CKR_HOST_MEMORY;
      }
      memcpy( ptr, mech->pParameter, mech->ulParameterLen );
   }

   ctx->mech.ulParameterLen = mech->ulParameterLen;
   ctx->mech.mechanism      = mech->mechanism;
   ctx->mech.pParameter     = ptr;
   ctx->multi               = FALSE;
   ctx->active              = TRUE;

   return CKR_OK;
}


//
//
CK_RV
digest_mgr_cleanup( DIGEST_CONTEXT *ctx )
{
   if (!ctx){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   ctx->mech.ulParameterLen = 0;
   ctx->mech.mechanism      = 0;
   ctx->multi               = FALSE;
   ctx->active              = FALSE;
   ctx->context_len         = 0;

   if (ctx->mech.pParameter) {
      free( ctx->mech.pParameter );
      ctx->mech.pParameter = NULL;
   }

   if (ctx->context != NULL) {
      free( ctx->context );
      ctx->context = NULL;
   }

   return CKR_OK;
}



//
//
CK_RV
digest_mgr_digest( SESSION         *sess,
                   CK_BBOOL         length_only,
                   DIGEST_CONTEXT  *ctx,
                   CK_BYTE         *in_data,
                   CK_ULONG         in_data_len,
                   CK_BYTE         *out_data,
                   CK_ULONG        *out_data_len )
{

   if (!sess || !ctx){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      st_err_log(32, __FILE__, __LINE__);
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   // if the caller just wants the encrypted length, there is no reason to
   // specify the input data.  I just need the data length
   //
   if ((length_only == FALSE) && (!in_data || !out_data)){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   if (ctx->multi == TRUE){
      st_err_log(31, __FILE__, __LINE__);
      return CKR_OPERATION_ACTIVE;
   }
   switch (ctx->mech.mechanism) {
      case CKM_SHA_1:
         return sha1_hash( sess,      length_only, ctx,
                           in_data,   in_data_len,
                           out_data,  out_data_len );

#if !(NOMD2 )
      case CKM_MD2:
         return md2_hash( sess,     length_only, ctx,
                          in_data,  in_data_len,
                          out_data, out_data_len );
#endif

      case CKM_MD5:
         return md5_hash( sess,     length_only, ctx,
                          in_data,  in_data_len,
                          out_data, out_data_len );

      default:
         st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
         return CKR_FUNCTION_FAILED;  // shouldn't happen
   }

   st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
digest_mgr_digest_update( SESSION         *sess,
                          DIGEST_CONTEXT  *ctx,
                          CK_BYTE         *data,
                          CK_ULONG         data_len )
{
   if (!sess || !ctx){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      st_err_log(32, __FILE__, __LINE__);
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   ctx->multi = TRUE;

   switch (ctx->mech.mechanism) {
      case CKM_SHA_1:
         return sha1_hash_update( sess, ctx, data, data_len );

#if !(NOMD2)
      case CKM_MD2:
         return md2_hash_update( sess, ctx, data, data_len );
#endif

      case CKM_MD5:
         return md5_hash_update( sess, ctx, data, data_len );

      default:
         st_err_log(28, __FILE__, __LINE__);
         return CKR_MECHANISM_INVALID;
   }

   st_err_log(28, __FILE__, __LINE__);
   return CKR_MECHANISM_INVALID;  // shouldn't happen!
}


//
//
CK_RV
digest_mgr_digest_key( SESSION          * sess,
                       DIGEST_CONTEXT   * ctx,
                       CK_OBJECT_HANDLE   key_handle )
{
   CK_ATTRIBUTE    * attr     = NULL;
   OBJECT          * key_obj  = NULL;
   CK_OBJECT_CLASS   class;
   CK_RV             rc;


   if (!sess || !ctx){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   rc = object_mgr_find_in_map1( key_handle, &key_obj );
   if (rc != CKR_OK){
      st_err_log(18, __FILE__, __LINE__);
      return CKR_KEY_HANDLE_INVALID;
   }
   // only allow digesting of CKO_SECRET keys
   //
   rc = template_attribute_find( key_obj->template, CKA_CLASS, &attr );
   if (rc == FALSE) {
      st_err_log(24, __FILE__, __LINE__);
      return CKR_KEY_INDIGESTIBLE;
   }
   else
      class = *(CK_OBJECT_CLASS *)attr->pValue;

   if (class != CKO_SECRET_KEY){
      st_err_log(24, __FILE__, __LINE__);
      return CKR_KEY_INDIGESTIBLE;
   }

   // every secret key has a CKA_VALUE attribute
   //
   rc = template_attribute_find( key_obj->template, CKA_VALUE, &attr );
   if (!rc){
      st_err_log(24, __FILE__, __LINE__);
      return CKR_KEY_INDIGESTIBLE;
   }
   rc = digest_mgr_digest_update( sess,
                                  ctx,
                                  attr->pValue,
                                  attr->ulValueLen );
   if (rc != CKR_OK){
      st_err_log(24, __FILE__, __LINE__);
   } 
   return rc;
}


//
//
CK_RV
digest_mgr_digest_final( SESSION         *sess,
                         CK_BBOOL         length_only,
                         DIGEST_CONTEXT  *ctx,
                         CK_BYTE         *hash,
                         CK_ULONG        *hash_len )
{
   if (!sess || !ctx){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   if (ctx->active == FALSE){
      st_err_log(32, __FILE__, __LINE__);
      return CKR_OPERATION_NOT_INITIALIZED;
   }

   /* XXX KEY - Turn off the multi flag to tell the next layer that this
    * is the final part of a multi part operation.
    */
   ctx->multi = FALSE;
   
   switch (ctx->mech.mechanism) {
      case CKM_SHA_1:
         return sha1_hash_final( sess, length_only,
                                 ctx,
                                 hash, hash_len );

#if !(NOMD2)
      case CKM_MD2:
         return md2_hash_final( sess, length_only,
                                ctx,
                                hash, hash_len );
#endif

      case CKM_MD5:
         return md5_hash_final( sess, length_only,
                                ctx,
                                hash, hash_len );

      default:
         st_err_log(28, __FILE__, __LINE__);
         return CKR_MECHANISM_INVALID;   // shouldn't happen
   }

   st_err_log(28, __FILE__, __LINE__);
   return CKR_MECHANISM_INVALID;
}
