
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


// File:  session.c
//
// Session manager related functions
//

//#include <windows.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>  // for memcmp() et al

#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"


// session_mgr_find()
//
// search for the specified session.  returning a pointer to the session
// is dangerous
//
// Returns:  SESSION * or NULL
//
SESSION *
session_mgr_find( CK_SESSION_HANDLE handle )
{
   DL_NODE  * node   = NULL;
   SESSION  * result = NULL;
   CK_RV      rc;

   rc = MY_LockMutex( &sess_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return NULL;
   }
   node = sess_list;

   while (node) {
      SESSION *s = (SESSION *)node->data;

      if (s->handle == handle) {
         result = s;
         break;
      }

      node = node->next;
   }

   MY_UnlockMutex( &sess_list_mutex );
   return result;
}


// session_mgr_new()
//
// creates a new session structure and adds it to the process's list
// of sessions
//
// Args:  CK_ULONG      flags : session flags                   (INPUT)
//        SESSION **     sess : new session pointer             (OUTPUT)
//
// Returns:  CK_RV
//
CK_RV
session_mgr_new( CK_ULONG flags, SESSION **sess )
{
   SESSION  * new_session  = NULL;
   SESSION  * s            = NULL;
   DL_NODE  * node         = NULL;
   CK_BBOOL   user_session = FALSE;
   CK_BBOOL   so_session   = FALSE;
   CK_BBOOL   pkcs_locked  = TRUE;
   CK_BBOOL   sess_locked  = TRUE;
   CK_RV      rc;


   new_session = (SESSION *)malloc(sizeof(SESSION));
   if (!new_session) {
      st_err_log(0, __FILE__, __LINE__);
      rc = CKR_HOST_MEMORY;
      goto done;
   }

   memset( new_session, 0x0, sizeof(SESSION) );

   // find an unused session handle.  session handles will wrap
   // automatically...
   //

   rc = MY_LockMutex( &pkcs_mutex );      // this protects next_session_handle
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   pkcs_locked = TRUE;

   do {
      s = session_mgr_find( next_session_handle );
      if (s != NULL)
         next_session_handle++;
      else
         new_session->handle = next_session_handle++;
   } while (s != NULL);

   MY_UnlockMutex( &pkcs_mutex );
   pkcs_locked = FALSE;


   new_session->session_info.slotID        = 1;
   new_session->session_info.flags         = flags;
   new_session->session_info.ulDeviceError = 0;

   rc = MY_LockMutex( &sess_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   sess_locked = TRUE;

   // determine the login/logout status of the new session.  PKCS 11 requires
   // that all sessions belonging to a process have the same login/logout status
   //
   node = sess_list;
   while (node) {
      SESSION *s = (SESSION *)node->data;
      if (s->session_info.state == CKS_RW_SO_FUNCTIONS) {
         so_session = TRUE;
         break;
      }

      if ((s->session_info.state == CKS_RO_USER_FUNCTIONS) ||
          (s->session_info.state == CKS_RW_USER_FUNCTIONS))
      {
         user_session = TRUE;
         break;
      }

      node = node->next;
   }

// SAB XXX login does not drop after all sessions are closed XXX
   if ( global_login_state == CKS_RW_SO_FUNCTIONS) {
  	so_session = TRUE;
   }
   if ((global_login_state == CKS_RO_USER_FUNCTIONS) ||
       (global_login_state == CKS_RW_USER_FUNCTIONS)) {
	user_session = TRUE;
   }

// END SAB login state carry

   // we don't have to worry about having a user and SO session at the same time.
   // that is prevented in the login routine
   //
   if (user_session) {
      if (new_session->session_info.flags & CKF_RW_SESSION)
         new_session->session_info.state = CKS_RW_USER_FUNCTIONS;
      else
         new_session->session_info.state = CKS_RO_USER_FUNCTIONS;
   }
   else if (so_session) {
      new_session->session_info.state = CKS_RW_SO_FUNCTIONS;
   }
   else {
      if (new_session->session_info.flags & CKF_RW_SESSION)
         new_session->session_info.state = CKS_RW_PUBLIC_SESSION;
      else
         new_session->session_info.state = CKS_RO_PUBLIC_SESSION;
   }

   sess_list = dlist_add_as_first( sess_list, new_session );
   *sess = new_session;

done:
   if (pkcs_locked)
      MY_UnlockMutex( &pkcs_mutex );

   if (sess_locked)
      MY_UnlockMutex( &sess_list_mutex );

   if (rc != CKR_OK && new_session != NULL){
      st_err_log(147, __FILE__, __LINE__); 
      free( new_session );
   }
   return rc;
}


// session_mgr_so_session_exists()
//
// determines whether a RW_SO session exists for the specified process
//
// Returns:  TRUE or FALSE
//
CK_BBOOL
session_mgr_so_session_exists( void )
{
   DL_NODE *node = NULL;
   CK_RV    rc;

   rc = MY_LockMutex( &sess_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   node = sess_list;
   while (node) {
      SESSION *s = (SESSION *)node->data;
      if (s->session_info.state == CKS_RW_SO_FUNCTIONS) {
         rc = TRUE;
         goto done;
      }

      node = node->next;
   }

   rc = FALSE;

done:
   MY_UnlockMutex( &sess_list_mutex );
   return rc;
}


// session_mgr_user_session_exists()
//
// determines whether a USER session exists for the specified process
//
// Returns:  TRUE or FALSE
//
CK_BBOOL
session_mgr_user_session_exists( void )
{
   DL_NODE *node = NULL;
   CK_RV    rc;

   rc = MY_LockMutex( &sess_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   node = sess_list;
   while (node) {
      SESSION *s = (SESSION *)node->data;
      if ((s->session_info.state == CKS_RO_USER_FUNCTIONS) ||
          (s->session_info.state == CKS_RW_USER_FUNCTIONS))
      {
         rc = TRUE;
         goto done;
      }

      node = node->next;
   }

   rc = FALSE;

done:
   MY_UnlockMutex( &sess_list_mutex );
   return rc;
}


// session_mgr_public_session_exists()
//
// determines whether a PUBLIC session exists for the specified process
//
// Returns:  TRUE or FALSE
//
CK_BBOOL
session_mgr_public_session_exists( void )
{
   DL_NODE *node = NULL;
   CK_RV    rc;

   rc = MY_LockMutex( &sess_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   node = sess_list;
   while (node) {
      SESSION *s = (SESSION *)node->data;
      if ((s->session_info.state == CKS_RO_PUBLIC_SESSION) ||
          (s->session_info.state == CKS_RW_PUBLIC_SESSION))
      {
          rc = TRUE;
          goto done;
      }

      node = node->next;
   }

   rc = FALSE;

done:
   MY_UnlockMutex( &sess_list_mutex );
   return rc;
}


// session_mgr_readonly_exists()
//
// determines whether the specified process owns any read-only sessions.  this is useful
// because the SO cannot log in if a read-only session exists.
//
CK_BBOOL
session_mgr_readonly_exists( void )
{
   DL_NODE *node = NULL;
   CK_RV    rc;

   rc = MY_LockMutex( &sess_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   node = sess_list;
   while (node) {
      SESSION *s = (SESSION *)node->data;
      if ((s->session_info.flags & CKF_RW_SESSION) == 0) {
         rc = TRUE;
         goto done;
      }

      node = node->next;
   }

   rc = FALSE;

done:
   MY_UnlockMutex( &sess_list_mutex );
   return rc;
}


// session_mgr_close_session()
//
// removes the specified session from the process' session list
//
// Args:   PROCESS *    proc  :  parent process
//         SESSION * session  :  session to remove
//
// Returns:  TRUE on success else FALSE
//
CK_RV
session_mgr_close_session( SESSION *sess )
{
   DL_NODE  * node = NULL;
   CK_RV      rc = CKR_OK;

   if (!sess)
      return FALSE;

   rc = MY_LockMutex( &sess_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return CKR_FUNCTION_FAILED;
   }
   node = dlist_find( sess_list, sess );
   if (!node) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   object_mgr_purge_session_objects( sess, ALL );

   if (sess->find_list)
      free( sess->find_list );

   if (sess->encr_ctx.context)
      free( sess->encr_ctx.context );

   if (sess->encr_ctx.mech.pParameter)
      free( sess->encr_ctx.mech.pParameter );

   if (sess->decr_ctx.context)
      free( sess->decr_ctx.context );

   if (sess->decr_ctx.mech.pParameter)
      free( sess->decr_ctx.mech.pParameter );

   if (sess->digest_ctx.context)
      free( sess->digest_ctx.context );

   if (sess->digest_ctx.mech.pParameter)
      free( sess->digest_ctx.mech.pParameter );

   if (sess->sign_ctx.context)
      free( sess->sign_ctx.context );

   if (sess->sign_ctx.mech.pParameter)
      free( sess->sign_ctx.mech.pParameter );

   if (sess->verify_ctx.context)
      free( sess->verify_ctx.context );

   if (sess->verify_ctx.mech.pParameter)
      free( sess->verify_ctx.mech.pParameter );

   free( sess );

   sess_list = dlist_remove_node( sess_list, node );

   // XXX XXX  Not having this is a problem
   //  for IHS.  The spec states that there is an implicit logout
   //  when the last session is closed.  Cannonicaly this is what other
   //  implementaitons do.  however on linux for some reason IHS can't seem 
   //  to keep the session open, which means that they go through the login
   //  path EVERY time, which of course causes a reload of the private 
   //  objects EVERY time.   If we are logged out, we MUST purge the private
   //  objects from this process..  
   //
   if (sess_list == NULL) {
	// SAB  XXX  if all sessions are closed.  Is this effectivly logging out
	   object_mgr_purge_private_token_objects();
   
		global_login_state = 0;
      // The objects really need to be purged .. but this impacts the
      // performance under linux.   So we need to make sure that the 
      // login state is valid.    I don't really like this.
    	MY_LockMutex( &obj_list_mutex );
   	object_mgr_purge_map((SESSION *)0xFFFF, PRIVATE);
     	MY_UnlockMutex( &obj_list_mutex );
   }

done:
   MY_UnlockMutex( &sess_list_mutex );
   return rc;
}


// session_mgr_close_all_sessions()
//
// removes all sessions from the specified process
//
CK_RV
session_mgr_close_all_sessions( void )
{
   CK_RV   rc = CKR_OK;

   rc = MY_LockMutex( &sess_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return CKR_FUNCTION_FAILED;
   }
   while (sess_list) {
      SESSION *sess = (SESSION *)sess_list->data;

      object_mgr_purge_session_objects( sess, ALL );

      if (sess->find_list)
         free( sess->find_list );

      if (sess->encr_ctx.context)
         free( sess->encr_ctx.context );

      if (sess->encr_ctx.mech.pParameter)
         free( sess->encr_ctx.mech.pParameter);

      if (sess->decr_ctx.context)
         free( sess->decr_ctx.context );

      if (sess->decr_ctx.mech.pParameter)
         free( sess->decr_ctx.mech.pParameter);

      if (sess->digest_ctx.context)
         free( sess->digest_ctx.context );

      if (sess->digest_ctx.mech.pParameter)
         free( sess->digest_ctx.mech.pParameter);

      if (sess->sign_ctx.context)
         free( sess->sign_ctx.context );

      if (sess->sign_ctx.mech.pParameter)
         free( sess->sign_ctx.mech.pParameter);

      if (sess->verify_ctx.context)
         free( sess->verify_ctx.context );

      if (sess->verify_ctx.mech.pParameter)
         free( sess->verify_ctx.mech.pParameter);

      free( sess );

      sess_list = dlist_remove_node( sess_list, sess_list );
   }

   MY_UnlockMutex( &sess_list_mutex );
   return CKR_OK;
}


// session_mgr_login_all()
//
// changes the login status of all sessions in the token
//
// Arg:  CK_USER_TYPE  user_type : USER or SO
//
CK_RV
session_mgr_login_all( CK_USER_TYPE user_type )
{
   DL_NODE  * node = NULL;
   CK_RV      rc = CKR_OK;

   rc = MY_LockMutex( &sess_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return CKR_FUNCTION_FAILED;
   }
   node = sess_list;
   while (node) {
      SESSION *s = (SESSION *)node->data;

      if (s->session_info.flags & CKF_RW_SESSION) {
         if (user_type == CKU_USER)
            s->session_info.state = CKS_RW_USER_FUNCTIONS;
         else
            s->session_info.state = CKS_RW_SO_FUNCTIONS;
      }
      else {
         if (user_type == CKU_USER)
            s->session_info.state = CKS_RO_USER_FUNCTIONS;
      }

      global_login_state = s->session_info.state; // SAB 
      node = node->next;
   }

   MY_UnlockMutex( &sess_list_mutex );
   return CKR_OK;
}


// session_mgr_logout_all()
//
// changes the login status of all sessions in the token
//
CK_RV
session_mgr_logout_all( void )
{
   DL_NODE  * node = NULL;
   SESSION  * s    = NULL;
   CK_RV      rc   = CKR_OK;

   rc = MY_LockMutex( &sess_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return CKR_FUNCTION_FAILED;
   }
   node = sess_list;
   while (node) {
      s = (SESSION *)node->data;

      // all sessions get logged out so destroy any private objects
      // public objects are left alone
      //
      object_mgr_purge_session_objects( s, PRIVATE );

      if (s->session_info.flags & CKF_RW_SESSION)
         s->session_info.state = CKS_RW_PUBLIC_SESSION;
      else
         s->session_info.state = CKS_RO_PUBLIC_SESSION;

      global_login_state = s->session_info.state; // SAB 

      node = node->next;
   }

   MY_UnlockMutex( &sess_list_mutex );
   return CKR_OK;
}


//
//
CK_RV
session_mgr_get_op_state( SESSION   *sess,
                          CK_BBOOL   length_only,
                          CK_BYTE   *data,
                          CK_ULONG  *data_len )
{
   OP_STATE_DATA  *op_data = NULL;
   CK_ULONG        op_data_len;
   CK_ULONG        offset;

   if (!sess){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }

   // ensure that at least one operation is active
   //
   if (sess->find_active == TRUE){
      st_err_log(71, __FILE__, __LINE__); 
      return CKR_STATE_UNSAVEABLE;
   }
   if (sess->encr_ctx.active == TRUE) {
      if (op_data != NULL){
         st_err_log(71, __FILE__, __LINE__); 
         return CKR_STATE_UNSAVEABLE;
      }
      op_data_len = sizeof(OP_STATE_DATA)      +
                    sizeof(ENCR_DECR_CONTEXT)  +
                    sess->encr_ctx.context_len +
                    sess->encr_ctx.mech.ulParameterLen;

      if (length_only == FALSE) {
         op_data = (OP_STATE_DATA *)data;

         op_data->data_len         = op_data_len - sizeof(OP_STATE_DATA);
         op_data->session_state    = sess->session_info.state;
         op_data->active_operation = STATE_ENCR;

         offset = sizeof(OP_STATE_DATA);

         memcpy( (CK_BYTE *)op_data + offset,
                 &sess->encr_ctx,
                 sizeof(ENCR_DECR_CONTEXT) );

         offset += sizeof(ENCR_DECR_CONTEXT);

         if (sess->encr_ctx.context_len != 0) {
            memcpy( (CK_BYTE *)op_data + offset,
                    sess->encr_ctx.context,
                    sess->encr_ctx.context_len );

            offset += sess->encr_ctx.context_len;
         }

         if (sess->encr_ctx.mech.ulParameterLen != 0) {
            memcpy( (CK_BYTE *)op_data + offset,
                    sess->encr_ctx.mech.pParameter,
                    sess->encr_ctx.mech.ulParameterLen );
         }
      }
   }

   if (sess->decr_ctx.active == TRUE) {
      if (op_data != NULL){
         st_err_log(71, __FILE__, __LINE__); 
         return CKR_STATE_UNSAVEABLE;
      }
      op_data_len = sizeof(OP_STATE_DATA)      +
                    sizeof(ENCR_DECR_CONTEXT)  +
                    sess->decr_ctx.context_len +
                    sess->decr_ctx.mech.ulParameterLen;

      if (length_only == FALSE) {
         op_data = (OP_STATE_DATA *)data;

         op_data->data_len         = op_data_len - sizeof(OP_STATE_DATA);
         op_data->session_state    = sess->session_info.state;
         op_data->active_operation = STATE_DECR;

         offset = sizeof(OP_STATE_DATA);

         memcpy( (CK_BYTE *)op_data + offset,
                 &sess->decr_ctx,
                 sizeof(ENCR_DECR_CONTEXT) );

         offset += sizeof(ENCR_DECR_CONTEXT);

         if (sess->decr_ctx.context_len != 0) {
            memcpy( (CK_BYTE *)op_data + offset,
                    sess->decr_ctx.context,
                    sess->decr_ctx.context_len );

            offset += sess->decr_ctx.context_len;
         }

         if (sess->decr_ctx.mech.ulParameterLen != 0) {
            memcpy( (CK_BYTE *)op_data + offset,
                    sess->decr_ctx.mech.pParameter,
                    sess->decr_ctx.mech.ulParameterLen );
         }
      }
   }

   if (sess->digest_ctx.active == TRUE) {
      if (op_data != NULL){
         st_err_log(71, __FILE__, __LINE__); 
         return CKR_STATE_UNSAVEABLE;
      }
      op_data_len = sizeof(OP_STATE_DATA)        +
                    sizeof(DIGEST_CONTEXT)       +
                    sess->digest_ctx.context_len +
                    sess->digest_ctx.mech.ulParameterLen;

      if (length_only == FALSE) {
         op_data = (OP_STATE_DATA *)data;

         op_data->data_len         = op_data_len - sizeof(OP_STATE_DATA);
         op_data->session_state    = sess->session_info.state;
         op_data->active_operation = STATE_DIGEST;

         offset = sizeof(OP_STATE_DATA);

         memcpy( (CK_BYTE *)op_data + offset,
                 &sess->digest_ctx,
                 sizeof(DIGEST_CONTEXT) );

         offset += sizeof(DIGEST_CONTEXT);

         if (sess->digest_ctx.context_len != 0) {
            memcpy( (CK_BYTE *)op_data + offset,
                    sess->digest_ctx.context,
                    sess->digest_ctx.context_len );

            offset += sess->digest_ctx.context_len;
         }

         if (sess->digest_ctx.mech.ulParameterLen != 0) {
            memcpy( (CK_BYTE *)op_data + offset,
                    sess->digest_ctx.mech.pParameter,
                    sess->digest_ctx.mech.ulParameterLen );
         }
      }
   }

   if (sess->sign_ctx.active == TRUE) {
      if (op_data != NULL){
         st_err_log(71, __FILE__, __LINE__); 
         return CKR_STATE_UNSAVEABLE;
      }
      op_data_len = sizeof(OP_STATE_DATA)       +
                    sizeof(SIGN_VERIFY_CONTEXT) +
                    sess->sign_ctx.context_len  +
                    sess->sign_ctx.mech.ulParameterLen;

      if (length_only == FALSE) {
         op_data = (OP_STATE_DATA *)data;

         op_data->data_len         = op_data_len - sizeof(OP_STATE_DATA);
         op_data->session_state    = sess->session_info.state;
         op_data->active_operation = STATE_SIGN;

         offset = sizeof(OP_STATE_DATA);

         memcpy( (CK_BYTE *)op_data + offset,
                 &sess->sign_ctx,
                 sizeof(SIGN_VERIFY_CONTEXT) );

         offset += sizeof(SIGN_VERIFY_CONTEXT);

         if (sess->sign_ctx.context_len != 0) {
            memcpy( (CK_BYTE *)op_data + offset,
                    sess->sign_ctx.context,
                    sess->sign_ctx.context_len );

            offset += sess->sign_ctx.context_len;
         }

         if (sess->sign_ctx.mech.ulParameterLen != 0) {
            memcpy( (CK_BYTE *)op_data + offset,
                    sess->sign_ctx.mech.pParameter,
                    sess->sign_ctx.mech.ulParameterLen );
         }
      }
   }

   if (sess->verify_ctx.active == TRUE) {
      if (op_data != NULL){
         st_err_log(71, __FILE__, __LINE__); 
         return CKR_STATE_UNSAVEABLE;
      }
      op_data_len = sizeof(OP_STATE_DATA)        +
                    sizeof(SIGN_VERIFY_CONTEXT)  +
                    sess->verify_ctx.context_len +
                    sess->verify_ctx.mech.ulParameterLen;

      if (length_only == FALSE) {
         op_data = (OP_STATE_DATA *)data;

         op_data->data_len         = op_data_len - sizeof(OP_STATE_DATA);
         op_data->session_state    = sess->session_info.state;
         op_data->active_operation = STATE_SIGN;

         offset = sizeof(OP_STATE_DATA);

         memcpy( (CK_BYTE *)op_data + offset,
                 &sess->verify_ctx,
                 sizeof(SIGN_VERIFY_CONTEXT) );

         offset += sizeof(SIGN_VERIFY_CONTEXT);

         if (sess->verify_ctx.context_len != 0) {
            memcpy( (CK_BYTE *)op_data + offset,
                    sess->verify_ctx.context,
                    sess->verify_ctx.context_len );

            offset += sess->verify_ctx.context_len;
         }

         if (sess->verify_ctx.mech.ulParameterLen != 0) {
            memcpy( (CK_BYTE *)op_data + offset,
                    sess->verify_ctx.mech.pParameter,
                    sess->verify_ctx.mech.ulParameterLen );
         }
      }
   }

   *data_len = op_data_len;
   return CKR_OK;
}


//
//
CK_RV
session_mgr_set_op_state( SESSION           * sess,
                          CK_OBJECT_HANDLE    encr_key,
                          CK_OBJECT_HANDLE    auth_key,
                          CK_BYTE           * data,
                          CK_ULONG            data_len )
{
   OP_STATE_DATA  *op_data    = NULL;
   CK_BYTE        *mech_param = NULL;
   CK_BYTE        *context    = NULL;
   CK_BYTE        *ptr1       = NULL;
   CK_BYTE        *ptr2       = NULL;
   CK_BYTE        *ptr3       = NULL;
   CK_ULONG        len;


   if (!sess || !data){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   op_data = (OP_STATE_DATA *)data;

   // make sure the session states are compatible
   //
   if (sess->session_info.state != op_data->session_state){
      st_err_log(69, __FILE__, __LINE__); 
      return CKR_SAVED_STATE_INVALID;
   }
   // validate the new state information.  don't touch the session
   // until the new state is valid.
   //
   switch (op_data->active_operation) {
      case STATE_ENCR:
      case STATE_DECR:
         {
            ENCR_DECR_CONTEXT *ctx = (ENCR_DECR_CONTEXT *)(data + sizeof(OP_STATE_DATA));

            len = sizeof(ENCR_DECR_CONTEXT) + ctx->context_len + ctx->mech.ulParameterLen;
            if (len != op_data->data_len){
               st_err_log(69, __FILE__, __LINE__); 
               return CKR_SAVED_STATE_INVALID;
            }
            if (auth_key != 0){
               st_err_log(21, __FILE__, __LINE__); 
               return CKR_KEY_NOT_NEEDED;
            }
            if (encr_key == 0){
               st_err_log(23, __FILE__, __LINE__); 
               return CKR_KEY_NEEDED;
            }
            ptr1 = (CK_BYTE *)ctx;
            ptr2 = ptr1 + sizeof(ENCR_DECR_CONTEXT);
            ptr3 = ptr2 + ctx->context_len;

            if (ctx->context_len) {
               context = (CK_BYTE *)malloc( ctx->context_len );
               if (!context){
                  st_err_log(0, __FILE__, __LINE__);
                  return CKR_HOST_MEMORY;
               }
               memcpy( context, ptr2, ctx->context_len );
            }

            if (ctx->mech.ulParameterLen) {
               mech_param = (CK_BYTE *)malloc( ctx->mech.ulParameterLen );
               if (!mech_param) {
                  if (context)
                     free( context );
                  st_err_log(0, __FILE__, __LINE__);
                  return CKR_HOST_MEMORY;
               }
               memcpy( mech_param, ptr3, ctx->mech.ulParameterLen );
            }
         }
         break;

      case STATE_SIGN:
      case STATE_VERIFY:
         {
            SIGN_VERIFY_CONTEXT *ctx = (SIGN_VERIFY_CONTEXT *)(data + sizeof(OP_STATE_DATA));

            len = sizeof(SIGN_VERIFY_CONTEXT) + ctx->context_len + ctx->mech.ulParameterLen;
            if (len != op_data->data_len){
               st_err_log(69, __FILE__, __LINE__); 
               return CKR_SAVED_STATE_INVALID;
            }
            if (auth_key == 0){
               st_err_log(23, __FILE__, __LINE__); 
               return CKR_KEY_NEEDED;
            }
            if (encr_key != 0){
               st_err_log(21, __FILE__, __LINE__); 
               return CKR_KEY_NOT_NEEDED;
            }
            ptr1 = (CK_BYTE *)ctx;
            ptr2 = ptr1 + sizeof(SIGN_VERIFY_CONTEXT);
            ptr3 = ptr2 + ctx->context_len;

            if (ctx->context_len) {
               context = (CK_BYTE *)malloc( ctx->context_len );
               if (!context){
                  st_err_log(0, __FILE__, __LINE__);
                  return CKR_HOST_MEMORY;
               }
               memcpy( context, ptr2, ctx->context_len );
            }

            if (ctx->mech.ulParameterLen) {
               mech_param = (CK_BYTE *)malloc( ctx->mech.ulParameterLen );
               if (!mech_param) {
                  if (context)
                     free( context );
                  st_err_log(0, __FILE__, __LINE__);
                  return CKR_HOST_MEMORY;
               }
               memcpy( mech_param, ptr3, ctx->mech.ulParameterLen );
            }
         }
         break;

      case STATE_DIGEST:
         {
            DIGEST_CONTEXT *ctx = (DIGEST_CONTEXT *)(data + sizeof(OP_STATE_DATA));

            len = sizeof(DIGEST_CONTEXT) + ctx->context_len + ctx->mech.ulParameterLen;
            if (len != op_data->data_len){
               st_err_log(69, __FILE__, __LINE__); 
               return CKR_SAVED_STATE_INVALID;
            }
            if (auth_key != 0){
               st_err_log(23, __FILE__, __LINE__); 
               return CKR_KEY_NOT_NEEDED;
            }
            if (encr_key != 0){
               st_err_log(23, __FILE__, __LINE__); 
               return CKR_KEY_NOT_NEEDED;
            }
            ptr1 = (CK_BYTE *)ctx;
            ptr2 = ptr1 + sizeof(DIGEST_CONTEXT);
            ptr3 = ptr2 + ctx->context_len;

            if (ctx->context_len) {
               context = (CK_BYTE *)malloc( ctx->context_len );
               if (!context){
                  st_err_log(0, __FILE__, __LINE__);
                  return CKR_HOST_MEMORY;
               }
               memcpy( context, ptr2, ctx->context_len );
            }

            if (ctx->mech.ulParameterLen) {
               mech_param = (CK_BYTE *)malloc( ctx->mech.ulParameterLen );
               if (!mech_param) {
                  if (context)
                     free( context );
                  st_err_log(0, __FILE__, __LINE__);
                  return CKR_HOST_MEMORY;
               }
               memcpy( mech_param, ptr3, ctx->mech.ulParameterLen );
            }
         }
         break;

      default:
         st_err_log(69, __FILE__, __LINE__); 
         return CKR_SAVED_STATE_INVALID;
   }


   // state information looks okay.  cleanup the current session state, first
   //
   if (sess->encr_ctx.active)
      encr_mgr_cleanup( &sess->encr_ctx );

   if (sess->decr_ctx.active)
      decr_mgr_cleanup( &sess->decr_ctx );

   if (sess->digest_ctx.active)
      digest_mgr_cleanup( &sess->digest_ctx );

   if (sess->sign_ctx.active)
      sign_mgr_cleanup( &sess->sign_ctx );

   if (sess->verify_ctx.active)
      verify_mgr_cleanup( &sess->verify_ctx );


   // copy the new state information
   //
   switch (op_data->active_operation) {
      case STATE_ENCR:
         memcpy( &sess->encr_ctx, ptr1, sizeof(ENCR_DECR_CONTEXT) );

         sess->encr_ctx.key             = encr_key;
         sess->encr_ctx.context         = context;
         sess->encr_ctx.mech.pParameter = mech_param;
         break;

      case STATE_DECR:
         memcpy( &sess->decr_ctx, ptr1, sizeof(ENCR_DECR_CONTEXT) );

         sess->decr_ctx.key             = encr_key;
         sess->decr_ctx.context         = context;
         sess->decr_ctx.mech.pParameter = mech_param;
         break;

      case STATE_SIGN:
         memcpy( &sess->sign_ctx, ptr1, sizeof(SIGN_VERIFY_CONTEXT) );

         sess->sign_ctx.key             = auth_key;
         sess->sign_ctx.context         = context;
         sess->sign_ctx.mech.pParameter = mech_param;
         break;

      case STATE_VERIFY:
         memcpy( &sess->verify_ctx, ptr1, sizeof(SIGN_VERIFY_CONTEXT) );

         sess->verify_ctx.key             = auth_key;
         sess->verify_ctx.context         = context;
         sess->verify_ctx.mech.pParameter = mech_param;
         break;

      case STATE_DIGEST:
         memcpy( &sess->digest_ctx, ptr1, sizeof(DIGEST_CONTEXT) );

         sess->digest_ctx.context         = context;
         sess->digest_ctx.mech.pParameter = mech_param;
         break;
   }

   return CKR_OK;
}

// Return TRUE if the session we're in has its PIN
// expired.
CK_BBOOL pin_expired(CK_SESSION_INFO *si, CK_FLAGS flags)
{
   // If this is an SO session
   if (	(flags & CKF_SO_PIN_TO_BE_CHANGED) &&
	   (si->state == CKS_RW_SO_FUNCTIONS) )
	   return TRUE;

   // Else we're a User session
   return( (flags & CKF_USER_PIN_TO_BE_CHANGED) &&
	  ((si->state == CKS_RO_USER_FUNCTIONS) ||
	   (si->state == CKS_RW_USER_FUNCTIONS)) );
}

// Return TRUE if the session we're in has its PIN
// locked.
CK_BBOOL pin_locked(CK_SESSION_INFO *si, CK_FLAGS flags)
{
   // If this is an SO session
   if (	(flags & CKF_SO_PIN_LOCKED) &&
	   (si->state == CKS_RW_SO_FUNCTIONS) )
	   return TRUE;

   // Else we're a User session
   return( (flags & CKF_USER_PIN_LOCKED) &&
	  ((si->state == CKS_RO_USER_FUNCTIONS) ||
	   (si->state == CKS_RW_USER_FUNCTIONS)) );
}

// Increment the login flags after an incorrect password
// has been passed to C_Login. New for v2.11. - KEY
void set_login_flags(CK_USER_TYPE userType, CK_FLAGS_32 *flags)
{
	if(userType == CKU_USER) {
		if(*flags & CKF_USER_PIN_FINAL_TRY) {
			*flags |= CKF_USER_PIN_LOCKED;
			*flags &= ~(CKF_USER_PIN_FINAL_TRY);
		} else if (*flags & CKF_USER_PIN_COUNT_LOW) {
			*flags |= CKF_USER_PIN_FINAL_TRY;
			*flags &= ~(CKF_USER_PIN_COUNT_LOW);
		} else {
			*flags |= CKF_USER_PIN_COUNT_LOW;
		}
	} else {
		if(*flags & CKF_SO_PIN_FINAL_TRY) {
			*flags |= CKF_SO_PIN_LOCKED;
			*flags &= ~(CKF_SO_PIN_FINAL_TRY);
		} else if (*flags & CKF_SO_PIN_COUNT_LOW) {
			*flags |= CKF_SO_PIN_FINAL_TRY;
			*flags &= ~(CKF_SO_PIN_COUNT_LOW);
		} else {
			*flags |= CKF_SO_PIN_COUNT_LOW;
		}
	}
}


