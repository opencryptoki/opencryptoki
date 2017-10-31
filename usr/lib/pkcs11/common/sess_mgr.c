/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  session.c
//
// Session manager related functions
//
#include <stdlib.h>
#include <string.h>  // for memcmp() et al

#include "pkcs11types.h"
#include "local_types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"


// session_mgr_find()
//
// search for the specified session.  returning a pointer to the session
// might be dangerous, but performs well
//
// Returns:  SESSION * or NULL
//
SESSION *
session_mgr_find( CK_SESSION_HANDLE handle )
{
   SESSION  * result = NULL;

   if (!handle) {
      return NULL;
   }

   result = bt_get_node_value(&sess_btree, handle);

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
session_mgr_new( CK_ULONG flags, CK_SLOT_ID slot_id, CK_SESSION_HANDLE_PTR phSession )
{
   SESSION  * new_session  = NULL;
   CK_BBOOL   user_session = FALSE;
   CK_BBOOL   so_session   = FALSE;
   CK_RV      rc = CKR_OK;


   new_session = (SESSION *)malloc(sizeof(SESSION));
   if (!new_session) {
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      rc = CKR_HOST_MEMORY;
      goto done;
   }

   memset( new_session, 0x0, sizeof(SESSION) );

   // find an unused session handle.  session handles will wrap
   // automatically...
   //
   new_session->session_info.slotID        = slot_id;
   new_session->session_info.flags         = flags;
   new_session->session_info.ulDeviceError = 0;


   // determine the login/logout status of the new session.  PKCS 11 requires
   // that all sessions belonging to a process have the same login/logout status
   //
   so_session = session_mgr_so_session_exists();
   user_session = session_mgr_user_session_exists();

   // we don't have to worry about having a user and SO session at the same time.
   // that is prevented in the login routine
   //
   if (user_session) {
      if (new_session->session_info.flags & CKF_RW_SESSION)
         new_session->session_info.state = CKS_RW_USER_FUNCTIONS;
      else {
         new_session->session_info.state = CKS_RO_USER_FUNCTIONS;
         ro_session_count++;
      }
   }
   else if (so_session) {
      new_session->session_info.state = CKS_RW_SO_FUNCTIONS;
   }
   else {
      if (new_session->session_info.flags & CKF_RW_SESSION)
         new_session->session_info.state = CKS_RW_PUBLIC_SESSION;
      else {
         new_session->session_info.state = CKS_RO_PUBLIC_SESSION;
         ro_session_count++;
      }
   }

   *phSession = bt_node_add(&sess_btree, new_session);
   if (*phSession == 0) {
      rc = CKR_HOST_MEMORY;
      /* new_session will be free'd below */
   }

done:
   if (rc != CKR_OK && new_session != NULL){
      TRACE_ERROR("Failed to add session to the btree.\n");
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
    __transaction_atomic { /* start transaction */
	    CK_BBOOL result;

	    result = (global_login_state == CKS_RW_SO_FUNCTIONS);

	    return result;
    } /* end transaction */
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
   __transaction_atomic { /* start transaction */
	   CK_BBOOL result;

	   result = ( (global_login_state == CKS_RO_USER_FUNCTIONS) ||
			(global_login_state == CKS_RW_USER_FUNCTIONS) );

	   return result;
   } /* end transaction */
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
  __transaction_atomic { /* start transaction */
	  CK_BBOOL result;

	  result = ( (global_login_state == CKS_RO_PUBLIC_SESSION) ||
			  (global_login_state == CKS_RW_PUBLIC_SESSION) );

	  return result;
   } /* end transaction */
}


// session_mgr_readonly_exists()
//
// determines whether the specified process owns any read-only sessions.  this is useful
// because the SO cannot log in if a read-only session exists.
//
CK_BBOOL
session_mgr_readonly_session_exists( void )
{
   __transaction_atomic { /* start transaction */
	   CK_BBOOL result;

	   result = (ro_session_count > 0);

	   return result;
   } /* end transaction */
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
session_mgr_close_session( STDLL_TokData_t *tokdata, CK_SESSION_HANDLE handle )
{
   SESSION *sess;
   CK_RV      rc = CKR_OK;

   sess = bt_get_node_value(&sess_btree, handle);
   if (!sess) {
	   TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
	   rc = CKR_SESSION_HANDLE_INVALID;
	   goto done;
   }

   object_mgr_purge_session_objects( tokdata, sess, ALL );

   __transaction_atomic { /* start transaction */
	   if ( (sess->session_info.state == CKS_RO_PUBLIC_SESSION) ||
		(sess->session_info.state == CKS_RO_USER_FUNCTIONS) ) {
		   ro_session_count--;
	   }
   } /* end transaction */

   // Make sure this address is now invalid
   sess->handle = CK_INVALID_HANDLE;

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

   bt_node_free(&sess_btree, handle, free);

   // XXX XXX  Not having this is a problem
   //  for IHS.  The spec states that there is an implicit logout
   //  when the last session is closed.  Cannonicaly this is what other
   //  implementaitons do.  however on linux for some reason IHS can't seem
   //  to keep the session open, which means that they go through the login
   //  path EVERY time, which of course causes a reload of the private
   //  objects EVERY time.   If we are logged out, we MUST purge the private
   //  objects from this process..
   //
   if (bt_is_empty(&sess_btree)) {
      // SAB  XXX  if all sessions are closed.  Is this effectivly logging out
        if (token_specific.t_logout) {
            rc = token_specific.t_logout();
        }
        object_mgr_purge_private_token_objects(tokdata);

	__transaction_atomic { /* start transaction */
		global_login_state = CKS_RO_PUBLIC_SESSION;
	} /* end transaction */
      // The objects really need to be purged .. but this impacts the
      // performance under linux.   So we need to make sure that the
      // login state is valid.    I don't really like this.
      object_mgr_purge_map(tokdata, (SESSION *)0xFFFF, PRIVATE);
   }

done:
   return rc;
}

/* session_free
 *
 * Callback used to free an individual SESSION object
 */
void
session_free(STDLL_TokData_t *tokdata, void *node_value,
	     unsigned long node_idx, void *p3)
{
   SESSION *sess = (SESSION *)node_value;

   object_mgr_purge_session_objects( tokdata, sess, ALL );
   sess->handle = CK_INVALID_HANDLE;

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

   /* NB: any access to sess or @node_value after this returns will segfault */
   bt_node_free(&sess_btree, node_idx, free);
}

// session_mgr_close_all_sessions()
//
// removes all sessions from the specified process
//
CK_RV
session_mgr_close_all_sessions( void )
{
   bt_for_each_node(NULL, &sess_btree, session_free, NULL);

   __transaction_atomic { /* start transaction */
	   global_login_state = CKS_RO_PUBLIC_SESSION;
	   ro_session_count = 0;
   } /* end transaction */

   return CKR_OK;
}

/* session_login
 *
 * Callback used to update a SESSION object's login state to logged in based on user type
 */
void
session_login(STDLL_TokData_t *tokdata, void *node_value,
	      unsigned long node_idx, void *p3)
{
   SESSION *s = (SESSION *)node_value;
   CK_USER_TYPE user_type = *(CK_USER_TYPE *)p3;

   if (s->session_info.flags & CKF_RW_SESSION) {
      if (user_type == CKU_USER)
         s->session_info.state = CKS_RW_USER_FUNCTIONS;
      else
         s->session_info.state = CKS_RW_SO_FUNCTIONS;
   } else {
      if (user_type == CKU_USER)
         s->session_info.state = CKS_RO_USER_FUNCTIONS;
   }

   global_login_state = s->session_info.state; // SAB
}

// session_mgr_login_all()
//
// changes the login status of all sessions in the token
//
// Arg:  CK_USER_TYPE  user_type : USER or SO
//
CK_RV
session_mgr_login_all( STDLL_TokData_t *tokdata, CK_USER_TYPE user_type )
{
   bt_for_each_node(tokdata, &sess_btree, session_login, (void *)&user_type);

   return CKR_OK;
}

/* session_logout
 *
 * Callback used to update a SESSION object's login state to be logged out
 */
void
session_logout(STDLL_TokData_t *tokdata, void *node_value,
	       unsigned long node_idx, void *p3)
{
   SESSION *s = (SESSION *)node_value;

   // all sessions get logged out so destroy any private objects
   // public objects are left alone
   //
   object_mgr_purge_session_objects( tokdata, s, PRIVATE );

   if (s->session_info.flags & CKF_RW_SESSION)
      s->session_info.state = CKS_RW_PUBLIC_SESSION;
   else
      s->session_info.state = CKS_RO_PUBLIC_SESSION;

   global_login_state = s->session_info.state; // SAB
}

// session_mgr_logout_all()
//
// changes the login status of all sessions in the token
//
CK_RV
session_mgr_logout_all( STDLL_TokData_t *tokdata )
{
   bt_for_each_node(tokdata, &sess_btree, session_logout, NULL);

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
   CK_ULONG        op_data_len = 0;
   CK_ULONG        offset;

   if (!sess){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }

   // ensure that at least one operation is active
   //
   if (sess->find_active == TRUE){
      TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
      return CKR_STATE_UNSAVEABLE;
   }
   if (sess->encr_ctx.active == TRUE) {
      if (op_data != NULL){
         TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
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
         TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
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
         TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
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
         TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
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
         TRACE_ERROR("%s\n", ock_err(ERR_STATE_UNSAVEABLE));
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
      TRACE_ERROR("%s received bad argument(s)\n", __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }
   op_data = (OP_STATE_DATA *)data;

   // make sure the session states are compatible
   //
   if (sess->session_info.state != op_data->session_state){
      TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
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
               TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
               return CKR_SAVED_STATE_INVALID;
            }
            if (auth_key != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_KEY_NOT_NEEDED));
               return CKR_KEY_NOT_NEEDED;
            }
            if (encr_key == 0){
               TRACE_ERROR("%s\n", ock_err(ERR_KEY_NEEDED));
               return CKR_KEY_NEEDED;
            }
            ptr1 = (CK_BYTE *)ctx;
            ptr2 = ptr1 + sizeof(ENCR_DECR_CONTEXT);
            ptr3 = ptr2 + ctx->context_len;

            if (ctx->context_len) {
               context = (CK_BYTE *)malloc( ctx->context_len );
               if (!context){
                  TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                  return CKR_HOST_MEMORY;
               }
               memcpy( context, ptr2, ctx->context_len );
            }

            if (ctx->mech.ulParameterLen) {
               mech_param = (CK_BYTE *)malloc( ctx->mech.ulParameterLen );
               if (!mech_param) {
                  if (context)
                     free( context );
                  TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
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
               TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
               return CKR_SAVED_STATE_INVALID;
            }
            if (auth_key == 0){
               TRACE_ERROR("%s\n", ock_err(ERR_KEY_NEEDED));
               return CKR_KEY_NEEDED;
            }
            if (encr_key != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_KEY_NOT_NEEDED));
               return CKR_KEY_NOT_NEEDED;
            }
            ptr1 = (CK_BYTE *)ctx;
            ptr2 = ptr1 + sizeof(SIGN_VERIFY_CONTEXT);
            ptr3 = ptr2 + ctx->context_len;

            if (ctx->context_len) {
               context = (CK_BYTE *)malloc( ctx->context_len );
               if (!context){
                  TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                  return CKR_HOST_MEMORY;
               }
               memcpy( context, ptr2, ctx->context_len );
            }

            if (ctx->mech.ulParameterLen) {
               mech_param = (CK_BYTE *)malloc( ctx->mech.ulParameterLen );
               if (!mech_param) {
                  if (context)
                     free( context );
                  TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
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
               TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
               return CKR_SAVED_STATE_INVALID;
            }
            if (auth_key != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_KEY_NOT_NEEDED));
               return CKR_KEY_NOT_NEEDED;
            }
            if (encr_key != 0){
               TRACE_ERROR("%s\n", ock_err(ERR_KEY_NOT_NEEDED));
               return CKR_KEY_NOT_NEEDED;
            }
            ptr1 = (CK_BYTE *)ctx;
            ptr2 = ptr1 + sizeof(DIGEST_CONTEXT);
            ptr3 = ptr2 + ctx->context_len;

            if (ctx->context_len) {
               context = (CK_BYTE *)malloc( ctx->context_len );
               if (!context){
                  TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                  return CKR_HOST_MEMORY;
               }
               memcpy( context, ptr2, ctx->context_len );
            }

            if (ctx->mech.ulParameterLen) {
               mech_param = (CK_BYTE *)malloc( ctx->mech.ulParameterLen );
               if (!mech_param) {
                  if (context)
                     free( context );
                  TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                  return CKR_HOST_MEMORY;
               }
               memcpy( mech_param, ptr3, ctx->mech.ulParameterLen );
            }
         }
         break;

      default:
         TRACE_ERROR("%s\n", ock_err(ERR_SAVED_STATE_INVALID));
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
