
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


// File:  obj_mgr.c
//
// Object manager related functions
//

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>

  #include <string.h>  // for memcmp() et al

#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"

#include <openssl/rsa.h>
#include "tpm_specific.h"


CK_RV
object_mgr_add( SESSION          * sess,
                CK_ATTRIBUTE     * pTemplate,
                CK_ULONG           ulCount,
                CK_OBJECT_HANDLE * handle )
{
   OBJECT    * o = NULL;
   CK_BBOOL    priv_obj, sess_obj;
   CK_BBOOL    locked = FALSE;
   CK_RV       rc;

   if (!sess || !pTemplate || !handle){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      return CKR_FUNCTION_FAILED;
   }

   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   locked = TRUE;

   rc = object_create( pTemplate, ulCount, &o );
   if (rc != CKR_OK){
      st_err_log(157, __FILE__, __LINE__); 
      goto done;
   }
   // check whether session has permissions to create the object, etc
   //
   // Object                  R/O      R/W      R/O     R/W    R/W
   // Type                   Public   Public    User    User   SO
   // -------------------------------------------------------------
   // Public session          R/W      R/W      R/W     R/W    R/W
   // Private session                           R/W     R/W
   // Public token            R/O      R/W      R/O     R/W    R/W
   // Private token                             R/O     R/W
   //
   sess_obj = object_is_session_object( o );
   priv_obj = object_is_private( o );

   if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
      if (priv_obj) {
         st_err_log(57, __FILE__, __LINE__); 
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }

      if (!sess_obj) {
         st_err_log(42, __FILE__, __LINE__); 
         rc = CKR_SESSION_READ_ONLY;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
      if (!sess_obj) {
         st_err_log(42, __FILE__, __LINE__);
         rc = CKR_SESSION_READ_ONLY;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
      if (priv_obj) {
         st_err_log(57, __FILE__, __LINE__);
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
      if (priv_obj) {
         st_err_log(57, __FILE__, __LINE__);
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }
   }

   // okay, object is created and the session permissions look okay.
   // add the object to the appropriate list and assign an object handle
   //

   if (sess_obj) {
      o->session = sess;
      memset( o->name, 0x00, sizeof(CK_BYTE) * 8 );

      sess_obj_list = dlist_add_as_first( sess_obj_list, o );
   }
   else {
      CK_BYTE current[8];
      CK_BYTE next[8];

      // we'll be modifying nv_token_data so we should protect this part with
      // the 'pkcs_mutex'
      //
      rc = XProcLock( xproclock );
      if (rc != CKR_OK){
         st_err_log(150, __FILE__, __LINE__); 
         goto done;
      }
      else {

         // Determine if we have already reached our Max Token Objects
         //
         if (priv_obj) {
            if (global_shm->num_priv_tok_obj >= MAX_TOK_OBJS) {
               rc = CKR_HOST_MEMORY;
               st_err_log(1, __FILE__, __LINE__); 
               XProcUnLock(xproclock);
               goto done;
            }
         }
         else {
            if (global_shm->num_publ_tok_obj >= MAX_TOK_OBJS) {
               rc = CKR_HOST_MEMORY;
               st_err_log(1, __FILE__, __LINE__); 
               XProcUnLock(xproclock);
               goto done;
            }
         }

         memcpy( current, &nv_token_data->next_token_object_name, 8 );

         o->session = NULL;
         memcpy( &o->name, current, 8 );

         compute_next_token_obj_name( current, next );
         memcpy( &nv_token_data->next_token_object_name, next, 8 );

         save_token_object( o );

         // add the object identifier to the shared memory segment
         //
         object_mgr_add_to_shm( o );

         XProcUnLock( xproclock );

         // save_token_data has to lock the mutex itself because it's used elsewhere
         //
         save_token_data();
      }

      // now, store the object in the appropriate local token object list
      //
      if (priv_obj)
         priv_token_obj_list = dlist_add_as_last( priv_token_obj_list, o );
      else
         publ_token_obj_list = dlist_add_as_last( publ_token_obj_list, o );
   }

   rc = object_mgr_add_to_map( sess, o, handle );
   if (rc != CKR_OK) {
      DL_NODE *node = NULL;

      st_err_log(157, __FILE__, __LINE__); 
      // this is messy but we need to remove the object from whatever
      // list we just added it to
      //
      if (sess_obj) {
         node = dlist_find( sess_obj_list, o );
         if (node)
            sess_obj_list = dlist_remove_node( sess_obj_list, node );
      }
      else {
         // we'll want to delete the token object file too!
         //
         delete_token_object( o );

         if (priv_obj) {
            node = dlist_find( priv_token_obj_list, o );
            if (node)
               priv_token_obj_list = dlist_remove_node( priv_token_obj_list, node );
         }
         else {
            node = dlist_find( publ_token_obj_list, o );
            if (node)
               publ_token_obj_list = dlist_remove_node( publ_token_obj_list, node );
         }

         rc = XProcLock( xproclock );
         if (rc != CKR_OK){
            st_err_log(150, __FILE__, __LINE__); 
            goto done;
         }
         object_mgr_del_from_shm( o );

         XProcUnLock( xproclock );
      }
   }


done:
   if (locked)
      MY_UnlockMutex( &obj_list_mutex );

   if ((rc != CKR_OK) && (o != NULL))
      object_free( o );

   return rc;
}


// object_mgr_add_to_map()
//
CK_RV
object_mgr_add_to_map( SESSION          * sess,
                       OBJECT           * obj,
                       CK_OBJECT_HANDLE * handle )
{
   OBJECT_MAP  *map_node = NULL;

   if (!sess || !obj || !handle){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   //
   // this guy doesn't lock a mutex because it's calling routines should have
   // already locked it
   //

   map_node = (OBJECT_MAP *)malloc(sizeof(OBJECT_MAP));
   if (!map_node){
      st_err_log(0, __FILE__, __LINE__); 
      return CKR_HOST_MEMORY;
   }
   map_node->handle   = next_object_handle++;
   map_node->session  = sess;
   map_node->ptr      = obj;

   if (obj->session != NULL)
      map_node->is_session_obj = TRUE;
   else
      map_node->is_session_obj = FALSE;

   // add the new map entry to the list
   //
   object_map = dlist_add_as_first( object_map, map_node );

   *handle = map_node->handle;
   return CKR_OK;
}


// object_mgr_copy()
//
// algorithm:
//    1) find the old object
//    2) get the template from the old object
//    3) merge in the new object's template
//    4) perform class-specific sanity checks
//
CK_RV
object_mgr_copy( SESSION          * sess,
                 CK_ATTRIBUTE     * pTemplate,
                 CK_ULONG           ulCount,
                 CK_OBJECT_HANDLE   old_handle,
                 CK_OBJECT_HANDLE * new_handle )
{
   OBJECT     *old_obj = NULL;
   OBJECT     *new_obj = NULL;
   CK_BBOOL    priv_obj;
   CK_BBOOL    sess_obj;
   CK_BBOOL    locked = FALSE;
   CK_RV       rc;

   if (!sess || !pTemplate || !new_handle){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }

   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   locked = TRUE;

   rc = object_mgr_find_in_map1( old_handle, &old_obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      goto done;
   }
   rc = object_copy( pTemplate, ulCount, old_obj, &new_obj );
   if (rc != CKR_OK){
      st_err_log(158, __FILE__, __LINE__);
      goto done;
   }

   // check whether session has permissions to create the object, etc
   //
   // Object                  R/O      R/W      R/O     R/W    R/W
   // Type                   Public   Public    User    User   SO
   // -------------------------------------------------------------
   // Public session          R/W      R/W      R/W     R/W    R/W
   // Private session                           R/W     R/W
   // Public token            R/O      R/W      R/O     R/W    R/W
   // Private token                             R/O     R/W
   //
   sess_obj = object_is_session_object( new_obj );
   priv_obj = object_is_private( new_obj );

   if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
      if (priv_obj) {
         st_err_log(57, __FILE__, __LINE__); 
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }

      if (!sess_obj) {
         st_err_log(42, __FILE__, __LINE__); 
         rc = CKR_SESSION_READ_ONLY;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
      if (!sess_obj) {
         st_err_log(42, __FILE__, __LINE__); 
         rc = CKR_SESSION_READ_ONLY;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
      if (priv_obj) {
         st_err_log(57, __FILE__, __LINE__); 
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
      if (priv_obj) {
         st_err_log(57, __FILE__, __LINE__); 
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }
   }

   // okay, object is created and the session permissions look okay.
   // add the object to the appropriate list and assign an object handle
   //

   if (sess_obj) {
      new_obj->session = sess;
      memset( &new_obj->name, 0x00, sizeof(CK_BYTE) * 8 );

      sess_obj_list = dlist_add_as_first( sess_obj_list, new_obj );
   }
   else {
      CK_BYTE current[8];
      CK_BYTE next[8];

      // we'll be modifying nv_token_data so we should protect this part
      // with 'pkcs_mutex'
      //
      rc = XProcLock( xproclock );
      if (rc != CKR_OK){
         st_err_log(150, __FILE__, __LINE__); 
         goto done;
      }
      else {

         // Determine if we have already reached our Max Token Objects
         //
         if (priv_obj) {
            if (global_shm->num_priv_tok_obj >= MAX_TOK_OBJS) {
               XProcUnLock(xproclock);
               st_err_log(1, __FILE__, __LINE__); 
               rc = CKR_HOST_MEMORY;
               goto done;
            }
         }
         else {
            if (global_shm->num_publ_tok_obj >= MAX_TOK_OBJS) {
               XProcUnLock(xproclock);
               st_err_log(1, __FILE__, __LINE__); 
               rc = CKR_HOST_MEMORY;
               goto done;
            }
         }
         memcpy( current, &nv_token_data->next_token_object_name, 8 );

         new_obj->session = NULL;
         memcpy( &new_obj->name, current, 8 );

         compute_next_token_obj_name( current, next );
         memcpy( &nv_token_data->next_token_object_name, next, 8 );

         save_token_object( new_obj );

         // add the object identifier to the shared memory segment
         //
         object_mgr_add_to_shm( new_obj );

         XProcUnLock( xproclock );

         save_token_data();
      }

      // now, store the object in the token object list in RAM for speed
      //
      if (priv_obj)
         priv_token_obj_list = dlist_add_as_last( priv_token_obj_list, new_obj );
      else
         publ_token_obj_list = dlist_add_as_last( publ_token_obj_list, new_obj );
   }

   rc = object_mgr_add_to_map( sess, new_obj, new_handle );
   if (rc != CKR_OK) {
      DL_NODE *node = NULL;
      
      st_err_log(157, __FILE__, __LINE__); 

      // this is messy but we need to remove the object from whatever
      // list we just added it to
      //
      if (sess_obj) {
         node = dlist_find( sess_obj_list, new_obj );
         if (node)
            sess_obj_list = dlist_remove_node( sess_obj_list, node );
      }
      else {
         // FIXME - need to destroy the token object file too
         //
         delete_token_object( new_obj );

         if (priv_obj) {
            node = dlist_find( priv_token_obj_list, new_obj );
            if (node)
               priv_token_obj_list = dlist_remove_node( priv_token_obj_list, node );
         }
         else {
            node = dlist_find( publ_token_obj_list, new_obj );
            if (node)
               publ_token_obj_list = dlist_remove_node( publ_token_obj_list, node );
         }

         rc = XProcLock( xproclock );
         if (rc != CKR_OK){
            st_err_log(150, __FILE__, __LINE__); 
            goto done;
         }
         object_mgr_del_from_shm( new_obj );

         XProcUnLock( xproclock );
      }
   }

done:
   if (locked)
      MY_UnlockMutex( &obj_list_mutex );

   if ((rc != CKR_OK) && (new_obj != NULL))
      object_free( new_obj );

   return rc;
}


// determines whether the session is allowed to create an object.  creates
// the object but doesn't add the object to any object lists or to the
// process' object map.
//
CK_RV
object_mgr_create_skel( SESSION       * sess,
                        CK_ATTRIBUTE  * pTemplate,
                        CK_ULONG        ulCount,
                        CK_ULONG        mode,
                        CK_ULONG        obj_type,
                        CK_ULONG        sub_class,
                        OBJECT       ** obj )
{
   OBJECT     *o = NULL;
   CK_RV       rc;
   CK_BBOOL    priv_obj;
   CK_BBOOL    sess_obj;

   if (!sess || !obj){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   if (!pTemplate && (ulCount != 0)){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   //
   // we don't need to lock mutex for this routine
   //

   rc = object_create_skel( pTemplate, ulCount,
                            mode,
                            obj_type, sub_class,
                            &o );
   if (rc != CKR_OK){
      st_err_log(89, __FILE__, __LINE__); 
      return rc;
   }
   sess_obj = object_is_session_object( o );
   priv_obj = object_is_private( o );

   if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
      if (priv_obj) {
         object_free( o );
         st_err_log(57, __FILE__, __LINE__); 
         return CKR_USER_NOT_LOGGED_IN;
      }

      if (!sess_obj) {
         object_free( o );
         st_err_log(42, __FILE__, __LINE__); 
         return CKR_SESSION_READ_ONLY;
      }
   }

   if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
      if (!sess_obj) {
         object_free( o );
         st_err_log(42, __FILE__, __LINE__); 
         return CKR_SESSION_READ_ONLY;
      }
   }

   if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
      if (priv_obj) {
         object_free( o );
         st_err_log(57, __FILE__, __LINE__); 
         return CKR_USER_NOT_LOGGED_IN;
      }
   }

   if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
      if (priv_obj) {
         object_free( o );
         st_err_log(57, __FILE__, __LINE__); 
         return CKR_USER_NOT_LOGGED_IN;
      }
   }

   *obj = o;
   return CKR_OK;
}


CK_RV
object_mgr_create_final( SESSION           * sess,
                         OBJECT            * obj,
                         CK_OBJECT_HANDLE  * handle )
{
   CK_BBOOL  sess_obj;
   CK_BBOOL  priv_obj;
   CK_BBOOL  locked = FALSE;
   CK_RV     rc;

   if (!sess || !obj || !handle){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   locked = TRUE;

   sess_obj = object_is_session_object( obj );
   priv_obj = object_is_private( obj );

   if (sess_obj) {
      obj->session = sess;
      memset( obj->name, 0x0, sizeof(CK_BYTE) * 8 );

      sess_obj_list = dlist_add_as_first( sess_obj_list, obj );
   }
   else {
      CK_BYTE current[8];
      CK_BYTE next[8];

      // we'll be modifying nv_token_data so we should protect this part
      // with 'pkcs_mutex'
      //
      rc = XProcLock( xproclock );
      if (rc != CKR_OK){
         st_err_log(150, __FILE__, __LINE__); 
         goto done;
      }
      else {

         // Determine if we have already reached our Max Token Objects
         //
         if (priv_obj) {
            if (global_shm->num_priv_tok_obj >= MAX_TOK_OBJS) {
               XProcUnLock(xproclock);
               st_err_log(1, __FILE__, __LINE__); 
               rc = CKR_HOST_MEMORY;
               goto done;
            }
         }
         else {
            if (global_shm->num_publ_tok_obj >= MAX_TOK_OBJS) {
               XProcUnLock(xproclock);
               st_err_log(1, __FILE__, __LINE__); 
               rc = CKR_HOST_MEMORY;
               goto done;
            }
         }
         memcpy( current, &nv_token_data->next_token_object_name, 8 );

         obj->session = NULL;
         memcpy( &obj->name, current, 8 );

         compute_next_token_obj_name( current, next );
         memcpy( &nv_token_data->next_token_object_name, next, 8 );

         save_token_object( obj );

         // add the object identifier to the shared memory segment
         //
         object_mgr_add_to_shm( obj );

         XProcUnLock( xproclock );

         save_token_data();
      }

      // now, store the object in the token object list in RAM for speed
      //
      if (priv_obj)
         priv_token_obj_list = dlist_add_as_last( priv_token_obj_list, obj );
      else
         publ_token_obj_list = dlist_add_as_last( publ_token_obj_list, obj );
   }

   rc = object_mgr_add_to_map( sess, obj, handle );
   if (rc != CKR_OK) {
      DL_NODE *node = NULL;

      st_err_log(157, __FILE__, __LINE__); 
      // this is messy but we need to remove the object from whatever
      // list we just added it to
      //
      if (sess_obj) {
         node = dlist_find( sess_obj_list, obj );
         if (node)
            sess_obj_list = dlist_remove_node( sess_obj_list, node );
      }
      else {
         // FIXME - need to destroy the token object file too
         //
         delete_token_object( obj );

         if (priv_obj) {
            node = dlist_find( priv_token_obj_list, obj );
            if (node)
               priv_token_obj_list = dlist_remove_node( priv_token_obj_list, node );
         }
         else {
            node = dlist_find( publ_token_obj_list, obj );
            if (node)
               publ_token_obj_list = dlist_remove_node( publ_token_obj_list, node );
         }

         rc = XProcLock( xproclock );
         if (rc != CKR_OK){
            st_err_log(150, __FILE__, __LINE__); 
            goto done;
         }
         object_mgr_del_from_shm( obj );

         XProcUnLock( xproclock );
      }
   }

done:
   if (locked)
      MY_UnlockMutex( &obj_list_mutex );

   return rc;
}


//
//
CK_RV
object_mgr_destroy_object( SESSION          * sess,
                           CK_OBJECT_HANDLE   handle )
{
   OBJECT    * obj = NULL;
   CK_BBOOL    sess_obj;
   CK_BBOOL    priv_obj;
   CK_BBOOL    locked = FALSE;
   CK_RV       rc;


   if (!sess){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      goto done;
   }
   locked = TRUE;

   rc = object_mgr_find_in_map1( handle, &obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      goto done;
   }
   sess_obj = object_is_session_object( obj );
   priv_obj = object_is_private( obj );

   if (sess_obj) {
      DL_NODE *node;

      node = dlist_find( sess_obj_list, obj );
      if (node) {
         object_mgr_remove_from_map( handle );

         object_free( obj );
         sess_obj_list = dlist_remove_node( sess_obj_list, node );

         rc = CKR_OK;
         goto done;
      }
   }
   else {
      DL_NODE *node = NULL;

      delete_token_object( obj );

      if (priv_obj)
         node = dlist_find( priv_token_obj_list, obj );
      else
         node = dlist_find( publ_token_obj_list, obj );

      if (node) {
         rc = XProcLock( xproclock );
         if (rc != CKR_OK){
            st_err_log(150, __FILE__, __LINE__); 
            goto done;
         }
         object_mgr_del_from_shm( obj );

         XProcUnLock( xproclock );

         object_mgr_remove_from_map( handle );

         object_free( obj );


         if (priv_obj)
            priv_token_obj_list = dlist_remove_node( priv_token_obj_list, node );
         else
            publ_token_obj_list = dlist_remove_node( publ_token_obj_list, node );

         rc = CKR_OK;
         goto done;
      }
   }

   st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
   rc = CKR_FUNCTION_FAILED;

done:
   if (locked)
      MY_UnlockMutex( &obj_list_mutex );

   return rc;
}


// this routine will destroy all token objects in the system
//
CK_RV
object_mgr_destroy_token_objects( void )
{
   CK_BBOOL locked1 = FALSE, locked2 = FALSE;
   CK_RV rc;

   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      goto done;
   }
   else
      locked1 = TRUE;

   while (publ_token_obj_list) {
      OBJECT *obj = (OBJECT *)publ_token_obj_list->data;

      CK_OBJECT_HANDLE handle;

      rc = object_mgr_find_in_map2( obj, &handle );
      if (rc == CKR_OK) {
         // only if it's found in the object map.  it might not be there
         //
         object_mgr_remove_from_map( handle );
      }
      else{
         st_err_log(110, __FILE__, __LINE__);
      }
      delete_token_object( obj );
      object_free( obj );

      publ_token_obj_list = dlist_remove_node( publ_token_obj_list, publ_token_obj_list );
   }

   while (priv_token_obj_list) {
      OBJECT *obj = (OBJECT *)priv_token_obj_list->data;

      CK_OBJECT_HANDLE handle;

      rc = object_mgr_find_in_map2( obj, &handle );
      if (rc == CKR_OK) {
         // only if it's found in the object map.  it might not be there
         //
         object_mgr_remove_from_map( handle );
      }
      else{
         st_err_log(110, __FILE__, __LINE__);
      }
      delete_token_object( obj );
      object_free( obj );

      priv_token_obj_list = dlist_remove_node( priv_token_obj_list, priv_token_obj_list );
   }

   // now we want to purge the token object list in shared memory
   //
   rc = XProcLock( xproclock );
   if (rc == CKR_OK) {
      locked2 = TRUE;

      global_shm->num_priv_tok_obj = 0;
      global_shm->num_publ_tok_obj = 0;

      memset( &global_shm->publ_tok_objs, 0x0, MAX_TOK_OBJS * sizeof(TOK_OBJ_ENTRY) );
      memset( &global_shm->priv_tok_objs, 0x0, MAX_TOK_OBJS * sizeof(TOK_OBJ_ENTRY) );
   }
   else
      st_err_log(150, __FILE__, __LINE__); 

done:
   if (locked1 == TRUE) MY_UnlockMutex( &obj_list_mutex );
   if (locked2 == TRUE) XProcUnLock( xproclock );

   return rc;
}


// object_mgr_find_in_map1()
//
// Locates the specified object in the map
//
CK_RV
object_mgr_find_in_map1( CK_OBJECT_HANDLE    handle,
                         OBJECT           ** ptr )
{
   DL_NODE   * node = NULL;
   OBJECT    * obj  = NULL;

   if (!ptr){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   //
   // no mutex here.  the calling function should have locked the mutex
   //

   node = object_map;
   while (node) {
      OBJECT_MAP *map = (OBJECT_MAP *)node->data;

      if (map->handle == handle) {
         obj = map->ptr;
         break;
      }

      node = node->next;
   }

   if (obj == NULL || node == NULL) {
      st_err_log(30, __FILE__, __LINE__); 
      return CKR_OBJECT_HANDLE_INVALID;
   }

   //
   // if this is a token object, we need to check the shared memory segment
   // to see if any other processes have updated the object
   //

   if (object_is_session_object(obj) == TRUE) {
      *ptr = obj;
      return CKR_OK;
   }

   object_mgr_check_shm( obj );

   *ptr = obj;
   return CKR_OK;
}


// object_mgr_find_in_map2()
//
CK_RV
object_mgr_find_in_map2( OBJECT           * obj,
                         CK_OBJECT_HANDLE * handle )
{
   DL_NODE           * node = NULL;
   CK_OBJECT_HANDLE    h    = (CK_OBJECT_HANDLE)NULL;

   if (!obj || !handle){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   //
   // no mutex here.  the calling function should have locked the mutex
   //

   node = object_map;
   while (node) {
      OBJECT_MAP *map = (OBJECT_MAP *)node->data;

      if (map->ptr == obj) {
         h = map->handle;
         break;
      }

      node = node->next;
   }

   if (node == NULL) {
//      st_err_log(30, __FILE__, __LINE__); 
      return CKR_OBJECT_HANDLE_INVALID;
   }

   //
   // if this is a token object, we need to check the shared memory segment
   // to see if any other processes have updated the object
   //

   if (object_is_session_object(obj) == TRUE) {
      *handle = h;
      return CKR_OK;
   }

   object_mgr_check_shm( obj );

   *handle = h;
   return CKR_OK;
}


CK_RV
object_mgr_find_init( SESSION      * sess,
                      CK_ATTRIBUTE * pTemplate,
                      CK_ULONG       ulCount )
{
   // it is possible the pTemplate == NULL
   //

   if (!sess){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   if (sess->find_active != FALSE){
      st_err_log(31, __FILE__, __LINE__); 
      return CKR_OPERATION_ACTIVE;
   }
   // initialize the found object list.  if it doesn't exist, allocate
   // a list big enough for 10 handles.  we'll reallocate if we need more
   //
   if (sess->find_list != NULL) {
      memset( sess->find_list, 0x0, sess->find_len * sizeof(CK_OBJECT_HANDLE) );
   }
   else {
      sess->find_list = (CK_OBJECT_HANDLE *)malloc(10 * sizeof(CK_OBJECT_HANDLE));
      if (!sess->find_list){
         st_err_log(0, __FILE__, __LINE__); 
         return CKR_HOST_MEMORY;
      }
      else {
         memset( sess->find_list, 0x0, 10 * sizeof(CK_OBJECT_HANDLE) );
         sess->find_len = 10;
      }
   }

   sess->find_count = 0;
   sess->find_idx   = 0;

//  --- need to grab the object lock here 
   MY_LockMutex(&obj_list_mutex);
   object_mgr_update_from_shm();
   MY_UnlockMutex(&obj_list_mutex);

   // which objects can be returned:
   //
   //   Public Session:   public session objects, public token objects
   //   User Session:     all session objects,    all token objects
   //   SO session:       public session objects, public token objects
   //
   switch (sess->session_info.state) {
      case CKS_RO_PUBLIC_SESSION:
      case CKS_RW_PUBLIC_SESSION:
      case CKS_RW_SO_FUNCTIONS:
         object_mgr_find_build_list( sess, pTemplate, ulCount, publ_token_obj_list, TRUE );
         object_mgr_find_build_list( sess, pTemplate, ulCount, sess_obj_list,       TRUE );
         break;

      case CKS_RO_USER_FUNCTIONS:
      case CKS_RW_USER_FUNCTIONS:
         object_mgr_find_build_list( sess, pTemplate, ulCount, priv_token_obj_list, FALSE );
         object_mgr_find_build_list( sess, pTemplate, ulCount, publ_token_obj_list, FALSE );
         object_mgr_find_build_list( sess, pTemplate, ulCount, sess_obj_list,  FALSE );
         break;
   }

   sess->find_active = TRUE;

   return CKR_OK;
}


//
//
CK_RV
object_mgr_find_build_list( SESSION      * sess,
                            CK_ATTRIBUTE * pTemplate,
                            CK_ULONG       ulCount,
                            DL_NODE      * obj_list,
                            CK_BBOOL       public_only )
{
   OBJECT           * obj  = NULL;
   DL_NODE          * node = NULL;
   CK_OBJECT_HANDLE   handle;
   CK_BBOOL           is_priv;
   CK_BBOOL           match;
   CK_BBOOL           hw_feature = FALSE;
   CK_BBOOL           hidden_object = FALSE;
   CK_RV              rc;
   CK_ATTRIBUTE     * attr;
   int		      i;

   // pTemplate == NULL is a legal condition here
   //

   if (!sess){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   // it's possible that the object list is empty
   //
   if (!obj_list)
      return CKR_OK;

   // PKCS#11 v2.11 (pg. 79): "When searching using C_FindObjectsInit
   // and C_FindObjects, hardware feature objects are not returned
   // unless the CKA_CLASS attribute in the template has the value
   // CKO_HW_FEATURE." So, we check for CKO_HW_FEATURE and if its set, 
   // we'll find these objects below. - KEY
   for (i = 0; i < ulCount; i++) {
      if (pTemplate[i].type == CKA_CLASS) {
	 if (*(CK_ULONG *)pTemplate[i].pValue == CKO_HW_FEATURE) {
	    hw_feature = TRUE;
	    break;
	 }
      }

      /* only find CKA_HIDDEN objects if its specified in the template. This
       * is an attribute specific to the TPM token */
      if (pTemplate[i].type == CKA_HIDDEN) {
	 if (*(CK_ULONG *)pTemplate[i].pValue == TRUE) {
	    hidden_object = TRUE;
	    break;
	 }
      }
   }

   node = obj_list;
   while (node) {
      match   = FALSE;
      obj     = (OBJECT *)node->data;
      is_priv = object_is_private( obj );


      if ((is_priv == FALSE) || (public_only == FALSE)) {
         // if the user doesn't specify any template attributes then we return
         // all objects
         //
         if (pTemplate == NULL || ulCount == 0)
            match = TRUE;
         else
            match = template_compare( pTemplate, ulCount, obj->template );
      }

      // if we have a match, find the object in the map (add it if necessary)
      // then add the object to the list of found objects
      //
      if (match) {
         rc = object_mgr_find_in_map2( obj, &handle );
         if (rc != CKR_OK) {
            //st_err_log(110, __FILE__, __LINE__);
            rc = object_mgr_add_to_map( sess, obj, &handle );
            if (rc != CKR_OK){
               st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
               return CKR_FUNCTION_FAILED;
            }
         }
         if (rc == CKR_OK) {
	    // If hw_feature is false here, we need to filter out all objects
	    // that have the CKO_HW_FEATURE attribute set. - KEY
            if ((hw_feature == FALSE) &&
	        (template_attribute_find(obj->template, CKA_CLASS, &attr) == TRUE)) {
               if (*(CK_OBJECT_CLASS *)attr->pValue == CKO_HW_FEATURE)
	          goto next_loop;
	    }

	    /* Don't find objects created by the TPM token */
            if ((hidden_object == FALSE) &&
                (template_attribute_find(obj->template, CKA_HIDDEN, &attr) == TRUE)) {
               if (*(CK_OBJECT_CLASS *)attr->pValue == TRUE)
	          goto next_loop;
	    }

            sess->find_list[ sess->find_count ] = handle;
            sess->find_count++;

            if (sess->find_count >= sess->find_len) {
               sess->find_len += 15;
               sess->find_list = (CK_OBJECT_HANDLE *)realloc( sess->find_list,
                                                              sess->find_len * sizeof(CK_OBJECT_HANDLE) );
               if (!sess->find_list){
                  st_err_log(0, __FILE__, __LINE__);
                  return CKR_HOST_MEMORY;
               }
            }
         }
      }
next_loop:
      node = node->next;
   }

   return CKR_OK;
}


//
//
CK_RV
object_mgr_find_final( SESSION *sess )
{
   if (!sess){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   if (sess->find_active == FALSE){
      st_err_log(32, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_OPERATION_NOT_INITIALIZED;
   }
   free( sess->find_list );
   sess->find_list   = NULL;
   sess->find_count  = 0;
   sess->find_idx    = 0;
   sess->find_active = FALSE;

   return CKR_OK;
}


//
//
CK_RV
object_mgr_get_attribute_values( SESSION           * sess,
                                 CK_OBJECT_HANDLE    handle,
                                 CK_ATTRIBUTE      * pTemplate,
                                 CK_ULONG            ulCount )
{
   OBJECT   * obj;
   CK_BBOOL   priv_obj;
   CK_BBOOL   locked = FALSE;
   CK_RV      rc;

   if (!pTemplate){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   locked = TRUE;

   rc = object_mgr_find_in_map1( handle, &obj );
   if (rc != CKR_OK){
      st_err_log(110, __FILE__, __LINE__);
      goto done;
   }
   priv_obj = object_is_private( obj );

   if (priv_obj == TRUE) {
      if (sess->session_info.state == CKS_RO_PUBLIC_SESSION ||
          sess->session_info.state == CKS_RW_PUBLIC_SESSION)
      {
         st_err_log(57, __FILE__, __LINE__); 
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }
   }

   rc = object_get_attribute_values( obj, pTemplate, ulCount );
   if (rc != CKR_OK)
         st_err_log(159, __FILE__, __LINE__); 
done:
   if (locked)
      MY_UnlockMutex( &obj_list_mutex );

   return rc;
}


//
//
CK_RV
object_mgr_get_object_size( CK_OBJECT_HANDLE   handle,
                            CK_ULONG         * size )
{
   OBJECT    * obj;
   CK_RV       rc;

   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   rc = object_mgr_find_in_map1( handle, &obj );
   if (rc != CKR_OK) {
      st_err_log(30, __FILE__, __LINE__);
      rc = CKR_OBJECT_HANDLE_INVALID;
      goto done;
   }

   *size = object_get_size( obj );

done:
   MY_UnlockMutex( &obj_list_mutex );
   return rc;
}


// object_mgr_invalidate_handle1()
//
// Returns:  TRUE  if successfully removes the node
//           FALSE if cannot remove the node (not found, etc)
//
CK_BBOOL
object_mgr_invalidate_handle1( CK_OBJECT_HANDLE handle )
{
   DL_NODE *node = NULL;

   //
   // no mutex stuff here.  the calling routine should have locked the mutex
   //

   node = object_map;

   while (node) {
      OBJECT_MAP *map = (OBJECT_MAP *)node->data;

      // I think we can do this because even token objects exist in RAM
      //
      if (map->handle == handle) {
         object_map = dlist_remove_node( object_map, node );
         free( map );

         return TRUE;
      }

      node = node->next;
   }

   return FALSE;

}


// object_mgr_invalidate_handle2()
//
// Returns:  TRUE  if successfully removes the node
//           FALSE if cannot remove the node (not found, etc)
//
CK_BBOOL
object_mgr_invalidate_handle2( OBJECT *obj )
{
   DL_NODE *node = NULL;

   if (!obj)
      return FALSE;

   //
   // no mutex stuff here.  the calling routine should have locked the mutex
   //

   node = object_map;

   while (node) {
      OBJECT_MAP *map = (OBJECT_MAP *)node->data;

      // I think we can do this because even token objects exist in RAM
      //
      if (map->ptr == obj) {
         object_map = dlist_remove_node( object_map, node );
         free( map );

         return TRUE;
      }

      node = node->next;
   }

   return FALSE;

}


// object_mgr_purge_session_objects()
//
// Args:    SESSION *
//          SESS_OBJ_TYPE:  can be ALL, PRIVATE or PUBLIC
//
// Remove all session objects owned by the specified session satisfying
// the 'type' requirements
//
CK_BBOOL
object_mgr_purge_session_objects( SESSION       * sess,
                                  SESS_OBJ_TYPE   type )
{
   DL_NODE   *node = NULL;
   DL_NODE   *next = NULL;
   OBJECT    *obj = NULL;
   CK_BBOOL   del;
   CK_RV      rc;

   if (!sess)
      return FALSE;

   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return FALSE;
   }
   node = sess_obj_list;

   while (node) {
      obj = (OBJECT *)node->data;
      del = FALSE;

      if (obj->session == sess) {
         if (type == PRIVATE) {
            if (object_is_private(obj))
               del = TRUE;
         }
         else if (type == PUBLIC) {
            if (object_is_public(obj))
               del = TRUE;
         }
         else if (type == ALL)
            del = TRUE;
      }

      if (del == TRUE) {
         CK_OBJECT_HANDLE handle;
         CK_RV            rc;

         rc = object_mgr_find_in_map2( obj, &handle );
         if (rc == CKR_OK) {
            object_mgr_invalidate_handle1( handle );
            object_free( obj );
         }
         else
            st_err_log(110, __FILE__, __LINE__);

         next = node->next;
         sess_obj_list = dlist_remove_node( sess_obj_list, node );
         node = next;
      }
      else
         node = node->next;
   }

   MY_UnlockMutex( &obj_list_mutex );

   return TRUE;
}


// this routine cleans up the list of token objects.  in general, we don't
// need to do this but when tracing memory leaks, it's best that we free everything
// that we've allocated
//
CK_BBOOL
object_mgr_purge_token_objects( )
{
   DL_NODE   *node = NULL;
   DL_NODE   *next = NULL;
   OBJECT    *obj = NULL;
   CK_RV      rc;

   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return FALSE;
   }
   node = publ_token_obj_list;
   while (publ_token_obj_list) {
      CK_OBJECT_HANDLE handle;
      CK_RV            rc;

      obj = (OBJECT *)node->data;

      rc = object_mgr_find_in_map2( obj, &handle );
      if (rc == CKR_OK){
         object_mgr_invalidate_handle1( handle );
      }
      object_free( obj );

      next = node->next;
      publ_token_obj_list = dlist_remove_node( publ_token_obj_list, node );
      node = next;
   }

   node = priv_token_obj_list;

   while (priv_token_obj_list) {
      CK_OBJECT_HANDLE handle;
      CK_RV            rc;

      obj = (OBJECT *)node->data;

      rc = object_mgr_find_in_map2( obj, &handle );
      if (rc == CKR_OK)
         object_mgr_invalidate_handle1( handle );
      else{
         st_err_log(110, __FILE__, __LINE__);
      }
      object_free( obj );

      next = node->next;
      priv_token_obj_list = dlist_remove_node( priv_token_obj_list, node );
      node = next;
   }

   MY_UnlockMutex( &obj_list_mutex );

   return TRUE;
}


CK_BBOOL
object_mgr_purge_private_token_objects( void )
{
   OBJECT   * obj  = NULL;
   DL_NODE  * node = NULL;
   DL_NODE  * next = NULL;
   CK_RV      rc;

   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return FALSE;
   }
   node = priv_token_obj_list;
   while (priv_token_obj_list) {
      CK_OBJECT_HANDLE handle;
      CK_RV            rc;

      obj = (OBJECT *)node->data;

      rc = object_mgr_find_in_map2( obj, &handle );
      if (rc == CKR_OK){
         object_mgr_invalidate_handle1( handle );
      }
      else{
         st_err_log(110, __FILE__, __LINE__);
      }
      object_free( obj );

      next = node->next;
      priv_token_obj_list = dlist_remove_node( priv_token_obj_list, node );
      node = next;
   }

   MY_UnlockMutex( &obj_list_mutex );

   return TRUE;
}


// object_mgr_remove_from_map()
//
CK_RV
object_mgr_remove_from_map( CK_OBJECT_HANDLE  handle )
{
   DL_NODE  *node = NULL;

   //
   // no mutex stuff here.  the calling routine should have locked the mutex
   //

   node = object_map;
   while (node) {
      OBJECT_MAP *map = (OBJECT_MAP *)node->data;

      if (map->handle == handle) {
         object_map = dlist_remove_node( object_map, node );
         free( map );
         return CKR_OK;
      }

      node = node->next;
   }

   st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
   return CKR_FUNCTION_FAILED;
}


//
//
CK_RV
object_mgr_restore_obj( CK_BYTE *data, OBJECT *oldObj )
{
   OBJECT    * obj  = NULL;
   CK_BBOOL    priv;
   CK_RV       rc;

   if (!data){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   // The calling stack MUST have the mutex
   // to many grab it now.
#if 0
   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK)
      return rc;
#endif

   if (oldObj != NULL) {
      obj = oldObj;
      rc = object_restore( data, &obj, TRUE );
   }
   else {
      rc = object_restore( data, &obj, FALSE );
      if (rc == CKR_OK) {
         priv = object_is_private( obj );

         if (priv)
            priv_token_obj_list = dlist_add_as_last( priv_token_obj_list, obj );
         else
            publ_token_obj_list = dlist_add_as_last( publ_token_obj_list, obj );

         XProcLock( xproclock );
           
         if (priv) {
            if (global_shm->priv_loaded == FALSE){
               if (global_shm->num_priv_tok_obj < MAX_TOK_OBJS) 
                  object_mgr_add_to_shm( obj );
               else{
                  st_err_log(1, __FILE__, __LINE__); 
                  rc = CKR_HOST_MEMORY;
               }
            }
         } else {
            if (global_shm->publ_loaded == FALSE){
               if (global_shm->num_publ_tok_obj < MAX_TOK_OBJS) 
                  object_mgr_add_to_shm( obj );
               else{
                  st_err_log(1, __FILE__, __LINE__); 
                  rc = CKR_HOST_MEMORY;
               }
            }
         }

         XProcUnLock( xproclock );
      } else {
         st_err_log(160, __FILE__, __LINE__); 
      }
   }

   // make the callers have to have the mutes
   // to many grab it now.
#if 0
   MY_UnlockMutex( &obj_list_mutex );
#endif
   return rc;
}


//
//
CK_RV
object_mgr_set_attribute_values( SESSION           * sess,
                                 CK_OBJECT_HANDLE    handle,
                                 CK_ATTRIBUTE      * pTemplate,
                                 CK_ULONG            ulCount )
{
   OBJECT    * obj;
   CK_BBOOL    sess_obj, priv_obj;
   CK_BBOOL    modifiable;
   CK_RV       rc;


   if (!pTemplate){
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
      return CKR_FUNCTION_FAILED;
   }
   rc = MY_LockMutex( &obj_list_mutex );
   if (rc != CKR_OK){
      st_err_log(146, __FILE__, __LINE__); 
      return rc;
   }
   rc = object_mgr_find_in_map1( handle, &obj );
   MY_UnlockMutex( &obj_list_mutex );

   if (rc != CKR_OK) {
      st_err_log(110, __FILE__, __LINE__);
      return CKR_OBJECT_HANDLE_INVALID;
   }


   // determine whether the session is allowed to modify the object
   //
   modifiable = object_is_modifiable( obj );
   sess_obj   = object_is_session_object( obj );
   priv_obj   = object_is_private( obj );

   // if object is not modifiable, it doesn't matter what kind of session
   // is issuing the request...
   //
   if (!modifiable){
      st_err_log(7, __FILE__, __LINE__); 
      return CKR_ATTRIBUTE_READ_ONLY;
   }
   if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
      if (priv_obj){
         st_err_log(57, __FILE__, __LINE__); 
         return CKR_USER_NOT_LOGGED_IN;
      }
      if (!sess_obj){
         st_err_log(42, __FILE__, __LINE__); 
         return CKR_SESSION_READ_ONLY;
      }
   }

   if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
      if (!sess_obj){
         st_err_log(42, __FILE__, __LINE__); 
         return CKR_SESSION_READ_ONLY;
      }
   }

   if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
      if (priv_obj){
         st_err_log(57, __FILE__, __LINE__); 
         return CKR_USER_NOT_LOGGED_IN;
      }
   }

   if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
      if (priv_obj){
         st_err_log(57, __FILE__, __LINE__); 
         return CKR_USER_NOT_LOGGED_IN;
      }
   }


   rc = object_set_attribute_values( obj, pTemplate, ulCount );
   if (rc != CKR_OK){
      st_err_log(161, __FILE__, __LINE__); 
      return rc;
   }
   // okay.  the object has been updated.  if it's a session object,
   // we're finished.  if it's a token object, we need to update
   // non-volatile storage.
   //
   if (!sess_obj) {
      TOK_OBJ_ENTRY  *entry = NULL;
      CK_ULONG        index;

      // I still think there's a race condition here if two processes are
      // updating the same token object at the same time.  I don't know how
      // to solve this short of assigning each token object it's own mutex...
      //
      obj->count_lo++;
      if (obj->count_lo == 0)
         obj->count_hi++;

      save_token_object( obj );

      rc = XProcLock( xproclock );
      if (rc != CKR_OK){
         st_err_log(150, __FILE__, __LINE__); 
         return rc;
      }
      if (priv_obj) {
         rc = object_mgr_search_shm_for_obj( global_shm->priv_tok_objs,
                                             0, global_shm->num_priv_tok_obj-1,
                                             obj, &index );

         if (rc != CKR_OK) {
            st_err_log(162, __FILE__, __LINE__); 
            XProcUnLock(xproclock);
            return rc;
         }

         entry = &global_shm->priv_tok_objs[index];
      }
      else {
         rc = object_mgr_search_shm_for_obj( global_shm->publ_tok_objs,
                                             0, global_shm->num_publ_tok_obj-1,
                                             obj, &index );
         if (rc != CKR_OK) {
            st_err_log(162, __FILE__, __LINE__); 
            XProcUnLock(xproclock);
            return rc;
         }

         entry = &global_shm->publ_tok_objs[index];
      }

      entry->count_lo = obj->count_lo;
      entry->count_hi = obj->count_hi;

      XProcUnLock( xproclock );
   }

   return rc;
}


//
//
CK_RV
object_mgr_add_to_shm( OBJECT *obj )
{
   TOK_OBJ_ENTRY  * entry  = NULL;
   CK_BBOOL         priv;

   // the calling routine is responsible for locking the global_shm mutex
   //

   priv = object_is_private( obj );

   if (priv)
      entry = &global_shm->priv_tok_objs[global_shm->num_priv_tok_obj];
   else
      entry = &global_shm->publ_tok_objs[global_shm->num_publ_tok_obj];

   entry->deleted  = FALSE;
   entry->count_lo = 0;
   entry->count_hi = 0;
   memcpy( entry->name, obj->name, 8 );

   if (priv) {
      global_shm->num_priv_tok_obj++;
      object_mgr_sort_priv_shm();
   }
   else {
      global_shm->num_publ_tok_obj++;
      object_mgr_sort_publ_shm();
   }

   return CKR_OK;
}


//
//
CK_RV
object_mgr_del_from_shm( OBJECT *obj )
{
   TOK_OBJ_ENTRY   * entry = NULL;
   CK_BYTE         * ptr;
   CK_ULONG          index, count;
   CK_BBOOL          priv;
   CK_RV             rc;


   // the calling routine is responsible for locking the global_shm mutex
   //

   priv = object_is_private( obj );

   if (priv) {
      rc = object_mgr_search_shm_for_obj( global_shm->priv_tok_objs,
                                          0, global_shm->num_priv_tok_obj-1,
                                          obj, &index );
      if (rc != CKR_OK){
         st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
         return CKR_FUNCTION_FAILED;
      }
      // Since the number of objects starts at 1 and index starts at zero, we
      // decrement before we get count.  This eliminates the need to perform
      // this operation later as well as decrementing the number of objects.
      // (i.e. If we have 10 objects, num will be 10 but the last index is 9.
      // If we want to delete the last object we need to subtract 9 from 9 not
      // 10 from 9.)
      //
      global_shm->num_priv_tok_obj--;
      count = global_shm->num_priv_tok_obj - index;

      if (count > 0) {  // If we are not deleting the last element in the list
         // Move up count number of elements effectively deleting the index
         bcopy((char *)&global_shm->priv_tok_objs[index+1],
               (char *)&global_shm->priv_tok_objs[index],
               sizeof(TOK_OBJ_ENTRY) * count );
         // We need to zero out the last entry... Since the memcopy
         // does not zero it out...
         bzero((char *)&global_shm->priv_tok_objs[global_shm->num_priv_tok_obj+1],
                sizeof(TOK_OBJ_ENTRY));
      }
      else { // We are deleting the last element which is in num_priv_tok_obj
         bzero((char *)&global_shm->priv_tok_objs[global_shm->num_priv_tok_obj],
                sizeof(TOK_OBJ_ENTRY));
      }
   }
   else {
      rc = object_mgr_search_shm_for_obj( global_shm->publ_tok_objs,
                                          0, global_shm->num_publ_tok_obj-1,
                                          obj, &index );
      if (rc != CKR_OK){
         st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
         return CKR_FUNCTION_FAILED;
      }
      global_shm->num_publ_tok_obj--;
      count = global_shm->num_publ_tok_obj - index;

      if (count > 0) {
         bcopy((char *)&global_shm->publ_tok_objs[index+1],
               (char *)&global_shm->publ_tok_objs[index],
               sizeof(TOK_OBJ_ENTRY) * count);
         // We need to zero out the last entry... Since the memcopy
         // does not zero it out...
         bzero((char *)&global_shm->publ_tok_objs[global_shm->num_publ_tok_obj+1],
                sizeof(TOK_OBJ_ENTRY));
      }
      else {
         bzero((char *)&global_shm->publ_tok_objs[global_shm->num_publ_tok_obj],
                sizeof(TOK_OBJ_ENTRY));
      }
   }

   //
   // object list is still sorted...so no need to re-sort
   //

   return CKR_OK;
}


//
//
CK_RV
object_mgr_check_shm( OBJECT *obj )
{
   TOK_OBJ_ENTRY   * entry = NULL;
   CK_BBOOL          priv;
   CK_ULONG          index;
   CK_RV             rc;


   // the calling routine is responsible for locking the global_shm mutex
   //

   priv = object_is_private( obj );

   if (priv) {
      rc = object_mgr_search_shm_for_obj( global_shm->priv_tok_objs,
                                          0, global_shm->num_priv_tok_obj-1,
                                          obj, &index );
      if (rc != CKR_OK){
         st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
         return CKR_FUNCTION_FAILED;
      }
      entry = &global_shm->priv_tok_objs[index];
   }
   else {
      rc = object_mgr_search_shm_for_obj( global_shm->publ_tok_objs,
                                          0, global_shm->num_publ_tok_obj-1,
                                          obj, &index );
      if (rc != CKR_OK){
         st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
         return CKR_FUNCTION_FAILED;
      }
      entry = &global_shm->publ_tok_objs[index];
   }

   if ((obj->count_hi == entry->count_hi) && (obj->count_lo == entry->count_lo))
      return CKR_OK;

   rc = reload_token_object( obj );
   return rc;
}


// I'd use the standard bsearch() routine but I want an index, not a pointer.
// Converting the pointer to an index might cause problems when switching
// to a 64-bit environment...
//
CK_RV
object_mgr_search_shm_for_obj( TOK_OBJ_ENTRY  * obj_list,
                               CK_ULONG         lo,
                               CK_ULONG         hi,
                               OBJECT         * obj,
                               CK_ULONG       * index )
{
   CK_ULONG    mid;
   int         val;

#if 1
   CK_ULONG   idx;
   for (idx=0;idx<=hi;idx++){
      if (memcmp(obj->name, obj_list[idx].name,8) == 0) {
         *index = idx;
         return CKR_OK;
      }
   }
   st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
   return CKR_FUNCTION_FAILED;
#else

   if (lo == hi) {
      if (memcmp(obj->name, obj_list[lo].name, 8) == 0) {
         *index = lo;
         return CKR_OK;
      }
      else{ 
         st_err_log(4, __FILE__, __LINE__, __FUNCTION__); 
         return CKR_FUNCTION_FAILED;
      }
   }

   mid = (lo + hi) / 2;

   val = memcmp( obj->name, obj_list[mid].name, 8 );

   if (val == 0) {
      *index = mid;
      return CKR_OK;
   }

   if (val < 0)
      return object_mgr_search_shm_for_obj( obj_list, lo, mid-1, obj, index );
   else
      return object_mgr_search_shm_for_obj( obj_list, mid+1, hi, obj, index );
#endif
}


//
//
CK_RV
object_mgr_sort_priv_shm( void )
{
   // for now, we assume the list is sorted by design.  this is not unreasonable
   // since new object handles are assigned in increasing order.  problems
   // will arise after 36^8 token objects have been created...
   //
   return CKR_OK;
}


//
//
CK_RV
object_mgr_sort_publ_shm( void )
{
   // for now, we assume the list is sorted by design.  this is not unreasonable
   // since new object handles are assigned in increasing order.  problems
   // will arise after 36^8 token objects have been created...
   //
   return CKR_OK;
}


// this routine scans the local token object lists and updates any objects that
// have changed.  it also adds any new token objects that have been added by
// other processes and deletes any objects that have been deleted by other
// processes
//
CK_RV
object_mgr_update_from_shm( void )
{
   object_mgr_update_publ_tok_obj_from_shm();
   object_mgr_update_priv_tok_obj_from_shm();
}


//
//
CK_RV
object_mgr_update_publ_tok_obj_from_shm()
{
   DL_NODE           * node = NULL;
   DL_NODE           * next = NULL;
   TOK_OBJ_ENTRY     * te   = NULL;
   OBJECT            * obj  = NULL;
   CK_OBJECT_HANDLE    handle;
   CK_ULONG            index;
   CK_BBOOL            cont;
   int                 val;
   CK_RV               rc;

   node  = publ_token_obj_list;
   index = 0;

   while ((node != NULL) && (index < global_shm->num_publ_tok_obj)) {
      te = &global_shm->publ_tok_objs[index];
      obj = (OBJECT *)node->data;

      val = memcmp( obj->name, te->name, 8 );

      // 3 cases:
      //    1) object in local list but not in the global list.  need to remove from local list
      //    2) object in both lists.  need to compare counters and update as needed
      //    3) object in global list but not in the local list.  need to add the object here.
      //
      if (val < 0) {
         rc = object_mgr_find_in_map2( obj, &handle );
         if (rc == CKR_OK){
            st_err_log(110, __FILE__, __LINE__);
            object_mgr_remove_from_map( handle );
         }
         object_free( obj );

         // we don't call delete_token_object since we assume it has been called by
         // another process already.  we just want to remove it from the local list
         //
         next = node->next;
         publ_token_obj_list = dlist_remove_node( publ_token_obj_list, node );

         // don't increment the index
      }
      else if (val == 0) {
         if ((te->count_hi != obj->count_hi) || (te->count_lo != obj->count_lo)) {
            reload_token_object( obj );
			obj->count_hi = te->count_hi;
			obj->count_lo = te->count_lo;
		 }

         next = node->next;
         index++;
      }
      else {
         DL_NODE  *new_node = NULL;
         OBJECT   *new_obj  = NULL;

         new_obj = (OBJECT *)malloc(sizeof(OBJECT));
         memset( new_obj, 0x0, sizeof(OBJECT) );

         memcpy( new_obj->name, te->name, 8 );
         reload_token_object( new_obj );

         // insert the new object into this position in the local list.  I don't
         // like accessing the DL_NODE internals like this but this is the best
         // way for the time being...
         //
         // We really need a dlist_insert() routine!
         //
         new_node = (DL_NODE *)malloc(sizeof(DL_NODE));
         new_node->data = new_obj;

         // this won't work if the list doesn't already exist but that's not a problem
         // here because if it doesn't exist we won't fall through this
         //
         new_node->next = node->next;
         node->next     = new_node;
         new_node->prev = node;

         next = new_node->next;
         index++;
      }

      node = next;
   }

   if ((node == NULL) && (index < global_shm->num_publ_tok_obj)) {
      DL_NODE  *new_node = NULL;
      OBJECT   *new_obj  = NULL;
      int       i;

      // new items added to the end of the list
      //

      for (i=index; i < global_shm->num_publ_tok_obj; i++) {
         new_obj = (OBJECT *)malloc(sizeof(OBJECT));
         memset( new_obj, 0x0, sizeof(OBJECT) );

         te = &global_shm->publ_tok_objs[index];

         memcpy( new_obj->name, te->name, 8 );
         reload_token_object( new_obj );

         // insert the new object at the end of the local list
         //
         publ_token_obj_list = dlist_add_as_last( publ_token_obj_list, new_obj );
      }
   }
   else if ((node != NULL) && (index >= global_shm->num_publ_tok_obj)) {
      while (node) {
         obj = (OBJECT *)node->data;

         rc = object_mgr_find_in_map2( obj, &handle );
         if (rc == CKR_OK){
            st_err_log(110, __FILE__, __LINE__);
            object_mgr_remove_from_map( handle );
         }
         object_free( obj );

         // we don't call delete_token_object since we assume it has been called by
         // another process already.  we just want to remove it from the local list
         //
         next = node->next;
         publ_token_obj_list = dlist_remove_node( publ_token_obj_list, node );

         node = next;
      }
   }

   return CKR_OK;
}


//
//
CK_RV
object_mgr_update_priv_tok_obj_from_shm()
{
   DL_NODE           * node = NULL;
   DL_NODE           * next = NULL;
   TOK_OBJ_ENTRY     * te   = NULL;
   OBJECT            * obj  = NULL;
   CK_OBJECT_HANDLE    handle;
   CK_ULONG            index;
   CK_BBOOL            cont;
   int                 val;
   CK_RV               rc;

   node  = priv_token_obj_list;
   index = 0;

   // SAB XXX don't bother doing this call if we are not in the correct
   // login state
   if ( !(global_login_state == CKS_RW_USER_FUNCTIONS ||
          global_login_state == CKS_RO_USER_FUNCTIONS)){
      return CKR_OK;
   }


   while ((node != NULL) && (index < global_shm->num_priv_tok_obj)) {
      te = &global_shm->priv_tok_objs[index];
      obj = (OBJECT *)node->data;

      val = memcmp( obj->name, te->name, 8 );

      // 3 cases:
      //    1) object in local list but not in the global list.  need to remove from local list
      //    2) object in both lists.  need to compare counters and update as needed
      //    3) object in global list but not in the local list.  need to add the object here.
      //
      if (val < 0) {
         rc = object_mgr_find_in_map2( obj, &handle );
         if (rc == CKR_OK){
            st_err_log(110, __FILE__, __LINE__);
            object_mgr_remove_from_map( handle );
         }
         object_free( obj );

         // we don't call delete_token_object since we assume it has been called by
         // another process already.  we just want to remove it from the local list
         //
         next = node->next;
         priv_token_obj_list = dlist_remove_node( priv_token_obj_list, node );

         // don't increment the index
      }
      else if (val == 0) {
         if ((te->count_hi != obj->count_hi) || (te->count_lo != obj->count_lo)){
            reload_token_object( obj );
			obj->count_hi = te->count_hi;
			obj->count_lo = te->count_lo;
		 }

         next = node->next;
         index++;
      }
      else {
         DL_NODE  *new_node = NULL;
         OBJECT   *new_obj  = NULL;

         new_obj = (OBJECT *)malloc(sizeof(OBJECT));
         memset( new_obj, 0x0, sizeof(OBJECT) );

         memcpy( new_obj->name, te->name, 8 );
         reload_token_object( new_obj );

         // insert the new object into this position in the local list.  I don't
         // like accessing the DL_NODE internals like this but this is the best
         // way for the time being...
         //
         // We really need a dlist_insert() routine!
         //
         new_node = (DL_NODE *)malloc(sizeof(DL_NODE));
         new_node->data = new_obj;

         // this won't work if the list doesn't already exist but that's not a problem
         // here because if it doesn't exist we won't fall through this
         //
         new_node->next = node->next;
         node->next     = new_node;
         new_node->prev = node;

         next = new_node->next;
         index++;
      }

      node = next;
   }

   if ((node == NULL) && (index < global_shm->num_priv_tok_obj)) {
      DL_NODE  *new_node = NULL;
      OBJECT   *new_obj  = NULL;
      int       i;

      // new items added to the end of the list
      //

      for (i=index; i < global_shm->num_priv_tok_obj; i++) {
         new_obj = (OBJECT *)malloc(sizeof(OBJECT));
         memset( new_obj, 0x0, sizeof(OBJECT) );

         te = &global_shm->priv_tok_objs[index];

         memcpy( new_obj->name, te->name, 8 );
         reload_token_object( new_obj );

         // insert the new object at the end of the local list
         //
         priv_token_obj_list = dlist_add_as_last( priv_token_obj_list, new_obj );
      }
   }
   else if ((node != NULL) && (index >= global_shm->num_priv_tok_obj)) {
      while (node) {
         obj = (OBJECT *)node->data;

         rc = object_mgr_find_in_map2( obj, &handle );
         if (rc == CKR_OK){
            st_err_log(110, __FILE__, __LINE__);
            object_mgr_remove_from_map( handle );
         }
         object_free( obj );

         // we don't call delete_token_object since we assume it has been called by
         // another process already.  we just want to remove it from the local list
         //
         next = node->next;
         priv_token_obj_list = dlist_remove_node( priv_token_obj_list, node );

         node = next;
      }
   }

   return CKR_OK;
}

// SAB FIXME FIXME

CK_BBOOL
object_mgr_purge_map(
                      SESSION       * sess,
                      SESS_OBJ_TYPE   type )
{
   DL_NODE *node = NULL;
   DL_NODE *next = NULL;

//  if (!proc || !sess)
//      return FALSE;

   node = object_map;

   while (node) {
      OBJECT_MAP *map = (OBJECT_MAP *)node->data;
      OBJECT     *obj = (OBJECT *)map->ptr;

      next = node->next;

      if (type == PRIVATE) {
         if (object_is_private(obj)) {
            object_map = dlist_remove_node( object_map, node );
            free( map );
         }
      }

      if (type == PUBLIC) {
         if (object_is_public(obj)) {
            object_map = dlist_remove_node( object_map, node );
            free( map );
         }
      }

      node = next;
   }

   return TRUE;
}

