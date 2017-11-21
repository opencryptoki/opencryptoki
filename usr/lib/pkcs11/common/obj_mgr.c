/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  obj_mgr.c
//
// Object manager related functions
//

#include <pthread.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>  // for memcmp() et al
#include <strings.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"

#include "../api/apiproto.h"

CK_RV
object_mgr_add( STDLL_TokData_t  * tokdata,
		SESSION          * sess,
                CK_ATTRIBUTE     * pTemplate,
                CK_ULONG           ulCount,
                CK_OBJECT_HANDLE * handle )
{
   OBJECT    * o = NULL;
   CK_BBOOL    priv_obj, sess_obj;
   CK_RV       rc;
   unsigned long obj_handle;

   if (!sess || !pTemplate || !handle){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }

   rc = object_create( tokdata, pTemplate, ulCount, &o );
   if (rc != CKR_OK){
      TRACE_DEVEL("Object Create failed.\n");
      goto done;
   }

   if (token_specific.t_object_add != NULL) {
      rc = token_specific.t_object_add(tokdata, o);
      if (rc != CKR_OK) {
	 TRACE_DEVEL("Token specific object add failed.\n");
	 goto done;
      }
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
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }

      if (!sess_obj) {
         TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
         rc = CKR_SESSION_READ_ONLY;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
      if (!sess_obj) {
         TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
         rc = CKR_SESSION_READ_ONLY;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
      if (priv_obj) {
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
      if (priv_obj) {
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
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

      if ((obj_handle = bt_node_add(&sess_obj_btree, o)) == 0) {
	 TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
	 rc = CKR_HOST_MEMORY;
	 goto done;
      }
   }
   else {
      CK_BYTE current[8];
      CK_BYTE next[8];

      // we'll be modifying nv_token_data so we should protect this part with
      // the 'pkcs_mutex'
      //
      rc = XProcLock(tokdata);
      if (rc != CKR_OK){
         TRACE_ERROR("Failed to get Process Lock.\n");
         goto done;
      }
      else {

         // Determine if we have already reached our Max Token Objects
         //
         if (priv_obj) {
            if (tokdata->global_shm->num_priv_tok_obj >= MAX_TOK_OBJS) {
               rc = CKR_HOST_MEMORY;
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               XProcUnLock(tokdata);
               goto done;
            }
         }
         else {
            if (tokdata->global_shm->num_publ_tok_obj >= MAX_TOK_OBJS) {
               rc = CKR_HOST_MEMORY;
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               XProcUnLock(tokdata);
               goto done;
            }
         }

         memcpy( current, &tokdata->nv_token_data->next_token_object_name, 8 );

         o->session = NULL;
         memcpy( &o->name, current, 8 );

         rc = compute_next_token_obj_name( current, next );
         if (rc != CKR_OK) {
                 // TODO: handle error, check if rc is a valid per spec
                XProcUnLock(tokdata);
                 goto done;
         }
         memcpy( &tokdata->nv_token_data->next_token_object_name, next, 8 );

         rc = save_token_object( tokdata, o );
         if (rc != CKR_OK) {
                 // TODO: handle error, check if rc is a valid per spec
                XProcUnLock(tokdata);
                goto done;
         }

         // add the object identifier to the shared memory segment
         //
         object_mgr_add_to_shm( o, tokdata->global_shm);

         // save_token_data has to lock the mutex itself because it's used elsewhere
         //
         rc = save_token_data(tokdata, sess->session_info.slotID);
         if (rc != CKR_OK) {
                 // TODO: handle error, check if rc is a valid per spec
                XProcUnLock(tokdata);
                goto done;
         }

         XProcUnLock(tokdata);

      }

      // now, store the object in the appropriate btree
      //
      if (priv_obj)
         obj_handle = bt_node_add(&priv_token_obj_btree, o);
      else
         obj_handle = bt_node_add(&publ_token_obj_btree, o);

      if (!obj_handle) {
	 TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
	 rc = CKR_HOST_MEMORY;
	 goto done;
      }
   }

   rc = object_mgr_add_to_map( tokdata, sess, o, obj_handle, handle );
   if (rc != CKR_OK) {
      // we need to remove the object from whatever btree we just added it to
      if (sess_obj) {
	 // put the binary tree node which holds o on the free list, but pass NULL here, so that
	 // o (the binary tree node's value pointer) isn't touched. It is free'd below
	 bt_node_free(&sess_obj_btree, obj_handle, NULL);
      }
      else {
         // we'll want to delete the token object file too!
         //
         delete_token_object( tokdata, o );

         if (priv_obj) {
	    // put the binary tree node which holds o on the free list, but pass NULL here, so that
	    // o (the binary tree node's value pointer) isn't touched. It is free'd below
	    bt_node_free(&priv_token_obj_btree, obj_handle, NULL);
         }
         else {
	    // put the binary tree node which holds o on the free list, but pass NULL here, so that
	    // o (the binary tree node's value pointer) isn't touched. It is free'd below
	    bt_node_free(&publ_token_obj_btree, obj_handle, NULL);
         }

         rc = XProcLock(tokdata);
         if (rc != CKR_OK){
            TRACE_ERROR("Failed to get Process Lock.\n");
            goto done;
         }
         object_mgr_del_from_shm( o, tokdata->global_shm );

         XProcUnLock(tokdata);
      }
   }


done:
   if ((rc != CKR_OK) && (o != NULL))
      object_free( o );

   return rc;
}


// object_mgr_add_to_map()
//
CK_RV
object_mgr_add_to_map( STDLL_TokData_t  * tokdata,
		       SESSION          * sess,
                       OBJECT           * obj,
		       unsigned long      obj_handle,
                       CK_OBJECT_HANDLE * map_handle )
{
   OBJECT_MAP  *map_node = NULL;

   if (!sess || !obj || !map_handle){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   //
   // this guy doesn't lock a mutex because it's calling routines should have
   // already locked it
   //

   map_node = (OBJECT_MAP *)malloc(sizeof(OBJECT_MAP));
   if (!map_node){
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }
   map_node->session  = sess;

   if (obj->session != NULL)
      map_node->is_session_obj = TRUE;
   else
      map_node->is_session_obj = FALSE;

   map_node->is_private = object_is_private( obj );

   // map_node->obj_handle will store the index of the btree node in one of these lists:
   // publ_token_obj_btree - for public token object
   // priv_token_obj_btree - for private token objects
   // sess_obj_btree - for session objects
   //
   // *map_handle, the application's CK_OBJECT_HANDLE, will then be the index of the btree node
   // in the object_map_btree
   //
   map_node->obj_handle = obj_handle;
   *map_handle = bt_node_add(&object_map_btree, map_node);

   if (*map_handle == 0) {
      free(map_node);
      TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
      return CKR_HOST_MEMORY;
   }
   obj->map_handle = *map_handle;

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
object_mgr_copy( STDLL_TokData_t  * tokdata,
		 SESSION          * sess,
                 CK_ATTRIBUTE     * pTemplate,
                 CK_ULONG           ulCount,
                 CK_OBJECT_HANDLE   old_handle,
                 CK_OBJECT_HANDLE * new_handle )
{
   OBJECT     *old_obj = NULL;
   OBJECT     *new_obj = NULL;
   CK_BBOOL    priv_obj;
   CK_BBOOL    sess_obj;
   CK_RV       rc;
   unsigned long obj_handle;

   if (!sess || !pTemplate || !new_handle){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }

   rc = object_mgr_find_in_map1( tokdata, old_handle, &old_obj );
   if (rc != CKR_OK){
      TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
      goto done;
   }
   rc = object_copy( tokdata, pTemplate, ulCount, old_obj, &new_obj );
   if (rc != CKR_OK){
      TRACE_DEVEL("Object Copy failed.\n");
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
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }

      if (!sess_obj) {
         TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
         rc = CKR_SESSION_READ_ONLY;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
      if (!sess_obj) {
         TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
         rc = CKR_SESSION_READ_ONLY;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
      if (priv_obj) {
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         rc = CKR_USER_NOT_LOGGED_IN;
         goto done;
      }
   }

   if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
      if (priv_obj) {
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
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

      if ((obj_handle = bt_node_add(&sess_obj_btree, new_obj)) == 0) {
	 TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
	 rc = CKR_HOST_MEMORY;
	 goto done;
      }
   }
   else {
      CK_BYTE current[8];
      CK_BYTE next[8];

      // we'll be modifying nv_token_data so we should protect this part
      // with 'pkcs_mutex'
      //
      rc = XProcLock(tokdata);
      if (rc != CKR_OK){
         TRACE_ERROR("Failed to get Process Lock.\n");
         goto done;
      }
      else {

         // Determine if we have already reached our Max Token Objects
         //
         if (priv_obj) {
            if (tokdata->global_shm->num_priv_tok_obj >= MAX_TOK_OBJS) {
               XProcUnLock(tokdata);
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               rc = CKR_HOST_MEMORY;
               goto done;
            }
         }
         else {
            if (tokdata->global_shm->num_publ_tok_obj >= MAX_TOK_OBJS) {
               XProcUnLock(tokdata);
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               rc = CKR_HOST_MEMORY;
               goto done;
            }
         }
         memcpy( current, &tokdata->nv_token_data->next_token_object_name, 8 );

         new_obj->session = NULL;
         memcpy( &new_obj->name, current, 8 );

         compute_next_token_obj_name( current, next );
         memcpy( &tokdata->nv_token_data->next_token_object_name, next, 8 );

         save_token_object( tokdata, new_obj );

         // add the object identifier to the shared memory segment
         //
         object_mgr_add_to_shm( new_obj, tokdata->global_shm );

         XProcUnLock(tokdata);

         save_token_data(tokdata, sess->session_info.slotID);
      }

      // now, store the object in the token object btree
      //
      if (priv_obj)
         obj_handle = bt_node_add(&priv_token_obj_btree, new_obj);
      else
         obj_handle = bt_node_add(&publ_token_obj_btree, new_obj);

      if (!obj_handle) {
	 TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
	 rc = CKR_HOST_MEMORY;
	 goto done;
      }
   }

   rc = object_mgr_add_to_map( tokdata, sess, new_obj, obj_handle, new_handle );
   if (rc != CKR_OK) {
      TRACE_DEVEL("object_mgr_add_to_map failed.\n");

      // this is messy but we need to remove the object from whatever
      // list we just added it to
      //
      if (sess_obj) {
	 // put the binary tree node which holds new_obj on the free list, but pass NULL here, so
	 // that new_obj (the binary tree node's value pointer) isn't touched. It is free'd below
	 bt_node_free(&sess_obj_btree, obj_handle, NULL);
      }
      else {
         // FIXME - need to destroy the token object file too
         //
         delete_token_object( tokdata, new_obj );

         if (priv_obj) {
	    // put the binary tree node which holds new_obj on the free list, but pass NULL here,
	    // so that new_obj (the binary tree node's value pointer) isn't touched. It is free'd
	    // below
	    bt_node_free(&priv_token_obj_btree, obj_handle, NULL);
         }
         else {
	    // put the binary tree node which holds new_obj on the free list, but pass NULL here,
	    // so that new_obj (the binary tree node's value pointer) isn't touched. It is free'd
	    // below
	    bt_node_free(&publ_token_obj_btree, obj_handle, NULL);
         }

         rc = XProcLock(tokdata);
         if (rc != CKR_OK){
            TRACE_ERROR("Failed to get Process Lock.\n");
            goto done;
         }
         object_mgr_del_from_shm( new_obj, tokdata->global_shm );

         XProcUnLock(tokdata);
      }
   }

done:
   if ((rc != CKR_OK) && (new_obj != NULL))
      object_free( new_obj );

   return rc;
}


// determines whether the session is allowed to create an object.  creates
// the object but doesn't add the object to any object lists or to the
// process' object map.
//
CK_RV
object_mgr_create_skel( STDLL_TokData_t * tokdata,
			SESSION       * sess,
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
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (!pTemplate && (ulCount != 0)){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   //
   // we don't need to lock mutex for this routine
   //

   rc = object_create_skel( tokdata, pTemplate, ulCount,
                            mode, obj_type, sub_class, &o );
   if (rc != CKR_OK){
      TRACE_DEVEL("object_create_skel failed.\n");
      return rc;
   }
   sess_obj = object_is_session_object( o );
   priv_obj = object_is_private( o );

   if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
      if (priv_obj) {
         object_free( o );
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         return CKR_USER_NOT_LOGGED_IN;
      }

      if (!sess_obj) {
         object_free( o );
         TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
         return CKR_SESSION_READ_ONLY;
      }
   }

   if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
      if (!sess_obj) {
         object_free( o );
         TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
         return CKR_SESSION_READ_ONLY;
      }
   }

   if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
      if (priv_obj) {
         object_free( o );
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         return CKR_USER_NOT_LOGGED_IN;
      }
   }

   if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
      if (priv_obj) {
         object_free( o );
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         return CKR_USER_NOT_LOGGED_IN;
      }
   }

   *obj = o;
   return CKR_OK;
}


CK_RV
object_mgr_create_final( STDLL_TokData_t  * tokdata,
			 SESSION           * sess,
                         OBJECT            * obj,
                         CK_OBJECT_HANDLE  * handle )
{
   CK_BBOOL  sess_obj;
   CK_BBOOL  priv_obj;
   CK_RV     rc;
   unsigned long obj_handle;

   if (!sess || !obj || !handle){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }

   sess_obj = object_is_session_object( obj );
   priv_obj = object_is_private( obj );

   if (sess_obj) {
      obj->session = sess;
      memset( obj->name, 0x0, sizeof(CK_BYTE) * 8 );

      if ((obj_handle = bt_node_add(&sess_obj_btree, obj)) == 0) {
	 TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
	 return CKR_HOST_MEMORY;
      }
   }
   else {
      CK_BYTE current[8];
      CK_BYTE next[8];

      // we'll be modifying nv_token_data so we should protect this part
      // with 'pkcs_mutex'
      //
      rc = XProcLock(tokdata);
      if (rc != CKR_OK){
         TRACE_ERROR("Failed to get Process Lock.\n");
         return rc;
      }
      else {

         // Determine if we have already reached our Max Token Objects
         //
         if (priv_obj) {
            if (tokdata->global_shm->num_priv_tok_obj >= MAX_TOK_OBJS) {
               XProcUnLock(tokdata);
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
         }
         else {
            if (tokdata->global_shm->num_publ_tok_obj >= MAX_TOK_OBJS) {
               XProcUnLock(tokdata);
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
            }
         }
         memcpy( current, &tokdata->nv_token_data->next_token_object_name, 8 );

         obj->session = NULL;
         memcpy( &obj->name, current, 8 );

         compute_next_token_obj_name( current, next );
         memcpy( &tokdata->nv_token_data->next_token_object_name, next, 8 );

         save_token_object( tokdata, obj );

         // add the object identifier to the shared memory segment
         //
         object_mgr_add_to_shm( obj, tokdata->global_shm );

         XProcUnLock(tokdata);

         save_token_data(tokdata, sess->session_info.slotID);
      }

      // now, store the object in the token object btree
      //
      if (priv_obj)
         obj_handle = bt_node_add(&priv_token_obj_btree, obj);
      else
         obj_handle = bt_node_add(&publ_token_obj_btree, obj);

      if (!obj_handle) {
	 TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
	 return CKR_HOST_MEMORY;
      }
   }

   rc = object_mgr_add_to_map( tokdata, sess, obj, obj_handle, handle );
   if (rc != CKR_OK) {
      TRACE_DEVEL("object_mgr_add_to_map failed.\n");
      // this is messy but we need to remove the object from whatever
      // list we just added it to
      //
      if (sess_obj) {
	 // put the binary tree node which holds obj on the free list, but pass NULL here, so
	 // that obj (the binary tree node's value pointer) isn't touched. It is free'd below
	 bt_node_free(&sess_obj_btree, obj_handle, NULL);
      }
      else {
         // FIXME - need to destroy the token object file too
         //
         delete_token_object( tokdata, obj );

         if (priv_obj) {
	    // put the binary tree node which holds obj on the free list, but pass NULL here,
	    // so that obj (the binary tree node's value pointer) isn't touched. It is free'd
	    // below
	    bt_node_free(&priv_token_obj_btree, obj_handle, NULL);
         }
         else {
	    // put the binary tree node which holds obj on the free list, but pass NULL here,
	    // so that obj (the binary tree node's value pointer) isn't touched. It is free'd
	    // below
	    bt_node_free(&publ_token_obj_btree, obj_handle, NULL);
         }

         rc = XProcLock(tokdata);
         if (rc != CKR_OK){
            TRACE_ERROR("Failed to get Process Lock.\n");
            return rc;
         }
         object_mgr_del_from_shm( obj, tokdata->global_shm );

         XProcUnLock(tokdata);
      }
   }

   return rc;
}

/* destroy_object_cb
 *
 * Callback used to delete an object from the object map btree and whichever other btree its
 * in (based on its type)
 */
void
destroy_object_cb(STDLL_TokData_t  *tokdata, void *node)
{
	OBJECT_MAP *map = (OBJECT_MAP *)node;
	OBJECT *o;

	if (map->is_session_obj)
		bt_node_free(&sess_obj_btree, map->obj_handle, call_free);
	else {
		if (map->is_private)
			o = bt_get_node_value(&priv_token_obj_btree, map->obj_handle);
		else
			o = bt_get_node_value(&publ_token_obj_btree, map->obj_handle);

		if (!o)
			return;

		delete_token_object(tokdata, o);

		/* Use the same calling convention as the old code, if XProcLock fails, don't
		 * delete from shm and don't free the object in its other btree */
		if (XProcLock(tokdata)) {
			TRACE_ERROR("Failed to get Process Lock.\n");
			goto done;
		}
		DUMP_SHM(tokdata->global_shm, "before");
		object_mgr_del_from_shm(o, tokdata->global_shm);
		DUMP_SHM(tokdata->global_shm, "after");

		XProcUnLock(tokdata);

		if (map->is_private)
			bt_node_free(&priv_token_obj_btree, map->obj_handle, call_free);
		else
			bt_node_free(&publ_token_obj_btree, map->obj_handle, call_free);
	}
done:
	free(map);
}

// XXX Why does this function take @sess as an argument?
//
CK_RV
object_mgr_destroy_object( STDLL_TokData_t  *tokdata,
			   SESSION          * sess,
                           CK_OBJECT_HANDLE   handle )
{
   CK_RV rc = CKR_OK;


   if (!sess){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }

   if (!bt_node_free_(tokdata, &object_map_btree, handle, destroy_object_cb)) {
      TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
      rc = CKR_OBJECT_HANDLE_INVALID;
   }

   return rc;
}

/* delete_token_obj_cb
 *
 * Callback to delete an object if its a token object
 */
void
delete_token_obj_cb(STDLL_TokData_t  *tokdata, void *node, unsigned long map_handle, void *p3)
{
	OBJECT_MAP *map = (OBJECT_MAP *)node;
	OBJECT *o;

	if (!(map->is_session_obj)) {
		if (map->is_private)
			o = bt_get_node_value(&priv_token_obj_btree, map->obj_handle);
		else
			o = bt_get_node_value(&publ_token_obj_btree, map->obj_handle);

		if (!o)
			goto done;

		delete_token_object(tokdata, o);

		/* Use the same calling convention as the old code, if
		 * XProcLock fails, don't delete from shm and don't free
		 * the object in its other btree
		 */
		if (XProcLock(tokdata)) {
			TRACE_ERROR("Failed to get Process Lock.\n");
			goto done;
		}

		object_mgr_del_from_shm(o, tokdata->global_shm);

		XProcUnLock(tokdata);

		if (map->is_private)
			bt_node_free(&priv_token_obj_btree, map->obj_handle, call_free);
		else
			bt_node_free(&publ_token_obj_btree, map->obj_handle, call_free);
	}
done:
	/* delete @node from this btree */
	bt_node_free(&object_map_btree, map_handle, free);
}

// this routine will destroy all token objects in the system
//
CK_RV
object_mgr_destroy_token_objects(STDLL_TokData_t *tokdata)
{
   CK_BBOOL locked = FALSE;
   CK_RV rc;

   bt_for_each_node(tokdata, &object_map_btree, delete_token_obj_cb, NULL);

   // now we want to purge the token object list in shared memory
   //
   rc = XProcLock(tokdata);
   if (rc == CKR_OK) {
      locked = TRUE;

      tokdata->global_shm->num_priv_tok_obj = 0;
      tokdata->global_shm->num_publ_tok_obj = 0;

	memset( &tokdata->global_shm->publ_tok_objs, 0x0, MAX_TOK_OBJS * sizeof(TOK_OBJ_ENTRY) );
	memset( &tokdata->global_shm->priv_tok_objs, 0x0, MAX_TOK_OBJS * sizeof(TOK_OBJ_ENTRY) );
   }
   else
      TRACE_ERROR("Failed to get Process Lock.\n");

   if (locked == TRUE) {
	XProcUnLock(tokdata);
   }

   return rc;
}


// object_mgr_find_in_map_nocache()
//
// Locates the specified object in the map
// without going and checking for cache update
//
CK_RV
object_mgr_find_in_map_nocache( CK_OBJECT_HANDLE    handle,
                         OBJECT           ** ptr )
{
   OBJECT_MAP * map  = NULL;
   OBJECT     * obj  = NULL;
   CK_RV      rc = CKR_OK;


   if (!ptr){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }

   if (!handle) {
      TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
      return CKR_OBJECT_HANDLE_INVALID;
   }

   //
   // no mutex here.  the calling function should have locked the mutex
   //

   map = bt_get_node_value(&object_map_btree, handle);
   if (!map) {
      TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
      return CKR_OBJECT_HANDLE_INVALID;
   }

   if (map->is_session_obj)
      obj = bt_get_node_value(&sess_obj_btree, map->obj_handle);
   else if (map->is_private)
      obj = bt_get_node_value(&priv_token_obj_btree, map->obj_handle);
   else
      obj = bt_get_node_value(&publ_token_obj_btree, map->obj_handle);

   if (!obj) {
      TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
      return CKR_OBJECT_HANDLE_INVALID;
   }

   *ptr = obj;

   return rc;
}

// object_mgr_find_in_map1()
//
// Locates the specified object in the map
//
CK_RV
object_mgr_find_in_map1( STDLL_TokData_t  *tokdata,
			 CK_OBJECT_HANDLE handle,
                         OBJECT           ** ptr )
{
   OBJECT_MAP * map  = NULL;
   OBJECT     * obj  = NULL;
   CK_RV      rc = CKR_OK;


   if (!ptr){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }

   map = bt_get_node_value(&object_map_btree, handle);
   if (!map) {
      TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
      return CKR_OBJECT_HANDLE_INVALID;
   }

   if (map->is_session_obj)
      obj = bt_get_node_value(&sess_obj_btree, map->obj_handle);
   else if (map->is_private)
      obj = bt_get_node_value(&priv_token_obj_btree, map->obj_handle);
   else
      obj = bt_get_node_value(&publ_token_obj_btree, map->obj_handle);

   if (!obj) {
      TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
      return CKR_OBJECT_HANDLE_INVALID;
   }

   /* SAB XXX Fix me.. need to make it more efficient than just looking
    * for the object to be changed. set a global flag that contains the
    * ref count to all objects.. if the shm ref count changes, then we
    * update the object. if not
    */

   /* Note: Each C_Initialize call loads up the public token objects
    * and build corresponding tree(s). The same for private token  objects
    * upon successful C_Login. Since token objects can be shared, it is
    * possible another process or session has deleted a token object.
    * Accounting is done in shm, so check shm to see if object still exists.
    */
   if (!object_is_session_object(obj)) {
	XProcLock(tokdata);
	rc = object_mgr_check_shm( tokdata, obj );
	XProcUnLock(tokdata);

        if (rc != CKR_OK) {
		TRACE_DEVEL("object_mgr_check_shm failed.\n");
		return rc;
	}
   }

   *ptr = obj;

   return rc;
}

void
find_obj_cb(STDLL_TokData_t *tokdata, void *node, unsigned long map_handle, void *p3)
{
	OBJECT_MAP *map = (OBJECT_MAP *)node;
	OBJECT     *obj;
	struct find_args *fa = (struct find_args *)p3;

	if (fa->done)
		return;

	if (map->is_session_obj)
		obj = bt_get_node_value(&sess_obj_btree, map->obj_handle);
	else if (map->is_private)
		obj = bt_get_node_value(&priv_token_obj_btree, map->obj_handle);
	else
		obj = bt_get_node_value(&publ_token_obj_btree, map->obj_handle);

	if (!obj)
		return;

	/* if this object is the one we're looking for (matches p3->obj), return
	 * its map_handle in p3->map_handle */
	if (obj == fa->obj) {
		fa->map_handle = map_handle;
		fa->done = TRUE;
	}
}

// object_mgr_find_in_map2()
//
CK_RV
object_mgr_find_in_map2( STDLL_TokData_t  * tokdata,
			 OBJECT           * obj,
                         CK_OBJECT_HANDLE * handle )
{
   struct find_args fa;

   if (!obj || !handle){
      TRACE_ERROR("Invalid function arguments.\n");
      return CKR_FUNCTION_FAILED;
   }
   //
   // no mutex here.  the calling function should have locked the mutex
   //

   fa.done = FALSE;
   fa.obj = obj;
   fa.map_handle = 0;

   // pass the fa structure with the values to operate on in the find_obj_cb function
   bt_for_each_node(tokdata, &object_map_btree, find_obj_cb, &fa);

   if (fa.done == FALSE || fa.map_handle == 0) {
      return CKR_OBJECT_HANDLE_INVALID;
   }

   *handle = fa.map_handle;

   XProcLock(tokdata);
   object_mgr_check_shm( tokdata, obj );
   XProcUnLock(tokdata);

   return CKR_OK;
}

void
find_build_list_cb(STDLL_TokData_t *tokdata, void *node,
		   unsigned long obj_handle, void *p3)
{
   OBJECT *obj = (OBJECT *)node;
   struct find_build_list_args *fa = (struct find_build_list_args *)p3;
   CK_OBJECT_HANDLE map_handle;
   CK_ATTRIBUTE *attr;
   CK_BBOOL match = FALSE;
   CK_RV rc;

   if ((object_is_private(obj) == FALSE) || (fa->public_only == FALSE)) {
      // if the user doesn't specify any template attributes then we return
      // all objects
      //
      if (fa->pTemplate == NULL || fa->ulCount == 0)
         match = TRUE;
      else
         match = template_compare( fa->pTemplate, fa->ulCount, obj->template );
   }

   // if we have a match, find the object in the map (add it if necessary)
   // then add the object to the list of found objects //
   if (match) {
      rc = object_mgr_find_in_map2( tokdata, obj, &map_handle );
      if (rc != CKR_OK) {
         rc = object_mgr_add_to_map(tokdata, fa->sess, obj, obj_handle, &map_handle);
         if (rc != CKR_OK){
            TRACE_DEVEL("object_mgr_add_to_map failed.\n");
            return;
         }
      }

      // If hw_feature is false here, we need to filter out all objects
      // that have the CKO_HW_FEATURE attribute set. - KEY
      if ((fa->hw_feature == FALSE) &&
	  (template_attribute_find(obj->template, CKA_CLASS, &attr) == TRUE)) {
	 if (attr->pValue == NULL) {
	    TRACE_DEVEL("%s\n", ock_err(ERR_GENERAL_ERROR));
	    return;
	 }
	 if (*(CK_OBJECT_CLASS *)attr->pValue == CKO_HW_FEATURE)
	    return;
      }

      /* Don't find objects that have been created with the CKA_HIDDEN
       * attribute set */
      if ((fa->hidden_object == FALSE) &&
	  (template_attribute_find(obj->template, CKA_HIDDEN, &attr) == TRUE)) {
	 if (*(CK_BBOOL *)attr->pValue == TRUE)
	    return;
      }

      fa->sess->find_list[ fa->sess->find_count ] = map_handle;
      fa->sess->find_count++;

      if (fa->sess->find_count >= fa->sess->find_len) {
	 fa->sess->find_len += 15;
	 fa->sess->find_list =
		 (CK_OBJECT_HANDLE *)realloc(fa->sess->find_list,
					     fa->sess->find_len * sizeof(CK_OBJECT_HANDLE));
	 if (!fa->sess->find_list) {
	    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
	    return;
	 }
      }
   }
}

CK_RV
object_mgr_find_init( STDLL_TokData_t  *tokdata,
		      SESSION      * sess,
                      CK_ATTRIBUTE * pTemplate,
                      CK_ULONG       ulCount )
{
   struct find_build_list_args fa;
   CK_ULONG i;
   // it is possible the pTemplate == NULL
   //

   if (!sess){
      TRACE_ERROR("Invalid function argument.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (sess->find_active != FALSE){
      return CKR_OPERATION_ACTIVE;
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
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
         TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
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
   XProcLock(tokdata);
   object_mgr_update_from_shm(tokdata);
   XProcUnLock(tokdata);

   fa.hw_feature = FALSE;
   fa.hidden_object = FALSE;
   fa.sess = sess;
   fa.pTemplate = pTemplate;
   fa.ulCount = ulCount;

   // which objects can be returned:
   //
   //   Public Session:   public session objects, public token objects
   //   User Session:     all session objects,    all token objects
   //   SO session:       public session objects, public token objects
   //
   // PKCS#11 v2.11 (pg. 79): "When searching using C_FindObjectsInit
   // and C_FindObjects, hardware feature objects are not returned
   // unless the CKA_CLASS attribute in the template has the value
   // CKO_HW_FEATURE." So, we check for CKO_HW_FEATURE and if its set,
   // we'll find these objects below. - KEY
   for (i = 0; i < ulCount; i++) {
      if (pTemplate[i].type == CKA_CLASS) {
	 if (*(CK_ULONG *)pTemplate[i].pValue == CKO_HW_FEATURE) {
	    fa.hw_feature = TRUE;
	 }
      }

      /* only find CKA_HIDDEN objects if its specified in the template. */
      if (pTemplate[i].type == CKA_HIDDEN) {
	 if (*(CK_BBOOL *)pTemplate[i].pValue == TRUE) {
	    fa.hidden_object = TRUE;
	 }
      }
   }

   switch (sess->session_info.state) {
      case CKS_RO_PUBLIC_SESSION:
      case CKS_RW_PUBLIC_SESSION:
      case CKS_RW_SO_FUNCTIONS:
	 fa.public_only = TRUE;

	 bt_for_each_node(tokdata, &publ_token_obj_btree, find_build_list_cb, &fa);
	 bt_for_each_node(tokdata, &sess_obj_btree, find_build_list_cb, &fa);
         break;

      case CKS_RO_USER_FUNCTIONS:
      case CKS_RW_USER_FUNCTIONS:
	 fa.public_only = FALSE;

	 bt_for_each_node(tokdata, &priv_token_obj_btree, find_build_list_cb, &fa);
	 bt_for_each_node(tokdata, &publ_token_obj_btree, find_build_list_cb, &fa);
	 bt_for_each_node(tokdata, &sess_obj_btree, find_build_list_cb, &fa);
         break;
   }

   sess->find_active = TRUE;

   return CKR_OK;
}

//
//
CK_RV
object_mgr_find_final( SESSION *sess )
{
   if (!sess){
      TRACE_ERROR("Invalid function argument.\n");
      return CKR_FUNCTION_FAILED;
   }
   if (sess->find_active == FALSE){
      TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
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
object_mgr_get_attribute_values( STDLL_TokData_t  *tokdata,
				 SESSION           * sess,
                                 CK_OBJECT_HANDLE    handle,
                                 CK_ATTRIBUTE      * pTemplate,
                                 CK_ULONG            ulCount )
{
   OBJECT   * obj;
   CK_BBOOL   priv_obj;
   CK_RV      rc;

   if (!pTemplate){
      TRACE_ERROR("Invalid function argument.\n");
      return CKR_FUNCTION_FAILED;
   }

   rc = object_mgr_find_in_map1( tokdata, handle, &obj );
   if (rc != CKR_OK){
      TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
      return rc;
   }
   priv_obj = object_is_private( obj );

   if (priv_obj == TRUE) {
      if (sess->session_info.state == CKS_RO_PUBLIC_SESSION ||
          sess->session_info.state == CKS_RW_PUBLIC_SESSION)
      {
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         return CKR_USER_NOT_LOGGED_IN;
      }
   }

   rc = object_get_attribute_values( obj, pTemplate, ulCount );
   if (rc != CKR_OK)
         TRACE_DEVEL("object_get_attribute_values failed.\n");

   return rc;
}


//
//
CK_RV
object_mgr_get_object_size( STDLL_TokData_t  *tokdata,
			    CK_OBJECT_HANDLE   handle,
                            CK_ULONG         * size )
{
   OBJECT    * obj;
   CK_RV       rc;

   rc = object_mgr_find_in_map1( tokdata, handle, &obj );
   if (rc != CKR_OK) {
      TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
      return rc;
   }

   *size = object_get_size( obj );

   return rc;
}

void
purge_session_obj_cb(STDLL_TokData_t  *tokdata, void *node,
		     unsigned long obj_handle, void *p3)
{
   OBJECT *obj = (OBJECT *)node;
   struct purge_args *pa = (struct purge_args *)p3;
   CK_BBOOL del = FALSE;

   if (obj->session == pa->sess) {
      if (pa->type == PRIVATE) {
         if (object_is_private(obj))
            del = TRUE;
      }
      else if (pa->type == PUBLIC) {
         if (object_is_public(obj))
            del = TRUE;
      }
      else if (pa->type == ALL) {
         del = TRUE;
      }

      if (del == TRUE) {
         if (obj->map_handle)
	    bt_node_free(&object_map_btree, obj->map_handle, free);

	 bt_node_free(&sess_obj_btree, obj_handle, call_free);
      }
   }
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
object_mgr_purge_session_objects( STDLL_TokData_t *tokdata,
				  SESSION         *sess,
                                  SESS_OBJ_TYPE   type )
{
   struct purge_args pa = { sess, type };

   if (!sess)
      return FALSE;

   bt_for_each_node(tokdata, &sess_obj_btree, purge_session_obj_cb, &pa);

   return TRUE;
}

/* purge_token_obj_cb
 *
 * @p3 is the btree we're purging from
 */
void
purge_token_obj_cb(STDLL_TokData_t  *tokdata, void *node, unsigned long obj_handle, void *p3)
{
   OBJECT *obj = (OBJECT *)node;
   struct btree *t = (struct btree *)p3;

   if (obj->map_handle)
      bt_node_free(&object_map_btree, obj->map_handle, free);

   bt_node_free(t, obj_handle, call_free);
}

// this routine cleans up the list of token objects.  in general, we don't
// need to do this but when tracing memory leaks, it's best that we free everything
// that we've allocated
//
CK_BBOOL
object_mgr_purge_token_objects(STDLL_TokData_t *tokdata)
{
   bt_for_each_node(tokdata, &priv_token_obj_btree, purge_token_obj_cb, &priv_token_obj_btree);
   bt_for_each_node(tokdata, &publ_token_obj_btree, purge_token_obj_cb, &publ_token_obj_btree);

   return TRUE;
}


CK_BBOOL
object_mgr_purge_private_token_objects(STDLL_TokData_t *tokdata)
{
   bt_for_each_node(tokdata, &priv_token_obj_btree, purge_token_obj_cb, &priv_token_obj_btree);

   return TRUE;
}

//
//
CK_RV
object_mgr_restore_obj( STDLL_TokData_t  *tokdata, CK_BYTE *data,
			OBJECT *oldObj )
{
    return object_mgr_restore_obj_withSize(tokdata, data, oldObj, -1);
}

//
//Modified verrsion of object_mgr_restore_obj to bounds check
//If data_size==-1, won't check bounds
CK_RV
object_mgr_restore_obj_withSize(STDLL_TokData_t  *tokdata, CK_BYTE *data,
				OBJECT *oldObj, int data_size )
{
   OBJECT    * obj  = NULL;
   CK_BBOOL    priv;
   CK_RV       rc;

   if (!data){
      TRACE_ERROR("Invalid function argument.\n");
      return CKR_FUNCTION_FAILED;
   }
   // The calling stack MUST have the mutex
   // to many grab it now.

   if (oldObj != NULL) {
      obj = oldObj;
      rc = object_restore_withSize( data, &obj, TRUE, data_size );
   }
   else {
      rc = object_restore_withSize( data, &obj, FALSE, data_size );
      if (rc == CKR_OK) {
         priv = object_is_private( obj );

	 if (priv) {
	    if (!bt_node_add(&priv_token_obj_btree, obj)) {
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
	    }
	 } else {
	    if (!bt_node_add(&publ_token_obj_btree, obj)) {
               TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
               return CKR_HOST_MEMORY;
	    }
	 }

         XProcLock(tokdata);

         if (priv) {
            if (tokdata->global_shm->priv_loaded == FALSE){
               if (tokdata->global_shm->num_priv_tok_obj < MAX_TOK_OBJS)
                  object_mgr_add_to_shm( obj, tokdata->global_shm );
               else{
                  TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                  rc = CKR_HOST_MEMORY;
               }
            }
         } else {
            if (tokdata->global_shm->publ_loaded == FALSE){
               if (tokdata->global_shm->num_publ_tok_obj < MAX_TOK_OBJS)
                  object_mgr_add_to_shm( obj, tokdata->global_shm );
               else{
                  TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                  rc = CKR_HOST_MEMORY;
               }
            }
         }

         XProcUnLock(tokdata);
      } else {
         TRACE_DEVEL("object_restore_withSize failed.\n");
      }
   }

   return rc;
}


//
//
CK_RV
object_mgr_set_attribute_values( STDLL_TokData_t  *tokdata,
				 SESSION           * sess,
                                 CK_OBJECT_HANDLE    handle,
                                 CK_ATTRIBUTE      * pTemplate,
                                 CK_ULONG            ulCount )
{
   OBJECT    * obj;
   CK_BBOOL    sess_obj, priv_obj;
   CK_BBOOL    modifiable;
   CK_RV       rc;


   if (!pTemplate){
      TRACE_ERROR("Invalid function argument.\n");
      return CKR_FUNCTION_FAILED;
   }

   rc = object_mgr_find_in_map1( tokdata, handle, &obj );

   if (rc != CKR_OK) {
      TRACE_DEVEL("object_mgr_find_in_map1 failed.\n");
      return rc;
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
      TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_READ_ONLY));
      return CKR_ATTRIBUTE_READ_ONLY;
   }
   if (sess->session_info.state == CKS_RO_PUBLIC_SESSION) {
      if (priv_obj){
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         return CKR_USER_NOT_LOGGED_IN;
      }
      if (!sess_obj){
         TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
         return CKR_SESSION_READ_ONLY;
      }
   }

   if (sess->session_info.state == CKS_RO_USER_FUNCTIONS) {
      if (!sess_obj){
         TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
         return CKR_SESSION_READ_ONLY;
      }
   }

   if (sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
      if (priv_obj){
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         return CKR_USER_NOT_LOGGED_IN;
      }
   }

   if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
      if (priv_obj){
         TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
         return CKR_USER_NOT_LOGGED_IN;
      }
   }


   rc = object_set_attribute_values( tokdata, obj, pTemplate, ulCount );
   if (rc != CKR_OK){
      TRACE_DEVEL("object_set_attribute_values failed.\n");
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

      save_token_object( tokdata, obj );

      rc = XProcLock(tokdata);
      if (rc != CKR_OK){
         TRACE_ERROR("Failed to get Process Lock.\n");
         return rc;
      }
      if (priv_obj) {
         rc = object_mgr_search_shm_for_obj(tokdata->global_shm->priv_tok_objs,
                                            0, tokdata->global_shm->num_priv_tok_obj-1,
                                            obj, &index );

         if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_search_shm_for_obj failed.\n");
            XProcUnLock(tokdata);
            return rc;
         }

         entry = &tokdata->global_shm->priv_tok_objs[index];
      }
      else {
         rc = object_mgr_search_shm_for_obj( tokdata->global_shm->publ_tok_objs,
                                             0, tokdata->global_shm->num_publ_tok_obj-1,
                                             obj, &index );
         if (rc != CKR_OK) {
            TRACE_DEVEL("object_mgr_search_shm_for_obj failed.\n");
            XProcUnLock(tokdata);
            return rc;
         }

         entry = &tokdata->global_shm->publ_tok_objs[index];
      }

      entry->count_lo = obj->count_lo;
      entry->count_hi = obj->count_hi;

      XProcUnLock(tokdata);
   }

   return rc;
}


//
//
void
object_mgr_add_to_shm( OBJECT *obj, LW_SHM_TYPE *global_shm )
{
   // TODO: Can't this function fail?
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

   return;
}


//
//
CK_RV
object_mgr_del_from_shm( OBJECT *obj, LW_SHM_TYPE *global_shm )
{
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
         TRACE_DEVEL("object_mgr_search_shm_for_obj failed.\n");
         return rc;
      }
      // Since the number of objects starts at 1 and index starts at zero, we
      // decrement before we get count.  This eliminates the need to perform
      // this operation later as well as decrementing the number of objects.
      // (i.e. If we have 10 objects, num will be 10 but the last index is 9.
      // If we want to delete the last object we need to subtract 9 from 9 not
      // 10 from 9.)
      //
      global_shm->num_priv_tok_obj--;
	if (index > global_shm->num_priv_tok_obj) {
	      count = index - global_shm->num_priv_tok_obj;
	} else {
	      count = global_shm->num_priv_tok_obj - index;
	}

      if (count > 0) {  // If we are not deleting the last element in the list
         // Move up count number of elements effectively deleting the index
	 // NB: memmove is required since the copied regions may overlap
         memmove((char *)&global_shm->priv_tok_objs[index],
                (char *)&global_shm->priv_tok_objs[index+1],
                sizeof(TOK_OBJ_ENTRY) * count );
         // We need to zero out the last entry... Since the memcopy
         // does not zero it out...
         memset((char *)&global_shm->priv_tok_objs[global_shm->num_priv_tok_obj+1], 0,
                sizeof(TOK_OBJ_ENTRY));
      }
      else { // We are deleting the last element which is in num_priv_tok_obj
         memset((char *)&global_shm->priv_tok_objs[global_shm->num_priv_tok_obj], 0,
                sizeof(TOK_OBJ_ENTRY));
      }
   }
   else {
      rc = object_mgr_search_shm_for_obj( global_shm->publ_tok_objs,
                                          0, global_shm->num_publ_tok_obj-1,
                                          obj, &index );
      if (rc != CKR_OK){
         TRACE_DEVEL("object_mgr_search_shm_for_obj failed.\n");
         return rc;
      }
      global_shm->num_publ_tok_obj--;


	if (index > global_shm->num_publ_tok_obj) {
	      count = index - global_shm->num_publ_tok_obj;
	} else {
	      count = global_shm->num_publ_tok_obj - index;
	}

      if (count > 0) {
	 // NB: memmove is required since the copied regions may overlap
         memmove((char *)&global_shm->publ_tok_objs[index],
                (char *)&global_shm->publ_tok_objs[index+1],
                sizeof(TOK_OBJ_ENTRY) * count);
         // We need to zero out the last entry... Since the memcopy
         // does not zero it out...
         memset((char *)&global_shm->publ_tok_objs[global_shm->num_publ_tok_obj+1], 0,
                sizeof(TOK_OBJ_ENTRY));
      }
      else {
         memset((char *)&global_shm->publ_tok_objs[global_shm->num_publ_tok_obj], 0,
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
object_mgr_check_shm( STDLL_TokData_t  *tokdata, OBJECT *obj )
{
   TOK_OBJ_ENTRY   * entry = NULL;
   CK_BBOOL          priv;
   CK_ULONG          index;
   CK_RV             rc;


   // the calling routine is responsible for locking the global_shm mutex
   //

   /* first check the object count. If it is 0, then just return. */
   priv = object_is_private( obj );

   if (priv) {

      if (tokdata->global_shm->num_priv_tok_obj == 0) {
	  TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
	  return CKR_OBJECT_HANDLE_INVALID;
      }
      rc = object_mgr_search_shm_for_obj( tokdata->global_shm->priv_tok_objs,
                                          0, tokdata->global_shm->num_priv_tok_obj-1,
                                          obj, &index );
      if (rc != CKR_OK){
         TRACE_ERROR("object_mgr_search_shm_for_obj failed.\n");
         return rc;
      }
      entry = &tokdata->global_shm->priv_tok_objs[index];
   }
   else {

      if (tokdata->global_shm->num_publ_tok_obj == 0) {
	  TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
	  return CKR_OBJECT_HANDLE_INVALID;
      }
      rc = object_mgr_search_shm_for_obj( tokdata->global_shm->publ_tok_objs,
                                          0, tokdata->global_shm->num_publ_tok_obj-1,
                                          obj, &index );
      if (rc != CKR_OK){
         TRACE_ERROR("object_mgr_search_shm_for_obj failed.\n");
         return rc;
      }
      entry = &tokdata->global_shm->publ_tok_objs[index];
   }

   if ((obj->count_hi == entry->count_hi) && (obj->count_lo == entry->count_lo))
      return CKR_OK;

   rc = reload_token_object( tokdata, obj );
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
// SAB  XXX reduce the search time since this is what seems to be burning cycles
   CK_ULONG idx;
   if ( obj->index == 0 ) {
	   for (idx=0;idx<=hi;idx++){
	      if (memcmp(obj->name, obj_list[idx].name,8) == 0) {
		 *index = idx;
		 obj->index = idx;
		 return CKR_OK ;
	      }
	   }
   } else {
	// SAB better double check
	if ( memcmp(obj->name, obj_list[obj->index].name,8) == 0 ){
		 *index = obj->index;
		 return CKR_OK ;
	} else { // something is hosed.. go back to the brute force method
	   for (idx=0;idx<=hi;idx++){
	      if (memcmp(obj->name, obj_list[idx].name,8) == 0) {
		 *index = idx;
		 obj->index = idx;
		 return CKR_OK ;
	      }
	   }
        }
   }
   TRACE_ERROR("%s\n", ock_err(ERR_OBJECT_HANDLE_INVALID));
   return CKR_OBJECT_HANDLE_INVALID;
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
object_mgr_update_from_shm(STDLL_TokData_t *tokdata)
{
   object_mgr_update_publ_tok_obj_from_shm(tokdata);
   object_mgr_update_priv_tok_obj_from_shm(tokdata);

   return CKR_OK;
}

void
delete_objs_from_btree_cb(STDLL_TokData_t  *tokdata, void *node,
			  unsigned long obj_handle, void *p3)
{
   struct update_tok_obj_args * ua = (struct update_tok_obj_args *)p3;
   TOK_OBJ_ENTRY              * shm_te = NULL;
   OBJECT                     * obj = (OBJECT *)node;
   CK_ULONG                     index;

   /* for each TOK_OBJ_ENTRY in the SHM list */
   for (index = 0; index < *(ua->num_entries); index++) {
      shm_te = &(ua->entries[index]);

      /* found it, return */
      if (!memcmp(obj->name, shm_te->name, 8)) {
	 return;
      }
   }

   /* didn't find it in SHM, delete it from its btree */
   bt_node_free(ua->t, obj_handle, call_free);
}

void
find_by_name_cb(STDLL_TokData_t  *tokdata, void *node,
		unsigned long obj_handle, void *p3)
{
	OBJECT *obj                  = (OBJECT *)node;
	struct find_by_name_args *fa = (struct find_by_name_args *)p3;

	if (fa->done)
		return;

	if (!memcmp(obj->name, fa->name, 8)) {
		fa->done = TRUE;
	}
}

CK_RV
object_mgr_update_publ_tok_obj_from_shm(STDLL_TokData_t  * tokdata)
{
	struct update_tok_obj_args   ua;
	struct find_by_name_args     fa;
	TOK_OBJ_ENTRY              * shm_te = NULL;
	CK_ULONG                     index;
	OBJECT                     * new_obj;

	ua.entries = tokdata->global_shm->publ_tok_objs;
	ua.num_entries = &(tokdata->global_shm->num_publ_tok_obj);
	ua.t = &publ_token_obj_btree;

	/* delete any objects not in SHM from the btree */
	bt_for_each_node(tokdata, &publ_token_obj_btree, delete_objs_from_btree_cb, &ua);

	/* for each item in SHM, add it to the btree if its not there */
	for (index = 0; index < tokdata->global_shm->num_publ_tok_obj; index++) {
		shm_te = &tokdata->global_shm->publ_tok_objs[index];

		fa.done = FALSE;
		fa.name = shm_te->name;

		/* find an object from SHM in the btree */
		bt_for_each_node(tokdata, &publ_token_obj_btree, find_by_name_cb, &fa);

		/* we didn't find it in the btree, so add it */
		if (fa.done == FALSE) {
			new_obj = (OBJECT *)malloc(sizeof(OBJECT));
			memset( new_obj, 0x0, sizeof(OBJECT) );

			memcpy( new_obj->name, shm_te->name, 8 );
			reload_token_object(tokdata, new_obj );
			bt_node_add(&publ_token_obj_btree, new_obj);
		}
	}

	return CKR_OK;
}

CK_RV
object_mgr_update_priv_tok_obj_from_shm(STDLL_TokData_t *tokdata)
{
	struct update_tok_obj_args   ua;
	struct find_by_name_args     fa;
	TOK_OBJ_ENTRY              * shm_te = NULL;
	CK_ULONG                     index;
	OBJECT                     * new_obj;

	// SAB XXX don't bother doing this call if we are not in the correct
	// login state
	if ( !(global_login_state == CKS_RW_USER_FUNCTIONS ||
	       global_login_state == CKS_RO_USER_FUNCTIONS) ) {
		return CKR_OK;
	}

	ua.entries = tokdata->global_shm->priv_tok_objs;
	ua.num_entries = &(tokdata->global_shm->num_priv_tok_obj);
	ua.t = &priv_token_obj_btree;

	/* delete any objects not in SHM from the btree */
	bt_for_each_node(tokdata, &priv_token_obj_btree, delete_objs_from_btree_cb, &ua);

	/* for each item in SHM, add it to the btree if its not there */
	for (index = 0; index < tokdata->global_shm->num_priv_tok_obj; index++) {
		shm_te = &tokdata->global_shm->priv_tok_objs[index];

		fa.done = FALSE;
		fa.name = shm_te->name;

		/* find an object from SHM in the btree */
		bt_for_each_node(tokdata, &priv_token_obj_btree, find_by_name_cb, &fa);

		/* we didn't find it in the btree, so add it */
		if (fa.done == FALSE) {
			new_obj = (OBJECT *)malloc(sizeof(OBJECT));
			memset( new_obj, 0x0, sizeof(OBJECT) );

			memcpy( new_obj->name, shm_te->name, 8 );
			reload_token_object( tokdata, new_obj );
			bt_node_add(&priv_token_obj_btree, new_obj);
		}
	}

	return CKR_OK;
}

// SAB FIXME FIXME

void
purge_map_by_type_cb(STDLL_TokData_t *tokdata, void *node,
		     unsigned long map_handle, void *p3)
{
   OBJECT_MAP    *map  = (OBJECT_MAP *)node;
   SESS_OBJ_TYPE  type = *(SESS_OBJ_TYPE *)p3;

   if (type == PRIVATE) {
      if (map->is_private) {
	 bt_node_free(&object_map_btree, map_handle, free);
      }
   } else if (type == PUBLIC) {
      if (!map->is_private) {
	 bt_node_free(&object_map_btree, map_handle, free);
      }
   }
}

CK_BBOOL
object_mgr_purge_map( STDLL_TokData_t *tokdata,
                      SESSION         *sess,
                      SESS_OBJ_TYPE   type )
{
   bt_for_each_node(tokdata, &object_map_btree, purge_map_by_type_cb, &type);

   return TRUE;
}

#ifdef DEBUG
void
dump_shm(LW_SHM_TYPE *global_shm, const char *s)
{
	CK_ULONG i;
	TRACE_DEBUG("%s: dump_shm priv:\n", s);

	for (i = 0; i < global_shm->num_priv_tok_obj; i++) {
		TRACE_DEBUG("[%lu]: %.8s\n", i, global_shm->priv_tok_objs[i].name);
	}
	TRACE_DEBUG("%s: dump_shm publ:\n", s);
	for (i = 0; i < global_shm->num_publ_tok_obj; i++) {
		TRACE_DEBUG("[%lu]: %.8s\n", i, global_shm->publ_tok_objs[i].name);
	}
}
#endif
