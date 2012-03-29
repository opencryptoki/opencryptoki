/*
 * Licensed materials, Property of IBM Corp.
 *
 * openCryptoki CCA token
 *
 * (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2006
 *
 * Author: Kent E. Yoder <yoder1@us.ibm.com>
 *
 */


// loadsave.c
//
// routines associated with loading/saving files
//
//

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <alloca.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/file.h>
#include <errno.h>
#include <syslog.h>

#include <pwd.h>
#include <grp.h>

#include "cca_stdll.h"

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"

void
set_perm(int file)
{
   struct group *grp;

   // Set absolute permissions or rw-rw-r--
   fchmod(file,S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH);

   grp = getgrnam("pkcs11"); // Obtain the group id
   if (grp){
	   fchown(file,getuid(),grp->gr_gid);  // set ownership to root, and pkcs11 group
   }
}

//
//
CK_RV
load_token_data()
{
   FILE        * fp;
   CK_BYTE     fname[PATH_MAX];
   TOKEN_DATA    td;
   CK_RV         rc;


   sprintf((char *)fname,"%s/%s",(char *)pk_dir, PK_LITE_NV);

   rc = XProcLock();
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_PROCESS_LOCK);
      goto out_nolock;
   }

   fp = fopen((char *)fname, "r");
   if (!fp) {
      /* Better error checking added */
      if (errno == ENOENT) {
         /* init_token_data may call save_token_data, which graps the 
          * lock, so we must release it around this call */
         XProcUnLock();
         init_token_data();
         rc = XProcLock();
         if (rc != CKR_OK){
            OCK_LOG_ERR(ERR_PROCESS_LOCK);
            goto out_nolock;
         }

         fp = fopen((char *)fname, "r");
         if (!fp) {
            // were really hosed here since the created
            // did not occur
	    OCK_SYSLOG(LOG_ERR, "failed opening %s for read: %s", fname, strerror(errno));
            rc = CKR_FUNCTION_FAILED;
            goto out_unlock;
         }
      } else {
         /* Could not open file for some unknown reason */
         OCK_LOG_ERR(ERR_FUNCTION_FAILED);
         rc = CKR_FUNCTION_FAILED;
         goto out_unlock;
      }
   }
   set_perm(fileno(fp));

   rc = fread( &td, sizeof(TOKEN_DATA), 1, fp );
   fclose(fp);

   if (rc == 0) {
      rc = CKR_FUNCTION_FAILED;
      goto out_unlock;
   }

   memcpy( nv_token_data, &td, sizeof(TOKEN_DATA) );

   rc = CKR_OK;

out_unlock:
   XProcUnLock();

out_nolock:
   return rc;
}


//
//
CK_RV
save_token_data()
{
   FILE       *fp;
   TOKEN_DATA  td;
   CK_RV       rc;
   CK_BYTE     fname[PATH_MAX];


   sprintf((char *)fname,"%s/%s",pk_dir, PK_LITE_NV);

   rc = XProcLock();
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_PROCESS_LOCK);
      goto out_nolock;
   }

   fp = fopen((char *)fname, "r+");
   if (!fp){
      fp = fopen((char *)fname, "w");
      if (!fp) {
         OCK_LOG_ERR(ERR_FUNCTION_FAILED);
         rc = CKR_FUNCTION_FAILED;
         goto done;
      }
   }
   set_perm(fileno(fp));

   memcpy( &td, nv_token_data, sizeof(TOKEN_DATA) );

   (void)fwrite( &td, sizeof(TOKEN_DATA), 1, fp );
   fclose(fp);

   rc = CKR_OK;

done:
   XProcUnLock();

out_nolock:
   return rc;
}


//
//
CK_RV
save_token_object( OBJECT *obj )
{
   FILE      * fp = NULL;
   CK_BYTE     line[100];
   CK_RV       rc;
   CK_BYTE     fname[PATH_MAX];

   if (object_is_private(obj) == TRUE)
      rc = save_private_token_object( obj );
   else
      rc = save_public_token_object( obj );

   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_TOKEN_SAVE);
      return rc;
   }
   // update the index file if it exists
   //
   sprintf((char *)fname,"%s/%s/%s",pk_dir,PK_LITE_OBJ_DIR,PK_LITE_OBJ_IDX);

   fp = fopen( (char *)fname, "r" );
   if (fp) {
	set_perm(fileno(fp));
      while (!feof(fp)) {
         (void)fgets((char *)line, 50, fp );
         if (!feof(fp)) {
            line[ strlen((char *)line)-1 ] = 0;
            if (strcmp((char *)line,(char *)( obj->name)) == 0) {
               fclose(fp);
               return CKR_OK;  // object is already in the list
            }
         }
      }
      fclose(fp);
   }


   // we didn't find it...either the index file doesn't exist or this
   // is a new object...
   //
   fp = fopen((char *)fname, "a");
   if (!fp){
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }
   set_perm(fileno(fp));

   set_perm(fileno(fp));
   fprintf( fp, "%s\n", obj->name );
   fclose(fp);

   return CKR_OK;
}


// this is the same as the old version.  public token objects are stored in the
// clear
//
CK_RV
save_public_token_object( OBJECT *obj )
{
   FILE       * fp       = NULL;
   CK_BYTE    * cleartxt = NULL;
   CK_BYTE      fname[PATH_MAX];
   CK_ULONG     cleartxt_len;
   CK_BBOOL     flag = FALSE;
   CK_RV        rc;
   CK_ULONG_32  total_len;


   sprintf( (char *)fname,"%s/%s/", pk_dir,PK_LITE_OBJ_DIR);

   strncat( (char *)fname, (char *) obj->name, 8 );

   rc = object_flatten( obj, &cleartxt, &cleartxt_len );
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJ_FLATTEN);
      goto error;
   }
   fp = fopen( (char *)fname, "w" );
   if (!fp) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto error;
   }

   set_perm(fileno(fp));

   total_len = cleartxt_len + sizeof(CK_ULONG_32) + sizeof(CK_BBOOL);

   (void)fwrite( &total_len, sizeof(CK_ULONG_32), 1, fp );
   (void)fwrite( &flag,      sizeof(CK_BBOOL), 1, fp );
   (void)fwrite( cleartxt,   cleartxt_len,     1, fp );

   fclose( fp );
   free( cleartxt );

   return CKR_OK;

error:
   if (fp)  fclose( fp );
   if (cleartxt) free( cleartxt );
   return rc;
}


//
//
CK_RV
save_private_token_object( OBJECT *obj )
{
   FILE             * fp        = NULL;
   CK_BYTE          * obj_data  = NULL;
   CK_BYTE          * cleartxt  = NULL;
   CK_BYTE          * ciphertxt = NULL;
   CK_BYTE          * ptr       = NULL;
   CK_BYTE            fname[100];
   CK_BYTE            hash_sha[SHA1_HASH_SIZE];
   CK_BYTE            des3_key[MASTER_KEY_SIZE];
   CK_ULONG           obj_data_len,cleartxt_len, ciphertxt_len;
   CK_ULONG           padded_len;
   CK_BBOOL           flag;
   CK_RV              rc;
   CK_ULONG_32        obj_data_len_32;
   CK_ULONG_32        total_len;


   sprintf( (char *)fname,"%s/%s/", pk_dir,PK_LITE_OBJ_DIR);

   rc = object_flatten( obj, &obj_data, &obj_data_len );
   obj_data_len_32 = obj_data_len;
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_OBJ_FLATTEN);
      goto error;
   }
   //
   // format for the object file:
   //    private flag
   //    ---- begin encrypted part        <--+
   //       length of object data            |
   //       object data                      +---- sensitive part
   //       SHA of (object data)             |
   //    ---- end encrypted part          <--+
   //
   compute_sha( obj_data, obj_data_len, hash_sha );

   // encrypt the sensitive object data.  need to be careful.
   // if I use the normal high-level encryption routines I'll need to
   // create a tepmorary key object containing the master key, perform the
   // encryption, then destroy the key object.  There is a race condition
   // here if the application is multithreaded (if a thread-switch occurs,
   // the other application thread could do a FindObject and be able to access
   // the master key object.
   //
   // So I have to use the low-level encryption routines.
   //
   memcpy( des3_key, master_key, MASTER_KEY_SIZE );

   cleartxt_len = sizeof(CK_ULONG_32) + obj_data_len_32 + SHA1_HASH_SIZE;
   padded_len   = DES_BLOCK_SIZE * (cleartxt_len / DES_BLOCK_SIZE + 1);

   cleartxt  = (CK_BYTE *)malloc( padded_len );
   ciphertxt = (CK_BYTE *)malloc( padded_len );
   if (!cleartxt || !ciphertxt) {
      OCK_LOG_ERR(ERR_HOST_MEMORY);
      rc = CKR_HOST_MEMORY;
      goto error;
   }

   ciphertxt_len = padded_len;

   ptr = cleartxt;
   memcpy( ptr, &obj_data_len_32, sizeof(CK_ULONG_32) );  ptr += sizeof(CK_ULONG_32);
   memcpy( ptr,  obj_data,     obj_data_len_32     );  ptr += obj_data_len_32;
   memcpy( ptr,  hash_sha,     SHA1_HASH_SIZE   );

   add_pkcs_padding( cleartxt + cleartxt_len, DES_BLOCK_SIZE, cleartxt_len, padded_len );

#ifndef  CLEARTEXT
	// SAB  XXX some crypto libraries expect to be able to change th einitial vector.
	// so we will enable that by a local variable

{
   CK_BYTE *initial_vector=NULL;
	
   initial_vector = (CK_BYTE *)alloca(strlen("10293847")+5);
   if (initial_vector) {	
      memcpy(initial_vector, "10293847", strlen("10293847"));
      rc = ckm_des3_cbc_encrypt( cleartxt,    padded_len,
				 ciphertxt,  &ciphertxt_len,
			         initial_vector, des3_key );
   } else {
      rc=CKR_FUNCTION_FAILED;
   }
}
#else
   memcpy(ciphertxt, cleartxt, padded_len);
   rc = CKR_OK;
#endif
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DES3_CBC_ENCRYPT);
      goto error;
   }

   strncat( (char *)fname,(char *) obj->name, 8 );

   fp = fopen( (char *)fname, "w" );
   if (!fp) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto error;
   }

   set_perm(fileno(fp));

   total_len = sizeof(CK_ULONG_32) + sizeof(CK_BBOOL) + ciphertxt_len;

   flag = TRUE;

   (void)fwrite( &total_len, sizeof(CK_ULONG_32), 1, fp );
   (void)fwrite( &flag,      sizeof(CK_BBOOL), 1, fp );
   (void)fwrite( ciphertxt,  ciphertxt_len,    1, fp );

   fclose( fp );

   free( obj_data  );
   free( cleartxt  );
   free( ciphertxt );
   return CKR_OK;

error:
   if (fp)  fclose( fp );

   if (obj_data)  free( obj_data  );
   if (cleartxt)  free( cleartxt  );
   if (ciphertxt) free( ciphertxt );

   return rc;
}


//
//
CK_RV
load_public_token_objects( void )
{
   FILE     *fp1 = NULL, *fp2 = NULL;
   CK_BYTE  *buf = NULL;
   CK_BYTE   tmp[PATH_MAX], fname[PATH_MAX],iname[PATH_MAX];
   CK_BBOOL  priv = FALSE;
   CK_ULONG_32  size;
   size_t       read_size;


   sprintf((char *)iname,"%s/%s/%s",pk_dir,PK_LITE_OBJ_DIR, PK_LITE_OBJ_IDX);

   fp1 = fopen((char *)iname, "r");
   if (!fp1)
      return CKR_OK;  // no token objects

   while (!feof(fp1)) {
      (void)fgets( (char *)tmp, 50, fp1 );
      if (!feof(fp1)) {
         tmp[ strlen((char *)tmp)-1 ] = 0;

	 sprintf((char *)fname,"%s/%s/",pk_dir, PK_LITE_OBJ_DIR);
         strcat((char *)fname, (char *)tmp );

         fp2 = fopen( (char *)fname, "r" );
         if (!fp2)
            continue;

         fread( &size, sizeof(CK_ULONG_32), 1, fp2 );
         fread( &priv, sizeof(CK_BBOOL), 1, fp2 );
         if (priv == TRUE) {
            fclose( fp2 );
            continue;
         }

         // size--;
	 size = size -sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);
         buf = (CK_BYTE *)malloc(size);
         if (!buf) {
            fclose(fp2);
	    OCK_SYSLOG(LOG_ERR, "Cannot malloc %u bytes to read in token object %s (ignoring it)",
		size, fname);
	    continue;
         }

         read_size = fread( buf, 1, size, fp2 );
	 if (read_size != size) {
	    OCK_SYSLOG(LOG_ERR, "Cannot read in token object %s (ignoring it)", fname);
            fclose(fp2);
	    free(buf);
	    continue;
	 }

         // ... grab object mutex here.
         MY_LockMutex(&obj_list_mutex);
	 if (object_mgr_restore_obj_withSize(buf, NULL, size) != CKR_OK) {
	    OCK_SYSLOG(LOG_ERR, "Cannot restore token object %s (ignoring it)", fname);
	 }
         MY_UnlockMutex(&obj_list_mutex);
         free( buf );
         fclose( fp2 );
      }
   }
   fclose(fp1);

   return CKR_OK;
}


//
//
CK_RV
load_private_token_objects( void )
{
   FILE     *fp1 = NULL, *fp2 = NULL;
   CK_BYTE  *buf = NULL;
   CK_BYTE   tmp[PATH_MAX], fname[PATH_MAX], iname[PATH_MAX];
   CK_BBOOL  priv;
   CK_ULONG_32  size;
   CK_RV     rc;


   sprintf((char *)iname,"%s/%s/%s",pk_dir,PK_LITE_OBJ_DIR, PK_LITE_OBJ_IDX);

   fp1 = fopen((char *)iname, "r");
   if (!fp1)
      return CKR_OK;  // no token objects

   while (!feof(fp1)) {
      (void)fgets((char *) tmp, 50, fp1 );
      if (!feof(fp1)) {
         tmp[ strlen((char *)tmp)-1 ] = 0;

	 sprintf((char *)fname,"%s/%s/",pk_dir,PK_LITE_OBJ_DIR);
         strcat((char *)fname,(char *) tmp );

         fp2 = fopen( (char *)fname, "r" );
         if (!fp2)
            continue;

         fread( &size, sizeof(CK_ULONG_32), 1, fp2 );
         fread( &priv, sizeof(CK_BBOOL), 1, fp2 );
         if (priv == FALSE) {
            fclose( fp2 );
            continue;
         }

         //size--;
	 size = size - sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);
         buf = (CK_BYTE *)malloc(size);
         if (!buf) {
	    fclose( fp2 );
	    OCK_SYSLOG(LOG_ERR, "Cannot malloc %u bytes to read in token object %s (ignoring it)",
		size, fname);
	    continue;
         }

         rc = fread( (char *)buf, size, 1, fp2 );
         if (rc != 1) {
	    OCK_SYSLOG(LOG_ERR, "Cannot read in token object %s (ignoring it)", fname);
	    fclose( fp2 );
	    continue;
         }

// Grab object list  mutex
	MY_LockMutex(&obj_list_mutex);
         rc = restore_private_token_object( buf, size, NULL );
	MY_UnlockMutex(&obj_list_mutex);
         if (rc != CKR_OK){
            OCK_LOG_ERR(ERR_TOKEN_RESTORE_PRIV);
            goto error;
         }

         free( buf );
         fclose( fp2 );
      }
   }
   fclose(fp1);

   return CKR_OK;

error:
   if (buf)  free( buf );
   if (fp1)  fclose( fp1 );
   if (fp2)  fclose( fp2 );
   return rc;
}


//
//
CK_RV
restore_private_token_object( CK_BYTE  * data,
                              CK_ULONG   len,
                              OBJECT   * pObj )
{
   CK_BYTE          * cleartxt  = NULL;
   CK_BYTE          * obj_data  = NULL;
   CK_BYTE          * ciphertxt = NULL;
   CK_BYTE          * ptr       = NULL;
   CK_BYTE            des3_key[MASTER_KEY_SIZE];
   CK_BYTE            hash_sha[SHA1_HASH_SIZE];
   CK_ULONG           cleartxt_len, obj_data_len;
   CK_RV              rc;

   // format for the object data:
   //    (private flag has already been read at this point)
   //    ---- begin encrypted part
   //       length of object data
   //       object data
   //       SHA of object data
   //    ---- end encrypted part
   //

   cleartxt_len = len;

   cleartxt  = (CK_BYTE *)malloc(len);
   if (!cleartxt) {
      OCK_LOG_ERR(ERR_HOST_MEMORY);
      rc = CKR_HOST_MEMORY;
      goto done;
   }

   ciphertxt = data;

   // decrypt the encrypted chunk
   //
   memcpy( des3_key, master_key, MASTER_KEY_SIZE );

#ifndef  CLEARTEXT
{
   CK_BYTE *initial_vector=NULL;

   initial_vector = (CK_BYTE *)alloca(strlen("10293847")+5);
   if (initial_vector) {
      memcpy(initial_vector, "10293847", strlen("10293847"));
      rc = ckm_des3_cbc_decrypt( ciphertxt,    len,
                                 cleartxt,  &len,
                                 initial_vector, des3_key );
   } else {
      rc=CKR_FUNCTION_FAILED;
   }
}
#else
   memcpy(cleartxt, ciphertxt, len);
   rc = CKR_OK;
#endif
 
   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DES3_CBC_DECRYPT);
      goto done;
   }

   strip_pkcs_padding( cleartxt, len, &cleartxt_len );

   // if the padding extraction didn't work it means the object was tampered with or
   // the key was incorrect
   //
   if (cleartxt_len > len) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   ptr = cleartxt;

   obj_data_len = *(CK_ULONG_32 *)ptr;

   if (obj_data_len > cleartxt_len) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   ptr += sizeof(CK_ULONG_32);
   obj_data = ptr;

   // check the hash
   //
   compute_sha( ptr, obj_data_len, hash_sha );
   ptr += obj_data_len;

   if (memcmp(ptr, hash_sha, SHA1_HASH_SIZE) != 0) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   // okay.  at this point, we're satisfied that nobody has tampered with the
   // token object...
   //

   object_mgr_restore_obj( obj_data, pObj );
   rc = CKR_OK;

done:
   if (cleartxt)  free( cleartxt );

   return rc;
}


//
//
CK_RV
load_masterkey_so( void )
{
   FILE               * fp  = NULL;
   CK_BYTE              hash_sha[SHA1_HASH_SIZE];
   CK_BYTE              cipher[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE              clear [sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE              des3_key[3 * DES_KEY_SIZE];
   MASTER_KEY_FILE_T    mk;
   CK_ULONG             cipher_len, clear_len;
   CK_RV                rc;
   CK_BYTE              fname[PATH_MAX];


   sprintf((char *)fname,"%s/MK_SO",pk_dir);

   memset( master_key, 0x0, MASTER_KEY_SIZE );

   // this file gets created on C_InitToken so we can assume that it always exists
   //
   fp = fopen((char *)fname, "r");
   if (!fp) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   set_perm(fileno(fp));
   clear_len = cipher_len = (sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE - 1) & ~(DES_BLOCK_SIZE - 1);

   rc = fread( cipher, cipher_len, 1, fp );
   if (rc != 1) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   // decrypt the master key data using the MD5 of the SO key
   // (we can't use the SHA of the SO key since the SHA of the key is stored
   // in the token data file).
   //
   memcpy( des3_key,                 so_pin_md5, MD5_HASH_SIZE );
   memcpy( des3_key + MD5_HASH_SIZE, so_pin_md5, DES_KEY_SIZE  );

#ifndef CLEARTEXT
{
   CK_BYTE *initial_vector=NULL;

   initial_vector = (CK_BYTE *)alloca(strlen("12345678")+5);
   if (initial_vector) {
      memcpy(initial_vector, "12345678", strlen("12345678"));
      rc = sw_des3_cbc_decrypt( cipher, cipher_len, clear, &clear_len, initial_vector, des3_key );
   } else {
      rc=CKR_FUNCTION_FAILED;
   }
}
#else
   memcpy(clear, cipher, cipher_len);
   rc = CKR_OK;
#endif

   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DES3_CBC_DECRYPT);
      goto done;
   }
   memcpy( (CK_BYTE *)&mk, clear, sizeof(mk) );

   //
   // technically should strip PKCS padding here but since I already know what
   // the length should be, I don't bother.
   //


   // compare the hashes
   //
   compute_sha( mk.key, MASTER_KEY_SIZE, hash_sha );

   if (memcmp(hash_sha, mk.sha_hash, SHA1_HASH_SIZE) != 0) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   memcpy( master_key, mk.key, MASTER_KEY_SIZE );
   rc = CKR_OK;

done:
   if (fp)  fclose(fp);
   return rc;
}


//
//
CK_RV
load_masterkey_user( void )
{
   FILE               * fp  = NULL;
   CK_BYTE              hash_sha[SHA1_HASH_SIZE];
   CK_BYTE              cipher[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE              clear[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE              des3_key[3 * DES_KEY_SIZE];
   MASTER_KEY_FILE_T    mk;
   CK_ULONG             cipher_len, clear_len;
   CK_RV                rc;
   CK_BYTE              fname[PATH_MAX];


   sprintf((char *)fname,"%s/MK_USER",pk_dir);

   memset( master_key, 0x0, MASTER_KEY_SIZE );

   // this file gets created on C_InitToken so we can assume that it always exists
   //
   fp = fopen( (char *)fname, "r" );
   if (!fp) {
      OCK_SYSLOG(LOG_ERR, "fopen(%s): %s", fname, strerror(errno));
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   set_perm(fileno(fp));
   clear_len = cipher_len = (sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE - 1) & ~(DES_BLOCK_SIZE - 1);

   rc = fread( cipher, cipher_len, 1, fp );
   if (rc != 1) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   // decrypt the master key data using the MD5 of the SO key
   // (we can't use the SHA of the SO key since the SHA of the key is stored
   // in the token data file).
   //
   memcpy( des3_key,                 user_pin_md5, MD5_HASH_SIZE );
   memcpy( des3_key + MD5_HASH_SIZE, user_pin_md5, DES_KEY_SIZE  );

#ifndef CLEARTEXT
{
   CK_BYTE *initial_vector=NULL;

   initial_vector = (CK_BYTE *)alloca(strlen("12345678")+5);
   if (initial_vector) {
      memcpy(initial_vector, "12345678", strlen("12345678"));
      rc = sw_des3_cbc_decrypt( cipher, cipher_len, clear, &clear_len, initial_vector, des3_key );
   } else {
      rc=CKR_FUNCTION_FAILED;
   }
}
#else
   memcpy(clear, cipher, cipher_len);
   rc = CKR_OK;
#endif

   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DES3_CBC_DECRYPT);
      goto done;
   }
   memcpy( (CK_BYTE *)&mk, clear, sizeof(mk) );

   //
   // technically should strip PKCS padding here but since I already know what
   // the length should be, I don't bother.
   //


   // compare the hashes
   //
   compute_sha( mk.key, MASTER_KEY_SIZE, hash_sha );

   if (memcmp(hash_sha, mk.sha_hash, SHA1_HASH_SIZE) != 0) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   memcpy( master_key, mk.key, MASTER_KEY_SIZE );
   rc = CKR_OK;

done:
   if (fp)  fclose(fp);
   return rc;
}


//
//
CK_RV
save_masterkey_so( void )
{
   FILE             * fp = NULL;
   CK_BYTE            cleartxt [sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE            ciphertxt[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE            des3_key[3 * DES_KEY_SIZE];
   MASTER_KEY_FILE_T  mk;
   CK_ULONG           cleartxt_len, ciphertxt_len, padded_len;
   CK_RV              rc;
   CK_BYTE            fname[PATH_MAX];


   memcpy( mk.key, master_key, MASTER_KEY_SIZE);

   compute_sha( master_key, MASTER_KEY_SIZE, mk.sha_hash );

   // encrypt the key data
   //
   memcpy( des3_key,                 so_pin_md5, MD5_HASH_SIZE );
   memcpy( des3_key + MD5_HASH_SIZE, so_pin_md5, DES_KEY_SIZE  );

   ciphertxt_len = sizeof(ciphertxt);
   cleartxt_len  = sizeof(mk);
   memcpy( cleartxt, &mk, cleartxt_len );

   padded_len = DES_BLOCK_SIZE * (cleartxt_len / DES_BLOCK_SIZE + 1);
   add_pkcs_padding( cleartxt + cleartxt_len, DES_BLOCK_SIZE, cleartxt_len, padded_len );

#ifndef CLEARTEXT
{
   CK_BYTE *initial_vector=NULL;

   initial_vector = (CK_BYTE *)alloca(strlen("12345678"));
   if (initial_vector) {
      memcpy(initial_vector, "12345678", strlen("12345678"));
      rc = sw_des3_cbc_encrypt( cleartxt, padded_len, ciphertxt, &ciphertxt_len, initial_vector, des3_key );
   } else {
      rc=CKR_FUNCTION_FAILED;
   }
}
#else
   memcpy(ciphertxt, cleartxt, padded_len);
   rc = CKR_OK;
#endif

   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DES3_CBC_ENCRYPT);
      goto done;
   }

   // write the file
   //
   // probably ought to ensure the permissions are correct
   //
   sprintf((char *)fname,"%s/MK_SO",pk_dir);
   fp = fopen( (char *)fname, "w" );
   if (!fp) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }
   set_perm(fileno(fp));

   rc = fwrite( ciphertxt, ciphertxt_len, 1, fp );
   if (rc != 1) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   rc = CKR_OK;

done:
   if (fp)  fclose( fp );
   return rc;
}


//
//
CK_RV
save_masterkey_user( void )
{
   FILE             * fp = NULL;
   CK_BYTE            cleartxt [sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE            ciphertxt[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE            des3_key[3 * DES_KEY_SIZE];
   MASTER_KEY_FILE_T  mk;
   CK_ULONG           cleartxt_len, ciphertxt_len, padded_len;
   CK_RV              rc;
   CK_BYTE            fname[PATH_MAX];

   memcpy( mk.key, master_key, MASTER_KEY_SIZE);

   compute_sha( master_key, MASTER_KEY_SIZE, mk.sha_hash );


   // encrypt the key data
   //
   memcpy( des3_key,                 user_pin_md5, MD5_HASH_SIZE );
   memcpy( des3_key + MD5_HASH_SIZE, user_pin_md5, DES_KEY_SIZE  );

   ciphertxt_len = sizeof(ciphertxt);
   cleartxt_len  = sizeof(mk);
   memcpy( cleartxt, &mk, cleartxt_len );

   padded_len = DES_BLOCK_SIZE * (cleartxt_len / DES_BLOCK_SIZE + 1);
   add_pkcs_padding( cleartxt + cleartxt_len, DES_BLOCK_SIZE, cleartxt_len, padded_len );

#ifndef CLEARTEXT
{
   CK_BYTE *initial_vector=NULL;

   initial_vector = (CK_BYTE *)alloca(strlen("12345678")+5);
   if (initial_vector) {
      memcpy(initial_vector, "12345678", strlen("12345678"));
      rc = sw_des3_cbc_encrypt( cleartxt, padded_len, ciphertxt, &ciphertxt_len, initial_vector, des3_key );
   } else {
      rc=CKR_FUNCTION_FAILED;
   }
}
#else
   memcpy(ciphertxt, cleartxt, padded_len);
   rc = CKR_OK;
#endif

   if (rc != CKR_OK){
      OCK_LOG_ERR(ERR_DES3_CBC_ENCRYPT);
      goto done;
   }


   // write the file
   //
   // probably ought to ensure the permissions are correct
   //
   sprintf((char *)fname,"%s/MK_USER", pk_dir);
   fp = fopen( (char *)fname, "w" );
   if (!fp) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   set_perm(fileno(fp));
   rc = fwrite( ciphertxt, ciphertxt_len, 1, fp );
   if (rc != 1) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   rc = CKR_OK;

done:
   if (fp)  fclose( fp );
   return rc;
}


//
//
CK_RV
reload_token_object( OBJECT *obj )
{
   FILE     * fp  = NULL;
   CK_BYTE  * buf = NULL;
   CK_BYTE    fname[PATH_MAX];
   CK_BBOOL   priv;
   CK_ULONG_32   size;
   CK_ULONG   size_64;
   CK_RV      rc;
   size_t     read_size;


   memset( (char *)fname, 0x0, sizeof(fname) );

   sprintf((char *)fname,"%s/%s/",pk_dir, PK_LITE_OBJ_DIR);

   strncat((char *)fname,(char *)  obj->name, 8 );

   fp = fopen( (char *)fname, "r" );
   if (!fp) {
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   set_perm(fileno(fp));

   fread( &size, sizeof(CK_ULONG_32), 1, fp );
   fread( &priv, sizeof(CK_BBOOL), 1, fp );

   size = size - sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);  // SAB

   buf = (CK_BYTE *)malloc(size);
   if (!buf) {
      rc = CKR_HOST_MEMORY;
      OCK_SYSLOG(LOG_ERR, "Cannot malloc %u bytes to read in token object %s (ignoring it)", size, fname);
      goto done;
   }

   read_size = fread( buf, 1, size, fp );
   if (read_size != size) {
      OCK_SYSLOG(LOG_ERR, "Token object %s appears corrupted (ignoring it)", fname);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   size_64 = size;

   if (priv){
      rc = restore_private_token_object( buf, size_64, obj );
      if (rc != CKR_OK)
         OCK_LOG_ERR(ERR_TOKEN_RESTORE_PRIV);
   }
   else{
      rc = object_mgr_restore_obj( buf, obj );
      if (rc != CKR_OK)
         OCK_LOG_ERR(ERR_OBJ_RESTORE);
   }

done:
   if (fp)  fclose( fp );
   if (buf) free( buf );
   return rc;
}



extern void set_perm(int) ;

//
//
CK_RV
delete_token_object( OBJECT *obj )
{
   FILE      *fp1, *fp2;
   CK_BYTE    line[100];
   CK_BYTE    objidx[PATH_MAX], idxtmp[PATH_MAX],fname[PATH_MAX];


   sprintf((char *)objidx,"%s/%s/%s",pk_dir, PK_LITE_OBJ_DIR,PK_LITE_OBJ_IDX);
   sprintf((char *)idxtmp,"%s/%s/%s",pk_dir, PK_LITE_OBJ_DIR, "IDX.TMP");

   // FIXME:  on UNIX, we need to make sure these guys aren't symlinks
   //         before we blindly write to these files...
   //

   // remove the object from the index file
   //

   fp1 = fopen((char *)objidx, "r");
   fp2 = fopen((char *)idxtmp, "w");
   if (!fp1 || !fp2) {
      if (fp1) fclose(fp1);
      if (fp2) fclose(fp2);
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   set_perm(fileno(fp2));

   while (!feof(fp1)) {
      (void)fgets((char *)line, 50, fp1 );
      if (!feof(fp1)) {
         line[ strlen((char *)line)-1 ] = 0;
         if (strcmp((char *)line, (char *)obj->name) == 0)
            continue;
         else
            fprintf( fp2, "%s\n", line );
      }
   }

   fclose(fp1);
   fclose(fp2);
   fp2 = fopen((char *)objidx, "w");
   fp1 = fopen((char *)idxtmp, "r");
   if (!fp1 || !fp2) {
      if (fp1) fclose(fp1);
      if (fp2) fclose(fp2);
      OCK_LOG_ERR(ERR_FUNCTION_FAILED);
      return CKR_FUNCTION_FAILED;
   }

   set_perm(fileno(fp2));

   while (!feof(fp1)) {
      (void)fgets((char *)line, 50, fp1 );
      if (!feof(fp1))
         fprintf( fp2, "%s",(char *) line );
   }

   fclose(fp1);
   fclose(fp2);

   sprintf((char *)fname,"%s/%s/%s",pk_dir, PK_LITE_OBJ_DIR,(char *)obj->name);
   unlink((char *)fname);
   return CKR_OK;

}

