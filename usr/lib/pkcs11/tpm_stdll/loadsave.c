
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


// loadsave.c
//
// routines associated with loading/saving files
//
//

/* loading/saving token objects will work like this on the TPM token:
 *
 * @DB_PATH@/TOK_OBJ/*                  - SO token objects
 * @DB_PATH@/TOK_OBJ/OBJ.IDX            - Index file for the SO token objects
 * @DB_PATH@/TOK_OBJ/username/*         - username's token objects
 * @DB_PATH@/TOK_OBJ/username/OBJ.IDX   - Index file for username's token objects
 *
 * XXX username must be prepended to the object name even inside the username directory
 * because all objects will be in one global namespace after they're read in from
 * disk.
 *
 */


#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <sys/file.h>
#include <unistd.h>
#include <errno.h>
#include <dirent.h>
#include <grp.h>

#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"
//#include "args.h"

//extern void  st_err_log(char *fmt, ...);

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
	CK_BYTE     fname[2048];
	TOKEN_DATA    td;
	CK_BYTE       clear[3 * DES_BLOCK_SIZE];  // enough to hold a CBC-encrypted SHA hash
	CK_BYTE       cipher[3 * DES_BLOCK_SIZE];
	CK_ULONG      clear_len, cipher_len;
	CK_RV         rc;

	rc = XProcLock( xproclock );
	if (rc != CKR_OK){
		st_err_log(150, __FILE__, __LINE__);
		goto out_nolock;
	}

	sprintf((char *)fname,"%s/%s",(char *)pk_dir, PK_LITE_NV);

	//fp = fopen("/tmp/NVTOK.DAT", "r");
	fp = fopen((char *)fname, "r");
	if (!fp) {
		/* Better error checking added */
		if (errno == ENOENT) {
			/* init_token_data may call save_token_data, which graps the 
			 * xproclock, so we must release it around this call */
			XProcUnLock( xproclock );
			init_token_data();
			rc = XProcLock( xproclock );
			if (rc != CKR_OK){
				st_err_log(150, __FILE__, __LINE__);
				goto out_nolock;
			}

			//fp = fopen("/tmp/NVTOK.DAT", "r");
			fp = fopen((char *)fname, "r");
			if (!fp) {
				// were really hosed here since the created
				// did not occur
				st_err_log(194, __FILE__, __LINE__, PK_LITE_NV, errno);
				rc = CKR_FUNCTION_FAILED;
				goto out_unlock;
			}
		} else {
			/* Could not open file for some unknown reason */
			st_err_log(194, __FILE__, __LINE__, PK_LITE_NV, errno);
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

	//   memcpy( cipher, &td.user_pin_sha, 3*DES_BLOCK_SIZE );
	//   clear_len = cipher_len = 3 * DES_BLOCK_SIZE;
	//   rc = ckm_des3_cbc_decrypt( cipher, cipher_len, clear, &clear_len, "12345678", master_key );
	//   if (rc != CKR_OK)
	//      return CKR_FUNCTION_FAILED;
	//
	//   memcpy( &td.user_pin_sha, clear, clear_len );
	//
	//   memcpy( cipher, &td.so_pin_sha, 3*DES_BLOCK_SIZE );
	//   clear_len = cipher_len = 3 * DES_BLOCK_SIZE;
	//   rc = ckm_des3_cbc_decrypt( cipher, cipher_len, clear, &clear_len, "12345678", master_key );
	//   if (rc != CKR_OK)
	//      return CKR_FUNCTION_FAILED;
	//
	//   memcpy( &td.so_pin_sha, clear, clear_len );

	memcpy( nv_token_data, &td, sizeof(TOKEN_DATA) );

	rc = CKR_OK;

out_unlock:
	XProcUnLock( xproclock );

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
	CK_BYTE     clear[3 * DES_BLOCK_SIZE];
	CK_BYTE     cipher[3 * DES_BLOCK_SIZE];
	CK_ULONG    clear_len, cipher_len;
	CK_RV       rc;
	CK_BYTE     fname[2048];

	rc = XProcLock( xproclock );
	if (rc != CKR_OK){
		st_err_log(150, __FILE__, __LINE__);
		goto out_nolock;
	}

	sprintf((char *)fname,"%s/%s",pk_dir, PK_LITE_NV);
	//fp = fopen("/tmp/NVTOK.DAT", "w");
	fp = fopen((char *)fname, "w");

	if (!fp){
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}
	set_perm(fileno(fp));

	memcpy( &td, nv_token_data, sizeof(TOKEN_DATA) );

	//   memcpy( clear, nv_token_data->user_pin_sha, SHA1_HASH_SIZE );
	//   memcpy( clear + SHA1_HASH_SIZE, "1234", 4 );
	//   clear_len = cipher_len = 3 * DES_KEY_SIZE;
	//   rc = ckm_des3_cbc_encrypt( clear, clear_len, cipher, &cipher_len, "12345678", master_key );
	//   if (rc != CKR_OK)
	//      goto done;
	//
	//   memcpy( td.user_pin_sha, cipher, 3*DES_BLOCK_SIZE );
	//
	//   memcpy( clear, nv_token_data->so_pin_sha, SHA1_HASH_SIZE );
	//   memcpy( clear + SHA1_HASH_SIZE, "1234", 4 );
	//   clear_len = cipher_len = 3 * DES_KEY_SIZE;
	//   rc = ckm_des3_cbc_encrypt( clear, clear_len, cipher, &cipher_len, "12345678", master_key );
	//   if (rc != CKR_OK)
	//      goto done;
	//
	//   memcpy( td.so_pin_sha, cipher, 3*DES_BLOCK_SIZE );

	fwrite( &td, sizeof(TOKEN_DATA), 1, fp );
	fclose(fp);

	rc = CKR_OK;

done:
	XProcUnLock( xproclock );

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
	CK_BYTE     fname[2048];

	if (object_is_private(obj) == TRUE)
		rc = save_private_token_object( obj );
	else
		rc = save_public_token_object( obj );

	if (rc != CKR_OK){
		st_err_log(104, __FILE__, __LINE__);
		return rc;
	}
	// update the index file if it exists
	//
	if (TPMTOK_USERNAME == NULL) {
		sprintf((char *)fname,"%s/%s/%s",pk_dir,PK_LITE_OBJ_DIR,PK_LITE_OBJ_IDX);
	} else {
		sprintf((char *)fname,"%s/%s/%s/%s",pk_dir,PK_LITE_OBJ_DIR,TPMTOK_USERNAME,PK_LITE_OBJ_IDX);
	}

	//fp = fopen( "/tmp/TOK_OBJ/OBJ.IDX", "r" );
	fp = fopen( (char *)fname, "r" );
	if (fp) {
		set_perm(fileno(fp));
		while (!feof(fp)) {
			fgets((char *)line, 50, fp );
			if (!feof(fp)) {
				line[ strlen((char *)line)-1 ] = 0;
				if (strcmp((char *)line,(char *)(obj->name)) == 0) {
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
	//fp = fopen("/tmp/TOK_OBJ/OBJ.IDX", "a");
	fp = fopen((char *)fname, "a");
	if (!fp){
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
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
save_public_token_object(OBJECT *obj )
{
	FILE       * fp       = NULL;
	CK_BYTE    * cleartxt = NULL;
	CK_BYTE      fname[2048];
	CK_ULONG     cleartxt_len;
	CK_BBOOL     flag = FALSE;
	CK_RV        rc;
	CK_ULONG_32  total_len;

	rc = object_flatten( obj, &cleartxt, &cleartxt_len );
	if (rc != CKR_OK){
		st_err_log(101, __FILE__, __LINE__);
		goto error;
	}

retry_open:
	//strcpy( fname, "/tmp/TOK_OBJ/" );
	if (TPMTOK_USERNAME == NULL) {
		sprintf( (char *)fname,"%s/%s/", pk_dir,PK_LITE_OBJ_DIR);
	} else {
		sprintf( (char *)fname,"%s/%s/%s/", pk_dir,PK_LITE_OBJ_DIR, TPMTOK_USERNAME);
	}
	strncat( (char *)fname, (char *) obj->name, 8 );

	//fp = fopen( (char *)fname, "w" );
	fp = fopen( (char *)fname, "r+" );
	if (!fp) {
		if (errno == ENOENT) {
			/* this is good, we're opening a new file */
			fp = fopen( (char *)fname, "w" );
			if (!fp) {
				LogError("errno: %d: %s", errno, strerror(errno));
				st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
				rc = CKR_FUNCTION_FAILED;
				goto error;
			}
		} else {
			LogError("errno: %d: %s", errno, strerror(errno));
			st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
			rc = CKR_FUNCTION_FAILED;
			goto error;
		}
	} else {
		/* XXX file exists, namespace collision hopefully due to migration */
		CK_CHAR name[8];

		memcpy(name, obj->name, 8);
		compute_next_token_obj_name(name, obj->name);
		goto retry_open;
	}

	set_perm(fileno(fp));

	total_len = cleartxt_len + sizeof(CK_ULONG_32) + sizeof(CK_BBOOL);

	fwrite( &total_len, sizeof(CK_ULONG_32), 1, fp );
	fwrite( &flag,      sizeof(CK_BBOOL), 1, fp );
	fwrite( cleartxt,   cleartxt_len,     1, fp );

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
save_private_token_object(OBJECT *obj)
{
	FILE             * fp        = NULL;
	CK_BYTE          * obj_data  = NULL;
	CK_BYTE          * cleartxt  = NULL;
	CK_BYTE          * ciphertxt = NULL;
	CK_BYTE          * ptr       = NULL;
	CK_BYTE            fname[100];
	CK_BYTE            hash_sha[SHA1_HASH_SIZE];
	CK_BYTE            hash_md5[MD5_HASH_SIZE];
	CK_BYTE            des3_key[3 * DES_KEY_SIZE];
	CK_ULONG           obj_data_len,cleartxt_len, ciphertxt_len, hash_len, tmp, tmp2;
	CK_ULONG           padded_len;
	CK_BBOOL           flag;
	CK_RV              rc;
	CK_ULONG_32        obj_data_len_32;
	CK_ULONG_32        total_len;

	rc = object_flatten( obj, &obj_data, &obj_data_len );
	obj_data_len_32 = obj_data_len;
	if (rc != CKR_OK){
		st_err_log(101, __FILE__, __LINE__);
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
	memcpy( des3_key, master_key, 3*DES_KEY_SIZE );

	cleartxt_len = sizeof(CK_ULONG_32) + obj_data_len_32 + SHA1_HASH_SIZE;
	padded_len   = DES_BLOCK_SIZE * (cleartxt_len / DES_BLOCK_SIZE + 1);

	cleartxt  = (CK_BYTE *)malloc( padded_len );
	ciphertxt = (CK_BYTE *)malloc( padded_len );
	if (!cleartxt || !ciphertxt) {
		st_err_log(0, __FILE__, __LINE__);
		rc = CKR_HOST_MEMORY;
		goto error;
	}

	ciphertxt_len = padded_len;

	ptr = cleartxt;
	memcpy( ptr, &obj_data_len_32, sizeof(CK_ULONG_32) );  ptr += sizeof(CK_ULONG_32);
	memcpy( ptr,  obj_data,     obj_data_len_32     );  ptr += obj_data_len_32;
	memcpy( ptr,  hash_sha,     SHA1_HASH_SIZE   );

	add_pkcs_padding( cleartxt + cleartxt_len, DES_BLOCK_SIZE, cleartxt_len, padded_len );

#if 0
#ifndef  CLEARTEXT

	rc = ckm_des3_cbc_encrypt( cleartxt,    padded_len,
			ciphertxt,  &ciphertxt_len,
			"10293847", (char *) des3_key );
#else
	bcopy(cleartxt,ciphertxt,padded_len);
	rc = CKR_OK;
#endif
#endif
	/* do things in cleartext for now */
	bcopy(cleartxt,ciphertxt,padded_len);
	rc = CKR_OK;

	if (rc != CKR_OK){
		st_err_log(105, __FILE__, __LINE__);
		goto error;
	}

retry_open:
	//strcpy( (char *)fname, "/tmp/TOK_OBJ/" );
	if (TPMTOK_USERNAME == NULL) {
		sprintf( (char *)fname,"%s/%s/", pk_dir,PK_LITE_OBJ_DIR);
	} else {
		sprintf( (char *)fname,"%s/%s/%s/", pk_dir,PK_LITE_OBJ_DIR, TPMTOK_USERNAME);
	}
	strncat( (char *)fname,(char *) obj->name, 8 );

	fp = fopen( (char *)fname, "r+" );
	if (!fp) {
		if (errno == ENOENT) {
			/* this is good, we're opening a new file */
			fp = fopen( (char *)fname, "w" );
			if (!fp) {
				LogError("errno: %d: %s", errno, strerror(errno));
				st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
				rc = CKR_FUNCTION_FAILED;
				goto error;
			}
		} else {
			LogError("errno: %d: %s", errno, strerror(errno));
			st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
			rc = CKR_FUNCTION_FAILED;
			goto error;
		}
	} else {
		/* XXX file exists, namespace collision hopefully due to migration */
		CK_CHAR name[8];

		memcpy(name, obj->name, 8);
		compute_next_token_obj_name(name, obj->name);
		goto retry_open;
	}


	set_perm(fileno(fp));

	total_len = sizeof(CK_ULONG_32) + sizeof(CK_BBOOL) + ciphertxt_len;

	flag = TRUE;

	fwrite( &total_len, sizeof(CK_ULONG_32), 1, fp );
	fwrite( &flag,      sizeof(CK_BBOOL), 1, fp );
	fwrite( ciphertxt,  ciphertxt_len,    1, fp );

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

/*
 * read objects from index file f.
 */
CK_RV
read_public_objects( FILE *f, CK_BYTE *dir )
{
	CK_ULONG_32  size;
	FILE *fp2 = NULL;
	CK_BYTE fname[2048], tmp[2048];
	CK_BYTE  *buf = NULL;
	CK_BBOOL  priv;

	while (!feof(f)) {
		fgets( (char *)tmp, 50, f );
		if (!feof(f)) {
			tmp[ strlen((char *)tmp)-1 ] = 0;

			//strcpy(fname,"/tmp/TOK_OBJ/username");
			if (dir == NULL) {
				sprintf((char *)fname,"%s/%s/",pk_dir, PK_LITE_OBJ_DIR);
			} else {
				sprintf((char *)fname,"%s/%s/%s/",pk_dir, PK_LITE_OBJ_DIR, dir);
			}
			strcat((char *)fname, (char *)tmp );

			fp2 = fopen( (char *)fname, "r" );
			if (!fp2) {
				LogError("Unable to open %s. Continuing.", fname);
				continue;
			}

			fread( &size, sizeof(CK_ULONG_32), 1, fp2 );
			fread( &priv, sizeof(CK_BBOOL), 1, fp2 );
			if (priv == TRUE) {
				fclose( fp2 );
				fp2 = NULL;
				continue;
			}

			// size--;
			size = size -sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);
			buf = (CK_BYTE *)malloc(size);
			if (!buf) {
				fclose(fp2);
				fp2 = NULL;
				st_err_log(0, __FILE__, __LINE__);
				return CKR_HOST_MEMORY;
			}

			fread( buf, size, 1, fp2 );

			// ... grab object mutex here.
			MY_LockMutex(&obj_list_mutex);
			object_mgr_restore_obj( buf, NULL );
			MY_UnlockMutex(&obj_list_mutex);
			free( buf );
			fclose( fp2 );
			fp2 = NULL;
		}
	}

	return CKR_OK;
}


// doesn't matter who owns these objects or what directories they're coming out of, we
// need to load *all* pub token objects.
CK_RV
load_public_token_objects( void )
{
	FILE     *fp1 = NULL;
	CK_BYTE   iname[2048];
	CK_BYTE dirname[2048], tmp[2048];
	DIR *obj_dir;
	struct dirent *dentry;
	struct stat dir_stat;

	sprintf((char *)iname,"%s/%s/%s",pk_dir,PK_LITE_OBJ_DIR, PK_LITE_OBJ_IDX);
	//fp1 = fopen("/tmp/TOK_OBJ/OBJ.IDX", "r");
	fp1 = fopen((char *)iname, "r");
	if (!fp1)
		return CKR_OK;  // no token objects

	/* read SO objects from the base object directory */
	if (read_public_objects(fp1, NULL) != CKR_OK)
		goto done;

	fclose(fp1);
	fp1 = NULL;

	/* for each user subdir, read objects out */
	sprintf((char *)dirname,"%s/%s",pk_dir,PK_LITE_OBJ_DIR);
	obj_dir = opendir(dirname);

	if (obj_dir == NULL)
		return CKR_OK;

	/* for each directory underneath pk_dir/PK_LITE_OBJ_DIR, read objects
	 * out */
	while ((dentry = readdir(obj_dir)) != NULL) {
		if (!strncmp(dentry->d_name, ".\0", 2))
			continue;
		if (!strncmp(dentry->d_name, "..\0", 3))
			continue;

		sprintf(tmp, "%s/%s", dirname, dentry->d_name);

		/* check if the given entry is a directory. */
		if (stat(tmp, &dir_stat) == -1) {
			LogError("stat of %s failed: %s", tmp, strerror(errno));
			continue;
		}

		/* is this a directory? */
		if (S_ISDIR(dir_stat.st_mode)) {
			sprintf((char *)iname,"%s/%s/%s/%s",pk_dir,PK_LITE_OBJ_DIR,dentry->d_name,PK_LITE_OBJ_IDX);
			//fp1 = fopen("/pk_dir/TOK_OBJ/username/OBJ.IDX", "r");
			fp1 = fopen((char *)iname, "r");
			if (!fp1) {
				LogError("Unable to open %s. Continuing.", iname);
				continue;
			}

			if (read_public_objects(fp1, dentry->d_name) != CKR_OK)
				goto done;

			fclose(fp1);
			fp1 = NULL;
		}
	}


done:
	if (fp1) {
		fclose(fp1);
	}

	return CKR_OK;
}


CK_RV
read_private_objects ( FILE *f, CK_BYTE *dir )
{
	CK_BYTE  *buf = NULL;
	CK_BYTE tmp[2048], fname[2048];
	CK_BBOOL  priv;
	FILE *fp2 = NULL;
	CK_RV rc;
	CK_ULONG_32  size;

	while (!feof(f)) {
		fgets((char *) tmp, 50, f );
		if (!feof(f)) {
			tmp[ strlen((char *)tmp)-1 ] = 0;

			//strcpy(fname,"/tmp/TOK_OBJ/username/OBJ.IDX");
			if (dir == NULL) {
				sprintf((char *)fname,"%s/%s/",pk_dir, PK_LITE_OBJ_DIR);
			} else {
				sprintf((char *)fname,"%s/%s/%s/",pk_dir, PK_LITE_OBJ_DIR, dir);
			}
			strcat((char *)fname,(char *) tmp );

			fp2 = fopen( (char *)fname, "r" );
			if (!fp2) {
				LogError("Unable to open %s. Continuing.", fname);
				continue;
			}

			fread( &size, sizeof(CK_ULONG_32), 1, fp2 );
			fread( &priv, sizeof(CK_BBOOL), 1, fp2 );
			if (priv == FALSE) {
				fclose( fp2 );
				fp2 = NULL;
				continue;
			}

			//size--;
			size = size - sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);
			buf = (CK_BYTE *)malloc(size);
			if (!buf) {
				st_err_log(0, __FILE__, __LINE__);
				rc = CKR_HOST_MEMORY;
				goto error;
			}

			rc = fread( (char *)buf, size, 1, fp2 );
			if (rc != 1) {
				st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
				rc = CKR_FUNCTION_FAILED;
				goto error;
			}

			// Grab object list  mutex
			MY_LockMutex(&obj_list_mutex);
			rc = restore_private_token_object( buf, size, NULL );
			MY_UnlockMutex(&obj_list_mutex);
			if (rc != CKR_OK){
				st_err_log(107, __FILE__, __LINE__);
				goto error;
			}

			free( buf );
			fclose( fp2 );
			fp2 = NULL;
		}
	}

error:
	if (fp2)  fclose( fp2 );
	return rc;
}

// doesn't matter who owns these objects or what directories they're coming out of, we
// need to load *all* priv token objects.
CK_RV
load_private_token_objects( void )
{
	FILE     *fp1 = NULL;
	CK_BYTE   iname[2048], dirname[2048];
	DIR *obj_dir;
	struct dirent *dentry;
	struct stat dir_stat;

	sprintf((char *)iname,"%s/%s/%s",pk_dir,PK_LITE_OBJ_DIR, PK_LITE_OBJ_IDX);
	//fp1 = fopen("/tmp/TOK_OBJ/OBJ.IDX", "r");
	fp1 = fopen((char *)iname, "r");
	if (!fp1)
		return CKR_OK;  // no token objects

	/* read SO objects from the base object directory */
	if (read_private_objects(fp1, NULL) != CKR_OK)
		goto done;

	fclose(fp1);

	/* for each user subdir, read objects out */
	sprintf((char *)dirname,"%s/%s",pk_dir,PK_LITE_OBJ_DIR);
	obj_dir = opendir(dirname);

	if (obj_dir == NULL)
		return CKR_OK;

	/* for each directory underneath pk_dir/PK_LITE_OBJ_DIR, read objects
	 * out */
	while ((dentry = readdir(obj_dir)) != NULL) {
		if (!strncmp(dentry->d_name, ".\0", 2))
			continue;
		if (!strncmp(dentry->d_name, "..\0", 3))
			continue;

		/* check if the given entry is a directory. */
		if (stat(dentry->d_name, &dir_stat) == -1) {
			continue;
		}

		/* is this a directory? */
		if (S_ISDIR(dir_stat.st_mode)) {
			sprintf((char *)iname,"%s/%s/%s/%s",pk_dir,PK_LITE_OBJ_DIR,dentry->d_name,PK_LITE_OBJ_IDX);
			//fp1 = fopen("/pk_dir/TOK_OBJ/username/OBJ.IDX", "r");
			fp1 = fopen((char *)iname, "r");
			if (!fp1)
				continue;

			if (read_private_objects(fp1, dentry->d_name) != CKR_OK) {
				goto done;
			}

			fclose(fp1);
		}
	}

done:
	fclose(fp1);

	return CKR_OK;
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
   CK_BYTE            des3_key[3 * DES_KEY_SIZE];
   CK_BYTE            hash_sha[SHA1_HASH_SIZE];
   CK_MECHANISM       mech;
   DIGEST_CONTEXT     digest_ctx;
   ENCR_DECR_CONTEXT  encr_ctx;
   CK_ULONG           hash_len, cleartxt_len, obj_data_len;
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
      st_err_log(0, __FILE__, __LINE__);
      rc = CKR_HOST_MEMORY;
      goto done;
   }

   ciphertxt = data;

   // decrypt the encrypted chunk
   //
   memcpy( des3_key, master_key, 3*DES_KEY_SIZE );

#if 0
#ifndef  CLEARTEXT
   rc = ckm_des3_cbc_decrypt( ciphertxt,  len,
                              cleartxt,  &len,
                              "10293847", des3_key );
#else
      bcopy(ciphertxt,cleartxt,len);
      rc = CKR_OK;
#endif
#endif
      /* do things in cleartext for now */
      bcopy(ciphertxt,cleartxt,len);
      rc = CKR_OK;

 
   if (rc != CKR_OK){
      st_err_log(106, __FILE__, __LINE__);
      goto done;
   }

   strip_pkcs_padding( cleartxt, len, &cleartxt_len );

   // if the padding extraction didn't work it means the object was tampered with or
   // the key was incorrect
   //
   if (cleartxt_len > len) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   ptr = cleartxt;

   obj_data_len = *(CK_ULONG_32 *)ptr;
   ptr += sizeof(CK_ULONG_32);
   obj_data = ptr;

   // check the hash
   //
   compute_sha( ptr, obj_data_len, hash_sha );
   ptr += obj_data_len;

   if (memcmp(ptr, hash_sha, SHA1_HASH_SIZE) != 0) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   // okay.  at this point, we're satisfied that nobody has tampered with the
   // token object...
   //

   //object_mgr_restore_obj( obj_data, NULL );
   object_mgr_restore_obj( obj_data, pObj );
   rc = CKR_OK;

done:
//   if (ciphertxt) free( ciphertxt );
   if (cleartxt)  free( cleartxt );

   return rc;
}


//
//
CK_RV
load_masterkey_so( void )
{
   FILE               * fp  = NULL;
   CK_BYTE            * ptr = NULL;
   CK_BYTE              hash_sha[SHA1_HASH_SIZE];
   CK_BYTE              cipher[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE              clear [sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE              des3_key[3 * DES_KEY_SIZE];
   CK_MECHANISM         mech;
   DIGEST_CONTEXT       digest_ctx;
   MASTER_KEY_FILE_T    mk;
   CK_ULONG             cipher_len, clear_len, hash_len;
   CK_RV                rc;
   CK_BYTE              fname[2048];

   memset( master_key, 0x0, 3*DES_KEY_SIZE );

   // this file gets created on C_InitToken so we can assume that it always exists
   //
   sprintf((char *)fname,"%s/MK_SO",pk_dir);
   //fp = fopen("/tmp/MK_SO", "r");
   fp = fopen((char *)fname, "r");
   if (!fp) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   set_perm(fileno(fp));
   clear_len = cipher_len = (sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE - 1) & ~(DES_BLOCK_SIZE - 1);

   rc = fread( cipher, cipher_len, 1, fp );
   if (rc != 1) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   // decrypt the master key data using the MD5 of the SO key
   // (we can't use the SHA of the SO key since the SHA of the key is stored
   // in the token data file).
   //
   memcpy( des3_key,                 so_pin_md5, MD5_HASH_SIZE );
   memcpy( des3_key + MD5_HASH_SIZE, so_pin_md5, DES_KEY_SIZE  );

#if 0
#ifndef CLEARTEXT
   rc = ckm_des3_cbc_decrypt( cipher, cipher_len, clear, &clear_len, "12345678", des3_key );
#else
   bcopy(cipher,clear,cipher_len);
   rc = CKR_OK;
#endif
#endif
   /* do things cleartext for now */
   bcopy(cipher,clear,cipher_len);
   rc = CKR_OK;

   if (rc != CKR_OK){
      st_err_log(106, __FILE__, __LINE__);
      LogError("WHAT THE FUCK");
      goto done;
   }
   memcpy( (CK_BYTE *)&mk, clear, sizeof(mk) );

   //
   // technically should strip PKCS padding here but since I already know what
   // the length should be, I don't bother.
   //


   // compare the hashes
   //
   compute_sha( mk.key, 3 * DES_KEY_SIZE, hash_sha );

   if (memcmp(hash_sha, mk.sha_hash, SHA1_HASH_SIZE) != 0) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   memcpy( master_key, mk.key, 3*DES_KEY_SIZE );
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
   CK_BYTE            * ptr = NULL;
   CK_BYTE              hash_sha[SHA1_HASH_SIZE];
   CK_BYTE              cipher[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE              clear[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
   CK_BYTE              des3_key[3 * DES_KEY_SIZE];
   CK_MECHANISM         mech;
   DIGEST_CONTEXT       digest_ctx;
   MASTER_KEY_FILE_T    mk;
   CK_ULONG             cipher_len, clear_len, hash_len;
   CK_RV                rc;
   CK_BYTE              fname[2048];

   memset( master_key, 0x0, 3*DES_KEY_SIZE );

   // this file gets created on C_InitToken so we can assume that it always exists
   //
   sprintf((char *)fname,"%s/MK_USER",pk_dir);
   //fp = fopen( "/tmp/MK_USER", "r" );
   fp = fopen( (char *)fname, "r" );
   if (!fp) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   set_perm(fileno(fp));
   clear_len = cipher_len = (sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE - 1) & ~(DES_BLOCK_SIZE - 1);

   rc = fread( cipher, cipher_len, 1, fp );
   if (rc != 1) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   // decrypt the master key data using the MD5 of the SO key
   // (we can't use the SHA of the SO key since the SHA of the key is stored
   // in the token data file).
   //
   memcpy( des3_key,                 user_pin_md5, MD5_HASH_SIZE );
   memcpy( des3_key + MD5_HASH_SIZE, user_pin_md5, DES_KEY_SIZE  );

#if 0
#ifndef CLEARTEXT
   rc = ckm_des3_cbc_decrypt( cipher, cipher_len, clear, &clear_len, "12345678", des3_key );
#else
   bcopy(cipher,clear,cipher_len);
   rc = CKR_OK;
#endif
#endif
   /* do things cleartext for now */
   bcopy(cipher,clear,cipher_len);
   rc = CKR_OK;

   if (rc != CKR_OK){
      st_err_log(106, __FILE__, __LINE__);
      goto done;
   }
   memcpy( (CK_BYTE *)&mk, clear, sizeof(mk) );

   //
   // technically should strip PKCS padding here but since I already know what
   // the length should be, I don't bother.
   //


   // compare the hashes
   //
   compute_sha( mk.key, 3 * DES_KEY_SIZE, hash_sha );

   if (memcmp(hash_sha, mk.sha_hash, SHA1_HASH_SIZE) != 0) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   memcpy( master_key, mk.key, 3*DES_KEY_SIZE );
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
   CK_MECHANISM       mech;
   DIGEST_CONTEXT     digest_ctx;
   MASTER_KEY_FILE_T  mk;
   CK_ULONG           hash_len, cleartxt_len, ciphertxt_len, padded_len;
   CK_RV              rc;
   CK_BYTE            fname[2048];


   memcpy( mk.key, master_key, 3 * DES_KEY_SIZE);

   compute_sha( master_key, 3 * DES_KEY_SIZE, mk.sha_hash );

   // encrypt the key data
   //
   memcpy( des3_key,                 so_pin_md5, MD5_HASH_SIZE );
   memcpy( des3_key + MD5_HASH_SIZE, so_pin_md5, DES_KEY_SIZE  );

   ciphertxt_len = sizeof(ciphertxt);
   cleartxt_len  = sizeof(mk);
   memcpy( cleartxt, &mk, cleartxt_len );

   padded_len = DES_BLOCK_SIZE * (cleartxt_len / DES_BLOCK_SIZE + 1);
   add_pkcs_padding( cleartxt + cleartxt_len, DES_BLOCK_SIZE, cleartxt_len, padded_len );

#if 0
#ifndef CLEARTEXT
   rc = ckm_des3_cbc_encrypt( cleartxt, padded_len, ciphertxt, &ciphertxt_len, "12345678", des3_key );
#else
            bcopy(cleartxt,ciphertxt,padded_len);
	             rc = CKR_OK;
#endif
#endif
   /* do things cleartext for now */
   bcopy(cleartxt,ciphertxt,padded_len);
   rc = CKR_OK;

   if (rc != CKR_OK){
      st_err_log(105, __FILE__, __LINE__);
      goto done;
   }

   // write the file
   //
   // probably ought to ensure the permissions are correct
   //
   sprintf((char *)fname,"%s/MK_SO",pk_dir);
   //fp = fopen( "/tmp/MK_SO", "w" );
   fp = fopen( (char *)fname, "w" );
   if (!fp) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }
   set_perm(fileno(fp));

   rc = fwrite( ciphertxt, ciphertxt_len, 1, fp );
   if (rc != 1) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
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
   CK_MECHANISM       mech;
   DIGEST_CONTEXT     digest_ctx;
   MASTER_KEY_FILE_T  mk;
   CK_ULONG           hash_len, cleartxt_len, ciphertxt_len, padded_len;
   CK_RV              rc;
   CK_BYTE            fname[2048];


   memcpy( mk.key, master_key, 3 * DES_KEY_SIZE);

   compute_sha( master_key, 3 * DES_KEY_SIZE, mk.sha_hash );


   // encrypt the key data
   //
   memcpy( des3_key,                 user_pin_md5, MD5_HASH_SIZE );
   memcpy( des3_key + MD5_HASH_SIZE, user_pin_md5, DES_KEY_SIZE  );

   ciphertxt_len = sizeof(ciphertxt);
   cleartxt_len  = sizeof(mk);
   memcpy( cleartxt, &mk, cleartxt_len );

   padded_len = DES_BLOCK_SIZE * (cleartxt_len / DES_BLOCK_SIZE + 1);
   add_pkcs_padding( cleartxt + cleartxt_len, DES_BLOCK_SIZE, cleartxt_len, padded_len );

#if 0
#ifndef CLEARTEXT
   rc = ckm_des3_cbc_encrypt( cleartxt, padded_len, ciphertxt, &ciphertxt_len, "12345678", des3_key );
#else
   bcopy(cleartxt,ciphertxt,padded_len);
   rc = CKR_OK;
#endif
#endif
   /* do the cleartext thing for now */
   bcopy(cleartxt,ciphertxt,padded_len);
   rc = CKR_OK;

   if (rc != CKR_OK){
      st_err_log(105, __FILE__, __LINE__);
      goto done;
   }


   // write the file
   //
   // probably ought to ensure the permissions are correct
   //
   sprintf((char *)fname,"%s/MK_USER", pk_dir);
   //fp = fopen( "/tmp/MK_USER", "w" );
   fp = fopen( (char *)fname, "w" );
   if (!fp) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   set_perm(fileno(fp));
   rc = fwrite( ciphertxt, ciphertxt_len, 1, fp );
   if (rc != 1) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
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
   CK_BYTE    fname[2048];
   CK_BBOOL   priv;
   CK_ULONG_32   size;
   CK_ULONG   size_64;
   CK_RV      rc;

   memset( (char *)fname, 0x0, sizeof(fname) );

  // strcpy(fname, "/tmp/TOK_OBJ/" );
   if (TPMTOK_USERNAME == NULL) {
	   sprintf((char *)fname,"%s/%s/",pk_dir, PK_LITE_OBJ_DIR);
	   strncat((char *)fname,(char *)  obj->name, 8 );
   } else {
	   sprintf((char *)fname,"%s/%s/%s/",pk_dir, PK_LITE_OBJ_DIR, TPMTOK_USERNAME);
	   strncat((char *)fname,(char *)  obj->name, 8 );
   }

   fp = fopen( (char *)fname, "r" );
   if (!fp) {
      st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
      rc = CKR_FUNCTION_FAILED;
      goto done;
   }

   set_perm(fileno(fp));

   fread( &size, sizeof(CK_ULONG_32), 1, fp );
   fread( &priv, sizeof(CK_BBOOL), 1, fp );

   size = size - sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);  // SAB

   buf = (CK_BYTE *)malloc(size);
   if (!buf) {
      st_err_log(0, __FILE__, __LINE__);
      rc = CKR_HOST_MEMORY;
      goto done;
   }

   fread( buf, size, 1, fp );

   size_64 = size;

   if (priv){
      rc = restore_private_token_object( buf, size_64, obj );
      if (rc != CKR_OK)
         st_err_log(107, __FILE__, __LINE__);
   }
   else{
      rc = object_mgr_restore_obj( buf, obj );
      if (rc != CKR_OK)
         st_err_log(108, __FILE__, __LINE__);
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
	CK_BYTE    objidx[2048], idxtmp[2048],fname[2048];

	// FIXME:  on UNIX, we need to make sure these guys aren't symlinks
	//         before we blindly write to these files...
	//

	// remove the object from the index file
	//

	if (TPMTOK_USERNAME == NULL) {
		sprintf((char *)objidx,"%s/%s/%s",pk_dir, PK_LITE_OBJ_DIR,PK_LITE_OBJ_IDX);
		sprintf((char *)idxtmp,"%s/%s/%s",pk_dir, PK_LITE_OBJ_DIR, "IDX.TMP");
		//fp1 = fopen("/tmp/TOK_OBJ/OBJ.IDX", "r");
		//fp2 = fopen("/tmp/TOK_OBJ/IDX.TMP", "w");
	} else {
		sprintf((char *)objidx,"%s/%s/%s/%s",pk_dir, PK_LITE_OBJ_DIR,TPMTOK_USERNAME,PK_LITE_OBJ_IDX);
		sprintf((char *)idxtmp,"%s/%s/%s/%s",pk_dir, PK_LITE_OBJ_DIR,TPMTOK_USERNAME,"IDX.TMP");
		//fp1 = fopen("/tmp/TOK_OBJ/username/OBJ.IDX", "r");
		//fp2 = fopen("/tmp/TOK_OBJ/username/IDX.TMP", "w");
	}
	fp1 = fopen((char *)objidx, "r");
	fp2 = fopen((char *)idxtmp, "w");
	if (!fp1 || !fp2) {
		if (fp1) fclose(fp1);
		if (fp2) fclose(fp2);
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	set_perm(fileno(fp2));

	while (!feof(fp1)) {
		fgets((char *)line, 50, fp1 );
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
	//fp2 = fopen("/tmp/TOK_OBJ/OBJ.IDX", "w");
	//fp1 = fopen("/tmp/TOK_OBJ/IDX.TMP", "r");
	fp2 = fopen((char *)objidx, "w");
	fp1 = fopen((char *)idxtmp, "r");
	if (!fp1 || !fp2) {
		if (fp1) fclose(fp1);
		if (fp2) fclose(fp2);
		st_err_log(4, __FILE__, __LINE__, __FUNCTION__);
		return CKR_FUNCTION_FAILED;
	}

	set_perm(fileno(fp2));

	while (!feof(fp1)) {
		fgets((char *)line, 50, fp1 );
		if (!feof(fp1))
			fprintf( fp2, "%s",(char *) line );
	}

	fclose(fp1);
	fclose(fp2);

	sprintf((char *)fname,"%s/%s/%s",pk_dir, PK_LITE_OBJ_DIR,(char *)obj->name);
	unlink((char *)fname);
	return CKR_OK;

}

