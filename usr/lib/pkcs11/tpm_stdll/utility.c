
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


#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <pthread.h>
#include <sys/stat.h>
#include <sys/ipc.h>
#include <errno.h>
#include <pwd.h>


#include "pkcs11/pkcs11types.h"
#include <pkcs11/stdll.h>
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "pkcs32.h"

#include <sys/file.h>



// Function:  dlist_add_as_first()
//
// Adds the specified node to the start of the list
//
// Returns:  pointer to the start of the list
//
DL_NODE *
dlist_add_as_first( DL_NODE *list, void *data )
{
	DL_NODE *node = NULL;

	if (!data)
		return list;

	node = (DL_NODE *)malloc(sizeof(DL_NODE));
	if (!node)
		return NULL;

	node->data = data;
	node->prev = NULL;
	node->next = list;
	if ( list)
		list->prev = node;

	return node;
}


// Function:  dlist_add_as_last()
//
// Adds the specified node to the end of the list
//
// Returns:  pointer to the start of the list
//
DL_NODE *
dlist_add_as_last( DL_NODE *list, void *data )
{
	DL_NODE *node = NULL;

	if (!data)
		return list;

	node = (DL_NODE *)malloc(sizeof(DL_NODE));
	if (!node)
		return NULL;

	node->data = data;
	node->next = NULL;

	if (!list)
	{
		node->prev = NULL;
		return node;
	}
	else
	{
		DL_NODE *temp = dlist_get_last( list );
		temp->next = node;
		node->prev = temp;

		return list;
	}
}


// Function:  dlist_find()
//
DL_NODE *
dlist_find( DL_NODE *list, void *data )
{
	DL_NODE *node = list;

	while (node && node->data != data)
		node = node->next;

	return node;
}


// Function:  dlist_get_first()
//
// Returns the last node in the list or NULL if list is empty
//
DL_NODE *
dlist_get_first( DL_NODE *list )
{
	DL_NODE *temp = list;

	if (!list)
		return NULL;

	while (temp->prev != NULL)
		temp = temp->prev;

	return temp;
}


// Function:  dlist_get_last()
//
// Returns the last node in the list or NULL if list is empty
//
DL_NODE *
dlist_get_last( DL_NODE *list )
{
	DL_NODE *temp = list;

	if (!list)
		return NULL;

	while (temp->next != NULL)
		temp = temp->next;

	return temp;
}


//
//
CK_ULONG
dlist_length( DL_NODE *list )
{
	DL_NODE  *temp = list;
	CK_ULONG  len  = 0;

	while (temp)
	{
		len++;
		temp = temp->next;
	}

	return len;
}


//
//
DL_NODE *
dlist_next( DL_NODE *node )
{
	if (!node)
		return NULL;

	return node->next;
}


//
//
DL_NODE *
dlist_prev( DL_NODE *node )
{
	if (!node)
		return NULL;

	return node->prev;
}


//
//
void
dlist_purge( DL_NODE *list )
{
	DL_NODE *node;

	if (!list)
		return;

	do
	{
		node = list->next;
		free( list );
		list = node;
	} while ( list );
}


// Function:  dlist_remove_node()
//
// Attempts to remove the specified node from the list.  The caller is
// responsible for freeing the data associated with the node prior to
// calling this routine
//
DL_NODE *
dlist_remove_node( DL_NODE *list, DL_NODE *node )
{
	DL_NODE *temp  = list;

	if (!list || !node)
		return NULL;

	// special case:  removing head of the list
	//
	if (list == node)
	{
		temp = list->next;
		if (temp)
			temp->prev = NULL;

		free( list );
		return temp;
	}

	// we have no guarantee that the node is in the list
	// so search through the list to find it
	//
	while ((temp != NULL) && (temp->next != node))
		temp = temp->next;

	if (temp != NULL)
	{
		DL_NODE *next = node->next;

		temp->next = next;
		if (next)
			next->prev = temp;

		free( node );
	}

	return list;
}


// NOTE about Mutexes and cross process locking....
//
// The code uses 2 types of locks... internal locks to prevent threads within the same
// process space from stomping on each other  (pthread_mutex's suffice for 
// this).... and Cross Process Locks....
// On AIX we use it's variation of Posix semaphores for this.... Idealy on other
// platforms either POSIXSEMaphores or PTHREADXPL (pthreads xprocess lock) would
// be used.  On Linux unfortunatly  neither of these are available so we need to
// use the old standby of  SYSV semaphores (YECH.... GAG....)....  The only
// pieces which have been tested are the AIX and SYSV portions although 
// we expect that the others work correctly.
//
// we use alot more mutexes in the redesign than we did in the original
// design.  so instead of just the single global "pkcs_mutex" we have to
// deal with a number of mutexes.  so we'll make the mutex routines a
// bit more generic.
//

CK_RV
_CreateMutex( MUTEX *mutex )
{
	CK_RV  rc;

	// on AIX we make this a no-op since we assume that
	// the mutex was created in the initialization
	pthread_mutex_init( mutex, NULL );
	return CKR_OK;
}

CK_RV
_DestroyMutex( MUTEX *mutex )
{
	CK_RV  rc;

	// no-op in AIX
	pthread_mutex_destroy((pthread_mutex_t *)mutex);
	return CKR_OK;

}

CK_RV
_LockMutex( MUTEX *mutex )
{
	pthread_mutex_lock( mutex);
	return CKR_OK;

}

CK_RV
_UnlockMutex( MUTEX *mutex )
{
	pthread_mutex_unlock(mutex);
	return CKR_OK;

}

int spinxplfd=-1;
int spin_created=0;

extern void set_perm(int);

CK_RV
CreateXProcLock(void)
{

	// open the file that we will do the locking on...
	spinxplfd = open("/tmp/.pkcs11spinloc",O_CREAT|O_APPEND|O_RDWR,
			S_IRWXU|S_IRWXG|S_IRWXO);
	if (spinxplfd) {

		set_perm(spinxplfd);
		fchmod(spinxplfd,S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH | S_IWOTH);
		spin_created=1;
	} else {
		perror("XPROC CREATE file :");
	}
	return CKR_OK;
}

CK_RV
DestroyXProcLock(void)
{
	return CKR_OK;
}

CK_RV
XProcLock(void)
{
	if (!spin_created) {
		spinxplfd = open("/tmp/.pkcs11spinloc",O_CREAT|O_APPEND|O_RDWR,
				S_IRWXU|S_IRWXG|S_IRWXO);
		fchmod(spinxplfd,S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH | S_IWOTH);
		spin_created=1;
	}
	if (spinxplfd){
		flock(spinxplfd,LOCK_EX);
	}
	return CKR_OK;
}

CK_RV
XProcUnLock(void)
{
	if (!spin_created) {
		spinxplfd = open("/tmp/.pkcs11spinloc",O_CREAT|O_APPEND|O_RDWR,
				S_IRWXU|S_IRWXG|S_IRWXO);
		fchmod(spinxplfd,S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP|S_IROTH | S_IWOTH);
		spin_created=1;
	}
	if (spinxplfd) {
		flock(spinxplfd,LOCK_UN);
	}
	return CKR_OK;
}


//
//

extern CK_CHAR manuf[];
extern CK_CHAR model[];
extern CK_CHAR descr[];
extern CK_CHAR label[];


//
//
void
init_slotInfo( void )
{
	memset( &slot_info.slotDescription, ' ', sizeof(slot_info.slotDescription) );
	memset( &slot_info.manufacturerID,  ' ', sizeof(slot_info.manufacturerID)  );

	memcpy( &slot_info.slotDescription, descr, strlen((char *)descr) );
	memcpy( &slot_info.manufacturerID,  manuf, strlen((char *)manuf) );

	slot_info.hardwareVersion.major = 1;
	slot_info.hardwareVersion.minor = 0;
	slot_info.firmwareVersion.major = 1;
	slot_info.firmwareVersion.minor = 0;
	slot_info.flags = CKF_TOKEN_PRESENT | CKF_HW_SLOT;
}


//
//
void
init_tokenInfo( void )
{
	CK_TOKEN_INFO_32    *token_info = NULL;
	CK_ULONG          len;

	token_info = &nv_token_data->token_info;

	memset( token_info->manufacturerID, ' ', sizeof(token_info->manufacturerID) );
	memset( token_info->model,          ' ', sizeof(token_info->model) );
	memset( token_info->serialNumber,   ' ', sizeof(token_info->serialNumber) );

	memcpy( token_info->label,          nv_token_data->token_info.label, 32 );

	memcpy( token_info->manufacturerID, manuf, strlen((char *)manuf) );
	memcpy( token_info->model,          model, strlen((char *)model) );

	// use the 41-xxxxx serial number from the coprocessor
	//
	memcpy( token_info->serialNumber,  "123" , 3 );

	// I don't see any API support for changing the clock so
	// we will use the system clock for the token's clock.
	//

	token_info->flags = CKF_RNG |
		CKF_LOGIN_REQUIRED |
		CKF_CLOCK_ON_TOKEN |
		CKF_SO_PIN_TO_BE_CHANGED; // XXX New in v2.11 - KEY

	if (memcmp(nv_token_data->user_pin_sha, "00000000000000000000", SHA1_HASH_SIZE) != 0)
		token_info->flags |= CKF_USER_PIN_INITIALIZED;
	else
		token_info->flags |= CKF_USER_PIN_TO_BE_CHANGED; // XXX New in v2.11 - KEY

	// For the release, we made these 
	// values as CK_UNAVAILABLE_INFORMATION
	//
	token_info->ulMaxSessionCount    = (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION;
	token_info->ulSessionCount       = (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION;
	token_info->ulMaxRwSessionCount  = (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION;
	token_info->ulRwSessionCount     = (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION;
	token_info->ulMaxPinLen          = MAX_PIN_LEN;
	token_info->ulMinPinLen          = MIN_PIN_LEN;
	token_info->ulTotalPublicMemory  = (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION;
	token_info->ulFreePublicMemory   = (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION;
	token_info->ulTotalPrivateMemory = (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION;
	token_info->ulFreePrivateMemory  = (CK_ULONG_32)CK_UNAVAILABLE_INFORMATION;

	token_info->hardwareVersion.major = 1;
	token_info->hardwareVersion.minor = 0;
	token_info->firmwareVersion.major = 1;
	token_info->firmwareVersion.minor = 0;

	memset( token_info->utcTime, ' ', sizeof(token_info->utcTime) );
}


//
//
CK_RV
init_token_data( void )
{
	CK_RV rc;

	memset( (char *)nv_token_data, 0, sizeof(nv_token_data) );

	// the normal USER pin is not set when the token is initialized
	//
	memcpy( nv_token_data->user_pin_sha, "00000000000000000000", SHA1_HASH_SIZE );
	memcpy( nv_token_data->so_pin_sha,   default_so_pin_sha,     SHA1_HASH_SIZE );

	memset( user_pin_md5, 0x0,                MD5_HASH_SIZE );
	memcpy( so_pin_md5,   default_so_pin_md5, MD5_HASH_SIZE );

	memcpy( nv_token_data->next_token_object_name, "00000000", 8 );

	// generate the master key used for signing the Operation State information
	//                          `
	memset( nv_token_data->token_info.label, ' ', sizeof(nv_token_data->token_info.label) );
	memcpy( nv_token_data->token_info.label, label, strlen((char *)label) );

	nv_token_data->tweak_vector.allow_weak_des   = TRUE;
	nv_token_data->tweak_vector.check_des_parity = FALSE;
	nv_token_data->tweak_vector.allow_key_mods   = TRUE;
	nv_token_data->tweak_vector.netscape_mods    = TRUE;

	init_tokenInfo();

	//
	// FIXME: erase the token object index file (and all token objects)
	//
#if 0
	rc  = rng_generate( master_key, 3 * DES_KEY_SIZE );
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_FUNCTION_FAILED); 
		return CKR_FUNCTION_FAILED;
	}
	rc = save_masterkey_so();
	if (rc != CKR_OK){
		OCK_LOG_ERR(ERR_FUNCTION_FAILED); 
		return CKR_FUNCTION_FAILED;
	}
#endif
	rc = save_token_data();
	if (rc != CKR_OK)
		OCK_LOG_ERR(ERR_FUNCTION_FAILED); 
	return rc;
}



// Function:  compute_next_token_obj_name()
//
// Given a token object name (8 bytes in the range [0-9A-Z]) increment by one
// adjusting as necessary
//
// This gives us a namespace of 36^8 = 2,821,109,907,456 objects before wrapping around
//
CK_RV
compute_next_token_obj_name( CK_BYTE *current, CK_BYTE *next )
{
	int val[8];
	int i;

	if (!current || !next){
		OCK_LOG_ERR(ERR_FUNCTION_FAILED); 
		return CKR_FUNCTION_FAILED;
	}
	// Convert to integral base 36
	//
	for (i = 0; i < 8; i++)
	{
		if (current[i] >= '0' && current[i] <= '9')
			val[i] = current[i] - '0';

		if (current[i] >= 'A' && current[i] <= 'Z')
			val[i] = current[i] - 'A' + 10;
	}

	val[0]++;

	i=0;

	while (val[i] > 35)
	{
		val[i] = 0;

		if (i+1 < 8) {
			val[i+1]++;
			i++;
		}
		else {
			val[0]++;
			i = 0;   // start pass 2
		}
	}

	// now, convert back to [0-9A-Z]
	//
	for (i = 0; i < 8; i++)
	{
		if (val[i] < 10)
			next[i] = '0' + val[i];
		else
			next[i] = 'A' + val[i] - 10;
	}

	return CKR_OK;
}


//
//
CK_RV
build_attribute( CK_ATTRIBUTE_TYPE  type,
		CK_BYTE           *data,
		CK_ULONG           data_len,
		CK_ATTRIBUTE     **attrib )
{
	CK_ATTRIBUTE *attr = NULL;

	attr = (CK_ATTRIBUTE *)malloc( sizeof(CK_ATTRIBUTE) + data_len );
	if (!attr){
		OCK_LOG_ERR(ERR_DEVICE_MEMORY);
		return CKR_DEVICE_MEMORY;
	}
	attr->type  = type;
	attr->ulValueLen = data_len;

	if (data_len > 0) {
		attr->pValue = (CK_BYTE *)attr + sizeof(CK_ATTRIBUTE);
		memcpy( attr->pValue, data, data_len );
	}
	else
		attr->pValue = NULL;

	*attrib = attr;

	return CKR_OK;
}


//
//
CK_RV
add_pkcs_padding( CK_BYTE  * ptr,
		CK_ULONG   block_size,
		CK_ULONG   data_len,
		CK_ULONG   total_len )
{
	CK_ULONG i, pad_len;
	CK_BYTE  pad_value;

	pad_len = block_size - (data_len % block_size);
	pad_value = (CK_BYTE)pad_len;

	if (data_len + pad_len > total_len){
		OCK_LOG_ERR(ERR_FUNCTION_FAILED); 
		return CKR_FUNCTION_FAILED;
	}
	for (i = 0; i < pad_len; i++)
		ptr[i] = pad_value;

	return CKR_OK;
}


//
//
CK_RV
strip_pkcs_padding( CK_BYTE   * ptr,
		CK_ULONG    total_len,
		CK_ULONG  * data_len )
{
	CK_BYTE  pad_value;

	pad_value = ptr[total_len - 1];
        if (pad_value > total_len)
                return CKR_ENCRYPTED_DATA_INVALID;

	// thus, we have 'pad_value' bytes of 'pad_value' appended to the end
	//
	*data_len = total_len - pad_value;

	return CKR_OK;
}


//
//
CK_BYTE
parity_adjust( CK_BYTE b )
{
	if (parity_is_odd(b) == FALSE)
		b = (b & 0xFE) | ((~b) & 0x1);

	return b;
}


//
//
CK_RV
parity_is_odd( CK_BYTE b )
{
	b = ((b >> 4) ^ b) & 0x0f;
	b = ((b >> 2) ^ b) & 0x03;
	b = ((b >> 1) ^ b) & 0x01;

	if (b == 1)
		return TRUE;
	else
		return FALSE;
}


CK_RV
attach_shm()
{
	key_t    key;
	int      shm_id;
	struct stat statbuf;
	CK_BBOOL created = FALSE;
	void *temp = NULL;

#if !(NOSHM) && !(MMAP)
	// Change TOK_PATH2 to be the directory 
	// of the data store specified.  This way we
	// have a unique key shared memory for each 
	// token object database
	if (stat(pk_dir, &statbuf) < 0) {
		OCK_LOG_ERR(ERR_FUNCTION_FAILED); 
		OCK_LOG_DEBUG("pk_dir = \"%s\"\n", pk_dir);
		return CKR_FUNCTION_FAILED;
	}

	key = ftok( pk_dir, 'c' );

	shm_id = shmget( key, sizeof(LW_SHM_TYPE),
			S_IRUSR | S_IWUSR |
			S_IRGRP | S_IWGRP |
			S_IROTH | S_IWOTH |
			IPC_CREAT | IPC_EXCL);

	if (shm_id < 0) {

#if 0
		if ((errno != EACCES) && (errno != EEXIST)) {
			fflush(stdout); fflush(stderr);
			OCK_LOG_ERR(ERR_FUNCTION_FAILED);
			return CKR_FUNCTION_FAILED;
		}
#endif
		// SAB XXX  it appears that in some cases linux does not set
		// the errno properly on a shmget failure... so if the create
		// failed we'll just try and attach....  If the basic attach
		// fails, then we can error out...

		// SHM segment already exists...
		//
		shm_id = shmget( key, sizeof(LW_SHM_TYPE),
				S_IRUSR | S_IWUSR |
				S_IRGRP | S_IWGRP |
				S_IROTH | S_IWOTH  );

		//if ((errno != EACCES) && (errno != EEXIST)) {
		if (shm_id < 0) {
			fflush(stdout); fflush(stderr);
			OCK_LOG_ERR(ERR_FUNCTION_FAILED);
			return CKR_FUNCTION_FAILED;
		}
	} else {
		created = TRUE;
	}

	global_shm = (void *)shmat( shm_id, NULL, 0 );
	if (!global_shm){
		OCK_LOG_ERR(ERR_FUNCTION_FAILED);
		return CKR_FUNCTION_FAILED;
	}
	if (created == TRUE) {
		// SYSV sem's are a global that is handled in the
		// Initialize routine...  all others are stored in the
		// shared memory segment so we have to do
		// this here after the segment is created
		// to prevent a core dump
		CreateXProcLock();
		XProcLock();
		global_shm->num_publ_tok_obj = 0;
		global_shm->num_priv_tok_obj = 0;
		memset( &global_shm->publ_tok_objs, 0x0, 2048 * sizeof(TOK_OBJ_ENTRY) );
		memset( &global_shm->priv_tok_objs, 0x0, 2048 * sizeof(TOK_OBJ_ENTRY) );
		XProcUnLock();
	}
#elif MMAP
	{
#define FILENAME   ".stmapfile"
		//#define MODE (S_IRUSR|S_IWUSR|S_IRGRP|S_IWGRP)
		//#define MODE (S_IRUSR|S_IWUSR)

//#warning "EXPERIMENTAL"
		char		*fname = NULL, *dirname = NULL;
		char		*b2 = NULL;
		int		fd = -1, i;
		struct passwd	*pw = NULL;
		mode_t		mode = (S_IRUSR | S_IWUSR | S_IXUSR);
		CK_RV		rc;

		/* manpage decrees that errno must be set to 0 if we want to check it on
		 * error.. */
		errno = 0;
		pw = getpwuid(getuid());
		if (pw == NULL) {
			OCK_LOG_DEBUG("getpwuid failed: %s\n", strerror(errno));
			return CKR_FUNCTION_FAILED;
		}

		// STAT the directory to see if it exists... If not, then create it
		dirname = malloc(strlen(pk_dir) + strlen(pw->pw_name) + strlen(PK_LITE_OBJ_DIR) + 2);
		if (dirname) {
			sprintf(dirname, "%s/%s", pk_dir, pw->pw_name);
		} else {
			OCK_LOG_ERR(ERR_HOST_MEMORY);
			return CKR_HOST_MEMORY;
		}

		// if the user specific directory doesn't exist, create it and userdir/TOK_OBJ
		if (stat(dirname, &statbuf) < 0) {
			if (mkdir(dirname, mode) == -1) {
				OCK_LOG_DEBUG("%s: mkdir(%s): %s\n", __FUNCTION__, dirname,
						strerror(errno));
				rc = CKR_FUNCTION_FAILED;
				goto err_out;
			}
			fd = open(dirname, O_RDONLY);
			if (fd < 0) {
				OCK_LOG_DEBUG("%s: open(%s): %s\n", __FUNCTION__, dirname,
						strerror(errno));
				rc = CKR_FUNCTION_FAILED;
				goto err_out;
			}
			if (fchmod(fd, mode) == -1) {
				OCK_LOG_DEBUG("%s: fchmod(%s): %s\n", __FUNCTION__, dirname,
						strerror(errno));
				close(fd);
				rc = CKR_FUNCTION_FAILED;
				goto err_out;
			}
			close(fd);

			// now create userdir/TOK_OBJ
			strncat(dirname, "/", 1);
			strncat(dirname, PK_LITE_OBJ_DIR, strlen(PK_LITE_OBJ_DIR));
			if (mkdir(dirname, mode) == -1) {
				OCK_LOG_DEBUG("%s: mkdir \"%s\": %s\n", __FUNCTION__, dirname,
						strerror(errno));
				rc = CKR_FUNCTION_FAILED;
				goto err_out;
			}
			fd = open(dirname, O_RDONLY);
			if (fd < 0) {
				OCK_LOG_DEBUG("%s: open(%s): %s\n", __FUNCTION__, dirname,
						strerror(errno));
				rc = CKR_FUNCTION_FAILED;
				goto err_out;
			}
			if (fchmod(fd, mode) == -1) {
				OCK_LOG_DEBUG("%s: fchmod(%s): %s\n", __FUNCTION__, dirname,
						strerror(errno));
				close(fd);
				rc = CKR_FUNCTION_FAILED;
				goto err_out;
			}
			close(fd);
		}

		// STAT the file to see if it exists... If not, then create it
		fname = malloc(strlen(dirname)+strlen(FILENAME)+100);
		if (fname ) {
			sprintf(fname, "%s/%s/%s", pk_dir, pw->pw_name, FILENAME);
		} else {
			OCK_LOG_ERR(ERR_HOST_MEMORY);
			return CKR_HOST_MEMORY;
		}

		if (stat(fname, &statbuf) < 0) {
			// File does not exist Create it
			fd = open(fname,O_RDWR|O_CREAT,mode);
			if (fd < 0 ){
				OCK_LOG_DEBUG("open of %s failed: %s\n", fname, strerror(errno));
				return CKR_FUNCTION_FAILED;  //Failed
			}
			i = sizeof(LW_SHM_TYPE);
			b2 = malloc(i);
			memset(b2,'\0',i);
			write(fd,b2,i);
			free(b2);
			created=TRUE;
		} else {
			fd = open(fname,O_RDWR,mode);
			if (fd < 0 ){
				OCK_LOG_DEBUG("open of %s failed: %s\n", fname, strerror(errno));
				return CKR_FUNCTION_FAILED;  //Failed
			}
		}

		global_shm = (LW_SHM_TYPE *)mmap(NULL,sizeof(LW_SHM_TYPE),PROT_READ|PROT_WRITE,MAP_SHARED,fd,0);
		if (created == TRUE) {
			XProcLock();
			global_shm->num_publ_tok_obj = 0;
			global_shm->num_priv_tok_obj = 0;
			memset( &global_shm->publ_tok_objs, 0x0, 2048 * sizeof(TOK_OBJ_ENTRY) );
			memset( &global_shm->priv_tok_objs, 0x0, 2048 * sizeof(TOK_OBJ_ENTRY) );
			XProcUnLock();
		}

		rc = CKR_OK;

err_out:
		free(dirname);
		free(fname);
		close(fd);
		return rc;

	}
#else
	global_shm = (void *)malloc(sizeof(LW_SHM_TYPE));

#endif

	return CKR_OK;
}


CK_RV
detach_shm()
{
#if !(NOSHM) && !(MMAP)
   shmdt( global_shm );
#elif MMAP
   // Detach from memory mapped file
   munmap((void *)global_shm,sizeof(LW_SHM_TYPE));
#else
   free(global_shm);
#endif
   return CKR_OK;
}


CK_RV
compute_sha( CK_BYTE  * data,
             CK_ULONG   len,
             CK_BYTE  * hash )
{
   // XXX KEY
   DIGEST_CONTEXT	ctx;
   CK_ULONG     	hash_len = SHA1_HASH_SIZE;
   CK_RV		rv;

   memset( &ctx, 0x0, sizeof(ctx) );

   ckm_sha1_init( &ctx );
   if( ctx.context == NULL )
	   return CKR_HOST_MEMORY;
   
   if( (rv = ckm_sha1_update( &ctx, data,  len )) != CKR_OK)
	   return rv;
   
   return ckm_sha1_final( &ctx, hash, &hash_len );
}


CK_RV
compute_md5( CK_BYTE  * data,
             CK_ULONG   len,
             CK_BYTE  * hash )
{
   MD5_CONTEXT ctx;

   memset( &ctx, 0x0, sizeof(ctx) );

   ckm_md5_init( &ctx );
   ckm_md5_update( &ctx, data,  len );
   ckm_md5_final(  &ctx, hash, MD5_HASH_SIZE );

   return CKR_OK;
}


