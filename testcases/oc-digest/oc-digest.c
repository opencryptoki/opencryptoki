
/*
 * openCryptoki sample app
 *
 * oc-digest.c - Run a digest algorthm on a given file
 *
 * usage: oc-digest [-h] [-t <digest>] [-slot <slot>] <filename>
 * 
 * Dec 11, 2002
 * Kent Yoder <yoder1@us.ibm.com>
 *
 */

#include <stdio.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "pkcs11types.h"

void oc_err_msg(char *, CK_RV);
int do_GetFunctionList(void);
int clean_up(void);

struct digest_type {
	char *id;	/* A unique string to be provided on the cmd line */
	CK_ULONG length;	/* The size of the resulting hash */
	CK_MECHANISM mech;	/* openCryptoki's mechanism structure */
};

CK_SLOT_ID		slot_id;
CK_FUNCTION_LIST	*funcs;
CK_SESSION_HANDLE	session_handle;
CK_MECHANISM_TYPE_PTR	mech_list;
CK_MECHANISM_INFO	mech_info;
CK_ULONG		mech_num;
CK_BYTE_PTR		msg_digest = NULL;

void *dl_handle;
char *file = NULL;		/* the file to digest */
int fd = -1;
struct stat file_stat;
char *buf = NULL;

#define READ_SIZE	(46)
#define MIN(a,b)	((a) < (b) ? (a) : (b))
#define MB		(0x100000)
#define NUM_DIGESTS	4
struct digest_type digests[NUM_DIGESTS] = {
	{
		.id = "md5",
		.length = 16,
		.mech = { 	
			.mechanism = CKM_MD5,
			.pParameter = NULL,
			.ulParameterLen = 0
		}
	},
	{
		.id = "fasthash",
		.length = 40,
		.mech = {
			.mechanism = CKM_FASTHASH,
			.pParameter = NULL,
			.ulParameterLen = 0
		}
	},
	{
		.id = "sha1",
		.length = 20,
		.mech = {
			.mechanism = CKM_SHA_1,
			.pParameter = NULL,
			.ulParameterLen = 0
		}
	},
	{
		.id = "sha256",
		.length = 32,
		.mech = {
			.mechanism = CKM_SHA256,
			.pParameter = NULL,
			.ulParameterLen = 0
		}
	}
};

/* The order here matters; must be the same as above */
enum digest_types {
	uninitialized = -1,
	md5,
	fasthash,
	sha1,
	sha256
};

enum digest_types hash = uninitialized;

void usage(char *argv0)
{
	int i;

	printf("usage: %s [-slot <num>] [-h] [-t <digest>] file\n", argv0);
	printf("Defaults: slot 0, md5 digest\n");
	printf("Digests supported:\n");
	for(i = 0; i < NUM_DIGESTS; i++)
		printf("\t%s\n", digests[i].id);
	exit(-1);
}

int main(int argc, char **argv)
{
	int i, j, bytes_read=READ_SIZE;
	CK_RV rc;
	CK_C_INITIALIZE_ARGS initialize_args;

	/* Set default slot to 0 */
	slot_id = 0;
	
	/* Parse the command line */
	for( i = 1; i < argc; i++ ) {
		if(strncmp(argv[i], "-slot", 5) == 0) {
			slot_id = atoi(argv[i + 1]);
			i++;
			continue;
		} else if(strncmp(argv[i], "-h", 2) == 0) {
			usage(argv[0]);
		} else if(strncmp(argv[i], "-t", 2) == 0) {
			if( argv[i + 1] ) {
				for( j = 0; j < NUM_DIGESTS; j++ ) {
					if( !strcmp(digests[j].id, argv[i+1]) )
						hash = j;
				}
				if( hash == -1 )
					usage(argv[0]);
			}
			
			i++;
			continue;
		} else {
			file = argv[i];
		}
	}
	
	if( file == NULL ) 
		usage(argv[0]);

	/* md5 is the default hash to use */
	if( hash == uninitialized )
		hash = md5;

#if 0
	printf("Using slot %d...\n\n", slot_id);
#endif
	if(do_GetFunctionList())
		return -1;
	
	/* There will be no multi-threaded Cryptoki access in this app */
	memset( &initialize_args, 0, sizeof(initialize_args) );
	
	if( (rc = funcs->C_Initialize( &initialize_args )) != CKR_OK ) {
		oc_err_msg("C_Initialize", rc);
		return;
	}

	/* stat the file for size, etc */
	if( stat(file, &file_stat) < 0 ) {
		printf("Error getting stats for file [%s]\n", file);
		perror("stat");
		return clean_up();
	}

	/* See if we can open the file */
	if( (fd = open(file, O_RDONLY)) < 0 ) {
		perror("open");
		return clean_up();
	}

	/* Open a session with the token */
	if( (rc = funcs->C_OpenSession(slot_id, 
					(CKF_SERIAL_SESSION|CKF_RW_SESSION), 
					NULL_PTR, 
					NULL_PTR, 
					&session_handle)) != CKR_OK ) {
		oc_err_msg("C_OpenSession", rc);
		goto file_close;
	}

	/* Get the mechanism list from the token */
	if( (rc = funcs->C_GetMechanismList(slot_id, NULL_PTR, &mech_num)) != CKR_OK) {
		oc_err_msg("C_GetMechanismList1", rc);
		goto session_close;
	}

	if( mech_num > 0 )
		mech_list = (CK_MECHANISM_TYPE_PTR)
			malloc(mech_num * sizeof(CK_MECHANISM_TYPE));
	else {
		printf("Token returned 0 mechanisms.\n");
		goto session_close;
	}
	
	if( (rc = funcs->C_GetMechanismList(slot_id, mech_list, &mech_num)) != CKR_OK) {
		oc_err_msg("C_GetMechanismList2", rc);
		goto mech_close;
	}

	if( (rc = funcs->C_GetMechanismInfo(slot_id, digests[hash].mech.mechanism, &mech_info)) != CKR_OK ) {
		oc_err_msg("C_GetMechanismInfo", rc);
		goto mech_close;
	}
	
	if( (msg_digest = (CK_BYTE_PTR)malloc(digests[hash].length)) == NULL) {
		perror("malloc");
		goto mech_close;
	}
	
	if( (buf = (char *)malloc(READ_SIZE)) == NULL ) {
		perror("malloc");
		goto mech_close;
	}

	if( (rc = funcs->C_DigestInit(session_handle, &digests[hash].mech)) != CKR_OK) {
		oc_err_msg("C_DigestInit", rc);
		goto mech_close;
	}

	/* loop until entire file is read */
	bytes_read = read(fd, buf, READ_SIZE);

	while(bytes_read == READ_SIZE) {
        	rc = funcs->C_DigestUpdate(session_handle, buf, bytes_read);
	        if( rc != CKR_OK) {
	                oc_err_msg("C_DigestUpdate", rc);
			goto mech_close;
		}
		bytes_read = read(fd, buf, READ_SIZE);
	}
	
	if( bytes_read )
	        rc = funcs->C_DigestUpdate(session_handle, (bytes_read ? buf : NULL), bytes_read);
	if( rc != CKR_OK) {
		oc_err_msg("C_DigestUpdate", rc);
		goto mech_close;
	}
	rc = funcs->C_DigestFinal(session_handle, msg_digest, &digests[hash].length);

	if( rc != CKR_OK) {
		oc_err_msg("C_DigestFinal", rc);
		goto mech_close;
	}

	for( i = 0; i < digests[hash].length; i++ )
		printf("%02x", msg_digest[i]);
	printf("\t*%s\n", file);



mech_close:
	if(msg_digest)
		free(msg_digest);

	if(buf)
		free(buf);
	
	free(mech_list);
	
session_close:
	/* Close the session */
	if( (rc = funcs->C_CloseSession(session_handle)) != CKR_OK ) {
		oc_err_msg("C_CloseSession", rc);
	}
	
file_close:
	/* close the file */
	close(fd);
	
	/* Call C_Finalize and dlclose the library */
	return clean_up();
}

int clean_up(void)
{
	int rc;
	
        if( (rc = funcs->C_Finalize(NULL)) != CKR_OK)
		oc_err_msg("C_Finalize", rc);

	/* Decrement the reference count to libopencryptoki.so */
	dlclose(dl_handle);
	
	return rc;
}

int do_GetFunctionList(void)
{
        char *pkcslib = "libopencryptoki.so";
	CK_RV (*func_ptr)();
	int rc;

	if( (dl_handle = dlopen(pkcslib, RTLD_NOW)) == NULL) {
		printf("dlopen: %s\n", dlerror());
		return -1;
	}
	
	func_ptr = (CK_RV (*)())dlsym(dl_handle, "C_GetFunctionList");

	if(func_ptr == NULL)
		return -1;

	if( (rc = func_ptr(&funcs)) != CKR_OK) {
		oc_err_msg("C_GetFunctionList", rc);
		return -1;
	}

	return 0;
}

void process_ret_code( CK_RV rc )
{
	switch (rc) {
	 case CKR_OK:printf(" CKR_OK");break;
	 case CKR_CANCEL:                           printf(" CKR_CANCEL");                           break;
	 case CKR_HOST_MEMORY:                      printf(" CKR_HOST_MEMORY");                      break;
	 case CKR_SLOT_ID_INVALID:                  printf(" CKR_SLOT_ID_INVALID");                  break;
	 case CKR_GENERAL_ERROR:                    printf(" CKR_GENERAL_ERROR");                    break;
	 case CKR_FUNCTION_FAILED:                  printf(" CKR_FUNCTION_FAILED");                  break;
	 case CKR_ARGUMENTS_BAD:                    printf(" CKR_ARGUMENTS_BAD");                    break;
	 case CKR_NO_EVENT:                         printf(" CKR_NO_EVENT");                         break;
	 case CKR_NEED_TO_CREATE_THREADS:           printf(" CKR_NEED_TO_CREATE_THREADS");           break;
	 case CKR_CANT_LOCK:                        printf(" CKR_CANT_LOCK");                        break;
	 case CKR_ATTRIBUTE_READ_ONLY:              printf(" CKR_ATTRIBUTE_READ_ONLY");              break;
	 case CKR_ATTRIBUTE_SENSITIVE:              printf(" CKR_ATTRIBUTE_SENSITIVE");              break;
	 case CKR_ATTRIBUTE_TYPE_INVALID:           printf(" CKR_ATTRIBUTE_TYPE_INVALID");           break;
	 case CKR_ATTRIBUTE_VALUE_INVALID:          printf(" CKR_ATTRIBUTE_VALUE_INVALID");          break;
	 case CKR_DATA_INVALID:                     printf(" CKR_DATA_INVALID");                     break;
	 case CKR_DATA_LEN_RANGE:                   printf(" CKR_DATA_LEN_RANGE");                   break;
	 case CKR_DEVICE_ERROR:                     printf(" CKR_DEVICE_ERROR");                     break;
	 case CKR_DEVICE_MEMORY:                    printf(" CKR_DEVICE_MEMORY");                    break;
	 case CKR_DEVICE_REMOVED:                   printf(" CKR_DEVICE_REMOVED");                   break;
	 case CKR_ENCRYPTED_DATA_INVALID:           printf(" CKR_ENCRYPTED_DATA_INVALID");           break;
	 case CKR_ENCRYPTED_DATA_LEN_RANGE:         printf(" CKR_ENCRYPTED_DATA_LEN_RANGE");         break;
	 case CKR_FUNCTION_CANCELED:                printf(" CKR_FUNCTION_CANCELED");                break;
	 case CKR_FUNCTION_NOT_PARALLEL:            printf(" CKR_FUNCTION_NOT_PARALLEL");            break;
	 case CKR_FUNCTION_NOT_SUPPORTED:           printf(" CKR_FUNCTION_NOT_SUPPORTED");           break;
	 case CKR_KEY_HANDLE_INVALID:               printf(" CKR_KEY_HANDLE_INVALID");               break;
	 case CKR_KEY_SIZE_RANGE:                   printf(" CKR_KEY_SIZE_RANGE");                   break;
	 case CKR_KEY_TYPE_INCONSISTENT:            printf(" CKR_KEY_TYPE_INCONSISTENT");            break;
	 case CKR_KEY_NOT_NEEDED:                   printf(" CKR_KEY_NOT_NEEDED");                   break;
	 case CKR_KEY_CHANGED:                      printf(" CKR_KEY_CHANGED");                      break;
	 case CKR_KEY_NEEDED:                       printf(" CKR_KEY_NEEDED");                       break;
	 case CKR_KEY_INDIGESTIBLE:                 printf(" CKR_KEY_INDIGESTIBLE");                 break;
	 case CKR_KEY_FUNCTION_NOT_PERMITTED:       printf(" CKR_KEY_FUNCTION_NOT_PERMITTED");       break;
	 case CKR_KEY_NOT_WRAPPABLE:                printf(" CKR_KEY_NOT_WRAPPABLE");                break;
	 case CKR_KEY_UNEXTRACTABLE:                printf(" CKR_KEY_UNEXTRACTABLE");                break;
	 case CKR_MECHANISM_INVALID:                printf(" CKR_MECHANISM_INVALID");                break;
	 case CKR_MECHANISM_PARAM_INVALID:          printf(" CKR_MECHANISM_PARAM_INVALID");          break;
	 case CKR_OBJECT_HANDLE_INVALID:            printf(" CKR_OBJECT_HANDLE_INVALID");            break;
	 case CKR_OPERATION_ACTIVE:                 printf(" CKR_OPERATION_ACTIVE");                 break;
	 case CKR_OPERATION_NOT_INITIALIZED:        printf(" CKR_OPERATION_NOT_INITIALIZED");        break;
	 case CKR_PIN_INCORRECT:                    printf(" CKR_PIN_INCORRECT");                    break;
	 case CKR_PIN_INVALID:                      printf(" CKR_PIN_INVALID");                      break;
	 case CKR_PIN_LEN_RANGE:                    printf(" CKR_PIN_LEN_RANGE");                    break;
	 case CKR_PIN_EXPIRED:                      printf(" CKR_PIN_EXPIRED");                      break;
	 case CKR_PIN_LOCKED:                       printf(" CKR_PIN_LOCKED");                       break;
	 case CKR_SESSION_CLOSED:                   printf(" CKR_SESSION_CLOSED");                   break;
	 case CKR_SESSION_COUNT:                    printf(" CKR_SESSION_COUNT");                    break;
	 case CKR_SESSION_HANDLE_INVALID:           printf(" CKR_SESSION_HANDLE_INVALID");           break;
	 case CKR_SESSION_PARALLEL_NOT_SUPPORTED:   printf(" CKR_SESSION_PARALLEL_NOT_SUPPORTED");   break;
	 case CKR_SESSION_READ_ONLY:                printf(" CKR_SESSION_READ_ONLY");                break;
	 case CKR_SESSION_EXISTS:                   printf(" CKR_SESSION_EXISTS");                   break;
	 case CKR_SESSION_READ_ONLY_EXISTS:         printf(" CKR_SESSION_READ_ONLY_EXISTS");         break;
	 case CKR_SESSION_READ_WRITE_SO_EXISTS:     printf(" CKR_SESSION_READ_WRITE_SO_EXISTS");     break;
	 case CKR_SIGNATURE_INVALID:                printf(" CKR_SIGNATURE_INVALID");                break;
	 case CKR_SIGNATURE_LEN_RANGE:              printf(" CKR_SIGNATURE_LEN_RANGE");              break;
	 case CKR_TEMPLATE_INCOMPLETE:              printf(" CKR_TEMPLATE_INCOMPLETE");              break;
	 case CKR_TEMPLATE_INCONSISTENT:            printf(" CKR_TEMPLATE_INCONSISTENT");            break;
	 case CKR_TOKEN_NOT_PRESENT:                printf(" CKR_TOKEN_NOT_PRESENT");                break;
	case CKR_TOKEN_NOT_RECOGNIZED:             printf(" CKR_TOKEN_NOT_RECOGNIZED");             break;
	case CKR_TOKEN_WRITE_PROTECTED:            printf(" CKR_TOKEN_WRITE_PROTECTED");            break;
	case CKR_UNWRAPPING_KEY_HANDLE_INVALID:    printf(" CKR_UNWRAPPING_KEY_HANDLE_INVALID");    break;
	case CKR_UNWRAPPING_KEY_SIZE_RANGE:        printf(" CKR_UNWRAPPING_KEY_SIZE_RANGE");        break;
	case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT: printf(" CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT"); break;
	case CKR_USER_ALREADY_LOGGED_IN:           printf(" CKR_USER_ALREADY_LOGGED_IN");           break;
	case CKR_USER_NOT_LOGGED_IN:               printf(" CKR_USER_NOT_LOGGED_IN");               break;
	case CKR_USER_PIN_NOT_INITIALIZED:         printf(" CKR_USER_PIN_NOT_INITIALIZED");         break;
	case CKR_USER_TYPE_INVALID:                printf(" CKR_USER_TYPE_INVALID");                break;
	case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:   printf(" CKR_USER_ANOTHER_ALREADY_LOGGED_IN");   break;
	case CKR_USER_TOO_MANY_TYPES:              printf(" CKR_USER_TOO_MANY_TYPES");              break;
	case CKR_WRAPPED_KEY_INVALID:              printf(" CKR_WRAPPED_KEY_INVALID");              break;
	case CKR_WRAPPED_KEY_LEN_RANGE:            printf(" CKR_WRAPPED_KEY_LEN_RANGE");            break;
	case CKR_WRAPPING_KEY_HANDLE_INVALID:      printf(" CKR_WRAPPING_KEY_HANDLE_INVALID");      break;
	case CKR_WRAPPING_KEY_SIZE_RANGE:          printf(" CKR_WRAPPING_KEY_SIZE_RANGE");          break;
	case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:   printf(" CKR_WRAPPING_KEY_TYPE_INCONSISTENT");   break;
	case CKR_RANDOM_SEED_NOT_SUPPORTED:        printf(" CKR_RANDOM_SEED_NOT_SUPPORTED");        break;
	case CKR_RANDOM_NO_RNG:                    printf(" CKR_RANDOM_NO_RNG");                    break;
	case CKR_BUFFER_TOO_SMALL:                 printf(" CKR_BUFFER_TOO_SMALL");                 break;
	case CKR_SAVED_STATE_INVALID:              printf(" CKR_SAVED_STATE_INVALID");              break;
	case CKR_INFORMATION_SENSITIVE:            printf(" CKR_INFORMATION_SENSITIVE");            break;
	case CKR_STATE_UNSAVEABLE:                 printf(" CKR_STATE_UNSAVEABLE");                 break;
	case CKR_CRYPTOKI_NOT_INITIALIZED:         printf(" CKR_CRYPTOKI_NOT_INITIALIZED");         break;
	case CKR_CRYPTOKI_ALREADY_INITIALIZED:     printf(" CKR_CRYPTOKI_ALREADY_INITIALIZED");     break;
	case CKR_MUTEX_BAD:                        printf(" CKR_MUTEX_BAD");break;
	case CKR_MUTEX_NOT_LOCKED:    printf(" CKR_MUTEX_NOT_LOCKED");break;
	}
}


void oc_err_msg( char *str, CK_RV rc )
{
	printf("Error: %s returned:  %d ", str, rc );
	process_ret_code( rc );
	printf("\n\n");
}

