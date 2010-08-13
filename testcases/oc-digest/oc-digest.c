
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
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>

#include "pkcs11types.h"
#include "p11util.h"

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
#define NUM_DIGESTS	6
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
	},
	{
		.id = "sha384",
		.length = 48,
		.mech = {
			.mechanism = CKM_SHA384,
			.pParameter = NULL,
			.ulParameterLen = 0
		}
	},
	{
		.id = "sha512",
		.length = 64,
		.mech = {
			.mechanism = CKM_SHA512,
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
	sha256,
	sha384,
	sha512
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
	unsigned int k;
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
		return rc;
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
	  rc = funcs->C_DigestUpdate(session_handle, (CK_BYTE_PTR)buf, bytes_read);
	        if( rc != CKR_OK) {
	                oc_err_msg("C_DigestUpdate", rc);
			goto mech_close;
		}
		bytes_read = read(fd, buf, READ_SIZE);
	}
	
	if( bytes_read )
	  rc = funcs->C_DigestUpdate(session_handle, (CK_BYTE_PTR)(bytes_read ? buf : NULL), bytes_read);
	if( rc != CKR_OK) {
		oc_err_msg("C_DigestUpdate", rc);
		goto mech_close;
	}
	rc = funcs->C_DigestFinal(session_handle, msg_digest, &digests[hash].length);

	if( rc != CKR_OK) {
		oc_err_msg("C_DigestFinal", rc);
		goto mech_close;
	}

	for( k = 0; k < digests[hash].length; k++ )
		printf("%02x", msg_digest[k]);
	printf("\t*%s\n", file);



mech_close:
	if(msg_digest)
		free(msg_digest);

	if(buf)
		free(buf);
	
	free(mech_list);
	
session_close:
	/* Close the session, being careful not to clobber rc */
	{
		CK_RV loc_rc;

		if( (loc_rc = funcs->C_CloseSession(session_handle)) != CKR_OK ) {
			oc_err_msg("C_CloseSession", loc_rc);

			if (rc == CKR_OK) {
				rc = loc_rc;
			}
		}
	}
	
file_close:
	/* close the file */
	close(fd);
	
	/* Call C_Finalize and dlclose the library */
	clean_up();

	return rc;
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


void oc_err_msg( char *str, CK_RV rc )
{
	printf("Error: %s returned:  %ld - %s\n", str, rc, p11_get_ckr(rc) );
}

