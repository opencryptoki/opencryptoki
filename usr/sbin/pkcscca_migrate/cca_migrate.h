
/*
 * Licensed materials - Property of IBM
 *
 * pkcs11_migrate - A tool to migrate PKCS#11 CCA key objects from one
 * master key to another.
 *
 * Copyright (C) International Business Machines Corp. 2007
 *
 */


#ifndef __CCA_MIGRATE_H_
#define __CCA_MIGRATE_H_

#define SHA1_HASH_SIZE		20
#define CCA_KEY_ID_SIZE		64
#define MASTER_KEY_SIZE         CCA_KEY_ID_SIZE
#define DES_BLOCK_SIZE		8
#define DES_KEY_SIZE		8
#define MD5_HASH_SIZE		16
#define CCA_SUCCESS		0

#define RSA_NAME		"RSA"
#define DES_NAME		"DES"
#define DES3_NAME		"3DES"
#define BAD_NAME		"Unknown"

CK_RV sw_des3_cbc(CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *, CK_BYTE *, CK_BYTE *, CK_BYTE);

#define sw_des3_cbc_encrypt(clear, len, cipher, len2, iv, key) \
	        sw_des3_cbc(clear, len, cipher, len2, iv, key, 1)

#define sw_des3_cbc_decrypt(clear, len, cipher, len2, iv, key) \
	        sw_des3_cbc(clear, len, cipher, len2, iv, key, 0)


typedef struct _MASTER_KEY_FILE_T
{
	CK_BYTE key[MASTER_KEY_SIZE];
	CK_BYTE sha_hash[SHA1_HASH_SIZE];
} MASTER_KEY_FILE_T;


#define EVP_SUCCESS 1
#define HASH_SHA1   1
#define HASH_MD5    2
#define print_openssl_errors() \
	do { \
		ERR_load_crypto_strings(); \
		ERR_print_errors_fp(stderr); \
	} while (0)

int compute_hash(int hash_type, int buf_size, char* buf, char* digest);

#define compute_sha(a,b,c)	compute_hash(HASH_SHA1,b,a,c)
#define compute_md5(a,b,c)	compute_hash(HASH_MD5,b,a,c)

char *p11strerror(CK_RV);

#define p11_error(s,rc)		fprintf(stderr, "%s:%d %s failed: rc=0x%lX (%s)\n", __FILE__, \
					__LINE__, s, rc, p11strerror(rc))
#define print_error(x, ...)	fprintf(stderr, "%s:%d " x "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define cca_error(f,rc,rsn)	fprintf(stderr, "%s:%d " f " failed. return code: %ld, reason" \
					"code: %ld\n", __FILE__, __LINE__, rc, rsn)
#define print_hex(x, y) \
	do { \
		unsigned char *hex = x; \
		int i; \
		for (i = 0; i < y; i++) { \
			printf("%02x", hex[i]); \
			if (((i+1) % 32) == 0) \
				printf("\n"); \
			else if (((i+1) % 4) == 0) \
				printf(" "); \
		} \
	} while (0)

struct object
{
	CK_OBJECT_HANDLE handle;
	CK_ULONG	 type;
	CK_BYTE          *opaque_attr;
	CK_ULONG         attr_len;

	struct object *next;
};

CK_RV load_masterkey(char *path, char *pin_md5, char *master_key);
CK_RV save_masterkey(char *path, char *pin_md5, char *master_key);


#endif
