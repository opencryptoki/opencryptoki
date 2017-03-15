/*
 * COPYRIGHT (c) International Business Machines Corp. 2014-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * pkcscca - A tool for PKCS#11 CCA token.
 * Currently, only migrates CCA private token objects from using a
 * CCA cipher to using a software cipher.
 *
 */


#ifndef __PKCSCCA_H_
#define __PKCSCCA_H_

#define CCA_LIBRARY "libcsulcca.so"
#define TOK_DATASTORE   CONFIG_PATH "/ccatok"
#define MASTER_KEY_SIZE 	64
#define SHA1_HASH_SIZE 		20
#define MD5_HASH_SIZE 		16
#define DES_BLOCK_SIZE 		8
#define DES_KEY_SIZE 		8
#define CCA_SUCCESS             0

#define AES_NAME                "AES"
#define DES_NAME                "DES"
#define DES2_NAME		"2DES"
#define DES3_NAME               "3DES"
#define ECC_NAME                "ECC"
#define HMAC_NAME		"HMAC"
#define RSA_NAME                "RSA"
#define BAD_NAME                "Unknown"

#define MK_AES			1
#define MK_APKA			2
#define MK_ASYM			3
#define MK_SYM			4

#define compute_sha1(a,b,c)     compute_hash(HASH_SHA1,b,a,c)
#define compute_md5(a,b,c)      compute_hash(HASH_MD5,b,a,c)
#define HASH_SHA1   1
#define HASH_MD5    2

typedef struct _MASTER_KEY_FILE_T
{
        CK_BYTE key[MASTER_KEY_SIZE];
        CK_BYTE sha_hash[SHA1_HASH_SIZE];
} MASTER_KEY_FILE_T;

CK_RV sw_des3_cbc(CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *, CK_BYTE *, CK_BYTE *, CK_BYTE);

#define sw_des3_cbc_encrypt(clear, len, cipher, len2, iv, key) \
                sw_des3_cbc(clear, len, cipher, len2, iv, key, 1)

#define sw_des3_cbc_decrypt(clear, len, cipher, len2, iv, key) \
                sw_des3_cbc(clear, len, cipher, len2, iv, key, 0)



/* from host_defs.h */
#include "pkcs32.h"
typedef struct _TWEAK_VEC
{
   int   allow_weak_des   ;
   int   check_des_parity ;
   int   allow_key_mods   ;
   int   netscape_mods    ;
} TWEAK_VEC;

typedef struct _TOKEN_DATA
{
   CK_TOKEN_INFO_32 token_info;

   CK_BYTE   user_pin_sha[3 * DES_BLOCK_SIZE];
   CK_BYTE   so_pin_sha[3 * DES_BLOCK_SIZE];
   CK_BYTE   next_token_object_name[8];
   TWEAK_VEC tweak_vector;
} TOKEN_DATA;

#define EVP_SUCCESS 1
#define HASH_SHA1   1
#define HASH_MD5    2
#define print_openssl_errors() \
        do { \
                ERR_load_crypto_strings(); \
                ERR_print_errors_fp(stderr); \
        } while (0)

int compute_hash(int hash_type, int buf_size, char* buf, char* digest);

#define compute_sha(a,b,c)      compute_hash(HASH_SHA1,b,a,c)
#define compute_md5(a,b,c)      compute_hash(HASH_MD5,b,a,c)

char *p11strerror(CK_RV);

#define p11_error(s,rc)         fprintf(stderr, "%s:%d %s failed: rc=0x%lX (%s)\n", __FILE__, \
                                        __LINE__, s, rc, p11strerror(rc))
#define print_error(x, ...)     fprintf(stderr, "%s:%d " x "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define cca_error(f,rc,rsn)     fprintf(stderr, "%s:%d " f " failed. return code: %ld, reason" \
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

struct key
{
        CK_OBJECT_HANDLE handle;
        CK_ULONG         type;
        CK_BYTE          *opaque_attr;
        CK_ULONG         attr_len;
	CK_CHAR_PTR	 label;

        struct key *next;
};

struct algo
{
	unsigned char *rule_array;
	unsigned char *name;
	long rule_array_count;
};

struct key_count
{
	int aes;
	int des;
	int des2;
	int des3;
	int ecc;
	int hmac;
	int rsa;
};

#endif
