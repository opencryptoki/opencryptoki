/*
 * Licensed materials - Property of IBM
 *
 * pkcs11_migrate - A tool to migrate PKCS#11 CCA key objects from one
 * master key to another.
 *
 * Copyright (C) International Business Machines Corp. 2007
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>

#include <pkcs11types.h>

#include <openssl/evp.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <openssl/md5.h>
#include <openssl/err.h>

#include "cca_migrate.h"


CK_RV
sw_des3_cbc(CK_BYTE  *in_data,
	    CK_ULONG in_data_len,
	    CK_BYTE  *out_data,
	    CK_ULONG *out_data_len,
	    CK_BYTE  *init_v,
	    CK_BYTE  *key_value,
	    CK_BYTE  encrypt)
{
	des_key_schedule des_key1;
	des_key_schedule des_key2;
	des_key_schedule des_key3;

	const_des_cblock key_SSL1, key_SSL2, key_SSL3;
	des_cblock ivec;

	// the des decrypt will only fail if the data length is not evenly divisible
	// by 8
	if (in_data_len % 8) {
		print_error("Data not a multiple of 8");
		return CKR_DATA_LEN_RANGE;
	}

	// The key as passed in is a 24 byte string containing 3 keys
	// pick it apart and create the key schedules
	memcpy(&key_SSL1, key_value, (size_t)8);
	memcpy(&key_SSL2, key_value+8, (size_t)8);
	memcpy(&key_SSL3, key_value+16, (size_t)8);
	des_set_key_unchecked(&key_SSL1, des_key1);
	des_set_key_unchecked(&key_SSL2, des_key2);
	des_set_key_unchecked(&key_SSL3, des_key3);

	memcpy(ivec, init_v, sizeof(ivec));

	// Encrypt or decrypt the data
	if (encrypt) {
		des_ede3_cbc_encrypt(in_data,
				out_data,
				in_data_len,
				des_key1,
				des_key2,
				des_key3,
				&ivec,
				DES_ENCRYPT);
		*out_data_len = in_data_len;
	} else {
		des_ede3_cbc_encrypt(in_data,
				out_data,
				in_data_len,
				des_key1,
				des_key2,
				des_key3,
				&ivec,
				DES_DECRYPT);
		*out_data_len = in_data_len;
	}

	return CKR_OK;
}

CK_RV
add_pkcs_padding(CK_BYTE  *ptr,
		 CK_ULONG block_size,
		 CK_ULONG data_len,
		 CK_ULONG total_len)
{
	CK_ULONG i, pad_len;
	CK_BYTE  pad_value;

	pad_len = block_size - (data_len % block_size);
	pad_value = (CK_BYTE)pad_len;

	if (data_len + pad_len > total_len){
		print_error("Padding error");
		return CKR_FUNCTION_FAILED;
	}

	for (i = 0; i < pad_len; i++)
		ptr[i] = pad_value;

	return CKR_OK;
}

int
compute_hash(int  hash_type,
	     int  buf_size,
	     char *buf,
	     char *digest)
{
	EVP_MD_CTX md_ctx;
	unsigned int result_size;
	int rv;

	switch (hash_type) {
		case HASH_SHA1:
			rv = EVP_DigestInit(&md_ctx, EVP_sha1());
			break;
		case HASH_MD5:
			rv = EVP_DigestInit(&md_ctx, EVP_md5());
			break;
		default:
			rv = 1;
			goto out;
			break;
	}

	if (rv != EVP_SUCCESS) {
		rv = 2;
		goto err;
	}

	rv = EVP_DigestUpdate(&md_ctx, buf, buf_size);
	if (rv != EVP_SUCCESS) {
		rv = 3;
		goto err;
	}

	result_size = EVP_MD_CTX_size(&md_ctx);
	rv = EVP_DigestFinal(&md_ctx, (unsigned char *)digest, &result_size);
	if (rv != EVP_SUCCESS) {
		rv = 4;
		goto err;
	} else
		rv = 0;

	goto out;

err:
	print_openssl_errors();
out:
	return rv;
}

CK_RV
load_masterkey(char *path, char *pin_md5, char *master_key)
{
	FILE               * fp = NULL;
	CK_BYTE              hash_sha[SHA1_HASH_SIZE];
	CK_BYTE              cipher[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
	CK_BYTE              clear[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
	CK_BYTE              des3_key[3 * DES_KEY_SIZE];
	MASTER_KEY_FILE_T    mk;
	CK_ULONG             cipher_len, clear_len;//, hash_len;
	CK_RV                rc;

	memset( master_key, 0x0, MASTER_KEY_SIZE );

	// this file gets created on C_InitToken so we can assume that it always exists
	//
	fp = fopen(path, "r" );
	if (!fp) {
		print_error("Error opening master key file: %s", path);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	clear_len = cipher_len = (sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE - 1) & ~(DES_BLOCK_SIZE - 1);

	rc = fread( cipher, cipher_len, 1, fp );
	if (rc != 1) {
		print_error("Error reading master key file: %s", path);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	// decrypt the master key data using the MD5 of the pin
	// (we can't use the SHA of the pin since the SHA of the pin is stored
	// in the token data file).
	//
	memcpy( des3_key,                 pin_md5, MD5_HASH_SIZE );
	memcpy( des3_key + MD5_HASH_SIZE, pin_md5, DES_KEY_SIZE  );
	rc = sw_des3_cbc_decrypt( cipher, cipher_len, clear, &clear_len, (CK_BYTE *)"12345678", des3_key );
	if (rc != CKR_OK){
		print_error("Error decrypting master key file after read");
		goto done;
	}
	memcpy( (CK_BYTE *)&mk, clear, sizeof(mk) );

	//
	// technically should strip PKCS padding here but since I already know what
	// the length should be, I don't bother.
	//

	// compare the hashes
	//
	rc = compute_sha( (char *)mk.key, MASTER_KEY_SIZE, (char *)hash_sha );
	if (rc) {
		print_error("Error computing SHA1 of master key after read: %s", path);
	}

	if (memcmp(hash_sha, mk.sha_hash, SHA1_HASH_SIZE) != 0) {
		print_error("Hash of loaded master key %s doesn't match!", path);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	memcpy( master_key, mk.key, MASTER_KEY_SIZE );
	rc = CKR_OK;

done:
	if (fp) fclose(fp);
	return rc;
}

CK_RV
save_masterkey(char *path, char *pin_md5, char *master_key)
{
	FILE             * fp = NULL;
	CK_BYTE            cleartxt [sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
	CK_BYTE            ciphertxt[sizeof(MASTER_KEY_FILE_T) + DES_BLOCK_SIZE];
	CK_BYTE            des3_key[3 * DES_KEY_SIZE];
	MASTER_KEY_FILE_T  mk;
	CK_ULONG           cleartxt_len, ciphertxt_len, padded_len;
	CK_RV              rc;


	memcpy(mk.key, master_key, MASTER_KEY_SIZE);

	rc = compute_sha(master_key, MASTER_KEY_SIZE, (char *)mk.sha_hash);
	if (rc) {
		print_error("Error computing SHA1 of master key before write");
		goto done;
	}

	// encrypt the key data
	//
	memcpy( des3_key,                 pin_md5, MD5_HASH_SIZE );
	memcpy( des3_key + MD5_HASH_SIZE, pin_md5, DES_KEY_SIZE  );

	ciphertxt_len = sizeof(ciphertxt);
	cleartxt_len  = sizeof(mk);
	memcpy(cleartxt, &mk, cleartxt_len);

	padded_len = DES_BLOCK_SIZE * (cleartxt_len / DES_BLOCK_SIZE + 1);
	add_pkcs_padding(cleartxt + cleartxt_len, DES_BLOCK_SIZE, cleartxt_len, padded_len);

	rc = sw_des3_cbc_encrypt(cleartxt, padded_len, ciphertxt, &ciphertxt_len, (CK_BYTE *)"12345678", des3_key);
	if (rc != CKR_OK){
		print_error("Error encrypting master key before write");
		goto done;
	}

	// write the file
	//
	// probably ought to ensure the permissions are correct
	//
	fp = fopen(path, "w" );
	if (!fp) {
		print_error("Error opening master key file for write: %s", path);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	rc = fwrite( ciphertxt, ciphertxt_len, 1, fp );
	if (rc != 1) {
		print_error("Error writing master key: %s", path);
		rc = CKR_FUNCTION_FAILED;
		goto done;
	}

	rc = CKR_OK;
done:
	if (fp) fclose(fp);
	return rc;
}

