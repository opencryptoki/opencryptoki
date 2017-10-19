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
 * Currently, only migrates CCA private token objects from CCA cipher
 * to using a software cipher.
 *
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <getopt.h>
#include <memory.h>
#include <linux/limits.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <termios.h>
#include <unistd.h>
#include <unistd.h>

#include <pkcs11types.h>

#include "sw_crypt.h"
#include "pkcscca.h"


int v_flag = 0;
void *p11_lib = NULL;
void (*CSNDKTC)();
void (*CSNBKTC)();
void (*CSNBKTC2)();
void (*CSNBDEC)();
void *lib_csulcca;

struct algo aes = {"RTCMK   AES     ", "AES", 2};
struct algo des = {"RTCMK   ", "DES", 1};
struct algo hmac = {"RTCMK   HMAC    ", "HMAC", 2};
struct algo ecc = {"RTCMK   ECC     ", "ECC", 2};
struct algo rsa = {"RTCMK   ", "RSA", 1};

int compute_hash(int hash_type, int buf_size, char *buf, char *digest)
{
	EVP_MD_CTX *md_ctx = NULL;
	unsigned int result_size;
	int rc;

	md_ctx = EVP_MD_CTX_create();

	switch (hash_type) {
	case HASH_SHA1:
		rc = EVP_DigestInit(md_ctx, EVP_sha1());
		break;
	case HASH_MD5:
		rc = EVP_DigestInit(md_ctx, EVP_md5());
		break;
	default:
		EVP_MD_CTX_destroy(md_ctx);
		return -1;
	break;
	}

	if (rc != 1) {
		fprintf(stderr, "EVP_DigestInit() failed: rc = %d\n", rc);
		return -1;
	}

        rc = EVP_DigestUpdate(md_ctx, buf, buf_size);
        if (rc != 1) {
		fprintf(stderr, "EVP_DigestUpdate() failed: rc = %d\n", rc);
		return -1;
        }

	result_size = EVP_MD_CTX_size(md_ctx);
	rc = EVP_DigestFinal(md_ctx, (unsigned char *)digest, &result_size);
        if (rc != 1) {
		fprintf(stderr, "EVP_DigestFinal() failed: rc = %d\n", rc);
		return -1;
        }
	EVP_MD_CTX_destroy(md_ctx);
        return 0;
}

int cca_decrypt(unsigned char *in_data, unsigned long in_data_len,
		  unsigned char *out_data, unsigned long *out_data_len,
		  unsigned char *init_v, unsigned char *key_value)
{
	long return_code, reason_code, rule_array_count, length;
	unsigned char chaining_vector[18];
	unsigned char rule_array[256];

	length = in_data_len;
	rule_array_count = 1;
	memcpy(rule_array, "CBC     ", 8);

	CSNBDEC(&return_code, &reason_code, NULL, NULL, key_value,
		&length, in_data, init_v, &rule_array_count,
		rule_array, chaining_vector, out_data);

        if (return_code != 0) {
                fprintf(stderr, "CSNBDEC (DES3 DECRYPT) failed: return_code=%ld reason_code=%ld\n", return_code, reason_code);
		return -1;
	}
	*out_data_len = length;
	return 0;
}

int reencrypt_private_token_object(unsigned char *data, unsigned long len,
				     unsigned char *new_cipher,
				     unsigned long *new_cipher_len,
				     unsigned char *masterkey)
{
	unsigned char *clear = NULL;
	unsigned char des3_key[64];
	unsigned char sw_des3_key[3 * DES_KEY_SIZE];
	unsigned long clear_len;
	CK_RV rc;
	int ret;

	/* cca wants 8 extra bytes for padding purposes */
	clear_len = len + 8;
	clear = (unsigned char *) malloc(clear_len);
	if (!clear) {
		fprintf(stderr, "malloc() failed: %s.\n", strerror(errno));
		ret =-1;
		goto done;
	}

	/* decrypt using cca des3 */
	memcpy(des3_key, masterkey, MASTER_KEY_SIZE);
	ret = cca_decrypt(data, len, clear, &clear_len, "10293847", des3_key);
	if (ret)
		goto done;

	/* now encrypt using software des3 */
	memcpy(sw_des3_key, masterkey, 3 * DES_KEY_SIZE);
	rc = sw_des3_cbc_encrypt(clear, clear_len, new_cipher, new_cipher_len,
				 "10293847", sw_des3_key);
	if (rc != CKR_OK)
		ret = -1;
done:
        if (clear)
                free(clear);

        return ret;
}

int load_private_token_objects(unsigned char *data_store,
			       unsigned char *masterkey)
{
	FILE *fp1 = NULL, *fp2 = NULL;
	unsigned char *buf = NULL;
	unsigned char tmp[PATH_MAX], fname[PATH_MAX], iname[PATH_MAX];
	CK_BBOOL priv;
	unsigned int size;
	int rc = 0, scount = 0, fcount = 0;
	size_t read_size;
	unsigned char *new_cipher = NULL;
	unsigned long new_cipher_len;

	snprintf(iname, sizeof(iname), "%s/TOK_OBJ/OBJ.IDX", data_store);

	fp1 = fopen((char *)iname, "r");
	if (!fp1)
		return -1;  // no token objects

	while (fgets((char *)tmp, 50, fp1)) {
		tmp[strlen((char *)tmp) - 1] = 0;

		snprintf((char *)fname, sizeof(fname), "%s/TOK_OBJ/",
			 data_store);
		strcat((char *)fname, (char *)tmp);

		fp2 = fopen((char *)fname, "r");
		if (!fp2)
			continue;

		read_size = fread(&size, sizeof(unsigned int), 1, fp2);
		if (read_size != 1) {
			fprintf(stderr, "Cannot read size\n");
			goto cleanup;
		}
		read_size = fread(&priv, sizeof(CK_BBOOL), 1, fp2);
		if (read_size != 1) {
			fprintf(stderr, "Cannot read boolean\n");
			goto cleanup;
		}
		if (priv == FALSE) {
			fclose(fp2);
			continue;
		}

		size = size - sizeof(unsigned int) - sizeof(CK_BBOOL);
		buf = (unsigned char *) malloc(size);
		if (!buf) {
			fprintf(stderr, "Cannot malloc for object %s "
				"(ignoring it).\n", tmp);
			goto cleanup;
		}

		read_size = fread((char *)buf, 1, size, fp2);
		if (read_size != size) {
			fprintf(stderr, "Cannot read object %s "
				"(ignoring it).\n", tmp);
			goto cleanup;
		}

		new_cipher_len = size;
		new_cipher = malloc(new_cipher_len);
		if (!new_cipher) {
			fprintf(stderr, "Cannot malloc space for new "
				"cipher (ignoring object %s).\n", tmp);
			goto cleanup;
		}

		/* After reading the private token object,
		 * decrypt it using CCA des3 and then re-encrypt it
		 * using software des3.
		 */
		memset(new_cipher, 0, new_cipher_len);
		rc = reencrypt_private_token_object(buf, size,
				new_cipher, &new_cipher_len,
				masterkey);
		if (rc)
			goto cleanup;

		fclose(fp2);

		/* now save the newly re-encrypted object back to
		 * disk in its original file.
		 */
		fp2 = fopen((char *)fname, "w");
		size = sizeof(unsigned int) + sizeof(CK_BBOOL)
			    + new_cipher_len;
		(void)fwrite(&size, sizeof(unsigned int), 1, fp2);
		(void)fwrite(&priv, sizeof(CK_BBOOL), 1, fp2);
		(void)fwrite(new_cipher, new_cipher_len, 1, fp2);
		rc = 0;

cleanup:
		if (fp2)
			fclose(fp2);
		if (buf)
			free(buf);
		if (new_cipher)
			free(new_cipher);

		if (rc) {
			if (v_flag)
				printf("Failed to process %s\n", fname);
			fcount++;
		} else {
			if (v_flag)
				printf("Processed %s.\n", fname);
			scount++;
		}
	}
	fclose(fp1);
	printf("Successfully migrated %d object(s).\n", scount);

	if (v_flag && fcount)
		printf("Failed to migrate %d object(s).\n", fcount);

	return 0;
}

int load_masterkey(char *mkfile, char *pin, char *masterkey)
{
	unsigned char des3_key[3 * DES_KEY_SIZE];
	unsigned char hash_sha[SHA1_HASH_SIZE];
	unsigned char pin_md5_hash[MD5_HASH_SIZE];
	unsigned char *cipher = NULL;
	unsigned char *clear = NULL;
	unsigned long cipher_len, clear_len;
	int ret;
	CK_RV rc;
	FILE *fp = NULL;

	clear_len = cipher_len = (MASTER_KEY_SIZE + SHA1_HASH_SIZE + (DES_BLOCK_SIZE - 1)) & ~(DES_BLOCK_SIZE - 1);

	fp = fopen((char *)mkfile, "r");
	if (!fp) {
		print_error("Could not open %s: %s\n", mkfile, strerror(errno));
		return -1;
	}

	cipher = malloc(cipher_len);
	clear = malloc(clear_len);
	if (cipher == NULL || clear == NULL) {
		ret = -1;
		goto done;
	}

	ret = fread(cipher, cipher_len, 1, fp);
	if (ret != 1) {
		print_error("Could not read %s: %s\n", mkfile, strerror(errno));
                ret = -1;
                goto done;
        }

	/* decrypt the masterkey */

	ret = compute_md5(pin, strlen(pin), pin_md5_hash);
	if (ret) {
		print_error("Error calculating MD5 of PIN!\n");
		goto done;
	}

	memcpy(des3_key, pin_md5_hash, MD5_HASH_SIZE);
	memcpy(des3_key + MD5_HASH_SIZE, pin_md5_hash, DES_KEY_SIZE);

	rc = sw_des3_cbc_decrypt(cipher, cipher_len, clear, &clear_len,
                                 (unsigned char *)"12345678", des3_key);
	if (rc != CKR_OK) {
		print_error("Error decrypting master key file after read");
		ret = -1;
		goto done;
	}

	/*
	 * technically should strip PKCS padding here but since I already know
	 * what the length should be, I don't bother.
	 *
	 * compare the hashes to verify integrity
	 */

        ret = compute_sha1(clear, MASTER_KEY_SIZE, hash_sha);
        if (ret) {
		print_error("Failed to compute sha for masterkey.\n");
                goto done;
        }

        if (memcmp(hash_sha, clear + MASTER_KEY_SIZE, SHA1_HASH_SIZE) != 0) {
		print_error("%s appears to have been tampered!\n", mkfile);
		print_error("Cannot migrate.\n");
		ret = -1;
                goto done;
        }

        memcpy(masterkey, clear, MASTER_KEY_SIZE);
	ret = 0;

done:
	if (fp)
		fclose(fp);
	if (clear)
		free(clear);
	if (cipher)
		free(cipher);

	return ret;
}

int get_pin(char **pin, size_t *pinlen)
{
	struct termios old, new;
	int nread;
	char *buff = NULL;
	size_t buflen;
	int rc = 0;

	/* turn echoing off */
	if (tcgetattr(fileno(stdin), &old) != 0)
	return -1;

	new = old;
	new.c_lflag &= ~ECHO;
	if (tcsetattr (fileno(stdin), TCSAFLUSH, &new) != 0)
		return -1;

	/* read the pin
	* Note: getline will allocate memory for buff. free it when done.
	*/
	nread = getline(&buff, &buflen, stdin);
	if (nread == -1) {
		rc = -1;
		goto done;
	}

	/* Restore terminal */
	(void) tcsetattr(fileno(stdin), TCSAFLUSH, &old);

	/* start a newline */
	printf("\n");
	fflush(stdout);

	/* Allocate  PIN.
	 * Note: nread includes carriage return.
	 * Replace with terminating NULL.
	 */
	*pin = (unsigned char *)malloc(nread);
	if (*pin == NULL) {
		rc = -ENOMEM;
		goto done;
	}

	/* strip the carriage return since not part of pin. */
	buff[nread - 1] = '\0';
	memcpy(*pin, buff, nread);
	/* don't include the terminating null in the pinlen */
	*pinlen = nread - 1;

done:
	if (buff)
		free(buff);

	return rc;
}

int verify_pins(char *data_store, char *sopin, unsigned long sopinlen,
		char *userpin, unsigned long userpinlen)
{
	TOKEN_DATA  td;
	unsigned char fname[PATH_MAX];
	unsigned char pin_sha[SHA1_HASH_SIZE];
	FILE *fp = NULL;
	int ret;

	/* read the NVTOK.DAT */
	snprintf(fname, PATH_MAX, "%s/NVTOK.DAT", data_store);
	fp = fopen((char *)fname, "r");
	if (!fp) {
		print_error("Could not open %s: %s\n", fname, strerror(errno));
		return -1;
	}

	ret = fread(&td, sizeof(TOKEN_DATA), 1, fp);
	if (ret != 1) {
		print_error("Could not read %s: %s\n", fname, strerror(errno));
		ret = -1;
		goto done;
	}

	/* Now compute the SHAs for the SO and USER pins entered.
	 * Compare with the SHAs for SO and USER PINs saved in
	 * NVTOK.DAT to verify.
	 */

	if (sopin != NULL) {
		ret = compute_sha1(sopin, sopinlen, pin_sha);
		if (ret) {
			print_error("Failed to compute sha for SO.\n");
			goto done;
		}

		if (memcmp(td.so_pin_sha, pin_sha, SHA1_HASH_SIZE) != 0) {
			print_error("SO PIN is incorrect.\n");
			ret = -1;
			goto done;
		}
	}

	if (userpin != NULL) {
		ret = compute_sha1(userpin, userpinlen, pin_sha);
		if (ret) {
			print_error("Failed to compute sha for USER.\n");
			goto done;
		}

		if (memcmp(td.user_pin_sha, pin_sha, SHA1_HASH_SIZE) != 0) {
			print_error("USER PIN is incorrect.\n");
			ret = -1;
			goto done;
		}
	}
	ret = 0;

done:
	/* clear out the hash */
	memset(pin_sha, 0, SHA1_HASH_SIZE);
	if (fp)
		fclose(fp);

	return ret;
}


CK_FUNCTION_LIST *p11_init(void)
{
	CK_RV            rv;
	CK_RV		 (*pfoo)();
	char		 *loc1_lib = "/usr/lib/pkcs11/PKCS11_API.so64";
	char		 *loc2_lib = "libopencryptoki.so";
	CK_FUNCTION_LIST *funcs = NULL;


	p11_lib = dlopen(loc1_lib, RTLD_NOW);
	if (p11_lib != NULL)
		goto get_list;

	p11_lib = dlopen(loc2_lib, RTLD_NOW);
	if (p11_lib == NULL) {
		print_error("Couldn't get a handle to the PKCS#11 library.");
		return NULL;
	}

get_list:
	pfoo = (CK_RV (*)())dlsym(p11_lib,"C_GetFunctionList");
	if (pfoo == NULL) {
		print_error("Couldn't get the address of the C_GetFunctionList routine.");
		dlclose(p11_lib);
		return NULL;
	}

	rv = pfoo(&funcs);
	if (rv != CKR_OK) {
		p11_error("C_GetFunctionList", rv);
		dlclose(p11_lib);
		return NULL;
	}

	rv = funcs->C_Initialize(NULL_PTR);
	if (rv != CKR_OK) {
		p11_error("C_Initialize", rv);
		dlclose(p11_lib);
		return NULL;
	}

	if (v_flag)
		printf("PKCS#11 library initialized\n");

	return funcs;
}

void p11_fini(CK_FUNCTION_LIST *funcs)
{
	funcs->C_Finalize(NULL_PTR);

	if (p11_lib)
		dlclose(p11_lib);
}

/* Expect attribute array to have 3 entries,
 * 0 CKA_IBM_OPAQUE
 * 1 CKA_KEY_TYPE
 * 2 CKA_LABEL
 */
int add_key(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE  *attrs, struct key **keys)
{
	struct key *new_key;
	CK_ULONG key_type = *(CK_ULONG *)attrs[1].pValue;

	new_key = malloc(sizeof(struct key));
	if (!new_key) {
		print_error("Malloc of %zd bytes failed!", sizeof(struct key));
		return 1;
	}

	switch (key_type) {
		case CKK_AES:
		case CKK_DES:
		case CKK_DES2:
		case CKK_DES3:
		case CKK_EC:
		case CKK_GENERIC_SECRET:
		case CKK_RSA:
			break;

		default:
			free(new_key);
			return 0;
	}

	new_key->type = key_type;
	new_key->opaque_attr = malloc(attrs[0].ulValueLen);
	if (!new_key->opaque_attr) {
		print_error("Malloc of %lu bytes failed!", attrs[0].ulValueLen);
		return 2;
	}
	new_key->handle = handle;
	new_key->attr_len = attrs[0].ulValueLen;
	memcpy(new_key->opaque_attr, attrs[0].pValue, attrs[0].ulValueLen);
	new_key->label = malloc(attrs[2].ulValueLen+1);
	if (!new_key->label) {
		print_error("Malloc of %lu bytes failed!", attrs[2].ulValueLen+1);
		return 2;
	}

	memset(new_key->label, 0, attrs[2].ulValueLen+1);
	memcpy(new_key->label, attrs[2].pValue, attrs[2].ulValueLen);

	new_key->next = *keys;
	*keys = new_key;

	if (v_flag) {
		char *type_name;
		switch (new_key->type) {
		case CKK_AES:
			type_name = AES_NAME;
			break;
		case CKK_DES:
			type_name = DES_NAME;
			break;
		case CKK_DES2:
			type_name = DES2_NAME;
			break;
		case CKK_DES3:
			type_name = DES3_NAME;
			break;
		case CKK_EC:
			type_name = ECC_NAME;
			break;
		case CKK_GENERIC_SECRET:
			type_name = HMAC_NAME;
			break;
		case CKK_RSA:
			type_name = RSA_NAME;
			break;
		default:
			type_name = BAD_NAME;
		}

		printf("Migratable key found: type=%s, label=%s, handle=%lu\n",
			type_name, new_key->label, handle);
	}

	return 0;
}

int find_wrapped_keys(CK_FUNCTION_LIST  *funcs, CK_SESSION_HANDLE sess,
		    CK_KEY_TYPE *key_type, struct key  **keys)
{
	CK_RV		 rv;
	CK_OBJECT_HANDLE *handles = NULL, tmp;
	CK_ULONG	 ulObjectCount = 0, ulTotalCount = 0;
        CK_BBOOL 	 true = TRUE;
        CK_ATTRIBUTE key_tmpl[] = {
                { CKA_KEY_TYPE, key_type, sizeof(*key_type) },
		{ CKA_TOKEN, &true, sizeof(true) },
		{ CKA_EXTRACTABLE, &true, sizeof(true) }
        };

	CK_ATTRIBUTE	 attrs[] = {
		{ CKA_IBM_OPAQUE, NULL, 0 },
		{ CKA_KEY_TYPE, NULL, 0 },
		{ CKA_LABEL, NULL, 0 }
	};
	int	i, rc, num_attrs = 3;


	/* Find all objects in the store */
	rv = funcs->C_FindObjectsInit(sess, key_tmpl, 3);
	if (rv != CKR_OK) {
		p11_error("C_FindObjectsInit", rv);
		print_error("Error finding CCA key objects");
		return 1;
	}

	while (1) {
		rv = funcs->C_FindObjects(sess, &tmp, 1, &ulObjectCount);
		if (rv != CKR_OK) {
			p11_error("C_FindObjects", rv);
			print_error("Error finding CCA key objects");
			free(handles);
			return 1;
		}

		if (ulObjectCount == 0)
			break;

		handles = realloc(handles, sizeof(CK_OBJECT_HANDLE) * (++ulTotalCount));
		if (!handles) {
			print_error("Malloc of %lu bytes failed!", ulTotalCount);
			break;
		}

		handles[ulTotalCount - 1] = tmp;
	}
	if (v_flag)
		printf("Found %lu keys to examine\n", ulTotalCount);

	/* Don't care if this fails */
	funcs->C_FindObjectsFinal(sess);

	/* At this point we have an array with handles to every object in the
	 * store. We only care about those with a CKA_IBM_OPAQUE attribute,
	 * so whittle down the list accordingly */
	for (tmp = 0; tmp < ulTotalCount; tmp++) {
		rv = funcs->C_GetAttributeValue(sess, handles[tmp], attrs, num_attrs);
		if (rv != CKR_OK) {
			p11_error("C_GetAttributeValue", rv);
			print_error("Error finding CCA key objects");
			free(handles);
			return 1;
		}

		/* If the opaque attr DNE, move to the next key */
		if (attrs[0].ulValueLen == ((CK_ULONG)-1)) {
			continue;
		}

		/* Allocate space in the template for the actual data */
		for (i = 0; i < num_attrs; i++) {
			attrs[i].pValue = malloc(attrs[i].ulValueLen);
			if (!attrs[i].pValue) {
				print_error("Malloc of %lu bytes failed!",
					attrs[i].ulValueLen);
				free(handles);
				return 1;
			}
		}

		/* Pull in the actual data */
		rv = funcs->C_GetAttributeValue(sess, handles[tmp], attrs,
						num_attrs);
		if (rv != CKR_OK) {
			p11_error("C_GetAttributeValue", rv);
			print_error("Error getting object attributes");
			free(handles);
			return 1;
		}

		rc = add_key(handles[tmp], attrs, keys);
		if (rc) {
			free(handles);
			return 1;
		}

		for (i = 0; i < num_attrs; i++) {
			free(attrs[i].pValue);
			attrs[i].pValue = NULL_PTR;
			attrs[i].ulValueLen = 0;
		}
	}

	free(handles);

	return 0;
}

int replace_keys(CK_FUNCTION_LIST  *funcs, CK_SESSION_HANDLE sess,
		struct key *keys)
{
	CK_RV rv;
	CK_ATTRIBUTE new_attr[] = { { CKA_IBM_OPAQUE, NULL, 0 } };
	struct key *key;

	for (key = keys; key; key = key->next) {
		new_attr->pValue = key->opaque_attr;
		new_attr->ulValueLen = key->attr_len;

		rv = funcs->C_SetAttributeValue(sess, key->handle,
				new_attr, 1);
		if (rv != CKR_OK) {
			p11_error("C_SetAttributeValue", rv);
			print_error("Error replacing old key with "
				"migrated key.");
			return 1;
		}
	}

	return 0;
}

int cca_migrate_asymmetric(struct key *key, char **out, struct algo algo)
{

	long return_code, reason_code, exit_data_length, key_identifier_length;
	unsigned char *key_identifier;

	exit_data_length = 0;
	key_identifier_length = key->attr_len;

	key_identifier = calloc(1, key->attr_len);
	if (!key_identifier) {
		print_error("Malloc of %lu bytes failed!", key->attr_len);
		return 1;
	}
	memcpy(key_identifier, (char *)key->opaque_attr, key->attr_len);

	CSNDKTC(&return_code,
		&reason_code,
		&exit_data_length,
		NULL,
		&(algo.rule_array_count),
		algo.rule_array,
		&key_identifier_length,
		key_identifier);

	if (return_code != CCA_SUCCESS) {
		cca_error("CSNDKTC (Key Token Change)", return_code, reason_code);
		print_error("Migrating %s key failed. label=%s, handle=%lu",
			algo.name, key->label, key->handle);
		return 1;
	} else if (v_flag) {
		printf("Successfully migrated %s key. label=%s, handle=%lu\n",
			algo.name, key->label, key->handle);
	}

	*out = (char *)key_identifier;

	if (!memcmp((CK_BYTE *)key->opaque_attr, (CK_BYTE *)key_identifier, key_identifier_length))
		printf("Skipping, %s token is  wrapped with current master key. label=%s, handle=%lu\n", algo.name,
			key->label, key->handle);

	return 0;
}

int cca_migrate_symmetric(struct key *key, char **out, struct algo algo)
{

	long return_code, reason_code, exit_data_length;
	unsigned char *key_identifier;

	exit_data_length = 0;

	key_identifier = calloc(1, key->attr_len);
	if (!key_identifier) {
		print_error("Malloc of %lu bytes failed!", key->attr_len);
		return 1;
	}
	memcpy(key_identifier, (char *)key->opaque_attr, key->attr_len);

	CSNBKTC(&return_code,
		&reason_code,
		&exit_data_length,
		NULL,
		&(algo.rule_array_count),
		algo.rule_array,
		key_identifier);

	if (return_code != CCA_SUCCESS) {
		cca_error("CSNBKTC (Key Token Change)", return_code, reason_code);
		print_error("Migrating %s key failed. label=%s, handle=%lu",
			algo.name, key->label, key->handle);
		return 1;
	} else if (v_flag) {
		printf("Successfully migrated %s key. label=%s, handle=%lu\n",
			algo.name, key->label, key->handle);
	}

	*out = (char *)key_identifier;

	if (!memcmp((CK_BYTE *)key->opaque_attr, (CK_BYTE *)key_identifier, key->attr_len))
		printf("Skipping, %s token is  wrapped with current master key. label=%s, handle=%lu\n", algo.name,
			key->label, key->handle);
	return 0;
}

int cca_migrate_hmac(struct key *key, char **out, struct algo algo)
{

	long return_code, reason_code, exit_data_length, key_identifier_length;
	unsigned char *key_identifier;

	exit_data_length = 0;
	key_identifier_length = key->attr_len;

	key_identifier = calloc(1, key->attr_len);
	if (!key_identifier) {
		print_error("Malloc of %lu bytes failed!", key->attr_len);
		return 1;
	}
	memcpy(key_identifier, (char *)key->opaque_attr, key->attr_len);

	CSNBKTC2(&return_code,
		&reason_code,
		&exit_data_length,
		NULL,
		&(algo.rule_array_count),
		algo.rule_array,
		&key_identifier_length,
		key_identifier);

	if (return_code != CCA_SUCCESS) {
		cca_error("CSNBKTC2 (Key Token Change)", return_code, reason_code);
		print_error("Migrating %s key failed. label=%s, handle=%lu",
			algo.name, key->label, key->handle);
		return 1;
	} else if (v_flag) {
		printf("Successfully migrated %s key. label=%s, handle=%lu\n",
			algo.name, key->label, key->handle);
	}

	*out = (char *)key_identifier;

	if (!memcmp((CK_BYTE *)key->opaque_attr, (CK_BYTE *)key_identifier, key_identifier_length))
		printf("Skipping, %s token is  wrapped with current master key. label=%s, handle=%lu\n", algo.name,
			key->label, key->handle);

	return 0;
}

/* @keys: A linked list of data to migrate and the PKCS#11 handle for the
 * object in the data store.
 * @count: counter for number of keys migrated
 * @count_failed: counter for number of keys that failed to migrate
 */
int cca_migrate(struct key *keys, struct key_count *count,
	struct key_count *count_failed)
{
	struct key *key;
	char *migrated_data;
	int rc;

	for (key = keys; key; key = key->next) {
		migrated_data = NULL;

		switch(key->type) {
		case CKK_AES:
			rc = cca_migrate_symmetric(key, &migrated_data, aes);
			if (rc)
				count_failed->aes++;
			else
				count->aes++;
			break;
		case CKK_DES:
		case CKK_DES2:
		case CKK_DES3:
			rc = cca_migrate_symmetric(key, &migrated_data, des);
			if (rc)
				count_failed->des++;
			else
				count->des++;
			break;
		case CKK_EC:
			rc = cca_migrate_asymmetric(key, &migrated_data, ecc);
			if (rc)
				count_failed->ecc++;
			else
				count->ecc++;
			break;
		case CKK_GENERIC_SECRET:
			rc = cca_migrate_hmac(key, &migrated_data, hmac);
			if (rc)
				count_failed->hmac++;
			else
				count->hmac++;
			break;
		case CKK_RSA:
			rc = cca_migrate_asymmetric(key, &migrated_data, rsa);
			if (rc)
				count_failed->rsa++;
			else
				count->rsa++;
			break;
		}


		/* replace the original key with the migrated key*/
		if (!rc && migrated_data) {
			free(key->opaque_attr);
			key->opaque_attr = (CK_BYTE *)migrated_data;
		}
	}
	return 0;
}

int migrate_keytype(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE sess,
CK_KEY_TYPE *k_type, struct key_count *count, struct key_count *count_failed)
{
	struct key	*keys = NULL, *tmp, *to_free;
	int		rc;

	rc = find_wrapped_keys(funcs, sess, k_type, &keys);
	if (rc) {
		goto done;
	}
	rc = cca_migrate(keys, count, count_failed);
	if (rc) {
		goto done;
	}
	rc = replace_keys(funcs, sess, keys);
	if (rc) {
		goto done;
	}
done:
	for (to_free = keys; to_free; to_free = tmp) {
		tmp = to_free->next;
		free(to_free->opaque_attr);
		free(to_free);
	}

	return rc;
}

void key_migration_results(struct key_count migrated, struct key_count failed)
{
	if (migrated.aes || migrated.des || migrated.des2 || migrated.des3 ||
		migrated.ecc || migrated.hmac || migrated.rsa)
		printf("Successfully migrated: ");
	if (migrated.aes)
		printf("AES: %d. ", migrated.aes);
	if (migrated.des)
		printf("DES: %d. ", migrated.des);
	if (migrated.des2)
		printf("DES2: %d. ", migrated.des2);
	if (migrated.des3)
		printf("DES3: %d. ", migrated.des3);
	if (migrated.ecc)
		printf("ECC: %d. ", migrated.ecc);
	if (migrated.hmac)
		printf("HMAC: %d. ", migrated.hmac);
	if (migrated.rsa)
		printf("RSA: %d. ", migrated.rsa);

	if (failed.aes || failed.des || failed.des2 || failed.des3 ||
		failed.ecc || failed.hmac || failed.rsa)
		printf("\nFailed to migrate: ");
	if (failed.aes)
		printf("AES: %d. ", failed.aes);
	if (failed.des)
		printf("DES: %d. ", failed.des);
	if (failed.des2)
		printf("DES2: %d. ", failed.des2);
	if (failed.des3)
		printf("DES3: %d. ", failed.des3);
	if (failed.ecc)
		printf("ECC: %d. ", failed.ecc);
	if (failed.hmac)
		printf("HMAC: %d. ", failed.hmac);
	if (failed.rsa)
		printf("RSA: %d. ", failed.rsa);

	printf("\n");

}

int migrate_wrapped_keys(CK_SLOT_ID slot_id, char *userpin, int masterkey)
{
	CK_FUNCTION_LIST *funcs;
	CK_KEY_TYPE key_type = 0;
	CK_ULONG slot_count;
	CK_SESSION_HANDLE sess;
	CK_RV rv;
	struct key_count count = {0,0,0,0,0,0,0};
	struct key_count count_failed = {0,0,0,0,0,0,0};
	int exit_code = 0, rc;

	funcs = p11_init();
	if (!funcs) {
		return 2;
	}

	rv = funcs->C_GetSlotList(TRUE, NULL_PTR, &slot_count);
	if (rv != CKR_OK) {
		p11_error("C_GetSlotList" ,rv);
		exit_code = 3;
		goto finalize;
	}

	if (slot_id >= slot_count) {
		print_error("%lu is not a valid slot ID." , slot_id);
		exit_code = 4;
		goto finalize;
	}

	rv = funcs->C_OpenSession(slot_id, CKF_RW_SESSION|
				  CKF_SERIAL_SESSION,NULL_PTR,NULL_PTR,
				  &sess);
	if (rv != CKR_OK) {
		p11_error("C_OpenSession", rv);
		exit_code = 5;
		goto finalize;
	}

	rv = funcs->C_Login(sess, CKU_USER, (CK_BYTE *)userpin,
			    strlen(userpin));
	if (rv != CKR_OK) {
		p11_error("C_Login (USER)", rv);
		exit_code = 8;
		goto finalize;
	}

	switch(masterkey) {
	case MK_AES:
			if (v_flag)
				printf("Search for AES keys\n");
			key_type = CKK_AES;
			rc = migrate_keytype(funcs, sess, &key_type, &count,
				&count_failed);
			if (rc) {
				goto done;
			}
			if (v_flag)
				printf("Search for HMAC keys\n");
			key_type = CKK_GENERIC_SECRET;
			rc = migrate_keytype(funcs, sess, &key_type, &count,
				&count_failed);
			if (rc) {
				goto done;
			}
			break;
	case MK_APKA:
			if (v_flag)
				printf("Search for ECC keys\n");
			key_type = CKK_EC;
			rc = migrate_keytype(funcs, sess, &key_type, &count,
				&count_failed);
			if (rc) {
				goto done;
			}
			break;
	case MK_ASYM:
			if (v_flag)
				printf("Search for RSA keys\n");
			key_type = CKK_RSA;
			rc = migrate_keytype(funcs, sess, &key_type, &count,
				&count_failed);
			if (rc) {
				goto done;
			}
			break;
	case MK_SYM:
			if (v_flag)
				printf("Search for DES keys\n");
			key_type = CKK_DES;
			rc = migrate_keytype(funcs, sess, &key_type, &count,
				&count_failed);
			if (rc) {
				goto done;
			}
			if (v_flag)
				printf("Search for DES2 keys\n");
			key_type = CKK_DES2;
			rc = migrate_keytype(funcs, sess, &key_type, &count,
				&count_failed);
			if (rc) {
				goto done;
			}
			if (v_flag)
				printf("Search for DES3 keys\n");
			key_type = CKK_DES3;
			rc = migrate_keytype(funcs, sess, &key_type, &count,
				&count_failed);
			if (rc) {
				goto done;
			}
			break;
	default:
			print_error("unknown key type (%lu)\n", key_type);
			return -1;
	}

	key_migration_results(count, count_failed);

done:
	funcs->C_CloseSession(sess);
finalize:
	p11_fini(funcs);
	return exit_code;
}

int migrate_version(char *sopin, char *userpin, unsigned char *data_store)
{
	unsigned char masterkey[MASTER_KEY_SIZE];
	char fname[PATH_MAX];
	struct stat statbuf;
	int ret = 0;

	/* Verify that the data store is valid by looking for
	 * MK_SO, MK_USER, and TOK_OBJ/OBJ.IDX.
	 */
	memset(fname, 0, PATH_MAX);
	snprintf(fname, PATH_MAX, "%s/MK_SO", data_store);
	if (stat(fname, &statbuf) != 0) {
		fprintf(stderr, "Cannot find %s.\n", fname);
		ret = -1;
		goto done;
	}

	memset(fname, 0, PATH_MAX);
	snprintf(fname, PATH_MAX, "%s/MK_USER", data_store);
	if (stat(fname, &statbuf) != 0) {
		fprintf(stderr, "Cannot find %s.\n", fname);
		ret = -1;
		goto done;
	}

	memset(fname, 0, PATH_MAX);
	snprintf(fname, PATH_MAX, "%s/TOK_OBJ/OBJ.IDX", data_store);
	if (stat(fname, &statbuf) != 0) {
		fprintf(stderr, "Cannot find %s.\n", fname);
		ret = -1;
		goto done;
	}

	/* If the OBJ.IDX is empty, then no objects to migrate. */
	if (statbuf.st_size == 0) {
		printf("OBJ.IDX file is empty. Thus no objects to migrate.\n");
		goto done;
	}

	if (v_flag)
		printf("%s has an MK_SO, MK_USER and TOK/OBJ.IDX\n",
			data_store);
	/* Get the masterkey from MK_SO.
	 * This also helps verify that correct SO pin was entered.
	 */
	memset(masterkey, 0, MASTER_KEY_SIZE);
	memset(fname, 0, PATH_MAX);
	snprintf(fname, PATH_MAX, "%s/MK_SO", data_store);
	ret = load_masterkey(fname, sopin, masterkey);
	if (ret) {
		fprintf(stderr, "Could not load masterkey from MK_SO.\n");
		goto done;
	}

	if (v_flag)
		printf("Successfully verified SO Pin.\n");

	/* Get the masterkey from MK_USER.
	 * This also helps verift that correct USER pin was entered.
	 */
	memset(masterkey, 0, MASTER_KEY_SIZE);
	memset(fname, 0, PATH_MAX);
	snprintf(fname, PATH_MAX, "%s/MK_USER", data_store);
	ret = load_masterkey(fname, userpin, masterkey);
	if (ret) {
		fprintf(stderr, "Could not load masterkey from MK_USER.\n");
		goto done;
	}

	if (v_flag)
		printf("Successfully verified USER Pin.\n");

	/* Load all the private token objects and re-encrypt them
	 * using software des3, instead of CSNBENC.
	 */
	(void)load_private_token_objects(data_store, masterkey);
done:
	return ret;
}

void usage(char *progname)
{
	printf(" Help:\t\t\t\t%s -h\n", progname);
	printf(" -h\t\t\t\tShow this help\n\n");
	printf(" Migrate Object Version:\t%s -m v2objectsv3 [OPTIONS] \n", progname);
	printf(" -m v2objectsv3.\t\tMigrates CCA private token objects from");
	printf(" CCA\n\t\t\t\tencryption (used in v2) to software encryption");
	printf(" \n\t\t\t\t(used in v3). \n");
	printf(" Migrate Wrapped Keys:\t\t%s -m keys -s SLOTID -k KEYTYPE [OPTIONS] \n", progname);
	printf(" -m keys.\t\t\tUnwraps private keys with the");
	printf(" old CCA master\n\t\t\t\tkey and wraps them with the");
	printf(" new CCA master key\n");
	printf(" -s, --slotid SLOTID\t\tPKCS slot number\n");
	printf(" -k aes|apka|asym|sym\t\tMigrate selected keytype\n\n");
	printf(" Options:\n");
	printf(" -d, --datastore DATASTORE\tCCA token datastore location\n");
	printf(" -v, --verbose\t\t\tProvide more detailed output\n");
	printf(" \n\t\t\t\tthe migrated data\n\n");
	return;
}

int main(int argc, char **argv)
{
	int ret = 0, opt = 0, c_flag = 0, masterkey = 0;
	int data_store_len = 0;
	CK_SLOT_ID slot_id = 0;
	char *sopin = NULL, *userpin = NULL;
	size_t sopinlen, userpinlen;
	unsigned char *data_store = NULL;
	unsigned char *m_type = NULL;
	unsigned char *mk_type = NULL;
	void *lib_csulcca;

	int m_version = 0;
	int m_keys = 0;

	struct option long_opts[] = {
		{ "datastore", required_argument, NULL, 'd' },
		{ "slotid", required_argument, NULL, 's' },
		{ "verbose", no_argument, NULL, 'v' },
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "m:d:s:k:hv", long_opts, NULL))
		!= -1) {
		switch (opt) {
		case 'd':
			data_store = strdup(optarg);
			break;

		case 'h':
			usage(argv[0]);
			return 0;

		case 'k':
			mk_type = strdup(optarg);
			if (!memcmp(mk_type, "aes", 3))
				masterkey = MK_AES;
			else if (!memcmp(mk_type, "apka", 4))
				masterkey = MK_APKA;
			else if (!memcmp(mk_type, "asym", 4))
				masterkey = MK_ASYM;
			else if (!memcmp(mk_type, "sym", 3))
				masterkey = MK_SYM;
			else {
				print_error("unknown key type (%s)\n", mk_type);
				usage(argv[0]);
				return -1;
			}
			break;

		case 'm':
			m_type = strdup(optarg);
			if (!memcmp(m_type, "v2objectsv3", 11))
				m_version = 1;
			else if (!memcmp(m_type, "keys", 4))
				m_keys = 1;
			else {
				print_error("unknown migration type (%s)\n",
					m_type);
				usage(argv[0]);
				return -1;
			}
			break;

		case 's':
			c_flag++;
			slot_id = atoi(optarg);
			break;

		case 'v':
			v_flag++;
			break;

		default:
			usage(argv[0]);
			return -1;
		}
	}

	/* check for missing parameters */
	if (!m_version && !m_keys) {
		print_error("missing migration type\n");
		usage(argv[0]);
		return -1;
	}

	/* use default data_store if one is not given */
	if (data_store == NULL) {
		data_store_len = strlen(TOK_DATASTORE);
		data_store = malloc(data_store_len + 1);
		if (data_store == NULL) {
			fprintf(stderr, "malloc failed: %s\n",strerror(errno));
			return -1;
		}
		memset(data_store, 0, data_store_len + 1);
		memcpy(data_store, TOK_DATASTORE, data_store_len);
	}

	/* get the SO pin to authorize migration */
	printf("Enter the SO PIN: ");
	fflush(stdout);
	ret = get_pin(&sopin, &sopinlen);
	if (ret != 0) {
		print_error("Could not get SO PIN.\n");
		goto done;
	}

	/* get the USER pin to authorize migration */
	printf("Enter the USER PIN: ");
	fflush(stdout);
	ret = get_pin(&userpin, &userpinlen);
        if (ret != 0) {
		print_error("Could not get USER PIN.\n");
		goto done;
        }

	/* verify the SO and USER PINs entered. */
	ret = verify_pins(data_store, sopin, sopinlen, userpin, userpinlen);
	if (ret)
		goto done;

	lib_csulcca = dlopen(CCA_LIBRARY, (RTLD_GLOBAL | RTLD_NOW));
	if (lib_csulcca == NULL) {
		fprintf(stderr, "dlopen(%s) failed: %s\n", CCA_LIBRARY,
			strerror(errno));
		return -1;
	}

	if (m_version) {
		CSNBDEC = dlsym(lib_csulcca, "CSNBDEC");
		ret = migrate_version(sopin, userpin, data_store);
	}
	else if (m_keys) {
		if (!slot_id) {
			print_error("missing slot number\n");
			usage(argv[0]);
			return -1;
		}

		if (!masterkey) {
			print_error("missing key type\n");
			usage(argv[0]);
			return -1;
		}

		CSNDKTC = dlsym(lib_csulcca, "CSNDKTC");
		CSNBKTC = dlsym(lib_csulcca, "CSNBKTC");
		CSNBKTC2 = dlsym(lib_csulcca, "CSNBKTC2");
		ret = migrate_wrapped_keys(slot_id, userpin, masterkey);
	}
done:

	if (sopin)
		free(sopin);
	if (userpin)
		free(userpin);
	if (data_store)
		free(data_store);

	return ret;
}

char *
p11strerror(CK_RV rc)
{
        switch (rc) {
                case CKR_OK:
                        return "CKR_OK";
                case CKR_CANCEL:
                        return "CKR_CANCEL";
                case CKR_HOST_MEMORY:
                        return "CKR_HOST_MEMORY";
                case CKR_SLOT_ID_INVALID:
                        return "CKR_SLOT_ID_INVALID";
                case CKR_GENERAL_ERROR:
                        return "CKR_GENERAL_ERROR";
                case CKR_FUNCTION_FAILED:
                        return "CKR_FUNCTION_FAILED";
                case CKR_ARGUMENTS_BAD:
                        return "CKR_ARGUMENTS_BAD";
                case CKR_NO_EVENT:
                        return "CKR_NO_EVENT";
                case CKR_NEED_TO_CREATE_THREADS:
                        return "CKR_NEED_TO_CREATE_THREADS";
                case CKR_CANT_LOCK:
                        return "CKR_CANT_LOCK";
                case CKR_ATTRIBUTE_READ_ONLY:
                        return "CKR_ATTRIBUTE_READ_ONLY";
                case CKR_ATTRIBUTE_SENSITIVE:
                        return "CKR_ATTRIBUTE_SENSITIVE";
                case CKR_ATTRIBUTE_TYPE_INVALID:
                        return "CKR_ATTRIBUTE_TYPE_INVALID";
                case CKR_ATTRIBUTE_VALUE_INVALID:
                        return "CKR_ATTRIBUTE_VALUE_INVALID";
                case CKR_DATA_INVALID:
                        return "CKR_DATA_INVALID";
                case CKR_DATA_LEN_RANGE:
                        return "CKR_DATA_LEN_RANGE";
                case CKR_DEVICE_ERROR:
                        return "CKR_DEVICE_ERROR";
                case CKR_DEVICE_MEMORY:
                        return "CKR_DEVICE_MEMORY";
                case CKR_DEVICE_REMOVED:
                        return "CKR_DEVICE_REMOVED";
                case CKR_ENCRYPTED_DATA_INVALID:
                        return "CKR_ENCRYPTED_DATA_INVALID";
                case CKR_ENCRYPTED_DATA_LEN_RANGE:
                        return "CKR_ENCRYPTED_DATA_LEN_RANGE";
                case CKR_FUNCTION_CANCELED:
                        return "CKR_FUNCTION_CANCELED";
                case CKR_FUNCTION_NOT_PARALLEL:
                        return "CKR_FUNCTION_NOT_PARALLEL";
                case CKR_FUNCTION_NOT_SUPPORTED:
                        return "CKR_FUNCTION_NOT_SUPPORTED";
                case CKR_KEY_HANDLE_INVALID:
                        return "CKR_KEY_HANDLE_INVALID";
                case CKR_KEY_SIZE_RANGE:
                        return "CKR_KEY_SIZE_RANGE";
                case CKR_KEY_TYPE_INCONSISTENT:
                        return "CKR_KEY_TYPE_INCONSISTENT";
                case CKR_KEY_NOT_NEEDED:
                        return "CKR_KEY_NOT_NEEDED";
                case CKR_KEY_CHANGED:
                        return "CKR_KEY_CHANGED";
                case CKR_KEY_NEEDED:
                        return "CKR_KEY_NEEDED";
                case CKR_KEY_INDIGESTIBLE:
                        return "CKR_KEY_INDIGESTIBLE";
                case CKR_KEY_FUNCTION_NOT_PERMITTED:
                        return "CKR_KEY_FUNCTION_NOT_PERMITTED";
                case CKR_KEY_NOT_WRAPPABLE:
                        return "CKR_KEY_NOT_WRAPPABLE";
                case CKR_KEY_UNEXTRACTABLE:
                        return "CKR_KEY_UNEXTRACTABLE";
                case CKR_MECHANISM_INVALID:
                        return "CKR_MECHANISM_INVALID";
                case CKR_MECHANISM_PARAM_INVALID:
                        return "CKR_MECHANISM_PARAM_INVALID";
                case CKR_OBJECT_HANDLE_INVALID:
                        return "CKR_OBJECT_HANDLE_INVALID";
                case CKR_OPERATION_ACTIVE:
                        return "CKR_OPERATION_ACTIVE";
                case CKR_OPERATION_NOT_INITIALIZED:
                        return "CKR_OPERATION_NOT_INITIALIZED";
                case CKR_PIN_INCORRECT:
                        return "CKR_PIN_INCORRECT";
                case CKR_PIN_INVALID:
                        return "CKR_PIN_INVALID";
                case CKR_PIN_LEN_RANGE:
                        return "CKR_PIN_LEN_RANGE";
                case CKR_PIN_EXPIRED:
                        return "CKR_PIN_EXPIRED";
                case CKR_PIN_LOCKED:
                        return "CKR_PIN_LOCKED";
                case CKR_SESSION_CLOSED:
                        return "CKR_SESSION_CLOSED";
                case CKR_SESSION_COUNT:
                        return "CKR_SESSION_COUNT";
                case CKR_SESSION_HANDLE_INVALID:
                        return "CKR_SESSION_HANDLE_INVALID";
                case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
                        return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
                case CKR_SESSION_READ_ONLY:
                        return "CKR_SESSION_READ_ONLY";
                case CKR_SESSION_EXISTS:
                        return "CKR_SESSION_EXISTS";
                case CKR_SESSION_READ_ONLY_EXISTS:
                        return "CKR_SESSION_READ_ONLY_EXISTS";
                case CKR_SESSION_READ_WRITE_SO_EXISTS:
                        return "CKR_SESSION_READ_WRITE_SO_EXISTS";
                case CKR_SIGNATURE_INVALID:
                        return "CKR_SIGNATURE_INVALID";
                case CKR_SIGNATURE_LEN_RANGE:
                        return "CKR_SIGNATURE_LEN_RANGE";
                case CKR_TEMPLATE_INCOMPLETE:
                        return "CKR_TEMPLATE_INCOMPLETE";
                case CKR_TEMPLATE_INCONSISTENT:
                        return "CKR_TEMPLATE_INCONSISTENT";
                case CKR_TOKEN_NOT_PRESENT:
                        return "CKR_TOKEN_NOT_PRESENT";
                case CKR_TOKEN_NOT_RECOGNIZED:
                        return "CKR_TOKEN_NOT_RECOGNIZED";
                case CKR_TOKEN_WRITE_PROTECTED:
                        return "CKR_TOKEN_WRITE_PROTECTED";
                case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
                        return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
                case CKR_UNWRAPPING_KEY_SIZE_RANGE:
                        return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
                case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
                        return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
                case CKR_USER_ALREADY_LOGGED_IN:
                        return "CKR_USER_ALREADY_LOGGED_IN";
                case CKR_USER_NOT_LOGGED_IN:
                        return "CKR_USER_NOT_LOGGED_IN";
                case CKR_USER_PIN_NOT_INITIALIZED:
                        return "CKR_USER_PIN_NOT_INITIALIZED";
                case CKR_USER_TYPE_INVALID:
                        return "CKR_USER_TYPE_INVALID";
                case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
                        return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
                case CKR_USER_TOO_MANY_TYPES:
                        return "CKR_USER_TOO_MANY_TYPES";
                case CKR_WRAPPED_KEY_INVALID:
                        return "CKR_WRAPPED_KEY_INVALID";
                case CKR_WRAPPED_KEY_LEN_RANGE:
                        return "CKR_WRAPPED_KEY_LEN_RANGE";
                case CKR_WRAPPING_KEY_HANDLE_INVALID:
                        return "CKR_WRAPPING_KEY_HANDLE_INVALID";
                case CKR_WRAPPING_KEY_SIZE_RANGE:
                        return "CKR_WRAPPING_KEY_SIZE_RANGE";
                case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
                        return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
                case CKR_RANDOM_SEED_NOT_SUPPORTED:
                        return "CKR_RANDOM_SEED_NOT_SUPPORTED";
                case CKR_RANDOM_NO_RNG:
                        return "CKR_RANDOM_NO_RNG";
                case CKR_BUFFER_TOO_SMALL:
                        return "CKR_BUFFER_TOO_SMALL";
                case CKR_SAVED_STATE_INVALID:
                        return "CKR_SAVED_STATE_INVALID";
                case CKR_INFORMATION_SENSITIVE:
                        return "CKR_INFORMATION_SENSITIVE";
                case CKR_STATE_UNSAVEABLE:
                        return "CKR_STATE_UNSAVEABLE";
                case CKR_CRYPTOKI_NOT_INITIALIZED:
                        return "CKR_CRYPTOKI_NOT_INITIALIZED";
                case CKR_CRYPTOKI_ALREADY_INITIALIZED:
                        return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
                case CKR_MUTEX_BAD:
                        return "CKR_MUTEX_BAD";
                case CKR_MUTEX_NOT_LOCKED:
                        return "CKR_MUTEX_NOT_LOCKED";
                default:
                        return "UNKNOWN";
        }

        return "UNKNOWN";
}
