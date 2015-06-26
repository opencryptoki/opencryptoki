/*
 * Licensed materials - Property of IBM
 *
 * pkcscca - A tool for PKCS#11 CCA token. 
 * Currently, only migrates CCA private token objects from CCA cipher
 * to using a software cipher.
 *
 *
 * Copyright (C) International Business Machines Corp. 2014
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <getopt.h>
#include <termios.h>
#include <dlfcn.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/limits.h>
#include <openssl/evp.h>
#include <pkcs11types.h>

#include "sw_crypt.h"
#include "pkcscca.h"

void (*CSNBDEC)();
int v_flag = 0;

int compute_hash(int hash_type, int buf_size, char *buf, char *digest)
{
	EVP_MD_CTX md_ctx;
	unsigned int result_size;
	int rc;

	switch (hash_type) {
	case HASH_SHA1:
		rc = EVP_DigestInit(&md_ctx, EVP_sha1());
		break;
	case HASH_MD5:
		rc = EVP_DigestInit(&md_ctx, EVP_md5());
		break;
	default:
		return -1;
	break;
	}

	if (rc != 1) {
		fprintf(stderr, "EVP_DigestInit() failed: rc = %d\n", rc);
		return -1;
	}

        rc = EVP_DigestUpdate(&md_ctx, buf, buf_size);
        if (rc != 1) {
		fprintf(stderr, "EVP_DigestUpdate() failed: rc = %d\n", rc);
		return -1;
        }

	result_size = EVP_MD_CTX_size(&md_ctx);
	rc = EVP_DigestFinal(&md_ctx, (unsigned char *)digest, &result_size);
        if (rc != 1) {
		fprintf(stderr, "EVP_DigestFinal() failed: rc = %d\n", rc);
		return -1;
        }

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

	while (!feof(fp1)) {
		(void)fgets((char *)tmp, 50, fp1);
		if (!feof(fp1)) {
			tmp[strlen((char *)tmp) - 1] = 0;

			snprintf((char *)fname, sizeof(fname), "%s/TOK_OBJ/",
				 data_store);
			strcat((char *)fname, (char *)tmp);

			fp2 = fopen((char *)fname, "r");
			if (!fp2)
				continue;

			fread(&size, sizeof(unsigned int), 1, fp2);
			fread(&priv, sizeof(CK_BBOOL), 1, fp2);
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
		fprintf(stderr, "Could not open %s: %s\n", mkfile,
			strerror(errno));
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
		fprintf(stderr, "Could not read %s: %s\n", mkfile,
			strerror(errno));
                ret = -1;
                goto done;
        }

	/* decrypt the masterkey */

	ret = compute_md5(pin, strlen(pin), pin_md5_hash);
	if (ret) {
		fprintf(stderr, "Error calculating MD5 of PIN!\n");
		goto done;
	}

	memcpy(des3_key, pin_md5_hash, MD5_HASH_SIZE);
	memcpy(des3_key + MD5_HASH_SIZE, pin_md5_hash, DES_KEY_SIZE);

	rc = sw_des3_cbc_decrypt(cipher, cipher_len, clear, &clear_len,
                                 (unsigned char *)"12345678", des3_key);
	if (rc != CKR_OK) {
		fprintf(stderr, "Error decrypting master key file after read");
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
		fprintf(stderr, "Failed to compute sha for masterkey.\n");
                goto done;
        }

        if (memcmp(hash_sha, clear + MASTER_KEY_SIZE, SHA1_HASH_SIZE) != 0) {
		fprintf(stderr, "%s appears to have been tampered!\n", mkfile);
		fprintf(stderr, "Cannot migrate.\n");
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
		fprintf(stderr, "Could not open %s: %s\n", fname,
			strerror(errno));
		return -1;
	}

	ret = fread(&td, sizeof(TOKEN_DATA), 1, fp);
	if (ret != 1) {
		fprintf(stderr, "Could not read %s: %s\n", fname,
			strerror(errno));
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
			fprintf(stderr, "Failed to compute sha for SO.\n");
			goto done;
		}

		if (memcmp(td.so_pin_sha, pin_sha, SHA1_HASH_SIZE) != 0) {
			fprintf(stderr, "SO PIN is incorrect.\n");
			ret = -1;
			goto done;
		}
	}

	if (userpin != NULL) {
		ret = compute_sha1(userpin, userpinlen, pin_sha);
		if (ret) {
			fprintf(stderr, "Failed to compute sha for USER.\n");
			goto done;
		}

		if (memcmp(td.user_pin_sha, pin_sha, SHA1_HASH_SIZE) != 0) {
			fprintf(stderr, "USER PIN is incorrect.\n");
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

void usage(char *progname)
{
	printf("usage:\t%s -h | -m v2objectsv3 [OPTIONS] \n", progname);
	printf(" -h\t\t\t\tshow this help\n");
	printf(" -m=migration_type\t\tCurrently the only type of CCA ");
	printf("migration\n\t\t\t\tsupported is v2objectsv3. v2objectsv3 ");
	printf("migrates\n\t\t\t\tCCA private token objects from CCA ");
	printf("encryption\n\t\t\t\t(used in v2)to software encryption ");
	printf("(used in v3). \n\n");
	printf("Migrate options (with -m v2objectsv3):\n");
	printf(" -d, --datastore=DIRECTORY\tCCA token datastore location\n");
	printf(" -v, --verbose\t\t\tprovide more detailed output\n");

	return;
}

int main(int argc, char **argv)
{
	int ret = 0, opt;
	char *sopin = NULL, *userpin = NULL;
	size_t sopinlen, userpinlen;
	unsigned char masterkey[MASTER_KEY_SIZE];
	unsigned char *data_store = NULL;
	unsigned char *m_type = NULL;
	int data_store_len;
	char fname[PATH_MAX];
	struct stat statbuf;
	void *lib_csulcca;

	struct option long_opts[] = {
		{ "datastore", required_argument, NULL, 'd' },
		{ "verbose", no_argument, NULL, 'v'},
		{ 0, 0, 0, 0 }
	};

	while ((opt = getopt_long(argc, argv, "d:m:hv", long_opts, NULL)) != -1) {
		switch (opt) {
		case 'd':
			data_store = strdup(optarg);
			break;

		case 'h':
			usage(argv[0]);
			return 0;

		case 'm':
			m_type = strdup(optarg);
			break;

		case 'v':
			v_flag++;
			break;

		default:
			usage(argv[0]);
			return -1;
		}
	}

	if (m_type) {
		if (memcmp(m_type, "v2objectsv3", strlen("v2objectsv3"))) {
			fprintf(stderr, "unknown migration type\n");
			usage(argv[0]);
			return -1;
		}
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

	/* get the SO pin to authorize migration */
	printf("Enter the SO PIN: ");
	fflush(stdout);
	ret = get_pin(&sopin, &sopinlen);
        if (ret != 0) {
		fprintf(stderr, "Could not get SO PIN.\n");
		goto done;
        }

	/* get the USER pin to authorize migration */
	printf("Enter the USER PIN: ");
	fflush(stdout);
	ret = get_pin(&userpin, &userpinlen);

        if (ret != 0) {
		fprintf(stderr, "Could not get USER PIN.\n");
		goto done;
        }

	/* Verify the SO and USER PINs entered. */
	ret = verify_pins(data_store, sopin, sopinlen, userpin, userpinlen);
	if (ret)
		goto done;

	lib_csulcca = dlopen(CCA_LIBRARY, (RTLD_GLOBAL | RTLD_NOW));
	if (lib_csulcca == NULL) {
		fprintf(stderr, "dlopen(%s) failed: %s\n", CCA_LIBRARY,
			strerror(errno));
		return -1;
	}

	CSNBDEC = dlsym(lib_csulcca, "CSNBDEC");

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

	if (sopin)
		free(sopin);
	if (userpin)
		free(userpin);
	if (data_store)
		free(data_store);

	return ret;
}
