
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

#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>

#include <tss/tss.h>

#include "pkcs11/pkcs11types.h"
#include "pkcs11/stdll.h"
#include "defs.h"
#include "host_defs.h"
#include "args.h"
#include "h_extern.h"
#include "tok_specific.h"
#include "tok_spec_struct.h"

#ifdef DEBUG
#define DEBUG_openssl_print_errors()	openssl_print_errors()
#else
#define DEBUG_openssl_print_errors()
#endif


/* retry count for generating software RSA keys */
#define KEYGEN_RETRY    5

void
openssl_print_errors()
{
	ERR_load_ERR_strings();
	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);
}

RSA *
openssl_gen_key()
{
	RSA *rsa;
	int rc, counter = 0;
	char buf[32];

	token_rng(buf, 32);
	RAND_seed(buf, 32);

regen_rsa_key:
	rsa = RSA_generate_key(2048, 65537, NULL, NULL);
	if (rsa == NULL) {
		fprintf(stderr, "Error generating user's RSA key\n");
		ERR_load_crypto_strings();
		ERR_print_errors_fp(stderr);
		return NULL;
	}

	rc = RSA_check_key(rsa);
	switch (rc) {
		case 0:
			/* rsa is not a valid RSA key */
			RSA_free(rsa);
			counter++;
			if (counter == KEYGEN_RETRY) {
				LogDebug("Tried %d times to generate a "
						"valid RSA key, failed.\n",
						KEYGEN_RETRY);
				return NULL;
			}
			goto regen_rsa_key;
			break;
		case 1:
			/* success case, rsa is a valid key */
			break;
		case -1:
			/* fall through */
		default:
			DEBUG_openssl_print_errors();
			break;
	}

	return rsa;
}

int
openssl_write_key(RSA *rsa, char *filename, char *pPin)
{
	BIO *b = BIO_new_file(filename, "w");

	if (!b) {
		LogError("%s: Error opening file for write: %s", __FUNCTION__, filename);
		return -1;
	}

	if (!PEM_write_bio_RSAPrivateKey(b, rsa, EVP_aes_256_cbc(), NULL, 0, 0, pPin)) {
		BIO_free(b);
		LogError("Writing key %s to disk failed.", filename);
		DEBUG_openssl_print_errors();
		return -1;
	}

	BIO_free(b);

	if (set_file_mode(filename, (S_IRUSR|S_IWUSR))) {
		LogError("Setting file mode of %s failed", filename);
	}

	return 0;
}

RSA *
openssl_read_key(char *filename, char *pPin)
{
	BIO *b;
	RSA *rsa = NULL;

	if (pPin == NULL)
		return NULL;

	b = BIO_new_file(filename, "r+");
	if (b == NULL) {
		LogError("%s: Error opening file for read: %s", __FUNCTION__, filename);
		return -1;
	}

	if ((rsa = PEM_read_bio_RSAPrivateKey(b, NULL, 0, pPin)) == NULL) {
		BIO_free(b);
		LogError("Reading key %s from disk failed.", filename);
		DEBUG_openssl_print_errors();
		return -1;
	}

	BIO_free(b);

	return rsa;
}

int
openssl_get_modulus_and_prime(RSA *rsa, unsigned int *size_n, unsigned char *n,
		unsigned int *size_p, unsigned char *p)
{
	/* get the modulus from the RSA object */
	if ((*size_n = BN_bn2bin(rsa->n, n)) <= 0) {
		DEBUG_openssl_print_errors();
		return -1;
	}

	if (*size_n > 2048/8) {
		LogError("rsa modulus too big! (%d)\n", *size_n);
		return -1;
	}

	/* get one of the primes from the RSA object */
	if ((*size_p = BN_bn2bin(rsa->p, p)) <= 0) {
		DEBUG_openssl_print_errors();
		return -1;
	}

	if (*size_p > 2048/8) {
		LogError("rsa prime too big! (%d)\n", *size_p);
		return -1;
	}

	return 0;
}

