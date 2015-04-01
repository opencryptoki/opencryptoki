
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
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <pwd.h>

#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include "pkcs11/pkcs11types.h"
#include "pkcs11/stdll.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_specific.h"
#include "tok_spec_struct.h"
#include "trace.h"

#include "tpm_specific.h"

#ifdef DEBUG
void
openssl_print_errors()
{
	ERR_load_ERR_strings();
	ERR_load_crypto_strings();
	ERR_print_errors_fp(stderr);
}
#endif

RSA *
openssl_gen_key()
{
	RSA *rsa;
	int rc, counter = 0;
	char buf[32];

	token_specific_rng((CK_BYTE *)buf, 32);
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
				TRACE_DEVEL("Tried %d times to generate a "
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
openssl_write_key(RSA *rsa, char *filename, CK_BYTE *pPin)
{
	BIO *b = NULL;
	char loc[PATH_MAX];
	struct passwd *pw = NULL;

	errno = 0;
	if ((pw = getpwuid(getuid())) == NULL) {
		TRACE_ERROR("Error getting username: %s\n", strerror(errno));
		return -1;
	}

	sprintf(loc, "%s/%s/%s", pk_dir, pw->pw_name, filename);

	b = BIO_new_file(loc, "w");
	if (!b) {
		TRACE_ERROR("Error opening file for write: %s\n", loc);
		return -1;
	}

	if (!PEM_write_bio_RSAPrivateKey(b, rsa, EVP_aes_256_cbc(), NULL, 0, 0, pPin)) {
		BIO_free(b);
		TRACE_ERROR("Writing key %s to disk failed.\n", loc);
		DEBUG_openssl_print_errors();
		return -1;
	}

	BIO_free(b);

	if (util_set_file_mode(loc, (S_IRUSR|S_IWUSR))) {
		TRACE_ERROR("Setting file mode of %s failed\n", loc);
	}

	return 0;
}

CK_RV
openssl_read_key(char *filename, CK_BYTE *pPin, RSA **ret)
{
	BIO *b = NULL;
	RSA *rsa = NULL;
	char loc[PATH_MAX];
	struct passwd *pw = NULL;
	CK_RV rc = CKR_FUNCTION_FAILED;

	errno = 0;
	if ((pw = getpwuid(getuid())) == NULL) {
		TRACE_ERROR("Error getting username: %s\n", strerror(errno));
		return CKR_FUNCTION_FAILED;
	}

	sprintf(loc, "%s/%s/%s", pk_dir, pw->pw_name, filename);

	/* we can't allow a pin of NULL here, since openssl will try to prompt
	 * for a password in PEM_read_bio_RSAPrivateKey */
	if (pPin == NULL)
		return CKR_PIN_INCORRECT;

	b = BIO_new_file(loc, "r+");
	if (b == NULL) {
		TRACE_ERROR("Error opening file for read: %s\n", loc);
		return CKR_FILE_NOT_FOUND;
	}

	if ((rsa = PEM_read_bio_RSAPrivateKey(b, NULL, 0, pPin)) == NULL) {
		TRACE_ERROR("Reading key %s from disk failed.\n", loc);
		DEBUG_openssl_print_errors();
		if (ERR_GET_REASON(ERR_get_error()) == PEM_R_BAD_DECRYPT) {
			rc = CKR_PIN_INCORRECT;
		}
		BIO_free(b);
		return rc;
	}

	BIO_free(b);
	*ret = rsa;

	return CKR_OK;
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

	/* get one of the primes from the RSA object */
	if ((*size_p = BN_bn2bin(rsa->p, p)) <= 0) {
		DEBUG_openssl_print_errors();
		return -1;
	}

	return 0;
}

