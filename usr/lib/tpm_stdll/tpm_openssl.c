/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
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
#include <openssl/evp.h>

#include <tss/platform.h>
#include <tss/tss_defines.h>
#include <tss/tss_typedef.h>
#include <tss/tss_structs.h>
#include <tss/tss_error.h>
#include <tss/tspi.h>

#include "pkcs11types.h"
#include "stdll.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_specific.h"
#include "tok_spec_struct.h"
#include "trace.h"

#include "tpm_specific.h"

/*
 * In order to make opencryptoki compatible with
 * OpenSSL 1.1 API Changes and backward compatible
 * we need to check for its version
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OLDER_OPENSSL
#endif

#ifdef DEBUG
void openssl_print_errors()
{
    ERR_load_ERR_strings();
    ERR_load_crypto_strings();
    ERR_print_errors_fp(stderr);
}
#endif

RSA *openssl_gen_key(STDLL_TokData_t *tokdata)
{
    RSA *rsa = NULL;
    int rc = 0, counter = 0;
    char buf[32];
#ifndef OLDER_OPENSSL
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    BIGNUM *bne = NULL;
#endif

    token_specific_rng(tokdata, (CK_BYTE *) buf, 32);
    RAND_seed(buf, 32);

regen_rsa_key:
#ifdef OLDER_OPENSSL
    rsa = RSA_generate_key(2048, 65537, NULL, NULL);
    if (rsa == NULL) {
        fprintf(stderr, "Error generating user's RSA key\n");
        ERR_load_crypto_strings();
        ERR_print_errors_fp(stderr);
        goto err;
    }

    rc = RSA_check_key(rsa);
#else
    bne = BN_new();
    rc = BN_set_word(bne, 65537);
    if (!rc) {
        fprintf(stderr, "Error generating bne\n");
        ERR_load_crypto_strings();
        ERR_print_errors_fp(stderr);
        goto err;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (ctx == NULL)
        goto err;

    if (EVP_PKEY_keygen_init(ctx) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0
        || EVP_PKEY_CTX_set_rsa_keygen_pubexp(ctx, bne) <= 0
        || EVP_PKEY_keygen(ctx, &pkey) <= 0
        || (rsa = EVP_PKEY_get1_RSA(pkey)) == NULL) {
        fprintf(stderr, "Error generating user's RSA key\n");
        ERR_load_crypto_strings();
        ERR_print_errors_fp(stderr);
        goto err;
    }
#if OPENSSL_VERSION_NUMBER < 0x10101000L
    rc = RSA_check_key(rsa);
#else
    rc = EVP_PKEY_check(ctx) == 1 ? 1 : 0;
#endif
#endif
    switch (rc) {
    case 0:
        /* rsa is not a valid RSA key */
        RSA_free(rsa);
        counter++;
        if (counter == KEYGEN_RETRY) {
            TRACE_DEVEL("Tried %d times to generate a "
                        "valid RSA key, failed.\n", KEYGEN_RETRY);
            goto err;
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

#ifndef OLDER_OPENSSL
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (bne != NULL)
        BN_free(bne);
#endif
    return rsa;
err:
    if (rsa != NULL)
        RSA_free(rsa);
#ifndef OLDER_OPENSSL
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (bne != NULL)
        BN_free(bne);
#endif
    return NULL;
}

int openssl_write_key(STDLL_TokData_t * tokdata, RSA * rsa, char *filename,
                      CK_BYTE * pPin)
{
    BIO *b = NULL;
    char loc[PATH_MAX];
    struct passwd *pw = NULL;

    errno = 0;
    if ((pw = getpwuid(getuid())) == NULL) {
        TRACE_ERROR("Error getting username: %s\n", strerror(errno));
        return -1;
    }

    if (ock_snprintf(loc, PATH_MAX, "%s/%s/%s",
                        tokdata->pk_dir, pw->pw_name, filename) != 0) {
        TRACE_ERROR("key path too long\n");
        return -1;
    }

    b = BIO_new_file(loc, "w");
    if (!b) {
        TRACE_ERROR("Error opening file for write: %s\n", loc);
        return -1;
    }

    if (!PEM_write_bio_RSAPrivateKey(b, rsa,
                                     EVP_aes_256_cbc(), NULL, 0, 0, pPin)) {
        BIO_free(b);
        TRACE_ERROR("Writing key %s to disk failed.\n", loc);
        DEBUG_openssl_print_errors();
        return -1;
    }

    BIO_free(b);

    if (util_set_file_mode(loc, (S_IRUSR | S_IWUSR))) {
        TRACE_ERROR("Setting file mode of %s failed\n", loc);
    }

    return 0;
}

CK_RV openssl_read_key(STDLL_TokData_t * tokdata, char *filename,
                       CK_BYTE * pPin, RSA ** ret)
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

    if (ock_snprintf(loc, PATH_MAX, "%s/%s/%s",
                     tokdata->pk_dir, pw->pw_name, filename) != 0) {
        TRACE_ERROR("key file name too long\n");
        return CKR_FUNCTION_FAILED;
    }

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

int openssl_get_modulus_and_prime(RSA * rsa, unsigned int *size_n,
                                  unsigned char *n, unsigned int *size_p,
                                  unsigned char *p)
{
#ifndef OLDER_OPENSSL
    const BIGNUM *n_tmp, *p_tmp;
#endif

    /* get the modulus from the RSA object */
#ifdef OLDER_OPENSSL
    if ((*size_n = BN_bn2bin(rsa->n, n)) <= 0) {
#else
    RSA_get0_key(rsa, &n_tmp, NULL, NULL);
    if ((*size_n = BN_bn2bin(n_tmp, n)) <= 0) {
#endif
        DEBUG_openssl_print_errors();
        return -1;
    }

    /* get one of the primes from the RSA object */
#ifdef OLDER_OPENSSL
    if ((*size_p = BN_bn2bin(rsa->p, p)) <= 0) {
#else
    RSA_get0_factors(rsa, &p_tmp, NULL);
    if ((*size_p = BN_bn2bin(p_tmp, p)) <= 0) {
#endif
        DEBUG_openssl_print_errors();
        return -1;
    }

    return 0;
}
