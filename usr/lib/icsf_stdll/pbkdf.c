/*
 * COPYRIGHT (c) International Business Machines Corp. 2013-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <grp.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "pbkdf.h"
#include "trace.h"


CK_RV get_randombytes(unsigned char *output, int bytes)
{
    int ranfd;
    int rlen;
    int totallen = 0;

    ranfd = open("/dev/urandom", O_RDONLY);
    if (ranfd >= 0) {
        do {
            rlen = read(ranfd, output + totallen, bytes - totallen);
            if (rlen == -1) {
                close(ranfd);
                TRACE_ERROR("read failed: %s\n", strerror(errno));
                return CKR_FUNCTION_FAILED;
            }
            totallen += rlen;
        } while (totallen < bytes);
        close(ranfd);
        return CKR_OK;
    }

    return CKR_FUNCTION_FAILED;
}

CK_RV set_perms(int file)
{
    struct group *grp;

    if (fchmod(file, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) != 0) {
        TRACE_ERROR("fchmod failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    grp = getgrnam("pkcs11");
    if (grp) {
        if (fchown(file, -1, grp->gr_gid) != 0) {
            TRACE_ERROR("fchown failed: %s\n", strerror(errno));
            return CKR_FUNCTION_FAILED;
        }
    } else {
        TRACE_ERROR("getgrnam failed:%s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV encrypt_aes(CK_BYTE * inbuf, int inbuflen, CK_BYTE * dkey,
                  CK_BYTE * iv, CK_BYTE * outbuf, int *outbuflen)
{
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int tmplen;

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_EncryptInit_ex(ctx, cipher, NULL, dkey, iv);
    if (!EVP_EncryptUpdate(ctx, outbuf, outbuflen, inbuf, inbuflen)) {
        TRACE_ERROR("EVP_EncryptUpdate failed.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (!EVP_EncryptFinal_ex(ctx, outbuf + (*outbuflen), &tmplen)) {
        TRACE_ERROR("EVP_EncryptFinal failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    *outbuflen = (*outbuflen) + tmplen;
    EVP_CIPHER_CTX_free(ctx);

#else
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    EVP_EncryptInit_ex(&ctx, cipher, NULL, dkey, iv);
    if (!EVP_EncryptUpdate(&ctx, outbuf, outbuflen, inbuf, inbuflen)) {
        TRACE_ERROR("EVP_EncryptUpdate failed.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (!EVP_EncryptFinal_ex(&ctx, outbuf + (*outbuflen), &tmplen)) {
        TRACE_ERROR("EVP_EncryptFinal failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    *outbuflen = (*outbuflen) + tmplen;
    EVP_CIPHER_CTX_cleanup(&ctx);
#endif

    return CKR_OK;
}

CK_RV decrypt_aes(CK_BYTE * inbuf, int inbuflen, CK_BYTE * dkey,
                  CK_BYTE * iv, CK_BYTE * outbuf, int *outbuflen)
{
    int size;
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();

#if OPENSSL_VERSION_NUMBER >= 0x10100000L
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

    EVP_DecryptInit_ex(ctx, cipher, NULL, dkey, iv);
    if (!EVP_DecryptUpdate(ctx, outbuf, outbuflen, inbuf, inbuflen)) {
        TRACE_ERROR("EVP_DecryptUpdate failed.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (!EVP_DecryptFinal_ex(ctx, outbuf + (*outbuflen), &size)) {
        TRACE_ERROR("EVP_DecryptFinal failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* total length of the decrypted data */
    *outbuflen = (*outbuflen) + size;

    /* EVP_DecryptFinal removes any padding. The final length
     * is the length of the decrypted data without padding.
     */

    EVP_CIPHER_CTX_free(ctx);

#else
    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);

    EVP_DecryptInit_ex(&ctx, cipher, NULL, dkey, iv);
    if (!EVP_DecryptUpdate(&ctx, outbuf, outbuflen, inbuf, inbuflen)) {
        TRACE_ERROR("EVP_DecryptUpdate failed.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (!EVP_DecryptFinal_ex(&ctx, outbuf + (*outbuflen), &size)) {
        TRACE_ERROR("EVP_DecryptFinal failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* total length of the decrypted data */
    *outbuflen = (*outbuflen) + size;

    /* EVP_DecryptFinal removes any padding. The final length
     * is the length of the decrypted data without padding.
     */

    EVP_CIPHER_CTX_cleanup(&ctx);
#endif

    return CKR_OK;
}

CK_RV get_masterkey(CK_BYTE *pin, CK_ULONG pinlen, const char *fname,
                    CK_BYTE *masterkey, int *len)
{
    struct stat statbuf;
    FILE *fp;
    CK_ULONG_32 totallen, datasize, readsize;
    int dkeysize;
    CK_BYTE salt[SALTSIZE];
    CK_BYTE dkey[AES_KEY_SIZE_256];
    CK_BYTE outbuf[ENCRYPT_SIZE];
    CK_RV rc = CKR_OK;
    size_t ret;

    /* see if the file exists */
    if ((stat(fname, &statbuf) < 0) && (errno == ENOENT)) {
        TRACE_ERROR("stat() failed: File does not exist.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* open the file */
    fp = fopen(fname, "r");
    if (fp == NULL) {
        TRACE_ERROR("fopen failed\n");
        return CKR_FUNCTION_FAILED;
    }

    ret = fread(&totallen, sizeof(CK_ULONG_32), 1, fp);
    if (ret != 1) {
        fclose(fp);
        TRACE_ERROR("fread failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    ret = fread(salt, SALTSIZE, 1, fp);
    if (ret != 1) {
        fclose(fp);
        TRACE_ERROR("fread failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* get length of encryted data */
    datasize = totallen - SALTSIZE;
    readsize = fread(outbuf, datasize, 1, fp);
    if (readsize != 1) {
        TRACE_ERROR("Could not get encrypted data in %s.\n", fname);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    fclose(fp);

    /* now derive the key using the salt and PIN */
    dkeysize = AES_KEY_SIZE_256;
    rc = pbkdf(pin, pinlen, salt, dkey, dkeysize);
    if (rc != CKR_OK) {
        TRACE_DEBUG("pbkdf(): Failed to derive a key.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* decrypt the masterkey */
    /* re-use salt for iv */
    rc = decrypt_aes(outbuf, datasize, dkey, salt, masterkey, len);
    if (rc != CKR_OK) {
        TRACE_DEBUG("Failed to decrypt the racf pwd.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* make sure len is equal to our masterkey size. */
    if (*len != AES_KEY_SIZE_256) {
        TRACE_ERROR("Decrypted key is invalid.\n");
        return CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV get_racf(CK_BYTE * masterkey, CK_ULONG mklen, CK_BYTE * racfpwd,
               int *racflen)
{
    struct stat statbuf;
    CK_BYTE outbuf[ENCRYPT_SIZE];
    CK_BYTE iv[AES_INIT_VECTOR_SIZE];
    int len, datasize, readsize;
    FILE *fp;
    CK_RV rc;

    UNUSED(mklen);

    /* see if the file exists ... */
    if ((stat(RACFFILE, &statbuf) < 0) && (errno == ENOENT)) {
        TRACE_ERROR("File does not exist.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* if file exists, open it */
    fp = fopen(RACFFILE, "r");
    if (fp == NULL) {
        TRACE_ERROR("fopen failed\n");
        return CKR_FUNCTION_FAILED;
    }

    readsize = fread(&len, sizeof(CK_ULONG_32), 1, fp);
    if (readsize != 1) {
        TRACE_ERROR("fread failed\n");
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    readsize = fread(iv, AES_INIT_VECTOR_SIZE, 1, fp);
    if (readsize != 1) {
        TRACE_ERROR("fread failed\n");
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    /* get length of encryted data */
    datasize = len - AES_INIT_VECTOR_SIZE;
    readsize = fread(outbuf, datasize, 1, fp);
    if (readsize != 1) {
        TRACE_ERROR("Could not get encrypted data in %s.\n", RACFFILE);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }
    fclose(fp);

    /* decrypt the data using the masterkey */
    rc = decrypt_aes(outbuf, datasize, masterkey, iv, racfpwd, racflen);

    /* terminate the decrypted string. */
    memset(racfpwd + (*racflen), 0, 1);

    if (rc != CKR_OK) {
        TRACE_DEBUG("Failed to decrypt the racf pwd.\n");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV pbkdf(CK_BYTE *password, CK_ULONG len, CK_BYTE *salt, CK_BYTE *dkey,
            CK_ULONG klen)
{
    int rc;

    if (!password || !salt || len > INT_MAX || klen > INT_MAX) {
        TRACE_ERROR("Invalid function argument(s).\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = PKCS5_PBKDF2_HMAC((char *)password, len, salt, SALTSIZE,
                            ITERATIONS, EVP_sha256(), klen, dkey);
    if (rc != 1) {
        TRACE_ERROR("PBKDF2 failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV secure_racf(CK_BYTE * racf, CK_ULONG racflen, CK_BYTE * key,
                  CK_ULONG keylen)
{
    CK_RV rc = CKR_OK;
    CK_BYTE iv[AES_INIT_VECTOR_SIZE];
    FILE *fp;
    CK_BYTE output[ENCRYPT_SIZE];
    CK_ULONG_32 totallen;
    int outputlen;

    UNUSED(keylen);

    /* generate an iv... */
    if ((get_randombytes(iv, AES_INIT_VECTOR_SIZE)) != CKR_OK) {
        TRACE_DEBUG("Could not generate an iv.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* encrypt the racf passwd using the masterkey */
    rc = encrypt_aes(racf, racflen, key, iv, output, &outputlen);
    if (rc != 0) {
        TRACE_DEBUG("Failed to encrypt racf pwd.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* store the following in the RACF file:
     * 1. total length = v + encrypted data
     * 2. iv
     * 3. encrypted data
     */

    /* get the total length */
    totallen = outputlen + AES_INIT_VECTOR_SIZE;

    fp = fopen(RACFFILE, "w");
    if (!fp) {
        TRACE_ERROR("fopen failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    /* set permisions on the file */
    rc = set_perms(fileno(fp));
    if (rc != 0) {
        TRACE_ERROR("Failed to set permissions on RACF file.\n");
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    /* write the info to the file */
    (void) fwrite(&totallen, sizeof(CK_ULONG_32), 1, fp);
    (void) fwrite(iv, AES_INIT_VECTOR_SIZE, 1, fp);
    (void) fwrite(output, outputlen, 1, fp);

    fclose(fp);

    return rc;
}

CK_RV secure_masterkey(CK_BYTE * masterkey, CK_ULONG len, CK_BYTE * pin,
                       CK_ULONG pinlen, const char *fname)
{
    CK_RV rc = CKR_OK;
    CK_BYTE salt[SALTSIZE];
    CK_BYTE dkey[AES_KEY_SIZE_256];
    CK_ULONG_32 totallen, dkey_size;
    int outputlen;
    CK_BYTE output[ENCRYPT_SIZE];
    FILE *fp;

    memset(salt, 0, SALTSIZE);
    memset(dkey, 0, AES_KEY_SIZE_256);
    dkey_size = AES_KEY_SIZE_256;

    /* get a salt for the password based key derivation function. */
    if ((get_randombytes(salt, SALTSIZE)) != CKR_OK) {
        TRACE_DEBUG("Could not get a salt for pbkdf.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* get a 32 byte key */
    rc = pbkdf(pin, pinlen, salt, dkey, dkey_size);
    if (rc != 0) {
        TRACE_DEBUG("Failed to derive a key for encryption.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* encrypt the masterkey using the derived key */
    /* re-use the salt for the iv... */
    rc = encrypt_aes(masterkey, len, dkey, salt, output, &outputlen);
    if (rc != 0) {
        TRACE_DEBUG("Failed to encrypt masterkey.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* write the encrypted masterkey to named file */
    /* store the following:
     * 1. total length = salt + encrypted data
     * 2. salt (always SALTSIZE)
     * 3. encrypted data
     */

    /* get the total length */
    totallen = outputlen + SALTSIZE;

    fp = fopen(fname, "w");
    if (!fp) {
        TRACE_ERROR("fopen failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    /* set permisions on the file */
    rc = set_perms(fileno(fp));
    if (rc != 0) {
        TRACE_ERROR("Failed to set permissions on encrypted file.\n");
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    /* write the info to the file */
    (void) fwrite(&totallen, sizeof(CK_ULONG_32), 1, fp);
    (void) fwrite(salt, SALTSIZE, 1, fp);
    (void) fwrite(output, outputlen, 1, fp);

    fclose(fp);

    return rc;
}
