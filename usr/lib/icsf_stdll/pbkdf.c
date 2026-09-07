/*
 * COPYRIGHT (c) International Business Machines Corp. 2013-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

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
#include "platform.h"

/*
 * Local AES-256 Key Wrap / Unwrap (RFC 3394) helpers.
 * These mirror aes_256_wrap/aes_256_unwrap from pkcs_utils.c but are
 * self-contained here to avoid pulling in the full pkcs_utils.c into
 * the ICSF stdll build (pkcs_utils.c uses OCK_TOOL tracing).
 */
static CK_RV icsf_aes_256_wrap(unsigned char out[40],
                                const unsigned char in[32],
                                const unsigned char kek[32])
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0, finaln = 0;
    CK_RV rc = CKR_FUNCTION_FAILED;
    unsigned char buf[40 + EVP_MAX_BLOCK_LENGTH];

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        TRACE_ERROR("EVP_CIPHER_CTX_new failed.\n");
        return CKR_HOST_MEMORY;
    }
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_CipherInit_ex(ctx, EVP_aes_256_wrap(), NULL, kek, NULL, 1) != 1
        || EVP_CipherUpdate(ctx, buf, &outlen, in, 32) != 1
        || EVP_CipherFinal_ex(ctx, buf + outlen, &finaln) != 1) {
        TRACE_ERROR("AES-256 key wrap failed.\n");
        goto done;
    }
    memcpy(out, buf, 40);
    rc = CKR_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(buf, sizeof(buf));
    return rc;
}

static CK_RV icsf_aes_256_unwrap(unsigned char key[32],
                                  const unsigned char in[40],
                                  const unsigned char kek[32])
{
    EVP_CIPHER_CTX *ctx;
    int outlen = 0, finaln = 0;
    CK_RV rc = CKR_FUNCTION_FAILED;
    unsigned char buf[32 + EVP_MAX_BLOCK_LENGTH];

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        TRACE_ERROR("EVP_CIPHER_CTX_new failed.\n");
        return CKR_HOST_MEMORY;
    }
    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);
    if (EVP_CipherInit_ex(ctx, EVP_aes_256_wrap(), NULL, kek, NULL, 0) != 1
        || EVP_CipherUpdate(ctx, buf, &outlen, in, 40) != 1
        || EVP_CipherFinal_ex(ctx, buf + outlen, &finaln) != 1) {
        TRACE_ERROR("AES-256 key unwrap failed.\n");
        goto done;
    }
    memcpy(key, buf, 32);
    rc = CKR_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(buf, sizeof(buf));
    return rc;
}

/*
 * Local AES-256-GCM unseal (decrypt + verify tag).
 * Mirrors aes_256_gcm_seal from pkcs_utils.c but is self-contained here.
 *
 * @out      plaintext output buffer (at least inlen bytes)
 * @tag      expected 16-byte GCM authentication tag
 * @aad/@aadlen  additional authenticated data
 * @in/@inlen    ciphertext
 * @key      32-byte AES key
 * @iv       12-byte GCM nonce
 *
 * Returns CKR_OK on success, CKR_FUNCTION_FAILED if tag verification fails.
 */
static CK_RV icsf_aes_256_gcm_unseal(unsigned char *out,
                                      const unsigned char tag[16],
                                      const unsigned char *aad, size_t aadlen,
                                      const unsigned char *in, size_t inlen,
                                      const unsigned char key[32],
                                      const unsigned char iv[12])
{
    EVP_CIPHER_CTX *ctx;
    int aad_len = 0, outlen = 0, finaln = 0;
    CK_RV rc = CKR_FUNCTION_FAILED;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        TRACE_ERROR("EVP_CIPHER_CTX_new failed.\n");
        return CKR_HOST_MEMORY;
    }

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, -1) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1
        || EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 0) != 1
        || EVP_CipherUpdate(ctx, NULL, &aad_len, aad, aadlen) != 1
        || EVP_CipherUpdate(ctx, out, &outlen, in, inlen) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                               (void *)tag) != 1
        || EVP_CipherFinal_ex(ctx, out + outlen, &finaln) != 1) {
        TRACE_ERROR("AES-256-GCM unseal failed (bad tag or data).\n");
        goto done;
    }
    rc = CKR_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

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

CK_RV set_perms(int file, const char *group)
{
    struct stat sb;
    struct group *grp;

    if (group == NULL || group[0] == '\0')
        group = PKCS_GROUP;

    if (fstat(file, &sb) != 0) {
        TRACE_DEVEL("fstat failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    grp = getgrnam(group);
    if (grp == NULL) {
        TRACE_DEVEL("getgrnam(%s) failed: %s\n", group, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    /* Set absolute permissions or rw-rw----, if not already as expected */
    if ((sb.st_mode & ~S_IFMT) != (S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP)) {
        if (fchmod(file, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP) != 0) {
            TRACE_DEVEL("fchmod(rw-rw----) failed: %s\n", strerror(errno));
            return CKR_FUNCTION_FAILED;
        }
    }

    /* set ownership to pkcs11 group, if not already as expected */
    if (sb.st_gid != grp->gr_gid) {
        if (fchown(file, -1, grp->gr_gid) != 0) {
            TRACE_DEVEL("fchown(-1, %s) failed: %s\n", group,
                         strerror(errno));
            return CKR_FUNCTION_FAILED;
        }
    }

    return CKR_OK;
}

CK_RV encrypt_aes(STDLL_TokData_t *tokdata,
                  CK_BYTE * inbuf, int inbuflen, CK_BYTE * dkey,
                  CK_BYTE * iv, CK_BYTE * outbuf, int *outbuflen,
                  CK_BBOOL wrap)
{
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int block_size = EVP_CIPHER_block_size(cipher);
    CK_RV rc = CKR_FUNCTION_FAILED;
    int partlen, tmplen;
    EVP_CIPHER_CTX *ctx;

    if (*outbuflen < inbuflen + block_size) {
        TRACE_ERROR("Output buffer too small for encrypt_aes "
                    "(need %d, have %d).\n", inbuflen + block_size, *outbuflen);
        return CKR_BUFFER_TOO_SMALL;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("EVP_CIPHER_CTX_new failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, dkey, iv)) {
        TRACE_ERROR("EVP_EncryptInit_ex failed.\n");
        goto done;
    }
    partlen = 0;
    if (!EVP_EncryptUpdate(ctx, outbuf, &partlen, inbuf, inbuflen)) {
        TRACE_ERROR("EVP_EncryptUpdate failed.\n");
        goto done;
    }
    tmplen = 0;
    if (!EVP_EncryptFinal_ex(ctx, outbuf + partlen, &tmplen)) {
        TRACE_ERROR("EVP_EncryptFinal failed.\n");
        goto done;
    }

    *outbuflen = partlen + tmplen;
    rc = CKR_OK;

done:
    EVP_CIPHER_CTX_free(ctx);

    if (rc == CKR_OK && tokdata != NULL &&
        (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0) {
        if (wrap)
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id,
                                                &tokdata->store_strength.wrap_crypt,
                                                tokdata->store_strength.wrap_strength);
        else
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id,
                                                &tokdata->store_strength.mk_crypt,
                                                tokdata->store_strength.mk_strength);
    }

    return rc;
}

CK_RV decrypt_aes(STDLL_TokData_t *tokdata,
                  CK_BYTE * inbuf, int inbuflen, CK_BYTE * dkey,
                  CK_BYTE * iv, CK_BYTE * outbuf, int *outbuflen,
                  CK_BBOOL unwrap)
{
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();
    int block_size = EVP_CIPHER_block_size(cipher);
    CK_RV rc = CKR_FUNCTION_FAILED;
    CK_BYTE finalbuf[EVP_MAX_BLOCK_LENGTH];
    int partlen, finallen;
    EVP_CIPHER_CTX *ctx;

    if (*outbuflen < inbuflen - block_size) {
        TRACE_ERROR("Output buffer too small for decrypt_aes "
                    "(need at least %d, have %d).\n",
                    inbuflen - block_size, *outbuflen);
        return CKR_BUFFER_TOO_SMALL;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("EVP_CIPHER_CTX_new failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, dkey, iv)) {
        TRACE_ERROR("EVP_DecryptInit_ex failed.\n");
        goto done;
    }
    partlen = 0;
    if (!EVP_DecryptUpdate(ctx, outbuf, &partlen, inbuf, inbuflen)) {
        TRACE_ERROR("EVP_DecryptUpdate failed.\n");
        goto done;
    }
    finallen = 0;
    if (!EVP_DecryptFinal_ex(ctx, finalbuf, &finallen)) {
        TRACE_ERROR("EVP_DecryptFinal failed.\n");
        goto done;
    }

    /* Check that the final (de-padded) bytes fit in the caller's buffer. */
    if (partlen + finallen > *outbuflen) {
        TRACE_ERROR("Output buffer too small for decrypt_aes result "
                    "(need %d, have %d).\n", partlen + finallen, *outbuflen);
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    if (finallen > 0)
        memcpy(outbuf + partlen, finalbuf, finallen);

    /* total length of the decrypted data (padding already stripped by Final) */
    *outbuflen = partlen + finallen;
    rc = CKR_OK;

done:
    EVP_CIPHER_CTX_free(ctx);

    if (rc == CKR_OK && tokdata != NULL &&
        (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0) {
        if (unwrap)
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id,
                                                &tokdata->store_strength.wrap_crypt,
                                                tokdata->store_strength.wrap_strength);
        else
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id,
                                                &tokdata->store_strength.mk_crypt,
                                                tokdata->store_strength.mk_strength);
    }

    return rc;
}

CK_RV get_masterkey(STDLL_TokData_t *tokdata,
                    CK_BYTE *pin, CK_ULONG pinlen, const char *fname,
                    CK_BYTE *masterkey, int *len)
{
    struct stat statbuf;
    FILE *fp;
    CK_ULONG_32 totallen, datasize, readsize, version;
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

    ret = fread(&version, sizeof(CK_ULONG_32), 1, fp);
    if (ret != 1) {
        fclose(fp);
        TRACE_ERROR("fread failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    /*
     * Version 1 files did not have the version field, thus the first field read
     * is the total length. If the first field is not a known version number,
     * we assume it is an old version file. For an old version file, the total
     * length is 64 bytes, this is it is much higher than the version number.
     */
    if (version == ICSF_MK_FILE_VERSION) {
        /* New version file detected */
        ret = fread(&totallen, sizeof(CK_ULONG_32), 1, fp);
        if (ret != 1) {
            fclose(fp);
            TRACE_ERROR("fread failed.\n");
            return CKR_FUNCTION_FAILED;
        }
    } else {
        TRACE_DEVEL("Old version master key file detected\n");
        totallen = version;
    }

    ret = fread(salt, SALTSIZE, 1, fp);
    if (ret != 1) {
        fclose(fp);
        TRACE_ERROR("fread failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* get length of encryted data */
    if (totallen <= SALTSIZE || totallen - SALTSIZE > sizeof(outbuf)) {
        TRACE_ERROR("Invalid total length %lu in master key file.\n",
                    (unsigned long)totallen);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }
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
    if (version == ICSF_MK_FILE_VERSION)
        rc = pbkdf_openssl(tokdata, pin, pinlen, salt, dkey, dkeysize);
    else
        rc = pbkdf_old(tokdata, pin, pinlen, salt, dkey, dkeysize);
    if (rc != CKR_OK) {
        TRACE_DEBUG("pbkdf(): Failed to derive a key.\n");
        OPENSSL_cleanse(dkey, sizeof(dkey));
        return CKR_FUNCTION_FAILED;
    }

    /* decrypt the masterkey */
    /* re-use salt for iv */
    rc = decrypt_aes(tokdata, outbuf, datasize, dkey, salt, masterkey, len,
                     CK_TRUE);
    OPENSSL_cleanse(dkey, sizeof(dkey));
    if (rc != CKR_OK) {
        TRACE_DEBUG("Failed to decrypt the racf pwd.\n");
        OPENSSL_cleanse(masterkey, *len > 0 ? (size_t)*len : 0);
        return CKR_FUNCTION_FAILED;
    }

    /* make sure len is equal to our masterkey size. */
    if (*len != AES_KEY_SIZE_256) {
        TRACE_ERROR("Decrypted key is invalid.\n");
        OPENSSL_cleanse(masterkey, (size_t)*len);
        return CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV get_racf(STDLL_TokData_t *tokdata,
               CK_BYTE * masterkey, CK_ULONG mklen, CK_BYTE * racfpwd,
               int *racflen)
{
    char fname[PATH_MAX];
    struct stat statbuf;
    CK_BYTE outbuf[ENCRYPT_SIZE];
    CK_BYTE iv[AES_INIT_VECTOR_SIZE];
    int len, datasize, readsize;
    FILE *fp;
    CK_RV rc;

    UNUSED(mklen);

    /* see if the file exists ... */
    snprintf(fname, sizeof(fname), "%s/%s", tokdata->data_store, RACFFILE);
    if ((stat(fname, &statbuf) < 0) && (errno == ENOENT)) {
        TRACE_ERROR("File does not exist.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* if file exists, open it */
    fp = fopen(fname, "r");
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
    if (len <= AES_INIT_VECTOR_SIZE ||
        len - AES_INIT_VECTOR_SIZE > (int)sizeof(outbuf)) {
        TRACE_ERROR("Invalid total length %d in RACF file.\n", len);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }
    datasize = len - AES_INIT_VECTOR_SIZE;
    readsize = fread(outbuf, datasize, 1, fp);
    if (readsize != 1) {
        TRACE_ERROR("Could not get encrypted data in %s.\n", RACFFILE);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }
    fclose(fp);

    /* decrypt the data using the masterkey */
    rc = decrypt_aes(tokdata, outbuf, datasize, masterkey, iv, racfpwd, racflen,
                     CK_FALSE);

    if (rc != CKR_OK) {
        TRACE_DEBUG("Failed to decrypt the racf pwd.\n");
        OPENSSL_cleanse(racfpwd, *racflen > 0 ? (size_t)*racflen : 0);
        return CKR_FUNCTION_FAILED;
    }

    if (*racflen >= PIN_SIZE) {
        TRACE_ERROR("Decrypted RACF password too long: %d (max %d).\n",
                    *racflen, PIN_SIZE - 1);
        OPENSSL_cleanse(racfpwd, (size_t)*racflen);
        return CKR_FUNCTION_FAILED;
    }

    /* terminate the decrypted string. */
    racfpwd[*racflen] = '\0';

    return CKR_OK;
}

CK_RV pbkdf_openssl(STDLL_TokData_t *tokdata,
                    CK_BYTE *password, CK_ULONG len, CK_BYTE *salt,
                    CK_BYTE *dkey, CK_ULONG klen)
{
    const CK_MECHANISM mech = { CKM_PKCS5_PBKD2, NULL, 0 };
    const CK_MECHANISM mech2 = { CKM_SHA256_HMAC, NULL, 0 };
    int rc;

    if (!password || !salt || len > INT_MAX || klen > INT_MAX) {
        TRACE_ERROR("Invalid function argument(s).\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = PKCS5_PBKDF2_HMAC((char *)password, (int)len, salt, SALTSIZE,
                            ITERATIONS, EVP_sha256(), (int)klen, dkey);
    if (rc != 1) {
        TRACE_ERROR("PBKDF2 failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    if (tokdata != NULL &&
        (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0) {
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id, &mech,
                                            POLICY_STRENGTH_IDX_0);
        if ((tokdata->statistics->flags & STATISTICS_FLAG_COUNT_IMPLICIT) != 0) {
            /*
             * We use CKM_PKCS5_PBKD2 with CKP_PKCS5_PBKD2_HMAC_SHA256.
             * Use strength 0 because the HMAC key is the pin, and it is max
             * 8 char (i.e. 64 bit) long, which is way below 112 bit anyway.
             */
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id, &mech2,
                                                POLICY_STRENGTH_IDX_0);
        }
    }

    return CKR_OK;
}

CK_RV pbkdf_old(STDLL_TokData_t *tokdata,
                CK_BYTE * password, CK_ULONG len, CK_BYTE * salt, CK_BYTE * dkey,
                CK_ULONG klen)
{
    unsigned char hash[SHA256_HASH_SIZE];
    unsigned char hash_block[SHA256_HASH_SIZE];
    unsigned char *result;
    unsigned int r, num_of_blocks;
    unsigned int count, hashlen;
    CK_ULONG rc = CKR_OK;
    unsigned int i, j;
    int k;
    const CK_MECHANISM mech = { CKM_PKCS5_PBKD2, NULL, 0 };
    const CK_MECHANISM mech2 = { CKM_SHA256_HMAC, NULL, 0 };

    /* check inputs */
    if (!password || !salt) {
        TRACE_ERROR("Invalid function argument(s).\n");
        return CKR_FUNCTION_FAILED;
    }

    /* check length of key.. for now only 32 byte keys */
    if (klen != DKEYLEN) {
        TRACE_ERROR("Only support 32 byte keys.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* SP 800-132 recommends a minimum iteration count of 1000.
     * so lets try that for now...
     */
    count = 1000;

    hashlen = SHA256_HASH_SIZE;

    /* Calculate amount of blocks in klen.
     * SP 800-132: len = [kLen / hLen] (rounded up).
     *             r = kLen - (len - 1) * hLen;
     */
    if (klen < SHA256_HASH_SIZE) {
        num_of_blocks = 1;
        r = klen;
    } else {
        num_of_blocks = klen / SHA256_HASH_SIZE;
        /* round up by adding another block if there is a modulus */
        if ((klen % SHA256_HASH_SIZE) != 0)
            num_of_blocks++;
        r = klen - (num_of_blocks - 1) * SHA256_HASH_SIZE;
    }

    /* SP 800-132: For i = 1 to len */
    for (i = 1; i <= num_of_blocks; i++) {

        /* SP 800-132: Ti = 0; */
        memset(hash_block, 0, SHA256_HASH_SIZE);

        /* SP 800-132: U0 = S || Int(i); */
        memset(hash, 0, SHA256_HASH_SIZE);
        memcpy(hash, salt, SALTSIZE);
        hash[SALTSIZE] = i;
        hashlen = SALTSIZE + 1;

        /* SP 800-132: For j = 1 to C */
        for (j = 1; j <= count; j++) {
            /* SP 800-132: Uj = HMAC(P, U(j-1)); */
            result =
                HMAC(EVP_sha256(), password, len, hash, hashlen, NULL, NULL);
            if (result == NULL) {
                TRACE_ERROR("Failed to compute the hmac.\n");
                rc = CKR_FUNCTION_FAILED;
                goto out;
            }

            /* SP 800-132: Ti = Ti Exclusive_OR Uj; */
            for (k = 0; k < SHA256_HASH_SIZE; k++)
                hash_block[k] ^= hash[k];

            /* prep U(j-1) for next iteration */
            memcpy(hash, result, SHA256_HASH_SIZE);
            hashlen = SHA256_HASH_SIZE;
        }

        /* SP 800-132: derived_key =
         *   hash_block(1)||hash_block(2)||hash_block(num_of_blocks)<0...r-1>
         * This means num_of_blocks are needed to concatencate
         * together to make the derived key.
         * However, if the derived key length is not a multiple of the
         * HASH_SIZE, then we only need some of the data in the last hash_block.
         * So, if there is an r, then only copy r bytes from last hash_block
         * to the derived_key.
         */
        if ((i == num_of_blocks) && (r != 0))
            memcpy(dkey, hash_block, r);
        else
            memcpy(dkey, hash_block, SHA256_HASH_SIZE);

    }

out:
    if (rc == CKR_OK && tokdata != NULL &&
        (tokdata->statistics->flags & STATISTICS_FLAG_COUNT_INTERNAL) != 0) {
        tokdata->statistics->increment_func(tokdata->statistics,
                                            tokdata->slot_id, &mech,
                                            POLICY_STRENGTH_IDX_0);
        if ((tokdata->statistics->flags & STATISTICS_FLAG_COUNT_IMPLICIT) != 0) {
            /*
             * We use CKM_PKCS5_PBKD2 with CKP_PKCS5_PBKD2_HMAC_SHA256.
             * Use strength 0 because the HMAC key is the pin, and it is max
             * 8 char (i.e. 64 bit) long, which is way below 112 bit anyway.
             */
            tokdata->statistics->increment_func(tokdata->statistics,
                                                tokdata->slot_id, &mech2,
                                                POLICY_STRENGTH_IDX_0);
        }
    }

    return rc;
}

CK_RV secure_racf(STDLL_TokData_t *tokdata,
                  CK_BYTE * racf, CK_ULONG racflen, CK_BYTE * key,
                  CK_ULONG keylen, const char *tokname)
{
    CK_RV rc = CKR_OK;
    CK_BYTE iv[AES_INIT_VECTOR_SIZE];
    FILE *fp;
    CK_BYTE output[ENCRYPT_SIZE];
    CK_ULONG_32 totallen;
    int outputlen;
    int truncret;
    char fname[PATH_MAX];

    UNUSED(keylen);

    /* generate an iv... */
    if ((get_randombytes(iv, AES_INIT_VECTOR_SIZE)) != CKR_OK) {
        TRACE_DEBUG("Could not generate an iv.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* encrypt the racf passwd using the masterkey */
    outputlen = sizeof(output);
    rc = encrypt_aes(tokdata, racf, racflen, key, iv, output, &outputlen,
                     CK_FALSE);
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

    snprintf(fname, sizeof(fname), "%s/%s/%s", CONFIG_PATH, tokname, RACFFILE);
    /* CWE-59 fix: Use fopen_nofollow to prevent symlink attacks */
    fp = fopen_nofollow(fname, "w");
    if (!fp) {
        if (errno == ELOOP)
            TRACE_ERROR("Refusing to follow symlink: %s\n", fname);
        else
            TRACE_ERROR("fopen failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    /* set permisions on the file */
    rc = set_perms(fileno(fp), tokdata != NULL ? tokdata->tokgroup : NULL);
    if (rc != 0) {
        TRACE_ERROR("Failed to set permissions on RACF file.\n");
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    /* write the info to the file */
    if (fwrite(&totallen, sizeof(CK_ULONG_32), 1, fp) != 1 ||
        fwrite(iv, AES_INIT_VECTOR_SIZE, 1, fp) != 1 ||
        fwrite(output, outputlen, 1, fp) != 1) {
        TRACE_ERROR("Failed to write RACF file: %s\n", strerror(errno));
        truncret = ftruncate(fileno(fp), 0);
        UNUSED(truncret);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    fclose(fp);

    return rc;
}

CK_RV secure_masterkey(STDLL_TokData_t *tokdata,
                       CK_BYTE * masterkey, CK_ULONG len, CK_BYTE * pin,
                       CK_ULONG pinlen, const char *fname)
{
    CK_RV rc = CKR_OK;
    CK_BYTE salt[SALTSIZE];
    CK_BYTE dkey[AES_KEY_SIZE_256];
    CK_ULONG_32 totallen, dkey_size, version;
    int outputlen;
    int truncret;
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
    rc = pbkdf_openssl(tokdata, pin, pinlen, salt, dkey, dkey_size);
    if (rc != 0) {
        TRACE_DEBUG("Failed to derive a key for encryption.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* encrypt the masterkey using the derived key */
    /* re-use the salt for the iv... */
    outputlen = sizeof(output);
    rc = encrypt_aes(tokdata, masterkey, len, dkey, salt, output, &outputlen,
                     CK_TRUE);
    if (rc != 0) {
        TRACE_DEBUG("Failed to encrypt masterkey.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* write the encrypted masterkey to named file */
    /* store the following:
     * 1. version field
     * 2. total length = salt + encrypted data
     * 3. salt (always SALTSIZE)
     * 4. encrypted data
     */

    /* get the total length */
    totallen = outputlen + SALTSIZE;

    /* CWE-59 fix: Use fopen_nofollow to prevent symlink attacks */
    fp = fopen_nofollow(fname, "w");
    if (!fp) {
        if (errno == ELOOP)
            TRACE_ERROR("Refusing to follow symlink: %s\n", fname);
        else
            TRACE_ERROR("fopen failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    /* set permisions on the file */
    rc = set_perms(fileno(fp), tokdata != NULL ? tokdata->tokgroup : NULL);
    if (rc != 0) {
        TRACE_ERROR("Failed to set permissions on encrypted file.\n");
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    /* write the info to the file (always new version format) */
    version = ICSF_MK_FILE_VERSION;
    if (fwrite(&version, sizeof(CK_ULONG_32), 1, fp) != 1 ||
        fwrite(&totallen, sizeof(CK_ULONG_32), 1, fp) != 1 ||
        fwrite(salt, SALTSIZE, 1, fp) != 1 ||
        fwrite(output, outputlen, 1, fp) != 1) {
        TRACE_ERROR("Failed to write master key file: %s\n", strerror(errno));
        truncret = ftruncate(fileno(fp), 0);
        UNUSED(truncret);
        fclose(fp);
        OPENSSL_cleanse(dkey, sizeof(dkey));
        return CKR_FUNCTION_FAILED;
    }

    fclose(fp);
    OPENSSL_cleanse(dkey, sizeof(dkey));
    return rc;
}

/*
 * secure_masterkey_v3 - write a version-3 MK_SO or MK_USER file.
 *
 * Format: 40 raw bytes = AES-256-KW(RFC 3394) of the 32-byte master key.
 * No version field — identical to loadsave.c save_masterkey_so/user.
 * The file size (40 bytes) is the implicit format discriminator.
 *
 * @tokdata   - token data (may be NULL when called from pkcsicsf tool)
 * @masterkey - 32-byte AES master key to protect
 * @wrap_key  - 32-byte PBKDF2-derived wrapping key from TOKEN_DATA_VERSION
 * @fname     - destination file path
 */
CK_RV secure_masterkey_v3(STDLL_TokData_t *tokdata,
                           const CK_BYTE *masterkey,
                           const CK_BYTE wrap_key[32],
                           const char *fname)
{
    unsigned char wrapped[40];
    FILE *fp;
    int truncret;
    CK_RV rc;

    rc = icsf_aes_256_wrap(wrapped, masterkey, wrap_key);
    if (rc != CKR_OK) {
        TRACE_ERROR("icsf_aes_256_wrap failed.\n");
        return rc;
    }

    fp = fopen_nofollow(fname, "w");
    if (!fp) {
        if (errno == ELOOP)
            TRACE_ERROR("Refusing to follow symlink: %s\n", fname);
        else
            TRACE_ERROR("fopen failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    rc = set_perms(fileno(fp), tokdata != NULL ? tokdata->tokgroup : NULL);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to set permissions on master key file.\n");
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    if (fwrite(wrapped, sizeof(wrapped), 1, fp) != 1) {
        TRACE_ERROR("Failed to write v3 master key file: %s\n",
                    strerror(errno));
        truncret = ftruncate(fileno(fp), 0);
        UNUSED(truncret);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    fclose(fp);
    return CKR_OK;
}

/*
 * get_masterkey_v3 - read and unwrap a version-3 MK_SO or MK_USER file.
 *
 * Format: 40 raw bytes = AES-256-KW(RFC 3394) of the 32-byte master key.
 * No version field — file size is the implicit format discriminator.
 *
 * @tokdata   - token data (may be NULL when called from pkcsicsf tool)
 * @wrap_key  - 32-byte PBKDF2-derived wrapping key from TOKEN_DATA_VERSION
 * @fname     - source file path
 * @masterkey - output: 32-byte unwrapped master key
 */
CK_RV get_masterkey_v3(STDLL_TokData_t *tokdata,
                       const CK_BYTE wrap_key[32],
                       const char *fname,
                       CK_BYTE masterkey[32])
{
    unsigned char wrapped[40];
    struct stat sb;
    FILE *fp;
    CK_RV rc;

    UNUSED(tokdata);

    fp = fopen(fname, "r");
    if (fp == NULL) {
        TRACE_ERROR("fopen(%s) failed: %s\n", fname, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    /*
     * Verify the file is exactly ICSF_MK_FILE_V3_SIZE (40) bytes before
     * attempting to read it as a v3 AES-256-KW blob. A different size
     * means the file is a legacy v1/v2 MK file (68 or 72 bytes).
     */
    if (fstat(fileno(fp), &sb) != 0) {
        TRACE_ERROR("fstat(%s) failed: %s\n", fname, strerror(errno));
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }
    if (sb.st_size != ICSF_MK_FILE_V3_SIZE) {
        TRACE_ERROR("v3 master key file \"%s\" has unexpected size %lld "
                    "(expected %d) -- file may be in legacy format; "
                    "check that tokversion = 3.28 is correct for this "
                    "token.\n",
                    fname, (long long)sb.st_size, ICSF_MK_FILE_V3_SIZE);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    if (fread(wrapped, sizeof(wrapped), 1, fp) != 1) {
        TRACE_ERROR("fread failed on v3 master key file: %s\n", fname);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }
    fclose(fp);

    rc = icsf_aes_256_unwrap(masterkey, wrapped, wrap_key);
    OPENSSL_cleanse(wrapped, sizeof(wrapped));
    if (rc != CKR_OK) {
        TRACE_ERROR("icsf_aes_256_unwrap failed.\n");
        OPENSSL_cleanse(masterkey, 32);
    }
    return rc;
}

/*
 * Local AES-256-GCM seal (encrypt + produce tag).
 * Self-contained so pbkdf.c does not depend on pkcs_utils.c.
 */
static CK_RV icsf_aes_256_gcm_seal(unsigned char *out, unsigned char tag[16],
                                    const unsigned char *aad, size_t aadlen,
                                    const unsigned char *in, size_t inlen,
                                    const unsigned char key[32],
                                    const unsigned char iv[12])
{
    EVP_CIPHER_CTX *ctx;
    int aad_len = 0, outlen = 0, finaln = 0;
    CK_RV rc = CKR_FUNCTION_FAILED;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        TRACE_ERROR("EVP_CIPHER_CTX_new failed.\n");
        return CKR_HOST_MEMORY;
    }

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, -1) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1
        || EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1) != 1
        || EVP_CipherUpdate(ctx, NULL, &aad_len, aad, aadlen) != 1
        || EVP_CipherUpdate(ctx, out, &outlen, in, inlen) != 1
        || EVP_CipherFinal_ex(ctx, out + outlen, &finaln) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        TRACE_ERROR("AES-256-GCM seal failed.\n");
        goto done;
    }
    rc = CKR_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/*
 * secure_racf_v3 - write a version-3 RACF file using AES-256-GCM.
 *
 * Format on disk (all multi-byte integers in big-endian):
 *   u32  version         = ICSF_RACF_FILE_VERSION_3  (big-endian)
 *   u8   iv[12]          random GCM nonce
 *   u8   tag[16]         GCM authentication tag
 *   u32  ciphertext_len  length of ciphertext         (big-endian)
 *   u8   ciphertext[ciphertext_len]
 *
 * @tokdata    token data (may be NULL when called from pkcsicsf tool)
 * @racf       RACF password bytes (not NUL-terminated)
 * @racflen    length of @racf
 * @masterkey  32-byte AES master key used as GCM key
 * @tokname    token directory name, used as path component and as AAD
 */
CK_RV secure_racf_v3(STDLL_TokData_t *tokdata,
                     const CK_BYTE *racf, CK_ULONG racflen,
                     const CK_BYTE masterkey[32],
                     const char *tokname)
{
    CK_ULONG_32 version = htobe32(ICSF_RACF_FILE_VERSION_3);
    CK_ULONG_32 ciphertext_len_be;
    unsigned char iv[12];
    unsigned char tag[16];
    unsigned char *ciphertext = NULL;
    FILE *fp = NULL;
    char fname[PATH_MAX];
    int truncret;
    CK_RV rc;

    if (racflen == 0 || racflen > PIN_SIZE - 1) {
        TRACE_ERROR("RACF password length invalid (%lu, max %d).\n",
                    (unsigned long)racflen, PIN_SIZE - 1);
        return CKR_FUNCTION_FAILED;
    }

    if (get_randombytes(iv, sizeof(iv)) != CKR_OK) {
        TRACE_ERROR("Could not generate GCM IV.\n");
        return CKR_FUNCTION_FAILED;
    }

    ciphertext = malloc(racflen);
    if (!ciphertext) {
        TRACE_ERROR("malloc failed.\n");
        return CKR_HOST_MEMORY;
    }

    /* Use tokname as AAD to bind the ciphertext to this specific token */
    rc = icsf_aes_256_gcm_seal(ciphertext, tag,
                                (const unsigned char *)tokname, strlen(tokname),
                                racf, racflen,
                                masterkey, iv);
    if (rc != CKR_OK) {
        TRACE_ERROR("AES-256-GCM seal of RACF password failed.\n");
        goto done;
    }
    ciphertext_len_be = htobe32((CK_ULONG_32)racflen);

    snprintf(fname, sizeof(fname), "%s/%s/%s", CONFIG_PATH, tokname, RACFFILE);
    fp = fopen_nofollow(fname, "w");
    if (!fp) {
        if (errno == ELOOP)
            TRACE_ERROR("Refusing to follow symlink: %s\n", fname);
        else
            TRACE_ERROR("fopen failed: %s\n", strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = set_perms(fileno(fp), tokdata != NULL ? tokdata->tokgroup : NULL);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to set permissions on RACF file.\n");
        fclose(fp);
        fp = NULL;
        goto done;
    }

    if (fwrite(&version, sizeof(version), 1, fp) != 1 ||
        fwrite(iv, sizeof(iv), 1, fp) != 1 ||
        fwrite(tag, sizeof(tag), 1, fp) != 1 ||
        fwrite(&ciphertext_len_be, sizeof(ciphertext_len_be), 1, fp) != 1 ||
        fwrite(ciphertext, racflen, 1, fp) != 1) {
        TRACE_ERROR("Failed to write v3 RACF file: %s\n", strerror(errno));
        truncret = ftruncate(fileno(fp), 0);
        UNUSED(truncret);
        rc = CKR_FUNCTION_FAILED;
    }

done:
    if (fp)
        fclose(fp);
    free(ciphertext);
    return rc;
}

/*
 * get_racf_v3 - read and authenticate-decrypt a version-3 RACF file.
 *
 * @tokdata    token data (provides data_store path and tokgroup)
 * @masterkey  32-byte AES master key used as GCM key
 * @racfpwd    output buffer for the decrypted RACF password (caller
 *             supplies a buffer of at least PIN_SIZE bytes)
 * @racflen    in/out: on entry the buffer size, on exit the password length
 *
 * The token name for AAD is derived from tokdata->data_store.
 */
CK_RV get_racf_v3(STDLL_TokData_t *tokdata,
                  const CK_BYTE masterkey[32],
                  CK_BYTE *racfpwd, int *racflen)
{
    char fname[PATH_MAX];
    const char *tokname;
    CK_ULONG_32 version, ciphertext_len_be, ciphertext_len;
    unsigned char iv[12];
    unsigned char tag[16];
    unsigned char *ciphertext = NULL;
    FILE *fp;
    CK_RV rc;
    struct stat statbuf;

    snprintf(fname, sizeof(fname), "%s/%s", tokdata->data_store, RACFFILE);

    if ((stat(fname, &statbuf) < 0) && errno == ENOENT) {
        TRACE_ERROR("RACF file does not exist: %s\n", fname);
        return CKR_FUNCTION_FAILED;
    }

    fp = fopen(fname, "r");
    if (!fp) {
        TRACE_ERROR("fopen(%s) failed: %s\n", fname, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    if (fread(&version, sizeof(version), 1, fp) != 1) {
        TRACE_ERROR("fread failed on v3 RACF file.\n");
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    if (be32toh(version) != ICSF_RACF_FILE_VERSION_3) {
        TRACE_ERROR("Unexpected version %u in RACF file (expected %u).\n",
                    (unsigned int)be32toh(version), ICSF_RACF_FILE_VERSION_3);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    if (fread(iv, sizeof(iv), 1, fp) != 1 ||
        fread(tag, sizeof(tag), 1, fp) != 1 ||
        fread(&ciphertext_len_be, sizeof(ciphertext_len_be), 1, fp) != 1) {
        TRACE_ERROR("fread failed on v3 RACF file header.\n");
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }
    ciphertext_len = be32toh(ciphertext_len_be);

    if (ciphertext_len == 0 || ciphertext_len >= (CK_ULONG_32)PIN_SIZE) {
        TRACE_ERROR("Invalid ciphertext_len %u in v3 RACF file.\n",
                    (unsigned int)ciphertext_len);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    ciphertext = malloc(ciphertext_len);
    if (!ciphertext) {
        TRACE_ERROR("malloc failed.\n");
        fclose(fp);
        return CKR_HOST_MEMORY;
    }

    if (fread(ciphertext, ciphertext_len, 1, fp) != 1) {
        TRACE_ERROR("fread of ciphertext failed in v3 RACF file.\n");
        fclose(fp);
        free(ciphertext);
        return CKR_FUNCTION_FAILED;
    }
    fclose(fp);

    /*
     * Derive the AAD from the last component of data_store (the token name).
     * data_store is the full path; the token name is the basename.
     */
    tokname = strrchr(tokdata->data_store, '/');
    tokname = tokname ? tokname + 1 : tokdata->data_store;

    if (*racflen < (int)ciphertext_len + 1) {
        TRACE_ERROR("racfpwd buffer too small (%d < %u).\n",
                    *racflen, (unsigned int)ciphertext_len + 1);
        free(ciphertext);
        return CKR_BUFFER_TOO_SMALL;
    }

    rc = icsf_aes_256_gcm_unseal(racfpwd, tag,
                                  (const unsigned char *)tokname, strlen(tokname),
                                  ciphertext, ciphertext_len,
                                  masterkey, iv);
    if (rc != CKR_OK) {
        TRACE_ERROR("AES-256-GCM unseal of RACF password failed "
                    "(tampered file or wrong master key).\n");
        OPENSSL_cleanse(racfpwd, ciphertext_len);
    } else {
        *racflen = (int)ciphertext_len;
        racfpwd[*racflen] = '\0';
    }

    OPENSSL_cleanse(ciphertext, ciphertext_len);
    free(ciphertext);
    return rc;
}
