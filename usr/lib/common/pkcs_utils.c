/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * Some routines that are shared between the pkcs utilities in usr/sbin.
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>
#include <grp.h>
#include <ctype.h>
#include <openssl/evp.h>
#include <pkcs11types.h>

#include "defs.h"
#include "host_defs.h"

#define OCK_TOOL
#include "pkcs_utils.h"

extern pkcs_trace_level_t trace_level;

void pkcs_trace(pkcs_trace_level_t level, const char *file, int line,
                const char *fmt, ...)
{
    va_list ap;
    const char *fmt_pre;
    char buf[1024];
    char *pbuf;
    int buflen, len;

    if (level > trace_level)
        return;

    pbuf = buf;
    buflen = sizeof(buf);

    /* add file line */
    switch (level) {
    case TRACE_LEVEL_NONE:
        fmt_pre = "";
        break;
    case TRACE_LEVEL_ERROR:
        fmt_pre = "[%s:%d] ERROR: ";
        break;
    case TRACE_LEVEL_WARNING:
        fmt_pre = "[%s:%d] WARN: ";
        break;
    case TRACE_LEVEL_INFO:
        fmt_pre = "[%s:%d] INFO: ";
        break;
    case TRACE_LEVEL_DEVEL:
        fmt_pre = "[%s:%d] DEVEL: ";
        break;
    case TRACE_LEVEL_DEBUG:
        fmt_pre = "[%s:%d] DEBUG: ";
        break;
    default:
        return;
    }
    snprintf(pbuf, buflen, fmt_pre, file, line);

    len = strlen(buf);
    pbuf = buf + len;
    buflen = sizeof(buf) - len;

    va_start(ap, fmt);
    vsnprintf(pbuf, buflen, fmt, ap);
    va_end(ap);

    printf("%s", buf);
}

#ifdef DEBUG

/* a simple function for dumping out a memory area */
void pkcs_hexdump(const char *prestr, void *buf, size_t buflen)
{
    /*           1         2         3         4         5         6
       0123456789012345678901234567890123456789012345678901234567890123456789
       xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx    ................
     */

    size_t i, j;
    char line[68];
    for (i = 0; i < buflen; i += 16) {
        for (j = 0; j < 16; j++) {
            if (i + j < buflen) {
                unsigned char b = ((unsigned char *) buf)[i + j];
                sprintf(line + j * 3, "%02hhx ", b);
                line[51 + j] = (isalnum(b) ? b : '.');
            } else {
                sprintf(line + j * 3, "   ");
                line[51 + j] = ' ';
            }
        }
        line[47] = line[48] = line[49] = line[50] = ' ';
        line[67] = '\0';
    if (prestr)
            TRACE_DEBUG("%s%s\n", prestr, line);
        else
            TRACE_DEBUG("%s\n", line);
    }
}

#endif /* DEBUG */

int compute_hash(int hash_type, int buf_size, const char *buf, char *digest)
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
        rc = -1;
        goto done;
    }

    if (rc != 1) {
        TRACE_ERROR("EVP_DigestInit() failed: rc = %d\n", rc);
        rc = -1;
        goto done;
    }

    rc = EVP_DigestUpdate(md_ctx, buf, buf_size);
    if (rc != 1) {
    	TRACE_ERROR("EVP_DigestUpdate() failed: rc = %d\n", rc);
        rc = -1;
        goto done;
    }

    result_size = EVP_MD_CTX_size(md_ctx);
    rc = EVP_DigestFinal(md_ctx, (unsigned char *) digest, &result_size);
    if (rc != 1) {
    	TRACE_ERROR("EVP_DigestFinal() failed: rc = %d\n", rc);
        rc = -1;
        goto done;
    }

    rc = 0;

done:

    EVP_MD_CTX_destroy(md_ctx);

    return rc;
}

#ifndef OCK_NO_LOCAL_RNG

CK_RV local_rng(CK_BYTE *output, CK_ULONG bytes)
{
    int ranfd;
    int rlen;
    unsigned int totallen = 0;

    ranfd = open("/dev/prandom", 0);
    if (ranfd < 0)
        ranfd = open("/dev/urandom", 0);
    if (ranfd >= 0) {
        do {
            rlen = read(ranfd, output + totallen, bytes - totallen);
            totallen += rlen;
        } while (totallen < bytes);
        close(ranfd);
        return CKR_OK;
    }

    return CKR_FUNCTION_FAILED;
}

#endif

CK_RV aes_256_wrap(unsigned char out[40], const unsigned char in[32],
                   const unsigned char kek[32])
{
    CK_RV rc;
    int outlen;
    unsigned char buffer[40 + EVP_MAX_BLOCK_LENGTH];

    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("EVP_CIPHER_CTX_new failed.\n");
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_wrap(), NULL, kek, NULL, 1) != 1
        || EVP_CipherUpdate(ctx, buffer, &outlen, in, 32) != 1
        || EVP_CipherFinal_ex(ctx, buffer + outlen, &outlen) != 1) {
        TRACE_ERROR("EVP_Cipher funcs failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    memcpy(out, buffer, 40);
    rc = CKR_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV aes_256_unwrap(unsigned char key[32], const unsigned char in[40],
                     const unsigned char kek[32])
{
    CK_RV rc;
    int outlen;
    unsigned char buffer[32 + EVP_MAX_BLOCK_LENGTH];

    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("EVP_CIPHER_CTX_new failed\n");
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_wrap(), NULL, kek, NULL, 0) != 1
        || EVP_CipherUpdate(ctx, buffer, &outlen, in, 40) != 1
        || EVP_CipherFinal_ex(ctx, buffer + outlen, &outlen) != 1) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    memcpy(key, buffer, 32);
    rc = CKR_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV aes_256_gcm_seal(unsigned char *out, unsigned char tag[16],
                       const unsigned char *aad, size_t aadlen,
                       const unsigned char *in, size_t inlen,
                       const unsigned char key[32],
                       const unsigned char iv[12])
{
    CK_RV rc;
    int outlen;

    EVP_CIPHER_CTX *ctx = NULL;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("EVP_CIPHER_CTX_new failed\n");
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL, -1) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1
        || EVP_CipherInit_ex(ctx, NULL, NULL, key, iv, 1) != 1
        || EVP_CipherUpdate(ctx, NULL, &outlen, aad, aadlen) != 1
        || EVP_CipherUpdate(ctx, out, &outlen, in, inlen) != 1
        || EVP_CipherFinal_ex(ctx, out + outlen, &outlen) != 1
        || EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        TRACE_ERROR("EVP_Cipher funcs failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;
done:
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

/**
 * Verify that SO PIN and user PIN are correct by comparing their SHA-1
 * values with the stored hashes in NVTOK.DAT.
 */
int verify_pins(char *data_store, const char *sopin, unsigned long sopinlen,
                  const char *userpin, unsigned long userpinlen)
{
    TOKEN_DATA td;
    char fname[PATH_MAX];
    char pin_sha[SHA1_HASH_SIZE];
    FILE *fp = NULL;
    int ret;
    int tdnew;
    struct stat stbuf;
    size_t tdlen;
    int fd;

    /* read the NVTOK.DAT */
    snprintf(fname, PATH_MAX, "%s/NVTOK.DAT", data_store);
    fp = fopen((char *) fname, "r");
    if (!fp) {
        TRACE_ERROR("Cannot not open %s: %s\n", fname, strerror(errno));
        return -1;
    }

    fd = fileno(fp);
    if ((fstat(fd, &stbuf) != 0) || (!S_ISREG(stbuf.st_mode))) {
        ret = -1;
        goto done;
    }

    if (stbuf.st_size == sizeof(TOKEN_DATA_OLD)) {
        /* old data store/pin format */
        tdnew = 0;
        tdlen = sizeof(TOKEN_DATA_OLD);
    } else if (stbuf.st_size == sizeof(TOKEN_DATA)) {
        /* new data store/pin format */
        tdnew = 1;
        tdlen = sizeof(TOKEN_DATA);
    } else {
        TRACE_ERROR("%s has an invalid size of %ld bytes. Neither old nor new token format.\n",
                  fname, stbuf.st_size);
        ret = -1;
        goto done;
    }

    ret = fread(&td, tdlen, 1, fp);
    if (ret != 1) {
        TRACE_ERROR("Could not read %s: %s\n", fname, strerror(errno));
        ret = -1;
        goto done;
    }

    if (tdnew == 0) {
        /* Now compute the SHAs for the SO and USER pins entered.
         * Compare with the SHAs for SO and USER PINs saved in
         * NVTOK.DAT to verify.
         */

        if (sopin != NULL) {
            ret = compute_sha1(sopin, sopinlen, pin_sha);
            if (ret) {
                TRACE_ERROR("Failed to compute sha for SO.\n");
                goto done;
            }

            if (memcmp(td.so_pin_sha, pin_sha, SHA1_HASH_SIZE) != 0) {
                TRACE_ERROR("SO PIN is incorrect.\n");
                ret = -1;
                goto done;
            }
        }

        if (userpin != NULL) {
            ret = compute_sha1(userpin, userpinlen, pin_sha);
            if (ret) {
                TRACE_ERROR("Failed to compute sha for USER.\n");
                goto done;
            }

            if (memcmp(td.user_pin_sha, pin_sha, SHA1_HASH_SIZE) != 0) {
                TRACE_ERROR("USER PIN is incorrect.\n");
                ret = -1;
                goto done;
            }
        }
    } else if (tdnew == 1) {
        if (sopin != NULL) {
            unsigned char so_login_key[32];

            ret = PKCS5_PBKDF2_HMAC(sopin, sopinlen,
                                    td.dat.so_login_salt, 64,
                                    td.dat.so_login_it, EVP_sha512(),
                                    256 / 8, so_login_key);
            if (ret != 1) {
                TRACE_ERROR("PBKDF2 failed.\n");
                goto done;
            }

            if (CRYPTO_memcmp(td.dat.so_login_key, so_login_key, 32) != 0) {
                TRACE_ERROR("USER PIN is incorrect.\n");
                ret = -1;
                goto done;
            }
        }
        if (userpin != NULL) {
            unsigned char user_login_key[32];

            ret = PKCS5_PBKDF2_HMAC(userpin, userpinlen,
                                    td.dat.user_login_salt, 64,
                                    td.dat.user_login_it, EVP_sha512(),
                                    256 / 8, user_login_key);
            if (ret != 1) {
                TRACE_ERROR("PBKDF2 failed.\n");
                goto done;
            }

            if (CRYPTO_memcmp(td.dat.user_login_key, user_login_key, 32) != 0) {
                TRACE_ERROR("USER PIN is incorrect.\n");
                ret = -1;
                goto done;
            }
        }
    } else {
        TRACE_ERROR("Unknown token format.\n");
        ret = -1;
        goto done;
    }
    ret = 0;

done:
    /* clear out the hash */
    memset(pin_sha, 0, SHA1_HASH_SIZE);
    if (fp)
        fclose(fp);

    return ret;
}

#ifndef OCK_NO_SET_PERM

void set_perm(int file)
{
    struct group *grp;

    // Set absolute permissions or rw-rw----
    fchmod(file, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);

    grp = getgrnam("pkcs11"); // Obtain the group id
    if (grp) {
        // set ownership to pkcs11 group
        if (fchown(file, -1, grp->gr_gid) != 0) {
            goto error;
        }
    } else {
        goto error;
    }

    return;

error:
    TRACE_DEVEL("Unable to set permissions on file.\n");
}

#endif
