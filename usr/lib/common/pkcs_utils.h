/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef PKCS_UTILS_H
#define PKCS_UTILS_H

#include "pkcs11types.h"

#define MASTER_KEY_SIZE           24
#define MASTER_KEY_SIZE_CCA       64
#define MAX_MASTER_KEY_SIZE       MASTER_KEY_SIZE_CCA

#define MK_FILE_SIZE_00           48
#define MK_FILE_SIZE_00_CCA       88

#define HASH_SHA1   1
#define HASH_MD5    2

#define compute_sha1(a,b,c)     compute_hash((HASH_SHA1),(b),(a),(c))
#define compute_md5(a,b,c)      compute_hash(HASH_MD5,(b),(a),(c))

int compute_hash(int hash_type, int buf_size, const char *buf, char *digest);

CK_RV local_rng(CK_BYTE *output, CK_ULONG bytes);

CK_RV aes_256_wrap(unsigned char out[40], const unsigned char in[32],
                   const unsigned char kek[32]);

CK_RV aes_256_unwrap(unsigned char key[32], const unsigned char in[40],
                     const unsigned char kek[32]);

CK_RV aes_256_gcm_seal(unsigned char *out, unsigned char tag[16],
                       const unsigned char *aad, size_t aadlen,
                       const unsigned char *in, size_t inlen,
                       const unsigned char key[32],
                       const unsigned char iv[12]);

int verify_pins(char *data_store, const char *sopin, unsigned long sopinlen,
                const char *userpin, unsigned long userpinlen);

void set_perm(int file);

#ifdef OCK_TOOL
/* Log levels */
typedef enum {
    TRACE_LEVEL_NONE = 0,
    TRACE_LEVEL_ERROR,
    TRACE_LEVEL_WARNING,
    TRACE_LEVEL_INFO,
    TRACE_LEVEL_DEVEL,
    TRACE_LEVEL_DEBUG
} pkcs_trace_level_t;

void pkcs_trace(pkcs_trace_level_t level, const char * file, int line,
                const char *fmt, ...)
                __attribute__ ((format(printf, 4, 5)));
void pkcs_hexdump(const char *prestr, void *buf, size_t buflen);

#define TRACE_NONE(...)    \
    pkcs_trace(TRACE_LEVEL_NONE, __FILE__, __LINE__, __VA_ARGS__)
#define TRACE_ERROR(...)    \
    pkcs_trace(TRACE_LEVEL_ERROR, __FILE__, __LINE__, __VA_ARGS__)
#define TRACE_WARN(...)    \
    pkcs_trace(TRACE_LEVEL_WARNING, __FILE__, __LINE__, __VA_ARGS__)
#define TRACE_INFO(...)    \
    pkcs_trace(TRACE_LEVEL_INFO, __FILE__, __LINE__, __VA_ARGS__)
#define TRACE_DEVEL(...)    \
    pkcs_trace(TRACE_LEVEL_DEVEL, __FILE__, __LINE__, __VA_ARGS__)
#define TRACE_DEBUG(...)    \
    pkcs_trace(TRACE_LEVEL_DEBUG, __FILE__, __LINE__, __VA_ARGS__)
#ifdef DEBUG
void hexdump(const char *prestr, void *buf, size_t buflen);
#define TRACE_DEBUG_DUMP(_prestr, _buf, _buflen) pkcs_hexdump(_prestr, _buf, _buflen)
#else
#define TRACE_DEBUG_DUMP(...)
#endif
#endif /* OCK_TOOL */

#endif
