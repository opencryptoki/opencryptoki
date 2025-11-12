/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  defs.h
//
// Contains various definitions needed by both the host-side
// and coprocessor-side code.
//

#ifndef _DEFS_H
#define _DEFS_H

#include <openssl/opensslv.h>

#ifndef OPENSSL_VERSION_PREREQ
    #if defined(OPENSSL_VERSION_MAJOR) && defined(OPENSSL_VERSION_MINOR)
        #define OPENSSL_VERSION_PREREQ(maj, min)        \
            ((OPENSSL_VERSION_MAJOR << 16) +        \
            OPENSSL_VERSION_MINOR >= ((maj) << 16) + (min))
    #else
        #define OPENSSL_VERSION_PREREQ(maj, min)        \
            (OPENSSL_VERSION_NUMBER >= (((maj) << 28) | \
            ((min) << 20)))
    #endif
#endif

#define MAX_SESSION_COUNT     64
#define MAX_PIN_LEN           8
#define MIN_PIN_LEN           4

#ifndef MIN
#define MIN(a, b)  ((a) < (b) ? (a) : (b))
#endif
#ifndef MAX
#define MAX(a, b)  ((a) > (b) ? (a) : (b))
#endif

#define UNUSED(var)            ((void)(var))

// the following constants are used for sccSignOn
//
#define PKCS_11_PRG_ID         "pkcs11 2.01"
#define PKCS_11_DEVELOPER_ID   0xE
#define PKCS_11_VERSION        1
#define PKCS_11_INSTANCE       0
#define PKCS_11_QUEUE          0

// the following are "boolean" attributes
//
#define CKA_IBM_TWEAK_ALLOW_KEYMOD    0x80000001
#define CKA_IBM_TWEAK_ALLOW_WEAK_DES  0x80000002
#define CKA_IBM_TWEAK_DES_PARITY_CHK  0x80000003
#define CKA_IBM_TWEAK_NETSCAPE        0x80000004

#define MODE_COPY       (1 << 0)
#define MODE_CREATE     (1 << 1)
#define MODE_KEYGEN     (1 << 2)
#define MODE_MODIFY     (1 << 3)
#define MODE_DERIVE     (1 << 4)
#define MODE_UNWRAP     (1 << 5)
#define MODE_UNWRAPPED  (1 << 6)

// RSA block formatting types
//
#define PKCS_BT_1       1
#define PKCS_BT_2       2

#define OP_ENCRYPT_INIT 1
#define OP_DECRYPT_INIT 2
#define OP_WRAP         3
#define OP_UNWRAP       4
#define OP_SIGN_INIT    5
#define OP_VERIFY_INIT  6

// saved-state identifiers
//
enum {
    STATE_INVALID = 0,
    STATE_ENCR,
    STATE_DECR,
    STATE_DIGEST,
    STATE_SIGN,
    STATE_VERIFY
};


#define ENCRYPT 1
#define DECRYPT 0

#define MAX_RSA_KEYLEN  (OPENSSL_RSA_MAX_MODULUS_BITS / 8)

#define AES_KEY_SIZE_256 32
#define AES_KEY_SIZE_192 24
#define AES_KEY_SIZE_128 16
#define AES_BLOCK_SIZE  16
#define AES_INIT_VECTOR_SIZE AES_BLOCK_SIZE
#define AES_COUNTER_SIZE        16
#define AES_KEY_WRAP_BLOCK_SIZE 8
#define AES_KEY_WRAP_IV_SIZE AES_KEY_WRAP_BLOCK_SIZE
#define AES_KEY_WRAP_KWP_IV_SIZE 4

#define DES_KEY_SIZE    8
#define DES_BLOCK_SIZE  8

/*
 * It should be able to keep any kind of key (AES, 3DES, etc) and also
 * a PBKDF key
 */
#define MAX_KEY_SIZE 96

#define SHA1_HASH_SIZE  20
#define SHA1_BLOCK_SIZE 64
#define SHA224_HASH_SIZE  28
#define SHA224_BLOCK_SIZE 64
#define SHA256_HASH_SIZE  32
#define SHA256_BLOCK_SIZE 64
#define SHA384_HASH_SIZE  48
#define SHA384_BLOCK_SIZE 128
#define SHA512_HASH_SIZE  64
#define SHA512_BLOCK_SIZE 128
#define SHA3_224_HASH_SIZE SHA224_HASH_SIZE
#define SHA3_224_BLOCK_SIZE 144
#define SHA3_256_HASH_SIZE SHA256_HASH_SIZE
#define SHA3_256_BLOCK_SIZE 136
#define SHA3_384_HASH_SIZE SHA384_HASH_SIZE
#define SHA3_384_BLOCK_SIZE 104
#define SHA3_512_HASH_SIZE SHA512_HASH_SIZE
#define SHA3_512_BLOCK_SIZE 72
#define MAX_SHA_HASH_SIZE SHA512_HASH_SIZE
#define MAX_SHA_BLOCK_SIZE SHA3_224_BLOCK_SIZE

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

struct oc_sha_ctx {
    unsigned char hash[MAX_SHA_HASH_SIZE + 1];
    unsigned int hash_len;
    unsigned int hash_blksize;
    unsigned int tail_len;
    int message_part;
    unsigned char tail[MAX_SHA_BLOCK_SIZE];
    unsigned int dev_ctx_offs;
};

#if !(NOMD2)
#define MD2_HASH_SIZE   16
#define MD2_BLOCK_SIZE  48
#endif

#define MD5_HASH_SIZE   16
#define MD5_BLOCK_SIZE  64

#define DSA_SIGNATURE_SIZE  40

#define DEFAULT_SO_PIN  "87654321"

#ifndef MAX_TOK_OBJS
    #define MAX_TOK_OBJS 2048
#endif


typedef enum {
    ALL = 1,
    PRIVATE,
    PUBLIC
} SESS_OBJ_TYPE;

typedef enum {
    NO_LOCK = 0,
    READ_LOCK,
    WRITE_LOCK,
} OBJ_LOCK_TYPE;

typedef struct _DL_NODE {
    struct _DL_NODE *next;
    struct _DL_NODE *prev;
    void *data;
} DL_NODE;


// Token local
//
#define PK_LITE_DIR token_specific.token_directory
#define PK_DIR PK_LITE_DIR
#define SUB_DIR token_specific.token_subdir
#define DBGTAG token_specific.token_debug_tag

#define PK_LITE_NV   "NVTOK.DAT"
#define PK_LITE_OBJ_DIR "TOK_OBJ"
#define PK_LITE_OBJ_IDX "OBJ.IDX"

#define DEL_CMD "/bin/rm -f"

#endif
