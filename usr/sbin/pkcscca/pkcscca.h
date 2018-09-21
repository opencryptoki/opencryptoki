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
 * Currently, only migrates CCA private token objects from using a
 * CCA cipher to using a software cipher.
 *
 */


#ifndef __PKCSCCA_H_
#define __PKCSCCA_H_

#define CCA_LIBRARY "libcsulcca.so"
#define TOK_DATASTORE   CONFIG_PATH "/ccatok"
#define MASTER_KEY_SIZE     64
#define SHA1_HASH_SIZE      20
#define MD5_HASH_SIZE       16
#define DES_BLOCK_SIZE      8
#define DES_KEY_SIZE        8
#define CCA_SUCCESS         0

#define AES_NAME    "AES"
#define DES_NAME    "DES"
#define DES2_NAME   "2DES"
#define DES3_NAME   "3DES"
#define ECC_NAME    "ECC"
#define HMAC_NAME   "HMAC"
#define RSA_NAME    "RSA"
#define BAD_NAME    "Unknown"

#define MK_AES      1
#define MK_APKA     2
#define MK_ASYM     3
#define MK_SYM      4

int compute_hash(int hash_type, int buf_size, char *buf, char *digest);

#define compute_sha1(a,b,c)     compute_hash(HASH_SHA1,b,a,c)
#define compute_md5(a,b,c)      compute_hash(HASH_MD5,b,a,c)
#define HASH_SHA1   1
#define HASH_MD5    2

CK_RV sw_des3_cbc(CK_BYTE *, CK_ULONG, CK_BYTE *, CK_ULONG *, CK_BYTE *,
                  CK_BYTE *, CK_BYTE);

#define sw_des3_cbc_encrypt(clear, len, cipher, len2, iv, key) \
                sw_des3_cbc(clear, len, cipher, len2, iv, key, 1)

#define sw_des3_cbc_decrypt(clear, len, cipher, len2, iv, key) \
                sw_des3_cbc(clear, len, cipher, len2, iv, key, 0)

#define EVP_SUCCESS 1
#define print_openssl_errors() \
        do { \
                ERR_load_crypto_strings(); \
                ERR_print_errors_fp(stderr); \
        } while (0)

char *p11strerror(CK_RV);

#define p11_error(s,rc) fprintf(stderr, "%s:%d %s failed: rc=0x%lX (%s)\n", \
                                __FILE__, __LINE__, s, rc, p11strerror(rc))

static inline void _print_error(const char *file, int line,
                                const char *fmt, ...) {
    char buf[512];
    size_t off;
    va_list ap;

    snprintf(buf, sizeof(buf), "%s:%d ", file, line);
    off = strlen("%s:%d ");

    va_start(ap, fmt);
    vsnprintf(buf + off, sizeof(buf) - off, fmt, ap);
    va_end(ap);

    fprintf(stderr, "%s", buf);
}
#define print_error(...) _print_error(__FILE__, __LINE__, __VA_ARGS__)

#define cca_error(f,rc,rsn) fprintf(stderr, "%s:%d " f " failed. return code: "\
                                    "%ld, reason code: %ld\n", __FILE__, \
                                    __LINE__, rc, rsn)
#define print_hex(x, y) \
        do { \
            unsigned char *hex = x; \
            int i; \
            for (i = 0; i < y; i++) { \
                printf("%02x", hex[i]); \
                if (((i+1) % 32) == 0) \
                    printf("\n"); \
                else if (((i+1) % 4) == 0) \
                    printf(" "); \
            } \
        } while (0)


typedef struct _MASTER_KEY_FILE_T {
    CK_BYTE key[MASTER_KEY_SIZE];
    CK_BYTE sha_hash[SHA1_HASH_SIZE];
} MASTER_KEY_FILE_T;

/* from host_defs.h */
#include "pkcs32.h"
typedef struct _TWEAK_VEC {
    int allow_weak_des;
    int check_des_parity;
    int allow_key_mods;
    int netscape_mods;
} TWEAK_VEC;

typedef struct _TOKEN_DATA {
    CK_TOKEN_INFO_32 token_info;

    CK_BYTE user_pin_sha[3 * DES_BLOCK_SIZE];
    CK_BYTE so_pin_sha[3 * DES_BLOCK_SIZE];
    CK_BYTE next_token_object_name[8];
    TWEAK_VEC tweak_vector;
} TOKEN_DATA;

struct key {
    CK_OBJECT_HANDLE handle;
    CK_ULONG type;
    CK_BYTE *opaque_attr;
    CK_ULONG attr_len;
    CK_CHAR_PTR label;

    struct key *next;
};

struct algo {
    unsigned char *rule_array;
    unsigned char *name;
    long rule_array_count;
};

struct key_count {
    int aes;
    int des;
    int des2;
    int des3;
    int ecc;
    int hmac;
    int rsa;
};

typedef struct _DL_NODE
{
    struct _DL_NODE   *next;
    struct _DL_NODE   *prev;
    void              *data;
} DL_NODE;

typedef struct _TEMPLATE
{
    DL_NODE  *attribute_list;
} TEMPLATE;

typedef void *SESSION;

typedef struct _OBJECT
{
    CK_OBJECT_CLASS   class;
    CK_BYTE           name[8];   // for token objects

    SESSION          *session;   // creator; only for session objects
    TEMPLATE         *template;
    CK_ULONG          count_hi;  // only significant for token objects
    CK_ULONG          count_lo;  // only significant for token objects
    CK_ULONG      index;  // SAB  Index into the SHM
    CK_OBJECT_HANDLE  map_handle;
} OBJECT;

struct secaeskeytoken {
    unsigned char  type;     /* 0x01 for internal key token */
    unsigned char  res0[3];
    unsigned char  version;  /* should be 0x04 */
    unsigned char  res1[1];
    unsigned char  flag;     /* key flags */
    unsigned char  res2[1];
    unsigned long  mkvp;     /* master key verification pattern */
    unsigned char  key[32];  /* key value (encrypted) */
    unsigned char  cv[8];    /* control vector */
    unsigned short bitsize;  /* key bit size */
    unsigned short keysize;  /* key byte size */
    unsigned char  tvv[4];   /* token validation value */
} __packed;

#endif
