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
 * pkcstok_migrate - A tool for migrating ICA, CCA, Soft, and EP11 token
 * repositories to 3.12 format.
 *
 */

#define _GNU_SOURCE
#include <dlfcn.h>
#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <memory.h>
#include <linux/limits.h>
#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <grp.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/mman.h>
#include <pkcs11types.h>
#include "cfgparser.h"
#include "configuration.h"

#include "sw_crypt.h"
#include "defs.h"
#include "host_defs.h"
#include "local_types.h"
#include "h_extern.h"
#include "slotmgr.h" // for ock_snprintf

#define OCK_TOOL
#include "pkcs_utils.h"
#include "pin_prompt.h"


#define TOKVERSION_00         0x00000000
#define TOKVERSION_312        0x0003000C
#define TOKVERSION_312_STRING "3.12"

#define INVALID_TOKEN         "unknown/unsupported"

#define HEADER_LEN            64
#define FOOTER_LEN            16

#define PKCSTOK_MIGRATE_MAX_PATH_LEN    (PATH_MAX - 200)

pkcs_trace_level_t trace_level = TRACE_LEVEL_NONE;

static FILE *open_datastore_file(char *buf, size_t buflen,
                                 const char *datastore, const char *file,
                                 const char *mode)
{
    FILE *res;

    if (ock_snprintf(buf, buflen, "%s/%s", datastore, file) != 0) {
        TRACE_ERROR("Path overflow for datastore file %s\n", file);
        return NULL;
    }
    res = fopen(buf, mode);
    if (!res)
        TRACE_ERROR("fopen(%s) failed, errno=%s\n", buf, strerror(errno));
    return res;
}

static FILE *open_tokenobject(char *buf, size_t buflen,
                              const char *datastore, const char *tokenobj,
                              const char *file, const char *mode)
{
    FILE *res;

    if (ock_snprintf(buf, buflen, "%s/%s/%s", datastore, tokenobj, file) != 0) {
        TRACE_ERROR("Path overflow for token object file %s for token %s\n",
                    file, tokenobj);
        return NULL;
    }
    res = fopen(buf, mode);
    if (!res)
        TRACE_ERROR("fopen(%s) failed, errno=%s\n", buf, strerror(errno));
    return res;
}

struct findstdll {
    char *stdll;
    size_t len;
    int slotnum;
    int activeslot;
    int error;
};

struct parseupdate {
    FILE *f;
    int   slotnum;
    int   activeslot;
    int   tokvers_added;
    int   at_newline;
};

/**
 * Make a 3.12 format OBJECT_PUB:
 *
 *   struct OBJECT_PUB {
 *       //--------------        <--+
 *       u32 tokversion;            | 16-byte header
 *       u8 private_flag;           |
 *       u8 reserved[7];            |
 *       u32 object_len;            |
 *       //--------------        <--+
 *       u8 object[object_len];     | body
 *       //--------------        <--+
 *   };
 */
static CK_RV make_OBJECT_PUB_312(char **obj_new, unsigned int *obj_new_len,
                                 unsigned char *clear, unsigned int clear_len)
{
    struct {
        uint32_t tokversion;
        uint8_t private_flag;
        uint8_t reserved[7];
        uint32_t object_len;
    } header;
    uint32_t total_len;
    char *object;
    CK_RV ret;

    *obj_new = NULL;
    *obj_new_len = 0;

    /* Check parms */
    if (!clear || clear_len == 0) {
        TRACE_ERROR("Error in parms.\n");
        ret = CKR_ARGUMENTS_BAD;
        goto done;
    }

    /* Allocate memory for new OBJECT_PUB */
    total_len = sizeof(header) + clear_len;
    object = malloc(total_len);
    if (object == NULL) {
        TRACE_ERROR("cannot malloc %d bytes.\n", total_len);
        ret = CKR_HOST_MEMORY;
        goto done;
    }

    /* Setup object */
    memset(&header, 0, sizeof(header));
    header.tokversion = htobe32(0x0003000C);
    header.private_flag = 0x00;
    header.object_len = htobe32(clear_len);
    memcpy(object, &header, sizeof(header));
    memcpy(object + sizeof(header), clear, clear_len);

    *obj_new = object;
    *obj_new_len = total_len;

    ret = CKR_OK;

done:

    return ret;
}

/**
 * This function migrates the public obj to the current format.
 */
static CK_RV migrate_public_token_object(const char *data_store, const char *name,
                                         unsigned char *data, unsigned long len)
{
    const char *tokobj = "TOK_OBJ";
    char fname[PATH_MAX];
    char *obj_new = NULL;
    unsigned int obj_new_len;
    FILE *fp = NULL;
    CK_RV ret = 0;

    /* Create new public object */
    ret = make_OBJECT_PUB_312(&obj_new, &obj_new_len, data, len);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot create an OBJECT_PUB_312, ret=%08lX.\n", ret);
        goto done;
    }

    /* Setup file name for new object */
    fp = open_tokenobject(fname, sizeof(fname), data_store, tokobj, name, "w");
    if (!fp) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }
    set_perm(fileno(fp));

    /* Save new object */
    if (fwrite(obj_new, obj_new_len, 1, fp) != 1) {
        TRACE_ERROR("fwrite(%s) failed, errno=%s\n", fname, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    free(obj_new);
    if (fp)
        fclose(fp);

    return ret;
}

/**
 * Make a 3.12 format OBJECT_PRIV:
 *
 *   struct OBJECT_PRIV {
 *       u32 total_len;
 *       --- auth -------           <--+
 *       u32 tokversion                | 64-byte header
 *       u8  private_flag              |
 *       u8  reserved[3]               |
 *       u8  key_wrapped[40]           |
 *       u8  iv[12]                    |
 *       u32 object_len                |
 *       --- auth+enc ---           <--+
 *       u8  object[object_len]        | body
 *       ----------------           <--+
 *       u8 tag[16]                    | 16-byte footer
 *       ----------------           <--+
 *   }
 */
static CK_RV make_OBJECT_PRIV_312(unsigned char **obj_new, unsigned int *obj_new_len,
                                  const char *name, unsigned char *clear,
                                  unsigned int clear_len, const CK_BYTE *masterkey)
{
    struct {
        uint32_t tokversion;
        uint8_t private_flag;
        uint8_t reserved[3];
        uint8_t key_wrapped[40];
        uint8_t iv[12];
        uint32_t object_len;
    } header;
    unsigned char *object = NULL;
    CK_BYTE obj_key[32];
    uint32_t total_len;
    CK_RV ret;

    *obj_new = NULL;
    *obj_new_len = 0;

    /* Check parms */
    if (!name || !clear || clear_len == 0 || !masterkey) {
        TRACE_ERROR("Error in parms.\n");
        ret = CKR_ARGUMENTS_BAD;
        goto done;
    }

    /* An obj name has by definition 8 chars */
    if (strlen(name) != 8) {
        TRACE_ERROR("obj name %s does not have 8 chars, OBJ.IDX probably corrupted.\n",
                    name);
        ret = CKR_ARGUMENTS_BAD;
        goto done;
    }

    /* Allocate memory for new OBJECT_PRIV */
    total_len = sizeof(header) + clear_len + FOOTER_LEN;
    object = malloc(total_len);
    if (object == NULL) {
        TRACE_ERROR("cannot malloc %d bytes.\n", total_len);
        ret = CKR_HOST_MEMORY;
        goto done;
    }

    /* Create new object key */
    ret = local_rng(obj_key, 32);
    if (ret != CKR_OK) {
        TRACE_ERROR("local_rng failed with ret=%08lX.\n", ret);
        goto done;
    }

    /* Setup header */
    memset(&header, 0, sizeof(header));
    header.tokversion = htobe32(0x0003000C);
    header.private_flag = 0x01;
    ret = aes_256_wrap(header.key_wrapped, obj_key, masterkey);
    if (ret != CKR_OK) {
        TRACE_ERROR("aes_256_wrap failed with ret=%08lX.\n", ret);
        goto done;
    }

    memcpy(header.iv, name, 8);
    header.iv[8] = 0;
    header.iv[9] = 0;
    header.iv[10] = 0;
    header.iv[11] = 1;
    header.object_len = htobe32(clear_len);
    memcpy(object, &header, HEADER_LEN);

    /* Encrypt body */
    ret = aes_256_gcm_seal(object + HEADER_LEN, /* ciphertext */
                           object + HEADER_LEN + clear_len, /* tag */
                           object, HEADER_LEN, /* aad */
                           clear, clear_len, /* plaintext */
                           obj_key, /* key */
                           header.iv /* iv */);
    if (ret != CKR_OK) {
        TRACE_ERROR("aes_256_gcm_seal failed with rc=%08lX.\n", ret);
        goto done;
    }

    *obj_new = object;
    *obj_new_len = total_len;
    object = NULL;

    ret = CKR_OK;

done:
    if (object != NULL)
        free(object);

    return ret;
}

/**
 * Decrypts the given version 0.0 private object with given old masterkey.
 *
 *   struct OBJECT_PRIV {
 *      u32 total_len;
 *      u8 private_flag;
 *      //--- enc ---        <- enc_old starts here
 *      u32 object_len;
 *      u8 object[object_len];
 *      u8 sha1[20];
 *      u8 padding[padding_len];
 *   };
 */
static CK_RV decrypt_OBJECT_PRIV_00(unsigned char **clear, unsigned int *clear_len,
                                    unsigned char *enc_old, unsigned int enc_len,
                                    const CK_BYTE *masterkey_old)
{
    CK_ULONG_32 obj_data_len_32;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_BYTE des3_key[MAX_MASTER_KEY_SIZE];
    unsigned char *tmp_clear, *raw_clear;
    CK_ULONG tmp_clear_len;
    CK_RV ret;

    *clear = NULL;
    *clear_len = 0;

    /* Allocate storage for clear output */
    tmp_clear = malloc(enc_len);
    if (!tmp_clear) {
        TRACE_ERROR("Cannot malloc %d bytes, errno=%s.\n",
                    enc_len, strerror(errno));
        ret = CKR_HOST_MEMORY;
        goto done;
    }

    /* Decrypt old object */
    memcpy(des3_key, masterkey_old, MAX_MASTER_KEY_SIZE);
    ret  = sw_des3_cbc_decrypt(enc_old, enc_len, tmp_clear, &tmp_clear_len,
                               (CK_BYTE *)"10293847", des3_key);
    if (ret) {
        TRACE_ERROR("sw_des3_cbc_decrypt failed with ret=%08lX\n", ret);
        goto done;
    }

    /* Validate the length */
    memcpy(&obj_data_len_32, tmp_clear, sizeof(CK_ULONG_32));
    if (obj_data_len_32 >= enc_len) {
        TRACE_ERROR("Decrypted object data length %d inconsistent\n",
                obj_data_len_32);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Validate the hash */
    ret = compute_sha1((char *)(tmp_clear + sizeof(CK_ULONG_32)),
                       obj_data_len_32, (char *)hash_sha);
    if (ret != CKR_OK) {
        TRACE_ERROR("compute_sha1 failed with ret=%08lX\n", ret);
        goto done;
    }

    if (memcmp(tmp_clear + sizeof(CK_ULONG_32) + obj_data_len_32, hash_sha,
               SHA1_HASH_SIZE) != 0) {
        TRACE_ERROR("Stored hash does not match with newly calculated hash.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* At this point, tmp_clear points to the full decrypted obj data:
     *  | 4 bytes len | clear obj[obj_data_len_32] | 20 bytes sha | padding |
     * But the caller only wants clear obj[obj_data_len_32].
     */
    raw_clear = malloc(obj_data_len_32);
    if (!raw_clear) {
        TRACE_ERROR("Cannot malloc %d bytes, errno=%s.\n", enc_len, strerror(errno));
        ret = CKR_HOST_MEMORY;
        goto done;
    }
    memcpy(raw_clear, tmp_clear + sizeof(CK_ULONG_32), obj_data_len_32);

    *clear = raw_clear;
    *clear_len = (unsigned int)obj_data_len_32;

    ret = CKR_OK;

done:

    free(tmp_clear);
    return ret;
}

/**
 * This function migrates the private obj to the current format.
 */
static CK_RV migrate_private_token_object(const char *data_store, const char *name,
                                          unsigned char *data, unsigned long len,
                                          const CK_BYTE *masterkey_old,
                                          const CK_BYTE *masterkey_new)
{
    const char *tokobj = "TOK_OBJ";
    char fname[PATH_MAX];
    unsigned char *clear = NULL;
    unsigned int clear_len;
    unsigned char *obj_new = NULL;
    unsigned int obj_new_len;
    FILE *fp = NULL;
    CK_RV ret;

    /* Decrypt old object */
    ret = decrypt_OBJECT_PRIV_00(&clear, &clear_len, data, len, masterkey_old);
    if (ret != 0) {
        TRACE_ERROR("Cannot decrypt old object with old masterkey, ret=%08lX.\n", ret);
        goto done;
    }

    /* Create new object */
    ret = make_OBJECT_PRIV_312(&obj_new, &obj_new_len, name, clear, clear_len,
                               masterkey_new);
    if (ret != 0) {
        TRACE_ERROR("make_OBJECT_PRIV_312 failed with ret=%08lX.\n", ret);
        goto done;
    }

    /* Create file name for new object */
    fp = open_tokenobject(fname, sizeof(fname), data_store, tokobj, name, "w");
    if (!fp) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }
    set_perm(fileno(fp));

    /* Save new object */
    if (fwrite(obj_new, obj_new_len, 1, fp) != 1) {
        TRACE_ERROR("fwrite(%s) failed, errno=%s\n", fname, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    if (fp) {
        fclose(fp);
        fp = NULL;
    }
    free(clear);
    free(obj_new);

    return ret;
}

/**
 * Reads a format 0.0 object:
 *
 *   struct OBJECT {
 *      u32 total_len;   <- indicates old or new format
 *      u8 private_flag;
 *      u8 object;       <- can be public or private
 *   };
 *
 * The total_len field has been already read to decide whether this
 * object is old or new. Its value is passed via the size parm.
 */
static CK_RV read_object_00(FILE *fp, const char *name, unsigned int size,
                            unsigned char **obj, unsigned int *obj_len,
                            CK_BBOOL *obj_priv)
{
    CK_BBOOL priv;
    size_t read_size;
    unsigned char *buf = NULL;
    CK_RV ret;

    *obj = NULL;
    *obj_len = 0;

    /* Check parms */
    if (!fp || !name) {
        TRACE_ERROR("Arguments bad.\n");
        ret = CKR_ARGUMENTS_BAD;
        goto done;
    }

    /* Read 1-char private flag */
    read_size = fread(&priv, sizeof(CK_BBOOL), 1, fp);
    if (read_size != 1) {
        TRACE_ERROR("Cannot read private flag from old object %s.\n", name);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (size <= sizeof(CK_ULONG_32) + sizeof(CK_BBOOL)) {
        TRACE_ERROR("Improper size of object %s (ignoring it)\n", name);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Allocate buffer for obj */
    size -= sizeof(CK_ULONG_32) + sizeof(CK_BBOOL);
    buf = malloc(size);
    if (!buf) {
        TRACE_ERROR("Cannot malloc %d bytes for object %s.\n", size, name);
        ret = CKR_HOST_MEMORY;
        goto done;
    }

    /* Read obj into buf */
    read_size = fread((char *)buf, 1, size, fp);
    if (read_size != size) {
        TRACE_ERROR("Cannot read old object %s.\n", name);
        ret = CKR_FUNCTION_FAILED;
        free(buf);
        goto done;
    }

    *obj = buf;
    *obj_len = size;
    *obj_priv = priv;

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Reads the token object given by name from given data_store and returns
 * pointers to the object, its length, and indications whether the object
 * is in 0.0 or 3.12 format and whether it's private.
 */
static CK_RV read_object(const char *data_store, const char *name,
                         unsigned char **obj, unsigned int *obj_len,
                         CK_ULONG *version, CK_BBOOL *obj_priv)
{
    char fname[PATH_MAX];
    unsigned int size = 0;
    size_t read_size;
    FILE *fp;
    CK_RV ret;

    *obj = NULL;
    *obj_len = 0;

    /* Open token object file */
    fp = open_tokenobject(fname, sizeof(fname), data_store, "TOK_OBJ", name, "r");
    if (!fp) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Read 32-bit size field */
    read_size = fread(&size, sizeof(CK_ULONG_32), 1, fp);
    if (read_size != 1) {
        TRACE_ERROR("Cannot read %ld bytes from %s, read_size = %ld. "
                    "Object probably empty or corrupted.\n",
                    sizeof(CK_ULONG_32), name, read_size);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if this object is old or current */
    if (size == TOKVERSION_312) {
        TRACE_INFO("%s is already in current format, nothing to do.\n", name);
        ret = CKR_OK;
        *version = TOKVERSION_312;
        goto done;
    }

    /* Read old object */
    *version = TOKVERSION_00;
    ret = read_object_00(fp, name, size, obj, obj_len, obj_priv);
    if (ret != 0) {
        TRACE_ERROR("Cannot read old object %s.\n", name);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    if (fp)
        fclose(fp);

    return ret;
}

/**
 * Migrate the token objects from old to new format. Some of the token objects
 * may be in old and some may be in new format if a previous migration run
 * was interrupted.
 */
static CK_RV migrate_token_objects(const char *data_store, const CK_BYTE *masterkey_old,
                                   const CK_BYTE *masterkey_new,
                                   const CK_BYTE *so_wrap_key,
                                   const CK_BYTE *user_wrap_key)
{
    const char *tokobj = "TOK_OBJ";
    const char *objidx = "OBJ.IDX";
    FILE *fp = NULL;
    unsigned char *obj = NULL;
    unsigned int obj_len;
    char tmp[PATH_MAX];
    char iname[PATH_MAX + 1 + strlen(tokobj) + 1 + strlen(objidx) + 1];
    CK_BBOOL priv;
    CK_ULONG version;
    int count = 0, scount = 0;
    CK_RV ret;

    /* Check parms */
    if (!data_store || !masterkey_old || !masterkey_new || !so_wrap_key
        || !user_wrap_key) {
        TRACE_ERROR("Invalid parms.\n");
        ret = CKR_ARGUMENTS_BAD;
        goto done;
    }

    /* Open index file OBJ.IDX */
    fp = open_tokenobject(iname, sizeof(iname),
                          data_store, tokobj, objidx, "r");
    if (!fp) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Migrate items from OBJ.IDX */
    while (fgets(tmp, PATH_MAX, fp)) {
        tmp[strlen(tmp) - 1] = 0;
        ret = read_object(data_store, tmp, &obj, &obj_len, &version, &priv);
        if (ret == 0 && version == TOKVERSION_00) {
            if (priv) {
                ret = migrate_private_token_object(data_store, tmp,
                                   obj, obj_len, masterkey_old, masterkey_new);
                if (ret != CKR_OK) {
                    TRACE_ERROR("Cannot migrate private object %s, continuing ... \n", tmp);
                } else
                    scount++;
            } else {
                ret = migrate_public_token_object(data_store, tmp,
                                                  obj, obj_len);
                if (ret != CKR_OK) {
                    TRACE_ERROR("Cannot migrate public object %s, continuing ... \n", tmp);
                } else
                    scount++;
            }
        }

        if (obj) {
            free(obj);
            obj = NULL;
        }
        count++;
    }

    /* OBJ.IDX must be at eof here */
    if (!feof(fp)) {
        TRACE_WARN("OBJ.IDX is not at eof after object %s, should not happen.\n",
                   tmp);
    }

    /* Close OBJ.IDX */
    fclose(fp);

    ret = CKR_OK;

    TRACE_NONE("Migrated %d object(s) out of %d object(s).\n", scount, count);

done:

    return ret;
}

/**
 * loads the new aes256 masterkey.
 * The new format defines the MK to be an AES-256 key. Its unencrypted format
 * are just the 32 key bytes. Its encrypted format is a 40 byte key blob
 */
static CK_RV load_masterkey_312(const char *data_store, const char *mkfile,
                                const char *pin, TOKEN_DATA *tokdata,
                                CK_BYTE *masterkey)
{
    FILE *fp = NULL;
    CK_RV ret;
    int rc;
    char fname[PATH_MAX];
    unsigned char inbuf[40];
    unsigned char wrap_key[32];

    /* Open file */
    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/%s", data_store, mkfile);
    fp = fopen(fname, "r");
    if (!fp) {
        TRACE_ERROR("fopen(%s) failed, errno=%s\n", fname, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Read wrapped key from file */
    rc = fread(inbuf, sizeof(inbuf), 1, fp);
    if (rc != 1) {
        TRACE_ERROR("Cannot read %ld bytes from %s.\n", sizeof(inbuf), fname);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Derive wrapping key from pin and public info in TOKEN_DATA */
    if (strstr(mkfile,"MK_SO")) {
        rc = PKCS5_PBKDF2_HMAC(pin, strlen(pin),
                               tokdata->dat.so_wrap_salt, 64,
                               tokdata->dat.so_wrap_it, EVP_sha512(),
                               256 / 8, wrap_key);
    } else {
        rc = PKCS5_PBKDF2_HMAC(pin, strlen(pin),
                               tokdata->dat.user_wrap_salt, 64,
                               tokdata->dat.user_wrap_it, EVP_sha512(),
                               256 / 8, wrap_key);
    }
    if (rc != 1) {
        TRACE_INFO("PKCS5_PBKDF2_HMAC returned rc=%08X.\n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Decrypt buffer with pin-related wrapping key */
    rc = aes_256_unwrap(masterkey, inbuf, wrap_key);
    if (rc != CKR_OK) {
        TRACE_ERROR("aes_256_unwrap failed with rc=%08X.\n", rc);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    if (fp)
        fclose(fp);

    return ret;
}

/**
 * loads the old des3 masterkey from given file with given PIN.
 * The format is:
 *
 *   struct MK {
 *     u8 MK [24 or 64 (cca)];
 *     u8 sha1 [20];
 *     u8 padding[4];
 *   };
 */
static CK_RV load_masterkey_00(const char *mkfile, const char *pin,
                               CK_BYTE *masterkey)
{
    CK_BYTE des3_key[3 * DES_KEY_SIZE];
    char hash_sha[SHA1_HASH_SIZE];
    char pin_md5_hash[MD5_HASH_SIZE];
    unsigned char *cipher = NULL;
    unsigned char *clear = NULL;
    unsigned long cipher_len, clear_len;
    CK_ULONG master_key_len = 0L;
    int file_size = 0;

    CK_RV ret;
    int rc;
    FILE *fp = NULL;

    fp = fopen(mkfile, "r");
    if (!fp) {
        TRACE_ERROR("fopen(%s) failed, errno=%s\n", mkfile, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    /* Determine the master key length */
    fseek(fp, 0L, SEEK_END);
    file_size = ftell(fp);
    switch (file_size) {
    case MK_FILE_SIZE_00_CCA: /* CCA token */
        master_key_len = MASTER_KEY_SIZE_CCA;
        break;
    case MK_FILE_SIZE_00: /* All other tokens */
        master_key_len = MASTER_KEY_SIZE;
        break;
    default:
        /* Unknown MK format, should not occur. */
        TRACE_ERROR("%s has an unknown file size of %d bytes. Should be either 48 or 88 bytes.\n",
                    mkfile, file_size);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }
    rewind(fp);

    /* Read file contents */
    clear_len = cipher_len =
            (master_key_len + SHA1_HASH_SIZE +
            (DES_BLOCK_SIZE - 1)) & ~(DES_BLOCK_SIZE - 1);

    cipher = malloc(cipher_len);
    clear = malloc(clear_len);
    if (cipher == NULL || clear == NULL) {
        ret = CKR_HOST_MEMORY;
        goto done;
    }

    rc = fread(cipher, cipher_len, 1, fp);
    if (rc != 1) {
        TRACE_ERROR("Cannot read %ld bytes from %s\n", cipher_len, mkfile);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Decrypt the masterkey */
    ret = compute_md5((char *)pin, strlen(pin), pin_md5_hash);
    if (ret) {
        TRACE_ERROR("Error calculating MD5 of PIN, ret=%08lX\n", ret);
        goto done;
    }

    memcpy(des3_key, pin_md5_hash, MD5_HASH_SIZE);
    memcpy(des3_key + MD5_HASH_SIZE, pin_md5_hash, DES_KEY_SIZE);

    ret = sw_des3_cbc_decrypt(cipher, cipher_len, clear,
                              &clear_len, (unsigned char *) "12345678",
                              des3_key);
    if (ret != CKR_OK) {
        TRACE_ERROR("failed to decrypt master key file after read, ret=%08lX\n", ret);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* compare the hashes to verify integrity */
    ret = compute_sha1((char *)clear, master_key_len, hash_sha);
    if (ret) {
        TRACE_ERROR("Failed to compute sha1 for masterkey, ret=%08lX\n", ret);
        goto done;
    }

    if (memcmp(hash_sha, clear + master_key_len, SHA1_HASH_SIZE) != 0) {
        TRACE_ERROR("%s appears to be tampered! Cannot migrate.\n", mkfile);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    memcpy(masterkey, clear, master_key_len);
    ret = 0;

done:
    if (fp)
        fclose(fp);
    free(clear);
    free(cipher);

    return ret;
}

/**
 * Check if the given conf_dir exists and contains the opencryptoki.conf.
 */
static CK_BBOOL conffile_exists(const char *conf_dir)
{
    char fname[PATH_MAX];
    struct stat statbuf;
    DIR *dir;

    TRACE_INFO("Checking if config file exists in %s ...\n", conf_dir);
    dir = opendir(conf_dir);
    if (dir == NULL) {
        TRACE_INFO("Cannot open %s.\n", conf_dir);
        return CK_FALSE;
    }

    /* Check if opencryptoki.conf exists */
    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/opencryptoki.conf", conf_dir);
    if (stat(fname, &statbuf) != 0) {
        TRACE_INFO("Cannot find %s.\n", fname);
        closedir(dir);
        return CK_FALSE;
    }
    closedir(dir);

    return CK_TRUE;
}

/**
 * Check if the given data_store directory exists.
 */
static CK_BBOOL datastore_exists(const char *data_store)
{
    DIR *dir;

    TRACE_INFO("Checking if datastore %s exists ...\n", data_store);
    dir = opendir(data_store);
    if (dir == NULL) {
        TRACE_INFO("Cannot open %s.\n", data_store);
        return CK_FALSE;
    }
    closedir(dir);

    return CK_TRUE;
}

/**
 *
 */
static CK_RV load_MK_SO_00(const char *data_store, const char *sopin,
                           CK_BYTE *masterkey)
{
    const char *mkso = "MK_SO";
    char fname[PATH_MAX];
    CK_RV ret;

    /* Get masterkey from MK_SO. This also verifies SO PIN is correct */
    memset(masterkey, 0, MAX_MASTER_KEY_SIZE);
    if (ock_snprintf(fname, sizeof(fname), "%s/%s", data_store, mkso) != 0) {
        TRACE_ERROR("path name for old MK_SO too long\n");
        return CKR_FUNCTION_FAILED;
    }
    ret = load_masterkey_00(fname, sopin, masterkey);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load old masterkey from MK_SO, ret=%08lX.\n", ret);
        // We cannot do anything more here, even when some objs are still old.
        // We would need the old key in order to open an old obj.
    }

    return ret;
}

/**
 *
 */
static CK_RV load_MK_USER_00(const char *data_store, const char *userpin,
                             CK_BYTE *masterkey)
{
    const char *mkuser = "MK_USER";
    char fname[PATH_MAX];
    CK_RV ret;

    /* Get masterkey from MK_USER. This also verifies user PIN is correct */
    memset(masterkey, 0, MAX_MASTER_KEY_SIZE);
    if (ock_snprintf(fname, sizeof(fname), "%s/%s", data_store, mkuser) != 0) {
        TRACE_ERROR("path name for old MK_USER too long\n");
        return CKR_FUNCTION_FAILED;
    }
    ret = load_masterkey_00(fname, userpin, masterkey);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load old masterkey from MK_USER, ret=%08lX.\n", ret);
    }

    return ret;
}

/**
 *
 */
static CK_RV load_MK_SO_312(const char *data_store, const char *sopin,
                            TOKEN_DATA *tokdata, CK_BYTE *masterkey)
{
    CK_RV ret;

    /* Get masterkey from MK_SO_312. This also verifies SO PIN is correct */
    memset(masterkey, 0, MAX_MASTER_KEY_SIZE);
    ret = load_masterkey_312(data_store, "MK_SO_312", sopin, tokdata, masterkey);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load masterkey from MK_SO_312, ret=%08lX.\n", ret);
    }

    return ret;
}

/**
 *
 */
static CK_RV load_MK_USER_312(const char *data_store, const char *userpin,
                              TOKEN_DATA *tokdata, CK_BYTE *masterkey)
{
    CK_RV ret;

    /* Get masterkey from MK_USER_312. This also verifies user PIN is correct */
    memset(masterkey, 0, MAX_MASTER_KEY_SIZE);
    ret = load_masterkey_312(data_store, "MK_USER_312", userpin, tokdata, masterkey);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load masterkey from MK_USER_312, ret=%08lX.\n", ret);
    }

    return ret;
}

/**
 * Loads the NVTOK.DAT and returns the TOKEN_DATA struct.
 */
static CK_RV load_NVTOK_DAT(const char *data_store, const char *nvtok_name,
                            TOKEN_DATA *td)
{
    char fname[PATH_MAX];
    struct stat stbuf;
    int fd;
    size_t tdlen;
    FILE *fp = NULL;
    CK_RV ret;

    /* Check parms */
    if (!data_store || !nvtok_name || !td) {
        ret = CKR_ARGUMENTS_BAD;
        goto done;
    }

    /* Read the NVTOK.DAT */
    fp = open_datastore_file(fname, sizeof(fname), data_store, nvtok_name, "r");
    if (!fp)
        return CKR_FUNCTION_FAILED;

    fd = fileno(fp);
    if ((fstat(fd, &stbuf) != 0) || (!S_ISREG(stbuf.st_mode))) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if this NVTOK.DAT is old or new */
    if (stbuf.st_size == sizeof(TOKEN_DATA_OLD)) {
        /* old data store/pin format */
        tdlen = sizeof(TOKEN_DATA_OLD);
    } else if (stbuf.st_size == sizeof(TOKEN_DATA)) {
        /* new data store/pin format */
        tdlen = sizeof(TOKEN_DATA);
    } else {
        TRACE_ERROR("%s has an invalid size of %ld bytes. Neither old nor new token format.\n",
                    fname, stbuf.st_size);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Read TOKEN_DATA */
    ret = fread(td, tdlen, 1, fp);
    if (ret != 1) {
        TRACE_ERROR("Cannot read %s, errno=%s\n", fname, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (stbuf.st_size == sizeof(TOKEN_DATA)) {
        /* The 312 version always uses big endian */
        td->token_info.flags = be32toh(td->token_info.flags);
        td->token_info.ulMaxSessionCount
          = be32toh(td->token_info.ulMaxSessionCount);
        td->token_info.ulSessionCount
          = be32toh(td->token_info.ulSessionCount);
        td->token_info.ulMaxRwSessionCount
          = be32toh(td->token_info.ulMaxRwSessionCount);
        td->token_info.ulRwSessionCount
          = be32toh(td->token_info.ulRwSessionCount);
        td->token_info.ulMaxPinLen = be32toh(td->token_info.ulMaxPinLen);
        td->token_info.ulMinPinLen = be32toh(td->token_info.ulMinPinLen);
        td->token_info.ulTotalPublicMemory
          = be32toh(td->token_info.ulTotalPublicMemory);
        td->token_info.ulFreePublicMemory
          = be32toh(td->token_info.ulFreePublicMemory);
        td->token_info.ulTotalPrivateMemory
          = be32toh(td->token_info.ulTotalPrivateMemory);
        td->token_info.ulFreePrivateMemory
          = be32toh(td->token_info.ulFreePrivateMemory);
        td->tweak_vector.allow_weak_des
          = be32toh(td->tweak_vector.allow_weak_des);
        td->tweak_vector.check_des_parity
          = be32toh(td->tweak_vector.check_des_parity);
        td->tweak_vector.allow_key_mods
          = be32toh(td->tweak_vector.allow_key_mods);
        td->tweak_vector.netscape_mods
          = be32toh(td->tweak_vector.netscape_mods);
        td->dat.version = be32toh(td->dat.version);
        td->dat.so_login_it = be64toh(td->dat.so_login_it);
        td->dat.user_login_it = be64toh(td->dat.user_login_it);
        td->dat.so_wrap_it = be64toh(td->dat.so_wrap_it);
        td->dat.user_wrap_it = be64toh(td->dat.user_wrap_it);
    }

    ret = CKR_OK;

done:

    if (fp)
        fclose(fp);

    return ret;
}

/**
 * Strip trailing chars from given string.
 */
static char *strip_trailing_chars(char *s, int slen, char c)
{
    int i;

    if (!s || slen == 0)
        return s;

    for (i = slen - 1; i >= 0; i--) {
        if (s[i] == c)
            s[i] = '\0';
        else
            break;
    }

    return s;
}

/**
 * Read the token info from NVTOK.DAT.
 */
static CK_RV get_token_info(const char *data_store, CK_TOKEN_INFO_32 *tokinfo)
{
    TOKEN_DATA tokdata;
    CK_RV ret;

    TRACE_INFO("Reading token info from NVTOK.DAT ...\n");

    ret = load_NVTOK_DAT(data_store, "NVTOK.DAT", &tokdata);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load NVTOK.DAT, datastore inconsistent.\n");
        return ret;
    }

    memcpy(tokinfo, &(tokdata.token_info), sizeof(CK_TOKEN_INFO_32));

    return CKR_OK;
}

static void config_parse_error(int line, int col, const char *msg)
{
    fprintf(stderr, "Error parsing config file: line %d column %d: %s\n", line,
            col, msg);
}

static struct ConfigBaseNode *config_parse(const char *config_file,
                                           CK_BBOOL track_comments)
{
    FILE *file;
    struct ConfigBaseNode *config = NULL;
    int ret;

    file = fopen(config_file, "r");
    if (file == NULL)
        return NULL;

    ret = parse_configlib_file(file, &config, config_parse_error, track_comments);
    fclose(file);
    if (ret != 0)
        return NULL;

    return config;
}

/**
 * Identify the token that belongs to the given slot ID.
 */
static CK_RV identify_token(CK_SLOT_ID slot_id, char *conf_dir,
                            char *dll_name, size_t dll_name_len)
{
    char conf_file[PATH_MAX];
    CK_RV ret;
    struct ConfigBaseNode *config = NULL, *c;
    struct ConfigIdxStructNode *slot;
    size_t max_cpy_size;
    char *stdll;

    max_cpy_size = dll_name_len > sizeof(((Slot_Info_t_64 *)NULL)->dll_location)
        ? sizeof(((Slot_Info_t_64 *)NULL)->dll_location) : dll_name_len;

    TRACE_INFO("Identifying the token that belongs to slot %ld ...\n", slot_id);

    if (slot_id >= NUMBER_SLOTS_MANAGED) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Open conf file */
    if (ock_snprintf(conf_file, PATH_MAX, "%s/%s",
                     conf_dir, "opencryptoki.conf") != 0) {
        TRACE_ERROR("Path name overflow for config file opencryptoki.conf\n");
        return CKR_FUNCTION_FAILED;
    }

    config = config_parse(conf_file, FALSE);
    if (config == NULL) {
        TRACE_ERROR("failed to parse config file %s\n", conf_file);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    slot = confignode_findidx(config, "slot", slot_id);
    if (slot == NULL) {
        TRACE_ERROR("failed to find slot %lu in config file %s\n", slot_id,
                    conf_file);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    c = confignode_find(slot->value, "stdll");
    if (c == NULL || (stdll = confignode_getstr(c)) == NULL) {
        TRACE_ERROR("failed to find stdll for slot %lu in config file %s\n",
                    slot_id, conf_file);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    strncpy(dll_name, stdll, max_cpy_size);
    dll_name[max_cpy_size - 1] = 0;

    ret = CKR_OK;

done:
    confignode_deepfree(config);

    return ret;
}

/**
 * derives the SO wrap key from the given SO pin and given public
 * info in NVTOK.DAT.
 */
static CK_RV derive_so_wrap_key_312(const char *sopin, TOKEN_DATA *tokdata,
                                    CK_BYTE *so_wrap_key)
{
    CK_RV ret;

    ret = PKCS5_PBKDF2_HMAC(sopin, strlen(sopin),
                            tokdata->dat.so_wrap_salt, 64,
                            tokdata->dat.so_wrap_it, EVP_sha512(),
                            256 / 8, so_wrap_key);
    if (ret != 1) {
        TRACE_ERROR("PBKDF2 failed.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    return ret;
}

/**
 * derives the user wrap key from the given user pin and given public
 * info in NVTOK.DAT.
 */
static CK_RV derive_user_wrap_key_312(const char *userpin, TOKEN_DATA *tokdata,
                                      CK_BYTE *user_wrap_key)
{
    CK_RV ret;

    ret = PKCS5_PBKDF2_HMAC(userpin, strlen(userpin),
                            tokdata->dat.user_wrap_salt, 64,
                            tokdata->dat.user_wrap_it, EVP_sha512(),
                            256 / 8, user_wrap_key);
    if (ret != 1) {
        TRACE_ERROR("PBKDF2 failed.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Activates the new repository by deleting the old MK_USER, MK_SO, and
 * NVTOK.DAT, and renaming the new MK_SO_312, MK_USER_312, NVTOK.DAT_312 to
 * their normal names.
 */
static CK_RV cleanup_repository_backup(const char *data_store)
{
    static char *names[] = { "MK_SO", "MK_USER", "NVTOK.DAT" };
    int num_names = sizeof(names) / sizeof(char *);
    char fname1[PATH_MAX + 9 + 1]; // satisfy compiler warning
    char fname2[PATH_MAX + 1 + 1]; // satisfy compiler warning
    int i, rc;
    CK_RV ret;

    /* Delete old files */
    for (i = 0; i < num_names; i++) {
        snprintf(fname1, sizeof(fname1), "%s/%s", data_store, names[i]);
        rc = remove(fname1);
        if (rc) {
            TRACE_ERROR("Cannot delete old file %s.\n", fname1);
            ret = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    /* Rename new files */
    for (i = 0; i < num_names; i++) {
        snprintf(fname1, sizeof(fname1), "%s/%s_312", data_store, names[i]);
        snprintf(fname2, sizeof(fname2), "%s/%s", data_store, names[i]);
        rc = rename(fname1, fname2);
        if (rc) {
            TRACE_ERROR("Cannot rename new file %s.\n", fname1);
            ret = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Migrates the repository. This process may be interrupted at any time and
 * must be able to resume until the complete repository is successfully
 * migrated. This especially requires to keep the old keys until
 * everything is done.
 */
static CK_RV migrate_repository(const char *data_store, const char *sopin,
                         const char *userpin)
{
    CK_BYTE so_masterkey_old[MAX_MASTER_KEY_SIZE];
    CK_BYTE so_masterkey_new[MAX_MASTER_KEY_SIZE];
    CK_BYTE user_masterkey_old[MAX_MASTER_KEY_SIZE];
    CK_BYTE user_masterkey_new[MAX_MASTER_KEY_SIZE];
    CK_BYTE so_wrap_key[32];
    CK_BYTE user_wrap_key[32];
    CK_RV ret;
    TOKEN_DATA tokdata;

    TRACE_INFO("Migrating the repository ...\n");

    /* Load NVTOK.DAT_312, which was either created before or exists from a
     * previous interrupted run. So tokdata definitely contains the 3.12
     * extension.
     */
    ret = load_NVTOK_DAT(data_store, "NVTOK.DAT_312", &tokdata);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load NVTOK.DAT_312, ret=%08lX.\n", ret);
        goto done;
    }

    ret = load_MK_SO_00(data_store, sopin, so_masterkey_old);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load old masterkey, ret=%08lX.\n", ret);
        goto done;
    }

    ret = load_MK_USER_00(data_store, userpin, user_masterkey_old);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load old masterkey, ret=%08lX.\n", ret);
        goto done;
    }

    if (memcmp(so_masterkey_old, user_masterkey_old, MAX_MASTER_KEY_SIZE) != 0) {
        TRACE_ERROR("MK_SO and MK_USER are inconsistent, got different MKs.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = load_MK_SO_312(data_store, sopin, &tokdata, so_masterkey_new);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load new masterkey from MK_SO_312, ret=%08lX.\n", ret);
        goto done;
    }

    ret = load_MK_USER_312(data_store, userpin, &tokdata, user_masterkey_new);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load new masterkey from MK_USER_312, ret=%08lX.\n", ret);
        goto done;
    }

    if (memcmp(so_masterkey_new, user_masterkey_new, MAX_MASTER_KEY_SIZE) != 0) {
        TRACE_ERROR("MK_SO_312 and MK_USER_312 are inconsistent, got different MKs.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* This function needs a new NVTOK.DAT with the public salt and icount */
    ret = derive_so_wrap_key_312(sopin, &tokdata, so_wrap_key);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot create new so_wrap_key, ret=%08lX.\n", ret);
        goto done;
    }

    /* This function needs a new NVTOK.DAT with the public salt and icount */
    ret = derive_user_wrap_key_312(userpin, &tokdata, user_wrap_key);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot create new user_wrap_key, ret=%08lX.\n", ret);
        goto done;
    }

    /* Now do the migration */
    ret = migrate_token_objects(data_store, so_masterkey_old, so_masterkey_new,
                                so_wrap_key, user_wrap_key);
    if (ret != CKR_OK) {
        TRACE_ERROR("Migrating token objects failed with ret=%08lX.\n", ret);
        goto done;
    }

    /* Remove temp files in backup */
    ret = cleanup_repository_backup(data_store);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cleanup repository backup failed with ret=%08lX.\n", ret);
        goto done;
    }

done:

    return ret;
}

/**
 * creates a MK_USER_312 file containing the new user MK.
 */
static CK_RV create_MK_USER_312(const char *data_store, const char *userpin,
                                const CK_BYTE *masterkey,
                                TOKEN_DATA *tokdata)
{
    const char *mkuser = "MK_USER_312";
    char fname[PATH_MAX];
    CK_BYTE user_wrap_key[32];
    CK_BYTE outbuf[40];
    FILE *fp = NULL;
    size_t rv;
    CK_RV ret;

    /* Create user wrap key */
    ret = derive_user_wrap_key_312(userpin, tokdata, (unsigned char *)&user_wrap_key);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot derive user wrap key, ret=%08lX.\n", ret);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Wrap user MK with user_wrap_key */
    ret = aes_256_wrap(outbuf, masterkey, user_wrap_key);
    if (ret != CKR_OK)
        goto done;

    /* Create file MK_USER_312 */
    fp = open_datastore_file(fname, sizeof(fname), data_store, mkuser, "w");
    if (!fp) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }
    set_perm(fileno(fp));

    rv = fwrite(outbuf, sizeof(outbuf), 1, fp);
    if (rv != 1) {
        TRACE_ERROR("fwrite(%s) failed, errno=%s.\n", fname, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    if (fp)
        fclose(fp);

    return ret;
}

/**
 * creates a MK_SO_312 file containing the new SO MK.
 */
static CK_RV create_MK_SO_312(const char *data_store, const char *sopin,
                              const CK_BYTE *masterkey,
                              TOKEN_DATA *tokdata)
{
    const char *mkso = "MK_SO_312";
    char fname[PATH_MAX];
    CK_BYTE outbuf[40];
    CK_BYTE so_wrap_key[32];
    FILE *fp = NULL;
    size_t rv;
    CK_RV ret;

    /* Derive so wrap key from sopin and tokdata */
    ret = derive_so_wrap_key_312(sopin, tokdata, so_wrap_key);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot derive new so wrap key, ret=%08lX.\n", ret);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Wrap masterkey with SO_wrap_key */
    ret = aes_256_wrap(outbuf, masterkey, so_wrap_key);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot wrap masterkey with so wrap key, ret=%08lX.\n", ret);
        goto done;
    }

    /* Create file MK_SO_312 */
    fp = open_datastore_file(fname, sizeof(fname), data_store, mkso, "w");
    if (!fp) {
        TRACE_ERROR("fopen(%s) failed, errno=%s\n", fname, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }
    set_perm(fileno(fp));

    rv = fwrite(outbuf, sizeof(outbuf), 1, fp);
    if (rv != 1) {
        TRACE_ERROR("fwrite(%s) failed, errno=%s.\n", fname, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    if (fp)
        fclose(fp);

    return ret;
}

/**
 * reads the old NVTOK.DAT and returns its contents:
 */
static CK_RV read_NVTOK_DAT_00(const char *data_store, TOKEN_DATA *tokdata)
{
    FILE *fp;
    const char *nvtok = "NVTOK.DAT";
    char fname[PATH_MAX];
    struct stat stbuf;
    int fd;
    CK_RV ret;

    /* Check parms */
    if (!data_store || !tokdata) {
        return CKR_ARGUMENTS_BAD;
    }

    /* Read the old NVTOK.DAT */
    fp = open_datastore_file(fname, sizeof(fname), data_store, nvtok, "r");
    if (!fp)
        return CKR_FUNCTION_FAILED;

    fd = fileno(fp);
    if ((fstat(fd, &stbuf) != 0) || (!S_ISREG(stbuf.st_mode))) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Ensure that this NVTOK.DAT is in fact old */
    if (stbuf.st_size != sizeof(TOKEN_DATA_OLD)) {
        TRACE_ERROR("%s has an invalid size of %ld bytes.\n", fname, stbuf.st_size);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Read TOKEN_DATA_OLD */
    ret = fread(tokdata, sizeof(TOKEN_DATA_OLD), 1, fp);
    if (ret != 1) {
        TRACE_ERROR("Cannot read %s, errno=%s\n", fname, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    if (fp)
        fclose(fp);

    return ret;
}

/**
 * creates the additions for new format.
 */
static CK_RV create_TOKEN_DATA_VERSION(const char *sopin, const char *userpin,
                                       TOKEN_DATA *tokdata)
{
    CK_RV ret;
    int rc;

    tokdata->dat.version = TOKVERSION_312;

    tokdata->dat.so_login_it = SO_KDF_LOGIN_IT;
    memcpy(tokdata->dat.so_login_salt, SO_KDF_LOGIN_PURPOSE, 32);
    ret = local_rng(tokdata->dat.so_login_salt + 32, 32);
    if (ret != CKR_OK) {
        TRACE_ERROR("local_rng returned %lX\n", ret);
        goto done;
    }
    rc = PKCS5_PBKDF2_HMAC(sopin, strlen(sopin),
                           tokdata->dat.so_login_salt, 64,
                           tokdata->dat.so_login_it, EVP_sha512(),
                           256 / 8, tokdata->dat.so_login_key);
    if (rc != 1) {
        TRACE_ERROR("Error: PKCS5_PBKDF2_HMAC\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    tokdata->dat.so_wrap_it = SO_KDF_WRAP_IT;
    memcpy(tokdata->dat.so_wrap_salt, SO_KDF_WRAP_PURPOSE, 32);
    ret = local_rng(tokdata->dat.so_wrap_salt + 32, 32);
    if (ret != CKR_OK) {
        TRACE_ERROR("local_rng returned %lX\n", ret);
        goto done;
    }

    tokdata->dat.user_login_it = USER_KDF_LOGIN_IT;
    memcpy(tokdata->dat.user_login_salt, USER_KDF_LOGIN_PURPOSE, 32);
    ret = local_rng(tokdata->dat.user_login_salt + 32, 32);
    if (ret != CKR_OK) {
        TRACE_ERROR("local_rng returned %lX\n", ret);
        goto done;
    }
    rc = PKCS5_PBKDF2_HMAC(userpin, strlen(userpin),
                           tokdata->dat.user_login_salt, 64,
                           tokdata->dat.user_login_it, EVP_sha512(),
                           256 / 8, tokdata->dat.user_login_key);
    if (rc != 1) {
        TRACE_ERROR("Error: PKCS5_PBKDF2_HMAC\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    tokdata->dat.user_wrap_it = USER_KDF_WRAP_IT;
    memcpy(tokdata->dat.user_wrap_salt, USER_KDF_WRAP_PURPOSE, 32);
    ret = local_rng(tokdata->dat.user_wrap_salt + 32, 32);
    if (ret != CKR_OK) {
        TRACE_ERROR("local_rng returned %lX\n", ret);
        goto done;
    }

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Creates the new NVTOK.DAT which now contains the public salt and iteration
 * count values that are necessary for re-deriving the pin-related
 * wrapping keys.
 */
static CK_RV create_NVTOK_DAT_312(const char *data_store, const char *sopin,
                                  const char *userpin, TOKEN_DATA *tokdata)
{
    const char *nvtok = "NVTOK.DAT_312";
    char fname[PATH_MAX];
    TOKEN_DATA be_tokdata;
    FILE *fp = NULL;
    CK_RV ret;
    size_t rc;

    /* Check parms */
    if (!data_store || !sopin || !userpin || !tokdata) {
        TRACE_ERROR("invalid parms.\n");
        ret = CKR_ARGUMENTS_BAD;
        goto done;
    }

    /* Create new file NVTOK.DAT_312 */
    fp = open_datastore_file(fname, sizeof(fname), data_store, nvtok, "w");
    if (!fp) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }
    set_perm(fileno(fp));

    /* Get contents from old NVTOK.DAT */
    ret = read_NVTOK_DAT_00(data_store, tokdata);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot read old NVTOK.DAT, ret=%08lX\n", ret);
        goto done;
    }

    /* Create additions for new format */
    ret = create_TOKEN_DATA_VERSION(sopin, userpin, tokdata);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot create TOKEN_DATA_VERSION struct, ret=%08lX\n", ret);
        goto done;
    }

    /* The 312 version always uses big endian */
    memcpy(&be_tokdata, tokdata, sizeof(TOKEN_DATA));
    be_tokdata.token_info.flags = htobe32(tokdata->token_info.flags);
    be_tokdata.token_info.ulMaxSessionCount
      = htobe32(tokdata->token_info.ulMaxSessionCount);
    be_tokdata.token_info.ulSessionCount
      = htobe32(tokdata->token_info.ulSessionCount);
    be_tokdata.token_info.ulMaxRwSessionCount
      = htobe32(tokdata->token_info.ulMaxRwSessionCount);
    be_tokdata.token_info.ulRwSessionCount
      = htobe32(tokdata->token_info.ulRwSessionCount);
    be_tokdata.token_info.ulMaxPinLen = htobe32(tokdata->token_info.ulMaxPinLen);
    be_tokdata.token_info.ulMinPinLen = htobe32(tokdata->token_info.ulMinPinLen);
    be_tokdata.token_info.ulTotalPublicMemory
      = htobe32(tokdata->token_info.ulTotalPublicMemory);
    be_tokdata.token_info.ulFreePublicMemory
      = htobe32(tokdata->token_info.ulFreePublicMemory);
    be_tokdata.token_info.ulTotalPrivateMemory
      = htobe32(tokdata->token_info.ulTotalPrivateMemory);
    be_tokdata.token_info.ulFreePrivateMemory
      = htobe32(tokdata->token_info.ulFreePrivateMemory);
    be_tokdata.tweak_vector.allow_weak_des
      = htobe32(tokdata->tweak_vector.allow_weak_des);
    be_tokdata.tweak_vector.check_des_parity
      = htobe32(tokdata->tweak_vector.check_des_parity);
    be_tokdata.tweak_vector.allow_key_mods
      = htobe32(tokdata->tweak_vector.allow_key_mods);
    be_tokdata.tweak_vector.netscape_mods
      = htobe32(tokdata->tweak_vector.netscape_mods);
    be_tokdata.dat.version = htobe32(tokdata->dat.version);
    be_tokdata.dat.so_login_it = htobe64(tokdata->dat.so_login_it);
    be_tokdata.dat.user_login_it = htobe64(tokdata->dat.user_login_it);
    be_tokdata.dat.so_wrap_it = htobe64(tokdata->dat.so_wrap_it);
    be_tokdata.dat.user_wrap_it = htobe64(tokdata->dat.user_wrap_it);

    /* Write converted token data into NVTOK.DAT_312 */
    rc = fwrite(&be_tokdata, sizeof(TOKEN_DATA), 1, fp);
    if (rc != 1) {
        TRACE_ERROR("fwrite(%s) failed, errno=%s.\n", fname, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    if (fp)
        fclose(fp);

    return ret;
}

/**
 * Creates new token keys MK_USER_312 and MK_SO_312. The old keys in
 * MK_USER and MK_SO are kept until the migration is fully completed.
 * Then the old keys are deleted and the new keys are renamed.
 */
static CK_RV create_token_keys_312(const char *data_store, const char *sopin,
                                   const char *userpin)
{
    unsigned char masterkey[32];
    TOKEN_DATA tokdata;
    CK_RV ret = CKR_OK;

    TRACE_INFO("Creating new v3.12 MK_SO, MK_USER, and NVTOK.DAT ...\n");

    /* Create master key */
    ret = local_rng(masterkey, 32);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot create master key, ret=%08lX\n", ret);
        goto done;
    }

    ret = create_NVTOK_DAT_312(data_store, sopin, userpin, &tokdata);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot create NVTOK.DAT_312, ret=%08lX\n", ret);
        goto done;
    }

    ret = create_MK_SO_312(data_store, sopin, masterkey, &tokdata);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot create MK_SO_312, ret=%08lX\n", ret);
        goto done;
    }

    ret = create_MK_USER_312(data_store, userpin, masterkey, &tokdata);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot create MK_USER_312, ret=%08lX\n", ret);
        goto done;
    }

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Count the objs in the data_store and return the number of total objs
 * and number of old objs.
 */
static CK_RV count_objects(const char *data_store, unsigned int *num_objs,
                           unsigned int *num_old_objs)
{
    char tmp[PATH_MAX], iname[PATH_MAX];
    unsigned char *obj = NULL;
    unsigned int obj_len;
    CK_ULONG version;
    CK_BBOOL priv;
    FILE *fp;
    CK_RV ret;

    *num_objs = 0;
    *num_old_objs = 0;

    /* Open index file OBJ.IDX */
    snprintf(iname, sizeof(iname), "%s/TOK_OBJ/OBJ.IDX", data_store);
    fp = fopen((char *) iname, "r");
    if (!fp) {
        TRACE_INFO("Cannot open %s, datastore probably empty.\n", iname);
        ret = CKR_OK;
        goto done;
    }

    /* Count objects and old objects */
    while (fgets(tmp, PATH_MAX, fp)) {
        tmp[strlen(tmp) - 1] = 0;
        (*num_objs)++;
        ret = read_object(data_store, tmp, &obj, &obj_len, &version, &priv);
        if (ret == 0 && version == TOKVERSION_00)
            (*num_old_objs)++;
        if (obj) {
            free(obj);
            obj = NULL;
        }
    }

    /* OBJ.IDX must be at eof here */
    if (!feof(fp)) {
        TRACE_WARN("OBJ.IDX is not at eof after object %s, should not happen.\n",
                   tmp);
    }

    fclose(fp);
    ret = CKR_OK;

done:

    return ret;
}

/**
 * Set parameter "*new" to true if the NVTOK.DAT in the given data store
 * is on 3.12 level, or false otherwise.
 */
static CK_RV NVTOK_DAT_is_312(const char *data_store, CK_BBOOL *new)
{
    CK_RV ret;
    char fname[PATH_MAX];
    struct stat stbuf;
    int fd;
    FILE *fp = NULL;

    *new = CK_FALSE;

    /* Read the NVTOK.DAT */
    snprintf(fname, PATH_MAX, "%s/NVTOK.DAT", data_store);
    fp = fopen((char *)fname, "r");
    if (!fp) {
        TRACE_ERROR("Cannot open %s, errno=%s\n", fname, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    fd = fileno(fp);
    if ((fstat(fd, &stbuf) != 0) || (!S_ISREG(stbuf.st_mode))) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if this NVTOK.DAT is old or new */
    if (stbuf.st_size == sizeof(TOKEN_DATA_OLD)) {
        *new = CK_FALSE;
    } else if (stbuf.st_size == sizeof(TOKEN_DATA)) {
        *new = CK_TRUE;
    } else {
        TRACE_ERROR("%s has an invalid size of %ld bytes. Neither old nor new token format.\n",
                    fname, stbuf.st_size);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:
    fclose(fp);

    return ret;
}

/**
 * Check if the data store is in 3.12 format.
 */
static CK_RV datastore_is_312(const char *data_store, const char *sopin,
                              const char *userpin, CK_BBOOL *new)
{
    CK_RV ret;
    CK_BYTE masterkey_so[32];
    CK_BYTE masterkey_user[32];
    unsigned int num_objs = 0, num_old_objs = 0;
    TOKEN_DATA tokdata;

    *new = CK_FALSE;

    TRACE_INFO("Checking if data store is already in 3.12 format ...\n");

    /* Check if NVTOK.DAT is new */
    ret = NVTOK_DAT_is_312(data_store, new);
    if (ret != CKR_OK) {
        warnx("Cannot determine if NVTOK.DAT has an old or new format.");
        warnx("Note that generic token formats cannot be migrated.");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (*new == CK_FALSE) {
        ret = CKR_OK;
        goto done;
    }

    /* NVTOK.DAT is already new, now check if we can read the keys */
    ret = load_NVTOK_DAT(data_store, "NVTOK.DAT", &tokdata);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot load NVTOK.DAT, datastore inconsistent, ret=%08lX\n", ret);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = load_masterkey_312(data_store, "MK_SO", sopin, &tokdata, masterkey_so);
    if (ret != CKR_OK) {
        TRACE_INFO("Cannot load new MK from MK_SO, datastore probably old.\n");
        goto done;
    }

    ret = load_masterkey_312(data_store, "MK_USER", userpin, &tokdata, masterkey_user);
    if (ret != CKR_OK) {
        TRACE_INFO("Cannot load new MK from MK_USER, datastore probably old.\n");
        goto done;
    }

    if (memcmp(masterkey_so, masterkey_user, 32) != 0) {
        TRACE_ERROR("MKs from MK_SO and MK_USER don't match, datastore inconsistent.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = count_objects(data_store, &num_objs, &num_old_objs);
    if (ret != CKR_OK) {
        TRACE_ERROR("cannot count objects in %s.\n", data_store);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    TRACE_INFO("Found %d objects total, %d old objects.\n", num_objs, num_old_objs);
    if (num_old_objs > 0)
        TRACE_WARN("Note that the old objects are not usable anymore, because "
                   "we don't have the corresponding old masterkey!\n");

    if (num_objs > 0 && num_old_objs == 0)
        *new = CK_TRUE;

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Switch to new repository by deleting the old repository and renaming
 * the backup folder to the original data store name.
 */
static CK_RV switch_to_new_repository(const char *data_store_old,
                                      const char *data_store_new)
{
    char fname1[PATH_MAX];
    CK_RV ret;
    int rc = -1;

    TRACE_INFO("Switching to new repository ...\n");

    /* Rename original repository folder */
    snprintf(fname1, sizeof(fname1), "%s_BAK", data_store_old);
    rc = rename(data_store_old, fname1);
    if (rc) {
        TRACE_ERROR("Cannot rename %s, errno=%s.\n", data_store_old, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Rename backup folder */
    rc = rename(data_store_new, data_store_old);
    if (rc) {
        TRACE_ERROR("Cannot rename %s, errno=%s.\n", data_store_new, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Inserts the new tokversion parm in the token's slot configuration, e.g.
 *
 *   slot 2
 *   {
 *     stdll = libpkcs11_cca.so
 *     tokversion = 3.12
 *   }
 */
static CK_RV update_opencryptoki_conf(CK_SLOT_ID slot_id, char *location)
{
    char dst_file[PATH_MAX], src_file[PATH_MAX], fname[PATH_MAX+20];
    struct ConfigBaseNode *config = NULL, *c;
    struct ConfigVersionValNode *v;
    struct ConfigIdxStructNode *slot;
    FILE *fp_w = NULL;
    CK_RV ret;
    int rc;

    TRACE_INFO("Updating config file ...\n");

    /* Open current conf file for read */
    snprintf(src_file, PATH_MAX, "%s/%s", location, "opencryptoki.conf");

    config = config_parse(src_file, TRUE);
    if (config == NULL) {
        TRACE_ERROR("failed to parse config file %s\n", src_file);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Update the tokeversion for the selected slot */
    slot = confignode_findidx(config, "slot", slot_id);
    if (slot == NULL) {
        TRACE_ERROR("failed to find slot %lu in config file %s\n", slot_id,
                    src_file);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    c = confignode_find(slot->value, "tokversion");
    if (c != NULL) {
        /* modify existing tokversion */
        if (confignode_hastype(c, CT_VERSIONVAL)) {
            confignode_to_versionval(c)->value = TOKVERSION_312;
        } else if (confignode_hastype(c, CT_STRINGVAL)) {
            free(confignode_to_stringval(c)->value);
            confignode_to_stringval(c)->value = strdup(TOKVERSION_312_STRING);
            if (confignode_to_stringval(c)->value == NULL) {
                TRACE_ERROR("strdup failed\n");
                ret = CKR_HOST_MEMORY;
                goto done;
            }
        } else {
            TRACE_ERROR("tokversion is invalid in slot %lu in config file %s\n",
                        slot_id, src_file);
            ret = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        /* add new tokversion */
        v = confignode_allocversionvaldumpable("tokversion", TOKVERSION_312, 0,
                                               " added by pkcstok_migrate");
        if (v == NULL) {
            TRACE_ERROR("failed to allocate config node for config file %s\n",
                        src_file);
            ret = CKR_HOST_MEMORY;
            goto done;
        }

        confignode_append(slot->value, &v->base);
    }

    /* Open new conf file for write */
    snprintf(dst_file, PATH_MAX, "%s/%s", location, "opencryptoki.conf_new");
    fp_w = fopen(dst_file, "w");
    if (!fp_w) {
        TRACE_ERROR("fopen(%s) failed, errno=%s\n", dst_file, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }
    fchmod(fileno(fp_w), S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);

    confignode_dump(fp_w, config, NULL, 2);

    fclose(fp_w);
    fp_w = NULL;

    /* Rename old conf file */
    snprintf(fname, sizeof(fname), "%s_BAK", src_file);
    rc = rename(src_file, fname);
    if (rc) {
        TRACE_ERROR("Cannot rename %s\n", src_file);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Rename new file */
    rc = rename(dst_file, src_file);
    if (rc) {
        TRACE_ERROR("Cannot rename %s.\n", dst_file);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:
    confignode_deepfree(config);

    return ret;

}

/**
 * Removes the token_s shared memory from /dev/shm
 */
static CK_RV remove_shared_memory(char *location)
{
    char shm_name[PATH_MAX];
    int i, k, rc;

    i = k = 0;
    shm_name[k++] = '/';
    if (location[i] == '/')
        i++;

    for (; location[i]; i++, k++) {
        if (location[i] == '/')
            shm_name[k] = '.';
        else
            shm_name[k] = location[i];
    }
    shm_name[k] = '\0';

    rc = shm_unlink(shm_name);
    if (rc != 0 && errno != ENOENT) {
        warnx("shm_unlink(%s) failed, errno=%s", shm_name, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

/**
 * Copy a file given by name from a src folder to a dst folder.
 */
static CK_RV file_copy(char *dst, const char *src, const char *name)
{
    char dst_file[PATH_MAX], src_file[PATH_MAX], buf[4096];
    FILE *fp_r = NULL, *fp_w = NULL;
    size_t written;
    CK_RV ret;

    snprintf(dst_file, PATH_MAX, "%s/%s", dst, name);
    snprintf(src_file, PATH_MAX, "%s/%s", src, name);

    fp_r = fopen(src_file, "r");
    if (!fp_r) {
        warnx("fopen(%s) failed, errno=%s", src_file, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    fp_w = fopen(dst_file, "w");
    if (!fp_w) {
        warnx("fopen(%s) failed, errno=%s", dst_file, strerror(errno));
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }
    set_perm(fileno(fp_w));

    while (!feof(fp_r)) {
        size_t bytes = fread(buf, 1, sizeof(buf), fp_r);
        if (bytes) { // can be zero, if file empty
            written = fwrite(buf, 1, bytes, fp_w);
            if (written != bytes) {
                warnx("fwrite(%s) failed, errno=%s", dst_file,
                      strerror(errno));
                ret = CKR_FUNCTION_FAILED;
                goto done;
            }
        }
    }

    ret = CKR_OK;

done:

    if (fp_r)
        fclose(fp_r);
    if (fp_w)
        fclose(fp_w);

    return ret;
}

/**
 * Change the group owner of the given directory to 'pkcs11'.
 */
static CK_RV change_owner(char *dir)
{
    struct group* grp;
    CK_RV ret;

    /* Set group owner */
    grp = getgrnam("pkcs11");
    if (grp) {
        if (chown(dir, -1, grp->gr_gid)) {
            ret = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Fix group permissions (see man 2 mkdir for details) */
    if (chmod(dir, 0770)) {
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = CKR_OK;

done:

    return ret;
}

/**
 * Copy the given src folder to the given dst folder including all
 * subdirectories and files.
 */
static CK_RV folder_copy(char *dst, const char *src)
{
    char d[PATH_MAX], s[PATH_MAX];
    struct dirent *entry;
    CK_RV ret;
    DIR *dir;

    /* Open src */
    dir = opendir(src);
    if (dir == NULL) {
        TRACE_ERROR("Cannot open %s\n", src);
        return CKR_FUNCTION_FAILED;
    }

    /* Create dst */
    if (mkdir(dst, 0) != 0) {
        TRACE_ERROR("Cannot create %s\n", dst);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Change group owner and set permissions */
    ret = change_owner(dst);
    if (ret != CKR_OK) {
        TRACE_ERROR("Cannot change owner and permissions for %s\n", dst);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Copy folder recursively, skip the "." and ".." entries */
    while ((entry = readdir(dir)) != NULL) {
        if (entry->d_type == DT_DIR) {
            if (strncmp(entry->d_name, ".", 1) != 0) {
                snprintf(d, PATH_MAX, "%s/%s", dst, entry->d_name);
                snprintf(s, PATH_MAX, "%s/%s", src, entry->d_name);
                ret = folder_copy(d, s);
                if (ret != CKR_OK)
                    goto done;
            }
        } else {
            ret = file_copy(dst, src, entry->d_name);
            if (ret != CKR_OK)
                goto done;
        }
    }

    ret = CKR_OK;

done:

    closedir(dir);

    return ret;
}

/**
 * Remove the given folder and all of its contents.
 */
static CK_RV folder_delete(const char *folder)
{
    DIR *dir;
    char fname[PATH_MAX];
    size_t len, path_len;
    struct stat statbuf;
    struct dirent *ent;
    CK_RV ret = CKR_OK;

    dir = opendir(folder);
    if (!dir) {
        TRACE_INFO("Folder %s doesn't exist.\n", folder);
        return CKR_OK;
    }

    path_len = strlen(folder);
    while (!ret && (ent = readdir(dir))) {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
            continue;
        len = path_len + strlen(ent->d_name) + 2;
        snprintf(fname, len, "%s/%s", folder, ent->d_name);
        if (!stat(fname, &statbuf)) {
            if (S_ISDIR(statbuf.st_mode)) {
                ret = folder_delete(fname);
                if (ret != CKR_OK)
                    goto done;
            } else {
                ret = remove(fname);
                if (ret != CKR_OK)
                    goto done;
            }
        } else {
            /* stat failed */
            TRACE_ERROR("Cannot stat %s, errno=%s.\n", fname, strerror(errno));
            ret = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    ret = CKR_OK;

done:

    closedir(dir);
    if (ret == CKR_OK)
        rmdir(folder);

    return ret;
}

static CK_BBOOL backups_already_existent(const char *data_store,
                                         const char *conf_dir)
{
    char fname[PATH_MAX];
    struct stat statbuf;
    CK_BBOOL ret = CK_FALSE;

    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s_BAK", data_store);

    TRACE_INFO("Checking if backup datastore exists in %s ...\n", fname);
    if (stat(fname, &statbuf) == 0) {
        warnx("Error: datastore backup already exists already: %s", fname);
        ret = CK_TRUE;
    }

    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/opencryptoki.conf_BAK", conf_dir);

    TRACE_INFO("Checking if config file backup exists in %s ...\n", fname);
    if (stat(fname, &statbuf) == 0) {
        warnx("Error: config file backup already exists already: %s", fname);
        ret = CK_TRUE;
    }

    return ret;
}

/**
 * Backs up the given data_store to data_store_PKCSTOK_MIGRATE_TMP.
 * All folders and files are recursively created and copied.
 * Remove the backup if it already exists so that we always have
 * a clean backup.
 * The calling routine ensures that data_store does not end with a '/' !
 */
static CK_RV backup_repository(const char *data_store)
{
    char dst[PATH_MAX];
    CK_RV ret = CKR_OK;

    TRACE_INFO("Creating data store backup ...\n");

    memset(dst, 0, PATH_MAX);
    snprintf(dst, PATH_MAX, "%s_PKCSTOK_MIGRATE_TMP", data_store);
    ret = folder_delete(dst);
    if (ret != CKR_OK) {
        warnx("Fatal error: cannot delete old backup: %s", dst);
        return CKR_FUNCTION_FAILED;
    }

    return folder_copy(dst, data_store);
}

/**
 * Checks if the pkcsslotd is running.
 */
static CK_BBOOL pkcsslotd_running(void)
{
    FILE *fp;
    char* endptr;
    long lpid;
    char fname[PATH_MAX];
    char buf[PATH_MAX];
    char* first;

    TRACE_INFO("Checking if pkcsslotd is running ...\n");

    fp = fopen(PID_FILE_PATH, "r");
    if (fp == NULL) {
        TRACE_INFO("Pid file '%s' not existent, pkcsslotd is not running\n",
                   PID_FILE_PATH);
        return CK_FALSE;
    }

    if (fgets(buf, sizeof(buf), fp) == NULL) {
        TRACE_WARN("Cannot read pid file '%s': %s\n", PID_FILE_PATH,
                   strerror(errno));
        fclose(fp);
        return CK_FALSE;
    }
    fclose(fp);

    lpid = strtol(buf, &endptr, 10);
    if (*endptr != '\0' && *endptr != '\n') {
        TRACE_WARN("Failed to parse pid file '%s': %s\n", PID_FILE_PATH,
                           buf);
        return CK_FALSE;
    }

    snprintf(fname, sizeof(fname), "/proc/%ld/cmdline", lpid);
    fp = fopen(fname, "r");
    if (fp == NULL) {
        TRACE_INFO("Stale pid file, pkcsslotd is not running\n");
        return CK_FALSE;
    }

    if (fgets(buf, sizeof(buf), fp) == NULL) {
        TRACE_INFO("Failed to read '%s'\n", fname);
        fclose(fp);
        return CK_FALSE;
    }
    fclose(fp);

    first = strtok(buf, " ");
    return (first != NULL && strstr(first, "pkcsslotd") != NULL);
}

/**
 *
 */
static CK_BBOOL token_invalid(const char *dll)
{
    if (strcmp(dll, INVALID_TOKEN) == 0)
        return CK_TRUE;
    else
        return CK_FALSE;
}

/**
 * returns the token name related to the given stdll name for the
 * 4 supported tokens.
 */
static const char *dll2name(const char *dll)
{
    static char *dlls[] = {
        "libpkcs11_ica.so", "libpkcs11_cca.so",
        "libpkcs11_sw.so", "libpkcs11_ep11.so"
    };
    static char *names[] = {
        "ICA", "CCA", "Soft", "EP11"
    };
    int i, num_tokens = sizeof(names) / sizeof(char *);

    for (i = 0; i < num_tokens; i++) {
        if (strcmp(dll, dlls[i]) == 0)
            return names[i];
    }

    return INVALID_TOKEN;
}

/**
 * translates the given verbose level string into a numeric verbose level.
 * Returns -1 if the string is invalid.
 */
static int verbose_str2level(char *str)
{
    const char *tlevel[] = {"none", "error", "warn", "info", "devel", "debug"};
    const int num = sizeof(tlevel) / sizeof(char *);
    int i;

    for (i = 0; i < num; i++) {
        if (strcmp(str, tlevel[i]) == 0) {
            return i;
        }
    }

    return -1;
}

static void usage(char *progname)
{
    printf(" Help:\t\t\t\t%s -h\n", progname);
    printf(" -h, --help \t\t\tShow this help\n\n");
    printf(" Options:\n");
    printf(" -s, --slotid SLOTID\t\tPKCS slot number (required)\n");
    printf(" -d, --datastore DATASTORE\ttoken datastore location (required)\n");
    printf(" -c, --confdir CONFDIR\t\tlocation of opencryptoki.conf (required)\n");
    printf(" -u, --userpin USERPIN\t\ttoken user pin (prompted if not specified)\n");
    printf(" -p, --sopin SOPIN\t\ttoken SO pin (prompted if not specified)\n");
    printf(" -v, --verbose LEVEL\t\tset verbose level (optional):\n");
    printf("\t\t\t\tnone (default), error, warn, info, devel, debug\n");
    return;
}

int main(int argc, char **argv)
{
    CK_RV ret = 0;
    int opt = 0, vlevel = -1;
    CK_SLOT_ID slot_id = 0;
    CK_BBOOL slot_id_specified = CK_FALSE;
    size_t buflen = 0;
    ssize_t num_chars;
    char *data_store = NULL, *data_store_old = NULL, *conf_dir = NULL;
    const char *sopin = NULL, *userpin = NULL;
    char *buf_so = NULL, *buf_user = NULL;
    char *verbose = NULL;
    char *buff = NULL;
    char dll_name[PATH_MAX];
    char data_store_new[PATH_MAX];
    CK_TOKEN_INFO_32 tokinfo;
    CK_BBOOL new;

    static const struct option long_opts[] = {
        {"datastore", required_argument, NULL, 'd'},
        {"confdir", required_argument, NULL, 'c'},
        {"slotid", required_argument, NULL, 's'},
        {"userpin", required_argument, NULL, 'u'},
        {"sopin", required_argument, NULL, 'p'},
        {"verbose", required_argument, NULL, 'v'},
        {"help", no_argument, NULL, 'h'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "d:c:s:u:p:v:h", long_opts, NULL)) != -1) {
        switch (opt) {
        case 'd':
            data_store = strdup(optarg);
            if (data_store == NULL) {
                warnx("strdup failed.");
                exit(1);
            }
            break;
        case 'c':
            conf_dir = strdup(optarg);
            if (conf_dir == NULL) {
                warnx("strdup failed.");
                exit(1);
            }
            break;
        case 's':
            slot_id = atoi(optarg);
            slot_id_specified = CK_TRUE;
            break;
        case 'u':
            userpin = optarg;
            break;
        case 'p':
            sopin = optarg;
            break;
        case 'v':
            verbose = strdup(optarg);
            if (verbose == NULL) {
                warnx("strdup failed.");
                exit(1);
            }
            vlevel = verbose_str2level(verbose);
            if (vlevel < 0) {
                warnx("Invalid verbose level '%s' specified.", verbose);
                usage(argv[0]);
                exit(1);
            }
            break;
        case 'h':
            usage(argv[0]);
            exit(0);
        default:
            warnx("Parameters are required.");
            usage(argv[0]);
            exit(1);
        }
    }

    if (argc == 1) {
        usage(argv[0]);
        exit(1);
    }

    if (geteuid() != 0) {
        fprintf(stderr, "%s can only be used as root.\n", argv[0]);
        exit(-1);
    }

    printf("\npkcstok_migrate:\n");
    printf("Summary of input parameters:\n");
    if (data_store) {
        strip_trailing_chars(data_store, strlen(data_store), '/');
        printf("  datastore = %s \n", data_store);
    }
    if (conf_dir) {
        strip_trailing_chars(conf_dir, strlen(conf_dir), '/');
        printf("  confdir = %s \n", conf_dir);
    }
    if (slot_id_specified)
        printf("  slot ID = %lu\n", slot_id);
    if (userpin)
        printf("  user PIN specified\n");
    if (sopin)
        printf("  SO PIN specified\n");
    if (vlevel >= 0) {
        trace_level = vlevel;
        printf("  verbose level = %s\n", verbose);
    }
    printf("\n");

    /* Slot ID must be given */
    if (!slot_id_specified) {
        warnx("Slot ID must be specified.");
        goto done;
    }

    /* Datastore must be given */
    if (data_store == NULL) {
        warnx("Data store path must be specified.");
        goto done;
    }

    /* Limit datastore path length because of appended suffixes */
    if (strlen(data_store) > PKCSTOK_MIGRATE_MAX_PATH_LEN) {
        warnx("Datastore path (%ld characters) is too long (max = %d).\n",
              strlen(data_store), PKCSTOK_MIGRATE_MAX_PATH_LEN);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Location of opencryptoki.conf must be specified. */
    if (conf_dir == NULL) {
        warnx("Location of opencryptoki.conf must be specified.");
        goto done;
    }

    /* Limit path to config file because of appended suffixes */
    if (strlen(conf_dir) > PKCSTOK_MIGRATE_MAX_PATH_LEN) {
        warnx("Path to config file (%ld characters) is too long (max = %d).\n",
              strlen(conf_dir), PKCSTOK_MIGRATE_MAX_PATH_LEN);
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if given data_store exists */
    if (!datastore_exists(data_store)) {
        ret = CKR_FUNCTION_FAILED;
        warnx("Datastore %s does not exist.", data_store);
        goto done;
    }

    /* Check if given conf_dir exists and contains opencryptoki.conf */
    if (!conffile_exists(conf_dir)) {
        ret = CKR_FUNCTION_FAILED;
        warnx("%s does not exist or does not contain opencryptoki.conf", conf_dir);
        goto done;
    }

    if (backups_already_existent(data_store, conf_dir)) {
        warnx("Please remove the backups before running this utility.");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Check if pkcsslotd is running */
    if (pkcsslotd_running()) {
        warnx("Please stop pkcsslotd before running this utility.");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Identify token related to given slot ID */
    ret = identify_token(slot_id, conf_dir, dll_name, sizeof(dll_name));
    if (ret != CKR_OK) {
        warnx("Cannot identify a token related to given slot ID %ld", slot_id);
        goto done;
    }

    /* Check if DLL name from conf file is a known and migratable token */
    printf("Slot ID %lu points to DLL name %s, which is a %s token.\n",
           slot_id, dll_name, dll2name(dll_name));
    if (token_invalid(dll2name(dll_name))) {
        warnx("Please check your input.");
        goto done;
    }

    /* Get token info from NVTOK.DAT */
    ret = get_token_info(data_store, &tokinfo);
    if (ret != CKR_OK) {
        warnx("Cannot get the token label from NVTOK.DAT");
        goto done;
    }

    /* Check with user if ok to migrate this token, or quit if token not migratable */
    printf("Data store %s points to this token info:\n", data_store);
    printf("  label           : %.*s\n", 32, tokinfo.label);
    printf("  manufacturerID  : %.*s\n", 32, tokinfo.manufacturerID);
    printf("  model           : %.*s\n", 16, tokinfo.model);
    printf("  serialNumber    : %.*s\n", 16, tokinfo.serialNumber);
    printf("  hardwareVersion : %i.%i\n", tokinfo.hardwareVersion.major, tokinfo.hardwareVersion.minor);
    printf("  firmwareVersion : %i.%i\n", tokinfo.firmwareVersion.major, tokinfo.firmwareVersion.minor);
    printf("Migrate this token with given slot ID? y/n\n");
    num_chars = getline(&buff, &buflen, stdin);
    if (num_chars < 0 || strncmp(buff, "y", 1) != 0) {
        printf("ok, let's quit.\n");
        goto done;
    }

    /* Get the SO pin to authorize migration */
    if (!sopin)
        sopin = pin_prompt(&buf_so, "Enter the SO PIN: ");

    if(!sopin) {
        warnx("Could not get SO PIN.");
        goto done;
    }

    /* Get the USER pin to authorize migration */
    if (!userpin)
        userpin = pin_prompt(&buf_user, "Enter the USER PIN: ");

    if (!userpin) {
        warnx("Could not get USER PIN.");
        goto done;
    }

    /* Verify the SO and USER PINs entered against NVTOK.DAT. */
    ret = verify_pins(data_store, sopin, strlen(sopin), userpin, strlen(userpin));
    if (ret) {
        warnx("Could not verify pins.");
        goto done;
    }

    /* Check if data store is already new */
    ret = datastore_is_312(data_store, sopin, userpin, &new);
    if (ret == 0 && new) {
        printf("Data store %s is already in new format.\n", data_store);
        goto finalize;
    }

    /* Backup repository if not already done */
    ret = backup_repository(data_store);
    if (ret != CKR_OK) {
        warnx("Failed to create backup.");
        goto done;
    }

    /* Perform all actions on the backup */
    data_store_old = data_store;
    snprintf(data_store_new, PATH_MAX, "%s_PKCSTOK_MIGRATE_TMP", data_store_old);

    /* Create new temp token keys, which exist in parallel to the old ones
     * until the migration is fully completed. */
    ret = create_token_keys_312(data_store_new, sopin, userpin);
    if (ret != CKR_OK) {
        warnx("Failed to create new token keys.");
        goto done;
    }

    /* Migrate repository */
    ret = migrate_repository(data_store_new, sopin, userpin);
    if (ret != CKR_OK) {
        warnx("Failed to migrate repository.");
        goto done;
    }

    /* Switch to new repository */
    ret = switch_to_new_repository(data_store_old, data_store_new);
    if (ret != CKR_OK) {
        warnx("Switch to new repository failed.");
        goto done;
    }

finalize:
    /* Remove the token's shared memory */
    ret = remove_shared_memory(data_store);
    if (ret != CKR_OK) {
        warnx("Failed to remove token's shared memory.");
        goto done;
    }

    /* Now insert new 'tokversion=3.12' parm in opencryptoki.conf */
    ret = update_opencryptoki_conf(slot_id, conf_dir);
    if (ret != CKR_OK) {
        warnx("Failed to update opencryptoki.conf, you must do this manually.");
        goto done;
    }

    if (data_store_old != NULL)
        printf("Pre-migration data backed up at '%s_BAK'\n", data_store_old);
    printf("Config file backed up at '%s/opencryptoki.conf_BAK'\n", conf_dir);
    printf("Remove these backups manually after testing the new repository.\n");

    ret = CKR_OK;

done:

    free(buff);
    pin_free(&buf_so);
    pin_free(&buf_user);
    free(data_store);
    free(conf_dir);
    free(verbose);

    if (ret == CKR_OK) {
        printf("pkcstok_migrate finished successfully.\n");
        return EXIT_SUCCESS;
    } else {
        printf("pkcstok_migrate finished with warnings/errors.\n");
        return EXIT_FAILURE;
    }
}
