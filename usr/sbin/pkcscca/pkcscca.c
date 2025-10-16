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
 * Currently, only migrates CCA private token objects from CCA cipher
 * to using a software cipher.
 *
 */

#include <dlfcn.h>
#include <errno.h>
#include <memory.h>

#if defined(_AIX)
    #include <limits.h>
#else
    #include <linux/limits.h>
#endif

#include <openssl/evp.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "platform.h"
#include "pkcs11types.h"
#include "sw_crypt.h"
#include "defs.h"
#include "host_defs.h"
#include "local_types.h"
#include "h_extern.h"
#include "slotmgr.h" // for ock_snprintf

#define OCK_TOOL
#include "pkcs_utils.h"
#include "pin_prompt.h"

#include "pkcscca.h"

const char manuf[] = "IBM";
const char model[] = "CCA";
const char descr[] = "IBM CCA Token";
const char label[] = "ccatok";

#if defined(_AIX)
    const char *__progname = "pkcscca";
#endif

pkcs_trace_level_t trace_level = TRACE_LEVEL_NONE;
token_spec_t token_specific;

int v_level = 0;
void *p11_lib = NULL;
void (*CSNDKTC)(long *return_code,
                long *reason_code,
                long *exit_data_length,
                unsigned char *exit_data,
                long *rule_array_count,
                unsigned char *rule_array, long *key_id_length,
                unsigned char *key_id);
void (*CSNBKTC)(long *return_code,
                long *reason_code,
                long *exit_data_length,
                unsigned char *exit_data,
                long *rule_array_count,
                unsigned char *rule_array,
                unsigned char *key_identifier);
void (*CSNBKTC2)(long *return_code,
                 long *reason_code,
                 long *exit_data_length,
                 unsigned char *exit_data,
                 long *rule_array_count,
                 unsigned char *rule_array,
                 long *key_identifier_length,
                 unsigned char *key_identifier);
void (*CSNBDEC)(long *return_code,
                long *reason_code,
                long *exit_data_length,
                unsigned char *exit_data,
                unsigned char *key_identifier,
                long *text_length,
                unsigned char *ciphertext,
                unsigned char *initialization_vector,
                long *rule_array_count,
                unsigned char *rule_array,
                unsigned char *chaining_vector,
                unsigned char *plaintext);
void (*CSNDPKT)(long *return_code,
                long *reason_code,
                long *exit_data_length,
                unsigned char *exit_data,
                long *rule_array_count,
                unsigned char *rule_array,
                long *source_key_identifier_length,
                unsigned char *source_key_identifier,
                long *source_transport_key_identifier_length,
                unsigned char *source_transport_key_identifier,
                long *target_transport_key_identifier_length,
                unsigned char *target_transport_key_identifier,
                long *target_key_token_length,
                unsigned char *target_key_token);
void (*CSNDPKX)(long *return_code,
                long *reason_code,
                long *exit_data_length,
                unsigned char *exit_data,
                long *rule_array_count,
                unsigned char *rule_array,
                long *source_key_identifier_length,
                unsigned char *source_key_identifier,
                long *target_key_token_length,
                unsigned char *target_key_token);
void *lib_csulcca;

static struct algo aes = {(CK_BYTE *)"RTCMK   AES     ", (CK_BYTE *)"AES", 2 };
static struct algo des = {(CK_BYTE *)"RTCMK   ", (CK_BYTE *)"DES", 1 };
static struct algo hmac = {(CK_BYTE *)"RTCMK   HMAC    ", (CK_BYTE *)"HMAC", 2 };
static struct algo ecc = {(CK_BYTE *)"RTCMK   ECC     ", (CK_BYTE *)"ECC", 2 };
static struct algo rsa = {(CK_BYTE *)"RTCMK   ", (CK_BYTE *)"RSA", 1 };
static struct algo ibm_dilithium = {(CK_BYTE *)"RTCMK   QSA     ",
                                                (CK_BYTE *)"IBM Dilithium", 2 };
static struct algo ibm_ml_dsa = {(CK_BYTE *)"RTCMK   QSA     ",
                                                (CK_BYTE *)"IBM ML_DSA", 2 };
static struct algo ibm_ml_kem = {(CK_BYTE *)"RTCMK   QSA     ",
                                                (CK_BYTE *)"IBM ML-KEM", 2 };

int cca_decrypt(unsigned char *in_data, unsigned long in_data_len,
                unsigned char *out_data, unsigned long *out_data_len,
                unsigned char *init_v, unsigned char *key_value)
{
    long return_code, reason_code, rule_array_count, length;
    unsigned char chaining_vector[18];
    unsigned char rule_array[256];

    length = in_data_len;
    rule_array_count = 1;
    memcpy(rule_array, "CBC     ", 8);

    CSNBDEC(&return_code, &reason_code, NULL, NULL, key_value,
            &length, in_data, init_v, &rule_array_count,
            rule_array, chaining_vector, out_data);

    if (return_code != 0) {
        fprintf(stderr,
                "CSNBDEC (DES3 DECRYPT) failed: "
                "return_code=%ld reason_code=%ld\n",
                return_code, reason_code);
        return -1;
    }

    *out_data_len = length;

    return 0;
}

#define CKR_IBM_NOT_TOUCHED     -1

int adjust_secret_key_attributes(OBJECT *obj, CK_ULONG key_type)
{
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *ibm_opaque_attr = NULL;
    CK_ULONG key_size;
    struct secaeskeytoken *aes_token;
    CK_BYTE *zero = NULL;

    if (key_type != CKK_AES) {
        /* DES/3DES keys are already contained in CKA_IBM_OPAQUE */
        return CKR_IBM_NOT_TOUCHED;
    }

    /* Don't touch if object already has an IBM_OPAQUE attribute */
    if (template_attribute_find(obj->template, CKA_IBM_OPAQUE, &attr))
        return CKR_IBM_NOT_TOUCHED;

    if (!template_attribute_find(obj->template, CKA_VALUE, &value_attr)) {
        fprintf(stderr, "No CKA_VALUE attribute found\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    aes_token = (struct secaeskeytoken *)value_attr->pValue;
    if (value_attr->ulValueLen != sizeof(struct secaeskeytoken) ||
        aes_token->type != 0x01 ||
        aes_token->version != 0x04) {
        fprintf(stderr, "CKA_VALUE does not contain a CCA secure key\n");
        return CKR_IBM_NOT_TOUCHED;
    }

    /* Move CKA_VALUE to CKA_IBM_OPAQUE */
    rc = build_attribute(CKA_IBM_OPAQUE, value_attr->pValue,
                         value_attr->ulValueLen, &ibm_opaque_attr);
    if (rc != CKR_OK)
        goto cleanup;

    rc = template_update_attribute(obj->template, ibm_opaque_attr);
    if (rc != CKR_OK)
        goto cleanup;
    ibm_opaque_attr = NULL;

    /* Provide dummy CKA_VAUE attribute in (clear) key size */
    key_size = be16toh(aes_token->bitsize) / 8;
    zero = (CK_BYTE *)calloc(key_size, 1);
    if (zero == NULL) {
        fprintf(stderr, "Failed to allocate zero value\n");
        rc = CKR_HOST_MEMORY;
        goto cleanup;
    }

    rc = build_attribute(CKA_VALUE, zero, key_size, &value_attr);
    if (rc != CKR_OK)
        goto cleanup;

    rc = template_update_attribute(obj->template, value_attr);
    if (rc != CKR_OK)
        goto cleanup;
    value_attr = NULL;

    free(zero);

    return CKR_OK;

cleanup:
    if (ibm_opaque_attr)
        free(ibm_opaque_attr);
    if (value_attr)
        free(value_attr);
    if (zero)
        free(zero);
    return rc;
}

/*
 * OCK version 2.x create AES key objects with the CCA secure key stored
 * in CKA_VALUE. OCK 3.x requires the secure in CKA_IBM_OPAQUE instead.
 * Note: Other key types, such as DES/3DES keys as well as symmetric
 * keys (RSA, EC, etc) already store the key in CKA_IBM_OPAQUE in OCK 2.x
 *
 * This function moves the CCA AES key from CKA_VALUE to CKA_IBM_OPAQUE
 * and supplies a dummy (all zero) key in CKA_VALUE.
 */
int adjust_key_object_attributes(unsigned char *data, unsigned long data_len,
                                 unsigned char **new_data,
                                 unsigned long *new_data_len,
                                 const char *fname)
{
    int rc;
    OBJECT *obj = NULL;
    CK_ULONG class, subclass = 0;

    *new_data = NULL;
    *new_data_len = 0;

    /* Now unflatten the OBJ */
    rc = object_restore_withSize(NULL, data, &obj, CK_FALSE, data_len, fname);
    if (rc)
        goto cleanup;

    if (!template_get_class(obj->template, &class, &subclass)) {
        fprintf(stderr, "No CKA_CLASS attribute found\n");
        rc = CKR_TEMPLATE_INCOMPLETE;
        goto cleanup;
    }

    switch(class) {
    case CKO_SECRET_KEY:
        rc = adjust_secret_key_attributes(obj, subclass);
        if (rc == CKR_IBM_NOT_TOUCHED) {
            rc = CKR_OK;
            goto cleanup;
        }
        break;
    default:
        /* no need to modify the object */
        rc = CKR_OK;
        goto cleanup;
    }
    if (rc != CKR_OK)
        goto cleanup;

    /* flatten the object */
    rc = object_flatten(obj, new_data, new_data_len);
    if (rc)
        goto cleanup;

cleanup:
    if (obj)
        object_free(obj);

    return rc;
}

int reencrypt_private_token_object(unsigned char *data, unsigned long len,
                                   unsigned char *new_cipher,
                                   unsigned long *new_cipher_len,
                                   unsigned char *masterkey,
                                   const char *fname)
{
    unsigned char *clear = NULL;
    unsigned char des3_key[64];
    unsigned char sw_des3_key[3 * DES_KEY_SIZE];
    unsigned long clear_len;
    unsigned char *new_obj_data = NULL;
    unsigned long new_obj_data_len;
    CK_ULONG_32 obj_data_len_32;
    CK_ULONG padded_len;
    CK_ULONG block_size = DES_BLOCK_SIZE;
    CK_BYTE *ptr = NULL;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_RV rc;
    int ret;

    /* cca wants 8 extra bytes for padding purposes */
    clear_len = len + 8;
    clear = (unsigned char *) malloc(clear_len);
    if (!clear) {
        fprintf(stderr, "malloc() failed: %s.\n", strerror(errno));
        ret = -1;
        goto done;
    }

    /* decrypt using cca des3 */
    memcpy(des3_key, masterkey, MASTER_KEY_SIZE_CCA);
    ret = cca_decrypt(data, len, clear, &clear_len, (CK_BYTE *)"10293847",
                      des3_key);
    if (ret)
        goto done;

    /* Validate the hash */
    memcpy(&obj_data_len_32, clear, sizeof(CK_ULONG_32));
    if (obj_data_len_32 >= clear_len) {
        fprintf(stderr, "Decrypted object data is inconsistent. Possibly already migrated?\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    ret = compute_sha1((char *)(clear + sizeof(CK_ULONG_32)),
                       obj_data_len_32, (char *)hash_sha);
    if (ret != CKR_OK) {
        goto done;
    }

    if (memcmp(clear + sizeof(CK_ULONG_32) + obj_data_len_32, hash_sha,
               SHA1_HASH_SIZE) != 0) {
        fprintf(stderr, "Stored hash does not match restored data hash.\n");
        ret = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Adjust the key object attributes */
    ret = adjust_key_object_attributes(clear + sizeof(CK_ULONG_32),
                                       obj_data_len_32,
                                       &new_obj_data, &new_obj_data_len,
                                       fname);
    if (ret)
        goto done;

    if (new_obj_data != NULL) {
        free(clear);

        /* build data to be encrypted */
        clear_len = sizeof(CK_ULONG_32) + new_obj_data_len + SHA1_HASH_SIZE;
        padded_len = block_size * (clear_len / block_size + 1);

        clear = malloc(padded_len);
        if (!clear) {
            fprintf(stderr, "Failed to allocate buffer\n");
            goto done;
        }

        ptr = clear;
        obj_data_len_32 = new_obj_data_len;
        memcpy(ptr, &obj_data_len_32, sizeof(CK_ULONG_32));
        ptr += sizeof(CK_ULONG_32);
        memcpy(ptr, new_obj_data, obj_data_len_32);
        ptr += obj_data_len_32;
        compute_sha1((char *)new_obj_data, new_obj_data_len, (char *)hash_sha);
        memcpy(ptr, hash_sha, SHA1_HASH_SIZE);

        add_pkcs_padding(clear + clear_len, block_size, clear_len,
                         padded_len);

        clear_len = padded_len;
    }
    /* now encrypt using software des3 */
    memcpy(sw_des3_key, masterkey, 3 * DES_KEY_SIZE);
    rc = sw_des3_cbc_encrypt(clear, clear_len, new_cipher, new_cipher_len,
                             (CK_BYTE *)"10293847", sw_des3_key);
    if (rc != CKR_OK)
        ret = -1;

done:
    if (clear)
        free(clear);
    if (new_obj_data)
        free(new_obj_data);

    return ret;
}

int load_token_objects(unsigned char *data_store,
                       unsigned char *masterkey)
{
    FILE *fp1 = NULL, *fp2 = NULL;
    unsigned char *buf = NULL;
    char tmp[PATH_MAX], fname[PATH_MAX], iname[PATH_MAX];
    CK_BBOOL priv;
    unsigned int size;
    int rc = 0, scount = 0, fcount = 0;
    size_t read_size;
    unsigned char *new_cipher = NULL;
    unsigned long new_cipher_len;

    snprintf(iname, sizeof(iname), "%s/TOK_OBJ/OBJ.IDX", data_store);

    fp1 = fopen((char *) iname, "r");
    if (!fp1)
        return -1;              // no token objects

    while (fgets((char *) tmp, 50, fp1)) {
        tmp[strlen((char *) tmp) - 1] = 0;

        snprintf((char *) fname, sizeof(fname), "%s/TOK_OBJ/", data_store);
        strcat((char *) fname, (char *) tmp);

        fp2 = fopen((char *) fname, "r");
        if (!fp2)
            continue;

        read_size = fread(&size, sizeof(CK_ULONG_32), 1, fp2);
        if (read_size != 1) {
            fprintf(stderr, "Cannot read size\n");
            goto cleanup;
        }
        read_size = fread(&priv, sizeof(CK_BBOOL), 1, fp2);
        if (read_size != 1) {
            fprintf(stderr, "Cannot read boolean\n");
            goto cleanup;
        }

        size = size - sizeof(CK_ULONG_32) - sizeof(CK_BBOOL);
        buf = (unsigned char *) malloc(size);
        if (!buf) {
            fprintf(stderr, "Cannot malloc for object %s "
                    "(ignoring it).\n", tmp);
            goto cleanup;
        }

        read_size = fread((char *) buf, 1, size, fp2);
        if (read_size != size) {
            fprintf(stderr, "Cannot read object %s " "(ignoring it).\n", tmp);
            goto cleanup;
        }

        fclose(fp2);
        fp2 = NULL;

        if (priv != FALSE) {
            /* private token object */
            new_cipher_len = size * 2; /* obj may grow during processing ! */
            new_cipher = malloc(new_cipher_len);
            if (!new_cipher) {
                fprintf(stderr, "Cannot malloc space for new "
                        "cipher (ignoring object %s).\n", tmp);
                goto cleanup;
            }

            /* After reading the private token object,
             * decrypt it using CCA des3 and then re-encrypt it
             * using software des3.
             */
            memset(new_cipher, 0, new_cipher_len);
            rc = reencrypt_private_token_object(buf, size,
                                                new_cipher, &new_cipher_len,
                                                masterkey, fname);
            if (rc)
                goto cleanup;
        } else {
            /* public token object */
            rc = adjust_key_object_attributes(buf, size, &new_cipher,
                                              &new_cipher_len, fname);
            if (rc)
                goto cleanup;

            /* Only save if the object has been changed */
            if (new_cipher == NULL)
                goto cleanup;
        }

        /* now save the newly re-encrypted object back to
         * disk in its original file.
         */
        fp2 = fopen((char *) fname, "w");
        if (fp2 == NULL) {
            printf("Failed to open file %s: %s", fname, strerror(errno));
            rc = CKR_FUNCTION_FAILED;
            goto cleanup;
        }
        size = sizeof(CK_ULONG_32) + sizeof(CK_BBOOL) + new_cipher_len;
        (void) fwrite(&size, sizeof(CK_ULONG_32), 1, fp2);
        (void) fwrite(&priv, sizeof(CK_BBOOL), 1, fp2);
        (void) fwrite(new_cipher, new_cipher_len, 1, fp2);
        rc = 0;

cleanup:
        if (fp2)
            fclose(fp2);
        if (buf) {
            free(buf);
            buf = NULL;
        }
        if (new_cipher) {
            free(new_cipher);
            new_cipher = NULL;
        }

        if (rc) {
            if (v_level)
                printf("Failed to process %s\n", fname);
            fcount++;
        } else {
            if (v_level)
                printf("Processed %s.\n", fname);
            scount++;
        }
    }
    fclose(fp1);
    printf("Successfully migrated %d object(s).\n", scount);

    if (v_level && fcount)
        printf("Failed to migrate %d object(s).\n", fcount);

    return 0;
}

int load_masterkey(char *mkfile, const char *pin, char *masterkey)
{
    unsigned char des3_key[3 * DES_KEY_SIZE];
    char hash_sha[SHA1_HASH_SIZE];
    char pin_md5_hash[MD5_HASH_SIZE];
    unsigned char *cipher = NULL;
    char *clear = NULL;
    unsigned long cipher_len, clear_len, master_key_len;
    struct stat statbuf;
    int ret;
    CK_RV rc;
    FILE *fp = NULL;

    if (stat((char *) mkfile, &statbuf) != 0) {
        print_error("Cannot find %s.\n", mkfile);
        return -1;
    }

    master_key_len = MASTER_KEY_SIZE;
    clear_len = cipher_len =
        (master_key_len + SHA1_HASH_SIZE +
         (DES_BLOCK_SIZE - 1)) & ~(DES_BLOCK_SIZE - 1);

    if ((CK_ULONG)statbuf.st_size > cipher_len) {
        /*
         * The CCA token used to have a secure master key length of 64, although
         * it uses clear keys for the master key in the meantime. The master key
         * length  has an influence on the file size of the MK_SO and MK_USER
         * files when using the old pin encryption format. Use special handling
         * for such larger MK_SO files, and accept the larger length. Newly
         * written MK_SO files will use the clear key master key length, but we
         * need to be able to read larger files for backwards compatibility.
         */
        master_key_len = MASTER_KEY_SIZE_CCA;

        clear_len = cipher_len =
            (master_key_len + SHA1_HASH_SIZE +
             (DES_BLOCK_SIZE - 1)) & ~(DES_BLOCK_SIZE - 1);
    }

    fp = fopen((char *) mkfile, "r");
    if (!fp) {
        print_error("Could not open %s: %s\n", mkfile, strerror(errno));
        return -1;
    }

    cipher = malloc(cipher_len);
    clear = malloc(clear_len);
    if (cipher == NULL || clear == NULL) {
        ret = -1;
        goto done;
    }

    ret = fread(cipher, cipher_len, 1, fp);
    if (ret != 1) {
        print_error("Could not read %s: %s\n", mkfile, strerror(errno));
        ret = -1;
        goto done;
    }

    /* decrypt the masterkey */

    ret = compute_md5(pin, strlen(pin), pin_md5_hash);
    if (ret) {
        print_error("Error calculating MD5 of PIN!\n");
        goto done;
    }

    memcpy(des3_key, pin_md5_hash, MD5_HASH_SIZE);
    memcpy(des3_key + MD5_HASH_SIZE, pin_md5_hash, DES_KEY_SIZE);

    rc = sw_des3_cbc_decrypt(cipher, cipher_len, (unsigned char *)clear,
                             &clear_len, (unsigned char *) "12345678",
                             des3_key);
    if (rc != CKR_OK) {
        print_error("Error decrypting master key file after read");
        ret = -1;
        goto done;
    }

    /*
     * technically should strip PKCS padding here but since I already know
     * what the length should be, I don't bother.
     *
     * compare the hashes to verify integrity
     */

    ret = compute_sha1(clear, master_key_len, hash_sha);
    if (ret) {
        print_error("Failed to compute sha for masterkey.\n");
        goto done;
    }

    if (memcmp(hash_sha, clear + master_key_len, SHA1_HASH_SIZE) != 0) {
        print_error("%s appears to have been tampered!\n", mkfile);
        print_error("Cannot migrate.\n");
        ret = -1;
        goto done;
    }

    memcpy(masterkey, clear, master_key_len);
    ret = 0;

done:
    if (fp)
        fclose(fp);
    if (clear)
        free(clear);
    if (cipher)
        free(cipher);

    return ret;
}

CK_FUNCTION_LIST *p11_init(void)
{
    CK_RV rv;
    CK_RV (*getfunclist)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    CK_FUNCTION_LIST *funcs = NULL;

    p11_lib = dlopen(OCK_API_LIBNAME, DYNLIB_LDFLAGS);
    if (p11_lib == NULL) {
        print_error("Couldn't get a handle to the PKCS#11 library.");
        return NULL;
    }

    *(void **)(&getfunclist) = dlsym(p11_lib, "C_GetFunctionList");
    if (getfunclist == NULL) {
        print_error("Couldn't get the address of the C_GetFunctionList "
                    "routine.");
#ifndef WITH_SANITIZER
        dlclose(p11_lib);
#endif
        return NULL;
    }

    rv = getfunclist(&funcs);
    if (rv != CKR_OK) {
        p11_error("C_GetFunctionList", rv);
#ifndef WITH_SANITIZER
        dlclose(p11_lib);
#endif
        return NULL;
    }

    rv = funcs->C_Initialize(NULL_PTR);
    if (rv != CKR_OK) {
        p11_error("C_Initialize", rv);
#ifndef WITH_SANITIZER
        dlclose(p11_lib);
#endif
        return NULL;
    }

    if (v_level)
        printf("PKCS#11 library initialized\n");

    return funcs;
}

void p11_fini(CK_FUNCTION_LIST *funcs)
{
    funcs->C_Finalize(NULL_PTR);

#ifndef WITH_SANITIZER
    if (p11_lib)
        dlclose(p11_lib);
#endif
}

/* Expect attribute array to have 3 entries,
 * 0 CKA_IBM_OPAQUE
 * 1 CKA_KEY_TYPE
 * 2 CKA_LABEL
 * 3 CKA_CLASS
 */
int add_key(CK_OBJECT_HANDLE handle, CK_ATTRIBUTE *attrs, struct key **keys)
{
    struct key *new_key;
    CK_ULONG key_type = *(CK_ULONG *) attrs[1].pValue;
    CK_ULONG class = *(CK_ULONG *) attrs[3].pValue;

    new_key = malloc(sizeof(struct key));
    if (!new_key) {
        print_error("Malloc of %zd bytes failed!", sizeof(struct key));
        return 1;
    }

    switch (key_type) {
    case CKK_AES:
    case CKK_AES_XTS:
    case CKK_DES:
    case CKK_DES2:
    case CKK_DES3:
    case CKK_EC:
    case CKK_GENERIC_SECRET:
    case CKK_RSA:
    case CKK_IBM_PQC_DILITHIUM:
    case CKK_IBM_ML_DSA:
    case CKK_IBM_ML_KEM:
        break;
    default:
        free(new_key);
        return 0;
    }

    new_key->type = key_type;
    new_key->class = class;
    new_key->opaque_attr = malloc(attrs[0].ulValueLen);
    if (!new_key->opaque_attr) {
        print_error("Malloc of %lu bytes failed!", attrs[0].ulValueLen);
        free(new_key);
        return 2;
    }
    new_key->handle = handle;
    new_key->attr_len = attrs[0].ulValueLen;
    memcpy(new_key->opaque_attr, attrs[0].pValue, attrs[0].ulValueLen);
    new_key->label = malloc(attrs[2].ulValueLen + 1);
    if (!new_key->label) {
        print_error("Malloc of %lu bytes failed!", attrs[2].ulValueLen + 1);
        free(new_key->opaque_attr);
        free(new_key);
        return 2;
    }

    memset(new_key->label, 0, attrs[2].ulValueLen + 1);
    memcpy(new_key->label, attrs[2].pValue, attrs[2].ulValueLen);

    new_key->next = *keys;
    *keys = new_key;

    if (v_level) {
        char *type_name;
        switch (new_key->type) {
        case CKK_AES:
            type_name = AES_NAME;
            break;
        case CKK_AES_XTS:
            type_name = AES_XTS_NAME;
            break;
        case CKK_DES:
            type_name = DES_NAME;
            break;
        case CKK_DES2:
            type_name = DES2_NAME;
            break;
        case CKK_DES3:
            type_name = DES3_NAME;
            break;
        case CKK_EC:
            type_name = ECC_NAME;
            break;
        case CKK_GENERIC_SECRET:
            type_name = HMAC_NAME;
            break;
        case CKK_RSA:
            type_name = RSA_NAME;
            break;
        case CKK_IBM_PQC_DILITHIUM:
            type_name = IBM_DILITHIUM_NAME;
            break;
        case CKK_IBM_ML_DSA:
            type_name = IBM_ML_DSA_NAME;
            break;
        case CKK_IBM_ML_KEM:
            type_name = IBM_ML_KEM_NAME;
            break;
        default:
            type_name = BAD_NAME;
        }

        printf("Migratable key found: type=%s, label=%s, handle=%lu\n",
               type_name, new_key->label, handle);
    }

    return 0;
}

int find_wrapped_keys(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE sess,
                      CK_KEY_TYPE *key_type, struct key **keys)
{
    CK_RV rv;
    void *ptr;
    CK_OBJECT_HANDLE *handles = NULL, tmp;
    CK_ULONG ulObjectCount = 0, ulTotalCount = 0;
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE key_tmpl[] = {
        {CKA_KEY_TYPE, key_type, sizeof(*key_type)},
        {CKA_TOKEN, &true, sizeof(true)},
    };

    CK_ATTRIBUTE attrs[] = {
        {CKA_IBM_OPAQUE, NULL, 0},
        {CKA_KEY_TYPE, NULL, 0},
        {CKA_LABEL, NULL, 0},
        {CKA_CLASS, NULL, 0},
    };
    int i, rc, num_attrs = 4;


    /* Find all objects in the store */
    rv = funcs->C_FindObjectsInit(sess, key_tmpl, 2);
    if (rv != CKR_OK) {
        p11_error("C_FindObjectsInit", rv);
        print_error("Error finding CCA key objects");
        return 1;
    }

    while (1) {
        rv = funcs->C_FindObjects(sess, &tmp, 1, &ulObjectCount);
        if (rv != CKR_OK) {
            p11_error("C_FindObjects", rv);
            print_error("Error finding CCA key objects");
            if (handles != NULL)
                free(handles);
            return 1;
        }

        if (ulObjectCount == 0)
            break;

        ptr = realloc(handles, sizeof(CK_OBJECT_HANDLE) * (++ulTotalCount));
        if (!ptr) {
            print_error("Malloc of %lu bytes failed!",
                        sizeof(CK_OBJECT_HANDLE) * ulTotalCount);
            funcs->C_FindObjectsFinal(sess);
            if (handles != NULL)
                free(handles);
            return 1;
        }
        handles = ptr;

        handles[ulTotalCount - 1] = tmp;
    }
    if (v_level)
        printf("Found %lu keys to examine\n", ulTotalCount);

    /* Don't care if this fails */
    funcs->C_FindObjectsFinal(sess);

    /* At this point we have an array with handles to every object in the
     * store. We only care about those with a CKA_IBM_OPAQUE attribute,
     * so whittle down the list accordingly */
    for (tmp = 0; tmp < ulTotalCount; tmp++) {
        rv = funcs->C_GetAttributeValue(sess, handles[tmp], attrs, num_attrs);
        if (rv != CKR_OK) {
            p11_error("C_GetAttributeValue", rv);
            print_error("Error finding CCA key objects");
            free(handles);
            return 1;
        }

        /* If the opaque attr DNE, move to the next key */
        if (attrs[0].ulValueLen == ((CK_ULONG) - 1)) {
            continue;
        }

        /* Allocate space in the template for the actual data */
        for (i = 0; i < num_attrs; i++) {
            attrs[i].pValue = malloc(attrs[i].ulValueLen);
            if (!attrs[i].pValue) {
                print_error("Malloc of %lu bytes failed!", attrs[i].ulValueLen);
                free(handles);
                return 1;
            }
        }

        /* Pull in the actual data */
        rv = funcs->C_GetAttributeValue(sess, handles[tmp], attrs, num_attrs);
        if (rv != CKR_OK) {
            p11_error("C_GetAttributeValue", rv);
            print_error("Error getting object attributes");
            free(handles);
            return 1;
        }

        rc = add_key(handles[tmp], attrs, keys);
        if (rc) {
            free(handles);
            return 1;
        }

        for (i = 0; i < num_attrs; i++) {
            free(attrs[i].pValue);
            attrs[i].pValue = NULL_PTR;
            attrs[i].ulValueLen = 0;
        }
    }

    free(handles);

    return 0;
}

int replace_keys(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE sess,
                 struct key *keys)
{
    CK_RV rv;
    CK_ATTRIBUTE new_attr[] = { {CKA_IBM_OPAQUE, NULL, 0} };
    struct key *key;

    for (key = keys; key; key = key->next) {
        new_attr->pValue = key->opaque_attr;
        new_attr->ulValueLen = key->attr_len;

        rv = funcs->C_SetAttributeValue(sess, key->handle, new_attr, 1);
        if (rv != CKR_OK) {
            p11_error("C_SetAttributeValue", rv);
            print_error("Error replacing old key with " "migrated key.");
            return 1;
        }
    }

    return 0;
}

int cca_migrate_asymmetric(struct key *key, char **out, struct algo algo,
                           int masterkey)
{
    long return_code, reason_code, exit_data_length, key_identifier_length;
    unsigned char *key_identifier;

    exit_data_length = 0;
    key_identifier_length = key->attr_len;

    if (key->attr_len < 16 ||
        key->opaque_attr[0] == 0x1e) { /* 0x1e: external PKA token */
        printf("Skipping key, its a public key. label=%s, handle=%lu\n",
               key->label, key->handle);
        return 0;
    }

    if (strcmp((char *)algo.name, "RSA") == 0) {
        /*
         * RSA keys come in 2 flavors: RSA-CRT (using ASYM-MK) and RSA-AESC
         * (using APKA-MK)
         */
        switch (masterkey) {
        case MK_ASYM:
            if (key->attr_len < 16 ||
                key->opaque_attr[0] != 0x1f ||  /* 0x1f: internal PKA token */
                key->opaque_attr[8] != 0x08) {  /* 0x08: RSA-CRT priv key token */
                printf("Skipping key, its not an old RSA key. label=%s, handle=%lu\n",
                       key->label, key->handle);
                return 0;
            }
            break;
        case MK_APKA:
            if (key->attr_len < 16 ||
                key->opaque_attr[0] != 0x1f ||  /* 0x1f: internal PKA token */
                (key->opaque_attr[8] != 0x31 &&  /* 0x31: RSA-AESC priv key token */
                 key->opaque_attr[8] != 0x30)) { /* 0x30: RSA-AESM priv key token */
                printf("Skipping key, its not an new RSA key. label=%s, handle=%lu\n",
                       key->label, key->handle);
                return 0;
            }
            break;
        default:
            return 1;
        }
    }

    key_identifier = calloc(1, key->attr_len);
    if (!key_identifier) {
        print_error("Malloc of %lu bytes failed!", key->attr_len);
        return 1;
    }
    memcpy(key_identifier, (char *) key->opaque_attr, key->attr_len);

    CSNDKTC(&return_code,
            &reason_code,
            &exit_data_length,
            NULL,
            &(algo.rule_array_count),
            algo.rule_array, &key_identifier_length, key_identifier);

    if (return_code != CCA_SUCCESS) {
        cca_error("CSNDKTC (Key Token Change)", return_code, reason_code);
        print_error("Migrating %s key failed. label=%s, handle=%lu",
                    algo.name, key->label, key->handle);
        return 1;
    } else if (v_level) {
        printf("Successfully migrated %s key. label=%s, handle=%lu\n",
               algo.name, key->label, key->handle);
    }

    *out = (char *) key_identifier;

    if (!memcmp((CK_BYTE *) key->opaque_attr,
                (CK_BYTE *) key_identifier, key_identifier_length)) {
        printf("Skipping, %s token is  wrapped with current master key. "
               "label=%s, handle=%lu\n",
               algo.name, key->label, key->handle);
    }

    return 0;
}

int cca_migrate_symmetric(struct key *key, char **out, struct algo algo)
{
    long return_code, reason_code, exit_data_length;
    unsigned char *key_identifier;
    long key_identifier_length;

    exit_data_length = 0;

    key_identifier = calloc(1, key->attr_len);
    if (!key_identifier) {
        print_error("Malloc of %lu bytes failed!", key->attr_len);
        return 1;
    }
    memcpy(key_identifier, (char *) key->opaque_attr, key->attr_len);

    if (key_identifier[0] == 0x01 && key_identifier[4] == 0x05 &&
        key_identifier[41] == 0x02) {
        /* AES CIPHER key */
        key_identifier_length = key->type == CKK_AES_XTS ?
                                        key->attr_len / 2 : key->attr_len;
        CSNBKTC2(&return_code,
                 &reason_code,
                 &exit_data_length,
                 NULL,
                 &(algo.rule_array_count),
                 algo.rule_array, &key_identifier_length, key_identifier);

        if (return_code != CCA_SUCCESS) {
            cca_error("CSNBKTC2 (Key Token Change)", return_code, reason_code);
            print_error("Migrating %s key failed. label=%s, handle=%lu",
                        algo.name, key->label, key->handle);
            return 1;
        }

        if (key->type == CKK_AES_XTS) {
            key_identifier_length = key->attr_len / 2;
            CSNBKTC2(&return_code,
                     &reason_code,
                     &exit_data_length,
                     NULL,
                     &(algo.rule_array_count),
                     algo.rule_array, &key_identifier_length,
                     key_identifier + key_identifier_length);

            if (return_code != CCA_SUCCESS) {
                cca_error("CSNBKTC2 (Key Token Change)", return_code,
                          reason_code);
                print_error("Migrating %s key failed. label=%s, handle=%lu",
                            algo.name, key->label, key->handle);
                return 1;
            }
        }
    } else {
        /* AES DATA key */
        CSNBKTC(&return_code,
                &reason_code,
                &exit_data_length,
                NULL, &(algo.rule_array_count), algo.rule_array, key_identifier);

        if (return_code != CCA_SUCCESS) {
            cca_error("CSNBKTC (Key Token Change)", return_code, reason_code);
            print_error("Migrating %s key failed. label=%s, handle=%lu",
                        algo.name, key->label, key->handle);
            return 1;
        }

        if (key->type == CKK_AES_XTS) {
            CSNBKTC(&return_code,
                    &reason_code,
                    &exit_data_length,
                    NULL, &(algo.rule_array_count), algo.rule_array,
                    key_identifier + (key->attr_len / 2));

            if (return_code != CCA_SUCCESS) {
                cca_error("CSNBKTC (Key Token Change)", return_code,
                          reason_code);
                print_error("Migrating %s key failed. label=%s, handle=%lu",
                            algo.name, key->label, key->handle);
                return 1;
            }
        }
    }
    if (v_level) {
        printf("Successfully migrated %s key. label=%s, handle=%lu\n",
               algo.name, key->label, key->handle);
    }

    *out = (char *) key_identifier;

    if (!memcmp((CK_BYTE *) key->opaque_attr,
                (CK_BYTE *) key_identifier, key->attr_len)) {
        printf("Skipping, %s token is  wrapped with current master key. "
                "label=%s, handle=%lu\n",
                algo.name, key->label, key->handle);
    }
    return 0;
}

int cca_migrate_hmac(struct key *key, char **out, struct algo algo)
{
    long return_code, reason_code, exit_data_length, key_identifier_length;
    unsigned char *key_identifier;

    exit_data_length = 0;
    key_identifier_length = key->attr_len;

    key_identifier = calloc(1, key->attr_len);
    if (!key_identifier) {
        print_error("Malloc of %lu bytes failed!", key->attr_len);
        return 1;
    }
    memcpy(key_identifier, (char *) key->opaque_attr, key->attr_len);

    CSNBKTC2(&return_code,
             &reason_code,
             &exit_data_length,
             NULL,
             &(algo.rule_array_count),
             algo.rule_array, &key_identifier_length, key_identifier);

    if (return_code != CCA_SUCCESS) {
        cca_error("CSNBKTC2 (Key Token Change)", return_code, reason_code);
        print_error("Migrating %s key failed. label=%s, handle=%lu",
                    algo.name, key->label, key->handle);
        return 1;
    } else if (v_level) {
        printf("Successfully migrated %s key. label=%s, handle=%lu\n",
               algo.name, key->label, key->handle);
    }

    *out = (char *) key_identifier;

    if (!memcmp((CK_BYTE *) key->opaque_attr,
                (CK_BYTE *) key_identifier, key_identifier_length)) {
        printf("Skipping, %s token is  wrapped with current master key. "
                "label=%s, handle=%lu\n",
                algo.name, key->label, key->handle);
    }

    return 0;
}

/* @keys: A linked list of data to migrate and the PKCS#11 handle for the
 * object in the data store.
 * @count: counter for number of keys migrated
 * @count_failed: counter for number of keys that failed to migrate
 */
int cca_migrate(struct key *keys, struct key_count *count,
                struct key_count *count_failed, int masterkey)
{
    struct key *key;
    char *migrated_data;
    int rc;

    for (key = keys; key; key = key->next) {
        migrated_data = NULL;

        switch (key->type) {
        case CKK_AES:
        case CKK_AES_XTS:
            rc = cca_migrate_symmetric(key, &migrated_data, aes);
            if (rc)
                count_failed->aes++;
            else
                count->aes++;
            break;
        case CKK_DES:
        case CKK_DES2:
        case CKK_DES3:
            rc = cca_migrate_symmetric(key, &migrated_data, des);
            if (rc)
                count_failed->des++;
            else
                count->des++;
            break;
        case CKK_EC:
            rc = cca_migrate_asymmetric(key, &migrated_data, ecc, masterkey);
            if (rc)
                count_failed->ecc++;
            else
                count->ecc++;
            break;
        case CKK_GENERIC_SECRET:
            rc = cca_migrate_hmac(key, &migrated_data, hmac);
            if (rc)
                count_failed->hmac++;
            else
                count->hmac++;
            break;
        case CKK_RSA:
            rc = cca_migrate_asymmetric(key, &migrated_data, rsa, masterkey);
            if (rc)
                count_failed->rsa++;
            else
                count->rsa++;
            break;
        case CKK_IBM_PQC_DILITHIUM:
            rc = cca_migrate_asymmetric(key, &migrated_data, ibm_dilithium,
                                        masterkey);
            if (rc)
                count_failed->ibm_dilithium++;
            else
                count->ibm_dilithium++;
            break;
        case CKK_IBM_ML_DSA:
            rc = cca_migrate_asymmetric(key, &migrated_data, ibm_ml_dsa,
                                        masterkey);
            if (rc)
                count_failed->ibm_ml_dsa++;
            else
                count->ibm_ml_dsa++;
            break;
        case CKK_IBM_ML_KEM:
            rc = cca_migrate_asymmetric(key, &migrated_data, ibm_ml_kem,
                                        masterkey);
            if (rc)
                count_failed->ibm_ml_kem++;
            else
                count->ibm_ml_kem++;
            break;
        default:
            rc = 1;
            break;
        }

        /* replace the original key with the migrated key */
        if (!rc && migrated_data) {
            free(key->opaque_attr);
            key->opaque_attr = (CK_BYTE *) migrated_data;
        }
    }

    return 0;
}

int migrate_keytype(CK_FUNCTION_LIST *funcs, CK_SESSION_HANDLE sess,
                    CK_KEY_TYPE *k_type, struct key_count *count,
                    struct key_count *count_failed, int masterkey)
{
    struct key *keys = NULL, *tmp, *to_free;
    int rc;

    rc = find_wrapped_keys(funcs, sess, k_type, &keys);
    if (rc) {
        goto done;
    }

    rc = cca_migrate(keys, count, count_failed, masterkey);
    if (rc) {
        goto done;
    }

    rc = replace_keys(funcs, sess, keys);
    if (rc) {
        goto done;
    }

done:
    for (to_free = keys; to_free; to_free = tmp) {
        tmp = to_free->next;
        free(to_free->opaque_attr);
        free(to_free);
    }

    return rc;
}

void key_migration_results(struct key_count migrated, struct key_count failed)
{
    if (migrated.aes || migrated.des || migrated.des2 || migrated.des3 ||
        migrated.ecc || migrated.hmac || migrated.rsa ||
        migrated.ibm_dilithium || migrated.ibm_ml_dsa || migrated.ibm_ml_kem)
        printf("Successfully migrated: ");
    if (migrated.aes)
        printf("AES: %d. ", migrated.aes);
    if (migrated.des)
        printf("DES: %d. ", migrated.des);
    if (migrated.des2)
        printf("DES2: %d. ", migrated.des2);
    if (migrated.des3)
        printf("DES3: %d. ", migrated.des3);
    if (migrated.ecc)
        printf("ECC: %d. ", migrated.ecc);
    if (migrated.hmac)
        printf("HMAC: %d. ", migrated.hmac);
    if (migrated.rsa)
        printf("RSA: %d. ", migrated.rsa);
    if (migrated.ibm_dilithium)
        printf("IBM Dilithium: %d. ", migrated.ibm_dilithium);
    if (migrated.ibm_ml_dsa)
        printf("IBM ML-DSA: %d. ", migrated.ibm_ml_dsa);
    if (migrated.ibm_ml_kem)
        printf("IBM ML-KEM: %d. ", migrated.ibm_ml_kem);

    if (failed.aes || failed.des || failed.des2 || failed.des3 ||
        failed.ecc || failed.hmac || failed.rsa ||
        failed.ibm_dilithium || failed.ibm_ml_dsa || failed.ibm_ml_kem)
        printf("\nFailed to migrate: ");
    if (failed.aes)
        printf("AES: %d. ", failed.aes);
    if (failed.des)
        printf("DES: %d. ", failed.des);
    if (failed.des2)
        printf("DES2: %d. ", failed.des2);
    if (failed.des3)
        printf("DES3: %d. ", failed.des3);
    if (failed.ecc)
        printf("ECC: %d. ", failed.ecc);
    if (failed.hmac)
        printf("HMAC: %d. ", failed.hmac);
    if (failed.rsa)
        printf("RSA: %d. ", failed.rsa);
    if (failed.ibm_dilithium)
        printf("IBM Dilithium: %d. ", failed.ibm_dilithium);
    if (failed.ibm_ml_dsa)
        printf("IBM ML-DSA: %d. ", failed.ibm_ml_dsa);
    if (failed.ibm_ml_kem)
        printf("IBM ML-KEM: %d. ", failed.ibm_ml_kem);

    printf("\n");
}

int migrate_wrapped_keys(CK_SLOT_ID slot_id, const char *userpin, int masterkey)
{
    CK_FUNCTION_LIST *funcs;
    CK_KEY_TYPE key_type = 0;
    CK_SESSION_HANDLE sess;
    CK_RV rv;
    struct key_count count = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    struct key_count count_failed = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
    int exit_code = 0, rc;

    funcs = p11_init();
    if (!funcs) {
        return 2;
    }

    rv = funcs->C_OpenSession(slot_id, CKF_RW_SESSION |
                              CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
    if (rv != CKR_OK) {
        p11_error("C_OpenSession", rv);
        exit_code = 5;
        goto finalize;
    }

    rv = funcs->C_Login(sess, CKU_USER, (CK_BYTE *) userpin, strlen(userpin));
    if (rv != CKR_OK) {
        p11_error("C_Login (USER)", rv);
        exit_code = 8;
        goto finalize;
    }

    switch (masterkey) {
    case MK_AES:
        if (v_level)
            printf("Search for AES keys\n");
        key_type = CKK_AES;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        key_type = CKK_AES_XTS;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        if (v_level)
            printf("Search for HMAC keys\n");
        key_type = CKK_GENERIC_SECRET;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        break;
    case MK_APKA:
        if (v_level)
            printf("Search for ECC keys\n");
        key_type = CKK_EC;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        if (v_level)
            printf("Search for RSA keys\n");
        key_type = CKK_RSA;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        if (v_level)
            printf("Search for IBM Dilithium keys\n");
        key_type = CKK_IBM_PQC_DILITHIUM;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        if (v_level)
            printf("Search for IBM ML-DSA keys\n");
        key_type = CKK_IBM_ML_DSA;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        if (v_level)
            printf("Search for IBM ML-KEM keys\n");
        key_type = CKK_IBM_ML_KEM;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        break;
    case MK_ASYM:
        if (v_level)
            printf("Search for old RSA keys\n");
        key_type = CKK_RSA;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        break;
    case MK_SYM:
        if (v_level)
            printf("Search for DES keys\n");
        key_type = CKK_DES;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        if (v_level)
            printf("Search for DES2 keys\n");
        key_type = CKK_DES2;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        if (v_level)
            printf("Search for DES3 keys\n");
        key_type = CKK_DES3;
        rc = migrate_keytype(funcs, sess, &key_type, &count, &count_failed,
                             masterkey);
        if (rc) {
            goto done;
        }
        break;
    default:
        print_error("unknown key type (%lu)\n", key_type);
        return -1;
    }

    key_migration_results(count, count_failed);

done:
    funcs->C_CloseSession(sess);
finalize:
    p11_fini(funcs);
    return exit_code;
}

/* @keys: A linked list of data to migrate and the PKCS#11 handle for the
 * object in the data store.
 * @count: counter for number of keys migrated
 * @count_failed: counter for number of keys that failed to migrate
 */
int cca_migrate_old_rsa(struct key *keys, unsigned int *count,
                        unsigned int *count_failed)
{
    long return_code, reason_code, exit_data_length = 0;
    long rule_array_count, source_len, target_len, zero_len = 0;
    unsigned char target_token[2500] = { 0 };
    unsigned char rule_array[8];
    struct key *key;

    for (key = keys; key; key = key->next) {
        if (key->attr_len < 16 ||
            key->opaque_attr[0] != 0x1f ||  /* 0x1f: internal PKA token */
            key->opaque_attr[8] != 0x08) {  /* 0x08: RSA-CRT priv key token */
            if (v_level)
                printf("Skipping RSA key, its not an old RSA key. label=%s, handle=%lu\n",
                       key->label, key->handle);
            continue;
        }

        source_len = key->attr_len;
        target_len = sizeof(target_token);
        memset(target_token, 0, sizeof(target_token));

        if (key->class == CKO_PUBLIC_KEY) {
            /* Extract public key only */
            rule_array_count = 0;

            CSNDPKX(&return_code, &reason_code,
                    &exit_data_length, NULL,
                    &rule_array_count, rule_array,
                    &source_len, key->opaque_attr,
                    &target_len, target_token);

            if (return_code != CCA_SUCCESS) {
                cca_error("CSNDPKX (Public Key Token Extract)", return_code, reason_code);
                print_error("Migrating old RSA key failed. label=%s, handle=%lu",
                            key->label, key->handle);
                (*count_failed)++;
                continue;
            } else if (v_level) {
                printf("Successfully migrated old RSA key. label=%s, handle=%lu\n",
                       key->label, key->handle);
            }
        } else {
            /* Convert to RSA-AESC token type */
            rule_array_count = 1;
            memcpy(rule_array, "INTDWAKW", 8);

            CSNDPKT(&return_code, &reason_code,
                    &exit_data_length, NULL,
                    &rule_array_count, rule_array,
                    &source_len, key->opaque_attr,
                    &zero_len, NULL, &zero_len, NULL,
                    &target_len, target_token);

            if (return_code != CCA_SUCCESS) {
                cca_error("CSNDPKT (PKA Key Translate)", return_code, reason_code);
                print_error("Migrating old RSA key failed. label=%s, handle=%lu",
                            key->label, key->handle);
                (*count_failed)++;
                continue;
            } else if (v_level) {
                printf("Successfully migrated old RSA key. label=%s, handle=%lu\n",
                       key->label, key->handle);
            }
        }

        /* replace the original key with the migrated key */
        free(key->opaque_attr);
        key->opaque_attr = malloc(target_len);
        if (key->opaque_attr == NULL) {
            print_error("Malloc of %ld bytes failed!", target_len);
            (*count_failed)++;
            continue;
        }
        memcpy(key->opaque_attr, target_token, target_len);
        key->attr_len = target_len;

        (*count)++;
    }

    return 0;
}

int migrate_old_rsa_keys(CK_SLOT_ID slot_id, const char *userpin)
{
    CK_FUNCTION_LIST *funcs;
    CK_SESSION_HANDLE sess;
    CK_RV rv;
    unsigned int count = 0;
    unsigned int count_failed = 0;
    int exit_code = 0, rc;
    struct key *keys = NULL, *tmp, *to_free;
    CK_KEY_TYPE key_type = CKK_RSA;

    funcs = p11_init();
    if (!funcs) {
        return 2;
    }

    rv = funcs->C_OpenSession(slot_id, CKF_RW_SESSION |
                              CKF_SERIAL_SESSION, NULL_PTR, NULL_PTR, &sess);
    if (rv != CKR_OK) {
        p11_error("C_OpenSession", rv);
        exit_code = 5;
        goto finalize;
    }

    rv = funcs->C_Login(sess, CKU_USER, (CK_BYTE *) userpin, strlen(userpin));
    if (rv != CKR_OK) {
        p11_error("C_Login (USER)", rv);
        exit_code = 8;
        goto finalize;
    }

    if (v_level)
        printf("Search for RSA keys\n");

     rc = find_wrapped_keys(funcs, sess, &key_type, &keys);
     if (rc) {
         exit_code = 8;
         goto done;
     }

     rc = cca_migrate_old_rsa(keys, &count, &count_failed);
     if (rc) {
         exit_code = 8;
         goto done;
     }

     rc = replace_keys(funcs, sess, keys);
     if (rc) {
         exit_code = 8;
         goto done;
     }

     printf("Successfully migrated: %u", count);
     if (count_failed)
         printf("\nFailed to migrate:   %u", count_failed);
     printf("\n");


done:
    for (to_free = keys; to_free; to_free = tmp) {
        tmp = to_free->next;
        free(to_free->opaque_attr);
        free(to_free);
    }
    funcs->C_CloseSession(sess);
finalize:
    p11_fini(funcs);
    return exit_code;
}

int migrate_version(const char *sopin, const char *userpin, unsigned char *data_store)
{
    char masterkey[MASTER_KEY_SIZE_CCA];
    char fname[PATH_MAX];
    struct stat statbuf;
    int ret = 0;

    /* Verify that the data store is valid by looking for
     * MK_SO, MK_USER, and TOK_OBJ/OBJ.IDX.
     */
    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/MK_SO", data_store);
    if (stat(fname, &statbuf) != 0) {
        fprintf(stderr, "Cannot find %s.\n", fname);
        ret = -1;
        goto done;
    }

    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/MK_USER", data_store);
    if (stat(fname, &statbuf) != 0) {
        fprintf(stderr, "Cannot find %s.\n", fname);
        ret = -1;
        goto done;
    }

    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/TOK_OBJ/OBJ.IDX", data_store);
    if (stat(fname, &statbuf) != 0) {
        fprintf(stderr, "Cannot find %s.\n", fname);
        ret = -1;
        goto done;
    }

    /* If the OBJ.IDX is empty, then no objects to migrate. */
    if (statbuf.st_size == 0) {
        printf("OBJ.IDX file is empty. Thus no objects to migrate.\n");
        goto done;
    }

    if (v_level)
        printf("%s has an MK_SO, MK_USER and TOK/OBJ.IDX\n", data_store);
    /* Get the masterkey from MK_SO.
     * This also helps verify that correct SO pin was entered.
     */
    memset(masterkey, 0, MASTER_KEY_SIZE_CCA);
    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/MK_SO", data_store);
    ret = load_masterkey(fname, sopin, masterkey);
    if (ret) {
        fprintf(stderr, "Could not load masterkey from MK_SO.\n");
        goto done;
    }

    if (v_level)
        printf("Successfully verified SO Pin.\n");

    /* Get the masterkey from MK_USER.
     * This also helps verift that correct USER pin was entered.
     */
    memset(masterkey, 0, MASTER_KEY_SIZE_CCA);
    memset(fname, 0, PATH_MAX);
    snprintf(fname, PATH_MAX, "%s/MK_USER", data_store);
    ret = load_masterkey(fname, userpin, masterkey);
    if (ret) {
        fprintf(stderr, "Could not load masterkey from MK_USER.\n");
        goto done;
    }

    if (v_level)
        printf("Successfully verified USER Pin.\n");

    /* Load all the private token objects and re-encrypt them
     * using software des3, instead of CSNBENC.
     * For private and public token objects, migrate the key object's
     * attributes to IBM_OPAQUE.
     */
    (void)load_token_objects(data_store, (CK_BYTE *)masterkey);

done:
    return ret;
}

void usage(char *progname)
{
    printf(" Help:\t\t\t\t%s -h\n", progname);
    printf(" -h\t\t\t\tShow this help\n\n");
    printf(" Migrate Object Version:\t%s -m v2objectsv3 [OPTIONS] \n",
           progname);
    printf(" -m v2objectsv3\t\t\tMigrates CCA private token objects from");
    printf(" CCA\n\t\t\t\tencryption (used in v2) to software encryption");
    printf(" \n\t\t\t\t(used in v3). \n");
    printf(" Migrate Wrapped Keys:\t\t%s -m keys -s SLOTID -k KEYTYPE "
           "[OPTIONS] \n", progname);
    printf(" -m keys\t\t\tUnwraps private keys with the");
    printf(" old CCA master\n\t\t\t\tkey and wraps them with the");
    printf(" new CCA master key\n");
    printf(" -s, --slotid SLOTID\t\tPKCS slot number\n");
    printf(" -k aes|apka|asym|sym\t\tMigrate selected keytype\n\n");
    printf(" Migrate old RSA Keys:\t\t%s -m oldrsakeys -s SLOTID [OPTIONS] \n",
           progname);
    printf(" -m oldrsakeys\t\t\tConverts old RSA keys (RSA-CRT) to the new\n "
           "\t\t\t\tformat (RSA-AESC) and extracts the public key\n"
           "\t\t\t\tsection only from key objects containing the\n"
           "\t\t\t\tfull RSA key token\n");
    printf(" -s, --slotid SLOTID\t\tPKCS slot number\n\n");
    printf(" Options:\n");
    printf(" -d, --datastore DATASTORE\tCCA token datastore location\n");
    printf(" -v, --verbose LEVEL\t\tset verbose level (optional):\n");
    printf("\t\t\t\tnone (default), error, warn, info, devel, debug\n");
    return;
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

int main(int argc, char **argv)
{
    int ret = -1, opt = 0, masterkey = 0;
    int data_store_len = 0;
    CK_SLOT_ID slot_id = 0;
    const char *sopin = NULL, *userpin = NULL;
    char *buf_so = NULL, *buf_user = NULL;
    char *data_store = NULL;
    char *m_type = NULL;
    char *mk_type = NULL;
    void *lib_csulcca;

    int m_version = 0;
    int m_keys = 0;
    int m_rsakeys = 0;

    memset(&token_specific, 0, sizeof(token_specific));

    struct option long_opts[] = {
        {"datastore", required_argument, NULL, 'd'},
        {"slotid", required_argument, NULL, 's'},
        {"verbose", no_argument, NULL, 'v'},
        {0, 0, 0, 0}
    };

    while ((opt = getopt_long(argc, argv, "m:d:s:k:v:h", long_opts, NULL))
           != -1) {
        switch (opt) {
        case 'd':
            data_store = strdup(optarg);
            break;
        case 'h':
            usage(argv[0]);
            return 0;
        case 'k':
            mk_type = strdup(optarg);
            if (strcmp(mk_type, "aes") == 0) {
                masterkey = MK_AES;
            } else if (strcmp(mk_type, "apka") == 0) {
                masterkey = MK_APKA;
            } else if (strcmp(mk_type, "asym") == 0) {
                masterkey = MK_ASYM;
            } else if (strcmp(mk_type, "sym") == 0) {
                masterkey = MK_SYM;
            } else {
                print_error("unknown key type (%s)\n", mk_type);
                usage(argv[0]);
                return -1;
            }
            break;
        case 'm':
            m_type = strdup(optarg);
            if (strcmp(m_type, "v2objectsv3") == 0) {
                m_version = 1;
            } else if (strcmp(m_type, "keys") == 0) {
                m_keys = 1;
            } else if (strcmp(m_type, "oldrsakeys") == 0) {
                m_rsakeys = 1;
            } else {
                print_error("unknown migration type (%s)\n", m_type);
                usage(argv[0]);
                return -1;
            }
            break;
        case 's':
            slot_id = atoi(optarg);
            break;
        case 'v':
            v_level = verbose_str2level(optarg);
            if (v_level < 0) {
                print_error("Invalid verbose level '%s' specified.\n", optarg);
                usage(argv[0]);
                return -1;
            }
            break;
        default:
            usage(argv[0]);
            return -1;
        }
    }

    /* check for missing parameters */
    if (!m_version && !m_keys && !m_rsakeys) {
        print_error("missing migration type\n");
        usage(argv[0]);
        return -1;
    }

    /* use default data_store if one is not given */
    if (data_store == NULL) {
        data_store_len = strlen(TOK_DATASTORE);
        data_store = malloc(data_store_len + 1);
        if (data_store == NULL) {
            fprintf(stderr, "malloc failed: %s\n", strerror(errno));
            return -1;
        }
        memset(data_store, 0, data_store_len + 1);
        memcpy(data_store, TOK_DATASTORE, data_store_len);
    }

    /* get the SO pin to authorize migration */
    sopin = pin_prompt(&buf_so, "Enter the SO PIN: ");
    if (!sopin) {
        print_error("Could not get SO PIN.\n");
        goto done;
    }

    /* get the USER pin to authorize migration */
    userpin = pin_prompt(&buf_user, "Enter the USER PIN: ");
    if (!userpin) {
        print_error("Could not get USER PIN.\n");
        goto done;
    }

    /* verify the SO and USER PINs entered. */
    ret = verify_pins(data_store, sopin, strlen(sopin), userpin, strlen(userpin));
    if (ret)
        goto done;

    lib_csulcca = dlopen(CCA_LIBRARY, (RTLD_GLOBAL | DYNLIB_LDFLAGS));
    if (lib_csulcca == NULL) {
        fprintf(stderr, "dlopen(%s) failed: %s\n", CCA_LIBRARY,
                strerror(errno));
        return -1;
    }

    if (m_version) {
        *(void **)(&CSNBDEC) = dlsym(lib_csulcca, "CSNBDEC");
        ret = migrate_version(sopin, userpin, (CK_BYTE *)data_store);
    } else if (m_keys) {
        if (!slot_id) {
            print_error("missing slot number\n");
            usage(argv[0]);
            return -1;
        }

        if (!masterkey) {
            print_error("missing key type\n");
            usage(argv[0]);
            return -1;
        }

        *(void **)(&CSNDKTC) = dlsym(lib_csulcca, "CSNDKTC");
        *(void **)(&CSNBKTC) = dlsym(lib_csulcca, "CSNBKTC");
        *(void **)(&CSNBKTC2) = dlsym(lib_csulcca, "CSNBKTC2");
        ret = migrate_wrapped_keys(slot_id, userpin, masterkey);
    } else if (m_rsakeys) {
        if (!slot_id) {
            print_error("missing slot number\n");
            usage(argv[0]);
            return -1;
        }

        *(void **)(&CSNDPKT) = dlsym(lib_csulcca, "CSNDPKT");
        *(void **)(&CSNDPKX) = dlsym(lib_csulcca, "CSNDPKX");

        ret = migrate_old_rsa_keys(slot_id, userpin);
    }

done:
    pin_free(&buf_so);
    pin_free(&buf_user);
    if (data_store)
        free(data_store);

    return ret;
}

char *p11strerror(CK_RV rc)
{
    switch (rc) {
    case CKR_OK:
        return "CKR_OK";
    case CKR_CANCEL:
        return "CKR_CANCEL";
    case CKR_HOST_MEMORY:
        return "CKR_HOST_MEMORY";
    case CKR_SLOT_ID_INVALID:
        return "CKR_SLOT_ID_INVALID";
    case CKR_GENERAL_ERROR:
        return "CKR_GENERAL_ERROR";
    case CKR_FUNCTION_FAILED:
        return "CKR_FUNCTION_FAILED";
    case CKR_ARGUMENTS_BAD:
        return "CKR_ARGUMENTS_BAD";
    case CKR_NO_EVENT:
        return "CKR_NO_EVENT";
    case CKR_NEED_TO_CREATE_THREADS:
        return "CKR_NEED_TO_CREATE_THREADS";
    case CKR_CANT_LOCK:
        return "CKR_CANT_LOCK";
    case CKR_ATTRIBUTE_READ_ONLY:
        return "CKR_ATTRIBUTE_READ_ONLY";
    case CKR_ATTRIBUTE_SENSITIVE:
        return "CKR_ATTRIBUTE_SENSITIVE";
    case CKR_ATTRIBUTE_TYPE_INVALID:
        return "CKR_ATTRIBUTE_TYPE_INVALID";
    case CKR_ATTRIBUTE_VALUE_INVALID:
        return "CKR_ATTRIBUTE_VALUE_INVALID";
    case CKR_DATA_INVALID:
        return "CKR_DATA_INVALID";
    case CKR_DATA_LEN_RANGE:
        return "CKR_DATA_LEN_RANGE";
    case CKR_DEVICE_ERROR:
        return "CKR_DEVICE_ERROR";
    case CKR_DEVICE_MEMORY:
        return "CKR_DEVICE_MEMORY";
    case CKR_DEVICE_REMOVED:
        return "CKR_DEVICE_REMOVED";
    case CKR_ENCRYPTED_DATA_INVALID:
        return "CKR_ENCRYPTED_DATA_INVALID";
    case CKR_ENCRYPTED_DATA_LEN_RANGE:
        return "CKR_ENCRYPTED_DATA_LEN_RANGE";
    case CKR_FUNCTION_CANCELED:
        return "CKR_FUNCTION_CANCELED";
    case CKR_FUNCTION_NOT_PARALLEL:
        return "CKR_FUNCTION_NOT_PARALLEL";
    case CKR_FUNCTION_NOT_SUPPORTED:
        return "CKR_FUNCTION_NOT_SUPPORTED";
    case CKR_KEY_HANDLE_INVALID:
        return "CKR_KEY_HANDLE_INVALID";
    case CKR_KEY_SIZE_RANGE:
        return "CKR_KEY_SIZE_RANGE";
    case CKR_KEY_TYPE_INCONSISTENT:
        return "CKR_KEY_TYPE_INCONSISTENT";
    case CKR_KEY_NOT_NEEDED:
        return "CKR_KEY_NOT_NEEDED";
    case CKR_KEY_CHANGED:
        return "CKR_KEY_CHANGED";
    case CKR_KEY_NEEDED:
        return "CKR_KEY_NEEDED";
    case CKR_KEY_INDIGESTIBLE:
        return "CKR_KEY_INDIGESTIBLE";
    case CKR_KEY_FUNCTION_NOT_PERMITTED:
        return "CKR_KEY_FUNCTION_NOT_PERMITTED";
    case CKR_KEY_NOT_WRAPPABLE:
        return "CKR_KEY_NOT_WRAPPABLE";
    case CKR_KEY_UNEXTRACTABLE:
        return "CKR_KEY_UNEXTRACTABLE";
    case CKR_MECHANISM_INVALID:
        return "CKR_MECHANISM_INVALID";
    case CKR_MECHANISM_PARAM_INVALID:
        return "CKR_MECHANISM_PARAM_INVALID";
    case CKR_OBJECT_HANDLE_INVALID:
        return "CKR_OBJECT_HANDLE_INVALID";
    case CKR_OPERATION_ACTIVE:
        return "CKR_OPERATION_ACTIVE";
    case CKR_OPERATION_NOT_INITIALIZED:
        return "CKR_OPERATION_NOT_INITIALIZED";
    case CKR_PIN_INCORRECT:
        return "CKR_PIN_INCORRECT";
    case CKR_PIN_INVALID:
        return "CKR_PIN_INVALID";
    case CKR_PIN_LEN_RANGE:
        return "CKR_PIN_LEN_RANGE";
    case CKR_PIN_EXPIRED:
        return "CKR_PIN_EXPIRED";
    case CKR_PIN_LOCKED:
        return "CKR_PIN_LOCKED";
    case CKR_SESSION_CLOSED:
        return "CKR_SESSION_CLOSED";
    case CKR_SESSION_COUNT:
        return "CKR_SESSION_COUNT";
    case CKR_SESSION_HANDLE_INVALID:
        return "CKR_SESSION_HANDLE_INVALID";
    case CKR_SESSION_PARALLEL_NOT_SUPPORTED:
        return "CKR_SESSION_PARALLEL_NOT_SUPPORTED";
    case CKR_SESSION_READ_ONLY:
        return "CKR_SESSION_READ_ONLY";
    case CKR_SESSION_EXISTS:
        return "CKR_SESSION_EXISTS";
    case CKR_SESSION_READ_ONLY_EXISTS:
        return "CKR_SESSION_READ_ONLY_EXISTS";
    case CKR_SESSION_READ_WRITE_SO_EXISTS:
        return "CKR_SESSION_READ_WRITE_SO_EXISTS";
    case CKR_SIGNATURE_INVALID:
        return "CKR_SIGNATURE_INVALID";
    case CKR_SIGNATURE_LEN_RANGE:
        return "CKR_SIGNATURE_LEN_RANGE";
    case CKR_TEMPLATE_INCOMPLETE:
        return "CKR_TEMPLATE_INCOMPLETE";
    case CKR_TEMPLATE_INCONSISTENT:
        return "CKR_TEMPLATE_INCONSISTENT";
    case CKR_TOKEN_NOT_PRESENT:
        return "CKR_TOKEN_NOT_PRESENT";
    case CKR_TOKEN_NOT_RECOGNIZED:
        return "CKR_TOKEN_NOT_RECOGNIZED";
    case CKR_TOKEN_WRITE_PROTECTED:
        return "CKR_TOKEN_WRITE_PROTECTED";
    case CKR_UNWRAPPING_KEY_HANDLE_INVALID:
        return "CKR_UNWRAPPING_KEY_HANDLE_INVALID";
    case CKR_UNWRAPPING_KEY_SIZE_RANGE:
        return "CKR_UNWRAPPING_KEY_SIZE_RANGE";
    case CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT:
        return "CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_USER_ALREADY_LOGGED_IN:
        return "CKR_USER_ALREADY_LOGGED_IN";
    case CKR_USER_NOT_LOGGED_IN:
        return "CKR_USER_NOT_LOGGED_IN";
    case CKR_USER_PIN_NOT_INITIALIZED:
        return "CKR_USER_PIN_NOT_INITIALIZED";
    case CKR_USER_TYPE_INVALID:
        return "CKR_USER_TYPE_INVALID";
    case CKR_USER_ANOTHER_ALREADY_LOGGED_IN:
        return "CKR_USER_ANOTHER_ALREADY_LOGGED_IN";
    case CKR_USER_TOO_MANY_TYPES:
        return "CKR_USER_TOO_MANY_TYPES";
    case CKR_WRAPPED_KEY_INVALID:
        return "CKR_WRAPPED_KEY_INVALID";
    case CKR_WRAPPED_KEY_LEN_RANGE:
        return "CKR_WRAPPED_KEY_LEN_RANGE";
    case CKR_WRAPPING_KEY_HANDLE_INVALID:
        return "CKR_WRAPPING_KEY_HANDLE_INVALID";
    case CKR_WRAPPING_KEY_SIZE_RANGE:
        return "CKR_WRAPPING_KEY_SIZE_RANGE";
    case CKR_WRAPPING_KEY_TYPE_INCONSISTENT:
        return "CKR_WRAPPING_KEY_TYPE_INCONSISTENT";
    case CKR_RANDOM_SEED_NOT_SUPPORTED:
        return "CKR_RANDOM_SEED_NOT_SUPPORTED";
    case CKR_RANDOM_NO_RNG:
        return "CKR_RANDOM_NO_RNG";
    case CKR_BUFFER_TOO_SMALL:
        return "CKR_BUFFER_TOO_SMALL";
    case CKR_SAVED_STATE_INVALID:
        return "CKR_SAVED_STATE_INVALID";
    case CKR_INFORMATION_SENSITIVE:
        return "CKR_INFORMATION_SENSITIVE";
    case CKR_STATE_UNSAVEABLE:
        return "CKR_STATE_UNSAVEABLE";
    case CKR_CRYPTOKI_NOT_INITIALIZED:
        return "CKR_CRYPTOKI_NOT_INITIALIZED";
    case CKR_CRYPTOKI_ALREADY_INITIALIZED:
        return "CKR_CRYPTOKI_ALREADY_INITIALIZED";
    case CKR_MUTEX_BAD:
        return "CKR_MUTEX_BAD";
    case CKR_MUTEX_NOT_LOCKED:
        return "CKR_MUTEX_NOT_LOCKED";
    case CKR_ACTION_PROHIBITED:
        return "CKR_ACTION_PROHIBITED";
    case CKR_AEAD_DECRYPT_FAILED:
        return "CKR_AEAD_DECRYPT_FAILED";
    case CKR_NEW_PIN_MODE:
        return "CKR_NEW_PIN_MODE";
    case CKR_NEXT_OTP:
        return "CKR_NEXT_OTP";
    case CKR_EXCEEDED_MAX_ITERATIONS:
        return "CKR_EXCEEDED_MAX_ITERATIONS";
    case CKR_FIPS_SELF_TEST_FAILED:
        return "CKR_FIPS_SELF_TEST_FAILED";
    case CKR_LIBRARY_LOAD_FAILED:
        return "CKR_LIBRARY_LOAD_FAILED";
    case CKR_PIN_TOO_WEAK:
        return "CKR_PIN_TOO_WEAK";
    case CKR_PUBLIC_KEY_INVALID:
        return "CKR_PUBLIC_KEY_INVALID";
    default:
        return "UNKNOWN";
    }

    return "UNKNOWN";
}
