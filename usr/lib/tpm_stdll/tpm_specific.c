/*
 * COPYRIGHT (c) International Business Machines Corp. 2005-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * tpm_specific.c
 *
 * Feb 10, 2005
 *
 * Author: Kent Yoder <yoder1@us.ibm.com>
 *
 * Encryption routines are based on ../soft_stdll/soft_specific.c.
 *
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <pthread.h>
#include <string.h>
#include <stdlib.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <pwd.h>
#include <syslog.h>
#include <grp.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
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
#include "tok_struct.h"
#include "trace.h"
#include "ock_syslog.h"

#include "tpm_specific.h"

#include "../api/apiproto.h"

typedef struct {
    /* The context we'll use globally to connect to the TSP */
    TSS_HCONTEXT tspContext;

    /* TSP key handles */
    TSS_HKEY hSRK;
    TSS_HKEY hPublicRootKey;
    TSS_HKEY hPublicLeafKey;
    TSS_HKEY hPrivateRootKey;
    TSS_HKEY hPrivateLeafKey;

    /* TSP policy handles */
    TSS_HPOLICY hDefaultPolicy;

    /* PKCS#11 key handles */
    CK_OBJECT_HANDLE ckPublicRootKey;
    CK_OBJECT_HANDLE ckPublicLeafKey;
    CK_OBJECT_HANDLE ckPrivateRootKey;
    CK_OBJECT_HANDLE ckPrivateLeafKey;

    int not_initialized;

    CK_BYTE current_user_pin_sha[SHA1_HASH_SIZE];
    CK_BYTE current_so_pin_sha[SHA1_HASH_SIZE];
} tpm_private_data_t;

TSS_RESULT util_set_public_modulus(TSS_HCONTEXT tspContext, TSS_HKEY,
                                  unsigned long, unsigned char *);

const char manuf[] = "IBM";
const char model[] = "TPM";
const char descr[] = "IBM TPM v1.1 token";
const char label[] = "tpmtok";

static const MECH_LIST_ELEMENT tpm_mech_list[] = {
    {CKM_RSA_PKCS_KEY_PAIR_GEN, {512, 2048, CKF_GENERATE_KEY_PAIR}},
    {CKM_DES_KEY_GEN, {0, 0, CKF_GENERATE}},
    {CKM_DES3_KEY_GEN, {0, 0, CKF_GENERATE}},
    {CKM_RSA_PKCS, {512, 2048, CKF_HW | CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP |
                    CKF_UNWRAP | CKF_SIGN | CKF_VERIFY | CKF_SIGN_RECOVER |
                    CKF_VERIFY_RECOVER}},
    {CKM_MD5_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA1_RSA_PKCS, {512, 2048, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_DES_ECB, {0, 0, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CBC, {0, 0, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CBC_PAD,
     {0, 0, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_ECB, {0, 0, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_CBC, {0, 0, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_CBC_PAD,
     {0, 0, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_SHA_1, {0, 0, CKF_DIGEST}},
    {CKM_SHA_1_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA_1_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_MD5, {0, 0, CKF_DIGEST}},
    {CKM_MD5_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_MD5_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SSL3_PRE_MASTER_KEY_GEN, {48, 48, CKF_GENERATE}},
    {CKM_SSL3_MASTER_KEY_DERIVE, {48, 48, CKF_DERIVE}},
    {CKM_SSL3_KEY_AND_MAC_DERIVE, {48, 48, CKF_DERIVE}},
    {CKM_SSL3_MD5_MAC, {384, 384, CKF_SIGN | CKF_VERIFY}},
    {CKM_SSL3_SHA1_MAC, {384, 384, CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_KEY_GEN, {16, 32, CKF_GENERATE}},
    {CKM_AES_ECB, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_CBC, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_CBC_PAD, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP |
                       CKF_UNWRAP}},
};

static const CK_ULONG tpm_mech_list_len =
                    (sizeof(tpm_mech_list) / sizeof(MECH_LIST_ELEMENT));

static void clear_internal_structures(STDLL_TokData_t * tokdata)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;

    tpm_data->hSRK = NULL_HKEY;
    tpm_data->hPrivateLeafKey = NULL_HKEY;
    tpm_data->hPublicLeafKey = NULL_HKEY;
    tpm_data->hPrivateRootKey = NULL_HKEY;
    tpm_data->hPublicRootKey = NULL_HKEY;

    memset(tpm_data->current_so_pin_sha, 0, SHA1_HASH_SIZE);
    memset(tpm_data->current_user_pin_sha, 0, SHA1_HASH_SIZE);
}

CK_RV token_specific_rng(STDLL_TokData_t * tokdata, CK_BYTE * output,
                         CK_ULONG bytes)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT rc;
    TSS_HTPM hTPM;
    BYTE *random_bytes = NULL;

    rc = Tspi_Context_GetTpmObject(tpm_data->tspContext, &hTPM);
    if (rc) {
        TRACE_ERROR("Tspi_Context_GetTpmObject: %x\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = Tspi_TPM_GetRandom(hTPM, bytes, &random_bytes);
    if (rc) {
        TRACE_ERROR("Tspi_TPM_GetRandom failed. rc=0x%x\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(output, random_bytes, bytes);
    Tspi_Context_FreeMemory(tpm_data->tspContext, random_bytes);

    return CKR_OK;
}

CK_RV token_specific_init(STDLL_TokData_t * tokdata, CK_SLOT_ID SlotNumber,
                          char *conf_name)
{
    tpm_private_data_t *tpm_data;
    TSS_RESULT result;
    char path_buf[PATH_MAX], fname[PATH_MAX];
    struct stat statbuf;

    UNUSED(conf_name);

    TRACE_INFO("tpm %s slot=%lu running\n", __func__, SlotNumber);

    tokdata->mech_list = (MECH_LIST_ELEMENT *)tpm_mech_list;
    tokdata->mech_list_len = tpm_mech_list_len;

    // if the user specific directory doesn't exist, create it
    if (get_pk_dir(tokdata, fname, PATH_MAX) == NULL) {
        TRACE_ERROR("pk_dir buffer overflow\n");
        return CKR_FUNCTION_FAILED;
    }
    if (stat(fname, &statbuf) < 0) {
        if (mkdir(fname, S_IRUSR | S_IWUSR | S_IXUSR) == -1) {
            TRACE_ERROR("mkdir(%s): %s\n", fname, strerror(errno));
            return CKR_FUNCTION_FAILED;
        }
    }
    // now create userdir/TOK_OBJ if it doesn't exist
    if (ock_snprintf(path_buf, PATH_MAX, "%s/%s", fname, PK_LITE_OBJ_DIR) != 0) {
        TRACE_ERROR("userdir/TOK_OBJ path name overflow\n");
        return CKR_FUNCTION_FAILED;
    }
    if (stat(path_buf, &statbuf) < 0) {
        if (mkdir(path_buf, S_IRUSR | S_IWUSR | S_IXUSR) == -1) {
            TRACE_ERROR("mkdir(%s): %s\n", path_buf, strerror(errno));
            return CKR_FUNCTION_FAILED;
        }
    }

    tpm_data = (tpm_private_data_t *)calloc(1, sizeof(tpm_private_data_t));
    if (tpm_data == NULL) {
        TRACE_ERROR("calloc failed\n");
        return CKR_HOST_MEMORY;
    }
    tokdata->private_data = tpm_data;

    tpm_data->tspContext = NULL_HCONTEXT;
    clear_internal_structures(tokdata);

    result = Tspi_Context_Create(&tpm_data->tspContext);
    if (result) {
        TRACE_ERROR("Tspi_Context_Create failed. rc=0x%x\n", result);
        free(tpm_data);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_Context_Connect(tpm_data->tspContext, NULL);
    if (result) {
        TRACE_ERROR("Tspi_Context_Connect failed. rc=0x%x\n", result);
        Tspi_Context_Close(tpm_data->tspContext);
        free(tpm_data);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_Context_GetDefaultPolicy(tpm_data->tspContext,
                                           &tpm_data->hDefaultPolicy);
    if (result) {
        TRACE_ERROR("Tspi_Context_GetDefaultPolicy failed. rc=0x%x\n", result);
        Tspi_Context_Close(tpm_data->tspContext);
        free(tpm_data);
        return CKR_FUNCTION_FAILED;
    }

    OpenSSL_add_all_algorithms();

    return CKR_OK;
}

CK_RV token_find_key(STDLL_TokData_t * tokdata, int key_type,
                     CK_OBJECT_CLASS class, CK_OBJECT_HANDLE * handle)
{
    CK_BYTE *key_id = util_create_id(key_type);
    CK_RV rc = CKR_OK;
    CK_BBOOL true = TRUE;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_ID, key_id, strlen((char *) key_id)},
        {CKA_CLASS, &class, sizeof(class)},
        {CKA_HIDDEN, &true, sizeof(CK_BBOOL)}
    };
    CK_OBJECT_HANDLE hObj;
    CK_ULONG ulObjCount;
    SESSION dummy_sess;

    /* init the dummy session state to something that will find any object on
     * the token */
    memset(&dummy_sess, 0, sizeof(SESSION));
    dummy_sess.session_info.state = CKS_RO_USER_FUNCTIONS;

    rc = object_mgr_find_init(tokdata, &dummy_sess, tmpl, 3);
    if (rc != CKR_OK) {
        goto done;
    }

    /* pulled from SC_FindObjects */
    ulObjCount = MIN(1, (dummy_sess.find_count - dummy_sess.find_idx));
    memcpy(&hObj, dummy_sess.find_list + dummy_sess.find_idx,
           ulObjCount * sizeof(CK_OBJECT_HANDLE));
    dummy_sess.find_idx += ulObjCount;

    if (ulObjCount > 1) {
        TRACE_INFO("More than one matching key found in the store!\n");
        rc = CKR_KEY_NOT_FOUND;
        goto done;
    } else if (ulObjCount < 1) {
        TRACE_INFO("key with ID=\"%s\" not found in the store!\n", key_id);
        rc = CKR_KEY_NOT_FOUND;
        goto done;
    }

    *handle = hObj;
done:
    object_mgr_find_final(&dummy_sess);
    free(key_id);

    return rc;
}

CK_RV token_get_key_blob(STDLL_TokData_t * tokdata, CK_OBJECT_HANDLE ckKey,
                         CK_ULONG * blob_size, CK_BYTE ** ret_blob)
{
    CK_RV rc = CKR_OK;
    CK_BYTE_PTR blob = NULL;
    CK_ATTRIBUTE tmpl[] = {
        {CKA_IBM_OPAQUE, NULL_PTR, 0}
    };
    SESSION dummy_sess;

    /* set up dummy session */
    memset(&dummy_sess, 0, sizeof(SESSION));
    dummy_sess.session_info.state = CKS_RO_USER_FUNCTIONS;

    /* find object the first time to return the size of the buffer needed */
    rc = object_mgr_get_attribute_values(tokdata, &dummy_sess, ckKey, tmpl, 1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_get_attribute_values failed:rc=0x%lx\n", rc);
        goto done;
    }

    blob = malloc(tmpl[0].ulValueLen);
    if (blob == NULL) {
        TRACE_ERROR("malloc %ld bytes failed.\n", tmpl[0].ulValueLen);
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    tmpl[0].pValue = blob;
    /* find object the 2nd time to fill the buffer with data */
    rc = object_mgr_get_attribute_values(tokdata, &dummy_sess, ckKey, tmpl, 1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_get_attribute_values failed:rc=0x%lx\n", rc);
        goto done;
    }

    *ret_blob = blob;
    *blob_size = tmpl[0].ulValueLen;

done:
    return rc;
}

CK_RV token_wrap_sw_key(STDLL_TokData_t * tokdata,
                        int size_n, unsigned char *n, int size_p,
                        unsigned char *p, TSS_HKEY hParentKey,
                        TSS_FLAG initFlags, TSS_HKEY * phKey)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;
    TSS_HPOLICY hPolicy;
    TSS_BOOL get_srk_pub_key = TRUE;
    UINT32 key_size;

    key_size = util_get_keysize_flag(size_n * 8);
    if (initFlags == 0) {
        TRACE_ERROR("Invalid key size.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* create the TSS key object */
    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_RSAKEY,
                                       TSS_KEY_MIGRATABLE | initFlags |
                                       key_size, phKey);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Context_CreateObject failed: rc=0x%x\n", result);
        return result;
    }

    result = util_set_public_modulus(tpm_data->tspContext, *phKey, size_n, n);
    if (result != TSS_SUCCESS) {
        TRACE_DEVEL("util_set_public_modulus failed:rc=0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        *phKey = NULL_HKEY;
        return result;
    }

    /* set the private key data in the TSS object */
    result = Tspi_SetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB,
                                TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY, size_p, p);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_SetAttribData failed: rc=0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        *phKey = NULL_HKEY;
        return result;
    }

    /* if the parent wrapping key is the SRK, we need to manually pull
     * out the SRK's pub key, which is not stored in persistent storage
     * for privacy reasons */
    if (hParentKey == tpm_data->hSRK && get_srk_pub_key == TRUE) {
        UINT32 pubKeySize;
        BYTE *pubKey;
        result = Tspi_Key_GetPubKey(hParentKey, &pubKeySize, &pubKey);
        if (result != TSS_SUCCESS) {
            if (result == TPM_E_INVALID_KEYHANDLE) {
                OCK_SYSLOG(LOG_WARNING,
                           "Warning: Your TPM is not configured to allow "
                           "reading the public SRK by anyone but the owner. "
                           "Use tpm_restrictsrk -a to allow reading the public "
                           "SRK");
            } else {
                OCK_SYSLOG(LOG_ERR, "Tspi_Key_GetPubKey failed: rc=0x%x",
                           result);
            }
            Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
            *phKey = NULL_HKEY;
            return result;
        }
        Tspi_Context_FreeMemory(tpm_data->tspContext, pubKey);
        get_srk_pub_key = FALSE;
    }

    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_POLICY,
                                       TSS_POLICY_MIGRATION, &hPolicy);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Context_CreateObject: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        *phKey = NULL_HKEY;
        return result;
    }

    result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_NONE, 0, NULL);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Policy_SetSecret failed. rc=0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
        *phKey = NULL_HKEY;
        return result;
    }

    result = Tspi_Policy_AssignToObject(hPolicy, *phKey);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Policy_AssignToObject: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
        *phKey = NULL_HKEY;
        return result;
    }

    if (TPMTOK_TSS_KEY_TYPE(initFlags) == TSS_KEY_TYPE_LEGACY) {
        result = Tspi_SetAttribUint32(*phKey, TSS_TSPATTRIB_KEY_INFO,
                                      TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                                      TSS_ES_RSAESPKCSV15);
        if (result) {
            TRACE_ERROR("Tspi_SetAttribUint32 failed. rc=0x%x\n", result);
            Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
            Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
            return result;
        }

        result = Tspi_SetAttribUint32(*phKey, TSS_TSPATTRIB_KEY_INFO,
                                      TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
                                      TSS_SS_RSASSAPKCS1V15_DER);
        if (result) {
            TRACE_ERROR("Tspi_SetAttribUint32 failed. rc=0x%x\n", result);
            Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
            Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
            return result;
        }
    }

    result = Tspi_Key_WrapKey(*phKey, hParentKey, NULL_HPCRS);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Key_WrapKey failed: rc=0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        *phKey = NULL_HKEY;
    }

    return result;
}

/*
 * Create a TPM key blob for an imported key. This function is only called when
 * a key is in active use, so any failure should trickle through.
 *
 * Note: The passed Object ckObject must not hold a lock, this function might
 *       need to acquire a WRITE lock on the object!
 */
CK_RV token_wrap_key_object(STDLL_TokData_t * tokdata,
                            CK_OBJECT_HANDLE ckObject, TSS_HKEY hParentKey,
                            TSS_HKEY * phKey)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_ATTRIBUTE *attr = NULL, *new_attr, *prime_attr;
    CK_ULONG class, key_type;
    OBJECT *obj = NULL;
    TSS_RESULT result;
    TSS_FLAG initFlags = 0;
    BYTE *rgbBlob;
    UINT32 ulBlobLen;

    rc = object_mgr_find_in_map1(tokdata, ckObject, &obj, WRITE_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* if the object isn't a key, fail */
    rc = template_attribute_get_ulong(obj->template, CKA_KEY_TYPE, &key_type);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
        goto done;
    }

    if (key_type != CKK_RSA) {
        TRACE_ERROR("Bad key type!\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = template_attribute_get_ulong(obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key\n");
        goto done;
    }

    if (class == CKO_PRIVATE_KEY) {
        /* In order to create a full TSS key blob using a PKCS#11 private key
         * object, we need one of the two primes, the modulus and the private
         * exponent and we need the public exponent to be correct */

        /* check the least likely attribute to exist first, the primes */
        rc = template_attribute_get_non_empty(obj->template,
                                              CKA_PRIME_1, &prime_attr);
        if (rc != CKR_OK) {
            rc = template_attribute_get_non_empty(obj->template,
                                                  CKA_PRIME_2, &prime_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("Couldn't find prime1 or prime2 of"
                            " key object to wrap\n");
                rc = CKR_TEMPLATE_INCONSISTENT;
                goto done;
            }
        }

        /* Make sure the public exponent is usable */
        if ((util_check_public_exponent(obj->template))) {
            TRACE_ERROR("Invalid public exponent\n");
            rc = CKR_TEMPLATE_INCONSISTENT;
            goto done;
        }

        /* get the modulus */
        rc = template_attribute_get_non_empty(obj->template, CKA_MODULUS,
                                              &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Couldn't find a required attribute of "
                        "key object\n");
            goto done;
        }

        /* make sure the key size is usable */
        initFlags = util_get_keysize_flag(attr->ulValueLen * 8);
        if (initFlags == 0) {
            TRACE_ERROR("Invalid key size.\n");
            rc = CKR_TEMPLATE_INCONSISTENT;
            goto done;
        }

        /* generate the software based key */
        rc = token_wrap_sw_key(tokdata, (int) attr->ulValueLen, attr->pValue,
                               (int) prime_attr->ulValueLen,
                               prime_attr->pValue,
                               hParentKey,
                               TSS_KEY_TYPE_LEGACY | TSS_KEY_NO_AUTHORIZATION,
                               phKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_wrap_sw_key failed. rc=0x%lu\n", rc);
            goto done;
        }
    } else if (class == CKO_PUBLIC_KEY) {
        /* Make sure the public exponent is usable */
        if ((util_check_public_exponent(obj->template))) {
            TRACE_DEVEL("Invalid public exponent\n");
            rc = CKR_TEMPLATE_INCONSISTENT;
            goto done;
        }

        /* grab the modulus to put into the TSS key object */
        rc = template_attribute_get_non_empty(obj->template, CKA_MODULUS,
                                              &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Couldn't find a required attribute of "
                        "key object\n");
            goto done;
        }

        /* make sure the key size is usable */
        initFlags = util_get_keysize_flag(attr->ulValueLen * 8);
        if (initFlags == 0) {
            TRACE_ERROR("Invalid key size.\n");
            rc = CKR_TEMPLATE_INCONSISTENT;
            goto done;
        }

        initFlags |=
            TSS_KEY_TYPE_LEGACY | TSS_KEY_MIGRATABLE | TSS_KEY_NO_AUTHORIZATION;

        result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                           TSS_OBJECT_TYPE_RSAKEY,
                                           initFlags, phKey);
        if (result) {
            TRACE_ERROR("Tspi_Context_CreateObject failed. " "rc=0x%x\n",
                        result);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        result = util_set_public_modulus(tpm_data->tspContext, *phKey,
                                         attr->ulValueLen, attr->pValue);
        if (result) {
            TRACE_DEVEL("util_set_public_modulus failed: 0x%x\n", result);
            Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
            *phKey = NULL_HKEY;
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        TRACE_ERROR("Bad key class!\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* grab the entire key blob to put into the PKCS#11 object */
    result = Tspi_GetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB,
                                TSS_TSPATTRIB_KEYBLOB_BLOB,
                                &ulBlobLen, &rgbBlob);
    if (result) {
        TRACE_ERROR("Tspi_GetAttribData failed with rc: 0x%x\n", result);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* insert the key blob into the object */
    rc = build_attribute(CKA_IBM_OPAQUE, rgbBlob, ulBlobLen, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_atribute failed\n");
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        goto done;
    }
    rc = template_update_attribute(obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        goto done;
    }
    Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);

    /* if this is a token object, save it with the new attribute so that we
     * don't have to go down this path again */
    if (!object_is_session_object(obj)) {
        rc = XProcLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to get process lock.\n");
            goto done;
        }
        rc = save_token_object(tokdata, obj);
        if (rc != CKR_OK) {
            XProcUnLock(tokdata);
        } else {
            rc = XProcUnLock(tokdata);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to release process lock.\n");
                goto done;
            }
        }
    }

done:
    object_put(tokdata, obj, TRUE);
    obj = NULL;

    return rc;
}

/*
 * load a key in the TSS hierarchy from its CK_OBJECT_HANDLE
 *
 * Note: The passed Object ckKey must not hold a lock, this function might
 *       need to acquire a READ or WRITE lock on the object!
 */
CK_RV token_load_key(STDLL_TokData_t * tokdata, CK_OBJECT_HANDLE ckKey,
                     TSS_HKEY hParentKey, CK_CHAR_PTR passHash,
                     TSS_HKEY * phKey)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;
    TSS_HPOLICY hPolicy;
    CK_BYTE *blob = NULL;
    CK_ULONG ulBlobSize = 0;
    CK_RV rc;

    rc = token_get_key_blob(tokdata, ckKey, &ulBlobSize, &blob);
    if (rc != CKR_OK) {
        if (rc != CKR_ATTRIBUTE_TYPE_INVALID) {
            TRACE_DEVEL("token_get_key_blob failed. rc=0x%lx\n", rc);
            return rc;
        }
        /* the key blob wasn't found, so check for a modulus
         * to load */
        TRACE_DEVEL("key blob not found, checking for modulus\n");
        rc = token_wrap_key_object(tokdata, ckKey, hParentKey, phKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_wrap_key_object failed. rc=0x%lx\n", rc);
            return rc;
        }
    }

    if (blob != NULL) {
        /* load the key inside the TSS */
        result = Tspi_Context_LoadKeyByBlob(tpm_data->tspContext,
                                            hParentKey,
                                            ulBlobSize, blob, phKey);
        if (result) {
            TRACE_ERROR("Tspi_Context_LoadKeyByBlob: 0x%x\n", result);
            goto done;
        }
    }
#if 0
    if ((result = Tspi_GetPolicyObject(*phKey, TSS_POLICY_USAGE, &hPolicy))) {
        TRACE_ERROR("Tspi_GetPolicyObject: 0x%x\n", result);
        goto done;
    }
#else
    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_POLICY,
                                       TSS_POLICY_USAGE, &hPolicy);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject: 0x%x\n", result);
        goto done;
    }
#endif

    if (passHash == NULL) {
        result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_NONE, 0, NULL);
    } else {
        result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1,
                                       SHA1_HASH_SIZE, passHash);
    }
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Policy_SetSecret: 0x%x\n", result);
        goto done;
    }

    result = Tspi_Policy_AssignToObject(hPolicy, *phKey);
    if (result) {
        TRACE_ERROR("Tspi_Policy_AssignToObject: 0x%x\n", result);
        goto done;
    }
done:
    free(blob);

    return result;
}

TSS_RESULT token_load_srk(STDLL_TokData_t * tokdata)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_HPOLICY hPolicy;
    TSS_RESULT result;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    struct srk_info srk;

    if (tpm_data->hSRK != NULL_HKEY)
        return TSS_SUCCESS;

    /* load the SRK */
    result = Tspi_Context_LoadKeyByUUID(tpm_data->tspContext,
                                        TSS_PS_TYPE_SYSTEM, SRK_UUID,
                                        &tpm_data->hSRK);
    if (result) {
        TRACE_ERROR("Tspi_Context_LoadKeyByUUID failed. rc=0x%x\n", result);
        goto done;
    }
#if 0
    if ((result = Tspi_GetPolicyObject(tpm_data->hSRK, TSS_POLICY_USAGE,
                                       &hPolicy))) {
        TRACE_ERROR("Tspi_GetPolicyObject failed. rc=0x%x\n", result);
        goto done;
    }
#else
    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_POLICY,
                                       TSS_POLICY_USAGE, &hPolicy);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        goto done;
    }

    result = Tspi_Policy_AssignToObject(hPolicy, tpm_data->hSRK);
    if (result) {
        TRACE_ERROR("Tspi_Policy_AssignToObject failed. rc=0x%x\n", result);
        goto done;
    }
#endif

    /* get the srk info */
    memset(&srk, 0, sizeof(srk));
    if (get_srk_info(&srk))
        return -1;

    result = Tspi_Policy_SetSecret(hPolicy, (TSS_FLAG) srk.mode,
                                   srk.len, (BYTE *) srk.secret);
    if (result)
        TRACE_ERROR("Tspi_Policy_SetSecret failed. rc=0x%x\n", result);

    if (srk.secret)
        free(srk.secret);

done:
    return result;
}

TSS_RESULT token_load_public_root_key(STDLL_TokData_t * tokdata)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;
    BYTE *blob;
    CK_ULONG blob_size;

    if (tpm_data->hPublicRootKey != NULL_HKEY)
        return TSS_SUCCESS;

    result = token_load_srk(tokdata);
    if (result) {
        TRACE_DEVEL("token_load_srk failed. rc=0x%x\n", result);
        return result;
    }

    result = token_find_key(tokdata, TPMTOK_PUBLIC_ROOT_KEY,
                            CKO_PRIVATE_KEY, &tpm_data->ckPublicRootKey);
    if (result) {
        TRACE_ERROR("token_find_key failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = token_get_key_blob(tokdata, tpm_data->ckPublicRootKey, &blob_size,
                                &blob);
    if (result) {
        TRACE_DEVEL("token_get_key_blob failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* load the Public Root Key */
    result = Tspi_Context_LoadKeyByBlob(tpm_data->tspContext, tpm_data->hSRK,
                                        blob_size, blob,
                                        &tpm_data->hPublicRootKey);
    if (result) {
        TRACE_ERROR("Tspi_Context_LoadKeyByBlob failed. rc=0x%x\n", result);
        free(blob);
        return CKR_FUNCTION_FAILED;
    }
    free(blob);

    return result;
}

TSS_RESULT tss_generate_key(STDLL_TokData_t * tokdata,
                            TSS_FLAG initFlags, BYTE * passHash,
                            TSS_HKEY hParentKey, TSS_HKEY * phKey)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;
    TSS_HPOLICY hPolicy, hMigPolicy = 0;

    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_RSAKEY,
                                       initFlags, phKey);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        return result;
    }
#if 0
    if ((result = Tspi_GetPolicyObject(*phKey, TSS_POLICY_USAGE, &hPolicy))) {
        TRACE_ERROR("Tspi_GetPolicyObject failed. rc=0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        return result;
    }
#else
    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_POLICY,
                                       TSS_POLICY_USAGE, &hPolicy);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        return result;
    }
#endif

    if (passHash == NULL) {
        result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_NONE, 0, NULL);
    } else {
        result =
            Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1, 20, passHash);
    }
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Policy_SetSecret failed. rc=0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
        return result;
    }

    result = Tspi_Policy_AssignToObject(hPolicy, *phKey);
    if (result) {
        TRACE_ERROR("Tspi_Policy_AssignToObject: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
        return result;
    }

    if (TPMTOK_TSS_KEY_MIG_TYPE(initFlags) == TSS_KEY_MIGRATABLE) {
        result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                           TSS_OBJECT_TYPE_POLICY,
                                           TSS_POLICY_MIGRATION, &hMigPolicy);
        if (result) {
            TRACE_ERROR("Tspi_Context_CreateObject: 0x%x\n", result);
            Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
            Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
            return result;
        }

        if (passHash == NULL) {
            result =
                Tspi_Policy_SetSecret(hMigPolicy, TSS_SECRET_MODE_NONE, 0,
                                      NULL);
        } else {
            result = Tspi_Policy_SetSecret(hMigPolicy, TSS_SECRET_MODE_SHA1, 20,
                                           passHash);
        }

        if (result != TSS_SUCCESS) {
            TRACE_ERROR("Tspi_Policy_SetSecret failed. rc=0x%x\n", result);
            Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
            Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
            Tspi_Context_CloseObject(tpm_data->tspContext, hMigPolicy);
            return result;
        }

        result = Tspi_Policy_AssignToObject(hMigPolicy, *phKey);
        if (result) {
            TRACE_ERROR("Tspi_Policy_AssignToObject: 0x%x\n", result);
            Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
            Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
            Tspi_Context_CloseObject(tpm_data->tspContext, hMigPolicy);
            return result;
        }
    }

    if (TPMTOK_TSS_KEY_TYPE(initFlags) == TSS_KEY_TYPE_LEGACY) {
        result = Tspi_SetAttribUint32(*phKey, TSS_TSPATTRIB_KEY_INFO,
                                      TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                                      TSS_ES_RSAESPKCSV15);
        if (result) {
            TRACE_ERROR("Tspi_SetAttribUint32 failed. rc=0x%x\n", result);
            Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
            Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
            Tspi_Context_CloseObject(tpm_data->tspContext, hMigPolicy);
            return result;
        }

        result = Tspi_SetAttribUint32(*phKey, TSS_TSPATTRIB_KEY_INFO,
                                      TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
                                      TSS_SS_RSASSAPKCS1V15_DER);
        if (result) {
            TRACE_ERROR("Tspi_SetAttribUint32 failed. rc=0x%x\n", result);
            Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
            Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
            Tspi_Context_CloseObject(tpm_data->tspContext, hMigPolicy);
            return result;
        }
    }

    result = Tspi_Key_CreateKey(*phKey, hParentKey, 0);
    if (result) {
        TRACE_ERROR("Tspi_Key_CreateKey failed with rc: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        Tspi_Context_CloseObject(tpm_data->tspContext, hPolicy);
        Tspi_Context_CloseObject(tpm_data->tspContext, hMigPolicy);
    }

    return result;
}

TSS_RESULT tss_change_auth(STDLL_TokData_t * tokdata,
                           TSS_HKEY hObjectToChange, TSS_HKEY hParentObject,
                           CK_CHAR * passHash)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;
    TSS_HPOLICY hPolicy;

    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_POLICY,
                                       TSS_POLICY_USAGE, &hPolicy);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed: 0x%x\n", result);
        return result;
    }

    result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1,
                                   SHA1_HASH_SIZE, passHash);
    if (result) {
        TRACE_ERROR("Tspi_Policy_SetSecret failed: 0x%x\n", result);
        return result;
    }

    result = Tspi_ChangeAuth(hObjectToChange, hParentObject, hPolicy);
    if (result) {
        TRACE_ERROR("Tspi_ChangeAuth failed: 0x%x\n", result);
    }

    return result;
}

CK_RV token_store_priv_key(STDLL_TokData_t * tokdata, TSS_HKEY hKey,
                           int key_type, CK_OBJECT_HANDLE * ckKey)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_ATTRIBUTE *new_attr = NULL;
    OBJECT *priv_key_obj = NULL;
    BYTE *rgbBlob = NULL, *rgbPrivBlob = NULL;
    UINT32 ulBlobLen = 0, ulPrivBlobLen = 0;
    CK_BBOOL flag;
    CK_BYTE *key_id = util_create_id(key_type);
    CK_RV rc;
    SESSION dummy_sess;

    /* set up dummy session */
    memset(&dummy_sess, 0, sizeof(SESSION));
    dummy_sess.session_info.state = CKS_RW_USER_FUNCTIONS;

    /* grab the entire key blob to put into the PKCS#11 private key object */
    rc = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
                            TSS_TSPATTRIB_KEYBLOB_BLOB, &ulBlobLen, &rgbBlob);
    if (rc) {
        TRACE_ERROR("Tspi_GetAttribData failed with rc: 0x%lx\n", rc);
        free(key_id);
        return rc;
    }

    /* grab the encrypted provate key to put into the object */
    rc = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
                            TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY,
                            &ulPrivBlobLen, &rgbPrivBlob);
    if (rc) {
        TRACE_ERROR("Tspi_GetAttribData failed with rc: 0x%lx\n", rc);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        free(key_id);
        return rc;
    }

    /* create skeleton for the private key object */
    rc = object_create_skel(tokdata, NULL, 0, MODE_KEYGEN,
                            CKO_PRIVATE_KEY, CKK_RSA, &priv_key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("objectr_create_skel: 0x%lx\n", rc);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbPrivBlob);
        free(key_id);
        return rc;
    }

    /* add the ID attribute */
    rc = build_attribute(CKA_ID, key_id, strlen((char *) key_id), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbPrivBlob);
        free(key_id);
        object_free(priv_key_obj);
        return rc;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbPrivBlob);
        free(key_id);
        object_free(priv_key_obj);
        return rc;
    }

    free(key_id);

    /* add the key blob to the PKCS#11 object template */
    rc = build_attribute(CKA_IBM_OPAQUE, rgbBlob, ulBlobLen, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbPrivBlob);
        object_free(priv_key_obj);
        return rc;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbPrivBlob);
        object_free(priv_key_obj);
        return rc;
    }

    Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);

    /* add the private key blob to the PKCS#11 object template */
    rc = build_attribute(CKA_MODULUS, rgbPrivBlob, ulPrivBlobLen, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbPrivBlob);
        object_free(priv_key_obj);
        return rc;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbPrivBlob);
        object_free(priv_key_obj);
        return rc;
    }

    Tspi_Context_FreeMemory(tpm_data->tspContext, rgbPrivBlob);

    /* add the HIDDEN attribute */
    flag = TRUE;
    rc = build_attribute(CKA_HIDDEN, &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        object_free(priv_key_obj);
        return rc;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        object_free(priv_key_obj);
        return rc;
    }

    /*  set CKA_ALWAYS_SENSITIVE to true */
    rc = build_attribute(CKA_ALWAYS_SENSITIVE, &flag,
                         sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        object_free(priv_key_obj);
        return rc;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        object_free(priv_key_obj);
        return rc;
    }


    /*  set CKA_NEVER_EXTRACTABLE to true */
    rc = build_attribute(CKA_NEVER_EXTRACTABLE,
                         &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        object_free(priv_key_obj);
        return rc;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        object_free(priv_key_obj);
        return rc;
    }

    /* make the object reside on the token, as if that were possible */
    rc = build_attribute(CKA_TOKEN, &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        object_free(priv_key_obj);
        return rc;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        object_free(priv_key_obj);
        return rc;
    }

    flag = FALSE;
    rc = build_attribute(CKA_PRIVATE, &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        object_free(priv_key_obj);
        return rc;
    }
    rc = template_update_attribute(priv_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        object_free(priv_key_obj);
        return rc;
    }

    rc = object_mgr_create_final(tokdata, &dummy_sess, priv_key_obj, ckKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_final failed.\n");
        object_free(priv_key_obj);
        priv_key_obj = NULL;
    }

    return rc;
}

CK_RV token_store_pub_key(STDLL_TokData_t * tokdata, TSS_HKEY hKey,
                          int key_type, CK_OBJECT_HANDLE * ckKey)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_RV rc;
    TSS_RESULT result;
    CK_ATTRIBUTE *new_attr = NULL;
    OBJECT *pub_key_obj;
    CK_BBOOL flag = TRUE;
    CK_OBJECT_CLASS pub_class = CKO_PUBLIC_KEY;
    CK_KEY_TYPE type = CKK_RSA;
    CK_BYTE *key_id = util_create_id(key_type);
    CK_BYTE pub_exp[] = { 1, 0, 1 };    // 65537
    CK_ATTRIBUTE pub_tmpl[] = {
        {CKA_CLASS, &pub_class, sizeof(pub_class)},
        {CKA_KEY_TYPE, &type, sizeof(type)},
        {CKA_ID, key_id, strlen((char *) key_id)},
        {CKA_PUBLIC_EXPONENT, pub_exp, sizeof(pub_exp)},
        {CKA_MODULUS, NULL_PTR, 0}
    };
    BYTE *rgbPubBlob = NULL;
    UINT32 ulBlobLen = 0;
    SESSION dummy_sess;

    /* set up dummy session */
    memset(&dummy_sess, 0, sizeof(SESSION));
    dummy_sess.session_info.state = CKS_RW_USER_FUNCTIONS;

    /* grab the public key  to put into the PKCS#11 public key object */
    result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
                                TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
                                &ulBlobLen, &rgbPubBlob);
    if (result) {
        TRACE_ERROR("Tspi_GetAttribData failed with rc: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, hKey);
        free(key_id);
        return result;
    }

    pub_tmpl[4].pValue = rgbPubBlob;
    pub_tmpl[4].ulValueLen = ulBlobLen;

    /* create skeleton for the private key object */
    rc = object_create_skel(tokdata, pub_tmpl, 5, MODE_CREATE,
                            CKO_PUBLIC_KEY, CKK_RSA, &pub_key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_create_skel: 0x%lx\n", rc);
        Tspi_Context_CloseObject(tpm_data->tspContext, hKey);
        free(key_id);
        return rc;
    }
    Tspi_Context_FreeMemory(tpm_data->tspContext, rgbPubBlob);

    /* make the object reside on the token, as if that were possible */
    rc = build_attribute(CKA_TOKEN, &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build attribute failed.\n");
        object_free(pub_key_obj);
        goto done;
    }
    rc = template_update_attribute(pub_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        object_free(pub_key_obj);
        goto done;
    }

    /* set the object to be hidden */
    rc = build_attribute(CKA_HIDDEN, &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build attribute failed.\n");
        object_free(pub_key_obj);
        goto done;
    }
    rc = template_update_attribute(pub_key_obj->template, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        object_free(pub_key_obj);
        goto done;
    }

    rc = object_mgr_create_final(tokdata, &dummy_sess, pub_key_obj, ckKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_final failed\n");
        object_free(pub_key_obj);
        pub_key_obj = NULL;
        goto done;
    }

done:
    return rc;
}

CK_RV token_update_private_key(STDLL_TokData_t * tokdata, TSS_HKEY hKey,
                               int key_type)
{
    CK_OBJECT_HANDLE ckHandle;
    CK_RV rc;
    SESSION dummy_sess;

    /* set up dummy session */
    memset(&dummy_sess, 0, sizeof(SESSION));
    dummy_sess.session_info.state = CKS_RW_USER_FUNCTIONS;

    /* find the private key portion of the key */
    rc = token_find_key(tokdata, key_type, CKO_PRIVATE_KEY, &ckHandle);
    if (rc != CKR_OK) {
        TRACE_ERROR("token_find_key failed: 0x%lx\n", rc);
        return rc;
    }

    /* destroy the private key and create a new one */
    rc = object_mgr_destroy_object(tokdata, &dummy_sess, ckHandle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_destroy_object failed: 0x%lx\n", rc);
        return rc;
    }

    rc = token_store_priv_key(tokdata, hKey, key_type, &ckHandle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_store_priv_key failed: 0x%lx\n", rc);
    }

    return rc;
}

CK_RV token_store_tss_key(STDLL_TokData_t * tokdata, TSS_HKEY hKey,
                          int key_type, CK_OBJECT_HANDLE * ckKey)
{
    CK_RV rc;

    /* create a PKCS#11 pub key object for the key */
    rc = token_store_pub_key(tokdata, hKey, key_type, ckKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_store_pub_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* create a PKCS#11 private key object for the key */
    rc = token_store_priv_key(tokdata, hKey, key_type, ckKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_store_priv_key failed. rc=0x%lx\n", rc);
    }

    return rc;
}

CK_RV token_generate_leaf_key(STDLL_TokData_t * tokdata, int key_type,
                              CK_CHAR_PTR passHash, TSS_HKEY * phKey)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_RV rc = CKR_FUNCTION_FAILED;
    TSS_RESULT result;
    TSS_HKEY hParentKey;
    CK_OBJECT_HANDLE *ckKey;
    TSS_FLAG initFlags = TSS_KEY_MIGRATABLE | TSS_KEY_TYPE_BIND |
        TSS_KEY_SIZE_2048 | TSS_KEY_AUTHORIZATION;

    switch (key_type) {
    case TPMTOK_PUBLIC_LEAF_KEY:
        hParentKey = tpm_data->hPublicRootKey;
        ckKey = &tpm_data->ckPublicRootKey;
        break;
    case TPMTOK_PRIVATE_LEAF_KEY:
        hParentKey = tpm_data->hPrivateRootKey;
        ckKey = &tpm_data->ckPrivateRootKey;
        break;
    default:
        TRACE_ERROR("Unknown key type.\n");
        goto done;
        break;
    }

    result = tss_generate_key(tokdata, initFlags, passHash, hParentKey, phKey);
    if (result) {
        TRACE_ERROR("tss_generate_key returned 0x%x\n", result);
        return result;
    }

    rc = token_store_tss_key(tokdata, *phKey, key_type, ckKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_store_tss_key failed. rc=0x%x\n", result);
    }

done:
    return rc;
}

CK_RV token_verify_pin(STDLL_TokData_t * tokdata, TSS_HKEY hKey)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_HENCDATA hEncData;
    UINT32 ulUnboundDataLen;
    BYTE *rgbUnboundData;
    char *rgbData = "CRAPPENFEST";
    TSS_RESULT result;
    CK_RV rc = CKR_FUNCTION_FAILED;

    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_ENCDATA,
                                       TSS_ENCDATA_BIND, &hEncData);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        goto done;
    }

    result = Tspi_Data_Bind(hEncData, hKey, strlen(rgbData), (BYTE *) rgbData);
    if (result) {
        TRACE_ERROR("Tspi_Data_Bind returned 0x%x\n", result);
        goto done;
    }

    /* unbind the junk data to test the key's auth data */
    result =
        Tspi_Data_Unbind(hEncData, hKey, &ulUnboundDataLen, &rgbUnboundData);
    if (result == TCPA_E_AUTHFAIL) {
        rc = CKR_PIN_INCORRECT;
        TRACE_ERROR("Tspi_Data_Unbind returned TCPA_AUTHFAIL\n");
        goto done;
    } else if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Data_ Unbind returned 0x%x\n", result);
        goto done;
    }

    rc = memcmp(rgbUnboundData, rgbData, ulUnboundDataLen);

    Tspi_Context_FreeMemory(tpm_data->tspContext, rgbUnboundData);
done:
    Tspi_Context_CloseObject(tpm_data->tspContext, hEncData);

    return rc;
}

CK_RV token_create_private_tree(STDLL_TokData_t * tokdata, CK_BYTE * pinHash,
                                CK_BYTE * pPin)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_RV rc;
    TSS_RESULT result;
    EVP_PKEY *pkey;
    unsigned int size_n, size_p;
    unsigned char n[256], p[256];

    /* all sw generated keys are 2048 bits */
    if ((pkey = openssl_gen_key(tokdata)) == NULL)
        return CKR_HOST_MEMORY;

    if (openssl_get_modulus_and_prime(pkey, &size_n, n, &size_p, p) != 0) {
        TRACE_DEVEL("openssl_get_modulus_and_prime failed\n");
        return CKR_FUNCTION_FAILED;
    }

    /* generate the software based user base key */
    rc = token_wrap_sw_key(tokdata, size_n, n, size_p, p, tpm_data->hSRK,
                           TSS_KEY_NO_AUTHORIZATION | TSS_KEY_TYPE_STORAGE,
                           &tpm_data->hPrivateRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_wrap_sw_key failed. rc=0x%lu\n", rc);
        return rc;
    }

    if (openssl_write_key(tokdata, pkey, TPMTOK_PRIV_ROOT_KEY_FILE, pPin)) {
        TRACE_DEVEL("openssl_write_key failed.\n");
        EVP_PKEY_free(pkey);
        return CKR_FUNCTION_FAILED;
    }

    EVP_PKEY_free(pkey);

    /* store the user base key in a PKCS#11 object internally */
    rc = token_store_tss_key(tokdata, tpm_data->hPrivateRootKey,
                             TPMTOK_PRIVATE_ROOT_KEY,
                             &tpm_data->ckPrivateRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_store_tss_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    result = Tspi_Key_LoadKey(tpm_data->hPrivateRootKey, tpm_data->hSRK);
    if (result) {
        TRACE_ERROR("Tspi_Key_LoadKey: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext,
                                 tpm_data->hPrivateRootKey);
        tpm_data->hPrivateRootKey = NULL_HKEY;
        return CKR_FUNCTION_FAILED;
    }

    /* generate the private leaf key */
    rc = token_generate_leaf_key(tokdata, TPMTOK_PRIVATE_LEAF_KEY,
                                 pinHash, &tpm_data->hPrivateLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_generate_leaf_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    result = Tspi_Key_LoadKey(tpm_data->hPrivateLeafKey,
                              tpm_data->hPrivateRootKey);
    if (result) {
        TRACE_ERROR("Tspi_Key_LoadKey: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext,
                                 tpm_data->hPrivateRootKey);
        tpm_data->hPrivateRootKey = NULL_HKEY;
        Tspi_Context_CloseObject(tpm_data->tspContext,
                                 tpm_data->hPrivateLeafKey);
        tpm_data->hPrivateRootKey = NULL_HKEY;
        return CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV token_create_public_tree(STDLL_TokData_t * tokdata, CK_BYTE * pinHash,
                               CK_BYTE * pPin)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_RV rc;
    TSS_RESULT result;
    EVP_PKEY *pkey;
    unsigned int size_n, size_p;
    unsigned char n[256], p[256];

    /* all sw generated keys are 2048 bits */
    if ((pkey = openssl_gen_key(tokdata)) == NULL)
        return CKR_HOST_MEMORY;

    if (openssl_get_modulus_and_prime(pkey, &size_n, n, &size_p, p) != 0) {
        TRACE_DEVEL("openssl_get_modulus_and_prime failed\n");
        return CKR_FUNCTION_FAILED;
    }

    /* create the public root key */
    rc = token_wrap_sw_key(tokdata, size_n, n, size_p, p, tpm_data->hSRK,
                           TSS_KEY_NO_AUTHORIZATION | TSS_KEY_TYPE_STORAGE,
                           &tpm_data->hPublicRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_wrap_sw_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    if (openssl_write_key(tokdata, pkey, TPMTOK_PUB_ROOT_KEY_FILE, pPin)) {
        TRACE_DEVEL("openssl_write_key\n");
        EVP_PKEY_free(pkey);
        return CKR_FUNCTION_FAILED;
    }

    EVP_PKEY_free(pkey);

    result = Tspi_Key_LoadKey(tpm_data->hPublicRootKey, tpm_data->hSRK);
    if (result) {
        TRACE_ERROR("Tspi_Key_LoadKey: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext,
                                 tpm_data->hPublicRootKey);
        tpm_data->hPublicRootKey = NULL_HKEY;
        return CKR_FUNCTION_FAILED;
    }

    rc = token_store_tss_key(tokdata, tpm_data->hPublicRootKey,
                             TPMTOK_PUBLIC_ROOT_KEY, &tpm_data->ckPublicRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_store_tss_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* create the SO's leaf key */
    rc = token_generate_leaf_key(tokdata, TPMTOK_PUBLIC_LEAF_KEY,
                                 pinHash, &tpm_data->hPublicLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_generate_leaf_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    result = Tspi_Key_LoadKey(tpm_data->hPublicLeafKey,
                              tpm_data->hPublicRootKey);
    if (result) {
        TRACE_ERROR("Tspi_Key_LoadKey: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext,
                                 tpm_data->hPublicRootKey);
        tpm_data->hPublicRootKey = NULL_HKEY;
        Tspi_Context_CloseObject(tpm_data->tspContext,
                                 tpm_data->hPublicLeafKey);
        tpm_data->hPublicLeafKey = NULL_HKEY;
        return CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV token_migrate(STDLL_TokData_t * tokdata, int key_type, CK_BYTE * pin)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    EVP_PKEY *pkey;
    char *backup_loc;
    unsigned int size_n, size_p;
    unsigned char n[256], p[256];
    TSS_RESULT result;
    TSS_HKEY *phKey;
    CK_RV rc;
    CK_OBJECT_HANDLE *ckHandle;
    SESSION dummy_sess;

    /* set up dummy session */
    memset(&dummy_sess, 0, sizeof(SESSION));
    dummy_sess.session_info.state = CKS_RW_USER_FUNCTIONS;

    if (key_type == TPMTOK_PUBLIC_ROOT_KEY) {
        backup_loc = TPMTOK_PUB_ROOT_KEY_FILE;
        phKey = &tpm_data->hPublicRootKey;
        ckHandle = &tpm_data->ckPublicRootKey;
    } else if (key_type == TPMTOK_PRIVATE_ROOT_KEY) {
        backup_loc = TPMTOK_PRIV_ROOT_KEY_FILE;
        phKey = &tpm_data->hPrivateRootKey;
        ckHandle = &tpm_data->ckPrivateRootKey;
    } else {
        TRACE_ERROR("Invalid key type.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* read the backup key with the old pin */
    if ((rc = openssl_read_key(tokdata, backup_loc, pin, &pkey))) {
        if (rc == CKR_FILE_NOT_FOUND)
            rc = CKR_FUNCTION_FAILED;
        TRACE_DEVEL("openssl_read_key failed\n");
        return rc;
    }

    /* So, reading the backup openssl key off disk succeeded with the SOs PIN.
     * We will now try to re-wrap that key with the current SRK
     */
    if (openssl_get_modulus_and_prime(pkey, &size_n, n, &size_p, p) != 0) {
        TRACE_DEVEL("openssl_get_modulus_and_prime failed\n");
        EVP_PKEY_free(pkey);
        return CKR_FUNCTION_FAILED;
    }

    rc = token_wrap_sw_key(tokdata, size_n, n, size_p, p, tpm_data->hSRK,
                           TSS_KEY_TYPE_STORAGE | TSS_KEY_NO_AUTHORIZATION,
                           phKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_wrap_sw_key failed. rc=0x%lx\n", rc);
        EVP_PKEY_free(pkey);
        return rc;
    }
    EVP_PKEY_free(pkey);

    result = Tspi_Key_LoadKey(*phKey, tpm_data->hSRK);
    if (result) {
        TRACE_ERROR("Tspi_Key_LoadKey: 0x%x\n", result);
        Tspi_Context_CloseObject(tpm_data->tspContext, *phKey);
        *phKey = NULL_HKEY;
        return CKR_FUNCTION_FAILED;
    }

    /* Loading succeeded, so we need to get rid of the old PKCS#11 objects
     * and store them anew.
     */
    rc = token_find_key(tokdata, key_type, CKO_PUBLIC_KEY, ckHandle);
    if (rc != CKR_OK) {
        TRACE_ERROR("token_find_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_destroy_object(tokdata, &dummy_sess, *ckHandle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_destroy_object failed: 0x%lx\n", rc);
        return rc;
    }

    rc = token_find_key(tokdata, key_type, CKO_PRIVATE_KEY, ckHandle);
    if (rc != CKR_OK) {
        TRACE_ERROR("token_find_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_destroy_object(tokdata, &dummy_sess, *ckHandle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_destroy_object failed: 0x%lx\n", rc);
        return rc;
    }

    rc = token_store_tss_key(tokdata, *phKey, key_type, ckHandle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_store_tss_key failed: 0x%lx\n", rc);
        return rc;
    }

    return CKR_OK;
}

CK_RV token_specific_login(STDLL_TokData_t * tokdata, SESSION * sess,
                           CK_USER_TYPE userType, CK_CHAR_PTR pPin,
                           CK_ULONG ulPinLen)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    TSS_RESULT result;

    UNUSED(sess);

    result = token_load_srk(tokdata);
    if (result) {
        TRACE_DEVEL("token_load_srk failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    rc = compute_sha1(tokdata, pPin, ulPinLen, hash_sha);
    if (rc != CKR_OK) {
        TRACE_ERROR("compute_sha1 failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    if (userType == CKU_USER) {
        /* If the public root key doesn't exist yet, the SO hasn't init'd the
         * token */
        result = token_load_public_root_key(tokdata);
        if (result) {
            TRACE_DEVEL("token_load_public_root_key failed. "
                        "rc=0x%x\n", result);
            return CKR_USER_PIN_NOT_INITIALIZED;
        }

        /* find, load the private root key */
        rc = token_find_key(tokdata, TPMTOK_PRIVATE_ROOT_KEY,
                            CKO_PRIVATE_KEY, &tpm_data->ckPrivateRootKey);
        if (rc != CKR_OK) {
            /* user's key chain not found, this must be the initial login */
            if (memcmp(hash_sha, default_user_pin_sha, SHA1_HASH_SIZE)) {
                TRACE_ERROR("token_find_key failed and PIN != default\n");
                return CKR_PIN_INCORRECT;
            }

            tpm_data->not_initialized = 1;
            return CKR_OK;
        }

        rc = token_load_key(tokdata, tpm_data->ckPrivateRootKey,
                            tpm_data->hSRK, NULL, &tpm_data->hPrivateRootKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);

            /* Here, we've found the private root key, but its load failed.
             * This should only happen in a migration path, where we have
             * the PKCS#11 key store available, but the SRK is now
             * different. So, we will try to decrypt the PEM backup file
             * for the private root key using the given password. If that
             * succeeds, we will assume that we're in a migration path and
             * re-wrap the private root key to the new SRK.
             */
            if ((token_migrate(tokdata, TPMTOK_PRIVATE_ROOT_KEY, pPin))) {
                TRACE_DEVEL("token_migrate. rc=0x%lx\n", rc);
                return rc;
            }

            /* At this point, the public root key has been successfully read
             * from backup, re-wrapped to the new SRK, loaded and the PKCS#11
             * objects have been updated. Proceed with login as normal.
             */
        }

        /* find, load the user leaf key */
        rc = token_find_key(tokdata, TPMTOK_PRIVATE_LEAF_KEY,
                            CKO_PRIVATE_KEY, &tpm_data->ckPrivateLeafKey);
        if (rc != CKR_OK) {
            TRACE_ERROR("token_find_key failed. rc=0x%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        rc = token_load_key(tokdata, tpm_data->ckPrivateLeafKey,
                            tpm_data->hPrivateRootKey,
                            hash_sha, &tpm_data->hPrivateLeafKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        rc = token_verify_pin(tokdata, tpm_data->hPrivateLeafKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_verify_pin failed. failed. rc=0x%lx\n", rc);
            return rc;
        }

        memcpy(tpm_data->current_user_pin_sha, hash_sha, SHA1_HASH_SIZE);

        rc = XProcLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to get process lock.\n");
            return rc;
        }

        rc = load_private_token_objects(tokdata);

        if (rc != CKR_OK) {
            XProcUnLock(tokdata);
            return rc;
        } 

        tokdata->global_shm->priv_loaded = TRUE;

        rc = XProcUnLock(tokdata);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to release process lock.\n");
            return rc;
        }
    } else {
        /* SO path --
         */
        /* find, load the root key */
        rc = token_find_key(tokdata, TPMTOK_PUBLIC_ROOT_KEY,
                            CKO_PRIVATE_KEY, &tpm_data->ckPublicRootKey);
        if (rc != CKR_OK) {
            /* The SO hasn't set her PIN yet, compare the login pin with
             * the hard-coded value */
            if (memcmp(default_so_pin_sha, hash_sha, SHA1_HASH_SIZE)) {
                TRACE_ERROR("token_find_key failed and PIN != default\n");
                return CKR_PIN_INCORRECT;
            }

            tpm_data->not_initialized = 1;
            return CKR_OK;
        }

        /* The SO's key hierarchy has previously been created, so load the key
         * hierarchy and verify the pin using the TPM. */
        rc = token_load_key(tokdata, tpm_data->ckPublicRootKey,
                            tpm_data->hSRK, NULL, &tpm_data->hPublicRootKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);

            /* Here, we've found the public root key, but its load failed.
             * This should only happen in a migration path, where we have
             * the PKCS#11 key store available, but the SRK is now
             * different. So, we will try to decrypt the PEM backup file
             * for the public root key using the given password. If that
             * succeeds, we will assume that we're in a migration path and
             * re-wrap the public root key to the new SRK.
             */
            if ((token_migrate(tokdata, TPMTOK_PUBLIC_ROOT_KEY, pPin))) {
                TRACE_DEVEL("token_migrate. rc=0x%lx\n", rc);
                return rc;
            }

            /* At this point, the public root key has been successfully read
             * from backup, re-wrapped to the new SRK, loaded and the PKCS#11
             * objects have been updated. Proceed with login as normal.
             */
        }

        /* find, load the public leaf key */
        rc = token_find_key(tokdata, TPMTOK_PUBLIC_LEAF_KEY,
                            CKO_PRIVATE_KEY, &tpm_data->ckPublicLeafKey);
        if (rc != CKR_OK) {
            TRACE_ERROR("token_find_key failed. rc=0x%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        rc = token_load_key(tokdata, tpm_data->ckPublicLeafKey,
                            tpm_data->hPublicRootKey, hash_sha,
                            &tpm_data->hPublicLeafKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        rc = token_verify_pin(tokdata, tpm_data->hPublicLeafKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_verify_pin failed. rc=0x%lx\n", rc);
            return rc;
        }

        memcpy(tpm_data->current_so_pin_sha, hash_sha, SHA1_HASH_SIZE);
    }

    return rc;
}

CK_RV token_specific_logout(STDLL_TokData_t *tokdata)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;

    if (tpm_data->hPrivateLeafKey != NULL_HKEY) {
        Tspi_Key_UnloadKey(tpm_data->hPrivateLeafKey);
    } else if (tpm_data->hPublicLeafKey != NULL_HKEY) {
        Tspi_Key_UnloadKey(tpm_data->hPublicLeafKey);
    }

    clear_internal_structures(tokdata);

    return CKR_OK;
}

CK_RV token_specific_init_pin(STDLL_TokData_t * tokdata, SESSION * sess,
                              CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(pPin);
    UNUSED(ulPinLen);

    /* Since the SO must log in before calling C_InitPIN, we will
     * be able to return CKR_OK automatically here.
     * This is because the USER key structure is created at the
     * time of her first login, not at C_InitPIN time.
     */
    return CKR_OK;
}

CK_RV check_pin_properties(CK_USER_TYPE userType, CK_BYTE * pinHash,
                           CK_ULONG ulPinLen)
{
    /* make sure the new PIN is different */
    if (userType == CKU_USER) {
        if (!memcmp(pinHash, default_user_pin_sha, SHA1_HASH_SIZE)) {
            TRACE_ERROR("new PIN must not be the default\n");
            return CKR_PIN_INVALID;
        }
    } else {
        if (!memcmp(pinHash, default_so_pin_sha, SHA1_HASH_SIZE)) {
            TRACE_ERROR("new PIN must not be the default\n");
            return CKR_PIN_INVALID;
        }
    }

    if (ulPinLen > MAX_PIN_LEN || ulPinLen < MIN_PIN_LEN) {
        TRACE_ERROR("New PIN is out of size range\n");
        return CKR_PIN_LEN_RANGE;
    }

    return CKR_OK;
}

/* use this function call from set_pin only, where a not logged in public
 * session can provide the user pin which must be verified. This function
 * assumes that the pin has already been set once, so there's no migration
 * path option or checking of the default user pin.
 */
CK_RV verify_user_pin(STDLL_TokData_t * tokdata, CK_BYTE * hash_sha)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_RV rc;

    /* find, load the private root key */
    rc = token_find_key(tokdata, TPMTOK_PRIVATE_ROOT_KEY,
                        CKO_PRIVATE_KEY, &tpm_data->ckPrivateRootKey);
    if (rc != CKR_OK) {
        TRACE_ERROR("token_find_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = token_load_key(tokdata, tpm_data->ckPrivateRootKey,
                        tpm_data->hSRK, NULL, &tpm_data->hPrivateRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    /* find, load the user leaf key */
    rc = token_find_key(tokdata, TPMTOK_PRIVATE_LEAF_KEY,
                        CKO_PRIVATE_KEY, &tpm_data->ckPrivateLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_find_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = token_load_key(tokdata, tpm_data->ckPrivateLeafKey,
                        tpm_data->hPrivateRootKey, hash_sha,
                        &tpm_data->hPrivateLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = token_verify_pin(tokdata, tpm_data->hPrivateLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_verify_pin failed. failed. rc=0x%lx\n", rc);
        return rc;
    }

    return CKR_OK;
}

CK_RV token_specific_set_pin(STDLL_TokData_t * tokdata, SESSION * sess,
                             CK_CHAR_PTR pOldPin, CK_ULONG ulOldPinLen,
                             CK_CHAR_PTR pNewPin, CK_ULONG ulNewPinLen)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_BYTE oldpin_hash[SHA1_HASH_SIZE], newpin_hash[SHA1_HASH_SIZE];
    CK_RV rc;
    EVP_PKEY *pkey_root;
    TSS_RESULT result;

    if (!sess) {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_HANDLE_INVALID));
        return CKR_SESSION_HANDLE_INVALID;
    }

    rc = compute_sha1(tokdata, pOldPin, ulOldPinLen, oldpin_hash);
    if (rc != CKR_OK) {
        TRACE_ERROR("compute_sha1 failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = compute_sha1(tokdata, pNewPin, ulNewPinLen, newpin_hash);
    if (rc != CKR_OK) {
        TRACE_ERROR("compute_sha1 failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    result = token_load_srk(tokdata);
    if (result) {
        TRACE_DEVEL("token_load_srk failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* From the PKCS#11 2.20 spec: "C_SetPIN modifies the PIN of the user that
     * is currently logged in, or the CKU_USER PIN if the session is not logged
     * in."
     * A non R/W session fails with CKR_SESSION_READ_ONLY.
     */
    if (sess->session_info.state == CKS_RW_USER_FUNCTIONS ||
        sess->session_info.state == CKS_RW_PUBLIC_SESSION) {
        if (tpm_data->not_initialized) {
            if (memcmp(oldpin_hash, default_user_pin_sha, SHA1_HASH_SIZE)) {
                TRACE_ERROR("old PIN != default for an "
                            "uninitialized user\n");
                return CKR_PIN_INCORRECT;
            }

            rc = check_pin_properties(CKU_USER, newpin_hash, ulNewPinLen);
            if (rc != CKR_OK) {
                return rc;
            }

            rc = token_create_private_tree(tokdata, newpin_hash, pNewPin);
            if (rc != CKR_OK) {
                TRACE_DEVEL("FAILED creating USER tree.\n");
                return CKR_FUNCTION_FAILED;
            }

            tokdata->nv_token_data->token_info.flags &=
                ~(CKF_USER_PIN_TO_BE_CHANGED);
            tokdata->nv_token_data->token_info.flags |=
                CKF_USER_PIN_INITIALIZED;

            return save_token_data(tokdata, sess->session_info.slotID);
        }

        if (sess->session_info.state == CKS_RW_USER_FUNCTIONS) {
            /* if we're already logged in, just verify the hash */
            if (memcmp(tpm_data->current_user_pin_sha, oldpin_hash,
                       SHA1_HASH_SIZE)) {
                TRACE_ERROR("USER pin incorrect\n");
                return CKR_PIN_INCORRECT;
            }
        } else {
            rc = verify_user_pin(tokdata, oldpin_hash);
            if (rc != CKR_OK) {
                return rc;
            }
        }

        rc = check_pin_properties(CKU_USER, newpin_hash, ulNewPinLen);
        if (rc != CKR_OK) {
            return rc;
        }

        /* change the auth on the TSS object */
        result = tss_change_auth(tokdata, tpm_data->hPrivateLeafKey,
                                 tpm_data->hPrivateRootKey, newpin_hash);
        if (result) {
            TRACE_ERROR("tss_change_auth failed\n");
            return CKR_FUNCTION_FAILED;
        }

        /* destroy the old PKCS#11 priv key object and create a new one */
        rc = token_update_private_key(tokdata, tpm_data->hPrivateLeafKey,
                                      TPMTOK_PRIVATE_LEAF_KEY);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_update_private_key failed.\n");
            return rc;
        }

        /* read the backup key with the old pin */
        rc = openssl_read_key(tokdata, TPMTOK_PRIV_ROOT_KEY_FILE, pOldPin,
                              &pkey_root);
        if (rc != CKR_OK) {
            if (rc == CKR_FILE_NOT_FOUND) {
                /* If the user has moved his backup PEM file off site, allow a
                 * change auth to succeed without updating it. */
                return CKR_OK;
            }

            TRACE_DEVEL("openssl_read_key failed\n");
            return rc;
        }

        /* write it out using the new pin */
        rc = openssl_write_key(tokdata, pkey_root, TPMTOK_PRIV_ROOT_KEY_FILE,
                               pNewPin);
        if (rc != CKR_OK) {
            EVP_PKEY_free(pkey_root);
            TRACE_DEVEL("openssl_write_key failed\n");
            return CKR_FUNCTION_FAILED;
        }
        EVP_PKEY_free(pkey_root);
    } else if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
        if (tpm_data->not_initialized) {
            if (memcmp(default_so_pin_sha, oldpin_hash, SHA1_HASH_SIZE)) {
                TRACE_ERROR("old PIN != default for an " "uninitialized SO\n");
                return CKR_PIN_INCORRECT;
            }

            rc = check_pin_properties(CKU_SO, newpin_hash, ulNewPinLen);
            if (rc != CKR_OK) {
                return rc;
            }

            rc = token_create_public_tree(tokdata, newpin_hash, pNewPin);
            if (rc != CKR_OK) {
                TRACE_DEVEL("FAILED creating SO tree.\n");
                return CKR_FUNCTION_FAILED;
            }

            tokdata->nv_token_data->token_info.flags &=
                ~(CKF_SO_PIN_TO_BE_CHANGED);

            return save_token_data(tokdata, sess->session_info.slotID);
        }

        if (memcmp(tpm_data->current_so_pin_sha, oldpin_hash, SHA1_HASH_SIZE)) {
            TRACE_ERROR("SO PIN incorrect\n");
            return CKR_PIN_INCORRECT;
        }

        rc = check_pin_properties(CKU_SO, newpin_hash, ulNewPinLen);
        if (rc != CKR_OK) {
            return rc;
        }

        /* change auth on the SO's leaf key */
        result = tss_change_auth(tokdata, tpm_data->hPublicLeafKey,
                                 tpm_data->hPublicRootKey, newpin_hash);
        if (result) {
            TRACE_ERROR("tss_change_auth failed\n");
            return CKR_FUNCTION_FAILED;
        }

        rc = token_update_private_key(tokdata, tpm_data->hPublicLeafKey,
                                      TPMTOK_PUBLIC_LEAF_KEY);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_update_private_key failed.\n");
            return rc;
        }

        /* change auth on the public root key's openssl backup */
        rc = openssl_read_key(tokdata, TPMTOK_PUB_ROOT_KEY_FILE, pOldPin,
                              &pkey_root);
        if (rc != CKR_OK) {
            if (rc == CKR_FILE_NOT_FOUND) {
                /* If the user has moved his backup PEM file off site, allow a
                 * change auth to succeed without updating it. */
                return CKR_OK;
            }

            TRACE_DEVEL("openssl_read_key failed\n");
            return rc;
        }

        /* write it out using the new pin */
        rc = openssl_write_key(tokdata, pkey_root, TPMTOK_PUB_ROOT_KEY_FILE,
                               pNewPin);
        if (rc != CKR_OK) {
            EVP_PKEY_free(pkey_root);
            TRACE_DEVEL("openssl_write_key failed\n");
            return CKR_FUNCTION_FAILED;
        }
        EVP_PKEY_free(pkey_root);
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
        rc = CKR_SESSION_READ_ONLY;
    }

    return rc;
}

static CK_RV delete_tpm_data(STDLL_TokData_t * tokdata)
{
    char *cmd = NULL;
    struct passwd *pw = NULL;

    pw = getpwuid(getuid());
    if (pw == NULL) {
        TRACE_ERROR("getpwuid failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }
    // delete the TOK_OBJ data files
    if (asprintf(&cmd, "%s %s/%s/%s/* > /dev/null 2>&1", DEL_CMD,
                 tokdata->pk_dir, pw->pw_name, PK_LITE_OBJ_DIR) < 0) {
        return CKR_HOST_MEMORY;
    }
    if (system(cmd) == -1)
        TRACE_ERROR("system() failed.\n");

    free(cmd);

    // delete the OpenSSL backup keys
    if (asprintf(&cmd, "%s %s/%s/%s > /dev/null 2>&1", DEL_CMD,
                 tokdata->pk_dir, pw->pw_name, TPMTOK_PUB_ROOT_KEY_FILE) < 0) {
        return CKR_HOST_MEMORY;
    }
    if (system(cmd) == -1)
        TRACE_ERROR("system() failed.\n");

    free(cmd);

    if (asprintf(&cmd, "%s %s/%s/%s > /dev/null 2>&1", DEL_CMD,
                 tokdata->pk_dir, pw->pw_name, TPMTOK_PRIV_ROOT_KEY_FILE) < 0) {
        return CKR_HOST_MEMORY;
    }
    if (system(cmd) == -1)
        TRACE_ERROR("system() failed.\n");

    free(cmd);

    // delete the masterkey
    if (asprintf(&cmd, "%s %s/%s/%s > /dev/null 2>&1", DEL_CMD,
                 tokdata->pk_dir, pw->pw_name, TPMTOK_MASTERKEY_PRIVATE) < 0) {
        return CKR_HOST_MEMORY;
    }
    if (system(cmd) == -1)
        TRACE_ERROR("system() failed.\n");

    free(cmd);

    return CKR_OK;
}

/* only called at token init time */
CK_RV token_specific_init_token(STDLL_TokData_t * tokdata, CK_SLOT_ID sid,
                                CK_CHAR_PTR pPin, CK_ULONG ulPinLen,
                                CK_CHAR_PTR pLabel)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_RV rc;

    rc = compute_sha1(tokdata, pPin, ulPinLen, hash_sha);
    if (rc != CKR_OK) {
        TRACE_ERROR("compute_sha1 failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    /* find, load the migratable root key */
    rc = token_find_key(tokdata, TPMTOK_PUBLIC_ROOT_KEY,
                        CKO_PRIVATE_KEY, &tpm_data->ckPublicRootKey);
    if (rc != CKR_OK) {
        /* The SO hasn't set her PIN yet, compare the login pin with
         * the hard-coded value */
        if (memcmp(default_so_pin_sha, hash_sha, SHA1_HASH_SIZE)) {
            TRACE_ERROR("token_find_key failed and PIN != default\n");
            return CKR_PIN_INCORRECT;
        }
        goto done;
    }

    rc = token_load_srk(tokdata);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_load_srk failed. rc = 0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    /* we found the root key, so check by loading the chain */
    rc = token_load_key(tokdata, tpm_data->ckPublicRootKey,
                        tpm_data->hSRK, NULL, &tpm_data->hPublicRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    /* find, load the public leaf key */
    rc = token_find_key(tokdata, TPMTOK_PUBLIC_LEAF_KEY,
                        CKO_PRIVATE_KEY, &tpm_data->ckPublicLeafKey);
    if (rc != CKR_OK) {
        TRACE_ERROR("token_find_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = token_load_key(tokdata, tpm_data->ckPublicLeafKey,
                        tpm_data->hPublicRootKey, hash_sha,
                        &tpm_data->hPublicLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_load_key(MigLeafKey) Failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = token_verify_pin(tokdata, tpm_data->hPublicLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_verify_pin failed. rc=0x%lx\n", rc);
        return rc;
    }

done:
    // Before we reconstruct all the data, we should delete the
    // token objects from the filesystem.
    object_mgr_destroy_token_objects(tokdata);
    rc = delete_tpm_data(tokdata);
    if (rc != CKR_OK)
        return rc;

    // META This should be fine since the open session checking should occur at
    // the API not the STDLL
    load_token_data(tokdata, sid);
    init_slotInfo(&tokdata->slot_info);
    memcpy(tokdata->nv_token_data->so_pin_sha, hash_sha, SHA1_HASH_SIZE);
    tokdata->nv_token_data->token_info.flags |= CKF_TOKEN_INITIALIZED;
    memcpy(tokdata->nv_token_data->token_info.label, pLabel, 32);

    // New for v2.11 - KEY
    tokdata->nv_token_data->token_info.flags |= CKF_TOKEN_INITIALIZED;

    rc = save_token_data(tokdata, sid);
    if (rc != CKR_OK) {
        TRACE_DEVEL("save_token_data failed.\n");
        return rc;
    }

    return CKR_OK;
}

CK_RV token_specific_final(STDLL_TokData_t *tokdata,
                           CK_BBOOL in_fork_initializer)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;

    TRACE_INFO("tpm %s running\n", __func__);

    /*
     * Only close the context if not in in_fork_initializer. If we close the
     * context in a forked child process, this also closes the parent's context.
     */
    if (!in_fork_initializer) {
        result = Tspi_Context_Close(tpm_data->tspContext);
        if (result) {
            TRACE_ERROR("Tspi_Context_Close failed. rc=0x%x\n", result);
            return CKR_FUNCTION_FAILED;
        }
    }

    clear_internal_structures(tokdata);

    free(tpm_data);
    tokdata->private_data = NULL;

    return CKR_OK;
}

CK_RV token_specific_des_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_BYTE **des_key, CK_ULONG *len,
                                 CK_ULONG keysize, CK_BBOOL *is_opaque)
{
    UNUSED(tmpl);

    *des_key = malloc(keysize);
    if (*des_key == NULL)
        return CKR_HOST_MEMORY;
    *len = keysize;
    *is_opaque = FALSE;

    // Nothing different to do for DES or TDES here as this is just
    // random data...  Validation handles the rest
    // Only check for weak keys when DES.
    if (keysize == (3 * DES_KEY_SIZE)) {
        rng_generate(tokdata, *des_key, keysize);
    } else {
        do {
            rng_generate(tokdata, *des_key, keysize);
        } while (des_check_weak_key(*des_key) == TRUE);
    }

    // we really need to validate the key for parity etc...
    // we should do that here... The caller validates the single des keys
    // against the known and suspected poor keys..
    return CKR_OK;
}

CK_RV token_specific_des_ecb(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE encrypt)
{
    return openssl_specific_des_ecb(tokdata, in_data, in_data_len,
                                    out_data, out_data_len, key, encrypt);
}

CK_RV token_specific_des_cbc(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    return openssl_specific_des_cbc(tokdata, in_data, in_data_len,
                                    out_data, out_data_len, key,
                                    init_v, encrypt);
}

CK_RV token_specific_tdes_ecb(STDLL_TokData_t *tokdata,
                              CK_BYTE *in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE *out_data,
                              CK_ULONG *out_data_len,
                              OBJECT *key, CK_BYTE encrypt)
{
    return openssl_specific_tdes_ecb(tokdata, in_data, in_data_len,
                                     out_data, out_data_len, key, encrypt);
}

CK_RV token_specific_tdes_cbc(STDLL_TokData_t *tokdata,
                              CK_BYTE *in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE *out_data,
                              CK_ULONG *out_data_len,
                              OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    return openssl_specific_tdes_cbc(tokdata, in_data, in_data_len,
                                     out_data, out_data_len, key,
                                     init_v, encrypt);
}

/* wrap the 20 bytes of auth data @authData and store in an attribute of the two
 * keys.
 */
CK_RV token_wrap_auth_data(STDLL_TokData_t * tokdata,
                           CK_BYTE * authData, TEMPLATE * publ_tmpl,
                           TEMPLATE * priv_tmpl)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *new_attr;

    TSS_HKEY hParentKey;
    TSS_HENCDATA hEncData;
    BYTE *blob;
    UINT32 blob_size;

    if ((tpm_data->hPrivateLeafKey == NULL_HKEY) &&
        (tpm_data->hPublicLeafKey == NULL_HKEY)) {
        TRACE_ERROR("Shouldn't be wrapping auth data in a " "public path!\n");
        return CKR_FUNCTION_FAILED;
    } else if (tpm_data->hPublicLeafKey != NULL_HKEY) {
        hParentKey = tpm_data->hPublicLeafKey;
    } else {
        hParentKey = tpm_data->hPrivateLeafKey;
    }

    /* create the encrypted data object */
    rc = Tspi_Context_CreateObject(tpm_data->tspContext,
                                   TSS_OBJECT_TYPE_ENCDATA,
                                   TSS_ENCDATA_BIND, &hEncData);
    if (rc != CKR_OK) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%lx\n", rc);
        return rc;
    }

    rc = Tspi_Data_Bind(hEncData, hParentKey, SHA1_HASH_SIZE, authData);
    if (rc != CKR_OK) {
        TRACE_ERROR("Tspi_Data_Bind failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* pull the encrypted data out of the encrypted data object */
    rc = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
                            TSS_TSPATTRIB_ENCDATABLOB_BLOB, &blob_size, &blob);
    if (rc != CKR_OK) {
        TRACE_ERROR("Tspi_SetAttribData failed. rc=0x%lx\n", rc);
        return rc;
    }

    rc = build_attribute(CKA_ENC_AUTHDATA, blob, blob_size, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed.\n");
        return rc;
    }
    rc = template_update_attribute(publ_tmpl, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        return rc;
    }

    rc = build_attribute(CKA_ENC_AUTHDATA, blob, blob_size, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed.\n");
        return rc;
    }
    rc = template_update_attribute(priv_tmpl, new_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(new_attr);
        return rc;
    }

    return rc;
}

CK_RV token_unwrap_auth_data(STDLL_TokData_t * tokdata,
                             CK_BYTE * encAuthData, CK_ULONG encAuthDataLen,
                             TSS_HKEY hKey, BYTE ** authData)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;
    TSS_HENCDATA hEncData;
    BYTE *buf;
    UINT32 buf_size;

    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_ENCDATA,
                                       TSS_ENCDATA_BIND, &hEncData);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_SetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
                                TSS_TSPATTRIB_ENCDATABLOB_BLOB,
                                encAuthDataLen, encAuthData);
    if (result) {
        TRACE_ERROR("Tspi_SetAttribData failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* unbind the data, receiving the plaintext back */
    result = Tspi_Data_Unbind(hEncData, hKey, &buf_size, &buf);
    if (result) {
        TRACE_ERROR("Tspi_Data_Unbind failed: rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    if (buf_size != SHA1_HASH_SIZE) {
        TRACE_ERROR("auth data decrypt error.\n");
        return CKR_FUNCTION_FAILED;
    }

    *authData = buf;

    return CKR_OK;
}

// convert from the local PKCS11 template representation to
// the underlying requirement
// returns the pointer to the local key representation
CK_BYTE *rsa_convert_public_key(OBJECT * key_obj)
{
    CK_ATTRIBUTE *modulus = NULL;
    CK_BYTE *ret;
    CK_RV rc;

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &modulus);
    if (rc != CKR_OK)
        return NULL;

    ret = malloc(modulus->ulValueLen);
    if (ret == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return NULL;
    }

    memcpy(ret, modulus->pValue, modulus->ulValueLen);

    return ret;
}

CK_RV token_specific_rsa_generate_keypair(STDLL_TokData_t * tokdata,
                                          TEMPLATE * publ_tmpl,
                                          TEMPLATE * priv_tmpl)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG mod_bits = 0;
    CK_RV rc;
    CK_BYTE tpm_pubexp[3] = { 1, 0, 1 };        // 65537
    TSS_FLAG initFlags = 0;
    BYTE authHash[SHA1_HASH_SIZE];
    BYTE *authData = NULL;
    TSS_HKEY hKey = NULL_HKEY;
    TSS_HKEY hParentKey = NULL_HKEY;
    TSS_RESULT result;
    UINT32 ulBlobLen;
    BYTE *rgbBlob;

    /* Make sure the public exponent is usable */
    if ((util_check_public_exponent(publ_tmpl))) {
        TRACE_DEVEL("Invalid public exponent\n");
        return CKR_TEMPLATE_INCONSISTENT;
    }

    rc = template_attribute_get_ulong(publ_tmpl, CKA_MODULUS_BITS, &mod_bits);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS_BITS for the key\n");
        return rc; // should never happen
    }

    if ((initFlags = util_get_keysize_flag(mod_bits)) == 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        return CKR_KEY_SIZE_RANGE;
    }

    /* If we're not logged in, hPrivateLeafKey and hPublicLeafKey
     * should be NULL */
    if ((tpm_data->hPrivateLeafKey == NULL_HKEY) &&
        (tpm_data->hPublicLeafKey == NULL_HKEY)) {
        /* public session, wrap key with the PRK */
        initFlags |=
            TSS_KEY_TYPE_LEGACY | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_MIGRATABLE;

        if ((result = token_load_public_root_key(tokdata))) {
            TRACE_DEVEL("token_load_public_root_key failed. "
                        "rc=%x\n", result);
            return CKR_FUNCTION_FAILED;
        }

        hParentKey = tpm_data->hPublicRootKey;
    } else if (tpm_data->hPrivateLeafKey != NULL_HKEY) {
        /* logged in USER session */
        initFlags |=
            TSS_KEY_TYPE_LEGACY | TSS_KEY_AUTHORIZATION | TSS_KEY_MIGRATABLE;

        /* get a random SHA1 hash for the auth data */
        if ((rc = token_specific_rng(tokdata, authHash, SHA1_HASH_SIZE))) {
            TRACE_DEVEL("token_rng failed. rc=%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        authData = authHash;
        hParentKey = tpm_data->hPrivateRootKey;
    } else {
        /* logged in SO session */
        initFlags |=
            TSS_KEY_TYPE_LEGACY | TSS_KEY_AUTHORIZATION | TSS_KEY_MIGRATABLE;

        /* get a random SHA1 hash for the auth data */
        rc = token_specific_rng(tokdata, authHash, SHA1_HASH_SIZE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_rng failed. rc=0x%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        authData = authHash;
        hParentKey = tpm_data->hPublicRootKey;
    }

    result = tss_generate_key(tokdata, initFlags, authData, hParentKey, &hKey);
    if (result) {
        TRACE_ERROR("tss_generate_key returned 0x%x\n", result);
        return result;
    }

    result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_KEY_BLOB,
                                TSS_TSPATTRIB_KEYBLOB_BLOB,
                                &ulBlobLen, &rgbBlob);
    if (result) {
        TRACE_ERROR("Tspi_GetAttribData failed with rc: 0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, rgbBlob, ulBlobLen, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_IBM_OPAQUE) failed.\n");
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        return rc;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        return rc;
    }
    rc = build_attribute(CKA_IBM_OPAQUE, rgbBlob, ulBlobLen, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_IBM_OPAQUE) failed.\n");
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        return rc;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        return rc;
    }

    Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);

    /* grab the public key to put into the public key object */
    result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
                                TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
                                &ulBlobLen, &rgbBlob);
    if (result) {
        TRACE_ERROR("Tspi_GetAttribData failed with rc: 0x%x\n", result);
        return result;
    }

    /* add the public key blob to the object template */
    rc = build_attribute(CKA_MODULUS, rgbBlob, ulBlobLen, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_MODULUS) failed.\n");
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        return rc;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        return rc;
    }

    /* add the public key blob to the object template */
    rc = build_attribute(CKA_MODULUS, rgbBlob, ulBlobLen, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_MODULUS) failed.\n");
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        return rc;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);
        return rc;
    }
    Tspi_Context_FreeMemory(tpm_data->tspContext, rgbBlob);

    /* put the public exponent into the private key object */
    rc = build_attribute(CKA_PUBLIC_EXPONENT,
                         tpm_pubexp, sizeof(tpm_pubexp), &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_PUBLIC_EXPONENT) failed.\n");
        return rc;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(attr);
        return rc;
    }

    /* wrap the authdata and put it into an object */
    if (authData != NULL) {
        rc = token_wrap_auth_data(tokdata, authData, publ_tmpl, priv_tmpl);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_wrap_auth_data failed with rc: 0x%lx\n", rc);
        }
    }

    return rc;
}

CK_RV token_rsa_load_key(STDLL_TokData_t * tokdata, OBJECT * key_obj,
                         TSS_HKEY * phKey)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;
    TSS_HPOLICY hPolicy = NULL_HPOLICY;
    TSS_HKEY hParentKey;
    BYTE *authData = NULL;
    CK_ATTRIBUTE *attr;
    CK_RV rc;
    CK_OBJECT_HANDLE handle;

    if (tpm_data->hPrivateLeafKey != NULL_HKEY) {
        hParentKey = tpm_data->hPrivateRootKey;
    } else {
        result = token_load_public_root_key(tokdata);
        if (result) {
            TRACE_DEVEL("token_load_public_root_key failed. "
                        "rc=%x\n", result);
            return CKR_FUNCTION_FAILED;
        }

        hParentKey = tpm_data->hPublicRootKey;
    }


    rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                          &attr);
    if (rc != CKR_OK) {
        /* if the key blob wasn't found, then try to wrap the key */
        rc = object_mgr_find_in_map2(tokdata, key_obj, &handle);
        if (rc != CKR_OK)
            return CKR_FUNCTION_FAILED;

        /* The Object holds the READ lock, but token_load_key might need the
         * WRITE lock, so unlock the object
         */
        rc = object_unlock(key_obj);
        if (rc != CKR_OK)
            return rc;

        rc = token_load_key(tokdata, handle, hParentKey, NULL, phKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
            object_lock(key_obj, READ_LOCK);
            return rc;
        }

        /* Get the READ lock again */
        rc = object_lock(key_obj, READ_LOCK);
        if (rc != CKR_OK)
            return rc;

        /* try again to get the CKA_IBM_OPAQUE attr */
        rc = template_attribute_get_non_empty(key_obj->template, CKA_IBM_OPAQUE,
                                              &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find key blob\n");
            return rc;
        }
    }

    result = Tspi_Context_LoadKeyByBlob(tpm_data->tspContext, hParentKey,
                                        attr->ulValueLen, attr->pValue, phKey);
    if (result) {
        TRACE_ERROR("Tspi_Context_LoadKeyByBlob failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* auth data may be required */
    rc = template_attribute_get_non_empty(key_obj->template, CKA_ENC_AUTHDATA,
                                          &attr);
    if (rc == CKR_OK) {
        if ((tpm_data->hPrivateLeafKey == NULL_HKEY) &&
            (tpm_data->hPublicLeafKey == NULL_HKEY)) {
            TRACE_ERROR("Shouldn't be in a public session here\n");
            return CKR_FUNCTION_FAILED;
        } else if (tpm_data->hPublicLeafKey != NULL_HKEY) {
            hParentKey = tpm_data->hPublicLeafKey;
        } else {
            hParentKey = tpm_data->hPrivateLeafKey;
        }

        result = token_unwrap_auth_data(tokdata, attr->pValue, attr->ulValueLen,
                                        hParentKey, &authData);
        if (result) {
            TRACE_DEVEL("token_unwrap_auth_data: 0x%x\n", result);
            return CKR_FUNCTION_FAILED;
        }

        result = Tspi_GetPolicyObject(*phKey, TSS_POLICY_USAGE, &hPolicy);
        if (result) {
            TRACE_ERROR("Tspi_GetPolicyObject: 0x%x\n", result);
            return CKR_FUNCTION_FAILED;
        }

        /* If the policy handle returned is the same as the context's default
         * policy, then a new policy must be created and assigned to the key.
         * Otherwise, just set the secret in the policy */
        if (hPolicy == tpm_data->hDefaultPolicy) {
            result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                               TSS_OBJECT_TYPE_POLICY,
                                               TSS_POLICY_USAGE, &hPolicy);
            if (result) {
                TRACE_ERROR("Tspi_Context_CreateObject: 0x%x\n", result);
                return CKR_FUNCTION_FAILED;
            }

            result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1,
                                           SHA1_HASH_SIZE, authData);
            if (result) {
                TRACE_ERROR("Tspi_Policy_SetSecret failed. "
                            "rc=0x%x\n", result);
                return CKR_FUNCTION_FAILED;
            }

            result = Tspi_Policy_AssignToObject(hPolicy, *phKey);
            if (result) {
                TRACE_ERROR("Tspi_Policy_AssignToObject failed."
                            " rc=0x%x\n", result);
                return CKR_FUNCTION_FAILED;
            }
        } else {
            result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_SHA1,
                                           SHA1_HASH_SIZE, authData);
            if (result) {
                TRACE_ERROR("Tspi_Policy_SetSecret failed. rc=0x%x\n", result);
                return CKR_FUNCTION_FAILED;
            }
        }

        Tspi_Context_FreeMemory(tpm_data->tspContext, authData);
    }

    return CKR_OK;
}

CK_RV token_specific_rsa_decrypt(STDLL_TokData_t * tokdata,
                                 CK_BYTE * in_data,
                                 CK_ULONG in_data_len,
                                 CK_BYTE * out_data,
                                 CK_ULONG * out_data_len, OBJECT * key_obj)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    CK_RV rc;
    TSS_RESULT result;
    TSS_HKEY hKey;
    TSS_HENCDATA hEncData = NULL_HENCDATA;
    UINT32 buf_size = 0;
    BYTE *buf = NULL;

    rc = token_rsa_load_key(tokdata, key_obj, &hKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_rsa_load_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* push the data into the encrypted data object */
    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_ENCDATA,
                                       TSS_ENCDATA_BIND, &hEncData);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_SetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
                                TSS_TSPATTRIB_ENCDATABLOB_BLOB,
                                in_data_len, in_data);
    if (result) {
        TRACE_ERROR("Tspi_SetAttribData failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* unbind the data, receiving the plaintext back */
    TRACE_DEVEL("unbinding data with size: %ld\n", in_data_len);

    result = Tspi_Data_Unbind(hEncData, hKey, &buf_size, &buf);
    if (result) {
        TRACE_ERROR("Tspi_Data_Unbind failed: 0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    if (*out_data_len < buf_size) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        Tspi_Context_FreeMemory(tpm_data->tspContext, buf);
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(out_data, buf, buf_size);
    *out_data_len = buf_size;

    Tspi_Context_FreeMemory(tpm_data->tspContext, buf);

    return CKR_OK;
}

CK_RV token_specific_rsa_verify(STDLL_TokData_t * tokdata,
                                SESSION * sess,
                                CK_BYTE * in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE * sig,
                                CK_ULONG sig_len, OBJECT * key_obj)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;
    TSS_HHASH hHash;
    TSS_HKEY hKey;
    CK_RV rc;

    UNUSED(sess);

    rc = token_rsa_load_key(tokdata, key_obj, &hKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_rsa_load_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* Create the hash object we'll use to sign */
    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_HASH,
                                       TSS_HASH_OTHER, &hHash);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* Insert the data into the hash object */
    result = Tspi_Hash_SetHashValue(hHash, in_data_len, in_data);
    if (result) {
        TRACE_ERROR("Tspi_Hash_SetHashValue failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* Verify */
    result = Tspi_Hash_VerifySignature(hHash, hKey, sig_len, sig);
    if (result != TSS_SUCCESS && TPMTOK_TSS_ERROR_CODE(result) != TSS_E_FAIL) {
        TRACE_ERROR("Tspi_Hash_VerifySignature failed. rc=0x%x\n", result);
    }

    if (TPMTOK_TSS_ERROR_CODE(result) == TSS_E_FAIL) {
        rc = CKR_SIGNATURE_INVALID;
    } else {
        rc = CKR_OK;
    }

    return rc;
}

CK_RV token_specific_rsa_sign(STDLL_TokData_t * tokdata,
                              SESSION * sess,
                              CK_BYTE * in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE * out_data,
                              CK_ULONG * out_data_len, OBJECT * key_obj)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;
    TSS_HHASH hHash;
    BYTE *sig;
    UINT32 sig_len;
    TSS_HKEY hKey;
    CK_RV rc;

    UNUSED(sess);

    rc = token_rsa_load_key(tokdata, key_obj, &hKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_rsa_load_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* Create the hash object we'll use to sign */
    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_HASH,
                                       TSS_HASH_OTHER, &hHash);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* Insert the data into the hash object */
    result = Tspi_Hash_SetHashValue(hHash, in_data_len, in_data);
    if (result) {
        TRACE_ERROR("Tspi_Hash_SetHashValue failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* Sign */
    result = Tspi_Hash_Sign(hHash, hKey, &sig_len, &sig);
    if (result) {
        TRACE_ERROR("Tspi_Hash_Sign failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    if (sig_len > *out_data_len) {
        TRACE_ERROR("Buffer too small to hold result.\n");
        Tspi_Context_FreeMemory(tpm_data->tspContext, sig);
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(out_data, sig, sig_len);
    *out_data_len = sig_len;
    Tspi_Context_FreeMemory(tpm_data->tspContext, sig);

    return CKR_OK;
}


CK_RV token_specific_rsa_encrypt(STDLL_TokData_t * tokdata,
                                 CK_BYTE * in_data,
                                 CK_ULONG in_data_len,
                                 CK_BYTE * out_data,
                                 CK_ULONG * out_data_len, OBJECT * key_obj)
{
    tpm_private_data_t *tpm_data = (tpm_private_data_t *)tokdata->private_data;
    TSS_RESULT result;
    TSS_HENCDATA hEncData;
    BYTE *dataBlob;
    UINT32 dataBlobSize;
    TSS_HKEY hKey;
    CK_RV rc;

    rc = token_rsa_load_key(tokdata, key_obj, &hKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_rsa_load_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    result = Tspi_Context_CreateObject(tpm_data->tspContext,
                                       TSS_OBJECT_TYPE_ENCDATA,
                                       TSS_ENCDATA_BIND, &hEncData);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_Data_Bind(hEncData, hKey, in_data_len, in_data);
    if (result) {
        TRACE_ERROR("Tspi_Data_Bind failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
                                TSS_TSPATTRIB_ENCDATABLOB_BLOB,
                                &dataBlobSize, &dataBlob);
    if (result) {
        TRACE_ERROR("Tspi_SetAttribData failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    if (dataBlobSize > *out_data_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        Tspi_Context_FreeMemory(tpm_data->tspContext, dataBlob);
        return CKR_DATA_LEN_RANGE;
    }

    memcpy(out_data, dataBlob, dataBlobSize);
    *out_data_len = dataBlobSize;
    Tspi_Context_FreeMemory(tpm_data->tspContext, dataBlob);

    return CKR_OK;
}

CK_RV token_specific_rsa_verify_recover(STDLL_TokData_t * tokdata,
                                        CK_BYTE * signature, CK_ULONG sig_len,
                                        CK_BYTE * out_data,
                                        CK_ULONG * out_data_len,
                                        OBJECT * key_obj)
{
    CK_RV rc;

    rc = token_specific_rsa_encrypt(tokdata, signature, sig_len, out_data,
                                    out_data_len, key_obj);

    if (rc != CKR_OK)
        TRACE_DEVEL("token specific rsa_encrypt failed.\n");

    return rc;
}

CK_RV token_specific_aes_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                 CK_BYTE **key, CK_ULONG *len, CK_ULONG keysize,
                                 CK_BBOOL *is_opaque)
{
    UNUSED(tmpl);

    *key = malloc(keysize);
    if (*key == NULL)
        return CKR_HOST_MEMORY;
    *len = keysize;
    *is_opaque = FALSE;

    return rng_generate(tokdata, *key, keysize);
}

CK_RV token_specific_aes_ecb(STDLL_TokData_t *tokdata, SESSION  *session,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE encrypt)
{
    UNUSED(session);

    return openssl_specific_aes_ecb(tokdata, in_data, in_data_len,
                                    out_data, out_data_len, key, encrypt);
}

CK_RV token_specific_aes_cbc(STDLL_TokData_t *tokdata, SESSION  *session,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    UNUSED(session);

    return openssl_specific_aes_cbc(tokdata, in_data, in_data_len,
                                    out_data, out_data_len, key,
                                    init_v, encrypt);
}

CK_RV token_specific_get_mechanism_list(STDLL_TokData_t * tokdata,
                                        CK_MECHANISM_TYPE_PTR pMechanismList,
                                        CK_ULONG_PTR pulCount)
{
    return ock_generic_get_mechanism_list(tokdata, pMechanismList, pulCount, NULL);
}

CK_RV token_specific_get_mechanism_info(STDLL_TokData_t * tokdata,
                                        CK_MECHANISM_TYPE type,
                                        CK_MECHANISM_INFO_PTR pInfo)
{
    return ock_generic_get_mechanism_info(tokdata, type, pInfo, NULL);
}

int token_specific_creatlock(void)
{
    char lockfile[PATH_MAX + (sizeof(LOCKDIR_PATH) - 1)
                  + 2 * (sizeof(SUB_DIR) - 1)
                  + (sizeof("///LCK..") - 1) + 1];
    char lockdir[(sizeof(LOCKDIR_PATH) - 1) + (sizeof(SUB_DIR) - 1)
                 + (sizeof("/") - 1) + 1];
    struct passwd *pw = NULL;
    struct stat statbuf;
    mode_t mode = (S_IRUSR | S_IWUSR | S_IXUSR);
    int lockfd = -1;;
    int ret = -1;
    struct group *grp = NULL;

    /* get userid */
    pw = getpwuid(getuid());
    if (pw == NULL) {
        OCK_SYSLOG(LOG_ERR, "getpwuid(): %s\n", strerror(errno));
        return -1;
    }
    if (strlen(pw->pw_name) > PATH_MAX) {
        OCK_SYSLOG(LOG_ERR, "Username(%s) too long\n", pw->pw_name);
        return -1;
    }

    /** create lock subdir for each token if it doesn't exist.
	 * The root /var/lock/opencryptoki directory should be created in slotmgr
	 * daemon **/
    sprintf(lockdir, "%s/%s", LOCKDIR_PATH, SUB_DIR);

    ret = stat(lockdir, &statbuf);
    if (ret != 0 && errno == ENOENT) {
        /* dir does not exist, try to create it */
        ret = mkdir(lockdir, S_IRWXU | S_IRWXG);
        if (ret != 0) {
            OCK_SYSLOG(LOG_ERR,
                       "Directory(%s) missing: %s\n", lockdir, strerror(errno));
            goto err;
        }
        grp = getgrnam(PKCS_GROUP);
        if (grp == NULL) {
            fprintf(stderr, "getgrname(%s): %s", PKCS_GROUP, strerror(errno));
            goto err;
        }
        /* set ownership to euid, and pkcs11 group */
        if (chown(lockdir, geteuid(), grp->gr_gid) != 0) {
            fprintf(stderr, "Failed to set owner:group \
					ownership\
					on %s directory", lockdir);
            goto err;
        }
        /* mkdir does not set group permission right, so
         ** trying explictly here again */
        if (chmod(lockdir, S_IRWXU | S_IRWXG) != 0) {
            fprintf(stderr, "Failed to change \
					permissions\
					on %s directory", lockdir);
            goto err;
        }
    }

    /* create user-specific directory */
    sprintf(lockfile, "%s/%s/%s", LOCKDIR_PATH, SUB_DIR, pw->pw_name);

    /* see if it exists, otherwise mkdir will fail */
    if (stat(lockfile, &statbuf) < 0) {
        if (mkdir(lockfile, mode) == -1) {
            OCK_SYSLOG(LOG_ERR, "mkdir(%s): %s\n", lockfile, strerror(errno));
            return -1;
        }

        /* ensure correct perms on user dir */
        if (chmod(lockfile, mode) == -1) {
            OCK_SYSLOG(LOG_ERR, "chmod(%s): %s\n", lockfile, strerror(errno));
            return -1;
        }
    }

    /* create user lock file */
    memset(lockfile, 0, sizeof(lockfile));
    sprintf(lockfile, "%s/%s/%s/LCK..%s", LOCKDIR_PATH, SUB_DIR, pw->pw_name,
            SUB_DIR);

    lockfd = open(lockfile, O_CREAT | O_RDWR, mode);
    if (lockfd == -1) {
        OCK_SYSLOG(LOG_ERR, "open(%s): %s\n", lockfile, strerror(errno));
        return -1;
    } else {
        /* umask may prevent correct mode, so set it. */
        if (fchmod(lockfd, mode) == -1) {
            OCK_SYSLOG(LOG_ERR, "fchmod(%s): %s\n", lockfile, strerror(errno));
            goto err;
        }
    }

    return lockfd;
err:
    if (lockfd != -1)
        close(lockfd);

    return -1;
}

CK_RV token_specific_init_token_data(STDLL_TokData_t * tokdata,
                                     CK_SLOT_ID slot_id)
{
    UNUSED(tokdata);
    UNUSED(slot_id);

    /* do nothing. */
    return CKR_OK;
}

CK_RV token_specific_key_wrap(STDLL_TokData_t *tokdata, SESSION *session,
                              CK_MECHANISM *mech, CK_BBOOL length_only,
                              OBJECT *wrapping_key, OBJECT *key,
                              CK_BYTE *wrapped_key, CK_ULONG *wrapped_key_len,
                              CK_BBOOL *not_opaque)
{
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE keytype;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(session);
    UNUSED(length_only);
    UNUSED(wrapped_key);
    UNUSED(wrapped_key_len);

    rc = template_attribute_get_ulong(wrapping_key->template, CKA_CLASS,
                                      &class);
    if (rc != CKR_OK)
        return rc;
    if (class != CKO_SECRET_KEY)
        return CKR_KEY_NOT_WRAPPABLE;

    rc = template_attribute_get_ulong(key->template, CKA_CLASS, &class);
    if (rc != CKR_OK)
        return rc;
    if (class != CKO_SECRET_KEY)
        return CKR_KEY_NOT_WRAPPABLE;

    rc = template_attribute_get_ulong(wrapping_key->template, CKA_KEY_TYPE,
                                      &keytype);
    if (rc != CKR_OK)
        return rc;

    switch (mech->mechanism) {
    case CKM_DES_ECB:
    case CKM_DES_CBC:
    case CKM_DES_CBC_PAD:
        if (keytype != CKK_DES)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        break;
    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
    case CKM_DES3_CBC_PAD:
        if (keytype != CKK_DES2 && keytype != CKK_DES3)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        break;
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
        if (keytype != CKK_AES)
            return CKR_WRAPPING_KEY_TYPE_INCONSISTENT;
        break;
    default:
        return CKR_KEY_NOT_WRAPPABLE;
    }

    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE,
                                      &keytype);
    if (rc != CKR_OK)
        return rc;

    switch (keytype) {
    case CKK_DES:
    case CKK_DES2:
    case CKK_DES3:
    case CKK_AES:
    case CKK_GENERIC_SECRET:
        break;
    default:
        return CKR_KEY_NOT_WRAPPABLE;
    }

    /* Symmetric keys are not opaque, so we can let common code do the wrap */
    *not_opaque = TRUE;
    return CKR_OK;
}

CK_RV token_specific_key_unwrap(STDLL_TokData_t *tokdata, SESSION *session,
                                CK_MECHANISM *mech,
                                CK_BYTE *wrapped_key, CK_ULONG wrapped_key_len,
                                OBJECT *unwrapping_key, OBJECT *unwrapped_key,
                                CK_BBOOL *not_opaque)
{
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE keytype;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(session);
    UNUSED(wrapped_key);
    UNUSED(wrapped_key_len);

    rc = template_attribute_get_ulong(unwrapping_key->template, CKA_CLASS,
                                      &class);
    if (rc != CKR_OK)
        return rc;
    if (class != CKO_SECRET_KEY)
        return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;

    rc = template_attribute_get_ulong(unwrapped_key->template, CKA_CLASS,
                                      &class);
    if (rc != CKR_OK)
        return rc;
    if (class != CKO_SECRET_KEY)
        return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;

    rc = template_attribute_get_ulong(unwrapping_key->template, CKA_KEY_TYPE,
                                      &keytype);
    if (rc != CKR_OK)
        return rc;

    switch (mech->mechanism) {
    case CKM_DES_ECB:
    case CKM_DES_CBC:
    case CKM_DES_CBC_PAD:
        if (keytype != CKK_DES)
            return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
        break;
    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
    case CKM_DES3_CBC_PAD:
        if (keytype != CKK_DES2 && keytype != CKK_DES3)
            return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
        break;
    case CKM_AES_ECB:
    case CKM_AES_CBC:
    case CKM_AES_CBC_PAD:
        if (keytype != CKK_AES)
            return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
        break;
    default:
        return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
    }

    rc = template_attribute_get_ulong(unwrapped_key->template, CKA_KEY_TYPE,
                                      &keytype);
    if (rc != CKR_OK)
        return rc;

    switch (keytype) {
    case CKK_DES:
    case CKK_DES2:
    case CKK_DES3:
    case CKK_AES:
    case CKK_GENERIC_SECRET:
        break;
    default:
        return CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT;
    }

    /* Symmetric keys are not opaque, so we can let common code do the unwrap */
    *not_opaque = TRUE;
    return CKR_OK;
}
