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

#include "pkcs11/pkcs11types.h"
#include "pkcs11/stdll.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_specific.h"
#include "tok_spec_struct.h"
#include "tok_struct.h"
#include "trace.h"

#include "tpm_specific.h"

#include "../api/apiproto.h"

TSS_RESULT util_set_public_modulus(TSS_HKEY, unsigned long, unsigned char *);

CK_CHAR manuf[] = "IBM Corp.";
CK_CHAR model[] = "TPM v1.1 Token";
CK_CHAR descr[] = "Token for the Trusted Platform Module";
CK_CHAR label[] = "IBM PKCS#11 TPM Token";

MECH_LIST_ELEMENT mech_list[] = {
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

CK_ULONG mech_list_len = (sizeof(mech_list) / sizeof(MECH_LIST_ELEMENT));

CK_BYTE master_key_private[MK_SIZE];

/* The context we'll use globally to connect to the TSP */
TSS_HCONTEXT tspContext = NULL_HCONTEXT;

/* TSP key handles */
TSS_HKEY hSRK = NULL_HKEY;
TSS_HKEY hPublicRootKey = NULL_HKEY;
TSS_HKEY hPublicLeafKey = NULL_HKEY;
TSS_HKEY hPrivateRootKey = NULL_HKEY;
TSS_HKEY hPrivateLeafKey = NULL_HKEY;

/* TSP policy handles */
TSS_HPOLICY hDefaultPolicy = NULL_HPOLICY;

/* PKCS#11 key handles */
CK_OBJECT_HANDLE ckPublicRootKey = 0;
CK_OBJECT_HANDLE ckPublicLeafKey = 0;
CK_OBJECT_HANDLE ckPrivateRootKey = 0;
CK_OBJECT_HANDLE ckPrivateLeafKey = 0;

int not_initialized = 0;

CK_BYTE current_user_pin_sha[SHA1_HASH_SIZE];
CK_BYTE current_so_pin_sha[SHA1_HASH_SIZE];

static void clear_internal_structures()
{
    hSRK = NULL_HKEY;
    hPrivateLeafKey = NULL_HKEY;
    hPublicLeafKey = NULL_HKEY;
    hPrivateRootKey = NULL_HKEY;
    hPublicRootKey = NULL_HKEY;

    memset(master_key_private, 0, MK_SIZE);
    memset(current_so_pin_sha, 0, SHA1_HASH_SIZE);
    memset(current_user_pin_sha, 0, SHA1_HASH_SIZE);
}

CK_RV token_specific_rng(STDLL_TokData_t * tokdata, CK_BYTE * output,
                         CK_ULONG bytes)
{
    TSS_RESULT rc;
    TSS_HTPM hTPM;
    BYTE *random_bytes = NULL;

    rc = Tspi_Context_GetTpmObject(tspContext, &hTPM);
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
    Tspi_Context_FreeMemory(tspContext, random_bytes);

    return CKR_OK;
}

CK_RV token_specific_init(STDLL_TokData_t * tokdata, CK_SLOT_ID SlotNumber,
                          char *conf_name)
{
    TSS_RESULT result;
    char path_buf[PATH_MAX], fname[PATH_MAX];
    struct stat statbuf;

    TRACE_INFO("tpm %s slot=%lu running\n", __func__, SlotNumber);

    // if the user specific directory doesn't exist, create it
    sprintf(path_buf, "%s", get_pk_dir(fname));
    if (stat(path_buf, &statbuf) < 0) {
        if (mkdir(path_buf, S_IRUSR | S_IWUSR | S_IXUSR) == -1) {
            TRACE_ERROR("mkdir(%s): %s\n", path_buf, strerror(errno));
            return CKR_FUNCTION_FAILED;
        }
    }
    // now create userdir/TOK_OBJ if it doesn't exist
    strncat(path_buf, "/", 1);
    strncat(path_buf, PK_LITE_OBJ_DIR, strlen(PK_LITE_OBJ_DIR));
    if (stat(path_buf, &statbuf) < 0) {
        if (mkdir(path_buf, S_IRUSR | S_IWUSR | S_IXUSR) == -1) {
            TRACE_ERROR("mkdir(%s): %s\n", path_buf, strerror(errno));
            return CKR_FUNCTION_FAILED;
        }
    }

    result = Tspi_Context_Create(&tspContext);
    if (result) {
        TRACE_ERROR("Tspi_Context_Create failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_Context_Connect(tspContext, NULL);
    if (result) {
        TRACE_ERROR("Tspi_Context_Connect failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_Context_GetDefaultPolicy(tspContext, &hDefaultPolicy);
    if (result) {
        TRACE_ERROR("Tspi_Context_GetDefaultPolicy failed. rc=0x%x\n", result);
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

CK_RV token_wrap_sw_key(int size_n, unsigned char *n, int size_p,
                        unsigned char *p, TSS_HKEY hParentKey,
                        TSS_FLAG initFlags, TSS_HKEY * phKey)
{
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
    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_RSAKEY,
                                       TSS_KEY_MIGRATABLE | initFlags |
                                       key_size, phKey);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Context_CreateObject failed: rc=0x%x\n", result);
        return result;
    }

    result = util_set_public_modulus(*phKey, size_n, n);
    if (result != TSS_SUCCESS) {
        TRACE_DEVEL("util_set_public_modulus failed:rc=0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
        *phKey = NULL_HKEY;
        return result;
    }

    /* set the private key data in the TSS object */
    result = Tspi_SetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB,
                                TSS_TSPATTRIB_KEYBLOB_PRIVATE_KEY, size_p, p);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_SetAttribData failed: rc=0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
        *phKey = NULL_HKEY;
        return result;
    }

    /* if the parent wrapping key is the SRK, we need to manually pull
     * out the SRK's pub key, which is not stored in persistent storage
     * for privacy reasons */
    if (hParentKey == hSRK && get_srk_pub_key == TRUE) {
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
            Tspi_Context_CloseObject(tspContext, *phKey);
            *phKey = NULL_HKEY;
            return result;
        }
        Tspi_Context_FreeMemory(tspContext, pubKey);
        get_srk_pub_key = FALSE;
    }

    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_POLICY,
                                       TSS_POLICY_MIGRATION, &hPolicy);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Context_CreateObject: 0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
        *phKey = NULL_HKEY;
        return result;
    }

    result = Tspi_Policy_SetSecret(hPolicy, TSS_SECRET_MODE_NONE, 0, NULL);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Policy_SetSecret failed. rc=0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
        Tspi_Context_CloseObject(tspContext, hPolicy);
        *phKey = NULL_HKEY;
        return result;
    }

    result = Tspi_Policy_AssignToObject(hPolicy, *phKey);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Policy_AssignToObject: 0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
        Tspi_Context_CloseObject(tspContext, hPolicy);
        *phKey = NULL_HKEY;
        return result;
    }

    if (TPMTOK_TSS_KEY_TYPE(initFlags) == TSS_KEY_TYPE_LEGACY) {
        result = Tspi_SetAttribUint32(*phKey, TSS_TSPATTRIB_KEY_INFO,
                                      TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                                      TSS_ES_RSAESPKCSV15);
        if (result) {
            TRACE_ERROR("Tspi_SetAttribUint32 failed. rc=0x%x\n", result);
            Tspi_Context_CloseObject(tspContext, *phKey);
            Tspi_Context_CloseObject(tspContext, hPolicy);
            return result;
        }

        result = Tspi_SetAttribUint32(*phKey, TSS_TSPATTRIB_KEY_INFO,
                                      TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
                                      TSS_SS_RSASSAPKCS1V15_DER);
        if (result) {
            TRACE_ERROR("Tspi_SetAttribUint32 failed. rc=0x%x\n", result);
            Tspi_Context_CloseObject(tspContext, *phKey);
            Tspi_Context_CloseObject(tspContext, hPolicy);
            return result;
        }
    }

    result = Tspi_Key_WrapKey(*phKey, hParentKey, NULL_HPCRS);
    if (result != TSS_SUCCESS) {
        TRACE_ERROR("Tspi_Key_WrapKey failed: rc=0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
        *phKey = NULL_HKEY;
    }

    return result;
}

/*
 * Create a TPM key blob for an imported key. This function is only called when
 * a key is in active use, so any failure should trickle through.
 */
CK_RV token_wrap_key_object(STDLL_TokData_t * tokdata,
                            CK_OBJECT_HANDLE ckObject, TSS_HKEY hParentKey,
                            TSS_HKEY * phKey)
{
    CK_RV rc = CKR_OK;
    CK_ATTRIBUTE *attr = NULL, *new_attr, *prime_attr;
    CK_ULONG class, key_type;
    CK_BBOOL found;
    OBJECT *obj;

    TSS_RESULT result;
    TSS_FLAG initFlags = 0;
    BYTE *rgbBlob;
    UINT32 ulBlobLen;

    rc = object_mgr_find_in_map1(tokdata, ckObject, &obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* if the object isn't a key, fail */
    found = template_attribute_find(obj->template, CKA_KEY_TYPE, &attr);
    if (found == FALSE) {
        TRACE_ERROR("template_attribute_find(CKA_KEY_TYPE) failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    key_type = *((CK_ULONG *) attr->pValue);

    if (key_type != CKK_RSA) {
        TRACE_ERROR("Bad key type!\n");
        return CKR_FUNCTION_FAILED;
    }

    found = template_attribute_find(obj->template, CKA_CLASS, &attr);
    if (found == FALSE) {
        TRACE_ERROR("template_attribute_find(CKA_CLASS) failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    class = *((CK_ULONG *) attr->pValue);

    if (class == CKO_PRIVATE_KEY) {
        /* In order to create a full TSS key blob using a PKCS#11 private key
         * object, we need one of the two primes, the modulus and the private
         * exponent and we need the public exponent to be correct */

        /* check the least likely attribute to exist first, the primes */
        found = template_attribute_find(obj->template,
                                        CKA_PRIME_1, &prime_attr);
        if (found == FALSE) {
            found = template_attribute_find(obj->template,
                                            CKA_PRIME_2, &prime_attr);
            if (found == FALSE) {
                TRACE_ERROR("Couldn't find prime1 or prime2 of"
                            " key object to wrap\n");
                return CKR_TEMPLATE_INCONSISTENT;
            }
        }

        /* Make sure the public exponent is usable */
        if ((util_check_public_exponent(obj->template))) {
            TRACE_ERROR("Invalid public exponent\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        /* get the modulus */
        found = template_attribute_find(obj->template, CKA_MODULUS, &attr);
        if (found == FALSE) {
            TRACE_ERROR("Couldn't find a required attribute of "
                        "key object\n");
            return CKR_FUNCTION_FAILED;
        }

        /* make sure the key size is usable */
        initFlags = util_get_keysize_flag(attr->ulValueLen * 8);
        if (initFlags == 0) {
            TRACE_ERROR("Invalid key size.\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        /* generate the software based key */
        rc = token_wrap_sw_key((int) attr->ulValueLen, attr->pValue,
                               (int) prime_attr->ulValueLen,
                               prime_attr->pValue,
                               hParentKey,
                               TSS_KEY_TYPE_LEGACY | TSS_KEY_NO_AUTHORIZATION,
                               phKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_wrap_sw_key failed. rc=0x%lu\n", rc);
            return rc;
        }
    } else if (class == CKO_PUBLIC_KEY) {
        /* Make sure the public exponent is usable */
        if ((util_check_public_exponent(obj->template))) {
            TRACE_DEVEL("Invalid public exponent\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        /* grab the modulus to put into the TSS key object */
        found = template_attribute_find(obj->template, CKA_MODULUS, &attr);
        if (found == FALSE) {
            TRACE_ERROR("Couldn't find a required attribute of "
                        "key object\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        /* make sure the key size is usable */
        initFlags = util_get_keysize_flag(attr->ulValueLen * 8);
        if (initFlags == 0) {
            TRACE_ERROR("Invalid key size.\n");
            return CKR_TEMPLATE_INCONSISTENT;
        }

        initFlags |=
            TSS_KEY_TYPE_LEGACY | TSS_KEY_MIGRATABLE | TSS_KEY_NO_AUTHORIZATION;

        result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_RSAKEY,
                                           initFlags, phKey);
        if (result) {
            TRACE_ERROR("Tspi_Context_CreateObject failed. " "rc=0x%x\n",
                        result);
            return result;
        }

        result = util_set_public_modulus(*phKey,
                                         attr->ulValueLen, attr->pValue);
        if (result) {
            TRACE_DEVEL("util_set_public_modulus failed: 0x%x\n", result);
            Tspi_Context_CloseObject(tspContext, *phKey);
            *phKey = NULL_HKEY;
            return CKR_FUNCTION_FAILED;
        }
    } else {
        TRACE_ERROR("Bad key class!\n");
        return CKR_FUNCTION_FAILED;
    }

    /* grab the entire key blob to put into the PKCS#11 object */
    result = Tspi_GetAttribData(*phKey, TSS_TSPATTRIB_KEY_BLOB,
                                TSS_TSPATTRIB_KEYBLOB_BLOB,
                                &ulBlobLen, &rgbBlob);
    if (result) {
        TRACE_ERROR("Tspi_GetAttribData failed with rc: 0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* insert the key blob into the object */
    rc = build_attribute(CKA_IBM_OPAQUE, rgbBlob, ulBlobLen, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_atribute failed\n");
        Tspi_Context_FreeMemory(tspContext, rgbBlob);
        return rc;
    }
    template_update_attribute(obj->template, new_attr);
    Tspi_Context_FreeMemory(tspContext, rgbBlob);

    /* if this is a token object, save it with the new attribute so that we
     * don't have to go down this path again */
    if (!object_is_session_object(obj)) {
        rc = save_token_object(tokdata, obj);
    }

    return rc;
}

/*
 * load a key in the TSS hierarchy from its CK_OBJECT_HANDLE
 */
CK_RV token_load_key(STDLL_TokData_t * tokdata, CK_OBJECT_HANDLE ckKey,
                     TSS_HKEY hParentKey, CK_CHAR_PTR passHash,
                     TSS_HKEY * phKey)
{
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
        result = Tspi_Context_LoadKeyByBlob(tspContext, hParentKey, ulBlobSize,
                                            blob, phKey);
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
    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_POLICY,
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

TSS_RESULT token_load_srk()
{
    TSS_HPOLICY hPolicy;
    TSS_RESULT result;
    TSS_UUID SRK_UUID = TSS_UUID_SRK;
    struct srk_info srk;

    if (hSRK != NULL_HKEY)
        return TSS_SUCCESS;

    /* load the SRK */
    result = Tspi_Context_LoadKeyByUUID(tspContext,
                                        TSS_PS_TYPE_SYSTEM, SRK_UUID, &hSRK);
    if (result) {
        TRACE_ERROR("Tspi_Context_LoadKeyByUUID failed. rc=0x%x\n", result);
        goto done;
    }
#if 0
    if ((result = Tspi_GetPolicyObject(hSRK, TSS_POLICY_USAGE, &hPolicy))) {
        TRACE_ERROR("Tspi_GetPolicyObject failed. rc=0x%x\n", result);
        goto done;
    }
#else
    result = Tspi_Context_CreateObject(tspContext,
                                       TSS_OBJECT_TYPE_POLICY,
                                       TSS_POLICY_USAGE, &hPolicy);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        goto done;
    }

    result = Tspi_Policy_AssignToObject(hPolicy, hSRK);
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
    TSS_RESULT result;
    BYTE *blob;
    CK_ULONG blob_size;

    if (hPublicRootKey != NULL_HKEY)
        return TSS_SUCCESS;

    result = token_load_srk();
    if (result) {
        TRACE_DEVEL("token_load_srk failed. rc=0x%x\n", result);
        return result;
    }

    result = token_find_key(tokdata, TPMTOK_PUBLIC_ROOT_KEY,
                            CKO_PRIVATE_KEY, &ckPublicRootKey);
    if (result) {
        TRACE_ERROR("token_find_key failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = token_get_key_blob(tokdata, ckPublicRootKey, &blob_size, &blob);
    if (result) {
        TRACE_DEVEL("token_get_key_blob failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* load the Public Root Key */
    result = Tspi_Context_LoadKeyByBlob(tspContext, hSRK,
                                        blob_size, blob, &hPublicRootKey);
    if (result) {
        TRACE_ERROR("Tspi_Context_LoadKeyByBlob failed. rc=0x%x\n", result);
        free(blob);
        return CKR_FUNCTION_FAILED;
    }
    free(blob);

    return result;
}

TSS_RESULT tss_generate_key(TSS_FLAG initFlags, BYTE * passHash,
                            TSS_HKEY hParentKey, TSS_HKEY * phKey)
{
    TSS_RESULT result;
    TSS_HPOLICY hPolicy, hMigPolicy;

    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_RSAKEY,
                                       initFlags, phKey);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        return result;
    }
#if 0
    if ((result = Tspi_GetPolicyObject(*phKey, TSS_POLICY_USAGE, &hPolicy))) {
        TRACE_ERROR("Tspi_GetPolicyObject failed. rc=0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
        return result;
    }
#else
    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_POLICY,
                                       TSS_POLICY_USAGE, &hPolicy);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject: 0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
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
        Tspi_Context_CloseObject(tspContext, *phKey);
        Tspi_Context_CloseObject(tspContext, hPolicy);
        return result;
    }

    result = Tspi_Policy_AssignToObject(hPolicy, *phKey);
    if (result) {
        TRACE_ERROR("Tspi_Policy_AssignToObject: 0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
        Tspi_Context_CloseObject(tspContext, hPolicy);
        return result;
    }

    if (TPMTOK_TSS_KEY_MIG_TYPE(initFlags) == TSS_KEY_MIGRATABLE) {
        result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_POLICY,
                                           TSS_POLICY_MIGRATION, &hMigPolicy);
        if (result) {
            TRACE_ERROR("Tspi_Context_CreateObject: 0x%x\n", result);
            Tspi_Context_CloseObject(tspContext, *phKey);
            Tspi_Context_CloseObject(tspContext, hPolicy);
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
            Tspi_Context_CloseObject(tspContext, *phKey);
            Tspi_Context_CloseObject(tspContext, hPolicy);
            Tspi_Context_CloseObject(tspContext, hMigPolicy);
            return result;
        }

        result = Tspi_Policy_AssignToObject(hMigPolicy, *phKey);
        if (result) {
            TRACE_ERROR("Tspi_Policy_AssignToObject: 0x%x\n", result);
            Tspi_Context_CloseObject(tspContext, *phKey);
            Tspi_Context_CloseObject(tspContext, hPolicy);
            Tspi_Context_CloseObject(tspContext, hMigPolicy);
            return result;
        }
    }

    if (TPMTOK_TSS_KEY_TYPE(initFlags) == TSS_KEY_TYPE_LEGACY) {
        result = Tspi_SetAttribUint32(*phKey, TSS_TSPATTRIB_KEY_INFO,
                                      TSS_TSPATTRIB_KEYINFO_ENCSCHEME,
                                      TSS_ES_RSAESPKCSV15);
        if (result) {
            TRACE_ERROR("Tspi_SetAttribUint32 failed. rc=0x%x\n", result);
            Tspi_Context_CloseObject(tspContext, *phKey);
            Tspi_Context_CloseObject(tspContext, hPolicy);
            Tspi_Context_CloseObject(tspContext, hMigPolicy);
            return result;
        }

        result = Tspi_SetAttribUint32(*phKey, TSS_TSPATTRIB_KEY_INFO,
                                      TSS_TSPATTRIB_KEYINFO_SIGSCHEME,
                                      TSS_SS_RSASSAPKCS1V15_DER);
        if (result) {
            TRACE_ERROR("Tspi_SetAttribUint32 failed. rc=0x%x\n", result);
            Tspi_Context_CloseObject(tspContext, *phKey);
            Tspi_Context_CloseObject(tspContext, hPolicy);
            Tspi_Context_CloseObject(tspContext, hMigPolicy);
            return result;
        }
    }

    result = Tspi_Key_CreateKey(*phKey, hParentKey, 0);
    if (result) {
        TRACE_ERROR("Tspi_Key_CreateKey failed with rc: 0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
        Tspi_Context_CloseObject(tspContext, hPolicy);
        Tspi_Context_CloseObject(tspContext, hMigPolicy);
    }

    return result;
}

TSS_RESULT tss_change_auth(TSS_HKEY hObjectToChange, TSS_HKEY hParentObject,
                           CK_CHAR * passHash)
{
    TSS_RESULT result;
    TSS_HPOLICY hPolicy;

    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_POLICY,
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
        Tspi_Context_FreeMemory(tspContext, rgbBlob);
        free(key_id);
        return rc;
    }

    /* create skeleton for the private key object */
    rc = object_create_skel(tokdata, NULL, 0, MODE_KEYGEN,
                            CKO_PRIVATE_KEY, CKK_RSA, &priv_key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("objectr_create_skel: 0x%lx\n", rc);
        Tspi_Context_FreeMemory(tspContext, rgbBlob);
        Tspi_Context_FreeMemory(tspContext, rgbPrivBlob);
        free(key_id);
        return rc;
    }

    /* add the ID attribute */
    rc = build_attribute(CKA_ID, key_id, strlen((char *) key_id), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        Tspi_Context_FreeMemory(tspContext, rgbBlob);
        Tspi_Context_FreeMemory(tspContext, rgbPrivBlob);
        free(key_id);
        return rc;
    }
    template_update_attribute(priv_key_obj->template, new_attr);
    free(key_id);

    /* add the key blob to the PKCS#11 object template */
    rc = build_attribute(CKA_IBM_OPAQUE, rgbBlob, ulBlobLen, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        Tspi_Context_FreeMemory(tspContext, rgbBlob);
        Tspi_Context_FreeMemory(tspContext, rgbPrivBlob);
        return rc;
    }
    template_update_attribute(priv_key_obj->template, new_attr);
    Tspi_Context_FreeMemory(tspContext, rgbBlob);

    /* add the private key blob to the PKCS#11 object template */
    rc = build_attribute(CKA_MODULUS, rgbPrivBlob, ulPrivBlobLen, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        Tspi_Context_FreeMemory(tspContext, rgbPrivBlob);
        return rc;
    }
    template_update_attribute(priv_key_obj->template, new_attr);
    Tspi_Context_FreeMemory(tspContext, rgbPrivBlob);

    /* add the HIDDEN attribute */
    flag = TRUE;
    rc = build_attribute(CKA_HIDDEN, &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        return rc;
    }
    template_update_attribute(priv_key_obj->template, new_attr);

    /*  set CKA_ALWAYS_SENSITIVE to true */
    rc = build_attribute(CKA_ALWAYS_SENSITIVE, &flag,
                         sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        return rc;
    }
    template_update_attribute(priv_key_obj->template, new_attr);

    /*  set CKA_NEVER_EXTRACTABLE to true */
    rc = build_attribute(CKA_NEVER_EXTRACTABLE,
                         &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        return rc;
    }
    template_update_attribute(priv_key_obj->template, new_attr);

    /* make the object reside on the token, as if that were possible */
    rc = build_attribute(CKA_TOKEN, &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        return rc;
    }
    template_update_attribute(priv_key_obj->template, new_attr);

    flag = FALSE;
    rc = build_attribute(CKA_PRIVATE, &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        return rc;
    }
    template_update_attribute(priv_key_obj->template, new_attr);

    rc = object_mgr_create_final(tokdata, &dummy_sess, priv_key_obj, ckKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_final failed.\n");
    }

    return rc;
}

CK_RV token_store_pub_key(STDLL_TokData_t * tokdata, TSS_HKEY hKey,
                          int key_type, CK_OBJECT_HANDLE * ckKey)
{
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
        Tspi_Context_CloseObject(tspContext, hKey);
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
        Tspi_Context_CloseObject(tspContext, hKey);
        free(key_id);
        return rc;
    }
    Tspi_Context_FreeMemory(tspContext, rgbPubBlob);

    /* make the object reside on the token, as if that were possible */
    rc = build_attribute(CKA_TOKEN, &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build attribute failed.\n");
        goto done;
    }
    template_update_attribute(pub_key_obj->template, new_attr);

    /* set the object to be hidden */
    rc = build_attribute(CKA_HIDDEN, &flag, sizeof(CK_BBOOL), &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build attribute failed.\n");
        goto done;
    }
    template_update_attribute(pub_key_obj->template, new_attr);

    rc = object_mgr_create_final(tokdata, &dummy_sess, pub_key_obj, ckKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_create_final failed\n");
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
    CK_RV rc = CKR_FUNCTION_FAILED;
    TSS_RESULT result;
    TSS_HKEY hParentKey;
    CK_OBJECT_HANDLE *ckKey;
    TSS_FLAG initFlags = TSS_KEY_MIGRATABLE | TSS_KEY_TYPE_BIND |
        TSS_KEY_SIZE_2048 | TSS_KEY_AUTHORIZATION;

    switch (key_type) {
    case TPMTOK_PUBLIC_LEAF_KEY:
        hParentKey = hPublicRootKey;
        ckKey = &ckPublicRootKey;
        break;
    case TPMTOK_PRIVATE_LEAF_KEY:
        hParentKey = hPrivateRootKey;
        ckKey = &ckPrivateRootKey;
        break;
    default:
        TRACE_ERROR("Unknown key type.\n");
        goto done;
        break;
    }

    result = tss_generate_key(initFlags, passHash, hParentKey, phKey);
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

CK_RV token_verify_pin(TSS_HKEY hKey)
{
    TSS_HENCDATA hEncData;
    UINT32 ulUnboundDataLen;
    BYTE *rgbUnboundData;
    char *rgbData = "CRAPPENFEST";
    TSS_RESULT result;
    CK_RV rc = CKR_FUNCTION_FAILED;

    result = Tspi_Context_CreateObject(tspContext,
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

    Tspi_Context_FreeMemory(tspContext, rgbUnboundData);
done:
    Tspi_Context_CloseObject(tspContext, hEncData);

    return rc;
}

CK_RV token_create_private_tree(STDLL_TokData_t * tokdata, CK_BYTE * pinHash,
                                CK_BYTE * pPin)
{
    CK_RV rc;
    TSS_RESULT result;
    RSA *rsa;
    unsigned int size_n, size_p;
    unsigned char n[256], p[256];

    /* all sw generated keys are 2048 bits */
    if ((rsa = openssl_gen_key()) == NULL)
        return CKR_HOST_MEMORY;

    if (openssl_get_modulus_and_prime(rsa, &size_n, n, &size_p, p) != 0) {
        TRACE_DEVEL("openssl_get_modulus_and_prime failed\n");
        return CKR_FUNCTION_FAILED;
    }

    /* generate the software based user base key */
    rc = token_wrap_sw_key(size_n, n, size_p, p, hSRK,
                           TSS_KEY_NO_AUTHORIZATION | TSS_KEY_TYPE_STORAGE,
                           &hPrivateRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_wrap_sw_key failed. rc=0x%lu\n", rc);
        return rc;
    }

    if (openssl_write_key(rsa, TPMTOK_PRIV_ROOT_KEY_FILE, pPin)) {
        TRACE_DEVEL("openssl_write_key failed.\n");
        RSA_free(rsa);
        return CKR_FUNCTION_FAILED;
    }

    RSA_free(rsa);

    /* store the user base key in a PKCS#11 object internally */
    rc = token_store_tss_key(tokdata, hPrivateRootKey,
                             TPMTOK_PRIVATE_ROOT_KEY,
                             &ckPrivateRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_store_tss_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    result = Tspi_Key_LoadKey(hPrivateRootKey, hSRK);
    if (result) {
        TRACE_ERROR("Tspi_Key_LoadKey: 0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, hPrivateRootKey);
        hPrivateRootKey = NULL_HKEY;
        return CKR_FUNCTION_FAILED;
    }

    /* generate the private leaf key */
    rc = token_generate_leaf_key(tokdata, TPMTOK_PRIVATE_LEAF_KEY,
                                 pinHash, &hPrivateLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_generate_leaf_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    result = Tspi_Key_LoadKey(hPrivateLeafKey, hPrivateRootKey);
    if (result) {
        TRACE_ERROR("Tspi_Key_LoadKey: 0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, hPrivateRootKey);
        hPrivateRootKey = NULL_HKEY;
        Tspi_Context_CloseObject(tspContext, hPrivateLeafKey);
        hPrivateRootKey = NULL_HKEY;
        return CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV token_create_public_tree(STDLL_TokData_t * tokdata, CK_BYTE * pinHash,
                               CK_BYTE * pPin)
{
    CK_RV rc;
    TSS_RESULT result;
    RSA *rsa;
    unsigned int size_n, size_p;
    unsigned char n[256], p[256];

    /* all sw generated keys are 2048 bits */
    if ((rsa = openssl_gen_key()) == NULL)
        return CKR_HOST_MEMORY;

    if (openssl_get_modulus_and_prime(rsa, &size_n, n, &size_p, p) != 0) {
        TRACE_DEVEL("openssl_get_modulus_and_prime failed\n");
        return CKR_FUNCTION_FAILED;
    }

    /* create the public root key */
    rc = token_wrap_sw_key(size_n, n, size_p, p, hSRK,
                           TSS_KEY_NO_AUTHORIZATION | TSS_KEY_TYPE_STORAGE,
                           &hPublicRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_wrap_sw_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    if (openssl_write_key(rsa, TPMTOK_PUB_ROOT_KEY_FILE, pPin)) {
        TRACE_DEVEL("openssl_write_key\n");
        RSA_free(rsa);
        return CKR_FUNCTION_FAILED;
    }

    RSA_free(rsa);

    result = Tspi_Key_LoadKey(hPublicRootKey, hSRK);
    if (result) {
        TRACE_ERROR("Tspi_Key_LoadKey: 0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, hPublicRootKey);
        hPublicRootKey = NULL_HKEY;
        return CKR_FUNCTION_FAILED;
    }

    rc = token_store_tss_key(tokdata, hPublicRootKey,
                             TPMTOK_PUBLIC_ROOT_KEY, &ckPublicRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_store_tss_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* create the SO's leaf key */
    rc = token_generate_leaf_key(tokdata, TPMTOK_PUBLIC_LEAF_KEY,
                                 pinHash, &hPublicLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_generate_leaf_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    result = Tspi_Key_LoadKey(hPublicLeafKey, hPublicRootKey);
    if (result) {
        TRACE_ERROR("Tspi_Key_LoadKey: 0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, hPublicRootKey);
        hPublicRootKey = NULL_HKEY;
        Tspi_Context_CloseObject(tspContext, hPublicLeafKey);
        hPublicLeafKey = NULL_HKEY;
        return CKR_FUNCTION_FAILED;
    }

    return rc;
}

CK_RV token_migrate(STDLL_TokData_t * tokdata, int key_type, CK_BYTE * pin)
{
    RSA *rsa;
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
        phKey = &hPublicRootKey;
        ckHandle = &ckPublicRootKey;
    } else if (key_type == TPMTOK_PRIVATE_ROOT_KEY) {
        backup_loc = TPMTOK_PRIV_ROOT_KEY_FILE;
        phKey = &hPrivateRootKey;
        ckHandle = &ckPrivateRootKey;
    } else {
        TRACE_ERROR("Invalid key type.\n");
        return CKR_FUNCTION_FAILED;
    }

    /* read the backup key with the old pin */
    if ((rc = openssl_read_key(backup_loc, pin, &rsa))) {
        if (rc == CKR_FILE_NOT_FOUND)
            rc = CKR_FUNCTION_FAILED;
        TRACE_DEVEL("openssl_read_key failed\n");
        return rc;
    }

    /* So, reading the backup openssl key off disk succeeded with the SOs PIN.
     * We will now try to re-wrap that key with the current SRK
     */
    if (openssl_get_modulus_and_prime(rsa, &size_n, n, &size_p, p) != 0) {
        TRACE_DEVEL("openssl_get_modulus_and_prime failed\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = token_wrap_sw_key(size_n, n, size_p, p, hSRK,
                           TSS_KEY_TYPE_STORAGE | TSS_KEY_NO_AUTHORIZATION,
                           phKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_wrap_sw_key failed. rc=0x%lx\n", rc);
        RSA_free(rsa);
        return rc;
    }
    RSA_free(rsa);

    result = Tspi_Key_LoadKey(*phKey, hSRK);
    if (result) {
        TRACE_ERROR("Tspi_Key_LoadKey: 0x%x\n", result);
        Tspi_Context_CloseObject(tspContext, *phKey);
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

CK_RV save_masterkey_private()
{
    char fname[PATH_MAX];
    struct stat file_stat;
    int err;
    FILE *fp = NULL;
    struct passwd *pw = NULL;

    TSS_RESULT result;
    TSS_HENCDATA hEncData;
    BYTE *encrypted_masterkey;
    UINT32 encrypted_masterkey_size;

    pw = getpwuid(getuid());
    if (pw == NULL) {
        TRACE_ERROR("getpwuid failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }
    //fp = fopen("/etc/pkcs11/tpm/MK_PRIVATE", "r");
    sprintf((char *) fname, "%s/%s/%s", pk_dir, pw->pw_name,
            TPMTOK_MASTERKEY_PRIVATE);

    /* if file exists, assume its been written correctly before */
    err = stat(fname, &file_stat);
    if (err == 0) {
        return CKR_OK;
    } else if (errno != ENOENT) {
        /* some error other than file doesn't exist */
        return CKR_FUNCTION_FAILED;
    }

    /* encrypt the private masterkey using the private leaf key */
    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_ENCDATA,
                                       TSS_ENCDATA_BIND, &hEncData);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_Data_Bind(hEncData, hPrivateLeafKey,
                            MK_SIZE, master_key_private);
    if (result) {
        TRACE_ERROR("Tspi_Data_Bind failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_GetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
                                TSS_TSPATTRIB_ENCDATABLOB_BLOB,
                                &encrypted_masterkey_size,
                                &encrypted_masterkey);
    if (result) {
        TRACE_ERROR("Tspi_GetAttribData failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    if (encrypted_masterkey_size > 256) {
        Tspi_Context_FreeMemory(tspContext, encrypted_masterkey);
        return CKR_DATA_LEN_RANGE;
    }

    /* write the encrypted key to disk */
    if ((fp = fopen((char *) fname, "w")) == NULL) {
        TRACE_ERROR("Error opening %s for write: %s\n", fname, strerror(errno));
        Tspi_Context_FreeMemory(tspContext, encrypted_masterkey);
        return CKR_FUNCTION_FAILED;
    }

    err = fwrite(encrypted_masterkey, encrypted_masterkey_size, 1, fp);
    if (err == 0) {
        TRACE_ERROR("Error writing %s: %s\n", fname, strerror(errno));
        Tspi_Context_FreeMemory(tspContext, encrypted_masterkey);
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    Tspi_Context_FreeMemory(tspContext, encrypted_masterkey);
    fclose(fp);

    return CKR_OK;
}

CK_RV load_masterkey_private(STDLL_TokData_t * tokdata)
{
    FILE *fp = NULL;
    int err;
    struct stat file_stat;
    CK_BYTE encrypted_masterkey[256];
    char fname[PATH_MAX];
    CK_RV rc;
    struct passwd *pw = NULL;

    TSS_RESULT result;
    TSS_HENCDATA hEncData;
    BYTE *masterkey;
    UINT32 masterkey_size, encrypted_masterkey_size = 256;

    pw = getpwuid(getuid());
    if (pw == NULL) {
        TRACE_ERROR("getpwuid failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    sprintf((char *) fname, "%s/%s/%s", pk_dir, pw->pw_name,
            TPMTOK_MASTERKEY_PRIVATE);

    /* if file exists, check its size */
    err = stat(fname, &file_stat);
    if (err == 0) {
        if (file_stat.st_size != 256) {
            TRACE_ERROR("Private master key has been corrupted\n");
            return CKR_FUNCTION_FAILED;
        }
    } else if (errno == ENOENT) {
        TRACE_INFO("Private master key doesn't exist, creating it...\n");

        /* create the private master key, then save */
        rc = token_specific_rng(tokdata, master_key_private, MK_SIZE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_rng failed. rc=0x%lx\n", rc);
            return rc;
        }

        return save_masterkey_private();
    } else {
        /* some error other than file doesn't exist */
        TRACE_ERROR("stat of private masterkey failed: %s\n", strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    //fp = fopen("/etc/pkcs11/tpm/MK_PUBLIC", "r");
    if ((fp = fopen((char *) fname, "r")) == NULL) {
        TRACE_ERROR("Error opening %s: %s\n", fname, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    if (fread(encrypted_masterkey, encrypted_masterkey_size, 1, fp) == 0) {
        TRACE_ERROR("Error reading %s: %s\n", fname, strerror(errno));
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }
    fclose(fp);

    /* decrypt the private masterkey using the private leaf key */
    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_ENCDATA,
                                       TSS_ENCDATA_BIND, &hEncData);
    if (result) {
        TRACE_ERROR("Tspi_Context_CreateObject failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_SetAttribData(hEncData, TSS_TSPATTRIB_ENCDATA_BLOB,
                                TSS_TSPATTRIB_ENCDATABLOB_BLOB,
                                encrypted_masterkey_size,
                                encrypted_masterkey);
    if (result) {
        TRACE_ERROR("Tspi_SetAttribData failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    result = Tspi_Data_Unbind(hEncData, hPrivateLeafKey,
                              &masterkey_size, &masterkey);
    if (result) {
        TRACE_ERROR("Tspi_Data_Unbind failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    if (masterkey_size != MK_SIZE) {
        TRACE_ERROR("decrypted private master key size is %u, "
                    "should be %u\n", masterkey_size, MK_SIZE);
        Tspi_Context_FreeMemory(tspContext, masterkey);
        return CKR_FUNCTION_FAILED;
    }

    memcpy(master_key_private, masterkey, MK_SIZE);
    Tspi_Context_FreeMemory(tspContext, masterkey);

    return CKR_OK;
}


CK_RV token_specific_login(STDLL_TokData_t * tokdata, SESSION * sess,
                           CK_USER_TYPE userType, CK_CHAR_PTR pPin,
                           CK_ULONG ulPinLen)
{
    CK_RV rc;
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    TSS_RESULT result;

    result = token_load_srk();
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
                            CKO_PRIVATE_KEY, &ckPrivateRootKey);
        if (rc != CKR_OK) {
            /* user's key chain not found, this must be the initial login */
            if (memcmp(hash_sha, default_user_pin_sha, SHA1_HASH_SIZE)) {
                TRACE_ERROR("token_find_key failed and PIN != default\n");
                return CKR_PIN_INCORRECT;
            }

            not_initialized = 1;
            return CKR_OK;
        }

        rc = token_load_key(tokdata, ckPrivateRootKey,
                            hSRK, NULL, &hPrivateRootKey);
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
                            CKO_PRIVATE_KEY, &ckPrivateLeafKey);
        if (rc != CKR_OK) {
            TRACE_ERROR("token_find_key failed. rc=0x%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        rc = token_load_key(tokdata, ckPrivateLeafKey,
                            hPrivateRootKey,
                            hash_sha, &hPrivateLeafKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        rc = token_verify_pin(hPrivateLeafKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_verify_pin failed. failed. rc=0x%lx\n", rc);
            return rc;
        }

        memcpy(current_user_pin_sha, hash_sha, SHA1_HASH_SIZE);

        /* load private data encryption key here */
        rc = load_masterkey_private(tokdata);
        if (rc != CKR_OK) {
            TRACE_DEVEL("load_masterkey_private failed. rc=0x%lx\n", rc);
            Tspi_Key_UnloadKey(hPrivateLeafKey);
            hPrivateLeafKey = NULL_HKEY;
            return rc;
        }

        rc = load_private_token_objects(tokdata);

        XProcLock(tokdata);
        tokdata->global_shm->priv_loaded = TRUE;
        XProcUnLock(tokdata);
    } else {
        /* SO path --
         */
        /* find, load the root key */
        rc = token_find_key(tokdata, TPMTOK_PUBLIC_ROOT_KEY,
                            CKO_PRIVATE_KEY, &ckPublicRootKey);
        if (rc != CKR_OK) {
            /* The SO hasn't set her PIN yet, compare the login pin with
             * the hard-coded value */
            if (memcmp(default_so_pin_sha, hash_sha, SHA1_HASH_SIZE)) {
                TRACE_ERROR("token_find_key failed and PIN != default\n");
                return CKR_PIN_INCORRECT;
            }

            not_initialized = 1;
            return CKR_OK;
        }

        /* The SO's key hierarchy has previously been created, so load the key
         * hierarchy and verify the pin using the TPM. */
        rc = token_load_key(tokdata, ckPublicRootKey,
                            hSRK, NULL, &hPublicRootKey);
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
                            CKO_PRIVATE_KEY, &ckPublicLeafKey);
        if (rc != CKR_OK) {
            TRACE_ERROR("token_find_key failed. rc=0x%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        rc = token_load_key(tokdata, ckPublicLeafKey,
                            hPublicRootKey, hash_sha, &hPublicLeafKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        rc = token_verify_pin(hPublicLeafKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_verify_pin failed. rc=0x%lx\n", rc);
            return rc;
        }

        memcpy(current_so_pin_sha, hash_sha, SHA1_HASH_SIZE);
    }

    return rc;
}

CK_RV token_specific_logout()
{
    if (hPrivateLeafKey != NULL_HKEY) {
        Tspi_Key_UnloadKey(hPrivateLeafKey);
    } else if (hPublicLeafKey != NULL_HKEY) {
        Tspi_Key_UnloadKey(hPublicLeafKey);
    }

    clear_internal_structures();

    return CKR_OK;
}

CK_RV token_specific_init_pin(STDLL_TokData_t * tokdata, SESSION * sess,
                              CK_CHAR_PTR pPin, CK_ULONG ulPinLen)
{
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
    CK_RV rc;

    /* find, load the private root key */
    rc = token_find_key(tokdata, TPMTOK_PRIVATE_ROOT_KEY,
                        CKO_PRIVATE_KEY, &ckPrivateRootKey);
    if (rc != CKR_OK) {
        TRACE_ERROR("token_find_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = token_load_key(tokdata, ckPrivateRootKey,
                        hSRK, NULL, &hPrivateRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    /* find, load the user leaf key */
    rc = token_find_key(tokdata, TPMTOK_PRIVATE_LEAF_KEY,
                        CKO_PRIVATE_KEY, &ckPrivateLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_find_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = token_load_key(tokdata, ckPrivateLeafKey,
                        hPrivateRootKey, hash_sha, &hPrivateLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = token_verify_pin(hPrivateLeafKey);
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
    CK_BYTE oldpin_hash[SHA1_HASH_SIZE], newpin_hash[SHA1_HASH_SIZE];
    CK_RV rc;
    RSA *rsa_root;
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

    result = token_load_srk();
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
        if (not_initialized) {
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
            if (memcmp(current_user_pin_sha, oldpin_hash, SHA1_HASH_SIZE)) {
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
        result = tss_change_auth(hPrivateLeafKey, hPrivateRootKey, newpin_hash);
        if (result) {
            TRACE_ERROR("tss_change_auth failed\n");
            return CKR_FUNCTION_FAILED;
        }

        /* destroy the old PKCS#11 priv key object and create a new one */
        rc = token_update_private_key(tokdata, hPrivateLeafKey,
                                      TPMTOK_PRIVATE_LEAF_KEY);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_update_private_key failed.\n");
            return rc;
        }

        /* read the backup key with the old pin */
        rc = openssl_read_key(TPMTOK_PRIV_ROOT_KEY_FILE, pOldPin, &rsa_root);
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
        rc = openssl_write_key(rsa_root, TPMTOK_PRIV_ROOT_KEY_FILE, pNewPin);
        if (rc != CKR_OK) {
            RSA_free(rsa_root);
            TRACE_DEVEL("openssl_write_key failed\n");
            return CKR_FUNCTION_FAILED;
        }
        RSA_free(rsa_root);
    } else if (sess->session_info.state == CKS_RW_SO_FUNCTIONS) {
        if (not_initialized) {
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

        if (memcmp(current_so_pin_sha, oldpin_hash, SHA1_HASH_SIZE)) {
            TRACE_ERROR("SO PIN incorrect\n");
            return CKR_PIN_INCORRECT;
        }

        rc = check_pin_properties(CKU_SO, newpin_hash, ulNewPinLen);
        if (rc != CKR_OK) {
            return rc;
        }

        /* change auth on the SO's leaf key */
        result = tss_change_auth(hPublicLeafKey, hPublicRootKey, newpin_hash);
        if (result) {
            TRACE_ERROR("tss_change_auth failed\n");
            return CKR_FUNCTION_FAILED;
        }

        rc = token_update_private_key(tokdata, hPublicLeafKey,
                                      TPMTOK_PUBLIC_LEAF_KEY);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_update_private_key failed.\n");
            return rc;
        }

        /* change auth on the public root key's openssl backup */
        rc = openssl_read_key(TPMTOK_PUB_ROOT_KEY_FILE, pOldPin, &rsa_root);
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
        rc = openssl_write_key(rsa_root, TPMTOK_PUB_ROOT_KEY_FILE, pNewPin);
        if (rc != CKR_OK) {
            RSA_free(rsa_root);
            TRACE_DEVEL("openssl_write_key failed\n");
            return CKR_FUNCTION_FAILED;
        }
        RSA_free(rsa_root);
    } else {
        TRACE_ERROR("%s\n", ock_err(ERR_SESSION_READ_ONLY));
        rc = CKR_SESSION_READ_ONLY;
    }

    return rc;
}

static CK_RV delete_tpm_data()
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
                 pk_dir, pw->pw_name, PK_LITE_OBJ_DIR) < 0) {
        return CKR_HOST_MEMORY;
    }
    if (system(cmd) == -1)
        TRACE_ERROR("system() failed.\n");

    free(cmd);

    // delete the OpenSSL backup keys
    if (asprintf(&cmd, "%s %s/%s/%s > /dev/null 2>&1", DEL_CMD,
                 pk_dir, pw->pw_name, TPMTOK_PUB_ROOT_KEY_FILE) < 0) {
        return CKR_HOST_MEMORY;
    }
    if (system(cmd) == -1)
        TRACE_ERROR("system() failed.\n");

    free(cmd);

    if (asprintf(&cmd, "%s %s/%s/%s > /dev/null 2>&1", DEL_CMD,
                 pk_dir, pw->pw_name, TPMTOK_PRIV_ROOT_KEY_FILE) < 0) {
        return CKR_HOST_MEMORY;
    }
    if (system(cmd) == -1)
        TRACE_ERROR("system() failed.\n");

    free(cmd);

    // delete the masterkey
    if (asprintf(&cmd, "%s %s/%s/%s > /dev/null 2>&1", DEL_CMD,
                 pk_dir, pw->pw_name, TPMTOK_MASTERKEY_PRIVATE) < 0) {
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
    CK_BYTE hash_sha[SHA1_HASH_SIZE];
    CK_RV rc;

    rc = compute_sha1(tokdata, pPin, ulPinLen, hash_sha);
    if (rc != CKR_OK) {
        TRACE_ERROR("compute_sha1 failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    /* find, load the migratable root key */
    rc = token_find_key(tokdata, TPMTOK_PUBLIC_ROOT_KEY,
                        CKO_PRIVATE_KEY, &ckPublicRootKey);
    if (rc != CKR_OK) {
        /* The SO hasn't set her PIN yet, compare the login pin with
         * the hard-coded value */
        if (memcmp(default_so_pin_sha, hash_sha, SHA1_HASH_SIZE)) {
            TRACE_ERROR("token_find_key failed and PIN != default\n");
            return CKR_PIN_INCORRECT;
        }
        goto done;
    }

    rc = token_load_srk();
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_load_srk failed. rc = 0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    /* we found the root key, so check by loading the chain */
    rc = token_load_key(tokdata, ckPublicRootKey,
                        hSRK, NULL, &hPublicRootKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    /* find, load the public leaf key */
    rc = token_find_key(tokdata, TPMTOK_PUBLIC_LEAF_KEY,
                        CKO_PRIVATE_KEY, &ckPublicLeafKey);
    if (rc != CKR_OK) {
        TRACE_ERROR("token_find_key failed. rc=0x%lx\n", rc);
        return CKR_FUNCTION_FAILED;
    }

    rc = token_load_key(tokdata, ckPublicLeafKey,
                        hPublicRootKey, hash_sha, &hPublicLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_load_key(MigLeafKey) Failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    rc = token_verify_pin(hPublicLeafKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_verify_pin failed. rc=0x%lx\n", rc);
        return rc;
    }

done:
    // Before we reconstruct all the data, we should delete the
    // token objects from the filesystem.
    object_mgr_destroy_token_objects(tokdata);
    rc = delete_tpm_data();
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

CK_RV token_specific_final()
{
    TSS_RESULT result;

    TRACE_INFO("tpm %s running\n", __func__);

    result = Tspi_Context_Close(tspContext);
    if (result) {
        TRACE_ERROR("Tspi_Context_Close failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    clear_internal_structures();

    return CKR_OK;
}

CK_RV token_specific_des_key_gen(STDLL_TokData_t * tokdata, CK_BYTE * des_key,
                                 CK_ULONG len, CK_ULONG keysize)
{
    // Nothing different to do for DES or TDES here as this is just
    // random data...  Validation handles the rest
    // Only check for weak keys when DES.
    if (len == (3 * DES_KEY_SIZE)) {
        rng_generate(tokdata, des_key, len);
    } else {
        do {
            rng_generate(tokdata, des_key, len);
        } while (des_check_weak_key(des_key) == TRUE);
    }

    // we really need to validate the key for parity etc...
    // we should do that here... The caller validates the single des keys
    // against the known and suspected poor keys..
    return CKR_OK;
}

CK_RV token_specific_des_ecb(STDLL_TokData_t * tokdata,
                             CK_BYTE * in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE * out_data,
                             CK_ULONG * out_data_len,
                             OBJECT * key, CK_BYTE encrypt)
{
    CK_ULONG rc;
    CK_ATTRIBUTE *attr = NULL;

    DES_key_schedule des_key2;
    const_DES_cblock key_val_SSL, in_key_data;
    DES_cblock out_key_data;
    unsigned int i, j;

    // get the key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("template_attribute_find(CKA_VALUE) failed.\n");
        return CKR_FUNCTION_FAILED;
    }
    // Create the key schedule
    memcpy(&key_val_SSL, attr->pValue, 8);
    DES_set_key_unchecked(&key_val_SSL, &des_key2);

    // the des decrypt will only fail if the data length is not evenly divisible
    // by 8
    if (in_data_len % 8) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }
    // Both the encrypt and the decrypt are done 8 bytes at a time
    if (encrypt) {
        for (i = 0; i < in_data_len; i = i + 8) {
            memcpy(in_key_data, in_data + i, 8);
            DES_ecb_encrypt(&in_key_data, &out_key_data, &des_key2,
                            DES_ENCRYPT);
            memcpy(out_data + i, out_key_data, 8);
        }

        *out_data_len = in_data_len;
        rc = CKR_OK;
    } else {

        for (j = 0; j < in_data_len; j = j + 8) {
            memcpy(in_key_data, in_data + j, 8);
            DES_ecb_encrypt(&in_key_data, &out_key_data, &des_key2,
                            DES_DECRYPT);
            memcpy(out_data + j, out_key_data, 8);
        }

        *out_data_len = in_data_len;
        rc = CKR_OK;
    }

    return rc;
}

CK_RV token_specific_des_cbc(STDLL_TokData_t * tokdata,
                             CK_BYTE * in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE * out_data,
                             CK_ULONG * out_data_len,
                             OBJECT * key, CK_BYTE * init_v, CK_BYTE encrypt)
{
    CK_ULONG rc;
    CK_ATTRIBUTE *attr = NULL;

    DES_cblock ivec;

    DES_key_schedule des_key2;
    const_DES_cblock key_val_SSL;

    // get the key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("template_attribute_find(CKA_VALUE) failed.\n");
        return CKR_FUNCTION_FAILED;
    }
    // Create the key schedule
    memcpy(&key_val_SSL, attr->pValue, 8);
    DES_set_key_unchecked(&key_val_SSL, &des_key2);

    memcpy(&ivec, init_v, 8);
    // the des decrypt will only fail if the data length is not evenly divisible
    // by 8
    if (in_data_len % 8) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }


    if (encrypt) {
        DES_ncbc_encrypt(in_data, out_data, in_data_len, &des_key2, &ivec,
                         DES_ENCRYPT);
        *out_data_len = in_data_len;
        rc = CKR_OK;
    } else {
        DES_ncbc_encrypt(in_data, out_data, in_data_len, &des_key2, &ivec,
                         DES_DECRYPT);
        *out_data_len = in_data_len;
        rc = CKR_OK;
    }
    return rc;
}

CK_RV token_specific_tdes_ecb(STDLL_TokData_t * tokdata,
                              CK_BYTE * in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE * out_data,
                              CK_ULONG * out_data_len,
                              OBJECT * key, CK_BYTE encrypt)
{
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_KEY_TYPE keytype;
    CK_BYTE key_value[3 * DES_KEY_SIZE];

    unsigned int k, j;
    DES_key_schedule des_key1;
    DES_key_schedule des_key2;
    DES_key_schedule des_key3;

    const_DES_cblock key_SSL1, key_SSL2, key_SSL3, in_key_data;
    DES_cblock out_key_data;

    // get the key type
    rc = template_attribute_find(key->template, CKA_KEY_TYPE, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("template_attribute_find(CKA_KEY_TYPE) failed.\n");
        return CKR_FUNCTION_FAILED;
    }
    keytype = *(CK_KEY_TYPE *) attr->pValue;

    // get the key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("template_attribute_find(CKA_VALUE) failed.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (keytype == CKK_DES2) {
        memcpy(key_value, attr->pValue, 2 * DES_KEY_SIZE);
        memcpy(key_value + (2 * DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
    } else {
        memcpy(key_value, attr->pValue, 3 * DES_KEY_SIZE);
    }

    // The key as passed is a 24 byte long string containing three des keys
    // pick them apart and create the 3 corresponding key schedules
    memcpy(&key_SSL1, key_value, 8);
    memcpy(&key_SSL2, key_value + 8, 8);
    memcpy(&key_SSL3, key_value + 16, 8);
    DES_set_key_unchecked(&key_SSL1, &des_key1);
    DES_set_key_unchecked(&key_SSL2, &des_key2);
    DES_set_key_unchecked(&key_SSL3, &des_key3);

    // the des decrypt will only fail if the data length is not evenly divisible
    // by 8
    if (in_data_len % 8) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }
    // the encrypt and decrypt are done 8 bytes at a time
    if (encrypt) {
        for (k = 0; k < in_data_len; k = k + 8) {
            memcpy(in_key_data, in_data + k, 8);
            DES_ecb3_encrypt((const_DES_cblock *) & in_key_data,
                             (DES_cblock *) & out_key_data,
                             &des_key1, &des_key2, &des_key3, DES_ENCRYPT);
            memcpy(out_data + k, out_key_data, 8);
        }
        *out_data_len = in_data_len;
        rc = CKR_OK;
    } else {
        for (j = 0; j < in_data_len; j = j + 8) {
            memcpy(in_key_data, in_data + j, 8);
            DES_ecb3_encrypt((const_DES_cblock *) & in_key_data,
                             (DES_cblock *) & out_key_data,
                             &des_key1, &des_key2, &des_key3, DES_DECRYPT);
            memcpy(out_data + j, out_key_data, 8);
        }
        *out_data_len = in_data_len;
        rc = CKR_OK;
    }

    return rc;
}

CK_RV token_specific_tdes_cbc(STDLL_TokData_t * tokdata,
                              CK_BYTE * in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE * out_data,
                              CK_ULONG * out_data_len,
                              OBJECT * key, CK_BYTE * init_v, CK_BYTE encrypt)
{
    CK_RV rc = CKR_OK;
    CK_ATTRIBUTE *attr = NULL;
    CK_KEY_TYPE keytype;
    CK_BYTE key_value[3 * DES_KEY_SIZE];

    DES_key_schedule des_key1;
    DES_key_schedule des_key2;
    DES_key_schedule des_key3;

    const_DES_cblock key_SSL1, key_SSL2, key_SSL3;
    DES_cblock ivec;

    // get the key type
    rc = template_attribute_find(key->template, CKA_KEY_TYPE, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("template_attribute_find(CKA_KEY_TYPE) failed.\n");
        return CKR_FUNCTION_FAILED;
    }
    keytype = *(CK_KEY_TYPE *) attr->pValue;

    // get the key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("template_attribute_find(CKA_VALUE) failed.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (keytype == CKK_DES2) {
        memcpy(key_value, attr->pValue, 2 * DES_KEY_SIZE);
        memcpy(key_value + (2 * DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
    } else {
        memcpy(key_value, attr->pValue, 3 * DES_KEY_SIZE);
    }

    // The key as passed in is a 24 byte string containing 3 keys
    // pick it apart and create the key schedules
    memcpy(&key_SSL1, key_value, 8);
    memcpy(&key_SSL2, key_value + 8, 8);
    memcpy(&key_SSL3, key_value + 16, 8);
    DES_set_key_unchecked(&key_SSL1, &des_key1);
    DES_set_key_unchecked(&key_SSL2, &des_key2);
    DES_set_key_unchecked(&key_SSL3, &des_key3);

    memcpy(ivec, init_v, sizeof(ivec));

    // the des decrypt will only fail if the data length is not evenly divisible
    // by 8
    if (in_data_len % 8) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }
    // Encrypt or decrypt the data
    if (encrypt) {
        DES_ede3_cbc_encrypt(in_data,
                             out_data,
                             in_data_len,
                             &des_key1,
                             &des_key2, &des_key3, &ivec, DES_ENCRYPT);
        *out_data_len = in_data_len;
        rc = CKR_OK;
    } else {
        DES_ede3_cbc_encrypt(in_data,
                             out_data,
                             in_data_len,
                             &des_key1,
                             &des_key2, &des_key3, &ivec, DES_DECRYPT);

        *out_data_len = in_data_len;
        rc = CKR_OK;
    }

    return rc;
}

/* wrap the 20 bytes of auth data @authData and store in an attribute of the two
 * keys.
 */
CK_RV token_wrap_auth_data(CK_BYTE * authData, TEMPLATE * publ_tmpl,
                           TEMPLATE * priv_tmpl)
{
    CK_RV rc;
    CK_ATTRIBUTE *new_attr;

    TSS_HKEY hParentKey;
    TSS_HENCDATA hEncData;
    BYTE *blob;
    UINT32 blob_size;

    if ((hPrivateLeafKey == NULL_HKEY) && (hPublicLeafKey == NULL_HKEY)) {
        TRACE_ERROR("Shouldn't be wrapping auth data in a " "public path!\n");
        return CKR_FUNCTION_FAILED;
    } else if (hPublicLeafKey != NULL_HKEY) {
        hParentKey = hPublicLeafKey;
    } else {
        hParentKey = hPrivateLeafKey;
    }

    /* create the encrypted data object */
    rc = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_ENCDATA,
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
    template_update_attribute(publ_tmpl, new_attr);

    rc = build_attribute(CKA_ENC_AUTHDATA, blob, blob_size, &new_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed.\n");
        return rc;
    }
    template_update_attribute(priv_tmpl, new_attr);

    return rc;
}

CK_RV token_unwrap_auth_data(CK_BYTE * encAuthData, CK_ULONG encAuthDataLen,
                             TSS_HKEY hKey, BYTE ** authData)
{
    TSS_RESULT result;
    TSS_HENCDATA hEncData;
    BYTE *buf;
    UINT32 buf_size;

    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_ENCDATA,
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

    rc = template_attribute_find(key_obj->template, CKA_MODULUS, &modulus);
    if (rc == FALSE) {
        return NULL;
    }

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
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG mod_bits = 0;
    CK_BBOOL flag;
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

    flag = template_attribute_find(publ_tmpl, CKA_MODULUS_BITS, &attr);
    if (!flag) {
        TRACE_ERROR("template_attribute_find(CKA_MODULUS_BITS) failed.\n");
        return CKR_TEMPLATE_INCOMPLETE; // should never happen
    }
    mod_bits = *(CK_ULONG *) attr->pValue;

    if ((initFlags = util_get_keysize_flag(mod_bits)) == 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        return CKR_KEY_SIZE_RANGE;
    }

    /* If we're not logged in, hPrivateLeafKey and hPublicLeafKey
     * should be NULL */
    if ((hPrivateLeafKey == NULL_HKEY) && (hPublicLeafKey == NULL_HKEY)) {
        /* public session, wrap key with the PRK */
        initFlags |=
            TSS_KEY_TYPE_LEGACY | TSS_KEY_NO_AUTHORIZATION | TSS_KEY_MIGRATABLE;

        if ((result = token_load_public_root_key(tokdata))) {
            TRACE_DEVEL("token_load_public_root_key failed. "
                        "rc=%x\n", result);
            return CKR_FUNCTION_FAILED;
        }

        hParentKey = hPublicRootKey;
    } else if (hPrivateLeafKey != NULL_HKEY) {
        /* logged in USER session */
        initFlags |=
            TSS_KEY_TYPE_LEGACY | TSS_KEY_AUTHORIZATION | TSS_KEY_MIGRATABLE;

        /* get a random SHA1 hash for the auth data */
        if ((rc = token_specific_rng(tokdata, authHash, SHA1_HASH_SIZE))) {
            TRACE_DEVEL("token_rng failed. rc=%lx\n", rc);
            return CKR_FUNCTION_FAILED;
        }

        authData = authHash;
        hParentKey = hPrivateRootKey;
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
        hParentKey = hPublicRootKey;
    }

    result = tss_generate_key(initFlags, authData, hParentKey, &hKey);
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
        Tspi_Context_FreeMemory(tspContext, rgbBlob);
        return rc;
    }
    template_update_attribute(priv_tmpl, attr);

    rc = build_attribute(CKA_IBM_OPAQUE, rgbBlob, ulBlobLen, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_IBM_OPAQUE) failed.\n");
        Tspi_Context_FreeMemory(tspContext, rgbBlob);
        return rc;
    }
    template_update_attribute(publ_tmpl, attr);

    Tspi_Context_FreeMemory(tspContext, rgbBlob);

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
        Tspi_Context_FreeMemory(tspContext, rgbBlob);
        return rc;
    }
    template_update_attribute(publ_tmpl, attr);

    /* add the public key blob to the object template */
    rc = build_attribute(CKA_MODULUS, rgbBlob, ulBlobLen, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_MODULUS) failed.\n");
        Tspi_Context_FreeMemory(tspContext, rgbBlob);
        return rc;
    }
    template_update_attribute(priv_tmpl, attr);
    Tspi_Context_FreeMemory(tspContext, rgbBlob);

    /* put the public exponent into the private key object */
    rc = build_attribute(CKA_PUBLIC_EXPONENT,
                         tpm_pubexp, sizeof(tpm_pubexp), &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_PUBLIC_EXPONENT) failed.\n");
        return rc;
    }
    template_update_attribute(priv_tmpl, attr);

    /* wrap the authdata and put it into an object */
    if (authData != NULL) {
        rc = token_wrap_auth_data(authData, publ_tmpl, priv_tmpl);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_wrap_auth_data failed with rc: 0x%lx\n", rc);
        }
    }

    return rc;
}

CK_RV token_rsa_load_key(STDLL_TokData_t * tokdata, OBJECT * key_obj,
                         TSS_HKEY * phKey)
{
    TSS_RESULT result;
    TSS_HPOLICY hPolicy = NULL_HPOLICY;
    TSS_HKEY hParentKey;
    BYTE *authData = NULL;
    CK_ATTRIBUTE *attr;
    CK_RV rc;
    CK_OBJECT_HANDLE handle;

    if (hPrivateLeafKey != NULL_HKEY) {
        hParentKey = hPrivateRootKey;
    } else {
        result = token_load_public_root_key(tokdata);
        if (result) {
            TRACE_DEVEL("token_load_public_root_key failed. "
                        "rc=%x\n", result);
            return CKR_FUNCTION_FAILED;
        }

        hParentKey = hPublicRootKey;
    }


    rc = template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr);
    if (rc == FALSE) {
        /* if the key blob wasn't found, then try to wrap the key */
        rc = object_mgr_find_in_map2(tokdata, key_obj, &handle);
        if (rc != CKR_OK)
            return CKR_FUNCTION_FAILED;

        rc = token_load_key(tokdata, handle, hParentKey, NULL, phKey);
        if (rc != CKR_OK) {
            TRACE_DEVEL("token_load_key failed. rc=0x%lx\n", rc);
            return rc;
        }
        /* try again to get the CKA_IBM_OPAQUE attr */
        rc = template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr);
        if (rc == FALSE) {
            TRACE_ERROR("Could not find key blob\n");
            return rc;
        }
    }

    result = Tspi_Context_LoadKeyByBlob(tspContext, hParentKey,
                                        attr->ulValueLen, attr->pValue, phKey);
    if (result) {
        TRACE_ERROR("Tspi_Context_LoadKeyByBlob failed. rc=0x%x\n", result);
        return CKR_FUNCTION_FAILED;
    }

    /* auth data may be required */
    if (template_attribute_find(key_obj->template, CKA_ENC_AUTHDATA, &attr) ==
        TRUE && attr) {
        if ((hPrivateLeafKey == NULL_HKEY) && (hPublicLeafKey == NULL_HKEY)) {
            TRACE_ERROR("Shouldn't be in a public session here\n");
            return CKR_FUNCTION_FAILED;
        } else if (hPublicLeafKey != NULL_HKEY) {
            hParentKey = hPublicLeafKey;
        } else {
            hParentKey = hPrivateLeafKey;
        }

        result = token_unwrap_auth_data(attr->pValue, attr->ulValueLen,
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
        if (hPolicy == hDefaultPolicy) {
            result = Tspi_Context_CreateObject(tspContext,
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

        Tspi_Context_FreeMemory(tspContext, authData);
    }

    return CKR_OK;
}

CK_RV token_specific_rsa_decrypt(STDLL_TokData_t * tokdata,
                                 CK_BYTE * in_data,
                                 CK_ULONG in_data_len,
                                 CK_BYTE * out_data,
                                 CK_ULONG * out_data_len, OBJECT * key_obj)
{
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
    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_ENCDATA,
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
        Tspi_Context_FreeMemory(tspContext, buf);
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(out_data, buf, buf_size);
    *out_data_len = buf_size;

    Tspi_Context_FreeMemory(tspContext, buf);

    return CKR_OK;
}

CK_RV token_specific_rsa_verify(STDLL_TokData_t * tokdata,
                                SESSION * sess,
                                CK_BYTE * in_data,
                                CK_ULONG in_data_len,
                                CK_BYTE * sig,
                                CK_ULONG sig_len, OBJECT * key_obj)
{
    TSS_RESULT result;
    TSS_HHASH hHash;
    TSS_HKEY hKey;
    CK_RV rc;

    rc = token_rsa_load_key(tokdata, key_obj, &hKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_rsa_load_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* Create the hash object we'll use to sign */
    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_HASH,
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
    TSS_RESULT result;
    TSS_HHASH hHash;
    BYTE *sig;
    UINT32 sig_len;
    TSS_HKEY hKey;
    CK_RV rc;

    rc = token_rsa_load_key(tokdata, key_obj, &hKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("token_rsa_load_key failed. rc=0x%lx\n", rc);
        return rc;
    }

    /* Create the hash object we'll use to sign */
    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_HASH,
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
        Tspi_Context_FreeMemory(tspContext, sig);
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(out_data, sig, sig_len);
    *out_data_len = sig_len;
    Tspi_Context_FreeMemory(tspContext, sig);

    return CKR_OK;
}


CK_RV token_specific_rsa_encrypt(STDLL_TokData_t * tokdata,
                                 CK_BYTE * in_data,
                                 CK_ULONG in_data_len,
                                 CK_BYTE * out_data,
                                 CK_ULONG * out_data_len, OBJECT * key_obj)
{
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

    result = Tspi_Context_CreateObject(tspContext, TSS_OBJECT_TYPE_ENCDATA,
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
        Tspi_Context_FreeMemory(tspContext, dataBlob);
        return CKR_DATA_LEN_RANGE;
    }

    memcpy(out_data, dataBlob, dataBlobSize);
    *out_data_len = dataBlobSize;
    Tspi_Context_FreeMemory(tspContext, dataBlob);

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

CK_RV token_specific_aes_key_gen(STDLL_TokData_t * tokdata, CK_BYTE * key,
                                 CK_ULONG len, CK_ULONG keysize)
{
    return token_specific_rng(tokdata, key, len);
}

CK_RV token_specific_aes_ecb(STDLL_TokData_t * tokdata,
                             CK_BYTE * in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE * out_data,
                             CK_ULONG * out_data_len,
                             OBJECT * key, CK_BYTE encrypt)
{
    CK_ATTRIBUTE *attr = NULL;
    AES_KEY ssl_aes_key;
    unsigned int i;
    /* There's a previous check that in_data_len % AES_BLOCK_SIZE == 0,
     * so this is fine */
    CK_ULONG loops = (CK_ULONG) (in_data_len / AES_BLOCK_SIZE);

    // get the key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("template_attribute_find(CKA_VALUE) failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    memset(&ssl_aes_key, 0, sizeof(AES_KEY));

    // AES_ecb_encrypt encrypts only a single block, so we have to break up the
    // input data here
    if (encrypt) {
        AES_set_encrypt_key((unsigned char *) attr->pValue,
                            (attr->ulValueLen * 8), &ssl_aes_key);
        for (i = 0; i < loops; i++) {
            AES_ecb_encrypt((unsigned char *) in_data + (i * AES_BLOCK_SIZE),
                            (unsigned char *) out_data + (i * AES_BLOCK_SIZE),
                            &ssl_aes_key, AES_ENCRYPT);
        }
    } else {
        AES_set_decrypt_key((unsigned char *) attr->pValue,
                            (attr->ulValueLen * 8), &ssl_aes_key);
        for (i = 0; i < loops; i++) {
            AES_ecb_encrypt((unsigned char *) in_data + (i * AES_BLOCK_SIZE),
                            (unsigned char *) out_data + (i * AES_BLOCK_SIZE),
                            &ssl_aes_key, AES_DECRYPT);
        }
    }
    *out_data_len = in_data_len;

    return CKR_OK;
}

CK_RV token_specific_aes_cbc(STDLL_TokData_t * tokdata,
                             CK_BYTE * in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE * out_data,
                             CK_ULONG * out_data_len,
                             OBJECT * key, CK_BYTE * init_v, CK_BYTE encrypt)
{
    AES_KEY ssl_aes_key;
    CK_ATTRIBUTE *attr = NULL;

    // get the key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("template_attribute_find(CKA_VALUE) failed.\n");
        return CKR_FUNCTION_FAILED;
    }

    memset(&ssl_aes_key, 0, sizeof(AES_KEY));

    // AES_cbc_encrypt chunks the data into AES_BLOCK_SIZE blocks, unlike
    // AES_ecb_encrypt, so no looping required.
    if (encrypt) {
        AES_set_encrypt_key((unsigned char *) attr->pValue,
                            (attr->ulValueLen * 8), &ssl_aes_key);
        AES_cbc_encrypt((unsigned char *) in_data, (unsigned char *) out_data,
                        in_data_len, &ssl_aes_key, init_v, AES_ENCRYPT);
    } else {
        AES_set_decrypt_key((unsigned char *) attr->pValue,
                            (attr->ulValueLen * 8), &ssl_aes_key);
        AES_cbc_encrypt((unsigned char *) in_data, (unsigned char *) out_data,
                        in_data_len, &ssl_aes_key, init_v, AES_DECRYPT);
    }
    *out_data_len = in_data_len;

    return CKR_OK;
}

CK_RV token_specific_get_mechanism_list(STDLL_TokData_t * tokdata,
                                        CK_MECHANISM_TYPE_PTR pMechanismList,
                                        CK_ULONG_PTR pulCount)
{
    int rc;
    /* common/mech_list.c */
    rc = ock_generic_get_mechanism_list(pMechanismList, pulCount);

    return rc;
}

CK_RV token_specific_get_mechanism_info(STDLL_TokData_t * tokdata,
                                        CK_MECHANISM_TYPE type,
                                        CK_MECHANISM_INFO_PTR pInfo)
{
    int rc;
    /* common/mech_list.c */
    rc = ock_generic_get_mechanism_info(type, pInfo);

    return rc;
}

int token_specific_creatlock(void)
{
    CK_BYTE lockfile[PATH_MAX];
    CK_BYTE lockdir[PATH_MAX];
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
        grp = getgrnam("pkcs11");
        if (grp == NULL) {
            fprintf(stderr, "getgrname(pkcs11): %s", strerror(errno));
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
    memset(lockfile, 0, PATH_MAX);
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
    /* do nothing. */
    return CKR_OK;
}
