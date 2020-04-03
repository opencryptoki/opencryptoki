/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/***************************************************************************
                          Change Log
                          ==========
       4/25/03    Kapil Sood (kapil@corrent.com)
                  Added DH key pair generation and DH shared key derivation
                  functions.



****************************************************************************/

#include <pthread.h>
#include <string.h>             // for memcmp() et al
#include <stdlib.h>
#include <unistd.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "errno.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "trace.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <endian.h>

#include <openssl/des.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/cmac.h>

/*
 * In order to make opencryptoki compatible with
 * OpenSSL 1.1 API Changes and backward compatible
 * we need to check for its version
 */
#if OPENSSL_VERSION_NUMBER < 0x10100000L
#define OLDER_OPENSSL
#endif

#define MAX_GENERIC_KEY_SIZE 256

const char manuf[] = "IBM";
const char model[] = "Soft";
const char descr[] = "IBM Soft token";
const char label[] = "softtok";

static const MECH_LIST_ELEMENT soft_mech_list[] = {
    {CKM_RSA_PKCS_KEY_PAIR_GEN, {512, 4096, CKF_GENERATE_KEY_PAIR}},
#if !(NODSA)
    {CKM_DSA_KEY_PAIR_GEN, {512, 1024, CKF_GENERATE_KEY_PAIR}},
#endif
    {CKM_DES_KEY_GEN, {8, 8, CKF_GENERATE}},
    {CKM_DES3_KEY_GEN, {24, 24, CKF_GENERATE}},
#if !(NOCDMF)
    {CKM_CDMF_KEY_GEN, {0, 0, CKF_GENERATE}},
#endif
    {CKM_RSA_PKCS,
     {512, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP | CKF_SIGN |
      CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER}},
    {CKM_RSA_PKCS_PSS, {1024, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA1_RSA_PKCS_PSS, {1024, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA224_RSA_PKCS_PSS, {1024, 4096, CKF_SIGN|CKF_VERIFY}},
    {CKM_SHA256_RSA_PKCS_PSS, {1024, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_RSA_PKCS_PSS, {1024, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_RSA_PKCS_PSS, {1024, 4096, CKF_SIGN | CKF_VERIFY}},
#if !(NOX509)
    {CKM_RSA_X_509,
     {512, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP | CKF_SIGN |
      CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER}},
#endif
    {CKM_RSA_PKCS_OAEP,
     {1024, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
#if !(NOMD2)
    {CKM_MD2_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
#endif
#if !(NOMD5)
    {CKM_MD5_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
#endif
#if !(NOSHA1)
    {CKM_SHA1_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
#endif
#if !(NODSA)
    {CKM_DSA, {512, 1024, CKF_SIGN | CKF_VERIFY}},
#endif
/* Begin code contributed by Corrent corp. */
#if !(NODH)
    {CKM_DH_PKCS_DERIVE, {512, 2048, CKF_DERIVE}},
    {CKM_DH_PKCS_KEY_PAIR_GEN, {512, 2048, CKF_GENERATE_KEY_PAIR}},
#endif
/* End code contributed by Corrent corp. */
    {CKM_DES_ECB, {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CBC, {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CBC_PAD,
     {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
#if !(NOCDMF)
    {CKM_CDMF_ECB, {0, 0, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_CDMF_CBC, {0, 0, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
#endif
    {CKM_DES3_ECB, {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_CBC, {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_CBC_PAD,
     {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_CMAC, {16, 24, CKF_SIGN | CKF_VERIFY}},
    {CKM_DES3_CMAC_GENERAL, {16, 24, CKF_SIGN | CKF_VERIFY}},
#if !(NOSHA1)
    {CKM_SHA_1, {0, 0, CKF_DIGEST}},
    {CKM_SHA_1_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA_1_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
#endif
    {CKM_SHA224, {0, 0, CKF_DIGEST}},
    {CKM_SHA224_HMAC, {0, 0, CKF_SIGN|CKF_VERIFY}},
    {CKM_SHA224_HMAC_GENERAL, {0, 0, CKF_SIGN|CKF_VERIFY}},
    {CKM_SHA256, {0, 0, CKF_DIGEST}},
    {CKM_SHA256_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384, {0, 0, CKF_DIGEST}},
    {CKM_SHA384_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512, {0, 0, CKF_DIGEST}},
    {CKM_SHA512_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_224, {0, 0, CKF_DIGEST}},
    {CKM_SHA512_256, {0, 0, CKF_DIGEST}},
#if !(NOMD2)
    {CKM_MD2, {0, 0, CKF_DIGEST}},
    {CKM_MD2_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_MD2_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
#endif
#if !(NOMD5)
    {CKM_MD5, {0, 0, CKF_DIGEST}},
    {CKM_MD5_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_MD5_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
#endif
    {CKM_SSL3_PRE_MASTER_KEY_GEN, {48, 48, CKF_GENERATE}},
    {CKM_SSL3_MASTER_KEY_DERIVE, {48, 48, CKF_DERIVE}},
    {CKM_SSL3_KEY_AND_MAC_DERIVE, {48, 48, CKF_DERIVE}},
    {CKM_SSL3_MD5_MAC, {384, 384, CKF_SIGN | CKF_VERIFY}},
    {CKM_SSL3_SHA1_MAC, {384, 384, CKF_SIGN | CKF_VERIFY}},
#if !(NOAES)
    {CKM_AES_KEY_GEN, {16, 32, CKF_GENERATE}},
    {CKM_AES_ECB, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_CBC, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_CBC_PAD,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_CMAC, {16, 32, CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_CMAC_GENERAL, {16, 32, CKF_SIGN | CKF_VERIFY}},
#endif
    {CKM_GENERIC_SECRET_KEY_GEN, {80, 2048, CKF_GENERATE}}
};

static const CK_ULONG soft_mech_list_len =
                    (sizeof(soft_mech_list) / sizeof(MECH_LIST_ELEMENT));

CK_RV token_specific_init(STDLL_TokData_t *tokdata, CK_SLOT_ID SlotNumber,
                          char *conf_name)
{
    UNUSED(conf_name);

    tokdata->mech_list = (MECH_LIST_ELEMENT *)soft_mech_list;
    tokdata->mech_list_len = soft_mech_list_len;

    TRACE_INFO("soft %s slot=%lu running\n", __func__, SlotNumber);

    return CKR_OK;
}

CK_RV token_specific_final(STDLL_TokData_t *tokdata,
                           CK_BBOOL token_specific_final)
{
    UNUSED(tokdata);
    UNUSED(token_specific_final);

    TRACE_INFO("soft %s running\n", __func__);

    return CKR_OK;
}

CK_RV token_specific_des_key_gen(STDLL_TokData_t *tokdata, CK_BYTE *des_key,
                                 CK_ULONG len, CK_ULONG keysize)
{
    UNUSED(keysize);

    // Nothing different to do for DES or TDES here as this is just
    // random data...  Validation handles the rest
    // Only check for weak keys when single DES.
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

CK_RV token_specific_des_ecb(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE encrypt)
{
    CK_ULONG rc;
    DES_key_schedule des_key2;
    const_DES_cblock key_val_SSL, in_key_data;
    DES_cblock out_key_data;
    unsigned int i, j;
    CK_ATTRIBUTE *attr = NULL;

    UNUSED(tokdata);

    // get the key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
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

CK_RV token_specific_des_cbc(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    CK_ULONG rc;
    CK_ATTRIBUTE *attr = NULL;
    DES_cblock ivec;
    DES_key_schedule des_key2;
    const_DES_cblock key_val_SSL;

    UNUSED(tokdata);

    // get the key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
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

CK_RV token_specific_tdes_ecb(STDLL_TokData_t *tokdata,
                              CK_BYTE *in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE *out_data,
                              CK_ULONG *out_data_len,
                              OBJECT *key, CK_BYTE encrypt)
{
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE key_value[3 * DES_KEY_SIZE];
    CK_KEY_TYPE keytype;
    unsigned int k, j;
    DES_key_schedule des_key1;
    DES_key_schedule des_key2;
    DES_key_schedule des_key3;
    const_DES_cblock key_SSL1, key_SSL2, key_SSL3, in_key_data;
    DES_cblock out_key_data;

    UNUSED(tokdata);

    // get the key type
    rc = template_attribute_find(key->template, CKA_KEY_TYPE, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
        return CKR_FUNCTION_FAILED;
    }
    keytype = *(CK_KEY_TYPE *) attr->pValue;

    // get the key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
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

CK_RV token_specific_tdes_cbc(STDLL_TokData_t *tokdata,
                              CK_BYTE *in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE *out_data,
                              CK_ULONG *out_data_len,
                              OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_RV rc = CKR_OK;
    CK_BYTE key_value[3 * DES_KEY_SIZE];
    CK_KEY_TYPE keytype;
    DES_key_schedule des_key1;
    DES_key_schedule des_key2;
    DES_key_schedule des_key3;
    const_DES_cblock key_SSL1, key_SSL2, key_SSL3;
    DES_cblock ivec;

    UNUSED(tokdata);

    // get the key type
    rc = template_attribute_find(key->template, CKA_KEY_TYPE, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
        return CKR_FUNCTION_FAILED;
    }
    keytype = *(CK_KEY_TYPE *) attr->pValue;

    // get the key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
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

// convert from the local PKCS11 template representation to
// the underlying requirement
// returns the pointer to the local key representation
static void *rsa_convert_public_key(OBJECT *key_obj)
{
    CK_BBOOL rc;
    CK_ATTRIBUTE *modulus = NULL;
    CK_ATTRIBUTE *pub_exp = NULL;

    RSA *rsa;
    BIGNUM *bn_mod, *bn_exp;

    rc = template_attribute_find(key_obj->template, CKA_MODULUS, &modulus);
    rc &=
        template_attribute_find(key_obj->template, CKA_PUBLIC_EXPONENT,
                                &pub_exp);

    if (rc == FALSE) {
        return NULL;
    }
    // Create an RSA key struct to return
    rsa = RSA_new();
    if (rsa == NULL)
        return NULL;

    // Create and init BIGNUM structs to stick in the RSA struct
    bn_mod = BN_new();
    bn_exp = BN_new();

    if (bn_exp == NULL || bn_mod == NULL) {
        if (bn_mod)
            free(bn_mod);
        if (bn_exp)
            free(bn_exp);
        RSA_free(rsa);
        return NULL;
    }
    // Convert from strings to BIGNUMs and stick them in the RSA struct
    BN_bin2bn((unsigned char *) modulus->pValue, modulus->ulValueLen, bn_mod);
    BN_bin2bn((unsigned char *) pub_exp->pValue, pub_exp->ulValueLen, bn_exp);

#ifdef OLDER_OPENSSL
    rsa->n = bn_mod;
    rsa->e = bn_exp;
#else
    RSA_set0_key(rsa, bn_mod, bn_exp, NULL);
#endif

    return (void *) rsa;
}

static void *rsa_convert_private_key(OBJECT *key_obj)
{
    CK_ATTRIBUTE *modulus = NULL;
    CK_ATTRIBUTE *pub_exp = NULL;
    CK_ATTRIBUTE *priv_exp = NULL;
    CK_ATTRIBUTE *prime1 = NULL;
    CK_ATTRIBUTE *prime2 = NULL;
    CK_ATTRIBUTE *exp1 = NULL;
    CK_ATTRIBUTE *exp2 = NULL;
    CK_ATTRIBUTE *coeff = NULL;
    CK_BBOOL rc;

    RSA *rsa;
    RSA_METHOD *meth;
    BIGNUM *bn_mod, *bn_pub_exp, *bn_priv_exp, *bn_p1, *bn_p2, *bn_e1, *bn_e2,
        *bn_cf;


    rc = template_attribute_find(key_obj->template, CKA_MODULUS, &modulus);
    rc &=
        template_attribute_find(key_obj->template, CKA_PUBLIC_EXPONENT,
                                &pub_exp);
    rc &=
        template_attribute_find(key_obj->template, CKA_PRIVATE_EXPONENT,
                                &priv_exp);
    rc &= template_attribute_find(key_obj->template, CKA_PRIME_1, &prime1);
    rc &= template_attribute_find(key_obj->template, CKA_PRIME_2, &prime2);
    rc &= template_attribute_find(key_obj->template, CKA_EXPONENT_1, &exp1);
    rc &= template_attribute_find(key_obj->template, CKA_EXPONENT_2, &exp2);
    rc &= template_attribute_find(key_obj->template, CKA_COEFFICIENT, &coeff);

    if (!prime2 && !modulus) {
        return NULL;
    }
    // Create and init all the RSA and BIGNUM structs we need.
    rsa = RSA_new();
    if (rsa == NULL)
        return NULL;

    /*
     * Depending if an engine is loaded on OpenSSL and define its own
     * RSA_METHOD, we can end up having an infinite loop as the SOFT
     * Token doesn't implement RSA and, instead, calls OpenSSL for it.
     * So to avoid it we set RSA methods to the default rsa methods.
     */
#ifdef OLDER_OPENSSL
    if (rsa->engine) {
        meth = (RSA_METHOD *) rsa->meth;
        const RSA_METHOD *meth2 = RSA_PKCS1_SSLeay();
        meth->rsa_pub_enc = meth2->rsa_pub_enc;
        meth->rsa_pub_dec = meth2->rsa_pub_dec;
        meth->rsa_priv_enc = meth2->rsa_priv_enc;
        meth->rsa_priv_dec = meth2->rsa_priv_dec;
        meth->rsa_mod_exp = meth2->rsa_mod_exp;
        meth->bn_mod_exp = meth2->bn_mod_exp;
#else
    ENGINE *e = RSA_get0_engine(rsa);
    if (e) {
        meth = (RSA_METHOD *) RSA_get_method(rsa);
        const RSA_METHOD *meth2 = RSA_PKCS1_OpenSSL();
        RSA_meth_set_pub_enc(meth, RSA_meth_get_pub_enc(meth2));
        RSA_meth_set_pub_dec(meth, RSA_meth_get_pub_dec(meth2));
        RSA_meth_set_priv_enc(meth, RSA_meth_get_priv_enc(meth2));
        RSA_meth_set_priv_dec(meth, RSA_meth_get_priv_dec(meth2));
        RSA_meth_set_mod_exp(meth, RSA_meth_get_mod_exp(meth2));
        RSA_meth_set_bn_mod_exp(meth, RSA_meth_get_bn_mod_exp(meth2));
#endif
    }

    bn_mod = BN_new();
    bn_pub_exp = BN_new();
    bn_priv_exp = BN_new();
    bn_p1 = BN_new();
    bn_p2 = BN_new();
    bn_e1 = BN_new();
    bn_e2 = BN_new();
    bn_cf = BN_new();

    if ((bn_cf == NULL) || (bn_e2 == NULL) || (bn_e1 == NULL) ||
        (bn_p2 == NULL) || (bn_p1 == NULL) || (bn_priv_exp == NULL) ||
        (bn_pub_exp == NULL) || (bn_mod == NULL)) {
        if (rsa)
            RSA_free(rsa);
        if (bn_mod)
            BN_free(bn_mod);
        if (bn_pub_exp)
            BN_free(bn_pub_exp);
        if (bn_priv_exp)
            BN_free(bn_priv_exp);
        if (bn_p1)
            BN_free(bn_p1);
        if (bn_p2)
            BN_free(bn_p2);
        if (bn_e1)
            BN_free(bn_e1);
        if (bn_e2)
            BN_free(bn_e2);
        if (bn_cf)
            BN_free(bn_cf);
        return NULL;
    }

    // CRT key?
    if (prime1) {
        if (!prime2 || !exp1 || !exp2 || !coeff) {
            return NULL;
        }
        // Even though this is CRT key, OpenSSL requires the
        // modulus and exponents filled in or encrypt and decrypt will
        // not work
        BN_bin2bn((unsigned char *) modulus->pValue, modulus->ulValueLen,
                  bn_mod);
        BN_bin2bn((unsigned char *) pub_exp->pValue, pub_exp->ulValueLen,
                  bn_pub_exp);
        BN_bin2bn((unsigned char *) priv_exp->pValue, priv_exp->ulValueLen,
                  bn_priv_exp);

        BN_bin2bn((unsigned char *) prime1->pValue, prime1->ulValueLen, bn_p1);
        BN_bin2bn((unsigned char *) prime2->pValue, prime2->ulValueLen, bn_p2);

        BN_bin2bn((unsigned char *) exp1->pValue, exp1->ulValueLen, bn_e1);
        BN_bin2bn((unsigned char *) exp2->pValue, exp2->ulValueLen, bn_e2);
        BN_bin2bn((unsigned char *) coeff->pValue, coeff->ulValueLen, bn_cf);
#ifdef OLDER_OPENSSL
        rsa->n = bn_mod;
        rsa->d = bn_priv_exp;
        rsa->p = bn_p1;
        rsa->q = bn_p2;
        rsa->dmp1 = bn_e1;
        rsa->dmq1 = bn_e2;
        rsa->iqmp = bn_cf;
#else
        RSA_set0_key(rsa, bn_mod, bn_pub_exp, bn_priv_exp);
        RSA_set0_factors(rsa, bn_p1, bn_p2);
        RSA_set0_crt_params(rsa, bn_e1, bn_e2, bn_cf);
#endif
        return rsa;
    } else {                    // must be a non-CRT key
        if (!priv_exp) {
            return NULL;
        }
        BN_bin2bn((unsigned char *) modulus->pValue, modulus->ulValueLen,
                  bn_mod);
        BN_bin2bn((unsigned char *) pub_exp->pValue, pub_exp->ulValueLen,
                  bn_pub_exp);
        BN_bin2bn((unsigned char *) priv_exp->pValue, priv_exp->ulValueLen,
                  bn_priv_exp);
#ifdef OLDER_OPENSSL
        rsa->n = bn_mod;
        rsa->d = bn_priv_exp;
#else
        RSA_set0_key(rsa, bn_mod, bn_pub_exp, bn_priv_exp);
#endif
    }

    return (void *) rsa;
}

static CK_RV os_specific_rsa_keygen(TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    CK_ATTRIBUTE *publ_exp = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG mod_bits;
    CK_BBOOL flag;
    CK_RV rc;
    CK_ULONG BNLength;
    RSA *rsa = NULL;
    const BIGNUM *bignum;
    CK_BYTE *ssl_ptr = NULL;
    BIGNUM *e = NULL;

    flag = template_attribute_find(publ_tmpl, CKA_MODULUS_BITS, &attr);
    if (!flag) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE; // should never happen
    }
    mod_bits = *(CK_ULONG *) attr->pValue;

    // we don't support less than 1024 bit keys in the sw
    if (mod_bits < 512 || mod_bits > 4096) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        return CKR_KEY_SIZE_RANGE;
    }

    flag = template_attribute_find(publ_tmpl, CKA_PUBLIC_EXPONENT, &publ_exp);
    if (!flag) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCOMPLETE));
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if (publ_exp->ulValueLen > sizeof(CK_ULONG)) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    e = BN_new();
    rsa = RSA_new();

    if (e == NULL || rsa == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    BN_bin2bn(publ_exp->pValue, publ_exp->ulValueLen, e);

    if (!RSA_generate_key_ex(rsa, mod_bits, e, NULL)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    // Now fill in the objects..
    //
    // modulus: n
    //
#ifdef OLDER_OPENSSL
    bignum = rsa->n;
#else
    RSA_get0_key(rsa, &bignum, NULL, NULL);
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_MODULUS, ssl_ptr, BNLength, &attr);    // in bytes
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(publ_tmpl, attr);
    free(ssl_ptr);
    ssl_ptr = NULL;

    // Public Exponent
#ifdef OLDER_OPENSSL
    bignum = rsa->e;
#else
    RSA_get0_key(rsa, NULL, &bignum, NULL);
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    // in bytes
    rc = build_attribute(CKA_PUBLIC_EXPONENT, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(publ_tmpl, attr);

    /* add public exponent to the private template. Its already an attribute in
     * the private template at this point, we're just making its value correct
     */
    rc = build_attribute(CKA_PUBLIC_EXPONENT, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(priv_tmpl, attr);
    free(ssl_ptr);
    ssl_ptr = NULL;

    // local = TRUE
    //
    flag = TRUE;
    rc = build_attribute(CKA_LOCAL, &flag, sizeof(CK_BBOOL), &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(publ_tmpl, attr);

    //
    // now, do the private key
    //
    // Cheat here and put the whole original key into the CKA_VALUE... remember
    // to force the system to not return this for RSA keys..

    // Add the modulus to the private key information
#ifdef OLDER_OPENSSL
    bignum = rsa->n;
#else
    RSA_get0_key(rsa, &bignum, NULL, NULL);
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_MODULUS, ssl_ptr, BNLength, &attr);    // in bytes
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(priv_tmpl, attr);
    free(ssl_ptr);
    ssl_ptr = NULL;

    // Private Exponent
#ifdef OLDER_OPENSSL
    bignum = rsa->d;
#else
    RSA_get0_key(rsa, NULL, NULL, &bignum);
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_PRIVATE_EXPONENT, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(priv_tmpl, attr);
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;

    // prime #1: p
    //
#ifdef OLDER_OPENSSL
    bignum = rsa->p;
#else
    RSA_get0_factors(rsa, &bignum, NULL);
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_PRIME_1, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(priv_tmpl, attr);
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;

    // prime #2: q
    //
#ifdef OLDER_OPENSSL
    bignum = rsa->q;
#else
    RSA_get0_factors(rsa, NULL, &bignum);
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_PRIME_2, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(priv_tmpl, attr);
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;

    // exponent 1: d mod(p-1)
    //
#ifdef OLDER_OPENSSL
    bignum = rsa->dmp1;
#else
    RSA_get0_crt_params(rsa, &bignum, NULL, NULL);
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_EXPONENT_1, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(priv_tmpl, attr);
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;

    // exponent 2: d mod(q-1)
    //
#ifdef OLDER_OPENSSL
    bignum = rsa->dmq1;
#else
    RSA_get0_crt_params(rsa, NULL, &bignum, NULL);
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_EXPONENT_2, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(priv_tmpl, attr);
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;

    // CRT coefficient:  q_inverse mod(p)
    //
#ifdef OLDER_OPENSSL
    bignum = rsa->iqmp;
#else
    RSA_get0_crt_params(rsa, NULL, NULL, &bignum);
#endif
    BNLength = BN_num_bytes(bignum);
    ssl_ptr = malloc(BNLength);
    if (ssl_ptr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    BNLength = BN_bn2bin(bignum, ssl_ptr);
    rc = build_attribute(CKA_COEFFICIENT, ssl_ptr, BNLength, &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(priv_tmpl, attr);
    OPENSSL_cleanse(ssl_ptr, BNLength);
    free(ssl_ptr);
    ssl_ptr = NULL;

    flag = TRUE;
    rc = build_attribute(CKA_LOCAL, &flag, sizeof(CK_BBOOL), &attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    template_update_attribute(priv_tmpl, attr);

done:
    if (e != NULL)
        BN_free(e);
    if (rsa != NULL)
        RSA_free(rsa);
    if (ssl_ptr != NULL)
        free(ssl_ptr);

    return rc;
}

CK_RV token_specific_rsa_generate_keypair(STDLL_TokData_t *tokdata,
                                          TEMPLATE *publ_tmpl,
                                          TEMPLATE *priv_tmpl)
{
    CK_RV rc;

    UNUSED(tokdata);

    rc = os_specific_rsa_keygen(publ_tmpl, priv_tmpl);
    if (rc != CKR_OK)
        TRACE_DEVEL("os_specific_rsa_keygen failed\n");

    return rc;
}


static CK_RV os_specific_rsa_encrypt(CK_BYTE *in_data,
                                     CK_ULONG in_data_len,
                                     CK_BYTE *out_data, OBJECT *key_obj)
{
    CK_RV rc;
    RSA *rsa;
    int size;

    // Convert the local representation to an RSA representation
    rsa = (RSA *) rsa_convert_public_key(key_obj);
    if (rsa == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        return rc;
    }
    // Do an RSA public encryption
    size =
        RSA_public_encrypt(in_data_len, in_data, out_data, rsa, RSA_NO_PADDING);
    if (size == -1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    rc = CKR_OK;

done:
    RSA_free(rsa);

    return rc;
}

static CK_RV os_specific_rsa_decrypt(CK_BYTE *in_data,
                                     CK_ULONG in_data_len,
                                     CK_BYTE *out_data, OBJECT *key_obj)
{
    CK_RV rc;
    RSA *rsa;
    int size;

    // Convert the local key representation to an RSA key representaion
    rsa = (RSA *) rsa_convert_private_key(key_obj);
    if (rsa == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        return rc;
    }
    // Do the private decryption
    size =
        RSA_private_decrypt(in_data_len, in_data, out_data, rsa,
                            RSA_NO_PADDING);

    if (size == -1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;

done:
    RSA_free(rsa);

    return rc;
}

CK_RV token_specific_rsa_encrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                 CK_ULONG in_data_len, CK_BYTE *out_data,
                                 CK_ULONG *out_data_len, OBJECT *key_obj)
{
    CK_RV rc;
    CK_ULONG modulus_bytes;
    CK_BYTE clear[MAX_RSA_KEYLEN], cipher[MAX_RSA_KEYLEN];
    CK_ATTRIBUTE *attr = NULL;

    /* format the data */
    if (!template_attribute_find(key_obj->template, CKA_MODULUS, &attr)) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return CKR_FUNCTION_FAILED;
    }
    modulus_bytes = attr->ulValueLen;

    rc = rsa_format_block(tokdata, in_data, in_data_len, clear,
                          modulus_bytes, PKCS_BT_2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_format_block failed\n");
        goto done;
    }
    // Do an RSA public encryption
    rc = os_specific_rsa_encrypt(clear, modulus_bytes, cipher, key_obj);

    if (rc == CKR_OK) {
        memcpy(out_data, cipher, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("os_specific_rsa_encrypt failed\n");
    }

done:
    OPENSSL_cleanse(clear, sizeof(clear));
    return rc;
}

CK_RV token_specific_rsa_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                 CK_ULONG in_data_len, CK_BYTE *out_data,
                                 CK_ULONG *out_data_len, OBJECT *key_obj)
{
    CK_RV rc;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;

    UNUSED(tokdata);

    modulus_bytes = in_data_len;

    rc = os_specific_rsa_decrypt(in_data, modulus_bytes, out, key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("os_specific_rsa_decrypt failed\n");
        goto done;
    }

    rc = rsa_parse_block(out, modulus_bytes, out_data, out_data_len, PKCS_BT_2);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_parse_block failed\n");
        goto done;
    }

    /*
     * For PKCS #1 v1.5 padding, out_data_len must be less than
     * modulus_bytes - 11.
     */
    if (*out_data_len > (modulus_bytes - 11)) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

done:
    OPENSSL_cleanse(out, sizeof(out));
    return rc;
}


CK_RV token_specific_rsa_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len,
                              OBJECT *key_obj)
{
    CK_BYTE data[MAX_RSA_KEYLEN], sig[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;

    UNUSED(tokdata);
    UNUSED(sess);

    /* format the data */
    if (!template_attribute_find(key_obj->template, CKA_MODULUS, &attr)) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return CKR_FUNCTION_FAILED;
    }
    modulus_bytes = attr->ulValueLen;
    rc = rsa_format_block(tokdata, in_data, in_data_len, data,
                          modulus_bytes, PKCS_BT_1);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_format_block failed\n");
        return rc;
    }

    /* signing is a private key operation --> decrypt */
    rc = os_specific_rsa_decrypt(data, modulus_bytes, sig, key_obj);
    if (rc == CKR_OK) {
        memcpy(out_data, sig, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("os_specific_rsa_decrypt failed\n");
    }

    return rc;
}

CK_RV token_specific_rsa_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                CK_BYTE *in_data, CK_ULONG in_data_len,
                                CK_BYTE *signature, CK_ULONG sig_len,
                                OBJECT *key_obj)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN], out_data[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes, out_data_len;
    CK_BBOOL flag;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(sig_len);

    out_data_len = MAX_RSA_KEYLEN;
    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return CKR_FUNCTION_FAILED;
    } else {
        modulus_bytes = attr->ulValueLen;
    }

    // verifying is a public key operation --> encrypt
    //
    rc = os_specific_rsa_encrypt(signature, modulus_bytes, out, key_obj);
    if (rc != CKR_OK) {
        /*
         * Return CKR_SIGNATURE_INVALID in case of CKR_ARGUMENTS_BAD
         * because we dont know why the RSA op failed and it may have
         * failed due to a tampered signature being greater or equal
         * to the modulus.
         */
        if (rc == CKR_ARGUMENTS_BAD) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rc = CKR_SIGNATURE_INVALID;
        } else {
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        }
        return rc;
    }

    rc = rsa_parse_block(out, modulus_bytes, out_data, &out_data_len,
                         PKCS_BT_1);
    if (rc == CKR_ENCRYPTED_DATA_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        return CKR_SIGNATURE_INVALID;
    } else if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    if (in_data_len != out_data_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        return CKR_SIGNATURE_INVALID;
    }

    if (CRYPTO_memcmp(in_data, out_data, out_data_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        return CKR_SIGNATURE_INVALID;
    }

    return rc;
}

CK_RV token_specific_rsa_verify_recover(STDLL_TokData_t *tokdata,
                                        CK_BYTE *signature, CK_ULONG sig_len,
                                        CK_BYTE *out_data,
                                        CK_ULONG *out_data_len,
                                        OBJECT *key_obj)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_BBOOL flag;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sig_len);

    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return CKR_FUNCTION_FAILED;
    } else {
        modulus_bytes = attr->ulValueLen;
    }

    // verifying is a public key operation --> encrypt
    //
    rc = os_specific_rsa_encrypt(signature, modulus_bytes, out, key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("os_specific_rsa_encrypt failed\n");
        return rc;
    }

    rc = rsa_parse_block(out, modulus_bytes, out_data, out_data_len, PKCS_BT_1);
    if (rc == CKR_ENCRYPTED_DATA_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        return CKR_SIGNATURE_INVALID;
    } else if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
    }

    return rc;
}

CK_RV token_specific_rsa_pss_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                                  SIGN_VERIFY_CONTEXT *ctx,
                                  CK_BYTE *in_data, CK_ULONG in_data_len,
                                  CK_BYTE *sig, CK_ULONG *sig_len)
{
    CK_RV rc;
    CK_ULONG modbytes;
    CK_BBOOL flag;
    CK_ATTRIBUTE *attr = NULL;
    OBJECT *key_obj = NULL;
    CK_BYTE *emdata = NULL;
    CK_RSA_PKCS_PSS_PARAMS *pssParms = NULL;

    UNUSED(sess);

    /* check the arguments */
    if (!in_data || !sig) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    if (!ctx) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    pssParms = (CK_RSA_PKCS_PSS_PARAMS *) ctx->mech.pParameter;

    /* get the key */
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        return rc;
    }

    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    } else {
        modbytes = attr->ulValueLen;
    }

    emdata = (CK_BYTE *) malloc(modbytes);
    if (emdata == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    rc = emsa_pss_encode(tokdata, pssParms, in_data, in_data_len, emdata,
                         &modbytes);
    if (rc != CKR_OK)
        goto done;

    /* signing is a private key operation --> decrypt  */
    rc = os_specific_rsa_decrypt(emdata, modbytes, sig, key_obj);
    if (rc == CKR_OK)
        *sig_len = modbytes;
    else
        TRACE_DEVEL("os_specific_rsa_decrypt failed\n");

done:
    if (emdata)
        free(emdata);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV token_specific_rsa_pss_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                    SIGN_VERIFY_CONTEXT *ctx,
                                    CK_BYTE *in_data, CK_ULONG in_data_len,
                                    CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_RV rc;
    CK_ULONG modbytes;
    OBJECT *key_obj = NULL;
    CK_BBOOL flag;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_RSA_PKCS_PSS_PARAMS *pssParms = NULL;

    UNUSED(sess);

    /* check the arguments */
    if (!in_data || !signature) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    if (!ctx) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    pssParms = (CK_RSA_PKCS_PSS_PARAMS *) ctx->mech.pParameter;

    /* get the key */
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        return rc;
    }

    /* verify is a public key operation ... encrypt */
    rc = os_specific_rsa_encrypt(signature, sig_len, out, key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("os_specific_rsa_encrypt failed\n");
        goto done;
    }

    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    } else {
        modbytes = attr->ulValueLen;
    }

    /* call the pss verify scheme */
    rc = emsa_pss_verify(tokdata, pssParms, in_data, in_data_len, out,
                         modbytes);

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV token_specific_rsa_x509_encrypt(STDLL_TokData_t *tokdata,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, OBJECT *key_obj)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE clear[MAX_RSA_KEYLEN], cipher[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_BBOOL flag;
    CK_RV rc;

    UNUSED(tokdata);

    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    modulus_bytes = attr->ulValueLen;

    // prepad with zeros
    //
    memset(clear, 0x0, modulus_bytes - in_data_len);
    memcpy(&clear[modulus_bytes - in_data_len], in_data, in_data_len);

    rc = os_specific_rsa_encrypt(clear, modulus_bytes, cipher, key_obj);
    if (rc == CKR_OK) {
        memcpy(out_data, cipher, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("os_specific_rsa_encrypt failed\n");
    }

done:
    OPENSSL_cleanse(clear, sizeof(clear));
    return rc;
}

CK_RV token_specific_rsa_x509_decrypt(STDLL_TokData_t *tokdata,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, OBJECT *key_obj)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_BBOOL flag;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(in_data_len);

    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    modulus_bytes = attr->ulValueLen;

    rc = os_specific_rsa_decrypt(in_data, modulus_bytes, out, key_obj);
    if (rc == CKR_OK) {
        memcpy(out_data, out, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("os_specific_rsa_decrypt failed\n");
    }

done:
    OPENSSL_cleanse(out, sizeof(out));
    return rc;
}


CK_RV token_specific_rsa_x509_sign(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                   CK_ULONG in_data_len, CK_BYTE *out_data,
                                   CK_ULONG *out_data_len, OBJECT *key_obj)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE data[MAX_RSA_KEYLEN], sig[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_BBOOL flag;
    CK_RV rc;

    UNUSED(tokdata);

    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return CKR_FUNCTION_FAILED;
    } else {
        modulus_bytes = attr->ulValueLen;
    }

    // prepad with zeros
    //

    memset(data, 0x0, modulus_bytes - in_data_len);
    memcpy(&data[modulus_bytes - in_data_len], in_data, in_data_len);

    rc = os_specific_rsa_decrypt(data, modulus_bytes, sig, key_obj);
    if (rc == CKR_OK) {
        memcpy(out_data, sig, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("os_specific_rsa_decrypt failed\n");
    }

    return rc;
}

CK_RV token_specific_rsa_x509_verify(STDLL_TokData_t *tokdata,
                                     CK_BYTE *in_data, CK_ULONG in_data_len,
                                     CK_BYTE *signature, CK_ULONG sig_len,
                                     OBJECT *key_obj)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_BBOOL flag;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sig_len);

    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return CKR_FUNCTION_FAILED;
    } else {
        modulus_bytes = attr->ulValueLen;
    }

    rc = os_specific_rsa_encrypt(signature, modulus_bytes, out, key_obj);
    if (rc == CKR_OK) {
        CK_ULONG pos1, pos2, len;
        // it should be noted that in_data_len is not necessarily
        // the same as the modulus length
        //
        for (pos1 = 0; pos1 < in_data_len; pos1++)
            if (in_data[pos1] != 0)
                break;

        for (pos2 = 0; pos2 < modulus_bytes; pos2++)
            if (out[pos2] != 0)
                break;

        // at this point, pos1 and pos2 point to the first non-zero
        // bytes in the input data and the decrypted signature
        // (the recovered data), respectively.
        if ((in_data_len - pos1) != (modulus_bytes - pos2)) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            return CKR_SIGNATURE_INVALID;
        }
        len = in_data_len - pos1;

        if (CRYPTO_memcmp(&in_data[pos1], &out[pos2], len) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            return CKR_SIGNATURE_INVALID;
        }
        return CKR_OK;
    } else {
        TRACE_DEVEL("os_specific_rsa_encrypt failed\n");
    }

    return rc;
}

CK_RV token_specific_rsa_x509_verify_recover(STDLL_TokData_t *tokdata,
                                             CK_BYTE *signature,
                                             CK_ULONG sig_len,
                                             CK_BYTE *out_data,
                                             CK_ULONG *out_data_len,
                                             OBJECT *key_obj)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE out[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_BBOOL flag;
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sig_len);

    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        return CKR_FUNCTION_FAILED;
    } else {
        modulus_bytes = attr->ulValueLen;
    }

    rc = os_specific_rsa_encrypt(signature, modulus_bytes, out, key_obj);
    if (rc == CKR_OK) {
        memcpy(out_data, out, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("os_specific_rsa_encrypt failed\n");
    }

    return rc;
}

CK_RV token_specific_rsa_oaep_encrypt(STDLL_TokData_t *tokdata,
                                      ENCR_DECR_CONTEXT *ctx,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE *hash,
                                      CK_ULONG hlen)
{
    CK_RV rc;
    CK_BYTE cipher[MAX_RSA_KEYLEN];
    CK_ULONG modulus_bytes;
    CK_BBOOL flag;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *em_data = NULL;
    OBJECT *key_obj = NULL;
    CK_RSA_PKCS_OAEP_PARAMS_PTR oaepParms = NULL;

    if (!in_data || !out_data || !hash) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    oaepParms = (CK_RSA_PKCS_OAEP_PARAMS_PTR) ctx->mech.pParameter;

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        return rc;
    }

    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    modulus_bytes = attr->ulValueLen;

    /* pkcs1v2.2, section 7.1.1 Step 2:
     * EME-OAEP encoding.
     */
    em_data = (CK_BYTE *) malloc(modulus_bytes * sizeof(CK_BYTE));
    if (em_data == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    rc = encode_eme_oaep(tokdata, in_data, in_data_len, em_data,
                         modulus_bytes, oaepParms->mgf, hash, hlen);
    if (rc != CKR_OK)
        goto done;

    rc = os_specific_rsa_encrypt(em_data, modulus_bytes, cipher, key_obj);
    if (rc == CKR_OK) {
        memcpy(out_data, cipher, modulus_bytes);
        *out_data_len = modulus_bytes;
    } else {
        TRACE_DEVEL("os_specific_rsa_encrypt failed\n");
    }

done:
    if (em_data) {
        OPENSSL_cleanse(em_data, modulus_bytes * sizeof(CK_BYTE));
        free(em_data);
    }

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV token_specific_rsa_oaep_decrypt(STDLL_TokData_t *tokdata,
                                      ENCR_DECR_CONTEXT *ctx,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE *hash,
                                      CK_ULONG hlen)
{
    CK_RV rc;
    CK_BYTE *decr_data = NULL;
    OBJECT *key_obj = NULL;
    CK_BBOOL flag;
    CK_ATTRIBUTE *attr = NULL;
    CK_RSA_PKCS_OAEP_PARAMS_PTR oaepParms = NULL;

    if (!in_data || !out_data || !hash) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    oaepParms = (CK_RSA_PKCS_OAEP_PARAMS_PTR) ctx->mech.pParameter;

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_DEVEL("object_mgr_find_in_map1 failed\n");
        return rc;
    }

    flag = template_attribute_find(key_obj->template, CKA_MODULUS, &attr);
    if (flag == FALSE) {
        TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    *out_data_len = attr->ulValueLen;

    decr_data = (CK_BYTE *) malloc(in_data_len);
    if (decr_data == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    rc = os_specific_rsa_decrypt(in_data, in_data_len, decr_data, key_obj);
    if (rc != CKR_OK)
        goto error;

    /* pkcs1v2.2, section 7.1.2 Step 2:
     * EME-OAEP decoding.
     */
    rc = decode_eme_oaep(tokdata, decr_data, in_data_len, out_data,
                         out_data_len, oaepParms->mgf, hash, hlen);

error:
    if (decr_data) {
        OPENSSL_cleanse(decr_data, in_data_len);
        free(decr_data);
    }

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

#ifndef NOAES

CK_RV token_specific_aes_key_gen(STDLL_TokData_t *tokdata, CK_BYTE *key,
                                 CK_ULONG len, CK_ULONG keysize)
{
    UNUSED(keysize);

    return rng_generate(tokdata, key, len);
}

CK_RV token_specific_aes_ecb(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE encrypt)
{
    AES_KEY ssl_aes_key;
    unsigned int i;
    CK_ATTRIBUTE *attr = NULL;
    /* There's a previous check that in_data_len % AES_BLOCK_SIZE == 0,
     * so this is fine */
    CK_ULONG loops = (CK_ULONG) (in_data_len / AES_BLOCK_SIZE);

    UNUSED(tokdata);

    memset(&ssl_aes_key, 0, sizeof(AES_KEY));

    // get key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return CKR_FUNCTION_FAILED;
    }
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

CK_RV token_specific_aes_cbc(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    AES_KEY ssl_aes_key;
    CK_ATTRIBUTE *attr = NULL;

    UNUSED(tokdata);

    memset(&ssl_aes_key, 0, sizeof(AES_KEY));

    // get key value
    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return CKR_FUNCTION_FAILED;
    }
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
#endif

/* Begin code contributed by Corrent corp. */
#ifndef NODH
// This computes DH shared secret, where:
//     Output: z is computed shared secret
//     Input:  y is other party's public key
//             x is private key
//             p is prime
// All length's are in number of bytes. All data comes in as Big Endian.
CK_RV token_specific_dh_pkcs_derive(STDLL_TokData_t *tokdata,
                                    CK_BYTE *z,
                                    CK_ULONG *z_len,
                                    CK_BYTE *y,
                                    CK_ULONG y_len,
                                    CK_BYTE *x,
                                    CK_ULONG x_len, CK_BYTE *p, CK_ULONG p_len)
{
    CK_RV rc;
    BIGNUM *bn_z, *bn_y, *bn_x, *bn_p;
    BN_CTX *ctx;

    UNUSED(tokdata);

    //  Create and Init the BIGNUM structures.
    bn_y = BN_new();
    bn_x = BN_new();
    bn_p = BN_new();
    bn_z = BN_new();

    if (bn_z == NULL || bn_p == NULL || bn_x == NULL || bn_y == NULL) {
        if (bn_y)
            BN_free(bn_y);
        if (bn_x)
            BN_free(bn_x);
        if (bn_p)
            BN_free(bn_p);
        if (bn_z)
            BN_free(bn_z);
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    // Initialize context
    ctx = BN_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    // Add data into these new BN structures

    BN_bin2bn((unsigned char *) y, y_len, bn_y);
    BN_bin2bn((unsigned char *) x, x_len, bn_x);
    BN_bin2bn((unsigned char *) p, p_len, bn_p);

    rc = BN_mod_exp(bn_z, bn_y, bn_x, bn_p, ctx);
    if (rc == 0) {
        BN_free(bn_z);
        BN_free(bn_y);
        BN_free(bn_x);
        BN_free(bn_p);
        BN_CTX_free(ctx);

        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    *z_len = BN_num_bytes(bn_z);
    BN_bn2bin(bn_z, z);

    BN_free(bn_z);
    BN_free(bn_y);
    BN_free(bn_x);
    BN_free(bn_p);
    BN_CTX_free(ctx);

    return CKR_OK;
}                               /* end token_specific_dh_pkcs_derive() */

// This computes DH key pair, where:
//     Output: priv_tmpl is generated private key
//             pub_tmpl is computed public key
//     Input:  pub_tmpl is public key (prime and generator)
// All length's are in number of bytes. All data comes in as Big Endian.
CK_RV token_specific_dh_pkcs_key_pair_gen(STDLL_TokData_t *tokdata,
                                          TEMPLATE *publ_tmpl,
                                          TEMPLATE *priv_tmpl)
{
    CK_BBOOL rc;
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *temp_attr = NULL;
    CK_ATTRIBUTE *value_bits_attr = NULL;
    CK_BYTE *temp_byte;
    CK_ULONG temp_bn_len;
    DH *dh;
    BIGNUM *bn_p;
    BIGNUM *bn_g;
    const BIGNUM *temp_bn;

    UNUSED(tokdata);

    rc = template_attribute_find(publ_tmpl, CKA_PRIME, &prime_attr);
    rc &= template_attribute_find(publ_tmpl, CKA_BASE, &base_attr);

    if (rc == FALSE) {
        TRACE_ERROR("Could not find CKA_PRIME or CKA_BASE for the key\n");
        return CKR_FUNCTION_FAILED;
    }

    if ((prime_attr->ulValueLen > 256) || (prime_attr->ulValueLen < 64)) {
        TRACE_ERROR("CKA_PRIME attribute value is invalid.\n");
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }

    dh = DH_new();
    if (dh == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    // Create and init BIGNUM structs to stick in the DH struct
    bn_p = BN_new();
    bn_g = BN_new();
    if (bn_g == NULL || bn_p == NULL) {
        if (bn_g)
            BN_free(bn_g);
        if (bn_p)
            BN_free(bn_p);
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }
    // Convert from strings to BIGNUMs and stick them in the DH struct
    BN_bin2bn((unsigned char *) prime_attr->pValue, prime_attr->ulValueLen,
              bn_p);
    BN_bin2bn((unsigned char *) base_attr->pValue, base_attr->ulValueLen, bn_g);
#ifdef OLDER_OPENSSL
    dh->p = bn_p;
    dh->g = bn_g;
#else
    DH_set0_pqg(dh, bn_p, NULL, bn_g);
#endif

    // Generate the DH Key
    if (!DH_generate_key(dh)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    // Extract the public and private key components from the DH struct,
    // and insert them in the publ_tmpl and priv_tmpl

    //
    // pub_key
    //
    //temp_bn = BN_new();
#ifdef OLDER_OPENSSL
    temp_bn = dh->pub_key;
#else
    DH_get0_key(dh, &temp_bn, NULL);
#endif
    temp_bn_len = BN_num_bytes(temp_bn);
    temp_byte = malloc(temp_bn_len);
    temp_bn_len = BN_bn2bin(temp_bn, temp_byte);
    // in bytes
    rc = build_attribute(CKA_VALUE, temp_byte, temp_bn_len, &temp_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        return CKR_FUNCTION_FAILED;
    }
    template_update_attribute(publ_tmpl, temp_attr);
    free(temp_byte);

    //
    // priv_key
    //
    //temp_bn = BN_new();
#ifdef OLDER_OPENSSL
    temp_bn = dh->priv_key;
#else
    DH_get0_key(dh, NULL, &temp_bn);
#endif
    temp_bn_len = BN_num_bytes(temp_bn);
    temp_byte = malloc(temp_bn_len);
    temp_bn_len = BN_bn2bin(temp_bn, temp_byte);
    // in bytes
    rc = build_attribute(CKA_VALUE, temp_byte, temp_bn_len, &temp_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        return CKR_FUNCTION_FAILED;
    }
    template_update_attribute(priv_tmpl, temp_attr);
    free(temp_byte);

    // Update CKA_VALUE_BITS attribute in the private key
    value_bits_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG));
    value_bits_attr->type = CKA_VALUE_BITS;
    value_bits_attr->ulValueLen = sizeof(CK_ULONG);
    value_bits_attr->pValue =
        (CK_BYTE *) value_bits_attr + sizeof(CK_ATTRIBUTE);
    *(CK_ULONG *) value_bits_attr->pValue = 8 * temp_bn_len;
    template_update_attribute(priv_tmpl, value_bits_attr);

    // Add prime and base to the private key template
    rc = build_attribute(CKA_PRIME,
                         (unsigned char *) prime_attr->pValue,
                         prime_attr->ulValueLen, &temp_attr);  // in bytes
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        return CKR_FUNCTION_FAILED;
    }
    template_update_attribute(priv_tmpl, temp_attr);

    rc = build_attribute(CKA_BASE,
                         (unsigned char *) base_attr->pValue,
                         base_attr->ulValueLen, &temp_attr);     // in bytes
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        return CKR_FUNCTION_FAILED;
    }
    template_update_attribute(priv_tmpl, temp_attr);

    // Cleanup DH key
    DH_free(dh);

    return CKR_OK;
}                               /* end token_specific_dh_key_pair_gen() */
#endif
/* End code contributed by Corrent corp. */

CK_RV token_specific_get_mechanism_list(STDLL_TokData_t *tokdata,
                                        CK_MECHANISM_TYPE_PTR pMechanismList,
                                        CK_ULONG_PTR pulCount)
{
    return ock_generic_get_mechanism_list(tokdata, pMechanismList, pulCount);
}

CK_RV token_specific_get_mechanism_info(STDLL_TokData_t *tokdata,
                                        CK_MECHANISM_TYPE type,
                                        CK_MECHANISM_INFO_PTR pInfo)
{
    return ock_generic_get_mechanism_info(tokdata, type, pInfo);
}

CK_RV token_specific_sha_init(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                              CK_MECHANISM *mech)
{
    int rc;
    CK_ULONG len;

    UNUSED(tokdata);

    switch (mech->mechanism) {
    case CKM_SHA_1:
        len = sizeof(SHA_CTX);
        break;
    case CKM_SHA224:
        len = sizeof(SHA256_CTX);
        break;
    case CKM_SHA256:
        len = sizeof(SHA256_CTX);
        break;
    case CKM_SHA384:
        len = sizeof(SHA512_CTX);
        break;
    case CKM_SHA512:
    case CKM_SHA512_224:
    case CKM_SHA512_256:
        len = sizeof(SHA512_CTX);
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    ctx->context_len = len;
    ctx->context = (CK_BYTE *) malloc(len);
    if (ctx->context == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    switch (mech->mechanism) {
    case CKM_SHA_1:
        rc = SHA1_Init((SHA_CTX *)ctx->context);
        break;
    case CKM_SHA224:
        rc = SHA224_Init((SHA256_CTX *)ctx->context);
        break;
    case CKM_SHA256:
        rc = SHA256_Init((SHA256_CTX *)ctx->context);
        break;
    case CKM_SHA384:
        rc = SHA384_Init((SHA512_CTX *)ctx->context);
        break;
    case CKM_SHA512:
    case CKM_SHA512_224:
    case CKM_SHA512_256:
        rc = SHA512_Init((SHA512_CTX *)ctx->context);
        break;
    default:	/* cannot happen */
        rc = CKR_MECHANISM_INVALID;
    }

    if (!rc) {
        free(ctx->context);
        ctx->context = NULL;
        ctx->context_len = 0;
        return CKR_FUNCTION_FAILED;
    }

    switch (mech->mechanism) {
    case CKM_SHA512_224:
        {
            SHA512_CTX *c = (SHA512_CTX *)ctx->context;

            /* SHA-512/224 uses a distinct initial hash value */
            c->h[0] = 0x8c3d37c819544da2ULL;
            c->h[1] = 0x73e1996689dcd4d6ULL;
            c->h[2] = 0x1dfab7ae32ff9c82ULL;
            c->h[3] = 0x679dd514582f9fcfULL;
            c->h[4] = 0x0f6d2b697bd44da8ULL;
            c->h[5] = 0x77e36f7304c48942ULL;
            c->h[6] = 0x3f9d85a86a1d36c8ULL;
            c->h[7] = 0x1112e6ad91d692a1ULL;
            break;
        }
    case CKM_SHA512_256:
        {
            SHA512_CTX *c = (SHA512_CTX *)ctx->context;

            /* SHA-512/256 uses a distinct initial hash value */
            c->h[0] = 0x22312194fc2bf72cULL;
            c->h[1] = 0x9f555fa3c84c64c2ULL;
            c->h[2] = 0x2393b86b6f53b151ULL;
            c->h[3] = 0x963877195940eabdULL;
            c->h[4] = 0x96283ee2a88effe3ULL;
            c->h[5] = 0xbe5e1e2553863992ULL;
            c->h[6] = 0x2b0199fc2c85b8aaULL;
            c->h[7] = 0x0eb72ddc81c52ca2ULL;
            break;
        }
    }

    return CKR_OK;
}

CK_RV token_specific_sha(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    unsigned int hlen;
    CK_BYTE temp_out_data[MAX_SHA_HASH_SIZE];
    CK_BYTE *orig_out_data = out_data;

    UNUSED(tokdata);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!in_data || !out_data)
        return CKR_ARGUMENTS_BAD;

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        hlen = SHA1_HASH_SIZE;
        break;
    case CKM_SHA224:
        hlen = SHA224_HASH_SIZE;
        break;
    case CKM_SHA256:
        hlen = SHA256_HASH_SIZE;
        break;
    case CKM_SHA384:
        hlen = SHA384_HASH_SIZE;
        break;
    case CKM_SHA512:
        hlen = SHA512_HASH_SIZE;
        break;
    case CKM_SHA512_224:
        hlen = SHA224_HASH_SIZE;
        break;
    case CKM_SHA512_256:
        hlen = SHA256_HASH_SIZE;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (*out_data_len < hlen)
        return CKR_BUFFER_TOO_SMALL;

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
	if (!SHA1_Update((SHA_CTX *)ctx->context, in_data, in_data_len)
            || !SHA1_Final(out_data, (SHA_CTX *)ctx->context))
            goto error;
        break;
    case CKM_SHA224:
	if (!SHA224_Update((SHA256_CTX *)ctx->context, in_data, in_data_len)
            || !SHA224_Final(out_data, (SHA256_CTX *)ctx->context))
            goto error;
        break;
    case CKM_SHA256:
	if (!SHA256_Update((SHA256_CTX *)ctx->context, in_data, in_data_len)
            || !SHA256_Final(out_data, (SHA256_CTX *)ctx->context))
            goto error;
        break;
    case CKM_SHA384:
	if (!SHA384_Update((SHA512_CTX *)ctx->context, in_data, in_data_len)
            || !SHA384_Final(out_data, (SHA512_CTX *)ctx->context))
            goto error;
        break;
    case CKM_SHA512:
	if (!SHA512_Update((SHA512_CTX *)ctx->context, in_data, in_data_len)
            || !SHA512_Final(out_data, (SHA512_CTX *)ctx->context))
            goto error;
        break;
    case CKM_SHA512_224:
    case CKM_SHA512_256:
        out_data = temp_out_data;

	if (!SHA512_Update((SHA512_CTX *)ctx->context, in_data, in_data_len)
            || !SHA512_Final(out_data, (SHA512_CTX *)ctx->context))
            goto error;

        memcpy(orig_out_data, temp_out_data, hlen);
        OPENSSL_cleanse(temp_out_data, sizeof(temp_out_data));
        break;
    }

    *out_data_len = hlen;
    return CKR_OK;

error:
    free(ctx->context);
    ctx->context = NULL;
    ctx->context_len = 0;

    return CKR_FUNCTION_FAILED;
}

CK_RV token_specific_sha_update(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                CK_BYTE *in_data, CK_ULONG in_data_len)
{
    int rc;

    UNUSED(tokdata);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!in_data)
        return CKR_ARGUMENTS_BAD;

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        rc = SHA1_Update((SHA_CTX *) ctx->context, in_data, in_data_len);
        break;
    case CKM_SHA224:
        rc = SHA224_Update((SHA256_CTX*) ctx->context, in_data, in_data_len);
        break;
    case CKM_SHA256:
        rc = SHA256_Update((SHA256_CTX *) ctx->context, in_data, in_data_len);
        break;
    case CKM_SHA384:
        rc = SHA384_Update((SHA512_CTX *) ctx->context, in_data, in_data_len);
        break;
    case CKM_SHA512:
    case CKM_SHA512_224:
    case CKM_SHA512_256:
        rc = SHA512_Update((SHA512_CTX *) ctx->context, in_data, in_data_len);
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (!rc) {
        free(ctx->context);
        ctx->context = NULL;
        ctx->context_len = 0;
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV token_specific_sha_final(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                               CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    unsigned int hlen;
    CK_BYTE temp_out_data[MAX_SHA_HASH_SIZE];
    CK_BYTE *orig_out_data = out_data;

    UNUSED(tokdata);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!out_data)
        return CKR_ARGUMENTS_BAD;

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
        hlen = SHA1_HASH_SIZE;
        break;
    case CKM_SHA224:
        hlen = SHA224_HASH_SIZE;
        break;
    case CKM_SHA256:
        hlen = SHA256_HASH_SIZE;
        break;
    case CKM_SHA384:
        hlen = SHA384_HASH_SIZE;
        break;
    case CKM_SHA512:
        hlen = SHA512_HASH_SIZE;
        break;
    case CKM_SHA512_224:
        hlen = SHA224_HASH_SIZE;
        break;
    case CKM_SHA512_256:
        hlen = SHA256_HASH_SIZE;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    if (*out_data_len < hlen)
        return CKR_BUFFER_TOO_SMALL;

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
	if (!SHA1_Final(out_data, (SHA_CTX *)ctx->context))
            goto error;
        break;
    case CKM_SHA224:
	if (!SHA224_Final(out_data, (SHA256_CTX *)ctx->context))
            goto error;
        break;
    case CKM_SHA256:
	if (!SHA256_Final(out_data, (SHA256_CTX *)ctx->context))
            goto error;
        break;
    case CKM_SHA384:
	if (!SHA384_Final(out_data, (SHA512_CTX *)ctx->context))
            goto error;
        break;
    case CKM_SHA512:
	if (!SHA512_Final(out_data, (SHA512_CTX *)ctx->context))
            goto error;
        break;
    case CKM_SHA512_224:
    case CKM_SHA512_256:
        out_data = temp_out_data;

	if (!SHA512_Final(out_data, (SHA512_CTX *)ctx->context))
            goto error;

        memcpy(orig_out_data, temp_out_data, hlen);
        OPENSSL_cleanse(temp_out_data, sizeof(temp_out_data));
        break;
    }

    *out_data_len = hlen;
    return CKR_OK;

error:
    free(ctx->context);
    ctx->context = NULL;
    ctx->context_len = 0;
    return CKR_FUNCTION_FAILED;
}

static CK_RV softtok_hmac_init(STDLL_TokData_t *tokdata,
                               SIGN_VERIFY_CONTEXT *ctx, CK_MECHANISM_PTR mech,
                               CK_OBJECT_HANDLE Hkey)
{
    int rc;
    OBJECT *key = NULL;
    CK_ATTRIBUTE *attr = NULL;
    EVP_MD_CTX *mdctx = NULL;
    EVP_PKEY *pkey = NULL;

    rc = object_mgr_find_in_map1(tokdata, Hkey, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, NULL, attr->pValue,
                                attr->ulValueLen);
    if (pkey == NULL) {
        TRACE_ERROR("EVP_PKEY_new_mac_key() failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    mdctx = EVP_MD_CTX_create();
    if (mdctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    switch (mech->mechanism) {
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA_1_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha1(), NULL, pkey);
        break;
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA224_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha224(), NULL, pkey);
        break;
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA256_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, pkey);
        break;
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA384_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha384(), NULL, pkey);
        break;
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha512(), NULL, pkey);
        break;
    default:
        EVP_MD_CTX_destroy(mdctx);
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    if (rc != 1) {
        EVP_MD_CTX_destroy(mdctx);
        ctx->context = NULL;
        TRACE_ERROR("EVP_DigestSignInit failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    } else {
        ctx->context = (CK_BYTE *) mdctx;
    }

    rc = CKR_OK;
done:
if (pkey != NULL)
        EVP_PKEY_free(pkey);

    object_put(tokdata, key, TRUE);
    key = NULL;
    return rc;
}

CK_RV token_specific_hmac_sign_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                    CK_MECHANISM *mech, CK_OBJECT_HANDLE Hkey)
{
    return softtok_hmac_init(tokdata, &sess->sign_ctx, mech, Hkey);
}

CK_RV token_specific_hmac_verify_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                      CK_MECHANISM *mech,
                                      CK_OBJECT_HANDLE Hkey)
{
    return softtok_hmac_init(tokdata, &sess->verify_ctx, mech, Hkey);
}

static CK_RV softtok_hmac(SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                          CK_ULONG in_data_len, CK_BYTE *signature,
                          CK_ULONG *sig_len, CK_BBOOL sign)
{
    int rc;
    size_t mac_len, len;
    unsigned char mac[MAX_SHA_HASH_SIZE];
    EVP_MD_CTX *mdctx = NULL;
    CK_RV rv = CKR_OK;
    CK_BBOOL general = FALSE;

    if (!ctx || !ctx->context) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (sign && !sig_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1_HMAC_GENERAL:
        general = TRUE;
        /* fallthrough */
    case CKM_SHA_1_HMAC:
        mac_len = SHA1_HASH_SIZE;
        break;
    case CKM_SHA224_HMAC_GENERAL:
        general = TRUE;
        /* fallthrough */
    case CKM_SHA224_HMAC:
        mac_len = SHA224_HASH_SIZE;
        break;
    case CKM_SHA256_HMAC_GENERAL:
        general = TRUE;
        /* fallthrough */
    case CKM_SHA256_HMAC:
        mac_len = SHA256_HASH_SIZE;
        break;
    case CKM_SHA384_HMAC_GENERAL:
        general = TRUE;
        /* fallthrough */
    case CKM_SHA384_HMAC:
        mac_len = SHA384_HASH_SIZE;
        break;
    case CKM_SHA512_HMAC_GENERAL:
        general = TRUE;
        /* fallthrough */
    case CKM_SHA512_HMAC:
        mac_len = SHA512_HASH_SIZE;
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    mdctx = (EVP_MD_CTX *) ctx->context;

    rc = EVP_DigestSignUpdate(mdctx, in_data, in_data_len);
    if (rc != 1) {
        TRACE_ERROR("EVP_DigestSignUpdate failed.\n");
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = EVP_DigestSignFinal(mdctx, mac, &mac_len);
    if (rc != 1) {
        TRACE_ERROR("EVP_DigestSignFinal failed.\n");
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (sign) {
        if (general)
            *sig_len = *(CK_ULONG *) ctx->mech.pParameter;
        else
            *sig_len = mac_len;

        memcpy(signature, mac, *sig_len);

    } else {
        if (general)
            len = *(CK_ULONG *) ctx->mech.pParameter;
        else
            len = mac_len;

        if (CRYPTO_memcmp(signature, mac, len) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rv = CKR_SIGNATURE_INVALID;
        }
    }
done:
    EVP_MD_CTX_destroy(mdctx);
    ctx->context = NULL;

    return rv;
}

CK_RV token_specific_hmac_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *signature, CK_ULONG *sig_len)
{
    UNUSED(tokdata);

    return softtok_hmac(&sess->sign_ctx, in_data, in_data_len, signature,
                        sig_len, TRUE);
}

CK_RV token_specific_hmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                 CK_BYTE *in_data, CK_ULONG in_data_len,
                                 CK_BYTE *signature, CK_ULONG sig_len)
{
    UNUSED(tokdata);

    return softtok_hmac(&sess->verify_ctx, in_data, in_data_len, signature,
                        &sig_len, FALSE);
}

static CK_RV softtok_hmac_update(SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                                 CK_ULONG in_data_len, CK_BBOOL sign)
{
    int rc;
    EVP_MD_CTX *mdctx = NULL;
    CK_RV rv = CKR_OK;

    UNUSED(sign);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    mdctx = (EVP_MD_CTX *) ctx->context;

    rc = EVP_DigestSignUpdate(mdctx, in_data, in_data_len);
    if (rc != 1) {
        TRACE_ERROR("EVP_DigestSignUpdate failed.\n");
        rv = CKR_FUNCTION_FAILED;
    } else {
        ctx->context = (CK_BYTE *) mdctx;
        return CKR_OK;
    }

    EVP_MD_CTX_destroy(mdctx);
    ctx->context = NULL;
    return rv;
}

CK_RV token_specific_hmac_sign_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                      CK_BYTE *in_data, CK_ULONG in_data_len)
{
    UNUSED(tokdata);

    return softtok_hmac_update(&sess->sign_ctx, in_data, in_data_len, TRUE);
}

CK_RV token_specific_hmac_verify_update(STDLL_TokData_t *tokdata,
                                        SESSION *sess, CK_BYTE *in_data,
                                        CK_ULONG in_data_len)
{
    UNUSED(tokdata);

    return softtok_hmac_update(&sess->verify_ctx, in_data, in_data_len, FALSE);
}

static CK_RV softtok_hmac_final(SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *signature,
                                CK_ULONG *sig_len, CK_BBOOL sign)
{
    int rc;
    size_t mac_len, len;
    unsigned char mac[MAX_SHA_HASH_SIZE];
    EVP_MD_CTX *mdctx = NULL;
    CK_RV rv = CKR_OK;
    CK_BBOOL general = FALSE;

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (sign && !sig_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1_HMAC_GENERAL:
        general = TRUE;
        /* fallthrough */
    case CKM_SHA_1_HMAC:
        mac_len = SHA1_HASH_SIZE;
        break;
    case CKM_SHA224_HMAC_GENERAL:
        general = TRUE;
        /* fallthrough */
    case CKM_SHA224_HMAC:
        mac_len = SHA224_HASH_SIZE;
        break;
    case CKM_SHA256_HMAC_GENERAL:
        general = TRUE;
        /* fallthrough */
    case CKM_SHA256_HMAC:
        mac_len = SHA256_HASH_SIZE;
        break;
    case CKM_SHA384_HMAC_GENERAL:
        general = TRUE;
        /* fallthrough */
    case CKM_SHA384_HMAC:
        mac_len = SHA384_HASH_SIZE;
        break;
    case CKM_SHA512_HMAC_GENERAL:
        general = TRUE;
        /* fallthrough */
    case CKM_SHA512_HMAC:
        mac_len = SHA512_HASH_SIZE;
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    if (signature == NULL) {
        if (sign) {
            if (general)
                *sig_len = *(CK_ULONG *) ctx->mech.pParameter;
            else
                *sig_len = (CK_ULONG) mac_len;
        }
        return CKR_OK;
    }

    mdctx = (EVP_MD_CTX *) ctx->context;

    rc = EVP_DigestSignFinal(mdctx, mac, &mac_len);
    if (rc != 1) {
        TRACE_ERROR("EVP_DigestSignFinal failed.\n");
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (sign) {
        if (general)
            *sig_len = *(CK_ULONG *) ctx->mech.pParameter;
        else
            *sig_len = mac_len;

        memcpy(signature, mac, *sig_len);

    } else {
        if (general)
            len = *(CK_ULONG *) ctx->mech.pParameter;
        else
            len = mac_len;

        if (CRYPTO_memcmp(signature, mac, len) != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
            rv = CKR_SIGNATURE_INVALID;
        }
    }
done:
    EVP_MD_CTX_destroy(mdctx);
    ctx->context = NULL;
    return rv;
}

CK_RV token_specific_hmac_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                     CK_BYTE *signature, CK_ULONG *sig_len)
{
    UNUSED(tokdata);

    return softtok_hmac_final(&sess->sign_ctx, signature, sig_len, TRUE);
}

CK_RV token_specific_hmac_verify_final(STDLL_TokData_t *tokdata,
                                       SESSION *sess, CK_BYTE *signature,
                                       CK_ULONG sig_len)
{
    UNUSED(tokdata);

    return softtok_hmac_final(&sess->verify_ctx, signature, &sig_len, FALSE);
}

CK_RV token_specific_generic_secret_key_gen(STDLL_TokData_t *tokdata,
                                            TEMPLATE *tmpl)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE *gkey = NULL;
    CK_RV rc = CKR_OK;
    CK_BYTE secret_key[MAX_GENERIC_KEY_SIZE];
    CK_ULONG key_length = 0;
    CK_ULONG key_length_in_bits = 0;

    rc = template_attribute_find(tmpl, CKA_VALUE_LEN, &attr);
    if (rc == FALSE) {
        TRACE_ERROR("CKA_VALUE_LEN missing in (HMAC) key template\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    //app specified key length in bytes
    key_length = *(CK_ULONG *) attr->pValue;
    key_length_in_bits = key_length * 8;

    /* After looking at fips cavs test vectors for HMAC ops,
     * it was decided that the key length should fall between
     * 80 and 2048 bits inclusive. openssl does not explicitly
     * specify limits to key sizes for secret keys
     */
    if ((key_length_in_bits < 80) || (key_length_in_bits > 2048)) {
        TRACE_ERROR("Generic secret key size of %lu bits not within"
                    " required range of 80-2048 bits\n", key_length_in_bits);
        return CKR_KEY_SIZE_RANGE;
    }

    rc = rng_generate(tokdata, secret_key, key_length);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Generic secret key generation failed.\n");
        return rc;
    }

    rc = build_attribute(CKA_VALUE, secret_key, key_length, &gkey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute(CKA_VALUE) failed\n");
        return rc;
    }

    rc = template_update_attribute(tmpl, gkey);
    if (rc != CKR_OK)
        TRACE_DEVEL("template_update_attribute(CKA_VALUE) failed.\n");

    return rc;
}

CK_RV token_specific_tdes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                               CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                               CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{
    int rc;
    CK_RV rv = CKR_OK;
    CK_ATTRIBUTE *attr = NULL;
    CK_KEY_TYPE keytype;
    CMAC_CTX *cmac_ctx;
    const EVP_CIPHER *cipher;
    size_t maclen;

    UNUSED(tokdata);

    if (first) {
        // get the key type
        rc = template_attribute_find(key->template, CKA_KEY_TYPE, &attr);
        if (rc == FALSE) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            return CKR_FUNCTION_FAILED;
        }
        keytype = *(CK_KEY_TYPE *) attr->pValue;

        // get the key value
        if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
            TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
            return CKR_FUNCTION_FAILED;
        }
        switch (keytype) {
        case CKK_DES2:
            cipher = EVP_des_ede_cbc();
            break;
        case CKK_DES3:
            cipher = EVP_des_ede3_cbc();
            break;
        default:
            TRACE_ERROR("Invalid key type: %lu\n", keytype);
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        if (cipher == NULL) {
            TRACE_ERROR("Failed to allocate cipher\n");
            return CKR_HOST_MEMORY;
        }

        cmac_ctx = CMAC_CTX_new();
        if (cmac_ctx == NULL) {
            TRACE_ERROR("Failed to allocate CMAC context\n");
            return CKR_HOST_MEMORY;
        }

        rc = CMAC_Init(cmac_ctx, attr->pValue, attr->ulValueLen, cipher, NULL);
        if (rc != 1) {
            TRACE_ERROR("CMAC_Init failed\n");
            CMAC_CTX_free(cmac_ctx);
            return CKR_FUNCTION_FAILED;
        }

        *ctx = cmac_ctx;
    }

    cmac_ctx = (CMAC_CTX *)*ctx;

    rc = CMAC_Update(cmac_ctx, message, message_len);
    if (rc != 1) {
        TRACE_ERROR("CMAC_Update failed\n");
        rv =  CKR_FUNCTION_FAILED;
    }

    if (last) {
        maclen = AES_BLOCK_SIZE;
        rc = CMAC_Final(cmac_ctx, mac, &maclen);
        if (rc != 1) {
            TRACE_ERROR("CMAC_Final failed\n");
            rv = CKR_FUNCTION_FAILED;
        }
    }

    if (last || (first && rv != CKR_OK)) {
        CMAC_CTX_free(cmac_ctx);
        *ctx = NULL;
    }

    return rv;
}


CK_RV token_specific_aes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                              CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                              CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{
    int rc;
    CK_RV rv = CKR_OK;
    CK_ATTRIBUTE *attr = NULL;
    CMAC_CTX *cmac_ctx;
    const EVP_CIPHER *cipher;
    size_t maclen;

    UNUSED(tokdata);

    if (first) {
        if (template_attribute_find(key->template, CKA_VALUE, &attr) == FALSE) {
            TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
            return CKR_FUNCTION_FAILED;
        }

        switch (attr->ulValueLen * 8) {
        case 128:
            cipher = EVP_aes_128_cbc();
            break;
        case 192:
            cipher = EVP_aes_192_cbc();
            break;
        case 256:
            cipher = EVP_aes_256_cbc();
            break;
        default:
            TRACE_ERROR("Invalid key size: %lu\n", attr->ulValueLen);
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        if (cipher == NULL) {
            TRACE_ERROR("Failed to allocate cipher\n");
            return CKR_HOST_MEMORY;
        }

        cmac_ctx = CMAC_CTX_new();
        if (cmac_ctx == NULL) {
            TRACE_ERROR("Failed to allocate CMAC context\n");
            return CKR_HOST_MEMORY;
        }

        rc = CMAC_Init(cmac_ctx, attr->pValue, attr->ulValueLen, cipher, NULL);
        if (rc != 1) {
            TRACE_ERROR("CMAC_Init failed\n");
            CMAC_CTX_free(cmac_ctx);
            return CKR_FUNCTION_FAILED;
        }

        *ctx = cmac_ctx;
    }

    cmac_ctx = (CMAC_CTX *)*ctx;

    rc = CMAC_Update(cmac_ctx, message, message_len);
    if (rc != 1) {
        TRACE_ERROR("CMAC_Update failed\n");
        rv =  CKR_FUNCTION_FAILED;
    }

    if (last) {
        maclen = AES_BLOCK_SIZE;
        rc = CMAC_Final(cmac_ctx, mac, &maclen);
        if (rc != 1) {
            TRACE_ERROR("CMAC_Final failed\n");
            rv = CKR_FUNCTION_FAILED;
        }
    }

    if (last || (first && rv != CKR_OK)) {
        CMAC_CTX_free(cmac_ctx);
        *ctx = NULL;
    }

    return rv;
}
