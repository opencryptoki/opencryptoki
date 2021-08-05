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

#include <openssl/opensslv.h>

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
#include <openssl/dh.h>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
#include <openssl/cmac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>
#include <openssl/err.h>
#if OPENSSL_VERSION_PREREQ(3, 0)
#include <openssl/core_names.h>
#include <openssl/param_build.h>
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
#if !OPENSSL_VERSION_PREREQ(3, 0)
    /* OpenSSL 3.0 supports single-DES only with the legacy provider */
    {CKM_DES_KEY_GEN, {8, 8, CKF_GENERATE}},
#endif
    {CKM_DES3_KEY_GEN, {24, 24, CKF_GENERATE}},
#if !(NOCDMF)
    {CKM_CDMF_KEY_GEN, {0, 0, CKF_GENERATE}},
#endif
    {CKM_RSA_PKCS,
     {512, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP | CKF_SIGN |
      CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER}},
    {CKM_SHA1_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA224_RSA_PKCS, {512, 4096, CKF_SIGN|CKF_VERIFY}},
    {CKM_SHA256_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA1_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA224_RSA_PKCS_PSS, {512, 4096, CKF_SIGN|CKF_VERIFY}},
    {CKM_SHA256_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_RSA_PKCS_PSS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
#if !(NOX509)
    {CKM_RSA_X_509,
     {512, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP | CKF_SIGN |
      CKF_VERIFY | CKF_SIGN_RECOVER | CKF_VERIFY_RECOVER}},
#endif
    {CKM_RSA_PKCS_OAEP,
     {512, 4096, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
#if !(NOMD2)
    {CKM_MD2_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
#endif
#if !(NOMD5)
    {CKM_MD5_RSA_PKCS, {512, 4096, CKF_SIGN | CKF_VERIFY}},
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
#if !OPENSSL_VERSION_PREREQ(3, 0)
    /* OpenSSL 3.0 supports single-DES only with the legacy provider */
    {CKM_DES_ECB, {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CBC, {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CBC_PAD,
     {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
#endif
#if !(NOCDMF)
    {CKM_CDMF_ECB, {0, 0, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_CDMF_CBC, {0, 0, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
#endif
    {CKM_DES3_ECB, {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_CBC, {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_CBC_PAD,
     {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_MAC, {16, 24, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_DES3_MAC_GENERAL, {16, 24, CKF_HW | CKF_SIGN | CKF_VERIFY}},
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
#ifdef NID_sha512_224WithRSAEncryption
    {CKM_SHA512_224, {0, 0, CKF_DIGEST}},
    {CKM_SHA512_224_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_224_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef NID_sha512_256WithRSAEncryption
    {CKM_SHA512_256, {0, 0, CKF_DIGEST}},
    {CKM_SHA512_256_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_256_HMAC_GENERAL, {0, 0, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef NID_sha3_224
    {CKM_IBM_SHA3_224, {0, 0, CKF_DIGEST}},
    {CKM_IBM_SHA3_224_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef NID_sha3_256
    {CKM_IBM_SHA3_256, {0, 0, CKF_DIGEST}},
    {CKM_IBM_SHA3_256_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef NID_sha3_384
    {CKM_IBM_SHA3_384, {0, 0, CKF_DIGEST}},
    {CKM_IBM_SHA3_384_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef NID_sha3_512
    {CKM_IBM_SHA3_512, {0, 0, CKF_DIGEST}},
    {CKM_IBM_SHA3_512_HMAC, {0, 0, CKF_SIGN | CKF_VERIFY}},
#endif
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
    {CKM_AES_MAC, {16, 32, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_MAC_GENERAL, {16, 32, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_CMAC, {16, 32, CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_CMAC_GENERAL, {16, 32, CKF_SIGN | CKF_VERIFY}},
#endif
    {CKM_GENERIC_SECRET_KEY_GEN, {80, 2048, CKF_GENERATE}},
#if !(NO_EC)
    {CKM_EC_KEY_PAIR_GEN, {160, 521, CKF_GENERATE_KEY_PAIR |
                           CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
    {CKM_ECDSA, {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_NAMEDCURVE |
                 CKF_EC_F_P}},
    {CKM_ECDSA_SHA1, {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_NAMEDCURVE |
                      CKF_EC_F_P}},
    {CKM_ECDSA_SHA224, {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_NAMEDCURVE |
                        CKF_EC_F_P}},
    {CKM_ECDSA_SHA256, {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_NAMEDCURVE |
                        CKF_EC_F_P}},
    {CKM_ECDSA_SHA384, {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_NAMEDCURVE |
                        CKF_EC_F_P}},
    {CKM_ECDSA_SHA512, {160, 521, CKF_SIGN | CKF_VERIFY | CKF_EC_NAMEDCURVE |
                        CKF_EC_F_P}},
    {CKM_ECDH1_DERIVE, {160, 521, CKF_DERIVE | CKF_EC_NAMEDCURVE | CKF_EC_F_P}},
#endif
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

CK_RV token_specific_des_key_gen(STDLL_TokData_t *tokdata, CK_BYTE **des_key,
                                 CK_ULONG *len, CK_ULONG keysize,
                                 CK_BBOOL *is_opaque)
{
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
            rng_generate(tokdata, *des_key, keysize);;
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
    const EVP_CIPHER *cipher = EVP_des_ecb();
    EVP_CIPHER_CTX *ctx = NULL;
    CK_ATTRIBUTE *attr = NULL;
    unsigned char dkey[DES_KEY_SIZE];
    CK_ULONG rc;
    int outlen;

    UNUSED(tokdata);

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    if (in_data_len % DES_BLOCK_SIZE || in_data_len > INT_MAX) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }

    memcpy(dkey, attr->pValue, sizeof(dkey));

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, cipher,
                          NULL, dkey, NULL, encrypt ? 1 : 0) != 1
        || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
        || EVP_CipherUpdate(ctx, out_data, &outlen, in_data, in_data_len) != 1
        || EVP_CipherFinal_ex(ctx, out_data, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    *out_data_len = in_data_len;
    rc = CKR_OK;
done:
    OPENSSL_cleanse(dkey, sizeof(dkey));
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV token_specific_des_cbc(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    const EVP_CIPHER *cipher = EVP_des_cbc();
    EVP_CIPHER_CTX *ctx = NULL;
    CK_ATTRIBUTE *attr = NULL;
    unsigned char dkey[DES_KEY_SIZE];
    CK_ULONG rc;
    int outlen;

    UNUSED(tokdata);

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    if (in_data_len % DES_BLOCK_SIZE || in_data_len > INT_MAX) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }

    memcpy(dkey, attr->pValue, sizeof(dkey));

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, cipher,
                          NULL, dkey, init_v, encrypt ? 1 : 0) != 1
        || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
        || EVP_CipherUpdate(ctx, out_data, &outlen, in_data, in_data_len) != 1
        || EVP_CipherFinal_ex(ctx, out_data, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    *out_data_len = in_data_len;
    rc = CKR_OK;
done:
    OPENSSL_cleanse(dkey, sizeof(dkey));
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV token_specific_tdes_ecb(STDLL_TokData_t *tokdata,
                              CK_BYTE *in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE *out_data,
                              CK_ULONG *out_data_len,
                              OBJECT *key, CK_BYTE encrypt)
{
    const EVP_CIPHER *cipher = EVP_des_ede3_ecb();
    EVP_CIPHER_CTX *ctx = NULL;
    CK_ATTRIBUTE *attr = NULL;
    unsigned char dkey[3 * DES_KEY_SIZE];
    CK_KEY_TYPE keytype;
    CK_ULONG rc;
    int outlen;

    UNUSED(tokdata);

    // get the key type
    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
        return rc;
    }

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return rc;
    }

    if (in_data_len % DES_BLOCK_SIZE || in_data_len > INT_MAX) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }

    if (keytype == CKK_DES2) {
        memcpy(dkey, attr->pValue, 2 * DES_KEY_SIZE);
        memcpy(dkey + (2 * DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
    } else {
        memcpy(dkey, attr->pValue, 3 * DES_KEY_SIZE);
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, cipher,
                          NULL, dkey, NULL, encrypt ? 1 : 0) != 1
        || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
        || EVP_CipherUpdate(ctx, out_data, &outlen, in_data, in_data_len) != 1
        || EVP_CipherFinal_ex(ctx, out_data, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    *out_data_len = in_data_len;
    rc = CKR_OK;
done:
    OPENSSL_cleanse(dkey, sizeof(dkey));
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV token_specific_tdes_cbc(STDLL_TokData_t *tokdata,
                              CK_BYTE *in_data,
                              CK_ULONG in_data_len,
                              CK_BYTE *out_data,
                              CK_ULONG *out_data_len,
                              OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    const EVP_CIPHER *cipher = EVP_des_ede3_cbc();
    EVP_CIPHER_CTX *ctx = NULL;
    CK_ATTRIBUTE *attr = NULL;
    unsigned char dkey[3 * DES_KEY_SIZE];
    CK_KEY_TYPE keytype;
    CK_RV rc;
    int outlen;

    UNUSED(tokdata);

    // get the key type
    rc = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
        return rc;
    }

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return rc;
    }

    if (keytype == CKK_DES2) {
        memcpy(dkey, attr->pValue, 2 * DES_KEY_SIZE);
        memcpy(dkey + (2 * DES_KEY_SIZE), attr->pValue, DES_KEY_SIZE);
    } else {
        memcpy(dkey, attr->pValue, 3 * DES_KEY_SIZE);
    }

    if (in_data_len % DES_BLOCK_SIZE || in_data_len > INT_MAX) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, cipher,
                          NULL, dkey, init_v, encrypt ? 1 : 0) != 1
        || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
        || EVP_CipherUpdate(ctx, out_data, &outlen, in_data, in_data_len) != 1
        || EVP_CipherFinal_ex(ctx, out_data, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    *out_data_len = in_data_len;
    rc = CKR_OK;
done:
    OPENSSL_cleanse(dkey, sizeof(dkey));
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV token_specific_tdes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                              CK_ULONG message_len, OBJECT *key, CK_BYTE *mac)
{
    CK_BYTE *out_buf;
    CK_ULONG out_len;
    CK_RV rc;

    out_buf = malloc(message_len);
    if (out_buf == NULL) {
        TRACE_ERROR("Malloc failed.\n");
        return CKR_HOST_MEMORY;
    }

    rc = token_specific_tdes_cbc(tokdata, message, message_len, out_buf,
                                 &out_len, key, mac, 1);

    if (rc == CKR_OK && out_len >= DES_BLOCK_SIZE)
        memcpy(mac, out_buf + out_len - DES_BLOCK_SIZE, DES_BLOCK_SIZE);

    free(out_buf);

    return rc;
}

CK_RV token_specific_rsa_generate_keypair(STDLL_TokData_t *tokdata,
                                          TEMPLATE *publ_tmpl,
                                          TEMPLATE *priv_tmpl)
{
    UNUSED(tokdata);

    return openssl_specific_rsa_keygen(publ_tmpl, priv_tmpl);
}

CK_RV token_specific_rsa_encrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                 CK_ULONG in_data_len, CK_BYTE *out_data,
                                 CK_ULONG *out_data_len, OBJECT *key_obj)
{
    return openssl_specific_rsa_pkcs_encrypt(tokdata, in_data, in_data_len,
                                             out_data, out_data_len, key_obj,
                                             openssl_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_decrypt(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                 CK_ULONG in_data_len, CK_BYTE *out_data,
                                 CK_ULONG *out_data_len, OBJECT *key_obj)
{
    return openssl_specific_rsa_pkcs_decrypt(tokdata, in_data, in_data_len,
                                             out_data, out_data_len, key_obj,
                                             openssl_specific_rsa_decrypt);
}

CK_RV token_specific_rsa_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len,
                              OBJECT *key_obj)
{
    return openssl_specific_rsa_pkcs_sign(tokdata, sess, in_data, in_data_len,
                                          out_data, out_data_len, key_obj,
                                          openssl_specific_rsa_decrypt);
}

CK_RV token_specific_rsa_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                CK_BYTE *in_data, CK_ULONG in_data_len,
                                CK_BYTE *signature, CK_ULONG sig_len,
                                OBJECT *key_obj)
{
    return openssl_specific_rsa_pkcs_verify(tokdata, sess, in_data, in_data_len,
                                          signature, sig_len, key_obj,
                                          openssl_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_verify_recover(STDLL_TokData_t *tokdata,
                                        CK_BYTE *signature, CK_ULONG sig_len,
                                        CK_BYTE *out_data,
                                        CK_ULONG *out_data_len,
                                        OBJECT *key_obj)
{
    return openssl_specific_rsa_pkcs_verify_recover(tokdata, signature,
                                                    sig_len, out_data,
                                                    out_data_len, key_obj,
                                                    openssl_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_pss_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                                  SIGN_VERIFY_CONTEXT *ctx,
                                  CK_BYTE *in_data, CK_ULONG in_data_len,
                                  CK_BYTE *sig, CK_ULONG *sig_len)
{
    return openssl_specific_rsa_pss_sign(tokdata, sess, ctx, in_data,
                                         in_data_len, sig, sig_len,
                                         openssl_specific_rsa_decrypt);
}

CK_RV token_specific_rsa_pss_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                    SIGN_VERIFY_CONTEXT *ctx,
                                    CK_BYTE *in_data, CK_ULONG in_data_len,
                                    CK_BYTE *signature, CK_ULONG sig_len)
{
    return openssl_specific_rsa_pss_verify(tokdata, sess, ctx, in_data,
                                           in_data_len, signature, sig_len,
                                           openssl_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_x509_encrypt(STDLL_TokData_t *tokdata,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, OBJECT *key_obj)
{
    return openssl_specific_rsa_x509_encrypt(tokdata, in_data, in_data_len,
                                             out_data, out_data_len, key_obj,
                                             openssl_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_x509_decrypt(STDLL_TokData_t *tokdata,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, OBJECT *key_obj)
{
    return openssl_specific_rsa_x509_decrypt(tokdata, in_data, in_data_len,
                                             out_data, out_data_len, key_obj,
                                             openssl_specific_rsa_decrypt);
}

CK_RV token_specific_rsa_x509_sign(STDLL_TokData_t *tokdata, CK_BYTE *in_data,
                                   CK_ULONG in_data_len, CK_BYTE *out_data,
                                   CK_ULONG *out_data_len, OBJECT *key_obj)
{
    return openssl_specific_rsa_x509_sign(tokdata, in_data, in_data_len,
                                          out_data, out_data_len, key_obj,
                                          openssl_specific_rsa_decrypt);
}

CK_RV token_specific_rsa_x509_verify(STDLL_TokData_t *tokdata,
                                     CK_BYTE *in_data, CK_ULONG in_data_len,
                                     CK_BYTE *signature, CK_ULONG sig_len,
                                     OBJECT *key_obj)
{
    return openssl_specific_rsa_x509_verify(tokdata, in_data, in_data_len,
                                            signature, sig_len, key_obj,
                                            openssl_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_x509_verify_recover(STDLL_TokData_t *tokdata,
                                             CK_BYTE *signature,
                                             CK_ULONG sig_len,
                                             CK_BYTE *out_data,
                                             CK_ULONG *out_data_len,
                                             OBJECT *key_obj)
{
    return openssl_specific_rsa_x509_verify_recover(tokdata, signature, sig_len,
                                                    out_data, out_data_len,
                                                    key_obj,
                                                    openssl_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_oaep_encrypt(STDLL_TokData_t *tokdata,
                                      ENCR_DECR_CONTEXT *ctx,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE *hash,
                                      CK_ULONG hlen)
{
    return openssl_specific_rsa_oaep_encrypt(tokdata, ctx, in_data,
                                             in_data_len, out_data,
                                             out_data_len, hash, hlen,
                                             openssl_specific_rsa_encrypt);
}

CK_RV token_specific_rsa_oaep_decrypt(STDLL_TokData_t *tokdata,
                                      ENCR_DECR_CONTEXT *ctx,
                                      CK_BYTE *in_data, CK_ULONG in_data_len,
                                      CK_BYTE *out_data,
                                      CK_ULONG *out_data_len, CK_BYTE *hash,
                                      CK_ULONG hlen)
{
    return openssl_specific_rsa_oaep_decrypt(tokdata, ctx, in_data,
                                             in_data_len, out_data,
                                             out_data_len, hash, hlen,
                                             openssl_specific_rsa_decrypt);
}

#ifndef NOAES

CK_RV token_specific_aes_key_gen(STDLL_TokData_t *tokdata, CK_BYTE **key,
                                 CK_ULONG *len, CK_ULONG keysize,
                                 CK_BBOOL *is_opaque)
{
    *key = malloc(keysize);
    if (*key == NULL)
        return CKR_HOST_MEMORY;
    *len = keysize;
    *is_opaque = FALSE;

    return rng_generate(tokdata, *key, keysize);
}

CK_RV token_specific_aes_ecb(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE encrypt)
{
    CK_RV rc;
    int outlen;
    unsigned char akey[32];
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG keylen;

    UNUSED(tokdata);

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        return rc;
    }

    keylen = attr->ulValueLen;
    if (keylen == 128 / 8)
        cipher = EVP_aes_128_ecb();
    else if (keylen == 192 / 8)
        cipher = EVP_aes_192_ecb();
    else if (keylen == 256 / 8)
        cipher = EVP_aes_256_ecb();

    memcpy(akey, attr->pValue, keylen);

    if (in_data_len % AES_BLOCK_SIZE || in_data_len > INT_MAX) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        rc = CKR_DATA_LEN_RANGE;
        goto done;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, cipher,
                          NULL, akey, NULL, encrypt ? 1 : 0) != 1
        || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
        || EVP_CipherUpdate(ctx, out_data, &outlen, in_data, in_data_len) != 1
        || EVP_CipherFinal_ex(ctx, out_data, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    *out_data_len = in_data_len;
    rc = CKR_OK;
done:
    OPENSSL_cleanse(akey, sizeof(akey));
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV token_specific_aes_cbc(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    CK_RV rc;
    int outlen;
    unsigned char akey[32];
    const EVP_CIPHER *cipher = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG keylen;

    UNUSED(tokdata);

    // get the key value
    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc  != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key\n");
        return rc;
    }

    keylen = attr->ulValueLen;
    if (keylen == 128 / 8)
        cipher = EVP_aes_128_cbc();
    else if (keylen == 192 / 8)
        cipher = EVP_aes_192_cbc();
    else if (keylen == 256 / 8)
        cipher = EVP_aes_256_cbc();

    memcpy(akey, attr->pValue, keylen);

    if (in_data_len % AES_BLOCK_SIZE || in_data_len > INT_MAX) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        rc = CKR_DATA_LEN_RANGE;
        goto done;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_CipherInit_ex(ctx, cipher,
                          NULL, akey, init_v, encrypt ? 1 : 0) != 1
        || EVP_CIPHER_CTX_set_padding(ctx, 0) != 1
        || EVP_CipherUpdate(ctx, out_data, &outlen, in_data, in_data_len) != 1
        || EVP_CipherFinal_ex(ctx, out_data, &outlen) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_GENERAL_ERROR));
        rc = CKR_GENERAL_ERROR;
        goto done;
    }

    *out_data_len = in_data_len;
    rc = CKR_OK;
done:
    OPENSSL_cleanse(akey, sizeof(akey));
    EVP_CIPHER_CTX_free(ctx);
    return rc;
}

CK_RV token_specific_aes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                             CK_ULONG message_len, OBJECT *key, CK_BYTE *mac)
{
    CK_BYTE *out_buf;
    CK_ULONG out_len;
    CK_RV rc;

    out_buf = malloc(message_len);
    if (out_buf == NULL) {
        TRACE_ERROR("Malloc failed.\n");
        return CKR_HOST_MEMORY;
    }

    rc = token_specific_aes_cbc(tokdata, message, message_len, out_buf,
                                &out_len, key, mac, 1);

    if (rc == CKR_OK && out_len >= AES_BLOCK_SIZE)
        memcpy(mac, out_buf + out_len - AES_BLOCK_SIZE, AES_BLOCK_SIZE);

    free(out_buf);

    return rc;
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
    CK_RV rv;
    CK_BBOOL rc;
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *temp_attr = NULL;
    CK_ATTRIBUTE *value_bits_attr = NULL;
    CK_BYTE *temp_byte = NULL, *temp_byte2 = NULL;
    CK_ULONG temp_bn_len;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    DH *dh = NULL;
#else
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *osparams = NULL;
#endif
    BIGNUM *bn_p = NULL;
    BIGNUM *bn_g = NULL;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    const BIGNUM *temp_bn = NULL;
#else
    BIGNUM *temp_bn = NULL;
#endif
    EVP_PKEY *params = NULL, *pkey = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    UNUSED(tokdata);

    rv = template_attribute_get_non_empty(publ_tmpl, CKA_PRIME, &prime_attr);
    if (rv != CKR_OK) {
        TRACE_ERROR("Could not find CKA_PRIME for the key.\n");
        goto done;
    }
    rv = template_attribute_get_non_empty(publ_tmpl, CKA_BASE, &base_attr);
    if (rv != CKR_OK) {
        TRACE_ERROR("Could not find CKA_BASE for the key.\n");
        goto done;
    }

    if ((prime_attr->ulValueLen > 256) || (prime_attr->ulValueLen < 64)) {
        TRACE_ERROR("CKA_PRIME attribute value is invalid.\n");
        rv = CKR_ATTRIBUTE_VALUE_INVALID;
        goto done;
    }

    // Create and init BIGNUM structs
    bn_p = BN_new();
    bn_g = BN_new();
    if (bn_g == NULL || bn_p == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    // Convert from strings to BIGNUMs
    BN_bin2bn((unsigned char *) prime_attr->pValue, prime_attr->ulValueLen,
              bn_p);
    BN_bin2bn((unsigned char *) base_attr->pValue, base_attr->ulValueLen, bn_g);
#if !OPENSSL_VERSION_PREREQ(3, 0)
    dh = DH_new();
    if (dh == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    DH_set0_pqg(dh, bn_p, NULL, bn_g);
    /* bn_p and bn_q freed together with dh */
    bn_p = NULL;
    bn_g = NULL;

    params = EVP_PKEY_new();
    if (params == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_PKEY_assign_DH(params, dh) != 1) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }
    dh = NULL; /* freed together with params */
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL)
        goto done;

    if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
        !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, bn_g))
        goto done;

    osparams = OSSL_PARAM_BLD_to_param(tmpl);
    if (osparams == NULL)
        goto done;

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (pctx == NULL)
        goto done;

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, &params, EVP_PKEY_PUBLIC_KEY, osparams))
        goto done;
#endif

    ctx = EVP_PKEY_CTX_new(params, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    if (EVP_PKEY_keygen_init(ctx) != 1
        || EVP_PKEY_keygen(ctx, &pkey) != 1
#if !OPENSSL_VERSION_PREREQ(3, 0)
        /* dh is freed together with pkey */
        || (dh = (DH *)EVP_PKEY_get0_DH(pkey)) == NULL) {
#else
        ) {
#endif
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    // Extract the public and private key components from the DH struct,
    // and insert them in the publ_tmpl and priv_tmpl

    //
    // pub_key
    //
#if !OPENSSL_VERSION_PREREQ(3, 0)
    DH_get0_key(dh, &temp_bn, NULL);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &temp_bn)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

    temp_bn_len = BN_num_bytes(temp_bn);
    temp_byte = malloc(temp_bn_len);
    temp_bn_len = BN_bn2bin(temp_bn, temp_byte);
    // in bytes
    rc = build_attribute(CKA_VALUE, temp_byte, temp_bn_len, &temp_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(publ_tmpl, temp_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(temp_attr);
        goto done;
    }
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(temp_bn);
    temp_bn = NULL;
#endif

    //
    // priv_key
    //
#if !OPENSSL_VERSION_PREREQ(3, 0)
    DH_get0_key(dh, NULL, &temp_bn);
#else
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &temp_bn)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif
    temp_bn_len = BN_num_bytes(temp_bn);
    temp_byte2 = malloc(temp_bn_len);
    temp_bn_len = BN_bn2bin(temp_bn, temp_byte2);
    // in bytes
    rc = build_attribute(CKA_VALUE, temp_byte2, temp_bn_len, &temp_attr);
    OPENSSL_cleanse(temp_byte2, temp_bn_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, temp_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(temp_attr);
        goto done;
    }
#if OPENSSL_VERSION_PREREQ(3, 0)
    BN_free(temp_bn);
    temp_bn = NULL;
#endif

    // Update CKA_VALUE_BITS attribute in the private key
    value_bits_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG));
    if (value_bits_attr == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rv = CKR_HOST_MEMORY;
        goto done;
    }
    value_bits_attr->type = CKA_VALUE_BITS;
    value_bits_attr->ulValueLen = sizeof(CK_ULONG);
    value_bits_attr->pValue =
        (CK_BYTE *) value_bits_attr + sizeof(CK_ATTRIBUTE);
    *(CK_ULONG *) value_bits_attr->pValue = 8 * temp_bn_len;
    rc = template_update_attribute(priv_tmpl, value_bits_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(temp_attr);
        goto done;
    }

    // Add prime and base to the private key template
    rc = build_attribute(CKA_PRIME,
                         (unsigned char *) prime_attr->pValue,
                         prime_attr->ulValueLen, &temp_attr);  // in bytes
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, temp_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(temp_attr);
        goto done;
    }

    rc = build_attribute(CKA_BASE,
                         (unsigned char *) base_attr->pValue,
                         base_attr->ulValueLen, &temp_attr);     // in bytes
    if (rc != CKR_OK) {
        TRACE_DEVEL("build_attribute failed\n");
        goto done;
    }
    rc = template_update_attribute(priv_tmpl, temp_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(temp_attr);
        goto done;
    }

    rv = CKR_OK;
done:
    if (bn_g != NULL)
        BN_free(bn_g);
    if (bn_p != NULL)
        BN_free(bn_p);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
    if (params != NULL)
        EVP_PKEY_free(params);
    free(temp_byte);
    free(temp_byte2);
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
    if (osparams != NULL)
        OSSL_PARAM_free(osparams);
    if (temp_bn != NULL)
        BN_free(temp_bn);
#endif
    return rv;
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

static const EVP_MD *md_from_mech(CK_MECHANISM *mech)
{
    const EVP_MD *md = NULL;

    switch (mech->mechanism) {
    case CKM_SHA_1:
        md = EVP_sha1();
        break;
    case CKM_SHA224:
        md = EVP_sha224();
        break;
    case CKM_SHA256:
        md = EVP_sha256();
        break;
    case CKM_SHA384:
        md = EVP_sha384();
        break;
    case CKM_SHA512:
        md = EVP_sha512();
        break;
#ifdef NID_sha512_224WithRSAEncryption
    case CKM_SHA512_224:
        md = EVP_sha512_224();
        break;
#endif
#ifdef NID_sha512_256WithRSAEncryption
    case CKM_SHA512_256:
        md = EVP_sha512_256();
        break;
#endif
#ifdef NID_sha3_224
    case CKM_IBM_SHA3_224:
        md = EVP_sha3_224();
        break;
#endif
#ifdef NID_sha3_256
    case CKM_IBM_SHA3_256:
        md = EVP_sha3_256();
        break;
#endif
#ifdef NID_sha3_384
    case CKM_IBM_SHA3_384:
        md = EVP_sha3_384();
        break;
#endif
#ifdef NID_sha3_512
    case CKM_IBM_SHA3_512:
        md = EVP_sha3_512();
        break;
#endif
    default:
        break;
    }

    return md;
}

#if !OPENSSL_VERSION_PREREQ(3, 0)
static EVP_MD_CTX *md_ctx_from_context(DIGEST_CONTEXT *ctx)
{
    const EVP_MD *md;
    EVP_MD_CTX *md_ctx;

    md_ctx = EVP_MD_CTX_new();
    if (md_ctx == NULL)
        return NULL;

    md = md_from_mech(&ctx->mech);
    if (md == NULL ||
        !EVP_DigestInit_ex(md_ctx, md, NULL)) {
        TRACE_ERROR("md_from_mech or EVP_DigestInit_ex failed\n");
        EVP_MD_CTX_free(md_ctx);
        return NULL;
    }

    if (ctx->context_len == 0) {
        ctx->context_len = EVP_MD_meth_get_app_datasize(EVP_MD_CTX_md(md_ctx));
        ctx->context = malloc(ctx->context_len);
        if (ctx->context == NULL) {
            TRACE_ERROR("malloc failed\n");
            EVP_MD_CTX_free(md_ctx);
            ctx->context_len = 0;
            return NULL;
        }

        /* Save context data for later use */
        memcpy(ctx->context,  EVP_MD_CTX_md_data(md_ctx), ctx->context_len);
    } else {
        if (ctx->context_len !=
                (CK_ULONG)EVP_MD_meth_get_app_datasize(EVP_MD_CTX_md(md_ctx))) {
            TRACE_ERROR("context size mismatcht\n");
            return NULL;
        }
        /* restore the MD context data */
        memcpy(EVP_MD_CTX_md_data(md_ctx), ctx->context, ctx->context_len);
    }

    return md_ctx;
}
#endif

#if OPENSSL_VERSION_PREREQ(3, 0)
static void token_specific_sha_free(STDLL_TokData_t *tokdata, SESSION *sess,
                                    CK_BYTE *context, CK_ULONG context_len)
{
    UNUSED(tokdata);
    UNUSED(sess);
    UNUSED(context_len);

    EVP_MD_CTX_free((EVP_MD_CTX *)context);
}
#endif

CK_RV token_specific_sha_init(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                              CK_MECHANISM *mech)
{
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EVP_MD_CTX *md_ctx;
#else
    const EVP_MD *md;
#endif

    UNUSED(tokdata);

    ctx->mech.ulParameterLen = mech->ulParameterLen;
    ctx->mech.mechanism = mech->mechanism;

#if !OPENSSL_VERSION_PREREQ(3, 0)
    md_ctx = md_ctx_from_context(ctx);
    if (md_ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    EVP_MD_CTX_free(md_ctx);
#else
    ctx->context_len = 1;
    ctx->context = (CK_BYTE *)EVP_MD_CTX_new();
    if (ctx->context == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    md = md_from_mech(&ctx->mech);
    if (md == NULL ||
        !EVP_DigestInit_ex((EVP_MD_CTX *)ctx->context, md, NULL)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        EVP_MD_CTX_free((EVP_MD_CTX *)ctx->context);
        return CKR_FUNCTION_FAILED;
    }

    ctx->state_unsaveable = CK_TRUE;
    ctx->context_free_func = token_specific_sha_free;
#endif

    return CKR_OK;
}

CK_RV token_specific_sha(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    unsigned int len;
    CK_RV rc = CKR_OK;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EVP_MD_CTX *md_ctx;
#endif

    UNUSED(tokdata);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!in_data || !out_data)
        return CKR_ARGUMENTS_BAD;

#if !OPENSSL_VERSION_PREREQ(3, 0)
    /* Recreate the OpenSSL MD context from the saved context */
    md_ctx = md_ctx_from_context(ctx);
    if (md_ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (*out_data_len < (CK_ULONG)EVP_MD_CTX_size(md_ctx))
        return CKR_BUFFER_TOO_SMALL;

    if (!EVP_DigestUpdate(md_ctx, in_data, in_data_len) ||
        !EVP_DigestFinal(md_ctx, out_data, &len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    *out_data_len = len;
#else
    if (*out_data_len < (CK_ULONG)EVP_MD_CTX_size((EVP_MD_CTX *)ctx->context)) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    len = *out_data_len;
    if (!EVP_DigestUpdate((EVP_MD_CTX *)ctx->context, in_data, in_data_len) ||
        !EVP_DigestFinal((EVP_MD_CTX *)ctx->context, out_data, &len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    *out_data_len = len;
#endif

#if !OPENSSL_VERSION_PREREQ(3, 0)
out:
    EVP_MD_CTX_free(md_ctx);
    free(ctx->context);
#else
    EVP_MD_CTX_free((EVP_MD_CTX *)ctx->context);
#endif
    ctx->context = NULL;
    ctx->context_len = 0;
    ctx->context_free_func = NULL;

    return rc;
}

CK_RV token_specific_sha_update(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                CK_BYTE *in_data, CK_ULONG in_data_len)
{
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EVP_MD_CTX *md_ctx;
#endif

    UNUSED(tokdata);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!in_data)
        return CKR_ARGUMENTS_BAD;

#if !OPENSSL_VERSION_PREREQ(3, 0)
    /* Recreate the OpenSSL MD context from the saved context */
    md_ctx = md_ctx_from_context(ctx);
    if (md_ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (!EVP_DigestUpdate(md_ctx, in_data, in_data_len)) {
        EVP_MD_CTX_free(md_ctx);
        free(ctx->context);
        ctx->context = NULL;
        ctx->context_len = 0;
        ctx->context_free_func = NULL;
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    /* Save context data for later use */
    memcpy(ctx->context,  EVP_MD_CTX_md_data(md_ctx), ctx->context_len);

    EVP_MD_CTX_free(md_ctx);
#else
    if (!EVP_DigestUpdate((EVP_MD_CTX *)ctx->context, in_data, in_data_len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
#endif

    return CKR_OK;
}

CK_RV token_specific_sha_final(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                               CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    unsigned int len;
    CK_RV rc = CKR_OK;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EVP_MD_CTX *md_ctx;
#endif

    UNUSED(tokdata);

    if (!ctx || !ctx->context)
        return CKR_OPERATION_NOT_INITIALIZED;

    if (!out_data)
        return CKR_ARGUMENTS_BAD;

#if !OPENSSL_VERSION_PREREQ(3, 0)
    /* Recreate the OpenSSL MD context from the saved context */
    md_ctx = md_ctx_from_context(ctx);
    if (md_ctx == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    if (*out_data_len < (CK_ULONG)EVP_MD_CTX_size(md_ctx))
        return CKR_BUFFER_TOO_SMALL;

    if (!EVP_DigestFinal(md_ctx, out_data, &len)) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
    *out_data_len = len;

out:
    EVP_MD_CTX_free(md_ctx);
    free(ctx->context);
    ctx->context = NULL;
    ctx->context_len = 0;
    ctx->context_free_func = NULL;
#else
    if (*out_data_len < (CK_ULONG)EVP_MD_CTX_size((EVP_MD_CTX *)ctx->context)) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    len = *out_data_len;
    if (!EVP_DigestFinal((EVP_MD_CTX *)ctx->context, out_data, &len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    *out_data_len = len;

    EVP_MD_CTX_free((EVP_MD_CTX *)ctx->context);
    ctx->context = NULL;
    ctx->context_len = 0;
    ctx->context_free_func = NULL;
#endif

    return rc;
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

    rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
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
#ifdef NID_sha512_224WithRSAEncryption
    case CKM_SHA512_224_HMAC_GENERAL:
    case CKM_SHA512_224_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha512_224(), NULL, pkey);
        break;
#endif
#ifdef NID_sha512_256WithRSAEncryption
    case CKM_SHA512_256_HMAC_GENERAL:
    case CKM_SHA512_256_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha512_256(), NULL, pkey);
        break;
#endif
#ifdef NID_sha3_224
    case CKM_IBM_SHA3_224_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha3_224(), NULL, pkey);
        break;
#endif
#ifdef NID_sha3_256
    case CKM_IBM_SHA3_256_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha3_256(), NULL, pkey);
        break;
#endif
#ifdef NID_sha3_384
    case CKM_IBM_SHA3_384_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha3_384(), NULL, pkey);
        break;
#endif
#ifdef NID_sha3_512
    case CKM_IBM_SHA3_512_HMAC:
        rc = EVP_DigestSignInit(mdctx, NULL, EVP_sha3_512(), NULL, pkey);
        break;
#endif
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
#ifdef NID_sha512_224WithRSAEncryption
    case CKM_SHA512_224_HMAC_GENERAL:
#endif
        general = TRUE;
        /* fallthrough */
    case CKM_SHA224_HMAC:
#ifdef NID_sha512_224WithRSAEncryption
    case CKM_SHA512_224_HMAC:
#endif
        mac_len = SHA224_HASH_SIZE;
        break;
    case CKM_SHA256_HMAC_GENERAL:
#ifdef NID_sha512_256WithRSAEncryption
    case CKM_SHA512_256_HMAC_GENERAL:
#endif
        general = TRUE;
        /* fallthrough */
    case CKM_SHA256_HMAC:
#ifdef NID_sha512_256WithRSAEncryption
    case CKM_SHA512_256_HMAC:
#endif
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
#ifdef NID_sha3_224
    case CKM_IBM_SHA3_224_HMAC:
        mac_len = SHA3_224_HASH_SIZE;
        break;
#endif
#ifdef NID_sha3_256
    case CKM_IBM_SHA3_256_HMAC:
        mac_len = SHA3_256_HASH_SIZE;
        break;
#endif
#ifdef NID_sha3_384
    case CKM_IBM_SHA3_384_HMAC:
        mac_len = SHA3_384_HASH_SIZE;
        break;
#endif
#ifdef NID_sha3_512
    case CKM_IBM_SHA3_512_HMAC:
        mac_len = SHA3_512_HASH_SIZE;
        break;
#endif
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
#ifdef NID_sha3_224
    case CKM_IBM_SHA3_224_HMAC:
        mac_len = SHA3_224_HASH_SIZE;
        break;
#endif
#ifdef NID_sha3_256
    case CKM_IBM_SHA3_256_HMAC:
        mac_len = SHA3_256_HASH_SIZE;
        break;
#endif
#ifdef NID_sha3_384
    case CKM_IBM_SHA3_384_HMAC:
        mac_len = SHA3_384_HASH_SIZE;
        break;
#endif
#ifdef NID_sha3_512
    case CKM_IBM_SHA3_512_HMAC:
        mac_len = SHA3_512_HASH_SIZE;
        break;
#endif
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
    CK_ATTRIBUTE *gkey = NULL;
    CK_RV rc = CKR_OK;
    CK_BYTE secret_key[MAX_GENERIC_KEY_SIZE];
    CK_ULONG key_length = 0;
    CK_ULONG key_length_in_bits = 0;

    rc = template_attribute_get_ulong(tmpl, CKA_VALUE_LEN, &key_length);
    if (rc != CKR_OK) {
        TRACE_ERROR("CKA_VALUE_LEN missing in (HMAC) key template\n");
        return CKR_TEMPLATE_INCOMPLETE;
    }

    //app specified key length in bytes
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
    if (rc != CKR_OK) {
        TRACE_DEVEL("template_update_attribute(CKA_VALUE) failed.\n");
        free(gkey);
    }

    return rc;
}

CK_RV token_specific_tdes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                               CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                               CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{
    int rc;
    size_t maclen;
    CK_RV rv = CKR_OK;
    CK_ATTRIBUTE *attr = NULL;
    CK_KEY_TYPE keytype;
    const EVP_CIPHER *cipher;
    struct cmac_ctx {
#if !OPENSSL_VERSION_PREREQ(3, 0)
        EVP_MD_CTX *mctx;
        EVP_PKEY_CTX *pctx;
        EVP_PKEY *pkey;
#else
        EVP_MAC *mac;
        EVP_MAC_CTX *mctx;
#endif
    };
    struct cmac_ctx *cmac = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    OSSL_PARAM params[2];
#endif

    UNUSED(tokdata);

    if (first) {
        if (key == NULL)
            return CKR_ARGUMENTS_BAD;

        // get the key type
        rv = template_attribute_get_ulong(key->template, CKA_KEY_TYPE, &keytype);
        if (rv != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key\n");
            return rv;
        }

        // get the key value
        rv = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
        if (rv != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE for the key\n");
            return rv;
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
            rv = CKR_KEY_TYPE_INCONSISTENT;
            goto err;
        }

        cmac = calloc(1, sizeof(*cmac));
        if (cmac == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rv = ERR_HOST_MEMORY;
            goto err;
        }

#if !OPENSSL_VERSION_PREREQ(3, 0)
        cmac->mctx = EVP_MD_CTX_new();
        if (cmac->mctx == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        cmac->pkey = EVP_PKEY_new_CMAC_key(NULL,
                                           attr->pValue, attr->ulValueLen,
                                           cipher);
        if (cmac->pkey == NULL) {
            TRACE_ERROR("EVP_DigestSignInit failed\n");
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }

        if (EVP_DigestSignInit(cmac->mctx, &cmac->pctx,
                               NULL, NULL, cmac->pkey) != 1) {
            TRACE_ERROR("EVP_DigestSignInit failed\n");
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }
#else
        cmac->mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
        if (cmac->mac == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }

        cmac->mctx = EVP_MAC_CTX_new(cmac->mac);
        if (cmac->mctx == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                      (char *)EVP_CIPHER_get0_name(cipher), 0);
        params[1] = OSSL_PARAM_construct_end();

        if (!EVP_MAC_init(cmac->mctx, attr->pValue, attr->ulValueLen, params)) {
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }
#endif

        *ctx = cmac;
    }

    cmac = (struct cmac_ctx *)*ctx;
    if (cmac == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rv =  CKR_FUNCTION_FAILED;
        goto err;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = EVP_DigestSignUpdate(cmac->mctx, message, message_len);
#else
    rc = EVP_MAC_update(cmac->mctx, message, message_len);
#endif
    if (rc != 1 || message_len > INT_MAX) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
        TRACE_ERROR("EVP_DigestSignUpdate failed\n");
#else
        TRACE_ERROR("EVP_MAC_update failed\n");
#endif
        rv =  CKR_FUNCTION_FAILED;
        goto err;
    }

    if (last) {
        maclen = AES_BLOCK_SIZE;

#if !OPENSSL_VERSION_PREREQ(3, 0)
        rc = EVP_DigestSignFinal(cmac->mctx, mac, &maclen);
#else
        rc = EVP_MAC_final(cmac->mctx, mac, &maclen, maclen);
#endif
        if (rc != 1) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
            TRACE_ERROR("EVP_DigestSignFinal failed\n");
#else
            TRACE_ERROR("EVP_MAC_final failed\n");
#endif
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }

#if !OPENSSL_VERSION_PREREQ(3, 0)
        EVP_MD_CTX_free(cmac->mctx); /* frees pctx */
        EVP_PKEY_free(cmac->pkey);
#else
        EVP_MAC_CTX_free(cmac->mctx);
        EVP_MAC_free(cmac->mac);
#endif
        free(cmac);
        *ctx = NULL;
    }

    return CKR_OK;
err:
    if (cmac != NULL) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
        if (cmac->mctx != NULL)
            EVP_MD_CTX_free(cmac->mctx); /* frees pctx */
        if (cmac->pkey != NULL)
            EVP_PKEY_free(cmac->pkey);
#else
        if (cmac->mctx != NULL)
            EVP_MAC_CTX_free(cmac->mctx);
        if (cmac->mac != NULL)
            EVP_MAC_free(cmac->mac);
#endif
        free(cmac);
    }
    *ctx = NULL;
    return rv;
}


CK_RV token_specific_aes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                              CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                              CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{
    int rc;
    size_t maclen;
    CK_RV rv = CKR_OK;
    CK_ATTRIBUTE *attr = NULL;
    const EVP_CIPHER *cipher;
    struct cmac_ctx {
#if !OPENSSL_VERSION_PREREQ(3, 0)
        EVP_MD_CTX *mctx;
        EVP_PKEY_CTX *pctx;
        EVP_PKEY *pkey;
#else
        EVP_MAC *mac;
        EVP_MAC_CTX *mctx;
#endif
    };
    struct cmac_ctx *cmac = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    OSSL_PARAM params[2];
#endif

    UNUSED(tokdata);

    if (first) {
        if (key == NULL)
            return CKR_ARGUMENTS_BAD;

        // get the key value
        rc = template_attribute_get_non_empty(key->template, CKA_VALUE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
            goto err;
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

        cmac = calloc(1, sizeof(*cmac));
        if (cmac == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rv = ERR_HOST_MEMORY;
            goto err;
        }

#if !OPENSSL_VERSION_PREREQ(3, 0)
        cmac->mctx = EVP_MD_CTX_new();
        if (cmac->mctx == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rv = ERR_HOST_MEMORY;
            goto err;
        }

        cmac->pkey = EVP_PKEY_new_CMAC_key(NULL,
                                           attr->pValue, attr->ulValueLen,
                                           cipher);
        if (cmac->pkey == NULL) {
            TRACE_ERROR("EVP_DigestSignInit failed\n");
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }

        if (EVP_DigestSignInit(cmac->mctx, &cmac->pctx,
                               NULL, NULL, cmac->pkey) != 1) {
            TRACE_ERROR("EVP_DigestSignInit failed\n");
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }
#else
        cmac->mac = EVP_MAC_fetch(NULL, "CMAC", NULL);
        if (cmac->mac == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }

        cmac->mctx = EVP_MAC_CTX_new(cmac->mac);
        if (cmac->mctx == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rv = CKR_HOST_MEMORY;
            goto err;
        }

        params[0] = OSSL_PARAM_construct_utf8_string(OSSL_MAC_PARAM_CIPHER,
                                      (char *)EVP_CIPHER_get0_name(cipher), 0);
        params[1] = OSSL_PARAM_construct_end();

        if (!EVP_MAC_init(cmac->mctx, attr->pValue, attr->ulValueLen, params)) {
            TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }
#endif

        *ctx = cmac;
    }

    cmac = (struct cmac_ctx *)*ctx;
    if (cmac == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rv =  CKR_FUNCTION_FAILED;
        goto err;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = EVP_DigestSignUpdate(cmac->mctx, message, message_len);
#else
    rc = EVP_MAC_update(cmac->mctx, message, message_len);
#endif
    if (rc != 1 || message_len > INT_MAX) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
        TRACE_ERROR("EVP_DigestSignUpdate failed\n");
#else
        TRACE_ERROR("EVP_MAC_update failed\n");
#endif
        rv =  CKR_FUNCTION_FAILED;
        goto err;
    }

    if (last) {
        maclen = AES_BLOCK_SIZE;

#if !OPENSSL_VERSION_PREREQ(3, 0)
        rc = EVP_DigestSignFinal(cmac->mctx, mac, &maclen);
#else
        rc = EVP_MAC_final(cmac->mctx, mac, &maclen, maclen);
#endif
        if (rc != 1) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
            TRACE_ERROR("EVP_DigestSignFinal failed\n");
#else
            TRACE_ERROR("EVP_MAC_final failed\n");
#endif
            rv = CKR_FUNCTION_FAILED;
            goto err;
        }

#if !OPENSSL_VERSION_PREREQ(3, 0)
        EVP_MD_CTX_free(cmac->mctx); /* frees pctx */
        EVP_PKEY_free(cmac->pkey);
#else
        EVP_MAC_CTX_free(cmac->mctx);
        EVP_MAC_free(cmac->mac);
#endif
        free(cmac);
        *ctx = NULL;
    }

    return CKR_OK;
err:
    if (cmac != NULL) {
#if !OPENSSL_VERSION_PREREQ(3, 0)
        if (cmac->mctx != NULL)
            EVP_MD_CTX_free(cmac->mctx); /* frees pctx */
        if (cmac->pkey != NULL)
            EVP_PKEY_free(cmac->pkey);
#else
        if (cmac->mctx != NULL)
            EVP_MAC_CTX_free(cmac->mctx);
        if (cmac->mac != NULL)
            EVP_MAC_free(cmac->mac);
#endif
        free(cmac);
    }
    *ctx = NULL;
    return rv;
}

#ifndef NO_EC

static int curve_nid_from_params(const CK_BYTE *params, CK_ULONG params_len)
{
    const unsigned char *oid;
    ASN1_OBJECT *obj = NULL;
    int nid;

    oid = params;
    obj = d2i_ASN1_OBJECT(NULL, &oid, params_len);
    if (obj == NULL) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        return NID_undef;
    }

    nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);

    return nid;
}

static int ec_prime_len_from_nid(int nid)
{
    EC_GROUP *group;
    int primelen;

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL)
        return -1;

    primelen = EC_GROUP_order_bits(group);

    EC_GROUP_free(group);

    if ((primelen % 8) == 0)
        return primelen / 8;
    else
        return (primelen / 8) + 1;
}

int ec_prime_len_from_pkey(EVP_PKEY *pkey)
{
#if !OPENSSL_VERSION_PREREQ(3, 0)
    return (EC_GROUP_order_bits(EC_KEY_get0_group(
                             EVP_PKEY_get0_EC_KEY(pkey))) + 7) / 8;
#else
    size_t curve_len;
    char curve[80];

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        curve, sizeof(curve), &curve_len))
        return -1;

    return ec_prime_len_from_nid(OBJ_sn2nid(curve));
#endif
}


#if !OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV make_ec_key_from_params(const CK_BYTE *params, CK_ULONG params_len,
                                     EC_KEY **key)
{
    EC_KEY *ec_key = NULL;
    int nid;
    CK_RV rc = CKR_OK;

    nid = curve_nid_from_params(params, params_len);
    if (nid == NID_undef) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

    ec_key = EC_KEY_new_by_curve_name(nid);
    if (ec_key == NULL) {
       TRACE_ERROR("curve not supported by OpenSSL.\n");
       rc = CKR_CURVE_NOT_SUPPORTED;
       goto out;
    }

out:
    if (rc != CKR_OK) {
        if (ec_key != NULL)
            EC_KEY_free(ec_key);

        return rc;
    }

    *key = ec_key;

    return CKR_OK;
}
#endif

#if OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV build_pkey_from_params(OSSL_PARAM_BLD *tmpl, int selection,
                                    EVP_PKEY **pkey)
{

    OSSL_PARAM *params = NULL;
    EVP_PKEY_CTX *pctx = NULL;
    CK_RV rc = CKR_OK;

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        TRACE_ERROR("OSSL_PARAM_BLD_to_param failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new_id failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, pkey, selection, params)) {
        TRACE_ERROR("EVP_PKEY_fromdata failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    EVP_PKEY_CTX_free(pctx);
    pctx = EVP_PKEY_CTX_new(*pkey, NULL);
    if (pctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (selection & OSSL_KEYMGMT_SELECT_PRIVATE_KEY) {
        if (EVP_PKEY_check(pctx) != 1) {
            TRACE_ERROR("EVP_PKEY_check failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
    } else {
        if (EVP_PKEY_public_check(pctx) != 1) {
            TRACE_ERROR("EVP_PKEY_public_check failed\n");
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }
    }

out:
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (params != NULL)
        OSSL_PARAM_free(params);

    if (rc != 0 && *pkey != NULL) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return rc;
}
#endif

#if !OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV fill_ec_key_from_pubkey(EC_KEY *ec_key, const CK_BYTE *data,
                                     CK_ULONG data_len, CK_BBOOL allow_raw,
                                     int nid, EVP_PKEY **ec_pkey)
#else
static CK_RV fill_ec_key_from_pubkey(OSSL_PARAM_BLD *tmpl, const CK_BYTE *data,
                                     CK_ULONG data_len, CK_BBOOL allow_raw,
                                     int nid, EVP_PKEY **ec_pkey)
#endif
{
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len, privlen;
    CK_BBOOL allocated = FALSE;

    CK_RV rc;

    privlen = ec_prime_len_from_nid(nid);
    if (privlen <= 0) {
        TRACE_ERROR("ec_prime_len_from_nid failed\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

    rc = ec_point_from_public_data(data, data_len, privlen, allow_raw,
                                   &allocated, &ecpoint, &ecpoint_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ec_point_from_public_data failed\n");
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (!EC_KEY_oct2key(ec_key, ecpoint, ecpoint_len, NULL)) {
        TRACE_ERROR("EC_KEY_oct2key failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EC_KEY_check_key(ec_key)) {
        TRACE_ERROR("EC_KEY_check_key failed\n");
        rc = CKR_PUBLIC_KEY_INVALID;
        goto out;
    }

    *ec_pkey = EVP_PKEY_new();
    if (*ec_pkey == NULL) {
       TRACE_ERROR("EVP_PKEY_CTX_new failed.\n");
       rc = CKR_HOST_MEMORY;
       goto out;
    }

    if (!EVP_PKEY_assign_EC_KEY(*ec_pkey, ec_key)) {
        TRACE_ERROR("EVP_PKEY_assign_EC_KEY failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#else
    if (!OSSL_PARAM_BLD_push_octet_string(tmpl,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          ecpoint, ecpoint_len)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_octet_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = build_pkey_from_params(tmpl, EVP_PKEY_PUBLIC_KEY, ec_pkey);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_pkey_from_params failed\n");
        goto out;
    }
 #endif

out:
    if (allocated && ecpoint != NULL)
        free(ecpoint);

    return rc;
}

#if !OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV fill_ec_key_from_privkey(EC_KEY *ec_key, const CK_BYTE *data,
                                      CK_ULONG data_len, EVP_PKEY **ec_pkey)
#else
static CK_RV fill_ec_key_from_privkey(OSSL_PARAM_BLD *tmpl, const CK_BYTE *data,
                                      CK_ULONG data_len, int nid,
                                      EVP_PKEY **ec_pkey)
#endif
{
    EC_POINT *point = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    EC_GROUP *group = NULL;
    BIGNUM *bn_priv = NULL;
    unsigned char *pub_key = NULL;
    unsigned int pub_key_len;
    point_conversion_form_t form;
#endif
    CK_RV rc = CKR_OK;

#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (!EC_KEY_oct2priv(ec_key, data, data_len)) {
        TRACE_ERROR("EC_KEY_oct2priv failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    point = EC_POINT_new(EC_KEY_get0_group(ec_key));
    if (point == NULL) {
        TRACE_ERROR("EC_POINT_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EC_POINT_mul(EC_KEY_get0_group(ec_key), point,
                      EC_KEY_get0_private_key(ec_key), NULL, NULL, NULL)) {
        TRACE_ERROR("EC_POINT_mul failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EC_KEY_set_public_key(ec_key, point)) {
        TRACE_ERROR("EC_KEY_set_public_key failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EC_KEY_check_key(ec_key)) {
        TRACE_ERROR("EC_KEY_check_key failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    *ec_pkey = EVP_PKEY_new();
    if (*ec_pkey == NULL) {
       TRACE_ERROR("EVP_PKEY_CTX_new failed.\n");
       rc = CKR_HOST_MEMORY;
       goto out;
    }

    if (!EVP_PKEY_assign_EC_KEY(*ec_pkey, ec_key)) {
        TRACE_ERROR("EVP_PKEY_assign_EC_KEY failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#else
    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL) {
        TRACE_ERROR("EC_GROUP_new_by_curve_name failed\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

    point = EC_POINT_new(group);
    if (point == NULL) {
        TRACE_ERROR("EC_POINT_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    bn_priv = BN_bin2bn(data, data_len, NULL);
    if (bn_priv == NULL) {
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!EC_POINT_mul(group, point, bn_priv, NULL, NULL, NULL)) {
        TRACE_ERROR("EC_POINT_mul failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    form = EC_GROUP_get_point_conversion_form(group);
    pub_key_len = EC_POINT_point2buf(group, point, form, &pub_key,
                                     NULL);
    if (pub_key_len == 0) {
        TRACE_ERROR("EC_POINT_point2buf failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PUB_KEY,
                                          pub_key, pub_key_len)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_octet_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_BN failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = build_pkey_from_params(tmpl, EVP_PKEY_KEYPAIR, ec_pkey);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_pkey_from_params failed\n");
        goto out;
    }
#endif

out:
    if (point != NULL)
        EC_POINT_free(point);
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (group != NULL)
        EC_GROUP_free(group);
    if (bn_priv != NULL)
        BN_free(bn_priv);
    if (pub_key != NULL)
        OPENSSL_free(pub_key);
#endif

    return rc;
}



static CK_RV make_ec_key_from_template(TEMPLATE *template, EVP_PKEY **pkey)
{
    CK_ATTRIBUTE *attr = NULL;
    CK_OBJECT_CLASS keyclass;
    EVP_PKEY *ec_pkey = NULL;
    int nid;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EC_KEY *ec_key = NULL;
#else
    OSSL_PARAM_BLD *tmpl = NULL;
#endif
    CK_RV rc;

    rc = template_attribute_get_ulong(template, CKA_CLASS, &keyclass);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS in the template\n");
        goto out;
    }

    rc = template_attribute_get_non_empty(template, CKA_ECDSA_PARAMS, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_ECDSA_PARAMS in the template\n");
        goto out;
    }

    nid = curve_nid_from_params(attr->pValue, attr->ulValueLen);
    if (nid == NID_undef) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = make_ec_key_from_params(attr->pValue, attr->ulValueLen, &ec_key);
    if (rc != CKR_OK)
        goto out;
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        TRACE_ERROR("OSSL_PARAM_BLD_new failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(tmpl, OSSL_PKEY_PARAM_GROUP_NAME,
                                         OBJ_nid2sn(nid), 0)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_utf8_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#endif

    switch (keyclass) {
    case CKO_PUBLIC_KEY:
        rc = template_attribute_get_non_empty(template, CKA_EC_POINT, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_EC_POINT in the template\n");
            goto out;
        }

#if !OPENSSL_VERSION_PREREQ(3, 0)
        rc = fill_ec_key_from_pubkey(ec_key, attr->pValue, attr->ulValueLen,
                                     FALSE, nid, &ec_pkey);
#else
        rc = fill_ec_key_from_pubkey(tmpl, attr->pValue, attr->ulValueLen,
                                     FALSE, nid, &ec_pkey);
#endif
        if (rc != CKR_OK) {
            TRACE_DEVEL("fill_ec_key_from_pubkey failed\n");
            goto out;
        }
        break;

    case CKO_PRIVATE_KEY:
        rc = template_attribute_get_non_empty(template, CKA_VALUE, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE in the template\n");
            goto out;
        }

#if !OPENSSL_VERSION_PREREQ(3, 0)
        rc = fill_ec_key_from_privkey(ec_key, attr->pValue, attr->ulValueLen,
                                      &ec_pkey);
#else
        rc = fill_ec_key_from_privkey(tmpl, attr->pValue, attr->ulValueLen,
                                      nid, &ec_pkey);

#endif
        if (rc != CKR_OK) {
            TRACE_DEVEL("fill_ec_key_from_privkey failed\n");
            goto out;
        }
        break;

    default:
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    ec_key = NULL;
#endif

    rc = CKR_OK;

out:
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
#endif

    if (rc != CKR_OK) {
        if (ec_pkey != NULL)
            EVP_PKEY_free(ec_pkey);
#if !OPENSSL_VERSION_PREREQ(3, 0)
        if (ec_key != NULL)
            EC_KEY_free(ec_key);
#endif

        return rc;
    }

    *pkey = ec_pkey;

    return CKR_OK;
}

CK_RV token_specific_ec_generate_keypair(STDLL_TokData_t *tokdata,
                                         TEMPLATE *publ_tmpl,
                                         TEMPLATE *priv_tmpl)
{

    CK_ATTRIBUTE *attr = NULL, *ec_point_attr, *value_attr, *parms_attr;
#if !OPENSSL_VERSION_PREREQ(3, 0)
    const EC_KEY *ec_key = NULL;
    BN_CTX *bnctx = NULL;
#else
    BIGNUM *bn_d = NULL;
#endif
    CK_BYTE *ecpoint = NULL, *enc_ecpoint = NULL, *d = NULL;
    CK_ULONG ecpoint_len, enc_ecpoint_len, d_len;
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *ec_pkey = NULL;
    int nid;
    CK_RV rc;

    UNUSED(tokdata);

    rc = template_attribute_get_non_empty(publ_tmpl, CKA_ECDSA_PARAMS, &attr);
    if (rc != CKR_OK)
        goto out;

    nid = curve_nid_from_params(attr->pValue, attr->ulValueLen);
    if (nid == NID_undef) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        TRACE_ERROR("EVP_PKEY_keygen_init failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        TRACE_ERROR("EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

    if (EVP_PKEY_keygen(ctx, &ec_pkey) <= 0) {
        TRACE_ERROR("EVP_PKEY_keygen failed\n");
        if (ERR_GET_REASON(ERR_peek_last_error()) == EC_R_INVALID_CURVE)
            rc = CKR_CURVE_NOT_SUPPORTED;
        else
            rc = CKR_FUNCTION_FAILED;
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    ec_key = EVP_PKEY_get0_EC_KEY(ec_pkey);
    if (ec_key == NULL) {
       TRACE_ERROR("EVP_PKEY_get0_EC_KEY failed\n");
       rc = CKR_FUNCTION_FAILED;
       goto out;
   }

    bnctx = BN_CTX_new();
    if (bnctx == NULL) {
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    ecpoint_len = EC_KEY_key2buf(ec_key, POINT_CONVERSION_UNCOMPRESSED,
                                 &ecpoint, bnctx);
    if (ecpoint_len == 0) {
        TRACE_ERROR("Failed to get the EC Point compressed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#else
    if (!EVP_PKEY_get_octet_string_param(ec_pkey,
                                         OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                         NULL, 0, &ecpoint_len)) {
        TRACE_ERROR("EVP_PKEY_get_octet_string_param failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    ecpoint = OPENSSL_zalloc(ecpoint_len);
    if (ecpoint == NULL) {
        TRACE_ERROR("OPENSSL_zalloc failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (!EVP_PKEY_get_octet_string_param(ec_pkey,
                                         OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                         ecpoint, ecpoint_len, &ecpoint_len)) {
        TRACE_ERROR("EVP_PKEY_get_octet_string_param failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#endif

    rc = ber_encode_OCTET_STRING(FALSE, &enc_ecpoint, &enc_ecpoint_len,
                                 ecpoint, ecpoint_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed\n");
        goto out;
    }

    rc = build_attribute(CKA_EC_POINT, enc_ecpoint, enc_ecpoint_len,
                         &ec_point_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_attribute for CKA_EC_POINT failed rc=0x%lx\n", rc);
        goto out;
    }
    rc = template_update_attribute(publ_tmpl, ec_point_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(ec_point_attr);
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    d_len = EC_KEY_priv2buf(ec_key, &d);
    if (d_len == 0) {
        TRACE_ERROR("Failed to get the EC private key.\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#else
    if (!EVP_PKEY_get_bn_param(ec_pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_d)) {
        TRACE_ERROR("EVP_PKEY_get_bn_param failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    d_len = ec_prime_len_from_nid(nid);
    d = OPENSSL_zalloc(d_len);
    if (d == NULL) {
        TRACE_ERROR("OPENSSL_zalloc failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    BN_bn2binpad(bn_d, d, d_len);
#endif

    rc = build_attribute(CKA_VALUE, d, d_len, &value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_attribute for CKA_VALUE failed, rc=0x%lx\n", rc);
        goto out;
    }
    rc = template_update_attribute(priv_tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(value_attr);
        goto out;
    }


    /* Add CKA_ECDSA_PARAMS to private template also */
    rc = build_attribute(CKA_ECDSA_PARAMS, attr->pValue, attr->ulValueLen,
                         &parms_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("build_attribute for CKA_ECDSA_PARAMS failed, rc=0x%lx\n",
                     rc);
        goto out;
    }
    rc = template_update_attribute(priv_tmpl, parms_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        free(parms_attr);
        goto out;
    }

    rc = CKR_OK;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (bnctx != NULL)
        BN_CTX_free(bnctx);
#else
    if (bn_d != NULL)
        BN_free(bn_d);
#endif
    if (ec_pkey != NULL)
        EVP_PKEY_free(ec_pkey);
    if (ecpoint != NULL)
        OPENSSL_free(ecpoint);
    if (enc_ecpoint != NULL)
        free(enc_ecpoint);
    if (d != NULL)
        OPENSSL_free(d);

    return rc;
}

CK_RV token_specific_ec_sign(STDLL_TokData_t *tokdata,  SESSION *sess,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj)
{
    EVP_PKEY *ec_key;
    ECDSA_SIG *sig = NULL;
    const BIGNUM *r, *s;
    CK_ULONG privlen, n;
    CK_RV rc = CKR_OK;
    EVP_PKEY_CTX *ctx = NULL;
    size_t siglen;
    CK_BYTE *sigbuf = NULL;
    const unsigned char *p;

    UNUSED(tokdata);
    UNUSED(sess);

    *out_data_len = 0;

    rc = make_ec_key_from_template(key_obj->template, &ec_key);
    if (rc != CKR_OK)
        return rc;

    ctx = EVP_PKEY_CTX_new(ec_key, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0) {
        TRACE_ERROR("EVP_PKEY_sign_init failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_sign(ctx, NULL, &siglen, in_data, in_data_len) <= 0) {
        TRACE_ERROR("EVP_PKEY_sign failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    sigbuf = malloc(siglen);
    if (sigbuf == NULL) {
        TRACE_ERROR("malloc failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (EVP_PKEY_sign(ctx, sigbuf, &siglen, in_data, in_data_len) <= 0) {
        TRACE_ERROR("EVP_PKEY_sign failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    p = sigbuf;
    sig = d2i_ECDSA_SIG(NULL, &p, siglen);
    if (sig == NULL) {
        TRACE_ERROR("d2i_ECDSA_SIG failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    ECDSA_SIG_get0(sig, &r, &s);

    privlen = ec_prime_len_from_pkey(ec_key);
    if (privlen <= 0) {
        TRACE_ERROR("ec_prime_len_from_pkey failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    /* Insert leading 0x00's if r or s shorter than privlen */
    n = privlen - BN_num_bytes(r);
    memset(out_data, 0x00, n);
    BN_bn2bin(r, &out_data[n]);

    n = privlen - BN_num_bytes(s);
    memset(out_data + privlen, 0x00, n);
    BN_bn2bin(s, &out_data[privlen + n]);

    *out_data_len = 2 * privlen;

out:
    if (sig != NULL)
        ECDSA_SIG_free(sig);
    if (ec_key != NULL)
        EVP_PKEY_free(ec_key);
    if (sigbuf != NULL)
        free(sigbuf);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return rc;
}

CK_RV token_specific_ec_verify(STDLL_TokData_t *tokdata,
                               SESSION *sess,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *signature,
                               CK_ULONG signature_len, OBJECT *key_obj)
{
    EVP_PKEY *ec_key;
    CK_ULONG privlen;
    ECDSA_SIG *sig = NULL;
    BIGNUM *r = NULL, *s = NULL;
    CK_RV rc = CKR_OK;
    size_t siglen;
    CK_BYTE *sigbuf = NULL;
    EVP_PKEY_CTX *ctx = NULL;

    UNUSED(tokdata);
    UNUSED(sess);

    rc = make_ec_key_from_template(key_obj->template, &ec_key);
    if (rc != CKR_OK)
        return rc;

    privlen = ec_prime_len_from_pkey(ec_key);
    if (privlen <= 0) {
        TRACE_ERROR("ec_prime_len_from_pkey failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (signature_len < 2 * privlen) {
        TRACE_ERROR("Signature is too short\n");
        rc = CKR_SIGNATURE_LEN_RANGE;
        goto out;
    }

    sig = ECDSA_SIG_new();
    if (sig == NULL) {
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    r = BN_bin2bn(signature, privlen, NULL);
    s = BN_bin2bn(signature + privlen, privlen, NULL);
    if (r == NULL || s == NULL) {
        TRACE_ERROR("BN_bin2bn failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (!ECDSA_SIG_set0(sig, r, s)) {
        TRACE_ERROR("ECDSA_SIG_set0 failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    siglen = i2d_ECDSA_SIG(sig, &sigbuf);
    if (siglen <= 0) {
        TRACE_ERROR("i2d_ECDSA_SIG failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    ctx = EVP_PKEY_CTX_new(ec_key, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("EVP_PKEY_CTX_new failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_verify_init(ctx) <= 0) {
        TRACE_ERROR("EVP_PKEY_verify_init failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = EVP_PKEY_verify(ctx, sigbuf, siglen, in_data, in_data_len);
    switch (rc) {
    case 0:
        rc = CKR_SIGNATURE_INVALID;
        break;
    case 1:
        rc = CKR_OK;
        break;
    default:
        rc = CKR_FUNCTION_FAILED;
        break;
    }

out:
    if (sig != NULL)
        ECDSA_SIG_free(sig);
    if (ec_key != NULL)
        EVP_PKEY_free(ec_key);
    if (sigbuf != NULL)
        OPENSSL_free(sigbuf);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return rc;
}

CK_RV token_specific_ecdh_pkcs_derive(STDLL_TokData_t *tokdata,
                                      CK_BYTE *priv_bytes,
                                      CK_ULONG priv_length,
                                      CK_BYTE *pub_bytes,
                                      CK_ULONG pub_length,
                                      CK_BYTE *secret_value,
                                      CK_ULONG *secret_value_len,
                                      CK_BYTE *oid, CK_ULONG oid_length)
{
#if !OPENSSL_VERSION_PREREQ(3, 0)
    EC_KEY *pub = NULL, *priv = NULL;
#else
    OSSL_PARAM_BLD *tmpl = NULL;
#endif
    EVP_PKEY *ec_pub = NULL, *ec_priv = NULL;
    EVP_PKEY_CTX *ctx = NULL;
    size_t secret_len;
    int nid;
    CK_RV rc;

    UNUSED(tokdata);

    nid = curve_nid_from_params(oid, oid_length);
    if (nid == NID_undef) {
        TRACE_ERROR("curve not supported by OpenSSL.\n");
        rc = CKR_CURVE_NOT_SUPPORTED;
        goto out;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = make_ec_key_from_params(oid, oid_length, &priv);
    if (rc != CKR_OK) {
        TRACE_DEVEL("make_ec_key_from_params failed\n");
        goto out;
    }
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        TRACE_ERROR("OSSL_PARAM_BLD_new failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(tmpl, OSSL_PKEY_PARAM_GROUP_NAME,
                                         OBJ_nid2sn(nid), 0)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_utf8_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#endif

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = fill_ec_key_from_privkey(priv, priv_bytes, priv_length, &ec_priv);
#else
    rc = fill_ec_key_from_privkey(tmpl, priv_bytes, priv_length, nid, &ec_priv);
#endif
    if (rc != CKR_OK) {
        TRACE_DEVEL("fill_ec_key_from_privkey failed\n");
        goto out;
    }
#if !OPENSSL_VERSION_PREREQ(3, 0)
    priv = NULL;
#else
    OSSL_PARAM_BLD_free(tmpl);
    tmpl = NULL;
#endif

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = make_ec_key_from_params(oid, oid_length, &pub);
    if (rc != CKR_OK) {
        TRACE_DEVEL("make_ec_key_from_params failed\n");
        goto out;
    }
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        TRACE_ERROR("OSSL_PARAM_BLD_new failed\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(tmpl, OSSL_PKEY_PARAM_GROUP_NAME,
                                         OBJ_nid2sn(nid), 0)) {
        TRACE_ERROR("OSSL_PARAM_BLD_push_utf8_string failed\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
#endif

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rc = fill_ec_key_from_pubkey(pub, pub_bytes, pub_length, TRUE, nid,
                                 &ec_pub);
#else
    rc = fill_ec_key_from_pubkey(tmpl, pub_bytes, pub_length, TRUE, nid,
                                 &ec_pub);
#endif
    if (rc != CKR_OK) {
        TRACE_DEVEL("fill_ec_key_from_pubkey failed\n");
        goto out;
    }
#if !OPENSSL_VERSION_PREREQ(3, 0)
    pub = NULL;
#else
    OSSL_PARAM_BLD_free(tmpl);
    tmpl = NULL;
#endif

    ctx = EVP_PKEY_CTX_new(ec_priv, NULL);
    if (ctx == NULL) {
        TRACE_DEVEL("EVP_PKEY_CTX_new failed\n");
        goto out;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0 ||
        EVP_PKEY_derive_set_peer(ctx, ec_pub) <= 0) {
        TRACE_DEVEL("EVP_PKEY_derive_init/EVP_PKEY_derive_set_peer failed\n");
        goto out;
    }

    secret_len = ec_prime_len_from_nid(nid);
    if (EVP_PKEY_derive(ctx, secret_value, &secret_len) <= 0) {
        TRACE_DEVEL("ECDH_compute_key failed\n");
        rc = CKR_FUNCTION_FAILED;
        *secret_value_len = 0;
        goto out;
    }

    *secret_value_len = secret_len;

out:
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (priv != NULL)
        EC_KEY_free(priv);
    if (pub != NULL)
        EC_KEY_free(pub);
#else
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
#endif
    if (ec_priv != NULL)
        EVP_PKEY_free(ec_priv);
    if (ec_pub != NULL)
        EVP_PKEY_free(ec_pub);
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return rc;
}

#endif

CK_RV token_specific_object_add(STDLL_TokData_t * tokdata, SESSION * sess,
                                OBJECT * obj)
{
    CK_KEY_TYPE keytype;
#ifndef NO_EC
    EVP_PKEY *ec_key = NULL;
#endif
    CK_RV rc;

    UNUSED(tokdata);
    UNUSED(sess);

    rc = template_attribute_get_ulong(obj->template, CKA_KEY_TYPE, &keytype);
    if (rc != CKR_OK)
        return CKR_OK;

    switch (keytype) {
#ifndef NO_EC
    case CKK_EC:
        /* Check if OpenSSL supports the curve */
        rc = make_ec_key_from_template(obj->template, &ec_key);
        if (ec_key != NULL)
                EVP_PKEY_free(ec_key);
        return rc;
#endif

    default:
        return CKR_OK;;
    }
}

