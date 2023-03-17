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

#include <openssl/rand.h>
#include <openssl/dh.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
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
    {CKM_DES_KEY_GEN, {8, 8, CKF_GENERATE}},
    {CKM_DES3_KEY_GEN, {24, 24, CKF_GENERATE}},
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
    {CKM_DH_PKCS_DERIVE, {512, 8192, CKF_DERIVE}},
    {CKM_DH_PKCS_KEY_PAIR_GEN, {512, 8192, CKF_GENERATE_KEY_PAIR}},
#endif
/* End code contributed by Corrent corp. */
    {CKM_DES_ECB, {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CBC, {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CBC_PAD,
     {8, 8, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_ECB, {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_CBC, {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_CBC_PAD,
     {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_OFB64, {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CFB8, {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES_CFB64, {24, 24, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_DES3_MAC, {16, 24, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_DES3_MAC_GENERAL, {16, 24, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_DES3_CMAC, {16, 24, CKF_SIGN | CKF_VERIFY}},
    {CKM_DES3_CMAC_GENERAL, {16, 24, CKF_SIGN | CKF_VERIFY}},
#if !(NOSHA1)
    {CKM_SHA_1, {0, 0, CKF_DIGEST}},
    {CKM_SHA_1_HMAC, {80, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA_1_HMAC_GENERAL, {80, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
    {CKM_SHA224, {0, 0, CKF_DIGEST}},
    {CKM_SHA224_HMAC, {112, 2048, CKF_SIGN|CKF_VERIFY}},
    {CKM_SHA224_HMAC_GENERAL, {112, 2048, CKF_SIGN|CKF_VERIFY}},
    {CKM_SHA256, {0, 0, CKF_DIGEST}},
    {CKM_SHA256_HMAC, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA256_HMAC_GENERAL, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384, {0, 0, CKF_DIGEST}},
    {CKM_SHA384_HMAC, {192, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA384_HMAC_GENERAL, {192, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512, {0, 0, CKF_DIGEST}},
    {CKM_SHA512_HMAC, {256, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_HMAC_GENERAL, {256, 2048, CKF_SIGN | CKF_VERIFY}},
#ifdef NID_sha512_224WithRSAEncryption
    {CKM_SHA512_224, {0, 0, CKF_DIGEST}},
    {CKM_SHA512_224_HMAC, {112, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_224_HMAC_GENERAL, {112, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef NID_sha512_256WithRSAEncryption
    {CKM_SHA512_256, {0, 0, CKF_DIGEST}},
    {CKM_SHA512_256_HMAC, {128, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_SHA512_256_HMAC_GENERAL, {128, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef NID_sha3_224
    {CKM_IBM_SHA3_224, {0, 0, CKF_DIGEST}},
    {CKM_IBM_SHA3_224_HMAC, {112, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef NID_sha3_256
    {CKM_IBM_SHA3_256, {0, 0, CKF_DIGEST}},
    {CKM_IBM_SHA3_256_HMAC, {128, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef NID_sha3_384
    {CKM_IBM_SHA3_384, {0, 0, CKF_DIGEST}},
    {CKM_IBM_SHA3_384_HMAC, {192, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#ifdef NID_sha3_512
    {CKM_IBM_SHA3_512, {0, 0, CKF_DIGEST}},
    {CKM_IBM_SHA3_512_HMAC, {256, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#if !(NOMD2)
    {CKM_MD2, {0, 0, CKF_DIGEST}},
    {CKM_MD2_HMAC, {8, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_MD2_HMAC_GENERAL, {8, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
#if !(NOMD5)
    {CKM_MD5, {0, 0, CKF_DIGEST}},
    {CKM_MD5_HMAC, {8, 2048, CKF_SIGN | CKF_VERIFY}},
    {CKM_MD5_HMAC_GENERAL, {8, 2048, CKF_SIGN | CKF_VERIFY}},
#endif
    {CKM_SSL3_PRE_MASTER_KEY_GEN, {48, 48, CKF_GENERATE}},
    {CKM_SSL3_MASTER_KEY_DERIVE, {48, 48, CKF_DERIVE}},
    {CKM_SSL3_KEY_AND_MAC_DERIVE, {48, 48, CKF_DERIVE}},
    {CKM_SSL3_MD5_MAC, {384, 384, CKF_SIGN | CKF_VERIFY}},
    {CKM_SSL3_SHA1_MAC, {384, 384, CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_KEY_GEN, {16, 32, CKF_GENERATE}},
    {CKM_AES_XTS_KEY_GEN, {32, 64, CKF_GENERATE}},
    {CKM_AES_ECB, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_CBC, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_CBC_PAD,
     {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_CTR, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
#if OPENSSL_VERSION_PREREQ(3, 0) || OPENSSL_VERSION_NUMBER >= 0x101010cfL
    /*
     * AES-OFB currently only works with >= OpenSSl 3.0, or >= OpenSSL 1.1.1l,
     * due to a bug in OpenSSL <= 1.1.1k in s390x_aes_ofb_cipher() not updating
     * the IV in the context.
     */
    {CKM_AES_OFB, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_CFB8, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
    {CKM_AES_CFB128, {16, 32, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
#endif
    {CKM_AES_GCM, {16, 32, CKF_ENCRYPT | CKF_DECRYPT}},
    {CKM_AES_MAC, {16, 32, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_MAC_GENERAL, {16, 32, CKF_HW | CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_CMAC, {16, 32, CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_CMAC_GENERAL, {16, 32, CKF_SIGN | CKF_VERIFY}},
    {CKM_AES_XTS, {32, 64, CKF_ENCRYPT | CKF_DECRYPT | CKF_WRAP | CKF_UNWRAP}},
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
    CK_RV rc;

    rc = ock_generic_filter_mechanism_list(tokdata,
                                           soft_mech_list, soft_mech_list_len,
                                           &(tokdata->mech_list),
                                           &(tokdata->mech_list_len));
    if (rc != CKR_OK) {
        TRACE_ERROR("Mechanism filtering failed!  rc = 0x%lx\n", rc);
        return rc;
    }

    TRACE_INFO("soft %s slot=%lu running\n", __func__, SlotNumber);

    return CKR_OK;
}

CK_RV token_specific_final(STDLL_TokData_t *tokdata,
                           CK_BBOOL token_specific_final)
{
    UNUSED(token_specific_final);

    TRACE_INFO("soft %s running\n", __func__);

    free(tokdata->mech_list);
    
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

CK_RV token_specific_tdes_ofb(STDLL_TokData_t *tokdata,
                              CK_BYTE *in_data,
                              CK_BYTE *out_data,
                              CK_ULONG data_len,
                              OBJECT *key, CK_BYTE *init_v, uint_32 direction)
{
    return openssl_specific_tdes_ofb(tokdata, in_data, data_len,
                                     out_data, key, init_v, direction);
}

CK_RV token_specific_tdes_cfb(STDLL_TokData_t *tokdata,
                              CK_BYTE *in_data,
                              CK_BYTE *out_data,
                              CK_ULONG data_len,
                              OBJECT *key,
                              CK_BYTE *init_v, uint_32 cfb_len,
                              uint_32 direction)
{
    return openssl_specific_tdes_cfb(tokdata, in_data, data_len,
                                     out_data, key, init_v, cfb_len,
                                     direction);
}

CK_RV token_specific_tdes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                              CK_ULONG message_len, OBJECT *key, CK_BYTE *mac)
{
    return openssl_specific_tdes_mac(tokdata, message, message_len, key, mac);
}

CK_RV token_specific_tdes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                               CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                               CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{
    return openssl_specific_tdes_cmac(tokdata, message, message_len, key, mac,
                                      first, last, ctx);
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

CK_RV token_specific_aes_xts_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl,
                                     CK_BYTE **key, CK_ULONG *len,
                                     CK_ULONG keysize, CK_BBOOL *is_opaque)
{
    UNUSED(tmpl);

    *key = malloc(keysize);
    if (*key == NULL)
        return CKR_HOST_MEMORY;
    *len = keysize;
    *is_opaque = FALSE;

    return rng_generate(tokdata, *key, keysize);
}

CK_RV token_specific_aes_ecb(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE encrypt)
{
    UNUSED(sess);

    return openssl_specific_aes_ecb(tokdata, in_data, in_data_len,
                                    out_data, out_data_len, key, encrypt);
}

CK_RV token_specific_aes_cbc(STDLL_TokData_t *tokdata, SESSION *sess,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key, CK_BYTE *init_v, CK_BYTE encrypt)
{
    UNUSED(sess);

    return openssl_specific_aes_cbc(tokdata, in_data, in_data_len,
                                    out_data, out_data_len, key,
                                    init_v, encrypt);
}

CK_RV token_specific_aes_ctr(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             CK_ULONG *out_data_len,
                             OBJECT *key,
                             CK_BYTE *counterblock,
                             CK_ULONG counter_width, CK_BYTE encrypt)
{
    return openssl_specific_aes_ctr(tokdata, in_data, in_data_len,
                                    out_data, out_data_len, key,
                                    counterblock, counter_width, encrypt);
}

CK_RV token_specific_aes_ofb(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             OBJECT *key,
                             CK_BYTE *init_v, uint_32 direction)
{
    return openssl_specific_aes_ofb(tokdata, in_data, in_data_len,
                                    out_data, key, init_v, direction);
}

CK_RV token_specific_aes_cfb(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data,
                             OBJECT *key,
                             CK_BYTE *init_v, uint_32 cfb_len,
                             uint_32 direction)
{
    return openssl_specific_aes_cfb(tokdata, in_data, in_data_len,
                                    out_data, key, init_v, cfb_len,
                                    direction);
}

CK_RV token_specific_aes_gcm_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                  ENCR_DECR_CONTEXT *ctx, CK_MECHANISM *mech,
                                  CK_OBJECT_HANDLE key, CK_BYTE encrypt)
{
    return openssl_specific_aes_gcm_init(tokdata, sess, ctx, mech,
                                         key, encrypt);
}

CK_RV token_specific_aes_gcm(STDLL_TokData_t *tokdata, SESSION *sess,
                             ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                             CK_ULONG in_data_len, CK_BYTE *out_data,
                             CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    return openssl_specific_aes_gcm(tokdata, sess, ctx, in_data, in_data_len,
                                    out_data, out_data_len, encrypt);
}

CK_RV token_specific_aes_gcm_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                    ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                                    CK_ULONG in_data_len, CK_BYTE *out_data,
                                    CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    return openssl_specific_aes_gcm_update(tokdata, sess, ctx, in_data,
                                           in_data_len, out_data, out_data_len,
                                           encrypt);
}

CK_RV token_specific_aes_gcm_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                   ENCR_DECR_CONTEXT *ctx, CK_BYTE *out_data,
                                   CK_ULONG *out_data_len, CK_BYTE encrypt)
{
    return openssl_specific_aes_gcm_final(tokdata, sess, ctx, out_data,
                                          out_data_len, encrypt);
}

CK_RV token_specific_aes_mac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                             CK_ULONG message_len, OBJECT *key, CK_BYTE *mac)
{
    return openssl_specific_aes_mac(tokdata, message, message_len, key, mac);
}

CK_RV token_specific_aes_cmac(STDLL_TokData_t *tokdata, CK_BYTE *message,
                              CK_ULONG message_len, OBJECT *key, CK_BYTE *mac,
                              CK_BBOOL first, CK_BBOOL last, CK_VOID_PTR *ctx)
{

    return openssl_specific_aes_cmac(tokdata, message, message_len, key, mac,
                                     first, last, ctx);
}

CK_RV token_specific_aes_xts(STDLL_TokData_t *tokdata,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj, CK_BYTE *tweak,
                             CK_BOOL encrypt, CK_BBOOL initial, CK_BBOOL final,
                             CK_BYTE* iv)
{
    return openssl_specific_aes_xts(tokdata, in_data, in_data_len,
                                    out_data, out_data_len, key_obj,
                                    tweak, encrypt, initial, final, iv);
}

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
    CK_ULONG temp_bn_len, value_bits;
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

    if ((prime_attr->ulValueLen > 1024) || (prime_attr->ulValueLen < 64)) {
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

    /* CKA_VALUE_BITS is optional */
    if (template_attribute_get_ulong(priv_tmpl, CKA_VALUE_BITS,
                                     &value_bits) == CKR_OK &&
        value_bits > 0)
        DH_set_length(dh, value_bits);

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
    if (tmpl == NULL) {
        rv = CKR_HOST_MEMORY;
        goto done;
    }

    if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
        !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, bn_g)) {
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* CKA_VALUE_BITS is optional */
    if (template_attribute_get_ulong(priv_tmpl, CKA_VALUE_BITS,
                                     &value_bits) == CKR_OK) {
        if (!OSSL_PARAM_BLD_push_long(tmpl, OSSL_PKEY_PARAM_DH_PRIV_LEN,
                                      value_bits)) {
            rv = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    osparams = OSSL_PARAM_BLD_to_param(tmpl);
    if (osparams == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (pctx == NULL) {
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, &params, EVP_PKEY_PUBLIC_KEY, osparams)) {
        rv = CKR_FUNCTION_FAILED;
        goto done;
    }
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

CK_RV token_specific_sha_init(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                              CK_MECHANISM *mech)
{
    return openssl_specific_sha_init(tokdata, ctx, mech);
}

CK_RV token_specific_sha(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    return openssl_specific_sha(tokdata, ctx, in_data, in_data_len,
                                out_data, out_data_len);
}

CK_RV token_specific_sha_update(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                                CK_BYTE *in_data, CK_ULONG in_data_len)
{
    return openssl_specific_sha_update(tokdata, ctx, in_data, in_data_len);
}

CK_RV token_specific_sha_final(STDLL_TokData_t *tokdata, DIGEST_CONTEXT *ctx,
                               CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    return openssl_specific_sha_final(tokdata, ctx, out_data, out_data_len);
}

CK_RV token_specific_hmac_sign_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                    CK_MECHANISM *mech, CK_OBJECT_HANDLE Hkey)
{
    return openssl_specific_hmac_init(tokdata, &sess->sign_ctx, mech, Hkey);
}

CK_RV token_specific_hmac_verify_init(STDLL_TokData_t *tokdata, SESSION *sess,
                                      CK_MECHANISM *mech,
                                      CK_OBJECT_HANDLE Hkey)
{
    return openssl_specific_hmac_init(tokdata, &sess->verify_ctx, mech, Hkey);
}

CK_RV token_specific_hmac_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *signature, CK_ULONG *sig_len)
{
    UNUSED(tokdata);

    return openssl_specific_hmac(&sess->sign_ctx, in_data, in_data_len,
                                 signature, sig_len, TRUE);
}

CK_RV token_specific_hmac_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                                 CK_BYTE *in_data, CK_ULONG in_data_len,
                                 CK_BYTE *signature, CK_ULONG sig_len)
{
    UNUSED(tokdata);

    return openssl_specific_hmac(&sess->verify_ctx, in_data, in_data_len,
                                 signature, &sig_len, FALSE);
}

CK_RV token_specific_hmac_sign_update(STDLL_TokData_t *tokdata, SESSION *sess,
                                      CK_BYTE *in_data, CK_ULONG in_data_len)
{
    UNUSED(tokdata);

    return openssl_specific_hmac_update(&sess->sign_ctx, in_data, in_data_len,
                                        TRUE);
}

CK_RV token_specific_hmac_verify_update(STDLL_TokData_t *tokdata,
                                        SESSION *sess, CK_BYTE *in_data,
                                        CK_ULONG in_data_len)
{
    UNUSED(tokdata);

    return openssl_specific_hmac_update(&sess->verify_ctx, in_data, in_data_len,
                                        FALSE);
}

CK_RV token_specific_hmac_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                     CK_BYTE *signature, CK_ULONG *sig_len)
{
    UNUSED(tokdata);

    return openssl_specific_hmac_final(&sess->sign_ctx, signature, sig_len,
                                       TRUE);
}

CK_RV token_specific_hmac_verify_final(STDLL_TokData_t *tokdata,
                                       SESSION *sess, CK_BYTE *signature,
                                       CK_ULONG sig_len)
{
    UNUSED(tokdata);

    return openssl_specific_hmac_final(&sess->verify_ctx, signature, &sig_len,
                                       FALSE);
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

#ifndef NO_EC

CK_RV token_specific_ec_generate_keypair(STDLL_TokData_t *tokdata,
                                         TEMPLATE *publ_tmpl,
                                         TEMPLATE *priv_tmpl)
{
    return openssl_specific_ec_generate_keypair(tokdata, publ_tmpl, priv_tmpl);
}

CK_RV token_specific_ec_sign(STDLL_TokData_t *tokdata,  SESSION *sess,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj)
{
    return openssl_specific_ec_sign(tokdata, sess, in_data, in_data_len,
                                    out_data, out_data_len, key_obj);
}

CK_RV token_specific_ec_verify(STDLL_TokData_t *tokdata,
                               SESSION *sess,
                               CK_BYTE *in_data,
                               CK_ULONG in_data_len,
                               CK_BYTE *signature,
                               CK_ULONG signature_len, OBJECT *key_obj)
{
    return openssl_specific_ec_verify(tokdata, sess, in_data, in_data_len,
                                      signature, signature_len, key_obj);
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
    return openssl_specific_ecdh_pkcs_derive(tokdata, priv_bytes, priv_length,
                                             pub_bytes, pub_length,
                                             secret_value, secret_value_len,
                                             oid, oid_length);
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
        rc = openssl_make_ec_key_from_template(obj->template, &ec_key);
        if (ec_key != NULL)
                EVP_PKEY_free(ec_key);
        return rc;
#endif

    default:
        return CKR_OK;
    }
}

