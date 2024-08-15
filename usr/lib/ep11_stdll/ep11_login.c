/*
 * COPYRIGHT (c) International Business Machines Corp. 2023
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <stdint.h>

#define OCK_NO_EP11_DEFINES
#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "trace.h"

#include <openssl/evp.h>
#include <openssl/ec.h>
#include <openssl/x509.h>
#if OPENSSL_VERSION_PREREQ(3, 0)
#include <openssl/core_names.h>
#endif

#include "ep11_specific.h"

static const CK_BYTE zero_session[XCP_WK_BYTES] = { 0 };

static const CK_BYTE OID_IBM_misc_ep11_session_info[] = {
        0x06, 0x0c, 0x2b, 0x06, 0x01, 0x04, 0x01,
        0x02, 0x82, 0x0b, 0x87, 0x67, 0x04, 0x01
};

static CK_RV generate_ec_session_key(XCP_LoginImporter_t imp_keytype,
                                     EVP_PKEY **ec_privkey)
{
    EVP_PKEY_CTX *ctx = NULL;
    CK_RV rc = CKR_FUNCTION_FAILED;
    int nid;

    switch (imp_keytype) {
    case XCP_LOGIN_IMPR_EC_P256:
        nid = NID_X9_62_prime256v1;
        break;
    case XCP_LOGIN_IMPR_EC_P521:
        nid = NID_secp521r1;
        break;
    default:
        TRACE_ERROR("%s Unsupported importer key type: %d\n",
                    __func__, imp_keytype);
        return CKR_ARGUMENTS_BAD;
    }

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("%s EVP_PKEY_CTX_new_id failed\n", __func__);
        goto out;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        TRACE_ERROR("%s EVP_PKEY_keygen_init failed\n", __func__);
        goto out;
    }

    if (EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) <= 0) {
        TRACE_ERROR("%s EVP_PKEY_CTX_set_ec_paramgen_curve_nid failed\n",
                    __func__);
        goto out;
    }

    if (EVP_PKEY_keygen(ctx, ec_privkey) <= 0) {
        TRACE_ERROR("%s EVP_PKEY_keygen failed\n", __func__);
        goto out;
    }

    rc = CKR_OK;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return rc;
}

static CK_RV get_login_importer_key(target_t target,
                                    XCP_LoginImporter_t imp_keytype,
                                    CK_BYTE ski[XCP_CERTHASH_BYTES],
                                    CK_BYTE tcounter[XCP_ADMCTR_BYTES],
                                    EVP_PKEY **ec_pubkey)
{
    CK_BYTE res[XCP_LOGIN_IMPR_MAX_SIZE];
    CK_ULONG reslen = sizeof(res);
    CK_BYTE *data = NULL, *spki = NULL, *ski_field = NULL, *cnt = NULL;
    CK_ULONG data_len = 0, field_len = 0;
    CK_ULONG spki_len = 0, ski_field_len, cnt_len = 0;
    const unsigned char *p;
    CK_RV rc;

    rc = dll_m_get_xcp_info(res, &reslen, CK_IBM_XCPQ_LOGIN_IMPORTER,
                            imp_keytype, target);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to query Login Importer key: 0x%lx\n",
                    __func__, rc);
        return CKR_FUNCTION_FAILED;
    }

    /*
     * xcpRsp ::= SEQUENCE
     *             SKI OCTET STRING,
     *             SPKI OCTET STRING (SEQUENCE ...),
     *             tcounter OCTET STRING  (16 bytes)
     */

    rc = ber_decode_SEQUENCE(res, &data, &data_len, &field_len);
    if (rc != CKR_OK || field_len > reslen) {
        TRACE_ERROR("%s ber_decode_SEQUENCE failed\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = ber_decode_OCTET_STRING(data, &ski_field, &ski_field_len, &field_len);
    if (rc != CKR_OK || field_len > data_len) {
        TRACE_ERROR("%s ber_decode_OCTET_STRING (SKI) failed\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    data += field_len;
    data_len -= field_len;

    rc = ber_decode_OCTET_STRING(data, &spki, &spki_len, &field_len);
    if (rc != CKR_OK || field_len > data_len) {
        TRACE_ERROR("%s ber_decode_OCTET_STRING (SPKI) failed\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    data += field_len;
    data_len -= field_len;

    rc = ber_decode_OCTET_STRING(data, &cnt, &cnt_len, &field_len);
    if (rc != CKR_OK || field_len > data_len) {
        TRACE_ERROR("%s ber_decode_OCTET_STRING (COUNTER) failed\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

#ifdef DEBUG
        TRACE_DEBUG("SKI (size: %lu):\n", ski_field_len);
        TRACE_DEBUG_DUMP("    ", ski_field, ski_field_len);
        TRACE_DEBUG("SPKI (size: %lu):\n", spki_len);
        TRACE_DEBUG_DUMP("    ", spki, spki_len);
        TRACE_DEBUG("TCounter (size: %lu):\n", cnt_len);
        TRACE_DEBUG_DUMP("    ", cnt, cnt_len);
#endif

    if (ski_field_len != XCP_CERTHASH_BYTES) {
        TRACE_ERROR("%s SKI length is not as expected (%lu != %u)\n", __func__,
                    ski_field_len, XCP_CERTHASH_BYTES);
        return CKR_BUFFER_TOO_SMALL;
    }
    memcpy(ski, ski_field, ski_field_len);

    if (cnt_len > XCP_ADMCTR_BYTES) {
        TRACE_ERROR("%s counter length is too large (%lu > %lu)\n", __func__,
                    cnt_len, XCP_ADMCTR_BYTES);
        return CKR_FUNCTION_FAILED;
    }
    memset(tcounter, 0, XCP_ADMCTR_BYTES - cnt_len);
    memcpy(tcounter + XCP_ADMCTR_BYTES - cnt_len, cnt, cnt_len);

    p = (const unsigned char *)spki;
    *ec_pubkey = d2i_PUBKEY(NULL, &p, spki_len);
    if (*ec_pubkey == NULL) {
        TRACE_ERROR("%s d2i_PUBKEY failed\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    return rc;
}

static void increment_tcounter(CK_BYTE tcounter[XCP_ADMCTR_BYTES])
{
    int i;

    for (i = XCP_ADMCTR_BYTES - 1; i >= 0; i--) {
        tcounter[i]++;
        if (tcounter[i] != 0)
            break;
    }

#ifdef DEBUG
    TRACE_DEBUG("TCounter after increment:\n");
    TRACE_DEBUG_DUMP("    ", tcounter, XCP_ADMCTR_BYTES);
#endif
}

static CK_RV ecdh_derive(EVP_PKEY *privkey, EVP_PKEY *pubkey,
                         CK_BYTE *secret, CK_ULONG *secret_len)
{
    CK_RV rc = CKR_FUNCTION_FAILED;
    EVP_PKEY_CTX *ctx = NULL;

    ctx = EVP_PKEY_CTX_new(privkey, NULL);
    if (ctx == NULL) {
        TRACE_ERROR("%s EVP_PKEY_CTX_new failed\n", __func__);
        goto out;
    }

    if (EVP_PKEY_derive_init(ctx) <= 0) {
        TRACE_ERROR("%s EVP_PKEY_derive_init failed\n", __func__);
        goto out;
    }

    if (EVP_PKEY_derive_set_peer(ctx, pubkey) != 1) {
        TRACE_ERROR("%s EVP_PKEY_derive_set_peer failed\n", __func__);
        goto out;
    }

    if (EVP_PKEY_derive(ctx, secret, secret_len) <= 0) {
        TRACE_ERROR("%s EVP_PKEY_derive failed\n", __func__);
        goto out;
    }

#ifdef DEBUG
    TRACE_DEBUG("Shared secret (%lu bytes):\n", *secret_len);
    TRACE_DEBUG_DUMP("    ", secret, *secret_len);
#endif

    rc = CKR_OK;

out:
    if (ctx != NULL)
        EVP_PKEY_CTX_free(ctx);

    return rc;
}

#if OPENSSL_VERSION_PREREQ(3, 0)
static int ec_prime_len_from_nid(int nid)
{
    EC_GROUP *group;
    int primelen;

    group = EC_GROUP_new_by_curve_name(nid);
    if (group == NULL)
        return -1;

    primelen = EC_GROUP_order_bits(group);

    EC_GROUP_free(group);

    return (primelen + 7) / 8;
}
#endif

static int ec_prime_len_from_pkey(EVP_PKEY *pkey)
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

static CK_RV ec_x_from_pkey(EVP_PKEY *pkey, CK_BYTE *x, CK_ULONG *x_len)
{
    int prime_len;
#if OPENSSL_VERSION_PREREQ(3, 0)
    OSSL_PARAM params[2];
#else
    const EC_KEY *ec_key;
    BIGNUM *bn_x = NULL;
#endif

    prime_len = ec_prime_len_from_pkey(pkey);
    if (prime_len < 0) {
        TRACE_ERROR("%s ec_prime_len_from_pkey failed\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (*x_len < (CK_ULONG)prime_len) {
        TRACE_ERROR("%s X buffer too small\n", __func__);
        return CKR_BUFFER_TOO_SMALL;
    }
    *x_len = prime_len;

#if OPENSSL_VERSION_PREREQ(3, 0)
    params[0] = OSSL_PARAM_construct_BN(OSSL_PKEY_PARAM_EC_PUB_X, x, *x_len);
    params[1] = OSSL_PARAM_construct_end();
    if (EVP_PKEY_get_params(pkey, params) != 1 ||
        !OSSL_PARAM_modified(&params[0])) {
        TRACE_ERROR("%s EVP_PKEY_get_params failed\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
#else
    ec_key = EVP_PKEY_get0_EC_KEY(pkey);
    if (ec_key == NULL) {
        TRACE_ERROR("EVP_PKEY_get0_EC_KEY failed\n");
        return CKR_FUNCTION_FAILED;
    }

    bn_x = BN_new();
    if (bn_x == NULL) {
        TRACE_ERROR("BN_new failed\n");
        return CKR_HOST_MEMORY;
    }

    if (!EC_POINT_get_affine_coordinates(EC_KEY_get0_group(ec_key),
                                         EC_KEY_get0_public_key(ec_key),
                                         bn_x, NULL, NULL)) {
        TRACE_ERROR("EC_POINT_get_affine_coordinates failed\n");
        BN_free(bn_x);
        return CKR_FUNCTION_FAILED;
    }

    if (BN_bn2binpad(bn_x, x, *x_len) != (int)*x_len) {
        TRACE_ERROR("BN_bn2binpad failed\n");
        BN_free(bn_x);
        return CKR_FUNCTION_FAILED;
    }

    BN_free(bn_x);
#endif

#ifdef DEBUG
    TRACE_DEBUG("EC coordinate X (%lu bytes):\n", *x_len);
    TRACE_DEBUG_DUMP("    ", x, *x_len);
#endif

    return CKR_OK;
}

static CK_RV kdf_sp800_56c_sha256(EVP_PKEY *ec_privkey,
                                  CK_BYTE *secret, CK_ULONG secret_len,
                                  CK_BYTE key[AES_KEY_SIZE_256])
{
    CK_RV rc = CKR_FUNCTION_FAILED;
    EVP_MD_CTX *ctx = NULL;
    CK_BYTE x[256];
    CK_ULONG x_len = sizeof(x);
    uint32_t be32_1 = htobe32(1);
    unsigned int md_len = AES_KEY_SIZE_256;

    /*
     * key = SHA256( BE32(1)
     *            || BE32(1)
     *            || secret
     *            || X coordinate of callers public key Qe )
     */

    rc = ec_x_from_pkey(ec_privkey, x, &x_len);
    if (rc != CKR_OK)
        return rc;

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s EVP_MD_CTX_new failed\n", __func__);
        goto out;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        TRACE_ERROR("%s EVP_DigestInit_ex failed\n", __func__);
        goto out;
    }

    if (EVP_DigestUpdate(ctx, &be32_1, sizeof(be32_1)) != 1) {
        TRACE_ERROR("%s EVP_DigestUpdate failed\n", __func__);
        goto out;
    }

    if (EVP_DigestUpdate(ctx, &be32_1, sizeof(be32_1)) != 1) {
        TRACE_ERROR("%s EVP_DigestUpdate failed\n", __func__);
        goto out;
    }

    if (EVP_DigestUpdate(ctx, secret, secret_len) != 1) {
        TRACE_ERROR("%s EVP_DigestUpdate failed\n", __func__);
        goto out;
    }

    if (EVP_DigestUpdate(ctx, x, x_len) != 1) {
        TRACE_ERROR("%s EVP_DigestUpdate failed\n", __func__);
        goto out;
    }

    if (EVP_DigestFinal(ctx, key, &md_len) != 1 ||
        md_len != AES_KEY_SIZE_256) {
        TRACE_ERROR("%s EVP_DigestFinal failed\n", __func__);
        goto out;
    }

#ifdef DEBUG
    TRACE_DEBUG("Derived key (%u bytes):\n", AES_KEY_SIZE_256);
    TRACE_DEBUG_DUMP("    ", key, AES_KEY_SIZE_256);
#endif

    rc = CKR_OK;

out:
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);

    return rc;
}

static CK_RV create_login_recipient(const CK_BYTE ski[XCP_CERTHASH_BYTES],
                                    EVP_PKEY *ec_privkey,
                                    CK_BYTE **buf, CK_ULONG *buf_len)
{
    CK_RV rc;
    CK_BBOOL length_only = (buf == NULL);
    uint32_t version = htobe32(1);
    CK_BYTE *spki = NULL, *data = NULL;
    CK_BYTE *v1_os = NULL, *ski_os = NULL, *spki_os = NULL;
    CK_ULONG v1_os_len, ski_os_len, spki_os_len, data_len, ofs;
    int spki_len;

    /*
     * LoginRecipient ::= SEQUENCE
     *           OCTET STRING <00000001> -- v1
     *           OCTET STRING <SKI>      -- SKI (recipient)
     *           OCTET STRING (
     *                 SEQUENCE ...      -- SPKI (sender)
     *           )
     */
    spki_len = i2d_PUBKEY(ec_privkey, length_only ? NULL : &spki);
    if (spki_len <= 0 || (spki == NULL && !length_only)) {
        TRACE_ERROR("%s i2d_PUBKEY failed\n", __func__);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

#ifdef DEBUG
    TRACE_DEBUG("SPKI (%u bytes):\n", spki_len);
    if (!length_only) {
        TRACE_DEBUG_DUMP("    ", spki, spki_len);
    }
#endif

    rc = ber_encode_OCTET_STRING(length_only, &v1_os, &v1_os_len,
                                 (CK_BYTE *)&version, sizeof(version));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (VERSION) failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &ski_os, &ski_os_len,
                                 (CK_BYTE *)ski, XCP_CERTHASH_BYTES);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (SKI) failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &spki_os, &spki_os_len,
                                 spki, spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (SPKI) failed\n", __func__);
        goto out;
    }

    data_len = v1_os_len + ski_os_len + spki_os_len;
    if (!length_only) {
        data = malloc(data_len);
        if (data == NULL) {
            TRACE_ERROR("%s Failed to allocate data buffer\n", __func__);
            rc = CKR_HOST_MEMORY;
            goto out;
        }

        ofs = 0;
        memcpy(data + ofs, v1_os, v1_os_len);
        ofs += v1_os_len;
        memcpy(data + ofs, ski_os, ski_os_len);
        ofs += ski_os_len;
        memcpy(data + ofs, spki_os, spki_os_len);
    }

    rc = ber_encode_SEQUENCE(length_only, buf, buf_len, data, data_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_SEQUENCE failed\n", __func__);
        goto out;
    }

#ifdef DEBUG
    TRACE_DEBUG("Login recipient (%lu bytes):\n", *buf_len);
    if (!length_only) {
        TRACE_DEBUG_DUMP("    ", *buf, *buf_len);
    }
#endif

out:
    if (spki != NULL)
        OPENSSL_free(spki);
    if (v1_os != NULL)
        free(v1_os);
    if (ski_os != NULL)
        free(ski_os);
    if (spki_os != NULL)
        free(spki_os);
    if (data != NULL)
        free(data);

    return rc;
}

static CK_RV create_login_extended_info(const CK_BYTE ski[XCP_CERTHASH_BYTES],
                                        XCP_LoginAlgorithm_t login_alg,
                                        const CK_BYTE *parent_session_id,
                                        EVP_PKEY *ec_privkey,
                                        CK_BYTE **buf, CK_ULONG *buf_len)
{
    CK_RV rc;
    CK_BBOOL length_only = (buf == NULL);
    uint32_t alg = htobe32(login_alg);
    CK_BYTE *recipient = NULL, *data = NULL;
    CK_ULONG recipient_len, data_len, ofs;
    CK_BYTE *vers_os = NULL, *alg_os = NULL, *parent_os = NULL;
    CK_BYTE *recipient_os = NULL, *attr_os = NULL, *ctx_os = NULL;
    CK_ULONG vers_os_len, alg_os_len, parent_os_len, recipient_os_len;
    CK_ULONG attr_os_len, ctx_os_len;

    /*
     * CK_IBM_LOGIN_EXTENDED_INFO ::= SEQUENCE
     *    version      OCTET STRING -- OBJECT IDENTIFIER
     *                                       OID_IBM_misc_ep11_session_info)
     *                                       -- 1.3.6.1.4.1.2.267.999.4.1
     *    algorithm    OCTET STRING -- derivation algorithm, 4 Bytes
     *    parent       OCTET STRING -- parent session id, 32 Bytes, may be zero
     *    recipient    OCTET STRING -- OPTIONAL: recipient info
     *    attributes   OCTET STRING -- OPTIONAL: session attributes, 8 Bytes
     *    context      OCTET STRING -- OPTIONAL: additional session context
     */

    rc = create_login_recipient(ski, ec_privkey, length_only ? NULL :
                                                 &recipient, &recipient_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s create_login_recipient failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &vers_os, &vers_os_len,
                                 (CK_BYTE *)OID_IBM_misc_ep11_session_info,
                                 sizeof(OID_IBM_misc_ep11_session_info));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (VERSION) failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &alg_os, &alg_os_len,
                                 (CK_BYTE *)&alg, sizeof(alg));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (ALG) failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &parent_os, &parent_os_len,
                                 (CK_BYTE *)(parent_session_id != NULL ?
                                                 parent_session_id :
                                                 zero_session),
                                 XCP_WK_BYTES);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (PARENT) failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &recipient_os, &recipient_os_len,
                                 recipient, recipient_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (RECIPIENT) failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &attr_os, &attr_os_len,
                                 (CK_BYTE *)"", 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (ATTRS) failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &ctx_os, &ctx_os_len,
                                 (CK_BYTE *)"", 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (CONTEXT) failed\n", __func__);
        goto out;
    }

    data_len = vers_os_len + alg_os_len + parent_os_len +
                        recipient_os_len + attr_os_len + ctx_os_len;
    if (!length_only) {
        data = malloc(data_len);
        if (data == NULL) {
            TRACE_ERROR("%s Failed to allocate data buffer\n", __func__);
            rc = CKR_HOST_MEMORY;
            goto out;
        }

        ofs = 0;
        memcpy(data + ofs, vers_os, vers_os_len);
        ofs += vers_os_len;
        memcpy(data + ofs, alg_os, alg_os_len);
        ofs += alg_os_len;
        memcpy(data + ofs, parent_os, parent_os_len);
        ofs += parent_os_len;
        memcpy(data + ofs, recipient_os, recipient_os_len);
        ofs += recipient_os_len;
        memcpy(data + ofs, attr_os, attr_os_len);
        ofs += attr_os_len;
        memcpy(data + ofs, ctx_os, ctx_os_len);
    }

    rc = ber_encode_SEQUENCE(length_only, buf, buf_len, data, data_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_SEQUENCE failed\n", __func__);
        goto out;
    }

#ifdef DEBUG
    TRACE_DEBUG("Login extended info (%lu bytes):\n", *buf_len);
    if (!length_only) {
        TRACE_DEBUG_DUMP("    ", *buf, *buf_len);
    }
#endif

out:
    if (recipient != NULL)
        free(recipient);
    if (vers_os != NULL)
        free(vers_os);
    if (alg_os != NULL)
        free(alg_os);
    if (parent_os != NULL)
        free(parent_os);
    if (recipient_os != NULL)
        free(recipient_os);
    if (attr_os != NULL)
        free(attr_os);
    if (ctx_os != NULL)
        free(ctx_os);
    if (data != NULL)
        free(data);

    return rc;
}

static CK_RV create_padded_pin(const CK_BYTE *pin, CK_ULONG pin_len,
                               const CK_BYTE tcounter[XCP_ADMCTR_BYTES],
                               int func_id,
                               CK_BYTE **buf, CK_ULONG *buf_len)
{
    CK_RV rc;
    CK_BBOOL length_only = (buf == NULL);
    uint32_t version = htobe32(1);
    uint32_t fnid = htobe32(func_id);
    CK_BYTE *vers_os = NULL, *fnid_os = NULL, *counter_os = NULL;
    CK_BYTE *pin_os = NULL, *data = NULL;
    CK_ULONG vers_os_len, fnid_os_len, counter_os_len, pin_os_len;
    CK_ULONG data_len, ofs;

    /*
     * PaddedPIN ::= SEQUENCE
     *              OCTET STRING <00000001> -- v1
     *              OCTET STRING <BE32 in-band data> -- function ID targeted
     *                                           - LoginExtended/LogoutExtended
     *              OCTET STRING <BE128 tctr> -- transaction counter +1
     *              OCTET STRING <PIN> -- user-provided PIN
     */

    rc = ber_encode_OCTET_STRING(length_only, &vers_os, &vers_os_len,
                                 (CK_BYTE *)&version, sizeof(version));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (VERSION) failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &fnid_os, &fnid_os_len,
                                 (CK_BYTE *)&fnid, sizeof(fnid));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (FNID) failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &counter_os, &counter_os_len,
                                 (CK_BYTE *)tcounter, XCP_ADMCTR_BYTES);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (COUNTER) failed\n", __func__);
        goto out;
    }

    rc = ber_encode_OCTET_STRING(length_only, &pin_os, &pin_os_len,
                                 (CK_BYTE *)pin, pin_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_OCTET_STRING (PIN) failed\n", __func__);
        goto out;
    }

    data_len = vers_os_len + fnid_os_len + counter_os_len + pin_os_len;
    if (!length_only) {
        data = malloc(data_len);
        if (data == NULL) {
            TRACE_ERROR("%s Failed to allocate data buffer\n", __func__);
            rc = CKR_HOST_MEMORY;
            goto out;
        }

        ofs = 0;
        memcpy(data + ofs, vers_os, vers_os_len);
        ofs += vers_os_len;
        memcpy(data + ofs, fnid_os, fnid_os_len);
        ofs += fnid_os_len;
        memcpy(data + ofs, counter_os, counter_os_len);
        ofs += counter_os_len;
        memcpy(data + ofs, pin_os, pin_os_len);
    }

    rc = ber_encode_SEQUENCE(length_only, buf, buf_len, data, data_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_encode_SEQUENCE failed\n", __func__);
        goto out;
    }

#ifdef DEBUG
    TRACE_DEBUG("Padded pin (%lu bytes):\n", *buf_len);
    if (!length_only) {
        TRACE_DEBUG_DUMP("    ", *buf, *buf_len);
    }
#endif

out:
    if (vers_os != NULL)
        free(vers_os);
    if (fnid_os != NULL)
        free(fnid_os);
    if (counter_os != NULL)
        free(counter_os);
    if (pin_os != NULL)
        free(pin_os);
    if (data != NULL)
        free(data);

    return rc;
}

static CK_ULONG aes_256_wrap_pad_encrypt_len(CK_ULONG clear_len)
{
    CK_ULONG enc_len;

    /*
     *  aes_256_wrap_pad encrypt pads up to 8 bytes if the input length is
     *  not a multiple of 8 bytes, and it always adds an authentication tag of
     *  8 bytes.
     */
    enc_len = clear_len;
    if (clear_len % 8 > 0)
        enc_len += 8 - (clear_len % 8);

    return enc_len + 8;
}

static CK_RV encrypt_padded_pin(const CK_BYTE* padded_pin,
                                CK_ULONG padded_pin_len,
                                const CK_BYTE key[AES_KEY_SIZE_256],
                                CK_BYTE **buf, CK_ULONG *buf_len)
{
    CK_RV rc = CKR_FUNCTION_FAILED;
    EVP_CIPHER_CTX *ctx;
    int len, total_len;

    if (buf == NULL) {
        *buf_len = aes_256_wrap_pad_encrypt_len(padded_pin_len);
        return CKR_OK;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s EVP_CIPHER_CTX_new failed\n", __func__);
        goto out;
    }

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap_pad(), NULL, key, NULL) != 1) {
        TRACE_ERROR("%s EVP_EncryptInit_ex failed\n", __func__);
        goto out;
    }

    total_len = aes_256_wrap_pad_encrypt_len(padded_pin_len);
    *buf = malloc(total_len);
    if (*buf == NULL) {
        TRACE_ERROR("%s Failed to allocate output buffer\n", __func__);
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    len  = total_len;
    if (EVP_EncryptUpdate(ctx, *buf, &len, padded_pin, padded_pin_len) != 1) {
        TRACE_ERROR("%s EVP_EncryptUpdate failed\n", __func__);
        goto out;
    }

    *buf_len = len;
    len = total_len - len;
    if (EVP_EncryptFinal(ctx, (*buf) + *buf_len, &len) != 1) {
        TRACE_ERROR("%s EVP_EncryptFinal failed\n", __func__);
        goto out;
    }

    *buf_len += len;

#ifdef DEBUG
    TRACE_DEBUG("Encrypted padded pin (%lu bytes):\n", *buf_len);
    TRACE_DEBUG_DUMP("    ", *buf, *buf_len);
#endif

    rc = CKR_OK;

out:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);

    return rc;
}

static CK_RV decrypt_pinblob(const CK_BYTE *enc_pinblob,
                             CK_ULONG enc_pinblob_len,
                             const CK_BYTE key[AES_KEY_SIZE_256],
                             CK_BYTE *pinblob, CK_ULONG *pinblob_len)
{
    CK_RV rc = CKR_FUNCTION_FAILED;
    EVP_CIPHER_CTX *ctx;
    int len, remaining;

#ifdef DEBUG
    TRACE_DEBUG("Encrypted pin blob (%lu bytes):\n", enc_pinblob_len);
    TRACE_DEBUG_DUMP("    ", (CK_BYTE *)enc_pinblob, enc_pinblob_len);
#endif

    if (*pinblob_len < enc_pinblob_len - 8) {
        TRACE_ERROR("%s pin blob buffer is too small\n", __func__);
        return CKR_BUFFER_TOO_SMALL;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s EVP_CIPHER_CTX_new failed\n", __func__);
        goto out;
    }

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_wrap_pad(), NULL, key, NULL) != 1) {
        TRACE_ERROR("%s EVP_DecryptInit_ex failed\n", __func__);
        goto out;
    }

    len = *pinblob_len;
    if (EVP_DecryptUpdate(ctx, pinblob, &len,
                          enc_pinblob, enc_pinblob_len) != 1) {
        TRACE_ERROR("%s EVP_DecryptUpdate failed\n", __func__);
        goto out;
    }

    remaining = *pinblob_len - len;
    *pinblob_len = len;
    len = remaining;

    if (EVP_DecryptFinal(ctx, pinblob + *pinblob_len, &len) != 1) {
        TRACE_ERROR("%s EVP_DecryptFinal failed\n", __func__);
        goto out;
    }

    *pinblob_len += len;

#ifdef DEBUG
    TRACE_DEBUG("Clear pin blob (%lu bytes):\n", *pinblob_len);
    TRACE_DEBUG_DUMP("    ", pinblob, *pinblob_len);
#endif

    rc = CKR_OK;

out:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);

    return rc;
}

static CK_RV derive_pinblob_key(const CK_BYTE *pinblob, CK_ULONG pinblob_len,
                                const CK_BYTE *pin, CK_ULONG pin_len,
                                CK_BYTE key[AES_KEY_SIZE_256])
{
    CK_RV rc = CKR_FUNCTION_FAILED;
    EVP_MD_CTX *ctx = NULL;
    uint32_t  be32_1 = htobe32(1);
    uint32_t  be32_3 = htobe32(3);
    uint8_t be8_0 = 0;
    unsigned int md_len = AES_KEY_SIZE_256;

    /*
     * CLear pin blob:
     *   SKM     32      session key modifier
     *   s       16      intermediate value for operational pinblob /
     *                   session identifier calculation
     */

    if (pinblob_len != 48 ||
        pinblob[EP11_PINBLOB_MARKER_OFS] != EP11_PINBLOB_V1_MARKER) {
        TRACE_ERROR("%s pinblob is invalid\n", __func__);
        goto out;
    }

    /* key = SHA-256(BE32(1) || BE32(3) || PIN || BE8(0) || s) */

    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s EVP_MD_CTX_new failed\n", __func__);
        goto out;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1) {
        TRACE_ERROR("%s EVP_DigestInit_ex failed\n", __func__);
        goto out;
    }

    if (EVP_DigestUpdate(ctx, &be32_1, sizeof(be32_1)) != 1) {
        TRACE_ERROR("%s EVP_DigestUpdate failed\n", __func__);
        goto out;
    }

    if (EVP_DigestUpdate(ctx, &be32_3, sizeof(be32_3)) != 1) {
        TRACE_ERROR("%s EVP_DigestUpdate failed\n", __func__);
        goto out;
    }

    if (EVP_DigestUpdate(ctx, pin, pin_len) != 1) {
        TRACE_ERROR("%s EVP_DigestUpdate failed\n", __func__);
        goto out;
    }

    if (EVP_DigestUpdate(ctx, &be8_0, sizeof(be8_0)) != 1) {
        TRACE_ERROR("%s EVP_DigestUpdate failed\n", __func__);
        goto out;
    }

    if (EVP_DigestUpdate(ctx, pinblob + XCP_WK_BYTES, 16) != 1) {
        TRACE_ERROR("%s EVP_DigestUpdate failed\n", __func__);
        goto out;
    }

    if (EVP_DigestFinal(ctx, key, &md_len) != 1 ||
        md_len != AES_KEY_SIZE_256) {
        TRACE_ERROR("%s EVP_DigestFinal failed\n", __func__);
        goto out;
    }

#ifdef DEBUG
    TRACE_DEBUG("Derived pin blob key (%u bytes):\n", AES_KEY_SIZE_256);
    TRACE_DEBUG_DUMP("    ", key, AES_KEY_SIZE_256);
#endif

    rc = CKR_OK;

out:
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);

    return rc;
}

static CK_RV encrypt_pinblob(const CK_BYTE *pinblob, CK_ULONG pinblob_len,
                             const CK_BYTE key[AES_KEY_SIZE_256],
                             CK_BYTE *op_pinblob, CK_ULONG *op_pinblob_len)
{
    CK_RV rc = CKR_FUNCTION_FAILED;
    EVP_CIPHER_CTX *ctx;
    int len, len2;

    if (aes_256_wrap_pad_encrypt_len(pinblob_len) > *op_pinblob_len) {
        TRACE_ERROR("%s pin blob buffer is too small\n", __func__);
        return CKR_BUFFER_TOO_SMALL;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        TRACE_ERROR("%s EVP_CIPHER_CTX_new failed\n", __func__);
        goto out;
    }

    EVP_CIPHER_CTX_set_flags(ctx, EVP_CIPHER_CTX_FLAG_WRAP_ALLOW);

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_wrap_pad(), NULL, key, NULL) != 1) {
        TRACE_ERROR("%s EVP_EncryptInit_ex failed\n", __func__);
        goto out;
    }

    len = *op_pinblob_len;
    if (EVP_EncryptUpdate(ctx, op_pinblob, &len, pinblob, pinblob_len) != 1) {
        TRACE_ERROR("%s EVP_EncryptUpdate failed\n", __func__);
        goto out;
    }

    len2 = *op_pinblob_len - len;
    if (EVP_EncryptFinal(ctx, op_pinblob + len, &len2) != 1) {
        TRACE_ERROR("%s EVP_EncryptFinal failed\n", __func__);
        goto out;
    }

    *op_pinblob_len = len + len2;

    op_pinblob[EP11_PINBLOB_MARKER_OFS] = EP11_PINBLOB_V1_MARKER;
    if (op_pinblob[0] == 0x30)
        op_pinblob[0] = 0xcc;

#ifdef DEBUG
    TRACE_DEBUG("Operational pin blob (%lu bytes):\n", *op_pinblob_len);
    TRACE_DEBUG_DUMP("    ", op_pinblob, *op_pinblob_len);
#endif

    rc = CKR_OK;

out:
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);

    return rc;
}

static CK_RV do_LoginLogoutExtended(int func_id, XCP_LoginAlgorithm_t alg,
                                    XCP_LoginImporter_t imp_keytype,
                                    const CK_BYTE *pin, CK_ULONG pin_len,
                                    const CK_BYTE *nonce, CK_ULONG nonce_len,
                                    CK_BYTE *pin_blob, CK_ULONG *pin_blob_len,
                                    const CK_BYTE *parent_session_id,
                                    target_t target)
{
    CK_BYTE peer_ski[XCP_CERTHASH_BYTES];
    CK_BYTE tcounter[XCP_ADMCTR_BYTES];
    CK_BYTE shared_secret[256];
    CK_ULONG shared_secret_len = sizeof(shared_secret);
    CK_BYTE shared_key[AES_KEY_SIZE_256];
    CK_BYTE *extended_info = NULL;
    CK_ULONG extended_info_len = 0;
    CK_BYTE *padded_pin = NULL;
    CK_ULONG padded_pin_len = 0;
    CK_BYTE *enc_padded_pin = NULL;
    CK_ULONG enc_padded_pin_len = 0;
    EVP_PKEY *local_ec_privkey = NULL, *peer_ec_pubkey = NULL;
    CK_BYTE enc_pinblob[XCP_PINBLOB_V1_BYTES];
    CK_ULONG enc_pinblob_len = sizeof(enc_pinblob);
    CK_BYTE clear_pinblob[XCP_PINBLOB_V1_BYTES];
    CK_ULONG clear_pinblob_len = sizeof(clear_pinblob);
    CK_BYTE pinblob_key[AES_KEY_SIZE_256];
    CK_ULONG retry_cnt = 0;
    CK_RV rc;

    if (alg != XCP_LOGIN_ALG_F2021) {
        TRACE_ERROR("%s Unsupported login algorithm: %u\n", __func__, alg);
        return CKR_ARGUMENTS_BAD;
    }

    rc = generate_ec_session_key(imp_keytype, &local_ec_privkey);
    if (rc != CKR_OK)
        goto done;

retry:
    rc = get_login_importer_key(target, imp_keytype, peer_ski,
                                tcounter, &peer_ec_pubkey);
    if (rc != CKR_OK)
        goto done;

    rc = ecdh_derive(local_ec_privkey, peer_ec_pubkey,
                     shared_secret, &shared_secret_len);
    if (rc != CKR_OK)
        goto done;

    rc = kdf_sp800_56c_sha256(local_ec_privkey,
                              shared_secret, shared_secret_len,
                              shared_key);
    if (rc != CKR_OK)
        goto done;

    rc = create_login_extended_info(peer_ski, alg, parent_session_id,
                                    local_ec_privkey,
                                    &extended_info, &extended_info_len);
    if (rc != CKR_OK)
        goto done;

    increment_tcounter(tcounter);

    rc = create_padded_pin(pin, pin_len, tcounter, func_id,
                           &padded_pin, &padded_pin_len);
    if (rc != CKR_OK)
        goto done;

    rc = encrypt_padded_pin(padded_pin, padded_pin_len, shared_key,
                            &enc_padded_pin, &enc_padded_pin_len);
    if (rc != CKR_OK)
        goto done;

    switch (func_id) {
    case __FNID_LoginExtended:
        rc = dll_m_LoginExtended(enc_padded_pin, enc_padded_pin_len,
                                 nonce, nonce_len,
                                 extended_info, extended_info_len,
                                 enc_pinblob, &enc_pinblob_len,
                                 target);
        break;
    case __FNID_LogoutExtended:
        rc = dll_m_LogoutExtended(enc_padded_pin, enc_padded_pin_len,
                                  nonce, nonce_len,
                                  extended_info, extended_info_len,
                                  target);
        break;
    default:
        TRACE_ERROR("%s Unsupported function: %u\n", __func__, func_id);
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        break;
    }

    if (rc == CKR_DATA_INVALID && retry_cnt < MAX_RETRY_COUNT) {
        /*
         * Transaction counter was modified by other process concurrently.
         * Retry with updated counter.
         */
        if (peer_ec_pubkey != NULL) {
            EVP_PKEY_free(peer_ec_pubkey);
            peer_ec_pubkey = NULL;
        }
        if (extended_info != NULL) {
            free(extended_info);
            extended_info = NULL;
        }
        if (padded_pin != NULL) {
            OPENSSL_cleanse(padded_pin, padded_pin_len);
            free(padded_pin);
            padded_pin = NULL;
        }
        if (enc_padded_pin != NULL) {
            OPENSSL_cleanse(enc_padded_pin, enc_padded_pin_len);
            free(enc_padded_pin);
            enc_padded_pin = NULL;
        }
        OPENSSL_cleanse(shared_key, sizeof(shared_key));
        OPENSSL_cleanse(shared_secret, shared_secret_len);

        retry_cnt++;
        goto retry;
    }

    if (rc != CKR_OK)
        goto done;

    if (func_id == __FNID_LogoutExtended)
        goto done;

    rc = decrypt_pinblob(enc_pinblob, enc_pinblob_len, shared_key,
                         clear_pinblob, &clear_pinblob_len);
    if (rc != CKR_OK)
        goto done;

    rc = derive_pinblob_key(clear_pinblob, clear_pinblob_len, pin, pin_len,
                            pinblob_key);
    if (rc != CKR_OK)
        goto done;

    rc = encrypt_pinblob(clear_pinblob, clear_pinblob_len, pinblob_key,
                         pin_blob, pin_blob_len);
    if (rc != CKR_OK)
        goto done;

done:
    if (local_ec_privkey != NULL)
        EVP_PKEY_free(local_ec_privkey);
    if (peer_ec_pubkey != NULL)
        EVP_PKEY_free(peer_ec_pubkey);
    if (extended_info != NULL)
        free(extended_info);
    if (padded_pin != NULL) {
        OPENSSL_cleanse(padded_pin, padded_pin_len);
        free(padded_pin);
    }
    if (enc_padded_pin != NULL) {
        OPENSSL_cleanse(enc_padded_pin, enc_padded_pin_len);
        free(enc_padded_pin);
    }
    OPENSSL_cleanse(shared_key, sizeof(shared_key));
    OPENSSL_cleanse(shared_secret, shared_secret_len);
    OPENSSL_cleanse(enc_pinblob, enc_pinblob_len);
    OPENSSL_cleanse(clear_pinblob, clear_pinblob_len);
    OPENSSL_cleanse(pinblob_key, sizeof(pinblob_key));

    return rc;
}

CK_RV do_LoginExtended(XCP_LoginAlgorithm_t alg,
                       XCP_LoginImporter_t imp_keytype,
                       const CK_BYTE *pin, CK_ULONG pin_len,
                       const CK_BYTE *nonce, CK_ULONG nonce_len,
                       CK_BYTE *pin_blob, CK_ULONG *pin_blob_len,
                       const CK_BYTE *parent_session_id, target_t target)
{
    if (dll_m_LoginExtended == NULL) {
        TRACE_ERROR("%s dll_m_LoginExtended is not available\n", __func__);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    return do_LoginLogoutExtended(__FNID_LoginExtended, alg, imp_keytype,
                                  pin, pin_len, nonce, nonce_len,
                                  pin_blob, pin_blob_len,
                                  parent_session_id, target);
}

CK_RV do_LogoutExtended(XCP_LoginAlgorithm_t alg,
                        XCP_LoginImporter_t imp_keytype,
                        const CK_BYTE *pin, CK_ULONG pin_len,
                        const CK_BYTE *nonce, CK_ULONG nonce_len,
                        target_t target)
{
    if (dll_m_LogoutExtended == NULL) {
        TRACE_ERROR("%s dll_m_LogoutExtended is not available\n", __func__);
        return CKR_FUNCTION_NOT_SUPPORTED;
    }

    return do_LoginLogoutExtended(__FNID_LogoutExtended, alg, imp_keytype,
                                  pin, pin_len, nonce, nonce_len,
                                  NULL, NULL, NULL, target);
}
