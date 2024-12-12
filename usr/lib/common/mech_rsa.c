/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  mech_rsa.c
//
// Mechanisms for RSA
//
// Routines contained within:

#include <pthread.h>
#include <stdio.h>

#include <string.h>             // for memcmp() et al
#include <stdlib.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"
#include "constant_time.h"
#include "p11util.h"

#include <openssl/crypto.h>
#include <openssl/rsa.h>

CK_BBOOL is_rsa_mechanism(CK_MECHANISM_TYPE mech)
{
    switch (mech) {
    case CKM_RSA_9796:
    case CKM_RSA_PKCS:
    case CKM_MD2_RSA_PKCS:
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA3_224_RSA_PKCS:
    case CKM_SHA3_256_RSA_PKCS:
    case CKM_SHA3_384_RSA_PKCS:
    case CKM_SHA3_512_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_SHA3_224_RSA_PKCS_PSS:
    case CKM_SHA3_256_RSA_PKCS_PSS:
    case CKM_SHA3_384_RSA_PKCS_PSS:
    case CKM_SHA3_512_RSA_PKCS_PSS:
    case CKM_RSA_PKCS_OAEP:
    case CKM_RSA_X_509:
    case CKM_RSA_X9_31:
    case CKM_SHA1_RSA_X9_31:
        return TRUE;
    }

    return FALSE;
}

CK_RV rsa_get_key_info(OBJECT *key_obj, CK_ULONG *mod_bytes,
                       CK_OBJECT_CLASS *keyclass)
{
    CK_RV rc;
    CK_ATTRIBUTE *attr;

    rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_MODULUS in the template\n");
        return rc;
    }

    *mod_bytes = attr->ulValueLen;

    rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS, keyclass);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS in the template\n");
        return rc;
    }

    return CKR_OK;
}


/*
 * Format an encryption block according to PKCS #1: RSA Encryption, Version
 * 1.5.
 */

CK_RV rsa_format_block(STDLL_TokData_t *tokdata,
                       CK_BYTE *in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG out_data_len, CK_ULONG type)
{
    CK_ULONG padding_len, i;
    CK_RV rc = CKR_OK;

    if (!in_data || !out_data || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (out_data_len < (in_data_len + 11)) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    /*
     * The padding string PS shall consist of k-3-||D|| octets.
     */
    padding_len = out_data_len - 3 - in_data_len;

    /*
     * For block types 01 and 02, the padding string is at least eight octets
     * long, which is a security condition for public-key operations that
     * prevents an attacker from recoving data by trying all possible
     * encryption blocks.
     */
    if ((type == 1 || type == 2) && ((padding_len) < 8)) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }

    /*
     * The leading 00 octet.
     */
    out_data[0] = (CK_BYTE) 0;

    /*
     * The block type.
     */
    out_data[1] = (CK_BYTE) type;

    switch (type) {
    /*
     * For block type 00, the octets shall have value 00.
     * EB = 00 || 00 || 00 * i || D
     * Where D must begin with a nonzero octet.
     */
    case 0:
        if (in_data[0] == (CK_BYTE) 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_DATA_INVALID));
            return CKR_DATA_INVALID;
        }

        for (i = 2; i < (padding_len + 2); i++)
            out_data[i] = (CK_BYTE) 0;

        break;
    /*
     * For block type 01, they shall have value FF.
     * EB = 00 || 01 || FF * i || 00 || D
     */
    case 1:
        for (i = 2; i < (padding_len + 2); i++)
            out_data[i] = (CK_BYTE) 0xff;

        break;
   /*
    * For block type 02, they shall be pseudorandomly generated and
    * nonzero.
    * EB = 00 || 02 || ?? * i || 00 || D
    * Where ?? is nonzero.
    */
    case 2:
        rc = rng_generate(tokdata, &out_data[2], padding_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("rng_generate failed.\n");
            return rc;
        }
        for (i = 2; i < (padding_len + 2); i++) {
            while (out_data[i] == (CK_BYTE) 0) {
                rc = rng_generate(tokdata, &out_data[i], 1);
                if (rc != CKR_OK) {
                    TRACE_DEVEL("rng_generate failed.\n");
                    return rc;
                }
            }
        }
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_INVALID));
        return CKR_DATA_INVALID;
    }

    out_data[i] = (CK_BYTE) 0;
    i++;

    if (in_data_len)
        memcpy(&out_data[i], in_data, in_data_len);

    return rc;
}


/*
 * Parse an encryption block according to PKCS #1: RSA Encryption, Version
 * 1.5.
 */

static CK_RV rsa_parse_block_type_1(CK_BYTE *in_data,
                                    CK_ULONG in_data_len,
                                    CK_BYTE *out_data,
                                    CK_ULONG *out_data_len)
{
    CK_ULONG i;
    CK_RV rc = CKR_OK;
    int found = 0;

    if (!in_data || !out_data || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if (in_data_len <= 11) {
        TRACE_DEVEL("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    /*
     * Check for the leading 00 octet.
     */
    if (in_data[0] != (CK_BYTE) 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_INVALID));
        return CKR_ENCRYPTED_DATA_INVALID;
    }

    /*
     * Check the block type.
     */
    if (in_data[1] != (CK_BYTE) PKCS_BT_1) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_INVALID));
        return CKR_ENCRYPTED_DATA_INVALID;
    }

    /*
     * The block type shall be a single octet indicating the structure of the
     * encryption block. It shall have value 01. For a private-key
     * operation, the block type shall be 01.
     *
     * For block type 01, they shall have value FF.
     *
     * For block type 01, the encryption block can be parsed
     * unambiguously since the padding string contains no octets with value 00
     * and the padding string is separated from the data by an octet with
     * value 00.
     */
    for (i = 2; i <= (in_data_len - 2); i++) {
        if (in_data[i] != (CK_BYTE) 0xff) {
            if (in_data[i] == (CK_BYTE) 0) {
                i++;
                found = 1;
                break;
            }

            TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_INVALID));
            return CKR_ENCRYPTED_DATA_INVALID;
        }
    }
    if (!found)
        i++;

    /*
     * For block type 01, the padding string is at least eight octets
     * long, which is a security condition for public-key operations that
     * prevents an attacker from recoving data by trying all possible
     * encryption blocks.
     */
    if ((i - 3) < 8) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_INVALID));
        return CKR_ENCRYPTED_DATA_INVALID;
    }

    if (in_data_len < 2) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_INVALID));
        return CKR_ENCRYPTED_DATA_INVALID;
    }

    if (*out_data_len < (in_data_len - i)) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    memcpy(out_data, &in_data[i], in_data_len - i);
    *out_data_len = in_data_len - i;

    return rc;
}

#define MAX_LEN_GEN_TRIES 128

static CK_RV rsa_parse_block_type_2(CK_BYTE *in_data,
                                    CK_ULONG in_data_len,
                                    CK_BYTE *out_data,
                                    CK_ULONG *out_data_len,
                                    CK_BYTE *kdk, CK_ULONG kdklen)
{
    unsigned int good = 0, found_zero_byte, equals0;
    size_t zero_index = 0, msg_index;
    unsigned char *synthetic = NULL;
    int synthetic_length;
    uint16_t len_candidate;
    unsigned char candidate_lengths[MAX_LEN_GEN_TRIES * sizeof(len_candidate)];
    uint16_t len_mask;
    uint16_t max_sep_offset;
    int synth_msg_index = 0;
    size_t i, j;
    CK_RV rc;

    if (kdk == NULL || kdklen == 0) {
        TRACE_DEVEL("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    /*
     * The implementation of this function is copied from OpenSSL's function
     * ossl_rsa_padding_check_PKCS1_type_2() in crypto/rsa/rsa_pk1.c
     * and is slightly modified to fit to the OpenCryptoki environment.
     *
     * The OpenSSL code is licensed under the Apache License 2.0.
     * You can obtain a copy in the file LICENSE in the OpenSSL source
     * distribution or at https://www.openssl.org/source/license.html
     *
     * Changes include:
     * - Different variable, function and define names.
     * - Usage of TRACE_ERROR to report errors and issue debug messages.
     * - Different return codes.
     */

    /*
     * The format is
     * 00 || BT || PS || 00 || D
     * BT - block type
     * PS - padding string, at least 8 bytes of random non-zero data for BT = 2
     * D  - data.
     */

    /*
     * PKCS#1 v1.5 decryption. See "PKCS #1 v2.2: RSA Cryptography Standard",
     * section 7.2.2.
     */
    if (in_data_len < RSA_PKCS1_PADDING_SIZE) {
        TRACE_DEVEL("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }

    /* Generate a random message to return in case the padding checks fail. */
    synthetic = calloc(1, in_data_len);
    if (synthetic == NULL) {
        TRACE_ERROR("Failed to allocate synthetic buffer");
        return CKR_HOST_MEMORY;
    }

    rc = openssl_specific_rsa_prf(synthetic, in_data_len, "message", 7,
                                  kdk, kdklen, in_data_len * 8);
    if (rc != CKR_OK)
        goto out;

    /* decide how long the random message should be */
    rc = openssl_specific_rsa_prf(candidate_lengths,
                                  sizeof(candidate_lengths),
                                  "length", 6, kdk, kdklen,
                                  MAX_LEN_GEN_TRIES *
                                              sizeof(len_candidate) * 8);
    if (rc != CKR_OK)
        goto out;

    /*
     * max message size is the size of the modulus size minus 2 bytes for
     * version and padding type and a minimum of 8 bytes padding
     */
    len_mask = max_sep_offset = in_data_len - 2 - 8;
    /*
     * we want a mask so let's propagate the high bit to all positions less
     * significant than it
     */
    len_mask |= len_mask >> 1;
    len_mask |= len_mask >> 2;
    len_mask |= len_mask >> 4;
    len_mask |= len_mask >> 8;

    synthetic_length = 0;
    for (i = 0; i < MAX_LEN_GEN_TRIES * (int)sizeof(len_candidate);
                                            i += sizeof(len_candidate)) {
        len_candidate = (candidate_lengths[i] << 8) |
                                                candidate_lengths[i + 1];
        len_candidate &= len_mask;

        synthetic_length = constant_time_select_int(
                        constant_time_lt(len_candidate, max_sep_offset),
                                         len_candidate, synthetic_length);
    }

    synth_msg_index = in_data_len - synthetic_length;

    good = constant_time_is_zero(in_data[0]);
    good &= constant_time_eq(in_data[1], 2);

    /* scan over padding data */
    found_zero_byte = 0;
    for (i = 2; i < in_data_len; i++) {
        equals0 = constant_time_is_zero(in_data[i]);

        zero_index = constant_time_select_int(~found_zero_byte & equals0,
                                              i, zero_index);
        found_zero_byte |= equals0;
    }

    /*
     * PS must be at least 8 bytes long, and it starts two bytes into |in_data|.
     * If we never found a 0-byte, then |zero_index| is 0 and the check
     * also fails.
     */
    good &= constant_time_ge(zero_index, 2 + 8);

    /*
     * Skip the zero byte. This is incorrect if we never found a zero-byte
     * but in this case we also do not copy the message out.
     */
    msg_index = zero_index + 1;

    /*
     * old code returned an error in case the decrypted message wouldn't fit
     * into the |out_data|, since that would leak information, return the
     * synthetic message instead
     */
    good &= constant_time_ge(*out_data_len, in_data_len - msg_index);

    msg_index = constant_time_select_int(good, msg_index, synth_msg_index);

    /*
     * since at this point the |msg_index| does not provide the signal
     * indicating if the padding check failed or not, we don't have to worry
     * about leaking the length of returned message, we still need to ensure
     * that we read contents of both buffers so that cache accesses don't leak
     * the value of |good|
     */
    for (i = msg_index, j = 0; i < in_data_len && j < *out_data_len;
                                                                i++, j++)
        out_data[j] = constant_time_select_8(good, in_data[i], synthetic[i]);

    *out_data_len = j;

out:
    if (synthetic != NULL)
        free(synthetic);

    return rc;
}

CK_RV rsa_parse_block(CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *out_data,
                      CK_ULONG *out_data_len, CK_ULONG type,
                      CK_BYTE *kdk, CK_ULONG kdklen)
{
    switch (type) {
    case PKCS_BT_1:
        return rsa_parse_block_type_1(in_data, in_data_len,
                                        out_data, out_data_len);
    case PKCS_BT_2:
        return rsa_parse_block_type_2(in_data, in_data_len,
                                       out_data, out_data_len, kdk, kdklen);
    }

    return CKR_ARGUMENTS_BAD;
}

//
//
CK_RV rsa_pkcs_encrypt(STDLL_TokData_t *tokdata,
                       SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ULONG modulus_bytes;
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;

    UNUSED(sess);

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }
    // check input data length restrictions
    //
    if (in_data_len > (modulus_bytes - 11)) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        rc = CKR_DATA_LEN_RANGE;
        goto done;
    }

    if (length_only == TRUE) {
        *out_data_len = modulus_bytes;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < modulus_bytes) {
        *out_data_len = modulus_bytes;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }
    // this had better be a public key
    if (keyclass != CKO_PUBLIC_KEY) {
        TRACE_ERROR("This operation requires a public key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    if (token_specific.t_rsa_encrypt == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = token_specific.t_rsa_encrypt(tokdata, in_data, in_data_len, out_data,
                                      out_data_len, key_obj);

    if (rc != CKR_OK)
        TRACE_DEVEL("Token Specific rsa encrypt failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;
    return rc;
}


//
//
CK_RV rsa_pkcs_decrypt(STDLL_TokData_t *tokdata,
                       SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ULONG modulus_bytes;
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;

    UNUSED(sess);

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }
    // check input data length restrictions
    //
    if (in_data_len != modulus_bytes) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
        goto done;
    }
    if (length_only == TRUE) {
        // this is not exact but it's the upper bound; otherwise we'll need
        // to do the RSA operation just to get the required length
        //
        *out_data_len = modulus_bytes - 11;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < (modulus_bytes - 11)) {
        *out_data_len = modulus_bytes - 11;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }
    // this had better be a private key
    if (keyclass != CKO_PRIVATE_KEY) {
        TRACE_ERROR("This operation requires a private key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /* check for token specific call first */
    if (token_specific.t_rsa_decrypt == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = token_specific.t_rsa_decrypt(tokdata, in_data, in_data_len, out_data,
                                      out_data_len, key_obj);

    rc = constant_time_select_int(constant_time_eq(rc, CKR_DATA_LEN_RANGE),
                                  CKR_ENCRYPTED_DATA_INVALID, rc);

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


CK_RV rsa_oaep_crypt(STDLL_TokData_t *tokdata, SESSION *sess,
                     CK_BBOOL length_only,
                     ENCR_DECR_CONTEXT *ctx, CK_BYTE *in_data,
                     CK_ULONG in_data_len, CK_BYTE *out_data,
                     CK_ULONG *out_data_len, CK_BBOOL encrypt)
{
    OBJECT *key_obj = NULL;
    CK_ULONG hlen, modulus_bytes;
    CK_OBJECT_CLASS keyclass;
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    CK_RV rc;
    CK_RSA_PKCS_OAEP_PARAMS_PTR oaepParms = NULL;

    UNUSED(sess);

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /*
     * To help mitigate timing and fault attacks when decrypting,
     * check oaep parameters that are passed in right now and compute
     * the hash of the Label.
     *
     * PKCS#11v2.20, section 12.1.7, Step a: if "source" is empty,
     * then pSourceData and ulSourceDatalen must be NULL, and zero
     * respectively.
     */
    oaepParms = (CK_RSA_PKCS_OAEP_PARAMS_PTR) ctx->mech.pParameter;
    if (!(oaepParms->source) && (oaepParms->pSourceData ||
                                 oaepParms->ulSourceDataLen)) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    /* verify hashAlg now as well as get hash size. */
    hlen = 0;
    rc = get_sha_size(oaepParms->hashAlg, &hlen);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    /* modulus size should be >= 2*hashsize+2 */
    if (modulus_bytes < (2 * hlen + 2)) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_SIZE_RANGE));
        rc = CKR_KEY_SIZE_RANGE;
        goto done;
    }

    if (encrypt) {
        if (in_data_len > (modulus_bytes - 2 * hlen - 2)) {
            TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
            rc = CKR_DATA_LEN_RANGE;
            goto done;
        }
    }

    if (length_only == TRUE) {
        *out_data_len = modulus_bytes;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < modulus_bytes) {
        *out_data_len = modulus_bytes;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    /* hash the label now */
    if (!(oaepParms->pSourceData) || !(oaepParms->ulSourceDataLen))
        rc = compute_sha(tokdata, (CK_BYTE *)"", 0, hash, oaepParms->hashAlg);
    else
        rc = compute_sha(tokdata, oaepParms->pSourceData,
                         oaepParms->ulSourceDataLen, hash, oaepParms->hashAlg);
    if (rc != CKR_OK)
        goto done;

    if (encrypt) {
        if (in_data_len > (modulus_bytes - 2 * hlen - 2)) {
            TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
            rc = CKR_DATA_LEN_RANGE;
            goto done;
        }
        // this had better be a public key
        if (keyclass != CKO_PUBLIC_KEY) {
            TRACE_ERROR("This operation requires a public key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }

        if (token_specific.t_rsa_oaep_encrypt == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
            rc = CKR_MECHANISM_INVALID;
            goto done;
        }

        /* Release obj lock, token specific rsa-oaep may re-acquire the lock */
        object_put(tokdata, key_obj, TRUE);
        key_obj = NULL;

        rc = token_specific.t_rsa_oaep_encrypt(tokdata, ctx, in_data,
                                               in_data_len, out_data,
                                               out_data_len, hash, hlen);
    } else {
        // decrypt
        if (in_data_len != modulus_bytes) {
            TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
            rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
            goto done;
        }
        // this had better be a private key
        if (keyclass != CKO_PRIVATE_KEY) {
            TRACE_ERROR("This operation requires a private key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }

        if (token_specific.t_rsa_oaep_decrypt == NULL) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
            rc = CKR_MECHANISM_INVALID;
            goto done;
        }

        /* Release obj lock, token specific rsa-oaep may re-acquire the lock */
        object_put(tokdata, key_obj, TRUE);
        key_obj = NULL;

        rc = token_specific.t_rsa_oaep_decrypt(tokdata, ctx, in_data,
                                               in_data_len, out_data,
                                               out_data_len, hash, hlen);
    }

    if (rc != CKR_OK)
        TRACE_DEVEL("Token Specific rsa oaep decrypt failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV rsa_pkcs_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ULONG modulus_bytes;
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }
    // check input data length restrictions
    //
    if (in_data_len > (modulus_bytes - 11)) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        rc = CKR_DATA_LEN_RANGE;
        goto done;
    }
    if (length_only == TRUE) {
        *out_data_len = modulus_bytes;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < modulus_bytes) {
        *out_data_len = modulus_bytes;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }
    // this had better be a private key
    //
    if (keyclass != CKO_PRIVATE_KEY) {
        TRACE_ERROR("This operation requires a private key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /* check for token specific call first */
    if (token_specific.t_rsa_sign == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = token_specific.t_rsa_sign(tokdata, sess, in_data, in_data_len,
                                   out_data, out_data_len, key_obj);

    if (rc != CKR_OK)
        TRACE_DEVEL("Token Specific rsa sign failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV rsa_pkcs_verify(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *signature, CK_ULONG sig_len)
{
    OBJECT *key_obj = NULL;
    CK_ULONG modulus_bytes;
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;


    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }
    // check input data length restrictions
    //
    if (sig_len != modulus_bytes) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
        rc = CKR_SIGNATURE_LEN_RANGE;
        goto done;
    }
    // verifying is a public key operation
    //
    if (keyclass != CKO_PUBLIC_KEY) {
        TRACE_ERROR("This operation requires a public key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /* check for token specific call first */
    if (token_specific.t_rsa_verify == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = token_specific.t_rsa_verify(tokdata, sess, in_data, in_data_len,
                                     signature, sig_len, key_obj);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token Specific rsa verify failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV rsa_pkcs_verify_recover(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              CK_BBOOL length_only,
                              SIGN_VERIFY_CONTEXT *ctx,
                              CK_BYTE *signature,
                              CK_ULONG sig_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_OBJECT_CLASS keyclass;
    CK_ULONG modulus_bytes;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }
    // check input data length restrictions
    //
    if (sig_len != modulus_bytes) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
        rc = CKR_SIGNATURE_LEN_RANGE;
        goto done;
    }
    if (length_only == TRUE) {
        *out_data_len = modulus_bytes - 11;
        rc = CKR_OK;
        goto done;
    }

    /* this had better be a public key */
    if (keyclass != CKO_PUBLIC_KEY) {
        TRACE_ERROR("This operation requires a public key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /* check for token specific call first */
    if (token_specific.t_rsa_verify_recover == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = token_specific.t_rsa_verify_recover(tokdata, signature, sig_len,
                                             out_data, out_data_len, key_obj);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token Specific rsa verify failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV rsa_x509_encrypt(STDLL_TokData_t *tokdata,
                       SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_OBJECT_CLASS keyclass;
    CK_ULONG modulus_bytes;
    CK_RV rc;

    UNUSED(sess);

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }
    // CKM_RSA_X_509 requires input data length to be no bigger than the modulus
    //
    if (in_data_len > modulus_bytes) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }
    if (length_only == TRUE) {
        *out_data_len = modulus_bytes;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < modulus_bytes) {
        *out_data_len = modulus_bytes;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    /* this had better be a public key */
    if (keyclass != CKO_PUBLIC_KEY) {
        TRACE_ERROR("This operation requires a public key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /* check for token specific call first */
    if (token_specific.t_rsa_x509_encrypt == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = token_specific.t_rsa_x509_encrypt(tokdata, in_data, in_data_len,
                                           out_data, out_data_len, key_obj);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token Specific rsa x509 encrypt failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV rsa_x509_decrypt(STDLL_TokData_t *tokdata,
                       SESSION *sess,
                       CK_BBOOL length_only,
                       ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data,
                       CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ULONG modulus_bytes;
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;

    UNUSED(sess);

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }
    // check input data length restrictions
    //
    if (in_data_len != modulus_bytes) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
        goto done;
    }
    if (length_only == TRUE) {
        *out_data_len = modulus_bytes;
        rc = CKR_OK;
        goto done;
    }
    // Although X.509 prepads with zeros, we don't strip it after
    // decryption (PKCS #11 specifies that X.509 decryption is supposed
    // to produce K bytes of cleartext where K is the modulus length)
    //
    if (*out_data_len < modulus_bytes) {
        *out_data_len = modulus_bytes;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    /* this had better be a private key */
    if (keyclass != CKO_PRIVATE_KEY) {
        TRACE_ERROR("This operation requires a private key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /* check for token specific call first */
    if (token_specific.t_rsa_x509_encrypt == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    rc = token_specific.t_rsa_x509_decrypt(tokdata, in_data, in_data_len,
                                           out_data, out_data_len, key_obj);
    if (rc != CKR_OK)
        TRACE_ERROR("Token Specific rsa x509 decrypt failed.\n");
    // ckm_rsa_operation is used for all RSA operations so we need to adjust
    // the return code accordingly
    //
    if (rc == CKR_DATA_LEN_RANGE) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        rc =  CKR_ENCRYPTED_DATA_LEN_RANGE;
        goto done;
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV rsa_x509_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ULONG modulus_bytes;
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }
    // check input data length restrictions
    //
    if (in_data_len > modulus_bytes) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        rc = CKR_DATA_LEN_RANGE;
        goto done;
    }
    if (length_only == TRUE) {
        *out_data_len = modulus_bytes;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < modulus_bytes) {
        *out_data_len = modulus_bytes;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    /* this had better be a private key */
    if (keyclass != CKO_PRIVATE_KEY) {
        TRACE_ERROR("This operation requires a private key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /* check for token specific call first */
    if (token_specific.t_rsa_x509_sign == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }
    rc = token_specific.t_rsa_x509_sign(tokdata, in_data, in_data_len, out_data,
                                        out_data_len, key_obj);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token Specific rsa x509 sign failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV rsa_x509_verify(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *signature, CK_ULONG sig_len)
{
    OBJECT *key_obj = NULL;
    CK_OBJECT_CLASS keyclass;
    CK_ULONG modulus_bytes;
    CK_RV rc;

    UNUSED(sess);

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }
    // check input data length restrictions
    //
    if (sig_len != modulus_bytes) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
        rc = CKR_SIGNATURE_LEN_RANGE;
        goto done;
    }

    /* this had better be a public key */
    if (keyclass != CKO_PUBLIC_KEY) {
        TRACE_ERROR("This operation requires a public key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /* check for token specific call first */
    if (token_specific.t_rsa_x509_verify == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }
    // verify is a public key operation --> encrypt
    //
    rc = token_specific.t_rsa_x509_verify(tokdata, in_data, in_data_len,
                                          signature, sig_len, key_obj);
    if (rc != CKR_OK)
        TRACE_ERROR("Token Specific rsa x509 verify failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV rsa_x509_verify_recover(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              CK_BBOOL length_only,
                              SIGN_VERIFY_CONTEXT *ctx,
                              CK_BYTE *signature,
                              CK_ULONG sig_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ULONG modulus_bytes;
    CK_OBJECT_CLASS keyclass;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }
    // check input data length restrictions
    //
    if (sig_len != modulus_bytes) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
        return CKR_SIGNATURE_LEN_RANGE;
    }
    if (length_only == TRUE) {
        *out_data_len = modulus_bytes;
        rc = CKR_OK;
        goto done;
    }
    // we perform no stripping of prepended zero bytes here
    //
    if (*out_data_len < modulus_bytes) {
        *out_data_len = modulus_bytes;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    /* this had better be a public key */
    if (keyclass != CKO_PUBLIC_KEY) {
        TRACE_ERROR("This operation requires a public key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    /* check for token specific call first */
    if (token_specific.t_rsa_x509_verify_recover == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }
    // verify is a public key operation --> encrypt
    //
    rc = token_specific.t_rsa_x509_verify_recover(tokdata, signature, sig_len,
                                                  out_data, out_data_len,
                                                  key_obj);
    if (rc != CKR_OK)
        TRACE_ERROR("Token Specific rsa x509 verify recover.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV rsa_pss_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                   CK_BBOOL length_only,
                   SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                   CK_ULONG in_data_len, CK_BYTE *out_data,
                   CK_ULONG *out_data_len)
{
    CK_RV rc;
    OBJECT *key_obj = NULL;
    CK_ULONG modulus_bytes, hlen;
    CK_OBJECT_CLASS keyclass;
    CK_RSA_PKCS_PSS_PARAMS_PTR pssParms = NULL;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    /* get modulus and key class */
    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }

    if (length_only == TRUE) {
        *out_data_len = modulus_bytes;
        rc = CKR_OK;
        goto done;
    }

    /* verify hashAlg now as well as get hash size. */
    pssParms = (CK_RSA_PKCS_PSS_PARAMS_PTR) ctx->mech.pParameter;
    hlen = 0;
    rc = get_sha_size(pssParms->hashAlg, &hlen);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto done;
    }

    /* pkcs#11v2.2, 12.1.10 states that this mechanism does not
     * compute a hash value on the message to be signed.
     * It assumes the input data is the hashed message.
     */
    if (in_data_len != hlen) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        rc = CKR_DATA_LEN_RANGE;
        goto done;
    }

    if (*out_data_len < modulus_bytes) {
        *out_data_len = modulus_bytes;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    /* this had better be a private key */
    if (keyclass != CKO_PRIVATE_KEY) {
        TRACE_ERROR("This operation requires a private key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    if (token_specific.t_rsa_pss_sign == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    /* Release obj lock, token specific rsa_pss may re-acquire the lock */
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    rc = token_specific.t_rsa_pss_sign(tokdata, sess, ctx, in_data, in_data_len,
                                       out_data, out_data_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token Specific rsa pss sign failed.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV rsa_pss_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                     SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                     CK_ULONG in_data_len, CK_BYTE *signature,
                     CK_ULONG sig_len)
{
    CK_RV rc;
    OBJECT *key_obj = NULL;
    CK_ULONG modulus_bytes;
    CK_OBJECT_CLASS keyclass;

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    /* get modulus and key class */
    rc = rsa_get_key_info(key_obj, &modulus_bytes, &keyclass);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        goto done;
    }

    /* check input data length restrictions */
    if (sig_len != modulus_bytes) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
        rc = CKR_SIGNATURE_LEN_RANGE;
        goto done;
    }

    /* this had better be a public key */
    if (keyclass != CKO_PUBLIC_KEY) {
        TRACE_ERROR("This operation requires a public key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    if (token_specific.t_rsa_pss_verify == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    /* Release obj lock, token specific rsa_pss may re-acquire the lock */
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    rc = token_specific.t_rsa_pss_verify(tokdata, sess, ctx, in_data,
                                         in_data_len, signature, sig_len);
    if (rc != CKR_OK)
        TRACE_ERROR("Token Specific rsa pss verify.\n");

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}

CK_RV rsa_hash_pss_sign(STDLL_TokData_t *tokdata, SESSION *sess,
                        CK_BBOOL length_only,
                        SIGN_VERIFY_CONTEXT *ctx, CK_BYTE *in_data,
                        CK_ULONG in_data_len, CK_BYTE *sig, CK_ULONG *sig_len)
{
    CK_ULONG hlen;
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    SIGN_VERIFY_CONTEXT sign_ctx;
    CK_MECHANISM digest_mech, sign_mech;
    CK_RV rc;

    if (!sess || !ctx || !in_data) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    memset(&digest_ctx, 0x0, sizeof(digest_ctx));
    memset(&sign_ctx, 0x0, sizeof(sign_ctx));

    rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
        return rc;
    }

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = get_sha_size(digest_mech.mechanism, &hlen);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx,
                           in_data, in_data_len, hash, &hlen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Digest failed.\n");
        digest_mgr_cleanup(tokdata, sess, &digest_ctx);
        return rc;
    }

    /* sign the hash */
    sign_mech.mechanism = CKM_RSA_PKCS_PSS;
    sign_mech.ulParameterLen = ctx->mech.ulParameterLen;
    sign_mech.pParameter = ctx->mech.pParameter;

    rc = sign_mgr_init(tokdata, sess, &sign_ctx, &sign_mech, FALSE, ctx->key,
                       FALSE, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign Mgr Init failed.\n");
        goto done;
    }

    rc = sign_mgr_sign(tokdata, sess, length_only, &sign_ctx, hash, hlen,
                       sig, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Sign Mgr Sign failed.\n");

done:
    sign_mgr_cleanup(tokdata, sess, &sign_ctx);

    return rc;
}

CK_RV rsa_hash_pss_update(STDLL_TokData_t *tokdata, SESSION *sess,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *in_data, CK_ULONG in_data_len)
{
    DIGEST_CONTEXT *digest_ctx = NULL;
    CK_MECHANISM digest_mech;
    CK_RV rc;

    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    /* see if digest has already been through init */
    digest_ctx = (DIGEST_CONTEXT *) ctx->context;
    if (digest_ctx->active == FALSE) {
        rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
            return rc;
        }

        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, digest_ctx, &digest_mech, FALSE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }
        ctx->state_unsaveable |= digest_ctx->state_unsaveable;
    }

    rc = digest_mgr_digest_update(tokdata, sess, digest_ctx, in_data,
                                  in_data_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Digest Mgr Update failed.\n");

    return rc;
}

CK_RV rsa_hash_pss_sign_final(STDLL_TokData_t *tokdata, SESSION *sess,
                              CK_BBOOL length_only, SIGN_VERIFY_CONTEXT *ctx,
                              CK_BYTE *signature, CK_ULONG *sig_len)
{
    CK_ULONG hlen;
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    DIGEST_CONTEXT *digest_ctx;
    SIGN_VERIFY_CONTEXT sign_ctx;
    CK_MECHANISM sign_mech;
    CK_RV rc;

    if (!sess || !ctx || !sig_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    memset(&sign_ctx, 0x0, sizeof(sign_ctx));

    digest_ctx = (DIGEST_CONTEXT *) ctx->context;

    if (digest_ctx->active == FALSE) {
        rc = rsa_hash_pss_update(tokdata, sess, ctx, NULL, 0);
        TRACE_DEVEL("rsa_hash_pss_update\n");
        if (rc != 0)
            return rc;
    }

    rc = get_sha_size(digest_ctx->mech.mechanism, &hlen);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    rc = digest_mgr_digest_final(tokdata, sess, length_only, digest_ctx,
                                 hash, &hlen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    /* sign the hash */
    sign_mech.mechanism = CKM_RSA_PKCS_PSS;
    sign_mech.ulParameterLen = ctx->mech.ulParameterLen;
    sign_mech.pParameter = ctx->mech.pParameter;

    rc = sign_mgr_init(tokdata, sess, &sign_ctx, &sign_mech, FALSE, ctx->key,
                       FALSE, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign Mgr Init failed.\n");
        goto done;
    }

    rc = sign_mgr_sign(tokdata, sess, length_only, &sign_ctx, hash, hlen,
                       signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Sign Mgr Sign failed.\n");

done:
    sign_mgr_cleanup(tokdata, sess, &sign_ctx);

    return rc;
}

CK_RV rsa_hash_pss_verify(STDLL_TokData_t *tokdata, SESSION *sess,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *in_data, CK_ULONG in_data_len,
                          CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_ULONG hlen;
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    SIGN_VERIFY_CONTEXT verify_ctx;
    CK_MECHANISM digest_mech, verify_mech;
    CK_RV rc;

    if (!sess || !ctx || !in_data) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    memset(&digest_ctx, 0x0, sizeof(digest_ctx));
    memset(&verify_ctx, 0x0, sizeof(verify_ctx));

    rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
        return rc;
    }

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = get_sha_size(digest_mech.mechanism, &hlen);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }

    rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx, in_data,
                           in_data_len, hash, &hlen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Digest failed.\n");
        digest_mgr_cleanup(tokdata, sess, &digest_ctx);
        return rc;
    }

    /* sign the hash */
    verify_mech.mechanism = CKM_RSA_PKCS_PSS;
    verify_mech.ulParameterLen = ctx->mech.ulParameterLen;
    verify_mech.pParameter = ctx->mech.pParameter;

    rc = verify_mgr_init(tokdata, sess, &verify_ctx, &verify_mech, FALSE,
                         ctx->key, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Verify Mgr Init failed.\n");
        goto done;
    }

    rc = verify_mgr_verify(tokdata, sess, &verify_ctx, hash, hlen,
                           signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Verify Mgr Verify failed.\n");

done:
    verify_mgr_cleanup(tokdata, sess, &verify_ctx);

    return rc;
}

CK_RV rsa_hash_pss_verify_final(STDLL_TokData_t *tokdata, SESSION *sess,
                                SIGN_VERIFY_CONTEXT *ctx,
                                CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_ULONG hlen;
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    DIGEST_CONTEXT *digest_ctx;
    SIGN_VERIFY_CONTEXT verify_ctx;
    CK_MECHANISM verify_mech;
    CK_RV rc;

    if (!sess || !ctx || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    memset(&verify_ctx, 0x0, sizeof(verify_ctx));

    digest_ctx = (DIGEST_CONTEXT *) ctx->context;

    if (digest_ctx->active == FALSE) {
        rc = rsa_hash_pss_update(tokdata, sess, ctx, NULL, 0);
        TRACE_DEVEL("rsa_hash_pss_update\n");
        if (rc != 0)
            return rc;
    }

    rc = get_sha_size(digest_ctx->mech.mechanism, &hlen);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    rc = digest_mgr_digest_final(tokdata, sess, FALSE, digest_ctx, hash, &hlen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }

    /* sign the hash */
    verify_mech.mechanism = CKM_RSA_PKCS_PSS;
    verify_mech.ulParameterLen = ctx->mech.ulParameterLen;
    verify_mech.pParameter = ctx->mech.pParameter;

    rc = verify_mgr_init(tokdata, sess, &verify_ctx, &verify_mech, FALSE,
                         ctx->key, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Verify Mgr Init failed.\n");
        goto done;
    }

    rc = verify_mgr_verify(tokdata, sess, &verify_ctx, hash, hlen,
                           signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Verify Mgr Verify failed.\n");

done:
    verify_mgr_cleanup(tokdata, sess, &verify_ctx);

    return rc;
}

static CK_RV rsa_pkcs_alg_oid_from_mech(CK_MECHANISM_TYPE mech,
                                        const CK_BYTE **oid, CK_ULONG *oid_len)
{
    switch (mech) {
#if !(NOMD2)
    case CKM_MD2_RSA_PKCS:
        *oid = ber_AlgMd2;
        *oid_len = ber_AlgMd2Len;
        break;
#endif
    case CKM_MD5_RSA_PKCS:
        *oid = ber_AlgMd5;
        *oid_len = ber_AlgMd5Len;
        break;
    case CKM_SHA1_RSA_PKCS:
        *oid = ber_AlgSha1;
        *oid_len = ber_AlgSha1Len;
        break;
    case CKM_SHA224_RSA_PKCS:
        *oid = ber_AlgSha224;
        *oid_len = ber_AlgSha224Len;
        break;
    case CKM_SHA256_RSA_PKCS:
        *oid = ber_AlgSha256;
        *oid_len = ber_AlgSha256Len;
        break;
    case CKM_SHA384_RSA_PKCS:
        *oid = ber_AlgSha384;
        *oid_len = ber_AlgSha384Len;
        break;
    case CKM_SHA512_RSA_PKCS:
        *oid = ber_AlgSha512;
        *oid_len = ber_AlgSha512Len;
        break;
    case CKM_SHA3_224_RSA_PKCS:
        *oid = ber_AlgSha3_224;
        *oid_len = ber_AlgSha3_224Len;
        break;
    case CKM_SHA3_256_RSA_PKCS:
        *oid = ber_AlgSha3_256;
        *oid_len = ber_AlgSha3_256Len;
        break;
    case CKM_SHA3_384_RSA_PKCS:
        *oid = ber_AlgSha3_384;
        *oid_len = ber_AlgSha3_384Len;
        break;
    case CKM_SHA3_512_RSA_PKCS:
        *oid = ber_AlgSha3_512;
        *oid_len = ber_AlgSha3_512Len;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

//
//
CK_RV rsa_hash_pkcs_sign(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_BBOOL length_only,
                         SIGN_VERIFY_CONTEXT *ctx,
                         CK_BYTE *in_data,
                         CK_ULONG in_data_len,
                         CK_BYTE *signature, CK_ULONG *sig_len)
{
    CK_BYTE *ber_data = NULL;
    CK_BYTE *octet_str = NULL;
    const CK_BYTE *oid = NULL;
    CK_BYTE *tmp = NULL;

    CK_ULONG buf1[16];          // 64 bytes is more than enough

    // must be large enough for the largest hash
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    SIGN_VERIFY_CONTEXT sign_ctx;
    CK_MECHANISM digest_mech;
    CK_MECHANISM sign_mech;
    CK_ULONG ber_data_len, hash_len, octet_str_len, oid_len;
    CK_RV rc;

    if (!sess || !ctx || !in_data) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    memset(&digest_ctx, 0x0, sizeof(digest_ctx));
    memset(&sign_ctx, 0x0, sizeof(sign_ctx));

    rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
        return rc;
    }

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = rsa_pkcs_alg_oid_from_mech(ctx->mech.mechanism, &oid, &oid_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s rsa_pkcs_alg_oid_from_mech failed\n", __func__);
        return rc;
    }

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }
    hash_len = sizeof(hash);
    rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx, in_data,
                           in_data_len, hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Digest failed.\n");
        digest_mgr_cleanup(tokdata, sess, &digest_ctx);
        return rc;
    }
    // build the BER-encodings

    rc = ber_encode_OCTET_STRING(FALSE, &octet_str, &octet_str_len, hash,
                                 hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed.\n");
        goto error;
    }
    tmp = (CK_BYTE *) buf1;
    memcpy(tmp, oid, oid_len);
    memcpy(tmp + oid_len, octet_str, octet_str_len);

    rc = ber_encode_SEQUENCE(FALSE, &ber_data, &ber_data_len, tmp,
                             (oid_len + octet_str_len));
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_SEQUENCE failed.\n");
        goto error;
    }
    // sign the BER-encoded data block


    sign_mech.mechanism = CKM_RSA_PKCS;
    sign_mech.ulParameterLen = 0;
    sign_mech.pParameter = NULL;

    rc = sign_mgr_init(tokdata, sess, &sign_ctx, &sign_mech, FALSE, ctx->key,
                       FALSE, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign Mgr Init failed.\n");
        goto error;
    }
    rc = sign_mgr_sign(tokdata, sess, length_only, &sign_ctx, ber_data,
                       ber_data_len, signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Sign Mgr Sign failed.\n");

error:
    if (octet_str)
        free(octet_str);
    if (ber_data)
        free(ber_data);
    sign_mgr_cleanup(tokdata, sess, &sign_ctx);

    return rc;
}


//
//
CK_RV rsa_hash_pkcs_sign_update(STDLL_TokData_t *tokdata,
                               SESSION *sess,
                               SIGN_VERIFY_CONTEXT *ctx,
                               CK_BYTE *in_data, CK_ULONG in_data_len)
{
    RSA_DIGEST_CONTEXT *context = NULL;
    CK_MECHANISM digest_mech;
    CK_RV rc;

    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (RSA_DIGEST_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
            return rc;
        }

        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &context->hash_context,
                             &digest_mech, FALSE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }
        context->flag = TRUE;
        ctx->state_unsaveable |= context->hash_context.state_unsaveable;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                  in_data, in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Digest failed.\n");
        return rc;
    }

    return CKR_OK;
}


//
//
CK_RV rsa_hash_pkcs_verify(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *in_data,
                           CK_ULONG in_data_len,
                           CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE *ber_data = NULL;
    CK_BYTE *octet_str = NULL;
    const CK_BYTE *oid = NULL;
    CK_BYTE *tmp = NULL;

    CK_ULONG buf1[16];          // 64 bytes is more than enough
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    DIGEST_CONTEXT digest_ctx;
    SIGN_VERIFY_CONTEXT verify_ctx;
    CK_MECHANISM digest_mech;
    CK_MECHANISM verify_mech;
    CK_ULONG ber_data_len, hash_len, octet_str_len, oid_len;
    CK_RV rc;

    if (!sess || !ctx || !in_data) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    memset(&digest_ctx, 0x0, sizeof(digest_ctx));
    memset(&verify_ctx, 0x0, sizeof(verify_ctx));

    rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
        return rc;
    }

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = rsa_pkcs_alg_oid_from_mech(ctx->mech.mechanism, &oid, &oid_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s rsa_pkcs_alg_oid_from_mech failed\n", __func__);
        return rc;
    }

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Init failed.\n");
        return rc;
    }
    hash_len = sizeof(hash);
    rc = digest_mgr_digest(tokdata, sess, FALSE, &digest_ctx, in_data,
                           in_data_len, hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Digest failed.\n");
        digest_mgr_cleanup(tokdata, sess, &digest_ctx);
        return rc;
    }
    // Build the BER encoding
    //
    rc = ber_encode_OCTET_STRING(FALSE, &octet_str, &octet_str_len, hash,
                                 hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed.\n");
        goto done;
    }
    tmp = (CK_BYTE *) buf1;
    memcpy(tmp, oid, oid_len);
    memcpy(tmp + oid_len, octet_str, octet_str_len);

    rc = ber_encode_SEQUENCE(FALSE, &ber_data, &ber_data_len, tmp,
                             (oid_len + octet_str_len));
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_SEQUENCE failed.\n");
        goto done;
    }
    // Verify the Signed BER-encoded Data block
    //
    verify_mech.mechanism = CKM_RSA_PKCS;
    verify_mech.ulParameterLen = 0;
    verify_mech.pParameter = NULL;

    rc = verify_mgr_init(tokdata, sess, &verify_ctx, &verify_mech, FALSE,
                         ctx->key, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Verify Mgr Init failed.\n");
        goto done;
    }
    rc = verify_mgr_verify(tokdata, sess, &verify_ctx, ber_data, ber_data_len,
                           signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Verify Mgr Verify failed.\n");
done:
    if (octet_str)
        free(octet_str);
    if (ber_data)
        free(ber_data);
    sign_mgr_cleanup(tokdata, sess, &verify_ctx);

    return rc;
}

//
//
CK_RV rsa_hash_pkcs_verify_update(STDLL_TokData_t *tokdata,
                                  SESSION *sess,
                                  SIGN_VERIFY_CONTEXT *ctx,
                                  CK_BYTE *in_data, CK_ULONG in_data_len)
{
    RSA_DIGEST_CONTEXT *context = NULL;
    CK_MECHANISM digest_mech;
    CK_RV rc;

    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (RSA_DIGEST_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = get_digest_from_mech(ctx->mech.mechanism, &digest_mech.mechanism);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
            return rc;
        }

        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        rc = digest_mgr_init(tokdata, sess, &context->hash_context,
                             &digest_mech, FALSE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Mgr Init failed.\n");
            return rc;
        }
        context->flag = TRUE;
        ctx->state_unsaveable |= context->hash_context.state_unsaveable;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                  in_data, in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Update failed.\n");
        return rc;
    }

    return CKR_OK;
}


//
//
CK_RV rsa_hash_pkcs_sign_final(STDLL_TokData_t *tokdata,
                               SESSION *sess,
                               CK_BBOOL length_only,
                               SIGN_VERIFY_CONTEXT *ctx,
                               CK_BYTE *signature, CK_ULONG *sig_len)
{
    CK_BYTE *ber_data = NULL;
    CK_BYTE *octet_str = NULL;
    const CK_BYTE *oid = NULL;
    CK_BYTE *tmp = NULL;

    CK_ULONG buf1[16];          // 64 bytes is more than enough

    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    RSA_DIGEST_CONTEXT *context = NULL;
    CK_ULONG ber_data_len, hash_len, octet_str_len, oid_len;
    CK_MECHANISM sign_mech;
    SIGN_VERIFY_CONTEXT sign_ctx;
    CK_RV rc;

    if (!sess || !ctx || !sig_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = rsa_pkcs_alg_oid_from_mech(ctx->mech.mechanism, &oid, &oid_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s rsa_pkcs_alg_oid_from_mech failed\n", __func__);
        return rc;
    }

    memset(&sign_ctx, 0x0, sizeof(sign_ctx));

    context = (RSA_DIGEST_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = rsa_hash_pkcs_sign_update(tokdata, sess, ctx, NULL, 0);
        TRACE_DEVEL("rsa_hash_pkcs_sign_update\n");
        if (rc != 0)
            return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, length_only,
                                 &context->hash_context, hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }
    // Build the BER Encoded Data block
    //
    rc = ber_encode_OCTET_STRING(FALSE, &octet_str, &octet_str_len, hash,
                                 hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed.\n");
        return rc;
    }
    tmp = (CK_BYTE *) buf1;
    memcpy(tmp, oid, oid_len);
    memcpy(tmp + oid_len, octet_str, octet_str_len);

    rc = ber_encode_SEQUENCE(FALSE, &ber_data, &ber_data_len, tmp,
                             (oid_len + octet_str_len));
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_SEQUENCE failed.\n");
        goto done;
    }
    // sign the BER-encoded data block
    //

    sign_mech.mechanism = CKM_RSA_PKCS;
    sign_mech.ulParameterLen = 0;
    sign_mech.pParameter = NULL;

    rc = sign_mgr_init(tokdata, sess, &sign_ctx, &sign_mech, FALSE, ctx->key,
                       FALSE, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign Mgr Init failed.\n");
        goto done;
    }
    rc = sign_mgr_sign(tokdata, sess, length_only, &sign_ctx, ber_data,
                       ber_data_len, signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Sign Mgr Sign failed.\n");

   /** Not sure why this check is here */
    if (length_only == TRUE || rc == CKR_BUFFER_TOO_SMALL)
        goto done;

done:
    if (octet_str)
        free(octet_str);
    if (ber_data)
        free(ber_data);
    sign_mgr_cleanup(tokdata, sess, &sign_ctx);

    return rc;
}


//
//
CK_RV rsa_hash_pkcs_verify_final(STDLL_TokData_t *tokdata,
                                 SESSION *sess,
                                 SIGN_VERIFY_CONTEXT *ctx,
                                 CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE *ber_data = NULL;
    CK_BYTE *octet_str = NULL;
    const CK_BYTE *oid = NULL;
    CK_BYTE *tmp = NULL;

    CK_ULONG buf1[16];          // 64 bytes is more than enough
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    RSA_DIGEST_CONTEXT *context = NULL;
    CK_ULONG ber_data_len, hash_len, octet_str_len, oid_len;
    CK_MECHANISM verify_mech;
    SIGN_VERIFY_CONTEXT verify_ctx;
    CK_RV rc;

    if (!sess || !ctx || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = rsa_pkcs_alg_oid_from_mech(ctx->mech.mechanism, &oid, &oid_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s rsa_pkcs_alg_oid_from_mech failed\n", __func__);
        return rc;
    }

    memset(&verify_ctx, 0x0, sizeof(verify_ctx));

    context = (RSA_DIGEST_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = rsa_hash_pkcs_verify_update(tokdata, sess, ctx, NULL, 0);
        TRACE_DEVEL("rsa_hash_pkcs_verify_update\n");
        if (rc != 0)
            return rc;
    }

    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &context->hash_context,
                                 hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Mgr Final failed.\n");
        return rc;
    }
    // Build the BER encoding
    //
    rc = ber_encode_OCTET_STRING(FALSE, &octet_str, &octet_str_len, hash,
                                 hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_OCTET_STRING failed.\n");
        goto done;
    }
    tmp = (CK_BYTE *) buf1;
    memcpy(tmp, oid, oid_len);
    memcpy(tmp + oid_len, octet_str, octet_str_len);

    rc = ber_encode_SEQUENCE(FALSE, &ber_data, &ber_data_len, tmp,
                             (oid_len + octet_str_len));
    if (rc != CKR_OK) {
        TRACE_DEVEL("ber_encode_SEQUENCE failed.\n");
        goto done;
    }
    // verify the signed BER-encoded data block
    //

    verify_mech.mechanism = CKM_RSA_PKCS;
    verify_mech.ulParameterLen = 0;
    verify_mech.pParameter = NULL;

    rc = verify_mgr_init(tokdata, sess, &verify_ctx, &verify_mech, FALSE,
                         ctx->key, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Verify Mgr Init failed.\n");
        goto done;
    }
    rc = verify_mgr_verify(tokdata, sess, &verify_ctx, ber_data, ber_data_len,
                           signature, sig_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("Verify Mgr Verify failed.\n");
done:
    if (octet_str)
        free(octet_str);
    if (ber_data)
        free(ber_data);
    verify_mgr_cleanup(tokdata, sess, &verify_ctx);

    return rc;
}


//
// mechanisms
//



//
//
CK_RV ckm_rsa_key_pair_gen(STDLL_TokData_t *tokdata,
                           TEMPLATE *publ_tmpl, TEMPLATE *priv_tmpl)
{
    CK_RV rc;

    /* check for token specific call first */
    if (token_specific.t_rsa_generate_keypair == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    rc = token_specific.t_rsa_generate_keypair(tokdata, publ_tmpl, priv_tmpl);
    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific rsa generate keypair failed.\n");

    return rc;
}

CK_RV mgf1(STDLL_TokData_t *tokdata, const CK_BYTE *seed, CK_ULONG seedlen,
           CK_BYTE *mask, CK_ULONG maskLen, CK_RSA_PKCS_MGF_TYPE mgf)
{

    int i;
    char *seed_buffer;
    unsigned char counter[4];
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    CK_RV rc = CKR_OK;
    CK_MECHANISM_TYPE mech;
    CK_ULONG hlen, T_len = 0;

    if (!mask || !seed)
        return CKR_FUNCTION_FAILED;

    rc = get_mgf_mech(mgf, &mech);
    if (rc != CKR_OK)
        return CKR_FUNCTION_FAILED;

    rc = get_sha_size(mech, &hlen);
    if (rc != CKR_OK)
        return CKR_FUNCTION_FAILED;

    /* do some preparations */
    seed_buffer = malloc(seedlen + 4);
    if (seed_buffer == NULL)
        return CKR_HOST_MEMORY;

    T_len = maskLen;
    for (i = 0; T_len > 0; i++) {
        /* convert i to an octet string of length 4 octets. */
        counter[0] = (unsigned char) ((i >> 24) & 0xff);
        counter[1] = (unsigned char) ((i >> 16) & 0xff);
        counter[2] = (unsigned char) ((i >> 8) & 0xff);
        counter[3] = (unsigned char) (i & 0xff);

        /* concatenate seed and octet string */
        memset(seed_buffer, 0, seedlen + 4);
        memcpy(seed_buffer, seed, seedlen);
        memcpy(seed_buffer + seedlen, counter, 4);

        /* compute hash of concatenated seed and octet string */
        rc = compute_sha(tokdata, (CK_BYTE *)seed_buffer, seedlen + 4, hash,
                         mech);
        if (rc != CKR_OK)
            goto done;

        if (T_len >= hlen) {
            memcpy(mask + (i * hlen), hash, hlen);
            T_len -= hlen;
        } else {
            /* in the case masklen is not a multiple of the
             * of the hash length, only copy over remainder
             */
            memcpy(mask + (i * hlen), hash, T_len);
	    T_len = 0;
        }
    }

done:
    if (seed_buffer)
        free(seed_buffer);

    return rc;
}

// RSA mechanism - EME-OAEP encoding
//
CK_RV encode_eme_oaep(STDLL_TokData_t *tokdata, CK_BYTE *mData, CK_ULONG mLen,
                      CK_BYTE *emData, CK_ULONG modLength,
                      CK_RSA_PKCS_MGF_TYPE mgf, CK_BYTE *hash, CK_ULONG hlen)
{
    int ps_len;
    CK_ULONG dbMask_len, i;
    CK_BYTE *maskedSeed, *maskedDB, *dbMask;
    CK_BYTE seed[MAX_SHA_HASH_SIZE];
    CK_RV rc = CKR_OK;

    if (!mData || !emData) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    /* pkcs1v2.2 Step i:
     * The encoded messages is a concatenated single octet, 0x00 with
     * maskedSeed and maskedDB to create encoded message EM.
     * So lets mark of the places in our output buffer.
     */
    memset(emData, 0, modLength);
    maskedSeed = emData + 1;
    maskedDB = emData + hlen + 1;

    /* pkcs1v2.2, Step b:
     * Generate an octet string PS and concatenate to DB.
     */
    ps_len = modLength - mLen - (2 * hlen) - 2;
    memcpy(maskedDB, hash, hlen);
    memset(maskedDB + hlen, 0, ps_len);

    /* pkcs1v2.2, Step c:
     * We have already concatenated hash and PS to maskedDB.
     * Now just concatenate 0x01 and message.
     */
    maskedDB[hlen + ps_len] = 0x01;
    memcpy(maskedDB + (hlen + ps_len + 1), mData, mLen);

    /* pkcs1v2.2, Step d:
     * Generate a random seed.
     */
    rc = rng_generate(tokdata, seed, hlen);
    if (rc != CKR_OK)
        return rc;

    /* pkcs1v2.2, Step e:
     * Compute dbmask using MGF1.
     */
    dbMask_len = modLength - hlen - 1;
    dbMask = malloc(sizeof(CK_BYTE) * dbMask_len);
    if (dbMask == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    rc = mgf1(tokdata, seed, hlen, dbMask, dbMask_len, mgf);
    if (rc != CKR_OK)
        goto done;

    /* pkcs1v2.2, Step f:
     * Compute maskedDB.
     */
    for (i = 0; i < dbMask_len; i++)
        maskedDB[i] ^= dbMask[i];

    /* pkcs1v2.2, Step g:
     * Compute seedMask using MGF1.
     */
    memset(maskedSeed, 0, hlen);
    rc = mgf1(tokdata, maskedDB, dbMask_len, maskedSeed, hlen, mgf);
    if (rc != CKR_OK)
        goto done;

    /* pkcs1v2.2, Step h:
     * Compute maskedSeed.
     */
    for (i = 0; i < hlen; i++)
        maskedSeed[i] ^= seed[i];
done:
    if (dbMask)
        free(dbMask);

    return rc;
}

CK_RV decode_eme_oaep(STDLL_TokData_t *tokdata, CK_BYTE *emData,
                      CK_ULONG emLen, CK_BYTE *out_data,
                      CK_ULONG *out_data_len, CK_RSA_PKCS_MGF_TYPE mgf,
                      CK_BYTE *hash, CK_ULONG hlen)
{
    size_t i, dblen = 0, mlen = -1, one_index = 0, msg_index;
    unsigned int ok = 0, found_one_byte, mask;
    const unsigned char *maskedseed, *maskeddb;
    unsigned char *db = NULL;
    unsigned char seed[EVP_MAX_MD_SIZE];

    /*
     * The implementation of this function is copied from OpenSSL's function
     * RSA_padding_check_PKCS1_OAEP_mgf1() in crypto/rsa/rsa_oaep.c
     * and is slightly modified to fit to the OpenCryptoki environment.
     *
     * The OpenSSL code is licensed under the Apache License 2.0.
     * You can obtain a copy in the file LICENSE in the OpenSSL source
     * distribution or at https://www.openssl.org/source/license.html
     *
     * Changes include:
     * - Different variable and define names.
     * - Usage of TRACE_ERROR to report errors and issue debug messages.
     * - Different return codes.
     * - No need for copying the input to an allocated 'em' buffer. The caller
     *   guarantees that the size of the input is already the size of the
     *   modulus.
     */

    /*
     * |emLen| is guaranteed by the caller to be the modulus size.
     * |emLen| >= 2 * |hlen| + 2 must hold for the modulus
     * irrespective of the ciphertext, see PKCS #1 v2.2, section 7.1.2.
     * This does not leak any side-channel information.
     */
    if (emLen < 2 * hlen + 2) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        return CKR_ARGUMENTS_BAD;
    }

    dblen = emLen - hlen - 1;
    db = calloc(1, dblen);
    if (db == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        return CKR_HOST_MEMORY;
    }

    /*
     * The first byte must be zero, however we must not leak if this is
     * true. See James H. Manger, "A Chosen Ciphertext  Attack on RSA
     * Optimal Asymmetric Encryption Padding (OAEP) [...]", CRYPTO 2001).
     */
    ok = constant_time_is_zero(emData[0]);

    maskedseed = emData + 1;
    maskeddb = emData + 1 + hlen;

    if (mgf1(tokdata, maskeddb, dblen, seed, hlen, mgf) != CKR_OK)
        goto done;

    for (i = 0; i < hlen; i++)
        seed[i] ^= maskedseed[i];

    if (mgf1(tokdata, seed, hlen, db, dblen, mgf) != CKR_OK)
        goto done;

    for (i = 0; i < dblen; i++)
        db[i] ^= maskeddb[i];

    ok &= constant_time_is_zero(CRYPTO_memcmp(db, hash, hlen));

    found_one_byte = 0;
    for (i = hlen; i < dblen; i++) {
        /*
         * Padding consists of a number of 0-bytes, followed by a 1.
         */
        unsigned int equals1 = constant_time_eq(db[i], 1);
        unsigned int equals0 = constant_time_is_zero(db[i]);
        one_index = constant_time_select_int(~found_one_byte & equals1,
                                             i, one_index);
        found_one_byte |= equals1;
        ok &= (found_one_byte | equals0);
    }

    ok &= found_one_byte;

    /*
     * At this point |good| is zero unless the plaintext was valid,
     * so plaintext-awareness ensures timing side-channels are no longer a
     * concern.
     */
    msg_index = one_index + 1;
    mlen = dblen - msg_index;

    /*
     * For good measure, do this check in constant time as well.
     */
    ok &= constant_time_ge(*out_data_len, mlen);

    /*
     * Move the result in-place by |dblen| - |hlen| - 1 - |mlen| bytes
     * to the left.
     * Then if |good| move |mlen| bytes from |db| + |hlen| + 1 to |out|.
     * Otherwise leave |out| unchanged.
     * Copy the memory back in a way that does not reveal the size of
     * the data being copied via a timing side channel. This requires copying
     * parts of the buffer multiple times based on the bits set in the real
     * length. Clear bits do a non-copy with identical access pattern.
     * The loop below has overall complexity of O(N*log(N)).
     */
    *out_data_len = constant_time_select_int(constant_time_lt(dblen - hlen - 1,
                                                              *out_data_len),
                                             dblen - hlen - 1, *out_data_len);
    for (msg_index = 1; msg_index < dblen - hlen - 1; msg_index <<= 1) {
        mask = ~constant_time_eq(msg_index & (dblen - hlen - 1 - mlen),
                                 0);
        for (i = hlen + 1; i < dblen - msg_index; i++)
            db[i] = constant_time_select_8(mask, db[i + msg_index], db[i]);
    }
    for (i = 0; i < *out_data_len; i++) {
        mask = ok & constant_time_lt(i, mlen);
        out_data[i] = constant_time_select_8(mask, db[i + hlen + 1],
                                             out_data[i]);
    }

done:
    OPENSSL_cleanse(seed, sizeof(seed));
    if (db) {
        OPENSSL_cleanse(db, dblen);
        free(db);
    }

    *out_data_len = constant_time_select_int(ok, mlen, 0);

    return constant_time_select_int(ok, CKR_OK, CKR_ENCRYPTED_DATA_INVALID);
}

CK_RV emsa_pss_encode(STDLL_TokData_t *tokdata,
                      CK_RSA_PKCS_PSS_PARAMS *pssParms, CK_BYTE *in_data,
                      CK_ULONG in_data_len, CK_BYTE *em, CK_ULONG *modbytes)
{
    CK_BYTE *salt, *DB, *H, *buf = NULL;
    CK_ULONG emBits, emLen, buflen, hlen, PSlen, i;
    CK_RV rc = CKR_OK;

    /*
     * Note: pkcs#11v2.20, Section 12.1.10:
     * in_data is the hashed message, mHash.
     *
     * Note: em is provided by the caller. It should be big enough to
     * hold k bytes of data, where k is the length in octets of the
     * modulus n.
     */

    /* pkcs1v2.2 8.1.1 describes emBits as length in bits of the
     * modulus - 1. It also says, the octet length of EM will be
     * one less than k if modBits - 1 is divisible by 8 and equal
     * to k otherwise. k is the length in octets of the modulus n.
     */
    emBits = (*modbytes * 8) - 1;
    if ((emBits % 8) == 0)
        emLen = *modbytes - 1;
    else
        emLen = *modbytes;

    /* get hash size based on hashAlg */
    if (get_sha_size(pssParms->hashAlg, &hlen))
        return CKR_MECHANISM_INVALID;

    /* allocate a helper buffer to be used for M' and dbmask */
    buflen = emLen - hlen - 1;
    if (buflen < (8 + hlen + pssParms->sLen))
        buflen = 8 + hlen + pssParms->sLen;
    buf = (CK_BYTE *) malloc(buflen);
    if (buf == NULL)
        return CKR_HOST_MEMORY;

    memset(em, 0, emLen);
    memset(buf, 0, buflen);

    /* set some pointers for EM */
    DB = em;
    H = em + (emLen - hlen - 1);

    /* pkcs1v2.2, Step 3: Check length */
    if (emLen < hlen + pssParms->sLen + 2) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* pkcs1v2.2, Step 4: Generate salt */
    salt = buf + (8 + in_data_len);
    if (pssParms->sLen > 0) {
        rc = rng_generate(tokdata, salt, pssParms->sLen);
        if (rc != CKR_OK)
            goto done;
    }

    /* pkcs1v2.2, Step 5: set M' */
    if (in_data_len > 0)
        memcpy(buf + 8, in_data, in_data_len);

    /* pkcs1v2.2, Step 6: Compute Hash(M') */
    rc = compute_sha(tokdata, buf, 8 + hlen + pssParms->sLen, H,
                     pssParms->hashAlg);
    if (rc != CKR_OK)
        goto done;

    /* pkcs1v2.2, Step 7 & 8: Generate DB */
    PSlen = emLen - pssParms->sLen - hlen - 2;
    DB[PSlen] = 0x01;
    memcpy(DB + (PSlen + 1), salt, pssParms->sLen);

    /* pkcs1v2.2, Step 9: Generate dbMask
     * Note: reuse "buf" for dbMask.
     */
    memset(buf, 0, buflen);
    rc = mgf1(tokdata, H, hlen, buf, emLen - hlen - 1, pssParms->mgf);
    if (rc != CKR_OK)
        goto done;

    /* pkcs1v2.2, Step 10: Compute maskedDB */
    for (i = 0; i < (emLen - hlen - 1); i++)
        em[i] ^= buf[i];

    /* pkcs1v2.2, Step 11: Set leftmost bits to zero. */
    em[0] &= 0xFF >> (8 * emLen - emBits);

    /* pkcs1v2.2, Step 12: EM = maskedDB || H || 0xbc */
    em[emLen - 1] = 0xbc;
    *modbytes = emLen;

done:
    if (buf)
        free(buf);

    return rc;
}

CK_RV emsa_pss_verify(STDLL_TokData_t *tokdata,
                      CK_RSA_PKCS_PSS_PARAMS *pssParms, CK_BYTE *in_data,
                      CK_ULONG in_data_len, CK_BYTE *sig, CK_ULONG modbytes)
{
    CK_ULONG buflen, hlen, emBits, emLen, plen, i;
    CK_BYTE *salt, *H, *M, *buf = NULL;
    CK_BYTE hash[MAX_SHA_HASH_SIZE];
    CK_RV rc = CKR_OK;

    /* pkcs1v2.2 8.1.1 describes emBits as length in bits of the
     * modulus - 1. It also says, the octet length of EM will be
     * one less than k if modBits - 1 is divisible by 8 and equal
     * to k otherwise. k is the length in octets of the modulus n.
     */
    emBits = (modbytes * 8) - 1;
    if ((emBits % 8) == 0)
        emLen = modbytes - 1;
    else
        emLen = modbytes;

    /* get hash size based on hashAlg */
    if (get_sha_size(pssParms->hashAlg, &hlen))
        return CKR_MECHANISM_INVALID;

    /* set up a big enough helper buffer to be used for M' and DB. */
    buflen = (emLen - hlen - 1) + (8 + hlen + pssParms->sLen);
    buf = (CK_BYTE *) malloc(buflen);
    if (buf == NULL)
        return CKR_HOST_MEMORY;
    memset(buf, 0, buflen);

    /* pkcs1v2.2, Step 4: Check rightmost octet. */
    if (sig[emLen - 1] != 0xbc) {
        rc = CKR_SIGNATURE_INVALID;
        goto done;
    }

    /* pkcs1v2.2, Step 5: Extract maskedDB and H */
    H = sig + (emLen - hlen - 1);

    /* pkcs1v2.2, Step 6: Check leftmost bits */
    if (sig[0] & ~(0xFF >> (8 * emLen - emBits))) {
        rc = CKR_SIGNATURE_INVALID;
        goto done;
    }

    /* pkcs1v2.2, Step 7: Compute mgf. */
    rc = mgf1(tokdata, H, hlen, buf, emLen - hlen - 1, pssParms->mgf);
    if (rc != CKR_OK)
        goto done;

    /* pkcs1v2.2, Step 8: DB = maskedDB ^ dbMask. */
    for (i = 0; i < emLen - hlen - 1; i++)
        buf[i] ^= sig[i];

    /* pkcs1v2.2, Step 9: Set leftmost bits in DB to zero. */
    buf[0] &= 0xFF >> (8 * emLen - emBits);

    /* pkcs1v2.2, Step 10: check DB. */
    i = 0;
    plen = emLen - hlen - pssParms->sLen - 2;
    while ((i < plen) && (buf[i] == 0))
        i++;

    if ((i != plen) || (buf[i++] != 0x01)) {
        rc = CKR_SIGNATURE_INVALID;
        goto done;
    }

    /* pkcs1v2.2, Step 11: Get the salt from DB. */
    salt = buf + i;

    /* pkcs1v2.2, Step 12: Set M'. Note: Use end of buf. */
    M = buf + (i + pssParms->sLen);
    memset(M, 0, 8);
    if (in_data_len > 0)
        memcpy(M + 8, in_data, in_data_len);        // in_data is mHash.
    memcpy(M + (8 + in_data_len), salt, pssParms->sLen);

    /* pkcs1v2.2, Step 13: Compute Hash(M'). */
    rc = compute_sha(tokdata, M, 8 + hlen + pssParms->sLen, hash,
                     pssParms->hashAlg);
    if (rc != CKR_OK)
        goto done;

    /* pkcs1v2.2, Step 14: H == H'. */
    if (CRYPTO_memcmp(hash, H, hlen))
        rc = CKR_SIGNATURE_INVALID;
    else
        rc = CKR_OK;
done:
    if (buf)
        free(buf);

    return rc;
}

CK_RV check_pss_params(CK_MECHANISM *mech, CK_ULONG modlen)
{
    CK_RSA_PKCS_PSS_PARAMS *pssParams;
    CK_MECHANISM_TYPE mgf_mech, digest_mech;
    CK_ULONG hlen;
    CK_RV rc;

    pssParams = (CK_RSA_PKCS_PSS_PARAMS *) mech->pParameter;

    if (mech->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
        mech->pParameter == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /*
     * If the signature mechanism includes hashing, make sure
     * pssParams->hashAlg matches.
     *
     * Note: pkcs#1v2.2, Section 8.1, It is recommended that the
     * hash algorithm used to hash the message be the same as the
     * one used in mgf.
     */
    rc = get_mgf_mech(pssParams->mgf, &mgf_mech);
    if (rc != CKR_OK) {
        TRACE_DEVEL("MGF mechanism is invalid.\n");
        return rc;
    }

    if (mech->mechanism != CKM_RSA_PKCS_PSS) {
        rc = get_digest_from_mech(mech->mechanism, &digest_mech);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s get_digest_from_mech failed\n", __func__);
            return rc;
        }
    } else {
        digest_mech = mgf_mech;
    }

    if (pssParams->hashAlg != digest_mech ||
        pssParams->hashAlg != mgf_mech) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* check the salt length,  pkcs11v2.2 Section 12.1.14 */
    rc = get_sha_size(pssParams->hashAlg, &hlen);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    if (!(pssParams->sLen <= modlen - 2 - hlen)) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    return CKR_OK;
}

CK_RV rsa_aes_key_wrap(STDLL_TokData_t *tokdata, SESSION *sess,
                       CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                       CK_BYTE *in_data, CK_ULONG in_data_len,
                       CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    CK_RSA_AES_KEY_WRAP_PARAMS *params;
    CK_MECHANISM aes_keygen_mech = { CKM_AES_KEY_GEN, NULL, 0 };
    CK_MECHANISM rsa_oaep_mech = { CKM_RSA_PKCS_OAEP, NULL, 0 };
    CK_MECHANISM aeskw_kwm_mech = { CKM_AES_KEY_WRAP_KWP, NULL, 0 };
    ENCR_DECR_CONTEXT aeskw_ctx = { 0 };
    CK_OBJECT_HANDLE aes_key_handle = CK_INVALID_HANDLE;
    CK_ULONG wrapped_aes_key_len = 0, wrapped_key_len = 0, total_len;
    CK_ULONG aes_key_size;
    CK_BBOOL ck_true = TRUE;
    CK_BBOOL ck_false = TRUE;
    CK_RV rc, rc2;

    CK_ATTRIBUTE aes_key_tmpl[] = {
        { CKA_VALUE_LEN, &aes_key_size, sizeof(aes_key_size) },
        { CKA_HIDDEN, &ck_true, sizeof(ck_true) },
        { CKA_EXTRACTABLE, &ck_true, sizeof(ck_true) },
        { CKA_SENSITIVE, &ck_true, sizeof(ck_true) },
        { CKA_TOKEN, &ck_false, sizeof(ck_false) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        { CKA_WRAP, &ck_true, sizeof(ck_true) },
        { CKA_UNWRAP, &ck_false, sizeof(ck_false) },
        { CKA_ENCRYPT, &ck_false, sizeof(ck_false) },
        { CKA_DECRYPT, &ck_false, sizeof(ck_false) },
        { CKA_SIGN, &ck_false, sizeof(ck_false) },
        { CKA_VERIFY, &ck_false, sizeof(ck_false) },
        { CKA_DERIVE, &ck_false, sizeof(ck_false) },
    };

    params = (CK_RSA_AES_KEY_WRAP_PARAMS *)ctx->mech.pParameter;
    if (params->pOAEPParams == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* Generate a temporary AES key of the desired size */
    aes_key_size = params->ulAESKeyBits / 8;
    rc = key_mgr_generate_key(tokdata, sess, &aes_keygen_mech,
                              aes_key_tmpl,
                              sizeof(aes_key_tmpl) / sizeof(CK_ATTRIBUTE),
                              &aes_key_handle, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to generate temporary AES key (%lu bits): "
                    "%s (0x%lx)\n", params->ulAESKeyBits, p11_get_ckr(rc), rc);
        goto done;
    }

    /*
     * Wrap the temporary AES key as first part of the wrapped key data
     * (length-only operation to get the size of the first part).
     */
    rsa_oaep_mech.pParameter = params->pOAEPParams;
    rsa_oaep_mech.ulParameterLen = sizeof(*params->pOAEPParams);

    rc = key_mgr_wrap_key(tokdata, sess, TRUE, &rsa_oaep_mech,
                          ctx->key, aes_key_handle,
                          NULL, &wrapped_aes_key_len, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to wrap temporary AES key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        if (rc == CKR_DATA_LEN_RANGE) {
            /*
             * An AES key of a certain size can only be wrapped by OAEP with a
             * large enough RSA key size. E.g. RSA 1014 with OAEP and SHA-384
             * can not wrap a 32 bytes AES key.
             */
            rc = CKR_WRAPPING_KEY_SIZE_RANGE;
        }
        goto done;
    }

    /*
     * Encrypt (wrap) the to-be-wrapped key as the second part of the wrapped
     * key data (length-only operation to get the size of the second part).
     */
    rc = encr_mgr_init(tokdata, sess, &aeskw_ctx, OP_WRAP,
                       &aeskw_kwm_mech, aes_key_handle, TRUE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to encrypt the to-be-wrapped key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

    rc = encr_mgr_encrypt(tokdata, sess, TRUE, &aeskw_ctx,
                          in_data, in_data_len, NULL, &wrapped_key_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to encrypt the to-be-wrapped key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

    /* Calculate the final length of the wrapped key data */
    total_len = wrapped_aes_key_len + wrapped_key_len;

    if (length_only) {
        *out_data_len = total_len;
        goto done;
    }

    if (*out_data_len < total_len) {
        *out_data_len = total_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    /*  Wrap the temporary AES key as first part of the wrapped key data */
    rc = key_mgr_wrap_key(tokdata, sess, FALSE, &rsa_oaep_mech,
                          ctx->key, aes_key_handle,
                          out_data, &wrapped_aes_key_len, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to wrap temporary AES key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        if (rc == CKR_DATA_LEN_RANGE) {
            /*
             * An AES key of a certain size can only be wrapped by OAEP with a
             * large enough RSA key size. E.g. RSA 1014 with OAEP and SHA-384
             * can not wrap a 32 bytes AES key.
             */
            rc = CKR_WRAPPING_KEY_SIZE_RANGE;
        }
        goto done;
    }

    /*
     * Encrypt (wrap) the to-be-wrapped key as the second part of the wrapped
     * key data.
     */
    rc = encr_mgr_encrypt(tokdata, sess, FALSE, &aeskw_ctx,
                          in_data, in_data_len, out_data + wrapped_aes_key_len,
                          &wrapped_key_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to encrypt the to-be-wrapped key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

    *out_data_len = total_len;

done:
    if (aes_key_handle != CK_INVALID_HANDLE) {
        rc2 = object_mgr_destroy_object(tokdata, sess, aes_key_handle);
        if (rc2 != CKR_OK) {
            TRACE_ERROR("Failed to destroy temporary AES key: %s (0x%lx)\n",
                        p11_get_ckr(rc2), rc2);
            if (rc == CKR_OK)
                rc = rc2;
        }
    }

    encr_mgr_cleanup(tokdata, sess, &aeskw_ctx);

    return rc;
}

CK_RV rsa_aes_key_unwrap(STDLL_TokData_t *tokdata, SESSION *sess,
                         CK_BBOOL length_only, ENCR_DECR_CONTEXT *ctx,
                         CK_BYTE *in_data, CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    CK_RSA_AES_KEY_WRAP_PARAMS *params;
    CK_MECHANISM rsa_oaep_mech = { CKM_RSA_PKCS_OAEP, NULL, 0 };
    CK_MECHANISM aeskw_kwm_mech = { CKM_AES_KEY_WRAP_KWP, NULL, 0 };
    ENCR_DECR_CONTEXT aeskw_ctx = { 0 };
    CK_OBJECT_HANDLE aes_key_handle = CK_INVALID_HANDLE;
    CK_ULONG  modulus_size = 0, value_len = 0;
    CK_OBJECT_CLASS rsa_key_class, aes_key_class = CKO_SECRET_KEY;
    CK_KEY_TYPE aes_key_type = CKK_AES;
    CK_BBOOL ck_true = TRUE;
    CK_BBOOL ck_false = TRUE;
    OBJECT *key_obj = NULL;
    CK_RV rc, rc2;

    CK_ATTRIBUTE aes_key_tmpl[] = {
        { CKA_CLASS, &aes_key_class, sizeof(aes_key_class) },
        { CKA_KEY_TYPE, &aes_key_type, sizeof(aes_key_type) },
        { CKA_HIDDEN, &ck_true, sizeof(ck_true) },
        { CKA_SENSITIVE, &ck_true, sizeof(ck_true) },
        { CKA_TOKEN, &ck_false, sizeof(ck_false) },
        { CKA_PRIVATE, &ck_true, sizeof(ck_true) },
        { CKA_WRAP, &ck_false, sizeof(ck_false) },
        { CKA_UNWRAP, &ck_true, sizeof(ck_true) },
        { CKA_ENCRYPT, &ck_false, sizeof(ck_false) },
        { CKA_DECRYPT, &ck_false, sizeof(ck_false) },
        { CKA_SIGN, &ck_false, sizeof(ck_false) },
        { CKA_VERIFY, &ck_false, sizeof(ck_false) },
        { CKA_DERIVE, &ck_false, sizeof(ck_false) },
    };

    params = (CK_RSA_AES_KEY_WRAP_PARAMS *)ctx->mech.pParameter;
    if (params->pOAEPParams == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        return CKR_MECHANISM_PARAM_INVALID;
    }

    /* Get RSA key size to split off first part of wrapped key data */
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = rsa_get_key_info(key_obj, &modulus_size, &rsa_key_class);
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;
    if (rc != CKR_OK) {
        TRACE_DEVEL("rsa_get_key_info failed.\n");
        return rc;
    }

    if (in_data_len < modulus_size + 2 * AES_KEY_WRAP_BLOCK_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

    /* Unwrap the temporary AES key */
    rsa_oaep_mech.pParameter = params->pOAEPParams;
    rsa_oaep_mech.ulParameterLen = sizeof(*params->pOAEPParams);

    rc = key_mgr_unwrap_key(tokdata, sess, &rsa_oaep_mech,
                            aes_key_tmpl,
                            sizeof(aes_key_tmpl) / sizeof(CK_ATTRIBUTE),
                            in_data, modulus_size, ctx->key, &aes_key_handle,
                            FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to unwrap temporary AES key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

    /* Get the bit-size of the temporary AES key */
    rc = object_mgr_find_in_map1(tokdata, aes_key_handle, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from temporary AES key handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            rc = CKR_KEY_HANDLE_INVALID;
        goto done;
    }

    rc = template_attribute_get_ulong(key_obj->template, CKA_VALUE_LEN,
                                      &value_len);
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to get CKA_VALUE_LEN from temp. AES key.\n");
        return rc;
    }

    /* Update the mechanism param (copy) in context. Might be needed later on */
    params->ulAESKeyBits = value_len * 8;

    /*
     * Decrypt (unwrap) the final key data from the the second part of the
     * wrapped key data.
     */
    rc = decr_mgr_init(tokdata, sess, &aeskw_ctx, OP_UNWRAP,
                       &aeskw_kwm_mech, aes_key_handle, TRUE, FALSE);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to decrypt the to-be-unwrapped key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

    rc = decr_mgr_decrypt(tokdata, sess, length_only, &aeskw_ctx,
                          in_data + modulus_size, in_data_len - modulus_size,
                          out_data, out_data_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to decrypt the to-be-unwrapped key: %s (0x%lx)\n",
                    p11_get_ckr(rc), rc);
        goto done;
    }

done:
    if (aes_key_handle != CK_INVALID_HANDLE) {
        rc2 = object_mgr_destroy_object(tokdata, sess, aes_key_handle);
        if (rc2 != CKR_OK) {
            TRACE_ERROR("Failed to destroy temporary AES key: %s (0x%lx)\n",
                        p11_get_ckr(rc2), rc2);
            if (rc == CKR_OK)
                rc = rc2;
        }
    }

    encr_mgr_cleanup(tokdata, sess, &aeskw_ctx);

    return rc;
}
