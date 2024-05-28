/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  mech_ssl3.c
//
// Mechanisms for SSL v3 support
//

#include <pthread.h>
#include <string.h>             // for memcmp() et al
#include <stdlib.h>
#include <stdio.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "attributes.h"
#include "tok_spec_struct.h"
#include "trace.h"

#include <openssl/crypto.h>

CK_RV ssl3_kmd_process_mac_keys(STDLL_TokData_t *tokdata,
                                SESSION *sess,
                                CK_ATTRIBUTE *pTemplate,
                                CK_ULONG ulCount,
                                CK_OBJECT_HANDLE *client_handle,
                                CK_BYTE *client_value,
                                CK_OBJECT_HANDLE *server_handle,
                                CK_BYTE *server_value, CK_ULONG mac_len);

CK_RV ssl3_kmd_process_write_keys(STDLL_TokData_t *tokdata,
                                  SESSION *sess,
                                  CK_ATTRIBUTE *pTemplate,
                                  CK_ULONG ulCount,
                                  CK_KEY_TYPE keytype,
                                  CK_OBJECT_HANDLE *client_handle,
                                  CK_BYTE *client_value,
                                  CK_OBJECT_HANDLE *server_handle,
                                  CK_BYTE *server_value, CK_ULONG write_len);

// The 'ssl3_mac_*' routines are used with the following mechanisms
//
//    CKM_SSL3_MD5_MAC
//    CKM_SSL3_SHA1_MAC
//

//
//
CK_RV ssl3_mac_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE hash[SHA1_HASH_SIZE];
    CK_BYTE *key_data = NULL;
    CK_BYTE inner[48], outer[48];
    DIGEST_CONTEXT digest_ctx;
    CK_MECHANISM digest_mech;
    CK_ULONG key_bytes, hash_len, mac_len;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    mac_len = *(CK_ULONG *) ctx->mech.pParameter;

    if (length_only == TRUE) {
        *out_data_len = mac_len;
        return CKR_OK;
    }

    if (*out_data_len < mac_len) {
        *out_data_len = mac_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }

    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        goto done;
    }

    key_bytes = attr->ulValueLen;
    key_data = attr->pValue;

    // unlike an HMAC operation, we don't XOR the key with the 0x36 or 0x5C.
    // we just append 48 bytes to the key data
    //
    memset(inner, 0x36, 48);
    memset(outer, 0x5C, 48);

    if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC)
        digest_mech.mechanism = CKM_MD5;
    else
        digest_mech.mechanism = CKM_SHA_1;

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;


    // inner hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Init failed.\n");
        goto done;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, key_data,
                                  key_bytes);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest update failed.\n");
        goto done;
    }
    if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC) {
        rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, inner, 48);
    } else {
        rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, inner, 40);
    }
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest update failed.\n");
        goto done;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, in_data,
                                  in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest update failed.\n");
        goto done;
    }
    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest final failed.\n");
        goto done;
    }
    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));


    // outer hash
    //
    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Init failed.\n");
        goto done;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, key_data,
                                  key_bytes);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest update failed.\n");
        goto done;
    }
    if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC)
        rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, outer, 48);
    else
        rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, outer, 40);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest update failed.\n");
        goto done;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash, hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest update failed.\n");
        goto done;
    }
    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash,
                                 &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest final failed.\n");
        goto done;
    }
    memcpy(out_data, hash, mac_len);
    *out_data_len = mac_len;

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV ssl3_mac_sign_update(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *in_data, CK_ULONG in_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *key_data = NULL;
    SSL3_MAC_CONTEXT *context = NULL;

    CK_BYTE inner[48];
    CK_MECHANISM digest_mech;
    CK_ULONG key_bytes;
    CK_RV rc;


    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (SSL3_MAC_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to acquire key from specified handle.\n");
            if (rc == CKR_OBJECT_HANDLE_INVALID)
                return CKR_KEY_HANDLE_INVALID;
            else
                return rc;
        }
        rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE,
                                              &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE in the template\n");
            goto done;
        }

        key_bytes = attr->ulValueLen;
        key_data = attr->pValue;

        // unlike an HMAC operation, we don't XOR the key with the 0x36 or 0x5C.
        // we just append 48 bytes to the key data
        //
        memset(inner, 0x36, 48);

        if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC)
            digest_mech.mechanism = CKM_MD5;
        else
            digest_mech.mechanism = CKM_SHA_1;

        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        // inner hash
        //
        rc = digest_mgr_init(tokdata, sess, &context->hash_context,
                             &digest_mech, FALSE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Init failed.\n");
            goto done;
        }
        rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                      key_data, key_bytes);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest update failed.\n");
            goto done;
        }
        if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC)
            rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                          inner, 48);
        else
            rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                          inner, 40);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest update failed.\n");
            goto done;
        }
        context->flag = TRUE;
        ctx->state_unsaveable |= context->hash_context.state_unsaveable;
    }


    rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                  in_data, in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest update failed.\n");
        goto done;
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV ssl3_mac_sign_final(STDLL_TokData_t *tokdata,
                          SESSION *sess,
                          CK_BBOOL length_only,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *key_data = NULL;
    CK_BYTE hash[SHA1_HASH_SIZE];
    SSL3_MAC_CONTEXT *context = NULL;

    CK_BYTE outer[48];
    CK_MECHANISM digest_mech;
    CK_ULONG key_bytes, hash_len, mac_len;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    mac_len = *(CK_ULONG *) ctx->mech.pParameter;

    if (length_only == TRUE) {
        *out_data_len = mac_len;
        return CKR_OK;
    }

    if (*out_data_len < mac_len) {
        *out_data_len = mac_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    context = (SSL3_MAC_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = ssl3_mac_sign_update(tokdata, sess, ctx, NULL, 0);
        TRACE_DEVEL("ssl3_mac_sign_update\n");
        if (rc != 0)
            return rc;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }
    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        goto done;
    }

    key_bytes = attr->ulValueLen;
    key_data = attr->pValue;

    // finish the inner hash
    //
    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &context->hash_context,
                                 hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Final failed.\n");
        goto done;
    }
    // now, do the outer hash
    //
    memset(context, 0x0, sizeof(SSL3_MAC_CONTEXT));

    memset(outer, 0x5C, 48);

    if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC)
        digest_mech.mechanism = CKM_MD5;
    else
        digest_mech.mechanism = CKM_SHA_1;

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = digest_mgr_init(tokdata, sess, &context->hash_context, &digest_mech,
                         FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Init failed.\n");
        goto done;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                  key_data, key_bytes);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        goto done;
    }
    if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC)
        rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                      outer, 48);
    else
        rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                      outer, 40);

    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        goto done;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context, hash,
                                  hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        goto done;
    }
    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &context->hash_context,
                                 hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Final failed.\n");
        goto done;
    }
    memcpy(out_data, hash, mac_len);
    *out_data_len = mac_len;

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}



// This routine could replace the HMAC verification routines
//
CK_RV ssl3_mac_verify(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_BYTE mac[SHA1_HASH_SIZE];
    SIGN_VERIFY_CONTEXT mac_ctx;
    CK_ULONG mac_len, len;
    CK_RV rc;

    if (!sess || !ctx || !in_data || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    mac_len = *(CK_ULONG *) ctx->mech.pParameter;

    memset(&mac_ctx, 0, sizeof(SIGN_VERIFY_CONTEXT));

    rc = sign_mgr_init(tokdata, sess, &mac_ctx, &ctx->mech, FALSE, ctx->key,
                       FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign Init failed.\n");
        goto error;
    }
    len = sizeof(mac);
    rc = sign_mgr_sign(tokdata, sess, FALSE, &mac_ctx,
                       in_data, in_data_len, mac, &len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Sign failed.\n");
        goto error;
    }
    if ((len != mac_len) || (len != sig_len)) {
        rc = CKR_SIGNATURE_LEN_RANGE;
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_LEN_RANGE));
        goto error;
    }

    if (CRYPTO_memcmp(mac, signature, mac_len) != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        rc = CKR_SIGNATURE_INVALID;
    }
error:
    sign_mgr_cleanup(tokdata, sess, &mac_ctx);

    return rc;
}


//
//
CK_RV ssl3_mac_verify_update(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             SIGN_VERIFY_CONTEXT *ctx,
                             CK_BYTE *in_data, CK_ULONG in_data_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *key_data = NULL;
    SSL3_MAC_CONTEXT *context = NULL;

    CK_BYTE inner[48];
    CK_MECHANISM digest_mech;
    CK_ULONG key_bytes;
    CK_RV rc;


    if (!sess || !ctx) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (SSL3_MAC_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to acquire key from specified handle.\n");
            if (rc == CKR_OBJECT_HANDLE_INVALID)
                return CKR_KEY_HANDLE_INVALID;
            else
                return rc;
        }

        rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE,
                                              &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VALUE in the template\n");
            goto done;
        }

        key_bytes = attr->ulValueLen;
        key_data = attr->pValue;

        // unlike an HMAC operation, we don't XOR the key with the 0x36 or 0x5C.
        // we just append 48 bytes to the key data
        //
        memset(inner, 0x36, 48);

        if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC)
            digest_mech.mechanism = CKM_MD5;
        else
            digest_mech.mechanism = CKM_SHA_1;

        digest_mech.ulParameterLen = 0;
        digest_mech.pParameter = NULL;

        // inner hash
        //
        rc = digest_mgr_init(tokdata, sess, &context->hash_context,
                             &digest_mech, FALSE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Init failed.\n");
            goto done;
        }
        rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                      key_data, key_bytes);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Update failed.\n");
            goto done;
        }
        if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC)
            rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                          inner, 48);
        else
            rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                          inner, 40);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Update failed.\n");
            goto done;
        }
        context->flag = TRUE;
        ctx->state_unsaveable |= context->hash_context.state_unsaveable;
    }

    rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                  in_data, in_data_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        goto done;
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV ssl3_mac_verify_final(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            SIGN_VERIFY_CONTEXT *ctx,
                            CK_BYTE *signature, CK_ULONG sig_len)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *key_data = NULL;
    SSL3_MAC_CONTEXT *context = NULL;
    CK_BYTE hash[SHA1_HASH_SIZE];

    CK_BYTE outer[48];
    CK_MECHANISM digest_mech;
    CK_ULONG key_bytes, hash_len, mac_len;
    CK_RV rc;


    if (!sess || !ctx || !signature) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    mac_len = *(CK_ULONG *) ctx->mech.pParameter;

    context = (SSL3_MAC_CONTEXT *) ctx->context;

    if (context->flag == FALSE) {
        rc = ssl3_mac_verify_update(tokdata, sess, ctx, NULL, 0);
        TRACE_DEVEL("ssl3_mac_verify_update\n");
        if (rc != 0)
            return rc;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }
    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        goto done;
    }

    key_bytes = attr->ulValueLen;
    key_data = attr->pValue;

    // finish the inner hash
    //
    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &context->hash_context,
                                 hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Final failed.\n");
        goto done;
    }
    // now, do the outer hash
    //
    memset(context, 0x0, sizeof(SSL3_MAC_CONTEXT));

    memset(outer, 0x5C, 48);

    if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC)
        digest_mech.mechanism = CKM_MD5;
    else
        digest_mech.mechanism = CKM_SHA_1;

    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = digest_mgr_init(tokdata, sess, &context->hash_context, &digest_mech,
                         FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Init failed.\n");
        goto done;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                  key_data, key_bytes);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        goto done;
    }
    if (ctx->mech.mechanism == CKM_SSL3_MD5_MAC)
        rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                      outer, 48);
    else
        rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context,
                                      outer, 40);

    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        goto done;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &context->hash_context, hash,
                                  hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        goto done;
    }
    hash_len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &context->hash_context,
                                 hash, &hash_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Final failed.\n");
        goto done;
    }
    if ((mac_len != sig_len) || (mac_len > hash_len)) {
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
        rc = CKR_SIGNATURE_INVALID;
    } else if (CRYPTO_memcmp(signature, hash, sig_len) != 0) {
        rc = CKR_SIGNATURE_INVALID;
        TRACE_ERROR("%s\n", ock_err(ERR_SIGNATURE_INVALID));
    }

done:
    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV ckm_ssl3_pre_master_key_gen(STDLL_TokData_t *tokdata,
                                  TEMPLATE *tmpl, CK_MECHANISM *mech)
{
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *value_len_attr = NULL;
    CK_ATTRIBUTE *key_type_attr = NULL;
    CK_ATTRIBUTE *class_attr = NULL;
    CK_ATTRIBUTE *local_attr = NULL;
    CK_ATTRIBUTE *derive_attr = NULL;
    CK_VERSION *version = NULL;
    CK_BYTE key[48];
    CK_ULONG rc;


    rc = rng_generate(tokdata, key, 48);
    if (rc != CKR_OK) {
        TRACE_DEVEL("rng_generate failed.\n");
        return rc;
    }
    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + 48);
    value_len_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_ULONG));
    key_type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    class_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS));
    local_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));
    derive_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));

    if (!value_attr || !value_len_attr || !key_type_attr ||
        !class_attr || !local_attr || !derive_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    version = (CK_VERSION *) mech->pParameter;
    key[0] = version->major;
    key[1] = version->minor;

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = 48;
    value_attr->pValue = (CK_BYTE *) value_attr + sizeof(CK_ATTRIBUTE);
    memcpy(value_attr->pValue, key, 48);

    value_len_attr->type = CKA_VALUE_LEN;
    value_len_attr->ulValueLen = sizeof(CK_ULONG);
    value_len_attr->pValue = (CK_BYTE *) value_len_attr + sizeof(CK_ATTRIBUTE);
    *(CK_ULONG *) value_len_attr->pValue = 48;

    key_type_attr->type = CKA_KEY_TYPE;
    key_type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    key_type_attr->pValue = (CK_BYTE *) key_type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_ATTRIBUTE_TYPE *) key_type_attr->pValue = CKK_GENERIC_SECRET;

    class_attr->type = CKA_CLASS;
    class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
    class_attr->pValue = (CK_BYTE *) class_attr + sizeof(CK_ATTRIBUTE);
    *(CK_OBJECT_CLASS *) class_attr->pValue = CKO_SECRET_KEY;

    local_attr->type = CKA_LOCAL;
    local_attr->ulValueLen = sizeof(CK_BBOOL);
    local_attr->pValue = (CK_BYTE *) local_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) local_attr->pValue = TRUE;

    derive_attr->type = CKA_DERIVE;
    derive_attr->ulValueLen = sizeof(CK_BBOOL);
    derive_attr->pValue = (CK_BYTE *) derive_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) derive_attr->pValue = TRUE;

    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;
    rc = template_update_attribute(tmpl, value_len_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_len_attr = NULL;
    rc = template_update_attribute(tmpl, key_type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    key_type_attr = NULL;
    rc = template_update_attribute(tmpl, class_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    class_attr = NULL;
    rc = template_update_attribute(tmpl, local_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    local_attr = NULL;
    rc = template_update_attribute(tmpl, derive_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    derive_attr = NULL;

    return CKR_OK;

error:
    if (value_attr)
        free(value_attr);
    if (value_len_attr)
        free(value_len_attr);
    if (key_type_attr)
        free(key_type_attr);
    if (class_attr)
        free(class_attr);
    if (local_attr)
        free(local_attr);
    if (derive_attr)
        free(derive_attr);

    return rc;
}


//
//
static CK_RV ssl3_sha_then_md5(STDLL_TokData_t *tokdata,
                               SESSION *sess,
                               CK_BYTE *secret,
                               CK_BYTE *firstRandom,
                               CK_ULONG firstRandomLen,
                               CK_BYTE *secondRandom,
                               CK_ULONG secondRandomLen,
                               CK_BYTE *variableData,
                               CK_ULONG variableDataLen, CK_BYTE *outBuff)
{
    DIGEST_CONTEXT digest_ctx;
    CK_MECHANISM digest_mech;
    CK_BYTE hash[SHA1_HASH_SIZE];
    CK_ULONG len;
    CK_RV rc;

    // SHA(variableData + secret + firstRandom + secondRandom)
    //
    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));
    digest_mech.mechanism = CKM_SHA_1;
    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Init failed.\n");
        return rc;
    }
    rc = digest_mgr_digest_update(tokdata, sess,
                                  &digest_ctx, variableData, variableDataLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        return rc;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, secret, 48);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        return rc;
    }
    rc = digest_mgr_digest_update(tokdata, sess,
                                  &digest_ctx, firstRandom, firstRandomLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        return rc;
    }
    rc = digest_mgr_digest_update(tokdata, sess,
                                  &digest_ctx, secondRandom, secondRandomLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        return rc;
    }
    len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash, &len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Final failed.\n");
        return rc;
    }
    // MD5(secret + SHA(...))
    //
    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));
    digest_mech.mechanism = CKM_MD5;
    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Init failed.\n");
        return rc;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, secret, 48);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        return rc;
    }
    rc = digest_mgr_digest_update(tokdata, sess, &digest_ctx, hash, len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        return rc;
    }
    len = sizeof(hash);
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, hash, &len);

    if (rc == CKR_OK)
        memcpy(outBuff, hash, len);
    else
        TRACE_DEVEL("Digest Final failed.\n");

    return rc;
}

//
//
static CK_RV ssl3_md5_only(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           CK_BYTE *firstString,
                           CK_ULONG firstStringLen,
                           CK_BYTE *secondString,
                           CK_ULONG secondStringLen,
                           CK_BYTE *thirdString,
                           CK_ULONG thirdStringLen, CK_BYTE *outBuff)
{
    DIGEST_CONTEXT digest_ctx;
    CK_MECHANISM digest_mech;
    CK_ULONG len;
    CK_RV rc;

    // If firstString is not NULL,
    //
    // MD5(firstString + secondString + thirdString)
    //
    // If firstString is NULL
    //
    // MD5(secondString + thirdString)
    //
    memset(&digest_ctx, 0x0, sizeof(DIGEST_CONTEXT));
    digest_mech.mechanism = CKM_MD5;
    digest_mech.ulParameterLen = 0;
    digest_mech.pParameter = NULL;

    rc = digest_mgr_init(tokdata, sess, &digest_ctx, &digest_mech, FALSE);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Init failed.\n");
        return rc;
    }
    if (firstString != NULL) {
        rc = digest_mgr_digest_update(tokdata, sess,
                                      &digest_ctx, firstString, firstStringLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Digest Update failed.\n");
            return rc;
        }
    }

    rc = digest_mgr_digest_update(tokdata, sess,
                                  &digest_ctx, secondString, secondStringLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        return rc;
    }
    rc = digest_mgr_digest_update(tokdata, sess,
                                  &digest_ctx, thirdString, thirdStringLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Update failed.\n");
        return rc;
    }
    len = MD5_HASH_SIZE;
    rc = digest_mgr_digest_final(tokdata, sess, FALSE, &digest_ctx, outBuff,
                                 &len);

    if (rc != CKR_OK) {
        TRACE_DEVEL("Digest Final failed.\n");
    }

    return rc;
}

//
//
CK_RV ssl3_master_key_derive(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_MECHANISM *mech,
                             OBJECT* base_key_obj,
                             CK_ATTRIBUTE *pTemplate,
                             CK_ULONG ulCount, CK_OBJECT_HANDLE *handle)
{
    OBJECT *derived_key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *value_len_attr = NULL;
    CK_BYTE *base_key_value = NULL;
    CK_BYTE key_data[48];
    CK_ULONG base_key_len;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE keytype;
    CK_ULONG value_len;
    CK_RV rc;

    CK_SSL3_MASTER_KEY_DERIVE_PARAMS *params = NULL;
    CK_SSL3_RANDOM_DATA *random_data = NULL;


    if (!sess || !mech) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    params = (CK_SSL3_MASTER_KEY_DERIVE_PARAMS *) mech->pParameter;

    rc = template_attribute_get_non_empty(base_key_obj->template, CKA_VALUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        goto error;
    }

    base_key_len = attr->ulValueLen;
    base_key_value = attr->pValue;

    if (base_key_len != 48) {
        TRACE_ERROR("The base key's length is not 48.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto error;
    }

    // this mechanism implies the following attributes:
    //    CKA_CLASS     : CKO_SECRET_KEY
    //    CKA_KEY_TYPE  : CKK_GENERIC_SECRET
    //    CKA_VALUE_LEN : 48
    // but we need to make sure the caller didn't specify any
    // wacky values.  it would have been better if Cryptoki had forbidden
    // these attributes from appearing in the template
    //
    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_CLASS,
                                     &class);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && class != CKO_SECRET_KEY) {
        TRACE_ERROR("This operation requires a secret key.\n");
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto error;
    }

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_KEY_TYPE,
                                     &keytype);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && keytype != CKK_GENERIC_SECRET) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto error;
    }

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_VALUE_LEN,
                                     &value_len);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && value_len != 48) {
        TRACE_ERROR("The derived key's length is not 48.\n");
        rc = CKR_TEMPLATE_INCONSISTENT;
        goto error;
    }

    memset(key_data, 0x0, sizeof(key_data));

    random_data = (CK_SSL3_RANDOM_DATA *) (&params->RandomInfo);

    // derive the master key data
    //
    rc = ssl3_sha_then_md5(tokdata, sess,
                           base_key_value,
                           random_data->pClientRandom,
                           random_data->ulClientRandomLen,
                           random_data->pServerRandom,
                           random_data->ulServerRandomLen,
                           (unsigned char *) "A", 1, key_data);

    if (rc != CKR_OK) {
        TRACE_DEVEL("ssl3_sha_then_md5 failed.\n");
        goto error;
    }
    rc = ssl3_sha_then_md5(tokdata, sess,
                           base_key_value,
                           random_data->pClientRandom,
                           random_data->ulClientRandomLen,
                           random_data->pServerRandom,
                           random_data->ulServerRandomLen,
                           (unsigned char *) "BB", 2, &key_data[16]);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ssl3_sha_then_md5 failed.\n");
        goto error;
    }
    rc = ssl3_sha_then_md5(tokdata, sess,
                           base_key_value,
                           random_data->pClientRandom,
                           random_data->ulClientRandomLen,
                           random_data->pServerRandom,
                           random_data->ulServerRandomLen,
                           (unsigned char *) "CCC", 3, &key_data[32]);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ssl3_sha_then_md5 failed.\n");
        goto error;
    }
    // build the key skeleton
    //
    rc = object_mgr_create_skel(tokdata, sess,
                                pTemplate, ulCount,
                                MODE_DERIVE,
                                CKO_SECRET_KEY, CKK_GENERIC_SECRET,
                                &derived_key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr Create Skeleton failed.\n");
        goto error;
    }

    rc = build_attribute(CKA_VALUE, key_data, 48, &value_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to build CKA_VALUE attribute.\n");
        goto error;
    }
    rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *) & base_key_len,
                         sizeof(CK_ULONG), &value_len_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to build CKA_VALUE_LEN attribute.\n");
        goto error;
    }

    rc = key_mgr_derive_always_sensitive_never_extractable_attrs(tokdata,
                                                base_key_obj, derived_key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("key_mgr_derive_always_sensitive_never_extractable_attrs "
                    "failed\n");
        goto error;
    }

    rc = template_update_attribute(derived_key_obj->template, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_attr = NULL;
    rc = template_update_attribute(derived_key_obj->template, value_len_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    value_len_attr = NULL;

    // at this point, the derived key is fully constructed...assign an
    // object handle and store the key
    //
    rc = object_mgr_create_final(tokdata, sess, derived_key_obj, handle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr create final failed.\n");
        object_free(derived_key_obj);
        derived_key_obj = NULL;
        object_put(tokdata, base_key_obj, TRUE);
        base_key_obj = NULL;
        return rc;              // do NOT goto error
    }
    // should we destroy the base key?  SSL3 says yes but that might
    // occur in a separate call to C_DestroyObject
    //

    INC_COUNTER(tokdata, sess, mech, base_key_obj, POLICY_STRENGTH_IDX_0);

    return CKR_OK;

error:
    if (value_attr)
        free(value_attr);
    if (value_len_attr)
        free(value_len_attr);
    if (derived_key_obj)
        object_free(derived_key_obj);

    return rc;
}


//
//
CK_RV ssl3_key_and_mac_derive(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              CK_MECHANISM *mech,
                              OBJECT *base_key_obj,
                              CK_ATTRIBUTE *pTemplate, CK_ULONG ulCount)
{
    CK_ATTRIBUTE *attr = NULL;

    CK_BYTE *client_MAC_key_value = NULL;
    CK_BYTE *server_MAC_key_value = NULL;
    CK_BYTE *client_write_key_value = NULL;
    CK_BYTE *server_write_key_value = NULL;
    CK_BYTE *client_IV = NULL;
    CK_BYTE *server_IV = NULL;
    CK_KEY_TYPE keytype;
    CK_BYTE variable_data[26];
    CK_BYTE key_block[(16 * 26) + (4 * 16)];
    CK_ULONG i, key_material_loop_count;
    CK_ULONG iv_len = 0, MAC_len, write_len;
    CK_BBOOL tmp;
    CK_OBJECT_CLASS cl;
    CK_RV rc;

    CK_BYTE *base_key_value = NULL;
    CK_BBOOL base_sensitive;
    CK_BBOOL base_always_sensitive;
    CK_BBOOL base_extractable;
    CK_BBOOL base_never_extractable;

    CK_OBJECT_HANDLE client_MAC_handle = 0;
    CK_OBJECT_HANDLE server_MAC_handle = 0;
    CK_OBJECT_HANDLE client_write_handle = 0;
    CK_OBJECT_HANDLE server_write_handle = 0;

    CK_SSL3_KEY_MAT_PARAMS *params = NULL;

    ATTRIBUTE_PARSE_LIST base_attrs[] = {
        {CKA_SENSITIVE, &base_sensitive, sizeof(CK_BBOOL), FALSE},
        {CKA_EXTRACTABLE, &base_extractable, sizeof(CK_BBOOL), FALSE},
        {CKA_ALWAYS_SENSITIVE, &base_always_sensitive, sizeof(CK_BBOOL), FALSE},
        {CKA_NEVER_EXTRACTABLE,
            &base_never_extractable, sizeof(CK_BBOOL), FALSE},
    };


    if (!sess || !mech) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    params = (CK_SSL3_KEY_MAT_PARAMS *) mech->pParameter;

    rc = template_attribute_get_non_empty(base_key_obj->template, CKA_VALUE,
                                          &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE in the template\n");
        goto error;
    }

    base_key_value = attr->pValue;

    template_attribute_find_multiple(base_key_obj->template, base_attrs, 4);

    for (i = 0; i < 4; i++) {
        if (base_attrs[i].found == FALSE) {
            TRACE_ERROR("Could not find attribute in the template\n");
            rc = CKR_FUNCTION_FAILED;
            goto error;
        }
    }

    // The SSL3 spec says the IVs are 16 bytes long in the exportable case.
    // For now, we'll barf if someone asks for an exportable output and asks
    // for more than 128 bits of IV...
    //
    if (params->bIsExport != FALSE && params->ulIVSizeInBits > 128) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
        rc = CKR_MECHANISM_PARAM_INVALID;
        goto error;
    }
    // the template must specify the key type for the client and server keys
    //
    // also, CKA_SENSITIVE, CKA_ALWAYS_SENSITIVE, CKA_EXTRACTABLE and
    // CKA_NEVER_EXTRACTABLE, if present, are not allowed to differ from
    // the base key.  We also check for stupid stuff.
    //
    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_KEY_TYPE,
                                     &keytype);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
        goto error;
    }

    rc = get_ulong_attribute_by_type(pTemplate, ulCount, CKA_CLASS,
                                     &cl);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && cl != CKO_SECRET_KEY) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        rc = CKR_TEMPLATE_INCONSISTENT;
        goto error;
    }

    rc = get_bool_attribute_by_type(pTemplate, ulCount, CKA_SENSITIVE,
                                    &tmp);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && tmp != base_sensitive) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        rc = CKR_TEMPLATE_INCONSISTENT;
        goto error;
    }

    rc = get_bool_attribute_by_type(pTemplate, ulCount, CKA_ALWAYS_SENSITIVE,
                                    &tmp);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && tmp != base_always_sensitive) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        rc = CKR_TEMPLATE_INCONSISTENT;
        goto error;
    }

    rc = get_bool_attribute_by_type(pTemplate, ulCount, CKA_EXTRACTABLE,
                                    &tmp);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && tmp != base_extractable) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        rc = CKR_TEMPLATE_INCONSISTENT;
        goto error;
    }

    rc = get_bool_attribute_by_type(pTemplate, ulCount, CKA_NEVER_EXTRACTABLE,
                                    &tmp);
    if (rc == CKR_ATTRIBUTE_VALUE_INVALID) {
        TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
    if (rc == CKR_OK && tmp != base_never_extractable) {
        TRACE_ERROR("%s\n", ock_err(ERR_TEMPLATE_INCONSISTENT));
        rc = CKR_TEMPLATE_INCONSISTENT;
        goto error;
    }

    // figure out how much key material we need to generate
    //
    key_material_loop_count = 2 * ((params->ulMacSizeInBits + 7) / 8) +
        2 * ((params->ulKeySizeInBits + 7) / 8);

    if (params->bIsExport == FALSE)
        key_material_loop_count += 2 * ((params->ulIVSizeInBits + 7) / 8);

    // we stop at 'ZZZZ....'  presumably this is enough for all cases?
    //
    if (key_material_loop_count > 26 * 16) {
        TRACE_DEVEL("key_material_loop_count is too big.\n");
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }
    key_material_loop_count = (key_material_loop_count + 15) / 16;

    // generate the key material
    //
    for (i = 0; i < key_material_loop_count; i++) {
        memset(variable_data, ('A' + i), i + 1);

        rc = ssl3_sha_then_md5(tokdata, sess,
                               base_key_value,
                               params->RandomInfo.pServerRandom,
                               params->RandomInfo.ulServerRandomLen,
                               params->RandomInfo.pClientRandom,
                               params->RandomInfo.ulClientRandomLen,
                               variable_data, i + 1, &(key_block[i * 16]));
        if (rc != CKR_OK) {
            TRACE_DEVEL("ssl3_sha_then_md5 failed.\n");
            goto error;
        }
    }

    // Break key material into pieces
    //
    MAC_len = (params->ulMacSizeInBits + 7) / 8;
    write_len = (params->ulKeySizeInBits + 7) / 8;      // check this

    client_MAC_key_value = key_block;
    server_MAC_key_value = client_MAC_key_value + MAC_len;

    client_write_key_value = server_MAC_key_value + MAC_len;
    server_write_key_value =
        client_write_key_value + (params->ulKeySizeInBits + 7) / 8;

    if (params->ulIVSizeInBits != 0) {
        iv_len = (params->ulIVSizeInBits + 7) / 8;
        client_IV = server_write_key_value + write_len;
        server_IV = client_IV + iv_len;
    }
    // Exportable ciphers require additional processing
    //
    if (params->bIsExport == TRUE) {
        rc = ssl3_md5_only(tokdata, sess,
                           client_write_key_value,
                           (params->ulKeySizeInBits + 7) / 8,
                           params->RandomInfo.pClientRandom,
                           params->RandomInfo.ulClientRandomLen,
                           params->RandomInfo.pServerRandom,
                           params->RandomInfo.ulServerRandomLen,
                           &(key_block[16 * 26]));
        if (rc != CKR_OK) {
            TRACE_DEVEL("ssl3_md5_only failed.\n");
            goto error;
        }
        client_write_key_value = &(key_block[16 * 26]);

        rc = ssl3_md5_only(tokdata, sess,
                           server_write_key_value,
                           (params->ulKeySizeInBits + 7) / 8,
                           params->RandomInfo.pServerRandom,
                           params->RandomInfo.ulServerRandomLen,
                           params->RandomInfo.pClientRandom,
                           params->RandomInfo.ulClientRandomLen,
                           &(key_block[16 * 26 + 16]));
        if (rc != CKR_OK) {
            TRACE_DEVEL("ssl3_md5_only failed.\n");
            goto error;
        }
        server_write_key_value = &(key_block[16 * 26 + 16]);

        if (params->ulIVSizeInBits != 0) {
            rc = ssl3_md5_only(tokdata, sess,
                               NULL,
                               0,
                               params->RandomInfo.pClientRandom,
                               params->RandomInfo.ulClientRandomLen,
                               params->RandomInfo.pServerRandom,
                               params->RandomInfo.ulServerRandomLen,
                               &(key_block[16 * 26 + 2 * 16]));
            if (rc != CKR_OK) {
                TRACE_DEVEL("ssl3_md5_only failed.\n");
                goto error;
            }
            client_IV = &(key_block[16 * 26 + 2 * 16]);

            rc = ssl3_md5_only(tokdata, sess,
                               NULL,
                               0,
                               params->RandomInfo.pServerRandom,
                               params->RandomInfo.ulServerRandomLen,
                               params->RandomInfo.pClientRandom,
                               params->RandomInfo.ulClientRandomLen,
                               &(key_block[16 * 26 + 3 * 16]));
            if (rc != CKR_OK) {
                TRACE_DEVEL("ssl3_md5_only failed.\n");
                goto error;
            }
            server_IV = &(key_block[16 * 26 + 3 * 16]);
        }
    }


    rc = ssl3_kmd_process_mac_keys(tokdata, sess, pTemplate, ulCount,
                                   &client_MAC_handle, client_MAC_key_value,
                                   &server_MAC_handle, server_MAC_key_value,
                                   MAC_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ssl3_kmd_process_mac_keys failed.\n");
        goto error;
    }

    rc = ssl3_kmd_process_write_keys(tokdata, sess, pTemplate, ulCount, keytype,
                                     &client_write_handle,
                                     client_write_key_value,
                                     &server_write_handle,
                                     server_write_key_value, write_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("ssl3_kmd_process_write_keys failed.\n");
        goto error;
    }

    params->pReturnedKeyMaterial->hClientMacSecret = client_MAC_handle;
    params->pReturnedKeyMaterial->hServerMacSecret = server_MAC_handle;
    params->pReturnedKeyMaterial->hClientKey = client_write_handle;
    params->pReturnedKeyMaterial->hServerKey = server_write_handle;

    if (params->ulIVSizeInBits != 0) {
        if (params->pReturnedKeyMaterial->pIVClient)
            memcpy(params->pReturnedKeyMaterial->pIVClient, client_IV, iv_len);

        if (params->pReturnedKeyMaterial->pIVServer)
            memcpy(params->pReturnedKeyMaterial->pIVServer, server_IV, iv_len);

#if 0
        CK_BYTE *p1, *p2;

        p1 = (CK_BYTE *) malloc(iv_len);
        p2 = (CK_BYTE *) malloc(iv_len);

        if (!p1 || !p2) {
            rc = CKR_HOST_MEMORY;
            goto error;
        }

        memcpy(p1, client_IV, iv_len);
        memcpy(p2, server_IV, iv_len);

        params->pReturnedKeyMaterial->pIVClient = p1;
        params->pReturnedKeyMaterial->pIVServer = p2;
#endif
    }

    INC_COUNTER(tokdata, sess, mech, base_key_obj, POLICY_STRENGTH_IDX_0);

error:
    return rc;
}


CK_RV ssl3_kmd_process_mac_keys(STDLL_TokData_t *tokdata,
                                SESSION *sess,
                                CK_ATTRIBUTE *pTemplate,
                                CK_ULONG ulCount,
                                CK_OBJECT_HANDLE *client_handle,
                                CK_BYTE *client_value,
                                CK_OBJECT_HANDLE *server_handle,
                                CK_BYTE *server_value, CK_ULONG mac_len)
{
    OBJECT *client_obj = NULL;
    OBJECT *server_obj = NULL;
    CK_ATTRIBUTE *client_val_attr = NULL;
    CK_ATTRIBUTE *client_val_len_attr = NULL;
    CK_ATTRIBUTE *server_val_attr = NULL;
    CK_ATTRIBUTE *server_val_len_attr = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE *new_attrs = NULL;
    CK_ULONG i, cnt;
    CK_ULONG true_vals[] = { CKA_SIGN, CKA_VERIFY, CKA_DERIVE };
    CK_ULONG false_vals[] = { CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP };
    CK_RV rc = 0;


    // for the MAC keys, we want the following default values:
    //    CKA_SIGN, CKA_VERIFY, CKA_DERIVE = TRUE
    //    CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP = FALSE
    //
    // attributes are added in sequential order so we stick the defaults
    // at the beginning so that they may be overridden by caller-specified
    // values.
    //
    new_attrs = (CK_ATTRIBUTE *) calloc(ulCount + 7, sizeof(CK_ATTRIBUTE));
    if (!new_attrs)
        goto error;

    // we have to treat these attributes a bit differently. normally, we
    // allocate the CK_ATTRIBUTE and the value with a single malloc and just
    // point the pValue member to the extra space.  we can't do that here
    // because we have to "emulate" the way attributes are passed in from the
    // cryptoki application...as an array of CK_ATTRIBUTEs with no extra space
    // (that is, pValue must be allocated separately).
    //
    attr = new_attrs;
    for (i = 0; i < sizeof(true_vals) / sizeof(CK_ULONG); i++, attr++) {
        attr->type = true_vals[i];
        attr->ulValueLen = sizeof(CK_BBOOL);
        attr->pValue = (CK_BBOOL *) malloc(sizeof(CK_BBOOL));
        if (!attr->pValue) {
            rc = CKR_HOST_MEMORY;
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            goto error;
        }
        *(CK_BBOOL *) attr->pValue = TRUE;
    }

    for (i = 0; i < sizeof(false_vals) / sizeof(CK_ULONG); i++, attr++) {
        attr->type = false_vals[i];
        attr->ulValueLen = sizeof(CK_BBOOL);
        attr->pValue = (CK_BBOOL *) malloc(sizeof(CK_BBOOL));
        if (!attr->pValue) {
            rc = CKR_HOST_MEMORY;
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            goto error;
        }
        *(CK_BBOOL *) attr->pValue = FALSE;
    }

    for (i = 0, cnt = 0; i < ulCount; i++) {
        if (pTemplate[i].type != CKA_KEY_TYPE &&
            pTemplate[i].type != CKA_VALUE &&
            pTemplate[i].type != CKA_VALUE_LEN) {
            attr->type = pTemplate[i].type;
            attr->ulValueLen = pTemplate[i].ulValueLen;
            if (attr->ulValueLen > 0) {
                if (pTemplate[i].pValue == NULL) {
                    rc = CKR_ATTRIBUTE_VALUE_INVALID;
                    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                    goto error;
                }
                attr->pValue = (char *) malloc(attr->ulValueLen);
                if (!attr->pValue) {
                    rc = CKR_HOST_MEMORY;
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    goto error;
                }
                memcpy(attr->pValue, pTemplate[i].pValue, attr->ulValueLen);
            } else {
                attr->pValue = NULL;
            }
            cnt++;
            attr++;
        }
    }

    ulCount = 7 + cnt;

    // create the key skeletons
    //
    rc = object_mgr_create_skel(tokdata, sess,
                                new_attrs, ulCount,
                                MODE_DERIVE,
                                CKO_SECRET_KEY,
                                CKK_GENERIC_SECRET, &client_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr Create Skeleton failed.\n");
        goto error;
    }
    rc = object_mgr_create_skel(tokdata, sess,
                                new_attrs, ulCount,
                                MODE_DERIVE,
                                CKO_SECRET_KEY,
                                CKK_GENERIC_SECRET, &server_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr Create Skeleton failed.\n");
        goto error;
    }
    for (i = 0; i < ulCount; i++)
        if (new_attrs[i].pValue)
            free(new_attrs[i].pValue);

    free(new_attrs);
    new_attrs = NULL;

    rc = build_attribute(CKA_VALUE, client_value, mac_len, &client_val_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to build CKA_VALUE attribute.\n");
        goto error;
    }
    rc = build_attribute(CKA_VALUE, server_value, mac_len, &server_val_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to build CKA_VALUE attribute.\n");
        goto error;
    }
    rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *) & mac_len, sizeof(CK_ULONG),
                         &client_val_len_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to build CKA_VALUE_LEN attribute.\n");
        goto error;
    }
    rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *) & mac_len, sizeof(CK_ULONG),
                         &server_val_len_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to build CKA_VALUE_LEN attribute.\n");
        goto error;
    }
    rc = template_update_attribute(client_obj->template, client_val_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    client_val_attr = NULL;
    rc = template_update_attribute(client_obj->template, client_val_len_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    client_val_len_attr = NULL;

    rc = template_update_attribute(server_obj->template, server_val_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    server_val_attr = NULL;
    rc = template_update_attribute(server_obj->template, server_val_len_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto error;
    }
    server_val_len_attr = NULL;

    rc = object_mgr_create_final(tokdata, sess, client_obj, client_handle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr Create Final failed.\n");
        goto error;
    }
    rc = object_mgr_create_final(tokdata, sess, server_obj, server_handle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr Create Final failed.\n");
        object_mgr_destroy_object(tokdata, sess, *client_handle);
        client_obj = NULL;
        goto error;
    }

    return CKR_OK;

error:
    *client_handle = 0;
    *server_handle = 0;

    if (client_obj)
        object_free(client_obj);

    if (server_obj)
        object_free(server_obj);

    if (client_val_attr)
        free(client_val_attr);
    if (client_val_len_attr)
        free(client_val_len_attr);
    if (server_val_attr)
        free(server_val_attr);
    if (server_val_len_attr)
        free(server_val_len_attr);

    if (new_attrs) {
        for (i = 0; i < ulCount; i++) {
            if (new_attrs[i].pValue)
                free(new_attrs[i].pValue);
        }

        free(new_attrs);
    }

    return rc;
}


CK_RV ssl3_kmd_process_write_keys(STDLL_TokData_t *tokdata,
                                  SESSION *sess,
                                  CK_ATTRIBUTE *pTemplate,
                                  CK_ULONG ulCount,
                                  CK_KEY_TYPE keytype,
                                  CK_OBJECT_HANDLE *client_handle,
                                  CK_BYTE *client_value,
                                  CK_OBJECT_HANDLE *server_handle,
                                  CK_BYTE *server_value, CK_ULONG write_len)
{
    CK_ATTRIBUTE *client_val_attr = NULL;
    CK_ATTRIBUTE *client_val_len_attr = NULL;
    CK_ATTRIBUTE *server_val_attr = NULL;
    CK_ATTRIBUTE *server_val_len_attr = NULL;
    CK_ATTRIBUTE *new_attrs = NULL;
    CK_ATTRIBUTE *attr = NULL;
    OBJECT *client_obj = NULL;
    OBJECT *server_obj = NULL;
    CK_ULONG i, cnt;
    CK_ULONG true_vals[] = { CKA_ENCRYPT, CKA_DECRYPT, CKA_DERIVE };
    CK_ULONG false_vals[] = { CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP };
    CK_RV rc = CKR_HOST_MEMORY;

    // for the write keys, we want the following default values:
    //    CKA_ENCRYPT, CKA_DECRYPT, CKA_DERIVE = TRUE
    //    CKA_SIGN, CKA_VERIFY, CKA_WRAP, CKA_UNWRAP = FALSE
    //
    // attributes are added in sequential order so we stick the defaults
    // at the beginning so that they may be overridden by caller-specified
    // values.
    //
    new_attrs = (CK_ATTRIBUTE *) calloc(ulCount + 7, sizeof(CK_ATTRIBUTE));
    if (!new_attrs)
        goto error;

    // we have to treat these attributes a bit differently. normally, we
    // allocate the CK_ATTRIBUTE and the value with a single malloc and just
    // point the pValue member to the extra space. we can't do that here because
    // we have to "emulate" the way attributes are passed in from the cryptoki
    // application...as an array of CK_ATTRIBUTEs with no extra space (that is,
    // pValue must be allocated separately).
    //
    attr = new_attrs;
    for (i = 0; i < sizeof(true_vals) / sizeof(CK_ULONG); i++, attr++) {
        attr->type = true_vals[i];
        attr->ulValueLen = sizeof(CK_BBOOL);
        attr->pValue = (CK_BBOOL *) malloc(sizeof(CK_BBOOL));
        if (!attr->pValue) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            goto error;
        }
        *(CK_BBOOL *) attr->pValue = TRUE;
    }

    for (i = 0; i < sizeof(false_vals) / sizeof(CK_ULONG); i++, attr++) {
        attr->type = false_vals[i];
        attr->ulValueLen = sizeof(CK_BBOOL);
        attr->pValue = (CK_BBOOL *) malloc(sizeof(CK_BBOOL));
        if (!attr->pValue) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            goto error;
        }
        *(CK_BBOOL *) attr->pValue = FALSE;
    }

    for (i = 0, cnt = 0; i < ulCount; i++) {
        if (pTemplate[i].type != CKA_KEY_TYPE &&
            pTemplate[i].type != CKA_VALUE &&
            pTemplate[i].type != CKA_VALUE_LEN) {
            attr->type = pTemplate[i].type;
            attr->ulValueLen = pTemplate[i].ulValueLen;
            if (attr->ulValueLen > 0) {
                if (pTemplate[i].pValue == NULL) {
                    rc = CKR_ATTRIBUTE_VALUE_INVALID;
                    TRACE_ERROR("%s\n", ock_err(ERR_ATTRIBUTE_VALUE_INVALID));
                    goto error;
                }
                attr->pValue = (char *) malloc(attr->ulValueLen);
                if (!attr->pValue) {
                    TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                    goto error;
                }
                memcpy(attr->pValue, pTemplate[i].pValue, attr->ulValueLen);
            } else {
                attr->pValue = NULL;
            }
            cnt++;
            attr++;
        }
    }

    ulCount = 7 + cnt;

    rc = object_mgr_create_skel(tokdata, sess,
                                new_attrs, ulCount,
                                MODE_DERIVE,
                                CKO_SECRET_KEY, keytype, &client_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr Create Skeleton failed.\n");
        goto error;
    }
    rc = object_mgr_create_skel(tokdata, sess,
                                new_attrs, ulCount,
                                MODE_DERIVE,
                                CKO_SECRET_KEY, keytype, &server_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr Create Skeleton failed.\n");
        goto error;
    }
    for (i = 0; i < ulCount; i++) {
        if (new_attrs[i].pValue)
            free(new_attrs[i].pValue);
    }

    free(new_attrs);
    new_attrs = NULL;

    rc = build_attribute(CKA_VALUE, client_value, write_len, &client_val_attr);
    rc |= build_attribute(CKA_VALUE, server_value, write_len, &server_val_attr);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Failed to build CKA_VALUE attribute.\n");
        goto error;
    }
    switch (keytype) {
    case CKK_AES:
    case CKK_AES_XTS:
    case CKK_GENERIC_SECRET:
    case CKK_DES:
    case CKK_DES2:
    case CKK_DES3:
        rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *) & write_len,
                             sizeof(CK_ULONG), &client_val_len_attr);
        rc |=
            build_attribute(CKA_VALUE_LEN, (CK_BYTE *) & write_len,
                            sizeof(CK_ULONG), &server_val_len_attr);
        if (rc != CKR_OK) {
            TRACE_DEVEL("Failed to build CKA_VALUE_LEN attribute.\n");
            goto error;
        }
        rc = template_validate_attribute(tokdata, client_obj->template,
                                         client_val_len_attr,
                                         CKO_SECRET_KEY, keytype, MODE_DERIVE);
        rc |= template_validate_attribute(tokdata, server_obj->template,
                                          server_val_len_attr,
                                          CKO_SECRET_KEY, keytype, MODE_DERIVE);

        // for these I use MODE_CREATE because I want to validate the
        // value/length. no othe modes are allowed to mess wiht CKA_VALUE (see
        // for instance, des_validate_attribute())
        //
        rc |= template_validate_attribute(tokdata, client_obj->template,
                                          client_val_attr,
                                          CKO_SECRET_KEY, keytype, MODE_CREATE);
        rc |= template_validate_attribute(tokdata, server_obj->template,
                                          server_val_attr,
                                          CKO_SECRET_KEY, keytype, MODE_CREATE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_validate_attribute failed.\n");
            goto error;
        }
        rc = template_update_attribute(client_obj->template, client_val_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        client_val_attr = NULL;
        rc = template_update_attribute(server_obj->template, server_val_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        server_val_attr = NULL;
        rc = template_update_attribute(client_obj->template,
                                       client_val_len_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        client_val_len_attr = NULL;
        rc = template_update_attribute(server_obj->template,
                                       server_val_len_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        server_val_len_attr = NULL;
        break;
    default:
        rc = template_validate_attribute(tokdata, client_obj->template,
                                         client_val_attr,
                                         CKO_SECRET_KEY, keytype, MODE_CREATE);
        rc |= template_validate_attribute(tokdata, server_obj->template,
                                          server_val_attr,
                                          CKO_SECRET_KEY, keytype, MODE_CREATE);
        if (rc != CKR_OK) {
            TRACE_DEVEL("template_validate_attribute failed.\n");
            goto error;
        }
        rc = template_update_attribute(client_obj->template, client_val_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        client_val_attr = NULL;
        rc = template_update_attribute(server_obj->template, server_val_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            goto error;
        }
        server_val_attr = NULL;
    }


    // finally, assign a handle to each key
    //
    rc = object_mgr_create_final(tokdata, sess, client_obj, client_handle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr Create Final failed.\n");
        goto error;
    }
    rc = object_mgr_create_final(tokdata, sess, server_obj, server_handle);
    if (rc != CKR_OK) {
        TRACE_DEVEL("Object Mgr Create Final failed.\n");
        object_mgr_destroy_object(tokdata, sess, *client_handle);
        client_obj = NULL;
        goto error;
    }

    return CKR_OK;

error:
    *client_handle = 0;
    *server_handle = 0;

    if (client_obj)
        object_free(client_obj);

    if (server_obj)
        object_free(server_obj);

    // the only way these guys are non-NULL is if they were created but
    // not yet to added to an object
    //
    if (client_val_attr)
        free(client_val_attr);
    if (client_val_len_attr)
        free(client_val_len_attr);
    if (server_val_attr)
        free(server_val_attr);
    if (server_val_len_attr)
        free(server_val_len_attr);

    if (new_attrs) {
        for (i = 0; i < ulCount; i++) {
            if (new_attrs[i].pValue)
                free(new_attrs[i].pValue);
        }

        free(new_attrs);
    }

    return rc;
}
