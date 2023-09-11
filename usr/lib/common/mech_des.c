/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  mech_des.c
//
// Mechanisms for DES
//

#include <string.h>             // for memcmp() et al
#include <stdlib.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"

#include <openssl/crypto.h>

//
//
CK_RV pk_des_ecb_encrypt(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_BBOOL length_only,
                         ENCR_DECR_CONTEXT *ctx,
                         CK_BYTE *in_data,
                         CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key = NULL;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    // CKM_DES_ECB requires the input data to be an integral
    // multiple of the block size
    //
    if (in_data_len % DES_BLOCK_SIZE != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    if (length_only == TRUE) {
        *out_data_len = in_data_len;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < in_data_len) {
        *out_data_len = in_data_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    rc = ckm_des_ecb_encrypt(tokdata, in_data, in_data_len,
                             out_data, out_data_len, key);

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}


//
//
CK_RV des_ecb_decrypt(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      CK_BBOOL length_only,
                      ENCR_DECR_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key = NULL;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    // CKM_DES_ECB requires the input data to be an integral
    // multiple of the block size
    //
    if (in_data_len % DES_BLOCK_SIZE != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    if (length_only == TRUE) {
        *out_data_len = in_data_len;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < in_data_len) {
        *out_data_len = in_data_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    rc = ckm_des_ecb_decrypt(tokdata, in_data, in_data_len,
                             out_data, out_data_len, key);

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}


//
//
CK_RV pk_des_cbc_encrypt(STDLL_TokData_t *tokdata,
                         SESSION *sess,
                         CK_BBOOL length_only,
                         ENCR_DECR_CONTEXT *ctx,
                         CK_BYTE *in_data,
                         CK_ULONG in_data_len,
                         CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key = NULL;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    // CKM_DES_CBC requires the input data to be an integral
    // multiple of the block size
    //
    if (in_data_len % DES_BLOCK_SIZE != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    if (length_only == TRUE) {
        *out_data_len = in_data_len;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < in_data_len) {
        *out_data_len = in_data_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    rc = ckm_des_cbc_encrypt(tokdata, in_data, in_data_len, out_data,
                             out_data_len, ctx->mech.pParameter, key);

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}


//
//
CK_RV des_cbc_decrypt(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      CK_BBOOL length_only,
                      ENCR_DECR_CONTEXT *ctx,
                      CK_BYTE *in_data,
                      CK_ULONG in_data_len,
                      CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key = NULL;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    // CKM_DES_CBC requires the input data to be an integral
    // multiple of the block size
    //
    if (in_data_len % DES_BLOCK_SIZE != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    if (length_only == TRUE) {
        *out_data_len = in_data_len;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < in_data_len) {
        *out_data_len = in_data_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    rc = ckm_des_cbc_decrypt(tokdata, in_data, in_data_len, out_data,
                             out_data_len, ctx->mech.pParameter, key);

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}


//
//
CK_RV des_cbc_pad_encrypt(STDLL_TokData_t *tokdata,
                          SESSION *sess,
                          CK_BBOOL length_only,
                          ENCR_DECR_CONTEXT *ctx,
                          CK_BYTE *in_data,
                          CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key = NULL;
    CK_BYTE *clear = NULL;
    CK_ULONG padded_len;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    // DES-CBC-PAD has no input length requirements
    //

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }
    // compute the output length, accounting for padding
    //
    padded_len = DES_BLOCK_SIZE * (in_data_len / DES_BLOCK_SIZE + 1);

    if (length_only == TRUE) {
        *out_data_len = padded_len;
        rc = CKR_OK;
        goto done;
    }

    if (*out_data_len < padded_len) {
        *out_data_len = padded_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        rc = CKR_BUFFER_TOO_SMALL;
        goto done;
    }

    clear = (CK_BYTE *) malloc(padded_len);
    if (!clear) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    if (in_data != NULL && in_data_len > 0)
        memcpy(clear, in_data, in_data_len);

    add_pkcs_padding(clear + in_data_len,
                     DES_BLOCK_SIZE, in_data_len, padded_len);

    rc = ckm_des_cbc_encrypt(tokdata, clear, padded_len, out_data, out_data_len,
                             ctx->mech.pParameter, key);
    free(clear);

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}


//
//
CK_RV des_cbc_pad_decrypt(STDLL_TokData_t *tokdata,
                          SESSION *sess,
                          CK_BBOOL length_only,
                          ENCR_DECR_CONTEXT *ctx,
                          CK_BYTE *in_data,
                          CK_ULONG in_data_len,
                          CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    OBJECT *key = NULL;
    CK_BYTE *clear = NULL;
    CK_ULONG padded_len;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    //
    // no need to validate the input length since we'll pad as necessary
    //

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }
    // we're decrypting so even with CBC-PAD, we should have an integral
    // number of block to decrypt
    //
    if (in_data_len % DES_BLOCK_SIZE != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
        goto done;
    }
    // the amount of cleartext after stripping the padding will actually be less
    // than the input bytes...
    //
    padded_len = in_data_len;

    if (length_only == TRUE) {
        *out_data_len = padded_len;
        rc = CKR_OK;
        goto done;
    }

    clear = (CK_BYTE *) malloc(padded_len);
    if (!clear) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    rc = ckm_des_cbc_decrypt(tokdata, in_data, in_data_len, clear, &padded_len,
                             ctx->mech.pParameter, key);

    if (rc == CKR_OK) {
        strip_pkcs_padding(clear, padded_len, out_data_len);
        memcpy(out_data, clear, *out_data_len);
    }

    free(clear);

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}


//
//
CK_RV des_ecb_encrypt_update(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;
    OBJECT *key = NULL;
    CK_BYTE *clear = NULL;
    CK_ULONG total, remain, out_len;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (DES_CONTEXT *) ctx->context;

    total = (context->len + in_data_len);

    if (total < DES_BLOCK_SIZE) {
        if (length_only == FALSE && in_data_len) {
            memcpy(context->data + context->len, in_data, in_data_len);
            context->len += in_data_len;
        }
        *out_data_len = 0;
        return CKR_OK;
    } else {
        // we have at least 1 block
        //
        remain = (total % DES_BLOCK_SIZE);
        out_len = (total - remain);     // should always be at least 1 block

        if (length_only == TRUE) {
            *out_data_len = out_len;
            return CKR_OK;
        }

        rc = object_mgr_find_in_map_nocache(tokdata, ctx->key, &key, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to find specified object.\n");
            return rc;
        }

        clear = (CK_BYTE *) malloc(out_len);
        if (!clear) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            object_put(tokdata, key, TRUE);
            key = NULL;
            return CKR_HOST_MEMORY;
        }
        // copy any data left over from the previous encryption operation first
        //
        memcpy(clear, context->data, context->len);
        memcpy(clear + context->len, in_data, out_len - context->len);

        rc = ckm_des_ecb_encrypt(tokdata, clear, out_len, out_data,
                                 out_data_len, key);
        if (rc == CKR_OK) {
            *out_data_len = out_len;

            // update the context buffer.  we already used the buffer's current
            // contents so we completely overwrite it
            //
            if (remain != 0)
                memcpy(context->data, in_data + (in_data_len - remain), remain);
            context->len = remain;
        }

        free(clear);

        object_put(tokdata, key, TRUE);
        key = NULL;

        return rc;
    }
}


//
//
CK_RV des_ecb_decrypt_update(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;
    OBJECT *key = NULL;
    CK_BYTE *cipher = NULL;
    CK_ULONG total, remain, out_len;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (DES_CONTEXT *) ctx->context;

    total = (context->len + in_data_len);

    if (total < DES_BLOCK_SIZE) {
        if (length_only == FALSE && in_data_len) {
            memcpy(context->data + context->len, in_data, in_data_len);
            context->len += in_data_len;
        }

        *out_data_len = 0;
        return CKR_OK;
    } else {
        // we have at least 1 block
        //
        remain = (total % DES_BLOCK_SIZE);
        out_len = total - remain;

        if (length_only == TRUE) {
            *out_data_len = out_len;
            return CKR_OK;
        }

        rc = object_mgr_find_in_map_nocache(tokdata, ctx->key, &key, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to find specified object.\n");
            return rc;
        }

        cipher = (CK_BYTE *) malloc(out_len);
        if (!cipher) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            object_put(tokdata, key, TRUE);
            key = NULL;
            return CKR_HOST_MEMORY;
        }
        // copy any data left over from the previous decryption operation first
        //
        memcpy(cipher, context->data, context->len);
        memcpy(cipher + context->len, in_data, out_len - context->len);

        rc = ckm_des_ecb_decrypt(tokdata, cipher, out_len, out_data,
                                 out_data_len, key);
        if (rc == CKR_OK) {
            *out_data_len = out_len;

            // copy the remaining 'new' input data to the context buffer
            //
            if (remain != 0)
                memcpy(context->data, in_data + (in_data_len - remain), remain);
            context->len = remain;
        }

        free(cipher);

        object_put(tokdata, key, TRUE);
        key = NULL;

        return rc;
    }
}


//
//
CK_RV des_cbc_encrypt_update(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;
    OBJECT *key = NULL;
    CK_BYTE *clear = NULL;
    CK_ULONG total, remain, out_len;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (DES_CONTEXT *) ctx->context;

    total = (context->len + in_data_len);

    if (total < DES_BLOCK_SIZE) {
        if (length_only == FALSE && in_data_len) {
            memcpy(context->data + context->len, in_data, in_data_len);
            context->len += in_data_len;
        }

        *out_data_len = 0;
        return CKR_OK;
    } else {
        // we have at least 1 block
        //
        remain = (total % DES_BLOCK_SIZE);
        out_len = total - remain;

        if (length_only == TRUE) {
            *out_data_len = out_len;
            return CKR_OK;
        }

        rc = object_mgr_find_in_map_nocache(tokdata, ctx->key, &key, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to find specified object.\n");
            return rc;
        }
        // these buffers need to be longword aligned
        //
        clear = (CK_BYTE *) malloc(out_len);
        if (!clear) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            object_put(tokdata, key, TRUE);
            key = NULL;
            return CKR_HOST_MEMORY;
        }
        // copy any data left over from the previous encryption operation first
        //
        memcpy(clear, context->data, context->len);
        memcpy(clear + context->len, in_data, out_len - context->len);

        rc = ckm_des_cbc_encrypt(tokdata, clear, out_len, out_data,
                                 out_data_len, ctx->mech.pParameter, key);
        if (rc == CKR_OK) {
            *out_data_len = out_len;

            // the new init_v is the last encrypted data block
            //
            memcpy(ctx->mech.pParameter,
                   out_data + (*out_data_len - DES_BLOCK_SIZE), DES_BLOCK_SIZE);

            // copy the remaining 'new' input data to the context buffer
            //
            if (remain != 0)
                memcpy(context->data, in_data + (in_data_len - remain), remain);
            context->len = remain;
        }

        free(clear);

        object_put(tokdata, key, TRUE);
        key = NULL;

        return rc;
    }
}


//
//
CK_RV des_cbc_decrypt_update(STDLL_TokData_t *tokdata,
                             SESSION *sess,
                             CK_BBOOL length_only,
                             ENCR_DECR_CONTEXT *ctx,
                             CK_BYTE *in_data,
                             CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;
    OBJECT *key = NULL;
    CK_BYTE *cipher = NULL;
    CK_ULONG total, remain, out_len;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (DES_CONTEXT *) ctx->context;

    total = context->len + in_data_len;

    if (total < DES_BLOCK_SIZE) {
        if (length_only == FALSE && in_data_len) {
            memcpy(context->data + context->len, in_data, in_data_len);
            context->len += in_data_len;
        }

        *out_data_len = 0;
        return CKR_OK;
    } else {
        // we have at least 1 block
        //
        remain = total % DES_BLOCK_SIZE;
        out_len = total - remain;

        if (length_only == TRUE) {
            *out_data_len = out_len;
            return CKR_OK;
        }

        rc = object_mgr_find_in_map_nocache(tokdata, ctx->key, &key, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to find specified object.\n");
            return rc;
        }
        // these buffers need to be longword aligned
        //
        cipher = (CK_BYTE *) malloc(out_len);
        if (!cipher) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            object_put(tokdata, key, TRUE);
            key = NULL;
            return CKR_HOST_MEMORY;
        }
        // copy any data left over from the previous decryption operation first
        //
        memcpy(cipher, context->data, context->len);
        memcpy(cipher + context->len, in_data, out_len - context->len);

        rc = ckm_des_cbc_decrypt(tokdata, cipher, out_len, out_data,
                                 out_data_len, ctx->mech.pParameter, key);
        if (rc == CKR_OK) {
            *out_data_len = out_len;

            // the new init_v is the last decrypted data block
            //
            memcpy(ctx->mech.pParameter, cipher + (out_len - DES_BLOCK_SIZE),
                   DES_BLOCK_SIZE);

            // copy the remaining 'new' input data to the context buffer
            //
            if (remain != 0)
                memcpy(context->data, in_data + (in_data_len - remain), remain);
            context->len = remain;
        }

        free(cipher);

        object_put(tokdata, key, TRUE);
        key = NULL;

        return rc;
    }
}


//
//
CK_RV des_cbc_pad_encrypt_update(STDLL_TokData_t *tokdata,
                                 SESSION *sess,
                                 CK_BBOOL length_only,
                                 ENCR_DECR_CONTEXT *ctx,
                                 CK_BYTE *in_data,
                                 CK_ULONG in_data_len,
                                 CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;
    OBJECT *key = NULL;
    CK_BYTE *clear = NULL;
    CK_ULONG total, remain, out_len;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (DES_CONTEXT *) ctx->context;

    total = (context->len + in_data_len);

    // note, this is subtly different from the other encrypt update routines
    //
    if (total <= DES_BLOCK_SIZE) {
        if (length_only == FALSE && in_data_len) {
            memcpy(context->data + context->len, in_data, in_data_len);
            context->len += in_data_len;
        }

        *out_data_len = 0;
        return CKR_OK;
    } else {
        // we have at least 1 block + 1 byte
        //
        remain = total % DES_BLOCK_SIZE;
        out_len = total - remain;

        if (remain == 0) {
            remain = DES_BLOCK_SIZE;
            out_len -= DES_BLOCK_SIZE;
        }

        if (length_only == TRUE) {
            *out_data_len = out_len;
            return CKR_OK;
        }
        // at this point, we should have:
        //    1) remain != 0
        //    2) out_len != 0
        //
        rc = object_mgr_find_in_map_nocache(tokdata, ctx->key, &key, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to find specified object.\n");
            return rc;
        }
        // these buffers need to be longword aligned
        //
        clear = (CK_BYTE *) malloc(out_len);
        if (!clear) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            object_put(tokdata, key, TRUE);
            key = NULL;
            return CKR_HOST_MEMORY;
        }
        // copy any data left over from the previous encryption operation first
        //
        memcpy(clear, context->data, context->len);
        memcpy(clear + context->len, in_data, out_len - context->len);

        //
        // we don't do padding during the update
        //
        rc = ckm_des_cbc_encrypt(tokdata, clear, out_len, out_data,
                                 out_data_len, ctx->mech.pParameter, key);

        if (rc == CKR_OK) {
            // the new init_v is the last encrypted data block
            //
            memcpy(ctx->mech.pParameter,
                   out_data + (*out_data_len - DES_BLOCK_SIZE), DES_BLOCK_SIZE);

            // copy the remaining 'new' input data to the temporary space
            //
            memcpy(context->data, in_data + (in_data_len - remain), remain);
            context->len = remain;
        }

        free(clear);

        object_put(tokdata, key, TRUE);
        key = NULL;

        return rc;
    }
}


//
//
CK_RV des_cbc_pad_decrypt_update(STDLL_TokData_t *tokdata,
                                 SESSION *sess,
                                 CK_BBOOL length_only,
                                 ENCR_DECR_CONTEXT *ctx,
                                 CK_BYTE *in_data,
                                 CK_ULONG in_data_len,
                                 CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;
    OBJECT *key = NULL;
    CK_BYTE *cipher = NULL;
    CK_ULONG total, remain, out_len;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    context = (DES_CONTEXT *) ctx->context;

    total = (context->len + in_data_len);

    // note, this is subtly different from the other decrypt update routines
    //
    if (total <= DES_BLOCK_SIZE) {
        if (length_only == FALSE && in_data_len) {
            memcpy(context->data + context->len, in_data, in_data_len);
            context->len += in_data_len;
        }

        *out_data_len = 0;
        return CKR_OK;
    } else {
        // we have at least 1 block + 1 byte
        //
        remain = total % DES_BLOCK_SIZE;
        out_len = total - remain;

        if (remain == 0) {
            remain = DES_BLOCK_SIZE;
            out_len -= DES_BLOCK_SIZE;
        }

        if (length_only == TRUE) {
            *out_data_len = out_len;
            return CKR_OK;
        }
        // at this point, we should have:
        //    1) remain != 0
        //    2) out_len != 0
        //
        rc = object_mgr_find_in_map_nocache(tokdata, ctx->key, &key, READ_LOCK);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to find specified object.\n");
            return rc;
        }
        // these buffers need to be longword aligned
        //
        cipher = (CK_BYTE *) malloc(out_len);
        if (!cipher) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            object_put(tokdata, key, TRUE);
            key = NULL;
            return CKR_HOST_MEMORY;
        }
        // copy any data left over from the previous decryption operation first
        //
        memcpy(cipher, context->data, context->len);
        memcpy(cipher + context->len, in_data, out_len - context->len);

        rc = ckm_des_cbc_decrypt(tokdata, cipher, out_len, out_data,
                                 out_data_len, ctx->mech.pParameter, key);

        if (rc == CKR_OK) {
            // the new init_v is the last decrypted data block
            //
            memcpy(ctx->mech.pParameter, cipher + (out_len - DES_BLOCK_SIZE),
                   DES_BLOCK_SIZE);

            // copy the remaining 'new' input data to the temporary space
            //
            memcpy(context->data, in_data + (in_data_len - remain), remain);
            context->len = remain;
        }
        free(cipher);

        object_put(tokdata, key, TRUE);
        key = NULL;

        return rc;
    }
}


//
//
CK_RV des_ecb_encrypt_final(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *ctx,
                            CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;

    UNUSED(tokdata);
    UNUSED(out_data);
    UNUSED(length_only);

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    context = (DES_CONTEXT *) ctx->context;

    // DES-ECB does no padding so there had better not be
    // any data in the context buffer.  if there is it means
    // that the overall data length was not a multiple of the blocksize
    //
    if (context->len != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }

    *out_data_len = 0;

    return CKR_OK;
}


//
//
CK_RV des_ecb_decrypt_final(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *ctx,
                            CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;

    UNUSED(tokdata);
    UNUSED(out_data);
    UNUSED(length_only);

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    context = (DES_CONTEXT *) ctx->context;

    // DES-ECB does no padding so there had better not be
    // any data in the context buffer.  if there is it means
    // that the overall data length was not a multiple of the blocksize
    //
    if (context->len != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

    *out_data_len = 0;

    return CKR_OK;
}


//
//
CK_RV des_cbc_encrypt_final(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *ctx,
                            CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;

    UNUSED(tokdata);
    UNUSED(out_data);
    UNUSED(length_only);

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    context = (DES_CONTEXT *) ctx->context;

    // DES-CBC does no padding so there had better not be
    // any data in the context buffer.  if there is it means
    // that the overall data length was not a multiple of the blocksize
    //
    if (context->len != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_DATA_LEN_RANGE));
        return CKR_DATA_LEN_RANGE;
    }

    *out_data_len = 0;

    return CKR_OK;
}


//
//
CK_RV des_cbc_decrypt_final(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            CK_BBOOL length_only,
                            ENCR_DECR_CONTEXT *ctx,
                            CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;

    UNUSED(tokdata);
    UNUSED(out_data);
    UNUSED(length_only);

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    context = (DES_CONTEXT *) ctx->context;

    // DES-CBC does no padding so there had better not be
    // any data in the context buffer.  if there is it means
    // that the overall data length was not a multiple of the blocksize
    //
    if (context->len != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        return CKR_ENCRYPTED_DATA_LEN_RANGE;
    }

    *out_data_len = 0;

    return CKR_OK;
}


//
//
CK_RV des_cbc_pad_encrypt_final(STDLL_TokData_t *tokdata,
                                SESSION *sess,
                                CK_BBOOL length_only,
                                ENCR_DECR_CONTEXT *ctx,
                                CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;
    OBJECT *key = NULL;
    CK_BYTE clear[2 * DES_BLOCK_SIZE];
    CK_ULONG out_len;
    CK_RV rc;


    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    context = (DES_CONTEXT *) ctx->context;

    // there will never be more than one block in the context buffer
    // so the amount of output is as follows:
    // if less than 1 block stored, we generate one block of output
    // if a full block is stored, we generate two blocks of output (one pad
    // block)
    //
    if (context->len == DES_BLOCK_SIZE)
        out_len = 2 * DES_BLOCK_SIZE;
    else
        out_len = DES_BLOCK_SIZE;

    if (length_only == TRUE) {
        *out_data_len = out_len;
        rc = CKR_OK;
    } else {
        memcpy(clear, context->data, context->len);

        add_pkcs_padding(clear + context->len,
                         DES_BLOCK_SIZE, context->len, out_len);

        rc = ckm_des_cbc_encrypt(tokdata, clear, out_len, out_data,
                                 out_data_len, ctx->mech.pParameter, key);
    }

    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}


//
//
CK_RV des_cbc_pad_decrypt_final(STDLL_TokData_t *tokdata,
                                SESSION *sess,
                                CK_BBOOL length_only,
                                ENCR_DECR_CONTEXT *ctx,
                                CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    DES_CONTEXT *context = NULL;
    OBJECT *key = NULL;
    CK_BYTE clear[DES_BLOCK_SIZE];
    CK_BYTE cipher[DES_BLOCK_SIZE];
    CK_ULONG out_len;
    CK_RV rc;

    if (!sess || !ctx || !out_data_len) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    rc = object_mgr_find_in_map1(tokdata, ctx->key, &key, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to find specified object.\n");
        return rc;
    }

    context = (DES_CONTEXT *) ctx->context;

    // there had better be a full block in the context buffer
    //
    if (context->len != DES_BLOCK_SIZE) {
        TRACE_ERROR("%s\n", ock_err(ERR_ENCRYPTED_DATA_LEN_RANGE));
        rc = CKR_ENCRYPTED_DATA_LEN_RANGE;
        goto done;
    }
    // we don't know a priori how much data we'll be returning. we won't
    // know until after we decrypt it and strip the padding. it's possible
    // that we'll return nothing (the final block might be a padding block).
    //
    out_len = DES_BLOCK_SIZE;   // upper bound on what we'll return

    if (length_only == TRUE) {
        *out_data_len = out_len;
        rc = CKR_OK;
    } else {
        memcpy(cipher, context->data, DES_BLOCK_SIZE);

        rc = ckm_des_cbc_decrypt(tokdata, cipher, DES_BLOCK_SIZE, clear,
                                 &out_len, ctx->mech.pParameter, key);
        if (rc == CKR_OK) {
            strip_pkcs_padding(clear, DES_BLOCK_SIZE, &out_len);

            if (out_len != 0)
                memcpy(out_data, clear, out_len);

            *out_data_len = out_len;
        }

    }

done:
    object_put(tokdata, key, TRUE);
    key = NULL;

    return rc;
}


//
// mechanisms
//


//
//
CK_RV ckm_des_key_gen(STDLL_TokData_t *tokdata, TEMPLATE *tmpl)
{

    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *opaque_attr = NULL;
    CK_ATTRIBUTE *key_type_attr = NULL;
    CK_ATTRIBUTE *class_attr = NULL;
    CK_ATTRIBUTE *local_attr = NULL;
    CK_BYTE *des_key = NULL;
    CK_ULONG rc;
    CK_ULONG keysize = 0;
    CK_BBOOL is_opaque = FALSE;

    if (token_specific.t_des_key_gen == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    rc = token_specific.t_des_key_gen(tokdata, tmpl, &des_key, &keysize,
                                      DES_KEY_SIZE, &is_opaque);
    if (rc != CKR_OK)
        goto err;

    /* For opaque keys put in CKA_IBM_OPAQUE and put dummy_key in CKA_VALUE. */
    if (is_opaque) {
        opaque_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + keysize);
        if (!opaque_attr) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto err;
        }
        opaque_attr->type = CKA_IBM_OPAQUE;
        opaque_attr->ulValueLen = keysize;
        opaque_attr->pValue = (CK_BYTE *) opaque_attr + sizeof(CK_ATTRIBUTE);
        memcpy(opaque_attr->pValue, des_key, keysize);
        rc = template_update_attribute(tmpl, opaque_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("template_update_attribute failed\n");
            free(opaque_attr);
            goto err;
        }
    } else {
        if (keysize != DES_KEY_SIZE) {
            TRACE_ERROR("Invalid key size: %lu\n", keysize);
            rc = CKR_FUNCTION_FAILED;
            goto err;
        }
    }

    value_attr = (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + DES_KEY_SIZE);
    key_type_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_KEY_TYPE));
    class_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_OBJECT_CLASS));
    local_attr =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) + sizeof(CK_BBOOL));

    if (!value_attr || !key_type_attr || !class_attr || !local_attr) {
        TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
        rc = CKR_HOST_MEMORY;
        goto err;
    }

    value_attr->type = CKA_VALUE;
    value_attr->ulValueLen = DES_KEY_SIZE;
    value_attr->pValue = (CK_BYTE *) value_attr + sizeof(CK_ATTRIBUTE);
    if (is_opaque)
        memset(value_attr->pValue, 0, DES_KEY_SIZE);
    else
        memcpy(value_attr->pValue, des_key, DES_KEY_SIZE);
    free(des_key);
    des_key = NULL;

    key_type_attr->type = CKA_KEY_TYPE;
    key_type_attr->ulValueLen = sizeof(CK_KEY_TYPE);
    key_type_attr->pValue = (CK_BYTE *) key_type_attr + sizeof(CK_ATTRIBUTE);
    *(CK_KEY_TYPE *) key_type_attr->pValue = CKK_DES;

    class_attr->type = CKA_CLASS;
    class_attr->ulValueLen = sizeof(CK_OBJECT_CLASS);
    class_attr->pValue = (CK_BYTE *) class_attr + sizeof(CK_ATTRIBUTE);
    *(CK_OBJECT_CLASS *) class_attr->pValue = CKO_SECRET_KEY;

    local_attr->type = CKA_LOCAL;
    local_attr->ulValueLen = sizeof(CK_BBOOL);
    local_attr->pValue = (CK_BYTE *) local_attr + sizeof(CK_ATTRIBUTE);
    *(CK_BBOOL *) local_attr->pValue = TRUE;

    rc = template_update_attribute(tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto err;
    }
    value_attr = NULL;
    rc = template_update_attribute(tmpl, key_type_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto err;
    }
    key_type_attr = NULL;
    rc = template_update_attribute(tmpl, class_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto err;
    }
    class_attr = NULL;
    rc = template_update_attribute(tmpl, local_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("template_update_attribute failed\n");
        goto err;
    }
    local_attr = NULL;

    return CKR_OK;

err:
    if (des_key)
        free(des_key);
    if (value_attr)
        free(value_attr);
    if (key_type_attr)
        free(key_type_attr);
    if (class_attr)
        free(class_attr);
    if (local_attr)
        free(local_attr);

    return rc;
}

//
//
CK_RV ckm_des_ecb_encrypt(STDLL_TokData_t *tokdata,
                          CK_BYTE *in_data,
                          CK_ULONG in_data_len,
                          CK_BYTE *out_data,
                          CK_ULONG *out_data_len, OBJECT *key)
{
    CK_ULONG rc;


    if (!in_data || !out_data || !key) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (*out_data_len < in_data_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    if (token_specific.t_des_ecb == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }
    rc = token_specific.t_des_ecb(tokdata, in_data, in_data_len,
                                  out_data, out_data_len, key, 1);

    if (rc != CKR_OK)
        TRACE_DEVEL("Token specific des_ecb encrypt failed.\n");

    return rc;
}


//
//
CK_RV ckm_des_ecb_decrypt(STDLL_TokData_t *tokdata,
                          CK_BYTE *in_data,
                          CK_ULONG in_data_len,
                          CK_BYTE *out_data,
                          CK_ULONG *out_data_len, OBJECT *key)
{
    CK_ULONG rc;



    if (!in_data || !out_data || !key) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (*out_data_len < in_data_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    if (token_specific.t_des_ecb == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }
    rc = token_specific.t_des_ecb(tokdata, in_data, in_data_len, out_data,
                                  out_data_len, key, 0);
    if (rc != CKR_OK)
        TRACE_ERROR("Token specific des ecb decrypt failed.\n");

    return rc;
}


//
//
CK_RV ckm_des_cbc_encrypt(STDLL_TokData_t *tokdata,
                          CK_BYTE *in_data,
                          CK_ULONG in_data_len,
                          CK_BYTE *out_data,
                          CK_ULONG *out_data_len,
                          CK_BYTE *init_v, OBJECT *key)
{
    CK_ULONG rc;


    if (!in_data || !out_data || !init_v || !key) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (*out_data_len < in_data_len) {
        *out_data_len = in_data_len;
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    if (token_specific.t_des_cbc == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }
    rc = token_specific.t_des_cbc(tokdata, in_data, in_data_len, out_data,
                                  out_data_len, key, init_v, 1);

    if (rc != CKR_OK)
        TRACE_ERROR("Token specific dec cbc encrypt failed.\n");

    return rc;
}


//
//
CK_RV ckm_des_cbc_decrypt(STDLL_TokData_t *tokdata,
                          CK_BYTE *in_data,
                          CK_ULONG in_data_len,
                          CK_BYTE *out_data,
                          CK_ULONG *out_data_len,
                          CK_BYTE *init_v, OBJECT *key)
{
    CK_ULONG rc;


    if (!in_data || !out_data || !init_v || !key) {
        TRACE_ERROR("%s received bad argument(s)\n", __func__);
        return CKR_FUNCTION_FAILED;
    }
    if (*out_data_len < in_data_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_BUFFER_TOO_SMALL));
        return CKR_BUFFER_TOO_SMALL;
    }

    if (token_specific.t_des_cbc == NULL) {
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }
    rc = token_specific.t_des_cbc(tokdata, in_data, in_data_len, out_data,
                                  out_data_len, key, init_v, 0);

    if (rc != CKR_OK)
        TRACE_ERROR("Token specific des cbc decrypt failed.\n");

    return rc;
}


// we're preparing to wrap a key using DES.  need to make sure the
// data length is a integral multiple of the DES block size.
//
// PKCS #11 specifies that the padding shall be in the form of NULL
// bytes appended to the data
//
// this routine works with either DES and 3DES as the wrapping mechanism
//
CK_RV ckm_des_wrap_format(STDLL_TokData_t *tokdata,
                          CK_BBOOL length_only,
                          CK_BYTE **data, CK_ULONG *data_len)
{
    CK_BYTE *ptr = NULL;
    CK_ULONG len1, len2;

    UNUSED(tokdata);

    len1 = *data_len;
    if (*data == NULL)
        len1 = 0;

    // if the input key data isn't a multiple of the blocksize,
    // we pad with NULLs to the next blocksize multiple.
    //
    if (len1 % DES_BLOCK_SIZE != 0) {
        len2 = DES_BLOCK_SIZE * ((len1 / DES_BLOCK_SIZE) + 1);

        if (length_only == FALSE) {
            /*
             * Don't use realloc here, since the buffer contains a key and the
             * old buffer needs to be cleansed before it is freed.
             */
            ptr = (CK_BYTE *)malloc(len2);
            if (!ptr) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                return CKR_HOST_MEMORY;
            }

            memset(ptr + len1, 0x0, (len2 - len1));
            if (*data != NULL) {
                memcpy(ptr, *data, len1);
                OPENSSL_cleanse(*data, len1);
                free(*data);
            }

            *data = ptr;
            *data_len = len2;
        }
    }

    return CKR_OK;
}
