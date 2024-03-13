/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  dig_mgr.c
//
// Digest manager routines
//

#include <pthread.h>
#include <string.h>             // for memcmp() et al
#include <stdlib.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "tok_spec_struct.h"
#include "trace.h"
#include "../api/statistics.h"

//
//
CK_RV digest_mgr_init(STDLL_TokData_t *tokdata,
                      SESSION *sess, DIGEST_CONTEXT *ctx, CK_MECHANISM *mech,
                      CK_BBOOL checkpolicy)
{
    CK_RV rc = CKR_OK;
    CK_BYTE *ptr = NULL;

    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->active != FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        return CKR_OPERATION_ACTIVE;
    }
    if (checkpolicy) {
        rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                              NULL, POLICY_CHECK_DIGEST, sess);
        if (rc != CKR_OK) {
            TRACE_ERROR("POLICY VIOLATION: digest init\n");
            return rc;
        }
    }


    // is the mechanism supported?  is the parameter present if required?
    //
    switch (mech->mechanism) {
    case CKM_SHA_1:
    case CKM_SHA224:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
    case CKM_SHA512_224:
    case CKM_SHA512_256:
    case CKM_IBM_SHA3_224:
    case CKM_IBM_SHA3_256:
    case CKM_IBM_SHA3_384:
    case CKM_IBM_SHA3_512:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            return CKR_MECHANISM_PARAM_INVALID;
        }

        ctx->context = NULL;
        rc = sha_init(tokdata, sess, ctx, mech);
        if (rc != CKR_OK) {
            digest_mgr_cleanup(tokdata, sess, ctx);    // to de-initialize context above
            TRACE_ERROR("Failed to init sha context.\n");
            return rc;
        }
        break;
#if !(NOMD2)
    case CKM_MD2:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            return CKR_MECHANISM_PARAM_INVALID;
        }
        ctx->context_len = sizeof(MD2_CONTEXT);
        ctx->context = (CK_BYTE *) malloc(sizeof(MD2_CONTEXT));
        if (!ctx->context) {
            digest_mgr_cleanup(tokdata, sess, ctx);    // to de-initialize context above
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }
        memset(ctx->context, 0x0, sizeof(MD2_CONTEXT));
        break;
#endif
    case CKM_MD5:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            return CKR_MECHANISM_PARAM_INVALID;
          }
          ctx->context = NULL;
          rc = md5_init(tokdata, sess, ctx, mech);
          if (rc != CKR_OK) {
              digest_mgr_cleanup(tokdata, sess, ctx);    // to de-initialize context above
              TRACE_ERROR("Failed to init md5 context.\n");
              return rc;
          }
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    if (mech->ulParameterLen > 0 && mech->pParameter != NULL) {
        ptr = (CK_BYTE *) malloc(mech->ulParameterLen);
        if (!ptr) {
            digest_mgr_cleanup(tokdata, sess, ctx);    // to de-initialize context above
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            return CKR_HOST_MEMORY;
        }
        memcpy(ptr, mech->pParameter, mech->ulParameterLen);
    }
    ctx->mech.ulParameterLen = mech->ulParameterLen;
    ctx->mech.mechanism = mech->mechanism;
    ctx->mech.pParameter = ptr;
    ctx->multi_init = FALSE;
    ctx->multi = FALSE;
    ctx->active = TRUE;

    if (ctx->count_statistics == TRUE)
        INC_COUNTER(tokdata, sess, mech, NULL, POLICY_STRENGTH_IDX_0);

    return CKR_OK;
}


//
//
CK_RV digest_mgr_cleanup(STDLL_TokData_t *tokdata, SESSION *sess,
                         DIGEST_CONTEXT *ctx)
{
    if (!ctx) {
        TRACE_ERROR("Invalid function argument.\n");
        return CKR_FUNCTION_FAILED;
    }
    ctx->mech.ulParameterLen = 0;
    ctx->mech.mechanism = 0;
    ctx->multi_init = FALSE;
    ctx->multi = FALSE;
    ctx->active = FALSE;
    ctx->state_unsaveable = FALSE;
    ctx->count_statistics = FALSE;

    if (ctx->mech.pParameter) {
        free(ctx->mech.pParameter);
        ctx->mech.pParameter = NULL;
    }

    if (ctx->context != NULL) {
        if (ctx->context_free_func != NULL)
            ctx->context_free_func(tokdata, sess, ctx->context,
                                   ctx->context_len);
        else
            free(ctx->context);
        ctx->context = NULL;
    }
    ctx->context_len = 0;
    ctx->context_free_func = NULL;

    return CKR_OK;
}



//
//
CK_RV digest_mgr_digest(STDLL_TokData_t *tokdata,
                        SESSION *sess,
                        CK_BBOOL length_only,
                        DIGEST_CONTEXT *ctx,
                        CK_BYTE *in_data,
                        CK_ULONG in_data_len,
                        CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    CK_RV rc;

    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->active == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->multi_init == FALSE) {
        ctx->multi = FALSE;
        ctx->multi_init = TRUE;
    }

    if (!in_data || !out_data_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }

    // if the caller just wants the encrypted length, there is no reason to
    // specify the input data.  I just need the data length
    //
    if ((length_only == FALSE) && (!in_data || !out_data)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (ctx->multi == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }
    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
    case CKM_SHA224:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
    case CKM_SHA512_224:
    case CKM_SHA512_256:
    case CKM_IBM_SHA3_224:
    case CKM_IBM_SHA3_256:
    case CKM_IBM_SHA3_384:
    case CKM_IBM_SHA3_512:
        rc = sha_hash(tokdata, sess, length_only, ctx, in_data, in_data_len,
                      out_data, out_data_len);
        break;
#if !(NOMD2 )
    case CKM_MD2:
        rc = md2_hash(tokdata, sess, length_only, ctx, in_data, in_data_len,
                      out_data, out_data_len);
        break;
#endif
    case CKM_MD5:
        rc = md5_hash(tokdata, sess, length_only, ctx, in_data, in_data_len,
                      out_data, out_data_len);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

out:
    if (!((rc == CKR_BUFFER_TOO_SMALL) ||
          (rc == CKR_OK && length_only == TRUE))) {
        // "A call to C_Digest always terminates the active digest operation
        // unless it returns CKR_BUFFER_TOO_SMALL or is a successful call (i.e.,
        // one which returns CKR_OK) to determine the length of the buffer
        // needed to hold the message digest."
        digest_mgr_cleanup(tokdata, sess, ctx);
    }

    return rc;
}


//
//
CK_RV digest_mgr_digest_update(STDLL_TokData_t *tokdata,
                               SESSION *sess,
                               DIGEST_CONTEXT *ctx,
                               CK_BYTE *data, CK_ULONG data_len)
{
    CK_RV rc;

    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->active == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->multi_init == FALSE) {
        ctx->multi = TRUE;
        ctx->multi_init = TRUE;
    }
    if (ctx->multi == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }

    if (!data && data_len != 0) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
    case CKM_SHA224:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
    case CKM_SHA512_224:
    case CKM_SHA512_256:
    case CKM_IBM_SHA3_224:
    case CKM_IBM_SHA3_256:
    case CKM_IBM_SHA3_384:
    case CKM_IBM_SHA3_512:
        rc = sha_hash_update(tokdata, sess, ctx, data, data_len);
        break;
#if !(NOMD2)
    case CKM_MD2:
        rc = md2_hash_update(tokdata, sess, ctx, data, data_len);
        break;
#endif
    case CKM_MD5:
        rc = md5_hash_update(tokdata, sess, ctx, data, data_len);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
    }

out:
    if (rc != CKR_OK) {
        digest_mgr_cleanup(tokdata, sess, ctx);
        // "A call to C_DigestUpdate which results in an error
        // terminates the current digest operation."
    }

    return rc;
}


//
//
CK_RV digest_mgr_digest_key(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            DIGEST_CONTEXT *ctx, CK_OBJECT_HANDLE key_handle)
{
    CK_ATTRIBUTE *attr = NULL;
    OBJECT *key_obj = NULL;
    CK_OBJECT_CLASS class;
    CK_RV rc;


    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    /*
     * Secure keys can not be digested by digesting the CKA_VALUE attribute.
     */
    if (token_specific.secure_key_token) {
        TRACE_ERROR("%s because its a secure key token\n",
                    ock_err(CKR_KEY_INDIGESTIBLE));
        rc = CKR_KEY_INDIGESTIBLE;
        goto out;
    }

    rc = object_mgr_find_in_map1(tokdata, key_handle, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_HANDLE_INVALID));
        rc = CKR_KEY_HANDLE_INVALID;
        goto out;
    }
    // only allow digesting of CKO_SECRET keys
    //
    rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
        goto out;
    }


    if (class != CKO_SECRET_KEY) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_INDIGESTIBLE));
        rc = CKR_KEY_INDIGESTIBLE;
        goto out;
    }
    // every secret key has a CKA_VALUE attribute
    //
    rc = template_attribute_get_non_empty(key_obj->template, CKA_VALUE, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("Could not find CKA_VALUE for the key.\n");
        goto out;
    }

    rc = digest_mgr_digest_update(tokdata, sess, ctx,
                                  attr->pValue, attr->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("digest_mgr_digest_update failed\n");
    }

out:
    if (rc != CKR_OK) {
        digest_mgr_cleanup(tokdata, sess, ctx);
    }

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV digest_mgr_digest_final(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              CK_BBOOL length_only,
                              DIGEST_CONTEXT *ctx,
                              CK_BYTE *hash, CK_ULONG *hash_len)
{
    CK_RV rc;

    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->active == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->multi_init == FALSE) {
        ctx->multi = TRUE;
        ctx->multi_init = TRUE;
    }
    if (ctx->multi == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        rc = CKR_OPERATION_ACTIVE;
        goto out;
    }

    if (!hash_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_ARGUMENTS_BAD));
        rc = CKR_ARGUMENTS_BAD;
        goto out;
    }

    switch (ctx->mech.mechanism) {
    case CKM_SHA_1:
    case CKM_SHA224:
    case CKM_SHA256:
    case CKM_SHA384:
    case CKM_SHA512:
    case CKM_SHA512_224:
    case CKM_SHA512_256:
    case CKM_IBM_SHA3_224:
    case CKM_IBM_SHA3_256:
    case CKM_IBM_SHA3_384:
    case CKM_IBM_SHA3_512:
        rc = sha_hash_final(tokdata, sess, length_only, ctx, hash, hash_len);
        break;
#if !(NOMD2)
    case CKM_MD2:
        rc = md2_hash_final(tokdata, sess, length_only, ctx, hash, hash_len);
        break;
#endif
    case CKM_MD5:
        rc = md5_hash_final(tokdata, sess, length_only, ctx, hash, hash_len);
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;     // shouldn't happen
    }

out:
    if (!((rc == CKR_BUFFER_TOO_SMALL) ||
          (rc == CKR_OK && length_only == TRUE))) {
        // "A call to C_DigestFinal always terminates the active digest
        // operation unless it returns CKR_BUFFER_TOO_SMALL or is a successful
        // call (i.e., one which returns CKR_OK) to determine the length of the
        // buffer needed to hold the message digest."
        digest_mgr_cleanup(tokdata, sess, ctx);
    }

    return rc;
}
