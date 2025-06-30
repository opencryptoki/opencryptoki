/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  sign_mgr.c
//
// Signature manager routines
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

#include "../api/policy.h"
#include "../api/statistics.h"

//
//
CK_RV sign_mgr_init(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_MECHANISM *mech,
                    CK_BBOOL recover_mode, CK_OBJECT_HANDLE key,
                    CK_BBOOL checkpolicy, CK_BBOOL checkauth)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_KEY_TYPE keytype, exp_keytype, alt_keytype;
    CK_OBJECT_CLASS class;
    CK_BBOOL flag;
    CK_RV rc;
    CK_ULONG strength = POLICY_STRENGTH_IDX_0;

    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->active != FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        return CKR_OPERATION_ACTIVE;
    }
    // key usage restrictions
    //
    rc = object_mgr_find_in_map1(tokdata, key, &key_obj, READ_LOCK);
    if (rc != CKR_OK) {
        TRACE_ERROR("Failed to acquire key from specified handle.\n");
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            return CKR_KEY_HANDLE_INVALID;
        else
            return rc;
    }
    if (checkpolicy) {
        rc = tokdata->policy->is_mech_allowed(tokdata->policy, mech,
                                              &key_obj->strength,
                                              POLICY_CHECK_SIGNATURE, sess);
        if (rc != CKR_OK) {
            TRACE_ERROR("POLICY VIOLATION: Sign init\n");
            goto done;
        }
    }

    ctx->auth_required = FALSE;
    if (checkauth) {
        rc = key_object_is_always_authenticate(key_obj->template,
                                               &ctx->auth_required);
        if (rc != CKR_OK) {
            TRACE_ERROR("key_object_is_always_authenticate failed\n");
            goto done;
        }
    }

    if (recover_mode) {
        // is key allowed to generate signatures where the data can be
        // recovered from the signature?
        rc = template_attribute_get_bool(key_obj->template, CKA_SIGN_RECOVER,
                                         &flag);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_SIGN_RECOVER for the key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
    } else {
        // is key allowed to generate signatures where the signature is an
        // appendix to the data?
        rc = template_attribute_get_bool(key_obj->template, CKA_SIGN, &flag);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_SIGN for the key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
    }
    if (flag != TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_KEY_FUNCTION_NOT_PERMITTED));
        rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
        goto done;
    }

    if (!key_object_is_mechanism_allowed(key_obj->template, mech->mechanism)) {
        TRACE_ERROR("Mechanism not allowed per CKA_ALLOWED_MECHANISMS.\n");
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }

    // is the mechanism supported?  is the key type correct?  is a
    // parameter present if required?  is the key size allowed?
    // is the key allowed to generate signatures?
    //
    switch (mech->mechanism) {
    case CKM_RSA_X_509:
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_PSS:
        if (mech->mechanism == CKM_RSA_PKCS_PSS) {
            rc = template_attribute_get_non_empty(key_obj->template,
                                                  CKA_MODULUS, &attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
                goto done;
            }

            rc = check_pss_params(mech, attr->ulValueLen);
            if (rc != CKR_OK) {
                TRACE_DEVEL("check_pss_params() failed.\n");
                goto done;
            }
        } else {
            if (mech->ulParameterLen != 0) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
        }

        rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        if (keytype != CKK_RSA) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto done;
        }

        // must be a PRIVATE key
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        // if it's not a private RSA key then we have an internal failure...
        // means that somehow a public key got assigned a CKA_SIGN attribute
        //
        if (class != CKO_PRIVATE_KEY) {
            TRACE_ERROR("This operation requires a private key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
        // PKCS #11 doesn't allow multi-part RSA operations
        //
        ctx->context_len = 0;
        ctx->context = NULL;
        break;
    case CKM_ECDSA:
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
    case CKM_ECDSA_SHA3_224:
    case CKM_ECDSA_SHA3_256:
    case CKM_ECDSA_SHA3_384:
    case CKM_ECDSA_SHA3_512:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        if (keytype != CKK_EC) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto done;
        }

        // must be a PRIVATE key
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        if (class != CKO_PRIVATE_KEY) {
            TRACE_ERROR("This operation requires a private key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }

        if (mech->mechanism == CKM_ECDSA) {
            ctx->context_len = 0;
            ctx->context = NULL;
        } else {
            ctx->context_len = sizeof(RSA_DIGEST_CONTEXT);
            ctx->context = (CK_BYTE *) malloc(sizeof(RSA_DIGEST_CONTEXT));
            if (!ctx->context) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                goto done;
            }
            memset(ctx->context, 0x0, sizeof(RSA_DIGEST_CONTEXT));
        }
        break;
    case CKM_EDDSA:
        /* Mechanism parameter CK_EDDSA_PARAMS is optional */
        if (mech->ulParameterLen != 0 &&
            mech->ulParameterLen != sizeof(CK_EDDSA_PARAMS)) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        if (keytype != CKK_EC_EDWARDS) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto done;
        }

        // must be a PRIVATE key
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        if (class != CKO_PRIVATE_KEY) {
            TRACE_ERROR("This operation requires a private key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }

        ctx->context_len = 0;
        ctx->context = NULL;
        break;
#if  !(NOMD2)
    case CKM_MD2_RSA_PKCS:
#endif
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
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        if (keytype != CKK_RSA) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto done;
        }

        // must be a PRIVATE key operation
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        if (class != CKO_PRIVATE_KEY) {
            TRACE_ERROR("This operation requires a private key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
        ctx->context_len = sizeof(RSA_DIGEST_CONTEXT);
        ctx->context = (CK_BYTE *) malloc(sizeof(RSA_DIGEST_CONTEXT));
        if (!ctx->context) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        memset(ctx->context, 0x0, sizeof(RSA_DIGEST_CONTEXT));
        break;
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_SHA3_224_RSA_PKCS_PSS:
    case CKM_SHA3_256_RSA_PKCS_PSS:
    case CKM_SHA3_384_RSA_PKCS_PSS:
    case CKM_SHA3_512_RSA_PKCS_PSS:
        rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                              &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        rc = check_pss_params(mech, attr->ulValueLen);
        if (rc != CKR_OK) {
            TRACE_DEVEL("check_pss_params failed.\n");
            goto done;
        }

        rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        if (keytype != CKK_RSA) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto done;
        }

        // must be a PRIVATE key operation
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        if (class != CKO_PRIVATE_KEY) {
            TRACE_ERROR("This operation requires a private key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
        ctx->context_len = sizeof(DIGEST_CONTEXT);
        ctx->context = (CK_BYTE *) malloc(ctx->context_len);
        if (!ctx->context) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        memset(ctx->context, 0x0, ctx->context_len);
        break;
#if !(NODSA)
    case CKM_DSA:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }

        rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        if (keytype != CKK_DSA) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto done;
        }

        // must be a PRIVATE key
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        // if it's not a private RSA key then we have an internal failure...
        // means that somehow a public key got assigned a CKA_SIGN attribute
        //
        if (class != CKO_PRIVATE_KEY) {
            TRACE_ERROR("This operation requires a private key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
        // PKCS #11 doesn't allow multi-part DSA operations
        //
        ctx->context_len = 0;
        ctx->context = NULL;
        break;
#endif
#if  !(NOMD2)
    case CKM_MD2_HMAC:
#endif
    case CKM_MD5_HMAC:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }

        rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        if (keytype != CKK_GENERIC_SECRET) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto done;
        }

        /* Note: It was previously believed that pkcs#11 did not
         * support hmac multipart. As a result, those tokens using the
         * locally implemented hmac helper functions do not support
         * multipart hmac.
         */
        ctx->context_len = 0;
        ctx->context = NULL;
        break;
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_512_HMAC:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }

        rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        rc = pkcsget_keytype_for_mech(mech->mechanism, &exp_keytype,
                                      &alt_keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("pkcsget_keytype_for_mech failed.\n");
            goto done;
        }

        if (keytype != exp_keytype && keytype != alt_keytype) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto done;
        }

        // PKCS #11 doesn't allow multi-part HMAC operations
        //
        ctx->context_len = 0;
        ctx->context = NULL;

        strength = key_obj->strength.strength;

        /* Release obj lock, token specific hmac-sign may re-acquire the lock */
        object_put(tokdata, key_obj, TRUE);
        key_obj = NULL;

        rc = hmac_sign_init(tokdata, sess, mech, key);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to initialize hmac.\n");
            goto done;
        }
        break;
#if  !(NOMD2)
    case CKM_MD2_HMAC_GENERAL:
#endif
    case CKM_MD5_HMAC_GENERAL:
        {
            CK_MAC_GENERAL_PARAMS *param =
                (CK_MAC_GENERAL_PARAMS *) mech->pParameter;

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
#if  !(NOMD2)
            if ((mech->mechanism == CKM_MD2_HMAC_GENERAL) && (*param > 16)) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
#endif

            if ((mech->mechanism == CKM_MD5_HMAC_GENERAL) && (*param > 16)) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }

            rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                              &keytype);
            if (rc != CKR_OK) {
                TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
                goto done;
            }

            if (keytype != CKK_GENERIC_SECRET) {
                TRACE_ERROR("A generic secret key is required.\n");
                rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
                goto done;
            }

            // PKCS #11 doesn't allow multi-part HMAC operations
            //
            ctx->context_len = 0;
            ctx->context = NULL;
        }
        break;
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_224_HMAC_GENERAL:
    case CKM_SHA512_256_HMAC_GENERAL:
    case CKM_SHA3_224_HMAC_GENERAL:
    case CKM_SHA3_256_HMAC_GENERAL:
    case CKM_SHA3_384_HMAC_GENERAL:
    case CKM_SHA3_512_HMAC_GENERAL:
        {
            CK_MAC_GENERAL_PARAMS *param =
                (CK_MAC_GENERAL_PARAMS *) mech->pParameter;
            CK_MECHANISM_TYPE digest_mech;
            CK_BBOOL general;
            CK_ULONG hsize;

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }

            rc = get_hmac_digest(mech->mechanism, &digest_mech, &general);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s get_hmac_digest failed\n", __func__);
                goto done;
            }

            rc = get_sha_size(digest_mech, &hsize);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s get_sha_size failed\n", __func__);
                goto done;
            }

            if (*param > hsize) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }

            rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                              &keytype);
            if (rc != CKR_OK) {
                TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
                goto done;
            }

            rc = pkcsget_keytype_for_mech(mech->mechanism, &exp_keytype,
                                          &alt_keytype);
            if (rc != CKR_OK) {
                TRACE_ERROR("pkcsget_keytype_for_mech failed.\n");
                goto done;
            }

            if (keytype != exp_keytype && keytype != alt_keytype) {
                TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                rc = CKR_KEY_TYPE_INCONSISTENT;
                goto done;
            }

            /* Note: It was previously believed that pkcs#11 did not
             * support hmac multipart. As a result, those tokens using the
             * locally implemented hmac helper functions do not support
             * multipart hmac.
             */
            ctx->context_len = 0;
            ctx->context = NULL;

            rc = hmac_sign_init(tokdata, sess, mech, key);
            if (rc != CKR_OK) {
                TRACE_ERROR("Failed to initialize hmac.\n");
                goto done;
            }
        }
        break;
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        {
            CK_MAC_GENERAL_PARAMS *param =
                (CK_MAC_GENERAL_PARAMS *) mech->pParameter;

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
            // FIXME - Netscape sets the parameter == 16.  PKCS #11 limit is 8
            //
            if (mech->mechanism == CKM_SSL3_MD5_MAC) {
                if (*param < 4 || *param > 16) {
                    TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                    rc = CKR_MECHANISM_PARAM_INVALID;
                    goto done;
                }
            }

            if (mech->mechanism == CKM_SSL3_SHA1_MAC) {
                if (*param < 4 || *param > 20) {
                    TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                    rc = CKR_MECHANISM_PARAM_INVALID;
                    goto done;
                }
            }

            rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                              &class);
            if (rc != CKR_OK) {
                TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
                goto done;
            }

            if (class != CKO_SECRET_KEY) {
                TRACE_ERROR("This operation requires a secret key.\n");
                rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
                goto done;
            }

            ctx->context_len = sizeof(SSL3_MAC_CONTEXT);
            ctx->context = (CK_BYTE *) malloc(sizeof(SSL3_MAC_CONTEXT));
            if (!ctx->context) {
                TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
                rc = CKR_HOST_MEMORY;
                goto done;
            }
            memset(ctx->context, 0x0, sizeof(SSL3_MAC_CONTEXT));
        }
        break;
    case CKM_DES3_MAC:
    case CKM_DES3_MAC_GENERAL:
        if (mech->pParameter) {

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }

            CK_MAC_GENERAL_PARAMS *param =
                (CK_MAC_GENERAL_PARAMS *) mech->pParameter;

            if (mech->mechanism == CKM_DES3_MAC_GENERAL) {
                if (*param < 1 || *param > DES_BLOCK_SIZE) {
                    TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                    rc = CKR_MECHANISM_PARAM_INVALID;
                    goto done;
                }
            } else {
                /* CKM_DES3_MAC should not have params */
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
        }

        ctx->context = (CK_BYTE *) malloc(sizeof(DES_DATA_CONTEXT));
        ctx->context_len = sizeof(DES_DATA_CONTEXT);

        if (!ctx->context) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        memset(ctx->context, 0x0, sizeof(DES_DATA_CONTEXT));
        break;
    case CKM_DES3_CMAC:
    case CKM_DES3_CMAC_GENERAL:
        if (mech->pParameter) {

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }

            CK_MAC_GENERAL_PARAMS *param =
                (CK_MAC_GENERAL_PARAMS *) mech->pParameter;

            if (mech->mechanism == CKM_DES3_CMAC_GENERAL) {
                if (*param < 1 || *param > DES_BLOCK_SIZE) {
                    TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                    rc = CKR_MECHANISM_PARAM_INVALID;
                    goto done;
                }
            } else {
                /* CKM_DES3_CMAC should not have params */
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
        }

        ctx->context = (CK_BYTE *) malloc(sizeof(DES_CMAC_CONTEXT));
        ctx->context_len = sizeof(DES_CMAC_CONTEXT);

        if (!ctx->context) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        memset(ctx->context, 0x0, sizeof(DES_CMAC_CONTEXT));
        break;
    case CKM_AES_MAC:
    case CKM_AES_MAC_GENERAL:
        if (mech->pParameter) {

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }

            CK_MAC_GENERAL_PARAMS *param =
                (CK_MAC_GENERAL_PARAMS *) mech->pParameter;

            if (mech->mechanism == CKM_AES_MAC_GENERAL) {
                if (*param < 1 || *param > AES_BLOCK_SIZE) {
                    TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                    rc = CKR_MECHANISM_PARAM_INVALID;
                    goto done;
                }
            } else {
                /* CKM_AES_MAC should not have params */
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
        }

        ctx->context = (CK_BYTE *) malloc(sizeof(AES_DATA_CONTEXT));
        ctx->context_len = sizeof(AES_DATA_CONTEXT);

        if (!ctx->context) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        memset(ctx->context, 0x0, sizeof(AES_DATA_CONTEXT));
        break;
    case CKM_AES_CMAC:
    case CKM_AES_CMAC_GENERAL:
        if (mech->pParameter) {

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }

            CK_MAC_GENERAL_PARAMS *param =
                (CK_MAC_GENERAL_PARAMS *) mech->pParameter;

            if (mech->mechanism == CKM_AES_CMAC_GENERAL) {
                if (*param < 1 || *param > AES_BLOCK_SIZE) {
                    TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                    rc = CKR_MECHANISM_PARAM_INVALID;
                    goto done;
                }
            } else {
                /* CKM_AES_CMAC should not have params */
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
        }

        ctx->context = (CK_BYTE *) malloc(sizeof(AES_CMAC_CONTEXT));
        ctx->context_len = sizeof(AES_CMAC_CONTEXT);

        if (!ctx->context) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        memset(ctx->context, 0x0, sizeof(AES_CMAC_CONTEXT));
        break;
    case CKM_IBM_DILITHIUM:
        if (mech->ulParameterLen != 0) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }

        rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        if (keytype != CKK_IBM_PQC_DILITHIUM) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto done;
        }

        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        if (class != CKO_PRIVATE_KEY) {
            TRACE_ERROR("This operation requires a private key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }

        ctx->context_len = 0;
        ctx->context = NULL;
        break;
    case CKM_IBM_ML_DSA:
        if (mech->ulParameterLen != 0 &&
            mech->ulParameterLen != sizeof(CK_IBM_SIGN_ADDITIONAL_CONTEXT)) {
            TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }
        if (mech->ulParameterLen == sizeof(CK_IBM_SIGN_ADDITIONAL_CONTEXT) &&
            mech->pParameter == NULL) {
            rc = CKR_MECHANISM_PARAM_INVALID;
            goto done;
        }

        rc = template_attribute_get_ulong(key_obj->template, CKA_KEY_TYPE,
                                          &keytype);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_KEY_TYPE for the key.\n");
            goto done;
        }

        if (keytype != CKK_IBM_ML_DSA) {
            TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
            rc = CKR_KEY_TYPE_INCONSISTENT;
            goto done;
        }

        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        if (class != CKO_PRIVATE_KEY) {
            TRACE_ERROR("This operation requires a private key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }

        ctx->context_len = 0;
        ctx->context = NULL;
        break;
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        rc = CKR_MECHANISM_INVALID;
        goto done;
    }


    if (mech->ulParameterLen > 0 && mech->pParameter != NULL) {
        ptr = (CK_BYTE *) malloc(mech->ulParameterLen);
        if (!ptr) {
            TRACE_ERROR("%s\n", ock_err(ERR_HOST_MEMORY));
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        memcpy(ptr, mech->pParameter, mech->ulParameterLen);

        /* Deep copy mechanism parameter, if required */
        switch (mech->mechanism)
        {
        case CKM_IBM_ML_DSA:
            rc = ibm_ml_dsa_dup_param(mech->pParameter, ptr,
                                      mech->ulParameterLen);
            if (rc != CKR_OK) {
                TRACE_ERROR("ibm_ml_dsa_dup_param failed\n");
                free(ptr);
            }
            break;
        default:
            break;
        }
    }

    ctx->key = key;
    ctx->mech.ulParameterLen = mech->ulParameterLen;
    ctx->mech.mechanism = mech->mechanism;
    ctx->mech.pParameter = ptr;
    ctx->multi_init = FALSE;
    ctx->multi = FALSE;
    ctx->active = TRUE;
    ctx->recover = recover_mode;
    ctx->pkey_active = FALSE;

    rc = CKR_OK;

done:
    if (ctx->count_statistics == TRUE && rc == CKR_OK)
        INC_COUNTER(tokdata, sess, mech, key_obj, strength);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV sign_mgr_cleanup(STDLL_TokData_t *tokdata, SESSION *sess,
                       SIGN_VERIFY_CONTEXT *ctx)
{
    if (!ctx) {
        TRACE_ERROR("Invalid function argument.\n");
        return CKR_FUNCTION_FAILED;
    }
    ctx->key = 0;
    ctx->multi_init = FALSE;
    ctx->multi = FALSE;
    ctx->active = FALSE;
    ctx->init_pending = FALSE;
    ctx->recover = FALSE;
    ctx->pkey_active = FALSE;
    ctx->state_unsaveable = FALSE;
    ctx->count_statistics = FALSE;
    ctx->auth_required = FALSE;

    if (ctx->mech.pParameter) {
        /* Deep free mechanism parameter, if required */
        switch (ctx->mech.mechanism)
        {
        case CKM_IBM_EC_AGGREGATE:
            ec_agg_free_param((CK_IBM_ECDSA_OTHER_BLS_PARAMS *)ctx->mech.pParameter);
            break;
        case CKM_IBM_ML_DSA:
            ibm_ml_dsa_free_param(ctx->mech.pParameter,
                                  ctx->mech.ulParameterLen);
            break;
        default:
            break;
        }

        free(ctx->mech.pParameter);
        ctx->mech.pParameter = NULL;
    }
    ctx->mech.mechanism = 0;
    ctx->mech.ulParameterLen = 0;

    if (ctx->context) {
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
CK_RV sign_mgr_sign(STDLL_TokData_t *tokdata,
                    SESSION *sess,
                    CK_BBOOL length_only,
                    SIGN_VERIFY_CONTEXT *ctx,
                    CK_BYTE *in_data,
                    CK_ULONG in_data_len,
                    CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->active == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->recover == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->auth_required == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
        return CKR_USER_NOT_LOGGED_IN;
    }
    if (ctx->multi_init == FALSE) {
        ctx->multi = FALSE;
        ctx->multi_init = TRUE;
    }

    // if the caller just wants the signature length, there is no reason to
    // specify the input data.  I just need the input data length
    //
    if ((length_only == FALSE) && (!in_data || !out_data)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->multi == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        return CKR_OPERATION_ACTIVE;
    }

    switch (ctx->mech.mechanism) {
    case CKM_RSA_PKCS:
        return rsa_pkcs_sign(tokdata, sess, length_only, ctx,
                             in_data, in_data_len, out_data, out_data_len);
    case CKM_RSA_X_509:
        return rsa_x509_sign(tokdata, sess, length_only, ctx,
                             in_data, in_data_len, out_data, out_data_len);
    case CKM_RSA_PKCS_PSS:
        return rsa_pss_sign(tokdata, sess, length_only, ctx, in_data,
                            in_data_len, out_data, out_data_len);
#if !(NOMD2)
    case CKM_MD2_RSA_PKCS:
#endif
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
        return rsa_hash_pkcs_sign(tokdata, sess, length_only, ctx,
                                  in_data, in_data_len, out_data, out_data_len);
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_SHA3_224_RSA_PKCS_PSS:
    case CKM_SHA3_256_RSA_PKCS_PSS:
    case CKM_SHA3_384_RSA_PKCS_PSS:
    case CKM_SHA3_512_RSA_PKCS_PSS:
        return rsa_hash_pss_sign(tokdata, sess, length_only, ctx, in_data,
                                 in_data_len, out_data, out_data_len);
#if !(NODSA)
    case CKM_DSA:
        return dsa_sign(tokdata, sess, length_only, ctx,
                        in_data, in_data_len, out_data, out_data_len);
#endif
#if !(NOMD2)
    case CKM_MD2_HMAC:
    case CKM_MD2_HMAC_GENERAL:
        return md2_hmac_sign(tokdata, sess, length_only, ctx,
                             in_data, in_data_len, out_data, out_data_len);
#endif
    case CKM_MD5_HMAC:
    case CKM_MD5_HMAC_GENERAL:
        return md5_hmac_sign(tokdata, sess, length_only, ctx,
                             in_data, in_data_len, out_data, out_data_len);
    case CKM_SHA_1_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA224_HMAC:
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA256_HMAC:
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA384_HMAC:
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_224_HMAC_GENERAL:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA512_256_HMAC_GENERAL:
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_224_HMAC_GENERAL:
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_256_HMAC_GENERAL:
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_384_HMAC_GENERAL:
    case CKM_SHA3_512_HMAC:
    case CKM_SHA3_512_HMAC_GENERAL:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        return sha_hmac_sign(tokdata, sess, length_only, ctx,
                             in_data, in_data_len, out_data, out_data_len);
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        return ssl3_mac_sign(tokdata, sess, length_only, ctx,
                             in_data, in_data_len, out_data, out_data_len);
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
    case CKM_ECDSA_SHA3_224:
    case CKM_ECDSA_SHA3_256:
    case CKM_ECDSA_SHA3_384:
    case CKM_ECDSA_SHA3_512:
        return ec_hash_sign(tokdata, sess, length_only, ctx,
                            in_data, in_data_len, out_data, out_data_len);
    case CKM_ECDSA:
    case CKM_EDDSA:
        return ec_sign(tokdata, sess, length_only, ctx,
                       in_data, in_data_len, out_data, out_data_len);
    case CKM_DES3_MAC:
    case CKM_DES3_MAC_GENERAL:
        return des3_mac_sign(tokdata, sess, length_only, ctx, in_data,
                             in_data_len, out_data, out_data_len);
    case CKM_DES3_CMAC:
    case CKM_DES3_CMAC_GENERAL:
        return des3_cmac_sign(tokdata, sess, length_only, ctx, in_data,
                              in_data_len, out_data, out_data_len);
    case CKM_AES_MAC:
    case CKM_AES_MAC_GENERAL:
        return aes_mac_sign(tokdata, sess, length_only, ctx, in_data,
                            in_data_len, out_data, out_data_len);
    case CKM_AES_CMAC:
    case CKM_AES_CMAC_GENERAL:
        return aes_cmac_sign(tokdata, sess, length_only, ctx, in_data,
                             in_data_len, out_data, out_data_len);
    case CKM_IBM_DILITHIUM:
    case CKM_IBM_ML_DSA:
        return ibm_ml_dsa_sign(tokdata, sess, length_only, ctx,
                               in_data, in_data_len, out_data, out_data_len);
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    TRACE_DEVEL("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}


//
//
CK_RV sign_mgr_sign_update(STDLL_TokData_t *tokdata,
                           SESSION *sess,
                           SIGN_VERIFY_CONTEXT *ctx,
                           CK_BYTE *in_data, CK_ULONG in_data_len)
{
    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }

    if (ctx->active == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->recover == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->auth_required == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
        return CKR_USER_NOT_LOGGED_IN;
    }
    if (ctx->multi_init == FALSE) {
        ctx->multi = TRUE;
        ctx->multi_init = TRUE;
    }
    if (ctx->multi == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        return CKR_OPERATION_ACTIVE;
    }

    switch (ctx->mech.mechanism) {
#if !(NOMD2)
    case CKM_MD2_RSA_PKCS:
#endif
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
        return rsa_hash_pkcs_sign_update(tokdata, sess, ctx, in_data,
                                         in_data_len);
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_SHA3_224_RSA_PKCS_PSS:
    case CKM_SHA3_256_RSA_PKCS_PSS:
    case CKM_SHA3_384_RSA_PKCS_PSS:
    case CKM_SHA3_512_RSA_PKCS_PSS:
        return rsa_hash_pss_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        return ssl3_mac_sign_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_DES3_MAC:
    case CKM_DES3_MAC_GENERAL:
        return des3_mac_sign_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_DES3_CMAC:
    case CKM_DES3_CMAC_GENERAL:
        return des3_cmac_sign_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_AES_MAC:
    case CKM_AES_MAC_GENERAL:
        return aes_mac_sign_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_AES_CMAC:
    case CKM_AES_CMAC_GENERAL:
        return aes_cmac_sign_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
    case CKM_ECDSA_SHA3_224:
    case CKM_ECDSA_SHA3_256:
    case CKM_ECDSA_SHA3_384:
    case CKM_ECDSA_SHA3_512:
        return ec_hash_sign_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_224_HMAC_GENERAL:
    case CKM_SHA512_256_HMAC_GENERAL:
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_224_HMAC_GENERAL:
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_256_HMAC_GENERAL:
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_384_HMAC_GENERAL:
    case CKM_SHA3_512_HMAC:
    case CKM_SHA3_512_HMAC_GENERAL:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        return hmac_sign_update(tokdata, sess, in_data, in_data_len);
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    TRACE_DEVEL("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}


//
//
CK_RV sign_mgr_sign_final(STDLL_TokData_t *tokdata,
                          SESSION *sess,
                          CK_BBOOL length_only,
                          SIGN_VERIFY_CONTEXT *ctx,
                          CK_BYTE *signature, CK_ULONG *sig_len)
{
    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->active == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->recover == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->auth_required == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
        return CKR_USER_NOT_LOGGED_IN;
    }
    if (ctx->multi_init == FALSE || ctx->multi == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        return CKR_OPERATION_ACTIVE;
    }

    switch (ctx->mech.mechanism) {
#if !(NOMD2)
    case CKM_MD2_RSA_PKCS:
#endif
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
        return rsa_hash_pkcs_sign_final(tokdata, sess, length_only, ctx,
                                        signature, sig_len);
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_SHA3_224_RSA_PKCS_PSS:
    case CKM_SHA3_256_RSA_PKCS_PSS:
    case CKM_SHA3_384_RSA_PKCS_PSS:
    case CKM_SHA3_512_RSA_PKCS_PSS:
        return rsa_hash_pss_sign_final(tokdata, sess, length_only, ctx,
                                       signature, sig_len);
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        return ssl3_mac_sign_final(tokdata, sess, length_only, ctx, signature,
                                   sig_len);
    case CKM_DES3_MAC:
    case CKM_DES3_MAC_GENERAL:
        return des3_mac_sign_final(tokdata, sess, length_only, ctx,
                                   signature, sig_len);
    case CKM_DES3_CMAC:
    case CKM_DES3_CMAC_GENERAL:
        return des3_cmac_sign_final(tokdata, sess, length_only, ctx,
                                    signature, sig_len);
    case CKM_AES_MAC:
    case CKM_AES_MAC_GENERAL:
        return aes_mac_sign_final(tokdata, sess, length_only, ctx, signature,
                                  sig_len);
    case CKM_AES_CMAC:
    case CKM_AES_CMAC_GENERAL:
        return aes_cmac_sign_final(tokdata, sess, length_only, ctx, signature,
                                   sig_len);
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
    case CKM_ECDSA_SHA3_224:
    case CKM_ECDSA_SHA3_256:
    case CKM_ECDSA_SHA3_384:
    case CKM_ECDSA_SHA3_512:
        return ec_hash_sign_final(tokdata, sess, length_only, ctx, signature,
                                  sig_len);
    case CKM_SHA_1_HMAC:
    case CKM_SHA224_HMAC:
    case CKM_SHA256_HMAC:
    case CKM_SHA384_HMAC:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_224_HMAC_GENERAL:
    case CKM_SHA512_256_HMAC_GENERAL:
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_224_HMAC_GENERAL:
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_256_HMAC_GENERAL:
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_384_HMAC_GENERAL:
    case CKM_SHA3_512_HMAC:
    case CKM_SHA3_512_HMAC_GENERAL:
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        return hmac_sign_final(tokdata, sess, signature, sig_len);
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    TRACE_DEVEL("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}


//
//
CK_RV sign_mgr_sign_recover(STDLL_TokData_t *tokdata,
                            SESSION *sess,
                            CK_BBOOL length_only,
                            SIGN_VERIFY_CONTEXT *ctx,
                            CK_BYTE *in_data,
                            CK_ULONG in_data_len,
                            CK_BYTE *out_data, CK_ULONG *out_data_len)
{
    if (!sess || !ctx) {
        TRACE_ERROR("Invalid function arguments.\n");
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->active == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->recover == FALSE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_NOT_INITIALIZED));
        return CKR_OPERATION_NOT_INITIALIZED;
    }
    if (ctx->auth_required == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_USER_NOT_LOGGED_IN));
        return CKR_USER_NOT_LOGGED_IN;
    }
    // if the caller just wants the signature length, there is no reason to
    // specify the input data.  I just need the input data length
    //
    if ((length_only == FALSE) && (!in_data || !out_data)) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->multi == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        return CKR_OPERATION_ACTIVE;
    }

    switch (ctx->mech.mechanism) {
    case CKM_RSA_PKCS:
        // we can use the same sign mechanism to do sign-recover
        //
        return rsa_pkcs_sign(tokdata, sess, length_only, ctx,
                             in_data, in_data_len, out_data, out_data_len);
    case CKM_RSA_X_509:
        return rsa_x509_sign(tokdata, sess, length_only, ctx,
                             in_data, in_data_len, out_data, out_data_len);
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    TRACE_DEVEL("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}
