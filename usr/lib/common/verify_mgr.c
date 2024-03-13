/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

// File:  verify_mgr.c
//
// Verify manager routines
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
CK_RV verify_mgr_init(STDLL_TokData_t *tokdata,
                      SESSION *sess,
                      SIGN_VERIFY_CONTEXT *ctx,
                      CK_MECHANISM *mech,
                      CK_BBOOL recover_mode, CK_OBJECT_HANDLE key,
                      CK_BBOOL checkpolicy)
{
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE *ptr = NULL;
    CK_KEY_TYPE keytype;
    CK_OBJECT_CLASS class;
    CK_BBOOL flag;
    CK_RV rc;


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
                                              POLICY_CHECK_VERIFY, sess);
        if (rc != CKR_OK) {
            TRACE_ERROR("POLICY VIOLATION: Verify init\n");
            goto done;
        }
    }

    if (recover_mode) {
        // is key allowed to verify signatures where the data can be
        // recovered from the signature?
        rc = template_attribute_get_bool(key_obj->template, CKA_VERIFY_RECOVER,
                                         &flag);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VERIFY_RECOVER for the key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
    } else {
        // is key allowed to verify signatures where the signature is an
        // appendix to the data?
        rc = template_attribute_get_bool(key_obj->template, CKA_VERIFY, &flag);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_VERIFY for the key.\n");
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
                TRACE_ERROR("Could not find CKA_VERIFY for the key.\n");
                goto done;
            }

            rc = check_pss_params(mech, attr->ulValueLen);
            if (rc != CKR_OK) {
                TRACE_DEVEL("check_pss_params failed.\n");
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

        // must be a PUBLIC key operation
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        if (class != CKO_PUBLIC_KEY) {
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

        // must be a PUBLIC key operation
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        if (class != CKO_PUBLIC_KEY) {
            TRACE_ERROR("This operation requires a public key.\n");
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
#if !(NOMD2)
    case CKM_MD2_RSA_PKCS:
#endif
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
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

        // must be a PUBLIC key operation
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        if (class != CKO_PUBLIC_KEY) {
            TRACE_ERROR("This operation requires a public key.\n");
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
        rc = template_attribute_get_non_empty(key_obj->template, CKA_MODULUS,
                                              &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_MODULUS for the key.\n");
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

        // must be a PUBLIC key operation
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        if (class != CKO_PUBLIC_KEY) {
            TRACE_ERROR("This operation requires a public key.\n");
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

        // must be a PUBLIC key operation
        //
        rc = template_attribute_get_ulong(key_obj->template, CKA_CLASS,
                                          &class);
        if (rc != CKR_OK) {
            TRACE_ERROR("Could not find CKA_CLASS for the key.\n");
            goto done;
        }

        if (class != CKO_PUBLIC_KEY) {
            TRACE_ERROR("This operation requires a public key.\n");
            rc = CKR_KEY_FUNCTION_NOT_PERMITTED;
            goto done;
        }
        // PKCS #11 doesn't allow multi-part DSA operations
        //
        ctx->context_len = 0;
        ctx->context = NULL;
        break;
#endif
#if !(NOMD2)
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

        // PKCS #11 doesn't allow multi-part HMAC operations
        //
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

        rc = hmac_verify_init(tokdata, sess, mech, key);
        if (rc != CKR_OK) {
            TRACE_ERROR("Failed to initialize hmac.\n");
            goto done;
        }
        break;
#if !(NOMD2)
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
#if !(NOMD2)
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
                TRACE_ERROR("%s\n", ock_err(ERR_KEY_TYPE_INCONSISTENT));
                rc = CKR_KEY_TYPE_INCONSISTENT;
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
        {
            CK_MAC_GENERAL_PARAMS *param =
                (CK_MAC_GENERAL_PARAMS *) mech->pParameter;

            if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc= CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
#if !(NOMD2)
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
            if ((mech->mechanism == CKM_SHA_1_HMAC_GENERAL) && (*param > 20)) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
            if ((mech->mechanism == CKM_SHA224_HMAC_GENERAL) && (*param > 28)) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
            if ((mech->mechanism == CKM_SHA256_HMAC_GENERAL) && (*param > 32)) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
            if ((mech->mechanism == CKM_SHA384_HMAC_GENERAL) && (*param > 48)) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
            if ((mech->mechanism == CKM_SHA512_HMAC_GENERAL) && (*param > 64)) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
            if ((mech->mechanism == CKM_SHA512_224_HMAC_GENERAL)
                && (*param > 28)) {
                TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_PARAM_INVALID));
                rc = CKR_MECHANISM_PARAM_INVALID;
                goto done;
            }
            if ((mech->mechanism == CKM_SHA512_256_HMAC_GENERAL)
                && (*param > 32)) {
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

            rc = hmac_verify_init(tokdata, sess, mech, key);
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
            // Netscape sets the parameter == 16.  PKCS #11 limit is 8
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
        {
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
                        TRACE_ERROR("%s\n",
                                    ock_err(ERR_MECHANISM_PARAM_INVALID));
                        rc = CKR_MECHANISM_PARAM_INVALID;
                        goto done;
                    }
                } else {
                    /* CKM_DES_MAC or CKM_DES3_MAC should not have params */
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
        }
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
                    TRACE_ERROR("%s\n",
                                ock_err(ERR_MECHANISM_PARAM_INVALID));
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
        {
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
                        TRACE_ERROR("%s\n",
                                    ock_err(ERR_MECHANISM_PARAM_INVALID));
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
        }
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
                    TRACE_ERROR("%s\n",
                                ock_err(ERR_MECHANISM_PARAM_INVALID));
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
        INC_COUNTER(tokdata, sess, mech, key_obj, POLICY_STRENGTH_IDX_0);

    object_put(tokdata, key_obj, TRUE);
    key_obj = NULL;

    return rc;
}


//
//
CK_RV verify_mgr_cleanup(STDLL_TokData_t *tokdata, SESSION *sess,
                         SIGN_VERIFY_CONTEXT *ctx)
{
    if (!ctx) {
        TRACE_ERROR("Invalid function argument.\n");
        return CKR_FUNCTION_FAILED;
    }
    ctx->key = 0;
    ctx->mech.ulParameterLen = 0;
    ctx->mech.mechanism = 0;
    ctx->multi_init = FALSE;
    ctx->multi = FALSE;
    ctx->active = FALSE;
    ctx->init_pending = FALSE;
    ctx->recover = FALSE;
    ctx->pkey_active = FALSE;
    ctx->state_unsaveable = FALSE;
    ctx->count_statistics = FALSE;

    if (ctx->mech.pParameter) {
        free(ctx->mech.pParameter);
        ctx->mech.pParameter = NULL;
    }

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
CK_RV verify_mgr_verify(STDLL_TokData_t *tokdata,
                        SESSION *sess,
                        SIGN_VERIFY_CONTEXT *ctx,
                        CK_BYTE *in_data,
                        CK_ULONG in_data_len,
                        CK_BYTE *signature, CK_ULONG sig_len)
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
    if (ctx->multi_init == FALSE) {
        ctx->multi = FALSE;
        ctx->multi_init = TRUE;
    }

    // if the caller just wants the signature length, there is no reason to
    // specify the input data.  I just need the input data length
    //
    if (!in_data || !signature) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->multi == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        return CKR_OPERATION_ACTIVE;
    }

    switch (ctx->mech.mechanism) {
    case CKM_RSA_PKCS:
        return rsa_pkcs_verify(tokdata, sess, ctx,
                               in_data, in_data_len, signature, sig_len);
    case CKM_RSA_X_509:
        return rsa_x509_verify(tokdata, sess, ctx,
                               in_data, in_data_len, signature, sig_len);
    case CKM_RSA_PKCS_PSS:
        return rsa_pss_verify(tokdata, sess, ctx, in_data, in_data_len,
                              signature, sig_len);
#if !(NOMD2)
    case CKM_MD2_RSA_PKCS:
#endif
    case CKM_MD5_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS:
        return rsa_hash_pkcs_verify(tokdata, sess, ctx,
                                    in_data, in_data_len, signature, sig_len);
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
        return rsa_hash_pss_verify(tokdata, sess, ctx, in_data, in_data_len,
                                   signature, sig_len);
#if !(NODSA)
    case CKM_DSA:
        return dsa_verify(tokdata, sess, ctx,
                          in_data, in_data_len, signature, sig_len);
#endif
#if !(NOMD2)
    case CKM_MD2_HMAC:
    case CKM_MD2_HMAC_GENERAL:
        return md2_hmac_verify(tokdata, sess, ctx,
                               in_data, in_data_len, signature, sig_len);
#endif
    case CKM_MD5_HMAC:
    case CKM_MD5_HMAC_GENERAL:
        return md5_hmac_verify(tokdata, sess, ctx,
                               in_data, in_data_len, signature, sig_len);
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
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        return sha_hmac_verify(tokdata, sess, ctx,
                               in_data, in_data_len, signature, sig_len);
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        return ssl3_mac_verify(tokdata, sess, ctx,
                               in_data, in_data_len, signature, sig_len);
    case CKM_DES3_MAC:
    case CKM_DES3_MAC_GENERAL:
        return des3_mac_verify(tokdata, sess, ctx, in_data, in_data_len,
                               signature, sig_len);
    case CKM_DES3_CMAC:
    case CKM_DES3_CMAC_GENERAL:
        return des3_cmac_verify(tokdata, sess, ctx, in_data, in_data_len,
                                signature, sig_len);
    case CKM_AES_MAC:
    case CKM_AES_MAC_GENERAL:
        return aes_mac_verify(tokdata, sess, ctx,
                              in_data, in_data_len, signature, sig_len);
    case CKM_AES_CMAC:
    case CKM_AES_CMAC_GENERAL:
        return aes_cmac_verify(tokdata, sess, ctx,
                               in_data, in_data_len, signature, sig_len);
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        return ec_hash_verify(tokdata, sess, ctx,
                              in_data, in_data_len, signature, sig_len);
    case CKM_ECDSA:
        return ec_verify(tokdata, sess, ctx,
                         in_data, in_data_len, signature, sig_len);
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}


//
//
CK_RV verify_mgr_verify_update(STDLL_TokData_t *tokdata,
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
        return rsa_hash_pkcs_verify_update(tokdata, sess, ctx, in_data,
                                           in_data_len);
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
        return rsa_hash_pss_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        return ssl3_mac_verify_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_DES3_MAC:
    case CKM_DES3_MAC_GENERAL:
        return des3_mac_verify_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_DES3_CMAC:
    case CKM_DES3_CMAC_GENERAL:
        return des3_cmac_verify_update(tokdata, sess, ctx, in_data,
                                       in_data_len);
    case CKM_AES_MAC:
    case CKM_AES_MAC_GENERAL:
        return aes_mac_verify_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_AES_CMAC:
    case CKM_AES_CMAC_GENERAL:
        return aes_cmac_verify_update(tokdata, sess, ctx, in_data, in_data_len);
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        return ec_hash_verify_update(tokdata, sess, ctx, in_data, in_data_len);
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
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        return hmac_verify_update(tokdata, sess, in_data, in_data_len);
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }
    TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}


//
//
CK_RV verify_mgr_verify_final(STDLL_TokData_t *tokdata,
                              SESSION *sess,
                              SIGN_VERIFY_CONTEXT *ctx,
                              CK_BYTE *signature, CK_ULONG sig_len)
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
        return rsa_hash_pkcs_verify_final(tokdata, sess, ctx, signature,
                                          sig_len);
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS_PSS:
        return rsa_hash_pss_verify_final(tokdata, sess, ctx, signature,
                                         sig_len);
    case CKM_SSL3_MD5_MAC:
    case CKM_SSL3_SHA1_MAC:
        return ssl3_mac_verify_final(tokdata, sess, ctx, signature, sig_len);
    case CKM_DES3_MAC:
    case CKM_DES3_MAC_GENERAL:
        return des3_mac_verify_final(tokdata, sess, ctx, signature, sig_len);
    case CKM_DES3_CMAC:
    case CKM_DES3_CMAC_GENERAL:
        return des3_cmac_verify_final(tokdata, sess, ctx, signature, sig_len);
    case CKM_AES_MAC:
    case CKM_AES_MAC_GENERAL:
        return aes_mac_verify_final(tokdata, sess, ctx, signature, sig_len);
    case CKM_AES_CMAC:
    case CKM_AES_CMAC_GENERAL:
        return aes_cmac_verify_final(tokdata, sess, ctx, signature, sig_len);
    case CKM_ECDSA_SHA1:
    case CKM_ECDSA_SHA224:
    case CKM_ECDSA_SHA256:
    case CKM_ECDSA_SHA384:
    case CKM_ECDSA_SHA512:
        return ec_hash_verify_final(tokdata, sess, ctx, signature, sig_len);
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
    case CKM_IBM_SHA3_224_HMAC:
    case CKM_IBM_SHA3_256_HMAC:
    case CKM_IBM_SHA3_384_HMAC:
    case CKM_IBM_SHA3_512_HMAC:
        return hmac_verify_final(tokdata, sess, signature, sig_len);
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}


//
//
CK_RV verify_mgr_verify_recover(STDLL_TokData_t *tokdata,
                                SESSION *sess,
                                CK_BBOOL length_only,
                                SIGN_VERIFY_CONTEXT *ctx,
                                CK_BYTE *signature,
                                CK_ULONG sig_len,
                                CK_BYTE *out_data, CK_ULONG *out_len)
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
    // if the caller just wants the signature length, there is no reason to
    // specify the input data.  I just need the input data length
    //
    if (!signature || !out_len) {
        TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));
        return CKR_FUNCTION_FAILED;
    }
    if (ctx->multi == TRUE) {
        TRACE_ERROR("%s\n", ock_err(ERR_OPERATION_ACTIVE));
        return CKR_OPERATION_ACTIVE;
    }

    switch (ctx->mech.mechanism) {
    case CKM_RSA_PKCS:
        return rsa_pkcs_verify_recover(tokdata, sess, length_only,
                                       ctx,
                                       signature, sig_len, out_data, out_len);
    case CKM_RSA_X_509:
        return rsa_x509_verify_recover(tokdata, sess, length_only,
                                       ctx,
                                       signature, sig_len, out_data, out_len);
    default:
        TRACE_ERROR("%s\n", ock_err(ERR_MECHANISM_INVALID));
        return CKR_MECHANISM_INVALID;
    }

    TRACE_ERROR("%s\n", ock_err(ERR_FUNCTION_FAILED));

    return CKR_FUNCTION_FAILED;
}
