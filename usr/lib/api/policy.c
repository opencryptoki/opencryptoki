/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include "cfgparser.h"
#include "stringtranslations.h"
#include "policy.h"
#include "trace.h"
#include "ock_syslog.h"
#include <stdlib.h>
#include <string.h>
#include "hashmap.h"
#include <ec_defs.h>
#include <pkcs11types.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <grp.h>
#include <errno.h>
#include <host_defs.h>
#include <pqc_defs.h>

/* in h_extern.h, but not included since it creates too many unneeded
   dependencies for unit tests. */
extern CK_RV get_sha_size(CK_ULONG mech, CK_ULONG *hsize);

#define COMPARE_MODEXP        0
#define COMPARE_ECC           1
#define COMPARE_SYMMETRIC     2
/* This is handled specially for now.  Value chosen such that it is
   not a valid index for struct strength.strength.arr. */
#define COMPARE_PQC           5
#define COMPARE_NOKEY         0xff

#define OCK_POLICY_CFG   OCK_CONFDIR "/policy.conf"
#define OCK_STRENGTH_CFG OCK_CONFDIR "/strength.conf"

#define OCK_POLICY_MINVERSION    0u
#define OCK_STRENGTH_MINVERSION  0u

#define OCK_POLICY_PERMS (0640u)

struct strength {
    union {
        CK_ULONG arr[5];
        struct {
            /* Keep this order in sync with the COMPARE_* definitions */
            CK_ULONG modexp;
            CK_ULONG ecc;
            CK_ULONG symmetric;
            CK_ULONG digests;
            CK_ULONG signatures;
        } details;
    } strength;
    CK_BBOOL set;
};

struct policy_private {
    struct hashmap   *allowedmechs;
    const struct _ec **allowedcurves;
    unsigned int       minstrengthidx;
    int                numallowedcurves; /* negative if all curves are allowed */
    CK_ULONG           allowedmgfs;
    CK_ULONG           allowedvendormgfs;
    CK_ULONG           allowedkdfs;
    CK_ULONG           allowedvendorkdfs;
    CK_ULONG           allowedprfs;
    CK_ULONG           maxcurvesize;
    /* Strength struct ordered from highest to lowest. */
    struct strength strengths[NUM_SUPPORTED_STRENGTHS];
};

static CK_ULONG policy_get_sym_key_strength(policy_t p, CK_ULONG sym_key_bits);

struct policy_private *policy_private_alloc(void)
{
    return calloc(1, sizeof(struct policy_private));
}

struct policy_private *policy_private_free(struct policy_private *pp)
{
    if (pp) {
        if (pp->allowedmechs)
            hashmap_free(pp->allowedmechs, NULL);
        if (pp->allowedcurves)
            free(pp->allowedcurves);
        free(pp);
    }
    return NULL;
}

void policy_private_deactivate(struct policy_private *pp)
{
    hashmap_free(pp->allowedmechs, NULL);
    /* Non-existing hash is universal. */
    pp->allowedmechs = NULL;
    free(pp->allowedcurves);
    pp->allowedcurves = NULL;
    pp->minstrengthidx = NUM_SUPPORTED_STRENGTHS;
    pp->numallowedcurves = -1;
    pp->allowedmgfs = ~0lu;
    pp->allowedvendormgfs = ~0lu;
    pp->allowedkdfs = ~0lu;
    pp->allowedvendorkdfs = ~0lu;
    pp->allowedprfs = ~0lu;
    pp->maxcurvesize = 521u;
}

static void policy_compute_strength(struct policy_private *pp,
                                    struct objstrength *s,
                                    CK_ULONG size, CK_ULONG ct)
{
    unsigned int i;

    if (ct == COMPARE_NOKEY || ct == COMPARE_PQC) {
        s->strength = 0;
    } else {
        for (i = 0; i < NUM_SUPPORTED_STRENGTHS; ++i) {
            if (pp->strengths[i].set == CK_TRUE &&
                size >= pp->strengths[i].strength.arr[ct]) {
                break;
            }
        }
        s->strength = i;
    }
}

static void policy_check_ec_allowed(struct policy_private *pp,
                                    struct objstrength *s,
                                    const CK_BYTE *oid, CK_ULONG oidlen)
{
    int i;

    if (pp->numallowedcurves >= 0) {
        s->allowed = CK_FALSE;
        for (i = 0; i < pp->numallowedcurves; ++i) {
            if (pp->allowedcurves[i]->data_size == oidlen &&
                memcmp(oid, pp->allowedcurves[i]->data, oidlen)) {
                s->allowed = CK_TRUE;
                break;
            }
        }
    } else {
        s->allowed = CK_TRUE;
    }
}

static CK_RV policy_get_curve_args(get_attr_val_f getattr, void *d,
                                   free_attr_f free_attr, CK_ULONG *size,
                                   const CK_BYTE **oid, CK_ULONG *oidlen)
{
    CK_ATTRIBUTE *ec_params = NULL;
    CK_RV rv;
    int i;

    rv = getattr(d, CKA_EC_PARAMS, &ec_params);
    if (rv == CKR_OK) {
        if (ec_params->pValue == NULL || ec_params->ulValueLen == 0) {
            TRACE_ERROR("Invalid CKA_EC_PARAMS value\n");
            rv = CKR_FUNCTION_FAILED;
            goto out;
        }

        rv = CKR_CURVE_NOT_SUPPORTED;
        for (i = 0; i < NUMEC; ++i) {
            if (der_ec_supported[i].data_size == ec_params->ulValueLen &&
                memcmp(ec_params->pValue, der_ec_supported[i].data,
                       ec_params->ulValueLen) == 0) {
                *size = der_ec_supported[i].prime_bits;
                *oid = der_ec_supported[i].data;
                *oidlen = der_ec_supported[i].data_size;
                rv = CKR_OK;
                break;
            }
        }
    }
 out:
    if (free_attr && ec_params)
        free_attr(d, ec_params);
    return rv;
}

static CK_RV policy_get_pqc_args(CK_KEY_TYPE key_type,
                                 get_attr_val_f getattr, void *d,
                                 free_attr_f free_attr, CK_ULONG *size,
                                 CK_ULONG *siglen, const CK_BYTE **oid,
                                 CK_ULONG *oidlen)
{
    CK_ATTRIBUTE_TYPE keyform_attr;
    CK_ATTRIBUTE_TYPE mode_attr;
    CK_ATTRIBUTE *keyform = NULL, *mode = NULL;
    const struct pqc_oid *oids, *pqc_oid = NULL;
    CK_RV rv;

    switch (key_type) {
    case CKK_IBM_PQC_DILITHIUM:
        keyform_attr = CKA_IBM_DILITHIUM_KEYFORM;
        mode_attr = CKA_IBM_DILITHIUM_MODE;
        oids = dilithium_oids;
        break;
    case CKK_IBM_PQC_KYBER:
        keyform_attr = CKA_IBM_KYBER_KEYFORM;
        mode_attr = CKA_IBM_KYBER_MODE;
        oids = kyber_oids;
        break;
    default:
        TRACE_ERROR("Unsupported key type 0x%lx\n", key_type);
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    rv = getattr(d, keyform_attr, &keyform);
    if (rv == CKR_OK && keyform->ulValueLen == sizeof(CK_ULONG)) {
        pqc_oid = find_pqc_by_keyform(oids, *(CK_ULONG *)keyform->pValue);
    } else {
        rv = getattr(d, mode_attr, &mode);
        if (rv == CKR_OK && mode->ulValueLen > 0)
            pqc_oid = find_pqc_by_oid(oids, mode->pValue, mode->ulValueLen);
    }
    if (pqc_oid == NULL) {
        TRACE_ERROR("Did not find KEYFORM or MODE for key type 0x%lx\n",
                     key_type);
        rv = CKR_TEMPLATE_INCOMPLETE;
        goto out;
    }

    *size = pqc_oid->policy_size;
    *siglen = pqc_oid->policy_siglen;
    *oid = pqc_oid->oid;
    *oidlen = pqc_oid->oid_len;

out:
    if (free_attr) {
        if (keyform)
            free_attr(d, keyform);
        if (mode)
            free_attr(d, mode);
    }

    return rv;
}

static CK_RV policy_extract_key_data(get_attr_val_f getattr, void *d,
                                     free_attr_f free_attr,
                                     CK_ULONG *comptarget, CK_ULONG *size,
                                     const CK_BYTE **oid, CK_ULONG *oidlen,
                                     CK_ULONG *siglen)
{
    CK_RV rv;
    CK_ATTRIBUTE *keytype = NULL, *keysize = NULL, *sigsize = NULL;

    *oid = NULL;
    *oidlen = 0;
    *size = 0;
    rv = getattr(d, CKA_KEY_TYPE, &keytype);
    if (rv != CKR_OK) {
        TRACE_INFO("Failed to retrieve key type.  rv=0x%lx\n", rv);
        *comptarget = COMPARE_NOKEY;
        *siglen = 0;
        return CKR_OK;
    }
    if (keytype->ulValueLen != sizeof(CK_ULONG)) {
        TRACE_ERROR("Wrong type for key type!\n");
        rv = CKR_FUNCTION_FAILED;
        goto out;
    }
    switch (*(CK_ULONG *)keytype->pValue) {
    case CKK_RSA:
        rv = getattr(d, CKA_MODULUS, &keysize);
        if (rv != CKR_OK) {
            TRACE_ERROR("Did not find CKA_MODULUS for RSA key!\n");
            goto out;
        }
        *size = keysize->ulValueLen * 8;
        *siglen = *size;
        *comptarget = COMPARE_MODEXP;
        break;
    case CKK_DSA:
        rv = getattr(d, CKA_SUBPRIME, &sigsize);
        if (rv != CKR_OK) {
            TRACE_ERROR("Did not find CKA_SUBPRIME for DSA key\n");
            goto out;
        }
        *siglen = sigsize->ulValueLen * 8 * 2;
        /* Fallthrough */
    case CKK_DH:
        /* Fallthrough */
    case CKK_X9_42_DH:
        rv = getattr(d, CKA_PRIME, &keysize);
        if (rv != CKR_OK) {
            TRACE_ERROR("Did not find CKA_PRIME for key type 0x%lx\n",
                        *(CK_ULONG *)keytype->pValue);
            return rv;
        }
        *size = keysize->ulValueLen * 8;
        *comptarget = COMPARE_MODEXP;
        break;
    case CKK_EC:
        rv = policy_get_curve_args(getattr, d, free_attr, size, oid, oidlen);
        *siglen = *size * 2;
        *comptarget = COMPARE_ECC;
        break;
    case CKK_DES:
        *size = 56;
        *siglen = 64;
        *comptarget = COMPARE_SYMMETRIC;
        break;
    case CKK_DES2:
        *size = 80;
        *siglen = 64;
        *comptarget = COMPARE_SYMMETRIC;
        break;
    case CKK_DES3:
        *size = 112;
        *siglen = 64;
        *comptarget = COMPARE_SYMMETRIC;
        break;
    case CKK_AES_XTS:
        /* Fallthrough */
    case CKK_AES:
        if (*(CK_ULONG *)keytype->pValue == CKK_AES)
            *siglen = 128;
        /* Fallthrough */
    case CKK_GENERIC_SECRET:
    case CKK_SHA_1_HMAC:
    case CKK_SHA224_HMAC:
    case CKK_SHA256_HMAC:
    case CKK_SHA384_HMAC:
    case CKK_SHA512_HMAC:
    case CKK_SHA3_224_HMAC:
    case CKK_SHA3_256_HMAC:
    case CKK_SHA3_384_HMAC:
    case CKK_SHA3_512_HMAC:
    case CKK_SHA512_224_HMAC:
    case CKK_SHA512_256_HMAC:
        rv = getattr(d, CKA_VALUE_LEN, &keysize);
        if (rv != CKR_OK) {
            TRACE_ERROR("Did not find CKA_PRIME for key type 0x%lx\n",
                        *(CK_ULONG *)keytype->pValue);
            goto out;
        }
        if (keysize->ulValueLen != sizeof(CK_ULONG)) {
            TRACE_ERROR("Unexpected type for CKA_VALUE_LEN\n");
            rv = CKR_FUNCTION_FAILED;
            goto out;
        }
        *size = (*(CK_ULONG*)keysize->pValue) * 8;
        if (*(CK_ULONG *)keytype->pValue == CKK_AES_XTS)
            *size /= 2;
        *comptarget = COMPARE_SYMMETRIC;
        break;
    case CKK_IBM_PQC_DILITHIUM:
    case CKK_IBM_PQC_KYBER:
        rv = policy_get_pqc_args(*(CK_ULONG *)keytype->pValue, getattr, d,
                                 free_attr, size, siglen, oid, oidlen);
        *comptarget = COMPARE_PQC;
        break;
        /* POLICY: New CKK */
    default:
        TRACE_ERROR("Strength determination not implemented for key type 0x%lx\n",
                    *(CK_ULONG *)keytype->pValue);
        rv = CKR_FUNCTION_FAILED;
    }
 out:
    if (free_attr) {
        if (keytype)
            free_attr(d, keytype);
        if (keysize)
            free_attr(d, keysize);
        if (sigsize)
            free_attr(d, sigsize);
    }
    return rv;
}

static CK_RV policy_get_digest_size(CK_MECHANISM_TYPE mech, CK_ULONG *hsize)
{
    CK_RV rv = CKR_OK;

    if (mech == CKM_MD2 || mech == CKM_MD5) {
        *hsize = 128;
        /* POLICY: New CKM digest */
    } else {
        rv = get_sha_size(mech, hsize);    
        if (rv == CKR_OK)
            *hsize *= 8;
    }
    return rv;
}

static CK_RV policy_get_sig_size(CK_MECHANISM_PTR mech, struct objstrength *s,
                                 CK_ULONG *ssize)
{
    const struct mechrow *col = mechrow_from_numeric(mech->mechanism);
    CK_ULONG size;

    if (!col || !s)
        return CKR_FUNCTION_FAILED;
    if (col->flags & MCF_MAC_GENERAL) {
        if (mech->ulParameterLen != sizeof(CK_MAC_GENERAL_PARAMS) ||
            mech->pParameter == NULL) {
            TRACE_ERROR("Invalid mechanism parameter\n");
            return CKR_MECHANISM_PARAM_INVALID;
        }
        size = *(CK_MAC_GENERAL_PARAMS *)mech->pParameter;
        if (size > col->outputsize)
            size = col->outputsize;
        *ssize = size * 8;
        return CKR_OK;
    }
    if (col->outputsize == MC_KEY_DEPENDENT) {
        switch (mech->mechanism) {
            /* POLICY: New CKM Sign/Verify */
        case CKM_IBM_CMAC:
            /* Fallthrough */
        case CKM_DSA:
            /* Fallthrough */
        case CKM_ECDSA:
            /* Fallthrough */
        case CKM_RSA_PKCS:
            /* Fallthrough */
        case CKM_RSA_PKCS_PSS:
            /* Fallthrough */
        case CKM_RSA_X_509:
            /* Fallthrough */
        case CKM_RSA_X9_31:
            /* Fallthrough */
        case CKM_IBM_ED448_SHA3:
            /* Fallthrough */
        case CKM_IBM_DILITHIUM:
            *ssize = s->siglen;
            break;
        case CKM_DSA_SHA1:
            /* Fallthrough */
        case CKM_ECDSA_SHA1:
            /* Fallthrough */
        case CKM_SHA1_RSA_PKCS:
            /* Fallthrough */
        case CKM_SHA1_RSA_PKCS_PSS:
            /* Fallthrough */
        case CKM_SHA1_RSA_X9_31:
            *ssize = MIN(s->siglen, 160);
            break;
        case CKM_MD5_RSA_PKCS:
            *ssize = MIN(s->siglen, 128);
            break;
        case CKM_ECDSA_SHA224:
            /* Fallthrough */
        case CKM_ECDSA_SHA3_224:
            /* Fallthrough */
        case CKM_SHA224_RSA_PKCS:
            /* Fallthrough */
        case CKM_SHA224_RSA_PKCS_PSS:
            /* Fallthrough */
        case CKM_SHA3_224_RSA_PKCS:
            /* Fallthrough */
        case CKM_SHA3_224_RSA_PKCS_PSS:
            *ssize = MIN(s->siglen, 224);
            break;
        case CKM_ECDSA_SHA256:
            /* Fallthrough */
        case CKM_ECDSA_SHA3_256:
            /* Fallthrough */
        case CKM_SHA256_RSA_PKCS:
            /* Fallthrough */
        case CKM_SHA256_RSA_PKCS_PSS:
            /* Fallthrough */
        case CKM_SHA3_256_RSA_PKCS:
            /* Fallthrough */
        case CKM_SHA3_256_RSA_PKCS_PSS:
            *ssize = MIN(s->siglen, 256);
            break;
        case CKM_ECDSA_SHA384:
            /* Fallthrough */
        case CKM_ECDSA_SHA3_384:
            /* Fallthrough */
        case CKM_SHA384_RSA_PKCS:
            /* Fallthrough */
        case CKM_SHA384_RSA_PKCS_PSS:
            /* Fallthrough */
        case CKM_SHA3_384_RSA_PKCS:
            /* Fallthrough */
        case CKM_SHA3_384_RSA_PKCS_PSS:
            *ssize = MIN(s->siglen, 384);
            break;
        case CKM_ECDSA_SHA512:
            /* Fallthrough */
        case CKM_ECDSA_SHA3_512:
            /* Fallthrough */
        case CKM_SHA512_RSA_PKCS:
            /* Fallthrough */
        case CKM_SHA512_RSA_PKCS_PSS:
            /* Fallthrough */
        case CKM_SHA3_512_RSA_PKCS:
            /* Fallthrough */
        case CKM_SHA3_512_RSA_PKCS_PSS:
            /* Fallthrough */
        case CKM_IBM_ED25519_SHA512:
            *ssize = MIN(s->siglen, 512);
            break;
        case CKM_IBM_ECDSA_OTHER:
            if (mech->ulParameterLen != sizeof(CK_IBM_ECDSA_OTHER_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("Invalid mechanism parameter\n");
                return CKR_MECHANISM_PARAM_INVALID;
            }
            switch (((CK_IBM_ECDSA_OTHER_PARAMS *)
                                            mech->pParameter)->submechanism) {
            case CKM_IBM_ECSDSA_RAND:
            case CKM_IBM_ECSDSA_COMPR_MULTI:
                *ssize = MIN(s->siglen, 256); /* Uses SHA-256 internally */
                break;
            default:
                return CKR_FUNCTION_FAILED;
            }
            break;
        default:
            return CKR_FUNCTION_FAILED;
        }
        return CKR_OK;
    }
    if (col->outputsize == MC_INFORMATION_UNAVAILABLE)
        return CKR_FUNCTION_FAILED;
    *ssize = col->outputsize * 8;
    return CKR_OK;
}

static inline CK_RV policy_is_mgf_allowed(struct policy_private *pp,
                                          CK_RSA_PKCS_MGF_TYPE mgf)
{
    if (mgf > CKG_VENDOR_DEFINED) {
        if ((mgf - CKG_VENDOR_DEFINED - 1) <= 31 &&
            (pp->allowedvendormgfs & (1u << (mgf - CKG_VENDOR_DEFINED - 1))))
            return CKR_OK;
    } else {
        if (mgf <= 31 && (pp->allowedmgfs & (1u << mgf)))
            return CKR_OK;
    }
    TRACE_WARNING("POLICY VIOLATION: mgf not allowed: 0x%lx\n", mgf);
    return CKR_FUNCTION_FAILED;
}

static inline CK_RV policy_is_kdf_allowed(struct policy_private *pp,
                                          CK_ULONG kdf)
{
    if (kdf > CKD_VENDOR_DEFINED) {
        if ((kdf - CKD_VENDOR_DEFINED - 1) <= 31 &&
            (pp->allowedvendorkdfs & (1u << (kdf - CKD_VENDOR_DEFINED - 1))))
            return CKR_OK;
    } else {
        if (kdf <= 31 && (pp->allowedkdfs & (1u << kdf)))
            return CKR_OK;
    }
    TRACE_WARNING("POLICY VIOLATION: kdf not allowed: 0x%lx\n", kdf);
    return CKR_FUNCTION_FAILED;
}

static inline CK_RV policy_is_prf_allowed(struct policy_private *pp,
                                          CK_ULONG val)
{
    if (pp->allowedprfs & (1u << val))
        return CKR_OK;
    TRACE_WARNING("POLICY VIOLATION: prf not allowed: 0x%lx\n", val);
    return CKR_FUNCTION_FAILED;
}

static CK_RV policy_is_key_allowed_i(struct policy_private *pp,
                                     struct objstrength *s)
{
    /* 1. Check strength */
    if (s->strength > pp->minstrengthidx) {
        TRACE_WARNING("POLICY VIOLATION: Key does not satisfy minimal strength constraint\n");
        return CKR_FUNCTION_FAILED;
    }
    /* 2. EC check */
    if (!s->allowed) {
        TRACE_WARNING("POLICY VIOLATION: Key belongs to a forbidden EC curve\n");
        return CKR_FUNCTION_FAILED;
    }
    return CKR_OK;
}

static CK_RV policy_update_modexp(struct policy_private *pp,
                                         CK_MECHANISM_INFO_PTR info)
{
    CK_ULONG minsize;

    if (pp->minstrengthidx < NUM_SUPPORTED_STRENGTHS &&
        pp->strengths[pp->minstrengthidx].set) {
        minsize = pp->strengths[pp->minstrengthidx].strength.details.modexp;
        if (minsize > info->ulMaxKeySize)
            return CKR_MECHANISM_INVALID;
        if (minsize > info->ulMinKeySize)
            info->ulMinKeySize = minsize;
    }
    return CKR_OK;
}

static CK_RV policy_update_symmetric(struct policy_private *pp,
                                     CK_MECHANISM_INFO_PTR info,
                                     CK_BBOOL isbytes, CK_BBOOL isaesxts)
{
    CK_ULONG minsize;

    if (pp->minstrengthidx < NUM_SUPPORTED_STRENGTHS &&
        pp->strengths[pp->minstrengthidx].set) {
        minsize = pp->strengths[pp->minstrengthidx].strength.details.symmetric;
        if (isbytes == CK_TRUE)
            minsize /= 8;
        if (isaesxts == CK_TRUE)
            minsize *= 2;
        if (minsize > info->ulMaxKeySize)
            return CKR_MECHANISM_INVALID;
        if (minsize > info->ulMinKeySize)
            info->ulMinKeySize = minsize;
    }
    return CKR_OK;
}

static CK_RV policy_update_ec(struct policy_private *pp,
                              CK_MECHANISM_INFO_PTR info)
{
    CK_ULONG minsize;

    if (pp->numallowedcurves == 0)
        /* We do not have any allowed curves */
        return CKR_MECHANISM_INVALID;
    if (pp->minstrengthidx < NUM_SUPPORTED_STRENGTHS &&
        pp->strengths[pp->minstrengthidx].set) {
        minsize = pp->strengths[pp->minstrengthidx].strength.details.ecc;
        if (minsize > info->ulMaxKeySize)
            return CKR_MECHANISM_INVALID;
        if (minsize > info->ulMinKeySize)
            info->ulMinKeySize = minsize;
    }
    return CKR_OK;
}

static CK_RV policy_update_digest(struct policy_private *pp,
                                  CK_MECHANISM_TYPE mech)
{
    CK_ULONG digestsize;

    if (pp->minstrengthidx < NUM_SUPPORTED_STRENGTHS &&
        pp->strengths[pp->minstrengthidx].set) {
        if (policy_get_digest_size(mech, &digestsize) != CKR_OK)
            /* Policy would reject this unknown mechanism */
            return CKR_MECHANISM_INVALID;
        if (digestsize < pp->strengths[pp->minstrengthidx].strength.details.digests)
            return CKR_MECHANISM_INVALID;
    }
    return CKR_OK;
}

static CK_RV policy_check_signature_size(struct policy_private *pp,
                                         CK_MECHANISM_TYPE mech,
                                         CK_MECHANISM_INFO_PTR info)
{
    CK_ULONG minsiglen;
    CK_ULONG siglen = 0;
    CK_MECHANISM testmech;
    struct objstrength s;
    CK_MAC_GENERAL_PARAMS params = 0;

    if (info->flags &
        (CKF_SIGN | CKF_SIGN_RECOVER | CKF_VERIFY | CKF_VERIFY_RECOVER)) {
        testmech.mechanism = mech;
        testmech.pParameter = &params;
        testmech.ulParameterLen = sizeof(params);
        if (pp->minstrengthidx < NUM_SUPPORTED_STRENGTHS &&
            pp->strengths[pp->minstrengthidx].set) {
            minsiglen =
                pp->strengths[pp->minstrengthidx].strength.details.signatures;
            switch (mech) {
                /* POLICY: New CKM Sign/Verify */
            case CKM_RSA_PKCS:
                /* Fallthrough */
            case CKM_RSA_PKCS_PSS:
                /* Fallthrough */
            case CKM_RSA_X_509:
                /* Fallthrough */
            case CKM_RSA_X9_31:
                /* Fallthrough */
            case CKM_SHA1_RSA_PKCS:
                /* Fallthrough */
            case CKM_SHA224_RSA_PKCS:
                /* Fallthrough */
            case CKM_SHA256_RSA_PKCS:
                /* Fallthrough */
            case CKM_SHA384_RSA_PKCS:
                /* Fallthrough */
            case CKM_SHA512_RSA_PKCS:
                /* Fallthrough */
            case CKM_SHA3_224_RSA_PKCS:
                /* Fallthrough */
            case CKM_SHA3_256_RSA_PKCS:
                /* Fallthrough */
            case CKM_SHA3_384_RSA_PKCS:
                /* Fallthrough */
            case CKM_SHA3_512_RSA_PKCS:
                /* Fallthrough */
            case CKM_SHA1_RSA_PKCS_PSS:
                /* Fallthrough */
            case CKM_SHA224_RSA_PKCS_PSS:
                /* Fallthrough */
            case CKM_SHA256_RSA_PKCS_PSS:
                /* Fallthrough */
            case CKM_SHA384_RSA_PKCS_PSS:
                /* Fallthrough */
            case CKM_SHA512_RSA_PKCS_PSS:
                /* Fallthrough */
            case CKM_SHA3_224_RSA_PKCS_PSS:
                /* Fallthrough */
            case CKM_SHA3_256_RSA_PKCS_PSS:
                /* Fallthrough */
            case CKM_SHA3_384_RSA_PKCS_PSS:
                /* Fallthrough */
            case CKM_SHA3_512_RSA_PKCS_PSS:
                /* Fallthrough */
            case CKM_SHA1_RSA_X9_31:
                siglen = info->ulMaxKeySize;
                break;
            case CKM_DSA:
                /* Fallthrough */
            case CKM_DSA_SHA1:
                /* Max size of CKA_SUBPRIME is 256 bits, so this is the biggest
                 * signature we can create with a DSA key. */
                siglen = 2u * 256u;
                break;
            case CKM_ECDSA:
                /* Fallthrough */
            case CKM_ECDSA_SHA1:
                /* Fallthrough */
            case CKM_ECDSA_SHA224:
                /* Fallthrough */
            case CKM_ECDSA_SHA256:
                /* Fallthrough */
            case CKM_ECDSA_SHA384:
                /* Fallthrough */
            case CKM_ECDSA_SHA512:
                /* Fallthrough */
            case CKM_ECDSA_SHA3_224:
                /* Fallthrough */
            case CKM_ECDSA_SHA3_256:
                /* Fallthrough */
            case CKM_ECDSA_SHA3_384:
                /* Fallthrough */
            case CKM_ECDSA_SHA3_512:
                /* Fallthrough */
            case CKM_IBM_ECDSA_OTHER:
                if (pp->numallowedcurves == 0) {
                    /* No curve allowed */
                    return CKR_MECHANISM_INVALID;
                }
                siglen = 2u * pp->maxcurvesize;
                break;
            case CKM_AES_CMAC_GENERAL:
                /* Fallthrough */
            case CKM_AES_MAC_GENERAL:
                params = 128 / 8;
                break;
            case CKM_DES3_CMAC_GENERAL:
                /* Fallthrough */
            case CKM_DES3_MAC_GENERAL:
                params = 64 / 8;
                break;
            case CKM_MD5_HMAC_GENERAL:
                params = 128 / 8;
                break;
            case CKM_SHA_1_HMAC_GENERAL:
                params = 160 / 8;
                break;
            case CKM_SHA512_224_HMAC_GENERAL:
                /* Fallthrough */
            case CKM_SHA224_HMAC_GENERAL:
                /* Fallthrough */
            case CKM_SHA3_224_HMAC_GENERAL:
                params = 224 / 8;
                break;
            case CKM_SHA512_256_HMAC_GENERAL:
                /* Fallthrough */
            case CKM_SHA256_HMAC_GENERAL:
                /* Fallthrough */
            case CKM_SHA3_256_HMAC_GENERAL:
                params = 256 / 8;
                break;
            case CKM_SHA384_HMAC_GENERAL:
                /* Fallthrough */
            case CKM_SHA3_384_HMAC_GENERAL:
                params = 384 / 8;
                break;
            case CKM_SHA512_HMAC_GENERAL:
                /* Fallthrough */
            case CKM_SHA3_512_HMAC_GENERAL:
                params = 512 / 8;
                break;
            case CKM_SSL3_MD5_MAC:
                /* Fallthrough */
            case CKM_SSL3_SHA1_MAC:
                params = 8;
                break;
            case CKM_IBM_DILITHIUM:
                siglen = 256;
                break;
            default:
                break;
            }
            s.siglen = siglen;
            if (policy_get_sig_size(&testmech, &s, &siglen) != CKR_OK)
                return CKR_MECHANISM_INVALID;
            if (siglen < minsiglen)
                return CKR_MECHANISM_INVALID;
        }
    }
    return CKR_OK;
}

/* main functions (exported via function pointers) */

static CK_RV policy_is_key_allowed(policy_t p, struct objstrength *s,
                                   SESSION *sess)
{
    struct policy_private *pp = p->priv;
    CK_RV rv = CKR_OK;

    if (pp) {
        rv = policy_is_key_allowed_i(pp, s);
        if (rv != CKR_OK && sess)
            sess->session_info.ulDeviceError = CKR_POLICY_VIOLATION;
    }
    return rv;
}

static CK_RV policy_store_object_strength(policy_t p, struct objstrength *s,
                                          get_attr_val_f getattr, void *d,
                                          free_attr_f free_attr, SESSION *sess)
{
    struct policy_private *pp = p->priv;
    /* silence maybe uninitialized warning for ct and siglen */
    CK_ULONG ct = 0, size, oidlen, siglen = 0;
    const CK_BYTE *oid;
    CK_RV rv = CKR_OK;

    if (pp) {
        rv = policy_extract_key_data(getattr, d, free_attr, &ct, &size,
                                     &oid, &oidlen, &siglen);
        if (rv == CKR_OK) {
            s->siglen = siglen;
            policy_compute_strength(pp, s, size, ct);
            if (ct == COMPARE_ECC)
                policy_check_ec_allowed(pp, s, oid, oidlen);
            else
                s->allowed = CK_TRUE;
            rv = policy_is_key_allowed_i(pp, s);
            if (rv != CKR_OK) {
                switch (ct) {
                case COMPARE_MODEXP:
                    TRACE_ERROR("POLICY: Modular exponentiation compare size %lu too small!\n",
                                size);
                    break;
                case COMPARE_ECC:
                    if (s->allowed)
                        TRACE_ERROR("POLICY: ECC curve size %lu too small!\n",
                                    size);
                    else
                        TRACE_ERROR("POLICY: ECC curve not allowed!\n");
                    break;
                case COMPARE_SYMMETRIC:
                    TRACE_ERROR("POLICY: Symmetric key compare size %lu too small!\n",
                                size);
                    break;
                case COMPARE_PQC:
                    TRACE_ERROR("POLICY: PQ key not allowed!\n");
                    break;
                case COMPARE_NOKEY:
                    TRACE_ERROR("POLICY: non-key object not allowed!\n");
                    break;
                default:
                    TRACE_ERROR("POLICY: Invalid compare target %lu!\n", ct);
                    break;
                }
            }
        } else {
            TRACE_ERROR("POLICY: Failed to extract key data.\n");
            s->strength = POLICY_STRENGTH_IDX_0;
            s->siglen = 0;
            s->allowed = CK_FALSE;
        }
        if (rv != CKR_OK && sess)
            sess->session_info.ulDeviceError = CKR_POLICY_VIOLATION;
    } else {
        s->strength = POLICY_STRENGTH_IDX_0;
        s->siglen = 0;
        s->allowed = CK_TRUE;
    }
    return rv;
}

static CK_RV policy_is_mech_allowed(policy_t p, CK_MECHANISM_PTR mech,
                                    struct objstrength *s, int check,
                                    SESSION *sess)
{
    struct policy_private *pp = p->priv;
    struct objstrength tmp_strength = { 0, 0, CK_TRUE };
    CK_RSA_PKCS_OAEP_PARAMS *oaep_params;
    CK_ULONG size;
    CK_RV rv = CKR_OK;

    if (pp) {
        if (s && policy_is_key_allowed_i(pp, s) != CKR_OK) {
            rv = CKR_FUNCTION_FAILED;
            goto out;
        }
        if (hashmap_find(pp->allowedmechs, mech->mechanism, NULL) == 0) {
            TRACE_WARNING("Mechanism 0x%lx not allowed by policy\n",
                          mech->mechanism);
            rv = CKR_FUNCTION_FAILED;
            goto out;
        }
        if (check == POLICY_CHECK_DIGEST) {
            if (policy_get_digest_size(mech->mechanism, &size) != CKR_OK) {
                TRACE_WARNING("POLICY ERROR: Failed to retrieve digest size.\n");
                rv = CKR_FUNCTION_FAILED;
                goto out;
            }
            if (pp->minstrengthidx < NUM_SUPPORTED_STRENGTHS &&
                size <
                pp->strengths[pp->minstrengthidx].strength.details.digests) {
                TRACE_WARNING("Digest output too small for policy.\n");
                rv = CKR_FUNCTION_FAILED;
                goto out;
            }
        } else if (check == POLICY_CHECK_SIGNATURE ||
                check == POLICY_CHECK_VERIFY) {
            if (policy_get_sig_size(mech, s, &size) != CKR_OK) {
                TRACE_WARNING("POLICY ERROR: Failed to retrieve signature size.\n");
                rv = CKR_FUNCTION_FAILED;
                goto out;
            }
            if (pp->minstrengthidx < NUM_SUPPORTED_STRENGTHS &&
                size <
                pp->strengths[pp->minstrengthidx].strength.details.signatures) {
                TRACE_WARNING("Signature too small for policy.\n");
                rv = CKR_FUNCTION_FAILED;
                goto out;
            }
        }
        switch (mech->mechanism) {
            /* POLICY: New CKM Deep Check */
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
            if (mech->ulParameterLen != sizeof(CK_RSA_PKCS_PSS_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("Invalid mechanism parameter\n");
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }
            if (hashmap_find(pp->allowedmechs,
                             ((CK_RSA_PKCS_PSS_PARAMS *)mech->pParameter)->hashAlg, NULL) == 0) {
                TRACE_WARNING("POLICY VIOLATION: PSS hash algorithm not allowed by policy.\n");
                rv = CKR_FUNCTION_FAILED;
            } else if (policy_is_mgf_allowed(pp,
                        ((CK_RSA_PKCS_PSS_PARAMS *)mech->pParameter)->mgf) != CKR_OK) {
                rv = CKR_FUNCTION_FAILED;
            }
            break;
        case CKM_RSA_PKCS_OAEP:
            if (mech->ulParameterLen != sizeof(CK_RSA_PKCS_OAEP_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("Invalid mechanism parameter\n");
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }
            if (hashmap_find(pp->allowedmechs,
                             ((CK_RSA_PKCS_OAEP_PARAMS *)mech->pParameter)->hashAlg, NULL) == 0) {
                TRACE_WARNING("POLICY VIOLATION: OAEP hash algorithm not allowed by policy.\n");
                rv = CKR_FUNCTION_FAILED;
            } else if (policy_is_mgf_allowed(pp,
                        ((CK_RSA_PKCS_OAEP_PARAMS *)mech->pParameter)->mgf) != CKR_OK) {
                rv = CKR_FUNCTION_FAILED;
            }
            break;
        case CKM_ECDH1_DERIVE:
            if (mech->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("Invalid mechanism parameter\n");
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }
            if (policy_is_kdf_allowed(pp,
                                      ((CK_ECDH1_DERIVE_PARAMS *)mech->pParameter)->kdf) != CKR_OK)
                rv = CKR_FUNCTION_FAILED;
            break;
        case CKM_IBM_ECDSA_OTHER:
            if (mech->ulParameterLen != sizeof(CK_IBM_ECDSA_OTHER_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("Invalid mechanism parameter\n");
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }
            switch (((CK_IBM_ECDSA_OTHER_PARAMS *) mech->pParameter)->submechanism) {
            case CKM_IBM_ECSDSA_RAND:
            case CKM_IBM_ECSDSA_COMPR_MULTI:
                /* Uses SHA-256 internally */
                if (hashmap_find(pp->allowedmechs, CKM_SHA256, NULL) == 0) {
                    TRACE_WARNING("POLICY VIOLATION: ECDSA OTHER SHA-256 algorithm not allowed by policy.\n");
                    rv = CKR_FUNCTION_FAILED;
                }
                break;
            default:
                rv = CKR_FUNCTION_FAILED;
                break;
            }
            break;
        case CKM_IBM_BTC_DERIVE:
            if (mech->ulParameterLen != sizeof(CK_IBM_BTC_DERIVE_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("Invalid mechanism parameter\n");
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }
            if (((CK_IBM_BTC_DERIVE_PARAMS *)mech->pParameter)->version !=
                                    CK_IBM_BTC_DERIVE_PARAMS_VERSION_1)
                break;
            switch (((CK_IBM_BTC_DERIVE_PARAMS *)mech->pParameter)->type) {
            case CK_IBM_BTC_BIP0032_PRV2PRV:
            case CK_IBM_BTC_BIP0032_PRV2PUB:
            case CK_IBM_BTC_BIP0032_PUB2PUB:
            case CK_IBM_BTC_BIP0032_MASTERK:
            case CK_IBM_BTC_SLIP0010_PRV2PRV:
            case CK_IBM_BTC_SLIP0010_PRV2PUB:
            case CK_IBM_BTC_SLIP0010_PUB2PUB:
            case CK_IBM_BTC_SLIP0010_MASTERK:
                /* Uses SHA-512 internally */
                if (hashmap_find(pp->allowedmechs, CKM_SHA512_HMAC, NULL) == 0) {
                    TRACE_WARNING("POLICY VIOLATION: BTC SHA-512-HMAC algorithm not allowed by policy.\n");
                    rv = CKR_FUNCTION_FAILED;
                }
                break;
            default:
                rv = CKR_FUNCTION_FAILED;
                break;
            }
            break;
        case CKM_IBM_KYBER:
            /* Only KEM uses a parameter, KeyGen, Encrypt/Decrypt don't */
            if (mech->ulParameterLen != sizeof(CK_IBM_KYBER_PARAMS) &&
                mech->ulParameterLen != 0) {
                TRACE_ERROR("Invalid mechanism parameter\n");
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }
            if (mech->ulParameterLen != sizeof(CK_IBM_KYBER_PARAMS))
                break;
            if (mech->pParameter == NULL) {
                TRACE_ERROR("Invalid mechanism parameter\n");
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }
            if (policy_is_kdf_allowed(pp,
                                      ((CK_IBM_KYBER_PARAMS *)mech->pParameter)->kdf) != CKR_OK) {
                rv = CKR_FUNCTION_FAILED;
                break;
            }
            break;
        case CKM_RSA_AES_KEY_WRAP:
            if (mech->ulParameterLen != sizeof(CK_RSA_AES_KEY_WRAP_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("Invalid mechanism parameter\n");
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }
            oaep_params =
                ((CK_RSA_AES_KEY_WRAP_PARAMS *)mech->pParameter)->pOAEPParams;
            if (oaep_params == NULL) {
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }
            if (hashmap_find(pp->allowedmechs, oaep_params->hashAlg, NULL) == 0) {
                TRACE_WARNING("POLICY VIOLATION: OAEP hash algorithm not allowed by policy.\n");
                rv = CKR_FUNCTION_FAILED;
                break;
            } else if (policy_is_mgf_allowed(pp, oaep_params->mgf) != CKR_OK) {
                rv = CKR_FUNCTION_FAILED;
                break;
            }
            if (((CK_RSA_AES_KEY_WRAP_PARAMS *)
                                         mech->pParameter)->ulAESKeyBits > 0) {
                tmp_strength.strength = policy_get_sym_key_strength(p,
                                    ((CK_RSA_AES_KEY_WRAP_PARAMS *)
                                            mech->pParameter)->ulAESKeyBits);
                rv = policy_is_key_allowed(p, &tmp_strength, sess);
                if (rv != CKR_OK)
                    break;
            }
            break;
        case CKM_ECDH_AES_KEY_WRAP:
            if (mech->ulParameterLen != sizeof(CK_ECDH_AES_KEY_WRAP_PARAMS) ||
                mech->pParameter == NULL) {
                TRACE_ERROR("Invalid mechanism parameter\n");
                rv = CKR_MECHANISM_PARAM_INVALID;
                break;
            }
            if (policy_is_kdf_allowed(pp,
                                      ((CK_ECDH_AES_KEY_WRAP_PARAMS *)
                                           mech->pParameter)->kdf) != CKR_OK) {
                rv = CKR_FUNCTION_FAILED;
                break;
            }
            if (((CK_ECDH_AES_KEY_WRAP_PARAMS *)
                                        mech->pParameter)->ulAESKeyBits > 0) {
                tmp_strength.strength = policy_get_sym_key_strength(p,
                                    ((CK_ECDH_AES_KEY_WRAP_PARAMS *)
                                            mech->pParameter)->ulAESKeyBits);
                rv = policy_is_key_allowed(p, &tmp_strength, sess);
                if (rv != CKR_OK)
                    break;
            }
            break;
        default:
            break;
        }
    }
 out:
    if (rv != CKR_OK && sess)
        sess->session_info.ulDeviceError = CKR_POLICY_VIOLATION;
    return rv;
}

static CK_RV policy_update_mech_info(policy_t p, CK_MECHANISM_TYPE mech,
                                     CK_MECHANISM_INFO_PTR info)
{
    struct policy_private *pp = p->priv;
    /* Silence spurious maybe-uninitialized warning. */
    struct objstrength tmp = { 0, 0, CK_TRUE };
    const struct mechrow *row;
    CK_BBOOL isaesxts = CK_FALSE;

    if (pp) {
        if (hashmap_find(pp->allowedmechs, mech, NULL) == 0)
            return CKR_MECHANISM_INVALID;
        switch (mech) {
            /* POLICY: New CKM */
        case CKM_AES_CBC:
        case CKM_AES_CBC_PAD:
        case CKM_AES_CFB128:
        case CKM_AES_CFB64:
        case CKM_AES_CFB8:
        case CKM_AES_CMAC:
        case CKM_AES_CMAC_GENERAL:
        case CKM_AES_CTR:
        case CKM_AES_ECB:
        case CKM_AES_GCM:
        case CKM_AES_XTS:
        case CKM_AES_KEY_GEN:
        case CKM_AES_XTS_KEY_GEN:
        case CKM_AES_MAC:
        case CKM_AES_MAC_GENERAL:
        case CKM_AES_OFB:
        case CKM_AES_KEY_WRAP:
        case CKM_AES_KEY_WRAP_PAD:
        case CKM_AES_KEY_WRAP_KWP:
        case CKM_AES_KEY_WRAP_PKCS7:
        case CKM_IBM_CMAC:
        case CKM_SHA1_KEY_DERIVATION:
        case CKM_SHA224_KEY_DERIVATION:
        case CKM_SHA256_KEY_DERIVATION:
        case CKM_SHA384_KEY_DERIVATION:
        case CKM_SHA512_KEY_DERIVATION:
        case CKM_SHA512_224_KEY_DERIVATION:
        case CKM_SHA512_256_KEY_DERIVATION:
        case CKM_SHA3_224_KEY_DERIVATION:
        case CKM_SHA3_256_KEY_DERIVATION:
        case CKM_SHA3_384_KEY_DERIVATION:
        case CKM_SHA3_512_KEY_DERIVATION:
        case CKM_SHAKE_128_KEY_DERIVATION:
        case CKM_SHAKE_256_KEY_DERIVATION:
        case CKM_SSL3_MASTER_KEY_DERIVE:
        case CKM_SSL3_PRE_MASTER_KEY_GEN:
        case CKM_TLS_PRE_MASTER_KEY_GEN:
            isaesxts = (mech == CKM_AES_XTS_KEY_GEN || mech == CKM_AES_XTS);
            if (policy_update_symmetric(pp, info, CK_TRUE,
                                        isaesxts) != CKR_OK) {
                row = mechrow_from_numeric(mech);
                TRACE_DEVEL("Mechanism %s (0x%lx) blocked by policy!\n",
                            row ? row->string : "UNKNOWN", mech);
                return CKR_MECHANISM_INVALID;
            }
            break;
        case CKM_DES_KEY_GEN:
        case CKM_DES_CBC:
        case CKM_DES_CBC_PAD:
        case CKM_DES_CFB64:
        case CKM_DES_CFB8:
        case CKM_DES_ECB:
        case CKM_DES_OFB64:
            policy_compute_strength(pp, &tmp, 56, COMPARE_SYMMETRIC);
            if (policy_is_key_allowed_i(pp, &tmp) != CKR_OK)
                return CKR_MECHANISM_INVALID;
            break;
        case CKM_DES2_KEY_GEN:
            policy_compute_strength(pp, &tmp, 80, COMPARE_SYMMETRIC);
            if (policy_is_key_allowed_i(pp, &tmp) != CKR_OK)
                return CKR_MECHANISM_INVALID;
            break;
        case CKM_DES3_KEY_GEN:
        case CKM_DES3_CBC:
        case CKM_DES3_CBC_PAD:
        case CKM_DES3_CMAC:
        case CKM_DES3_CMAC_GENERAL:
        case CKM_DES3_ECB:
        case CKM_DES3_MAC:
        case CKM_DES3_MAC_GENERAL:
            policy_compute_strength(pp, &tmp, 112, COMPARE_SYMMETRIC);
            if (policy_is_key_allowed_i(pp, &tmp) != CKR_OK)
                return CKR_MECHANISM_INVALID;
            break;
        case CKM_DH_PKCS_DERIVE:
        case CKM_DH_PKCS_KEY_PAIR_GEN:
        case CKM_DH_PKCS_PARAMETER_GEN:
        case CKM_DSA:
        case CKM_DSA_KEY_PAIR_GEN:
        case CKM_DSA_PARAMETER_GEN:
        case CKM_DSA_SHA1:
        case CKM_MD5_RSA_PKCS:
        case CKM_RSA_PKCS:
        case CKM_RSA_PKCS_KEY_PAIR_GEN:
        case CKM_RSA_PKCS_OAEP:
        case CKM_RSA_PKCS_PSS:
        case CKM_RSA_X_509:
        case CKM_RSA_X9_31:
        case CKM_RSA_X9_31_KEY_PAIR_GEN:
        case CKM_SHA1_RSA_PKCS:
        case CKM_SHA1_RSA_PKCS_PSS:
        case CKM_SHA1_RSA_X9_31:
        case CKM_SHA224_RSA_PKCS:
        case CKM_SHA224_RSA_PKCS_PSS:
        case CKM_SHA256_RSA_PKCS:
        case CKM_SHA256_RSA_PKCS_PSS:
        case CKM_SHA384_RSA_PKCS:
        case CKM_SHA384_RSA_PKCS_PSS:
        case CKM_SHA512_RSA_PKCS:
        case CKM_SHA512_RSA_PKCS_PSS:
        case CKM_SHA3_224_RSA_PKCS:
        case CKM_SHA3_224_RSA_PKCS_PSS:
        case CKM_SHA3_256_RSA_PKCS:
        case CKM_SHA3_256_RSA_PKCS_PSS:
        case CKM_SHA3_384_RSA_PKCS:
        case CKM_SHA3_384_RSA_PKCS_PSS:
        case CKM_SHA3_512_RSA_PKCS:
        case CKM_SHA3_512_RSA_PKCS_PSS:
        case CKM_RSA_AES_KEY_WRAP:
            if (policy_update_modexp(pp, info) != CKR_OK) {
                TRACE_DEVEL("Mechanism 0x%lx blocked by policy!\n", mech);
                return CKR_MECHANISM_INVALID;
            }
            break;
        case CKM_ECDH1_DERIVE:
        case CKM_ECDSA:
        case CKM_ECDSA_KEY_PAIR_GEN:
        case CKM_ECDSA_SHA1:
        case CKM_ECDSA_SHA224:
        case CKM_ECDSA_SHA256:
        case CKM_ECDSA_SHA384:
        case CKM_ECDSA_SHA512:
        case CKM_ECDSA_SHA3_224:
        case CKM_ECDSA_SHA3_256:
        case CKM_ECDSA_SHA3_384:
        case CKM_ECDSA_SHA3_512:
        case CKM_IBM_EC_C25519:
        case CKM_IBM_EC_C448:
        case CKM_IBM_ED25519_SHA512:
        case CKM_IBM_ED448_SHA3:
        case CKM_IBM_ECDSA_OTHER:
        case CKM_IBM_BTC_DERIVE:
        case CKM_ECDH_AES_KEY_WRAP:
            if (policy_update_ec(pp, info) != CKR_OK) {
                TRACE_DEVEL("Mechanism 0x%lx blocked by policy!\n", mech);
                return CKR_MECHANISM_INVALID;
            }
            break;
        case CKM_GENERIC_SECRET_KEY_GEN:
        case CKM_SHA_1_KEY_GEN:
        case CKM_SHA224_KEY_GEN:
        case CKM_SHA256_KEY_GEN:
        case CKM_SHA384_KEY_GEN:
        case CKM_SHA512_KEY_GEN:
        case CKM_SHA512_224_KEY_GEN:
        case CKM_SHA512_256_KEY_GEN:
        case CKM_SHA3_224_KEY_GEN:
        case CKM_SHA3_256_KEY_GEN:
        case CKM_SHA3_384_KEY_GEN:
        case CKM_SHA3_512_KEY_GEN:
        case CKM_SSL3_MD5_MAC:
        case CKM_SSL3_SHA1_MAC:
            if (policy_update_symmetric(pp, info, CK_FALSE,
                                        CK_FALSE) != CKR_OK) {
                TRACE_DEVEL("Mechanism 0x%lx blocked by policy!\n", mech);
                return CKR_MECHANISM_INVALID;
            }
            break;
        case CKM_IBM_DILITHIUM:
        case CKM_IBM_KYBER:
            break;
        case CKM_IBM_SHA3_224:
        case CKM_IBM_SHA3_256:
        case CKM_IBM_SHA3_384:
        case CKM_IBM_SHA3_512:
        case CKM_MD5:
        case CKM_SHA_1:
        case CKM_SHA224:
        case CKM_SHA256:
        case CKM_SHA384:
        case CKM_SHA512:
        case CKM_SHA512_224:
        case CKM_SHA512_256:
        case CKM_SHA3_224:
        case CKM_SHA3_256:
        case CKM_SHA3_384:
        case CKM_SHA3_512:
            if (policy_update_digest(pp, mech) != CKR_OK) {
                TRACE_DEVEL("Mechanism 0x%lx blocked by policy!\n", mech);
                return CKR_MECHANISM_INVALID;
            }
            break;
        case CKM_PBE_SHA1_DES3_EDE_CBC:
            /* For this mechanism, the standard does not specify a
               value for the MECHANISM_INFO structure.  But this
               mechanism generates a DES3 key.  Check if DES3 keys can
               be generated in this policy.  If not, block this
               mechanism since it can only fail. */
            tmp.strength = POLICY_STRENGTH_IDX_112;
            tmp.allowed = CK_TRUE;
            if (policy_is_key_allowed_i(pp, &tmp) != CKR_OK)
                return CKR_MECHANISM_INVALID;
            break;
        case CKM_KEY_WRAP_LYNKS:
        case CKM_MD5_HMAC:
        case CKM_MD5_HMAC_GENERAL:
        case CKM_SHA_1_HMAC:
        case CKM_SHA_1_HMAC_GENERAL:
        case CKM_SHA224_HMAC:
        case CKM_SHA224_HMAC_GENERAL:
        case CKM_SHA256_HMAC:
        case CKM_SHA256_HMAC_GENERAL:
        case CKM_SHA384_HMAC:
        case CKM_SHA384_HMAC_GENERAL:
        case CKM_SHA512_224_HMAC:
        case CKM_SHA512_224_HMAC_GENERAL:
        case CKM_SHA512_256_HMAC:
        case CKM_SHA512_256_HMAC_GENERAL:
        case CKM_SHA512_HMAC:
        case CKM_SHA512_HMAC_GENERAL:
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
        case CKM_SSL3_KEY_AND_MAC_DERIVE:
        case CKM_TLS_KEY_AND_MAC_DERIVE:
        case CKM_IBM_ATTRIBUTEBOUND_WRAP:
            /* For these mechanisms, the standard does not specify a
               value for info.  So we only pass them to the generic
               check for signature size. */
            break;
        default:
            TRACE_ERROR("Mechanism 0x%lx unknown to policy!\n", mech);
            return CKR_MECHANISM_INVALID;
        }        
        if (policy_check_signature_size(pp, mech, info) != CKR_OK) {
            row = mechrow_from_numeric(mech);
            TRACE_DEVEL("Policy removes SIGN/VERIFY from %s (0x%lx)\n",
                        row ? row->string : "UNKNOWN", mech);
            info->flags &= ~(CKF_SIGN | CKF_SIGN_RECOVER |
                             CKF_VERIFY | CKF_VERIFY_RECOVER);
            if ((info->flags &
                    ~(CKF_HW|CKF_EC_F_P|CKF_EC_NAMEDCURVE|CKF_EC_UNCOMPRESS)) == 0) {
                TRACE_DEVEL("Mechanism %s (0x%lx) does not provide any feature after policy adjustment!\n",
                            row ? row->string : "UNKNOWN", mech);
                return CKR_MECHANISM_INVALID;
            }
        }
    }
    return CKR_OK;
}

/* If encalgo is NULL, the function assumes it should check the ICSF token. */
static CK_RV policy_check_token_store(policy_t p, CK_BBOOL newversion,
                                      CK_MECHANISM_TYPE encalgo,
                                      CK_SLOT_ID slot,
                                      struct tokstore_strength *ts)
{
    struct policy_private *pp = p->priv;
    struct objstrength s;

    if (pp) {
        s.allowed = CK_TRUE;
        if (newversion) {
            if (hashmap_find(pp->allowedmechs, CKM_AES_KEY_GEN, NULL) == 0) {
                TRACE_WARNING("POLICY VIOLATION: CKM_AES_KEY_GEN needed by Token-Store for slot %lu\n", slot);
                OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKM_AES_KEY_GEN needed by Token-Store for slot %lu\n", slot);
                return CKR_GENERAL_ERROR;
            }
            if (hashmap_find(pp->allowedmechs, CKM_AES_KEY_WRAP, NULL) == 0) {
                TRACE_WARNING("POLICY VIOLATION: CKM_AES_KEY_WRAP needed by Token-Store for slot %lu\n", slot);
                OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKM_AES_KEY_WRAP needed by Token-Store for slot %lu\n", slot);
                return CKR_GENERAL_ERROR;
            }
            if (hashmap_find(pp->allowedmechs, CKM_AES_GCM, NULL) == 0) {
                TRACE_WARNING("POLICY VIOLATION: CKM_AES_GCM needed by Token-Store for slot %lu\n", slot);
                OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKM_AES_GCM needed by Token-Store for slot %lu\n", slot);
                return CKR_GENERAL_ERROR;
            }
            policy_compute_strength(pp, &s, 256, COMPARE_SYMMETRIC);
            if (hashmap_find(pp->allowedmechs, CKM_PKCS5_PBKD2, NULL) == 0) {
                TRACE_WARNING("POLICY VIOLATION: CKM_PKCS5_PBKD2 needed by Token-Store for slot %lu\n", slot);
                OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKM_PKCS5_PBKD2 needed by Token-Store for slot %lu\n", slot);
                return CKR_GENERAL_ERROR;
            }
            if (policy_is_prf_allowed(pp, CKP_PKCS5_PBKD2_HMAC_SHA512) != CKR_OK) {
                TRACE_WARNING("POLICY VIOLATION: CKP_PKCS5_PBKD2_HMAC_SHA512 needed by Token-Store for slot %lu\n", slot);
                OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKP_PKCS5_PBKD2_HMAC_SHA512 needed by Token-Store for slot %lu\n", slot);
                return CKR_GENERAL_ERROR;
            }
            if (ts) {
                ts->mk_keygen.mechanism = CKM_AES_KEY_GEN;
                ts->mk_crypt.mechanism = CKM_AES_GCM;
                ts->wrap_crypt.mechanism = CKM_AES_GCM;
                ts->mk_keygen.pParameter = ts->mk_crypt.pParameter =
                    ts->wrap_crypt.pParameter = NULL;
                ts->mk_keygen.ulParameterLen = ts->mk_crypt.ulParameterLen =
                    ts->wrap_crypt.ulParameterLen = 0;
                ts->mk_strength = ts->wrap_strength = s.strength;
            }
        } else {
            /* ICSF does not use a datastore, so encalgo is 0. */
            if (encalgo && hashmap_find(pp->allowedmechs, encalgo, NULL) == 0) {
                TRACE_WARNING("POLICY VIOLATION: Token-Store encryption method not allowed for slot %lu!\n", slot);
                OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: Token-Store encryption method not allowed for slot %lu!\n", slot);
                return CKR_GENERAL_ERROR;
            }
            /* SO pin hash */
            if (hashmap_find(pp->allowedmechs, CKM_SHA_1, NULL) == 0) {
                TRACE_WARNING("POLICY VIOLATION: Token-Store requires SHA1 for slot %lu!\n", slot);
                OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: Token-Store requires SHA1 for slot %lu!\n", slot);
                return CKR_GENERAL_ERROR;
            }
            /* User pin hash */
            if (hashmap_find(pp->allowedmechs, CKM_MD5, NULL) == 0) {
                TRACE_WARNING("POLICY VIOLATION: Token-Store requires MD5 for slot %lu!\n", slot);
                OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: Token-Store requires MD5 for slot %lu!\n", slot);
                return CKR_GENERAL_ERROR;
            }
            if (encalgo == CKM_DES3_CBC) {
                if (hashmap_find(pp->allowedmechs, CKM_DES3_KEY_GEN, NULL) == 0) {
                    TRACE_WARNING("POLICY VIOLATION: CKM_DES3_KEY_GEN needed by Token-Store for slot %lu\n", slot);
                    OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKM_DES3_KEY_GEN needed by Token-Store for slot %lu\n", slot);
                    return CKR_GENERAL_ERROR;
                }
                /* We use a 3DES key with three parts as master key... */
                policy_compute_strength(pp, &s, 112, COMPARE_SYMMETRIC);
                if (ts)
                    ts->mk_strength = s.strength;
                /* ... and a 2Key 3DES keys as wrapping key. */
                policy_compute_strength(pp, &s, 80, COMPARE_SYMMETRIC);
                if (ts) {
                    ts->mk_keygen.mechanism = CKM_DES3_KEY_GEN;
                    ts->mk_crypt.mechanism = ts->wrap_crypt.mechanism = encalgo;
                    ts->mk_keygen.pParameter = ts->mk_crypt.pParameter =
                        ts->wrap_crypt.pParameter = NULL;
                    ts->mk_keygen.ulParameterLen = ts->mk_crypt.ulParameterLen =
                        ts->wrap_crypt.ulParameterLen = 0;
                    ts->wrap_strength = s.strength;
                }
            } else if (encalgo == CKM_AES_CBC) {
                if (hashmap_find(pp->allowedmechs, CKM_AES_KEY_GEN, NULL) == 0) {
                    TRACE_WARNING("POLICY VIOLATION: CKM_AES_KEY_GEN needed by Token-Store for slot %lu\n", slot);
                    OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKM_AES_KEY_GEN needed by Token-Store for slot %lu\n", slot);
                    return CKR_GENERAL_ERROR;
                }
                policy_compute_strength(pp, &s, 256, COMPARE_SYMMETRIC);
                if (ts) {
                    ts->mk_keygen.mechanism = CKM_AES_KEY_GEN;
                    ts->mk_crypt.mechanism = ts->wrap_crypt.mechanism = encalgo;
                    ts->mk_keygen.pParameter = ts->mk_crypt.pParameter =
                        ts->wrap_crypt.pParameter = NULL;
                    ts->mk_keygen.ulParameterLen = ts->mk_crypt.ulParameterLen =
                        ts->wrap_crypt.ulParameterLen = 0;
                    ts->mk_strength = ts->wrap_strength = s.strength;
                }
            } else if (encalgo) {
                TRACE_WARNING("POLICY VIOLATION: Unknown Token-Store encryption method for slot %lu!\n", slot);
                OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: Unknown Token-Store encryption method for slot %lu!\n", slot);
                return CKR_GENERAL_ERROR;
            } else {
                /* ICSF token */
                if (hashmap_find(pp->allowedmechs, CKM_AES_KEY_GEN, NULL) == 0) {
                    TRACE_WARNING("POLICY VIOLATION: CKM_AES_KEY_GEN needed by Token-Store for slot %lu\n", slot);
                    OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKM_AES_KEY_GEN needed by Token-Store for slot %lu\n", slot);
                    return CKR_GENERAL_ERROR;
                }
                if (hashmap_find(pp->allowedmechs, CKM_AES_CBC, NULL) == 0) {
                    TRACE_WARNING("POLICY VIOLATION: CKM_AES_CBC needed by Token-Store for slot %lu\n", slot);
                    OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKM_AES_CBC needed by Token-Store for slot %lu\n", slot);
                    return CKR_GENERAL_ERROR;
                }
                policy_compute_strength(pp, &s, 256, COMPARE_SYMMETRIC);
                if (hashmap_find(pp->allowedmechs, CKM_PKCS5_PBKD2, NULL) == 0) {
                    TRACE_WARNING("POLICY VIOLATION: CKM_PKCS5_PBKD2 needed by Token-Store for slot %lu\n", slot);
                    OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKM_PKCS5_PBKD2 needed by Token-Store for slot %lu\n", slot);
                    return CKR_GENERAL_ERROR;
                }
                if (policy_is_prf_allowed(pp, CKP_PKCS5_PBKD2_HMAC_SHA256) != CKR_OK) {
                    TRACE_WARNING("POLICY VIOLATION: CKP_PKCS5_PBKD2_HMAC_SHA256 needed by Token-Store for slot %lu\n", slot);
                    OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: CKP_PKCS5_PBKD2_HMAC_SHA256 needed by Token-Store for slot %lu\n", slot);
                    return CKR_GENERAL_ERROR;
                }
                if (ts) {
                    ts->mk_keygen.mechanism = CKM_AES_KEY_GEN;
                    ts->mk_crypt.mechanism = ts->wrap_crypt.mechanism =
                        CKM_AES_CBC;
                    ts->mk_keygen.pParameter = ts->mk_crypt.pParameter =
                        ts->wrap_crypt.pParameter = NULL;
                    ts->mk_keygen.ulParameterLen = ts->mk_crypt.ulParameterLen =
                        ts->wrap_crypt.ulParameterLen = 0;
                    ts->mk_strength = ts->wrap_strength = s.strength;
                }
            }
        }
        /* Both token store versions now have the weakest key strength in s */
        if (policy_is_key_allowed_i(pp, &s) != CKR_OK) {
            TRACE_WARNING("POLICY VIOLATION: Token-Store encryption key too weak for slot %lu!\n", slot);
            OCK_SYSLOG(LOG_ERR, "POLICY VIOLATION: Token-Store encryption key too weak for slot %lu!\n", slot);
            return CKR_GENERAL_ERROR;
        }
    }
    return CKR_OK;
}

static CK_ULONG policy_get_sym_key_strength(policy_t p, CK_ULONG sym_key_bits)
{
    struct policy_private *pp = p->priv;
    struct objstrength s;

    policy_compute_strength(pp, &s, sym_key_bits, COMPARE_SYMMETRIC);

   return s.strength;
}

/* Policy loading support (internal functions) */
static CK_RV policy_check_cfg_file(FILE *fp, const char *name)
{
    struct stat statbuf;
    struct group *grp = NULL;
    int err;

    grp = getgrnam(PKCS_GROUP);
    if (!grp) {
        TRACE_ERROR("Could not retrieve \"%s\" group!", PKCS_GROUP);
        OCK_SYSLOG(LOG_ERR, "POLICY: Could not retrieve \"%s\" group!",
                   PKCS_GROUP);
        return CKR_GENERAL_ERROR;
    }
    if (fstat(fileno(fp), &statbuf)) {
        err = errno;
        TRACE_ERROR("Could not stat configuration file %s: %s\n",
                    name, strerror(err));
        OCK_SYSLOG(LOG_ERR, "POLICY: Could not stat configuration file %s: %s\n",
                   name, strerror(err));
        return CKR_GENERAL_ERROR;
    }
    if (statbuf.st_uid != 0) {
        TRACE_ERROR("Policy configuration file %s should be owned by \"root\"!\n",
                    name);
        OCK_SYSLOG(LOG_ERR, "POLICY: Configuration file %s should be owned by \"root\"!\n",
                   name);
        return CKR_GENERAL_ERROR;
    }
    if (statbuf.st_gid != grp->gr_gid) {
        TRACE_ERROR("Policy configuration file %s should have group \"%s\"!\n",
                    name, PKCS_GROUP);
        OCK_SYSLOG(LOG_ERR, "POLICY: Configuration file %s should have group \"%s\"!\n",
                   name, PKCS_GROUP);
        return CKR_GENERAL_ERROR;
    }
    if ((statbuf.st_mode & ~S_IFMT) != OCK_POLICY_PERMS) {
        TRACE_ERROR("Configuration file %s has wrong permissions!\n", name);
        OCK_SYSLOG(LOG_ERR, "POLICY: Configuration file %s has wrong permissions!\n",
                   name);
        return CKR_GENERAL_ERROR;
    }
    return CKR_OK;
}

/* Policy loading support (externalized for testing purpose) */
void policy_init_policy(struct policy *p)
{
    p->store_object_strength = policy_store_object_strength;
    p->is_key_allowed = policy_is_key_allowed;
    p->is_mech_allowed = policy_is_mech_allowed;
    p->update_mech_info = policy_update_mech_info;
    p->check_token_store = policy_check_token_store;
    p->get_sym_key_strength = policy_get_sym_key_strength;
    p->active = CK_FALSE;
}

static void parse_error_hook(int line, int col, const char *msg)
{
    TRACE_ERROR("Parse error at %d:%d: %s\n", line, col, msg);
}

static CK_RV policy_fileversion_check(struct ConfigBaseNode *cfg,
                                      char *versionprefix, size_t prefixlen,
                                      unsigned int minversion,
                                      unsigned int *vers)
{
    const char *filevers;

    if (!confignode_hastype(cfg, CT_FILEVERSION)) {
        TRACE_ERROR("Fileversion not found!\n");
        return CKR_FUNCTION_FAILED;
    }
    filevers = cfg->key;
    if (strncmp(versionprefix, filevers, prefixlen) != 0 ||
        sscanf(filevers + prefixlen, "%u", vers) != 1 || *vers < minversion) {
        TRACE_ERROR("Wrong version.  Expected \"%s%d\" or higher but got \"%s\"\n",
                    versionprefix, minversion, filevers);
        return CKR_FUNCTION_FAILED;
    }
    cfg->flags = 1;
    return CKR_OK;
}

static CK_RV policy_extract_strength_key(struct ConfigIdxStructNode *sd,
                                         const char *key, CK_ULONG *val, int i)
{
    struct ConfigBaseNode *n;

    n = confignode_find(sd->value, key);
    if (!n) {
        TRACE_DEVEL("Strength configuration for %lu does not specify %s.\n",
                    supportedstrengths[i], key);
        *val = ~0u;
    } else if (!confignode_hastype(n, CT_INTVAL)) {
        TRACE_ERROR("Strength configuration for %lu does not specify integer value for %s!\n",
                    supportedstrengths[i], key);
        return CKR_FUNCTION_FAILED;
    } else {
        *val = confignode_to_intval(n)->value;
        n->flags = 1;
    }
    return CKR_OK;
}

static CK_RV policy_check_unmarked(struct ConfigBaseNode *n)
{
    struct ConfigBaseNode *i;
    CK_RV rc = CKR_OK;
    int f;

    confignode_foreach(i, n, f) {
        if (i->flags != 1) {
            TRACE_ERROR("Unknown keyword \"%s\" in line %hd\n",
                        i->key, i->line);
            rc = CKR_FUNCTION_FAILED;
        }
    }
    return rc;
}

static CK_RV policy_parse_mechlist(struct policy_private *pp,
                                   struct ConfigBaseNode *list)
{
    union hashmap_value val = { .ulVal = 0 };
    struct ConfigBaseNode *i;
    const char *mechstr;
    struct hashmap *h;
    CK_RV rc = CKR_OK;
    CK_ULONG mech;
    int f;

    h = hashmap_new();
    if (!h)
        return CKR_HOST_MEMORY;
    if (list) {
        confignode_foreach(i, list, f) {
            mechstr = i->key;
            rc = translate_string_to_mech(mechstr, strlen(mechstr), &mech);
            if (rc != CKR_OK) {
                TRACE_ERROR("POLICY: Unknown mechanism: %s (line %hd)\n",
                            mechstr, i->line);
                break;
            }
            if (hashmap_add(h, mech, val, NULL)) {
                TRACE_ERROR("POLICY: failed to add mechanism to hash!\n");
                rc = CKR_HOST_MEMORY;
                break;
            }
        }
    }
    pp->allowedmechs = h;
    return rc;
}

static CK_RV policy_parse_curvelist(struct policy_private *pp,
                                    struct ConfigBaseNode *list)
{
    const struct _ec **curves;
    struct ConfigBaseNode *i;
    const struct _ec *curve;
    int f, count = 0, p = 0;
    CK_ULONG maxsize = 0;
    CK_RV rc = CKR_OK;

    /* Compute size */
    if (list) {
        confignode_foreach(i, list, f) {
            rc = translate_string_to_curve(i->key, strlen(i->key), &curve);
            if (rc != CKR_OK) {
                TRACE_ERROR("POLICY: Unknown curve \"%s\" in line %hd\n",
                            i->key, i->line);
                OCK_SYSLOG(LOG_ERR, "POLICY: Unknown curve \"%s\" in line %hd\n",
                        i->key, i->line);
                return rc;
            }
            ++count;
            if (curve->prime_bits > maxsize)
                maxsize = curve->prime_bits;
        }
    }
    pp->numallowedcurves = count;
    pp->maxcurvesize = maxsize;
    if (count == 0)
        return CKR_OK;
    curves = calloc(count, sizeof(const struct _ec *));
    if (!curves) {
        TRACE_ERROR("POLICY: Not enough memory for curves array!\n");
        return CKR_HOST_MEMORY;
    }
    confignode_foreach(i, list, f) {
        /* Ignore rc since it has been checked before. */
        translate_string_to_curve(i->key, strlen(i->key), &curve);
        curves[p++] = curve;
    }
    pp->allowedcurves = curves;
    return rc;
}

static CK_RV policy_parse_mgfs(struct policy_private *pp,
                               struct ConfigBaseNode *list)
{
    CK_ULONG smgfs = 0, vmgfs = 0;
    struct ConfigBaseNode *i;
    CK_RV rc = CKR_OK;
    CK_ULONG mgf;
    int f;

    if (list) {
        confignode_foreach(i, list, f) {
            rc = translate_string_to_mgf(i->key, strlen(i->key), &mgf);
            if (rc != CKR_OK) {
                TRACE_ERROR("POLICY: Unknown MGF: \"%s\" (line %hd)\n",
                            i->key, i->line);
                break;
            }
            if (mgf >= CKG_VENDOR_DEFINED) {
                if ((mgf - CKG_VENDOR_DEFINED - 1) > 31) {
                    TRACE_ERROR("POLICY: MGF invalid: \"%s\" (line %hd)\n",
                                i->key, i->line);
                    rc = CKR_FUNCTION_FAILED;
                    break;
                }
                vmgfs |= (1u << (mgf - CKG_VENDOR_DEFINED - 1));
            } else {
                if (mgf > 31) {
                    TRACE_ERROR("POLICY: MGF invalid: \"%s\" (line %hd)\n",
                                i->key, i->line);
                    rc = CKR_FUNCTION_FAILED;
                    break;
                }
                smgfs |= (1u << mgf);
            }
        }
    }
    pp->allowedmgfs = smgfs;
    pp->allowedvendormgfs = vmgfs;
    return rc;
}

static CK_RV policy_parse_kdfs(struct policy_private *pp,
                               struct ConfigBaseNode *list)
{
    struct ConfigBaseNode *i;
    CK_ULONG kdfs = 0, vkdfs = 0, kdf;
    CK_RV rc = CKR_OK;
    int f;

    if (list) {
        confignode_foreach(i, list, f) {
            rc = translate_string_to_kdf(i->key, strlen(i->key), &kdf);
            if (rc != CKR_OK) {
                TRACE_ERROR("POLICY: Unknown KDF: \"%s\" (line %hd)\n",
                            i->key, i->line);
                break;
            }

            if (kdf >= CKD_VENDOR_DEFINED) {
                if ((kdf - CKD_VENDOR_DEFINED - 1) > 31) {
                    TRACE_ERROR("POLICY: KDF invalid: \"%s\" (line %hd)\n",
                                i->key, i->line);
                    rc = CKR_FUNCTION_FAILED;
                    break;
                }
                vkdfs |= (1u << (kdf - CKD_VENDOR_DEFINED - 1));
            } else {
                if (kdf > 31) {
                    TRACE_ERROR("POLICY: KDF invalid: \"%s\" (line %hd)\n",
                                i->key, i->line);
                    rc = CKR_FUNCTION_FAILED;
                    break;
                }
                kdfs |= (1u << kdf);
            }
        }
    }
    pp->allowedkdfs = kdfs;
    pp->allowedvendorkdfs = vkdfs;
    return rc;
}

static CK_RV policy_parse_prfs(struct policy_private *pp,
                               struct ConfigBaseNode *list)
{
    struct ConfigBaseNode *i;
    CK_ULONG prfs = 0, prf;
    CK_RV rc = CKR_OK;
    int f;

    if (list) {
        confignode_foreach(i, list, f) {
            rc = translate_string_to_prf(i->key, strlen(i->key), &prf);
            if (rc != CKR_OK) {
                TRACE_ERROR("POLICY: Unknown PRF: \"%s\" (line %hd)\n",
                            i->key, i->line);
                break;
            }
            prfs |= (1u << prf);
        }
    }
    pp->allowedprfs = prfs;
    return rc;
}

CK_RV policy_load_strength_cfg(struct policy_private *pp,
                               FILE *fp)
{
    struct ConfigIdxStructNode *sd;
    struct ConfigBaseNode *cfg;
    CK_RV rc = CKR_OK;
    unsigned int vers;
    int i;

    TRACE_DEVEL("Parsing strength configuration file\n");
    if (parse_configlib_file(fp, &cfg, parse_error_hook, 0)) {
        TRACE_ERROR("Parsing strength configuration failed!\n");
        return CKR_FUNCTION_FAILED;
    }
    rc = policy_fileversion_check(cfg, "strength-", strlen("strength-"),
                                  OCK_STRENGTH_MINVERSION, &vers);
    if (rc != CKR_OK)
        goto out;
    for (i = 0; i < NUM_SUPPORTED_STRENGTHS; ++i) {
        sd = confignode_findidx(cfg, "strength", supportedstrengths[i]);
        if (sd) {
            sd->base.flags = 1;
            rc = policy_extract_strength_key(sd, "MOD_EXP",
                                             &pp->strengths[i].strength.details.modexp,
                                             i);
            if (rc != CKR_OK)
                goto out;
            rc = policy_extract_strength_key(sd, "ECC",
                                             &pp->strengths[i].strength.details.ecc,
                                             i);
            if (rc != CKR_OK)
                goto out;
            rc = policy_extract_strength_key(sd, "SYMMETRIC",
                                             &pp->strengths[i].strength.details.symmetric,
                                             i);
            if (rc != CKR_OK)
                goto out;
            rc = policy_extract_strength_key(sd, "digest",
                                             &pp->strengths[i].strength.details.digests,
                                             i);
            if (rc != CKR_OK)
                goto out;
            rc = policy_extract_strength_key(sd, "signature",
                                             &pp->strengths[i].strength.details.signatures,
                                             i);
            if (rc != CKR_OK)
                goto out;
            pp->strengths[i].set = CK_TRUE;
            rc = policy_check_unmarked(sd->value);
            if (rc != CKR_OK)
                goto out;
        } else {
            pp->strengths[i].set = CK_FALSE;
        }
    }
 out:
    if (rc == CKR_OK)
        rc = policy_check_unmarked(cfg);
    confignode_deepfree(cfg);
    return rc;
}

CK_RV policy_load_policy_cfg(struct policy_private *pp,
                             FILE *fp, CK_BBOOL *restricting)
{
    struct ConfigBaseNode *cfg, *strength, *allowedmechs, *allowedcurves,
        *allowedmgfs, *allowedkdfs, *allowedprfs;
    unsigned long reqstrength;
    CK_RV rc = CKR_OK;
    unsigned int vers;
    int i;

    *restricting = CK_FALSE;
    if (parse_configlib_file(fp, &cfg, parse_error_hook, 0)) {
        TRACE_ERROR("Parsing policy configuration failed!\n");
        OCK_SYSLOG(LOG_ERR, "Parsing policy configuration failed!\n");
        return CKR_FUNCTION_FAILED;
    }
    rc = policy_fileversion_check(cfg, "policy-", strlen("policy-"),
                                  OCK_STRENGTH_MINVERSION, &vers);
    if (rc != CKR_OK)
        return rc;
    strength = confignode_find(cfg, "strength");
    if (!strength || !confignode_hastype(strength, CT_INTVAL)) {
        TRACE_ERROR("Invalid strength configuration in policy!\n");
        OCK_SYSLOG(LOG_ERR, "Invalid strength configuration in policy!\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }
    strength->flags = 1;
    reqstrength = confignode_to_intval(strength)->value;
    for (i = 0; i < NUM_SUPPORTED_STRENGTHS; ++i) {
        if (reqstrength == supportedstrengths[i]) {
            TRACE_DEVEL("POLICY: Using strength %lu\n", supportedstrengths[i]);
            break;
        } else if (reqstrength > supportedstrengths[i]) {
            if (i > 0)
                i -= 1;
            TRACE_DEVEL("POLICY: Using strength %lu\n", supportedstrengths[i]);
            break;
        }
    }
    if (i == NUM_SUPPORTED_STRENGTHS && reqstrength > 0) {
        i -=1;
        TRACE_DEVEL("POLICY: Using strength %lu\n", supportedstrengths[i]);
    }
    if (i != NUM_SUPPORTED_STRENGTHS)
        *restricting = CK_TRUE;
    pp->minstrengthidx = i;
    allowedmechs = confignode_find(cfg, "allowedmechs");
    if (!allowedmechs) {
        TRACE_DEVEL("POLICY: No mechanism restriction\n");
    } else if (!confignode_hastype(allowedmechs, CT_BARELIST)) {
        TRACE_ERROR("POLICY: allowedmechs has wrong type!\n");
        OCK_SYSLOG(LOG_ERR, "POLICY: allowedmechs has wrong type!\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    } else {
        *restricting = CK_TRUE;
        allowedmechs->flags = 1;
        rc = policy_parse_mechlist(pp,
                                   confignode_to_barelist(allowedmechs)->value);
        if (rc != CKR_OK)
            goto out;
    }
    allowedcurves = confignode_find(cfg, "allowedcurves");
    if (!allowedcurves) {
        TRACE_DEVEL("POLICY: No curve restrictions\n");
        pp->allowedcurves = NULL;
        pp->numallowedcurves = -1;
        pp->maxcurvesize = 521;
    } else if (!confignode_hastype(allowedcurves, CT_BARELIST)) {
        TRACE_ERROR("POLICY: allowedcurves has wrong type!\n");
        OCK_SYSLOG(LOG_ERR, "POLICY: allowedcurves has wrong type!\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    } else {
        *restricting = CK_TRUE;
        allowedcurves->flags = 1;
        rc = policy_parse_curvelist(pp,
                                    confignode_to_barelist(allowedcurves)->
                                    value);
        if (rc != CKR_OK)
            goto out;
    }
    allowedmgfs = confignode_find(cfg, "allowedmgfs");
    if (!allowedmgfs) {
        TRACE_DEVEL("POLICY: No MGF restrictions\n");
        pp->allowedmgfs = ~0u;
        pp->allowedvendormgfs = ~0u;
    } else if (!confignode_hastype(allowedmgfs, CT_BARELIST)) {
        TRACE_ERROR("POLICY: allowedmgfs has wrong type!\n");
        OCK_SYSLOG(LOG_ERR, "POLICY: allowedmgfs has wrong type!\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    } else {
        *restricting = CK_TRUE;
        allowedmgfs->flags = 1;
        rc = policy_parse_mgfs(pp,
                               confignode_to_barelist(allowedmgfs)->value);
        if (rc != CKR_OK)
            goto out;
    }
    allowedkdfs = confignode_find(cfg, "allowedkdfs");
    if (!allowedkdfs) {
        TRACE_DEVEL("POLICY: No KDF restrictions\n");
        pp->allowedkdfs = ~0u;
        pp->allowedvendorkdfs = ~0u;
    } else if (!confignode_hastype(allowedkdfs, CT_BARELIST)) {
        TRACE_ERROR("POLICY: allowedkdfs has wrong type!\n");
        OCK_SYSLOG(LOG_ERR, "POLICY: allowedkdfs has wrong type!\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    } else {
        *restricting = CK_TRUE;
        allowedkdfs->flags = 1;
        rc = policy_parse_kdfs(pp,
                               confignode_to_barelist(allowedkdfs)->value);
        if (rc != CKR_OK)
            goto out;
    }
    allowedprfs = confignode_find(cfg, "allowedprfs");
    if (!allowedprfs) {
        TRACE_DEVEL("POLICY: No PRF restrictions\n");
        pp->allowedprfs = ~0u;
    } else if (!confignode_hastype(allowedprfs, CT_BARELIST)) {
        TRACE_ERROR("POLICY: allowedprfs has wrong type!\n");
        OCK_SYSLOG(LOG_ERR, "POLICY: allowedprfs has wrong type!\n");
        rc = CKR_FUNCTION_FAILED;
        goto out;
    } else {
        *restricting = CK_TRUE;
        allowedprfs->flags = 1;
        rc = policy_parse_prfs(pp,
                               confignode_to_barelist(allowedprfs)->value);
        if (rc != CKR_OK)
            goto out;
    }
 out:
    if (rc == CKR_OK)
        rc = policy_check_unmarked(cfg);
    if (rc == CKR_FUNCTION_FAILED)
        rc = CKR_GENERAL_ERROR;
    confignode_deepfree(cfg);
    return rc;
}

/* Loading and unloading from API library */

CK_RV policy_load(struct policy *p)
{
    FILE *fp = NULL;
    CK_RV rc = CKR_OK;
    struct policy_private *pp = NULL;
    int err;
    CK_BBOOL restricting = CK_FALSE;

    policy_init_policy(p);
    /* Load the strength definition */
    fp = fopen(OCK_STRENGTH_CFG, "r");
    if (fp == NULL) {
        err = errno;
        TRACE_ERROR("Failed to open " OCK_STRENGTH_CFG ": %s\n",
                    strerror(err));
        OCK_SYSLOG(LOG_ERR, "POLICY: Failed to open " OCK_STRENGTH_CFG ": %s\n",
                   strerror(err));
        rc = CKR_GENERAL_ERROR;
        goto out;
    }
    rc = policy_check_cfg_file(fp, OCK_STRENGTH_CFG);
    if (rc != CKR_OK)
        goto out;
    pp = policy_private_alloc();
    if (pp == NULL) {
        TRACE_ERROR("Could not allocate policy private data!\n");
        OCK_SYSLOG(LOG_ERR, "POLICY: Could not allocate policy private data!\n");
        rc = CKR_HOST_MEMORY;
        goto out;
    }
    rc = policy_load_strength_cfg(pp, fp);
    if (rc != CKR_OK) {
        TRACE_ERROR("Strength definition failed to parse!\n");
        OCK_SYSLOG(LOG_ERR, "POLICY: Strength definition %s failed to parse!\n",
                   OCK_STRENGTH_CFG);
        goto out;
    }
    fclose(fp);
    /* Load the policy definition */
    fp = fopen(OCK_POLICY_CFG, "r");
    if (fp == NULL) {
        err = errno;
        if (errno == ENOENT) {
            /* If policy does not exit, but strength definition, run
             * without policy.
             */
            policy_private_deactivate(pp);
            goto out;
        }
        TRACE_ERROR("Failed to open " OCK_POLICY_CFG ": %s\n",
                    strerror(err));
        OCK_SYSLOG(LOG_ERR, "POLICY: Failed to open " OCK_POLICY_CFG ": %s\n",
                   strerror(err));
        rc = CKR_GENERAL_ERROR;
        goto out;
    }
    rc = policy_check_cfg_file(fp, OCK_POLICY_CFG);
    if (rc != CKR_OK)
        goto out;
    rc = policy_load_policy_cfg(pp, fp, &restricting);
    if (rc != CKR_OK) {
        TRACE_ERROR("Policy definition failed to parse!\n");
        OCK_SYSLOG(LOG_ERR, "POLICY: Policy definition %s failed to parse!\n",
                   OCK_POLICY_CFG);
    }
 out:
    if (fp)
        fclose(fp);
    if (rc != CKR_OK) {
        pp = policy_private_free(pp);
        restricting = CK_FALSE;
    }
    p->priv = pp;
    p->active = restricting;
    return rc;
}

void policy_unload(struct policy *p)
{
    struct policy_private *pp = p->priv;

    p->active = CK_FALSE;
    if (pp)
        p->priv = policy_private_free(pp);
}
