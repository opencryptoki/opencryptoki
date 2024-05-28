/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <limits.h>
#include "pkcs11types.h"
#include "defs.h"
#include "trace.h"

CK_RV get_sha_size(CK_ULONG mech, CK_ULONG *hsize)
{
    switch (mech) {
#if !(NOMD2 )
    case CKM_MD2:
        *hsize = MD2_HASH_SIZE;
        break;
#endif
    case CKM_MD5:
        *hsize = MD5_HASH_SIZE;
        break;
    case CKM_SHA_1:
        *hsize = SHA1_HASH_SIZE;
        break;
    case CKM_SHA224:
    case CKM_SHA512_224:
        *hsize = SHA224_HASH_SIZE;
        break;
    case CKM_SHA256:
    case CKM_SHA512_256:
        *hsize = SHA256_HASH_SIZE;
        break;
    case CKM_SHA384:
        *hsize = SHA384_HASH_SIZE;
        break;
    case CKM_SHA512:
        *hsize = SHA512_HASH_SIZE;
        break;
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        *hsize = SHA3_224_HASH_SIZE;
        break;
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        *hsize = SHA3_256_HASH_SIZE;
        break;
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        *hsize = SHA3_384_HASH_SIZE;
        break;
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        *hsize = SHA3_512_HASH_SIZE;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }
    return CKR_OK;
}

CK_RV get_sha_block_size(CK_ULONG mech, CK_ULONG *bsize)
{
    switch (mech) {
#if !(NOMD2 )
    case CKM_MD2:
        *bsize = MD2_BLOCK_SIZE;
        break;
#endif
    case CKM_MD5:
        *bsize = MD5_BLOCK_SIZE;
        break;
    case CKM_SHA_1:
        *bsize = SHA1_BLOCK_SIZE;
        break;
    case CKM_SHA224:
        *bsize = SHA224_BLOCK_SIZE;
        break;
    case CKM_SHA256:
        *bsize = SHA256_BLOCK_SIZE;
        break;
    case CKM_SHA384:
        *bsize = SHA384_BLOCK_SIZE;
        break;
    case CKM_SHA512:
    case CKM_SHA512_224:
    case CKM_SHA512_256:
        *bsize = SHA512_BLOCK_SIZE;
        break;
    case CKM_SHA3_224:
    case CKM_IBM_SHA3_224:
        *bsize = SHA3_224_BLOCK_SIZE;
        break;
    case CKM_SHA3_256:
    case CKM_IBM_SHA3_256:
        *bsize = SHA3_256_BLOCK_SIZE;
        break;
    case CKM_SHA3_384:
    case CKM_IBM_SHA3_384:
        *bsize = SHA3_384_BLOCK_SIZE;
        break;
    case CKM_SHA3_512:
    case CKM_IBM_SHA3_512:
        *bsize = SHA3_512_BLOCK_SIZE;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }
    return CKR_OK;
}

CK_RV get_hmac_digest(CK_ULONG mech, CK_ULONG *digest_mech, CK_BBOOL *general)
{
    switch (mech) {
#if !(NOMD2 )
    case CKM_MD2_HMAC:
    case CKM_MD2_HMAC_GENERAL:
        *digest_mech = CKM_MD2;
        *general = (mech == CKM_MD2_HMAC_GENERAL);
        break;
#endif
    case CKM_MD5_HMAC:
    case CKM_MD5_HMAC_GENERAL:
        *digest_mech = CKM_MD5;
        *general = (mech == CKM_MD5_HMAC_GENERAL);
        break;
    case CKM_RIPEMD128_HMAC:
    case CKM_RIPEMD128_HMAC_GENERAL:
        *digest_mech = CKM_RIPEMD128;
        *general = (mech == CKM_RIPEMD128_HMAC_GENERAL);
        break;
    case CKM_SHA_1_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
        *digest_mech = CKM_SHA_1;
        *general = (mech == CKM_SHA_1_HMAC_GENERAL);
        break;
    case CKM_SHA224_HMAC:
    case CKM_SHA224_HMAC_GENERAL:
        *digest_mech = CKM_SHA224;
        *general = (mech == CKM_SHA224_HMAC_GENERAL);
        break;
    case CKM_SHA256_HMAC:
    case CKM_SHA256_HMAC_GENERAL:
        *digest_mech = CKM_SHA256;
        *general = (mech == CKM_SHA256_HMAC_GENERAL);
        break;
    case CKM_SHA384_HMAC:
    case CKM_SHA384_HMAC_GENERAL:
        *digest_mech = CKM_SHA384;
        *general = (mech == CKM_SHA384_HMAC_GENERAL);
        break;
    case CKM_SHA512_HMAC:
    case CKM_SHA512_HMAC_GENERAL:
        *digest_mech = CKM_SHA512;
        *general = (mech == CKM_SHA512_HMAC_GENERAL);
        break;
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_224_HMAC_GENERAL:
        *digest_mech = CKM_SHA512_224;
        *general = (mech == CKM_SHA512_224_HMAC_GENERAL);
        break;
    case CKM_SHA512_256_HMAC:
    case CKM_SHA512_256_HMAC_GENERAL:
        *digest_mech = CKM_SHA512_256;
        *general = (mech == CKM_SHA512_256_HMAC_GENERAL);
        break;
    case CKM_SHA3_224_HMAC:
    case CKM_SHA3_224_HMAC_GENERAL:
        *digest_mech = CKM_SHA3_224;
        *general = (mech == CKM_SHA3_224_HMAC_GENERAL);
        break;
    case CKM_SHA3_256_HMAC:
    case CKM_SHA3_256_HMAC_GENERAL:
        *digest_mech = CKM_SHA3_256;
        *general = (mech == CKM_SHA3_256_HMAC_GENERAL);
        break;
    case CKM_SHA3_384_HMAC:
    case CKM_SHA3_384_HMAC_GENERAL:
        *digest_mech = CKM_SHA3_384;
        *general = (mech == CKM_SHA3_384_HMAC_GENERAL);
        break;
    case CKM_SHA3_512_HMAC:
    case CKM_SHA3_512_HMAC_GENERAL:
        *digest_mech = CKM_SHA3_512;
        *general = (mech == CKM_SHA3_512_HMAC_GENERAL);
        break;
    case CKM_IBM_SHA3_224_HMAC:
        *digest_mech = CKM_IBM_SHA3_224;
        *general = FALSE;
        break;
    case CKM_IBM_SHA3_256_HMAC:
        *digest_mech = CKM_IBM_SHA3_256;
        *general = FALSE;
        break;
    case CKM_IBM_SHA3_384_HMAC:
        *digest_mech = CKM_IBM_SHA3_384;
        *general = FALSE;
        break;
    case CKM_IBM_SHA3_512_HMAC:
        *digest_mech = CKM_IBM_SHA3_512;
        *general = FALSE;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }
    return CKR_OK;
}

CK_RV digest_from_kdf(CK_EC_KDF_TYPE kdf, CK_MECHANISM_TYPE *mech)
{
    switch (kdf) {
    case CKD_SHA1_KDF:
    case CKD_SHA1_KDF_SP800:
    case CKD_IBM_HYBRID_SHA1_KDF:
        *mech = CKM_SHA_1;
        break;
    case CKD_SHA224_KDF:
    case CKD_SHA224_KDF_SP800:
    case CKD_IBM_HYBRID_SHA224_KDF:
        *mech = CKM_SHA224;
        break;
    case CKD_SHA256_KDF:
    case CKD_SHA256_KDF_SP800:
    case CKD_IBM_HYBRID_SHA256_KDF:
        *mech = CKM_SHA256;
        break;
    case CKD_SHA384_KDF:
    case CKD_SHA384_KDF_SP800:
    case CKD_IBM_HYBRID_SHA384_KDF:
        *mech = CKM_SHA384;
        break;
    case CKD_SHA512_KDF:
    case CKD_SHA512_KDF_SP800:
    case CKD_IBM_HYBRID_SHA512_KDF:
        *mech = CKM_SHA512;
        break;
    case CKD_SHA3_224_KDF:
    case CKD_SHA3_224_KDF_SP800:
        *mech = CKM_SHA3_224;
        break;
    case CKD_SHA3_256_KDF:
    case CKD_SHA3_256_KDF_SP800:
        *mech = CKM_SHA3_256;
        break;
    case CKD_SHA3_384_KDF:
    case CKD_SHA3_384_KDF_SP800:
        *mech = CKM_SHA3_384;
        break;
    case CKD_SHA3_512_KDF:
    case CKD_SHA3_512_KDF_SP800:
        *mech = CKM_SHA3_512;
        break;
    default:
        TRACE_ERROR("Error unsupported KDF %ld.\n", kdf);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

CK_RV get_digest_from_mech(CK_MECHANISM_TYPE mech, CK_MECHANISM_TYPE *digest)
{
    switch (mech) {
#if !(NOMD2)
    case CKM_MD2_RSA_PKCS:
        *digest = CKM_MD2;
        break;
#endif
    case CKM_MD5_RSA_PKCS:
        *digest = CKM_MD5;
        break;
    case CKM_ECDSA_SHA1:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
        *digest = CKM_SHA_1;
        break;
    case CKM_ECDSA_SHA224:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS_PSS:
        *digest = CKM_SHA224;
        break;
    case CKM_ECDSA_SHA256:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
        *digest = CKM_SHA256;
        break;
    case CKM_ECDSA_SHA384:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
        *digest = CKM_SHA384;
        break;
    case CKM_ECDSA_SHA512:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
        *digest = CKM_SHA512;
        break;
    case CKM_ECDSA_SHA3_224:
    case CKM_SHA3_224_RSA_PKCS:
    case CKM_SHA3_224_RSA_PKCS_PSS:
        *digest = CKM_SHA3_224;
        break;
    case CKM_ECDSA_SHA3_256:
    case CKM_SHA3_256_RSA_PKCS:
    case CKM_SHA3_256_RSA_PKCS_PSS:
        *digest = CKM_SHA3_256;
        break;
    case CKM_ECDSA_SHA3_384:
    case CKM_SHA3_384_RSA_PKCS:
    case CKM_SHA3_384_RSA_PKCS_PSS:
        *digest = CKM_SHA3_384;
        break;
    case CKM_ECDSA_SHA3_512:
    case CKM_SHA3_512_RSA_PKCS:
    case CKM_SHA3_512_RSA_PKCS_PSS:
        *digest = CKM_SHA3_512;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

/* helper function for rsa-oaep and rsa-pss */
CK_RV get_mgf_mech(CK_RSA_PKCS_MGF_TYPE mgf, CK_MECHANISM_TYPE *mech)
{
    switch (mgf) {
    case CKG_MGF1_SHA1:
        *mech = CKM_SHA_1;
        break;
    case CKG_MGF1_SHA224:
        *mech = CKM_SHA224;
        break;
    case CKG_MGF1_SHA256:
        *mech = CKM_SHA256;
        break;
    case CKG_MGF1_SHA384:
        *mech = CKM_SHA384;
        break;
    case CKG_MGF1_SHA512:
        *mech = CKM_SHA512;
        break;
    case CKG_MGF1_SHA3_224:
        *mech = CKM_SHA3_224;
        break;
    case CKG_MGF1_SHA3_256:
        *mech = CKM_SHA3_256;
        break;
    case CKG_MGF1_SHA3_384:
        *mech = CKM_SHA3_384;
        break;
    case CKG_MGF1_SHA3_512:
        *mech = CKM_SHA3_512;
        break;
    case CKG_IBM_MGF1_SHA3_224:
        *mech = CKM_IBM_SHA3_224;
        break;
    case CKG_IBM_MGF1_SHA3_256:
        *mech = CKM_IBM_SHA3_256;
        break;
    case CKG_IBM_MGF1_SHA3_384:
        *mech = CKM_IBM_SHA3_384;
        break;
    case CKG_IBM_MGF1_SHA3_512:
        *mech = CKM_IBM_SHA3_512;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}
