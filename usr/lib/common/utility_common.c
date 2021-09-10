/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include "pkcs11types.h"
#include "defs.h"

CK_RV get_sha_size(CK_ULONG mech, CK_ULONG *hsize)
{
    switch (mech) {
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
    case CKM_IBM_SHA3_224:
        *hsize = SHA3_224_HASH_SIZE;
        break;
    case CKM_IBM_SHA3_256:
        *hsize = SHA3_256_HASH_SIZE;
        break;
    case CKM_IBM_SHA3_384:
        *hsize = SHA3_384_HASH_SIZE;
        break;
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
    case CKM_IBM_SHA3_224:
        *bsize = SHA3_224_BLOCK_SIZE;
        break;
    case CKM_IBM_SHA3_256:
        *bsize = SHA3_256_BLOCK_SIZE;
        break;
    case CKM_IBM_SHA3_384:
        *bsize = SHA3_384_BLOCK_SIZE;
        break;
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
    case CKM_MD2_HMAC:
    case CKM_MD2_HMAC_GENERAL:
        *digest_mech = CKM_MD2;
        *general = (mech == CKM_MD2_HMAC_GENERAL);
        break;
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
