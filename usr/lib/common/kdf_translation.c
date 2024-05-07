/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#include <string.h>
#include <pkcs11types.h>

CK_RV translate_string_to_kdf(const char *str, size_t len, CK_ULONG* kdf)
{
    switch(len) {
    case 8:
        if (strcmp("CKD_NULL", str) == 0) {
            *kdf = CKD_NULL;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 12:
        if (strcmp("CKD_SHA1_KDF", str) == 0) {
            *kdf = CKD_SHA1_KDF;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 17:
        if (strcmp("CKD_SHA1_KDF_ASN1", str) == 0) {
            *kdf = CKD_SHA1_KDF_ASN1;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 24:
        if (strcmp("CKD_SHA1_KDF_CONCATENATE", str) == 0) {
            *kdf = CKD_SHA1_KDF_CONCATENATE;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 14:
        if (strcmp("CKD_SHA224_KDF", str) == 0) {
            *kdf = CKD_SHA224_KDF;
            return CKR_OK;
        }
        if (strcmp("CKD_SHA256_KDF", str) == 0) {
            *kdf = CKD_SHA256_KDF;
            return CKR_OK;
        }
        if (strcmp("CKD_SHA384_KDF", str) == 0) {
            *kdf = CKD_SHA384_KDF;
            return CKR_OK;
        }
        if (strcmp("CKD_SHA512_KDF", str) == 0) {
            *kdf = CKD_SHA512_KDF;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 16:
        if (strcmp("CKD_SHA3_224_KDF", str) == 0) {
            *kdf = CKD_SHA3_224_KDF;
            return CKR_OK;
        }
        if (strcmp("CKD_SHA3_256_KDF", str) == 0) {
            *kdf = CKD_SHA3_256_KDF;
            return CKR_OK;
        }
        if (strcmp("CKD_SHA3_384_KDF", str) == 0) {
            *kdf = CKD_SHA3_384_KDF;
            return CKR_OK;
        }
        if (strcmp("CKD_SHA3_512_KDF", str) == 0) {
            *kdf = CKD_SHA3_512_KDF;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 19:
        if (strcmp("CKD_IBM_HYBRID_NULL", str) == 0) {
            *kdf = CKD_IBM_HYBRID_NULL;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 23:
        if (strcmp("CKD_IBM_HYBRID_SHA1_KDF", str) == 0) {
            *kdf = CKD_IBM_HYBRID_SHA1_KDF;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 25:
        if (strcmp("CKD_IBM_HYBRID_SHA224_KDF", str) == 0) {
            *kdf = CKD_IBM_HYBRID_SHA224_KDF;
            return CKR_OK;
        }
        if (strcmp("CKD_IBM_HYBRID_SHA256_KDF", str) == 0) {
            *kdf = CKD_IBM_HYBRID_SHA256_KDF;
            return CKR_OK;
        }
        if (strcmp("CKD_IBM_HYBRID_SHA384_KDF", str) == 0) {
            *kdf = CKD_IBM_HYBRID_SHA384_KDF;
            return CKR_OK;
        }
        if (strcmp("CKD_IBM_HYBRID_SHA512_KDF", str) == 0) {
            *kdf = CKD_IBM_HYBRID_SHA512_KDF;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    default:
        return CKR_FUNCTION_FAILED;
    }
}
