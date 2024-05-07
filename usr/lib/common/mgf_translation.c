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

CK_RV translate_string_to_mgf(const char *str, size_t len, CK_ULONG* mgf)
{
    switch(len) {
    case 13:
        if (strcmp("CKG_MGF1_SHA1", str) == 0) {
            *mgf = CKG_MGF1_SHA1;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 15:
        if (strcmp("CKG_MGF1_SHA224", str) == 0) {
            *mgf = CKG_MGF1_SHA224;
            return CKR_OK;
        }
        if (strcmp("CKG_MGF1_SHA256", str) == 0) {
            *mgf = CKG_MGF1_SHA256;
            return CKR_OK;
        }
        if (strcmp("CKG_MGF1_SHA384", str) == 0) {
            *mgf = CKG_MGF1_SHA384;
            return CKR_OK;
        }
        if (strcmp("CKG_MGF1_SHA512", str) == 0) {
            *mgf = CKG_MGF1_SHA512;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 17:
        if (strcmp("CKG_MGF1_SHA3_224", str) == 0) {
            *mgf = CKG_MGF1_SHA3_224;
            return CKR_OK;
        }
        if (strcmp("CKG_MGF1_SHA3_256", str) == 0) {
            *mgf = CKG_MGF1_SHA3_256;
            return CKR_OK;
        }
        if (strcmp("CKG_MGF1_SHA3_384", str) == 0) {
            *mgf = CKG_MGF1_SHA3_384;
            return CKR_OK;
        }
        if (strcmp("CKG_MGF1_SHA3_512", str) == 0) {
            *mgf = CKG_MGF1_SHA3_512;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    case 21:
        if (strcmp("CKG_IBM_MGF1_SHA3_224", str) == 0) {
            *mgf = CKG_IBM_MGF1_SHA3_224;
            return CKR_OK;
        }
        if (strcmp("CKG_IBM_MGF1_SHA3_256", str) == 0) {
            *mgf = CKG_IBM_MGF1_SHA3_256;
            return CKR_OK;
        }
        if (strcmp("CKG_IBM_MGF1_SHA3_384", str) == 0) {
            *mgf = CKG_IBM_MGF1_SHA3_384;
            return CKR_OK;
        }
        if (strcmp("CKG_IBM_MGF1_SHA3_512", str) == 0) {
            *mgf = CKG_IBM_MGF1_SHA3_512;
            return CKR_OK;
        }
        return CKR_FUNCTION_FAILED;
    default:
        return CKR_FUNCTION_FAILED;
    }
}
