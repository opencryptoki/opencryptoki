/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef OCK_STRINGTRANSLATIONS_H
#define OCK_STRINGTRANSLATIONS_H

#include <string.h>
#include <pkcs11types.h>
#include "ec_defs.h"
#include "mechtable.h"

/*
 * Translate a string of a given length CK_RVo a mechanism id.
 */
static inline CK_RV translate_string_to_mech(const char *str, size_t len,
                                             CK_ULONG *mech)
{
    (void)len;
    const struct mechrow *col = mechrow_from_string(str);

    if (col) {
        *mech = col->numeric;
        return CKR_OK;
    }
    return CKR_FUNCTION_FAILED;
}

/*
 * Translate an elliptic curve name (all caps) of a given length CK_RVo
 * a struct _ec.
 */
CK_RV translate_string_to_curve(const char *str, size_t len,
                                const struct _ec **curve);

CK_RV translate_string_to_mgf(const char *str, size_t len, CK_ULONG* mgf);

CK_RV translate_string_to_kdf(const char *str, size_t len, CK_ULONG* kdf);

static inline CK_RV translate_string_to_prf(const char *str, size_t len,
                                            CK_ULONG* prf)
{
    (void)len;
    if (strcmp(str, "CKP_PKCS5_PBKD2_HMAC_SHA256") == 0) {
        *prf = CKP_PKCS5_PBKD2_HMAC_SHA256;
        return CKR_OK;
    }
    if (strcmp(str, "CKP_PKCS5_PBKD2_HMAC_SHA512") == 0) {
        *prf = CKP_PKCS5_PBKD2_HMAC_SHA512;
        return CKR_OK;
    }
    return CKR_FUNCTION_FAILED;
}    

#endif
