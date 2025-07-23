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
#include <stdint.h>
#include <sys/types.h>
#include <pkcs11types.h>
#include <ec_curves.h>
#include "ec_defs.h"

static int get_curve_index(const char *str)
{
    /* Keep in sync with the order in der_ec_supported */
    static const struct nameidxmapping {
        const char *name;
        int         idx;
    } mappings[] = {
            { "BRAINPOOL_P160R1",  0 },
            { "BRAINPOOL_P160T1",  1 },
            { "BRAINPOOL_P192R1",  2 },
            { "BRAINPOOL_P192T1",  3 },
            { "BRAINPOOL_P224R1",  4 },
            { "BRAINPOOL_P224T1",  5 },
            { "BRAINPOOL_P256R1",  6 },
            { "BRAINPOOL_P256T1",  7 },
            { "BRAINPOOL_P320R1",  8 },
            { "BRAINPOOL_P320T1",  9 },
            { "BRAINPOOL_P384R1", 10 },
            { "BRAINPOOL_P384T1", 11 },
            { "BRAINPOOL_P512R1", 12 },
            { "BRAINPOOL_P512T1", 13 },
            { "PRIME192V1",       14 },
            { "SECP224R1",        15 },
            { "PRIME256V1",       16 },
            { "SECP384R1",        17 },
            { "SECP521R1",        18 },
            { "SECP256K1",        19 },
            { "CURVE25519",       20 },
            { "CURVE448",         21 },
            { "ED25519",          22 },
            { "ED448",            23 },
            { "BLS12_381",        24 },
    };
    size_t i;

    for (i = 0; i < sizeof(mappings) / sizeof(struct nameidxmapping); ++i) {
        if (strcmp(mappings[i].name, str) == 0)
            return i;
    }
    return -1;
}

CK_RV translate_string_to_curve(const char *str, size_t len,
                                const struct _ec **curve)
{
    (void)len;
    int idx = get_curve_index(str);
    if (idx >= 0) {
        *curve = &der_ec_supported[idx];
        return CKR_OK;
    }
    return CKR_FUNCTION_FAILED;
}
