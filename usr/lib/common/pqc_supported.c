/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <string.h>
#include "pkcs11types.h"
#include "pqc_defs.h"

const CK_BYTE dilithium_r2_65[] = OCK_DILITHIUM_R2_65;
const CK_ULONG dilithium_r2_65_len = sizeof(dilithium_r2_65);
const CK_BYTE dilithium_r2_87[] = OCK_DILITHIUM_R2_87;
const CK_ULONG dilithium_r2_87_len = sizeof(dilithium_r2_87);
const CK_BYTE dilithium_r3_44[] = OCK_DILITHIUM_R3_44;
const CK_ULONG dilithium_r3_44_len = sizeof(dilithium_r3_44);
const CK_BYTE dilithium_r3_65[] = OCK_DILITHIUM_R3_65;
const CK_ULONG dilithium_r3_65_len = sizeof(dilithium_r3_65);
const CK_BYTE dilithium_r3_87[] = OCK_DILITHIUM_R3_87;
const CK_ULONG dilithium_r3_87_len = sizeof(dilithium_r3_87);

const struct pqc_oid dilithium_oids[] = {
    { .oid = dilithium_r2_65, .oid_len = dilithium_r2_65_len,
      .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND2_65,
      .policy_size = 256, .policy_siglen = 3366 },
    { .oid = dilithium_r2_87, .oid_len = dilithium_r2_87_len,
      .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND2_87,
      .policy_size = 256, .policy_siglen = 4668 },
    { .oid = dilithium_r3_44, .oid_len = dilithium_r3_44_len,
      .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND3_44,
      .policy_size = 256, .policy_siglen = 2420 },
    { .oid = dilithium_r3_65, .oid_len = dilithium_r3_65_len,
      .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND3_65,
      .policy_size = 256, .policy_siglen = 3293 },
    { .oid = dilithium_r3_87, .oid_len = dilithium_r3_87_len,
      .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND3_87,
      .policy_size = 256, .policy_siglen = 4595 },
    { .oid = NULL, .oid_len = 0, .keyform = 0,
      .policy_size = 0, .policy_siglen = 0 }
};

const CK_BYTE kyber_r2_768[] = OCK_KYBER_R2_768;
const CK_ULONG kyber_r2_768_len = sizeof(kyber_r2_768);
const CK_BYTE kyber_r2_1024[] = OCK_KYBER_R2_1024;
const CK_ULONG kyber_r2_1024_len = sizeof(kyber_r2_1024);

const struct pqc_oid kyber_oids[] = {
    { .oid = kyber_r2_768, .oid_len = kyber_r2_768_len,
       .keyform = CK_IBM_KYBER_KEYFORM_ROUND2_768,
       .policy_size = 256, .policy_siglen = 0 },
    { .oid = kyber_r2_1024, .oid_len = kyber_r2_1024_len,
      .keyform = CK_IBM_KYBER_KEYFORM_ROUND2_1024,
      .policy_size = 256, .policy_siglen = 0 },
    { .oid = NULL, .oid_len = 0, .keyform = 0,
      .policy_size = 0, .policy_siglen = 0 }
};

const struct pqc_oid *find_pqc_by_keyform(const struct pqc_oid *pqcs,
                                          CK_ULONG keyform)
{
    CK_ULONG i;

    for (i = 0; pqcs[i].oid != NULL; i++) {
        if (pqcs[i].keyform == keyform)
            return &pqcs[i];
    }

    return NULL;
}

const struct pqc_oid *find_pqc_by_oid(const struct pqc_oid *pqcs,
                                      CK_BYTE *oid, CK_ULONG oid_len)
{
    CK_ULONG i;

    for (i = 0; pqcs[i].oid != NULL; i++) {
        if (pqcs[i].oid_len == oid_len &&
            memcmp(pqcs[i].oid, oid, oid_len) == 0)
            return &pqcs[i];
    }

    return NULL;
}
