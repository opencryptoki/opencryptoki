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
const CK_BYTE dilithium_r2_87[] = OCK_DILITHIUM_R2_87;
const CK_BYTE dilithium_r3_44[] = OCK_DILITHIUM_R3_44;
const CK_BYTE dilithium_r3_65[] = OCK_DILITHIUM_R3_65;
const CK_BYTE dilithium_r3_87[] = OCK_DILITHIUM_R3_87;

const struct pqc_oid dilithium_oids[] = {
    { .oid = dilithium_r2_65, .oid_len = sizeof(dilithium_r2_65),
      .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND2_65,
      .policy_size = 256, .policy_siglen = 3366,
      .len_info.dilithium.rho_len = 32, .len_info.dilithium.seed_len = 32,
      .len_info.dilithium.tr_len = 48, .len_info.dilithium.s1_len = 480,
      .len_info.dilithium.s2_len = 576, .len_info.dilithium.t0_len = 2688,
      .len_info.dilithium.t1_len = 1728, },
    { .oid = dilithium_r2_87, .oid_len = sizeof(dilithium_r2_87),
      .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND2_87,
      .policy_size = 256, .policy_siglen = 4668,
      .len_info.dilithium.rho_len = 32, .len_info.dilithium.seed_len = 32,
      .len_info.dilithium.tr_len = 48, .len_info.dilithium.s1_len = 672,
      .len_info.dilithium.s2_len = 768, .len_info.dilithium.t0_len = 3584,
      .len_info.dilithium.t1_len = 2304, },
    { .oid = dilithium_r3_44, .oid_len = sizeof(dilithium_r3_44),
      .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND3_44,
      .policy_size = 256, .policy_siglen = 2420,
      .len_info.dilithium.rho_len = 32, .len_info.dilithium.seed_len = 32,
      .len_info.dilithium.tr_len = 32, .len_info.dilithium.s1_len = 384,
      .len_info.dilithium.s2_len = 384, .len_info.dilithium.t0_len = 1664,
      .len_info.dilithium.t1_len = 1280, },
    { .oid = dilithium_r3_65, .oid_len = sizeof(dilithium_r3_65),
      .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND3_65,
      .policy_size = 256, .policy_siglen = 3293,
      .len_info.dilithium.rho_len = 32, .len_info.dilithium.seed_len = 32,
      .len_info.dilithium.tr_len = 32, .len_info.dilithium.s1_len = 640,
      .len_info.dilithium.s2_len = 768, .len_info.dilithium.t0_len = 2496,
      .len_info.dilithium.t1_len = 1920, },
    { .oid = dilithium_r3_87, .oid_len = sizeof(dilithium_r3_87),
      .keyform = CK_IBM_DILITHIUM_KEYFORM_ROUND3_87,
      .policy_size = 256, .policy_siglen = 4595,
      .len_info.dilithium.rho_len = 32, .len_info.dilithium.seed_len = 32,
      .len_info.dilithium.tr_len = 32, .len_info.dilithium.s1_len = 672,
      .len_info.dilithium.s2_len = 768, .len_info.dilithium.t0_len = 3328,
      .len_info.dilithium.t1_len = 2560, },
    { .oid = NULL, .oid_len = 0, .keyform = 0,
      .policy_size = 0, .policy_siglen = 0 }
};

const CK_BYTE kyber_r2_768[] = OCK_KYBER_R2_768;
const CK_BYTE kyber_r2_1024[] = OCK_KYBER_R2_1024;

const struct pqc_oid kyber_oids[] = {
    { .oid = kyber_r2_768, .oid_len = sizeof(kyber_r2_768),
       .keyform = CK_IBM_KYBER_KEYFORM_ROUND2_768,
       .policy_size = 256, .policy_siglen = 0 },
    { .oid = kyber_r2_1024, .oid_len = sizeof(kyber_r2_1024),
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
