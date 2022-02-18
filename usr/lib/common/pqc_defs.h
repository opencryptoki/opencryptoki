/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef _PQC_DEFS
#define _PQC_DEFS

#include <stdio.h>

#include "pqc_oids.h"

extern const CK_BYTE dilithium_r2_65[];
extern const CK_ULONG dilithium_r2_65_len;
extern const CK_BYTE dilithium_r2_87[];
extern const CK_ULONG dilithium_r2_87_len;
extern const CK_BYTE dilithium_r3_44[];
extern const CK_ULONG dilithium_r3_44_len;
extern const CK_BYTE dilithium_r3_56[];
extern const CK_ULONG dilithium_r3_56_len;
extern const CK_BYTE dilithium_r3_87[];
extern const CK_ULONG dilithium_r3_87_len;

extern const CK_BYTE kyber_r2_768[];
extern const CK_ULONG kyber_r2_768_len;
extern const CK_BYTE kyber_r2_1024[];
extern const CK_ULONG kyber_r2_1024_len;

struct pqc_oid {
    const CK_BYTE *oid;
    CK_ULONG oid_len;
    CK_ULONG keyform;
    CK_ULONG policy_size;
    CK_ULONG policy_siglen;
};

extern const struct pqc_oid dilithium_oids[];
extern const struct pqc_oid kyber_oids[];

const struct pqc_oid *find_pqc_by_keyform(const struct pqc_oid *pqcs,
                                          CK_ULONG keyform);
const struct pqc_oid *find_pqc_by_oid(const struct pqc_oid *pqcs,
                                      CK_BYTE *oid, CK_ULONG oid_len);

#endif
