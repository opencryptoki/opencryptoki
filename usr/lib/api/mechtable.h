/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef OCK_MECHTABLE_H
#define OCK_MECHTABLE_H

#include <stdint.h>

#include <pkcs11types.h>

/* This include can only be done once the file is generated.  Since
   the generator itself includes the current header file before
   generating mechtable-gen.h, we have to guard the include. */
#ifndef MECHTABLE_IN_GEN
#  include "mechtable-gen.h"
#endif

/* block size or output size not available */
#define MC_INFORMATION_UNAVAILABLE 0xffffu
/* output size depends on key*/
#define MC_KEY_DEPENDENT           0xfffeu

/*** Flags ***/
#define MCF_DIGEST            (1u <<  0u)
#define MCF_SIGNVERIFY        (1u <<  1u)
#define MCF_ENCRYPTDECRYPT    (1u <<  2u)
#define MCF_KEYGEN            (1u <<  3u)
#define MCF_WRAPUNWRAP        (1u <<  4u)
#define MCF_DERIVE            (1u <<  5u)
#define MCF_ENDECAPS          (1u <<  6u)

#define MCF_NEEDSPARAM        (1u <<  8u)
#define MCF_OPTIONALPARAM     (1u <<  9u)
#define MCF_MAC_GENERAL       (1u << 10u)

struct mechrow {
    const char *      string;
    CK_MECHANISM_TYPE numeric;
    uint16_t          blocksize;
    /* the maximum size of general macs */
    uint16_t          outputsize;
    uint32_t          flags;
};

struct mechtable_funcs {
    int (*p_idx_from_num)(CK_ULONG mech);
    int (*p_idx_from_str)(const char *mech);
    const struct mechrow *(*p_row_from_num)(CK_ULONG mech);
    const struct mechrow *(*p_row_from_str)(const char *mech);
};

extern const struct mechtable_funcs mechtable_funcs;

/* The table.  It has exactly MECHTABLE_NUM_ELEMS elements.  The
   constant is in the generated header mechtable-gen.h which is
   included by this header. */
extern const struct mechrow mechtable_rows[];

/*** Index functions ***/
/* Locate a table row by numeric value of the mechanism.  Returns -1
   if the name is invalid. */
int mechtable_idx_from_numeric(CK_ULONG mech);

/* Locate a table row by a string key.  This respects aliases, so the
   row at the returned index might have a different string
   representation if the name changed in the meantime.  Returns -1 if
   the name is invalid. */
int mechtable_idx_from_string(const char *mech);

/* Translate a mechanism number into a mechanism column.
   Returns NULL if the mechanism number is not known to the table. */
const struct mechrow *mechrow_from_numeric(CK_ULONG mech);

/* Translate a mechanism name into a mechanism column.
   Returns NULL if the mechanism name is not known to the table. */
const struct mechrow *mechrow_from_string(const char *mech);

#endif
