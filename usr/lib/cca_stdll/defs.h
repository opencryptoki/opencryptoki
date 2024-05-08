/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/* File:  defs.h
 *
 * Contains various definitions needed by both the host-side
 * and coprocessor-side code.
 */

#ifndef _CCA_DEFS_H
#define _CCA_DEFS_H

#include "../common/defs.h"

#undef MAX_PIN_LEN
#undef MIN_PIN_LEN
#define MAX_PIN_LEN 128
#define MIN_PIN_LEN   4

#define CCA_CHAIN_VECTOR_SHA3_LEN  256
#define CCA_HASH_PART_FIRST        0
#define CCA_HASH_PART_MIDDLE       1
#define CCA_HASH_PART_LAST         2
#define CCA_HASH_PART_ONLY         3

struct cca_sha_ctx {
    unsigned char chain_vector[CCA_CHAIN_VECTOR_SHA3_LEN];
    long chain_vector_len;
    unsigned char tail[MAX_SHA_BLOCK_SIZE];
    long tail_len;
    unsigned char hash[MAX_SHA_HASH_SIZE];
    long hash_len;
    int part;
};

#endif
