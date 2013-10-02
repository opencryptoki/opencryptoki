
/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */


// File:  defs.h
//
// Contains various definitions needed by both the host-side
// and coprocessor-side code.
//

#ifndef _CCA_DEFS_H
#define _CCA_DEFS_H

#include "../common/defs.h"

#undef MAX_PIN_LEN
#undef MIN_PIN_LEN
#define MAX_PIN_LEN 128
#define MIN_PIN_LEN   4

#define CCA_CHAIN_VECTOR_LEN     128
#define CCA_MAX_TAIL_LEN          64
#define CCA_HASH_PART_FIRST        0
#define CCA_HASH_PART_MIDDLE       1
#define CCA_HASH_PART_LAST         2
#define CCA_HASH_PART_ONLY         3

struct cca_sha256_ctx {
	unsigned char chain_vector[CCA_CHAIN_VECTOR_LEN];
	long chain_vector_len;
	unsigned char *tail;
	unsigned long tail_len;
	unsigned char scratch[SHA2_HASH_SIZE];
	unsigned long scratch_len;
	int part;
};

#endif
