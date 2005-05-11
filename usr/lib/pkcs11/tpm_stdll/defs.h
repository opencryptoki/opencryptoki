
/* (C) COPYRIGHT International Business Machines Corp. 2001, 2002, 2005 */


// File:  defs.h
//
// Contains various definitions needed by both the host-side
// and coprocessor-side code.
//

#ifndef _TPM_DEFS_H
#define _TPM_DEFS_H

#include "../common/defs.h"

#undef MAX_PIN_LEN
#undef MIN_PIN_LEN
#define MAX_PIN_LEN           127
#define MIN_PIN_LEN           6

#endif
