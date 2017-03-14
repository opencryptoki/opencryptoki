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

#ifndef _TPM_DEFS_H
#define _TPM_DEFS_H

#include "../common/defs.h"

#undef MAX_PIN_LEN
#undef MIN_PIN_LEN
#define MAX_PIN_LEN           127
#define MIN_PIN_LEN           6

#endif
