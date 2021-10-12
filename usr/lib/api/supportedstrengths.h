/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#ifndef OCK_SUPPORTEDSTRENGTHS_H
#define OCK_SUPPORTEDSTRENGTHS_H

/* The number of supported non-0 strengths. */
#define NUM_SUPPORTED_STRENGTHS 4

#define POLICY_STRENGTH_IDX_0   NUM_SUPPORTED_STRENGTHS
#define POLICY_STRENGTH_IDX_112 3
#define POLICY_STRENGTH_IDX_128 2
#define POLICY_STRENGTH_IDX_192 1
#define POLICY_STRENGTH_IDX_256 0

/* Non-0 supported strengths in descending order. */
extern const CK_ULONG supportedstrengths[NUM_SUPPORTED_STRENGTHS];

#endif
