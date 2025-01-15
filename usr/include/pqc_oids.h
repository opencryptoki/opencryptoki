/*
 * COPYRIGHT (c) International Business Machines Corp. 2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */


#ifndef _PQC_OIDS_H_
#define _PQC_OIDS_H_

/*
 * OIDs and their DER encoding for the post-quantum crypto algorithms
 * supported by OpenCryptoki:
 */

/* Dilithium Round 2 high-security (SHAKE-256): 1.3.6.1.4.1.2.267.1.6.5 */
#define OCK_DILITHIUM_R2_65        { 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, \
                                     0x01, 0x02, 0x82, 0x0B, 0x01, 0x06, 0x05 }

/* Dilithium Round 2 for outbound authentication: 1.3.6.1.4.1.2.267.1.8.7 */
#define OCK_DILITHIUM_R2_87        { 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, \
                                     0x01, 0x02, 0x82, 0x0B, 0x01, 0x08, 0x07 }

/* Dilithium Round 3 weak (SHAKE-256): 1.3.6.1.4.1.2.267.7.4.4 */
#define OCK_DILITHIUM_R3_44        { 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, \
                                     0x01, 0x02, 0x82, 0x0B, 0x07, 0x04, 0x04 }

/* Dilithium Round 3 recommended (SHAKE-256): 1.3.6.1.4.1.2.267.7.6.5 */
#define OCK_DILITHIUM_R3_65        { 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, \
                                     0x01, 0x02, 0x82, 0x0B, 0x07, 0x06, 0x05 }

/* Dilithium Round 3 high-security (SHAKE-256): 1.3.6.1.4.1.2.267.7.8.7 */
#define OCK_DILITHIUM_R3_87        { 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, \
                                     0x01, 0x02, 0x82, 0x0B, 0x07, 0x08, 0x07 }

/* Kyber Round 2 768 (SHAKE-128): 1.3.6.1.4.1.2.267.5.3.3 */
#define OCK_KYBER_R2_768           { 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, \
                                     0x01, 0x02, 0x82, 0x0B, 0x05, 0x03, 0x03 }

/* Kyber Round 2 1024 (SHAKE-128): 1.3.6.1.4.1.2.267.5.4.4 */
#define OCK_KYBER_R2_1024          { 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, \
                                     0x01, 0x02, 0x82, 0x0B, 0x05, 0x04, 0x04 }

/* ML-DSA 44: 2.16.840.1.101.3.4.3.17 */
#define OCK_ML_DSA_44              { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, \
                                     0x65, 0x03, 0x04, 0x03, 0x11 }

/* ML-DSA 65: 2.16.840.1.101.3.4.3.18 */
#define OCK_ML_DSA_65              { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, \
                                     0x65, 0x03, 0x04, 0x03, 0x12 }

/* ML-DSA 87: 2.16.840.1.101.3.4.3.19 */
#define OCK_ML_DSA_87              { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, \
                                     0x65, 0x03, 0x04, 0x03, 0x13 }

/* ML-KEM 512: 2.16.840.1.101.3.4.4.1 */
#define OCK_ML_KEM_512             { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, \
                                     0x65, 0x03, 0x04, 0x04, 0x01 }

/* ML-KEM 768: 2.16.840.1.101.3.4.4.2 */
#define OCK_ML_KEM_786             { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, \
                                     0x65, 0x03, 0x04, 0x04, 0x02 }

/* ML-KEM 1024: 2.16.840.1.101.3.4.4.3 */
#define OCK_ML_KEM_1024            { 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, \
                                     0x65, 0x03, 0x04, 0x04, 0x03 }

#endif                          // _PQC_OIDS_H_
