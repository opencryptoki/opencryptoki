/*
 * COPYRIGHT (c) International Business Machines Corp. 2021
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */
#include "pkcs11types.h"
#include "ec_defs.h"

#include "openssl/obj_mac.h"
#include <openssl/ec.h>

#ifndef NID_brainpoolP160r1
/*
 * Older OpenSSL versions may not have the brainpool NIDs defined, define them
 * here
 */
#define NID_brainpoolP160r1             921
#define NID_brainpoolP160t1             922
#define NID_brainpoolP192r1             923
#define NID_brainpoolP192t1             924
#define NID_brainpoolP224r1             925
#define NID_brainpoolP224t1             926
#define NID_brainpoolP256r1             927
#define NID_brainpoolP256t1             928
#define NID_brainpoolP320r1             929
#define NID_brainpoolP320t1             930
#define NID_brainpoolP384r1             931
#define NID_brainpoolP384t1             932
#define NID_brainpoolP512r1             933
#define NID_brainpoolP512t1             934

#endif

#ifndef NID_X25519
#define NID_X25519                      1034
#define NID_X448                        1035
#endif
#ifndef NID_ED25519
#define NID_ED25519                     1087
#define NID_ED448                       1088
#endif

const CK_BYTE brainpoolP160r1[] = OCK_BRAINPOOL_P160R1;
const CK_BYTE brainpoolP160t1[] = OCK_BRAINPOOL_P160T1;
const CK_BYTE brainpoolP192r1[] = OCK_BRAINPOOL_P192R1;
const CK_BYTE brainpoolP192t1[] = OCK_BRAINPOOL_P192T1;
const CK_BYTE brainpoolP224r1[] = OCK_BRAINPOOL_P224R1;
const CK_BYTE brainpoolP224t1[] = OCK_BRAINPOOL_P224T1;
const CK_BYTE brainpoolP256r1[] = OCK_BRAINPOOL_P256R1;
const CK_BYTE brainpoolP256t1[] = OCK_BRAINPOOL_P256T1;
const CK_BYTE brainpoolP320r1[] = OCK_BRAINPOOL_P320R1;
const CK_BYTE brainpoolP320t1[] = OCK_BRAINPOOL_P320T1;
const CK_BYTE brainpoolP384r1[] = OCK_BRAINPOOL_P384R1;
const CK_BYTE brainpoolP384t1[] = OCK_BRAINPOOL_P384T1;
const CK_BYTE brainpoolP512r1[] = OCK_BRAINPOOL_P512R1;
const CK_BYTE brainpoolP512t1[] = OCK_BRAINPOOL_P512T1;
const CK_BYTE prime192v1[] = OCK_PRIME192V1;
const CK_BYTE secp224r1[] = OCK_SECP224R1;
const CK_BYTE prime256v1[] = OCK_PRIME256V1;
const CK_BYTE secp384r1[] = OCK_SECP384R1;
const CK_BYTE secp521r1[] = OCK_SECP521R1;
const CK_BYTE secp256k1[] = OCK_SECP256K1;
const CK_BYTE curve25519[] = OCK_CURVE25519;
const CK_BYTE curve448[] = OCK_CURVE448;
const CK_BYTE ed25519[] = OCK_ED25519;
const CK_BYTE ed448[] = OCK_ED448;
const CK_BYTE bls12_381[] = OCK_BLS12_381;

const struct _ec der_ec_supported[NUMEC] = {
    {BRAINPOOL_CURVE, CURVE160, CURVE160, NID_brainpoolP160r1, CK_FALSE,
            sizeof(brainpoolP160r1), &brainpoolP160r1},
    {BRAINPOOL_CURVE, CURVE160, CURVE160, NID_brainpoolP160t1, CK_TRUE,
            sizeof(brainpoolP160t1), &brainpoolP160t1},
    {BRAINPOOL_CURVE, CURVE192, CURVE192, NID_brainpoolP192r1, CK_FALSE,
            sizeof(brainpoolP192r1), &brainpoolP192r1},
    {BRAINPOOL_CURVE, CURVE192, CURVE192, NID_brainpoolP192t1, CK_TRUE,
            sizeof(brainpoolP192t1), &brainpoolP192t1},
    {BRAINPOOL_CURVE, CURVE224, CURVE224, NID_brainpoolP224r1, CK_FALSE,
            sizeof(brainpoolP224r1), &brainpoolP224r1},
    {BRAINPOOL_CURVE, CURVE224, CURVE224, NID_brainpoolP224t1, CK_TRUE,
            sizeof(brainpoolP224t1), &brainpoolP224t1},
    {BRAINPOOL_CURVE, CURVE256, CURVE256, NID_brainpoolP256r1, CK_FALSE,
            sizeof(brainpoolP256r1), &brainpoolP256r1},
    {BRAINPOOL_CURVE, CURVE256, CURVE256, NID_brainpoolP256t1, CK_TRUE,
            sizeof(brainpoolP256t1), &brainpoolP256t1},
    {BRAINPOOL_CURVE, CURVE320, CURVE320, NID_brainpoolP320r1, CK_FALSE,
            sizeof(brainpoolP320r1), &brainpoolP320r1},
    {BRAINPOOL_CURVE, CURVE320, CURVE320, NID_brainpoolP320t1, CK_TRUE,
            sizeof(brainpoolP320t1), &brainpoolP320t1},
    {BRAINPOOL_CURVE, CURVE384, CURVE384, NID_brainpoolP384r1, CK_FALSE,
            sizeof(brainpoolP384r1), &brainpoolP384r1},
    {BRAINPOOL_CURVE, CURVE384, CURVE384, NID_brainpoolP384t1, CK_TRUE,
            sizeof(brainpoolP384t1), &brainpoolP384t1},
    {BRAINPOOL_CURVE, CURVE512, CURVE512, NID_brainpoolP512r1, CK_FALSE,
            sizeof(brainpoolP512r1), &brainpoolP512r1},
    {BRAINPOOL_CURVE, CURVE512, CURVE512, NID_brainpoolP512t1, CK_TRUE,
            sizeof(brainpoolP512t1), &brainpoolP512t1},
    {PRIME_CURVE, CURVE192, CURVE192, NID_X9_62_prime192v1, CK_FALSE,
            sizeof(prime192v1), &prime192v1},
    {PRIME_CURVE, CURVE224, CURVE224, NID_secp224r1, CK_FALSE,
            sizeof(secp224r1), &secp224r1},
    {PRIME_CURVE, CURVE256, CURVE256, NID_X9_62_prime256v1, CK_FALSE,
            sizeof(prime256v1), &prime256v1},
    {PRIME_CURVE, CURVE384, CURVE384, NID_secp384r1, CK_FALSE,
            sizeof(secp384r1), &secp384r1},
    {PRIME_CURVE, CURVE521, CURVE521, NID_secp521r1, CK_FALSE,
            sizeof(secp521r1), &secp521r1},
    {KOBLITZ_CURVE, CURVE256, CURVE256, NID_secp256k1, CK_FALSE,
            sizeof(secp256k1), &secp256k1},
    {MONTGOMERY_CURVE, CURVE256, CURVE256, NID_X25519, CK_FALSE,
            sizeof(curve25519), &curve25519},
    {MONTGOMERY_CURVE, CURVE456, CURVE448, NID_X448, CK_FALSE,
            sizeof(curve448), &curve448},
    {EDWARDS_CURVE, CURVE256, CURVE256, NID_ED25519, CK_FALSE,
            sizeof(ed25519), &ed25519},
    {EDWARDS_CURVE, CURVE456, CURVE448, NID_ED448, CK_FALSE,
            sizeof(ed448), &ed448},
    {BLS12_381_CURVE, CURVE384, CURVE384, NID_undef, CK_TRUE,
            sizeof(bls12_381), &bls12_381},
};
