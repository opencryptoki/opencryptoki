/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#include <ec_curves.h>

typedef enum {
    no_cmd, gen_key, list_key, remove_key
} p11sak_cmd;

/*
 * The first enum items are for SYMMETRIC keys for kt <= 2.
 * The last enum items are for ASYMMETRIC keys for kt >= 3
 */
typedef enum {
    kt_DES,
    kt_3DES,
    kt_AES,
    kt_AES_XTS,
    kt_RSAPKCS,
    kt_EC,
    kt_IBM_DILITHIUM,
    kt_IBM_KYBER,
    kt_GENERIC,
    kt_SECRET,
    kt_PUBLIC,
    kt_PRIVATE,
    kt_ALL,
    no_key_type
} p11sak_kt;

#define  KEY_MAX_BOOL_ATTR_COUNT 15
#define  SEC_KEY_MAX_BOOL_ATTR_COUNT 15
#define  PRV_KEY_MAX_BOOL_ATTR_COUNT 12
#define  PUB_KEY_MAX_BOOL_ATTR_COUNT 8

#define P11SAK_DEFAULT_CONF_FILE OCK_CONFDIR "/p11sak_defined_attrs.conf"

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

CK_BBOOL ckb_true = CK_TRUE;
CK_BBOOL ckb_false = CK_FALSE;
