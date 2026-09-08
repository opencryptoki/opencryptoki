# COPYRIGHT (c) International Business Machines Corp. 2026
#
# This program is provided under the terms of the Common Public License,
# version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
# software constitutes recipient's acceptance of CPL-1.0 terms which can be
# found in the file LICENSE file or at
# https://opensource.org/licenses/cpl1.0.php


"""
pkcs11_const.py — PKCS#11 attribute type and class constants.

These are the values used by openCryptoki when creating / searching objects.
Values match pkcs11types.h exactly.
"""

# CKA_* attribute types — Object class (common)
CKA_CLASS             = 0x00000000
CKA_TOKEN             = 0x00000001
CKA_PRIVATE           = 0x00000002
CKA_LABEL             = 0x00000003
CKA_APPLICATION       = 0x00000010
CKA_VALUE             = 0x00000011
CKA_OBJECT_ID         = 0x00000012
CKA_CERTIFICATE_TYPE        = 0x00000080
CKA_ISSUER                  = 0x00000081
CKA_SERIAL_NUMBER           = 0x00000082
CKA_AC_ISSUER               = 0x00000083
CKA_OWNER                   = 0x00000084
CKA_ATTR_TYPES              = 0x00000085
CKA_TRUSTED                 = 0x00000086
CKA_CERTIFICATE_CATEGORY    = 0x00000087
CKA_JAVA_MIDP_SECURITY_DOMAIN = 0x00000088
CKA_URL                     = 0x00000089
CKA_HASH_OF_SUBJECT_PUBLIC_KEY = 0x0000008A
CKA_HASH_OF_ISSUER_PUBLIC_KEY  = 0x0000008B
CKA_NAME_HASH_ALGORITHM     = 0x0000008C
CKA_CHECK_VALUE             = 0x00000090
CKA_KEY_TYPE          = 0x00000100
CKA_SUBJECT           = 0x00000101
CKA_ID                = 0x00000102
CKA_SENSITIVE         = 0x00000103
CKA_ENCRYPT           = 0x00000104
CKA_DECRYPT           = 0x00000105
CKA_WRAP              = 0x00000106
CKA_UNWRAP            = 0x00000107
CKA_SIGN              = 0x00000108
CKA_SIGN_RECOVER      = 0x00000109
CKA_VERIFY            = 0x0000010A
CKA_VERIFY_RECOVER    = 0x0000010B
CKA_DERIVE            = 0x0000010C
CKA_START_DATE        = 0x00000110
CKA_END_DATE          = 0x00000111
CKA_MODULUS           = 0x00000120
CKA_MODULUS_BITS      = 0x00000121
CKA_PUBLIC_EXPONENT   = 0x00000122
CKA_PRIVATE_EXPONENT  = 0x00000123
CKA_PRIME_1           = 0x00000124
CKA_PRIME_2           = 0x00000125
CKA_EXPONENT_1        = 0x00000126
CKA_EXPONENT_2        = 0x00000127
CKA_COEFFICIENT       = 0x00000128
CKA_PUBLIC_KEY_INFO   = 0x00000129
CKA_PRIME             = 0x00000130
CKA_SUBPRIME          = 0x00000131
CKA_BASE              = 0x00000132
CKA_PRIME_BITS        = 0x00000133
CKA_SUBPRIME_BITS     = 0x00000134
CKA_VALUE_BITS        = 0x00000160
CKA_VALUE_LEN         = 0x00000161
CKA_EXTRACTABLE       = 0x00000162
CKA_LOCAL             = 0x00000163
CKA_NEVER_EXTRACTABLE = 0x00000164
CKA_ALWAYS_SENSITIVE  = 0x00000165
CKA_KEY_GEN_MECHANISM = 0x00000166
CKA_MODIFIABLE        = 0x00000170
CKA_COPYABLE          = 0x00000171
CKA_DESTROYABLE       = 0x00000172
CKA_EC_PARAMS         = 0x00000180
CKA_EC_POINT          = 0x00000181
CKA_ALWAYS_AUTHENTICATE     = 0x00000202
CKA_WRAP_WITH_TRUSTED       = 0x00000210
CKA_WRAP_TEMPLATE           = 0x40000211
CKA_UNWRAP_TEMPLATE         = 0x40000212
CKA_DERIVE_TEMPLATE         = 0x40000213
CKA_OTP_FORMAT              = 0x00000220
CKA_ALLOWED_MECHANISMS      = 0x40000600

# CKO_* object classes (value of CKA_CLASS attribute)
CKO_DATA              = 0x00000000
CKO_CERTIFICATE       = 0x00000001
CKO_PUBLIC_KEY        = 0x00000002
CKO_PRIVATE_KEY       = 0x00000003
CKO_SECRET_KEY        = 0x00000004
CKO_HW_FEATURE        = 0x00000005
CKO_DOMAIN_PARAMETERS = 0x00000006
CKO_MECHANISM         = 0x00000007

# CKT_* certificate types (value of CKA_CERTIFICATE_TYPE)
CKC_X_509             = 0x00000000
CKC_X_509_ATTR_CERT   = 0x00000001
CKC_WTLS              = 0x00000002

# CKH_* hash algorithm IDs (used in CKA_NAME_HASH_ALGORITHM)
CKM_SHA_1             = 0x00000220
CKM_SHA256            = 0x00000250
CKM_SHA384            = 0x00000260
CKM_SHA512            = 0x00000270

# CKK_* key types
CKK_RSA               = 0x00000000
CKK_DSA               = 0x00000001
CKK_DH                = 0x00000002
CKK_EC                = 0x00000003
CKK_X9_42_DH          = 0x00000004
CKK_KEA               = 0x00000005
CKK_GENERIC_SECRET    = 0x00000010
CKK_RC2               = 0x00000011
CKK_RC4               = 0x00000012
CKK_DES               = 0x00000013
CKK_DES2              = 0x00000014
CKK_DES3              = 0x00000015
CKK_CAST              = 0x00000016
CKK_CAST3             = 0x00000017
CKK_CAST5             = 0x00000018
CKK_RC5               = 0x00000019
CKK_IDEA              = 0x0000001A
CKK_SKIPJACK          = 0x0000001B
CKK_BATON             = 0x0000001C
CKK_JUNIPER           = 0x0000001D
CKK_CDMF              = 0x0000001E
CKK_AES               = 0x0000001F
CKK_BLOWFISH          = 0x00000020
CKK_TWOFISH           = 0x00000021
CKK_SECURID           = 0x00000022
CKK_HOTP              = 0x00000023
CKK_ACTI              = 0x00000024
CKK_CAMELLIA          = 0x00000025
CKK_ARIA              = 0x00000026
CKK_SHA512_224_HMAC   = 0x00000027
CKK_SHA512_256_HMAC   = 0x00000028
CKK_SHA512_T_HMAC     = 0x00000029
CKK_SHA_1_HMAC        = 0x00000027  # alias
CKK_SEED              = 0x0000002F
CKK_IBM_DILITHIUM     = 0x80010023
CKK_IBM_KYBER         = 0x80010024

# CKM_* mechanism types (only the key-gen ones needed for CKA_KEY_GEN_MECHANISM)
CKM_RSA_PKCS_KEY_PAIR_GEN  = 0x00000000
CKM_DSA_KEY_PAIR_GEN        = 0x00000010
CKM_DH_PKCS_KEY_PAIR_GEN    = 0x00000020
CKM_DH_PKCS_DERIVE          = 0x00000021
CKM_EC_KEY_PAIR_GEN         = 0x00001040
CKM_DES_KEY_GEN             = 0x00000120
CKM_DES2_KEY_GEN            = 0x00000130
CKM_DES3_KEY_GEN            = 0x00000131
CKM_AES_KEY_GEN             = 0x00001080
CKM_GENERIC_SECRET_KEY_GEN  = 0x00000350
CKM_SSL3_PRE_MASTER_KEY_GEN = 0x00000370
CKM_SSL3_MASTER_KEY_DERIVE  = 0x00000371
CKM_SSL3_KEY_AND_MAC_DERIVE = 0x00000372
CKM_TLS_PRE_MASTER_KEY_GEN  = 0x00000374
CKM_TLS_KEY_AND_MAC_DERIVE  = 0x00000376
CKM_UNAVAILABLE_INFORMATION = 0xFFFFFFFF  # CK_UNAVAILABLE_INFORMATION

# CK_BBOOL values
CK_TRUE  = b'\x01'
CK_FALSE = b'\x00'


def bool_attr(val: bool) -> bytes:
    return CK_TRUE if val else CK_FALSE


def ulong_attr(val: int) -> int:
    """Return an integer value suitable for a numeric attribute."""
    return val


# Attribute types whose wire value is an integer (CK_ULONG), not an OCTET
# STRING.  Must match is_numeric_attr() in icsf.c exactly — verified against
# usr/include/pkcs11types.h.  All other attributes (including CK_BBOOL flags
# like CKA_SENSITIVE=0x103) are encoded as charValue [0] OCTET STRING.
# Shared by ber_codec.py and handlers/trl.py to avoid duplication.
NUMERIC_ATTR_TYPES = {
    CKA_CLASS,                    # 0x00000000
    CKA_CERTIFICATE_TYPE,         # 0x00000080
    CKA_CERTIFICATE_CATEGORY,     # 0x00000087
    CKA_JAVA_MIDP_SECURITY_DOMAIN,# 0x00000088
    CKA_NAME_HASH_ALGORITHM,      # 0x0000008C
    CKA_KEY_TYPE,                 # 0x00000100
    CKA_MODULUS_BITS,             # 0x00000121
    CKA_PRIME_BITS,               # 0x00000133
    CKA_SUBPRIME_BITS,            # 0x00000134
    CKA_VALUE_BITS,               # 0x00000160
    CKA_VALUE_LEN,                # 0x00000161
    CKA_KEY_GEN_MECHANISM,        # 0x00000166
    0x00000300,                   # CKA_HW_FEATURE_TYPE (not in this file)
}


# Reverse map: attribute type (int) -> name string.
# Built once at import time from all CKA_* names defined above.
CKA_NAME = {v: k for k, v in globals().items() if k.startswith('CKA_')}

# Reverse map: certificate type (int) -> name string.
CKC_NAME = {v: k for k, v in globals().items() if k.startswith('CKC_')}
