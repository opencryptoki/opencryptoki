 /*
  * COPYRIGHT (c) International Business Machines Corp. 2001-2017
  *
  * This program is provided under the terms of the Common Public License,
  * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
  * software constitutes recipient's acceptance of CPL-1.0 terms which can be
  * found in the file LICENSE file or at
  * https://opensource.org/licenses/cpl1.0.php
  */

//----------------------------------------------------------------------------
//
// File: PKCS11Types.h
//
//
//----------------------------------------------------------------------------


#ifndef _PKCS11TYPES_H_
#define _PKCS11TYPES_H_


#ifdef __cplusplus
extern "C"
{
#endif

#define CK_TRUE  1
#define CK_FALSE 0

#ifndef CK_DISABLE_TRUE_FALSE
#ifndef FALSE
#define FALSE CK_FALSE
#endif

#ifndef TRUE
#define TRUE  CK_TRUE
#endif
#endif

// AIX Addition for 64Bit work.
// All types are 32bit types, therefore the longs have to be
// typedefed to be 32bit values.
typedef unsigned int uint_32;
typedef int int_32;

#define CK_PTR *

#define CK_CALLBACK_FUNCTION(returnType, name) \
  returnType (* name)

#ifndef NULL_PTR
	#define NULL_PTR ((void *) NULL)
#endif /* NULL_PTR */

/* an unsigned 8-bit value */
typedef unsigned char     CK_BYTE;

/* an unsigned 8-bit character */
typedef CK_BYTE           CK_CHAR;

/* an 8-bit UTF-8 character */
typedef CK_BYTE           CK_UTF8CHAR;

/* a BYTE-sized Boolean flag */
typedef CK_BYTE           CK_BBOOL;

/* an unsigned value, at least 32 bits long */
typedef unsigned long int CK_ULONG;

/* a signed value, the same size as a CK_ULONG */
/* CK_LONG is new for v2.0 */
typedef long int          CK_LONG;

/* at least 32 bits; each bit is a Boolean flag */
typedef CK_ULONG          CK_FLAGS;


/* some special values for certain CK_ULONG variables */
#define CK_UNAVAILABLE_INFORMATION (~0UL)
#define CK_EFFECTIVELY_INFINITE    0


typedef CK_BYTE     CK_PTR   CK_BYTE_PTR;
typedef CK_CHAR     CK_PTR   CK_CHAR_PTR;
typedef CK_UTF8CHAR CK_PTR   CK_UTF8CHAR_PTR;
typedef CK_ULONG    CK_PTR   CK_ULONG_PTR;
typedef void        CK_PTR   CK_VOID_PTR;

/* Pointer to a CK_VOID_PTR-- i.e., pointer to pointer to void */
typedef CK_VOID_PTR CK_PTR CK_VOID_PTR_PTR;


/* The following value is always invalid if used as a session */
/* handle or object handle */
#define CK_INVALID_HANDLE 0


typedef struct CK_VERSION {
  CK_BYTE       major;  /* integer portion of version number */
  CK_BYTE       minor;  /* 1/100ths portion of version number */
} CK_VERSION;

typedef CK_VERSION CK_PTR CK_VERSION_PTR;


typedef struct CK_INFO {
  CK_VERSION    cryptokiVersion;     /* Cryptoki interface ver */
  CK_CHAR       manufacturerID[32];  /* blank padded */
  CK_FLAGS      flags;               /* must be zero */

  /* libraryDescription and libraryVersion are new for v2.0 */
  CK_CHAR       libraryDescription[32];  /* blank padded */
  CK_VERSION    libraryVersion;          /* version of library */
} CK_INFO;

typedef CK_INFO CK_PTR    CK_INFO_PTR;


/* CK_NOTIFICATION enumerates the types of notifications that
 * Cryptoki provides to an application */
/* CK_NOTIFICATION has been changed from an enum to a CK_ULONG
 * for v2.0 */
typedef CK_ULONG CK_NOTIFICATION;
#define CKN_SURRENDER       0


typedef CK_ULONG          CK_SLOT_ID;

typedef CK_SLOT_ID CK_PTR CK_SLOT_ID_PTR;


/* CK_SLOT_INFO provides information about a slot */
typedef struct CK_SLOT_INFO {
  CK_CHAR       slotDescription[64];  /* blank padded */
  CK_CHAR       manufacturerID[32];   /* blank padded */
  CK_FLAGS      flags;

  /* hardwareVersion and firmwareVersion are new for v2.0 */
  CK_VERSION    hardwareVersion;  /* version of hardware */
  CK_VERSION    firmwareVersion;  /* version of firmware */
} CK_SLOT_INFO;

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag              Mask        Meaning
 */
#define CKF_TOKEN_PRESENT     0x00000001  /* a token is there */
#define CKF_REMOVABLE_DEVICE  0x00000002  /* removable devices*/
#define CKF_HW_SLOT           0x00000004  /* hardware slot */

typedef CK_SLOT_INFO CK_PTR CK_SLOT_INFO_PTR;


/* CK_TOKEN_INFO provides information about a token */
typedef struct CK_TOKEN_INFO {
  CK_CHAR       label[32];           /* blank padded */
  CK_CHAR       manufacturerID[32];  /* blank padded */
  CK_CHAR       model[16];           /* blank padded */
  CK_CHAR       serialNumber[16];    /* blank padded */
  CK_FLAGS      flags;               /* see below */

  /* ulMaxSessionCount, ulSessionCount, ulMaxRwSessionCount,
   * ulRwSessionCount, ulMaxPinLen, and ulMinPinLen have all been
   * changed from CK_USHORT to CK_ULONG for v2.0 */
  CK_ULONG      ulMaxSessionCount;     /* max open sessions */
  CK_ULONG      ulSessionCount;        /* sess. now open */
  CK_ULONG      ulMaxRwSessionCount;   /* max R/W sessions */
  CK_ULONG      ulRwSessionCount;      /* R/W sess. now open */
  CK_ULONG      ulMaxPinLen;           /* in bytes */
  CK_ULONG      ulMinPinLen;           /* in bytes */
  CK_ULONG      ulTotalPublicMemory;   /* in bytes */
  CK_ULONG      ulFreePublicMemory;    /* in bytes */
  CK_ULONG      ulTotalPrivateMemory;  /* in bytes */
  CK_ULONG      ulFreePrivateMemory;   /* in bytes */

  /* hardwareVersion, firmwareVersion, and time are new for
   * v2.0 */
  CK_VERSION    hardwareVersion;       /* version of hardware */
  CK_VERSION    firmwareVersion;       /* version of firmware */
  CK_CHAR       utcTime[16];           /* time */
} CK_TOKEN_INFO;

/* The flags parameter is defined as follows:
 *      Bit Flag                    Mask        Meaning
 */
#define CKF_RNG                     0x00000001  /* has random #
                                                 * generator */
#define CKF_WRITE_PROTECTED         0x00000002  /* token is
                                                 * write-
                                                 * protected */
#define CKF_LOGIN_REQUIRED          0x00000004  /* user must
                                                 * login */
#define CKF_USER_PIN_INITIALIZED    0x00000008  /* normal user's
                                                 * PIN is set */

/* CKF_RESTORE_KEY_NOT_NEEDED is new for v2.0.  If it is set,
 * that means that *every* time the state of cryptographic
 * operations of a session is successfully saved, all keys
 * needed to continue those operations are stored in the state */
#define CKF_RESTORE_KEY_NOT_NEEDED  0x00000020

/* CKF_CLOCK_ON_TOKEN is new for v2.0.  If it is set, that means
 * that the token has some sort of clock.  The time on that
 * clock is returned in the token info structure */
#define CKF_CLOCK_ON_TOKEN          0x00000040

/* CKF_PROTECTED_AUTHENTICATION_PATH is new for v2.0.  If it is
 * set, that means that there is some way for the user to login
 * without sending a PIN through the Cryptoki library itself */
#define CKF_PROTECTED_AUTHENTICATION_PATH 0x00000100

/* CKF_DUAL_CRYPTO_OPERATIONS is new for v2.0.  If it is true,
 * that means that a single session with the token can perform
 * dual simultaneous cryptographic operations (digest and
 * encrypt; decrypt and digest; sign and encrypt; and decrypt
 * and sign) */
#define CKF_DUAL_CRYPTO_OPERATIONS  0x00000200

/* CKF_TOKEN_INITIALIZED is new for v2.11. If it is true, the
 * token has been initialized using C_InitializeToken or an
 * equivalent mechanism outside the scope of this standard.
 * Calling C_InitializeToken when this flag is set will cause
 * the token to be reinitialized. */
#define CKF_TOKEN_INITIALIZED		0x00000400

/* CKF_SECONDARY_AUTHENTICATION is new for v2.11.  If it is
 * true, the token supports secondary authentication for private
 * key objects. According to the 2.11 spec pg. 45, this flag
 * is deprecated and this flags should never be true. */
#define CKF_SECONDARY_AUTHENTICATION	0x00000800

/* CKF_USER_PIN_COUNT_LOW is new in v2.11.  This flag is true
 * is an incorrect user PIN has been entered at least once
 * since the last successful authentication. */
#define CKF_USER_PIN_COUNT_LOW		0x00010000

/* CKF_USER_PIN_FINAL_TRY is new in v2.11.  This flag is true if
 * supplying an incorrect user PIN will cause it to become
 * locked. */
#define CKF_USER_PIN_FINAL_TRY		0x00020000

/* CKF_USER_PIN_LOCKED is new in v2.11.  This is true if the
 * user PIN has been locked.  User login to the token is not
 * possible. */
#define CKF_USER_PIN_LOCKED		0x00040000

/* CKF_USER_PIN_TO_BE_CHANGED is new in v2.11.  This flag is
 * true if the user PIN value is the default value set by
 * token initialization of manufacturing, or the PIN has
 * been expired by the card. */
#define CKF_USER_PIN_TO_BE_CHANGED	0x00080000

/* CKF_SO_PIN_COUNT_LOW is new in v2.11.  This flag is true if
 * and incorrect SO login PIN has been entered at least once
 * since the last successful authentication. */
#define CKF_SO_PIN_COUNT_LOW		0x00100000

/* CKF_SO_PIN_FINAL_TRY is new in v2.11.  This flag is true if
 * supplying an incorrect SO PIN will cause it to become
 * locked. */
#define CKF_SO_PIN_FINAL_TRY		0x00200000

/* CKF_SO_PIN_LOCKED is new in v2.11.  This flag is true if
 * the SO PIN has been locked.  User login to the token is not
 * possible. */
#define CKF_SO_PIN_LOCKED		0x00400000

/* CKF_SO_PIN_TO_BE_CHANGED is new in v2.11. This flag is true
 * if the SO PIN calue is the default value set by token init-
 * ialization of manufacturing, or the PIN has been expired by
 * the card. */
#define CKF_SO_PIN_TO_BE_CHANGED	0x00800000

#if 0
/* IBM extended Token Info Flags - defined by Michael Hamann */
/* These Flags are not part of PKCS#11 Version 2.01          */

/* This will be used to track the state of login retries     */
#define CKF_USER_PIN_COUNT_LOW      0x00010000
#define CKF_USER_PIN_FINAL_TRY      0x00020000
#define CKF_USER_PIN_LOCKED         0x00040000
#define CKF_USER_PIN_MANUFACT_VALUE 0x00080000

#define CKF_SO_PIN_COUNT_LOW        0x00100000
#define CKF_SO_PIN_FINAL_TRY        0x00200000
#define CKF_SO_PIN_LOCKED           0x00400000
#define CKF_SO_PIN_MANUFACT_VALUE   0x00800000
#endif

/*  other IBM extended Token info Flags 05/29/99  */
#define CKF_SO_PIN_DERIVED          0x01000000  // Sec Officer pin on card is derived from card id
#define CKF_SO_CARD                 0x02000000  // Security Officer Card
/* End of IBM extented Token Info Flags   */


typedef CK_TOKEN_INFO CK_PTR CK_TOKEN_INFO_PTR;

/* CK_SESSION_HANDLE is a Cryptoki-assigned value that
 * identifies a session */
typedef CK_ULONG          CK_SESSION_HANDLE;

typedef CK_SESSION_HANDLE CK_PTR CK_SESSION_HANDLE_PTR;


/* CK_USER_TYPE enumerates the types of Cryptoki users */
/* CK_USER_TYPE has been changed from an enum to a CK_ULONG for
 * v2.0 */
typedef CK_ULONG          CK_USER_TYPE;
/* Security Officer */
#define CKU_SO    0
/* Normal user */
#define CKU_USER  1


/* CK_STATE enumerates the session states */
/* CK_STATE has been changed from an enum to a CK_ULONG for
 * v2.0 */
typedef CK_ULONG          CK_STATE;
#define CKS_RO_PUBLIC_SESSION  0
#define CKS_RO_USER_FUNCTIONS  1
#define CKS_RW_PUBLIC_SESSION  2
#define CKS_RW_USER_FUNCTIONS  3
#define CKS_RW_SO_FUNCTIONS    4


/* CK_SESSION_INFO provides information about a session */
typedef struct CK_SESSION_INFO {
  CK_SLOT_ID    slotID;
  CK_STATE      state;
  CK_FLAGS      flags;          /* see below */

  /* ulDeviceError was changed from CK_USHORT to CK_ULONG for
   * v2.0 */
  CK_ULONG      ulDeviceError;  /* device-dependent error code */
} CK_SESSION_INFO;

/* The flags are defined in the following table:
 *      Bit Flag                Mask        Meaning
 */
#define CKF_RW_SESSION          0x00000002  /* session is r/w */
#define CKF_SERIAL_SESSION      0x00000004  /* no parallel */

typedef CK_SESSION_INFO CK_PTR CK_SESSION_INFO_PTR;


/* CK_OBJECT_HANDLE is a token-specific identifier for an
 * object  */
typedef CK_ULONG          CK_OBJECT_HANDLE;

typedef CK_OBJECT_HANDLE CK_PTR CK_OBJECT_HANDLE_PTR;


/* CK_OBJECT_CLASS is a value that identifies the classes (or
 * types) of objects that Cryptoki recognizes.  It is defined
 * as follows: */
/* CK_OBJECT_CLASS was changed from CK_USHORT to CK_ULONG for
 * v2.0 */
typedef CK_ULONG          CK_OBJECT_CLASS;

/* The following classes of objects are defined: */
#define CKO_DATA              0x00000000
#define CKO_CERTIFICATE       0x00000001
#define CKO_PUBLIC_KEY        0x00000002
#define CKO_PRIVATE_KEY       0x00000003
#define CKO_SECRET_KEY        0x00000004
/* CKO_HW_FEATURE and CKO_DOMAIN_PARAMETERS are new for v2.11 */
#define CKO_HW_FEATURE        0x00000005
#define CKO_DOMAIN_PARAMETERS 0x00000006
#define CKO_VENDOR_DEFINED    0x80000000

typedef CK_OBJECT_CLASS CK_PTR CK_OBJECT_CLASS_PTR;

/* CK_HW_FEATURE_TYPE is a value that identifies a hardware
 * feature type of a device. This is new for v2.11.
 */
typedef CK_ULONG          CK_HW_FEATURE_TYPE;

/* The following hardware feature types are defined: */
#define CKH_MONOTONIC_COUNTER	0x00000001
#define CKH_CLOCK		0x00000002
#define CKH_VENDOR_DEFINED	0x80000000


/* CK_KEY_TYPE is a value that identifies a key type */
/* CK_KEY_TYPE was changed from CK_USHORT to CK_ULONG for v2.0 */
typedef CK_ULONG          CK_KEY_TYPE;

/* the following key types are defined: */
#define CKK_RSA             0x00000000
#define CKK_DSA             0x00000001
#define CKK_DH              0x00000002

/* CKK_ECDSA and CKK_KEA are new for v2.0 */
/* CKK_ECDSA is deprecated in v2.11, CKK_EC is preferred */
#define CKK_ECDSA           0x00000003
#define CKK_EC              0x00000003
#define CKK_X9_42_DH        0x00000004
#define CKK_KEA             0x00000005

#define CKK_GENERIC_SECRET  0x00000010
#define CKK_RC2             0x00000011
#define CKK_RC4             0x00000012
#define CKK_DES             0x00000013
#define CKK_DES2            0x00000014
#define CKK_DES3            0x00000015

/* all these key types are new for v2.0 */
#define CKK_CAST            0x00000016
#define CKK_CAST3           0x00000017
/* CKK_CAST5 is deprecated in v2.11, CKK_CAST128 is preferred */
#define CKK_CAST5           0x00000018
#define CKK_CAST128         0x00000018  /* CAST128=CAST5 */
#define CKK_RC5             0x00000019
#define CKK_IDEA            0x0000001A
#define CKK_SKIPJACK        0x0000001B
#define CKK_BATON           0x0000001C
#define CKK_JUNIPER         0x0000001D
#define CKK_CDMF            0x0000001E
/* CKK_AES is new for v2.11 */
#define CKK_AES             0x0000001F

#define CKK_VENDOR_DEFINED  0x80000000


/* CK_CERTIFICATE_TYPE is a value that identifies a certificate
 * type */
/* CK_CERTIFICATE_TYPE was changed from CK_USHORT to CK_ULONG
 * for v2.0 */
typedef CK_ULONG          CK_CERTIFICATE_TYPE;

/* The following certificate types are defined: */
#define CKC_X_509           0x00000000
/* CKC_X_509_ATTR_CERT is new for v2.11 */
#define CKC_X_509_ATTR_CERT 0x00000001
#define CKC_VENDOR_DEFINED  0x80000000


/* CK_ATTRIBUTE_TYPE is a value that identifies an attribute
 * type */
/* CK_ATTRIBUTE_TYPE was changed from CK_USHORT to CK_ULONG for
 * v2.0 */
typedef CK_ULONG          CK_ATTRIBUTE_TYPE;

/* The CKF_ARRAY_ATTRIBUTE flag identifies an attribute which
 * consists of an array of values. */
#define CKF_ARRAY_ATTRIBUTE    0x40000000

/* The following attribute types are defined: */
#define CKA_CLASS              0x00000000
#define CKA_TOKEN              0x00000001
#define CKA_PRIVATE            0x00000002
#define CKA_LABEL              0x00000003
#define CKA_APPLICATION        0x00000010
#define CKA_VALUE              0x00000011
/* CKA_OBJECT_ID is new for v2.11 */
#define CKA_OBJECT_ID          0x00000012
#define CKA_CERTIFICATE_TYPE   0x00000080
#define CKA_ISSUER             0x00000081
#define CKA_SERIAL_NUMBER      0x00000082
/* CKA_AC_ISSUER, CKA_OWNER, CKA_ATTR_TYPES and CKA_TRUSTED
 * are new for v2.11 */
#define CKA_AC_ISSUER          0x00000083
#define CKA_OWNER              0x00000084
#define CKA_ATTR_TYPES         0x00000085
#define CKA_TRUSTED            0x00000086

#define CKA_KEY_TYPE           0x00000100
#define CKA_SUBJECT            0x00000101
#define CKA_ID                 0x00000102
#define CKA_SENSITIVE          0x00000103
#define CKA_ENCRYPT            0x00000104
#define CKA_DECRYPT            0x00000105
#define CKA_WRAP               0x00000106
#define CKA_UNWRAP             0x00000107
#define CKA_SIGN               0x00000108
#define CKA_SIGN_RECOVER       0x00000109
#define CKA_VERIFY             0x0000010A
#define CKA_VERIFY_RECOVER     0x0000010B
#define CKA_DERIVE             0x0000010C
#define CKA_START_DATE         0x00000110
#define CKA_END_DATE           0x00000111
#define CKA_MODULUS            0x00000120
#define CKA_MODULUS_BITS       0x00000121
#define CKA_PUBLIC_EXPONENT    0x00000122
#define CKA_PRIVATE_EXPONENT   0x00000123
#define CKA_PRIME_1            0x00000124
#define CKA_PRIME_2            0x00000125
#define CKA_EXPONENT_1         0x00000126
#define CKA_EXPONENT_2         0x00000127
#define CKA_COEFFICIENT        0x00000128
#define CKA_PRIME              0x00000130
#define CKA_SUBPRIME           0x00000131
#define CKA_BASE               0x00000132
/* CKA_PRIME_BITS and CKA_SUB_PRIME_BITS are new for v2.11 */
#define CKA_PRIME_BITS         0x00000133
#define CKA_SUBPRIME_BITS      0x00000134

#define CKA_VALUE_BITS         0x00000160
#define CKA_VALUE_LEN          0x00000161

/* CKA_EXTRACTABLE, CKA_LOCAL, CKA_NEVER_EXTRACTABLE,
 * CKA_ALWAYS_SENSITIVE, CKA_MODIFIABLE, CKA_ECDSA_PARAMS,
 * and CKA_EC_POINT are new for v2.0 */
#define CKA_EXTRACTABLE        0x00000162
#define CKA_LOCAL              0x00000163
#define CKA_NEVER_EXTRACTABLE  0x00000164
#define CKA_ALWAYS_SENSITIVE   0x00000165
/* CKA_KEY_GEN_MECHANISM is new for v2.11 */
#define CKA_KEY_GEN_MECHANISM  0x00000166
#define CKA_MODIFIABLE         0x00000170
/* CKA_ECDSA_PARAMS is deprecated in v2.11, CKA_EC_PARAMS is preferred */
#define CKA_ECDSA_PARAMS       0x00000180
#define CKA_EC_PARAMS          0x00000180
#define CKA_EC_POINT           0x00000181
/* The following are new for v2.11 */
#define CKA_SECONDARY_AUTH     0x00000200
#define CKA_AUTH_PIN_FLAGS     0x00000201
#define CKA_ALWAYS_AUTHENTICATE 0x00000202
#define CKA_HW_FEATURE_TYPE    0x00000300
#define CKA_RESET_ON_INIT      0x00000301
#define CKA_HAS_RESET          0x00000302

#define CKA_WRAP_TEMPLATE        (CKF_ARRAY_ATTRIBUTE|0x00000211UL)
#define CKA_UNWRAP_TEMPLATE      (CKF_ARRAY_ATTRIBUTE|0x00000212UL)

#define CKA_VENDOR_DEFINED     0x80000000

/* For use in storing objects that have an encrypted or otherwise
 * opaque attribute. Support has been added to use this attribute
 * in key objects only. */
#define CKA_IBM_OPAQUE         CKA_VENDOR_DEFINED + 1


/* CK_ATTRIBUTE is a structure that includes the type, length
 * and value of an attribute */
typedef struct CK_ATTRIBUTE {
  CK_ATTRIBUTE_TYPE type;
  CK_VOID_PTR       pValue;

  /* ulValueLen went from CK_USHORT to CK_ULONG for v2.0 */
  CK_ULONG          ulValueLen;  /* in bytes */
} CK_ATTRIBUTE;

typedef CK_ATTRIBUTE CK_PTR CK_ATTRIBUTE_PTR;


/* CK_DATE is a structure that defines a date */
typedef struct CK_DATE{
  CK_CHAR       year[4];   /* the year ("1900" - "9999") */
  CK_CHAR       month[2];  /* the month ("01" - "12") */
  CK_CHAR       day[2];    /* the day   ("01" - "31") */
} CK_DATE;


/* CK_MECHANISM_TYPE is a value that identifies a mechanism
 * type */
/* CK_MECHANISM_TYPE was changed from CK_USHORT to CK_ULONG for
 * v2.0 */
typedef CK_ULONG          CK_MECHANISM_TYPE;

/* the following mechanism types are defined: */
#define CKM_RSA_PKCS_KEY_PAIR_GEN      0x00000000
#define CKM_RSA_PKCS                   0x00000001
#define CKM_RSA_9796                   0x00000002
#define CKM_RSA_X_509                  0x00000003

/* CKM_MD2_RSA_PKCS, CKM_MD5_RSA_PKCS, and CKM_SHA1_RSA_PKCS
 * are new for v2.0.  They are mechanisms which hash and sign */
#define CKM_MD2_RSA_PKCS               0x00000004
#define CKM_MD5_RSA_PKCS               0x00000005
#define CKM_SHA1_RSA_PKCS              0x00000006
/* The following are new for v2.11: */
#define CKM_RIPEMD128_RSA_PKCS         0x00000007
#define CKM_RIPEMD160_RSA_PKCS         0x00000008
#define CKM_RSA_PKCS_OAEP              0x00000009
#define CKM_RSA_X9_31_KEY_PAIR_GEN     0x0000000A
#define CKM_RSA_X9_31                  0x0000000B
#define CKM_SHA1_RSA_X9_31             0x0000000C
#define CKM_RSA_PKCS_PSS               0x0000000D
#define CKM_SHA1_RSA_PKCS_PSS          0x0000000E

#define CKM_DSA_KEY_PAIR_GEN           0x00000010
#define CKM_DSA                        0x00000011
#define CKM_DSA_SHA1                   0x00000012
#define CKM_DH_PKCS_KEY_PAIR_GEN       0x00000020
#define CKM_DH_PKCS_DERIVE             0x00000021
/* The following are new for v2.11 */
#define CKM_X9_42_DH_KEY_PAIR_GEN      0x00000030
#define CKM_X9_42_DH_DERIVE            0x00000031
#define CKM_X9_42_DH_HYBRID_DERIVE     0x00000032
#define CKM_X9_42_MQV_DERIVE           0x00000033

#define CKM_SHA256_RSA_PKCS            0x00000040
#define CKM_SHA384_RSA_PKCS            0x00000041
#define CKM_SHA512_RSA_PKCS            0x00000042

#define CKM_SHA256_RSA_PKCS_PSS	       0x00000043
#define CKM_SHA384_RSA_PKCS_PSS	       0x00000044
#define CKM_SHA512_RSA_PKCS_PSS	       0x00000045

#define CKM_RC2_KEY_GEN                0x00000100
#define CKM_RC2_ECB                    0x00000101
#define CKM_RC2_CBC                    0x00000102
#define CKM_RC2_MAC                    0x00000103

/* CKM_RC2_MAC_GENERAL and CKM_RC2_CBC_PAD are new for v2.0 */
#define CKM_RC2_MAC_GENERAL            0x00000104
#define CKM_RC2_CBC_PAD                0x00000105

#define CKM_RC4_KEY_GEN                0x00000110
#define CKM_RC4                        0x00000111
#define CKM_DES_KEY_GEN                0x00000120
#define CKM_DES_ECB                    0x00000121
#define CKM_DES_CBC                    0x00000122
#define CKM_DES_MAC                    0x00000123

/* CKM_DES_MAC_GENERAL and CKM_DES_CBC_PAD are new for v2.0 */
#define CKM_DES_MAC_GENERAL            0x00000124
#define CKM_DES_CBC_PAD                0x00000125

#define CKM_DES2_KEY_GEN               0x00000130
#define CKM_DES3_KEY_GEN               0x00000131
#define CKM_DES3_ECB                   0x00000132
#define CKM_DES3_CBC                   0x00000133
#define CKM_DES3_MAC                   0x00000134

/* CKM_DES3_MAC_GENERAL, CKM_DES3_CBC_PAD, CKM_CDMF_KEY_GEN,
 * CKM_CDMF_ECB, CKM_CDMF_CBC, CKM_CDMF_MAC,
 * CKM_CDMF_MAC_GENERAL, and CKM_CDMF_CBC_PAD are new for v2.0 */
#define CKM_DES3_MAC_GENERAL           0x00000135
#define CKM_DES3_CBC_PAD               0x00000136
#define CKM_CDMF_KEY_GEN               0x00000140
#define CKM_CDMF_ECB                   0x00000141
#define CKM_CDMF_CBC                   0x00000142
#define CKM_CDMF_MAC                   0x00000143
#define CKM_CDMF_MAC_GENERAL           0x00000144
#define CKM_CDMF_CBC_PAD               0x00000145

#define CKM_DES_OFB64                  0x00000150
#define CKM_DES_CFB64                  0x00000152
#define CKM_DES_CFB8                   0x00000153

#define CKM_MD2                        0x00000200

/* CKM_MD2_HMAC and CKM_MD2_HMAC_GENERAL are new for v2.0 */
#define CKM_MD2_HMAC                   0x00000201
#define CKM_MD2_HMAC_GENERAL           0x00000202

#define CKM_MD5                        0x00000210

/* CKM_MD5_HMAC and CKM_MD5_HMAC_GENERAL are new for v2.0 */
#define CKM_MD5_HMAC                   0x00000211
#define CKM_MD5_HMAC_GENERAL           0x00000212

#define CKM_SHA_1                      0x00000220

/* CKM_SHA_1_HMAC and CKM_SHA_1_HMAC_GENERAL are new for v2.0 */
#define CKM_SHA_1_HMAC                 0x00000221
#define CKM_SHA_1_HMAC_GENERAL         0x00000222

/* The following are new for v2.11 */
#define CKM_RIPEMD128                  0x00000230
#define CKM_RIPEMD128_HMAC             0x00000231
#define CKM_RIPEMD128_HMAC_GENERAL     0x00000232
#define CKM_RIPEMD160                  0x00000240
#define CKM_RIPEMD160_HMAC             0x00000241
#define CKM_RIPEMD160_HMAC_GENERAL     0x00000242

#define CKM_SHA256                     0x00000250
#define CKM_SHA256_HMAC                0x00000251
#define CKM_SHA256_HMAC_GENERAL        0x00000252
#define CKM_SHA224                     0x00000255
#define CKM_SHA224_HMAC                0x00000256
#define CKM_SHA224_HMAC_GENERAL        0x00000257
#define CKM_SHA384                     0x00000260
#define CKM_SHA384_HMAC                0x00000261
#define CKM_SHA384_HMAC_GENERAL        0x00000262
#define CKM_SHA512                     0x00000270
#define CKM_SHA512_HMAC                0x00000271
#define CKM_SHA512_HMAC_GENERAL        0x00000272

/* All of the following mechanisms are new for v2.0 */
/* Note that CAST128 and CAST5 are the same algorithm */
#define CKM_CAST_KEY_GEN               0x00000300
#define CKM_CAST_ECB                   0x00000301
#define CKM_CAST_CBC                   0x00000302
#define CKM_CAST_MAC                   0x00000303
#define CKM_CAST_MAC_GENERAL           0x00000304
#define CKM_CAST_CBC_PAD               0x00000305
#define CKM_CAST3_KEY_GEN              0x00000310
#define CKM_CAST3_ECB                  0x00000311
#define CKM_CAST3_CBC                  0x00000312
#define CKM_CAST3_MAC                  0x00000313
#define CKM_CAST3_MAC_GENERAL          0x00000314
#define CKM_CAST3_CBC_PAD              0x00000315
#define CKM_CAST5_KEY_GEN              0x00000320
#define CKM_CAST128_KEY_GEN            0x00000320
#define CKM_CAST5_ECB                  0x00000321
#define CKM_CAST128_ECB                0x00000321
#define CKM_CAST5_CBC                  0x00000322
#define CKM_CAST128_CBC                0x00000322
#define CKM_CAST5_MAC                  0x00000323
#define CKM_CAST128_MAC                0x00000323
#define CKM_CAST5_MAC_GENERAL          0x00000324
#define CKM_CAST128_MAC_GENERAL        0x00000324
#define CKM_CAST5_CBC_PAD              0x00000325
#define CKM_CAST128_CBC_PAD            0x00000325
#define CKM_RC5_KEY_GEN                0x00000330
#define CKM_RC5_ECB                    0x00000331
#define CKM_RC5_CBC                    0x00000332
#define CKM_RC5_MAC                    0x00000333
#define CKM_RC5_MAC_GENERAL            0x00000334
#define CKM_RC5_CBC_PAD                0x00000335
#define CKM_IDEA_KEY_GEN               0x00000340
#define CKM_IDEA_ECB                   0x00000341
#define CKM_IDEA_CBC                   0x00000342
#define CKM_IDEA_MAC                   0x00000343
#define CKM_IDEA_MAC_GENERAL           0x00000344
#define CKM_IDEA_CBC_PAD               0x00000345
#define CKM_GENERIC_SECRET_KEY_GEN     0x00000350
#define CKM_CONCATENATE_BASE_AND_KEY   0x00000360
#define CKM_CONCATENATE_BASE_AND_DATA  0x00000362
#define CKM_CONCATENATE_DATA_AND_BASE  0x00000363
#define CKM_XOR_BASE_AND_DATA          0x00000364
#define CKM_EXTRACT_KEY_FROM_KEY       0x00000365
#define CKM_SSL3_PRE_MASTER_KEY_GEN    0x00000370
#define CKM_SSL3_MASTER_KEY_DERIVE     0x00000371
#define CKM_SSL3_KEY_AND_MAC_DERIVE    0x00000372
/* The following are new for v2.11 */
#define CKM_SSL3_MASTER_KEY_DERIVE_DH  0x00000373
#define CKM_TLS_PRE_MASTER_KEY_GEN     0x00000374
#define CKM_TLS_MASTER_KEY_DERIVE      0x00000375
#define CKM_TLS_KEY_AND_MAC_DERIVE     0x00000376
#define CKM_TLS_MASTER_KEY_DERIVE_DH   0x00000377

#define CKM_SSL3_MD5_MAC               0x00000380
#define CKM_SSL3_SHA1_MAC              0x00000381
#define CKM_MD5_KEY_DERIVATION         0x00000390
#define CKM_MD2_KEY_DERIVATION         0x00000391
#define CKM_SHA1_KEY_DERIVATION        0x00000392
#define CKM_SHA256_KEY_DERIVATION      0x00000393
#define CKM_PBE_MD2_DES_CBC            0x000003A0
#define CKM_PBE_MD5_DES_CBC            0x000003A1
#define CKM_PBE_MD5_CAST_CBC           0x000003A2
#define CKM_PBE_MD5_CAST3_CBC          0x000003A3
#define CKM_PBE_MD5_CAST5_CBC          0x000003A4
#define CKM_PBE_MD5_CAST128_CBC        0x000003A4
#define CKM_PBE_SHA1_CAST5_CBC         0x000003A5
#define CKM_PBE_SHA1_CAST128_CBC       0x000003A5
#define CKM_PBE_SHA1_RC4_128           0x000003A6
#define CKM_PBE_SHA1_RC4_40            0x000003A7
#define CKM_PBE_SHA1_DES3_EDE_CBC      0x000003A8
#define CKM_PBE_SHA1_DES2_EDE_CBC      0x000003A9
#define CKM_PBE_SHA1_RC2_128_CBC       0x000003AA
#define CKM_PBE_SHA1_RC2_40_CBC        0x000003AB
/* CKM_PKCS5_PBKD2 is new for v2.11 */
#define CKM_PKCS5_PBKD2                0x000003B0
#define CKM_PBA_SHA1_WITH_SHA1_HMAC    0x000003C0
#define CKM_KEY_WRAP_LYNKS             0x00000400
#define CKM_KEY_WRAP_SET_OAEP          0x00000401

/* Fortezza mechanisms */
#define CKM_SKIPJACK_KEY_GEN           0x00001000
#define CKM_SKIPJACK_ECB64             0x00001001
#define CKM_SKIPJACK_CBC64             0x00001002
#define CKM_SKIPJACK_OFB64             0x00001003
#define CKM_SKIPJACK_CFB64             0x00001004
#define CKM_SKIPJACK_CFB32             0x00001005
#define CKM_SKIPJACK_CFB16             0x00001006
#define CKM_SKIPJACK_CFB8              0x00001007
#define CKM_SKIPJACK_WRAP              0x00001008
#define CKM_SKIPJACK_PRIVATE_WRAP      0x00001009
#define CKM_SKIPJACK_RELAYX            0x0000100a
#define CKM_KEA_KEY_PAIR_GEN           0x00001010
#define CKM_KEA_KEY_DERIVE             0x00001011
#define CKM_FORTEZZA_TIMESTAMP         0x00001020
#define CKM_BATON_KEY_GEN              0x00001030
#define CKM_BATON_ECB128               0x00001031
#define CKM_BATON_ECB96                0x00001032
#define CKM_BATON_CBC128               0x00001033
#define CKM_BATON_COUNTER              0x00001034
#define CKM_BATON_SHUFFLE              0x00001035
#define CKM_BATON_WRAP                 0x00001036

/* CKM_ECDSA_KEY_PAIR_GEN is deprecated in v2.11,
 * CKM_EC_KEY_PAIR_GEN is preferred. */
#define CKM_ECDSA_KEY_PAIR_GEN         0x00001040
#define CKM_EC_KEY_PAIR_GEN            0x00001040
#define CKM_ECDSA                      0x00001041
#define CKM_ECDSA_SHA1                 0x00001042
/* The following are new for v2.3 */
#define CKM_ECDSA_SHA224               0x00001043
#define CKM_ECDSA_SHA256               0x00001044
#define CKM_ECDSA_SHA384               0x00001045
#define CKM_ECDSA_SHA512               0x00001046
/* The following are new for v2.11 */
#define CKM_ECDH1_DERIVE               0x00001050
#define CKM_ECDH1_COFACTOR_DERIVE      0x00001051
#define CKM_ECMQV_DERIVE               0x00001052

#define CKM_JUNIPER_KEY_GEN            0x00001060
#define CKM_JUNIPER_ECB128             0x00001061
#define CKM_JUNIPER_CBC128             0x00001062
#define CKM_JUNIPER_COUNTER            0x00001063
#define CKM_JUNIPER_SHUFFLE            0x00001064
#define CKM_JUNIPER_WRAP               0x00001065
#define CKM_FASTHASH                   0x00001070
/* The following are new for v2.11 */
#define CKM_AES_KEY_GEN                0x00001080
#define CKM_AES_ECB                    0x00001081
#define CKM_AES_CBC                    0x00001082
#define CKM_AES_MAC                    0x00001083
#define CKM_AES_MAC_GENERAL            0x00001084
#define CKM_AES_CBC_PAD                0x00001085
#define CKM_AES_CTR                    0x00001086
#define CKM_AES_GCM                    0x00001087
#define CKM_DSA_PARAMETER_GEN          0x00002000
#define CKM_DH_PKCS_PARAMETER_GEN      0x00002001
#define CKM_X9_42_DH_PARAMETER_GEN     0x00002002

#define CKM_AES_OFB                    0x00002104
#define CKM_AES_CFB64                  0x00002105
#define CKM_AES_CFB8                   0x00002106
#define CKM_AES_CFB128                 0x00002107

#define CKM_VENDOR_DEFINED             0x80000000

typedef CK_MECHANISM_TYPE CK_PTR CK_MECHANISM_TYPE_PTR;


/* CK_MECHANISM is a structure that specifies a particular
 * mechanism  */
typedef struct CK_MECHANISM {
  CK_MECHANISM_TYPE mechanism;
  CK_VOID_PTR       pParameter;

  /* ulParameterLen was changed from CK_USHORT to CK_ULONG for
   * v2.0 */
  CK_ULONG          ulParameterLen;  /* in bytes */
} CK_MECHANISM;

typedef CK_MECHANISM CK_PTR CK_MECHANISM_PTR;


/* CK_MECHANISM_INFO provides information about a particular
 * mechanism */
typedef struct CK_MECHANISM_INFO {
    CK_ULONG    ulMinKeySize;
    CK_ULONG    ulMaxKeySize;
    CK_FLAGS    flags;
} CK_MECHANISM_INFO;

/* The flags are defined as follows:
 *      Bit Flag               Mask        Meaning */
#define CKF_HW                 0x00000001  /* performed by HW */

/* The flags CKF_ENCRYPT, CKF_DECRYPT, CKF_DIGEST, CKF_SIGN,
 * CKG_SIGN_RECOVER, CKF_VERIFY, CKF_VERIFY_RECOVER,
 * CKF_GENERATE, CKF_GENERATE_KEY_PAIR, CKF_WRAP, CKF_UNWRAP,
 * and CKF_DERIVE are new for v2.0.  They specify whether or not
 * a mechanism can be used for a particular task */
#define CKF_ENCRYPT            0x00000100
#define CKF_DECRYPT            0x00000200
#define CKF_DIGEST             0x00000400
#define CKF_SIGN               0x00000800
#define CKF_SIGN_RECOVER       0x00001000
#define CKF_VERIFY             0x00002000
#define CKF_VERIFY_RECOVER     0x00004000
#define CKF_GENERATE           0x00008000
#define CKF_GENERATE_KEY_PAIR  0x00010000
#define CKF_WRAP               0x00020000
#define CKF_UNWRAP             0x00040000
#define CKF_DERIVE             0x00080000
/* The following are new for v2.11 */
#define CKF_EC_F_P             0x00100000
#define CKF_EC_F_2M            0x00200000
#define CKF_EC_ECPARAMETERS    0x00400000
#define CKF_EC_NAMEDCURVE      0x00800000
#define CKF_EC_UNCOMPRESS      0x01000000
#define CKF_EC_COMPRESS        0x02000000

#define CKF_EXTENSION          0x80000000  /* FALSE for 2.01 */

typedef CK_MECHANISM_INFO CK_PTR CK_MECHANISM_INFO_PTR;


/* CK_RV is a value that identifies the return value of a
 * Cryptoki function */
/* CK_RV was changed from CK_USHORT to CK_ULONG for v2.0 */
typedef CK_ULONG          CK_RV;

#define CKR_OK                                0x00000000
#define CKR_CANCEL                            0x00000001
#define CKR_HOST_MEMORY                       0x00000002
#define CKR_SLOT_ID_INVALID                   0x00000003

/* CKR_FLAGS_INVALID was removed for v2.0 */

/* CKR_GENERAL_ERROR and CKR_FUNCTION_FAILED are new for v2.0 */
#define CKR_GENERAL_ERROR                     0x00000005
#define CKR_FUNCTION_FAILED                   0x00000006

/* CKR_ARGUMENTS_BAD, CKR_NO_EVENT, CKR_NEED_TO_CREATE_THREADS,
 * and CKR_CANT_LOCK are new for v2.01 */
#define CKR_ARGUMENTS_BAD                     0x00000007
#define CKR_NO_EVENT                          0x00000008
#define CKR_NEED_TO_CREATE_THREADS            0x00000009
#define CKR_CANT_LOCK                         0x0000000A

#define CKR_ATTRIBUTE_READ_ONLY               0x00000010
#define CKR_ATTRIBUTE_SENSITIVE               0x00000011
#define CKR_ATTRIBUTE_TYPE_INVALID            0x00000012
#define CKR_ATTRIBUTE_VALUE_INVALID           0x00000013
#define CKR_DATA_INVALID                      0x00000020
#define CKR_DATA_LEN_RANGE                    0x00000021
#define CKR_DEVICE_ERROR                      0x00000030
#define CKR_DEVICE_MEMORY                     0x00000031
#define CKR_DEVICE_REMOVED                    0x00000032
#define CKR_ENCRYPTED_DATA_INVALID            0x00000040
#define CKR_ENCRYPTED_DATA_LEN_RANGE          0x00000041
#define CKR_FUNCTION_CANCELED                 0x00000050
#define CKR_FUNCTION_NOT_PARALLEL             0x00000051

/* CKR_FUNCTION_NOT_SUPPORTED is new for v2.0 */
#define CKR_FUNCTION_NOT_SUPPORTED            0x00000054

#define CKR_KEY_HANDLE_INVALID                0x00000060

/* CKR_KEY_SENSITIVE was removed for v2.0 */

#define CKR_KEY_SIZE_RANGE                    0x00000062
#define CKR_KEY_TYPE_INCONSISTENT             0x00000063

/* CKR_KEY_NOT_NEEDED, CKR_KEY_CHANGED, CKR_KEY_NEEDED,
 * CKR_KEY_INDIGESTIBLE, CKR_KEY_FUNCTION_NOT_PERMITTED,
 * CKR_KEY_NOT_WRAPPABLE, and CKR_KEY_UNEXTRACTABLE are new for
 * v2.0 */
#define CKR_KEY_NOT_NEEDED                    0x00000064
#define CKR_KEY_CHANGED                       0x00000065
#define CKR_KEY_NEEDED                        0x00000066
#define CKR_KEY_INDIGESTIBLE                  0x00000067
#define CKR_KEY_FUNCTION_NOT_PERMITTED        0x00000068
#define CKR_KEY_NOT_WRAPPABLE                 0x00000069
#define CKR_KEY_UNEXTRACTABLE                 0x0000006A

#define CKR_MECHANISM_INVALID                 0x00000070
#define CKR_MECHANISM_PARAM_INVALID           0x00000071

/* CKR_OBJECT_CLASS_INCONSISTENT and CKR_OBJECT_CLASS_INVALID
 * were removed for v2.0 */
#define CKR_OBJECT_HANDLE_INVALID             0x00000082
#define CKR_OPERATION_ACTIVE                  0x00000090
#define CKR_OPERATION_NOT_INITIALIZED         0x00000091
#define CKR_PIN_INCORRECT                     0x000000A0
#define CKR_PIN_INVALID                       0x000000A1
#define CKR_PIN_LEN_RANGE                     0x000000A2

/* CKR_PIN_EXPIRED and CKR_PIN_LOCKED are new for v2.0 */
#define CKR_PIN_EXPIRED                       0x000000A3
#define CKR_PIN_LOCKED                        0x000000A4

#define CKR_SESSION_CLOSED                    0x000000B0
#define CKR_SESSION_COUNT                     0x000000B1
#define CKR_SESSION_HANDLE_INVALID            0x000000B3
#define CKR_SESSION_PARALLEL_NOT_SUPPORTED    0x000000B4
#define CKR_SESSION_READ_ONLY                 0x000000B5
#define CKR_SESSION_EXISTS                    0x000000B6

/* CKR_SESSION_READ_ONLY_EXISTS and
 * CKR_SESSION_READ_WRITE_SO_EXISTS are new for v2.0 */
#define CKR_SESSION_READ_ONLY_EXISTS          0x000000B7
#define CKR_SESSION_READ_WRITE_SO_EXISTS      0x000000B8

#define CKR_SIGNATURE_INVALID                 0x000000C0
#define CKR_SIGNATURE_LEN_RANGE               0x000000C1
#define CKR_TEMPLATE_INCOMPLETE               0x000000D0
#define CKR_TEMPLATE_INCONSISTENT             0x000000D1
#define CKR_TOKEN_NOT_PRESENT                 0x000000E0
#define CKR_TOKEN_NOT_RECOGNIZED              0x000000E1
#define CKR_TOKEN_WRITE_PROTECTED             0x000000E2
#define CKR_UNWRAPPING_KEY_HANDLE_INVALID     0x000000F0
#define CKR_UNWRAPPING_KEY_SIZE_RANGE         0x000000F1
#define CKR_UNWRAPPING_KEY_TYPE_INCONSISTENT  0x000000F2
#define CKR_USER_ALREADY_LOGGED_IN            0x00000100
#define CKR_USER_NOT_LOGGED_IN                0x00000101
#define CKR_USER_PIN_NOT_INITIALIZED          0x00000102
#define CKR_USER_TYPE_INVALID                 0x00000103

/* CKR_USER_ANOTHER_ALREADY_LOGGED_IN and CKR_USER_TOO_MANY_TYPES
 * are new to v2.01 */
#define CKR_USER_ANOTHER_ALREADY_LOGGED_IN    0x00000104
#define CKR_USER_TOO_MANY_TYPES               0x00000105

#define CKR_WRAPPED_KEY_INVALID               0x00000110
#define CKR_WRAPPED_KEY_LEN_RANGE             0x00000112
#define CKR_WRAPPING_KEY_HANDLE_INVALID       0x00000113
#define CKR_WRAPPING_KEY_SIZE_RANGE           0x00000114
#define CKR_WRAPPING_KEY_TYPE_INCONSISTENT    0x00000115
#define CKR_RANDOM_SEED_NOT_SUPPORTED         0x00000120

/* These are new to v2.0 */
#define CKR_RANDOM_NO_RNG                     0x00000121
/* CKR_DOMAIN_PARAMS_INVALID is new for v2.11 */
#define CKR_DOMAIN_PARAMS_INVALID             0x00000130
#define CKR_BUFFER_TOO_SMALL                  0x00000150
#define CKR_SAVED_STATE_INVALID               0x00000160
#define CKR_INFORMATION_SENSITIVE             0x00000170
#define CKR_STATE_UNSAVEABLE                  0x00000180

/* These are new to v2.01 */
#define CKR_CRYPTOKI_NOT_INITIALIZED          0x00000190
#define CKR_CRYPTOKI_ALREADY_INITIALIZED      0x00000191
#define CKR_MUTEX_BAD                         0x000001A0
#define CKR_MUTEX_NOT_LOCKED                  0x000001A1

#define CKR_VENDOR_DEFINED                    0x80000000


/* CK_NOTIFY is an application callback that processes events */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_NOTIFY)(
  CK_SESSION_HANDLE hSession,     /* the session's handle */
  CK_NOTIFICATION   event,
  CK_VOID_PTR       pApplication  /* passed to C_OpenSession */
);

/* CK_CREATEMUTEX is an application callback for creating a
 * mutex object */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_CREATEMUTEX)(
  CK_VOID_PTR_PTR ppMutex  /* location to receive ptr to mutex */
);


/* CK_DESTROYMUTEX is an application callback for destroying a
 * mutex object */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_DESTROYMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_LOCKMUTEX is an application callback for locking a mutex */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_LOCKMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_UNLOCKMUTEX is an application callback for unlocking a
 * mutex */
typedef CK_CALLBACK_FUNCTION(CK_RV, CK_UNLOCKMUTEX)(
  CK_VOID_PTR pMutex  /* pointer to mutex */
);


/* CK_C_INITIALIZE_ARGS provides the optional arguments to
 * C_Initialize */
// SAB the mutex ones had pf infront previously..
// The spec says otherwise.
typedef struct CK_C_INITIALIZE_ARGS {
  CK_CREATEMUTEX  CreateMutex;
  CK_DESTROYMUTEX DestroyMutex;
  CK_LOCKMUTEX    LockMutex;
  CK_UNLOCKMUTEX  UnlockMutex;
  CK_FLAGS        flags;
  CK_VOID_PTR     pReserved;
} CK_C_INITIALIZE_ARGS;

/* flags: bit flags that provide capabilities of the slot
 *      Bit Flag                           Mask       Meaning
 */
#define CKF_LIBRARY_CANT_CREATE_OS_THREADS 0x00000001
#define CKF_OS_LOCKING_OK                  0x00000002

typedef CK_C_INITIALIZE_ARGS CK_PTR CK_C_INITIALIZE_ARGS_PTR;


/* additional flags for parameters to functions */

/* CKF_DONT_BLOCK is for the function C_WaitForSlotEvent */
#define CKF_DONT_BLOCK     1


/* CK_KEA_DERIVE_PARAMS provides the parameters to the
 * CKM_KEA_DERIVE mechanism */
/* CK_KEA_DERIVE_PARAMS is new for v2.0 */
typedef struct CK_KEA_DERIVE_PARAMS {
  CK_BBOOL      isSender;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pRandomB;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
} CK_KEA_DERIVE_PARAMS;

typedef CK_KEA_DERIVE_PARAMS CK_PTR CK_KEA_DERIVE_PARAMS_PTR;


/* CK_RC2_PARAMS provides the parameters to the CKM_RC2_ECB and
 * CKM_RC2_MAC mechanisms.  An instance of CK_RC2_PARAMS just
 * holds the effective keysize */
typedef CK_ULONG          CK_RC2_PARAMS;

typedef CK_RC2_PARAMS CK_PTR CK_RC2_PARAMS_PTR;


/* CK_RC2_CBC_PARAMS provides the parameters to the CKM_RC2_CBC
 * mechanism */
typedef struct CK_RC2_CBC_PARAMS {
  /* ulEffectiveBits was changed from CK_USHORT to CK_ULONG for
   * v2.0 */
  CK_ULONG      ulEffectiveBits;  /* effective bits (1-1024) */

  CK_BYTE       iv[8];            /* IV for CBC mode */
} CK_RC2_CBC_PARAMS;

typedef CK_RC2_CBC_PARAMS CK_PTR CK_RC2_CBC_PARAMS_PTR;


/* CK_RC2_MAC_GENERAL_PARAMS provides the parameters for the
 * CKM_RC2_MAC_GENERAL mechanism */
/* CK_RC2_MAC_GENERAL_PARAMS is new for v2.0 */
typedef struct CK_RC2_MAC_GENERAL_PARAMS {
  CK_ULONG      ulEffectiveBits;  /* effective bits (1-1024) */
  CK_ULONG      ulMacLength;      /* Length of MAC in bytes */
} CK_RC2_MAC_GENERAL_PARAMS;

typedef CK_RC2_MAC_GENERAL_PARAMS CK_PTR \
  CK_RC2_MAC_GENERAL_PARAMS_PTR;


/* CK_RC5_PARAMS provides the parameters to the CKM_RC5_ECB and
 * CKM_RC5_MAC mechanisms */
/* CK_RC5_PARAMS is new for v2.0 */
typedef struct CK_RC5_PARAMS {
  CK_ULONG      ulWordsize;  /* wordsize in bits */
  CK_ULONG      ulRounds;    /* number of rounds */
} CK_RC5_PARAMS;

typedef CK_RC5_PARAMS CK_PTR CK_RC5_PARAMS_PTR;

/* CK_AES_CTR_PARAMS is new for PKCS #11 v2.20 amendment 3 */
typedef struct CK_AES_CTR_PARAMS {
    CK_ULONG ulCounterBits;
    CK_BYTE cb[16];
} CK_AES_CTR_PARAMS;

typedef CK_AES_CTR_PARAMS CK_PTR CK_AES_CTR_PARAMS_PTR;

typedef struct CK_GCM_PARAMS {
	CK_BYTE_PTR pIv;
	CK_ULONG ulIvLen;
	CK_BYTE_PTR pAAD;
	CK_ULONG ulAADLen;
	CK_ULONG ulTagBits;
} CK_GCM_PARAMS;

typedef CK_GCM_PARAMS CK_PTR CK_GCM_PARAMS_PTR;

/* CK_RC5_CBC_PARAMS provides the parameters to the CKM_RC5_CBC
 * mechanism */
/* CK_RC5_CBC_PARAMS is new for v2.0 */
typedef struct CK_RC5_CBC_PARAMS {
  CK_ULONG      ulWordsize;  /* wordsize in bits */
  CK_ULONG      ulRounds;    /* number of rounds */
  CK_BYTE_PTR   pIv;         /* pointer to IV */
  CK_ULONG      ulIvLen;     /* length of IV in bytes */
} CK_RC5_CBC_PARAMS;

typedef CK_RC5_CBC_PARAMS CK_PTR CK_RC5_CBC_PARAMS_PTR;


/* CK_RC5_MAC_GENERAL_PARAMS provides the parameters for the
 * CKM_RC5_MAC_GENERAL mechanism */
/* CK_RC5_MAC_GENERAL_PARAMS is new for v2.0 */
typedef struct CK_RC5_MAC_GENERAL_PARAMS {
  CK_ULONG      ulWordsize;   /* wordsize in bits */
  CK_ULONG      ulRounds;     /* number of rounds */
  CK_ULONG      ulMacLength;  /* Length of MAC in bytes */
} CK_RC5_MAC_GENERAL_PARAMS;

typedef CK_RC5_MAC_GENERAL_PARAMS CK_PTR \
  CK_RC5_MAC_GENERAL_PARAMS_PTR;


/* CK_MAC_GENERAL_PARAMS provides the parameters to most block
 * ciphers' MAC_GENERAL mechanisms.  Its value is the length of
 * the MAC */
/* CK_MAC_GENERAL_PARAMS is new for v2.0 */
typedef CK_ULONG          CK_MAC_GENERAL_PARAMS;

typedef CK_MAC_GENERAL_PARAMS CK_PTR CK_MAC_GENERAL_PARAMS_PTR;


/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS provides the parameters to the
 * CKM_SKIPJACK_PRIVATE_WRAP mechanism */
/* CK_SKIPJACK_PRIVATE_WRAP_PARAMS is new for v2.0 */
typedef struct CK_SKIPJACK_PRIVATE_WRAP_PARAMS {
  CK_ULONG      ulPasswordLen;
  CK_BYTE_PTR   pPassword;
  CK_ULONG      ulPublicDataLen;
  CK_BYTE_PTR   pPublicData;
  CK_ULONG      ulPAndGLen;
  CK_ULONG      ulQLen;
  CK_ULONG      ulRandomLen;
  CK_BYTE_PTR   pRandomA;
  CK_BYTE_PTR   pPrimeP;
  CK_BYTE_PTR   pBaseG;
  CK_BYTE_PTR   pSubprimeQ;
} CK_SKIPJACK_PRIVATE_WRAP_PARAMS;

typedef CK_SKIPJACK_PRIVATE_WRAP_PARAMS CK_PTR \
  CK_SKIPJACK_PRIVATE_WRAP_PTR;


/* CK_SKIPJACK_RELAYX_PARAMS provides the parameters to the
 * CKM_SKIPJACK_RELAYX mechanism */
/* CK_SKIPJACK_RELAYX_PARAMS is new for v2.0 */
typedef struct CK_SKIPJACK_RELAYX_PARAMS {
  CK_ULONG      ulOldWrappedXLen;
  CK_BYTE_PTR   pOldWrappedX;
  CK_ULONG      ulOldPasswordLen;
  CK_BYTE_PTR   pOldPassword;
  CK_ULONG      ulOldPublicDataLen;
  CK_BYTE_PTR   pOldPublicData;
  CK_ULONG      ulOldRandomLen;
  CK_BYTE_PTR   pOldRandomA;
  CK_ULONG      ulNewPasswordLen;
  CK_BYTE_PTR   pNewPassword;
  CK_ULONG      ulNewPublicDataLen;
  CK_BYTE_PTR   pNewPublicData;
  CK_ULONG      ulNewRandomLen;
  CK_BYTE_PTR   pNewRandomA;
} CK_SKIPJACK_RELAYX_PARAMS;

typedef CK_SKIPJACK_RELAYX_PARAMS CK_PTR \
  CK_SKIPJACK_RELAYX_PARAMS_PTR;


typedef struct CK_PBE_PARAMS {
  CK_CHAR_PTR  pInitVector;
  CK_CHAR_PTR  pPassword;
  CK_ULONG     ulPasswordLen;
  CK_CHAR_PTR  pSalt;
  CK_ULONG     ulSaltLen;
  CK_ULONG     ulIteration;
} CK_PBE_PARAMS;

typedef CK_PBE_PARAMS CK_PTR CK_PBE_PARAMS_PTR;


/* CK_KEY_WRAP_SET_OAEP_PARAMS provides the parameters to the
 * CKM_KEY_WRAP_SET_OAEP mechanism */
/* CK_KEY_WRAP_SET_OAEP_PARAMS is new for v2.0 */
typedef struct CK_KEY_WRAP_SET_OAEP_PARAMS {
  CK_BYTE       bBC;     /* block contents byte */
  CK_BYTE_PTR   pX;      /* extra data */
  CK_ULONG      ulXLen;  /* length of extra data in bytes */
} CK_KEY_WRAP_SET_OAEP_PARAMS;

typedef CK_KEY_WRAP_SET_OAEP_PARAMS CK_PTR \
  CK_KEY_WRAP_SET_OAEP_PARAMS_PTR;


typedef struct CK_SSL3_RANDOM_DATA {
  CK_BYTE_PTR  pClientRandom;
  CK_ULONG     ulClientRandomLen;
  CK_BYTE_PTR  pServerRandom;
  CK_ULONG     ulServerRandomLen;
} CK_SSL3_RANDOM_DATA;


typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS {
  CK_SSL3_RANDOM_DATA RandomInfo;
  CK_VERSION_PTR pVersion;
} CK_SSL3_MASTER_KEY_DERIVE_PARAMS;

typedef struct CK_SSL3_MASTER_KEY_DERIVE_PARAMS CK_PTR \
  CK_SSL3_MASTER_KEY_DERIVE_PARAMS_PTR;


typedef struct CK_SSL3_KEY_MAT_OUT {
  CK_OBJECT_HANDLE hClientMacSecret;
  CK_OBJECT_HANDLE hServerMacSecret;
  CK_OBJECT_HANDLE hClientKey;
  CK_OBJECT_HANDLE hServerKey;
  CK_BYTE_PTR      pIVClient;
  CK_BYTE_PTR      pIVServer;
} CK_SSL3_KEY_MAT_OUT;

typedef CK_SSL3_KEY_MAT_OUT CK_PTR CK_SSL3_KEY_MAT_OUT_PTR;


typedef struct CK_SSL3_KEY_MAT_PARAMS {
  CK_ULONG                ulMacSizeInBits;
  CK_ULONG                ulKeySizeInBits;
  CK_ULONG                ulIVSizeInBits;
  CK_BBOOL                bIsExport;
  CK_SSL3_RANDOM_DATA     RandomInfo;
  CK_SSL3_KEY_MAT_OUT_PTR pReturnedKeyMaterial;
} CK_SSL3_KEY_MAT_PARAMS;

typedef CK_SSL3_KEY_MAT_PARAMS CK_PTR CK_SSL3_KEY_MAT_PARAMS_PTR;


typedef struct CK_KEY_DERIVATION_STRING_DATA {
  CK_BYTE_PTR pData;
  CK_ULONG    ulLen;
} CK_KEY_DERIVATION_STRING_DATA;

typedef CK_KEY_DERIVATION_STRING_DATA CK_PTR \
  CK_KEY_DERIVATION_STRING_DATA_PTR;


/* The CK_EXTRACT_PARAMS is used for the
 * CKM_EXTRACT_KEY_FROM_KEY mechanism.  It specifies which bit
 * of the base key should be used as the first bit of the
 * derived key */
/* CK_EXTRACT_PARAMS is new for v2.0 */
typedef CK_ULONG CK_EXTRACT_PARAMS;

typedef CK_EXTRACT_PARAMS CK_PTR CK_EXTRACT_PARAMS_PTR;

/* RSA mechanism OAEP encoding */
typedef CK_ULONG CK_RSA_PKCS_OAEP_SOURCE_TYPE;
typedef CK_ULONG CK_RSA_PKCS_MGF_TYPE;
typedef CK_RSA_PKCS_MGF_TYPE CK_PTR CK_RSA_PKCS_MGF_TYPE_PTR;
/* PKCS#1 RSA OAEP Encoding Parameter Sources */
#define CKZ_DATA_SPECIFIED 0x00000001

/* PKCS#1 Mask Generation Functions */
#define CKG_MGF1_SHA1   0x00000001
#define CKG_MGF1_SHA256 0x00000002
#define CKG_MGF1_SHA384 0x00000003
#define CKG_MGF1_SHA512 0x00000004

typedef struct CK_RSA_PKCS_OAEP_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_RSA_PKCS_OAEP_SOURCE_TYPE source;
	CK_VOID_PTR pSourceData;
	CK_ULONG ulSourceDataLen;
} CK_RSA_PKCS_OAEP_PARAMS;

typedef CK_RSA_PKCS_OAEP_PARAMS CK_PTR CK_RSA_PKCS_OAEP_PARAMS_PTR;

typedef struct CK_RSA_PKCS_PSS_PARAMS {
	CK_MECHANISM_TYPE hashAlg;
	CK_RSA_PKCS_MGF_TYPE mgf;
	CK_ULONG sLen;
} CK_RSA_PKCS_PSS_PARAMS;

typedef CK_RSA_PKCS_PSS_PARAMS CK_PTR CK_RSA_PKCS_PSS_PARAMS_PTR;

/* CK_FUNCTION_LIST is a structure holding a Cryptoki spec
 * version and pointers of appropriate types to all the
 * Cryptoki functions */
/* CK_FUNCTION_LIST is new for v2.0 */
typedef struct CK_FUNCTION_LIST CK_FUNCTION_LIST;

typedef CK_FUNCTION_LIST CK_PTR CK_FUNCTION_LIST_PTR;

typedef CK_FUNCTION_LIST_PTR CK_PTR CK_FUNCTION_LIST_PTR_PTR;

typedef CK_RV	(CK_PTR CK_C_Initialize)
						(CK_VOID_PTR pReserved);
typedef CK_RV	(CK_PTR  CK_C_Finalize)
						(CK_VOID_PTR pReserved);
typedef CK_RV	(CK_PTR  CK_C_Terminate)
						(void);
typedef CK_RV	(CK_PTR  CK_C_GetInfo)
						(CK_INFO_PTR pInfo);
typedef CK_RV	(CK_PTR  CK_C_GetFunctionList)
						(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
typedef CK_RV	(CK_PTR  CK_C_GetSlotList)
						(CK_BBOOL tokenPresent, CK_SLOT_ID_PTR pSlotList,
						 CK_ULONG_PTR pusCount);
typedef CK_RV	(CK_PTR  CK_C_GetSlotInfo)
						(CK_SLOT_ID slotID, CK_SLOT_INFO_PTR pInfo);
typedef CK_RV	(CK_PTR  CK_C_GetTokenInfo)
						(CK_SLOT_ID slotID, CK_TOKEN_INFO_PTR pInfo);
typedef CK_RV	(CK_PTR  CK_C_GetMechanismList)
						(CK_SLOT_ID slotID, CK_MECHANISM_TYPE_PTR pMechanismList,
						 CK_ULONG_PTR pusCount);
typedef CK_RV	(CK_PTR  CK_C_GetMechanismInfo)
						(CK_SLOT_ID slotID, CK_MECHANISM_TYPE type,
						 CK_MECHANISM_INFO_PTR pInfo);
typedef CK_RV	(CK_PTR  CK_C_InitToken)
						(CK_SLOT_ID slotID, CK_CHAR_PTR pPin, CK_ULONG usPinLen,
						 CK_CHAR_PTR pLabel);
typedef CK_RV	(CK_PTR  CK_C_InitPIN)
						(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pPin,
						 CK_ULONG usPinLen);
typedef CK_RV	(CK_PTR  CK_C_SetPIN)
						(CK_SESSION_HANDLE hSession, CK_CHAR_PTR pOldPin,
						 CK_ULONG usOldLen, CK_CHAR_PTR pNewPin,
						 CK_ULONG usNewLen);
typedef CK_RV	(CK_PTR  CK_C_OpenSession)
						(CK_SLOT_ID slotID, CK_FLAGS flags,
						 CK_VOID_PTR pApplication,
						 CK_RV  (*Notify) (CK_SESSION_HANDLE hSession,
						 CK_NOTIFICATION event, CK_VOID_PTR pApplication),
						 CK_SESSION_HANDLE_PTR phSession);
typedef CK_RV	(CK_PTR  CK_C_CloseSession)
						(CK_SESSION_HANDLE hSession);
typedef CK_RV	(CK_PTR  CK_C_CloseAllSessions)
						(CK_SLOT_ID slotID);
typedef CK_RV	(CK_PTR  CK_C_GetSessionInfo)
						(CK_SESSION_HANDLE hSession, CK_SESSION_INFO_PTR pInfo);
typedef CK_RV	(CK_PTR  CK_C_GetOperationState)
						(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
						 CK_ULONG_PTR pulOperationStateLen);
typedef CK_RV	(CK_PTR  CK_C_SetOperationState)
						(CK_SESSION_HANDLE hSession, CK_BYTE_PTR pOperationState,
						 CK_ULONG ulOperationStateLen,
						 CK_OBJECT_HANDLE hEncryptionKey,
						 CK_OBJECT_HANDLE hAuthenticationKey);
typedef CK_RV	(CK_PTR  CK_C_Login)(CK_SESSION_HANDLE hSession,
						 CK_USER_TYPE userType, CK_CHAR_PTR pPin,
						 CK_ULONG usPinLen);
typedef CK_RV	(CK_PTR  CK_C_Logout)(CK_SESSION_HANDLE hSession);
typedef CK_RV	(CK_PTR  CK_C_CreateObject)
						(CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
						 CK_ULONG usCount, CK_OBJECT_HANDLE_PTR phObject);
typedef CK_RV	(CK_PTR  CK_C_CopyObject)
						(CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
						 CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount,
						 CK_OBJECT_HANDLE_PTR phNewObject);
typedef CK_RV (CK_PTR  CK_C_DestroyObject)
                       (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject);
typedef CK_RV(CK_PTR  CK_C_GetObjectSize)
                       (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                        CK_ULONG_PTR pusSize);
typedef CK_RV(CK_PTR  CK_C_GetAttributeValue)
                       (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount);
typedef CK_RV(CK_PTR  CK_C_SetAttributeValue)
                       (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hObject,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount);
typedef CK_RV (CK_PTR  CK_C_FindObjectsInit)
                       (CK_SESSION_HANDLE hSession, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG usCount);
typedef CK_RV (CK_PTR  CK_C_FindObjects)
                       (CK_SESSION_HANDLE hSession,
                        CK_OBJECT_HANDLE_PTR phObject, CK_ULONG usMaxObjectCount,
                        CK_ULONG_PTR pusObjectCount);
typedef CK_RV (CK_PTR  CK_C_FindObjectsFinal)
                       (CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_PTR  CK_C_EncryptInit)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  CK_C_Encrypt)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                        CK_ULONG usDataLen, CK_BYTE_PTR pEncryptedData,
                        CK_ULONG_PTR pusEncryptedDataLen);
typedef CK_RV (CK_PTR  CK_C_EncryptUpdate)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                        CK_ULONG usPartLen, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG_PTR pusEncryptedPartLen);
typedef CK_RV (CK_PTR  CK_C_EncryptFinal)
                       (CK_SESSION_HANDLE hSession,
                        CK_BYTE_PTR pLastEncryptedPart,
                        CK_ULONG_PTR pusLastEncryptedPartLen);
typedef CK_RV (CK_PTR  CK_C_DecryptInit)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  CK_C_Decrypt)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedData,
                        CK_ULONG usEncryptedDataLen, CK_BYTE_PTR pData,
                        CK_ULONG_PTR pusDataLen);
typedef CK_RV (CK_PTR  CK_C_DecryptUpdate)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG usEncryptedPartLen, CK_BYTE_PTR pPart,
                        CK_ULONG_PTR pusPartLen);
typedef CK_RV (CK_PTR  CK_C_DecryptFinal)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pLastPart,
                        CK_ULONG_PTR pusLastPartLen);
typedef CK_RV (CK_PTR  CK_C_DigestInit)
                       (CK_SESSION_HANDLE hSession,
                        CK_MECHANISM_PTR pMechanism);
typedef CK_RV (CK_PTR  CK_C_Digest)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                        CK_ULONG usDataLen, CK_BYTE_PTR pDigest,
                        CK_ULONG_PTR pusDigestLen);
typedef CK_RV (CK_PTR  CK_C_DigestUpdate)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                        CK_ULONG usPartLen);
typedef CK_RV (CK_PTR  CK_C_DigestKey)
                       (CK_SESSION_HANDLE hSession, CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  CK_C_DigestFinal)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pDigest,
                        CK_ULONG_PTR pusDigestLen);
typedef CK_RV (CK_PTR  CK_C_SignInit)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  CK_C_Sign)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                        CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
                        CK_ULONG_PTR pusSignatureLen);
typedef CK_RV (CK_PTR  CK_C_SignUpdate)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                        CK_ULONG usPartLen);
typedef CK_RV (CK_PTR  CK_C_SignFinal)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                        CK_ULONG_PTR pusSignatureLen);
typedef CK_RV (CK_PTR  CK_C_SignRecoverInit)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  CK_C_SignRecover)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                        CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
                        CK_ULONG_PTR pusSignatureLen);
typedef CK_RV (CK_PTR  CK_C_VerifyInit)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  CK_C_Verify)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pData,
                        CK_ULONG usDataLen, CK_BYTE_PTR pSignature,
                        CK_ULONG usSignatureLen);
typedef CK_RV (CK_PTR  CK_C_VerifyUpdate)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                        CK_ULONG usPartLen);
typedef CK_RV (CK_PTR  CK_C_VerifyFinal)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                        CK_ULONG usSignatureLen);
typedef CK_RV (CK_PTR  CK_C_VerifyRecoverInit)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hKey);
typedef CK_RV (CK_PTR  CK_C_VerifyRecover)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSignature,
                        CK_ULONG usSignatureLen, CK_BYTE_PTR pData,
                        CK_ULONG_PTR pusDataLen);
typedef CK_RV (CK_PTR  CK_C_DigestEncryptUpdate)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                        CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (CK_PTR  CK_C_DecryptDigestUpdate)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                        CK_ULONG_PTR pulPartLen);
typedef CK_RV (CK_PTR  CK_C_SignEncryptUpdate)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pPart,
                        CK_ULONG ulPartLen, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG_PTR pulEncryptedPartLen);
typedef CK_RV (CK_PTR  CK_C_DecryptVerifyUpdate)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pEncryptedPart,
                        CK_ULONG ulEncryptedPartLen, CK_BYTE_PTR pPart,
                        CK_ULONG_PTR pulPartLen);
typedef CK_RV (CK_PTR  CK_C_GenerateKey)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pTemplate, CK_ULONG usCount,
                        CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_PTR  CK_C_GenerateKeyPair)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                        CK_ULONG usPublicKeyAttributeCount,
                        CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                        CK_ULONG usPrivateKeyAttributeCount,
                        CK_OBJECT_HANDLE_PTR phPrivateKey,
                        CK_OBJECT_HANDLE_PTR phPublicKey);
typedef CK_RV (CK_PTR  CK_C_WrapKey)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hWrappingKey, CK_OBJECT_HANDLE hKey,
                        CK_BYTE_PTR pWrappedKey, CK_ULONG_PTR pusWrappedKeyLen);
typedef CK_RV (CK_PTR  CK_C_UnwrapKey)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hUnwrappingKey, CK_BYTE_PTR pWrappedKey,
                        CK_ULONG usWrappedKeyLen, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG usAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_PTR  CK_C_DeriveKey)
                       (CK_SESSION_HANDLE hSession, CK_MECHANISM_PTR pMechanism,
                        CK_OBJECT_HANDLE hBaseKey, CK_ATTRIBUTE_PTR pTemplate,
                        CK_ULONG usAttributeCount, CK_OBJECT_HANDLE_PTR phKey);
typedef CK_RV (CK_PTR  CK_C_SeedRandom)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pSeed,
                        CK_ULONG usSeedLen);
typedef CK_RV (CK_PTR  CK_C_GenerateRandom)
                       (CK_SESSION_HANDLE hSession, CK_BYTE_PTR pRandomData,
                        CK_ULONG usRandomLen);
typedef CK_RV (CK_PTR  CK_C_GetFunctionStatus)
                       (CK_SESSION_HANDLE hSession);
typedef CK_RV (CK_PTR  CK_C_CancelFunction)
                       (CK_SESSION_HANDLE hSession);
typedef CK_RV	(CK_PTR  CK_Notify)
						(CK_SESSION_HANDLE hSession, CK_NOTIFICATION event,
						 CK_VOID_PTR pApplication);
typedef CK_RV	(CK_PTR  CK_C_WaitForSlotEvent)
						(CK_FLAGS flags, CK_SLOT_ID_PTR pSlot,
						 CK_VOID_PTR pReserved);

struct CK_FUNCTION_LIST {
	CK_VERSION version;
	CK_C_Initialize C_Initialize;
	CK_C_Finalize C_Finalize;
	CK_C_GetInfo C_GetInfo;
	CK_C_GetFunctionList C_GetFunctionList;
	CK_C_GetSlotList C_GetSlotList;
	CK_C_GetSlotInfo C_GetSlotInfo;
	CK_C_GetTokenInfo C_GetTokenInfo;
	CK_C_GetMechanismList C_GetMechanismList;
	CK_C_GetMechanismInfo C_GetMechanismInfo;
	CK_C_InitToken C_InitToken;
	CK_C_InitPIN C_InitPIN;
	CK_C_SetPIN C_SetPIN;
	CK_C_OpenSession C_OpenSession;
	CK_C_CloseSession C_CloseSession;
	CK_C_CloseAllSessions C_CloseAllSessions;
	CK_C_GetSessionInfo C_GetSessionInfo;
	CK_C_GetOperationState C_GetOperationState;
	CK_C_SetOperationState C_SetOperationState;
	CK_C_Login C_Login;
	CK_C_Logout C_Logout;
	CK_C_CreateObject C_CreateObject;
	CK_C_CopyObject C_CopyObject;
	CK_C_DestroyObject C_DestroyObject;
	CK_C_GetObjectSize C_GetObjectSize;
	CK_C_GetAttributeValue C_GetAttributeValue;
	CK_C_SetAttributeValue C_SetAttributeValue;
	CK_C_FindObjectsInit C_FindObjectsInit;
	CK_C_FindObjects C_FindObjects;
	CK_C_FindObjectsFinal C_FindObjectsFinal;
	CK_C_EncryptInit C_EncryptInit;
	CK_C_Encrypt C_Encrypt;
	CK_C_EncryptUpdate C_EncryptUpdate;
	CK_C_EncryptFinal C_EncryptFinal;
	CK_C_DecryptInit C_DecryptInit;
	CK_C_Decrypt C_Decrypt;
	CK_C_DecryptUpdate C_DecryptUpdate;
	CK_C_DecryptFinal C_DecryptFinal;
	CK_C_DigestInit C_DigestInit;
	CK_C_Digest C_Digest;
	CK_C_DigestUpdate C_DigestUpdate;
	CK_C_DigestKey C_DigestKey;
	CK_C_DigestFinal C_DigestFinal;
	CK_C_SignInit C_SignInit;
	CK_C_Sign C_Sign;
	CK_C_SignUpdate C_SignUpdate;
	CK_C_SignFinal C_SignFinal;
	CK_C_SignRecoverInit C_SignRecoverInit;
	CK_C_SignRecover C_SignRecover;
	CK_C_VerifyInit C_VerifyInit;
	CK_C_Verify C_Verify;
	CK_C_VerifyUpdate C_VerifyUpdate;
	CK_C_VerifyFinal C_VerifyFinal;
	CK_C_VerifyRecoverInit C_VerifyRecoverInit;
	CK_C_VerifyRecover C_VerifyRecover;
	CK_C_DigestEncryptUpdate C_DigestEncryptUpdate;
	CK_C_DecryptDigestUpdate C_DecryptDigestUpdate;
	CK_C_SignEncryptUpdate C_SignEncryptUpdate;
	CK_C_DecryptVerifyUpdate C_DecryptVerifyUpdate;
	CK_C_GenerateKey C_GenerateKey;
	CK_C_GenerateKeyPair C_GenerateKeyPair;
	CK_C_WrapKey C_WrapKey;
	CK_C_UnwrapKey C_UnwrapKey;
	CK_C_DeriveKey C_DeriveKey;
	CK_C_SeedRandom C_SeedRandom;
	CK_C_GenerateRandom C_GenerateRandom;
	CK_C_GetFunctionStatus C_GetFunctionStatus;
	CK_C_CancelFunction C_CancelFunction;
	CK_C_WaitForSlotEvent C_WaitForSlotEvent;
};

#ifdef __cplusplus
}
#endif

#endif // _PKCS11TYPES_H_
