/*
 * (C) Copyright IBM Corp. 2012, 2025
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 *
 *----------------------------------------------------------------------
 *  EP11 service mail address: EP11SERV@de.ibm.com
 *
 *  Use this e-mail address for Bugs and Comments with the EP11 product.
 *----------------------------------------------------------------------*/

#if !defined(XCP_H__)
#define XCP_H__

#define XCP_API_VERSION 0x0906
#if !defined(CKR_OK)
#include "pkcs11.h"
#endif

#if !defined(INT64_MIN)
#error "We need 64-bit <stdint.h> types, please include before this file."
#endif

//
// used for internal and external paths/addresses
#define  MAX_FNAME_CHARS  256

// Error Values for functions that do not return CK_RV
// general errors
#define XCP_OK                   0  /* function successful
                                     */
#define XCP_EINTERNAL           -1  /* host library internal error.
                                     * host library is in an inconsistent state
                                     * shutdown and new init is needed
                                     */
#define XCP_EARG                -2  /* Argument is invalid
                                     */
#define XCP_ETARGET             -3  /* Target argument is invalid
                                     */
#define XCP_EMEMORY             -4  /* could not allocate memory
                                     */
#define XCP_EMUTEX              -5  /* Mutex is invalid
                                     */
#define XCP_EINIT               -6  /* Could not initialize library
                                     */
#define XCP_EDEVICE             -7  /* The channel that is used to communicate
                                     * with the backend is not available or
                                     * invalid
                                     */
#define XCP_EGROUP              -8  /* Target group is unusable or invalid
                                     */
#define XCP_ESIZE               -9  /* invalid size
                                     */
#define XCP_EINVALID            -10 /* invalid content of parameter
                                     */
#define XCP_ERESPONSE           -11 /* bad response from module. Sometimes
                                     * it is not possible to return the CK_RV
                                     * value directly and we can only say that
                                     * something failed.
                                     */
#define XCP_EAPI                -12  /* incompatible/invalid api
                                     */
// module specific errors
#define  XCP_MOD_EOBSOLETE      -101 /* past feature has been obsoleted,
                                      * no longer available. check notes on
                                      * future-compatibility.
                                      */
#define  XCP_MOD_EVERSION       -102 /* library predates caller, does not
                                      * support requested API version
                                      */
#define  XCP_MOD_EFLAGS         -103 /* library does not support all requested
                                      * flags, even if call/struct is otherwise
                                      * API-compatible. expect this only when
                                      * device-specific details (module
                                      * selection, communication/channel type)
                                      * are not supported by the backend.
                                      */
#define  XCP_MOD_EMODULE        -104 /* library does not support this module
                                      * number (a real one, not virtual ones).
                                      * typical error when locally attached
                                      * modules' count has an upper bound.
                                      */
#define  XCP_MOD_EDOMAIN        -105 /* the targeted module does not support
                                      * the requested domain.
                                      */
#define  XCP_MOD_EINIT          -106 /* the targeted module is not initialized
                                      * typical error for socket attached
                                      * modules, because adding this modules
                                      * on the fly is not possible
                                      */
#define  XCP_MOD_EPROBE         -107 /* probe did fail for all defined domains.
                                      * This is an error even when the strict
                                      * flag is not active
                                      */

/*--------------------------------------------------------------------------*/
#define XCP_COMMON_PUBLIC_H__

#ifndef XCP_H__
#define CK_DISABLE_TRUE_FALSE
#endif

#define  XCP_API_VERSION_Z16  0x0827     /* major[8] minor[8] */
#define  XCP_API_VERSION_Z17  0x0906     /* major[8] minor[8] */
#define  XCP_API_ORDINAL  0x0006
	       /* increment this with every major/minor change */

#define  XCP_HOST_API_VER  0x040200   /* major[8] minor[8] fixpack[8] */

/* HSM connection information; not for PKCS11 user consumption */
#define  XCP_HSM_AGENT_ID   0x5843           /* ASCII "XC" */
#define  XCP_HSM_USERDEF32  0x01234567

// protected key requires API ordinal greater or equal to 4
#define XCP_API_ALLOW_PROTKEY  0x0004

// Support for extended FIPS2021 attributes
//
// Requests for card/domain attributes (XCP_ADMQ_ATTRS/XCP_ADMQ_DOM_ATTRS)
// will contain the extended attributes (key-types, adm FIPS2021 compliance)
// only with API ordinal 5 (or higher) for compatibility reasons.
// Also, the module sub-queries CK_IBM_XCPMSQ_ATTRLIST, CK_IBM_XCPMSQ_ATTRS
// and CK_IBM_XCPMSQ_ATTRCOUNT will contain the information related to the
// extended attributes only with this API ordinal.
#define XCP_API_ALLOW_FIPS2021  0x0005


// function sub-variants
// 0 means regular request
typedef enum {
	XCP_FNVAR_SIZEQUERY  = 1, /* sizequery: databytes[64]->resp.bytes[64] */
	XCP_FNVAR_MULTIDATA  = 2, /* multi-data request                       */
	XCP_FNVAR_MULTISIZEQ = 3  /* multi-data request, size query           */
} XCP_FNVariant_t;


// XCP-specific return codes
//
#define  CKR_IBM_WKID_MISMATCH      (CKR_VENDOR_DEFINED +0x10001)
#define  CKR_IBM_INTERNAL_ERROR     (CKR_VENDOR_DEFINED +0x10002)
#define  CKR_IBM_TRANSPORT_ERROR    (CKR_VENDOR_DEFINED +0x10003)
#define  CKR_IBM_BLOB_ERROR         (CKR_VENDOR_DEFINED +0x10004)
		/* WK setup changed during the execution of a single request,
		 * preventing return of encrypted data to the host. (i.e.,
		 * an administrative operation changed WKs before the
		 * function could re-wrap data to pass back to the host)
		 */
#define  CKR_IBM_BLOBKEY_CONFLICT   (CKR_VENDOR_DEFINED +0x10005)
#define  CKR_IBM_MODE_CONFLICT      (CKR_VENDOR_DEFINED +0x10006)
		/* an RSA key in non-CRT form is encountered which is not
		 * supported by this hardware/engine configuration, if the
		 * setup has non/CRT-specific size restrictions.
		 * in essence, a more specific sub-division of
		 * the standard CKR_KEY_SIZE_RANGE, and MAY be
		 * safely mapped to that by host libraries.
		 */
#define  CKR_IBM_NONCRT_KEY_SIZE    (CKR_VENDOR_DEFINED +0x10008)
#define  CKR_IBM_WK_NOT_INITIALIZED (CKR_VENDOR_DEFINED +0x10009)
		/* unexpected/consistency error of CA operations of the
		 * hosting HSM, if not otherwise classified.
		 */
#define  CKR_IBM_OA_API_ERROR       (CKR_VENDOR_DEFINED +0x1000a)
		/* potentially long-running request, such as those involving
		 * prime generation, did not complete in a 'reasonable'
		 * number of iterations. supported to prevent timeout-
		 * triggered module resets, such as mainframe firmware
		 * resetting modules 'stuck in infinite loops' (as perceived
		 * by the host)
		 */
#define  CKR_IBM_REQ_TIMEOUT        (CKR_VENDOR_DEFINED +0x1000b)
                /* backend in read-only state, rejecting state-changing
		 * operations:
		 */
#define  CKR_IBM_READONLY           (CKR_VENDOR_DEFINED +0x1000c)
                /* backend/policy may not be configured to accept request.
		 * this is the permanent form of policy failure
		 * (which is mapped to standard CKR_FUNCTION_CANCELED)
		 */
#define  CKR_IBM_STATIC_POLICY      (CKR_VENDOR_DEFINED +0x1000d)


                 /* backend not allowed to return requested nr of bytes: */
#define  CKR_IBM_TRANSPORT_LIMIT    (CKR_VENDOR_DEFINED +0x10010)
//
// use CKR_IBM_TRANSPORT_ERROR for errors introduced between ep11.h and backend
//     CKR_IBM_TRANSPORT_LIMIT for errors on return path
//     CKR_ARGUMENTS_BAD or specific one for bad data passed through ep11.h

#define  CKR_IBM_FCV_NOT_SET        (CKR_VENDOR_DEFINED +0x10011)

// Error returned by check if the performance category has not been set
#define  CKR_IBM_PERF_CATEGORY_INVALID   (CKR_VENDOR_DEFINED +0x10012)

// API ORDINAL number is unknown or function id is in illegal range
#define  CKR_IBM_API_MISMATCH   (CKR_VENDOR_DEFINED +0x10013)

// target token is invalid
#define  CKR_IBM_TARGET_INVALID     (CKR_VENDOR_DEFINED +0x10030)


#define  CKR_IBM_PQC_PARAMS_NOT_SUPPORTED  (CKR_VENDOR_DEFINED +0x10031)

#define  CKR_IBM_PARAM_NOT_SUPPORTED   (CKR_VENDOR_DEFINED +0x10032)

#define  CKR_IBM_SESSION_IMMUTABLE   (CKR_VENDOR_DEFINED +0x10033)

// Error returned if internal verification of crypto engines fail
#define CKR_IBM_ERROR_STATE       (CKR_VENDOR_DEFINED +0x10101)


/*---  mechanisms  ---------------------------------------------------------*/
#define  CKM_IBM_SHA3_224         (CKM_VENDOR_DEFINED +0x10001)
#define  CKM_IBM_SHA3_256         (CKM_VENDOR_DEFINED +0x10002)
#define  CKM_IBM_SHA3_384         (CKM_VENDOR_DEFINED +0x10003)
#define  CKM_IBM_SHA3_512         (CKM_VENDOR_DEFINED +0x10004)

#define  CKM_IBM_CMAC             (CKM_VENDOR_DEFINED +0x10007)
//
// non-SHA-1 ECDSA: no standard mechansims pre-v2.40
#define  CKM_IBM_ECDSA_SHA224     (CKM_VENDOR_DEFINED +0x10008)
#define  CKM_IBM_ECDSA_SHA256     (CKM_VENDOR_DEFINED +0x10009)
#define  CKM_IBM_ECDSA_SHA384     (CKM_VENDOR_DEFINED +0x1000a)
#define  CKM_IBM_ECDSA_SHA512     (CKM_VENDOR_DEFINED +0x1000b)

// EC point multiply
#define  CKM_IBM_EC_MULTIPLY      (CKM_VENDOR_DEFINED +0x1000c)


// EAC (machine-readable travel document: passport, DL, ID card PKI)
//
// derive secure messaging, a class of functions
#define  CKM_IBM_EAC              (CKM_VENDOR_DEFINED +0x1000d)
#define  XCP_EAC_NONCE_MAX_BYTES  64  /* salt/nonce */
#define  XCP_EAC_INFO_MAX_BYTES   64  /* other auxiliary data */
//
// variants within EAC
typedef enum {
	EACV_IBM_KEK_V101  = 1, // secret -> secure msg KEK  (EAC v1.01)
	EACV_IBM_MACK_V101 = 2, // secret -> secure msg MACK (EAC v1.01)
	EACV_IBM_PWD_V200  = 3, // passphrase -> secure msg KEK (EAC v2.00)
	EACV_IBM_HKDF      = 4, // HKDF( base-key, mechanism-attached salt )
	                        // salt is supplied with mechanism parameter
	                        // output bytecount specified as attribute
	                        // of derived key
	EACV_IBM_BCHAIN_TCERT0
	                   = 5  // blockchain: derive tcert from base EC key
	                        // and additive cleartext [potentially insecure]
} EAC_Var_t;

// test access

#define  CKM_IBM_TESTCODE         (CKM_VENDOR_DEFINED +0x1000e)


// SHA-512 derivatives later than PKCS#11 v2.20, SHA-512/256 and SHA-512/224
// see pkcs11add.h (since v2.40 drafts)(since v2.40 drafts)(since v2.40 drafts)(since v2.40 drafts)
//
#define  CKM_IBM_SHA512_256       (CKM_VENDOR_DEFINED +0x10012)
#define  CKM_IBM_SHA512_224       (CKM_VENDOR_DEFINED +0x10013)
#define  CKM_IBM_SHA512_256_HMAC  (CKM_VENDOR_DEFINED +0x10014)
#define  CKM_IBM_SHA512_224_HMAC  (CKM_VENDOR_DEFINED +0x10015)
//

// curve25519, key agreement
#define  CKM_IBM_EC_X25519                  (CKM_VENDOR_DEFINED +0x1001b)
//
// eddsa/25519 signatures, with SHA-512, no prehashing
#define  CKM_IBM_ED25519_SHA512             (CKM_VENDOR_DEFINED +0x1001c)
// curve448 ('Goldilocks'), key agreement
#define  CKM_IBM_EC_X448                    (CKM_VENDOR_DEFINED +0x1001e)
//
// ed448 signatures, with SHA-3/XOF, no prehashing
#define  CKM_IBM_ED448_SHA3                 (CKM_VENDOR_DEFINED +0x1001f)


// round counts are passed as mechanism parameters
#define  CKM_IBM_SIPHASH                    (CKM_VENDOR_DEFINED +0x10021)


// these need a strength definition
// XCP_U32_VALUE_BITS/CKA_VALUE_BITS would be sufficient; strength->K/L mapping
//
// umbrella mech for PQC/Crystals variants
#define  CKM_IBM_DILITHIUM                  (CKM_VENDOR_DEFINED +0x10023)
         // ^^^ sign/verify plus keygen only
#define  CKM_IBM_KYBER                      (CKM_VENDOR_DEFINED +0x10024)
         // ^^^ en/decrypt, keygen, key transport, and (hybrid) key derivation

// SHA-3 HMAC variants
#define  CKM_IBM_SHA3_224_HMAC              (CKM_VENDOR_DEFINED +0x10025)
#define  CKM_IBM_SHA3_256_HMAC              (CKM_VENDOR_DEFINED +0x10026)
#define  CKM_IBM_SHA3_384_HMAC              (CKM_VENDOR_DEFINED +0x10027)
#define  CKM_IBM_SHA3_512_HMAC              (CKM_VENDOR_DEFINED +0x10028)

// curve25519, key agreement (using KEK)
#define  CKM_IBM_EC_X25519_RAW              (CKM_VENDOR_DEFINED +0x10029)

// curve448 ('Goldilocks'), key agreement (using KEK)
#define  CKM_IBM_EC_X448_RAW                (CKM_VENDOR_DEFINED +0x10030)

#define  CKM_IBM_ECDSA_OTHER                (CKM_VENDOR_DEFINED +0x10031)


typedef enum {

	ECSG_IBM_ECSDSA_S256        = 3,
	                              // [Randomized] Schnorr signatures
	                              // BSI TR03111 ECSDSA
	                              // no prehashing; SHA-256 only
	ECSG_IBM_ECSDSA_COMPR_MULTI = 5,
	                              // [Randomized] Schnorr signatures
	                              // BSI TR-03111 @2012, working on
	                              // compressed public key format and
	                              // including signers public key

	ECSG_IBM_BLS                = 6,
	                              // Boneh-Lynn-Shacham signatures
	                              // RFC draft-irtf-cfrg-bls-signature-05


	ECSG_IBM_MAX                = ECSG_IBM_BLS,
} ECSG_Var_t;


#define  CKM_IBM_EC_AGGREGATE  (CKM_VENDOR_DEFINED +0x10034)

typedef enum {
	EC_AGG_BLS12_381_SIGN = 1, // size of signature is sufficient indicator
	EC_AGG_BLS12_381_PKEY = 2,
	EC_AGG_BLS12_381_MAX  = EC_AGG_BLS12_381_PKEY,
} ECAgg_Var_t;

#define  CK_IBM_EC_AGG_BLS12_381_SIGN  EC_AGG_BLS12_381_SIGN
#define  CK_IBM_EC_AGG_BLS12_381_PKEY  EC_AGG_BLS12_381_PKEY

typedef struct XCP_EC_AGGREGATE_PARAMS {
	CK_ULONG version;
	CK_ULONG mode;
	CK_ULONG perElementSize;
	CK_BYTE_PTR pElements;
	CK_ULONG ulElementsLen;
} XCP_EC_AGGREGATE_PARAMS;


#define  CK_IBM_ECSG_IBM_ECSDSA_S256             ECSG_IBM_ECSDSA_S256
#define  CK_IBM_ECSG_IBM_ECDSA_COMPR_MULTI_S256  ECSG_IBM_ECDSA_COMPR_MULTI_S256
#define  CK_IBM_ECSG_IBM_BLS                     ECSG_IBM_BLS
#define  CK_IBM_ECSG_IBM_MAX                     ECSG_IBM_MAX

#define  CKM_IBM_ML_DSA_KEY_PAIR_GEN     (CKM_VENDOR_DEFINED +0x10035)
#define  CKM_IBM_ML_DSA                  (CKM_VENDOR_DEFINED +0x10036)
         // ^^^ sign/verify only
#define  CKM_IBM_ML_KEM_KEY_PAIR_GEN     (CKM_VENDOR_DEFINED +0x10037)
#define  CKM_IBM_ML_KEM                  (CKM_VENDOR_DEFINED +0x10038)
         // ^^^ key transport, and (hybrid) key derivation


//---  transport additions  --------------------------------------------------
#define  CKM_IBM_CLEARKEY_TRANSPORT    (CKM_VENDOR_DEFINED +0x20001)
// key+attributes bound format (ignores other attributes)
#define  CKM_IBM_ATTRIBUTEBOUND_WRAP   (CKM_VENDOR_DEFINED +0x20004)
// operations related to key cloning
#define  CKM_IBM_TRANSPORTKEY          (CKM_VENDOR_DEFINED +0x20005)

// EC/DH equivalents: derive key, then return encrypted under
// KEK supplied as auxiliary data
// (does not resemble regular PKCS11 mechanisms)
//
#define  CKM_IBM_DH_PKCS_DERIVE_RAW    (CKM_VENDOR_DEFINED +0x20006)
#define  CKM_IBM_ECDH1_DERIVE_RAW      (CKM_VENDOR_DEFINED +0x20007)

// none of these have PKCS11 constants (as of 2018-02)


//
// allow direct access to mechanism's wireform
// parameter of this mechanism is used as wire form
#define  CKM_IBM_WIRETEST              (CKM_VENDOR_DEFINED +0x30004)


//---  separate infrastructure-related mechs  --------------------------------
// to generate/refill semi-retained keys
// see also CKA_IBM_RETAINKEY
//
#define  CKM_IBM_RETAINKEY             (CKM_VENDOR_DEFINED +0x40001)



// IBM protkey data key import mechanism (WrapKey)
#define  CKM_IBM_CPACF_WRAP            (CKM_VENDOR_DEFINED +0x60001)


// bitcoin key derivation
#define  CKM_IBM_BTC_DERIVE            (CKM_VENDOR_DEFINED +0x70001)

// etherium key derivation
#define  CKM_IBM_ETH_DERIVE            (CKM_VENDOR_DEFINED +0x70002)

/*---  attributes  ---------------------------------------------------------*/

// object may have rights removed, but not added (subset of modifiability)
#define  CKA_IBM_RESTRICTABLE      (CKA_VENDOR_DEFINED +0x10001)

// object was created non-MODIFIABLE
#define  CKA_IBM_NEVER_MODIFIABLE  (CKA_VENDOR_DEFINED +0x10002)

// object is HSM-resident (handle instead of full token)
// has a single parameter, usage count
#define  CKA_IBM_RETAINKEY         (CKA_VENDOR_DEFINED +0x10003)

// object must be transported with attributes, never separated
// note: incompatible with pure-PKCS#11 un/wrap
#define  CKA_IBM_ATTRBOUND         (CKA_VENDOR_DEFINED +0x10004)

// symbolic key type in other hierarchies (CK_ULONG)
// XCP stores but ignores it
#define  CKA_IBM_KEYTYPE           (CKA_VENDOR_DEFINED +0x10005)

// restrictions inherited from other type systems
// XCP stores and partially interprets it
#define  CKA_IBM_CV                (CKA_VENDOR_DEFINED +0x10006)

// attribute containing MAC key handle, or blob, for authenticated key transport
#define  CKA_IBM_MACKEY            (CKA_VENDOR_DEFINED +0x10007)

// object may be used as base data of other ops, i.e., hashing or key derivation
//
#define  CKA_IBM_USE_AS_DATA       (CKA_VENDOR_DEFINED +0x10008)

// DSA/DH parameters as ALGID structure (PKCS#3)
#define  CKA_IBM_STRUCT_PARAMS     (CKA_VENDOR_DEFINED +0x10009)

// compliance mode, bitfield within 32-bit (CK_ULONG) parameter
#define  CKA_IBM_STD_COMPLIANCE1   (CKA_VENDOR_DEFINED +0x1000a)


// key is extractable only as protected key
#define  CKA_IBM_PROTKEY_EXTRACTABLE        (CKA_VENDOR_DEFINED +0x1000c)

// key is never extractable as protected key
#define  CKA_IBM_PROTKEY_NEVER_EXTRACTABLE  (CKA_VENDOR_DEFINED +0x1000d)

#define  CKA_IBM_PQC_PARAMS        (CKA_VENDOR_DEFINED +0x1000e)

// query or modify login session an object is bound to
#define  CKA_IBM_LOGIN_SESSION     (CKA_VENDOR_DEFINED +0x1000f)

// query or modify login session an object is bound to
#define  CKA_IBM_LOGIN_SESSION     (CKA_VENDOR_DEFINED +0x1000f)

#define  CKA_IBM_PARAMETER_SET        (CKA_VENDOR_DEFINED +0x10010)

// query MAC'd spki from a private key
#define  CKA_IBM_MACED_PUBLIC_KEY_INFO (CKA_VENDOR_DEFINED +0x20002)

// direct access to attributes' wire form
// parameters of this attribute, if it's the only one present,
// inserted verbatim into request package
#define  CKA_IBM_WIRETEST          (CKA_VENDOR_DEFINED +0x20001)


// matches the key type constant for clear key Dilithium with ICSF
#define CKK_IBM_PQC_DILITHIUM      (CKK_VENDOR_DEFINED +0x10023)

#define CKK_IBM_PQC_KYBER          (CKK_VENDOR_DEFINED +0x10024)

#define CKK_IBM_ML_DSA         (CKK_VENDOR_DEFINED +0x10025)

#define CKK_IBM_ML_KEM         (CKK_VENDOR_DEFINED +0x10026)





#define XCP_MOD_ERROR_STATE_OFF               0x00000000
#define XCP_MOD_ERROR_STATE_MODULE_SELFTEST   0x00000001
#define XCP_MOD_ERROR_STATE_KEYPAIR_GEN_PCT   0x00000002
#define XCP_MOD_ERROR_STATE_SYSTEST_CMD       0x00000003
#define XCP_MOD_ERROR_STATE_TRNG_HEALTH       0x00000004


/*----------------------------------------------------------------------------
 * sizes related to blobs and host-visible entities
 *
 * Cast as many to size_t/unsigned types as possible, to minimize the number
 * of 'mixed un/signed types' warnings. Unfortunately, this does not work
 * for those which are used by preprocessor math (XCP_WK_BYTES, for example),
 * since the preprocessor can not deal with typed arithmetic.
 */
#define  XCP_HMAC_BYTES ((size_t) (256 /8)) /* SHA-256 */
#define  XCP_FWID_BYTES ((size_t) (256 /8)) /* SHA-256 */
#define  XCP_WK_BYTES   ((size_t) (256 /8)) /* keypart and session sizes   */
                                            /* are identical               */
#define  XCP_WKID_BYTES ((size_t) (128 /8)) /* truncated hash */
#define  XCP_BLOBCLRATTR_BYTES           8  /* clear blob attr's bytecount    */
                                            /* keep in sync with objattr_t    */
#define  XCP_BLOBCLRMODE_BYTES           8  /* clear blob modefield bytecount */
#define  XCP_WRAP_BLOCKSIZE ((size_t) (128 /8)) /* blob crypt block bytecount */
#define  XCP_MACKEY_BYTES       (256 /8)   /* derived from controlling WK     */
//
#define  XCP_PIN_SALT_BYTES      XCP_WRAP_BLOCKSIZE
#define  XCP_PINBLOB_BYTES  \
        (XCP_WK_BYTES +XCP_PIN_SALT_BYTES +XCP_HMAC_BYTES)
#define  XCP_SESSION_SALT_BYTES  ((size_t) 128 /8)
				/* salt used in PIN blob rewrapping */
#define  XCP_SESSION_TCTR_BYTES   ((size_t) (128/8))  /* transaction counter */
#define  XCP_SESSION_MAC1_BYTES  ((size_t) 64 /8)             /* AES/KW MAC */
//
// full v1 (FIPS/2021) PIN, AESKW/pad ciphertext size
#define  XCP_PINBLOB_V1_BYTES  \
        (XCP_WK_BYTES +XCP_SESSION_SALT_BYTES +XCP_SESSION_MAC1_BYTES)

#define  XCP_PBE_TYPE_CLEAR           0  /* clear passphrase                */
#define  XCP_PBE_TYPE_BLOB            1  /* passphrase as generic secretkey */
#define  XCP_PBE_TYPE_MAX            (XCP_PBE_TYPE_BLOB)
//
#define  XCP_PBE_HDR_BYTES           16  /* fixed part of PBE wire struct   */
#define  XCP_PBE_PWD_MAX_BYTES     1024
#define  XCP_PBE_SALT_MAX_BYTES     256
// currently, these are the largest possible param structs
#define  XCP_MECH_WIRE_PRM_BYTES  ((size_t) 4)     /* CK_ULONG(mech) on wire */
#define  XCP_MECH_PRM_MAX_BYTES   \
        (XCP_MECH_WIRE_PRM_BYTES +XCP_PBE_HDR_BYTES \
         +XCP_PBE_PWD_MAX_BYTES +XCP_PBE_SALT_MAX_BYTES)

	// wire-encoded file header: file ID, start/offset, bytecount
	// return path fills in fields, plus may supply data slice
#define  XCP_WIRE_FILEHDR_BYTES ((size_t) (4+4+4))

// currently, PBE iteration count limit is global
// the limit may increase, but not decrease, in the future
#define  XCP_PBE_ITER_MAX         (64*1024)


// SYS_TEST-only, configuration query size
#define  XCP_CSP_CONFIG_BYTES      40


#define  XCP_SESSIONBLOB_SALT_BYTES          16
#define  XCP_SESSIONBLOB_BYTES  \
         (XCP_WK_BYTES +XCP_SESSIONBLOB_SALT_BYTES +XCP_HMAC_BYTES)

#define  XCP_SIZEQ_WIRE_BYTES   8   /* wire size of data/response bytecounts */


#define  XCP_PSS_WIRE_BYTES (4+4+4) /* hash[32] || MGF[32] || salt bytes[32] */
//
// infer value from mechanism/hash function
#define  XCP_PSS_DEFAULT_VALUE  0xffffffff

#define  XCP_OAEP_MIN_WIRE_BYTES  (4+4+4)  /* hash[32] || MGF[32] || src[32] */

#define  XCP_OAEP_MAX_SOURCE_BYTES  1024
	/* limit encoding parameter length to a sane number of Bytes */

#define  XCP_SHAKE_WIRE_BYTES  4  /* XOF Bytes[32] */

#define  XCP_ECDH1_DERIVE_MIN_WIRE_BYTES  (4+4+4)  /* kdf[32] ||
                                                      SharedDataLen[32] ||
                                                      PublicDataLen[32] */

#define  XCP_BTC_MIN_WIRE_BYTES  (4+4+4+4)     /* type[32] ||
                                                  childKeyIndex[32] ||
                                                  chaincode[32]
                                                  version[32] */

#define  XCP_BIP0032_CHAINCODE_BYTES  32

#define  XCP_BTC_VERSION  1

#define  XCP_ETH_MIN_WIRE_BYTES  (4+4+4+4+4)     /* type[32]          ||
                                                    childKeyIndex[32] ||
                                                    KeyInfo[32]       ||
                                                    version[32]       ||
                                                    sigVersion[32] */
#define  XCP_EIP2333_KEYINFO_BYTES  32

#define  XCP_ETH_VERSION  1

#define  XCP_ETH_SIG_VERSION  4

#define  XCP_KYBER_KEM_VERSION  0

#define  XCP_KYBER_KEM_MIN_WIRE_BYTES (4 + 4 + 4 + 4 + 4 + 4) /* version[32] ||
                                                                 kdf[32]     ||
                                                                 mode[32]    ||
                                                                 cphr[32]    ||
                                                                 shrd[32]    ||
                                                                 blob  [32] */

#define  XCP_KYBER_RAW_BYTES  32


#define  XCP_ECDH1_DERIVE_MAX_PUBLIC_BYTES 1024 /* limit public data length to
                                                   reasonable number of bytes */
//
#define  XCP_ECDH1_DERIVE_MAX_SHARED_BYTES 1024 /* limit shared data length to
                                                   reasonable number of bytes */
//
// full RK ID (handle)
#define  XCP_RETAINID_BYTES        (XCP_HMAC_BYTES +XCP_HMAC_BYTES)
//
// RK label (name, other human-readable information)
#define  XCP_RETAINLABEL_BYTES     ((size_t) 64)
//
// truncated form
#define  XCP_RETAINID_SHORT_BYTES  4


/*---  infrastructure  -----------------------------------------------------*/
typedef enum {
	CKF_IBM_HW_EXTWNG  =      1, // module monitors removal from its slot.
	CKF_IBM_HW_ATTEST  =      2, // module has hardware-assisted attestation
	CKF_IBM_HW_BATTERY =      4, // module has battery, may raise warnings
	CKF_IBM_HW_SYSTEST =      8, // module supports insecure test functions
	CKF_IBM_HW_RETAIN  =   0x10, // module may retain hardware-internal keys
	CKF_IBM_HW_AUDIT   =   0x40, // module supports audit-event logging
	CKF_IBM_HW_ADM_DOMIMPORT
	                   = 0x0200, // module supports domain import
	                             // see also related extended capability
	                             // (CK_IBM_XCPXQ_DOMIMPORT_VER)

	CKF_IBM_HW_PROTKEY_TOLERATION
	                   = 0x0400, // module tolerates blob attributes
	                             // related to the protected-key capability
	                             // see also CKA_IBM_PROTKEY_* description

	CKF_IBM_HW_DUAL_OA = 0x1000, // module supports dual OA certs/signatures
	                             // see CK_IBM_XCPXQ_OA_CAP for more details
	CKF_IBM_HW_RSA_IMPLICIT_REJECTION
	                   = 0x2000, // module performs implicit rejection of
				     // data with invalid RSA PKCS 1.5 padding
} XCP_CK_EXTFLAGS_t;

// these numbers apply to current version, subject to change
//
#define  XCP_MAX_MODULES         256   /* number of targetable backends      */

#define  XCP_SERIALNR_CHARS        8
#define  XCP_DOMAIN_INSTANCE_BYTES 4
#define  XCP_DOMAIN_NUMBER_BYTES   4
#define  XCP_DOMAIN_REVISION_BYTES 4
#define  XCP_DOMAIN_FLAGS_BYTES    4

#define  XCP_WRAPKEY_BYTES        32   /* keep integer blocks of blob cipher */

#define  XCP_SPKISALT_BYTES        8   /* in MACed SPKIs (public key objs)   */
#define  XCP_DOMAINS             256   /* keep multiple of 8                 */
#define  XCP_DOMAIN_BYTES          4   /* wire-encoding bytecount            */
#define  XCP_MAX_ADMINS            8   /* per domain; card has +1            */
#define  XCP_MAX_KEYPARTS         20   /* per export/import call             */

#define  XCP_MIN_PINBYTES          8
#define  XCP_MAX_PINBYTES         16
//
// v1 PINs, LoginExtended(FIPS/2021), specific limits
#define  XCP_MIN_ALG1_PINBYTES         ((size_t)  8)
#define  XCP_MAX_ALG1_PINBYTES         ((size_t) 64)
#define  XCP_MAX_LXTD_CONTEXT_BYTES   ((size_t) 128)           /* addl.context */

//
// max(...all possible PIN sizes...)
#define  XCP_MAX_ANY_PINBYTES           XCP_MAX_ALG1_PINBYTES

// ~arbitrary limit on acceptable admin. certificates
// additional limits, such as transport-bytecount, may restrict further
#define  XCP_CERT_MAX_BYTES   ((size_t) 12288) /* fits dil certs (8k + meta) */
#define  XCP_CERTHASH_BYTES   (256/8)
      /* hash or SKI of public key, or other hash-identified things; SHA-256 */

#define  XCP_ADMCTR_BYTES   ((size_t) (128/8))
                                       /* card/domain admin transaction ctrs */
#define  XCP_KEYCSUM_BYTES    (256/8)  /* full size of verification pattern  */

/* maximum coordinate bytecount, NIST P or BP curves */
#define  XCP_MAX_EC_COORD_BYTES ((size_t) 66)          /* P-521-> 512+9 bits */
#define  XCP_MIN_EC_CURVE_BITS   192
		/* ^^^ increase this when policy moves beyond shorter curves */
#define  XCP_MAX_EC_CURVE_BITS   521

#define  XCP_MAX_DIL_SIGNATURE_BYTES 4668 /* max. length of dil. 8-7 sigs    */
#define  XCP_MAX_SINFO_META_BYTES     100 /* signer info framework bytes     */

/* bytecount of raw (generic) keys, not key schedules */
#define  MOD_MAX_SYMMKEY_BYTES   256

#define  XCP_FCV_PUBLIC_BYTES  ((size_t) 76)  /* raw struct without signature */
/**/
/* note: entire signed packet, w/o key info, before Sentry */
/* Sentry and beyond, key info is no longer passed to card */
/**/
typedef enum {
	XCP_FCV_RSA_BYTES      = (76+ 4096/8),           /* RSA/4096 signature */
	XCP_FCV_EC_BYTES       = (76+ 2*66),             /* ECDSA/P-521 */
	XCP_FCV_MAX_BYTES      = XCP_FCV_RSA_BYTES
} XCP_FCV_Bytes_t;


#define  PKCS11_CHECKSUM_BYTES     ((size_t) 3)
#define  XCP_KEYBITS_FIELD_BYTES   ((size_t) 4)
	/* trailing big-endian bitcount field after UnwrapKey() checksum */

/* card(OA) signature bytecount: SKI-identified SignerInfo,
 * Non quantum safe: Must contain space for either:
 *  - 4096-bit RSA signature, hash OID, encr. OID and SKI
 *  - EC-P521 signature, hash OID, encr. OID and SKI
 */
#define  XCP_RSPSIG_RSA          (4096 / 8)
#define  XCP_RSPSIG_MAX_BYTES    (XCP_MAX_SINFO_META_BYTES + \
                                  XCP_RSPSIG_RSA)

/* card(OA) signature bytecount: SKI-identified SignerInfo,
 * Quantum safe: Must contain space for:
 *  - DIL signature, hash OID, encr. OID and SKI
 */
#define  XCP_RSPSIG_QS_MAX_BYTES (XCP_MAX_SINFO_META_BYTES + \
                                  XCP_MAX_DIL_SIGNATURE_BYTES)

/* minimal padding for raw RSA enc/dec/sign/ver/wr/unwr
 * Used for example in CKM_RSA_PKCS. See RFC 2313 chapter 8 for a complete
 * description */
#define XCP_RSA_PKCS_MIN_PAD     11

/*===  audit events  =======================================================*/

#define  XCP_LOG_STATE_BYTES     (256 /8)  /* SHA-256-based hash chain */

#define  XCP_LOG_HEADER_BYTE  0x42  /* event-record header, v0 */

#define  XCP_LOGEV_SPEC  (0xffff0000)
      /* indicates particular events, not generic event types/categories, */
      /* if bits in this region are non-zero                              */

                     /* functionality categories: keep within uint16_t range */
#define  XCP_LOGEV_QUERY                0
#define  XCP_LOGEV_FUNCTION             1
#define  XCP_LOGEV_ADMFUNCTION          2
#define  XCP_LOGEV_STARTUP              3
#define  XCP_LOGEV_SHUTDOWN             4
#define  XCP_LOGEV_SELFTEST             5
#define  XCP_LOGEV_DOM_IMPORT           6 /* import sec-relevant data to */
                                          /* domain */
#define  XCP_LOGEV_DOM_EXPORT           7 /* export sec-relevant data from */
                                          /* domain */
#define  XCP_LOGEV_FAILURE              8
#define  XCP_LOGEV_GENERATE             9
#define  XCP_LOGEV_REMOVE              10
#define  XCP_LOGEV_SPECIFIC            11 /* obtain meaning elsewhere */
#define  XCP_LOGEV_STATE_IMPORT        12 /* import to card/multiple domains */
#define  XCP_LOGEV_STATE_EXPORT        13 /* export from card/multiple */
                                          /* domains */
                                          /* [after successful export] */
#define  XCP_LOGEV_IMPORT              14 /* key/state import (UnwrapKey) */
                                          /* fields provide more context */
#define  XCP_LOGEV_EXPORT              15 /* key/state import (WrapKey) */
                                          /* fields provide more context */

            /*---  specific events (any including XCP_LOGEV_SPEC)  ---------*/

#define  XCP_LOGSPEV_TRANSACT_ZEROIZE  (XCP_LOGEV_SPEC +1)
                                       /* zeroize card by transaction */

#define  XCP_LOGSPEV_KAT_FAILED        (XCP_LOGEV_SPEC +2)
                                       /* algorithm selftest failed */

#define  XCP_LOGSPEV_KAT_COMPLETED     (XCP_LOGEV_SPEC +3)
                                       /* algorithm selftests completed */
                                       /* redundant; logged only to     */
                                       /* provide specific event        */

#define  XCP_LOGSPEV_EARLY_Q_START     (XCP_LOGEV_SPEC +4)
                                       /* subsequent events were found  */
                                       /* in the early-event queue.     */
                                       /* their timestamps are only     */
                                       /* approximate; order is correct */

#define  XCP_LOGSPEV_EARLY_Q_END       (XCP_LOGEV_SPEC +5)
                                       /* early-even queue processing ends. */
                                       /* subsequent events are through     */
                                       /* regular auditing, with valid      */
                                       /* timestamps and ordering.          */

#define  XCP_LOGSPEV_AUDIT_NEWCHAIN    (XCP_LOGEV_SPEC +6)
                                       /* audit state is corrupted; removed. */
                                       /* generating new instance and start  */
                                       /* new chain as a replacement         */

#define  XCP_LOGSPEV_TIMECHG_BEFORE    (XCP_LOGEV_SPEC +7)
                                       /* time change: original time */

#define  XCP_LOGSPEV_TIMECHG_AFTER     (XCP_LOGEV_SPEC +8)
                                       /* time change: updated time  */

#define  XCP_LOGSPEV_MODSTIMPORT_START (XCP_LOGEV_SPEC +9)
                                       /* accepted full-state import */
                                       /* data structure             */
                                       /* starting update procedure  */

#define  XCP_LOGSPEV_MODSTIMPORT_FAIL  (XCP_LOGEV_SPEC +10)
                                       /* rejected import structure    */
                                       /* issued after initial verify; */
                                       /* indicates some inconsistency */
                                       /* of import data structures    */

#define  XCP_LOGSPEV_MODSTIMPORT_END   (XCP_LOGEV_SPEC +11)
                                       /* completed full-state import */

#define  XCP_LOGSPEV_MODSTEXPORT_START (XCP_LOGEV_SPEC +12)
                                       /* started full-state export */
                                       /* see also: XCP_LOGEV_STATE_EXPORT */

#define  XCP_LOGSPEV_MODSTEXPORT_FAIL  (XCP_LOGEV_SPEC +13)


typedef enum {
	XCP_LOGSYS_AUDIT      = 1,  /* audit infrastructure itself    */
	XCP_LOGSYS_CRYPTTEST  = 2,  /* cryptographic test operations  */
	                            /* such as known-answer tests     */
	XCP_LOGSYS_SELFTEST   = 3,  /* non-crypto tests               */
	XCP_LOGSYS_FULL       = 4,  /* full module functionality      */
	XCP_LOGSYS_WK         = 5,  /* one wrapping key (WK)          */
	XCP_LOGSYS_STATE      = 6   /* all transportable module state */
} XCP_LogSystem_t;

/* bitmask of audit-event flags (mainly optional fields) */
#define  XCP_LOGFL_WK_PRESENT          0x80000000
#define  XCP_LOGFL_COMPLIANCE_PRESENT  0x40000000  /* ...of hosting domain */
#define  XCP_LOGFL_FINALWK_PRESENT     0x20000000
#define  XCP_LOGFL_KEYREC0_PRESENT     0x10000000
#define  XCP_LOGFL_KEYREC0_COMPL       0x08000000  /* key0 compliance */
#define  XCP_LOGFL_KEYREC1_PRESENT     0x04000000
#define  XCP_LOGFL_KEYREC2_PRESENT     0x02000000
#define  XCP_LOGFL_FINTIME_PRESENT     0x01000000
#define  XCP_LOGFL_SALT0_PRESENT       0x00800000
#define  XCP_LOGFL_SALT1_PRESENT       0x00400000
#define  XCP_LOGFL_SALT2_PRESENT       0x00200000
#define  XCP_LOGFL_REASON_PRESENT      0x00100000
#define  XCP_LOGFL_SEQPRF_PRESENT      0x00080000



//---  importer PK types  ----------------------------------------------------
typedef enum {
	XCP_IMPRKEY_RSA_2048    = 0,
	XCP_IMPRKEY_RSA_4096    = 1,
	XCP_IMPRKEY_EC_P256     = 2,    /* EC, NIST P-256                     */
	XCP_IMPRKEY_EC_P521     = 3,    /* EC, NIST P-521                     */
	XCP_IMPRKEY_EC_BP256r   = 4,    /* EC, Brainpool BP-256r              */
	XCP_IMPRKEY_EC_BP320r   = 5,    /* EC, Brainpool BP-320r              */
	XCP_IMPRKEY_EC_BP512r   = 6,    /* EC, Brainpool BP-512r              */
	XCP_IMPRKEY_RSA_3072    = 7,
	XCP_IMPRKEY_EC_P521_TKE = 8,    /* EC, NIST P-521 (TKE propr. sign.)  */
	XCP_IMPRKEY_MAX         = XCP_IMPRKEY_EC_P521_TKE
} XCP_IMPRKEY_t;


//---  OA key types  ----------------------------------------------------
typedef enum {
	XCP_OAKEY_RSA_4096      = 1,    /* RSA 4096 bit          */
	XCP_OAKEY_ECC_P521      = 2,    /* ECC NIST P-521        */
	XCP_OAKEY_DIL_87R2      = 3,    /* DIL 8-7 R2            */
	XCP_OAKEY_MAX           = XCP_OAKEY_DIL_87R2
} XCP_OAKEY_t;



//---  retained key structures  ---------------------------
// initial loading:
//    NULL rkData means no refills; invalid with 0 credits
//
// serialized as:
//   nothing         if structure is missing (i.e., no restrictions)
//
//   credits [be32]  if structure is present
//   rkdata  [var ]
//
typedef struct CK_RETAINEDKEY_PARAMS {
	CK_ULONG    credits;
	CK_VOID_PTR rkData;
	CK_ULONG    rkdLen;
} CK_RETAINEDKEY_PARAMS;




//---  operation categories (perf. measurement)  -----------------------------
typedef enum {
	XCP_OPCAT_ASYMM_SLOW   = 1,
	XCP_OPCAT_ASYMM_FAST   = 2,
	XCP_OPCAT_SYMM_PARTIAL = 3,  /* including hashing                   */
	XCP_OPCAT_SYMM_FULL    = 4,  /* including key generation/derivation */
	XCP_OPCAT_ASYMM_GEN    = 5,
	XCP_OPCAT_ASYMM_MAX    = XCP_OPCAT_ASYMM_GEN
} XCP_OPCAT_t;
//


//---  query sub-types  ------------------------------------------------------
typedef enum {
	CK_IBM_XCPQ_API         =  0,  /* API and build identifier     */
	CK_IBM_XCPQ_MODULE      =  1,  /* module-level information     */
	CK_IBM_XCPQ_DOMAINS     =  2,  /* list active domains & WK IDs */
	CK_IBM_XCPQ_DOMAIN      =  3,
	CK_IBM_XCPQ_SELFTEST    =  4,  /* integrity & algorithm tests  */
	CK_IBM_XCPQ_EXT_CAPS    =  5,  /* extended capabilities, count */
	CK_IBM_XCPQ_EXT_CAPLIST =  6,  /* extended capabilities, list  */
	CK_IBM_XCPQ_AUDITLOG    =  8,  /* audit record or records      */
	                               /* 9 not used ----------------- */
	CK_IBM_XCPQ_EC_CURVES   = 10,  /* supported elliptic curves,   */
	                               /* individual curves, bitmask   */
	                               /* see: XCP_ECcurve_t           */
	CK_IBM_XCPQ_COMPAT      = 11,  /* domains' compatibility modes */
	CK_IBM_XCPQ_EC_CURVEGRPS
	                        = 12,  /* supported elliptic curves,   */
	                               /* groups/categories, bitmask   */
	                               /* see: CK_IBM_ECCURVEQ_t       */
	CK_IBM_XCPQ_CP_BLACKLIST
	                        = 13,  /* control point blacklist:     */
	                               /* control points which may     */
	                               /* never be enabled due to      */
	                               /* policy-minimum restrictions. */

        CK_IBM_XCPQ_PQC_STRENGTHS
                                = 14,  /* supported quantum safe levels*/
                                       /* of strength                  */
                                       /* see: XCP_PQCStrength_t       */

	CK_IBM_XCPQ_LOGIN_IMPORTER
	                        = 15,  /* current session importer key */
	                               /* and it's transaction counter */
	                               /* for given curve type         */
	                               /* see: XCP_ECCurve_t and       */
	                               /*  CK_IBM_XCPXQ_LOGIN_KEYTYPES */

	CK_IBM_XCPQ_COMPAT_ADM  = 16,  /* domains' administrative      */
	                               /* compatibility modes          */

	CK_IBM_XCPQ_MAX         = CK_IBM_XCPQ_COMPAT_ADM
} CK_IBM_XCPQUERY_t;

//---  module sub-query sub-types  --------------------------------------------
typedef enum {
	CK_IBM_XCPMSQ_DEFAULT     =  0,  /* zero indicates no sub-query  */
	CK_IBM_XCPMSQ_DESCRTEXT   =  1,  /* human-readable text/tokens   */
	CK_IBM_XCPMSQ_FNLIST      =  2,  /* supported function id bitmask*/
	CK_IBM_XCPMSQ_FNS         =  3,  /* count of fn ids              */
	CK_IBM_XCPMSQ_MOD_V1      =  4,  /* add version one fields to    */
	                                 /* module query                 */
	CK_IBM_XCPMSQ_ATTRLIST    =  5,  /* supported administrative     */
	                                 /* attributes bitmask           */
	CK_IBM_XCPMSQ_ATTRS       =  6,  /* list of supported attribute  */
	                                 /* bits (1 byte / attribute)    */
	                                 /* administrative attributes    */
	CK_IBM_XCPMSQ_MOD_V2      =  7,  /* add version two fields to    */
	                                 /* module query                 */
	CK_IBM_XCPMSQ_ATTRCOUNT   =  8,  /* number of supported          */
	                                 /* administrative attributes    */
	CK_IBM_XCPMSQ_MAX         = CK_IBM_XCPMSQ_ATTRCOUNT
} CK_IBM_XCPMSUBQUERY_t;


//---  selftest sub-query sub-types  ------------------------------------------
typedef enum {
	CK_IBM_XCPSSQ_DEFAULT    =  0,  /* run non-failing POST tests   */
	CK_IBM_XCPSSQ_POST_F     =  1,  /* run failing POST tests       */
} CK_IBM_XCPSSUBQUERY_t;


// byte sizes of queries which are not represented as structures
#define XCP_MSQ_FNLIST_SIZE      16
#define XCP_XCPMSQ_FNS_SIZE       1
#define XCP_XCPMSQ_ATTRCOUNT_SIZE 4



#define CK_IBM_XCP_HOSTQ_IDX  0xff000000  /* host-only queries index, min. */

#define CK_IBM_XCPHQ_COUNT        0xff000000 /* number of host-query indexes  */
                                             /* including this type itself    */
#define CK_IBM_XCPHQ_VERSION      0xff000001 /* host-specific package version */
                                             /* such as packaging library ID  */
#define CK_IBM_XCPHQ_VERSION_HASH 0xff000002
                                             /* assumed-unique identifier of  */
                                             /* host code, such as version-   */
                                             /* identifying cryptographic hash*/
                                             /* (library signature field...)  */
#define CK_IBM_XCPHQ_DIAGS        0xff000003 /* host code diagnostic level    */
                                             /* 0 if non-diagnostics host code*/
#define CK_IBM_XCPHQ_HVERSION     0xff000004 /* human-readable host version   */
                                             /* identification (recommended:  */
                                             /* UTF-8 string)                 */
#define CK_IBM_XCPHQ_TGT_MODE     0xff000005 /* host targeting modes          */
                                             /* returns supported target modes*/
                                             /* as bitmask                    */
                                             /* if not available only compat  */
                                             /* target mode is in use         */
                                             /* See CK_IBM_XCPHQ_TGT_MODES_t  */
#define CK_IBM_XCPHQ_ECDH_DERPRM  0xff000006
                                             /* ECDH DeriveKey parameter usage*/
                                             /* is being enforced with hostlib*/
                                             /* version                       */
                                             /**/

#define CK__IBM_XCPHQ_MAX CK_IBM_XCPHQ_TGT_MODE


typedef enum {
	CK_IBM_XCPHQ_TGT_MODES_TGTGRP = 1,  /* target groups are supported    */
	CK_IBM_XCPHQ_TGT_MODES_MAX = CK_IBM_XCPHQ_TGT_MODES_TGTGRP
} CK_IBM_XCPHQ_TGT_MODES_t;


typedef enum {
	CK_IBM_XCPXQ_AUDIT_EV_BYTES =  2, /* largest audit event, bytecount  */
	CK_IBM_XCPXQ_AUDIT_ENTRIES  =  3, /* max. size of event history      */
	CK_IBM_XCPXQ_DEBUGLVL_MAX   =  4, /* backend diagnostics granularity */
	CK_IBM_XCPXQ_ERRINJECT_FREQ =  5, /* error-inject frequency N        */
	                                  /* N calls fail in a million       */
	                                  /* 0 for production releases,      */
	                                  /* which do not error-injection    */
	CK_IBM_XCPXQ_MULTIDATA_N    =  6, /* maximum number of supported     */
	                                  /* sub-fields in multi-data        */
	                                  /* requests. 0 if not supported,   */
	                                  /* all-1's if no predefined limit. */
	CK_IBM_XCPXQ_IMPEXP_CAPS    =  7, /* capability for WK and state     */
	                                  /* export / import. See 8.7.1.1.1  */
	                                  /* for more info                   */
	CK_IBM_XCPXQ_CERT_MAXBYTES  =  8, /* bytecount of largest accepted   */
	                                  /* administrative certificate, if  */
	                                  /* there is an upper limit.  0 if  */
	                                  /* the backend does not enforce    */
	                                  /* any specific limit of its own.  */
	CK_IBM_XCPXQ_MOD_COUNTERS   =  9, /* number of module-internal dev   */
	                                  /* counters supported, 0 if none   */


	CK_IBM_XCPXQ_MAX_SESSIONS   = 12,
	CK_IBM_XCPXQ_AVAIL_SESSIONS = 13, /* maximum, currently available    */
	                                  /* number of backend sessions      */
	CK_IBM_XCPXQ_BTC_CAP        = 14, /* bit field for bitcoin related   */
	                                  /* additions                       */

	CK_IBM_XCPXQ_ECDSA_OTHER    = 15, /* bitmask of supported, other EC
	                                     signing mechanisms */
	CK_IBM_XCPXQ_OA_CAP         = 16, /* bitmask of supported outbound
	                                     authority signing mechanisms */

	CK_IBM_XCPXQ_LOGIN_ALG      = 18, /* bitmask of login algorithms     */
	                                  /* supported with LoginExtended    */
	CK_IBM_XCPXQ_LOGIN_ATTR0    = 19, /* bitmask of supported session    */
                                          /* attributes with Login Extended  */
					  /* first double-word               */
	CK_IBM_XCPXQ_LOGIN_ATTR1    = 20, /* session attributes, 2nd DW      */
#if 0
	CK_IBM_XCPXQ_LOGIN_ATTR2    = 21, /* session attributes, 3rd DW      */
	CK_IBM_XCPXQ_LOGIN_ATTR3    = 22, /* session attributes, 4th DW      */
#endif
	CK_IBM_XCPXQ_LOGIN_KEYTYPES = 23, /* bitmask of Login importer types */
	                                  /* supported for PIN encryption    */

	CK_IBM_XCPXQ_MAXIDX         = CK_IBM_XCPXQ_LOGIN_KEYTYPES,
} CK_IBM_XCPEXTCAP_t;


#define CK_IBM_DOM_ADMIND              1   /* administrators present     */
#define CK_IBM_DOM_CURR_WK             2   /* domain has current WK      */
#define CK_IBM_DOM_NEXT_WK             4   /* domain has pending/next WK */
#define CK_IBM_DOM_COMMITTED_NWK       8   /* next WK is active(committed) */
#define CK_IBM_DOM_IMPRINTED        0x10   /* has left imprint mode */
#define CK_IBM_DOM_IMPRINTS   0x80000000   /* enforces imprint mode */
#define CK_IBM_DOM_PROTKEY_ALLOW    0x20   /* policies allow protected key */
//
// note: CK_IBM_DOM_IMPRINTS will go away

#define  CK_IBM_DOM_ACTIVE          \
        (CK_IBM_DOM_ADMIND        | \
         CK_IBM_DOM_CURR_WK       | \
         CK_IBM_DOM_NEXT_WK       | \
         CK_IBM_DOM_COMMITTED_NWK | \
         CK_IBM_DOM_IMPRINTED)

typedef enum {
	CK_IBM_ECCURVE_NIST   =    1, /* NIST P-curves P-192 to P-521 */
	CK_IBM_ECCURVE_BPOOL  =    2, /* Brainpool curves, regular+twisted */
	                              /* BP160R to BP512T */
	CK_IBM_ECCURVE_S256K1 =    4, /* secp256k1 (Bitcoin default) */
	CK_IBM_ECCURVE_25519  =    8, /* curve25519 */
	                              /* ECDH/sign vars (isomorphic curves) */
	                              /* are not reported separately */
	CK_IBM_ECCURVE_ED448  = 0x20, /* ed448 (Goldilocks) Edwards curve */
} CK_IBM_ECCURVEQ_t;


typedef struct CK_IBM_XCPAPI_INFO {
	CK_ULONG firmwareApi;
	CK_ULONG firmwareConfig;          /* truncated firmware hash */
} CK_IBM_XCPAPI_INFO;

typedef CK_IBM_XCPAPI_INFO    CK_PTR   CK_IBM_XCPAPI_INFO_PTR;

#define CK_IBM_XCP_INFO_MEMBERS_V0                                             \
	CK_ULONG firmwareApi;         /* API ordinal number */                 \
	                              /* major+minor pairs  */                 \
	CK_ULONG   firmwareId;        /* truncated firmwareConfig */           \
	CK_VERSION firmwareVersion;   /* xcp only, matches xcpConfig below */  \
	CK_VERSION cspVersion;                                                 \
	                              /* hashes, possibly truncated */         \
	CK_BYTE  firmwareConfig[ 32 ];                                         \
	CK_BYTE  xcpConfig[ 32 ];                                              \
	CK_BYTE  cspConfig[ 32 ];                                              \
	CK_CHAR  serialNumber[ 16 ];  /* device || instance */                 \
	CK_CHAR  utcTime[ 16 ];                                                \
	CK_ULONG opMode2;             /* currently, reserved 0 */              \
	CK_ULONG opMode1;             /* operational mode, card-level */       \
	CK_FLAGS flags;               /*     PKCS#11 capabilities */           \
	CK_FLAGS extflags;            /* non-PKCS#11 capabilities */           \
	CK_ULONG domains;                                                      \
	CK_ULONG symmStateBytes;                                               \
	CK_ULONG digestStateBytes;                                             \
	CK_ULONG pinBlockBytes;                                                \
	CK_ULONG symmKeyBytes;                                                 \
	CK_ULONG spkiBytes;                                                    \
	CK_ULONG prvkeyBytes;                                                  \
	CK_ULONG maxPayloadBytes;                                              \
	CK_ULONG cpProfileBytes;                                               \
	CK_ULONG controlPoints;

#define CK_IBM_XCP_DESCINFO_MEMBER                                             \
	CK_CHAR manufacturerID[ 32 ];                                          \
	CK_CHAR          model[ 16 ];

#define CK_IBM_XCP_ADMATTRLIST_MEMBER                                          \
	CK_BYTE  perm_modes[ 8 ];                                              \
	CK_BYTE infra_modes[ 8 ];                                              \
	CK_BYTE  comp_modes[ 8 ];

#define CK_IBM_XCP_ADMATTRCOUNT_MEMBER                                         \
	CK_BYTE  perm_count;                                                   \
	CK_BYTE infra_count;                                                   \
	CK_BYTE  comp_count;

#define CK_IBM_XCP_ADMATTRLIST_MEMBER_V2                                       \
	CK_BYTE perm_ext01_modes[ 8 ];

#define CK_IBM_XCP_ADMATTRCOUNT_MEMBER_V2                                      \
	CK_BYTE perm_ext01_count;

#define CK_IBM_XCP_ADMATTRLIST_MEMBER_EXT                                      \
	CK_BYTE gen_ktype_modes[ 8 ];                                          \
	CK_BYTE ecc_ktype_modes[ 8 ];                                          \
	CK_BYTE dil_ktype_modes[ 8 ];                                          \
	CK_BYTE adm_compl_modes[ 8 ];

#define CK_IBM_XCP_ADMATTRCOUNT_MEMBER_EXT                                     \
	CK_BYTE gen_ktype_count;                                               \
	CK_BYTE ecc_ktype_count;                                               \
	CK_BYTE dil_ktype_count;                                               \
	CK_BYTE adm_compl_count;

// see chapter 5.1.1. in the wire spec
typedef struct CK_IBM_XCP_INFO {
	CK_IBM_XCP_INFO_MEMBERS_V0
} CK_IBM_XCP_INFO;
//
// see chapter 5.1.1. in the wire spec
typedef struct CK_IBM_XCP_INFO_V1 {
	CK_IBM_XCP_INFO_MEMBERS_V0
	CK_IBM_XCP_DESCINFO_MEMBER
	CK_BYTE      fnid_mask[ 16 ];
	CK_BYTE fnid_count;
	CK_IBM_XCP_ADMATTRLIST_MEMBER
	CK_IBM_XCP_ADMATTRCOUNT_MEMBER
} CK_IBM_XCP_INFO_V1;
//
// see chapter 5.1.1. in the wire spec
typedef struct CK_IBM_XCP_INFO_V2 {
	CK_IBM_XCP_INFO_MEMBERS_V0
	CK_IBM_XCP_DESCINFO_MEMBER
	CK_BYTE      fnid_mask[ 16 ];
	CK_BYTE fnid_count;
	CK_IBM_XCP_ADMATTRLIST_MEMBER
	CK_IBM_XCP_ADMATTRCOUNT_MEMBER
	CK_IBM_XCP_ADMATTRLIST_MEMBER_V2
	CK_IBM_XCP_ADMATTRCOUNT_MEMBER_V2
} CK_IBM_XCP_INFO_V2;
//
// see chapter 5.1.1.1. in the wire spec
typedef struct CK_IBM_XCP_DESCINFO {
	CK_IBM_XCP_DESCINFO_MEMBER
} CK_IBM_XCP_DESCINFO;
//
// see chapter 5.1.1.3. in the wire spec
typedef struct CK_IBM_XCP_ATTRLIST {
	CK_IBM_XCP_ADMATTRLIST_MEMBER
	CK_IBM_XCP_ADMATTRLIST_MEMBER_V2
	CK_IBM_XCP_ADMATTRLIST_MEMBER_EXT
} CK_IBM_XCP_ATTRLIST;
//
// see chapter 5.1.1.3. in the wire spec
typedef struct CK_IBM_XCP_ATTRCOUNT {
	CK_IBM_XCP_ADMATTRCOUNT_MEMBER
	CK_IBM_XCP_ADMATTRCOUNT_MEMBER_V2
	CK_IBM_XCP_ADMATTRCOUNT_MEMBER_EXT
} CK_IBM_XCP_ATTRCOUNT;

typedef struct CK_IBM_XCP_ATTRLIST_LGC {
	CK_IBM_XCP_ADMATTRLIST_MEMBER
	CK_IBM_XCP_ADMATTRLIST_MEMBER_V2
} CK_IBM_XCP_ATTRLIST_LGC;

typedef struct CK_IBM_XCP_ATTRCOUNT_LGC {
	CK_IBM_XCP_ADMATTRCOUNT_MEMBER
	CK_IBM_XCP_ADMATTRCOUNT_MEMBER_V2
} CK_IBM_XCP_ATTRCOUNT_LGC;


/**/
#define CK_IBM_XCP_INFO_INIT0  \
        { 0,0, {0,0,},{0,0,},  {0,},{0,},{0,}, {0,},{0,}, \
          0,0, 0,0, 0,0,0,0,0,0,0, 0,0,0, }

#define CK_IBM_XCP_INFO_V2_INIT0  \
        { 0,0, {0,0,},{0,0,},  {0,},{0,},{0,}, {0,},{0,}, \
          0,0, 0,0, 0,0,0,0,0,0,0, 0,0,0,                 \
          {0}, {0}, {0}, 0, {0}, {0}, {0}, 0, 0, 0,       \
          {0}, 0}

typedef CK_IBM_XCP_INFO         CK_PTR CK_IBM_XCP_INFO_PTR;
typedef CK_IBM_XCP_INFO_V1      CK_PTR CK_IBM_XCP_INFO_V1_PTR;
typedef CK_IBM_XCP_INFO_V2      CK_PTR CK_IBM_XCP_INFO_V2_PTR;
typedef CK_IBM_XCP_DESCINFO     CK_PTR CK_IBM_XCP_DESCINFO_PTR;
typedef CK_IBM_XCP_ATTRLIST     CK_PTR CK_IBM_XCP_ATTRLIST_PTR;
typedef CK_IBM_XCP_ATTRCOUNT    CK_PTR CK_IBM_XCP_ATTRCOUNT_PTR;

typedef struct CK_IBM_DOMAIN_INFO {
	CK_ULONG    domain;
	CK_BYTE     wk[ XCP_KEYCSUM_BYTES ];
	CK_BYTE nextwk[ XCP_KEYCSUM_BYTES ];
	CK_ULONG  flags;
	CK_BYTE   mode[ 8 ];
} CK_IBM_DOMAIN_INFO;
/**/
#define  CK_IBM_DOMAIN_INFO_INIT0  { 0, { 0, }, { 0, }, 0, { 0, } }


typedef CK_IBM_DOMAIN_INFO CK_PTR   CK_IBM_DOMAIN_INFO_PTR;


//---  BTC mechparams  --------------------------------------------------
typedef struct CK_IBM_BTC_DERIVE_PARAMS {
	CK_ULONG type;
	CK_ULONG childKeyIndex;
	CK_BYTE_PTR pChainCode;
	CK_ULONG ulChainCodeLen;
	CK_ULONG version;
} CK_IBM_BTC_DERIVE_PARAMS;

typedef CK_IBM_BTC_DERIVE_PARAMS CK_PTR CK_IBM_BTC_DERIVE_PARAMS_PTR;

// key index flag; hardened, i.e., keys cannot be used for pub2pub derivation
#define  CK_IBM_BIP0032_HARDENED                        (0x80000000)

// sub-variants of BIP-0032 key derivation
typedef enum {
	CK_IBM_BIP0032_PRV2PRV  = 1,
	CK_IBM_BIP0032_PRV2PUB  = 2,
	CK_IBM_BIP0032_PUB2PUB  = 3,
	CK_IBM_BIP0032_MASTERK  = 4,
	CK_IBM_SLIP0010_PRV2PRV = 5,
	CK_IBM_SLIP0010_PRV2PUB = 6,
	CK_IBM_SLIP0010_PUB2PUB = 7,
	CK_IBM_SLIP0010_MASTERK = 8,
} CK_IBM_BTC_t;

//---  ETH mechparams  --------------------------------------------------
typedef struct CK_IBM_ETH_DERIVE_PARAMS {
	CK_ULONG version;
	CK_ULONG sigVersion;
	CK_ULONG type;
	CK_ULONG childKeyIndex;
	CK_BYTE_PTR pKeyInfo;
	CK_ULONG ulKeyInfoLen;
} CK_IBM_ETH_DERIVE_PARAMS;

typedef CK_IBM_ETH_DERIVE_PARAMS CK_PTR CK_IBM_ETH_DERIVE_PARAMS_PTR;

// sub-variants of EIP-2333 key derivation
typedef enum {
	CK_IBM_EIP2333_PRV2PRV  = 1,
	CK_IBM_EIP2333_PRV2PUB  = 2,
	CK_IBM_EIP2333_MASTERK  = 3,
} CK_IBM_ETH_t;


typedef enum {
	XCP_KEM_ENCAPSULATE = 1,
	XCP_KEM_DECAPSULATE = 2,
} XCP_KEM_t;

typedef CK_ULONG CK_IBM_KEM_MODE;

#define  XCP_ML_KEM_DSA_MAX_SEED_BYTES	64

#define  CK_IBM_KEM_ENCAPSULATE  XCP_KEM_ENCAPSULATE
#define  CK_IBM_KEM_DECAPSULATE  XCP_KEM_DECAPSULATE

typedef struct XCP_KYBER_KEM_PARAMS {
	CK_ULONG         version;
	CK_IBM_KEM_MODE  mode;
	CK_ULONG         kdf;
	CK_BBOOL         prepend;
	CK_BYTE          *pCipher;
	CK_ULONG         ulCipherLen;
	CK_BYTE          *pSharedData;
	CK_ULONG         ulSharedDataLen;
	CK_BYTE          *pBlob;
	CK_ULONG         ulBlobLen;
} XCP_KYBER_KEM_PARAMS_t;


//---  Login Extended Information  -------------------------------------------
// data types and constants related to LoginExtended and LogoutExtended
// see wire spec 6.19

// currently known Login Algorithms for Session ID calculation
typedef enum XCP_LoginAlgorithm {
	XCP_LOGIN_ALG_PRE_F2021           = 0,
	XCP_LOGIN_ALG_F2021               = 2,
	XCP_LOGIN_ALG_MAX                 = XCP_LOGIN_ALG_F2021
} XCP_LoginAlgorithm_t;

typedef CK_ULONG CK_IBM_LOGIN_ALG;

#define  CK_IBM_LOGIN_ALG_PRE_F2021            XCP_LOGIN_ALG_PRE_F2021
#define  CK_IBM_LOGIN_ALG_F2021                XCP_LOGIN_ALG_F2021

// currently known Login importer key types for encrypted PIN transport
typedef enum XCP_LoginImporter {
	XCP_LOGIN_IMPR_EC_P256 = 1,    /* EC, NIST P-256 */
	XCP_LOGIN_IMPR_EC_P521 = 2,    /* EC, NIST P-521 */
} XCP_LoginImporter_t;

// maximum size of login importer structure, assuming DER encoding
// and EC P-521 as maximum key
//
#define  XCP_LOGIN_IMPR_MAX_SIZE  (3 + (2 + XCP_CERTHASH_BYTES)    \
                                     + (3 + 158)                   \
				     + (2 + XCP_SESSION_TCTR_BYTES) )

// login session attributes, bit index
typedef enum XCP_LoginAttribute {
	XCP_LOGIN_ATTR_SUPERVISOR = 0,
	XCP_LOGIN_ATTR_MIGRATION  = 1,
        XCP_LOGIN_ATTR_VOLATILE   = 2,
        XCP_LOGIN_ATTR_MAX        = XCP_LOGIN_ATTR_VOLATILE,
} XCP_LoginAttribute_t;

#define CK_IBM_LOGIN_ATTR_SUPERVISOR XCP_LOGIN_ATTR_SUPERVISOR
#define CK_IBM_LOGIN_ATTR_MIGRATION  XCP_LOGIN_ATTR_MIGRATION
#define CK_IBM_LOGIN_ATTR_VOLATILE   XCP_LOGIN_ATTR_VOLATILE
#define CK_IBM_LOGIN_ATTR_MAX        XCP_LOGIN_ATTR_VOLATILE

// login recipient structure
typedef struct XCP_LoginRecipient {
	CK_BYTE   recipient_ski[ XCP_CERTHASH_BYTES ];
	CK_BYTE   sender_spki;
	CK_ULONG  spkilen;
} XCP_LoginRecipient_t;

// extended login information structure
typedef struct XCP_LoginExtendedInfo {
	CK_BYTE               *version;
	CK_ULONG              verlen;
	CK_IBM_LOGIN_ALG      algorithm;
	CK_BYTE               parent[ XCP_WK_BYTES ];
	XCP_LoginRecipient_t  *recepient;
	CK_ULONG              attributes;
	CK_BYTE               context;
	CK_ULONG              contlen;
} XCP_LoginExtendedInfo_t;


//---  attribute constants  --------------------------------------------------
//
typedef enum {
	XCP_BLOB_EXTRACTABLE       =        1,
	                           // May be encrypted by other keys.
	                           // May not be reset.
	XCP_BLOB_NEVER_EXTRACTABLE =        2,
	                           // set if key was created non-extractable.
	                           // Set only initially, may not be
	                           // modified.
	XCP_BLOB_MODIFIABLE        =        4,
	                           // attributes may be changed
	XCP_BLOB_NEVER_MODIFIABLE  =        8,
	                           // object was created read-only.
	                           // Set only initially, may not be
	                           // modified.
	XCP_BLOB_RESTRICTABLE      =     0x10,
	                           // attributes may be removed, but may not be
	                           // made more permissive.
	XCP_BLOB_LOCAL             =     0x20,
	                           // was created inside this CSP,
	                           // was not imported.  Set upon object
	                           // creation, may not be modified.
	XCP_BLOB_ATTRBOUND         =     0x40,
	                           // may be transported only in
	                           // attribute-bound formats,
	                           // but not pure PKCS11 ones.
	                           // May not be modified.
	XCP_BLOB_USE_AS_DATA       =     0x80,
	                           // raw key bytes may be input
	                           // to other processing as data,
	                           // such as hashed, or deriving
	                           // keys from them.

	XCP_BLOB_SIGN              =   0x0100,
	                           // may generate signatures
	XCP_BLOB_SIGN_RECOVER      =   0x0200,
	                           // may generate (asymmetric)
	                           // signatures with message recovery
	XCP_BLOB_DECRYPT           =   0x0400, // may decrypt data
	XCP_BLOB_ENCRYPT           =   0x0800, // may encrypt data
	XCP_BLOB_DERIVE            =   0x1000, // may derive other keys
	XCP_BLOB_UNWRAP            =   0x2000,
	                           // may decrypt (transport) other keys
	XCP_BLOB_WRAP              =   0x4000,
	                           // may encrypt (transport) other keys
	XCP_BLOB_VERIFY            =   0x8000, // may verify signatures
	XCP_BLOB_VERIFY_RECOVER    = 0x010000,
	                           // may verify signatures and recover
	                           // signed messages

	XCP_BLOB_TRUSTED           = 0x020000,   // PKCS11 CKA_TRUSTED key
	XCP_BLOB_WRAP_W_TRUSTED    = 0x040000,   // needs CKA_TRUSTED KEK
	                           // note: _TRUSTED enforcement does not
	                           // provide security guarantees.  We only
	                           // track it inside the HSM to assist hosts.
	XCP_BLOB_RETAINED          = 0x080000,   // blob resides within
	                           // backend, not (no longer) on host
	XCP_BLOB_ALWAYS_RETAINED   = 0x100000,   // blob has been generated
	                           // inside
	XCP_BLOB_PROTKEY_EXTRACTABLE       = 0x200000,
	                           // May be imported as protected key.
	                           // May not be reset.
	XCP_BLOB_PROTKEY_NEVER_EXTRACTABLE = 0x400000,
	                           // set if key was created non-extractable
	                           // as a protected key.
	                           // Set only initially, may not be
	                           // modified.
	XCP_BLOB_BIT_MAX = XCP_BLOB_PROTKEY_NEVER_EXTRACTABLE
} XCP_Attr_t;


//---  control points  -------------------------------------------------------
#define  XCP_CPID_BYTES          8     /*  bytecount in CP profiles        */
                                       /*  if backend supports them        */

#define  XCP_CPBLOCK_BITS      128     /*  handle CPs in this granularity  */
                                       /*  CP sets get padded to multiple  */

typedef enum {
    XCP_CPB_ADD_CPBS        =  0, // allow activation of CP bits
    XCP_CPB_DELETE_CPBS     =  1, // allow deactivation of CP bits
                                  // (remove both ADD_CPBs and DELETE_CPBs
                                  // to make unit read-only)

    XCP_CPB_SIGN_ASYMM      =  2, // sign with private keys
    XCP_CPB_SIGN_SYMM       =  3, // sign with HMAC or CMAC
    XCP_CPB_SIGVERIFY_SYMM  =  4, // verify with HMAC or CMAC.
                                  // No asymmetric counterpart: one
                                  // may not restrict use of public keys.

    XCP_CPB_ENCRYPT_SYMM    =  5, // encrypt with symmetric keys.
                                  // No asymmetric counterpart: one
                                  // may not restrict use of public keys.

    XCP_CPB_DECRYPT_ASYMM   =  6, // decrypt with private keys
    XCP_CPB_DECRYPT_SYMM    =  7, // decrypt with symmetric keys

    XCP_CPB_WRAP_ASYMM      =  8, // key export with public keys
    XCP_CPB_WRAP_SYMM       =  9, // key export with symmetric keys
    XCP_CPB_UNWRAP_ASYMM    = 10, // key import with private keys
    XCP_CPB_UNWRAP_SYMM     = 11, // key import with symmetric keys

    XCP_CPB_KEYGEN_ASYMM    = 12, // generate asymmetric keypairs
                                  // (fn:GenerateKeyPair)
    XCP_CPB_KEYGEN_SYMM     = 13, // generate or derive symmetric keys
                                  // including DSA or DH parameters

    XCP_CPB_RETAINKEYS      = 14, // allow backend to save semi-retained keys
    XCP_CPB_SKIP_KEYTESTS   = 15, // disable selftests on new asymmetric keys
    XCP_CPB_NON_ATTRBOUND   = 16, // allow keywrap without attribute-binding
    XCP_CPB_MODIFY_OBJECTS  = 17, // allow changes to objects (Booleans only)
    XCP_CPB_RNG_SEED        = 18, // allow mixing external seed to RNG
                                  // backend may restrict further

    XCP_CPB_ALG_RAW_RSA     = 19, // allow RSA private-key use without padding
                                  // (highly discouraged)
    XCP_CPB_ALG_NFIPS2009   = 20, // allow non-FIPS-approved algs (as of 2009)
                                  // including non-FIPS keysizes
    XCP_CPB_ALG_NBSI2009    = 21, // allow non-BSI algorithms (as of 2009)
                                  // including non-BSI keysizes
    XCP_CPB_KEYSZ_HMAC_ANY  = 22, // don't enforce minimum keysize on HMAC
                                  // (allows keys shorter than half of digest)

    XCP_CPB_KEYSZ_BELOW80BIT = 23, // allow algorithms below 80-bit strength
    XCP_CPB_KEYSZ_80BIT      = 24, // allow 80  to 111-bit algorithms
    XCP_CPB_KEYSZ_112BIT     = 25, // allow 112 to 127-bit algorithms
    XCP_CPB_KEYSZ_128BIT     = 26, // allow 128 to 191-bit algorithms
    XCP_CPB_KEYSZ_192BIT     = 27, // allow 192 to 255-bit algorithms
    XCP_CPB_KEYSZ_256BIT     = 28, // allow 256-bit        algorithms
    XCP_CPB_KEYSZ_RSA65536   = 29, // allow RSA public exponents below 0x10001
    XCP_CPB_ALG_RSA          = 30, // RSA private-key or key-encrypt use
    XCP_CPB_ALG_DSA          = 31, // DSA private-key use
    XCP_CPB_ALG_EC           = 32, // EC private-key use (see CP on curves)
    XCP_CPB_ALG_EC_BPOOLCRV  = 33, // Brainpool (E.U.) EC curves
    XCP_CPB_ALG_EC_NISTCRV   = 34, // NIST/SECG EC curves

    XCP_CPB_ALG_NFIPS2011   = 35, // allow non-FIPS-approved algs (as of 2011)
                                  // including non-FIPS keysizes
    XCP_CPB_ALG_NBSI2011    = 36, // allow non-BSI algorithms (as of 2011)
                                  // including non-BSI keysizes

    XCP_CPB_USER_SET_TRUSTED   = 37, // allow non-admin set TRUSTED on blob/SPKI
    XCP_CPB_ALG_SKIP_CROSSCHK  = 38, // do not double-check sign/decrypt ops

    XCP_CPB_WRAP_CRYPT_KEYS    = 39, // allow keys which can en/decrypt data
                                     // and also un/wrap other keys
                                     // (applies to both generation and use)
    XCP_CPB_SIGN_CRYPT_KEYS    = 40, // allow keys which can en/decrypt data
                                     // and also sign/verify
                                     // (applies to both generation and use)
    XCP_CPB_WRAP_SIGN_KEYS     = 41, // allow keys which can un/wrap data
                                     // and also sign/verify
                                     // (applies to both generation and use)

    XCP_CPB_USER_SET_ATTRBOUND = 42, // allow non-administrators to
                                     // mark public key objects ATTRBOUND
    XCP_CPB_ALLOW_PASSPHRASE   = 43, // allow host to pass passprases, such as
                                     // PKCS12 data, in the clear
    XCP_CPB_WRAP_STRONGER_KEY  = 44, // allow wrapping of stronger keys
                                     // by weaker keys
    XCP_CPB_WRAP_WITH_RAW_SPKI = 45, // allow wrapping with SPKIs without
                                     // MAC and attributes
    XCP_CPB_ALG_DH             = 46, // Diffie-Hellman use (private keys)
    XCP_CPB_DERIVE             = 47, // allow key derivation (symmetric+EC/DH)

    XCP_CPB_ALLOW_NONSESSION   = 48, // allow use of blobs without sessions
                                     // i.e., key/session state not bound
                                     // to Login/Logout-controlled state
    XCP_CPB_ALG_EC_25519       = 55, // enable support of curve25519,
                                     // c448 and related algorithms
                                     // incl. EdDSA (ed25519 and ed448)
    XCP_CPB_ALG_EC_SECGCRV     = 60, // Prime-field SECG EC curves excluding
                                     // those shared with NIST P-curves
    XCP_CPB_ALG_NBSI2017       = 61, // allow non-BSI algorithms (as of 2017)
                                     // including non-BSI keysizes
                                     // (fn:Sign/RSA)
    XCP_CPB_CPACF_PK           = 64, // support data key generation and import
                                     // for protected key

    XCP_CPB_ALG_PQC            = 65, // support for PQ algorithms (top CPB)

    XCP_CPB_BTC                = 66, // enable BTC-related functionality
                                     // including blockchain, altcoins, and
                                     // digital assets

    XCP_CPB_ECDSA_OTHER        = 67, // enable non-ECDSA/non-EdDSA elliptic
                                     // curve signature algorithms
    XCP_CPB_ALG_NFIPS2021      = 68, // allow non-FIPS-approved algs (2021)

    XCP_CPB_ALG_NFIPS2024      = 69, // allow non-FIPS-approved algs (2024)

    XCP_CPB_COMPAT_LEGACY_SHA3 = 70, // allow fall-back to non-standard
                                     // SHA3 defaults
    XCP_CPB_DSA_PARAMETER_GEN  = 71, // allow DSA/PQG parameter generation
    XCP_CPB_DERIVE_NON_AB_KEYS = 72,  // allow the derivation of a non-AB or raw
                                     // from an AB key. Only relevant if
                                     // XCP_CPB_NON_ATTRBOUND
    XCP_CPB_ALLOW_LOGIN_PRE_F2021   = 73, // allow usage of basic login sessions
                                          // or extended login sessions using
                                          // pre-FIPS2021-algorithms
    XCP_CPB_ALG_RSA_OAEP       = 74, // allow RSA OAEP
    XCP_CPB_ALLOW_COMBINED_EXTRACT  = 75, // allow creation and usage of keys
                                          // with both EXTRACTABLE and
                                          // PROTKEY_EXTRACTABLE attributes set
    XCP_CPB_ALG_EC_PAIRING_FRIENDLY = 76,

    XCP_CPB_ALG_DILITHIUM           = 77, // support for pre-Standard dilithium
    XCP_CPB_ALG_KYBER               = 78, // support for pre-Standard kyber
    XCP_CPB_ALG_ML_DSA              = 79, // support for NIST 204
    XCP_CPB_ALG_ML_KEM              = 80, // support for NIST 203

    XCP_CPBITS_MAX             = XCP_CPB_ALG_ML_KEM
                                     // marks last used CPB
} XCP_CPbit_t;


// rounded CP count, multiple of XCP_CPBLOCK_BITS
// integer bytes, by construction (CPBLOCK_BITS is)
//
#define  XCP_CPCOUNT   \
  (((XCP_CPBITS_MAX +XCP_CPBLOCK_BITS-1) /XCP_CPBLOCK_BITS) *XCP_CPBLOCK_BITS)

#define  XCP_CP_BYTES  (XCP_CPCOUNT /8)    /* full blocks, incl. unused bits */

#define  XCP_CPB__INVERT  (XCP_CPCOUNT-1)  /* reserve MS CP bit for negation */


/*---  CP checks  --------------------*/
//
// XCP_CPB_ADD_CPBS
//    - SetAttribute()
// XCP_CPB_DELETE_CPBS
//    - SetAttribute()     -- if attempting to set a previously unset attribute
// XCP_CPB_SIGN_ASYMM
//    - SignSingle()       -- private key blobs
//    - SignInit()         -- private key blobs
// XCP_CPB_SIGN_SYMM
//    - SignSingle()       -- symmetric blobs
//    - SignInit()         -- symmetric blobs
// XCP_CPB_SIGVERIFY_SYMM
//    - VerifySingle()     -- symmetric blobs
//    - VerifyInit()       -- symmetric blobs
// XCP_CPB_ENCRYPT_SYMM
//    - EncryptSingle()    -- symmetric blobs
//    - EncryptInit()      -- symmetric blobs
// XCP_CPB_DECRYPT_ASYMM
//    - DecryptSingle()    -- private key blobs
//    - DecryptInit()      -- private key blobs
// XCP_CPB_DECRYPT_SYMM
//    - DecryptSingle()    -- symmetric blobs
//    - DecryptInit()      -- symmetric blobs
// XCP_CPB_WRAP_ASYMM
//    - WrapKey()          -- SPKIs
// XCP_CPB_WRAP_SYMM
//    - WrapKey()          -- symmetric blobs
// XCP_CPB_UNWRAP_ASYMM
//    - UnwrapKey()        -- private key blobs
// XCP_CPB_UNWRAP_SYMM
//    - UnwrapKey()        -- symmetric blobs
// XCP_CPB_KEYGEN_ASYMM
//    - GenerateKeyPair()
// XCP_CPB_KEYGEN_SYMM
//    - GenerateKey()
//    - UnwrapKey()        -- symmetric target
//    - DeriveKey()        -- all targets, except openblockchain t-cert
//                         -- derivation, are symmetric
// XCP_CPB_RETAINKEYS
//    - WrapKey(), the form which turns blob into SRK (handle+object)
// XCP_CPB_SKIP_KEYTESTS
//    - GenerateKeyPair()
//    - UnwrapKey()
//      -- note: this functionality can only be verified based on logs
//      --       it enables cross-checking opaque to the host
// XCP_CPB_NON_ATTRBOUND
//    - WrapKey()           -- when wrapping to non-AB form
//    - UnwrapKey()         -- when accepting non-AB form
// XCP_CPB_MODIFY_OBJECTS
//    - SetAttributeValue() -- globally, not just per object
// XCP_CPB_RNG_SEED
//    - SeedRandom()
// XCP_CPB_ALG_RAW_RSA
//    - SignSingle()        -- RSA blobs
//    - Sign()              -- RSA blobs
//    - DecryptSingle()     -- RSA blobs
//    - Decrypt()           -- RSA blobs
// XCP_CPB_ALG_NFIPS2009
//    - see NIST algorithms
// XCP_CPB_ALG_NBSI2009
//    - see BSI algorithms
// XCP_CPB_KEYSZ_HMAC_ANY
//    - SignSingle()        -- symmetric blobs with HMAC mech
//    - Sign()              -- symmetric blobs with HMAC mech
//    - VerifySingle()      -- symmetric blobs with HMAC mech
//    - Verify()            -- symmetric blobs with HMAC mech
// XCP_CPB_KEYSZ_BELOW80BIT
//    - see size restrictions
// XCP_CPB_KEYSZ_80BIT
//    - see size restrictions
// XCP_CPB_KEYSZ_112BIT
//    - see size restrictions
// XCP_CPB_KEYSZ_128BIT
//    - see size restrictions
// XCP_CPB_KEYSZ_192BIT
//    - see size restrictions
// XCP_CPB_KEYSZ_256BIT
//    - see size restrictions
// XCP_CPB_KEYSZ_RSA65536
//    - GenerateKeyPair()
//    - UnwrapKey()
// XCP_CPB_ALG_RSA
//    - GenerateKeyPair()   -- CKK_RSA
//    - UnwrapKey()         -- CKK_RSA
//    - SignSingle()        -- RSA blobs
//    - Sign()              -- RSA blobs
//    - VerifySingle()      -- RSA blobs
//    - Verify()            -- RSA blobs
// XCP_CPB_ALG_DSA
//    - GenerateKeyPair()   -- CKK_DSA
//    - UnwrapKey()         -- CKK_DSA
//    - SignSingle()        -- DSA blobs
//    - Sign()              -- DSA blobs
// XCP_CPB_ALG_EC
//    - GenerateKeyPair()   -- CKK_EC
//    - UnwrapKey()         -- CKK_EC
//    - SignSingle()        -- EC blobs
//    - Sign()              -- EC blobs
// XCP_CPB_ALG_EC_BPOOLCRV
//    - GenerateKeyPair()   -- CKK_EC with Brainpool curves
//    - UnwrapKey()         -- CKK_EC with Brainpool curves
// XCP_CPB_ALG_EC_NISTCRV
//    - GenerateKeyPair()   -- CKK_EC with NIST curves
//    - UnwrapKey()         -- CKK_EC with NIST curves
// XCP_CPB_ALG_NFIPS2011
//    - see NIST algorithms
// XCP_CPB_ALG_NBSI2011
//    - see BSI algorithms
// XCP_CPB_USER_SET_TRUSTED
//    - SetAttributeValue()
// XCP_CPB_ALG_SKIP_CROSSCHK
// XCP_CPB_WRAP_CRYPT_KEYS
//    - unwrap_blob()       -- all blob uses
// XCP_CPB_SIGN_CRYPT_KEYS
//    - unwrap_blob()       -- all blob uses
// XCP_CPB_WRAP_SIGN_KEYS
//    - unwrap_blob()       -- all blob uses
// XCP_CPB_USER_SET_ATTRBOUND
//    - SetAttributeValue()
// XCP_CPB_ALLOW_PASSPHRASE
//    - DeriveKey()
// XCP_CPB_WRAP_STRONGER_KEY
//    - WrapKey()
//    - UnwrapKey()
// XCP_CPB_WRAP_WITH_RAW_SPKI
//    - WrapKey()
//
/*--  /CP checks  --------------------*/


/*---  administration  -----------------------------------------------------*/

#define  XCP_ADM_QUERY  0x10000

typedef enum {
	XCP_ADM_ADMIN_LOGIN        = 1,   // add admin certificate
	XCP_ADM_DOM_ADMIN_LOGIN    = 2,   // add domain admin certificate
	XCP_ADM_ADMIN_LOGOUT       = 3,   // revoke admin certificate
	XCP_ADM_DOM_ADMIN_LOGOUT   = 4,   // revoke domain admin certificate
	XCP_ADM_ADMIN_REPLACE      = 5,   // transition admin certificate
	XCP_ADM_DOM_ADMIN_REPLACE  = 6,   // transition domain admin certificate

	XCP_ADM_SET_ATTR           = 7,   // set card attribute/s
	XCP_ADM_DOM_SET_ATTR       = 8,   // set domain attribute/

	XCP_ADM_GEN_DOM_IMPORTER   = 9,   // generate new importer (PK) key
	XCP_ADM_GEN_WK             = 10,  // create random domain WK
	XCP_ADM_EXPORT_WK          = 11,  // wrap+output WK or parts
	XCP_ADM_EXPORT_NEXT_WK     = 38,  // wrap+output next WK or parts
	XCP_ADM_IMPORT_WK          = 12,  // set (set of) WK (parts) to pending
	XCP_ADM_COMMIT_WK          = 13,  // activate pending WK
	XCP_ADM_FINALIZE_WK        = 14,  // remove previous WK's

	XCP_ADM_ZEROIZE            = 15,  // release CSPs from entire module
	XCP_ADM_DOM_ZEROIZE        = 16,  // release CSPs from domain/s

	XCP_ADM_DOM_CTRLPOINT_SET  = 17,  // fix domain control points
	XCP_ADM_DOM_CTRLPOINT_ADD  = 18,  // enable domain control points
	XCP_ADM_DOM_CTRLPOINT_DEL  = 19,  // disable domain control points

	XCP_ADM_SET_CLOCK          = 20,  // set module-internal UTC time
	XCP_ADM_SET_FCV            = 21,  // set function-control vector

	XCP_ADM_CTRLPOINT_SET      = 22,  // fix card control points
	XCP_ADM_CTRLPOINT_ADD      = 23,  // enable card control points
	XCP_ADM_CTRLPOINT_DEL      = 24,  // disable card control points

	XCP_ADM_REENCRYPT          = 25,  // transform blobs to next WK
	XCP_ADM_RK_REMOVE          = 26,  // remove (semi-) retained key
	XCP_ADM_CLEAR_WK           = 27,  // erase current WK
	XCP_ADM_CLEAR_NEXT_WK      = 28,  // erase pending WK
	XCP_ADM_SYSTEM_ZEROIZE     = 29,  // card zeroize, preserving system
	                                  // key, if it is present
	XCP_ADM_EXPORT_STATE       = 30,  // create card state backup
	XCP_ADM_IMPORT_STATE       = 31,  // import card state backup (part)
	XCP_ADM_COMMIT_STATE       = 32,  // activate imported card state
	XCP_ADM_REMOVE_STATE       = 33,  // purge import/export state backup
	XCP_ADM_GEN_MODULE_IMPORTER= 34,  // generate new importer (PK) key
	XCP_ADM_SET_TRUSTED        = 35,  // activate TRUSTED attribute on
	                                  // blob/SPKI
	XCP_ADM_DOMAINS_ZEROIZE    = 36,  // multi-domain zeroize
//	XCP_ADM_EXPORT_NEXT_WK     = 38,  // placeholder, find real entry above
	XCP_ADM_SESSION_REMOVE     = 39,  // remove all or selected sessions

	XCP_ADMQ_ADMIN             = 1  | XCP_ADM_QUERY, // admin SKI/cert
	XCP_ADMQ_DOMADMIN          = 2  | XCP_ADM_QUERY, // domain adm. SKI/cert
	XCP_ADMQ_DEVICE_CERT       = 3  | XCP_ADM_QUERY, // module CA (OA) cert
	XCP_ADMQ_DOM_IMPORTER_CERT = 4  | XCP_ADM_QUERY, // dom WK importer
	XCP_ADMQ_CTRLPOINTS        = 5  | XCP_ADM_QUERY, // card CP
	XCP_ADMQ_DOM_CTRLPOINTS    = 6  | XCP_ADM_QUERY, // domain CP
	XCP_ADMQ_WK                = 7  | XCP_ADM_QUERY, // current WK
	XCP_ADMQ_NEXT_WK           = 8  | XCP_ADM_QUERY, // pending WK
	XCP_ADMQ_ATTRS             = 9  | XCP_ADM_QUERY, // card attributes
	XCP_ADMQ_DOM_ATTRS         = 10 | XCP_ADM_QUERY, // domain attributes
	XCP_ADMQ_FCV               = 11 | XCP_ADM_QUERY, // public parts of FCV
	XCP_ADMQ_WK_ORIGINS        = 12 | XCP_ADM_QUERY,
	                                  // information on original WK
	                                  // components (keyparts
	                                  // verification patterns)
	XCP_ADMQ_RKLIST            = 13 | XCP_ADM_QUERY,
	                                  // retained-key id list
	XCP_ADMQ_INTERNAL_STATE    = 14 | XCP_ADM_QUERY,
	                                  // (part of) import/export state(file)
	XCP_ADMQ_IMPORTER_CERT     = 15  | XCP_ADM_QUERY,
	                                  // current migration importer
	XCP_ADMQ_AUDIT_STATE       = 16  | XCP_ADM_QUERY,
	                                  // audit state entry or event count
	XCP_ADMQ_LASTCMD_DOM_MASK  = 17 | XCP_ADM_QUERY,
	                                  // domain-bitmask affected by last
	                                  // state-related administrative
	                                  // command (export, import)
	XCP_ADMQ_SVCADMIN          = 18 | XCP_ADM_QUERY, // svc admin SKI/cert
	XCP_ADMQ_LOGIN_IMPORTER    = 19 | XCP_ADM_QUERY,
	                                  // session importer key
} XCP_Admcmd_t;

typedef enum {
	XCP_ADMINT_SIGN_THR        = 1,   // signature threshold
	XCP_ADMINT_REVOKE_THR      = 2,   // revocation (signature) threshold
	XCP_ADMINT_PERMS           = 3,   // permissions
	XCP_ADMINT_MODE            = 4,   // operating mode
	XCP_ADMINT_STD             = 5,   // standards' compliance
	XCP_ADMINT_PERMS_EXT01     = 6,   // permissions (extension #1)
	XCP_ADMINT_GEN_KTYPES      = 7,   // generic keytypes
	XCP_ADMINT_ECC_KTYPES      = 8,   // ECC curve types
	XCP_ADMINT_DIL_KTYPES      = 9,   // Dilithium types
	XCP_ADMINT_ADM_COMPL       = 10,  // administrative compliance
	XCP_ADMINT_IDX_MAX         = XCP_ADMINT_ADM_COMPL
} XCP_AdmAttr_t;

#define XCP_ADMIN_ATTRIBUTE_COUNT  XCP_ADMINT_IDX_MAX

// init-time value
#define XCP_ADM_SIGTHR__DEFAULT        0
#define XCP_ADM_REVTHR__DEFAULT        0

// permissions
#define XCP_ADMP_WK_IMPORT             1  // allow WK import
#define XCP_ADMP_WK_EXPORT             2  // allow WK export
#define XCP_ADMP_WK_1PART              4  // allow WK transport in one part
#define XCP_ADMP_WK_RANDOM             8  // allow internally generated WK
#define XCP_ADMP_1SIGN              0x10  // allow single-signed administration
                                          // (threshold set to 1)
#define XCP_ADMP_CP_1SIGN           0x20  // allow single-signed CP modification
#define XCP_ADMP_ZERO_1SIGN         0x40  // allow single-signed zeroize
//
#define XCP_ADMP_NO_DOMAIN_IMPRINT     \
                                  0x0080  // prohibit logging in to domains in
                                          // imprint mode (card only)
#define XCP_ADMP_STATE_IMPORT     0x0100  // allow state (part) import
                                          // (ignored by domains)
#define XCP_ADMP_STATE_EXPORT     0x0200  // allow state (part) export
                                          // (ignored by domains)
#define XCP_ADMP_STATE_1PART      0x0400  // allow state transport with 1-part
                                          // key (ignored by domains)
#define XCP_ADMP_DO_NOT_DISTURB   0x2000  // do not count module-administrator
                                          // signatures for domain commands,
                                          // other than zeroize commands
                                          // (managed but ignored for module-
                                          // level attributes)
//
// if adding other change-control bits, also update:
//
#define XCP_ADMP_CHG_WK_IMPORT   0x10000  // allow changing WK import flag
#define XCP_ADMP_CHG_WK_EXPORT   0x20000  // allow changing WK export flag
#define XCP_ADMP_CHG_WK_1PART    0x40000  // allow changing WK 1-part
                                          // transport flag
#define XCP_ADMP_CHG_WK_RANDOM   0x80000  // allow changing internal WK flag
#define XCP_ADMP_CHG_SIGN_THR   0x100000  // allow changing sign threshold
#define XCP_ADMP_CHG_REVOKE_THR 0x200000  // allow changing revoke threshold
#define XCP_ADMP_CHG_1SIGN      0x400000  // allow changing single-sign
                                          // threshold setting
#define XCP_ADMP_CHG_CP_1SIGN   0x800000  // allow changing 1-sign (CPs)
#define XCP_ADMP_CHG_ZERO_1SIGN        \
                              0x01000000  // allow changing 1-sign (zeroize)
#define XCP_ADMP_CHG_ST_IMPORT         \
                              0x02000000  // allow changing state import bit
                                          // (ignored by domains)
#define XCP_ADMP_CHG_ST_EXPORT         \
                              0x04000000  // allow changing state export bit
                                          // (ignored by domains)
#define XCP_ADMP_CHG_ST_1PART 0x08000000  // allow changing 1-part encrypt bit
                                          // (ignored by domains)
#define XCP_ADMP_CHG_DO_NOT_DISTURB    \
                              0x80000000  // allow changing the corresponding
                                          // Do Not Disturb bit

//
// permissions (extension 01)
//
#define XCP_ADMP_NQS_OA_SIGNATURES     1  // enable non-quantum-safe OA signat.
#define XCP_ADMP_QS_OA_SIGNATURES      2  // enable quantum-safe OA signatures
#define XCP_ADMP_NQS_ADM_SIGNATURES    4  // enable non-quantum-safe adm signat.
#define XCP_ADMP_QS_ADM_SIGNATURES     8  // enable quantum-safe adm signatures

#define XCP_ADMP_CHG_NQS_OA_SIGNATURES \
                                 0x10000  // allow changing the corresponding
                                          // non-quantum-safe OA signature bit
#define XCP_ADMP_CHG_QS_OA_SIGNATURES  \
                                 0x20000  // allow changing the corresponding
                                          // quantum-safe OA signature bit
#define XCP_ADMP_CHG_NQS_ADM_SIGNATURES \
                                 0x40000  // allow changing the corresponding
                                          // non-quantum-safe adm signature bit
#define XCP_ADMP_CHG_QS_ADM_SIGNATURES  \
                                 0x80000  // allow changing the corresponding
                                          // quantum-safe adm signature bit

//
// generic administrative keytypes
//
#define XCP_ADMK_KTYPE_RSA             1  // enable admin key type RSA
#define XCP_ADMK_KTYPE_ECC             2  // enable admin key type EC
#define XCP_ADMK_KTYPE_DIL             4  // enable admin key type Dilithium
#define XCP_ADMK_CHG_KTYPE_RSA   0x10000  // allow changing the corresponding
                                          // adm key type RSA
#define XCP_ADMK_CHG_KTYPE_ECC         \
                                 0x20000  // allow changing the corresponding
                                          // adm key type EC
#define XCP_ADMK_CHG_KTYPE_DIL         \
                                 0x40000  // allow changing the corresponding
                                          // adm key type Dilithium

#define XCP_ADMK__ALL                  \
       (XCP_ADMK_KTYPE_RSA           | \
        XCP_ADMK_KTYPE_ECC           | \
        XCP_ADMK_KTYPE_DIL)

#define XCP_ADMK__CHGBITS              \
       (XCP_ADMK_CHG_KTYPE_RSA       | \
        XCP_ADMK_CHG_KTYPE_ECC       | \
        XCP_ADMK_CHG_KTYPE_DIL)

#define XCP_ADMK__DEFAULT              \
       (XCP_ADMK__CHGBITS            | \
        XCP_ADMK__ALL)

#define XCP__ADMK_SUP  XCP_ADMK__DEFAULT

//
// supported administrative curve types
// (depends on XCP_ADMK_KTYPE_ECC)
//
#define XCP_ADME_KTYPE_ECC_NIST        1  // enable admin key type EC NIST
#define XCP_ADME_KTYPE_ECC_BP          2  // enable admin key type EC Brainpool
#define XCP_ADME_KTYPE_ECC_ED          4  // enable admin key type EC Edwards
#define XCP_ADME_KTYPE_ECC_MG          8  // enable admin key type EC Montgomery
#define XCP_ADME_CHG_KTYPE_ECC_NIST    \
                                 0x10000  // allow changing the corresponding
                                          // adm key type EC NIST
#define XCP_ADME_CHG_KTYPE_ECC_BP      \
                                 0x20000  // allow changing the corresponding
                                          // adm key type EC Brainpool
#define XCP_ADME_CHG_KTYPE_ECC_ED      \
                                 0x40000  // allow changing the corresponding
                                          // adm key type EC Edwards
#define XCP_ADME_CHG_KTYPE_ECC_MG      \
                                 0x80000  // allow changing the corresponding
                                          // adm key type EC Montgomery

#define XCP_ADME__ALL                  \
       (XCP_ADME_KTYPE_ECC_NIST      | \
        XCP_ADME_KTYPE_ECC_BP        | \
        XCP_ADME_KTYPE_ECC_ED)

#define XCP_ADME__CHGBITS              \
       (XCP_ADME_CHG_KTYPE_ECC_NIST  | \
        XCP_ADME_CHG_KTYPE_ECC_BP    | \
        XCP_ADME_CHG_KTYPE_ECC_ED)

#define XCP_ADME__DEFAULT              \
       (XCP_ADME__CHGBITS            | \
        XCP_ADME__ALL)

#define XCP__ADME_SUP  XCP_ADME__DEFAULT

//
// supported administrative DIL types
// (depends on XCP_ADMK_KTYPE_DIL)
//
#define XCP_ADMQ_KTYPE_DIL_R2          1  // enable admin key type Dilithium R2
#define XCP_ADMQ_KTYPE_DIL_R3          2  // enable admin key type Dilithium R3
#define XCP_ADMQ_CHG_KTYPE_DIL_R2      \
                                 0x10000  // allow changing the corresponding
                                          // adm key type Dilithium R2
#define XCP_ADMQ_CHG_KTYPE_DIL_R3      \
                                 0x20000  // allow changing the corresponding
                                          // adm key type Dilithium R3

#define XCP_ADMQ__ALL                  \
       (XCP_ADMQ_KTYPE_DIL_R2        | \
        XCP_ADMQ_KTYPE_DIL_R3)

#define XCP_ADMQ__CHGBITS              \
       (XCP_ADMQ_CHG_KTYPE_DIL_R2    | \
        XCP_ADMQ_CHG_KTYPE_DIL_R3)

#define XCP_ADMQ__DEFAULT              \
       (XCP_ADMQ__CHGBITS            | \
        XCP_ADMQ__ALL)

#define XCP__ADMQ_SUP  XCP_ADMQ__DEFAULT

//
// Administrative compliance
//
#define XCP_ADMC_ADM_FIPS2021          1  // NIST SP800-131A REV.2, 2021.01.01


//
// if adding other change-control bits, also update:
//      prevented_perm_changes()
//      valid_attr_reactivate()
// ...as well as constants below
//
#define XCP_ADMP__CHGBITS           \
       (XCP_ADMP_CHG_WK_IMPORT    | \
        XCP_ADMP_CHG_WK_EXPORT    | \
        XCP_ADMP_CHG_WK_1PART     | \
        XCP_ADMP_CHG_WK_RANDOM    | \
        XCP_ADMP_CHG_SIGN_THR     | \
        XCP_ADMP_CHG_REVOKE_THR   | \
        XCP_ADMP_CHG_1SIGN        | \
        XCP_ADMP_CHG_CP_1SIGN     | \
        XCP_ADMP_CHG_ZERO_1SIGN   | \
        XCP_ADMP_CHG_ST_IMPORT    | \
        XCP_ADMP_CHG_ST_EXPORT    | \
        XCP_ADMP_CHG_ST_1PART     | \
        XCP_ADMP_CHG_DO_NOT_DISTURB)
//
#define XCP_ADMP__PERMS              \
       (XCP_ADMP_WK_IMPORT         | \
        XCP_ADMP_WK_EXPORT         | \
        XCP_ADMP_WK_1PART          | \
        XCP_ADMP_WK_RANDOM         | \
        XCP_ADMP_1SIGN             | \
        XCP_ADMP_CP_1SIGN          | \
        XCP_ADMP_ZERO_1SIGN        | \
        XCP_ADMP_NO_DOMAIN_IMPRINT | \
        XCP_ADMP_STATE_IMPORT      | \
        XCP_ADMP_STATE_EXPORT      | \
        XCP_ADMP_STATE_1PART       | \
        XCP_ADMP_DO_NOT_DISTURB)
//
// CHGBITS / PERMS (extension 01)
#define XCP_ADMP__CHGBITS_EXT01           \
       (XCP_ADMP_CHG_NQS_OA_SIGNATURES  | \
        XCP_ADMP_CHG_QS_OA_SIGNATURES   | \
        XCP_ADMP_CHG_NQS_ADM_SIGNATURES | \
        XCP_ADMP_CHG_QS_ADM_SIGNATURES)
//
#define XCP_ADMP__PERMS_EXT01         \
       (XCP_ADMP_NQS_OA_SIGNATURES  | \
        XCP_ADMP_QS_OA_SIGNATURES   | \
        XCP_ADMP_NQS_ADM_SIGNATURES | \
        XCP_ADMP_QS_ADM_SIGNATURES)
//
#define XCP__ADMP_SUP_EXT01 (XCP_ADMP__PERMS_EXT01 | \
                             XCP_ADMP__CHGBITS_EXT01)
//
//
#define XCP_ADMP__DEFAULT         \
       (XCP_ADMP_WK_IMPORT      | \
        XCP_ADMP_1SIGN          | \
        XCP_ADMP__CHGBITS)
//
#define XCP_ADMP__DEFAULT_EXT01       \
       (XCP_ADMP__CHGBITS_EXT01     | \
        XCP_ADMP_NQS_OA_SIGNATURES  | \
        XCP_ADMP_QS_OA_SIGNATURES   | \
        XCP_ADMP_NQS_ADM_SIGNATURES | \
        XCP_ADMP_QS_ADM_SIGNATURES)
//
#define XCPM_ADMP__MODULE_DEFAULTS_MASK   \
       (XCP_ADMP_DO_NOT_DISTURB         | \
        XCP_ADMP_CHG_DO_NOT_DISTURB)
//
#define XCPM_ADMP__MODULE_DEFAULTS_MASK_EXT01  \
       (XCP_ADMP_NQS_OA_SIGNATURES           | \
        XCP_ADMP_CHG_NQS_OA_SIGNATURES       | \
        XCP_ADMP_QS_OA_SIGNATURES            | \
        XCP_ADMP_CHG_QS_OA_SIGNATURES        | \
        XCP_ADMP_NQS_ADM_SIGNATURES          | \
        XCP_ADMP_CHG_NQS_ADM_SIGNATURES      | \
        XCP_ADMP_QS_ADM_SIGNATURES           | \
        XCP_ADMP_CHG_QS_ADM_SIGNATURES)
//
#define XCP_ADMP__CARD_MASK       \
      ~(XCP_ADMP_WK_IMPORT      | \
        XCP_ADMP_WK_EXPORT      | \
        XCP_ADMP_WK_1PART       | \
        XCP_ADMP_WK_RANDOM      | \
        XCP_ADMP_CP_1SIGN       | \
        XCP_ADMP_CHG_WK_IMPORT  | \
        XCP_ADMP_CHG_WK_EXPORT  | \
        XCP_ADMP_CHG_WK_1PART   | \
        XCP_ADMP_CHG_WK_RANDOM  | \
        XCP_ADMP_CHG_CP_1SIGN)
//
#define XCP_ADMP__CARD_MASK_EXT01 \
       ~(0U)
//
#define XCP_ADMP__DOM_MASK           \
      ~(XCP_ADMP_NO_DOMAIN_IMPRINT | \
        XCP_ADMP_STATE_IMPORT      | \
        XCP_ADMP_STATE_EXPORT      | \
        XCP_ADMP_STATE_1PART       | \
        XCP_ADMP_CHG_ST_IMPORT     | \
        XCP_ADMP_CHG_ST_EXPORT     | \
        XCP_ADMP_CHG_ST_1PART)
//
#define XCP_ADMP__DOM_MASK_EXT01     \
      ~(0U)
//

#define XCP__ADMP_SUP ((XCP_ADMP__PERMS | XCP_ADMP__CHGBITS) &\
                       ~XCP_ADMP_NOT_SUP)

// card modes
#define XCP_ADMM_AUTHENTICATED         1U  // no longer in imprint mode
#define XCP_ADMM_EXTWNG                2U  // zeroize if starting w/ ext.
                                           // warning included in default setup
//
// minimum administrator strength
#define XCP_ADMM_STR_112BIT            4U  // require 112+ bits' admin strength
#define XCP_ADMM_STR_128BIT            8U  // require 128+ bits' admin strength
#define XCP_ADMM_STR_160BIT         0x10U  // require 160+ bits' admin strength
#define XCP_ADMM_STR_192BIT         0x20U  // require 192+ bits' admin strength
#define XCP_ADMM_STR_256BIT         0x40U  // require 256  bits' admin strength
#define XCP_ADMM_WKCLEAN_EXTWNG     0x80U  // zeroize WKs if starting with
                                           // ext. warning set.  Leaves
                                           // other parameters unaffected
#define XCP_ADMM_BATT_LOW         0x0100U  // module reports low battery
                                           // (read only)
#define XCP_ADMM_API_ACTIVE       0x0200U  // remove to disable XCP within card

//
// change-control bits
#define XCP_ADMM_CHG_KEYSTR      0x040000  // change key strength bits (112-256)


//
#define XCP_ADMM__DEFAULT   \
       (XCP_ADMM_EXTWNG     | \
        XCP_ADMM_API_ACTIVE | \
        XCP_ADMM_CHG_KEYSTR)
//
// all defined attributes
#define XCP_ADMM__MASK            \
        (XCP_ADMM_AUTHENTICATED  | \
         XCP_ADMM_EXTWNG         | \
         XCP_ADMM_STR_112BIT     | \
         XCP_ADMM_STR_128BIT     | \
         XCP_ADMM_STR_160BIT     | \
         XCP_ADMM_STR_192BIT     | \
         XCP_ADMM_STR_256BIT     | \
         XCP_ADMM_WKCLEAN_EXTWNG | \
         XCP_ADMM_BATT_LOW       | \
         XCP_ADMM_API_ACTIVE     | \
         XCP_ADMM_CHG_KEYSTR)
//
// infrastructure modes read only on domain level
#define XCP_ADMM__CARD_ONLY_ATTR  \
       (XCP_ADMM_EXTWNG         | \
        XCP_ADMM_WKCLEAN_EXTWNG | \
        XCP_ADMM_API_ACTIVE)
//
#define XCP_ADMM__READ_ONLY_ATTR \
       (XCP_ADMM_AUTHENTICATED | \
        XCP_ADMM_BATT_LOW)

// strength bits restrict adm key strength
#define XCP__ADMM_ADMSTR      \
       (XCP_ADMM_STR_112BIT | \
        XCP_ADMM_STR_128BIT | \
        XCP_ADMM_STR_160BIT | \
        XCP_ADMM_STR_192BIT | \
        XCP_ADMM_STR_256BIT)

#define XCP__ADMM_SUP XCP_ADMM__MASK


// specific standards' compliance suites
#define XCP_ADMS_FIPS2009              1  // NIST, 80+ bits,  -2011.01.01.
#define XCP_ADMS_BSI2009               2  // BSI , 80+ bits,  -2011.01.01.
#define XCP_ADMS_FIPS2011              4  // NIST, 112+ bits,  2011.01.01.-
#define XCP_ADMS_BSI2011               8  // BSI,  112+ bits,  2011.01.01.-
//
// two bits reserved but not yet reported
#define XCP_ADMS_SIGG_IMPORT        0x10  // .de SigG, key import
#define XCP_ADMS_SIGG               0x20  // .de SigG, no key import
//
#define XCP_ADMS_BSICC2017          0x40  // BSI, EP11 Common Criteria EAL4 2017
//
#define XCP_ADMS_FIPS2021           0x80  // NIST SP800-131A REV.2, 2021.01.01
#define XCP_ADMS_FIPS2024          0x100  // NIST SP800-131A REV.2, 2024.01.01

#define XCP_ADMS__ALL  \
       (XCP_ADMS_FIPS2009  | \
        XCP_ADMS_BSI2009   | \
        XCP_ADMS_FIPS2011  | \
        XCP_ADMS_BSI2011   | \
        XCP_ADMS_BSICC2017 | \
        XCP_ADMS_FIPS2021  | \
        XCP_ADMS_FIPS2024)

#define XCP_ADMC__ALL  \
       (XCP_ADMC_ADM_FIPS2021)

// The following 'legacy' defines are used as default 'supported bit masks'
// for older devices that do not have native bit masks for that purpose.
// Note: If supported bits are not present, the import of these bits are
//       skipped and the default values will be kept.
#define XCP__ADMP_SUP_LEGACY          \
       (XCP_ADMP_WK_IMPORT          | \
        XCP_ADMP_WK_EXPORT          | \
        XCP_ADMP_WK_1PART           | \
        XCP_ADMP_WK_RANDOM          | \
        XCP_ADMP_1SIGN              | \
        XCP_ADMP_CP_1SIGN           | \
        XCP_ADMP_ZERO_1SIGN         | \
        XCP_ADMP_NO_DOMAIN_IMPRINT  | \
        XCP_ADMP_STATE_IMPORT       | \
        XCP_ADMP_STATE_EXPORT       | \
        XCP_ADMP_STATE_1PART        | \
        XCP_ADMP_CHG_WK_IMPORT      | \
        XCP_ADMP_CHG_WK_EXPORT      | \
        XCP_ADMP_CHG_WK_1PART       | \
        XCP_ADMP_CHG_WK_RANDOM      | \
        XCP_ADMP_CHG_SIGN_THR       | \
        XCP_ADMP_CHG_REVOKE_THR     | \
        XCP_ADMP_CHG_1SIGN          | \
        XCP_ADMP_CHG_CP_1SIGN       | \
        XCP_ADMP_CHG_ZERO_1SIGN     | \
        XCP_ADMP_CHG_ST_IMPORT      | \
        XCP_ADMP_CHG_ST_EXPORT      | \
        XCP_ADMP_CHG_ST_1PART)

#define XCP__ADMM_SUP_LEGACY          \
       (XCP_ADMM_AUTHENTICATED      | \
        XCP_ADMM_EXTWNG             | \
        XCP__ADMM_ADMSTR            | \
        XCP_ADMM_WKCLEAN_EXTWNG     | \
        XCP_ADMM_BATT_LOW           | \
        XCP_ADMM_API_ACTIVE)

#define XCP_ADMS__ALL_LEGACY          \
       (XCP_ADMS_FIPS2009           | \
        XCP_ADMS_BSI2009            | \
        XCP_ADMS_FIPS2011           | \
        XCP_ADMS_BSI2011            | \
        XCP_ADMS_BSICC2017)

#define XCP__ADMP_SUP_EXT01_LEGACY        \
       (XCP_ADMP_NQS_OA_SIGNATURES      | \
        XCP_ADMP_QS_OA_SIGNATURES       | \
        XCP_ADMP_CHG_NQS_OA_SIGNATURES  | \
        XCP_ADMP_CHG_QS_OA_SIGNATURES   | \
        XCP_ADMP_NQS_ADM_SIGNATURES     | \
        XCP_ADMP_QS_ADM_SIGNATURES      | \
        XCP_ADMP_CHG_NQS_ADM_SIGNATURES | \
        XCP_ADMP_CHG_QS_ADM_SIGNATURES)

// has compliance any BSI mode
#define XCP_ADMS_IS_BSI(mode)  (!!((mode) & (XCP_ADMS_BSI2009   | \
                                             XCP_ADMS_BSI2011   | \
                                             XCP_ADMS_BSICC2017    )) )
// mask of supported import keys
// 3k and 4k RSA are not supported
#define  XCP_ADM_IMPEXP_KEYS__MASK       \
         ((1 << XCP_IMPRKEY_RSA_2048)  | \
          (1 << XCP_IMPRKEY_EC_P256)   | \
          (1 << XCP_IMPRKEY_EC_P521)   | \
          (1 << XCP_IMPRKEY_EC_BP256r) | \
          (1 << XCP_IMPRKEY_EC_BP320r) | \
          (1 << XCP_IMPRKEY_EC_BP512r) | \
          (1 << XCP_IMPRKEY_EC_P521_TKE))


/*---  audit chains  -------------------------------------------------------*/
#define  XCP_LOG_KEYREC_BYTES       24
#define  XCP_LOG_SEQNR_BYTES         6
#define  XCP_LOG_INSTANCEID_BYTES    2
#define  XCP_LOG_TIMET_BYTES        (4+2)   /* sec[36](time_t) || msec[12] */
#define  XCP_LOG_SEQNR_OFFSET      ((size_t) 4) /* in fixed event header */
#define  XCP_LOG_SEQPRF_BASE_BYTES   \
         ((size_t) XCP_LOG_SEQNR_BYTES +XCP_LOG_TIMET_BYTES)
#define  XCP_LOG_COMPLIANCE_BYTES    8
#define  XCP_LOG_REASON_BYTES        4
#define  XCP_LOG_SALTUNIT_BYTES      4
#define  XCP_LOG_SALT_MAX_UNITS      3
#define  XCP_LOG_SALT_MAX_BYTES      \
        (XCP_LOG_SALT_MAX_UNITS * XCP_LOG_SALTUNIT_BYTES)
#define  XCP_LOG_PRFSALT_BYTES     ((size_t) 64/8)            /* Siphash-2-4 */

/* event context: fields present in all audit records */
#define  XCP_LOG_CONTEXT_BYTES                     \
        (2* XCP_SERIALNR_CHARS+                    \
         2+2+    /* audit instance, event type  */ \
         4+4+    /* event type, firmware ID     */ \
         4+4     /* fn ID, domain, var-len size */ )

/* optional fields, total (see flags) */
#define  XCP_LOG_OPTFIELD_MAX_BYTES    \
        (2* XCP_WK_BYTES             + \
            XCP_LOG_COMPLIANCE_BYTES + \
         3* XCP_LOG_KEYREC_BYTES     + \
            XCP_LOG_TIMET_BYTES      + \
	    XCP_LOG_COMPLIANCE_BYTES + \
            XCP_LOG_REASON_BYTES     + \
            XCP_LOG_SALT_MAX_BYTES)

#define  XCP_LOG_HEADER_BYTES   \
        (1+1+2 +         /* type, version, bytecount */ \
         XCP_LOG_SEQNR_BYTES +  \
         XCP_LOG_TIMET_BYTES)

        /* worst-case full wire-formatted entry, incl. trailing hash */
#define  XCP_LOG_ENTRY_MAX_BYTES                               \
        (XCP_LOG_HEADER_BYTES       +                          \
         XCP_LOG_STATE_BYTES        + /* initial state/hash */ \
         XCP_LOG_CONTEXT_BYTES      +                          \
         XCP_LOG_OPTFIELD_MAX_BYTES +                          \
         XCP_LOG_STATE_BYTES)


/*---  state serialization  ------------------------------------------------*/
typedef enum {
	XCP_STSTYPE_SECTIONCOUNT      =  1, // section count +file hash
	XCP_STSTYPE_DOMAINIDX_MAX     =  2, // largest index +total nr of doms
	XCP_STSTYPE_DOMAINS_MASK      =  3, // bitmask of included domains
	XCP_STSTYPE_SERIALNR          =  4,
	XCP_STSTYPE_CREATE_TIME       =  5, // file date/time (UTC)
	XCP_STSTYPE_FCV               =  6, // public parts of originating FCV
	XCP_STSTYPE_CARD_QUERY        =  7, // V0 card state struct (xcp_info)
	XCP_STSTYPE_CARD_ADM_SKIS     =  8, // card admin SKIs, packed
	XCP_STSTYPE_CARD_ADM_CERTS    =  9, // card admin certificates, packed
	XCP_STSTYPE_DOM_ADM_SKIS      = 10, // domain admin SKIs, packed
	XCP_STSTYPE_DOM_ADM_CERTS     = 11, // domain admin certs, packed
	XCP_STSTYPE_DOM_QUERY         = 12, // domain state struct (xcp_info)
	XCP_STSTYPE_KPH_SKIS          = 13, // count and SKIs of targeted KPHs
	XCP_STSTYPE_CARD_ATTRS        = 14, // card attributes
	XCP_STSTYPE_DOM_ATTRS         = 15, // domain attributes
	XCP_STSTYPE_CARD_TRANSCTR     = 16, // card transaction counter
	XCP_STSTYPE_DOM_TRANSCTR      = 17, // domain transaction counter
	XCP_STSTYPE_WK_ENCR_ALG       = 18,
	XCP_STSTYPE_WK_ENCR_DATA      = 19,
	XCP_STSTYPE_SIG_CERT_COUNT    = 20,
	XCP_STSTYPE_SIG_CERTS         = 21,
	XCP_STSTYPE_FILE_SIG          = 22,
	XCP_STSTYPE_DOM_CPS           = 23, // full set of control points
	XCP_STSTYPE_STATE_SALT        = 24,
	XCP_STSTYPE_KEYPART           = 25, // encrypted keypart (RecipientInfo)
	XCP_STSTYPE_KEYPART_SIG       = 26, // signature on encrypted keypart
	XCP_STSTYPE_KEYPART_COUNT     = 27, // total number of keyparts
	XCP_STSTYPE_KEYPART_LIMIT     = 28, // number of keyparts needed to
	                                    // restore
	XCP_STSTYPE_KEYPART_CERT      = 29, // certificate of keypart holder
	XCP_STSTYPE_CERT_AUTH         = 30, // certificate authority issuing
	                                    // some of the certificates.  This
	                                    // field contains host-supplied data
	                                    // and it is ignored by EP11 itself.
	XCP_STSTYPE_STATE_SCOPE       = 31, // restriction on contents of full
	                                    // state structure
	XCP_STSTYPE_MULTIIMPORT_MASK  = 32, // import only: designate import
	                                    // request to be replicated into
	                                    // multiple recipient domains
	XCP_STSTYPE_CPS_MASK          = 33, // bitmask of all CPs supported
	                                    // by the exporting module
	XCP_STSTYPE_CARD_QUERY_V1     = 34, // V1 card state struct (xcp_info)
	XCP_STSTYPE_CARD_QUERY_V2     = 35, // V2 card state struct (xcp_info)
	XCP_STSTYPE_CARD_EXTADM_SKIS  = 36, // ext. card admin SKIs, packed
	XCP_STSTYPE_CARD_EXTADM_CERTS = 37, // ext. card admin certs, packed
	XCP_STSTYPE_DOM_EXTADM_SKIS   = 38, // ext. dom admin SKIs, packed
	XCP_STSTYPE_DOM_EXTADM_CERTS  = 39, // ext. dom admin certs, packed
	XCP_STSTYPE_CARD_ATTRS_SUPP   = 40, // supported bits of card attributes

	XCP_STSTYPE_MAX               = XCP_STSTYPE_CARD_ATTRS_SUPP
} XCP_StateSection_t;


typedef enum {
	XCP_STALG_AES256_CBC       = 1
} XCP_StateEncrAlg_t;

typedef enum {
	XCP_FILEID_SAVED_STATE     = 1,   // serialized state
	XCP_FILEID_KEYPARTS        = 2,   // encrypted keyparts
	XCP_FILEID_TESTDATA        = 3,   // not supported by production code
	XCP_FILEID_EXPREQUEST      = 4,   // export request
	XCP_FILEID_MAX             = XCP_FILEID_EXPREQUEST
} XCP_FileId_t;


typedef enum {
	XCP_STDATA_NO_RESTRICTION  = 0,   // no state restrictions to card
	                                  // or domain data
	XCP_STDATA_DOMAIN          = 1,   // state restricted to domain data
	                                  // only, excluding card-specific
	                                  // sections
	XCP_STDATA_NONSENSITIVE    = 2,   // serialized state restricted to
	                                  // non-sensitive sections only
	XCP_STWK_KP_NO_CERT        = 4,   // keypart section restricted to
	                                  // not return KPH certificates
	XCP_STWK_KP_NO_OA_CHAIN    = 8,   // keypart section restricted to
	                                  // not return OA certificate chain
	XCP_STDATA_NQS             = 0x20,// allow use of non-quantum-safe
	                                  // algorithms in KP export/signature
	XCP_STDATA_QS              = 0x40,// allow use of quantum-safe
	                                  // algorithms in KP export/signature
	XCP_STDATA_MAX             = ((XCP_STDATA_QS *2) -1)
} XCP_StateType_t;

// type || identifier prefixes
#define  XCP_STSTYPE_TYPE_BYTES    2
#define  XCP_STSTYPE_TYPEID_BYTES  4


/*---  EC curves  ----------------------------------------------------------*/

// NIST/SECG object identifiers
#define  XCP_EC_P192        "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x01"
#define  XCP_EC_P192_BYTES  10
#define  XCP_EC_P224        "\x06\x05\x2b\x81\x04\x00\x21"
#define  XCP_EC_P224_BYTES  7
#define  XCP_EC_P256        "\x06\x08\x2a\x86\x48\xce\x3d\x03\x01\x07"
#define  XCP_EC_P256_BYTES  10
#define  XCP_EC_P384        "\x06\x05\x2b\x81\x04\x00\x22"
#define  XCP_EC_P384_BYTES  7
#define  XCP_EC_P521        "\x06\x05\x2b\x81\x04\x00\x23"
#define  XCP_EC_P521_BYTES  7

// NIST/SECG, curve names as UTF-8/ASCII strings
#define  XCP_EC_P192_NAME        "\x50\x2d\x31\x39\x32"  /* P-192 */
#define  XCP_EC_P192_NAME_BYTES  5
#define  XCP_EC_P224_NAME        "\x50\x2d\x32\x32\x34"  /* P-224 */
#define  XCP_EC_P224_NAME_BYTES  5
#define  XCP_EC_P256_NAME        "\x50\x2d\x32\x35\x36"  /* P-256 */
#define  XCP_EC_P256_NAME_BYTES  5
#define  XCP_EC_P384_NAME        "\x50\x2d\x33\x38\x34"  /* P-384 */
#define  XCP_EC_P384_NAME_BYTES  5
#define  XCP_EC_P521_NAME        "\x50\x2d\x35\x32\x31"  /* P-521 */
#define  XCP_EC_P521_NAME_BYTES  5

// Brainpool object identifiers
#define  XCP_EC_BP160R        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x01"
#define  XCP_EC_BP160R_BYTES  11
#define  XCP_EC_BP160T        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x02"
#define  XCP_EC_BP160T_BYTES  11
#define  XCP_EC_BP192R        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x03"
#define  XCP_EC_BP192R_BYTES  11
#define  XCP_EC_BP192T        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x04"
#define  XCP_EC_BP192T_BYTES  11
#define  XCP_EC_BP224R        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x05"
#define  XCP_EC_BP224R_BYTES  11
#define  XCP_EC_BP224T        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x06"
#define  XCP_EC_BP224T_BYTES  11
#define  XCP_EC_BP256R        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x07"
#define  XCP_EC_BP256R_BYTES  11
#define  XCP_EC_BP256T        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x08"
#define  XCP_EC_BP256T_BYTES  11
#define  XCP_EC_BP320R        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x09"
#define  XCP_EC_BP320R_BYTES  11
#define  XCP_EC_BP320T        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x0a"
#define  XCP_EC_BP320T_BYTES  11
#define  XCP_EC_BP384R        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x0b"
#define  XCP_EC_BP384R_BYTES  11
#define  XCP_EC_BP384T        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x0c"
#define  XCP_EC_BP384T_BYTES  11
#define  XCP_EC_BP512R        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x0d"
#define  XCP_EC_BP512R_BYTES  11
#define  XCP_EC_BP512T        "\x06\x09\x2b\x24\x03\x03\x02\x08\x01\x01\x0e"
#define  XCP_EC_BP512T_BYTES  11
#define  XCP_EC_BPOID_BYTES   11
//
#define  XCP_EC_BPOIDS        14

// Brainpool, curve names as UTF-8/ASCII strings
#define  XCP_EC_BP160R_NAME        "\x42\x50\x2d\x31\x36\x30\x52" /* BP-160R */
#define  XCP_EC_BP160R_NAME_BYTES  7
#define  XCP_EC_BP160T_NAME        "\x42\x50\x2d\x31\x36\x30\x54" /* BP-160T */
#define  XCP_EC_BP160T_NAME_BYTES  7
#define  XCP_EC_BP192R_NAME        "\x42\x50\x2d\x31\x39\x32\x52" /* BP-192R */
#define  XCP_EC_BP192R_NAME_BYTES  7
#define  XCP_EC_BP192T_NAME        "\x42\x50\x2d\x31\x39\x32\x54" /* BP-192T */
#define  XCP_EC_BP192T_NAME_BYTES  7
#define  XCP_EC_BP224R_NAME        "\x42\x50\x2d\x32\x32\x34\x52" /* BP-224R */
#define  XCP_EC_BP224R_NAME_BYTES  7
#define  XCP_EC_BP224T_NAME        "\x42\x50\x2d\x32\x32\x34\x54" /* BP-224T */
#define  XCP_EC_BP224T_NAME_BYTES  7
#define  XCP_EC_BP256R_NAME        "\x42\x50\x2d\x32\x35\x36\x52" /* BP-256R */
#define  XCP_EC_BP256R_NAME_BYTES  7
#define  XCP_EC_BP256T_NAME        "\x42\x50\x2d\x32\x35\x36\x54" /* BP-256T */
#define  XCP_EC_BP256T_NAME_BYTES  7
#define  XCP_EC_BP320R_NAME        "\x42\x50\x2d\x33\x32\x30\x52" /* BP-320R */
#define  XCP_EC_BP320R_NAME_BYTES  7
#define  XCP_EC_BP320T_NAME        "\x42\x50\x2d\x33\x32\x30\x54" /* BP-320T */
#define  XCP_EC_BP320T_NAME_BYTES  7
#define  XCP_EC_BP384R_NAME        "\x42\x50\x2d\x33\x38\x34\x52" /* BP-384R */
#define  XCP_EC_BP384R_NAME_BYTES  7
#define  XCP_EC_BP384T_NAME        "\x42\x50\x2d\x33\x38\x34\x54" /* BP-384T */
#define  XCP_EC_BP384T_NAME_BYTES  7
#define  XCP_EC_BP512R_NAME        "\x42\x50\x2d\x35\x31\x32\x52" /* BP-512R */
#define  XCP_EC_BP512R_NAME_BYTES  7
#define  XCP_EC_BP512T_NAME        "\x42\x50\x2d\x35\x31\x32\x54" /* BP-512T */
#define  XCP_EC_BP512T_NAME_BYTES  7

// secp256k1 (Bitcoin default curve)
#define  XCP_EC_S256K1             "\x06\x05" "\x2b\x81\x04\x00\x0a"
#define  XCP_EC_S256K1_BYTES       7
#define  XCP_EC_S256K1_NAME        "\x53\x45\x43\x50\x32\x35\x36\x4b\x31"
                                                                /* SECP256K1 */
#define  XCP_EC_S256K1_NAME_BYTES  9

// curve25519, curve448, related OIDs
//
// 1.3.101.110: curve25519, allocated by PKIX, ECDH only
#define  XCP_EC_X25519        "\x06\x03\x2b\x65\x6e"
#define  XCP_EC_X25519_BYTES  5
#define  XCP_EC_X25519_NAME  "\x63\x75\x72\x76\x65\x32\x35\x35\x31\x39"
                                      /* curve25519 */
#define  XCP_EC_X25519_NAME_BYTES  10
//
// 1.3.101.111: curve[of-ed]448 'Goldilocks', allocated by PKIX, ECDH only
#define  XCP_EC_X448        "\x06\x03\x2b\x65\x6f"
#define  XCP_EC_X448_BYTES  5
#define  XCP_EC_X448_NAME   "\x78\x34\x34\x38"    /* c448, matching RFC8410 */
#define  XCP_EC_X448_NAME_BYTES  4
//
// 1.3.101.112: EDDSA, 25519
#define  XCP_EC_DSA25519        "\x06\x03\x2b\x65\x70"
#define  XCP_EC_DSA25519_BYTES  5
#define  XCP_EC_DSA25519_NAME   "\x65\x64\x32\x35\x35\x31\x39" /* ed25519 */
#define  XCP_EC_DSA25519_NAME_BYTES  7
// 1.3.101.113: EDDSA/448 (ed448)
#define  XCP_EC_DSA448        "\x06\x03\x2b\x65\x71"
#define  XCP_EC_DSA448_BYTES  5
#define  XCP_EC_DSA448_NAME   "\x65\x64\x34\x34\x38" /* ed448 */
#define  XCP_EC_DSA448_NAME_BYTES  5

// 1.3.6.1.4.1.2.267.999.3.2 : 2B0601040102820B87670302 : bls12_381_et
#define  XCP_EC_BLS12_381_ET  "\x6\xC\x2B\x6\x1\x4\x1\x2\x82\xB\x87\x67\x3\x2"
#define  XCP_EC_BLS12_381_ET_BYTES  14

#define  XCP_EC_MAX_ID_BYTES    14   /* fits all EC names/OIDs */


/*------------------------------------*/
typedef enum {
	XCP_EC_C_NIST_P192 = 1,      /* NIST, FP curves */
	XCP_EC_C_NIST_P224 = 2,
	XCP_EC_C_NIST_P256 = 3,
	XCP_EC_C_NIST_P384 = 4,
	XCP_EC_C_NIST_P521 = 5,

	XCP_EC_C_BP160R    = 6,      /* Brainpool, FP curves      */
	XCP_EC_C_BP160T    = 7,
	XCP_EC_C_BP192R    = 8,
	XCP_EC_C_BP192T    = 9,
	XCP_EC_C_BP224R    = 10,
	XCP_EC_C_BP224T    = 11,
	XCP_EC_C_BP256R    = 12,
	XCP_EC_C_BP256T    = 13,
	XCP_EC_C_BP320R    = 14,
	XCP_EC_C_BP320T    = 15,
	XCP_EC_C_BP384R    = 16,
	XCP_EC_C_BP384T    = 17,
	XCP_EC_C_BP512R    = 18,
	XCP_EC_C_BP512T    = 19,

	XCP_EC_C_25519     = 20,     /* curve25519, FP (2^255-19) */
	XCP_EC_C_SECP256K1 = 23,     /* secp256k1, Bitcoin default curve */
	XCP_EC_C_ED448     = 24,     /* ed448 ('Goldilocks') FP(2^448-2^244+1)*/
	XCP_EC_C_448       = 25,     /* c448/x448, ECDH only */
	XCP_EC_C_ED25519   = 26,     /* ed25519, EDDSA */


	XCP_EC_C_BLS12_381 = 28,     /* pairing-friendly BLS12-381 */
	XCP_EC_C_MAX       = XCP_EC_C_BLS12_381,
	                             /* last possible value */

} XCP_ECcurve_t;


/*--------------------------------------
 * groups of EC curves, without specific OIDs
 */
typedef enum {
	XCP_EC_CG_NIST             = 1,      /* NIST, FP curves */
	XCP_EC_CG_BPOOL            = 2,      /* Brainpool, FP curves      */
	XCP_EC_CG_C25519           = 3,      /* curve25519, ed25519 */
	XCP_EC_CG_SECP256K1        = 4,      /* SECP K-curves, */
                                             /* incl. Bitcoin default */
	XCP_EC_CG_C448             = 6,      /* c448, ed448 ('Goldilocks') */
	XCP_EC_CG_PAIRING_FRIENDLY = 7,      /* pairing-friendly curves,
	                                        BLS12-381 */
	XCP_EC_CG_MAX       = XCP_EC_CG_PAIRING_FRIENDLY
} XCP_ECCurveGrp_t;


/*---  PQC algorithms  ------------------------------------------------------*/

// Dilithium related OIDs
// Round 2 Dilithium-3 (5-4)
#define XCP_PQC_DILITHIUM_R2_54  "\x6\xb\x2b\x6\x1\x4\x1\x2\x82\xb\x1\x5\x4"
#define XCP_PQC_DILITHIUM_R2_54_BYTES 13
// Round 2 Dilithium-4 (6-5)
#define XCP_PQC_DILITHIUM_R2_65  "\x6\xb\x2b\x6\x1\x4\x1\x2\x82\xb\x1\x6\x5"
#define XCP_PQC_DILITHIUM_R2_65_BYTES 13
// Round 2 Dilithium-5 (8-7)
#define XCP_PQC_DILITHIUM_R2_87  "\x6\xb\x2b\x6\x1\x4\x1\x2\x82\xb\x1\x8\x7"
#define XCP_PQC_DILITHIUM_R2_87_BYTES 13
// Round 3 Dilithium-2 (4-4)
#define XCP_PQC_DILITHIUM_R3_44      "\x6\xb\x2b\x6\x1\x4\x1\x2\x82\xb\x7\x4\x4"
#define XCP_PQC_DILITHIUM_R3_44_BYTES     13
// Round 3 Dilithium-3 (6-5)
#define XCP_PQC_DILITHIUM_R3_65      "\x6\xb\x2b\x6\x1\x4\x1\x2\x82\xb\x7\x6\x5"
#define XCP_PQC_DILITHIUM_R3_65_BYTES     13
// Round 3 Dilithium-5 (8-7)
#define XCP_PQC_DILITHIUM_R3_87      "\x6\xb\x2b\x6\x1\x4\x1\x2\x82\xb\x7\x8\x7"
#define XCP_PQC_DILITHIUM_R3_87_BYTES     13

// Round 2 Kyber 512
#define XCP_PQC_KYBER_R2_512 "\x6\x9\x2B\x6\x1\x4\x1\x2\x82\xB\x5"
#define XCP_PQC_KYBER_R2_512_BYTES 11

// Round 2 Kyber 768
#define XCP_PQC_KYBER_R2_768 "\x6\xB\x2B\x6\x1\x4\x1\x2\x82\xB\x5\x3\x3"
#define XCP_PQC_KYBER_R2_768_BYTES 13

// Round 2 Kyber 1024
#define XCP_PQC_KYBER_R2_1024 "\x6\xB\x2B\x6\x1\x4\x1\x2\x82\xB\x5\x4\x4"
#define XCP_PQC_KYBER_R2_1024_BYTES 13

// NIST Standards
typedef CK_ULONG CK_IBM_ML_DSA_PARAMETER_SET_TYPE;
#define  CKP_IBM_ML_DSA_44 ((CK_IBM_ML_DSA_PARAMETER_SET_TYPE)1)
#define  CKP_IBM_ML_DSA_65 ((CK_IBM_ML_DSA_PARAMETER_SET_TYPE)2)
#define  CKP_IBM_ML_DSA_87 ((CK_IBM_ML_DSA_PARAMETER_SET_TYPE)3)

typedef CK_ULONG CK_IBM_ML_KEM_PARAMETER_SET_TYPE;
#define  CKP_IBM_ML_KEM_512  ((CK_IBM_ML_KEM_PARAMETER_SET_TYPE)1)
#define  CKP_IBM_ML_KEM_768  ((CK_IBM_ML_KEM_PARAMETER_SET_TYPE)2)
#define  CKP_IBM_ML_KEM_1024 ((CK_IBM_ML_KEM_PARAMETER_SET_TYPE)3)

typedef CK_ULONG CK_IBM_HEDGE_TYPE;
#define CKH_IBM_HEDGE_PREFERRED        ((CK_IBM_HEDGE_TYPE)1)
#define CKH_IBM_HEDGE_REQUIRED         ((CK_IBM_HEDGE_TYPE)2)
#define CKH_IBM_DETERMINISTIC_REQUIRED ((CK_IBM_HEDGE_TYPE)3)

typedef struct CK_IBM_SIGN_ADDITIONAL_CONTEXT {
    CK_IBM_HEDGE_TYPE hedgeVariant;
    CK_BYTE_PTR pContext;
    CK_ULONG ulContextLen;
} CK_IBM_SIGN_ADDITIONAL_CONTEXT;

/*------------------------------------*/
typedef enum {
	XCP_PQC_S_DILITHIUM_R2_54      =  1,      /* Round-2 Dilithium */
	XCP_PQC_S_DILITHIUM_R2_65      =  2,
	XCP_PQC_S_DILITHIUM_R2_87      =  3,
	XCP_PQC_S_DILITHIUM_R3_44      =  4,      /* Round-3 Dilithium */
	XCP_PQC_S_DILITHIUM_R3_65      =  5,
	XCP_PQC_S_DILITHIUM_R3_87      =  6,
	XCP_PQC_S_KYBER_R2_512     =  7,      /* Round-2 Kyber */
	XCP_PQC_S_KYBER_R2_768     =  8,
	XCP_PQC_S_KYBER_R2_1024    =  9,
	XCP_PQC_S_ML_DSA_44 = 10, /* NIST Standards */
	XCP_PQC_S_ML_DSA_65 = 11,
	XCP_PQC_S_ML_DSA_87 = 12,
	XCP_PQC_S_ML_KEM_512 = 13,
	XCP_PQC_S_ML_KEM_768 = 14,
	XCP_PQC_S_ML_KEM_1024 = 15,

	XCP_PQC_MAX               = XCP_PQC_S_ML_KEM_1024,
} XCP_PQCStrength_t;


// binary encoding of function/version query
// SEQUENCE { OCTET STRING (0) }
// module responds with API version and build ID
//
#define  XCP_VERS_QUERY_REQ  0x30,0x03,0x04,0x01,0x00  /* request body */
#define  XCP_VERS_QUERY_REQ_BYTES   5

/*---  development-only test functions  ------------------------------------*/

typedef enum {
	XCP_DEV_SET_WK           = 1,   // set and activate (imprint) WK
	XCP_DEV_SET_NEXT_WK      = 2,   // set+commit next WK (+imprint)
	XCP_DEV_AES_ENCR_CYCLE   = 3,   // AES encrypt in loop
	                                // (side-channel, other measurements)
	XCP_DEV_AES_DECR_CYCLE   = 4,   // AES decrypt in loop
	XCP_DEV_DES_ENCR_CYCLE   = 5,   // 1/2/3DES, auto-selected
	XCP_DEV_DES_DECR_CYCLE   = 6,   // 1/2/3DES, auto-selected
	XCP_DEV_ZEROIZE_CARD     = 7,
	XCP_DEV_ZEROIZE_DOMAIN   = 8,
	XCP_DEV_SET_DOMAIN_CPS   = 9,   // import full set of CPs
	XCP_DEV_SET_WK_RAW       = 10,  // set WK without imprinting
	XCP_DEV_COMMIT_NEXT_WK   = 11,  // finalizes next WK to current
	XCP_DEVQ_ADMINLIST       = 12,  // SKI list, without card signature
	XCP_DEVQ_DOM_ADMINLIST   = 13,  // SKI list, without card signature
	XCP_DEV_SET_NEXT_WK_RAW  = 14,  // set next WK, does not imprint
	XCP_DEV_FSMODE           = 15,  // manage access to filesystems
	XCP_DEV_ADMSIGN          = 16,  // admin-sign file in filesystem
	                                // used to pass arbitrary bad structs
	                                // for verification
	XCP_DEV_FSWRITE          = 17,  // write data to temporary file
	XCP_DEV_DSA_PQG_GEN      = 18,
	XCP_DEVQ_BLOBCONFIG      = 19,  // blob details: endianness and sizes
	XCP_DEV_RSA_X931_KEYGEN  = 20,  // ANSI x9.31 key gen. from prime seeds
	                                // returns PKCS8-encoded key, in clear
	                                // may be unsupported, depending on CSP
	                                // setup
	XCP_DEV_RNGSTATE         = 21,  // query or set backend RNG state
	XCP_DEV_RNG_SEED         = 22,  // forces immediate RNG re/seeding
	                                // recommended before exporting RNG
	                                // state, to maximize number of
	                                // matching bits after state is restored

	XCP_DEVQ_ENTROPY         = 23,  // retrieve raw TRNG output
	                                // conditioned entropy, no DRNG
	                                // processing a direct-call subset of
	                                // XCP_DEV_RNG_TRNG (does not require
	                                // background completion)
	                                // note that this call changes DRNG
	                                // setup during processing,
	                                // slowing it down
	                                // see also: XCP_DEV_RAWENTROPY

	XCP_DEVQ_PERFMODE        = 24,  // query performance/timestamp setup
	XCP_DEV_PERFMODE         = 25,  // change performance/timestamp setup

	XCP_DEV_RSA_DECR_CYCLE    = 26, // RSA, raw mod. exponentiation, looped
	XCP_DEV_RSACRT_DECR_CYCLE = 27, // RSA, private exponent, CRT, looped
	XCP_DEV_ECMUL_CYCLE       = 28, // EC scalar multiplication, looped

	XCP_DEV_PERFMARK         = 29,  // add performance-test marker
	                                // LS 4 bits included in entry

	XCP_DEVQ_PERF_LOCK       = 30,  // raw performance: un/lock cycles,
	                                // single thread
	                                // test on otherwise quiesced backend
	XCP_DEVQ_PERF_WAKE       = 31,  // raw performance: un/lock cycles,
	                                // forcing context switching
	                                // test on otherwise quiesced backend
	XCP_DEVQ_PERF_SCALE      = 32,  // raw performance: add calibrating
	                                // timestamp/syslog/etc. entries
	                                // to simplify offline scaling of
	                                // performance management

	XCP_DEV_CACHE_MODE       = 33,  // set or query module-internal cache
	                                // state and statistics
	XCP_DEVQ_CACHE_STATS     = 34,  // log cache-statistics summary
	                                // over syslog etc. (system-dependent)
	XCP_DEV_DELAY            = 35,  // NOP: delay the backend thread by
	                                // a host-influenced amount of time,
	                                // without performing other operations

	XCP_DEV_COMPRESS         = 36,  // return 'summarized' version of any
	                                // supplied data
	XCP_DEV_XOR_FF           = 37,  // returns a copy of data, all bits
	                                // flipped (XORed with 0xff)
	XCP_DEV_PRF              = 38,  // returns PRF stream from caller-
	                                // provided seed and bytecount

	XCP_DEV_TRANSPORTSTATE1  = 39,  // transport-statistics dump
	                                // (system-dependent functionality)

	XCP_DEVQ_CACHEINDEX      = 40,  // return module-internal blob index
	                                // of caller-provided key
	XCP_DEVQ_CSP_OBJCOUNT    = 41,  // CSP-object reference counter,
	                                // if available

	XCP_DEV_CSPTYPE          = 42,  // preferred CSP-object (engine) type

	XCP_DEV_FCV              = 43,  // query and/or set current FCV
	                                // without signature verification
	XCP_DEV_CLEAR_FCV        = 44,  // erase any existing FCV

	XCP_DEVQ_ASSERTIONS      = 45,  // verify the consistency of module-
	                                // internal data structures, as a
	                                // stronger form of assertion-checking

	XCP_DEV_TEST_LATESTART   = 46,  // perform any initial test which has
	                                // been skipped during backend startup.
	                                // not necessary unless running against
	                                // the most aggressive SYS_TEST_0START
	                                // settings [which trim down backend
	                                // testing to a bare minimum]. Safe to
	                                // issue, a NOP otherwise.

	XCP_DEV_ENVSEED          = 47,  // seed backend with device-unique,
	                                // environment-derived, low quality
	                                // entropy [augments/replaces real
	                                // entropy seeding; added to let
	                                // unrelated backends diverge even
	                                // when VM-hosted or otherwise lacking
	                                // proper initial entropy]

	XCP_DEVQ_RAWENTROPY      = 48,  // retrieve raw entropy pool, before
	                                // compression, if backend supports
	                                // this (see Clic docs for raw-pool
	                                // state details)
	                                //
	                                // see also: XCP_DEV_ENTROPY

	XCP_DEV_EC_SIGVER_CYCLE  = 49,  // EC sign/verify in loop
	                                // operation derived from supplied blob
	                                // (EC private/SPKI)
	                                // see also: XCP_DEV_ECMUL_CYCLE

	XCP_DEV_DRAIN_ENTROPY    = 50,  // TRNG: force at least one collect
	                                // entropy->compression call
	                                // [may be more, depends on DRNG state]

	XCP_DEV_CONV_EC_BLOB     = 51,  // CLiC blob conversion: Convert a
	                                // software Blob to a 4767 hardware blob
	                                // At the moment only EC blobs are
	                                // supported

	XCP_DEVQ_COUNTERS        = 52,  // retrieve coverage counters
	                                // these are intentionally not published

	XCP_DEV_RSACRT_MSG_CYCLE = 53,  // RSA, private exponent, CRT, looped
	                                // this variant increments message
	                                // and returns per-message statistics

	XCP_DEV_AUDIT_CYCLE      = 54,  // audit-log, generate log entries
	                                // in a loop

	XCP_DEV_EDDSA            = 55,  // EC dig.signature forms

	XCP_DEV_ECDH             = 56,  // EC Diffie-Hellman/Montgomery forms

	XCP_DEV_PQC_DILITHIUM    = 57,  // post-quantum algs: generic call
	                                // for Dilithium (from PQ Crystals)

	XCP_DEV_ABORT            = 63,	// raise abort signal
	XCP_DEV_DRNG             = 64,  // gen non-randomly-seeded DRNG bytes
	XCP_DEV_DRNG_RESEED      = 65,  // explicitly set DRNG seed
	XCP_DEV_FAULT_INJECT     = 66,  // control fault point injection
	XCP_DEVQ_FAULTLIST       = 67,  // list available fault points
	XCP_DEV_FLIP_ERRORSTATE  = 68,  // explicitly flip the setting of the
	                                // error state of the module
	XCP_DEV_AESKW            = 69,
	XCP_DEV_KDF_SP108        = 70,  // NIST SP800-108 KDF
	XCP_DEV_KDF_SP56C        = 71,  // NIST SP800-56C ECDH+KDF(ECIES)
	XCP_DEV_UNIT_TEST        = 72,  // run unit tests on module


	XCP_DEV_MAX_INDEX        = XCP_DEV_UNIT_TEST
} XCP_DEVcmd_t;
//
// upper limit on additional data bytes, for SYS-TEST commands with aux. data
// (arbitrary limit, commands may restict further)
#define  XCP_DEV_MAX_DATABYTES   ((size_t) 64000)
//
// iteration-count limit applies to any iterative call
// driver[timeout] may interfere; dev-only feature is not otherwise restricted
#define  XCP_DEV_MAX_ITERATIONS  ((unsigned int) 128*1024)

#define XCP_DEV_C25519               (unsigned int)255
#define XCP_DEV_C448                 (unsigned int)448
#define XCP_DEV_ED25519            ~((unsigned int)255)
#define XCP_DEV_ED448              ~((unsigned int)448)
#define XCP_DEV_ED25519_2          ~((unsigned int)256)
#define XCP_DEV_ED448_2            ~((unsigned int)456)

#define XCP_DEV_AESKW_WRAP        (unsigned int)1
#define XCP_DEV_AESKW_UNWRAP      (unsigned int)2
#define XCP_DEV_AESKW_WRAP_PAD    (unsigned int)3
#define XCP_DEV_AESKW_UNWRAP_PAD  (unsigned int)4

typedef enum {
	XCP_DEVC_CACHE_ACTIVE     = 1,   // blob-cache is available
	XCP_DEVC_CACHE_INACTIVE   = 2,   // caching suspended: lookups fail,
	                                 // new entries are not accepted
	XCP_DEVC_CACHE_FLUSH      = 4,   // evict all currently cached objects
	                                 // available even if cache is suspended
} XCP_DEVcache_t;

typedef enum {
	XCP_DEV_RNG_TRNG         = 0,   // no DRNG involvement
	XCP_DEV_RNG_DRNG         = 1,   // DRNG, no reseeding
	XCP_DEV_RNG_MIXED        = 2,   // DRNG, with TRNG reseeding
	XCP_DEV_RNG_SWDRNG       = 4,   // Software-DRNG
	XCP_DEV_RNG_TYPE_MAX     = XCP_DEV_RNG_SWDRNG
} XCP_DEVrng_t;

typedef enum {
	XCP_DEVFS_QUERY          = 0,   // current state query only
	XCP_DEVFS_READONLY       = 1,   // prevent writes
	XCP_DEVFS_NOACCESS       = 2    // prevent all filesystem access
} XCP_DEVfs_t;

// size of coverage counters
#define  XCP_DEV_CTR_SIZE  4
#define  XCP_DEV_CTR_TYPE  uint32_t

typedef enum {
	XCP_DEV_FAULT_EXPR   = 1,       // evaluate to non-null if triggered
	XCP_DEV_FAULT_FUNC   = 2,       // call callback function
	XCP_DEV_FAULT_MSLEEP = 4,       // sleep for msleep ms
	XCP_DEV_FAULT_RV     = 8,       // faultpoint returns rv
	XCP_DEV_FAULT_DBIT   = 16,      // flip bit at compile-time const offset
	XCP_DEV_FAULT_DNULL  = 32,      // faultpoint memsets data to zero
	XCP_DEV_FAULT_RBIT   = 64,      // flip bit at random offset
} XCP_DEVfault_t;

// no vendor extension definition for CKG available yet
#if !defined(CKG_VENDOR_DEFINED)
#define  CKG_VENDOR_DEFINED            0x80000000UL
#endif

#define  CKG_IBM_MGF1_SHA3_224         (CKG_VENDOR_DEFINED +1)
#define  CKG_IBM_MGF1_SHA3_256         (CKG_VENDOR_DEFINED +2)
#define  CKG_IBM_MGF1_SHA3_384         (CKG_VENDOR_DEFINED +3)
#define  CKG_IBM_MGF1_SHA3_512         (CKG_VENDOR_DEFINED +4)

#if !defined(CKD_VENDOR_DEFINED)
#define  CKD_VENDOR_DEFINED            0x80000000UL
#endif

#define  CKD_IBM_HYBRID_NULL           (CKD_VENDOR_DEFINED + 0x00000001UL)
#define  CKD_IBM_HYBRID_SHA1_KDF       (CKD_VENDOR_DEFINED + 0x00000002UL)
#define  CKD_IBM_HYBRID_SHA224_KDF     (CKD_VENDOR_DEFINED + 0x00000003UL)
#define  CKD_IBM_HYBRID_SHA256_KDF     (CKD_VENDOR_DEFINED + 0x00000004UL)
#define  CKD_IBM_HYBRID_SHA384_KDF     (CKD_VENDOR_DEFINED + 0x00000005UL)
#define  CKD_IBM_HYBRID_SHA512_KDF     (CKD_VENDOR_DEFINED + 0x00000006UL)

#define  XCP_MODEL_CEX4P               4
#define  XCP_MODEL_CEX5P               5
#define  XCP_MODEL_CEX6P               6
#define  XCP_MODEL_CEX7P               7
#define  XCP_MODEL_CEX8P               8

/*--------------------------------------------------------------------------*/
// max value for target groups
#define XCP_MAX_GRPIDX 1024u

//
// macros for setting/checking and removing domains from (tgt.mgmt) domain mask
#define XCPTGTMASK_SET_DOM(mask, domain)      \
                           ((mask)[((domain)/8)] |=   (1 << (7-(domain)%8)))
#define XCPTGTMASK_DOM_IS_SET(mask, domain)   \
                           ((mask)[((domain)/8)] &   (1 << (7-(domain)%8)))
#define XCPTGTMASK_CLR_DOM(mask, domain)      \
                           ((mask)[((domain)/8)] &=  ~(1 << (7-(domain)%8)))


/* flags that can be set for the target tokens
 *
 * This flags are domain specific and are therefore called domain flags
 *
 * start of flags is >16 Bit. Max value for domains is 0xFF. Should be enough
 * room for extensions
 */
#define XCP_TGTFL_WCAP     0x10000000  /* Capture wire request in output buffer
                                        * without sending it to the module
                                        */
#define XCP_TGTFL_WCAP_SQ  0x20000000  /* Size query: Return size of request in
                                        * output buffer length field
                                        */
#define XCP_TGTFL_SET_SCMD 0x40000000  /* Protected key special command: Set the
                                        * special command flag in the CPRB
                                        * header
                                        */
#define XCP_TGTFL_API_CHKD 0x80000000  /* supported API version of modules in
                                        * target (group) has been checked
                                        */

#define XCP_TGTFL_NO_LOCK  0x01000000  /* target token ignores sequential locks
                                        * for target probing
                                        */
#define XCP_TGTFL_CHK_ATTR 0x02000000  /* reject unknown attribute in attribute
                                        * templates with
                                        * CKR_TEMPLATE_INCONSISTENT. Default is
                                        * to ignore unknown attributes.
                                        */
#define XCP_TGTFL_SET_ACMD 0x04000000  /* add CPRB admin flag to CPRB header */

#define XCP_TGTFL_NO_SPLIT 0x08000000  /* enforce single-shot requests */

//--------------------------------------
// socket use only
#define  XCP_MAXCONNECTIONS 256      /* max value for active connections */
#define  XCP_MAX_PORT     0xffff

// hostname and port value fore one module
typedef struct XCP_ModuleSocket {
	char host[ MAX_FNAME_CHARS +1 ];
	uint32_t port;
} *XCP_ModuleSocket_t ;


//--------------------------------------
// diagnostics use only
typedef struct XCP_DomainPerf {
	/* perf value of last request per domain
	 *
	 * At the moment unused
	 * */
	unsigned int lastperf[ 256 ];
} *XCP_DomainPerf_t;


// current version of XCP_Module structure; host code SHOULD interact with
// future/past versions, MUST be set by caller before using m_add_module()
// valid versions are all >0
#define  XCP_MOD_VERSION  2
//--------------------------------------
// subsequent communications with a module MAY skip infrastructure-specific
// fields, such as a query not reporting device handles etc., even if they
// have been supplied originally when the module has been registered.
//
typedef struct XCP_Module {
	uint32_t version;     /* >0 for supported API versions */

	uint64_t flags;       /* see XCP_Module_Flags */

	uint32_t domains;     /* max# addressable under this module;
	                       * cached from OS
	                       *
	                       * when callers set domains  to 0, the library
	                       * returns the module-claimed domain count.
	                       */

	unsigned char domainmask[ 256 /8 ];
	                      /* higher domain# through future flags (none
	                       * currently defined) which would add things
	                       * like 'FLAG_256_1023' etc. at the same time,
	                       * we would add domainmask2[] etc.
	                       * corresponding new fields.
	                       *
	                       * new fields would then store mask for
	                       * domains 256+ etc.
	                       *
	                       * domain #0 is bit x80 of 1st byte,
	                       * #255 is bit 0x01 of last byte.
	                       */

		// when a domainmask is supplied, with bits set beyond
		// what the module supports, the bitmask is trimmed to
		// the supported range, but this is NOT reported as an
		// error, unless XCP_MFL_STRICT is also supplied.
		//
		// without XCP_MFL_STRICT, callers are expected to check
		// at least the returned domain count.

			/* used only when flags includes XCP_MFL_SOCKET */
	struct XCP_ModuleSocket socket;

			/* used when system exposes modules through an
			 * array of transparent pipes, or similar abstraction
			 * (such as mainframe AP Queues, or other Linux
			 * 'device-minor' numbers etc.). Interpretation
			 * is platform-dependent.
			 *
			 * used only when flags includes XCP_MFL_MODULE
			 */
	uint32_t module_nr;

			/* used by systems which associate devices with
			 * device handles/structs/etc. persistent state.
			 * opaque pointer, usually a const pointer to
			 * such aux structs, MAY be stored here.
			 *
			 * interpretation is platform-dependent.
			 * used only when flags includes XCP_MFL_MHANDLE
			 */
	void *mhandle;
			/* diagnostics use only, when XCP_MFL_PERF is set */
	struct XCP_DomainPerf perf;
	//-----  end of v1 fields  -------------------------------------------

	uint32_t api; /* module api version*/
	//-----  end of v2 fields  -------------------------------------------
} *XCP_Module_t ;

typedef enum {
	XCP_MFL_SOCKET       =    1,  /* backend is socket-attached */
	XCP_MFL_MODULE       =    2,  /* backends identified in
	                                 array-of-modules */
	XCP_MFL_MHANDLE      =    4,  /* backends uses 'module handle' field */
	XCP_MFL_PERF         =    8,  /* performance statistics collected
	                               * for this module, see .perf
	                               */
	XCP_MFL_VIRTUAL      = 0x10,  /* queried 'target' is a load-balancer,
	                               * other other group.
	                               */
	XCP_MFL_STRICT       = 0x20,  /* enable aggressive error checking,
	                               * see field descriptions for effect
	                               */
	XCP_MFL_PROBE        = 0x40,  /* send api query to module, to check if
	                               * target(s) can be used
	                               */
	XCP_MFL_ALW_TGT_ADD  = 0x80,  /* Allows it to use a target in any
	                               * functional and admin call without
	                               * adding it beforehand with
	                               * m_add_module()
	                               */
	XCP_MFL_MAX          = 0xff
} XCP_Module_Flags;

typedef uint64_t target_t;

#define XCP_TGT_INIT ~0UL

#define XCP_TGT_FMT "x%016" PRIx64

int m_add_module(XCP_Module_t module, target_t *target) ;

int m_rm_module(XCP_Module_t module, target_t target) ;

CK_RV m_admin (unsigned char *response1, size_t *r1len,
               unsigned char *response2, size_t *r2len,
         const unsigned char *cmd,       size_t clen,
         const unsigned char *sigs,      size_t slen,
                         target_t target) ;

/*----------------------------------------------------------------------
 *  CK_... type arguments correspond to the original PKCS#11 call's
 *  arguments.  Standard types mean PKCS#11 objects (session, token etc.)
 *  are mapped to a native type (key blob, mechanism) etc.
 *
 *  As an example, for _Encrypt and _Decrypt, a session is passed to
 *  the PKCS#11 function.  This session needs to be matched to a key blob,
 *  so our _Encrypt interface takes a key/keylen buffer instead of the
 *  session.  All other parameters should be passed through unchanged.
 *
 *  For certain operations, such as _GenerateKey, there are no real
 *  PKCS#11 type parameters at this level.
 */


CK_RV m_Login ( CK_UTF8CHAR_PTR pin,      CK_ULONG pinlen,
            const unsigned char *nonce,     size_t nlen,
                  unsigned char *pinblob,   size_t *pinbloblen,
                       target_t target) ;
CK_RV m_Logout ( const unsigned char *pin, size_t len,     target_t target) ;

CK_RV m_LoginExtended( CK_UTF8CHAR_PTR pin,    CK_ULONG pinlen,
                   const unsigned char *nonce,   size_t nlen,
                   const unsigned char *xstruct, size_t xslen,
                         unsigned char *pinblob, size_t *pinbloblen,
                              target_t target) ;

CK_RV m_LogoutExtended( CK_UTF8CHAR_PTR pin,    CK_ULONG pinlen,
                    const unsigned char *nonce,   size_t nlen,
                    const unsigned char *xstruct, size_t xslen,
                               target_t target) ;

int xcpu_LoginRecipient (uint8_t *result,    size_t *rlen,
                      uint32_t version,
                 const uint8_t *rcpt_ski,  size_t rslen,
                 const uint8_t *send_spki, size_t slen);

CK_RV m_GenerateRandom   (CK_BYTE_PTR rnd, CK_ULONG len,     target_t target) ;
/**/
/* note: external seeding not supported */
CK_RV m_SeedRandom (CK_BYTE_PTR pSeed,   CK_ULONG ulSeedLen,
                       target_t target) ;

CK_RV m_DigestInit     (unsigned char *state,     size_t *len,
               const CK_MECHANISM_PTR pmech,
                             target_t target) ;
/**/
CK_RV m_Digest (const unsigned char *state,       size_t slen,
                        CK_BYTE_PTR data,       CK_ULONG len,
                        CK_BYTE_PTR digest, CK_ULONG_PTR dglen,
                           target_t target) ;
CK_RV m_DigestUpdate (unsigned char *state,       size_t slen,
                        CK_BYTE_PTR data,       CK_ULONG dlen,
                           target_t target) ;
CK_RV m_DigestKey    (unsigned char *state,       size_t slen,
                const unsigned char *key,         size_t klen,
                           target_t target) ;
CK_RV m_DigestFinal  (const unsigned char *state,       size_t slen,
                              CK_BYTE_PTR digest, CK_ULONG_PTR dlen,
                                 target_t target) ;
CK_RV m_DigestSingle (CK_MECHANISM_PTR pmech,
                           CK_BYTE_PTR data,       CK_ULONG len,
                           CK_BYTE_PTR digest, CK_ULONG_PTR dlen,
                              target_t target) ;

CK_RV m_GenerateKey (CK_MECHANISM_PTR pmech,
                     CK_ATTRIBUTE_PTR ptempl, CK_ULONG templcount,
                  const unsigned char *pin,     size_t pinlen,
                        unsigned char *key,     size_t *klen,
                        unsigned char *csum,    size_t *clen,
                             target_t target) ;
/**/
CK_RV m_GenerateKeyPair (CK_MECHANISM_PTR pmech,
                         CK_ATTRIBUTE_PTR ppublic,  CK_ULONG pubattrs,
                         CK_ATTRIBUTE_PTR pprivate, CK_ULONG prvattrs,
                      const unsigned char *pin,       size_t pinlen,
                            unsigned char *key,       size_t *klen,
                            unsigned char *pubkey,    size_t *pklen,
                                 target_t target) ;

/* mackey is NULL for PKCS#11 formats, not for authenticated ones */
CK_RV m_WrapKey (const unsigned char *key,          size_t keylen,
                 const unsigned char *kek,          size_t keklen,
                 const unsigned char *mackey,       size_t mklen,
              const CK_MECHANISM_PTR pmech,
                         CK_BYTE_PTR wrapped, CK_ULONG_PTR wlen,
                            target_t target) ;
/**/
/* mackey is NULL for PKCS#11 formats, not for authenticated ones */
CK_RV m_UnwrapKey (const   CK_BYTE_PTR wrapped,  CK_ULONG wlen,
                   const unsigned char *kek,       size_t keklen,
                   const unsigned char *mackey,    size_t mklen,
                   const unsigned char *pin,       size_t pinlen,
                const CK_MECHANISM_PTR uwmech,
                const CK_ATTRIBUTE_PTR ptempl,   CK_ULONG pcount,
                         unsigned char *unwrapped, size_t *uwlen,
                           CK_BYTE_PTR csum,     CK_ULONG *cslen,
                              target_t target) ;

CK_RV m_DeriveKey ( CK_MECHANISM_PTR pderivemech,
                    CK_ATTRIBUTE_PTR ptempl, CK_ULONG templcount,
                 const unsigned char *basekey, size_t bklen,
                 const unsigned char *data,    size_t dlen,
                 const unsigned char *pin,     size_t pinlen,
                       unsigned char *newkey,  size_t *nklen,
                       unsigned char *csum,    size_t *cslen,
                       target_t target) ;

CK_RV m_GetAttributeValue (const unsigned char *obj,        size_t olen,
                              CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                      target_t target) ;
CK_RV m_SetAttributeValue       (unsigned char *obj,        size_t olen,
                              CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                      target_t target) ;

/**/
CK_RV m_GetMechanismList (CK_SLOT_ID slot,
               CK_MECHANISM_TYPE_PTR mechs,
                        CK_ULONG_PTR count,
                            target_t target) ;
CK_RV m_GetMechanismInfo (CK_SLOT_ID slot,
                   CK_MECHANISM_TYPE mech,
               CK_MECHANISM_INFO_PTR pmechinfo,
                            target_t target) ;

CK_RV m_get_xcp_info (CK_VOID_PTR pinfo, CK_ULONG_PTR infbytes,
                     unsigned int query,
                     unsigned int subquery,
                         target_t target) ;

// see also: CK_IBM_XCPQUERY_t

CK_RV m_EncryptInit        (unsigned char *state, size_t *slen,
                         CK_MECHANISM_PTR pmech,
                      const unsigned char *key,   size_t klen,
                                 target_t target) ;
CK_RV m_DecryptInit        (unsigned char *state, size_t *slen,
                         CK_MECHANISM_PTR pmech,
                      const unsigned char *key,   size_t klen,
                                 target_t target) ;
/**/
CK_RV m_EncryptUpdate      (unsigned char *state,       size_t slen,
                              CK_BYTE_PTR plain,      CK_ULONG plen,
                              CK_BYTE_PTR cipher, CK_ULONG_PTR clen,
                                 target_t target) ;
CK_RV m_DecryptUpdate      (unsigned char *state,       size_t slen,
                              CK_BYTE_PTR cipher,     CK_ULONG clen,
                              CK_BYTE_PTR plain,  CK_ULONG_PTR plen,
                                 target_t target) ;
/**/
/* one-pass en/decrypt with key blob */
CK_RV m_Encrypt       (const unsigned char *state,       size_t slen,
                               CK_BYTE_PTR plain,      CK_ULONG plen,
                               CK_BYTE_PTR cipher, CK_ULONG_PTR clen,
                                  target_t target) ;
CK_RV m_Decrypt       (const unsigned char *state,       size_t slen,
                               CK_BYTE_PTR cipher,     CK_ULONG clen,
                               CK_BYTE_PTR plain,  CK_ULONG_PTR plen,
                                  target_t target) ;
/**/
CK_RV m_EncryptFinal  (const unsigned char *state,       size_t slen,
                               CK_BYTE_PTR output, CK_ULONG_PTR len,
                                  target_t target) ;
CK_RV m_DecryptFinal  (const unsigned char *state,       size_t slen,
                               CK_BYTE_PTR output, CK_ULONG_PTR len,
                                  target_t target) ;
/**/
/* en/decrypt directly with key blob */
CK_RV m_EncryptSingle (const unsigned char *key,         size_t klen,
                          CK_MECHANISM_PTR mech,
                               CK_BYTE_PTR plain,      CK_ULONG plen,
                               CK_BYTE_PTR cipher, CK_ULONG_PTR clen,
                                  target_t target) ;
CK_RV m_DecryptSingle (const unsigned char *key,         size_t klen,
                          CK_MECHANISM_PTR mech,
                               CK_BYTE_PTR cipher,     CK_ULONG clen,
                               CK_BYTE_PTR plain,  CK_ULONG_PTR plen,
                                  target_t target) ;
/**/
/* de+encrypt in one pass, without exposing cleartext */
CK_RV m_ReencryptSingle (const unsigned char *dkey,     size_t dklen,
                         const unsigned char *ekey,     size_t eklen,
                         CK_MECHANISM_PTR pdecrmech,
                         CK_MECHANISM_PTR pencrmech,
                              CK_BYTE_PTR in,       CK_ULONG ilen,
                              CK_BYTE_PTR out,  CK_ULONG_PTR olen,
                                 target_t target) ;

CK_RV m_SignInit     (unsigned char *state,     size_t *slen,
                   CK_MECHANISM_PTR alg,
                const unsigned char *key,       size_t klen,
                           target_t target) ;
CK_RV m_VerifyInit   (unsigned char *state,     size_t *slen,
                   CK_MECHANISM_PTR alg,
                const unsigned char *key,       size_t klen,
                           target_t target) ;
/**/
CK_RV m_SignUpdate   (unsigned char *state,     size_t slen,
                        CK_BYTE_PTR data,     CK_ULONG dlen,
                           target_t target) ;
CK_RV m_VerifyUpdate (unsigned char *state,     size_t slen,
                        CK_BYTE_PTR data,     CK_ULONG dlen,
                           target_t target) ;
/**/
CK_RV m_SignFinal    (const unsigned char *state,      size_t stlen,
                              CK_BYTE_PTR sig,   CK_ULONG_PTR siglen,
                                 target_t target) ;
CK_RV m_VerifyFinal  (const unsigned char *state,      size_t stlen,
                              CK_BYTE_PTR sig,       CK_ULONG siglen,
                                 target_t target) ;
/**/
CK_RV m_Sign   (const unsigned char *state,     size_t stlen,
                        CK_BYTE_PTR data,     CK_ULONG dlen,
                        CK_BYTE_PTR sig,  CK_ULONG_PTR siglen,
                           target_t target) ;
CK_RV m_Verify (const unsigned char *state,     size_t stlen,
                        CK_BYTE_PTR data,     CK_ULONG dlen,
                        CK_BYTE_PTR sig,      CK_ULONG siglen,
                           target_t target) ;
/**/
CK_RV m_SignSingle   (const unsigned char *key,      size_t klen,
                         CK_MECHANISM_PTR pmech,
                              CK_BYTE_PTR data,    CK_ULONG dlen,
                              CK_BYTE_PTR sig, CK_ULONG_PTR slen,
                                 target_t target) ;
CK_RV m_VerifySingle (const unsigned char *key,      size_t klen,
                         CK_MECHANISM_PTR pmech,
                              CK_BYTE_PTR data,    CK_ULONG dlen,
                              CK_BYTE_PTR sig,     CK_ULONG slen,
                                 target_t target) ;

// m_wire() by default removes transport headers of responses (CPRB header etc.)
// setting to prevent stripping:
//
#define XCP_CHN_RETURN_RAW         1  /* return raw wire response, w/headers */
#define XCP_CHN_HIGH_PRIORITY      2  /* please note: Not all backends       */
#define XCP_CHN_MEDIUM_PRIORITY    4  /* support channel priority mgmt       */
#define XCP_CHN_NODEV_LOG_SKIP     8  /* do not log if no device is found    */
#define XCP_CHN_PARSE_IRV       0x10

/*--------------------------------------------------------------------------
 *  direct interface without wire formatting & parsing.
 */
CK_RV m_wire (unsigned char *rsp, size_t *rsplen, CK_RV *irv,
        const unsigned char *req, size_t reqlen,
               unsigned int flags,
                   target_t target) ;

// options allowed within flags
#define  XCP_W_NO_SEND_CPRB  1      /* data already includes request header */
#define  XCP_W_NO_RECV_CPRB  2      /* leave transport header in response   */

// initializes the library
int m_init(void);
// shutting down the library
int m_shutdown(void);



/*--  build identification  ------------------------------------------------*/

#define  XCP_BUILD_ID    0x3942f3bb
#define  XCP_BUILD_DATE  0x20250923       /* UTC */
#define  XCP_BUILD_TIME  0x083816         /* UTC */

/*--------------------------------------------------------------------------*/
#define __XCP_REASONCODES_H__ 1


typedef enum {
	XCP_RSC_NO_IMPORTER = 1,  /* targeted domain has no importer private key */
	XCP_RSC_NO_KEYPARTS = 2,  /* import WK request without keypart SEQUENCEs */
	XCP_RSC_IMPR_CMDBLK_BER = 3,  /* embedded keyparts' BER envelope invalid */
	XCP_RSC_IMPR_CMDBLK_FIELDS = 4,  /* command block BER structure (field count) invalid */
	XCP_RSC_IMPR_CMDBLK_FIELDCOUNT = 5,  /* command block field count invalid */
	XCP_RSC_IMPR_EMBEDDED_FN = 6,  /* embedded admin request (external) with invalid/non-m_admin() function identifier */
	XCP_RSC_IMPR_DOMAIN_DIFF = 7,  /* internal block (within import WK) with different targeted domain */
	XCP_RSC_IMPR_NO_INT_CMDBLK = 8,  /* import internal keypart SEQUENCE without command block */
	XCP_RSC_IMPR_NO_INT_SIGNATURE = 9,  /* import internal keypart SEQUENCE without signature */
	XCP_RSC_IMPR_BAD_CMDBLK_BER = 10,  /* import internal keypart SEQUENCE without signature */
	XCP_RSC_CMD_EMBEDDED_FN = 11,  /* admin command block with invalid function identifier */
	XCP_RSC_CMD_DOMAIN_RANGE = 12,  /* requested domain index is out of range */
	XCP_RSC_DOMAIN_INST_FMT = 13,  /* domain instance malformed, or non-zero for card service */
	XCP_RSC_DOMAIN_INST_MISMATCH = 14,  /* domain instance does not match that of domain */
	XCP_RSC_MODULE_INST_FMT = 15,  /* module serialnumber/instance malformed */
	XCP_RSC_MODULE_INST_MISMATCH = 16,  /* module instance does not match that of domain */
	XCP_RSC_MODULE_SERNO_MISMATCH = 17,  /* module serial number does not match that of module */
	XCP_RSC_TCTR_FMT = 18,  /* transaction counter malformed (for this service) */
	XCP_RSC_TCTR_VALUE = 19,  /* transaction counter value invalid (already passed) */
	XCP_RSC_DOMAIN_INST_DIFF = 20,  /* internal block domain instance (within import WK) differs from external one */
	XCP_RSC_SIGS_INSUFFICIENT = 21,  /* not enough signatures for requested admin service */
	XCP_RSC_SIGS_REJECTED = 22,  /* at least one signature has been rejected */
	XCP_RSC_RCPTINFO_FMT = 23,  /* recipientInfo SEQUENCE malformed */
	XCP_RSC_RCPTINFO_ENCRD_SIZE = 24,  /* encrypted keypart size invalid */
	XCP_RSC_RCPTINFO_ECDH_SRC = 25,  /* ECDH failed (possibly invalid originator point) */
	XCP_RSC_RCPTINFO_KDF_SHARED = 26,  /* ECDH sharedinfo parameters are invalid */
	XCP_RSC_RCPTINFO_KDF = 27,  /* ECDH key derivation failed */
	XCP_RSC_RCPTINFO_KEY_SIZE = 28,  /* derived/recovered key size invalid */
	XCP_RSC_RCPTINFO_KEY_MIXMODE = 29,  /* standalone and full-key keyparts mixed (keyparts both with and without full-key VP) */
	XCP_RSC_RCPTINFO_KEY_VPS_DIFF = 30,  /* keypart full-key VPs are not identical */
	XCP_RSC_RCPTINFO_KEY_VPS_MISMATCH = 31,  /* reassembled key VP differs from those within keyparts */
	XCP_RSC_SKI_MALFORMED = 32,  /* admin key SKI bytecount is invalid */
	XCP_RSC_SKI_NOT_FOUND = 33,  /* admin key SKI bytecount is not present */
	XCP_RSC_MODE_IMPRINT = 34,  /* service not available in imprint mode */
	XCP_RSC_MODE_NONIMPRINT = 35,  /* service not available when no longer in imprint mode */
	XCP_RSC_IMPRINT_EXIT_INVD = 36,  /* attempt to leave imprint mode is not permitted */
	XCP_RSC_CP_MODE_SET = 37,  /* activating one or more CP bits is not allowed (operational mode) */
	XCP_RSC_SKI_FOUND = 38,  /* SKI is already registered, may not be repeatedly logged in */
	XCP_RSC_ADMINLIST_FULL = 39,  /* no more SKIs may be registered */
	XCP_RSC_CERT_FMT = 40,  /* certificate not recognized as X.509 one */
	XCP_RSC_ATTRS_FMT = 41,  /* packed attributes' size is invalid */
	XCP_RSC_ATTRS_TYPE_INVALID = 42,  /* unsupported attribute (index) specified */
	XCP_RSC_ATTRS_REPEAT = 43,  /* attribute (index) repeats */
	XCP_RSC_CPS_FMT = 44,  /* control point set (size) invalid */
	XCP_RSC_CPS_SET_INCONSISTENT = 45,  /* specified control points are rejected */
	XCP_RSC_CPS_PREVENT_ADD = 46,  /* policy prevents enabling the specified CP bits */
	XCP_RSC_CPS_PREVENT_DEL = 47,  /* policy prevents disabling the specified CP bits */
	XCP_RSC_WK_MISMATCH = 48,  /* indicated WK (verification pattern) is malformed/does not match targeted one */
	XCP_RSC_WK_MISSING = 49,  /* service requires a WK, while none present */
	XCP_RSC_NEXT_WK_MISSING = 50,  /* service requires next-WK, while none present */
	XCP_RSC_EC_IMPORT_SYMM = 51,  /* can not use KDF-derived value as KEK */
	XCP_RSC_RANDOM_WK_PROHIBITED = 52,  /* use of random WKs and next-WKs prohibited by policy */
	XCP_RSC_WKS_PRESENT = 53,  /* presence of WK and pending WK prevents random-WK generation */
	XCP_RSC_IMPR_FIELD_SIZE = 54,  /* invalid importer type (field length) */
	XCP_RSC_IMPORTER_INVD_TYPE = 55,  /* requested importer type is unknown/unsupported */
	XCP_RSC_IMPR_REVOKE_ZERO = 56,  /* not allowed to leave imprint mode with revoke threshold of 0 */
	XCP_RSC_IMPR_TOOMANY_SIGNERS = 57,  /* attempting to set threshold to more than current signers */
	XCP_RSC_IMPR_TOOMANY_REVOKERS = 58,  /* attempting to set revoke threshold to more than current signers */
	XCP_RSC_OAIDX_FIELD_SIZE = 59,  /* invalid OA certificate index (field length) */
	XCP_RSC_OAIDX_INVALID = 60,  /* OA certificate index out of range */
	XCP_RSC_FCV_NOT_PRESENT = 61,  /* no FCV has been loaded */
	XCP_RSC_FCV_FMT = 62,  /* FCV size/structure is invalid */
	XCP_RSC_FCV_DIFFERS = 63,  /* different FCV is already present */
	XCP_RSC_COMMITTED_WK_MISSING = 64,  /* service requires a committed pending WK, which is not present */
	XCP_RSC_IMPR_EMBEDDED_FN_FMT = 65,  /* embedded admin request (external) with malformed function identifier (wrong size) */
	XCP_RSC_LOGOUT_BELOW_THRESHOLD = 66,  /* attempted logout would decrease number of admins below signature or revocation threshold */
	XCP_RSC_LOGOUT_NO_SINGLE_SIGN = 67,  /* attempted logout of second last admin but single sign not allowed */
	XCP_RSC_LOGOUT_LAST_ADMIN = 68,  /* attempted logout of last admin */
	XCP_RSC_REACTIVATE_RO_ATTRS = 69,  /* attempting to enable reset-only attribute/s */
	XCP_RSC_CHG_PROTECTED_ATTRS = 70,  /* attempting to modify change-protected attribute/s */
	XCP_RSC_CHG_PROTECTED_THRESHOLD = 71,  /* attempting to modify change-protected signing or revocation threshold */
	XCP_RSC_CHG_READONLY_ATTRS = 72,  /* attempting to modify read-only attribute/s */
	XCP_RSC_INACTIVE_CHG_ATTRS = 73,  /* attempting to modify attributes of inactive backend */
	XCP_RSC_CHG_ATTRS_PREVENTED = 74,  /* attempting to modify attributes prevented by other setting */
	XCP_RSC_IMPR_MANY_KEYPARTS = 75,  /* too many keyparts are present */
	XCP_RSC_LOWERING_SIGNERS_TO_ZERO = 76,  /* lowering sign threshold to zero */
	XCP_RSC_LOWERING_REVOKERS_TO_ZERO = 77,  /* lowering revoke threshold to zero */
	XCP_RSC_CHG_SIGNERS_TO_ONE_NO_1SIGN = 78,  /* changing sign threshold to one but XCP_ADMP_1SIGN is not set */
	XCP_RSC_CHG_REVOKERS_TO_ONE_NO_1SIGN = 79,  /* changing revoke threshold to one but XCP_ADMP_1SIGN is not set */
	XCP_RSC_IMPORT_WK_PROHIBITED = 80,  /* import of WKs prohibited by policy */
	XCP_RSC_IMPR_SINGLE_KEYPART = 81,  /* import attempted with single keypart, prohibited by policy */
	XCP_RSC_IMPR_CSP = 82,  /* crypto operation failed during imported WK administration (should not happen) */
	XCP_RSC_QUERY_DMASK_VERSION = 83,  /* unsupported domain-mask version */
	XCP_RSC_QUERY_DMASK_FMT = 84,  /* domain-mask field format invalid */
	XCP_RSC_LEAVE_DOM_IMPR_CARD_STILL = 85,  /* attempting to leave domain imprint mode but card is still in imprint mode */
	XCP_RSC_BLOB_REENCRYPT_REJECT = 86,  /* blob to re-encrypt is rejected */
	XCP_RSC_TOO_MANY_SIGNERINFOS = 87,  /* too many signerinfos present */
	XCP_RSC_NO_GLOBAL_CONTEXT = 88,  /* no initialized global context */
	XCP_RSC_ATTRS_TOO_MANY = 89,  /* too many attributes (index too high) */
	XCP_RSC_CP_SET_INVALID = 90,  /* CP set invalid */
	XCP_RSC_RK_IDLEN_INVALID = 91,  /* retained-key ID size not supported */
	XCP_RSC_RK_ID_INVALID = 92,  /* retained-key ID not present */
	XCP_RSC_FILEID_UNKNOWN = 93,  /* file identifier is beyond those recognized by the backend */
	XCP_RSC_FILEID_UNSUPPORTED = 94,  /* recognized, conditionally present file ID is not supported by this backend */
	XCP_RSC_CPS_REJECTED_FCV = 95,  /* requested set of control points conflicts with installed FCV */
	XCP_RSC_EXPR_KEYPART_LIMIT = 96,  /* requested limit and KPH count inconsistent */
	XCP_RSC_EXPR_KEYPART_ZEROLIMIT = 97,  /* requested nonzero KP reconstruction limit */
	XCP_RSC_EXPR_KEYPART_DIFF_LIMIT = 98,  /* export: multiple, different KP reconstruction limits specified */
	XCP_RSC_EXPR_KEYPART_DIFF_COUNT = 99,  /* export: conflicting keypart counts specified */
	XCP_RSC_EXPR_DOMMASK_DIFF = 100,  /* export: conflicting domain masks specified */
	XCP_RSC_EXPR_INDEX_INVALID = 101,  /* export: supplied keypart index repeats or is out of range */
	XCP_RSC_EXPR_CERT_INVALID = 102,  /* export: supplied KPH certificate is not recognized/unsupported */
	XCP_RSC_IMPR_STATE_STRUCT = 103,  /* import: state file missing, bytecount out of range, or file structure invalid */
	XCP_RSC_EXPR_AUTHCERT_INVALID = 104,  /* export: supplied MCA certificate is not recognized/unsupported */
	XCP_RSC_IMPR_KEYPARTS_STRUCT = 105,  /* import: keyparts missing, bytecount out of range, or file structure invalid */
	XCP_RSC_IMPR_STATE_REPEAT = 106,  /* import: sections repeat with incompatible instances */
	XCP_RSC_IMPR_ENCR_ALG = 107,  /* import: unsupported encryption algorithm or malformed auxiliary data */
	XCP_RSC_IMPR_FILESIG_INFRASTRUCTURE = 108,  /* import: sections related to file-signature are missing, malformed or invalid */
	XCP_RSC_IMPR_FILESIG = 109,  /* import: signature of the file is invalid (infrastructure has been verified) */
	XCP_RSC_EXPR_SINGLE_KEYPART = 110,  /* export attempted with 1-of-N keypart/s, prohibited by policy */
	XCP_RSC_IMPR_KEYPARTS_REASSEMBLY = 111,  /* import: reconstructing key from keyparts failed */
	XCP_RSC_IMPR_KEYPARTS_CONFLICT = 112,  /* import: multiple keyparts present, with type/size conflicts */
	XCP_RSC_IMPR_ENCRD_DATA_DIFF = 113,  /* import: multiple, conflicting encrypted state fields present */
	XCP_RSC_IMPR_ENCRD_DATA_STRUCT = 114,  /* import: encrypted state field missing or size invalid */
	XCP_RSC_IMPR_ENCR_PARAMS = 115,  /* import: encryption parameter (IV) missing */
	XCP_RSC_IMPR_ENCRD_CONSISTENCY = 116,  /* import: encrypted state/integrity/structure invalid */
	XCP_RSC_BLOB_SETTRUST_REJECT = 117,  /* blob to mark as TRUSTED is rejected */
	XCP_RSC_BLOB_SETCLK_FIELD = 118,  /* time field malformed/missing */
	XCP_RSC_BLOB_SETCLK_TIME = 119,  /* time field (UTC string) contents invalid */
	XCP_RSC_EXPR_SCOPE_INVALID = 120,  /* export: scope restriction not recognized/unsupported */
	XCP_RSC_IMPR_SCOPE_INVALID = 121,  /* import: scope restriction not recognized/unsupported */
	XCP_RSC_IMPR_SCOPE_DOM_RES_VIOLATION = 122,  /* import: domain restricted scope but card sections present */
	XCP_RSC_IMPR_AMBIGUOUS_DOMAIN_SOURCE = 123,  /* import: multiple exported domains for multi domain import */
	XCP_RSC_IMPR_MDOMAIN_IMPORT_MASK_INVALID = 124,  /* import: invalid domain mask for multi domain import */
	XCP_RSC_IMPR_NO_CARD_IMPORTER = 125,  /* import: no card importer key */
	XCP_RSC_IMPR_IMPORT_DOM_DATA_FAILED = 126,  /* import: importing domain data failed */
	XCP_RSC_IMPR_IMPORT_DOM_WKS_FAILED = 127,  /* import: importing domain WKs failed */
	XCP_RSC_IMPR_IMPORT_TGT_DOM_ZEROIZE_FAILED = 128,  /* import: zeroize of target domain failed */
	XCP_RSC_AUDIT_QUERY_PAYLOAD_SIZE = 129,  /* audit query: size of payload too small */
	XCP_RSC_AUDIT_QUERY_INVALID_INDEX = 130,  /* audit query: invalid audit history index */
	XCP_RSC_EXPORT_WK_PROHIBITED = 131,  /* export of WKs prohibited by policy */
	XCP_RSC_EXPORT_STATE_PROHIBITED = 132,  /* export of state prohibited by policy */
	XCP_RSC_IMPORT_STATE_PROHIBITED = 133,  /* import of state prohibited by policy */
	XCP_RSC_EXPORT_WK_UNAUTHORIZED = 134,  /* Card admin attempted to export a DnD domain WK (empty dom admin exp.request?) */
	XCP_RSC_OA_SIG_POLICY_VIOLATION = 135,  /* invalid OA signature config, at least one OA signature type must be enabled */
	XCP_RSC_OA_SIG_NOT_SUPPORTED = 136,  /* requested OA signature type not supported/configured */
	XCP_RSC_ASN_FMT_INVALID = 137,  /* invalid ASN.1 encoded format */
	XCP_RSC_CERT_TYPE_INVALID = 138,  /* Certificate type invalid */
	XCP_RSC_ROLE_ID_INVALID = 139,  /* Role ID invalid */
	XCP_RSC_ADM_SIG_POLICY_VIOLATION = 140,  /* invalid ADM signature config, at least one ADM signature type must be enabled */
	XCP_RSC_KEY_STRENGTH_POLICY_VIOLATION = 141,  /* invalid key strength configuration, a maximum of only one bit may be enabled */
	XCP_RSC_ADM_SIG_CHANGE_PROHIBITED = 142,  /* ADM signature configuration change prohibited, not enough remaining admins to meet security */
	XCP_RSC_KEY_STRENGTH_CHANGE_PROHIBITED = 143,  /* Key strength configuration change prohibited, not enough remaining admins to meet security */
	XCP_RSC_ADM_KTYPE_POLICY_VIOLATION = 144,  /* invalid ADM key type config, inconsistent sig/key types or no key type enabled at all */
	XCP_RSC_ADM_KTYPE_CHANGE_PROHIBITED = 145,  /* Key type configuration change prohibited, not enough remaining admins to meet security */
	XCP_RSC_ADM_SVC_ADMIN_POLICY_VIOLATION = 146,  /* Changing security policy or thresholds prohibited, not enough svc admins to meet security */
	XCP_RSC_ADM_EP11_ADMIN_POLICY_VIOLATION = 147,  /* Changing security policy or thresholds prohibited, not enough ep11 admins to meet security */
	XCP_RSC_CMD_NOT_ALLOWED_IN_INACTIVE_STATE = 148,  /* Command rejected, card is in inactive state */
	XCP_RSC_MAX = XCP_RSC_CMD_NOT_ALLOWED_IN_INACTIVE_STATE
} XCP_ReasonCode_t ;


/* function identifiers must be consecutive, between: */
#define  __MIN_MOD_FNID  1
#define  __MAX_MOD_FNID  44
/* selectively disabled functions within that range reported separately */

#define  __FNID_Login              1
#define  __FNID_Logout             2
#define  __FNID_SeedRandom         3
#define  __FNID_GenerateRandom     4
#define  __FNID_DigestInit         5
#define  __FNID_DigestUpdate       6
#define  __FNID_DigestKey          7
#define  __FNID_DigestFinal        8
#define  __FNID_Digest             9
#define  __FNID_DigestSingle       10
#define  __FNID_EncryptInit        11
#define  __FNID_DecryptInit        12
#define  __FNID_EncryptUpdate      13
#define  __FNID_DecryptUpdate      14
#define  __FNID_EncryptFinal       15
#define  __FNID_DecryptFinal       16
#define  __FNID_Encrypt            17
#define  __FNID_Decrypt            18
#define  __FNID_EncryptSingle      19
#define  __FNID_DecryptSingle      20
#define  __FNID_GenerateKey        21
#define  __FNID_GenerateKeyPair    22
#define  __FNID_SignInit           23
#define  __FNID_SignUpdate         24
#define  __FNID_SignFinal          25
#define  __FNID_Sign               26
#define  __FNID_VerifyInit         27
#define  __FNID_VerifyUpdate       28
#define  __FNID_VerifyFinal        29
#define  __FNID_Verify             30
#define  __FNID_SignSingle         31
#define  __FNID_VerifySingle       32
#define  __FNID_WrapKey            33
#define  __FNID_UnwrapKey          34
#define  __FNID_DeriveKey          35
#define  __FNID_GetMechanismList   36
#define  __FNID_GetMechanismInfo   37
#define  __FNID_get_xcp_info       38
#define  __FNID_GetAttributeValue  39
#define  __FNID_SetAttributeValue  40
#define  __FNID_admin              41
#define  __FNID_ReencryptSingle    42
#define  __FNID_LoginExtended      43
#define  __FNID_LogoutExtended     44
//
#define  __FNID_NEXT_AVAILABLE     45
//
#define  __FNID_MAX                __FNID_LogoutExtended


//
// 64 bit mask. See XCP__FNIDS_DW1 if more bits required (up to 128 bit)
#define  XCP__FNIDS_BIT0  0x8000000000000000ULL
#define  XCP__FNIDS_DW0   \
	      ( (XCP__FNIDS_BIT0)                             |\
	        (XCP__FNIDS_BIT0 >> __FNID_Login)             |\
	        (XCP__FNIDS_BIT0 >> __FNID_Logout)            |\
	        (XCP__FNIDS_BIT0 >> __FNID_SeedRandom)        |\
	        (XCP__FNIDS_BIT0 >> __FNID_GenerateRandom)    |\
	        (XCP__FNIDS_BIT0 >> __FNID_DigestInit)        |\
	        (XCP__FNIDS_BIT0 >> __FNID_DigestUpdate)      |\
/*NOTE: FNID_DigestKey is not supported            \
	        (XCP__FNIDS_BIT0 >> __FNID_DigestKey)         |\
*/                                                 \
	        (XCP__FNIDS_BIT0 >> __FNID_DigestFinal)       |\
	        (XCP__FNIDS_BIT0 >> __FNID_Digest)            |\
	        (XCP__FNIDS_BIT0 >> __FNID_DigestSingle)      |\
	        (XCP__FNIDS_BIT0 >> __FNID_EncryptInit)       |\
	        (XCP__FNIDS_BIT0 >> __FNID_DecryptInit)       |\
	        (XCP__FNIDS_BIT0 >> __FNID_EncryptUpdate)     |\
	        (XCP__FNIDS_BIT0 >> __FNID_DecryptUpdate)     |\
	        (XCP__FNIDS_BIT0 >> __FNID_EncryptFinal)      |\
	        (XCP__FNIDS_BIT0 >> __FNID_DecryptFinal)      |\
	        (XCP__FNIDS_BIT0 >> __FNID_Encrypt)           |\
	        (XCP__FNIDS_BIT0 >> __FNID_Decrypt)           |\
	        (XCP__FNIDS_BIT0 >> __FNID_EncryptSingle)     |\
	        (XCP__FNIDS_BIT0 >> __FNID_DecryptSingle)     |\
	        (XCP__FNIDS_BIT0 >> __FNID_GenerateKey)       |\
	        (XCP__FNIDS_BIT0 >> __FNID_GenerateKeyPair)   |\
	        (XCP__FNIDS_BIT0 >> __FNID_SignInit)          |\
	        (XCP__FNIDS_BIT0 >> __FNID_SignUpdate)        |\
	        (XCP__FNIDS_BIT0 >> __FNID_SignFinal)         |\
	        (XCP__FNIDS_BIT0 >> __FNID_Sign)              |\
	        (XCP__FNIDS_BIT0 >> __FNID_VerifyInit)        |\
	        (XCP__FNIDS_BIT0 >> __FNID_VerifyUpdate)      |\
	        (XCP__FNIDS_BIT0 >> __FNID_VerifyFinal)       |\
	        (XCP__FNIDS_BIT0 >> __FNID_Verify)            |\
	        (XCP__FNIDS_BIT0 >> __FNID_SignSingle)        |\
	        (XCP__FNIDS_BIT0 >> __FNID_VerifySingle)      |\
	        (XCP__FNIDS_BIT0 >> __FNID_WrapKey)           |\
	        (XCP__FNIDS_BIT0 >> __FNID_UnwrapKey)         |\
	        (XCP__FNIDS_BIT0 >> __FNID_DeriveKey)         |\
	        (XCP__FNIDS_BIT0 >> __FNID_GetMechanismList)  |\
	        (XCP__FNIDS_BIT0 >> __FNID_GetMechanismInfo)  |\
	        (XCP__FNIDS_BIT0 >> __FNID_get_xcp_info)      |\
	        (XCP__FNIDS_BIT0 >> __FNID_GetAttributeValue) |\
	        (XCP__FNIDS_BIT0 >> __FNID_SetAttributeValue) |\
	        (XCP__FNIDS_BIT0 >> __FNID_admin)             |\
	        (XCP__FNIDS_BIT0 >> __FNID_ReencryptSingle)   |\
	        (XCP__FNIDS_BIT0 >> __FNID_LoginExtended)     |\
	        (XCP__FNIDS_BIT0 >> __FNID_LogoutExtended))

// used for the module query, see CK_IBM_XCPMSQ_FNLIST
#define XCP__FNIDS_DW1  0


/* maximum nr of non-system parameters:        */
#define  __HOST2MOD_DATAPRM  9
#define  __MOD2HOST_DATAPRM  2


#endif /* n defined(XCP_H__) */

