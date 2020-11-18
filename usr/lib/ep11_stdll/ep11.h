/*
 * COPYRIGHT (c) International Business Machines Corp. 2020
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*----------------------------------------------------------------------
 * This EP11 header file is distributed under the following license
 *
 * Copyright 2020 IBM Corp. All Rights Reserved
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *----------------------------------------------------------------------
 *  EP11 service mail address: EP11SERV@de.ibm.com
 *
 *  Use this mail address for Bugs and Comments with the EP11 product.
 *----------------------------------------------------------------------*/
#if !defined(XCP_H__)
#define XCP_H__
#if !defined(CKR_OK)
#include "pkcs11.h"
#endif
#if !defined(INT64_MIN)
#error "We need 64-bit <stdint.h> types, please include before this file."
#endif
#if !defined(CKM_SHA224)
#define  CKM_SHA224                 0x00000255
#define  CKM_SHA224_HMAC            0x00000256
#define  CKM_SHA224_HMAC_GENERAL    0x00000257
#define  CKM_SHA224_RSA_PKCS        0x00000046
#define  CKM_SHA224_RSA_PKCS_PSS    0x00000047
#define  CKM_SHA224_KEY_DERIVATION  0x00000396
#define  CKM_AES_CTR                0x00001086
#define  CKG_MGF1_SHA224            0x00000005
#endif
#if !defined(CKM_AES_CMAC)
#define  CKM_AES_CMAC               0x0000108a
#endif
#if !defined(CKM_DES3_CMAC)
#define  CKM_DES3_CMAC              0x00000138
#endif
#define XCP_MAX_GRPIDX 1024u
#define  XCP_MOD_VERSION  2
#define  MAX_FNAME_CHARS  256
#define XCPTGTMASK_SET_DOM(mask, domain)      \
                           mask[((domain)/8)] |=   (1 << (7-(domain)%8))
#define XCPTGTMASK_DOM_IS_SET(mask, domain)   \
                           (mask[((domain)/8)] &   (1 << (7-(domain)%8)))
#define XCPTGTMASK_CLR_DOM(mask, domain)      \
                           mask[((domain)/8)] &=  ~(1 << (7-(domain)%8))
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
#define XCP_TGTFL_NO_LOCK 0x01000000   /* target token ignores sequential locks
                                        * for target probing
                                        */
#define  XCP_MAXCONNECTIONS 64       /* max value for active connections */
#define  XCP_MAX_PORT     0xffff
typedef struct XCP_ModuleSocket {
	char host[ MAX_FNAME_CHARS +1 ];
	uint32_t port;
} *XCP_ModuleSocket_t ;
typedef struct XCP_DomainPerf {
	/* perf value of last request per domain
	 *
	 * At the moment unused
	 * */
	unsigned int lastperf[ 256 ];
} *XCP_DomainPerf_t;
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
#define  XCP_API_VERSION  0x0711     /* major[8] minor[8] */
#define  XCP_API_ORDINAL  0x0004
                       /* increment this with every major/minor change */
#define  XCP_HOST_API_VER  0x030001   /* major[8] minor[8] fixpack[8] */
#define  XCP_RPM_VERSION   XCP_HOST_API_VER   /* deprecated */
/* HSM connection information; not for PKCS11 user consumption */
#define  XCP_HSM_AGENT_ID   0x5843           /* ASCII "XC" */
#define  XCP_HSM_USERDEF32  0x01234567
#define XCP_API_ALLOW_PROTKEY  0x0004
typedef enum {
	XCP_FNVAR_SIZEQUERY  = 1, /* sizequery: databytes[64]->resp.bytes[64] */
	XCP_FNVAR_MULTIDATA  = 2, /* multi-data request                       */
	XCP_FNVAR_MULTISIZEQ = 3  /* multi-data request, size query           */
} XCP_FNVariant_t;
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
#define  CKR_IBM_FCV_NOT_SET        (CKR_VENDOR_DEFINED +0x10011)
#define  CKR_IBM_PERF_CATEGORY_INVALID   (CKR_VENDOR_DEFINED +0x10012)
#define  CKR_IBM_API_MISMATCH   (CKR_VENDOR_DEFINED +0x10013)
#define  CKR_IBM_TARGET_INVALID     (CKR_VENDOR_DEFINED +0x10030)
/*---  mechanisms  ---------------------------------------------------------*/
#define  CKM_IBM_SHA3_224         (CKM_VENDOR_DEFINED +0x10001)
#define  CKM_IBM_SHA3_256         (CKM_VENDOR_DEFINED +0x10002)
#define  CKM_IBM_SHA3_384         (CKM_VENDOR_DEFINED +0x10003)
#define  CKM_IBM_SHA3_512         (CKM_VENDOR_DEFINED +0x10004)
#define  CKM_IBM_CMAC             (CKM_VENDOR_DEFINED +0x10007)
#define  CKM_IBM_ECDSA_SHA224     (CKM_VENDOR_DEFINED +0x10008)
#define  CKM_IBM_ECDSA_SHA256     (CKM_VENDOR_DEFINED +0x10009)
#define  CKM_IBM_ECDSA_SHA384     (CKM_VENDOR_DEFINED +0x1000a)
#define  CKM_IBM_ECDSA_SHA512     (CKM_VENDOR_DEFINED +0x1000b)
#define  CKM_IBM_EC_MULTIPLY      (CKM_VENDOR_DEFINED +0x1000c)
#define  CKM_IBM_EAC              (CKM_VENDOR_DEFINED +0x1000d)
#define  XCP_EAC_NONCE_MAX_BYTES  64  /* salt/nonce */
#define  XCP_EAC_INFO_MAX_BYTES   64  /* other auxiliary data */
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
#define  CKM_IBM_TESTCODE         (CKM_VENDOR_DEFINED +0x1000e)
#define  CKM_IBM_SHA512_256       (CKM_VENDOR_DEFINED +0x10012)
#define  CKM_IBM_SHA512_224       (CKM_VENDOR_DEFINED +0x10013)
#define  CKM_IBM_SHA512_256_HMAC  (CKM_VENDOR_DEFINED +0x10014)
#define  CKM_IBM_SHA512_224_HMAC  (CKM_VENDOR_DEFINED +0x10015)
#define  CKM_IBM_EC_X25519                  (CKM_VENDOR_DEFINED +0x1001b)
#define  CKM_IBM_ED25519_SHA512             (CKM_VENDOR_DEFINED +0x1001c)
#define  CKM_IBM_EC_X448                    (CKM_VENDOR_DEFINED +0x1001e)
#define  CKM_IBM_ED448_SHA3                 (CKM_VENDOR_DEFINED +0x1001f)
#define  CKM_IBM_SIPHASH                    (CKM_VENDOR_DEFINED +0x10021)
#define  CKM_IBM_DILITHIUM                  (CKM_VENDOR_DEFINED +0x10023)
         // ^^^ sign/verify plus keygen only
#define  CKM_IBM_SHA3_224_HMAC              (CKM_VENDOR_DEFINED +0x10025)
#define  CKM_IBM_SHA3_256_HMAC              (CKM_VENDOR_DEFINED +0x10026)
#define  CKM_IBM_SHA3_384_HMAC              (CKM_VENDOR_DEFINED +0x10027)
#define  CKM_IBM_SHA3_512_HMAC              (CKM_VENDOR_DEFINED +0x10028)
#define  CKM_IBM_EC_X25519_RAW              (CKM_VENDOR_DEFINED +0x10029)
#define  CKM_IBM_EC_X448_RAW                (CKM_VENDOR_DEFINED +0x10030)
#define  CKM_IBM_CLEARKEY_TRANSPORT    (CKM_VENDOR_DEFINED +0x20001)
#define  CKM_IBM_ATTRIBUTEBOUND_WRAP   (CKM_VENDOR_DEFINED +0x20004)
#define  CKM_IBM_TRANSPORTKEY          (CKM_VENDOR_DEFINED +0x20005)
#define  CKM_IBM_DH_PKCS_DERIVE_RAW    (CKM_VENDOR_DEFINED +0x20006)
#define  CKM_IBM_ECDH1_DERIVE_RAW      (CKM_VENDOR_DEFINED +0x20007)
#define  CKM_IBM_WIRETEST              (CKM_VENDOR_DEFINED +0x30004)
#define  CKM_IBM_RETAINKEY             (CKM_VENDOR_DEFINED +0x40001)
#define  CKM_IBM_CPACF_WRAP            (CKM_VENDOR_DEFINED +0x60001)
/*---  attributes  ---------------------------------------------------------*/
#define  CKA_IBM_RESTRICTABLE      (CKA_VENDOR_DEFINED +0x10001)
#define  CKA_IBM_NEVER_MODIFIABLE  (CKA_VENDOR_DEFINED +0x10002)
#define  CKA_IBM_RETAINKEY         (CKA_VENDOR_DEFINED +0x10003)
#define  CKA_IBM_ATTRBOUND         (CKA_VENDOR_DEFINED +0x10004)
#define  CKA_IBM_KEYTYPE           (CKA_VENDOR_DEFINED +0x10005)
#define  CKA_IBM_CV                (CKA_VENDOR_DEFINED +0x10006)
#define  CKA_IBM_MACKEY            (CKA_VENDOR_DEFINED +0x10007)
#define  CKA_IBM_USE_AS_DATA       (CKA_VENDOR_DEFINED +0x10008)
#define  CKA_IBM_STRUCT_PARAMS     (CKA_VENDOR_DEFINED +0x10009)
#define  CKA_IBM_STD_COMPLIANCE1   (CKA_VENDOR_DEFINED +0x1000a)
#define CKA_IBM_PROTKEY_EXTRACTABLE        (CKA_VENDOR_DEFINED +0x1000c)
#define CKA_IBM_PROTKEY_NEVER_EXTRACTABLE  (CKA_VENDOR_DEFINED +0x1000d)
#define CKA_IBM_PQC_PARAMS (CKA_VENDOR_DEFINED +0x1000e)
#define  CKA_IBM_WIRETEST          (CKA_VENDOR_DEFINED +0x20001)
#define CKK_IBM_PQC_DILITHIUM      (CKK_VENDOR_DEFINED +0x10023)
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
#define  MOD_WRAP_BLOCKSIZE ((size_t) (128 /8)) /* blob crypt block bytecount */
#define  XCP_MACKEY_BYTES       (256 /8)   /* derived from controlling WK     */
#define  XCP_PIN_SALT_BYTES  MOD_WRAP_BLOCKSIZE
#define  XCP_PINBLOB_BYTES  \
        (XCP_WK_BYTES +XCP_PIN_SALT_BYTES +XCP_HMAC_BYTES)
#define  XCP_PBE_TYPE_CLEAR           0  /* clear passphrase                */
#define  XCP_PBE_TYPE_BLOB            1  /* passphrase as generic secretkey */
#define  XCP_PBE_TYPE_MAX            (XCP_PBE_TYPE_BLOB)
#define  XCP_PBE_HDR_BYTES           16  /* fixed part of PBE wire struct   */
#define  XCP_PBE_PWD_MAX_BYTES     1024
#define  XCP_PBE_SALT_MAX_BYTES     256
#define  XCP_MECH_WIRE_PRM_BYTES  ((size_t) 4)     /* CK_ULONG(mech) on wire */
#define  XCP_MECH_PRM_MAX_BYTES   \
        (XCP_MECH_WIRE_PRM_BYTES +XCP_PBE_HDR_BYTES \
         +XCP_PBE_PWD_MAX_BYTES +XCP_PBE_SALT_MAX_BYTES)
	// wire-encoded file header: file ID, start/offset, bytecount
	// return path fills in fields, plus may supply data slice
#define  XCP_WIRE_FILEHDR_BYTES ((size_t) (4+4+4))
#define  XCP_PBE_ITER_MAX         (64*1024)
#define  XCP_CSP_CONFIG_BYTES      40
#define  XCP_SESSIONBLOB_SALT_BYTES          16
#define  XCP_SESSIONBLOB_BYTES  \
         (XCP_WK_BYTES +XCP_SESSIONBLOB_SALT_BYTES +XCP_HMAC_BYTES)
#define  XCP_SIZEQ_WIRE_BYTES   8   /* wire size of data/response bytecounts */
#define  XCP_PSS_WIRE_BYTES (4+4+4) /* hash[32] || MGF[32] || salt bytes[32] */
#define  XCP_PSS_DEFAULT_VALUE  0xffffffff
#define  XCP_OAEP_MIN_WIRE_BYTES  (4+4+4)  /* hash[32] || MGF[32] || src[32] */
#define  XCP_OAEP_MAX_SOURCE_BYTES  1024
	/* limit encoding parameter length to a sane number of Bytes */
#define  XCP_SHAKE_WIRE_BYTES  4  /* XOF Bytes[32] */
#define  XCP_ECDH1_DERIVE_MIN_WIRE_BYTES  (4+4+4)  /* kdf[32] ||
                                                      SharedDataLen[32] ||
                                                      PublicDataLen[32] */
#define  XCP_ECDH1_DERIVE_MAX_PUBLIC_BYTES 1024 /* limit public data length to
                                                   reasonable number of bytes */
#define  XCP_ECDH1_DERIVE_MAX_SHARED_BYTES 1024 /* limit shared data length to
                                                   reasonable number of bytes */
#define  XCP_RETAINID_BYTES        (XCP_HMAC_BYTES +XCP_HMAC_BYTES)
#define  XCP_RETAINLABEL_BYTES     ((size_t) 64)
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
} XCP_CK_EXTFLAGS_t;
#define  XCP_MAX_MODULES         256   /* number of targetable backends      */
#define  XCP_SERIALNR_CHARS        8
#define  XCP_DOMAIN_INSTANCE_BYTES 4
#define  XCP_WRAPKEY_BYTES        32   /* keep integer blocks of blob cipher */
#define  XCP_SPKISALT_BYTES        8   /* in MACed SPKIs (public key objs)   */
#define  XCP_DOMAINS             256   /* keep multiple of 8                 */
#define  XCP_DOMAIN_BYTES          4   /* wire-encoding bytecount            */
#define  XCP_MAX_ADMINS            8   /* per domain; card has +1            */
#define  XCP_MAX_KEYPARTS         20   /* per export/import call             */
#define  XCP_MIN_PINBYTES          8
#define  XCP_MAX_PINBYTES         16
#define  XCP_CERT_MAX_BYTES   ((size_t) 4096)
#define  XCP_CERTHASH_BYTES   (256/8)
      /* hash or SKI of public key, or other hash-identified things; SHA-256 */
#define  XCP_ADMCTR_BYTES   ((size_t) (128/8))
                                       /* card/domain admin transaction ctrs */
#define  XCP_KEYCSUM_BYTES    (256/8)  /* full size of verification pattern  */
/* maximum coordinate bytecount, NIST P or BP curves */
#define  XCP_MAX_EC_COORD_BYTES ((size_t) 66)          /* P-521-> 512+9 bits */
#define  XCP_MAX_EC_CURVE_BITS   521
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
   4096-bit RSA signature, with SHA-256 hash */
#define  XCP_RSPSIG_MAX_BYTES    (75 +4096/8)
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
typedef enum {       /* functionality categories: keep within uint16_t range */
	XCP_LOGEV_QUERY        =  0,
	XCP_LOGEV_FUNCTION     =  1,
	XCP_LOGEV_ADMFUNCTION  =  2,
	XCP_LOGEV_STARTUP      =  3,
	XCP_LOGEV_SHUTDOWN     =  4,
	XCP_LOGEV_SELFTEST     =  5,
	XCP_LOGEV_DOM_IMPORT   =  6, /* import sec-relevant data to domain */
	XCP_LOGEV_DOM_EXPORT   =  7, /* export sec-relevant data from domain */
	XCP_LOGEV_FAILURE      =  8,
	XCP_LOGEV_GENERATE     =  9,
	XCP_LOGEV_REMOVE       = 10,
	XCP_LOGEV_SPECIFIC     = 11, /* obtain meaning elsewhere */
	XCP_LOGEV_STATE_IMPORT = 12, /* import to card/multiple domains */
	XCP_LOGEV_STATE_EXPORT = 13, /* export from card/multiple domains */
	                             /* [after successful export] */
	XCP_LOGEV_IMPORT       = 14, /* key/state import (UnwrapKey) */
	                             /* fields provide more context */
	XCP_LOGEV_EXPORT       = 15, /* key/state import (WrapKey) */
	                             /* fields provide more context */
	    /*---  specific events (any including XCP_LOGEV_SPEC)  ---------*/
	XCP_LOGSPEV_TRANSACT_ZEROIZE  = XCP_LOGEV_SPEC +1,
	                               /* zeroize card by transaction */
	XCP_LOGSPEV_KAT_FAILED        = XCP_LOGEV_SPEC +2,
	                               /* algorithm selftest failed */
	XCP_LOGSPEV_KAT_COMPLETED     = XCP_LOGEV_SPEC +3,
	                               /* algorithm selftests completed */
	                               /* redundant; logged only to     */
	                               /* provide specific event        */
	XCP_LOGSPEV_EARLY_Q_START     = XCP_LOGEV_SPEC +4,
	                               /* subsequent events were found  */
	                               /* in the early-event queue.     */
	                               /* their timestamps are only     */
	                               /* approximate; order is correct */
	XCP_LOGSPEV_EARLY_Q_END       = XCP_LOGEV_SPEC +5,
				       /* early-even queue processing ends. */
	                               /* subsequent events are through     */
	                               /* regular auditing, with valid      */
	                               /* timestamps and ordering.          */
	XCP_LOGSPEV_AUDIT_NEWCHAIN    = XCP_LOGEV_SPEC +6,
				       /* audit state is corrupted; removed. */
				       /* generating new instance and start  */
				       /* new chain as a replacement         */
	XCP_LOGSPEV_TIMECHG_BEFORE    = XCP_LOGEV_SPEC +7,
				       /* time change: original time */
	XCP_LOGSPEV_TIMECHG_AFTER     = XCP_LOGEV_SPEC +8,
				       /* time change: updated time  */
	XCP_LOGSPEV_MODSTIMPORT_START = XCP_LOGEV_SPEC +9,
	                               /* accepted full-state import */
	                               /* data structure             */
	                               /* starting update procedure  */
	XCP_LOGSPEV_MODSTIMPORT_FAIL  = XCP_LOGEV_SPEC +10,
	                               /* rejected import structure    */
	                               /* issued after initial verify; */
	                               /* indicates some inconsistency */
	                               /* of import data structures    */
	XCP_LOGSPEV_MODSTIMPORT_END   = XCP_LOGEV_SPEC +11,
	                               /* completed full-state import */
	XCP_LOGSPEV_MODSTEXPORT_START = XCP_LOGEV_SPEC +12,
	                               /* started full-state export */
	                               /* see also: XCP_LOGEV_STATE_EXPORT */
	XCP_LOGSPEV_MODSTEXPORT_FAIL  = XCP_LOGEV_SPEC +13
	                               /* full-state export did not complete */
} XCP_LogEvent_t;
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
typedef enum {
	XCP_LOGFL_WK_PRESENT         = 0x80000000,
	XCP_LOGFL_COMPLIANCE_PRESENT = 0x40000000,  /* ...of hosting domain */
	XCP_LOGFL_FINALWK_PRESENT    = 0x20000000,
	XCP_LOGFL_KEYREC0_PRESENT    = 0x10000000,
	XCP_LOGFL_KEYREC0_COMPL      = 0x08000000,  /* key0 compliance */
	XCP_LOGFL_KEYREC1_PRESENT    = 0x04000000,
	XCP_LOGFL_KEYREC2_PRESENT    = 0x02000000,
	XCP_LOGFL_FINTIME_PRESENT    = 0x01000000,
	XCP_LOGFL_SALT0_PRESENT      = 0x00800000,
	XCP_LOGFL_SALT1_PRESENT      = 0x00400000,
	XCP_LOGFL_SALT2_PRESENT      = 0x00200000,
	XCP_LOGFL_REASON_PRESENT     = 0x00100000,
	XCP_LOGFL_SEQPRF_PRESENT     = 0x00080000
} XCP_LogFlags_t;
typedef enum {
	XCP_IMPRKEY_RSA_2048    = 0,
	XCP_IMPRKEY_RSA_4096    = 1,
	XCP_IMPRKEY_EC_P256     = 2,    /* EC, NIST P-256        */
	XCP_IMPRKEY_EC_P521     = 3,    /* EC, NIST P-521        */
	XCP_IMPRKEY_EC_BP256r   = 4,    /* EC, Brainpool BP-256r */
	XCP_IMPRKEY_EC_BP320r   = 5,    /* EC, Brainpool BP-320r */
	XCP_IMPRKEY_EC_BP512r   = 6,    /* EC, Brainpool BP-512r */
	XCP_IMPRKEY_RSA_3072    = 7,
	XCP_IMPRKEY_MAX         = XCP_IMPRKEY_RSA_3072
} XCP_IMPRKEY_t;
typedef struct CK_RETAINEDKEY_PARAMS {
	CK_ULONG    credits;
	CK_VOID_PTR rkData;
	CK_ULONG    rkdLen;
} CK_RETAINEDKEY_PARAMS;
typedef enum {
	XCP_OPCAT_ASYMM_SLOW   = 1,
	XCP_OPCAT_ASYMM_FAST   = 2,
	XCP_OPCAT_SYMM_PARTIAL = 3,  /* including hashing                   */
	XCP_OPCAT_SYMM_FULL    = 4,  /* including key generation/derivation */
	XCP_OPCAT_ASYMM_GEN    = 5,
	XCP_OPCAT_ASYMM_MAX    = XCP_OPCAT_ASYMM_GEN
} XCP_OPCAT_t;
typedef enum {
	CK_IBM_XCPQ_API         =  0,  /* API and build identifier     */
	CK_IBM_XCPQ_MODULE      =  1,  /* module-level information     */
	CK_IBM_XCPQ_DOMAINS     =  2,  /* list active domains & WK IDs */
	CK_IBM_XCPQ_DOMAIN      =  3,
	CK_IBM_XCPQ_SELFTEST    =  4,  /* integrity & algorithm tests  */
	CK_IBM_XCPQ_EXT_CAPS    =  5,  /* extended capabilities, count */
	CK_IBM_XCPQ_EXT_CAPLIST =  6,  /* extended capabilities, list  */
	CK_IBM_XCPQ_AUDITLOG    =  8,  /* audit record or records      */
	CK_IBM_XCPQ_DESCRTEXT   =  9,  /* human-readable text/tokens   */
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
	CK_IBM_XCPQ_MAX         = CK_IBM_XCPQ_CP_BLACKLIST
} CK_IBM_XCPQUERY_t;
#define CK_IBM_XCP_HOSTQ_IDX  0xff000000  /* host-only queries index, min. */
typedef enum {
	CK_IBM_XCPHQ_COUNT    = 0xff000000, /* number of host-query indexes   */
	                                    /* including this type itself     */
	CK_IBM_XCPHQ_VERSION  = 0xff000001, /* host-specific package version  */
	                                    /* such as packaging library ID   */
	CK_IBM_XCPHQ_VERSION_HASH = 0xff000002,
	                                    /* assumed-unique identifier of   */
	                                    /* host code, such as version-    */
	                                    /* identifying cryptographic hash */
	                                    /* (library signature field...)   */
	CK_IBM_XCPHQ_DIAGS    = 0xff000003, /* host code diagnostic level     */
	                                    /* 0 if non-diagnostics host code */
	CK_IBM_XCPHQ_HVERSION = 0xff000004, /* human-readable host version    */
	                                    /* identification (recommended:   */
	                                    /* UTF-8 string)                  */
	CK_IBM_XCPHQ_TGT_MODE = 0xff000005, /* host targeting modes           */
	                                    /* returns supported target modes */
	                                    /* as bitmask                     */
	                                    /* if not available only compat   */
	                                    /* target mode is in use          */
	                                    /* See CK_IBM_XCPHQ_TGT_MODES_t   */
	CK_IBM_XCPHQ_ECDH_DERPRM = 0xff000006,
	                                    /* ECDH DeriveKey parameter usage */
	                                    /* is being enforced with hostlib */
	                                    /* version                        */
	                                    /**/
	CK__IBM_XCPHQ_MAX = CK_IBM_XCPHQ_TGT_MODE
} CK_IBM_XCPHQUERY_t;
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
	CK_IBM_XCPXQ_DOMIMPORT_VER  =  7, /* 1-based revision of domain-     */
	                                  /* import capability. 0 if feature */
	                                  /* is not supported                */
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
	CK_IBM_XCPXQ_MAXIDX         = CK_IBM_XCPXQ_AVAIL_SESSIONS
} CK_IBM_XCPEXTCAP_t;
typedef enum {
	CK_IBM_DOM_ADMIND         =    1,  /* administrators present     */
	CK_IBM_DOM_CURR_WK        =    2,  /* domain has current WK      */
	CK_IBM_DOM_NEXT_WK        =    4,  /* domain has pending/next WK */
	CK_IBM_DOM_COMMITTED_NWK  =    8,  /* next WK is active(committed) */
	CK_IBM_DOM_IMPRINTED      = 0x10,  /* has left imprint mode */
	CK_IBM_DOM_IMPRINTS = 0x80000000,  /* enforces imprint mode */
	CK_IBM_DOM_PROTKEY_ALLOW  = 0x20   /* policies allow protected key */
} CK_IBM_DOMAINQ_t;
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
typedef struct CK_IBM_XCP_INFO {
	CK_ULONG   firmwareApi;         /* API ordinal number */
	                                /* major+minor pairs  */
	CK_ULONG   firmwareId;          /* truncated firmwareConfig */
	CK_VERSION firmwareVersion;     /* xcp only, matches xcpConfig below */
	CK_VERSION cspVersion;
	                                /* hashes, possibly truncated */
	CK_BYTE    firmwareConfig[ 32 ];
	CK_BYTE    xcpConfig     [ 32 ];
	CK_BYTE    cspConfig     [ 32 ];
	CK_CHAR    serialNumber[ 16 ];    /* device || instance */
	CK_CHAR    utcTime     [ 16 ];
	CK_ULONG   opMode2;               /* currently, reserved 0        */
	CK_ULONG   opMode1;               /* operational mode, card-level */
	CK_FLAGS   flags;               /*     PKCS#11 capabilities */
	CK_FLAGS   extflags;            /* non-PKCS#11 capabilities */
	CK_ULONG   domains;
	CK_ULONG   symmStateBytes;
	CK_ULONG digestStateBytes;
	CK_ULONG    pinBlockBytes;
	CK_ULONG     symmKeyBytes;
	CK_ULONG        spkiBytes;
	CK_ULONG      prvkeyBytes;
	CK_ULONG  maxPayloadBytes;
	CK_ULONG   cpProfileBytes;
	CK_ULONG    controlPoints;
} CK_IBM_XCP_INFO;
/**/
#define CK_IBM_XCP_INFO_INIT0  \
        { 0,0, {0,0,},{0,0,},  {0,},{0,},{0,}, {0,},{0,}, \
          0,0, 0,0, 0,0,0,0,0,0,0, 0,0,0, }
typedef CK_IBM_XCP_INFO    CK_PTR   CK_IBM_XCP_INFO_PTR;
typedef CK_IBM_XCP_INFO CK_IBM_EP11_INFO;
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
#define  XCP_CPID_BYTES          8     /*  bytecount in CP profiles        */
                                       /*  if backend supports them        */
#define  XCP_CPBLOCK_BITS      128     /*  handle CPs in this granularity  */
                                       /*  CP sets get padded to multiple  */
typedef enum {
    XCP_CPB_ADD_CPBS        =  0, // allow addition (activation) of CP bits
    XCP_CPB_DELETE_CPBS     =  1, // disable activating further control points
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
    XCP_CPB_ALG_RSA         = 30, // RSA private-key or key-encrypt use
    XCP_CPB_ALG_DSA         = 31, // DSA private-key use
    XCP_CPB_ALG_EC          = 32, // EC private-key use (see CP on curves)
    XCP_CPB_ALG_EC_BPOOLCRV = 33, // Brainpool (E.U.) EC curves
    XCP_CPB_ALG_EC_NISTCRV  = 34, // NIST/SECG EC curves
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
    XCP_CPB_ALG_EC_25519       = 55, // enable support of curve25519,
                                     // c448 and related algorithms
                                     // incl. EdDSA (ed25519 and ed448)
    XCP_CPB_ALG_NBSI2017       = 61, // allow non-BSI algorithms (as of 2017)
                                     // including non-BSI keysizes
                                     // (fn:Sign/RSA)
    XCP_CPB_CPACF_PK           = 64, // support data key generation and import
                                     // for protected key
    XCP_CPB_ALG_PQC            = 65, // support for PQ algorithms (top CPB)
    XCP_CPBITS_MAX             = 65
} XCP_CPbit_t;
#define  XCP_CPCOUNT   \
  (((XCP_CPBITS_MAX +XCP_CPBLOCK_BITS-1) /XCP_CPBLOCK_BITS) *XCP_CPBLOCK_BITS)
#define  XCP_CP_BYTES  (XCP_CPCOUNT /8)    /* full blocks, incl. unused bits */
#define  XCP_CPB__INVERT  (XCP_CPCOUNT-1)  /* reserve MS CP bit for negation */
/*---  CP checks  --------------------*/
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
	XCP_ADMQ_LASTCMD_DOM_MASK  = 17 | XCP_ADM_QUERY
	                                  // domain-bitmask affected by last
	                                  // state-related administrative
	                                  // command (export, import)
} XCP_Admcmd_t;
typedef enum {
	XCP_ADMINT_SIGN_THR        = 1,   // signature threshold
	XCP_ADMINT_REVOKE_THR      = 2,   // revocation (signature) threshold
	XCP_ADMINT_PERMS           = 3,   // permissions
	XCP_ADMINT_MODE            = 4,   // operating mode
	XCP_ADMINT_STD             = 5,   // standards' compliance
	XCP_ADMINT_IDX_MAX         = XCP_ADMINT_STD
} XCP_AdmAttr_t;
#define XCP_ADMIN_ATTRIBUTE_COUNT  XCP_ADMINT_IDX_MAX
#define XCP_ADM_SIGTHR__DEFAULT        0
#define XCP_ADM_REVTHR__DEFAULT        0
#define XCP_ADMP_WK_IMPORT             1  // allow WK import
#define XCP_ADMP_WK_EXPORT             2  // allow WK export
#define XCP_ADMP_WK_1PART              4  // allow WK transport in one part
#define XCP_ADMP_WK_RANDOM             8  // allow internally generated WK
#define XCP_ADMP_1SIGN              0x10  // allow single-signed administration
                                          // (threshold set to 1)
#define XCP_ADMP_CP_1SIGN           0x20  // allow single-signed CP modification
#define XCP_ADMP_ZERO_1SIGN         0x40  // allow single-signed zeroize
#define XCP_ADMP_NO_DOMAIN_IMPRINT     \
                                  0x0080  // prohibit logging in to domains in
                                          // imprint mode (card only)
#define XCP_ADMP_STATE_IMPORT     0x0100  // allow state (part) import
                                          // (ignored by domains)
#define XCP_ADMP_STATE_EXPORT     0x0200  // allow state (part) export
                                          // (ignored by domains)
#define XCP_ADMP_STATE_1PART      0x0400  // allow state transport with 1-part
                                          // key (ignored by domains)
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
        XCP_ADMP_CHG_ST_1PART)
#define XCP_ADMP__DEFAULT         	\
       (XCP_ADMP_WK_IMPORT      	| \
        XCP_ADMP_1SIGN          	| \
        XCP_ADMP__CHGBITS)
#define XCP_ADMP__CARD_MASK       	\
      ~(XCP_ADMP_WK_IMPORT      	| \
        XCP_ADMP_WK_EXPORT      	| \
        XCP_ADMP_WK_1PART       	| \
        XCP_ADMP_WK_RANDOM      	| \
        XCP_ADMP_CP_1SIGN       	| \
        XCP_ADMP_CHG_WK_IMPORT  	| \
        XCP_ADMP_CHG_WK_EXPORT  	| \
        XCP_ADMP_CHG_WK_1PART   	| \
        XCP_ADMP_CHG_WK_RANDOM  	| \
        XCP_ADMP_CHG_CP_1SIGN)
#define XCP_ADMP__DOM_MASK       	\
      ~(XCP_ADMP_NO_DOMAIN_IMPRINT	| \
        XCP_ADMP_STATE_IMPORT		| \
        XCP_ADMP_STATE_EXPORT		| \
        XCP_ADMP_STATE_1PART		| \
        XCP_ADMP_CHG_ST_IMPORT		| \
        XCP_ADMP_CHG_ST_EXPORT		| \
        XCP_ADMP_CHG_ST_1PART)
#define XCP_ADMM_AUTHENTICATED         1  // no longer in imprint mode
#define XCP_ADMM_EXTWNG                2  // zeroize if starting w/ ext. warning
                                          // included in default setup
#define XCP_ADMM_STR_112BIT            4  // require 112+ bits' admin strength
#define XCP_ADMM_STR_128BIT            8  // require 128+ bits' admin strength
#define XCP_ADMM_STR_160BIT         0x10  // require 160+ bits' admin strength
#define XCP_ADMM_STR_192BIT         0x20  // require 192+ bits' admin strength
#define XCP_ADMM_STR_256BIT         0x40  // require 256  bits' admin strength
#define XCP_ADMM_WKCLEAN_EXTWNG     0x80  // zeroize WKs if starting with
                                          // ext. warning set.  Leaves
                                          // other parameters unaffected
#define XCP_ADMM_BATT_LOW         0x0100  // module reports low battery
                                          // (read only)
#define XCP_ADMM_API_ACTIVE       0x0200  // remove to disable XCP within card
#define XCP_ADMM__DEFAULT   \
       (XCP_ADMM_EXTWNG     | \
        XCP_ADMM_API_ACTIVE)
#define XCP_ADMS_FIPS2009              1  // NIST, 80+ bits,  -2011.01.01.
#define XCP_ADMS_BSI2009               2  // BSI , 80+ bits,  -2011.01.01.
#define XCP_ADMS_FIPS2011              4  // NIST, 112+ bits,  2011.01.01.-
#define XCP_ADMS_BSI2011               8  // BSI,  112+ bits,  2011.01.01.-
#define XCP_ADMS_SIGG_IMPORT        0x10  // .de SigG, key import
#define XCP_ADMS_SIGG               0x20  // .de SigG, no key import
#define XCP_ADMS_BSICC2017          0x40  // BSI, EP11 Common Criteria EAL4 2017
#define XCP_ADMS__ALL  \
       (XCP_ADMS_FIPS2009  | \
        XCP_ADMS_BSI2009   | \
        XCP_ADMS_FIPS2011  | \
        XCP_ADMS_BSI2011   | \
        XCP_ADMS_BSICC2017)
#define XCP_ADMS_IS_BSI(mode)  (!!(mode & (XCP_ADMS_BSI2009   | \
                                           XCP_ADMS_BSI2011   | \
                                           XCP_ADMS_BSICC2017    )) )
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
	XCP_STSTYPE_SECTIONCOUNT   =  1,  // section count +file hash
	XCP_STSTYPE_DOMAINIDX_MAX  =  2,  // largest index +total nr of domains
	XCP_STSTYPE_DOMAINS_MASK   =  3,  // bitmask of included domains
	XCP_STSTYPE_SERIALNR       =  4,
	XCP_STSTYPE_CREATE_TIME    =  5,  // file date/time (UTC)
	XCP_STSTYPE_FCV            =  6,  // public parts of originating FCV
	XCP_STSTYPE_CARD_QUERY     =  7,  // card state structure (xcp_info)
	XCP_STSTYPE_CARD_ADM_SKIS  =  8,  // card admin SKIs, packed
	XCP_STSTYPE_CARD_ADM_CERTS =  9,  // card admin certificates, packed
	XCP_STSTYPE_DOM_ADM_SKIS   = 10,  // domain admin SKIs, packed
	XCP_STSTYPE_DOM_ADM_CERTS  = 11,  // domain admin certificates, packed
	XCP_STSTYPE_DOM_QUERY      = 12,  // domain state structure (xcp_info)
	XCP_STSTYPE_KPH_SKIS       = 13,  // count and SKIs of targeted KPHs
	XCP_STSTYPE_CARD_ATTRS     = 14,  // card attributes
	XCP_STSTYPE_DOM_ATTRS      = 15,  // domain attributes
	XCP_STSTYPE_CARD_TRANSCTR  = 16,  // card transaction counter
	XCP_STSTYPE_DOM_TRANSCTR   = 17,  // domain transaction counter
	XCP_STSTYPE_WK_ENCR_ALG    = 18,
	XCP_STSTYPE_WK_ENCR_DATA   = 19,
	XCP_STSTYPE_SIG_CERT_COUNT = 20,
	XCP_STSTYPE_SIG_CERTS      = 21,
	XCP_STSTYPE_FILE_SIG       = 22,
	XCP_STSTYPE_DOM_CPS        = 23,  // full set of control points
	XCP_STSTYPE_STATE_SALT     = 24,
	XCP_STSTYPE_KEYPART        = 25,  // encrypted keypart (RecipientInfo)
	XCP_STSTYPE_KEYPART_SIG    = 26,  // signature on encrypted keypart
	XCP_STSTYPE_KEYPART_COUNT  = 27,  // total number of keyparts
	XCP_STSTYPE_KEYPART_LIMIT  = 28,  // number of keyparts needed to
	                                  // restore
	XCP_STSTYPE_KEYPART_CERT   = 29,  // certificate of keypart holder
	XCP_STSTYPE_CERT_AUTH      = 30,  // certificate authority issuing
	                                  // some of the certificates.  This
	                                  // field contains host-supplied data
	                                  // and it is ignored by EP11 itself.
	XCP_STSTYPE_STATE_SCOPE    = 31,  // restriction on contents of full
	                                  // state structure
	XCP_STSTYPE_MULTIIMPORT_MASK
	                           = 32,  // import only: designate import
	                                  // request to be replicated into
	                                  // multiple recipient domains
	XCP_STSTYPE_CPS_MASK       = 33,  // bitmask of all CPs supported
	                                  // by the exporting module
	XCP_STSTYPE_MAX            = XCP_STSTYPE_CPS_MASK
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
	XCP_STDATA_DOMAIN          = 1,   // state restricted to domain data
	                                  // only, excluding card-specific
	                                  // sections
	XCP_STDATA_NONSENSITIVE    = 2,   // serialized state restricted to
	                                  // non-sensitive sections only
	XCP_STWK_KP_NO_CERT        = 4,   // keypart section restricted to
	                                  // not return KPH certificates
	XCP_STDATA_MAX             = ((XCP_STWK_KP_NO_CERT *2) -1)
} XCP_StateType_t;
#define  XCP_STSTYPE_TYPE_BYTES    2
#define  XCP_STSTYPE_TYPEID_BYTES  4
/*---  EC curves  ----------------------------------------------------------*/
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
#define  XCP_EC_BPOIDS        14
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
#define  XCP_EC_S256K1             "\x06\x05" "\x2b\x81\x04\x00\x0a"
#define  XCP_EC_S256K1_BYTES       7
#define  XCP_EC_S256K1_NAME        "\x53\x45\x43\x50\x32\x35\x36\x4b\x31"
                                                                /* SECP256K1 */
#define  XCP_EC_S256K1_NAME_BYTES  9
#define  XCP_EC_X25519        "\x06\x03\x2b\x65\x6e"
#define  XCP_EC_X25519_BYTES  5
#define  XCP_EC_X25519_NAME  "\x63\x75\x72\x76\x65\x32\x35\x35\x31\x39"
                                      /* curve25519 */
#define  XCP_EC_X25519_NAME_BYTES  10
#define  XCP_EC_X448        "\x06\x03\x2b\x65\x6f"
#define  XCP_EC_X448_BYTES  5
#define  XCP_EC_X448_NAME   "\x78\x34\x34\x38"    /* c448, matching RFC8410 */
#define  XCP_EC_X448_NAME_BYTES  4
#define  XCP_EC_DSA25519        "\x06\x03\x2b\x65\x70"
#define  XCP_EC_DSA25519_BYTES  5
#define  XCP_EC_DSA25519_NAME   "\x65\x64\x32\x35\x35\x31\x39" /* ed25519 */
#define  XCP_EC_DSA25519_NAME_BYTES  7
#define  XCP_EC_DSA448        "\x06\x03\x2b\x65\x71"
#define  XCP_EC_DSA448_BYTES  5
#define  XCP_EC_DSA448_NAME   "\x65\x64\x34\x34\x38" /* ed448 */
#define  XCP_EC_DSA448_NAME_BYTES  5
#define  XCP_EC_MAX_ID_BYTES    11   /* fits all EC names/OIDs */
#define XCP_PQC_DILITHIUM_65_NAME       "\x6\xB\x2B\x6\x1\x4\x1\x2\x82\xB\x1\x6\x5"
#define XCP_PQC_DILITHIUM_65_NAME_BYTES 13
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
	XCP_EC_C_MAX       = XCP_EC_C_ED25519
} XCP_ECcurve_t;
/*--------------------------------------
 * groups of EC curves, without specific OIDs
 */
typedef enum {
	XCP_EC_CG_NIST      = 1,      /* NIST, FP curves */
	XCP_EC_CG_BPOOL     = 2,      /* Brainpool, FP curves      */
	XCP_EC_CG_C25519    = 3,      /* curve25519, ed25519 */
	XCP_EC_CG_SECP256K1 = 4,      /* SECP K-curves, incl. Bitcoin default */
	XCP_EC_CG_C448      = 6,      /* c448, ed448 ('Goldilocks') */
	XCP_EC_CG_MAX       = XCP_EC_CG_C448
} XCP_ECCurveGrp_t;
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
	XCP_DEV_PQC_DILITHIUM    = 55,  // post-quantum algs: generic call
	                                // for Dilithium (from PQ Crystals)
	XCP_DEV_MAX_INDEX        = XCP_DEV_PQC_DILITHIUM
} XCP_DEVcmd_t;
#define  XCP_DEV_MAX_DATABYTES   ((size_t) 4096)
#define  XCP_DEV_MAX_ITERATIONS  ((unsigned int) 128*1024)
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
	XCP_DEV_RNG_TYPE_MAX     = XCP_DEV_RNG_MIXED
} XCP_DEVrng_t;
typedef enum {
	XCP_DEVFS_QUERY          = 0,   // current state query only
	XCP_DEVFS_READONLY       = 1,   // prevent writes
	XCP_DEVFS_NOACCESS       = 2    // prevent all filesystem access
} XCP_DEVfs_t;
#define  XCP_DEV_CTR_SIZE  4
#define  XCP_DEV_CTR_TYPE  uint32_t
#if !defined(CKG_VENDOR_DEFINED)
#define  CKG_VENDOR_DEFINED            0x80000000UL
#endif
#define  CKG_IBM_MGF1_SHA3_224         (CKG_VENDOR_DEFINED +1)
#define  CKG_IBM_MGF1_SHA3_256         (CKG_VENDOR_DEFINED +2)
#define  CKG_IBM_MGF1_SHA3_384         (CKG_VENDOR_DEFINED +3)
#define  CKG_IBM_MGF1_SHA3_512         (CKG_VENDOR_DEFINED +4)
typedef uint64_t target_t;
#define XCP_TGT_INIT ~0UL
#define XCP_TGT_FMT "x%016" PRIx64
int m_init(void);
int m_shutdown(void);
int m_add_module(XCP_Module_t module, target_t *target) ;
int m_rm_module(XCP_Module_t module, target_t target) ;
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
/**/
CK_RV m_GetMechanismList (CK_SLOT_ID slot,
               CK_MECHANISM_TYPE_PTR mechs,
                        CK_ULONG_PTR count,
                            target_t target) ;
CK_RV m_GetMechanismInfo (CK_SLOT_ID slot,
                   CK_MECHANISM_TYPE mech,
               CK_MECHANISM_INFO_PTR pmechinfo,
                            target_t target) ;
CK_RV m_GetAttributeValue (const unsigned char *obj,        size_t olen,
                              CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                      target_t target) ;
CK_RV m_SetAttributeValue       (unsigned char *obj,        size_t olen,
                              CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount,
                                      target_t target) ;
CK_RV m_Login ( CK_UTF8CHAR_PTR pin,      CK_ULONG pinlen,
            const unsigned char *nonce,     size_t nlen,
                  unsigned char *pinblob,   size_t *pinbloblen,
                       target_t target) ;
CK_RV m_Logout ( const unsigned char *pin, size_t len,     target_t target) ;
CK_RV m_admin (unsigned char *response1, size_t *r1len,
               unsigned char *response2, size_t *r2len,
         const unsigned char *cmd,       size_t clen,
         const unsigned char *sigs,      size_t slen,
                         target_t target) ;
CK_RV m_get_xcp_info (CK_VOID_PTR pinfo, CK_ULONG_PTR infbytes,
                     unsigned int query,
                     unsigned int subquery,
                         target_t target) ;
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
#define  XCP_W_NO_SEND_CPRB  1      /* data already includes request header */
#define  XCP_W_NO_RECV_CPRB  2      /* leave transport header in response   */
/*--  build identification  ------------------------------------------------*/
#define  XCP_BUILD_ID    0xba1d9ae2
#define  XCP_BUILD_DATE  0x20200211       /* UTC */
#define  XCP_BUILD_TIME  0x080208       /* UTC */
/*--------------------------------------------------------------------------*/
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
	XCP_RSC_MAX = XCP_RSC_AUDIT_QUERY_INVALID_INDEX
} XCP_ReasonCode_t ;
#if ! defined(__transport_fns_h__)
#define __transport_fns_h__
/* function identifiers must be consecutive, between: */
#define  __MIN_MOD_FNID  1
#define  __MAX_MOD_FNID  43
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
#define  __FNID_NEXT_AVAILABLE     43
#define  __FNID_MAX                __FNID_ReencryptSingle
/* maximum nr of non-system parameters:        */
#define  __HOST2MOD_DATAPRM  9
#define  __MOD2HOST_DATAPRM  2
#endif  /* n defined(__transport_fns_h__) */
#endif /* n defined(XCP_H__) */
