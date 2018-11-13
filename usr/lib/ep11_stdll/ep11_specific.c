/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2017
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/***************************************************************************
     Change Log
     ==========
****************************************************************************/

#include <pthread.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <stdint.h>
#include <regex.h>
#include <dirent.h>
#include <libgen.h>

#include "pkcs11types.h"
#include "defs.h"
#include "host_defs.h"
#include "h_extern.h"
#include "errno.h"
#include "tok_specific.h"
#include "tok_struct.h"
#include "stdll.h"
#include "attributes.h"
#include "trace.h"
#include "ock_syslog.h"
#include "ec_defs.h"

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <asm/zcrypt.h>
#include <syslog.h>
#include <dlfcn.h>
#include <lber.h>
#include <grp.h>
#include <sys/time.h>
#include <time.h>

#ifdef DEBUG
#include <ctype.h>
#endif

#include <ica_api.h>
#include <openssl/crypto.h>

#include "ep11.h"
#include "ep11_func.h"
#include "ep11_specific.h"

#define EP11SHAREDLIB "libep11.so"
#define ICASHAREDLIB  "libica.so"

CK_RV ep11tok_get_mechanism_list(STDLL_TokData_t * tokdata,
                                 CK_MECHANISM_TYPE_PTR mlist,
                                 CK_ULONG_PTR count);
CK_RV ep11tok_get_mechanism_info(STDLL_TokData_t * tokdata,
                                 CK_MECHANISM_TYPE type,
                                 CK_MECHANISM_INFO_PTR pInfo);
CK_RV ep11tok_is_mechanism_supported(STDLL_TokData_t *tokdata,
                                     CK_MECHANISM_TYPE type);

static m_GenerateRandom_t dll_m_GenerateRandom;
static m_SeedRandom_t dll_m_SeedRandom;

static m_Digest_t dll_m_Digest;
static m_DigestInit_t dll_m_DigestInit;
static m_DigestUpdate_t dll_m_DigestUpdate;
static m_DigestKey_t dll_m_DigestKey;
static m_DigestFinal_t dll_m_DigestFinal;
static m_DigestSingle_t dll_m_DigestSingle;

static m_Encrypt_t dll_m_Encrypt;
static m_EncryptInit_t dll_m_EncryptInit;
static m_EncryptUpdate_t dll_m_EncryptUpdate;
static m_EncryptFinal_t dll_m_EncryptFinal;
static m_EncryptSingle_t dll_m_EncryptSingle;

static m_Decrypt_t dll_m_Decrypt;
static m_DecryptInit_t dll_m_DecryptInit;
static m_DecryptUpdate_t dll_m_DecryptUpdate;
static m_DecryptFinal_t dll_m_DecryptFinal;
static m_DecryptSingle_t dll_m_DecryptSingle;

static m_ReencryptSingle_t dll_m_ReencryptSingle;
static m_GenerateKey_t dll_m_GenerateKey;
static m_GenerateKeyPair_t dll_m_GenerateKeyPair;

static m_Sign_t dll_m_Sign;
static m_SignInit_t dll_m_SignInit;
static m_SignUpdate_t dll_m_SignUpdate;
static m_SignFinal_t dll_m_SignFinal;
static m_SignSingle_t dll_m_SignSingle;

static m_Verify_t dll_m_Verify;
static m_VerifyInit_t dll_m_VerifyInit;
static m_VerifyUpdate_t dll_m_VerifyUpdate;
static m_VerifyFinal_t dll_m_VerifyFinal;
static m_VerifySingle_t dll_m_VerifySingle;

static m_WrapKey_t dll_m_WrapKey;
static m_UnwrapKey_t dll_m_UnwrapKey;
static m_DeriveKey_t dll_m_DeriveKey;

static m_GetMechanismList_t dll_m_GetMechanismList;
static m_GetMechanismInfo_t dll_m_GetMechanismInfo;
static m_GetAttributeValue_t dll_m_GetAttributeValue;
static m_SetAttributeValue_t dll_m_SetAttributeValue;

static m_Login_t dll_m_Login;
static m_Logout_t dll_m_Logout;
static m_admin_t dll_m_admin;
static m_add_backend_t dll_m_add_backend;
static m_init_t dll_m_init;
static m_shutdown_t dll_m_shutdown;

static xcpa_queryblock_t dll_xcpa_queryblock;
static xcpa_internal_rv_t dll_xcpa_internal_rv;

static m_get_xcp_info_t dll_m_get_xcp_info;

#ifdef DEBUG

/* a simple function for dumping out a memory area */
static inline void hexdump(void *buf, size_t buflen)
{
    /*           1         2         3         4         5         6
       0123456789012345678901234567890123456789012345678901234567890123456789
       xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx xx    ................
     */

    size_t i, j;
    char line[68];
    for (i = 0; i < buflen; i += 16) {
        for (j = 0; j < 16; j++) {
            if (i + j < buflen) {
                unsigned char b = ((unsigned char *) buf)[i + j];
                sprintf(line + j * 3, "%02hhx ", b);
                line[51 + j] = (isalnum(b) ? b : '.');
            } else {
                sprintf(line + j * 3, "   ");
                line[51 + j] = ' ';
            }
        }
        line[47] = line[48] = line[49] = line[50] = ' ';
        line[67] = '\0';
        TRACE_DEBUG("%s\n", line);
    }
}

#define TRACE_DEBUG_DUMP(_buf, _buflen) hexdump(_buf, _buflen)

#endif                          /* DEBUG */

const char manuf[] = "IBM Corp.";
const char model[] = "IBM EP11Tok ";
const char descr[] = "IBM PKCS#11 EP11 token";
const char label[] = "IBM OS PKCS#11   ";

/* largest blobsize ever seen is about 5k (for 4096 mod bits RSA keys) */
#define MAX_BLOBSIZE 8192
#define MAX_CSUMSIZE 64
#define MAX_DIGEST_STATE_BYTES 1024
#define MAX_CRYPT_STATE_BYTES 8192
#define MAX_SIGN_STATE_BYTES 8192
#define MAX_APQN 256

/* wrap_key is used for importing keys */
static const char wrap_key_name[] = "EP11_wrapkey";

typedef struct cp_mech_config {
    CK_MECHANISM_TYPE mech;     // the mechanism ID
    struct cp_mech_config *next;        // next mechanism, or NULL
} cp_mech_config_t;


typedef struct cp_config {
    unsigned long int cp;       // control point number
    cp_mech_config_t *mech;     // list of mechanisms affected by this CP
    struct cp_config *next;     // next control point, or NULL
} cp_config_t;

typedef struct {
    SESSION *session;
    CK_BYTE session_id[SHA256_HASH_SIZE];
    CK_BYTE vhsm_pin[XCP_MAX_PINBYTES];
    CK_BYTE flags;
    CK_BYTE session_pin_blob[XCP_PINBLOB_BYTES];
    CK_OBJECT_HANDLE session_object;
    CK_BYTE vhsm_pin_blob[XCP_PINBLOB_BYTES];
    CK_OBJECT_HANDLE vhsm_object;
} ep11_session_t;

#define EP11_SESS_PINBLOB_VALID  0x01
#define EP11_VHSM_PINBLOB_VALID  0x02
#define EP11_VHSMPIN_VALID       0x10
#define EP11_STRICT_MODE         0x40
#define EP11_VHSM_MODE           0x80

#define DEFAULT_EP11_PIN         "        "

#define CKH_IBM_EP11_SESSION     CKH_VENDOR_DEFINED + 1
#define CKH_IBM_EP11_VHSMPIN     CKH_VENDOR_DEFINED + 2

#define PUBLIC_SESSION_ID_LENGTH    16

#define MAX_RETRY_COUNT 100

#define RETRY_START             do {                                     \
                                    int retry_count;                     \
                                    for(retry_count = 0;                 \
                                        retry_count < MAX_RETRY_COUNT;   \
                                        retry_count ++) {

#define RETRY_END(rc, tokdata, session)  if ((rc) != CKR_SESSION_CLOSED) \
                                             break;                      \
                                         (rc) = ep11tok_relogin_session( \
                                                      tokdata, session); \
                                         if ((rc) != CKR_OK)             \
                                             break;                      \
                                    }                                    \
                                } while (0);

#define CKF_EP11_HELPER_SESSION      0x80000000

static CK_BOOL ep11_is_session_object(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len);
static CK_RV ep11tok_relogin_session(STDLL_TokData_t * tokdata, SESSION * session);
static void ep11_get_pin_blob(ep11_session_t * ep11_session, CK_BOOL is_session_obj,
                              CK_BYTE ** pin_blob, CK_ULONG * pin_blob_len);
static CK_RV ep11_open_helper_session(STDLL_TokData_t * tokdata, SESSION * sess,
                                      CK_SESSION_HANDLE_PTR phSession);
static CK_RV ep11_close_helper_session(STDLL_TokData_t * tokdata,
                                       ST_SESSION_HANDLE * sSession);

static void free_cp_config(cp_config_t * cp);
#ifdef DEBUG
static const char *ep11_get_cp(unsigned int cp);
#endif
static CK_ULONG ep11_get_cp_by_name(const char *name);
static CK_RV check_cps_for_mechanism(cp_config_t * cp_config,
                                     CK_MECHANISM_TYPE mech,
                                     unsigned char *cp, size_t cp_len,
                                     size_t max_cp_index);
static CK_RV get_control_points(STDLL_TokData_t * tokdata,
                                unsigned char *cp, size_t * cp_len,
                                size_t *max_cp_index);

typedef struct ep11_card_version {
    struct ep11_card_version *next;
    CK_ULONG card_type;
    CK_VERSION firmware_version;
    CK_ULONG firmware_API_version;
} ep11_card_version_t;

static CK_RV ep11tok_get_ep11_version(STDLL_TokData_t *tokdata);
static void free_card_versions(ep11_card_version_t *card_version);
static int check_card_version(STDLL_TokData_t *tokdata, CK_ULONG card_type,
                              const CK_VERSION *ep11_lib_version,
                              const CK_VERSION *firmware_version,
                              const CK_ULONG *firmware_API_version);
static int compare_ck_version(const CK_VERSION *v1, const CK_VERSION *v2);

typedef struct {
    const CK_VERSION *min_lib_version;
    const CK_VERSION *min_firmware_version;
    const CK_ULONG *min_firmware_API_version;
    CK_ULONG card_type;
} version_req_t;

static int check_required_versions(STDLL_TokData_t *tokdata,
                                   const version_req_t req[],
                                   CK_ULONG num_req);

/* EP11 Firmware levels that contain the HMAC min/max keysize fix */
static const CK_VERSION cex4p_hmac_fix = { .major = 4, .minor = 20 };
static const CK_VERSION cex5p_hmac_fix = { .major = 6, .minor = 3 };
static const CK_VERSION cex6p_hmac_fix = { .major = 6, .minor = 9 };

static const version_req_t hmac_req_versions[] = {
        { .card_type = 4, .min_firmware_version = &cex4p_hmac_fix },
        { .card_type = 5, .min_firmware_version = &cex5p_hmac_fix },
        { .card_type = 6, .min_firmware_version = &cex6p_hmac_fix }
};
#define NUM_HMAC_REQ sizeof(hmac_req_versions)/sizeof(version_req_t)

/* Definitions for loading libica dynamically */

typedef unsigned int (*ica_sha1_t)(unsigned int message_part,
                                   unsigned int input_length,
                                   unsigned char *input_data,
                                   sha_context_t *sha_context,
                                   unsigned char *output_data);

typedef unsigned int (*ica_sha224_t)(unsigned int message_part,
                                     unsigned int input_length,
                                     unsigned char *input_data,
                                     sha256_context_t *sha_context,
                                     unsigned char *output_data);

typedef unsigned int (*ica_sha256_t)(unsigned int message_part,
                                     unsigned int input_length,
                                     unsigned char *input_data,
                                     sha256_context_t *sha_context,
                                     unsigned char *output_data);

typedef unsigned int (*ica_sha384_t)(unsigned int message_part,
                                     unsigned int input_length,
                                     unsigned char *input_data,
                                     sha512_context_t *sha_context,
                                     unsigned char *output_data);

typedef unsigned int (*ica_sha512_t)(unsigned int message_part,
                                     unsigned int input_length,
                                     unsigned char *input_data,
                                     sha512_context_t *sha_context,
                                     unsigned char *output_data);

typedef unsigned int (*ica_sha512_224_t)(unsigned int message_part,
                                         unsigned int input_length,
                                         unsigned char *input_data,
                                         sha512_context_t *sha_context,
                                         unsigned char *output_data);

typedef unsigned int (*ica_sha512_256_t)(unsigned int message_part,
                                         unsigned int input_length,
                                         unsigned char *input_data,
                                         sha512_context_t *sha_context,
                                         unsigned char *output_data);

typedef struct {
    CK_BYTE buffer[MAX_SHA_BLOCK_SIZE];
    CK_ULONG block_size;
    CK_ULONG offset;
    CK_BBOOL first;
    union {
        sha_context_t sha1;
        sha256_context_t sha256;
        sha512_context_t sha512;
    } ctx;
} libica_sha_context_t;

typedef struct {
    void *library;
    ica_sha1_t ica_sha1;
    ica_sha224_t ica_sha224;
    ica_sha256_t ica_sha256;
    ica_sha384_t ica_sha384;
    ica_sha512_t ica_sha512;
    ica_sha512_224_t ica_sha512_224;
    ica_sha512_256_t ica_sha512_256;
} libica_t;

/* EP11 token private data */
typedef struct {
    uint64_t *target_list;      // pointer to adapter target list
    CK_BYTE raw2key_wrap_blob[MAX_BLOBSIZE];
    size_t raw2key_wrap_blob_l;
    int cka_sensitive_default_true;
    char cp_filter_config_filename[PATH_MAX];
    cp_config_t *cp_config;
    unsigned char control_points[XCP_CP_BYTES];
    size_t control_points_len;
    size_t max_control_point_index;
    int strict_mode;
    int vhsm_mode;
    int optimize_single_ops;
    int digest_libica;
    char digest_libica_path[PATH_MAX];
    libica_t libica;
    CK_VERSION ep11_lib_version;
    ep11_card_version_t *card_versions;
    CK_CHAR serialNumber[16];
} ep11_private_data_t;

/* target list of adapters/domains, specified in a config file by user,
   tells the device driver which adapter/domain pairs should be used,
   they must have the same master key */
typedef struct {
    short format;
    short length;
    short apqns[2 * MAX_APQN];
} __attribute__ ((packed)) ep11_target_t;

/* defined in the makefile, ep11 library can run standalone (without HW card),
   crypto algorithms are implemented in software then (no secure key) */


/* mechanisms provided by this token will be generated from the underlaying
 * crypto adapter. Anyway to be conform to the generic mech_list handling
 * we need to define these dummies */
MECH_LIST_ELEMENT mech_list[] = {{0}};

CK_ULONG mech_list_len = 0;

typedef struct const_info {
    unsigned const int code;
    const char *name;
} const_info_t;

#define CONSTINFO(_X) { (_X), (#_X) }

/* mechanisms defined by EP11 with an invalid (outdated) ID */
#define CKM_EP11_SHA512_224                 0x000002B0  // 0x00000048 in PKCS#11
#define CKM_EP11_SHA512_224_HMAC            0x000002B1  // 0x00000049 in PKCS#11
#define CKM_EP11_SHA512_224_HMAC_GENERAL    0x000002B2  // 0x0000004A in PKCS#11
#define CKM_EP11_SHA512_256                 0x000002C0  // 0x0000004C in PKCS#11
#define CKM_EP11_SHA512_256_HMAC            0x000002C1  // 0x0000004D in PKCS#11
#define CKM_EP11_SHA512_256_HMAC_GENERAL    0x000002C2  // 0x0000004E in PKCS#11

/* Vendor specific mechanisms unknown by ock, but known by EP11 */
#define CKM_IBM_CMAC                       CKM_VENDOR_DEFINED + 0x00010007
#define CKM_IBM_ECDSA_SHA224               CKM_VENDOR_DEFINED + 0x00010008
#define CKM_IBM_ECDSA_SHA256               CKM_VENDOR_DEFINED + 0x00010009
#define CKM_IBM_ECDSA_SHA384               CKM_VENDOR_DEFINED + 0x0001000A
#define CKM_IBM_ECDSA_SHA512               CKM_VENDOR_DEFINED + 0x0001000B
#define CKM_IBM_EC_MULTIPLY                CKM_VENDOR_DEFINED + 0x0001000C
#define CKM_IBM_EAC                        CKM_VENDOR_DEFINED + 0x0001000D
#define CKM_IBM_SHA512_256                 CKM_VENDOR_DEFINED + 0x00010012
#define CKM_IBM_SHA512_224                 CKM_VENDOR_DEFINED + 0x00010013
#define CKM_IBM_SHA512_256_HMAC            CKM_VENDOR_DEFINED + 0x00010014
#define CKM_IBM_SHA512_224_HMAC            CKM_VENDOR_DEFINED + 0x00010015
#define CKM_IBM_SHA512_256_KEY_DERIVATION  CKM_VENDOR_DEFINED + 0x00010016
#define CKM_IBM_SHA512_224_KEY_DERIVATION  CKM_VENDOR_DEFINED + 0x00010017
#define CKM_IBM_EC_C25519                  CKM_VENDOR_DEFINED + 0x0001001B
#define CKM_IBM_EDDSA_SHA512               CKM_VENDOR_DEFINED + 0x0001001C
#define CKM_IBM_EDDSA_PH_SHA512            CKM_VENDOR_DEFINED + 0x0001001D
#define CKM_IBM_EC_C448                    CKM_VENDOR_DEFINED + 0x0001001E
#define CKM_IBM_SIPHASH                    CKM_VENDOR_DEFINED + 0x00010021
#define CKM_IBM_CLEARKEY_TRANSPORT         CKM_VENDOR_DEFINED + 0x00020001
#define CKM_IBM_ATTRIBUTEBOUND_WRAP        CKM_VENDOR_DEFINED + 0x00020004
#define CKM_IBM_TRANSPORTKEY               CKM_VENDOR_DEFINED + 0x00020005
#define CKM_IBM_DH_PKCS_DERIVE_RAW         CKM_VENDOR_DEFINED + 0x00020006
#define CKM_IBM_ECDH1_DERIVE_RAW           CKM_VENDOR_DEFINED + 0x00020007
#define CKM_IBM_WIRETEST                   CKM_VENDOR_DEFINED + 0x00030004
#define CKM_IBM_RETAINKEY                  CKM_VENDOR_DEFINED + 0x00040001

static CK_RV cleanse_attribute(TEMPLATE *template,
                               CK_ATTRIBUTE_TYPE attr_type)
{
    CK_RV rc;
    CK_ATTRIBUTE *attr;

    rc = template_attribute_find(template, attr_type, &attr);
    if (rc != CKR_OK)
        return rc;

    OPENSSL_cleanse(attr->pValue, attr->ulValueLen);

    return CKR_OK;
}

static CK_RV check_key_attributes(STDLL_TokData_t * tokdata,
                                  CK_KEY_TYPE kt, CK_OBJECT_CLASS kc,
                                  CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len,
                                  CK_ATTRIBUTE_PTR * p_attrs,
                                  CK_ULONG * p_attrs_len)
{

    CK_RV rc;
    CK_ULONG i;
    CK_BBOOL cktrue = TRUE;
    CK_ULONG check_types_pub[] = { CKA_VERIFY, CKA_ENCRYPT, CKA_WRAP };
    CK_ULONG check_types_priv[] = { CKA_SIGN, CKA_DECRYPT, CKA_UNWRAP };
    CK_ULONG check_types_sec[] =
        { CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP };
    CK_ULONG check_types_sec_sensitive[] =
        { CKA_ENCRYPT, CKA_DECRYPT, CKA_WRAP, CKA_UNWRAP, CKA_SENSITIVE };
    CK_ULONG check_types_gen_sec[] =
        { CKA_SIGN, CKA_VERIFY, CKA_ENCRYPT, CKA_DECRYPT };
    CK_ULONG check_types_gen_sec_sensitive[] =
        { CKA_SIGN, CKA_VERIFY, CKA_ENCRYPT, CKA_DECRYPT, CKA_SENSITIVE };
    CK_ULONG check_types_derive[] = { CKA_DERIVE };
    CK_ULONG *check_types = NULL;
    CK_BBOOL *check_values[] = { &cktrue, &cktrue, &cktrue, &cktrue, &cktrue };
    CK_ULONG attr_cnt = 0;
    ep11_private_data_t *ep11_data = tokdata->private_data;

    /* check/add attributes for public key template */
    if ((rc = dup_attribute_array(attrs, attrs_len, p_attrs, p_attrs_len)))
        return rc;

    switch (kc) {
    case CKO_SECRET_KEY:
        if (kt == CKK_GENERIC_SECRET) {
            if (ep11_data->cka_sensitive_default_true) {
                check_types = &check_types_gen_sec_sensitive[0];
                attr_cnt =
                    sizeof(check_types_gen_sec_sensitive) / sizeof(CK_ULONG);

            } else {
                check_types = &check_types_gen_sec[0];
                attr_cnt = sizeof(check_types_gen_sec) / sizeof(CK_ULONG);
            }
        } else {
            if (ep11_data->cka_sensitive_default_true) {
                check_types = &check_types_sec_sensitive[0];
                attr_cnt = sizeof(check_types_sec_sensitive) / sizeof(CK_ULONG);
            } else {
                check_types = &check_types_sec[0];
                attr_cnt = sizeof(check_types_sec) / sizeof(CK_ULONG);
            }
        }
        break;
    case CKO_PUBLIC_KEY:
        if ((kt == CKK_EC) || (kt == CKK_ECDSA) || (kt == CKK_DSA)) {
            check_types = &check_types_pub[0];
            attr_cnt = 1;       /* only CKA_VERIFY */
        } else if (kt == CKK_RSA) {
            check_types = &check_types_pub[0];
            attr_cnt = sizeof(check_types_pub) / sizeof(CK_ULONG);
        }
        /* do nothing for CKM_DH_PKCS_KEY_PAIR_GEN
           and CKM_DH_PKCS_PARAMETER_GEN */
        break;
    case CKO_PRIVATE_KEY:
        if ((kt == CKK_EC) || (kt == CKK_ECDSA) || (kt == CKK_DSA)) {
            check_types = &check_types_priv[0];
            attr_cnt = 1;       /* only CKA_SIGN */
        } else if (kt == CKK_RSA) {
            check_types = &check_types_priv[0];
            attr_cnt = sizeof(check_types_priv) / sizeof(CK_ULONG);
        } else if (kt == CKK_DH) {
            check_types = &check_types_derive[0];
            attr_cnt = sizeof(check_types_derive) / sizeof(CK_ULONG);
        }
        break;
    default:
        return CKR_OK;
    }

    for (i = 0; i < attr_cnt; i++, check_types++) {
        CK_ATTRIBUTE_PTR attr = get_attribute_by_type(*p_attrs,
                                                      *p_attrs_len,
                                                      *check_types);
        if (!attr) {
            rc = add_to_attribute_array(p_attrs, p_attrs_len,
                                        *check_types,
                                        (CK_BYTE *) check_values[i],
                                        sizeof(*check_values[i]));
            if (rc)
                goto cleanup;
        }
    }
    return CKR_OK;
cleanup:
    if (rc) {
        free_attribute_array(*p_attrs, *p_attrs_len);
        *p_attrs = NULL;
        *p_attrs_len = 0;
    }
    return rc;
}

static CK_RV ber_encode_RSAPublicKey(CK_BBOOL length_only, CK_BYTE ** data,
                                     CK_ULONG * data_len, CK_ATTRIBUTE * modulus,
                                     CK_ATTRIBUTE * publ_exp)
{
    CK_ULONG len, offset, total, total_len;
    CK_RV rc;
    CK_BYTE *buf = NULL;
    CK_BYTE *buf2 = NULL;
    CK_BYTE *buf3 = NULL;
    BerValue *val;
    BerElement *ber;

    UNUSED(length_only);

    offset = 0;
    rc = 0;
    total_len = ber_AlgIdRSAEncryptionLen;
    total = 0;

    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, modulus->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, publ_exp->ulValueLen);
    offset += len;

    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    buf = (CK_BYTE *) malloc(offset);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }
    offset = 0;
    rc = 0;

    rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                            (CK_BYTE *) modulus + sizeof(CK_ATTRIBUTE),
                            modulus->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_INTEGER(FALSE, &buf2, &len,
                            (CK_BYTE *) publ_exp + sizeof(CK_ATTRIBUTE),
                            publ_exp->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    /* length of outer sequence */
    rc = ber_encode_OCTET_STRING(TRUE, NULL, &total, buf2, len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Oct_Str failed with rc=0x%lx\n", __func__,
                    rc);
        return rc;
    } else {
        total_len += total + 1;
    }

    /* mem for outer sequence */
    buf3 = (CK_BYTE *) malloc(total_len);
    if (!buf3) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }
    total_len = 0;

    /* copy alg id */
    memcpy(buf3 + total_len, ber_AlgIdRSAEncryption, ber_AlgIdRSAEncryptionLen);
    total_len += ber_AlgIdRSAEncryptionLen;

    /* need a bitstring */
    ber = ber_alloc_t(LBER_USE_DER);
    rc = ber_put_bitstring(ber, (char *)buf2, len * 8, 0x03);
    rc = ber_flatten(ber, &val);
    memcpy(buf3 + total_len, val->bv_val, val->bv_len);
    total_len += val->bv_len;

    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf3, total_len);
    if (rc != CKR_OK)
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);

    return rc;
}


static CK_RV ber_encode_ECPublicKey(CK_BBOOL length_only, CK_BYTE ** data,
                                    CK_ULONG * data_len, CK_ATTRIBUTE * params,
                                    CK_ATTRIBUTE * point)
{
    CK_ULONG len, total;
    CK_ULONG algid_len = der_AlgIdECBaseLen + params->ulValueLen;
    CK_RV rc = 0;
    CK_BYTE *buf = NULL;
    BerValue *val;
    BerElement *ber;

    /* Calculate the BER container length
     *
     * SPKI := SEQUENCE {
     *      SEQUENCE {
     *              OID
     *              Parameters
     *      }
     *      BITSTRING public key
     * }
     */
    rc = ber_encode_SEQUENCE(TRUE, NULL, &len, NULL, algid_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_sequence failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    /* public key */
    ber = ber_alloc_t(LBER_USE_DER);
    rc = ber_put_bitstring(ber, (char *)point->pValue,
                           point->ulValueLen * 8, 0x03);
    rc = ber_flatten(ber, &val);

    rc = ber_encode_SEQUENCE(TRUE, NULL, &total, NULL, len + val->bv_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_sequence failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }
    ber_free(ber, 1);

    if (length_only == TRUE) {
        *data_len = total;
        return rc;
    }

    /* Now compute with real data */
    buf = (CK_BYTE *) malloc(total);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    memcpy(buf, der_AlgIdECBase, der_AlgIdECBaseLen);
    memcpy(buf + der_AlgIdECBaseLen, params->pValue, params->ulValueLen);
    buf[1] += params->ulValueLen;

    /* generate bitstring */
    ber = ber_alloc_t(LBER_USE_DER);
    rc = ber_put_bitstring(ber, (char *)point->pValue,
                           point->ulValueLen * 8, 0x03);
    rc = ber_flatten(ber, &val);

    memcpy(buf + der_AlgIdECBaseLen + params->ulValueLen, val->bv_val,
           val->bv_len);
    ber_free(ber, 1);

    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf,
                             der_AlgIdECBaseLen +
                             params->ulValueLen + val->bv_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    free(buf);

    return rc;
}

static CK_RV ber_encode_DSAPublicKey(CK_BBOOL length_only, CK_BYTE ** data,
                                     CK_ULONG * data_len, CK_ATTRIBUTE * prime,
                                     CK_ATTRIBUTE * subprime, CK_ATTRIBUTE * base,
                                     CK_ATTRIBUTE * value)
{
    CK_ULONG len, parm_len, id_len, pub_len, offset, total;
    CK_RV rc = 0;
    CK_BYTE *buf = NULL;
    CK_BYTE *buf2 = NULL;
    BerValue *val;
    BerElement *ber;

    /* Calculate the BER container length
     *
     * SPKI := SEQUENCE {
     *  SEQUENCE {
     *      OID
     *      Parameters
     *  }
     *  BITSTRING public key
     * }
     */

    offset = 0;
    rc = 0;
    total = 0;
    parm_len = 0;
    id_len = 0;
    pub_len = 0;

    /* OID and parameters */
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, subprime->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, base->ulValueLen);
    offset += len;
    rc |= ber_encode_SEQUENCE(TRUE, NULL, &parm_len, NULL, offset);
    rc |=
        ber_encode_SEQUENCE(TRUE, NULL, &id_len, NULL, ber_idDSALen + parm_len);

    /* public key */
    rc |=
        ber_encode_INTEGER(FALSE, &buf, &len, value->pValue, value->ulValueLen);
    ber = ber_alloc_t(LBER_USE_DER);
    rc = ber_put_bitstring(ber, (char *)buf, len * 8, 0x03);
    rc = ber_flatten(ber, &val);
    pub_len = val->bv_len;
    ber_free(ber, 1);
    free(buf);

    rc |= ber_encode_SEQUENCE(TRUE, NULL, &total, NULL, id_len + pub_len);

    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_sequence failed with rc=0x%lx\n", __func__,
                    rc);
        return rc;
    }

    if (length_only == TRUE) {
        *data_len = total;
        return rc;
    }

    buf = (CK_BYTE *) malloc(id_len + pub_len);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    /* Parameters */
    offset = 0;
    rc = ber_encode_INTEGER(FALSE, &buf2, &len, prime->pValue,
                            prime->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_INTEGER(FALSE, &buf2, &len, subprime->pValue,
                            subprime->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_INTEGER(FALSE, &buf2, &len, base->pValue, base->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &parm_len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    /* OID and parameters */
    memcpy(buf, ber_idDSA, ber_idDSALen);
    memcpy(buf + ber_idDSALen, buf2, parm_len);
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &id_len, buf,
                             ber_idDSALen + parm_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    free(buf);

    /* public key */
    rc = ber_encode_INTEGER(FALSE, &buf, &len, value->pValue,
                            value->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    ber = ber_alloc_t(LBER_USE_DER);
    rc = ber_put_bitstring(ber, (char *)buf, len * 8, 0x03);
    rc = ber_flatten(ber, &val);
    free(buf);

    buf = (CK_BYTE *) malloc(id_len + val->bv_len);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }
    memcpy(buf, buf2, id_len);
    memcpy(buf + id_len, val->bv_val, val->bv_len);
    free(buf2);
    ber_free(ber, 1);

    /* outer sequence */
    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf, id_len + pub_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    free(buf);

    return rc;
}

static CK_RV ber_encode_DHPublicKey(CK_BBOOL length_only, CK_BYTE ** data,
                                    CK_ULONG * data_len, CK_ATTRIBUTE * prime,
                                    CK_ATTRIBUTE * base, CK_ATTRIBUTE * value)
{
    CK_ULONG len, parm_len, id_len, pub_len, offset, total;
    CK_RV rc = 0;
    CK_BYTE *buf = NULL;
    CK_BYTE *buf2 = NULL;
    BerValue *val;
    BerElement *ber;

    /* Calculate the BER container length
     *
     * SPKI := SEQUENCE {
     *  SEQUENCE {
     *      OID
     *      Parameters
     *  }
     *  BITSTRING public key
     * }
     */

    offset = 0;
    rc = 0;
    total = 0;
    parm_len = 0;
    id_len = 0;
    pub_len = 0;

    /* OID and parameters */
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, prime->ulValueLen);
    offset += len;
    rc |= ber_encode_INTEGER(TRUE, NULL, &len, NULL, base->ulValueLen);
    offset += len;
    rc |= ber_encode_SEQUENCE(TRUE, NULL, &parm_len, NULL, offset);
    rc |=
        ber_encode_SEQUENCE(TRUE, NULL, &id_len, NULL, ber_idDHLen + parm_len);

    /* public key */
    rc |=
        ber_encode_INTEGER(FALSE, &buf, &len, value->pValue, value->ulValueLen);
    ber = ber_alloc_t(LBER_USE_DER);
    rc = ber_put_bitstring(ber, (char *)buf, len * 8, 0x03);
    rc = ber_flatten(ber, &val);
    pub_len = val->bv_len;
    ber_free(ber, 1);
    free(buf);

    rc |= ber_encode_SEQUENCE(TRUE, NULL, &total, NULL, id_len + pub_len);

    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_sequence failed with rc=0x%lx\n", __func__,
                    rc);
        return rc;
    }

    if (length_only == TRUE) {
        *data_len = total;
        return rc;
    }

    buf = (CK_BYTE *) malloc(id_len + pub_len);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    /* Parameters */
    offset = 0;
    rc = ber_encode_INTEGER(FALSE, &buf2, &len, prime->pValue,
                            prime->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_INTEGER(FALSE, &buf2, &len, base->pValue, base->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    memcpy(buf + offset, buf2, len);
    offset += len;
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &parm_len, buf, offset);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    /* OID and parameters */
    memcpy(buf, ber_idDH, ber_idDHLen);
    memcpy(buf + ber_idDHLen, buf2, parm_len);
    free(buf2);

    rc = ber_encode_SEQUENCE(FALSE, &buf2, &id_len, buf,
                             ber_idDHLen + parm_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    free(buf);

    /* public key */
    rc = ber_encode_INTEGER(FALSE, &buf, &len, value->pValue,
                            value->ulValueLen);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s ber_encode_Int failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    ber = ber_alloc_t(LBER_USE_DER);
    rc = ber_put_bitstring(ber, (char *)buf, len * 8, 0x03);
    rc = ber_flatten(ber, &val);
    free(buf);

    buf = (CK_BYTE *) malloc(id_len + val->bv_len);
    if (!buf) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }
    memcpy(buf, buf2, id_len);
    memcpy(buf + id_len, val->bv_val, val->bv_len);
    free(buf2);
    ber_free(ber, 1);

    /* outer sequence */
    rc = ber_encode_SEQUENCE(FALSE, data, data_len, buf, id_len + pub_len);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s der_encode_Seq failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }
    free(buf);

    return rc;
}

/* get the public key from a SPKI
 *   SubjectPublicKeyInfo ::= SEQUENCE {
 *     algorithm         AlgorithmIdentifier,
 *     subjectPublicKey  BIT STRING
 *   }
 *
 *   AlgorithmIdentifier ::= SEQUENCE {
 *     algorithm   OBJECT IDENTIFIER,
 *     parameters  ANY DEFINED BY algorithm OPTIONAL
 *   }
 */
static CK_RV ep11_spki_key(CK_BYTE * spki, CK_BYTE ** key, CK_ULONG * bit_str_len)
{
    CK_BYTE *out_seq, *id_seq, *bit_str;
    CK_BYTE *data;
    CK_ULONG data_len;
    CK_ULONG field_len;
    CK_ULONG key_len_bytes;
    CK_RV rc;
    CK_ULONG length_octets = 0;
    CK_ULONG len = 0;

    *bit_str_len = 0;
    out_seq = spki;
    rc = ber_decode_SEQUENCE(out_seq, &data, &data_len, &field_len);

    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_decode_SEQUENCE #1 failed rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    id_seq = out_seq + field_len - data_len;
    /* get id seq length */
    rc = ber_decode_SEQUENCE(id_seq, &data, &data_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_decode_SEQUENCE #2 failed rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    bit_str = id_seq + field_len;
    /* we should be at a bistring */
    if (bit_str[0] != 0x03) {
        TRACE_ERROR("%s ber_decode no BITSTRING\n", __func__);
        return CKR_FUNCTION_FAILED;
    }

    if ((bit_str[1] & 0x80) == 0) {
        key_len_bytes = 1;
        *bit_str_len = bit_str[1] & 0x7F;
    } else {
        key_len_bytes = 1 + (bit_str[1] & 0x7F);
    }

    *key = bit_str + key_len_bytes + 2; /* one 'unused bits' byte */

    if (*bit_str_len == 0) {
        length_octets = bit_str[1] & 0x7F;

        if (length_octets == 1) {
            len = bit_str[2];
        }

        if (length_octets == 2) {
            len = bit_str[2];
            len = len << 8;
            len |= bit_str[3];
        }

        if (length_octets == 3) {
            len = bit_str[2];
            len = len << 8;
            len |= bit_str[3];
            len = len << 8;
            len |= bit_str[4];
        }
        *bit_str_len = len;
    }

    (*bit_str_len)--; /* remove 'unused bits' byte from length */

    return CKR_OK;
}


static CK_RV ep11_get_keytype(CK_ATTRIBUTE * attrs, CK_ULONG attrs_len,
                              CK_MECHANISM_PTR mech, CK_ULONG * type, CK_ULONG * class)
{
    CK_ULONG i;
    CK_RV rc = CKR_TEMPLATE_INCONSISTENT;

    *type = 0;
    *class = 0;

    for (i = 0; i < attrs_len; i++) {
        if (attrs[i].type == CKA_CLASS)
            *class = *(CK_ULONG *) attrs[i].pValue;
    }

    for (i = 0; i < attrs_len; i++) {
        if (attrs[i].type == CKA_KEY_TYPE) {
            *type = *(CK_ULONG *) attrs[i].pValue;
            return CKR_OK;
        }
    }

    /* no CKA_KEY_TYPE found, derive from mech */

    switch (mech->mechanism) {
    case CKM_DES_KEY_GEN:
        *type = CKK_DES;
        break;
    case CKM_DES3_KEY_GEN:
        *type = CKK_DES3;
        break;
    case CKM_CDMF_KEY_GEN:
        *type = CKK_CDMF;
        break;
    case CKM_AES_KEY_GEN:
        *type = CKK_AES;
        break;
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
        *type = CKK_RSA;
        break;
    case CKM_EC_KEY_PAIR_GEN:
        *type = CKK_EC;
        break;
    case CKM_DSA_KEY_PAIR_GEN:
        *type = CKK_DSA;
        break;
    case CKM_DH_PKCS_KEY_PAIR_GEN:
        *type = CKK_DH;
        break;
    default:
        return CKR_MECHANISM_INVALID;
    }

    rc = CKR_OK;

    return rc;
}

static const_info_t ep11_mechanisms[] = {
    CONSTINFO(CKM_RSA_PKCS_KEY_PAIR_GEN),
    CONSTINFO(CKM_RSA_PKCS),
    CONSTINFO(CKM_RSA_9796),
    CONSTINFO(CKM_RSA_X_509),
    CONSTINFO(CKM_MD2_RSA_PKCS),
    CONSTINFO(CKM_MD5_RSA_PKCS),
    CONSTINFO(CKM_SHA1_RSA_PKCS),
    CONSTINFO(CKM_RIPEMD128_RSA_PKCS),
    CONSTINFO(CKM_RIPEMD160_RSA_PKCS),
    CONSTINFO(CKM_RSA_PKCS_OAEP),
    CONSTINFO(CKM_RSA_X9_31_KEY_PAIR_GEN),
    CONSTINFO(CKM_RSA_X9_31),
    CONSTINFO(CKM_SHA1_RSA_X9_31),
    CONSTINFO(CKM_RSA_PKCS_PSS),
    CONSTINFO(CKM_SHA1_RSA_PKCS_PSS),
    CONSTINFO(CKM_DSA_KEY_PAIR_GEN),
    CONSTINFO(CKM_DSA),
    CONSTINFO(CKM_DSA_SHA1),
    CONSTINFO(CKM_DH_PKCS_KEY_PAIR_GEN),
    CONSTINFO(CKM_DH_PKCS_DERIVE),
    CONSTINFO(CKM_X9_42_DH_KEY_PAIR_GEN),
    CONSTINFO(CKM_X9_42_DH_DERIVE),
    CONSTINFO(CKM_X9_42_DH_HYBRID_DERIVE),
    CONSTINFO(CKM_X9_42_MQV_DERIVE),
    CONSTINFO(CKM_SHA256_RSA_PKCS),
    CONSTINFO(CKM_SHA384_RSA_PKCS),
    CONSTINFO(CKM_SHA512_RSA_PKCS),
    CONSTINFO(CKM_RC2_KEY_GEN),
    CONSTINFO(CKM_RC2_ECB),
    CONSTINFO(CKM_RC2_CBC),
    CONSTINFO(CKM_RC2_MAC),
    CONSTINFO(CKM_RC2_MAC_GENERAL),
    CONSTINFO(CKM_RC2_CBC_PAD),
    CONSTINFO(CKM_RC4_KEY_GEN),
    CONSTINFO(CKM_RC4),
    CONSTINFO(CKM_DES_KEY_GEN),
    CONSTINFO(CKM_DES_ECB),
    CONSTINFO(CKM_DES_CBC),
    CONSTINFO(CKM_DES_MAC),
    CONSTINFO(CKM_DES_MAC_GENERAL),
    CONSTINFO(CKM_DES_CBC_PAD),
    CONSTINFO(CKM_DES2_KEY_GEN),
    CONSTINFO(CKM_DES3_KEY_GEN),
    CONSTINFO(CKM_DES3_ECB),
    CONSTINFO(CKM_DES3_CBC),
    CONSTINFO(CKM_DES3_MAC),
    CONSTINFO(CKM_DES3_MAC_GENERAL),
    CONSTINFO(CKM_DES3_CBC_PAD),
    CONSTINFO(CKM_CDMF_KEY_GEN),
    CONSTINFO(CKM_CDMF_ECB),
    CONSTINFO(CKM_CDMF_CBC),
    CONSTINFO(CKM_CDMF_MAC),
    CONSTINFO(CKM_CDMF_MAC_GENERAL),
    CONSTINFO(CKM_CDMF_CBC_PAD),
    CONSTINFO(CKM_MD2),
    CONSTINFO(CKM_MD2_HMAC),
    CONSTINFO(CKM_MD2_HMAC_GENERAL),
    CONSTINFO(CKM_MD5),
    CONSTINFO(CKM_MD5_HMAC),
    CONSTINFO(CKM_MD5_HMAC_GENERAL),
    CONSTINFO(CKM_SHA_1),
    CONSTINFO(CKM_SHA_1_HMAC),
    CONSTINFO(CKM_SHA_1_HMAC_GENERAL),
    CONSTINFO(CKM_RIPEMD128),
    CONSTINFO(CKM_RIPEMD128_HMAC),
    CONSTINFO(CKM_RIPEMD128_HMAC_GENERAL),
    CONSTINFO(CKM_RIPEMD160),
    CONSTINFO(CKM_RIPEMD160_HMAC),
    CONSTINFO(CKM_RIPEMD160_HMAC_GENERAL),
    CONSTINFO(CKM_SHA224),
    CONSTINFO(CKM_SHA224_HMAC),
    CONSTINFO(CKM_SHA224_HMAC_GENERAL),
    CONSTINFO(CKM_SHA256),
    CONSTINFO(CKM_SHA256_HMAC),
    CONSTINFO(CKM_SHA256_HMAC_GENERAL),
    CONSTINFO(CKM_SHA384),
    CONSTINFO(CKM_SHA384_HMAC),
    CONSTINFO(CKM_SHA384_HMAC_GENERAL),
    CONSTINFO(CKM_SHA512),
    CONSTINFO(CKM_SHA512_HMAC),
    CONSTINFO(CKM_SHA512_HMAC_GENERAL),
    CONSTINFO(CKM_CAST_KEY_GEN),
    CONSTINFO(CKM_CAST_ECB),
    CONSTINFO(CKM_CAST_CBC),
    CONSTINFO(CKM_CAST_MAC),
    CONSTINFO(CKM_CAST_MAC_GENERAL),
    CONSTINFO(CKM_CAST_CBC_PAD),
    CONSTINFO(CKM_CAST3_KEY_GEN),
    CONSTINFO(CKM_CAST3_ECB),
    CONSTINFO(CKM_CAST3_CBC),
    CONSTINFO(CKM_CAST3_MAC),
    CONSTINFO(CKM_CAST3_MAC_GENERAL),
    CONSTINFO(CKM_CAST3_CBC_PAD),
    CONSTINFO(CKM_CAST5_KEY_GEN),
    CONSTINFO(CKM_CAST5_ECB),
    CONSTINFO(CKM_CAST5_CBC),
    CONSTINFO(CKM_CAST5_MAC),
    CONSTINFO(CKM_CAST5_MAC_GENERAL),
    CONSTINFO(CKM_CAST5_CBC_PAD),
    CONSTINFO(CKM_RC5_KEY_GEN),
    CONSTINFO(CKM_RC5_ECB),
    CONSTINFO(CKM_RC5_CBC),
    CONSTINFO(CKM_RC5_MAC),
    CONSTINFO(CKM_RC5_MAC_GENERAL),
    CONSTINFO(CKM_RC5_CBC_PAD),
    CONSTINFO(CKM_IDEA_KEY_GEN),
    CONSTINFO(CKM_IDEA_ECB),
    CONSTINFO(CKM_IDEA_CBC),
    CONSTINFO(CKM_IDEA_MAC),
    CONSTINFO(CKM_IDEA_MAC_GENERAL),
    CONSTINFO(CKM_IDEA_CBC_PAD),
    CONSTINFO(CKM_GENERIC_SECRET_KEY_GEN),
    CONSTINFO(CKM_CONCATENATE_BASE_AND_KEY),
    CONSTINFO(CKM_CONCATENATE_BASE_AND_DATA),
    CONSTINFO(CKM_CONCATENATE_DATA_AND_BASE),
    CONSTINFO(CKM_XOR_BASE_AND_DATA),
    CONSTINFO(CKM_EXTRACT_KEY_FROM_KEY),
    CONSTINFO(CKM_SSL3_PRE_MASTER_KEY_GEN),
    CONSTINFO(CKM_SSL3_MASTER_KEY_DERIVE),
    CONSTINFO(CKM_SSL3_KEY_AND_MAC_DERIVE),
    CONSTINFO(CKM_SSL3_MASTER_KEY_DERIVE_DH),
    CONSTINFO(CKM_TLS_PRE_MASTER_KEY_GEN),
    CONSTINFO(CKM_TLS_MASTER_KEY_DERIVE),
    CONSTINFO(CKM_TLS_KEY_AND_MAC_DERIVE),
    CONSTINFO(CKM_TLS_MASTER_KEY_DERIVE_DH),
    CONSTINFO(CKM_SSL3_MD5_MAC),
    CONSTINFO(CKM_SSL3_SHA1_MAC),
    CONSTINFO(CKM_MD5_KEY_DERIVATION),
    CONSTINFO(CKM_MD2_KEY_DERIVATION),
    CONSTINFO(CKM_SHA1_KEY_DERIVATION),
    CONSTINFO(CKM_SHA256_KEY_DERIVATION),
    CONSTINFO(CKM_PBE_MD2_DES_CBC),
    CONSTINFO(CKM_PBE_MD5_DES_CBC),
    CONSTINFO(CKM_PBE_MD5_CAST_CBC),
    CONSTINFO(CKM_PBE_MD5_CAST3_CBC),
    CONSTINFO(CKM_PBE_MD5_CAST5_CBC),
    CONSTINFO(CKM_PBE_SHA1_CAST5_CBC),
    CONSTINFO(CKM_PBE_SHA1_RC4_128),
    CONSTINFO(CKM_PBE_SHA1_RC4_40),
    CONSTINFO(CKM_PBE_SHA1_DES3_EDE_CBC),
    CONSTINFO(CKM_PBE_SHA1_DES2_EDE_CBC),
    CONSTINFO(CKM_PBE_SHA1_RC2_128_CBC),
    CONSTINFO(CKM_PBE_SHA1_RC2_40_CBC),
    CONSTINFO(CKM_PKCS5_PBKD2),
    CONSTINFO(CKM_PBA_SHA1_WITH_SHA1_HMAC),
    CONSTINFO(CKM_KEY_WRAP_LYNKS),
    CONSTINFO(CKM_KEY_WRAP_SET_OAEP),
    CONSTINFO(CKM_SKIPJACK_KEY_GEN),
    CONSTINFO(CKM_SKIPJACK_ECB64),
    CONSTINFO(CKM_SKIPJACK_CBC64),
    CONSTINFO(CKM_SKIPJACK_OFB64),
    CONSTINFO(CKM_SKIPJACK_CFB64),
    CONSTINFO(CKM_SKIPJACK_CFB32),
    CONSTINFO(CKM_SKIPJACK_CFB16),
    CONSTINFO(CKM_SKIPJACK_CFB8),
    CONSTINFO(CKM_SKIPJACK_WRAP),
    CONSTINFO(CKM_SKIPJACK_PRIVATE_WRAP),
    CONSTINFO(CKM_SKIPJACK_RELAYX),
    CONSTINFO(CKM_KEA_KEY_PAIR_GEN),
    CONSTINFO(CKM_KEA_KEY_DERIVE),
    CONSTINFO(CKM_FORTEZZA_TIMESTAMP),
    CONSTINFO(CKM_BATON_KEY_GEN),
    CONSTINFO(CKM_BATON_ECB128),
    CONSTINFO(CKM_BATON_ECB96),
    CONSTINFO(CKM_BATON_CBC128),
    CONSTINFO(CKM_BATON_COUNTER),
    CONSTINFO(CKM_BATON_SHUFFLE),
    CONSTINFO(CKM_BATON_WRAP),
    CONSTINFO(CKM_EC_KEY_PAIR_GEN),
    CONSTINFO(CKM_ECDSA),
    CONSTINFO(CKM_ECDSA_SHA1),
    CONSTINFO(CKM_ECDSA_SHA224),
    CONSTINFO(CKM_ECDSA_SHA256),
    CONSTINFO(CKM_ECDSA_SHA384),
    CONSTINFO(CKM_ECDSA_SHA512),
    CONSTINFO(CKM_ECDH1_DERIVE),
    CONSTINFO(CKM_ECDH1_COFACTOR_DERIVE),
    CONSTINFO(CKM_ECMQV_DERIVE),
    CONSTINFO(CKM_JUNIPER_KEY_GEN),
    CONSTINFO(CKM_JUNIPER_ECB128),
    CONSTINFO(CKM_JUNIPER_CBC128),
    CONSTINFO(CKM_JUNIPER_COUNTER),
    CONSTINFO(CKM_JUNIPER_SHUFFLE),
    CONSTINFO(CKM_JUNIPER_WRAP),
    CONSTINFO(CKM_FASTHASH),
    CONSTINFO(CKM_AES_KEY_GEN),
    CONSTINFO(CKM_AES_ECB),
    CONSTINFO(CKM_AES_CBC),
    CONSTINFO(CKM_AES_MAC),
    CONSTINFO(CKM_AES_MAC_GENERAL),
    CONSTINFO(CKM_AES_CBC_PAD),
    CONSTINFO(CKM_AES_CTR),
    CONSTINFO(CKM_DSA_PARAMETER_GEN),
    CONSTINFO(CKM_DH_PKCS_PARAMETER_GEN),
    CONSTINFO(CKM_X9_42_DH_PARAMETER_GEN),
    CONSTINFO(CKM_VENDOR_DEFINED),
    CONSTINFO(CKM_SHA256_RSA_PKCS_PSS),
    CONSTINFO(CKM_SHA224_RSA_PKCS),
    CONSTINFO(CKM_SHA224_RSA_PKCS_PSS),
    CONSTINFO(CKM_SHA384_RSA_PKCS_PSS),
    CONSTINFO(CKM_SHA512_RSA_PKCS_PSS),
    CONSTINFO(CKM_SHA224_KEY_DERIVATION),
    CONSTINFO(CKM_SHA384_KEY_DERIVATION),
    CONSTINFO(CKM_SHA512_KEY_DERIVATION),
    CONSTINFO(CKM_SHA512_224),
    CONSTINFO(CKM_SHA512_224_HMAC),
    CONSTINFO(CKM_SHA512_224_HMAC_GENERAL),
    CONSTINFO(CKM_SHA512_256),
    CONSTINFO(CKM_SHA512_256_HMAC),
    CONSTINFO(CKM_SHA512_256_HMAC_GENERAL),
    CONSTINFO(CKM_EP11_SHA512_224),
    CONSTINFO(CKM_EP11_SHA512_224_HMAC),
    CONSTINFO(CKM_EP11_SHA512_224_HMAC_GENERAL),
    CONSTINFO(CKM_EP11_SHA512_256),
    CONSTINFO(CKM_EP11_SHA512_256_HMAC),
    CONSTINFO(CKM_EP11_SHA512_256_HMAC_GENERAL),
    CONSTINFO(CKM_IBM_CMAC),
    CONSTINFO(CKM_IBM_ECDSA_SHA224),
    CONSTINFO(CKM_IBM_ECDSA_SHA256),
    CONSTINFO(CKM_IBM_ECDSA_SHA384),
    CONSTINFO(CKM_IBM_ECDSA_SHA512),
    CONSTINFO(CKM_IBM_EC_MULTIPLY),
    CONSTINFO(CKM_IBM_EAC),
    CONSTINFO(CKM_IBM_SHA512_256),
    CONSTINFO(CKM_IBM_SHA512_224),
    CONSTINFO(CKM_IBM_SHA512_256_HMAC),
    CONSTINFO(CKM_IBM_SHA512_224_HMAC),
    CONSTINFO(CKM_IBM_SHA512_256_KEY_DERIVATION),
    CONSTINFO(CKM_IBM_SHA512_224_KEY_DERIVATION),
    CONSTINFO(CKM_IBM_EC_C25519),
    CONSTINFO(CKM_IBM_EDDSA_SHA512),
    CONSTINFO(CKM_IBM_EDDSA_PH_SHA512),
    CONSTINFO(CKM_IBM_EC_C448),
    CONSTINFO(CKM_IBM_SIPHASH),
    CONSTINFO(CKM_IBM_CLEARKEY_TRANSPORT),
    CONSTINFO(CKM_IBM_ATTRIBUTEBOUND_WRAP),
    CONSTINFO(CKM_IBM_TRANSPORTKEY),
    CONSTINFO(CKM_IBM_DH_PKCS_DERIVE_RAW),
    CONSTINFO(CKM_IBM_ECDH1_DERIVE_RAW),
    CONSTINFO(CKM_IBM_WIRETEST),
    CONSTINFO(CKM_IBM_RETAINKEY),
};

#define UNKNOWN_MECHANISM   0xFFFFFFFF

/* for logging, debugging */
static const char *ep11_get_ckm(CK_ULONG mechanism)
{
    unsigned int i;

    for (i = 0;
         i < (sizeof(ep11_mechanisms) / sizeof(ep11_mechanisms[0]));
         i++) {
        if (ep11_mechanisms[i].code == mechanism)
            return ep11_mechanisms[i].name;
    }

    TRACE_WARNING("%s unknown mechanism %lx\n", __func__, mechanism);
    return "UNKNOWN";
}

static CK_ULONG ep11_get_mechanisms_by_name(const char *name)
{
    unsigned int i;

    for (i = 0;
         i < (sizeof(ep11_mechanisms) / sizeof(ep11_mechanisms[0]));
         i++) {
        if (strcmp(ep11_mechanisms[i].name, name) == 0)
            return ep11_mechanisms[i].code;
    }

    TRACE_WARNING("%s unknown mechanism name '%s'\n", __func__, name);
    return UNKNOWN_MECHANISM;
}

static CK_RV h_opaque_2_blob(STDLL_TokData_t * tokdata, CK_OBJECT_HANDLE handle,
                             CK_BYTE ** blob, size_t * blob_len,
                             OBJECT ** kobj);
static CK_RV obj_opaque_2_blob(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                               CK_BYTE **blob, size_t *blobsize);

#define EP11_DEFAULT_CFG_FILE "ep11tok.conf"
#define EP11_CFG_FILE_SIZE 4096

#define EP11_DEFAULT_CPFILTER_FILE "ep11cpfilter.conf"

/* error rc for reading the adapter config file */
static const int APQN_FILE_INV = 3;
static const int APQN_FILE_INV_FILE_SIZE = 5;
static const int APQN_FILE_SYNTAX_ERROR_0 = 7;
static const int APQN_FILE_SYNTAX_ERROR_1 = 8;
static const int APQN_FILE_SYNTAX_ERROR_2 = 9;
static const int APQN_FILE_SYNTAX_ERROR_3 = 10;
static const int APQN_FILE_SYNTAX_ERROR_4 = 11;
static const int APQN_FILE_SYNTAX_ERROR_5 = 12;
static const int APQN_FILE_NO_APQN_GIVEN = 13;
static const int APQN_FILE_NO_APQN_MODE = 14;
static const int APQN_FILE_UNEXPECTED_END_OF_FILE = 15;
static const int APQN_FILE_SYNTAX_ERROR_6 = 16;
static const int APQN_FILE_SYNTAX_ERROR_7 = 17;
static const int APQN_FILE_SYNTAX_ERROR_8 = 18;
static const int APQN_OUT_OF_MEMORY = 19;

static int read_adapter_config_file(STDLL_TokData_t * tokdata,
                                    const char *conf_name);
static int read_cp_filter_config_file(const char *conf_name,
                                      cp_config_t ** cp_config);

/*
 * EP11 specific return codes
 */
#define CKR_IBM_WKID_MISMATCH       CKR_VENDOR_DEFINED + 0x00010001
#define CKR_IBM_INTERNAL_ERROR      CKR_VENDOR_DEFINED + 0x00010002
#define CKR_IBM_TRANSPORT_ERROR     CKR_VENDOR_DEFINED + 0x00010003
#define CKR_IBM_BLOB_ERROR          CKR_VENDOR_DEFINED + 0x00010004
#define CKR_IBM_BLOBKEY_CONFLICT    CKR_VENDOR_DEFINED + 0x00010005
#define CKR_IBM_MODE_CONFLICT       CKR_VENDOR_DEFINED + 0x00010006
#define CKR_IBM_NONCRT_KEY_SIZE     CKR_VENDOR_DEFINED + 0x00010008
#define CKR_IBM_WK_NOT_INITIALIZED  CKR_VENDOR_DEFINED + 0x00010009
#define CKR_IBM_OA_API_ERROR        CKR_VENDOR_DEFINED + 0x0001000a
#define CKR_IBM_REQ_TIMEOUT         CKR_VENDOR_DEFINED + 0x0001000b
#define CKR_IBM_READONLY            CKR_VENDOR_DEFINED + 0x0001000c
#define CKR_IBM_STATIC_POLICY       CKR_VENDOR_DEFINED + 0x0001000d
#define CKR_IBM_TRANSPORT_LIMIT     CKR_VENDOR_DEFINED + 0x00010010

static CK_RV ep11_error_to_pkcs11_error(CK_RV rc, SESSION *session)
{
    if (rc < CKR_VENDOR_DEFINED)
        return rc;

    TRACE_ERROR("%s ep11 specific error: rc=0x%lx\n", __func__, rc);

    if (session != NULL)
        session->session_info.ulDeviceError = rc;

    switch (rc) {
    case CKR_IBM_INTERNAL_ERROR:
    case CKR_IBM_TRANSPORT_ERROR:
    case CKR_IBM_OA_API_ERROR:
    case CKR_IBM_TRANSPORT_LIMIT:
    case CKR_IBM_REQ_TIMEOUT:
        return CKR_FUNCTION_FAILED;
    case CKR_IBM_WKID_MISMATCH:
    case CKR_IBM_WK_NOT_INITIALIZED:
        return CKR_DEVICE_ERROR;
    case CKR_IBM_STATIC_POLICY:
        return CKR_KEY_SIZE_RANGE;
    case CKR_IBM_READONLY:
        return CKR_ARGUMENTS_BAD;
    case CKR_IBM_BLOB_ERROR:
    case CKR_IBM_BLOBKEY_CONFLICT:
        return CKR_ENCRYPTED_DATA_INVALID;
    case CKR_IBM_MODE_CONFLICT:
    case CKR_IBM_NONCRT_KEY_SIZE:
        return CKR_ARGUMENTS_BAD;
    default:
        return CKR_FUNCTION_FAILED;
    }
}

/* import a DES/AES key, that is, make a blob for a DES/AES key
 * that was not created by EP11 hardware, encrypt the key by the wrap key,
 * unwrap it by the wrap key
 */
static CK_RV rawkey_2_blob(STDLL_TokData_t * tokdata, SESSION * sess,
                           unsigned char *key,
                           CK_ULONG ksize, CK_KEY_TYPE ktype,
                           unsigned char *blob, size_t * blen, OBJECT * key_obj)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG clen = sizeof(cipher);
    CK_BYTE csum[MAX_CSUMSIZE];
    size_t cslen = sizeof(csum);
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    DL_NODE *node = key_obj->template->attribute_list;
    CK_RV rc;
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;

    /* tell ep11 the attributes the user specified */
    node = key_obj->template->attribute_list;
    while (node != NULL) {
        CK_ATTRIBUTE_PTR a = node->data;

        /* ep11 handles this as 'read only' and reports
         * an error if specified
         */
        if (CKA_NEVER_EXTRACTABLE == a->type || CKA_MODIFIABLE == a->type
            || CKA_LOCAL == a->type) {
            ;
        } else {
            rc = add_to_attribute_array(&p_attrs, &attrs_len,
                                        a->type, a->pValue, a->ulValueLen);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s adding attribute failed type=0x%lx rc=0x%lx\n",
                            __func__, a->type, rc);
                goto rawkey_2_blob_end;
            }
        }

        node = node->next;
    }

    memset(cipher, 0, sizeof(cipher));
    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /*
     * calls the ep11 lib (which in turns sends the request to the card),
     * all m_ function are ep11 functions
     */
    RETRY_START
        rc = dll_m_EncryptSingle(ep11_data->raw2key_wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, &mech, key,
                                 ksize, cipher, &clen,
                                 (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s encrypt ksize=0x%lx clen=0x%lx rc=0x%lx\n",
                    __func__, ksize, clen, rc);
        goto rawkey_2_blob_end;
    }
    TRACE_INFO("%s encrypt ksize=0x%lx clen=0x%lx rc=0x%lx\n",
               __func__, ksize, clen, rc);

    rc = check_key_attributes(tokdata, ktype, CKO_SECRET_KEY, p_attrs,
                              attrs_len, &new_p_attrs, &new_attrs_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s RSA/EC check private key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        return rc;
    }

    ep11_get_pin_blob(ep11_session, object_is_session_object(key_obj),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    /* the encrypted key is decrypted and a blob is build,
     * card accepts only blobs as keys
     */
    RETRY_START
        rc = dll_m_UnwrapKey(cipher, clen, ep11_data->raw2key_wrap_blob,
                             ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                             ep11_pin_blob, ep11_pin_blob_len, &mech,
                             new_p_attrs, new_attrs_len, blob, blen, csum,
                             &cslen, (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s unwrap blen=%zd rc=0x%lx\n", __func__, *blen, rc);
    } else {
        TRACE_INFO("%s unwrap blen=%zd rc=0x%lx\n", __func__, *blen, rc);
    }

rawkey_2_blob_end:
    if (p_attrs != NULL)
        free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        free_attribute_array(new_p_attrs, new_attrs_len);
    return rc;
}

/* random number generator */
CK_RV token_specific_rng(STDLL_TokData_t * tokdata, CK_BYTE * output,
                         CK_ULONG bytes)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    CK_RV rc = dll_m_GenerateRandom(output, bytes,
                                    (uint64_t) ep11_data->target_list);
    if (rc != CKR_OK)
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s output=%p bytes=%lu rc=0x%lx\n",
                    __func__, (void *)output, bytes, rc);
    return rc;
}

/*
 * for importing keys we need to encrypt the keys and build the blob by
 * m_UnwrapKey, use one wrap key for this purpose, can be any key,
 * we use an AES key
 */
static CK_RV make_wrapblob(STDLL_TokData_t * tokdata, CK_ATTRIBUTE * tmpl_in,
                           CK_ULONG tmpl_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_MECHANISM mech = { CKM_AES_KEY_GEN, NULL_PTR, 0 };
    CK_BYTE csum[MAX_CSUMSIZE];
    size_t csum_l = sizeof(csum);
    CK_RV rc;

    if (ep11_data->raw2key_wrap_blob_l != 0) {
        TRACE_INFO("%s blob already exists raw2key_wrap_blob_l=0x%zx\n",
                   __func__, ep11_data->raw2key_wrap_blob_l);
        return CKR_OK;
    }

    ep11_data->raw2key_wrap_blob_l = sizeof(ep11_data->raw2key_wrap_blob);
    rc = dll_m_GenerateKey(&mech, tmpl_in, tmpl_len, NULL, 0,
                           ep11_data->raw2key_wrap_blob,
                           &ep11_data->raw2key_wrap_blob_l, csum, &csum_l,
                           (uint64_t) ep11_data->target_list);


    if (rc != CKR_OK) {
        TRACE_ERROR("%s end raw2key_wrap_blob_l=0x%zx rc=0x%lx\n",
                    __func__, ep11_data->raw2key_wrap_blob_l, rc);
    } else {
        TRACE_INFO("%s end raw2key_wrap_blob_l=0x%zx rc=0x%lx\n",
                   __func__, ep11_data->raw2key_wrap_blob_l, rc);
    }

    return rc;
}

static CK_RV ep11_resolve_lib_sym(void *hdl)
{
    char *error = NULL;

    dlerror();                  /* Clear existing error */

    *(void **)(&dll_m_GenerateRandom) = dlsym(hdl, "m_GenerateRandom");
    *(void **)(&dll_m_SeedRandom) = dlsym(hdl, "m_SeedRandom");

    *(void **)(&dll_m_Digest) = dlsym(hdl, "m_Digest");
    *(void **)(&dll_m_DigestInit) = dlsym(hdl, "m_DigestInit");
    *(void **)(&dll_m_DigestUpdate) = dlsym(hdl, "m_DigestUpdate");
    *(void **)(&dll_m_DigestFinal) = dlsym(hdl, "m_DigestFinal");
    *(void **)(&dll_m_DigestKey) = dlsym(hdl, "m_DigestKey");
    *(void **)(&dll_m_DigestSingle) = dlsym(hdl, "m_DigestSingle");

    *(void **)(&dll_m_Encrypt) = dlsym(hdl, "m_Encrypt");
    *(void **)(&dll_m_EncryptInit) = dlsym(hdl, "m_EncryptInit");
    *(void **)(&dll_m_EncryptUpdate) = dlsym(hdl, "m_EncryptUpdate");
    *(void **)(&dll_m_EncryptFinal) = dlsym(hdl, "m_EncryptFinal");
    *(void **)(&dll_m_EncryptSingle) = dlsym(hdl, "m_EncryptSingle");

    *(void **)(&dll_m_Decrypt) = dlsym(hdl, "m_Decrypt");
    *(void **)(&dll_m_DecryptInit) = dlsym(hdl, "m_DecryptInit");
    *(void **)(&dll_m_DecryptUpdate) = dlsym(hdl, "m_DecryptUpdate");
    *(void **)(&dll_m_DecryptFinal) = dlsym(hdl, "m_DecryptFinal");
    *(void **)(&dll_m_DecryptSingle) = dlsym(hdl, "m_DecryptSingle");

    *(void **)(&dll_m_ReencryptSingle) = dlsym(hdl, "m_ReencryptSingle");
    *(void **)(&dll_m_GenerateKey) = dlsym(hdl, "m_GenerateKey");
    *(void **)(&dll_m_GenerateKeyPair) = dlsym(hdl, "m_GenerateKeyPair");

    *(void **)(&dll_m_Sign) = dlsym(hdl, "m_Sign");
    *(void **)(&dll_m_SignInit) = dlsym(hdl, "m_SignInit");
    *(void **)(&dll_m_SignUpdate) = dlsym(hdl, "m_SignUpdate");
    *(void **)(&dll_m_SignFinal) = dlsym(hdl, "m_SignFinal");
    *(void **)(&dll_m_SignSingle) = dlsym(hdl, "m_SignSingle");

    *(void **)(&dll_m_Verify) = dlsym(hdl, "m_Verify");
    *(void **)(&dll_m_VerifyInit) = dlsym(hdl, "m_VerifyInit");
    *(void **)(&dll_m_VerifyUpdate) = dlsym(hdl, "m_VerifyUpdate");
    *(void **)(&dll_m_VerifyFinal) = dlsym(hdl, "m_VerifyFinal");
    *(void **)(&dll_m_VerifySingle) = dlsym(hdl, "m_VerifySingle");

    *(void **)(&dll_m_WrapKey) = dlsym(hdl, "m_WrapKey");
    *(void **)(&dll_m_UnwrapKey) = dlsym(hdl, "m_UnwrapKey");
    *(void **)(&dll_m_DeriveKey) = dlsym(hdl, "m_DeriveKey");

    *(void **)(&dll_m_GetMechanismList) = dlsym(hdl, "m_GetMechanismList");
    *(void **)(&dll_m_GetMechanismInfo) = dlsym(hdl, "m_GetMechanismInfo");
    *(void **)(&dll_m_GetAttributeValue) = dlsym(hdl, "m_GetAttributeValue");
    *(void **)(&dll_m_SetAttributeValue) = dlsym(hdl, "m_SetAttributeValue");

    *(void **)(&dll_m_Login) = dlsym(hdl, "m_Login");
    *(void **)(&dll_m_Logout) = dlsym(hdl, "m_Logout");
    *(void **)(&dll_m_admin) = dlsym(hdl, "m_admin");

    *(void **)(&dll_m_init) = dlsym(hdl, "m_init");
    *(void **)(&dll_m_add_backend) = dlsym(hdl, "m_add_backend");
    *(void **)(&dll_m_shutdown) = dlsym(hdl, "m_shutdown");

    *(void **)(&dll_xcpa_queryblock) = dlsym(hdl, "xcpa_queryblock");
    *(void **)(&dll_xcpa_internal_rv) = dlsym(hdl, "xcpa_internal_rv");

    *(void **)(&dll_m_get_xcp_info) = dlsym(hdl, "m_get_xcp_info");

    if ((error = dlerror()) != NULL) {
        TRACE_ERROR("%s Error: %s\n", __func__, error);
        OCK_SYSLOG(LOG_ERR, "%s: Error: %s\n", __func__, error);
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV ep11tok_load_libica(STDLL_TokData_t *tokdata)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    libica_t *libica = &ep11_data->libica;
    int default_libica = 0;
    char *errstr;

    if (ep11_data->digest_libica == 0)
        return CKR_OK;

    if (strcmp(ep11_data->digest_libica_path, "") == 0) {
        strcpy(ep11_data->digest_libica_path, ICASHAREDLIB);
        default_libica = 1;
    }

    libica->library = dlopen(ep11_data->digest_libica_path,
                             RTLD_GLOBAL | RTLD_NOW);
    if (libica->library == NULL) {
        errstr = dlerror();
        OCK_SYSLOG(default_libica ? LOG_WARNING : LOG_ERR,
               "%s: Error loading shared library '%s' [%s]\n",
               __func__, ep11_data->digest_libica_path, errstr);
        TRACE_ERROR("%s Error loading shared library '%s' [%s]\n",
                __func__, ep11_data->digest_libica_path, errstr);
        ep11_data->digest_libica = 0;
        return default_libica ? CKR_OK : CKR_FUNCTION_FAILED;
    }

    *(void **)(&libica->ica_sha1) = dlsym(libica->library, "ica_sha1");
    *(void **)(&libica->ica_sha224) = dlsym(libica->library, "ica_sha224");
    *(void **)(&libica->ica_sha256) = dlsym(libica->library, "ica_sha256");
    *(void **)(&libica->ica_sha384) = dlsym(libica->library, "ica_sha384");
    *(void **)(&libica->ica_sha512) = dlsym(libica->library, "ica_sha512");
    *(void **)(&libica->ica_sha512_224) =
        dlsym(libica->library, "ica_sha512_224");
    *(void **)(&libica->ica_sha512_256) =
        dlsym(libica->library, "ica_sha512_256");
    /* No error checking, each of the libica functions is allowed to be NULL */

    TRACE_DEVEL("%s: Loaded libica from '%s'\n", __func__,
                ep11_data->digest_libica_path);
    return CKR_OK;
}

CK_RV ep11tok_init(STDLL_TokData_t * tokdata, CK_SLOT_ID SlotNumber,
                   char *conf_name)
{
    CK_RV rc;
    void *lib_ep11;
    CK_ULONG len = 16;
    CK_BBOOL cktrue = 1;
    CK_ATTRIBUTE wrap_tmpl[] = { {CKA_VALUE_LEN, &len, sizeof(CK_ULONG)}
    ,
    {CKA_WRAP, (void *) &cktrue, sizeof(cktrue)}
    ,
    {CKA_UNWRAP, (void *) &cktrue, sizeof(cktrue)}
    ,
    {CKA_ENCRYPT, (void *) &cktrue, sizeof(cktrue)}
    ,
    {CKA_DECRYPT, (void *) &cktrue, sizeof(cktrue)}
    ,
    {CKA_EXTRACTABLE, (void *) &cktrue, sizeof(cktrue)}
    ,
    {CKA_LABEL, (void *) wrap_key_name, sizeof(wrap_key_name)}
    ,
    {CKA_TOKEN, (void *) &cktrue, sizeof(cktrue)}
    };
    ep11_private_data_t *ep11_data;

    TRACE_INFO("ep11 %s slot=%lu running\n", __func__, SlotNumber);

    ep11_data = calloc(1, sizeof(ep11_private_data_t));
    if (ep11_data == NULL)
        return CKR_HOST_MEMORY;
    ep11_data->target_list = calloc(1, sizeof(ep11_target_t));
    if (ep11_data->target_list == NULL) {
        free(ep11_data);
        return CKR_HOST_MEMORY;
    }

    tokdata->private_data = ep11_data;

    /* read ep11 specific config file with user specified
     * adapter/domain pairs */
    rc = read_adapter_config_file(tokdata, conf_name);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ep11 config file error rc=0x%lx\n", __func__, rc);
        rc = CKR_GENERAL_ERROR;
        goto error;
    }

    /* dynamically load in the ep11 shared library */
    lib_ep11 = dlopen(EP11SHAREDLIB, RTLD_GLOBAL | RTLD_NOW);
    if (!lib_ep11) {
        OCK_SYSLOG(LOG_ERR,
                   "%s: Error loading shared library '%s' [%s]\n",
                   __func__, EP11SHAREDLIB, dlerror());
        TRACE_ERROR("%s Error loading shared library '%s' [%s]\n",
                    __func__, EP11SHAREDLIB, dlerror());
        rc = CKR_FUNCTION_FAILED;
        goto error;
    }

    rc = ep11_resolve_lib_sym(lib_ep11);
    if (rc != CKR_OK)
        goto error;

#ifndef XCP_STANDALONE
    /* call ep11 shared lib init */
    if (dll_m_init() < 0) {
        TRACE_ERROR("%s ep11 lib init failed\n", __func__);
        OCK_SYSLOG(LOG_ERR,
                   "%s: Error: EP 11 library initialization failed\n",
                   __func__);
        rc = CKR_DEVICE_ERROR;
        goto error;
    }
#endif

    rc = ep11tok_get_ep11_version(tokdata);
    if (rc != CKR_OK)
        goto error;

    if (ep11_data->digest_libica) {
        rc = ep11tok_load_libica(tokdata);
        if (rc != CKR_OK)
            goto error;
    }

    ep11_data->control_points_len = sizeof(ep11_data->control_points);
    rc = get_control_points(tokdata, ep11_data->control_points,
                            &ep11_data->control_points_len,
                            &ep11_data->max_control_point_index);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to get the control points (get_control_points "
                    "rc=0x%lx)\n", __func__, rc);
        OCK_SYSLOG(LOG_ERR, "%s: Failed to get the control points rc=0x%lx\n",
                   __func__, rc);
        goto error;
    }

    /* create an AES key needed for importing keys
     * (encrypt by wrap_key and m_UnwrapKey by wrap key)
     */
    rc = make_wrapblob(tokdata, wrap_tmpl, 8);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s make_wrapblob failed rc=0x%lx\n", __func__, rc);
        if (rc == CKR_IBM_WK_NOT_INITIALIZED) {
            TRACE_ERROR("%s rc is CKR_IBM_WK_NOT_INITIALIZED, "
                        "no master key set ?\n", __func__);
            OCK_SYSLOG(LOG_ERR,
                       "%s: Error: CKR_IBM_WK_NOT_INITIALIZED occurred, no "
                       "master key set ?\n", __func__);
        }
        if (rc == CKR_FUNCTION_CANCELED) {
            TRACE_ERROR("%s rc is CKR_FUNCTION_CANCELED, "
                        "control point 13 (generate or derive symmetric "
                        "keys including DSA parameters) disabled ?\n",
                        __func__);
            OCK_SYSLOG(LOG_ERR,
                       "%s: Error: CKR_FUNCTION_CANCELED occurred, "
                       "control point 13 (generate or derive symmetric "
                       "keys including DSA parameters) disabled ?\n", __func__);
        }
        rc = CKR_GENERAL_ERROR;
        goto error;
    }

    TRACE_INFO("%s init done successfully\n", __func__);
    return CKR_OK;

error:
    ep11tok_final(tokdata);
    TRACE_INFO("%s init failed with rc: 0x%lx\n", __func__, rc);
    return rc;
}

CK_RV ep11tok_final(STDLL_TokData_t * tokdata)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    TRACE_INFO("ep11 %s running\n", __func__);

    if (ep11_data != NULL) {
        if (ep11_data->target_list)
            free(ep11_data->target_list);
        free_cp_config(ep11_data->cp_config);
        free_card_versions(ep11_data->card_versions);
        free(ep11_data);
        tokdata->private_data = NULL;
    }

    return CKR_OK;
}


/*
 * makes blobs for private imported RSA keys and
 * SPKIs for public imported RSA keys.
 * Similar to rawkey_2_blob, but keys must follow a standard BER encoding.
 */
static CK_RV import_RSA_key(STDLL_TokData_t * tokdata, SESSION * sess,
                            OBJECT * rsa_key_obj,
                            CK_BYTE * blob, size_t * blob_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech_w = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG cipher_l = sizeof(cipher);
    DL_NODE *node;
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_BYTE csum[MAX_BLOBSIZE];
    CK_ULONG cslen = sizeof(csum);
    CK_OBJECT_CLASS class;
    CK_BYTE *data = NULL;
    CK_ULONG data_len;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;

    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /* need class for private/public key info */
    if (!template_attribute_find(rsa_key_obj->template, CKA_CLASS, &attr)) {
        TRACE_ERROR("%s no CKA_CLASS\n", __func__);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* m_Unwrap builds key blob in the card,
     * tell ep11 the attributes the user specified for that key.
     */
    node = rsa_key_obj->template->attribute_list;
    while (node != NULL) {
        CK_ATTRIBUTE_PTR a = node->data;

        /* ep11 handles this as 'read only' */
        if (CKA_NEVER_EXTRACTABLE == a->type ||
            CKA_MODIFIABLE == a->type || CKA_LOCAL == a->type) {
            ;
        } else {
            rc = add_to_attribute_array(&p_attrs, &attrs_len,
                                        a->type, a->pValue, a->ulValueLen);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s adding attribute failed type=0x%lx rc=0x%lx\n",
                            __func__, a->type, rc);
                goto import_RSA_key_end;
            }
        }

        node = node->next;
    }

    class = *(CK_OBJECT_CLASS *) attr->pValue;

    if (class != CKO_PRIVATE_KEY) {

        /* an imported public RSA key, we need a SPKI for it. */

        CK_ATTRIBUTE *modulus;
        CK_ATTRIBUTE *publ_exp;

        if (!template_attribute_find(rsa_key_obj->template,
                                     CKA_MODULUS, &modulus)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_RSA_key_end;
        }
        if (!template_attribute_find(rsa_key_obj->template,
                                     CKA_PUBLIC_EXPONENT, &publ_exp)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_RSA_key_end;
        }

        /* our contribution to asn1.c,
         * builds the BER encoding that is a SPKI.
         */
        rc = ber_encode_RSAPublicKey(0, &data, &data_len, modulus, publ_exp);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s public key import class=0x%lx rc=0x%lx "
                        "data_len=0x%lx\n", __func__, class, rc, data_len);
            goto import_RSA_key_end;
        } else {
            TRACE_INFO("%s public key import class=0x%lx rc=0x%lx "
                       "data_len=0x%lx\n", __func__, class, rc, data_len);
        }

        /* save the SPKI as blob although it is not a blob.
         * The card expects SPKIs as public keys.
         */
        memcpy(blob, data, data_len);
        *blob_size = data_len;

    } else {

        /* imported private RSA key goes here */

        /* extract the secret data to be wrapped
         * since this is AES_CBC_PAD, padding is done in mechanism.
         */
        rc = rsa_priv_wrap_get_data(rsa_key_obj->template, FALSE,
                                    &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("%s RSA wrap get data failed\n", __func__);
            goto import_RSA_key_end;
        }

        /* encrypt */
        RETRY_START
            rc = dll_m_EncryptSingle(ep11_data->raw2key_wrap_blob,
                                     ep11_data->raw2key_wrap_blob_l, &mech_w,
                                     data, data_len, cipher, &cipher_l,
                                     (uint64_t) ep11_data->target_list);
        RETRY_END(rc, tokdata, sess)

        TRACE_INFO("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                   __func__, rc, cipher_l);

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                        __func__, rc, cipher_l);
            goto import_RSA_key_end;
        }

        rc = check_key_attributes(tokdata, CKK_RSA, CKO_PRIVATE_KEY, p_attrs,
                                  attrs_len, &new_p_attrs, &new_attrs_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s RSA/EC check private key attributes failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto import_RSA_key_end;
        }

        ep11_get_pin_blob(ep11_session, object_is_session_object(rsa_key_obj),
                          &ep11_pin_blob, &ep11_pin_blob_len);

        /* calls the card, it decrypts the private RSA key,
         * reads its BER format and builds a blob.
         */
        RETRY_START
            rc = dll_m_UnwrapKey(cipher, cipher_l, ep11_data->raw2key_wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                                 ep11_pin_blob, ep11_pin_blob_len, &mech_w,
                                 new_p_attrs, new_attrs_len, blob, blob_size,
                                 csum, &cslen,
                                 (uint64_t) ep11_data->target_list);
        RETRY_END(rc, tokdata, sess)

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                        __func__, rc, *blob_size);
        } else {
            TRACE_INFO("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                       __func__, rc, *blob_size);
        }

        cleanse_attribute(rsa_key_obj->template, CKA_PRIVATE_EXPONENT);
        cleanse_attribute(rsa_key_obj->template, CKA_PRIME_1);
        cleanse_attribute(rsa_key_obj->template, CKA_PRIME_2);
        cleanse_attribute(rsa_key_obj->template, CKA_EXPONENT_1);
        cleanse_attribute(rsa_key_obj->template, CKA_EXPONENT_2);
        cleanse_attribute(rsa_key_obj->template, CKA_COEFFICIENT);
    }

import_RSA_key_end:
    if (data) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    if (p_attrs != NULL)
        cleanse_and_free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        cleanse_and_free_attribute_array(new_p_attrs, new_attrs_len);
    return rc;
}

/*
 * makes blobs for private imported EC keys and
 * SPKIs for public imported EC keys.
 * Similar to rawkey_2_blob, but keys must follow a standard BER encoding.
 */
static CK_RV import_EC_key(STDLL_TokData_t * tokdata, SESSION * sess,
                           OBJECT * ec_key_obj,
                           CK_BYTE * blob, size_t * blob_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech_w = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG cipher_l = sizeof(cipher);
    DL_NODE *node;
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_BYTE csum[MAX_BLOBSIZE];
    CK_ULONG cslen = sizeof(csum);
    CK_OBJECT_CLASS class;
    CK_BYTE *data = NULL;
    CK_ULONG data_len;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;

    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /* need class for private/public key info */
    if (!template_attribute_find(ec_key_obj->template, CKA_CLASS, &attr)) {
        TRACE_ERROR("%s no CKA_CLASS\n", __func__);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* m_Unwrap builds key blob in the card,
     * tell ep11 the attributes the user specified for that key.
     */
    node = ec_key_obj->template->attribute_list;
    while (node != NULL) {
        CK_ATTRIBUTE_PTR a = node->data;

        /* ep11 handles this as 'read only' */
        if (CKA_NEVER_EXTRACTABLE == a->type ||
            CKA_MODIFIABLE == a->type || CKA_LOCAL == a->type) {
            ;
        } else {
            rc = add_to_attribute_array(&p_attrs, &attrs_len,
                                        a->type, a->pValue, a->ulValueLen);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s adding attribute failed type=0x%lx rc=0x%lx\n",
                            __func__, a->type, rc);
                goto import_EC_key_end;
            }
        }

        node = node->next;
    }

    class = *(CK_OBJECT_CLASS *) attr->pValue;

    if (class != CKO_PRIVATE_KEY) {

        /* an imported public EC key, we need a SPKI for it. */

        CK_ATTRIBUTE *ec_params;
        CK_ATTRIBUTE *ec_point;

        if (!template_attribute_find(ec_key_obj->template,
                                     CKA_EC_PARAMS, &ec_params)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_EC_key_end;
        }
        if (!template_attribute_find(ec_key_obj->template,
                                     CKA_EC_POINT, &ec_point)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_EC_key_end;
        }

        /*
         * Builds the DER encoding (ansi_x962) SPKI.
         * (get the length first)
         */
        rc = ber_encode_ECPublicKey(TRUE, &data, &data_len,
                                    ec_params, ec_point);
        data = malloc(data_len);

        rc = ber_encode_ECPublicKey(FALSE, &data, &data_len,
                                    ec_params, ec_point);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s public key import class=0x%lx rc=0x%lx "
                        "data_len=0x%lx\n", __func__, class, rc, data_len);
            goto import_EC_key_end;
        } else {
            TRACE_INFO("%s public key import class=0x%lx rc=0x%lx "
                       "data_len=0x%lx\n", __func__, class, rc, data_len);
        }

        /* save the SPKI as blob although it is not a blob.
         * The card expects SPKIs as public keys.
         */
        memcpy(blob, data, data_len);
        *blob_size = data_len;

    } else {

        /* imported private EC key goes here */

        /* extract the secret data to be wrapped
         * since this is AES_CBC_PAD, padding is done in mechanism.
         */
        rc = ecdsa_priv_wrap_get_data(ec_key_obj->template, FALSE,
                                      &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("%s EC wrap get data failed\n", __func__);
            goto import_EC_key_end;
        }

        /* encrypt */
        RETRY_START
            rc = dll_m_EncryptSingle(ep11_data->raw2key_wrap_blob,
                                     ep11_data->raw2key_wrap_blob_l,
                                     &mech_w, data, data_len,
                                     cipher, &cipher_l,
                                     (uint64_t) ep11_data->target_list);
        RETRY_END(rc, tokdata, sess)

        TRACE_INFO("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                   __func__, rc, cipher_l);

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                        __func__, rc, cipher_l);
            goto import_EC_key_end;
        }

        rc = check_key_attributes(tokdata, CKK_EC, CKO_PRIVATE_KEY, p_attrs,
                                  attrs_len, &new_p_attrs, &new_attrs_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s EC check private key attributes failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto import_EC_key_end;
        }

        ep11_get_pin_blob(ep11_session, object_is_session_object(ec_key_obj),
                          &ep11_pin_blob, &ep11_pin_blob_len);

        /* calls the card, it decrypts the private EC key,
         * reads its BER format and builds a blob.
         */
        RETRY_START
            rc = dll_m_UnwrapKey(cipher, cipher_l,
                                 ep11_data->raw2key_wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                                 ep11_pin_blob,
                                 ep11_pin_blob_len, &mech_w,
                                 new_p_attrs, new_attrs_len, blob,
                                 blob_size, csum, &cslen,
                                 (uint64_t) ep11_data->target_list);
        RETRY_END(rc, tokdata, sess)

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                        __func__, rc, *blob_size);
        } else {
            TRACE_INFO("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                       __func__, rc, *blob_size);
        }

        cleanse_attribute(ec_key_obj->template, CKA_VALUE);
    }

import_EC_key_end:
    if (data) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    if (p_attrs != NULL)
        cleanse_and_free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        cleanse_and_free_attribute_array(new_p_attrs, new_attrs_len);
    return rc;
}

/*
 * makes blobs for private imported DSA keys and
 * SPKIs for public imported DSA keys.
 * Similar to rawkey_2_blob, but keys must follow a standard BER encoding.
 */
static CK_RV import_DSA_key(STDLL_TokData_t * tokdata, SESSION * sess,
                            OBJECT * dsa_key_obj,
                            CK_BYTE * blob, size_t * blob_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech_w = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG cipher_l = sizeof(cipher);
    DL_NODE *node;
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_BYTE csum[MAX_BLOBSIZE];
    CK_ULONG cslen = sizeof(csum);
    CK_OBJECT_CLASS class;
    CK_BYTE *data = NULL;
    CK_ULONG data_len;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;

    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /* need class for private/public key info */
    if (!template_attribute_find(dsa_key_obj->template, CKA_CLASS, &attr)) {
        TRACE_ERROR("%s no CKA_CLASS\n", __func__);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* m_Unwrap builds key blob in the card,
     * tell ep11 the attributes the user specified for that key.
     */
    node = dsa_key_obj->template->attribute_list;
    while (node != NULL) {
        CK_ATTRIBUTE_PTR a = node->data;

        /* ep11 handles this as 'read only' */
        if (CKA_NEVER_EXTRACTABLE == a->type ||
            CKA_MODIFIABLE == a->type || CKA_LOCAL == a->type) {
            ;
        } else {
            rc = add_to_attribute_array(&p_attrs, &attrs_len,
                                        a->type, a->pValue, a->ulValueLen);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s adding attribute failed type=0x%lx rc=0x%lx\n",
                            __func__, a->type, rc);
                goto import_DSA_key_end;
            }
        }

        node = node->next;
    }

    class = *(CK_OBJECT_CLASS *) attr->pValue;

    if (class != CKO_PRIVATE_KEY) {

        /* an imported public DSA key, we need a SPKI for it. */

        CK_ATTRIBUTE *prime;
        CK_ATTRIBUTE *subprime;
        CK_ATTRIBUTE *base;
        CK_ATTRIBUTE *value;

        if (!template_attribute_find(dsa_key_obj->template,
                                     CKA_PRIME, &prime)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_DSA_key_end;
        }
        if (!template_attribute_find(dsa_key_obj->template,
                                     CKA_SUBPRIME, &subprime)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_DSA_key_end;
        }
        if (!template_attribute_find(dsa_key_obj->template, CKA_BASE, &base)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_DSA_key_end;
        }
        if (!template_attribute_find(dsa_key_obj->template,
                                     CKA_VALUE, &value)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_DSA_key_end;
        }

        /*
         * Builds the DER encoding (ansi_x962) SPKI.
         * (get the length first)
         */
        rc = ber_encode_DSAPublicKey(TRUE, &data, &data_len,
                                     prime, subprime, base, value);
        data = malloc(data_len);

        rc = ber_encode_DSAPublicKey(FALSE, &data, &data_len,
                                     prime, subprime, base, value);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s public key import class=0x%lx rc=0x%lx "
                        "data_len=0x%lx\n", __func__, class, rc, data_len);
            goto import_DSA_key_end;
        } else {
            TRACE_INFO("%s public key import class=0x%lx rc=0x%lx "
                       "data_len=0x%lx\n", __func__, class, rc, data_len);
        }

        /* save the SPKI as blob although it is not a blob.
         * The card expects SPKIs as public keys.
         */
        memcpy(blob, data, data_len);
        *blob_size = data_len;

    } else {

        /* imported private DSA key goes here */

        /* extract the secret data to be wrapped
         * since this is AES_CBC_PAD, padding is done in mechanism.
         */
        rc = dsa_priv_wrap_get_data(dsa_key_obj->template, FALSE,
                                    &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("%s DSA wrap get data failed\n", __func__);
            goto import_DSA_key_end;
        }

        /* encrypt */
        RETRY_START
            rc = dll_m_EncryptSingle(ep11_data->raw2key_wrap_blob,
                                     ep11_data->raw2key_wrap_blob_l,
                                     &mech_w, data, data_len,
                                     cipher, &cipher_l,
                                     (uint64_t) ep11_data->target_list);
        RETRY_END(rc, tokdata, sess)


        TRACE_INFO("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                   __func__, rc, cipher_l);

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                        __func__, rc, cipher_l);
            goto import_DSA_key_end;
        }

        rc = check_key_attributes(tokdata, CKK_DSA, CKO_PRIVATE_KEY, p_attrs,
                                  attrs_len, &new_p_attrs, &new_attrs_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s DSA check private key attributes failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto import_DSA_key_end;
        }

        ep11_get_pin_blob(ep11_session, object_is_session_object(dsa_key_obj),
                          &ep11_pin_blob, &ep11_pin_blob_len);

        /* calls the card, it decrypts the private EC key,
         * reads its BER format and builds a blob.
         */
        RETRY_START
            rc = dll_m_UnwrapKey(cipher, cipher_l,
                                 ep11_data->raw2key_wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                                 ep11_pin_blob,
                                 ep11_pin_blob_len, &mech_w,
                                 new_p_attrs, new_attrs_len, blob,
                                 blob_size, csum, &cslen,
                                 (uint64_t) ep11_data->target_list);
        RETRY_END(rc, tokdata, sess)

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                        __func__, rc, *blob_size);
        } else {
            TRACE_INFO("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                       __func__, rc, *blob_size);
        }

        cleanse_attribute(dsa_key_obj->template, CKA_VALUE);
    }

import_DSA_key_end:
    if (data) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    if (p_attrs != NULL)
        cleanse_and_free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        cleanse_and_free_attribute_array(new_p_attrs, new_attrs_len);
    return rc;
}

/*
 * makes blobs for private imported DH keys and
 * SPKIs for public imported DH keys.
 * Similar to rawkey_2_blob, but keys must follow a standard BER encoding.
 */
static CK_RV import_DH_key(STDLL_TokData_t * tokdata, SESSION * sess,
                           OBJECT * dh_key_obj,
                           CK_BYTE * blob, size_t * blob_size)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE iv[AES_BLOCK_SIZE];
    CK_MECHANISM mech_w = { CKM_AES_CBC_PAD, iv, AES_BLOCK_SIZE };
    CK_BYTE cipher[MAX_BLOBSIZE];
    CK_ULONG cipher_l = sizeof(cipher);
    DL_NODE *node;
    CK_ATTRIBUTE_PTR p_attrs = NULL;
    CK_ULONG attrs_len = 0;
    CK_ATTRIBUTE_PTR new_p_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_BYTE csum[MAX_BLOBSIZE];
    CK_ULONG cslen = sizeof(csum);
    CK_OBJECT_CLASS class;
    CK_BYTE *data = NULL;
    CK_ULONG data_len;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;

    memcpy(iv, "1234567812345678", AES_BLOCK_SIZE);

    /* need class for private/public key info */
    if (!template_attribute_find(dh_key_obj->template, CKA_CLASS, &attr)) {
        TRACE_ERROR("%s no CKA_CLASS\n", __func__);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    /* m_Unwrap builds key blob in the card,
     * tell ep11 the attributes the user specified for that key.
     */
    node = dh_key_obj->template->attribute_list;
    while (node != NULL) {
        CK_ATTRIBUTE_PTR a = node->data;

        /* ep11 handles this as 'read only' */
        if (CKA_NEVER_EXTRACTABLE == a->type ||
            CKA_MODIFIABLE == a->type || CKA_LOCAL == a->type) {
            ;
        } else {
            rc = add_to_attribute_array(&p_attrs, &attrs_len,
                                        a->type, a->pValue, a->ulValueLen);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s adding attribute failed type=0x%lx rc=0x%lx\n",
                            __func__, a->type, rc);
                goto import_DH_key_end;
            }
        }

        node = node->next;
    }

    class = *(CK_OBJECT_CLASS *) attr->pValue;

    if (class != CKO_PRIVATE_KEY) {

        /* an imported public DH key, we need a SPKI for it. */

        CK_ATTRIBUTE *prime;
        CK_ATTRIBUTE *base;
        CK_ATTRIBUTE *value;

        if (!template_attribute_find(dh_key_obj->template, CKA_PRIME, &prime)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_DH_key_end;
        }
        if (!template_attribute_find(dh_key_obj->template, CKA_BASE, &base)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_DH_key_end;
        }
        if (!template_attribute_find(dh_key_obj->template, CKA_VALUE, &value)) {
            rc = CKR_TEMPLATE_INCOMPLETE;
            goto import_DH_key_end;
        }

        /*
         * Builds the DER encoding (ansi_x962) SPKI.
         * (get the length first)
         */
        rc = ber_encode_DHPublicKey(TRUE, &data, &data_len, prime, base, value);
        data = malloc(data_len);

        rc = ber_encode_DHPublicKey(FALSE, &data, &data_len,
                                    prime, base, value);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s public key import class=0x%lx rc=0x%lx "
                        "data_len=0x%lx\n", __func__, class, rc, data_len);
            goto import_DH_key_end;
        } else {
            TRACE_INFO("%s public key import class=0x%lx rc=0x%lx "
                       "data_len=0x%lx\n", __func__, class, rc, data_len);
        }

        /* save the SPKI as blob although it is not a blob.
         * The card expects SPKIs as public keys.
         */
        memcpy(blob, data, data_len);
        *blob_size = data_len;

    } else {

        /* imported private DH key goes here */

        /* extract the secret data to be wrapped
         * since this is AES_CBC_PAD, padding is done in mechanism.
         */
        rc = dh_priv_wrap_get_data(dh_key_obj->template, FALSE,
                                   &data, &data_len);
        if (rc != CKR_OK) {
            TRACE_DEVEL("%s DH wrap get data failed\n", __func__);
            goto import_DH_key_end;
        }

        /* encrypt */
        RETRY_START
            rc = dll_m_EncryptSingle(ep11_data->raw2key_wrap_blob,
                                     ep11_data->raw2key_wrap_blob_l,
                                     &mech_w, data, data_len,
                                     cipher, &cipher_l,
                                     (uint64_t) ep11_data->target_list);
        RETRY_END(rc, tokdata, sess)

        TRACE_INFO("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                   __func__, rc, cipher_l);

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping wrap key rc=0x%lx cipher_l=0x%lx\n",
                        __func__, rc, cipher_l);
            goto import_DH_key_end;
        }

        rc = check_key_attributes(tokdata, CKK_DH, CKO_PRIVATE_KEY, p_attrs,
                                  attrs_len, &new_p_attrs, &new_attrs_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s DH check private key attributes failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto import_DH_key_end;
        }

        ep11_get_pin_blob(ep11_session, object_is_session_object(dh_key_obj),
                          &ep11_pin_blob, &ep11_pin_blob_len);

        /* calls the card, it decrypts the private EC key,
         * reads its BER format and builds a blob.
         */
        RETRY_START
            rc = dll_m_UnwrapKey(cipher, cipher_l,
                                 ep11_data->raw2key_wrap_blob,
                                 ep11_data->raw2key_wrap_blob_l, NULL, ~0,
                                 ep11_pin_blob,
                                 ep11_pin_blob_len, &mech_w,
                                 new_p_attrs, new_attrs_len, blob,
                                 blob_size, csum, &cslen,
                                 (uint64_t) ep11_data->target_list);
        RETRY_END(rc, tokdata, sess)

        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, sess);
            TRACE_ERROR("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                        __func__, rc, *blob_size);
        } else {
            TRACE_INFO("%s wrapping unwrap key rc=0x%lx blob_size=0x%zx\n",
                       __func__, rc, *blob_size);
        }

        cleanse_attribute(dh_key_obj->template, CKA_VALUE);
    }

import_DH_key_end:
    if (data) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }
    if (p_attrs != NULL)
        cleanse_and_free_attribute_array(p_attrs, attrs_len);
    if (new_p_attrs)
        cleanse_and_free_attribute_array(new_p_attrs, new_attrs_len);
    return rc;
}

CK_RV token_specific_object_add(STDLL_TokData_t * tokdata, SESSION * sess,
                                OBJECT * obj)
{
    CK_KEY_TYPE keytype;
    CK_ATTRIBUTE *attr = NULL;
    CK_BYTE blob[MAX_BLOBSIZE];
    size_t blobsize = sizeof(blob);
    CK_RV rc;

    /* get key type */
    if (template_attribute_find(obj->template, CKA_KEY_TYPE, &attr) == FALSE) {
        /* not a key, so nothing to do. Just return. */
        return CKR_OK;
    }

    keytype = *(CK_KEY_TYPE *) attr->pValue;

    memset(blob, 0, sizeof(blob));

    /* only these keys can be imported */
    switch (keytype) {
    case CKK_RSA:
        rc = import_RSA_key(tokdata, sess, obj, blob, &blobsize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import RSA key rc=0x%lx blobsize=0x%zx\n",
                        __func__, rc, blobsize);
            return rc;
        }
        TRACE_INFO("%s import RSA key rc=0x%lx blobsize=0x%zx\n",
                   __func__, rc, blobsize);
        break;
    case CKK_EC:
        rc = import_EC_key(tokdata, sess, obj, blob, &blobsize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import EC key rc=0x%lx blobsize=0x%zx\n",
                        __func__, rc, blobsize);
            return rc;
        }
        TRACE_INFO("%s import EC key rc=0x%lx blobsize=0x%zx\n",
                   __func__, rc, blobsize);
        break;
    case CKK_DSA:
        rc = import_DSA_key(tokdata, sess, obj, blob, &blobsize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import DSA key rc=0x%lx blobsize=0x%zx\n",
                        __func__, rc, blobsize);
            return rc;
        }
        TRACE_INFO("%s import DSA key rc=0x%lx blobsize=0x%zx\n",
                   __func__, rc, blobsize);
        break;
    case CKK_DH:
        rc = import_DH_key(tokdata, sess, obj, blob, &blobsize);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s import DH key rc=0x%lx blobsize=0x%zx\n",
                        __func__, rc, blobsize);
            return rc;
        }
        TRACE_INFO("%s import DH key rc=0x%lx blobsize=0x%zx\n",
                   __func__, rc, blobsize);
        break;
    case CKK_DES2:
    case CKK_DES3:
    case CKK_AES:
    case CKK_GENERIC_SECRET:
        /* get key value */
        if (template_attribute_find(obj->template, CKA_VALUE, &attr) == FALSE) {
            TRACE_ERROR("%s token_specific_object_add incomplete template\n",
                        __func__);
            return CKR_TEMPLATE_INCOMPLETE;
        }
        /* attr holds key value specified by user,
         * import that key (make a blob)
         */
        rc = rawkey_2_blob(tokdata, sess, attr->pValue, attr->ulValueLen,
                           keytype, blob, &blobsize, obj);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s rawkey_2_blob rc=0x%lx "
                        "blobsize=0x%zx\n", __func__, rc, blobsize);
            return rc;
        }

        /* clear value attribute */
        OPENSSL_cleanse(attr->pValue, attr->ulValueLen);

        TRACE_INFO("%s rawkey_2_blob rc=0x%lx blobsize=0x%zx\n",
                   __func__, rc, blobsize);

        break;
    default:
        return CKR_KEY_FUNCTION_NOT_PERMITTED;
    }

    /* store the blob in the key obj */
    rc = build_attribute(CKA_IBM_OPAQUE, blob, blobsize, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        return rc;
    }

    rc = template_update_attribute(obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    return CKR_OK;
}


CK_RV ep11tok_generate_key(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs,
                           CK_ULONG attrs_len, CK_OBJECT_HANDLE_PTR handle)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_BYTE blob[MAX_BLOBSIZE];
    size_t blobsize = sizeof(blob);
    CK_BYTE csum[MAX_CSUMSIZE];
    size_t csum_len = sizeof(csum);
    CK_ATTRIBUTE *attr = NULL;
    OBJECT *key_obj = NULL;
    CK_ULONG ktype;
    CK_ULONG class;
    CK_ATTRIBUTE_PTR new_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    CK_RV rc;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) session->private_data;

    memset(blob, 0, sizeof(blob));
    memset(csum, 0, sizeof(csum));

    /* Get the keytype to use when creating the key object */
    rc = ep11_get_keytype(attrs, attrs_len, mech, &ktype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_subclass failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = check_key_attributes(tokdata, ktype, CKO_SECRET_KEY, attrs, attrs_len,
                              &new_attrs, &new_attrs_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s check secret key attributes failed: rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    ep11_get_pin_blob(ep11_session, ep11_is_session_object(attrs, attrs_len),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    RETRY_START
        rc = dll_m_GenerateKey(mech, new_attrs, new_attrs_len, ep11_pin_blob,
                               ep11_pin_blob_len, blob, &blobsize,
                               csum, &csum_len,
                               (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s m_GenerateKey rc=0x%lx mech='%s' attrs_len=0x%lx\n",
                    __func__, rc, ep11_get_ckm(mech->mechanism), attrs_len);
        return rc;
    }

    TRACE_INFO("%s m_GenerateKey rc=0x%lx mech='%s' attrs_len=0x%lx\n",
               __func__, rc, ep11_get_ckm(mech->mechanism), attrs_len);

    /* Start creating the key object */
    rc = object_mgr_create_skel(tokdata, session, new_attrs, new_attrs_len,
                                MODE_KEYGEN, CKO_SECRET_KEY, ktype, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_skel failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, blob, blobsize, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = template_update_attribute(key_obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    /* key should be fully constructed.
     * Assign an object handle and store key
     */
    rc = object_mgr_create_final(tokdata, session, key_obj, handle);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_final with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    goto done;
error:
    if (key_obj)
        object_free(key_obj);
    *handle = 0;
done:
    if (new_attrs)
        free_attribute_array(new_attrs, new_attrs_len);
    return rc;
}

static CK_BBOOL ep11tok_libica_digest_available(ep11_private_data_t *ep11_data,
                                                CK_MECHANISM_TYPE mech)
{
    int use_libica;

    switch (mech) {
    case CKM_SHA_1:
        use_libica = ep11_data->libica.ica_sha1 != NULL;
        break;
    case CKM_SHA224:
        use_libica = ep11_data->libica.ica_sha224 != NULL;
        break;
    case CKM_SHA256:
        use_libica = ep11_data->libica.ica_sha256 != NULL;
        break;
    case CKM_SHA384:
        use_libica = ep11_data->libica.ica_sha384 != NULL;
        break;
    case CKM_SHA512:
        use_libica = ep11_data->libica.ica_sha512 != NULL;
        break;
    case CKM_SHA512_224:
        use_libica = ep11_data->libica.ica_sha512_224 != NULL;
        break;
    case CKM_SHA512_256:
        use_libica = ep11_data->libica.ica_sha512_256 != NULL;
        break;
    default:
        use_libica = 0;
    }

    if (use_libica == 0)
        TRACE_DEVEL("%s mech=%s is not supported by libica\n", __func__,
                    ep11_get_ckm(mech));

    return use_libica ? CK_TRUE : CK_FALSE;
}

static CK_RV ep11tok_digest_from_mech(CK_MECHANISM_TYPE mech,
                                      CK_MECHANISM_TYPE *digest_mech)
{
    switch (mech) {
    case CKM_SHA_1:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA1:
        *digest_mech = CKM_SHA_1;
        break;

    case CKM_SHA224:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA224:
        *digest_mech = CKM_SHA224;
        break;

    case CKM_SHA256:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA256:
        *digest_mech = CKM_SHA256;
        break;

    case CKM_SHA384:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA384:
        *digest_mech = CKM_SHA384;
        break;

    case CKM_SHA512:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_ECDSA_SHA512:
        *digest_mech = CKM_SHA512;
        break;

    case CKM_SHA512_224:
        *digest_mech = CKM_SHA512_224;
        break;

    case CKM_SHA512_256:
        *digest_mech = CKM_SHA512_256;
        break;

    default:
        return CKR_MECHANISM_INVALID;
    }

    return CKR_OK;
}

static CK_BBOOL ep11tok_ec_curve_supported(STDLL_TokData_t *tokdata,
                                           CK_OBJECT_HANDLE hKey)
{
    CK_RV rc;
    OBJECT *key_obj;
    CK_ATTRIBUTE *attr = NULL;
    int i;

    rc = object_mgr_find_in_map1(tokdata, hKey, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s key 0x%lx not mapped\n", __func__, hKey);
        return CK_FALSE;
    }

    if (!template_attribute_find(key_obj->template, CKA_ECDSA_PARAMS, &attr)) {
        TRACE_ERROR("%s Could not find CKA_ECDSA_PARAMS for the key.\n",
                   __func__);
        return CK_FALSE;
    }

    for (i = 0; i < NUMEC; i++) {
        if ((memcmp(attr->pValue, der_ec_supported[i].data,
             attr->ulValueLen) == 0)) {
            return CK_TRUE;
        }
    }

    TRACE_DEVEL("%s EC curve not supported\n", __func__);
    return CK_FALSE;
}

CK_BBOOL ep11tok_libica_mech_available(STDLL_TokData_t *tokdata,
                                       CK_MECHANISM_TYPE mech,
                                       CK_OBJECT_HANDLE hKey)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_MECHANISM_TYPE digest_mech;
    CK_RV rc;

    rc = ep11tok_digest_from_mech(mech, &digest_mech);
    if (rc != CKR_OK)
        return CK_FALSE;

    switch (mech) {
       case CKM_ECDSA_SHA1:
       case CKM_ECDSA_SHA224:
       case CKM_ECDSA_SHA256:
       case CKM_ECDSA_SHA384:
       case CKM_ECDSA_SHA512:
           if (!ep11tok_ec_curve_supported(tokdata, hKey))
               return CK_FALSE;
           break;
    }

    return ep11tok_libica_digest_available(ep11_data, digest_mech);
}

static CK_RV ep11tok_libica_digest(ep11_private_data_t *ep11_data,
                                   CK_MECHANISM_TYPE mech, libica_sha_context_t *ctx,
                                   CK_BYTE *in_data, CK_ULONG in_data_len,
                                   CK_BYTE *out_data, CK_ULONG *out_data_len,
                                   unsigned int message_part)
{
    CK_ULONG hsize;
    CK_RV rc;

    rc = get_sha_size(mech, &hsize);
    if (rc != CKR_OK)
        return rc;

    if (*out_data_len < hsize)
        return CKR_BUFFER_TOO_SMALL;

    TRACE_DEVEL("%s mech=%s part=%u\n", __func__,
                ep11_get_ckm(mech), message_part);

    switch (mech) {
    case CKM_SHA_1:
        rc = ep11_data->libica.ica_sha1(message_part, in_data_len, in_data,
                                        &ctx->ctx.sha1, out_data);
        break;
    case CKM_SHA224:
        rc = ep11_data->libica.ica_sha224(message_part, in_data_len, in_data,
                                          &ctx->ctx.sha256, out_data);
        break;
    case CKM_SHA256:
        rc = ep11_data->libica.ica_sha256(message_part, in_data_len, in_data,
                                          &ctx->ctx.sha256, out_data);
        break;
    case CKM_SHA384:
        rc = ep11_data->libica.ica_sha384(message_part, in_data_len, in_data,
                                          &ctx->ctx.sha512, out_data);
        break;
    case CKM_SHA512:
        rc = ep11_data->libica.ica_sha512(message_part, in_data_len, in_data,
                                          &ctx->ctx.sha512, out_data);
        break;
    case CKM_SHA512_224:
        rc = ep11_data->libica.ica_sha512_224(message_part, in_data_len, in_data,
                                              &ctx->ctx.sha512, out_data);
        break;
    case CKM_SHA512_256:
        rc = ep11_data->libica.ica_sha512_256(message_part, in_data_len, in_data,
                                              &ctx->ctx.sha512, out_data);
        break;
    default:
        TRACE_ERROR("%s Invalid mechanism: mech=%s\n", __func__,
                    ep11_get_ckm(mech));
        return CKR_MECHANISM_INVALID;
    }

    if (rc != CKR_OK) {
        TRACE_ERROR("%s Libica SHA failed. mech=%s rc=0x%lx\n", __func__,
                    ep11_get_ckm(mech), rc);

        switch (rc) {
        case EINVAL:
            return CKR_ARGUMENTS_BAD;
        case ENODEV:
            return CKR_DEVICE_ERROR;
        default:
            return CKR_FUNCTION_FAILED;
        }
    }

    *out_data_len = hsize;
    return CKR_OK;
}

CK_RV token_specific_sha_init(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * c,
                              CK_MECHANISM * mech)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    size_t state_len = MAX(MAX_DIGEST_STATE_BYTES, sizeof(libica_sha_context_t));
    CK_BYTE *state;
    libica_sha_context_t *libica_ctx;

    state = calloc(state_len, 1); /* freed by dig_mgr.c */
    if (!state) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    if (ep11tok_libica_digest_available(ep11_data, mech->mechanism)) {
        libica_ctx = (libica_sha_context_t *)state;
        state_len = sizeof(libica_sha_context_t);
        libica_ctx->first = CK_TRUE;
        rc = get_sha_block_size(mech->mechanism, &libica_ctx->block_size);
    } else {
        rc = dll_m_DigestInit(state, &state_len, mech,
                              (uint64_t)ep11_data->target_list);
    }

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
        free(state);
    } else {
        /* DIGEST_CONTEXT will show up with following
         *  requests (sha_update), 'state' is build by the card
         * and holds all to continue, even by another adapter
         */
        c->mech.ulParameterLen = mech->ulParameterLen;
        c->mech.mechanism = mech->mechanism;
        c->mech.pParameter = NULL;
        c->context = state;
        c->context_len = state_len;

        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV token_specific_sha(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * c,
                         CK_BYTE * in_data,
                         CK_ULONG in_data_len, CK_BYTE * out_data,
                         CK_ULONG * out_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;

    if (ep11tok_libica_digest_available(ep11_data, c->mech.mechanism)) {
        rc = ep11tok_libica_digest(ep11_data, c->mech.mechanism,
                                   (libica_sha_context_t *)c->context,
                                   in_data, in_data_len,
                                   out_data, out_data_len,
                                   SHA_MSG_PART_ONLY);
    } else {
        rc = dll_m_Digest(c->context, c->context_len, in_data, in_data_len,
                          out_data, out_data_len,
                          (uint64_t)ep11_data->target_list);
    }

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }
    return rc;
}


CK_RV token_specific_sha_update(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * c,
                                CK_BYTE * in_data, CK_ULONG in_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    libica_sha_context_t *libica_ctx = (libica_sha_context_t *)c->context;
    CK_BYTE temp_out[MAX_SHA_HASH_SIZE];
    CK_ULONG out_len = sizeof(temp_out);
    CK_ULONG len;
    CK_RV rc = CKR_OK;

    if (ep11tok_libica_digest_available(ep11_data, c->mech.mechanism)) {
        if (libica_ctx->offset > 0 || in_data_len < libica_ctx->block_size) {
            len = MIN(libica_ctx->block_size - libica_ctx->offset,
                      in_data_len);
            memcpy(&libica_ctx->buffer[libica_ctx->offset], in_data, len);
            libica_ctx->offset += len;

            in_data += len;
            in_data_len -= len;

            if (libica_ctx->offset == libica_ctx->block_size) {
                rc = ep11tok_libica_digest(ep11_data, c->mech.mechanism,
                                           libica_ctx, libica_ctx->buffer,
                                           libica_ctx->offset, temp_out,
                                           &out_len, libica_ctx->first ?
                                                        SHA_MSG_PART_FIRST :
                                                        SHA_MSG_PART_MIDDLE);
                if (rc != CKR_OK)
                    goto out;

                libica_ctx->first = CK_FALSE;

                libica_ctx->offset = 0;
            }
        }

        if (in_data_len > 0) {
            len = (in_data_len / libica_ctx->block_size) * libica_ctx->block_size;
            rc = ep11tok_libica_digest(ep11_data, c->mech.mechanism,
                                       libica_ctx, in_data, len, temp_out,
                                       &out_len, libica_ctx->first ?
                                                    SHA_MSG_PART_FIRST :
                                                    SHA_MSG_PART_MIDDLE);
            if (rc != CKR_OK)
                goto out;

            libica_ctx->first = CK_FALSE;

            in_data += len;
            in_data_len -= len;

            if (in_data_len > 0) {
                memcpy(libica_ctx->buffer, in_data, in_data_len);
                libica_ctx->offset = in_data_len;
            }
        }
    } else {
        rc = dll_m_DigestUpdate(c->context, c->context_len,
                                in_data, in_data_len,
                                (uint64_t)ep11_data->target_list);
    }

out:
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }
    return rc;
}


CK_RV token_specific_sha_final(STDLL_TokData_t * tokdata, DIGEST_CONTEXT * c,
                               CK_BYTE * out_data, CK_ULONG * out_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    libica_sha_context_t *libica_ctx = (libica_sha_context_t *)c->context;
    CK_RV rc;

    if (ep11tok_libica_digest_available(ep11_data, c->mech.mechanism)) {
        rc = ep11tok_libica_digest(ep11_data, c->mech.mechanism,
                                   libica_ctx, libica_ctx->buffer,
                                   libica_ctx->offset,
                                   out_data, out_data_len,
                                   libica_ctx->first ?
                                        SHA_MSG_PART_ONLY :
                                        SHA_MSG_PART_FINAL);
    } else {
        rc = dll_m_DigestFinal(c->context, c->context_len,
                               out_data, out_data_len,
                               (uint64_t)ep11_data->target_list);
    }

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV token_specific_rsa_sign(STDLL_TokData_t *tokdata, SESSION *session,
                              CK_BYTE *in_data, CK_ULONG in_data_len,
                              CK_BYTE *out_data, CK_ULONG *out_data_len,
                              OBJECT *key_obj)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    CK_MECHANISM mech;

    rc = obj_opaque_2_blob(tokdata, key_obj, &keyblob, &keyblobsize);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    mech.mechanism = CKM_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    RETRY_START
    rc = dll_m_SignSingle(keyblob, keyblobsize, &mech, in_data, in_data_len,
                          out_data, out_data_len,
                          (uint64_t)ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV token_specific_rsa_verify(STDLL_TokData_t *tokdata, SESSION *session,
                                CK_BYTE *in_data, CK_ULONG in_data_len,
                                CK_BYTE *signature, CK_ULONG sig_len,
                                OBJECT *key_obj)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE *spki;
    size_t spki_len = 0;
    CK_MECHANISM mech;

    rc = obj_opaque_2_blob(tokdata, key_obj, &spki, &spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    mech.mechanism = CKM_RSA_PKCS;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    RETRY_START
    rc = dll_m_VerifySingle(spki, spki_len, &mech, in_data, in_data_len,
                            signature, sig_len,
                            (uint64_t)ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV token_specific_rsa_pss_sign(STDLL_TokData_t *tokdata, SESSION *session,
                                  SIGN_VERIFY_CONTEXT *ctx,
                                  CK_BYTE *in_data, CK_ULONG in_data_len,
                                  CK_BYTE *sig, CK_ULONG *sig_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj;
    CK_MECHANISM mech;

    rc = h_opaque_2_blob(tokdata, ctx->key, &keyblob, &keyblobsize, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    mech.mechanism = CKM_RSA_PKCS_PSS;
    mech.ulParameterLen = ctx->mech.ulParameterLen;
    mech.pParameter = ctx->mech.pParameter;

    RETRY_START
    rc = dll_m_SignSingle(keyblob, keyblobsize, &mech, in_data, in_data_len,
                          sig, sig_len,
                          (uint64_t)ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV token_specific_rsa_pss_verify(STDLL_TokData_t *tokdata, SESSION *session,
                                    SIGN_VERIFY_CONTEXT *ctx,
                                    CK_BYTE *in_data, CK_ULONG in_data_len,
                                    CK_BYTE *signature, CK_ULONG sig_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE *spki;
    size_t spki_len = 0;
    OBJECT *key_obj;
    CK_MECHANISM mech;

    rc = h_opaque_2_blob(tokdata, ctx->key, &spki, &spki_len, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    mech.mechanism = CKM_RSA_PKCS_PSS;
    mech.ulParameterLen = ctx->mech.ulParameterLen;
    mech.pParameter = ctx->mech.pParameter;

    RETRY_START
    rc = dll_m_VerifySingle(spki, spki_len, &mech, in_data, in_data_len,
                            signature, sig_len,
                            (uint64_t)ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV token_specific_ec_sign(STDLL_TokData_t *tokdata, SESSION  *session,
                             CK_BYTE *in_data, CK_ULONG in_data_len,
                             CK_BYTE *out_data, CK_ULONG *out_data_len,
                             OBJECT *key_obj )
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    CK_MECHANISM mech;

    rc = obj_opaque_2_blob(tokdata, key_obj, &keyblob, &keyblobsize);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    mech.mechanism = CKM_ECDSA;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    RETRY_START
    rc = dll_m_SignSingle(keyblob, keyblobsize, &mech, in_data, in_data_len,
                          out_data, out_data_len,
                          (uint64_t)ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV token_specific_ec_verify(STDLL_TokData_t *tokdata, SESSION  *session,
                               CK_BYTE *in_data, CK_ULONG in_data_len,
                               CK_BYTE *out_data, CK_ULONG out_data_len,
                               OBJECT *key_obj )
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE *spki;
    size_t spki_len = 0;
    CK_MECHANISM mech;

    rc = obj_opaque_2_blob(tokdata, key_obj, &spki, &spki_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    mech.mechanism = CKM_ECDSA;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    RETRY_START
    rc = dll_m_VerifySingle(spki, spki_len, &mech, in_data, in_data_len,
                            out_data, out_data_len,
                            (uint64_t)ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV ep11tok_derive_key(STDLL_TokData_t * tokdata, SESSION * session,
                         CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE hBaseKey,
                         CK_OBJECT_HANDLE_PTR handle, CK_ATTRIBUTE_PTR attrs,
                         CK_ULONG attrs_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE *keyblob;
    size_t keyblobsize;
    CK_BYTE newblob[MAX_BLOBSIZE];
    size_t newblobsize = sizeof(newblob);
    CK_BYTE csum[MAX_BLOBSIZE];
    CK_ULONG cslen = sizeof(csum);
    CK_ATTRIBUTE *opaque_attr = NULL;
    OBJECT *key_obj = NULL;
    CK_ULONG ktype;
    CK_ULONG class;
    CK_ATTRIBUTE_PTR new_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) session->private_data;
    CK_ECDH1_DERIVE_PARAMS *ecdh1_parms;
    CK_MECHANISM ecdh1_mech;

    memset(newblob, 0, sizeof(newblob));

    /*
     * EP11 supports CKM_ECDH1_DERIVE slightly different than specified in
     * PKCS#11 v2.11 or later. It expects the public data directly as mechanism
     * param, not via CK_ECDH1_DERIVE_PARAMS. It also does not support KDFs and
     * shared data.
     *
     * ATTENTION: Once the EP11 library supports CKM_ECDH1_DERIVE in PKCS#11
     * way, the following if block needs to be adapted.
     */
    if (mech->mechanism == CKM_ECDH1_DERIVE) {
        if (mech->ulParameterLen != sizeof(CK_ECDH1_DERIVE_PARAMS)) {
            TRACE_ERROR("%s Param len for CKM_ECDH1_DERIVE wrong: %lu\n",
                        __func__, mech->ulParameterLen);
            return CKR_MECHANISM_PARAM_INVALID;
        }
        ecdh1_parms = mech->pParameter;

        if (ecdh1_parms->kdf != CKD_NULL) {
            TRACE_ERROR("%s KDF for CKM_ECDH1_DERIVE not supported: %lu\n",
                        __func__, ecdh1_parms->kdf);
            return CKR_MECHANISM_PARAM_INVALID;
        }

        if (ecdh1_parms->pSharedData != NULL ||
            ecdh1_parms->ulSharedDataLen > 0) {
            TRACE_ERROR("%s Shared data for CKM_ECDH1_DERIVE not supported\n",
                        __func__);
            return CKR_MECHANISM_PARAM_INVALID;
        }

        ecdh1_mech.mechanism = CKM_ECDH1_DERIVE;
        ecdh1_mech.pParameter = ecdh1_parms->pPublicData;
        ecdh1_mech.ulParameterLen = ecdh1_parms->ulPublicDataLen;
        mech = &ecdh1_mech;
    }

    rc = h_opaque_2_blob(tokdata, hBaseKey, &keyblob, &keyblobsize, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s failedL hBaseKey=0x%lx\n", __func__, hBaseKey);
        return rc;
    }

    /* Get the keytype to use when creating the key object */
    rc = ep11_get_keytype(attrs, attrs_len, mech, &ktype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_subclass failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = check_key_attributes(tokdata, ktype, class, attrs, attrs_len,
                              &new_attrs, &new_attrs_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Check key attributes for derived key failed with "
                    "rc=0x%lx\n", __func__, rc);
        return rc;
    }

    ep11_get_pin_blob(ep11_session, ep11_is_session_object(attrs, attrs_len),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    RETRY_START
        rc =
        dll_m_DeriveKey(mech, new_attrs, new_attrs_len, keyblob, keyblobsize,
                        NULL, 0, ep11_pin_blob, ep11_pin_blob_len, newblob,
                        &newblobsize, csum, &cslen,
                        (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        TRACE_ERROR("%s hBaseKey=0x%lx rc=0x%lx handle=0x%lx blobsize=0x%zx\n",
                    __func__, hBaseKey, rc, *handle, newblobsize);
        return rc;
    }
    TRACE_INFO("%s hBaseKey=0x%lx rc=0x%lx handle=0x%lx blobsize=0x%zx\n",
               __func__, hBaseKey, rc, *handle, newblobsize);

    /* Start creating the key object */
    rc = object_mgr_create_skel(tokdata, session, new_attrs, new_attrs_len,
                                MODE_DERIVE, class, ktype, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_skel failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, newblob, newblobsize, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = template_update_attribute(key_obj->template, opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    /* key should be fully constructed.
     * Assign an object handle and store key
     */
    rc = object_mgr_create_final(tokdata, session, key_obj, handle);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_final with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    return rc;

error:
    if (key_obj)
        object_free(key_obj);
    *handle = 0;
    if (new_attrs)
        free_attribute_array(new_attrs, new_attrs_len);
    return rc;
}



static CK_RV dh_generate_keypair(STDLL_TokData_t * tokdata,
                                 SESSION * sess,
                                 CK_MECHANISM_PTR pMechanism,
                                 TEMPLATE * publ_tmpl, TEMPLATE * priv_tmpl,
                                 CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                 CK_ULONG ulPublicKeyAttributeCount,
                                 CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                 CK_ULONG ulPrivateKeyAttributeCount,
                                 CK_SESSION_HANDLE h)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE publblob[MAX_BLOBSIZE];
    size_t publblobsize = sizeof(publblob);
    CK_BYTE privblob[MAX_BLOBSIZE];
    size_t privblobsize = sizeof(privblob);
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *opaque_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE *pPublicKeyTemplate_new = NULL;
    size_t p_len = 0, g_len = 0;
    int new_public_attr;
    CK_ULONG i;
    CK_ULONG data_len;
    CK_ULONG field_len;
    CK_BYTE *data;
    CK_BYTE *y_start;
    CK_ULONG bit_str_len;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;

    /* ep11 accepts CKA_PRIME and CKA_BASE parameters/attributes
     * only in this format
     */
    struct {
        size_t pg_bytes;        /* total size: 2*bytecount(P) */
        unsigned char *pg;
    } dh_pgs;

    UNUSED(h);

    memset(&dh_pgs, 0, sizeof(dh_pgs));
    memset(publblob, 0, sizeof(publblob));
    memset(privblob, 0, sizeof(privblob));

    /* card does not want CKA_PRIME/CKA_BASE in template but in dh_pgs */
    pPublicKeyTemplate_new =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) *
                                ulPublicKeyAttributeCount);
    if (!pPublicKeyTemplate_new) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }
    memset(pPublicKeyTemplate_new, 0,
           sizeof(CK_ATTRIBUTE) * ulPublicKeyAttributeCount);

    for (i = 0, new_public_attr = 0; i < ulPublicKeyAttributeCount; i++) {
        /* filter out CKA_PRIME/CKA_BASE,
         * but remember where they can  be found
         */
        switch (pPublicKeyTemplate[i].type) {
        case CKA_PRIME:
            prime_attr = &(pPublicKeyTemplate[i]);
            p_len = pPublicKeyTemplate[i].ulValueLen;
            break;
        case CKA_BASE:
            base_attr = &(pPublicKeyTemplate[i]);
            g_len = pPublicKeyTemplate[i].ulValueLen;
            break;
        default:
            /* copy all other attributes */
            memcpy(&pPublicKeyTemplate_new[new_public_attr],
                   &(pPublicKeyTemplate[i]), sizeof(CK_ATTRIBUTE));
            new_public_attr++;
        }
    }

    if (prime_attr == NULL || base_attr == NULL) {
        TRACE_ERROR("%s Incomplete template prime_attr=%p base_attr=%p\n",
                    __func__, (void *)prime_attr, (void *)base_attr);
        rc = CKR_TEMPLATE_INCOMPLETE;
        goto dh_generate_keypair_end;
    }

    /* copy CKA_PRIME/CKA_BASE to private template */
    rc = build_attribute(CKA_PRIME, prime_attr->pValue,
                         prime_attr->ulValueLen, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto dh_generate_keypair_end;
    }
    rc = build_attribute(CKA_BASE, base_attr->pValue,
                         base_attr->ulValueLen, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto dh_generate_keypair_end;
    }

    /* copy CKA_PRIME/CKA_BASE values */
    dh_pgs.pg = malloc(p_len * 2);
    if (!dh_pgs.pg) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }
    memset(dh_pgs.pg, 0, p_len * 2);
    memcpy(dh_pgs.pg, prime_attr->pValue, p_len);     /* copy CKA_PRIME value */
    /* copy CKA_BASE value, it must have leading zeros
     * if it is shorter than CKA_PRIME
     */
    memcpy(dh_pgs.pg + p_len + (p_len - g_len), base_attr->pValue, g_len);
    dh_pgs.pg_bytes = p_len * 2;

#ifdef DEBUG
    TRACE_DEBUG("%s P:\n", __func__);
    TRACE_DEBUG_DUMP(&dh_pgs.pg[0], p_len);
    TRACE_DEBUG("%s G:\n", __func__);
    TRACE_DEBUG_DUMP(&dh_pgs.pg[p_len], p_len);
#endif

    /* add special attribute, do not add it to ock's pPublicKeyTemplate */
    CK_ATTRIBUTE pgs[] = { {CKA_IBM_STRUCT_PARAMS, (CK_VOID_PTR) dh_pgs.pg,
                            dh_pgs.pg_bytes}
    };
    memcpy(&(pPublicKeyTemplate_new[new_public_attr]),
           &(pgs[0]), sizeof(CK_ATTRIBUTE));

    ep11_get_pin_blob(ep11_session,
                      (ep11_is_session_object
                       (pPublicKeyTemplate, ulPublicKeyAttributeCount)
                       || ep11_is_session_object(pPrivateKeyTemplate,
                                                 ulPrivateKeyAttributeCount)),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    RETRY_START
        rc = dll_m_GenerateKeyPair(pMechanism, pPublicKeyTemplate_new,
                                   new_public_attr + 1, pPrivateKeyTemplate,
                                   ulPrivateKeyAttributeCount, ep11_pin_blob,
                                   ep11_pin_blob_len, privblob, &privblobsize,
                                   publblob, &publblobsize,
                                   (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s m_GenerateKeyPair failed rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    TRACE_INFO("%s rc=0x%lx plen=%zd publblobsize=0x%zx privblobsize=0x%zx\n",
               __func__, rc, p_len, publblobsize, privblobsize);

    /* store the blobs */
    rc = build_attribute(CKA_IBM_OPAQUE, publblob, publblobsize, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    rc = template_update_attribute(publ_tmpl, opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto dh_generate_keypair_end;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, privblob, privblobsize, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    rc = template_update_attribute(priv_tmpl, opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto dh_generate_keypair_end;
    }
#ifdef DEBUG
    TRACE_DEBUG("%s DH SPKI\n", __func__);
    TRACE_DEBUG_DUMP(publblob, publblobsize);
#endif

    /* CKA_VALUE of the public key must hold 'y' */
    rc = ep11_spki_key(publblob, &y_start, &bit_str_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_decode SKPI failed rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    /* DHPublicKey ::= INTEGER -- public key, y = g^x mod p */
    rc = ber_decode_INTEGER(y_start, &data, &data_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s ber_decode_INTEGER failed rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    TRACE_INFO("%s DH SPKI decode INTEGER rc=0x%lx y_start=0x%x"
               " field_len=%lu data_len=%lu data=0x%hhx\n",
               __func__, rc, y_start[1], field_len, data_len, data[0]);

    /* remove leading zero, a leading zero is needed
     * (according to standard) if left most bit of first byte is 1,
     * in order to indicate a positive number.
     * ock, like many others, interpret 'y' always as positive number,
     * a leading zero is not expected by ock.
     */
    if (data[0] == 0) {
        data_len = data_len - 1;
        data = data + 1;
        TRACE_INFO("%s DH SPKI removed leading zero rc=0x%lx"
                   " y_start=0x%x field_len=%lu data_len=%lu data=0x%hhx\n",
                   __func__, rc, y_start[1], field_len, data_len, data[0]);
    }

    rc = build_attribute(CKA_VALUE, data, data_len, &value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dh_generate_keypair_end;
    }

    rc = template_update_attribute(publ_tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
    }

dh_generate_keypair_end:
    free(pPublicKeyTemplate_new);
    if (dh_pgs.pg != NULL)
        free(dh_pgs.pg);
    return rc;
}

static CK_RV dsa_generate_keypair(STDLL_TokData_t * tokdata,
                                  SESSION * sess,
                                  CK_MECHANISM_PTR pMechanism,
                                  TEMPLATE * publ_tmpl, TEMPLATE * priv_tmpl,
                                  CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                  CK_ULONG ulPublicKeyAttributeCount,
                                  CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                  CK_ULONG ulPrivateKeyAttributeCount,
                                  CK_SESSION_HANDLE h)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE publblob[MAX_BLOBSIZE];
    size_t publblobsize = sizeof(publblob);
    CK_BYTE privblob[MAX_BLOBSIZE];
    size_t privblobsize = sizeof(privblob);
    CK_ATTRIBUTE *prime_attr = NULL;
    CK_ATTRIBUTE *sub_prime_attr = NULL;
    CK_ATTRIBUTE *base_attr = NULL;
    CK_ATTRIBUTE *opaque_attr = NULL;
    CK_ATTRIBUTE *value_attr = NULL;
    CK_ATTRIBUTE *attr = NULL;
    size_t p_len = 0, q_len = 0, g_len = 0;
    int new_public_attr;
    CK_ULONG i;
    CK_ATTRIBUTE *pPublicKeyTemplate_new = NULL;
    CK_BYTE *key;
    CK_BYTE *data;
    CK_ULONG data_len, field_len, bit_str_len;
    CK_ATTRIBUTE_PTR dsa_pPublicKeyTemplate = NULL;
    CK_ULONG dsa_ulPublicKeyAttributeCount = 0;
    CK_ATTRIBUTE_PTR dsa_pPrivateKeyTemplate = NULL;
    CK_ULONG dsa_ulPrivateKeyAttributeCount = 0;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;

    /* ep11 accepts CKA_PRIME,CKA_SUBPRIME,CKA_BASE only in this format */
    struct {
        size_t pqg_bytes;       /* total size: 3*bytecount(P) */
        unsigned char *pqg;
    } dsa_pqgs;

    UNUSED(h);

    memset(&dsa_pqgs, 0, sizeof(dsa_pqgs));
    memset(publblob, 0, sizeof(publblob));
    memset(privblob, 0, sizeof(privblob));

    /* card does not want CKA_PRIME/CKA_BASE/CKA_SUBPRIME
     * in template but in dsa_pqgs
     */
    pPublicKeyTemplate_new =
        (CK_ATTRIBUTE *) malloc(sizeof(CK_ATTRIBUTE) *
                                ulPublicKeyAttributeCount);
    if (!pPublicKeyTemplate_new) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }
    memset(pPublicKeyTemplate_new, 0,
           sizeof(CK_ATTRIBUTE) * ulPublicKeyAttributeCount);

    for (i = 0, new_public_attr = 0; i < ulPublicKeyAttributeCount; i++) {
        switch (pPublicKeyTemplate[i].type) {
        case CKA_PRIME:
            prime_attr = &(pPublicKeyTemplate[i]);
            p_len = pPublicKeyTemplate[i].ulValueLen;
            break;
        case CKA_SUBPRIME:
            sub_prime_attr = &(pPublicKeyTemplate[i]);
            q_len = pPublicKeyTemplate[i].ulValueLen;
            break;
        case CKA_BASE:
            base_attr = &(pPublicKeyTemplate[i]);
            g_len = pPublicKeyTemplate[i].ulValueLen;
            break;
        default:
            /* copy all other attributes */
            memcpy(&pPublicKeyTemplate_new[new_public_attr],
                   &(pPublicKeyTemplate[i]), sizeof(CK_ATTRIBUTE));
            new_public_attr++;
        }
    }

    if (prime_attr == NULL || sub_prime_attr == NULL || base_attr == NULL)
        return CKR_TEMPLATE_INCOMPLETE;

    /* copy CKA_PRIME/CKA_BASE/CKA_SUBPRIME to private template */
    rc = build_attribute(CKA_PRIME, prime_attr->pValue,
                         prime_attr->ulValueLen, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = build_attribute(CKA_BASE, base_attr->pValue,
                         base_attr->ulValueLen, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = build_attribute(CKA_PRIME, sub_prime_attr->pValue,
                         sub_prime_attr->ulValueLen, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto dsa_generate_keypair_end;
    }

    /* if CKA_SUBPRIME,CKA_BASE are smaller than CKA_PRIME
     * then they are extented by leading zeros till they have
     * the size of CKA_PRIME
     */
    dsa_pqgs.pqg = malloc(p_len * 3);
    if (!dsa_pqgs.pqg) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }
    memset(dsa_pqgs.pqg, 0, p_len * 3);
    memcpy(dsa_pqgs.pqg, prime_attr->pValue, p_len);
    memcpy(dsa_pqgs.pqg + p_len + (p_len - q_len),
           sub_prime_attr->pValue, q_len);
    memcpy(dsa_pqgs.pqg + 2 * p_len + (p_len - g_len),
           base_attr->pValue, g_len);
    dsa_pqgs.pqg_bytes = p_len * 3;

#ifdef DEBUG
    TRACE_DEBUG("%s P:\n", __func__);
    TRACE_DEBUG_DUMP(&dsa_pqgs.pqg[0], p_len);
    TRACE_DEBUG("%s Q:\n", __func__);
    TRACE_DEBUG_DUMP(&dsa_pqgs.pqg[p_len], p_len);
    TRACE_DEBUG("%s G:\n", __func__);
    TRACE_DEBUG_DUMP(&dsa_pqgs.pqg[2 * p_len], p_len);
#endif

    CK_ATTRIBUTE pqgs[] = { {CKA_IBM_STRUCT_PARAMS,
                             (CK_VOID_PTR) dsa_pqgs.pqg, dsa_pqgs.pqg_bytes}
    };

    /* add special attribute, do not add it to ock's pPublicKeyTemplate */
    memcpy(&(pPublicKeyTemplate_new[new_public_attr]),
           &(pqgs[0]), sizeof(CK_ATTRIBUTE));

    rc = check_key_attributes(tokdata, CKK_DSA, CKO_PUBLIC_KEY,
                              pPublicKeyTemplate_new, new_public_attr + 1,
                              &dsa_pPublicKeyTemplate,
                              &dsa_ulPublicKeyAttributeCount);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s RSA/EC check public key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        return rc;
    }

    rc = check_key_attributes(tokdata, CKK_DSA, CKO_PRIVATE_KEY,
                              pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                              &dsa_pPrivateKeyTemplate,
                              &dsa_ulPrivateKeyAttributeCount);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s RSA/EC check private key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        return rc;
    }

    ep11_get_pin_blob(ep11_session,
                      (ep11_is_session_object
                       (pPublicKeyTemplate, ulPublicKeyAttributeCount)
                       || ep11_is_session_object(pPrivateKeyTemplate,
                                                 ulPrivateKeyAttributeCount)),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    RETRY_START
        rc = dll_m_GenerateKeyPair(pMechanism, dsa_pPublicKeyTemplate,
                                   dsa_ulPublicKeyAttributeCount,
                                   dsa_pPrivateKeyTemplate,
                                   dsa_ulPrivateKeyAttributeCount,
                                   ep11_pin_blob, ep11_pin_blob_len, privblob,
                                   &privblobsize, publblob, &publblobsize,
                                   (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, sess)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s m_GenerateKeyPair failed with rc=0x%lx\n", __func__,
                    rc);
        goto dsa_generate_keypair_end;
    }

    TRACE_INFO("%s rc=0x%lx p_len=%zd publblobsize=0x%zx privblobsize=0x%zx "
               "npattr=0x%x\n",
               __func__, rc, p_len, publblobsize, privblobsize,
               new_public_attr + 1);

    rc = build_attribute(CKA_IBM_OPAQUE, publblob, publblobsize, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = template_update_attribute(publ_tmpl, opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, privblob, privblobsize, &opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = template_update_attribute(priv_tmpl, opaque_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto dsa_generate_keypair_end;
    }

    /* set CKA_VALUE of the public key, first get key from SPKI */
    rc = ep11_spki_key(publblob, &key, &bit_str_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s reading DSA SPKI failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    /* key must be an integer */
    rc = ber_decode_INTEGER(key, &data, &data_len, &field_len);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s reading DSA public key failed with rc=0x%lx\n",
                    __func__, rc);
        goto dsa_generate_keypair_end;
    }
#ifdef DEBUG
    TRACE_DEBUG("%s dsa_generate_keypair public key:\n", __func__);
    TRACE_DEBUG_DUMP(data, data_len);
#endif

    rc = build_attribute(CKA_VALUE, data, data_len, &value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto dsa_generate_keypair_end;
    }

    rc = template_update_attribute(publ_tmpl, value_attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
    }

dsa_generate_keypair_end:
    free(pPublicKeyTemplate_new);
    if (dsa_pqgs.pqg != NULL)
        free(dsa_pqgs.pqg);
    if (dsa_pPublicKeyTemplate)
        free_attribute_array(dsa_pPublicKeyTemplate,
                             dsa_ulPublicKeyAttributeCount);
    if (dsa_pPrivateKeyTemplate)
        free_attribute_array(dsa_pPrivateKeyTemplate,
                             dsa_ulPrivateKeyAttributeCount);
    return rc;
}

static CK_RV rsa_ec_generate_keypair(STDLL_TokData_t * tokdata,
                                     SESSION * sess,
                                     CK_MECHANISM_PTR pMechanism,
                                     TEMPLATE * publ_tmpl, TEMPLATE * priv_tmpl,
                                     CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                     CK_ULONG ulPublicKeyAttributeCount,
                                     CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                     CK_ULONG ulPrivateKeyAttributeCount,
                                     CK_SESSION_HANDLE h)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE *n_attr = NULL;
    CK_BYTE privkey_blob[MAX_BLOBSIZE];
    size_t privkey_blob_len = sizeof(privkey_blob);
    unsigned char spki[MAX_BLOBSIZE];
    size_t spki_len = sizeof(spki);
    CK_BYTE publblob[MAX_BLOBSIZE];
    size_t publblobsize = sizeof(publblob);
    CK_BYTE privblob[MAX_BLOBSIZE];
    size_t privblobsize = sizeof(privblob);
    CK_ULONG i;
    CK_ULONG bit_str_len;
    CK_BYTE *key;
    CK_BYTE *data;
    CK_ULONG data_len;
    CK_ULONG field_len;
    CK_ATTRIBUTE_PTR new_pPublicKeyTemplate = NULL;
    CK_ULONG new_ulPublicKeyAttributeCount = 0;
    CK_ATTRIBUTE_PTR new_pPrivateKeyTemplate = NULL;
    CK_ULONG new_ulPrivateKeyAttributeCount = 0;
    CK_ULONG ktype;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) sess->private_data;

    UNUSED(h);

    if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
        ktype = CKK_EC;
    } else if ((pMechanism->mechanism == CKM_RSA_PKCS_KEY_PAIR_GEN) ||
               (pMechanism->mechanism == CKM_RSA_X9_31_KEY_PAIR_GEN)) {
        ktype = CKK_RSA;
    } else {
        TRACE_ERROR("%s Neither RSA nor EC mech type provided for "
                    "RSA/EC_key_pair_gen\n", __func__);
        return CKR_MECHANISM_INVALID;
    }

    rc = check_key_attributes(tokdata, ktype, CKO_PUBLIC_KEY,
                              pPublicKeyTemplate, ulPublicKeyAttributeCount,
                              &new_pPublicKeyTemplate,
                              &new_ulPublicKeyAttributeCount);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s RSA/EC check public key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        return rc;
    }

    rc = check_key_attributes(tokdata, ktype, CKO_PRIVATE_KEY,
                              pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                              &new_pPrivateKeyTemplate,
                              &new_ulPrivateKeyAttributeCount);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s RSA/EC check private key attributes failed with "
                    "rc=0x%lx\n", __func__, rc);
        goto error;
    }

    /* debug */
    for (i = 0; i < new_ulPrivateKeyAttributeCount; i++) {
        TRACE_INFO("%s gen priv attr type=0x%lx valuelen=0x%lx attrcnt=0x%lx\n",
                   __func__, new_pPrivateKeyTemplate[i].type,
                   new_pPrivateKeyTemplate[i].ulValueLen,
                   new_ulPrivateKeyAttributeCount);
    }

    ep11_get_pin_blob(ep11_session,
                      (ep11_is_session_object
                       (pPublicKeyTemplate, ulPublicKeyAttributeCount)
                       || ep11_is_session_object(pPrivateKeyTemplate,
                                                 ulPrivateKeyAttributeCount)),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    RETRY_START
        rc = dll_m_GenerateKeyPair(pMechanism, new_pPublicKeyTemplate,
                                   new_ulPublicKeyAttributeCount,
                                   new_pPrivateKeyTemplate,
                                   new_ulPrivateKeyAttributeCount,
                                   ep11_pin_blob, ep11_pin_blob_len,
                                   privkey_blob, &privkey_blob_len, spki,
                                   &spki_len,
                                   (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, sess)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, sess);
        TRACE_ERROR("%s m_GenerateKeyPair rc=0x%lx spki_len=0x%zx "
                    "privkey_blob_len=0x%zx mech='%s'\n",
                    __func__, rc, spki_len, privkey_blob_len,
                    ep11_get_ckm(pMechanism->mechanism));
        goto error;
    }
    TRACE_INFO("%s m_GenerateKeyPair rc=0x%lx spki_len=0x%zx "
               "privkey_blob_len=0x%zx mech='%s'\n",
               __func__, rc, spki_len, privkey_blob_len,
               ep11_get_ckm(pMechanism->mechanism));

    if (spki_len > MAX_BLOBSIZE || privkey_blob_len > MAX_BLOBSIZE) {
        TRACE_ERROR("%s blobsize error\n", __func__);
        rc = CKR_KEY_INDIGESTIBLE;
        goto error;
    }

    memset(publblob, 0, sizeof(publblob));
    memset(privblob, 0, sizeof(privblob));

    memcpy(publblob, spki, spki_len);
    publblobsize = spki_len;

    memcpy(privblob, privkey_blob, privkey_blob_len);
    privblobsize = privkey_blob_len;

    rc = build_attribute(CKA_IBM_OPAQUE, publblob, publblobsize, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }
    rc = template_update_attribute(publ_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, privblob, privblobsize, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }
    rc = template_update_attribute(priv_tmpl, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    if (pMechanism->mechanism == CKM_EC_KEY_PAIR_GEN) {
        /* scan the SPKI for CKA_EC_POINT */

#ifdef DEBUG
        TRACE_DEBUG("%s ec_generate_keypair spki:\n", __func__);
        TRACE_DEBUG_DUMP(spki, spki_len);
#endif
        rc = ep11_spki_key(spki, &key, &bit_str_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s read key from SPKI failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        /* 'key' is already EC point,
         * SEC 1: Elliptic Curve Cryptography:
         * The elliptic curve public key (a value of type ECPoint
         * that is an OCTET STRING) is mapped to a subjectPublicKey
         * (a value encoded as type BIT STRING) as follows: The most
         * significant bit of the value of the OCTET STRING becomes
         * the most significant bit of the value of the BIT STRING
         * and so on with consecutive bits until the least significant
         * bit of the OCTET STRING becomes the least significant bit
         * of the BIT STRING.
         */
        TRACE_INFO("%s ecpoint length 0x%lx\n", __func__, bit_str_len);
        data_len = bit_str_len;
        data = key;

#ifdef DEBUG
        TRACE_DEBUG("%s ec_generate_keypair ecpoint:\n", __func__);
        TRACE_DEBUG_DUMP(data, data_len);
#endif

        /* build and add CKA_EC_POINT */
        rc = build_attribute(CKA_EC_POINT, data, data_len, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        rc = template_update_attribute(publ_tmpl, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        /* copy CKA_EC_PARAMS/CKA_ECDSA_PARAMS to private template  */
        if (template_attribute_find(publ_tmpl, CKA_EC_PARAMS, &attr)) {
            rc = build_attribute(attr->type, attr->pValue,
                                 attr->ulValueLen, &n_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                            __func__, rc);
                goto error;
            }

            rc = template_update_attribute(priv_tmpl, n_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s template_update_attribute failed with "
                            "rc=0x%lx\n", __func__, rc);
                goto error;
            }
        }

        if (template_attribute_find(publ_tmpl, CKA_ECDSA_PARAMS, &attr)) {
            rc = build_attribute(attr->type, attr->pValue,
                                 attr->ulValueLen, &n_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                            __func__, rc);
                goto error;
            }

            rc = template_update_attribute(priv_tmpl, n_attr);
            if (rc != CKR_OK) {
                TRACE_ERROR("%s template_update_attribute failed with "
                            "rc=0x%lx\n", __func__, rc);
                goto error;
            }
        }
    } else {
        /* scan the SPKI for modulus and public exponent and
         * set the public key attributes, a user would use the
         * already built SPKI (in CKA_IBM_OPAQUE of the public key).
         */
        CK_BYTE *modulus, *publ_exp;

        rc = ep11_spki_key(spki, &key, &bit_str_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s read key from SPKI failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        /* key must be a sequence holding two integers,
         * modulus and public exponent
         */
        rc = ber_decode_SEQUENCE(key, &data, &data_len, &field_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s read sequence failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        modulus = key + field_len - data_len;
        rc = ber_decode_INTEGER(modulus, &data, &data_len, &field_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s read modulus failed with rc=0x%lx\n", __func__, rc);
            goto error;
        }
#ifdef DEBUG
        TRACE_DEBUG("%s rsa_generate_keypair modulus:\n", __func__);
        TRACE_DEBUG_DUMP(data, data_len);
#endif

        /* build and add CKA_MODULUS */
        rc = build_attribute(CKA_MODULUS, data, data_len, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        rc = template_update_attribute(publ_tmpl, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        /* read public exponent */
        publ_exp = modulus + field_len;
        rc = ber_decode_INTEGER(publ_exp, &data, &data_len, &field_len);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s read public exponent failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
#ifdef DEBUG
        TRACE_DEBUG("%s rsa_generate_keypair public exponent:\n", __func__);
        TRACE_DEBUG_DUMP(data, data_len);
#endif

        /* build and add CKA_PUBLIC_EXPONENT */
        rc = build_attribute(CKA_PUBLIC_EXPONENT, data, data_len, &attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
        rc = template_update_attribute(publ_tmpl, attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }
    }

error:
    if (new_pPrivateKeyTemplate)
        free_attribute_array(new_pPrivateKeyTemplate,
                             new_ulPrivateKeyAttributeCount);
    if (new_pPublicKeyTemplate)
        free_attribute_array(new_pPublicKeyTemplate,
                             new_ulPublicKeyAttributeCount);
    return rc;
}


/* generic function to generate RSA,DH,EC and DSA key pairs */
CK_RV ep11tok_generate_key_pair(STDLL_TokData_t * tokdata, SESSION * sess,
                                CK_MECHANISM_PTR pMechanism,
                                CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                CK_ULONG ulPublicKeyAttributeCount,
                                CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                CK_ULONG ulPrivateKeyAttributeCount,
                                CK_OBJECT_HANDLE_PTR phPublicKey,
                                CK_OBJECT_HANDLE_PTR phPrivateKey)
{
    CK_RV rc;
    OBJECT *public_key_obj = NULL;
    OBJECT *private_key_obj = NULL;
    CK_ULONG priv_ktype, publ_ktype;
    CK_ULONG class;
    CK_ATTRIBUTE *attr = NULL;
    CK_ATTRIBUTE *n_attr = NULL;

    /* Get the keytype to use when creating the key object */
    rc = ep11_get_keytype(pPrivateKeyTemplate, ulPrivateKeyAttributeCount,
                          pMechanism, &priv_ktype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_keytype failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = ep11_get_keytype(pPublicKeyTemplate, ulPublicKeyAttributeCount,
                          pMechanism, &publ_ktype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_keytype failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    /* Now build the skeleton key. */
    rc = object_mgr_create_skel(tokdata, sess, pPublicKeyTemplate,
                                ulPublicKeyAttributeCount, MODE_KEYGEN,
                                CKO_PUBLIC_KEY, publ_ktype, &public_key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Object mgr create skeleton failed\n", __func__);
        goto error;
    }

    rc = object_mgr_create_skel(tokdata, sess, pPrivateKeyTemplate,
                                ulPrivateKeyAttributeCount, MODE_KEYGEN,
                                CKO_PRIVATE_KEY, priv_ktype, &private_key_obj);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Object mgr create skeleton failed\n", __func__);
        goto error;
    }

    switch (pMechanism->mechanism) {
    case CKM_DH_PKCS_KEY_PAIR_GEN:
        rc = dh_generate_keypair(tokdata, sess, pMechanism,
                                 public_key_obj->template,
                                 private_key_obj->template,
                                 pPublicKeyTemplate,
                                 ulPublicKeyAttributeCount,
                                 pPrivateKeyTemplate,
                                 ulPrivateKeyAttributeCount, sess->handle);
        break;
    case CKM_EC_KEY_PAIR_GEN:  /* takes same parameters as RSA */
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
    case CKM_RSA_X9_31_KEY_PAIR_GEN:
        rc = rsa_ec_generate_keypair(tokdata, sess, pMechanism,
                                     public_key_obj->template,
                                     private_key_obj->template,
                                     pPublicKeyTemplate,
                                     ulPublicKeyAttributeCount,
                                     pPrivateKeyTemplate,
                                     ulPrivateKeyAttributeCount, sess->handle);
        break;
    case CKM_DSA_PARAMETER_GEN:
    case CKM_DSA_KEY_PAIR_GEN:
        rc = dsa_generate_keypair(tokdata, sess, pMechanism,
                                  public_key_obj->template,
                                  private_key_obj->template,
                                  pPublicKeyTemplate,
                                  ulPublicKeyAttributeCount,
                                  pPrivateKeyTemplate,
                                  ulPrivateKeyAttributeCount, sess->handle);
        break;
    default:
        TRACE_ERROR("%s invalid mech %s\n", __func__,
                    ep11_get_ckm(pMechanism->mechanism));
        rc = CKR_MECHANISM_INVALID;
        goto error;
    }

    if (rc != CKR_OK) {
        TRACE_ERROR("%s rc=0x%lx hpubkey=0x%lx hprivkey=0x%lx"
                    " pub_name='%s' priv_name='%s' pub_obj=%p priv_obj=%p\n",
                    __func__, rc, *phPublicKey, *phPrivateKey,
                    public_key_obj->name, private_key_obj->name,
                    (void *)public_key_obj, (void *)private_key_obj);
        goto error;
    } else {
        TRACE_INFO("%s rc=0x%lx hpubkey=0x%lx hprivkey=0x%lx"
                   " pub_name='%s' priv_name='%s' pub_obj=%p priv_obj=%p\n",
                   __func__, rc, *phPublicKey, *phPrivateKey,
                   public_key_obj->name, private_key_obj->name,
                   (void *)public_key_obj, (void *)private_key_obj);
    }

    /* Copy CKA_MODULUS and CKA_PUBLIC_EXPONENT attributes from
     * public key object to private key object to fulfill PKCS#11
     * private key template requirements
     */

    if (template_attribute_find(public_key_obj->template, CKA_MODULUS, &attr)) {
        rc = build_attribute(attr->type, attr->pValue, attr->ulValueLen,
                             &n_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        rc = template_update_attribute(private_key_obj->template, n_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto error;
        }
    }

    if (template_attribute_find(public_key_obj->template,
                                CKA_PUBLIC_EXPONENT, &attr)) {
        rc = build_attribute(attr->type, attr->pValue, attr->ulValueLen,
                             &n_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n",
                        __func__, rc);
            goto error;
        }

        rc = template_update_attribute(private_key_obj->template, n_attr);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s template_update_attribute failed with "
                        "rc=0x%lx\n", __func__, rc);
            goto error;
        }
    }

    /* Keys should be fully constructed,
     * assign object handles and store keys.
     */
    rc = object_mgr_create_final(tokdata, sess, public_key_obj, phPublicKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Object mgr create final failed\n", __func__);
        goto error;
    }

    rc = object_mgr_create_final(tokdata, sess, private_key_obj, phPrivateKey);
    if (rc != CKR_OK) {
        TRACE_DEVEL("%s Object mgr create final failed\n", __func__);
        object_mgr_destroy_object(tokdata, sess, *phPublicKey);
        public_key_obj = NULL;
        goto error;
    }
    return rc;

error:
    if (public_key_obj)
        object_free(public_key_obj);
    if (private_key_obj)
        object_free(private_key_obj);

    *phPublicKey = 0;
    *phPrivateKey = 0;

    return rc;
}


/* Returns a blob for a key object.
 * The blob is created if none was build yet.
 */
static CK_RV obj_opaque_2_blob(STDLL_TokData_t *tokdata, OBJECT *key_obj,
                               CK_BYTE **blob, size_t *blobsize)
{
    CK_ATTRIBUTE *attr = NULL;

    UNUSED(tokdata);

    /* blob already exists */
    if (template_attribute_find(key_obj->template, CKA_IBM_OPAQUE, &attr) &&
        (attr->ulValueLen > 0)) {
        *blob = attr->pValue;
        *blobsize = (size_t) attr->ulValueLen;
        TRACE_INFO("%s blob found blobsize=0x%zx\n", __func__, *blobsize);
        return CKR_OK;
    } else {

        /* should not happen, imported key types not supported
         * should cause a failing token_specific_object_add
         */
        TRACE_ERROR("%s no blob\n", __func__);
        return CKR_ATTRIBUTE_VALUE_INVALID;
    }
}

/* Returns a blob for a key handle.
 * The blob is created if none was build yet.
 */
static CK_RV h_opaque_2_blob(STDLL_TokData_t *tokdata, CK_OBJECT_HANDLE handle,
                             CK_BYTE **blob, size_t *blobsize, OBJECT **kobj)
{
    OBJECT *key_obj;
    CK_RV rc;

    /* find the key obj by the key handle */
    rc = object_mgr_find_in_map1(tokdata, handle, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s key 0x%lx not mapped\n", __func__, handle);
        if (rc == CKR_OBJECT_HANDLE_INVALID)
            rc = CKR_KEY_HANDLE_INVALID;
        return rc;
    }

    rc = obj_opaque_2_blob(tokdata, key_obj, blob, blobsize);

    if (rc == CKR_OK)
        *kobj = key_obj;

    return rc;
}

CK_RV ep11tok_sign_init(STDLL_TokData_t * tokdata, SESSION * session,
                        CK_MECHANISM * mech, CK_BBOOL recover_mode,
                        CK_OBJECT_HANDLE key)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;
    size_t ep11_sign_state_l = MAX_SIGN_STATE_BYTES;
    CK_BYTE *ep11_sign_state = malloc(ep11_sign_state_l);

    UNUSED(recover_mode);

    if (!ep11_sign_state) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    rc = h_opaque_2_blob(tokdata, key, &keyblob, &keyblobsize, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_START
        rc = dll_m_SignInit(ep11_sign_state, &ep11_sign_state_l,
                            mech, keyblob, keyblobsize,
                            (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx blobsize=0x%zx key=0x%lx mech=0x%lx\n",
                    __func__, rc, keyblobsize, key, mech->mechanism);
        free(ep11_sign_state);
    } else {
        /* SIGN_VERIFY_CONTEX holds all needed for continuing,
         * also by another adapter (stateless requests)
         */
        ctx->key = key;
        ctx->active = TRUE;
        ctx->context = ep11_sign_state;
        ctx->context_len = ep11_sign_state_l;

        TRACE_INFO("%s rc=0x%lx blobsize=0x%zx key=0x%lx mech=0x%lx\n",
                   __func__, rc, keyblobsize, key, mech->mechanism);
    }

    return rc;
}


CK_RV ep11tok_sign(STDLL_TokData_t * tokdata, SESSION * session,
                   CK_BBOOL length_only, CK_BYTE * in_data,
                   CK_ULONG in_data_len, CK_BYTE * signature,
                   CK_ULONG * sig_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;

    UNUSED(length_only);

    RETRY_START
        rc = dll_m_Sign(ctx->context, ctx->context_len, in_data, in_data_len,
                        signature, sig_len, (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_sign_update(STDLL_TokData_t * tokdata, SESSION * session,
                          CK_BYTE * in_data, CK_ULONG in_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;

    if (!in_data || !in_data_len)
        return CKR_OK;

    RETRY_START
        rc = dll_m_SignUpdate(ctx->context, ctx->context_len, in_data,
                              in_data_len, (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_sign_final(STDLL_TokData_t * tokdata, SESSION * session,
                         CK_BBOOL length_only, CK_BYTE * signature,
                         CK_ULONG * sig_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->sign_ctx;

    UNUSED(length_only);

    RETRY_START
        rc = dll_m_SignFinal(ctx->context, ctx->context_len, signature, sig_len,
                             (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV ep11tok_sign_single(STDLL_TokData_t *tokdata, SESSION *session,
                          CK_MECHANISM *mech, CK_BBOOL length_only,
                          CK_OBJECT_HANDLE key, CK_BYTE *in_data,
                          CK_ULONG in_data_len, CK_BYTE *signature,
                          CK_ULONG *sig_len)
{
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    ep11_private_data_t *ep11_data = tokdata->private_data;

    UNUSED(length_only);

    rc = h_opaque_2_blob(tokdata, key, &keyblob, &keyblobsize, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_START
    rc = dll_m_SignSingle(keyblob, keyblobsize, mech, in_data, in_data_len,
                          signature, sig_len,
                          (uint64_t)ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_verify_init(STDLL_TokData_t * tokdata, SESSION * session,
                          CK_MECHANISM * mech, CK_BBOOL recover_mode,
                          CK_OBJECT_HANDLE key)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE *spki;
    size_t spki_len = 0;
    OBJECT *key_obj = NULL;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;
    size_t ep11_sign_state_l = MAX_SIGN_STATE_BYTES;
    CK_BYTE *ep11_sign_state = malloc(ep11_sign_state_l);

    UNUSED(recover_mode);

    if (!ep11_sign_state) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    rc = h_opaque_2_blob(tokdata, key, &spki, &spki_len, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_START
        rc = dll_m_VerifyInit(ep11_sign_state, &ep11_sign_state_l, mech,
                              spki, spki_len,
                              (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx spki_len=0x%zx key=0x%lx "
                    "ep11_sign_state_l=0x%zx mech=0x%lx\n", __func__,
                    rc, spki_len, key, ep11_sign_state_l, mech->mechanism);
    } else {
        ctx->key = key;
        ctx->active = TRUE;
        ctx->context = ep11_sign_state;
        ctx->context_len = ep11_sign_state_l;

        TRACE_INFO("%s rc=0x%lx spki_len=0x%zx key=0x%lx "
                   "ep11_sign_state_l=0x%zx mech=0x%lx\n", __func__,
                   rc, spki_len, key, ep11_sign_state_l, mech->mechanism);
    }

    return rc;
}


CK_RV ep11tok_verify(STDLL_TokData_t * tokdata, SESSION * session,
                     CK_BYTE * in_data, CK_ULONG in_data_len,
                     CK_BYTE * signature, CK_ULONG sig_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;

    RETRY_START
        rc = dll_m_Verify(ctx->context, ctx->context_len, in_data, in_data_len,
                          signature, sig_len,
                          (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_verify_update(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_BYTE * in_data, CK_ULONG in_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;

    if (!in_data || !in_data_len)
        return CKR_OK;

    RETRY_START
        rc = dll_m_VerifyUpdate(ctx->context, ctx->context_len, in_data,
                                in_data_len, (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_verify_final(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_BYTE * signature, CK_ULONG sig_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    SIGN_VERIFY_CONTEXT *ctx = &session->verify_ctx;

    RETRY_START
        rc = dll_m_VerifyFinal(ctx->context, ctx->context_len, signature,
                               sig_len, (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV ep11tok_verify_single(STDLL_TokData_t *tokdata, SESSION *session,
                            CK_MECHANISM *mech, CK_OBJECT_HANDLE key,
                            CK_BYTE *in_data, CK_ULONG in_data_len,
                            CK_BYTE *signature, CK_ULONG sig_len)
{
    CK_RV rc;
    CK_BYTE *spki;
    size_t spki_len = 0;
    OBJECT *key_obj = NULL;
    ep11_private_data_t *ep11_data = tokdata->private_data;

    rc = h_opaque_2_blob(tokdata, key, &spki, &spki_len, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_START
    rc = dll_m_VerifySingle(spki, spki_len, mech, in_data, in_data_len,
                            signature, sig_len,
                            (uint64_t)ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV ep11tok_decrypt_final(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_BYTE_PTR output_part,
                            CK_ULONG_PTR p_output_part_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;

    RETRY_START
        rc = dll_m_DecryptFinal(ctx->context, ctx->context_len,
                                output_part, p_output_part_len,
                                (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_decrypt(STDLL_TokData_t * tokdata, SESSION * session,
                      CK_BYTE_PTR input_data, CK_ULONG input_data_len,
                      CK_BYTE_PTR output_data, CK_ULONG_PTR p_output_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;

    RETRY_START
        rc = dll_m_Decrypt(ctx->context, ctx->context_len, input_data,
                           input_data_len, output_data, p_output_data_len,
                           (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_decrypt_update(STDLL_TokData_t * tokdata, SESSION * session,
                             CK_BYTE_PTR input_part, CK_ULONG input_part_len,
                             CK_BYTE_PTR output_part,
                             CK_ULONG_PTR p_output_part_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;

    if (!input_part || !input_part_len) {
        *p_output_part_len = 0;
        return CKR_OK;          /* nothing to update, keep context */
    }

    RETRY_START
        rc = dll_m_DecryptUpdate(ctx->context, ctx->context_len,
                                 input_part, input_part_len, output_part,
                                 p_output_part_len,
                                 (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV ep11tok_decrypt_single(STDLL_TokData_t *tokdata, SESSION *session,
                             CK_MECHANISM *mech, CK_BBOOL length_only,
                             CK_OBJECT_HANDLE key, CK_BYTE_PTR input_data,
                             CK_ULONG input_data_len, CK_BYTE_PTR output_data,
                             CK_ULONG_PTR p_output_data_len)
{
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    ep11_private_data_t *ep11_data = tokdata->private_data;

    UNUSED(length_only);

    rc = h_opaque_2_blob(tokdata, key, &keyblob, &keyblobsize, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_START
    rc = dll_m_DecryptSingle(keyblob, keyblobsize, mech, input_data,
                             input_data_len, output_data, p_output_data_len,
                             (uint64_t)ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV ep11tok_encrypt_final(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_BYTE_PTR output_part,
                            CK_ULONG_PTR p_output_part_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;

    RETRY_START
        rc = dll_m_EncryptFinal(ctx->context, ctx->context_len,
                                output_part, p_output_part_len,
                                (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_encrypt(STDLL_TokData_t * tokdata, SESSION * session,
                      CK_BYTE_PTR input_data, CK_ULONG input_data_len,
                      CK_BYTE_PTR output_data, CK_ULONG_PTR p_output_data_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;

    RETRY_START
        rc = dll_m_Encrypt(ctx->context, ctx->context_len, input_data,
                           input_data_len, output_data, p_output_data_len,
                           (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_encrypt_update(STDLL_TokData_t * tokdata, SESSION * session,
                             CK_BYTE_PTR input_part, CK_ULONG input_part_len,
                             CK_BYTE_PTR output_part,
                             CK_ULONG_PTR p_output_part_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;

    if (!input_part || !input_part_len) {
        *p_output_part_len = 0;
        return CKR_OK;          /* nothing to update, keep context */
    }

    RETRY_START
        rc = dll_m_EncryptUpdate(ctx->context, ctx->context_len,
                                 input_part, input_part_len, output_part,
                                 p_output_part_len,
                                 (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

CK_RV ep11tok_encrypt_single(STDLL_TokData_t *tokdata, SESSION *session,
                             CK_MECHANISM *mech, CK_BBOOL length_only,
                             CK_OBJECT_HANDLE key, CK_BYTE_PTR input_data,
                             CK_ULONG input_data_len, CK_BYTE_PTR output_data,
                             CK_ULONG_PTR p_output_data_len)
{
    CK_RV rc;
    size_t keyblobsize = 0;
    CK_BYTE *keyblob;
    OBJECT *key_obj = NULL;
    ep11_private_data_t *ep11_data = tokdata->private_data;

    UNUSED(length_only);

    rc = h_opaque_2_blob(tokdata, key, &keyblob, &keyblobsize, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    RETRY_START
    rc = dll_m_EncryptSingle(keyblob, keyblobsize, mech, input_data,
                             input_data_len, output_data, p_output_data_len,
                             (uint64_t)ep11_data->target_list);
    RETRY_END(rc, tokdata, session)
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}

static CK_RV ep11_ende_crypt_init(STDLL_TokData_t * tokdata, SESSION * session,
                                  CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key,
                                  int op)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc = CKR_OK;
    CK_BYTE *blob;
    size_t blob_len = 0;
    OBJECT *key_obj = NULL;
    size_t ep11_state_l = MAX_CRYPT_STATE_BYTES;
    CK_BYTE *ep11_state = malloc(ep11_state_l); /* freed by encr/decr_mgr.c */

    if (!ep11_state) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }

    rc = h_opaque_2_blob(tokdata, key, &blob, &blob_len, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s no blob rc=0x%lx\n", __func__, rc);
        return rc;
    }

    if (op == DECRYPT) {
        ENCR_DECR_CONTEXT *ctx = &session->decr_ctx;
        RETRY_START
            rc = dll_m_DecryptInit(ep11_state, &ep11_state_l, mech, blob,
                                   blob_len, (uint64_t) ep11_data->target_list);
        RETRY_END(rc, tokdata, session)
        ctx->key = key;
        ctx->active = TRUE;
        ctx->context = ep11_state;
        ctx->context_len = ep11_state_l;
        if (rc != CKR_OK) {
            decr_mgr_cleanup(ctx);
            rc = ep11_error_to_pkcs11_error(rc, session);
            TRACE_ERROR("%s m_DecryptInit rc=0x%lx blob_len=0x%zx "
                        "mech=0x%lx\n", __func__, rc, blob_len,
                        mech->mechanism);
        } else {
            TRACE_INFO("%s m_DecryptInit rc=0x%lx blob_len=0x%zx "
                       "mech=0x%lx\n", __func__, rc, blob_len, mech->mechanism);
        }
    } else {
        ENCR_DECR_CONTEXT *ctx = &session->encr_ctx;
        RETRY_START
            rc = dll_m_EncryptInit(ep11_state, &ep11_state_l, mech, blob,
                                   blob_len, (uint64_t) ep11_data->target_list);
        RETRY_END(rc, tokdata, session)
        ctx->key = key;
        ctx->active = TRUE;
        ctx->context = ep11_state;
        ctx->context_len = ep11_state_l;
        if (rc != CKR_OK) {
            encr_mgr_cleanup(ctx);
            rc = ep11_error_to_pkcs11_error(rc, session);
            TRACE_ERROR("%s m_EncryptInit rc=0x%lx blob_len=0x%zx "
                        "mech=0x%lx\n", __func__, rc, blob_len,
                        mech->mechanism);
        } else {
            TRACE_INFO("%s m_EncryptInit rc=0x%lx blob_len=0x%zx "
                       "mech=0x%lx\n", __func__, rc, blob_len, mech->mechanism);
        }
    }

    return rc;
}


CK_RV ep11tok_encrypt_init(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key)
{
    CK_RV rc;

    TRACE_INFO("%s key=0x%lx\n", __func__, key);

    rc = ep11_ende_crypt_init(tokdata, session, mech, key, ENCRYPT);

    if (rc != CKR_OK) {
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_decrypt_init(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key)
{
    CK_RV rc;

    TRACE_INFO("%s key=0x%lx mech=0x%lx\n", __func__, key, mech->mechanism);

    rc = ep11_ende_crypt_init(tokdata, session, mech, key, DECRYPT);

    if (rc != CKR_OK) {
        TRACE_ERROR("%s rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx\n", __func__, rc);
    }

    return rc;
}


CK_RV ep11tok_wrap_key(STDLL_TokData_t * tokdata, SESSION * session,
                       CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE wrapping_key,
                       CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped_key,
                       CK_ULONG_PTR p_wrapped_key_len)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE *wrapping_blob;
    size_t wrapping_blob_len;

    CK_BYTE *wrap_target_blob;
    size_t wrap_target_blob_len;
    int size_querry = 0;
    OBJECT *key_obj = NULL;
    CK_ATTRIBUTE *attr;

    /* ep11 weakness:
     * it does not set *p_wrapped_key_len if wrapped_key == NULL
     * (that is with a size query)
     */
    if (wrapped_key == NULL) {
        size_querry = 1;
        *p_wrapped_key_len = MAX_BLOBSIZE;
        wrapped_key = malloc(MAX_BLOBSIZE);
        if (!wrapped_key) {
            TRACE_ERROR("%s Memory allocation failed\n", __func__);
            return CKR_HOST_MEMORY;
        }
    }

    /* the key that encrypts */
    rc = h_opaque_2_blob(tokdata, wrapping_key, &wrapping_blob,
                         &wrapping_blob_len, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob(wrapping_key) failed with rc=0x%lx\n",
                    __func__, rc);
        if (size_querry)
            free(wrapped_key);
        return rc;
    }

    /* the key to be wrapped */
    rc = h_opaque_2_blob(tokdata, key, &wrap_target_blob,
                         &wrap_target_blob_len, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob(key) failed with rc=0x%lx\n", __func__,
                    rc);
        if (size_querry)
            free(wrapped_key);
        return rc;
    }

    /* check if wrap mechanism is allowed for the key to be wrapped.
     * AES_ECB and AES_CBC is only allowed to wrap secret keys.
     */
    if (!template_attribute_find(key_obj->template, CKA_CLASS, &attr)) {
        TRACE_ERROR("%s No CKA_CLASS attribute found in key template\n",
                    __func__);
        return CKR_TEMPLATE_INCOMPLETE;
    }

    if ((*(CK_OBJECT_CLASS *) attr->pValue != CKO_SECRET_KEY) &&
        ((mech->mechanism == CKM_AES_ECB) ||
         (mech->mechanism == CKM_AES_CBC))) {
        TRACE_ERROR("%s Wrap mechanism does not match to target key type\n",
                    __func__);
        return CKR_KEY_NOT_WRAPPABLE;
    }

    /* debug */
    TRACE_INFO("%s start wrapKey: mech=0x%lx wr_key=0x%lx\n",
               __func__, mech->mechanism, wrapping_key);

    /* the key to be wrapped is extracted from its blob by the card
     * and a standard BER encoding is build which is encryted by
     * the wrapping key (wrapping_blob).
     * The wrapped key can be processed by any PKCS11 implementation.
     */
    RETRY_START
        rc =
        dll_m_WrapKey(wrap_target_blob, wrap_target_blob_len, wrapping_blob,
                      wrapping_blob_len, NULL, ~0, mech, wrapped_key,
                      p_wrapped_key_len, (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        TRACE_ERROR("%s m_WrapKey failed with rc=0x%lx\n", __func__, rc);
    } else {
        TRACE_INFO("%s rc=0x%lx wr_key=%p wr_key_len=0x%lx\n",
                   __func__, rc, (void *)wrapped_key, *p_wrapped_key_len);
    }

    if (size_querry)
        free(wrapped_key);
    return rc;
}


CK_RV ep11tok_unwrap_key(STDLL_TokData_t * tokdata, SESSION * session,
                         CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs,
                         CK_ULONG attrs_len, CK_BYTE_PTR wrapped_key,
                         CK_ULONG wrapped_key_len,
                         CK_OBJECT_HANDLE wrapping_key,
                         CK_OBJECT_HANDLE_PTR p_key)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_BYTE *wrapping_blob;
    size_t wrapping_blob_len;
    CK_BYTE csum[MAX_BLOBSIZE];
    CK_ULONG cslen = sizeof(csum);
    OBJECT *key_obj = NULL;
    CK_BYTE keyblob[MAX_BLOBSIZE];
    size_t keyblobsize = sizeof(keyblob);
    CK_ATTRIBUTE *attr = NULL;
    CK_ULONG i;
    CK_ULONG ktype;
    CK_ULONG class;
    CK_ULONG len;
    CK_ATTRIBUTE_PTR new_attrs = NULL;
    CK_ULONG new_attrs_len = 0;
    OBJECT *kobj = NULL;
    unsigned char *ep11_pin_blob = NULL;
    CK_ULONG ep11_pin_blob_len = 0;
    ep11_session_t *ep11_session = (ep11_session_t *) session->private_data;

    /* get wrapping key blob */
    rc = h_opaque_2_blob(tokdata, wrapping_key, &wrapping_blob,
                         &wrapping_blob_len, &kobj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s h_opaque_2_blob(wrapping_key) failed with rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }

    TRACE_DEVEL("%s start unwrapKey:  mech=0x%lx attrs_len=0x%lx "
                "wr_key=0x%lx\n", __func__, mech->mechanism, attrs_len,
                wrapping_key);
    for (i = 0; i < attrs_len; i++) {
        TRACE_DEVEL(" attribute attrs.type=0x%lx\n", attrs[i].type);
    }

    memset(keyblob, 0, sizeof(keyblob));

    /*get key type of unwrapped key */
    CK_ATTRIBUTE_PTR cla_attr =
        get_attribute_by_type(attrs, attrs_len, CKA_CLASS);
    CK_ATTRIBUTE_PTR keytype_attr =
        get_attribute_by_type(attrs, attrs_len, CKA_KEY_TYPE);
    if (!cla_attr || !keytype_attr) {
        TRACE_ERROR("%s CKA_CLASS or CKA_KEY_CLASS attributes not found\n",
                    __func__);
        return CKR_TEMPLATE_INCONSISTENT;
    }
    switch (*(CK_KEY_TYPE *) cla_attr->pValue) {
    case CKO_SECRET_KEY:
        rc = check_key_attributes(tokdata,
                                  *(CK_KEY_TYPE *) keytype_attr->pValue,
                                  CKO_SECRET_KEY, attrs,
                                  attrs_len, &new_attrs, &new_attrs_len);
        break;
    case CKO_PUBLIC_KEY:
        rc = check_key_attributes(tokdata,
                                  *(CK_KEY_TYPE *) keytype_attr->pValue,
                                  CKO_PUBLIC_KEY, attrs, attrs_len,
                                  &new_attrs, &new_attrs_len);
        break;
    case CKO_PRIVATE_KEY:
        rc = check_key_attributes(tokdata,
                                  *(CK_KEY_TYPE *) keytype_attr->pValue,
                                  CKO_PRIVATE_KEY, attrs, attrs_len,
                                  &new_attrs, &new_attrs_len);
        break;
    default:
        TRACE_ERROR("%s Missing CKA_CLASS type of wrapped key\n", __func__);
        return CKR_TEMPLATE_INCOMPLETE;
    }
    if (rc != CKR_OK) {
        TRACE_ERROR("%s check key attributes failed: rc=0x%lx\n", __func__, rc);
        goto error;
    }

    /* check if unwrap mechanism is allowed for the key to be unwrapped.
     * AES_ECB and AES_CBC only allowed to unwrap secret keys.
     */
    if ((*(CK_OBJECT_CLASS *) cla_attr->pValue != CKO_SECRET_KEY) &&
        ((mech->mechanism == CKM_AES_ECB) || (mech->mechanism == CKM_AES_CBC)))
        return CKR_ARGUMENTS_BAD;

    ep11_get_pin_blob(ep11_session, ep11_is_session_object(attrs, attrs_len),
                      &ep11_pin_blob, &ep11_pin_blob_len);

    /* we need a blob for the new key created by unwrapping,
     * the wrapped key comes in BER
     */
    RETRY_START
        rc = dll_m_UnwrapKey(wrapped_key, wrapped_key_len, wrapping_blob,
                             wrapping_blob_len, NULL, ~0, ep11_pin_blob,
                             ep11_pin_blob_len, mech, new_attrs, new_attrs_len,
                             keyblob, &keyblobsize, csum, &cslen,
                             (uint64_t) ep11_data->target_list);
    RETRY_END(rc, tokdata, session)

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s m_UnwrapKey rc=0x%lx blobsize=0x%zx mech=0x%lx\n",
                    __func__, rc, keyblobsize, mech->mechanism);
        goto error;
    }
    TRACE_INFO("%s m_UnwrapKey rc=0x%lx blobsize=0x%zx mech=0x%lx\n",
               __func__, rc, keyblobsize, mech->mechanism);

    /* card provides length in csum bytes 4 - 7, big endian */
    len =
        csum[6] + 256 * csum[5] + 256 * 256 * csum[4] +
        256 * 256 * 256 * csum[3];
    len = len / 8;              /* comes in bits */
    TRACE_INFO("%s m_UnwrapKey length 0x%hhx 0x%hhx 0x%hhx 0x%hhx 0x%lx\n",
               __func__, csum[3], csum[4], csum[5], csum[6], len);

    /* Get the keytype to use when creating the key object */
    rc = ep11_get_keytype(new_attrs, new_attrs_len, mech, &ktype, &class);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s get_subclass failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    /* Start creating the key object */
    rc = object_mgr_create_skel(tokdata, session, new_attrs, new_attrs_len,
                                MODE_UNWRAP, class, ktype, &key_obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_skel failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = build_attribute(CKA_IBM_OPAQUE, keyblob, keyblobsize, &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = template_update_attribute(key_obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    rc = build_attribute(CKA_VALUE_LEN, (CK_BYTE *) & len, sizeof(CK_ULONG),
                         &attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s build_attribute failed with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    rc = template_update_attribute(key_obj->template, attr);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s template_update_attribute failed with rc=0x%lx\n",
                    __func__, rc);
        goto error;
    }

    /*
     * In case of unwrapping an EC private key
     * (CKA_CLASS == CKO_PRIVATE_KEY, CKA_KEY_TYPE == CKK_EC),
     * the following attributes needs to be added to the new template.
     * CKA_EC_PARAMS (curve's algorithm id)
     * CKA_EC_POINT (public key information)
     */
    if ((*(CK_OBJECT_CLASS *) cla_attr->pValue == CKO_PRIVATE_KEY) &&
        (*(CK_KEY_TYPE *) keytype_attr->pValue == CKK_EC)) {
        ecdsa_priv_unwrap_get_data(key_obj->template, csum, cslen);
    }

    /* key should be fully constructed.
     * Assign an object handle and store key.
     */
    rc = object_mgr_create_final(tokdata, session, key_obj, p_key);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s object_mgr_create_final with rc=0x%lx\n", __func__, rc);
        goto error;
    }

    goto done;

error:
    if (key_obj)
        object_free(key_obj);
    *p_key = 0;
done:
    if (new_attrs)
        free_attribute_array(new_attrs, new_attrs_len);

    return rc;
}


/* mechanisms ep11 reports but should be hidden because e.g.
   the EP11 card operates in a FIPS mode that forbides the mechanism,
   add here other mechanisms if required */
static const CK_MECHANISM_TYPE ep11_banned_mech_list[] = {
#ifdef DEFENSIVE_MECHLIST
    CKM_DES_KEY_GEN,
    CKM_DES_ECB,
    CKM_DES_CBC,
    CKM_DES_CBC_PAD,
    CKM_GENERIC_SECRET_KEY_GEN,

    /* Wrong/outdated */
    CKM_EP11_SHA512_224,
    CKM_EP11_SHA512_224_HMAC,
    CKM_EP11_SHA512_224_HMAC_GENERAL,
    CKM_EP11_SHA512_256,
    CKM_EP11_SHA512_256_HMAC,
    CKM_EP11_SHA512_256_HMAC_GENERAL,

    /* Vendor specific */
    CKM_IBM_CMAC,
    CKM_IBM_ECDSA_SHA224,
    CKM_IBM_ECDSA_SHA256,
    CKM_IBM_ECDSA_SHA384,
    CKM_IBM_ECDSA_SHA512,
    CKM_IBM_EC_MULTIPLY,
    CKM_IBM_EAC,
    CKM_IBM_SHA512_256,
    CKM_IBM_SHA512_224,
    CKM_IBM_SHA512_256_HMAC,
    CKM_IBM_SHA512_224_HMAC,
    CKM_IBM_SHA512_256_KEY_DERIVATION,
    CKM_IBM_SHA512_224_KEY_DERIVATION,
    CKM_IBM_EC_C25519,
    CKM_IBM_EDDSA_SHA512,
    CKM_IBM_EDDSA_PH_SHA512,
    CKM_IBM_EC_C448,
    CKM_IBM_SIPHASH,
    CKM_IBM_CLEARKEY_TRANSPORT,
    CKM_IBM_ATTRIBUTEBOUND_WRAP,
    CKM_IBM_TRANSPORTKEY,
    CKM_IBM_DH_PKCS_DERIVE_RAW,
    CKM_IBM_ECDH1_DERIVE_RAW,
    CKM_IBM_WIRETEST,
    CKM_IBM_RETAINKEY,

#endif
};

static const CK_ULONG banned_mech_list_len =
    (sizeof(ep11_banned_mech_list) / sizeof(CK_MECHANISM_TYPE));


/* filtering out some mechanisms we do not want to provide
 * makes it complicated
 */
CK_RV ep11tok_get_mechanism_list(STDLL_TokData_t * tokdata,
                                 CK_MECHANISM_TYPE_PTR pMechanismList,
                                 CK_ULONG_PTR pulCount)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc = 0;
    CK_ULONG counter = 0, size = 0;
    CK_MECHANISM_TYPE_PTR mlist = NULL;
    CK_ULONG i;

    /* size querry */
    if (pMechanismList == NULL) {
        rc = dll_m_GetMechanismList(0, pMechanismList, pulCount,
                                    (uint64_t) ep11_data->target_list);
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #1\n",
                        __func__, rc);
            return rc;
        }

        /* adjust the size according to the ban list,
         * for this we need to know what the card provides
         */
        counter = *pulCount;
        mlist =
            (CK_MECHANISM_TYPE *) malloc(sizeof(CK_MECHANISM_TYPE) * counter);
        if (!mlist) {
            TRACE_ERROR("%s Memory allocation failed\n", __func__);
            return CKR_HOST_MEMORY;
        }
        rc = dll_m_GetMechanismList(0, mlist, &counter,
                                    (uint64_t) ep11_data->target_list);
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #2\n",
                        __func__, rc);
            free(mlist);
            return rc;
        }

        for (i = 0; i < counter; i++) {
            if (ep11tok_is_mechanism_supported(tokdata, mlist[i]) != CKR_OK) {
                /* banned mech found,
                 * decrement reported list size
                 */
                *pulCount = *pulCount - 1;
            }
        }
    } else {
        /* 2. call, content request */
        size = *pulCount;

        /* find out size ep11 will report, cannot use the size
         * that comes as parameter, this is a 'reduced size',
         * ep11 would complain about insufficient list size
         */
        rc = dll_m_GetMechanismList(0, mlist, &counter,
                                    (uint64_t) ep11_data->target_list);
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #3\n",
                        __func__, rc);
            return rc;
        }

        mlist =
            (CK_MECHANISM_TYPE *) malloc(sizeof(CK_MECHANISM_TYPE) * counter);
        if (!mlist) {
            TRACE_ERROR("%s Memory allocation failed\n", __func__);
            return CKR_HOST_MEMORY;
        }
        /* all the card has */
        rc = dll_m_GetMechanismList(0, mlist, &counter,
                                    (uint64_t) ep11_data->target_list);
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s bad rc=0x%lx from m_GetMechanismList() #4\n",
                        __func__, rc);
            free(mlist);
            return rc;
        }

        for (i = 0; i < counter; i++)
            TRACE_INFO("%s raw mech list entry '%s'\n",
                       __func__, ep11_get_ckm(mlist[i]));

        /* copy only mechanisms not banned */
        *pulCount = 0;
        for (i = 0; i < counter; i++) {
            if (ep11tok_is_mechanism_supported(tokdata, mlist[i]) == CKR_OK) {
                if (*pulCount < size)
                    pMechanismList[*pulCount] = mlist[i];
                *pulCount = *pulCount + 1;
            }
        }
        if (*pulCount > size)
            rc = CKR_BUFFER_TOO_SMALL;
    }

    if (mlist)
        free(mlist);
    return rc;
}


CK_RV ep11tok_is_mechanism_supported(STDLL_TokData_t *tokdata,
                                     CK_MECHANISM_TYPE type)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_VERSION ver1_3 = { .major = 1, .minor = 3 };
    CK_ULONG i;
    int status;

    for (i = 0; i < banned_mech_list_len; i++) {
        if (type == ep11_banned_mech_list[i]) {
            TRACE_INFO("%s Mech '%s' banned\n", __func__, ep11_get_ckm(type));
            return CKR_MECHANISM_INVALID;
        }
    }

    if (check_cps_for_mechanism(ep11_data->cp_config,
                                type, ep11_data->control_points,
                                ep11_data->control_points_len,
                                ep11_data->max_control_point_index) != CKR_OK) {
        TRACE_INFO("%s Mech '%s' banned due to control point\n",
                                   __func__, ep11_get_ckm(type));
        return CKR_MECHANISM_INVALID;
    }

    switch(type) {
    case CKM_SHA_1_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA224_HMAC:
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA256_HMAC:
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA384_HMAC:
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_224_HMAC_GENERAL:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA512_256_HMAC_GENERAL:
        /*
         * Older levels of the EP11 firmware report ulMinKeySize in bytes,
         * but ulMaxKeySize in bits for HMAC mechanisms. Newer levels of the
         * EP11 firmware report both ulMinKeySize and ulMaxKeySize in bytes.
         * HMAC mechanisms are only supported when all configured EP11
         * crypto adapters either have the fix, or all don't have the fix.
         */
        status = check_required_versions(tokdata, hmac_req_versions,
                                         NUM_HMAC_REQ);
        if (status == -1) {
            TRACE_INFO("%s Mech '%s' banned due to mixed firmware versions\n",
                        __func__, ep11_get_ckm(type));
            return CKR_MECHANISM_INVALID;
        }
        break;

    case CKM_RSA_PKCS_OAEP:
        /* CKM_RSA_PKCS_OAEP is not supported with EP11 host library <= 1.3 */
        if (compare_ck_version(&ep11_data->ep11_lib_version, &ver1_3) <= 0)
            return CKR_MECHANISM_INVALID;
        break;
    }

    return CKR_OK;
}

CK_RV ep11tok_get_mechanism_info(STDLL_TokData_t * tokdata,
                                 CK_MECHANISM_TYPE type,
                                 CK_MECHANISM_INFO_PTR pInfo)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    int status;

    rc = ep11tok_is_mechanism_supported(tokdata, type);
    if (rc != CKR_OK) {
        TRACE_DEBUG("%s rc=0x%lx unsupported '%s'\n", __func__, rc,
                    ep11_get_ckm(type));
        return rc;
    }

    rc = dll_m_GetMechanismInfo(0, type, pInfo,
                                (uint64_t) ep11_data->target_list);
    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, NULL);
        TRACE_ERROR("%s m_GetMechanismInfo(0x%lx) failed with rc=0x%lx\n",
                    __func__, type, rc);
        return rc;
    }

    /* The card operates always in a FISP mode that requires stronger
     * key sizes, but, in theory, can also operate with weaker key sizes.
     * Customers are not interested in theory but in what mechanism
     * they can use (mechanisms that are not rejected by the card).
     */
#ifdef DEFENSIVE_MECHLIST
    switch (type) {
    case CKM_RSA_PKCS:
    case CKM_RSA_PKCS_KEY_PAIR_GEN:
    case CKM_RSA_X9_31_KEY_PAIR_GEN:
    case CKM_RSA_PKCS_PSS:
    case CKM_RSA_PKCS_OAEP:
    case CKM_SHA1_RSA_X9_31:
    case CKM_SHA1_RSA_PKCS:
    case CKM_SHA1_RSA_PKCS_PSS:
    case CKM_SHA256_RSA_PKCS:
    case CKM_SHA256_RSA_PKCS_PSS:
    case CKM_SHA224_RSA_PKCS:
    case CKM_SHA224_RSA_PKCS_PSS:
    case CKM_SHA384_RSA_PKCS:
    case CKM_SHA384_RSA_PKCS_PSS:
    case CKM_SHA512_RSA_PKCS:
    case CKM_SHA512_RSA_PKCS_PSS:
    case CKM_RSA_X_509:
    case CKM_RSA_X9_31:
        /* EP11 card always in a FIPS mode rejecting
         * lower key sizes
         */
        pInfo->ulMinKeySize = 1024;
        break;

    case CKM_SHA_1_HMAC:
    case CKM_SHA_1_HMAC_GENERAL:
    case CKM_SHA224_HMAC:
    case CKM_SHA224_HMAC_GENERAL:
    case CKM_SHA256_HMAC:
    case CKM_SHA256_HMAC_GENERAL:
    case CKM_SHA384_HMAC:
    case CKM_SHA384_HMAC_GENERAL:
    case CKM_SHA512_HMAC:
    case CKM_SHA512_HMAC_GENERAL:
    case CKM_SHA512_224_HMAC:
    case CKM_SHA512_224_HMAC_GENERAL:
    case CKM_SHA512_256_HMAC:
    case CKM_SHA512_256_HMAC_GENERAL:
        /*
         * Older levels of the EP11 firmware report ulMinKeySize in bytes,
         * but ulMaxKeySize in bits for HMAC mechanisms. Adjust ulMinKeySize
         * so that both are in bits, as required by the PKCS#11 standard.
         * Newer levels of the EP11 firmware report both ulMinKeySize and
         * ulMaxKeySize in bytes. Adjust both, so that both are in bits, as
         * required by the PKCS#11 standard.
         */
        status = check_required_versions(tokdata, hmac_req_versions,
                                         NUM_HMAC_REQ);
        if (status == -1)
            return CKR_MECHANISM_INVALID;

        pInfo->ulMinKeySize *= 8;
        if (status == 1)
            pInfo->ulMaxKeySize *= 8;
        break;

    case CKM_DES3_ECB:
    case CKM_DES3_CBC:
    case CKM_DES3_CBC_PAD:
        /* EP11 card always in a FIPS mode rejecting
         * lower key sizes < 80 bits.
         */
        if (pInfo->ulMinKeySize == 8)
            pInfo->ulMinKeySize = 16;
        break;

    default:
        ; /* do not touch */
    }
#endif                          /* DEFENSIVE_MECHLIST */

    return CKR_OK;
}


/* used for reading in the adapter config file,
 * converts a 'token' to a number, returns 0 with success
 */
static inline short check_n(ep11_target_t * target, char *nptr, int *apqn_i)
{
    int num;

    if (sscanf(nptr, "%i", &num) != 1) {
        TRACE_ERROR("%s invalid number '%s'\n", __func__, nptr);
        return -1;
    }

    if (num < 0 || num > 255) {
        TRACE_ERROR("%s invalid number '%s' %d\n", __func__, nptr, num);
        return -1;
    } else if (*apqn_i < 0 || *apqn_i >= MAX_APQN * 2) {
        TRACE_ERROR("%s invalid amount of numbers %d\n", __func__, num);
        return -1;
    } else {
        /* insert number into target variable */
        target->apqns[*apqn_i] = (short) num;
        /* how many APQNs numbers so far */
        *apqn_i = *apqn_i + 1;
        return 0;
    }
}


static int read_adapter_config_file(STDLL_TokData_t * tokdata,
                                    const char *conf_name)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    FILE *ap_fp = NULL;         /* file pointer adapter config file */
    int i, ap_file_size = 0;    /* size adapter config file */
    char *token, *str;
    char filebuf[EP11_CFG_FILE_SIZE];
    char line[1024];
    int whitemode = 0;
    int anymode = 0;
    int apqn_i = 0;             /* how many APQN numbers */
    char *conf_dir = getenv("OCK_EP11_TOKEN_DIR");
    char fname[PATH_MAX];
    ep11_target_t *ep11_targets = (ep11_target_t *) ep11_data->target_list;
    int rc = 0;
    char *cfg_dir;
    char cfgname[2*PATH_MAX + 1];

    if (tokdata->initialized)
        return 0;

    memset(fname, 0, PATH_MAX);

    /* via envrionment variable it is possible to overwrite the
     * directory where the ep11 token config file is searched.
     */
    if (conf_dir) {
        if (conf_name && strlen(conf_name) > 0) {
            /* extract filename part from conf_name */
            for (i = strlen(conf_name) - 1; i >= 0 && conf_name[i] != '/'; i--);

            snprintf(fname, sizeof(fname), "%s/%s", conf_dir,
                     conf_name + i + 1);
            fname[sizeof(fname) - 1] = '\0';
            ap_fp = fopen(fname, "r");

            if (!ap_fp)
                TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
                            __func__, fname, errno);
        }
        if (!ap_fp) {
            snprintf(fname, sizeof(fname), "%s/%s", conf_dir,
                     EP11_DEFAULT_CFG_FILE);
            fname[sizeof(fname) - 1] = '\0';
            ap_fp = fopen(fname, "r");
            if (!ap_fp)
                TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
                            __func__, fname, errno);
        }
    } else {
        if (conf_name && strlen(conf_name) > 0) {
            strncpy(fname, conf_name, sizeof(fname));
            fname[sizeof(fname) - 1] = '\0';
            ap_fp = fopen(fname, "r");
            if (!ap_fp) {
                TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
                            __func__, fname, errno);
                snprintf(fname, sizeof(fname), "%s/%s", OCK_CONFDIR, conf_name);
                fname[sizeof(fname) - 1] = '\0';
                ap_fp = fopen(fname, "r");
                if (!ap_fp)
                    TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
                                __func__, fname, errno);
            }
        } else {
            snprintf(fname, sizeof(fname), "%s/%s", OCK_CONFDIR,
                     EP11_DEFAULT_CFG_FILE);
            fname[sizeof(fname) - 1] = '\0';
            ap_fp = fopen(fname, "r");
            if (!ap_fp)
                TRACE_DEVEL("%s fopen('%s') failed with errno %d\n",
                            __func__, fname, errno);
        }
    }

    /* now we should really have an open ep11 token config file */
    if (!ap_fp) {
        TRACE_ERROR("%s no valid EP 11 config file found\n", __func__);
        OCK_SYSLOG(LOG_ERR, "%s: Error: EP 11 config file '%s' not found\n",
                   __func__, fname);
        return APQN_FILE_INV;
    }

    TRACE_INFO("%s EP 11 token config file is '%s'\n", __func__, fname);

    /* read config file line by line,
     * ignore empty and # and copy rest into file buf
     */
    memset(filebuf, 0, EP11_CFG_FILE_SIZE);
    while (fgets((char *) line, sizeof(line), ap_fp)) {
        char *p;
        int len;
        /* skip over leading spaces */
        for (p = line; *p == ' ' || *p == '\t'; p++);
        /* if line is empty or starts with # skip line */
        len = strlen(p);
        if (*p != '#' && *p != '\n' && len > 0) {
            /* store line in buffer */
            if (ap_file_size + len < EP11_CFG_FILE_SIZE) {
                memcpy(filebuf + ap_file_size, p, len);
                ap_file_size += len;
            } else {
                TRACE_ERROR("%s EP 11 config file '%s' is too large\n",
                            __func__, fname);
                fclose(ap_fp);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: EP 11 config file '%s' is too large\n",
                           __func__, fname);
                return APQN_FILE_INV_FILE_SIZE;
            }
        }
    }
    fclose(ap_fp);

    ep11_targets->length = 0;

    /* Default to use default libica library for digests */
    ep11_data->digest_libica = 1;
    strcpy(ep11_data->digest_libica_path, "");

    /* parse the file buf
     * please note, we still accept the LOGLEVEL entry
     * for compatibility reasons but just ignore it.
     */
    for (i = 0, str = filebuf; rc == 0; str = NULL) {
        /* strtok tokenizes the string,
         * delimiters are newline and whitespace.
         */
        token = strtok(str, "\n\t ");

        if (i == 0) {
            /* expecting APQN_WHITELIST or APQN_ANY or LOGLEVEL or eof */
            if (token == NULL)
                break;
            if (strncmp(token, "APQN_WHITELIST", 14) == 0) {
                whitemode = 1;
                i = 1;
            } else if (strncmp(token, "APQN_ANY", 8) == 0) {
                anymode = 1;
                i = 0;
            } else if (strncmp(token, "LOGLEVEL", 8) == 0) {
                i = 3;
            } else if (strncmp(token, "FORCE_SENSITIVE", 15) == 0) {
                i = 0;
                ep11_data->cka_sensitive_default_true = 1;
            } else if (strncmp(token, "CPFILTER", 8) == 0) {
                i = 4;
            } else if (strncmp(token, "STRICT_MODE", 11) == 0) {
                i = 0;
                ep11_data->strict_mode = 1;
            } else if (strncmp(token, "VHSM_MODE", 11) == 0) {
                i = 0;
                ep11_data->vhsm_mode = 1;
            } else if (strncmp(token, "OPTIMIZE_SINGLE_PART_OPERATIONS", 
                               31) == 0) {
               i = 0;
               ep11_data->optimize_single_ops = 1;
            } else if (strncmp(token, "DIGEST_LIBICA", 13) == 0) {
                i = 5;
            } else {
                /* syntax error */
                TRACE_ERROR("%s Expected APQN_WHITELIST,"
                            " APQN_ANY, LOGLEVEL, FORCE_SENSITIVE, CPFILTER,"
                            " STRICT_MODE, VHSM_MODE, "
                            " OPTIMIZE_SINGLE_PART_OPERATIONS, or DIGEST_LIBICA"
                            " keyword, found '%s' in config file '%s'\n", __func__,
                            token, fname);
                OCK_SYSLOG(LOG_ERR, "%s: Error: Expected APQN_WHITELIST,"
                           " APQN_ANY, LOGLEVEL, FORCE_SENSITIVE, CPFILTER,"
                           " STRICT_MODE, VHSM_MODE,"
                           " OPTIMIZE_SINGLE_PART_OPERATIONS, or DIGEST_LIBICA"
                           " keyword, found '%s' in config file '%s'\n",
                           __func__, token, fname);
                rc = APQN_FILE_SYNTAX_ERROR_0;
                break;
            }
        } else if (i == 1) {
            /* expecting END or first number of a number
             * pair (number range 0...255)
             */
            if (token == NULL) {
                rc = APQN_FILE_UNEXPECTED_END_OF_FILE;
                OCK_SYSLOG(LOG_ERR, "%s: Error: Unexpected end of file found"
                           " in config file '%s', expected 'END' or adapter"
                           " number\n",
                           __func__, fname);
                break;
            }
            if (strncmp(token, "END", 3) == 0) {
                i = 0;
            } else {
                if (check_n(ep11_targets, token, &apqn_i) < 0) {
                    rc = APQN_FILE_SYNTAX_ERROR_1;
                    OCK_SYSLOG(LOG_ERR, "%s: Error: Expected valid adapter"
                               " number, found '%s' in config file '%s'\n",
                               __func__, token, fname);
                    break;
                }
                i = 2;
            }
        } else if (i == 2) {
            /* expecting second number of a number pair
             * (number range 0...255)
             */
            if (token == NULL) {
                rc = APQN_FILE_UNEXPECTED_END_OF_FILE;
                OCK_SYSLOG(LOG_ERR, "%s: Error: Unexpected end of file found"
                           " in config file '%s', expected domain number"
                           " (2nd number)\n", __func__, fname);
                break;
            }
            if (strncmp(token, "END", 3) == 0) {
                TRACE_ERROR("%s Expected 2nd number, found '%s' in config "
                            "file\n", __func__, token);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: Expected valid domain"
                           " number (2nd number), found '%s' in config file"
                           " '%s'\n", __func__, token, fname);
                rc = APQN_FILE_SYNTAX_ERROR_2;
                break;
            }
            if (check_n(ep11_targets, token, &apqn_i) < 0) {
                OCK_SYSLOG(LOG_ERR, "%s: Error: Expected valid domain"
                           " number (2nd number), found '%s' in config file"
                           " '%s'\n", __func__, token, fname);
                rc = APQN_FILE_SYNTAX_ERROR_3;
                break;
            }
            ep11_targets->length++;
            if (ep11_targets->length > MAX_APQN) {
                TRACE_ERROR("%s Too many APQNs in config file (max %d)\n",
                            __func__, (int) MAX_APQN);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: Too many APQNs in config file '%s'\n",
                           __func__, fname);
                rc = APQN_FILE_SYNTAX_ERROR_4;
                break;
            }
            i = 1;
        } else if (i == 3) {
            /* expecting log level value
             * (a number in the range 0...9)
             */
            if (token == NULL) {
                rc = APQN_FILE_UNEXPECTED_END_OF_FILE;
                OCK_SYSLOG(LOG_ERR, "%s: Error: Unexpected end of file found"
                           " in config file '%s', expected LOGLEVEL value\n",
                           __func__, fname);
                break;
            }
            char *endptr;
            int loglevel = strtol(token, &endptr, 10);
            if (*endptr != '\0' || loglevel < 0 || loglevel > 9) {
                TRACE_ERROR("%s Invalid loglevel value '%s' in config file\n",
                            __func__, token);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: Invalid LOGLEVEL value '%s' in config "
                           "file '%s'\n",
                           __func__, token, fname);
                rc = APQN_FILE_SYNTAX_ERROR_5;
                break;
            }
            TRACE_WARNING("%s LOGLEVEL setting is not supported any more !\n",
                          __func__);
            TRACE_WARNING
                ("%s Use opencryptoki logging/tracing facilities instead.\n",
                 __func__);
            OCK_SYSLOG(LOG_WARNING,
                       "%s: Warning: LOGLEVEL setting is not supported any "
                       "more. Use opencryptoki logging/tracing facilities "
                       "instead.\n", __func__);
            i = 0;
        } else if (i == 4) {
            /* expecting CP-filter config file name */
            if (token == NULL) {
                rc = APQN_FILE_UNEXPECTED_END_OF_FILE;
                OCK_SYSLOG(LOG_ERR, "%s: Error: Unexpected end of file found"
                           " in config file '%s', expected CP-Filter file "
                           "name\n", __func__, fname);
                break;
            }
            if (strlen(token) >
                sizeof(ep11_data->cp_filter_config_filename) - 1) {
                TRACE_ERROR("%s CP-Filter config file name is too long: '%s'\n",
                            __func__, token);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: CP-Filter config file name '%s' is too "
                           "long in config file '%s'\n",
                           __func__, token, fname);
                rc = APQN_FILE_SYNTAX_ERROR_6;
                break;
            }
            strncpy(ep11_data->cp_filter_config_filename, token,
                    sizeof(ep11_data->cp_filter_config_filename) - 1);
            ep11_data->cp_filter_config_filename[
                sizeof(ep11_data->cp_filter_config_filename) - 1] = '\0';
            i = 0;
        } else if (i == 5) {
            /* expecting libica path, 'DEFAULT', or 'OFF' */
            if (token == NULL) {
                rc = APQN_FILE_UNEXPECTED_END_OF_FILE;
                OCK_SYSLOG(LOG_ERR,"%s: Error: Unexpected end of file found"
                           " in config file '%s', expected libica path, "
                           "'DEFAULT', or 'OFF'\n",
                           __func__, fname);
                break;
            }
            if (strcmp(token, "OFF") == 0) {
                ep11_data->digest_libica = 0;
            } else if (strcmp(token, "DEFAULT") == 0) {
                ep11_data->digest_libica = 1;
                strcpy(ep11_data->digest_libica_path, "");
            } else {
                if (strlen(token) > sizeof(ep11_data->digest_libica_path)-1) {
                    TRACE_ERROR("%s libica path is too long: '%s'\n",
                                            __func__, token);
                    OCK_SYSLOG(LOG_ERR,"%s: Error: libica path '%s' is too long"
                               " in config file '%s'\n",
                               __func__, token, fname);
                    rc = APQN_FILE_SYNTAX_ERROR_6;
                    break;
                }
                ep11_data->digest_libica = 1;
                strncpy(ep11_data->digest_libica_path, token,
                        sizeof(ep11_data->digest_libica_path)-1);
                ep11_data->digest_libica_path[sizeof(ep11_data->digest_libica_path)-1] = '\0';
            }
            i = 0;
        }
    }

    /* do some checks: */
    if (rc == 0) {
        if (!(whitemode || anymode)) {
            TRACE_ERROR("%s At least one APQN mode needs to be present in "
                        "config file: APQN_WHITEMODE or APQN_ANY\n", __func__);
            OCK_SYSLOG(LOG_ERR,
                       "%s: Error: At least one APQN mode needs to be present "
                       " in config file '%s': APQN_WHITEMODE or APQN_ANY\n",
                       __func__, fname);
            rc = APQN_FILE_NO_APQN_MODE;
        } else if (whitemode && anymode) {
            TRACE_ERROR("%s Only one APQN mode can be present in config file:"
                        " APQN_WHITEMODE or APQN_ANY\n", __func__);
            OCK_SYSLOG(LOG_ERR,
                       "%s: Error: Only one APQN mode can be present in"
                       " config file '%s': APQN_WHITEMODE or APQN_ANY\n",
                       __func__, fname);
            rc = APQN_FILE_NO_APQN_MODE;
        } else if (whitemode) {
            /* at least one APQN needs to be defined */
            if (ep11_targets->length < 1) {
                TRACE_ERROR("%s At least one APQN needs to be defined in the "
                            "config file\n", __func__);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: At least one APQN needs to be defined in"
                           " config file '%s'\n", __func__, fname);
                rc = APQN_FILE_NO_APQN_GIVEN;
            }
        }
    }

    /* log the whitelist of APQNs */
    if (rc == 0 && whitemode) {
        TRACE_INFO("%s whitelist with %d APQNs defined:\n",
                   __func__, ep11_targets->length);
        for (i = 0; i < ep11_targets->length; i++) {
            TRACE_INFO(" APQN entry %d: adapter=%d domain=%d\n", i,
                       ep11_targets->apqns[2 * i],
                       ep11_targets->apqns[2 * i + 1]);
        }
    }

    /* read CP-filter config file */
    if (rc == 0) {
        cfg_dir = dirname(fname);
        if (strlen(ep11_data->cp_filter_config_filename) == 0) {
            snprintf(ep11_data->cp_filter_config_filename,
                     sizeof(ep11_data->cp_filter_config_filename) - 1,
                     "%s/%s", cfg_dir, EP11_DEFAULT_CPFILTER_FILE);
            ep11_data->cp_filter_config_filename[
                sizeof(ep11_data->cp_filter_config_filename) - 1] = '\0';
        }

        if (strchr(ep11_data->cp_filter_config_filename, '/') == NULL) {
            cfgname[0] = '\0';

            if (strlen(cfg_dir) + 1
                + strlen(ep11_data->cp_filter_config_filename)
                <= sizeof(cfgname) - 1) {
                strcpy(cfgname, cfg_dir);
                cfgname[strlen(cfg_dir)] = '/';
                strcpy(cfgname + strlen(cfg_dir) + 1,
                       ep11_data->cp_filter_config_filename);
            }

            strncpy(ep11_data->cp_filter_config_filename, cfgname,
                    sizeof(ep11_data->cp_filter_config_filename));
            ep11_data->cp_filter_config_filename[
                sizeof(ep11_data->cp_filter_config_filename) - 1] = '\0';
        }

        rc = read_cp_filter_config_file(ep11_data->cp_filter_config_filename,
                                        &ep11_data->cp_config);
    }

    tokdata->initialized = TRUE;
    return rc;
}

#define UNKNOWN_CP          0xFFFFFFFF

#define CP_BYTE_NO(cp)      ((cp) / 8)
#define CP_BIT_IN_BYTE(cp)  ((cp) % 8)
#define CP_BIT_MASK(cp)     (0x80 >> CP_BIT_IN_BYTE(cp))

static int read_cp_filter_config_file(const char *conf_name,
                                      cp_config_t ** cp_config)
{
    int rc = 0;
    FILE *fp = NULL;
    char line[1024];
    char *tok;
    unsigned long int val;
    char *endp;
    cp_config_t *cp;
    cp_config_t *last_cp = NULL;
    cp_mech_config_t *mech;
    cp_mech_config_t *last_mech;

    TRACE_INFO("%s EP 11 CP-filter config file is '%s'\n", __func__, conf_name);

    fp = fopen(conf_name, "r");
    if (fp == NULL) {
        TRACE_ERROR("%s no valid EP 11 CP-filter config file found\n",
                    __func__);
        OCK_SYSLOG(LOG_WARNING,
                   "%s: Warning: EP 11 CP-filter config file '%s'"
                   " does not exist, no filtering will be used\n", __func__,
                   conf_name);
        /* this is not an error condition. When no CP-filter file is available,
         * then the mechanisms are not filtered. */
        return 0;
    }

    while (fgets((char *) line, sizeof(line), fp)) {
        tok = strtok(line, ": \t\n");

        if (tok == NULL)
            continue;
        if (*tok == '#')
            continue;

        val = strtoul(tok, &endp, 0);
        if (*endp != '\0') {
            val = ep11_get_cp_by_name(tok);
            if (val == UNKNOWN_CP) {
                TRACE_ERROR("%s Syntax error in EP 11 CP-filter config file "
                            "found. \n", __func__);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: Expected valid control point name or "
                           "number, found '%s' in CP-filter config file '%s'\n",
                           __func__, tok, conf_name);
                rc = APQN_FILE_SYNTAX_ERROR_7;
                goto out_fclose;
            }
        }

        cp = (cp_config_t *) malloc(sizeof(cp_config_t));
        if (cp == NULL) {
            TRACE_ERROR("%s Out of memory.\n", __func__);
            rc = APQN_OUT_OF_MEMORY;
            goto out_fclose;
        }
        cp->cp = val;
        cp->mech = NULL;
        cp->next = NULL;

        last_mech = NULL;
        while ((tok = strtok(NULL, ", \t\n")) != NULL) {
            if (*tok == '#')
                break;

            val = strtoul(tok, &endp, 0);
            if (*endp != '\0') {
                val = ep11_get_mechanisms_by_name(tok);
                if (val == UNKNOWN_MECHANISM) {
                    TRACE_ERROR("%s Syntax error in EP 11 CP-filter config file"
                                " found. \n", __func__);
                    OCK_SYSLOG(LOG_ERR,
                               "%s: Error: Expected valid mechanism name or "
                               "number, found '%s' in CP-filter config file "
                               "'%s'\n", __func__, tok, conf_name);
                    rc = APQN_FILE_SYNTAX_ERROR_8;
                    free_cp_config(cp);
                    goto out_fclose;
                }
            }

            mech = (cp_mech_config_t *) malloc(sizeof(cp_mech_config_t));
            if (mech == NULL) {
                TRACE_ERROR("%s Out of memory.\n", __func__);
                OCK_SYSLOG(LOG_ERR, "%s: Error: Out of memory while parsing the"
                           " CP-filter config file '%s'\n",
                           __func__, conf_name);
                rc = APQN_OUT_OF_MEMORY;
                free_cp_config(cp);
                goto out_fclose;
            }
            mech->mech = val;
            mech->next = NULL;

            if (last_mech == NULL)
                cp->mech = mech;
            else
                last_mech->next = mech;
            last_mech = mech;
        }

        if (cp->mech == NULL) {
            /* empty CP, skip this one */
            free(cp);
            continue;
        }

        if (last_cp == NULL)
            *cp_config = cp;
        else
            last_cp->next = cp;
        last_cp = cp;
    }

#ifdef DEBUG
    /* print CP filter config */
    TRACE_INFO("%s CP-Filter defined:\n", __func__);
    cp = *cp_config;
    while (cp != NULL) {
        TRACE_INFO("  CP %lu (%s):\n", cp->cp, ep11_get_cp(cp->cp));
        mech = cp->mech;
        while (mech != NULL) {
            TRACE_INFO("    Mechanism 0x%08lx (%s)\n", mech->mech,
                       ep11_get_ckm(mech->mech));
            mech = mech->next;
        }
        cp = cp->next;
    }
#endif

out_fclose:
    fclose(fp);
    return rc;
}

static void free_cp_config(cp_config_t * cp)
{
    cp_config_t *next_cp = cp;
    cp_mech_config_t *mech;
    cp_mech_config_t *next_mech;

    TRACE_INFO("%s running\n", __func__);

    while (cp != NULL) {
        mech = cp->mech;
        while (mech != NULL) {
            next_mech = mech->next;
            free(mech);
            mech = next_mech;
        }

        next_cp = cp->next;
        free(cp);
        cp = next_cp;
    }
}

static const_info_t ep11_cps[] = {
    CONSTINFO(XCP_CPB_ADD_CPBS),
    CONSTINFO(XCP_CPB_DELETE_CPBS),
    CONSTINFO(XCP_CPB_SIGN_ASYMM),
    CONSTINFO(XCP_CPB_SIGN_SYMM),
    CONSTINFO(XCP_CPB_SIGVERIFY_SYMM),
    CONSTINFO(XCP_CPB_ENCRYPT_SYMM),
    CONSTINFO(XCP_CPB_DECRYPT_ASYMM),
    CONSTINFO(XCP_CPB_DECRYPT_SYMM),
    CONSTINFO(XCP_CPB_WRAP_ASYMM),
    CONSTINFO(XCP_CPB_WRAP_SYMM),
    CONSTINFO(XCP_CPB_UNWRAP_ASYMM),
    CONSTINFO(XCP_CPB_UNWRAP_SYMM),
    CONSTINFO(XCP_CPB_KEYGEN_ASYMM),
    CONSTINFO(XCP_CPB_KEYGEN_SYMM),
    CONSTINFO(XCP_CPB_RETAINKEYS),
    CONSTINFO(XCP_CPB_SKIP_KEYTESTS),
    CONSTINFO(XCP_CPB_NON_ATTRBOUND),
    CONSTINFO(XCP_CPB_MODIFY_OBJECTS),
    CONSTINFO(XCP_CPB_RNG_SEED),
    CONSTINFO(XCP_CPB_ALG_RAW_RSA),
    CONSTINFO(XCP_CPB_ALG_NFIPS2009),
    CONSTINFO(XCP_CPB_ALG_NBSI2009),
    CONSTINFO(XCP_CPB_KEYSZ_HMAC_ANY),
    CONSTINFO(XCP_CPB_KEYSZ_BELOW80BIT),
    CONSTINFO(XCP_CPB_KEYSZ_80BIT),
    CONSTINFO(XCP_CPB_KEYSZ_112BIT),
    CONSTINFO(XCP_CPB_KEYSZ_128BIT),
    CONSTINFO(XCP_CPB_KEYSZ_192BIT),
    CONSTINFO(XCP_CPB_KEYSZ_256BIT),
    CONSTINFO(XCP_CPB_KEYSZ_RSA65536),
    CONSTINFO(XCP_CPB_ALG_RSA),
    CONSTINFO(XCP_CPB_ALG_DSA),
    CONSTINFO(XCP_CPB_ALG_EC),
    CONSTINFO(XCP_CPB_ALG_EC_BPOOLCRV),
    CONSTINFO(XCP_CPB_ALG_EC_NISTCRV),
    CONSTINFO(XCP_CPB_ALG_NFIPS2011),
    CONSTINFO(XCP_CPB_ALG_NBSI2011),
    CONSTINFO(XCP_CPB_USER_SET_TRUSTED),
    CONSTINFO(XCP_CPB_ALG_SKIP_CROSSCHK),
    CONSTINFO(XCP_CPB_WRAP_CRYPT_KEYS),
    CONSTINFO(XCP_CPB_SIGN_CRYPT_KEYS),
    CONSTINFO(XCP_CPB_WRAP_SIGN_KEYS),
    CONSTINFO(XCP_CPB_USER_SET_ATTRBOUND),
    CONSTINFO(XCP_CPB_ALLOW_PASSPHRASE),
    CONSTINFO(XCP_CPB_WRAP_STRONGER_KEY),
    CONSTINFO(XCP_CPB_WRAP_WITH_RAW_SPKI),
    CONSTINFO(XCP_CPB_ALG_DH),
    CONSTINFO(XCP_CPB_DERIVE),
    CONSTINFO(XCP_CPB_ALG_NBSI2017),
};

#ifdef DEBUG
static const char *ep11_get_cp(unsigned int cp)
{
    unsigned int i;

    for (i = 0; i < (sizeof(ep11_cps) / sizeof(ep11_cps[0])); i++) {
        if (ep11_cps[i].code == cp)
            return ep11_cps[i].name;
    }

    TRACE_WARNING("%s unknown control point %u\n", __func__, cp);
    return "UNKNOWN";
}
#endif

static CK_ULONG ep11_get_cp_by_name(const char *name)
{
    unsigned int i;

    for (i = 0; i < (sizeof(ep11_cps) / sizeof(ep11_cps[0])); i++) {
        if (strcmp(ep11_cps[i].name, name) == 0)
            return ep11_cps[i].code;
    }

    TRACE_WARNING("%s unknown control point name '%s'\n", __func__, name);
    return UNKNOWN_CP;
}

static CK_RV check_cps_for_mechanism(cp_config_t * cp_config,
                                     CK_MECHANISM_TYPE mech,
                                     unsigned char *cp, size_t cp_len,
                                     size_t max_cp_index)
{
    cp_config_t *cp_cfg = cp_config;
    cp_mech_config_t *mech_cfg;

    TRACE_DEBUG("%s Check mechanism 0x%08lx ('%s')\n", __func__, mech,
                ep11_get_ckm(mech));

    while (cp_cfg != NULL) {
        if (CP_BYTE_NO(cp_cfg->cp) < cp_len &&
            cp_cfg->cp <= max_cp_index &&
            (cp[CP_BYTE_NO(cp_cfg->cp)] & CP_BIT_MASK(cp_cfg->cp)) == 0) {
            /* CP is off, check if the current mechanism is
             * associated with it */
            mech_cfg = cp_cfg->mech;
            while (mech_cfg != NULL) {
                if (mech_cfg->mech == mech) {
                    TRACE_DEBUG("%s mechanism 0x%08lx ('%s') not enabled\n",
                                __func__, mech, ep11_get_ckm(mech));
                    return CKR_MECHANISM_INVALID;
                }
                mech_cfg = mech_cfg->next;
            }
        }
        cp_cfg = cp_cfg->next;
    }

    return CKR_OK;
}

#define SYSFS_DEVICES_AP        "/sys/devices/ap/"
#define REGEX_CARD_PATTERN      "card[0-9a-fA-F]+"
#define REGEX_SUB_CARD_PATTERN  "[0-9a-fA-F]+\\.[0-9a-fA-F]+"
#define MASK_EP11               0x04000000

typedef CK_RV(*adapter_handler_t) (uint_32 adapter, uint_32 domain,
                                   void *handler_data);

static CK_RV file_fgets(const char *fname, char *buf, size_t buflen)
{
    FILE *fp;
    char *end;
    CK_RV rc = CKR_OK;

    buf[0] = '\0';

    fp = fopen(fname, "r");
    if (fp == NULL) {
        TRACE_ERROR("Failed to open file '%s'\n", fname);
        return CKR_FUNCTION_FAILED;
    }
    if (fgets(buf, buflen, fp) == NULL) {
        TRACE_ERROR("Failed to read from file '%s'\n", fname);
        rc = CKR_FUNCTION_FAILED;
        goto out_fclose;
    }

    end = memchr(buf, '\n', buflen);
    if (end)
        *end = 0;
    else
        buf[buflen - 1] = 0;

    if (strlen(buf) == 0) {
        rc = CKR_FUNCTION_FAILED;
        goto out_fclose;
    }

out_fclose:
    fclose(fp);
    return rc;
}

static CK_RV is_card_ep11_and_online(const char *name)
{
    char fname[290];
    char buf[250];
    CK_RV rc;
    unsigned long val;

    sprintf(fname, "%s%s/online", SYSFS_DEVICES_AP, name);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc != CKR_OK)
        return rc;
    if (strcmp(buf, "1") != 0)
        return CKR_FUNCTION_FAILED;

    sprintf(fname, "%s%s/ap_functions", SYSFS_DEVICES_AP, name);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc != CKR_OK)
        return rc;
    if (sscanf(buf, "%lx", &val) != 1)
        val = 0x00000000;
    if ((val & MASK_EP11) == 0)
        return CKR_FUNCTION_FAILED;

    return CKR_OK;
}

static CK_RV scan_for_card_domains(const char *name, adapter_handler_t handler,
                                   void *handler_data)
{
    char fname[290];
    regex_t reg_buf;
    regmatch_t pmatch[1];
    DIR *d;
    struct dirent *de;
    char *tok;
    uint_32 adapter, domain;

    if (regcomp(&reg_buf, REGEX_SUB_CARD_PATTERN, REG_EXTENDED) != 0) {
        TRACE_ERROR("Failed to compile regular expression '%s'\n",
                    REGEX_SUB_CARD_PATTERN);
        return CKR_FUNCTION_FAILED;
    }

    sprintf(fname, "%s%s/", SYSFS_DEVICES_AP, name);
    d = opendir(fname);
    if (d == NULL) {
        TRACE_ERROR("Directory %s is not available\n", fname);
        regfree(&reg_buf);
        // ignore this error, card may have been removed in the meantime
        return CKR_OK;
    }

    while ((de = readdir(d)) != NULL) {
        if (regexec(&reg_buf, de->d_name, (size_t) 1, pmatch, 0) == 0) {
            tok = strtok(de->d_name, ".");
            if (tok == NULL)
                continue;
            if (sscanf(tok, "%x", &adapter) != 1)
                continue;

            tok = strtok(NULL, ",");
            if (tok == NULL)
                continue;
            if (sscanf(tok, "%x", &domain) != 1)
                continue;

            if (handler(adapter, domain, handler_data) != CKR_OK)
                break;
        }
    }

    closedir(d);
    regfree(&reg_buf);
    return CKR_OK;
}

/*
 * Iterate over all cards in the sysfs directorys /sys/device/ap/cardxxx
 * and check if the card is online. Calls the handler function for all
 * online EP11 cards.
 */
static CK_RV scan_for_ep11_cards(adapter_handler_t handler, void *handler_data)
{
    DIR *d;
    struct dirent *de;
    regex_t reg_buf;
    regmatch_t pmatch[1];

    if (handler == NULL)
        return CKR_ARGUMENTS_BAD;

    if (regcomp(&reg_buf, REGEX_CARD_PATTERN, REG_EXTENDED) != 0) {
        TRACE_ERROR("Failed to compile regular expression '%s'\n",
                    REGEX_CARD_PATTERN);
        return CKR_FUNCTION_FAILED;
    }

    d = opendir(SYSFS_DEVICES_AP);
    if (d == NULL) {
        TRACE_ERROR("Directory %s is not available\n", SYSFS_DEVICES_AP);
        regfree(&reg_buf);
        return CKR_FUNCTION_FAILED;
    }

    while ((de = readdir(d)) != NULL) {
        if (regexec(&reg_buf, de->d_name, (size_t) 1, pmatch, 0) == 0) {
            if (is_card_ep11_and_online(de->d_name) != CKR_OK)
                continue;

            if (scan_for_card_domains(de->d_name, handler, handler_data) !=
                CKR_OK)
                break;
        }
    }

    closedir(d);
    regfree(&reg_buf);
    return CKR_OK;
}

static CK_RV handle_all_ep11_cards(ep11_target_t * ep11_targets,
                                   adapter_handler_t handler,
                                   void *handler_data)
{
    int i;
    CK_RV rc;

    if (ep11_targets->length > 0) {
        /* APQN_WHITELIST is specified */
        for (i = 0; i < ep11_targets->length; i++) {
            rc = handler(ep11_targets->apqns[2 * i],
                         ep11_targets->apqns[2 * i + 1], handler_data);
            if (rc != CKR_OK)
                return rc;
        }
    } else {
        /* APQN_ANY used, scan sysfs for available cards */
        return scan_for_ep11_cards(handler, handler_data);
    }

    return CKR_OK;
}

static CK_RV get_control_points_for_adapter(uint_32 adapter, uint_32 domain,
                                            unsigned char *cp, size_t * cp_len,
                                            size_t *max_cp_index)
{
    unsigned char rsp[200];
    unsigned char cmd[100];
    struct XCPadmresp rb;
    size_t rlen, clen;
    long rc;
    CK_RV rv = 0;
    ep11_target_t target;
    CK_IBM_XCP_INFO xcp_info;
    CK_ULONG xcp_info_len = sizeof(xcp_info);

    memset(&target, 0, sizeof(target));
    target.length = 1;
    target.apqns[0] = adapter;
    target.apqns[1] = domain;

    memset(cmd, 0, sizeof(cmd));
    rc = dll_xcpa_queryblock(cmd, sizeof(cmd), XCP_ADMQ_DOM_CTRLPOINTS,
                             (uint64_t) adapter << 32 | domain, NULL, 0);
    if (rc < 0) {
        TRACE_ERROR("%s xcpa_queryblock failed: rc=%ld\n", __func__, rc);
        return CKR_DEVICE_ERROR;
    }
    clen = rc;

    memset(rsp, 0, sizeof(rsp));
    rlen = sizeof(rsp);
    rc = dll_m_admin(rsp, &rlen, NULL, NULL, cmd, clen, NULL, 0,
                     (uint64_t) & target);
    if (rc < 0) {
        TRACE_ERROR("%s m_admin rc=%ld\n", __func__, rc);
        return CKR_DEVICE_ERROR;
    }

    memset(&rb, 0, sizeof(rb));
    rc = dll_xcpa_internal_rv(rsp, rlen, &rb, &rv);
    if (rc < 0 || rv != 0) {
        TRACE_ERROR("%s xcpa_internal_rv failed: rc=%ld rv=%ld\n",
                    __func__, rc, rv);
        return CKR_DEVICE_ERROR;
    }

    if (*cp_len < rb.pllen) {
        TRACE_ERROR("%s Cp_len is too small. cp_len=%lu required=%lu\n",
                    __func__, *cp_len, rb.pllen);
        *cp_len = rb.pllen;
        return CKR_ARGUMENTS_BAD;
    }

    memcpy(cp, rb.payload, rb.pllen);
    *cp_len = rb.pllen;

    rc = dll_m_get_xcp_info(&xcp_info, &xcp_info_len, CK_IBM_XCPQ_MODULE, 0,
                           (uint64_t)&target);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to query xcp info from adapter %02X.%04X\n",
                    __func__, adapter, domain);
        return CKR_DEVICE_ERROR;
    }

    *max_cp_index = xcp_info.controlPoints;

    return CKR_OK;
}

typedef struct cp_handler_data {
    unsigned char combined_cp[XCP_CP_BYTES];
    unsigned char first_cp[XCP_CP_BYTES];
    uint32_t first_adapter;
    uint32_t first_domain;
    int first;
    size_t max_cp_index;
} cp_handler_data_t;

static CK_RV control_point_handler(uint_32 adapter, uint_32 domain,
                                   void *handler_data)
{
    CK_RV rc;
    cp_handler_data_t *data = (cp_handler_data_t *) handler_data;
    unsigned char cp[XCP_CP_BYTES];
    size_t cp_len = sizeof(cp);
    size_t max_cp_index;
    CK_ULONG i;

    TRACE_INFO("Getting control points for adapter %02X.%04X\n", adapter,
               domain);

    memset(cp, 0, sizeof(cp));
    rc = get_control_points_for_adapter(adapter, domain, cp, &cp_len,
                                        &max_cp_index);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to get CPS from adapter %02X.%04X\n",
                    __func__, adapter, domain);
        // card may no longer be online, so ignore this error situation
        return CKR_OK;
    }
#ifdef DEBUG
    TRACE_DEBUG("Control points from adapter %02X.%04X\n", adapter, domain);
    TRACE_DEBUG_DUMP(cp, cp_len);
#endif

    if (data->first) {
        data->first_adapter = adapter;
        data->first_domain = domain;
        memcpy(data->first_cp, cp, cp_len);
        memcpy(data->combined_cp, cp, cp_len);
        data->max_cp_index = max_cp_index;
        data->first = 0;
    } else {
        // check if subsequent adapters have the same CPs
        if (memcmp(cp, data->first_cp, sizeof(cp)) != 0) {
            TRACE_WARNING("%s Adapter %02X.%04X has different control points "
                          "than adapter %02X.%04X, using minimum.\n",
                          __func__, adapter, domain, data->first_adapter,
                          data->first_domain);
            OCK_SYSLOG(LOG_WARNING,
                       "Warning: Adapter %02X.%04X has different control points"
                       " than adapter %02X.%04X, using minimum\n",
                       adapter, domain, data->first_adapter,
                       data->first_domain);
        }

        for (i = 0; i < cp_len; i++) {
            data->combined_cp[i] &= cp[i];
        }

        if (max_cp_index != data->max_cp_index) {
            TRACE_WARNING("%s Adapter %02X.%04X has a different number of "
                          "control points than adapter %02X.%04X, using "
                          "maximum.\n", __func__, adapter, domain,
                          data->first_adapter, data->first_domain);
            OCK_SYSLOG(LOG_WARNING,
                       "Warning: Adapter %02X.%04X has a different number of "
                       "control points than adapter %02X.%04X, using maximum\n",
                       adapter, domain, data->first_adapter,
                       data->first_domain);

            data->max_cp_index = MAX(max_cp_index, data->max_cp_index);
        }
    }

    return CKR_OK;
}

#ifdef DEBUG
static void print_control_points(unsigned char *cp, size_t cp_len,
                                 size_t max_cp_index)
{
    unsigned int i;

    for (i = 0; i <= max_cp_index && CP_BYTE_NO(i) < cp_len; i++) {
        if ((cp[CP_BYTE_NO(i)] & CP_BIT_MASK(i)) == 0)
            TRACE_INFO("CP %u (%s)is off\n", i, ep11_get_cp(i));
        else
            TRACE_INFO("CP %u (%s) is on\n", i, ep11_get_cp(i));
    }
}
#endif

static CK_RV get_control_points(STDLL_TokData_t * tokdata,
                                unsigned char *cp, size_t * cp_len,
                                size_t *max_cp_index)
{
    CK_RV rc;
    cp_handler_data_t data;
    ep11_private_data_t *ep11_data = tokdata->private_data;

    memset(&data, 0, sizeof(data));
    data.first = 1;
    rc = handle_all_ep11_cards((ep11_target_t *) ep11_data->target_list,
                               control_point_handler, &data);
    if (rc != CKR_OK)
        return rc;

    *cp_len = MIN(*cp_len, sizeof(data.combined_cp));
    memcpy(cp, data.combined_cp, *cp_len);
    *max_cp_index = data.max_cp_index;

#ifdef DEBUG
    TRACE_DEBUG("Combined control points from all cards (%lu CPs):\n",
                data.max_cp_index);
    TRACE_DEBUG_DUMP(cp, *cp_len);
    print_control_points(cp, *cp_len, data.max_cp_index);
#endif

    return CKR_OK;
}


CK_RV SC_CreateObject(STDLL_TokData_t * tokdata,
                      ST_SESSION_HANDLE * sSession, CK_ATTRIBUTE_PTR pTemplate,
                      CK_ULONG ulCount, CK_OBJECT_HANDLE_PTR phObject);
CK_RV SC_DestroyObject(STDLL_TokData_t * tokdata,
                       ST_SESSION_HANDLE * sSession, CK_OBJECT_HANDLE hObject);
CK_RV SC_FindObjectsInit(STDLL_TokData_t * tokdata,
                         ST_SESSION_HANDLE * sSession,
                         CK_ATTRIBUTE_PTR pTemplate, CK_ULONG ulCount);
CK_RV SC_FindObjects(STDLL_TokData_t * tokdata,
                     ST_SESSION_HANDLE * sSession,
                     CK_OBJECT_HANDLE_PTR phObject, CK_ULONG ulMaxObjectCount,
                     CK_ULONG_PTR pulObjectCount);
CK_RV SC_FindObjectsFinal(STDLL_TokData_t * tokdata,
                          ST_SESSION_HANDLE * sSession);
CK_RV SC_GetAttributeValue(STDLL_TokData_t * tokdata,
                           ST_SESSION_HANDLE * sSession,
                           CK_OBJECT_HANDLE hObject, CK_ATTRIBUTE_PTR pTemplate,
                           CK_ULONG ulCount);
CK_RV SC_OpenSession(STDLL_TokData_t * tokdata, CK_SLOT_ID sid, CK_FLAGS flags,
                     CK_SESSION_HANDLE_PTR phSession);
CK_RV SC_CloseSession(STDLL_TokData_t * tokdata, ST_SESSION_HANDLE * sSession);

static CK_RV generate_ep11_session_id(STDLL_TokData_t * tokdata,
                                      SESSION * session,
                                      ep11_session_t * ep11_session)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    struct {
        CK_SESSION_HANDLE handle;
        struct timeval timeofday;
        clock_t clock;
        pid_t pid;
    } session_id_data;
    CK_MECHANISM mech;
    CK_ULONG len;
    libica_sha_context_t ctx;

    session_id_data.handle = session->handle;
    gettimeofday(&session_id_data.timeofday, NULL);
    session_id_data.clock = clock();
    session_id_data.pid = getpid();

    mech.mechanism = CKM_SHA256;
    mech.pParameter = NULL;
    mech.ulParameterLen = 0;

    len = sizeof(ep11_session->session_id);
    if (ep11tok_libica_digest_available(ep11_data, mech.mechanism))
        rc = ep11tok_libica_digest(ep11_data, mech.mechanism, &ctx,
                                   (CK_BYTE_PTR)&session_id_data,
                                   sizeof(session_id_data),
                                   ep11_session->session_id, &len,
                                   SHA_MSG_PART_ONLY);
    else
        rc = dll_m_DigestSingle(&mech, (CK_BYTE_PTR)&session_id_data,
                                sizeof(session_id_data),
                                ep11_session->session_id, &len,
                                (uint64_t)ep11_data->target_list);

    if (rc != CKR_OK) {
        rc = ep11_error_to_pkcs11_error(rc, session);
        TRACE_ERROR("%s Digest failed: 0x%lx\n", __func__, rc);
        return rc;
    }

    return CKR_OK;
}

static CK_RV create_ep11_object(STDLL_TokData_t * tokdata,
                                ST_SESSION_HANDLE * handle,
                                ep11_session_t * ep11_session,
                                CK_BYTE * pin_blob, CK_ULONG pin_blob_len,
                                CK_OBJECT_HANDLE * obj)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_RV rc;
    CK_OBJECT_CLASS class = CKO_HW_FEATURE;
    CK_HW_FEATURE_TYPE type = CKH_IBM_EP11_SESSION;
    CK_BYTE subject[] = "EP11 Session Object";
    pid_t pid;
    CK_DATE date;
    CK_BYTE cktrue = TRUE;
    time_t t;
    struct tm *tm;
    char tmp[40];

    CK_ATTRIBUTE attrs[] = {
        {CKA_CLASS, &class, sizeof(class)}
        ,
        {CKA_TOKEN, &cktrue, sizeof(cktrue)}
        ,
        {CKA_PRIVATE, &cktrue, sizeof(cktrue)}
        ,
        {CKA_HIDDEN, &cktrue, sizeof(cktrue)}
        ,
        {CKA_HW_FEATURE_TYPE, &type, sizeof(type)}
        ,
        {CKA_SUBJECT, &subject, sizeof(subject)}
        ,
        {CKA_VALUE, pin_blob, pin_blob_len}
        ,
        {CKA_ID, ep11_session->session_id, PUBLIC_SESSION_ID_LENGTH}
        ,
        {CKA_APPLICATION, (ep11_target_t *) ep11_data->target_list,
         sizeof(ep11_target_t)}
        ,
        {CKA_OWNER, &pid, sizeof(pid)}
        ,
        {CKA_START_DATE, &date, sizeof(date)}
    };

    pid = getpid();
    time(&t);
    tm = localtime(&t);
    sprintf(tmp, "%4d%2d%2d", tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday);
    memcpy(date.year, tmp, 4);
    memcpy(date.month, tmp + 4, 2);
    memcpy(date.day, tmp + 4 + 2, 2);

    rc = SC_CreateObject(tokdata, handle,
                         attrs, sizeof(attrs) / sizeof(CK_ATTRIBUTE), obj);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s SC_CreateObject failed: 0x%lx\n", __func__, rc);
        return rc;
    }

    return CKR_OK;
}

static CK_RV get_vhsmpin(STDLL_TokData_t * tokdata,
                         SESSION * session, ep11_session_t * ep11_session)
{
    CK_RV rc;
    ST_SESSION_HANDLE handle = {.slotID =
            session->session_info.slotID,.sessionh = session->handle
    };
    CK_OBJECT_HANDLE obj_store[16];
    CK_ULONG objs_found = 0;
    CK_OBJECT_CLASS class = CKO_HW_FEATURE;
    CK_HW_FEATURE_TYPE type = CKH_IBM_EP11_VHSMPIN;
    CK_BYTE cktrue = TRUE;
    CK_ATTRIBUTE vhsmpin_template[] = {
        {CKA_CLASS, &class, sizeof(class)}
        ,
        {CKA_TOKEN, &cktrue, sizeof(cktrue)}
        ,
        {CKA_PRIVATE, &cktrue, sizeof(cktrue)}
        ,
        {CKA_HIDDEN, &cktrue, sizeof(cktrue)}
        ,
        {CKA_HW_FEATURE_TYPE, &type, sizeof(type)}
        ,
    };
    CK_ATTRIBUTE attrs[] = {
        {CKA_VALUE, ep11_session->vhsm_pin, sizeof(ep11_session->vhsm_pin)}
        ,
    };

    rc = SC_FindObjectsInit(tokdata, &handle,
                            vhsmpin_template,
                            sizeof(vhsmpin_template) / sizeof(CK_ATTRIBUTE));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s SC_FindObjectsInit failed: 0x%lx\n", __func__, rc);
        goto out;
    }

    rc = SC_FindObjects(tokdata, &handle, obj_store, 16, &objs_found);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s SC_FindObjects failed: 0x%lx\n", __func__, rc);
        goto out;
    }

    if (objs_found == 0) {
        rc = CKR_FUNCTION_FAILED;
        TRACE_ERROR("%s No VHSMPIN object found\n", __func__);
        goto out;
    }

    rc = SC_GetAttributeValue(tokdata, &handle, obj_store[0],
                              attrs, sizeof(attrs) / sizeof(CK_ATTRIBUTE));
    if (rc != CKR_OK) {
        TRACE_ERROR("%s SC_GetAttributeValue failed: 0x%lx\n", __func__, rc);
        goto out;
    }

    ep11_session->flags |= EP11_VHSMPIN_VALID;

out:
    SC_FindObjectsFinal(tokdata, &handle);
    return rc;
}

static CK_RV ep11_login_handler(uint_32 adapter, uint_32 domain,
                                void *handler_data)
{
    ep11_session_t *ep11_session = (ep11_session_t *) handler_data;
    ep11_target_t target;
    CK_RV rc;
    CK_BYTE pin_blob[XCP_PINBLOB_BYTES];
    CK_ULONG pin_blob_len = XCP_PINBLOB_BYTES;
    CK_BYTE *pin = (CK_BYTE *)DEFAULT_EP11_PIN;
    CK_ULONG pin_len = strlen(DEFAULT_EP11_PIN);
    CK_BYTE *nonce = NULL;
    CK_ULONG nonce_len = 0;

    TRACE_INFO("Logging in adapter %02X.%04X\n", adapter, domain);

    memset(&target, 0, sizeof(target));
    target.length = 1;
    target.apqns[0] = adapter;
    target.apqns[1] = domain;

    if (ep11_session->flags & EP11_VHSM_MODE) {
        pin = ep11_session->vhsm_pin;
        pin_len = sizeof(ep11_session->vhsm_pin);

        rc = dll_m_Login(pin, pin_len,
                         nonce, nonce_len,
                         pin_blob, &pin_blob_len, (uint64_t) & target);
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s dll_m_Login failed: 0x%lx\n", __func__, rc);
            /* ignore the error here, the adapter may not be able to perform
             * m_Login at this moment */
            goto strict_mode;
        }
#ifdef DEBUG
        TRACE_DEBUG("EP11 VHSM Pin blob (size: %lu):\n", XCP_PINBLOB_BYTES);
        TRACE_DEBUG_DUMP(pin_blob, XCP_PINBLOB_BYTES);
#endif

        if (ep11_session->flags & EP11_VHSM_PINBLOB_VALID) {
            /* First part of pin-blob (keypart and session) must be equal */
            if (memcmp(ep11_session->vhsm_pin_blob, pin_blob, XCP_WK_BYTES) !=
                0) {
                TRACE_ERROR("%s VHSM-Pin blob not equal to previous one\n",
                            __func__);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: VHSM-Pin blob of adapter %02X.%04X is "
                           "not equal to other adapters for same session\n",
                           __func__, adapter, domain);
                return CKR_DEVICE_ERROR;
            }
        } else {
            memcpy(ep11_session->vhsm_pin_blob, pin_blob, XCP_PINBLOB_BYTES);
            ep11_session->flags |= EP11_VHSM_PINBLOB_VALID;
        }
    }

strict_mode:
    if (ep11_session->flags & EP11_STRICT_MODE) {
        nonce = ep11_session->session_id;
        nonce_len = sizeof(ep11_session->session_id);
        /* pin is already set to default pin or vhsm pin (if VHSM mode) */

        rc = dll_m_Login(pin, pin_len,
                         nonce, nonce_len,
                         pin_blob, &pin_blob_len, (uint64_t) & target);
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s dll_m_Login failed: 0x%lx\n", __func__, rc);
            /* ignore the error here, the adapter may not be able to perform
             * m_Login at this moment */
            return CKR_OK;
        }
#ifdef DEBUG
        TRACE_DEBUG("EP11 Session Pin blob (size: %lu):\n", XCP_PINBLOB_BYTES);
        TRACE_DEBUG_DUMP(pin_blob, XCP_PINBLOB_BYTES);
#endif

        if (ep11_session->flags & EP11_SESS_PINBLOB_VALID) {
            /* First part of pin-blob (keypart and session) must be equal */
            if (memcmp(ep11_session->session_pin_blob, pin_blob, XCP_WK_BYTES)
                != 0) {
                TRACE_ERROR("%s Pin blob not equal to previous one\n",
                            __func__);
                OCK_SYSLOG(LOG_ERR,
                           "%s: Error: Pin blob of adapter %02X.%04X is not "
                           "equal to other adapters for same session\n",
                           __func__, adapter, domain);
                return CKR_DEVICE_ERROR;
            }
        } else {
            memcpy(ep11_session->session_pin_blob, pin_blob, XCP_PINBLOB_BYTES);
            ep11_session->flags |= EP11_SESS_PINBLOB_VALID;
        }
    }

    return CKR_OK;
}

static CK_RV ep11_logout_handler(uint_32 adapter, uint_32 domain,
                                 void *handler_data)
{
    ep11_session_t *ep11_session = (ep11_session_t *) handler_data;
    ep11_target_t target;
    CK_RV rc;

    TRACE_INFO("Logging out adapter %02X.%04X\n", adapter, domain);

    memset(&target, 0, sizeof(target));
    target.length = 1;
    target.apqns[0] = adapter;
    target.apqns[1] = domain;

    if (ep11_session->flags & EP11_SESS_PINBLOB_VALID) {
#ifdef DEBUG
        TRACE_DEBUG("EP11 Session Pin blob (size: %lu):\n", XCP_PINBLOB_BYTES);
        TRACE_DEBUG_DUMP(ep11_session->session_pin_blob, XCP_PINBLOB_BYTES);
#endif

        rc = dll_m_Logout(ep11_session->session_pin_blob, XCP_PINBLOB_BYTES,
                          (uint64_t) & target);
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s dll_m_Logout failed: 0x%lx\n", __func__, rc);
          /* ignore any errors during m_logout */
        }
    }

    if (ep11_session->flags & EP11_VHSM_PINBLOB_VALID) {
#ifdef DEBUG
        TRACE_DEBUG("EP11 VHSM Pin blob (size: %lu):\n", XCP_PINBLOB_BYTES);
        TRACE_DEBUG_DUMP(ep11_session->vhsm_pin_blob, XCP_PINBLOB_BYTES);
#endif

        rc = dll_m_Logout(ep11_session->vhsm_pin_blob, XCP_PINBLOB_BYTES,
                          (uint64_t) & target);
        if (rc != CKR_OK) {
            rc = ep11_error_to_pkcs11_error(rc, NULL);
            TRACE_ERROR("%s dll_m_Logout failed: 0x%lx\n", __func__, rc);
            /* ignore any errors during m_logout */
        }
    }

    return CKR_OK;
}

CK_RV ep11tok_login_session(STDLL_TokData_t * tokdata, SESSION * session)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_session_t *ep11_session;
    CK_RV rc;
    CK_RV rc2;
    ST_SESSION_HANDLE handle = {.slotID =
            session->session_info.slotID,.sessionh = session->handle
    };
    CK_SESSION_HANDLE helper_session = CK_INVALID_HANDLE;

    TRACE_INFO("%s session=%lu\n", __func__, session->handle);

    if (!ep11_data->strict_mode && !ep11_data->vhsm_mode)
        return CKR_OK;

    if (session->session_info.flags & CKF_EP11_HELPER_SESSION)
        return CKR_OK;

    switch (session->session_info.state) {
    case CKS_RW_SO_FUNCTIONS:
    case CKS_RO_PUBLIC_SESSION:
    case CKS_RW_PUBLIC_SESSION:
        TRACE_INFO("%s Public or SO session\n", __func__);
        return CKR_OK;
    case CKS_RO_USER_FUNCTIONS:
        rc = ep11_open_helper_session(tokdata, session, &helper_session);
        if (rc != CKR_OK)
            return rc;
        handle.sessionh = helper_session;
        break;
    default:
        break;
    }

    if (session->private_data != NULL) {
        TRACE_INFO("%s Session already logged in\n", __func__);
        return CKR_USER_ALREADY_LOGGED_IN;
    }

    ep11_session = (ep11_session_t *) calloc(1, sizeof(ep11_session_t));
    if (ep11_session == NULL) {
        TRACE_ERROR("%s Memory allocation failed\n", __func__);
        return CKR_HOST_MEMORY;
    }
    ep11_session->session = session;
    ep11_session->session_object = CK_INVALID_HANDLE;
    ep11_session->vhsm_object = CK_INVALID_HANDLE;
    if (ep11_data->strict_mode)
        ep11_session->flags |= EP11_STRICT_MODE;
    if (ep11_data->vhsm_mode)
        ep11_session->flags |= EP11_VHSM_MODE;
    session->private_data = ep11_session;

    rc = generate_ep11_session_id(tokdata, session, ep11_session);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s _generate_ep11_session_id failed: 0x%lx\n", __func__,
                    rc);
        goto done;
    }
#ifdef DEBUG
    TRACE_DEBUG("EP11 Session-ID for PKCS#11 session %lu:\n", session->handle);
    TRACE_DEBUG_DUMP(ep11_session->session_id,
                     sizeof(ep11_session->session_id));
#endif

    if (ep11_data->vhsm_mode) {
        rc = get_vhsmpin(tokdata, session, ep11_session);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s get_vhsmpin failed: 0x%lx\n", __func__, rc);
            OCK_SYSLOG(LOG_ERR,
                       "%s: Error: A VHSM-PIN is required for VHSM_MODE.\n",
                       __func__);
            goto done;
        }
    }

    rc = handle_all_ep11_cards((ep11_target_t *) & ep11_data->target_list,
                               ep11_login_handler, ep11_session);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n", __func__, rc);
        goto done;
    }

    if (ep11_data->strict_mode) {
        if ((ep11_session->flags & EP11_SESS_PINBLOB_VALID) == 0) {
            rc = CKR_DEVICE_ERROR;
            TRACE_ERROR("%s no pinblob available\n", __func__);
            goto done;
        }

        rc = create_ep11_object(tokdata, &handle, ep11_session,
                                ep11_session->session_pin_blob,
                                sizeof(ep11_session->session_pin_blob),
                                &ep11_session->session_object);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s _create_ep11_object failed: 0x%lx\n", __func__, rc);
            goto done;
        }
    }

    if (ep11_data->vhsm_mode) {
        if ((ep11_session->flags & EP11_VHSM_PINBLOB_VALID) == 0) {
            rc = CKR_DEVICE_ERROR;
            TRACE_ERROR("%s no VHSM pinblob available\n", __func__);
            goto done;
        }

        rc = create_ep11_object(tokdata, &handle, ep11_session,
                                ep11_session->vhsm_pin_blob,
                                sizeof(ep11_session->vhsm_pin_blob),
                                &ep11_session->vhsm_object);
        if (rc != CKR_OK) {
            TRACE_ERROR("%s _create_ep11_object failed: 0x%lx\n", __func__, rc);
            goto done;
        }
    }

done:
    if (rc != CKR_OK) {
        if (ep11_session->flags &
            (EP11_SESS_PINBLOB_VALID | EP11_VHSM_PINBLOB_VALID)) {
            rc2 =
                handle_all_ep11_cards((ep11_target_t *) &
                                      ep11_data->target_list,
                                      ep11_logout_handler, ep11_session);
            if (rc2 != CKR_OK)
                TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n",
                            __func__, rc2);
        }

        if (ep11_session->session_object != CK_INVALID_HANDLE) {
            rc2 =
                SC_DestroyObject(tokdata, &handle,
                                 ep11_session->session_object);
            if (rc2 != CKR_OK)
                TRACE_ERROR("%s SC_DestroyObject failed: 0x%lx\n", __func__,
                            rc2);
        }

        if (ep11_session->vhsm_object != CK_INVALID_HANDLE) {
            rc2 = SC_DestroyObject(tokdata, &handle, ep11_session->vhsm_object);
            if (rc2 != CKR_OK)
                TRACE_ERROR("%s SC_DestroyObject failed: 0x%lx\n", __func__,
                            rc2);
        }

        free(ep11_session);
        session->private_data = NULL;

        TRACE_ERROR("%s: failed: 0x%lx\n", __func__, rc);
    }

    if (helper_session != CK_INVALID_HANDLE) {
        rc2 = ep11_close_helper_session(tokdata, &handle);
        if (rc2 != CKR_OK)
            TRACE_ERROR("%s ep11_close_helper_session failed: 0x%lx\n",
                        __func__, rc2);
    }

    return rc;
}

static CK_RV ep11tok_relogin_session(STDLL_TokData_t * tokdata,
                                     SESSION * session)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_session_t *ep11_session = (ep11_session_t *) session->private_data;
    CK_RV rc;

    TRACE_INFO("%s session=%lu\n", __func__, session->handle);

    if (ep11_session == NULL) {
        TRACE_INFO("%s Session not yet logged in\n", __func__);
        return CKR_USER_NOT_LOGGED_IN;
    }

    rc = handle_all_ep11_cards((ep11_target_t *) & ep11_data->target_list,
                               ep11_login_handler, ep11_session);
    if (rc != CKR_OK)
        TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n", __func__, rc);

    return CKR_OK;
}

CK_RV ep11tok_logout_session(STDLL_TokData_t * tokdata, SESSION * session)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_session_t *ep11_session = (ep11_session_t *) session->private_data;
    CK_RV rc, rc2;
    ST_SESSION_HANDLE handle = {.slotID =
            session->session_info.slotID,.sessionh = session->handle
    };
    CK_SESSION_HANDLE helper_session = CK_INVALID_HANDLE;

    TRACE_INFO("%s session=%lu\n", __func__, session->handle);

    if (!ep11_data->strict_mode && !ep11_data->vhsm_mode)
        return CKR_OK;

    if (session->session_info.flags & CKF_EP11_HELPER_SESSION)
        return CKR_OK;

    switch (session->session_info.state) {
    case CKS_RW_SO_FUNCTIONS:
    case CKS_RO_PUBLIC_SESSION:
    case CKS_RW_PUBLIC_SESSION:
        TRACE_INFO("%s Public or SO session\n", __func__);
        return CKR_OK;
    case CKS_RO_USER_FUNCTIONS:
        rc = ep11_open_helper_session(tokdata, session, &helper_session);
        if (rc != CKR_OK)
            return rc;
        handle.sessionh = helper_session;
        break;
    default:
        break;
    }

    if (ep11_session == NULL) {
        TRACE_INFO("%s CKR_USER_NOT_LOGGED_IN\n", __func__);
        return CKR_USER_NOT_LOGGED_IN;
    }

    rc = handle_all_ep11_cards((ep11_target_t *) & ep11_data->target_list,
                               ep11_logout_handler, ep11_session);
    if (rc != CKR_OK)
        TRACE_ERROR("%s handle_all_ep11_cards failed: 0x%lx\n", __func__, rc);

    if (ep11_session->session_object != CK_INVALID_HANDLE) {
        rc = SC_DestroyObject(tokdata, &handle, ep11_session->session_object);
        if (rc != CKR_OK)
            TRACE_ERROR("%s SC_DestroyObject failed: 0x%lx\n", __func__, rc);
    }
    if (ep11_session->vhsm_object != CK_INVALID_HANDLE) {
        rc = SC_DestroyObject(tokdata, &handle, ep11_session->vhsm_object);
        if (rc != CKR_OK)
            TRACE_ERROR("%s SC_DestroyObject failed: 0x%lx\n", __func__, rc);
    }

    free(ep11_session);
    session->private_data = NULL;

    if (helper_session != CK_INVALID_HANDLE) {
        rc2 = ep11_close_helper_session(tokdata, &handle);
        if (rc2 != CKR_OK)
            TRACE_ERROR("%s ep11_close_helper_session failed: 0x%lx\n",
                        __func__, rc2);
    }

    return rc;
}


static CK_BOOL ep11_is_session_object(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len)
{
    CK_ATTRIBUTE_PTR attr;

    attr = get_attribute_by_type(attrs, attrs_len, CKA_TOKEN);
    if (attr == NULL)
        return TRUE;

    if (attr->pValue == NULL)
        return TRUE;

    if (*((CK_BBOOL *) attr->pValue) == FALSE)
        return TRUE;

    return FALSE;
}

static void ep11_get_pin_blob(ep11_session_t * ep11_session, CK_BOOL is_session_obj,
                              CK_BYTE ** pin_blob, CK_ULONG * pin_blob_len)
{
    if (ep11_session != NULL &&
        (ep11_session->flags & EP11_STRICT_MODE) && is_session_obj) {
        *pin_blob = ep11_session->session_pin_blob;
        *pin_blob_len = sizeof(ep11_session->session_pin_blob);
        TRACE_DEVEL
            ("%s Strict mode and CKA_TOKEN=FALSE -> pass session pin_blob\n",
             __func__);
    } else if (ep11_session != NULL && (ep11_session->flags & EP11_VHSM_MODE)) {
        *pin_blob = ep11_session->vhsm_pin_blob;
        *pin_blob_len = sizeof(ep11_session->vhsm_pin_blob);
        TRACE_DEVEL("%s vHSM mode -> pass VHSM pin_blob\n", __func__);
    } else {
        *pin_blob = NULL;
        *pin_blob_len = 0;
    }
}

static CK_RV ep11_open_helper_session(STDLL_TokData_t * tokdata, SESSION * sess,
                                      CK_SESSION_HANDLE_PTR phSession)
{
    CK_RV rc;

    TRACE_INFO("%s\n", __func__);

    rc = SC_OpenSession(tokdata, sess->session_info.slotID,
                        CKF_RW_SESSION | CKF_SERIAL_SESSION |
                        CKF_EP11_HELPER_SESSION, phSession);
    if (rc != CKR_OK)
        TRACE_ERROR("%s SC_OpenSession failed: 0x%lx\n", __func__, rc);

    return rc;
}

static CK_RV ep11_close_helper_session(STDLL_TokData_t * tokdata,
                                       ST_SESSION_HANDLE * sSession)
{
    CK_RV rc;

    TRACE_INFO("%s\n", __func__);

    rc = SC_CloseSession(tokdata, sSession);
    if (rc != CKR_OK)
        TRACE_ERROR("%s SC_CloseSession failed: 0x%lx\n", __func__, rc);

    return rc;
}

CK_BBOOL ep11tok_optimize_single_ops(STDLL_TokData_t *tokdata)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    return ep11_data->optimize_single_ops ? CK_TRUE : CK_FALSE;
}

/* return -1 if v1 < v2, 0 if v1 == v2, 1 if v1 > v2 */
static int compare_ck_version(const CK_VERSION *v1, const CK_VERSION *v2)
{

    if (v1->major < v2->major)
        return -1;
    if (v1->major > v2->major)
        return 1;
    if (v1->minor < v2->minor)
        return -1;
    if (v1->minor > v2->minor)
        return 1;
    return 0;
}

static CK_RV get_card_type(uint_32 adapter, CK_ULONG *type)
{
    char fname[PATH_MAX];
    char buf[250];
    CK_RV rc;

    sprintf(fname, "%scard%02x/type", SYSFS_DEVICES_AP, adapter);
    rc = file_fgets(fname, buf, sizeof(buf));
    if (rc != CKR_OK)
        return rc;
    if (sscanf(buf, "CEX%luP", type) != 1)
        return CKR_FUNCTION_FAILED;
    return CKR_OK;
}

typedef struct query_version
{
    ep11_private_data_t *ep11_data;
    CK_CHAR serialNumber[16];
    CK_BBOOL first;
    CK_BBOOL error;
} query_version_t;

static CK_RV version_query_handler(uint_32 adapter, uint_32 domain,
                                   void *handler_data)
{
    query_version_t *qv = (query_version_t *)handler_data;
    CK_IBM_XCP_INFO xcp_info;
    CK_ULONG xcp_info_len = sizeof(xcp_info);
    CK_RV rc;
    ep11_target_t target;
    CK_ULONG card_type;
    ep11_card_version_t *card_version;

    memset(&target, 0, sizeof(target));
    target.length = 1;
    target.apqns[0] = adapter;
    target.apqns[1] = domain;

    rc = dll_m_get_xcp_info(&xcp_info, &xcp_info_len, CK_IBM_XCPQ_MODULE, 0,
                           (uint64_t)&target);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to query module version from adapter %02X.%04X\n",
                           __func__, adapter, domain);
       /* card may no longer be online, so ignore this error situation */
        return CKR_OK;
    }

    rc = get_card_type(adapter, &card_type);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s Failed to get card type for adapter %02X.%04X\n",
                   __func__, adapter, domain);
        /* card may no longer be online, so ignore this error situation */
        return CKR_OK;
    }

    /* Try to find existing version info for this card type */
    card_version = qv->ep11_data->card_versions;
    while (card_version != NULL) {
        if (card_version->card_type == card_type)
           break;
        card_version = card_version->next;
    }

    if (card_version == NULL) {
        /*
         * No version info for this card type found, create new entry and add
         * it to the list
         */
        card_version = calloc(1, sizeof(ep11_card_version_t));
        if (card_version == NULL) {
            TRACE_ERROR("%s Memory allocation failed\n", __func__);
            qv->error = TRUE;
            return CKR_HOST_MEMORY;
        }

        card_version->card_type = card_type;
        card_version->firmware_API_version = xcp_info.firmwareApi;
        card_version->firmware_version = xcp_info.firmwareVersion;

        card_version->next = qv->ep11_data->card_versions;
        qv->ep11_data->card_versions = card_version;
    } else {
        /*
         * Version info for this card type is already available, so check this
         * card against the existing info
         */
        if (card_version->firmware_API_version != xcp_info.firmwareApi) {
            TRACE_ERROR("%s Adapter %02X.%04X has a different API version "
                        "than the previous CEX%luP adapters: %lu\n", __func__,
                        adapter, domain, card_version->card_type,
                        xcp_info.firmwareApi);
            OCK_SYSLOG(LOG_ERR,
                       "Warning: Adapter %02X.%04X has a different API version "
                       "than the previous CEX%luP adapters: %lu\n",
                       adapter, domain, card_version->card_type,
                       xcp_info.firmwareApi);
            qv->error = TRUE;
            return CKR_OK;
        }

        if (compare_ck_version(&card_version->firmware_version,
                               &xcp_info.firmwareVersion) != 0) {
            TRACE_ERROR("%s Adapter %02X.%04X has a different firmware version "
                        "than the previous CEX%luP adapters: %d.%d\n", __func__,
                        adapter, domain, card_version->card_type,
                        xcp_info.firmwareVersion.major,
                        xcp_info.firmwareVersion.minor);
            OCK_SYSLOG(LOG_ERR,
                       "Warning: Adapter %02X.%04X has a different firmware "
                       "version than the previous CEX%luP adapters: %d.%d\n",
                       adapter, domain, card_version->card_type,
                       xcp_info.firmwareVersion.major,
                       xcp_info.firmwareVersion.minor);
            qv->error = TRUE;
            return CKR_OK;
        }
    }

    if (qv->first)
        memcpy(qv->serialNumber, xcp_info.serialNumber,
               sizeof(qv->serialNumber));
    qv->first = FALSE;

    return CKR_OK;
}

static CK_RV ep11tok_get_ep11_version(STDLL_TokData_t *tokdata)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_card_version_t *card_version;
    query_version_t qv;
    unsigned int host_version;
    CK_ULONG version_len = sizeof(host_version);
    CK_RV rc;

    if (dll_m_get_xcp_info == NULL) {
        TRACE_ERROR("%s Function dll_m_get_xcp_info is not available\n",
                    __func__);
        return CKR_FUNCTION_FAILED;
    }

    rc = dll_m_get_xcp_info(&host_version, &version_len,
                            CK_IBM_XCPHQ_VERSION, 0, 0);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s dll_m_get_xcp_info (HOST) failed: rc=0x%lx\n", __func__,
                    rc);
        return rc;
    }
    ep11_data->ep11_lib_version.major = (host_version & 0x00FF0000) >> 16;
    ep11_data->ep11_lib_version.minor = host_version & 0x000000FF0000;
    /*
     * EP11 host library < v2.0 returns an invalid version (i.e. 0x100). This
     * can safely be treated as version 1.0
     */
    if (ep11_data->ep11_lib_version.major == 0) {
        ep11_data->ep11_lib_version.major = 1;
        ep11_data->ep11_lib_version.minor = 0;
    }

    TRACE_INFO("%s Host library version: %d.%d\n", __func__,
               ep11_data->ep11_lib_version.major,
               ep11_data->ep11_lib_version.minor);

    memset(&qv, 0, sizeof(qv));
    qv.ep11_data = ep11_data;
    qv.first = TRUE;

    rc = handle_all_ep11_cards((ep11_target_t *)ep11_data->target_list,
                               version_query_handler, &qv);
    if (rc != CKR_OK) {
        TRACE_ERROR("%s handle_all_ep11_cards failed: rc=0x%lx\n",
                    __func__, rc);
        return rc;
    }
    if (qv.first) {
        TRACE_ERROR("%s No EP11 adapters are online or configured\n", __func__);
        return CKR_DEVICE_ERROR;
    }
    if (qv.error) {
        TRACE_ERROR("%s Failed to query version of EP11 adapters\n", __func__);
        return CKR_DEVICE_ERROR;
    }

    memcpy(ep11_data->serialNumber, qv.serialNumber,
           sizeof(ep11_data->serialNumber));

    TRACE_INFO("%s Serial number: %.16s\n", __func__, ep11_data->serialNumber);

    card_version = ep11_data->card_versions;
    while (card_version != NULL) {
        TRACE_INFO("%s Card type: CEX%luP\n", __func__,
                   card_version->card_type);
        TRACE_INFO("%s   Firmware API: %lu\n", __func__,
                card_version->firmware_API_version);
        TRACE_INFO("%s   Firmware Version: %d.%d\n", __func__,
                card_version->firmware_version.major,
                card_version->firmware_version.minor);
        card_version = card_version->next;
    }

    return CKR_OK;
}

static void free_card_versions(ep11_card_version_t *card_version)
{
    ep11_card_version_t *next_card_version;

    TRACE_INFO("%s running\n", __func__);

    while (card_version != NULL) {
        next_card_version = card_version->next;
        free(card_version);
        card_version = next_card_version;
    }
}

void ep11tok_copy_firmware_info(STDLL_TokData_t *tokdata,
                                 CK_TOKEN_INFO_PTR pInfo)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;

    /*
     * report the EP11 firmware version as hardware version, and
     * the EP11 host library version as firmware version
     */
    if (ep11_data->card_versions != NULL)
        pInfo->hardwareVersion = ep11_data->card_versions->firmware_version;
    pInfo->firmwareVersion = ep11_data->ep11_lib_version;
    memcpy(pInfo->serialNumber, ep11_data->serialNumber,
           sizeof(pInfo->serialNumber));
}

/**
 * Returns 1 if all APQNs that are present are at least at the required
 * versions. If non of the APQNs are at the required versions, 0 is returned.
 * If the APQN versions are inconsistent, -1 is returned.
 * Card types > the highest card type contained in the requirements array are
 * assumed to fulfill the minimum version requirements.
 */
static int check_required_versions(STDLL_TokData_t *tokdata,
                                   const version_req_t req[],
                                   CK_ULONG num_req)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    CK_ULONG i, max_card_type = 0;
    CK_BBOOL req_not_fullfilled = CK_FALSE;
    CK_BBOOL req_fullfilled = CK_FALSE;
    ep11_card_version_t *card_version;
    int status;

    for (i = 0; i < num_req; i++) {
        status = check_card_version(tokdata, req[i].card_type,
                                           req[i].min_lib_version,
                                           req[i].min_firmware_version,
                                           req[i].min_firmware_API_version);
        if (status == 0)
            req_not_fullfilled = CK_TRUE;
        if (status == 1)
            req_fullfilled = CK_TRUE;
        max_card_type = MAX(max_card_type, req[i].card_type);
    }

    /* Are card types > max_card_type present? */
    card_version = ep11_data->card_versions;
    while (card_version != NULL) {
        if (card_version->card_type > max_card_type) {
            /*
              * Card types > the highest card type contained in the requirements
              * array are assumed to fulfill the minimum version requirements.
              * So all others must also meet the version requirements or be
              * not present.
              */
             if (req_not_fullfilled == CK_TRUE)
                 return -1;
             return 1;
        }
        card_version = card_version->next;
    }

     /* No newer cards then max_card_type are present */
    if (req_not_fullfilled == CK_TRUE) {
        /*
         * At least one don't meet the requirements, so all other must not
         * fulfill the requirements, too, or are not present.
         */
        if (req_fullfilled == CK_TRUE)
                return -1;
        return 0;
    } else {
        /* All of the cards that are present fulfill the requirements */
        return 1;
    }
}

/**
 * returns 1 if all APQNs of the specified card type are at least at the
 * specified versions, 0 otherwise. If no APQN of that card type is online,
 * then -1 is returned.
 * Those parameters that are NULL are not checked.
 */
static int check_card_version(STDLL_TokData_t *tokdata, CK_ULONG card_type,
                              const CK_VERSION *ep11_lib_version,
                              const CK_VERSION *firmware_version,
                              const CK_ULONG *firmware_API_version)
{
    ep11_private_data_t *ep11_data = tokdata->private_data;
    ep11_card_version_t *card_version;

    TRACE_DEBUG("%s checking versions for CEX%luP cards.\n", __func__, card_type);

    if (ep11_lib_version != NULL) {
        if (compare_ck_version(&ep11_data->ep11_lib_version,
                               ep11_lib_version) < 0) {
            TRACE_DEBUG("%s ep11_lib_version is less than required\n", __func__);
            return 0;
        }
    }

    card_version = ep11_data->card_versions;
    while (card_version != NULL) {
        if (card_version->card_type == card_type)
            break;
        card_version = card_version->next;
    }

    if (card_version == NULL)
        return -1;

    if (firmware_version != NULL) {
        if (compare_ck_version(&card_version->firmware_version,
                               firmware_version) < 0) {
            TRACE_DEBUG("%s firmware_version is less than required\n", __func__);
            return 0;
        }
    }

    if (firmware_API_version != NULL) {
        if (card_version->firmware_API_version < *firmware_API_version) {
            TRACE_DEBUG("%s firmware_API_version is less than required\n",
                       __func__);
            return 0;
        }
    }

    return 1;
}
