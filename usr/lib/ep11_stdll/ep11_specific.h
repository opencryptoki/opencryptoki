/*
 * COPYRIGHT (c) International Business Machines Corp. 2015-2023
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

/*
 * OpenCryptoki EP11 token - EP11 token functions
 *
 */

#ifndef EP11_SPECIFIC_H
#define EP11_SPECIFIC_H

#include "ep11_func.h"
#include "configuration.h"

#include <ica_api.h>

#include <pthread.h>

#define EP11SHAREDLIB_NAME          "OCK_EP11_LIBRARY"
#define EP11SHAREDLIB_V4            "libep11.so.4"
#define EP11SHAREDLIB_V3            "libep11.so.3"
#define EP11SHAREDLIB_V2            "libep11.so.2"
#define EP11SHAREDLIB_V1            "libep11.so.1"
#define EP11SHAREDLIB               "libep11.so"

#define EP11_DEFAULT_CFG_FILE       "ep11tok.conf"
#define EP11_DEFAULT_CPFILTER_FILE  "ep11cpfilter.conf"

/* largest blobsize ever seen is about 5k (for 4096 mod bits RSA keys) */
/* Attribute bound keys can be larger */
#define MAX_BLOBSIZE                (8192 * 2)
#define MAX_CSUMSIZE                64
#define EP11_CSUMSIZE               3
#define MAX_DIGEST_STATE_BYTES      1024
#define MAX_CRYPT_STATE_BYTES       12288
#define MAX_SIGN_STATE_BYTES        12288
#define MAX_APQN                    256
#define EP11_BLOB_WKID_OFFSET       32

typedef struct cp_mech_config {
    CK_MECHANISM_TYPE mech;
    struct cp_mech_config *next;
} cp_mech_config_t;

typedef struct cp_config {
    unsigned long int cp;
    cp_mech_config_t *mech;
    struct cp_config *next;
} cp_config_t;

#define MAX_RETRY_COUNT             100

typedef struct ep11_card_version {
    struct ep11_card_version *next;
    CK_ULONG card_type;
    CK_VERSION firmware_version;
    CK_ULONG firmware_API_version;
} ep11_card_version_t;

typedef struct {
    const CK_VERSION *min_lib_version;
    const CK_VERSION *min_firmware_version;
    const CK_ULONG *min_firmware_API_version;
    CK_ULONG card_type;
} version_req_t;

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

#define EP11_SESS_PINBLOB_VALID     0x01
#define EP11_VHSM_PINBLOB_VALID     0x02
#define EP11_VHSMPIN_VALID          0x10
#define EP11_STRICT_MODE            0x40
#define EP11_VHSM_MODE              0x80

#define DEFAULT_EP11_PIN            "        "

#define CKH_IBM_EP11_SESSION        CKH_VENDOR_DEFINED + 1
#define CKH_IBM_EP11_VHSMPIN        CKH_VENDOR_DEFINED + 2

#define PUBLIC_SESSION_ID_LENGTH    16

#define CKF_EP11_HELPER_SESSION     0x80000000

/* Definitions for loading libica dynamically */
#define ICASHAREDLIB_V4  "libica.so.4"
#define ICASHAREDLIB_V3  "libica.so.3"

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

#ifdef SHA3_224
typedef unsigned int (*ica_sha3_224_t)(unsigned int message_part,
                                       unsigned int input_length,
                                       unsigned char *input_data,
                                       sha3_224_context_t *sha3_224_context,
                                       unsigned char *output_data);

typedef unsigned int (*ica_sha3_256_t)(unsigned int message_part,
                                       unsigned int input_length,
                                       unsigned char *input_data,
                                       sha3_256_context_t *sha3_256_context,
                                       unsigned char *output_data);

typedef unsigned int (*ica_sha3_384_t)(unsigned int message_part,
                                       uint64_t input_length,
                                       unsigned char *input_data,
                                       sha3_384_context_t *sha3_384_context,
                                       unsigned char *output_data);

typedef unsigned int (*ica_sha3_512_t)(unsigned int message_part,
                                       uint64_t input_length,
                                       unsigned char *input_data,
                                       sha3_512_context_t *sha3_512_context,
                                       unsigned char *output_data);
#endif
typedef void (*ica_cleanup_t) (void);
typedef int (*ica_fips_status_t) (void);

typedef struct {
    CK_BYTE buffer[MAX_SHA_BLOCK_SIZE];
    CK_ULONG block_size;
    CK_ULONG offset;
    CK_BBOOL first;
    union {
        sha_context_t sha1;
        sha256_context_t sha256;
        sha512_context_t sha512;
#ifdef SHA3_224
        sha3_224_context_t sha3_224;
        sha3_256_context_t sha3_256;
        sha3_384_context_t sha3_384;
        sha3_512_context_t sha3_512;
#endif
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
#ifdef SHA3_224
    ica_sha3_224_t ica_sha3_224;
    ica_sha3_256_t ica_sha3_256;
    ica_sha3_384_t ica_sha3_384;
    ica_sha3_512_t ica_sha3_512;
#endif
    ica_cleanup_t ica_cleanup;
    ica_fips_status_t ica_fips_status;
} libica_t;

/*
 * target list of adapters/domains, specified in a config file by user,
 * tells the device driver which adapter/domain pairs should be used,
 * they must have the same master key
 */
typedef struct {
    short format;
    short length;
    short apqns[2 * MAX_APQN];
} __attribute__ ((packed)) ep11_target_t;

/* EP11 token private data */
#define PKEY_MK_VP_LENGTH           32

#define PKEY_MODE_DISABLED          0
#define PKEY_MODE_DEFAULT           1
#define PKEY_MODE_ENABLE4NONEXTR    2

#define PQC_BYTE_NO(idx)            (((idx) - 1) / 8)
#define PQC_BIT_IN_BYTE(idx)        (((idx - 1)) % 8)
#define PQC_BIT_MASK(idx)           (0x80 >> PQC_BIT_IN_BYTE(idx))
#define PQC_BYTES                   ((((XCP_PQC_MAX / 32) * 32) + 32) / 8)

typedef struct {
    volatile unsigned long ref_count;
    target_t target;
    ep11_card_version_t *card_versions;
    CK_ULONG used_firmware_API_version;
    unsigned char control_points[XCP_CP_BYTES];
    size_t control_points_len;
    size_t max_control_point_index;
    CK_CHAR serialNumber[16];
    CK_BYTE pqc_strength[PQC_BYTES];
    int single_apqn;
    uint_32 adapter; /* set if single_apqn = 1 */
    uint_32 domain; /* set if single_apqn = 1 */
    volatile int single_apqn_has_new_wk;
} ep11_target_info_t;

typedef struct {
    char token_config_filename[PATH_MAX];
    ep11_target_t target_list;
    CK_BYTE raw2key_wrap_blob[MAX_BLOBSIZE];
    CK_BYTE raw2key_wrap_blob_reenc[MAX_BLOBSIZE];
    size_t raw2key_wrap_blob_l;
    int cka_sensitive_default_true;
    char cp_filter_config_filename[PATH_MAX];
    cp_config_t *cp_config;
    int strict_mode;
    int vhsm_mode;
    int optimize_single_ops;
    int pkey_mode;
    int pkey_wrap_supported;
    char pkey_mk_vp[PKEY_MK_VP_LENGTH];
    int msa_level;
    int digest_libica;
    char digest_libica_path[PATH_MAX];
    unsigned char expected_wkvp[XCP_WKID_BYTES];
    int expected_wkvp_set;
    volatile int mk_change_active;
    char mk_change_op[8]; /* set if mk_change_active = 1 */
    unsigned char new_wkvp[XCP_WKID_BYTES]; /* set if mk_change_active = 1 */
    struct apqn *mk_change_apqns; /* set if mk_change_active = 1 */
    unsigned int num_mk_change_apqns; /* set if mk_change_active = 1 */
    int inconsistent;
    libica_t libica;
    void *lib_ep11;
    CK_VERSION ep11_lib_version;
    volatile ep11_target_info_t *target_info;
    pthread_rwlock_t target_rwlock;
} ep11_private_data_t;

#define UNKNOWN_CP          0xFFFFFFFF

#define CP_BYTE_NO(cp)      ((cp) / 8)
#define CP_BIT_IN_BYTE(cp)  ((cp) % 8)
#define CP_BIT_MASK(cp)     (0x80 >> CP_BIT_IN_BYTE(cp))

#define SYSFS_DEVICES_AP        "/sys/devices/ap/"
#define REGEX_CARD_PATTERN      "card[0-9a-fA-F]+"
#define REGEX_SUB_CARD_PATTERN  "[0-9a-fA-F]+\\.[0-9a-fA-F]+"
#define MASK_EP11               0x04000000

typedef struct {
    STDLL_TokData_t *tokdata;
    ep11_session_t *ep11_session;
    CK_BBOOL wrap_was_successful;
    CK_RV wrap_error;
    CK_VOID_PTR secure_key;
    CK_ULONG secure_key_len;
    CK_VOID_PTR secure_key_reenc;
    CK_ULONG secure_key_reenc_len;
    CK_BYTE *pkey_buf;
    size_t *pkey_buflen_p;
    /* for AES XTS processing */
    CK_VOID_PTR secure_key2;
    CK_ULONG secure_key_len2;
    CK_VOID_PTR secure_key_reenc2;
    CK_ULONG secure_key_reenc_len2;
    CK_BYTE *pkey_buf2;
    size_t *pkey_buflen_p2;
    CK_BBOOL aes_xts;
} pkey_wrap_handler_data_t;

/* A wrapped key can have max 132 bytes for an EC-p521 key */
#define EP11_MAX_WRAPPED_KEY_SIZE      (2 * (521 / 8 + 1))
#define EP11_WRAPPED_KEY_VERSION_1     0x0001
#define EP11_WRAPPED_KEY_TYPE_AES      0x1
#define EP11_WRAPPED_KEY_TYPE_DES      0x2
#define EP11_WRAPPED_KEY_TYPE_EC       0x3
#define EP11_WRAPPED_KEY_TYPE_ED       0x4

typedef struct {
    uint16_t version;
    uint8_t res0[16];
    uint32_t wrapped_key_type;
    uint32_t bit_length;
    uint64_t token_size;
    uint8_t res1[8];
    uint8_t wrapped_key[EP11_MAX_WRAPPED_KEY_SIZE];
    uint8_t res2[50];
} __attribute__((packed)) wrapped_key_t;

extern m_DigestSingle_t dll_m_DigestSingle;
extern m_Login_t dll_m_Login;
extern m_Logout_t dll_m_Logout;
extern m_get_xcp_info_t dll_m_get_xcp_info;
extern m_admin_t dll_m_admin;
extern xcpa_cmdblock_t dll_xcpa_cmdblock;
extern xcpa_internal_rv_t dll_xcpa_internal_rv;

typedef CK_RV(*adapter_handler_t) (uint_32 adapter, uint_32 domain,
                                   void *handler_data);

CK_RV handle_all_ep11_cards(ep11_target_t * ep11_targets,
                            adapter_handler_t handler, void *handler_data);
CK_BBOOL is_apqn_online(uint_32 card, uint_32 domain);

CK_BOOL ep11_is_session_object(CK_ATTRIBUTE_PTR attrs, CK_ULONG attrs_len);
CK_RV ep11tok_relogin_session(STDLL_TokData_t *tokdata, SESSION *session);
void ep11_get_pin_blob(ep11_session_t *ep11_session, CK_BOOL is_session_obj,
                       CK_BYTE **pin_blob, CK_ULONG *pin_blob_len);
CK_RV ep11_login_handler(uint_32 adapter, uint_32 domain, void *handler_data);

ep11_target_info_t *get_target_info(STDLL_TokData_t *tokdata);
void put_target_info(STDLL_TokData_t *tokdata, ep11_target_info_t *target_info);
CK_RV refresh_target_info(STDLL_TokData_t *tokdata, CK_BBOOL wait_for_new_wk);

CK_RV get_ep11_target_for_apqn(uint_32 adapter, uint_32 domain,
                               target_t *target, uint64_t flags);
void free_ep11_target_for_apqn(target_t target);

CK_RV ep11_error_to_pkcs11_error(CK_RV rc, SESSION *session);

CK_BBOOL ep11tok_libica_digest_available(STDLL_TokData_t *tokdata,
                                         ep11_private_data_t *ep11_data,
                                         CK_MECHANISM_TYPE mech);
CK_RV ep11tok_libica_digest(STDLL_TokData_t *tokdata,
                            ep11_private_data_t *ep11_data,
                            CK_MECHANISM_TYPE mech, libica_sha_context_t *ctx,
                            CK_BYTE *in_data, CK_ULONG in_data_len,
                            CK_BYTE *out_data, CK_ULONG *out_data_len,
                            unsigned int message_part);

CK_RV ep11tok_handle_mk_change_event(STDLL_TokData_t *tokdata,
                                     unsigned int event_type,
                                     unsigned int event_flags,
                                     const char *payload,
                                     unsigned int payload_len);
CK_RV ep11tok_mk_change_check_pending_ops(STDLL_TokData_t *tokdata);
CK_BBOOL ep11tok_is_blob_new_wkid(STDLL_TokData_t *tokdata,
                                   CK_BYTE *blob, CK_ULONG blob_len);
CK_RV ep11tok_reencipher_blob(STDLL_TokData_t *tokdata, SESSION *session,
                              ep11_target_info_t **target_info,
                              CK_BYTE *blob, CK_ULONG blob_len,
                              CK_BYTE *new_blob);

void ep11_config_parse_error(int line, int col, const char *msg);
void ep11_config_error_token(const char *fname, const char *key,
                             int line, const char *expected);
CK_RV ep11_config_next(struct ConfigBaseNode **c, unsigned typemask,
                       const char *fname, const char *expected);

CK_RV ep11tok_get_mechanism_list(STDLL_TokData_t * tokdata,
                                 CK_MECHANISM_TYPE_PTR pMechanismList,
                                 CK_ULONG_PTR pulCount);

CK_RV ep11tok_get_mechanism_info(STDLL_TokData_t * tokdata,
                                 CK_MECHANISM_TYPE type,
                                 CK_MECHANISM_INFO_PTR pInfo);

CK_RV ep11tok_is_mechanism_supported(STDLL_TokData_t *tokdata,
                                     CK_MECHANISM_TYPE type);

CK_RV ep11tok_is_mechanism_supported_ex(STDLL_TokData_t *tokdata,
                                        CK_MECHANISM_PTR mech);

CK_RV ep11tok_init(STDLL_TokData_t * tokdata, CK_SLOT_ID SlotNumber,
                   char *conf_name);

CK_RV ep11tok_final(STDLL_TokData_t * tokdata, CK_BBOOL in_fork_initializer);

CK_RV ep11tok_generate_key(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs,
                           CK_ULONG attrs_len, CK_OBJECT_HANDLE_PTR handle);

CK_RV ep11tok_derive_key(STDLL_TokData_t * tokdata, SESSION * session,
                         CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE hBaseKey,
                         CK_OBJECT_HANDLE_PTR handle, CK_ATTRIBUTE_PTR attrs,
                         CK_ULONG attrs_len);

CK_RV ep11tok_generate_key_pair(STDLL_TokData_t * tokdata, SESSION * sess,
                                CK_MECHANISM_PTR pMechanism,
                                CK_ATTRIBUTE_PTR pPublicKeyTemplate,
                                CK_ULONG ulPublicKeyAttributeCount,
                                CK_ATTRIBUTE_PTR pPrivateKeyTemplate,
                                CK_ULONG ulPrivateKeyAttributeCount,
                                CK_OBJECT_HANDLE_PTR phPublicKey,
                                CK_OBJECT_HANDLE_PTR phPrivateKey);

CK_RV ep11tok_check_single_mech_key(STDLL_TokData_t *tokdata, SESSION * session,
                                    CK_MECHANISM *mech, CK_OBJECT_HANDLE key,
                                    CK_ULONG operation);

CK_BOOL ep11tok_mech_single_only(CK_MECHANISM *mech);

CK_RV ep11tok_sign_init(STDLL_TokData_t * tokdata, SESSION * session,
                        CK_MECHANISM * mech, CK_BBOOL recover_mode,
                        CK_OBJECT_HANDLE key);

CK_RV ep11tok_sign(STDLL_TokData_t * tokdata, SESSION * session,
                   CK_BBOOL length_only, CK_BYTE * in_data,
                   CK_ULONG in_data_len, CK_BYTE * signature,
                   CK_ULONG * sig_len);

CK_RV ep11tok_sign_update(STDLL_TokData_t * tokdata, SESSION * session,
                          CK_BYTE * in_data, CK_ULONG in_data_len);

CK_RV ep11tok_sign_final(STDLL_TokData_t * tokdata, SESSION * session,
                         CK_BBOOL length_only, CK_BYTE * signature,
                         CK_ULONG * sig_len);

CK_RV ep11tok_sign_single(STDLL_TokData_t *tokdata, SESSION *session,
                          CK_MECHANISM *mech, CK_BBOOL length_only,
                          CK_OBJECT_HANDLE key, CK_BYTE_PTR in_data,
                          CK_ULONG in_data_len, CK_BYTE_PTR signature,
                          CK_ULONG_PTR sig_len);

CK_RV ep11tok_verify_init(STDLL_TokData_t * tokdata, SESSION * session,
                          CK_MECHANISM * mech, CK_BBOOL recover_mode,
                          CK_OBJECT_HANDLE key);

CK_RV ep11tok_verify(STDLL_TokData_t * tokdata, SESSION * session,
                     CK_BYTE * in_data, CK_ULONG in_data_len,
                     CK_BYTE * signature, CK_ULONG sig_len);

CK_RV ep11tok_verify_update(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_BYTE * in_data, CK_ULONG in_data_len);

CK_RV ep11tok_verify_final(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_BYTE * signature, CK_ULONG sig_len);

CK_RV ep11tok_verify_single(STDLL_TokData_t *tokdata, SESSION *session,
                            CK_MECHANISM *mech, CK_OBJECT_HANDLE key,
                            CK_BYTE_PTR in_data, CK_ULONG in_data_len,
                            CK_BYTE_PTR signature, CK_ULONG sig_len);

CK_RV ep11tok_decrypt_final(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_BYTE_PTR output_part,
                            CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_decrypt(STDLL_TokData_t * tokdata, SESSION * session,
                      CK_BYTE_PTR input_data, CK_ULONG input_data_len,
                      CK_BYTE_PTR output_data, CK_ULONG_PTR p_output_data_len);

CK_RV ep11tok_decrypt_update(STDLL_TokData_t * tokdata, SESSION * session,
                             CK_BYTE_PTR input_part, CK_ULONG input_part_len,
                             CK_BYTE_PTR output_part,
                             CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_encrypt_final(STDLL_TokData_t * tokdata, SESSION * session,
                            CK_BYTE_PTR output_part,
                            CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_encrypt(STDLL_TokData_t * tokdata, SESSION * session,
                      CK_BYTE_PTR input_data, CK_ULONG input_data_len,
                      CK_BYTE_PTR output_data, CK_ULONG_PTR p_output_data_len);

CK_RV ep11tok_encrypt_update(STDLL_TokData_t * tokdata, SESSION * session,
                             CK_BYTE_PTR input_part,
                             CK_ULONG input_part_len, CK_BYTE_PTR output_part,
                             CK_ULONG_PTR p_output_part_len);

CK_RV ep11tok_encrypt_init(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key);

CK_RV ep11tok_encrypt_single(STDLL_TokData_t *tokdata, SESSION *session,
                             CK_MECHANISM *mech, CK_BBOOL length_only,
                             CK_OBJECT_HANDLE key, CK_BYTE *input_data,
                             CK_ULONG input_data_len, CK_BYTE *output_data,
                             CK_ULONG_PTR p_output_data_len);

CK_RV ep11tok_decrypt_init(STDLL_TokData_t * tokdata, SESSION * session,
                           CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE key);

CK_RV ep11tok_decrypt_single(STDLL_TokData_t *tokdata, SESSION *session,
                             CK_MECHANISM *mech, CK_BBOOL length_only,
                             CK_OBJECT_HANDLE key, CK_BYTE_PTR input_data,
                             CK_ULONG input_data_len, CK_BYTE_PTR output_data,
                             CK_ULONG_PTR p_output_data_len);

CK_RV ep11tok_wrap_key(STDLL_TokData_t * tokdata, SESSION * session,
                       CK_MECHANISM_PTR mech, CK_OBJECT_HANDLE wrapping_key,
                       CK_OBJECT_HANDLE key, CK_BYTE_PTR wrapped_key,
                       CK_ULONG_PTR p_wrapped_key_len);

CK_RV ep11tok_unwrap_key(STDLL_TokData_t * tokdata, SESSION * session,
                         CK_MECHANISM_PTR mech, CK_ATTRIBUTE_PTR attrs,
                         CK_ULONG attrs_len, CK_BYTE_PTR wrapped_key,
                         CK_ULONG wrapped_key_len,
                         CK_OBJECT_HANDLE wrapping_key,
                         CK_OBJECT_HANDLE_PTR p_key);

CK_RV ep11tok_login_session(STDLL_TokData_t * tokdata, SESSION * session);

CK_RV ep11tok_logout_session(STDLL_TokData_t * tokdata, SESSION * session,
                             CK_BBOOL in_fork_initializer);

CK_BBOOL ep11tok_optimize_single_ops(STDLL_TokData_t *tokdata);

CK_BBOOL ep11tok_libica_mech_available(STDLL_TokData_t *tokdata,
                                       CK_MECHANISM_TYPE mech,
                                       CK_OBJECT_HANDLE hKey);

CK_RV ep11tok_copy_firmware_info(STDLL_TokData_t *tokdata,
                                 CK_TOKEN_INFO_PTR pInfo);

CK_BBOOL ep11tok_pkey_usage_ok(STDLL_TokData_t *tokdata, SESSION *session,
                               CK_OBJECT_HANDLE hkey, CK_MECHANISM *mech);

CK_RV ep11tok_set_operation_state(STDLL_TokData_t *tokdata, SESSION *session);

/*
 * Macros to enclose EP11 library calls involving session bound blobs.
 * If the EP11 token is in an inconsistent state, fail with CKR_DEVICE_ERROR.
 * Obtain a target_info to be used with the EP11 library call.
 * If in single-APQN mode, and that APQN went offline, select another APQN and
 * retry the library call.
 * In case of EP11 library function failed with CKR_SESSION_CLOSED, relogin
 * all APQNs and retry the library call.
 */
#define RETRY_SESSION_SINGLE_APQN_START(rc, tokdata)                     \
                do {                                                     \
                    ep11_target_info_t* target_info;                     \
                    int retry_count;                                     \
                    CK_RV rc2;                                           \
                    if (((ep11_private_data_t *)                         \
                              (tokdata)->private_data)->inconsistent) {  \
                        (rc) = CKR_DEVICE_ERROR;                         \
                        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));  \
                        break;                                           \
                    }                                                    \
                    target_info = get_target_info((tokdata));            \
                    if (target_info == NULL) {                           \
                        (rc) = CKR_FUNCTION_FAILED;                      \
                        break;                                           \
                    }                                                    \
                    for (retry_count = 0;                                \
                         target_info != NULL &&                          \
                         retry_count < MAX_RETRY_COUNT;                  \
                         retry_count ++) {

#define RETRY_SESSION_SINGLE_APQN_END(rc, tokdata, session)              \
                         if (target_info->single_apqn &&                 \
                             ((rc) == CKR_IBM_TARGET_INVALID ||          \
                              ((rc) == CKR_FUNCTION_FAILED &&            \
                               !is_apqn_online(target_info->adapter,     \
                                               target_info->domain)))) { \
                             /* Single APQN went offline, select other */\
                             TRACE_DEVEL("%s single APQN went offline\n",\
                                         __func__);                      \
                             put_target_info((tokdata), target_info);    \
                             target_info = NULL;                         \
                             (rc) = refresh_target_info((tokdata),       \
                                                        FALSE);          \
                             if ((rc) != CKR_OK)                         \
                                 break;                                  \
                             target_info = get_target_info((tokdata));   \
                             if (target_info == NULL) {                  \
                                 (rc) = CKR_FUNCTION_FAILED;             \
                                 break;                                  \
                             }                                           \
                             continue;                                   \
                         }                                               \
                         if ((rc) != CKR_SESSION_CLOSED)                 \
                             break;                                      \
                         rc2 = ep11tok_relogin_session((tokdata),        \
                                                       (session));       \
                         if (rc2 != CKR_OK) {                            \
                             (rc) = rc2;                                 \
                             break;                                      \
                         }                                               \
                    }                                                    \
                    put_target_info((tokdata), target_info);             \
                } while (0);

/*
 * Macros to enclose EP11 library calls not involving session bound blobs, and
 * with given target_info.
 * If the EP11 token is in an inconsistent state, fail with CKR_DEVICE_ERROR.
 * If in single-APQN mode, and that APQN went offline, select another APQN and
 * retry the library call.
 */
#define RETRY_SINGLE_APQN_START(tokdata, rc)                             \
                do {                                                     \
                    int retry_count;                                     \
                    if (((ep11_private_data_t *)                         \
                              (tokdata)->private_data)->inconsistent) {  \
                        (rc) = CKR_DEVICE_ERROR;                         \
                        TRACE_ERROR("%s\n", ock_err(ERR_DEVICE_ERROR));  \
                        break;                                           \
                    }                                                    \
                    for (retry_count = 0;                                \
                         retry_count < MAX_RETRY_COUNT;                  \
                         retry_count ++) {

#define RETRY_SINGLE_APQN_END(rc, tokdata, target_info)                  \
                         if ((target_info) == NULL)                      \
                             break;                                      \
                         if ((target_info)->single_apqn &&               \
                             ((rc) == CKR_IBM_TARGET_INVALID ||          \
                              ((rc) == CKR_FUNCTION_FAILED &&            \
                               !is_apqn_online((target_info)->adapter,   \
                                            (target_info)->domain)))) {  \
                             /* Single APQN went offline, select other */\
                             TRACE_DEVEL("%s single APQN went offline\n",\
                                         __func__);                      \
                             put_target_info((tokdata), (target_info));  \
                             target_info = NULL;                         \
                             (rc) = refresh_target_info((tokdata),       \
                                                        FALSE);          \
                             if ((rc) != CKR_OK)                         \
                                 break;                                  \
                             (target_info) = get_target_info((tokdata)); \
                             if ((target_info) == NULL) {                \
                                 (rc) = CKR_FUNCTION_FAILED;             \
                                 break;                                  \
                             }                                           \
                             continue;                                   \
                         }                                               \
                         break;                                          \
                    }                                                    \
                } while (0);

/*
 * Macros to enclose EP11 library calls with 1, 2 or 3 key blobs as argument.
 * If a master key change is active, and the single APQN has the new WK,
 * obtain and use the re-enciphered blob(s) from CKA_IBM_OPAQUE_REENC from
 * the key object(s).
 * If a master key change is active, and the EP11 library call fails with
 * CKR_IBM_WKID_MISMATCH and the used blob(s) are enciphered with the new WK,
 * then select a new single APQN that has the new WK. If no available APQN has
 * the new WK, wait until on at least one the new WK gets activated.
 * In case the blob(s) are enciphered with the old WK, then obtain the
 * re-enciphered blob(s) from CKA_IBM_OPAQUE_REENC from the key object(s)
 * and retry the library call.
 * If the retry was successful, indicate that the single APQN has the new WK.
 */
#define RETRY_REENC_BLOB_START(tokdata, target_info, obj, blob, blobsize,\
                               useblob, useblobsize, rc) \
                RETRY_REENC_BLOB3_START(tokdata, target_info, obj, blob, \
                                        blobsize, useblob, useblobsize,  \
                                        NULL, blob, blobsize, blob,      \
                                        blobsize,  NULL, blob, blobsize, \
                                        blob, blobsize, rc)

#define RETRY_REENC_BLOB_END(tokdata, target_info, useblob, useblobsize, \
                             rc)                                         \
                RETRY_REENC_BLOB3_END(tokdata, target_info, useblob,     \
                                      useblobsize, NULL, 0, NULL, 0, rc)

#define RETRY_REENC_BLOB2_START(tokdata, target_info, obj1, blob1,       \
                                blobsize1, useblob1, useblobsize1,       \
                                obj2, blob2, blobsize2, useblob2,        \
                                useblobsize2, rc)                        \
                RETRY_REENC_BLOB3_START(tokdata, target_info, obj1,      \
                                        blob1, blobsize1, useblob1,      \
                                        useblobsize1, obj2, blob2,       \
                                        blobsize2, useblob2,             \
                                        useblobsize2, NULL, blob1,       \
                                        blobsize1, blob1, blobsize1, rc)

#define RETRY_REENC_BLOB2_END(tokdata, target_info, useblob1,            \
                              useblobsize1, useblob2, useblobsize2, rc)  \
                RETRY_REENC_BLOB3_END(tokdata, target_info, useblob1,    \
                                      useblobsize1, useblob2,            \
                                      useblobsize2, NULL, 0, rc)

#define RETRY_REENC_BLOB3_START(tokdata, target_info, obj1, blob1,       \
                                blobsize1, useblob1, useblobsize1,       \
                                obj2, blob2, blobsize2, useblob2,        \
                                useblobsize2, obj3, blob3, blobsize3,    \
                                useblob3, useblobsize3, rc)              \
                do {                                                     \
                    int retry = 0;                                       \
                    do {                                                 \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            ((target_info)->single_apqn_has_new_wk ||    \
                             retry == 1)) {                              \
                            /* New WK is set on single APQN */           \
                            TRACE_DEVEL("%s single APQN has new WK\n",   \
                                        __func__);                       \
                            (rc) = obj_opaque_2_reenc_blob((tokdata),    \
                                                   (obj1), &(useblob1),  \
                                                   &(useblobsize1));     \
                            if ((rc) == CKR_TEMPLATE_INCOMPLETE) {       \
                                (useblob1) = (blob1);                    \
                                (useblobsize1) = (blobsize1);            \
                            } else if ((rc) != CKR_OK) {                 \
                                TRACE_ERROR("%s reenc blob1 invalid\n",  \
                                            __func__);                   \
                                break;                                   \
                            }                                            \
                            if (obj2 != NULL) {                          \
                                (rc) = obj_opaque_2_reenc_blob((tokdata),\
                                                     (obj2), &(useblob2),\
                                                     &(useblobsize2));   \
                                if ((rc) == CKR_TEMPLATE_INCOMPLETE) {   \
                                    (useblob2) = (blob2);                \
                                    (useblobsize2) = (blobsize2);        \
                                } else if ((rc) != CKR_OK) {             \
                                    TRACE_ERROR(                         \
                                            "%s reenc blob2 invalid\n",  \
                                            __func__);                   \
                                    break;                               \
                                }                                        \
                            }                                            \
                            if (obj3 != NULL) {                          \
                                (rc) = obj_opaque_2_reenc_blob((tokdata),\
                                                     (obj3), &(useblob3),\
                                                     &(useblobsize3));   \
                                if ((rc) == CKR_TEMPLATE_INCOMPLETE) {   \
                                    (useblob3) = (blob3);                \
                                    (useblobsize3) = (blobsize3);        \
                                } else if ((rc) != CKR_OK) {             \
                                    TRACE_ERROR(                         \
                                            "%s reenc blob3 invalid\n",  \
                                            __func__);                   \
                                    break;                               \
                                }                                        \
                            }                                            \
                            retry = 1;                                   \
                        }  else {                                        \
                            (useblob1) = (blob1);                        \
                            (useblobsize1) = (blobsize1);                \
                            if (obj2 != NULL) {                          \
                                (useblob2) = (blob2);                    \
                                (useblobsize2) = (blobsize2);            \
                            }                                            \
                            if (obj3 != NULL) {                          \
                                (useblob3) = (blob3);                    \
                                (useblobsize3) = (blobsize3);            \
                            }                                            \
                        }

#define RETRY_REENC_BLOB3_END(tokdata, target_info, useblob1,            \
                              useblobsize1, useblob2, useblobsize2,      \
                              useblob3, useblobsize3, rc)                \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            retry == 0 &&                                \
                            (rc) == CKR_IBM_WKID_MISMATCH) {             \
                            if (ep11tok_is_blob_new_wkid((tokdata),      \
                                          (useblob1), (useblobsize1)) || \
                                (useblob2 != NULL &&                     \
                                 ep11tok_is_blob_new_wkid((tokdata),     \
                                         (useblob2), (useblobsize2))) || \
                                (useblob3 != NULL &&                     \
                                 ep11tok_is_blob_new_wkid((tokdata),     \
                                         (useblob3), (useblobsize3)))) { \
                                /* blob has new WK, but single APQN not.
                                   Wait until other single APQN with
                                   new WK set is available */            \
                                TRACE_DEVEL("%s WKID mismatch, blob has "\
                                            "new WK, retry with new "    \
                                            "single APQN with new WK, "  \
                                            "wait if required\n",        \
                                            __func__);                   \
                                put_target_info((tokdata),               \
                                                 (target_info));         \
                                (target_info) = NULL;                    \
                                (rc) = refresh_target_info((tokdata),    \
                                                           TRUE);        \
                                if ((rc) != CKR_OK)                      \
                                    break;                               \
                                (target_info) =                          \
                                             get_target_info((tokdata)); \
                                if ((target_info) == NULL) {             \
                                    (rc) = CKR_FUNCTION_FAILED;          \
                                    break;                               \
                                }                                        \
                                continue;                                \
                            }                                            \
                            /* Single APQN seems to now have new WK */   \
                            TRACE_DEVEL("%s WKID mismatch, retry with "  \
                                        "reenc-blob(s)\n", __func__);    \
                            retry = 1;                                   \
                            continue;                                    \
                        }                                                \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            retry == 1 &&                                \
                            (rc) != CKR_IBM_WKID_MISMATCH &&             \
                            (rc) != CKR_IBM_TARGET_INVALID &&            \
                            (rc) != CKR_FUNCTION_FAILED) {               \
                            /* retry with re-enciphered blob worked */   \
                            TRACE_DEVEL("%s single APQN has new WK\n",   \
                                        __func__);                       \
                            __sync_or_and_fetch(                         \
                                 &(target_info)->single_apqn_has_new_wk, \
                                 1);                                     \
                        }                                                \
                        break;                                           \
                    } while (1);                                         \
                } while (0);

/*
 * Macros to enclose EP11 library calls with the wrap-blob as argument.
 * If a master key change is active, and the single APQN has the new WK,
 * obtain and use the re-enciphered wrap-blob.
 * If a master key change is active, and the EP11 library call fails with
 * CKR_IBM_WKID_MISMATCH and the used wrap blob is enciphered with the new WK,
 * then select a new single APQN that has the new WK. If no available APQN has
 * the new WK, wait until on at least one the new WK gets activated.
 * In case the used wrap blob is enciphered with the old WK, then obtain the
 * re-enciphered wrap-blob and retry the library call.
 * If the retry was successful, indicate that the single APQN has the new WK.
 */
#define RETRY_REENC_WRAPBLOB_START(tokdata, target_info, useblob)        \
                do {                                                     \
                    int retry = 0;                                       \
                    do {                                                 \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            (target_info)->single_apqn_has_new_wk &&     \
                            retry == 0) {                                \
                            /* New WK is already set on single APQN */   \
                            TRACE_DEVEL("%s single APQN has new WK\n",   \
                                        __func__);                       \
                            (useblob) = ((ep11_private_data_t *)         \
                                           (tokdata)->private_data)->    \
                                                raw2key_wrap_blob_reenc; \
                            retry = 1;                                   \
                        } else {                                         \
                            (useblob) = ((ep11_private_data_t *)         \
                                           (tokdata)->private_data)->    \
                                                raw2key_wrap_blob;       \
                        }

#define RETRY_REENC_WRAPBLOB_END(tokdata, target_info, useblob, rc)      \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            retry == 0 &&                                \
                            (rc) == CKR_IBM_WKID_MISMATCH) {             \
                            if (ep11tok_is_blob_new_wkid((tokdata),      \
                                   (useblob),                            \
                                   ((ep11_private_data_t *)              \
                                           (tokdata)->private_data)->    \
                                                 raw2key_wrap_blob_l)) { \
                                /* blob has new WK, but single APQN not.
                                   Wait until other single APQN with
                                   new WK set is available */            \
                                TRACE_DEVEL("%s WKID mismatch, blob has "\
                                            "new WK, retry with new "    \
                                            "single APQN with new WK, "  \
                                            "wait if required\n",        \
                                            __func__);                   \
                                put_target_info((tokdata),               \
                                                 (target_info));         \
                                (target_info) = NULL;                    \
                                (rc) = refresh_target_info((tokdata),    \
                                                           TRUE);        \
                                if ((rc) != CKR_OK)                      \
                                    break;                               \
                                (target_info) =                          \
                                             get_target_info((tokdata)); \
                                if ((target_info) == NULL) {             \
                                    (rc) = CKR_FUNCTION_FAILED;          \
                                    break;                               \
                                }                                        \
                                continue;                                \
                            }                                            \
                            /* Single APQN seems to now have new WK */   \
                            TRACE_DEVEL("%s WKID mismatch, retry with "  \
                                        "reenc-wrap-blob\n", __func__);  \
                            (useblob) = ((ep11_private_data_t *)         \
                                           (tokdata)->private_data)->    \
                                                raw2key_wrap_blob_reenc; \
                            retry = 1;                                   \
                            continue;                                    \
                        }                                                \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            retry == 1 &&                                \
                            (rc) != CKR_IBM_WKID_MISMATCH &&             \
                            (rc) != CKR_IBM_TARGET_INVALID &&            \
                            (rc) != CKR_FUNCTION_FAILED) {               \
                            /* retry with re-enciphered blob worked */   \
                            TRACE_DEVEL("%s single APQN has new WK\n",   \
                                        __func__);                       \
                            __sync_or_and_fetch(                         \
                                 &(target_info)->single_apqn_has_new_wk, \
                                 1);                                     \
                        }                                                \
                        break;                                           \
                    } while (1);                                         \
                } while (0);

/*
 * Macros to enclose EP11 library calls with a blob as argument that gets
 * updated by the EP11 library call.
 * If a master key change is active, and the single APQN has the new WK,
 * use the re-enciphered blob for the EP11 library call.
 * If a master key change is active, and the EP11 library call fails with
 * CKR_IBM_WKID_MISMATCH use the re-enciphered blob and retry the library call.
 * Also indicate that the single APQN has the new WK.
 * If a master key change is active, and the EP11 library call was successful
 * when using the old blob, re-encipher the (potentially updated) blob.
 * When re-enciphering fails with CKR_IBM_WK_NOT_INITIALIZED, because the
 * new WK was just activated on the single APQN, indicate that the single APQN
 * has the new WK, and retry the EP11 library call with the (still unchanged)
 * re-enciphered blob (which then will be potentially updated by the EP11
 * library call).
 */
#define RETRY_UPDATE_BLOB_START(tokdata, target_info, blob, blobsize,    \
                                reencblob, reencblobsize,                \
                                useblob, useblobsize)                    \
                do {                                                     \
                    CK_RV rc2;                                           \
                    int retry = 0;                                       \
                    do {                                                 \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            ((target_info)->single_apqn_has_new_wk ||    \
                             retry == 1)) {                              \
                            /* New WK is set on single APQN */           \
                            TRACE_DEVEL("%s single APQN has new WK\n",   \
                                        __func__);                       \
                            (useblob) = (reencblob);                     \
                            (useblobsize) = (reencblobsize);             \
                            retry = 1;                                   \
                        } else {                                         \
                            (useblob) = (blob);                          \
                            (useblobsize) = (blobsize);                  \
                        }

#define RETRY_UPDATE_BLOB_END(tokdata, session, target_info, blob,       \
                              blobsize, reencblob, reencblobsize,        \
                              useblob, useblobsize, rc)                  \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            retry == 0 &&                                \
                            (rc) == CKR_IBM_WKID_MISMATCH) {             \
                            if (ep11tok_is_blob_new_wkid((tokdata),      \
                                            (useblob), (useblobsize))) { \
                                /* blob has new WK, but single APQN not.
                                   Wait until other single APQN with
                                   new WK set is available */            \
                                TRACE_DEVEL("%s WKID mismatch, blob has "\
                                            "new WK, retry with new "    \
                                            "single APQN with new WK, "  \
                                            "wait if required\n",        \
                                            __func__);                   \
                                put_target_info((tokdata),               \
                                                 (target_info));         \
                                (target_info) = NULL;                    \
                                (rc) = refresh_target_info((tokdata),    \
                                                           TRUE);        \
                                if ((rc) != CKR_OK)                      \
                                    break;                               \
                                (target_info) =                          \
                                             get_target_info((tokdata)); \
                                if ((target_info) == NULL) {             \
                                    (rc) = CKR_FUNCTION_FAILED;          \
                                    break;                               \
                                }                                        \
                                continue;                                \
                            }                                            \
                            /* Single APQN seems to now have new WK */   \
                            TRACE_DEVEL("%s single APQN has new WK\n",   \
                                        __func__);                       \
                            retry = 1;                                   \
                            continue;                                    \
                        }                                                \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            retry == 0 &&                                \
                            (rc) != CKR_IBM_WKID_MISMATCH &&             \
                            (rc) != CKR_IBM_TARGET_INVALID &&            \
                            (rc) != CKR_FUNCTION_FAILED) {               \
                            /* Op worked, re-encipher updated blob */    \
                            TRACE_DEVEL("%s reencipher updated blob\n",  \
                                        __func__);                       \
                            if ((blobsize) != (reencblobsize)) {         \
                                TRACE_ERROR("%s reencblobsize wrong \n", \
                                            __func__);                   \
                                (rc) = CKR_ARGUMENTS_BAD;                \
                                break;                                   \
                            }                                            \
                            rc2 = ep11tok_reencipher_blob((tokdata),     \
                                                          (session),     \
                                                          &(target_info),\
                                                          (blob),        \
                                                          (blobsize),    \
                                                          (reencblob));  \
                            if (rc2 == CKR_IBM_WK_NOT_INITIALIZED) {     \
                                /* Single APQN now has new WK */         \
                                TRACE_DEVEL("%s WKID mismatch on "       \
                                      "reencipher, retry\n", __func__);  \
                                retry = 1;                               \
                                continue;                                \
                            }                                            \
                            if (rc2 != CKR_OK) {                         \
                                (rc) = CKR_DEVICE_ERROR;                 \
                                TRACE_ERROR("%s\n",                      \
                                            ock_err(ERR_DEVICE_ERROR));  \
                                break;                                   \
                            }                                            \
                        }                                                \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            retry == 1 &&                                \
                            (rc) != CKR_IBM_WKID_MISMATCH &&             \
                            (rc) != CKR_IBM_TARGET_INVALID &&            \
                            (rc) != CKR_FUNCTION_FAILED) {               \
                            /* retry with re-enciphered blob worked */   \
                            TRACE_DEVEL("%s single APQN has new WK\n",   \
                                        __func__);                       \
                            __sync_or_and_fetch(                         \
                                 &(target_info)->single_apqn_has_new_wk, \
                                 1);                                     \
                            /* old blob is no longer valid, replace with
                             * re-enciphered blob */                     \
                            if ((blobsize) != (useblobsize)) {           \
                                TRACE_ERROR("%s useblobsize wrong \n",   \
                                            __func__);                   \
                                (rc) = CKR_ARGUMENTS_BAD;                \
                                break;                                   \
                            }                                            \
                            memcpy((blob), (useblob), (blobsize));       \
                        }                                                \
                        break;                                           \
                    } while (1);                                         \
                } while (0);

/*
 * Macros to enclose EP11 library calls with a key blob and a state blob as
 * arguments where the state blob gets updated by the EP11 library call.
 * If a master key change is active, and the single APQN has the new WK,
 * obtain and use the re-enciphered key blob CKA_IBM_OPAQUE_REENC from
 * the key object, and also use the re-enciphered state blob(s) for the EP11
 * library call.
 * If a master key change is active, and the EP11 library call fails with
 * CKR_IBM_WKID_MISMATCH use the re-enciphered blobs and retry the library
 * call.
 * If the retry was successful, indicate that the single APQN has the new WK.
 * If a master key change is active, and the EP11 library call was successful
 * when using the old blobs, re-encipher the (potentially updated) state blob.
 * When re-enciphering fails with CKR_IBM_WK_NOT_INITIALIZED, because the
 * new WK was just activated on the single APQN, indicate that the single APQN
 * has the new WK, and retry the EP11 library call with the (still unchanged)
 * re-enciphered state blob (which then will be potentially updated by the EP11
 * library call).
 */
#define RETRY_REENC_BLOB_STATE_START(tokdata, target_info, obj, blob,    \
                                     blobsize, useblob, useblobsize,     \
                                     stateblob, reencstate,              \
                                     stateblobsize, usestate,            \
                                     usestatesize, rc)                   \
                do {                                                     \
                    int retry = 0;                                       \
                    do {                                                 \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            ((target_info)->single_apqn_has_new_wk ||    \
                             retry == 1)) {                              \
                            /* New WK is set on single APQN */           \
                            TRACE_DEVEL("%s single APQN has new WK\n",   \
                                        __func__);                       \
                            (rc) = obj_opaque_2_reenc_blob((tokdata),    \
                                      (obj), &(useblob), &(useblobsize));\
                            if ((rc) == CKR_TEMPLATE_INCOMPLETE) {       \
                                (useblob) = (blob);                      \
                                (useblobsize) = (blobsize);              \
                            } else if ((rc) != CKR_OK) {                 \
                                TRACE_ERROR("%s reenc blob invalid\n",   \
                                            __func__);                   \
                                break;                                   \
                            }                                            \
                            (usestate) = (reencstate);                   \
                            retry = 1;                                   \
                        } else {                                         \
                            (useblob) = (blob);                          \
                            (useblobsize) = (blobsize);                  \
                            (usestate) = (stateblob);                    \
                        }                                                \
                        (usestatesize) = (stateblobsize);

#define RETRY_REENC_BLOB_STATE_END(tokdata, session, target_info,        \
                                   blob, blobsize,                       \
                                   useblob,  useblobsize, stateblob,     \
                                   reencstate, stateblobsize, usestate,  \
                                   usestatesize, newstate, rc)           \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            retry == 0 &&                                \
                            (rc) == CKR_IBM_WKID_MISMATCH) {             \
                            if (ep11tok_is_blob_new_wkid((tokdata),      \
                                            (useblob), (useblobsize)) || \
                                ep11tok_is_blob_new_wkid((tokdata),      \
                                         (usestate), (usestatesize))) {  \
                                /* blob has new WK, but single APQN not.
                                   Wait until other single APQN with
                                   new WK set is available */            \
                                TRACE_DEVEL("%s WKID mismatch, blob has "\
                                            "new WK, retry with new "    \
                                            "single APQN with new WK, "  \
                                            "wait if required\n",        \
                                            __func__);                   \
                                put_target_info((tokdata),               \
                                                 (target_info));         \
                                (target_info) = NULL;                    \
                                (rc) = refresh_target_info((tokdata),    \
                                                           TRUE);        \
                                if ((rc) != CKR_OK)                      \
                                    break;                               \
                                (target_info) =                          \
                                             get_target_info((tokdata)); \
                                if ((target_info) == NULL) {             \
                                    (rc) = CKR_FUNCTION_FAILED;          \
                                    break;                               \
                                }                                        \
                                continue;                                \
                            }                                            \
                            /* Single APQN seems to now have new WK */   \
                            TRACE_DEVEL("%s WKID mismatch, retry with "  \
                                        "reenc-blob\n", __func__);       \
                            retry = 1;                                   \
                            continue;                                    \
                        }                                                \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            retry == 1 &&                                \
                            (((newstate) && (rc) == CKR_OK) ||           \
                             (!(newstate) &&                             \
                              (rc) != CKR_IBM_WKID_MISMATCH &&           \
                              (rc) != CKR_IBM_TARGET_INVALID &&          \
                              (rc) != CKR_FUNCTION_FAILED))) {           \
                            /* retry with re-enciphered blob worked */   \
                            TRACE_DEVEL("%s single APQN has new WK\n",   \
                                        __func__);                       \
                            __sync_or_and_fetch(                         \
                                 &(target_info)->single_apqn_has_new_wk, \
                                 1);                                     \
                            /* old blobs are no longer valid, replace with
                             * re-enciphered blobs */                    \
                            if ((blobsize) != (useblobsize)) {           \
                                TRACE_ERROR("%s useblobsize wrong \n",   \
                                            __func__);                   \
                                (rc) = CKR_ARGUMENTS_BAD;                \
                                break;                                   \
                            }                                            \
                            memcpy((blob), (useblob), (blobsize));       \
                            if ((stateblobsize) != (usestatesize)) {     \
                                TRACE_ERROR("%s usestatesize wrong \n",  \
                                            __func__);                   \
                                (rc) = CKR_ARGUMENTS_BAD;                \
                                break;                                   \
                            }                                            \
                            memcpy((stateblob), (usestate),              \
                                   (stateblobsize));                     \
                        }                                                \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                      private_data)->mk_change_active && \
                            retry == 0 &&                                \
                            (((newstate) && (rc) == CKR_OK) ||           \
                             (!(newstate) &&                             \
                              (rc) != CKR_IBM_WKID_MISMATCH &&           \
                              (rc) != CKR_IBM_TARGET_INVALID &&          \
                              (rc) != CKR_FUNCTION_FAILED))) {           \
                            /* worked, re-encipher updated state blob */ \
                            TRACE_DEVEL("%s reencipher updated state "   \
                                       "blob\n",  __func__);             \
                            rc2 = ep11tok_reencipher_blob((tokdata),     \
                                                        (session),       \
                                                        &(target_info),  \
                                                        (stateblob),     \
                                                        (stateblobsize), \
                                                        (reencstate));   \
                            if (rc2 == CKR_IBM_WK_NOT_INITIALIZED) {     \
                                /* Single APQN now has new WK */         \
                                TRACE_DEVEL("%s WKID mismatch on "       \
                                            "reencipher, retry\n",       \
                                            __func__);                   \
                                __sync_or_and_fetch(&(target_info)->     \
                                                  single_apqn_has_new_wk,\
                                                  1);                    \
                                continue;                                \
                            }                                            \
                            if (rc2 != CKR_OK) {                         \
                                (rc) = CKR_DEVICE_ERROR;                 \
                                TRACE_ERROR("%s\n",                      \
                                         ock_err(ERR_DEVICE_ERROR));     \
                                break;                                   \
                            }                                            \
                        }                                                \
                        break;                                           \
                    } while (1);                                         \
                } while (0);

/*
 * Macros to enclose EP11 library calls that create 1 or 2 key blobs as output.
 * If a master key change is active, and the key blob(s) were created with the
 * new WK, copy them to the re-enciphered blob(s) and indicate that the
 * single APQN has the new WK.
 * If a master key change is active, and the key blob(s) were created with the
 * old WK, re-encipher the key blob(s).
 * If re-enciphering fails with CKR_IBM_WK_NOT_INITIALIZED, because the new WK
 * was just activated on the single APQN, indicate that the single APQN has
 * the new WK, and retry the EP11 library call. This creates new key blob(s)
 * that are then enciphered with the new WK.
 */
#define RETRY_REENC_CREATE_KEY_START()                                   \
                RETRY_REENC_CREATE_KEY2_START()

#define RETRY_REENC_CREATE_KEY_END(tokdata, session, target_info, blob,  \
                                   reencblob, blobsize, rc)              \
                RETRY_REENC_CREATE_KEY2_END(tokdata, session,            \
                                            target_info, blob,           \
                                            reencblob, blobsize, blob,   \
                                            reencblob, 0, rc)

#define RETRY_REENC_CREATE_KEY2_START()                                  \
                do {                                                     \
                    do {                                                 \

#define RETRY_REENC_CREATE_KEY2_END(tokdata, session, target_info, blob1,\
                                    reencblob1, blobsize1, blob2,        \
                                    reencblob2, blobsize2, rc)           \
                        if (((ep11_private_data_t *)(tokdata)->          \
                                private_data)->mk_change_active &&       \
                            (rc) == CKR_OK) {                            \
                            /* Key creation successful */                \
                            if (ep11tok_is_blob_new_wkid((tokdata),      \
                                              (blob1), (blobsize1)) ||   \
                                ((blobsize2) > 0 &&                      \
                                 ep11tok_is_blob_new_wkid((tokdata),     \
                                               (blob2), (blobsize2)))) { \
                                /* Key created with new WK already:
                                   supply it in reencblob as well */     \
                                TRACE_DEVEL("%s new key has new WK\n",   \
                                            __func__);                   \
                                memcpy((reencblob1), (blob1),            \
                                       (blobsize1));                     \
                                if ((blobsize2) > 0)                     \
                                    memcpy((reencblob2), (blob2),        \
                                           (blobsize2));                 \
                                __sync_or_and_fetch(&(target_info)->     \
                                                 single_apqn_has_new_wk, \
                                                 1);                     \
                            } else {                                     \
                                /* created with old WK, re-encipher it */\
                                TRACE_DEVEL("%s new key has old WK, "    \
                                            "reencipher it\n", __func__);\
                                (rc) = ep11tok_reencipher_blob((tokdata),\
                                             (session),                  \
                                             &(target_info), (blob1),    \
                                             (blobsize1), (reencblob1)); \
                                if ((rc) == CKR_IBM_WK_NOT_INITIALIZED) {\
                                    /* Single APQN now has new WK,
                                       repeat key creation. */           \
                                    TRACE_DEVEL("%s WKID mismatch on "   \
                                                "reencipher, retry\n",   \
                                                __func__);               \
                                    continue;                            \
                                }                                        \
                                if ((rc) != CKR_OK) {                    \
                                    (rc) = CKR_DEVICE_ERROR;             \
                                    TRACE_ERROR("%s\n",                  \
                                             ock_err(ERR_DEVICE_ERROR)); \
                                    break;                               \
                                }                                        \
                                if ((blobsize2) > 0) {                   \
                                    (rc) = ep11tok_reencipher_blob(      \
                                               (tokdata), (session),     \
                                               &(target_info),           \
                                               (blob2),  (blobsize2),    \
                                               (reencblob2));            \
                                    if ((rc) ==                          \
                                            CKR_IBM_WK_NOT_INITIALIZED) {\
                                        /* Single APQN now has new WK,
                                           repeat key creation. */       \
                                        TRACE_DEVEL("%s WKID mismatch "  \
                                                "on reencipher, retry\n",\
                                                __func__);               \
                                        continue;                        \
                                    }                                    \
                                    if ((rc) != CKR_OK) {                \
                                        (rc) = CKR_DEVICE_ERROR;         \
                                        TRACE_ERROR("%s\n",              \
                                             ock_err(ERR_DEVICE_ERROR)); \
                                        break;                           \
                                    }                                    \
                                }                                        \
                            }                                            \
                        }                                                \
                        break;                                           \
                    } while (1);                                         \
                } while (0);

#endif
