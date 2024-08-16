/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef P11KMIP_H_
#define P11KMIP_H_

#include "pkcs11types.h"
#include "ec_curves.h"
#include <kmipclient/kmipclient.h>

#define P11KMIP_DEFAULT_PKCS11_LIB           "libopencryptoki.so";
#define P11KMIP_CONFIG_FILE_NAME             "p11kmip.conf"
#define P11KMIP_DEFAULT_CONFIG_FILE          OCK_CONFDIR "/" P11KMIP_CONFIG_FILE_NAME
#define P11KMIP_SERVER_CERT_PATH             "/tmp/p11kmip-server-cert-tmp.pem"
#define P11KMIP_SERVER_PKEY_PATH             "/tmp/p11kmip-server-pubkey-tmp.pem"

#define P11KMIP_PKCSLIB_ENV_NAME             "PKCSLIB"
#define P11KMIP_CONF_FILE_ENV_NAME           "P11KMIP_CONF_FILE"
#define PKCS11_USER_PIN_ENV_NAME             "PKCS11_USER_PIN"
#define PKCS11_SLOT_ID_ENV_NAME              "PKCS11_SLOT_ID"
#define KMIP_HOSTNAME_ENV_NAME               "KMIP_HOSTNAME"
#define KMIP_CLIENT_CERT_ENV_NAME            "KMIP_CLIENT_CERT"
#define KMIP_CLIENT_KEY_ENV_NAME             "KMIP_CLIENT_KEY"
#define KMIP_PEM_PASSWORD_ENV_NAME           "KMIP_PEM_PASSWORD"

#define P11KMIP_CONFIG_KEYWORD_KMIP          "kmip"
#define P11KMIP_CONFIG_KEYWORD_PKCS11        "pkcs11"
#define P11KMIP_CONFIG_KEYWORD_HOST          "host"
#define P11KMIP_CONFIG_KEYWORD_PORT          "port"
#define P11KMIP_CONFIG_KEYWORD_CLIENT_CERT   "tls_client_cert"
#define P11KMIP_CONFIG_KEYWORD_CLIENT_KEY    "tls_client_key"
#define P11KMIP_CONFIG_KEYWORD_WRAP_KEY_FMT  "wrap_key_format"
#define P11KMIP_CONFIG_KEYWORD_WRAP_KEY_ALG  "wrap_key_algorithm"
#define P11KMIP_CONFIG_KEYWORD_WRAP_KEY_SIZE "wrap_key_size"
#define P11KMIP_CONFIG_KEYWORD_WRAP_PAD_MTHD "wrap_padding_method"
#define P11KMIP_CONFIG_KEYWORD_WRAP_HASH_ALG "wrap_hashing_algorithm"
#define P11KMIP_CONFIG_KEYWORD_PKCS_SLOT     "slot"

#define P11KMIP_CONFIG_VALUE_KEY_ALG_RSA     "RSA"
#define P11KMIP_CONFIG_VALUE_FMT_PKCS1       "PKCS1"
#define P11KMIP_CONFIG_VALUE_FMT_PKCS8       "PKCS8"
#define P11KMIP_CONFIG_VALUE_FMT_TRANSPARENT "TransparentPublicKey"
#define P11KMIP_CONFIG_VALUE_METHD_PKCS15    "PKCS1.5"
#define P11KMIP_CONFIG_VALUE_METHD_OAEP      "OAEP"
#define P11KMIP_CONFIG_VALUE_HSH_ALG_SHA_1   "SHA-1"
#define P11KMIP_CONFIG_VALUE_HSH_ALG_SHA_256 "SHA-256"

#define UNUSED(var)             ((void)(var))

#define OPT_FORCE_PIN_PROMPT    256
#define OPT_PEM_PASSWORD        257
#define OPT_FORCE_PEM_PWD_PROMPT 258
#define OPT_SEND_WRAPKEY        259
#define OPT_RETR_WRAPKEY        260
#define OPT_GEN_TARGKEY         261
#define OPT_KMIP_HOSTNAME       262
#define OPT_KMIP_CLIENT_CERT    263
#define OPT_KMIP_CLIENT_KEY     264
#define OPT_KMIP_PEM_PASSWORD   265
#define OPT_TLS_VERIFY_HOSTNAME 266
#define OPT_TLS_NO_VERIFY_CERT  267
#define OPT_TLS_TRUST_CERT      268
#define OPT_TARGKEY_ATTRS       269
#define OPT_TARGKEY_ID          270
#define OPT_TARGKEY_LEN         271
#define OPT_WRAPKEY_ATTRS       272
#define OPT_WRAPKEY_ID          273

#define MAX_PRINT_LINE_LENGTH   80
#define PRINT_INDENT_POS        45

#define FIND_OBJECTS_COUNT      64
#define LIST_KEYTYPE_CELL_SIZE  22

#define MAX_SYM_CLEAR_KEY_SIZE  64

#define P11KMIP_DEFAULT_AES_KEY_LENGTH 32

/* CLI Struct definitions */

enum p11kmip_arg_type {
    ARG_TYPE_PLAIN = 0,         /* no argument */
    ARG_TYPE_STRING = 1,
    ARG_TYPE_ENUM = 2,
    ARG_TYPE_NUMBER = 3,
};

struct p11kmip_enum_value {
    const char *value;
    const struct p11kmip_arg *args;
    union {
        const void *ptr;
        CK_ULONG num;
    } private;
    char **any_value;           /* if this is not NULL then this enum value matches to
                                   any string, and the string is set into any_value */
};

struct p11kmip_arg {
    const char *name;
    enum p11kmip_arg_type type;
    bool required;
    bool case_sensitive;
    const struct p11kmip_enum_value *enum_values;
    union {
        bool *plain;
        char **string;
        struct p11kmip_enum_value **enum_value;
        CK_ULONG *number;
    } value;
    bool (*is_set)(const struct p11kmip_arg * arg);
    const char *description;
};

struct p11kmip_opt {
    char short_opt;             /* 0 if no short option is used */
    const char *long_opt;       /* NULL if no long option */
    int long_opt_val;           /* Used only if short_opt is 0 */
    bool required;
    struct p11kmip_arg arg;
    const char *description;
};

struct p11kmip_cmd {
    const char *cmd;
    const char *cmd_short1;
    const char *cmd_short2;
     CK_RV(*func) (void);
    const struct p11kmip_opt *opts;
    const struct p11kmip_arg *args;
    const char *description;
    void (*help)(void);
    CK_FLAGS session_flags;
};

struct p11kmip_attr {
    const char *name;
    CK_ATTRIBUTE_TYPE type;
    char letter;
    bool secret;
    bool public;
    bool private;
    bool settable;
    void (*print_short)(const CK_ATTRIBUTE * val, bool applicable);
    void (*print_long)(const char *attr, const CK_ATTRIBUTE * val,
                       int indent, bool sensitive);
};

/* Key object struct definitions */
struct p11kmip_keytype {
    const char *name;
    CK_KEY_TYPE type;
    CK_OBJECT_CLASS class;
    const char *ckk_name;
    CK_MECHANISM keygen_mech;
    bool is_asymmetric;
    bool sign_verify;
    bool encrypt_decrypt;
    bool wrap_unwrap;
    bool derive;
     CK_RV(*keygen_prepare) (const struct p11kmip_keytype * keytype,
                             void **private);
    void (*keygen_cleanup)(const struct p11kmip_keytype * keytype,
                           void *private);
     CK_RV(*keygen_get_key_size) (const struct p11kmip_keytype * keytype,
                                  void *private, CK_ULONG * keysize);
     CK_RV(*keygen_add_secret_attrs) (const struct p11kmip_keytype * keytype,
                                      CK_ATTRIBUTE ** attrs,
                                      CK_ULONG * num_attrs, void *private);
     CK_RV(*keygen_add_public_attrs) (const struct p11kmip_keytype * keytype,
                                      CK_ATTRIBUTE ** attrs,
                                      CK_ULONG * num_attrs, void *private);
     CK_RV(*keygen_add_private_attrs) (const struct p11kmip_keytype * keytype,
                                       CK_ATTRIBUTE ** attrs,
                                       CK_ULONG * num_attrs, void *private);
    CK_ATTRIBUTE_TYPE filter_attr;
    CK_ULONG filter_value;
    CK_ATTRIBUTE_TYPE keysize_attr;
    CK_ULONG keysize_value;
    bool keysize_attr_value_len;
     CK_ULONG(*key_keysize_adjust) (const struct p11kmip_keytype * keytype,
                                    CK_ULONG keysize);
    const struct p11kmip_attr *secret_attrs;
    const struct p11kmip_attr *public_attrs;
    const struct p11kmip_attr *private_attrs;
     CK_RV(*import_check_sym_keysize) (const struct p11kmip_keytype * keytype,
                                       CK_ULONG keysize);
     CK_RV(*import_sym_clear) (const struct p11kmip_keytype * keytype,
                               CK_BYTE * data, CK_ULONG data_len,
                               CK_ATTRIBUTE ** attrs, CK_ULONG * num_attrs);
     CK_RV(*import_asym_pkey) (const struct p11kmip_keytype * keytype,
                               EVP_PKEY * pkey, bool private,
                               CK_ATTRIBUTE ** attrs, CK_ULONG * num_attrs);
     CK_RV(*import_asym_pem_data) (const struct p11kmip_keytype * keytype,
                                   unsigned char *data, size_t data_len,
                                   bool private, CK_ATTRIBUTE ** attrs,
                                   CK_ULONG * num_attrs);
     CK_RV(*export_sym_clear) (const struct p11kmip_keytype * keytype,
                               CK_BYTE ** data, CK_ULONG * data_len,
                               CK_OBJECT_HANDLE key, const char *label);
     CK_RV(*export_asym_pkey) (const struct p11kmip_keytype * keytype,
                               EVP_PKEY ** pkey, bool private,
                               CK_OBJECT_HANDLE key, const char *label);
     CK_RV(*export_asym_pem_data) (const struct p11kmip_keytype * keytype,
                                   unsigned char **data, size_t *data_len,
                                   bool private, CK_OBJECT_HANDLE key,
                                   const char *label);
    const char *pem_name_private;
    const char *pem_name_public;
};

struct p11kmip_class {
    const char *name;
    CK_OBJECT_CLASS class;
};

struct p11kmip_custom_attr_type {
    const char *type;
    void (*print_long)(const char *attr, const CK_ATTRIBUTE * val,
                       int indent, bool sensitive);
};

#define P11KMIP_P11_UNKNOWN_ALG                   0xFFFFFFFF
#define P11KMIP_KMIP_UNKNOWN_ALG                  0xFF
#define P11KMIP_KMIP_TO_P11_ALG_TABLE_LENGTH      14
#define P11KMIP_P11_TO_KMIP_ALG_TABLE_LENGTH      32

const CK_KEY_TYPE P11KMIP_KMIP_TO_P11_ALG_TABLE[] = {
    P11KMIP_P11_UNKNOWN_ALG,
    CKK_DES,
    CKK_DES3,
    CKK_AES,
    CKK_RSA,
    CKK_DSA,
    CKK_ECDSA,
    P11KMIP_P11_UNKNOWN_ALG,    // KMIP_CRYPTO_ALGO_HMAC_SHA1
    P11KMIP_P11_UNKNOWN_ALG,    // KMIP_CRYPTO_ALGO_HMAC_SHA224
    P11KMIP_P11_UNKNOWN_ALG,    // KMIP_CRYPTO_ALGO_HMAC_SHA256
    P11KMIP_P11_UNKNOWN_ALG,    // KMIP_CRYPTO_ALGO_HMAC_SHA384
    P11KMIP_P11_UNKNOWN_ALG,    // KMIP_CRYPTO_ALGO_HMAC_SHA512
    P11KMIP_P11_UNKNOWN_ALG,    // KMIP_CRYPTO_ALGO_HMAC_MD5
    CKK_DH
};

const enum kmip_crypto_algo P11KMIP_P11_TO_KMIP_ALG_TABLE[] = {
    KMIP_CRYPTO_ALGO_RSA,
    KMIP_CRYPTO_ALGO_DSA,
    KMIP_CRYPTO_ALGO_DH,
    KMIP_CRYPTO_ALGO_EC,
    P11KMIP_KMIP_UNKNOWN_ALG,   // CKK_X9_42_DH
    P11KMIP_KMIP_UNKNOWN_ALG,   // CKK_KEA
    P11KMIP_KMIP_UNKNOWN_ALG,   // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG,   // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG,   // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG,   // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG,   // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG,   // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG,   // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG,   // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG,   // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG,   // Undefined
    P11KMIP_KMIP_UNKNOWN_ALG,   // CKK_GENERIC_SECRET
    KMIP_CRYPTO_ALGO_RC2,
    KMIP_CRYPTO_ALGO_RC4,
    KMIP_CRYPTO_ALGO_DES,
    P11KMIP_KMIP_UNKNOWN_ALG,   // CKK_DES2
    KMIP_CRYPTO_ALGO_3DES,
    P11KMIP_KMIP_UNKNOWN_ALG,   // CKK_CAST
    P11KMIP_KMIP_UNKNOWN_ALG,   // CKK_CAST3
    KMIP_CRYPTO_ALGO_CAST5,
    KMIP_CRYPTO_ALGO_RC5,
    KMIP_CRYPTO_ALGO_IDEA,
    KMIP_CRYPTO_ALGO_SKIPJACK,
    P11KMIP_KMIP_UNKNOWN_ALG,   // CKK_BATON
    P11KMIP_KMIP_UNKNOWN_ALG,   // CKK_JUNIPER
    P11KMIP_KMIP_UNKNOWN_ALG,   // CKK_CDMF
    KMIP_CRYPTO_ALGO_AES
};

#define P11KMIP_P11_UNKNOWN_OBJ                0xFFFFFFFF
#define P11KMIP_KMIP_UNKNOWN_OBJ               0xFF
#define P11KMIP_KMIP_TO_P11_OBJ_TABLE_LENGTH   10
#define P11KMIP_P11_TO_KMIP_OBJ_TABLE_LENGTH   10

const CK_OBJECT_CLASS P11KMIP_KMIP_TO_P11_OBJ_TABLE[] = {
    P11KMIP_P11_UNKNOWN_OBJ,    // Undefined
    CKO_CERTIFICATE,
    CKO_SECRET_KEY,
    CKO_PUBLIC_KEY,
    CKO_PRIVATE_KEY,
    P11KMIP_P11_UNKNOWN_OBJ,    // KMIP_OBJECT_TYPE_SPLIT_KEY
    P11KMIP_P11_UNKNOWN_OBJ,    // KMIP_OBJECT_TYPE_TEMPLATE
    P11KMIP_P11_UNKNOWN_OBJ,    // KMIP_OBJECT_TYPE_SECRET_DATA
    P11KMIP_P11_UNKNOWN_OBJ,    // KMIP_OBJECT_TYPE_OPAQUE_OBJECT
    P11KMIP_P11_UNKNOWN_OBJ,    // KMIP_OBJECT_TYPE_PGP_KEY
    P11KMIP_P11_UNKNOWN_OBJ     // KMIP_OBJECT_TYPE_CERTIFICATE_REQUEST
};

const enum kmip_object_type P11KMIP_P11_TO_KMIP_OBJ_TABLE[] = {
    P11KMIP_KMIP_UNKNOWN_OBJ,   // CKO_DATA
    KMIP_OBJECT_TYPE_CERTIFICATE,
    KMIP_OBJECT_TYPE_PUBLIC_KEY,
    KMIP_OBJECT_TYPE_PRIVATE_KEY,
    KMIP_OBJECT_TYPE_SYMMETRIC_KEY,
    P11KMIP_KMIP_UNKNOWN_OBJ,   // CKO_HW_FEATURE
    P11KMIP_KMIP_UNKNOWN_OBJ,   // CKO_DOMAIN_PARAMETERS
    P11KMIP_KMIP_UNKNOWN_OBJ,   // Undefined
    P11KMIP_KMIP_UNKNOWN_OBJ,   // Undefined
    P11KMIP_KMIP_UNKNOWN_OBJ,   // Undefined
    P11KMIP_KMIP_UNKNOWN_OBJ    // CKO_PROFILE
};

#define P11KMIP_P11_UNKNOWN_HASH               0xFFFFFFFF
#define P11KMIP_KMIP_TO_P11_HASH_TABLE_LENGTH  18

const CK_MECHANISM_TYPE P11KMIP_KMIP_TO_P11_HASH_TABLE[] = {
    P11KMIP_P11_UNKNOWN_HASH,   // kmip_hashing_algo enums are 1-indexed
    CKM_MD2,
    P11KMIP_P11_UNKNOWN_HASH,   //MD4
    CKM_MD5,
    CKM_SHA_1,
    CKM_SHA224,
    CKM_SHA256,
    CKM_SHA384,
    CKM_SHA512,
    CKM_RIPEMD160,
    P11KMIP_P11_UNKNOWN_HASH,   // TIGER
    P11KMIP_P11_UNKNOWN_HASH,   //WHIRLPOOL
    CKM_SHA512_224,
    CKM_SHA512_256,
    CKM_SHA3_224,
    CKM_SHA3_256,
    CKM_SHA3_384,
    CKM_SHA3_512,
};

struct kmip_enum_name {
    uint32_t value;
    const char *name;
};

static const struct kmip_enum_name required_operations[] = {
    {.value = KMIP_OPERATION_QUERY,.name = "Query"},
    {.value = KMIP_OPERATION_CREATE,.name = "Create"},
    {.value = KMIP_OPERATION_REGISTER,.name = "Register"},
    {.value = KMIP_OPERATION_ACTIVATE,.name = "Activate"},
    {.value = KMIP_OPERATION_REVOKE,.name = "Revoke"},
    {.value = KMIP_OPERATION_DESTROY,.name = "Destroy"},
    {.value = KMIP_OPERATION_GET,.name = "Get"},
    {.value = KMIP_OPERATION_LOCATE,.name = "Locate"},
    {.value = KMIP_OPERATION_GET_ATTRIBUTE_LIST,
     .name = "Get Attribute List"},
    {.value = KMIP_OPERATION_GET_ATTRIBUTES,
     .name = "Get Attributes"},
    {.value = KMIP_OPERATION_ADD_ATTRIBUTE,
     .name = "Add Attribute"},
    {.value = KMIP_OPERATION_DELETE_ATTRIBUTE,
     .name = "Delete Attribute"},
    {.value = 0,.name = NULL},
};

static const struct kmip_enum_name required_objtypes[] = {
    {.value = KMIP_OBJECT_TYPE_SYMMETRIC_KEY,.name = "Symmetric Key"},
    {.value = KMIP_OBJECT_TYPE_PUBLIC_KEY,.name = "Public Key"},
    {.value = 0,.name = NULL},
};

static const struct kmip_version kmip_version_1_0 = {
    .major = 1,.minor = 0,
};

static const struct kmip_version kmip_version_1_2 = {
    .major = 1,.minor = 2,
};

static const struct kmip_enum_name kmip_result_statuses[] = {
    {.value = KMIP_RESULT_STATUS_SUCCESS,.name = "Success"},
    {.value = KMIP_RESULT_STATUS_OPERATION_FAILED,
     .name = "Operation Failed"},
    {.value = KMIP_RESULT_STATUS_OPERATION_PENDING,
     .name = "Operation Pending"},
    {.value = KMIP_RESULT_STATUS_OPERATION_UNDONE,
     .name = "Operation Undone"},
    {.value = 0,.name = NULL},
};

static const struct kmip_enum_name kmip_result_reasons[] = {
    {.value = KMIP_RESULT_REASON_ITEM_NOT_FOUND,
     .name = "Item Not Found"},
    {.value = KMIP_RESULT_REASON_RESPONSE_TOO_LARGE,
     .name = "Response Too Large"},
    {.value = KMIP_RESULT_REASON_AUTH_NOT_SUCCESSFUL,
     .name = "Authentication Not Successful"},
    {.value = KMIP_RESULT_REASON_INVALID_MESSAGE,
     .name = "Invalid Message"},
    {.value = KMIP_RESULT_REASON_OPERATION_NOT_SUCCESSFUL,
     .name = "Operation Not Supported"},
    {.value = KMIP_RESULT_REASON_MISSING_DATA,.name = "Missing Data"},
    {.value = KMIP_RESULT_REASON_INVALIUD_FIELD,.name = "Invalid Field"},
    {.value = KMIP_RESULT_REASON_FEATURE_NOT_SUPPORTED,
     .name = "Feature Not Supported"},
    {.value = KMIP_RESULT_REASON_OP_CANCELED_BY_REQUESTOR,
     .name = "Operation Canceled By Requeste"},
    {.value = KMIP_RESULT_REASON_CRYPTOGRAPHIC_FAILURE,
     .name = "Cryptographic Failure"},
    {.value = KMIP_RESULT_REASON_ILLEGAL_OPERATION,
     .name = "Illegal Operation"},
    {.value = KMIP_RESULT_REASON_PERMISSION_DENIED,
     .name = "Permission Denied"},
    {.value = KMIP_RESULT_REASON_OBJECT_ARCHIVED,
     .name = "Object Archived"},
    {.value = KMIP_RESULT_REASON_INDEX_OUT_OF_BOUNDS,
     .name = "Index Out Of Bounds"},
    {.value = KMIP_RESULT_REASON_APP_NAMESPACE_NOT_SUPPORTED,
     .name = "Application Namespace Not Supported"},
    {.value = KMIP_RESULT_REASON_KEY_FORMAT_TYPE_NOT_SUPPORTED,
     .name = "Key Format Type Not Supported"},
    {.value = KMIP_RESULT_REASON_KEY_COMPRESSION_TYPE_NOT_SUPPORTED,
     .name = "Key Compression Type Not Supported"},
    {.value = KMIP_RESULT_REASON_ENCODING_OPTION_ERROR,
     .name = "Encoding Option Error"},
    {.value = KMIP_RESULT_REASON_KEY_VALUE_NOT_PRESENT,
     .name = "Key Value Not Present"},
    {.value = KMIP_RESULT_REASON_ATTESTATION_REQUIRED,
     .name = "Attestation Required"},
    {.value = KMIP_RESULT_REASON_ATTESTATION_FAILED,
     .name = "Attestation Failed"},
    {.value = KMIP_RESULT_REASON_SENSITIVE,.name = "Sensitive"},
    {.value = KMIP_RESULT_REASON_NOT_EXTRACTABLE,
     .name = "Not Extractable"},
    {.value = KMIP_RESULT_REASON_OBJECT_ALREADY_EXISTS,
     .name = "Object Already Exists"},
    {.value = KMIP_RESULT_REASON_INVALID_TICKET,
     .name = "Invalid Ticket"},
    {.value = KMIP_RESULT_REASON_USAGE_LIMIT_EXCEEDED,
     .name = "Usage Limit Exceeded"},
    {.value = KMIP_RESULT_REASON_NUMERIC_RANGE,.name = "Numeric Range"},
    {.value = KMIP_RESULT_REASON_INVALID_DATA_TYPE,
     .name = "Invalid Data Type"},
    {.value = KMIP_RESULT_REASON_READ_ONLY_ATTRIBUTE,
     .name = "Read Only Attribute"},
    {.value = KMIP_RESULT_REASON_MULTI_VALUED_ATTRIBUTE,
     .name = "Multi Valued Attribute"},
    {.value = KMIP_RESULT_REASON_UNSUPPORTED_ATTRIBUTE,
     .name = "Unsupported Attribute"},
    {.value = KMIP_RESULT_REASON_ATTRIBUTE_INSTANCE_NOT_FOUND,
     .name = "Attribute Instance Not Found"},
    {.value = KMIP_RESULT_REASON_ATTRIBUTE_NOT_FOUND,
     .name = "Attribute Not Found"},
    {.value = KMIP_RESULT_REASON_ATTRIBUTE_READ_ONLY,
     .name = "Attribute Read Only"},
    {.value = KMIP_RESULT_REASON_ATTRIBUTE_SINGLE_VALUED,
     .name = "Attribute Single Valued"},
    {.value = KMIP_RESULT_REASON_BAD_CRYPTOGRAPHIC_PARAMETERS,
     .name = "Bad Cryptographic Parameters"},
    {.value = KMIP_RESULT_REASON_BAD_PASSWORD,.name = "Bad Password"},
    {.value = KMIP_RESULT_REASON_CODEC_ERROR,.name = "Codec Error"},
    {.value = KMIP_RESULT_REASON_ILLEGAL_OBJECT_TYPE,
     .name = "Illegal Object Type"},
    {.value = KMIP_RESULT_REASON_INCOMPATIBLE_CRYPTO_USAGE_MASK,
     .name = "Incompatible Cryptographic Usage Mask"},
    {.value = KMIP_RESULT_REASON_INTERNAL_SERVER_ERROR,
     .name = "Internal Server Error"},
    {.value = KMIP_RESULT_REASON_INVALID_ASYNC_CORRELATION_VALUE,
     .name = "Invalid Asynchronous Correlation Value"},
    {.value = KMIP_RESULT_REASON_INVALID_ATTRIBUTE,
     .name = "Invalid Attribute"},
    {.value = KMIP_RESULT_REASON_INVALID_ATTRIBUTE_VALUE,
     .name = "Invalid Attribute Value"},
    {.value = KMIP_RESULT_REASON_INVALID_CORRELATION_VALUE,
     .name = "Invalid Correlation Value"},
    {.value = KMIP_RESULT_REASON_INVALID_CSR,.name = "Invalid CSR"},
    {.value = KMIP_RESULT_REASON_INVALID_OBJECT_TYPE,
     .name = "Invalid Object Type"},
    {.value = KMIP_RESULT_REASON_KEY_WRAP_TYPE_NOT_SUPPORTED,
     .name = "Key Wrap Type Not Supported"},
    {.value = KMIP_RESULT_REASON_MISSING_INITIALIZATION_VECTOR,
     .name = "Missing Initialization Vector"},
    {.value = KMIP_RESULT_REASON_NOT_UNIQUE_NAME_ATTRIBUTE,
     .name = "Non Unique Name Attribute"},
    {.value = KMIP_RESULT_REASON_OBJECT_DESTROYED,
     .name = "Object Destroyed"},
    {.value = KMIP_RESULT_REASON_OBJECT_NOT_FOUND,
     .name = "Object Not Found"},
    {.value = KMIP_RESULT_REASON_NOT_AUTHORISED,
     .name = "Not Authorised"},
    {.value = KMIP_RESULT_REASON_SERVER_LIMIT_EXCEEDED,
     .name = "Server Limit Exceeded"},
    {.value = KMIP_RESULT_REASON_UNKNOWN_ENUMERATION,
     .name = "Unknown Enumeration"},
    {.value = KMIP_RESULT_REASON_UNKNOWN_MESSAGE_EXTENSION,
     .name = "Unknown Message Extension"},
    {.value = KMIP_RESULT_REASON_UNKNOWN_TAG,.name = "Unknown Tag"},
    {.value = KMIP_RESULT_REASON_UNSUPPORTED_CRYPTO_PARAMETERS,
     .name = "Unsupported Cryptographic Parameters"},
    {.value = KMIP_RESULT_REASON_UNSUPPORTED_PROTOCOL_VERSION,
     .name = "Unsupported Protocol Version"},
    {.value = KMIP_RESULT_REASON_WRAPPING_OBJECT_ARCHIVED,
     .name = "Wrapping Object Archived"},
    {.value = KMIP_RESULT_REASON_WRAPPING_OBJECT_DESTROYED,
     .name = "Wrapping Object Destroyed"},
    {.value = KMIP_RESULT_REASON_WRAPPING_OBJECT_NOT_FOUND,
     .name = "Wrapping Object Not Found"},
    {.value = KMIP_RESULT_REASON_WRONG_KEY_LIFECYCLE_STATE,
     .name = "Wrong Key Lifecycle State"},
    {.value = KMIP_RESULT_REASON_PROTECTION_STORAGE_UNAVAILABLE,
     .name = "Protection Storage Unavailable"},
    {.value = KMIP_RESULT_REASON_PKCS_11_CODE_ERROR,
     .name = "PKCS#11 Codec Error"},
    {.value = KMIP_RESULT_REASON_PKCS_11_INVALID_FUNCTION,
     .name = "PKCS#11 Invalid Function"},
    {.value = KMIP_RESULT_REASON_PKCS_11_INVALID_INTERFACE,
     .name = "PKCS#11 Invalid Interface"},
    {.value = KMIP_RESULT_REASON_PRIVATE_PROT_STORAGE_UNAVAILABLE,
     .name = "Private Protection Storage Unavailable"},
    {.value = KMIP_RESULT_REASON_PUBLIC_PROT_STORAGE_UNAVAILABLE,
     .name = "Public Protection Storage Unavailable"},
    {.value = KMIP_RESULT_REASON_UNKNOWN_OBJECT_GROUP,
     .name = "Unknown Object Group"},
    {.value = KMIP_RESULT_REASON_CONSTRAINT_VIOLATION,
     .name = "Constraint Violation"},
    {.value = KMIP_RESULT_REASON_DUPLICATE_PROCESS_REQUEST,
     .name = "Duplicate Process Request"},
    {.value = KMIP_RESULT_REASON_GENERAL_FAILURE,
     .name = "General Failure"},
    {.value = 0,.name = NULL},
};

#define print_hex(x, y) \
        do { \
            unsigned char *hex = x; \
            int i; \
            for (i = 0; i < y; i++) { \
                printf("%02x", hex[i]); \
            } \
        } while (0)


#endif
