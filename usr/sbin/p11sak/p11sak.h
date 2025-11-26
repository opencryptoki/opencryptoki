/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2025
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef P11SAK_H_
#define P11SAK_H_

#include "p11tool.h"
#include "ec_curves.h"


#define PKCS11_PEM_PASSWORD_ENV_NAME        "PKCS11_PEM_PASSWORD"
#define P11SAK_DEFAULT_CONF_FILE_ENV_NAME   "P11SAK_DEFAULT_CONF_FILE"
#define P11SAK_CONFIG_FILE_NAME             "p11sak_defined_attrs.conf"
#define P11SAK_DEFAULT_CONFIG_FILE          OCK_CONFDIR "/" P11SAK_CONFIG_FILE_NAME

#define P11SAK_CONFIG_KEYWORD_ATTRIBUTE     "attribute"
#define P11SAK_CONFIG_KEYWORD_NAME          "name"
#define P11SAK_CONFIG_KEYWORD_ID            "id"
#define P11SAK_CONFIG_KEYWORD_TYPE          "type"

#define P11SAK_CONFIG_TYPE_BOOL             "CK_BBOOL"
#define P11SAK_CONFIG_TYPE_ULONG            "CK_ULONG"
#define P11SAK_CONFIG_TYPE_BYTE             "CK_BYTE"
#define P11SAK_CONFIG_TYPE_DATE             "CK_DATE"

#define UNUSED(var)             ((void)(var))

#define OPT_FORCE_PIN_PROMPT    256
#define OPT_DETAILED_URI        257
#define OPT_FORCE_PEM_PWD_PROMPT 258
#define OPT_SO                  259
#define OPT_URI_PIN_VALUE       260
#define OPT_URI_PIN_SOURCE      261
#define OPT_OQSPROVIDER_PEM     262
#define OPT_OAEP_HASH_ALG       263
#define OPT_OAEP_MGF_ALG        264
#define OPT_OAEP_SOURCE_DATA    265
#define OPT_AESKW_KEY_SIZE      266
#define OPT_ECDH_KDF_ALG        267
#define OPT_ECDH_SHARED_DATA    268

#define PRINT_INDENT_POS        35

#define FIND_OBJECTS_COUNT      64
#define LIST_KEYTYPE_CELL_SIZE  22
#define LIST_MKVP_MIN_CELL_SIZE 32
#define LIST_MKTYPE_MIN_CELL_SIZE 8
#define LIST_SESS_MIN_CELL_SIZE 16
#define LIST_CERTTYPE_CELL_SIZE  9
#define LIST_CERT_CN_CELL_SIZE  22

#define MAX_SYM_CLEAR_KEY_SIZE  64

#define PKCS11_URI_PEM_NAME     "PKCS#11 PROVIDER URI"
#define PKCS11_URI_DESCRIPTION  "PKCS#11 Provider URI v1.0"

struct p11sak_custom_attr_type {
    const char *type;
    void (*print_long)(const char *attr, const CK_ATTRIBUTE *val,
                       int indent, bool sensitive);
};

struct p11sak_iterate_compare_data {
    CK_RV (*compare_obj)(CK_OBJECT_HANDLE obj1,
                         CK_OBJECT_HANDLE obj2,
                         int *result,
                         void *private);
    void *private;
    CK_RV rc;
};

struct p11sak_remove_data {
    unsigned long num_removed;
    unsigned long num_skipped;
    unsigned long num_failed;
    bool remove_all;
    bool skip_all;
};

enum p11sak_sort_field {
    SORT_NONE = 0,
    SORT_LABEL = 1,
    SORT_KEYTYPE = 2,
    SORT_CLASS = 3,
    SORT_KEYSIZE = 4,
    SORT_CN = 5,
};

#define MAX_SORT_FIELDS     5

struct p11sak_sort_info {
    enum p11sak_sort_field field;
    bool descending;
};

struct p11sak_list_data {
    unsigned long num_displayed;
    CK_ATTRIBUTE *bool_attrs;
    CK_ULONG num_bool_attrs;
    enum p11tool_objclass objclass;
    const struct p11tool_attr *attrs;
    struct p11sak_sort_info sort_info[MAX_SORT_FIELDS];
};

struct p11sak_set_attr_data {
    unsigned long num_set;
    unsigned long num_skipped;
    unsigned long num_failed;
    bool set_all;
    bool skip_all;
};

struct p11sak_copy_data {
    unsigned long num_copied;
    unsigned long num_skipped;
    unsigned long num_failed;
    bool copy_all;
    bool skip_all;
};

struct p11sak_export_data {
    unsigned long num_exported;
    unsigned long num_skipped;
    unsigned long num_failed;
    bool export_all;
    bool skip_all;
    bool last_was_pem;
    bool last_was_binary;
};

struct curve_info {
    const CK_BYTE *oid;
    CK_ULONG oid_len;
    CK_ULONG bitsize;
};

#ifdef P11SAK_DECLARE_CURVES
static const CK_BYTE brainpoolP160r1[] = OCK_BRAINPOOL_P160R1;
static const CK_BYTE brainpoolP160t1[] = OCK_BRAINPOOL_P160T1;
static const CK_BYTE brainpoolP192r1[] = OCK_BRAINPOOL_P192R1;
static const CK_BYTE brainpoolP192t1[] = OCK_BRAINPOOL_P192T1;
static const CK_BYTE brainpoolP224r1[] = OCK_BRAINPOOL_P224R1;
static const CK_BYTE brainpoolP224t1[] = OCK_BRAINPOOL_P224T1;
static const CK_BYTE brainpoolP256r1[] = OCK_BRAINPOOL_P256R1;
static const CK_BYTE brainpoolP256t1[] = OCK_BRAINPOOL_P256T1;
static const CK_BYTE brainpoolP320r1[] = OCK_BRAINPOOL_P320R1;
static const CK_BYTE brainpoolP320t1[] = OCK_BRAINPOOL_P320T1;
static const CK_BYTE brainpoolP384r1[] = OCK_BRAINPOOL_P384R1;
static const CK_BYTE brainpoolP384t1[] = OCK_BRAINPOOL_P384T1;
static const CK_BYTE brainpoolP512r1[] = OCK_BRAINPOOL_P512R1;
static const CK_BYTE brainpoolP512t1[] = OCK_BRAINPOOL_P512T1;
static const CK_BYTE prime192v1[] = OCK_PRIME192V1;
static const CK_BYTE secp224r1[] = OCK_SECP224R1;
static const CK_BYTE prime256v1[] = OCK_PRIME256V1;
static const CK_BYTE secp384r1[] = OCK_SECP384R1;
static const CK_BYTE secp521r1[] = OCK_SECP521R1;
static const CK_BYTE secp256k1[] = OCK_SECP256K1;
static const CK_BYTE curve25519[] = OCK_CURVE25519;
static const CK_BYTE curve448[] = OCK_CURVE448;
static const CK_BYTE ed25519[] = OCK_ED25519;
static const CK_BYTE ed448[] = OCK_ED448;
static const CK_BYTE bls12_381[] = OCK_BLS12_381;
#endif

#define EP11_WKVP_OFFSET        32
#define EP11_SESSION_ID_OFFSET  0

struct cca_token_header {
    unsigned char id;
    unsigned char reserved1;
    unsigned short len;
    unsigned char version;
    unsigned char reserved2[3];
};

extern const struct p11tool_attr p11sak_bool_attrs[];

const struct p11tool_objtype *find_keytype(CK_KEY_TYPE ktype);

CK_RV iterate_objects(const struct p11tool_objtype *objtype,
                      const char *label_filter,
                      const char *id_filter,
                      const char *attr_filter,
                      enum p11tool_objclass objclass,
                      CK_RV (*compare_obj)(CK_OBJECT_HANDLE obj1,
                                           CK_OBJECT_HANDLE obj2,
                                           int *result,
                                           void *private),
                      CK_RV (*handle_obj)(CK_OBJECT_HANDLE obj,
                                          CK_OBJECT_CLASS class,
                                          const struct p11tool_objtype *objtype,
                                          CK_ULONG keysize,
                                          const char *typestr,
                                          const char* label,
                                          const char *common_name,
                                          void *private),
                      void *private);

struct p11sak_select_kek_data {
    CK_BBOOL prompt;
    CK_OBJECT_CLASS kek_class;
    CK_BBOOL cancel;
    CK_ULONG count;
    CK_OBJECT_HANDLE kek_handle;
};

struct p11sak_wrap_data {
    unsigned long num_wrapped;
    unsigned long num_skipped;
    unsigned long num_failed;
    bool wrap_all;
    bool skip_all;
    const struct p11sak_wrap_mech *wrap_mech;
    CK_OBJECT_HANDLE kek_handle;
    CK_MECHANISM mech;
    char *pem_header;
};

struct p11sak_wrap_mech {
    const char *name;
    CK_MECHANISM_TYPE mech;
    CK_ULONG mech_param_size;
    CK_BBOOL mech_param_optional;
    CK_OBJECT_CLASS wrap_class;
    CK_OBJECT_CLASS unwrap_class;
    CK_KEY_TYPE key_type;
    CK_RV (*prepare_mech_param_from_opts)(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech);
    CK_RV (*prepare_mech_param_from_pem)(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech, char **pem_headers);
    void (*cleanup_mech_param)(const struct p11sak_wrap_mech *wrap_mech,
                               CK_MECHANISM *mech);
    CK_RV (*prepare_pem_header)(const struct p11sak_wrap_mech *wrap_mech,
                                char **pem_header);
};

#define P11SAK_WRAP_PEM_NAME                  "P11SAK WRAPPED KEY"
#define P11SAK_WRAP_PEM_HDR_ALG               "WRAP-ALG"
#define P11SAK_WRAP_PEM_HDR_KEY_TYPE          "KEY-TYPE"
#define P11SAK_WRAP_PEM_HDR_IV                "IV"
#define P11SAK_WRAP_PEM_HDR_IV_ZERO           "00000000000000000000000000000000"
#define P11SAK_WRAP_PEM_HDR_IV_DEFAULT        "[default]"
#define P11SAK_WRAP_PEM_HDR_OAEP_HASH_ALG     "HASH-ALG"
#define P11SAK_WRAP_PEM_HDR_OAEP_MGF_ALG      "MGF-ALG"
#define P11SAK_WRAP_PEM_HDR_OAEP_SOURCE       "SOURCE-DATA"
#define P11SAK_WRAP_PEM_HDR_OAEP_SOURCE_NONE  "[none]"
#define P11SAK_WRAP_PEM_HDR_AES_KEY_SIZE      "AES-KEY-SIZE"
#define P11SAK_WRAP_PEM_HDR_ECDH_KDF_ALG      "KDF-ALG"
#define P11SAK_WRAP_PEM_HDR_ECDH_SHARED       "SHARED-DATA"
#define P11SAK_WRAP_PEM_HDR_ECDH_SHARED_NONE  "[none]"

extern CK_SLOT_ID opt_slot;
extern bool opt_so;
extern bool opt_force;
extern char *opt_label;
extern char *opt_attr;
extern char *opt_id;
extern char *opt_file;
extern char *opt_kek_label;
extern char *opt_kek_id;
extern bool opt_raw;
extern struct p11tool_enum_value *opt_wrap_mech;
extern struct p11tool_enum_value *opt_keytype;

extern const struct p11tool_enum_value p11sak_wrap_mech_values[];
extern const struct p11tool_objtype *p11sak_keytypes[];

CK_RV p11sak_wrap_key(void);
CK_RV p11sak_unwrap_key(void);

void print_wrap_key_help(void);
void print_unwrap_key_help(void);

#endif
