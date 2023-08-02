/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef P11SAK_H_
#define P11SAK_H_

#include "pkcs11types.h"
#include "ec_curves.h"

#define P11SAK_DEFAULT_PKCS11_LIB           "libopencryptoki.so";
#define P11SAK_PKCSLIB_ENV_NAME             "PKCSLIB"
#define PKCS11_USER_PIN_ENV_NAME            "PKCS11_USER_PIN"
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

#define MAX_PRINT_LINE_LENGTH   80
#define PRINT_INDENT_POS        35

#define FIND_OBJECTS_COUNT      64
#define LIST_KEYTYPE_CELL_SIZE  22
#define LIST_CERTTYPE_CELL_SIZE  9
#define LIST_CERT_CN_CELL_SIZE  22

#define MAX_SYM_CLEAR_KEY_SIZE  64

enum p11sak_arg_type {
    ARG_TYPE_PLAIN = 0, /* no argument */
    ARG_TYPE_STRING = 1,
    ARG_TYPE_ENUM = 2,
    ARG_TYPE_NUMBER = 3,
};

struct p11sak_enum_value {
    const char *value;
    const struct p11sak_arg *args;
    union {
        const void *ptr;
        CK_ULONG num;
    } private;
    char **any_value; /* if this is not NULL then this enum value matches to
                         any string, and the string is set into any_value */
};

struct p11sak_arg {
    const char *name;
    enum p11sak_arg_type type;
    bool required;
    bool case_sensitive;
    const struct p11sak_enum_value *enum_values;
    union {
        bool *plain;
        char **string;
        struct p11sak_enum_value **enum_value;
        CK_ULONG *number;
    } value;
    bool (*is_set)(const struct p11sak_arg *arg);
    const char *description;
};

struct p11sak_opt {
    char short_opt; /* 0 if no short option is used */
    const char *long_opt; /* NULL if no long option */
    int long_opt_val; /* Used only if short_opt is 0 */
    bool required;
    struct p11sak_arg arg;
    const char *description;
};

struct p11sak_cmd {
    const char *cmd;
    const char *cmd_short1;
    const char *cmd_short2;
    CK_RV (*func)(void);
    const struct p11sak_opt *opts;
    const struct p11sak_arg *args;
    const char *description;
    void (*help)(void);
    CK_FLAGS session_flags;
};

struct p11sak_attr {
    const char *name;
    CK_ATTRIBUTE_TYPE type;
    char letter;
    bool secret;
    bool public;
    bool private;
    bool settable;
    void (*print_short)(const CK_ATTRIBUTE *val, bool applicable);
    void (*print_long)(const char *attr, const CK_ATTRIBUTE *val,
                       int indent, bool sensitive);
};

struct p11sak_objtype {
    const char *obj_typestr;
    const char *obj_liststr;
    const char *name;
    CK_ULONG type; /* CKA_KEY_TYPE or CKA_CERTIFICATE_TYPE */
    const char *ck_name;
    CK_MECHANISM keygen_mech;
    bool is_asymmetric;
    bool sign_verify;
    bool encrypt_decrypt;
    bool wrap_unwrap;
    bool derive;
    CK_RV (*keygen_prepare)(const struct p11sak_objtype *keytype,
                            void **private);
    void (*keygen_cleanup)(const struct p11sak_objtype *keytype, void *private);
    CK_RV (*keygen_get_key_size)(const struct p11sak_objtype *keytype,
                                 void *private, CK_ULONG *keysize);
    CK_RV (*keygen_add_secret_attrs)(const struct p11sak_objtype *keytype,
                                     CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     void *private);
    CK_RV (*keygen_add_public_attrs)(const struct p11sak_objtype *keytype,
                                     CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     void *private);
    CK_RV (*keygen_add_private_attrs)(const struct p11sak_objtype *keytype,
                                      CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                      void *private);
    CK_ATTRIBUTE_TYPE filter_attr;
    CK_ULONG filter_value;
    CK_ATTRIBUTE_TYPE keysize_attr;
    bool keysize_attr_value_len;
    CK_ULONG (*key_keysize_adjust)(const struct p11sak_objtype *keytype,
                                   CK_ULONG keysize);
    const struct p11sak_attr *secret_attrs;
    const struct p11sak_attr *public_attrs;
    const struct p11sak_attr *private_attrs;
    CK_RV (*import_check_sym_keysize)(const struct p11sak_objtype *keytype,
                                      CK_ULONG keysize);
    CK_RV (*import_sym_clear)(const struct p11sak_objtype *keytype,
                              CK_BYTE *data, CK_ULONG data_len,
                              CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
    CK_RV (*import_asym_pkey)(const struct p11sak_objtype *keytype,
                              EVP_PKEY *pkey, bool private,
                              CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
    CK_RV (*import_asym_pem_data)(const struct p11sak_objtype *keytype,
                                  unsigned char *data, size_t data_len,
                                  bool private, CK_ATTRIBUTE **attrs,
                                  CK_ULONG *num_attrs);
    CK_RV (*export_sym_clear)(const struct p11sak_objtype *keytype,
                              CK_BYTE **data, CK_ULONG* data_len,
                              CK_OBJECT_HANDLE key, const char *label);
    CK_RV (*export_asym_pkey)(const struct p11sak_objtype *keytype,
                              EVP_PKEY **pkey, bool private,
                              CK_OBJECT_HANDLE key, const char *label);
    CK_RV (*export_asym_pem_data)(const struct p11sak_objtype *keytype,
                                  unsigned char **data, size_t *data_len,
                                  bool private, CK_OBJECT_HANDLE key,
                                  const char *label);
    const char *pem_name_private;
    const char *pem_name_public;
    /* Following entries are for certificates */
    const struct p11sak_attr *cert_attrs;
    CK_RV (*import_x509_data)(const struct p11sak_objtype *certtype,
                              X509 *x509, CK_ATTRIBUTE **attrs,
                              CK_ULONG *num_attrs);
    CK_RV (*export_x509_data)(const struct p11sak_objtype *certtype,
                              unsigned char **data, size_t *data_len,
                              CK_OBJECT_HANDLE cert, const char *label);
    CK_RV (*extract_x509_pubkey)(const struct p11sak_objtype *certtype,
                                 CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                 CK_OBJECT_HANDLE cert, const char * label);
};

struct p11sak_class {
    const char *name;
    CK_OBJECT_CLASS class;
};

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

enum p11sak_objclass {
    OBJCLASS_KEY = 0,
    OBJCLASS_CERTIFICATE = 1,
};

struct p11sak_list_data {
    unsigned long num_displayed;
    CK_ATTRIBUTE *bool_attrs;
    CK_ULONG num_bool_attrs;
    enum p11sak_objclass objclass;
    const struct p11sak_attr *attrs;
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
#endif

#endif
