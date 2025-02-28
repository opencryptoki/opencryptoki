/*
 * COPYRIGHT (c) International Business Machines Corp. 2025
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#ifndef P11TOOL_H_
#define P11TOOL_H_

#include "platform.h"

#if !defined(_AIX)
    #include <linux/limits.h>
#endif /* _AIX */

#include "pkcs11types.h"
#include "defs.h"
#include "uri.h"

#define UNUSED(var)             ((void)(var))

#define P11TOOL_DEFAULT_PKCS11_LIB           OCK_API_LIBNAME;
#define P11TOOL_PKCSLIB_ENV_NAME             "PKCSLIB"
#define PKCS11_USER_PIN_ENV_NAME             "PKCS11_USER_PIN"
#define PKCS11_SO_PIN_ENV_NAME               "PKCS11_SO_PIN"

#define MAX_PRINT_LINE_LENGTH   80

enum p11tool_arg_type {
    ARG_TYPE_PLAIN = 0, /* no argument */
    ARG_TYPE_STRING = 1,
    ARG_TYPE_ENUM = 2,
    ARG_TYPE_NUMBER = 3,
};

struct p11tool_enum_value {
    const char *value;
    const struct p11tool_arg *args;
    union {
        const void *ptr;
        CK_ULONG num;
    } private;
    char **any_value; /* if this is not NULL then this enum value matches to
                         any string, and the string is set into any_value */
};

struct p11tool_arg {
    const char *name;
    enum p11tool_arg_type type;
    bool required;
    bool case_sensitive;
    const struct p11tool_enum_value *enum_values;
    union {
        bool *plain;
        char **string;
        struct p11tool_enum_value **enum_value;
        CK_ULONG *number;
    } value;
    bool (*is_set)(const struct p11tool_arg *arg);
    const char *description;
};

struct p11tool_opt {
    char short_opt; /* 0 if no short option is used */
    const char *long_opt; /* NULL if no long option */
    int long_opt_val; /* Used only if short_opt is 0 */
    bool required;
    struct p11tool_arg arg;
    const char *description;
};

struct p11tool_cmd {
    const char *cmd;
    const char *cmd_short1;
    const char *cmd_short2;
    CK_RV (*func)(void);
    const struct p11tool_opt *opts;
    const struct p11tool_arg *args;
    const char *description;
    void (*help)(void);
    CK_FLAGS session_flags;
};

struct p11tool_attr {
    const char *name;
    CK_ATTRIBUTE_TYPE type;
    char letter;
    bool secret;
    bool public;
    bool private;
    bool settable;
    bool so_set_to_true; /* can only be set to TRUE by SO */
    void (*print_short)(const CK_ATTRIBUTE *val, bool applicable);
    void (*print_long)(const char *attr, const CK_ATTRIBUTE *val,
                       int indent, bool sensitive);
};

#define DECLARE_BOOL_ATTR(attr, ch, sec, pub, priv, set)                       \
    { .name = # attr, .type = attr, .letter = ch,                              \
      .secret = sec, .public = pub, .private = priv,                           \
      .settable = set, .print_short = p11tool_print_bool_attr_short,           \
      .print_long = p11tool_print_bool_attr_long, }

#define DECLARE_BOOL_ATTR_SO(attr, ch, sec, pub, priv, set, so_set_true)       \
    { .name = # attr, .type = attr, .letter = ch,                              \
      .secret = sec, .public = pub, .private = priv,                           \
      .settable = set, .so_set_to_true = so_set_true,                          \
      .print_short = p11tool_print_bool_attr_short,                            \
      .print_long = p11tool_print_bool_attr_long, }

struct p11tool_objtype {
    const char *obj_typestr;
    const char *obj_liststr;
    const char *name;
    CK_ULONG type; /* CK_KEY_TYPE or CK_CERTIFICATE_TYPE */
    const char *ck_name;
    int pkey_type; /* OpenSSL PKEY_xxx type or 0 if not applicable */
    bool supports_oqsprovider_pem;
    CK_MECHANISM keygen_mech;
    bool is_asymmetric;
    bool sign_verify;
    bool encrypt_decrypt;
    bool wrap_unwrap;
    bool derive;
    CK_RV (*keygen_prepare)(const struct p11tool_objtype *keytype,
                            void **private);
    void (*keygen_cleanup)(const struct p11tool_objtype *keytype,
                           void *private);
    CK_RV (*keygen_get_key_size)(const struct p11tool_objtype *keytype,
                                 void *private, CK_ULONG *keysize);
    CK_RV (*keygen_add_secret_attrs)(const struct p11tool_objtype *keytype,
                                     CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     void *private);
    CK_RV (*keygen_add_public_attrs)(const struct p11tool_objtype *keytype,
                                     CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     void *private);
    CK_RV (*keygen_add_private_attrs)(const struct p11tool_objtype *keytype,
                                      CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                      void *private);
    CK_ATTRIBUTE_TYPE filter_attr;
    CK_ULONG filter_value;
    CK_ATTRIBUTE_TYPE keysize_attr;

    CK_ULONG keysize_value;

    bool keysize_attr_value_len;
    CK_ULONG (*key_keysize_adjust)(const struct p11tool_objtype *keytype,
                                   CK_ULONG keysize);
    const struct p11tool_attr *secret_attrs;
    const struct p11tool_attr *public_attrs;
    const struct p11tool_attr *private_attrs;
    CK_RV (*import_check_sym_keysize)(const struct p11tool_objtype *keytype,
                                      CK_ULONG keysize);
    CK_RV (*import_sym_clear)(const struct p11tool_objtype *keytype,
                              CK_BYTE *data, CK_ULONG data_len,
                              CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
    CK_RV (*import_asym_pkey)(const struct p11tool_objtype *keytype,
                              EVP_PKEY *pkey, bool private,
                              CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
    CK_RV (*import_asym_pem_data)(const struct p11tool_objtype *keytype,
                                  unsigned char *data, size_t data_len,
                                  bool private, CK_ATTRIBUTE **attrs,
                                  CK_ULONG *num_attrs);
    CK_RV (*export_sym_clear)(const struct p11tool_objtype *keytype,
                              CK_BYTE **data, CK_ULONG* data_len,
                              CK_OBJECT_HANDLE key, const char *label);
    CK_RV (*export_asym_pkey)(const struct p11tool_objtype *keytype,
                              EVP_PKEY **pkey, bool private,
                              CK_OBJECT_HANDLE key, const char *label);
    CK_RV (*export_asym_pem_data)(const struct p11tool_objtype *keytype,
                                  CK_BYTE **data, CK_ULONG *data_len,
                                  bool private, CK_OBJECT_HANDLE key,
                                  const char *label);
    const char *pem_name_private;
    const char *pem_name_public;
    /* Following entries are for certificates */
    const struct p11tool_attr *cert_attrs;
    CK_RV (*import_x509_data)(const struct p11tool_objtype *certtype,
                              X509 *x509, CK_ATTRIBUTE **attrs,
                              CK_ULONG *num_attrs);
    CK_RV (*export_x509_data)(const struct p11tool_objtype *certtype,
                              CK_BYTE **data, CK_ULONG *data_len,
                              CK_OBJECT_HANDLE cert, const char *label);
    CK_RV (*extract_x509_pubkey)(const struct p11tool_objtype *certtype,
                                 CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                 CK_OBJECT_HANDLE cert, const char * label);
};

struct p11tool_class {
    const char *name;
    CK_OBJECT_CLASS class;
};

enum p11tool_objclass {
    OBJCLASS_KEY = 0,
    OBJCLASS_CERTIFICATE = 1,
};

enum p11tool_token_type {
    TOKTYPE_UNKNOWN = 0,
    TOKTYPE_CCA = 1,
    TOKTYPE_EP11 = 2,
};

struct p11tool_token_info {
    enum p11tool_token_type type;
    const char *manufacturer;
    const char *model;
    unsigned int mkvp_size;
    unsigned int mktype_cell_size;
    CK_ATTRIBUTE_TYPE secure_key_attr;
    void (*print_mkvp_long)(const struct p11tool_token_info *info,
                            const CK_BYTE *secure_key,
                            CK_ULONG secure_key_len,
                            int indent);
    void (*print_mkvp_short)(const struct p11tool_token_info *info,
                             const CK_BYTE *secure_key,
                             CK_ULONG secure_key_len,
                             const char *separator);
};

extern void *p11tool_pkcs11_lib;
extern bool p11tool_pkcs11_initialized;
extern CK_FUNCTION_LIST *p11tool_pkcs11_funcs;
extern CK_SESSION_HANDLE p11tool_pkcs11_session;
extern CK_INFO p11tool_pkcs11_info;
extern CK_TOKEN_INFO p11tool_pkcs11_tokeninfo;
extern const struct p11tool_token_info *p11tool_token_info;
extern CK_SLOT_INFO p11tool_pkcs11_slotinfo;
extern char *p11tool_pin;

extern const struct p11tool_class p11tool_classes[];
extern const struct p11tool_enum_value p11tool_ibm_dilithium_versions[];
extern const struct p11tool_enum_value p11tool_ibm_kyber_versions[];

const struct p11tool_cmd *p11tool_find_command(const struct p11tool_cmd *cmds,
                                               const char *cmd);
CK_RV p11tool_parse_cmd_arguments(const struct p11tool_cmd *cmd,
                                  int *argc, char **argv[]);
CK_RV p11tool_parse_cmd_options(const struct p11tool_cmd *cmd,
                                const struct p11tool_opt *generic_opts,
                                int argc, char *argv[]);
CK_RV p11tool_check_required_args(const struct p11tool_arg *args);
CK_RV p11tool_check_required_cmd_opts(const struct p11tool_opt *cmd_opts,
                                      const struct p11tool_opt *generic_opts);
void p11tool_print_indented(const char *str, int indent);
void p11tool_print_help(const char *name,
                        const struct p11tool_cmd *commands,
                        const struct p11tool_opt *generic_opts,
                        int indent_pos);
void p11tool_print_command_help(const char *name,
                                const struct p11tool_cmd *cmd,
                                const struct p11tool_opt *generic_opts,
                                int indent_pos);
void p11tool_print_version(const char *name);

void p11tool_print_bool_attr_short(const CK_ATTRIBUTE *val, bool applicable);
void p11tool_print_bool_attr_long(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive);
void p11tool_print_utf8_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive);
void p11tool_print_java_midp_secdom_attr(const char *attr,
                                         const CK_ATTRIBUTE *val,
                                         int indent, bool sensitive);
void p11tool_print_cert_category_attr(const char *attr, const CK_ATTRIBUTE *val,
                                      int indent, bool sensitive);
void p11tool_print_x509_name_attr(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive);
void p11tool_print_x509_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive);
void p11tool_print_x509_serial_number_attr(const char *attr,
                                           const CK_ATTRIBUTE *val,
                                           int indent, bool sensitive);
void p11tool_print_byte_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                   int indent, bool sensitive);
void p11tool_print_ulong_attr(const char *attr, const CK_ATTRIBUTE *val,
                              int indent, bool sensitive);
void p11tool_print_date_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive);
void p11tool_print_mech_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive);
void p11tool_print_mech_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                   int indent, bool sensitive);
void p11tool_print_class_attr(const char *attr, const CK_ATTRIBUTE *val,
                              int indent, bool sensitive);
void p11tool_print_oid_attr(const char *attr, const CK_ATTRIBUTE *val,
                            int indent, bool sensitive);
void p11tool_print_ibm_dilithium_keyform_attr(const char *attr,
                                              const CK_ATTRIBUTE *val,
                                              int indent, bool sensitive);
void p11tool_print_ibm_kyber_keyform_attr(const char *attr,
                                          const CK_ATTRIBUTE *val,
                                          int indent, bool sensitive);

int p11tool_openssl_err_cb(const char *str, size_t len, void *u);

void p11tool_free_attributes(CK_ATTRIBUTE *attrs, CK_ULONG num_attrs);
bool p11tool_is_attr_array_attr(CK_ATTRIBUTE *attr);
void p11tool_free_attr_array_attr(CK_ATTRIBUTE *attr);
CK_RV p11tool_alloc_attr_array_attr(CK_ATTRIBUTE *attr, bool *allocated);

CK_RV p11tool_add_attribute(CK_ATTRIBUTE_TYPE type, const void *value,
                            CK_ULONG value_len, CK_ATTRIBUTE **attrs,
                            CK_ULONG *num_attrs);
CK_RV p11tool_add_bignum_attr(CK_ATTRIBUTE_TYPE type, const BIGNUM* bn,
                              CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
CK_RV p11tool_add_attributes(const struct p11tool_objtype *objtype,
                             const struct p11tool_attr *bool_attrs,
                             CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                             const char *label, const char *attr_string,
                             const char *id, bool is_sensitive, bool so,
                             CK_RV (*add_attrs)(
                                     const struct p11tool_objtype *objtype,
                                     CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     void *private),
                             void *private,
                             bool (*attr_applicable)(
                                     const struct p11tool_objtype *objtype,
                                     const struct p11tool_attr *attr));
CK_RV p11tool_parse_id(const char *id_string, CK_ATTRIBUTE **attrs,
                       CK_ULONG *num_attrs);
const struct p11tool_attr *p11tool_find_attr_by_letter(
                                        const struct p11tool_attr *bool_attrs,
                                        char letter);
CK_RV p11tool_parse_boolean_attrs(const struct p11tool_objtype *objtype,
                                  const struct p11tool_attr *bool_attrs,
                                  const char *attr_string, CK_ATTRIBUTE **attrs,
                                  CK_ULONG *num_attrs, bool check_settable,
                                  bool so,
                                  bool (*attr_applicable)(
                                         const struct p11tool_objtype *objtype,
                                         const struct p11tool_attr *attr));

CK_RV p11tool_get_attribute(CK_OBJECT_HANDLE key, CK_ATTRIBUTE *attr);
CK_RV p11tool_get_bignum_attr(CK_OBJECT_HANDLE key, CK_ATTRIBUTE_TYPE type,
                              BIGNUM **bn);

CK_RV p11tool_get_common_name_value(CK_OBJECT_HANDLE obj, char *label,
                                    char **common_name_value);
CK_RV p11tool_get_keysize_value(CK_OBJECT_HANDLE obj, char *label,
                                const struct p11tool_objtype *objtype_val,
                                CK_ULONG *keysize_val);
CK_RV p11tool_get_typestr_value(CK_OBJECT_CLASS class_val, CK_ULONG keysize_val,
                                const struct p11tool_objtype *objtype_val,
                                char *label, char **typestr);
CK_RV p11tool_get_class_and_type_values(CK_OBJECT_HANDLE obj, char *label,
                                       CK_OBJECT_CLASS *class_val,
                                       CK_ULONG *otype_val);
CK_RV p11tool_get_label_value(CK_OBJECT_HANDLE obj, char** label_value);
CK_BBOOL p11tool_objclass_expected(CK_OBJECT_HANDLE obj,
                                   enum p11tool_objclass objclass);

bool p11tool_attr_applicable_for_certtype(
                                        const struct p11tool_objtype *certtype,
                                        const struct p11tool_attr *attr);
bool p11tool_attr_applicable_for_keytype(const struct p11tool_objtype *keytype,
                                         const struct p11tool_attr *attr);
bool p11tool_cert_attr_applicable(const struct p11tool_objtype *certtype,
                                  const struct p11tool_attr *attr);
bool p11tool_secret_attr_applicable(const struct p11tool_objtype *objtype,
                                    const struct p11tool_attr *attr);
bool p11tool_public_attr_applicable(const struct p11tool_objtype *objtype,
                                    const struct p11tool_attr *attr);
bool p11tool_private_attr_applicable(const struct p11tool_objtype *objtype,
                                     const struct p11tool_attr *attr);

CK_RV p11tool_init_pkcs11(const struct p11tool_cmd *command, bool no_login,
                          const char *pin, bool force_pin_prompt, bool so,
                          bool remember_pin, CK_SLOT_ID slot,
                          const struct p11tool_token_info *known_tokens);
void p11tool_term_pkcs11(void);
bool p11tool_is_rejected_by_policy(CK_RV ret_code, CK_SESSION_HANDLE session);
CK_RV p11tool_check_keygen_mech_supported(CK_SLOT_ID slot, CK_MECHANISM_TYPE mechanism,
                                   bool is_asymmetric, CK_ULONG keysize);

char p11tool_prompt_user(const char *message, char* allowed_chars);

struct p11tool_pem_password_cb_data {
    const char *pem_file_name;
    const char *pem_password;
    const char *env_var_name;
    bool force_prompt;
};

int p11tool_pem_password_cb(char *buf, int size, int rwflag, void *userdata);

CK_RV p11tool_ASN1_TIME2date(const ASN1_TIME *asn1time, CK_DATE *date);

CK_RV p11tool_get_octet_string_param_from_pkey(EVP_PKEY *pkey,
                                               const char *param,
                                               CK_BYTE **key, size_t *key_len);

CK_RV p11tool_prepare_uri(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS *class,
                          const struct p11tool_objtype *objtype,
                          const char *typestr, const char* label,
                          bool detailed_uri, CK_SLOT_ID slot,
                          struct p11_uri **uri);

#endif
