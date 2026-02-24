/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#if defined(_AIX)
    const char *__progname = "p11sak";
#endif

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <limits.h>
#include <dlfcn.h>
#include <pwd.h>
#include <ctype.h>
#include <fnmatch.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/rsa.h>
#include <openssl/ec.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>

#define P11SAK_DECLARE_CURVES
#include "p11sak.h"
#include "p11util.h"
#include "pin_prompt.h"
#include "cfgparser.h"
#include "configuration.h"
#include "mechtable.h"
#include "defs.h"
#include "pqc_defs.h"

#if OPENSSL_VERSION_PREREQ(3, 0)
    #include <openssl/core_names.h>
    #include <openssl/decoder.h>
    #include <openssl/param_build.h>

    #ifndef OSSL_PKEY_PARAM_ML_DSA_SEED
        #define OSSL_PKEY_PARAM_ML_DSA_SEED "seed"
    #endif
    #ifndef OSSL_PKEY_PARAM_ML_KEM_SEED
        #define OSSL_PKEY_PARAM_ML_KEM_SEED "seed"
    #endif
#endif

static CK_RV p11sak_generate_key(void);
static CK_RV p11sak_list_key(void);
static CK_RV p11sak_remove_key(void);
static CK_RV p11sak_set_key_attr(void);
static CK_RV p11sak_copy_key(void);
static CK_RV p11sak_import_key(void);
static CK_RV p11sak_export_key(void);
static CK_RV p11sak_extract_key_pubkey(void);
static void print_generate_import_key_attr_help(void);
static void print_list_key_attr_help(void);
static void print_set_copy_extract_key_attr_help(void);
static void print_remove_key_help(void);
static CK_RV p11sak_list_cert(void);
static CK_RV p11sak_remove_cert(void);
static CK_RV p11sak_set_cert_attr(void);
static CK_RV p11sak_copy_cert(void);
static CK_RV p11sak_import_cert(void);
static CK_RV p11sak_export_cert(void);
static CK_RV p11sak_extract_cert_pubkey(void);
static void print_import_cert_attr_help(void);
static void print_list_cert_attr_help(void);
static void print_set_copy_cert_attr_help(void);
static void print_remove_cert_help(void);
static void print_extract_cert_pubkey_help(void);

static struct ConfigBaseNode *p11sak_cfg = NULL;

static bool opt_help = false;
static bool opt_version = false;
CK_SLOT_ID opt_slot = (CK_SLOT_ID)-1;
static char *opt_pin = NULL;
static bool opt_force_pin_prompt = false;
static bool opt_no_login = false;
bool opt_so = false;
struct p11tool_enum_value *opt_keytype = NULL;
static struct p11tool_enum_value *opt_certtype = NULL;
static CK_ULONG opt_keybits_num = 0;
static struct p11tool_enum_value *opt_keybits = NULL;
static struct p11tool_enum_value *opt_group = NULL;
static char *opt_pem_file = NULL;
static struct p11tool_enum_value *opt_curve = NULL;
static struct p11tool_enum_value *opt_pqc_version = NULL;
char *opt_label = NULL;
bool opt_force = false;
static CK_ULONG opt_exponent = 0;
char *opt_attr = NULL;
char *opt_id = NULL;
static bool opt_long = false;
static bool opt_detailed_uri = false;
static char *opt_sort = NULL;
static char *opt_new_attr = NULL;
static char *opt_new_label = NULL;
static char *opt_new_id = NULL;
char *opt_file = NULL;
static char *opt_pem_password = NULL;
static bool opt_force_pem_pwd_prompt = false;
static bool opt_encrypted_pem = false;
static bool opt_opaque = false;
static struct p11tool_enum_value *opt_asym_kind = NULL;
static bool opt_spki = false;
static bool opt_der = false;
static bool opt_cacert = false;
static bool opt_uri_pem = false;
static bool opt_uri_pin_value = false;
static char *opt_uri_pin_source = NULL;
static bool opt_oqsprovider_pem = false;
static bool opt_hsm_mkvp = false;
static bool opt_ep11_session_id = false;
char *opt_kek_label = NULL;
char *opt_kek_id = NULL;
bool opt_raw = false;
struct p11tool_enum_value *opt_wrap_mech = NULL;

static bool opt_slot_is_set(const struct p11tool_arg *arg);
static CK_RV generic_get_key_size(const struct p11tool_objtype *keytype,
                                  void *private, CK_ULONG *keysize);
static CK_RV generic_add_secret_attrs(const struct p11tool_objtype *keytype,
                                      CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                      void *private);
static CK_ULONG generic_keysize_adjust(const struct p11tool_objtype *keytype,
                                       CK_ULONG keysize);
static CK_RV aes_get_key_size(const struct p11tool_objtype *keytype,
                              void *private, CK_ULONG *keysize);
static CK_RV aes_add_secret_attrs(const struct p11tool_objtype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private);
static CK_ULONG aes_keysize_adjust(const struct p11tool_objtype *keytype,
                                   CK_ULONG keysize);
static CK_ULONG aes_xts_keysize_adjust(const struct p11tool_objtype *keytype,
                                       CK_ULONG keysize);
static CK_ULONG rsa_keysize_adjust(const struct p11tool_objtype *keytype,
                                   CK_ULONG keysize);
static CK_ULONG dh_keysize_adjust(const struct p11tool_objtype *keytype,
                                  CK_ULONG keysize);
static CK_ULONG dsa_keysize_adjust(const struct p11tool_objtype *keytype,
                                   CK_ULONG keysize);
static CK_RV rsa_get_key_size(const struct p11tool_objtype *keytype,
                              void *private, CK_ULONG *keysize);
static CK_RV rsa_add_public_attrs(const struct p11tool_objtype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private);
static CK_RV ec_get_key_size(const struct p11tool_objtype *keytype,
                             void *private, CK_ULONG *keysize);
static CK_RV ec_add_public_attrs(const struct p11tool_objtype *keytype,
                                 CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                 void *private);
static CK_RV dh_prepare(const struct p11tool_objtype *keytype, void **private);
static void dh_cleanup(const struct p11tool_objtype *keytype, void *private);
static CK_RV dh_get_key_size(const struct p11tool_objtype *keytype,
                             void *private, CK_ULONG *keysize);
static CK_RV dh_add_public_attrs(const struct p11tool_objtype *keytype,
                                 CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                 void *private);
static CK_RV dh_add_private_attrs(const struct p11tool_objtype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private);
static CK_RV dsa_prepare(const struct p11tool_objtype *keytype, void **private);
static void dsa_cleanup(const struct p11tool_objtype *keytype, void *private);
static CK_RV dsa_get_key_size(const struct p11tool_objtype *keytype,
                              void *private, CK_ULONG *keysize);
static CK_RV dsa_add_public_attrs(const struct p11tool_objtype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private);
static CK_RV ibm_dilithium_add_public_attrs(
                                        const struct p11tool_objtype *keytype,
                                        CK_ATTRIBUTE **attrs,
                                        CK_ULONG *num_attrs,
                                        void *private);
static CK_RV ibm_kyber_add_public_attrs(const struct p11tool_objtype *keytype,
                                        CK_ATTRIBUTE **attrs,
                                        CK_ULONG *num_attrs,
                                        void *private);
static CK_RV ibm_ml_dsa_kem_add_public_attrs(
                                         const struct p11tool_objtype *keytype,
                                         CK_ATTRIBUTE **attrs,
                                         CK_ULONG *num_attrs,
                                         void *private);

static CK_RV p11sak_import_check_des_keysize(
                                        const struct p11tool_objtype *keytype,
                                        CK_ULONG keysize);
static CK_RV p11sak_import_check_3des_keysize(
                                        const struct p11tool_objtype *keytype,
                                        CK_ULONG keysize);
static CK_RV p11sak_import_check_generic_keysize(
                                        const struct p11tool_objtype *keytype,
                                        CK_ULONG keysize);
static CK_RV p11sak_import_check_aes_keysize(
                                        const struct p11tool_objtype *keytype,
                                        CK_ULONG keysize);
static CK_RV p11sak_import_check_aes_xts_keysize(
                                        const struct p11tool_objtype *keytype,
                                        CK_ULONG keysize);
static CK_RV p11sak_import_sym_clear_des_3des_aes_generic(
                                    const struct p11tool_objtype *keytype,
                                    CK_BYTE *data, CK_ULONG data_len,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
static CK_RV p11sak_import_rsa_pkey(const struct p11tool_objtype *keytype,
                                    EVP_PKEY *pkey, bool private,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
static CK_RV p11sak_import_cert_attrs(const struct p11tool_objtype *certtype,
                                      X509 *x509, CK_ATTRIBUTE **attrs,
                                      CK_ULONG *num_attrs);
static CK_RV p11sak_import_x509_attrs(const struct p11tool_objtype *certtype,
                                      X509 *x509, CK_ATTRIBUTE **attrs,
                                      CK_ULONG *num_attrs);
static CK_RV p11sak_import_dh_pkey(const struct p11tool_objtype *keytype,
                                    EVP_PKEY *pkey, bool private,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
static CK_RV p11sak_import_dsa_pkey(const struct p11tool_objtype *keytype,
                                    EVP_PKEY *pkey, bool private,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
static CK_RV p11sak_import_ec_pkey(const struct p11tool_objtype *keytype,
                                   EVP_PKEY *pkey, bool private,
                                   CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs);
static CK_RV p11sak_import_dilithium_kyber_pem_data(
                                        const struct p11tool_objtype *keytype,
                                        unsigned char *data, size_t data_len,
                                        bool private,
                                        CK_ATTRIBUTE **attrs,
                                        CK_ULONG *num_attrs);
static CK_RV p11sak_import_dilithium_ml_dsa_pkey(const struct p11tool_objtype *keytype,
                                          EVP_PKEY *pkey, bool private,
                                          CK_ATTRIBUTE **attrs,
                                          CK_ULONG *num_attrs);
static CK_RV p11sak_import_ml_kem_pkey(const struct p11tool_objtype *keytype,
                                       EVP_PKEY *pkey, bool private,
                                       CK_ATTRIBUTE **attrs,
                                       CK_ULONG *num_attrs);
static CK_RV p11sak_export_sym_clear_des_3des_aes_generic(
                                    const struct p11tool_objtype *keytype,
                                    CK_BYTE **data, CK_ULONG* data_len,
                                    CK_OBJECT_HANDLE key, const char *label);
static CK_RV p11sak_export_rsa_pkey(const struct p11tool_objtype *keytype,
                                    EVP_PKEY **pkey, bool private,
                                    CK_OBJECT_HANDLE key, const char *label);
static CK_RV p11sak_export_dh_pkey(const struct p11tool_objtype *keytype,
                                   EVP_PKEY **pkey, bool private,
                                   CK_OBJECT_HANDLE key, const char *label);
static CK_RV p11sak_export_dsa_pkey(const struct p11tool_objtype *keytype,
                                    EVP_PKEY **pkey, bool private,
                                    CK_OBJECT_HANDLE key, const char *label);
static CK_RV p11sak_export_ec_pkey(const struct p11tool_objtype *keytype,
                                   EVP_PKEY **pkey, bool private,
                                   CK_OBJECT_HANDLE key, const char *label);
static CK_RV p11sak_export_dilithium_kyber_pem_data(
                                        const struct p11tool_objtype *keytype,
                                        CK_BYTE **data, CK_ULONG *data_len,
                                        bool private, CK_OBJECT_HANDLE key,
                                        const char *label);
static CK_RV p11sak_export_dilithium_ml_dsa_pkey(const struct p11tool_objtype *keytype,
                                          EVP_PKEY **pkey, bool private,
                                          CK_OBJECT_HANDLE key,
                                          const char *label);
static CK_RV p11sak_export_ml_kem_pkey(const struct p11tool_objtype *keytype,
                                       EVP_PKEY **pkey, bool private,
                                       CK_OBJECT_HANDLE key,
                                       const char *label);
static CK_RV p11sak_export_x509(const struct p11tool_objtype *certtype,
                                CK_BYTE **data, CK_ULONG *data_len,
                                CK_OBJECT_HANDLE cert, const char *label);
static CK_RV p11sak_extract_x509_pk(const struct p11tool_objtype *certtype,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                    CK_OBJECT_HANDLE cert, const char* label);
static void print_attr_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive);
static void print_key_type_attr(const char *attr, const CK_ATTRIBUTE *val,
                                int indent, bool sensitive);
static void print_cert_type_attr(const char *attr, const CK_ATTRIBUTE *val,
                                 int indent, bool sensitive);
static void p11sak_print_mkvp_cca_short(const struct p11tool_token_info *info,
                                        const CK_BYTE *secure_key,
                                        CK_ULONG secure_key_len,
                                        const char *separator);
static void p11sak_print_mkvp_cca_long(const struct p11tool_token_info *info,
                                       const CK_BYTE *secure_key,
                                       CK_ULONG secure_key_len,
                                       int indent);
static void p11sak_print_mkvp_ep11_short(const struct p11tool_token_info *info,
                                         const CK_BYTE *secure_key,
                                         CK_ULONG secure_key_len,
                                         const char *separator);
static void p11sak_print_mkvp_ep11_long(const struct p11tool_token_info *info,
                                        const CK_BYTE *secure_key,
                                        CK_ULONG secure_key_len,
                                        int indent);
static void p11sak_print_session_id_ep11_short(
                                         const struct p11tool_token_info *info,
                                         const CK_BYTE *secure_key,
                                         CK_ULONG secure_key_len);
static void p11sak_print_session_id_ep11_long(
                                         const struct p11tool_token_info *info,
                                         const CK_BYTE *secure_key,
                                         CK_ULONG secure_key_len,
                                         int indent);

#define DECLARE_CERT_ATTRS                                                     \
    { .name = "CKA_LABEL", .type = CKA_LABEL,                                  \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_utf8_attr, },                                \
    { .name = "CKA_CLASS", .type = CKA_CLASS,                                  \
      .secret = true, .public = true, .private = true, .settable = false,      \
      .print_long = p11tool_print_class_attr, },                               \
    { .name = "CKA_CERTIFICATE_TYPE", .type = CKA_CERTIFICATE_TYPE,            \
      .secret = true, .public = true, .private = true, .settable = false,      \
      .print_long = print_cert_type_attr, },                                   \
    { .name = "CKA_CERTIFICATE_CATEGORY", .type = CKA_CERTIFICATE_CATEGORY,    \
      .secret = true, .public = true, .private = true, .settable = false,      \
      .print_long = p11tool_print_cert_category_attr, },                       \
    { .name = "CKA_CHECK_VALUE", .type = CKA_CHECK_VALUE,                      \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_START_DATE", .type = CKA_START_DATE,                        \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_date_attr, },                                \
    { .name = "CKA_END_DATE", .type = CKA_END_DATE,                            \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_date_attr, },                                \
    { .name = "CKA_PUBLIC_KEY_INFO", .type = CKA_PUBLIC_KEY_INFO,              \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_byte_array_attr, }

static const struct p11tool_attr p11sak_x509_attrs[] = {
    DECLARE_CERT_ATTRS,
    { .name = "CKA_SUBJECT", .type = CKA_SUBJECT,
      .secret = true, .public = true, .private = true, .settable = true,
      .print_long = p11tool_print_x509_name_attr, },
    { .name = "CKA_ID", .type = CKA_ID,
      .secret = true, .public = true, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_ISSUER", .type = CKA_ISSUER,
      .secret = true, .public = true, .private = true, .settable = true,
      .print_long = p11tool_print_x509_name_attr, },
    { .name = "CKA_SERIAL_NUMBER", .type = CKA_SERIAL_NUMBER,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_x509_serial_number_attr, },
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_x509_attr, },
    { .name = "CKA_NAME_HASH_ALGORITHM", .type = CKA_NAME_HASH_ALGORITHM,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_mech_attr, },
    { .name = "CKA_HASH_OF_SUBJECT_PUBLIC_KEY", .type = CKA_HASH_OF_SUBJECT_PUBLIC_KEY,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_HASH_OF_ISSUER_PUBLIC_KEY", .type = CKA_HASH_OF_ISSUER_PUBLIC_KEY,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_URL", .type = CKA_URL,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_utf8_attr, },
    { .name = "CKA_JAVA_MIDP_SECURITY_DOMAIN", .type = CKA_JAVA_MIDP_SECURITY_DOMAIN,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_java_midp_secdom_attr, },
    { .name = NULL },
};

#define DECLARE_KEY_ATTRS                                                      \
    { .name = "CKA_LABEL", .type = CKA_LABEL,                                  \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_utf8_attr, },                                \
    { .name = "CKA_CLASS", .type = CKA_CLASS,                                  \
      .secret = true, .public = true, .private = true, .settable = false,      \
      .print_long = p11tool_print_class_attr, },                               \
    { .name = "CKA_KEY_TYPE", .type = CKA_KEY_TYPE,                            \
      .secret = true, .public = true, .private = true, .settable = false,      \
      .print_long = print_key_type_attr, },                                    \
    { .name = "CKA_ID", .type = CKA_ID,                                        \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_START_DATE", .type = CKA_START_DATE,                        \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_date_attr, },                                \
    { .name = "CKA_END_DATE", .type = CKA_END_DATE,                            \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_date_attr, },                                \
    { .name = "CKA_KEY_GEN_MECHANISM", .type = CKA_KEY_GEN_MECHANISM,          \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_mech_attr, },                                \
    { .name = "CKA_ALLOWED_MECHANISMS", .type = CKA_ALLOWED_MECHANISMS,        \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = p11tool_print_mech_array_attr, }

#define DECLARE_SECRET_KEY_ATTRS                                               \
    { .name = "CKA_CHECK_VALUE", .type = CKA_CHECK_VALUE,                      \
      .secret = true, .public = false, .private = false, .settable = true,     \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_WRAP_TEMPLATE", .type = CKA_WRAP_TEMPLATE,                  \
      .secret = true, .public = true, .private = false, .settable = true,      \
      .print_long = print_attr_array_attr, },                                  \
    { .name = "CKA_UNWRAP_TEMPLATE", .type = CKA_UNWRAP_TEMPLATE,              \
      .secret = true, .public = false, .private = true, .settable = true,      \
      .print_long = print_attr_array_attr, },                                  \
    { .name = "CKA_DERIVE_TEMPLATE", .type = CKA_DERIVE_TEMPLATE,              \
      .secret = true, .public = false, .private = true, .settable = true,      \
      .print_long = print_attr_array_attr, }

#define DECLARE_PUBLIC_KEY_ATTRS                                               \
    { .name = "CKA_SUBJECT", .type = CKA_SUBJECT,                              \
      .secret = true, .public = false, .private = true, .settable = true,      \
      .print_long = p11tool_print_x509_name_attr, },                           \
    { .name = "CKA_WRAP_TEMPLATE", .type = CKA_WRAP_TEMPLATE,                  \
      .secret = true, .public = true, .private = false, .settable = true,      \
      .print_long = print_attr_array_attr, },                                  \
    { .name = "CKA_PUBLIC_KEY_INFO", .type = CKA_PUBLIC_KEY_INFO,              \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, }

#define DECLARE_PRIVATE_KEY_ATTRS                                              \
    { .name = "CKA_SUBJECT", .type = CKA_SUBJECT,                              \
      .secret = true, .public = false, .private = true, .settable = true,      \
      .print_long = p11tool_print_x509_name_attr, },                           \
    { .name = "CKA_UNWRAP_TEMPLATE", .type = CKA_UNWRAP_TEMPLATE,              \
      .secret = true, .public = false, .private = true, .settable = true,      \
      .print_long = print_attr_array_attr, },                                  \
    { .name = "CKA_PUBLIC_KEY_INFO", .type = CKA_PUBLIC_KEY_INFO,              \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_DERIVE_TEMPLATE", .type = CKA_DERIVE_TEMPLATE,              \
      .secret = true, .public = false, .private = true, .settable = true,      \
      .print_long = print_attr_array_attr, }

static const struct p11tool_attr p11sak_des_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_SECRET_KEY_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11tool_attr p11sak_3des_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_SECRET_KEY_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11tool_attr p11sak_generic_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_SECRET_KEY_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_VALUE_LEN", .type = CKA_VALUE_LEN,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_ulong_attr, },
    { .name = NULL },
};

static const struct p11tool_attr p11sak_aes_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_SECRET_KEY_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_VALUE_LEN", .type = CKA_VALUE_LEN,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = p11tool_print_ulong_attr, },
    { .name = NULL },
};

#define DECLARE_PUBLIC_RSA_ATTRS                                               \
    { .name = "CKA_MODULUS", .type = CKA_MODULUS,                              \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_MODULUS_BITS", .type = CKA_MODULUS_BITS,                    \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_ulong_attr, },                               \
    { .name = "CKA_PUBLIC_EXPONENT", .type = CKA_PUBLIC_EXPONENT,              \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, }

static const struct p11tool_attr p11sak_public_rsa_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_PUBLIC_RSA_ATTRS,
    { .name = NULL },
};

static const struct p11tool_attr p11sak_private_rsa_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_PUBLIC_RSA_ATTRS,
    { .name = "CKA_PRIVATE_EXPONENT", .type = CKA_PRIVATE_EXPONENT,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_PRIME_1", .type = CKA_PRIME_1,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_PRIME_2", .type = CKA_PRIME_2,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_EXPONENT_1", .type = CKA_EXPONENT_1,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_EXPONENT_2", .type = CKA_EXPONENT_2,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_COEFFICIENT", .type = CKA_COEFFICIENT,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

#define DECLARE_DH_ATTRS                                                       \
    { .name = "CKA_PRIME", .type = CKA_PRIME,                                  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_BASE", .type = CKA_BASE,                                    \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_VALUE", .type = CKA_VALUE,                                  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, }

static const struct p11tool_attr p11sak_public_dh_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_DH_ATTRS,
    { .name = NULL },
};

static const struct p11tool_attr p11sak_private_dh_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_DH_ATTRS,
    { .name = "CKA_VALUE_BITS", .type = CKA_VALUE_BITS,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_ulong_attr, },
    { .name = NULL },
};

#define DECLARE_DSA_ATTRS                                                      \
    { .name = "CKA_PRIME", .type = CKA_PRIME,                                  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_SUBPRIME", .type = CKA_SUBPRIME,                            \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_BASE", .type = CKA_BASE,                                    \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_VALUE", .type = CKA_VALUE,                                  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, }

static const struct p11tool_attr p11sak_public_dsa_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_DSA_ATTRS,
    { .name = NULL },
};

static const struct p11tool_attr p11sak_private_dsa_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_DSA_ATTRS,
    { .name = NULL },
};

#define DECLARE_EC_ATTRS                                                       \
    { .name = "CKA_EC_PARAMS", .type = CKA_EC_PARAMS,                          \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_oid_attr, }

static const struct p11tool_attr p11sak_public_ec_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_EC_ATTRS,
    { .name = "CKA_EC_POINT", .type = CKA_EC_POINT,
      .secret = false, .public = true, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11tool_attr p11sak_private_ec_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_EC_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

#define DECLARE_PUBLIC_IBM_DILITHIUM_ATTRS                                     \
    { .name = "CKA_IBM_DILITHIUM_KEYFORM", .type = CKA_IBM_DILITHIUM_KEYFORM,  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_ibm_dilithium_keyform_attr, },               \
    { .name = "CKA_IBM_DILITHIUM_MODE", .type = CKA_IBM_DILITHIUM_MODE,        \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_oid_attr, },                                 \
    { .name = "CKA_IBM_DILITHIUM_RHO", .type = CKA_IBM_DILITHIUM_RHO,          \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_IBM_DILITHIUM_T1", .type = CKA_IBM_DILITHIUM_T1,            \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, }

static const struct p11tool_attr p11sak_public_ibm_dilithium_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_PUBLIC_IBM_DILITHIUM_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = false, .public = true, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11tool_attr p11sak_private_ibm_dilithium_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_PUBLIC_IBM_DILITHIUM_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_DILITHIUM_SEED", .type = CKA_IBM_DILITHIUM_SEED,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_DILITHIUM_TR", .type = CKA_IBM_DILITHIUM_TR,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_DILITHIUM_S1", .type = CKA_IBM_DILITHIUM_S1,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_DILITHIUM_S2", .type = CKA_IBM_DILITHIUM_S2,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_DILITHIUM_T0", .type = CKA_IBM_DILITHIUM_T0,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

#define DECLARE_PUBLIC_IBM_KYBER_ATTRS                                         \
    { .name = "CKA_IBM_KYBER_KEYFORM", .type = CKA_IBM_KYBER_KEYFORM,          \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_ibm_kyber_keyform_attr, },                   \
    { .name = "CKA_IBM_KYBER_MODE", .type = CKA_IBM_KYBER_MODE,                \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_oid_attr, },                                 \
    { .name = "CKA_IBM_KYBER_PK", .type = CKA_IBM_KYBER_PK,                    \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, }

static const struct p11tool_attr p11sak_public_ibm_kyber_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_PUBLIC_IBM_KYBER_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = false, .public = true, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11tool_attr p11sak_private_ibm_kyber_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_PUBLIC_IBM_KYBER_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_KYBER_SK", .type = CKA_IBM_KYBER_SK,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

#define DECLARE_PUBLIC_PRIVATE_IBM_ML_DSA_ATTRS                                \
    { .name = "CKA_IBM_PARAMETER_SET", .type = CKA_IBM_PARAMETER_SET,          \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_ibm_ml_dsa_parameter_set_attr, },            \
    { .name = "CKA_IBM_ML_DSA_RHO", .type = CKA_IBM_ML_DSA_RHO,                \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, },                          \
    { .name = "CKA_IBM_ML_DSA_T1", .type = CKA_IBM_ML_DSA_T1,                  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, }

static const struct p11tool_attr p11sak_public_ibm_ml_dsa_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_PUBLIC_PRIVATE_IBM_ML_DSA_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = false, .public = true, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11tool_attr p11sak_private_ibm_ml_dsa_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_PUBLIC_PRIVATE_IBM_ML_DSA_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_ML_DSA_SEED", .type = CKA_IBM_ML_DSA_SEED,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_ML_DSA_TR", .type = CKA_IBM_ML_DSA_TR,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_ML_DSA_S1", .type = CKA_IBM_ML_DSA_S1,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_ML_DSA_S2", .type = CKA_IBM_ML_DSA_S2,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_ML_DSA_T0", .type = CKA_IBM_ML_DSA_T0,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_ML_DSA_PRIVATE_SEED",
       .type = CKA_IBM_ML_DSA_PRIVATE_SEED,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

#define DECLARE_PUBLIC_PRIVATE_IBM_ML_KEM_ATTRS                                \
    { .name = "CKA_IBM_PARAMETER_SET", .type = CKA_IBM_PARAMETER_SET,          \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_ibm_ml_kem_parameter_set_attr, },            \
    { .name = "CKA_IBM_ML_KEM_PK", .type = CKA_IBM_ML_KEM_PK,                  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = p11tool_print_byte_array_attr, }

static const struct p11tool_attr p11sak_public_ibm_ml_kem_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_PUBLIC_PRIVATE_IBM_ML_KEM_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = false, .public = true, .private = false, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11tool_attr p11sak_private_ibm_ml_kem_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_PUBLIC_PRIVATE_IBM_ML_KEM_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_ML_KEM_SK", .type = CKA_IBM_ML_KEM_SK,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = "CKA_IBM_ML_KEM_PRIVATE_SEED",
      .type = CKA_IBM_ML_KEM_PRIVATE_SEED,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = p11tool_print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11tool_objtype p11sak_des_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "DES", .type = CKK_DES, .ck_name = "CKK_DES",
    .keygen_mech = { .mechanism = CKM_DES_KEY_GEN, },
    .is_asymmetric = false,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_DES,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .secret_attrs = p11sak_des_attrs,
    .import_check_sym_keysize = p11sak_import_check_des_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_3des_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "3DES",  .type = CKK_DES3, .ck_name = "CKK_DES3",
    .keygen_mech = { .mechanism = CKM_DES3_KEY_GEN, },
    .is_asymmetric = false,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_DES3,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .secret_attrs = p11sak_3des_attrs,
    .import_check_sym_keysize = p11sak_import_check_3des_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_generic_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "GENERIC",  .type = CKK_GENERIC_SECRET,
    .ck_name = "CKK_GENERIC_SECRET",
    .keygen_mech = { .mechanism = CKM_GENERIC_SECRET_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_GENERIC_SECRET,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha_1_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA-1-HMAC",  .type = CKK_SHA_1_HMAC,
    .ck_name = "CKK_SHA_1_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA_1_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA_1_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha224_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA224-HMAC",  .type = CKK_SHA224_HMAC,
    .ck_name = "CKK_SHA224_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA224_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA224_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha256_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA256-HMAC",  .type = CKK_SHA256_HMAC,
    .ck_name = "CKK_SHA256_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA256_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA256_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha384_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA384-HMAC",  .type = CKK_SHA384_HMAC,
    .ck_name = "CKK_SHA384_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA384_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA384_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha512_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA512-HMAC",  .type = CKK_SHA512_HMAC,
    .ck_name = "CKK_SHA512_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA512_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA512_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha512_224_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA512/224-HMAC",  .type = CKK_SHA512_224_HMAC,
    .ck_name = "CKK_SHA512_224_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA512_224_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA512_224_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha512_256_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA512/256-HMAC",  .type = CKK_SHA512_256_HMAC,
    .ck_name = "CKK_SHA512_256_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA512_256_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA512_256_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha3_224_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA3-224-HMAC",  .type = CKK_SHA3_224_HMAC,
    .ck_name = "CKK_SHA3_224_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA3_224_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA3_224_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha3_256_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA3-256-HMAC",  .type = CKK_SHA3_256_HMAC,
    .ck_name = "CKK_SHA3_256_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA3_256_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA3_256_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha3_384_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA3-384-HMAC",  .type = CKK_SHA3_384_HMAC,
    .ck_name = "CKK_SHA3_384_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA3_384_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA3_384_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_sha3_512_hmac_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "SHA3-512-HMAC",  .type = CKK_SHA3_512_HMAC,
    .ck_name = "CKK_SHA3_512_HMAC",
    .keygen_mech = { .mechanism = CKM_SHA3_512_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_SHA3_512_HMAC,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
    .import_check_sym_keysize = p11sak_import_check_generic_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_aes_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "AES",  .type = CKK_AES, .ck_name = "CKK_AES",
    .keygen_mech = { .mechanism = CKM_AES_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = aes_get_key_size,
    .keygen_add_secret_attrs = aes_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_AES,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = aes_keysize_adjust,
    .secret_attrs = p11sak_aes_attrs,
    .import_check_sym_keysize = p11sak_import_check_aes_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_aes_xts_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "AES-XTS",  .type = CKK_AES_XTS, .ck_name = "CKK_AES_XTS",
    .keygen_mech = { .mechanism = CKM_AES_XTS_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = aes_get_key_size,
    .keygen_add_secret_attrs = aes_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_AES_XTS,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = aes_xts_keysize_adjust,
    .secret_attrs = p11sak_aes_attrs,
    .import_check_sym_keysize = p11sak_import_check_aes_xts_keysize,
    .import_sym_clear = p11sak_import_sym_clear_des_3des_aes_generic,
    .export_sym_clear = p11sak_export_sym_clear_des_3des_aes_generic,
};

static const struct p11tool_objtype p11sak_rsa_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key", .pkey_type = EVP_PKEY_RSA,
    .name = "RSA",  .type = CKK_RSA, .ck_name = "CKK_RSA",
    .keygen_mech = { .mechanism = CKM_RSA_PKCS_KEY_PAIR_GEN, },
    .is_asymmetric = true,
    .keygen_get_key_size = rsa_get_key_size,
    .keygen_add_public_attrs = rsa_add_public_attrs,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = false,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_RSA,
    .keysize_attr = CKA_MODULUS, .keysize_attr_value_len = true,
    .key_keysize_adjust = rsa_keysize_adjust,
    .public_attrs = p11sak_public_rsa_attrs,
    .private_attrs = p11sak_private_rsa_attrs,
    .import_asym_pkey = p11sak_import_rsa_pkey,
    .export_asym_pkey = p11sak_export_rsa_pkey,
};

static const struct p11tool_objtype p11sak_dh_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key", .pkey_type = EVP_PKEY_DH,
    .name = "DH", .type = CKK_DH, .ck_name = "CKK_DH",
    .keygen_mech = { .mechanism = CKM_DH_PKCS_KEY_PAIR_GEN, },
    .is_asymmetric = true,
    .keygen_prepare = dh_prepare,
    .keygen_cleanup = dh_cleanup,
    .keygen_get_key_size = dh_get_key_size,
    .keygen_add_public_attrs = dh_add_public_attrs,
    .keygen_add_private_attrs = dh_add_private_attrs,
    .sign_verify = false, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_DH,
    .keysize_attr = CKA_PRIME, .keysize_attr_value_len = true,
    .key_keysize_adjust = dh_keysize_adjust,
    .public_attrs = p11sak_public_dh_attrs,
    .private_attrs = p11sak_private_dh_attrs,
    .import_asym_pkey = p11sak_import_dh_pkey,
    .export_asym_pkey = p11sak_export_dh_pkey,
};

static const struct p11tool_objtype p11sak_dsa_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key", .pkey_type = EVP_PKEY_DSA,
    .name = "DSA",  .type = CKK_DSA, .ck_name = "CKK_DSA",
    .keygen_mech = { .mechanism = CKM_DSA_KEY_PAIR_GEN, },
    .is_asymmetric = true,
    .keygen_prepare = dsa_prepare,
    .keygen_cleanup = dsa_cleanup,
    .keygen_get_key_size = dsa_get_key_size,
    .keygen_add_public_attrs = dsa_add_public_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = false,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_DSA,
    .keysize_attr = CKA_PRIME, .keysize_attr_value_len = true,
    .key_keysize_adjust = dsa_keysize_adjust,
    .public_attrs = p11sak_public_dsa_attrs,
    .private_attrs = p11sak_private_dsa_attrs,
    .import_asym_pkey = p11sak_import_dsa_pkey,
    .export_asym_pkey = p11sak_export_dsa_pkey,
};

static const struct p11tool_objtype p11sak_ec_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key", .pkey_type = EVP_PKEY_EC,
    .name = "EC",  .type = CKK_EC, .ck_name = "CKK_EC",
    .keygen_mech = { .mechanism = CKM_EC_KEY_PAIR_GEN, },
    .is_asymmetric = true,
    .keygen_get_key_size = ec_get_key_size,
    .keygen_add_public_attrs = ec_add_public_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_EC,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .public_attrs = p11sak_public_ec_attrs,
    .private_attrs = p11sak_private_ec_attrs,
    .import_asym_pkey = p11sak_import_ec_pkey,
    .export_asym_pkey = p11sak_export_ec_pkey,
};

static const struct p11tool_objtype p11sak_ec_edwards_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "EC-Edwards",  .type = CKK_EC_EDWARDS, .ck_name = "CKK_EC_EDWARDS",
    .keygen_mech = { .mechanism = CKM_EC_EDWARDS_KEY_PAIR_GEN, },
    .is_asymmetric = true,
    .keygen_get_key_size = ec_get_key_size,
    .keygen_add_public_attrs = ec_add_public_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = false,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_EC_EDWARDS,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .public_attrs = p11sak_public_ec_attrs,
    .private_attrs = p11sak_private_ec_attrs,
    .import_asym_pkey = p11sak_import_ec_pkey,
    .export_asym_pkey = p11sak_export_ec_pkey,
};

static const struct p11tool_objtype p11sak_ec_montgomery_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "EC-Montgomery",  .type = CKK_EC_MONTGOMERY,
    .ck_name = "CKK_EC_MONTGOMERY",
    .keygen_mech = { .mechanism = CKM_EC_MONTGOMERY_KEY_PAIR_GEN, },
    .is_asymmetric = true,
    .keygen_get_key_size = ec_get_key_size,
    .keygen_add_public_attrs = ec_add_public_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_EC_MONTGOMERY,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .public_attrs = p11sak_public_ec_attrs,
    .private_attrs = p11sak_private_ec_attrs,
    .import_asym_pkey = p11sak_import_ec_pkey,
    .export_asym_pkey = p11sak_export_ec_pkey,
};

static const struct p11tool_objtype p11sak_ibm_dilithium_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "IBM-Dilithium",  .type = CKK_IBM_PQC_DILITHIUM,
    .ck_name = "CKK_IBM_PQC_DILITHIUM",
    .supports_oqsprovider_pem = true,
    .keygen_mech = { .mechanism = CKM_IBM_DILITHIUM, },
    .is_asymmetric = true,
    .keygen_add_public_attrs = ibm_dilithium_add_public_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = false,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_IBM_PQC_DILITHIUM,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .public_attrs = p11sak_public_ibm_dilithium_attrs,
    .private_attrs = p11sak_private_ibm_dilithium_attrs,
    .import_asym_pem_data = p11sak_import_dilithium_kyber_pem_data,
    .import_asym_pkey = p11sak_import_dilithium_ml_dsa_pkey,
    .export_asym_pem_data = p11sak_export_dilithium_kyber_pem_data,
    .export_asym_pkey = p11sak_export_dilithium_ml_dsa_pkey,
    .pem_name_private = "IBM-DILITHIUM PRIVATE KEY",
    .pem_name_public = "IBM-DILITHIUM PUBLIC KEY",
};

static const struct p11tool_objtype p11sak_ibm_kyber_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "IBM-Kyber",  .type = CKK_IBM_PQC_KYBER,
    .ck_name = "CKK_IBM_PQC_KYBER",
    .keygen_mech = { .mechanism = CKM_IBM_KYBER, },
    .is_asymmetric = true,
    .keygen_add_public_attrs = ibm_kyber_add_public_attrs,
    .sign_verify = false, .encrypt_decrypt = true,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_IBM_PQC_KYBER,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .public_attrs = p11sak_public_ibm_kyber_attrs,
    .private_attrs = p11sak_private_ibm_kyber_attrs,
    .import_asym_pem_data = p11sak_import_dilithium_kyber_pem_data,
    .export_asym_pem_data = p11sak_export_dilithium_kyber_pem_data,
    .pem_name_private = "IBM-KYBER PRIVATE KEY",
    .pem_name_public = "IBM-KYBER PUBLIC KEY",
};

static const struct p11tool_objtype p11sak_ibm_ml_dsa_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "IBM-ML-DSA",  .type = CKK_IBM_ML_DSA,
    .ck_name = "CKK_IBM_ML_DSA",
    .keygen_mech = { .mechanism = CKM_IBM_ML_DSA_KEY_PAIR_GEN, },
    .is_asymmetric = true,
    .keygen_add_public_attrs = ibm_ml_dsa_kem_add_public_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = false,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_IBM_ML_DSA,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .public_attrs = p11sak_public_ibm_ml_dsa_attrs,
    .private_attrs = p11sak_private_ibm_ml_dsa_attrs,
    .import_asym_pkey = p11sak_import_dilithium_ml_dsa_pkey,
    .export_asym_pkey = p11sak_export_dilithium_ml_dsa_pkey,
};

static const struct p11tool_objtype p11sak_ibm_ml_kem_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "IBM-ML-KEM",  .type = CKK_IBM_ML_KEM,
    .ck_name = "CKK_IBM_ML_KEM",
    .keygen_mech = { .mechanism = CKM_IBM_ML_KEM_KEY_PAIR_GEN, },
    .is_asymmetric = true,
    .keygen_add_public_attrs = ibm_ml_dsa_kem_add_public_attrs,
    .sign_verify = false, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_IBM_ML_KEM,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .public_attrs = p11sak_public_ibm_ml_kem_attrs,
    .private_attrs = p11sak_private_ibm_ml_kem_attrs,
    .import_asym_pkey = p11sak_import_ml_kem_pkey,
    .export_asym_pkey = p11sak_export_ml_kem_pkey,
};

static const struct p11tool_objtype p11sak_secret_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "Secret",
    .is_asymmetric = false,
    .filter_attr = CKA_CLASS, .filter_value = CKO_SECRET_KEY,
};

static const struct p11tool_objtype p11sak_public_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "Public",
    .is_asymmetric = true,
    .filter_attr = CKA_CLASS, .filter_value = CKO_PUBLIC_KEY,
};

static const struct p11tool_objtype p11sak_private_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "Private",
    .is_asymmetric = true,
    .filter_attr = CKA_CLASS, .filter_value = CKO_PRIVATE_KEY,
};

static const struct p11tool_objtype p11sak_all_keytype = {
    .obj_typestr = "key", .obj_liststr = "Key",
    .name = "All",
    .filter_attr = (CK_ATTRIBUTE_TYPE)-1,
};

static const struct p11tool_objtype p11sak_x509_certtype = {
    .obj_typestr = "certificate", .obj_liststr = "Certificate",
    .name = "X.509", .type = CKC_X_509, .ck_name = "CKC_X_509",
    .filter_attr = CKA_CERTIFICATE_TYPE, .filter_value = CKC_X_509,
    .cert_attrs = p11sak_x509_attrs,
    .import_x509_data = p11sak_import_x509_attrs,
    .export_x509_data = p11sak_export_x509,
    .extract_x509_pubkey = p11sak_extract_x509_pk,
};

const struct p11tool_objtype *p11sak_keytypes[] = {
    &p11sak_des_keytype,
    &p11sak_3des_keytype,
    &p11sak_generic_keytype,
    &p11sak_sha_1_hmac_keytype,
    &p11sak_sha224_hmac_keytype,
    &p11sak_sha256_hmac_keytype,
    &p11sak_sha384_hmac_keytype,
    &p11sak_sha512_hmac_keytype,
    &p11sak_sha512_224_hmac_keytype,
    &p11sak_sha512_256_hmac_keytype,
    &p11sak_sha3_224_hmac_keytype,
    &p11sak_sha3_256_hmac_keytype,
    &p11sak_sha3_384_hmac_keytype,
    &p11sak_sha3_512_hmac_keytype,
    &p11sak_aes_keytype,
    &p11sak_aes_xts_keytype,
    &p11sak_rsa_keytype,
    &p11sak_dh_keytype,
    &p11sak_dsa_keytype,
    &p11sak_ec_keytype,
    &p11sak_ec_edwards_keytype,
    &p11sak_ec_montgomery_keytype,
    &p11sak_ibm_dilithium_keytype,
    &p11sak_ibm_kyber_keytype,
    &p11sak_ibm_ml_dsa_keytype,
    &p11sak_ibm_ml_kem_keytype,
    NULL,
};

static const struct p11tool_objtype *p11sak_certtypes[] = {
    &p11sak_x509_certtype,
    NULL,
};

static const struct p11tool_opt p11sak_generic_opts[] = {
    { .short_opt = 'h', .long_opt = "help", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_help, },
       .description = "Print this help, then exit." },
    { .short_opt = 'v', .long_opt = "version", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_version, },
      .description = "Print version information, then exit."},
    { .short_opt = 0, .long_opt = NULL, },
};

#define PKCS11_OPTS                                                            \
    { .short_opt = 's', .long_opt = "slot", .required = true,                  \
      .arg =  { .type = ARG_TYPE_NUMBER, .required = true,                     \
                .value.number = &opt_slot, .is_set = opt_slot_is_set,          \
                .name = "SLOT", },                                             \
      .description = "The PKCS#11 slot ID.", },                                \
    { .short_opt = 'p', .long_opt = "pin", .required = false,                  \
      .arg = { .type = ARG_TYPE_STRING, .required = true,                      \
               .value.string = &opt_pin, .name = "USER-PIN" },                 \
      .description = "The PKCS#11 user PIN. If this option is not specified, " \
                     "and environment variable PKCS11_USER_PIN is not set, "   \
                     "then you are prompted for the PIN. If the '--so' "   \
                     "option is specified, specify the SO PIN, or supply "     \
                     "the SO PIN via environment variable PKCS11_SO_PIN.", },  \
    { .short_opt = 0, .long_opt = "force-pin-prompt", .required = false,       \
      .long_opt_val = OPT_FORCE_PIN_PROMPT,                                    \
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,                      \
               .value.plain = &opt_force_pin_prompt, },                        \
      .description = "Enforce user PIN prompt, even if environment variable "  \
                     "PKCS11_USER_PIN is set, or the '-p'/'--pin' option is "  \
                     "specified.", },                                          \
    { .short_opt = 'N', .long_opt = "no-login", .required = false,             \
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,                      \
               .value.plain = &opt_no_login, },                                \
      .description = "Do not login the session. This means that only public "  \
                     "token objects (CKA_PRIVATE=FALSE) can be accessed.", },  \
    { .short_opt = 0, .long_opt = "so", .required = false,                     \
      .long_opt_val = OPT_SO,                                                  \
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,                      \
               .value.plain = &opt_so, },                                      \
      .description = "Login as SO (security officer). Option '-p'/'--pin' "    \
                     "must specify the SO PIN, or if the '-p'/'--pin' option " \
                     "is not specified, environment variable PKCS11_SO_PIN "   \
                     "is used. If PKCS11_SO_PIN is not set, then you are " \
                     "prompted for the SO PIN. SO can only access public "     \
                     "token objects (CKA_PRIVATE=FALSE).", }

#define KEY_FILTER_OPTS                                                        \
    { .short_opt = 'L', .long_opt = "label", .required = false,                \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_label, .name = "LABEL", },                \
      .description = "Filter the keys by label (optional). You can use "       \
                     "wildcards ('*' and '?') in the label specification. To " \
                     "specify a wildcard character that should not be treated "\
                     "as a wildcard, it must be escaped using a backslash "    \
                     "('\\*' or '\\?'). Also, a backslash character that "     \
                     "should not be treated a an escape character must be "    \
                     "escaped ('\\\\').", },                                   \
    { .short_opt = 'i', .long_opt = "id", .required = false,                   \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_id, .name = "ID", },                      \
      .description = "Filter the keys by ID (optional). Specify a hex string " \
                     "(not prefixed with 0x) of any number of bytes.", },      \
    { .short_opt = 'a', .long_opt = "attr", .required = false,                 \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_attr, .name = "ATTRS", },                 \
      .description = "Filter the key by its boolean attribute values:\n"       \
                     "P L M B Y R E D G C V O W U S A X N T I H K Z (optional)"\
                     ". Specify a set of these letters without any blanks in " \
                     "between. See below for the meaning of the attribute "    \
                     "letters. Attributes that are not specified are not "     \
                     "used to filter the keys.", }

#define CERT_FILTER_OPTS                                                       \
    { .short_opt = 'L', .long_opt = "label", .required = false,                \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_label, .name = "LABEL", },                \
      .description = "Filter the certificates by label (optional). You can use "\
                     "wildcards ('*' and '?') in the label specification. To " \
                     "specify a wildcard character that should not be treated "\
                     "as a wildcard, it must be escaped using a backslash "    \
                     "('\\*' or '\\?'). Also, a backslash character that "     \
                     "should not be treated a an escape character must be "    \
                     "escaped ('\\\\').", },                                   \
    { .short_opt = 'i', .long_opt = "id", .required = false,                   \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_id, .name = "ID", },                      \
      .description = "Filter the certificates by ID (optional). Specify a hex "\
                     "string (not prefixed with 0x) of any number of bytes.", },\
    { .short_opt = 'a', .long_opt = "attr", .required = false,                 \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_attr, .name = "ATTRS", },                 \
      .description = "Filter the certificate by its boolean attribute values: "\
                     "P M B Y T (optional). "                                  \
                     "Specify a set of these letters without any blanks in "   \
                     "between. See below for the meaning of the attribute "    \
                     "letters. Attributes that are not specified are not "     \
                     "used to filter the certificates.", }

#define KEYGEN_KEYTYPES(args_prefix)                                           \
    { .value = "des", .args = NULL,                                            \
      .private = { .ptr = &p11sak_des_keytype, }, },                           \
    { .value = "3des", .args = NULL,                                           \
      .private = { .ptr = &p11sak_3des_keytype }, },                           \
    { .value = "generic", .args = args_prefix##_generic_args,                  \
      .private = { .ptr = &p11sak_generic_keytype }, },                        \
    { .value = "sha-1-hmac", .args = args_prefix##_generic_args,               \
      .private = { .ptr = &p11sak_sha_1_hmac_keytype }, },                     \
    { .value = "sha224-hmac", .args = args_prefix##_generic_args,              \
      .private = { .ptr = &p11sak_sha224_hmac_keytype }, },                    \
    { .value = "sha256-hmac", .args = args_prefix##_generic_args,              \
      .private = { .ptr = &p11sak_sha256_hmac_keytype }, },                    \
    { .value = "sha384-hmac", .args = args_prefix##_generic_args,              \
      .private = { .ptr = &p11sak_sha384_hmac_keytype }, },                    \
    { .value = "sha512-hmac", .args = args_prefix##_generic_args,              \
      .private = { .ptr = &p11sak_sha512_hmac_keytype }, },                    \
    { .value = "sha512/224-hmac", .args = args_prefix##_generic_args,          \
      .private = { .ptr = &p11sak_sha512_224_hmac_keytype }, },                \
    { .value = "sha512/256-hmac", .args = args_prefix##_generic_args,          \
      .private = { .ptr = &p11sak_sha512_256_hmac_keytype }, },                \
    { .value = "sha3-224-hmac", .args = args_prefix##_generic_args,            \
      .private = { .ptr = &p11sak_sha3_224_hmac_keytype }, },                  \
    { .value = "sha3-256-hmac", .args = args_prefix##_generic_args,            \
      .private = { .ptr = &p11sak_sha3_256_hmac_keytype }, },                  \
    { .value = "sha3-384-hmac", .args = args_prefix##_generic_args,            \
      .private = { .ptr = &p11sak_sha3_384_hmac_keytype }, },                  \
    { .value = "sha3-512-hmac", .args = args_prefix##_generic_args,            \
      .private = { .ptr = &p11sak_sha3_512_hmac_keytype }, },                  \
    { .value = "aes", .args = args_prefix##_aes_args,                          \
      .private = { .ptr = &p11sak_aes_keytype }, },                            \
    { .value = "aes-xts", .args = args_prefix##_aes_xts_args,                  \
      .private = { .ptr = &p11sak_aes_xts_keytype }, },                        \
    { .value = "rsa", .args = args_prefix##_rsa_args,                          \
      .private = { .ptr = &p11sak_rsa_keytype }, },                            \
    { .value = "dh", .args = args_prefix##_dh_args,                            \
      .private = { .ptr = &p11sak_dh_keytype }, },                             \
    { .value = "dsa", .args = args_prefix##_dsa_args,                          \
      .private = { .ptr = &p11sak_dsa_keytype }, },                            \
    { .value = "ec", .args = args_prefix##_ec_args,                            \
      .private = { .ptr = &p11sak_ec_keytype }, },                             \
    { .value = "ec-edwards", .args = args_prefix##_ec_edwards_args,            \
      .private = { .ptr = &p11sak_ec_edwards_keytype }, },                     \
    { .value = "ec-montgomery", .args = args_prefix##_ec_montgomery_args,      \
      .private = { .ptr = &p11sak_ec_montgomery_keytype }, },                  \
    { .value = "ibm-dilithium", .args = args_prefix##_ibm_dilithium_args,      \
      .private = { .ptr = &p11sak_ibm_dilithium_keytype }, },                  \
    { .value = "ibm-kyber", .args = args_prefix##_ibm_kyber_args,              \
      .private = { .ptr = &p11sak_ibm_kyber_keytype }, },                      \
    { .value = "ibm-ml-dsa", .args = args_prefix##_ibm_ml_dsa_args,            \
      .private = { .ptr = &p11sak_ibm_ml_dsa_keytype }, },                     \
    { .value = "ibm-ml-kem", .args = args_prefix##_ibm_ml_kem_args,            \
      .private = { .ptr = &p11sak_ibm_ml_kem_keytype }, }

#define GROUP_KEYTYPES                                                         \
    { .value = "public", .args = NULL,                                         \
       .private = { .ptr = &p11sak_public_keytype }, },                        \
    { .value = "private", .args = NULL,                                        \
      .private = { .ptr = &p11sak_private_keytype }, },                        \
    { .value = "secret", .args = NULL,                                         \
      .private = { .ptr = &p11sak_secret_keytype }, },                         \
    { .value = "all", .args = NULL,                                            \
      .private = { .ptr = &p11sak_all_keytype }, }

#define GROUP_CERTTYPES                                                        \
    { .value = "x509", .args = NULL,                                           \
      .private = { .ptr = &p11sak_x509_certtype }, }

static const struct p11tool_opt p11sak_generate_key_opts[] = {
    PKCS11_OPTS,
    { .short_opt = 'L', .long_opt = "label", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_label, .name = "LABEL", },
      .description = "The label of the key to be generated. For asymmetric "
                     "keys set individual labels for public and private key, "
                     "separated by a colon (':'): 'PUB_LABEL:PRIV_LABEL'. If "
                     "only one label is specified for an asymmetric key, the "
                     "label is automatically extended by ':pub' and ':prv' for "
                     "the public and private keys respectively. To use the "
                     "same label for public and private keys specify the equal "
                     "sign ('=') for the private key label part: "
                     "'LABEL:='.", },
    { .short_opt = 'a', .long_opt = "attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the key:\n"
                     "P M B Y R E D G C V O W U S X T I H K (optional). "
                     "Specify a set of these letters without any blanks in "
                     "between. See below for the meaning of the attribute "
                     "letters. For asymmetric keys set individual key "
                     "attributes for public and private key separated by a "
                     "colon (':'): 'PUB-ATTRS:PRIV-ATTRS'.", },
    { .short_opt = 'i', .long_opt = "id", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_id, .name = "ID", },
      .description = "The ID of the key to be generated. Specify a hex string "
                     "(not prefixed with 0x) of any number of bytes. For "
                     "asymmetric keys the same ID is set for both, the public "
                     "and the private key.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_arg p11sak_generate_generic_args[] = {
    { .name = "KEYBITS", .type = ARG_TYPE_NUMBER, .required = true,
      .value.number = &opt_keybits_num,
      .description = "Size of the generic key in bits.", },
    { .name = NULL, },
};

static const struct p11tool_enum_value p11sak_aes_keybits[] = {
    { .value = "128", .args = NULL, .private = { .num = 128 }, },
    { .value = "192", .args = NULL, .private = { .num = 192 }, },
    { .value = "256", .args = NULL, .private = { .num = 256 }, },
    { .value = NULL, },
};

static const struct p11tool_arg p11sak_generate_aes_args[] = {
    { .name = "KEYBITS", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_aes_keybits,
      .value.enum_value = &opt_keybits,
      .description = "Size of the AES key in bits:", },
    { .name = NULL, },
};

static const struct p11tool_enum_value p11sak_aes_xts_keybits[] = {
    { .value = "128", .args = NULL, .private = { .num = 128 * 2 }, },
    { .value = "256", .args = NULL, .private = { .num = 256 * 2 }, },
    { .value = NULL, },
};

static const struct p11tool_arg p11sak_generate_aes_xts_args[] = {
    { .name = "KEYBITS", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_aes_xts_keybits,
      .value.enum_value = &opt_keybits,
      .description = "Size of the AES-XTS key in bits:", },
    { .name = NULL, },
};

#define STRINGIFY(a)    _STRINGIFY(a)
#define _STRINGIFY(a)   #a

static const struct p11tool_arg p11sak_generate_rsa_args[] = {
    { .name = "KEYBITS", .type = ARG_TYPE_NUMBER, .required = true,
      .value.number = &opt_keybits_num,
      .description = "Size of the RSA key in bits. Must be from 512 to "
                      STRINGIFY(OPENSSL_RSA_MAX_MODULUS_BITS) " and a "
                     "multiple of 8 bits. Typical key sizes are 512, 1024, "
                     "2048, 4096, or 8192.", },
    { .name = "PUBL-EXP", .type = ARG_TYPE_NUMBER, .required = false,
      .value.number = &opt_exponent,
      .description = "The public exponent for RSA (optional).", },
    { .name = NULL, },
};

static const struct p11tool_enum_value p11sak_dh_group[] = {
    { .value = "ffdhe2048", .args = NULL,
      .private = { .num = NID_ffdhe2048 }, },
    { .value = "ffdhe3072", .args = NULL,
      .private = { .num = NID_ffdhe3072 }, },
    { .value = "ffdhe4096", .args = NULL,
      .private = { .num = NID_ffdhe4096 }, },
    { .value = "ffdhe6144", .args = NULL,
      .private = { .num = NID_ffdhe6144 }, },
    { .value = "ffdhe8192", .args = NULL,
      .private = { .num = NID_ffdhe6144 }, },
#ifdef NID_modp_1536
    { .value = "modp1536", .args = NULL,
      .private = { .num = NID_modp_1536 }, },
#endif
#ifdef NID_modp_2048
    { .value = "modp2048", .args = NULL,
      .private = { .num = NID_modp_2048 }, },
#endif
#ifdef NID_modp_3072
    { .value = "modp3072", .args = NULL,
      .private = { .num = NID_modp_3072 }, },
#endif
#ifdef NID_modp_4096
    { .value = "modp4096", .args = NULL,
      .private = { .num = NID_modp_4096 }, },
#endif
#ifdef NID_modp_6144
    { .value = "modp6144", .args = NULL,
      .private = { .num = NID_modp_6144 }, },
#endif
#ifdef NID_modp_8192
    { .value = "modp8192", .args = NULL,
      .private = { .num = NID_modp_8192 }, },
#endif
    { .value = "DH-PARAM-PEM-FILE", .args = NULL,
      .private = { .num = 0 },
      .any_value = &opt_pem_file, },
    { .value = NULL, },
};

static const struct p11tool_arg p11sak_generate_dh_args[] = {
    { .name = "GROUP", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_dh_group,
      .value.enum_value = &opt_group,
      .description = "The Diffie-Hellman FFC group name "
                     "or the name of a DH parameters PEM file:", },
    { .name = "PRIV-BITS", .type = ARG_TYPE_NUMBER, .required = false,
      .value.number = &opt_keybits_num,
      .description = "Size of the DH private key in bits (optional).",},
    { .name = NULL, },
};

static const struct p11tool_arg p11sak_generate_dsa_args[] = {
    { .name = "DSA-PARAM-PEM-FILE", .type = ARG_TYPE_STRING, .required = true,
      .value.string = &opt_pem_file,
      .description = "The name of a DSA parameters PEM file.", },
    { .name = NULL, },
};

#define DECLARE_CURVE_INFO(name, size)                                         \
    static const struct curve_info name ## _info = {                           \
        .oid = name, .oid_len = sizeof(name), .bitsize = size,                 \
    }

#define DECLARE_CURVE_VALUE(name)                                              \
    { .value = # name, .args = NULL, .private = { .ptr = &name ## _info, }, }
#define DECLARE_CURVE_VALUE2(name, def)                                        \
    { .value = # name, .args = NULL, .private = { .ptr = &def ## _info, }, }

DECLARE_CURVE_INFO(prime256v1, 256);
DECLARE_CURVE_INFO(prime192v1, 192);
DECLARE_CURVE_INFO(secp224r1, 224);
DECLARE_CURVE_INFO(secp384r1, 384);
DECLARE_CURVE_INFO(secp521r1, 521);
DECLARE_CURVE_INFO(secp256k1, 256);
DECLARE_CURVE_INFO(brainpoolP160r1, 160);
DECLARE_CURVE_INFO(brainpoolP160t1, 160);
DECLARE_CURVE_INFO(brainpoolP192r1, 192);
DECLARE_CURVE_INFO(brainpoolP192t1, 192);
DECLARE_CURVE_INFO(brainpoolP224r1, 224);
DECLARE_CURVE_INFO(brainpoolP224t1, 224);
DECLARE_CURVE_INFO(brainpoolP256r1, 256);
DECLARE_CURVE_INFO(brainpoolP256t1, 256);
DECLARE_CURVE_INFO(brainpoolP320r1, 320);
DECLARE_CURVE_INFO(brainpoolP320t1, 320);
DECLARE_CURVE_INFO(brainpoolP384r1, 384);
DECLARE_CURVE_INFO(brainpoolP384t1, 384);
DECLARE_CURVE_INFO(brainpoolP512r1, 512);
DECLARE_CURVE_INFO(brainpoolP512t1, 512);
DECLARE_CURVE_INFO(curve25519, 256);
DECLARE_CURVE_INFO(curve448, 448);
DECLARE_CURVE_INFO(ed25519, 256);
DECLARE_CURVE_INFO(ed448, 448);
DECLARE_CURVE_INFO(bls12_381, 384);

static const struct p11tool_enum_value p11sak_ec_curves[] = {
    DECLARE_CURVE_VALUE(prime256v1),
    DECLARE_CURVE_VALUE(prime192v1),
    DECLARE_CURVE_VALUE(secp224r1),
    DECLARE_CURVE_VALUE(secp384r1),
    DECLARE_CURVE_VALUE(secp521r1),
    DECLARE_CURVE_VALUE(secp256k1),
    DECLARE_CURVE_VALUE(brainpoolP160r1),
    DECLARE_CURVE_VALUE(brainpoolP160t1),
    DECLARE_CURVE_VALUE(brainpoolP192r1),
    DECLARE_CURVE_VALUE(brainpoolP192t1),
    DECLARE_CURVE_VALUE(brainpoolP224r1),
    DECLARE_CURVE_VALUE(brainpoolP224t1),
    DECLARE_CURVE_VALUE(brainpoolP256r1),
    DECLARE_CURVE_VALUE(brainpoolP256t1),
    DECLARE_CURVE_VALUE(brainpoolP320r1),
    DECLARE_CURVE_VALUE(brainpoolP320t1),
    DECLARE_CURVE_VALUE(brainpoolP384r1),
    DECLARE_CURVE_VALUE(brainpoolP384t1),
    DECLARE_CURVE_VALUE(brainpoolP512r1),
    DECLARE_CURVE_VALUE(brainpoolP512t1),
    DECLARE_CURVE_VALUE(curve25519),
    DECLARE_CURVE_VALUE(curve448),
    DECLARE_CURVE_VALUE(ed25519),
    DECLARE_CURVE_VALUE(ed448),
    DECLARE_CURVE_VALUE2(bls12-381, bls12_381),
    { .value = NULL, },
};

static const struct p11tool_enum_value p11sak_ec_edwards_curves[] = {
    DECLARE_CURVE_VALUE(ed25519),
    DECLARE_CURVE_VALUE(ed448),
    { .value = NULL, },
};

static const struct p11tool_enum_value p11sak_ec_montgomery_curves[] = {
    DECLARE_CURVE_VALUE(curve25519),
    DECLARE_CURVE_VALUE(curve448),
    { .value = NULL, },
};

static const struct p11tool_arg p11sak_generate_ec_args[] = {
    { .name = "CURVE", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_ec_curves,
      .value.enum_value = &opt_curve,
      .description = "The curve name. One of the following:", },
    { .name = NULL, },
};

static const struct p11tool_arg p11sak_generate_ec_edwards_args[] = {
    { .name = "CURVE", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_ec_edwards_curves,
      .value.enum_value = &opt_curve,
      .description = "The curve name. One of the following:", },
    { .name = NULL, },
};

static const struct p11tool_arg p11sak_generate_ec_montgomery_args[] = {
    { .name = "CURVE", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_ec_montgomery_curves,
      .value.enum_value = &opt_curve,
      .description = "The curve name. One of the following:", },
    { .name = NULL, },
};

static const struct p11tool_arg p11sak_generate_ibm_dilithium_args[] = {
    { .name = "VERSION", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11tool_ibm_dilithium_versions,
      .value.enum_value = &opt_pqc_version,
      .description = "The version of the IBM Dilithium key pair:", },
    { .name = NULL, },
};

static const struct p11tool_arg p11sak_generate_ibm_kyber_args[] = {
    { .name = "VERSION", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11tool_ibm_kyber_versions,
      .value.enum_value = &opt_pqc_version,
      .description = "The version of the IBM Kyber key pair:", },
    { .name = NULL, },
};

static const struct p11tool_arg p11sak_generate_ibm_ml_dsa_args[] = {
    { .name = "VERSION", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11tool_ibm_ml_dsa_versions,
      .value.enum_value = &opt_pqc_version,
      .description = "The version of the IBM ML-DSA key pair:", },
    { .name = NULL, },
};

static const struct p11tool_arg p11sak_generate_ibm_ml_kem_args[] = {
    { .name = "VERSION", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11tool_ibm_ml_kem_versions,
      .value.enum_value = &opt_pqc_version,
      .description = "The version of the IBM ML-KEM key pair:", },
    { .name = NULL, },
};

static const struct p11tool_enum_value p11sak_generate_key_keytypes[] = {
    KEYGEN_KEYTYPES(p11sak_generate),
    { .value = NULL, },
};

static const struct p11tool_arg p11sak_generate_key_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_generate_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the key. One of the following:", },
    { .name = NULL },
};

static const struct p11tool_opt p11sak_list_key_opts[] = {
    PKCS11_OPTS,
    KEY_FILTER_OPTS,
    { .short_opt = 'l', .long_opt = "long", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_long, },
      .description = "List keys in long (detailed) format.", },
    { .short_opt = 0, .long_opt = "detailed-uri", .required = false,
      .long_opt_val = OPT_DETAILED_URI,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_detailed_uri, },
      .description = "Show detailed PKCS#11 URI.", },
    { .short_opt = 'm', .long_opt = "hsm-mkvp", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_hsm_mkvp, },
      .description = "Show the HSM master key verification patterns (MKVPs) of "
                     "the key objects. Only valid for secure key tokens, such "
                     "as the CCA and EP11 tokens.", },
    { .short_opt = 'e', .long_opt = "ep11-session-id", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_ep11_session_id, },
      .description = "Show the EP11 session-IDs of the key objects. Only valid "
                     "for an EP11 token.", },
    { .short_opt = 'S', .long_opt = "sort", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_sort, .name = "SORT-SPEC" },
      .description = "Sort the keys by label, key type, object class, and/or "
                     "key size. Specify a sort selection of up to 4 fields, "
                     "each represented by its corresponding letter, separated "
                     "by comma (','):\n"
                     "- label:        'l'\n"
                     "- key type:     'k'\n"
                     "- object class: 'c'\n"
                     "- key size:     's'\n"
                     " The sort order ('a' = ascending (default), 'd' = "
                     "descending) can be appended  to the  field designator by "
                     "a colon (':').\n"
                     "Example: 'l:a,k:d' sorts by label in ascending order "
                     "and then by key type in descending order.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_list_cert_opts[] = {
    PKCS11_OPTS,
    CERT_FILTER_OPTS,
    { .short_opt = 'l', .long_opt = "long", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_long, },
      .description = "List certificates in long (detailed) format.", },
    { .short_opt = 0, .long_opt = "detailed-uri", .required = false,
      .long_opt_val = OPT_DETAILED_URI,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_detailed_uri, },
      .description = "Show detailed PKCS#11 URI.", },
    { .short_opt = 'S', .long_opt = "sort", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_sort, .name = "SORT-SPEC" },
      .description = "Sort the certs by label and/or subject common name (CN). "
                     "Specify a sort selection of up to 2 fields, "
                     "each represented by its corresponding letter, separated "
                     "by comma (','):\n"
                     "- label:            'l'\n"
                     "- subj common name: 'n'\n"
                     "The sort order ('a' = ascending (default), 'd' = "
                     "descending) can be appended  to the  field designator by "
                     "a colon (':').\n"
                     "Example: 'l:a,n:d' sorts by label in ascending order "
                     "and then by common name in descending order.", },
    { .short_opt = 0, .long_opt = NULL, },
};

#define null_generic_args           NULL
#define null_aes_args               NULL
#define null_aes_xts_args           NULL
#define null_rsa_args               NULL
#define null_dh_args                NULL
#define null_dsa_args               NULL
#define null_ec_args                NULL
#define null_ec_edwards_args        NULL
#define null_ec_montgomery_args     NULL
#define null_ibm_dilithium_args     NULL
#define null_ibm_kyber_args         NULL
#define null_ibm_ml_dsa_args        NULL
#define null_ibm_ml_kem_args        NULL

static const struct p11tool_enum_value
                        p11sak_list_remove_set_copy_export_key_keytypes[] = {
    KEYGEN_KEYTYPES(null),
    GROUP_KEYTYPES,
    { .value = NULL, },
};

static const struct p11tool_enum_value p11sak_private_key_keytypes[] = {
    { .value = "rsa", .args = NULL,
      .private = { .ptr = &p11sak_rsa_keytype }, },
    { .value = "dh", .args = NULL,
      .private = { .ptr = &p11sak_dh_keytype }, },
    { .value = "dsa", .args = NULL,
      .private = { .ptr = &p11sak_dsa_keytype }, },
    { .value = "ec", .args = NULL,
      .private = { .ptr = &p11sak_ec_keytype }, },
    { .value = "ec-edwards", .args = NULL,
      .private = { .ptr = &p11sak_ec_edwards_keytype }, },
    { .value = "ec-montgomery", .args = NULL,
      .private = { .ptr = &p11sak_ec_montgomery_keytype }, },
    { .value = "ibm-dilithium", .args = NULL,
      .private = { .ptr = &p11sak_ibm_dilithium_keytype }, },
    { .value = "ibm-kyber", .args = NULL,
      .private = { .ptr = &p11sak_ibm_kyber_keytype }, },
    { .value = "ibm-ml-dsa", .args = NULL,
      .private = { .ptr = &p11sak_ibm_ml_dsa_keytype }, },
    { .value = "ibm-ml-kem", .args = NULL,
      .private = { .ptr = &p11sak_ibm_ml_kem_keytype }, },
    { .value = "private", .args = NULL,
      .private = { .ptr = &p11sak_private_keytype }, },
    { .value = "all", .args = NULL,
      .private = { .ptr = &p11sak_all_keytype }, },
    { .value = NULL, },
};

static const struct p11tool_enum_value
                        p11sak_list_remove_set_copy_export_cert_certtypes[] = {
    GROUP_CERTTYPES,
    { .value = NULL, },
};

static const struct p11tool_arg p11sak_list_key_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the keys to list (optional). If no key type "
                     "is specified, all key types are listed.", },
    { .name = NULL },
};

static const struct p11tool_arg p11sak_list_cert_args[] = {
    { .name = "CERTTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_cert_certtypes,
      .value.enum_value = &opt_certtype,
      .description = "The type of the certificates to list (optional). If no "
                     "certificate type is specified, certificate type x509 "
                     "is used, because currently no other certificate types "
                     "are supported.", },
    { .name = NULL },
};

static const struct p11tool_opt p11sak_remove_key_opts[] = {
    PKCS11_OPTS,
    KEY_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to remove a key. "
                     "Use with care, all keys matching the filter are "
                     "removed!", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_remove_cert_opts[] = {
    PKCS11_OPTS,
    CERT_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to remove a certificate. "
                     "Use with care, all certificates matching the filter are "
                     "removed!", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_arg p11sak_remove_key_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the keys to select for removal (optional). "
                     "If no key type is specified, all key types are "
                     "selected.", },
    { .name = NULL },
};

static const struct p11tool_arg p11sak_remove_cert_args[] = {
    { .name = "CERTTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_cert_certtypes,
      .value.enum_value = &opt_certtype,
      .description = "The type of the certificates to select for removal "
                     "(optional). If no certificate type is specified, "
                     "certificate type x509 is used, because currently no "
                     "other certificate types are supported.", },
    { .name = NULL },
};

static const struct p11tool_opt p11sak_set_key_attr_opts[] = {
    PKCS11_OPTS,
    KEY_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to set the attributes "
                     "of a key. Use with care, all keys matching the filter "
                     "are changed!", },
    { .short_opt = 'A', .long_opt = "new-attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the key (optional):\n"
                     "P M B Y R E D G C V O W U S X T I K. "
                     "Specify a set of these letters without any blanks in "
                     "between. See below for the meaning of the attribute "
                     "letters. Restrictions on attribute values may apply.", },
    { .short_opt = 'l', .long_opt = "new-label", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_label, .name = "LABEL", },
      .description = "The new label to set for the key (optional).", },
    { .short_opt = 'I', .long_opt = "new-id", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_id, .name = "ID", },
      .description = "The new ID to set for the key (optional).", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_set_cert_attr_opts[] = {
    PKCS11_OPTS,
    CERT_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to set the attributes "
                     "of a certificate. Use with care, all certificates "
                     "matching the filter are changed!", },
    { .short_opt = 'A', .long_opt = "new-attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the certificate "
                     "(optional): P M B Y. "
                     "Specify a set of these letters without any blanks in "
                     "between. See below for the meaning of the attribute "
                     "letters. Restrictions on attribute values may apply.", },
    { .short_opt = 'l', .long_opt = "new-label", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_label, .name = "LABEL", },
      .description = "The new label to set for the certificate (optional).", },
    { .short_opt = 'I', .long_opt = "new-id", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_id, .name = "ID", },
      .description = "The new ID to set for the certificate (optional).", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_arg p11sak_set_key_attr_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the keys to select for update (optional). "
                     "If no key type is specified, all key types are "
                     "selected.", },
    { .name = NULL },
};

static const struct p11tool_arg p11sak_set_cert_attr_args[] = {
    { .name = "CERTTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_cert_certtypes,
      .value.enum_value = &opt_certtype,
      .description = "The type of the certificates to select for update "
                     "(optional). If no certificate type is specified, "
                     "certificate type x509 is used, because currently no "
                     "other certificate types are supported.", },
    { .name = NULL },
};

static const struct p11tool_opt p11sak_copy_key_opts[] = {
    PKCS11_OPTS,
    KEY_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to copy a key. Use with "
                     "care, all keys matching the filter are copied!", },
    { .short_opt = 'A', .long_opt = "new-attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the copied key "
                     "(optional):\n P L M B Y R E D G C V O W U S A X N T I. "
                     "Specify a set of these letters without any blanks in "
                     "between. See below for the meaning of the attribute "
                     "letters. Restrictions on attribute values may apply.", },
    { .short_opt = 'l', .long_opt = "new-label", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_label, .name = "LABEL", },
      .description = "The new label to set for the copied key (optional).", },
    { .short_opt = 'I', .long_opt = "new-id", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_id, .name = "ID", },
      .description = "The new ID to set for the copied key (optional).", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_copy_cert_opts[] = {
    PKCS11_OPTS,
    CERT_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to copy a certificate. "
                     "Use with care, all certificates matching the filter "
                     "are copied!", },
    { .short_opt = 'A', .long_opt = "new-attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the copied certificate "
                     "(optional): P M B Y. "
                     "Specify a set of these letters without any blanks in "
                     "between. See below for the meaning of the attribute "
                     "letters. Restrictions on attribute values may apply.", },
    { .short_opt = 'l', .long_opt = "new-label", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_label, .name = "LABEL", },
      .description = "The new label to set for the copied certificate "
                     "(optional).", },
    { .short_opt = 'I', .long_opt = "new-id", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_id, .name = "ID", },
      .description = "The new ID to set for the copied certificate (optional).", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_arg p11sak_copy_key_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the keys to select for copying (optional). "
                     "If no key type is specified, all key types are "
                     "selected.", },
    { .name = NULL },
};

static const struct p11tool_arg p11sak_copy_cert_args[] = {
    { .name = "CERTTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_cert_certtypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the certificates to select for copying "
                     "(optional). If no certificate type is specified, "
                     "certificate type x509 is used, because currently no "
                     "other certificate types are supported.", },
    { .name = NULL },
};

static const struct p11tool_opt p11sak_import_key_opts[] = {
    PKCS11_OPTS,
    { .short_opt = 'L', .long_opt = "label", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_label, .name = "LABEL", },
      .description = "The label of the key to be imported.", },
    { .short_opt = 'a', .long_opt = "attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the key:\n"
                     "P M B Y R E D G C V O W U S X T I H K (optional). "
                     "Specify a set of these letters without any blanks in "
                     "between. See below for the meaning of the attribute "
                     "letters.", },
    { .short_opt = 'i', .long_opt = "id", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_id, .name = "ID", },
      .description = "The ID of the key to be imported. Specify a hex string "
                     "(not prefixed with 0x) of any number of bytes.", },
    { .short_opt = 'F', .long_opt = "file", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_file, .name = "FILENAME", },
      .description = "The file name of the file that contains the key to be "
                     "imported. For symmetric keys, this is a binary file "
                     "containing the key material in clear. For asymmetric "
                     "keys, this is an OpenSSL PEM file containing a "
                     "public or private key. PEM files can optionally be "
                     "password protected. Specify the PEM password with the "
                     "'-P'/'--pem-password' option or environment variable "
                     "P11SAK_PEM_PASSWORD. If the PEM file is password "
                     "protected, but no PEM password is specified, you are "
                     "prompted for the PEM password.", },
    { .short_opt = 'P', .long_opt = "pem-password", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_pem_password, .name = "PASSWORD", },
      .description = "The password of the PEM file specified with the "
                     "'-F'/'--file' option. If the PEM file is password "
                     "protected, but this option is not specified, nor "
                     "environment variable P11SAK_PEM_PASSWORD is set, you "
                     "are prompted for the PEM password.", },
    { .short_opt = 0, .long_opt = "force-pem-pwd-prompt", .required = false,
      .long_opt_val = OPT_FORCE_PEM_PWD_PROMPT,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_force_pem_pwd_prompt, },
      .description = "Enforce PEM password prompt, even if environment "
                     "variable P11SAK_PEM_PASSWORD is set, or the "
                     "'-P'/'--pem-password' option is specified.", },
    { .short_opt = 'o', .long_opt = "opaque", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_opaque, },
      .description = "The key material in the file specified with the "
                     "'-F'/'--file' option is an opaque secure key blob. "
                     "Not all tokens support this.", },
    { .short_opt = 0, .long_opt = "oqsprovider-pem", .required = false,
      .long_opt_val = OPT_OQSPROVIDER_PEM,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_oqsprovider_pem, },
      .description = "The key material in the PEM file specified with the "
                     "'-F'/'--file' option is in the 'oqsprovider' format. "
                     "This option is only valid for the 'ibm-dilithium' "
                     "keytype. PEM files in 'oqsprovider' format are only "
                     "supported when the 'oqsprovider' has been configured "
                     "with OpenSSL 3.0 or later. This is an experimental "
                     "feature, it may change in an incompatible way in the "
                     "future!", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_import_cert_opts[] = {
    PKCS11_OPTS,
    { .short_opt = 'L', .long_opt = "label", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_label, .name = "LABEL", },
      .description = "The label of the certificate to be imported.", },
    { .short_opt = 'a', .long_opt = "attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the certificate: "
                     "P M B Y (optional). "
                     "Specify a set of these letters without any blanks in "
                     "between. See below for the meaning of the attribute "
                     "letters.", },
    { .short_opt = 'i', .long_opt = "id", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_id, .name = "ID", },
      .description = "The ID of the certificate to be imported. Specify a hex "
                     "string (not prefixed with 0x) of any number of bytes.", },
    { .short_opt = 'F', .long_opt = "file", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_file, .name = "FILENAME", },
      .description = "The file name of the file that contains the certificate "
                     "to be imported. Supported input formats are PEM and binary "
                     "(DER-encoded). The format is automatically detected.", },
    { .short_opt = 'C', .long_opt = "ca-cert", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_cacert, },
      .description = "The certificate is a Certificate Authority (CA) "
                     "certificate.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_enum_value p11sak_import_asym_types[] = {
    { .value = "public", .args = NULL, .private = { .num = false }, },
    { .value = "private", .args = NULL, .private = { .num = true }, },
    { .value = NULL, },
};

static const struct p11tool_arg p11sak_import_asym_args[] = {
    { .name = "KIND", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_import_asym_types,
      .value.enum_value = &opt_asym_kind,
      .description = "The kind of the asymmetric key to import.", },
    { .name = NULL, },
};

#define IMPORT_KEYTYPES(asym_args)                                             \
    { .value = "des", .args = NULL,                                            \
      .private = { .ptr = &p11sak_des_keytype, }, },                           \
    { .value = "3des", .args = NULL,                                           \
      .private = { .ptr = &p11sak_3des_keytype }, },                           \
    { .value = "generic", .args = NULL,                                        \
      .private = { .ptr = &p11sak_generic_keytype }, },                        \
    { .value = "sha-1-hmac", .args = NULL,                                     \
      .private = { .ptr = &p11sak_sha_1_hmac_keytype }, },                     \
    { .value = "sha224-hmac", .args = NULL,                                    \
      .private = { .ptr = &p11sak_sha224_hmac_keytype }, },                    \
    { .value = "sha256-hmac", .args = NULL,                                    \
      .private = { .ptr = &p11sak_sha256_hmac_keytype }, },                    \
    { .value = "sha384-hmac", .args = NULL,                                    \
      .private = { .ptr = &p11sak_sha384_hmac_keytype }, },                    \
    { .value = "sha512-hmac", .args = NULL,                                    \
      .private = { .ptr = &p11sak_sha512_hmac_keytype }, },                    \
    { .value = "sha512/224-hmac", .args = NULL,                                \
      .private = { .ptr = &p11sak_sha512_224_hmac_keytype }, },                \
    { .value = "sha512/256-hmac", .args = NULL,                                \
      .private = { .ptr = &p11sak_sha512_256_hmac_keytype }, },                \
    { .value = "sha3-224-hmac", .args = NULL,                                  \
      .private = { .ptr = &p11sak_sha3_224_hmac_keytype }, },                  \
    { .value = "sha3-256-hmac", .args = NULL,                                  \
      .private = { .ptr = &p11sak_sha3_256_hmac_keytype }, },                  \
    { .value = "sha3-384-hmac", .args = NULL,                                  \
      .private = { .ptr = &p11sak_sha3_384_hmac_keytype }, },                  \
    { .value = "sha3-512-hmac", .args = NULL,                                  \
      .private = { .ptr = &p11sak_sha3_512_hmac_keytype }, },                  \
    { .value = "aes", .args = NULL,                                            \
      .private = { .ptr = &p11sak_aes_keytype }, },                            \
    { .value = "aes-xts", .args = NULL,                                        \
      .private = { .ptr = &p11sak_aes_xts_keytype }, },                        \
    { .value = "rsa", .args = asym_args,                                       \
      .private = { .ptr = &p11sak_rsa_keytype }, },                            \
    { .value = "dh", .args = asym_args,                                        \
      .private = { .ptr = &p11sak_dh_keytype }, },                             \
    { .value = "dsa", .args = asym_args,                                       \
      .private = { .ptr = &p11sak_dsa_keytype }, },                            \
    { .value = "ec", .args = asym_args,                                        \
      .private = { .ptr = &p11sak_ec_keytype }, },                             \
    { .value = "ec-edwards", .args = asym_args,                                \
      .private = { .ptr = &p11sak_ec_edwards_keytype }, },                     \
    { .value = "ec-montgomery", .args = asym_args,                             \
      .private = { .ptr = &p11sak_ec_montgomery_keytype }, },                  \
    { .value = "ibm-dilithium", .args = asym_args,                             \
      .private = { .ptr = &p11sak_ibm_dilithium_keytype }, },                  \
    { .value = "ibm-kyber", .args = asym_args,                                 \
      .private = { .ptr = &p11sak_ibm_kyber_keytype }, },                      \
    { .value = "ibm-ml-dsa", .args = asym_args,                                \
      .private = { .ptr = &p11sak_ibm_ml_dsa_keytype }, },                     \
    { .value = "ibm-ml-kem", .args = asym_args,                                \
      .private = { .ptr = &p11sak_ibm_ml_kem_keytype }, }

static const struct p11tool_enum_value p11sak_import_key_keytypes[] = {
    IMPORT_KEYTYPES(p11sak_import_asym_args),
    { .value = NULL, },
};

#define IMPORT_CERTTYPES                                                       \
    { .value = "x509", .args = NULL,                                           \
      .private = { .ptr = &p11sak_x509_certtype, }, }

static const struct p11tool_enum_value p11sak_import_cert_certtypes[] = {
    IMPORT_CERTTYPES,
    { .value = NULL, },
};

static const struct p11tool_arg p11sak_import_key_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_import_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the key. One of the following:", },
    { .name = NULL },
};

static const struct p11tool_arg p11sak_import_cert_args[] = {
    { .name = "CERTTYPE", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_import_cert_certtypes,
      .value.enum_value = &opt_certtype,
      .description = "The type of the certificate. One of the following:", },
    { .name = NULL },
};

static const struct p11tool_opt p11sak_export_key_opts[] = {
    PKCS11_OPTS,
    KEY_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to export a key. "
                     "Use with care, all keys matching the filter are "
                     "exported! See the description of the '-F'/'--file' "
                     "option about what happens when multiple keys match the "
                     "filter and are exported into the same file.", },
    { .short_opt = 'F', .long_opt = "file", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_file, .name = "FILENAME", },
      .description = "The file name of the file to which the keys to be "
                     "exported are written to. For symmetric keys, this is a "
                     "binary file where the key material in clear is written "
                     "to. For asymmetric keys, this is an OpenSSL PEM file "
                     "where the public or private keys are written to. If "
                     "multiple asymmetric keys match the filter, the keys "
                     "are appended to the PEM file specified with the "
                     "'-F'/'--file' option. If multiple symmetric keys or a "
                     "mixture of asymmetric and symmetric keys match the "
                     "filter, then you are prompted to confirm to overwrite "
                     "the previously created file, unless the '-f'\'--force' "
                     "option is specified.", },
    { .short_opt = 'e', .long_opt = "encrypted-pem", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_encrypted_pem, },
      .description = "Encrypt the PEM file using AES-CBC with an AES 256 bit "
                     "key derived from a password via PBKDF2. The PEM password "
                     "can be specified with the '-P'/'--pem-password' option, "
                     "or via environment variable P11SAK_PEM_PASSWORD, "
                     "otherwise you are prompted for the PEM password. This "
                     "option is only valid for exporting private keys. It is "
                     "not allowed when exporting SPKIs, opaque secure key "
                     "blobs, or URI-PEMs, and it is ignored when exporting "
                     "public or secret keys.", },
    { .short_opt = 'P', .long_opt = "pem-password", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_pem_password, .name = "PASSWORD", },
      .description = "The password used to to encrypt the PEM file specified "
                     "with the '-F'/'--file' option. If PEM file is to be "
                     "encrypted, but this option is not specified, nor "
                     "environment variable P11SAK_PEM_PASSWORD is set, you "
                     "are prompted for the PEM password.", },
    { .short_opt = 0, .long_opt = "force-pem-pwd-prompt", .required = false,
      .long_opt_val = OPT_FORCE_PEM_PWD_PROMPT,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_force_pem_pwd_prompt, },
      .description = "Enforce PEM password prompt, even if environment "
                     "variable P11SAK_PEM_PASSWORD is set, or the "
                     "'-P'/'--pem-password' option is specified.", },
    { .short_opt = 'o', .long_opt = "opaque", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_opaque, },
      .description = "The key's opaque secure key blob is written to the file "
                     "specified with the '-F'/'--file' option. Not all tokens "
                     "support this.", },
    { .short_opt = 'S', .long_opt = "spki", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_spki, },
      .description = "Export the Subject Public Key Info (SPKI) from the "
                     "CKA_PUBLIC_KEY_INFO attribute of an asymmetric private "
                     "key instead of its private key material. This option can "
                     "only be used with private keys.", },
    { .short_opt = 'u', .long_opt = "uri-pem", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_uri_pem, },
      .description = "Export the key's PKCS#11 URI in PEM form instead of the "
                     "key material. Such an URI-PEM file can then be used with "
                     "the pkcs11-provider (https://github.com/latchset/"
                     "pkcs11-provider).", },
    { .short_opt = 0, .long_opt = "uri-pin-value", .required = false,
       .long_opt_val = OPT_URI_PIN_VALUE,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_uri_pin_value, },
      .description = "When exporting the key's PKCS#11 URI in PEM form, "
                     "include the PKCS#11 user PIN value in the URI using "
                     "the 'pin-value' query attribute. This reveals the "
                     "PKCS#11 user PIN in clear, use with care! "
                     "This option can only be used together with the "
                     "'-u'/'--uri-pem' option, and when options "
                     "'-N'/'--no-login' and '--so' are not specified.", },
    { .short_opt = 0, .long_opt = "uri-pin-source", .required = false,
      .long_opt_val = OPT_URI_PIN_SOURCE,
      .arg = { .type = ARG_TYPE_STRING, .required = true,
               .value.string = &opt_uri_pin_source, .name = "FILENAME" },
      .description = "When exporting the key's PKCS#11 URI in PEM form, "
                     "include the 'pin-source' query attribute in the URI, "
                     "referencing the file name specified with this option. "
                     "The PKCS#11 user PIN value is written into that file as "
                     "part of the export operation. This reveals the PKCS#11 "
                     "user PIN in clear, use with care! Adjust the file "
                     "permissions of the specified file so that it can only be "
                     "read by the desired user(s). "
                     "This option can only be used together with the "
                     "'-u'/'--uri-pem' option, and when options "
                     "'-N'/'--no-login' and '--so' are not specified.", },
    { .short_opt = 0, .long_opt = "oqsprovider-pem", .required = false,
      .long_opt_val = OPT_OQSPROVIDER_PEM,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_oqsprovider_pem, },
      .description = "The key material shall be exported in the 'oqsprovider' "
                     "format into the PEM file specified with the "
                     "'-F'/'--file' option. PEM files in 'oqsprovider' format "
                     "are only supported when the 'oqsprovider' has been "
                     "configured with OpenSSL 3.0 or later. This is an "
                     "experimental feature, it may change in an incompatible "
                     "way in the future!", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_extract_pubkey_opts[] = {
    PKCS11_OPTS,
    KEY_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to extract public keys. "
                     "Use with care, public keys of all private keys matching "
                     "the filter are extracted!", },
    { .short_opt = 'A', .long_opt = "new-attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the extracted public "
                     "key (optional): P M B Y R E D G C V O W U S X T I K. "
                     "Specify a set of these letters without any blanks in "
                     "between. See below for the meaning of the attribute "
                     "letters. Restrictions on attribute values may apply.", },
    { .short_opt = 'l', .long_opt = "new-label", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_label, .name = "LABEL", },
      .description = "The new label to set for the extracted public key (optional). "
                     "If no new label is specified, the new label is derived "
                     "from the private key label by appending '_pubkey'.", },
    { .short_opt = 'I', .long_opt = "new-id", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_id, .name = "ID", },
      .description = "The new ID to set for the extracted public key (optional).", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_export_cert_opts[] = {
    PKCS11_OPTS,
    CERT_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to export a certificate. "
                     "Use with care, all certificates matching the filter are "
                     "exported! If it's a PEM file, multiple certificates can "
                     "be exported to the same file. If it's a binary file, "
                     "each subsequent export overwrites the previous data "
                     "in the output file. You are prompted to confirm to "
                     "overwrite the previously created file, unless the "
                     "[--force|-f] option is specified.", },
    { .short_opt = 'F', .long_opt = "file", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_file, .name = "FILENAME", },
      .description = "The file name of the file to which the certificates to be "
                     "exported are written to. Supported output formats "
                     "are PEM and binary (DER-encoded).",},
    { .short_opt = 'D', .long_opt = "der", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_der, },
      .description = "The certificate is written to the file in binary "
                     "(DER-encoded) form. Default is PEM.", },
    { .short_opt = 'u', .long_opt = "uri-pem", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_uri_pem, },
      .description = "Export the certifcate's PKCS#11 URI in PEM form instead "
                     "of the certificate material. Such an URI-PEM file can "
                     "then be used with the pkcs11-provider (https://github.com"
                     "/latchset/pkcs11-provider).", },
    { .short_opt = 0, .long_opt = "uri-pin-value", .required = false,
       .long_opt_val = OPT_URI_PIN_VALUE,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_uri_pin_value, },
      .description = "When exporting the certifcate's PKCS#11 URI in PEM form, "
                     "include the PKCS#11 user PIN value in the URI using "
                     "the 'pin-value' query attribute. This reveals the "
                     "PKCS#11 user PIN in clear, use with care! "
                     "This option can only be used together with the "
                     "'-u'/'--uri-pem' option, and when options "
                     "'-N'/'--no-login' and '--so' are not specified.", },
    { .short_opt = 0, .long_opt = "uri-pin-source", .required = false,
      .long_opt_val = OPT_URI_PIN_SOURCE,
      .arg = { .type = ARG_TYPE_STRING, .required = true,
               .value.string = &opt_uri_pin_source, .name = "FILENAME" },
      .description = "When exporting the certifcate's PKCS#11 URI in PEM form, "
                     "include the 'pin-source' query attribute in the URI, "
                     "referencing the file name specified with this option. "
                     "The PKCS#11 user PIN value is written into that file as "
                     "part of the export operation. This reveals the PKCS#11 "
                     "user PIN in clear, use with care! Adjust the file "
                     "permissions of the specified file so that it can only be "
                     "read by the desired user(s). "
                     "This option can only be used together with the "
                     "'-u'/'--uri-pem' option, and when options "
                     "'-N'/'--no-login' and '--so' are not specified.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_extract_cert_pubkey_opts[] = {
    PKCS11_OPTS,
    CERT_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to extract public keys. "
                     "Use with care, public keys of all certificates matching "
                     "the filter are extracted!", },
    { .short_opt = 'A', .long_opt = "new-attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the extracted public "
                     "key (optional): P M B Y R E D G C V O W U S X T I K. "
                     "Specify a set of these letters without any blanks in "
                     "between. See below for the meaning of the attribute "
                     "letters. Restrictions on attribute values may apply.", },
    { .short_opt = 'l', .long_opt = "new-label", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_label, .name = "LABEL", },
      .description = "The new label to set for the extracted public key (optional). "
                     "If no new label is specified, the new label is derived "
                     "from the certificate label by appending '_pubkey'.", },
    { .short_opt = 'I', .long_opt = "new-id", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_id, .name = "ID", },
      .description = "The new ID to set for the extracted public key (optional).", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_arg p11sak_export_key_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the keys to select for export (optional). "
                     "If no key type is specified, all key types are "
                     "selected.", },
    { .name = NULL },
};

static const struct p11tool_arg p11sak_extract_pubkey_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_private_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the private keys to select for public key "
                     "extraction (optional). If no key type is specified, all "
                     "private key types are selected.", },
    { .name = NULL },
};

static const struct p11tool_arg p11sak_export_cert_args[] = {
    { .name = "CERTTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_cert_certtypes,
      .value.enum_value = &opt_certtype,
      .description = "The type of the certificates to select for export "
                     "(optional). If no certificate type is specified, "
                     "certificate type x509 is used, because currently no "
                     "other certificate types are supported.", },
    { .name = NULL },
};

static const struct p11tool_arg p11sak_extract_cert_pubkey_args[] = {
    { .name = "CERTTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_copy_export_cert_certtypes,
      .value.enum_value = &opt_certtype,
      .description = "The type of the certificates to select for public key "
                     "extraction (optional). If no certificate type is specified, "
                     "certificate type x509 is used, because currently no "
                     "other certificate types are supported.", },
    { .name = NULL },
};

#define KEK_SELECT_OPTS                                                        \
    { .short_opt = 'K', .long_opt = "kek-label", .required = false,            \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_kek_label, .name = "LABEL", },            \
      .description = "Select the key encrypting key (KEK) by label. Only keys "\
                     "with the right object class and key type that fit to "   \
                     "the wrapping mechanism are selected. You can use "       \
                     "wildcards ('*' and '?') in the kek-label specification. "\
                     "To specify a wildcard character that should not be "     \
                     "treated as a wildcard, it must be escaped using a "      \
                     "backslash ('\\*' or '\\?'). Also, a backslash character "\
                     "that should not be treated a an escape character must "  \
                     "be escaped ('\\\\'). If multiple key objects match then "\
                     "you are prompted to confirm to use the desired key "     \
                     "object.", },                                             \
    { .short_opt = 'k', .long_opt = "kek-id", .required = false,               \
      .arg =  { .type = ARG_TYPE_STRING, .required = true,                     \
                .value.string = &opt_kek_id, .name = "ID", },                  \
      .description = "Select the key encrypting key (KEK) by ID. Only keys "   \
                     "with the right object class and key type that fit to "   \
                     "the wrapping mechanism are selected. Specify a hex "     \
                     "string (not prefixed with 0x) of any number of bytes. "  \
                     "If multiple key objects match then you are prompted to " \
                     "confirm to use the desired key object.", }

static const struct p11tool_opt p11sak_wrap_key_opts[] = {
    PKCS11_OPTS,
    KEK_SELECT_OPTS,
    KEY_FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to use a key as KEK or "
                     "to wrap a key. Use with care, all keys matching the "
                     "filter are wrapped!", },
    { .short_opt = 'F', .long_opt = "file", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_file, .name = "FILENAME", },
      .description = "The file name of the file to which the wrapped key "
                     "material is written to. By default this is a PEM file "
                     "using a p11sak-specific type and a header that contains "
                     "information about the wrapping mechanism and mechanism "
                     "parameters (if any). If option '-R'/'--raw' is specified "
                     "then the file is a raw binary file and the raw wrapped "
                     "key material is written to it.", },
    { .short_opt = 'R', .long_opt = "raw", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_raw, },
      .description = "Store the wrapped key material as raw bytes into the "
                     "file specified with the '-F'/'--file' option.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_enum_value p11sak_wrap_key_keytypes[] = {
    KEYGEN_KEYTYPES(null),
    { .value = "private", .args = NULL,
      .private = { .ptr = &p11sak_private_keytype }, },
    { .value = "secret", .args = NULL,
      .private = { .ptr = &p11sak_secret_keytype }, },
    { .value = "all", .args = NULL,
      .private = { .ptr = &p11sak_all_keytype }, },
    { .value = NULL, },
};

static const struct p11tool_arg p11sak_wrap_key_args[] = {
    { .name = "WRAP-MECH", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_wrap_mech_values,
      .value.enum_value = &opt_wrap_mech,
      .description = "The key wrapping mechanism to use for wrapping the key. "
                     "Dependent on the key wrapping mechanism, additional "
                     "options may be supported to specify mechanism "
                     "parameters.", },
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_wrap_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the keys to select for wrapping (optional). "
                     "If no key type is specified, all key types are "
                     "selected.", },
    { .name = NULL },
};

static const struct p11tool_opt p11sak_unwrap_key_opts[] = {
    PKCS11_OPTS,
    KEK_SELECT_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to use a key as KEK.", },
    { .short_opt = 'L', .long_opt = "label", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_label, .name = "LABEL", },
      .description = "The label of the unwrapped key.", },
    { .short_opt = 'a', .long_opt = "attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the unwrapped key:\n"
                     "P M B Y R E D G C V O W U S X T I H K (optional). "
                     "Specify a set of these letters without any blanks in "
                     "between. See below for the meaning of the attribute "
                     "letters.", },
    { .short_opt = 'i', .long_opt = "id", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_id, .name = "ID", },
      .description = "The ID of the unwrapped key. Specify a hex string "
                     "(not prefixed with 0x) of any number of bytes.", },
    { .short_opt = 'F', .long_opt = "file", .required = true,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_file, .name = "FILENAME", },
      .description = "The file name of the file containing the wrapped key "
                     "material. By default this is a PEM file using a p11sak-"
                     "specific type and a header that contains information "
                     "about the wrapping mechanism and mechanism parameters "
                     "(if any). If option '-R'/'--raw' is specified then the "
                     "file is a raw binary file and the raw wrapped key "
                     "material is contained.", },
    { .short_opt = 'R', .long_opt = "raw", .required = false,
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,
               .value.plain = &opt_raw, },
      .description = "Read the wrapped key material as raw bytes from the file "
                     "specified with the '-F'/'--file' option.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_enum_value p11sak_unwrap_key_keytypes[] = {
    IMPORT_KEYTYPES(NULL),
    { .value = NULL, },
};

static const struct p11tool_arg p11sak_unwrap_key_args[] = {
    { .name = "WRAP-MECH", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_wrap_mech_values,
      .value.enum_value = &opt_wrap_mech,
      .description = "The key wrapping mechanism to use for unwrapping the "
                     "key. This argument is only required when option "
                     "'-R'/'--raw' is specified. Dependent on the key wrapping "
                     "mechanism, additional options may be supported to "
                     "specify mechanism parameters.", },
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_unwrap_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the key. This argument is only required when "
                     "option '-R'/'--raw' is specified. One of the "
                     "following:", },
    { .name = NULL },
};

static const struct p11tool_cmd p11sak_commands[] = {
    { .cmd = "generate-key", .cmd_short1 = "gen-key", .cmd_short2 = "gen",
      .func = p11sak_generate_key,
      .opts = p11sak_generate_key_opts, .args = p11sak_generate_key_args,
      .description = "Generate a key.",
      .help = print_generate_import_key_attr_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "list-key", .cmd_short1 = "ls-key", .cmd_short2 = "ls",
      .func = p11sak_list_key,
      .opts = p11sak_list_key_opts, .args = p11sak_list_key_args,
      .description = "List keys in the repository.",
      .help = print_list_key_attr_help, .session_flags = CKF_SERIAL_SESSION, },
    { .cmd = "remove-key", .cmd_short1 = "rm-key", .cmd_short2 = "rm",
      .func = p11sak_remove_key,
      .opts = p11sak_remove_key_opts, .args = p11sak_remove_key_args,
      .description = "Delete keys in the repository.",
      .help = print_remove_key_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "set-key-attr", .cmd_short1 = "set-key", .cmd_short2 = "set",
      .func = p11sak_set_key_attr,
      .opts = p11sak_set_key_attr_opts, .args = p11sak_set_key_attr_args,
      .description = "Set attributes of keys in the repository.",
      .help = print_set_copy_extract_key_attr_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "copy-key", .cmd_short1 = "copy", .cmd_short2 = "cp",
      .func = p11sak_copy_key,
      .opts = p11sak_copy_key_opts, .args = p11sak_copy_key_args,
      .description = "Copy keys in the repository.",
      .help = print_set_copy_extract_key_attr_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "import-key", .cmd_short1 = "import", .cmd_short2 = "imp",
      .func = p11sak_import_key,
      .opts = p11sak_import_key_opts, .args = p11sak_import_key_args,
      .description = "Import a key from a binary file or PEM file.",
      .help = print_generate_import_key_attr_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "export-key", .cmd_short1 = "export", .cmd_short2 = "exp",
      .func = p11sak_export_key,
      .opts = p11sak_export_key_opts, .args = p11sak_export_key_args,
      .description = "Export keys to a binary file or PEM file.",
      .session_flags = CKF_SERIAL_SESSION, },
    { .cmd = "extract-pubkey", .cmd_short1 = "extr-pubkey", .cmd_short2 = "expub",
      .func = p11sak_extract_key_pubkey,
      .opts = p11sak_extract_pubkey_opts, .args = p11sak_extract_pubkey_args,
      .description = "Extract the public key from private keys in the repository.",
      .help = print_set_copy_extract_key_attr_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "list-cert", .cmd_short1 = "ls-cert", .cmd_short2 = "lsc",
      .func = p11sak_list_cert,
      .opts = p11sak_list_cert_opts, .args = p11sak_list_cert_args,
      .description = "List certificates in the repository.",
      .help = print_list_cert_attr_help, .session_flags = CKF_SERIAL_SESSION, },
    { .cmd = "remove-cert", .cmd_short1 = "rm-cert", .cmd_short2 = "rmc",
      .func = p11sak_remove_cert,
      .opts = p11sak_remove_cert_opts, .args = p11sak_remove_cert_args,
      .description = "Delete certificates in the repository.",
      .help = print_remove_cert_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "set-cert-attr", .cmd_short1 = "set-cert", .cmd_short2 = "setc",
      .func = p11sak_set_cert_attr,
      .opts = p11sak_set_cert_attr_opts, .args = p11sak_set_cert_attr_args,
      .description = "Set attributes of certificates in the repository.",
      .help = print_set_copy_cert_attr_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "copy-cert", .cmd_short1 = "copyc", .cmd_short2 = "cpc",
      .func = p11sak_copy_cert,
      .opts = p11sak_copy_cert_opts, .args = p11sak_copy_cert_args,
      .description = "Copy certificates in the repository.",
      .help = print_set_copy_cert_attr_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "import-cert", .cmd_short1 = "importc", .cmd_short2 = "impc",
      .func = p11sak_import_cert,
      .opts = p11sak_import_cert_opts, .args = p11sak_import_cert_args,
      .description = "Import a certificate from a binary file or PEM file.",
      .help = print_import_cert_attr_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "export-cert", .cmd_short1 = "exportc", .cmd_short2 = "expc",
      .func = p11sak_export_cert,
      .opts = p11sak_export_cert_opts, .args = p11sak_export_cert_args,
      .description = "Export certificates to a binary file or PEM file.",
      .session_flags = CKF_SERIAL_SESSION, },
    { .cmd = "extract-cert-pubkey", .cmd_short1 = "extrc-pubkey", .cmd_short2 = "excpub",
      .func = p11sak_extract_cert_pubkey,
      .opts = p11sak_extract_cert_pubkey_opts, .args = p11sak_extract_cert_pubkey_args,
      .description = "Extract the public key from certificates in the repository.",
      .help = print_extract_cert_pubkey_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "wrap-key", .cmd_short1 = "wrap",
      .func = p11sak_wrap_key,
      .opts = p11sak_wrap_key_opts, .args = p11sak_wrap_key_args,
      .description = "Export a key by wrapping it with a key encrypting key. "
                     "Only private and secret keys can be wrapped.",
      .help = print_wrap_key_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "unwrap-key", .cmd_short1 = "unwrap",
      .func = p11sak_unwrap_key,
      .opts = p11sak_unwrap_key_opts, .args = p11sak_unwrap_key_args,
      .description = "Import a key by unwrapping it with a key encrypting key. "
                     "Only private and secret keys can be unwrapped.",
      .help = print_unwrap_key_help,
       .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = NULL, .func = NULL },
};

const struct p11tool_attr p11sak_bool_attrs[] = {
    DECLARE_BOOL_ATTR(CKA_PRIVATE,           'P', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_LOCAL,             'L', true,  true,  true,  false),
    DECLARE_BOOL_ATTR(CKA_MODIFIABLE,        'M', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_COPYABLE,          'B', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_DESTROYABLE,       'Y', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_DERIVE,            'R', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_ENCRYPT,           'E', true,  true,  false, true),
    DECLARE_BOOL_ATTR(CKA_DECRYPT,           'D', true,  false, true,  true),
    DECLARE_BOOL_ATTR(CKA_SIGN,              'G', true,  false, true,  true),
    DECLARE_BOOL_ATTR(CKA_SIGN_RECOVER,      'C', false, false, true,  true),
    DECLARE_BOOL_ATTR(CKA_VERIFY,            'V', true,  true,  false, true),
    DECLARE_BOOL_ATTR(CKA_VERIFY_RECOVER,    'O', false, true,  false, true),
    DECLARE_BOOL_ATTR(CKA_WRAP,              'W', true,  true,  false, true),
    DECLARE_BOOL_ATTR(CKA_UNWRAP,            'U', true,  false, true,  true),
    DECLARE_BOOL_ATTR(CKA_SENSITIVE,         'S', true,  false, true,  true),
    DECLARE_BOOL_ATTR(CKA_ALWAYS_SENSITIVE,  'A', true,  false, true,  false),
    DECLARE_BOOL_ATTR(CKA_EXTRACTABLE,       'X', true,  false, true,  true),
    DECLARE_BOOL_ATTR(CKA_NEVER_EXTRACTABLE, 'N', true,  false, true,  false),
    DECLARE_BOOL_ATTR_SO(CKA_TRUSTED,        'T', true,  true,  false, true,
                                                  true),
    DECLARE_BOOL_ATTR(CKA_WRAP_WITH_TRUSTED, 'I', true,  false, true,  true),
    DECLARE_BOOL_ATTR(CKA_ALWAYS_AUTHENTICATE,
                                             'H', false, false, true,  true),
    DECLARE_BOOL_ATTR(CKA_IBM_PROTKEY_EXTRACTABLE,
                                             'K', true,  false, true,  true),
    DECLARE_BOOL_ATTR(CKA_IBM_PROTKEY_NEVER_EXTRACTABLE,
                                             'Z', true,  false, true,  false),
    { .name = NULL, },
};

static const struct p11tool_attr p11sak_bool_cert_attrs[] = {
    DECLARE_BOOL_ATTR(CKA_PRIVATE,           'P', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_MODIFIABLE,        'M', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_COPYABLE,          'B', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_DESTROYABLE,       'Y', true,  true,  true,  true),
    DECLARE_BOOL_ATTR_SO(CKA_TRUSTED,        'T', true,  true,  true,  true,
                                                  true),
    { .name = NULL, },
};

static const struct p11sak_custom_attr_type custom_attr_types[] = {
    { .type = P11SAK_CONFIG_TYPE_BOOL, .print_long = p11tool_print_bool_attr_long, },
    { .type = P11SAK_CONFIG_TYPE_ULONG, .print_long = p11tool_print_ulong_attr, },
    { .type = P11SAK_CONFIG_TYPE_BYTE, .print_long = p11tool_print_byte_array_attr, },
    { .type = P11SAK_CONFIG_TYPE_DATE, .print_long = p11tool_print_date_attr, },
    { .type = NULL, },
};

static const struct p11tool_token_info p11sak_known_tokens[] = {
    { .type = TOKTYPE_CCA,  .manufacturer = "IBM", .model = "CCA",
      .mkvp_size = 8,  .mktype_cell_size = 8,
      .secure_key_attr = CKA_IBM_OPAQUE,
      .print_mkvp_short = p11sak_print_mkvp_cca_short,
      .print_mkvp_long = p11sak_print_mkvp_cca_long, },
    { .type = TOKTYPE_EP11, .manufacturer = "IBM", .model = "EP11",
      .mkvp_size = 16, .mktype_cell_size = 8,
      .session_id_size = 32,
      .secure_key_attr = CKA_IBM_OPAQUE,
      .print_mkvp_short = p11sak_print_mkvp_ep11_short,
      .print_mkvp_long = p11sak_print_mkvp_ep11_long,
      .print_session_id_short = p11sak_print_session_id_ep11_short,
      .print_session_id_long = p11sak_print_session_id_ep11_long, },
    { .type = TOKTYPE_UNKNOWN, },
};

#if defined(_AIX)
    static void *global_private = NULL;
#endif

static void print_import_cert_attr_help(void)
{
    const struct p11tool_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_cert_attrs; attr->name != NULL; attr++) {
        if (attr->settable)
            printf("    '%c':   %s%s\n", attr->letter, attr->name,
                   attr->so_set_to_true ?
                           " (can be set to TRUE by SO only)" : "");
    }
    printf("\n");

    printf("    ");
    p11tool_print_indented("An uppercase letter sets the corresponding "
                           "attribute to CK_TRUE, a lower case letter to "
                           "CK_FALSE.\n"
                           "If an attribute is not set explicitly, its default "
                           "value is used.\n"
                           "Not all attributes may be accepted for all "
                           "certificate types.\n"
                           "Attribute CKA_TOKEN is always set to CK_TRUE.", 4);
    printf("\n");
}

static void print_generate_import_key_attr_help(void)
{
    const struct p11tool_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++) {
        if (attr->settable)
            printf("    '%c':   %s%s\n", attr->letter, attr->name,
                   attr->so_set_to_true ?
                           " (can be set to TRUE by SO only)" : "");
    }
    printf("\n");

    printf("    ");
    p11tool_print_indented("An uppercase letter sets the corresponding "
                           "attribute to CK_TRUE, a lower case letter to "
                           "CK_FALSE.\n"
                           "If an attribute is not set explicitly, its default "
                           "value is used.\n"
                           "Not all attributes may be accepted for all key "
                           "types.\n"
                           "Attribute CKA_TOKEN is always set to CK_TRUE.", 4);
    printf("\n");
}

static void print_list_key_attr_help(void)
{
    const struct p11tool_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++)
        printf("    '%c':   %s\n", attr->letter, attr->name);
    printf("\n");

    printf("    ");
    p11tool_print_indented("Not all attributes may be defined for all key "
                           "types.\n"
                           "Attribute CKA_TOKEN is always CK_TRUE for all keys "
                           "listed.", 4);
    printf("\n");
}

static void print_list_cert_attr_help(void)
{
    const struct p11tool_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_cert_attrs; attr->name != NULL; attr++)
        printf("    '%c':   %s\n", attr->letter, attr->name);
    printf("\n");

    printf("    ");
    p11tool_print_indented("Not all attributes may be defined for all "
                           "certificate types.\n"
                           "Attribute CKA_TOKEN is always CK_TRUE for all "
                           "certificates listed.", 4);
    printf("\n");
}

static void print_remove_key_help(void)
{
    const struct p11tool_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++)
        printf("    '%c':   %s\n", attr->letter, attr->name);
    printf("\n");

    printf("    ");
    p11tool_print_indented("Not all attributes may be defined for all key "
                           "types.", 4);
    printf("\n");
}

static void print_set_copy_extract_key_attr_help(void)
{
    const struct p11tool_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++)
        printf("    '%c':   %s%s\n", attr->letter, attr->name,
               attr->so_set_to_true ?
                       " (can be set to TRUE by SO only)" : "");
    printf("\n");

    printf("    ");
    p11tool_print_indented("Keys can be filtered by all attributes, setting "
                           "is possible for all except L A N Z. T can be set "
                           "to TRUE by SO only.\n"
                           "An uppercase letter sets the corresponding "
                           "attribute to CK_TRUE, a lower case letter to "
                           "CK_FALSE.\n"
                           "If an attribute is not set explicitly, its value "
                           "is not changed.\n"
                           "Not all attributes may be allowed to be changed "
                           "for all key types, or to all values.\n", 4);
    printf("\n");
}

static void print_set_copy_cert_attr_help(void)
{
    const struct p11tool_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_cert_attrs; attr->name != NULL; attr++)
        printf("    '%c':   %s%s\n", attr->letter, attr->name,
               attr->so_set_to_true ?
                       " (can be set to TRUE by SO only)" : "");

    printf("\n");

    printf("    ");
    p11tool_print_indented("Certificates can be filtered by all attributes, "
                           "setting is also possible for all, but T can be set "
                           "to TRUE by SO only.\n"
                           "An uppercase letter sets the corresponding "
                           "attribute to CK_TRUE, a lower case letter to "
                           "CK_FALSE.\n"
                           "If an attribute is not set explicitly, its value "
                           "is not changed.\n"
                           "Not all attributes may be allowed to be changed "
                           "for all certificate types, or to all values.\n", 4);
    printf("\n");
}

static void print_remove_cert_help(void)
{
    const struct p11tool_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_cert_attrs; attr->name != NULL; attr++)
        printf("    '%c':   %s\n", attr->letter, attr->name);
    printf("\n");

    printf("    ");
    p11tool_print_indented("Not all attributes may be defined for all "
                           "certificate types.", 4);
    printf("\n");
}

static void print_extract_cert_pubkey_help(void)
{
    const struct p11tool_attr *attr;

    printf("ATTRIBUTES (for filtering):\n");
    for (attr = p11sak_bool_cert_attrs; attr->name != NULL; attr++)
        printf("    '%c':   %s\n", attr->letter, attr->name);
    printf("\n");

    printf("    ");

    p11tool_print_indented("When filtering certificates, use lowercase letters "
                           "to include only certificates where the related "
                           "attribute value is equal to CK_FALSE, use "
                           "uppercase letters if the related attribute shall "
                           "be CK_TRUE.\n", 4);

    printf("ATTRIBUTES (for setting):\n");
    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++) {
        if (attr->settable)
            printf("    '%c':   %s%s\n", attr->letter, attr->name,
                   attr->so_set_to_true ?
                           " (can be set to TRUE by SO only)" : "");
    }
    printf("\n");

    printf("    ");

    p11tool_print_indented("When setting attributes for extracted public keys, "
                           "use uppercase letters to set the corresponding "
                           "attribute to CK_TRUE, lowercase letters to "
                           "CK_FALSE.\n"
                           "If an attribute is not set explicitly, its value "
                           "is set to its default.\n"
                           "Not all attributes may be allowed to be set for "
                           "all public keys, or to all values.\n", 4);
    printf("\n");
}

static bool opt_slot_is_set(const struct p11tool_arg *arg)
{
    return (*arg->value.number != (CK_ULONG)-1);
}

static CK_RV generic_get_key_size(const struct p11tool_objtype *keytype,
                                  void *private, CK_ULONG *keysize)
{
    UNUSED(private);
    UNUSED(keytype);

    *keysize = opt_keybits_num;

    return CKR_OK;
}

static CK_RV generic_add_secret_attrs(const struct p11tool_objtype *keytype,
                                      CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                      void *private)
{
    CK_ULONG value_len = opt_keybits_num / 8;

    UNUSED(private);
    UNUSED(keytype);

    return p11tool_add_attribute(CKA_VALUE_LEN, &value_len, sizeof(value_len),
                                 attrs, num_attrs);
}

static CK_ULONG generic_keysize_adjust(const struct p11tool_objtype *keytype,
                                       CK_ULONG keysize)
{
    UNUSED(keytype);

    return keysize * 8;
}

static CK_RV aes_get_key_size(const struct p11tool_objtype *keytype,
                              void *private, CK_ULONG *keysize)
{
    UNUSED(private);
    UNUSED(keytype);

    *keysize = opt_keybits->private.num / 8;

    return CKR_OK;
}

static CK_RV aes_add_secret_attrs(const struct p11tool_objtype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private)
{
    CK_ULONG value_len = opt_keybits->private.num / 8;

    UNUSED(private);
    UNUSED(keytype);

    return p11tool_add_attribute(CKA_VALUE_LEN, &value_len, sizeof(value_len),
                                 attrs, num_attrs);
}

static CK_ULONG aes_keysize_adjust(const struct p11tool_objtype *keytype,
                                   CK_ULONG keysize)
{
    UNUSED(keytype);

    return keysize * 8;
}

static CK_ULONG aes_xts_keysize_adjust(const struct p11tool_objtype *keytype,
                                       CK_ULONG keysize)
{
    UNUSED(keytype);

    return (keysize * 8) / 2;
}

static CK_ULONG rsa_keysize_adjust(const struct p11tool_objtype *keytype,
                                   CK_ULONG keysize)
{
    UNUSED(keytype);

    return keysize * 8;
}

static CK_ULONG dh_keysize_adjust(const struct p11tool_objtype *keytype,
                                  CK_ULONG keysize)
{
    UNUSED(keytype);

    return keysize * 8;
}

static CK_ULONG dsa_keysize_adjust(const struct p11tool_objtype *keytype,
                                   CK_ULONG keysize)
{
    UNUSED(keytype);

    return keysize * 8;
}

static CK_RV rsa_get_key_size(const struct p11tool_objtype *keytype,
                              void *private, CK_ULONG *keysize)
{
    UNUSED(private);
    UNUSED(keytype);

    if ((opt_keybits_num % 8) != 0 ||
        opt_keybits_num < 512 ||
        opt_keybits_num > OPENSSL_RSA_MAX_MODULUS_BITS) {
        warnx("The RSA key size of '%lu' is not valid", opt_keybits_num);
        return CKR_ARGUMENTS_BAD;
    }

    *keysize = opt_keybits_num;

    return CKR_OK;
}

static CK_RV rsa_add_public_attrs(const struct p11tool_objtype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private)
{
    CK_RV rc;
    CK_BYTE *b;
    CK_ULONG val;
    unsigned int i;

    UNUSED(private);
    UNUSED(keytype);

    rc = rsa_get_key_size(keytype, NULL, &val);
    if (rc != CKR_OK)
        return rc;

    rc = p11tool_add_attribute(CKA_MODULUS_BITS, &val, sizeof(val),
                               attrs, num_attrs);
    if (rc != CKR_OK)
        return rc;

    if (opt_exponent != 0) {
        /* Convert CK_ULONG to big-endian byte array */
        val = htobe64(opt_exponent);
        for (i = 0, b = (CK_BYTE *)&val; i < sizeof(val) && *b == 0; i++, b++)
            ;

        rc = p11tool_add_attribute(CKA_PUBLIC_EXPONENT, b, sizeof(val) - i,
                                   attrs, num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

    return CKR_OK;
}

static CK_RV ec_get_key_size(const struct p11tool_objtype *keytype,
                             void *private, CK_ULONG *keysize)
{
    const struct curve_info *curve = opt_curve->private.ptr;

    UNUSED(private);
    UNUSED(keytype);

    *keysize = curve->bitsize;

    return CKR_OK;
}

static CK_RV ec_add_public_attrs(const struct p11tool_objtype *keytype,
                                 CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                 void *private)
{
    const struct curve_info *curve = opt_curve->private.ptr;

    UNUSED(private);
    UNUSED(keytype);

    return p11tool_add_attribute(CKA_EC_PARAMS, curve->oid, curve->oid_len,
                                 attrs, num_attrs);
}

static CK_RV dh_dsa_read_params_pem(const char *pem_file, bool is_dsa,
                                    EVP_PKEY **pkey)
{
    CK_RV rc = CKR_OK;
    EVP_PKEY *param = NULL;
    BIO *f;

    f = BIO_new_file(pem_file, "r");
    if (f == NULL) {
        warnx("Failed to open PEM file '%s'.", pem_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_ARGUMENTS_BAD;
    }

    param = PEM_read_bio_Parameters(f, NULL);
    if (param == NULL ||
        EVP_PKEY_base_id(param) != (is_dsa ? EVP_PKEY_DSA : EVP_PKEY_DH)) {
        warnx("Failed to read %s PEM file '%s'.", is_dsa ? "DSA" : "DH",
              pem_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    *pkey = param;
    param = NULL;

done:
    BIO_free(f);
    if (param != NULL)
        EVP_PKEY_free(param);

    return rc;
}

static CK_RV dh_group_params(int group_nid, EVP_PKEY **pkey)
{
    EVP_PKEY_CTX *ctx = NULL;
    EVP_PKEY *param = NULL;
    CK_RV rc = CKR_OK;

    ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (ctx == NULL) {
        warnx("Failed to set up an EVP context for DH.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        warnx("Failed to initialize a DH paramgen context.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (EVP_PKEY_CTX_set_dh_nid(ctx, group_nid) <= 0) {
        warnx("Failed to set group for DH paramgen context.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (EVP_PKEY_paramgen(ctx, &param) <= 0) {
        warnx("Failed to generate the DH params.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    *pkey = param;
    param = NULL;

done:
    if (param != NULL)
        EVP_PKEY_free(param);
    EVP_PKEY_CTX_free(ctx);

    return rc;
}

static CK_RV dh_dsa_add_public_attrs(CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     EVP_PKEY *pkey, bool is_dsa)
{
    CK_RV rc = CKR_OK;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BIGNUM *bn_p = NULL, *bn_q = NULL, *bn_g = NULL;
#else
    const DH *dh;
    const DSA *dsa;
    const BIGNUM *bn_p = NULL, *bn_q = NULL, *bn_g = NULL;
#endif

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &bn_p) ||
        (is_dsa &&
         !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_Q, &bn_q)) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &bn_g)) {
        warnx("Failed to get the %s params.", is_dsa ? "DSA" : "DH");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
     }
#else
    if (is_dsa) {
        dsa = EVP_PKEY_get0_DSA(pkey);
        if (dsa == NULL) {
            warnx("Failed to get the DSA params.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        DSA_get0_pqg(dsa, &bn_p, &bn_q, &bn_g);
        if (bn_p == NULL || (dsa && bn_q == NULL) || bn_g == NULL) {
            warnx("Failed to get the DSA params.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        dh = EVP_PKEY_get0_DH(pkey);
        if (dh == NULL) {
            warnx("Failed to get the DH params.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        DH_get0_pqg(dh, &bn_p, NULL, &bn_g);
        if (bn_p == NULL || bn_g == NULL) {
            warnx("Failed to get the DH params.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }
#endif

    rc = p11tool_add_bignum_attr(CKA_PRIME, bn_p, attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    if (is_dsa) {
        rc = p11tool_add_bignum_attr(CKA_SUBPRIME, bn_q, attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;
    }

    rc = p11tool_add_bignum_attr(CKA_BASE, bn_g, attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

done:
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (bn_p != NULL)
        BN_free(bn_p);
    if (bn_q != NULL)
        BN_free(bn_q);
    if (bn_g != NULL)
        BN_free(bn_g);
#endif

    return rc;
}

static CK_RV dh_prepare(const struct p11tool_objtype *keytype, void **private)
{
    CK_RV rc;
    EVP_PKEY *pkey = NULL;

    UNUSED(keytype);

    if (opt_pem_file != NULL)
        rc = dh_dsa_read_params_pem(opt_pem_file, false, &pkey);
    else
        rc = dh_group_params(opt_group->private.num, &pkey);

    if (rc != CKR_OK)
        return rc;

    *private = pkey;

    return CKR_OK;
}

static void dh_cleanup(const struct p11tool_objtype *keytype, void *private)
{
    EVP_PKEY *pkey = private;

    UNUSED(keytype);

    EVP_PKEY_free(pkey);
}

static CK_RV dh_get_key_size(const struct p11tool_objtype *keytype,
                             void *private, CK_ULONG *keysize)
{
    EVP_PKEY *pkey = private;
    CK_RV rc = CKR_OK;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BIGNUM *bn_p = NULL;
#else
    const DH *dh;
    const BIGNUM *bn_p = NULL;
#endif

    UNUSED(keytype);

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &bn_p)) {
        warnx("Failed to get the DH params.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
     }
#else
    dh = EVP_PKEY_get0_DH(pkey);
    if (dh == NULL) {
        warnx("Failed to get the DH params.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    DH_get0_pqg(dh, &bn_p, NULL, NULL);
    if (bn_p == NULL) {
        warnx("Failed to get the DH params.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

    *keysize = BN_num_bits(bn_p);

done:
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (bn_p != NULL)
        BN_free(bn_p);
#endif

    return rc;
}

static CK_RV dh_add_public_attrs(const struct p11tool_objtype *keytype,
                                 CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                 void *private)
{
    EVP_PKEY *pkey = private;

    UNUSED(keytype);

    return dh_dsa_add_public_attrs(attrs, num_attrs, pkey, false);
}

static CK_RV dh_add_private_attrs(const struct p11tool_objtype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private)
{
    UNUSED(private);
    UNUSED(keytype);

    if (opt_keybits_num == 0)
        return CKR_OK;

    return p11tool_add_attribute(CKA_VALUE_BITS, &opt_keybits_num,
                                 sizeof(opt_keybits_num), attrs, num_attrs);
}

static CK_RV dsa_prepare(const struct p11tool_objtype *keytype, void **private)
{
    CK_RV rc;
    EVP_PKEY *pkey = NULL;

    UNUSED(keytype);

    rc = dh_dsa_read_params_pem(opt_pem_file, true, &pkey);
    if (rc != CKR_OK)
        return rc;

    *private = pkey;

    return CKR_OK;
}

static void dsa_cleanup(const struct p11tool_objtype *keytype, void *private)
{
    EVP_PKEY *pkey = private;

    UNUSED(keytype);

    EVP_PKEY_free(pkey);
}

static CK_RV dsa_get_key_size(const struct p11tool_objtype *keytype,
                              void *private, CK_ULONG *keysize)
{
    EVP_PKEY *pkey = private;
    CK_RV rc = CKR_OK;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BIGNUM *bn_p = NULL;
#else
    const DSA *dsa;
    const BIGNUM *bn_p = NULL;
#endif

    UNUSED(keytype);

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &bn_p)) {
        warnx("Failed to get the DSA params.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
     }
#else
    dsa = EVP_PKEY_get0_DSA(pkey);
    if (dsa == NULL) {
        warnx("Failed to get the DSA params.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    DSA_get0_pqg(dsa, &bn_p, NULL, NULL);
    if (bn_p == NULL) {
        warnx("Failed to get the DSA params.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

    *keysize = BN_num_bits(bn_p);

done:
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (bn_p != NULL)
        BN_free(bn_p);
#endif

    return rc;
}

static CK_RV dsa_add_public_attrs(const struct p11tool_objtype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private)
{
    EVP_PKEY *pkey = private;

    UNUSED(keytype);

    return dh_dsa_add_public_attrs(attrs, num_attrs, pkey, true);
}

static CK_RV ibm_dilithium_add_public_attrs(
                                        const struct p11tool_objtype *keytype,
                                        CK_ATTRIBUTE **attrs,
                                        CK_ULONG *num_attrs,
                                        void *private)
{
    UNUSED(private);
    UNUSED(keytype);

    return p11tool_add_attribute(CKA_IBM_DILITHIUM_KEYFORM,
                                 &opt_pqc_version->private.num,
                                 sizeof(opt_pqc_version->private.num),
                                 attrs, num_attrs);
}

static CK_RV ibm_kyber_add_public_attrs(const struct p11tool_objtype *keytype,
                                        CK_ATTRIBUTE **attrs,
                                        CK_ULONG *num_attrs,
                                        void *private)
{
    UNUSED(private);
    UNUSED(keytype);

    return p11tool_add_attribute(CKA_IBM_KYBER_KEYFORM,
                                 &opt_pqc_version->private.num,
                                 sizeof(opt_pqc_version->private.num),
                                 attrs, num_attrs);
}

static CK_RV ibm_ml_dsa_kem_add_public_attrs(
                                         const struct p11tool_objtype *keytype,
                                         CK_ATTRIBUTE **attrs,
                                         CK_ULONG *num_attrs,
                                         void *private)
{
    UNUSED(private);
    UNUSED(keytype);

    return p11tool_add_attribute(CKA_IBM_PARAMETER_SET,
                                 &opt_pqc_version->private.num,
                                 sizeof(opt_pqc_version->private.num),
                                 attrs, num_attrs);
}

static CK_RV parse_key_pair_label(const char *label, char **pub_label,
                                  char** priv_label)
{
    char *pub = NULL;
    char *priv = NULL;
    unsigned int i;

    for (i = 0; i < strlen(label); i++) {
        if (label[i] == '\\') {
            i++; /* skip escaped character */
            continue;
        }

        if (label[i] == ':') {
            if (!(pub = strndup(label, i))) {
                warnx("Failed to allocate memory for pub label");
                return CKR_HOST_MEMORY;
            }
            if (!(priv = strdup(&label[i + 1]))) {
                warnx("Failed to allocate memory for priv label");
                free(pub);
                return CKR_HOST_MEMORY;
            }
            break;
        }
    }

    if (pub != NULL && priv != NULL) {
        if (strcmp(priv, "=") == 0) {
            free(priv);
            if (!(priv = strdup(pub))) {
                warnx("Failed to allocate memory for priv label");
                free(pub);
                return CKR_HOST_MEMORY;
            }
        }
    } else {
        if (!(pub = malloc(strlen(label) + 5))) {
            warnx("Failed to allocate memory for pub label");
            return CKR_HOST_MEMORY;
        }
        pub = strcpy(pub, label);
        pub = strcat(pub, ":pub");

        if (!(priv = malloc(strlen(label) + 5))) {
            warnx("Failed to allocate memory for priv label");
            free(pub);
            return CKR_HOST_MEMORY;
        }
        priv = strcpy(priv, label);
        priv = strcat(priv, ":prv");
    }

    for (i = 0; i < strlen(pub); i++) {
        if (pub[i] == '\\')
            memmove(&pub[i], &pub[i + 1],
                    strlen(&pub[i + 1]) + 1);
    }

    for (i = 0; i < strlen(priv); i++) {
        if (priv[i] == '\\')
            memmove(&priv[i], &priv[i + 1],
                    strlen(&priv[i + 1]) + 1);
    }

    *pub_label = pub;
    *priv_label = priv;

    return CKR_OK;
}

static CK_RV parse_key_pair_attrs(const char *attrs, char **pub_attrs,
                                  char** priv_attrs)
{
    char *ch, *pub, *priv;

    if (attrs == NULL) {
        *pub_attrs = NULL;
        *priv_attrs = NULL;
        return CKR_OK;
    }

    ch = strchr(attrs, ':');

    if (ch == NULL) {
        pub = strdup(attrs);
        priv = strdup(attrs);
    } else {
        pub = strndup(attrs, ch - attrs);
        priv = strdup(ch + 1);
    }

    if (pub == NULL || priv == NULL) {
        warnx("Failed to allocate memory for pub/priv labels");
        free(pub);
        free(priv);
        return CKR_HOST_MEMORY;
    }

    *pub_attrs = pub;
    *priv_attrs = priv;

    return CKR_OK;
}

const struct p11tool_objtype *find_keytype(CK_KEY_TYPE ktype)
{
    const struct p11tool_objtype **kt;

    for (kt = p11sak_keytypes; *kt != NULL; kt++) {
        if ((*kt)->type == ktype)
            return *kt;
    }

    return NULL;
}

static const struct p11tool_objtype *find_keytype_by_pkey(int pkey_type)
{
    const struct p11tool_objtype **kt;

    if (pkey_type == NID_undef)
        return NULL;

    for (kt = p11sak_keytypes; *kt != NULL; kt++) {
        switch (pkey_type) {
#if OPENSSL_VERSION_PREREQ(3, 0)
        case EVP_PKEY_ED25519:
        case EVP_PKEY_ED448:
            if ((*kt)->type == CKK_EC_EDWARDS)
                return *kt;
            break;
        case EVP_PKEY_X25519:
        case EVP_PKEY_X448:
            if ((*kt)->type == CKK_EC_MONTGOMERY)
                return *kt;
            break;
#endif
        default:
            if ((*kt)->pkey_type == pkey_type)
                return *kt;
            break;
        }
    }

    return NULL;
}

#if OPENSSL_VERSION_PREREQ(3, 0)
static const struct pqc_oid *pqc_oid_from_pkey(EVP_PKEY *pkey,
                                               const struct pqc_oid *pqc_oids,
                                               bool show_err_msg)
{
    const char *alg_name;
    ASN1_OBJECT *obj = NULL;
    const struct pqc_oid *oid = NULL;
    CK_BYTE *val = NULL;
    int val_len;
    int nid;

    alg_name = EVP_PKEY_get0_type_name(pkey);
    if (alg_name == NULL) {
        warnx("Failed to obtain the key type of the imported key");
        return NULL;
    }

    nid = OBJ_ln2nid(alg_name);
    if (nid == NID_undef) {
        warnx("OBJ_ln2nid failed for '%s'", alg_name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return NULL;
    }

    obj = OBJ_nid2obj(nid);
    if (obj == NULL) {
        warnx("OBJ_nid2obj failed for NID %d ('%s')", nid, alg_name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return NULL;
    }

    val_len = i2d_ASN1_OBJECT(obj, &val);
    if (val_len <= 0) {
        warnx("i2d_ASN1_OBJECT failed for algorithm '%s'", alg_name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        goto done;
    }

    oid = find_pqc_by_oid(pqc_oids, val, val_len);
    if (oid == NULL && show_err_msg)
        warnx("Algorithm '%s' is not supported by p11sak", alg_name);

    OPENSSL_free(val);

done:
    ASN1_OBJECT_free(obj);
    return oid;
}
#endif

static const struct p11tool_objtype *find_certtype(CK_KEY_TYPE ktype)
{
    const struct p11tool_objtype **kt;

    for (kt = p11sak_certtypes; *kt != NULL; kt++) {
        if ((*kt)->type == ktype)
            return *kt;
    }

    return NULL;
}

static CK_RV get_obj_infos(CK_OBJECT_HANDLE obj, CK_OBJECT_CLASS *class,
                           CK_ULONG *otype, CK_ULONG *keysize,
                           char** label, char** typestr,
                           const struct p11tool_objtype **objtype,
                           char **common_name)
{
    CK_RV rc;
    CK_OBJECT_CLASS class_val = 0;
    CK_ULONG otype_val = 0;
    const struct p11tool_objtype *objtype_val;
    CK_ULONG keysize_val = 0;
    char *label_val = NULL;
    char *common_name_val = NULL;

    rc = p11tool_get_label_value(obj, &label_val);
    if (rc != CKR_OK)
        return rc;

    rc = p11tool_get_class_and_type_values(obj, label_val, &class_val,
                                           &otype_val);
    if (rc != CKR_OK) {
        free(label_val);
        return rc;
    }

    switch (class_val) {
    case CKO_SECRET_KEY:
    case CKO_PUBLIC_KEY:
    case CKO_PRIVATE_KEY:
        objtype_val = find_keytype(otype_val);
        if (objtype_val == NULL) {
            warnx("Object \"%s\" has an unsupported type: %lu",
                  label_val, otype_val);
            free(label_val);
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        if (keysize != NULL) {
            rc = p11tool_get_keysize_value(obj, label_val, objtype_val,
                                           &keysize_val);
            if (rc != CKR_OK) {
                free(label_val);
                return rc;
            }
            *keysize = keysize_val;
        }
        break;
    case CKO_CERTIFICATE:
        objtype_val = find_certtype(otype_val);
        if (objtype_val == NULL) {
            warnx("Object \"%s\" has an unsupported type: %lu",
                  label_val, otype_val);
            free(label_val);
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        if (common_name != NULL) {
            rc = p11tool_get_common_name_value(obj, label_val,
                                               &common_name_val);
            if (rc != CKR_OK) {
                free(label_val);
                free(common_name_val);
                return rc;
            }
            *common_name = common_name_val;
        }
        break;
    default:
        /* Should not occur */
        warnx("Object \"%s\" has an unsupported class: %lu",
              label_val, class_val);
        free(label_val);
        return CKR_KEY_TYPE_INCONSISTENT;
        break;
    }

    if (class != NULL)
        *class = class_val;

    if (otype != NULL)
        *otype = otype_val;

    if (objtype != NULL)
        *objtype = objtype_val;

    if (typestr != NULL) {
        rc = p11tool_get_typestr_value(class_val, keysize_val, objtype_val,
                                       label_val, typestr);
        if (rc != CKR_OK) {
            free(label_val);
            return rc;
        }
    }

    if (label != NULL)
        *label = label_val;
    else
        free(label_val);

    return CKR_OK;
}

static int iterate_compare(const void *a, const void *b, void *private)
{
    struct p11sak_iterate_compare_data *data = private;
    const CK_OBJECT_HANDLE *obj1 = a;
    const CK_OBJECT_HANDLE *obj2 = b;
    int result = 0;
    CK_RV rc;

    if (data->rc != CKR_OK)
        return 0;

    rc = data->compare_obj(*obj1, *obj2, &result, data->private);
    if (rc != CKR_OK)
        data->rc = rc;

    return result;
}

#if defined(_AIX)
static int iterate_compare_aix(const void *a, const void *b)
{
    return iterate_compare(a, b, global_private);
}
#endif

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
                      void *private)
{
    CK_RV rc, rc2;
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    const CK_BBOOL ck_true = CK_TRUE;
    CK_OBJECT_HANDLE objs[FIND_OBJECTS_COUNT];
    CK_ULONG i, num_objs;
    bool manual_filtering = false;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE ktype;
    CK_ULONG keysize = 0;
    char *label = NULL;
    char *typestr = NULL;
    char *common_name = NULL;
    const struct p11tool_objtype *type;
    CK_OBJECT_HANDLE *matched_objs = NULL, *tmp;
    CK_ULONG num_matched_objs = 0;
    CK_ULONG alloc_matched_objs = 0;
    struct p11sak_iterate_compare_data data;

    rc = p11tool_add_attribute(CKA_TOKEN, &ck_true, sizeof(ck_true),
                               &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    if (objtype != NULL && objtype->filter_attr != (CK_ATTRIBUTE_TYPE)-1) {
        rc = p11tool_add_attribute(objtype->filter_attr, &objtype->filter_value,
                                   sizeof(objtype->filter_value),
                                   &attrs, &num_attrs);
        if (rc != CKR_OK)
            goto done;
    }

    if (label_filter != NULL) {
        manual_filtering = (strpbrk(label_filter, "*?\\") != NULL);
        if (!manual_filtering) {
            /* add label filter only if no escapes are used */
            rc = p11tool_add_attribute(CKA_LABEL, label_filter,
                                       strlen(label_filter),
                                       &attrs, &num_attrs);
            if (rc != CKR_OK)
                goto done;
        }
    }

    if (id_filter != NULL) {
        rc = p11tool_parse_id(id_filter, &attrs, &num_attrs);
        if (rc != CKR_OK)
            goto done;
    }

    if (attr_filter != NULL) {
        rc = p11tool_parse_boolean_attrs(NULL, p11sak_bool_attrs, opt_attr,
                                         &attrs, &num_attrs, false, opt_so,
                                         NULL);
        if (rc != CKR_OK)
            goto done;
    }

    rc = p11tool_pkcs11_funcs->C_FindObjectsInit(p11tool_pkcs11_session, attrs,
                                                 num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to initialize the find operation: C_FindObjectsInit: 0x%lX: %s",
              rc, p11_get_ckr(rc));
        goto done;
    }

    while (1) {
        memset(objs, 0, sizeof(objs));
        num_objs = 0;

        rc = p11tool_pkcs11_funcs->C_FindObjects(p11tool_pkcs11_session, objs,
                                                 FIND_OBJECTS_COUNT, &num_objs);
        if (rc != CKR_OK) {
            warnx("Failed to find objects: C_FindObjects: 0x%lX: %s",
                  rc, p11_get_ckr(rc));
            goto done_find;
        }

        if (num_objs == 0)
            break;

        for (i = 0; i < num_objs; i++) {
            if (!p11tool_objclass_expected(objs[i], objclass))
                continue;

            if (manual_filtering) {
                rc = p11tool_get_label_value(objs[i], &label);
                if (rc != CKR_OK)
                    break;

                if (fnmatch(label_filter, label, 0) != 0)
                    goto next;
            }

            if (num_matched_objs >= alloc_matched_objs) {
                tmp = realloc(matched_objs,
                              (alloc_matched_objs + FIND_OBJECTS_COUNT) *
                                                  sizeof(CK_OBJECT_HANDLE));
                if (tmp == NULL) {
                    warnx("Failed to allocate a list of matched objects.");
                    rc = CKR_HOST_MEMORY;
                    goto done_find;
                }

                matched_objs = tmp;
                alloc_matched_objs += FIND_OBJECTS_COUNT;
            }

            matched_objs[num_matched_objs++] = objs[i];

next:
            if (label != NULL)
                free(label);
            label = NULL;
        }
    }

done_find:
    rc2 = p11tool_pkcs11_funcs->C_FindObjectsFinal(p11tool_pkcs11_session);
    if (rc2 != CKR_OK) {
        warnx("Failed to finalize the find operation: C_FindObjectsFinal: 0x%lX: %s",
              rc2, p11_get_ckr(rc2));
        if (rc == CKR_OK)
            rc = rc2;
    }

    if (rc != CKR_OK)
        goto done;

    if (compare_obj != NULL && num_matched_objs > 0) {
        data.compare_obj = compare_obj;
        data.private = private;
        data.rc = CKR_OK;

#if defined(_AIX)
        global_private = &data;
        qsort(matched_objs, num_matched_objs, sizeof(CK_OBJECT_HANDLE),
                iterate_compare_aix);
#else
        qsort_r(matched_objs, num_matched_objs, sizeof(CK_OBJECT_HANDLE),
                iterate_compare, &data);
#endif
        rc = data.rc;
        if (rc != CKR_OK)
            goto done;
    }

    for (i = 0; i < num_matched_objs; i++) {
        rc = get_obj_infos(matched_objs[i], &class, &ktype, &keysize,
                           &label, &typestr, &type, &common_name);
        if (rc != CKR_OK)
            break;

        rc = handle_obj(matched_objs[i], class, type, keysize, typestr, label,
                        common_name, private);
        if (rc != CKR_OK)
            break;

        if (label != NULL)
            free(label);
        label = NULL;
        if (typestr != NULL)
            free(typestr);
        typestr = NULL;
        if (common_name != NULL)
            free(common_name);
        common_name = NULL;
    }

done:
    p11tool_free_attributes(attrs, num_attrs);

    if (label != NULL)
        free(label);
    if (typestr != NULL)
        free(typestr);
    if (common_name != NULL)
        free(common_name);
    if (matched_objs != NULL)
        free(matched_objs);

    return rc;
}

static CK_RV p11sak_generate_key(void)
{
    const struct p11tool_objtype *keytype;
    void *private = NULL;
    CK_RV rc = CKR_OK;
    CK_ULONG keysize = 0;
    char *pub_label = NULL, *priv_label = NULL;
    char *pub_attrs = NULL, *priv_attrs = NULL;
    CK_ATTRIBUTE *secret_attrs = NULL;
    CK_ULONG num_secret_attrs = 0;
    CK_ATTRIBUTE *public_attrs = NULL;
    CK_ULONG num_public_attrs = 0;
    CK_ATTRIBUTE *private_attrs = NULL;
    CK_ULONG num_private_attrs = 0;
    CK_OBJECT_HANDLE pub_key, priv_key, secret_key;

    if (opt_keytype == NULL || opt_keytype->private.ptr == NULL)
        return CKR_ARGUMENTS_BAD;

    keytype = opt_keytype->private.ptr;

    if (keytype->keygen_prepare != NULL) {
        rc = keytype->keygen_prepare(keytype, &private);
        if (rc != CKR_OK) {
            warnx("Failed to prepare key type %s: 0x%lX: %s", keytype->name,
                  rc, p11_get_ckr(rc));
            return rc;
        }
    }

    if (keytype->keygen_get_key_size != NULL) {
        rc = keytype->keygen_get_key_size(keytype, private, &keysize);
        if (rc != CKR_OK) {
            warnx("Failed to get key size for key type %s: 0x%lX: %s",
                  keytype->name, rc, p11_get_ckr(rc));
            goto done;
        }
    }

    rc = p11tool_check_keygen_mech_supported(opt_slot, keytype->keygen_mech.mechanism,
                                      keytype->is_asymmetric, keysize);
    if (rc != CKR_OK)
        goto done;

    if (keytype->is_asymmetric) {
        rc = parse_key_pair_label(opt_label, &pub_label, &priv_label);
        if (rc != CKR_OK)
            goto done;

        rc = parse_key_pair_attrs(opt_attr, &pub_attrs, &priv_attrs);
        if (rc != CKR_OK)
            goto done;

        rc = p11tool_add_attributes(keytype, p11sak_bool_attrs,
                                    &public_attrs, &num_public_attrs,
                                    pub_label, pub_attrs, opt_id, false, opt_so,
                                    keytype->keygen_add_public_attrs, private,
                                    p11tool_public_attr_applicable);
        if (rc != CKR_OK)
            goto done;

        rc = p11tool_add_attributes(keytype, p11sak_bool_attrs,
                                    &private_attrs, &num_private_attrs,
                                    priv_label, priv_attrs, opt_id, true, opt_so,
                                    keytype->keygen_add_private_attrs, private,
                                    p11tool_private_attr_applicable);
        if (rc != CKR_OK)
            goto done;
    } else {
        rc = p11tool_add_attributes(keytype, p11sak_bool_attrs,
                                    &secret_attrs, &num_secret_attrs,
                                    opt_label, opt_attr, opt_id, true, opt_so,
                                    keytype->keygen_add_secret_attrs, private,
                                    p11tool_secret_attr_applicable);
        if (rc != CKR_OK)
            goto done;
    }

    if (keytype->is_asymmetric)
        rc = p11tool_pkcs11_funcs->C_GenerateKeyPair(p11tool_pkcs11_session,
                                          (CK_MECHANISM *)&keytype->keygen_mech,
                                          public_attrs, num_public_attrs,
                                          private_attrs, num_private_attrs,
                                          &pub_key, &priv_key);
     else
         rc = p11tool_pkcs11_funcs->C_GenerateKey(p11tool_pkcs11_session,
                                          (CK_MECHANISM *)&keytype->keygen_mech,
                                          secret_attrs, num_secret_attrs,
                                          &secret_key);
    if (rc != CKR_OK) {
        if (p11tool_is_rejected_by_policy(rc, p11tool_pkcs11_session)) {
            if (keysize == 0)
                warnx("Key generation of a %s key is rejected by policy",
                      keytype->name);
            else
                warnx("Key generation of a %s key of size %lu is rejected by policy",
                      keytype->name, keysize);
        } else {
            if (keysize == 0)
                warnx("Key generation of a %s key failed: 0x%lX: %s",
                      keytype->name, rc, p11_get_ckr(rc));
            else
                warnx("Key generation of a %s key of size %lu failed: 0x%lX: %s",
                      keytype->name, keysize, rc, p11_get_ckr(rc));
        }
        goto done;
    }

    if (keytype->is_asymmetric)
        printf("Successfully generated a %s key pair with labels \"%s\":\"%s\".\n",
               keytype->name, pub_label, priv_label);
    else
        printf("Successfully generated a %s key with label \"%s\".\n",
               keytype->name, opt_label);

done:
    if (keytype->keygen_cleanup != NULL)
        keytype->keygen_cleanup(keytype, private);

    if (pub_label != NULL)
        free(pub_label);
    if (priv_label != NULL)
        free(priv_label);
    if (pub_attrs != NULL)
        free(pub_attrs);
    if (priv_attrs != NULL)
        free(priv_attrs);

    p11tool_free_attributes(secret_attrs, num_secret_attrs);
    p11tool_free_attributes(public_attrs, num_public_attrs);
    p11tool_free_attributes(private_attrs, num_private_attrs);

    return rc;
}

static void print_key_type_attr(const char *attr, const CK_ATTRIBUTE *val,
                                int indent, bool sensitive)
{
    const struct p11tool_objtype *ktype;
    const char *name = NULL;

    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_KEY_TYPE))
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
        return;
    }

    ktype = find_keytype(*(CK_KEY_TYPE *)(val->pValue));
    if (ktype != NULL)
        name = ktype->ck_name;

    if (name != NULL)
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr, name,
               *(CK_KEY_TYPE *)(val->pValue));
    else
        printf("%*s%s: 0x%lX\n", indent, "", attr,
               *(CK_KEY_TYPE *)(val->pValue));
}

static void print_cert_type_attr(const char *attr, const CK_ATTRIBUTE *val,
                                 int indent, bool sensitive)
{
    const struct p11tool_objtype *ctype;
    const char *name = NULL;

    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_CERTIFICATE_TYPE))
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
        return;
    }

    ctype = find_certtype(*(CK_CERTIFICATE_TYPE *)(val->pValue));
    if (ctype != NULL)
        name = ctype->ck_name;

    if (name != NULL)
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr, name,
               *(CK_CERTIFICATE_TYPE *)(val->pValue));
    else
        printf("%*s%s: 0x%lX\n", indent, "", attr,
               *(CK_CERTIFICATE_TYPE *)(val->pValue));
}

static const struct p11tool_attr *find_attribute(CK_ATTRIBUTE_TYPE type)
{
    const struct p11tool_attr *attr;
    const struct p11tool_objtype **keytype;

    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++) {
        if (attr->type == type)
            return attr;
    }

    for (keytype = p11sak_keytypes; *keytype != NULL; keytype++) {
        for (attr = (*keytype)->secret_attrs;
                                attr != NULL && attr->name != NULL; attr++) {
            if (attr->type == type)
                return attr;
        }

        for (attr = (*keytype)->public_attrs;
                                attr != NULL && attr->name != NULL; attr++) {
            if (attr->type == type)
                return attr;
        }

        for (attr = (*keytype)->private_attrs;
                                attr != NULL && attr->name != NULL; attr++) {
            if (attr->type == type)
                return attr;
        }
    }

    for (keytype = p11sak_certtypes; *keytype != NULL; keytype++) {
        for (attr = (*keytype)->cert_attrs;
                                attr != NULL && attr->name != NULL; attr++) {
            if (attr->type == type)
                return attr;
        }
    }

    return NULL;
}

static void print_attr_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive)
{
    const struct p11tool_attr *a;
    unsigned int i, num;

    if (val->ulValueLen == CK_UNAVAILABLE_INFORMATION ||
        (val->ulValueLen % sizeof(CK_ATTRIBUTE)) != 0)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else {
        num = val->ulValueLen / sizeof(CK_ATTRIBUTE);
        printf("%*s%s: %u attributes\n", indent, "", attr, num);
        for (i = 0; i < num; i++) {
            a = find_attribute(((CK_ATTRIBUTE *)(val->pValue))[i].type);
            if (a == NULL || a->print_long == NULL)
                printf("%*s%s: [attribute not supported]", indent + 4, "",
                       p11_get_cka(((CK_ATTRIBUTE *)(val->pValue))[i].type));
            else
                a->print_long(p11_get_cka(
                                   ((CK_ATTRIBUTE *)(val->pValue))[i].type),
                              &((CK_ATTRIBUTE *)(val->pValue))[i],
                              indent + 4, false);
        }
    }
}

static void print_custom_attrs(CK_OBJECT_HANDLE key,
                               const struct p11tool_attr *standard_attrs,
                               int indent)
{
    CK_RV rc;
    int f;
    struct ConfigBaseNode *c, *name, *id, *type;
    struct ConfigStructNode *structnode;
    const struct p11sak_custom_attr_type *atype;
    const struct p11tool_attr *attr;
    CK_ATTRIBUTE val;
    bool skip;

    confignode_foreach(c, p11sak_cfg, f) {
        if (!confignode_hastype(c, CT_STRUCT) ||
            strcmp(c->key, P11SAK_CONFIG_KEYWORD_ATTRIBUTE) != 0)
           continue;

        structnode = confignode_to_struct(c);
        name = confignode_find(structnode->value,
                               P11SAK_CONFIG_KEYWORD_NAME);
        id = confignode_find(structnode->value,
                             P11SAK_CONFIG_KEYWORD_ID);
        type = confignode_find(structnode->value,
                               P11SAK_CONFIG_KEYWORD_TYPE);

        if (name == NULL || !confignode_hastype(name, CT_BAREVAL)) {
            warnx("Sytax error in config file: Missing '%s' in attribute at line %hu\n",
                  P11SAK_CONFIG_KEYWORD_NAME, c->line);
            return;
        }
        if (id == NULL || !confignode_hastype(id, CT_INTVAL)) {
            warnx("Sytax error in config file: Missing '%s' in attribute at line %hu\n",
                  P11SAK_CONFIG_KEYWORD_ID, c->line);
            return;
        }
        if (type == NULL || !confignode_hastype(type, CT_BAREVAL)) {
            warnx("Sytax error in config file: Missing '%s' in attribute at line %hu\n",
                  P11SAK_CONFIG_KEYWORD_TYPE, c->line);
            return;
        }

        for (atype = custom_attr_types; atype->type != NULL; atype ++) {
            if (strcmp(atype->type,
                       confignode_to_bareval(type)->value) == 0)
                break;
        }
        if (atype->type == NULL) {
            warnx("Sytax error in config file: Invalid '%s' value in attribute at line %hu\n",
                   P11SAK_CONFIG_KEYWORD_TYPE, c->line);
            return;
        }

        /* Ignore any standard attributes also defined in the config file */
        for (skip = false, attr = standard_attrs;
                            attr != NULL && attr->name != NULL; attr++) {
            if (attr->type == confignode_to_intval(id)->value) {
                 skip = true;
                 break;
            }
        }
        if (skip)
            continue;

        val.type = confignode_to_intval(id)->value;
        val.ulValueLen = 0;
        val.pValue = NULL;
        rc = p11tool_get_attribute(key, &val);
        if (rc != CKR_OK && rc != CKR_ATTRIBUTE_SENSITIVE)
            continue;

        atype->print_long(confignode_to_bareval(name)->value,
                          &val, indent, rc == CKR_ATTRIBUTE_SENSITIVE);

        if (p11tool_is_attr_array_attr(&val))
            p11tool_free_attr_array_attr(&val);
        if (val.pValue != NULL)
            free(val.pValue);
    }
}

static void print_obj_attrs(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                            const struct p11tool_objtype *objtype, int indent)
{
    const struct p11tool_attr *attrs, *attr;
    CK_ATTRIBUTE val;
    CK_RV rc;

    switch (class) {
    case CKO_SECRET_KEY:
        attrs = objtype->secret_attrs;
        break;
    case CKO_PUBLIC_KEY:
        attrs = objtype->public_attrs;
        break;
    case CKO_PRIVATE_KEY:
        attrs = objtype->private_attrs;
        break;
    case CKO_CERTIFICATE:
        attrs = objtype->cert_attrs;
        break;
    default:
        attrs = NULL;
        break;
    }

    for (attr = attrs; attr != NULL && attr->name != NULL; attr++) {
        val.type = attr->type;
        val.ulValueLen = 0;
        val.pValue = NULL;

        rc = p11tool_get_attribute(key, &val);
        if (rc != CKR_OK && rc != CKR_ATTRIBUTE_SENSITIVE)
            continue;

        attr->print_long(attr->name, &val, indent,
                         rc == CKR_ATTRIBUTE_SENSITIVE);

        if (p11tool_is_attr_array_attr(&val))
            p11tool_free_attr_array_attr(&val);
        if (val.pValue != NULL)
            free(val.pValue);
    }

    print_custom_attrs(key, attrs, indent);
}

static CK_RV print_boolean_attrs(CK_OBJECT_HANDLE obj, CK_OBJECT_CLASS class,
                                 const struct p11tool_objtype *objtype,
                                 const char *typestr, const char* label,
                                 struct p11sak_list_data *data)
{
    const struct p11tool_attr *attr;
    bool applicable;
    CK_ULONG i;
    CK_RV rc;

    rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session, obj,
                                                   data->bool_attrs,
                                                   data->num_bool_attrs);
    if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID) {
        warnx("Failed to get boolean attributes for %s %s \"%s\": 0x%lX: %s",
              typestr, objtype->obj_typestr, label, rc, p11_get_ckr(rc));
        return rc;
    }

    for (attr = data->attrs, i = 0; attr->name != NULL; attr++, i++) {
        switch (class) {
        case CKO_SECRET_KEY:
            applicable = p11tool_secret_attr_applicable(objtype, attr);
            break;
        case CKO_PUBLIC_KEY:
            applicable = p11tool_public_attr_applicable(objtype, attr);
            break;
        case CKO_PRIVATE_KEY:
            applicable = p11tool_private_attr_applicable(objtype, attr);
            break;
        case CKO_CERTIFICATE:
            applicable = p11tool_cert_attr_applicable(objtype, attr);
            break;
        default:
           applicable = false;
           break;
        }

        if (data->bool_attrs[i].ulValueLen == CK_UNAVAILABLE_INFORMATION)
            applicable = false;

        if (opt_long) {
            if (!applicable)
                continue;

            attr->print_long(attr->name, &data->bool_attrs[i], 8, false);
        } else {
            attr->print_short(&data->bool_attrs[i], applicable);
        }
    }

    return CKR_OK;
}

static const CK_BYTE *p11sak_get_cca_wkvp(const struct p11tool_token_info *info,
                                          const CK_BYTE *secure_key,
                                          CK_ULONG secure_key_len,
                                          const char **mktype)
{
    const struct cca_token_header *header =
                        (const struct cca_token_header *)secure_key;
    CK_ULONG mkvp_offset = 0;

    if (secure_key_len <= sizeof(*header))
        return NULL;

    /*
     * For token format, values and offsets, see manual "Common Cryptographic
     * Architecture Application Programmer's Guide" chapter 20 "Key token
     * formats"
     */
    if (header->id == 0x01 &&
        (header->version == 0x00 || header->version == 0x01)) {
        /* Internal secure CCA DES DATA key with exact 64 bytes */
        mkvp_offset = sizeof(*header);
        *mktype = "CCA SYM";
    } else if (header->id == 0x01 && header->version == 0x04) {
        /* Internal secure CCA AES DATA key with exact 64 bytes */
        mkvp_offset = sizeof(*header);
        *mktype = "CCA AES";
    } else if (header->id == 0x01 && header->version == 0x05) {
        /* Internal variable length secure CCA key */
        if (secure_key_len < be16toh(header->len) || secure_key_len < 42)
            return NULL;
        if (secure_key[41] == 0x02 &&
            be16toh(*((uint16_t*)(&secure_key[42]))) == 0x0001) {
            /* Internal variable length secure CCA AES CIPHER key */
            mkvp_offset = 10;
            *mktype = "CCA AES";
        } else if (secure_key[41] == 0x03 &&
             be16toh(*((uint16_t*)(&secure_key[42]))) == 0x0002) {
             /* Internal variable length secure CCA HMAC key */
             mkvp_offset = 10;
             *mktype = "CCA AES";
        } else {
            return NULL;
        }
    } else if (header->id == 0x1f) {
        /* Internal secure CCA private key */
        if (secure_key_len < be16toh(header->len))
            return NULL;
        if (secure_key[sizeof(*header)] == 0x30) {
            /* Internal secure CCA private RSA key, ME format */
            mkvp_offset = sizeof(*header) + 104;
            *mktype = "CCA APKA";
        } else if (secure_key[sizeof(*header)] == 0x31) {
            /* Internal secure CCA private RSA key, CRT format */
            mkvp_offset = sizeof(*header) + 116;
            *mktype = "CCA APKA";
        } else if (secure_key[sizeof(*header)] == 0x20) {
            /* Internal secure CCA private ECC key */
            mkvp_offset = sizeof(*header) + 16;
            *mktype = "CCA APKA";
        } else if (secure_key[sizeof(*header)] == 0x50) {
            /* Internal secure CCA private QSA key */
            mkvp_offset = sizeof(*header) + 118;
            *mktype = "CCA APKA";
        } else {
            return NULL;
        }
    } else  {
       return NULL;
    }

    if (secure_key_len < mkvp_offset + info->mkvp_size)
        return NULL;

    return &secure_key[mkvp_offset];
}

static void p11sak_print_mkvp_cca_short(const struct p11tool_token_info *info,
                                        const CK_BYTE *secure_key,
                                        CK_ULONG secure_key_len,
                                        const char *separator)
{
    unsigned int i;
    const CK_BYTE *mkvp;
    const char *mktype = NULL;

    mkvp = p11sak_get_cca_wkvp(info, secure_key, secure_key_len, &mktype);
    if (mkvp == NULL) {
        printf("%-*s | %-*s", MAX(LIST_MKVP_MIN_CELL_SIZE, info->mkvp_size * 2),
               "-", MAX(LIST_MKTYPE_MIN_CELL_SIZE, info->mktype_cell_size),
               "-");
        return;
    }

    for (i = 0; i < info->mkvp_size; i++)
        printf("%02X", mkvp[i]);
    for (i = info->mkvp_size * 2; i < LIST_MKVP_MIN_CELL_SIZE; i++)
        printf(" ");
    printf("%s%-*s", separator, MAX(LIST_MKTYPE_MIN_CELL_SIZE,
                                    info->mktype_cell_size), mktype);
}

static void p11sak_print_mkvp_cca_long(const struct p11tool_token_info *info,
                                       const CK_BYTE *secure_key,
                                       CK_ULONG secure_key_len,
                                       int indent)
{
    unsigned int i;
    const CK_BYTE *mkvp;
    const char *mktype = NULL;

    mkvp = p11sak_get_cca_wkvp(info, secure_key, secure_key_len, &mktype);
    if (mkvp == NULL)
        return;

    printf("%*sMKVP: ", indent, "");
    for (i = 0; i < info->mkvp_size; i++)
        printf("%02X", mkvp[i]);
    printf(" (%s)\n", mktype);
}

static CK_RV p11sak_get_ep11_get_spki_len(const CK_BYTE *secure_key,
                                          CK_ULONG secure_key_len,
                                          CK_ULONG *spki_len)
{
    CK_ULONG len, i, val = 0;

    /*
     * From the EP11 structure document:
     *    Session identifiers are guaranteed not to have 0x30 as their first
     *    byte. This allows a single-byte check to differentiate between blobs
     *    starting with session identifiers, and MACed SPKIs, which may be
     *    used as blobs under other conditions.
     * Key and state blobs start with the session identifier (32 bytes).
     * SPKIs start with a DER encoded SPKI, which itself stars with a SEQUENCE
     * denoted by 0x30 followed by the DER encoded length of the SPKI.
     */
    if (secure_key_len > 5 && secure_key[0] == 0x30) {
        len = secure_key[1] & 0x7F;
        if (secure_key[1] & 0x80) {
            /* long form, len contains number of length bytes */
            if (len > 4)
                return CKR_FUNCTION_FAILED;

            for (i = 0; i < len; i++) {
                if (i > 0)
                    val <<= 8;
                val |= secure_key[2 + i];
            }

            *spki_len = 2 + len + val;
        } else {
            /* short form */
            *spki_len = 2 + len;
        }

        return CKR_OK;
    }

    /* No SPKI */
    *spki_len = 0;
    return CKR_OK;
}

static const CK_BYTE *p11sak_get_ep11_wkvp(const struct p11tool_token_info *info,
                                           const CK_BYTE *secure_key,
                                           CK_ULONG secure_key_len)
{
    CK_ULONG spki_len, wkid_len;

    if (p11sak_get_ep11_get_spki_len(secure_key, secure_key_len,
                                     &spki_len) != CKR_OK)
        return NULL;

    if (spki_len > 0) {
        /* An OCTET STRING with short form length must follow */
        if (secure_key_len < spki_len + 2 || secure_key[spki_len] != 0x04)
            return NULL;

        wkid_len = secure_key[spki_len + 1];
        if (wkid_len != info->mkvp_size)
            return NULL;

        return &secure_key[spki_len + 2];
    }

    /* Secure key */
    if (secure_key_len <= EP11_WKVP_OFFSET + info->mkvp_size)
        return NULL;

    return &secure_key[EP11_WKVP_OFFSET];
}

static void p11sak_print_mkvp_ep11_short(const struct p11tool_token_info *info,
                                         const CK_BYTE *secure_key,
                                         CK_ULONG secure_key_len,
                                         const char *separator)
{
    unsigned int i;
    const CK_BYTE *wkvp;

    wkvp = p11sak_get_ep11_wkvp(info, secure_key, secure_key_len);
    if (wkvp == NULL) {
        printf("%-*s | %-*s", MAX(LIST_MKVP_MIN_CELL_SIZE, info->mkvp_size * 2),
               "-", MAX(LIST_MKTYPE_MIN_CELL_SIZE, info->mktype_cell_size),
               "-");
        return;
    }

    for (i = 0; i < info->mkvp_size; i++)
        printf("%02X", wkvp[i]);
    for (i = info->mkvp_size * 2; i < LIST_MKVP_MIN_CELL_SIZE; i++)
        printf(" ");
    printf("%s%-*s", separator, MAX(LIST_MKTYPE_MIN_CELL_SIZE,
                                    info->mktype_cell_size), "EP11-WK");
}

static void p11sak_print_mkvp_ep11_long(const struct p11tool_token_info *info,
                                        const CK_BYTE *secure_key,
                                        CK_ULONG secure_key_len,
                                        int indent)
{
    unsigned int i;
    const CK_BYTE *wkvp;

    wkvp = p11sak_get_ep11_wkvp(info, secure_key, secure_key_len);
    if (wkvp == NULL)
        return;

    printf("%*sMKVP: ", indent, "");
    for (i = 0; i < info->mkvp_size; i++)
        printf("%02X", wkvp[i]);
    printf(" (EP11-WK)\n");
}

static const CK_BYTE *p11sak_get_ep11_session_id(
                                          const struct p11tool_token_info *info,
                                          const CK_BYTE *secure_key,
                                          CK_ULONG secure_key_len)
{
    CK_ULONG spki_len, wkid_len, sess_id_len;

    if (p11sak_get_ep11_get_spki_len(secure_key, secure_key_len,
                                     &spki_len) != CKR_OK)
        return NULL;

    if (spki_len > 0) {
        /* An OCTET STRING with short form length must follow */
        if (secure_key_len < spki_len + 2 || secure_key[spki_len] != 0x04)
            return NULL;

        wkid_len = secure_key[spki_len + 1];
        if (wkid_len != info->mkvp_size)
            return NULL;

        /* An OCTET STRING with short form length must follow */
        if (secure_key_len < spki_len + 2 + wkid_len + 2 ||
            secure_key[spki_len + 2 + wkid_len] != 0x04)
            return NULL;

        sess_id_len = secure_key[spki_len + 2 + wkid_len + 1];
        if (sess_id_len != info->session_id_size)
            return NULL;

        return &secure_key[spki_len + 2 + wkid_len + 2];
    }

    /* Secure key */
    if (secure_key_len <= EP11_SESSION_ID_OFFSET + info->session_id_size)
        return NULL;

    return &secure_key[EP11_SESSION_ID_OFFSET];
}

static const CK_BYTE ep11_null_session[32] = { 0 };

static void p11sak_print_session_id_ep11_short(
                                         const struct p11tool_token_info *info,
                                         const CK_BYTE *secure_key,
                                         CK_ULONG secure_key_len)
{
    unsigned int i;
    const CK_BYTE *session_id;

    session_id = p11sak_get_ep11_session_id(info, secure_key, secure_key_len);
    if (session_id == NULL ||
        memcmp(session_id, ep11_null_session, sizeof(ep11_null_session)) == 0) {
        printf("%-*s", MAX(LIST_SESS_MIN_CELL_SIZE,
                           info->session_id_size * 2), "-");
        return;
    }

    for (i = 0; i < info->session_id_size; i++)
        printf("%02X", session_id[i]);
    for (i = info->session_id_size * 2; i < LIST_SESS_MIN_CELL_SIZE; i++)
        printf(" ");
}

static void p11sak_print_session_id_ep11_long(
                                        const struct p11tool_token_info *info,
                                        const CK_BYTE *secure_key,
                                        CK_ULONG secure_key_len,
                                        int indent)
{
    unsigned int i;
    const CK_BYTE *session_id;

    session_id = p11sak_get_ep11_session_id(info, secure_key, secure_key_len);
    if (session_id == NULL)
        return;

    if (memcmp(session_id, ep11_null_session, sizeof(ep11_null_session)) == 0) {
        printf("%*sSession-ID: [none]\n", indent, "");
        return;
    }

    printf("%*sSession-ID: ", indent, "");
    for (i = 0; i < info->session_id_size; i++)
        printf("%02X", session_id[i]);
    printf("\n");
}

static CK_RV handle_obj_list(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                             const struct p11tool_objtype *objtype,
                             CK_ULONG keysize, const char *typestr,
                             const char* label, const char *common_name,
                             void *private)
{
    struct p11sak_list_data *data = private;
    struct p11_uri *uri = NULL;
    CK_ATTRIBUTE secure_key_attr = { 0 };
    CK_RV rc;

    UNUSED(keysize);

    rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session, key,
                                                   data->bool_attrs,
                                                   data->num_bool_attrs);
    if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID) {
        warnx("Failed to get boolean attributes for %s %s \"%s\": 0x%lX: %s",
              typestr, objtype->obj_typestr, label, rc, p11_get_ckr(rc));
        return rc;
    }

    if ((opt_hsm_mkvp || opt_ep11_session_id) && p11tool_token_info != NULL) {
        /* Get secure key attr, ignore if key does not have that attribute */
        secure_key_attr.type =  p11tool_token_info->secure_key_attr;
        rc = p11tool_get_attribute(key, &secure_key_attr);
        if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID) {
            warnx("Failed to retrieve attribute %s from object "
                  "\"%s\": 0x%lX: %s",
                  p11_get_ckm(&mechtable_funcs, secure_key_attr.type),
                  label, rc, p11_get_ckr(rc));
            return rc;
        }
    }

    if (opt_long) {
        rc = p11tool_prepare_uri(key, &class, objtype, typestr, label,
                                 opt_detailed_uri, opt_slot, &uri);
        if (rc != CKR_OK)
            goto done;

        printf("Label: \"%s\"\n", label);
        printf("    URI: %s\n", p11_uri_format(uri));
        printf("    %s: %s\n", objtype->obj_liststr, typestr);
        if (opt_hsm_mkvp && p11tool_token_info != NULL &&
            secure_key_attr.pValue != NULL && secure_key_attr.ulValueLen > 0) {
             p11tool_token_info->print_mkvp_long(p11tool_token_info,
                                        secure_key_attr.pValue,
                                        secure_key_attr.ulValueLen,
                                        4);
        }
        if (opt_ep11_session_id && p11tool_token_info != NULL &&
                   secure_key_attr.pValue != NULL &&
                   secure_key_attr.ulValueLen > 0 &&
                   p11tool_token_info->print_session_id_long != NULL) {
             p11tool_token_info->print_session_id_long(p11tool_token_info,
                                        secure_key_attr.pValue,
                                        secure_key_attr.ulValueLen,
                                        4);
        }
        printf("    Attributes:\n");
        printf("        CKA_TOKEN: CK_TRUE\n");
    } else {
        printf("| ");
    }

    if (!opt_long && opt_hsm_mkvp && p11tool_token_info != NULL) {
        if (secure_key_attr.pValue != NULL && secure_key_attr.ulValueLen > 0)
            p11tool_token_info->print_mkvp_short(p11tool_token_info,
                                         secure_key_attr.pValue,
                                         secure_key_attr.ulValueLen,
                                         " | ");
        else
            printf("%-*s | %-*s", MAX(LIST_MKVP_MIN_CELL_SIZE,
                    p11tool_token_info->mkvp_size * 2),
                   "-", MAX(LIST_MKTYPE_MIN_CELL_SIZE,
                           p11tool_token_info->mktype_cell_size), "-");
        printf(" ");
    } else if (!opt_long && opt_ep11_session_id && p11tool_token_info != NULL) {
        if (secure_key_attr.pValue != NULL && secure_key_attr.ulValueLen > 0 &&
            p11tool_token_info->print_session_id_short != NULL)
            p11tool_token_info->print_session_id_short(p11tool_token_info,
                                         secure_key_attr.pValue,
                                         secure_key_attr.ulValueLen);
        else
            printf("%-*s", MAX(LIST_SESS_MIN_CELL_SIZE,
                    p11tool_token_info->session_id_size * 2), "-");
        printf(" ");
    } else {
        rc = print_boolean_attrs(key, class, objtype, typestr, label, data);
        if (rc != CKR_OK)
            goto done;
    }

    if (opt_long)
        print_obj_attrs(key, class, objtype, 8);
    else {
        if (data->objclass != OBJCLASS_CERTIFICATE) {
            printf("| %*s | \"%s\"\n", LIST_KEYTYPE_CELL_SIZE, typestr, label);
        } else {
            char display_name[LIST_CERT_CN_CELL_SIZE + 1] = { 0 };
            int len = strlen(common_name);
            if (len > LIST_CERT_CN_CELL_SIZE) {
                strncpy(display_name, common_name, LIST_CERT_CN_CELL_SIZE - 3);
                strcat(display_name, "...");
            } else {
                strcpy(display_name, common_name);
            }
            printf("| %*s | %*s | \"%s\"\n", LIST_CERTTYPE_CELL_SIZE, typestr,
                   LIST_CERT_CN_CELL_SIZE, display_name, label);
        }
    }

    data->num_displayed++;
    rc = CKR_OK;

done:
    if (uri != NULL) {
        if (uri->obj_id[0].pValue != NULL)
            free(uri->obj_id[0].pValue);
        p11_uri_free(uri);
    }
    if (secure_key_attr.pValue != NULL)
        free(secure_key_attr.pValue);

    return rc;
}

static CK_RV p11sak_list_obj_compare(CK_OBJECT_HANDLE obj1,
                                     CK_OBJECT_HANDLE obj2,
                                     int *result, void *private)
{
    struct p11sak_list_data *data = private;
    CK_OBJECT_CLASS class1, class2;
    CK_KEY_TYPE ktype1, ktype2;
    CK_ULONG keysize1 = 0, keysize2 = 0;
    char *label1 = NULL, *label2 = NULL;
    char *cn1 = NULL, *cn2 = NULL;
    CK_RV rc;
    int i;

    *result = 0;

    rc = get_obj_infos(obj1, &class1, &ktype1, &keysize1, &label1, NULL, NULL, &cn1);
    if (rc != CKR_OK)
        goto done;

    rc = get_obj_infos(obj2, &class2, &ktype2, &keysize2, &label2, NULL, NULL, &cn2);
    if (rc != CKR_OK)
        goto done;

    for (i = 0; i < MAX_SORT_FIELDS; i++) {
        switch (data->sort_info[i].field) {
        case SORT_LABEL:
            if (label1 == NULL || label2 == NULL)
                break;
            *result = strcmp(label1, label2);
            break;
        case SORT_KEYTYPE:
            *result = (long)ktype1 - (long)ktype2;
            break;
        case SORT_CLASS:
            *result = (long)class1 - (long)class2;
            break;
        case SORT_KEYSIZE:
            *result = (long)keysize1 - (long)keysize2;
            break;
        case SORT_CN:
            if (cn1 == NULL || cn2 == NULL)
                break;
            *result = strcmp(cn1, cn2);
            break;
        case SORT_NONE:
        default:
            break;
        }

        if (data->sort_info[i].descending)
            *result = -*result;

        if (*result != 0)
            break;
    }

done:
    if (label1 != NULL)
        free(label1);
    if (label2 != NULL)
        free(label2);
    if (cn1 != NULL)
        free(cn1);
    if (cn2 != NULL)
        free(cn2);

    return rc;
}

static CK_RV parse_sort_specification(const char *sort_spec,
                                      struct p11sak_list_data *data)
{
    CK_RV rc = CKR_OK;
    char *tok;
    unsigned int i = 0;
    char *spec;

    spec = strdup(sort_spec);
    if (spec == NULL) {
        warnx("Failed to allocate the sort specification string.");
        return CKR_HOST_MEMORY;
    }

    tok = strtok(spec, ",");
    while (tok != NULL) {
        if (i >= MAX_SORT_FIELDS) {
            warnx("Too many sort field designators.");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        switch (data->objclass) {
        case OBJCLASS_CERTIFICATE:
            switch (tolower(*tok)) {
            case 'l':
                data->sort_info[i].field = SORT_LABEL;
                break;
            case 'n':
                data->sort_info[i].field = SORT_CN;
                break;
            default:
                warnx("Invalid sort field designator: '%c'.", *tok);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
            break;
        case OBJCLASS_KEY:
            switch (tolower(*tok)) {
            case 'l':
                data->sort_info[i].field = SORT_LABEL;
                break;
            case 'k':
                data->sort_info[i].field = SORT_KEYTYPE;
                break;
            case 'c':
                data->sort_info[i].field = SORT_CLASS;
                break;
            case 's':
                data->sort_info[i].field = SORT_KEYSIZE;
                break;
            default:
                warnx("Invalid sort field designator: '%c'.", *tok);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
            break;
        default:
            warnx("Cannot sort objects of class %d", data->objclass);
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        tok++;
        if (*tok == ':') {
            tok++;
            switch (tolower(*tok)) {
            case 'a':
                data->sort_info[i].descending = false;
                break;
            case 'd':
                data->sort_info[i].descending = true;
                break;
            default:
                warnx("Invalid sort order designator: '%c'.", *tok);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }

            tok++;
            if (*tok != '\0') {
                warnx("Invalid character(s) after sort order designator: '%s'.",
                      tok);
                rc = CKR_ARGUMENTS_BAD;
                goto done;
            }
        } else if (*tok == '\0') {
            data->sort_info[i].descending = false;
        } else {
            warnx("Invalid character(s) after sort field designator: '%s'.",
                  tok);
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        tok = strtok(NULL, ",");
        i++;
    }

done:
    free(spec);

    return rc;
}

static CK_RV p11sak_list_key(void)
{
    const struct p11tool_objtype *keytype = NULL;
    const struct p11tool_attr *attr;
    struct p11sak_list_data data = { 0 };
    unsigned int i;
    CK_BYTE *attr_data = NULL;
    CK_RV rc;

    if (opt_keytype != NULL)
        keytype = opt_keytype->private.ptr;

    if (opt_hsm_mkvp && p11tool_token_info == NULL) {
        warnx("Option '-m'/'--hsm-mkvp' can only be used with secure key "
              "tokens");
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }
    if (opt_ep11_session_id && (p11tool_token_info == NULL ||
        (p11tool_token_info != NULL &&
         p11tool_token_info->type != TOKTYPE_EP11))) {
        warnx("Option '-e'/'--ep11-session-id' can only be used with an EP11 "
              "token");
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }
    if (!opt_long && opt_hsm_mkvp && opt_ep11_session_id) {
        warnx("Either '-m'/'--hsm-mkvp' or '-e'/'--ep11-session-id' can can be "
              "specified, unless '-l'/'--long' is also specified");
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    for (attr = p11sak_bool_attrs, data.num_bool_attrs = 0; attr->name != NULL;
                                        attr++, data.num_bool_attrs++)
        ;
    attr_data = calloc(data.num_bool_attrs, sizeof(CK_BBOOL));
    data.bool_attrs = calloc(data.num_bool_attrs, sizeof(CK_ATTRIBUTE));
    if (attr_data == NULL || data.bool_attrs == NULL) {
        warnx("Failed to allocate memory for the attributes");
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    for (attr = p11sak_bool_attrs, i = 0; attr->name != NULL; attr++, i++) {
        data.bool_attrs[i].type = attr->type;
        data.bool_attrs[i].ulValueLen = sizeof(CK_BBOOL);
        data.bool_attrs[i].pValue = &attr_data[i];
    }
    data.attrs = p11sak_bool_attrs;
    data.objclass = OBJCLASS_KEY;

    if (opt_sort) {
        rc = parse_sort_specification(opt_sort, &data);
        if (rc != CKR_OK)
            goto done;
    }

    if (opt_hsm_mkvp && !opt_long) {
        printf("| MASTER KEY VERIFICATION PATTERN ");
        for(i = LIST_MKVP_MIN_CELL_SIZE; i < p11tool_token_info->mkvp_size * 2;
                                                            i++)
            printf(" ");
        printf(" | %-*s ", MAX(LIST_MKTYPE_MIN_CELL_SIZE,
                p11tool_token_info->mktype_cell_size), "MK TYPE");
        printf("| %*s | LABEL\n", LIST_KEYTYPE_CELL_SIZE, "KEY TYPE");
        printf("|-");
        for(i = 0; i < MAX(LIST_MKVP_MIN_CELL_SIZE,
                           p11tool_token_info->mkvp_size * 2); i++)
            printf("-");
        printf("-+-");
        for (i = 0; i < MAX(LIST_MKTYPE_MIN_CELL_SIZE,
                p11tool_token_info->mktype_cell_size); i++)
            printf("-");
        printf("-+-");
        for (i = 0; i < LIST_KEYTYPE_CELL_SIZE; i++)
            printf("-");
        printf("-+--------------------\n");
    } else if (opt_ep11_session_id && !opt_long) {
        printf("| EP11 SESSION ID ");
        for(i = LIST_SESS_MIN_CELL_SIZE;
                            i < p11tool_token_info->session_id_size * 2; i++)
            printf(" ");
        printf(" | %*s | LABEL\n", LIST_KEYTYPE_CELL_SIZE, "KEY TYPE");
        printf("|-");
        for(i = 0; i < MAX(LIST_SESS_MIN_CELL_SIZE,
                           p11tool_token_info->session_id_size * 2); i++)
            printf("-");
        printf("-+-");
        for (i = 0; i < LIST_KEYTYPE_CELL_SIZE; i++)
            printf("-");
        printf("-+--------------------\n");
    } else if (!opt_long) {
        printf("| ");
        for (attr = p11sak_bool_attrs; attr->name != NULL; attr++)
            printf("%c ", attr->letter);
        printf("| %*s | LABEL\n", LIST_KEYTYPE_CELL_SIZE, "KEY TYPE");
        printf("|-");
        for (attr = p11sak_bool_attrs; attr->name != NULL; attr++)
            printf("--");
        printf("+-");
        for (i = 0; i < LIST_KEYTYPE_CELL_SIZE; i++)
            printf("-");
        printf("-+--------------------\n");
    }

    rc = iterate_objects(keytype, opt_label, opt_id, opt_attr,
                         OBJCLASS_KEY,
                         opt_sort != NULL ? p11sak_list_obj_compare : NULL,
                         handle_obj_list, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over key objects for key type %s: 0x%lX: %s",
                keytype != NULL ? keytype->name : "All", rc, p11_get_ckr(rc));
        goto done;
    }

    printf("\n");
    printf("%lu key(s) displayed\n", data.num_displayed);

done:
    if (data.bool_attrs != NULL)
        free(data.bool_attrs);
    if (attr_data != NULL)
        free(attr_data);

    return rc;
}

static CK_RV p11sak_list_cert(void)
{
    const struct p11tool_objtype *certtype = NULL;
    const struct p11tool_attr *attr;
    struct p11sak_list_data data = { 0 };
    unsigned int i;
    CK_BYTE *attr_data = NULL;
    CK_RV rc;

    if (opt_certtype != NULL)
        certtype = opt_certtype->private.ptr;

    for (attr = p11sak_bool_cert_attrs, data.num_bool_attrs = 0; attr->name != NULL;
                                        attr++, data.num_bool_attrs++)
        ;
    attr_data = calloc(data.num_bool_attrs, sizeof(CK_BBOOL));
    data.bool_attrs = calloc(data.num_bool_attrs, sizeof(CK_ATTRIBUTE));
    if (attr_data == NULL || data.bool_attrs == NULL) {
        warnx("Failed to allocate memory for the attributes");
        rc = CKR_HOST_MEMORY;
        goto done;
    }
    for (attr = p11sak_bool_cert_attrs, i = 0; attr->name != NULL; attr++, i++) {
        data.bool_attrs[i].type = attr->type;
        data.bool_attrs[i].ulValueLen = sizeof(CK_BBOOL);
        data.bool_attrs[i].pValue = &attr_data[i];
    }
    data.attrs = p11sak_bool_cert_attrs;
    data.objclass = OBJCLASS_CERTIFICATE;

    if (opt_sort) {
        rc = parse_sort_specification(opt_sort, &data);
        if (rc != CKR_OK)
            goto done;
    }

    if (!opt_long) {
        printf("| ");
        for (attr = p11sak_bool_cert_attrs; attr->name != NULL; attr++)
            printf("%c ", attr->letter);
        printf("| %*s | SUBJECT-CN             | LABEL\n", LIST_CERTTYPE_CELL_SIZE, "CERT TYPE");
        printf("|-");
        for (attr = p11sak_bool_cert_attrs; attr->name != NULL; attr++)
            printf("--");
        printf("+-");
        for (i = 0; i < LIST_CERTTYPE_CELL_SIZE; i++)
            printf("-");
        printf("-+------------------------+-------------------------\n");
    }

    rc = iterate_objects(certtype, opt_label, opt_id, opt_attr,
                         OBJCLASS_CERTIFICATE,
                         opt_sort != NULL ? p11sak_list_obj_compare : NULL,
                         handle_obj_list, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over certificate objects for type %s: 0x%lX: %s",
                certtype != NULL ? certtype->name : "All", rc, p11_get_ckr(rc));
        goto done;
    }

    printf("\n");
    printf("%lu certificate(s) displayed\n", data.num_displayed);

done:
    if (data.bool_attrs != NULL)
        free(data.bool_attrs);
    if (attr_data != NULL)
        free(attr_data);

    return rc;
}

static CK_RV handle_obj_remove(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                               const struct p11tool_objtype *keytype,
                               CK_ULONG keysize, const char *typestr,
                               const char* label, const char *common_name,
                               void *private)
{
    struct p11sak_remove_data *data = private;
    char *msg = NULL;
    char ch;
    CK_RV rc;

    UNUSED(class);
    UNUSED(keysize);
    UNUSED(common_name);

    if (data->skip_all) {
        data->num_skipped++;
        return CKR_OK;
    }

    if (!data->remove_all) {
        if (asprintf(&msg, "Are you sure you want to remove %s %s object \"%s\" [y/n/a/c]? ",
                     typestr, keytype->obj_typestr, label) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return CKR_HOST_MEMORY;
        }
        ch = p11tool_prompt_user(msg, "ynac");
        free(msg);

        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        case 'c':
        case '\0':
            data->skip_all = true;
            data->num_skipped++;
            return CKR_OK;
        case 'a':
            data->remove_all = true;
            break;
        default:
            break;
        }
    }

    rc = p11tool_pkcs11_funcs->C_DestroyObject(p11tool_pkcs11_session, key);
    if (rc != CKR_OK) {
        warnx("Failed to remove %s %s object \"%s\": C_DestroyObject: 0x%lX: %s",
               typestr, keytype->obj_typestr, label, rc, p11_get_ckr(rc));
        data->num_failed++;
        return CKR_OK;
    }

    printf("Successfully removed %s %s object \"%s\".\n", typestr, keytype->obj_typestr, label);
    data->num_removed++;

    return CKR_OK;
}

static CK_RV p11sak_remove_key(void)
{
    const struct p11tool_objtype *keytype = NULL;
    struct p11sak_remove_data data = { 0 };
    CK_RV rc;

    if (opt_keytype != NULL)
        keytype = opt_keytype->private.ptr;

    data.remove_all = opt_force;

    rc = iterate_objects(keytype, opt_label, opt_id, opt_attr,
                         OBJCLASS_KEY, NULL,
                         handle_obj_remove, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over key objects for key type %s: 0x%lX: %s",
                keytype != NULL ? keytype->name : "All", rc, p11_get_ckr(rc));
        return rc;
    }

    printf("%lu key object(s) removed.\n", data.num_removed);
    if (data.num_skipped > 0)
        printf("%lu key object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu key object(s) failed to remove.\n", data.num_failed);

    return data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV p11sak_remove_cert(void)
{
    const struct p11tool_objtype *certtype = NULL;
    struct p11sak_remove_data data = { 0 };
    CK_RV rc;

    if (opt_certtype != NULL)
        certtype = opt_certtype->private.ptr;

    data.remove_all = opt_force;

    rc = iterate_objects(certtype, opt_label, opt_id, opt_attr,
                         OBJCLASS_CERTIFICATE, NULL,
                         handle_obj_remove, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over certificate objects for type %s: 0x%lX: %s",
                certtype != NULL ? certtype->name : "All", rc, p11_get_ckr(rc));
        return rc;
    }

    printf("%lu certificate object(s) removed.\n", data.num_removed);
    if (data.num_skipped > 0)
        printf("%lu certificate object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu certificate object(s) failed to remove.\n", data.num_failed);

    return data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV handle_obj_set_attr(CK_OBJECT_HANDLE obj, CK_OBJECT_CLASS class,
                                 const struct p11tool_objtype *objtype,
                                 CK_ULONG keysize, const char *typestr,
                                 const char* label, const char *common_name,
                                 void *private)
{
    struct p11sak_set_attr_data *data = private;
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    char *msg = NULL;
    char ch;
    CK_RV rc;
    bool (*attr_applicable)(const struct p11tool_objtype *objtype,
                            const struct p11tool_attr *attr);

    UNUSED(keysize);
    UNUSED(common_name);

    if (data->skip_all) {
        data->num_skipped++;
        return CKR_OK;
    }

    if (!data->set_all) {
        if (asprintf(&msg, "Are you sure you want to change %s %s object \"%s\" [y/n/a/c]? ",
                     typestr, objtype->obj_typestr, label) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return CKR_HOST_MEMORY;
        }
        ch = p11tool_prompt_user(msg, "ynac");
        free(msg);

        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        case 'c':
        case '\0':
            data->skip_all = true;
            data->num_skipped++;
            return CKR_OK;
        case 'a':
            data->set_all = true;
            break;
        default:
            break;
        }
    }

    switch (class) {
    case CKO_SECRET_KEY:
        attr_applicable = p11tool_secret_attr_applicable;
        break;
    case CKO_PUBLIC_KEY:
        attr_applicable = p11tool_public_attr_applicable;
        break;
    case CKO_PRIVATE_KEY:
        attr_applicable = p11tool_private_attr_applicable;
        break;
    case CKO_CERTIFICATE:
        attr_applicable = p11tool_cert_attr_applicable;
        break;
    default:
        warnx("Object \"%s\" has an unsupported object class: %lu",
              label, class);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }

    if (opt_new_attr != NULL) {
        rc = p11tool_parse_boolean_attrs(objtype, p11sak_bool_attrs,
                                         opt_new_attr, &attrs, &num_attrs,
                                         true, opt_so, attr_applicable);
        if (rc != CKR_OK) {
            data->num_failed++;
            goto done;
        }

        if (num_attrs == 0) {
            warnx("None of the specified attributes apply to %s %s object \"%s\".",
                  typestr, objtype->obj_typestr, label);
            data->num_skipped++;
            goto done;
        }
    }

    if (opt_new_label != NULL) {
        rc = p11tool_add_attribute(CKA_LABEL, opt_new_label,
                                   strlen(opt_new_label),
                                   &attrs, &num_attrs);
        if (rc != CKR_OK) {
            warnx("Failed to add %s %s attribute CKA_LABEL: 0x%lX: %s",
                  objtype->name, objtype->obj_typestr, rc, p11_get_ckr(rc));
            goto done;
        }
    }

    if (opt_new_id != NULL) {
        rc = p11tool_parse_id(opt_new_id, &attrs, &num_attrs);
        if (rc != CKR_OK)
            goto done;
    }

    rc = p11tool_pkcs11_funcs->C_SetAttributeValue(p11tool_pkcs11_session, obj,
                                                   attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to change %s %s object \"%s\": C_SetAttributeValue: 0x%lX: %s",
              typestr, objtype->obj_typestr, label, rc, p11_get_ckr(rc));
        data->num_failed++;
        rc = CKR_OK;
        goto done;
    }

    printf("Successfully changed %s %s object \"%s\".\n", typestr,
            objtype->obj_typestr, label);
    data->num_set++;

done:
    p11tool_free_attributes(attrs, num_attrs);
    return rc;
}

static CK_RV p11sak_set_key_attr(void)
{
    const struct p11tool_objtype *keytype = NULL;
    struct p11sak_set_attr_data data = { 0 };
    CK_RV rc;

    if (opt_keytype != NULL)
        keytype = opt_keytype->private.ptr;

    if (opt_new_attr == NULL && opt_new_label == NULL && opt_new_id == NULL) {
        warnx("At least one of the following options must be specified:");
        warnx("'-A'/'--new-attr', '-l'/'--new-label', or '-I'/'--new-id'");
        return CKR_ARGUMENTS_BAD;
    }

    data.set_all = opt_force;

    rc = iterate_objects(keytype, opt_label, opt_id, opt_attr,
                         OBJCLASS_KEY, NULL,
                         handle_obj_set_attr, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over key objects for key type %s: 0x%lX: %s",
                keytype != NULL ? keytype->name : "All", rc, p11_get_ckr(rc));
        return rc;
    }

    printf("%lu key object(s) updated.\n", data.num_set);
    if (data.num_skipped > 0)
        printf("%lu key object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu key object(s) failed to update.\n", data.num_failed);

    return data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV p11sak_set_cert_attr(void)
{
    const struct p11tool_objtype *certtype = NULL;
    struct p11sak_set_attr_data data = { 0 };
    CK_RV rc;

    if (opt_certtype != NULL)
        certtype = opt_certtype->private.ptr;

    if (opt_new_attr == NULL && opt_new_label == NULL && opt_new_id == NULL) {
        warnx("At least one of the following options must be specified:");
        warnx("'-A'/'--new-attr', '-l'/'--new-label', or '-I'/'--new-id'");
        return CKR_ARGUMENTS_BAD;
    }

    data.set_all = opt_force;

    rc = iterate_objects(certtype, opt_label, opt_id, opt_attr,
                         OBJCLASS_CERTIFICATE, NULL,
                         handle_obj_set_attr, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over certificate objects for cert type %s: 0x%lX: %s",
                certtype != NULL ? certtype->name : "All", rc, p11_get_ckr(rc));
        return rc;
    }

    printf("%lu certificate object(s) updated.\n", data.num_set);
    if (data.num_skipped > 0)
        printf("%lu certificate object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu certificate object(s) failed to update.\n", data.num_failed);

    return data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV handle_obj_copy(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                             const struct p11tool_objtype *objtype,
                             CK_ULONG keysize, const char *typestr,
                             const char* label, const char *common_name,
                             void *private)
{
    struct p11sak_copy_data *data = private;
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    CK_OBJECT_HANDLE new_key = CK_INVALID_HANDLE;
    char *msg = NULL;
    char ch;
    CK_RV rc;
    bool (*attr_applicable)(const struct p11tool_objtype *objtype,
                            const struct p11tool_attr *attr);

    UNUSED(keysize);
    UNUSED(common_name);

    if (data->skip_all) {
        data->num_skipped++;
        return CKR_OK;
    }

    if (!data->copy_all) {
        if (asprintf(&msg, "Are you sure you want to copy %s %s object \"%s\" [y/n/a/c]? ",
                     objtype->obj_typestr, typestr, label) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return CKR_HOST_MEMORY;
        }
        ch = p11tool_prompt_user(msg, "ynac");
        free(msg);

        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        case 'c':
        case '\0':
            data->skip_all = true;
            data->num_skipped++;
            return CKR_OK;
        case 'a':
            data->copy_all = true;
            break;
        default:
            break;
        }
    }

    switch (class) {
    case CKO_SECRET_KEY:
        attr_applicable = p11tool_secret_attr_applicable;
        break;
    case CKO_PUBLIC_KEY:
        attr_applicable = p11tool_public_attr_applicable;
        break;
    case CKO_PRIVATE_KEY:
        attr_applicable = p11tool_private_attr_applicable;
        break;
    case CKO_CERTIFICATE:
        attr_applicable = p11tool_cert_attr_applicable;
        break;
    default:
        warnx("Object \"%s\" has an unsupported object class: %lu",
              label, class);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }

    if (opt_new_attr != NULL) {
        rc = p11tool_parse_boolean_attrs(objtype, p11sak_bool_attrs,
                                         opt_new_attr, &attrs, &num_attrs,
                                         true, opt_so, attr_applicable);
        if (rc != CKR_OK) {
            data->num_failed++;
            goto done;
        }
    }

    if (opt_new_label != NULL) {
        rc = p11tool_add_attribute(CKA_LABEL, opt_new_label,
                                   strlen(opt_new_label),
                                   &attrs, &num_attrs);
        if (rc != CKR_OK) {
            warnx("Failed to add %s %s attribute CKA_LABEL: 0x%lX: %s",
                  objtype->name, objtype->obj_typestr, rc, p11_get_ckr(rc));
            data->num_failed++;
            goto done;
        }
    }

    if (opt_new_id != NULL) {
        rc = p11tool_parse_id(opt_new_id, &attrs, &num_attrs);
        if (rc != CKR_OK) {
            data->num_failed++;
            goto done;
        }
    }

    rc = p11tool_pkcs11_funcs->C_CopyObject(p11tool_pkcs11_session, key, attrs,
                                            num_attrs, &new_key);
    if (rc != CKR_OK) {
        warnx("Failed to copy %s key object \"%s\": C_CopyObject: 0x%lX: %s",
              typestr, label, rc, p11_get_ckr(rc));
        data->num_failed++;
        rc = CKR_OK;
        goto done;
    }

    printf("Successfully copied %s key object \"%s\".\n", typestr, label);
    data->num_copied++;

done:
    p11tool_free_attributes(attrs, num_attrs);
    return rc;
}


static CK_RV p11sak_copy_key(void)
{
    const struct p11tool_objtype *keytype = NULL;
    struct p11sak_copy_data data = { 0 };
    CK_RV rc;

    if (opt_keytype != NULL)
        keytype = opt_keytype->private.ptr;

    data.copy_all = opt_force;

    rc = iterate_objects(keytype, opt_label, opt_id, opt_attr,
                         OBJCLASS_KEY, NULL,
                         handle_obj_copy, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over key objects for key type %s: 0x%lX: %s",
                keytype != NULL ? keytype->name : "All", rc, p11_get_ckr(rc));
        return rc;
    }

    printf("%lu key object(s) copied.\n", data.num_copied);
    if (data.num_skipped > 0)
        printf("%lu key object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu key object(s) failed to copy.\n", data.num_failed);

    return data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV p11sak_copy_cert(void)
{
    const struct p11tool_objtype *certtype = NULL;
    struct p11sak_copy_data data = { 0 };
    CK_RV rc;

    if (opt_keytype != NULL)
        certtype = opt_keytype->private.ptr;

    data.copy_all = opt_force;

    rc = iterate_objects(certtype, opt_label, opt_id, opt_attr,
                         OBJCLASS_CERTIFICATE, NULL,
                         handle_obj_copy, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over certificate objects for type %s: 0x%lX: %s",
                certtype != NULL ? certtype->name : "All", rc, p11_get_ckr(rc));
        return rc;
    }

    printf("%lu certificate object(s) copied.\n", data.num_copied);
    if (data.num_skipped > 0)
        printf("%lu certificate object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu certificate object(s) failed to copy.\n", data.num_failed);

    return data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV p11sak_import_check_des_keysize(
                                          const struct p11tool_objtype *keytype,
                                          CK_ULONG keysize)
{
    if (keysize != 8) {
        warnx("Size of %s key is invalid, expected 8 bytes", keytype->name);
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

static CK_RV p11sak_import_check_3des_keysize(
                                        const struct p11tool_objtype *keytype,
                                        CK_ULONG keysize)
{
    if (keysize != 24) {
        warnx("Size of %s key is invalid, expected 24 bytes", keytype->name);
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

static CK_RV p11sak_import_check_generic_keysize(
                                        const struct p11tool_objtype *keytype,
                                        CK_ULONG keysize)
{
    if (keysize == 0) {
        warnx("Size of %s key is invalid, expected at least one byte",
              keytype->name);
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

static CK_RV p11sak_import_check_aes_keysize(
                                        const struct p11tool_objtype *keytype,
                                        CK_ULONG keysize)
{
    if (keysize != 16 && keysize != 24 && keysize != 32) {
        warnx("Size of %s key is invalid, expected 16, 24, or 32 bytes",
              keytype->name);
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

static CK_RV p11sak_import_check_aes_xts_keysize(
                                        const struct p11tool_objtype *keytype,
                                        CK_ULONG keysize)
{
    if (keysize != 32 && keysize != 64) {
        warnx("Size of %s key is invalid, expected 32 or 64 bytes",
              keytype->name);
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

static CK_RV p11sak_import_sym_clear_des_3des_aes_generic(
                                    const struct p11tool_objtype *keytype,
                                    CK_BYTE *data, CK_ULONG data_len,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    UNUSED(keytype);

    return p11tool_add_attribute(CKA_VALUE, data, data_len, attrs, num_attrs);
}

/*
 * Imports the common attrs applicable for CKO_CERTIFICATE
 */
static CK_RV p11sak_import_cert_attrs(const struct p11tool_objtype *certtype,
                                      X509 *x509, CK_ATTRIBUTE **attrs,
                                      CK_ULONG *num_attrs)
{
    const ASN1_TIME *not_before, *not_after;
    CK_BYTE *value_buf = NULL;
    CK_BYTE check_buf[20];
    CK_DATE start_date, end_date;
    EVP_PKEY *pkey = NULL;
    CK_BYTE *spki = NULL;
    int spki_len, value_len;
    EVP_MD_CTX *ctx = NULL;
    unsigned int digest_len;
    CK_RV rc = CKR_OK;

    UNUSED(certtype);

    /* CKA_START_DATE: CK_DATE struct of certificate start date */
    not_before = X509_get0_notBefore(x509);
    rc = p11tool_ASN1_TIME2date(not_before, &start_date);
    if (rc != CKR_OK)
        goto done;

    /* CKA_END_DATE: CK_DATE struct of certificate end date */
    not_after = X509_get0_notAfter(x509);
    rc = p11tool_ASN1_TIME2date(not_after, &end_date);
    if (rc != CKR_OK)
        goto done;

    /* CKA_PUBLIC_KEY_INFO: DER-encoding of the SubjectPublicKeyInfo */
    pkey = X509_get_pubkey(x509);
    if (pkey == NULL) {
        warnx("509_get_pubkey failed to get the EVP_PKEY from X509");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    spki_len = i2d_PUBKEY(pkey, &spki);
    if (spki_len <= 0) {
        warnx("openssl i2d_PUBKEY failed to create spki from EVP_PKEY");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* CKA_VALUE: only needed for CKA_CHECK_VALUE below */
    value_len = i2d_X509(x509, &value_buf);
    if (value_len <= 0) {
        warnx("i2d_X509 failed to convert the x509 into a buffer for cert's CKA_VALUE");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    /* CKA_CHECK_VALUE: first 3 bytes of the SHA-1 hash of CKA_VALUE */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        warnx("Error creating MD_CTX for CKA_CHECK_VALUE");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (!EVP_DigestInit(ctx, EVP_sha1()) ||
        !EVP_DigestUpdate(ctx, value_buf, value_len) ||
        !EVP_DigestFinal(ctx, check_buf, &digest_len)) {
        warnx("Error creating sha1 hash for CKA_CHECK_VALUE");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* Add attributes */
    rc = p11tool_add_attribute(CKA_CERTIFICATE_TYPE, &certtype->type,
                               sizeof(certtype->type), attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_START_DATE, &start_date, sizeof(CK_DATE),
                                attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_END_DATE, &end_date, sizeof(CK_DATE),
                                attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_PUBLIC_KEY_INFO, spki, spki_len,
                                attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_CHECK_VALUE, check_buf, 3,
                                attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add attributes for imported certificate.");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;

done:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);
    if (spki != NULL)
        OPENSSL_free(spki);
    if (value_buf != NULL)
        OPENSSL_free(value_buf);

    return rc;
}

/*
 * Imports attributes for X.509 public key certificates
 */
static CK_RV p11sak_import_x509_attrs(const struct p11tool_objtype *certtype,
                                      X509 *x509, CK_ATTRIBUTE **attrs,
                                      CK_ULONG *num_attrs)
{
    ASN1_INTEGER *serialno;
    unsigned char *serial_buf = NULL;
    X509_NAME *name;
    const unsigned char *subj_name = NULL, *issuer_name = NULL;
    size_t subj_name_len, issuer_name_len;
    CK_BYTE *value_buf = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *spki = NULL;
    unsigned char spki_hash[32];
    CK_ULONG spki_hash_len;
    int spki_len, serial_len, value_len;
    EVP_MD_CTX *ctx = NULL;
    CK_MECHANISM_TYPE name_hash_algo = CKM_SHA256;
    unsigned int hash_len;
    CK_RV rc = CKR_OK;

    UNUSED(certtype);

    /* CKA_SUBJECT: DER-encoding of the cert subject name */
    name = X509_get_subject_name(x509);
    if (!X509_NAME_get0_der(name, &subj_name, &subj_name_len)) {
        warnx("OpenSSL X509_NAME_get0_der failed to return the certificate's subj name");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* CKA_ISSUER: DER-encoding of the cert issuer name */
    name = X509_get_issuer_name(x509);
    if (!X509_NAME_get0_der(name, &issuer_name, &issuer_name_len)) {
        warnx("OpenSSL X509_NAME_get0_der failed to return the certificate's issuer name");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* CKA_SERIAL_NUMBER: serial number */
    serialno = X509_get_serialNumber(x509);
    serial_len = i2d_ASN1_INTEGER(serialno, &serial_buf);
    if (serial_len <= 0 || serial_buf == NULL) {
        warnx("i2d_ASN1_INTEGER failed for the certificate's serial no");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    /* CKA_VALUE: BER-encoding of certificate */
    value_len = i2d_X509(x509, &value_buf);
    if (value_len <= 0) {
        warnx("OPENSSL_malloc failed to convert the x509 into a buffer for the certificate's CKA_VALUE");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    /* CKA_PUBLIC_KEY_INFO: only needed for CKA_HASH_OF_SUBJECT_PUBLIC_KEY */
    pkey = X509_get_pubkey(x509);
    if (pkey == NULL) {
        warnx("X509_get_pubkey failed to get the EVP_PKEY from X509");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    spki_len = i2d_PUBKEY(pkey, &spki);
    if (spki_len <= 0) {
        warnx("OpenSSL i2d_PUBKEY failed to create spki from EVP_PKEY");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    /* CKA_HASH_OF_SUBJECT_PUBLIC_KEY: Hash of the subject public key.
     * Hash algorithm is defined by CKA_NAME_HASH_ALGORITHM */
    ctx = EVP_MD_CTX_new();
    if (ctx == NULL) {
        warnx("Error creating MD_CTX for CKA_HASH_OF_SUBJECT_PUBLIC_KEY");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (!EVP_DigestInit(ctx, EVP_sha256()) ||
        !EVP_DigestUpdate(ctx, spki, spki_len) ||
        !EVP_DigestFinal(ctx, spki_hash, &hash_len)) {
        warnx("Error creating sha256 hash for CKA_HASH_OF_SUBJECT_PUBLIC_KEY");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    spki_hash_len = hash_len;

    /* Add attributes */
    rc = p11tool_add_attribute(CKA_SUBJECT, subj_name, subj_name_len,
                               attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_ISSUER, issuer_name, issuer_name_len,
                                attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_SERIAL_NUMBER, serial_buf, serial_len,
                                attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_VALUE, value_buf, value_len,
                                attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_NAME_HASH_ALGORITHM, &name_hash_algo,
                                sizeof(CK_MECHANISM_TYPE), attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_HASH_OF_SUBJECT_PUBLIC_KEY, spki_hash,
                                spki_hash_len, attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add attributes for imported certificate.");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;

done:
    if (serial_buf != NULL)
        OPENSSL_free(serial_buf);
    if (value_buf != NULL)
        OPENSSL_free(value_buf);
    if (spki != NULL)
        OPENSSL_free(spki);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (ctx != NULL)
        EVP_MD_CTX_free(ctx);

    return rc;
}

static CK_RV p11sak_extract_x509_pk(const struct p11tool_objtype *certtype,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                    CK_OBJECT_HANDLE cert, const char *label)
{
    const struct p11tool_objtype *keytype;
    CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 0 };
    CK_ATTRIBUTE id_attr = { CKA_ID, NULL, 0 };
    const CK_BYTE *tmp_ptr;
    const unsigned char *subj_name = NULL;
    X509_NAME *name = NULL;
    size_t subj_name_len;
    char *pubkey_label = NULL;
    X509 *x509 = NULL;
    EVP_PKEY *pkey = NULL;
    CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
    CK_BBOOL btrue = CK_TRUE;
    CK_RV rc;
    int pkey_type;
#if OPENSSL_VERSION_PREREQ(3, 0)
    const struct pqc_oid *oid;
#endif

    rc = p11tool_get_attribute(cert, &attr);
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_VALUE from %s certificate "
              "object \"%s\": 0x%lX: %s", certtype->name, label, rc,
              p11_get_ckr(rc));
        return rc;
    }

    tmp_ptr = attr.pValue;
    x509 = d2i_X509(NULL, &tmp_ptr, attr.ulValueLen);
    if (x509 == NULL) {
        warnx("OpenSSL d2i_X509 failed to get X509 from CKA_VALUE.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    pkey = X509_get_pubkey(x509);
    if (pkey == NULL) {
        warnx("OpenSSL X509_get_pubkey failed to get certificate's public key.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    name = X509_get_subject_name(x509);
    if (!X509_NAME_get0_der(name, &subj_name, &subj_name_len)) {
        warnx("OpenSSL X509_NAME_get0_der failed to return the certificate's subj name");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    pkey_type = EVP_PKEY_base_id(pkey);
    if (pkey_type == EVP_PKEY_RSA_PSS)
        pkey_type = EVP_PKEY_RSA;
    keytype = find_keytype_by_pkey(pkey_type);

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (keytype == NULL && pkey_type == NID_undef) {
        oid = pqc_oid_from_pkey(pkey, dilithium_oids, false);
        if (oid != NULL) {
            keytype = &p11sak_ibm_dilithium_keytype;
        } else {
            oid = pqc_oid_from_pkey(pkey, ml_dsa_oids, false);
            if (oid != NULL)
                keytype = &p11sak_ibm_ml_dsa_keytype;
        }
    }
#endif

    if (keytype == NULL || keytype->import_asym_pkey == NULL) {
        warnx("Key type %s cannot be extracted from a certificate.",
              OBJ_nid2ln(pkey_type));
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_NOT_SUPPORTED;
        goto done;
    }

    rc = keytype->import_asym_pkey(keytype, pkey, CK_FALSE, attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to import %s public key from %s certificate "
              "object \"%s\": 0x%lX: %s", keytype->name, certtype->name, label,
              rc, p11_get_ckr(rc));
        goto done;
    }

    /* If no new label parm specified, derive new label from cert label */
    if (opt_new_label == NULL) {
        if (asprintf(&pubkey_label, "%s_pubkey", label) < 0 || pubkey_label == NULL) {
            warnx("Failed to allocate memory for new public key label.");
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        rc = p11tool_add_attribute(CKA_LABEL, pubkey_label,
                                   strlen(pubkey_label), attrs, num_attrs);
        if (rc != CKR_OK) {
            warnx("Failed to add attributes for extracted certificate's public key.");
            goto done;
        }
    }

    /* If no new ID is specified, try to use ID from certificate */
    if (opt_new_id == NULL) {
        rc = p11tool_get_attribute(cert, &id_attr);
        if (rc == CKR_OK && id_attr.ulValueLen > 0) {
            rc = p11tool_add_attribute(CKA_ID, id_attr.pValue,
                                       id_attr.ulValueLen, attrs, num_attrs);
            if (rc != CKR_OK) {
                warnx("Failed to add attributes for extracted certificate's public key.");
                goto done;
            }
        }
    }

    rc = p11tool_add_attribute(CKA_CLASS, &key_class, sizeof(CK_OBJECT_CLASS),
                               attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_KEY_TYPE, &keytype->type,
                                sizeof(CK_KEY_TYPE), attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_TOKEN, &btrue, sizeof(CK_BBOOL),
                                attrs, num_attrs);
    rc += p11tool_add_attribute(CKA_SUBJECT, subj_name, subj_name_len,
                                attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add attributes for extracted certificate's public key.");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = CKR_OK;

done:
    if (attr.pValue != NULL)
        free(attr.pValue);
    if (id_attr.pValue != NULL)
        free(id_attr.pValue);
    if (x509 != NULL)
        X509_free(x509);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (pubkey_label != NULL)
        free(pubkey_label);

    return rc;
}

static CK_RV p11sak_import_rsa_pkey(const struct p11tool_objtype *keytype,
                                    EVP_PKEY *pkey, bool private,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    CK_RV rc = CKR_OK;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL;
    BIGNUM *bn_p = NULL, *bn_q = NULL;
    BIGNUM *bn_dmp1 = NULL, *bn_dmq1 = NULL, *bn_iqmp = NULL;
#else
    const RSA *rsa;
    const BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL;
    const BIGNUM *bn_p = NULL, *bn_q = NULL;
    const BIGNUM *bn_dmp1 = NULL, *bn_dmq1 = NULL, *bn_iqmp = NULL;
#endif

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA &&
        EVP_PKEY_base_id(pkey) != EVP_PKEY_RSA_PSS) {
        warnx("PEM file '%s' does not contain an %s %s key.", opt_file,
              keytype->name, private ? "private" : "public");
        return CKR_FUNCTION_FAILED;
    }

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (private) {
        bn_d = BN_secure_new();
        bn_p = BN_secure_new();
        bn_q = BN_secure_new();
        bn_dmp1 = BN_secure_new();
        bn_dmq1 = BN_secure_new();
        bn_iqmp = BN_secure_new();
        if (bn_d == NULL || bn_p == NULL || bn_q == NULL ||
            bn_dmp1 == NULL || bn_dmq1 == NULL || bn_iqmp == NULL) {
            warnx("Failed to allocate OpenSSL BIGNUM");
            rc = CKR_HOST_MEMORY;
            goto done;
        }
    }

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &bn_n) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &bn_e) ||
        (private &&
         (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_D, &bn_d) ||
          !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR1, &bn_p) ||
          !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_FACTOR2, &bn_q) ||
          !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT1,
                                 &bn_dmp1) ||
          !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_EXPONENT2,
                                 &bn_dmq1) ||
          !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                                 &bn_iqmp)))) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
     }
#else
    rsa = EVP_PKEY_get0_RSA(pkey);
    if (rsa == NULL) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    RSA_get0_key(rsa, &bn_n, &bn_e, private ? &bn_d : NULL);
    if (private) {
        RSA_get0_factors(rsa, &bn_p, &bn_q);
        RSA_get0_crt_params(rsa, &bn_dmp1, &bn_dmq1, &bn_iqmp);
    }
    if (bn_n == NULL || bn_e == NULL ||
        (private && (bn_d == NULL || bn_p == NULL || bn_q == NULL ||
                     bn_dmp1 == NULL || bn_dmq1 == NULL || bn_iqmp == NULL))) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

    rc = p11tool_add_bignum_attr(CKA_MODULUS, bn_n, attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    rc = p11tool_add_bignum_attr(CKA_PUBLIC_EXPONENT, bn_e, attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    if (private) {
        rc = p11tool_add_bignum_attr(CKA_PRIVATE_EXPONENT, bn_d,
                                     attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;

        rc = p11tool_add_bignum_attr(CKA_PRIME_1, bn_p, attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;

        rc = p11tool_add_bignum_attr(CKA_PRIME_2, bn_q, attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;

        rc = p11tool_add_bignum_attr(CKA_EXPONENT_1, bn_dmp1, attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;

        rc = p11tool_add_bignum_attr(CKA_EXPONENT_2, bn_dmq1, attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;

        rc = p11tool_add_bignum_attr(CKA_COEFFICIENT, bn_iqmp,
                                     attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;
    }

done:
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (bn_n != NULL)
        BN_free(bn_n);
    if (bn_e != NULL)
        BN_free(bn_e);
    if (bn_d != NULL)
        BN_clear_free(bn_d);
    if (bn_p != NULL)
        BN_clear_free(bn_p);
    if (bn_q != NULL)
        BN_clear_free(bn_q);
    if (bn_dmp1 != NULL)
        BN_clear_free(bn_dmp1);
    if (bn_dmq1 != NULL)
        BN_clear_free(bn_dmq1);
    if (bn_iqmp != NULL)
        BN_clear_free(bn_iqmp);
#endif

    return rc;
}

static CK_RV p11sak_import_dh_pkey(const struct p11tool_objtype *keytype,
                                   EVP_PKEY *pkey, bool private,
                                   CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    CK_RV rc = CKR_OK;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BIGNUM *bn_p = NULL, *bn_g = NULL, *bn_pub = NULL, *bn_priv = NULL;
#else
    const DH *dh;
    const BIGNUM *bn_p = NULL, *bn_g = NULL, *bn_pub = NULL, *bn_priv = NULL;
#endif

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_DH) {
        warnx("PEM file '%s' does not contain an %s %s key.", opt_file,
              keytype->name, private ? "private" : "public");
        return CKR_FUNCTION_FAILED;
    }

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (private) {
        bn_priv = BN_secure_new();
        if (bn_priv == NULL) {
            warnx("Failed to allocate OpenSSL BIGNUM");
            rc = CKR_HOST_MEMORY;
            goto done;
        }
    }

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &bn_p) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &bn_g) ||
        (!private &&
         !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &bn_pub)) ||
        (private &&
         !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv))) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
     }
#else
    dh = EVP_PKEY_get0_DH(pkey);
    if (dh == NULL) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    DH_get0_pqg(dh, &bn_p, NULL, &bn_g);
    DH_get0_key(dh, !private ? &bn_pub : NULL, private ? &bn_priv : NULL);
    if (bn_p == NULL || bn_g == NULL ||
        (!private && bn_pub == NULL) || (private && bn_priv == NULL)) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

    rc = p11tool_add_bignum_attr(CKA_PRIME, bn_p, attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    rc = p11tool_add_bignum_attr(CKA_BASE, bn_g, attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    rc = p11tool_add_bignum_attr(CKA_VALUE, private ? bn_priv : bn_pub,
                                 attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

done:
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (bn_p != NULL)
        BN_free(bn_p);
    if (bn_g != NULL)
        BN_free(bn_g);
    if (bn_pub != NULL)
        BN_free(bn_pub);
    if (bn_priv != NULL)
        BN_clear_free(bn_priv);
#endif

    return rc;
}

static CK_RV p11sak_import_dsa_pkey(const struct p11tool_objtype *keytype,
                                    EVP_PKEY *pkey, bool private,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    CK_RV rc = CKR_OK;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BIGNUM *bn_p = NULL, *bn_q = NULL, *bn_g = NULL;
    BIGNUM *bn_pub = NULL, *bn_priv = NULL;
#else
    const DSA *dsa;
    const BIGNUM *bn_p = NULL, *bn_q = NULL, *bn_g = NULL;
    const BIGNUM *bn_pub = NULL, *bn_priv = NULL;
#endif

    if (EVP_PKEY_base_id(pkey) != EVP_PKEY_DSA) {
        warnx("PEM file '%s' does not contain an %s %s key.", opt_file,
              keytype->name, private ? "private" : "public");
        return CKR_FUNCTION_FAILED;
    }

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (private) {
        bn_priv = BN_secure_new();
        if (bn_priv == NULL) {
            warnx("Failed to allocate OpenSSL BIGNUM");
            rc = CKR_HOST_MEMORY;
            goto done;
        }
    }

    if (!EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_P, &bn_p) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_Q, &bn_q) ||
        !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_FFC_G, &bn_g) ||
        (!private &&
         !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PUB_KEY, &bn_pub)) ||
        (private &&
         !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv))) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
     }
#else
    dsa = EVP_PKEY_get0_DSA(pkey);
    if (dsa == NULL) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    DSA_get0_pqg(dsa, &bn_p, &bn_q, &bn_g);
    DSA_get0_key(dsa, !private ? &bn_pub : NULL, private ? &bn_priv : NULL);
    if (bn_p == NULL || bn_q == NULL || bn_g == NULL ||
        (!private && bn_pub == NULL) || (private && bn_priv == NULL)) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

    rc = p11tool_add_bignum_attr(CKA_PRIME, bn_p, attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    rc = p11tool_add_bignum_attr(CKA_SUBPRIME, bn_q, attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    rc = p11tool_add_bignum_attr(CKA_BASE, bn_g, attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    rc = p11tool_add_bignum_attr(CKA_VALUE, private ? bn_priv : bn_pub,
                                 attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

done:
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (bn_p != NULL)
        BN_free(bn_p);
    if (bn_q != NULL)
        BN_free(bn_q);
    if (bn_g != NULL)
        BN_free(bn_g);
    if (bn_pub != NULL)
        BN_free(bn_pub);
    if (bn_priv != NULL)
        BN_clear_free(bn_priv);
#endif

    return rc;
}

#if OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV p11sak_import_ecx_pkey(const struct p11tool_objtype *keytype,
                                    int pkey_type, EVP_PKEY *pkey, bool private,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    CK_RV rc = CKR_OK;
    unsigned char priv[100] = { 0 };
    size_t priv_len = 0;
    unsigned char point[300] = { 0 };
    unsigned char *point_ptr;
    size_t point_len = 0;
    ASN1_OBJECT *obj = NULL;
    unsigned char *ec_params = NULL;
    int ec_params_len;

    if ((!private &&          /* leave 3 bytes space for DER encoding */
         !EVP_PKEY_get_octet_string_param(pkey,
                                          OSSL_PKEY_PARAM_PUB_KEY,
                                          point + 3, sizeof(point) - 3,
                                          &point_len)) ||
        (private &&
         !EVP_PKEY_get_octet_string_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY,
                                          priv, sizeof(priv), &priv_len))) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    obj = OBJ_nid2obj(pkey_type);
    if (obj == NULL) {
        warnx("OBJ_nid2obj failed for curve nid %d.", pkey_type);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    ec_params_len = i2d_ASN1_OBJECT(obj, &ec_params);
    if (ec_params_len <= 0 || ec_params == NULL) {
        warnx("i2d_ASN1_OBJECT failed for curve nid %d.", pkey_type);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = p11tool_add_attribute(CKA_EC_PARAMS, ec_params, ec_params_len,
                               attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    if (private) {
        rc = p11tool_add_attribute(CKA_VALUE, priv, priv_len, attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;
    } else {
        if (keytype->type == CKK_EC) {
            /* EC: CKA_EC_POINT needs DER encoded EC point */
            if (point_len < 0x80) {
                point[1] = 0x04; /* OCTET-STRING */
                point[2] = point_len & 0x7f;
                point_len += 2;
                point_ptr = &point[1];
            } else if (point_len < 0x0100) {
                point[0] = 0x04; /* OCTET-STRING */
                point[1] = 0x81; /* 1 byte length field */
                point[2] = point_len & 0xff;
                point_len += 3;
                point_ptr = &point[0];
            } else {
                warnx("EC point is too long.");
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
        } else {
            /* Edwards/Montgomery use raw EC point */
            point_ptr = &point[3];
        }

        rc = p11tool_add_attribute(CKA_EC_POINT, point_ptr, point_len,
                                   attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;
    }

done:
    if (obj != NULL)
        ASN1_OBJECT_free(obj);
    if (ec_params != NULL)
        OPENSSL_free(ec_params);

    return rc;
}
#endif

static CK_RV p11sak_import_ec_pkey(const struct p11tool_objtype *keytype,
                                   EVP_PKEY *pkey, bool private,
                                   CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    CK_RV rc = CKR_OK;
#if OPENSSL_VERSION_PREREQ(3, 0)
    BIGNUM *bn_priv = NULL;
    char group[200] = { 0 };
    EC_GROUP *ec_group = NULL;
    unsigned char point[200] = { 0 };
    const OSSL_PARAM params[2] = {
        OSSL_PARAM_utf8_string(OSSL_PKEY_PARAM_GROUP_NAME,
                               group, sizeof(group) -1),
        OSSL_PARAM_END,
    };
#else
    const EC_KEY *ec;
    const EC_GROUP *ec_group = NULL;
    const BIGNUM *bn_priv = NULL;
    const EC_POINT *ec_point = NULL;
    unsigned char *point = NULL;
#endif
    unsigned char *point_ptr;
    size_t point_len = 0;
    ASN1_OBJECT *obj = NULL;
    unsigned char *ec_params = NULL;
    int ec_params_len, type;

    type = EVP_PKEY_base_id(pkey);
    switch (type) {
    case EVP_PKEY_EC:
        if (keytype->type != CKK_EC) {
            warnx("PEM file '%s' contains an EC %s key, but a %s %s key is "
                  "expected.", opt_file, private ? "private" : "public",
                  keytype->name, private ? "private" : "public");
            return CKR_ARGUMENTS_BAD;
        }
        break;
#if OPENSSL_VERSION_PREREQ(3, 0)
    case EVP_PKEY_ED25519:
    case EVP_PKEY_ED448:
        if (keytype->type != CKK_EC && keytype->type != CKK_EC_EDWARDS) {
            warnx("PEM file '%s' contains an EC-Edwards %s key, but a %s %s "
                  "key is expected.", opt_file, private ? "private" : "public",
                  keytype->name, private ? "private" : "public");
            return CKR_ARGUMENTS_BAD;
        }
        return p11sak_import_ecx_pkey(keytype, type, pkey, private,
                                      attrs, num_attrs);
    case EVP_PKEY_X25519:
    case EVP_PKEY_X448:
        if (keytype->type != CKK_EC && keytype->type != CKK_EC_MONTGOMERY) {
            warnx("PEM file '%s' contains an EC-Montgomery %s key, but a %s %s "
                  "key is expected.", opt_file, private ? "private" : "public",
                  keytype->name, private ? "private" : "public");
            return CKR_ARGUMENTS_BAD;
        }
        return p11sak_import_ecx_pkey(keytype, type, pkey, private,
                                      attrs, num_attrs);
#endif
    default:
        warnx("PEM file '%s' does not contain an %s %s key.", opt_file,
              keytype->name, private ? "private" : "public");
        return CKR_FUNCTION_FAILED;
    }

#if OPENSSL_VERSION_PREREQ(3, 0)
    if (private) {
        bn_priv = BN_secure_new();
        if (bn_priv == NULL) {
            warnx("Failed to allocate OpenSSL BIGNUM");
            rc = CKR_HOST_MEMORY;
            goto done;
        }
    }

    if (!EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                                        group, sizeof(group), NULL) ||
        (!private &&          /* leave 3 bytes space for DER encoding */
         !EVP_PKEY_get_octet_string_param(pkey,
                                          OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                          point + 3, sizeof(point) - 3,
                                          &point_len)) ||
        (private &&
         !EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_PRIV_KEY, &bn_priv))) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    ec_group = EC_GROUP_new_from_params(params, NULL, NULL);
    if (ec_group == NULL) {
        warnx("EC_GROUP_new_from_params failed for curve '%s'.", group);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#else
    ec = EVP_PKEY_get0_EC_KEY(pkey);
    if (ec == NULL) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    ec_group = EC_KEY_get0_group(ec);
    if (private)
        bn_priv = EC_KEY_get0_private_key(ec);
    else
        ec_point = EC_KEY_get0_public_key(ec);
    if (ec_group == NULL ||
        (!private && ec_point == NULL) ||
        (private && bn_priv == NULL)) {
        warnx("Failed to get the %s params.", keytype->name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!private) {
        point_len = EC_POINT_point2oct(ec_group, ec_point,
                                       POINT_CONVERSION_UNCOMPRESSED,
                                       NULL, 0, NULL);
        if (point_len == 0) {
            warnx("EC_POINT_point2oct failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        /* Leave 3 bytes space for DER encoding of OCTET-STRING */
        point = calloc(3 + point_len, 1);
        if (point == NULL) {
            warnx("Failed to allocate buffer for EC point.");
            rc = CKR_HOST_MEMORY;
            goto done;
        }

        if (EC_POINT_point2oct(ec_group, ec_point,
                               POINT_CONVERSION_UNCOMPRESSED,
                               point + 3, point_len, NULL) != point_len) {
            warnx("EC_POINT_point2oct failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }
#endif

    obj = OBJ_nid2obj(EC_GROUP_get_curve_name(ec_group));
    if (obj == NULL) {
        warnx("OBJ_nid2obj failed for curve nid %d.",
              EC_GROUP_get_curve_name(ec_group));
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    ec_params_len = i2d_ASN1_OBJECT(obj, &ec_params);
    if (ec_params_len <= 0 || ec_params == NULL) {
        warnx("i2d_ASN1_OBJECT failed for curve nid %d.",
              EC_GROUP_get_curve_name(ec_group));
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = p11tool_add_attribute(CKA_EC_PARAMS, ec_params, ec_params_len,
                               attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    if (private) {
        rc = p11tool_add_bignum_attr(CKA_VALUE, bn_priv, attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;
    } else {
        /* CKA_EC_POINT needs DER encoded EC point */
        if (point_len < 0x80) {
            point[1] = 0x04; /* OCTET-STRING */
            point[2] = point_len & 0x7f;
            point_len += 2;
            point_ptr = &point[1];
        } else if (point_len < 0x0100) {
            point[0] = 0x04; /* OCTET-STRING */
            point[1] = 0x81; /* 1 byte length field */
            point[2] = point_len & 0xff;
            point_len += 3;
            point_ptr = &point[0];
        } else {
            warnx("EC point is too long.");
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        rc = p11tool_add_attribute(CKA_EC_POINT, point_ptr, point_len,
                                   attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;
    }

done:
#if OPENSSL_VERSION_PREREQ(3, 0)
    if (bn_priv != NULL)
        BN_clear_free(bn_priv);
    if (ec_group != NULL)
        EC_GROUP_free(ec_group);
#else
    if (point != NULL)
        free(point);
#endif
    if (obj != NULL)
        ASN1_OBJECT_free(obj);
    if (ec_params != NULL)
        OPENSSL_free(ec_params);

    return rc;
}

static CK_RV p11sak_import_dilithium_kyber_pem_data(
                                        const struct p11tool_objtype *keytype,
                                        unsigned char *data, size_t data_len,
                                        bool private,
                                        CK_ATTRIBUTE **attrs,
                                        CK_ULONG *num_attrs)
{
    UNUSED(keytype);
    UNUSED(private);

    return p11tool_add_attribute(CKA_VALUE, data, data_len, attrs, num_attrs);
}

static CK_RV p11sak_import_dilithium_ml_dsa_pkey(
                                          const struct p11tool_objtype *keytype,
                                          EVP_PKEY *pkey, bool private,
                                          CK_ATTRIBUTE **attrs,
                                          CK_ULONG *num_attrs)
{
#if OPENSSL_VERSION_PREREQ(3, 0)
    const struct pqc_oid *oid;
    size_t priv_len = 0, pub_len = 0;
    CK_BYTE *priv_key = NULL, *pub_key = NULL;
    CK_ULONG ofs;
    size_t seed_len = 0;
    CK_BYTE *priv_seed = NULL;
    CK_RV rc;

    UNUSED(keytype);

    oid = pqc_oid_from_pkey(pkey, keytype->type == CKK_IBM_PQC_DILITHIUM ?
                                        dilithium_oids : ml_dsa_oids,
                            true);
    if (oid == NULL)
        return CKR_FUNCTION_FAILED;

    /* Add keyform and attribute */
    rc = p11tool_add_attribute(keytype->type == CKK_IBM_PQC_DILITHIUM ?
                                  CKA_IBM_DILITHIUM_KEYFORM :
                                  CKA_IBM_PARAMETER_SET,
                               &oid->keyform, sizeof(oid->keyform),
                               attrs, num_attrs);
    if (rc != CKR_OK)
       goto out;

    if (private) {
        rc = p11tool_get_octet_string_param_from_pkey(pkey,
                                                      OSSL_PKEY_PARAM_PRIV_KEY,
                                                      &priv_key, &priv_len,
                                                      FALSE);
        if (rc != CKR_OK)
            goto out;

        if (priv_len != oid->len_info.ml_dsa.rho_len +
                        oid->len_info.ml_dsa.seed_len +
                        oid->len_info.ml_dsa.tr_len +
                        oid->len_info.ml_dsa.s1_len +
                        oid->len_info.ml_dsa.s2_len +
                        oid->len_info.ml_dsa.t0_len) {
            warnx("Size of private %s key is not valid.", keytype->name);
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        ofs = 0;
        rc = p11tool_add_attribute(CKA_IBM_ML_DSA_RHO,
                                   priv_key + ofs,
                                   oid->len_info.ml_dsa.rho_len,
                                   attrs, num_attrs);
        if (rc != CKR_OK)
           goto out;

        ofs += oid->len_info.ml_dsa.rho_len;
        rc = p11tool_add_attribute(CKA_IBM_ML_DSA_SEED,
                                   priv_key + ofs,
                                   oid->len_info.ml_dsa.seed_len,
                                   attrs, num_attrs);
        if (rc != CKR_OK)
           goto out;

        ofs += oid->len_info.ml_dsa.seed_len;
        rc = p11tool_add_attribute(CKA_IBM_ML_DSA_TR,
                                   priv_key + ofs,
                                   oid->len_info.ml_dsa.tr_len,
                                   attrs, num_attrs);
        if (rc != CKR_OK)
           goto out;

        ofs += oid->len_info.ml_dsa.tr_len;
        rc = p11tool_add_attribute(CKA_IBM_ML_DSA_S1,
                                   priv_key + ofs,
                                   oid->len_info.ml_dsa.s1_len,
                                   attrs, num_attrs);
        if (rc != CKR_OK)
           goto out;

        ofs += oid->len_info.ml_dsa.s1_len;
        rc = p11tool_add_attribute(CKA_IBM_ML_DSA_S2,
                                   priv_key + ofs,
                                   oid->len_info.ml_dsa.s2_len,
                                   attrs, num_attrs);
        if (rc != CKR_OK)
           goto out;

        ofs += oid->len_info.ml_dsa.s2_len;
        rc = p11tool_add_attribute(CKA_IBM_ML_DSA_T0,
                                   priv_key + ofs,
                                   oid->len_info.ml_dsa.t0_len,
                                   attrs, num_attrs);
        if (rc != CKR_OK)
           goto out;

        /* Try to get private seed, but ignore if it is not available */
        rc = p11tool_get_octet_string_param_from_pkey(pkey,
                                              OSSL_PKEY_PARAM_ML_DSA_SEED,
                                              &priv_seed, &seed_len, TRUE);
        if (rc != CKR_OK)
            goto out;

        if (priv_seed != NULL &&
            seed_len == oid->len_info.ml_dsa.priv_seed_len) {
            rc = p11tool_add_attribute(CKA_IBM_ML_DSA_PRIVATE_SEED,
                                       priv_seed, seed_len,
                                       attrs, num_attrs);
            if (rc != CKR_OK)
               goto out;
        }
    }

    rc = p11tool_get_octet_string_param_from_pkey(pkey,
                                                  OSSL_PKEY_PARAM_PUB_KEY,
                                                  &pub_key, &pub_len, FALSE);
    if (rc != CKR_OK)
        goto out;

    if (pub_len != oid->len_info.ml_dsa.rho_len +
                   oid->len_info.ml_dsa.t1_len) {
        warnx("Size of public %s key is not valid.", keytype->name);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    ofs = 0;
    rc = p11tool_add_attribute(CKA_IBM_ML_DSA_RHO,
                               pub_key + ofs, oid->len_info.ml_dsa.rho_len,
                               attrs, num_attrs);
    if (rc != CKR_OK)
       goto out;

    ofs += oid->len_info.ml_dsa.rho_len;
    rc = p11tool_add_attribute(CKA_IBM_ML_DSA_T1,
                               pub_key + ofs, oid->len_info.ml_dsa.t1_len,
                               attrs, num_attrs);
    if (rc != CKR_OK)
       goto out;

out:
    if (priv_key != NULL) {
        OPENSSL_cleanse(priv_key, priv_len);
        free(priv_key);
    }
    if (pub_key != NULL)
        free(pub_key);

    return rc;
#else
    UNUSED(keytype);
    UNUSED(pkey);
    UNUSED(private);
    UNUSED(attrs);
    UNUSED(num_attrs);

    warnx("Importing an 'oqsprovider' format PEM file is only supported with "
          "OpenSSL 3.0 or later.");
    return CKR_FUNCTION_NOT_SUPPORTED;
#endif
}

static CK_RV p11sak_import_ml_kem_pkey(const struct p11tool_objtype *keytype,
                                       EVP_PKEY *pkey, bool private,
                                       CK_ATTRIBUTE **attrs,
                                       CK_ULONG *num_attrs)
{
#if OPENSSL_VERSION_PREREQ(3, 0)
    const struct pqc_oid *oid;
    size_t priv_len = 0, pub_len = 0;
    CK_BYTE *priv_key = NULL, *pub_key = NULL;
    size_t seed_len = 0;
    CK_BYTE *priv_seed = NULL;
    CK_RV rc;

    UNUSED(keytype);

    oid = pqc_oid_from_pkey(pkey, ml_kem_oids, true);
    if (oid == NULL)
        return CKR_FUNCTION_FAILED;

    /* Add Parameter-set and attribute */
    rc = p11tool_add_attribute(CKA_IBM_PARAMETER_SET,
                               &oid->keyform, sizeof(oid->keyform),
                               attrs, num_attrs);
    if (rc != CKR_OK)
       goto out;

    if (private) {
        rc = p11tool_get_octet_string_param_from_pkey(pkey,
                                                      OSSL_PKEY_PARAM_PRIV_KEY,
                                                      &priv_key, &priv_len,
                                                      FALSE);
        if (rc != CKR_OK)
            goto out;

        if (priv_len != oid->len_info.ml_kem.sk_len) {
            warnx("Size of private %s key is not valid.", keytype->name);
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        rc = p11tool_add_attribute(CKA_IBM_ML_KEM_SK,
                                   priv_key, oid->len_info.ml_kem.sk_len,
                                   attrs, num_attrs);
        if (rc != CKR_OK)
           goto out;

        rc = p11tool_get_octet_string_param_from_pkey(pkey,
                                              OSSL_PKEY_PARAM_ML_KEM_SEED,
                                              &priv_seed, &seed_len, TRUE);
        if (rc != CKR_OK)
            goto out;

        if (priv_seed != NULL &&
            seed_len == oid->len_info.ml_kem.priv_seed_len) {
            rc = p11tool_add_attribute(CKA_IBM_ML_KEM_PRIVATE_SEED,
                                       priv_seed, seed_len,
                                       attrs, num_attrs);
            if (rc != CKR_OK)
               goto out;
        }
    }

    rc = p11tool_get_octet_string_param_from_pkey(pkey,
                                                  OSSL_PKEY_PARAM_PUB_KEY,
                                                  &pub_key, &pub_len, FALSE);
    if (rc != CKR_OK)
        goto out;

    if (pub_len != oid->len_info.ml_kem.pk_len) {
        warnx("Size of public %s key is not valid.", keytype->name);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    rc = p11tool_add_attribute(CKA_IBM_ML_KEM_PK,
                               pub_key, oid->len_info.ml_kem.pk_len,
                               attrs, num_attrs);
    if (rc != CKR_OK)
       goto out;

out:
    if (priv_key != NULL) {
        OPENSSL_cleanse(priv_key, priv_len);
        free(priv_key);
    }
    if (pub_key != NULL)
        free(pub_key);

    return rc;
#else
    UNUSED(keytype);
    UNUSED(pkey);
    UNUSED(private);
    UNUSED(attrs);
    UNUSED(num_attrs);

    warnx("Importing an 'oqsprovider' format PEM file is only supported with "
          "OpenSSL 3.0 or later.");
    return CKR_FUNCTION_NOT_SUPPORTED;
#endif
}

static CK_RV p11sak_x509_from_pem_file(X509 **x509)
{
    struct p11tool_pem_password_cb_data cb_data = { 0 };
    BIO *bio = NULL;
    X509 *x = NULL;
    CK_RV rc;

    cb_data.pem_file_name = opt_file;
    cb_data.pem_password = opt_pem_password;
    cb_data.env_var_name = PKCS11_PEM_PASSWORD_ENV_NAME;
    cb_data.force_prompt = opt_force_pem_pwd_prompt;

    bio = BIO_new_file(opt_file, "r");
    if (bio == NULL) {
        warnx("Failed to open file '%s'", opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    x = PEM_read_bio_X509(bio, NULL, p11tool_pem_password_cb, &cb_data);
    if (x == NULL) {
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    *x509 = x;
    rc = CKR_OK;

done:
    if (bio != NULL)
        BIO_free(bio);

    return rc;
}

static CK_RV p11sak_x509_from_der_file(X509 **x509)
{
    CK_BYTE *value;
    CK_ULONG value_len;
    const CK_BYTE *tmp_value;
    X509 *x;
    struct stat sb;
    FILE *fp = NULL;
    CK_RV rc;

    if (stat(opt_file, &sb) != 0) {
        warnx("Failed to access file '%s': %s", opt_file, strerror(errno));
        return CKR_ARGUMENTS_BAD;
    }

    value_len = sb.st_size;
    value = malloc(value_len);
    if (value == NULL) {
        warnx("Cannot malloc %ld bytes for DER file contents.", value_len);
        return CKR_HOST_MEMORY;
    }

    fp = fopen(opt_file, "r");
    if (fp == NULL) {
        warnx("Failed to open file '%s': %s", opt_file, strerror(errno));
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    if (fread(value, value_len, 1, fp) != 1) {
        warnx("Failed to read from file '%s': %s", opt_file, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    tmp_value = (CK_BYTE *)value;
    x = d2i_X509(NULL, &tmp_value, value_len);
    if (x == NULL) {
        warnx("d2i_X509 failed to decode contents from file '%s'", opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    *x509 = x;
    rc = CKR_OK;

done:
    if (fp != NULL)
        fclose(fp);
    if (value != NULL)
        free(value);

    return rc;
}

static CK_RV p11sak_import_opaque_key(const struct p11tool_objtype *keytype,
                                      CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    CK_BYTE *value;
    CK_ULONG value_len;
    struct stat sb;
    FILE *fp;
    CK_RV rc = CKR_OK;

    UNUSED(keytype);

    if (stat(opt_file, &sb) != 0) {
        warnx("Failed to access file '%s': %s", opt_file, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }
    value_len = sb.st_size;

    value = malloc(value_len);
    if (value == NULL) {
        warnx("Failed to allocate a buffer for the opaque key");
        return CKR_FUNCTION_FAILED;
    }

    fp = fopen(opt_file, "r");
    if (fp == NULL) {
        warnx("Failed to open file '%s': %s", opt_file, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (fread(value, value_len, 1, fp) != 1) {
        warnx("Failed to read from file '%s': %s", opt_file, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = p11tool_add_attribute(CKA_IBM_OPAQUE, value, value_len,
                               attrs, num_attrs);
    if (rc != CKR_OK)
        goto done;

done:
    if (value != NULL) {
        OPENSSL_cleanse(value, value_len);
        free(value);
    }
    if (fp != NULL)
        fclose(fp);

    return rc;
}

static CK_RV p11sak_import_asym_key(const struct p11tool_objtype *keytype,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    struct p11tool_pem_password_cb_data cb_data = { 0 };
    EVP_PKEY *pkey = NULL;
    CK_RV rc = CKR_OK;
    unsigned char *data = NULL;
    long data_len = 0;
    char *header = NULL;
    BIO *bio;
    int ret;

    cb_data.pem_file_name = opt_file;
    cb_data.pem_password = opt_pem_password;
    cb_data.env_var_name = PKCS11_PEM_PASSWORD_ENV_NAME;
    cb_data.force_prompt = opt_force_pem_pwd_prompt;

    bio = BIO_new_file(opt_file, "r");
    if (bio == NULL) {
        warnx("Failed to open PEM file '%s'.", opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    if (keytype->import_asym_pkey != NULL &&
        (!keytype->supports_oqsprovider_pem ||
         (opt_oqsprovider_pem && keytype->supports_oqsprovider_pem))) {
        if (opt_asym_kind->private.num)
            pkey = PEM_read_bio_PrivateKey(bio, NULL, p11tool_pem_password_cb,
                                           &cb_data);
        else
            pkey = PEM_read_bio_PUBKEY(bio, NULL, p11tool_pem_password_cb,
                                       &cb_data);

        if (pkey == NULL) {
            warnx("Failed to read PEM file '%s'.%s", opt_file,
                  opt_oqsprovider_pem ?
                          " Is the 'oqsprovider' configured?" : "");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        rc = keytype->import_asym_pkey(keytype, pkey,
                                       opt_asym_kind->private.num,
                                       attrs, num_attrs);
        if (rc != CKR_OK)
            goto done;
    } else if (keytype->import_asym_pem_data != NULL) {
        ret = PEM_bytes_read_bio(&data, &data_len, &header,
                                 opt_asym_kind->private.num ?
                                     keytype->pem_name_private :
                                     keytype->pem_name_public,
                                 bio, p11tool_pem_password_cb, &cb_data);
        if (ret != 1) {
            warnx("Failed to read PEM file '%s'.", opt_file);
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        rc = keytype->import_asym_pem_data(keytype, data, data_len,
                                           opt_asym_kind->private.num,
                                           attrs, num_attrs);
        if (rc != CKR_OK)
            goto done;
    } else {
        warnx("No support for importing %s key from PEM file '%s'",
              keytype->name, opt_file);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

done:
    BIO_free(bio);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (data != NULL)
        OPENSSL_clear_free(data, data_len);
    if (header != NULL)
        OPENSSL_free(header);

    return rc;
}

static CK_RV p11sak_import_sym_key(const struct p11tool_objtype *keytype,
                                   CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    CK_BYTE data[MAX_SYM_CLEAR_KEY_SIZE];
    CK_ULONG data_len;
    struct stat sb;
    FILE *fp;
    CK_RV rc;

    if (keytype->import_sym_clear == NULL) {
        warnx("No support for importing %s key from file '%s'",
              keytype->name, opt_file);
        return CKR_ARGUMENTS_BAD;
    }

    if (stat(opt_file, &sb) != 0) {
        warnx("Failed to access file '%s': %s", opt_file, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }
    data_len = sb.st_size;

    if (keytype->import_check_sym_keysize != NULL) {
        rc = keytype->import_check_sym_keysize(keytype, data_len);
        if (rc != CKR_OK)
            return rc;
    }

    if (data_len > (CK_ULONG)sizeof(data)) {
        warnx("Size of %s key is too large", keytype->name);
        return CKR_ARGUMENTS_BAD;
    }

    fp = fopen(opt_file, "r");
    if (fp == NULL) {
        warnx("Failed to open file '%s': %s", opt_file, strerror(errno));
        return CKR_FUNCTION_FAILED;
    }

    if (fread(data, data_len, 1, fp) != 1) {
        warnx("Failed to read from file '%s': %s", opt_file, strerror(errno));
        fclose(fp);
        return CKR_FUNCTION_FAILED;
    }

    fclose(fp);

    rc = keytype->import_sym_clear(keytype, data, data_len,
                                   attrs, num_attrs);

    OPENSSL_cleanse(data, sizeof(data));

    return rc;
}

static CK_RV p11sak_import_key(void)
{
    const struct p11tool_objtype *keytype;
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    CK_OBJECT_CLASS class;
    CK_OBJECT_HANDLE key;
    CK_RV rc;

    if (opt_keytype == NULL || opt_keytype->private.ptr == NULL)
        return CKR_ARGUMENTS_BAD;

    keytype = opt_keytype->private.ptr;

    if (opt_oqsprovider_pem && !keytype->supports_oqsprovider_pem) {
        warnx("Option '--oqsprovider-pem' is not supported for keytype '%s'.",
              keytype->name);
        return CKR_ARGUMENTS_BAD;
    }

    class = keytype->is_asymmetric ?
            (opt_asym_kind->private.num ? CKO_PRIVATE_KEY : CKO_PUBLIC_KEY) :
            CKO_SECRET_KEY;
    rc = p11tool_add_attribute(CKA_CLASS, &class, sizeof(class),
                               &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_add_attribute(CKA_KEY_TYPE, &keytype->type,
                               sizeof(keytype->type), &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_add_attributes(keytype, p11sak_bool_attrs, &attrs, &num_attrs,
                                opt_label, opt_attr, opt_id,
                                !keytype->is_asymmetric ||
                                (keytype->is_asymmetric &&
                                                    opt_asym_kind->private.num),
                                opt_so, NULL, NULL,
                                keytype->is_asymmetric ?
                                        (opt_asym_kind->private.num ?
                                              p11tool_private_attr_applicable :
                                              p11tool_public_attr_applicable) :
                                p11tool_secret_attr_applicable);
    if (rc != CKR_OK)
        goto done;

    if (opt_opaque)
        rc = p11sak_import_opaque_key(keytype, &attrs, &num_attrs);
    else if (keytype->is_asymmetric)
        rc = p11sak_import_asym_key(keytype, &attrs, &num_attrs);
    else
        rc = p11sak_import_sym_key(keytype, &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_pkcs11_funcs->C_CreateObject(p11tool_pkcs11_session, attrs,
                                              num_attrs, &key);
    if (rc != CKR_OK) {
       if (p11tool_is_rejected_by_policy(rc, p11tool_pkcs11_session))
           warnx("Key import of a %s key is rejected by policy", keytype->name);
       else
           warnx("Key import of a %s key failed: 0x%lX: %s", keytype->name,
                 rc, p11_get_ckr(rc));
       goto done;
    }

    printf("Successfully imported a %s key with label \"%s\".\n",
           keytype->name, opt_label);

done:
    p11tool_free_attributes(attrs, num_attrs);

    return rc;
}

static bool has_ibm_opaque_attr(CK_OBJECT_HANDLE key)
{
    CK_RV rc;
    CK_ATTRIBUTE attr = { CKA_IBM_OPAQUE, NULL, 0 };

    rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session, key,
                                                   &attr, 1);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        return true;
    if (rc != CKR_OK)
        return false;

    return true;
}

static CK_RV p11sak_export_sym_clear_des_3des_aes_generic(
                                    const struct p11tool_objtype *keytype,
                                    CK_BYTE **data, CK_ULONG* data_len,
                                    CK_OBJECT_HANDLE key, const char *label)
{
    CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 0 };
    CK_RV rc;

    rc = p11tool_get_attribute(key, &attr);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        return rc;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_VALUE from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        return rc;
    }

    *data = attr.pValue;
    *data_len = attr.ulValueLen;

    return CKR_OK;
}

static CK_RV p11sak_export_rsa_pkey(const struct p11tool_objtype *keytype,
                                    EVP_PKEY **pkey, bool private,
                                    CK_OBJECT_HANDLE key, const char *label)
{
    BIGNUM *bn_n = NULL, *bn_e = NULL, *bn_d = NULL, *bn_iqmp = NULL;
    BIGNUM *bn_p = NULL, *bn_q = NULL, *bn_dmp1 = NULL, *bn_dmq1 = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
#else
    RSA *rsa = NULL;
#endif
    CK_RV rc;

    rc = p11tool_get_bignum_attr(key, CKA_MODULUS, &bn_n);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_MODULUS from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

    rc = p11tool_get_bignum_attr(key, CKA_PUBLIC_EXPONENT, &bn_e);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_PUBLIC_EXPONENT from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

    if (private) {
        bn_d = BN_secure_new();
        bn_p = BN_secure_new();
        bn_q = BN_secure_new();
        bn_dmp1 = BN_secure_new();
        bn_dmq1 = BN_secure_new();
        bn_iqmp = BN_secure_new();
        if (bn_d == NULL || bn_p == NULL || bn_q == NULL ||
            bn_dmp1 == NULL || bn_dmq1 == NULL || bn_iqmp == NULL) {
            warnx("Failed to allocate OpenSSL BIGNUM");
            rc = CKR_HOST_MEMORY;
            goto done;
        }

        rc = p11tool_get_bignum_attr(key, CKA_PRIVATE_EXPONENT, &bn_d);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;

        rc = p11tool_get_bignum_attr(key, CKA_PRIME_1, &bn_p);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;

        rc = p11tool_get_bignum_attr(key, CKA_PRIME_2, &bn_q);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;

        rc = p11tool_get_bignum_attr(key, CKA_EXPONENT_1, &bn_dmp1);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;

        rc = p11tool_get_bignum_attr(key, CKA_EXPONENT_2, &bn_dmq1);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;

        rc = p11tool_get_bignum_attr(key, CKA_COEFFICIENT, &bn_iqmp);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    rsa = RSA_new();
    if (rsa == NULL) {
        warnx("RSA_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    if (RSA_set0_key(rsa, bn_n, bn_e, bn_d) != 1) {
        warnx("RSA_set0_key failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    bn_n = bn_e = bn_d = NULL;

    if (private) {
        if (RSA_set0_factors(rsa, bn_p, bn_q) != 1) {
            warnx("RSA_set0_factors failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
        bn_p = bn_q = NULL;

        if (RSA_set0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp) != 1) {
            warnx("RSA_set0_crt_params failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
        bn_dmp1 = bn_dmq1 = bn_iqmp = NULL;
    }

    *pkey = EVP_PKEY_new();
    if (*pkey == NULL) {
        warnx("EVP_PKEY_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (EVP_PKEY_assign_RSA(*pkey, rsa) != 1) {
        warnx("EVP_PKEY_assign_RSA failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    rsa = NULL;
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        warnx("OSSL_PARAM_BLD_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_N, bn_n) ||
        !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_E, bn_e)) {
        warnx("OSSL_PARAM_BLD_push_BN failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (private) {
        if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_D, bn_d) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR1, bn_p) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_FACTOR2, bn_q) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT1,
                                                                   bn_dmp1) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_EXPONENT2,
                                                                   bn_dmq1) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_RSA_COEFFICIENT1,
                                                                   bn_iqmp)) {
            warnx("OSSL_PARAM_BLD_push_BN failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        warnx("OSSL_PARAM_BLD_to_param failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (pctx == NULL) {
        warnx("EVP_PKEY_CTX_new_id failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, pkey,
                           private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                           params)) {
        warnx("EVP_PKEY_fromdata_init/EVP_PKEY_fromdata failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

done:
    if (bn_n != NULL)
        BN_free(bn_n);
    if (bn_e != NULL)
        BN_free(bn_e);
    if (bn_d != NULL)
        BN_clear_free(bn_d);
    if (bn_p != NULL)
        BN_clear_free(bn_p);
    if (bn_q != NULL)
        BN_clear_free(bn_q);
    if (bn_dmp1 != NULL)
        BN_clear_free(bn_dmp1);
    if (bn_dmq1 != NULL)
        BN_clear_free(bn_dmq1);
    if (bn_iqmp != NULL)
        BN_clear_free(bn_iqmp);
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (rsa != NULL)
        RSA_free(rsa);
#else
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
    if (params != NULL)
        OSSL_PARAM_free(params);
#endif
    if (rc != CKR_OK && *pkey != NULL) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return rc;
}

static CK_RV p11sak_export_dh_pkey(const struct p11tool_objtype *keytype,
                                   EVP_PKEY **pkey, bool private,
                                   CK_OBJECT_HANDLE key, const char *label)
{
    BIGNUM *bn_p = NULL, *bn_g = NULL, *bn_pub = NULL, *bn_priv = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
#else
    DH *dh = NULL;
#endif
    CK_RV rc;

    rc = p11tool_get_bignum_attr(key, CKA_PRIME, &bn_p);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_PRIME from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

    rc = p11tool_get_bignum_attr(key, CKA_BASE, &bn_g);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_BASE from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

    if (private) {
        bn_priv = BN_secure_new();
        if (bn_priv == NULL) {
            warnx("Failed to allocate OpenSSL BIGNUM");
            rc = CKR_HOST_MEMORY;
            goto done;
        }
    }

    rc = p11tool_get_bignum_attr(key, CKA_VALUE, private ? &bn_priv : &bn_pub);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_VALUE from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    dh = DH_new();
    if (dh == NULL) {
        warnx("DH_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (DH_set0_pqg(dh, bn_p, NULL, bn_g) != 1) {
        warnx("DH_set0_pqg failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    bn_p = bn_g = NULL;

    if (DH_set0_key(dh, bn_pub, bn_priv) != 1) {
        warnx("DH_set0_key failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    bn_pub = bn_priv = NULL;

    *pkey = EVP_PKEY_new();
    if (*pkey == NULL) {
        warnx("EVP_PKEY_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (EVP_PKEY_assign_DH(*pkey, dh) != 1) {
        warnx("EVP_PKEY_assign_DH failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    dh = NULL;
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        warnx("OSSL_PARAM_BLD_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
        !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, bn_g) ||
        (!private &&
         !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PUB_KEY, bn_pub)) ||
         (private &&
          !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv))) {
        warnx("OSSL_PARAM_BLD_push_BN failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        warnx("OSSL_PARAM_BLD_to_param failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DH, NULL);
    if (pctx == NULL) {
        warnx("EVP_PKEY_CTX_new_id failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, pkey,
                           private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                           params)) {
        warnx("EVP_PKEY_fromdata_init/EVP_PKEY_fromdata failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

done:
    if (bn_p != NULL)
        BN_free(bn_p);
    if (bn_g != NULL)
        BN_free(bn_g);
    if (bn_priv != NULL)
        BN_clear_free(bn_priv);
    if (bn_pub != NULL)
        BN_free(bn_pub);
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (dh != NULL)
        DH_free(dh);
#else
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
    if (params != NULL)
        OSSL_PARAM_free(params);
#endif
    if (rc != CKR_OK && *pkey != NULL) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return rc;
}

static CK_RV p11sak_export_dsa_pkey(const struct p11tool_objtype *keytype,
                                    EVP_PKEY **pkey, bool private,
                                    CK_OBJECT_HANDLE key, const char *label)
{
    BIGNUM *bn_p = NULL, *bn_q = NULL, *bn_g = NULL;
    BIGNUM *bn_pub = NULL, *bn_priv = NULL;
#if OPENSSL_VERSION_PREREQ(3, 0)
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
#else
    DSA *dsa = NULL;
#endif
    CK_RV rc;

    rc = p11tool_get_bignum_attr(key, CKA_PRIME, &bn_p);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_PRIME from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

    rc = p11tool_get_bignum_attr(key, CKA_SUBPRIME, &bn_q);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_SUBPRIME from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }


    rc = p11tool_get_bignum_attr(key, CKA_BASE, &bn_g);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_BASE from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

    if (private) {
        bn_priv = BN_secure_new();
        if (bn_priv == NULL) {
            warnx("Failed to allocate OpenSSL BIGNUM");
            rc = CKR_HOST_MEMORY;
            goto done;
        }
    }

    rc = p11tool_get_bignum_attr(key, CKA_VALUE, private ? &bn_priv : &bn_pub);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_VALUE from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    dsa = DSA_new();
    if (dsa == NULL) {
        warnx("DSA_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (DSA_set0_pqg(dsa, bn_p, bn_q, bn_g) != 1) {
        warnx("DSA_set0_pqg failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    bn_p = bn_q = bn_g = NULL;

    if (DSA_set0_key(dsa, bn_pub, bn_priv) != 1) {
        warnx("DSA_set0_key failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    bn_pub = bn_priv = NULL;

    *pkey = EVP_PKEY_new();
    if (*pkey == NULL) {
        warnx("EVP_PKEY_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (EVP_PKEY_assign_DSA(*pkey, dsa) != 1) {
        warnx("EVP_PKEY_assign_DSA failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    dsa = NULL;
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        warnx("OSSL_PARAM_BLD_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_P, bn_p) ||
        !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_Q, bn_q) ||
        !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_FFC_G, bn_g) ||
        (!private &&
         !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PUB_KEY, bn_pub)) ||
         (private &&
          !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv))) {
        warnx("OSSL_PARAM_BLD_push_BN failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        warnx("OSSL_PARAM_BLD_to_param failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_DSA, NULL);
    if (pctx == NULL) {
        warnx("EVP_PKEY_CTX_new_id failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, pkey,
                           private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                           params)) {
        warnx("EVP_PKEY_fromdata_init/EVP_PKEY_fromdata failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

done:
    if (bn_p != NULL)
        BN_free(bn_p);
    if (bn_q != NULL)
        BN_free(bn_q);
    if (bn_g != NULL)
        BN_free(bn_g);
    if (bn_priv != NULL)
        BN_clear_free(bn_priv);
    if (bn_pub != NULL)
        BN_free(bn_pub);
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (dsa != NULL)
        DSA_free(dsa);
#else
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
    if (params != NULL)
        OSSL_PARAM_free(params);
#endif
    if (rc != CKR_OK && *pkey != NULL) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return rc;
}

static CK_RV x509_to_pem(X509 *cert, CK_BYTE **data, CK_ULONG *data_len)
{
    BIO *bio = NULL;
    BUF_MEM *bptr;
    CK_BYTE *pem = NULL;
    int bio_len;
    CK_RV rc;

    bio = BIO_new(BIO_s_mem());
    if (bio == NULL)
        return CKR_HOST_MEMORY;

    if (!PEM_write_bio_X509(bio, cert)) {
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    BIO_get_mem_ptr(bio, &bptr);
    bio_len = bptr->length;

    pem = malloc(bio_len);
    if (pem == NULL) {
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (BIO_read(bio, pem, bio_len) != bio_len) {
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    *data = pem;
    *data_len = bio_len;

    rc = CKR_OK;

done:
    if (bio != NULL)
        BIO_free(bio);

    return rc;
}

static CK_RV p11sak_export_x509(const struct p11tool_objtype *certtype,
                                CK_BYTE **data, CK_ULONG *data_len,
                                CK_OBJECT_HANDLE cert,
                                const char *label)
{
    CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 0 };
    const CK_BYTE *tmp_value;
    X509* x509;
    CK_RV rc;

    rc = p11tool_get_attribute(cert, &attr);
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_VALUE from %s certificate "
              "object \"%s\": 0x%lX: %s", certtype->name, label, rc,
              p11_get_ckr(rc));
        return rc;
    }

    if (opt_der) {
        *data = attr.pValue;
        *data_len = attr.ulValueLen;
    } else {
        tmp_value = (CK_BYTE *)attr.pValue;
        x509 = d2i_X509(NULL, &tmp_value, attr.ulValueLen);
        if (x509 == NULL) {
            warnx("Failed to convert CKA_VALUE from %s certificate "
                  "object \"%s\" to X509 object.", certtype->name, label);
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            if (attr.pValue != NULL)
                free(attr.pValue);
            goto done;
        }
        rc = x509_to_pem(x509, data, data_len);
        X509_free(x509);
        if (attr.pValue != NULL)
            free(attr.pValue);
        if (rc != CKR_OK) {
            warnx("Failed to convert X509 from %s certificate "
                  "object \"%s\" to PEM form.", certtype->name, label);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    rc = CKR_OK;

done:

    return rc;
}

#if OPENSSL_VERSION_PREREQ(3, 0)
static CK_RV p11sak_export_ecx_pkey(const struct p11tool_objtype *keytype,
                                    int type, EVP_PKEY **pkey, bool private,
                                    CK_OBJECT_HANDLE key, const char *label)
{
    CK_ATTRIBUTE value_attr = { CKA_VALUE, NULL, 0 };
    CK_ATTRIBUTE ecpoint_attr = { CKA_EC_POINT, NULL, 0 };
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len = 0;
    CK_RV rc;

    if (private) {
        rc = p11tool_get_attribute(key, &value_attr);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;
        if (rc != CKR_OK) {
            warnx("Failed to retrieve attribute CKA_VALUE from %s key "
                  "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
                  p11_get_ckr(rc));
            goto done;
        }
    } else {
        rc = p11tool_get_attribute(key, &ecpoint_attr);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;
        if (rc != CKR_OK) {
            warnx("Failed to retrieve attribute CKA_EC_POINT from %s key "
                  "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
                  p11_get_ckr(rc));
            goto done;
        }

        ecpoint = (CK_BYTE*)ecpoint_attr.pValue;
        ecpoint_len = ecpoint_attr.ulValueLen;

        if (keytype->type == CKK_EC) {
            /* remove octet string BER encoding */
            if ((ecpoint[1] & 0x80) == 0) {
                ecpoint += 2;
                ecpoint_len -= 2;
            } else {
                ecpoint += 2 + (ecpoint[1] & 0x7f);
                ecpoint_len -= 3 + (ecpoint[1] & 0x7f);
            }
        }
    }

    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        warnx("OSSL_PARAM_BLD_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (private) {
        if (!OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PRIV_KEY,
                                              value_attr.pValue,
                                              value_attr.ulValueLen)) {
            warnx("OSSL_PARAM_BLD_push_octet_string failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        if (!OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PUB_KEY,
                                              ecpoint, ecpoint_len)) {
            warnx("OSSL_PARAM_BLD_push_octet_string failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        warnx("OSSL_PARAM_BLD_to_param failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    pctx = EVP_PKEY_CTX_new_id(type, NULL);
    if (pctx == NULL) {
        warnx("EVP_PKEY_CTX_new_id failed for type %d.", type);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, pkey,
                           private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                           params)) {
        warnx("EVP_PKEY_fromdata_init/EVP_PKEY_fromdata for type %d failed.",
              type);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

done:
    if (ecpoint_attr.pValue != NULL)
        free(ecpoint_attr.pValue);
    if (value_attr.pValue != NULL)
        free(value_attr.pValue);
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
    if (params != NULL)
        OSSL_PARAM_free(params);
    if (private && ecpoint != NULL)
        OPENSSL_free(ecpoint);
    if (rc != CKR_OK && *pkey != NULL) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return rc;
}
#endif

static CK_RV p11sak_export_ec_pkey(const struct p11tool_objtype *keytype,
                                   EVP_PKEY **pkey, bool private,
                                   CK_OBJECT_HANDLE key, const char *label)
{
    BIGNUM *bn_priv = NULL;
    CK_ATTRIBUTE ecparams_attr = { CKA_EC_PARAMS, NULL, 0 };
    CK_ATTRIBUTE ecpoint_attr = { CKA_EC_POINT, NULL, 0 };
#if OPENSSL_VERSION_PREREQ(3, 0)
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *tmpl = NULL;
    OSSL_PARAM *params = NULL;
    EC_GROUP *group = NULL;
#else
    EC_KEY *ec = NULL;
#endif
    CK_BYTE *ecpoint = NULL;
    CK_ULONG ecpoint_len = 0;
    EC_POINT *point = NULL;
    const unsigned char *oid;
    ASN1_OBJECT *obj = NULL;
    int nid;
    CK_RV rc;

    rc = p11tool_get_attribute(key, &ecparams_attr);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto done;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_EC_PARAMS from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto done;
    }

    oid = ecparams_attr.pValue;
    obj = d2i_ASN1_OBJECT(NULL, &oid, ecparams_attr.ulValueLen);
    if (obj == NULL ||
        oid != (CK_BYTE *)ecparams_attr.pValue + ecparams_attr.ulValueLen) {
        warnx("Curve of %s key object \"%s\" not supported by OpenSSL.",
              keytype->name, label);
        goto done;
    }

    nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);
    if (ecparams_attr.pValue != NULL)
        free(ecparams_attr.pValue);
    ecparams_attr.pValue = NULL;
    ecparams_attr.ulValueLen = 0;

    switch (nid) {
#if OPENSSL_VERSION_PREREQ(3, 0)
    case NID_X25519:
    case NID_ED25519:
    case NID_X448:
    case NID_ED448:
        return p11sak_export_ecx_pkey(keytype, nid, pkey, private, key, label);
#endif
    default:
        break;
    }

    if (private) {
        bn_priv = BN_secure_new();
        if (bn_priv == NULL) {
            warnx("Failed to allocate OpenSSL BIGNUM");
            rc = CKR_HOST_MEMORY;
            goto done;
        }

        rc = p11tool_get_bignum_attr(key, CKA_VALUE, &bn_priv);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;
        if (rc != CKR_OK) {
            warnx("Failed to retrieve attribute CKA_VALUE from %s key "
                  "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
                  p11_get_ckr(rc));
            goto done;
        }
    } else {
        rc = p11tool_get_attribute(key, &ecpoint_attr);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto done;
        if (rc != CKR_OK) {
            warnx("Failed to retrieve attribute CKA_EC_POINT from %s key "
                  "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
                  p11_get_ckr(rc));
            goto done;
        }

        /* remove octet string BER encoding */
        ecpoint = (CK_BYTE*)ecpoint_attr.pValue;
        ecpoint_len = ecpoint_attr.ulValueLen;
        if ((ecpoint[1] & 0x80) == 0) {
            ecpoint += 2;
            ecpoint_len -= 2;
        } else {
            ecpoint += 2 + (ecpoint[1] & 0x7f);
            ecpoint_len -= 3 + (ecpoint[1] & 0x7f);
        }
    }

#if !OPENSSL_VERSION_PREREQ(3, 0)
    ec = EC_KEY_new_by_curve_name(nid);
    if (ec == NULL) {
        warnx("EC_KEY_new_by_curve_name failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (private) {
        if (EC_KEY_set_private_key(ec, bn_priv) != 1) {
            warnx("EC_KEY_set_private_key failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
        bn_priv = NULL;

        point = EC_POINT_new(EC_KEY_get0_group(ec));
        if (point == NULL) {
            warnx("EC_POINT_new failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        if (!EC_POINT_mul(EC_KEY_get0_group(ec), point,
                          EC_KEY_get0_private_key(ec), NULL, NULL, NULL)) {
            warnx("EC_POINT_mul failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        if (!EC_KEY_set_public_key(ec, point)) {
            warnx("EC_KEY_set_public_key failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        if (!EC_KEY_oct2key(ec, ecpoint, ecpoint_len, NULL)) {
            warnx("EC_KEY_oct2key failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    *pkey = EVP_PKEY_new();
    if (*pkey == NULL) {
        warnx("EVP_PKEY_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (EVP_PKEY_assign_EC_KEY(*pkey, ec) != 1) {
        warnx("EVP_PKEY_assign_EC failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
    ec = NULL;
#else
    tmpl = OSSL_PARAM_BLD_new();
    if (tmpl == NULL) {
        warnx("OSSL_PARAM_BLD_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!OSSL_PARAM_BLD_push_utf8_string(tmpl, OSSL_PKEY_PARAM_GROUP_NAME,
                                         OBJ_nid2sn(nid), 0)) {
        warnx("OSSL_PARAM_BLD_push_BN failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (private) {
        group = EC_GROUP_new_by_curve_name(nid);
        if (group == NULL) {
            warnx("EC_GROUP_new_by_curve_name failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        point = EC_POINT_new(group);
        if (point == NULL) {
            warnx("EC_POINT_new failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        if (!EC_POINT_mul(group, point, bn_priv, NULL, NULL, NULL)) {
            warnx("EC_POINT_mul failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        ecpoint_len = EC_POINT_point2buf(group, point,
                                    EC_GROUP_get_point_conversion_form(group),
                                    &ecpoint, NULL);
        if (ecpoint_len == 0) {
            warnx("EC_POINT_point2buf failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        if (!OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PUB_KEY,
                                              ecpoint, ecpoint_len) ||
            !OSSL_PARAM_BLD_push_BN(tmpl, OSSL_PKEY_PARAM_PRIV_KEY, bn_priv)) {
            warnx("OSSL_PARAM_BLD_push_BN failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        if (!OSSL_PARAM_BLD_push_octet_string(tmpl, OSSL_PKEY_PARAM_PUB_KEY,
                                              ecpoint, ecpoint_len)) {
            warnx("OSSL_PARAM_BLD_push_BN failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

    params = OSSL_PARAM_BLD_to_param(tmpl);
    if (params == NULL) {
        warnx("OSSL_PARAM_BLD_to_param failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (pctx == NULL) {
        warnx("EVP_PKEY_CTX_new_id failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (!EVP_PKEY_fromdata_init(pctx) ||
        !EVP_PKEY_fromdata(pctx, pkey,
                           private ? EVP_PKEY_KEYPAIR : EVP_PKEY_PUBLIC_KEY,
                           params)) {
        warnx("EVP_PKEY_fromdata_init/EVP_PKEY_fromdata failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }
#endif

done:
    if (bn_priv != NULL)
        BN_clear_free(bn_priv);
    if (ecparams_attr.pValue != NULL)
        free(ecparams_attr.pValue);
    if (ecpoint_attr.pValue != NULL)
        free(ecpoint_attr.pValue);
    if (point != NULL)
        EC_POINT_free(point);
#if !OPENSSL_VERSION_PREREQ(3, 0)
    if (ec != NULL)
        EC_KEY_free(ec);
#else
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (tmpl != NULL)
        OSSL_PARAM_BLD_free(tmpl);
    if (params != NULL)
        OSSL_PARAM_free(params);
    if (group != NULL)
        EC_GROUP_free(group);
    if (private && ecpoint != NULL)
        OPENSSL_free(ecpoint);
#endif
    if (rc != CKR_OK && *pkey != NULL) {
        EVP_PKEY_free(*pkey);
        *pkey = NULL;
    }

    return rc;
}

static CK_RV p11sak_export_dilithium_kyber_pem_data(
                                        const struct p11tool_objtype *keytype,
                                        CK_BYTE **data, CK_ULONG *data_len,
                                        bool private, CK_OBJECT_HANDLE key,
                                        const char *label)
{
    CK_ATTRIBUTE attr = { CKA_VALUE, NULL, 0 };
    CK_RV rc;

    UNUSED(private);

    rc = p11tool_get_attribute(key, &attr);
    if (rc == CKR_ATTRIBUTE_SENSITIVE) {
        warnx("%s key object \"%s\" is sensitive and can not be exported.",
              keytype->name, label);
        return rc;
    }
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_VALUE from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        return rc;
    }

    *data = attr.pValue;
    *data_len = attr.ulValueLen;

    return CKR_OK;
}

#if OPENSSL_VERSION_PREREQ(3, 0)
static const char *get_openssl_pqc_oid_name(const struct pqc_oid *oid)
{
    const CK_BYTE *poid = oid->oid;
    ASN1_OBJECT *obj = NULL;
    int nid;

    if (d2i_ASN1_OBJECT(&obj, &poid, oid->oid_len) == NULL)
        return NULL;

    nid = OBJ_obj2nid(obj);
    ASN1_OBJECT_free(obj);

    if (nid == NID_undef)
        return NULL;

    return OBJ_nid2ln(nid);
}
#endif

static CK_RV p11sak_export_dilithium_ml_dsa_pkey(
                                          const struct p11tool_objtype *keytype,
                                          EVP_PKEY **pkey, bool private,
                                          CK_OBJECT_HANDLE key,
                                          const char *label)
{
#if OPENSSL_VERSION_PREREQ(3, 0)
    CK_ULONG keyform = 0;
    CK_ATTRIBUTE keyform_attr = { CKA_IBM_DILITHIUM_KEYFORM,
                                  &keyform, sizeof(keyform) };
    CK_ATTRIBUTE parameter_set_attr = { CKA_IBM_PARAMETER_SET,
                                        &keyform, sizeof(keyform) };
    CK_ATTRIBUTE priv_attrs[] = {
        { CKA_IBM_ML_DSA_RHO, NULL, 0 },
        { CKA_IBM_ML_DSA_SEED, NULL, 0 },
        { CKA_IBM_ML_DSA_TR, NULL, 0 },
        { CKA_IBM_ML_DSA_S1, NULL, 0 },
        { CKA_IBM_ML_DSA_S2, NULL, 0 },
        { CKA_IBM_ML_DSA_T0, NULL, 0 },
        { CKA_IBM_ML_DSA_PRIVATE_SEED, NULL, 0 },
    };
    CK_ATTRIBUTE pub_attrs[] = {
        { CKA_IBM_ML_DSA_RHO, NULL, 0 },
        { CKA_IBM_ML_DSA_T1, NULL, 0 },
    };
    const struct pqc_oid *oid;
    const char *alg_name;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    CK_ULONG priv_len = 0, pub_len = 0, seed_len = 0, ofs;
    CK_BYTE *priv_key = NULL, *pub_key = NULL, *priv_seed = NULL;
    CK_RV rc;

    rc = p11tool_get_attribute(key, keytype->type == CKK_IBM_PQC_DILITHIUM ?
                                        &keyform_attr : &parameter_set_attr);
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute %s from %s "
              "key object \"%s\": 0x%lX: %s",
              keytype->type == CKK_IBM_PQC_DILITHIUM ?
                      "CKA_IBM_DILITHIUM_KEYFORM" : "CKA_IBM_PARAMETER_SET",
              keytype->name, label, rc, p11_get_ckr(rc));
        return rc;
    }

    oid = find_pqc_by_keyform(keytype->type == CKK_IBM_PQC_DILITHIUM ?
                                        dilithium_oids : ml_dsa_oids,
                              keyform);
    if (oid == NULL) {
        warnx("%s keyform '%lu' is not supported by p11sak.", keytype->name,
              keyform);
        return CKR_FUNCTION_FAILED;
    }

    alg_name = get_openssl_pqc_oid_name(oid);
    if (alg_name == NULL) {
        warnx("%s keyform '%lu' is not supported by OpenSSL. "
              "Is the 'oqsprovider' configured (for OpenSSL < version 3.5)?",
              keytype->name, keyform);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    if (private) {
        priv_len = oid->len_info.ml_dsa.rho_len +
                   oid->len_info.ml_dsa.seed_len +
                   oid->len_info.ml_dsa.tr_len +
                   oid->len_info.ml_dsa.s1_len +
                   oid->len_info.ml_dsa.s2_len +
                   oid->len_info.ml_dsa.t0_len;

        priv_key = calloc(1, priv_len);
        if (priv_key == NULL) {
            warnx("Failed to allocate buffer for private key.");
            rc = CKR_HOST_MEMORY;
            goto out;
        }

        if (keytype->type == CKK_IBM_ML_DSA) {
            seed_len = oid->len_info.ml_dsa.priv_seed_len;
            priv_seed = calloc(1, seed_len);
            if (priv_seed == NULL) {
                warnx("Failed to allocate buffer for private seed.");
                rc = CKR_HOST_MEMORY;
                goto out;
            }
        }

        ofs = 0;
        priv_attrs[0].pValue = priv_key + ofs;
        priv_attrs[0].ulValueLen = oid->len_info.ml_dsa.rho_len;
        ofs += oid->len_info.ml_dsa.rho_len;
        priv_attrs[1].pValue = priv_key + ofs;
        priv_attrs[1].ulValueLen = oid->len_info.ml_dsa.seed_len;
        ofs += oid->len_info.ml_dsa.seed_len;
        priv_attrs[2].pValue = priv_key + ofs;
        priv_attrs[2].ulValueLen = oid->len_info.ml_dsa.tr_len;
        ofs += oid->len_info.ml_dsa.tr_len;
        priv_attrs[3].pValue = priv_key + ofs;
        priv_attrs[3].ulValueLen = oid->len_info.ml_dsa.s1_len;
        ofs += oid->len_info.ml_dsa.s1_len;
        priv_attrs[4].pValue = priv_key + ofs;
        priv_attrs[4].ulValueLen = oid->len_info.ml_dsa.s2_len;
        ofs += oid->len_info.ml_dsa.s2_len;
        priv_attrs[5].pValue = priv_key + ofs;
        priv_attrs[5].ulValueLen = oid->len_info.ml_dsa.t0_len;

        if (keytype->type == CKK_IBM_ML_DSA) {
            priv_attrs[6].pValue = priv_seed;
            priv_attrs[6].ulValueLen = oid->len_info.ml_dsa.priv_seed_len;
        }

        rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session,
                                                       key, priv_attrs,
                                                       keytype->type ==
                                                               CKK_IBM_ML_DSA ?
                                                                       7 : 6);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto out;
        if (rc != CKR_OK) {
            warnx("Failed to retrieve private key attributes from %s key "
                  "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
                  p11_get_ckr(rc));
            goto out;
        }

        if (priv_attrs[0].ulValueLen != oid->len_info.ml_dsa.rho_len ||
            priv_attrs[1].ulValueLen != oid->len_info.ml_dsa.seed_len ||
            priv_attrs[2].ulValueLen != oid->len_info.ml_dsa.tr_len ||
            priv_attrs[3].ulValueLen != oid->len_info.ml_dsa.s1_len ||
            priv_attrs[4].ulValueLen != oid->len_info.ml_dsa.s2_len ||
            priv_attrs[5].ulValueLen != oid->len_info.ml_dsa.t0_len) {
            warnx("Failed to retrieve private key attributes from %s key "
                  "object \"%s\": Private key component lengths are wrong.",
                  keytype->name, label);
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        if (keytype->type == CKK_IBM_ML_DSA &&
            priv_attrs[6].ulValueLen != oid->len_info.ml_dsa.priv_seed_len &&
            priv_attrs[6].ulValueLen != 0) {
            warnx("Failed to retrieve private key attributes from %s key "
                  "object \"%s\": Private key component lengths are wrong.",
                  keytype->name, label);
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        seed_len = priv_attrs[6].ulValueLen;
    }

    pub_len = oid->len_info.ml_dsa.rho_len +
              oid->len_info.ml_dsa.t1_len;

    pub_key = calloc(1, pub_len);
    if (pub_key == NULL) {
        warnx("Failed to allocate buffer for public key.");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    ofs = 0;
    pub_attrs[0].pValue = pub_key + ofs;
    pub_attrs[0].ulValueLen = oid->len_info.ml_dsa.rho_len;
    ofs += oid->len_info.ml_dsa.rho_len;
    pub_attrs[1].pValue = pub_key + ofs;
    pub_attrs[1].ulValueLen = oid->len_info.ml_dsa.t1_len;

    rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session, key,
                                                   pub_attrs, 2);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto out;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve public key attributes from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto out;
    }

    if (pub_attrs[0].ulValueLen != oid->len_info.ml_dsa.rho_len ||
        pub_attrs[1].ulValueLen != oid->len_info.ml_dsa.t1_len) {
        warnx("Failed to retrieve public key attributes from %s key "
              "object \"%s\": Public key component lengths are wrong.",
              keytype->name, label);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    pctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (pctx == NULL) {
        warnx("EVP_PKEY_CTX_new_from_name failed for '%s'. "
              "Is the 'oqsprovider' configured (for OpenSSL < version 3.5)?",
              alg_name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        warnx("OSSL_PARAM_BLD_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (private) {
        if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             priv_key, priv_len) != 1) {
            warnx("OSSL_PARAM_BLD_push_octet_string failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        /* Try to set private seed, but ignore if it is not available */
        if (p11tool_check_settable_fromdata_params(pctx,
                                             OSSL_PKEY_PARAM_ML_KEM_SEED) &&
            seed_len > 0) {
            if (OSSL_PARAM_BLD_push_octet_string(bld,
                                                 OSSL_PKEY_PARAM_ML_DSA_SEED,
                                                 priv_seed, seed_len) != 1) {
                warnx("OSSL_PARAM_BLD_push_octet_string failed.");
                ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
                rc = CKR_FUNCTION_FAILED;
                goto out;
            }
        }
    }

    if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         pub_key, pub_len) != 1) {
        warnx("OSSL_PARAM_BLD_push_octet_string failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        warnx("OSSL_PARAM_BLD_to_param failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_fromdata_init(pctx) != 1) {
        warnx("EVP_PKEY_fromdata_init failed for '%s'.", alg_name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_fromdata(pctx, pkey, private ? EVP_PKEY_KEYPAIR :
                                                EVP_PKEY_PUBLIC_KEY,
                          params) != 1) {
        warnx("EVP_PKEY_fromdata failed for '%s'.", alg_name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

out:
    if (priv_key != NULL) {
        OPENSSL_cleanse(priv_key, priv_len);
        free(priv_key);
    }
    if (priv_seed != NULL) {
        OPENSSL_cleanse(priv_seed, seed_len);
        free(priv_seed);
    }
    if (pub_key != NULL)
        free(pub_key);
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (bld != NULL)
        OSSL_PARAM_BLD_free(bld);
    if (params != NULL)
        OSSL_PARAM_free(params);

    return rc;
#else
    UNUSED(keytype);
    UNUSED(pkey);
    UNUSED(private);
    UNUSED(key);
    UNUSED(label);

    warnx("Exporting an 'oqsprovider' format PEM file is only supported with "
          "OpenSSL 3.0 or later.");
    return CKR_FUNCTION_NOT_SUPPORTED;
#endif
}

static CK_RV p11sak_export_ml_kem_pkey(const struct p11tool_objtype *keytype,
                                       EVP_PKEY **pkey, bool private,
                                       CK_OBJECT_HANDLE key,
                                       const char *label)
{
#if OPENSSL_VERSION_PREREQ(3, 0)
    CK_ULONG parameter_set = 0;
    CK_ATTRIBUTE parameter_set_attr = { CKA_IBM_PARAMETER_SET,
                                        &parameter_set, sizeof(parameter_set) };
    CK_ATTRIBUTE priv_attrs[] = {
        { CKA_IBM_ML_KEM_SK, NULL, 0 },
        { CKA_IBM_ML_KEM_PRIVATE_SEED, NULL, 0 },
    };
    CK_ATTRIBUTE pub_attrs[] = {
        { CKA_IBM_ML_KEM_PK, NULL, 0 },
    };
    const struct pqc_oid *oid;
    const char *alg_name;
    EVP_PKEY_CTX *pctx = NULL;
    OSSL_PARAM_BLD *bld = NULL;
    OSSL_PARAM *params = NULL;
    CK_ULONG priv_len = 0, pub_len = 0, seed_len = 0;
    CK_BYTE *priv_key = NULL, *pub_key = NULL, *priv_seed = NULL;
    CK_RV rc;

    rc = p11tool_get_attribute(key, &parameter_set_attr);
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_IBM_PARAMETER_SET from %s "
              "key object \"%s\": 0x%lX: %s",
              keytype->name, label, rc, p11_get_ckr(rc));
        return rc;
    }

    oid = find_pqc_by_keyform(ml_kem_oids, parameter_set);
    if (oid == NULL) {
        warnx("%s parameter set '%lu' is not supported by p11sak.",
              keytype->name, parameter_set);
        return CKR_FUNCTION_FAILED;
    }

    alg_name = get_openssl_pqc_oid_name(oid);
    if (alg_name == NULL) {
        warnx("%s parameter set '%lu' is not supported by OpenSSL. "
              "Is the 'oqsprovider' configured (for OpenSSL < version 3.5)?",
              keytype->name, parameter_set);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    if (private) {
        priv_len = oid->len_info.ml_kem.sk_len;

        priv_key = calloc(1, priv_len);
        if (priv_key == NULL) {
            warnx("Failed to allocate buffer for private key.");
            rc = CKR_HOST_MEMORY;
            goto out;
        }

        seed_len = oid->len_info.ml_kem.priv_seed_len;
        priv_seed = calloc(1, seed_len);
        if (priv_seed == NULL) {
            warnx("Failed to allocate buffer for private seed.");
            rc = CKR_HOST_MEMORY;
            goto out;
        }

        priv_attrs[0].pValue = priv_key;
        priv_attrs[0].ulValueLen = oid->len_info.ml_kem.sk_len;
        priv_attrs[1].pValue = priv_seed;
        priv_attrs[1].ulValueLen = oid->len_info.ml_kem.priv_seed_len;

        rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session,
                                                       key, priv_attrs, 2);
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            goto out;
        if (rc != CKR_OK) {
            warnx("Failed to retrieve private key attributes from %s key "
                  "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
                  p11_get_ckr(rc));
            goto out;
        }

        if (priv_attrs[0].ulValueLen != oid->len_info.ml_kem.sk_len ||
            (priv_attrs[1].ulValueLen != oid->len_info.ml_kem.priv_seed_len &&
             priv_attrs[1].ulValueLen != 0)) {
            warnx("Failed to retrieve private key attributes from %s key "
                  "object \"%s\": Private key component lengths are wrong.",
                  keytype->name, label);
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        seed_len = priv_attrs[1].ulValueLen;
    }

    pub_len = oid->len_info.ml_kem.pk_len;

    pub_key = calloc(1, pub_len);
    if (pub_key == NULL) {
        warnx("Failed to allocate buffer for public key.");
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    pub_attrs[0].pValue = pub_key;
    pub_attrs[0].ulValueLen = oid->len_info.ml_kem.pk_len;

    rc = p11tool_pkcs11_funcs->C_GetAttributeValue(p11tool_pkcs11_session, key,
                                                   pub_attrs, 1);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        goto out;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve public key attributes from %s key "
              "object \"%s\": 0x%lX: %s", keytype->name, label, rc,
              p11_get_ckr(rc));
        goto out;
    }

    if (pub_attrs[0].ulValueLen != oid->len_info.ml_kem.pk_len) {
        warnx("Failed to retrieve public key attributes from %s key "
              "object \"%s\": Public key component lengths are wrong.",
              keytype->name, label);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }


    pctx = EVP_PKEY_CTX_new_from_name(NULL, alg_name, NULL);
    if (pctx == NULL) {
        warnx("EVP_PKEY_CTX_new_from_name failed for '%s'. "
              "Is the 'oqsprovider' configured (for OpenSSL < version 3.5)?",
              alg_name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    bld = OSSL_PARAM_BLD_new();
    if (bld == NULL) {
        warnx("OSSL_PARAM_BLD_new failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_HOST_MEMORY;
        goto out;
    }

    if (private) {
        if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PRIV_KEY,
                                             priv_key, priv_len) != 1) {
            warnx("OSSL_PARAM_BLD_push_octet_string failed.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto out;
        }

        /* Try to set private seed, but ignore if it is not available */
        if (p11tool_check_settable_fromdata_params(pctx,
                                              OSSL_PKEY_PARAM_ML_KEM_SEED) &&
            seed_len > 0) {
            if (OSSL_PARAM_BLD_push_octet_string(bld,
                                                 OSSL_PKEY_PARAM_ML_KEM_SEED,
                                                 priv_seed, seed_len) != 1) {
                warnx("OSSL_PARAM_BLD_push_octet_string failed.");
                ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
                rc = CKR_FUNCTION_FAILED;
                goto out;
            }
        }
    }

    if (OSSL_PARAM_BLD_push_octet_string(bld, OSSL_PKEY_PARAM_PUB_KEY,
                                         pub_key, pub_len) != 1) {
        warnx("OSSL_PARAM_BLD_push_octet_string failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    params = OSSL_PARAM_BLD_to_param(bld);
    if (params == NULL) {
        warnx("OSSL_PARAM_BLD_to_param failed.");
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }


    if (EVP_PKEY_fromdata_init(pctx) != 1) {
        warnx("EVP_PKEY_fromdata_init failed for '%s'.", alg_name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (EVP_PKEY_fromdata(pctx, pkey, private ? EVP_PKEY_KEYPAIR :
                                                EVP_PKEY_PUBLIC_KEY,
                          params) != 1) {
        warnx("EVP_PKEY_fromdata failed for '%s'.", alg_name);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

out:
    if (priv_key != NULL) {
        OPENSSL_cleanse(priv_key, priv_len);
        free(priv_key);
    }
    if (pub_key != NULL)
        free(pub_key);
    if (pctx != NULL)
        EVP_PKEY_CTX_free(pctx);
    if (bld != NULL)
        OSSL_PARAM_BLD_free(bld);
    if (params != NULL)
        OSSL_PARAM_free(params);

    return rc;
#else
    UNUSED(keytype);
    UNUSED(pkey);
    UNUSED(private);
    UNUSED(key);
    UNUSED(label);

    warnx("Exporting an 'oqsprovider' format PEM file is only supported with "
          "OpenSSL 3.0 or later.");
    return CKR_FUNCTION_NOT_SUPPORTED;
#endif
}

static CK_RV p11sak_export_spki(const struct p11tool_objtype *keytype,
                                CK_OBJECT_HANDLE key,
                                const char *typestr, const char* label,
                                BIO* bio)
{
    CK_ATTRIBUTE attr = { CKA_PUBLIC_KEY_INFO, NULL, 0 };
    CK_RV rc;
    int ret;

    UNUSED(keytype);

    rc = p11tool_get_attribute(key, &attr);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        return rc;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_PUBLIC_KEY_INFO from %s key "
              "object \"%s\": 0x%lX: %s", typestr, label, rc, p11_get_ckr(rc));
        return rc;
    }

    ret = PEM_write_bio(bio, PEM_STRING_PUBLIC, "",
                        attr.pValue, attr.ulValueLen);
    if (ret <= 0) {
        warnx("Failed to write SPKI of %s key object \"%s\" to PEM file '%s'.",
              typestr, label, opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

done:
    free(attr.pValue);

    return rc;
}

static CK_RV p11sak_export_opaque_key(const struct p11tool_objtype *keytype,
                                      CK_OBJECT_HANDLE key,
                                      const char *typestr, const char* label,
                                      BIO* bio)
{
    CK_ATTRIBUTE attr = { CKA_IBM_OPAQUE, NULL, 0 };
    CK_RV rc;

    UNUSED(keytype);

    rc = p11tool_get_attribute(key, &attr);
    if (rc == CKR_ATTRIBUTE_SENSITIVE)
        return rc;
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_IBM_OPAQUE from %s key "
              "object \"%s\": 0x%lX: %s", typestr, label, rc, p11_get_ckr(rc));
        return rc;
    }

    if (BIO_write(bio, attr.pValue, attr.ulValueLen) != (int)attr.ulValueLen) {
        warnx("Failed to write to file '%s'.", opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

done:
    free(attr.pValue);

    return rc;
}

static CK_ULONG ber_encode_len(CK_ULONG data_len, CK_BYTE *out)
{
    CK_ULONG ret = 0;

    if (data_len < 128) {
        ret = 1;
        if (out != NULL)
            out[0] = (CK_BYTE)(data_len & 0x7f);
    } else if (data_len < 256) {
        ret = 2;
        if (out != NULL) {
            out[0] = 0x81;
            out[1] = (CK_BYTE)(data_len & 0xff);
        }
    } else if (data_len < (1 << 16)) {
        ret = 3;
        if (out != NULL) {
            out[0] = 0x82;
            out[1] = (CK_BYTE)((data_len >> 8) & 0xff);
            out[2] = (CK_BYTE)(data_len & 0xff);
        }
    }

    return ret;
}

static CK_RV p11sak_export_uri_pem(const struct p11tool_objtype *keytype,
                                   CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                                   const char *typestr, const char *msgtype,
                                   const char* label, BIO* bio)
{
    struct p11_uri *uri = NULL;
    const char *uri_str;
    CK_ULONG descr_len, uri_len, total_len, ofs = 0;
    CK_BYTE *data = NULL;
    CK_RV rc;
    int ret;

    rc = p11tool_prepare_uri(key, &class, keytype, typestr, label,
                             opt_detailed_uri, opt_slot, &uri);
    if (rc != CKR_OK)
        goto done;

    if (opt_uri_pin_value)
        uri->pin_value = p11tool_pin;
    else if (opt_uri_pin_source != NULL)
        uri->pin_source = opt_uri_pin_source;

    uri_str = p11_uri_format(uri);

    descr_len = 1 + ber_encode_len(strlen(PKCS11_URI_DESCRIPTION), NULL) +
                strlen(PKCS11_URI_DESCRIPTION);
    uri_len = 1 + ber_encode_len(strlen(uri_str), NULL) + strlen(uri_str);
    total_len = 1 + ber_encode_len(descr_len + uri_len, NULL) +
                descr_len + uri_len;

    data = calloc(total_len, 1);
    if (data == NULL) {
        warnx("Failed to allocate a buffer for the URI-PEM data");
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    data[ofs++] = 0x30; /* SEQUENE */
    ofs += ber_encode_len(descr_len + uri_len, &data[ofs]);
    data[ofs++] = 0x1a; /* VISIBLE STRING */
    ofs += ber_encode_len(strlen(PKCS11_URI_DESCRIPTION), &data[ofs]);
    memcpy(&data[ofs], PKCS11_URI_DESCRIPTION, strlen(PKCS11_URI_DESCRIPTION));
    ofs += strlen(PKCS11_URI_DESCRIPTION);
    data[ofs++] = 0x0c; /* UTF8 STRING */
    ofs += ber_encode_len(strlen(uri_str), &data[ofs]);
    memcpy(&data[ofs], uri_str, strlen(uri_str));
    ofs += strlen(uri_str);

    ret = PEM_write_bio(bio, PKCS11_URI_PEM_NAME, "", data, total_len);
    if (ret <= 0) {
        warnx("Failed to write %s %s object \"%s\" to URI-PEM file '%s'.",
              typestr, msgtype, label, opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

done:
    if (uri != NULL) {
        if (uri->obj_id[0].pValue != NULL)
            free(uri->obj_id[0].pValue);
        p11_uri_free(uri);
    }

    if (data != NULL) {
        OPENSSL_cleanse(data,  total_len);
        free(data);
    }

    return rc;
}

static CK_RV p11sak_export_asym_key(const struct p11tool_objtype *keytype,
                                    CK_OBJECT_HANDLE key, bool private,
                                    const char *typestr, const char* label,
                                    BIO* bio)
{
    struct p11tool_pem_password_cb_data cb_data = { 0 };
    EVP_PKEY *pkey = NULL;
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_RV rc = CKR_OK;
    int ret;

    if (private && has_ibm_opaque_attr(key)) {
        warnx("%s key object \"%s\" contains an opaque secure key blob and "
              "can not be exported in clear.", typestr, label);
        warnx("Use option '-o'/'--opaque' to export the opaque secure key blob "
              "instead.");
        return CKR_KEY_UNEXTRACTABLE;
    }

    if (opt_oqsprovider_pem && !keytype->supports_oqsprovider_pem) {
        warnx("Option '--oqsprovider-pem' is not supported for keytype '%s'.",
              keytype->name);
        return CKR_ARGUMENTS_BAD;
    }

    if (keytype->export_asym_pkey != NULL &&
        (!keytype->supports_oqsprovider_pem ||
         (opt_oqsprovider_pem && keytype->supports_oqsprovider_pem))) {
        if (opt_encrypted_pem && !private) {
            warnx("Option '-e'/'--encrypted-pem' is specified but is ignored "
                  "for exporting %s key \"%s\".", typestr, label);
        }

        rc = keytype->export_asym_pkey(keytype, &pkey, private, key, label);
        if (rc != CKR_OK)
            goto done;

        cb_data.pem_file_name = opt_file;
        cb_data.pem_password = opt_pem_password;
        cb_data.env_var_name = PKCS11_PEM_PASSWORD_ENV_NAME;
        cb_data.force_prompt = opt_force_pem_pwd_prompt;

        if (private)
            ret = PEM_write_bio_PrivateKey(bio, pkey,
                                           opt_encrypted_pem ?
                                                   EVP_aes_256_cbc() : NULL,
                                           NULL, 0,
                                           p11tool_pem_password_cb, &cb_data);
        else
            ret = PEM_write_bio_PUBKEY(bio, pkey);
        if (ret != 1) {
            warnx("Failed to write %s key object \"%s\" to PEM file '%s'.",
                  typestr, label, opt_file);
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

    } else if (keytype->export_asym_pem_data != NULL) {
        if (opt_encrypted_pem) {
            warnx("Option '-e'/'--encrypted-pem' is specified but is ignored "
                  "for exporting %s key \"%s\".", typestr, label);
        }

        rc = keytype->export_asym_pem_data(keytype, &data, &data_len,
                                           private, key, label);
        if (rc != CKR_OK)
            goto done;

        ret = PEM_write_bio(bio, private ?
                                    keytype->pem_name_private :
                                    keytype->pem_name_public,
                            "", data, data_len);
        if (ret <= 0) {
            warnx("Failed to write %s key object \"%s\" to PEM file '%s'.",
                  typestr, label, opt_file);
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        warnx("No support for exporting %s key object \"%s\" to a PEM "
              "file '%s'", typestr, label, opt_file);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

done:
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (data != NULL) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }

    return rc;
}

static CK_RV p11sak_export_sym_key(const struct p11tool_objtype *keytype,
                                   CK_OBJECT_HANDLE key,
                                   const char *typestr, const char* label,
                                   BIO* bio)
{
    CK_BYTE *data = NULL;
    CK_ULONG data_len = 0;
    CK_RV rc;

    if (opt_encrypted_pem) {
        warnx("Option '-e'/'--encrypted-pem' is specified but is ignored for "
              "exporting %s key \"%s\".", typestr, label);
    }

    if (keytype->export_sym_clear == NULL) {
        warnx("No support for exporting %s key object \"%s\" to file '%s'",
              typestr, label, opt_file);
        return CKR_ARGUMENTS_BAD;
    }

    if (has_ibm_opaque_attr(key)) {
        warnx("%s key object \"%s\" contains an opaque secure key blob and "
              "can not be exported in clear.", typestr, label);
        warnx("Use option '-o'/'--opaque' to export the opaque secure key blob "
              "instead.");
        return CKR_KEY_UNEXTRACTABLE;
    }

    rc = keytype->export_sym_clear(keytype, &data, &data_len, key, label);
    if (rc != CKR_OK)
        goto done;

    if (BIO_write(bio, data, data_len) != (int)data_len) {
        warnx("Failed to write to file '%s'.", opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

done:
    if (data != NULL) {
        OPENSSL_cleanse(data, data_len);
        free(data);
    }

    return rc;
}

static CK_RV p11sak_key_extract_pubkey(const struct p11tool_objtype *keytype,
                                       CK_OBJECT_HANDLE key,
                                       const char *typestr, const char* label)
{
    CK_OBJECT_HANDLE pubkey;
    CK_ATTRIBUTE spki = { CKA_PUBLIC_KEY_INFO, NULL, 0 };
    CK_ATTRIBUTE id_attr = { CKA_ID, NULL, 0 };
    const unsigned char *p;
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    EVP_PKEY *pkey = NULL;
    char *pubkey_label = NULL;
    CK_OBJECT_CLASS key_class = CKO_PUBLIC_KEY;
    CK_BBOOL btrue = CK_TRUE;
    CK_RV rc;

    if (opt_new_attr != NULL) {
        rc = p11tool_parse_boolean_attrs(keytype, p11sak_bool_attrs,
                                         opt_new_attr, &attrs, &num_attrs,
                                         true, opt_so,
                                         p11tool_public_attr_applicable);
        if (rc != CKR_OK)
            goto done;

        if (num_attrs == 0) {
            warnx("None of the specified attributes apply to a public key object.");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }
    }

    if (opt_new_label != NULL) {
        rc = p11tool_add_attribute(CKA_LABEL, opt_new_label,
                                   strlen(opt_new_label), &attrs, &num_attrs);
        if (rc != CKR_OK) {
            warnx("Failed to add %s key attribute CKA_LABEL: 0x%lX: %s",
                  keytype->name, rc, p11_get_ckr(rc));
            goto done;
        }
    }

    if (opt_new_id != NULL) {
        rc = p11tool_parse_id(opt_new_id, &attrs, &num_attrs);
        if (rc != CKR_OK)
            goto done;
    }

    rc = p11tool_get_attribute(key, &spki);
    if (rc != CKR_OK) {
        warnx("Failed to retrieve attribute CKA_PUBLIC_KEY_INFO from %s key "
              "object \"%s\": 0x%lX: %s", typestr, label, rc, p11_get_ckr(rc));
        goto done;
    }

    if (keytype->import_asym_pem_data != NULL) {
        rc = keytype->import_asym_pem_data(keytype,
                                           (unsigned char *)spki.pValue,
                                           spki.ulValueLen, false,
                                           &attrs, &num_attrs);
    } else if (keytype->import_asym_pkey != NULL) {
        p = spki.pValue;
        pkey = d2i_PUBKEY(NULL, &p, spki.ulValueLen);
        if (pkey == NULL) {
            warnx("OpenSSL d2i_PUBKEY failed to get PKEY from SPKI.");
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        rc = keytype->import_asym_pkey(keytype, pkey, false,
                                       &attrs, &num_attrs);
    } else {
        warnx("No support for extracting %s public key", keytype->name);
        rc = CKR_ARGUMENTS_BAD;
    }
    if (rc != CKR_OK)
        goto done;

    /* If no new label parm specified, derive new label from key label */
    if (opt_new_label == NULL) {
        if (asprintf(&pubkey_label, "%s_pubkey", label) < 0 ||
            pubkey_label == NULL) {
            warnx("Failed to allocate memory for new public key label.");
            rc = CKR_HOST_MEMORY;
            goto done;
        }
        rc = p11tool_add_attribute(CKA_LABEL, pubkey_label,
                                   strlen(pubkey_label), &attrs, &num_attrs);
        if (rc != CKR_OK) {
            warnx("Failed to add attributes for extracted key's public key.");
            goto done;
        }
    }

    /* If no new ID is specified, try to use ID from certificate */
    if (opt_new_id == NULL) {
        rc = p11tool_get_attribute(key, &id_attr);
        if (rc == CKR_OK && id_attr.ulValueLen > 0) {
            rc = p11tool_add_attribute(CKA_ID, id_attr.pValue,
                                       id_attr.ulValueLen, &attrs, &num_attrs);
            if (rc != CKR_OK) {
                warnx("Failed to add attributes for extracted key's public key.");
                goto done;
            }
        }
    }

    rc = p11tool_add_attribute(CKA_CLASS, &key_class,
                               sizeof(CK_OBJECT_CLASS),
                               &attrs, &num_attrs);
    rc += p11tool_add_attribute(CKA_KEY_TYPE, &keytype->type,
                                sizeof(CK_KEY_TYPE),
                                &attrs, &num_attrs);
    rc += p11tool_add_attribute(CKA_TOKEN, &btrue, sizeof(CK_BBOOL),
                                &attrs, &num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add attributes for extracted key's public key.");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = p11tool_pkcs11_funcs->C_CreateObject(p11tool_pkcs11_session, attrs,
                                              num_attrs, &pubkey);
    if (rc != CKR_OK) {
       if (p11tool_is_rejected_by_policy(rc, p11tool_pkcs11_session))
           warnx("Public key extraction of a %s key is rejected by policy",
                 keytype->name);
       else
           warnx("Public key extraction of a %s key failed: 0x%lX: %s",
                 keytype->name, rc, p11_get_ckr(rc));
       goto done;
    }

done:
    p11tool_free_attributes(attrs, num_attrs);
    if (spki.pValue != NULL)
        free(spki.pValue);
    if (id_attr.pValue != NULL)
        free(id_attr.pValue);
    if (pkey != NULL)
        EVP_PKEY_free(pkey);
    if (pubkey_label != NULL)
        free(pubkey_label);

    return rc;
}

static CK_RV p11sak_cert_extract_pubkey(const struct p11tool_objtype *certtype,
                                        CK_OBJECT_HANDLE cert,
                                        const char *typestr, const char* label)
{
    CK_OBJECT_HANDLE pubkey;
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    CK_RV rc;

    UNUSED(typestr);

    if (opt_new_attr != NULL) {
        rc = p11tool_parse_boolean_attrs(certtype, p11sak_bool_attrs,
                                         opt_new_attr, &attrs, &num_attrs,
                                         true, opt_so,
                                         p11tool_public_attr_applicable);
        if (rc != CKR_OK)
            goto done;

        if (num_attrs == 0) {
            warnx("None of the specified attributes apply to a public key object.");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }
    }

    if (opt_new_label != NULL) {
        rc = p11tool_add_attribute(CKA_LABEL, opt_new_label,
                                   strlen(opt_new_label),
                                   &attrs, &num_attrs);
        if (rc != CKR_OK) {
            warnx("Failed to add %s key attribute CKA_LABEL: 0x%lX: %s",
                    certtype->name, rc, p11_get_ckr(rc));
            goto done;
        }
    }

    if (opt_new_id != NULL) {
        rc = p11tool_parse_id(opt_new_id, &attrs, &num_attrs);
        if (rc != CKR_OK)
            goto done;
    }

    rc = certtype->extract_x509_pubkey(certtype, &attrs, &num_attrs, cert,
                                       label);
    if (rc != CKR_OK) {
        warnx("Failed to extract public key from certificate object: 0x%lx: %s",
              rc, p11_get_ckr(rc));
        goto done;
    }

    rc = p11tool_pkcs11_funcs->C_CreateObject(p11tool_pkcs11_session, attrs,
                                              num_attrs, &pubkey);
    if (rc != CKR_OK) {
       if (p11tool_is_rejected_by_policy(rc, p11tool_pkcs11_session))
           warnx("Public key extraction of a %s certificate is rejected by "
                 "policy", certtype->name);
       else
           warnx("Public key extraction of a %s certificate failed: 0x%lX: %s",
                 certtype->name, rc, p11_get_ckr(rc));
       goto done;
    }

done:
    p11tool_free_attributes(attrs, num_attrs);

    return rc;
}

static CK_RV handle_key_export(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                               const struct p11tool_objtype *keytype,
                               CK_ULONG keysize, const char *typestr,
                               const char* label, const char *common_name,
                               void *private)
{
    struct p11sak_export_data *data = private;
    char *msg = NULL;
    BIO *bio;
    bool overwrite = false;
    char ch;
    CK_RV rc;

    UNUSED(keysize);
    UNUSED(common_name);

    if (data->skip_all) {
        data->num_skipped++;
        return CKR_OK;
    }

    if (!data->export_all) {
        if (asprintf(&msg, "Are you sure you want to export %s key object \"%s\" [y/n/a/c]? ",
                     typestr, label) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return CKR_HOST_MEMORY;
        }
        ch = p11tool_prompt_user(msg, "ynac");
        free(msg);

        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        case 'c':
        case '\0':
            data->skip_all = true;
            data->num_skipped++;
            return CKR_OK;
        case 'a':
            data->export_all = true;
            break;
        default:
            break;
        }
    }

    if (opt_spki && class != CKO_PRIVATE_KEY) {
        warnx("The '-S'/'--spki' option can only be used with private keys.");
        data->num_failed++;
        return CKR_OK;
    }

    if (opt_opaque && data->num_exported > 0) {
        printf("The last exported key was a binary opaque secure key blob, "
               "and the current\nkey is also to be exported as binary opaque "
               "secure key blob.\nIt can not be appended to the previously "
               "exported key(s).\n");
        overwrite = true;
    } else if (keytype->is_asymmetric) {
        if (data->last_was_binary) {
            printf("The last exported key was a binary symmetric key, but "
                   "the current\nkey is an asymmetric key to be exported in "
                   "PEM format.\nIt can not be appended to the previously "
                   "exported key(s).\n");
            overwrite = true;
        }
    } else {
        if (data->last_was_binary) {
            printf("The last exported key was a binary symmetric key, and "
                   "the current\nkey is also a symmetric key to be exported "
                   "in binary.\nIt can not be appended to the previously "
                   "exported key(s).\n");
            overwrite = true;
        } else if (data->last_was_pem) {
            printf("The last exported key was an asymmetric key in PEM "
                   "format, but the\ncurrent key is a symmetric key to be "
                   "exported in binary.\nIt can not be appended to the "
                   "previously exported key(s).\n");
            overwrite = true;
        }
    }
    if (overwrite && !opt_force) {
        ch = p11tool_prompt_user("Overwrite the previously exported "
                                 "key(s) [y/n]? ", "yn");
        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        default:
            break;
        }
    }

    bio = BIO_new_file(opt_file,
                       overwrite || data->num_exported == 0 ? "w" : "a");
    if (bio == NULL) {
        warnx("Failed to open PEM file '%s'.", opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        data->num_failed++;
        return CKR_ARGUMENTS_BAD;
    }

    if (opt_opaque)
        rc = p11sak_export_opaque_key(keytype, key, typestr, label, bio);
    else if (opt_spki)
        rc = p11sak_export_spki(keytype, key, typestr, label, bio);
    else if (opt_uri_pem)
        rc = p11sak_export_uri_pem(keytype, key, class, typestr, "key",
                                   label, bio);
    else if (keytype->is_asymmetric)
        rc = p11sak_export_asym_key(keytype, key, class == CKO_PRIVATE_KEY,
                                    typestr, label, bio);
    else
        rc = p11sak_export_sym_key(keytype, key, typestr, label, bio);
    if (rc != CKR_OK) {
        if (rc == CKR_ATTRIBUTE_SENSITIVE)
            warnx("%s key object \"%s\" is sensitive and can not be exported.",
                  typestr, label);

        data->num_failed++;
        rc = CKR_OK;
        goto done;
    }

    printf("Successfully exported %s key object \"%s\" to file '%s'.\n",
           typestr, label, opt_file);
    data->num_exported++;

    data->last_was_pem = (keytype->is_asymmetric && !opt_opaque) || opt_uri_pem;
    data->last_was_binary = (!keytype->is_asymmetric || opt_opaque) &&
                            !opt_uri_pem;

done:
    BIO_free(bio);

    return rc;
}

static CK_RV handle_key_pubkey_extract(CK_OBJECT_HANDLE cert,
                                       CK_OBJECT_CLASS class,
                                       const struct p11tool_objtype *keytype,
                                       CK_ULONG keysize, const char *typestr,
                                       const char* label,
                                       const char *common_name,
                                       void *private)
{
    struct p11sak_export_data *data = private;
    char *msg = NULL;
    char ch;
    CK_RV rc;

    UNUSED(keysize);
    UNUSED(common_name);

    if (class != CKO_PRIVATE_KEY)
        return CKR_OK;

    if (data->skip_all) {
        data->num_skipped++;
        return CKR_OK;
    }

    if (!data->export_all) {
        if (asprintf(&msg, "Are you sure you want to extract the public key from %s key object \"%s\" [y/n/a/c]? ",
                     typestr, label) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return CKR_HOST_MEMORY;
        }
        ch = p11tool_prompt_user(msg, "ynac");
        free(msg);

        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        case 'c':
        case '\0':
            data->skip_all = true;
            data->num_skipped++;
            return CKR_OK;
        case 'a':
            data->export_all = true;
            break;
        default:
            break;
        }
    }

    rc = p11sak_key_extract_pubkey(keytype, cert, typestr, label);
    if (rc != CKR_OK) {
        data->num_failed++;
        rc = CKR_OK;
        goto done;
    }

    if (opt_new_label != NULL)
        printf("Successfully extracted the public key from %s key object \"%s\" into new token object \"%s\".\n",
                typestr, label, opt_new_label);
    else
        printf("Successfully extracted the public key from %s key object \"%s\" into new token object \"%s_pubkey\".\n",
               typestr, label, label);
    data->num_exported++;

done:

    return rc;
}

static CK_RV handle_cert_export(CK_OBJECT_HANDLE cert, CK_OBJECT_CLASS class,
                                const struct p11tool_objtype *certtype,
                                CK_ULONG keysize, const char *typestr,
                                const char* label, const char *common_name,
                                void *private)
{
    struct p11sak_export_data *data = private;
    char *msg = NULL;
    BIO *bio = NULL;
    bool overwrite = false;
    char ch;
    CK_BYTE *cert_data = NULL;
    CK_ULONG data_len = 0;
    CK_RV rc;

    UNUSED(class);
    UNUSED(keysize);
    UNUSED(common_name);

    if (data->skip_all) {
        data->num_skipped++;
        return CKR_OK;
    }

    if (!data->export_all) {
        if (asprintf(&msg, "Are you sure you want to export %s certificate object \"%s\" [y/n/a/c]? ",
                     typestr, label) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return CKR_HOST_MEMORY;
        }
        ch = p11tool_prompt_user(msg, "ynac");
        free(msg);

        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        case 'c':
        case '\0':
            data->skip_all = true;
            data->num_skipped++;
            return CKR_OK;
        case 'a':
            data->export_all = true;
            break;
        default:
            break;
        }
    }

    if (opt_der && data->num_exported > 0) {
        printf("The last exported and current certificate are both in binary "
               "form.\nIt's not possible to write both into the same file.\n");
        overwrite = true;
    }

    if (overwrite && !opt_force) {
        ch = p11tool_prompt_user("Overwrite the previously exported "
                                 "certificate(s) [y/n]? ", "yn");
        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        default:
            break;
        }
    }

    bio = BIO_new_file(opt_file,
                       overwrite || data->num_exported == 0 ? "w" : "a");
    if (bio == NULL) {
        warnx("Failed to open output file '%s'.", opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        data->num_failed++;
        return CKR_ARGUMENTS_BAD;
    }

    if (opt_uri_pem) {
        rc = p11sak_export_uri_pem(certtype, cert, class, typestr,
                                   "certificate", label, bio);
        if (rc != CKR_OK) {
            warnx("Failed to export certificate object into URI-PEM file, "
                  "0x%lx: %s", rc, p11_get_ckr(rc));
            data->num_failed++;
            rc = CKR_OK;
            goto done;
        }
        goto finish;
    }

    rc = certtype->export_x509_data(certtype, &cert_data, &data_len, cert, label);
    if (rc != CKR_OK) {
        warnx("Failed to export certificate object into X509 object, 0x%lx: %s",
              rc, p11_get_ckr(rc));
        data->num_failed++;
        rc = CKR_OK;
        goto done;
    }

    if (BIO_write(bio, cert_data, data_len) != (int)data_len) {
        warnx("Failed to write to file '%s'.", opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        data->num_failed++;
        rc = CKR_OK;
        goto done;
    }

finish:
    printf("Successfully exported %s certificate object \"%s\" to file '%s'.\n",
           typestr, label, opt_file);
    data->num_exported++;

    data->last_was_pem = !opt_der || opt_uri_pem;
    data->last_was_binary = opt_der && !opt_uri_pem;

done:
    free(cert_data);
    if (bio != NULL)
        BIO_free(bio);

    return rc;
}

static CK_RV handle_cert_pubkey_extract(CK_OBJECT_HANDLE cert,
                                        CK_OBJECT_CLASS class,
                                        const struct p11tool_objtype *certtype,
                                        CK_ULONG keysize, const char *typestr,
                                        const char* label,
                                        const char *common_name,
                                        void *private)
{
    struct p11sak_export_data *data = private;
    char *msg = NULL;
    char ch;
    CK_RV rc;

    UNUSED(class);
    UNUSED(keysize);
    UNUSED(common_name);

    if (data->skip_all) {
        data->num_skipped++;
        return CKR_OK;
    }

    if (!data->export_all) {
        if (asprintf(&msg, "Are you sure you want to extract the public key from %s certificate object \"%s\" [y/n/a/c]? ",
                     typestr, label) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return CKR_HOST_MEMORY;
        }
        ch = p11tool_prompt_user(msg, "ynac");
        free(msg);

        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        case 'c':
        case '\0':
            data->skip_all = true;
            data->num_skipped++;
            return CKR_OK;
        case 'a':
            data->export_all = true;
            break;
        default:
            break;
        }
    }

    rc = p11sak_cert_extract_pubkey(certtype, cert, typestr, label);
    if (rc != CKR_OK) {
        data->num_failed++;
        rc = CKR_OK;
        goto done;
    }

    if (opt_new_label != NULL)
        printf("Successfully extracted the public key from %s certificate object \"%s\" into new token object \"%s\".\n",
                typestr, label, opt_new_label);
    else
        printf("Successfully extracted the public key from %s certificate object \"%s\" into new token object \"%s_pubkey\".\n",
               typestr, label, label);
    data->num_exported++;

done:

    return rc;
}

static CK_RV p11sak_create_uri_pin_source(const char *pin_source,
                                          const char *pin)
{
    FILE *fp;
    CK_RV rc = CKR_OK;

    fp = fopen(pin_source, "w");
    if (fp == NULL) {
        warnx("Failed to open pin-source file '%s' for writing: %s",
              pin_source, strerror(errno));
        return CKR_ARGUMENTS_BAD;
    }

    if (fchmod(fileno(fp), S_IRUSR | S_IWUSR) != 0) {
        warnx("Failed to set permissions of pin-source file '%s': %s",
              pin_source, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

    if (fprintf(fp, "%s\n", pin) <= 0) {
        warnx("Failed to write to pin-source file '%s': %s",
              pin_source, strerror(errno));
        rc = CKR_FUNCTION_FAILED;
        goto out;
    }

out:
    fclose(fp);

    if (rc == CKR_OK) {
        printf("Successfully wrote PKCS#11 user PIN into '%s'.\n", pin_source);
        printf("Adjust the file permissions of that file so that it can only "
               "be read by the desired user(s).\n");
    }

    return rc;
}

static CK_RV p11sak_export_key(void)
{
    const struct p11tool_objtype *keytype = NULL;
    struct p11sak_export_data data = { 0 };
    CK_RV rc;

    if (opt_keytype != NULL)
        keytype = opt_keytype->private.ptr;

    data.export_all = opt_force;

    if ((opt_opaque && opt_spki) || (opt_opaque && opt_uri_pem) ||
        (opt_spki && opt_uri_pem)) {
        warnx("Either '-o'/'--opaque', '-S'/'--spki', or '-u'/'--uri-pem' can "
              "be specified.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_value && !opt_uri_pem) {
        warnx("Option '--uri-pin-value' can only be specified together with "
              "the '-u'/'--uri-pem' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_value && opt_no_login) {
        warnx("Option '--uri-pin-value' can not be specified together with "
              "the '-N'/'--no_login' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_value && opt_so) {
        warnx("Option '--uri-pin-value' can not be specified together with "
              "the '--so' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_source != NULL && !opt_uri_pem) {
        warnx("Option '--uri-pin-source' can only be specified together with "
              "the '-u'/'--uri-pem' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_source != NULL && opt_no_login) {
        warnx("Option '--uri-pin-source' can not be specified together with "
              "the '-N'/'--no_login' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_source != NULL && opt_so) {
        warnx("Option '--uri-pin-source' can not be specified together with "
              "the '--so' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_encrypted_pem && (opt_spki || opt_opaque || opt_uri_pem)) {
        warnx("Option '-e'/'--encrypted-pem' can not be specified together "
               "with the '-o'/'--opaque', '-S'/'--spki', or '-u'/'--uri-pem' "
               "options");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_pem_password != NULL && !opt_encrypted_pem) {
        warnx("Option '-P'/'--pem-password' can only be specified together "
              "with the '-e'/'--encrypted-pem' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_force_pem_pwd_prompt && !opt_encrypted_pem) {
        warnx("Option '--force-pem-pwd-prompt' can only be specified together "
              "with the '-e'/'--encrypted-pem' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_oqsprovider_pem &&
        keytype != NULL && !keytype->supports_oqsprovider_pem) {
        warnx("Option '--oqsprovider-pem' is not supported for keytype '%s'.",
              keytype->name);
        return CKR_ARGUMENTS_BAD;
    }

    rc = iterate_objects(keytype, opt_label, opt_id, opt_attr,
                         OBJCLASS_KEY, NULL,
                         handle_key_export, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over key objects for key type %s: 0x%lX: %s",
                keytype != NULL ? keytype->name : "All", rc, p11_get_ckr(rc));
        return rc;
    }

    if (opt_uri_pem && opt_uri_pin_source != NULL && p11tool_pin != NULL &&
        data.num_exported > 0) {
        rc = p11sak_create_uri_pin_source(opt_uri_pin_source, p11tool_pin);
        return rc;
    }

    printf("%lu key object(s) exported.\n", data.num_exported);
    if (data.num_skipped > 0)
        printf("%lu key object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu key object(s) failed to export.\n", data.num_failed);

    return data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV p11sak_extract_key_pubkey(void)
{
    const struct p11tool_objtype *keytype = NULL;
    struct p11sak_export_data data = { 0 };
    CK_RV rc;

    if (opt_keytype != NULL)
        keytype = opt_keytype->private.ptr;

    data.export_all = opt_force;

    rc = iterate_objects(keytype, opt_label, opt_id, opt_attr,
                         OBJCLASS_KEY, NULL,
                         handle_key_pubkey_extract, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over key objects for type %s: 0x%lX: %s",
              keytype != NULL ? keytype->name : "All", rc, p11_get_ckr(rc));
        return rc;
    }

    printf("%lu public key object(s) extracted.\n", data.num_exported);
    if (data.num_skipped > 0)
        printf("%lu private key object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu private key object(s) failed to export the public key.\n",
               data.num_failed);

    return data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV p11sak_export_cert(void)
{
    const struct p11tool_objtype *certtype = NULL;
    struct p11sak_export_data data = { 0 };
    CK_RV rc;

    if (opt_certtype != NULL)
        certtype = opt_certtype->private.ptr;

    data.export_all = opt_force;

    if (opt_der && opt_uri_pem) {
        warnx("Either '-D'/'--der' or '-u'/'--uri-pem' can be specified.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_value && !opt_uri_pem) {
        warnx("Option '--uri-pin-value' can only be specified together with "
              "the '-u'/'--uri-pem' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_value && opt_no_login) {
        warnx("Option '--uri-pin-value' can not be specified together with "
              "the '-N'/'--no_login' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_value && opt_so) {
        warnx("Option '--uri-pin-value' can not be specified together with "
              "the '--so' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_source != NULL && !opt_uri_pem) {
        warnx("Option '--uri-pin-source' can only be specified together with "
              "the '-u'/'--uri-pem' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_source != NULL && opt_no_login) {
        warnx("Option '--uri-pin-source' can not be specified together with "
              "the '-N'/'--no_login' option.");
        return CKR_ARGUMENTS_BAD;
    }
    if (opt_uri_pin_source != NULL && opt_so) {
        warnx("Option '--uri-pin-source' can not be specified together with "
              "the '--so' option.");
        return CKR_ARGUMENTS_BAD;
    }

    rc = iterate_objects(certtype, opt_label, opt_id, opt_attr,
                         OBJCLASS_CERTIFICATE, NULL,
                         handle_cert_export, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over certificate objects for type %s: 0x%lX: %s",
                certtype != NULL ? certtype->name : "All", rc, p11_get_ckr(rc));
        return rc;
    }

    if (opt_uri_pem && opt_uri_pin_source != NULL && p11tool_pin != NULL &&
        data.num_exported > 0) {
        rc = p11sak_create_uri_pin_source(opt_uri_pin_source, p11tool_pin);
        return rc;
    }

    printf("%lu certificate object(s) exported.\n", data.num_exported);
    if (data.num_skipped > 0)
        printf("%lu certificate object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu certificate object(s) failed to export.\n", data.num_failed);

    return data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV p11sak_import_cert(void)
{
    const struct p11tool_objtype *certtype;
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    CK_OBJECT_CLASS class;
    CK_OBJECT_HANDLE cert;
    CK_RV rc;
    X509 *x509 = NULL;
    CK_CERTIFICATE_CATEGORY cert_category;

    if (opt_certtype == NULL || opt_certtype->private.ptr == NULL)
        return CKR_ARGUMENTS_BAD;

    certtype = opt_certtype->private.ptr;

    rc = p11sak_x509_from_pem_file(&x509);
    switch (rc) {
    case CKR_OK:
        break;
    case CKR_ARGUMENTS_BAD:
        return rc;
    default:
        rc = p11sak_x509_from_der_file(&x509);
        if (rc != CKR_OK)
            return rc;
        break;
    }

    class = CKO_CERTIFICATE;
    rc = p11tool_add_attribute(CKA_CLASS, &class, sizeof(class),
                               &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_add_attributes(certtype, p11sak_bool_attrs, &attrs, &num_attrs,
                                opt_label, opt_attr, opt_id, FALSE, opt_so,
                                NULL, NULL, p11tool_cert_attr_applicable);
    if (rc != CKR_OK)
        goto done;

    /*
     * Set CA-cert attribute dependent on input option or BasicConstraints CA
     * flag of the certificate
     */
    if (opt_cacert ||
        (X509_get_extension_flags(x509) & EXFLAG_CA) != 0) {
        cert_category = CK_CERTIFICATE_CATEGORY_AUTHORITY;
        rc = p11tool_add_attribute(CKA_CERTIFICATE_CATEGORY, &cert_category,
                                   sizeof(CK_CERTIFICATE_CATEGORY),
                                   &attrs, &num_attrs);
        if (rc != CKR_OK) {
            warnx("Failed to add %s attribute CKA_CERTIFICATE_CATEGORY: 0x%lX: %s",
                  certtype->name, rc, p11_get_ckr(rc));
            goto done;
        }
    }

    /* Set common attributes for all types of certificates */
    rc = p11sak_import_cert_attrs(certtype, x509, &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    /* Set attributes dependent on certificate type */
    if (certtype->import_x509_data != NULL) {
        rc = certtype->import_x509_data(certtype, x509, &attrs, &num_attrs);
        if (rc != CKR_OK)
            goto done;
    }

    rc = p11tool_pkcs11_funcs->C_CreateObject(p11tool_pkcs11_session, attrs,
                                              num_attrs, &cert);
    if (rc != CKR_OK) {
       if (p11tool_is_rejected_by_policy(rc, p11tool_pkcs11_session))
           warnx("Certificate import of a %s certificate is rejected by policy",
                 certtype->name);
       else
           warnx("Certificate import of a %s certificate failed: 0x%lX: %s",
                 certtype->name, rc, p11_get_ckr(rc));
       goto done;
    }

    printf("Successfully imported a %s certificate with label \"%s\".\n",
           certtype->name, opt_label);

done:
    p11tool_free_attributes(attrs, num_attrs);
    X509_free(x509);

    return rc;
}

static CK_RV p11sak_extract_cert_pubkey(void)
{
    const struct p11tool_objtype *certtype = NULL;
    struct p11sak_export_data data = { 0 };
    CK_RV rc;

    if (opt_certtype != NULL)
        certtype = opt_certtype->private.ptr;

    data.export_all = opt_force;

    rc = iterate_objects(certtype, opt_label, opt_id, opt_attr,
                         OBJCLASS_CERTIFICATE, NULL,
                         handle_cert_pubkey_extract, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over certificate objects for type %s: 0x%lX: %s",
                certtype != NULL ? certtype->name : "All", rc, p11_get_ckr(rc));
        return rc;
    }

    printf("%lu public key object(s) extracted.\n", data.num_exported);
    if (data.num_skipped > 0)
        printf("%lu certificate object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu certificate object(s) failed to export the public key.\n", data.num_failed);

    return data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static void parse_config_file_error_hook(int line, int col, const char *msg)
{
  warnx("Parse error: %d:%d: %s", line, col, msg);
}

static CK_RV parse_config_file(void)
{
    FILE *fp = NULL;
    char *file_loc = getenv(P11SAK_DEFAULT_CONF_FILE_ENV_NAME);
    char pathname[PATH_MAX];
    struct passwd *pw;

    if (file_loc != NULL) {
        fp = fopen(file_loc, "r");
        if (fp == NULL) {
            warnx("Cannot read config file '%s' (specified via env variable %s): %s",
                  file_loc, P11SAK_DEFAULT_CONF_FILE_ENV_NAME, strerror(errno));
            warnx("Printing of custom attributes not available.");
            return CKR_OK;
        }
    } else {
        pw = getpwuid(geteuid());
        if (pw != NULL) {
            snprintf(pathname, sizeof(pathname), "%s/.%s", pw->pw_dir,
                     P11SAK_CONFIG_FILE_NAME);
            file_loc = pathname;
            fp = fopen(file_loc, "r");
        }
        if (fp == NULL) {
            file_loc = P11SAK_DEFAULT_CONFIG_FILE;
            fp = fopen(file_loc, "r");
            if (fp == NULL) {
                warnx("Cannot read config file '%s': %s",
                       file_loc, strerror(errno));
                warnx("Printing of custom attributes not available.");
                return CKR_OK;
            }
        }
    }

    if (parse_configlib_file(fp, &p11sak_cfg,
                             parse_config_file_error_hook, 0)) {
        warnx("Failed to parse config file '%s'", file_loc);
        fclose(fp);
        return CKR_DATA_INVALID;
    }

    fclose(fp);

    return CKR_OK;
}

int main(int argc, char *argv[])
{
    const struct p11tool_cmd *command = NULL;
    CK_RV rc = CKR_OK;

    /* Get p11sak command (if any) */
    if (argc >= 2 && strncmp(argv[1], "-", 1) != 0) {
        command = p11tool_find_command(p11sak_commands, argv[1]);
        if (command == NULL) {
            warnx("Invalid command '%s'", argv[1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        argc--;
        argv = &argv[1];
    }

    /* Get command arguments (if any) */
    rc = p11tool_parse_cmd_arguments(command, &argc, &argv);
    if (rc != CKR_OK)
        goto done;

    /* Get generic and command specific options (if any) */
    rc = p11tool_parse_cmd_options(command, p11sak_generic_opts, argc, argv);
    if (rc != CKR_OK)
        goto done;

    if (opt_help) {
        if (command == NULL)
            p11tool_print_help("p11sak", p11sak_commands, p11sak_generic_opts,
                               PRINT_INDENT_POS);
        else
            p11tool_print_command_help("p11sak", command, p11sak_generic_opts,
                                       PRINT_INDENT_POS);
        goto done;
    }

    if (opt_version) {
        p11tool_print_version("p11sak");
        goto done;
    }

    if (command == NULL) {
        warnx("A command is required. Use '-h'/'--help' to see the list of "
              "supported commands");
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    rc = p11tool_check_required_args(command->args);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_check_required_cmd_opts(command->opts, command->args,
                                         p11sak_generic_opts);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_init_pkcs11(command, opt_no_login, opt_pin,
                             opt_force_pin_prompt, opt_so,
                             opt_uri_pem && (opt_uri_pin_value ||
                                             opt_uri_pin_source != NULL),
                             opt_slot, p11sak_known_tokens);
    if (rc != CKR_OK)
        goto done;

    rc = parse_config_file();
    if (rc != CKR_OK)
        goto done;

    /* Run the command */
    rc = command->func();
    if (rc != CKR_OK) {
        warnx("Failed to perform the '%s' command: %s", command->cmd,
              p11_get_ckr(rc));
        goto done;
    }

done:
    p11tool_term_pkcs11();

    if (p11sak_cfg != NULL)
        confignode_deepfree(p11sak_cfg);

    return rc;
}
