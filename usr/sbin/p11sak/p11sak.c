/*
 * COPYRIGHT (c) International Business Machines Corp. 2001-2022
 *
 * This program is provided under the terms of the Common Public License,
 * version 1.0 (CPL-1.0). Any use, reproduction or distribution for this
 * software constitutes recipient's acceptance of CPL-1.0 terms which can be
 * found in the file LICENSE file or at
 * https://opensource.org/licenses/cpl1.0.php
 */

#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>
#include <stdbool.h>
#include <unistd.h>
#include <getopt.h>
#include <err.h>
#include <limits.h>
#include <dlfcn.h>
#include <pwd.h>
#include <ctype.h>
#include <fnmatch.h>

#include <openssl/obj_mac.h>
#include <openssl/evp.h>
#include <openssl/dh.h>
#include <openssl/dsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>

#define P11SAK_DECLARE_CURVES
#include "p11sak.h"
#include "p11util.h"
#include "pin_prompt.h"
#include "cfgparser.h"
#include "configuration.h"
#include "mechtable.h"
#include "defs.h"
#include "uri.h"

#if OPENSSL_VERSION_PREREQ(3, 0)
#include <openssl/core_names.h>
#include <openssl/decoder.h>
#endif

static CK_RV p11sak_generate_key(void);
static CK_RV p11sak_list_key(void);
static CK_RV p11sak_remove_key(void);
static CK_RV p11sak_set_key_attr(void);
static void print_generate_key_attr_help(void);
static void print_list_key_attr_help(void);
static void print_set_key_attr_help(void);

static void *pkcs11_lib = NULL;
static bool pkcs11_initialized = false;
static CK_FUNCTION_LIST *pkcs11_funcs = NULL;
static CK_SESSION_HANDLE pkcs11_session = CK_INVALID_HANDLE;
static CK_INFO pkcs11_info;
static CK_TOKEN_INFO pkcs11_tokeninfo;
static CK_SLOT_INFO pkcs11_slotinfo;

static struct ConfigBaseNode *p11sak_cfg = NULL;

static bool opt_help = false;
static bool opt_version = false;
static CK_SLOT_ID opt_slot = (CK_SLOT_ID)-1;
static char *opt_pin = NULL;
static bool opt_force_pin_prompt = false;
static struct p11sak_enum_value *opt_keytype = NULL;
static CK_ULONG opt_keybits_num = 0;
static struct p11sak_enum_value *opt_keybits = NULL;
static struct p11sak_enum_value *opt_group = NULL;
static char *opt_pem_file = NULL;
static struct p11sak_enum_value *opt_curve = NULL;
static struct p11sak_enum_value *opt_pqc_version = NULL;
static char *opt_label = NULL;
static bool opt_force = false;
static CK_ULONG opt_exponent = 0;
static char *opt_attr = NULL;
static char *opt_id = NULL;
static bool opt_long = false;
static bool opt_detailed_uri = false;
static char *opt_sort = NULL;
static char *opt_new_attr = NULL;
static char *opt_new_label = NULL;
static char *opt_new_id = NULL;

static bool opt_slot_is_set(const struct p11sak_arg *arg);
static CK_RV generic_get_key_size(const struct p11sak_keytype *keytype,
                                  void *private, CK_ULONG *keysize);
static CK_RV generic_add_secret_attrs(const struct p11sak_keytype *keytype,
                                      CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                      void *private);
static CK_ULONG generic_keysize_adjust(const struct p11sak_keytype *keytype,
                                       CK_ULONG keysize);
static CK_RV aes_get_key_size(const struct p11sak_keytype *keytype,
                              void *private, CK_ULONG *keysize);
static CK_RV aes_add_secret_attrs(const struct p11sak_keytype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private);
static CK_ULONG aes_keysize_adjust(const struct p11sak_keytype *keytype,
                                   CK_ULONG keysize);
static CK_ULONG aes_xts_keysize_adjust(const struct p11sak_keytype *keytype,
                                       CK_ULONG keysize);
static CK_ULONG rsa_keysize_adjust(const struct p11sak_keytype *keytype,
                                   CK_ULONG keysize);
static CK_ULONG dh_keysize_adjust(const struct p11sak_keytype *keytype,
                                  CK_ULONG keysize);
static CK_ULONG dsa_keysize_adjust(const struct p11sak_keytype *keytype,
                                   CK_ULONG keysize);
static CK_RV rsa_get_key_size(const struct p11sak_keytype *keytype,
                              void *private, CK_ULONG *keysize);
static CK_RV rsa_add_public_attrs(const struct p11sak_keytype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private);
static CK_RV ec_get_key_size(const struct p11sak_keytype *keytype,
                             void *private, CK_ULONG *keysize);
static CK_RV ec_add_public_attrs(const struct p11sak_keytype *keytype,
                                 CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                 void *private);
static CK_RV dh_prepare(const struct p11sak_keytype *keytype, void **private);
static void dh_cleanup(const struct p11sak_keytype *keytype, void *private);
static CK_RV dh_get_key_size(const struct p11sak_keytype *keytype,
                             void *private, CK_ULONG *keysize);
static CK_RV dh_add_public_attrs(const struct p11sak_keytype *keytype,
                                 CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                 void *private);
static CK_RV dh_add_private_attrs(const struct p11sak_keytype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private);
static CK_RV dsa_prepare(const struct p11sak_keytype *keytype, void **private);
static void dsa_cleanup(const struct p11sak_keytype *keytype, void *private);
static CK_RV dsa_get_key_size(const struct p11sak_keytype *keytype,
                              void *private, CK_ULONG *keysize);
static CK_RV dsa_add_public_attrs(const struct p11sak_keytype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private);
static CK_RV ibm_dilithium_add_public_attrs(const struct p11sak_keytype *keytype,
                                            CK_ATTRIBUTE **attrs,
                                            CK_ULONG *num_attrs,
                                            void *private);
static CK_RV ibm_kyber_add_public_attrs(const struct p11sak_keytype *keytype,
                                        CK_ATTRIBUTE **attrs,
                                        CK_ULONG *num_attrs,
                                        void *private);

static void print_bool_attr_short(const CK_ATTRIBUTE *val, bool applicable);
static void print_bool_attr_long(const char *attr, const CK_ATTRIBUTE *val,
                                 int indent, bool sensitive);
static void print_utf8_attr(const char *attr, const CK_ATTRIBUTE *val,
                            int indent, bool sensitive);
static void print_byte_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive);
static void print_ulong_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive);
static void print_date_attr(const char *attr, const CK_ATTRIBUTE *val,
                            int indent, bool sensitive);
static void print_mech_attr(const char *attr, const CK_ATTRIBUTE *val,
                            int indent, bool sensitive);
static void print_mech_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive);
static void print_attr_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive);
static void print_class_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive);
static void print_key_type_attr(const char *attr, const CK_ATTRIBUTE *val,
                                int indent, bool sensitive);
static void print_oid_attr(const char *attr, const CK_ATTRIBUTE *val,
                           int indent, bool sensitive);
static void print_ibm_dilithium_keyform_attr(const char *attr,
                                             const CK_ATTRIBUTE *val,
                                             int indent, bool sensitive);
static void print_ibm_kyber_keyform_attr(const char *attr,
                                         const CK_ATTRIBUTE *val,
                                         int indent, bool sensitive);

#define DECLARE_KEY_ATTRS                                                      \
    { .name = "CKA_LABEL", .type = CKA_LABEL,                                  \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = print_utf8_attr, },                                        \
    { .name = "CKA_CLASS", .type = CKA_CLASS,                                  \
      .secret = true, .public = true, .private = true, .settable = false,      \
      .print_long = print_class_attr, },                                       \
    { .name = "CKA_KEY_TYPE", .type = CKA_KEY_TYPE,                            \
      .secret = true, .public = true, .private = true, .settable = false,      \
      .print_long = print_key_type_attr, },                                    \
    { .name = "CKA_ID", .type = CKA_ID,                                        \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_START_DATE", .type = CKA_START_DATE,                        \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = print_date_attr, },                                        \
    { .name = "CKA_END_DATE", .type = CKA_END_DATE,                            \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = print_date_attr, },                                        \
    { .name = "CKA_KEY_GEN_MECHANISM", .type = CKA_KEY_GEN_MECHANISM,          \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = print_mech_attr, },                                        \
    { .name = "CKA_ALLOWED_MECHANISMS", .type = CKA_ALLOWED_MECHANISMS,        \
      .secret = true, .public = true, .private = true, .settable = true,       \
      .print_long = print_mech_array_attr, }

#define DECLARE_SECRET_KEY_ATTRS                                               \
    { .name = "CKA_CHECK_VALUE", .type = CKA_CHECK_VALUE,                      \
      .secret = true, .public = false, .private = false, .settable = true,     \
      .print_long = print_byte_array_attr, },                                  \
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
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_WRAP_TEMPLATE", .type = CKA_WRAP_TEMPLATE,                  \
      .secret = true, .public = true, .private = false, .settable = true,      \
      .print_long = print_attr_array_attr, },                                  \
    { .name = "CKA_PUBLIC_KEY_INFO", .type = CKA_PUBLIC_KEY_INFO,              \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, }

#define DECLARE_PRIVATE_KEY_ATTRS                                              \
    { .name = "CKA_SUBJECT", .type = CKA_SUBJECT,                              \
      .secret = true, .public = false, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_UNWRAP_TEMPLATE", .type = CKA_UNWRAP_TEMPLATE,              \
      .secret = true, .public = false, .private = true, .settable = true,      \
      .print_long = print_attr_array_attr, },                                  \
    { .name = "CKA_PUBLIC_KEY_INFO", .type = CKA_PUBLIC_KEY_INFO,              \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_DERIVE_TEMPLATE", .type = CKA_DERIVE_TEMPLATE,              \
      .secret = true, .public = false, .private = true, .settable = true,      \
      .print_long = print_attr_array_attr, }

static const struct p11sak_attr p11sak_des_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_SECRET_KEY_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11sak_attr p11sak_3des_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_SECRET_KEY_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11sak_attr p11sak_generic_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_SECRET_KEY_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_VALUE_LEN", .type = CKA_VALUE_LEN,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = print_ulong_attr, },
    { .name = NULL },
};

static const struct p11sak_attr p11sak_aes_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_SECRET_KEY_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_VALUE_LEN", .type = CKA_VALUE_LEN,
      .secret = true, .public = false, .private = false, .settable = true,
      .print_long = print_ulong_attr, },
    { .name = NULL },
};

#define DECLARE_PUBLIC_RSA_ATTRS                                               \
    { .name = "CKA_MODULUS", .type = CKA_MODULUS,                              \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_MODULUS_BITS", .type = CKA_MODULUS_BITS,                    \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_ulong_attr, },                                       \
    { .name = "CKA_PUBLIC_EXPONENT", .type = CKA_PUBLIC_EXPONENT,              \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, }

static const struct p11sak_attr p11sak_public_rsa_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_PUBLIC_RSA_ATTRS,
    { .name = NULL },
};

static const struct p11sak_attr p11sak_private_rsa_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_PUBLIC_RSA_ATTRS,
    { .name = "CKA_PRIVATE_EXPONENT", .type = CKA_PRIVATE_EXPONENT,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_PRIME_1", .type = CKA_PRIME_1,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_PRIME_2", .type = CKA_PRIME_2,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_EXPONENT_1", .type = CKA_EXPONENT_1,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_EXPONENT_2", .type = CKA_EXPONENT_2,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_COEFFICIENT", .type = CKA_COEFFICIENT,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = NULL },
};

#define DECLARE_DH_ATTRS                                                       \
    { .name = "CKA_PRIME", .type = CKA_PRIME,                                  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_BASE", .type = CKA_BASE,                                    \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_VALUE", .type = CKA_VALUE,                                  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, }

static const struct p11sak_attr p11sak_public_dh_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_DH_ATTRS,
    { .name = NULL },
};

static const struct p11sak_attr p11sak_private_dh_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_DH_ATTRS,
    { .name = "CKA_VALUE_BITS", .type = CKA_VALUE_BITS,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_ulong_attr, },
    { .name = NULL },
};

#define DECLARE_DSA_ATTRS                                                      \
    { .name = "CKA_PRIME", .type = CKA_PRIME,                                  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_SUBPRIME", .type = CKA_SUBPRIME,                            \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_BASE", .type = CKA_BASE,                                    \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_VALUE", .type = CKA_VALUE,                                  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, }

static const struct p11sak_attr p11sak_public_dsa_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_DSA_ATTRS,
    { .name = NULL },
};

static const struct p11sak_attr p11sak_private_dsa_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_DSA_ATTRS,
    { .name = NULL },
};

#define DECLARE_EC_ATTRS                                                       \
    { .name = "CKA_EC_PARAMS", .type = CKA_EC_PARAMS,                          \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_oid_attr, }

static const struct p11sak_attr p11sak_public_ec_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_EC_ATTRS,
    { .name = "CKA_EC_POINT", .type = CKA_EC_POINT,
      .secret = false, .public = true, .private = false, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11sak_attr p11sak_private_ec_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_EC_ATTRS,
    { .name = "CKA_VALUE", .type = CKA_VALUE,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = NULL },
};

#define DECLARE_PUBLIC_IBM_DILITHIUM_ATTRS                                     \
    { .name = "CKA_IBM_DILITHIUM_KEYFORM", .type = CKA_IBM_DILITHIUM_KEYFORM,  \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_ibm_dilithium_keyform_attr, },                       \
    { .name = "CKA_IBM_DILITHIUM_MODE", .type = CKA_IBM_DILITHIUM_MODE,        \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_oid_attr, },                                         \
    { .name = "CKA_IBM_DILITHIUM_RHO", .type = CKA_IBM_DILITHIUM_RHO,          \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, },                                  \
    { .name = "CKA_IBM_DILITHIUM_T1", .type = CKA_IBM_DILITHIUM_T1,            \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, }

static const struct p11sak_attr p11sak_public_ibm_dilithium_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_PUBLIC_IBM_DILITHIUM_ATTRS,
    { .name = NULL },
};

static const struct p11sak_attr p11sak_private_ibm_dilithium_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_PUBLIC_IBM_DILITHIUM_ATTRS,
    { .name = "CKA_IBM_DILITHIUM_SEED", .type = CKA_IBM_DILITHIUM_SEED,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_IBM_DILITHIUM_TR", .type = CKA_IBM_DILITHIUM_TR,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_IBM_DILITHIUM_S1", .type = CKA_IBM_DILITHIUM_S1,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_IBM_DILITHIUM_S2", .type = CKA_IBM_DILITHIUM_S2,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = "CKA_IBM_DILITHIUM_T0", .type = CKA_IBM_DILITHIUM_T0,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = NULL },
};

#define DECLARE_PUBLIC_IBM_KYBER_ATTRS                                         \
    { .name = "CKA_IBM_KYBER_KEYFORM", .type = CKA_IBM_KYBER_KEYFORM,          \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_ibm_kyber_keyform_attr, },                           \
    { .name = "CKA_IBM_KYBER_MODE", .type = CKA_IBM_KYBER_MODE,                \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_oid_attr, },                                         \
    { .name = "CKA_IBM_KYBER_PK", .type = CKA_IBM_KYBER_PK,                    \
      .secret = false, .public = true, .private = true, .settable = true,      \
      .print_long = print_byte_array_attr, }

static const struct p11sak_attr p11sak_public_ibm_kyber_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PUBLIC_KEY_ATTRS,
    DECLARE_PUBLIC_IBM_KYBER_ATTRS,
    { .name = NULL },
};

static const struct p11sak_attr p11sak_private_ibm_kyber_attrs[] = {
    DECLARE_KEY_ATTRS,
    DECLARE_PRIVATE_KEY_ATTRS,
    DECLARE_PUBLIC_IBM_KYBER_ATTRS,
    { .name = "CKA_IBM_KYBER_SK", .type = CKA_IBM_KYBER_SK,
      .secret = false, .public = false, .private = true, .settable = true,
      .print_long = print_byte_array_attr, },
    { .name = NULL },
};

static const struct p11sak_keytype p11sak_des_keytype = {
    .name = "DES", .type = CKK_DES, .ckk_name = "CKK_DES",
    .keygen_mech = { .mechanism = CKM_DES_KEY_GEN, },
    .is_asymmetric = false,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_DES,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .secret_attrs = p11sak_des_attrs,
};

static const struct p11sak_keytype p11sak_3des_keytype = {
    .name = "3DES",  .type = CKK_DES3, .ckk_name = "CKK_DES3",
    .keygen_mech = { .mechanism = CKM_DES3_KEY_GEN, },
    .is_asymmetric = false,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_DES3,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .secret_attrs = p11sak_3des_attrs,
};

static const struct p11sak_keytype p11sak_generic_keytype = {
    .name = "GENERIC",  .type = CKK_GENERIC_SECRET,
    .ckk_name = "CKK_GENERIC_SECRET",
    .keygen_mech = { .mechanism = CKM_GENERIC_SECRET_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = generic_get_key_size,
    .keygen_add_secret_attrs = generic_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_GENERIC_SECRET,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = generic_keysize_adjust,
    .secret_attrs = p11sak_generic_attrs,
};

static const struct p11sak_keytype p11sak_aes_keytype = {
    .name = "AES",  .type = CKK_AES, .ckk_name = "CKK_AES",
    .keygen_mech = { .mechanism = CKM_AES_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = aes_get_key_size,
    .keygen_add_secret_attrs = aes_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_AES,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = aes_keysize_adjust,
    .secret_attrs = p11sak_aes_attrs,
};

static const struct p11sak_keytype p11sak_aes_xts_keytype = {
    .name = "AES-XTS",  .type = CKK_AES_XTS, .ckk_name = "CKK_AES_XTS",
    .keygen_mech = { .mechanism = CKM_AES_XTS_KEY_GEN, },
    .is_asymmetric = false,
    .keygen_get_key_size = aes_get_key_size,
    .keygen_add_secret_attrs = aes_add_secret_attrs,
    .sign_verify = true, .encrypt_decrypt = true,
    .wrap_unwrap = true, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_AES_XTS,
    .keysize_attr = CKA_VALUE_LEN, .key_keysize_adjust = aes_xts_keysize_adjust,
    .secret_attrs = p11sak_aes_attrs,
};

static const struct p11sak_keytype p11sak_rsa_keytype = {
    .name = "RSA",  .type = CKK_RSA, .ckk_name = "CKK_RSA",
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
};

static const struct p11sak_keytype p11sak_dh_keytype = {
    .name = "DH", .type = CKK_DH, .ckk_name = "CKK_DH",
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
};

static const struct p11sak_keytype p11sak_dsa_keytype = {
    .name = "DSA",  .type = CKK_DSA, .ckk_name = "CKK_DSA",
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
};

static const struct p11sak_keytype p11sak_ec_keytype = {
    .name = "EC",  .type = CKK_EC, .ckk_name = "CKK_EC",
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
};

static const struct p11sak_keytype p11sak_ibm_dilithium_keytype = {
    .name = "IBM-Dilithium",  .type = CKK_IBM_PQC_DILITHIUM,
    .ckk_name = "CKK_IBM_PQC_DILITHIUM",
    .keygen_mech = { .mechanism = CKM_IBM_DILITHIUM, },
    .is_asymmetric = true,
    .keygen_add_public_attrs = ibm_dilithium_add_public_attrs,
    .sign_verify = true, .encrypt_decrypt = false,
    .wrap_unwrap = false, .derive = false,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_IBM_PQC_DILITHIUM,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .public_attrs = p11sak_public_ibm_dilithium_attrs,
    .private_attrs = p11sak_private_ibm_dilithium_attrs,
};

static const struct p11sak_keytype p11sak_ibm_kyber_keytype = {
    .name = "IBM-Kyber",  .type = CKK_IBM_PQC_KYBER,
    .ckk_name = "CKK_IBM_PQC_KYBER",
    .keygen_mech = { .mechanism = CKM_IBM_KYBER, },
    .is_asymmetric = true,
    .keygen_add_public_attrs = ibm_kyber_add_public_attrs,
    .sign_verify = false, .encrypt_decrypt = true,
    .wrap_unwrap = false, .derive = true,
    .filter_attr = CKA_KEY_TYPE, .filter_value = CKK_IBM_PQC_KYBER,
    .keysize_attr = (CK_ATTRIBUTE_TYPE)-1,
    .public_attrs = p11sak_public_ibm_kyber_attrs,
    .private_attrs = p11sak_private_ibm_kyber_attrs,
};

static const struct p11sak_keytype p11sak_secret_keytype = {
    .name = "Secret",
    .is_asymmetric = false,
    .filter_attr = CKA_CLASS, .filter_value = CKO_SECRET_KEY,
};

static const struct p11sak_keytype p11sak_public_keytype = {
    .name = "Public",
    .is_asymmetric = true,
    .filter_attr = CKA_CLASS, .filter_value = CKO_PUBLIC_KEY,
};

static const struct p11sak_keytype p11sak_private_keytype = {
    .name = "Private",
    .is_asymmetric = true,
    .filter_attr = CKA_CLASS, .filter_value = CKO_PRIVATE_KEY,
};

static const struct p11sak_keytype p11sak_all_keytype = {
    .name = "All",
    .filter_attr = (CK_ATTRIBUTE_TYPE)-1,
};

static const struct p11sak_keytype *p11sak_keytypes[] = {
    &p11sak_des_keytype,
    &p11sak_3des_keytype,
    &p11sak_generic_keytype,
    &p11sak_aes_keytype,
    &p11sak_aes_xts_keytype,
    &p11sak_rsa_keytype,
    &p11sak_dh_keytype,
    &p11sak_dsa_keytype,
    &p11sak_ec_keytype,
    &p11sak_ibm_dilithium_keytype,
    &p11sak_ibm_kyber_keytype,
    NULL,
};

static const struct p11sak_class p11sak_classes[] = {
    { .name = "CKO_DATA", .class = CKO_DATA, },
    { .name = "CKO_CERTIFICATE", .class = CKO_CERTIFICATE, },
    { .name = "CKO_PUBLIC_KEY", .class = CKO_PUBLIC_KEY, },
    { .name = "CKO_PRIVATE_KEY", .class = CKO_PRIVATE_KEY, },
    { .name = "CKO_SECRET_KEY", .class = CKO_SECRET_KEY, },
    { .name = "CKO_HW_FEATURE", .class = CKO_HW_FEATURE, },
    { .name = "CKO_DOMAIN_PARAMETERS", .class = CKO_DOMAIN_PARAMETERS, },
    { .name = "CKO_PROFILE", .class = CKO_PROFILE, },
    { .name = NULL, .class = 0, }
};

static const struct p11sak_opt p11sak_generic_opts[] = {
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
      .description = "The PKCS#11 user pin. If this option is not specified, " \
                     "and environment variable PKCS11_USER_PIN is not set, "   \
                     "then you will be prompted for the PIN.", },              \
    { .short_opt = 0, .long_opt = "force-pin-prompt", .required = false,       \
      .long_opt_val = OPT_FORCE_PIN_PROMPT,                                    \
      .arg = { .type = ARG_TYPE_PLAIN, .required = false,                      \
               .value.plain = &opt_force_pin_prompt, },                        \
      .description = "Enforce user PIN prompt, even if environment variable "  \
                     "PKCS11_USER_PIN is set, or the '-p'/'--pin' option is "  \
                     "specified.", }

#define FILTER_OPTS                                                            \
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
                     "P L M B Y R E D G C V O W U S A X N T I (optional). "    \
                     "Specify a set of these letters without any blanks in "   \
                     "between. See below for the meaning of the attribute "    \
                     "letters. Attributes that are not specified are not "     \
                     "used to filter the keys.", }

#define KEYGEN_KEYTYPES(args_prefix)                                           \
    { .value = "des", .args = NULL,                                            \
      .private = { .ptr = &p11sak_des_keytype, }, },                           \
    { .value = "3des", .args = NULL,                                           \
      .private = { .ptr = &p11sak_3des_keytype }, },                           \
    { .value = "generic", .args = args_prefix##_generic_args,                  \
      .private = { .ptr = &p11sak_generic_keytype }, },                        \
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
    { .value = "ibm-dilithium", .args = args_prefix##_ibm_dilithium_args,      \
      .private = { .ptr = &p11sak_ibm_dilithium_keytype }, },                  \
    { .value = "ibm-kyber", .args = args_prefix##_ibm_kyber_args,              \
      .private = { .ptr = &p11sak_ibm_kyber_keytype }, }

#define GROUP_KEYTYPES                                                         \
    { .value = "public", .args = NULL,                                         \
       .private = { .ptr = &p11sak_public_keytype }, },                        \
    { .value = "private", .args = NULL,                                        \
      .private = { .ptr = &p11sak_private_keytype }, },                        \
    { .value = "secret", .args = NULL,                                         \
      .private = { .ptr = &p11sak_secret_keytype }, },                         \
    { .value = "all", .args = NULL,                                            \
      .private = { .ptr = &p11sak_all_keytype }, }

static const struct p11sak_opt p11sak_generate_key_opts[] = {
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
                     "P L M B Y R E D G C V O W U S A X N T I (optional). "
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

static const struct p11sak_arg p11sak_generate_generic_args[] = {
    { .name = "KEYBITS", .type = ARG_TYPE_NUMBER, .required = true,
      .value.number = &opt_keybits_num,
      .description = "Size of the generic key in bits.", },
    { .name = NULL, },
};

static const struct p11sak_enum_value p11sak_aes_keybits[] = {
    { .value = "128", .args = NULL, .private = { .num = 128 }, },
    { .value = "192", .args = NULL, .private = { .num = 192 }, },
    { .value = "256", .args = NULL, .private = { .num = 256 }, },
    { .value = NULL, },
};

static const struct p11sak_arg p11sak_generate_aes_args[] = {
    { .name = "KEYBITS", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_aes_keybits,
      .value.enum_value = &opt_keybits,
      .description = "Size of the AES key in bits:", },
    { .name = NULL, },
};

static const struct p11sak_enum_value p11sak_aes_xts_keybits[] = {
    { .value = "128", .args = NULL, .private = { .num = 128 * 2 }, },
    { .value = "256", .args = NULL, .private = { .num = 256 * 2 }, },
    { .value = NULL, },
};

static const struct p11sak_arg p11sak_generate_aes_xts_args[] = {
    { .name = "KEYBITS", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_aes_xts_keybits,
      .value.enum_value = &opt_keybits,
      .description = "Size of the AES-XTS key in bits:", },
    { .name = NULL, },
};

static const struct p11sak_enum_value p11sak_rsa_keybits[] = {
    { .value = "512", .args = NULL, .private = { .num = 512 }, },
    { .value = "1024", .args = NULL, .private = { .num = 1024 }, },
    { .value = "2048", .args = NULL, .private = { .num = 2048 }, },
    { .value = "4096", .args = NULL, .private = { .num = 4096 }, },
    { .value = NULL, },
};

static const struct p11sak_arg p11sak_generate_rsa_args[] = {
    { .name = "KEYBITS", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_rsa_keybits,
      .value.enum_value = &opt_keybits,
      .description = "Size of the RSA key in bits:", },
    { .name = "PUBL-EXP", .type = ARG_TYPE_NUMBER, .required = false,
      .value.number = &opt_exponent,
      .description = "The public exponent for RSA (optional).", },
    { .name = NULL, },
};

static const struct p11sak_enum_value p11sak_dh_group[] = {
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

static const struct p11sak_arg p11sak_generate_dh_args[] = {
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

static const struct p11sak_arg p11sak_generate_dsa_args[] = {
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

static const struct p11sak_enum_value p11sak_ec_curves[] = {
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
    { .value = NULL, },
};

static const struct p11sak_arg p11sak_generate_ec_args[] = {
    { .name = "CURVE", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_ec_curves,
      .value.enum_value = &opt_curve,
      .description = "The curve name. One of the following:", },
    { .name = NULL, },
};

static const struct p11sak_enum_value p11sak_ibm_dilithium_versions[] = {
    { .value = "r2_65", .args = NULL,
      .private = { .num = CK_IBM_DILITHIUM_KEYFORM_ROUND2_65 }, },
    { .value = "r2_87", .args = NULL,
      .private = { .num = CK_IBM_DILITHIUM_KEYFORM_ROUND2_87 }, },
    { .value = "r2_44", .args = NULL,
      .private = { .num = CK_IBM_DILITHIUM_KEYFORM_ROUND3_44 }, },
    { .value = "r3_65", .args = NULL,
      .private = { .num = CK_IBM_DILITHIUM_KEYFORM_ROUND3_65 }, },
    { .value = "r3_87", .args = NULL,
      .private = { .num = CK_IBM_DILITHIUM_KEYFORM_ROUND3_87 }, },
    { .value = NULL, },
};

static const struct p11sak_arg p11sak_generate_ibm_dilithium_args[] = {
    { .name = "VERSION", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_ibm_dilithium_versions,
      .value.enum_value = &opt_pqc_version,
      .description = "The version of the IBM Dilithium key pair:", },
    { .name = NULL, },
};

static const struct p11sak_enum_value p11sak_ibm_kyber_versions[] = {
    { .value = "r2_768", .args = NULL,
      .private = { .num = CK_IBM_KYBER_KEYFORM_ROUND2_768 }, },
    { .value = "r2_1024", .args = NULL,
      .private = { .num = CK_IBM_KYBER_KEYFORM_ROUND2_1024 }, },
    { .value = NULL, },
};

static const struct p11sak_arg p11sak_generate_ibm_kyber_args[] = {
    { .name = "VERSION", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_ibm_kyber_versions,
      .value.enum_value = &opt_pqc_version,
      .description = "The version of the IBM Kyber key pair:", },
    { .name = NULL, },
};

static const struct p11sak_enum_value p11sak_generate_key_keytypes[] = {
    KEYGEN_KEYTYPES(p11sak_generate),
    { .value = NULL, },
};

static const struct p11sak_arg p11sak_generate_key_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = true,
      .enum_values = p11sak_generate_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the key. One of the following:", },
    { .name = NULL },
};

static const struct p11sak_opt p11sak_list_key_opts[] = {
    PKCS11_OPTS,
    FILTER_OPTS,
    { .short_opt = 'l', .long_opt = "long", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_long, },
      .description = "List keys in long (detailed) format.", },
    { .short_opt = 0, .long_opt = "detailed-uri", .required = false,
      .long_opt_val = OPT_DETAILED_URI,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_detailed_uri, },
      .description = "Show detailed PKCS#11 URI.", },
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
                     "Example: 'l:a,k:d' will sort by label in ascending order "
                     "and then by key type in descending order.", },
    { .short_opt = 0, .long_opt = NULL, },
};

#define null_generic_args           NULL
#define null_aes_args               NULL
#define null_aes_xts_args           NULL
#define null_rsa_args               NULL
#define null_dh_args                NULL
#define null_dsa_args               NULL
#define null_ec_args                NULL
#define null_ibm_dilithium_args     NULL
#define null_ibm_kyber_args         NULL

static const struct p11sak_enum_value p11sak_list_remove_set_key_keytypes[] = {
    KEYGEN_KEYTYPES(null),
    GROUP_KEYTYPES,
    { .value = NULL, },
};

static const struct p11sak_arg p11sak_list_key_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the keys to list (optional). If no key type "
                     "is specified, all key types are listed.", },
    { .name = NULL },
};

static const struct p11sak_opt p11sak_remove_key_opts[] = {
    PKCS11_OPTS,
    FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to remove a key. "
                     "Use with care, all keys matching the filter will be "
                     "removed!", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11sak_arg p11sak_remove_key_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the keys to select for removal (optional). "
                     "If no key type is specified, all key types are "
                     "selected.", },
    { .name = NULL },
};

static const struct p11sak_opt p11sak_set_key_attr_opts[] = {
    PKCS11_OPTS,
    FILTER_OPTS,
    { .short_opt = 'f', .long_opt = "force", .required = false,
      .arg =  { .type = ARG_TYPE_PLAIN, .required = false,
                .value.plain = &opt_force, },
      .description = "Do not prompt for a confirmation to set the attributes "
                     "of a key. Use with care, all keys matching the filter "
                     "will be changed!", },
    { .short_opt = 'A', .long_opt = "new-attr", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_new_attr, .name = "ATTRS", },
      .description = "The boolean attributes to set for the key (optional):\n"
                     "P L M B Y R E D G C V O W U S A X N T I. "
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

static const struct p11sak_arg p11sak_set_key_attr_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_set_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the keys to select for update (optional). "
                     "If no key type is specified, all key types are "
                     "selected.", },
    { .name = NULL },
};

static const struct p11sak_cmd p11sak_commands[] = {
    { .cmd = "generate-key", .cmd_short1 = "gen-key", .cmd_short2 = "gen",
      .func = p11sak_generate_key,
      .opts = p11sak_generate_key_opts, .args = p11sak_generate_key_args,
      .description = "Generate a key.", .help = print_generate_key_attr_help,
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
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = "set-key-attr", .cmd_short1 = "set-key", .cmd_short2 = "set",
      .func = p11sak_set_key_attr,
      .opts = p11sak_set_key_attr_opts, .args = p11sak_set_key_attr_args,
      .description = "Set attributes of keys in the repository.",
      .help = print_set_key_attr_help,
      .session_flags = CKF_SERIAL_SESSION | CKF_RW_SESSION, },
    { .cmd = NULL, .func = NULL },
};

#define DECLARE_BOOL_ATTR(attr, ch, sec, pub, priv, set)                       \
    { .name = # attr, .type = attr, .letter = ch,                              \
      .secret = sec, .public = pub, .private = priv,                           \
      .settable = set, .print_short = print_bool_attr_short,                   \
      .print_long = print_bool_attr_long, }

static const struct p11sak_attr p11sak_bool_attrs[] = {
    DECLARE_BOOL_ATTR(CKA_PRIVATE,           'P', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_LOCAL,             'L', true,  true,  true,  false),
    DECLARE_BOOL_ATTR(CKA_MODIFIABLE,        'M', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_COPYABLE,          'B', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_DESTROYABLE,       'Y', true,  true,  true,  true),
    DECLARE_BOOL_ATTR(CKA_DERIVE,            'R', true,  false, true,  true),
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
    DECLARE_BOOL_ATTR(CKA_TRUSTED,           'T', true,  true,  true,  false),
    DECLARE_BOOL_ATTR(CKA_WRAP_WITH_TRUSTED, 'I', true,  false, true,  true),
    DECLARE_BOOL_ATTR(CKA_IBM_PROTKEY_EXTRACTABLE,
                                             'K', true,  false, true,  true),
    DECLARE_BOOL_ATTR(CKA_IBM_PROTKEY_NEVER_EXTRACTABLE,
                                             'Z', true,  false, true,  false),
    { .name = NULL, },
};

static const struct p11sak_custom_attr_type custom_attr_types[] = {
    { .type = P11SAK_CONFIG_TYPE_BOOL, .print_long = print_bool_attr_long, },
    { .type = P11SAK_CONFIG_TYPE_ULONG, .print_long = print_ulong_attr, },
    { .type = P11SAK_CONFIG_TYPE_BYTE, .print_long = print_byte_array_attr, },
    { .type = P11SAK_CONFIG_TYPE_DATE, .print_long = print_date_attr, },
    { .type = NULL, },
};

static const struct p11sak_cmd *find_command(const char *cmd)
{
    unsigned int i;

    for (i = 0; p11sak_commands[i].cmd != NULL; i++) {
        if (strcasecmp(cmd, p11sak_commands[i].cmd) == 0)
            return &p11sak_commands[i];
        if (p11sak_commands[i].cmd_short1 != NULL &&
            strcasecmp(cmd, p11sak_commands[i].cmd_short1) == 0)
            return &p11sak_commands[i];
        if (p11sak_commands[i].cmd_short2 != NULL &&
            strcasecmp(cmd, p11sak_commands[i].cmd_short2) == 0)
            return &p11sak_commands[i];
    }

    return NULL;
}

static void count_opts(const struct p11sak_opt *opts,
                       unsigned int *optstring_len,
                       unsigned int *longopts_count)
{
    const struct p11sak_opt *opt;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0) {
            (*optstring_len)++;
            if (opt->arg.type != ARG_TYPE_PLAIN) {
                (*optstring_len)++;
                if (!opt->arg.required)
                    (*optstring_len)++;
            }
        }

        if (opt->long_opt != NULL)
            (*longopts_count)++;
    }
}

static CK_RV build_opts(const struct p11sak_opt *opts,
                        char *optstring,
                        struct option *longopts)
{
    const struct p11sak_opt *opt;
    unsigned int opts_idx, long_idx;

    opts_idx = strlen(optstring);

    for (long_idx = 0; longopts[long_idx].name != NULL; long_idx++)
        ;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0) {
            optstring[opts_idx++] = opt->short_opt;
            if (opt->arg.type != ARG_TYPE_PLAIN) {
                optstring[opts_idx++] = ':';
                if (!opt->arg.required)
                    optstring[opts_idx++] = ':';
            }
        }

        if (opt->long_opt != NULL) {
            longopts[long_idx].name = opt->long_opt;
            longopts[long_idx].has_arg = opt->arg.type != ARG_TYPE_PLAIN ?
                              (opt->arg.required ?
                                      required_argument : optional_argument ) :
                              no_argument;
            longopts[long_idx].flag = NULL;
            longopts[long_idx].val = opt->short_opt != 0 ?
                                        opt->short_opt : opt->long_opt_val;
            long_idx++;
        }
    }

    return CKR_OK;
}

static CK_RV build_cmd_opts(const struct p11sak_opt *cmd_opts,
                            char **optstring, struct option **longopts)
{
    unsigned int optstring_len = 0, longopts_count = 0;
    CK_RV rc;

    count_opts(p11sak_generic_opts, &optstring_len, &longopts_count);
    if (cmd_opts != NULL)
        count_opts(cmd_opts, &optstring_len, &longopts_count);

    *optstring = calloc(1 + optstring_len + 1, 1);
    *longopts = calloc(longopts_count + 1, sizeof(struct option));
    if (*optstring == NULL || *longopts == NULL) {
        rc = CKR_HOST_MEMORY;
        goto error;
    }

    (*optstring)[0] = ':'; /* Let getopt return ':' on missing argument */

    rc = build_opts(p11sak_generic_opts, *optstring, *longopts);
    if (rc != CKR_OK)
        goto error;

    if (cmd_opts != NULL) {
        rc = build_opts(cmd_opts, *optstring, *longopts);
        if (rc != CKR_OK)
            goto error;
    }

    return CKR_OK;

error:
    if (*optstring != NULL)
        free(*optstring);
    *optstring = NULL;

    if (*longopts != NULL)
        free(*longopts);
    *longopts = NULL;

    return rc;
}

static CK_RV process_plain_argument(const struct p11sak_arg *arg)
{
    *arg->value.plain = true;

    return CKR_OK;
}

static CK_RV process_string_argument(const struct p11sak_arg *arg, char *val)
{
    *arg->value.string = val;

    return CKR_OK;
}

static CK_RV process_enum_argument(const struct p11sak_arg *arg, char *val)
{
    const struct p11sak_enum_value *enum_val, *any_val = NULL;

    for (enum_val = arg->enum_values; enum_val->value != NULL; enum_val++) {

        if (enum_val->any_value != NULL) {
            any_val = enum_val;
        } else if (arg->case_sensitive ?
                            strcasecmp(val, enum_val->value) == 0 :
                            strcmp(val, enum_val->value) == 0) {

            *arg->value.enum_value = (struct p11sak_enum_value *)enum_val;
            return CKR_OK;
        }
    }

    /* process ANY enumeration value after all others */
    if (any_val != NULL) {
        *any_val->any_value = val;
        *arg->value.enum_value = (struct p11sak_enum_value *)any_val;
        return CKR_OK;
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV process_number_argument(const struct p11sak_arg *arg, char *val)
{
    char *endptr;

    *arg->value.number = strtoul(val, &endptr, 0);

    if ((errno == ERANGE && *arg->value.number == ULONG_MAX) ||
        (errno != 0 && *arg->value.number == 0) ||
        endptr == val) {
        return CKR_ARGUMENTS_BAD;
    }

    return CKR_OK;
}

static CK_RV processs_argument(const struct p11sak_arg *arg, char *val)
{
    switch (arg->type) {
    case ARG_TYPE_PLAIN:
        return process_plain_argument(arg);
    case ARG_TYPE_STRING:
        return process_string_argument(arg, val);
    case ARG_TYPE_ENUM:
        return process_enum_argument(arg, val);
    case ARG_TYPE_NUMBER:
        return process_number_argument(arg, val);
    default:
        return CKR_ARGUMENTS_BAD;
    }
}

static bool argument_is_set(const struct p11sak_arg *arg)
{
    if (arg->is_set != NULL)
       return arg->is_set(arg);

    switch (arg->type) {
    case ARG_TYPE_PLAIN:
        return *arg->value.plain;
    case ARG_TYPE_STRING:
        return *arg->value.string != NULL;
    case ARG_TYPE_ENUM:
        return *arg->value.enum_value != NULL;
    case ARG_TYPE_NUMBER:
        return *arg->value.number != 0;
    default:
        return false;
    }
}

static void option_arg_error(const struct p11sak_opt *opt, const char *arg)
{
    if (opt->short_opt != 0 && opt->long_opt != NULL)
        warnx("Invalid argument '%s' for option '-%c/--%s'", arg,
             opt->short_opt, opt->long_opt);
    else if (opt->long_opt != NULL)
        warnx("Invalid argument '%s' for option '--%s'", arg, opt->long_opt);
    else
        warnx("Invalid argument '%s' for option '-%c'", arg, opt->short_opt);
}

static void option_missing_error(const struct p11sak_opt *opt)
{
    if (opt->short_opt != 0 && opt->long_opt != NULL)
        warnx("Option '-%c/--%s' is required but not specified", opt->short_opt,
             opt->long_opt);
    else if (opt->long_opt != NULL)
        warnx("Option '--%s is required but not specified'", opt->long_opt);
    else
        warnx("Option '-%c' is required but not specified", opt->short_opt);
}

static CK_RV process_option(const struct p11sak_opt *opts, int ch, char *val)
{
    const struct p11sak_opt *opt;
    CK_RV rc;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (ch == (opt->short_opt != 0 ? opt->short_opt : opt->long_opt_val)) {
            rc = processs_argument(&opt->arg, val);
            if (rc != CKR_OK) {
                option_arg_error(opt, val);
                return rc;
            }

            return CKR_OK;
        }
    }

    return CKR_ARGUMENTS_BAD;
}

static CK_RV process_cmd_option(const struct p11sak_opt *cmd_opts,
                                int opt, char *arg)
{
    CK_RV rc;

    rc = process_option(p11sak_generic_opts, opt, arg);
    if (rc == CKR_OK)
        return CKR_OK;

    if (cmd_opts != NULL) {
        rc = process_option(cmd_opts, opt, arg);
        if (rc == CKR_OK)
            return CKR_OK;
    }

    return rc;
}

static CK_RV check_required_opts(const struct p11sak_opt *opts)
{
    const struct p11sak_opt *opt;
    CK_RV rc = CKR_OK;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->required && opt->arg.required &&
            argument_is_set(&opt->arg) == false) {
            option_missing_error(opt);
            rc = CKR_ARGUMENTS_BAD;
            /* No break, report all missing options */
        }
    }

    return rc;
}

static CK_RV check_required_cmd_opts(const struct p11sak_opt *cmd_opts)
{
    CK_RV rc;

    rc = check_required_opts(p11sak_generic_opts);
    if (rc != CKR_OK)
        return rc;

    if (cmd_opts != NULL) {
        rc = check_required_opts(cmd_opts);
        if (rc != CKR_OK)
            return rc;
    }

    return CKR_OK;
}

static CK_RV parse_cmd_options(const struct p11sak_cmd *cmd,
                               int argc, char *argv[])
{
    char *optstring = NULL;
    struct option *longopts = NULL;
    CK_RV rc;
    int c;

    rc = build_cmd_opts(cmd != NULL ? cmd->opts : NULL, &optstring, &longopts);
    if (rc != CKR_OK)
        goto done;

    opterr = 0;
    while (1) {
        c = getopt_long(argc, argv, optstring, longopts, NULL);
        if (c == -1)
            break;

        switch (c) {
        case ':':
            warnx("Option '%s' requires an argument", argv[optind - 1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;

        case '?': /* An invalid option has been specified */
            if (optopt)
                warnx("Invalid option '-%c'", optopt);
            else
                warnx("Invalid option '%s'", argv[optind - 1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;

        default:
            rc = process_cmd_option(cmd != NULL ? cmd->opts : NULL, c, optarg);
            if (rc != CKR_OK)
                goto done;
            break;
        }
    }

    if (optind < argc) {
        warnx("Invalid argument '%s'", argv[optind]);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

done:
    if (optstring != NULL)
        free(optstring);
    if (longopts != NULL)
        free(longopts);

    return rc;
}

static CK_RV check_required_args(const struct p11sak_arg *args)
{
    const struct p11sak_arg *arg;
    CK_RV rc2, rc = CKR_OK;

    for (arg = args; arg != NULL && arg->name != NULL; arg++) {
        if (arg->required && argument_is_set(arg) == false) {
            warnx("Argument '%s' is required but not specified", arg->name);
            rc = CKR_ARGUMENTS_BAD;
            /* No break, report all missing arguments */
        }

        /* Check enumeration value specific arguments (if any) */
        if (arg->type == ARG_TYPE_ENUM && *arg->value.enum_value != NULL &&
            (*arg->value.enum_value)->args != NULL) {
            rc2 = check_required_args((*arg->value.enum_value)->args);
            if (rc2 != CKR_OK)
                rc = rc2;
            /* No break, report all missing arguments */
        }
    }

    return rc;
}

static CK_RV parse_arguments(const struct p11sak_arg *args,
                             int *argc, char **argv[])
{
    const struct p11sak_arg *arg;
    CK_RV rc = CKR_OK;

    for (arg = args; arg->name != NULL; arg++) {
        if (*argc < 2 || strncmp((*argv)[1], "-", 1) == 0)
            break;

        rc = processs_argument(arg, (*argv)[1]);
        if (rc != CKR_OK) {
            if (rc == CKR_ARGUMENTS_BAD)
                warnx("Invalid argument '%s' for '%s'", (*argv)[1], arg->name);
            break;
        }

        (*argc)--;
        (*argv)++;

        /* Process enumeration value specific arguments (if any) */
        if (arg->type == ARG_TYPE_ENUM && *arg->value.enum_value != NULL &&
            (*arg->value.enum_value)->args != NULL) {
            rc = parse_arguments((*arg->value.enum_value)->args, argc, argv);
            if (rc != CKR_OK)
                break;
        }
    }

    return rc;
}

static CK_RV parse_cmd_arguments(const struct p11sak_cmd *cmd,
                                 int *argc, char **argv[])
{
    if (cmd == NULL)
        return CKR_OK;

    return parse_arguments(cmd->args, argc, argv);
}

static void print_indented(const char *str, int indent)
{
    char *word, *line, *desc, *desc_ptr;
    int word_len, pos = indent;

    desc = desc_ptr = strdup(str);
    if (desc == NULL)
        return;

    line = strsep(&desc, "\n");
    while (line != NULL) {
        word = strsep(&line, " ");
        pos = indent;
        while (word != NULL) {
            word_len = strlen(word);
            if (pos + word_len + 1 > MAX_PRINT_LINE_LENGTH) {
                printf("\n%*s", indent, "");
                pos = indent;
            }
            if (pos == indent)
                printf("%s", word);
            else
                printf(" %s", word);
            pos += word_len + 1;
            word = strsep(&line, " ");
        }
        if (desc)
            printf("\n%*s", indent, "");
        line =  strsep(&desc, "\n");
    }

    printf("\n");
    free(desc_ptr);
}

static void print_options_help(const struct p11sak_opt *opts)
{
    const struct p11sak_opt *opt;
    char tmp[200];
    int len;

    for (opt = opts; opt->short_opt != 0 || opt->long_opt != NULL; opt++) {
        if (opt->short_opt != 0 && opt->long_opt != NULL)
            len = snprintf(tmp, sizeof(tmp), "-%c, --%s", opt->short_opt,
                           opt->long_opt);
        else if (opt->short_opt == 0 && opt->long_opt != NULL)
            len = snprintf(tmp, sizeof(tmp),"    --%s", opt->long_opt);
        else
            len = snprintf(tmp, sizeof(tmp),"-%c", opt->short_opt);

        if (opt->arg.type != ARG_TYPE_PLAIN) {
            if (opt->arg.required)
                snprintf(&tmp[len], sizeof(tmp) - len, " %s", opt->arg.name);
            else if (opt->long_opt == NULL)
                snprintf(&tmp[len], sizeof(tmp) - len, "[%s]", opt->arg.name);
            else
                snprintf(&tmp[len], sizeof(tmp) - len, "[=%s]", opt->arg.name);
        }

        printf("    %-30.30s ", tmp);
        print_indented(opt->description, PRINT_INDENT_POS);
    }
}

static void print_arguments_help(const struct p11sak_cmd *cmd,
                                 const struct p11sak_arg *args,
                                 int indent)
{
    const struct p11sak_arg *arg;
    const struct p11sak_enum_value *val;
    int width;
    bool newline = false;

    if (indent > 0) {
        for (arg = args; arg->name != NULL; arg++) {
            if (arg->required)
                printf(" %s", arg->name);
            else
                printf(" [%s]", arg->name);
        }
        printf("\n\n");
    }

    for (arg = args; arg->name != NULL; arg++) {
        width = 30 - indent;
        if (width < (int)strlen(arg->name))
            width = (int)strlen(arg->name);

        printf("%*s    %-*.*s ", indent, "", width, width, arg->name);
        print_indented(arg->description, PRINT_INDENT_POS);

        newline = false;

        if (arg->type != ARG_TYPE_ENUM)
            continue;

        /* Enumeration: print possible values */
        for (val = arg->enum_values; val->value != NULL; val++) {
            if (arg == cmd->args && argument_is_set(arg) &&
                *arg->value.enum_value != val)
                continue;

            newline = true;

            printf("%*s        %s", indent, "", val->value);

            if (val->args != NULL) {
                print_arguments_help(cmd, val->args, indent + 8);
                newline = false;
            } else {
                printf("\n");
            }
        }
    }

    if (indent > 0 || newline)
        printf("\n");
}

static void print_help(void)
{
    const struct p11sak_cmd *cmd;

    printf("\n");
    printf("Usage: p11sak COMMAND [ARGS] [OPTIONS]\n");
    printf("\n");
    printf("COMMANDS:\n");
    for (cmd = p11sak_commands; cmd->cmd != NULL; cmd++) {
        printf("    %-30.30s ", cmd->cmd);
        print_indented(cmd->description, PRINT_INDENT_POS);
    }
    printf("\n");
    printf("COMMON OPTIONS\n");
    print_options_help(p11sak_generic_opts);
    printf("\n");
    printf("For more information use 'p11sak COMMAND --help'.\n");
    printf("\n");
}

static void print_command_help(const struct p11sak_cmd *cmd)
{
    printf("\n");
    printf("Usage: p11sak %s [ARGS] [OPTIONS]\n", cmd->cmd);
    printf("\n");
    printf("ARGS:\n");
    print_arguments_help(cmd, cmd->args, 0);
    printf("OPTIONS:\n");
    print_options_help(cmd->opts);
    print_options_help(p11sak_generic_opts);
    printf("\n");
    if (cmd->help != NULL)
        cmd->help();
}

static void print_generate_key_attr_help(void)
{
    const struct p11sak_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++) {
        if (attr->settable)
            printf("    '%c':   %s\n", attr->letter, attr->name);
    }
    printf("\n");

    printf("    ");
    print_indented("An uppercase letter sets the corresponding attribute to "
                   "CK_TRUE, a lower case letter to CK_FALSE.\n"
                   "If an attribute is not set explicitly, its default value "
                   "is used.\n"
                   "Not all attributes may be accepted for all key types.\n"
                   "Attribute CKA_TOKEN is always set to CK_TRUE.", 4);
    printf("\n");
}

static void print_list_key_attr_help(void)
{
    const struct p11sak_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++)
        printf("    '%c':   %s\n", attr->letter, attr->name);
    printf("\n");

    printf("    ");
    print_indented("Not all attributes may be defined for all key types.\n"
                   "Attribute CKA_TOKEN is always CK_TRUE for all keys listed.",
                   4);
    printf("\n");
}

static void print_set_key_attr_help(void)
{
    const struct p11sak_attr *attr;

    printf("ATTRIBUTES:\n");
    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++) {
        if (attr->settable)
            printf("    '%c':   %s\n", attr->letter, attr->name);
    }
    printf("\n");

    printf("    ");
    print_indented("An uppercase letter sets the corresponding attribute to "
                   "CK_TRUE, a lower case letter to CK_FALSE.\n"
                   "If an attribute is not set explicitly, its value is not "
                   "changed.\n"
                   "Not all attributes may be allowed to be changed for all "
                   "key types, or to all values.\n", 4);
    printf("\n");
}

static void print_version(void)
{
    printf("p11sak version %s\n", PACKAGE_VERSION);
}

static bool opt_slot_is_set(const struct p11sak_arg *arg)
{
    return (*arg->value.number != (CK_ULONG)-1);
}

static int openssl_err_cb(const char *str, size_t len, void *u)
{
    UNUSED(u);

    if (str[len - 1] == '\n')
        len--;

    warnx("OpenSSL error: %.*s", (int)len, str);
    return 1;
}

static bool is_rejected_by_policy(CK_RV ret_code, CK_SESSION_HANDLE session)
{
    CK_SESSION_INFO info;
    CK_RV rc;

    if (ret_code != CKR_FUNCTION_FAILED)
        return false;

    rc = pkcs11_funcs->C_GetSessionInfo(session, &info);
    if (rc != CKR_OK) {
        warnx("C_GetSessionInfo failed: 0x%lX: %s", rc, p11_get_ckr(rc));
        return false;
    }

    return (info.ulDeviceError == CKR_POLICY_VIOLATION);
}

static CK_RV check_mech_supported(const struct p11sak_keytype *keytype,
                                  CK_ULONG keysize)
{
    CK_MECHANISM_INFO mech_info;
    CK_RV rc;

    rc = pkcs11_funcs->C_GetMechanismInfo(opt_slot,
                                          keytype->keygen_mech.mechanism,
                                          &mech_info);
    if (rc != CKR_OK) {
        warnx("Token in slot %lu does not support mechanism %s", opt_slot,
              p11_get_ckm(&mechtable_funcs, keytype->keygen_mech.mechanism));
        return rc;
    }

    if ((mech_info.flags & (keytype->is_asymmetric ?
                                CKF_GENERATE_KEY_PAIR : CKF_GENERATE)) == 0) {
        warnx("Mechanism %s does not support to generate keys",
              p11_get_ckm(&mechtable_funcs, keytype->keygen_mech.mechanism));
        return CKR_MECHANISM_INVALID;
    }

    if (keysize != 0 &&
        mech_info.ulMinKeySize != 0 && mech_info.ulMaxKeySize != 0) {
        if (keysize < mech_info.ulMinKeySize ||
            keysize > mech_info.ulMaxKeySize) {
            warnx("Mechanism %s does not support to generate keys of size %lu",
                  p11_get_ckm(&mechtable_funcs, keytype->keygen_mech.mechanism),
                  keysize);
            return CKR_KEY_SIZE_RANGE;
        }
    }

    return CKR_OK;
}

static CK_RV add_attribute(CK_ATTRIBUTE_TYPE type, const void *value,
                           CK_ULONG value_len, CK_ATTRIBUTE **attrs,
                           CK_ULONG *num_attrs)
{
    CK_ATTRIBUTE *tmp;

    tmp = realloc(*attrs, (*num_attrs + 1) * sizeof(CK_ATTRIBUTE));
    if (tmp == NULL) {
        warnx("Failed to allocate memory for attribute list");
        return CKR_HOST_MEMORY;
    }

    *attrs = tmp;

    tmp[*num_attrs].type = type;
    tmp[*num_attrs].ulValueLen = value_len;
    tmp[*num_attrs].pValue = malloc(value_len);
    if (tmp[*num_attrs].pValue == NULL) {
        warnx("Failed to allocate memory attribute to add to list");
        return CKR_HOST_MEMORY;
    }
    memcpy(tmp[*num_attrs].pValue, value, value_len);

    (*num_attrs)++;

    return CKR_OK;
}

static CK_RV generic_get_key_size(const struct p11sak_keytype *keytype,
                                  void *private, CK_ULONG *keysize)
{
    UNUSED(private);
    UNUSED(keytype);

    *keysize = opt_keybits_num;

    return CKR_OK;
}

static CK_RV generic_add_secret_attrs(const struct p11sak_keytype *keytype,
                                      CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                      void *private)
{
    CK_ULONG value_len = opt_keybits_num / 8;

    UNUSED(private);
    UNUSED(keytype);

    return add_attribute(CKA_VALUE_LEN, &value_len, sizeof(value_len),
                         attrs, num_attrs);
}

static CK_ULONG generic_keysize_adjust(const struct p11sak_keytype *keytype,
                                       CK_ULONG keysize)
{
    UNUSED(keytype);

    return keysize * 8;
}

static CK_RV aes_get_key_size(const struct p11sak_keytype *keytype,
                              void *private, CK_ULONG *keysize)
{
    UNUSED(private);
    UNUSED(keytype);

    *keysize = opt_keybits->private.num / 8;

    return CKR_OK;
}

static CK_RV aes_add_secret_attrs(const struct p11sak_keytype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private)
{
    CK_ULONG value_len = opt_keybits->private.num / 8;

    UNUSED(private);
    UNUSED(keytype);

    return add_attribute(CKA_VALUE_LEN, &value_len, sizeof(value_len),
                         attrs, num_attrs);
}

static CK_ULONG aes_keysize_adjust(const struct p11sak_keytype *keytype,
                                   CK_ULONG keysize)
{
    UNUSED(keytype);

    return keysize * 8;
}

static CK_ULONG aes_xts_keysize_adjust(const struct p11sak_keytype *keytype,
                                       CK_ULONG keysize)
{
    UNUSED(keytype);

    return (keysize * 8) / 2;
}

static CK_ULONG rsa_keysize_adjust(const struct p11sak_keytype *keytype,
                                   CK_ULONG keysize)
{
    UNUSED(keytype);

    return keysize * 8;
}

static CK_ULONG dh_keysize_adjust(const struct p11sak_keytype *keytype,
                                  CK_ULONG keysize)
{
    UNUSED(keytype);

    return keysize * 8;
}

static CK_ULONG dsa_keysize_adjust(const struct p11sak_keytype *keytype,
                                   CK_ULONG keysize)
{
    UNUSED(keytype);

    return keysize * 8;
}

static CK_RV rsa_get_key_size(const struct p11sak_keytype *keytype,
                              void *private, CK_ULONG *keysize)
{
    UNUSED(private);
    UNUSED(keytype);

    *keysize = opt_keybits->private.num;

    return CKR_OK;
}

static CK_RV rsa_add_public_attrs(const struct p11sak_keytype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private)
{
    CK_RV rc;
    CK_BYTE *b;
    CK_ULONG val;
    unsigned int i;

    UNUSED(private);
    UNUSED(keytype);

    rc = add_attribute(CKA_MODULUS_BITS, &opt_keybits->private.num,
                       sizeof(opt_keybits->private.num), attrs, num_attrs);
    if (rc != CKR_OK)
        return rc;

    if (opt_exponent != 0) {
        /* Convert CK_ULOING to big-endian byte array */
        val = htobe64(opt_exponent);
        for (i = 0, b = (CK_BYTE *)&val; i < sizeof(val) && *b == 0; i++, b++)
            ;

        rc = add_attribute(CKA_PUBLIC_EXPONENT, b, sizeof(val) - i,
                           attrs, num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

    return CKR_OK;
}

static CK_RV ec_get_key_size(const struct p11sak_keytype *keytype,
                             void *private, CK_ULONG *keysize)
{
    const struct curve_info *curve = opt_curve->private.ptr;

    UNUSED(private);
    UNUSED(keytype);

    *keysize = curve->bitsize;

    return CKR_OK;
}

static CK_RV ec_add_public_attrs(const struct p11sak_keytype *keytype,
                                 CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                 void *private)
{
    const struct curve_info *curve = opt_curve->private.ptr;

    UNUSED(private);
    UNUSED(keytype);

    return add_attribute(CKA_EC_PARAMS, curve->oid, curve->oid_len,
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
        ERR_print_errors_cb(openssl_err_cb, NULL);
        return CKR_ARGUMENTS_BAD;
    }

    param = PEM_read_bio_Parameters(f, NULL);
    if (param == NULL ||
        EVP_PKEY_base_id(param) != (is_dsa ? EVP_PKEY_DSA : EVP_PKEY_DH)) {
        warnx("Failed to read %s PEM file '%s'.", is_dsa ? "DSA" : "DH",
              pem_file);
        ERR_print_errors_cb(openssl_err_cb, NULL);
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
        ERR_print_errors_cb(openssl_err_cb, NULL);
        return CKR_FUNCTION_FAILED;
    }

    if (EVP_PKEY_paramgen_init(ctx) <= 0) {
        warnx("Failed to initialize a DH paramgen context.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (EVP_PKEY_CTX_set_dh_nid(ctx, group_nid) <= 0) {
        warnx("Failed to set group for DH paramgen context.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    if (EVP_PKEY_paramgen(ctx, &param) <= 0) {
        warnx("Failed to generate the DH params.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
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

static CK_RV add_bignum_attr(CK_ATTRIBUTE_TYPE type, const BIGNUM* bn,
                             CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs)
{
    int len;
    CK_BYTE *buff = NULL;
    CK_RV rc;

    len = BN_num_bytes(bn);
    buff = calloc(len, 1);
    if (buff == NULL || len == 0) {
        warnx("Failed to allocate a buffer for a bignum");
        if (buff != NULL)
            free(buff);
        return CKR_HOST_MEMORY;
    }

    if (BN_bn2bin(bn, buff) != len) {
        warnx("Failed to get a bignum.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        free(buff);
        return CKR_FUNCTION_FAILED;
    }

    rc = add_attribute(type, buff, len, attrs, num_attrs);
    free(buff);

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
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
     }
#else
    if (is_dsa) {
        dsa = EVP_PKEY_get0_DSA(pkey);
        if (dsa == NULL) {
            warnx("Failed to get the DSA params.");
            ERR_print_errors_cb(openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        DSA_get0_pqg(dsa, &bn_p, &bn_q, &bn_g);
        if (bn_p == NULL || (dsa && bn_q == NULL) || bn_g == NULL) {
            warnx("Failed to get the DSA params.");
            ERR_print_errors_cb(openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        dh = EVP_PKEY_get0_DH(pkey);
        if (dh == NULL) {
            warnx("Failed to get the DH params.");
            ERR_print_errors_cb(openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }

        DH_get0_pqg(dh, &bn_p, NULL, &bn_g);
        if (bn_p == NULL || bn_g == NULL) {
            warnx("Failed to get the DH params.");
            ERR_print_errors_cb(openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }
#endif

    rc = add_bignum_attr(CKA_PRIME, bn_p, attrs, num_attrs);
    if (rc != CKR_OK)
       goto done;

    if (is_dsa) {
        rc = add_bignum_attr(CKA_SUBPRIME, bn_q, attrs, num_attrs);
        if (rc != CKR_OK)
           goto done;
    }

    rc = add_bignum_attr(CKA_BASE, bn_g, attrs, num_attrs);
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

static CK_RV dh_prepare(const struct p11sak_keytype *keytype, void **private)
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

static void dh_cleanup(const struct p11sak_keytype *keytype, void *private)
{
    EVP_PKEY *pkey = private;

    UNUSED(keytype);

    EVP_PKEY_free(pkey);
}

static CK_RV dh_get_key_size(const struct p11sak_keytype *keytype,
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
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
     }
#else
    dh = EVP_PKEY_get0_DH(pkey);
    if (dh == NULL) {
        warnx("Failed to get the DH params.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    DH_get0_pqg(dh, &bn_p, NULL, NULL);
    if (bn_p == NULL) {
        warnx("Failed to get the DH params.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
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

static CK_RV dh_add_public_attrs(const struct p11sak_keytype *keytype,
                                 CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                 void *private)
{
    EVP_PKEY *pkey = private;

    UNUSED(keytype);

    return dh_dsa_add_public_attrs(attrs, num_attrs, pkey, false);
}

static CK_RV dh_add_private_attrs(const struct p11sak_keytype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private)
{
    UNUSED(private);
    UNUSED(keytype);

    if (opt_keybits_num == 0)
        return CKR_OK;

    return add_attribute(CKA_VALUE_BITS, &opt_keybits_num,
                         sizeof(opt_keybits_num), attrs, num_attrs);
}

static CK_RV dsa_prepare(const struct p11sak_keytype *keytype, void **private)
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

static void dsa_cleanup(const struct p11sak_keytype *keytype, void *private)
{
    EVP_PKEY *pkey = private;

    UNUSED(keytype);

    EVP_PKEY_free(pkey);
}

static CK_RV dsa_get_key_size(const struct p11sak_keytype *keytype,
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
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
     }
#else
    dsa = EVP_PKEY_get0_DSA(pkey);
    if (dsa == NULL) {
        warnx("Failed to get the DSA params.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    DSA_get0_pqg(dsa, &bn_p, NULL, NULL);
    if (bn_p == NULL) {
        warnx("Failed to get the DSA params.");
        ERR_print_errors_cb(openssl_err_cb, NULL);
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

static CK_RV dsa_add_public_attrs(const struct p11sak_keytype *keytype,
                                  CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                  void *private)
{
    EVP_PKEY *pkey = private;

    UNUSED(keytype);

    return dh_dsa_add_public_attrs(attrs, num_attrs, pkey, true);
}

static CK_RV ibm_dilithium_add_public_attrs(const struct p11sak_keytype *keytype,
                                            CK_ATTRIBUTE **attrs,
                                            CK_ULONG *num_attrs,
                                            void *private)
{
    UNUSED(private);
    UNUSED(keytype);

    return add_attribute(CKA_IBM_DILITHIUM_KEYFORM,
                         &opt_pqc_version->private.num,
                         sizeof(opt_pqc_version->private.num),
                         attrs, num_attrs);
}

static CK_RV ibm_kyber_add_public_attrs(const struct p11sak_keytype *keytype,
                                        CK_ATTRIBUTE **attrs,
                                        CK_ULONG *num_attrs,
                                        void *private)
{
    UNUSED(private);
    UNUSED(keytype);

    return add_attribute(CKA_IBM_KYBER_KEYFORM,
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

static const struct p11sak_attr *find_attr_by_letter(char letter)
{
    const struct p11sak_attr *attr;

    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++) {
        if (attr->letter == toupper(letter))
            return attr;
    }

    return NULL;
}

static bool attr_applicaple_for_keytype(const struct p11sak_keytype *keytype,
                                        const struct p11sak_attr *attr)
{
    switch (attr->type) {
    case CKA_SIGN:
    case CKA_SIGN_RECOVER:
    case CKA_VERIFY:
    case CKA_VERIFY_RECOVER:
        return keytype->sign_verify;

    case CKA_ENCRYPT:
    case CKA_DECRYPT:
        return keytype->encrypt_decrypt;

    case CKA_WRAP:
    case CKA_WRAP_WITH_TRUSTED:
    case CKA_UNWRAP:
        return keytype->wrap_unwrap;

    case CKA_DERIVE:
        return keytype->derive;

    default:
        return true;
    }
}

static bool secret_attr_applicable(const struct p11sak_keytype *keytype,
                                   const struct p11sak_attr *attr)
{
    return attr->secret && attr_applicaple_for_keytype(keytype, attr);
}

static bool public_attr_applicable(const struct p11sak_keytype *keytype,
                                   const struct p11sak_attr *attr)
{
    UNUSED(keytype);

    return attr->public && attr_applicaple_for_keytype(keytype, attr);
}

static bool private_attr_applicable(const struct p11sak_keytype *keytype,
                                    const struct p11sak_attr *attr)
{
    UNUSED(keytype);

    return attr->private && attr_applicaple_for_keytype(keytype, attr);
}

static CK_RV parse_boolean_attrs(const struct p11sak_keytype *keytype,
                                 const char *attr_string, CK_ATTRIBUTE **attrs,
                                 CK_ULONG *num_attrs, bool check_settable,
                                 bool (*attr_aplicable)(
                                         const struct p11sak_keytype *keytype,
                                         const struct p11sak_attr *attr))
{
    const struct p11sak_attr *attr;
    unsigned int i = 0;
    CK_BBOOL val;
    CK_RV rc;

    if (attr_string == NULL)
        return CKR_OK;

    for (i = 0; attr_string[i] != '\0'; i++) {
        attr = find_attr_by_letter(attr_string[i]);
        if (attr == NULL) {
            warnx("Attribute '%c' is not valid", attr_string[i]);
            return CKR_ARGUMENTS_BAD;
        }

        /* silently ignore attributes that are not settable or not applicable */
        if ((check_settable && !attr->settable) ||
            (attr_aplicable != NULL && keytype != NULL &&
             !attr_aplicable(keytype, attr)))
            continue;

        val = isupper(attr_string[i]) ? CK_TRUE : CK_FALSE;

        rc = add_attribute(attr->type, &val, sizeof(val), attrs, num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

    return CKR_OK;
}

static CK_RV parse_id(const char *id_string, CK_ATTRIBUTE **attrs,
                      CK_ULONG *num_attrs)
{
    unsigned char *buf = NULL;
    BIGNUM *b = NULL;
    int len;
    CK_RV rc = CKR_OK;

    len = BN_hex2bn(&b, id_string);
    if (len < (int)strlen(id_string)) {
        warnx("Hex string '%s' is not valid", id_string);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    len = len / 2 + (len % 2 > 0 ? 1 : 0);
    buf = calloc(1, len);
    if (buf == NULL) {
        warnx("Failed to allocate memory for CKA_ID attribute");
        rc = CKR_HOST_MEMORY;
        goto done;
    }

    if (BN_bn2binpad(b, buf, len) != len) {
        warnx("Failed to prepare the value for CKA_ID attribute");
        rc = CKR_FUNCTION_FAILED;
        goto done;
    }

    rc = add_attribute(CKA_ID, buf, len, attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add attribute CKA_ID: 0x%lX: %s", rc, p11_get_ckr(rc));
        goto done;
    }

done:
    if (buf != NULL)
        free(buf);
    if (b != NULL)
        BN_free(b);

    return rc;
}

static CK_RV add_attributes(const struct p11sak_keytype *keytype,
                            CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                            const char *label, const char *attr_string,
                            const char *id, bool is_sensitive,
                            CK_RV (*add_attrs)(
                                    const struct p11sak_keytype *keytype,
                                    CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                    void *private),
                            void *private,
                            bool (*attr_aplicable)(
                                    const struct p11sak_keytype *keytype,
                                    const struct p11sak_attr *attr))
{
    const CK_BBOOL ck_true = TRUE;
    bool found;
    CK_ULONG i;
    CK_RV rc;

    rc = add_attribute(CKA_LABEL, label, strlen(label), attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add %s key attribute CKA_LABEL: 0x%lX: %s",
              keytype->name, rc, p11_get_ckr(rc));
        return rc;
    }

    rc = add_attribute(CKA_TOKEN, &ck_true, sizeof(ck_true), attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to add %s key attribute CKA_TOKEN: 0x%lX: %s",
              keytype->name, rc, p11_get_ckr(rc));
        return rc;
    }

    rc = parse_boolean_attrs(keytype, attr_string, attrs, num_attrs,
                             true, attr_aplicable);
    if (rc != CKR_OK)
        return rc;

    if (id != NULL) {
        rc = parse_id(id, attrs, num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

    if (add_attrs != NULL) {
        rc = add_attrs(keytype, attrs, num_attrs, private);
        if (rc != CKR_OK) {
            warnx("Failed to add %s key attributes: 0x%lX: %s",
                  keytype->name, rc, p11_get_ckr(rc));
            return rc;
        }
    }

    if (is_sensitive) {
        /* Add CKA_SENSITIVE=TRUE if its not already in attribute list */
        for (i = 0, found = false; i < *num_attrs && !found; i++) {
            if ((*attrs)[i].type == CKA_SENSITIVE)
                found = true;
        }

        if (!found) {
            rc = add_attribute(CKA_SENSITIVE, &ck_true, sizeof(ck_true),
                               attrs, num_attrs);
            if (rc != CKR_OK) {
                warnx("Failed to add %s key attribute CKA_SENSITIVE: 0x%lX: %s",
                      keytype->name, rc, p11_get_ckr(rc));
                return rc;
            }
        }
    }

    return CKR_OK;
}

static void free_attributes(CK_ATTRIBUTE *attrs, CK_ULONG num_attrs)
{
    CK_ULONG i;

    if (attrs == NULL)
        return;

    for (i = 0; i < num_attrs; i++) {
        if (attrs[i].pValue != NULL)
            free(attrs[i].pValue);
    }

    free(attrs);
}

static bool is_attr_array_attr(CK_ATTRIBUTE *attr)
{
    switch (attr->type) {
    case CKA_WRAP_TEMPLATE:
    case CKA_UNWRAP_TEMPLATE:
    case CKA_DERIVE_TEMPLATE:
        return true;

    default:
        return false;
    }
}

static void free_attr_array_attr(CK_ATTRIBUTE *attr)
{
    CK_ULONG i, num;
    CK_ATTRIBUTE *elem;

    num = attr->ulValueLen / sizeof(CK_ATTRIBUTE);
    for (i = 0, elem = attr->pValue; elem != NULL && i < num; i++, elem++) {
        if (elem->pValue != NULL) {
            if (is_attr_array_attr(elem))
                free_attr_array_attr(elem);
            free(elem->pValue);
            elem->pValue = NULL;
        }
    }
}

static CK_RV alloc_attr_array_attr(CK_ATTRIBUTE *attr, bool *allocated)
{
    CK_ULONG i, num;
    CK_ATTRIBUTE *elem;
    CK_RV rc;

    *allocated = false;

    num = attr->ulValueLen / sizeof(CK_ATTRIBUTE);
    for (i = 0, elem = attr->pValue; i < num; i++, elem++) {
        if (elem->ulValueLen > 0 && elem->pValue == NULL) {
            elem->pValue = calloc(elem->ulValueLen, 1);
            if (elem->pValue == NULL) {
                free_attr_array_attr(attr);
                return CKR_HOST_MEMORY;
            }

            *allocated = true;
            continue;
        }

        if (is_attr_array_attr(elem)) {
            rc = alloc_attr_array_attr(elem, allocated);
            if (rc != CKR_OK) {
                free_attr_array_attr(attr);
                return CKR_HOST_MEMORY;
            }
        }
    }

    return CKR_OK;
}

static CK_RV get_attribute(CK_OBJECT_HANDLE key, CK_ATTRIBUTE *attr)
{
    bool allocated;
    CK_RV rc;

    rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key, attr, 1);
    if (rc != CKR_OK)
        return rc;

    if (attr->pValue == NULL && attr->ulValueLen > 0) {
        attr->pValue = calloc(attr->ulValueLen, 1);
        if (attr->pValue == NULL)
            return CKR_HOST_MEMORY;

        rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key, attr, 1);
    }

    if (is_attr_array_attr(attr) && rc == CKR_OK &&
        attr->pValue != NULL && attr->ulValueLen > 0) {
        do {
            allocated = false;
            rc = alloc_attr_array_attr(attr, &allocated);
            if (rc != CKR_OK)
                return rc;

            if (!allocated)
                break;

            rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key,
                                                   attr, 1);
        } while (rc == CKR_OK);
    }

    return rc;
}

static const struct p11sak_keytype *find_keytype(CK_KEY_TYPE ktype)
{
    const struct p11sak_keytype **kt;

    for (kt = p11sak_keytypes; (*kt)->name != NULL; kt++) {
        if ((*kt)->type == ktype)
            return *kt;
    }

    return NULL;
}

static CK_RV get_key_infos(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS *class,
                           CK_KEY_TYPE *ktype, CK_ULONG *keysize,
                           char** label, char** typestr,
                           const struct p11sak_keytype **keytype)
{
    CK_RV rc;
    CK_ULONG i;
    CK_OBJECT_CLASS class_val = 0;
    CK_KEY_TYPE ktype_val = 0;
    CK_ATTRIBUTE attrs[] = {
        { CKA_LABEL, NULL, 0 }, /* label must be first one */
        { CKA_CLASS, &class_val, sizeof(class_val) },
        { CKA_KEY_TYPE, &ktype_val, sizeof(ktype_val) },
    };
    const CK_ULONG num_attrs = sizeof(attrs) / sizeof(CK_ATTRIBUTE);
    const struct p11sak_keytype *keytype_val;
    CK_ULONG keysize_val = 0;
    CK_ATTRIBUTE keysize_attr;
    int rv;

    rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key,
                                           attrs, num_attrs);
    if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID &&
        rc != CKR_ATTRIBUTE_SENSITIVE) {
        warnx("Failed to get attributes: C_GetAttributeValue: 0x%lX: %s",
              rc, p11_get_ckr(rc));
        return rc;
    }

    if (attrs[0].ulValueLen != 0 &&
        attrs[0].ulValueLen != CK_UNAVAILABLE_INFORMATION) {
        attrs[0].pValue = calloc(attrs[0].ulValueLen + 1, 1);
        if (attrs[0].pValue == NULL) {
            warnx("Failed to allocate memory for label attribute");
            return CKR_HOST_MEMORY;
        }

        rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key,
                                               attrs, num_attrs);
        if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID &&
            rc != CKR_ATTRIBUTE_SENSITIVE) {
            warnx("Failed to get attributes: C_GetAttributeValue: 0x%lX: %s",
                  rc, p11_get_ckr(rc));
            free(attrs[0].pValue);
            return rc;
        }
    } else {
        attrs[0].pValue = strdup("");
        if (attrs[0].pValue == NULL) {
            warnx("Failed to allocate memory for label attribute");
            return CKR_HOST_MEMORY;
        }
    }

    for (i = 0; i < num_attrs; i++) {
        if (attrs[i].ulValueLen == CK_UNAVAILABLE_INFORMATION) {
            warnx("Attribute %s is not available in key object",
                  p11_get_cka(attrs[i].type));
            free(attrs[0].pValue);
            return CKR_TEMPLATE_INCOMPLETE;
        }
    }

    if (class != NULL)
        *class = class_val;
    if (ktype != NULL)
        *ktype = ktype_val;

    keytype_val = find_keytype(ktype_val);
    if (keytype_val == NULL) {
        warnx("Key object \"%s\" has an unsupported key type: %lu",
              (char *)attrs[0].pValue, ktype_val);
        free(attrs[0].pValue);
        return CKR_KEY_TYPE_INCONSISTENT;
    }

    if (keytype != NULL)
        *keytype = keytype_val;

    if (keytype_val->keysize_attr != (CK_ATTRIBUTE_TYPE)-1) {
        keysize_attr.type = keytype_val->keysize_attr;
        if (!keytype_val->keysize_attr_value_len) {
            keysize_attr.ulValueLen = sizeof(keysize_val);
            keysize_attr.pValue = &keysize_val;
        } else {
            /* Query attribute length only */
            keysize_attr.ulValueLen = 0;
            keysize_attr.pValue = NULL;
        }
        rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key,
                                               &keysize_attr, 1);
        if (rc != CKR_OK) {
            warnx("Attribute %s is not available in key object",
                  p11_get_cka( keysize_attr.type));
            free(attrs[0].pValue);
            return rc;
        }

        if (keytype_val->keysize_attr_value_len)
            keysize_val = keysize_attr.ulValueLen;

        if (keytype_val->key_keysize_adjust != NULL)
            keysize_val = keytype_val->key_keysize_adjust(keytype_val,
                                                          keysize_val);
    }

    if (keysize != NULL)
        *keysize = keysize_val;

    if (typestr != NULL) {
        switch (class_val) {
        case CKO_SECRET_KEY:
            if (keysize_val != 0)
                rv = asprintf(typestr, "%s %lu", keytype_val->name, keysize_val);
            else
                rv = asprintf(typestr, "%s", keytype_val->name);
            break;
        case CKO_PUBLIC_KEY:
            if (keysize_val != 0)
                rv = asprintf(typestr, "public %s %lu", keytype_val->name, keysize_val);
            else
                rv = asprintf(typestr, "public %s", keytype_val->name);
            break;
        case CKO_PRIVATE_KEY:
            if (keysize_val != 0)
                rv = asprintf(typestr, "private %s %lu", keytype_val->name, keysize_val);
            else
                rv = asprintf(typestr, "private %s", keytype_val->name);
            break;
        default:
            warnx("Key object \"%s\" has an unsupported object class: %lu",
                  (char *)attrs[0].pValue, class_val);
            free(attrs[0].pValue);
            return CKR_KEY_TYPE_INCONSISTENT;
        }
        if (*typestr == NULL || rv < 0) {
            warnx("Failed to allocate type string buffer");
            free(attrs[0].pValue);
            return CKR_HOST_MEMORY;
        }
    }

    if (label != NULL)
        *label = attrs[0].pValue;
    else
        free(attrs[0].pValue);

    return CKR_OK;
}


static int iterate_compare(const void *a, const void *b, void *private)
{
    struct p11sak_iterate_compare_data *data = private;
    const CK_OBJECT_HANDLE *key1 = a;
    const CK_OBJECT_HANDLE *key2 = b;
    int result = 0;
    CK_RV rc;

    if (data->rc!= CKR_OK)
        return 0;

    rc = data->compare_key(*key1, *key2, &result, data->private);
    if (rc != CKR_OK)
        data->rc = rc;

    return result;
}

static CK_RV iterate_key_objects(const struct p11sak_keytype *keytype,
                                 const char *label_filter,
                                 const char *id_filter,
                                 const char *attr_filter,
                                 CK_RV (*compare_key)(CK_OBJECT_HANDLE key1,
                                                      CK_OBJECT_HANDLE key2,
                                                      int *result,
                                                      void *private),
                                 CK_RV (*handle_key)(CK_OBJECT_HANDLE key,
                                                     CK_OBJECT_CLASS class,
                                                     const struct p11sak_keytype *keytype,
                                                     CK_ULONG keysize,
                                                     const char *typestr,
                                                     const char* label,
                                                     void *private),
                                 void *private)
{
    CK_RV rc, rc2;
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    const CK_BBOOL ck_true = CK_TRUE;
    CK_OBJECT_HANDLE keys[FIND_OBJECTS_COUNT];
    CK_ULONG i, num_keys;
    bool manual_filtering = false;
    CK_OBJECT_CLASS class;
    CK_KEY_TYPE ktype;
    CK_ULONG keysize = 0;
    char *label = NULL;
    char *typestr = NULL;
    const struct p11sak_keytype *type;
    CK_OBJECT_HANDLE *matched_keys = NULL, *tmp;
    CK_ULONG num_matched_keys = 0;
    CK_ULONG alloc_matched_keys = 0;
    struct p11sak_iterate_compare_data data;

    rc = add_attribute(CKA_TOKEN, &ck_true, sizeof(ck_true), &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    if (keytype != NULL && keytype->filter_attr != (CK_ATTRIBUTE_TYPE)-1) {
        rc = add_attribute(keytype->filter_attr, &keytype->filter_value,
                           sizeof(keytype->filter_value), &attrs, &num_attrs);
        if (rc != CKR_OK)
            goto done;
    }

    if (label_filter != NULL) {
        manual_filtering = (strpbrk(label_filter, "*?\\") != NULL);
        if (!manual_filtering) {
            /* add label filter only if no escapes are used */
            rc = add_attribute(CKA_LABEL, label_filter, strlen(label_filter),
                               &attrs, &num_attrs);
            if (rc != CKR_OK)
                goto done;
        }
    }

    if (id_filter != NULL) {
        rc = parse_id(id_filter, &attrs, &num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

    if (attr_filter != NULL) {
        rc = parse_boolean_attrs(NULL, opt_attr, &attrs, &num_attrs,
                                 false, NULL);
        if (rc != CKR_OK)
            return rc;
    }

    rc = pkcs11_funcs->C_FindObjectsInit(pkcs11_session, attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to initialize the find operation: C_FindObjectsInit: 0x%lX: %s",
              rc, p11_get_ckr(rc));
        goto done;
    }

    while (1) {
        memset(keys, 0, sizeof(keys));
        num_keys = 0;

        rc = pkcs11_funcs->C_FindObjects(pkcs11_session, keys,
                                         FIND_OBJECTS_COUNT, &num_keys);
        if (rc != CKR_OK) {
            warnx("Failed to find objects: C_FindObjects: 0x%lX: %s",
                  rc, p11_get_ckr(rc));
            goto done_find;
        }

        if (num_keys == 0)
            break;

        for (i = 0; i < num_keys; i++) {
            if (manual_filtering) {
                rc = get_key_infos(keys[i], NULL, NULL, NULL, &label,
                                   NULL, NULL);
                if (rc != CKR_OK)
                    break;

                if (fnmatch(label_filter, label, 0) != 0)
                    goto next;
            }

            if (num_matched_keys >= alloc_matched_keys) {
                tmp = realloc(matched_keys,
                              (alloc_matched_keys + FIND_OBJECTS_COUNT) *
                                                  sizeof(CK_OBJECT_HANDLE));
                if (tmp == NULL) {
                    warnx("Failed to allocate a list of matched keys.");
                    rc = CKR_HOST_MEMORY;
                    goto done_find;
                }

                matched_keys = tmp;
                alloc_matched_keys += FIND_OBJECTS_COUNT;
            }

            matched_keys[num_matched_keys++] = keys[i];

next:
            if (label != NULL)
                free(label);
            label = NULL;
        }
    }

done_find:
    rc2 = pkcs11_funcs->C_FindObjectsFinal(pkcs11_session);
    if (rc2 != CKR_OK) {
        warnx("Failed to finalize the find operation: C_FindObjectsFinal: 0x%lX: %s",
              rc2, p11_get_ckr(rc2));
        if (rc == CKR_OK)
            rc = rc2;
    }

    if (rc != CKR_OK)
        goto done;

    if (compare_key != NULL && num_matched_keys > 0) {
        data.compare_key = compare_key;
        data.private = private;
        data.rc = CKR_OK;

        qsort_r(matched_keys, num_matched_keys, sizeof(CK_OBJECT_HANDLE),
                iterate_compare, &data);

        rc = data.rc;
        if (rc != CKR_OK)
            goto done;
    }

    for (i = 0; i < num_matched_keys; i++) {
        rc = get_key_infos(matched_keys[i], &class, &ktype, &keysize,
                           &label, &typestr, &type);
        if (rc != CKR_OK)
            break;

        rc = handle_key(matched_keys[i], class, type, keysize, typestr, label,
                        private);
        if (rc != CKR_OK)
            break;

        if (label != NULL)
            free(label);
        label = NULL;
        if (typestr != NULL)
            free(typestr);
        typestr = NULL;
    }

done:
    free_attributes(attrs, num_attrs);

    if (label != NULL)
        free(label);
    if (typestr != NULL)
        free(typestr);
    if (matched_keys != NULL)
        free(matched_keys);

    return rc;
}

static CK_RV p11sak_generate_key(void)
{
    const struct p11sak_keytype *keytype;
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

    rc = check_mech_supported(keytype, keysize);
    if (rc != CKR_OK)
        goto done;

    if (keytype->is_asymmetric) {
        rc = parse_key_pair_label(opt_label, &pub_label, &priv_label);
        if (rc != CKR_OK)
            goto done;

        rc = parse_key_pair_attrs(opt_attr, &pub_attrs, &priv_attrs);
        if (rc != CKR_OK)
            goto done;

        rc = add_attributes(keytype, &public_attrs, &num_public_attrs,
                            pub_label, pub_attrs, opt_id, false,
                            keytype->keygen_add_public_attrs, private,
                            public_attr_applicable);
        if (rc != CKR_OK)
            goto done;

        rc = add_attributes(keytype, &private_attrs, &num_private_attrs,
                            priv_label, priv_attrs, opt_id, true,
                            keytype->keygen_add_private_attrs, private,
                            private_attr_applicable);
        if (rc != CKR_OK)
            goto done;
    } else {
        rc = add_attributes(keytype, &secret_attrs, &num_secret_attrs,
                            opt_label, opt_attr, opt_id, true,
                            keytype->keygen_add_secret_attrs, private,
                            secret_attr_applicable);
        if (rc != CKR_OK)
            goto done;
    }

    if (keytype->is_asymmetric)
        rc = pkcs11_funcs->C_GenerateKeyPair(pkcs11_session,
                                             (CK_MECHANISM *)&keytype->keygen_mech,
                                             public_attrs, num_public_attrs,
                                             private_attrs, num_private_attrs,
                                             &pub_key, &priv_key);
     else
         rc = pkcs11_funcs->C_GenerateKey(pkcs11_session,
                                          (CK_MECHANISM *)&keytype->keygen_mech,
                                          secret_attrs, num_secret_attrs,
                                          &secret_key);
    if (rc != CKR_OK) {
        if (is_rejected_by_policy(rc, pkcs11_session)) {
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

    free_attributes(secret_attrs, num_secret_attrs);
    free_attributes(public_attrs, num_public_attrs);
    free_attributes(private_attrs, num_private_attrs);

    return rc;
}

static void print_bool_attr_short(const CK_ATTRIBUTE *val, bool applicable)
{
    if (val->ulValueLen == CK_UNAVAILABLE_INFORMATION ||
        val->ulValueLen != sizeof(CK_BBOOL))
        applicable = false;
    printf("%c ", applicable ? (*(CK_BBOOL *)(val->pValue) ? '1' : '0') : '-');
}

static void print_bool_attr_long(const char *attr, const CK_ATTRIBUTE *val,
                                 int indent, bool sensitive)
{
    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive)||
        val->ulValueLen != sizeof(CK_BBOOL))
        return;

    printf("%*s%s: %s\n", indent, "", attr,
           sensitive ? "[sensitive]" :
                   *(CK_BBOOL *)(val->pValue) ? "CK_TRUE" : "CK_FALSE");
}

static void print_utf8_attr(const char *attr, const CK_ATTRIBUTE *val,
                            int indent, bool sensitive)
{
    if (val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
    } else {
        printf("%*s%s: \"%.*s\"\n", indent, "", attr, (int)val->ulValueLen,
               (char *)val->pValue);
    }
}

static void print_dump(CK_BYTE *p, CK_ULONG len, int indent)
{
    CK_ULONG i;

    for (i = 0; i < len; i++) {
        if (i % 16 == 0)
            printf("\n%*s%02X ", indent, "", p[i]);
        else
            printf("%02X ", p[i]);
    }
    printf("\n");
}

static void print_byte_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive)
{
    if (val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
    } else {
        printf("%*s%s: len=%lu value:", indent, "", attr,
               val->ulValueLen);
        print_dump((CK_BYTE *)val->pValue, val->ulValueLen, indent + 4);
    }
}

static void print_ulong_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive)
{
    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_ULONG))
        return;

    if (sensitive)
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    else
        printf("%*s%s: %lu (0x%lX)\n", indent, "", attr,
               *(CK_ULONG *)(val->pValue), *(CK_ULONG *)(val->pValue));
}

static void print_date_attr(const char *attr, const CK_ATTRIBUTE *val,
                            int indent, bool sensitive)
{
    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_DATE))
        return;

    if (sensitive)
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    else
        printf("%*s%s: %.4s-%.2s-%.2s\n", indent, "", attr,
               ((CK_DATE *)(val->pValue))->year,
               ((CK_DATE *)(val->pValue))->month,
               ((CK_DATE *)(val->pValue))->day);
}

static void print_mech_attr(const char *attr, const CK_ATTRIBUTE *val,
                            int indent, bool sensitive)
{
    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_MECHANISM_TYPE))
        return;

    if (sensitive)
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    else if (*(CK_MECHANISM_TYPE *)(val->pValue) == CK_UNAVAILABLE_INFORMATION)
        printf("%*s%s: [information unavailable]\n", indent, "", attr);
    else
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr,
               p11_get_ckm(&mechtable_funcs,
                           *(CK_MECHANISM_TYPE *)(val->pValue)),
               *(CK_MECHANISM_TYPE *)(val->pValue));
}

static void print_mech_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive)
{
    unsigned int i, num;

    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        (val->ulValueLen % sizeof(CK_MECHANISM_TYPE)) != 0)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else {
        num = val->ulValueLen / sizeof(CK_MECHANISM_TYPE);
        if (num == 0 && val->type == CKA_ALLOWED_MECHANISMS) {
            printf("%*s%s: [no restriction]\n", indent, "", attr);
            return;
        }

        printf("%*s%s: %u mechanisms\n", indent, "", attr, num);
        for (i = 0; i < num; i++) {
            printf("%*s- %s (0x%lX)\n", indent + 4, "",
                   p11_get_ckm(&mechtable_funcs,
                               ((CK_MECHANISM_TYPE *)(val->pValue))[i]),
                   ((CK_MECHANISM_TYPE *)(val->pValue))[i]);
        }
    }
}

static void print_oid(const CK_BYTE *oid, CK_ULONG oid_len, bool long_name)
{
    ASN1_OBJECT *obj = NULL;
    char buf[250];
    int nid;

    if (d2i_ASN1_OBJECT(&obj, &oid, oid_len) == NULL) {
        printf("[invalid object ID]");
        return;
    }

    nid = OBJ_obj2nid(obj);

    if (OBJ_obj2txt(buf, sizeof(buf), obj, 1) <= 0) {
        printf("[error]");
        ASN1_OBJECT_free(obj);
        return;
    }

    printf("oid=%s", buf);
    if (long_name && nid != NID_undef)
        printf(" (%s)", OBJ_nid2ln(nid));

    ASN1_OBJECT_free(obj);
}

static void print_ibm_dilithium_keyform_attr(const char *attr,
                                             const CK_ATTRIBUTE *val,
                                             int indent, bool sensitive)
{
    const struct p11sak_enum_value *eval;
    const char *name = "[unknown]";

    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION ||
         val->ulValueLen != sizeof (CK_ULONG)) &&
        !sensitive)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
    } else {
        for (eval = p11sak_ibm_dilithium_versions; eval->value != NULL; eval++) {
            if (eval->private.num == *(CK_ULONG *)(val->pValue)) {
                name = eval->value;
                break;
            }
        }
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr, name,
               *(CK_ULONG *)(val->pValue));
    }
}

static void print_ibm_kyber_keyform_attr(const char *attr,
                                         const CK_ATTRIBUTE *val,
                                         int indent, bool sensitive)
{
    const struct p11sak_enum_value *eval;
    const char *name = "[unknown]";

    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION ||
         val->ulValueLen != sizeof (CK_ULONG)) &&
        !sensitive)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
    } else {
        for (eval = p11sak_ibm_kyber_versions; eval->value != NULL; eval++) {
            if (eval->private.num == *(CK_ULONG *)(val->pValue)) {
                name = eval->value;
                break;
            }
        }
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr, name,
               *(CK_ULONG *)(val->pValue));
    }
}

static void print_class_attr(const char *attr, const CK_ATTRIBUTE *val,
                             int indent, bool sensitive)
{
    const struct p11sak_class *cls;
    const char *name = NULL;

    if ((val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive) ||
        val->ulValueLen != sizeof(CK_OBJECT_CLASS))
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
        return;
    }

    for (cls = p11sak_classes; cls->name  != NULL; cls++) {
        if (*(CK_OBJECT_CLASS *)(val->pValue) == cls->class) {
            name = cls->name;
            break;
        }
    }

    if (name != NULL)
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr, name,
               *(CK_OBJECT_CLASS *)(val->pValue));
    else
        printf("%*s%s: 0x%lX\n", indent, "", attr,
               *(CK_OBJECT_CLASS *)(val->pValue));
}

static void print_key_type_attr(const char *attr, const CK_ATTRIBUTE *val,
                                int indent, bool sensitive)
{
    const struct p11sak_keytype *ktype;
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
        name = ktype->ckk_name;

    if (name != NULL)
        printf("%*s%s: %s (0x%lX)\n", indent, "", attr, name,
               *(CK_KEY_TYPE *)(val->pValue));
    else
        printf("%*s%s: 0x%lX\n", indent, "", attr,
               *(CK_KEY_TYPE *)(val->pValue));
}

static void print_oid_attr(const char *attr, const CK_ATTRIBUTE *val,
                           int indent, bool sensitive)
{
    if (val->ulValueLen == CK_UNAVAILABLE_INFORMATION && !sensitive)
        return;

    if (sensitive) {
        printf("%*s%s: [sensitive]\n", indent, "", attr);
    } else if (val->ulValueLen == 0) {
        printf("%*s%s: [no value]\n", indent, "", attr);
    } else {
        printf("%*s%s: ", indent, "", attr);
        print_oid(val->pValue, val->ulValueLen, true);
        printf(" len=%lu value:", val->ulValueLen);
        print_dump((CK_BYTE *)val->pValue,val->ulValueLen, indent + 4);
    }
}

static const struct p11sak_attr *find_attribute(CK_ATTRIBUTE_TYPE type)
{
    const struct p11sak_attr *attr;
    const struct p11sak_keytype **keytype;

    for (attr = p11sak_bool_attrs; attr->name != NULL; attr++) {
        if (attr->type == type)
            return attr;
    }

    for (keytype = p11sak_keytypes; (*keytype)->name != NULL; keytype++) {
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

    return NULL;
}

static void print_attr_array_attr(const char *attr, const CK_ATTRIBUTE *val,
                                  int indent, bool sensitive)
{
    const struct p11sak_attr *a;
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
                               const struct p11sak_attr *standard_attrs,
                               int indent)
{
    CK_RV rc;
    int f;
    struct ConfigBaseNode *c, *name, *id, *type;
    struct ConfigStructNode *structnode;
    const struct p11sak_custom_attr_type *atype;
    const struct p11sak_attr *attr;
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
        for (skip = false, attr = standard_attrs; attr->name != NULL; attr++) {
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
        rc = get_attribute(key, &val);
        if (rc != CKR_OK && rc != CKR_ATTRIBUTE_SENSITIVE)
            continue;

        atype->print_long(p11_get_cka(confignode_to_intval(id)->value),
                          &val, indent, rc == CKR_ATTRIBUTE_SENSITIVE);

        if (is_attr_array_attr(&val))
            free_attr_array_attr(&val);
        if (val.pValue != NULL)
            free(val.pValue);
    }
}

static void print_key_attrs(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                            const struct p11sak_keytype *keytype, int indent)
{
    const struct p11sak_attr *attrs, *attr;
    CK_ATTRIBUTE val;
    CK_RV rc;

    switch (class) {
    case CKO_SECRET_KEY:
        attrs = keytype->secret_attrs;
        break;
    case CKO_PUBLIC_KEY:
        attrs = keytype->public_attrs;
        break;
    case CKO_PRIVATE_KEY:
        attrs = keytype->private_attrs;
        break;
    default:
        attrs = NULL;
        break;
    }

    for (attr = attrs; attr != NULL && attr->name != NULL; attr++) {
        val.type = attr->type;
        val.ulValueLen = 0;
        val.pValue = NULL;

        rc = get_attribute(key, &val);
        if (rc != CKR_OK && rc != CKR_ATTRIBUTE_SENSITIVE)
            continue;

        attr->print_long(attr->name, &val, indent,
                         rc == CKR_ATTRIBUTE_SENSITIVE);

        if (is_attr_array_attr(&val))
            free_attr_array_attr(&val);
        if (val.pValue != NULL)
            free(val.pValue);
    }

    print_custom_attrs(key, attrs, indent);
}

static CK_RV print_boolean_attrs(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                                 const struct p11sak_keytype *keytype,
                                 const char *typestr, const char* label,
                                 struct p11sak_list_data *data)
{
    const struct p11sak_attr *attr;
    bool applicable;
    CK_ULONG i;
    CK_RV rc;

    rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key,
                                           data->bool_attrs,
                                           data->num_bool_attrs);
    if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID) {
        warnx("Failed to get boolean attributes for %s key \"%s\": 0x%lX: %s",
              typestr, label, rc, p11_get_ckr(rc));
        return rc;
    }

    for (attr = p11sak_bool_attrs, i = 0; attr->name != NULL; attr++, i++) {
        switch (class) {
        case CKO_SECRET_KEY:
            applicable = secret_attr_applicable(keytype, attr);
            break;
        case CKO_PUBLIC_KEY:
            applicable = public_attr_applicable(keytype, attr);
            break;
        case CKO_PRIVATE_KEY:
            applicable = private_attr_applicable(keytype, attr);
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

static CK_RV prepare_uri(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS *class,
                         const char *typestr, const char* label,
                         struct p11_uri **uri)
{
    struct p11_uri *u;
    CK_RV rc;

    u = p11_uri_new();
    if (u == NULL) {
        warnx("Failed to allocate URI for %s key \"%s\"", typestr, label);
        return CKR_HOST_MEMORY;
    }

    if (opt_detailed_uri) {
        /* include library and slot information only in detailed URIs */
        u->info = &pkcs11_info;
        u->slot_id = opt_slot;
        u->slot_info = &pkcs11_slotinfo;
    }
    u->token_info = &pkcs11_tokeninfo;

    u->obj_class[0].ulValueLen = sizeof(*class);
    u->obj_class[0].pValue = class;

    u->obj_label[0].ulValueLen = label != NULL ? strlen(label) : 0;
    u->obj_label[0].pValue = (char *)label;

    rc = get_attribute(key, &u->obj_id[0]);
    if (rc != CKR_OK) {
        warnx("Failed to get CKA_ID for %s key \"%s\": 0x%lX: %s",
              typestr, label, rc, p11_get_ckr(rc));
        if (u->obj_id[0].pValue != NULL)
            free(u->obj_id[0].pValue);
        p11_uri_free(u);
        return rc;
    }

    *uri = u;

    return CKR_OK;
}

static CK_RV handle_key_list(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                             const struct p11sak_keytype *keytype,
                             CK_ULONG keysize, const char *typestr,
                             const char* label, void *private)
{
    struct p11sak_list_data *data = private;
    struct p11_uri *uri = NULL;
    CK_RV rc;

    UNUSED(keysize);

    rc = pkcs11_funcs->C_GetAttributeValue(pkcs11_session, key,
                                           data->bool_attrs,
                                           data->num_bool_attrs);
    if (rc != CKR_OK && rc != CKR_ATTRIBUTE_TYPE_INVALID) {
        warnx("Failed to get boolean attributes for %s key \"%s\": 0x%lX: %s",
              typestr, label, rc, p11_get_ckr(rc));
        return rc;
    }

    if (opt_long) {
        rc = prepare_uri(key, &class, typestr, label, &uri);
        if (rc != CKR_OK)
            goto done;

        printf("Label: \"%s\"\n", label);
        printf("    URI: %s\n", p11_uri_format(uri));
        printf("    Key: %s\n", typestr);
        printf("    Attributes:\n");
        printf("        CKA_TOKEN: CK_TRUE\n");
    } else {
        printf("| ");
    }

    rc = print_boolean_attrs(key, class, keytype, typestr, label, data);
    if (rc != CKR_OK)
        goto done;

    if (opt_long)
        print_key_attrs(key, class, keytype, 8);
    else
        printf("| %*s | \"%s\"\n", LIST_KEYTYPE_CELL_SIZE, typestr, label);

    data->num_displayed++;
    rc = CKR_OK;

done:
    if (uri != NULL) {
        if (uri->obj_id[0].pValue != NULL)
            free(uri->obj_id[0].pValue);
        p11_uri_free(uri);
    }

    return rc;
}

static CK_RV p11sak_list_key_compare(CK_OBJECT_HANDLE key1,
                                     CK_OBJECT_HANDLE key2,
                                     int *result, void *private)
{
    struct p11sak_list_data *data = private;
    CK_OBJECT_CLASS class1, class2;
    CK_KEY_TYPE ktype1, ktype2;
    CK_ULONG keysize1, keysize2;
    char *label1 = NULL, *label2 = NULL;
    CK_RV rc;
    int i;

    *result = 0;

    rc = get_key_infos(key1, &class1, &ktype1, &keysize1, &label1, NULL, NULL);
    if (rc != CKR_OK)
        goto done;

    rc = get_key_infos(key2, &class2, &ktype2, &keysize2, &label2, NULL, NULL);
    if (rc != CKR_OK)
        goto done;

    for (i = 0; i < MAX_SORT_FIELDS; i++) {
        switch (data->sort_info[i].field) {
        case SORT_LABEL:
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
    const struct p11sak_keytype *keytype = NULL;
    const struct p11sak_attr *attr;
    struct p11sak_list_data data = { 0 };
    unsigned int i;
    CK_BYTE *attr_data = NULL;
    CK_RV rc;

    if (opt_keytype != NULL)
        keytype = opt_keytype->private.ptr;

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

    if (opt_sort) {
        rc = parse_sort_specification(opt_sort, &data);
        if (rc != CKR_OK)
            goto done;
    }

    if (!opt_long) {
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

    rc = iterate_key_objects(keytype, opt_label, opt_id, opt_attr,
                             opt_sort != NULL ? p11sak_list_key_compare : NULL,
                             handle_key_list, &data);
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

static char prompt_user(const char *message, char* allowed_chars)
{
    int len;
    size_t linelen = 0;
    char *line = NULL;
    char ch = '\0';

    printf("%s", message);

    while (1) {
        len = getline(&line, &linelen, stdin);
        if (len == -1)
            break;

        if (strlen(line) == 2 && strpbrk(line, allowed_chars) != 0) {
            ch = line[0];
            break;
        }

        warnx("Improper reply, try again");
    }

    if (line != NULL)
        free(line);

    return ch;
}

static CK_RV handle_key_remove(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                               const struct p11sak_keytype *keytype,
                               CK_ULONG keysize, const char *typestr,
                               const char* label, void *private)
{
    struct p11sak_remove_data *data = private;
    char *msg = NULL;
    char ch;
    CK_RV rc;

    UNUSED(class);
    UNUSED(keysize);
    UNUSED(keytype);

    if (data->skip_all) {
        data->num_skipped++;
        return CKR_OK;
    }

    if (!data->remove_all) {
        if (asprintf(&msg, "Are you sure you want to remove %s key object \"%s\" [y/n/a/c]? ",
                     typestr, label) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return CKR_HOST_MEMORY;
        }
        ch = prompt_user(msg, "ynac");
        free(msg);

        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        case 'c':
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

    rc = pkcs11_funcs->C_DestroyObject(pkcs11_session, key);
    if (rc != CKR_OK) {
        warnx("Failed to remove %s key object \"%s\": C_DestroyObject: 0x%lX: %s",
                typestr, label, rc, p11_get_ckr(rc));
        data->num_failed++;
        return CKR_OK;
    }

    printf("Successfully removed %s key object \"%s\".\n", typestr, label);
    data->num_removed++;

    return CKR_OK;
}

static CK_RV p11sak_remove_key(void)
{
    const struct p11sak_keytype *keytype = NULL;
    struct p11sak_remove_data data = { 0 };
    CK_RV rc;

    if (opt_keytype != NULL)
        keytype = opt_keytype->private.ptr;

    data.remove_all = opt_force;

    rc = iterate_key_objects(keytype, opt_label, opt_id, opt_attr, NULL,
                             handle_key_remove, &data);
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

static CK_RV handle_key_set_attr(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                                 const struct p11sak_keytype *keytype,
                                 CK_ULONG keysize, const char *typestr,
                                 const char* label, void *private)
{
    struct p11sak_set_attr_data *data = private;
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    char *msg = NULL;
    char ch;
    CK_RV rc;
    bool (*attr_aplicable)(const struct p11sak_keytype *keytype,
                           const struct p11sak_attr *attr);

    UNUSED(keysize);

    if (data->skip_all) {
        data->num_skipped++;
        return CKR_OK;
    }

    if (!data->set_all) {
        if (asprintf(&msg, "Are you sure you want to change %s key object \"%s\" [y/n/a/c]? ",
                     typestr, label) < 0 ||
            msg == NULL) {
            warnx("Failed to allocate memory for a message");
            return CKR_HOST_MEMORY;
        }
        ch = prompt_user(msg, "ynac");
        free(msg);

        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        case 'c':
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
        attr_aplicable = secret_attr_applicable;
        break;
    case CKO_PUBLIC_KEY:
        attr_aplicable = public_attr_applicable;
        break;
    case CKO_PRIVATE_KEY:
        attr_aplicable = private_attr_applicable;
        break;
    default:
        warnx("Key object \"%s\" has an unsupported object class: %lu",
              label, class);
        rc = CKR_KEY_TYPE_INCONSISTENT;
        goto done;
    }

    if (opt_new_attr != NULL) {
        rc = parse_boolean_attrs(keytype, opt_new_attr, &attrs, &num_attrs,
                                 true, attr_aplicable);
        if (rc != CKR_OK) {
            data->num_failed++;
            goto done;
        }

        if (num_attrs == 0) {
            warnx("None of the specified attributes apply to %s key object \"%s\".",
                  typestr, label);
            data->num_skipped++;
            goto done;
        }
    }

    if (opt_new_label != NULL) {
        rc = add_attribute(CKA_LABEL, opt_new_label, strlen(opt_new_label),
                           &attrs, &num_attrs);
        if (rc != CKR_OK) {
            warnx("Failed to add %s key attribute CKA_LABEL: 0x%lX: %s",
                  keytype->name, rc, p11_get_ckr(rc));
            return rc;
        }
    }

    if (opt_new_id != NULL) {
        rc = parse_id(opt_new_id, &attrs, &num_attrs);
        if (rc != CKR_OK)
            return rc;
    }

    rc = pkcs11_funcs->C_SetAttributeValue(pkcs11_session, key,
                                           attrs, num_attrs);
    if (rc != CKR_OK) {
        warnx("Failed to change %s key object \"%s\": C_SetAttributeValue: 0x%lX: %s",
              typestr, label, rc, p11_get_ckr(rc));
        data->num_failed++;
        rc = CKR_OK;
        goto done;
    }

    printf("Successfully changed %s key object \"%s\".\n", typestr, label);
    data->num_set++;

done:
    free_attributes(attrs, num_attrs);
    return rc;
}

static CK_RV p11sak_set_key_attr(void)
{
    const struct p11sak_keytype *keytype = NULL;
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

    rc = iterate_key_objects(keytype, opt_label, opt_id, opt_attr, NULL,
                             handle_key_set_attr, &data);
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

static CK_RV load_pkcs11_lib(void)
{
    CK_RV rc;
    CK_RV (*getfunclist)(CK_FUNCTION_LIST_PTR_PTR ppFunctionList);
    const char *libname;

    libname = secure_getenv(P11SAK_PKCSLIB_ENV_NAME);
    if (libname == NULL || strlen(libname) < 1)
        libname = P11SAK_DEFAULT_PKCS11_LIB;

    pkcs11_lib = dlopen(libname, RTLD_NOW);
    if (pkcs11_lib == NULL) {
        warnx("Failed to load PKCS#11 library '%s': %s", libname, dlerror());
        return CKR_FUNCTION_FAILED;
    }

    *(void**) (&getfunclist) = dlsym(pkcs11_lib, "C_GetFunctionList");
    if (getfunclist == NULL) {
        warnx("Failed to resolve symbol '%s' from PKCS#11 library '%s': %s",
              "C_GetFunctionList", libname, dlerror());
        return CKR_FUNCTION_FAILED;
    }

    rc = getfunclist(&pkcs11_funcs);
    if (rc != CKR_OK) {
        warnx("C_GetFunctionList() on PKCS#11 library '%s' failed with 0x%lX: %s)\n",
              libname, rc, p11_get_ckr(rc));
        return CKR_FUNCTION_FAILED;
    }

    return CKR_OK;
}

static CK_RV open_pkcs11_session(CK_SLOT_ID slot, CK_FLAGS flags,
                                 const char *pin)
{
    CK_RV rc;

    rc = pkcs11_funcs->C_GetInfo(&pkcs11_info);
    if (rc != CKR_OK) {
        warnx("Failed to getPKCS#11 info: C_GetInfo: 0x%lX: %s",
              rc, p11_get_ckr(rc));
        return rc;
    }

    rc = pkcs11_funcs->C_GetSlotInfo(slot, &pkcs11_slotinfo);
    if (rc != CKR_OK) {
        warnx("Slot %lu is not available: C_GetSlotInfo: 0x%lX: %s", slot,
              rc, p11_get_ckr(rc));
        return rc;
    }

    rc = pkcs11_funcs->C_GetTokenInfo(slot, &pkcs11_tokeninfo);
    if (rc != CKR_OK) {
        warnx("Token at slot %lu is not available: C_GetTokenInfo: 0x%lX: %s",
              slot, rc, p11_get_ckr(rc));
        return rc;
    }

    rc = pkcs11_funcs->C_OpenSession(slot, flags, NULL, NULL, &pkcs11_session);
    if (rc != CKR_OK) {
        warnx("Opening a session failed: C_OpenSession: 0x%lX: %s)", rc,
              p11_get_ckr(rc));
        return rc;
    }

    rc = pkcs11_funcs->C_Login(pkcs11_session, CKU_USER, (CK_CHAR *)pin,
                               strlen(pin));
    if (rc != CKR_OK) {
        warnx("Login failed: C_Login: 0x%lX: %s", rc, p11_get_ckr(rc));
        return rc;
    }

    return CKR_OK;
}

static void close_pkcs11_session(void)
{
    CK_RV rc;

    rc = pkcs11_funcs->C_Logout(pkcs11_session);
    if (rc != CKR_OK && rc != CKR_USER_NOT_LOGGED_IN)
        warnx("C_Logout failed: 0x%lX: %s", rc, p11_get_ckr(rc));

    rc = pkcs11_funcs->C_CloseSession(pkcs11_session);
    if (rc != CKR_OK)
        warnx("C_CloseSession failed: 0x%lX: %s", rc, p11_get_ckr(rc));

    pkcs11_session = CK_INVALID_HANDLE;
}

static CK_RV init_pkcs11(const struct p11sak_cmd *command)
{
    CK_RV rc;
    char *buf_user_pin = NULL;
    const char *pin = opt_pin;

    if (command == NULL || command->session_flags == 0)
        return CKR_OK;

    if (pin == NULL)
        pin = getenv(PKCS11_USER_PIN_ENV_NAME);
    if (opt_force_pin_prompt || pin == NULL)
        pin = pin_prompt(&buf_user_pin, "Please enter user PIN: ");
    if (pin == NULL)
        return CKR_FUNCTION_FAILED;

    rc = load_pkcs11_lib();
    if (rc != CKR_OK)
        goto done;

    rc = pkcs11_funcs->C_Initialize(NULL);
    if (rc != CKR_OK) {
        warnx("C_Initialize failed: 0x%lX: %s", rc, p11_get_ckr(rc));
        goto done;
    }

    pkcs11_initialized = true;

    rc = open_pkcs11_session(opt_slot, command->session_flags, pin);
    if (rc != CKR_OK)
        goto done;

done:
    pin_free(&buf_user_pin);

    return rc;
}

static void term_pkcs11(void)
{
    CK_RV rc;

    if (pkcs11_session != CK_INVALID_HANDLE)
        close_pkcs11_session();

    if (pkcs11_funcs != NULL && pkcs11_initialized) {
        rc = pkcs11_funcs->C_Finalize(NULL);
        if (rc != CKR_OK)
            warnx("C_Finalize failed: 0x%lX: %s", rc, p11_get_ckr(rc));
    }

    if (pkcs11_lib != NULL)
        dlclose(pkcs11_lib);

    pkcs11_lib = NULL;
    pkcs11_funcs = NULL;
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
    const struct p11sak_cmd *command = NULL;
    CK_RV rc = CKR_OK;

    /* Get p11sak command (if any) */
    if (argc >= 2 && strncmp(argv[1], "-", 1) != 0) {
        command = find_command(argv[1]);
        if (command == NULL) {
            warnx("Invalid command '%s'", argv[1]);
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        argc--;
        argv = &argv[1];
    }

    /* Get command arguments (if any) */
    rc = parse_cmd_arguments(command, &argc, &argv);
    if (rc != CKR_OK)
        goto done;

    /* Get generic and command specific options (if any) */
    rc = parse_cmd_options(command, argc, argv);
    if (rc != CKR_OK)
        goto done;

    if (opt_help) {
        if (command == NULL)
            print_help();
        else
            print_command_help(command);
        goto done;
    }

    if (opt_version) {
        print_version();
        goto done;
    }

    if (command == NULL) {
        warnx("A command is required. Use '-h'/'--help' to see the list of "
              "supported commands");
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    rc = check_required_args(command->args);
    if (rc != CKR_OK)
        goto done;

    rc = check_required_cmd_opts(command->opts);
    if (rc != CKR_OK)
        goto done;

    rc = init_pkcs11(command);
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
    term_pkcs11();

    if (p11sak_cfg != NULL)
        confignode_deepfree(p11sak_cfg);

    return rc;
}
