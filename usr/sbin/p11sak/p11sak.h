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
#define P11SAK_DEFAULT_CONF_FILE_ENV_NAME   "P11SAK_DEFAULT_CONF_FILE"
#define P11SAK_CONFIG_FILE_NAME             "p11sak_defined_attrs.conf"
#define P11SAK_DEFAULT_CONFIG_FILE          OCK_CONFDIR "/" P11SAK_CONFIG_FILE_NAME

#define UNUSED(var)             ((void)(var))

#define OPT_FORCE_PIN_PROMPT    256
#define OPT_DETAILED_URI        257

#define MAX_PRINT_LINE_LENGTH   80
#define PRINT_INDENT_POS        35

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
};

struct p11sak_keytype {
    const char *name;
    CK_KEY_TYPE type;
    CK_MECHANISM keygen_mech;
    bool is_asymmetric;
    bool sign_verify;
    bool encrypt_decrypt;
    bool wrap_unwrap;
    bool derive;
    CK_RV (*keygen_prepare)(const struct p11sak_keytype *keytype,
                            void **private);
    void (*keygen_cleanup)(const struct p11sak_keytype *keytype, void *private);
    CK_RV (*keygen_get_key_size)(const struct p11sak_keytype *keytype,
                                 void *private, CK_ULONG *keysize);
    CK_RV (*keygen_add_secret_attrs)(const struct p11sak_keytype *keytype,
                                     CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     void *private);
    CK_RV (*keygen_add_public_attrs)(const struct p11sak_keytype *keytype,
                                     CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                     void *private);
    CK_RV (*keygen_add_private_attrs)(const struct p11sak_keytype *keytype,
                                      CK_ATTRIBUTE **attrs, CK_ULONG *num_attrs,
                                      void *private);
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
