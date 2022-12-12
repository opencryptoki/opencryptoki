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

#include <openssl/obj_mac.h>

#define P11SAK_DECLARE_CURVES
#include "p11sak.h"
#include "p11util.h"
#include "pin_prompt.h"
#include "cfgparser.h"
#include "configuration.h"

static CK_RV p11sak_generate_key(void);
static CK_RV p11sak_list_key(void);
static CK_RV p11sak_remove_key(void);
static void print_generate_key_attr_help(void);
static void print_list_key_attr_help(void);

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

static bool opt_slot_is_set(const struct p11sak_arg *arg);

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
      .private = { .ptr = NULL }, },                                           \
    { .value = "3des", .args = NULL,                                           \
      .private = { .ptr = NULL }, },                                           \
    { .value = "generic", .args = args_prefix##_generic_args,                  \
      .private = { .ptr = NULL }, },                                           \
    { .value = "aes", .args = args_prefix##_aes_args,                          \
      .private = { .ptr = NULL }, },                                           \
    { .value = "aes-xts", .args = args_prefix##_aes_xts_args,                  \
      .private = { .ptr = NULL }, },                                           \
    { .value = "rsa", .args = args_prefix##_rsa_args,                          \
      .private = { .ptr = NULL }, },                                           \
    { .value = "dh", .args = args_prefix##_dh_args,                            \
      .private = { .ptr = NULL }, },                                           \
    { .value = "dsa", .args = args_prefix##_dsa_args,                          \
      .private = { .ptr = NULL }, },                                           \
    { .value = "ec", .args = args_prefix##_ec_args,                            \
      .private = { .ptr = NULL }, },                                           \
    { .value = "ibm-dilithium", .args = args_prefix##_ibm_dilithium_args,      \
      .private = { .ptr = NULL }, },                                           \
    { .value = "ibm-kyber", .args = args_prefix##_ibm_kyber_args,              \
      .private = { .ptr = NULL }, }

#define GROUP_KEYTYPES                                                         \
    { .value = "public", .args = NULL,                                         \
       .private = { .ptr = NULL }, },                                          \
    { .value = "private", .args = NULL,                                        \
      .private = { .ptr = NULL }, },                                           \
    { .value = "secret", .args = NULL,                                         \
      .private = { .ptr = NULL }, },                                           \
    { .value = "all", .args = NULL,                                            \
      .private = { .ptr = NULL }, }

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

static const struct p11sak_enum_value p11sak_list_remove_key_keytypes[] = {
    KEYGEN_KEYTYPES(null),
    GROUP_KEYTYPES,
    { .value = NULL, },
};

static const struct p11sak_arg p11sak_list_key_args[] = {
    { .name = "KEYTYPE", .type = ARG_TYPE_ENUM, .required = false,
      .enum_values = p11sak_list_remove_key_keytypes,
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
      .enum_values = p11sak_list_remove_key_keytypes,
      .value.enum_value = &opt_keytype,
      .description = "The type of the keys to select for removal (optional). "
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
    { .cmd = NULL, .func = NULL },
};

#define DECLARE_BOOL_ATTR(attr, ch, sec, pub, priv, set)                       \
    { .name = # attr, .type = attr, .letter = ch,                              \
      .secret = sec, .public = pub, .private = priv,                           \
      .settable = set, }

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

static void print_version(void)
{
    printf("p11sak version %s\n", PACKAGE_VERSION);
}

static bool opt_slot_is_set(const struct p11sak_arg *arg)
{
    return (*arg->value.number != (CK_ULONG)-1);
}

static CK_RV p11sak_generate_key(void)
{

    // TODO

    return CKR_OK;
}

static CK_RV p11sak_list_key(void)
{;

    // TODO

    return CKR_OK;
}

static CK_RV p11sak_remove_key(void)
{
    // TODO

    return CKR_OK;
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
