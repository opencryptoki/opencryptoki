/*
 * COPYRIGHT (c) International Business Machines Corp. 2025
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

#define P11SAK_DECLARE_CURVES
#include "p11sak.h"
#include "p11util.h"
#include "mechtable.h"
#include "defs.h"

#include <openssl/pem.h>
#include <openssl/err.h>

static char *opt_iv = NULL;
static struct p11tool_enum_value *opt_oaep_hash_alg = NULL;
static struct p11tool_enum_value *opt_oaep_mgf_alg = NULL;
static char *opt_oaep_source_data = NULL;
static struct p11tool_enum_value *opt_aeskw_keybits = NULL;
static struct p11tool_enum_value *opt_ecdh_kdf_alg = NULL;
static char *opt_ecdh_shared_data = NULL;

static CK_RV p11sak_aes_iv_prepare_mech_param_from_opts(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech);
static CK_RV p11sak_aes_iv_prepare_mech_param_from_pem(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech, char **pem_headers);
static CK_RV p11sak_aes_iv_prepare_pem_header(
                                const struct p11sak_wrap_mech *wrap_mech,
                                char **pem_header);
static CK_RV p11sak_rsa_oaep_prepare_mech_param_from_opts(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech);
static CK_RV p11sak_rsa_oaep_prepare_mech_param_from_pem(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech, char **pem_headers);
static void p11sak_rsa_oaep_cleanup_mech_param(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech);
static CK_RV p11sak_rsa_oaep_prepare_pem_header(
                                const struct p11sak_wrap_mech *wrap_mech,
                                char **pem_header);
static CK_RV p11sak_rsa_aeskw_prepare_mech_param_from_opts(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech);
static CK_RV p11sak_rsa_aeskw_prepare_mech_param_from_pem(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech, char **pem_headers);
static void p11sak_rsa_aeskw_cleanup_mech_param(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech);
static CK_RV p11sak_rsa_aeskw_prepare_pem_header(
                                const struct p11sak_wrap_mech *wrap_mech,
                                char **pem_header);
static CK_RV p11sak_ecdh_aeskw_prepare_mech_param_from_opts(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech);
static CK_RV p11sak_ecdh_aeskw_prepare_mech_param_from_pem(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech, char **pem_headers);
static void p11sak_ecdh_aeskw_cleanup_mech_param(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech);
static CK_RV p11sak_ecdh_aeskw_prepare_pem_header(
                                const struct p11sak_wrap_mech *wrap_mech,
                                char **pem_header);

static const struct p11sak_wrap_mech p11sak_wrap_mech_aes_cbc = {
    .name = "AES-CBC-PAD",
    .mech = CKM_AES_CBC_PAD,
    .mech_param_size = AES_INIT_VECTOR_SIZE,
    .wrap_class = CKO_SECRET_KEY,
    .unwrap_class = CKO_SECRET_KEY,
    .key_type = CKK_AES,
    .prepare_mech_param_from_opts = p11sak_aes_iv_prepare_mech_param_from_opts,
    .prepare_mech_param_from_pem = p11sak_aes_iv_prepare_mech_param_from_pem,
    .prepare_pem_header = p11sak_aes_iv_prepare_pem_header,
};

static const struct p11sak_wrap_mech p11sak_wrap_mech_aeskw_kwp = {
    .name = "AESKW-KWP",
    .mech = CKM_AES_KEY_WRAP_KWP,
    .mech_param_size = AES_KEY_WRAP_KWP_IV_SIZE,
    .mech_param_optional = CK_TRUE,
    .wrap_class = CKO_SECRET_KEY,
    .unwrap_class = CKO_SECRET_KEY,
    .key_type = CKK_AES,
    .prepare_mech_param_from_opts = p11sak_aes_iv_prepare_mech_param_from_opts,
    .prepare_mech_param_from_pem = p11sak_aes_iv_prepare_mech_param_from_pem,
    .prepare_pem_header = p11sak_aes_iv_prepare_pem_header,
};

static const struct p11sak_wrap_mech p11sak_wrap_mech_aeskw_pkcs7 = {
    .name = "AESKW-PKCS7",
    .mech = CKM_AES_KEY_WRAP_PKCS7,
    .mech_param_size = AES_KEY_WRAP_IV_SIZE,
    .mech_param_optional = CK_TRUE,
    .wrap_class = CKO_SECRET_KEY,
    .unwrap_class = CKO_SECRET_KEY,
    .key_type = CKK_AES,
    .prepare_mech_param_from_opts = p11sak_aes_iv_prepare_mech_param_from_opts,
    .prepare_mech_param_from_pem = p11sak_aes_iv_prepare_mech_param_from_pem,
    .prepare_pem_header = p11sak_aes_iv_prepare_pem_header,
};

static const struct p11sak_wrap_mech p11sak_wrap_mech_rsa_pkcs = {
    .name = "RSA-PKCS",
    .mech = CKM_RSA_PKCS,
    .mech_param_size = 0,
    .wrap_class = CKO_PUBLIC_KEY,
    .unwrap_class = CKO_PRIVATE_KEY,
    .key_type = CKK_RSA,
};

static const struct p11sak_wrap_mech p11sak_wrap_mech_rsa_oaep = {
    .name = "RSA-OAEP",
    .mech = CKM_RSA_PKCS_OAEP,
    .mech_param_size = sizeof(CK_RSA_PKCS_OAEP_PARAMS),
    .wrap_class = CKO_PUBLIC_KEY,
    .unwrap_class = CKO_PRIVATE_KEY,
    .key_type = CKK_RSA,
    .prepare_mech_param_from_opts =
                        p11sak_rsa_oaep_prepare_mech_param_from_opts,
    .prepare_mech_param_from_pem =
                        p11sak_rsa_oaep_prepare_mech_param_from_pem,
    .cleanup_mech_param = p11sak_rsa_oaep_cleanup_mech_param,
    .prepare_pem_header = p11sak_rsa_oaep_prepare_pem_header,
};

static const struct p11sak_wrap_mech p11sak_wrap_mech_rsa_aeskw = {
    .name = "RSA-AESKW",
    .mech = CKM_RSA_AES_KEY_WRAP,
    .mech_param_size = sizeof(CK_RSA_AES_KEY_WRAP_PARAMS),
    .wrap_class = CKO_PUBLIC_KEY,
    .unwrap_class = CKO_PRIVATE_KEY,
    .key_type = CKK_RSA,
    .prepare_mech_param_from_opts =
                        p11sak_rsa_aeskw_prepare_mech_param_from_opts,
    .prepare_mech_param_from_pem =
                        p11sak_rsa_aeskw_prepare_mech_param_from_pem,
    .cleanup_mech_param = p11sak_rsa_aeskw_cleanup_mech_param,
    .prepare_pem_header = p11sak_rsa_aeskw_prepare_pem_header,
};

static const struct p11sak_wrap_mech p11sak_wrap_mech_ecdh_aeskw = {
    .name = "ECDH-AESKW",
    .mech = CKM_ECDH_AES_KEY_WRAP,
    .mech_param_size = sizeof(CK_ECDH_AES_KEY_WRAP_PARAMS),
    .wrap_class = CKO_PUBLIC_KEY,
    .unwrap_class = CKO_PRIVATE_KEY,
    .key_type = CKK_EC,
    .prepare_mech_param_from_opts =
                        p11sak_ecdh_aeskw_prepare_mech_param_from_opts,
    .prepare_mech_param_from_pem =
                        p11sak_ecdh_aeskw_prepare_mech_param_from_pem,
    .cleanup_mech_param = p11sak_ecdh_aeskw_cleanup_mech_param,
    .prepare_pem_header = p11sak_ecdh_aeskw_prepare_pem_header,
};

static const struct p11tool_opt p11sak_wrap_mech_aes_cbc_opts[] = {
    { .short_opt = 'I', .long_opt = "iv", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_iv, .name = "IV", },
      .description = "The initialization vector (IV) for the AES-CBC "
                     "operation. Specify a hex string (not prefixed with 0x) "
                     "of exactly 16 bytes. The default is to use 16 all zero "
                     "bytes.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_wrap_mech_aeskw_kwp_opts[] = {
    { .short_opt = 'I', .long_opt = "iv", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_iv, .name = "IV", },
      .description = "The initialization vector (IV) for the AESKW-KWP "
                     "operation. Specify a hex string (not prefixed with 0x) "
                     "of exactly 4 bytes. If no IV is specified then the "
                     "default IV as per AESKW-KWP specification is used.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_opt p11sak_wrap_mech_aeskw_pkcs7_opts[] = {
    { .short_opt = 'I', .long_opt = "iv", .required = false,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .value.string = &opt_iv, .name = "IV", },
      .description = "The initialization vector (IV) for the AESKW-PKCS7 "
                     "operation. Specify a hex string (not prefixed with 0x) "
                     "of exactly 8 bytes. If no IV is specified then the "
                     "default IV as per AESKW-PKCS7 specification is used.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_enum_value p11sak_oaep_hash_algs[] = {
    { .value = "SHA-1", .args = NULL, .private = { .num = CKM_SHA_1 }, },
    { .value = "SHA224", .args = NULL, .private = { .num = CKM_SHA224 }, },
    { .value = "SHA256", .args = NULL, .private = { .num = CKM_SHA256 }, },
    { .value = "SHA384", .args = NULL, .private = { .num = CKM_SHA384 }, },
    { .value = "SHA512", .args = NULL, .private = { .num = CKM_SHA512 }, },
    { .value = "SHA3-224", .args = NULL, .private = { .num = CKM_SHA3_224 }, },
    { .value = "SHA3-256", .args = NULL, .private = { .num = CKM_SHA3_256 }, },
    { .value = "SHA3-384", .args = NULL, .private = { .num = CKM_SHA3_384 }, },
    { .value = "SHA3-512", .args = NULL, .private = { .num = CKM_SHA3_512 }, },
    { .value = NULL, },
};

static const struct p11tool_enum_value p11sak_oaep_mgf_algs[] = {
    { .value = "SHA-1", .args = NULL, .private = { .num = CKG_MGF1_SHA1 }, },
    { .value = "SHA224", .args = NULL,
      .private = { .num = CKG_MGF1_SHA224 }, },
    { .value = "SHA256", .args = NULL,
      .private = { .num = CKG_MGF1_SHA256 }, },
    { .value = "SHA384", .args = NULL,
      .private = { .num = CKG_MGF1_SHA384 }, },
    { .value = "SHA512", .args = NULL,
      .private = { .num = CKG_MGF1_SHA512 }, },
    { .value = "SHA3-224", .args = NULL,
      .private = { .num = CKG_MGF1_SHA3_224 }, },
    { .value = "SHA3-256", .args = NULL,
      .private = { .num = CKG_MGF1_SHA3_256 }, },
    { .value = "SHA3-384", .args = NULL,
      .private = { .num = CKG_MGF1_SHA3_384 }, },
    { .value = "SHA3-512", .args = NULL,
      .private = { .num = CKG_MGF1_SHA3_512 }, },
    { .value = NULL, },
};

static const struct p11tool_opt p11sak_wrap_mech_rsa_oaep_opts[] = {
    { .short_opt = 0, .long_opt = "hash-alg", .required = false,
      .long_opt_val = OPT_OAEP_HASH_ALG,
      .arg =  { .type = ARG_TYPE_ENUM, .required = true, .name = "HASH-ALG",
                .value.enum_value = &opt_oaep_hash_alg,
                .enum_values = p11sak_oaep_hash_algs, },
      .description = "The message digest algorithm used to calculate the "
                     "digest of the OAEP encoding parameter. The default is "
                     "to use the same algorithm as specified with option "
                     "'--mgf-alg', or SHA256 if neither is specified. "
                     "Possible algorithms are:", },
    { .short_opt = 0, .long_opt = "mgf-alg", .required = false,
      .long_opt_val = OPT_OAEP_MGF_ALG,
      .arg =  { .type = ARG_TYPE_ENUM, .required = true, .name = "MGF-ALG",
                .value.enum_value = &opt_oaep_mgf_alg,
                .enum_values = p11sak_oaep_mgf_algs, },
      .description = "The mask generation function algorithm to use on the "
                     "encoded block. The default is to use the same algorithm "
                     "as specified with option '--hash-alg', or SHA256 if "
                     "neither is specified. Possible algorithms are:", },
    { .short_opt = 0, .long_opt = "source-data", .required = false,
      .long_opt_val = OPT_OAEP_SOURCE_DATA,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .name = "SOURCE-DATA",
                .value.string = &opt_oaep_source_data, },
      .description = "The source of the OAEP encoding parameter. Specify a hex "
                     "string (not prefixed with 0x) of any number of bytes. "
                     "The default is that no source data is used.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_enum_value p11sak_aeskw_keybits[] = {
    { .value = "128", .args = NULL, .private = { .num = 128 }, },
    { .value = "192", .args = NULL, .private = { .num = 192 }, },
    { .value = "256", .args = NULL, .private = { .num = 256 }, },
    { .value = NULL, },
};

static const struct p11tool_opt p11sak_wrap_mech_rsa_aeskw_opts[] = {
    { .short_opt = 0, .long_opt = "aes-key-size", .required = false,
      .long_opt_val = OPT_AESKW_KEY_SIZE,
      .arg =  { .type = ARG_TYPE_ENUM, .required = true, .name = "AES-KEYBITS",
                .value.enum_value = &opt_aeskw_keybits,
                .enum_values = p11sak_aeskw_keybits, },
      .description = "The size of the temporary AES key in bits. The default "
                     "is 256 bits. Possible key sizes are:", },
    { .short_opt = 0, .long_opt = "hash-alg", .required = false,
      .long_opt_val = OPT_OAEP_HASH_ALG,
      .arg =  { .type = ARG_TYPE_ENUM, .required = true, .name = "HASH-ALG",
                .value.enum_value = &opt_oaep_hash_alg,
                .enum_values = p11sak_oaep_hash_algs, },
      .description = "The message digest algorithm used to calculate the "
                     "digest of the OAEP encoding parameter. The default is "
                     "to use the same algorithm as specified with option "
                     "'--mgf-alg', or SHA256 if neither is specified. "
                     "Possible algorithms are:", },
    { .short_opt = 0, .long_opt = "mgf-alg", .required = false,
      .long_opt_val = OPT_OAEP_MGF_ALG,
      .arg =  { .type = ARG_TYPE_ENUM, .required = true, .name = "MGF-ALG",
                .value.enum_value = &opt_oaep_mgf_alg,
                .enum_values = p11sak_oaep_mgf_algs, },
      .description = "The mask generation function algorithm to use on the "
                     "encoded block. The default is to use the same algorithm "
                     "as specified with option '--hash-alg', or SHA256 if "
                     "neither is specified. Possible algorithms are:", },
    { .short_opt = 0, .long_opt = "source-data", .required = false,
      .long_opt_val = OPT_OAEP_SOURCE_DATA,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .name = "SOURCE-DATA",
                .value.string = &opt_oaep_source_data, },
      .description = "The source of the OAEP encoding parameter. Specify a hex "
                     "string (not prefixed with 0x) of any number of bytes. "
                     "The default is that no source data is used.", },
    { .short_opt = 0, .long_opt = NULL, },
};

static const struct p11tool_enum_value p11sak_ecdh_kdf_algs[] = {
    { .value = "NULL", .args = NULL, .private = { .num = CKD_NULL}, },
    { .value = "SHA-1", .args = NULL, .private = { .num = CKD_SHA1_KDF }, },
    { .value = "SHA224", .args = NULL, .private = { .num = CKD_SHA224_KDF }, },
    { .value = "SHA256", .args = NULL, .private = { .num = CKD_SHA256_KDF }, },
    { .value = "SHA384", .args = NULL, .private = { .num = CKD_SHA384_KDF }, },
    { .value = "SHA512", .args = NULL, .private = { .num = CKD_SHA512_KDF }, },
    { .value = "SHA3-224", .args = NULL,
      .private = { .num = CKD_SHA3_224_KDF }, },
    { .value = "SHA3-256", .args = NULL,
      .private = { .num = CKD_SHA3_256_KDF }, },
    { .value = "SHA3-384", .args = NULL,
      .private = { .num = CKD_SHA3_384_KDF }, },
    { .value = "SHA3-512", .args = NULL,
      .private = { .num = CKD_SHA3_512_KDF }, },
    { .value = "SHA-1-SP800", .args = NULL,
      .private = { .num = CKD_SHA1_KDF_SP800 }, },
    { .value = "SHA224-SP800", .args = NULL,
      .private = { .num = CKD_SHA224_KDF_SP800 }, },
    { .value = "SHA256-SP800", .args = NULL,
      .private = { .num = CKD_SHA256_KDF_SP800 }, },
    { .value = "SHA384-SP800", .args = NULL,
      .private = { .num = CKD_SHA384_KDF_SP800 }, },
    { .value = "SHA512-SP800", .args = NULL,
      .private = { .num = CKD_SHA512_KDF_SP800 }, },
    { .value = "SHA3-224-SP800", .args = NULL,
      .private = { .num = CKD_SHA3_224_KDF_SP800 }, },
    { .value = "SHA3-256-SP800", .args = NULL,
      .private = { .num = CKD_SHA3_256_KDF_SP800 }, },
    { .value = "SHA3-384-SP800", .args = NULL,
      .private = { .num = CKD_SHA3_384_KDF_SP800 }, },
    { .value = "SHA3-512-SP800", .args = NULL,
      .private = { .num = CKD_SHA3_512_KDF_SP800 }, },
    { .value = NULL, },
};

static const struct p11tool_opt p11sak_wrap_mech_ecdh_aeskw_opts[] = {
    { .short_opt = 0, .long_opt = "aes-key-size", .required = false,
      .long_opt_val = OPT_AESKW_KEY_SIZE,
      .arg =  { .type = ARG_TYPE_ENUM, .required = true, .name = "AES-KEYBITS",
                .value.enum_value = &opt_aeskw_keybits,
                .enum_values = p11sak_aeskw_keybits, },
      .description = "The size of the temporary AES key in bits. The default "
                     "is 256 bits. Possible key sizes are:", },
    { .short_opt = 0, .long_opt = "kdf-alg", .required = false,
      .long_opt_val = OPT_ECDH_KDF_ALG,
      .arg =  { .type = ARG_TYPE_ENUM, .required = true, .name = "KDF-ALG",
                .value.enum_value = &opt_ecdh_kdf_alg,
                .enum_values = p11sak_ecdh_kdf_algs, },
      .description = "The key derivation function algorithm used on the shared "
                     "secret value to generate the internal AES key. The "
                     "default is SHA256. Possible algorithms are:", },
    { .short_opt = 0, .long_opt = "shared-data", .required = false,
      .long_opt_val = OPT_ECDH_SHARED_DATA,
      .arg =  { .type = ARG_TYPE_STRING, .required = true,
                .name = "SHARED-DATA",
                .value.string = &opt_ecdh_shared_data, },
      .description = "Some data shared between the two parties. Specify a hex "
                     "string (not prefixed with 0x) of any number of bytes. "
                     "The default is that no shared data is used.", },
    { .short_opt = 0, .long_opt = NULL, },
};

const struct p11tool_enum_value p11sak_wrap_mech_values[] = {
    { .value = "aes-cbc-pad", .args = NULL,
      .opts = p11sak_wrap_mech_aes_cbc_opts,
      .description = "Use mechanism CKM_AES_CBC_PAD for key wrapping. "
                     "Wrapping and unwrapping is done with an AES key.",
      .private = { .ptr = &p11sak_wrap_mech_aes_cbc, }, },
    { .value = "aeskw-kwp", .args = NULL,
      .opts = p11sak_wrap_mech_aeskw_kwp_opts,
      .description = "Use mechanism CKM_AES_KEY_WRAP_KWP for key wrapping. "
                     "Wrapping and unwrapping is done with an AES key.",
      .private = { .ptr = &p11sak_wrap_mech_aeskw_kwp, }, },
    { .value = "aeskw-pkcs7", .args = NULL,
      .opts = p11sak_wrap_mech_aeskw_pkcs7_opts,
      .description = "Use mechanism CKM_AES_KEY_WRAP_PKCS7 for key wrapping. "
                     "Wrapping and unwrapping is done with an AES key.",
      .private = { .ptr = &p11sak_wrap_mech_aeskw_pkcs7, }, },
    { .value = "rsa-pkcs", .args = NULL, .opts = NULL,
      .description = "Use mechanism CKM_RSA_PKCS for key wrapping. "
                     "Wrapping is done with an RSA public key, unwrapping is "
                     "done with the corresponding RSA private key. Only keys "
                     "whose key material size is up to the KEK's RSA modulus "
                     "size minus 11 bytes can be wrapped with this mechanism.",
      .private = { .ptr = &p11sak_wrap_mech_rsa_pkcs, }, },
    { .value = "rsa-oaep", .args = NULL,
      .opts = p11sak_wrap_mech_rsa_oaep_opts,
      .description = "Use mechanism CKM_RSA_PKCS_OAEP for key wrapping. "
                     "Wrapping is done with an RSA public key, unwrapping is "
                     "done with the corresponding RSA private key. Only keys "
                     "whose key material size is up to the KEK's RSA modulus "
                     "size minus 2 times the hash-alg digest size bytes minus "
                     "2 bytes wrapped with this mechanism.",
      .private = { .ptr = &p11sak_wrap_mech_rsa_oaep, }, },
    { .value = "rsa-aeskw", .args = NULL,
      .opts = p11sak_wrap_mech_rsa_aeskw_opts,
      .description = "Use mechanism CKM_RSA_AES_KEY_WRAP for key wrapping. "
                     "Wrapping is done with an RSA public key, unwrapping is "
                     "done with the corresponding RSA private key.",
      .private = { .ptr = &p11sak_wrap_mech_rsa_aeskw, }, },
    { .value = "ecdh-aeskw", .args = NULL,
      .opts = p11sak_wrap_mech_ecdh_aeskw_opts,
      .description = "Use mechanism CKM_ECDH_AES_KEY_WRAP for key wrapping. "
                     "Wrapping is done with an EC public key, unwrapping is "
                     "done with the corresponding EC private key.",
      .private = { .ptr = &p11sak_wrap_mech_ecdh_aeskw, }, },
    { .value = NULL, },
};

static char *find_pem_header(char **headers, const char *name)
{
    CK_ULONG i, len;
    char *tok;

    for (i = 0; headers[i] != NULL; i++) {
        tok = strchr(headers[i], ':');
        if (tok == NULL || tok[1] != ' ')
            continue;

        len = tok - headers[i];
        if (len != strlen(name) ||
            strncmp(headers[i], name, len) != 0)
            continue;

        return headers[i] + len + 2;
    }

    return NULL;
}

static const struct p11sak_wrap_mech *find_wrap_mech_by_name(const char *name)
{
    const struct p11tool_enum_value *val;

    for (val = p11sak_wrap_mech_values; val->value != NULL; val++) {
        if (strcasecmp(val->value, name) == 0)
            return val->private.ptr;
    }

    return NULL;
}

static const struct p11tool_objtype *find_keytype_by_name(const char *name)
{
    const struct p11tool_objtype **kt;

    for (kt = p11sak_keytypes; *kt != NULL; kt++) {
        if (strcasecmp((*kt)->name, name) == 0)
            return *kt;
    }

    return NULL;
}

static CK_MECHANISM_TYPE find_hash_alg_by_name(const char *name)
{
    const struct p11tool_enum_value *val;

    for (val = p11sak_oaep_hash_algs; val->value != NULL; val++) {
        if (strcasecmp(val->value, name) == 0)
            return val->private.num;
    }

    return (CK_MECHANISM_TYPE)-1;
}

static CK_RSA_PKCS_MGF_TYPE find_mgf_alg_by_name(const char *name)
{
    const struct p11tool_enum_value *val;

    for (val = p11sak_oaep_mgf_algs; val->value != NULL; val++) {
        if (strcasecmp(val->value, name) == 0)
            return val->private.num;
    }

    return (CK_RSA_PKCS_MGF_TYPE)-1;
}

static CK_ULONG find_aeskw_keybits_by_name(const char *name)
{
    const struct p11tool_enum_value *val;

    for (val = p11sak_aeskw_keybits; val->value != NULL; val++) {
        if (strcasecmp(val->value, name) == 0)
            return val->private.num;
    }

    return (CK_ULONG)-1;
}

static CK_EC_KDF_TYPE find_kdf_alg_by_name(const char *name)
{
    const struct p11tool_enum_value *val;

    for (val = p11sak_ecdh_kdf_algs; val->value != NULL; val++) {
        if (strcasecmp(val->value, name) == 0)
            return val->private.num;
    }

    return (CK_EC_KDF_TYPE)-1;
}

static CK_RV p11sak_aes_iv_prepare_mech_param_from_opts(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech)
{
    CK_BYTE *buf = NULL;
    CK_ULONG len = 0;
    CK_RV rc;

    if (opt_iv == NULL) {
        if (wrap_mech->mech_param_optional) {
            mech->pParameter = NULL;
            mech->ulParameterLen = 0;
        } else {
            memset(mech->pParameter, 0, mech->ulParameterLen);
        }
        return CKR_OK;
    }

    rc = p11tool_parse_hex(opt_iv, &buf, &len);
    if (rc != CKR_OK)
        return rc;

    if (len != mech->ulParameterLen) {
        warnx("Hex string specified as IV has an invalid length, expected "
              "%lu bytes.", mech->ulParameterLen);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    memcpy(mech->pParameter, buf, mech->ulParameterLen);

done:
    if (buf != NULL)
        free(buf);

    return rc;
}

static CK_RV p11sak_aes_iv_prepare_mech_param_from_pem(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech, char **pem_headers)
{
    CK_BYTE *buf = NULL;
    CK_ULONG len = 0;
    char *iv = NULL;
    CK_RV rc = CKR_OK;

    if (opt_iv != NULL) {
        warnx("Option '-I'/'--iv' is ignored, using information from "
              "PEM file '%s'.", opt_file);
    }

    iv = find_pem_header(pem_headers, P11SAK_WRAP_PEM_HDR_IV);
    if (iv == NULL) {
        if (wrap_mech->mech_param_optional)
            iv = P11SAK_WRAP_PEM_HDR_IV_DEFAULT;
        else
            iv = P11SAK_WRAP_PEM_HDR_IV_ZERO;
    }

    if (strcasecmp(iv, P11SAK_WRAP_PEM_HDR_IV_DEFAULT) == 0) {
        mech->pParameter = NULL;
        mech->ulParameterLen = 0;
    } else if (strcasecmp(iv, P11SAK_WRAP_PEM_HDR_IV_ZERO) == 0) {
        memset(mech->pParameter, 0, mech->ulParameterLen);
    } else {
        rc = p11tool_parse_hex(iv, &buf, &len);
        if (rc != CKR_OK)
            return rc;

        if (len != mech->ulParameterLen) {
            warnx("Hex string specified as IV has an invalid length, expected "
                  "%lu bytes.", mech->ulParameterLen);
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        memcpy(mech->pParameter, buf, mech->ulParameterLen);
    }

done:
    if (buf != NULL)
        free(buf);

    return rc;
}

static CK_RV p11sak_aes_iv_prepare_pem_header(
                                const struct p11sak_wrap_mech *wrap_mech,
                                char **pem_header)
{
    int len;
    char *iv = opt_iv;

    if (opt_iv == NULL) {
        if (wrap_mech->mech_param_optional)
            iv = P11SAK_WRAP_PEM_HDR_IV_DEFAULT;
        else
            iv = P11SAK_WRAP_PEM_HDR_IV_ZERO;
    }

    len = asprintf(pem_header, "%s: %s\n", P11SAK_WRAP_PEM_HDR_IV, iv);
    if (len <= 0) {
        warnx("Failed to allocate memory for a PEM header");
        return CKR_HOST_MEMORY;
    }

    return CKR_OK;
}

static CK_RV p11sak_rsa_oaep_prepare_mech_param_from_opts(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech)
{
    CK_RSA_PKCS_OAEP_PARAMS *oaep_param = mech->pParameter;
    CK_RV rc;

    UNUSED(wrap_mech);

    if (opt_oaep_hash_alg != NULL) {
        oaep_param->hashAlg = opt_oaep_hash_alg->private.num;
    } else if (opt_oaep_mgf_alg != NULL){
        oaep_param->hashAlg = find_hash_alg_by_name(opt_oaep_mgf_alg->value);
        if (oaep_param->hashAlg == (CK_MECHANISM_TYPE)-1) {
            warnx("Invalid algorithm specified with option '--mgf-alg': %s",
                  opt_oaep_mgf_alg->value);
            return CKR_ARGUMENTS_BAD;
        }
    } else {
        oaep_param->hashAlg = CKM_SHA256;
    }

    if (opt_oaep_mgf_alg != NULL) {
        oaep_param->mgf = opt_oaep_mgf_alg->private.num;
    } else if (opt_oaep_hash_alg != NULL) {
        oaep_param->mgf = find_mgf_alg_by_name(opt_oaep_hash_alg->value);
        if (oaep_param->mgf == (CK_MECHANISM_TYPE)-1) {
            warnx("Invalid algorithm specified with option '--hash-alg': %s",
                  opt_oaep_hash_alg->value);
            return CKR_ARGUMENTS_BAD;
        }
    } else {
        oaep_param->mgf = CKG_MGF1_SHA256;
    }

    if (opt_oaep_source_data != NULL) {
        rc = p11tool_parse_hex(opt_oaep_source_data,
                               (CK_BYTE **)&oaep_param->pSourceData,
                               &oaep_param->ulSourceDataLen);
        if (rc != CKR_OK)
            return rc;

        oaep_param->source = CKZ_DATA_SPECIFIED;
    } else {
        oaep_param->source = 0;
        oaep_param->pSourceData = NULL;
        oaep_param->ulSourceDataLen = 0;
    }

    return CKR_OK;
}

static CK_RV p11sak_rsa_oaep_prepare_mech_param_from_pem(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech, char **pem_headers)
{
    CK_RSA_PKCS_OAEP_PARAMS *oaep_param = mech->pParameter;
    char *hash_alg = NULL, *mgf_alg = NULL, *source_data = NULL;
    CK_RV rc;

    UNUSED(wrap_mech);

    if (opt_oaep_hash_alg != NULL) {
        warnx("Option '--hash-alg' is ignored, using information from "
              "PEM file '%s'.", opt_file);
    };

    if (opt_oaep_mgf_alg != NULL) {
        warnx("Option '--mgf-alg' is ignored, using information from "
              "PEM file '%s'.", opt_file);
    };

    if (opt_oaep_source_data != NULL) {
        warnx("Option '--source-data' is ignored, using information "
              "from PEM file '%s'.", opt_file);
    };

    hash_alg = find_pem_header(pem_headers, P11SAK_WRAP_PEM_HDR_OAEP_HASH_ALG);
    mgf_alg = find_pem_header(pem_headers, P11SAK_WRAP_PEM_HDR_OAEP_MGF_ALG);
    source_data = find_pem_header(pem_headers, P11SAK_WRAP_PEM_HDR_OAEP_SOURCE);

    if (hash_alg != NULL) {
        oaep_param->hashAlg = find_hash_alg_by_name(hash_alg);
        if (oaep_param->hashAlg == (CK_MECHANISM_TYPE)-1) {
            warnx("Invalid hash algorithm '%s' in PEM file '%s'.",
                  hash_alg, opt_file);
            return CKR_ARGUMENTS_BAD;
        }
    } else if (mgf_alg != NULL) {
        oaep_param->hashAlg = find_hash_alg_by_name(mgf_alg);
        if (oaep_param->hashAlg == (CK_MECHANISM_TYPE)-1) {
            warnx("Invalid mgf algorithm '%s' in PEM file '%s'.",
                    mgf_alg, opt_file);
            return CKR_ARGUMENTS_BAD;
        }
    } else {
        oaep_param->hashAlg = CKM_SHA256;
    }

    if (mgf_alg != NULL) {
        oaep_param->mgf = find_mgf_alg_by_name(mgf_alg);
        if (oaep_param->mgf == (CK_RSA_PKCS_MGF_TYPE)-1) {
            warnx("Invalid mgf algorithm '%s' in PEM file '%s'.",
                  mgf_alg, opt_file);
            return CKR_ARGUMENTS_BAD;
        }
    } else if (hash_alg != NULL) {
        oaep_param->mgf = find_mgf_alg_by_name(hash_alg);
        if (oaep_param->mgf == (CK_RSA_PKCS_MGF_TYPE)-1) {
            warnx("Invalid hash algorithm '%s' in PEM file '%s'.",
                    hash_alg, opt_file);
            return CKR_ARGUMENTS_BAD;
        }
    } else {
        oaep_param->mgf = CKG_MGF1_SHA256;
    }

    if (source_data != NULL) {
        if (strcasecmp(source_data,
                       P11SAK_WRAP_PEM_HDR_OAEP_SOURCE_NONE) == 0) {
            oaep_param->source = 0;
            oaep_param->pSourceData = NULL;
            oaep_param->ulSourceDataLen = 0;
        } else {
            rc = p11tool_parse_hex(source_data,
                                   (CK_BYTE **)&oaep_param->pSourceData,
                                   &oaep_param->ulSourceDataLen);
            if (rc != CKR_OK)
                return rc;

            oaep_param->source = CKZ_DATA_SPECIFIED;
        }
    } else {
        oaep_param->source = 0;
        oaep_param->pSourceData = NULL;
        oaep_param->ulSourceDataLen = 0;
    }

    return CKR_OK;
}


static void p11sak_rsa_oaep_cleanup_mech_param(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech)
{
    CK_RSA_PKCS_OAEP_PARAMS *oaep_param = mech->pParameter;

    UNUSED(wrap_mech);

    if (oaep_param->pSourceData != NULL)
        free(oaep_param->pSourceData);
}

static CK_RV p11sak_rsa_oaep_prepare_pem_header(
                                const struct p11sak_wrap_mech *wrap_mech,
                                char **pem_header)
{
    int len;

    UNUSED(wrap_mech);

    len = asprintf(pem_header, "%s: %s\n%s: %s\n%s: %s\n",
                   P11SAK_WRAP_PEM_HDR_OAEP_HASH_ALG,
                   opt_oaep_hash_alg != NULL ?
                           opt_oaep_hash_alg->value :
                           opt_oaep_mgf_alg != NULL ?
                                   opt_oaep_mgf_alg->value : "SHA256",
                   P11SAK_WRAP_PEM_HDR_OAEP_MGF_ALG,
                   opt_oaep_mgf_alg != NULL ?
                           opt_oaep_mgf_alg->value :
                           opt_oaep_hash_alg != NULL ?
                                   opt_oaep_hash_alg->value : "SHA256",
                   P11SAK_WRAP_PEM_HDR_OAEP_SOURCE,
                   opt_oaep_source_data != NULL ?
                           opt_oaep_source_data :
                           P11SAK_WRAP_PEM_HDR_OAEP_SOURCE_NONE);
    if (len <= 0) {
        warnx("Failed to allocate memory for a PEM header");
        return CKR_HOST_MEMORY;
    }

    return CKR_OK;
}

static CK_RV p11sak_rsa_aeskw_prepare_mech_param_from_opts(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech)
{
    CK_RSA_AES_KEY_WRAP_PARAMS *rsa_aeskw_param = mech->pParameter;

    CK_MECHANISM tmp_mech;
    CK_RV rc;

    UNUSED(wrap_mech);

    rsa_aeskw_param->pOAEPParams = calloc(1, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
    if (rsa_aeskw_param->pOAEPParams == NULL) {
        warnx("Failed to allocate memory for a mechanism parameter");
        return CKR_HOST_MEMORY;
    }

    if (opt_aeskw_keybits != NULL)
        rsa_aeskw_param->ulAESKeyBits = opt_aeskw_keybits->private.num;
    else
        rsa_aeskw_param->ulAESKeyBits = 256;

    tmp_mech.mechanism = CKM_RSA_PKCS_OAEP;
    tmp_mech.pParameter = rsa_aeskw_param->pOAEPParams;
    tmp_mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);

    rc = p11sak_rsa_oaep_prepare_mech_param_from_opts(wrap_mech, &tmp_mech);
    if (rc != CKR_OK) {
        p11sak_rsa_aeskw_cleanup_mech_param(wrap_mech, mech);
        return rc;
    }

    return CKR_OK;
}

static CK_RV p11sak_rsa_aeskw_prepare_mech_param_from_pem(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech, char **pem_headers)
{
    CK_RSA_AES_KEY_WRAP_PARAMS *rsa_aeskw_param = mech->pParameter;
    char *aes_key_size;
    CK_MECHANISM tmp_mech;
    CK_RV rc;

    UNUSED(wrap_mech);

    rsa_aeskw_param->pOAEPParams = calloc(1, sizeof(CK_RSA_PKCS_OAEP_PARAMS));
    if (rsa_aeskw_param->pOAEPParams == NULL) {
        warnx("Failed to allocate memory for a mechanism parameter");
        return CKR_HOST_MEMORY;
    }

    if (opt_aeskw_keybits != NULL) {
        warnx("Option '--aes-key-size' is ignored, using information "
              "from PEM file '%s'.", opt_file);
    };

    aes_key_size = find_pem_header(pem_headers,
                                   P11SAK_WRAP_PEM_HDR_AES_KEY_SIZE);

    if (aes_key_size != NULL) {
        rsa_aeskw_param->ulAESKeyBits =
                                    find_aeskw_keybits_by_name(aes_key_size);
        if (rsa_aeskw_param->ulAESKeyBits == (CK_ULONG)-1) {
            warnx("Invalid AES key size '%s' in PEM file '%s'.",
                  aes_key_size, opt_file);
            return CKR_ARGUMENTS_BAD;
        }
    } else {
        rsa_aeskw_param->ulAESKeyBits = 256;
    }

    tmp_mech.mechanism = CKM_RSA_PKCS_OAEP;
    tmp_mech.pParameter = rsa_aeskw_param->pOAEPParams;
    tmp_mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);

    rc = p11sak_rsa_oaep_prepare_mech_param_from_pem(wrap_mech, &tmp_mech,
                                                     pem_headers);
    if (rc != CKR_OK) {
        p11sak_rsa_aeskw_cleanup_mech_param(wrap_mech, mech);
        return rc;
    }

    return CKR_OK;
}

static void p11sak_rsa_aeskw_cleanup_mech_param(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech)
{
    CK_RSA_AES_KEY_WRAP_PARAMS *rsa_aeskw_param = mech->pParameter;
    CK_MECHANISM tmp_mech;

    UNUSED(wrap_mech);

    if (rsa_aeskw_param->pOAEPParams == NULL)
        return;

    tmp_mech.mechanism = CKM_RSA_PKCS_OAEP;
    tmp_mech.pParameter = rsa_aeskw_param->pOAEPParams;
    tmp_mech.ulParameterLen = sizeof(CK_RSA_PKCS_OAEP_PARAMS);

    p11sak_rsa_oaep_cleanup_mech_param(wrap_mech, &tmp_mech);

    free(rsa_aeskw_param->pOAEPParams);
}

static CK_RV p11sak_rsa_aeskw_prepare_pem_header(
                                const struct p11sak_wrap_mech *wrap_mech,
                                char **pem_header)
{
    char *oaep_hdr = NULL;
    CK_RV rc;
    int len;

    UNUSED(wrap_mech);

    rc = p11sak_rsa_oaep_prepare_pem_header(wrap_mech, &oaep_hdr);
    if (rc != CKR_OK)
        return rc;

    len = asprintf(pem_header, "%s: %s\n%s",
                   P11SAK_WRAP_PEM_HDR_AES_KEY_SIZE,
                   opt_aeskw_keybits != NULL ?
                            opt_aeskw_keybits->value : "256",
                   oaep_hdr != NULL ? oaep_hdr : "");

    if (oaep_hdr != NULL)
        free(oaep_hdr);

    if (len <= 0) {
        warnx("Failed to allocate memory for a PEM header");
        return CKR_HOST_MEMORY;
    }

    return CKR_OK;
}

static CK_RV p11sak_ecdh_aeskw_prepare_mech_param_from_opts(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech)
{
    CK_ECDH_AES_KEY_WRAP_PARAMS *ecdh_aeskw_param = mech->pParameter;
    CK_RV rc;

    UNUSED(wrap_mech);

    if (opt_aeskw_keybits != NULL)
        ecdh_aeskw_param->ulAESKeyBits = opt_aeskw_keybits->private.num;
    else
        ecdh_aeskw_param->ulAESKeyBits = 256;

    if (opt_ecdh_kdf_alg != NULL)
        ecdh_aeskw_param->kdf = opt_ecdh_kdf_alg->private.num;
    else
        ecdh_aeskw_param->kdf = CKD_SHA256_KDF;

    if (opt_ecdh_shared_data != NULL) {
        rc = p11tool_parse_hex(opt_ecdh_shared_data,
                               (CK_BYTE **)&ecdh_aeskw_param->pSharedData,
                               &ecdh_aeskw_param->ulSharedDataLen);
        if (rc != CKR_OK)
            return rc;
    } else {
        ecdh_aeskw_param->pSharedData = NULL;
        ecdh_aeskw_param->ulSharedDataLen = 0;
    }

    return CKR_OK;
}

static CK_RV p11sak_ecdh_aeskw_prepare_mech_param_from_pem(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech, char **pem_headers)
{
    CK_ECDH_AES_KEY_WRAP_PARAMS *ecdh_aeskw_param = mech->pParameter;
    char *aes_key_size, *kdf_alg, *shared_data;
    CK_RV rc;

    UNUSED(wrap_mech);

    if (opt_aeskw_keybits != NULL) {
        warnx("Option '--aes-key-size' is ignored, using information "
              "from PEM file '%s'.", opt_file);
    };

    if (opt_ecdh_kdf_alg != NULL) {
        warnx("Option '--kdf-alg' is ignored, using information "
              "from PEM file '%s'.", opt_file);
    };

    if (opt_ecdh_shared_data != NULL) {
        warnx("Option '--shared-data' is ignored, using information "
              "from PEM file '%s'.", opt_file);
    };

    aes_key_size = find_pem_header(pem_headers,
                                   P11SAK_WRAP_PEM_HDR_AES_KEY_SIZE);
    kdf_alg = find_pem_header(pem_headers, P11SAK_WRAP_PEM_HDR_ECDH_KDF_ALG);
    shared_data = find_pem_header(pem_headers, P11SAK_WRAP_PEM_HDR_ECDH_SHARED);

    if (aes_key_size != NULL) {
        ecdh_aeskw_param->ulAESKeyBits =
                                    find_aeskw_keybits_by_name(aes_key_size);
        if (ecdh_aeskw_param->ulAESKeyBits == (CK_ULONG)-1) {
            warnx("Invalid AES key size '%s' in PEM file '%s'.",
                  aes_key_size, opt_file);
            return CKR_ARGUMENTS_BAD;
        }
    } else {
        ecdh_aeskw_param->ulAESKeyBits = 256;
    }

    if (kdf_alg != NULL) {
        ecdh_aeskw_param->kdf = find_kdf_alg_by_name(kdf_alg);
        if (ecdh_aeskw_param->kdf == (CK_MECHANISM_TYPE)-1) {
            warnx("Invalid kdf algorithm '%s' in PEM file '%s'.",
                  kdf_alg, opt_file);
            return CKR_ARGUMENTS_BAD;
        }
    } else {
        ecdh_aeskw_param->kdf = CKD_SHA256_KDF;
    }

    if (shared_data != NULL) {
        if (strcasecmp(shared_data,
                       P11SAK_WRAP_PEM_HDR_ECDH_SHARED_NONE) == 0) {
            ecdh_aeskw_param->pSharedData = NULL;
            ecdh_aeskw_param->ulSharedDataLen = 0;
        } else {
            rc = p11tool_parse_hex(shared_data,
                                   (CK_BYTE **)&ecdh_aeskw_param->pSharedData,
                                   &ecdh_aeskw_param->ulSharedDataLen);
            if (rc != CKR_OK)
                return rc;
        }
    } else {
        ecdh_aeskw_param->pSharedData = NULL;
        ecdh_aeskw_param->ulSharedDataLen = 0;
    }

    return CKR_OK;
}

static void p11sak_ecdh_aeskw_cleanup_mech_param(
                                const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech)
{
    CK_ECDH_AES_KEY_WRAP_PARAMS *ecdh_aeskw_param = mech->pParameter;

    UNUSED(wrap_mech);

    if (ecdh_aeskw_param->pSharedData != NULL)
        free(ecdh_aeskw_param->pSharedData);
}

static CK_RV p11sak_ecdh_aeskw_prepare_pem_header(
                                const struct p11sak_wrap_mech *wrap_mech,
                                char **pem_header)
{
    int len;

    UNUSED(wrap_mech);

    len = asprintf(pem_header, "%s: %s\n%s: %s\n%s: %s\n",
                   P11SAK_WRAP_PEM_HDR_AES_KEY_SIZE,
                   opt_aeskw_keybits != NULL ?
                           opt_aeskw_keybits->value : "256",
                   P11SAK_WRAP_PEM_HDR_ECDH_KDF_ALG,
                   opt_ecdh_kdf_alg != NULL ?
                           opt_ecdh_kdf_alg->value : "SHA256",
                   P11SAK_WRAP_PEM_HDR_ECDH_SHARED,
                   opt_ecdh_shared_data != NULL ?
                           opt_ecdh_shared_data :
                           P11SAK_WRAP_PEM_HDR_ECDH_SHARED_NONE);
    if (len <= 0) {
        warnx("Failed to allocate memory for a PEM header");
        return CKR_HOST_MEMORY;
    }

    return CKR_OK;
}

static CK_RV handle_kek_select(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                               const struct p11tool_objtype *objtype,
                               CK_ULONG keysize, const char *typestr,
                               const char* label, const char *common_name,
                               void *private)
{
    struct p11sak_select_kek_data *data = private;
    char *msg = NULL;
    char ch;

    UNUSED(objtype);
    UNUSED(keysize);
    UNUSED(common_name);

    if (data->cancel)
        return CKR_OK;

    if (class != data->kek_class)
        return CKR_OK;

    data->count++;

    if (!data->prompt) {
        data->kek_handle = key;
        return CKR_OK;
    }

    if (data->kek_handle != CK_INVALID_HANDLE)
        return CKR_OK;

    if (opt_force) {
        data->kek_handle = key;
        return CKR_OK;
    }

    if (asprintf(&msg, "Use %s key object \"%s\" as key encrypting key (KEK) "
                 "[y/n/c]? ",
                 typestr, label) < 0 ||
        msg == NULL) {
        warnx("Failed to allocate memory for a message");
        return CKR_HOST_MEMORY;
    }
    ch = p11tool_prompt_user(msg, "ync");
    free(msg);

    switch (ch) {
    case 'n':
        return CKR_OK;
    case 'c':
    case '\0':
        data->cancel = CK_TRUE;
        return CKR_OK;
    default:
        break;
    }

    data->kek_handle = key;

    return CKR_OK;
}

static CK_RV p11sak_select_kek(CK_OBJECT_CLASS kek_class, CK_KEY_TYPE kek_type,
                               CK_OBJECT_HANDLE *kek_handle)
{
    struct p11sak_select_kek_data data = { 0 };
    const struct p11tool_objtype *keytype;
    CK_RV rc;

    if (opt_kek_label == NULL && opt_kek_id == NULL) {
        warnx("At least one of the following options must be specified:");
        warnx("'-K'/'--kek-label',  r '-k'/'--kek-id'");
        return CKR_ARGUMENTS_BAD;
    }

    data.prompt = CK_FALSE;
    data.kek_class = kek_class;
    data.count = 0;
    data.kek_handle = CK_INVALID_HANDLE;

    keytype = find_keytype(kek_type);
    rc = iterate_objects(keytype, opt_kek_label, opt_kek_id, NULL, OBJCLASS_KEY,
                         NULL, handle_kek_select, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over key objects: 0x%lX: %s",
               rc, p11_get_ckr(rc));
        return rc;
    }

    if (data.count > 1) {
        data.prompt = CK_TRUE;
        data.count = 0;
        data.cancel = CK_FALSE;

        data.kek_handle = CK_INVALID_HANDLE;

        rc = iterate_objects(keytype, opt_kek_label, opt_kek_id, NULL,
                             OBJCLASS_KEY, NULL, handle_kek_select, &data);
        if (rc != CKR_OK) {
            warnx("Failed to iterate over key objects: 0x%lX: %s",
                   rc, p11_get_ckr(rc));
            return rc;
        }

        if (data.cancel)
            return CKR_CANCEL;
    }

    if (data.kek_handle == CK_INVALID_HANDLE) {
        warnx("No %s%s key matched the specified KEK label or ID.",
              kek_class == CKO_SECRET_KEY ? "" :
                      kek_class == CKO_PUBLIC_KEY ? "public " : "private ",
              keytype != NULL ? keytype->name : "");
        return CKR_ARGUMENTS_BAD;
    }

    *kek_handle = data.kek_handle;

    return CKR_OK;
}

static CK_RV p11sak_wrap_key_perform(struct p11sak_wrap_data *data,
                                     const struct p11tool_objtype *keytype,
                                     CK_OBJECT_HANDLE key,
                                     const char *typestr, const char* label,
                                     BIO *bio)
{
    CK_ULONG len = 0;
    CK_BYTE *buf = NULL;
    char *hdr = NULL;
    CK_RV rc;

    rc = p11tool_pkcs11_funcs->C_WrapKey(p11tool_pkcs11_session, &data->mech,
                                         data->kek_handle, key, NULL, &len);
    if (rc != CKR_OK) {
        warnx("Failed to wrap %s key \"%s\": 0x%lX: %s",
              typestr, label, rc, p11_get_ckr(rc));
        return rc;
    }

    buf = calloc(1, len);
    if (buf == NULL) {
        warnx("Failed to allocate memory for wrapped key");
        return CKR_HOST_MEMORY;
    }

    rc = p11tool_pkcs11_funcs->C_WrapKey(p11tool_pkcs11_session, &data->mech,
                                         data->kek_handle, key, buf, &len);
    if (rc != CKR_OK) {
        warnx("Failed to wrap %s key \"%s\": 0x%lX: %s",
              typestr, label, rc, p11_get_ckr(rc));
        return rc;
    }

    if (opt_raw) {
        if (BIO_write(bio, buf, len) != (int)len) {
            warnx("Failed to write to file '%s'.", opt_file);
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    } else {
        if (asprintf(&hdr, "%s: %s\n%s", P11SAK_WRAP_PEM_HDR_KEY_TYPE,
                     keytype->name, data->pem_header) <= 0) {
            warnx("Failed to allocate memory for a PEM header");
            rc = CKR_HOST_MEMORY;
            goto done;
        }

        if (PEM_write_bio(bio, P11SAK_WRAP_PEM_NAME, hdr, buf, len) <= 0) {
            warnx("Failed to write to PEM file '%s'.", opt_file);
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            rc = CKR_FUNCTION_FAILED;
            goto done;
        }
    }

done:
    free(buf);
    if (hdr != NULL)
        free(hdr);

    return rc;
}

static CK_RV handle_obj_wrap(CK_OBJECT_HANDLE key, CK_OBJECT_CLASS class,
                             const struct p11tool_objtype *objtype,
                             CK_ULONG keysize, const char *typestr,
                             const char* label, const char *common_name,
                             void *private)
{
    struct p11sak_wrap_data *data = private;
    char *msg = NULL;
    BIO *bio;
    bool overwrite = false;
    char ch;
    CK_RV rc;

    UNUSED(keysize);
    UNUSED(common_name);

    if (class == CKO_PUBLIC_KEY)
        return CKR_OK;

    if (data->skip_all) {
        data->num_skipped++;
        return CKR_OK;
    }

    if (!data->wrap_all) {
        if (asprintf(&msg, "Are you sure you want to wrap %s key object \"%s\""
                     " [y/n/a/c]? ", typestr, label) < 0 ||
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
            data->wrap_all = true;
            break;
        default:
            break;
        }
    }

    if (opt_raw && data->num_wrapped > 0) {
        printf("The last wrapped key was stored as raw binary wrapped key "
               "material, and the current\nkey is also to be stored as raw "
               "binary  wrapped key material.\nIt can not be appended to the "
               "previously wrapped key(s).\n");
        overwrite = true;
    }
    if (overwrite && !opt_force) {
        ch = p11tool_prompt_user("Overwrite the previously wrapped key "
                                 "material [y/n]? ", "yn");
        switch (ch) {
        case 'n':
            data->num_skipped++;
            return CKR_OK;
        default:
            break;
        }
    }

    bio = BIO_new_file(opt_file,
                       overwrite || data->num_wrapped == 0 ? "w" : "a");
    if (bio == NULL) {
        warnx("Failed to open file '%s'.", opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        data->num_failed++;
        return CKR_ARGUMENTS_BAD;
    }

    rc = p11sak_wrap_key_perform(data, objtype, key, typestr, label, bio);
    if (rc != CKR_OK) {
        switch (rc) {
        case CKR_KEY_UNEXTRACTABLE:
            warnx("%s key object \"%s\" is unextractable and can not be "
                  "wrapped.", typestr, label);
            break;
        case CKR_KEY_NOT_WRAPPABLE:
            warnx("%s key object \"%s\" can not be wrapped.",
                  typestr, label);
            break;
        }
        data->num_failed++;
        goto done;
    }

    printf("Successfully wrapped %s key object \"%s\" to file '%s'.\n",
           typestr, label, opt_file);
    data->num_wrapped++;

done:
    BIO_free(bio);

    if (rc != CKR_OK &&
        (overwrite || data->num_wrapped == 0))
        remove(opt_file);

    return CKR_OK;
}

static CK_RV prepare_mech_param(const struct p11sak_wrap_mech *wrap_mech,
                                CK_MECHANISM *mech, void **mech_param,
                                char **pem_headers)
{
    CK_RV rc = CKR_OK;

    if (wrap_mech->mech_param_size > 0) {
        *mech_param = calloc(1, wrap_mech->mech_param_size);
        if (*mech_param == NULL) {
            warnx("Failed to allocate memory for mechanism parameter");
            return CKR_HOST_MEMORY;
        }
    }

    mech->mechanism = wrap_mech->mech;
    mech->ulParameterLen = wrap_mech->mech_param_size;
    mech->pParameter = *mech_param;

    if (wrap_mech->mech_param_size == 0)
        return CKR_OK;

    if (pem_headers != NULL) {
        if (wrap_mech->prepare_mech_param_from_pem != NULL)
            rc = wrap_mech->prepare_mech_param_from_pem(wrap_mech, mech,
                                                        pem_headers);

    } else {
        if (wrap_mech->prepare_mech_param_from_opts != NULL)
            rc = wrap_mech->prepare_mech_param_from_opts(wrap_mech, mech);
    }

    if (rc != CKR_OK) {
        free(*mech_param);
        *mech_param = NULL;
    }

    return rc;
}

static void cleanup_mech_param(const struct p11sak_wrap_mech *wrap_mech,
                               CK_MECHANISM *mech, void *mech_param)
{
    if (mech_param == NULL)
        return;

    if (wrap_mech->cleanup_mech_param != NULL)
        wrap_mech->cleanup_mech_param(wrap_mech, mech);

    free(mech_param);
}

static CK_RV prepare_pem_header(const struct p11sak_wrap_mech *wrap_mech,
                                char **pem_header)
{
    CK_RV rc;
    char *param_hdr = NULL;
    int len;

    if (wrap_mech->prepare_pem_header != NULL) {
        rc = wrap_mech->prepare_pem_header(wrap_mech, &param_hdr);
        if (rc != CKR_OK)
            return rc;
    }

    len = asprintf(pem_header, "%s: %s\n%s",
                   P11SAK_WRAP_PEM_HDR_ALG, wrap_mech->name,
                   param_hdr != NULL ? param_hdr : "");

    if (param_hdr != NULL)
        free(param_hdr);

    if (len <= 0) {
        warnx("Failed to allocate memory for a PEM header");
        return CKR_HOST_MEMORY;
    }

    return CKR_OK;
}

CK_RV p11sak_wrap_key(void)
{
    const struct p11tool_objtype *keytype = NULL;
    const struct p11sak_wrap_mech *wrap_mech = opt_wrap_mech->private.ptr;
    struct p11sak_wrap_data data = { 0 };
    void *mech_param = NULL;
    CK_RV rc;

    if (opt_keytype != NULL)
        keytype = opt_keytype->private.ptr;

    rc = p11tool_check_wrap_mech_supported(opt_slot, wrap_mech->mech,
                                           CK_TRUE, CK_FALSE);
    if (rc != CKR_OK)
        return rc;

    rc = p11sak_select_kek(wrap_mech->wrap_class, wrap_mech->key_type,
                           &data.kek_handle);
    if (rc != CKR_OK)
        return rc;

    rc = prepare_mech_param(wrap_mech, &data.mech, &mech_param, NULL);
    if (rc != CKR_OK)
        return rc;

    if (!opt_raw) {
        rc = prepare_pem_header(wrap_mech, &data.pem_header);
        if (rc != CKR_OK)
            return rc;
    }

    data.wrap_mech = wrap_mech;
    data.wrap_all = opt_force;

    rc = iterate_objects(keytype, opt_label, opt_id, opt_attr,
                         OBJCLASS_KEY, NULL,
                         handle_obj_wrap, &data);
    if (rc != CKR_OK) {
        warnx("Failed to iterate over key objects for key type %s: 0x%lX: %s",
              keytype != NULL ? keytype->name : "All", rc, p11_get_ckr(rc));
        goto out;
    }

    printf("%lu key object(s) wrapped.\n", data.num_wrapped);
    if (data.num_skipped > 0)
        printf("%lu key object(s) skipped.\n", data.num_skipped);
    if (data.num_failed > 0)
        printf("%lu key object(s) failed to wrap.\n", data.num_failed);

out:
    cleanup_mech_param(wrap_mech, &data.mech, mech_param);
    if (data.pem_header != NULL)
        free(data.pem_header);

    return rc != CKR_OK ? rc :
                    data.num_failed == 0 ? CKR_OK : CKR_FUNCTION_FAILED;
}

static CK_RV read_wrapped_key(CK_BYTE **buf, CK_ULONG *len, char **pem_header)
{
    char *pem_name = NULL;
    long pem_len;
    BIO *bio;
    CK_RV rc = CKR_OK;

    *buf = NULL;
    *len = 0;
    *pem_header = NULL;

    bio = BIO_new_file(opt_file, "r");
    if (bio == NULL) {
        warnx("Failed to open file '%s'.", opt_file);
        ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
        return CKR_ARGUMENTS_BAD;
    }

    if (opt_raw) {
        rc = p11tool_bio_readall(bio, buf, len);
        if (rc != CKR_OK) {
            warnx("Failed to read file '%s'.", opt_file);
            ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
            goto done;
        }
    } else {
        do {
            if (pem_name != NULL)
                OPENSSL_free(pem_name);
            if (*pem_header != NULL)
                OPENSSL_free(*pem_header);
            if (*buf != NULL)
                OPENSSL_free(*buf);

            *buf = NULL;
            *len = 0;
            *pem_header = NULL;

            if (PEM_read_bio(bio, &pem_name, pem_header,
                             buf, &pem_len) != 1) {
                warnx("Failed to read PEM file '%s'.", opt_file);
                ERR_print_errors_cb(p11tool_openssl_err_cb, NULL);
                rc = CKR_FUNCTION_FAILED;
                goto done;
            }
            *len = pem_len;
        } while (strcmp(pem_name, P11SAK_WRAP_PEM_NAME) != 0);
    }

done:
    BIO_free(bio);
    if (pem_name != NULL)
        OPENSSL_free(pem_name);
    if (rc != CKR_OK && *pem_header != NULL)
        OPENSSL_free(*pem_header);
    if (rc != CKR_OK)
        OPENSSL_free(*buf);

    return rc;
}

static CK_RV process_pem_header(char *pem_header,
                                const struct p11sak_wrap_mech **wrap_mech,
                                const struct p11tool_objtype **keytype,
                                CK_MECHANISM *mech, void **mech_param)
{
    char **headers = NULL;
    char *wrap_alg_str, *keytype_str;
    CK_RV rc;

    rc = p11tool_split_by_delim(pem_header, "\n", &headers);
    if (rc != CKR_OK)
        return rc;

    wrap_alg_str = find_pem_header(headers, P11SAK_WRAP_PEM_HDR_ALG);
    if (wrap_alg_str == NULL) {
        warnx("No '%s' header line found in PEM file '%s'",
              P11SAK_WRAP_PEM_HDR_ALG, opt_file);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    if (*wrap_mech != NULL) {
        warnx("Argument 'WRAP-MECH' is ignored, using information from "
              "PEM file '%s'.", opt_file);
    }

    *wrap_mech = find_wrap_mech_by_name(wrap_alg_str);
    if (*wrap_mech == NULL) {
        warnx("Wrap mechanism '%s' from PEM file '%s' is not valid",
              wrap_alg_str, opt_file);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    keytype_str = find_pem_header(headers, P11SAK_WRAP_PEM_HDR_KEY_TYPE);
    if (keytype_str == NULL) {
        warnx("No '%s' header line found in PEM file '%s'",
              P11SAK_WRAP_PEM_HDR_KEY_TYPE, opt_file);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    if (*keytype != NULL) {
        warnx("Argument 'KEYTYPE' is ignored, using information from "
              "PEM file '%s'.", opt_file);
    }

    *keytype = find_keytype_by_name(keytype_str);
    if (*keytype == NULL) {
        warnx("Key type '%s' from PEM file '%s' is not valid",
              keytype_str, opt_file);
        rc = CKR_ARGUMENTS_BAD;
        goto done;
    }

    rc = prepare_mech_param(*wrap_mech, mech, mech_param, headers);
    if (rc != CKR_OK)
        return rc;

done:
    free(headers);

    return rc;
}

static CK_RV p11sak_unwrap_key_perform(const struct p11tool_objtype *keytype,
                                       CK_OBJECT_HANDLE kek_handle,
                                       CK_MECHANISM *mech,
                                       CK_BYTE *wrapped_key,
                                       CK_ULONG wrapped_key_len)
{
    CK_ATTRIBUTE *attrs = NULL;
    CK_ULONG num_attrs = 0;
    CK_OBJECT_CLASS class;
    CK_OBJECT_HANDLE key_kandle;
    CK_RV rc;

    class = keytype->is_asymmetric ? CKO_PRIVATE_KEY : CKO_SECRET_KEY;
    rc = p11tool_add_attribute(CKA_CLASS, &class, sizeof(class),
                               &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_add_attribute(CKA_KEY_TYPE, &keytype->type,
                               sizeof(keytype->type), &attrs, &num_attrs);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_add_attributes(keytype, p11sak_bool_attrs, &attrs, &num_attrs,
                                opt_label, opt_attr, opt_id, CK_TRUE,
                                opt_so, NULL, NULL,
                                class == CKO_PRIVATE_KEY ?
                                        p11tool_private_attr_applicable :
                                        p11tool_secret_attr_applicable);
    if (rc != CKR_OK)
        goto done;

    rc = p11tool_pkcs11_funcs->C_UnwrapKey(p11tool_pkcs11_session, mech,
                                           kek_handle,
                                           wrapped_key, wrapped_key_len,
                                           attrs, num_attrs,
                                           &key_kandle);
    if (rc != CKR_OK) {
        warnx("Failed to unwrap %s key \"%s\": 0x%lX: %s",
              keytype->name, opt_label, rc, p11_get_ckr(rc));
        goto done;
    }

    printf("Successfully unwrapped a %s key with label \"%s\".\n",
           keytype->name, opt_label);

done:
    p11tool_free_attributes(attrs, num_attrs);

    return rc;
}

CK_RV p11sak_unwrap_key(void)
{
    const struct p11sak_wrap_mech *wrap_mech = NULL;
    const struct p11tool_objtype *keytype = NULL;
    CK_OBJECT_HANDLE kek_handle = CK_INVALID_HANDLE;
    CK_MECHANISM mech = { 0 };
    void *mech_param = NULL;
    char *pem_header = NULL;
    CK_BYTE *wrapped_key = NULL;
    CK_ULONG wrapped_key_len = 0;
    CK_RV rc;

    if (opt_wrap_mech != NULL)
        wrap_mech = opt_wrap_mech->private.ptr;
    if (opt_keytype != NULL)
        keytype = opt_keytype->private.ptr;

    rc = read_wrapped_key(&wrapped_key, &wrapped_key_len, &pem_header);
    if (rc != CKR_OK)
        return rc;

    if (opt_raw) {
        if (wrap_mech == NULL) {
            warnx("Argument 'WRAP-MECH' is required when '-R'/'--raw' is "
                  "specified");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        if (keytype == NULL) {
            warnx("Argument 'KEYTYPE' is required when '-R'/'--raw' is "
                  "specified");
            rc = CKR_ARGUMENTS_BAD;
            goto done;
        }

        /* Get mechanism param from options only */
        rc = prepare_mech_param(wrap_mech, &mech, &mech_param, NULL);
        if (rc != CKR_OK)
            goto done;
    } else {
        /* Get mechanism param from PEM file */
        rc = process_pem_header(pem_header, &wrap_mech, &keytype,
                                &mech, &mech_param);
        if (rc != CKR_OK)
            goto done;
    }

    rc = p11tool_check_wrap_mech_supported(opt_slot, wrap_mech->mech,
                                           CK_FALSE, CK_TRUE);
    if (rc != CKR_OK)
        goto done;

    rc = p11sak_select_kek(wrap_mech->unwrap_class, wrap_mech->key_type,
                           &kek_handle);
    if (rc != CKR_OK)
        goto done;

    rc = p11sak_unwrap_key_perform(keytype, kek_handle, &mech,
                                   wrapped_key, wrapped_key_len);
    if (rc != CKR_OK)
        goto done;

done:
    cleanup_mech_param(wrap_mech, &mech, mech_param);

    if (pem_header != NULL)
        OPENSSL_free(pem_header);
    OPENSSL_free(wrapped_key);

    return rc;
}

void print_wrap_key_help(void)
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

void print_unwrap_key_help(void)
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
